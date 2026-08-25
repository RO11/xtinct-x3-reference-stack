#include "OtaBootSwitch.h"

#include <Logging.h>
#include <esp_app_format.h>
#include <esp_ota_ops.h>
#include <esp_rom_crc.h>
#include <mbedtls/sha256.h>
#include <spi_flash_mmap.h>
#include <string.h>

#include <algorithm>

namespace {

constexpr size_t kValidationChunkSize = 512;
constexpr size_t kImageShaSize = 32;
constexpr uint8_t kImageChecksumSeed = 0xEF;

bool readPartition(const esp_partition_t* partition, size_t offset, void* destination, size_t length) {
  if (!partition || offset > partition->size || length > partition->size - offset) return false;
  return esp_partition_read(partition, offset, destination, length) == ESP_OK;
}

bool hashAndChecksumPartition(const esp_partition_t* partition, size_t offset, size_t length,
                              mbedtls_sha256_context* sha, uint8_t* checksum) {
  uint8_t buffer[kValidationChunkSize];
  size_t remaining = length;
  size_t position = offset;
  while (remaining > 0) {
    const size_t amount = std::min(remaining, sizeof(buffer));
    if (!readPartition(partition, position, buffer, amount)) return false;
    mbedtls_sha256_update(sha, buffer, amount);
    for (size_t index = 0; index < amount; ++index) *checksum ^= buffer[index];
    position += amount;
    remaining -= amount;
  }
  return true;
}

class Sha256Scope {
 public:
  Sha256Scope() { mbedtls_sha256_init(&context); }
  ~Sha256Scope() { mbedtls_sha256_free(&context); }

  mbedtls_sha256_context context;
};

}  // namespace

namespace ota_boot {

uint32_t computeSeqCrc(uint32_t seq) {
  return esp_rom_crc32_le(UINT32_MAX, reinterpret_cast<const uint8_t*>(&seq), kOtaSeqCrcLen);
}

const esp_partition_t* findAlternateAppPartition() {
  const esp_partition_t* running = esp_ota_get_running_partition();
  if (!running || running->type != ESP_PARTITION_TYPE_APP) {
    LOG_ERR("BOOT", "Running app partition unavailable");
    return nullptr;
  }

  esp_partition_subtype_t otherSubtype;
  if (running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0) {
    otherSubtype = ESP_PARTITION_SUBTYPE_APP_OTA_1;
  } else if (running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1) {
    otherSubtype = ESP_PARTITION_SUBTYPE_APP_OTA_0;
  } else {
    LOG_ERR("BOOT", "Running app is not ota_0/ota_1 (subtype=0x%02X)", running->subtype);
    return nullptr;
  }

  const esp_partition_t* other = esp_partition_find_first(ESP_PARTITION_TYPE_APP, otherSubtype, nullptr);
  if (!other || other == running) {
    LOG_ERR("BOOT", "Alternate OTA app partition unavailable");
    return nullptr;
  }
  return other;
}

bool hasValidAppImageHeader(const esp_partition_t* partition) {
  if (!partition || partition->type != ESP_PARTITION_TYPE_APP ||
      (partition->subtype != ESP_PARTITION_SUBTYPE_APP_OTA_0 &&
       partition->subtype != ESP_PARTITION_SUBTYPE_APP_OTA_1) ||
      partition->size < sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t) + sizeof(esp_app_desc_t)) {
    LOG_ERR("BOOT", "Candidate is not a usable OTA app partition");
    return false;
  }

  esp_image_header_t candidateHeader = {};
  if (!readPartition(partition, 0, &candidateHeader, sizeof(candidateHeader)) ||
      candidateHeader.magic != ESP_IMAGE_HEADER_MAGIC || candidateHeader.segment_count == 0 ||
      candidateHeader.segment_count > ESP_IMAGE_MAX_SEGMENTS || candidateHeader.entry_addr == 0 ||
      candidateHeader.entry_addr == UINT32_MAX || candidateHeader.hash_appended > 1) {
    LOG_ERR("BOOT", "Candidate %s has an invalid ESP image header", partition->label);
    return false;
  }

  const esp_partition_t* running = esp_ota_get_running_partition();
  esp_image_header_t runningHeader = {};
  if (!running || !readPartition(running, 0, &runningHeader, sizeof(runningHeader)) ||
      runningHeader.magic != ESP_IMAGE_HEADER_MAGIC || candidateHeader.chip_id != runningHeader.chip_id) {
    LOG_ERR("BOOT", "Candidate %s targets a different or unknown chip", partition->label);
    return false;
  }

  Sha256Scope sha;
  mbedtls_sha256_starts(&sha.context, /*is224=*/0);
  mbedtls_sha256_update(&sha.context, reinterpret_cast<const uint8_t*>(&candidateHeader), sizeof(candidateHeader));

  uint8_t checksum = kImageChecksumSeed;
  size_t position = sizeof(candidateHeader);
  for (uint8_t segmentIndex = 0; segmentIndex < candidateHeader.segment_count; ++segmentIndex) {
    if (position > partition->size || sizeof(esp_image_segment_header_t) > partition->size - position) {
      LOG_ERR("BOOT", "Candidate %s segment %u header exceeds partition", partition->label, segmentIndex);
      return false;
    }

    esp_image_segment_header_t segment = {};
    if (!readPartition(partition, position, &segment, sizeof(segment))) {
      LOG_ERR("BOOT", "Candidate %s segment %u header read failed", partition->label, segmentIndex);
      return false;
    }
    mbedtls_sha256_update(&sha.context, reinterpret_cast<const uint8_t*>(&segment), sizeof(segment));
    position += sizeof(segment);

    if (segment.data_len > partition->size - position) {
      LOG_ERR("BOOT", "Candidate %s segment %u data exceeds partition", partition->label, segmentIndex);
      return false;
    }
    if (segmentIndex == 0) {
      if (segment.data_len < sizeof(esp_app_desc_t)) {
        LOG_ERR("BOOT", "Candidate %s first segment cannot contain an app descriptor", partition->label);
        return false;
      }
      esp_app_desc_t appDescription = {};
      if (!readPartition(partition, position, &appDescription, sizeof(appDescription)) ||
          appDescription.magic_word != ESP_APP_DESC_MAGIC_WORD) {
        LOG_ERR("BOOT", "Candidate %s has no valid app descriptor", partition->label);
        return false;
      }
    }
    if (!hashAndChecksumPartition(partition, position, segment.data_len, &sha.context, &checksum)) {
      LOG_ERR("BOOT", "Candidate %s segment %u data read failed", partition->label, segmentIndex);
      return false;
    }
    position += segment.data_len;
  }

  // ESP images always end the segment body with 1..16 padding/checksum bytes;
  // the final byte is the XOR checksum and the resulting end is 16-byte aligned.
  const size_t paddingLength = 16u - (position & 15u);
  if (position > partition->size || paddingLength > partition->size - position) {
    LOG_ERR("BOOT", "Candidate %s checksum padding exceeds partition", partition->label);
    return false;
  }
  uint8_t padding[16] = {};
  if (!readPartition(partition, position, padding, paddingLength)) {
    LOG_ERR("BOOT", "Candidate %s checksum padding read failed", partition->label);
    return false;
  }
  mbedtls_sha256_update(&sha.context, padding, paddingLength);
  if (padding[paddingLength - 1] != checksum) {
    LOG_ERR("BOOT", "Candidate %s checksum mismatch", partition->label);
    return false;
  }
  position += paddingLength;

  if (candidateHeader.hash_appended) {
    if (position > partition->size || kImageShaSize > partition->size - position) {
      LOG_ERR("BOOT", "Candidate %s SHA trailer exceeds partition", partition->label);
      return false;
    }
    uint8_t computed[kImageShaSize] = {};
    uint8_t stored[kImageShaSize] = {};
    mbedtls_sha256_finish(&sha.context, computed);
    if (!readPartition(partition, position, stored, sizeof(stored)) || memcmp(computed, stored, sizeof(stored)) != 0) {
      LOG_ERR("BOOT", "Candidate %s SHA256 trailer mismatch", partition->label);
      return false;
    }
  }

  LOG_INF("BOOT", "Candidate %s passed full ESP image validation", partition->label);
  return true;
}

bool switchTo(const esp_partition_t* dest) {
  if (!hasValidAppImageHeader(dest)) return false;

  const esp_partition_t* otadata =
      esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_OTA, nullptr);
  if (!otadata) {
    LOG_ERR("BOOT", "otadata partition not found");
    return false;
  }
  if (otadata->size < 2 * SPI_FLASH_SEC_SIZE) {
    LOG_ERR("BOOT", "otadata too small: %u", static_cast<unsigned>(otadata->size));
    return false;
  }

  SelectEntry slots[2] = {};
  if (esp_partition_read(otadata, 0, &slots[0], sizeof(SelectEntry)) != ESP_OK ||
      esp_partition_read(otadata, SPI_FLASH_SEC_SIZE, &slots[1], sizeof(SelectEntry)) != ESP_OK) {
    LOG_ERR("BOOT", "otadata read failed");
    return false;
  }

  // Pick the slot with valid CRC and highest seq, ignoring INVALID/ABORTED.
  int activeIdx = -1;
  uint32_t activeSeq = 0;
  for (int i = 0; i < 2; ++i) {
    if (slots[i].ota_seq == 0xFFFFFFFFu) continue;
    if (slots[i].crc != computeSeqCrc(slots[i].ota_seq)) continue;
    if (slots[i].ota_state == kOtaImgInvalid || slots[i].ota_state == kOtaImgAborted) continue;
    if (activeIdx < 0 || slots[i].ota_seq > activeSeq) {
      activeIdx = i;
      activeSeq = slots[i].ota_seq;
    }
  }
  LOG_INF("BOOT", "otadata: active slot=%d seq=%u", activeIdx, static_cast<unsigned>(activeSeq));

  // ota_seq encoding: (seq - 1) % NUM_OTA_PARTITIONS picks the partition.
  const uint32_t destOtaIdx =
      static_cast<uint32_t>(dest->subtype) - static_cast<uint32_t>(ESP_PARTITION_SUBTYPE_APP_OTA_0);
  if (destOtaIdx > 15) {
    LOG_ERR("BOOT", "dest is not an OTA app partition (subtype=0x%02X)", dest->subtype);
    return false;
  }

  // Find the smallest representable seq > activeSeq whose parity selects dest.
  // Do the arithmetic wide so UINT32_MAX (the erased sentinel) is never emitted
  // and a near-overflow sequence cannot wrap or spin forever.
  uint64_t candidateSeq = static_cast<uint64_t>(activeSeq) + 1u;
  if (((candidateSeq - 1u) % 2u) != (destOtaIdx % 2u)) ++candidateSeq;
  if (candidateSeq == 0 || candidateSeq >= UINT32_MAX) {
    LOG_ERR("BOOT", "No safe otadata sequence remains after %u", static_cast<unsigned>(activeSeq));
    return false;
  }
  const uint32_t newSeq = static_cast<uint32_t>(candidateSeq);

  SelectEntry next = {};
  next.ota_seq = newSeq;
  memset(next.seq_label, 0xFF, sizeof(next.seq_label));
  next.ota_state = kOtaImgNew;
  next.crc = computeSeqCrc(next.ota_seq);

  // Write to the OTHER slot (so the bootloader sees a higher seq there).
  const int targetSlot = (activeIdx == 0) ? 1 : 0;
  const size_t targetOff = static_cast<size_t>(targetSlot) * SPI_FLASH_SEC_SIZE;

  if (esp_partition_erase_range(otadata, targetOff, SPI_FLASH_SEC_SIZE) != ESP_OK) {
    LOG_ERR("BOOT", "otadata erase failed (slot=%d)", targetSlot);
    return false;
  }
  if (esp_partition_write(otadata, targetOff, &next, sizeof(next)) != ESP_OK) {
    LOG_ERR("BOOT", "otadata write failed (slot=%d)", targetSlot);
    return false;
  }

  LOG_INF("BOOT", "otadata: wrote slot=%d seq=%u crc=0x%08x -> %s", targetSlot, static_cast<unsigned>(newSeq),
          static_cast<unsigned>(next.crc), dest->label);
  return true;
}

}  // namespace ota_boot
