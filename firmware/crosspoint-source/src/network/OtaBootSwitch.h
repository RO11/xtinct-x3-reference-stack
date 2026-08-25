#pragma once

#include <esp_partition.h>

#include <cstddef>
#include <cstdint>

// X4 (and X3) factory bootloaders accept our patch_firmware_image.py-patched
// firmware.bin (web flasher proves this), but the running ESP-IDF's
// esp_image_verify rejects with bogus efuse-blk-rev errors. Both SD-card and
// OTA update paths bypass that runtime check by writing the OTA app partition
// raw and updating otadata directly — same scheme as the web flasher
// (crosspoint-reader-docs/src/lib/flasher/OtaPartition.ts).
//
// Layout reference: esp_flash_partitions.h. CRC covers ota_seq (4 bytes) only.

namespace ota_boot {

struct __attribute__((packed)) SelectEntry {
  uint32_t ota_seq;
  uint8_t seq_label[20];
  uint32_t ota_state;
  uint32_t crc;
};
static_assert(sizeof(SelectEntry) == 32, "SelectEntry must be 32 bytes");

constexpr uint32_t kOtaImgNew = 0;      // ESP_OTA_IMG_NEW
constexpr uint32_t kOtaImgInvalid = 3;  // ESP_OTA_IMG_INVALID
constexpr uint32_t kOtaImgAborted = 4;  // ESP_OTA_IMG_ABORTED
constexpr size_t kOtaSeqCrcLen = 4;

// CRC32-LE over the 4-byte ota_seq, init UINT32_MAX. Matches IDF and web flasher.
uint32_t computeSeqCrc(uint32_t seq);

// Resolve the other slot in the fixed ota_0/ota_1 layout. Returns nullptr when
// the running image is not in one of those slots or the sibling is absent.
const esp_partition_t* findAlternateAppPartition();

// Full, bootloader-independent integrity check for an installed app slot:
// validates partition type/subtype, target chip ID, every segment bound, the
// embedded esp_app_desc magic, the ESP XOR checksum and an optional SHA256
// trailer. The legacy function name is retained for callers. This intentionally
// does not call esp_image_verify because the X3/X4 factory-compatible patched
// image trips that running-IDF check despite booting correctly.
bool hasValidAppImageHeader(const esp_partition_t* partition);

// Switch the bootloader's selected app partition to `dest` by writing a fresh
// otadata entry into the inactive otadata slot. Bypasses esp_ota_set_boot_partition's
// esp_image_verify call. The bytes in `dest` must already be a valid app image
// (e.g. patch_firmware_image.py output) — caller is responsible for that.
//
// Re-validates the complete destination app image before touching otadata.
// Returns true on success.
bool switchTo(const esp_partition_t* dest);

}  // namespace ota_boot
