#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace xtinct::sync_v2 {

constexpr size_t MAX_DELIVERIES = 16;
constexpr size_t MAX_TOMBSTONES = 16;
constexpr size_t MAX_ACK_EVENTS = 24;
constexpr size_t MAX_ACK_JSON_BYTES = 16 * 1024;
constexpr size_t MAX_OUTBOX_BYTES = 32 * 1024;
constexpr size_t MAX_OUTBOX_EVENTS = 48;
constexpr size_t MAX_OUTBOX_EVENT_LINE_BYTES = 1536;
constexpr size_t MAX_ARTIFACT_BYTES = 20 * 1024 * 1024;
constexpr size_t MAX_TITLE_BYTES = 120;
constexpr size_t MAX_METADATA_BYTES = 2 * 1024;
constexpr size_t MAX_INBOX_ITEMS = 64;
// Each committed metadata file may have a bounded .tmp and .bak sidecar. The
// extra entry is a sentinel used to detect/refuse an overfull owned directory.
constexpr size_t MAX_INBOX_METADATA_SCAN_FILES = MAX_INBOX_ITEMS * 3 + 1;
// Legacy Inbox image payload. This is not the physical X3 sleep-screen
// geometry and must never be activated as /sleep.bmp.
constexpr uint32_t X3_ONE_BIT_BMP_BYTES = 62U + 60U * 800U;
constexpr uint16_t X3_SLEEP_BMP_WIDTH = 528;
constexpr uint16_t X3_SLEEP_BMP_HEIGHT = 792;
constexpr uint8_t X3_SLEEP_BMP_BITS_PER_PIXEL = 4;
constexpr uint32_t X3_SLEEP_BMP_PIXEL_OFFSET = 70;
constexpr uint32_t X3_SLEEP_BMP_ROW_BYTES = 264;
constexpr uint32_t X3_NATIVE_SLEEP_BMP_BYTES =
    X3_SLEEP_BMP_PIXEL_OFFSET + X3_SLEEP_BMP_ROW_BYTES * X3_SLEEP_BMP_HEIGHT;
constexpr char DEVICE_STATUS_ITEM_ID[] = "device-status";
constexpr char DEVICE_STATUS_REVISION[] = "0000000000000000000000000000000000000000000000000000000000000000";

inline bool isAckEventType(const char* value) {
  if (!value) return false;
  constexpr const char* EVENT_TYPES[] = {"downloaded", "opened",     "failed",      "kept",
                                         "archived",   "done",       "deferred",    "progress",
                                         "open-phone", "deleted",    "like",        "dislike",
                                         "device-status"};
  for (const char* eventType : EVENT_TYPES) {
    if (std::strcmp(value, eventType) == 0) return true;
  }
  return false;
}

// Persisted receipts are never displaced to make room for a later event. A
// caller may append only when both fixed bounds still hold after including the
// JSONL newline. This keeps the SD footprint bounded without weakening retry
// durability for terminal actions such as `deleted`.
constexpr bool outboxCanAppend(const size_t existingEvents, const size_t existingBytes,
                               const size_t eventLineBytes) {
  if (existingEvents >= MAX_OUTBOX_EVENTS || existingBytes > MAX_OUTBOX_BYTES ||
      eventLineBytes > MAX_OUTBOX_EVENT_LINE_BYTES) {
    return false;
  }
  const size_t requiredBytes = eventLineBytes + 1;
  return requiredBytes <= MAX_OUTBOX_BYTES - existingBytes;
}

static_assert(outboxCanAppend(MAX_OUTBOX_EVENTS - 1, 0, MAX_OUTBOX_EVENT_LINE_BYTES));
static_assert(!outboxCanAppend(MAX_OUTBOX_EVENTS, 0, 1));
static_assert(outboxCanAppend(0, MAX_OUTBOX_BYTES - MAX_OUTBOX_EVENT_LINE_BYTES - 1,
                              MAX_OUTBOX_EVENT_LINE_BYTES));
static_assert(!outboxCanAppend(0, MAX_OUTBOX_BYTES - MAX_OUTBOX_EVENT_LINE_BYTES,
                               MAX_OUTBOX_EVENT_LINE_BYTES));

// Atomic writes use final -> .bak followed by .tmp -> final. Recovery must
// therefore prefer the last committed backup whenever the final path is
// absent, even if an uncommitted temporary file is also present. A lone
// temporary file has never been committed and may be discarded.
enum class AtomicRecoveryAction : uint8_t { UseFinal, RestoreBackup, DiscardTemporary, Missing };

constexpr AtomicRecoveryAction atomicRecoveryAction(const bool finalExists, const bool backupExists,
                                                     const bool temporaryExists) {
  if (finalExists) return AtomicRecoveryAction::UseFinal;
  if (backupExists) return AtomicRecoveryAction::RestoreBackup;
  if (temporaryExists) return AtomicRecoveryAction::DiscardTemporary;
  return AtomicRecoveryAction::Missing;
}

static_assert(atomicRecoveryAction(true, true, true) == AtomicRecoveryAction::UseFinal);
static_assert(atomicRecoveryAction(false, true, true) == AtomicRecoveryAction::RestoreBackup);
static_assert(atomicRecoveryAction(false, true, false) == AtomicRecoveryAction::RestoreBackup);
static_assert(atomicRecoveryAction(false, false, true) == AtomicRecoveryAction::DiscardTemporary);
static_assert(atomicRecoveryAction(false, false, false) == AtomicRecoveryAction::Missing);

enum class Kind : uint8_t { Invalid, Card, Text, Image1Bit, Epub, Action, SleepScreen };

inline bool isSafeId(const char* value) {
  if (!value) return false;
  const size_t length = std::strlen(value);
  if (length == 0 || length > 32) return false;
  const auto first = static_cast<unsigned char>(value[0]);
  if (!((first >= 'a' && first <= 'z') || (first >= '0' && first <= '9'))) return false;
  for (size_t i = 1; i < length; ++i) {
    const auto c = static_cast<unsigned char>(value[i]);
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
  }
  return true;
}

inline bool managedMetadataItemId(const char* fileName, char itemId[33]) {
  if (!fileName || !itemId) return false;
  const size_t length = std::strlen(fileName);
  constexpr char SUFFIX[] = ".json";
  constexpr size_t SUFFIX_BYTES = sizeof(SUFFIX) - 1;
  if (length <= SUFFIX_BYTES || length > 32 + SUFFIX_BYTES ||
      std::strcmp(fileName + length - SUFFIX_BYTES, SUFFIX) != 0) {
    return false;
  }
  const size_t idLength = length - SUFFIX_BYTES;
  std::memcpy(itemId, fileName, idLength);
  itemId[idLength] = '\0';
  if (!isSafeId(itemId)) {
    itemId[0] = '\0';
    return false;
  }
  return true;
}

inline bool managedMetadataSidecarFinalName(const char* fileName, char finalName[38]) {
  if (!fileName || !finalName) return false;
  const size_t length = std::strlen(fileName);
  if (length <= 4 ||
      (std::strcmp(fileName + length - 4, ".tmp") != 0 &&
       std::strcmp(fileName + length - 4, ".bak") != 0) ||
      length - 4 >= 38) {
    return false;
  }
  std::memcpy(finalName, fileName, length - 4);
  finalName[length - 4] = '\0';
  char itemId[33];
  if (!managedMetadataItemId(finalName, itemId)) {
    finalName[0] = '\0';
    return false;
  }
  return true;
}

inline bool isSha256(const char* value) {
  if (!value || std::strlen(value) != 64) return false;
  for (size_t i = 0; i < 64; ++i) {
    const char c = value[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

inline Kind parseKind(const char* value) {
  if (!value) return Kind::Invalid;
  if (std::strcmp(value, "card") == 0) return Kind::Card;
  if (std::strcmp(value, "text") == 0) return Kind::Text;
  if (std::strcmp(value, "image-1bit") == 0) return Kind::Image1Bit;
  if (std::strcmp(value, "epub") == 0) return Kind::Epub;
  if (std::strcmp(value, "action") == 0) return Kind::Action;
  if (std::strcmp(value, "sleep-screen") == 0) return Kind::SleepScreen;
  return Kind::Invalid;
}

inline const char* kindName(const Kind kind) {
  switch (kind) {
    case Kind::Card:
      return "card";
    case Kind::Text:
      return "text";
    case Kind::Image1Bit:
      return "image-1bit";
    case Kind::Epub:
      return "epub";
    case Kind::Action:
      return "action";
    case Kind::SleepScreen:
      return "sleep-screen";
    default:
      return "invalid";
  }
}

inline const char* extensionForKind(const Kind kind) {
  switch (kind) {
    case Kind::Epub:
      return ".epub";
    case Kind::Image1Bit:
    case Kind::SleepScreen:
      return ".bmp";
    case Kind::Card:
    case Kind::Text:
    case Kind::Action:
      return ".txt";
    default:
      return "";
  }
}

// Returns the content digest for files owned by the XTINCT artifact cache.
// Unknown names are deliberately ignored so garbage collection can never
// remove a user's unrelated SD-card file.
inline bool managedArtifactDigest(const char* fileName, char digest[65]) {
  if (!fileName || !digest || std::strlen(fileName) < 68) return false;
  char candidate[65];
  std::memcpy(candidate, fileName, 64);
  candidate[64] = '\0';
  if (!isSha256(candidate)) return false;

  const char* suffix = fileName + 64;
  bool knownExtension = false;
  constexpr const char* EXTENSIONS[] = {".txt", ".bmp", ".epub"};
  for (const char* extension : EXTENSIONS) {
    const size_t extensionLength = std::strlen(extension);
    if (std::strncmp(suffix, extension, extensionLength) != 0) continue;
    const char* sidecar = suffix + extensionLength;
    knownExtension = sidecar[0] == '\0' || std::strcmp(sidecar, ".tmp") == 0 ||
                     std::strcmp(sidecar, ".bak") == 0;
    if (knownExtension) break;
  }
  if (!knownExtension) return false;
  std::memcpy(digest, candidate, sizeof(candidate));
  return true;
}

inline bool mimeAllowed(const Kind kind, const char* mime) {
  if (!mime) return false;
  switch (kind) {
    case Kind::Card:
    case Kind::Text:
    case Kind::Action:
      return std::strcmp(mime, "text/plain") == 0 ||
             std::strcmp(mime, "text/plain; charset=utf-8") == 0;
    case Kind::Image1Bit:
    case Kind::SleepScreen:
      return std::strcmp(mime, "image/bmp") == 0;
    case Kind::Epub:
      return std::strcmp(mime, "application/epub+zip") == 0;
    default:
      return false;
  }
}

inline uint16_t little16(const uint8_t* bytes) {
  return static_cast<uint16_t>(bytes[0]) | (static_cast<uint16_t>(bytes[1]) << 8);
}

inline uint32_t little32(const uint8_t* bytes) {
  return static_cast<uint32_t>(bytes[0]) | (static_cast<uint32_t>(bytes[1]) << 8) |
         (static_cast<uint32_t>(bytes[2]) << 16) | (static_cast<uint32_t>(bytes[3]) << 24);
}

// X3 remote images are deliberately pre-rendered. Requiring an exact
// uncompressed 480x800, one-bit BMP keeps decoding deterministic and prevents
// a malicious artifact from turning image scaling into a RAM exhaustion path.
inline bool isX3OneBitBmpHeader(const uint8_t* bytes, const size_t length, const uint32_t totalBytes) {
  if (!bytes || length < 54 || bytes[0] != 'B' || bytes[1] != 'M') return false;
  const uint32_t declaredSize = little32(bytes + 2);
  const uint32_t pixelOffset = little32(bytes + 10);
  const uint32_t dibSize = little32(bytes + 14);
  const int32_t width = static_cast<int32_t>(little32(bytes + 18));
  const int32_t height = static_cast<int32_t>(little32(bytes + 22));
  const uint16_t planes = little16(bytes + 26);
  const uint16_t bitsPerPixel = little16(bytes + 28);
  const uint32_t compression = little32(bytes + 30);
  return declaredSize == totalBytes && totalBytes == X3_ONE_BIT_BMP_BYTES && pixelOffset == 62 && dibSize >= 40 &&
         width == 480 && (height == 800 || height == -800) && planes == 1 && bitsPerPixel == 1 && compression == 0;
}

// A native X3 sleep screen is a standard 4-bpp Windows BMP. Four palette
// entries map directly to the panel's 0/85/170/255 gray levels, so Bitmap
// takes the native-palette path and never creates a one-bit halftone grid.
inline bool isX3NativeSleepBmpHeader(const uint8_t* bytes, const size_t length,
                                     const uint32_t totalBytes) {
  if (!bytes || length < X3_SLEEP_BMP_PIXEL_OFFSET || bytes[0] != 'B' || bytes[1] != 'M') return false;
  const uint32_t declaredSize = little32(bytes + 2);
  const uint16_t reserved1 = little16(bytes + 6);
  const uint16_t reserved2 = little16(bytes + 8);
  const uint32_t pixelOffset = little32(bytes + 10);
  const uint32_t dibSize = little32(bytes + 14);
  const int32_t width = static_cast<int32_t>(little32(bytes + 18));
  const int32_t height = static_cast<int32_t>(little32(bytes + 22));
  const uint16_t planes = little16(bytes + 26);
  const uint16_t bitsPerPixel = little16(bytes + 28);
  const uint32_t compression = little32(bytes + 30);
  const uint32_t imageBytes = little32(bytes + 34);
  const uint32_t colorsUsed = little32(bytes + 46);
  const uint32_t importantColors = little32(bytes + 50);
  constexpr uint8_t NATIVE_PALETTE[] = {
      0, 0, 0, 0, 85, 85, 85, 0, 170, 170, 170, 0, 255, 255, 255, 0,
  };
  return declaredSize == totalBytes && totalBytes == X3_NATIVE_SLEEP_BMP_BYTES &&
         reserved1 == 0 && reserved2 == 0 && pixelOffset == X3_SLEEP_BMP_PIXEL_OFFSET &&
         dibSize == 40 && width == X3_SLEEP_BMP_WIDTH &&
         (height == X3_SLEEP_BMP_HEIGHT || height == -static_cast<int32_t>(X3_SLEEP_BMP_HEIGHT)) &&
         planes == 1 && bitsPerPixel == X3_SLEEP_BMP_BITS_PER_PIXEL && compression == 0 &&
         imageBytes == X3_SLEEP_BMP_ROW_BYTES * X3_SLEEP_BMP_HEIGHT && colorsUsed == 4 &&
         (importantColors == 0 || importantColors == 4) &&
         std::memcmp(bytes + 54, NATIVE_PALETTE, sizeof(NATIVE_PALETTE)) == 0;
}

inline bool isEpubHeader(const uint8_t* bytes, const size_t length) {
  return bytes && length >= 4 && bytes[0] == 'P' && bytes[1] == 'K' && bytes[2] == 3 && bytes[3] == 4;
}

class Utf8Validator {
 public:
  void feed(const uint8_t* bytes, const size_t length) {
    if (!bytes) {
      valid = false;
      return;
    }
    for (size_t index = 0; index < length && valid; ++index) {
      const uint8_t byte = bytes[index];
      if (remaining == 0) {
        if (byte == 0) {
          valid = false;
          continue;
        }
        if (byte <= 0x7f) continue;
        if (byte >= 0xc2 && byte <= 0xdf) {
          remaining = 1;
          codepoint = byte & 0x1f;
          minimum = 0x80;
        } else if (byte >= 0xe0 && byte <= 0xef) {
          remaining = 2;
          codepoint = byte & 0x0f;
          minimum = 0x800;
        } else if (byte >= 0xf0 && byte <= 0xf4) {
          remaining = 3;
          codepoint = byte & 0x07;
          minimum = 0x10000;
        } else {
          valid = false;
        }
        continue;
      }
      if ((byte & 0xc0) != 0x80) {
        valid = false;
        continue;
      }
      codepoint = (codepoint << 6) | (byte & 0x3f);
      --remaining;
      if (remaining == 0 &&
          (codepoint < minimum || codepoint > 0x10ffff || (codepoint >= 0xd800 && codepoint <= 0xdfff))) {
        valid = false;
      }
    }
  }

  bool complete() const { return valid && remaining == 0; }

 private:
  uint32_t codepoint = 0;
  uint32_t minimum = 0;
  uint8_t remaining = 0;
  bool valid = true;
};

inline uint32_t secondsUntilNextWindow(const uint32_t localSecondsOfDay) {
  constexpr uint32_t DAY = 24U * 60U * 60U;
  constexpr uint32_t WINDOWS[] = {4U * 3600U + 15U * 60U, 8U * 3600U + 15U * 60U, 18U * 3600U};
  const uint32_t now = localSecondsOfDay % DAY;
  for (const uint32_t window : WINDOWS) {
    if (window > now) return window - now;
  }
  return DAY - now + WINDOWS[0];
}

}  // namespace xtinct::sync_v2
