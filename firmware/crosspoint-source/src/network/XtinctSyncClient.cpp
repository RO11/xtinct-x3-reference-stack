#include "XtinctSyncClient.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HalClock.h>
#include <HalPowerManager.h>
#include <HalStorage.h>
#include <Logging.h>
#include <Memory.h>
#include <SDCardManager.h>
#include <SecureHttpClient.h>
#include <WiFi.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>

#include "CrossPointSettings.h"
#include "XtinctFeedConfigStore.h"
#include "XtinctTrustAnchors.h"
#include "FileTransferSafety.h"
#include "util/XtinctAtomicFile.h"
#include "util/BoundedResponseBuffer.h"
#include "util/DailyCardsFreshnessPolicy.h"
#include "util/InboxDailyCachePolicy.h"
#include "util/InboxNewestSelection.h"
#include "util/InboxSyncPagingPolicy.h"
#include "util/XtinctNetworkPersistence.h"

namespace {
using xtinct::sync_v2::Kind;

constexpr char ROOT_DIR[] = "/.crosspoint/xtinct-v2";
constexpr char INBOX_DIR[] = "/.crosspoint/xtinct-v2/inbox";
constexpr char ARTIFACT_DIR[] = "/.crosspoint/xtinct-v2/artifacts";
constexpr char CURSOR_PATH[] = "/.crosspoint/xtinct-v2/cursor";
constexpr char DEVICE_ID_PATH[] = "/.crosspoint/xtinct-v2/device-id";
constexpr char EVENT_SEQUENCE_PATH[] = "/.crosspoint/xtinct-v2/event-sequence";
constexpr char OUTBOX_PATH[] = "/.crosspoint/xtinct-v2/outbox.jsonl";
constexpr char SLEEP_ACTIVATION_PATH[] = "/.crosspoint/xtinct-v2/sleep-activation.json";
// V1 was written by the first cache implementation immediately after TLS and
// could incorrectly bless a partial parse as complete. Never read it again.
constexpr char LEGACY_FAST_FIRST_PAGE_PATH[] = "/.crosspoint/xtinct-v2/inbox-first-page.json";
constexpr char FAST_FIRST_PAGE_PATH[] = "/.crosspoint/xtinct-v2/inbox-first-page-v2.json";
constexpr char SYNC_COMPLETE_PATH[] = "/.crosspoint/xtinct-v2/inbox-sync-complete.json";
constexpr size_t MAX_SYNC_BODY_BYTES = xtinct::inbox_sync_paging::MAX_DIRECT_RESPONSE_BYTES;
constexpr size_t MAX_META_FILE_BYTES = 4096;
constexpr size_t MAX_FAST_FIRST_PAGE_BYTES = 1024;
constexpr size_t MAX_SYNC_COMPLETE_BYTES = 256;
constexpr size_t FAST_FIRST_PAGE_ITEMS = 8;
// The wire contract accepts 16 KiB, but an X3 ACK request must coexist with
// TLS. Keep the device batch small and let event-id deduplication handle more
// batches on later best-effort passes.
constexpr size_t MAX_DEVICE_ACK_JSON_BYTES = 4 * 1024;
static_assert(MAX_DEVICE_ACK_JSON_BYTES <= xtinct::sync_v2::MAX_ACK_JSON_BYTES);
constexpr uint8_t MAX_SYNC_PAGES_PER_WAKE = xtinct::inbox_sync_paging::MAX_PAGES_PER_WAKE;
constexpr size_t MAX_INBOX_ATOMIC_SCAN_FILES = xtinct::sync_v2::MAX_INBOX_METADATA_SCAN_FILES;
constexpr size_t MAX_ARTIFACT_SCAN_FILES = xtinct::sync_v2::MAX_INBOX_ITEMS * 3 + 64;
constexpr size_t MAX_ARTIFACT_REMOVALS_PER_PASS = 64;
constexpr uint32_t HTTP_TIMEOUT_MS = 25000;

struct Delivery {
  XtinctInboxItem item;
};

struct Tombstone {
  char deliveryId[33] = {0};
  char itemId[33] = {0};
  char revision[65] = {0};
};

struct SyncPage {
  char deviceId[33] = {0};
  char cursor[24] = {0};
  bool hasMore = false;
  uint8_t deliveryCount = 0;
  Delivery deliveries[xtinct::inbox_sync_paging::DIRECT_PAGE_CHANGES];
  uint8_t tombstoneCount = 0;
  Tombstone tombstones[xtinct::inbox_sync_paging::DIRECT_PAGE_CHANGES];
};

static_assert(sizeof(SyncPage) == 7480, "Inbox sync-page RAM contract changed");
static_assert(sizeof(SyncPage) <= 8 * 1024, "Inbox sync page exceeds the X3 heap budget");

class Sha256Scope {
 public:
  Sha256Scope() { mbedtls_sha256_init(&context); }
  ~Sha256Scope() { mbedtls_sha256_free(&context); }
  mbedtls_sha256_context context;
};

class HalJsonReader {
 public:
  explicit HalJsonReader(HalFile& file) : file(file) {}
  int read() { return file.read(); }
  size_t readBytes(char* buffer, const size_t length) {
    const int amount = file.read(buffer, length);
    return amount > 0 ? static_cast<size_t>(amount) : 0;
  }

 private:
  HalFile& file;
};

bool copyText(char* destination, const size_t capacity, const char* source) {
  if (!destination || capacity == 0 || !source) return false;
  const size_t length = std::strlen(source);
  if (length >= capacity) return false;
  std::memcpy(destination, source, length + 1);
  return true;
}

bool isDecimalCursor(const char* value) {
  if (!value || value[0] == '\0' || std::strlen(value) >= 24) return false;
  for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value); *cursor; ++cursor) {
    if (!std::isdigit(*cursor)) return false;
  }
  return true;
}

bool parseDecimalUint64(const char* value, uint64_t& result) {
  if (!isDecimalCursor(value)) return false;
  result = 0;
  for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value); *cursor; ++cursor) {
    const uint8_t digit = static_cast<uint8_t>(*cursor - '0');
    if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10U) return false;
    result = result * 10U + digit;
  }
  return true;
}

bool isBoundedAscii(const char* value, const size_t maxLength, const bool allowEmpty = false) {
  if (!value) return false;
  const size_t length = std::strlen(value);
  if ((!allowEmpty && length == 0) || length > maxLength) return false;
  for (size_t i = 0; i < length; ++i) {
    const unsigned char c = static_cast<unsigned char>(value[i]);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

bool digestMatches(const uint8_t digest[32], const char* expected) {
  if (!xtinct::sync_v2::isSha256(expected)) return false;
  uint8_t difference = 0;
  for (size_t i = 0; i < 32; ++i) {
    auto nibble = [](const char c) -> uint8_t {
      return c >= '0' && c <= '9' ? static_cast<uint8_t>(c - '0') : static_cast<uint8_t>(c - 'a' + 10);
    };
    const uint8_t expectedByte = static_cast<uint8_t>((nibble(expected[i * 2]) << 4) | nibble(expected[i * 2 + 1]));
    difference |= digest[i] ^ expectedByte;
  }
  return difference == 0;
}

bool ensureDirectories() {
  return (Storage.exists(ROOT_DIR) || Storage.mkdir(ROOT_DIR)) &&
         (Storage.exists(INBOX_DIR) || Storage.mkdir(INBOX_DIR)) &&
          (Storage.exists(ARTIFACT_DIR) || Storage.mkdir(ARTIFACT_DIR));
}

struct AtomicStorageOps {
  bool exists(const char* path) const { return Storage.exists(path); }
  bool remove(const char* path) const { return Storage.remove(path); }
  bool rename(const char* source, const char* destination) const {
    return Storage.rename(source, destination);
  }
};

const char* atomicResultName(const xtinct::atomic_file::Result result) {
  using xtinct::atomic_file::Result;
  switch (result) {
    case Result::Ok: return "ok";
    case Result::InvalidPath: return "invalid-path";
    case Result::MissingTemporary: return "missing-temporary";
    case Result::MissingFinal: return "missing-final";
    case Result::UnexpectedBackup: return "unexpected-backup";
    case Result::RemoveTemporaryFailed: return "remove-temporary-failed";
    case Result::RemoveBackupFailed: return "remove-backup-failed";
    case Result::MoveOriginalToBackupFailed: return "move-original-to-backup-failed";
    case Result::PromoteFailedNoPrevious: return "promote-failed-no-previous";
    case Result::PromoteFailedRestored: return "promote-failed-restored";
    case Result::PromoteFailedRestoreFailed: return "promote-failed-restore-failed";
    case Result::RestoreBackupFailed: return "restore-backup-failed";
    case Result::ParkReplacementFailed: return "park-replacement-failed";
    case Result::RollbackRestoreFailed: return "rollback-restore-failed";
    case Result::PreviousFinalMissing: return "previous-final-missing";
    case Result::RemoveReplacementFailed: return "remove-replacement-failed";
  }
  return "unknown";
}

bool atomicPaths(const char* finalPath, char* temporaryPath, const size_t temporarySize,
                 char* backupPath, const size_t backupSize) {
  if (!finalPath || !temporaryPath || !backupPath || temporarySize == 0 || backupSize == 0) return false;
  const int temporaryLength = std::snprintf(temporaryPath, temporarySize, "%s.tmp", finalPath);
  const int backupLength = std::snprintf(backupPath, backupSize, "%s.bak", finalPath);
  return temporaryLength > 0 && temporaryLength < static_cast<int>(temporarySize) &&
         backupLength > 0 && backupLength < static_cast<int>(backupSize);
}

bool logAtomicFailure(const char* operation, const char* finalPath,
                      const xtinct::atomic_file::Result result) {
  if (xtinct::atomic_file::succeeded(result)) return true;
  LOG_ERR("XSYNC", "Atomic %s failed for %s: %s", operation, finalPath, atomicResultName(result));
  return false;
}

bool recoverAtomicFile(const char* finalPath) {
  if (!finalPath) return false;
  char backupPath[192];
  char temporaryPath[192];
  if (!atomicPaths(finalPath, temporaryPath, sizeof(temporaryPath), backupPath, sizeof(backupPath))) return false;
  AtomicStorageOps ops;
  return logAtomicFailure("recovery", finalPath,
                          xtinct::atomic_file::recover(ops, finalPath, temporaryPath, backupPath));
}

bool recoverInboxMetadataSidecars() {
  if (!Storage.exists(INBOX_DIR)) return true;
  struct RecoverySet {
    char finalNames[xtinct::sync_v2::MAX_INBOX_ITEMS][38] = {{0}};
    size_t count = 0;
  };
  auto recoveries = makeUniqueNoThrow<RecoverySet>();
  if (!recoveries) {
    LOG_ERR("XSYNC", "Inbox metadata recovery skipped: no heap for fixed path set");
    return false;
  }
  HalFile directory = Storage.open(INBOX_DIR, O_RDONLY);
  if (!directory || !directory.isDirectory()) {
    directory.close();
    return false;
  }
  size_t scannedFiles = 0;
  bool ok = true;
  while (ok) {
    HalFile entry = directory.openNextFile();
    if (!entry) break;
    const bool isDirectory = entry.isDirectory();
    char name[128] = {0};
    const size_t nameLength = entry.getName(name, sizeof(name));
    entry.close();
    if (isDirectory || nameLength == 0 || nameLength >= sizeof(name) ||
        ++scannedFiles >= MAX_INBOX_ATOMIC_SCAN_FILES) {
      ok = false;
      break;
    }
    char finalName[38];
    if (!xtinct::sync_v2::managedMetadataSidecarFinalName(name, finalName)) continue;
    bool known = false;
    for (size_t index = 0; index < recoveries->count; ++index) {
      if (std::strcmp(recoveries->finalNames[index], finalName) == 0) {
        known = true;
        break;
      }
    }
    if (!known &&
        (recoveries->count >= xtinct::sync_v2::MAX_INBOX_ITEMS ||
         !copyText(recoveries->finalNames[recoveries->count],
                   sizeof(recoveries->finalNames[recoveries->count]), finalName))) {
      ok = false;
      break;
    }
    if (!known) ++recoveries->count;
  }
  directory.close();
  if (!ok) {
    LOG_ERR("XSYNC", "Inbox metadata sidecar recovery failed or exceeded its bound");
    return false;
  }

  // Do not mutate a FAT directory while openNextFile() is walking it: an
  // entry skipped after a remove/rename could hide the only metadata backup
  // from the subsequent artifact reference scan.
  for (size_t index = 0; index < recoveries->count; ++index) {
    char finalPath[160];
    if (std::snprintf(finalPath, sizeof(finalPath), "%s/%s", INBOX_DIR,
                      recoveries->finalNames[index]) >= static_cast<int>(sizeof(finalPath)) ||
        !recoverAtomicFile(finalPath)) {
      return false;
    }
  }
  return true;
}

bool promoteAtomic(const char* temporaryPath, const char* finalPath, bool& previousExisted) {
  char backupPath[192];
  if (std::snprintf(backupPath, sizeof(backupPath), "%s.bak", finalPath) >= static_cast<int>(sizeof(backupPath))) {
    return false;
  }
  AtomicStorageOps ops;
  return logAtomicFailure("promotion", finalPath,
                          xtinct::atomic_file::promoteRetainingBackup(
                              ops, temporaryPath, finalPath, backupPath, previousExisted));
}

bool commitAtomic(const char* finalPath) {
  char temporaryPath[192];
  char backupPath[192];
  if (!atomicPaths(finalPath, temporaryPath, sizeof(temporaryPath), backupPath, sizeof(backupPath))) return false;
  AtomicStorageOps ops;
  return logAtomicFailure("commit", finalPath,
                          xtinct::atomic_file::commit(ops, finalPath, temporaryPath, backupPath));
}

bool rollbackAtomic(const char* finalPath, const bool previousExisted) {
  char temporaryPath[192];
  char backupPath[192];
  if (!atomicPaths(finalPath, temporaryPath, sizeof(temporaryPath), backupPath, sizeof(backupPath))) return false;
  AtomicStorageOps ops;
  return logAtomicFailure("rollback", finalPath,
                          xtinct::atomic_file::rollback(
                              ops, finalPath, temporaryPath, backupPath, previousExisted));
}

bool removeTemporaryAtomic(const char* temporaryPath) {
  if (!temporaryPath || !Storage.exists(temporaryPath)) return true;
  if (Storage.remove(temporaryPath)) return true;
  LOG_ERR("XSYNC", "Could not remove atomic temporary file %s", temporaryPath);
  return false;
}

bool writeAtomic(const char* path, const char* value, const size_t length) {
  if (!path || !value || !recoverAtomicFile(path)) return false;
  char temporaryPath[192];
  if (std::snprintf(temporaryPath, sizeof(temporaryPath), "%s.tmp", path) >=
      static_cast<int>(sizeof(temporaryPath))) {
    return false;
  }
  if (Storage.exists(temporaryPath) && !Storage.remove(temporaryPath)) return false;
  HalFile file;
  if (!Storage.openFileForWrite("XSYNC", temporaryPath, file)) return false;
  const bool durable = xtinct::file_transfer::finishDurableWrite(file, file.write(value, length) == length);
  bool previousExisted = false;
  if (!durable || !promoteAtomic(temporaryPath, path, previousExisted)) {
    removeTemporaryAtomic(temporaryPath);
    return false;
  }
  return commitAtomic(path);
}

bool writeAtomic(const char* path, const std::string& value) { return writeAtomic(path, value.data(), value.size()); }

bool removeAtomicIfPresent(const char* path) {
  if (!recoverAtomicFile(path)) return false;
  return !Storage.exists(path) || Storage.remove(path);
}

bool invalidateFastIndex() {
  return removeAtomicIfPresent(LEGACY_FAST_FIRST_PAGE_PATH) &&
         removeAtomicIfPresent(FAST_FIRST_PAGE_PATH);
}

bool invalidateFastFirstPage() {
  return invalidateFastIndex() && removeAtomicIfPresent(SYNC_COMPLETE_PATH);
}

bool metadataPath(const char* itemId, char* path, const size_t pathSize) {
  if (!xtinct::sync_v2::isSafeId(itemId) || !path || pathSize == 0) return false;
  const int written = std::snprintf(path, pathSize, "%s/%s.json", INBOX_DIR, itemId);
  return written > 0 && written < static_cast<int>(pathSize);
}

bool artifactPathFor(const XtinctInboxItem& item, char* path, const size_t pathSize) {
  if (!xtinct::sync_v2::isSha256(item.sha256) || item.kind == Kind::Invalid || !path || pathSize == 0) return false;
  const int written = std::snprintf(path, pathSize, "%s/%s%s", ARTIFACT_DIR, item.sha256,
                                    xtinct::sync_v2::extensionForKind(item.kind));
  return written > 0 && written < static_cast<int>(pathSize);
}

uint8_t parseActions(const JsonArrayConst actions, bool& valid) {
  uint8_t result = 0;
  valid = actions.size() <= 5;
  for (const JsonVariantConst actionValue : actions) {
    const char* action = actionValue.as<const char*>();
    uint8_t bit = 0;
    if (action && std::strcmp(action, "keep") == 0) bit = XTINCT_ACTION_KEEP;
    else if (action && std::strcmp(action, "archive") == 0) bit = XTINCT_ACTION_ARCHIVE;
    else if (action && std::strcmp(action, "done") == 0) bit = XTINCT_ACTION_DONE;
    else if (action && std::strcmp(action, "defer") == 0) bit = XTINCT_ACTION_DEFER;
    else if (action && std::strcmp(action, "open-phone") == 0) bit = XTINCT_ACTION_OPEN_PHONE;
    else if (action && std::strcmp(action, "like") == 0) bit = XTINCT_ACTION_LIKE;
    else if (action && std::strcmp(action, "dislike") == 0) bit = XTINCT_ACTION_DISLIKE;
    else valid = false;
    if ((result & bit) != 0) valid = false;
    result |= bit;
  }
  return result;
}

bool parseInboxDigest(const JsonVariantConst value, xtinct::inbox_digest_contract::Digest& digest) {
  digest = {};
  if (value.isNull()) return true;
  if (!value.is<JsonObjectConst>()) return false;
  const JsonObjectConst object = value.as<JsonObjectConst>();
  if (!xtinct::inbox_digest_contract::hasExactObjectShape(
          object.size(), object["schema"].is<const char*>(),
          object["summary"].is<const char*>(), object["points"].is<JsonArrayConst>())) {
    return false;
  }

  const JsonString schema = object["schema"].as<JsonString>();
  const JsonString summary = object["summary"].as<JsonString>();
  const JsonArrayConst pointValues = object["points"].as<JsonArrayConst>();
  if (schema.isNull() || summary.isNull() ||
      pointValues.size() > xtinct::inbox_digest_contract::MAX_POINTS) {
    return false;
  }
  xtinct::inbox_digest_contract::TextSpan points[xtinct::inbox_digest_contract::MAX_POINTS] = {};
  size_t pointCount = 0;
  for (const JsonVariantConst pointValue : pointValues) {
    if (!pointValue.is<const char*>()) return false;
    const JsonString point = pointValue.as<JsonString>();
    if (point.isNull()) return false;
    points[pointCount++] = {point.c_str(), point.size()};
  }
  return xtinct::inbox_digest_contract::assign(
      digest, {schema.c_str(), schema.size()}, {summary.c_str(), summary.size()}, points, pointCount);
}

bool parseDelivery(const JsonObjectConst object, XtinctInboxItem& item) {
  std::memset(&item, 0, sizeof(item));
  const char* deliveryId = object["delivery_id"] | "";
  const char* itemId = object["item_id"] | "";
  const char* moduleId = object["module_id"] | "";
  const char* kindValue = object["kind"] | "";
  const char* title = object["title"] | "";
  const char* revision = object["revision"] | "";
  const char* sha256 = object["sha256"] | "";
  const char* mime = object["mime"] | "";
  const char* createdAt = object["created_at"] | "";
  const char* expiresAt = object["expires_at"].isNull() ? "" : (object["expires_at"] | "");
  const uint64_t bytes = object["bytes"] | static_cast<uint64_t>(0);
  const Kind kind = xtinct::sync_v2::parseKind(kindValue);
  if (!xtinct::sync_v2::isSafeId(deliveryId) || !xtinct::sync_v2::isSafeId(itemId) ||
      !xtinct::sync_v2::isSafeId(moduleId) || kind == Kind::Invalid || std::strlen(title) == 0 ||
      std::strlen(title) > xtinct::sync_v2::MAX_TITLE_BYTES || !xtinct::sync_v2::isSha256(revision) ||
      !xtinct::sync_v2::isSha256(sha256) || bytes == 0 || bytes > xtinct::sync_v2::MAX_ARTIFACT_BYTES ||
      !xtinct::sync_v2::mimeAllowed(kind, mime) || !isBoundedAscii(createdAt, 39) ||
      !isBoundedAscii(expiresAt, 39, true)) {
    return false;
  }
  if (!object["actions"].is<JsonArrayConst>() ||
      (!object["metadata"].isNull() && !object["metadata"].is<JsonObjectConst>()) ||
      (!object["metadata"].isNull() && measureJson(object["metadata"]) > xtinct::sync_v2::MAX_METADATA_BYTES)) {
    return false;
  }
  xtinct::inbox_digest_contract::Digest digest;
  if (!parseInboxDigest(object["metadata"]["digest"], digest)) return false;
  bool actionsValid = false;
  const uint8_t actions = parseActions(object["actions"].as<JsonArrayConst>(), actionsValid);
  if (!actionsValid) return false;
  if (!copyText(item.deliveryId, sizeof(item.deliveryId), deliveryId) ||
      !copyText(item.itemId, sizeof(item.itemId), itemId) || !copyText(item.moduleId, sizeof(item.moduleId), moduleId) ||
      !copyText(item.title, sizeof(item.title), title) || !copyText(item.revision, sizeof(item.revision), revision) ||
      !copyText(item.sha256, sizeof(item.sha256), sha256) || !copyText(item.mime, sizeof(item.mime), mime) ||
      !copyText(item.createdAt, sizeof(item.createdAt), createdAt) ||
      !copyText(item.expiresAt, sizeof(item.expiresAt), expiresAt) || !copyText(item.state, sizeof(item.state), "new")) {
    return false;
  }
  item.kind = kind;
  item.bytes = static_cast<uint32_t>(bytes);
  item.actions = actions;
  item.activateSleepScreen = object["metadata"]["activate"] | false;
  item.digest = digest;
  if (item.kind != Kind::SleepScreen && item.activateSleepScreen) return false;
  return true;
}

bool parseSyncPage(char* body, const size_t bodyLength, SyncPage& page) {
  if (!body || bodyLength == 0 || bodyLength > MAX_SYNC_BODY_BYTES) return false;
  std::memset(&page, 0, sizeof(page));
  JsonDocument document;
  // Mutable input enables ArduinoJson's zero-copy string mode. The bounded
  // response buffer remains alive until every fixed-size field is copied.
  const DeserializationError error = deserializeJson(document, body, bodyLength);
  if (error || (document["schema"] | 0) != 2) return false;
  const char* deviceId = document["device_id"] | "";
  const char* cursor = document["cursor"] | "";
  if (!xtinct::sync_v2::isSafeId(deviceId) || !isDecimalCursor(cursor) ||
      !document["deliveries"].is<JsonArrayConst>() || !document["tombstones"].is<JsonArrayConst>()) {
    return false;
  }
  const JsonArrayConst deliveries = document["deliveries"].as<JsonArrayConst>();
  const JsonArrayConst tombstones = document["tombstones"].as<JsonArrayConst>();
  if (deliveries.size() > xtinct::inbox_sync_paging::DIRECT_PAGE_CHANGES ||
      tombstones.size() > xtinct::inbox_sync_paging::DIRECT_PAGE_CHANGES ||
      deliveries.size() + tombstones.size() > xtinct::inbox_sync_paging::DIRECT_PAGE_CHANGES ||
      !copyText(page.deviceId, sizeof(page.deviceId), deviceId) || !copyText(page.cursor, sizeof(page.cursor), cursor)) {
    return false;
  }
  page.hasMore = document["has_more"] | false;
  for (const JsonObjectConst deliveryObject : deliveries) {
    if (!parseDelivery(deliveryObject, page.deliveries[page.deliveryCount].item)) return false;
    for (uint8_t existing = 0; existing < page.deliveryCount; ++existing) {
      if (std::strcmp(page.deliveries[existing].item.itemId, page.deliveries[page.deliveryCount].item.itemId) == 0) {
        return false;
      }
    }
    ++page.deliveryCount;
  }
  for (const JsonObjectConst tombstoneObject : tombstones) {
    Tombstone& tombstone = page.tombstones[page.tombstoneCount];
    const char* deliveryId = tombstoneObject["delivery_id"] | "";
    const char* itemId = tombstoneObject["item_id"] | "";
    const char* revision = tombstoneObject["revision"] | "";
    const char* deletedAt = tombstoneObject["deleted_at"] | "";
    if (!xtinct::sync_v2::isSafeId(deliveryId) || !xtinct::sync_v2::isSafeId(itemId) ||
        !xtinct::sync_v2::isSha256(revision) || !isBoundedAscii(deletedAt, 39) ||
        !copyText(tombstone.deliveryId, sizeof(tombstone.deliveryId), deliveryId) ||
        !copyText(tombstone.itemId, sizeof(tombstone.itemId), itemId) ||
        !copyText(tombstone.revision, sizeof(tombstone.revision), revision)) {
      return false;
    }
    ++page.tombstoneCount;
  }
  return true;
}

bool parseMetadata(const char* path, XtinctInboxItem& item) {
  if (!recoverAtomicFile(path)) return false;
  HalFile file;
  if (!Storage.openFileForRead("XSYNC", path, file)) return false;
  const uint64_t bytes = file.fileSize64();
  if (!xtinct::network_persistence::boundedFileSizeAllowed(bytes, MAX_META_FILE_BYTES)) {
    file.close();
    return false;
  }
  HalJsonReader reader(file);
  JsonDocument document;
  const DeserializationError error = deserializeJson(document, reader);
  const bool closed = file.close();
  if (!closed || error || (document["schema"] | 0) != 2) return false;
  JsonObjectConst object = document.as<JsonObjectConst>();
  // Reuse delivery validation, then restore the local state field.
  if (!parseDelivery(object, item)) return false;
  const char* state = object["state"] | "new";
  return isBoundedAscii(state, 15) && copyText(item.state, sizeof(item.state), state);
}

bool writeMetadataAtPath(const XtinctInboxItem& item, const char* path,
                         const bool orderingMayChange = true) {
  if (!path || path[0] == '\0' || !xtinct::inbox_digest_contract::isWellFormed(item.digest)) return false;
  // The index is only an acceleration layer. Remove it before any mutation
  // that could change which items belong on the first page, so a reset between
  // the metadata and cursor commits can only cause a safe slow scan.
  if (orderingMayChange && !invalidateFastFirstPage()) return false;
  JsonDocument document;
  document["schema"] = 2;
  document["delivery_id"] = item.deliveryId;
  document["item_id"] = item.itemId;
  document["module_id"] = item.moduleId;
  document["kind"] = xtinct::sync_v2::kindName(item.kind);
  document["title"] = item.title;
  document["revision"] = item.revision;
  document["sha256"] = item.sha256;
  document["bytes"] = item.bytes;
  document["mime"] = item.mime;
  document["created_at"] = item.createdAt;
  if (item.expiresAt[0] == '\0') document["expires_at"] = nullptr;
  else document["expires_at"] = item.expiresAt;
  document["state"] = item.state;
  JsonArray actions = document["actions"].to<JsonArray>();
  if (item.actions & XTINCT_ACTION_KEEP) actions.add("keep");
  if (item.actions & XTINCT_ACTION_ARCHIVE) actions.add("archive");
  if (item.actions & XTINCT_ACTION_DONE) actions.add("done");
  if (item.actions & XTINCT_ACTION_DEFER) actions.add("defer");
  if (item.actions & XTINCT_ACTION_OPEN_PHONE) actions.add("open-phone");
  if (item.actions & XTINCT_ACTION_LIKE) actions.add("like");
  if (item.actions & XTINCT_ACTION_DISLIKE) actions.add("dislike");
  JsonObject metadata = document["metadata"].to<JsonObject>();
  if (item.kind == Kind::SleepScreen) metadata["activate"] = item.activateSleepScreen;
  if (xtinct::inbox_digest_contract::isPresent(item.digest)) {
    JsonObject digest = metadata["digest"].to<JsonObject>();
    digest["schema"] = xtinct::inbox_digest_contract::SCHEMA;
    digest["summary"] = item.digest.summary;
    JsonArray points = digest["points"].to<JsonArray>();
    for (uint8_t index = 0; index < item.digest.pointCount; ++index) {
      points.add(item.digest.points[index]);
    }
  }
  const size_t bytes = measureJson(document);
  xtinct::network::BoundedResponseBuffer output(MAX_META_FILE_BYTES);
  if (document.overflowed() || bytes == 0 || bytes > MAX_META_FILE_BYTES ||
      !output.reserve(bytes) || serializeJson(document, output.data(), bytes + 1) != bytes) {
    return false;
  }
  return writeAtomic(path, output.data(), bytes);
}

bool writeMetadata(const XtinctInboxItem& item, const bool orderingMayChange = true) {
  char path[128];
  return metadataPath(item.itemId, path, sizeof(path)) &&
         writeMetadataAtPath(item, path, orderingMayChange);
}

bool validateArtifactFile(const XtinctInboxItem& item, const char* path) {
  HalFile file;
  if (!Storage.openFileForRead("XSYNC", path, file) || file.fileSize64() != item.bytes) return false;
  Sha256Scope sha;
  if (mbedtls_sha256_starts(&sha.context, 0) != 0) return false;
  uint8_t header[xtinct::sync_v2::X3_SLEEP_BMP_PIXEL_OFFSET] = {0};
  size_t headerBytes = 0;
  uint8_t buffer[1024];
  uint32_t remaining = item.bytes;
  const bool validateUtf8 = item.kind == Kind::Card || item.kind == Kind::Text || item.kind == Kind::Action;
  xtinct::sync_v2::Utf8Validator utf8;
  while (remaining > 0) {
    const size_t wanted = std::min<size_t>(sizeof(buffer), remaining);
    const int read = file.read(buffer, wanted);
    if (read <= 0 || static_cast<size_t>(read) != wanted ||
        mbedtls_sha256_update(&sha.context, buffer, wanted) != 0) {
      file.close();
      return false;
    }
    if (headerBytes < sizeof(header)) {
      const size_t copied = std::min(sizeof(header) - headerBytes, wanted);
      std::memcpy(header + headerBytes, buffer, copied);
      headerBytes += copied;
    }
    if (validateUtf8) utf8.feed(buffer, wanted);
    remaining -= static_cast<uint32_t>(wanted);
  }
  file.close();
  uint8_t digest[32];
  if (mbedtls_sha256_finish(&sha.context, digest) != 0 || !digestMatches(digest, item.sha256)) return false;
  if (item.kind == Kind::Image1Bit &&
      !xtinct::sync_v2::isX3OneBitBmpHeader(header, headerBytes, item.bytes)) {
    return false;
  }
  if (item.kind == Kind::SleepScreen &&
      !xtinct::sync_v2::isX3NativeSleepBmpHeader(header, headerBytes, item.bytes)) {
    return false;
  }
  if (item.kind == Kind::Epub && !xtinct::sync_v2::isEpubHeader(header, headerBytes)) return false;
  if (validateUtf8 && !utf8.complete()) return false;
  return true;
}

bool fileDigestHex(const char* path, const uint32_t maximumBytes, char output[65]) {
  if (!path || !output || !Storage.exists(path)) return false;
  HalFile file;
  if (!Storage.openFileForRead("XSYNC", path, file)) return false;
  const uint64_t bytes = file.fileSize64();
  if (!xtinct::network_persistence::boundedFileSizeAllowed(bytes, maximumBytes)) {
    file.close();
    return false;
  }
  Sha256Scope sha;
  if (mbedtls_sha256_starts(&sha.context, 0) != 0) {
    file.close();
    return false;
  }
  uint8_t buffer[512];
  uint64_t remaining = bytes;
  while (remaining > 0) {
    const size_t wanted = std::min<uint64_t>(sizeof(buffer), remaining);
    const int count = file.read(buffer, wanted);
    if (count <= 0 || static_cast<size_t>(count) != wanted ||
        mbedtls_sha256_update(&sha.context, buffer, wanted) != 0) {
      file.close();
      return false;
    }
    remaining -= wanted;
  }
  const bool closed = file.close();
  uint8_t digest[32];
  if (!closed || mbedtls_sha256_finish(&sha.context, digest) != 0) return false;
  constexpr char HEX_DIGITS[] = "0123456789abcdef";
  for (size_t index = 0; index < 32; ++index) {
    output[index * 2] = HEX_DIGITS[digest[index] >> 4];
    output[index * 2 + 1] = HEX_DIGITS[digest[index] & 0x0f];
  }
  output[64] = '\0';
  return true;
}

bool fileDigestMatches(const char* path, const uint32_t maximumBytes, const char* expectedSha256) {
  if (!xtinct::sync_v2::isSha256(expectedSha256)) return false;
  char actual[65];
  return fileDigestHex(path, maximumBytes, actual) && std::strcmp(actual, expectedSha256) == 0;
}

struct SleepActivationPlan {
  uint8_t previousMode = 0;
  bool previousExisted = false;
  char previousSha256[65] = {0};
  char targetSha256[65] = {0};
};

bool removeSleepActivationPlan() {
  if (!recoverAtomicFile(SLEEP_ACTIVATION_PATH)) return false;
  if (!Storage.exists(SLEEP_ACTIVATION_PATH)) return true;
  if (Storage.remove(SLEEP_ACTIVATION_PATH)) return true;
  LOG_ERR("XSYNC", "Could not remove committed sleep activation journal");
  return false;
}

bool writeSleepActivationPlan(const SleepActivationPlan& plan) {
  JsonDocument document;
  document["schema"] = 1;
  document["previous_mode"] = plan.previousMode;
  document["previous_existed"] = plan.previousExisted;
  document["previous_sha256"] = plan.previousSha256;
  document["target_sha256"] = plan.targetSha256;
  char encoded[384];
  const size_t bytes = serializeJson(document, encoded, sizeof(encoded));
  return !document.overflowed() && document.size() == 5 && bytes > 0 && bytes < sizeof(encoded) &&
         writeAtomic(SLEEP_ACTIVATION_PATH, encoded, bytes);
}

bool readSleepActivationPlan(SleepActivationPlan& plan) {
  plan = {};
  if (!recoverAtomicFile(SLEEP_ACTIVATION_PATH) || !Storage.exists(SLEEP_ACTIVATION_PATH)) return false;
  HalFile file;
  if (!Storage.openFileForRead("XSYNC", SLEEP_ACTIVATION_PATH, file)) return false;
  const uint64_t bytes = file.fileSize64();
  if (!xtinct::network_persistence::boundedFileSizeAllowed(bytes, 384)) {
    file.close();
    return false;
  }
  HalJsonReader reader(file);
  JsonDocument document;
  const DeserializationError error = deserializeJson(document, reader);
  const bool closed = file.close();
  if (!closed || error || !document.is<JsonObjectConst>()) return false;
  JsonObjectConst object = document.as<JsonObjectConst>();
  const int previousMode = object["previous_mode"] | -1;
  if (object.size() != 5 || (object["schema"] | 0) != 1 ||
      previousMode < 0 || previousMode >= CrossPointSettings::SLEEP_SCREEN_MODE_COUNT ||
      !object["previous_existed"].is<bool>() ||
      !copyText(plan.previousSha256, sizeof(plan.previousSha256), object["previous_sha256"] | "") ||
      !copyText(plan.targetSha256, sizeof(plan.targetSha256), object["target_sha256"] | "") ||
      !xtinct::sync_v2::isSha256(plan.targetSha256)) {
    return false;
  }
  plan.previousMode = static_cast<uint8_t>(previousMode);
  plan.previousExisted = object["previous_existed"].as<bool>();
  return plan.previousExisted == xtinct::sync_v2::isSha256(plan.previousSha256);
}

bool recoverSleepScreenActivation() {
  constexpr char finalPath[] = "/sleep.bmp";
  constexpr char temporaryPath[] = "/sleep.bmp.tmp";
  constexpr char backupPath[] = "/sleep.bmp.bak";
  if (!recoverAtomicFile(SLEEP_ACTIVATION_PATH)) return false;
  if (!Storage.exists(SLEEP_ACTIVATION_PATH)) return recoverAtomicFile(finalPath);

  SleepActivationPlan plan;
  if (!readSleepActivationPlan(plan)) {
    LOG_ERR("XSYNC", "Refusing malformed sleep activation journal");
    return false;
  }
  const bool finalExists = Storage.exists(finalPath);
  const bool temporaryExists = Storage.exists(temporaryPath);
  const bool backupExists = Storage.exists(backupPath);
  const bool finalTarget = finalExists &&
      fileDigestMatches(finalPath, xtinct::sync_v2::MAX_ARTIFACT_BYTES, plan.targetSha256);
  const bool finalPrevious = plan.previousExisted && finalExists &&
      fileDigestMatches(finalPath, xtinct::sync_v2::MAX_ARTIFACT_BYTES, plan.previousSha256);
  const bool tempTarget = temporaryExists &&
      fileDigestMatches(temporaryPath, xtinct::sync_v2::MAX_ARTIFACT_BYTES, plan.targetSha256);
  const bool backupPrevious = plan.previousExisted && backupExists &&
      fileDigestMatches(backupPath, xtinct::sync_v2::MAX_ARTIFACT_BYTES, plan.previousSha256);
  const bool settingsCommitted =
      plan.previousMode == CrossPointSettings::CUSTOM || SETTINGS.sleepScreen == CrossPointSettings::CUSTOM;
  switch (xtinct::network_persistence::sleepRecoveryDirection(
      plan.previousExisted, settingsCommitted, finalExists, finalPrevious, finalTarget,
      temporaryExists, tempTarget, backupExists, backupPrevious)) {
    case xtinct::network_persistence::SleepRecoveryDirection::FinishCommit:
      return commitAtomic(finalPath) && removeSleepActivationPlan();
    case xtinct::network_persistence::SleepRecoveryDirection::RollBack:
      if (!rollbackAtomic(finalPath, plan.previousExisted)) return false;
      SETTINGS.sleepScreen = plan.previousMode;
      if (!SETTINGS.saveToFile()) return false;
      return removeSleepActivationPlan();
    case xtinct::network_persistence::SleepRecoveryDirection::FailClosed:
      LOG_ERR("XSYNC", "Refusing sleep activation recovery with an unknown file identity");
      return false;
  }
  return false;
}

XtinctSyncClient::SyncResult downloadArtifact(freeink::SecureHttpClient& http, const XtinctInboxItem& item) {
  char finalPath[160];
  if (!artifactPathFor(item, finalPath, sizeof(finalPath))) return XtinctSyncClient::SyncResult::INVALID_DATA;
  if (!recoverAtomicFile(finalPath)) return XtinctSyncClient::SyncResult::STORAGE_ERROR;
  if (Storage.exists(finalPath) && validateArtifactFile(item, finalPath)) return XtinctSyncClient::SyncResult::CURRENT;

  char temporaryPath[176];
  if (std::snprintf(temporaryPath, sizeof(temporaryPath), "%s.tmp", finalPath) >=
      static_cast<int>(sizeof(temporaryPath))) {
    return XtinctSyncClient::SyncResult::STORAGE_ERROR;
  }
  if (Storage.exists(temporaryPath) && !Storage.remove(temporaryPath)) return XtinctSyncClient::SyncResult::STORAGE_ERROR;
  HalFile file;
  if (!Storage.openFileForWrite("XSYNC", temporaryPath, file)) return XtinctSyncClient::SyncResult::STORAGE_ERROR;

  Sha256Scope sha;
  if (mbedtls_sha256_starts(&sha.context, 0) != 0) {
    file.close();
    return removeTemporaryAtomic(temporaryPath) ? XtinctSyncClient::SyncResult::INVALID_DATA
                                                : XtinctSyncClient::SyncResult::STORAGE_ERROR;
  }
  const std::string url = XTINCT_FEED_CONFIG.getBaseUrl() + "/v2/artifacts/" + item.sha256;
  if (!http.begin(url)) {
    file.close();
    return removeTemporaryAtomic(temporaryPath) ? XtinctSyncClient::SyncResult::NETWORK_ERROR
                                                : XtinctSyncClient::SyncResult::STORAGE_ERROR;
  }
  http.addHeader("Accept", item.mime);
  http.addHeader("Authorization", std::string("Bearer ") + XTINCT_FEED_CONFIG.getReadToken());
  size_t received = 0;
  bool overflow = false;
  bool writeFailed = false;
  bool hashFailed = false;
  const int status = http.GET([&](const uint8_t* data, const size_t length) {
    if (received > item.bytes || length > item.bytes - received ||
        received > xtinct::sync_v2::MAX_ARTIFACT_BYTES ||
        length > xtinct::sync_v2::MAX_ARTIFACT_BYTES - received) {
      overflow = true;
      return false;
    }
    if (file.write(data, length) != length) {
      writeFailed = true;
      return false;
    }
    if (mbedtls_sha256_update(&sha.context, data, length) != 0) {
      hashFailed = true;
      return false;
    }
    received += length;
    return true;
  });
  const bool durable = xtinct::file_transfer::finishDurableWrite(file, !writeFailed);

  XtinctSyncClient::SyncResult failure = XtinctSyncClient::SyncResult::UPDATED;
  const std::string responseMime = http.getHeader("content-type");
  const std::string responseEtag = http.getHeader("etag");
  const std::string responseNosniff = http.getHeader("x-content-type-options");
  const bool hasContentLength = http.hasContentLength();
  const size_t contentLength = hasContentLength ? http.getContentLength() : 0;
  const bool callbackAborted = http.callbackAborted();
  const bool transportAborted = http.aborted();
  const bool responseComplete = http.responseComplete();
  http.end();  // Release TLS before SHA finalization, promotion and full readback.
  const std::string expectedEtag = std::string("\"") + item.sha256 + "\"";
  if (status == 401 || status == 403) failure = XtinctSyncClient::SyncResult::UNAUTHORIZED;
  else if (status != 200) failure = XtinctSyncClient::SyncResult::NETWORK_ERROR;
  else if (!durable) failure = XtinctSyncClient::SyncResult::STORAGE_ERROR;
  else if (overflow || hashFailed || received != item.bytes || !hasContentLength ||
           contentLength != item.bytes || responseMime != item.mime || responseEtag != expectedEtag ||
           responseNosniff != "nosniff" || (callbackAborted && !transportAborted)) {
    failure = XtinctSyncClient::SyncResult::INVALID_DATA;
  } else if (!responseComplete || transportAborted) {
    failure = XtinctSyncClient::SyncResult::NETWORK_ERROR;
  }
  uint8_t digest[32];
  if (failure == XtinctSyncClient::SyncResult::UPDATED &&
      (mbedtls_sha256_finish(&sha.context, digest) != 0 || !digestMatches(digest, item.sha256))) {
    failure = XtinctSyncClient::SyncResult::INVALID_DATA;
  }
  if (failure != XtinctSyncClient::SyncResult::UPDATED) {
    if (!removeTemporaryAtomic(temporaryPath)) return XtinctSyncClient::SyncResult::STORAGE_ERROR;
    return failure;
  }

  bool previousExisted = false;
  if (!promoteAtomic(temporaryPath, finalPath, previousExisted)) {
    if (!removeTemporaryAtomic(temporaryPath)) return XtinctSyncClient::SyncResult::STORAGE_ERROR;
    return XtinctSyncClient::SyncResult::STORAGE_ERROR;
  }
  if (!validateArtifactFile(item, finalPath)) {
    if (!rollbackAtomic(finalPath, previousExisted)) {
      LOG_ERR("XSYNC", "Artifact readback failed and rollback could not restore %s", finalPath);
    }
    return XtinctSyncClient::SyncResult::STORAGE_ERROR;
  }
  if (!commitAtomic(finalPath)) return XtinctSyncClient::SyncResult::STORAGE_ERROR;
  return XtinctSyncClient::SyncResult::UPDATED;
}

bool activateSleepScreen(const XtinctInboxItem& item) {
  if (!recoverSleepScreenActivation()) return false;
  char sourcePath[160];
  if (!artifactPathFor(item, sourcePath, sizeof(sourcePath)) || !recoverAtomicFile(sourcePath) ||
      !validateArtifactFile(item, sourcePath)) {
    return false;
  }
  constexpr char finalPath[] = "/sleep.bmp";
  constexpr char temporaryPath[] = "/sleep.bmp.tmp";
  if (!recoverAtomicFile(finalPath)) return false;
  SleepActivationPlan activationPlan;
  activationPlan.previousMode = SETTINGS.sleepScreen;
  activationPlan.previousExisted = Storage.exists(finalPath);
  if (!copyText(activationPlan.targetSha256, sizeof(activationPlan.targetSha256), item.sha256) ||
      (activationPlan.previousExisted &&
       !fileDigestHex(finalPath, xtinct::sync_v2::MAX_ARTIFACT_BYTES,
                      activationPlan.previousSha256))) {
    return false;
  }
  if (Storage.exists(temporaryPath) && !Storage.remove(temporaryPath)) return false;
  HalFile source;
  HalFile target;
  if (!Storage.openFileForRead("XSYNC", sourcePath, source) ||
      !Storage.openFileForWrite("XSYNC", temporaryPath, target)) {
    source.close();
    target.close();
    if (!removeTemporaryAtomic(temporaryPath)) {
      LOG_ERR("XSYNC", "Could not clean an incomplete sleep-screen staging file");
    }
    return false;
  }
  uint8_t buffer[1024];
  uint32_t copied = 0;
  bool ok = true;
  while (copied < item.bytes) {
    const size_t wanted = std::min<size_t>(sizeof(buffer), item.bytes - copied);
    const int read = source.read(buffer, wanted);
    if (read <= 0 || static_cast<size_t>(read) != wanted || target.write(buffer, wanted) != wanted) {
      ok = false;
      break;
    }
    copied += static_cast<uint32_t>(wanted);
  }
  const bool durableTarget = xtinct::file_transfer::finishDurableWrite(target, ok);
  const bool sourceCloseOk = source.close();
  if (!durableTarget || !sourceCloseOk || copied != item.bytes || !validateArtifactFile(item, temporaryPath)) {
    if (!removeTemporaryAtomic(temporaryPath)) {
      LOG_ERR("XSYNC", "Sleep-screen staging failed and temporary cleanup also failed");
    }
    return false;
  }

  if (!writeSleepActivationPlan(activationPlan)) {
    removeTemporaryAtomic(temporaryPath);
    return false;
  }

  bool hadPrevious = false;
  if (!promoteAtomic(temporaryPath, finalPath, hadPrevious) ||
      hadPrevious != activationPlan.previousExisted) {
    // Let the durable journal perform the same identity-checked recovery used
    // after a reboot. Generic rollback cannot tell a missing previous final
    // from a newly promoted target when no backup is present.
    if (!recoverSleepScreenActivation()) {
      LOG_ERR("XSYNC", "Sleep activation promotion mismatch remains journaled for recovery");
    }
    return false;
  }
  SETTINGS.sleepScreen = CrossPointSettings::SLEEP_SCREEN_MODE::CUSTOM;
  if (!SETTINGS.saveToFile()) {
    SETTINGS.sleepScreen = activationPlan.previousMode;
    if (!rollbackAtomic(finalPath, activationPlan.previousExisted)) {
      LOG_ERR("XSYNC", "Settings save failed and the prior sleep screen could not be restored");
      return false;
    }
    if (!SETTINGS.saveToFile()) return false;
    if (!removeSleepActivationPlan()) {
      LOG_ERR("XSYNC", "Prior sleep screen restored but activation journal cleanup failed");
    }
    return false;
  }
  return commitAtomic(finalPath) && removeSleepActivationPlan();
}

bool collectUnreferencedArtifacts() {
  if (!Storage.exists(INBOX_DIR) || !Storage.exists(ARTIFACT_DIR)) return true;

  if (!recoverInboxMetadataSidecars()) {
    // Fail closed: without every committed metadata reference, no artifact is
    // safe to classify as unreferenced.
    return true;
  }

  struct ReferencedDigestSet {
    char values[xtinct::sync_v2::MAX_INBOX_ITEMS][65] = {{0}};
    size_t count = 0;
  };
  auto referenced = makeUniqueNoThrow<ReferencedDigestSet>();
  if (!referenced) {
    LOG_ERR("XSYNC", "Artifact GC skipped: no heap for fixed digest set");
    return true;
  }
  size_t metadataEntries = 0;
  HalFile metadataDirectory = Storage.open(INBOX_DIR, O_RDONLY);
  if (!metadataDirectory || !metadataDirectory.isDirectory()) {
    metadataDirectory.close();
    return true;
  }
  bool metadataComplete = true;
  while (metadataComplete) {
    HalFile entry = metadataDirectory.openNextFile();
    if (!entry) break;
    const bool isDirectory = entry.isDirectory();
    char name[128] = {0};
    const size_t nameLength = entry.getName(name, sizeof(name));
    entry.close();
    if (++metadataEntries >= MAX_INBOX_ATOMIC_SCAN_FILES || isDirectory || nameLength == 0 ||
        nameLength >= sizeof(name)) {
      metadataComplete = false;
      break;
    }
    char itemId[33];
    if (!xtinct::sync_v2::managedMetadataItemId(name, itemId)) continue;
    char path[160];
    if (std::snprintf(path, sizeof(path), "%s/%s", INBOX_DIR, name) >= static_cast<int>(sizeof(path))) {
      metadataComplete = false;
      break;
    }
    XtinctInboxItem item;
    if (!parseMetadata(path, item) || std::strcmp(item.itemId, itemId) != 0) {
      metadataComplete = false;
      break;
    }
    bool alreadyReferenced = false;
    for (size_t index = 0; index < referenced->count; ++index) {
      if (std::strcmp(referenced->values[index], item.sha256) == 0) {
        alreadyReferenced = true;
        break;
      }
    }
    if (!alreadyReferenced) {
      if (referenced->count >= xtinct::sync_v2::MAX_INBOX_ITEMS ||
          !copyText(referenced->values[referenced->count], sizeof(referenced->values[referenced->count]),
                    item.sha256)) {
        metadataComplete = false;
        break;
      }
      ++referenced->count;
    }
  }
  metadataDirectory.close();
  if (!metadataComplete) {
    LOG_ERR("XSYNC", "Artifact GC skipped: inbox metadata scan incomplete or over bound");
    return true;
  }

  // First pass proves the artifact directory is bounded before any deletion.
  HalFile artifactDirectory = Storage.open(ARTIFACT_DIR, O_RDONLY);
  if (!artifactDirectory || !artifactDirectory.isDirectory()) {
    artifactDirectory.close();
    return true;
  }
  size_t artifactEntries = 0;
  bool artifactComplete = true;
  while (artifactComplete) {
    HalFile entry = artifactDirectory.openNextFile();
    if (!entry) break;
    const bool isDirectory = entry.isDirectory();
    char name[128] = {0};
    const size_t nameLength = entry.getName(name, sizeof(name));
    entry.close();
    if (++artifactEntries >= MAX_ARTIFACT_SCAN_FILES || isDirectory || nameLength == 0 ||
        nameLength >= sizeof(name)) {
      artifactComplete = false;
    }
  }
  artifactDirectory.close();
  if (!artifactComplete) {
    LOG_ERR("XSYNC", "Artifact GC skipped: artifact directory scan incomplete or over bound");
    return true;
  }

  artifactDirectory = Storage.open(ARTIFACT_DIR, O_RDONLY);
  if (!artifactDirectory || !artifactDirectory.isDirectory()) {
    artifactDirectory.close();
    return true;
  }
  size_t removed = 0;
  bool ok = true;
  size_t secondPassEntries = 0;
  while (ok && removed < MAX_ARTIFACT_REMOVALS_PER_PASS) {
    HalFile entry = artifactDirectory.openNextFile();
    if (!entry) break;
    const bool isDirectory = entry.isDirectory();
    char name[128] = {0};
    const size_t nameLength = entry.getName(name, sizeof(name));
    entry.close();
    if (++secondPassEntries > artifactEntries || isDirectory || nameLength == 0 || nameLength >= sizeof(name)) {
      ok = false;
      break;
    }
    char digest[65];
    if (!xtinct::sync_v2::managedArtifactDigest(name, digest)) continue;
    bool isReferenced = false;
    for (size_t index = 0; index < referenced->count; ++index) {
      if (std::strcmp(referenced->values[index], digest) == 0) {
        isReferenced = true;
        break;
      }
    }
    if (isReferenced) continue;
    char path[176];
    if (std::snprintf(path, sizeof(path), "%s/%s", ARTIFACT_DIR, name) >= static_cast<int>(sizeof(path))) {
      ok = false;
      continue;
    }
    if (Storage.exists(path) && !Storage.remove(path)) {
      ok = false;
      continue;
    }
    ++removed;
  }
  artifactDirectory.close();
  if (!ok) LOG_ERR("XSYNC", "Artifact GC could not remove one or more orphaned files");
  return ok;
}

bool readSmallFileBuffer(const char* path, const size_t maximum,
                         xtinct::network::BoundedResponseBuffer& result) {
  if (!recoverAtomicFile(path)) return false;
  if (!Storage.exists(path)) return true;
  HalFile file;
  if (!Storage.openFileForRead("XSYNC", path, file)) return false;
  const uint64_t bytes = file.fileSize64();
  if (!xtinct::network_persistence::boundedFileSizeAllowed(bytes, maximum, true) ||
      !result.reserve(static_cast<size_t>(bytes))) {
    file.close();
    return false;
  }
  uint8_t buffer[512];
  uint64_t remaining = bytes;
  while (remaining > 0) {
    const size_t wanted = std::min<uint64_t>(sizeof(buffer), remaining);
    const int count = file.read(buffer, wanted);
    if (count <= 0 || static_cast<size_t>(count) != wanted || !result.append(buffer, wanted)) {
      file.close();
      return false;
    }
    remaining -= wanted;
  }
  return file.close();
}

bool readSmallFile(const char* path, const size_t maximum, char* result,
                   const size_t capacity, size_t& resultBytes) {
  resultBytes = 0;
  if (!result || capacity == 0 || maximum >= capacity || maximum > 32) return false;
  result[0] = '\0';
  xtinct::network::BoundedResponseBuffer body(maximum);
  if (!readSmallFileBuffer(path, maximum, body)) return false;
  if (body.size() >= capacity) return false;
  if (body.size() != 0) std::memcpy(result, body.data(), body.size());
  result[body.size()] = '\0';
  resultBytes = body.size();
  return true;
}

enum class OutboxLineResult : uint8_t { End, Line, Malformed, IoError };

OutboxLineResult readOutboxLine(HalFile& file, uint64_t& remaining, char* line,
                                const size_t capacity, size_t& lineBytes) {
  lineBytes = 0;
  if (!line || capacity < 2) return OutboxLineResult::IoError;
  bool sawByte = false;
  bool overflow = false;
  while (remaining > 0) {
    const int value = file.read();
    if (value < 0) return OutboxLineResult::IoError;
    --remaining;
    sawByte = true;
    if (value == '\n') break;
    if (lineBytes >= capacity - 1) {
      overflow = true;
      continue;
    }
    line[lineBytes++] = static_cast<char>(value);
  }
  if (!sawByte) return OutboxLineResult::End;
  if (lineBytes > 0 && line[lineBytes - 1] == '\r') --lineBytes;
  if (overflow || lineBytes == 0) {
    line[0] = '\0';
    return OutboxLineResult::Malformed;
  }
  line[lineBytes] = '\0';
  return OutboxLineResult::Line;
}

bool isValidOutboxLine(const char* line, const size_t lineBytes) {
  if (!line || lineBytes == 0 || lineBytes > xtinct::sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES) return false;
  JsonDocument event;
  const DeserializationError error = deserializeJson(event, line, lineBytes);
  return !error && event.is<JsonObjectConst>();
}

bool inspectOutbox(size_t& eventCount, size_t& encodedBytes, bool& repairNeeded) {
  eventCount = 0;
  encodedBytes = 0;
  repairNeeded = false;
  if (!recoverAtomicFile(OUTBOX_PATH)) return false;
  if (!Storage.exists(OUTBOX_PATH)) return true;

  HalFile input;
  if (!Storage.openFileForRead("XSYNC", OUTBOX_PATH, input)) return false;
  uint64_t remaining = input.fileSize64();
  if (!xtinct::network_persistence::boundedFileSizeAllowed(
          remaining, xtinct::sync_v2::MAX_OUTBOX_BYTES, true)) {
    input.close();
    return false;
  }
  char line[xtinct::sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES + 1];
  while (remaining > 0) {
    size_t lineBytes = 0;
    const OutboxLineResult result = readOutboxLine(input, remaining, line, sizeof(line), lineBytes);
    if (result == OutboxLineResult::IoError || result == OutboxLineResult::End) {
      input.close();
      return false;
    }
    if (result == OutboxLineResult::Malformed || !isValidOutboxLine(line, lineBytes)) {
      repairNeeded = true;
      continue;
    }
    if (++eventCount > xtinct::sync_v2::MAX_OUTBOX_EVENTS ||
        lineBytes + 1 > xtinct::sync_v2::MAX_OUTBOX_BYTES - encodedBytes) {
      input.close();
      return false;
    }
    encodedBytes += lineBytes + 1;
  }
  return input.close();
}

// Rewrite the outbox without ever materializing it as vector<string>. The
// original remains canonical until the replacement has been synced and closed;
// a failed promotion is recovered by the same final/.tmp/.bak transaction used
// by the rest of V2 storage.
bool rewriteOutboxStreaming(const size_t skipValidLines, const char* appendLine,
                            const size_t appendBytes, const bool dropMalformed) {
  if ((appendLine == nullptr) != (appendBytes == 0) ||
      appendBytes > xtinct::sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES ||
      (appendLine && !isValidOutboxLine(appendLine, appendBytes)) ||
      !recoverAtomicFile(OUTBOX_PATH)) {
    return false;
  }

  const bool previousExists = Storage.exists(OUTBOX_PATH);
  HalFile input;
  uint64_t remaining = 0;
  if (previousExists) {
    if (!Storage.openFileForRead("XSYNC", OUTBOX_PATH, input)) return false;
    remaining = input.fileSize64();
    if (!xtinct::network_persistence::boundedFileSizeAllowed(
            remaining, xtinct::sync_v2::MAX_OUTBOX_BYTES, true)) {
      input.close();
      return false;
    }
  } else if (skipValidLines != 0) {
    return false;
  }

  char temporaryPath[192];
  char backupPath[192];
  if (!atomicPaths(OUTBOX_PATH, temporaryPath, sizeof(temporaryPath), backupPath, sizeof(backupPath)) ||
      (Storage.exists(temporaryPath) && !Storage.remove(temporaryPath))) {
    if (input) input.close();
    return false;
  }
  HalFile output;
  if (!Storage.openFileForWrite("XSYNC", temporaryPath, output)) {
    if (input) input.close();
    return false;
  }

  bool writesOk = true;
  size_t validLines = 0;
  size_t skippedLines = 0;
  size_t outputBytes = 0;
  char line[xtinct::sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES + 1];
  const uint8_t newline = '\n';
  while (writesOk && remaining > 0) {
    size_t lineBytes = 0;
    const OutboxLineResult result = readOutboxLine(input, remaining, line, sizeof(line), lineBytes);
    if (result == OutboxLineResult::IoError || result == OutboxLineResult::End) {
      writesOk = false;
      break;
    }
    if (result == OutboxLineResult::Malformed || !isValidOutboxLine(line, lineBytes)) {
      if (!dropMalformed) writesOk = false;
      continue;
    }
    if (++validLines > xtinct::sync_v2::MAX_OUTBOX_EVENTS) {
      writesOk = false;
      break;
    }
    if (skippedLines < skipValidLines) {
      ++skippedLines;
      continue;
    }
    if (lineBytes + 1 > xtinct::sync_v2::MAX_OUTBOX_BYTES - outputBytes ||
        output.write(line, lineBytes) != lineBytes || output.write(&newline, 1) != 1) {
      writesOk = false;
      break;
    }
    outputBytes += lineBytes + 1;
  }
  if (writesOk && skippedLines != skipValidLines) writesOk = false;
  if (writesOk && appendLine) {
    if (appendBytes + 1 > xtinct::sync_v2::MAX_OUTBOX_BYTES - outputBytes ||
        output.write(appendLine, appendBytes) != appendBytes || output.write(&newline, 1) != 1) {
      writesOk = false;
    } else {
      outputBytes += appendBytes + 1;
    }
  }
  const bool inputClosed = !input || input.close();
  const bool durable = xtinct::file_transfer::finishDurableWrite(output, writesOk && inputClosed);
  if (!durable) {
    removeTemporaryAtomic(temporaryPath);
    return false;
  }
  bool promotedPrevious = false;
  if (!promoteAtomic(temporaryPath, OUTBOX_PATH, promotedPrevious) || promotedPrevious != previousExists) {
    removeTemporaryAtomic(temporaryPath);
    return false;
  }
  return commitAtomic(OUTBOX_PATH);
}

bool prepareOutbox(size_t& eventCount, size_t& encodedBytes) {
  bool repairNeeded = false;
  if (!inspectOutbox(eventCount, encodedBytes, repairNeeded)) return false;
  if (!repairNeeded) return true;
  if (!rewriteOutboxStreaming(0, nullptr, 0, true)) return false;
  repairNeeded = false;
  return inspectOutbox(eventCount, encodedBytes, repairNeeded) && !repairNeeded;
}

bool appendOutboxLineAtomic(const char* line, const size_t lineBytes) {
  size_t eventCount = 0;
  size_t encodedBytes = 0;
  if (!prepareOutbox(eventCount, encodedBytes) ||
      !xtinct::sync_v2::outboxCanAppend(eventCount, encodedBytes, lineBytes)) {
    return false;
  }
  return rewriteOutboxStreaming(0, line, lineBytes, false);
}

bool appendResponseBytes(xtinct::network::BoundedResponseBuffer& output,
                         const char* bytes, const size_t length) {
  return output.append(reinterpret_cast<const uint8_t*>(bytes), length);
}

bool buildAckPayload(xtinct::network::BoundedResponseBuffer& payload, size_t& sendCount) {
  sendCount = 0;
  if (!recoverAtomicFile(OUTBOX_PATH) || !Storage.exists(OUTBOX_PATH)) return false;
  HalFile input;
  if (!Storage.openFileForRead("XSYNC", OUTBOX_PATH, input)) return false;
  uint64_t remaining = input.fileSize64();
  if (!xtinct::network_persistence::boundedFileSizeAllowed(
          remaining, xtinct::sync_v2::MAX_OUTBOX_BYTES, true)) {
    input.close();
    return false;
  }
  constexpr char PREFIX[] = R"({"schema":2,"events":[)";
  constexpr char SUFFIX[] = "]}";
  if (!appendResponseBytes(payload, PREFIX, sizeof(PREFIX) - 1)) {
    input.close();
    return false;
  }
  char line[xtinct::sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES + 1];
  while (remaining > 0 && sendCount < xtinct::sync_v2::MAX_ACK_EVENTS) {
    size_t lineBytes = 0;
    const OutboxLineResult result = readOutboxLine(input, remaining, line, sizeof(line), lineBytes);
    if (result != OutboxLineResult::Line || !isValidOutboxLine(line, lineBytes)) {
      input.close();
      return false;
    }
    const size_t separatorBytes = sendCount == 0 ? 0 : 1;
    if (separatorBytes + lineBytes + sizeof(SUFFIX) - 1 > payload.maximum() - payload.size()) break;
    if ((separatorBytes != 0 && !appendResponseBytes(payload, ",", 1)) ||
        !appendResponseBytes(payload, line, lineBytes)) {
      input.close();
      return false;
    }
    ++sendCount;
  }
  const bool closed = input.close();
  return closed && sendCount > 0 && appendResponseBytes(payload, SUFFIX, sizeof(SUFFIX) - 1);
}

uint64_t nextEventSequence() {
  char stored[24];
  size_t storedBytes = 0;
  if (!readSmallFile(EVENT_SEQUENCE_PATH, sizeof(stored) - 1, stored, sizeof(stored), storedBytes)) return 0;
  uint64_t sequence = 0;
  if (storedBytes == 0) {
    // Missing is valid on first use; an existing empty file is corrupt and
    // must not reset the sequence or permit event-ID reuse.
    if (Storage.exists(EVENT_SEQUENCE_PATH)) return 0;
  } else if (!parseDecimalUint64(stored, sequence)) {
    return 0;
  }
  if (sequence == std::numeric_limits<uint64_t>::max()) return 0;
  ++sequence;
  char encoded[24];
  const int encodedBytes = std::snprintf(encoded, sizeof(encoded), "%llu",
                                         static_cast<unsigned long long>(sequence));
  return encodedBytes > 0 && encodedBytes < static_cast<int>(sizeof(encoded)) &&
                 writeAtomic(EVENT_SEQUENCE_PATH, encoded, static_cast<size_t>(encodedBytes))
             ? sequence
             : 0;
}

bool currentDeviceId(char deviceId[33]) {
  size_t storedBytes = 0;
  if (!readSmallFile(DEVICE_ID_PATH, 32, deviceId, 33, storedBytes)) return false;
  if (storedBytes == 0) {
    if (Storage.exists(DEVICE_ID_PATH)) return false;
    return copyText(deviceId, 33, "x3-main");
  }
  return xtinct::sync_v2::isSafeId(deviceId);
}

bool currentLocalDay(uint32_t& localDay) {
  if (!halClock.hasValidTime()) return false;
  const time_t now = time(nullptr);
  if (now < 1609459200) return false;
  return xtinct::inbox_cache::localDayFromUtcEpoch(
      static_cast<int64_t>(now),
      xtinct::daily_cards::BRISBANE_UTC_OFFSET_QUARTER_HOURS_BIASED, localDay);
}

bool readDurableCursor(char cursor[24]) {
  size_t cursorBytes = 0;
  if (!readSmallFile(CURSOR_PATH, 23, cursor, 24, cursorBytes)) return false;
  if (cursorBytes == 0) {
    if (Storage.exists(CURSOR_PATH)) return false;
    return copyText(cursor, 24, "0");
  }
  return isDecimalCursor(cursor);
}

bool hasFreshSyncMarker(const char* cursor, const uint32_t localDay) {
  if (!isDecimalCursor(cursor)) return false;
  xtinct::network::BoundedResponseBuffer body(MAX_SYNC_COMPLETE_BYTES);
  if (!readSmallFileBuffer(SYNC_COMPLETE_PATH, MAX_SYNC_COMPLETE_BYTES, body) ||
      body.size() == 0) {
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, body.data(), body.size()) ||
      !document.is<JsonObjectConst>()) {
    return false;
  }
  const JsonObjectConst root = document.as<JsonObjectConst>();
  return root.size() == 3 && (root["schema"] | 0) == 1 &&
         root["local_day"].is<uint32_t>() &&
         root["local_day"].as<uint32_t>() == localDay &&
         std::strcmp(root["cursor"] | "", cursor) == 0;
}

bool writeSyncCompleteMarker(const char* cursor) {
  if (!isDecimalCursor(cursor)) return false;
  uint32_t localDay = 0;
  if (!currentLocalDay(localDay) || !invalidateFastFirstPage()) return false;
  JsonDocument document;
  document["schema"] = 1;
  document["local_day"] = localDay;
  document["cursor"] = cursor;
  const size_t bytes = measureJson(document);
  xtinct::network::BoundedResponseBuffer output(MAX_SYNC_COMPLETE_BYTES);
  if (document.overflowed() || bytes == 0 || bytes > MAX_SYNC_COMPLETE_BYTES ||
      !output.reserve(bytes) ||
      serializeJson(document, output.data(), bytes + 1) != bytes) {
    return false;
  }
  return writeAtomic(SYNC_COMPLETE_PATH, output.data(), bytes);
}

void isoUtcNow(char output[32], const time_t adjustmentSeconds = 0) {
  time_t now = time(nullptr);
  if (now < 1609459200) now = 1609459200;
  now += adjustmentSeconds;
  struct tm utc {};
  gmtime_r(&now, &utc);
  std::strftime(output, 32, "%Y-%m-%dT%H:%M:%SZ", &utc);
}

bool findItemByArtifactPath(const std::string& requestedPath, XtinctInboxItem& item) {
  if (!Storage.exists(INBOX_DIR) || !recoverInboxMetadataSidecars()) return false;
  HalFile directory = Storage.open(INBOX_DIR, O_RDONLY);
  if (!directory || !directory.isDirectory()) {
    directory.close();
    return false;
  }
  size_t scannedEntries = 0;
  bool found = false;
  bool complete = true;
  while (complete) {
    HalFile entry = directory.openNextFile();
    if (!entry) break;
    const bool isDirectory = entry.isDirectory();
    char name[128] = {0};
    const size_t nameLength = entry.getName(name, sizeof(name));
    entry.close();
    if (++scannedEntries >= MAX_INBOX_ATOMIC_SCAN_FILES || isDirectory || nameLength == 0 ||
        nameLength >= sizeof(name)) {
      complete = false;
      break;
    }
    char itemId[33];
    if (!xtinct::sync_v2::managedMetadataItemId(name, itemId)) continue;
    char metadataFile[160];
    if (std::snprintf(metadataFile, sizeof(metadataFile), "%s/%s", INBOX_DIR, name) >=
        static_cast<int>(sizeof(metadataFile))) {
      complete = false;
      break;
    }
    XtinctInboxItem candidate;
    if (!parseMetadata(metadataFile, candidate) || std::strcmp(candidate.itemId, itemId) != 0) continue;
    char path[160];
    if (artifactPathFor(candidate, path, sizeof(path)) && requestedPath == path) {
      item = candidate;
      found = true;
    }
  }
  directory.close();
  return complete && found;
}

size_t scanInboxPage(XtinctInboxItem* items, const size_t capacity,
                     const char* beforeCreatedAt, const char* beforeItemId,
                     bool& hasOlderItems, bool& scanComplete) {
  hasOlderItems = false;
  scanComplete = false;
  if (!items || capacity == 0 || !Storage.exists(INBOX_DIR) ||
      !recoverInboxMetadataSidecars()) {
    return 0;
  }

  HalFile directory = Storage.open(INBOX_DIR, O_RDONLY);
  if (!directory || !directory.isDirectory()) {
    directory.close();
    return 0;
  }
  size_t scannedFiles = 0;
  size_t metadataCount = 0;
  size_t eligibleCount = 0;
  size_t retainedCount = 0;
  bool allMetadataValid = true;
  bool overCapacity = false;
  bool ok = true;
  while (ok) {
    HalFile entry = directory.openNextFile();
    if (!entry) break;
    const bool isDirectory = entry.isDirectory();
    char name[128] = {0};
    const size_t nameLength = entry.getName(name, sizeof(name));
    entry.close();
    if (isDirectory || nameLength == 0 || nameLength >= sizeof(name) ||
        ++scannedFiles >= MAX_INBOX_ATOMIC_SCAN_FILES) {
      ok = false;
      break;
    }
    char fileItemId[33];
    if (!xtinct::sync_v2::managedMetadataItemId(name, fileItemId)) continue;
    if (++metadataCount > xtinct::sync_v2::MAX_INBOX_ITEMS) overCapacity = true;
    char path[160];
    if (std::snprintf(path, sizeof(path), "%s/%s", INBOX_DIR, name) >=
        static_cast<int>(sizeof(path))) {
      ok = false;
      break;
    }
    XtinctInboxItem candidate;
    if (!parseMetadata(path, candidate) ||
        std::strcmp(candidate.itemId, fileItemId) != 0) {
      // The visible fallback may still show the other valid items, but a
      // partial parse must never become a persisted "complete" fast index.
      allMetadataValid = false;
      continue;
    }
    if (!xtinct::inbox_selection::isStrictlyOlderThanCursor(
            candidate.createdAt, candidate.itemId, beforeCreatedAt,
            beforeItemId)) {
      continue;
    }
    ++eligibleCount;
    retainedCount = xtinct::inbox_selection::retainNewest(
        items, retainedCount, capacity, candidate);
  }
  directory.close();
  if (!ok) {
    LOG_ERR("XSYNC", "Inbox page load refused: owned directory exceeded its bound");
    return 0;
  }
  if (overCapacity) {
    // A damaged or historically over-retained cache must not turn a valid
    // newest page into an apparently empty Inbox. Keep the scan bounded by
    // MAX_INBOX_ATOMIC_SCAN_FILES, return only the caller's fixed-size newest
    // selection, and refuse to persist a "complete" fast-page marker.
    LOG_ERR("XSYNC", "Inbox metadata exceeds the 64-item bound; showing a bounded newest-page fallback");
  }
  hasOlderItems = eligibleCount > retainedCount;
  scanComplete = allMetadataValid && !overCapacity;
  return retainedCount;
}

bool loadFastFirstPage(XtinctInboxItem* items, const size_t capacity,
                       bool& hasOlderItems, size_t& itemCount) {
  itemCount = 0;
  hasOlderItems = false;
  if (!items || capacity == 0) return false;

  xtinct::network::BoundedResponseBuffer body(MAX_FAST_FIRST_PAGE_BYTES);
  if (!readSmallFileBuffer(FAST_FIRST_PAGE_PATH, MAX_FAST_FIRST_PAGE_BYTES,
                           body) ||
      body.size() == 0) {
    return false;
  }
  JsonDocument document;
  if (deserializeJson(document, body.data(), body.size()) ||
      !document.is<JsonObjectConst>()) {
    return false;
  }
  const JsonObjectConst root = document.as<JsonObjectConst>();
  if (root.size() != 6 || (root["schema"] | 0) != 2 ||
      !root["complete"].is<bool>() || !root["complete"].as<bool>() ||
      !root["has_older"].is<bool>() ||
      !root["local_day"].is<uint32_t>() ||
      !root["item_ids"].is<JsonArrayConst>()) {
    return false;
  }
  const char* cachedCursor = root["cursor"] | "";
  if (!isDecimalCursor(cachedCursor)) return false;
  char durableCursor[24];
  if (!readDurableCursor(durableCursor)) return false;
  uint32_t localDay = 0;
  const bool dayKnown = currentLocalDay(localDay);
  if (!xtinct::inbox_cache::canUseFastFirstPage(
          true, true, std::strcmp(cachedCursor, durableCursor) == 0, dayKnown,
          localDay, root["local_day"].as<uint32_t>()) ||
      !hasFreshSyncMarker(durableCursor, localDay)) {
    return false;
  }

  const JsonArrayConst ids = root["item_ids"].as<JsonArrayConst>();
  if (ids.size() > FAST_FIRST_PAGE_ITEMS) return false;
  char seen[FAST_FIRST_PAGE_ITEMS][33] = {{0}};
  XtinctInboxItem previous;
  bool havePrevious = false;
  size_t totalCount = 0;
  for (const JsonVariantConst value : ids) {
    if (!value.is<const char*>()) return false;
    const char* itemId = value.as<const char*>();
    if (!xtinct::sync_v2::isSafeId(itemId)) return false;
    for (size_t index = 0; index < totalCount; ++index) {
      if (std::strcmp(seen[index], itemId) == 0) return false;
    }
    if (!copyText(seen[totalCount], sizeof(seen[totalCount]), itemId)) return false;
    char path[160];
    XtinctInboxItem candidate;
    if (!metadataPath(itemId, path, sizeof(path)) ||
        !parseMetadata(path, candidate) ||
        std::strcmp(candidate.itemId, itemId) != 0 ||
        (havePrevious &&
         !xtinct::inbox_selection::isNewer(
             previous.createdAt, previous.itemId, candidate.createdAt,
             candidate.itemId))) {
      return false;
    }
    previous = candidate;
    havePrevious = true;
    if (totalCount < capacity) items[totalCount] = candidate;
    ++totalCount;
  }
  itemCount = std::min(totalCount, capacity);
  hasOlderItems = root["has_older"].as<bool>() || totalCount > itemCount;
  return true;
}

bool writeFastFirstPage(const char* cursor, const uint32_t localDay,
                        const XtinctInboxItem* items, const size_t itemCount,
                        const bool hasOlderItems) {
  if (!isDecimalCursor(cursor) || !items || itemCount > FAST_FIRST_PAGE_ITEMS ||
      (itemCount < FAST_FIRST_PAGE_ITEMS && hasOlderItems)) {
    return false;
  }
  for (size_t index = 0; index < itemCount; ++index) {
    if (!xtinct::sync_v2::isSafeId(items[index].itemId) ||
        (index > 0 && !xtinct::inbox_selection::isNewer(
                          items[index - 1].createdAt, items[index - 1].itemId,
                          items[index].createdAt, items[index].itemId))) {
      return false;
    }
  }

  JsonDocument document;
  document["schema"] = 2;
  document["complete"] = true;
  document["local_day"] = localDay;
  document["cursor"] = cursor;
  document["has_older"] = hasOlderItems;
  JsonArray ids = document["item_ids"].to<JsonArray>();
  for (size_t index = 0; index < itemCount; ++index) {
    ids.add(items[index].itemId);
  }
  const size_t bytes = measureJson(document);
  xtinct::network::BoundedResponseBuffer output(MAX_FAST_FIRST_PAGE_BYTES);
  if (document.overflowed() || bytes == 0 || bytes > MAX_FAST_FIRST_PAGE_BYTES ||
      !output.reserve(bytes) ||
      serializeJson(document, output.data(), bytes + 1) != bytes) {
    return false;
  }
  return writeAtomic(FAST_FIRST_PAGE_PATH, output.data(), bytes);
}
}  // namespace

size_t XtinctSyncClient::loadInboxPage(XtinctInboxItem* items, const size_t capacity,
                                       const char* beforeCreatedAt, const char* beforeItemId,
                                       bool& hasOlderItems) {
  hasOlderItems = false;
  if (!items || capacity == 0) return 0;
  const bool noCreatedAt = !beforeCreatedAt || beforeCreatedAt[0] == '\0';
  const bool noItemId = !beforeItemId || beforeItemId[0] == '\0';
  if (noCreatedAt != noItemId ||
      (!noCreatedAt && (!isBoundedAscii(beforeCreatedAt, 39) || !xtinct::sync_v2::isSafeId(beforeItemId)))) {
    return 0;
  }

  const size_t boundedCapacity = std::min(capacity, xtinct::sync_v2::MAX_INBOX_ITEMS);
  if (noCreatedAt && boundedCapacity <= FAST_FIRST_PAGE_ITEMS) {
    size_t fastCount = 0;
    if (loadFastFirstPage(items, boundedCapacity, hasOlderItems, fastCount)) {
      return fastCount;
    }
  }
  bool scanComplete = false;
  const size_t itemCount = scanInboxPage(items, boundedCapacity, beforeCreatedAt,
                                         beforeItemId, hasOlderItems, scanComplete);
  // Build the acceleration index from the items already selected by this
  // local UI scan. Never launch a second metadata parse in the post-TLS sync
  // tail; that was both slow and unsafe on the X3's fragmented heap.
  if (noCreatedAt && boundedCapacity == FAST_FIRST_PAGE_ITEMS && scanComplete) {
    char cursor[24];
    uint32_t localDay = 0;
    if (readDurableCursor(cursor) && currentLocalDay(localDay) &&
        hasFreshSyncMarker(cursor, localDay) &&
        !writeFastFirstPage(cursor, localDay, items, itemCount, hasOlderItems)) {
      invalidateFastIndex();
    }
  }
  return itemCount;
}

size_t XtinctSyncClient::loadInbox(XtinctInboxItem* items, const size_t capacity) {
  bool ignored = false;
  return loadInboxPage(items, capacity, nullptr, nullptr, ignored);
}

bool XtinctSyncClient::invalidateInboxFastPage() {
  return invalidateFastFirstPage();
}

bool XtinctSyncClient::refreshInboxFastPage() {
  char cursor[24];
  return readDurableCursor(cursor) && writeSyncCompleteMarker(cursor);
}

bool XtinctSyncClient::isInboxSyncCompleteToday() {
  char cursor[24];
  uint32_t localDay = 0;
  return readDurableCursor(cursor) && currentLocalDay(localDay) &&
         hasFreshSyncMarker(cursor, localDay);
}

bool XtinctSyncClient::artifactPath(const XtinctInboxItem& item, char* path, const size_t pathSize) {
  return artifactPathFor(item, path, pathSize) && recoverAtomicFile(path);
}

bool XtinctSyncClient::queueEvent(const char* itemId, const char* revision, const char* type, const char* dataJson) {
#if defined(__cpp_exceptions)
  try {
#endif
  if (!xtinct::sync_v2::isSafeId(itemId) || !xtinct::sync_v2::isSha256(revision) ||
      !isBoundedAscii(type, 24) || !dataJson || std::strlen(dataJson) > 1024 || !ensureDirectories()) {
    return false;
  }
  if (!xtinct::sync_v2::isAckEventType(type)) return false;
  JsonDocument dataDocument;
  if (deserializeJson(dataDocument, dataJson) || !dataDocument.is<JsonObject>()) return false;

  const uint64_t sequence = nextEventSequence();
  if (sequence == 0) return false;
  char occurredAt[32];
  isoUtcNow(occurredAt);
  char deviceId[33];
  if (!currentDeviceId(deviceId)) return false;
  char eventId[96];
  const unsigned long epoch = static_cast<unsigned long>(std::max<time_t>(time(nullptr), 1609459200));
  if (std::snprintf(eventId, sizeof(eventId), "%s-%lu-%llu", deviceId, epoch,
                    static_cast<unsigned long long>(sequence)) >= static_cast<int>(sizeof(eventId))) {
    return false;
  }
  JsonDocument event;
  event["event_id"] = eventId;
  event["item_id"] = itemId;
  event["revision"] = revision;
  event["type"] = type;
  event["occurred_at"] = occurredAt;
  event["data"].set(dataDocument.as<JsonVariantConst>());
  const size_t lineBytes = measureJson(event);
  xtinct::network::BoundedResponseBuffer line(xtinct::sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES);
  if (event.overflowed() || lineBytes == 0 ||
      lineBytes > xtinct::sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES || !line.reserve(lineBytes) ||
      serializeJson(event, line.data(), lineBytes + 1) != lineBytes) {
    LOG_ERR("XSYNC", "Outbox event encoding failed; existing receipts retained");
    return false;
  }
  if (!appendOutboxLineAtomic(line.data(), lineBytes)) {
    LOG_ERR("XSYNC", "Outbox byte limit reached; new receipt rejected, existing receipts retained");
    return false;
  }
  return true;
#if defined(__cpp_exceptions)
  } catch (const std::bad_alloc&) {
    LOG_ERR("XSYNC", "Receipt append skipped after allocation failure");
    return false;
  } catch (const std::length_error&) {
    LOG_ERR("XSYNC", "Receipt append skipped after bounded-length failure");
    return false;
  } catch (...) {
    LOG_ERR("XSYNC", "Receipt append skipped after unexpected exception");
    return false;
  }
#endif
}

bool XtinctSyncClient::sendPendingAcks() {
#if defined(__cpp_exceptions)
  try {
#endif
  size_t eventCount = 0;
  size_t encodedBytes = 0;
  if (!prepareOutbox(eventCount, encodedBytes)) {
    LOG_ERR("XSYNC", "Outbox unreadable or over capacity; refusing destructive repair");
    return false;
  }
  (void)encodedBytes;
  if (eventCount == 0) return true;

  // Keep one fixed line buffer plus one bounded request buffer. The previous
  // vector implementation could hold the 32 KiB outbox, a duplicate vector,
  // a 16 KiB JSON tree and a serialized payload at the same time.
  xtinct::network::BoundedResponseBuffer payload(MAX_DEVICE_ACK_JSON_BYTES);
  if (!payload.reserve(2048)) return false;
  size_t sendCount = 0;
  if (!buildAckPayload(payload, sendCount)) return false;
  auto http = makeUniqueNoThrow<freeink::SecureHttpClient>();
  if (!http) return false;
  http->setTimeout(HTTP_TIMEOUT_MS);
  http->setUserAgent("XTINCT-X3-" CROSSPOINT_VERSION);
  http->setReuse(false);
  http->setFollowRedirects(0);
  http->setCACert(XTINCT_WORKER_CA_BUNDLE);
  if (!http->begin(XTINCT_FEED_CONFIG.getBaseUrl() + "/v2/acks")) return false;
  http->addHeader("Accept", "application/json");
  http->addHeader("Content-Type", "application/json");
  http->addHeader("Authorization", std::string("Bearer ") + XTINCT_FEED_CONFIG.getReadToken());
  xtinct::network::BoundedResponseBuffer responseBody(1024);
  if (!responseBody.reserve(256)) return false;
  const int status = http->sendRequest(
      "POST", reinterpret_cast<const uint8_t*>(payload.data()), payload.size(),
      [&responseBody](const uint8_t* data, const size_t length) { return responseBody.append(data, length); });
  const bool responseComplete = http->responseComplete();
  const bool responseAborted = http->aborted();
  const bool callbackAborted = http->callbackAborted();
  http->end();
  http.reset();
  payload.release();
  if (status != 200 || !responseComplete || responseAborted || callbackAborted ||
      responseBody.allocationFailed() || responseBody.limitExceeded() || responseBody.size() == 0) {
    return false;
  }
  size_t represented = 0;
  bool responseValid = false;
  {
    JsonDocument responseDocument;
    if (!deserializeJson(responseDocument, responseBody.data(), responseBody.size()) &&
        (responseDocument["schema"] | 0) == 2) {
      represented = static_cast<size_t>(responseDocument["accepted"] | 0) +
                    static_cast<size_t>(responseDocument["duplicates"] | 0) +
                    static_cast<size_t>(responseDocument["rejected"] | 0);
      responseValid = true;
    }
  }
  responseBody.release();
  if (!responseValid || represented != sendCount) return false;
  // A local rewrite failure leaves the acknowledged prefix in place. The
  // server's event-id deduplication makes retry safe; no receipt is lost.
  return rewriteOutboxStreaming(sendCount, nullptr, 0, false);
#if defined(__cpp_exceptions)
  } catch (const std::bad_alloc&) {
    LOG_ERR("XSYNC", "Receipt upload skipped after allocation failure");
    return false;
  } catch (const std::length_error&) {
    LOG_ERR("XSYNC", "Receipt upload skipped after bounded-length failure");
    return false;
  } catch (...) {
    LOG_ERR("XSYNC", "Receipt upload skipped after unexpected exception");
    return false;
  }
#endif
}

void XtinctSyncClient::recordOpenedBestEffort(const XtinctInboxItem& item) {
  if (recordAction(item, "opened")) return;
  // itemId is contract-bounded to 32 bytes, but keep the formatter bounded as
  // well so damaged local metadata can never turn telemetry into a log spill.
  LOG_ERR("XSYNC", "Opened receipt unavailable for %.32s; local open continues", item.itemId);
}

bool XtinctSyncClient::recordAction(const XtinctInboxItem& item, const char* action) {
  if (!action) return false;
  if (std::strcmp(action, "open-phone") == 0) {
    return queueEvent(item.itemId, item.revision, "open-phone", "{}");
  }
  if (std::strcmp(action, "defer") == 0) {
    char until[32];
    isoUtcNow(until, 24 * 60 * 60);
    char data[64];
    std::snprintf(data, sizeof(data), R"({"until":"%s"})", until);
    return queueEvent(item.itemId, item.revision, "deferred", data);
  }
  if (std::strcmp(action, "delete") == 0) {
    return queueEvent(item.itemId, item.revision, "deleted", "{}");
  }
  if (std::strcmp(action, "like") == 0) {
    return queueEvent(item.itemId, item.revision, "like", "{}");
  }
  if (std::strcmp(action, "dislike") == 0) {
    return queueEvent(item.itemId, item.revision, "dislike", "{}");
  }
  if (std::strcmp(action, "opened") == 0 || std::strcmp(action, "keep") == 0 ||
      std::strcmp(action, "archive") == 0 || std::strcmp(action, "done") == 0) {
    const char* type = std::strcmp(action, "keep") == 0       ? "kept"
                       : std::strcmp(action, "archive") == 0 ? "archived"
                       : std::strcmp(action, "done") == 0    ? "done"
                                                               : "opened";
    return queueEvent(item.itemId, item.revision, type, "{}");
  }
  return false;
}

bool XtinctSyncClient::removeFromInbox(const XtinctInboxItem& item) {
  char path[128];
  if (!metadataPath(item.itemId, path, sizeof(path)) || !recoverAtomicFile(path) ||
      (Storage.exists(path) && !Storage.remove(path))) {
    return false;
  }
  // The canonical metadata is the visibility source of truth. If fast-index
  // invalidation fails, its next read sees the missing metadata and falls back
  // to the bounded directory scan, so cache cleanup must not undo local delete.
  if (!invalidateFastFirstPage()) {
    LOG_ERR("XSYNC", "Inbox fast index remained after local removal of %.32s", item.itemId);
  }
  // Metadata is the source of truth. GC retains a digest while any other item
  // still references it, including temporary/backup variants of that digest.
  collectUnreferencedArtifacts();
  return true;
}

bool XtinctSyncClient::updateInboxState(const XtinctInboxItem& item, const char* state) {
  if (!isBoundedAscii(state, 15)) return false;
  XtinctInboxItem updated = item;
  if (!copyText(updated.state, sizeof(updated.state), state)) return false;
  // State does not alter first-page membership or ordering. The fast index
  // stores only item IDs and reparses this metadata when Inbox opens.
  return writeMetadata(updated, false);
}

bool XtinctSyncClient::queueReaderProgress(const std::string& requestedArtifactPath, const uint16_t progress,
                                           const bool bookmark, const bool bookmarkRemoved) {
  if (progress > 10000) return false;
  XtinctInboxItem item;
  if (!findItemByArtifactPath(requestedArtifactPath, item)) return false;
  char data[96];
  if (bookmark) {
    std::snprintf(data, sizeof(data), R"({"progress":%u,"bookmark":true,"removed":%s})",
                  static_cast<unsigned>(progress), bookmarkRemoved ? "true" : "false");
  } else {
    std::snprintf(data, sizeof(data), R"({"progress":%u})", static_cast<unsigned>(progress));
  }
  return queueEvent(item.itemId, item.revision, "progress", data);
}

bool XtinctSyncClient::queueDeviceStatus(const SyncResult result) {
  const uint64_t total = SDCardManager::getInstance().sdTotalBytes();
  const uint64_t used = SDCardManager::getInstance().sdUsedBytes();
  const uint64_t freeBytes = used <= total ? total - used : 0;
  JsonDocument data;
  data["battery_percent"] = powerManager.getBatteryPercentage();
  data["free_sd_bytes"] = freeBytes;
  data["firmware_version"] = CROSSPOINT_VERSION;
  data["last_sync_result"] = resultMessage(result);
  std::string encoded;
  serializeJson(data, encoded);
  // Device status has no delivery. Its identity is reserved by the v2
  // contract and cannot collide with a publishable item.
  return queueEvent(xtinct::sync_v2::DEVICE_STATUS_ITEM_ID, xtinct::sync_v2::DEVICE_STATUS_REVISION,
                    "device-status", encoded.c_str());
}

XtinctSyncClient::SyncResult XtinctSyncClient::sync() {
#if defined(__cpp_exceptions)
  try {
#endif
  if (!recoverSleepScreenActivation()) return SyncResult::STORAGE_ERROR;
  if (!XTINCT_FEED_CONFIG.hasReadToken() || !XtinctFeedConfigStore::isValidBaseUrl(XTINCT_FEED_CONFIG.getBaseUrl())) {
    return SyncResult::NO_CONFIG;
  }
  if (WiFi.status() != WL_CONNECTED) return SyncResult::NO_WIFI;
  if (!ensureDirectories()) return SyncResult::STORAGE_ERROR;

  // Best effort: old receipts never block receiving new content. They remain
  // durably queued and are retried after this sync if the preflight fails.
  sendPendingAcks();

  char cursor[24] = "0";
  size_t storedCursorBytes = 0;
  if (!readSmallFile(CURSOR_PATH, sizeof(cursor) - 1, cursor, sizeof(cursor), storedCursorBytes)) {
    return SyncResult::STORAGE_ERROR;
  }
  if (storedCursorBytes == 0) {
    if (Storage.exists(CURSOR_PATH)) return SyncResult::STORAGE_ERROR;
    copyText(cursor, sizeof(cursor), "0");
  } else if (!isDecimalCursor(cursor)) {
    return SyncResult::STORAGE_ERROR;
  }
  bool changed = false;
  bool fullyCaughtUp = false;
  bool downloadReceiptsAvailable = true;
  SyncResult finalResult = SyncResult::CURRENT;
  for (uint8_t pageIndex = 0; pageIndex < MAX_SYNC_PAGES_PER_WAKE; ++pageIndex) {
    auto http = makeUniqueNoThrow<freeink::SecureHttpClient>();
    if (!http) return SyncResult::NETWORK_ERROR;
    http->setTimeout(HTTP_TIMEOUT_MS);
    http->setUserAgent("XTINCT-X3-" CROSSPOINT_VERSION);
    http->setReuse(true);
    http->setFollowRedirects(0);
    http->setCACert(XTINCT_WORKER_CA_BUNDLE);
    const std::string url = XTINCT_FEED_CONFIG.getBaseUrl() + "/v2/sync?cursor=" + cursor + "&limit=" +
                            std::to_string(xtinct::inbox_sync_paging::DIRECT_PAGE_CHANGES);
    if (!http->begin(url)) return SyncResult::NETWORK_ERROR;
    http->addHeader("Accept", "application/json");
    http->addHeader("Authorization", std::string("Bearer ") + XTINCT_FEED_CONFIG.getReadToken());
    xtinct::network::BoundedResponseBuffer body(MAX_SYNC_BODY_BYTES);
    if (!body.reserve(8192)) {
      LOG_ERR("XSYNC", "Sync response allocation failed before request (limit=%u heap=%u max=%u)",
              static_cast<unsigned>(body.maximum()), static_cast<unsigned>(ESP.getFreeHeap()),
              static_cast<unsigned>(ESP.getMaxAllocHeap()));
      return SyncResult::NETWORK_ERROR;
    }
    const int status = http->GET([&body](const uint8_t* data, const size_t length) {
      return body.append(data, length);
    });
    const bool responseComplete = http->responseComplete();
    const bool transportAborted = http->aborted();
    const bool callbackAborted = http->callbackAborted();
    http->end();  // The response body and TLS arena must never overlap JSON parsing.
    if (status == 401 || status == 403) return SyncResult::UNAUTHORIZED;
    if (body.allocationFailed()) {
      LOG_ERR("XSYNC", "Sync response allocation failed (bytes=%u limit=%u heap=%u max=%u)",
              static_cast<unsigned>(body.size()), static_cast<unsigned>(body.maximum()),
              static_cast<unsigned>(ESP.getFreeHeap()), static_cast<unsigned>(ESP.getMaxAllocHeap()));
      return SyncResult::NETWORK_ERROR;
    }
    if (body.limitExceeded()) return SyncResult::INVALID_DATA;
    if (status != 200 || !responseComplete || transportAborted) return SyncResult::NETWORK_ERROR;
    if (callbackAborted && !transportAborted) return SyncResult::INVALID_DATA;

    auto page = makeUniqueNoThrow<SyncPage>();
    if (!page) {
      LOG_ERR("XSYNC", "Sync page allocation failed (heap=%u max=%u)",
              static_cast<unsigned>(ESP.getFreeHeap()), static_cast<unsigned>(ESP.getMaxAllocHeap()));
      return SyncResult::NETWORK_ERROR;
    }
    if (!parseSyncPage(body.data(), body.size(), *page)) return SyncResult::INVALID_DATA;
    body.release();  // Artifact TLS fetches must not overlap the 28 KiB response cap.
    if (!writeAtomic(DEVICE_ID_PATH, page->deviceId, std::strlen(page->deviceId))) return SyncResult::STORAGE_ERROR;

    for (uint8_t index = 0; index < page->deliveryCount; ++index) {
      XtinctInboxItem& item = page->deliveries[index].item;
      char metaPath[128];
      XtinctInboxItem cached;
      const bool sameMetadata = metadataPath(item.itemId, metaPath, sizeof(metaPath)) && parseMetadata(metaPath, cached) &&
                                std::strcmp(cached.revision, item.revision) == 0 &&
                                std::strcmp(cached.sha256, item.sha256) == 0 &&
                                xtinct::inbox_digest_contract::same(cached.digest, item.digest);
      char artifactPath[160];
      const bool haveValidArtifact = artifactPathFor(item, artifactPath, sizeof(artifactPath)) &&
                                     Storage.exists(artifactPath) && validateArtifactFile(item, artifactPath);
      if (!sameMetadata || !haveValidArtifact) {
        const SyncResult download = downloadArtifact(*http, item);
        if (download != SyncResult::UPDATED && download != SyncResult::CURRENT) {
          queueEvent(item.itemId, item.revision, "failed", R"({"reason":"artifact-download"})");
          return download;
        }
        if (!writeMetadata(item)) return SyncResult::STORAGE_ERROR;
        // A downloaded receipt is telemetry, not part of the artifact/metadata
        // transaction. A full or temporarily unreadable outbox must not strand
        // the cursor at zero after installing only the first delivery.
        if (downloadReceiptsAvailable &&
            !queueEvent(item.itemId, item.revision, "downloaded", "{}")) {
          downloadReceiptsAvailable = false;
          LOG_ERR("XSYNC", "Downloaded receipt unavailable; continuing content sync");
        }
        changed = true;
      }
      // Activation is outside the cache-hit branch. If installing the verified
      // BMP fails after its artifact/metadata commit, the cursor stays put and
      // the next sync retries this transaction instead of silently advancing.
      if (item.kind == Kind::SleepScreen && item.activateSleepScreen && !activateSleepScreen(item)) {
        queueEvent(item.itemId, item.revision, "failed", R"({"reason":"sleep-screen-activation"})");
        return SyncResult::STORAGE_ERROR;
      }
    }

    http->end();
    http.reset();  // Release artifact TLS before tombstones and SD cleanup.

    for (uint8_t index = 0; index < page->tombstoneCount; ++index) {
      const Tombstone& tombstone = page->tombstones[index];
      char metaPath[128];
      XtinctInboxItem cached;
      if (metadataPath(tombstone.itemId, metaPath, sizeof(metaPath)) && parseMetadata(metaPath, cached) &&
          std::strcmp(cached.revision, tombstone.revision) == 0) {
        if (!invalidateFastFirstPage() || !Storage.remove(metaPath)) {
          return SyncResult::STORAGE_ERROR;
        }
        changed = true;
      }
    }

    char nextCursor[24];
    if (!copyText(nextCursor, sizeof(nextCursor), page->cursor)) return SyncResult::INVALID_DATA;
    const bool hasMore = page->hasMore;
    page.reset();  // Release the fixed page block before fixed-set artifact GC.

    // Best effort and bounded: a failed cleanup never sacrifices a durable
    // cursor or a still-referenced artifact. The next sync retries the pass.
    collectUnreferencedArtifacts();

    if (!writeAtomic(CURSOR_PATH, nextCursor, std::strlen(nextCursor))) return SyncResult::STORAGE_ERROR;
    copyText(cursor, sizeof(cursor), nextCursor);
    if (!hasMore) {
      fullyCaughtUp = true;
      break;
    }
    if (pageIndex + 1 == MAX_SYNC_PAGES_PER_WAKE) {
      LOG_INF("XSYNC", "Page cap reached; remaining changes deferred to next sync");
    }
  }

  if (fullyCaughtUp) {
    if (!writeSyncCompleteMarker(cursor)) {
      LOG_ERR("XSYNC", "Complete sync could not record Inbox freshness; using safe scan");
      invalidateFastFirstPage();
    }
  } else {
    // The ten-page safety cap leaves a durable, resumable partial cursor.
    // Never advertise that state as today's complete first page.
    invalidateFastFirstPage();
  }
  finalResult = fullyCaughtUp ? (changed ? SyncResult::UPDATED : SyncResult::CURRENT)
                              : SyncResult::CATCH_UP_PENDING;
  queueDeviceStatus(finalResult);
  sendPendingAcks();
  return finalResult;
#if defined(__cpp_exceptions)
  } catch (const std::bad_alloc&) {
    LOG_ERR("XSYNC", "V2 sync stopped safely after allocation failure");
    return SyncResult::NETWORK_ERROR;
  } catch (const std::length_error&) {
    LOG_ERR("XSYNC", "V2 sync stopped safely after bounded-length failure");
    return SyncResult::NETWORK_ERROR;
  } catch (...) {
    // No exception may escape into ActivityManager::loop(): the ESP32 runtime
    // turns an uncaught exception into abort(), which previously rebooted the
    // device while the Inbox screen still displayed "Syncing XTINCT...".
    LOG_ERR("XSYNC", "V2 sync stopped safely after unexpected exception");
    return SyncResult::NETWORK_ERROR;
  }
#endif
}

const char* XtinctSyncClient::resultMessage(const SyncResult result) {
  switch (result) {
    case SyncResult::UPDATED:
      return "updated";
    case SyncResult::CURRENT:
      return "current";
    case SyncResult::CATCH_UP_PENDING:
      return "more content waiting";
    case SyncResult::NO_CONFIG:
      return "not configured";
    case SyncResult::NO_WIFI:
      return "no Wi-Fi";
    case SyncResult::UNAUTHORIZED:
      return "unauthorized";
    case SyncResult::INVALID_DATA:
      return "invalid data";
    case SyncResult::STORAGE_ERROR:
      return "storage error";
    case SyncResult::NETWORK_ERROR:
    default:
      return "network error";
  }
}

bool XtinctSyncClient::validatePocketDeliveryJson(const std::string& json, XtinctInboxItem& item) {
  if (json.empty() || json.size() > MAX_META_FILE_BYTES) return false;
  JsonDocument document;
  if (deserializeJson(document, json) || !document.is<JsonObjectConst>()) return false;
  return parseDelivery(document.as<JsonObjectConst>(), item);
}

bool XtinctSyncClient::validatePocketDeliveryFile(const char* stagedPath, XtinctInboxItem& item) {
  if (!stagedPath) return false;
  HalFile file;
  if (!Storage.openFileForRead("XSYNC", stagedPath, file)) return false;
  const uint64_t bytes = file.fileSize64();
  if (bytes == 0 || bytes > MAX_META_FILE_BYTES) {
    file.close();
    return false;
  }
  HalJsonReader reader(file);
  JsonDocument document;
  const DeserializationError error = deserializeJson(document, reader);
  file.close();
  return !error && document.is<JsonObjectConst>() && parseDelivery(document.as<JsonObjectConst>(), item);
}

bool XtinctSyncClient::validatePocketArtifactFile(const XtinctInboxItem& item, const char* stagedPath) {
  return stagedPath && validateArtifactFile(item, stagedPath);
}

bool XtinctSyncClient::writePocketMetadataFile(const XtinctInboxItem& item, const char* destinationPath) {
  // This is only a private shadow file. The Pocket transaction invalidates the
  // first-page cache immediately before any canonical metadata is applied.
  return writeMetadataAtPath(item, destinationPath, false);
}

bool XtinctSyncClient::pocketMetadataFinalPath(const char* itemId, char* path, const size_t pathSize) {
  return metadataPath(itemId, path, pathSize);
}

bool XtinctSyncClient::pocketArtifactFinalPath(const XtinctInboxItem& item, char* path, const size_t pathSize) {
  return artifactPathFor(item, path, pathSize);
}

bool XtinctSyncClient::pocketTombstoneMatches(const char* itemId, const char* revision) {
  if (!xtinct::sync_v2::isSafeId(itemId) || !xtinct::sync_v2::isSha256(revision)) return false;
  char path[160];
  if (!metadataPath(itemId, path, sizeof(path)) || !Storage.exists(path)) return false;
  XtinctInboxItem item;
  return parseMetadata(path, item) && std::strcmp(item.revision, revision) == 0;
}

bool XtinctSyncClient::pocketReadCursor(uint64_t& cursor) {
  cursor = 0;
  char value[24];
  size_t valueBytes = 0;
  if (!readSmallFile(CURSOR_PATH, sizeof(value) - 1, value, sizeof(value), valueBytes)) return false;
  if (valueBytes == 0) return !Storage.exists(CURSOR_PATH);
  return parseDecimalUint64(value, cursor);
}

bool XtinctSyncClient::pocketRecoverInboxMetadata() { return recoverInboxMetadataSidecars(); }

const char* XtinctSyncClient::pocketCursorFinalPath() { return CURSOR_PATH; }
