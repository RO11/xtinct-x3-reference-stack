#include "XtinctFeedClient.h"

#include <ArduinoJson.h>
#include <HalClock.h>
#include <HalStorage.h>
#include <Logging.h>
#include <Memory.h>
#include <SecureHttpClient.h>
#include <WiFi.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <iterator>

#include "CrossPointSettings.h"
#include "WifiCredentialStore.h"
#include "XtinctFeedConfigStore.h"
#include "XtinctTrustAnchors.h"
#include "FileTransferSafety.h"
#include "util/BoundedResponseBuffer.h"
#include "util/XtinctAtomicFile.h"
#include "util/XtinctNetworkPersistence.h"
#include "util/XtinctReportCacheNaming.h"

namespace {
constexpr char CACHE_DIR[] = "/.crosspoint/xtinct";
constexpr char CARD_DIR[] = "/.crosspoint/xtinct/cards";
constexpr const char* REPORT_DIR = xtinct::report_cache::DIRECTORY;
constexpr char MANIFEST_PATH[] = "/.crosspoint/xtinct/manifest.json";
constexpr char ETAG_PATH[] = "/.crosspoint/xtinct/manifest.etag";
constexpr char TRANSACTION_PATH[] = "/.crosspoint/xtinct/transaction.json";
constexpr size_t MAX_MANIFEST_BYTES = 8192;
constexpr size_t MAX_CARD_BYTES = 16 * 1024;
constexpr size_t MAX_REPORT_BYTES = 24 * 1024;
constexpr size_t MAX_TRANSACTION_BYTES = 2048;
constexpr unsigned long WIFI_CONNECT_TIMEOUT_MS = 7000;
constexpr uint8_t MAX_WIFI_ATTEMPTS = 3;

constexpr auto& TASK_IDS = xtinct::report_cache::TASK_IDS;
static_assert(std::size(TASK_IDS) == 4, "XtinctFeedClient::TASK_COUNT must match the report task allowlist");

const char* cardPath(const char* taskId, char* buffer, size_t bufferSize);
bool copyText(char* destination, size_t destinationSize, const char* source);

bool isAllowedTaskId(const char* value) {
  if (!value) return false;
  for (const char* id : TASK_IDS) {
    if (strcmp(id, value) == 0) return true;
  }
  return false;
}

bool isLowerHex(const char* value, const size_t exactLength) {
  if (!value || strlen(value) != exactLength) return false;
  for (size_t i = 0; i < exactLength; ++i) {
    if (!std::isdigit(static_cast<unsigned char>(value[i])) && (value[i] < 'a' || value[i] > 'f')) return false;
  }
  return true;
}

bool isSafeRevision(const char* value) { return isLowerHex(value, 32); }

bool expectedReportUrl(const char* taskId, const char* revision, char* buffer, const size_t bufferSize) {
  if (!isAllowedTaskId(taskId) || !isSafeRevision(revision) || !buffer || bufferSize == 0) return false;
  const int written = snprintf(buffer, bufferSize, "/v1/reports/%s/%s.txt", taskId, revision);
  return written > 0 && written < static_cast<int>(bufferSize);
}

bool reportPath(const char* taskId, const char* revision, char* buffer, const size_t bufferSize) {
  return isAllowedTaskId(taskId) && isSafeRevision(revision) &&
         xtinct::report_cache::buildFinalPath(taskId, revision, buffer, bufferSize);
}

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

uint8_t hexNibble(const char value) {
  if (value >= '0' && value <= '9') return static_cast<uint8_t>(value - '0');
  return static_cast<uint8_t>(value - 'a' + 10);
}

bool digestMatchesHex(const uint8_t digest[32], const char* expected) {
  if (!isLowerHex(expected, 64)) return false;
  uint8_t difference = 0;
  for (size_t i = 0; i < 32; ++i) {
    const uint8_t expectedByte = static_cast<uint8_t>((hexNibble(expected[i * 2]) << 4) | hexNibble(expected[i * 2 + 1]));
    difference |= digest[i] ^ expectedByte;
  }
  return difference == 0;
}

bool validateReportFile(const char* path, const uint32_t expectedBytes, const char* expectedSha256) {
  if (!path || expectedBytes == 0 || expectedBytes > MAX_REPORT_BYTES || !isLowerHex(expectedSha256, 64)) return false;
  HalFile file;
  if (!Storage.openFileForRead("XFEED", path, file) || file.fileSize64() != expectedBytes) return false;

  Sha256Scope sha;
  if (mbedtls_sha256_starts(&sha.context, /*is224=*/0) != 0) return false;
  uint8_t buffer[512];
  uint32_t remaining = expectedBytes;
  while (remaining > 0) {
    const size_t wanted = std::min<size_t>(sizeof(buffer), remaining);
    const int read = file.read(buffer, wanted);
    if (read <= 0 || static_cast<size_t>(read) != wanted ||
        mbedtls_sha256_update(&sha.context, buffer, static_cast<size_t>(read)) != 0) {
      file.close();
      return false;
    }
    remaining -= static_cast<uint32_t>(read);
  }
  file.close();
  uint8_t digest[32];
  return mbedtls_sha256_finish(&sha.context, digest) == 0 && digestMatchesHex(digest, expectedSha256);
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
  const int temporaryLength = snprintf(temporaryPath, temporarySize, "%s.tmp", finalPath);
  const int backupLength = snprintf(backupPath, backupSize, "%s.bak", finalPath);
  return temporaryLength > 0 && temporaryLength < static_cast<int>(temporarySize) &&
         backupLength > 0 && backupLength < static_cast<int>(backupSize);
}

bool logAtomicFailure(const char* operation, const char* finalPath,
                      const xtinct::atomic_file::Result result) {
  if (xtinct::atomic_file::succeeded(result)) return true;
  LOG_ERR("XFEED", "Atomic %s failed for %s: %s", operation, finalPath, atomicResultName(result));
  return false;
}

bool recoverAtomicFile(const char* finalPath) {
  char temporaryPath[176];
  char backupPath[176];
  if (!atomicPaths(finalPath, temporaryPath, sizeof(temporaryPath), backupPath, sizeof(backupPath))) return false;
  AtomicStorageOps ops;
  return logAtomicFailure("recovery", finalPath,
                          xtinct::atomic_file::recover(ops, finalPath, temporaryPath, backupPath));
}

bool promoteAtomicFile(const char* tempPath, const char* finalPath, bool& previousExisted) {
  char backupPath[176];
  if (snprintf(backupPath, sizeof(backupPath), "%s.bak", finalPath) >= static_cast<int>(sizeof(backupPath))) {
    return false;
  }
  AtomicStorageOps ops;
  return logAtomicFailure("promotion", finalPath,
                          xtinct::atomic_file::promoteRetainingBackup(
                              ops, tempPath, finalPath, backupPath, previousExisted));
}

bool commitAtomicFile(const char* finalPath) {
  char temporaryPath[176];
  char backupPath[176];
  if (!atomicPaths(finalPath, temporaryPath, sizeof(temporaryPath), backupPath, sizeof(backupPath))) return false;
  AtomicStorageOps ops;
  return logAtomicFailure("commit", finalPath,
                          xtinct::atomic_file::commit(ops, finalPath, temporaryPath, backupPath));
}

bool rollbackAtomicFile(const char* finalPath, const bool previousExisted) {
  char temporaryPath[176];
  char backupPath[176];
  if (!atomicPaths(finalPath, temporaryPath, sizeof(temporaryPath), backupPath, sizeof(backupPath))) return false;
  AtomicStorageOps ops;
  return logAtomicFailure("rollback", finalPath,
                          xtinct::atomic_file::rollback(
                              ops, finalPath, temporaryPath, backupPath, previousExisted));
}

bool removeAtomicTemporary(const char* path) {
  if (!path || !Storage.exists(path)) return true;
  if (Storage.remove(path)) return true;
  LOG_ERR("XFEED", "Could not remove atomic temporary file %s", path);
  return false;
}

bool recoverReportCacheSidecars() {
  if (!Storage.exists(REPORT_DIR)) return true;
  HalFile directory = Storage.open(REPORT_DIR, O_RDONLY);
  if (!directory || !directory.isDirectory()) {
    directory.close();
    return false;
  }
  constexpr size_t MAX_DIRECTORY_ENTRIES = 64;
  constexpr size_t MAX_UNIQUE_REPORTS = 32;
  xtinct::report_cache::ManagedFile finals[MAX_UNIQUE_REPORTS];
  size_t finalCount = 0;
  size_t visited = 0;
  bool complete = true;
  while (complete) {
    HalFile entry = directory.openNextFile();
    if (!entry) break;
    const bool isDirectory = entry.isDirectory();
    char name[128] = {0};
    const size_t nameLength = entry.getName(name, sizeof(name));
    entry.close();
    if (++visited > MAX_DIRECTORY_ENTRIES || isDirectory || nameLength == 0 || nameLength >= sizeof(name)) {
      complete = false;
      break;
    }
    xtinct::report_cache::ManagedFile managed;
    if (!xtinct::report_cache::parseManagedFilename(name, managed)) continue;
    bool known = false;
    for (size_t index = 0; index < finalCount; ++index) {
      if (finals[index].taskIndex == managed.taskIndex &&
          std::strcmp(finals[index].revision, managed.revision) == 0) {
        known = true;
        break;
      }
    }
    if (!known) {
      if (finalCount >= MAX_UNIQUE_REPORTS) {
        complete = false;
        break;
      }
      managed.kind = xtinct::report_cache::FileKind::FINAL;
      finals[finalCount++] = managed;
    }
  }
  directory.close();
  if (!complete) {
    LOG_ERR("XFEED", "Report recovery refused an incomplete or over-bound directory scan");
    return false;
  }
  for (size_t index = 0; index < finalCount; ++index) {
    char finalPath[176];
    if (!xtinct::report_cache::buildPath(finals[index], finalPath, sizeof(finalPath)) ||
        !recoverAtomicFile(finalPath)) {
      return false;
    }
  }
  return true;
}

bool stageAtomicFile(const char* finalPath, const char* content, const size_t contentLength,
                     char* tempPath, const size_t tempPathSize) {
  if (!finalPath || !content || !tempPath || tempPathSize == 0 ||
      (!Storage.exists(CACHE_DIR) && !Storage.mkdir(CACHE_DIR)) ||
      (!Storage.exists(CARD_DIR) && !Storage.mkdir(CARD_DIR)) || !recoverAtomicFile(finalPath)) {
    return false;
  }
  const int pathLength = snprintf(tempPath, tempPathSize, "%s.tmp", finalPath);
  if (pathLength <= 0 || pathLength >= static_cast<int>(tempPathSize)) return false;
  if (Storage.exists(tempPath) && !Storage.remove(tempPath)) return false;
  HalFile file;
  if (!Storage.openFileForWrite("XFEED", tempPath, file)) return false;
  const bool durable = xtinct::file_transfer::finishDurableWrite(
      file, file.write(content, contentLength) == contentLength);
  if (!durable) {
    removeAtomicTemporary(tempPath);
    return false;
  }
  return true;
}

const char* cardPath(const char* taskId, char* buffer, const size_t bufferSize) {
  snprintf(buffer, bufferSize, "%s/%s.json", CARD_DIR, taskId);
  return buffer;
}

bool copyText(char* destination, const size_t destinationSize, const char* source) {
  if (!destination || destinationSize == 0 || !source) return false;
  const size_t length = strlen(source);
  if (length >= destinationSize) return false;
  memcpy(destination, source, length + 1);
  return true;
}

bool readBoundedFile(const char* path, const size_t maximumBytes,
                     xtinct::network::BoundedResponseBuffer& body, const bool allowEmpty = false) {
  if (!path || body.maximum() < maximumBytes) return false;
  HalFile file;
  if (!Storage.openFileForRead("XFEED", path, file)) return false;
  const uint64_t bytes64 = file.fileSize64();
  if (!xtinct::network_persistence::boundedFileSizeAllowed(bytes64, maximumBytes, allowEmpty) ||
      !body.reserve(static_cast<size_t>(bytes64))) {
    file.close();
    return false;
  }
  uint8_t chunk[512];
  uint64_t remaining = bytes64;
  while (remaining > 0) {
    const size_t wanted = std::min<uint64_t>(sizeof(chunk), remaining);
    const int count = file.read(chunk, wanted);
    if (count <= 0 || static_cast<size_t>(count) != wanted || !body.append(chunk, wanted)) {
      file.close();
      return false;
    }
    remaining -= wanted;
  }
  return file.close();
}

void digestToHex(const uint8_t digest[32], char output[65]) {
  constexpr char HEX_DIGITS[] = "0123456789abcdef";
  for (size_t index = 0; index < 32; ++index) {
    output[index * 2] = HEX_DIGITS[digest[index] >> 4];
    output[index * 2 + 1] = HEX_DIGITS[digest[index] & 0x0f];
  }
  output[64] = '\0';
}

bool sha256BytesHex(const char* bytes, const size_t length, char output[65]) {
  if (!bytes || length == 0 || !output) return false;
  Sha256Scope sha;
  uint8_t digest[32];
  if (mbedtls_sha256_starts(&sha.context, 0) != 0 ||
      mbedtls_sha256_update(&sha.context, reinterpret_cast<const uint8_t*>(bytes), length) != 0 ||
      mbedtls_sha256_finish(&sha.context, digest) != 0) {
    return false;
  }
  digestToHex(digest, output);
  return true;
}

bool sha256FileHex(const char* path, const size_t maximumBytes, char output[65]) {
  if (!path || !output || !Storage.exists(path)) return false;
  HalFile file;
  if (!Storage.openFileForRead("XFEED", path, file)) return false;
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
  digestToHex(digest, output);
  return true;
}

bool fileMatchesSha256(const char* path, const size_t maximumBytes, const char* expected) {
  char actual[65];
  return isLowerHex(expected, 64) && sha256FileHex(path, maximumBytes, actual) &&
         std::strcmp(actual, expected) == 0;
}

bool isSafeHeaderValue(const char* value) {
  if (!value || value[0] == '\0') return false;
  for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value); *cursor; ++cursor) {
    if (*cursor < 0x21 || *cursor > 0x7e) return false;
  }
  return true;
}

XtinctCardState parseState(const char* state) {
  if (state && strcmp(state, "empty") == 0) return XtinctCardState::EMPTY;
  if (state && strcmp(state, "attention") == 0) return XtinctCardState::ATTENTION;
  if (state && strcmp(state, "error") == 0) return XtinctCardState::ERROR;
  return XtinctCardState::OK;
}

int stateRank(const XtinctCardState state) {
  switch (state) {
    case XtinctCardState::ERROR:
      return 3;
    case XtinctCardState::ATTENTION:
      return 2;
    case XtinctCardState::OK:
      return 1;
    case XtinctCardState::EMPTY:
    default:
      return 0;
  }
}

bool connectCredential(const WifiCredential& credential) {
  // Keep the STA/netif allocation alive between bounded credential attempts.
  // Tearing Wi-Fi fully down here fragments the X3's small heap immediately
  // before NTP and the certificate-heavy TLS handshake.
  WiFi.disconnect(false, true);
  delay(100);
  if (credential.password.empty()) {
    WiFi.begin(credential.ssid.c_str());
  } else {
    WiFi.begin(credential.ssid.c_str(), credential.password.c_str());
  }

  const unsigned long started = millis();
  while (millis() - started < WIFI_CONNECT_TIMEOUT_MS) {
    const wl_status_t status = WiFi.status();
    if (status == WL_CONNECTED) return true;
    if (status == WL_CONNECT_FAILED || status == WL_NO_SSID_AVAIL) return false;
    delay(100);
  }
  WiFi.disconnect(false, true);
  return false;
}

bool performJsonGet(freeink::SecureHttpClient& http, const std::string& url, const std::string& token,
                    const char* ifNoneMatch, int& status, xtinct::network::BoundedResponseBuffer& body,
                    std::string& responseEtag) {
  if (!body.reserve(std::min<size_t>(body.maximum(), 4096))) {
    LOG_ERR("XFEED", "HTTP response allocation failed before request (limit=%u heap=%u max=%u)",
            static_cast<unsigned>(body.maximum()), static_cast<unsigned>(ESP.getFreeHeap()),
            static_cast<unsigned>(ESP.getMaxAllocHeap()));
    return false;
  }
  if (!http.begin(url)) {
    LOG_ERR("XFEED", "HTTP begin failed (heap=%u max=%u)", static_cast<unsigned>(ESP.getFreeHeap()),
            static_cast<unsigned>(ESP.getMaxAllocHeap()));
    return false;
  }
  http.addHeader("Accept", "application/json");
  http.addHeader("Authorization", std::string("Bearer ") + token);
  if (ifNoneMatch && ifNoneMatch[0] != '\0') http.addHeader("If-None-Match", ifNoneMatch);

  status = http.GET([&body](const uint8_t* data, const size_t length) {
    return body.append(data, length);
  });
  responseEtag = http.getHeader("etag");

  if (body.limitExceeded()) {
    LOG_ERR("XFEED", "HTTP body exceeded %u bytes", static_cast<unsigned>(body.maximum()));
    return false;
  }
  if (body.allocationFailed()) {
    LOG_ERR("XFEED", "HTTP response allocation failed (bytes=%u limit=%u heap=%u max=%u)",
            static_cast<unsigned>(body.size()), static_cast<unsigned>(body.maximum()),
            static_cast<unsigned>(ESP.getFreeHeap()), static_cast<unsigned>(ESP.getMaxAllocHeap()));
    return false;
  }
  if (status < 0) {
    LOG_ERR("XFEED", "HTTP transport failed (status=%d bytes=%u heap=%u max=%u)", status,
            static_cast<unsigned>(body.size()), static_cast<unsigned>(ESP.getFreeHeap()),
            static_cast<unsigned>(ESP.getMaxAllocHeap()));
    return false;
  }
  if (status == 304) return true;
  const bool responseComplete = http.responseComplete();
  const bool callbackAborted = http.callbackAborted();
  if (!responseComplete || callbackAborted) {
    LOG_ERR("XFEED", "HTTP response incomplete (status=%d bytes=%u complete=%u aborted=%u)", status,
            static_cast<unsigned>(body.size()), responseComplete ? 1U : 0U, callbackAborted ? 1U : 0U);
    return false;
  }
  return true;
}
}  // namespace

bool XtinctFeedClient::connectSavedWifi() {
  WIFI_STORE.loadFromFile();
  const auto& credentials = WIFI_STORE.getCredentials();
  if (credentials.empty()) return false;

  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(false);
  WiFi.setScanMethod(WIFI_ALL_CHANNEL_SCAN);
  WiFi.setSortMethod(WIFI_CONNECT_AP_BY_SIGNAL);

  String mac = WiFi.macAddress();
  mac.replace(":", "");
  const String hostname = "XTINCT-X3-" + mac;
  WiFi.setHostname(hostname.c_str());

  bool attempted[8] = {false};
  uint8_t attempts = 0;
  const std::string& lastSsid = WIFI_STORE.getLastConnectedSsid();
  for (size_t i = 0; i < credentials.size() && i < std::size(attempted); ++i) {
    if (!lastSsid.empty() && credentials[i].ssid == lastSsid) {
      attempted[i] = true;
      attempts++;
      if (connectCredential(credentials[i])) {
        LOG_INF("XFEED", "Connected to preferred saved network");
        return true;
      }
      break;
    }
  }

  const int16_t found = WiFi.scanNetworks(false, true);
  for (uint8_t pass = 0; pass < MAX_WIFI_ATTEMPTS && attempts < MAX_WIFI_ATTEMPTS; ++pass) {
    int bestCredential = -1;
    int32_t bestRssi = INT32_MIN;
    for (size_t credentialIndex = 0; credentialIndex < credentials.size() && credentialIndex < 8; ++credentialIndex) {
      if (attempted[credentialIndex]) continue;
      for (int networkIndex = 0; networkIndex < found; ++networkIndex) {
        if (credentials[credentialIndex].ssid == WiFi.SSID(networkIndex).c_str() && WiFi.RSSI(networkIndex) > bestRssi) {
          bestCredential = static_cast<int>(credentialIndex);
          bestRssi = WiFi.RSSI(networkIndex);
        }
      }
    }
    if (bestCredential < 0) break;
    attempted[bestCredential] = true;
    attempts++;
    if (connectCredential(credentials[bestCredential])) {
      WIFI_STORE.setLastConnectedSsid(credentials[bestCredential].ssid);
      LOG_INF("XFEED", "Connected to a visible saved network");
      WiFi.scanDelete();
      return true;
    }
  }
  WiFi.scanDelete();
  disconnectWifi();
  return false;
}

void XtinctFeedClient::disconnectWifi() {
  if (WiFi.getMode() == WIFI_MODE_NULL) return;
  WiFi.disconnect(true, true);
  WiFi.mode(WIFI_OFF);
  delay(30);
}

void XtinctFeedClient::loadCachedRevisions() {
  cachedRevisionCount = 0;
  auto cachedCard = makeUniqueNoThrow<XtinctDailyCard>();
  if (!cachedCard) {
    LOG_ERR("XFEED", "OOM: cached revision validator");
    return;
  }
  for (const char* taskId : TASK_IDS) {
    char path[96];
    if (!validatePocketCardFile(taskId, nullptr, cardPath(taskId, path, sizeof(path)), cachedCard.get()) ||
        !validateCachedReport(*cachedCard)) {
      continue;
    }
    auto& cached = cachedRevisions[cachedRevisionCount++];
    copyText(cached.id, sizeof(cached.id), taskId);
    copyText(cached.revision, sizeof(cached.revision), cachedCard->revision);
  }
}

bool XtinctFeedClient::parseManifest(const char* body, const size_t bodyLength, char* bodyEtag,
                                     const size_t bodyEtagSize) {
  if (!body || bodyLength == 0 || bodyLength > MAX_MANIFEST_BYTES) return false;
  remoteCardCount = 0;
  JsonDocument doc;
  const DeserializationError error = deserializeJson(doc, body, bodyLength);
  if (error || (doc["schema"] | 0) != 1) return false;
  if (!copyText(bodyEtag, bodyEtagSize, doc["etag"] | "") || !isSafeHeaderValue(bodyEtag)) return false;

  if (!doc["cards"].is<JsonArrayConst>()) return false;
  JsonArrayConst cards = doc["cards"].as<JsonArrayConst>();
  for (JsonObjectConst item : cards) {
    if (remoteCardCount >= TASK_COUNT) return false;
    const char* id = item["id"] | "";
    const char* revision = item["revision"] | "";
    const char* url = item["url"] | "";
    char expectedUrl[96];
    snprintf(expectedUrl, sizeof(expectedUrl), "/v1/cards/%s.json", id);
    if (!isAllowedTaskId(id) || !isSafeRevision(revision) || strcmp(url, expectedUrl) != 0) return false;
    for (uint8_t existing = 0; existing < remoteCardCount; ++existing) {
      if (strcmp(remoteCards[existing].id, id) == 0) return false;
    }
    auto& remote = remoteCards[remoteCardCount++];
    if (!copyText(remote.id, sizeof(remote.id), id) || !copyText(remote.revision, sizeof(remote.revision), revision) ||
        !copyText(remote.url, sizeof(remote.url), url)) {
      return false;
    }
  }
  return true;
}

bool XtinctFeedClient::writeTransactionPlan(const V1TransactionPlan& plan) {
  JsonDocument document;
  document["schema"] = 1;
  document["target_etag"] = plan.targetEtag;
  document["target_manifest_sha256"] = plan.targetManifestSha256;
  document["previous_manifest"] = plan.previousManifestExisted;
  document["previous_manifest_sha256"] = plan.previousManifestSha256;
  document["remote_mask"] = plan.remoteMask;
  document["changed_mask"] = plan.changedMask;
  document["previous_card_mask"] = plan.previousCardMask;
  JsonArray targetRevisions = document["target_revisions"].to<JsonArray>();
  JsonArray targetCards = document["target_card_sha256"].to<JsonArray>();
  JsonArray previousCards = document["previous_card_sha256"].to<JsonArray>();
  for (size_t index = 0; index < TASK_COUNT; ++index) {
    if (!targetRevisions.add(plan.targetRevisions[index]) ||
        !targetCards.add(plan.targetCardSha256[index]) ||
        !previousCards.add(plan.previousCardSha256[index])) {
      return false;
    }
  }
  const size_t bytes = measureJson(document);
  xtinct::network::BoundedResponseBuffer serialized(MAX_TRANSACTION_BYTES);
  if (document.overflowed() || document.size() != 11 || bytes == 0 || bytes > MAX_TRANSACTION_BYTES ||
      !serialized.reserve(bytes) ||
      serializeJson(document, serialized.data(), bytes + 1) != bytes) {
    return false;
  }
  return writeAtomic(TRANSACTION_PATH, serialized.data(), bytes);
}

bool XtinctFeedClient::readTransactionPlan(V1TransactionPlan& plan) {
  plan = {};
  xtinct::network::BoundedResponseBuffer body(MAX_TRANSACTION_BYTES);
  if (!readBoundedFile(TRANSACTION_PATH, MAX_TRANSACTION_BYTES, body)) return false;
  JsonDocument document;
  const DeserializationError error = deserializeJson(document, body.data(), body.size());
  if (error || !document.is<JsonObjectConst>()) return false;
  JsonObjectConst object = document.as<JsonObjectConst>();
  if (object.size() != 11 || (object["schema"] | 0) != 1 ||
      !object["previous_manifest"].is<bool>() ||
      !object["remote_mask"].is<int>() || !object["changed_mask"].is<int>() ||
      !object["previous_card_mask"].is<int>() ||
      !object["target_revisions"].is<JsonArrayConst>() ||
      !object["target_card_sha256"].is<JsonArrayConst>() ||
      !object["previous_card_sha256"].is<JsonArrayConst>()) {
    return false;
  }

  const int remoteMask = object["remote_mask"].as<int>();
  const int changedMask = object["changed_mask"].as<int>();
  const int previousCardMask = object["previous_card_mask"].as<int>();
  if (remoteMask < 0 || remoteMask > 0x0f || changedMask < 0 || changedMask > 0x0f ||
      previousCardMask < 0 || previousCardMask > 0x0f || (changedMask & ~remoteMask) != 0 ||
      !copyText(plan.targetEtag, sizeof(plan.targetEtag), object["target_etag"] | "") ||
      !isSafeHeaderValue(plan.targetEtag) ||
      !copyText(plan.targetManifestSha256, sizeof(plan.targetManifestSha256),
                object["target_manifest_sha256"] | "") ||
      !isLowerHex(plan.targetManifestSha256, 64)) {
    return false;
  }
  plan.remoteMask = static_cast<uint8_t>(remoteMask);
  plan.changedMask = static_cast<uint8_t>(changedMask);
  plan.previousCardMask = static_cast<uint8_t>(previousCardMask);
  plan.previousManifestExisted = object["previous_manifest"].as<bool>();
  if (!copyText(plan.previousManifestSha256, sizeof(plan.previousManifestSha256),
                object["previous_manifest_sha256"] | "") ||
      (plan.previousManifestExisted != isLowerHex(plan.previousManifestSha256, 64))) {
    return false;
  }

  const JsonArrayConst revisions = object["target_revisions"].as<JsonArrayConst>();
  const JsonArrayConst targets = object["target_card_sha256"].as<JsonArrayConst>();
  const JsonArrayConst previous = object["previous_card_sha256"].as<JsonArrayConst>();
  if (revisions.size() != TASK_COUNT || targets.size() != TASK_COUNT || previous.size() != TASK_COUNT) {
    return false;
  }
  for (size_t index = 0; index < TASK_COUNT; ++index) {
    const uint8_t bit = static_cast<uint8_t>(1U << index);
    if (!copyText(plan.targetRevisions[index], sizeof(plan.targetRevisions[index]), revisions[index] | "") ||
        !copyText(plan.targetCardSha256[index], sizeof(plan.targetCardSha256[index]), targets[index] | "") ||
        !copyText(plan.previousCardSha256[index], sizeof(plan.previousCardSha256[index]),
                  previous[index] | "") ||
        (((plan.remoteMask & bit) != 0) != isSafeRevision(plan.targetRevisions[index])) ||
        (((plan.changedMask & bit) != 0) != isLowerHex(plan.targetCardSha256[index], 64)) ||
        (((plan.previousCardMask & bit) != 0) != isLowerHex(plan.previousCardSha256[index], 64))) {
      return false;
    }
  }
  return true;
}

bool XtinctFeedClient::finishCommittedTransaction(const V1TransactionPlan& plan) {
  if (!fileMatchesSha256(MANIFEST_PATH, MAX_MANIFEST_BYTES, plan.targetManifestSha256) ||
      !validateTargetCards(plan)) {
    return false;
  }

  // Validate every identity before the first cleanup. A foreign/corrupt file
  // is preserved and the journal remains for inspection/retry.
  for (size_t index = 0; index < TASK_COUNT; ++index) {
    const uint8_t bit = static_cast<uint8_t>(1U << index);
    char finalPath[96];
    char temporaryPath[128];
    char backupPath[128];
    cardPath(TASK_IDS[index], finalPath, sizeof(finalPath));
    if (!atomicPaths(finalPath, temporaryPath, sizeof(temporaryPath), backupPath, sizeof(backupPath))) return false;
    if ((plan.changedMask & bit) != 0) {
      if (!fileMatchesSha256(finalPath, MAX_CARD_BYTES, plan.targetCardSha256[index]) ||
          (Storage.exists(temporaryPath) &&
           !fileMatchesSha256(temporaryPath, MAX_CARD_BYTES, plan.targetCardSha256[index])) ||
          (Storage.exists(backupPath) &&
           (((plan.previousCardMask & bit) == 0) ||
            !fileMatchesSha256(backupPath, MAX_CARD_BYTES, plan.previousCardSha256[index])))) {
        return false;
      }
    } else if ((plan.remoteMask & bit) != 0) {
      if ((plan.previousCardMask & bit) == 0 || Storage.exists(temporaryPath) ||
          Storage.exists(backupPath) ||
          !fileMatchesSha256(finalPath, MAX_CARD_BYTES, plan.previousCardSha256[index])) {
        return false;
      }
    } else {
      if (Storage.exists(temporaryPath) || Storage.exists(backupPath) ||
          (Storage.exists(finalPath) &&
           (((plan.previousCardMask & bit) == 0) ||
            !fileMatchesSha256(finalPath, MAX_CARD_BYTES, plan.previousCardSha256[index])))) {
        return false;
      }
    }
  }

  char manifestTemporary[176];
  char manifestBackup[176];
  if (!atomicPaths(MANIFEST_PATH, manifestTemporary, sizeof(manifestTemporary),
                   manifestBackup, sizeof(manifestBackup)) ||
      (Storage.exists(manifestTemporary) &&
       !fileMatchesSha256(manifestTemporary, MAX_MANIFEST_BYTES, plan.targetManifestSha256)) ||
      (Storage.exists(manifestBackup) &&
       (!plan.previousManifestExisted ||
        !fileMatchesSha256(manifestBackup, MAX_MANIFEST_BYTES, plan.previousManifestSha256)))) {
    return false;
  }

  if (!writeAtomic(ETAG_PATH, plan.targetEtag)) return false;
  for (size_t index = 0; index < TASK_COUNT; ++index) {
    const uint8_t bit = static_cast<uint8_t>(1U << index);
    char finalPath[96];
    cardPath(TASK_IDS[index], finalPath, sizeof(finalPath));
    if ((plan.changedMask & bit) != 0 && !commitAtomicFile(finalPath)) return false;
    if ((plan.remoteMask & bit) == 0 && Storage.exists(finalPath) && !Storage.remove(finalPath)) {
      LOG_ERR("XFEED", "Could not prune committed withdrawn card %s", TASK_IDS[index]);
      return false;
    }
  }
  if (!commitAtomicFile(MANIFEST_PATH) || !sweepReportCache()) return false;
  if (!recoverAtomicFile(TRANSACTION_PATH) ||
      (Storage.exists(TRANSACTION_PATH) && !Storage.remove(TRANSACTION_PATH))) {
    return false;
  }
  return true;
}

bool XtinctFeedClient::rollBackTransaction(const V1TransactionPlan& plan) {
  // Preflight every changed card. Never partially roll back a set after seeing
  // an identity that is neither the journaled old nor target version.
  for (size_t index = 0; index < TASK_COUNT; ++index) {
    const uint8_t bit = static_cast<uint8_t>(1U << index);
    if ((plan.changedMask & bit) == 0) continue;
    char finalPath[96];
    char temporaryPath[128];
    char backupPath[128];
    cardPath(TASK_IDS[index], finalPath, sizeof(finalPath));
    if (!atomicPaths(finalPath, temporaryPath, sizeof(temporaryPath), backupPath, sizeof(backupPath))) return false;
    const bool previous = (plan.previousCardMask & bit) != 0;
    const bool finalExists = Storage.exists(finalPath);
    const bool temporaryExists = Storage.exists(temporaryPath);
    const bool backupExists = Storage.exists(backupPath);
    const bool finalOld = previous && finalExists &&
                          fileMatchesSha256(finalPath, MAX_CARD_BYTES, plan.previousCardSha256[index]);
    const bool finalTarget = finalExists &&
                             fileMatchesSha256(finalPath, MAX_CARD_BYTES, plan.targetCardSha256[index]);
    const bool backupOld = previous && backupExists &&
                           fileMatchesSha256(backupPath, MAX_CARD_BYTES, plan.previousCardSha256[index]);
    const bool tempTarget = temporaryExists &&
                            fileMatchesSha256(temporaryPath, MAX_CARD_BYTES, plan.targetCardSha256[index]);
    if (!xtinct::network_persistence::v1RollbackStateAllowed(
            previous, finalExists, finalOld, finalTarget, temporaryExists,
            tempTarget, backupExists, backupOld)) {
      LOG_ERR("XFEED", "Refusing rollback of unknown card identity for %s", TASK_IDS[index]);
      return false;
    }
  }

  char manifestTemporary[176];
  char manifestBackup[176];
  if (!atomicPaths(MANIFEST_PATH, manifestTemporary, sizeof(manifestTemporary),
                   manifestBackup, sizeof(manifestBackup))) return false;
  const bool manifestFinalExists = Storage.exists(MANIFEST_PATH);
  const bool manifestTemporaryExists = Storage.exists(manifestTemporary);
  const bool manifestBackupExists = Storage.exists(manifestBackup);
  const bool manifestFinalOld = plan.previousManifestExisted && manifestFinalExists &&
      fileMatchesSha256(MANIFEST_PATH, MAX_MANIFEST_BYTES, plan.previousManifestSha256);
  const bool manifestFinalTarget = manifestFinalExists &&
      fileMatchesSha256(MANIFEST_PATH, MAX_MANIFEST_BYTES, plan.targetManifestSha256);
  const bool manifestBackupOld = plan.previousManifestExisted && manifestBackupExists &&
      fileMatchesSha256(manifestBackup, MAX_MANIFEST_BYTES, plan.previousManifestSha256);
  const bool manifestTempTarget = manifestTemporaryExists &&
      fileMatchesSha256(manifestTemporary, MAX_MANIFEST_BYTES, plan.targetManifestSha256);
  if (!xtinct::network_persistence::v1RollbackStateAllowed(
          plan.previousManifestExisted, manifestFinalExists, manifestFinalOld,
          manifestFinalTarget, manifestTemporaryExists, manifestTempTarget,
          manifestBackupExists, manifestBackupOld)) {
    LOG_ERR("XFEED", "Refusing rollback of unknown manifest identity");
    return false;
  }

  for (size_t index = 0; index < TASK_COUNT; ++index) {
    const uint8_t bit = static_cast<uint8_t>(1U << index);
    if ((plan.changedMask & bit) == 0) continue;
    char finalPath[96];
    cardPath(TASK_IDS[index], finalPath, sizeof(finalPath));
    if (!rollbackAtomicFile(finalPath, (plan.previousCardMask & bit) != 0)) return false;
  }
  // Restore the old manifest last, after every final it references is back.
  if (!rollbackAtomicFile(MANIFEST_PATH, plan.previousManifestExisted)) return false;
  if (!recoverAtomicFile(TRANSACTION_PATH) ||
      (Storage.exists(TRANSACTION_PATH) && !Storage.remove(TRANSACTION_PATH))) {
    return false;
  }
  return true;
}

bool XtinctFeedClient::recoverPendingTransaction() {
  if (!recoverAtomicFile(TRANSACTION_PATH)) return false;
  if (!recoverReportCacheSidecars()) return false;
  if (!Storage.exists(TRANSACTION_PATH)) {
    if (!recoverAtomicFile(MANIFEST_PATH) || !recoverAtomicFile(ETAG_PATH)) return false;
    for (const char* taskId : TASK_IDS) {
      char path[96];
      if (!recoverAtomicFile(cardPath(taskId, path, sizeof(path)))) return false;
    }
    return true;
  }

  V1TransactionPlan plan;
  if (!readTransactionPlan(plan)) {
    LOG_ERR("XFEED", "Refusing malformed bounded V1 transaction journal");
    return false;
  }
  const bool manifestExists = Storage.exists(MANIFEST_PATH);
  const bool targetMatches = manifestExists &&
      fileMatchesSha256(MANIFEST_PATH, MAX_MANIFEST_BYTES, plan.targetManifestSha256);
  const bool previousMatches = manifestExists && plan.previousManifestExisted &&
      fileMatchesSha256(MANIFEST_PATH, MAX_MANIFEST_BYTES, plan.previousManifestSha256);
  switch (xtinct::network_persistence::v1RecoveryDirection(
      manifestExists, targetMatches, plan.previousManifestExisted, previousMatches)) {
    case xtinct::network_persistence::V1RecoveryDirection::FinishCommit:
      return finishCommittedTransaction(plan);
    case xtinct::network_persistence::V1RecoveryDirection::RollBack:
      return rollBackTransaction(plan);
    case xtinct::network_persistence::V1RecoveryDirection::FailClosed:
      LOG_ERR("XFEED", "V1 transaction manifest is neither journaled old nor target");
      return false;
  }
  return false;
}

bool XtinctFeedClient::validateCachedManifestAndCards(const char* expectedManifestEtag) {
  if (!expectedManifestEtag || expectedManifestEtag[0] == '\0') return false;

  xtinct::network::BoundedResponseBuffer manifestContent(MAX_MANIFEST_BYTES);
  if (!readBoundedFile(MANIFEST_PATH, MAX_MANIFEST_BYTES, manifestContent)) return false;

  char cachedManifestEtag[96] = {0};
  if (!parseManifest(manifestContent.data(), manifestContent.size(), cachedManifestEtag,
                     sizeof(cachedManifestEtag)) ||
      strcmp(cachedManifestEtag, expectedManifestEtag) != 0) {
    return false;
  }

  auto cachedCard = makeUniqueNoThrow<XtinctDailyCard>();
  if (!cachedCard) return false;
  for (uint8_t i = 0; i < remoteCardCount; ++i) {
    char path[96];
    if (!validatePocketCardFile(remoteCards[i].id, remoteCards[i].revision,
                                cardPath(remoteCards[i].id, path, sizeof(path)), cachedCard.get()) ||
        !validateCachedReport(*cachedCard)) {
      return false;
    }
  }
  return true;
}

bool XtinctFeedClient::validateCachedReport(const XtinctDailyCard& card) {
  if (!card.hasReport) return true;
  char path[160];
  return cachedReportPath(card, path, sizeof(path)) &&
         validateReportFile(path, card.reportBytes, card.reportSha256);
}

bool XtinctFeedClient::sweepReportCache() {
  // Destructive precondition: call only after referenced finals have passed a
  // 304 cache validation or a 200 repair/commit. Before that point a `.bak`
  // may be the only recoverable copy left by power loss during promotion.
  if (!Storage.exists(REPORT_DIR)) return true;

  // Only structurally valid card metadata can retain a final report. The
  // report body itself is checked separately by loadCachedRevisions(), so a
  // damaged referenced final remains available for the normal repair fetch.
  struct ReportReference {
    bool present = false;
    char revision[xtinct::report_cache::REVISION_LENGTH + 1] = {0};
  } references[TASK_COUNT];

  auto parsedCard = makeUniqueNoThrow<XtinctDailyCard>();
  if (!parsedCard) {
    LOG_ERR("XFEED", "OOM: report-cache sweep card validator");
    return false;
  }
  for (size_t taskIndex = 0; taskIndex < TASK_COUNT; ++taskIndex) {
    char path[96];
    if (!validatePocketCardFile(TASK_IDS[taskIndex], nullptr,
                                cardPath(TASK_IDS[taskIndex], path, sizeof(path)), parsedCard.get()) ||
        !parsedCard->hasReport) {
      continue;
    }
    references[taskIndex].present =
        copyText(references[taskIndex].revision, sizeof(references[taskIndex].revision), parsedCard->revision);
  }

  HalFile directory = Storage.open(REPORT_DIR);
  if (!directory || !directory.isDirectory()) {
    if (directory) directory.close();
    LOG_ERR("XFEED", "Report cache path is not a readable directory");
    return false;
  }

  // A healthy cache has at most one final per task and no sidecars. Bound both
  // total directory work and stack storage so a damaged/hostile SD card cannot
  // turn a wake cycle into an unbounded scan.
  constexpr size_t MAX_DIRECTORY_ENTRIES = 64;
  constexpr size_t MAX_MANAGED_FILES = 32;
  xtinct::report_cache::ManagedFile managedFiles[MAX_MANAGED_FILES];
  size_t managedCount = 0;
  size_t visitedCount = 0;
  bool complete = true;
  while (true) {
    HalFile entry = directory.openNextFile();
    if (!entry) break;
    ++visitedCount;
    if (visitedCount > MAX_DIRECTORY_ENTRIES) {
      entry.close();
      complete = false;
      break;
    }
    if (entry.isDirectory()) {
      entry.close();
      continue;
    }

    char name[128] = {0};
    const size_t nameLength = entry.getName(name, sizeof(name));
    entry.close();
    name[sizeof(name) - 1] = '\0';
    if (nameLength == 0 || nameLength >= sizeof(name)) continue;

    xtinct::report_cache::ManagedFile managed;
    if (xtinct::report_cache::parseManagedFilename(name, managed)) {
      if (managedCount < MAX_MANAGED_FILES) {
        managedFiles[managedCount++] = managed;
      } else {
        complete = false;
      }
    }
    yield();
  }
  directory.close();

  bool removedAll = true;
  for (size_t i = 0; i < managedCount; ++i) {
    const auto& managed = managedFiles[i];
    const bool referencedFinal =
        managed.kind == xtinct::report_cache::FileKind::FINAL && references[managed.taskIndex].present &&
        strcmp(references[managed.taskIndex].revision, managed.revision) == 0;
    if (referencedFinal) continue;

    // Never join or remove using the enumerated filename. Rebuild the target
    // solely from the task allowlist, strict lowercase revision and fixed
    // suffix parsed by XtinctReportCacheNaming.
    char managedPath[176];
    if (!xtinct::report_cache::buildPath(managed, managedPath, sizeof(managedPath)) ||
        (Storage.exists(managedPath) && !Storage.remove(managedPath))) {
      LOG_ERR("XFEED", "Could not remove stale managed report-cache entry");
      removedAll = false;
    }
  }
  // Cap exhaustion is diagnostic, not a permanent sync denial: unknown files
  // are deliberately untouched, so 65 such names must not block Daily Cards.
  // Managed files already removed make later bounded passes progress.
  if (!complete) LOG_ERR("XFEED", "Report cache sweep reached its bounded entry limit");
  return removedAll;
}

XtinctFeedClient::SyncResult XtinctFeedClient::downloadAndCacheReport(freeink::SecureHttpClient& http,
                                                                      const std::string& baseUrl,
                                                                      const std::string& token,
                                                                      const XtinctDailyCard& card,
                                                                      bool& promotedReport) {
  promotedReport = false;
  if (!card.hasReport) return SyncResult::UPDATED;
  char finalPath[160];
  char relativeUrl[128];
  if (!cachedReportPath(card, finalPath, sizeof(finalPath)) ||
      !expectedReportUrl(card.taskId, card.revision, relativeUrl, sizeof(relativeUrl))) {
    return SyncResult::INVALID_DATA;
  }
  if (!recoverAtomicFile(finalPath)) return SyncResult::STORAGE_ERROR;
  if (validateReportFile(finalPath, card.reportBytes, card.reportSha256)) return SyncResult::UPDATED;

  if ((!Storage.exists(CACHE_DIR) && !Storage.mkdir(CACHE_DIR)) ||
      (!Storage.exists(REPORT_DIR) && !Storage.mkdir(REPORT_DIR))) {
    return SyncResult::STORAGE_ERROR;
  }
  char tempPath[176];
  if (snprintf(tempPath, sizeof(tempPath), "%s.tmp", finalPath) >= static_cast<int>(sizeof(tempPath))) {
    return SyncResult::STORAGE_ERROR;
  }
  if (Storage.exists(tempPath) && !Storage.remove(tempPath)) return SyncResult::STORAGE_ERROR;

  HalFile file;
  if (!Storage.openFileForWrite("XFEED", tempPath, file)) return SyncResult::STORAGE_ERROR;
  Sha256Scope sha;
  if (mbedtls_sha256_starts(&sha.context, /*is224=*/0) != 0) {
    file.close();
    return removeAtomicTemporary(tempPath) ? SyncResult::INVALID_DATA : SyncResult::STORAGE_ERROR;
  }

  size_t received = 0;
  bool overflow = false;
  bool writeFailed = false;
  bool hashFailed = false;
  if (!http.begin(baseUrl + relativeUrl)) {
    file.close();
    return removeAtomicTemporary(tempPath) ? SyncResult::NETWORK_ERROR : SyncResult::STORAGE_ERROR;
  }
  http.addHeader("Accept", "text/plain; charset=utf-8");
  http.addHeader("Authorization", std::string("Bearer ") + token);
  const int status = http.GET([&](const uint8_t* data, const size_t length) {
    if (received > card.reportBytes || length > card.reportBytes - received || received > MAX_REPORT_BYTES ||
        length > MAX_REPORT_BYTES - received) {
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

  // Copy every response fact needed below, then release the TLS arena before
  // SHA finalization, FAT promotion and the full readback validator.
  const bool callbackAborted = http.callbackAborted();
  const bool transportAborted = http.aborted();
  const bool responseComplete = http.responseComplete();
  const bool hasContentLength = http.hasContentLength();
  const size_t contentLength = hasContentLength ? http.getContentLength() : 0;
  http.end();

  SyncResult failure = SyncResult::UPDATED;
  if (status == 401 || status == 403) {
    failure = SyncResult::UNAUTHORIZED;
  } else if (status != 200) {
    failure = SyncResult::NETWORK_ERROR;
  } else if (!durable) {
    failure = SyncResult::STORAGE_ERROR;
  } else if (overflow || hashFailed || (callbackAborted && !transportAborted) || received != card.reportBytes ||
             (hasContentLength && contentLength != card.reportBytes)) {
    failure = SyncResult::INVALID_DATA;
  } else if (!responseComplete || transportAborted) {
    failure = SyncResult::NETWORK_ERROR;
  }

  uint8_t digest[32];
  if (failure == SyncResult::UPDATED &&
      (mbedtls_sha256_finish(&sha.context, digest) != 0 || !digestMatchesHex(digest, card.reportSha256))) {
    failure = SyncResult::INVALID_DATA;
  }
  if (failure != SyncResult::UPDATED) {
    if (!removeAtomicTemporary(tempPath)) return SyncResult::STORAGE_ERROR;
    LOG_ERR("XFEED", "Report fetch failed for %s (status=%d bytes=%u)", card.taskId, status,
            static_cast<unsigned>(received));
    return failure;
  }
  bool previousExisted = false;
  if (!promoteAtomicFile(tempPath, finalPath, previousExisted)) {
    removeAtomicTemporary(tempPath);
    return SyncResult::STORAGE_ERROR;
  }
  if (!validateReportFile(finalPath, card.reportBytes, card.reportSha256)) {
    if (!rollbackAtomicFile(finalPath, previousExisted)) {
      LOG_ERR("XFEED", "Report readback failed and rollback could not restore %s", finalPath);
    }
    return SyncResult::STORAGE_ERROR;
  }
  if (!commitAtomicFile(finalPath)) return SyncResult::STORAGE_ERROR;
  promotedReport = true;
  return SyncResult::UPDATED;
}

XtinctFeedClient::SyncResult XtinctFeedClient::downloadAndStageChangedCards(V1TransactionPlan& plan) {
  auto http = makeUniqueNoThrow<freeink::SecureHttpClient>();
  if (!http) {
    LOG_ERR("XFEED", "OOM: secure HTTP client");
    return SyncResult::NETWORK_ERROR;
  }
  http->setTimeout(20000);
  http->setUserAgent("XTINCT-X3-" CROSSPOINT_VERSION);
  http->setReuse(true);
  http->setFollowRedirects(0);
  http->setCACert(XTINCT_WORKER_CA_BUNDLE);

  const std::string& baseUrl = XTINCT_FEED_CONFIG.getBaseUrl();
  const std::string& token = XTINCT_FEED_CONFIG.getReadToken();
  for (uint8_t i = 0; i < remoteCardCount; ++i) {
    size_t taskIndex = 0;
    while (taskIndex < TASK_COUNT && std::strcmp(TASK_IDS[taskIndex], remoteCards[i].id) != 0) ++taskIndex;
    if (taskIndex >= TASK_COUNT) return SyncResult::INVALID_DATA;
    const uint8_t taskBit = static_cast<uint8_t>(1U << taskIndex);
    if ((plan.changedMask & taskBit) == 0) continue;

    int status = 0;
    xtinct::network::BoundedResponseBuffer body(MAX_CARD_BYTES);
    std::string ignoredEtag;
    // The manifest keeps the backward-compatible unqueried card path, while
    // this firmware pins the actual fetch to that manifest's retained strict
    // revision. This prevents manifest A/card B races during a publish.
    const std::string cardUrl =
        baseUrl + remoteCards[i].url + "?revision=" + remoteCards[i].revision;
    const bool fetched = performJsonGet(*http, cardUrl, token, nullptr, status, body, ignoredEtag);
    http->end();  // Drop TLS before allocating/parsing the card document.
    if (!fetched || status != 200) {
      LOG_ERR("XFEED", "Card fetch failed for %s revision %.8s (status=%d)", remoteCards[i].id,
              remoteCards[i].revision, status);
      return body.limitExceeded() ? SyncResult::INVALID_DATA : SyncResult::NETWORK_ERROR;
    }
    auto parsedCard = makeUniqueNoThrow<XtinctDailyCard>();
    if (!parsedCard) {
      LOG_ERR("XFEED", "OOM: downloaded card validator (heap=%u max=%u)",
              static_cast<unsigned>(ESP.getFreeHeap()), static_cast<unsigned>(ESP.getMaxAllocHeap()));
      return SyncResult::NETWORK_ERROR;
    }
    if (!parseCard(remoteCards[i].id, remoteCards[i].revision, body.data(), body.size(), parsedCard.get())) {
      LOG_ERR("XFEED", "Rejected invalid card for %s", remoteCards[i].id);
      return SyncResult::INVALID_DATA;
    }

    char path[96];
    cardPath(remoteCards[i].id, path, sizeof(path));
    char stagedCardPath[128];
    if (!stageAtomicFile(path, body.data(), body.size(), stagedCardPath, sizeof(stagedCardPath))) {
      LOG_ERR("XFEED", "Could not stage card for %s", remoteCards[i].id);
      return SyncResult::STORAGE_ERROR;
    }
    if (!sha256BytesHex(body.data(), body.size(), plan.targetCardSha256[taskIndex])) {
      removeAtomicTemporary(stagedCardPath);
      return SyncResult::INVALID_DATA;
    }
    body.release();  // The report TLS handshake must not overlap the JSON body.

    bool promotedReport = false;
    const SyncResult reportResult = downloadAndCacheReport(*http, baseUrl, token, *parsedCard, promotedReport);
    http->end();  // Release any report TLS state before SD promotion/readback.
    if (reportResult != SyncResult::UPDATED) {
      if (Storage.exists(stagedCardPath) && !Storage.remove(stagedCardPath)) {
        LOG_ERR("XFEED", "Could not remove staged card after report failure");
      }
      return reportResult;
    }
    (void)promotedReport;  // The revision-named report remains an inert orphan until its card commits.
  }
  return SyncResult::UPDATED;
}

bool XtinctFeedClient::promoteStagedCards(const V1TransactionPlan& plan) {
  for (size_t taskIndex = 0; taskIndex < TASK_COUNT; ++taskIndex) {
    const uint8_t bit = static_cast<uint8_t>(1U << taskIndex);
    if ((plan.changedMask & bit) == 0) continue;
    char finalPath[96];
    char temporaryPath[128];
    cardPath(TASK_IDS[taskIndex], finalPath, sizeof(finalPath));
    if (snprintf(temporaryPath, sizeof(temporaryPath), "%s.tmp", finalPath) >=
            static_cast<int>(sizeof(temporaryPath)) ||
        !fileMatchesSha256(temporaryPath, MAX_CARD_BYTES, plan.targetCardSha256[taskIndex])) {
      LOG_ERR("XFEED", "Staged card identity changed before promotion for %s", TASK_IDS[taskIndex]);
      return false;
    }

    const bool expectedPrevious = (plan.previousCardMask & bit) != 0;
    if (Storage.exists(finalPath) != expectedPrevious ||
        (expectedPrevious && !fileMatchesSha256(finalPath, MAX_CARD_BYTES,
                                                plan.previousCardSha256[taskIndex]))) {
      LOG_ERR("XFEED", "Previous card identity changed before promotion for %s", TASK_IDS[taskIndex]);
      return false;
    }

    bool previousExisted = false;
    if (!promoteAtomicFile(temporaryPath, finalPath, previousExisted) ||
        previousExisted != expectedPrevious ||
        !fileMatchesSha256(finalPath, MAX_CARD_BYTES, plan.targetCardSha256[taskIndex])) {
      LOG_ERR("XFEED", "Could not publish staged card for %s", TASK_IDS[taskIndex]);
      return false;
    }
  }
  return true;
}

bool XtinctFeedClient::validateTargetCards(const V1TransactionPlan& plan) {
  auto card = makeUniqueNoThrow<XtinctDailyCard>();
  if (!card) return false;
  for (size_t index = 0; index < TASK_COUNT; ++index) {
    const uint8_t bit = static_cast<uint8_t>(1U << index);
    if ((plan.remoteMask & bit) == 0) continue;
    char path[96];
    cardPath(TASK_IDS[index], path, sizeof(path));
    const char* expectedSha = (plan.changedMask & bit) != 0
                                  ? plan.targetCardSha256[index]
                                  : plan.previousCardSha256[index];
    if (((plan.changedMask & bit) == 0 && (plan.previousCardMask & bit) == 0) ||
        !fileMatchesSha256(path, MAX_CARD_BYTES, expectedSha) ||
        !validatePocketCardFile(TASK_IDS[index], plan.targetRevisions[index], path, card.get()) ||
        !validateCachedReport(*card)) {
      LOG_ERR("XFEED", "Target transaction card failed final validation for %s", TASK_IDS[index]);
      return false;
    }
  }
  return true;
}

XtinctFeedClient::SyncResult XtinctFeedClient::sync() {
  if (!recoverPendingTransaction()) return SyncResult::STORAGE_ERROR;
  if (!XTINCT_FEED_CONFIG.hasReadToken() || !XtinctFeedConfigStore::isValidBaseUrl(XTINCT_FEED_CONFIG.getBaseUrl())) {
    return SyncResult::NO_CONFIG;
  }
  if (WiFi.status() != WL_CONNECTED) return SyncResult::NO_WIFI;

  loadCachedRevisions();

  char etag[96] = {0};
  Storage.readFileToBuffer(ETAG_PATH, etag, sizeof(etag), sizeof(etag) - 1);
  if (etag[0] != '\0' && !isSafeHeaderValue(etag)) {
    LOG_ERR("XFEED", "Ignoring invalid cached manifest ETag");
    etag[0] = '\0';
  }

  const std::string manifestUrl = XTINCT_FEED_CONFIG.getBaseUrl() + "/v1/manifest.json";
  // At most two manifest requests: the normal conditional request, followed
  // by one unconditional recovery request only when a 304 points at an
  // unusable local manifest/card set.
  for (uint8_t requestIndex = 0; requestIndex < 2; ++requestIndex) {
    const char* requestEtag = requestIndex == 0 && etag[0] != '\0' ? etag : nullptr;
    auto http = makeUniqueNoThrow<freeink::SecureHttpClient>();
    if (!http) {
      LOG_ERR("XFEED", "OOM: manifest HTTP client");
      return SyncResult::NETWORK_ERROR;
    }
    http->setTimeout(20000);
    http->setUserAgent("XTINCT-X3-" CROSSPOINT_VERSION);
    http->setReuse(false);
    http->setFollowRedirects(0);
    http->setCACert(XTINCT_WORKER_CA_BUNDLE);

    int status = 0;
    xtinct::network::BoundedResponseBuffer body(MAX_MANIFEST_BYTES);
    std::string responseEtag;
    const bool fetched = performJsonGet(*http, manifestUrl, XTINCT_FEED_CONFIG.getReadToken(), requestEtag,
                                        status, body, responseEtag);
    http->end();
    http.reset();  // Release TLS and its header vectors before JSON/cache work.
    if (!fetched) {
      return body.limitExceeded() ? SyncResult::INVALID_DATA : SyncResult::NETWORK_ERROR;
    }
    if (status == 304) {
      if (requestIndex == 0 && requestEtag && validateCachedManifestAndCards(requestEtag)) {
        // Cached finals have just passed byte-count/SHA validation, so any
        // remaining sidecars are conclusively stale rather than crash-recovery
        // copies of a missing final.
        if (!sweepReportCache()) return SyncResult::STORAGE_ERROR;
        return SyncResult::NOT_MODIFIED;
      }
      if (requestIndex != 0 || !requestEtag) return SyncResult::INVALID_DATA;

      LOG_ERR("XFEED", "304 referenced unusable cache; forcing one unconditional manifest fetch");
      if (Storage.exists(ETAG_PATH) && !Storage.remove(ETAG_PATH)) return SyncResult::STORAGE_ERROR;
      etag[0] = '\0';
      // Do not trust any revision-only cache entries during recovery. The
      // unconditional manifest response must re-download every referenced
      // card so a structurally invalid same-revision card is repaired too.
      cachedRevisionCount = 0;
      continue;
    }
    if (status == 401 || status == 403) return SyncResult::UNAUTHORIZED;
    if (status != 200) return SyncResult::NETWORK_ERROR;

    char bodyEtag[96] = {0};
    if (!parseManifest(body.data(), body.size(), bodyEtag, sizeof(bodyEtag))) return SyncResult::INVALID_DATA;
    if (!responseEtag.empty() && responseEtag != bodyEtag) return SyncResult::INVALID_DATA;

    auto plan = makeUniqueNoThrow<V1TransactionPlan>();
    if (!plan || !copyText(plan->targetEtag, sizeof(plan->targetEtag), bodyEtag) ||
        !sha256BytesHex(body.data(), body.size(), plan->targetManifestSha256)) {
      return SyncResult::NETWORK_ERROR;
    }
    plan->previousManifestExisted = Storage.exists(MANIFEST_PATH);
    if (plan->previousManifestExisted &&
        !sha256FileHex(MANIFEST_PATH, MAX_MANIFEST_BYTES, plan->previousManifestSha256)) {
      return SyncResult::STORAGE_ERROR;
    }
    for (size_t taskIndex = 0; taskIndex < TASK_COUNT; ++taskIndex) {
      const uint8_t bit = static_cast<uint8_t>(1U << taskIndex);
      char path[96];
      cardPath(TASK_IDS[taskIndex], path, sizeof(path));
      if (Storage.exists(path)) {
        if (!sha256FileHex(path, MAX_CARD_BYTES, plan->previousCardSha256[taskIndex])) {
          return SyncResult::STORAGE_ERROR;
        }
        plan->previousCardMask |= bit;
      }
      for (uint8_t remoteIndex = 0; remoteIndex < remoteCardCount; ++remoteIndex) {
        if (std::strcmp(remoteCards[remoteIndex].id, TASK_IDS[taskIndex]) != 0) continue;
        plan->remoteMask |= bit;
        if (!copyText(plan->targetRevisions[taskIndex], sizeof(plan->targetRevisions[taskIndex]),
                      remoteCards[remoteIndex].revision)) {
          return SyncResult::INVALID_DATA;
        }
        bool unchanged = false;
        for (uint8_t cachedIndex = 0; cachedIndex < cachedRevisionCount; ++cachedIndex) {
          if (std::strcmp(cachedRevisions[cachedIndex].id, TASK_IDS[taskIndex]) == 0 &&
              std::strcmp(cachedRevisions[cachedIndex].revision,
                          remoteCards[remoteIndex].revision) == 0) {
            unchanged = true;
            break;
          }
        }
        if (!unchanged) plan->changedMask |= bit;
        break;
      }
    }

    // Durably own the validated raw response before releasing its 8 KiB RAM
    // buffer. Publication is deliberately deferred until every referenced
    // card/report has committed and pruning has succeeded.
    char stagedManifestPath[128];
    if (!stageAtomicFile(MANIFEST_PATH, body.data(), body.size(), stagedManifestPath,
                         sizeof(stagedManifestPath))) {
      return SyncResult::STORAGE_ERROR;
    }
    body.release();
    const SyncResult cardResult = downloadAndStageChangedCards(*plan);
    if (cardResult != SyncResult::UPDATED) {
      return rollBackTransaction(*plan) ? cardResult : SyncResult::STORAGE_ERROR;
    }
    if (!writeTransactionPlan(*plan)) {
      if (!rollBackTransaction(*plan)) LOG_ERR("XFEED", "Unjournaled staging rollback remains pending");
      return SyncResult::STORAGE_ERROR;
    }
    if (!promoteStagedCards(*plan)) {
      if (!rollBackTransaction(*plan)) LOG_ERR("XFEED", "Card transaction rollback remains pending");
      return SyncResult::STORAGE_ERROR;
    }
    if (!validateTargetCards(*plan)) {
      if (!rollBackTransaction(*plan)) LOG_ERR("XFEED", "Target-card rollback remains pending");
      return SyncResult::STORAGE_ERROR;
    }
    bool previousManifestExisted = false;
    if (!promoteAtomicFile(stagedManifestPath, MANIFEST_PATH, previousManifestExisted) ||
        previousManifestExisted != plan->previousManifestExisted ||
        !fileMatchesSha256(MANIFEST_PATH, MAX_MANIFEST_BYTES, plan->targetManifestSha256)) {
      if (!rollBackTransaction(*plan)) LOG_ERR("XFEED", "Manifest transaction rollback remains pending");
      return SyncResult::STORAGE_ERROR;
    }
    if (!finishCommittedTransaction(*plan)) return SyncResult::STORAGE_ERROR;
    return SyncResult::UPDATED;
  }
  return SyncResult::INVALID_DATA;
}

bool parseCardObject(const char* expectedTaskId, const char* expectedRevision, const JsonObjectConst doc,
                     XtinctDailyCard* parsedCard) {
  if ((doc["schema"] | 0) != 1) return false;
  const char* taskId = doc["task_id"] | "";
  const char* revision = doc["revision"] | "";
  const char* title = doc["title"] | "";
  const char* summary = doc["summary"] | "";
  const char* generatedAt = doc["generated_at"] | "";
  if (!isAllowedTaskId(taskId) || !isSafeRevision(revision) || title[0] == '\0' || summary[0] == '\0' ||
      generatedAt[0] == '\0' ||
      (expectedTaskId && strcmp(taskId, expectedTaskId) != 0) ||
      (expectedRevision && expectedRevision[0] != '\0' && strcmp(revision, expectedRevision) != 0)) {
    return false;
  }
  std::unique_ptr<XtinctDailyCard> validationCard;
  if (!parsedCard) validationCard = makeUniqueNoThrow<XtinctDailyCard>();
  XtinctDailyCard* card = parsedCard ? parsedCard : validationCard.get();
  if (!card) {
    LOG_ERR("XFEED", "OOM: Daily Card parser");
    return false;
  }
  memset(card, 0, sizeof(*card));
  card->state = XtinctCardState::OK;
  if (!copyText(card->taskId, sizeof(card->taskId), taskId) ||
      !copyText(card->revision, sizeof(card->revision), revision) ||
      !copyText(card->generatedAt, sizeof(card->generatedAt), generatedAt) ||
      !copyText(card->title, sizeof(card->title), title) || !copyText(card->summary, sizeof(card->summary), summary)) {
    return false;
  }
  card->priority = std::min<uint8_t>(doc["priority"] | static_cast<uint8_t>(0), 3);
  card->state = parseState(doc["state"] | "ok");

  const JsonVariantConst reportValue = doc["report"];
  if (!reportValue.isNull()) {
    if (!reportValue.is<JsonObjectConst>()) return false;
    const JsonObjectConst report = reportValue.as<JsonObjectConst>();
    if (report.size() != 3 || !report.containsKey("url") || !report.containsKey("bytes") ||
        !report.containsKey("sha256")) {
      return false;
    }
    const char* url = report["url"] | "";
    const char* sha256 = report["sha256"] | "";
    if (!report["bytes"].is<uint32_t>()) return false;
    const uint32_t bytes = report["bytes"].as<uint32_t>();
    char expectedUrl[128];
    if (bytes == 0 || bytes > MAX_REPORT_BYTES || !isLowerHex(sha256, 64) ||
        !expectedReportUrl(taskId, revision, expectedUrl, sizeof(expectedUrl)) || strcmp(url, expectedUrl) != 0 ||
        !copyText(card->reportSha256, sizeof(card->reportSha256), sha256)) {
      return false;
    }
    card->hasReport = true;
    card->reportBytes = bytes;
  }

  const JsonArrayConst metrics = doc["metrics"].as<JsonArrayConst>();
  if (metrics.size() > 4) return false;
  for (JsonObjectConst metric : metrics) {
    auto& target = card->metrics[card->metricCount];
    if (!copyText(target.label, sizeof(target.label), metric["label"] | "") ||
        !copyText(target.value, sizeof(target.value), metric["value"] | "") ||
        !copyText(target.tone, sizeof(target.tone), metric["tone"] | "neutral")) {
      return false;
    }
    if (target.label[0] != '\0' && target.value[0] != '\0') card->metricCount++;
  }

  const JsonArrayConst sections = doc["sections"].as<JsonArrayConst>();
  if (sections.size() > 3) return false;
  for (JsonObjectConst section : sections) {
    auto& target = card->sections[card->sectionCount];
    if (!copyText(target.heading, sizeof(target.heading), section["heading"] | "")) return false;
    const JsonArrayConst lines = section["lines"].as<JsonArrayConst>();
    if (lines.size() > 4) return false;
    for (JsonVariantConst lineValue : lines) {
      const char* line = lineValue | "";
      if (!copyText(target.lines[target.lineCount], sizeof(target.lines[target.lineCount]), line)) return false;
      if (target.lines[target.lineCount][0] != '\0') target.lineCount++;
    }
    if (target.heading[0] != '\0' && target.lineCount > 0) card->sectionCount++;
  }

  return true;
}

bool XtinctFeedClient::parseCard(const char* expectedTaskId, const char* expectedRevision, const char* body,
                                 const size_t bodyLength, XtinctDailyCard* parsedCard) {
  if (!body || bodyLength == 0 || bodyLength > MAX_CARD_BYTES) return false;
  JsonDocument doc;
  const DeserializationError error = deserializeJson(doc, body, bodyLength);
  return !error && doc.is<JsonObjectConst>() &&
         parseCardObject(expectedTaskId, expectedRevision, doc.as<JsonObjectConst>(), parsedCard);
}

bool XtinctFeedClient::cachedReportPath(const XtinctDailyCard& card, char* path, const size_t pathSize) {
  if (!card.hasReport || card.reportBytes == 0 || card.reportBytes > MAX_REPORT_BYTES ||
      !isLowerHex(card.reportSha256, 64)) {
    return false;
  }
  return reportPath(card.taskId, card.revision, path, pathSize);
}

bool XtinctFeedClient::loadCardByTaskId(const char* taskId, XtinctDailyCard& out) {
  if (!isAllowedTaskId(taskId)) return false;
  char path[96];
  if (!validatePocketCardFile(taskId, nullptr, cardPath(taskId, path, sizeof(path)), &out)) return false;
  if (out.hasReport && !validateCachedReport(out)) {
    LOG_ERR("XFEED", "Cached report unavailable for %s", taskId);
    out.hasReport = false;
    out.reportBytes = 0;
    out.reportSha256[0] = '\0';
  }
  return true;
}

size_t XtinctFeedClient::cachedCardCount() {
  if (!recoverPendingTransaction()) return 0;
  size_t count = 0;
  for (const char* id : TASK_IDS) {
    char path[96];
    if (Storage.exists(cardPath(id, path, sizeof(path)))) count++;
  }
  return count;
}

bool XtinctFeedClient::loadCachedCard(const size_t availableIndex, XtinctDailyCard& out) {
  size_t current = 0;
  for (const char* id : TASK_IDS) {
    char path[96];
    if (!Storage.exists(cardPath(id, path, sizeof(path)))) continue;
    if (current++ == availableIndex) return loadCardByTaskId(id, out);
  }
  return false;
}

bool XtinctFeedClient::loadBestCachedCard(XtinctDailyCard& out, size_t& availableIndex) {
  const size_t count = cachedCardCount();
  auto candidate = makeUniqueNoThrow<XtinctDailyCard>();
  if (!candidate) {
    LOG_ERR("XFEED", "OOM: cached-card selector");
    return false;
  }
  bool found = false;
  int bestScore = INT32_MIN;
  for (size_t i = 0; i < count; ++i) {
    if (!loadCachedCard(i, *candidate)) continue;
    const int score = static_cast<int>(candidate->priority) * 10 + stateRank(candidate->state);
    if (!found || score > bestScore) {
      out = *candidate;
      availableIndex = i;
      bestScore = score;
      found = true;
    }
  }
  return found;
}

bool XtinctFeedClient::writeAtomic(const char* finalPath, const char* content, const size_t contentLength) {
  char tempPath[128];
  if (!stageAtomicFile(finalPath, content, contentLength, tempPath, sizeof(tempPath))) return false;
  bool previousExisted = false;
  if (promoteAtomicFile(tempPath, finalPath, previousExisted)) {
    return commitAtomicFile(finalPath);
  }
  removeAtomicTemporary(tempPath);
  return false;
}

bool XtinctFeedClient::writeAtomic(const char* finalPath, const std::string& content) {
  return writeAtomic(finalPath, content.data(), content.size());
}

bool XtinctFeedClient::writeAtomic(const char* finalPath, const char* content) {
  return content && writeAtomic(finalPath, content, std::strlen(content));
}

const char* XtinctFeedClient::resultMessageKey(const SyncResult result) {
  switch (result) {
    case SyncResult::UPDATED:
      return "updated";
    case SyncResult::NOT_MODIFIED:
      return "current";
    case SyncResult::NO_CONFIG:
      return "not-configured";
    case SyncResult::NO_WIFI:
      return "no-wifi";
    case SyncResult::CLOCK_ERROR:
      return "clock-error";
    case SyncResult::UNAUTHORIZED:
      return "unauthorized";
    case SyncResult::INVALID_DATA:
      return "invalid-data";
    case SyncResult::STORAGE_ERROR:
      return "storage-error";
    case SyncResult::NETWORK_ERROR:
    default:
      return "network-error";
  }
}

bool XtinctFeedClient::validatePocketCardJson(const char* expectedTaskId, const char* expectedRevision,
                                               const std::string& body, XtinctDailyCard* parsedCard) {
  return parseCard(expectedTaskId, expectedRevision, body.data(), body.size(), parsedCard);
}

bool XtinctFeedClient::validatePocketCardFile(const char* expectedTaskId, const char* expectedRevision,
                                              const char* stagedPath, XtinctDailyCard* parsedCard) {
  if (!stagedPath) return false;
  HalFile file;
  if (!Storage.openFileForRead("XFEED", stagedPath, file)) return false;
  const uint64_t bytes = file.fileSize64();
  if (bytes == 0 || bytes > MAX_CARD_BYTES) {
    file.close();
    return false;
  }
  HalJsonReader reader(file);
  JsonDocument document;
  const DeserializationError error = deserializeJson(document, reader);
  file.close();
  return !error && document.is<JsonObjectConst>() &&
         parseCardObject(expectedTaskId, expectedRevision, document.as<JsonObjectConst>(), parsedCard);
}

bool XtinctFeedClient::validatePocketReportFile(const XtinctDailyCard& card, const char* stagedPath) {
  return card.hasReport && validateReportFile(stagedPath, card.reportBytes, card.reportSha256);
}

bool XtinctFeedClient::pocketCardFinalPath(const char* taskId, char* path, const size_t pathSize) {
  if (!isAllowedTaskId(taskId) || !path || pathSize == 0) return false;
  const int written = std::snprintf(path, pathSize, "%s/%s.json", CARD_DIR, taskId);
  return written > 0 && written < static_cast<int>(pathSize);
}

bool XtinctFeedClient::pocketReportFinalPath(const char* taskId, const char* revision, char* path,
                                             const size_t pathSize) {
  return reportPath(taskId, revision, path, pathSize);
}

const char* XtinctFeedClient::pocketManifestFinalPath() { return MANIFEST_PATH; }

const char* XtinctFeedClient::pocketManifestEtagFinalPath() { return ETAG_PATH; }

uint8_t XtinctFeedClient::pocketCachedRevisionMask(char revisions[4][33]) {
  if (!revisions) return 0;
  std::memset(revisions, 0, sizeof(char) * 4 * 33);
  auto card = makeUniqueNoThrow<XtinctDailyCard>();
  if (!card) return 0;
  uint8_t mask = 0;
  for (size_t index = 0; index < TASK_COUNT; ++index) {
    char path[96];
    const char* cachedPath = cardPath(TASK_IDS[index], path, sizeof(path));
    if (cachedPath && validatePocketCardFile(TASK_IDS[index], nullptr, cachedPath, card.get()) &&
        validateCachedReport(*card) && copyText(revisions[index], 33, card->revision)) {
      mask |= static_cast<uint8_t>(1U << index);
    }
  }
  return mask;
}
