#include "PocketSyncStore.h"

#include <Arduino.h>
#include <ArduinoJson.h>
#include <HalStorage.h>
#include <Logging.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>

#include <StreamingJsonParser.h>
#include "XtinctBuildInfo.h"
#include "network/XtinctFeedClient.h"
#include "network/XtinctSyncClient.h"
#include "util/XtinctReportCacheNaming.h"

namespace {
using xtinct::pocket_sync::MAX_MANIFEST_BYTES;
using xtinct::pocket_sync::MAX_OBJECTS;
using xtinct::pocket_sync::MAX_OBJECT_BYTES;
using xtinct::pocket_sync::MAX_PACK_BYTES;
using xtinct::pocket_sync::MAX_PLAN_OPERATIONS;
using xtinct::pocket_sync::MANIFEST_STREAM;
using xtinct::pocket_sync::Phase;
using xtinct::pocket_sync::Result;
using xtinct::sync_v2::Kind;

static_assert(sizeof(XtinctDailyCard) == 4244, "Pocket Sync V1 transient budget changed");
static_assert(sizeof(XtinctInboxItem) == 796, "Pocket Sync V2 transient budget changed");

constexpr char ROOT_DIR[] = "/.crosspoint/xtinct-pocket";
constexpr char INCOMING_DIR[] = "/.crosspoint/xtinct-pocket/incoming";
constexpr char RECEIPTS_PATH[] = "/.crosspoint/xtinct-pocket/receipts.json";
constexpr char ACTIVE_COMMIT_PATH[] = "/.crosspoint/xtinct-pocket/active-commit.json";
constexpr char PUBLIC_FAILURE_PATH[] = "/psync-status.txt";
constexpr char V1_ROOT_DIR[] = "/.crosspoint/xtinct";
constexpr char V1_CARD_DIR[] = "/.crosspoint/xtinct/cards";
constexpr char V1_REPORT_DIR[] = "/.crosspoint/xtinct/reports";
constexpr char V2_ROOT_DIR[] = "/.crosspoint/xtinct-v2";
constexpr char V2_INBOX_DIR[] = "/.crosspoint/xtinct-v2/inbox";
constexpr char V2_ARTIFACT_DIR[] = "/.crosspoint/xtinct-v2/artifacts";
constexpr size_t MAX_PLAN_LINE_BYTES = 768;
constexpr size_t MAX_RECEIPT_HISTORY = 16;
constexpr size_t COPY_BUFFER_BYTES = 1024;
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

bool isLowerHex(const char* value, const size_t exactLength) {
  if (!value || std::strlen(value) != exactLength) return false;
  for (size_t index = 0; index < exactLength; ++index) {
    const char c = value[index];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

uint8_t hexNibble(const char value) {
  return value <= '9' ? static_cast<uint8_t>(value - '0') : static_cast<uint8_t>(value - 'a' + 10);
}

void bytesToHex(const uint8_t* bytes, const size_t length, char* output) {
  constexpr char HEX_DIGITS[] = "0123456789abcdef";
  for (size_t index = 0; index < length; ++index) {
    output[index * 2] = HEX_DIGITS[bytes[index] >> 4];
    output[index * 2 + 1] = HEX_DIGITS[bytes[index] & 0x0f];
  }
  output[length * 2] = '\0';
}

bool hexToBytes(const char* input, const size_t inputLength, uint8_t* output) {
  if (!isLowerHex(input, inputLength) || (inputLength & 1U) != 0) return false;
  for (size_t index = 0; index < inputLength / 2; ++index) {
    output[index] = static_cast<uint8_t>((hexNibble(input[index * 2]) << 4) | hexNibble(input[index * 2 + 1]));
  }
  return true;
}

bool parseDecimal(const char* value, uint64_t& result) {
  if (!value || value[0] == '\0') return false;
  if (value[0] == '0' && value[1] != '\0') return false;
  result = 0;
  for (const char* cursor = value; *cursor; ++cursor) {
    if (*cursor < '0' || *cursor > '9') return false;
    const uint8_t digit = static_cast<uint8_t>(*cursor - '0');
    if (result > (std::numeric_limits<uint64_t>::max() - digit) / 10U) return false;
    result = result * 10U + digit;
  }
  return true;
}

bool readBoundedOwnedTextFile(const char* path, const size_t maximum, std::unique_ptr<char[]>& content,
                              size_t& length) {
  content.reset();
  length = 0;
  if (!path || maximum == 0) return false;
  HalFile file;
  if (!Storage.openFileForRead("PSYNC", path, file)) return false;
  const uint64_t fileBytes = file.fileSize64();
  if (!xtinct::pocket_sync::validBoundedTextFileSize(fileBytes, maximum)) {
    file.close();
    return false;
  }
  const size_t boundedBytes = static_cast<size_t>(fileBytes);
  std::unique_ptr<char[]> bounded(new (std::nothrow) char[boundedBytes + 1U]);
  if (!bounded) {
    file.close();
    return false;
  }
  size_t readBytes = 0;
  bool readOk = true;
  while (readBytes < boundedBytes) {
    const int amount = file.read(bounded.get() + readBytes, boundedBytes - readBytes);
    if (amount <= 0 || static_cast<size_t>(amount) > boundedBytes - readBytes) {
      readOk = false;
      break;
    }
    readBytes += static_cast<size_t>(amount);
  }
  const bool closeOk = file.close();
  if (!readOk || !closeOk || readBytes != boundedBytes ||
      std::memchr(bounded.get(), '\0', boundedBytes) != nullptr) {
    return false;
  }
  bounded[boundedBytes] = '\0';
  content = std::move(bounded);
  length = boundedBytes;
  return true;
}

bool boundedAscii(const char* value, const size_t maximum, const bool allowEmpty = false) {
  if (!value) return false;
  const size_t length = std::strlen(value);
  if ((!allowEmpty && length == 0) || length > maximum) return false;
  for (size_t index = 0; index < length; ++index) {
    const auto c = static_cast<unsigned char>(value[index]);
    if (c < 0x20 || c > 0x7e) return false;
  }
  return true;
}

int taskIndex(const char* taskId) {
  if (!taskId) return -1;
  for (size_t index = 0; index < xtinct::report_cache::TASK_COUNT; ++index) {
    if (std::strcmp(taskId, xtinct::report_cache::TASK_IDS[index]) == 0) return static_cast<int>(index);
  }
  return -1;
}

bool ensureDirectory(const char* path) {
  if (!path || path[0] == '\0') return false;
  if (Storage.exists(path)) return true;
  char buffer[256];
  const size_t len = std::strlen(path);
  if (len >= sizeof(buffer)) return false;
  std::memcpy(buffer, path, len + 1);
  for (size_t i = 1; i < len; ++i) {
    if (buffer[i] == '/') {
      buffer[i] = '\0';
      if (buffer[0] != '\0' && !Storage.exists(buffer)) {
        if (!Storage.mkdir(buffer)) return false;
      }
      buffer[i] = '/';
    }
  }
  return Storage.exists(path) || Storage.mkdir(path);
}

bool ensureAllDirectories() {
  return ensureDirectory("/.crosspoint") && ensureDirectory(ROOT_DIR) && ensureDirectory(INCOMING_DIR) &&
         ensureDirectory(V1_ROOT_DIR) && ensureDirectory(V1_CARD_DIR) && ensureDirectory(V1_REPORT_DIR) &&
         ensureDirectory(V2_ROOT_DIR) && ensureDirectory(V2_INBOX_DIR) && ensureDirectory(V2_ARTIFACT_DIR);
}

bool recoverAtomic(const char* finalPath) {
  if (!finalPath || finalPath[0] == '\0') return false;
  char temporaryPath[240];
  char backupPath[240];
  if (std::snprintf(temporaryPath, sizeof(temporaryPath), "%s.pstmp", finalPath) >=
          static_cast<int>(sizeof(temporaryPath)) ||
      std::snprintf(backupPath, sizeof(backupPath), "%s.psbak", finalPath) >= static_cast<int>(sizeof(backupPath))) {
    return false;
  }
  const bool hasFinal = Storage.exists(finalPath);
  const bool hasBackup = Storage.exists(backupPath);
  const bool hasTemporary = Storage.exists(temporaryPath);
  if (hasFinal) {
    if (hasTemporary && !Storage.remove(temporaryPath)) return false;
    if (hasBackup && !Storage.remove(backupPath)) return false;
    return true;
  }
  if (hasBackup) {
    if (!Storage.rename(backupPath, finalPath) || !Storage.exists(finalPath)) return false;
    if (hasTemporary && !Storage.remove(temporaryPath)) return false;
    return true;
  }
  // A lone temporary has never crossed the final->backup commit point.
  return !hasTemporary || Storage.remove(temporaryPath);
}

bool atomicPromote(const char* temporaryPath, const char* finalPath) {
  if (!recoverAtomic(finalPath)) return false;
  char backupPath[240];
  if (std::snprintf(backupPath, sizeof(backupPath), "%s.psbak", finalPath) >= static_cast<int>(sizeof(backupPath))) {
    return false;
  }
  if (Storage.exists(backupPath) && !Storage.remove(backupPath)) return false;
  const bool hadFinal = Storage.exists(finalPath);
  if (hadFinal && !Storage.rename(finalPath, backupPath)) return false;
  if (!Storage.rename(temporaryPath, finalPath)) {
    if (hadFinal) Storage.rename(backupPath, finalPath);
    return false;
  }
  if (hadFinal && !Storage.remove(backupPath)) LOG_ERR("PSYNC", "Atomic sidecar cleanup failed");
  return true;
}

bool writeAtomic(const char* finalPath, const uint8_t* bytes, const size_t length) {
  if (!finalPath || (!bytes && length != 0) || !recoverAtomic(finalPath)) return false;
  char temporaryPath[240];
  if (std::snprintf(temporaryPath, sizeof(temporaryPath), "%s.pstmp", finalPath) >=
      static_cast<int>(sizeof(temporaryPath))) {
    return false;
  }
  if (Storage.exists(temporaryPath) && !Storage.remove(temporaryPath)) return false;
  HalFile file;
  if (!Storage.openFileForWrite("PSYNC", temporaryPath, file)) return false;
  const bool written = length == 0 || file.write(bytes, length) == length;
  file.flush();
  file.close();
  if (!written || !atomicPromote(temporaryPath, finalPath)) {
    Storage.remove(temporaryPath);
    return false;
  }
  return true;
}

bool writeAtomic(const char* finalPath, const std::string& value) {
  return writeAtomic(finalPath, reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

bool writeJsonAtomic(const char* path, const JsonDocument& document) {
  std::string encoded;
  encoded.reserve(512);
  serializeJson(document, encoded);
  return writeAtomic(path, encoded);
}

bool hashFile(const char* path, const uint64_t expectedBytes, uint8_t digest[32]) {
  if (!path || !digest || expectedBytes > MAX_PACK_BYTES || !recoverAtomic(path)) return false;
  HalFile file;
  if (!Storage.openFileForRead("PSYNC", path, file) || file.fileSize64() != expectedBytes) return false;
  Sha256Scope sha;
  if (mbedtls_sha256_starts(&sha.context, 0) != 0) return false;
  uint8_t buffer[COPY_BUFFER_BYTES];
  uint64_t remaining = expectedBytes;
  while (remaining > 0) {
    const size_t wanted = static_cast<size_t>(std::min<uint64_t>(sizeof(buffer), remaining));
    const int amount = file.read(buffer, wanted);
    if (amount != static_cast<int>(wanted) || mbedtls_sha256_update(&sha.context, buffer, wanted) != 0) {
      file.close();
      return false;
    }
    remaining -= wanted;
  }
  file.close();
  return mbedtls_sha256_finish(&sha.context, digest) == 0;
}

bool hashMatches(const char* path, const uint64_t expectedBytes, const char* expectedHex) {
  if (!isLowerHex(expectedHex, 64)) return false;
  uint8_t expected[32];
  uint8_t actual[32];
  return hexToBytes(expectedHex, 64, expected) && hashFile(path, expectedBytes, actual) &&
         std::memcmp(actual, expected, sizeof(actual)) == 0;
}

bool copyFile(const char* sourcePath, const char* targetPath, const uint64_t expectedBytes,
              const char* expectedSha256) {
  if (!sourcePath || !targetPath || expectedBytes > MAX_PACK_BYTES || !isLowerHex(expectedSha256, 64) ||
      !hashMatches(sourcePath, expectedBytes, expectedSha256)) {
    return false;
  }
  char temporaryPath[240];
  if (std::snprintf(temporaryPath, sizeof(temporaryPath), "%s.pstmp", targetPath) >=
      static_cast<int>(sizeof(temporaryPath))) {
    return false;
  }
  if (Storage.exists(temporaryPath) && !Storage.remove(temporaryPath)) return false;
  HalFile source;
  HalFile target;
  if (!Storage.openFileForRead("PSYNC", sourcePath, source) ||
      !Storage.openFileForWrite("PSYNC", temporaryPath, target)) {
    source.close();
    target.close();
    return false;
  }
  uint8_t buffer[COPY_BUFFER_BYTES];
  uint64_t copied = 0;
  bool ok = true;
  while (copied < expectedBytes) {
    const size_t wanted = static_cast<size_t>(std::min<uint64_t>(sizeof(buffer), expectedBytes - copied));
    const int amount = source.read(buffer, wanted);
    if (amount != static_cast<int>(wanted) || target.write(buffer, wanted) != wanted) {
      ok = false;
      break;
    }
    copied += wanted;
  }
  target.flush();
  target.close();
  source.close();
  if (!ok || copied != expectedBytes || !hashMatches(temporaryPath, expectedBytes, expectedSha256) ||
      !atomicPromote(temporaryPath, targetPath)) {
    Storage.remove(temporaryPath);
    return false;
  }
  return hashMatches(targetPath, expectedBytes, expectedSha256);
}

bool fileDigestInfo(const char* path, uint32_t& bytes, char sha256[65]) {
  HalFile file;
  if (!Storage.openFileForRead("PSYNC", path, file) || file.fileSize64() > MAX_PACK_BYTES) return false;
  const uint64_t size = file.fileSize64();
  file.close();
  if (size > std::numeric_limits<uint32_t>::max()) return false;
  uint8_t digest[32];
  if (!hashFile(path, size, digest)) return false;
  bytes = static_cast<uint32_t>(size);
  bytesToHex(digest, sizeof(digest), sha256);
  return true;
}

bool appendLine(const char* path, const std::string& line) {
  if (!path || line.empty() || line.size() >= MAX_PLAN_LINE_BYTES) return false;
  HalFile file = Storage.open(path, O_WRONLY | O_CREAT | O_APPEND);
  if (!file) return false;
  const bool ok = file.write(line.data(), line.size()) == line.size() && file.write("\n", 1) == 1;
  file.flush();
  file.close();
  return ok;
}

bool appendInstall(const char* planPath, const char* source, const char* target) {
  uint32_t bytes = 0;
  char sha256[65];
  if (!fileDigestInfo(source, bytes, sha256)) return false;
  JsonDocument operation;
  operation["op"] = "install";
  operation["source"] = source;
  operation["target"] = target;
  operation["bytes"] = bytes;
  operation["sha256"] = sha256;
  std::string encoded;
  serializeJson(operation, encoded);
  return appendLine(planPath, encoded);
}

bool appendInstallKnown(const char* planPath, const char* source, const char* target, const uint32_t bytes,
                        const char* sha256) {
  // The plan is built when the manifest is sealed, before object bytes arrive.
  // The source is verified when its stream completes, again before COMMIT, and
  // once more while the atomic install is applied.
  if (!source || !target || !bytes || !isLowerHex(sha256, 64)) return false;
  JsonDocument operation;
  operation["op"] = "install";
  operation["source"] = source;
  operation["target"] = target;
  operation["bytes"] = bytes;
  operation["sha256"] = sha256;
  std::string encoded;
  serializeJson(operation, encoded);
  return appendLine(planPath, encoded);
}

bool appendDelete(const char* planPath, const char* target) {
  JsonDocument operation;
  operation["op"] = "delete";
  operation["target"] = target;
  std::string encoded;
  serializeJson(operation, encoded);
  return appendLine(planPath, encoded);
}

bool readLine(HalFile& file, std::string& line) {
  line.clear();
  while (file.available()) {
    const int raw = file.read();
    if (raw < 0) return false;
    if (raw == '\n') return !line.empty();
    if (raw == '\r') continue;
    if (line.size() + 1 >= MAX_PLAN_LINE_BYTES) return false;
    line.push_back(static_cast<char>(raw));
  }
  return !line.empty();
}

bool safePackHex(const char* value) { return isLowerHex(value, 64); }

bool isAllowedTarget(const char* path) {
  if (!path || path[0] != '/') return false;
  if (std::strcmp(path, "/.crosspoint/xtinct/manifest.json") == 0 ||
      std::strcmp(path, "/.crosspoint/xtinct/manifest.etag") == 0 ||
      std::strcmp(path, "/.crosspoint/xtinct-v2/cursor") == 0) {
    return true;
  }
  constexpr char CARD_PREFIX[] = "/.crosspoint/xtinct/cards/";
  if (std::strncmp(path, CARD_PREFIX, sizeof(CARD_PREFIX) - 1) == 0) {
    const char* fileName = path + sizeof(CARD_PREFIX) - 1;
    for (const char* task : xtinct::report_cache::TASK_IDS) {
      char expected[64];
      std::snprintf(expected, sizeof(expected), "%s.json", task);
      if (std::strcmp(fileName, expected) == 0) return true;
    }
    return false;
  }
  constexpr char REPORT_PREFIX[] = "/.crosspoint/xtinct/reports/";
  if (std::strncmp(path, REPORT_PREFIX, sizeof(REPORT_PREFIX) - 1) == 0) {
    xtinct::report_cache::ManagedFile managed;
    return xtinct::report_cache::parseManagedFilename(path + sizeof(REPORT_PREFIX) - 1, managed) &&
           managed.kind == xtinct::report_cache::FileKind::FINAL;
  }
  constexpr char INBOX_PREFIX[] = "/.crosspoint/xtinct-v2/inbox/";
  if (std::strncmp(path, INBOX_PREFIX, sizeof(INBOX_PREFIX) - 1) == 0) {
    const char* fileName = path + sizeof(INBOX_PREFIX) - 1;
    const size_t length = std::strlen(fileName);
    if (length <= 5 || std::strcmp(fileName + length - 5, ".json") != 0) return false;
    char itemId[33];
    if (length - 5 >= sizeof(itemId)) return false;
    std::memcpy(itemId, fileName, length - 5);
    itemId[length - 5] = '\0';
    return xtinct::sync_v2::isSafeId(itemId);
  }
  constexpr char ARTIFACT_PREFIX[] = "/.crosspoint/xtinct-v2/artifacts/";
  if (std::strncmp(path, ARTIFACT_PREFIX, sizeof(ARTIFACT_PREFIX) - 1) == 0) {
    const char* fileName = path + sizeof(ARTIFACT_PREFIX) - 1;
    char digest[65];
    const size_t length = std::strlen(fileName);
    return length > 4 && std::strcmp(fileName + length - 4, ".tmp") != 0 &&
           std::strcmp(fileName + length - 4, ".bak") != 0 &&
           xtinct::sync_v2::managedArtifactDigest(fileName, digest);
  }
  return false;
}

bool isAllowedSource(const char* path, const char* packRoot) {
  if (!path || !packRoot) return false;
  const size_t rootLength = std::strlen(packRoot);
  return std::strncmp(path, packRoot, rootLength) == 0 && path[rootLength] == '/' &&
         std::strstr(path + rootLength + 1, "..") == nullptr && std::strchr(path + rootLength + 1, '\\') == nullptr;
}

bool validatePlanOperation(const JsonObjectConst operation, const char* packRoot) {
  const char* op = operation["op"] | "";
  const char* target = operation["target"] | "";
  if (!isAllowedTarget(target)) return false;
  if (std::strcmp(op, "delete") == 0) return operation.size() == 2;
  if (std::strcmp(op, "install") != 0 || operation.size() != 5) return false;
  const char* source = operation["source"] | "";
  const char* sha256 = operation["sha256"] | "";
  const uint64_t bytes = operation["bytes"] | static_cast<uint64_t>(MAX_PACK_BYTES + 1ULL);
  return isAllowedSource(source, packRoot) && bytes <= MAX_PACK_BYTES && isLowerHex(sha256, 64);
}

bool removeOwnedDirectory(const char* path, const char* expectedParent) {
  if (!path || !expectedParent) return false;
  const size_t parentLength = std::strlen(expectedParent);
  if (std::strncmp(path, expectedParent, parentLength) != 0 || path[parentLength] != '/' ||
      std::strstr(path + parentLength + 1, "..") != nullptr) {
    return false;
  }
  return !Storage.exists(path) || Storage.removeDir(path);
}

bool copyRawFile(const char* source, const char* destination) {
  uint32_t bytes = 0;
  char digest[65];
  return fileDigestInfo(source, bytes, digest) && copyFile(source, destination, bytes, digest);
}

bool taskReportUrl(const char* taskId, const char* revision, char* output, const size_t outputSize) {
  if (taskIndex(taskId) < 0 || !isLowerHex(revision, 32)) return false;
  const int written = std::snprintf(output, outputSize, "/v1/reports/%s/%s.txt", taskId, revision);
  return written > 0 && written < static_cast<int>(outputSize);
}

bool writePreparedText(const char* path, const std::string& text) { return writeAtomic(path, text); }

bool writeLiteral(HalFile& file, const char* value) {
  if (!value) return false;
  const size_t length = std::strlen(value);
  return file.write(value, length) == length;
}

bool writeJsonValue(HalFile& file, const JsonVariantConst value) {
  const size_t expected = measureJson(value);
  return expected > 0 && serializeJson(value, file) == expected;
}

bool finishPreparedJson(HalFile& file, const char* path, const bool complete, const uint64_t maximumBytes) {
  file.flush();
  const uint64_t bytes = file.fileSize64();
  file.close();
  if (complete && bytes > 0 && bytes <= maximumBytes) return true;
  if (Storage.exists(path) && !Storage.remove(path)) LOG_ERR("PSYNC", "Could not remove invalid prepared JSON");
  return false;
}

// Map the cloud card into the established V1 cache shape directly on SD. This
// deliberately avoids a second JsonDocument and an encoded std::string while
// NimBLE is alive. The resulting file is still parsed by the existing V1
// validator after the cloud document has been released.
bool writeLegacyCardFile(const char* path, const JsonObjectConst card) {
  if (!path || (Storage.exists(path) && !Storage.remove(path))) return false;
  HalFile file;
  if (!Storage.openFileForWrite("PSYNC", path, file)) return false;
  bool ok = writeLiteral(file, "{\"schema\":1,\"task_id\":") && writeJsonValue(file, card["taskId"]) &&
            writeLiteral(file, ",\"revision\":") && writeJsonValue(file, card["revision"]) &&
            writeLiteral(file, ",\"generated_at\":") && writeJsonValue(file, card["updatedAt"]) &&
            writeLiteral(file, ",\"expires_at\":") && writeJsonValue(file, card["expiresAt"]) &&
            writeLiteral(file, ",\"title\":") && writeJsonValue(file, card["title"]) &&
            writeLiteral(file, ",\"summary\":") && writeJsonValue(file, card["summary"]) &&
            writeLiteral(file, ",\"priority\":") && writeJsonValue(file, card["priority"]) &&
            writeLiteral(file, ",\"state\":") && writeJsonValue(file, card["state"]) &&
            writeLiteral(file, ",\"metrics\":") && writeJsonValue(file, card["metrics"]) &&
            writeLiteral(file, ",\"sections\":") && writeJsonValue(file, card["sections"]);
  if (ok && !card["report"].isNull()) {
    const JsonObjectConst report = card["report"].as<JsonObjectConst>();
    char reportUrl[128];
    ok = taskReportUrl(card["taskId"] | "", card["revision"] | "", reportUrl, sizeof(reportUrl)) &&
         writeLiteral(file, ",\"report\":{\"url\":\"") && writeLiteral(file, reportUrl) &&
         writeLiteral(file, "\",\"bytes\":") && writeJsonValue(file, report["bytes"]) &&
         writeLiteral(file, ",\"sha256\":") && writeJsonValue(file, report["sha256"]) && writeLiteral(file, "}");
  }
  ok = ok && writeLiteral(file, "}");
  return finishPreparedJson(file, path, ok, 16U * 1024U);
}

// Same single-DOM rule for V2. The SD shadow is validated through
// XtinctSyncClient::parseDelivery before the normal metadata writer is used.
bool writeLegacyDeliveryFile(const char* path, const JsonObjectConst change) {
  if (!path || (Storage.exists(path) && !Storage.remove(path))) return false;
  HalFile file;
  if (!Storage.openFileForWrite("PSYNC", path, file)) return false;
  const bool ok =
      writeLiteral(file, "{\"delivery_id\":") && writeJsonValue(file, change["deliveryId"]) &&
      writeLiteral(file, ",\"item_id\":") && writeJsonValue(file, change["itemId"]) &&
      writeLiteral(file, ",\"module_id\":") && writeJsonValue(file, change["moduleId"]) &&
      writeLiteral(file, ",\"kind\":") && writeJsonValue(file, change["kind"]) &&
      writeLiteral(file, ",\"title\":") && writeJsonValue(file, change["title"]) &&
      writeLiteral(file, ",\"revision\":") && writeJsonValue(file, change["revision"]) &&
      writeLiteral(file, ",\"sha256\":") && writeJsonValue(file, change["sha256"]) &&
      writeLiteral(file, ",\"bytes\":") && writeJsonValue(file, change["bytes"]) &&
      writeLiteral(file, ",\"mime\":") && writeJsonValue(file, change["mime"]) &&
      writeLiteral(file, ",\"created_at\":") && writeJsonValue(file, change["createdAt"]) &&
      writeLiteral(file, ",\"expires_at\":") && writeJsonValue(file, change["expiresAt"]) &&
      writeLiteral(file, ",\"actions\":") && writeJsonValue(file, change["actions"]) &&
      writeLiteral(file, ",\"metadata\":") && writeJsonValue(file, change["metadata"]) && writeLiteral(file, "}");
  return finishPreparedJson(file, path, ok, 4096U);
}

enum class SliceArray : uint8_t { None, Cards, Changes, Objects };

class JsonBudgetProbe {
 public:
  JsonBudgetProbe()
      : parser(JsonCallbacks{this, eventKey, eventString, eventNumber, eventBool, eventNull, eventContainer,
                             eventContainer, eventContainer, eventContainer}) {}

  bool run(const char* path, const size_t maximumBytes, const size_t maximumEvents) {
    limit = maximumEvents;
    HalFile file;
    if (!Storage.openFileForRead("PSYNC", path, file) || file.fileSize64() > maximumBytes) return false;
    char buffer[256];
    while (!failed && file.available()) {
      const int amount = file.read(buffer, sizeof(buffer));
      if (amount <= 0) {
        failed = true;
        break;
      }
      parser.feed(buffer, static_cast<size_t>(amount));
    }
    file.close();
    return !failed && !parser.hasError() && !parser.hadTokenOverflow() && events <= limit;
  }

 private:
  StreamingJsonParser parser;
  size_t events = 0;
  size_t limit = 0;
  bool failed = false;
  void add() {
    if (++events > limit) failed = true;
  }
  static void eventKey(void* context, const char*, size_t) { static_cast<JsonBudgetProbe*>(context)->add(); }
  static void eventString(void* context, const char*, size_t) { static_cast<JsonBudgetProbe*>(context)->add(); }
  static void eventNumber(void* context, const char*, size_t) { static_cast<JsonBudgetProbe*>(context)->add(); }
  static void eventBool(void* context, bool) { static_cast<JsonBudgetProbe*>(context)->add(); }
  static void eventNull(void* context) { static_cast<JsonBudgetProbe*>(context)->add(); }
  static void eventContainer(void* context) { static_cast<JsonBudgetProbe*>(context)->add(); }
};

class ManifestObjectExtractor {
 public:
  using Handler = bool (*)(void* context, SliceArray array, uint8_t index, const char* slicePath);

  ManifestObjectExtractor(const char* packRoot, Handler handler, void* handlerContext)
      : packRoot(packRoot), handler(handler), handlerContext(handlerContext),
        parser(JsonCallbacks{this, onKey, onString, onNumber, onBool, onNull, onObjectStart, onObjectEnd,
                             onArrayStart, onArrayEnd}) {}

  bool run(const char* manifestPath) {
    if (!manifestPath || !packRoot || !handler) return false;
    HalFile input;
    if (!Storage.openFileForRead("PSYNC", manifestPath, input) || input.fileSize64() > MAX_MANIFEST_BYTES) return false;
    char buffer[512];
    while (!failed && input.available()) {
      const int amount = input.read(buffer, sizeof(buffer));
      if (amount <= 0) {
        failed = true;
        break;
      }
      for (int i = 0; i < amount && !failed; ++i) {
        const char byte = buffer[i];
        const bool wasCapturing = capturing;
        captureStarted = false;
        captureEnded = false;
        parser.feed(&byte, 1);
        if ((wasCapturing || captureStarted) &&
            (!sliceFile || sliceBytes >= sliceLimit || sliceFile.write(&byte, 1) != 1)) {
          failed = true;
        } else if (wasCapturing || captureStarted) {
          ++sliceBytes;
        }
        ++absoluteOffset;
        if (captureEnded && !finishCapture()) failed = true;
      }
    }
    input.close();
    if (sliceFile) sliceFile.close();
    return !failed && !parser.hasError() && !capturing && frameDepth == 0 && rootSeen &&
           counts[static_cast<uint8_t>(SliceArray::Cards)] <= 4 &&
           counts[static_cast<uint8_t>(SliceArray::Changes)] <= 64 &&
           counts[static_cast<uint8_t>(SliceArray::Objects)] <= MAX_OBJECTS;
  }

  uint8_t count(const SliceArray array) const { return counts[static_cast<uint8_t>(array)]; }

 private:
  enum class FrameType : uint8_t { Object, Array };
  enum class Context : uint8_t { Root, V1, V2, Other };
  struct Frame {
    FrameType type = FrameType::Object;
    Context context = Context::Other;
    SliceArray target = SliceArray::None;
  };

  const char* packRoot;
  Handler handler;
  void* handlerContext;
  StreamingJsonParser parser;
  Frame frames[StreamingJsonParser::MAX_NESTING];
  uint8_t frameDepth = 0;
  char lastKey[48] = {0};
  bool rootSeen = false;
  bool failed = false;
  bool capturing = false;
  bool captureStarted = false;
  bool captureEnded = false;
  uint8_t captureFrameDepth = 0;
  SliceArray captureArray = SliceArray::None;
  uint8_t counts[4] = {0};
  size_t captureBytes = 0;
  size_t sliceBytes = 0;
  size_t sliceLimit = 0;
  uint64_t absoluteOffset = 0;
  HalFile sliceFile;
  char slicePath[192] = {0};

  static bool keyEquals(const char* key, const size_t length, const char* expected) {
    return std::strlen(expected) == length && std::memcmp(key, expected, length) == 0;
  }

  static bool rootKeyAllowed(const Context context, const char* key, const size_t length) {
    if (context == Context::Root) {
      constexpr const char* KEYS[] = {"schema", "protocolVersion", "packId", "targetId", "expiresAt",
                                      "v1", "v2", "objects", "totalBytes"};
      for (const char* allowed : KEYS) if (keyEquals(key, length, allowed)) return true;
      return false;
    }
    if (context == Context::V1) return keyEquals(key, length, "status") || keyEquals(key, length, "cards");
    if (context == Context::V2) {
      constexpr const char* KEYS[] = {"status", "mode", "fromCursor", "toCursor", "changes"};
      for (const char* allowed : KEYS) if (keyEquals(key, length, allowed)) return true;
      return false;
    }
    return true;
  }

  Frame* top() { return frameDepth == 0 ? nullptr : &frames[frameDepth - 1]; }

  void beginCapture(const SliceArray array) {
    if (capturing || array == SliceArray::None || counts[static_cast<uint8_t>(array)] >= MAX_OBJECTS) {
      failed = true;
      return;
    }
    if (std::snprintf(slicePath, sizeof(slicePath), "%s/slice.json", packRoot) >=
        static_cast<int>(sizeof(slicePath))) {
      failed = true;
      return;
    }
    if (Storage.exists(slicePath) && !Storage.remove(slicePath)) {
      failed = true;
      return;
    }
    if (!Storage.openFileForWrite("PSYNC", slicePath, sliceFile)) {
      failed = true;
      return;
    }
    captureArray = array;
    captureFrameDepth = frameDepth;
    capturing = true;
    captureStarted = true;
    captureBytes = 0;
    sliceBytes = 0;
    sliceLimit = array == SliceArray::Cards ? 12U * 1024U : (array == SliceArray::Changes ? 6U * 1024U : 1536U);
  }

  bool finishCapture() {
    if (!capturing || !sliceFile) return false;
    sliceFile.flush();
    sliceFile.close();
    const uint8_t index = counts[static_cast<uint8_t>(captureArray)]++;
    const SliceArray completedArray = captureArray;
    capturing = false;
    captureArray = SliceArray::None;
    captureFrameDepth = 0;
    if (!handler(handlerContext, completedArray, index, slicePath)) return false;
    return !Storage.exists(slicePath) || Storage.remove(slicePath);
  }

  static void onKey(void* context, const char* key, const size_t length) {
    auto* self = static_cast<ManifestObjectExtractor*>(context);
    Frame* frame = self->top();
    if (!frame || frame->type != FrameType::Object ||
        (!self->capturing && !rootKeyAllowed(frame->context, key, length)) || length >= sizeof(self->lastKey)) {
      self->failed = true;
      return;
    }
    std::memcpy(self->lastKey, key, length);
    self->lastKey[length] = '\0';
  }

  static void primitive(void* context) {
    auto* self = static_cast<ManifestObjectExtractor*>(context);
    Frame* frame = self->top();
    if (!self->capturing && frame && frame->type == FrameType::Array && frame->target != SliceArray::None) {
      self->failed = true;
    }
    self->lastKey[0] = '\0';
  }
  static void onString(void* context, const char*, size_t) { primitive(context); }
  static void onNumber(void* context, const char*, size_t) { primitive(context); }
  static void onBool(void* context, bool) { primitive(context); }
  static void onNull(void* context) { primitive(context); }

  static void onObjectStart(void* context) {
    auto* self = static_cast<ManifestObjectExtractor*>(context);
    if (self->frameDepth >= StreamingJsonParser::MAX_NESTING) {
      self->failed = true;
      return;
    }
    const Frame* parent = self->top();
    Context objectContext = Context::Other;
    SliceArray parentTarget = SliceArray::None;
    if (!parent) {
      if (self->rootSeen) {
        self->failed = true;
        return;
      }
      self->rootSeen = true;
      objectContext = Context::Root;
    } else if (parent->type == FrameType::Object && parent->context == Context::Root) {
      if (std::strcmp(self->lastKey, "v1") == 0) objectContext = Context::V1;
      else if (std::strcmp(self->lastKey, "v2") == 0) objectContext = Context::V2;
    } else if (parent->type == FrameType::Array) {
      parentTarget = parent->target;
    }
    self->frames[self->frameDepth++] = Frame{FrameType::Object, objectContext, SliceArray::None};
    self->lastKey[0] = '\0';
    if (!self->capturing && parentTarget != SliceArray::None) self->beginCapture(parentTarget);
  }

  static void onObjectEnd(void* context) {
    auto* self = static_cast<ManifestObjectExtractor*>(context);
    if (self->frameDepth == 0 || self->frames[self->frameDepth - 1].type != FrameType::Object) {
      self->failed = true;
      return;
    }
    if (self->capturing && self->frameDepth == self->captureFrameDepth) self->captureEnded = true;
    --self->frameDepth;
    self->lastKey[0] = '\0';
  }

  static void onArrayStart(void* context) {
    auto* self = static_cast<ManifestObjectExtractor*>(context);
    if (self->frameDepth >= StreamingJsonParser::MAX_NESTING) {
      self->failed = true;
      return;
    }
    const Frame* parent = self->top();
    SliceArray target = SliceArray::None;
    if (!self->capturing && parent && parent->type == FrameType::Object) {
      if (parent->context == Context::V1 && std::strcmp(self->lastKey, "cards") == 0) target = SliceArray::Cards;
      else if (parent->context == Context::V2 && std::strcmp(self->lastKey, "changes") == 0)
        target = SliceArray::Changes;
      else if (parent->context == Context::Root && std::strcmp(self->lastKey, "objects") == 0)
        target = SliceArray::Objects;
    }
    self->frames[self->frameDepth++] = Frame{FrameType::Array, Context::Other, target};
    self->lastKey[0] = '\0';
  }

  static void onArrayEnd(void* context) {
    auto* self = static_cast<ManifestObjectExtractor*>(context);
    if (self->frameDepth == 0 || self->frames[self->frameDepth - 1].type != FrameType::Array) {
      self->failed = true;
      return;
    }
    --self->frameDepth;
    self->lastKey[0] = '\0';
  }
};

}  // namespace

PocketSyncStore::PocketSyncStore() = default;

PocketSyncStore::~PocketSyncStore() { closeStream(); }

void PocketSyncStore::fail(const Result result, const uint8_t stream) {
  closeStream();
  setStatus(Phase::Error, result, stream, currentStatus.durableOffset);
}

void PocketSyncStore::setStatus(const Phase phase, const Result result, const uint8_t stream, const uint32_t offset) {
  currentStatus.phase = phase;
  currentStatus.result = result;
  currentStatus.stream = stream;
  currentStatus.durableOffset = offset;
  ++currentStatus.sequence;
}

void PocketSyncStore::recordFailure(const char* site, const Result result, const uint8_t stream,
                                    const uint32_t offset) const {
  char body[224];
  const int length = std::snprintf(
      body, sizeof(body),
      "schema=1\nbuild=%s\nsite=%s\nresult=%u\nstream=%u\noffset=%lu\nsequence=%lu\n",
      XTINCT_BUILD_ID, site ? site : "unknown", static_cast<unsigned>(result),
      static_cast<unsigned>(stream), static_cast<unsigned long>(offset),
      static_cast<unsigned long>(currentStatus.sequence + 1U));
  if (length <= 0 || length >= static_cast<int>(sizeof(body))) return;
  HalFile file = Storage.open(PUBLIC_FAILURE_PATH, O_WRITE | O_CREAT | O_TRUNC);
  if (!file) return;
  file.write(reinterpret_cast<const uint8_t*>(body), static_cast<size_t>(length));
  file.flush();
  file.close();
}

void PocketSyncStore::closeStream() {
  if (streamFile) {
    streamFile.flush();
    streamFile.close();
  }
  openStream = 0xfe;
}

bool PocketSyncStore::ensureBaseDirectories() const { return ensureAllDirectories(); }

bool PocketSyncStore::streamPath(const uint8_t stream, char* path, const size_t pathSize) const {
  if (!path || pathSize == 0 || (!sealed && stream != MANIFEST_STREAM) ||
      (stream != MANIFEST_STREAM && stream >= expectedObjectCount)) {
    return false;
  }
  const int written = stream == MANIFEST_STREAM
                          ? std::snprintf(path, pathSize, "%s/manifest.part", packRoot)
                          : std::snprintf(path, pathSize, "%s/objects/%02u.part", packRoot, stream);
  return written > 0 && written < static_cast<int>(pathSize);
}

bool PocketSyncStore::markerPath(const uint8_t stream, char* path, const size_t pathSize) const {
  if (!path || pathSize == 0) return false;
  const int written = stream == MANIFEST_STREAM
                          ? std::snprintf(path, pathSize, "%s/manifest.sealed", packRoot)
                          : std::snprintf(path, pathSize, "%s/objects/%02u.ok", packRoot, stream);
  return written > 0 && written < static_cast<int>(pathSize);
}

bool PocketSyncStore::offsetPath(const uint8_t stream, char* path, const size_t pathSize) const {
  if (!path || pathSize == 0 || (stream != MANIFEST_STREAM && stream >= expectedObjectCount)) return false;
  const int written = stream == MANIFEST_STREAM
                          ? std::snprintf(path, pathSize, "%s/manifest.offset", packRoot)
                          : std::snprintf(path, pathSize, "%s/objects/%02u.offset", packRoot, stream);
  return written > 0 && written < static_cast<int>(pathSize);
}

bool PocketSyncStore::readDurableOffset(const uint8_t stream, uint32_t& offset) const {
  offset = 0;
  char path[192];
  if (!offsetPath(stream, path, sizeof(path))) return false;
  if (!Storage.exists(path)) return true;
  std::unique_ptr<char[]> value;
  size_t valueLength = 0;
  uint64_t parsed = 0;
  if (!readBoundedOwnedTextFile(path, 10, value, valueLength) || valueLength > 10 ||
      !parseDecimal(value.get(), parsed) || parsed > UINT32_MAX) {
    return false;
  }
  offset = static_cast<uint32_t>(parsed);
  return true;
}

bool PocketSyncStore::writeDurableOffset(const uint8_t stream, const uint32_t offset) const {
  char path[192];
  char value[11];
  if (!offsetPath(stream, path, sizeof(path))) return false;
  const int written = std::snprintf(value, sizeof(value), "%lu", static_cast<unsigned long>(offset));
  return written > 0 && written < static_cast<int>(sizeof(value)) &&
         writeAtomic(path, reinterpret_cast<const uint8_t*>(value), static_cast<size_t>(written));
}

bool PocketSyncStore::discardStreamForRetry(const uint8_t stream) {
  closeStream();
  char path[192];
  char marker[192];
  char offset[192];
  if (!streamPath(stream, path, sizeof(path)) || !markerPath(stream, marker, sizeof(marker)) ||
      !offsetPath(stream, offset, sizeof(offset))) {
    return false;
  }
  // Remove the completion claim first, then the resume checkpoint. If power is
  // lost before the staged bytes are removed, prepareStreamForResume() safely
  // truncates the now-uncheckpointed file to zero on the next START.
  bool removed = true;
  if (Storage.exists(marker) && !Storage.remove(marker)) removed = false;
  if (Storage.exists(offset) && !Storage.remove(offset)) removed = false;
  if (Storage.exists(path) && !Storage.remove(path)) removed = false;
  return removed;
}

bool PocketSyncStore::prepareStreamForResume(const uint8_t stream, uint32_t& offset) {
  closeStream();
  const uint32_t expected = expectedBytesFor(stream);
  char path[192];
  if (expected == 0 || !streamPath(stream, path, sizeof(path))) return false;

  const bool offsetReadable = readDurableOffset(stream, offset);
  const bool exists = Storage.exists(path);
  HalFile file;
  uint64_t size = 0;
  bool readable = true;
  if (exists) {
    file = Storage.open(path, O_RDWR);
    readable = static_cast<bool>(file);
    size = readable ? file.fileSize64() : UINT64_MAX;
  }
  if (xtinct::pocket_sync::resumeStateRequiresReset(offsetReadable, offset, expected, exists, readable, size)) {
    if (file) file.close();
    if (!discardStreamForRetry(stream)) return false;
    offset = 0;
  } else if (exists) {
    if (size > offset && !file.truncate(offset)) {
      file.close();
      // Truncation is only an optimization for an uncheckpointed tail. If the
      // card rejects it, discard this uncommitted stream and let the phone
      // retransmit from zero instead of pinning the pack in StorageError.
      if (!discardStreamForRetry(stream)) return false;
      offset = 0;
    } else {
      if (size > offset) file.flush();
      file.close();
    }
  }
  acceptedOffset = offset;
  chunksSinceStatus = 0;
  return true;
}

bool PocketSyncStore::selectNextObjectForResume(const uint8_t firstStream, uint8_t& nextStream,
                                                uint32_t& offset) {
  nextStream = manifest.objectCount;
  offset = 0;
  for (uint8_t index = firstStream; index < manifest.objectCount; ++index) {
    nextStream = index;
    char path[192];
    char okPath[192];
    if (!streamPath(index, path, sizeof(path)) || !markerPath(index, okPath, sizeof(okPath))) return false;
    if (Storage.exists(okPath)) {
      if (Storage.exists(path) && validateCompletedObject(index)) continue;
      if (!discardStreamForRetry(index)) return false;
    }
    if (!prepareStreamForResume(index, offset)) return false;
    if (offset == expectedBytesFor(index)) {
      if (validateCompletedObject(index)) continue;
      // A complete but unsealed staging object cannot become valid without a
      // retransmission. Reset it so this same session requests byte zero.
      if (!discardStreamForRetry(index) || !prepareStreamForResume(index, offset)) return false;
    }
    return true;
  }
  nextStream = manifest.objectCount;
  offset = 0;
  return true;
}

uint32_t PocketSyncStore::expectedBytesFor(const uint8_t stream) const {
  if (stream == MANIFEST_STREAM) return expectedManifestBytes;
  if (!sealed || stream >= manifest.objectCount) return 0;
  ObjectDescriptor descriptor;
  return readObjectDescriptor(stream, descriptor) ? descriptor.bytes : 0;
}

bool PocketSyncStore::readObjectDescriptor(const uint8_t index, ObjectDescriptor& descriptor) const {
  if (index >= manifest.objectCount) return false;
  char path[192];
  if (std::snprintf(path, sizeof(path), "%s/object-ledger.bin", packRoot) >= static_cast<int>(sizeof(path))) {
    return false;
  }
  HalFile file = Storage.open(path, O_RDONLY);
  const uint64_t expectedSize = static_cast<uint64_t>(manifest.objectCount) * sizeof(ObjectDescriptor);
  if (!file || file.fileSize64() != expectedSize || !file.seek64(static_cast<uint64_t>(index) * sizeof(ObjectDescriptor)) ||
      file.read(&descriptor, sizeof(descriptor)) != static_cast<int>(sizeof(descriptor))) {
    file.close();
    return false;
  }
  file.close();
  return descriptor.index == index && descriptor.source != ObjectSource::Invalid;
}

bool PocketSyncStore::writeObjectDescriptor(const ObjectDescriptor& descriptor) const {
  if (descriptor.index >= expectedObjectCount) return false;
  char path[192];
  if (std::snprintf(path, sizeof(path), "%s/object-ledger.bin", packRoot) >= static_cast<int>(sizeof(path))) {
    return false;
  }
  HalFile file = Storage.open(path, O_RDWR | O_CREAT);
  if (!file || !file.seek64(static_cast<uint64_t>(descriptor.index) * sizeof(ObjectDescriptor)) ||
      file.write(&descriptor, sizeof(descriptor)) != sizeof(descriptor)) {
    file.close();
    return false;
  }
  file.flush();
  file.close();
  return true;
}

bool PocketSyncStore::openStreamAt(const uint8_t stream, const uint32_t offset) {
  if (openStream == stream && streamFile) return streamFile.position() == offset;
  closeStream();
  char path[192];
  if (!streamPath(stream, path, sizeof(path))) return false;
  streamFile = Storage.open(path, O_RDWR | O_CREAT);
  if (!streamFile || streamFile.fileSize64() != offset || !streamFile.seek(offset)) {
    closeStream();
    return false;
  }
  openStream = stream;
  return true;
}

bool PocketSyncStore::writeSessionRecord() const {
  char path[192];
  if (std::snprintf(path, sizeof(path), "%s/session.json", packRoot) >= static_cast<int>(sizeof(path))) return false;
  char manifestHex[65];
  bytesToHex(manifestDigest, sizeof(manifestDigest), manifestHex);
  JsonDocument session;
  session["schema"] = 1;
  session["pack"] = packHex;
  session["manifestBytes"] = expectedManifestBytes;
  session["manifestSha256"] = manifestHex;
  session["objectBytes"] = expectedObjectBytes;
  session["objectCount"] = expectedObjectCount;
  return writeJsonAtomic(path, session);
}

bool PocketSyncStore::readAndValidateSessionRecord() const {
  char path[192];
  if (std::snprintf(path, sizeof(path), "%s/session.json", packRoot) >= static_cast<int>(sizeof(path))) return false;
  std::unique_ptr<char[]> content;
  size_t contentLength = 0;
  if (!readBoundedOwnedTextFile(path, 512, content, contentLength)) return false;
  JsonDocument session;
  if (deserializeJson(session, content.get(), contentLength) || session.size() != 6 ||
      (session["schema"] | 0) != 1) return false;
  char manifestHex[65];
  bytesToHex(manifestDigest, sizeof(manifestDigest), manifestHex);
  return std::strcmp(session["pack"] | "", packHex) == 0 &&
         std::strcmp(session["manifestSha256"] | "", manifestHex) == 0 &&
         (session["manifestBytes"] | 0U) == expectedManifestBytes &&
         (session["objectBytes"] | 0U) == expectedObjectBytes &&
         (session["objectCount"] | 0U) == expectedObjectCount;
}

bool PocketSyncStore::isCompletedReplay() const {
  if (!Storage.exists(RECEIPTS_PATH)) return false;
  std::unique_ptr<char[]> body;
  size_t bodyLength = 0;
  if (!readBoundedOwnedTextFile(RECEIPTS_PATH, 4096, body, bodyLength)) return false;
  JsonDocument document;
  if (deserializeJson(document, body.get(), bodyLength) || !document["packs"].is<JsonArrayConst>()) return false;
  for (const char* completed : document["packs"].as<JsonArrayConst>()) {
    if (completed && std::strcmp(completed, packHex) == 0) return true;
  }
  return false;
}

Result PocketSyncStore::start(const uint8_t suppliedPackDigest[32], const uint32_t manifestBytes,
                              const uint8_t suppliedManifestSha256[32], const uint32_t totalObjectBytes,
                              const uint8_t objectCount, const uint8_t negotiatedChunk) {
  closeStream();
  if (Storage.exists(PUBLIC_FAILURE_PATH)) Storage.remove(PUBLIC_FAILURE_PATH);
  sessionActive = false;
  sealed = false;
  manifest = {};
  if (!suppliedPackDigest || !suppliedManifestSha256 || negotiatedChunk == 0 ||
      !xtinct::pocket_sync::validPackBounds(manifestBytes, objectCount, totalObjectBytes) ||
      !ensureBaseDirectories() || !recoverPendingCommit()) {
    setStatus(Phase::Error, Result::Bounds, MANIFEST_STREAM, 0);
    return currentStatus.result;
  }
  std::memcpy(packDigest, suppliedPackDigest, sizeof(packDigest));
  std::memcpy(manifestDigest, suppliedManifestSha256, sizeof(manifestDigest));
  bytesToHex(packDigest, sizeof(packDigest), packHex);
  std::memcpy(currentStatus.packPrefix, packDigest, sizeof(currentStatus.packPrefix));
  expectedManifestBytes = manifestBytes;
  expectedObjectBytes = totalObjectBytes;
  expectedObjectCount = objectCount;
  currentStatus.negotiatedChunk = negotiatedChunk;
  if (std::snprintf(packRoot, sizeof(packRoot), "%s/%s", INCOMING_DIR, packHex) >=
      static_cast<int>(sizeof(packRoot))) {
    setStatus(Phase::Error, Result::StorageError, MANIFEST_STREAM, 0);
    return currentStatus.result;
  }
  if (isCompletedReplay()) {
    // A retry of the exact sealed pack is an idempotent success. The receipt
    // ledger prevents re-applying it; returning OK lets a phone that lost the
    // final GATT response finish without manufacturing a new package.
    setStatus(Phase::Complete, Result::Ok, expectedObjectCount, 0);
    return Result::Ok;
  }
  const bool existing = Storage.exists(packRoot);
  if (!existing) {
    char objectsPath[192];
    char shadowPath[192];
    if (std::snprintf(objectsPath, sizeof(objectsPath), "%s/objects", packRoot) >=
            static_cast<int>(sizeof(objectsPath)) ||
        std::snprintf(shadowPath, sizeof(shadowPath), "%s/shadow", packRoot) >=
            static_cast<int>(sizeof(shadowPath))) {
      recordFailure("start-path-bounds", Result::StorageError, MANIFEST_STREAM, 0);
      setStatus(Phase::Error, Result::StorageError, MANIFEST_STREAM, 0);
      return currentStatus.result;
    }

    const char* failedSite = "start-new-session";
    const auto createSessionTree = [&]() {
      if (!Storage.mkdir(packRoot)) {
        failedSite = "start-mkdir-pack";
        return false;
      }
      if (!ensureDirectory(objectsPath)) {
        failedSite = "start-mkdir-objects";
        return false;
      }
      if (!ensureDirectory(shadowPath)) {
        failedSite = "start-mkdir-shadow";
        return false;
      }
      if (!writeSessionRecord()) {
        failedSite = "start-write-session";
        return false;
      }
      return true;
    };

    if (!createSessionTree()) {
      // No manifest bytes have been accepted yet. A failed first mkdir/write
      // can therefore be removed and retried once without risking committed
      // Inbox/Card state or weakening the resumable transfer contract.
      if ((Storage.exists(packRoot) && !removeOwnedDirectory(packRoot, INCOMING_DIR)) ||
          Storage.exists(packRoot)) {
        recordFailure("start-cleanup-partial", Result::StorageError, MANIFEST_STREAM, 0);
        setStatus(Phase::Error, Result::StorageError, MANIFEST_STREAM, 0);
        return currentStatus.result;
      }
      if (!createSessionTree()) {
        recordFailure(failedSite, Result::StorageError, MANIFEST_STREAM, 0);
        setStatus(Phase::Error, Result::StorageError, MANIFEST_STREAM, 0);
        return currentStatus.result;
      }
    }
  } else {
    if (!ensureDirectory((std::string(packRoot) + "/objects").c_str()) ||
        !ensureDirectory((std::string(packRoot) + "/shadow").c_str())) {
      recordFailure("start-existing-dirs", Result::StorageError, MANIFEST_STREAM, 0);
      setStatus(Phase::Error, Result::StorageError, MANIFEST_STREAM, 0);
      return currentStatus.result;
    }
    if (!readAndValidateSessionRecord()) {
      if (!removeOwnedDirectory(packRoot, INCOMING_DIR) || Storage.exists(packRoot) || !Storage.mkdir(packRoot) ||
          !ensureDirectory((std::string(packRoot) + "/objects").c_str()) ||
          !ensureDirectory((std::string(packRoot) + "/shadow").c_str()) || !writeSessionRecord()) {
        recordFailure("start-reset-session", Result::StorageError, MANIFEST_STREAM, 0);
        setStatus(Phase::Error, Result::StorageError, MANIFEST_STREAM, 0);
        return currentStatus.result;
      }
    }
  }
  sessionActive = true;
  char sealedPath[192];
  char manifestPath[192];
  markerPath(MANIFEST_STREAM, sealedPath, sizeof(sealedPath));
  streamPath(MANIFEST_STREAM, manifestPath, sizeof(manifestPath));
  if (Storage.exists(sealedPath)) {
    uint8_t actualManifestDigest[32];
    sealed = hashFile(manifestPath, expectedManifestBytes, actualManifestDigest) &&
             std::memcmp(actualManifestDigest, manifestDigest, sizeof(actualManifestDigest)) == 0 &&
             parseAndPrepareManifest();
    if (!sealed) {
      setStatus(Phase::Error, Result::Manifest, MANIFEST_STREAM, 0);
      return currentStatus.result;
    }
  }
  uint8_t nextStream = MANIFEST_STREAM;
  uint32_t offset = 0;
  if (!sealed) {
    if (!prepareStreamForResume(MANIFEST_STREAM, offset)) {
      recordFailure("start-manifest-resume", Result::StorageError, MANIFEST_STREAM, 0);
      setStatus(Phase::Error, Result::StorageError, MANIFEST_STREAM, 0);
      return currentStatus.result;
    }
    setStatus(Phase::Manifest, Result::Ok, MANIFEST_STREAM, offset);
    return Result::Ok;
  }
  if (!selectNextObjectForResume(0, nextStream, offset)) {
    recordFailure("start-object-resume", Result::StorageError, nextStream, offset);
    setStatus(Phase::Error, Result::StorageError, nextStream, offset);
    return currentStatus.result;
  }
  if (nextStream < manifest.objectCount) setStatus(Phase::Objects, Result::Ok, nextStream, offset);
  else setStatus(Phase::Validating, Result::Ok, manifest.objectCount, 0);
  return Result::Ok;
}

Result PocketSyncStore::write(const uint8_t stream, const uint32_t offset, const uint8_t* bytes,
                              const uint8_t length) {
  if (!sessionActive || !bytes || length == 0 || length > currentStatus.negotiatedChunk ||
      stream != currentStatus.stream || offset != acceptedOffset) {
    setStatus(Phase::Error, Result::Sequence, stream, currentStatus.durableOffset);
    return currentStatus.result;
  }
  const uint32_t expected = expectedBytesFor(stream);
  if (expected == 0 || offset > expected || length > expected - offset || !openStreamAt(stream, offset) ||
      streamFile.write(bytes, length) != length) {
    closeStream();
    recordFailure("write-data", Result::StorageError, stream, offset);
    setStatus(Phase::Error, Result::StorageError, stream, offset);
    return currentStatus.result;
  }
  const uint32_t next = offset + length;
  acceptedOffset = next;
  ++chunksSinceStatus;
  const bool streamComplete = next == expected;
  if (!xtinct::pocket_sync::shouldCheckpoint(chunksSinceStatus, next, expected)) return Result::Ok;

  streamFile.flush();
  if (!writeDurableOffset(stream, next)) {
    closeStream();
    recordFailure("write-checkpoint", Result::StorageError, stream, currentStatus.durableOffset);
    setStatus(Phase::Error, Result::StorageError, stream, currentStatus.durableOffset);
    return currentStatus.result;
  }
  chunksSinceStatus = 0;
  setStatus(stream == MANIFEST_STREAM ? Phase::Manifest : Phase::Objects, Result::Ok, stream, next);
  if (!streamComplete) return Result::Ok;

  closeStream();
  if (stream == MANIFEST_STREAM) return Result::Ok;
  if (!validateCompletedObject(stream)) {
    setStatus(Phase::Error, Result::Hash, stream, next);
    return currentStatus.result;
  }
  uint8_t nextStream = manifest.objectCount;
  uint32_t nextOffset = 0;
  if (!selectNextObjectForResume(static_cast<uint8_t>(stream + 1U), nextStream, nextOffset)) {
    recordFailure("write-next-object", Result::StorageError, nextStream, nextOffset);
    setStatus(Phase::Error, Result::StorageError, nextStream, nextOffset);
    return currentStatus.result;
  }
  // Android releases through 0.3.10 receive the durable ACK for the object
  // that just completed, then begin the following object at byte zero. START
  // can resume an interrupted object, but an in-session transition must reset
  // a stale partial next object so those installed companions cannot collide
  // with its old file size and fall back into Result::StorageError.
  if (nextStream < manifest.objectCount && nextOffset != 0) {
    if (!discardStreamForRetry(nextStream) || !prepareStreamForResume(nextStream, nextOffset) || nextOffset != 0) {
      recordFailure("write-reset-next", Result::StorageError, nextStream, nextOffset);
      setStatus(Phase::Error, Result::StorageError, nextStream, nextOffset);
      return currentStatus.result;
    }
  }
  if (nextStream < manifest.objectCount) setStatus(Phase::Objects, Result::Ok, nextStream, nextOffset);
  else setStatus(Phase::Validating, Result::Ok, manifest.objectCount, 0);
  return Result::Ok;
}

bool PocketSyncStore::validateCompletedObject(const uint8_t stream) {
  if (!sealed || stream >= manifest.objectCount) return false;
  char path[192];
  char okPath[192];
  if (!streamPath(stream, path, sizeof(path)) || !markerPath(stream, okPath, sizeof(okPath))) return false;
  ObjectDescriptor descriptor;
  if (!readObjectDescriptor(stream, descriptor)) return false;
  bool valid = false;
  if (descriptor.source == ObjectSource::V1Report) {
    std::unique_ptr<XtinctDailyCard> card(new (std::nothrow) XtinctDailyCard());
    if (!card) return false;
    copyText(card->taskId, sizeof(card->taskId), descriptor.taskId);
    copyText(card->revision, sizeof(card->revision), descriptor.revision);
    copyText(card->reportSha256, sizeof(card->reportSha256), descriptor.sha256);
    card->hasReport = true;
    card->reportBytes = descriptor.bytes;
    valid = XtinctFeedClient::validatePocketReportFile(*card, path);
  } else if (descriptor.source == ObjectSource::V2Artifact) {
    XtinctInboxItem item;
    item.kind = descriptor.kind;
    item.bytes = descriptor.bytes;
    copyText(item.sha256, sizeof(item.sha256), descriptor.sha256);
    copyText(item.mime, sizeof(item.mime), descriptor.mime);
    valid = XtinctSyncClient::validatePocketArtifactFile(item, path);
  }
  if (!valid) return false;
  return writeAtomic(okPath, reinterpret_cast<const uint8_t*>(descriptor.sha256), 64);
}

bool PocketSyncStore::allObjectsComplete() {
  if (!sealed) return false;
  for (uint8_t index = 0; index < manifest.objectCount; ++index) {
    char path[192];
    char okPath[192];
    if (!streamPath(index, path, sizeof(path)) || !markerPath(index, okPath, sizeof(okPath)) ||
        !Storage.exists(okPath) || !Storage.exists(path) || !validateCompletedObject(index)) {
      return false;
    }
  }
  return true;
}

Result PocketSyncStore::sealManifest() {
  if (!sessionActive) return Result::Sequence;
  uint32_t durable = 0;
  if (currentStatus.stream != MANIFEST_STREAM || acceptedOffset != expectedManifestBytes ||
      !readDurableOffset(MANIFEST_STREAM, durable) || durable != expectedManifestBytes) {
    setStatus(Phase::Error, Result::Incomplete, MANIFEST_STREAM, currentStatus.durableOffset);
    return currentStatus.result;
  }
  closeStream();
  char path[192];
  char sealedPath[192];
  if (!streamPath(MANIFEST_STREAM, path, sizeof(path)) || !markerPath(MANIFEST_STREAM, sealedPath, sizeof(sealedPath))) {
    setStatus(Phase::Error, Result::StorageError, MANIFEST_STREAM, 0);
    return currentStatus.result;
  }
  uint8_t actual[32];
  if (!hashFile(path, expectedManifestBytes, actual) || std::memcmp(actual, manifestDigest, sizeof(actual)) != 0) {
    setStatus(Phase::Error, Result::Hash, MANIFEST_STREAM, currentStatus.durableOffset);
    return currentStatus.result;
  }
  setStatus(Phase::Validating, Result::Ok, expectedObjectCount, 0);
  // buildCommitPlan calls streamPath() for object indices. streamPath() requires
  // sealed==true for non-manifest streams, so we set it here and roll back on failure.
  sealed = true;
  if (!parseAndPrepareManifest() || !buildCommitPlan() ||
      !writeAtomic(sealedPath, reinterpret_cast<const uint8_t*>(packHex), 64)) {
    sealed = false;
    setStatus(Phase::Error, Result::Manifest, MANIFEST_STREAM, expectedManifestBytes);
    return currentStatus.result;
  }
  if (manifest.objectCount == 0) setStatus(Phase::Validating, Result::Ok, 0, 0);
  else setStatus(Phase::Objects, Result::Ok, 0, 0);
  return Result::Ok;
}

bool PocketSyncStore::parseAndPrepareManifest() {
  char manifestPath[192];
  char ledgerPath[192];
  char semanticPlanPath[192];
  char shadowDir[192];
  char cardSlicesDir[192];
  char changeSlicesDir[192];
  if (!streamPath(MANIFEST_STREAM, manifestPath, sizeof(manifestPath)) ||
      std::snprintf(ledgerPath, sizeof(ledgerPath), "%s/object-ledger.bin", packRoot) >=
          static_cast<int>(sizeof(ledgerPath)) ||
      std::snprintf(semanticPlanPath, sizeof(semanticPlanPath), "%s/semantic-plan.jsonl", packRoot) >=
          static_cast<int>(sizeof(semanticPlanPath)) ||
      std::snprintf(shadowDir, sizeof(shadowDir), "%s/shadow", packRoot) >= static_cast<int>(sizeof(shadowDir)) ||
      std::snprintf(cardSlicesDir, sizeof(cardSlicesDir), "%s/card-slices", packRoot) >=
          static_cast<int>(sizeof(cardSlicesDir)) ||
      std::snprintf(changeSlicesDir, sizeof(changeSlicesDir), "%s/change-slices", packRoot) >=
          static_cast<int>(sizeof(changeSlicesDir))) {
    return false;
  }

  // Rebuilding the derived ledger is idempotent. Raw manifest/object bytes are
  // never removed here, so an interrupted parse can safely restart.
  if ((Storage.exists(ledgerPath) && !Storage.remove(ledgerPath)) ||
      (Storage.exists(semanticPlanPath) && !Storage.remove(semanticPlanPath)) ||
      (Storage.exists(shadowDir) && !removeOwnedDirectory(shadowDir, packRoot)) ||
      (Storage.exists(cardSlicesDir) && !removeOwnedDirectory(cardSlicesDir, packRoot)) ||
      (Storage.exists(changeSlicesDir) && !removeOwnedDirectory(changeSlicesDir, packRoot)) ||
      !Storage.mkdir(shadowDir) || !Storage.mkdir(cardSlicesDir) || !Storage.mkdir(changeSlicesDir)) {
    return false;
  }

  // ArduinoJson's filter validates the complete 64 KiB stream while retaining
  // only a tiny root/V1/V2 scalar skeleton. Arrays are extracted one object at
  // a time below and are never materialized as a DOM in RAM.
  HalFile manifestFile;
  if (!Storage.openFileForRead("PSYNC", manifestPath, manifestFile) ||
      manifestFile.fileSize64() != expectedManifestBytes) {
    return false;
  }
  HalJsonReader reader(manifestFile);
  JsonDocument filter;
  filter["schema"] = true;
  filter["protocolVersion"] = true;
  filter["packId"] = true;
  filter["targetId"] = true;
  filter["expiresAt"] = true;
  filter["totalBytes"] = true;
  filter["v1"]["status"] = true;
  filter["v2"]["status"] = true;
  filter["v2"]["mode"] = true;
  filter["v2"]["fromCursor"] = true;
  filter["v2"]["toCursor"] = true;
  JsonDocument skeleton;
  const DeserializationError rootError = deserializeJson(skeleton, reader, DeserializationOption::Filter(filter));
  manifestFile.close();
  if (rootError || !skeleton.is<JsonObjectConst>() ||
      std::strcmp(skeleton["schema"] | "", "xtinct-pocket-sync-pack/1") != 0 ||
      (skeleton["protocolVersion"] | 0) != xtinct::pocket_sync::PROTOCOL_VERSION ||
      std::strcmp(skeleton["targetId"] | "", "x3-main") != 0 ||
      !xtinct::pocket_sync::isPackId(skeleton["packId"] | "") ||
      !xtinct::pocket_sync::isKnownSourceStatus(skeleton["v1"]["status"] | "") ||
      !xtinct::pocket_sync::isKnownSourceStatus(skeleton["v2"]["status"] | "") ||
      (std::strcmp(skeleton["v2"]["mode"] | "", "delta") != 0 &&
       std::strcmp(skeleton["v2"]["mode"] | "", "snapshot") != 0) ||
      !skeleton["totalBytes"].is<uint32_t>() || skeleton["totalBytes"].as<uint32_t>() != expectedObjectBytes ||
      (!skeleton["expiresAt"].isNull() && !boundedAscii(skeleton["expiresAt"] | "", 39))) {
    return false;
  }
  char expectedPackId[69];
  std::snprintf(expectedPackId, sizeof(expectedPackId), "ps1-%s", packHex);
  if (std::strcmp(skeleton["packId"] | "", expectedPackId) != 0 ||
      !copyText(manifest.packId, sizeof(manifest.packId), expectedPackId) ||
      !copyText(manifest.v1Status, sizeof(manifest.v1Status), skeleton["v1"]["status"] | "") ||
      !copyText(manifest.v2Status, sizeof(manifest.v2Status), skeleton["v2"]["status"] | "") ||
      !copyText(manifest.v2Mode, sizeof(manifest.v2Mode), skeleton["v2"]["mode"] | "") ||
      !parseDecimal(skeleton["v2"]["fromCursor"] | "", manifest.fromCursor) ||
      !parseDecimal(skeleton["v2"]["toCursor"] | "", manifest.toCursor) ||
      manifest.toCursor < manifest.fromCursor) {
    return false;
  }
  manifest.objectCount = expectedObjectCount;
  manifest.totalBytes = expectedObjectBytes;
  // ArduinoJson 7 releases its pools on clear(). Do not retain even this tiny
  // filtered root while processing a card or V2 change.
  filter.clear();
  skeleton.clear();

  struct ExtractContext {
    PocketSyncStore* store;
    char cardDir[192];
    char changeDir[192];
  };

  auto extractHandler = +[](void* rawContext, const SliceArray array, const uint8_t sliceIndex,
                            const char* slicePath) -> bool {
    auto* context = static_cast<ExtractContext*>(rawContext);
    PocketSyncStore* store = context->store;
    if (array == SliceArray::Cards || array == SliceArray::Changes) {
      char destination[224];
      const char* directory = array == SliceArray::Cards ? context->cardDir : context->changeDir;
      if (std::snprintf(destination, sizeof(destination), "%s/%02u.json", directory, sliceIndex) >=
          static_cast<int>(sizeof(destination))) {
        return false;
      }
      return copyRawFile(slicePath, destination);
    }
    if (array != SliceArray::Objects) return false;
    JsonBudgetProbe budget;
    if (!budget.run(slicePath, 1536, 48)) return false;
    HalFile file;
    if (!Storage.openFileForRead("PSYNC", slicePath, file) || file.fileSize64() > 1536) return false;
    HalJsonReader sliceReader(file);
    JsonDocument objectDocument;
    const DeserializationError error = deserializeJson(objectDocument, sliceReader);
    file.close();
    if (error || !objectDocument.is<JsonObjectConst>()) return false;
    const JsonObjectConst object = objectDocument.as<JsonObjectConst>();
    // IMPORTANT: The number of fields (11) must EXACTLY match the number of fields in
    // PocketObjectWire on the Android side (PocketSyncContract.kt). If fields are added
    // or removed in the app, this size check must be updated accordingly.
    if (object.size() != 11 || !object["index"].is<uint8_t>() || object["index"].as<uint8_t>() != sliceIndex ||
        !(object["required"] | false)) {
      return false;
    }
    PocketSyncStore::ObjectDescriptor descriptor;
    descriptor.index = sliceIndex;
    descriptor.kind = xtinct::sync_v2::parseKind(object["kind"] | "");
    descriptor.bytes = object["bytes"] | 0U;
    const char* source = object["source"] | "";
    const char* id = object["id"] | "";
    const char* moduleId = object["moduleId"] | "";
    const char* revision = object["revision"] | "";
    const char* sha256 = object["sha256"] | "";
    const char* mime = object["mime"] | "";
    const char* downloadPath = object["downloadPath"] | "";
    if (descriptor.kind == Kind::Invalid || descriptor.bytes == 0 || descriptor.bytes > MAX_OBJECT_BYTES ||
        !xtinct::sync_v2::isSafeId(moduleId) || !isLowerHex(sha256, 64) ||
        !xtinct::sync_v2::mimeAllowed(descriptor.kind, mime) || !boundedAscii(id, 180) ||
        !boundedAscii(downloadPath, 320) || !copyText(descriptor.moduleId, sizeof(descriptor.moduleId), moduleId) ||
        !copyText(descriptor.revision, sizeof(descriptor.revision), revision) ||
        !copyText(descriptor.sha256, sizeof(descriptor.sha256), sha256) ||
        !copyText(descriptor.mime, sizeof(descriptor.mime), mime)) {
      return false;
    }
    if (std::strcmp(source, "v1-report") == 0) {
      descriptor.source = PocketSyncStore::ObjectSource::V1Report;
      if (descriptor.kind != Kind::Text || std::strcmp(mime, "text/plain; charset=utf-8") != 0 ||
          !isLowerHex(revision, 32)) {
        return false;
      }
      bool matched = false;
      for (const char* task : xtinct::report_cache::TASK_IDS) {
        char expectedId[180];
        char expectedPath[320];
        std::snprintf(expectedId, sizeof(expectedId), "v1-report:%s:%s", task, revision);
        std::snprintf(expectedPath, sizeof(expectedPath), "/api/pocket-sync/v1/objects/v1-report/%s/%s", task,
                      revision);
        if (std::strcmp(id, expectedId) == 0 && std::strcmp(downloadPath, expectedPath) == 0) {
          matched = copyText(descriptor.taskId, sizeof(descriptor.taskId), task);
          break;
        }
      }
      if (!matched) return false;
    } else if (std::strcmp(source, "v2-artifact") == 0) {
      descriptor.source = PocketSyncStore::ObjectSource::V2Artifact;
      char expectedPath[320];
      std::snprintf(expectedPath, sizeof(expectedPath), "/api/pocket-sync/v1/objects/v2-artifact/x3-main/%s", sha256);
      if (!isLowerHex(revision, 64) || std::strcmp(downloadPath, expectedPath) != 0) return false;
    } else {
      return false;
    }
    return store->writeObjectDescriptor(descriptor);
  };

  uint8_t cardCount = 0;
  uint8_t changeCount = 0;
  {
    // Release the extractor's token buffer and nesting stack before any DOM is
    // created for a card/change slice.
    ExtractContext extractContext{this};
    if (!copyText(extractContext.cardDir, sizeof(extractContext.cardDir), cardSlicesDir) ||
        !copyText(extractContext.changeDir, sizeof(extractContext.changeDir), changeSlicesDir)) {
      return false;
    }
    ManifestObjectExtractor extractor(packRoot, extractHandler, &extractContext);
    if (!extractor.run(manifestPath) || extractor.count(SliceArray::Objects) != expectedObjectCount) return false;
    cardCount = extractor.count(SliceArray::Cards);
    changeCount = extractor.count(SliceArray::Changes);
    if (expectedObjectCount == 0) {
      if (Storage.exists(ledgerPath)) return false;
    } else {
      HalFile ledger = Storage.open(ledgerPath, O_RDONLY);
      const bool validLedger = ledger && ledger.fileSize64() ==
                                            static_cast<uint64_t>(expectedObjectCount) * sizeof(ObjectDescriptor);
      ledger.close();
      if (!validLedger) return false;
    }
  }

  char cachedRevisions[4][33] = {{0}};
  const uint8_t cachedMask = XtinctFeedClient::pocketCachedRevisionMask(cachedRevisions);
  uint8_t cardMask = 0;
  uint8_t changedCards = 0;
  JsonDocument legacyManifest;
  legacyManifest["schema"] = 1;
  char pocketEtag[40];
  std::snprintf(pocketEtag, sizeof(pocketEtag), "\"%.32s\"", packHex);
  legacyManifest["etag"] = pocketEtag;
  JsonArray legacyRefs = legacyManifest["cards"].to<JsonArray>();

  for (uint8_t sliceIndex = 0; sliceIndex < cardCount; ++sliceIndex) {
    char slicePath[224];
    std::snprintf(slicePath, sizeof(slicePath), "%s/%02u.json", cardSlicesDir, sliceIndex);
    JsonBudgetProbe budget;
    if (!budget.run(slicePath, 12U * 1024U, 192)) return false;
    HalFile file;
    if (!Storage.openFileForRead("PSYNC", slicePath, file) || file.fileSize64() > 12U * 1024U) return false;
    HalJsonReader sliceReader(file);
    JsonDocument cloudCard;
    const DeserializationError error = deserializeJson(cloudCard, sliceReader);
    file.close();
    if (error || !cloudCard.is<JsonObjectConst>()) return false;
    const JsonObjectConst card = cloudCard.as<JsonObjectConst>();
    if (card.size() != 12 || !card["changed"].is<bool>() || !card["priority"].is<uint8_t>() ||
        card["priority"].as<uint8_t>() > 3 || !card["metrics"].is<JsonArrayConst>() ||
        !card["sections"].is<JsonArrayConst>() || card["metrics"].size() > 4 || card["sections"].size() > 3) {
      return false;
    }
    const char* taskId = card["taskId"] | "";
    const char* revision = card["revision"] | "";
    const char* updatedAt = card["updatedAt"] | "";
    const char* expiresAt = card["expiresAt"] | "";
    const int index = taskIndex(taskId);
    if (index < 0 || (cardMask & (1U << index)) != 0 || !isLowerHex(revision, 32) ||
        !boundedAscii(updatedAt, 39) || !boundedAscii(expiresAt, 39)) {
      return false;
    }
    char taskIdValue[33];
    char revisionValue[33];
    if (!copyText(taskIdValue, sizeof(taskIdValue), taskId) ||
        !copyText(revisionValue, sizeof(revisionValue), revision)) {
      return false;
    }
    cardMask |= static_cast<uint8_t>(1U << index);
    const bool changed = card["changed"].as<bool>();
    if (changed) ++changedCards;

    int reportObjectIndex = -1;
    if (!card["report"].isNull()) {
      if (!card["report"].is<JsonObjectConst>() || card["report"].size() != 3) return false;
      const JsonObjectConst report = card["report"].as<JsonObjectConst>();
      const uint32_t reportBytes = report["bytes"] | 0U;
      const char* reportSha = report["sha256"] | "";
      if (reportBytes == 0 || reportBytes > 24U * 1024U || !isLowerHex(reportSha, 64)) return false;
      if (!report["objectIndex"].isNull()) {
        if (!report["objectIndex"].is<uint8_t>() || report["objectIndex"].as<uint8_t>() >= expectedObjectCount) {
          return false;
        }
        reportObjectIndex = report["objectIndex"].as<uint8_t>();
      }
      char reportUrl[128];
      if (!taskReportUrl(taskId, revision, reportUrl, sizeof(reportUrl))) return false;
    }

    char shadowPath[224];
    std::snprintf(shadowPath, sizeof(shadowPath), "%s/v1-card-%s.json", shadowDir, taskIdValue);
    if (!writeLegacyCardFile(shadowPath, card)) return false;
    // The file now owns the mapped bytes; release the only card DOM before the
    // established V1 parser allocates its own bounded document.
    cloudCard.clear();
    std::unique_ptr<XtinctDailyCard> parsedCard(new (std::nothrow) XtinctDailyCard());
    if (!parsedCard ||
        !XtinctFeedClient::validatePocketCardFile(taskIdValue, revisionValue, shadowPath, parsedCard.get())) {
      return false;
    }
    if (reportObjectIndex >= 0) {
      ObjectDescriptor descriptor;
      if (!readObjectDescriptor(static_cast<uint8_t>(reportObjectIndex), descriptor) ||
          descriptor.source != ObjectSource::V1Report || std::strcmp(descriptor.taskId, parsedCard->taskId) != 0 ||
          std::strcmp(descriptor.revision, parsedCard->revision) != 0 || descriptor.bytes != parsedCard->reportBytes ||
          std::strcmp(descriptor.sha256, parsedCard->reportSha256) != 0 || descriptor.references == UINT8_MAX) {
        return false;
      }
      ++descriptor.references;
      if (!writeObjectDescriptor(descriptor)) return false;
    } else if (parsedCard->hasReport) {
      if (changed) return false;
      char cachedReportPath[176];
      if (!XtinctFeedClient::pocketReportFinalPath(parsedCard->taskId, parsedCard->revision, cachedReportPath,
                                                   sizeof(cachedReportPath)) ||
          !XtinctFeedClient::validatePocketReportFile(*parsedCard, cachedReportPath)) {
        return false;
      }
    }

    if (changed) {
      char finalPath[160];
      if (!XtinctFeedClient::pocketCardFinalPath(parsedCard->taskId, finalPath, sizeof(finalPath)) ||
          !appendInstall(semanticPlanPath, shadowPath, finalPath)) {
        return false;
      }
    } else {
      if ((cachedMask & (1U << index)) == 0 || std::strcmp(cachedRevisions[index], parsedCard->revision) != 0 ||
          (Storage.exists(shadowPath) && !Storage.remove(shadowPath))) {
        return false;
      }
    }
    JsonObject reference = legacyRefs.add<JsonObject>();
    reference["id"] = parsedCard->taskId;
    reference["revision"] = parsedCard->revision;
    char cardUrl[96];
    std::snprintf(cardUrl, sizeof(cardUrl), "/v1/cards/%s.json", parsedCard->taskId);
    reference["url"] = cardUrl;
  }

  const bool v1Complete = std::strcmp(manifest.v1Status, "complete") == 0;
  if (!xtinct::pocket_sync::validV1SourceTransition(manifest.v1Status, changedCards, cachedMask, cardMask)) {
    return false;
  }
  if (v1Complete) {
    for (size_t index = 0; index < xtinct::report_cache::TASK_COUNT; ++index) {
      if ((cardMask & (1U << index)) != 0) continue;
      char target[160];
      if (!XtinctFeedClient::pocketCardFinalPath(xtinct::report_cache::TASK_IDS[index], target, sizeof(target)) ||
          !appendDelete(semanticPlanPath, target)) {
        return false;
      }
    }
    std::string encodedManifest;
    serializeJson(legacyManifest, encodedManifest);
    char manifestShadow[224];
    char etagShadow[224];
    std::snprintf(manifestShadow, sizeof(manifestShadow), "%s/v1-manifest.json", shadowDir);
    std::snprintf(etagShadow, sizeof(etagShadow), "%s/v1-manifest.etag", shadowDir);
    if (!writePreparedText(manifestShadow, encodedManifest) || !writePreparedText(etagShadow, pocketEtag) ||
        !appendInstall(semanticPlanPath, manifestShadow, XtinctFeedClient::pocketManifestFinalPath()) ||
        !appendInstall(semanticPlanPath, etagShadow, XtinctFeedClient::pocketManifestEtagFinalPath())) {
      return false;
    }
  }

  uint64_t localCursor = 0;
  if (!XtinctSyncClient::pocketReadCursor(localCursor) || manifest.fromCursor != localCursor) return false;
  const bool snapshot = std::strcmp(manifest.v2Mode, "snapshot") == 0;
  if ((snapshot && localCursor != 0) || (!snapshot && localCursor == 0)) return false;
  uint64_t previousSequence = manifest.fromCursor;
  uint8_t appliedChanges = 0;
  bool containsTombstone = false;
  for (uint8_t sliceIndex = 0; sliceIndex < changeCount; ++sliceIndex) {
    char slicePath[224];
    std::snprintf(slicePath, sizeof(slicePath), "%s/%02u.json", changeSlicesDir, sliceIndex);
    JsonBudgetProbe budget;
    if (!budget.run(slicePath, 6U * 1024U, 160)) return false;
    HalFile file;
    if (!Storage.openFileForRead("PSYNC", slicePath, file) || file.fileSize64() > 6U * 1024U) return false;
    HalJsonReader sliceReader(file);
    JsonDocument changeDocument;
    const DeserializationError error = deserializeJson(changeDocument, sliceReader);
    file.close();
    if (error || !changeDocument.is<JsonObjectConst>()) return false;
    const JsonObjectConst change = changeDocument.as<JsonObjectConst>();
    const char* type = change["type"] | "";
    const char* sequenceText = change["seq"] | "";
    const char* itemId = change["itemId"] | "";
    uint64_t sequence = 0;
    if (!parseDecimal(sequenceText, sequence) || sequence <= previousSequence || sequence > manifest.toCursor ||
        !xtinct::sync_v2::isSafeId(itemId)) {
      return false;
    }
    char itemIdValue[33];
    if (!copyText(itemIdValue, sizeof(itemIdValue), itemId)) return false;
    previousSequence = sequence;
    char seenPath[224];
    std::snprintf(seenPath, sizeof(seenPath), "%s/change-%s.seen", shadowDir, itemIdValue);
    if (Storage.exists(seenPath) || !writeAtomic(seenPath, nullptr, 0)) return false;

    if (std::strcmp(type, "upsert") == 0) {
      if (change.size() != 16 || !change["objectIndex"].is<uint8_t>() ||
          change["objectIndex"].as<uint8_t>() >= expectedObjectCount || !change["actions"].is<JsonArrayConst>() ||
          change["actions"].size() > 3 || !change["metadata"].is<JsonObjectConst>() ||
          measureJson(change["metadata"]) > xtinct::sync_v2::MAX_METADATA_BYTES) {
        return false;
      }
      const uint8_t objectIndex = change["objectIndex"].as<uint8_t>();
      char validationPath[224];
      std::snprintf(validationPath, sizeof(validationPath), "%s/v2-validate-%02u.json", shadowDir, sliceIndex);
      if (!writeLegacyDeliveryFile(validationPath, change)) return false;
      // Do not overlap the cloud-change DOM with the established delivery
      // parser's document.
      changeDocument.clear();
      XtinctInboxItem item;
      if (!XtinctSyncClient::validatePocketDeliveryFile(validationPath, item) ||
          (Storage.exists(validationPath) && !Storage.remove(validationPath))) {
        return false;
      }
      ObjectDescriptor descriptor;
      if (!readObjectDescriptor(objectIndex, descriptor) || descriptor.source != ObjectSource::V2Artifact ||
          descriptor.kind != item.kind || descriptor.bytes != item.bytes ||
          std::strcmp(descriptor.moduleId, item.moduleId) != 0 ||
          std::strcmp(descriptor.revision, item.revision) != 0 || std::strcmp(descriptor.sha256, item.sha256) != 0 ||
          std::strcmp(descriptor.mime, item.mime) != 0 || descriptor.references == UINT8_MAX) {
        return false;
      }
      ++descriptor.references;
      if (!writeObjectDescriptor(descriptor)) return false;
      char shadowPath[224];
      char finalPath[160];
      std::snprintf(shadowPath, sizeof(shadowPath), "%s/v2-meta-%s.json", shadowDir, item.itemId);
      if (!XtinctSyncClient::pocketMetadataFinalPath(item.itemId, finalPath, sizeof(finalPath)) ||
          !XtinctSyncClient::writePocketMetadataFile(item, shadowPath) ||
          !appendInstall(semanticPlanPath, shadowPath, finalPath)) {
        return false;
      }
    } else if (std::strcmp(type, "tombstone") == 0) {
      containsTombstone = true;
      if (snapshot) return false;
      if (change.size() != 6 || !xtinct::sync_v2::isSafeId(change["deliveryId"] | "") ||
          !xtinct::sync_v2::isSha256(change["revision"] | "") || !boundedAscii(change["deletedAt"] | "", 39)) {
        return false;
      }
      char revisionValue[65];
      if (!copyText(revisionValue, sizeof(revisionValue), change["revision"] | "")) return false;
      changeDocument.clear();
      if (XtinctSyncClient::pocketTombstoneMatches(itemIdValue, revisionValue)) {
        char finalPath[160];
        if (!XtinctSyncClient::pocketMetadataFinalPath(itemIdValue, finalPath, sizeof(finalPath)) ||
            !appendDelete(semanticPlanPath, finalPath)) {
          return false;
        }
      }
    } else {
      return false;
    }
    ++appliedChanges;
  }

  if (!xtinct::pocket_sync::validV2SourceTransition(manifest.v2Mode, manifest.v2Status, appliedChanges,
                                                     containsTombstone, manifest.fromCursor,
                                                     manifest.toCursor, localCursor)) {
    return false;
  }

  // A cursor-zero snapshot is the complete live metadata set. Reconcile the
  // previous set by streaming the owned directory one entry at a time; the 64
  // item set is never materialized as an in-RAM array.
  if (snapshot) {
    if (!XtinctSyncClient::pocketRecoverInboxMetadata()) return false;
    HalFile directory = Storage.open(V2_INBOX_DIR, O_RDONLY);
    if (!directory || !directory.isDirectory()) {
      directory.close();
      return false;
    }
    size_t scannedFiles = 0;
    size_t metadataFiles = 0;
    bool scanOk = true;
    while (scanOk) {
      HalFile entry = directory.openNextFile();
      if (!entry) break;
      const bool isDirectory = entry.isDirectory();
      char name[128] = {0};
      const size_t nameLength = entry.getName(name, sizeof(name));
      entry.close();
      if (isDirectory || nameLength == 0 || nameLength >= sizeof(name) ||
          ++scannedFiles >= xtinct::sync_v2::MAX_INBOX_METADATA_SCAN_FILES) {
        scanOk = false;
        break;
      }
      char cachedItemId[33];
      if (!xtinct::sync_v2::managedMetadataItemId(name, cachedItemId)) continue;
      if (++metadataFiles > xtinct::sync_v2::MAX_INBOX_ITEMS) {
        scanOk = false;
        break;
      }
      char seenPath[224];
      if (std::snprintf(seenPath, sizeof(seenPath), "%s/change-%s.seen", shadowDir, cachedItemId) >=
          static_cast<int>(sizeof(seenPath))) {
        scanOk = false;
        break;
      }
      if (Storage.exists(seenPath)) continue;
      char finalPath[160];
      if (!XtinctSyncClient::pocketMetadataFinalPath(cachedItemId, finalPath, sizeof(finalPath)) ||
          !appendDelete(semanticPlanPath, finalPath)) {
        scanOk = false;
      }
    }
    directory.close();
    if (!scanOk) return false;
  }

  // Snapshot no_changes may still advance across historical tombstones. The
  // validated cursor is therefore persisted whenever it moves, independent
  // of the source status spelling.
  if (manifest.toCursor > localCursor) {
    char cursorShadow[224];
    std::snprintf(cursorShadow, sizeof(cursorShadow), "%s/v2-cursor", shadowDir);
    const std::string cursorText = std::to_string(manifest.toCursor);
    if (!writePreparedText(cursorShadow, cursorText) ||
        !appendInstall(semanticPlanPath, cursorShadow, XtinctSyncClient::pocketCursorFinalPath())) {
      return false;
    }
  }

  uint64_t summedObjectBytes = 0;
  for (uint8_t index = 0; index < expectedObjectCount; ++index) {
    ObjectDescriptor descriptor;
    if (!readObjectDescriptor(index, descriptor) || descriptor.references == 0 ||
        descriptor.bytes > expectedObjectBytes - summedObjectBytes) {
      return false;
    }
    summedObjectBytes += descriptor.bytes;
  }
  if (summedObjectBytes != expectedObjectBytes) return false;

  removeOwnedDirectory(cardSlicesDir, packRoot);
  removeOwnedDirectory(changeSlicesDir, packRoot);
  return true;
}

bool PocketSyncStore::buildCommitPlan() {
  char planPath[192];
  char semanticPath[192];
  if (std::snprintf(planPath, sizeof(planPath), "%s/plan.jsonl", packRoot) >= static_cast<int>(sizeof(planPath)) ||
      std::snprintf(semanticPath, sizeof(semanticPath), "%s/semantic-plan.jsonl", packRoot) >=
          static_cast<int>(sizeof(semanticPath)) ||
      !writeAtomic(planPath, nullptr, 0)) {
    return false;
  }

  size_t operationCount = 0;
  for (uint8_t index = 0; index < manifest.objectCount; ++index) {
    ObjectDescriptor descriptor;
    char sourcePath[192];
    char targetPath[192];
    if (!readObjectDescriptor(index, descriptor) || !streamPath(index, sourcePath, sizeof(sourcePath))) return false;
    bool alreadyInstalled = false;
    if (descriptor.source == ObjectSource::V1Report) {
      std::unique_ptr<XtinctDailyCard> card(new (std::nothrow) XtinctDailyCard());
      if (!card) return false;
      card->hasReport = true;
      card->reportBytes = descriptor.bytes;
      copyText(card->taskId, sizeof(card->taskId), descriptor.taskId);
      copyText(card->revision, sizeof(card->revision), descriptor.revision);
      copyText(card->reportSha256, sizeof(card->reportSha256), descriptor.sha256);
      if (!XtinctFeedClient::pocketReportFinalPath(descriptor.taskId, descriptor.revision, targetPath,
                                                   sizeof(targetPath))) {
        return false;
      }
      alreadyInstalled =
          Storage.exists(targetPath) && XtinctFeedClient::validatePocketReportFile(*card, targetPath);
    } else if (descriptor.source == ObjectSource::V2Artifact) {
      XtinctInboxItem item;
      item.kind = descriptor.kind;
      item.bytes = descriptor.bytes;
      copyText(item.sha256, sizeof(item.sha256), descriptor.sha256);
      copyText(item.mime, sizeof(item.mime), descriptor.mime);
      if (!XtinctSyncClient::pocketArtifactFinalPath(item, targetPath, sizeof(targetPath))) return false;
      alreadyInstalled = Storage.exists(targetPath) && XtinctSyncClient::validatePocketArtifactFile(item, targetPath);
    } else {
      return false;
    }
    if (!alreadyInstalled) {
      if (!appendInstallKnown(planPath, sourcePath, targetPath, descriptor.bytes, descriptor.sha256)) return false;
      if (!xtinct::pocket_sync::validPlanOperationCount(++operationCount)) return false;
    }
  }

  if (Storage.exists(semanticPath)) {
    HalFile semantic;
    if (!Storage.openFileForRead("PSYNC", semanticPath, semantic)) return false;
    std::string line;
    while (semantic.available()) {
      if (!readLine(semantic, line)) {
        semantic.close();
        return false;
      }
      JsonDocument operation;
      if (deserializeJson(operation, line) || !operation.is<JsonObjectConst>() ||
          !validatePlanOperation(operation.as<JsonObjectConst>(), packRoot) || !appendLine(planPath, line) ||
          !xtinct::pocket_sync::validPlanOperationCount(++operationCount)) {
        semantic.close();
        return false;
      }
    }
    semantic.close();
  }
  return true;
}

namespace {

struct ActiveCommit {
  char pack[65] = {0};
  char phase[12] = {0};
  uint16_t next = 0;
  uint16_t operations = 0;
  uint64_t toCursor = 0;
};

bool activeCommitPathFor(const char* pack, char root[160], char plan[192], char backups[192]) {
  if (!safePackHex(pack)) return false;
  return std::snprintf(root, 160, "%s/%s", INCOMING_DIR, pack) < 160 &&
         std::snprintf(plan, 192, "%s/plan.jsonl", root) < 192 &&
         std::snprintf(backups, 192, "%s/backups", root) < 192;
}

bool writeActiveCommit(const ActiveCommit& active) {
  if (!safePackHex(active.pack) ||
      (std::strcmp(active.phase, "backup") != 0 && std::strcmp(active.phase, "apply") != 0 &&
       std::strcmp(active.phase, "rollback") != 0) ||
      !xtinct::pocket_sync::validCommitProgress(active.next, active.operations)) {
    return false;
  }
  JsonDocument document;
  document["schema"] = 1;
  document["pack"] = active.pack;
  document["phase"] = active.phase;
  document["next"] = active.next;
  document["operations"] = active.operations;
  document["toCursor"] = std::to_string(active.toCursor);
  return writeJsonAtomic(ACTIVE_COMMIT_PATH, document);
}

bool readActiveCommit(ActiveCommit& active) {
  if (!Storage.exists(ACTIVE_COMMIT_PATH)) return false;
  std::unique_ptr<char[]> body;
  size_t bodyLength = 0;
  if (!readBoundedOwnedTextFile(ACTIVE_COMMIT_PATH, 512, body, bodyLength)) return false;
  JsonDocument document;
  if (deserializeJson(document, body.get(), bodyLength) || document.size() != 6 ||
      (document["schema"] | 0) != 1 ||
      !copyText(active.pack, sizeof(active.pack), document["pack"] | "") ||
      !copyText(active.phase, sizeof(active.phase), document["phase"] | "") ||
      !safePackHex(active.pack) || !parseDecimal(document["toCursor"] | "", active.toCursor)) {
    return false;
  }
  active.next = document["next"] | static_cast<uint16_t>(MAX_PLAN_OPERATIONS + 1);
  active.operations = document["operations"] | static_cast<uint16_t>(MAX_PLAN_OPERATIONS + 1);
  return xtinct::pocket_sync::validCommitProgress(active.next, active.operations) &&
         (std::strcmp(active.phase, "backup") == 0 || std::strcmp(active.phase, "apply") == 0 ||
          std::strcmp(active.phase, "rollback") == 0);
}

bool countAndValidatePlan(const char* planPath, const char* packRoot, uint16_t& count) {
  count = 0;
  HalFile plan;
  if (!Storage.openFileForRead("PSYNC", planPath, plan)) return false;
  std::string line;
  while (plan.available()) {
    if (!readLine(plan, line)) {
      plan.close();
      return false;
    }
    JsonDocument operation;
    if (deserializeJson(operation, line) || !operation.is<JsonObjectConst>() ||
        !validatePlanOperation(operation.as<JsonObjectConst>(), packRoot) ||
        !xtinct::pocket_sync::validPlanOperationCount(++count)) {
      plan.close();
      return false;
    }
  }
  plan.close();
  return true;
}

bool backupMarkerPaths(const char* backupsDir, const uint16_t index, char backup[224], char present[224],
                       char absent[224]) {
  return std::snprintf(backup, 224, "%s/%03u.bak", backupsDir, index) < 224 &&
         std::snprintf(present, 224, "%s/%03u.present", backupsDir, index) < 224 &&
         std::snprintf(absent, 224, "%s/%03u.absent", backupsDir, index) < 224;
}

bool prepareBackups(ActiveCommit& active, const char* root, const char* planPath, const char* backupsDir) {
  if (!ensureDirectory(backupsDir)) return false;
  HalFile plan;
  if (!Storage.openFileForRead("PSYNC", planPath, plan)) return false;
  std::string line;
  uint16_t index = 0;
  while (plan.available()) {
    if (!readLine(plan, line)) {
      plan.close();
      return false;
    }
    JsonDocument operation;
    if (deserializeJson(operation, line) || !operation.is<JsonObjectConst>() ||
        !validatePlanOperation(operation.as<JsonObjectConst>(), root)) {
      plan.close();
      return false;
    }
    char backup[224], present[224], absent[224];
    if (!backupMarkerPaths(backupsDir, index, backup, present, absent)) {
      plan.close();
      return false;
    }
    if (!Storage.exists(present) && !Storage.exists(absent)) {
      const char* target = operation["target"] | "";
      if (Storage.exists(target)) {
        if (!copyRawFile(target, backup) || !writeAtomic(present, nullptr, 0)) {
          plan.close();
          return false;
        }
      } else if (!writeAtomic(absent, nullptr, 0)) {
        plan.close();
        return false;
      }
    }
    active.next = ++index;
    if (!writeActiveCommit(active)) {
      plan.close();
      return false;
    }
  }
  plan.close();
  return index == active.operations;
}

bool applyPlan(ActiveCommit& active, const char* root, const char* planPath) {
  HalFile plan;
  if (!Storage.openFileForRead("PSYNC", planPath, plan)) return false;
  std::string line;
  uint16_t index = 0;
  while (plan.available()) {
    if (!readLine(plan, line)) {
      plan.close();
      return false;
    }
    JsonDocument operation;
    if (deserializeJson(operation, line) || !operation.is<JsonObjectConst>() ||
        !validatePlanOperation(operation.as<JsonObjectConst>(), root)) {
      plan.close();
      return false;
    }
    const uint16_t operationIndex = index++;
    if (!xtinct::pocket_sync::shouldApplyPlanOperation(operationIndex, active.next)) continue;
    const char* op = operation["op"] | "";
    const char* target = operation["target"] | "";
    bool ok = false;
    if (std::strcmp(op, "delete") == 0) {
      ok = !Storage.exists(target) || Storage.remove(target);
    } else {
      ok = copyFile(operation["source"] | "", target, operation["bytes"] | 0U,
                    operation["sha256"] | "");
    }
    if (!ok) {
      plan.close();
      return false;
    }
    active.next = index;
    if (!writeActiveCommit(active)) {
      plan.close();
      return false;
    }
  }
  plan.close();
  return index == active.operations;
}

bool rollbackPlan(const ActiveCommit& active, const char* root, const char* planPath, const char* backupsDir) {
  HalFile plan;
  if (!Storage.openFileForRead("PSYNC", planPath, plan)) return false;
  std::string line;
  uint16_t index = 0;
  bool ok = true;
  while (plan.available()) {
    if (!readLine(plan, line)) {
      ok = false;
      break;
    }
    JsonDocument operation;
    if (deserializeJson(operation, line) || !operation.is<JsonObjectConst>() ||
        !validatePlanOperation(operation.as<JsonObjectConst>(), root)) {
      ok = false;
      break;
    }
    char backup[224], present[224], absent[224];
    if (!backupMarkerPaths(backupsDir, index++, backup, present, absent)) {
      ok = false;
      break;
    }
    const char* target = operation["target"] | "";
    if (Storage.exists(present)) {
      if (!Storage.exists(backup) || !copyRawFile(backup, target)) ok = false;
    } else if (Storage.exists(absent)) {
      if (Storage.exists(target) && !Storage.remove(target)) ok = false;
    } else {
      ok = false;
    }
  }
  plan.close();
  return ok && index == active.operations;
}

bool writeReceipt(const char* pack, const uint64_t toCursor) {
  JsonDocument receipts;
  if (Storage.exists(RECEIPTS_PATH)) {
    std::unique_ptr<char[]> body;
    size_t bodyLength = 0;
    if (!readBoundedOwnedTextFile(RECEIPTS_PATH, 4096, body, bodyLength) ||
        deserializeJson(receipts, body.get(), bodyLength) ||
        (receipts["schema"] | 0) != 1 || !receipts["packs"].is<JsonArray>()) {
      return false;
    }
  } else {
    receipts["schema"] = 1;
    receipts["packs"].to<JsonArray>();
  }
  JsonArray packs = receipts["packs"].as<JsonArray>();
  bool found = false;
  for (const char* value : packs) {
    if (!safePackHex(value)) return false;
    if (std::strcmp(value, pack) == 0) found = true;
  }
  if (!found) {
    while (packs.size() >= MAX_RECEIPT_HISTORY) packs.remove(0);
    packs.add(pack);
  }
  receipts["lastPack"] = pack;
  receipts["v2Cursor"] = std::to_string(toCursor);
  return writeJsonAtomic(RECEIPTS_PATH, receipts);
}

bool executeCommit(ActiveCommit active) {
  char root[160], planPath[192], backupsDir[192];
  uint16_t counted = 0;
  if (!activeCommitPathFor(active.pack, root, planPath, backupsDir) || !Storage.exists(root) ||
      !countAndValidatePlan(planPath, root, counted) || counted != active.operations) {
    return false;
  }
  if (std::strcmp(active.phase, "rollback") == 0) {
    if (!rollbackPlan(active, root, planPath, backupsDir)) return false;
    if (!Storage.remove(ACTIVE_COMMIT_PATH)) return false;
    removeOwnedDirectory(root, INCOMING_DIR);
    // Recovery has restored every target and durably removed the marker. This
    // is a successful recovery, not a failed commit attempt; normal boot may
    // proceed. (The apply-failure branch below correctly remains false.)
    return true;
  }
  if (std::strcmp(active.phase, "backup") == 0) {
    if (!prepareBackups(active, root, planPath, backupsDir)) return false;
    copyText(active.phase, sizeof(active.phase), "apply");
    active.next = 0;
    if (!writeActiveCommit(active)) return false;
  }
  if (!applyPlan(active, root, planPath) || !writeReceipt(active.pack, active.toCursor)) {
    copyText(active.phase, sizeof(active.phase), "rollback");
    active.next = 0;
    if (!writeActiveCommit(active) || !rollbackPlan(active, root, planPath, backupsDir)) return false;
    if (!Storage.remove(ACTIVE_COMMIT_PATH)) return false;
    removeOwnedDirectory(root, INCOMING_DIR);
    return false;
  }
  if (!Storage.remove(ACTIVE_COMMIT_PATH)) return false;
  removeOwnedDirectory(root, INCOMING_DIR);
  return true;
}

}  // namespace

bool PocketSyncStore::runCommitPlan() {
  char planPath[192];
  uint16_t operationCount = 0;
  if (std::snprintf(planPath, sizeof(planPath), "%s/plan.jsonl", packRoot) >= static_cast<int>(sizeof(planPath)) ||
      Storage.exists(ACTIVE_COMMIT_PATH) || !countAndValidatePlan(planPath, packRoot, operationCount)) {
    return false;
  }
  ActiveCommit active;
  copyText(active.pack, sizeof(active.pack), packHex);
  copyText(active.phase, sizeof(active.phase), "backup");
  active.operations = operationCount;
  active.toCursor = manifest.toCursor;
  // A phone pack can replace/delete Inbox metadata before its cursor is
  // committed. Remove the acceleration index first so a reset can only fall
  // back to the canonical metadata scan, never display a stale first page.
  if (!XtinctSyncClient::invalidateInboxFastPage() || !writeActiveCommit(active)) return false;
  if (!executeCommit(active)) return false;
  if (!XtinctSyncClient::refreshInboxFastPage()) {
    LOG_ERR("PSYNC", "Pocket commit complete; fast Inbox index will rebuild after the next full sync");
  }
  return true;
}

Result PocketSyncStore::commit() {
  if (!sessionActive || !sealed) {
    setStatus(Phase::Error, Result::Sequence, currentStatus.stream, currentStatus.durableOffset);
    return currentStatus.result;
  }
  closeStream();
  setStatus(Phase::Validating, Result::Ok, manifest.objectCount, 0);
  if (!allObjectsComplete()) {
    setStatus(Phase::Error, Result::Incomplete, currentStatus.stream, currentStatus.durableOffset);
    return currentStatus.result;
  }
  setStatus(Phase::Committing, Result::Ok, manifest.objectCount, 0);
  if (!runCommitPlan()) {
    setStatus(Phase::Error, Result::Commit, manifest.objectCount, 0);
    return currentStatus.result;
  }
  sessionActive = false;
  setStatus(Phase::Complete, Result::Ok, manifest.objectCount, 0);
  return Result::Ok;
}

void PocketSyncStore::abort() {
  closeStream();
  if (sessionActive && !Storage.exists(ACTIVE_COMMIT_PATH)) removeOwnedDirectory(packRoot, INCOMING_DIR);
  sessionActive = false;
  sealed = false;
  setStatus(Phase::Idle, Result::Ok, MANIFEST_STREAM, 0);
}

bool PocketSyncStore::recoverPendingCommit() {
  if (!Storage.exists(ACTIVE_COMMIT_PATH)) return true;
  ActiveCommit active;
  if (!readActiveCommit(active)) {
    LOG_ERR("PSYNC", "Invalid active commit marker; refusing automatic mutation");
    return false;
  }
  LOG_INF("PSYNC", "Recovering Pocket Sync transaction phase=%s next=%u", active.phase, active.next);
  return executeCommit(active);
}

bool PocketSyncStore::queryLocalState(uint8_t& revisionMask, char revisions[4][33], uint64_t& v2Cursor,
                                      uint8_t lastPackDigest[32]) {
  if (!revisions || !lastPackDigest || !ensureAllDirectories() || !recoverPendingCommit()) return false;
  revisionMask = XtinctFeedClient::pocketCachedRevisionMask(revisions);
  if (!XtinctSyncClient::pocketReadCursor(v2Cursor)) return false;
  std::memset(lastPackDigest, 0, 32);
  if (!Storage.exists(RECEIPTS_PATH)) return true;
  std::unique_ptr<char[]> body;
  size_t bodyLength = 0;
  if (!readBoundedOwnedTextFile(RECEIPTS_PATH, 4096, body, bodyLength)) return false;
  JsonDocument receipts;
  if (deserializeJson(receipts, body.get(), bodyLength) || (receipts["schema"] | 0) != 1) return false;
  const char* last = receipts["lastPack"] | "";
  return last[0] == '\0' || hexToBytes(last, 64, lastPackDigest);
}
