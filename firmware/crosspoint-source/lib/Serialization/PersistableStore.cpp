#include "PersistableStore.h"

#include <HalStorage.h>
#include <Logging.h>
#include <ObfuscationUtils.h>

#include "PersistableStorePolicy.h"

namespace {
class BoundedPersistableJsonReader {
 public:
  explicit BoundedPersistableJsonReader(HalFile& file) : file_(file) {}
  int read() { return file_.read(); }
  size_t readBytes(char* buffer, const size_t length) {
    const int amount = file_.read(buffer, length);
    return amount > 0 ? static_cast<size_t>(amount) : 0;
  }

 private:
  HalFile& file_;
};
}  // namespace

bool PersistableStoreBase::writeDocToFile(const char* path, const JsonDocument& doc) {
  Storage.mkdir("/.crosspoint");
  String json;
  serializeJson(doc, json);
  if (!Storage.writeFile(path, json)) {
    LOG_ERR("PERSIST", "Failed to write %s", path);
    return false;
  }
  return true;
}

bool PersistableStoreBase::readDocFromFile(const char* path, JsonDocument& doc) {
  if (!Storage.exists(path)) {
    return false;  // Expected on first boot — not an error.
  }
  HalFile file;
  if (!Storage.openFileForRead("PERSIST", path, file)) {
    LOG_ERR("PERSIST", "Failed to open %s", path);
    return false;
  }
  const uint64_t bytes = file.fileSize64();
  if (!persistable_store_policy::validPersistedJsonFileSize(bytes)) {
    file.close();
    LOG_ERR("PERSIST", "Rejected %s with invalid size", path);
    return false;
  }
  BoundedPersistableJsonReader reader(file);
  const auto error = deserializeJson(doc, reader);
  const bool closeOk = file.close();
  if (error) {
    LOG_ERR("PERSIST", "JSON parse error in %s: %s", path, error.c_str());
    return false;
  }
  if (!closeOk) {
    LOG_ERR("PERSIST", "Failed to close %s after read", path);
    return false;
  }
  return true;
}

std::string PersistableStoreBase::extractPassword(JsonVariantConst doc, bool& needsResave) {
  bool ok = false;
  std::string pass = obfuscation::deobfuscateFromBase64(doc["password_obf"] | "", &ok);
  if (!ok) {
    // Deobfuscation failed — fall back to legacy plaintext password.
    pass = doc["password"] | "";
    if (!pass.empty()) needsResave = true;
  }
  // A successfully decoded empty string is a legitimate value; preserve as-is.
  return pass;
}
