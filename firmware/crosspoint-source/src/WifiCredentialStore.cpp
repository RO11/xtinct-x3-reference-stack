#include "WifiCredentialStore.h"

#include <Logging.h>
#include <ObfuscationUtils.h>
#include <Preferences.h>

#include <algorithm>

namespace {
constexpr char NVS_NAMESPACE[] = "xtinct_wifi";
constexpr char NVS_CREDENTIALS_KEY[] = "credentials";
constexpr size_t MAX_SSID_BYTES = 32;
constexpr size_t MAX_PASSWORD_BYTES = 64;

bool validCredential(const WifiCredential& credential) {
  return !credential.ssid.empty() && credential.ssid.size() <= MAX_SSID_BYTES &&
         credential.password.size() <= MAX_PASSWORD_BYTES;
}

bool writeCredentialsToNvs(const std::vector<WifiCredential>& credentials) {
  JsonDocument document;
  document["version"] = 1;
  JsonArray entries = document["credentials"].to<JsonArray>();
  for (const auto& credential : credentials) {
    if (!validCredential(credential)) return false;
    JsonObject entry = entries.add<JsonObject>();
    entry["ssid"] = credential.ssid;
    entry["password"] = credential.password;
  }
  String encoded;
  serializeJson(document, encoded);
  Preferences preferences;
  if (!preferences.begin(NVS_NAMESPACE, false)) return false;
  const size_t written = preferences.putString(NVS_CREDENTIALS_KEY, encoded);
  preferences.end();
  return written == encoded.length();
}

bool readCredentialsFromNvs(std::vector<WifiCredential>& credentials, bool& present) {
  present = false;
  Preferences preferences;
  if (!preferences.begin(NVS_NAMESPACE, true)) return false;
  present = preferences.isKey(NVS_CREDENTIALS_KEY);
  const String encoded = present ? preferences.getString(NVS_CREDENTIALS_KEY, "") : String();
  preferences.end();
  if (!present) return true;
  JsonDocument document;
  if (encoded.isEmpty() || deserializeJson(document, encoded) || (document["version"] | 0) != 1 ||
      !document["credentials"].is<JsonArrayConst>()) {
    return false;
  }
  const JsonArrayConst entries = document["credentials"].as<JsonArrayConst>();
  if (entries.size() > 8) return false;
  std::vector<WifiCredential> loaded;
  loaded.reserve(entries.size());
  for (const JsonObjectConst entry : entries) {
    WifiCredential credential{entry["ssid"] | "", entry["password"] | ""};
    if (!validCredential(credential)) return false;
    loaded.push_back(std::move(credential));
  }
  credentials = std::move(loaded);
  return true;
}
}  // namespace

void WifiCredentialStore::toJson(JsonDocument& doc) const {
  doc["version"] = 2;
  doc["lastConnectedSsid"] = lastConnectedSsid;

  JsonArray arr = doc["credentials"].to<JsonArray>();
  for (const auto& cred : credentials) {
    JsonObject obj = arr.add<JsonObject>();
    obj["ssid"] = cred.ssid;
  }
}

bool WifiCredentialStore::fromJson(JsonVariantConst doc) {
  lastConnectedSsid = doc["lastConnectedSsid"] | "";

  bool nvsPresent = false;
  if (!readCredentialsFromNvs(credentials, nvsPresent)) {
    LOG_ERR("WCS", "Internal WiFi credential store is invalid");
    credentials.clear();
    return false;
  }
  if (nvsPresent) {
    if ((doc["version"] | 0) < 2) requestResave();
    LOG_DBG("WCS", "Loaded %zu WiFi credentials from internal NVS", credentials.size());
    return true;
  }

  // One-time migration from CrossPoint's legacy removable-card store.
  credentials.clear();
  JsonArrayConst arr = doc["credentials"].as<JsonArrayConst>();
  credentials.reserve(std::min(arr.size(), MAX_NETWORKS));
  bool legacyShape = false;

  for (JsonObjectConst obj : arr) {
    if (credentials.size() >= MAX_NETWORKS) break;
    const bool hasLegacyPassword = !obj["password_obf"].isNull() || !obj["password"].isNull();
    legacyShape = legacyShape || hasLegacyPassword;
    if (!hasLegacyPassword) continue;
    WifiCredential cred;
    cred.ssid = obj["ssid"] | "";
    bool decodedLegacy = false;
    cred.password = extractPassword(obj, decodedLegacy);
    if (validCredential(cred)) credentials.push_back(std::move(cred));
  }

  if (!writeCredentialsToNvs(credentials)) {
    LOG_ERR("WCS", "Could not migrate WiFi credentials to internal NVS; retaining legacy SD data");
    return !legacyShape && credentials.empty();
  }
  LOG_INF("WCS", "Migrated %zu WiFi credentials from SD to internal NVS", credentials.size());
  requestResave();
  return true;
}

bool WifiCredentialStore::addCredential(const std::string& ssid, const std::string& password) {
  if (!validCredential({ssid, password})) return false;
  const auto original = credentials;
  // Check if this SSID already exists and update it
  const auto cred = find_if(credentials.begin(), credentials.end(),
                            [&ssid](const WifiCredential& cred) { return cred.ssid == ssid; });
  if (cred != credentials.end()) {
    cred->password = password;
    LOG_DBG("WCS", "Updated credentials for: %s", ssid.c_str());
    if (writeCredentialsToNvs(credentials) && saveToFile()) return true;
    credentials = original;
    writeCredentialsToNvs(credentials);
    return false;
  }

  // Check if we've reached the limit
  if (credentials.size() >= MAX_NETWORKS) {
    LOG_DBG("WCS", "Cannot add more networks, limit of %zu reached", MAX_NETWORKS);
    return false;
  }

  // Add new credential
  credentials.push_back({ssid, password});
  LOG_DBG("WCS", "Added credentials for: %s", ssid.c_str());
  if (writeCredentialsToNvs(credentials) && saveToFile()) return true;
  credentials = original;
  writeCredentialsToNvs(credentials);
  return false;
}

bool WifiCredentialStore::removeCredential(const std::string& ssid) {
  const auto originalCredentials = credentials;
  const std::string originalLastSsid = lastConnectedSsid;
  const auto cred = find_if(credentials.begin(), credentials.end(),
                            [&ssid](const WifiCredential& cred) { return cred.ssid == ssid; });
  if (cred != credentials.end()) {
    credentials.erase(cred);
    LOG_DBG("WCS", "Removed credentials for: %s", ssid.c_str());
    if (ssid == lastConnectedSsid) {
      lastConnectedSsid.clear();
    }
    if (writeCredentialsToNvs(credentials) && saveToFile()) return true;
    credentials = originalCredentials;
    lastConnectedSsid = originalLastSsid;
    writeCredentialsToNvs(credentials);
    return false;
  }
  return false;  // Not found
}

const WifiCredential* WifiCredentialStore::findCredential(const std::string& ssid) const {
  const auto cred = find_if(credentials.begin(), credentials.end(),
                            [&ssid](const WifiCredential& cred) { return cred.ssid == ssid; });

  if (cred != credentials.end()) {
    return &*cred;
  }

  return nullptr;
}

bool WifiCredentialStore::hasSavedCredential(const std::string& ssid) const { return findCredential(ssid) != nullptr; }

void WifiCredentialStore::setLastConnectedSsid(const std::string& ssid) {
  if (lastConnectedSsid != ssid) {
    lastConnectedSsid = ssid;
    saveToFile();
  }
}

const std::string& WifiCredentialStore::getLastConnectedSsid() const { return lastConnectedSsid; }

void WifiCredentialStore::clearLastConnectedSsid() {
  if (!lastConnectedSsid.empty()) {
    lastConnectedSsid.clear();
    saveToFile();
  }
}

void WifiCredentialStore::clearAll() {
  const auto originalCredentials = credentials;
  const std::string originalLastSsid = lastConnectedSsid;
  credentials.clear();
  lastConnectedSsid.clear();
  if (writeCredentialsToNvs(credentials) && saveToFile()) {
    LOG_DBG("WCS", "Cleared all WiFi credentials");
    return;
  }
  credentials = originalCredentials;
  lastConnectedSsid = originalLastSsid;
  writeCredentialsToNvs(credentials);
  LOG_ERR("WCS", "Could not clear WiFi credentials");
}
