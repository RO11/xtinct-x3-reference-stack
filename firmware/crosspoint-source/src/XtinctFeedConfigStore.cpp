#include "XtinctFeedConfigStore.h"

#include <Logging.h>
#include <Preferences.h>

#include <algorithm>
#include <mutex>

#include "util/XtinctFeedCredentialPolicy.h"

namespace {
constexpr char NVS_NAMESPACE[] = "xtinct_feed";
constexpr char NVS_CREDENTIAL_KEY[] = "feed_cred_v1";
constexpr char LEGACY_NVS_TOKEN_KEY[] = "read_token";

bool eraseLegacyToken(Preferences& preferences) {
  if (!preferences.isKey(LEGACY_NVS_TOKEN_KEY)) return true;
  return preferences.remove(LEGACY_NVS_TOKEN_KEY) &&
         !preferences.isKey(LEGACY_NVS_TOKEN_KEY);
}

bool eraseLegacyTokenFromNvs() {
  Preferences preferences;
  if (!preferences.begin(NVS_NAMESPACE, false)) return false;
  const bool erased = eraseLegacyToken(preferences);
  preferences.end();
  return erased;
}

std::string readCredentialRecordFromNvs() {
  Preferences preferences;
  if (!preferences.begin(NVS_NAMESPACE, true)) return {};
  const String stored = preferences.getString(NVS_CREDENTIAL_KEY, "");
  preferences.end();
  return std::string(stored.c_str(), stored.length());
}

bool writeCredentialRecordToNvs(const std::string& record) {
  Preferences preferences;
  if (!preferences.begin(NVS_NAMESPACE, false)) return false;
  if (!eraseLegacyToken(preferences)) {
    preferences.end();
    return false;
  }
  const size_t written = preferences.putString(NVS_CREDENTIAL_KEY, record.c_str());
  const String readback = preferences.getString(NVS_CREDENTIAL_KEY, "");
  const bool ok = written == record.size() && readback.length() == record.size() &&
                  std::string(readback.c_str(), readback.length()) == record;
  preferences.end();
  return ok;
}
}  // namespace

void XtinctFeedConfigStore::toJson(JsonDocument& doc) const {
  doc["enabled"] = enabled;
  doc["wake_hour"] = wakeHour;
  doc["wake_minute"] = wakeMinute;
}

bool XtinctFeedConfigStore::fromJson(JsonVariantConst doc) {
  // Public builds never accept a destination or bearer from removable media.
  // Request a rewrite when upgrading any legacy private configuration.
  if (!doc["base_url"].isNull() || !doc["token_obf"].isNull() || !doc["read_token"].isNull()) {
    requestResave();
  }

  wakeHour = std::min<uint8_t>(doc["wake_hour"] | static_cast<uint8_t>(4), 23);
  const int loadedWakeMinute = doc["wake_minute"] | -1;
  if (loadedWakeMinute < 0) {
    wakeMinute = 15;
    requestResave();
  } else if (loadedWakeMinute > 59 || loadedWakeMinute % 15 != 0) {
    LOG_ERR("XCFG", "Invalid wake minute in config; using 15");
    wakeMinute = 15;
    requestResave();
  } else {
    wakeMinute = static_cast<uint8_t>(loadedWakeMinute);
  }
  enabled = doc["enabled"] | false;
  return true;
}

bool XtinctFeedConfigStore::load() {
  const bool settingsLoaded = loadFromFile();
  if (!eraseLegacyTokenFromNvs()) {
    LOG_ERR("XCFG", "Could not erase obsolete split feed token from NVS");
  }
  const std::string record = readCredentialRecordFromNvs();
  xtinct::feed_credential::Credential credential;
  const bool credentialLoaded = xtinct::feed_credential::parse(record, credential);
  {
    std::lock_guard<std::mutex> lock(storeMutex);
    if (credentialLoaded) {
      baseUrl = std::move(credential.origin);
      readToken = std::move(credential.token);
    } else {
      baseUrl.clear();
      readToken.clear();
    }
  }
  if (!record.empty() && !credentialLoaded) {
    LOG_ERR("XCFG", "Malformed or obsolete bound feed credential ignored");
  }
  return settingsLoaded || credentialLoaded;
}

bool XtinctFeedConfigStore::updateSettings(const bool newEnabled, const uint8_t newWakeHour,
                                           const uint8_t newWakeMinute) {
  if (newWakeHour > 23 || newWakeMinute > 59 || newWakeMinute % 15 != 0) return false;

  const bool oldEnabled = enabled;
  const uint8_t oldWakeHour = wakeHour;
  const uint8_t oldWakeMinute = wakeMinute;
  enabled = newEnabled;
  wakeHour = newWakeHour;
  wakeMinute = newWakeMinute;
  if (saveToFile()) return true;

  enabled = oldEnabled;
  wakeHour = oldWakeHour;
  wakeMinute = oldWakeMinute;
  return false;
}

bool XtinctFeedConfigStore::replaceCredential(const std::string& newBaseUrl,
                                              const std::string& newReadToken) {
  const std::string record = xtinct::feed_credential::serialize(newBaseUrl, newReadToken);
  if (record.empty()) return false;
  if (!writeCredentialRecordToNvs(record)) {
    LOG_ERR("XCFG", "Could not save atomic feed credential to NVS");
    return false;
  }
  baseUrl = xtinct::feed_credential::canonicalizeOrigin(newBaseUrl);
  readToken = newReadToken;
  return true;
}

bool XtinctFeedConfigStore::isValidBaseUrl(const std::string& candidate) {
  return xtinct::feed_credential::isValidWorkerOrigin(candidate);
}

bool XtinctFeedConfigStore::isValidReadToken(const std::string& candidate) {
  return xtinct::feed_credential::isValidToken(candidate);
}
