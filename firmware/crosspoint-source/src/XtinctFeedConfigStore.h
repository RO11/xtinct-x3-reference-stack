#pragma once

#include <ArduinoJson.h>
#include <PersistableStore.h>

#include <cstdint>
#include <string>

#include "util/XtinctWakeRuntimePolicy.h"

class XtinctFeedConfigStore : public PersistableStore<XtinctFeedConfigStore> {
 private:
  // Public builds deliberately ship without a feed destination. The origin
  // and bearer are provisioned together over physical USB as one atomic NVS
  // record; removable storage never selects the effective destination.
  std::string baseUrl;
  std::string readToken;
  bool enabled = false;
  uint8_t wakeHour = 4;
  uint8_t wakeMinute = 15;

  XtinctFeedConfigStore() = default;
  friend class PersistableStore<XtinctFeedConfigStore>;

 public:
  static const char* getFilePath() { return "/.crosspoint/xtinct_feed.json"; }

  void toJson(JsonDocument& doc) const;
  bool fromJson(JsonVariantConst doc);
  bool load();

  const std::string& getBaseUrl() const { return baseUrl; }
  const std::string& getReadToken() const { return readToken; }
  bool hasReadToken() const { return !baseUrl.empty() && !readToken.empty(); }
  // The explicit user-saved switch, kept separate from credential readiness
  // so diagnostics can say "auto sync off" instead of silently collapsing all
  // blocked states into isEnabled()==false.
  bool isAutoSyncRequested() const { return enabled; }
  bool isEnabled() const {
    return isValidBaseUrl(baseUrl) && xtinct::wake_runtime::isEffectiveAutoSyncEnabled(enabled, hasReadToken());
  }
  uint8_t getWakeHour() const { return wakeHour; }
  uint8_t getWakeMinute() const { return wakeMinute; }

  bool updateSettings(bool newEnabled, uint8_t newWakeHour, uint8_t newWakeMinute);
  bool replaceCredential(const std::string& newBaseUrl, const std::string& newReadToken);

  static bool isValidBaseUrl(const std::string& candidate);
  static bool isValidReadToken(const std::string& candidate);
};

#define XTINCT_FEED_CONFIG XtinctFeedConfigStore::getInstance()
