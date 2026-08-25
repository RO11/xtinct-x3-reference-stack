#pragma once

#include <ArduinoJson.h>
#include <PersistableStore.h>

#include <cstdint>

#include "XtinctWakePlan.h"

enum class XtinctTimerArmState : uint8_t { Unknown = 0, NotArmed, Armed, Error };
enum class XtinctObservedWakeCause : uint8_t { Unknown = 0, Timer, PowerButton, UsbPower, AfterFlash, Other };

class XtinctWakeStatusStore : public PersistableStore<XtinctWakeStatusStore> {
 private:
  XtinctTimerArmState lastTimerState = XtinctTimerArmState::Unknown;
  XtinctWakeBlockReason lastTimerReason = XtinctWakeBlockReason::AutoSyncOff;
  bool lastTimerNextLocalKnown = false;
  uint8_t lastTimerNextHour = 0;
  uint8_t lastTimerNextMinute = 0;
  uint32_t lastTimerSeconds = 0;
  int32_t lastTimerError = 0;
  XtinctObservedWakeCause lastWakeCause = XtinctObservedWakeCause::Unknown;

  XtinctWakeStatusStore() = default;
  friend class PersistableStore<XtinctWakeStatusStore>;

 public:
  static const char* getFilePath() { return "/.crosspoint/xtinct_wake_status.json"; }

  void toJson(JsonDocument& doc) const;
  bool fromJson(JsonVariantConst doc);

  void recordTimerResult(const XtinctWakePlan& plan, XtinctTimerArmState state, int32_t errorCode = 0);
  void recordWakeCause(XtinctObservedWakeCause cause) { lastWakeCause = cause; }

  XtinctTimerArmState getLastTimerState() const { return lastTimerState; }
  XtinctWakeBlockReason getLastTimerReason() const { return lastTimerReason; }
  bool isLastTimerNextLocalKnown() const { return lastTimerNextLocalKnown; }
  uint8_t getLastTimerNextHour() const { return lastTimerNextHour; }
  uint8_t getLastTimerNextMinute() const { return lastTimerNextMinute; }
  uint32_t getLastTimerSeconds() const { return lastTimerSeconds; }
  int32_t getLastTimerError() const { return lastTimerError; }
  XtinctObservedWakeCause getLastWakeCause() const { return lastWakeCause; }
};

const char* xtinctTimerArmStateCode(XtinctTimerArmState state);
const char* xtinctTimerArmStateLabel(XtinctTimerArmState state);
const char* xtinctWakeCauseCode(XtinctObservedWakeCause cause);
const char* xtinctWakeCauseLabel(XtinctObservedWakeCause cause);

#define XTINCT_WAKE_STATUS XtinctWakeStatusStore::getInstance()
