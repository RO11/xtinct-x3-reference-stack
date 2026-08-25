#include "XtinctWakeStatusStore.h"

#include <cstring>

namespace {
XtinctTimerArmState timerStateFromCode(const char* code) {
  if (!code) return XtinctTimerArmState::Unknown;
  for (uint8_t value = static_cast<uint8_t>(XtinctTimerArmState::Unknown);
       value <= static_cast<uint8_t>(XtinctTimerArmState::Error); ++value) {
    const auto state = static_cast<XtinctTimerArmState>(value);
    if (std::strcmp(code, xtinctTimerArmStateCode(state)) == 0) return state;
  }
  return XtinctTimerArmState::Unknown;
}

XtinctObservedWakeCause wakeCauseFromCode(const char* code) {
  if (!code) return XtinctObservedWakeCause::Unknown;
  for (uint8_t value = static_cast<uint8_t>(XtinctObservedWakeCause::Unknown);
       value <= static_cast<uint8_t>(XtinctObservedWakeCause::Other); ++value) {
    const auto cause = static_cast<XtinctObservedWakeCause>(value);
    if (std::strcmp(code, xtinctWakeCauseCode(cause)) == 0) return cause;
  }
  return XtinctObservedWakeCause::Unknown;
}
}  // namespace

void XtinctWakeStatusStore::toJson(JsonDocument& doc) const {
  doc["schema"] = 1;
  doc["last_timer_state"] = xtinctTimerArmStateCode(lastTimerState);
  doc["last_timer_reason"] = xtinctWakeReasonCode(lastTimerReason);
  doc["last_timer_next_known"] = lastTimerNextLocalKnown;
  doc["last_timer_next_hour"] = lastTimerNextHour;
  doc["last_timer_next_minute"] = lastTimerNextMinute;
  doc["last_timer_seconds"] = lastTimerSeconds;
  doc["last_timer_error"] = lastTimerError;
  doc["last_wake_cause"] = xtinctWakeCauseCode(lastWakeCause);
}

bool XtinctWakeStatusStore::fromJson(const JsonVariantConst doc) {
  if ((doc["schema"] | 0) != 1) return false;
  lastTimerState = timerStateFromCode(doc["last_timer_state"] | "unknown");
  lastTimerReason = xtinctWakeReasonFromCode(doc["last_timer_reason"] | "schedule_invalid");
  lastTimerNextLocalKnown = doc["last_timer_next_known"] | false;
  const int hour = doc["last_timer_next_hour"] | 0;
  const int minute = doc["last_timer_next_minute"] | 0;
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) {
    lastTimerNextLocalKnown = false;
    lastTimerNextHour = 0;
    lastTimerNextMinute = 0;
  } else {
    lastTimerNextHour = static_cast<uint8_t>(hour);
    lastTimerNextMinute = static_cast<uint8_t>(minute);
  }
  lastTimerSeconds = doc["last_timer_seconds"] | static_cast<uint32_t>(0);
  lastTimerError = doc["last_timer_error"] | static_cast<int32_t>(0);
  lastWakeCause = wakeCauseFromCode(doc["last_wake_cause"] | "unknown");
  return true;
}

void XtinctWakeStatusStore::recordTimerResult(const XtinctWakePlan& plan, const XtinctTimerArmState state,
                                               const int32_t errorCode) {
  lastTimerState = state;
  lastTimerReason = plan.reason;
  lastTimerNextLocalKnown = plan.nextLocalKnown;
  lastTimerNextHour = plan.nextHour;
  lastTimerNextMinute = plan.nextMinute;
  lastTimerSeconds = plan.seconds;
  lastTimerError = errorCode;
}

const char* xtinctTimerArmStateCode(const XtinctTimerArmState state) {
  switch (state) {
    case XtinctTimerArmState::Unknown:
      return "unknown";
    case XtinctTimerArmState::NotArmed:
      return "not_armed";
    case XtinctTimerArmState::Armed:
      return "armed";
    case XtinctTimerArmState::Error:
      return "arm_error";
  }
  return "unknown";
}

const char* xtinctTimerArmStateLabel(const XtinctTimerArmState state) {
  switch (state) {
    case XtinctTimerArmState::Unknown:
      return "No sleep attempt recorded";
    case XtinctTimerArmState::NotArmed:
      return "Timer was not armed";
    case XtinctTimerArmState::Armed:
      return "Timer arm call succeeded";
    case XtinctTimerArmState::Error:
      return "Timer arm call failed";
  }
  return "No sleep attempt recorded";
}

const char* xtinctWakeCauseCode(const XtinctObservedWakeCause cause) {
  switch (cause) {
    case XtinctObservedWakeCause::Unknown:
      return "unknown";
    case XtinctObservedWakeCause::Timer:
      return "timer";
    case XtinctObservedWakeCause::PowerButton:
      return "power_button";
    case XtinctObservedWakeCause::UsbPower:
      return "usb_power";
    case XtinctObservedWakeCause::AfterFlash:
      return "after_flash";
    case XtinctObservedWakeCause::Other:
      return "other";
  }
  return "unknown";
}

const char* xtinctWakeCauseLabel(const XtinctObservedWakeCause cause) {
  switch (cause) {
    case XtinctObservedWakeCause::Unknown:
      return "Unknown / no record";
    case XtinctObservedWakeCause::Timer:
      return "Timer";
    case XtinctObservedWakeCause::PowerButton:
      return "Power button";
    case XtinctObservedWakeCause::UsbPower:
      return "USB power";
    case XtinctObservedWakeCause::AfterFlash:
      return "Firmware flash";
    case XtinctObservedWakeCause::Other:
      return "Other reset";
  }
  return "Unknown / no record";
}
