#include "XtinctWakePlan.h"

#include <HalClock.h>

#include <cstdio>
#include <cstring>

#include "CrossPointSettings.h"
#include "XtinctFeedConfigStore.h"
#include "util/XtinctWakeSchedule.h"

XtinctWakePlan calculateXtinctWakePlan() {
  XtinctWakePlan plan;
  if (!XTINCT_FEED_CONFIG.isAutoSyncRequested()) {
    plan.reason = XtinctWakeBlockReason::AutoSyncOff;
    return plan;
  }
  if (!XTINCT_FEED_CONFIG.hasReadToken()) {
    plan.reason = XtinctWakeBlockReason::CredentialMissing;
    return plan;
  }
  if (!SETTINGS.clockHasBeenSynced) {
    plan.reason = XtinctWakeBlockReason::ClockNotSynced;
    return plan;
  }
  if (!halClock.isAvailable()) {
    plan.reason = XtinctWakeBlockReason::RtcUnavailable;
    return plan;
  }
  if (SETTINGS.clockUtcOffsetQ > 104) {
    plan.reason = XtinctWakeBlockReason::TimezoneInvalid;
    return plan;
  }

  uint8_t utcHour = 0;
  uint8_t utcMinute = 0;
  uint8_t utcSecond = 0;
  if (!halClock.getUtcTime(utcHour, utcMinute, utcSecond)) {
    plan.reason = XtinctWakeBlockReason::RtcInvalid;
    return plan;
  }

  xtinct::wake_schedule::NextWake next;
  if (!xtinct::wake_schedule::nextWake(utcHour, utcMinute, utcSecond, SETTINGS.clockUtcOffsetQ,
                                        XTINCT_FEED_CONFIG.getWakeHour(), XTINCT_FEED_CONFIG.getWakeMinute(), next)) {
    plan.reason = XtinctWakeBlockReason::ScheduleInvalid;
    return plan;
  }

  plan.ready = true;
  plan.reason = XtinctWakeBlockReason::Ready;
  plan.seconds = next.seconds;
  plan.nextLocalKnown = true;
  plan.nextHour = next.hour;
  plan.nextMinute = next.minute;
  return plan;
}

namespace {
XtinctWakePlan calculateXtinctOverrideWakePlan(const uint32_t seconds, const XtinctWakeBlockReason purpose) {
  XtinctWakePlan plan;
  if (seconds == 0) return calculateXtinctWakePlan();

  plan.ready = true;
  plan.reason = purpose;
  plan.seconds = seconds;

  uint8_t utcHour = 0;
  uint8_t utcMinute = 0;
  uint8_t utcSecond = 0;
  if (!halClock.getUtcTime(utcHour, utcMinute, utcSecond) || SETTINGS.clockUtcOffsetQ > 104) return plan;

  constexpr uint32_t SECONDS_PER_DAY = 24U * 60U * 60U;
  const int32_t offsetSeconds = (static_cast<int32_t>(SETTINGS.clockUtcOffsetQ) - 48) * 15 * 60;
  int64_t localSeconds = static_cast<int64_t>(utcHour) * 3600 + static_cast<int64_t>(utcMinute) * 60 + utcSecond;
  localSeconds += offsetSeconds + seconds;
  localSeconds %= SECONDS_PER_DAY;
  if (localSeconds < 0) localSeconds += SECONDS_PER_DAY;
  plan.nextLocalKnown = true;
  plan.nextHour = static_cast<uint8_t>(localSeconds / 3600);
  plan.nextMinute = static_cast<uint8_t>((localSeconds % 3600) / 60);
  return plan;
}
}  // namespace

XtinctWakePlan calculateXtinctRetryWakePlan(const uint32_t seconds) {
  return calculateXtinctOverrideWakePlan(seconds, XtinctWakeBlockReason::ScheduledRetry);
}

XtinctWakePlan calculateXtinctDiagnosticTestWakePlan(const uint32_t seconds) {
  return calculateXtinctOverrideWakePlan(seconds, XtinctWakeBlockReason::DiagnosticTest);
}

const char* xtinctWakeReasonCode(const XtinctWakeBlockReason reason) {
  switch (reason) {
    case XtinctWakeBlockReason::Ready:
      return "ready";
    case XtinctWakeBlockReason::AutoSyncOff:
      return "auto_sync_off";
    case XtinctWakeBlockReason::CredentialMissing:
      return "credential_missing";
    case XtinctWakeBlockReason::ClockNotSynced:
      return "clock_not_synced";
    case XtinctWakeBlockReason::RtcUnavailable:
      return "rtc_unavailable";
    case XtinctWakeBlockReason::RtcInvalid:
      return "rtc_invalid";
    case XtinctWakeBlockReason::TimezoneInvalid:
      return "timezone_invalid";
    case XtinctWakeBlockReason::ScheduleInvalid:
      return "schedule_invalid";
    case XtinctWakeBlockReason::ScheduledRetry:
      return "scheduled_retry";
    case XtinctWakeBlockReason::DiagnosticTest:
      return "diagnostic_test";
  }
  return "schedule_invalid";
}

const char* xtinctWakeReasonLabel(const XtinctWakeBlockReason reason) {
  switch (reason) {
    case XtinctWakeBlockReason::Ready:
      return "Ready; sleeping will arm the timer";
    case XtinctWakeBlockReason::AutoSyncOff:
      return "Auto sync is off";
    case XtinctWakeBlockReason::CredentialMissing:
      return "Private read credential is missing";
    case XtinctWakeBlockReason::ClockNotSynced:
      return "Clock has not been synchronized";
    case XtinctWakeBlockReason::RtcUnavailable:
      return "Hardware clock is unavailable";
    case XtinctWakeBlockReason::RtcInvalid:
      return "Hardware clock time is invalid";
    case XtinctWakeBlockReason::TimezoneInvalid:
      return "Local UTC offset is invalid";
    case XtinctWakeBlockReason::ScheduleInvalid:
      return "Wake schedule is invalid";
    case XtinctWakeBlockReason::ScheduledRetry:
      return "Scheduled retry";
    case XtinctWakeBlockReason::DiagnosticTest:
      return "Diagnostic test wake";
  }
  return "Wake schedule is invalid";
}

XtinctWakeBlockReason xtinctWakeReasonFromCode(const char* code) {
  if (!code) return XtinctWakeBlockReason::ScheduleInvalid;
  for (uint8_t value = static_cast<uint8_t>(XtinctWakeBlockReason::Ready);
       value <= static_cast<uint8_t>(XtinctWakeBlockReason::DiagnosticTest); ++value) {
    const auto reason = static_cast<XtinctWakeBlockReason>(value);
    if (std::strcmp(code, xtinctWakeReasonCode(reason)) == 0) return reason;
  }
  return XtinctWakeBlockReason::ScheduleInvalid;
}

bool formatXtinctLocalTime(const uint8_t hour, const uint8_t minute, char* output, const size_t outputSize) {
  if (!output || outputSize < 6 || hour > 23 || minute > 59) return false;
  return std::snprintf(output, outputSize, "%02u:%02u", static_cast<unsigned>(hour), static_cast<unsigned>(minute)) == 5;
}

bool formatXtinctUtcOffset(const uint8_t biasedQuarterHours, char* output, const size_t outputSize) {
  if (!output || outputSize < 10 || biasedQuarterHours > 104) return false;
  const int signedQuarters = static_cast<int>(biasedQuarterHours) - 48;
  const char sign = signedQuarters < 0 ? '-' : '+';
  const int absoluteQuarters = signedQuarters < 0 ? -signedQuarters : signedQuarters;
  const int hours = absoluteQuarters / 4;
  const int minutes = (absoluteQuarters % 4) * 15;
  const int written = std::snprintf(output, outputSize, "UTC%c%02d:%02d", sign, hours, minutes);
  return written > 0 && static_cast<size_t>(written) < outputSize;
}

bool formatXtinctWakeWindows(char* output, const size_t outputSize) {
  if (!output || outputSize == 0) return false;
  const auto windows = xtinct::wake_schedule::buildWindows(XTINCT_FEED_CONFIG.getWakeHour(),
                                                            XTINCT_FEED_CONFIG.getWakeMinute());
  size_t used = 0;
  for (size_t i = 0; i < windows.count; ++i) {
    const int written = std::snprintf(output + used, outputSize - used, "%s%02u:%02u", i == 0 ? "" : " / ",
                                      static_cast<unsigned>(windows.values[i].hour),
                                      static_cast<unsigned>(windows.values[i].minute));
    if (written < 0 || static_cast<size_t>(written) >= outputSize - used) {
      output[0] = '\0';
      return false;
    }
    used += static_cast<size_t>(written);
  }
  return windows.count > 0;
}
