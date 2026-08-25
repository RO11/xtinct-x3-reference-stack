#pragma once

#include <cstddef>
#include <cstdint>

enum class XtinctWakeBlockReason : uint8_t {
  Ready = 0,
  AutoSyncOff,
  CredentialMissing,
  ClockNotSynced,
  RtcUnavailable,
  RtcInvalid,
  TimezoneInvalid,
  ScheduleInvalid,
  ScheduledRetry,
  DiagnosticTest,
};

struct XtinctWakePlan {
  bool ready = false;
  XtinctWakeBlockReason reason = XtinctWakeBlockReason::AutoSyncOff;
  uint32_t seconds = 0;
  bool nextLocalKnown = false;
  uint8_t nextHour = 0;
  uint8_t nextMinute = 0;
};

XtinctWakePlan calculateXtinctWakePlan();
XtinctWakePlan calculateXtinctRetryWakePlan(uint32_t seconds);
XtinctWakePlan calculateXtinctDiagnosticTestWakePlan(uint32_t seconds);

const char* xtinctWakeReasonCode(XtinctWakeBlockReason reason);
const char* xtinctWakeReasonLabel(XtinctWakeBlockReason reason);
XtinctWakeBlockReason xtinctWakeReasonFromCode(const char* code);

bool formatXtinctLocalTime(uint8_t hour, uint8_t minute, char* output, size_t outputSize);
bool formatXtinctUtcOffset(uint8_t biasedQuarterHours, char* output, size_t outputSize);
bool formatXtinctWakeWindows(char* output, size_t outputSize);
