#pragma once

#include <cstdint>

namespace local_time_math {

// Return the delay to the next occurrence of targetHour:targetMinute in the
// configured local timezone. The offset uses CrossPoint's biased quarter-hour
// representation (48 = UTC, 88 = UTC+10). A target matching the current
// second means the next day, not an immediate wake loop.
inline bool secondsUntilNextLocalTime(const uint8_t utcHour, const uint8_t utcMinute, const uint8_t utcSecond,
                                      const uint8_t targetHour, const uint8_t targetMinute,
                                      uint8_t utcOffsetQuarterHoursBiased, uint32_t& seconds) {
  if (utcHour > 23 || utcMinute > 59 || utcSecond > 59 || targetHour > 23 || targetMinute > 59) return false;

  if (utcOffsetQuarterHoursBiased > 104) utcOffsetQuarterHoursBiased = 104;
  constexpr int32_t SECONDS_PER_DAY = 24 * 60 * 60;
  const int32_t offsetSeconds = (static_cast<int32_t>(utcOffsetQuarterHoursBiased) - 48) * 15 * 60;
  int32_t localSeconds = static_cast<int32_t>(utcHour) * 3600 + static_cast<int32_t>(utcMinute) * 60 + utcSecond;
  localSeconds = ((localSeconds + offsetSeconds) % SECONDS_PER_DAY + SECONDS_PER_DAY) % SECONDS_PER_DAY;

  const int32_t targetSeconds = static_cast<int32_t>(targetHour) * 3600 + static_cast<int32_t>(targetMinute) * 60;
  int32_t delaySeconds = (targetSeconds - localSeconds + SECONDS_PER_DAY) % SECONDS_PER_DAY;
  if (delaySeconds == 0) delaySeconds = SECONDS_PER_DAY;
  seconds = static_cast<uint32_t>(delaySeconds);
  return true;
}

}  // namespace local_time_math
