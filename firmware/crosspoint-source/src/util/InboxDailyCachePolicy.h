#pragma once

#include <cstdint>

namespace xtinct::inbox_cache {

// CrossPoint stores UTC in its RTC. Convert an epoch timestamp to the local
// calendar-day number using the same biased quarter-hour offset as Settings
// (48 = UTC, 88 = Brisbane). Keeping this pure makes the midnight boundary
// independently testable without an RTC or filesystem.
constexpr bool localDayFromUtcEpoch(const int64_t utcSeconds, const uint8_t utcOffsetQuarterHoursBiased,
                                    uint32_t& localDay) {
  if (utcSeconds < 0 || utcOffsetQuarterHoursBiased > 104) return false;
  const int64_t offsetSeconds = (static_cast<int64_t>(utcOffsetQuarterHoursBiased) - 48) * 15 * 60;
  const int64_t localSeconds = utcSeconds + offsetSeconds;
  if (localSeconds < 0) return false;
  localDay = static_cast<uint32_t>(localSeconds / (24 * 60 * 60));
  return true;
}

// The fast first-page index is only an optimisation. It is usable when a
// complete sync built it today, the durable cursor is unchanged, and the
// caller is requesting the first page. Every other state falls back to the
// existing bounded metadata scan.
constexpr bool canUseFastFirstPage(const bool firstPage, const bool complete, const bool cursorMatches,
                                   const bool currentDayKnown, const uint32_t currentLocalDay,
                                   const uint32_t cachedLocalDay) {
  return firstPage && complete && cursorMatches && currentDayKnown && currentLocalDay == cachedLocalDay;
}

}  // namespace xtinct::inbox_cache
