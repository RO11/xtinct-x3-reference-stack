#pragma once

#include <cstddef>
#include <cstdint>

#include <LocalTimeMath.h>

namespace xtinct::wake_schedule {

struct Window {
  uint8_t hour = 0;
  uint8_t minute = 0;
};

struct WindowSet {
  static constexpr size_t CAPACITY = 3;
  Window values[CAPACITY] = {};
  size_t count = 0;
};

struct NextWake {
  uint32_t seconds = 0;
  uint8_t hour = 0;
  uint8_t minute = 0;
};

constexpr bool isValidWindow(const Window window) { return window.hour < 24 && window.minute < 60; }

constexpr bool isSameWindow(const Window lhs, const Window rhs) {
  return lhs.hour == rhs.hour && lhs.minute == rhs.minute;
}

constexpr void appendUnique(WindowSet& set, const Window window) {
  if (!isValidWindow(window) || set.count >= WindowSet::CAPACITY) return;
  for (size_t i = 0; i < set.count; ++i) {
    if (isSameWindow(set.values[i], window)) return;
  }
  set.values[set.count++] = window;
}

// The phone-configured primary wake is followed by two fixed catch-up windows.
// Duplicate times are collapsed so a primary of 08:15 or 18:00 cannot create
// two immediate timer candidates for the same wall-clock minute.
constexpr WindowSet buildWindows(const uint8_t primaryHour, const uint8_t primaryMinute) {
  WindowSet set;
  appendUnique(set, Window{primaryHour, primaryMinute});
  appendUnique(set, Window{8, 15});
  appendUnique(set, Window{18, 0});
  return set;
}

inline bool nextWake(const uint8_t utcHour, const uint8_t utcMinute, const uint8_t utcSecond,
                     const uint8_t utcOffsetQuarterHoursBiased, const uint8_t primaryHour,
                     const uint8_t primaryMinute, NextWake& next) {
  const WindowSet windows = buildWindows(primaryHour, primaryMinute);
  if (windows.count == 0) return false;

  bool found = false;
  for (size_t i = 0; i < windows.count; ++i) {
    uint32_t seconds = 0;
    if (!local_time_math::secondsUntilNextLocalTime(utcHour, utcMinute, utcSecond, windows.values[i].hour,
                                                     windows.values[i].minute, utcOffsetQuarterHoursBiased, seconds)) {
      return false;
    }
    if (seconds == 0) continue;
    if (!found || seconds < next.seconds) {
      found = true;
      next.seconds = seconds;
      next.hour = windows.values[i].hour;
      next.minute = windows.values[i].minute;
    }
  }
  return found;
}

}  // namespace xtinct::wake_schedule
