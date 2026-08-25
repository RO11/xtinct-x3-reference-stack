#pragma once

#include <Arduino.h>
#include <Rtc.h>

class HalClock;
extern HalClock halClock;  // Singleton

class HalClock {
  bool _available = false;
  mutable Rtc _sdkRtc;
  mutable uint8_t _cachedHour = 0;
  mutable uint8_t _cachedMinute = 0;
  mutable bool _hasCachedTime = false;
  mutable bool _hasValidTime = false;
  mutable unsigned long _lastPollMs = 0;

  static constexpr unsigned long CLOCK_POLL_MS = 10000;  // 10 seconds

  // Restore the ESP system clock from the battery-backed UTC RTC. TLS
  // certificate validation uses the system clock after every cold/deep boot.
  bool restoreSystemTimeFromRtc();

 public:
  // Call after BoardConfig has selected the active device.
  void begin();

  // True if an RTC is present on this device
  bool isAvailable() const { return _available; }

  // True only when the current RTC value is present and plausible. This reads
  // the RTC rather than trusting the historical clockHasBeenSynced setting, so
  // a flat coin cell or reset RTC can trigger NTP recovery.
  bool hasValidTime() const;

  // Get current hour (0-23) and minute (0-59).
  // Returns false if RTC is not available.
  bool getTime(uint8_t& hour, uint8_t& minute) const;

  // Read one coherent UTC hour/minute/second snapshot directly from the RTC.
  // Scheduled-wake selection uses this instead of three independent reads so
  // a calculation that crosses a minute boundary cannot choose inconsistent
  // candidates.
  bool getUtcTime(uint8_t& hour, uint8_t& minute, uint8_t& second) const;

  // Format time into a caller-provided buffer.
  // 24h mode produces "HH:MM" (needs >=6 bytes); 12h mode produces "H:MM AM"/"HH:MM PM" (needs >=9 bytes).
  // utcOffsetQuarterHoursBiased: biased quarter-hour offset (48 = UTC+0, 0 = UTC-12, 104 = UTC+14).
  // use12Hour: when true, format as 12-hour clock with AM/PM suffix.
  // Returns false if RTC is not available.
  bool formatTime(char* buf, size_t bufSize, uint8_t utcOffsetQuarterHoursBiased = 48, bool use12Hour = false) const;

  // Sync the RTC from an NTP server. Requires WiFi to be connected.
  // Blocks for up to ~5s while waiting for SNTP response.
  // Returns true if the RTC was successfully updated.
  //
  // Debouncing (skip if already synced once) is enforced by the caller, not here,
  // so the HAL stays free of any app-layer settings dependency.
  bool syncFromNTP();

  // Calculate a one-shot delay to the next local occurrence of
  // targetHour:targetMinute.
  // The RTC stores UTC; utcOffsetQuarterHoursBiased uses the same representation
  // as CrossPointSettings (48 = UTC, 88 = UTC+10).
  bool secondsUntilLocalTime(uint8_t targetHour, uint8_t targetMinute, uint8_t utcOffsetQuarterHoursBiased,
                             uint32_t& seconds) const;
};
