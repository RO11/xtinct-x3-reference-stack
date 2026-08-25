#include "HalClock.h"

#include <Logging.h>
#include <WiFi.h>
#include <esp_sntp.h>
#include <sys/time.h>
#include <time.h>

#include "LocalTimeMath.h"

HalClock halClock;  // Singleton instance

namespace {
bool isPlausibleUtc(const Rtc::DateTime& dt) {
  if (dt.year < 2024 || dt.year > 2099 || dt.month < 1 || dt.month > 12 || dt.day < 1 || dt.hour > 23 ||
      dt.minute > 59 || dt.second > 59) {
    return false;
  }
  static constexpr uint8_t DAYS_IN_MONTH[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  uint8_t maximumDay = DAYS_IN_MONTH[dt.month - 1];
  const bool leapYear = (dt.year % 4 == 0 && dt.year % 100 != 0) || dt.year % 400 == 0;
  if (dt.month == 2 && leapYear) maximumDay = 29;
  return dt.day <= maximumDay;
}
}  // namespace

void HalClock::begin() {
  _hasValidTime = false;
  _available = _sdkRtc.begin();
  LOG_INF("CLK", _available ? "SDK RTC found" : "RTC not found");
  if (_available && !restoreSystemTimeFromRtc()) {
    LOG_ERR("CLK", "RTC present but system time could not be restored");
  }
}

bool HalClock::restoreSystemTimeFromRtc() {
  Rtc::DateTime dt;
  if (!_sdkRtc.now(dt) || !isPlausibleUtc(dt)) {
    _hasValidTime = false;
    return false;
  }

  // CrossPoint stores UTC in the hardware RTC and applies the user's offset
  // only when formatting. Keep libc in UTC as well so mktime is deterministic.
  setenv("TZ", "UTC0", 1);
  tzset();
  struct tm utc = {};
  utc.tm_year = static_cast<int>(dt.year) - 1900;
  utc.tm_mon = static_cast<int>(dt.month) - 1;
  utc.tm_mday = dt.day;
  utc.tm_hour = dt.hour;
  utc.tm_min = dt.minute;
  utc.tm_sec = dt.second;
  utc.tm_isdst = 0;
  const time_t epoch = mktime(&utc);
  if (epoch <= 0) return false;

  const struct timeval value = {epoch, 0};
  if (settimeofday(&value, nullptr) != 0) return false;
  _hasValidTime = true;
  LOG_DBG("CLK", "System clock restored from RTC");
  return true;
}

bool HalClock::hasValidTime() const {
  if (!_available) return false;
  Rtc::DateTime dt;
  _hasValidTime = _sdkRtc.now(dt) && isPlausibleUtc(dt);
  return _hasValidTime;
}

bool HalClock::getTime(uint8_t& hour, uint8_t& minute) const {
  if (!_available) return false;

  const unsigned long now = millis();
  if (_lastPollMs != 0 && (now - _lastPollMs) < CLOCK_POLL_MS) {
    hour = _cachedHour;
    minute = _cachedMinute;
    return true;
  }

  Rtc::DateTime dt;
  if (!_sdkRtc.now(dt)) {
    if (!_hasCachedTime) return false;
    _lastPollMs = now;
    hour = _cachedHour;
    minute = _cachedMinute;
    return true;
  }
  _cachedHour = dt.hour;
  _cachedMinute = dt.minute;
  _lastPollMs = now;
  _hasCachedTime = true;
  hour = _cachedHour;
  minute = _cachedMinute;
  return true;
}

bool HalClock::getUtcTime(uint8_t& hour, uint8_t& minute, uint8_t& second) const {
  if (!_available) return false;
  Rtc::DateTime dt;
  if (!_sdkRtc.now(dt) || !isPlausibleUtc(dt)) {
    _hasValidTime = false;
    return false;
  }
  _hasValidTime = true;
  hour = dt.hour;
  minute = dt.minute;
  second = dt.second;
  return true;
}

bool HalClock::formatTime(char* buf, size_t bufSize, uint8_t utcOffsetQuarterHoursBiased, bool use12Hour) const {
  if (bufSize < (use12Hour ? 9u : 6u)) return false;
  uint8_t h, m;
  if (!getTime(h, m)) return false;

  // Apply UTC offset: convert biased value to signed quarter-hours.
  // Clamp against corrupted persisted values so display time can't drift outside [-12:00, +14:00].
  if (utcOffsetQuarterHoursBiased > 104) utcOffsetQuarterHoursBiased = 104;
  int offsetQuarterHours = static_cast<int>(utcOffsetQuarterHoursBiased) - 48;
  int totalMinutes = static_cast<int>(h) * 60 + static_cast<int>(m) + offsetQuarterHours * 15;

  // Wrap around 24 hours
  totalMinutes = ((totalMinutes % 1440) + 1440) % 1440;

  const int hour24 = totalMinutes / 60;
  const int min = totalMinutes % 60;
  if (use12Hour) {
    const bool pm = hour24 >= 12;
    int hour12 = hour24 % 12;
    if (hour12 == 0) hour12 = 12;
    snprintf(buf, bufSize, "%d:%02d %s", hour12, min, pm ? "PM" : "AM");
  } else {
    snprintf(buf, bufSize, "%02d:%02d", hour24, min);
  }
  return true;
}

bool HalClock::syncFromNTP() {
  if (!_available) return false;

  if (WiFi.status() != WL_CONNECTED) {
    LOG_ERR("CLK", "WiFi not connected, cannot sync NTP");
    return false;
  }

  LOG_INF("CLK", "Starting NTP sync...");
  configTzTime("UTC0", "pool.ntp.org", "time.nist.gov");

  // Wait for SNTP sync to complete (up to 5 seconds)
  constexpr int maxAttempts = 50;
  for (int i = 0; i < maxAttempts; i++) {
    if (sntp_get_sync_status() == SNTP_SYNC_STATUS_COMPLETED) {
      time_t now = time(nullptr);
      struct tm timeinfo;
      gmtime_r(&now, &timeinfo);

      Rtc::DateTime dt;
      dt.year = static_cast<uint16_t>(timeinfo.tm_year + 1900);
      dt.month = static_cast<uint8_t>(timeinfo.tm_mon + 1);
      dt.day = static_cast<uint8_t>(timeinfo.tm_mday);
      dt.hour = static_cast<uint8_t>(timeinfo.tm_hour);
      dt.minute = static_cast<uint8_t>(timeinfo.tm_min);
      dt.second = static_cast<uint8_t>(timeinfo.tm_sec);
      dt.weekday = static_cast<uint8_t>(timeinfo.tm_wday);
      if (_sdkRtc.set(dt)) {
        _lastPollMs = 0;
        _cachedHour = dt.hour;
        _cachedMinute = dt.minute;
        _hasCachedTime = true;
        _hasValidTime = true;
        LOG_INF("CLK", "RTC set to %04u-%02u-%02u %02u:%02u:%02u UTC", dt.year, dt.month, dt.day, dt.hour, dt.minute,
                dt.second);
        return true;
      }
      return false;
    }
    delay(100);
  }

  LOG_ERR("CLK", "NTP sync timed out");
  return false;
}

bool HalClock::secondsUntilLocalTime(const uint8_t targetHour, const uint8_t targetMinute,
                                     const uint8_t utcOffsetQuarterHoursBiased, uint32_t& seconds) const {
  if (!_available) return false;
  Rtc::DateTime dt;
  if (!_sdkRtc.now(dt) || !isPlausibleUtc(dt)) {
    _hasValidTime = false;
    return false;
  }
  _hasValidTime = true;
  return local_time_math::secondsUntilNextLocalTime(dt.hour, dt.minute, dt.second, targetHour, targetMinute,
                                                     utcOffsetQuarterHoursBiased, seconds);
}
