#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <initializer_list>

namespace xtinct {

// Formats the calendar date carried by an ISO-8601 generated_at timestamp.
// The timestamp already includes the report producer's explicit UTC offset,
// so deliberately use its YYYY-MM-DD component instead of applying the X3's
// current timezone a second time.
inline bool formatGeneratedDate(const char* iso8601, char* output, const size_t outputSize) {
  if (!output || outputSize == 0) return false;
  output[0] = '\0';
  if (!iso8601 || strlen(iso8601) < 11) return false;
  for (const size_t index : {0U, 1U, 2U, 3U, 5U, 6U, 8U, 9U}) {
    if (iso8601[index] < '0' || iso8601[index] > '9') return false;
  }
  if (iso8601[4] != '-' || iso8601[7] != '-' || iso8601[10] != 'T') return false;

  const uint16_t year = static_cast<uint16_t>((iso8601[0] - '0') * 1000 + (iso8601[1] - '0') * 100 +
                                               (iso8601[2] - '0') * 10 + (iso8601[3] - '0'));
  const uint8_t month = static_cast<uint8_t>((iso8601[5] - '0') * 10 + (iso8601[6] - '0'));
  const uint8_t day = static_cast<uint8_t>((iso8601[8] - '0') * 10 + (iso8601[9] - '0'));
  static constexpr const char* MONTHS[] = {"January",   "February", "March",    "April",
                                           "May",       "June",     "July",     "August",
                                           "September", "October",  "November", "December"};
  static constexpr uint8_t DAYS_IN_MONTH[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  if (year == 0 || month < 1 || month > 12 || day < 1) return false;
  uint8_t maximumDay = DAYS_IN_MONTH[month - 1];
  const bool leapYear = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
  if (month == 2 && leapYear) maximumDay = 29;
  if (day > maximumDay) return false;

  const int written = snprintf(output, outputSize, "%u %s %04u", static_cast<unsigned>(day), MONTHS[month - 1],
                               static_cast<unsigned>(year));
  return written > 0 && written < static_cast<int>(outputSize);
}

}  // namespace xtinct
