#include <gtest/gtest.h>

#include "lib/hal/LocalTimeMath.h"

TEST(LocalTimeMath, SchedulesBrisbaneQuarterHourWake) {
  uint32_t seconds = 0;
  // 18:14:59 UTC is 04:14:59 in Brisbane (UTC+10).
  ASSERT_TRUE(local_time_math::secondsUntilNextLocalTime(18, 14, 59, 4, 15, 88, seconds));
  EXPECT_EQ(seconds, 1U);
}

TEST(LocalTimeMath, ExactTargetSchedulesNextDay) {
  uint32_t seconds = 0;
  ASSERT_TRUE(local_time_math::secondsUntilNextLocalTime(18, 15, 0, 4, 15, 88, seconds));
  EXPECT_EQ(seconds, 86400U);
}

TEST(LocalTimeMath, HandlesWakeAfterLocalMidnight) {
  uint32_t seconds = 0;
  // 13:30 UTC is 23:30 local; 04:15 is 4h45m away.
  ASSERT_TRUE(local_time_math::secondsUntilNextLocalTime(13, 30, 0, 4, 15, 88, seconds));
  EXPECT_EQ(seconds, 4U * 3600U + 45U * 60U);
}

TEST(LocalTimeMath, HandlesNegativeUtcOffset) {
  uint32_t seconds = 0;
  // Offset value 28 is UTC-5, so 08:00 UTC is 03:00 local.
  ASSERT_TRUE(local_time_math::secondsUntilNextLocalTime(8, 0, 0, 4, 15, 28, seconds));
  EXPECT_EQ(seconds, 75U * 60U);
}

TEST(LocalTimeMath, RejectsInvalidClockOrTarget) {
  uint32_t seconds = 123;
  EXPECT_FALSE(local_time_math::secondsUntilNextLocalTime(24, 0, 0, 4, 15, 88, seconds));
  EXPECT_FALSE(local_time_math::secondsUntilNextLocalTime(0, 60, 0, 4, 15, 88, seconds));
  EXPECT_FALSE(local_time_math::secondsUntilNextLocalTime(0, 0, 60, 4, 15, 88, seconds));
  EXPECT_FALSE(local_time_math::secondsUntilNextLocalTime(0, 0, 0, 24, 15, 88, seconds));
  EXPECT_FALSE(local_time_math::secondsUntilNextLocalTime(0, 0, 0, 4, 60, 88, seconds));
}
