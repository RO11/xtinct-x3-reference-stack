#include <gtest/gtest.h>

#include "src/util/XtinctWakeSchedule.h"

namespace wake = xtinct::wake_schedule;

TEST(XtinctWakeSchedule, KeepsConfiguredPrimaryAndFixedCatchUpWindows) {
  constexpr wake::WindowSet windows = wake::buildWindows(4, 15);
  static_assert(windows.count == 3);
  EXPECT_EQ(windows.values[0].hour, 4);
  EXPECT_EQ(windows.values[0].minute, 15);
  EXPECT_EQ(windows.values[1].hour, 8);
  EXPECT_EQ(windows.values[1].minute, 15);
  EXPECT_EQ(windows.values[2].hour, 18);
  EXPECT_EQ(windows.values[2].minute, 0);
}

TEST(XtinctWakeSchedule, DeduplicatesPrimaryAgainstCatchUpWindows) {
  constexpr wake::WindowSet morningDuplicate = wake::buildWindows(8, 15);
  static_assert(morningDuplicate.count == 2);
  EXPECT_EQ(morningDuplicate.values[0].hour, 8);
  EXPECT_EQ(morningDuplicate.values[1].hour, 18);

  constexpr wake::WindowSet eveningDuplicate = wake::buildWindows(18, 0);
  static_assert(eveningDuplicate.count == 2);
  EXPECT_EQ(eveningDuplicate.values[0].hour, 18);
  EXPECT_EQ(eveningDuplicate.values[1].hour, 8);
}

TEST(XtinctWakeSchedule, SelectsPrimaryOneSecondBeforeWindow) {
  wake::NextWake next;
  // 18:14:59 UTC is 04:14:59 in Brisbane.
  ASSERT_TRUE(wake::nextWake(18, 14, 59, 88, 4, 15, next));
  EXPECT_EQ(next.seconds, 1U);
  EXPECT_EQ(next.hour, 4);
  EXPECT_EQ(next.minute, 15);
}

TEST(XtinctWakeSchedule, ExactPrimaryAdvancesToCatchUpInsteadOfLooping) {
  wake::NextWake next;
  // At exactly 04:15 local, the primary maps to tomorrow; 08:15 is next.
  ASSERT_TRUE(wake::nextWake(18, 15, 0, 88, 4, 15, next));
  EXPECT_EQ(next.seconds, 4U * 60U * 60U);
  EXPECT_EQ(next.hour, 8);
  EXPECT_EQ(next.minute, 15);
}

TEST(XtinctWakeSchedule, AfterEveningWindowSelectsNextDaysPrimary) {
  wake::NextWake next;
  // 08:00:01 UTC is 18:00:01 in Brisbane.
  ASSERT_TRUE(wake::nextWake(8, 0, 1, 88, 4, 15, next));
  EXPECT_EQ(next.seconds, 10U * 60U * 60U + 14U * 60U + 59U);
  EXPECT_EQ(next.hour, 4);
  EXPECT_EQ(next.minute, 15);
}

TEST(XtinctWakeSchedule, UsesPhoneConfiguredPrimary) {
  wake::NextWake next;
  // 18:59:30 UTC is 04:59:30 in Brisbane.
  ASSERT_TRUE(wake::nextWake(18, 59, 30, 88, 5, 0, next));
  EXPECT_EQ(next.seconds, 30U);
  EXPECT_EQ(next.hour, 5);
  EXPECT_EQ(next.minute, 0);
}

TEST(XtinctWakeSchedule, RejectsInvalidPrimary) {
  wake::NextWake next;
  // Fixed windows remain usable even when a corrupted primary is discarded.
  ASSERT_TRUE(wake::nextWake(0, 0, 0, 48, 24, 0, next));
  EXPECT_EQ(next.hour, 8);
  EXPECT_EQ(next.minute, 15);
}
