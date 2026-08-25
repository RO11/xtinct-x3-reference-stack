#include <gtest/gtest.h>

#include "src/util/DailyCardsFreshnessPolicy.h"
#include "src/util/InboxDailyCachePolicy.h"

namespace policy = xtinct::daily_cards;

TEST(DailyCardsFreshnessPolicy, MissingOrOlderStateAllowsOneAutomaticClaim) {
  constexpr uint32_t today = 20676;
  static_assert(policy::shouldClaimAutomaticSync(
      true, policy::StoredStateStatus::Missing, today, 0, 0));
  EXPECT_TRUE(policy::shouldClaimAutomaticSync(
      true, policy::StoredStateStatus::Valid, today, today - 1, today - 1));
}

TEST(DailyCardsFreshnessPolicy, AttemptOrFreshnessTodaySuppressesAnotherAutomaticSync) {
  constexpr uint32_t today = 20676;
  EXPECT_FALSE(policy::shouldClaimAutomaticSync(
      true, policy::StoredStateStatus::Valid, today, today, 0));
  EXPECT_FALSE(policy::shouldClaimAutomaticSync(
      true, policy::StoredStateStatus::Valid, today, today - 1, today));
}

TEST(DailyCardsFreshnessPolicy, UnknownDayOrMalformedStateFailsClosed) {
  constexpr uint32_t today = 20676;
  EXPECT_FALSE(policy::shouldClaimAutomaticSync(
      false, policy::StoredStateStatus::Missing, today, 0, 0));
  EXPECT_FALSE(policy::shouldClaimAutomaticSync(
      true, policy::StoredStateStatus::Invalid, today, 0, 0));
}

TEST(DailyCardsFreshnessPolicy, DayBoundaryIsFixedToBrisbane) {
  static_assert(policy::BRISBANE_UTC_OFFSET_QUARTER_HOURS_BIASED == 88);
  constexpr int64_t beforeMidnight = 2 * 86400 + 13 * 3600 + 59 * 60 + 59;
  uint32_t beforeDay = 0;
  uint32_t afterDay = 0;
  ASSERT_TRUE(xtinct::inbox_cache::localDayFromUtcEpoch(
      beforeMidnight, policy::BRISBANE_UTC_OFFSET_QUARTER_HOURS_BIASED, beforeDay));
  ASSERT_TRUE(xtinct::inbox_cache::localDayFromUtcEpoch(
      beforeMidnight + 1, policy::BRISBANE_UTC_OFFSET_QUARTER_HOURS_BIASED, afterDay));
  EXPECT_EQ(beforeDay, 2U);
  EXPECT_EQ(afterDay, 3U);
}

TEST(DailyCardsFreshnessPolicy, FreshRequiresBothDurableFeeds) {
  static_assert(policy::canStampFresh(true, true));
  EXPECT_FALSE(policy::canStampFresh(false, true));
  EXPECT_FALSE(policy::canStampFresh(true, false));
  EXPECT_FALSE(policy::canStampFresh(false, false));
}

TEST(DailyCardsFreshnessPolicy, FailedForcedAttemptCannotInheritEarlierFreshness) {
  constexpr uint32_t today = 20676;
  uint32_t freshDay = policy::freshDayAfterAttempt(true, today);
  ASSERT_EQ(freshDay, today);

  // A forced attempt starts, then its V2 pass is partial. Freshness remains
  // cleared, so a later ordinary open is eligible for its one automatic try.
  freshDay = policy::freshDayAfterAttempt(false, today);
  ASSERT_EQ(freshDay, 0U);
  EXPECT_FALSE(policy::canStampFresh(true, false));
  EXPECT_TRUE(policy::shouldClaimAutomaticSync(
      true, policy::StoredStateStatus::Valid, today, today - 1, freshDay));
}
