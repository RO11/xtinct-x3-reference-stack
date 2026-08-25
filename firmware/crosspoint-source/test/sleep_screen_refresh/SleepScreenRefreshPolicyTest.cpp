#include <gtest/gtest.h>

#include "SleepScreenRefreshPolicy.h"

TEST(SleepScreenRefreshPolicy, UsesMaximumValidatedConditionCount) {
  EXPECT_EQ(SleepScreenRefreshPolicy::X3_VALIDATED_POST_CONDITION_PASSES, 1);
  EXPECT_EQ(SleepScreenRefreshPolicy::X3_VALIDATED_POST_CONDITION_PASSES,
            SleepScreenRefreshPolicy::X3_MAX_SAFE_POST_CONDITION_PASSES);
}
