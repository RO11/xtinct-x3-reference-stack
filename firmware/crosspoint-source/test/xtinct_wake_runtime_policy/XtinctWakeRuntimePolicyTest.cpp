#include <gtest/gtest.h>

#include "src/util/XtinctWakeRuntimePolicy.h"

namespace policy = xtinct::wake_runtime;

TEST(XtinctWakeRuntimePolicy, RequestedStateRemainsSeparateFromCredentialReadiness) {
  static_assert(!policy::isEffectiveAutoSyncEnabled(false, false));
  static_assert(!policy::isEffectiveAutoSyncEnabled(false, true));
  static_assert(!policy::isEffectiveAutoSyncEnabled(true, false));
  static_assert(policy::isEffectiveAutoSyncEnabled(true, true));

  EXPECT_FALSE(policy::isEffectiveAutoSyncEnabled(true, false));
  EXPECT_TRUE(policy::isEffectiveAutoSyncEnabled(true, true));
}

TEST(XtinctWakeRuntimePolicy, DiagnosticWakeNeverSchedulesOrdinaryRetry) {
  static_assert(!policy::shouldScheduleRetry(false, true, 0, 3));
  EXPECT_FALSE(policy::shouldScheduleRetry(false, true, 0, 3));
}

TEST(XtinctWakeRuntimePolicy, OrdinaryWakeRetainsBoundedRetries) {
  static_assert(policy::shouldScheduleRetry(true, true, 0, 3));
  static_assert(policy::shouldScheduleRetry(true, true, 2, 3));
  static_assert(!policy::shouldScheduleRetry(true, true, 3, 3));
  static_assert(!policy::shouldScheduleRetry(true, false, 0, 3));

  EXPECT_TRUE(policy::shouldScheduleRetry(true, true, 2, 3));
  EXPECT_FALSE(policy::shouldScheduleRetry(true, true, 3, 3));
}
