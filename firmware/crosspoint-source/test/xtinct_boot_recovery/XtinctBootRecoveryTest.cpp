#include <gtest/gtest.h>

#include <cstdint>

#include "src/util/XtinctBootRecovery.h"

namespace recovery = xtinct::boot_recovery;

namespace {

recovery::Result hold(recovery::Detector& detector, uint32_t& now, const recovery::Sample sample,
                      const uint32_t duration) {
  recovery::Result result;
  for (uint32_t held = 0; held <= duration; held += 10) {
    result = detector.step(now, sample);
    now += 10;
  }
  return result;
}

}  // namespace

TEST(XtinctBootRecovery, AcceptsRepresentablePowerUpNeutralPowerDownSequence) {
  uint32_t now = 1000;
  recovery::Detector detector(now);
  auto result = hold(detector, now, {true, true, false}, recovery::POWER_UP_HOLD_MS + 10);
  EXPECT_TRUE(result.sdRecoveryLatched);
  EXPECT_FALSE(result.partitionRollback);
  result = hold(detector, now, {true, false, false}, recovery::NEUTRAL_HOLD_MS + 10);
  result = hold(detector, now, {true, false, true}, recovery::POWER_DOWN_HOLD_MS + 10);
  EXPECT_TRUE(result.finished);
  EXPECT_TRUE(result.sdRecoveryLatched);
  EXPECT_TRUE(result.partitionRollback);
}

TEST(XtinctBootRecovery, PowerUpAloneFallsBackToSdRecovery) {
  uint32_t now = 2000;
  recovery::Detector detector(now);
  auto result = hold(detector, now, {true, true, false}, recovery::POWER_UP_HOLD_MS + 10);
  ASSERT_TRUE(result.sdRecoveryLatched);
  result = detector.step(now, {false, false, false});
  EXPECT_TRUE(result.finished);
  EXPECT_TRUE(result.sdRecoveryLatched);
  EXPECT_FALSE(result.partitionRollback);
}

TEST(XtinctBootRecovery, NeverAcceptsImpossibleSimultaneousLadderState) {
  recovery::Detector detector(0);
  const auto result = detector.step(0, {true, true, true});
  EXPECT_TRUE(result.finished);
  EXPECT_FALSE(result.sdRecoveryLatched);
  EXPECT_FALSE(result.partitionRollback);
}

TEST(XtinctBootRecovery, RequiresObservableNeutralGap) {
  uint32_t now = 3000;
  recovery::Detector detector(now);
  auto result = hold(detector, now, {true, true, false}, recovery::POWER_UP_HOLD_MS + 10);
  ASSERT_TRUE(result.sdRecoveryLatched);
  result = detector.step(now, {true, false, true});
  EXPECT_TRUE(result.finished);
  EXPECT_TRUE(result.sdRecoveryLatched);
  EXPECT_FALSE(result.partitionRollback);
}

TEST(XtinctBootRecovery, SecondStageTimeoutKeepsSdFallback) {
  uint32_t now = 4000;
  recovery::Detector detector(now);
  auto result = hold(detector, now, {true, true, false}, recovery::POWER_UP_HOLD_MS + 10);
  ASSERT_TRUE(result.sdRecoveryLatched);
  result = detector.step(now + recovery::SECOND_STAGE_TIMEOUT_MS, {true, true, false});
  EXPECT_TRUE(result.finished);
  EXPECT_TRUE(result.sdRecoveryLatched);
  EXPECT_FALSE(result.partitionRollback);
}

TEST(XtinctBootRecovery, TimersAreWrapSafe) {
  uint32_t now = 0xfffffff0U;
  recovery::Detector detector(now);
  auto result = hold(detector, now, {true, true, false}, recovery::POWER_UP_HOLD_MS + 10);
  ASSERT_TRUE(result.sdRecoveryLatched);
  result = hold(detector, now, {true, false, false}, recovery::NEUTRAL_HOLD_MS + 10);
  result = hold(detector, now, {true, false, true}, recovery::POWER_DOWN_HOLD_MS + 10);
  EXPECT_TRUE(result.finished);
  EXPECT_TRUE(result.partitionRollback);
  static_assert(recovery::elapsed(0x20U, 0xfffffff0U, 0x30U));
}

TEST(XtinctBootRecovery, ExplicitSdRecoveryPrecedesDamagedPendingCommit) {
  EXPECT_FALSE(recovery::mustRecoverPendingCommit(true));
  EXPECT_TRUE(recovery::mayContinueBoot(true, false));
  EXPECT_TRUE(recovery::mustRecoverPendingCommit(false));
  EXPECT_FALSE(recovery::mayContinueBoot(false, false));
  EXPECT_TRUE(recovery::mayContinueBoot(false, true));
}

TEST(XtinctBootRecovery, LatchedRecoveryBypassesEveryPreRoutingSleepIncludingUsbBoot) {
  EXPECT_FALSE(recovery::mayEnterPreRoutingSleep(true));
  EXPECT_TRUE(recovery::mayEnterPreRoutingSleep(false));
}
