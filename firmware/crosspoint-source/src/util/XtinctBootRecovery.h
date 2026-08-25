#pragma once

#include <cstdint>

namespace xtinct::boot_recovery {

// The X3 and X3-UC8279 Up/Down keys share one ADC ladder. They cannot be
// represented as a simultaneous chord, so partition rollback is deliberately
// entered as a sequence while Power stays held:
//
//   Power+Up (hold) -> release Up (neutral gap) -> Power+Down (hold)
//
// A confirmed first stage also latches the ordinary SD-firmware recovery
// intent. If the second stage is absent, malformed or times out, callers must
// keep that safer SD-recovery fallback instead of continuing normal boot.
struct Sample {
  bool power = false;
  bool up = false;
  bool down = false;
};

enum class Phase : uint8_t {
  AwaitPowerUp,
  ConfirmPowerUp,
  AwaitNeutral,
  ConfirmNeutral,
  AwaitPowerDown,
  ConfirmPowerDown,
  Finished,
};

struct Result {
  bool finished = false;
  bool sdRecoveryLatched = false;
  bool partitionRollback = false;
};

constexpr uint32_t POWER_UP_HOLD_MS = 180;
constexpr uint32_t NEUTRAL_HOLD_MS = 80;
constexpr uint32_t POWER_DOWN_HOLD_MS = 240;
constexpr uint32_t SECOND_STAGE_TIMEOUT_MS = 2200;

// Unsigned subtraction is defined modulo 2^32, so this remains correct across
// the millis() wrap as long as durations stay below half the counter range.
constexpr bool elapsed(const uint32_t now, const uint32_t since, const uint32_t duration) {
  return static_cast<uint32_t>(now - since) >= duration;
}

// Explicit SD recovery has precedence over a damaged Pocket Sync transaction:
// it must reach the on-card firmware picker without touching the marker. Every
// ordinary boot still has to recover the marker successfully before proceeding.
constexpr bool mustRecoverPendingCommit(const bool sdRecoveryLatched) { return !sdRecoveryLatched; }

constexpr bool mayContinueBoot(const bool sdRecoveryLatched, const bool pendingCommitRecovered) {
  return sdRecoveryLatched || pendingCommitRecovered;
}

// Once explicit recovery is latched, no wake-reason-specific branch may sleep
// before the firmware picker is routed. This includes USB/cold boots where the
// recorded cause is not PowerButton even though the physical sequence exists.
constexpr bool mayEnterPreRoutingSleep(const bool sdRecoveryLatched) { return !sdRecoveryLatched; }

class Detector {
 public:
  explicit constexpr Detector(const uint32_t startedAt) : phaseSince(startedAt), sequenceSince(startedAt) {}

  constexpr Result step(const uint32_t now, const Sample sample) {
    if (phase == Phase::Finished) return current();

    // Up+Down is not a physical state on the X3 ADC ladder. Treat it as an
    // invalid/noisy sample, never as the old impossible rollback chord.
    if (sample.up && sample.down) {
      finish();
      return current();
    }

    switch (phase) {
      case Phase::AwaitPowerUp:
        if (!sample.power) {
          finish();
        } else if (sample.up && !sample.down) {
          phase = Phase::ConfirmPowerUp;
          phaseSince = now;
        } else {
          finish();
        }
        break;

      case Phase::ConfirmPowerUp:
        if (!sample.power || !sample.up || sample.down) {
          finish();
        } else if (elapsed(now, phaseSince, POWER_UP_HOLD_MS)) {
          sdRecoveryLatched = true;
          sequenceSince = now;
          phase = Phase::AwaitNeutral;
          phaseSince = now;
        }
        break;

      case Phase::AwaitNeutral:
        if (!sample.power || elapsed(now, sequenceSince, SECOND_STAGE_TIMEOUT_MS)) {
          finish();
        } else if (!sample.up && !sample.down) {
          phase = Phase::ConfirmNeutral;
          phaseSince = now;
        } else if (sample.down) {
          // A direct Up-to-Down transition is too easy to trigger through ADC
          // settling. Require an observable all-released gap.
          finish();
        }
        break;

      case Phase::ConfirmNeutral:
        if (!sample.power || elapsed(now, sequenceSince, SECOND_STAGE_TIMEOUT_MS)) {
          finish();
        } else if (sample.up || sample.down) {
          phase = Phase::AwaitNeutral;
          phaseSince = now;
        } else if (elapsed(now, phaseSince, NEUTRAL_HOLD_MS)) {
          phase = Phase::AwaitPowerDown;
          phaseSince = now;
        }
        break;

      case Phase::AwaitPowerDown:
        if (!sample.power || elapsed(now, sequenceSince, SECOND_STAGE_TIMEOUT_MS)) {
          finish();
        } else if (sample.up) {
          finish();
        } else if (sample.down) {
          phase = Phase::ConfirmPowerDown;
          phaseSince = now;
        }
        break;

      case Phase::ConfirmPowerDown:
        if (!sample.power || sample.up || !sample.down ||
            elapsed(now, sequenceSince, SECOND_STAGE_TIMEOUT_MS)) {
          finish();
        } else if (elapsed(now, phaseSince, POWER_DOWN_HOLD_MS)) {
          partitionRollback = true;
          finish();
        }
        break;

      case Phase::Finished:
        break;
    }
    return current();
  }

  constexpr Phase currentPhase() const { return phase; }

 private:
  constexpr void finish() { phase = Phase::Finished; }

  constexpr Result current() const {
    return {phase == Phase::Finished, sdRecoveryLatched, partitionRollback};
  }

  Phase phase = Phase::AwaitPowerUp;
  uint32_t phaseSince = 0;
  uint32_t sequenceSince = 0;
  bool sdRecoveryLatched = false;
  bool partitionRollback = false;
};

}  // namespace xtinct::boot_recovery
