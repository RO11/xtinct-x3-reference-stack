#pragma once

#include <cstdint>

// Sleep-screen refresh policy is deliberately separate from the reader's page
// cadence.  The UC8253 X3 driver turns this one requested condition pass into a
// calibrated sequence: FULL clean base -> NORMAL condition -> FAST baseline
// settle.  displayGrayscaleBase then adds the OEM pre-BW-mid pass and the final
// two-plane gray waveform.  More NORMAL/FULL repeats were tried upstream and
// are not a supported gray-quality control; they add flashes/charge, consume
// battery, and can enlarge border/gray artifacts.
namespace SleepScreenRefreshPolicy {

inline constexpr uint8_t X3_VALIDATED_POST_CONDITION_PASSES = 1;
inline constexpr uint8_t X3_MAX_SAFE_POST_CONDITION_PASSES = 1;

static_assert(X3_VALIDATED_POST_CONDITION_PASSES == X3_MAX_SAFE_POST_CONDITION_PASSES,
              "Sleep image must use the maximum hardware-validated condition count");

}  // namespace SleepScreenRefreshPolicy
