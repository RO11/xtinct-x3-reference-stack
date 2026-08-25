#pragma once

#include <cstdint>

namespace xtinct::daily_cards {

// XTINCT's Daily Cards contract is anchored to Australia/Brisbane (UTC+10,
// no daylight-saving transition). CrossPoint stores offsets as biased
// quarter-hours: 48 is UTC, therefore Brisbane is 88.
constexpr uint8_t BRISBANE_UTC_OFFSET_QUARTER_HOURS_BIASED = 88;

enum class StoredStateStatus : uint8_t { Missing, Valid, Invalid };

// A corrupt policy file is fail-closed: manual Refresh and scheduled wakes
// still work, but an ordinary open must not start an unbounded retry loop.
constexpr bool shouldClaimAutomaticSync(const bool currentDayKnown,
                                        const StoredStateStatus stateStatus,
                                        const uint32_t currentDay,
                                        const uint32_t attemptDay,
                                        const uint32_t freshDay) {
  if (!currentDayKnown || stateStatus == StoredStateStatus::Invalid) return false;
  return stateStatus == StoredStateStatus::Missing ||
         (attemptDay != currentDay && freshDay != currentDay);
}

// V2's result enum can report success at its bounded page cap. Only the
// explicit complete-marker query may satisfy the second half of this gate.
constexpr bool canStampFresh(const bool v1Complete, const bool v2CompleteToday) {
  return v1Complete && v2CompleteToday;
}

// Clear a previous combined-success proof before any new network attempt.
// A failed or partial replacement attempt therefore cannot inherit freshness
// from an earlier success on the same day.
constexpr uint32_t freshDayAfterAttempt(const bool complete, const uint32_t currentDay) {
  return complete ? currentDay : 0;
}

}  // namespace xtinct::daily_cards
