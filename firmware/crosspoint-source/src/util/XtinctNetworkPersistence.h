#pragma once

#include <cstdint>

namespace xtinct::network_persistence {

constexpr bool boundedFileSizeAllowed(const uint64_t actualBytes, const uint64_t maximumBytes,
                                      const bool allowEmpty = false) {
  return actualBytes <= maximumBytes && (allowEmpty || actualBytes != 0);
}

enum class V1RecoveryDirection : uint8_t { FinishCommit, RollBack, FailClosed };
enum class SleepRecoveryDirection : uint8_t { FinishCommit, RollBack, FailClosed };

// The exact target manifest is the durable commit marker. A missing manifest
// or the exact journaled previous manifest can be rolled back. Any third
// identity is foreign/corrupt and must be preserved for fail-closed recovery.
constexpr V1RecoveryDirection v1RecoveryDirection(const bool finalExists,
                                                   const bool targetMatches,
                                                   const bool previousExisted,
                                                   const bool previousMatches) {
  if (finalExists && targetMatches) return V1RecoveryDirection::FinishCommit;
  if (!finalExists || (previousExisted && previousMatches)) return V1RecoveryDirection::RollBack;
  return V1RecoveryDirection::FailClosed;
}

// A rollback may consume only the exact journaled target/previous identities.
// If a previous final existed, either that final or its retained backup must
// still be available. This makes retries idempotent after an earlier rollback
// has already consumed the backup.
constexpr bool v1RollbackStateAllowed(const bool previousExisted,
                                      const bool finalExists, const bool finalPrevious,
                                      const bool finalTarget, const bool temporaryExists,
                                      const bool temporaryTarget, const bool backupExists,
                                      const bool backupPrevious) {
  if ((finalPrevious && (!previousExisted || !finalExists)) ||
      (finalTarget && !finalExists) || (temporaryTarget && !temporaryExists) ||
      (backupPrevious && (!previousExisted || !backupExists))) {
    return false;
  }
  if ((finalExists && !finalPrevious && !finalTarget) ||
      (temporaryExists && !temporaryTarget) ||
      (backupExists && !backupPrevious)) {
    return false;
  }
  return !previousExisted || finalPrevious || backupPrevious;
}

// The sleep bitmap and its setting form one transaction. A target final plus
// a durable CUSTOM setting is the commit marker even if a prior recovery has
// already removed the backup. Otherwise rollback is permitted only while the
// exact previous bytes remain recoverable.
constexpr SleepRecoveryDirection sleepRecoveryDirection(
    const bool previousExisted, const bool settingsCommitted,
    const bool finalExists, const bool finalPrevious, const bool finalTarget,
    const bool temporaryExists, const bool temporaryTarget,
    const bool backupExists, const bool backupPrevious) {
  if ((finalPrevious && (!previousExisted || !finalExists)) ||
      (finalTarget && !finalExists) || (temporaryTarget && !temporaryExists) ||
      (backupPrevious && (!previousExisted || !backupExists)) ||
      (finalExists && !finalPrevious && !finalTarget) ||
      (temporaryExists && !temporaryTarget) ||
      (backupExists && !backupPrevious)) {
    return SleepRecoveryDirection::FailClosed;
  }
  if (finalTarget && settingsCommitted) return SleepRecoveryDirection::FinishCommit;
  if (previousExisted && !finalPrevious && !backupPrevious) {
    return SleepRecoveryDirection::FailClosed;
  }
  return SleepRecoveryDirection::RollBack;
}

static_assert(boundedFileSizeAllowed(1, 8192));
static_assert(!boundedFileSizeAllowed(8193, 8192));
static_assert(!boundedFileSizeAllowed(0, 8192));
static_assert(boundedFileSizeAllowed(0, 8192, true));
static_assert(v1RecoveryDirection(true, true, true, false) == V1RecoveryDirection::FinishCommit);
static_assert(v1RecoveryDirection(true, false, true, true) == V1RecoveryDirection::RollBack);
static_assert(v1RecoveryDirection(false, false, true, false) == V1RecoveryDirection::RollBack);
static_assert(v1RecoveryDirection(true, false, false, false) == V1RecoveryDirection::FailClosed);
static_assert(v1RollbackStateAllowed(true, true, true, false, true, true, false, false));
static_assert(v1RollbackStateAllowed(false, true, false, true, false, false, false, false));
static_assert(!v1RollbackStateAllowed(false, true, false, false, false, false, false, false));
static_assert(sleepRecoveryDirection(true, true, true, false, true, false, false, false, false) ==
              SleepRecoveryDirection::FinishCommit);
static_assert(sleepRecoveryDirection(true, false, true, false, true, false, false, true, true) ==
              SleepRecoveryDirection::RollBack);

}  // namespace xtinct::network_persistence
