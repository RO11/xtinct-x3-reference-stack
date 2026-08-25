#pragma once

#include <cstdint>

namespace xtinct::atomic_file {

// The filesystem adapter used here is intentionally tiny so the exact FAT
// rename/remove protocol can be fault-tested on a host without SdFat or
// Arduino. An adapter provides exists(path), remove(path), and rename(a, b).
enum class Result : uint8_t {
  Ok,
  InvalidPath,
  MissingTemporary,
  MissingFinal,
  UnexpectedBackup,
  RemoveTemporaryFailed,
  RemoveBackupFailed,
  MoveOriginalToBackupFailed,
  PromoteFailedNoPrevious,
  PromoteFailedRestored,
  PromoteFailedRestoreFailed,
  RestoreBackupFailed,
  ParkReplacementFailed,
  RollbackRestoreFailed,
  PreviousFinalMissing,
  RemoveReplacementFailed,
};

constexpr bool succeeded(const Result result) { return result == Result::Ok; }

template <typename Ops>
Result recover(Ops& ops, const char* finalPath, const char* temporaryPath, const char* backupPath) {
  if (!finalPath || !temporaryPath || !backupPath) return Result::InvalidPath;

  const bool finalExists = ops.exists(finalPath);
  const bool backupExists = ops.exists(backupPath);
  const bool temporaryExists = ops.exists(temporaryPath);

  if (finalExists) {
    // A final is a completed rename. Outside an active multi-file journal, any
    // remaining temporary/backup is stale. Keep the backup until temporary
    // cleanup succeeds so a failed cleanup never reduces redundancy.
    if (temporaryExists && !ops.remove(temporaryPath)) return Result::RemoveTemporaryFailed;
    if (backupExists && !ops.remove(backupPath)) return Result::RemoveBackupFailed;
    return Result::Ok;
  }

  if (backupExists) {
    // The power cut happened after final -> backup but before temp -> final.
    // Restore the last committed bytes first and only then discard the temp.
    if (!ops.rename(backupPath, finalPath)) return Result::RestoreBackupFailed;
    if (temporaryExists && !ops.remove(temporaryPath)) return Result::RemoveTemporaryFailed;
    return Result::Ok;
  }

  // A lone temp was never published.
  if (temporaryExists && !ops.remove(temporaryPath)) return Result::RemoveTemporaryFailed;
  return Result::Ok;
}

// Publishes a durable temp but deliberately retains the previous final in
// backup. The caller must validate the new final, then call commit() or
// rollback(). This is also the primitive used by the bounded V1 journal.
template <typename Ops>
Result promoteRetainingBackup(Ops& ops, const char* temporaryPath, const char* finalPath,
                              const char* backupPath, bool& previousExisted) {
  previousExisted = false;
  if (!finalPath || !temporaryPath || !backupPath) return Result::InvalidPath;
  if (!ops.exists(temporaryPath)) return Result::MissingTemporary;
  if (ops.exists(backupPath)) return Result::UnexpectedBackup;

  previousExisted = ops.exists(finalPath);
  if (previousExisted && !ops.rename(finalPath, backupPath)) {
    return Result::MoveOriginalToBackupFailed;
  }
  if (ops.rename(temporaryPath, finalPath)) return Result::Ok;

  if (!previousExisted) return Result::PromoteFailedNoPrevious;
  if (!ops.rename(backupPath, finalPath)) return Result::PromoteFailedRestoreFailed;
  return Result::PromoteFailedRestored;
}

template <typename Ops>
Result commit(Ops& ops, const char* finalPath, const char* temporaryPath, const char* backupPath) {
  if (!finalPath || !temporaryPath || !backupPath) return Result::InvalidPath;
  if (!ops.exists(finalPath)) return Result::MissingFinal;
  if (ops.exists(temporaryPath) && !ops.remove(temporaryPath)) return Result::RemoveTemporaryFailed;
  if (ops.exists(backupPath) && !ops.remove(backupPath)) return Result::RemoveBackupFailed;
  return Result::Ok;
}

// Reverts a retained-backup promotion. If a previous final existed, the new
// final is first parked at temp; therefore a failed backup restore still
// leaves both byte sets recoverable for the next deterministic retry.
template <typename Ops>
Result rollback(Ops& ops, const char* finalPath, const char* temporaryPath, const char* backupPath,
                const bool previousExisted) {
  if (!finalPath || !temporaryPath || !backupPath) return Result::InvalidPath;

  if (!previousExisted) {
    if (ops.exists(backupPath)) return Result::UnexpectedBackup;
    if (ops.exists(temporaryPath) && !ops.remove(temporaryPath)) return Result::RemoveTemporaryFailed;
    if (ops.exists(finalPath) && !ops.remove(finalPath)) return Result::RemoveReplacementFailed;
    return Result::Ok;
  }

  if (!ops.exists(backupPath)) {
    // Either promotion never began or an earlier rollback already restored the
    // previous final. In both cases the previous final must still be present.
    if (!ops.exists(finalPath)) return Result::PreviousFinalMissing;
    if (ops.exists(temporaryPath) && !ops.remove(temporaryPath)) return Result::RemoveTemporaryFailed;
    return Result::Ok;
  }

  if (ops.exists(temporaryPath) && !ops.remove(temporaryPath)) return Result::RemoveTemporaryFailed;
  if (ops.exists(finalPath) && !ops.rename(finalPath, temporaryPath)) return Result::ParkReplacementFailed;
  if (!ops.rename(backupPath, finalPath)) return Result::RollbackRestoreFailed;
  if (ops.exists(temporaryPath) && !ops.remove(temporaryPath)) return Result::RemoveTemporaryFailed;
  return Result::Ok;
}

}  // namespace xtinct::atomic_file
