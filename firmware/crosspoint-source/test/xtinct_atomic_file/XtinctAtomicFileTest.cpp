#include <gtest/gtest.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "src/util/XtinctAtomicFile.h"
#include "src/util/XtinctNetworkPersistence.h"

namespace {

using xtinct::atomic_file::Result;

struct FakeOps {
  std::map<std::string, std::string> files;
  int failOperation = -1;
  int operations = 0;

  bool exists(const char* path) const { return files.count(path) != 0; }

  bool remove(const char* path) {
    if (operations++ == failOperation) return false;
    return files.erase(path) == 1;
  }

  bool rename(const char* source, const char* destination) {
    if (operations++ == failOperation) return false;
    const auto found = files.find(source);
    if (found == files.end() || files.count(destination) != 0) return false;
    files.emplace(destination, found->second);
    files.erase(found);
    return true;
  }
};

constexpr char FINAL[] = "/card";
constexpr char TEMP[] = "/card.tmp";
constexpr char BACKUP[] = "/card.bak";

TEST(XtinctAtomicFile, RecoversEveryPowerCutStateWithoutChoosingUncommittedTemp) {
  struct Case {
    std::vector<std::pair<std::string, std::string>> initial;
    bool finalExpected;
    const char* bytes;
  };
  const Case cases[] = {
      {{{FINAL, "old"}}, true, "old"},
      {{{FINAL, "new"}, {BACKUP, "old"}}, true, "new"},
      {{{FINAL, "old"}, {TEMP, "new"}}, true, "old"},
      {{{BACKUP, "old"}, {TEMP, "new"}}, true, "old"},
      {{{BACKUP, "old"}}, true, "old"},
      {{{TEMP, "new"}}, false, ""},
      {{}, false, ""},
  };
  for (const auto& test : cases) {
    FakeOps ops;
    ops.files.insert(test.initial.begin(), test.initial.end());
    EXPECT_EQ(xtinct::atomic_file::recover(ops, FINAL, TEMP, BACKUP), Result::Ok);
    EXPECT_EQ(ops.exists(FINAL), test.finalExpected);
    if (test.finalExpected) EXPECT_EQ(ops.files[FINAL], test.bytes);
    EXPECT_FALSE(ops.exists(TEMP));
    EXPECT_FALSE(ops.exists(BACKUP));
  }
}

TEST(XtinctAtomicFile, ReportsBackupRestoreFailureAndPreservesBothCopies) {
  FakeOps ops;
  ops.files = {{BACKUP, "old"}, {TEMP, "new"}};
  ops.failOperation = 0;
  EXPECT_EQ(xtinct::atomic_file::recover(ops, FINAL, TEMP, BACKUP), Result::RestoreBackupFailed);
  EXPECT_EQ(ops.files[BACKUP], "old");
  EXPECT_EQ(ops.files[TEMP], "new");
  EXPECT_FALSE(ops.exists(FINAL));
}

TEST(XtinctAtomicFile, PromotionFailureDistinguishesSuccessfulAndFailedRestore) {
  FakeOps restored;
  restored.files = {{FINAL, "old"}, {TEMP, "new"}};
  restored.failOperation = 1;  // temp -> final
  bool previous = false;
  EXPECT_EQ(xtinct::atomic_file::promoteRetainingBackup(restored, TEMP, FINAL, BACKUP, previous),
            Result::PromoteFailedRestored);
  EXPECT_TRUE(previous);
  EXPECT_EQ(restored.files[FINAL], "old");
  EXPECT_EQ(restored.files[TEMP], "new");
  EXPECT_FALSE(restored.exists(BACKUP));

  FakeOps stranded;
  stranded.files = {{FINAL, "old"}, {TEMP, "new"}};
  // Fail temp -> final and then backup -> final. FakeOps supports one injected
  // operation, so make destination final appear occupied after the first fail.
  struct TwoFailureOps : FakeOps {
    bool rename(const char* source, const char* destination) {
      if (operations == 1 || operations == 2) {
        ++operations;
        return false;
      }
      return FakeOps::rename(source, destination);
    }
  } two;
  two.files = stranded.files;
  previous = false;
  EXPECT_EQ(xtinct::atomic_file::promoteRetainingBackup(two, TEMP, FINAL, BACKUP, previous),
            Result::PromoteFailedRestoreFailed);
  EXPECT_EQ(two.files[BACKUP], "old");
  EXPECT_EQ(two.files[TEMP], "new");
  EXPECT_FALSE(two.exists(FINAL));
}

TEST(XtinctAtomicFile, RollbackParksReplacementBeforeRestoringLastGoodBackup) {
  FakeOps ops;
  ops.files = {{FINAL, "new"}, {BACKUP, "old"}};
  EXPECT_EQ(xtinct::atomic_file::rollback(ops, FINAL, TEMP, BACKUP, true), Result::Ok);
  EXPECT_EQ(ops.files[FINAL], "old");
  EXPECT_FALSE(ops.exists(TEMP));
  EXPECT_FALSE(ops.exists(BACKUP));
}

TEST(XtinctAtomicFile, FailedRollbackRestoreNeverErasesEitherVersion) {
  FakeOps ops;
  ops.files = {{FINAL, "new"}, {BACKUP, "old"}};
  ops.failOperation = 1;  // backup -> final, after parking final -> temp
  EXPECT_EQ(xtinct::atomic_file::rollback(ops, FINAL, TEMP, BACKUP, true),
            Result::RollbackRestoreFailed);
  EXPECT_FALSE(ops.exists(FINAL));
  EXPECT_EQ(ops.files[BACKUP], "old");
  EXPECT_EQ(ops.files[TEMP], "new");

  ops.failOperation = -1;
  EXPECT_EQ(xtinct::atomic_file::rollback(ops, FINAL, TEMP, BACKUP, true), Result::Ok);
  EXPECT_EQ(ops.files[FINAL], "old");
  EXPECT_FALSE(ops.exists(TEMP));
  EXPECT_FALSE(ops.exists(BACKUP));
}

TEST(XtinctAtomicFile, CommitChecksTemporaryThenBackupCleanup) {
  FakeOps tempFailure;
  tempFailure.files = {{FINAL, "new"}, {TEMP, "stale"}, {BACKUP, "old"}};
  tempFailure.failOperation = 0;
  EXPECT_EQ(xtinct::atomic_file::commit(tempFailure, FINAL, TEMP, BACKUP),
            Result::RemoveTemporaryFailed);
  EXPECT_EQ(tempFailure.files[BACKUP], "old");

  FakeOps backupFailure;
  backupFailure.files = {{FINAL, "new"}, {BACKUP, "old"}};
  backupFailure.failOperation = 0;
  EXPECT_EQ(xtinct::atomic_file::commit(backupFailure, FINAL, TEMP, BACKUP),
            Result::RemoveBackupFailed);
  EXPECT_EQ(backupFailure.files[FINAL], "new");
  EXPECT_EQ(backupFailure.files[BACKUP], "old");
}

TEST(XtinctNetworkPersistence, RejectsOversizedProtectedFilesBeforeAllocation) {
  using xtinct::network_persistence::boundedFileSizeAllowed;
  EXPECT_TRUE(boundedFileSizeAllowed(8192, 8192));
  EXPECT_FALSE(boundedFileSizeAllowed(8193, 8192));
  EXPECT_FALSE(boundedFileSizeAllowed(UINT64_MAX, 8192));
  EXPECT_FALSE(boundedFileSizeAllowed(0, 8192));
  EXPECT_TRUE(boundedFileSizeAllowed(0, 8192, true));
}

TEST(XtinctNetworkPersistence, UnknownManifestIdentityFailsClosed) {
  using xtinct::network_persistence::V1RecoveryDirection;
  using xtinct::network_persistence::v1RecoveryDirection;
  EXPECT_EQ(v1RecoveryDirection(true, true, true, false), V1RecoveryDirection::FinishCommit);
  EXPECT_EQ(v1RecoveryDirection(true, false, true, true), V1RecoveryDirection::RollBack);
  EXPECT_EQ(v1RecoveryDirection(false, false, true, false), V1RecoveryDirection::RollBack);
  EXPECT_EQ(v1RecoveryDirection(true, false, false, false), V1RecoveryDirection::FailClosed);
  EXPECT_EQ(v1RecoveryDirection(true, false, true, false), V1RecoveryDirection::FailClosed);
}

TEST(XtinctNetworkPersistence, V1RollbackConsumesOnlyJournaledIdentities) {
  using xtinct::network_persistence::v1RollbackStateAllowed;
  // A newly created card may be removed only when its final is the exact
  // target. A third identity is preserved by refusing rollback.
  EXPECT_TRUE(v1RollbackStateAllowed(false, true, false, true,
                                     false, false, false, false));
  EXPECT_FALSE(v1RollbackStateAllowed(false, true, false, false,
                                      false, false, false, false));
  // Retrying after an earlier rollback consumed the backup is valid when the
  // old final is already restored.
  EXPECT_TRUE(v1RollbackStateAllowed(true, true, true, false,
                                     false, false, false, false));
  EXPECT_FALSE(v1RollbackStateAllowed(true, true, false, true,
                                      false, false, false, false));
  EXPECT_TRUE(v1RollbackStateAllowed(true, false, false, false,
                                     true, true, true, true));
}

TEST(XtinctNetworkPersistence, SleepRecoveryIsIdempotentAcrossSettingsAndCleanupCuts) {
  using xtinct::network_persistence::SleepRecoveryDirection;
  using xtinct::network_persistence::sleepRecoveryDirection;
  // Journal cleanup can fail after the backup has already been removed. The
  // target final plus durable CUSTOM setting still completes the commit.
  EXPECT_EQ(sleepRecoveryDirection(true, true, true, false, true,
                                   false, false, false, false),
            SleepRecoveryDirection::FinishCommit);
  EXPECT_EQ(sleepRecoveryDirection(true, true, true, false, true,
                                   false, false, true, true),
            SleepRecoveryDirection::FinishCommit);
  // Before the setting commits, the exact old backup is required.
  EXPECT_EQ(sleepRecoveryDirection(true, false, true, false, true,
                                   false, false, true, true),
            SleepRecoveryDirection::RollBack);
  EXPECT_EQ(sleepRecoveryDirection(true, false, true, false, true,
                                   false, false, false, false),
            SleepRecoveryDirection::FailClosed);
  // A prior rollback may already have restored the old final and consumed its
  // backup; settings restoration remains safely retryable.
  EXPECT_EQ(sleepRecoveryDirection(true, true, true, true, false,
                                   false, false, false, false),
            SleepRecoveryDirection::RollBack);
  EXPECT_EQ(sleepRecoveryDirection(false, false, true, false, true,
                                   false, false, false, false),
            SleepRecoveryDirection::RollBack);
  EXPECT_EQ(sleepRecoveryDirection(false, false, false, false, false,
                                   true, false, false, false),
            SleepRecoveryDirection::FailClosed);
}

TEST(XtinctAtomicFile, RollbackRetryDoesNotRequireAnAlreadyConsumedBackup) {
  FakeOps ops;
  ops.files = {{FINAL, "old"}};
  EXPECT_EQ(xtinct::atomic_file::rollback(ops, FINAL, TEMP, BACKUP, true), Result::Ok);
  EXPECT_EQ(ops.files[FINAL], "old");
  EXPECT_FALSE(ops.exists(TEMP));
  EXPECT_FALSE(ops.exists(BACKUP));
}

TEST(XtinctAtomicFile, ManifestIsTheCommitMarkerAcrossEveryV1PowerCut) {
  constexpr char MANIFEST[] = "/manifest";
  constexpr char MANIFEST_TMP[] = "/manifest.tmp";
  constexpr char MANIFEST_BAK[] = "/manifest.bak";
  constexpr char CARD0[] = "/card0";
  constexpr char CARD0_TMP[] = "/card0.tmp";
  constexpr char CARD0_BAK[] = "/card0.bak";
  constexpr char CARD1[] = "/card1";
  constexpr char CARD1_TMP[] = "/card1.tmp";
  constexpr char CARD1_BAK[] = "/card1.bak";
  constexpr char WITHDRAWN[] = "/withdrawn";
  constexpr char JOURNAL[] = "/transaction";
  constexpr char ETAG[] = "/etag";
  constexpr char OLD_REPORT[] = "/reports/old";
  constexpr char NEW_REPORT[] = "/reports/new";

  for (int cut = 0; cut <= 7; ++cut) {
    FakeOps ops;
    ops.files = {{MANIFEST, "old-manifest"}, {CARD0, "old-card0"}, {CARD1, "old-card1"},
                 {WITHDRAWN, "withdrawn-card"}, {ETAG, "old-etag"}, {OLD_REPORT, "old-report"},
                 {MANIFEST_TMP, "new-manifest"}, {CARD0_TMP, "new-card0"},
                 {CARD1_TMP, "new-card1"}, {JOURNAL, "plan"}, {NEW_REPORT, "new-report"}};
    bool previous = false;
    if (cut >= 1) EXPECT_EQ(xtinct::atomic_file::promoteRetainingBackup(
                                ops, CARD0_TMP, CARD0, CARD0_BAK, previous), Result::Ok);
    if (cut >= 2) EXPECT_EQ(xtinct::atomic_file::promoteRetainingBackup(
                                ops, CARD1_TMP, CARD1, CARD1_BAK, previous), Result::Ok);
    if (cut >= 3) EXPECT_EQ(xtinct::atomic_file::promoteRetainingBackup(
                                ops, MANIFEST_TMP, MANIFEST, MANIFEST_BAK, previous), Result::Ok);
    if (cut >= 4) ops.files[ETAG] = "new-etag";
    if (cut >= 5) EXPECT_TRUE(ops.remove(WITHDRAWN));
    if (cut >= 6) {
      EXPECT_EQ(xtinct::atomic_file::commit(ops, CARD0, CARD0_TMP, CARD0_BAK), Result::Ok);
      EXPECT_EQ(xtinct::atomic_file::commit(ops, CARD1, CARD1_TMP, CARD1_BAK), Result::Ok);
    }
    if (cut >= 7) EXPECT_EQ(xtinct::atomic_file::commit(
                                ops, MANIFEST, MANIFEST_TMP, MANIFEST_BAK), Result::Ok);

    // This is the bounded journal recovery decision used by the firmware: the
    // exact target manifest means commit; every earlier cut means rollback.
    const bool targetManifestCommitted =
        ops.exists(MANIFEST) && ops.files[MANIFEST] == "new-manifest";
    if (targetManifestCommitted) {
      EXPECT_EQ(ops.files[CARD0], "new-card0");
      EXPECT_EQ(ops.files[CARD1], "new-card1");
      EXPECT_EQ(xtinct::atomic_file::commit(ops, CARD0, CARD0_TMP, CARD0_BAK), Result::Ok);
      EXPECT_EQ(xtinct::atomic_file::commit(ops, CARD1, CARD1_TMP, CARD1_BAK), Result::Ok);
      EXPECT_EQ(xtinct::atomic_file::commit(ops, MANIFEST, MANIFEST_TMP, MANIFEST_BAK), Result::Ok);
      ops.files[ETAG] = "new-etag";
      if (ops.exists(WITHDRAWN)) EXPECT_TRUE(ops.remove(WITHDRAWN));
    } else {
      EXPECT_EQ(xtinct::atomic_file::rollback(ops, CARD0, CARD0_TMP, CARD0_BAK, true), Result::Ok);
      EXPECT_EQ(xtinct::atomic_file::rollback(ops, CARD1, CARD1_TMP, CARD1_BAK, true), Result::Ok);
      EXPECT_EQ(xtinct::atomic_file::rollback(
                    ops, MANIFEST, MANIFEST_TMP, MANIFEST_BAK, true), Result::Ok);
    }
    EXPECT_TRUE(ops.remove(JOURNAL));

    EXPECT_EQ(ops.files[MANIFEST], targetManifestCommitted ? "new-manifest" : "old-manifest");
    EXPECT_EQ(ops.files[CARD0], targetManifestCommitted ? "new-card0" : "old-card0");
    EXPECT_EQ(ops.files[CARD1], targetManifestCommitted ? "new-card1" : "old-card1");
    EXPECT_EQ(ops.files[ETAG], targetManifestCommitted ? "new-etag" : "old-etag");
    EXPECT_EQ(ops.exists(WITHDRAWN), !targetManifestCommitted);
    // New revision reports are inert orphans before their card commits. The
    // last offline-good report is never removed by either recovery branch.
    EXPECT_EQ(ops.files[OLD_REPORT], "old-report");
    EXPECT_EQ(ops.files[NEW_REPORT], "new-report");
  }
}

}  // namespace
