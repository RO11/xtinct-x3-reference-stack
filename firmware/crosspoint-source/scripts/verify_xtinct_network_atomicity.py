#!/usr/bin/env python3
"""Fail-closed source-order gate for XTINCT V1/V2 network persistence."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class GateError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def read(relative: str, root: Path = ROOT) -> str:
    path = root / relative
    require(path.is_file(), f"missing source: {relative}")
    return path.read_text(encoding="utf-8")


def function(source: str, start: str, end: str) -> str:
    begin = source.find(start)
    require(begin >= 0, f"missing function start: {start}")
    finish = source.find(end, begin + len(start))
    require(finish > begin, f"missing function end marker after: {start}")
    return source[begin:finish]


def ordered(source: str, labels: list[tuple[str, str]]) -> None:
    cursor = -1
    for label, token in labels:
        position = source.find(token, cursor + 1)
        require(position > cursor, f"missing/out-of-order {label}: {token}")
        cursor = position


def verify_v1_sync_transaction_order(feed_sync: str) -> None:
    ordered(feed_sync, [
        ("transaction recovery before network/config", "recoverPendingTransaction()"),
        ("validated raw manifest staging", "stageAtomicFile(MANIFEST_PATH"),
        ("manifest RAM release", "body.release();"),
        ("all child staging", "downloadAndStageChangedCards"),
        ("durable journal", "writeTransactionPlan"),
        ("card promotion", "promoteStagedCards"),
        ("manifest-last promotion", "promoteAtomicFile(stagedManifestPath, MANIFEST_PATH"),
        ("committed cleanup", "finishCommittedTransaction"),
    ])


def verify_v1_sync_transaction_order_mutation(feed_sync: str) -> None:
    journal = "writeTransactionPlan"
    promotion = "promoteStagedCards"
    journal_at = feed_sync.find(journal)
    promotion_at = feed_sync.find(promotion, journal_at + len(journal))
    require(0 <= journal_at < promotion_at,
            "V1 transaction mutation fixture could not isolate journal/promotion calls")
    mutated = (
        feed_sync[:journal_at] + promotion +
        feed_sync[journal_at + len(journal):promotion_at] + journal +
        feed_sync[promotion_at + len(promotion):]
    )
    try:
        verify_v1_sync_transaction_order(mutated)
    except GateError:
        return
    raise GateError("V1 journal-before-promotion mutation was not rejected")


def verify(root: Path = ROOT) -> None:
    root = root.resolve()
    feed = read("src/network/XtinctFeedClient.cpp", root)
    sync = read("src/network/XtinctSyncClient.cpp", root)
    helper = read("src/util/XtinctAtomicFile.h", root)
    persistence = read("src/util/XtinctNetworkPersistence.h", root)
    tests = read("test/xtinct_atomic_file/XtinctAtomicFileTest.cpp", root)

    for name, source in (("V1 feed", feed), ("V2 sync", sync)):
        require("Storage.readFile(" not in source, f"{name} regained an unbounded SD String read")
        require("Storage.listFiles(" not in source, f"{name} regained a throwing directory vector")
    require(".resize(" not in sync, "V2 sync regained a throwing resize path")
    require("std::string output;" not in sync,
            "V2 metadata serialization regained a throwing string accumulator")

    report = function(feed, "XtinctFeedClient::SyncResult XtinctFeedClient::downloadAndCacheReport",
                      "XtinctFeedClient::SyncResult XtinctFeedClient::downloadAndStageChangedCards")
    ordered(report, [
        ("durable report close", "finishDurableWrite"),
        ("captured response completion", "const bool responseComplete"),
        ("report TLS release", "http.end();"),
        ("report SHA finalization", "mbedtls_sha256_finish"),
        ("report promotion", "promoteAtomicFile"),
        ("report full readback", "validateReportFile(finalPath"),
        ("report backup commit", "commitAtomicFile(finalPath)"),
    ])

    artifact = function(sync, "XtinctSyncClient::SyncResult downloadArtifact",
                        "bool activateSleepScreen")
    ordered(artifact, [
        ("durable artifact close", "finishDurableWrite"),
        ("captured response completion", "const bool responseComplete"),
        ("artifact TLS release", "http.end();"),
        ("artifact SHA finalization", "mbedtls_sha256_finish"),
        ("artifact promotion", "promoteAtomic"),
        ("artifact full readback", "validateArtifactFile(item, finalPath)"),
        ("artifact backup commit", "commitAtomic(finalPath)"),
    ])

    feed_sync = function(feed, "XtinctFeedClient::SyncResult XtinctFeedClient::sync()",
                         "bool parseCardObject")
    verify_v1_sync_transaction_order(feed_sync)
    verify_v1_sync_transaction_order_mutation(feed_sync)
    require("pruneCardsMissingFromManifest" not in feed,
            "withdrawn cards can again be pruned before manifest publication")

    finish = function(feed, "bool XtinctFeedClient::finishCommittedTransaction",
                      "bool XtinctFeedClient::rollBackTransaction")
    ordered(finish, [
        ("target manifest validation", "fileMatchesSha256(MANIFEST_PATH"),
        ("ETag publication", "writeAtomic(ETAG_PATH"),
        ("card backup cleanup", "commitAtomicFile(finalPath)"),
        ("post-commit withdrawal pruning", "Storage.remove(finalPath)"),
        ("manifest backup cleanup", "commitAtomicFile(MANIFEST_PATH)"),
        ("report orphan sweep", "sweepReportCache()"),
        ("journal removal last", "Storage.remove(TRANSACTION_PATH)"),
    ])
    rollback = function(feed, "bool XtinctFeedClient::rollBackTransaction",
                        "bool XtinctFeedClient::recoverPendingTransaction")
    require("Refusing rollback of unknown card identity" in rollback,
            "V1 rollback no longer fails closed on foreign card bytes")
    require("v1RollbackStateAllowed" in rollback,
            "V1 rollback no longer shares the pure exact-identity state policy")
    ordered(rollback, [
        ("all-card preflight", "Preflight every changed card"),
        ("card rollback", "rollbackAtomicFile(finalPath"),
        ("manifest restored last", "Restore the old manifest last"),
        ("manifest rollback", "rollbackAtomicFile(MANIFEST_PATH"),
        ("rollback journal removal", "Storage.remove(TRANSACTION_PATH)"),
    ])
    require('object.size() != 11' in feed and "MAX_TRANSACTION_BYTES = 2048" in feed,
            "bounded strict V1 journal parser drifted")

    sleep = function(sync, "bool activateSleepScreen", "bool collectUnreferencedArtifacts")
    require("Storage.remove(finalPath)" not in sleep,
            "sleep rollback can delete the replacement before restoring the last good backup")
    ordered(sleep, [
        ("durable sleep journal", "writeSleepActivationPlan"),
        ("sleep promotion", "promoteAtomic"),
        ("settings save", "SETTINGS.saveToFile()"),
        ("settings rollback", "rollbackAtomic(finalPath"),
    ])
    sleep_recovery = function(sync, "bool recoverSleepScreenActivation", "XtinctSyncClient::SyncResult downloadArtifact")
    require("Refusing sleep activation recovery with an unknown file identity" in sleep_recovery and
            "sleepRecoveryDirection" in sleep_recovery and
            "commitAtomic(finalPath) && removeSleepActivationPlan()" in sleep_recovery and
            "rollbackAtomic(finalPath, plan.previousExisted)" in sleep_recovery,
            "sleep journal recovery lost exact identity/commit/rollback handling")
    v2_sync = function(sync, "XtinctSyncClient::SyncResult XtinctSyncClient::sync()",
                       "const char* XtinctSyncClient::resultMessage")
    ordered(v2_sync, [
        ("sleep recovery before configuration/network", "recoverSleepScreenActivation()"),
        ("configuration check", "XTINCT_FEED_CONFIG.hasReadToken()"),
    ])

    gc = function(sync, "bool collectUnreferencedArtifacts", "bool readSmallFileBuffer")
    require("char values[xtinct::sync_v2::MAX_INBOX_ITEMS][65]" in gc and
            "makeUniqueNoThrow<ReferencedDigestSet>()" in gc,
            "artifact GC lost its fixed digest set")
    require("First pass proves the artifact directory is bounded before any deletion" in gc,
            "artifact GC lost its pre-delete completeness pass")
    require("Artifact GC skipped: inbox metadata scan incomplete or over bound" in gc,
            "artifact GC lost explicit fail-closed metadata handling")
    metadata_recovery = function(sync, "bool recoverInboxMetadataSidecars", "bool promoteAtomic")
    ordered(metadata_recovery, [
        ("bounded sidecar collection", "makeUniqueNoThrow<RecoverySet>()"),
        ("directory close before mutation", "directory.close();"),
        ("sidecar recovery after close", "recoverAtomicFile(finalPath)"),
    ])

    require("PromoteFailedRestoreFailed" in helper and "RollbackRestoreFailed" in helper,
            "atomic helper no longer distinguishes restore failure")
    require("boundedFileSizeAllowed" in persistence and "V1RecoveryDirection::FailClosed" in persistence and
            "SleepRecoveryDirection::FinishCommit" in persistence,
            "bounded file/manifest identity policy helper drifted")
    require("ManifestIsTheCommitMarkerAcrossEveryV1PowerCut" in tests and
            "FailedRollbackRestoreNeverErasesEitherVersion" in tests and
            "RejectsOversizedProtectedFilesBeforeAllocation" in tests and
            "UnknownManifestIdentityFailsClosed" in tests and
            "V1RollbackConsumesOnlyJournaledIdentities" in tests and
            "SleepRecoveryIsIdempotentAcrossSettingsAndCleanupCuts" in tests,
            "atomic cut/fault regressions are missing")



def main() -> None:
    verify(ROOT)
    print("XTINCT_NETWORK_ATOMICITY_OK")


if __name__ == "__main__":
    try:
        main()
    except (GateError, OSError, UnicodeError) as error:
        raise SystemExit(f"XTINCT_NETWORK_ATOMICITY_FAILED: {error}")
