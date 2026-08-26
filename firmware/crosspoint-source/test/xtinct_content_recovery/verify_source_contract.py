from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def section(source: str, start: str, end: str) -> str:
    begin = source.find(start)
    require(begin >= 0, f"missing section start: {start}")
    finish = source.find(end, begin + len(start))
    require(finish > begin, f"missing section end: {end}")
    return source[begin:finish]


def compact(source: str) -> str:
    return " ".join(source.split())


sync_header = (ROOT / "src/network/XtinctSyncClient.h").read_text(encoding="utf-8")
sync_source = (ROOT / "src/network/XtinctSyncClient.cpp").read_text(encoding="utf-8")
feed_source = (ROOT / "src/network/XtinctFeedClient.cpp").read_text(encoding="utf-8")
cards_source = (ROOT / "src/activities/home/DailyCardsActivity.cpp").read_text(encoding="utf-8")
inbox_source = (ROOT / "src/activities/home/InboxActivity.cpp").read_text(encoding="utf-8")
model_source = (ROOT / "tools/x3-simulator/web/network-model.js").read_text(encoding="utf-8")

hex_validator = compact(section(feed_source, "bool isLowerHex(", "bool isSafeRevision("))
require("return true;" in hex_validator, "lowercase hexadecimal validation no longer has a successful return")
require("remoteCardCount" not in hex_validator, "the fixed-slot manifest rule escaped into hexadecimal validation")

require("CATCH_UP_PENDING" in sync_header, "V2 result enum lacks the bounded catch-up state")
sync = compact(section(
    sync_source,
    "XtinctSyncClient::SyncResult XtinctSyncClient::sync()",
    "const char* XtinctSyncClient::resultMessage",
))
require(
    "finalResult = fullyCaughtUp ? (changed ? SyncResult::UPDATED : SyncResult::CURRENT) : SyncResult::CATCH_UP_PENDING;"
    in sync,
    "ten-page V2 exhaustion can still be reported as current or updated",
)
require(
    'case SyncResult::CATCH_UP_PENDING: return "more content waiting";' in compact(sync_source),
    "catch-up state lacks a user-visible status",
)

cards_retry = compact(section(cards_source, "bool isTransientFailure(const XtinctSyncClient::SyncResult", "void logHeapStage"))
require("SyncResult::CATCH_UP_PENDING" in cards_retry, "scheduled wakes do not retry bounded V2 catch-up")
cards_status = compact(section(cards_source, "const char* DailyCardsActivity::syncStatusText()", "void DailyCardsActivity::renderCard()"))
require(
    "v1SyncComplete(syncResult)" in cards_status
    and "inboxSyncResult != XtinctSyncClient::SyncResult::UPDATED" in cards_status
    and "inboxSyncResult != XtinctSyncClient::SyncResult::CURRENT" in cards_status
    and "XtinctSyncClient::resultMessage(inboxSyncResult)" in cards_status,
    "Daily Cards hides an incomplete V2 lane behind a successful V1 status",
)

manifest = section(
    feed_source,
    "bool XtinctFeedClient::parseManifest",
    "bool XtinctFeedClient::writeTransactionPlan",
)
require(
    "return remoteCardCount == TASK_COUNT;" in manifest,
    "a partial fixed-slot V1 manifest can still reach the pruning transaction",
)
card_download = section(
    feed_source,
    "XtinctFeedClient::SyncResult XtinctFeedClient::downloadAndStageChangedCards",
    "bool XtinctFeedClient::promoteStagedCards",
)
auth_check = card_download.find("if (status == 401 || status == 403) return SyncResult::UNAUTHORIZED;")
generic_failure = card_download.find("return body.limitExceeded() ? SyncResult::INVALID_DATA : SyncResult::NETWORK_ERROR;")
require(0 <= auth_check < generic_failure, "changed-card authorization errors are still mislabeled as network failures")

inbox_loop = section(inbox_source, "void InboxActivity::loop()", "void InboxActivity::render(")
paint_guard = inbox_loop.find("if (!requestUpdateAndWait())")
network_start = inbox_loop.find("runSync();")
require(0 <= paint_guard < network_start, "Inbox starts Wi-Fi/TLS before confirming its busy screen")
require("Refresh cancelled: display busy" in inbox_loop, "Inbox paint failure lacks a visible retry status")

scan = section(sync_source, "size_t scanInboxPage(", "bool loadFastFirstPage(")
require("bool overCapacity = false;" in scan, "Inbox scan lacks an over-capacity fallback state")
require("scanComplete = allMetadataValid && !overCapacity;" in scan, "over-capacity scan can poison the fast-page marker")
require("return retainedCount;" in scan, "over-capacity scan still returns an empty Inbox")

require(
    "value.cards.length === V1_TASK_IDS.length" in model_source,
    "simulator still accepts partial V1 manifests",
)
require(
    'this.last.inbox = fullyCaughtUp ? (changed ? "UPDATED" : "CURRENT") : "CATCH_UP_PENDING";' in compact(model_source),
    "simulator hides bounded V2 catch-up",
)
require(
    ".slice(0, MAX_INBOX_ITEMS)" in model_source,
    "simulator lacks the newest-items over-capacity fallback",
)

print("XTINCT_CONTENT_RECOVERY_SOURCE_CONTRACT_OK")
