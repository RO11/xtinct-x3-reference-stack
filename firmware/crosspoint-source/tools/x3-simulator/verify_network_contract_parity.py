#!/usr/bin/env python3
"""Fail-closed source gate binding the simulator to current firmware seams."""

from __future__ import annotations

from pathlib import Path


SIM_ROOT = Path(__file__).resolve().parent
SOURCE_ROOT = SIM_ROOT.parents[1] / "src"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(f"network simulator parity gate failed: {message}")


def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    require(start >= 0, f"missing firmware function {signature}")
    opening = source.find("{", start + len(signature))
    require(opening >= 0, f"unterminated signature {signature}")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening : index + 1]
    raise RuntimeError(f"network simulator parity gate failed: unterminated function {signature}")


def contains_all(source: str, fragments: tuple[str, ...], label: str) -> None:
    for fragment in fragments:
        require(fragment in source, f"{label} lost {fragment}")


def verify() -> None:
    feed = (SOURCE_ROOT / "network" / "XtinctFeedClient.cpp").read_text(encoding="utf-8")
    feed_header = (SOURCE_ROOT / "network" / "XtinctFeedClient.h").read_text(encoding="utf-8")
    sync = (SOURCE_ROOT / "network" / "XtinctSyncClient.cpp").read_text(encoding="utf-8")
    sync_contract = (SOURCE_ROOT / "util" / "XtinctSyncContract.h").read_text(encoding="utf-8")
    paging = (SOURCE_ROOT / "util" / "InboxSyncPagingPolicy.h").read_text(encoding="utf-8")
    digest = (SOURCE_ROOT / "util" / "InboxDigestContract.h").read_text(encoding="utf-8")
    reports = (SOURCE_ROOT / "util" / "XtinctReportCacheNaming.h").read_text(encoding="utf-8")
    activity = (SOURCE_ROOT / "activities" / "home" / "InboxActivity.cpp").read_text(encoding="utf-8")
    cards_activity = (SOURCE_ROOT / "activities" / "home" / "DailyCardsActivity.cpp").read_text(encoding="utf-8")
    model = (SIM_ROOT / "web" / "network-model.js").read_text(encoding="utf-8")
    fixture = (SIM_ROOT / "network_fixture.py").read_text(encoding="utf-8")

    contains_all(feed, (
        'constexpr size_t MAX_MANIFEST_BYTES = 8192;',
        'constexpr size_t MAX_CARD_BYTES = 16 * 1024;',
        'constexpr size_t MAX_REPORT_BYTES = 24 * 1024;',
        '"/v1/manifest.json"',
        '"?revision=" + remoteCards[i].revision',
        'if (!responseEtag.empty() && responseEtag != bodyEtag)',
    ), "XtinctFeedClient")
    contains_all(feed_header, ('char title[81]', 'char summary[321]', 'XtinctCardMetric metrics[4]',
                               'XtinctCardSection sections[3]'), "XtinctFeedClient storage")
    manifest = function_body(feed, "bool XtinctFeedClient::parseManifest(")
    contains_all(manifest, (
        '(doc["schema"] | 0) != 1',
        'doc["cards"].is<JsonArrayConst>()',
        'snprintf(expectedUrl, sizeof(expectedUrl), "/v1/cards/%s.json", id)',
        'isAllowedTaskId(id)',
        'isSafeRevision(revision)',
    ), "V1 manifest parser")
    card = function_body(feed, "bool parseCardObject(")
    contains_all(card, (
        '(doc["schema"] | 0) != 1',
        'metrics.size() > 4',
        'sections.size() > 3',
        'lines.size() > 4',
        'bytes > MAX_REPORT_BYTES',
        'expectedReportUrl(taskId, revision',
    ), "V1 card parser")
    for task in ("market-briefing", "weekday-freelancer-scan", "3d-job-search", "outlook-attention-watch"):
        require(f'"{task}"' in reports and f'"{task}"' in fixture, f"task allowlist drifted for {task}")

    contains_all(paging, (
        'constexpr size_t DIRECT_PAGE_CHANGES = 8;',
        'constexpr uint8_t MAX_PAGES_PER_WAKE = 10;',
        'constexpr size_t MAX_DIRECT_RESPONSE_BYTES = 28 * 1024;',
    ), "Inbox paging policy")
    contains_all(sync_contract, (
        'constexpr size_t MAX_ARTIFACT_BYTES = 20 * 1024 * 1024;',
        'constexpr size_t MAX_OUTBOX_BYTES = 32 * 1024;',
        'constexpr size_t MAX_OUTBOX_EVENTS = 48;',
        'constexpr size_t MAX_ACK_EVENTS = 24;',
        '"deleted"',
        '"like"',
        '"dislike"',
    ), "V2 shared contract")
    contains_all(digest, (
        'inline constexpr size_t MAX_SUMMARY_BYTES = 144;',
        'inline constexpr size_t MAX_POINT_BYTES = 64;',
        'inline constexpr size_t MAX_POINTS = 2;',
        'memberCount == 3',
    ), "Inbox digest contract")

    page = function_body(sync, "bool parseSyncPage(")
    contains_all(page, (
        '(document["schema"] | 0) != 2',
        'deliveries.size() + tombstones.size() > xtinct::inbox_sync_paging::DIRECT_PAGE_CHANGES',
        'parseDelivery(deliveryObject',
        'parseDelivery',
    ), "V2 page parser")
    delivery = function_body(sync, "bool parseDelivery(")
    contains_all(delivery, (
        'MAX_TITLE_BYTES',
        'MAX_ARTIFACT_BYTES',
        'mimeAllowed(kind, mime)',
        'measureJson(object["metadata"]) > xtinct::sync_v2::MAX_METADATA_BYTES',
        'parseInboxDigest',
        'parseActions',
    ), "V2 delivery parser")
    artifact = function_body(sync, "XtinctSyncClient::SyncResult downloadArtifact(")
    contains_all(artifact, (
        '"/v2/artifacts/" + item.sha256',
        'contentLength != item.bytes',
        'responseMime != item.mime',
        'responseEtag != expectedEtag',
        'responseNosniff != "nosniff"',
        '!digestMatches(digest, item.sha256)',
    ), "V2 artifact verifier")
    sync_body = function_body(sync, "XtinctSyncClient::SyncResult XtinctSyncClient::sync()")
    contains_all(sync_body, (
        '"/v2/sync?cursor=" + cursor + "&limit="',
        'sendPendingAcks();',
        'downloadArtifact(*http, item)',
        'writeMetadata(item)',
        'writeAtomic(CURSOR_PATH, nextCursor',
        'MAX_SYNC_PAGES_PER_WAKE',
    ), "V2 sync transaction")
    require(sync_body.index("downloadArtifact(*http, item)") < sync_body.index("writeMetadata(item)") <
            sync_body.index("writeAtomic(CURSOR_PATH, nextCursor"),
            "V2 artifact/metadata/cursor commit ordering changed")
    acks = function_body(sync, "bool XtinctSyncClient::sendPendingAcks()")
    contains_all(acks, (
        '"/v2/acks"',
        'responseDocument["accepted"]',
        'responseDocument["duplicates"]',
        'responseDocument["rejected"]',
        'represented != sendCount',
        'rewriteOutboxStreaming(sendCount',
    ), "V2 ACK verifier")

    action = function_body(activity, "void InboxActivity::applyAction(")
    contains_all(action, (
        'if (action != "delete" && !receiptQueued)',
        'action == "archive" || action == "done" || action == "delete" || action == "like" || action == "dislike"',
        'XtinctSyncClient::removeFromInbox(selected)',
    ), "Inbox action ordering")
    inbox_loop = function_body(activity, "void InboxActivity::loop()")
    contains_all(inbox_loop, (
        'mappedInput.wasReleased(MappedInputManager::Button::Confirm)',
        'showActions();',
    ), "Inbox actions release boundary")
    require('mappedInput.wasPressed(MappedInputManager::Button::Confirm)' not in inbox_loop,
            "Inbox actions must not open on press and consume the same release as Sync now")

    cards_loop = function_body(cards_activity, "void DailyCardsActivity::loop()")
    checked_busy_paint = "if (!syncScreenPainted && !requestUpdateAndWait())"
    contains_all(cards_loop, (
        checked_busy_paint,
        "Daily Cards sync cancelled: busy screen was not confirmed",
        "syncScreenPainted = false;",
        "runSync();",
        "Daily Cards refresh cancelled: busy screen was not confirmed",
        "syncScreenPainted = true;",
    ), "Daily Cards refresh visibility")
    require(cards_loop.index(checked_busy_paint) < cards_loop.index("runSync();"),
            "Daily Cards must paint its busy page before starting network sync")
    confirm_start = cards_loop.find("if (mappedInput.wasPressed(MappedInputManager::Button::Confirm))")
    require(confirm_start >= 0, "Daily Cards Confirm branch is missing")
    confirm_end = cards_loop.find("\n  if (mappedInput.wasPressed", confirm_start + 1)
    require(confirm_end > confirm_start, "Daily Cards Confirm branch is not bounded")
    confirm_body = cards_loop[confirm_start:confirm_end]
    require("if (!requestUpdateAndWait())" in confirm_body and
            "syncScreenPainted = true;" in confirm_body,
            "manual Daily Cards refresh must finish a physical busy paint before returning")
    cards_sync = function_body(cards_activity, "void DailyCardsActivity::runSync()")
    contains_all(cards_sync, (
        "try {",
        "catch (const std::bad_alloc&)",
        "catch (const std::length_error&)",
        "catch (...)",
        "XtinctFeedClient::disconnectWifi();",
        "state = cardCount > 0 ? State::CARD_READY : State::NO_CARD;",
        "requestUpdate();",
    ), "Daily Cards exception containment")
    require(cards_sync.index("try {") < cards_sync.index("XtinctFeedClient::connectSavedWifi()"),
            "Daily Cards must contain exceptions from Wi-Fi through V1/V2 and cache reload")

    # The browser constants and exact relative paths are deliberately literal;
    # this gate makes any firmware-side change fail until the model is reviewed.
    contains_all(model, (
        'export const DIRECT_PAGE_CHANGES = 8;',
        'export const MAX_PAGES_PER_WAKE = 10;',
        'export const MAX_SYNC_BODY_BYTES = 28 * 1024;',
        '`${this.baseUrl}/v1/manifest.json`',
        '`${this.baseUrl}${reference.url}?revision=${encodeURIComponent(reference.revision)}`',
        '`${this.baseUrl}/v2/sync?cursor=${encodeURIComponent(this.cursor)}&limit=${DIRECT_PAGE_CHANGES}`',
        '`${this.baseUrl}/v2/artifacts/${item.sha256}`',
        '`${this.baseUrl}/v2/acks`',
        'represented === count',
        'action !== "delete" && !queued',
        '["delete", "archive", "done", "like", "dislike"]',
    ), "browser contract model")


def main() -> int:
    verify()
    print("network simulator parity source gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
