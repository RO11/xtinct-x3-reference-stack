#!/usr/bin/env python3
"""Source gate for the X3 V2 sync/outbox crash boundary."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "src/network/XtinctSyncClient.cpp").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"outbox memory contract failed: {message}")


def function_body(signature: str) -> str:
    start = SOURCE.find(signature)
    require(start >= 0, f"missing function {signature}")
    opening = SOURCE.find("{", start)
    require(opening >= 0, f"missing body for {signature}")
    depth = 0
    for index in range(opening, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[opening : index + 1]
    raise SystemExit(f"outbox memory contract failed: unterminated function {signature}")


sync = function_body("XtinctSyncClient::SyncResult XtinctSyncClient::sync()")
send = function_body("bool XtinctSyncClient::sendPendingAcks()")
queue = function_body("bool XtinctSyncClient::queueEvent(")
rewrite = function_body("bool rewriteOutboxStreaming(")
build = function_body("bool buildAckPayload(")

for fragment in (
    "catch (const std::bad_alloc&)",
    "catch (const std::length_error&)",
    "catch (...)",
    "return SyncResult::NETWORK_ERROR;",
):
    require(fragment in sync, f"V2 sync exception boundary lost {fragment}")

for body, name in ((send, "sendPendingAcks"), (queue, "queueEvent")):
    for forbidden in ("std::vector", "splitLines(", "persistOutbox("):
        require(forbidden not in body, f"{name} regained whole-outbox duplication via {forbidden}")
    for fragment in (
        "catch (const std::bad_alloc&)",
        "catch (const std::length_error&)",
        "catch (...)",
        "return false;",
    ):
        require(fragment in body, f"best-effort {name} boundary lost {fragment}")

for fragment in (
    "prepareOutbox(eventCount, encodedBytes)",
    "BoundedResponseBuffer payload(MAX_DEVICE_ACK_JSON_BYTES)",
    "buildAckPayload(payload, sendCount)",
    'http->sendRequest(\n      "POST"',
    "BoundedResponseBuffer responseBody(1024)",
    "http.reset();",
    "payload.release();",
    "responseBody.release();",
    "rewriteOutboxStreaming(sendCount, nullptr, 0, false)",
):
    require(fragment in send, f"bounded ACK path lost {fragment}")

send_order = (
    send.find("prepareOutbox("),
    send.find("buildAckPayload("),
    send.find("http->sendRequest("),
    send.find("represented != sendCount"),
    send.find("rewriteOutboxStreaming(sendCount"),
)
require(all(index >= 0 for index in send_order) and list(send_order) == sorted(send_order),
        "ACK validation/prefix-removal order changed")

for fragment in (
    "appendOutboxLineAtomic(line.data(), lineBytes)",
    "BoundedResponseBuffer line(xtinct::sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES)",
):
    require(fragment in queue, f"bounded receipt append lost {fragment}")

for fragment in (
    "finishDurableWrite(output",
    "promoteAtomic(temporaryPath, OUTBOX_PATH",
    "commitAtomic(OUTBOX_PATH)",
    "skippedLines != skipValidLines",
):
    require(fragment in rewrite, f"atomic streaming rewrite lost {fragment}")

require("char line[xtinct::sync_v2::MAX_OUTBOX_EVENT_LINE_BYTES + 1]" in build,
        "ACK builder lost its single fixed line buffer")
require("constexpr size_t MAX_DEVICE_ACK_JSON_BYTES = 4 * 1024" in SOURCE,
        "device ACK payload is no longer capped at 4 KiB")
require("static_assert(MAX_DEVICE_ACK_JSON_BYTES <= xtinct::sync_v2::MAX_ACK_JSON_BYTES)" in SOURCE,
        "device ACK cap is no longer bound below the wire-contract maximum")
require("std::string payload" not in send, "ACK payload regained throwing string serialization")
require("std::vector<std::string> splitLines" not in SOURCE,
        "legacy whole-outbox line duplication remains compiled")

print("outbox memory contract: PASS")
