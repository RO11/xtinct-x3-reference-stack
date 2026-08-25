"""Deterministic, localhost-only Cards V1 and Inbox V2 fixture service.

This module models the HTTP surface consumed by XtinctFeedClient and
XtinctSyncClient.  It never performs outbound I/O and intentionally uses only
synthetic content.  The browser simulator talks to it with real HTTP requests
so request headers, conditional GETs, cursor paging, artifact integrity and
receipt retries can be exercised without reaching the production Worker.
"""

from __future__ import annotations

import hashlib
import io
import json
import threading
import zipfile
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs


READ_TOKEN = "synthetic-read-token"
DEVICE_ID = "sim-x3-main"
MAX_LOG_ENTRIES = 96
V1_TASK_IDS = (
    "market-briefing",
    "weekday-freelancer-scan",
    "3d-job-search",
    "outlook-attention-watch",
)

SCENARIOS: dict[str, str] = {
    "happy-path": "Complete V1 and V2 download with valid reports and artifacts.",
    "cache-current": "Valid data with ETag/unchanged revisions for cache-first repeat sync.",
    "pagination": "Eighteen ordered V2 changes across 8/8/2 cursor pages, including a tombstone.",
    "http-503": "V1 manifest and V2 sync return an HTTP 503 service failure.",
    "malformed-payload": "V1 and V2 return syntactically valid JSON that violates their schemas.",
    "artifact-failure-once": "The second V2 artifact request fails with 503; the committed prefix survives and retry succeeds.",
    "artifact-short-once": "The second V2 artifact is short; byte-count validation rejects it before retry succeeds.",
    "report-short-once": "The first V1 report is short; the full V1 transaction rolls back before retry succeeds.",
    "ack-failure-once": "The first V2 receipt upload fails with 503; queued events retry safely.",
    "no-config": "The device has no read token; no HTTP request is attempted.",
    "no-wifi": "The device cannot connect to saved Wi-Fi; no HTTP request is attempted.",
    "clock-error": "The RTC/NTP gate fails before Cards V1; no feed request is attempted.",
    "storage-error": "The local recovery/storage preflight fails closed before HTTP.",
}


def _compact_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _revision(seed: str) -> str:
    return hashlib.sha256(f"revision:{seed}".encode("utf-8")).hexdigest()[:32]


def _epub_bytes() -> bytes:
    """Create a small deterministic EPUB fixture with a single readable spine."""

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        entries = (
            (
                "mimetype",
                b"application/epub+zip",
                zipfile.ZIP_STORED,
            ),
            (
                "META-INF/container.xml",
                b'<?xml version="1.0"?><container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container"><rootfiles><rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/></rootfiles></container>',
                zipfile.ZIP_DEFLATED,
            ),
            (
                "OEBPS/content.opf",
                b'<?xml version="1.0"?><package version="3.0" xmlns="http://www.idpf.org/2007/opf" unique-identifier="id"><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:identifier id="id">urn:xtinct:sim:today</dc:identifier><dc:title>Today - Simulator Edition</dc:title><dc:language>en</dc:language></metadata><manifest><item id="today" href="today.xhtml" media-type="application/xhtml+xml"/></manifest><spine><itemref idref="today"/></spine></package>',
                zipfile.ZIP_DEFLATED,
            ),
            (
                "OEBPS/today.xhtml",
                b'<?xml version="1.0" encoding="utf-8"?><html xmlns="http://www.w3.org/1999/xhtml"><head><title>Today</title></head><body><h1>Today</h1><p>This synthetic edition proves that Inbox downloads and opens a complete local EPUB artifact.</p><h2>Plan</h2><p>Review the cards, choose one useful action, and protect recovery time.</p></body></html>',
                zipfile.ZIP_STORED,
            ),
        )
        for name, content, compression in entries:
            info = zipfile.ZipInfo(name, date_time=(2026, 8, 12, 0, 0, 0))
            info.compress_type = compression
            info.create_system = 0
            info.external_attr = 0o600 << 16
            archive.writestr(info, content)
    return output.getvalue()


def _build_card(task_id: str, index: int) -> tuple[dict[str, Any], bytes | None]:
    revision = _revision(task_id)
    report = (
        f"{task_id.replace('-', ' ').title()}\n\n"
        "This deterministic full report is served only by the local X3 simulator.\n"
        "It exercises the same bounded report path, byte count and SHA-256 checks as firmware.\n"
    ).encode("utf-8")
    card: dict[str, Any] = {
        "schema": 1,
        "task_id": task_id,
        "revision": revision,
        "generated_at": f"2026-08-12T0{index + 5}:00:00+10:00",
        "title": task_id.replace("-", " ").title(),
        "summary": "A synthetic local card used to verify the X3 HTTPS contract and cache transaction.",
        "priority": (index % 3) + 1,
        "state": "attention" if index == 3 else "ok",
        "metrics": [
            {"label": "items", "value": str(index + 1), "tone": "neutral"},
            {"label": "source", "value": "local", "tone": "good"},
        ],
        "sections": [
            {"heading": "TODAY", "lines": ["Validate the cached summary", "Open the bounded report"]},
            {"heading": "STATUS", "lines": ["No production service contacted"]},
        ],
        "report": {
            "url": f"/v1/reports/{task_id}/{revision}.txt",
            "bytes": len(report),
            "sha256": _sha256(report),
        },
    }
    return card, report


def _build_delivery(index: int) -> tuple[dict[str, Any], bytes]:
    item_id = "sim-today" if index == 1 else f"sim-inbox-{index:02d}"
    if index == 1:
        kind = "epub"
        mime = "application/epub+zip"
        title = "Today - Simulator Edition"
        artifact = _epub_bytes()
    else:
        kind = "text"
        mime = "text/plain; charset=utf-8"
        title = f"Simulator Inbox Article {index:02d}"
        artifact = (
            f"{title}\n\n"
            "This is complete synthetic long-form content from the localhost-only fixture server.\n\n"
            "Open, delete, action receipt, retry and cursor behavior can be tested without production data.\n"
        ).encode("utf-8")
    digest = _sha256(artifact)
    revision = hashlib.sha256(f"inbox-revision:{index}:{digest}".encode("utf-8")).hexdigest()
    delivery = {
        "delivery_id": f"sim-delivery-{index:02d}",
        "item_id": item_id,
        "module_id": "today-sheet" if index == 1 else "simulator-feed",
        "kind": kind,
        "title": title,
        "revision": revision,
        "sha256": digest,
        "bytes": len(artifact),
        "mime": mime,
        "created_at": f"2026-08-{12 - ((index - 1) // 4):02d}T{23 - (index % 12):02d}:00:00+10:00",
        "expires_at": None,
        "actions": ["keep", "archive", "done", "like", "dislike"],
        "metadata": {
            "digest": {
                "schema": "xtinct.inbox-digest/v1",
                "summary": "A complete local fixture article for deterministic X3 Inbox contract testing.",
                "points": ["Artifact integrity is checked", "Receipts stay queued until accepted"],
            }
        },
    }
    return delivery, artifact


@dataclass(frozen=True)
class NetworkCorpus:
    manifest: dict[str, Any]
    manifest_body: bytes
    etag: str
    cards: dict[str, bytes]
    reports: dict[tuple[str, str], bytes]
    changes: tuple[dict[str, Any], ...]
    artifacts: dict[str, bytes]
    artifact_mimes: dict[str, str]


def _build_corpus() -> NetworkCorpus:
    card_bodies: dict[str, bytes] = {}
    reports: dict[tuple[str, str], bytes] = {}
    refs: list[dict[str, str]] = []
    for index, task_id in enumerate(V1_TASK_IDS):
        card, report = _build_card(task_id, index)
        revision = str(card["revision"])
        card_bodies[task_id] = _compact_json(card)
        if report is not None:
            reports[(task_id, revision)] = report
        refs.append({"id": task_id, "revision": revision, "url": f"/v1/cards/{task_id}.json"})

    etag_value = '"sim-v1-20260812"'
    manifest = {"schema": 1, "etag": etag_value, "cards": refs}
    manifest_body = _compact_json(manifest)

    artifacts: dict[str, bytes] = {}
    artifact_mimes: dict[str, str] = {}
    changes: list[dict[str, Any]] = []
    deliveries: list[dict[str, Any]] = []
    for index in range(1, 18):
        delivery, artifact = _build_delivery(index)
        deliveries.append(delivery)
        digest = str(delivery["sha256"])
        artifacts[digest] = artifact
        artifact_mimes[digest] = str(delivery["mime"])
        changes.append({"sequence": index, "delivery": delivery})
    changes.append(
        {
            "sequence": 18,
            "tombstone": {
                "delivery_id": deliveries[1]["delivery_id"],
                "item_id": deliveries[1]["item_id"],
                "revision": deliveries[1]["revision"],
                "deleted_at": "2026-08-12T07:45:00+10:00",
            },
        }
    )
    return NetworkCorpus(
        manifest=manifest,
        manifest_body=manifest_body,
        etag=etag_value,
        cards=card_bodies,
        reports=reports,
        changes=tuple(changes),
        artifacts=artifacts,
        artifact_mimes=artifact_mimes,
    )


CORPUS = _build_corpus()


@dataclass
class NetworkSessionState:
    scenario: str = "happy-path"
    counts: dict[str, int] = field(default_factory=dict)
    failed_once: set[str] = field(default_factory=set)
    accepted_event_ids: set[str] = field(default_factory=set)
    request_log: list[dict[str, Any]] = field(default_factory=list)


class NetworkFixtureStore:
    """Thread-safe per-browser state for deterministic failure injection."""

    def __init__(self) -> None:
        self._states: dict[str, NetworkSessionState] = {}
        self._lock = threading.Lock()

    def _state(self, token: str) -> NetworkSessionState:
        return self._states.setdefault(token, NetworkSessionState())

    def reset(self, token: str, scenario: str = "happy-path") -> NetworkSessionState:
        if scenario not in SCENARIOS:
            raise ValueError("Unknown network scenario")
        with self._lock:
            state = NetworkSessionState(scenario=scenario)
            self._states[token] = state
            return state

    def select(self, token: str, scenario: str) -> NetworkSessionState:
        return self.reset(token, scenario)

    def snapshot(self, token: str) -> dict[str, Any]:
        with self._lock:
            state = self._state(token)
            return {
                "schema": "xtinct-x3-network-status/1",
                "scenario": state.scenario,
                "description": SCENARIOS[state.scenario],
                "request_counts": dict(state.counts),
                "accepted_event_count": len(state.accepted_event_ids),
                "requests": list(state.request_log),
                "transport": "localhost-http",
                "outbound_network": "disabled",
            }

    def record(self, token: str, method: str, path: str, detail: str = "") -> NetworkSessionState:
        with self._lock:
            state = self._state(token)
            key = f"{method} {path}"
            state.counts[key] = state.counts.get(key, 0) + 1
            state.request_log.append({"method": method, "path": path, "detail": detail})
            if len(state.request_log) > MAX_LOG_ENTRIES:
                del state.request_log[: len(state.request_log) - MAX_LOG_ENTRIES]
            return state

    def consume_failure_once(self, token: str, key: str) -> bool:
        with self._lock:
            state = self._state(token)
            if key in state.failed_once:
                return False
            state.failed_once.add(key)
            return True

    def count_prefix(self, token: str, prefix: str) -> int:
        with self._lock:
            state = self._state(token)
            return sum(count for key, count in state.counts.items() if key.startswith(prefix))

    def accept_events(self, token: str, event_ids: list[str]) -> tuple[int, int]:
        with self._lock:
            state = self._state(token)
            accepted = 0
            duplicates = 0
            for event_id in event_ids:
                if event_id in state.accepted_event_ids:
                    duplicates += 1
                else:
                    state.accepted_event_ids.add(event_id)
                    accepted += 1
            return accepted, duplicates


def listed_scenarios() -> dict[str, object]:
    return {
        "schema": "xtinct-x3-network-scenarios/1",
        "default": "happy-path",
        "scenarios": [
            {"id": identifier, "description": description}
            for identifier, description in SCENARIOS.items()
        ],
        "transport": "localhost-http",
        "production_access": False,
    }


def sync_page(cursor_text: str, limit_text: str, scenario: str) -> dict[str, Any]:
    if not cursor_text.isdecimal() or not limit_text.isdecimal():
        raise ValueError("Cursor and limit must be decimal")
    cursor = int(cursor_text)
    limit = int(limit_text)
    if cursor < 0 or not 1 <= limit <= 8:
        raise ValueError("Cursor or limit is outside the firmware contract")
    source = CORPUS.changes if scenario == "pagination" else CORPUS.changes[:4]
    available = [change for change in source if int(change["sequence"]) > cursor]
    selected = available[:limit]
    next_cursor = int(selected[-1]["sequence"]) if selected else cursor
    return {
        "schema": 2,
        "device_id": DEVICE_ID,
        "cursor": str(next_cursor),
        "has_more": len(available) > len(selected),
        "deliveries": [change["delivery"] for change in selected if "delivery" in change],
        "tombstones": [change["tombstone"] for change in selected if "tombstone" in change],
    }


def parse_query(query: str) -> dict[str, str]:
    parsed = parse_qs(query, keep_blank_values=True)
    if any(len(values) != 1 for values in parsed.values()):
        raise ValueError("Each query parameter must occur exactly once")
    return {key: values[0] for key, values in parsed.items()}
