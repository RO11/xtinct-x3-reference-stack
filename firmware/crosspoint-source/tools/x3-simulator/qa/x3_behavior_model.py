"""Deterministic Tier-1 behavior models for XTINCT X3 release QA.

These models deliberately use only synthetic, in-memory data.  They mirror
the firmware's bounded policies closely enough to exercise failure paths, but
they do not pretend to execute ESP32-C3 instructions or emulate peripherals.
Source-conformance checks in ``run_full_qa.py`` bind each model to the C++
contract that it represents.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable


SUPPORTED_BOOK_EXTENSIONS = (".epub", ".xtc", ".txt", ".md", ".markdown", ".bmp")
MANAGED_INBOX_PREFIX = "/.crosspoint/xtinct-v2/artifacts/"
MAX_INBOX_ITEMS = 64
INBOX_PAGE_ITEMS = 8
MAX_INBOX_SYNC_PAGES = 10
MAX_INBOX_CHANGES_PER_WAKE = INBOX_PAGE_ITEMS * MAX_INBOX_SYNC_PAGES


class ModelError(RuntimeError):
    """A fail-closed modeled firmware refusal."""


def normalize_sd_path(path: str, *, allow_root: bool = True) -> str:
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
        raise ModelError("SD path must be absolute within the virtual card")
    if "\x00" in path or "\\" in path or len(path.encode("utf-8")) > 512:
        raise ModelError("Invalid SD path")
    parts = path.split("/")[1:]
    if any(part in {"", ".", ".."} or len(part.encode("utf-8")) > 255 for part in parts):
        if path == "/" and allow_root:
            return "/"
        raise ModelError("Invalid SD path component")
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/") or normalized == "/" and not allow_root:
        raise ModelError("Invalid SD path")
    return normalized


@dataclass
class VirtualSd:
    """Small in-memory SD model with explicit directories and fault injection."""

    files: dict[str, bytes] = field(default_factory=dict)
    directories: set[str] = field(default_factory=lambda: {"/"})
    fail_writes: bool = False
    fail_deletes: set[str] = field(default_factory=set)

    def mkdir(self, path: str) -> None:
        path = normalize_sd_path(path, allow_root=False)
        parent = posixpath.dirname(path) or "/"
        if parent not in self.directories:
            raise ModelError("Parent directory is missing")
        self.directories.add(path)

    def write(self, path: str, data: bytes) -> None:
        path = normalize_sd_path(path, allow_root=False)
        if self.fail_writes:
            raise ModelError("Simulated storage error")
        parent = posixpath.dirname(path) or "/"
        if parent not in self.directories:
            raise ModelError("Parent directory is missing")
        self.files[path] = bytes(data)

    def exists(self, path: str) -> bool:
        path = normalize_sd_path(path)
        return path in self.directories or path in self.files

    def delete(self, path: str) -> None:
        path = normalize_sd_path(path, allow_root=False)
        if path in self.fail_deletes:
            raise ModelError("Simulated delete failure")
        if path in self.files:
            del self.files[path]
            return
        if path not in self.directories:
            raise ModelError("Path is missing")
        descendants = sorted(
            [candidate for candidate in self.files if candidate.startswith(path + "/")],
            key=len,
            reverse=True,
        )
        child_directories = sorted(
            [candidate for candidate in self.directories if candidate.startswith(path + "/")],
            key=len,
            reverse=True,
        )
        for candidate in descendants:
            if candidate in self.fail_deletes:
                raise ModelError("Simulated recursive delete failure")
            del self.files[candidate]
        for candidate in child_directories:
            if candidate in self.fail_deletes:
                raise ModelError("Simulated recursive delete failure")
            self.directories.remove(candidate)
        self.directories.remove(path)

    def atomic_replace(self, path: str, data: bytes, *, fail_phase: str | None = None) -> str:
        """Model temp -> backup -> final promotion while preserving old bytes."""

        path = normalize_sd_path(path, allow_root=False)
        parent = posixpath.dirname(path) or "/"
        if parent not in self.directories:
            raise ModelError("Parent directory is missing")
        temporary = path + ".put-model"
        backup = path + ".bak-model"
        old = self.files.get(path)
        if fail_phase == "write" or self.fail_writes:
            raise ModelError("Simulated incomplete upload")
        self.files[temporary] = bytes(data)
        if fail_phase == "before-promote":
            del self.files[temporary]
            return "old-retained"
        if old is not None:
            self.files[backup] = old
            del self.files[path]
        if fail_phase == "promote":
            if old is not None:
                self.files[path] = self.files.pop(backup)
            del self.files[temporary]
            return "old-restored"
        self.files[path] = self.files.pop(temporary)
        if fail_phase == "backup-cleanup" and old is not None:
            return "committed-backup-retained"
        self.files.pop(backup, None)
        return "committed"

    def list_book_entries(self, directory: str = "/", *, show_hidden: bool = False) -> list[str]:
        directory = normalize_sd_path(directory)
        if directory not in self.directories:
            raise ModelError("Directory is missing")
        prefix = "/" if directory == "/" else directory + "/"
        found: set[str] = set()
        for candidate in self.directories | set(self.files):
            if candidate == directory or not candidate.startswith(prefix):
                continue
            remainder = candidate[len(prefix) :]
            leaf = remainder.split("/", 1)[0]
            if not show_hidden and leaf.startswith("."):
                continue
            if leaf.casefold() == "system volume information":
                continue
            if "/" in remainder or candidate in self.directories:
                found.add(leaf + "/")
            elif leaf.casefold().endswith(SUPPORTED_BOOK_EXTENSIONS):
                found.add(leaf)
        return sorted(found, key=lambda value: (not value.endswith("/"), value.casefold(), value))


def reader_kind(path: str) -> str:
    suffix = posixpath.splitext(path)[1].casefold()
    if suffix == ".epub":
        return "epub"
    if suffix == ".xtc":
        return "xtc"
    if suffix in {".txt", ".md", ".markdown"}:
        return "txt"
    if suffix == ".bmp":
        return "bmp"
    raise ModelError("Unsupported reader file")


@dataclass
class RecentsModel:
    paths: list[str] = field(default_factory=list)

    def prune(self, sd: VirtualSd) -> None:
        self.paths = [path for path in self.paths if path in sd.files]

    def add(self, path: str) -> None:
        path = normalize_sd_path(path, allow_root=False)
        self.paths = [candidate for candidate in self.paths if candidate != path]
        self.paths.insert(0, path)

    def remove(self, path: str) -> None:
        self.paths = [candidate for candidate in self.paths if candidate != path]

    def open(self, index: int, sd: VirtualSd) -> tuple[str, bytes]:
        self.prune(sd)
        if not 0 <= index < len(self.paths):
            raise ModelError("Recent book is unavailable")
        path = self.paths[index]
        return reader_kind(path), sd.files[path]


def _logical_lines(data: bytes) -> list[tuple[int, str]]:
    if b"\x00" in data:
        raise ModelError("Embedded NUL is not renderable")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ModelError("TXT is not valid UTF-8") from error
    result: list[tuple[int, str]] = []
    offset = 0
    for raw in text.splitlines(keepends=True):
        source = raw.encode("utf-8")
        display = raw[:-2] if raw.endswith("\r\n") else raw[:-1] if raw.endswith(("\r", "\n")) else raw
        result.append((offset, display))
        offset += len(source)
    if not result or offset < len(data):
        result.append((offset, text.encode("utf-8")[offset:].decode("utf-8")))
    return result


@dataclass
class TxtReaderModel:
    data: bytes
    lines_per_page: int = 8
    wrap_columns: int = 44
    page_offsets: list[int] = field(init=False)
    pages: list[list[str]] = field(init=False)
    current_page: int = 0

    def __post_init__(self) -> None:
        if self.lines_per_page < 1 or self.wrap_columns < 1:
            raise ModelError("Invalid TXT viewport")
        rendered: list[tuple[int, str]] = []
        for source_offset, line in _logical_lines(self.data):
            pieces = [line[index : index + self.wrap_columns] for index in range(0, len(line), self.wrap_columns)]
            if not pieces:
                pieces = [""]
            rendered.extend((source_offset, piece) for piece in pieces)
        self.pages = []
        self.page_offsets = []
        for index in range(0, len(rendered), self.lines_per_page):
            chunk = rendered[index : index + self.lines_per_page]
            self.page_offsets.append(chunk[0][0] if chunk else 0)
            self.pages.append([line for _offset, line in chunk])
        if not self.pages:
            self.pages = [[]]
            self.page_offsets = [0]

    @property
    def total_pages(self) -> int:
        return len(self.pages)

    @property
    def progress_basis_points(self) -> int:
        return min(10000, ((self.current_page + 1) * 10000) // self.total_pages)

    def restore(self, saved_page: int) -> None:
        self.current_page = min(max(saved_page, 0), self.total_pages - 1)

    def next(self) -> bool:
        if self.current_page + 1 >= self.total_pages:
            return False
        self.current_page += 1
        return True

    def previous(self) -> bool:
        if self.current_page == 0:
            return False
        self.current_page -= 1
        return True


@dataclass
class EpubReaderModel:
    path: str
    spines: list[list[str]]
    spine: int = 0
    page: int = 0
    end_of_book: bool = False

    def __post_init__(self) -> None:
        if not self.spines or any(not pages for pages in self.spines):
            raise ModelError("EPUB requires at least one page in every spine")

    def restore(self, saved_spine: int, saved_page: int) -> None:
        if saved_spine < 0 or saved_spine >= len(self.spines):
            self.spine = 0
            self.page = 0
        else:
            self.spine = saved_spine
            self.page = min(max(saved_page, 0), len(self.spines[self.spine]) - 1)
        self.end_of_book = False

    def next(self) -> bool:
        if self.end_of_book:
            return False
        if self.page + 1 < len(self.spines[self.spine]):
            self.page += 1
            return True
        if self.spine + 1 < len(self.spines):
            self.spine += 1
            self.page = 0
            return True
        self.end_of_book = True
        return False

    def previous(self) -> bool:
        if self.end_of_book:
            self.end_of_book = False
            self.spine = len(self.spines) - 1
            self.page = len(self.spines[-1]) - 1
            return True
        if self.page > 0:
            self.page -= 1
            return True
        if self.spine > 0:
            self.spine -= 1
            self.page = len(self.spines[self.spine]) - 1
            return True
        return False

    @property
    def saved_position(self) -> tuple[int, int]:
        # The in-session end screen is never persisted as spineCount.
        return self.spine, self.page

    @property
    def allows_sibling_suggestions(self) -> bool:
        return not self.path.startswith(MANAGED_INBOX_PREFIX)


@dataclass(frozen=True)
class InboxItem:
    item_id: str
    created_at: str
    kind: str = "text"


def inbox_pages(items: Iterable[InboxItem]) -> list[list[InboxItem]]:
    bounded = list(items)
    if len(bounded) > MAX_INBOX_ITEMS:
        raise ModelError("Inbox metadata exceeds the X3 bound")
    # Firmware orders newest timestamps first and uses ascending item_id as a
    # deterministic tie-breaker.
    ordered = sorted(bounded, key=lambda item: item.item_id)
    ordered.sort(key=lambda item: item.created_at, reverse=True)
    return [ordered[index : index + INBOX_PAGE_ITEMS] for index in range(0, len(ordered), INBOX_PAGE_ITEMS)]


def brisbane_local_day(utc_epoch: int) -> int:
    if utc_epoch < 0:
        raise ModelError("RTC time is invalid")
    return (utc_epoch + 10 * 3600) // 86400


def should_claim_daily_sync(*, day_known: bool, state_valid: bool, today: int, attempt_day: int, fresh_day: int) -> bool:
    return day_known and state_valid and attempt_day != today and fresh_day != today


def can_stamp_daily_fresh(cards_complete: bool, inbox_complete: bool) -> bool:
    return cards_complete and inbox_complete


def next_wake_seconds(
    now_utc: datetime,
    *,
    primary_hour: int,
    primary_minute: int,
) -> tuple[int, int, int]:
    if now_utc.tzinfo is None:
        raise ModelError("UTC clock must be timezone-aware")
    windows: list[tuple[int, int]] = []
    for candidate in ((primary_hour, primary_minute), (8, 15), (18, 0)):
        if 0 <= candidate[0] < 24 and 0 <= candidate[1] < 60 and candidate not in windows:
            windows.append(candidate)
    if not windows:
        raise ModelError("No valid wake window")
    brisbane = now_utc.astimezone(timezone(timedelta(hours=10)))
    choices: list[tuple[int, int, int]] = []
    for hour, minute in windows:
        target = brisbane.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if target <= brisbane:
            target += timedelta(days=1)
        choices.append((int((target - brisbane).total_seconds()), hour, minute))
    return min(choices)


def should_retry_scheduled_sync(
    *, allow_retries: bool, transient_failure: bool, retry_count: int, maximum_retries: int
) -> bool:
    return allow_retries and transient_failure and retry_count < maximum_retries


def sanitized_crash_report(
    *, reason: str, program_counter: int, return_address: int, machine_cause: int, abort_message: str = ""
) -> str:
    report = [
        f"Reason: {reason[:32]}",
        f"Program counter: 0x{program_counter & 0xFFFFFFFF:08X}",
        f"Return address: 0x{return_address & 0xFFFFFFFF:08X}",
        f"Machine cause: 0x{machine_cause & 0xFFFFFFFF:08X}",
    ]
    prefix = "abort() was called at PC 0x"
    suffix = " on core "
    if abort_message.startswith(prefix):
        remainder = abort_message[len(prefix) :]
        if len(remainder) == 8 + len(suffix) + 1 and remainder[8 : 8 + len(suffix)] == suffix:
            digits, core = remainder[:8], remainder[-1]
            if all(value in "0123456789abcdefABCDEF" for value in digits) and core.isdigit():
                report.append(f"Abort caller PC: 0x{int(digits, 16):08X}")
    report.append("Raw stack memory and retained logs are intentionally omitted.")
    return "\n".join(report)
