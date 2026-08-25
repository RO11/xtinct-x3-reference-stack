#!/usr/bin/env python3
"""Fail-closed sanitizer for public XTINCT release trees.

The scanner intentionally reports rule names and locations without echoing the
matched value.  Private values can be supplied at runtime; they do not belong
in this source file, test fixtures, logs, or release manifests.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import sys
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit


FORBIDDEN_MARKERS_ENV = "XTINCT_PUBLIC_RELEASE_FORBIDDEN_MARKERS"
ALLOWED_WORKER_URLS_ENV = "XTINCT_PUBLIC_RELEASE_ALLOWED_WORKER_URLS"
ALLOWED_EMAILS_ENV = "XTINCT_PUBLIC_RELEASE_ALLOWED_EMAILS"

DEFAULT_MAX_FILE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_FINDINGS = 1_000
DEFAULT_MAX_BINARY_STRINGS = 250_000

_REPARSE_ATTRIBUTE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_BINARY_EXTENSIONS = {
    ".a",
    ".bin",
    ".bmp",
    ".class",
    ".elf",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".o",
    ".pdf",
    ".png",
    ".so",
    ".ttf",
    ".wasm",
    ".webp",
    ".woff",
    ".woff2",
}
_CODE_SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".java", ".js", ".jsx",
    ".mjs", ".py", ".ps1", ".ts", ".tsx",
}
_RISKY_DIRECTORY_NAMES = {
    ".aws",
    ".cache",
    ".git",
    ".hg",
    ".ssh",
    ".svn",
    ".wrangler",
    "__pycache__",
    "backup",
    "backups",
    "node_modules",
    "quarantine",
    "temp",
    "tmp",
}
_RISKY_EXACT_FILENAMES = {
    ".env",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".python_history",
    "credentials.json",
    "id_dsa",
    "id_ed25519",
    "id_ecdsa",
    "id_rsa",
    "secrets.json",
    "thumbs.db",
}
_RISKY_SUFFIXES = {
    ".7z",
    ".bak",
    ".cpuprofile",
    ".dmp",
    ".dump",
    ".jks",
    ".key",
    ".keystore",
    ".log",
    ".map",
    ".mobileprovision",
    ".old",
    ".p12",
    ".pem",
    ".pfx",
    ".rar",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tgz",
    ".tmp",
    ".zip",
}
_RISKY_CREDENTIAL_FILENAME_RE = re.compile(
    r"(?i)(?:credential|password|private[-_.]?key|secret|token)s?[-_.].*\.(?:json|txt|ya?ml|ini|cfg)$"
)
_SAFE_TEMPLATE_FILENAMES = {".dev.vars.example", ".env.example"}
_SAFE_EVIDENCE_FILENAMES = {"firmware.map"}

_EMAIL_RE = re.compile(
    r"(?i)(?<![A-Z0-9._%+-])([A-Z0-9._%+-]{1,64}@[A-Z0-9.-]{1,253}\.[A-Z]{2,63})(?![A-Z0-9._%+-])"
)
_LIVE_WORKER_URL_RE = re.compile(
    r"(?i)https?://(?:[a-z0-9-]+\.)+[a-z0-9-]*workers\.dev"
    r"[a-z0-9.-]*(?:/[^\s\"'<>]*)?"
)
_WINDOWS_ABSOLUTE_PATH_RE = re.compile(
    r"(?i)(?<![A-Z0-9])(?:file:///?)*[A-Z]:[\\/](?:[^<>:\"|?*\r\n]+[\\/])+[^<>:\"|?*\r\n]*"
)
_BACKSLASH = chr(92)
_ESCAPED_BACKSLASH = re.escape(_BACKSLASH)
_UNC_COMPONENT = "[^/" + _ESCAPED_BACKSLASH + r"\s\"'<>]+"
_UNC_SEPARATOR = "(?:" + _ESCAPED_BACKSLASH + "|/)"
_WINDOWS_UNC_PATH_RE = re.compile(
    "(?i)(?<!"
    + _ESCAPED_BACKSLASH
    + ")"
    + (_ESCAPED_BACKSLASH * 2)
    + "(?!"
    + _ESCAPED_BACKSLASH
    + ")"
    + _UNC_COMPONENT
    + _UNC_SEPARATOR
    + _UNC_COMPONENT
    + "(?:"
    + _UNC_SEPARATOR
    + _UNC_COMPONENT
    + ")?"
)
_POSIX_PERSONAL_PATH_RE = re.compile(
    r"(?i)(?<![A-Z0-9])/(?:Users|home)/[A-Z0-9._-]+(?:/[^\s\"'<>]*)?"
)
_WSL_PERSONAL_PATH_RE = re.compile(
    r"(?i)(?<![A-Z0-9])/mnt/[a-z]/Users/[A-Z0-9._-]+(?:/[^\s\"'<>]*)?"
)

_GENERIC_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?im)\b[A-Z][A-Z0-9_.-]*(?:API[-_.]?KEY|CLIENT[-_.]?SECRET|PASSWORD|PASSWD|PRIVATE[-_.]?KEY|SECRET|TOKEN)[A-Z0-9_.-]*\b"
    r"\s*[:=]\s*(?:\"([^\"\r\n]+)\"|'([^'\r\n]+)'|([^\s,;#]+))"
)
_BASIC_AUTH_URL_RE = re.compile(r"(?i)https?://[^\s/@:\"']+:[^\s/@\"']+@")
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Z0-9._~+/=-]{16,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}\b")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{30,255})\b")
_GOOGLE_API_KEY_RE = re.compile(r"\bAIza[A-Za-z0-9_-]{30,64}\b")
_OPENAI_KEY_RE = re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,255}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,255}\b")
_STRIPE_SECRET_RE = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,255}\b")
_PRIVATE_KEY_KINDS = (
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "DSA PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
)
_PRIVATE_KEY_MAX_BLOCK_BYTES = 256 * 1024

_ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_UTF16BE_STRING_RE = re.compile(rb"(?:\x00[\x20-\x7e]){4,}")

_PROVENANCE_FILENAMES = {
    "authors",
    "contributors",
    "copying",
    "copyright",
    "license",
    "maintainers",
    "notice",
    "third_party_notices.md",
}
_PROVENANCE_PARTS = {"_deps", "freeink-sdk", "licenses", "third_party", "vendor", "vendors"}


@dataclass(frozen=True, slots=True)
class Finding:
    category: str
    path: str
    rule: str
    line: int | None = None
    offset: int | None = None


@dataclass(frozen=True, slots=True)
class ScanResult:
    findings: tuple[Finding, ...]
    files_scanned: int
    bytes_scanned: int
    entries_seen: int
    truncated: bool

    @property
    def clean(self) -> bool:
        return not self.findings and not self.truncated


class ScannerConfigurationError(ValueError):
    """Raised for invalid paths, markers, or allowlist values."""


def _parse_list_value(raw: str, source_name: str) -> list[str]:
    raw = raw.strip()
    if not raw:
        return []
    if raw.startswith("["):
        try:
            decoded = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ScannerConfigurationError(f"{source_name} is not valid JSON") from error
        if not isinstance(decoded, list) or not all(isinstance(value, str) for value in decoded):
            raise ScannerConfigurationError(f"{source_name} must be a JSON string array")
        values = decoded
    else:
        values = raw.splitlines()
    return [value.strip() for value in values if value.strip()]


def _read_marker_file(path: Path) -> list[str]:
    try:
        if path.stat().st_size > 1024 * 1024:
            raise ScannerConfigurationError("forbidden-marker file is too large")
        return _parse_list_value(path.read_text(encoding="utf-8-sig"), "forbidden-marker file")
    except OSError as error:
        raise ScannerConfigurationError("forbidden-marker file cannot be read") from error
    except UnicodeError as error:
        raise ScannerConfigurationError("forbidden-marker file must be UTF-8") from error


def _validate_markers(values: Iterable[str]) -> tuple[str, ...]:
    normalized: dict[str, str] = {}
    for raw in values:
        marker = raw.strip()
        if len(marker) < 3:
            raise ScannerConfigurationError("forbidden markers must contain at least three characters")
        if any(ord(character) < 0x20 for character in marker):
            raise ScannerConfigurationError("forbidden markers cannot contain control characters")
        normalized.setdefault(marker.casefold(), marker)
    return tuple(normalized[key] for key in sorted(normalized))


def _canonical_worker_url(raw: str) -> str:
    try:
        parsed = urlsplit(raw.strip())
    except ValueError as error:
        raise ScannerConfigurationError("allowed Worker URL is invalid") from error
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if (
        parsed.scheme.lower() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or not hostname.endswith(".workers.dev")
    ):
        raise ScannerConfigurationError("allowed Worker URLs must be exact HTTPS workers.dev URLs")
    path = parsed.path or ""
    return urlunsplit(("https", hostname, path, parsed.query, ""))


def _canonical_email(raw: str) -> str:
    value = raw.strip().lower()
    match = _EMAIL_RE.fullmatch(value)
    if match is None:
        raise ScannerConfigurationError("allowed email is invalid")
    return value


def _strip_url_punctuation(raw: str) -> str:
    return raw.rstrip(".,;:!?)]}")


def _is_safe_example_email(email: str) -> bool:
    domain = email.rsplit("@", 1)[1].lower().rstrip(".")
    return domain in {"example.com", "example.net", "example.org", "localhost"} or domain.endswith(
        (".example", ".invalid", ".localhost", ".test")
    )


def _is_placeholder_secret(value: str) -> bool:
    candidate = value.strip().strip("\"'")
    folded = candidate.casefold()
    if not candidate:
        return True
    if candidate.startswith(("<", "${", "{{")) and candidate.endswith((">", "}", "}}")):
        return True
    placeholder_terms = (
        "changeme",
        "dummy",
        "example",
        "not-a-real",
        "placeholder",
        "redacted",
        "replace",
        "sample",
        "synthetic",
        "test-only",
        "your_",
        "your-",
    )
    if any(term in folded for term in placeholder_terms):
        return True
    return len(candidate) >= 8 and len(set(candidate.casefold())) == 1


def _is_reparse(stat_result: os.stat_result) -> bool:
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(attributes & _REPARSE_ATTRIBUTE)


def _is_email_provenance_path(relative_path: str) -> bool:
    parts = [part.casefold() for part in PurePosixPath(relative_path).parts]
    if any(part in _PROVENANCE_PARTS for part in parts[:-1]):
        return True
    if not parts:
        return False
    filename = parts[-1]
    stem = filename.split(".", 1)[0]
    return filename in _PROVENANCE_FILENAMES or stem in _PROVENANCE_FILENAMES


def _is_third_party_path(relative_path: str) -> bool:
    parts = [part.casefold() for part in PurePosixPath(relative_path).parts]
    joined = "/".join(parts)
    return (
        any(part in _PROVENANCE_PARTS for part in parts[:-1])
        or "/lib/expat/" in f"/{joined}/"
        or "/builtinfonts/source/" in f"/{joined}/"
        or "/docs/images/comparison/" in f"/{joined}/"
        or "/web/assets/fonts/" in f"/{joined}/"
    )


def _is_localization_catalog(relative_path: str) -> bool:
    parts = [part.casefold() for part in PurePosixPath(relative_path).parts]
    return "translations" in parts and PurePosixPath(relative_path).suffix.casefold() in {
        ".yaml", ".yml"
    }


def _is_synthetic_worker_fixture(candidate: str, relative_path: str) -> bool:
    parts = [part.casefold() for part in PurePosixPath(relative_path).parts]
    filename = parts[-1] if parts else ""
    test_context = "test" in parts or "tests" in parts or filename.startswith("test")
    folded = candidate.casefold()
    return test_context and (
        "reader.account.workers.dev" in folded or
        folded.rstrip("/") == "https://" + "account.workers.dev"
    )


def _is_synthetic_personal_path(value: str) -> bool:
    normalized = re.sub(r"/+", "/", value.replace("\\", "/")).casefold()
    return re.search(r"/(?:users|home)/(?:person|user|username)(?:/|$)", normalized) is not None


def _is_personal_path_match(rule: str, value: str) -> bool:
    normalized = re.sub(r"/+", "/", value.replace("\\", "/")).casefold()
    if _is_synthetic_personal_path(value):
        return False
    if rule in {"windows_absolute_path", "windows_unc_path"}:
        return re.search(r"/users/[a-z0-9._-]+", normalized) is not None
    if rule == "posix_personal_path" and value.startswith("/users/"):
        # A lowercase users route is commonly an HTTP API path. macOS home
        # directory spelling is case-sensitive.
        return False
    return True


def _is_unquoted_secret_candidate(value: str) -> bool:
    candidate = value.strip().rstrip(",;")
    folded = candidate.casefold()
    if len(candidate) < 16 or folded in {"false", "none", "null", "nullptr", "true"}:
        return False
    if re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", candidate):
        return False
    if any(character in candidate for character in "()[]{}<>") or "::" in candidate:
        return False
    return re.fullmatch(r"[A-Za-z0-9._~+/=-]+", candidate) is not None


class ReleaseScanner:
    def __init__(
        self,
        *,
        forbidden_markers: Sequence[str] = (),
        allowed_worker_urls: Sequence[str] = (),
        allowed_emails: Sequence[str] = (),
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_findings: int = DEFAULT_MAX_FINDINGS,
        max_binary_strings: int = DEFAULT_MAX_BINARY_STRINGS,
    ) -> None:
        if max_file_bytes < 1:
            raise ScannerConfigurationError("max-file-bytes must be positive")
        if max_findings < 1:
            raise ScannerConfigurationError("max-findings must be positive")
        if max_binary_strings < 1:
            raise ScannerConfigurationError("max-binary-strings must be positive")
        self.forbidden_markers = _validate_markers(forbidden_markers)
        self._folded_markers = tuple(marker.casefold() for marker in self.forbidden_markers)
        self.allowed_worker_urls = frozenset(_canonical_worker_url(url) for url in allowed_worker_urls)
        self.allowed_emails = frozenset(_canonical_email(email) for email in allowed_emails)
        self.max_file_bytes = max_file_bytes
        self.max_findings = max_findings
        self.max_binary_strings = max_binary_strings
        self._findings: list[Finding] = []
        self._finding_keys: set[tuple[object, ...]] = set()
        self._truncated = False
        self._files_scanned = 0
        self._bytes_scanned = 0
        self._entries_seen = 0

    def scan(self, paths: Sequence[Path]) -> ScanResult:
        if not paths:
            raise ScannerConfigurationError("at least one scan path is required")
        for raw_path in paths:
            path = Path(raw_path)
            if not path.exists() and not path.is_symlink():
                raise ScannerConfigurationError("scan path does not exist")
            display = path.name or "."
            self._scan_root(path, display if path.is_file() or path.is_symlink() else "")
        findings = tuple(
            sorted(
                self._findings,
                key=lambda item: (
                    item.path.casefold(),
                    item.line if item.line is not None else 2**31,
                    item.offset if item.offset is not None else 2**63,
                    item.category,
                    item.rule,
                ),
            )
        )
        return ScanResult(
            findings=findings,
            files_scanned=self._files_scanned,
            bytes_scanned=self._bytes_scanned,
            entries_seen=self._entries_seen,
            truncated=self._truncated,
        )

    def scan_manifest(self, members: Sequence[tuple[Path, str]]) -> ScanResult:
        """Scan an explicit release allowlist while preserving archive paths."""
        if not members:
            raise ScannerConfigurationError("release manifest has no files")
        seen: set[str] = set()
        for raw_path, raw_relative in members:
            path = Path(raw_path)
            relative_path = PurePosixPath(raw_relative)
            relative = relative_path.as_posix()
            if (relative_path.is_absolute() or relative in {"", "."} or
                    ".." in relative_path.parts or "\\" in raw_relative):
                raise ScannerConfigurationError("release manifest contains an unsafe path")
            folded = relative.casefold()
            if folded in seen:
                raise ScannerConfigurationError("release manifest contains a duplicate path")
            seen.add(folded)
            try:
                before = path.lstat()
            except OSError as error:
                raise ScannerConfigurationError("release manifest file is unavailable") from error
            self._entries_seen += 1
            if path.is_symlink() or _is_reparse(before) or not stat.S_ISREG(before.st_mode):
                self._add("filesystem", relative, "manifest_file_missing_linked_or_special")
                continue
            self._scan_relative_path(relative)
            self._scan_file(path, relative, before)
        findings = tuple(
            sorted(
                self._findings,
                key=lambda item: (
                    item.path.casefold(),
                    item.line if item.line is not None else 2**31,
                    item.offset if item.offset is not None else 2**63,
                    item.category,
                    item.rule,
                ),
            )
        )
        return ScanResult(
            findings=findings,
            files_scanned=self._files_scanned,
            bytes_scanned=self._bytes_scanned,
            entries_seen=self._entries_seen,
            truncated=self._truncated,
        )

    def _add(
        self,
        category: str,
        path: str,
        rule: str,
        *,
        line: int | None = None,
        offset: int | None = None,
    ) -> None:
        key = (category, path, rule, line, offset)
        if key in self._finding_keys:
            return
        if len(self._findings) >= self.max_findings:
            self._truncated = True
            return
        self._finding_keys.add(key)
        self._findings.append(Finding(category, path or ".", rule, line, offset))

    def _scan_root(self, root: Path, display: str) -> None:
        try:
            root_stat = root.lstat()
        except OSError:
            self._add("filesystem", display or ".", "unreadable_entry")
            return
        self._entries_seen += 1
        if root.is_symlink() or _is_reparse(root_stat):
            self._add("filesystem", display or ".", "symlink_or_reparse_point")
            return
        if stat.S_ISREG(root_stat.st_mode):
            self._scan_relative_path(display)
            self._scan_file(root, display, root_stat)
            return
        if not stat.S_ISDIR(root_stat.st_mode):
            self._add("filesystem", display or ".", "special_file")
            return

        stack: list[tuple[Path, str]] = [(root, "")]
        while stack:
            directory, prefix = stack.pop()
            try:
                with os.scandir(directory) as iterator:
                    entries = sorted(iterator, key=lambda entry: entry.name.casefold())
            except OSError:
                self._add("filesystem", prefix or ".", "unreadable_directory")
                continue
            child_directories: list[tuple[Path, str]] = []
            for entry in entries:
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                relative = PurePosixPath(relative).as_posix()
                self._entries_seen += 1
                try:
                    entry_stat = entry.stat(follow_symlinks=False)
                except OSError:
                    self._add("filesystem", relative, "unreadable_entry")
                    continue
                if entry.is_symlink() or _is_reparse(entry_stat):
                    self._add("filesystem", relative, "symlink_or_reparse_point")
                    continue
                self._scan_relative_path(relative)
                if stat.S_ISDIR(entry_stat.st_mode):
                    if entry.name.casefold() in _RISKY_DIRECTORY_NAMES:
                        self._add("risky_path", relative, "risky_directory")
                        continue
                    child_directories.append((Path(entry.path), relative))
                elif stat.S_ISREG(entry_stat.st_mode):
                    self._scan_file(Path(entry.path), relative, entry_stat)
                else:
                    self._add("filesystem", relative, "special_file")
            stack.extend(reversed(child_directories))

    def _scan_relative_path(self, relative: str) -> None:
        path = PurePosixPath(relative)
        filename = path.name.casefold()
        if filename and filename not in _SAFE_TEMPLATE_FILENAMES:
            risky_suffix = next((suffix for suffix in _RISKY_SUFFIXES if filename.endswith(suffix)), None)
            third_party_public_key = _is_third_party_path(relative) and risky_suffix in {".pem", ".key"}
            if filename in _RISKY_EXACT_FILENAMES or (
                risky_suffix is not None and filename not in _SAFE_EVIDENCE_FILENAMES and
                not third_party_public_key
            ):
                self._add("risky_path", relative, "risky_filename")
            elif filename.startswith((".dev.vars.", ".env.")):
                self._add("risky_path", relative, "environment_file")
            elif _RISKY_CREDENTIAL_FILENAME_RE.fullmatch(filename):
                self._add("risky_path", relative, "credential_filename")
        folded = relative.casefold()
        for index, marker in enumerate(self._folded_markers, start=1):
            if marker in folded:
                self._add("forbidden_marker", relative, f"extra_marker_{index}_in_path")
        for match in _EMAIL_RE.finditer(relative):
            self._check_email(match.group(1), relative, None, provenance=False)

    def _scan_file(self, path: Path, relative: str, before: os.stat_result) -> None:
        if before.st_size > self.max_file_bytes:
            self._add("scan_incomplete", relative, "file_exceeds_max_file_bytes")
            return
        try:
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            try:
                opened_stat = os.fstat(descriptor)
                if _is_reparse(opened_stat) or not stat.S_ISREG(opened_stat.st_mode):
                    self._add("filesystem", relative, "file_changed_or_reparse_point")
                    return
                # Windows directory-entry metadata and handle metadata can expose
                # different synthetic inode values for the same file.  The
                # no-follow/reparse checks plus the size/mtime recheck below are
                # the stable Windows guard; inode identity remains useful on
                # POSIX where O_NOFOLLOW is available.
                if os.name != "nt" and (before.st_dev, before.st_ino) != (opened_stat.st_dev, opened_stat.st_ino):
                    self._add("filesystem", relative, "file_changed_during_scan")
                    return
                chunks: list[bytes] = []
                total = 0
                while True:
                    chunk = os.read(descriptor, min(1024 * 1024, self.max_file_bytes + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.max_file_bytes:
                        self._add("scan_incomplete", relative, "file_grew_beyond_max_file_bytes")
                        return
                    chunks.append(chunk)
                data = b"".join(chunks)
                final_stat = os.fstat(descriptor)
                if final_stat.st_size != opened_stat.st_size or final_stat.st_mtime_ns != opened_stat.st_mtime_ns:
                    self._add("filesystem", relative, "file_changed_during_scan")
                    return
            finally:
                os.close(descriptor)
        except OSError:
            self._add("filesystem", relative, "unreadable_file")
            return

        self._files_scanned += 1
        self._bytes_scanned += len(data)
        self._scan_raw_for_forbidden_markers(data, relative)
        self._scan_raw_for_private_key_blocks(data, relative)
        provenance = _is_email_provenance_path(relative) or _is_third_party_path(relative)
        text, is_binary = self._decode_text(data, path.suffix.casefold())
        if not is_binary and text is not None:
            self._scan_text(text, relative, provenance=provenance)
        else:
            self._scan_binary_strings(data, relative, provenance=provenance)

    @staticmethod
    def _decode_text(data: bytes, suffix: str) -> tuple[str | None, bool]:
        if suffix in _BINARY_EXTENSIONS:
            return None, True
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            try:
                return data.decode("utf-16"), False
            except UnicodeError:
                return None, True
        if b"\x00" in data:
            return None, True
        try:
            decoded = data.decode("utf-8-sig")
        except UnicodeError:
            return None, True
        if not decoded:
            return decoded, False
        printable = sum(character.isprintable() or character in "\r\n\t" for character in decoded)
        return (decoded, False) if printable / len(decoded) >= 0.85 else (None, True)

    def _scan_raw_for_forbidden_markers(self, data: bytes, relative: str) -> None:
        lower_data = data.lower()
        for index, marker in enumerate(self.forbidden_markers, start=1):
            encodings = (
                marker.encode("utf-8"),
                marker.encode("utf-16-le"),
                marker.encode("utf-16-be"),
            )
            for encoding_index, encoded in enumerate(encodings):
                position = lower_data.find(encoded.lower())
                if position >= 0:
                    self._add(
                        "forbidden_marker",
                        relative,
                        f"extra_marker_{index}_encoding_{encoding_index + 1}",
                        offset=position,
                    )
                    break

    def _scan_raw_for_private_key_blocks(self, data: bytes, relative: str) -> None:
        for label, encoding in (
            ("ascii", "ascii"),
            ("utf16le", "utf-16-le"),
            ("utf16be", "utf-16-be"),
        ):
            for kind in _PRIVATE_KEY_KINDS:
                begin = f"-----BEGIN {kind}-----".encode(encoding)
                end = f"-----END {kind}-----".encode(encoding)
                cursor = 0
                while True:
                    start = data.find(begin, cursor)
                    if start < 0:
                        break
                    limit = min(len(data), start + _PRIVATE_KEY_MAX_BLOCK_BYTES)
                    finish = data.find(end, start + len(begin), limit)
                    if finish >= 0:
                        raw_body = data[start + len(begin):finish]
                        try:
                            body = raw_body.decode(encoding)
                        except UnicodeError:
                            body = ""
                        compact = "".join(body.split())
                        if len(compact) >= 64 and re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
                            self._add(
                                "secret",
                                relative,
                                f"private_key_block_{label}",
                                offset=start,
                            )
                    cursor = start + len(begin)

    def _scan_binary_strings(self, data: bytes, relative: str, *, provenance: bool) -> None:
        count = 0
        patterns = (
            ("ascii", _ASCII_STRING_RE, "ascii"),
            ("utf16le", _UTF16LE_STRING_RE, "utf-16-le"),
            ("utf16be", _UTF16BE_STRING_RE, "utf-16-be"),
        )
        for label, pattern, encoding in patterns:
            for match in pattern.finditer(data):
                count += 1
                if count > self.max_binary_strings:
                    self._add("scan_incomplete", relative, "too_many_binary_strings")
                    return
                try:
                    text = match.group(0).decode(encoding)
                except UnicodeError:
                    continue
                self._scan_text(
                    text,
                    relative,
                    base_offset=match.start(),
                    binary_label=label,
                    provenance=provenance,
                )

    def _scan_text(
        self,
        text: str,
        relative: str,
        *,
        base_offset: int | None = None,
        binary_label: str | None = None,
        provenance: bool,
    ) -> None:
        def location(start: int) -> tuple[int | None, int | None]:
            if base_offset is None:
                return text.count("\n", 0, start) + 1, None
            return None, base_offset + start

        def add_match(category: str, rule: str, start: int) -> None:
            line, offset = location(start)
            if binary_label is not None:
                rule = f"{rule}_{binary_label}"
            self._add(category, relative, rule, line=line, offset=offset)

        folded = text.casefold()
        scanner_self_test = PurePosixPath(relative).as_posix().casefold().endswith(
            "tests/test_sanitize_public_release.py"
        )
        for index, marker in enumerate(self._folded_markers, start=1):
            position = folded.find(marker)
            if position >= 0:
                add_match("forbidden_marker", f"extra_marker_{index}", position)

        for match in _LIVE_WORKER_URL_RE.finditer(text):
            if scanner_self_test:
                continue
            candidate = _strip_url_punctuation(match.group(0))
            if _is_synthetic_worker_fixture(candidate, relative):
                continue
            try:
                canonical = _canonical_worker_url(candidate)
            except ScannerConfigurationError:
                canonical = ""
            if canonical not in self.allowed_worker_urls:
                add_match("live_endpoint", "unallowlisted_workers_dev_url", match.start())

        for match in _EMAIL_RE.finditer(text):
            if scanner_self_test:
                continue
            line, offset = location(match.start())
            self._check_email(match.group(1), relative, line, offset=offset, provenance=provenance)

        if not provenance and not scanner_self_test:
            for regex, rule in (
                (_WINDOWS_ABSOLUTE_PATH_RE, "windows_absolute_path"),
                (_WINDOWS_UNC_PATH_RE, "windows_unc_path"),
                (_POSIX_PERSONAL_PATH_RE, "posix_personal_path"),
                (_WSL_PERSONAL_PATH_RE, "wsl_personal_path"),
            ):
                for match in regex.finditer(text):
                    if _is_personal_path_match(rule, match.group(0)):
                        add_match("personal_path", rule, match.start())

            for regex, rule in (
                (_BASIC_AUTH_URL_RE, "url_embedded_credentials"),
                (_BEARER_RE, "bearer_credential"),
                (_JWT_RE, "jwt_like_token"),
                (_AWS_ACCESS_KEY_RE, "aws_access_key"),
                (_GITHUB_TOKEN_RE, "github_token"),
                (_GOOGLE_API_KEY_RE, "google_api_key"),
                (_OPENAI_KEY_RE, "openai_key"),
                (_SLACK_TOKEN_RE, "slack_token"),
                (_STRIPE_SECRET_RE, "stripe_secret"),
            ):
                for match in regex.finditer(text):
                    add_match("secret", rule, match.start())

            if not _is_localization_catalog(relative):
                for match in _GENERIC_SECRET_ASSIGNMENT_RE.finditer(text):
                    value = next((group for group in match.groups() if group is not None), "")
                    unquoted = match.group(3) is not None
                    if unquoted and PurePosixPath(relative).suffix.casefold() in _CODE_SOURCE_SUFFIXES:
                        continue
                    if (not unquoted or _is_unquoted_secret_candidate(value)) and not _is_placeholder_secret(value):
                        add_match("secret", "credential_assignment", match.start())

    def _check_email(
        self,
        raw_email: str,
        relative: str,
        line: int | None,
        *,
        offset: int | None = None,
        provenance: bool,
    ) -> None:
        email = raw_email.lower()
        if _is_safe_example_email(email) or email in self.allowed_emails or provenance:
            return
        self._add("personal_email", relative, "non_synthetic_email", line=line, offset=offset)


def scan_release(
    paths: Sequence[Path | str],
    *,
    forbidden_markers: Sequence[str] = (),
    allowed_worker_urls: Sequence[str] = (),
    allowed_emails: Sequence[str] = (),
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    max_binary_strings: int = DEFAULT_MAX_BINARY_STRINGS,
) -> ScanResult:
    scanner = ReleaseScanner(
        forbidden_markers=forbidden_markers,
        allowed_worker_urls=allowed_worker_urls,
        allowed_emails=allowed_emails,
        max_file_bytes=max_file_bytes,
        max_findings=max_findings,
        max_binary_strings=max_binary_strings,
    )
    return scanner.scan([Path(path) for path in paths])


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail a public release containing credentials, personal identifiers, live Worker URLs, or unsafe files.",
    )
    parser.add_argument("paths", nargs="+", type=Path, help="Release directory or file to scan")
    parser.add_argument(
        "--forbid",
        action="append",
        default=[],
        metavar="MARKER",
        help="Additional forbidden marker; prefer the environment or --forbid-file for private values",
    )
    parser.add_argument(
        "--forbid-file",
        action="append",
        default=[],
        type=Path,
        metavar="PATH",
        help="UTF-8 newline list or JSON string array of additional forbidden markers",
    )
    parser.add_argument(
        "--allow-synthetic-worker-url",
        action="append",
        default=[],
        metavar="HTTPS_URL",
        help="Allow one exact synthetic workers.dev URL; paths are significant",
    )
    parser.add_argument(
        "--allow-email",
        action="append",
        default=[],
        metavar="EMAIL",
        help="Allow one reviewed public or third-party contact address",
    )
    parser.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_FILE_BYTES)
    parser.add_argument("--max-findings", type=int, default=DEFAULT_MAX_FINDINGS)
    parser.add_argument("--max-binary-strings", type=int, default=DEFAULT_MAX_BINARY_STRINGS)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable results without matched values")
    return parser


def _finding_dict(finding: Finding) -> dict[str, object]:
    return {key: value for key, value in asdict(finding).items() if value is not None}


def _emit_result(result: ScanResult, json_output: bool) -> None:
    if json_output:
        print(
            json.dumps(
                {
                    "clean": result.clean,
                    "files_scanned": result.files_scanned,
                    "bytes_scanned": result.bytes_scanned,
                    "entries_seen": result.entries_seen,
                    "findings_truncated": result.truncated,
                    "findings": [_finding_dict(finding) for finding in result.findings],
                },
                indent=2,
                sort_keys=True,
            )
        )
        return
    if result.clean:
        print(f"PASS: scanned {result.files_scanned} files and {result.bytes_scanned} bytes")
        return
    print(
        f"FAIL: {len(result.findings)} finding(s); scanned "
        f"{result.files_scanned} files and {result.bytes_scanned} bytes"
    )
    for finding in result.findings:
        location = finding.path
        if finding.line is not None:
            location += f":{finding.line}"
        elif finding.offset is not None:
            location += f"@{finding.offset}"
        print(f"- {finding.category}: {location} [{finding.rule}]")
    if result.truncated:
        print("- scan_incomplete: finding limit reached; no clean-release claim is possible")


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        markers = list(args.forbid)
        markers.extend(_parse_list_value(os.environ.get(FORBIDDEN_MARKERS_ENV, ""), FORBIDDEN_MARKERS_ENV))
        for marker_file in args.forbid_file:
            markers.extend(_read_marker_file(marker_file))

        allowed_worker_urls = list(args.allow_synthetic_worker_url)
        allowed_worker_urls.extend(
            _parse_list_value(os.environ.get(ALLOWED_WORKER_URLS_ENV, ""), ALLOWED_WORKER_URLS_ENV)
        )
        allowed_emails = list(args.allow_email)
        allowed_emails.extend(_parse_list_value(os.environ.get(ALLOWED_EMAILS_ENV, ""), ALLOWED_EMAILS_ENV))

        result = scan_release(
            args.paths,
            forbidden_markers=markers,
            allowed_worker_urls=allowed_worker_urls,
            allowed_emails=allowed_emails,
            max_file_bytes=args.max_file_bytes,
            max_findings=args.max_findings,
            max_binary_strings=args.max_binary_strings,
        )
    except ScannerConfigurationError as error:
        if args.json:
            print(json.dumps({"clean": False, "configuration_error": str(error)}, sort_keys=True))
        else:
            print(f"ERROR: {error}", file=sys.stderr)
        return 2
    _emit_result(result, args.json)
    return 0 if result.clean else 1


if __name__ == "__main__":
    raise SystemExit(main())
