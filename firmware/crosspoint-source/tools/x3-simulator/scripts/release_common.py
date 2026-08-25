#!/usr/bin/env python3
"""Shared, explicit public-package contract for X3 Preview & QA Lab."""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from typing import Iterable


RELEASE_PROFILE_PATH = Path(__file__).resolve().parent.parent / "release-profile.json"


def _load_release_profile() -> dict[str, object]:
    try:
        info = RELEASE_PROFILE_PATH.lstat()
    except FileNotFoundError as error:
        raise RuntimeError("release-profile.json is missing") from error
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & reparse_flag
    ) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("release-profile.json must be a regular non-linked file")
    try:
        profile = json.loads(RELEASE_PROFILE_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"release-profile.json is invalid: {error}") from error
    if not isinstance(profile, dict) or set(profile) != {
        "schema", "product", "version", "target", "firmware"
    }:
        raise RuntimeError("release-profile.json has an unsupported top-level contract")
    if profile.get("schema") != "x3-preview-release-profile/1":
        raise RuntimeError("release-profile.json has an unsupported schema")
    if profile.get("product") != "X3 Preview & QA Lab for Windows":
        raise RuntimeError("release-profile.json has an unexpected product")
    version = profile.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"0\.[0-9]+\.[0-9]+-alpha\.[1-9][0-9]*", version):
        raise RuntimeError("release-profile.json has an invalid alpha version")
    if profile.get("target") != {"model": "Xteink X3", "mcu": "ESP32-C3"}:
        raise RuntimeError("release-profile.json has an unsupported target")
    if profile.get("firmware") != {
        "bundled": True,
        "runtime_policy": "bundled-official-baseline-read-only",
        "preview_mode": "synthetic-modeled-demo",
        "device_access": "none",
        "baseline": {
            "project": "CrossPoint Reader",
            "version": "v1.5.0",
            "channel": "stable",
            "asset": "firmware-baseline/crosspoint-v1.5.0/firmware.bin",
            "byte_count": 5544112,
            "sha256": "a7087155757bc63c1fcf60ae8d60a3760ce6d3406aaf7b9f23d0025244434f08",
            "release_url": "https://github.com/crosspoint-reader/crosspoint-reader/releases/tag/v1.5.0",
            "download_url": "https://github.com/crosspoint-reader/crosspoint-reader/releases/download/v1.5.0/firmware.bin",
            "license": "MIT",
            "execution": "inspected-not-executed",
        },
    }:
        raise RuntimeError("release-profile.json has an unsupported firmware policy")
    return profile


RELEASE_PROFILE = _load_release_profile()
VERSION = str(RELEASE_PROFILE["version"])
PRODUCT_NAME = str(RELEASE_PROFILE["product"])
TARGET_PROFILE = dict(RELEASE_PROFILE["target"])
FIRMWARE_PROFILE = dict(RELEASE_PROFILE["firmware"])
FIRMWARE_BASELINE_PROFILE = dict(FIRMWARE_PROFILE["baseline"])
ARCHIVE_STEM = f"X3-Preview-QA-Lab-Windows-v{VERSION}"
ZIP_TIMESTAMP = (2026, 8, 25, 0, 0, 0)
PUBLIC_APPLICATION_ROOT = Path("app/firmware/crosspoint-source/tools/x3-simulator")
BUNDLED_FIRMWARE_SOURCE_RELATIVE = Path(str(FIRMWARE_BASELINE_PROFILE["asset"]))
BUNDLED_FIRMWARE_PUBLIC_RELATIVE = PUBLIC_APPLICATION_ROOT / BUNDLED_FIRMWARE_SOURCE_RELATIVE
BUNDLED_PYTHON_LICENSE_PUBLIC_RELATIVE = PUBLIC_APPLICATION_ROOT / "runtime/python/LICENSE.txt"
APPROVED_THIRD_PARTY_LICENSE_EMAILS = {
    BUNDLED_PYTHON_LICENSE_PUBLIC_RELATIVE.as_posix(): ("jseward@acm.org",),
}

ROOT_DOCUMENTS = (
    "README.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "BETA_TEST_CHECKLIST.md",
    "docs/DISTRIBUTION.md",
    "docs/FIRMWARE_TESTING.md",
    "docs/QEMU_SETUP.md",
)

APPLICATION_FILES = (
    "release-profile.json",
    "server.py",
    "network_fixture.py",
    "standalone_inputs.py",
    "run-x3-simulator.cmd",
    "fixtures/device.json",
    "fixtures/x3-resource-budgets.demo.json",
)

APPLICATION_TREES = (
    "web",
    "firmware-baseline",
)

TEXT_SUFFIXES = {
    "", ".cmd", ".css", ".html", ".js", ".json", ".md", ".mjs", ".py", ".txt"
}

FORBIDDEN_FILE_SUFFIXES = {
    ".bin", ".elf", ".hex", ".img", ".map", ".pem", ".pfx", ".uf2"
}

FORBIDDEN_PARTS = {
    ".git", ".runtime", "__pycache__", "artifacts", "build", "coverage",
    "dist", "node_modules"
}

FORBIDDEN_BASENAMES = {
    ".dev.vars", ".env", "sleep.bmp", "update.bin"
}

CONTENT_PATTERNS = (
    ("personal Windows user path", re.compile(r"(?i)[a-z]:[\\/]+users[\\/]+(?!public(?:[\\/]|$))")),
    ("Codex private path", re.compile(r"(?i)(?:[\\/]|^)\.codex(?:[\\/]|$)")),
    ("private build label", re.compile(r"(?i)ready\d+")),
    ("personal username placeholder", re.compile(r"(?i)\b(?:private-user|local-user)\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{30,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{20,}")),
    ("bearer token", re.compile(r"(?i)authorization\s*[:=]\s*bearer\s+[0-9A-Za-z._~+/-]{16,}")),
    ("email address", re.compile(r"(?i)\b[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b")),
)


def transform_public_text(relative: Path, value: str) -> str:
    """Apply narrow public-demo substitutions without mutating firmware source."""

    normalized = relative.as_posix()
    if normalized.endswith("/network_fixture.py"):
        needle = '"title": task_id.replace("-", " ").title(),'
        replacement = (
            '"title": {\n'
            '            "market-briefing": "Sample Dashboard",\n'
            '            "weekday-freelancer-scan": "Sample Opportunity Scan",\n'
            '            "3d-job-search": "Sample Project Search",\n'
            '            "outlook-attention-watch": "Sample Message Triage",\n'
            '        }[task_id],'
        )
        if value.count(needle) != 1:
            raise RuntimeError("Public network fixture title seam drifted")
        value = value.replace(needle, replacement)
    return value


def is_link_or_reparse(path: Path) -> bool:
    info = path.lstat()
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & reparse_flag
    )


def require_plain_directory(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    info = resolved.lstat()
    if is_link_or_reparse(resolved) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{label} must be a real directory, not a link or reparse point: {resolved}")
    return resolved


def require_plain_file(path: Path, label: str) -> Path:
    resolved = path.resolve(strict=True)
    info = resolved.lstat()
    if is_link_or_reparse(resolved) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{label} must be a regular non-linked file: {resolved}")
    return resolved


def is_within(candidate: Path, boundary: Path) -> bool:
    try:
        return os.path.commonpath((str(candidate.resolve()), str(boundary.resolve()))) == str(boundary.resolve())
    except ValueError:
        return False


def iter_plain_tree(root: Path) -> Iterable[Path]:
    root = require_plain_directory(root, "Release tree")
    for candidate in sorted(root.rglob("*"), key=lambda value: value.as_posix().casefold()):
        if is_link_or_reparse(candidate):
            raise RuntimeError(f"Release tree contains a link or reparse point: {candidate}")
        if candidate.is_file():
            yield candidate
        elif not candidate.is_dir():
            raise RuntimeError(f"Release tree contains a special file: {candidate}")


def validate_public_path(relative: Path, *, bundled_runtime: bool = False) -> list[str]:
    problems: list[str] = []
    bundled_firmware = relative.as_posix() == BUNDLED_FIRMWARE_PUBLIC_RELATIVE.as_posix()
    lowered_parts = {part.casefold() for part in relative.parts}
    blocked_parts = {part.casefold() for part in FORBIDDEN_PARTS}
    if lowered_parts & blocked_parts:
        problems.append("forbidden generated/private directory")
    if relative.name.casefold() in {name.casefold() for name in FORBIDDEN_BASENAMES}:
        problems.append("forbidden private or device-bound file")
    if relative.suffix.casefold() in FORBIDDEN_FILE_SUFFIXES and not bundled_firmware:
        problems.append("firmware/build/secret file type")
    if not bundled_runtime and "runtime" in lowered_parts:
        problems.append("runtime present in a source-portable package")
    return problems


def scan_text(path: Path, relative: Path) -> list[str]:
    if path.suffix.casefold() not in TEXT_SUFFIXES:
        return []
    try:
        value = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [f"{relative.as_posix()}: text file is not valid UTF-8"]
    return scan_text_value(value, relative)


def scan_text_value(value: str, relative: Path) -> list[str]:
    normalized = relative.as_posix()
    for approved_path, approved_addresses in APPROVED_THIRD_PARTY_LICENSE_EMAILS.items():
        if normalized == approved_path or normalized.endswith(f"/{approved_path}"):
            for address in approved_addresses:
                value = value.replace(address, "[approved upstream license contact]")
    findings: list[str] = []
    for label, pattern in CONTENT_PATTERNS:
        if pattern.search(value):
            findings.append(f"{relative.as_posix()}: {label}")
    return findings
