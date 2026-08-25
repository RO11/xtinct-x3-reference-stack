#!/usr/bin/env python3
"""Sanitize the explicit public source set or a built portable archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import zipfile
from pathlib import Path

from release_common import (
    APPLICATION_FILES,
    APPLICATION_TREES,
    BUNDLED_FIRMWARE_PUBLIC_RELATIVE,
    BUNDLED_FIRMWARE_SOURCE_RELATIVE,
    FIRMWARE_BASELINE_PROFILE,
    PUBLIC_APPLICATION_ROOT,
    ROOT_DOCUMENTS,
    VERSION,
    is_link_or_reparse,
    iter_plain_tree,
    require_plain_directory,
    require_plain_file,
    scan_text_value,
    transform_public_text,
    validate_public_path,
)


SCRIPT_ROOT = Path(__file__).resolve().parent
DEFAULT_SOURCE = SCRIPT_ROOT.parent
APP_RELATIVE_ROOT = PUBLIC_APPLICATION_ROOT
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 64 * 1024 * 1024


def _source_map(source_root: Path) -> list[tuple[Path, Path]]:
    source_root = require_plain_directory(source_root, "Simulator source")
    result: list[tuple[Path, Path]] = []
    for relative_name in ROOT_DOCUMENTS:
        result.append((source_root / relative_name, Path(relative_name)))
    result.append((source_root / "scripts/portable-root-launcher.cmd", Path("Launch X3 Preview QA Lab.cmd")))
    for relative_name in APPLICATION_FILES:
        result.append((source_root / relative_name, APP_RELATIVE_ROOT / relative_name))
    for relative_name in APPLICATION_TREES:
        tree = require_plain_directory(source_root / relative_name, "Public application tree")
        for file_path in iter_plain_tree(tree):
            result.append((file_path, APP_RELATIVE_ROOT / relative_name / file_path.relative_to(tree)))
    return result


def scan_source(source_root: Path) -> list[str]:
    findings: list[str] = []
    seen: set[str] = set()
    for source_path, public_relative in _source_map(source_root):
        source_path = require_plain_file(source_path, "Public release source")
        public_name = public_relative.as_posix()
        if public_name in seen:
            findings.append(f"{public_name}: duplicate public destination")
            continue
        seen.add(public_name)
        for problem in validate_public_path(public_relative, bundled_runtime=False):
            findings.append(f"{public_name}: {problem}")
        if source_path.suffix.casefold() in {"", ".cmd", ".css", ".html", ".js", ".json", ".md", ".mjs", ".py", ".txt"}:
            value = source_path.read_text(encoding="utf-8")
            findings.extend(scan_text_value(transform_public_text(public_relative, value), public_relative))

    package_path = source_root / "package.json"
    try:
        package_text = package_path.read_text(encoding="utf-8")
        package = json.loads(package_text)
    except (OSError, json.JSONDecodeError) as error:
        findings.append(f"package.json: invalid JSON: {error}")
    else:
        findings.extend(scan_text_value(package_text, Path("package.json")))
        if package.get("name") != "x3-preview-qa-lab":
            findings.append("package.json: unexpected public package name")
        if package.get("version") != VERSION:
            findings.append("package.json: version differs from release contract")
        if package.get("private") is True:
            findings.append("package.json: private must not be true for the public alpha")
        if "repository" in package:
            findings.append("package.json: repository must not imply ownership by an upstream project")
    baseline_path = source_root / BUNDLED_FIRMWARE_SOURCE_RELATIVE
    try:
        baseline_path = require_plain_file(baseline_path, "Bundled CrossPoint baseline")
    except (OSError, RuntimeError) as error:
        findings.append(f"bundled firmware: {error}")
    else:
        expected_bytes = int(FIRMWARE_BASELINE_PROFILE["byte_count"])
        if baseline_path.stat().st_size != expected_bytes:
            findings.append("bundled firmware: byte count differs from release profile")
        digest = hashlib.sha256(baseline_path.read_bytes()).hexdigest()
        if digest != FIRMWARE_BASELINE_PROFILE["sha256"]:
            findings.append("bundled firmware: SHA-256 differs from release profile")
    return findings


def scan_archive(archive_path: Path) -> list[str]:
    archive_path = require_plain_file(archive_path, "Portable archive")
    findings: list[str] = []
    try:
        with zipfile.ZipFile(archive_path, "r") as source:
            infos = source.infolist()
            if source.testzip() is not None:
                findings.append("archive: failed ZIP CRC validation")
            if sum(info.file_size for info in infos) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                findings.append("archive: uncompressed payload exceeds the public package limit")
            names: set[str] = set()
            bundled_firmware_seen = False
            for info in infos:
                relative = Path(info.filename)
                if info.filename in names:
                    findings.append(f"archive: duplicate entry {info.filename}")
                names.add(info.filename)
                if info.filename.startswith(("/", "\\")) or ".." in relative.parts:
                    findings.append(f"archive: unsafe entry path {info.filename}")
                    continue
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    findings.append(f"archive: linked entry {info.filename}")
                stripped_parts = relative.parts[1:] if len(relative.parts) > 1 else relative.parts
                public_relative = Path(*stripped_parts)
                for problem in validate_public_path(
                    public_relative,
                    bundled_runtime="bundled-python" in relative.parts[0] if relative.parts else False,
                ):
                    findings.append(f"{info.filename}: {problem}")
                if public_relative.as_posix() == BUNDLED_FIRMWARE_PUBLIC_RELATIVE.as_posix():
                    bundled_firmware_seen = True
                    payload = source.read(info)
                    if len(payload) != int(FIRMWARE_BASELINE_PROFILE["byte_count"]):
                        findings.append(f"{info.filename}: bundled firmware byte count mismatch")
                    if hashlib.sha256(payload).hexdigest() != FIRMWARE_BASELINE_PROFILE["sha256"]:
                        findings.append(f"{info.filename}: bundled firmware SHA-256 mismatch")
                if public_relative.suffix.casefold() in {"", ".cmd", ".css", ".html", ".js", ".json", ".md", ".mjs", ".py", ".txt"}:
                    try:
                        text_value = source.read(info).decode("utf-8")
                    except UnicodeDecodeError:
                        findings.append(f"{info.filename}: text file is not valid UTF-8")
                        continue
                    findings.extend(scan_text_value(text_value, Path(info.filename)))
            if not any(name.endswith("/FILES.SHA256") for name in names):
                findings.append("archive: internal FILES.SHA256 is missing")
            if not any(name.endswith("/release-metadata.json") for name in names):
                findings.append("archive: release-metadata.json is missing")
            if not bundled_firmware_seen:
                findings.append("archive: bundled CrossPoint baseline is missing")
    except zipfile.BadZipFile as error:
        findings.append(f"archive: invalid ZIP: {error}")
    return findings


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--archive", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    findings = scan_source(arguments.source)
    if arguments.archive:
        findings.extend(scan_archive(arguments.archive))
    report = {
        "schema": "x3-preview-qa-lab-sanitizer/1",
        "source": str(arguments.source.resolve()),
        "archive": str(arguments.archive.resolve()) if arguments.archive else None,
        "files_checked": len(_source_map(arguments.source)) + 1,
        "findings": sorted(set(findings)),
        "status": "PASS" if not findings else "FAIL",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
