#!/usr/bin/env python3
"""Build a deterministic, allowlisted Windows portable alpha archive."""

from __future__ import annotations

import argparse
import calendar
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from release_common import (
    APPLICATION_FILES,
    APPLICATION_TREES,
    ARCHIVE_STEM,
    BUNDLED_FIRMWARE_SOURCE_RELATIVE,
    FIRMWARE_PROFILE,
    FIRMWARE_BASELINE_PROFILE,
    PRODUCT_NAME,
    PUBLIC_APPLICATION_ROOT,
    RELEASE_PROFILE,
    ROOT_DOCUMENTS,
    TARGET_PROFILE,
    VERSION,
    ZIP_TIMESTAMP,
    is_link_or_reparse,
    is_within,
    iter_plain_tree,
    require_plain_directory,
    require_plain_file,
    scan_text,
    transform_public_text,
    validate_public_path,
)


SCRIPT_ROOT = Path(__file__).resolve().parent
SIMULATOR_ROOT = SCRIPT_ROOT.parent
QUARANTINE_DRIVES = ("D", "E")
APP_RELATIVE_ROOT = PUBLIC_APPLICATION_ROOT
ROOT_LAUNCHER_NAME = "Launch X3 Preview QA Lab.cmd"
MAX_PACKAGE_BYTES = 64 * 1024 * 1024
PUBLIC_PAYLOAD_DIGEST_ALGORITHM = "sha256-path-length-content-v1"
PUBLIC_PAYLOAD_EXCLUSIONS = frozenset({"FILES.SHA256", "release-metadata.json"})
PYTHON_RUNTIME_DIGEST_ALGORITHM = "sha256-path-length-content-v1-domain-x3-preview-python-runtime-v1"
PYTHON_RUNTIME_PTH = (
    b"python314.zip\r\n"
    b".\r\n"
    b"../../..\r\n"
    b"\r\n"
    b"# Uncomment to run site.main() automatically\r\n"
    b"#import site\r\n"
)
PYTHON_RUNTIME_PROFILE = {
    "implementation": "CPython",
    "version": "3.14.7",
    "architecture": "amd64",
    "distribution": "Windows embeddable package",
    "archive": "python-3.14.7-embed-amd64.zip",
    "archive_byte_count": 12673227,
    "archive_sha256": "d297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15",
    "source_url": "https://www.python.org/ftp/python/3.14.7/python-3.14.7-embed-amd64.zip",
    "license": "Python Software Foundation License Version 2",
    "license_file": "runtime/python/LICENSE.txt",
    "tree_digest_algorithm": PYTHON_RUNTIME_DIGEST_ALGORITHM,
    "source_tree_sha256": "04cb0c29f815d844dac63b70a47b6905e0676fe03a5603c485b59a286c1f9f97",
    "packaged_tree_sha256": "73d86e9cc8dae5a0cf207b4b7364a092859679bf1478b920397b6c74bb17a665",
    "application_path_entry": "../../..",
    "site_import_enabled": False,
}
PYTHON_RUNTIME_REQUIRED_FILES = frozenset({
    "LICENSE.txt",
    "python.exe",
    "python3.dll",
    "python314._pth",
    "python314.dll",
    "python314.zip",
    "vcruntime140.dll",
})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _update_public_payload_digest(
    digest: hashlib._Hash,
    relative: str,
    content: bytes,
) -> None:
    encoded_path = relative.encode("utf-8")
    digest.update(len(encoded_path).to_bytes(8, "big"))
    digest.update(encoded_path)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)


def public_payload_sha256(stage_root: Path) -> str:
    """Hash the exact transformed package inputs, excluding generated metadata."""

    digest = hashlib.sha256()
    digest.update(b"x3-preview-public-payload-v1\0")
    for file_path in iter_plain_tree(stage_root):
        relative = file_path.relative_to(stage_root).as_posix()
        if relative in PUBLIC_PAYLOAD_EXCLUSIONS:
            continue
        _update_public_payload_digest(digest, relative, file_path.read_bytes())
    return digest.hexdigest()


def python_runtime_tree_sha256(runtime_root: Path) -> str:
    """Hash the exact reviewed embedded-runtime tree with domain separation."""

    runtime_root = require_plain_directory(runtime_root, "Bundled Python runtime")
    digest = hashlib.sha256()
    digest.update(b"x3-preview-python-runtime-v1\0")
    for file_path in iter_plain_tree(runtime_root):
        relative = file_path.relative_to(runtime_root).as_posix()
        _update_public_payload_digest(digest, relative, file_path.read_bytes())
    return digest.hexdigest()


def _git_result(*arguments: str) -> subprocess.CompletedProcess[str] | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(SIMULATOR_ROOT), *arguments],
            capture_output=True,
            check=False,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result if result.returncode == 0 else None


def _git_provenance() -> tuple[str | None, bool]:
    head_result = _git_result("rev-parse", "HEAD")
    head = head_result.stdout.strip().casefold() if head_result is not None else ""
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        head = ""

    root_result = _git_result("rev-parse", "--show-toplevel")
    if root_result is None:
        return (head or None, True)
    try:
        git_root = Path(root_result.stdout.strip()).resolve(strict=True)
        source_inputs = [
            *(SIMULATOR_ROOT / name for name in ROOT_DOCUMENTS),
            *(SIMULATOR_ROOT / name for name in APPLICATION_FILES),
            *(SIMULATOR_ROOT / name for name in APPLICATION_TREES),
            SIMULATOR_ROOT / "package.json",
            SCRIPT_ROOT / "build_portable.py",
            SCRIPT_ROOT / "portable-root-launcher.cmd",
            SCRIPT_ROOT / "release_common.py",
        ]
        pathspecs = [
            f":(top){path.resolve(strict=True).relative_to(git_root).as_posix()}"
            for path in source_inputs
        ]
    except (OSError, RuntimeError, ValueError):
        return (head or None, True)
    status_result = _git_result(
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
        *pathspecs,
    )
    if status_result is None:
        return (head or None, True)
    return (head or None, bool(status_result.stdout.strip()))


def _source_epoch(git_head: str | None) -> int:
    configured = os.environ.get("SOURCE_DATE_EPOCH")
    if configured is not None:
        if not re.fullmatch(r"[0-9]+", configured) or int(configured) <= 0:
            raise RuntimeError("SOURCE_DATE_EPOCH must be a positive integer")
        return int(configured)
    if git_head is not None:
        result = _git_result("show", "-s", "--format=%ct", git_head)
        if result is not None and re.fullmatch(r"[0-9]+", result.stdout.strip()):
            return int(result.stdout.strip())
    return calendar.timegm((*ZIP_TIMESTAMP, 0, 0, 0))


def _plain_parent_chain(path: Path, boundary: Path) -> None:
    boundary = require_plain_directory(boundary, "Packaging boundary")
    current = path.resolve(strict=True)
    if not is_within(current, boundary):
        raise RuntimeError(f"Path escapes the packaging boundary: {current}")
    while True:
        if is_link_or_reparse(current):
            raise RuntimeError(f"Packaging path contains a link or reparse point: {current}")
        if current == boundary:
            return
        current = current.parent


def _local_staging_boundary() -> Path:
    if os.environ.get("CI", "").casefold() == "true":
        runner_temp = os.environ.get("RUNNER_TEMP") or tempfile.gettempdir()
        boundary = Path(runner_temp)
        return require_plain_directory(boundary, "CI packaging staging directory")
    if os.name != "nt":
        return require_plain_directory(Path(tempfile.gettempdir()), "Packaging staging directory")

    for drive in QUARANTINE_DRIVES:
        drive_root = Path(f"{drive}:/")
        if not drive_root.exists():
            continue
        drive_root = require_plain_directory(drive_root, f"{drive}: drive root")
        boundary = drive_root / "quarantine"
        if not boundary.exists():
            boundary.mkdir()
        boundary = require_plain_directory(boundary, "Packaging staging directory")
        if boundary.parent != drive_root:
            raise RuntimeError(f"Quarantine path escaped the validated drive root: {boundary}")
        return boundary
    raise RuntimeError("Packaging requires a real D:\\quarantine or E:\\quarantine directory")


def _validate_output_directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    resolved = require_plain_directory(path, "Release output directory")
    workspace_release = (SIMULATOR_ROOT / "release").resolve()
    if os.environ.get("CI", "").casefold() == "true":
        return resolved
    if resolved != workspace_release:
        raise RuntimeError(
            f"Local builds may retain their final artifacts only in {workspace_release}"
        )
    return resolved


def _copy_plain_file(source: Path, destination: Path) -> None:
    source = require_plain_file(source, "Public release source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise RuntimeError(f"Duplicate package destination: {destination}")
    shutil.copyfile(source, destination)


def _copy_plain_tree(source: Path, destination: Path) -> None:
    source = require_plain_directory(source, "Public release source tree")
    for file_path in iter_plain_tree(source):
        _copy_plain_file(file_path, destination / file_path.relative_to(source))


def _validate_bundled_firmware(path: Path, label: str) -> Path:
    selected = require_plain_file(path, label)
    expected_bytes = int(FIRMWARE_BASELINE_PROFILE["byte_count"])
    expected_sha256 = str(FIRMWARE_BASELINE_PROFILE["sha256"])
    if selected.stat().st_size != expected_bytes:
        raise RuntimeError(
            f"{label} byte count differs from the frozen release profile: "
            f"{selected.stat().st_size} != {expected_bytes}"
        )
    actual_sha256 = sha256_file(selected)
    if actual_sha256 != expected_sha256:
        raise RuntimeError(
            f"{label} SHA-256 differs from the frozen release profile: {actual_sha256}"
        )
    return selected


def _validate_python_runtime(path: Path) -> Path:
    runtime = require_plain_directory(path, "Bundled Python runtime")
    present = {
        file_path.relative_to(runtime).as_posix()
        for file_path in iter_plain_tree(runtime)
    }
    missing = sorted(PYTHON_RUNTIME_REQUIRED_FILES.difference(present))
    if missing:
        raise RuntimeError(f"Bundled Python runtime is incomplete: {missing}")
    actual_digest = python_runtime_tree_sha256(runtime)
    if actual_digest != PYTHON_RUNTIME_PROFILE["source_tree_sha256"]:
        raise RuntimeError(
            "Bundled Python runtime differs from the reviewed CPython 3.14.7 tree: "
            f"{actual_digest}"
        )
    return runtime


def _configure_packaged_python_runtime(runtime: Path) -> None:
    runtime = require_plain_directory(runtime, "Packaged Python runtime")
    pth = require_plain_file(runtime / "python314._pth", "Packaged Python path file")
    pth.write_bytes(PYTHON_RUNTIME_PTH)
    actual_digest = python_runtime_tree_sha256(runtime)
    if actual_digest != PYTHON_RUNTIME_PROFILE["packaged_tree_sha256"]:
        raise RuntimeError(
            "Configured Python runtime differs from the frozen packaged tree: "
            f"{actual_digest}"
        )


def _copy_payload(stage_root: Path, python_runtime: Path | None) -> bool:
    for relative_name in ROOT_DOCUMENTS:
        source = SIMULATOR_ROOT / relative_name
        _copy_plain_file(source, stage_root / relative_name)

    _copy_plain_file(
        SCRIPT_ROOT / "portable-root-launcher.cmd",
        stage_root / ROOT_LAUNCHER_NAME,
    )

    application_root = stage_root / APP_RELATIVE_ROOT
    for relative_name in APPLICATION_FILES:
        _copy_plain_file(
            SIMULATOR_ROOT / relative_name,
            application_root / relative_name,
        )
    for relative_name in APPLICATION_TREES:
        _copy_plain_tree(
            SIMULATOR_ROOT / relative_name,
            application_root / relative_name,
        )
    _validate_bundled_firmware(
        application_root / BUNDLED_FIRMWARE_SOURCE_RELATIVE,
        "Bundled CrossPoint baseline",
    )

    if python_runtime is None:
        _transform_public_payload(stage_root)
        return False
    runtime = _validate_python_runtime(python_runtime)
    packaged_runtime = application_root / "runtime/python"
    _copy_plain_tree(runtime, packaged_runtime)
    _configure_packaged_python_runtime(packaged_runtime)
    _transform_public_payload(stage_root)
    return True


def _transform_public_payload(stage_root: Path) -> None:
    for file_path in iter_plain_tree(stage_root):
        relative = file_path.relative_to(stage_root)
        if file_path.suffix.casefold() not in {"", ".cmd", ".css", ".html", ".js", ".json", ".md", ".mjs", ".py", ".txt"}:
            continue
        value = file_path.read_text(encoding="utf-8")
        transformed = transform_public_text(relative, value)
        if transformed != value:
            file_path.write_text(transformed, encoding="utf-8", newline="\n")


def _metadata(
    stage_root: Path,
    distribution: str,
    bundled_runtime: bool,
) -> dict[str, object]:
    git_head, git_dirty = _git_provenance()
    demo_contract = (
        stage_root
        / APP_RELATIVE_ROOT
        / "fixtures/x3-resource-budgets.demo.json"
    )
    return {
        "schema": "x3-preview-qa-lab-release/2",
        "profile_schema": RELEASE_PROFILE["schema"],
        "product": PRODUCT_NAME,
        "version": VERSION,
        "target": TARGET_PROFILE,
        "firmware": FIRMWARE_PROFILE,
        "distribution": distribution,
        "bundled_runtime": bundled_runtime,
        "bundled_python": PYTHON_RUNTIME_PROFILE if bundled_runtime else None,
        "synthetic_demo": True,
        "firmware_included": True,
        "bundled_firmware": FIRMWARE_BASELINE_PROFILE,
        "qemu_runtime_included": False,
        "build_outputs_included": False,
        "outbound_network": "disabled",
        "bind_host": "127.0.0.1",
        "provenance": {
            "public_payload_sha256": public_payload_sha256(stage_root),
            "public_payload_algorithm": PUBLIC_PAYLOAD_DIGEST_ALGORITHM,
            "public_payload_scope": (
                "all transformed packaged inputs except release-metadata.json and FILES.SHA256"
            ),
            "builder_script_sha256": sha256_file(Path(__file__).resolve()),
            "demo_contract_sha256": sha256_file(demo_contract),
            "git_head": git_head,
            "dirty": git_dirty,
            "source_epoch": _source_epoch(git_head),
        },
        "evidence": [
            "MODELED",
            "REAL CONTRACT TEST (source checkout only)",
            "QEMU (not included)",
            "PHYSICAL DEVICE REQUIRED",
        ],
    }


def _scan_stage(stage_root: Path, bundled_runtime: bool) -> list[str]:
    findings: list[str] = []
    for file_path in iter_plain_tree(stage_root):
        relative = file_path.relative_to(stage_root)
        for problem in validate_public_path(relative, bundled_runtime=bundled_runtime):
            findings.append(f"{relative.as_posix()}: {problem}")
        findings.extend(scan_text(file_path, relative))
    return findings


def _write_internal_manifest(stage_root: Path) -> None:
    entries = []
    for file_path in iter_plain_tree(stage_root):
        relative = file_path.relative_to(stage_root).as_posix()
        if relative == "FILES.SHA256":
            continue
        entries.append(f"{sha256_file(file_path)}  {relative}")
    (stage_root / "FILES.SHA256").write_text("\n".join(entries) + "\n", encoding="utf-8", newline="\n")


def _zip_stage(stage_root: Path, archive: Path, package_root_name: str) -> None:
    if archive.exists():
        raise RuntimeError(f"Temporary archive unexpectedly exists: {archive}")
    total_bytes = sum(path.stat().st_size for path in iter_plain_tree(stage_root))
    if total_bytes > MAX_PACKAGE_BYTES:
        raise RuntimeError(f"Public payload is unexpectedly large: {total_bytes} bytes")
    with zipfile.ZipFile(
        archive,
        "w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as output:
        for file_path in iter_plain_tree(stage_root):
            relative = file_path.relative_to(stage_root).as_posix()
            info = zipfile.ZipInfo(f"{package_root_name}/{relative}", ZIP_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            with file_path.open("rb") as source:
                output.writestr(info, source.read(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def _verify_archive(archive: Path, package_root_name: str) -> dict[str, object]:
    archive = require_plain_file(archive, "Portable archive")
    with zipfile.ZipFile(archive, "r") as source:
        if source.testzip() is not None:
            raise RuntimeError("Portable archive failed its ZIP CRC test")
        names = source.namelist()
        if not names or len(names) != len(set(names)):
            raise RuntimeError("Portable archive has no files or contains duplicate paths")
        expected_prefix = f"{package_root_name}/"
        if any(not name.startswith(expected_prefix) for name in names):
            raise RuntimeError("Portable archive contains an entry outside its product root")
        if any(".." in Path(name).parts or name.startswith(("/", "\\")) for name in names):
            raise RuntimeError("Portable archive contains an unsafe path")
        required = {
            f"{expected_prefix}{ROOT_LAUNCHER_NAME}",
            f"{expected_prefix}README.md",
            f"{expected_prefix}FILES.SHA256",
            f"{expected_prefix}release-metadata.json",
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/server.py",
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/release-profile.json",
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/standalone_inputs.py",
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/fixtures/device.json",
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/fixtures/x3-resource-budgets.demo.json",
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/{BUNDLED_FIRMWARE_SOURCE_RELATIVE.as_posix()}",
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/firmware-baseline/crosspoint-v1.5.0/manifest.json",
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/firmware-baseline/crosspoint-v1.5.0/LICENSE.txt",
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/firmware-baseline/crosspoint-v1.5.0/README.md",
        }
        missing = sorted(required.difference(names))
        if missing:
            raise RuntimeError(f"Portable archive is missing required entries: {missing}")

        manifest_name = f"{expected_prefix}FILES.SHA256"
        manifest_lines = source.read(manifest_name).decode("utf-8").splitlines()
        manifest: dict[str, str] = {}
        for line in manifest_lines:
            digest, separator, relative = line.partition("  ")
            if not separator or len(digest) != 64 or relative in manifest:
                raise RuntimeError("Internal SHA-256 manifest is malformed")
            manifest[relative] = digest
        actual_names = {
            name.removeprefix(expected_prefix)
            for name in names
            if name != manifest_name and not name.endswith("/")
        }
        if set(manifest) != actual_names:
            raise RuntimeError("Internal SHA-256 manifest does not cover the exact payload")
        for relative, expected in manifest.items():
            actual = hashlib.sha256(source.read(f"{expected_prefix}{relative}")).hexdigest()
            if actual != expected:
                raise RuntimeError(f"Internal SHA-256 mismatch: {relative}")

        metadata = json.loads(source.read(f"{expected_prefix}release-metadata.json"))
        expected_bundled_runtime = package_root_name.endswith("-bundled-python")
        if metadata.get("distribution") != (
            "bundled-python" if expected_bundled_runtime else "source-portable"
        ):
            raise RuntimeError("Release metadata distribution differs from the archive name")
        if metadata.get("bundled_runtime") is not expected_bundled_runtime:
            raise RuntimeError("Release metadata bundled-runtime state is incorrect")
        runtime_prefix = (
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/runtime/python/"
        )
        runtime_names = sorted(
            (name for name in names if name.startswith(runtime_prefix)),
            key=str.casefold,
        )
        if expected_bundled_runtime:
            runtime_relatives = {
                name.removeprefix(runtime_prefix) for name in runtime_names
            }
            missing_runtime = sorted(
                PYTHON_RUNTIME_REQUIRED_FILES.difference(runtime_relatives)
            )
            if missing_runtime:
                raise RuntimeError(
                    f"Portable archive is missing runtime entries: {missing_runtime}"
                )
            runtime_digest = hashlib.sha256()
            runtime_digest.update(b"x3-preview-python-runtime-v1\0")
            for name in runtime_names:
                _update_public_payload_digest(
                    runtime_digest,
                    name.removeprefix(runtime_prefix),
                    source.read(name),
                )
            if runtime_digest.hexdigest() != PYTHON_RUNTIME_PROFILE["packaged_tree_sha256"]:
                raise RuntimeError("Packaged Python runtime tree failed SHA-256 verification")
            if metadata.get("bundled_python") != PYTHON_RUNTIME_PROFILE:
                raise RuntimeError("Release metadata has incorrect Python runtime provenance")
        elif runtime_names or metadata.get("bundled_python") is not None:
            raise RuntimeError("Source-portable archive unexpectedly contains runtime metadata or files")
        provenance = metadata.get("provenance", {})
        digest = hashlib.sha256()
        digest.update(b"x3-preview-public-payload-v1\0")
        for name in sorted(names, key=str.casefold):
            relative = name.removeprefix(expected_prefix)
            if relative in PUBLIC_PAYLOAD_EXCLUSIONS or name.endswith("/"):
                continue
            _update_public_payload_digest(digest, relative, source.read(name))
        if provenance.get("public_payload_sha256") != digest.hexdigest():
            raise RuntimeError("Public payload provenance digest is incorrect")
        demo_name = (
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}"
            "/fixtures/x3-resource-budgets.demo.json"
        )
        if provenance.get("demo_contract_sha256") != hashlib.sha256(
            source.read(demo_name)
        ).hexdigest():
            raise RuntimeError("Demo-contract provenance digest is incorrect")
        baseline_name = (
            f"{expected_prefix}{APP_RELATIVE_ROOT.as_posix()}/"
            f"{BUNDLED_FIRMWARE_SOURCE_RELATIVE.as_posix()}"
        )
        baseline_bytes = source.read(baseline_name)
        if len(baseline_bytes) != int(FIRMWARE_BASELINE_PROFILE["byte_count"]):
            raise RuntimeError("Bundled CrossPoint baseline has the wrong byte count")
        if hashlib.sha256(baseline_bytes).hexdigest() != FIRMWARE_BASELINE_PROFILE["sha256"]:
            raise RuntimeError("Bundled CrossPoint baseline has the wrong SHA-256")
    return {
        "bytes": archive.stat().st_size,
        "sha256": sha256_file(archive),
        "entries": len(names),
    }


def _safe_remove_staging(stage_root: Path, boundary: Path) -> None:
    resolved = require_plain_directory(stage_root, "Disposable staging directory")
    boundary = require_plain_directory(boundary, "Packaging staging boundary")
    if resolved.parent != boundary or not resolved.name.startswith("x3-preview-qa-lab-stage-"):
        raise RuntimeError(f"Refusing to remove unexpected staging directory: {resolved}")
    _plain_parent_chain(resolved, boundary)
    list(iter_plain_tree(resolved))
    shutil.rmtree(resolved)


def _replace_exact_artifact(source: Path, destination: Path, expected_sha: str) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        existing = require_plain_file(destination, "Existing release artifact")
        if existing.parent != destination.parent.resolve():
            raise RuntimeError(f"Existing release artifact escaped its directory: {existing}")
        if sha256_file(existing) == expected_sha:
            return
        existing.unlink()
    shutil.copyfile(source, destination)
    require_plain_file(destination, "Copied release artifact")
    if sha256_file(destination) != expected_sha:
        destination.unlink()
        raise RuntimeError("Copied release artifact failed SHA-256 verification")


def _remove_superseded_archives(output_dir: Path, keep: Path) -> list[str]:
    removed: list[str] = []
    name_pattern = re.compile(
        r"^X3-Preview-QA-Lab-Windows-v[0-9A-Za-z][0-9A-Za-z.+-]{0,79}-(?:source-portable|bundled-python)\.zip$"
    )
    candidates: list[Path] = []
    with os.scandir(output_dir) as entries:
        for entry in entries:
            if not name_pattern.fullmatch(entry.name):
                continue
            candidate = Path(entry.path)
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                raise RuntimeError(f"Release directory contains a linked or special archive candidate: {candidate}")
            candidates.append(candidate)
    if len(candidates) > 20:
        raise RuntimeError(f"Refusing broad archive cleanup: found {len(candidates)} exact candidates")
    for candidate in sorted(candidates, key=lambda value: value.name.casefold()):
        if candidate == keep:
            continue
        candidate = require_plain_file(candidate, "Superseded release archive")
        if candidate.parent != output_dir:
            raise RuntimeError(f"Superseded archive escaped the release directory: {candidate}")
        sidecar = candidate.with_suffix(candidate.suffix + ".sha256")
        candidate.unlink()
        removed.append(candidate.name)
        if sidecar.exists():
            sidecar = require_plain_file(sidecar, "Superseded release checksum")
            if sidecar.parent != output_dir:
                raise RuntimeError(f"Superseded checksum escaped the release directory: {sidecar}")
            sidecar.unlink()
            removed.append(sidecar.name)
    return removed


def build(output_dir: Path, python_runtime: Path | None = None) -> dict[str, object]:
    staging_boundary = _local_staging_boundary()
    output_dir = _validate_output_directory(output_dir)
    staging_name = tempfile.mkdtemp(prefix="x3-preview-qa-lab-stage-", dir=staging_boundary)
    stage_container = Path(staging_name)
    _plain_parent_chain(stage_container, staging_boundary)
    stage_root = stage_container / "payload"
    stage_root.mkdir()
    archive_in_staging: Path | None = None
    try:
        bundled_runtime = _copy_payload(stage_root, python_runtime)
        distribution = "bundled-python" if bundled_runtime else "source-portable"
        metadata = _metadata(stage_root, distribution, bundled_runtime)
        (stage_root / "release-metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        findings = _scan_stage(stage_root, bundled_runtime)
        if findings:
            raise RuntimeError("Public-package sanitization failed:\n" + "\n".join(findings))
        _write_internal_manifest(stage_root)
        findings = _scan_stage(stage_root, bundled_runtime)
        if findings:
            raise RuntimeError("Manifested package sanitization failed:\n" + "\n".join(findings))

        package_root_name = f"{ARCHIVE_STEM}-{distribution}"
        archive_in_staging = stage_container / f"{package_root_name}.zip"
        _zip_stage(stage_root, archive_in_staging, package_root_name)
        verification = _verify_archive(archive_in_staging, package_root_name)

        destination = output_dir / archive_in_staging.name
        _replace_exact_artifact(archive_in_staging, destination, str(verification["sha256"]))
        sidecar = destination.with_suffix(destination.suffix + ".sha256")
        sidecar_content = f"{verification['sha256']}  {destination.name}\n"
        if sidecar.exists():
            existing_sidecar = require_plain_file(sidecar, "Existing release checksum")
            if existing_sidecar.read_text(encoding="utf-8") != sidecar_content:
                existing_sidecar.unlink()
                sidecar.write_text(sidecar_content, encoding="utf-8", newline="\n")
        else:
            sidecar.write_text(sidecar_content, encoding="utf-8", newline="\n")
        removed = _remove_superseded_archives(output_dir, destination)
        pyinstaller_available = bool(
            shutil.which("pyinstaller") or importlib.util.find_spec("PyInstaller")
        )
        return {
            **verification,
            "archive": str(destination),
            "checksum_file": str(sidecar),
            "distribution": distribution,
            "bundled_runtime": bundled_runtime,
            "pyinstaller_available": pyinstaller_available,
            "sanitizer_findings": 0,
            "superseded_files_removed": removed,
            "staging_boundary": str(staging_boundary),
        }
    finally:
        _safe_remove_staging(stage_container, staging_boundary)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=SIMULATOR_ROOT / "release",
        help="final artifact directory; local builds are restricted to the simulator release directory",
    )
    parser.add_argument(
        "--python-runtime",
        type=Path,
        help="optional reviewed Windows Python runtime directory containing python.exe",
    )
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    result = build(arguments.output_dir, arguments.python_runtime)
    print(json.dumps(result, indent=2, sort_keys=True))
    if result["distribution"] == "source-portable":
        print("NOTE: source-portable package; Python 3.10+ is required and no self-contained EXE is claimed.")
        if not result["pyinstaller_available"]:
            print("NOTE: PyInstaller was not available; no executable was built.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
