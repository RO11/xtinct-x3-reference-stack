#!/usr/bin/env python3
"""Create deterministic, source-bound XTINCT X3 public release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

SCRIPT_DIRECTORY = Path(__file__).resolve().parent
if str(SCRIPT_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIRECTORY))
import sanitize_public_release as sanitizer


ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_PROJECT = ROOT / "firmware/crosspoint-source"
FIRMWARE_SCRIPTS = FIRMWARE_PROJECT / "scripts"
sys.path.insert(0, str(FIRMWARE_SCRIPTS))
import xtinct_ready27_cache as ready27_cache  # noqa: E402

FIXED_ZIP_TIME = (2026, 8, 25, 0, 0, 0)
MAX_FILES = 100_000
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
SOURCE_ROOT_ENTRIES = (
    ".github",
    ".gitignore",
    "CONTRIBUTING.md",
    "LICENSE",
    "LICENSES",
    "LICENSING.md",
    "README.md",
    "SECURITY.md",
    "THIRD_PARTY_NOTICES.md",
    "assets",
    "docs",
    "firmware",
    "release-profile.json",
    "scripts",
    "services",
    "sleep.bmp",
    "tests",
)
SOURCE_EXCLUDED_PARTS = {
    ".git", ".pio", ".cache", "__pycache__", "delivery", "dist",
    "node_modules", ".wrangler",
}
SOURCE_EXCLUDED_SUFFIXES = {".log", ".pyc", ".pyo", ".tmp"}
QEMU_NAMES = ("firmware.bin", "bootloader.bin", "partitions.bin", "boot_app0.bin")
EVIDENCE_NAMES = ("firmware.map", "sdkconfig.h")
PUBLIC_LINKED_EVIDENCE_NAMES = (
    "NimBLEServer.cpp.d.normalized",
    "PocketSyncBleServer.cpp.d.normalized",
    "cxx-exception-build-evidence.json",
    "pocket-sync-linked-evidence.json",
)
LINKED_ARTIFACT_NAMES = (
    "firmware.bin", "firmware.elf", "firmware.map", "bootloader.bin",
    "partitions.bin", "boot_app0.bin", "sdkconfig.h",
)
LOCAL_FREEINK_NAMES = {
    "BatteryMonitor", "InputManager", "EInkDisplay", "SDCardManager",
    "BoardConfig", "XteinkDetect", "PowerManager", "Rtc", "Imu",
    "SecureNet", "FreeInkUI", "Icons",
}
PUBLIC_UPSTREAM_EMAILS = ("jseward@acm.org",)
OFFICIAL_BASELINE_RELATIVE = (
    "firmware/crosspoint-source/tools/x3-simulator/firmware-baseline/"
    "crosspoint-v1.5.0/firmware.bin"
)
OFFICIAL_BASELINE_BYTES = 5_544_112
OFFICIAL_BASELINE_SHA256 = "a7087155757bc63c1fcf60ae8d60a3760ce6d3406aaf7b9f23d0025244434f08"
PREBUILD_REQUIRED_GATES = {
    "behavior-model", "crash-security", "file-transfer-security", "native-contracts",
    "network-simulator", "pocket-security", "resource-source", "resource-self-test",
    "simulator-js", "simulator-server", "simulator-python", "network-source-parity",
    "sleep-asset", "sleep-refresh-source-contract", "source-contracts",
    "today-epub", "ui-surface", "i18n", "outbox-memory-source-contract",
    "public-credential-source-contract", "epub-source-contract",
    "epub-source-contract-mutations", "daily-cards-render-wait-source-contract",
    "behavior-pocket-models",
}
POSTBUILD_REQUIRED_GATES = PREBUILD_REQUIRED_GATES | {
    "firmware-identity", "resource-linked", "qemu-smoke",
}


class ReleaseError(RuntimeError):
    pass


ACTIVE_STAGE: Path | None = None


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def is_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except OSError:
        return True
    return bool(getattr(info, "st_file_attributes", 0) & 0x400) or stat.S_ISLNK(info.st_mode)


def require_plain_file(path: Path, label: str) -> None:
    require(path.is_file() and not is_reparse(path), f"{label} is missing or linked: {path}")


def require_plain_dir(path: Path, label: str) -> None:
    require(path.is_dir() and not is_reparse(path), f"{label} is missing or linked: {path}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_copy(source: Path, destination: Path) -> None:
    require_plain_file(source, "copy source")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent, delete=False
    ) as handle:
        temporary = Path(handle.name)
        with source.open("rb") as incoming:
            shutil.copyfileobj(incoming, handle, 1024 * 1024)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        require(temporary.stat().st_size == source.stat().st_size, "atomic copy size changed")
        require(sha256_file(temporary) == sha256_file(source), "atomic copy hash changed")
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    require_plain_file(destination, "copy destination")


def safe_members(root: Path, *, source_mode: bool = False,
                 skip_top_names: set[str] | None = None) -> list[tuple[Path, str]]:
    require_plain_dir(root, "archive root")
    members: list[tuple[Path, str]] = []
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        require_plain_dir(directory, "archive directory")
        for child in sorted(directory.iterdir(), key=lambda item: item.name.casefold(), reverse=True):
            relative = child.relative_to(root)
            parts = {part.casefold() for part in relative.parts}
            hidden_build_part = any(part.casefold().startswith(".xtinct-")
                                    for part in relative.parts)
            if source_mode and (parts & SOURCE_EXCLUDED_PARTS or hidden_build_part or
                                child.suffix.lower() in SOURCE_EXCLUDED_SUFFIXES):
                continue
            if skip_top_names and relative.parts[0] in skip_top_names:
                continue
            require(not is_reparse(child), f"archive refuses link/reparse entry: {child}")
            if child.is_dir():
                pending.append(child)
                continue
            require(child.is_file(), f"archive refuses non-file entry: {child}")
            total += child.stat().st_size
            require(total <= MAX_TOTAL_BYTES, "archive source exceeds byte limit")
            members.append((child, relative.as_posix()))
            require(len(members) <= MAX_FILES, "archive source exceeds file-count limit")
    members.sort(key=lambda item: item[1])
    return members


def write_zip(destination: Path, members: list[tuple[Path, str]], prefix: str) -> None:
    require(members, f"archive has no files: {destination.name}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    require(not temporary.exists(), f"temporary archive already exists: {temporary}")
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for source, relative in members:
                require_plain_file(source, "archive member")
                name = f"{prefix.rstrip('/')}/{relative}" if prefix else relative
                folded = name.casefold()
                require(folded not in seen, f"duplicate archive path: {name}")
                seen.add(folded)
                info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
                info.create_system = 3
                info.external_attr = (0o100644 & 0xFFFF) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                with source.open("rb") as handle:
                    archive.writestr(info, handle.read())
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    require_plain_file(destination, "release archive")


def source_members() -> list[tuple[Path, str]]:
    members: list[tuple[Path, str]] = []
    for name in SOURCE_ROOT_ENTRIES:
        path = ROOT / name
        if not path.exists():
            continue
        require(not is_reparse(path), f"source entry is linked: {path}")
        if path.is_file():
            members.append((path, name))
        else:
            members.extend((source, f"{name}/{relative}") for source, relative in safe_members(path, source_mode=True))
    members.sort(key=lambda item: item[1])
    return members


def read_json(path: Path, label: str) -> dict[str, object]:
    require_plain_file(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"invalid {label}: {path}: {error}") from error
    require(isinstance(value, dict), f"{label} must be an object")
    return value


def scan_members(members: list[tuple[Path, str]], label: str,
                 forbidden_markers: list[str],
                 provenance_prefix: str | None = None) -> dict[str, object]:
    scan_manifest = members
    if provenance_prefix:
        prefix = provenance_prefix.strip("/")
        scan_manifest = [
            (path, f"{prefix}/{relative}") for path, relative in members
        ]
    result = sanitizer.ReleaseScanner(
        forbidden_markers=forbidden_markers,
        allowed_emails=PUBLIC_UPSTREAM_EMAILS,
    ).scan_manifest(scan_manifest)
    require(result.clean and not result.truncated,
            f"public sanitizer rejected {label}: "
            f"{[(finding.path, finding.category, finding.rule) for finding in result.findings[:12]]}")
    return {
        "bytes_scanned": result.bytes_scanned,
        "entries_seen": result.entries_seen,
        "files_scanned": result.files_scanned,
        "status": "clean",
    }


def member_identity(members: list[tuple[Path, str]], label: str) -> dict[str, object]:
    digest = hashlib.sha256()
    total = 0
    for path, relative in members:
        require_plain_file(path, f"{label} member")
        size = path.stat().st_size
        file_hash = sha256_file(path)
        digest.update(f"{relative}\0{size}\0{file_hash}\n".encode("utf-8"))
        total += size
    return {"bytes": total, "files": len(members), "sha256": digest.hexdigest()}


def dependency_sbom(repo_version: str, firmware_version: str,
                    source_sha: str,
                    dependency_inventory: dict[str, object]) -> dict[str, object]:
    """Return a deterministic SPDX 2.3 inventory for every vendored library."""
    packages: list[dict[str, object]] = []
    relationships: list[dict[str, str]] = []

    registry_sources = {
        "ArduinoJson": "https://registry.platformio.org/libraries/bblanchon/ArduinoJson",
        "PNGdec": "https://registry.platformio.org/libraries/bitbank2/PNGdec",
        "QRCode": "https://registry.platformio.org/libraries/ricmoo/QRCode",
        "SdFat": "https://registry.platformio.org/libraries/greiman/SdFat",
    }
    for name in sorted(ready27_cache.PINNED_REGISTRY_DEPENDENCY_VERSIONS):
        identity = ready27_cache.PINNED_REGISTRY_DEPENDENCY_IDENTITIES[name]
        spdx_id = f"SPDXRef-Package-{re.sub(r'[^A-Za-z0-9.-]', '-', name)}"
        packages.append({
            "SPDXID": spdx_id,
            "name": name,
            "versionInfo": ready27_cache.PINNED_REGISTRY_DEPENDENCY_VERSIONS[name],
            "downloadLocation": registry_sources[name],
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "comment": (
                "Vendored source; XTINCT canonical path/mode/byte inventory "
                f"SHA-256 {identity['inventory_sha256']} over {identity['files']} files."
            ),
        })
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id,
        })

    for spec in sorted(ready27_cache.GIT_DEPENDENCY_SPECS,
                       key=lambda item: item.name.casefold()):
        identity = ready27_cache.PINNED_GIT_DEPENDENCY_SEED_IDENTITIES[spec.name]
        spdx_id = f"SPDXRef-Package-{re.sub(r'[^A-Za-z0-9.-]', '-', spec.name)}"
        packages.append({
            "SPDXID": spdx_id,
            "name": spec.name,
            "versionInfo": spec.commit,
            "downloadLocation": f"{spec.origin}@{spec.commit}",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "comment": (
                "Vendored exact Git commit plus the reviewed release patch when applicable; "
                "XTINCT canonical path/mode/byte inventory "
                f"SHA-256 {identity['inventory_sha256']} over {identity['files']} files."
            ),
        })
        relationships.append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": spdx_id,
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"XTINCT X3 {firmware_version} vendored dependency sources",
        "documentNamespace": (
            "https://github.com/RO11/xtinct-x3-reference-stack/"
            f"releases/tag/v{repo_version}/sbom/{source_sha}"
        ),
        "creationInfo": {
            "created": "2026-08-25T00:00:00Z",
            "creators": ["Tool: XTINCT public release packager"],
        },
        "comment": (
            "The complete dependency-source tree is byte-bound by XTINCT canonical "
            f"inventory SHA-256 {dependency_inventory['inventory_sha256']} over "
            f"{dependency_inventory['files']} files. Review THIRD_PARTY_NOTICES.md and "
            "LICENSES/ for authoritative license text."
        ),
        "packages": packages,
        "relationships": relationships,
    }


def redact_local_paths(value: object, replacements: list[tuple[str, str]]) -> object:
    if isinstance(value, dict):
        return {key: redact_local_paths(item, replacements) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_local_paths(item, replacements) for item in value]
    if not isinstance(value, str):
        return value
    redacted = value
    for private, public in replacements:
        for spelling in {private, private.replace("\\", "/")}:
            redacted = re.sub(re.escape(spelling), lambda _match: public,
                              redacted, flags=re.IGNORECASE)
    for regex in (
        sanitizer._WINDOWS_ABSOLUTE_PATH_RE,
        sanitizer._WINDOWS_UNC_PATH_RE,
        sanitizer._POSIX_PERSONAL_PATH_RE,
        sanitizer._WSL_PERSONAL_PATH_RE,
    ):
        redacted = regex.sub("$LOCAL_PATH", redacted)
    return redacted


def write_public_report(source: Path, destination: Path,
                        replacements: list[tuple[str, str]]) -> None:
    value = read_json(source, "private QA evidence")
    public_value = redact_local_paths(value, replacements)
    require(isinstance(public_value, dict), "redacted QA report must remain an object")
    public_value["public_evidence_redaction"] = {
        "local_paths_replaced": [public for _private, public in replacements],
        "original_bytes": source.stat().st_size,
        "original_sha256": sha256_file(source),
        "policy": "paths-only; test results and artifact hashes unchanged",
    }
    destination.write_text(json.dumps(public_value, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8", newline="\n")


def report_identity(report: dict[str, object], phase: str, source_sha: str) -> None:
    require(report.get("schema") == 2 and report.get("phase") == phase,
            f"{phase} report envelope changed")
    source = report.get("source")
    summary = report.get("summary")
    require(isinstance(source, dict) and source.get("sha256") == source_sha,
            f"{phase} report source does not match")
    require(isinstance(summary, dict) and summary.get("blocking_failures") == 0,
            f"{phase} report has blocking failures")
    required = PREBUILD_REQUIRED_GATES if phase == "prebuild" else POSTBUILD_REQUIRED_GATES
    passed = report.get("passed_gates")
    require(isinstance(passed, list) and required.issubset(set(passed)),
            f"{phase} report omits mandatory gates")


def validate_release_profile(profile: dict[str, object], source_sha: str,
                             build_dir: Path, prebuild_report: Path,
                             postbuild_report: Path) -> None:
    require(profile.get("schema") == "xtinct-x3-reference-release/1",
            "release profile schema changed")
    require(profile.get("status") == "qa-passed-physical-pending",
            "release profile is not approved for public packaging")

    firmware_path = build_dir / "firmware.bin"
    require_plain_file(firmware_path, "profile firmware")
    expected_firmware = {
        "bytes": firmware_path.stat().st_size,
        "sha256": sha256_file(firmware_path),
    }
    require(profile.get("firmware") == expected_firmware,
            "release profile firmware differs from the authoritative build")

    evidence = profile.get("evidence")
    require(isinstance(evidence, dict), "release profile evidence is missing")
    require(evidence.get("source_sha256") == source_sha,
            "release profile source SHA differs from frozen QA")
    for phase, path in (("prebuild", prebuild_report), ("postbuild", postbuild_report)):
        require_plain_file(path, f"profile {phase} report")
        expected_report = {
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        require(evidence.get(phase) == expected_report,
                f"release profile {phase} report differs from QA evidence")
    require(evidence.get("qemu") == "passed" and
            evidence.get("physical_x3") == "required",
            "release profile must preserve the QEMU/physical evidence boundary")


def validate_recorded_file(record: object, expected: Path, label: str) -> None:
    require(isinstance(record, dict) and set(record) == {"bytes", "path", "sha256"},
            f"{label} evidence is invalid")
    require_plain_file(expected, label)
    recorded_path = Path(str(record["path"]))
    require(recorded_path.resolve() == expected.resolve() and
            record["bytes"] == expected.stat().st_size and
            record["sha256"] == sha256_file(expected),
            f"{label} differs from QA evidence")


def validate_release_support(prebuild: dict[str, object],
                             postbuild: dict[str, object]) -> None:
    require(prebuild.get("sleep_assets") == postbuild.get("sleep_assets"),
            "prebuild/postbuild sleep evidence differs")
    require(prebuild.get("release_support") == postbuild.get("release_support"),
            "prebuild/postbuild release-support evidence differs")
    sleep = prebuild.get("sleep_assets")
    support = prebuild.get("release_support")
    require(isinstance(sleep, dict) and set(sleep) == {"asset", "master"},
            "sleep evidence envelope is invalid")
    require(isinstance(support, dict) and set(support) == {"sleep_checker"},
            "release-support evidence envelope is invalid")
    validate_recorded_file(sleep["asset"], ROOT / "sleep.bmp", "canonical sleep.bmp")
    validate_recorded_file(
        sleep["master"], ROOT / "assets/sleep/xtinct-public-sleep-master.png",
        "sleep-screen master",
    )
    validate_recorded_file(
        support["sleep_checker"], ROOT / "scripts/check_x3_sleep_screen.py",
        "sleep-screen checker",
    )


def current_source_snapshot() -> dict[str, object]:
    powershell = Path(os.environ.get("SystemRoot", "C:\\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    snapshotter = FIRMWARE_PROJECT / "scripts/Get-XtinctSourceSnapshot.ps1"
    require_plain_file(snapshotter, "source snapshotter")
    result = subprocess.run(
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-File", str(snapshotter),
         "-SourceRoot", str(FIRMWARE_PROJECT)],
        cwd=FIRMWARE_PROJECT, text=True, encoding="utf-8", errors="replace",
        capture_output=True, check=False,
    )
    require(result.returncode == 0 and not result.stderr,
            "current source snapshot failed")
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ReleaseError("current source snapshot is not JSON") from error
    require(isinstance(value, dict) and value.get("schema") == 1 and
            re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", ""))) is not None,
            "current source snapshot envelope changed")
    return value


def validate_linked_generation(postbuild: dict[str, object], build_dir: Path,
                               profile: dict[str, object]) -> dict[str, str]:
    evidence = postbuild.get("postbuild_evidence")
    require(isinstance(evidence, dict), "postbuild linked evidence is missing")
    manifest_record = evidence.get("linked_evidence_manifest")
    identity = evidence.get("identity")
    require(isinstance(manifest_record, dict) and isinstance(identity, dict),
            "postbuild linked identity is invalid")
    manifest_path = build_dir / "linked-provenance/pocket-sync-linked-evidence.json"
    require_plain_file(manifest_path, "linked evidence manifest")
    require(manifest_record.get("path") == "linked-provenance/pocket-sync-linked-evidence.json" and
            manifest_record.get("bytes") == manifest_path.stat().st_size and
            manifest_record.get("sha256") == sha256_file(manifest_path),
            "linked evidence manifest changed after postbuild QA")
    manifest = read_json(manifest_path, "linked evidence manifest")
    require(manifest.get("identity") == identity,
            "linked manifest identity differs from postbuild QA")
    require(identity.get("version") == profile.get("firmware_version") and
            identity.get("build_id") == profile.get("build_id") and
            identity.get("release_label") == profile.get("release_label"),
            "release profile identity differs from the QEMU-tested firmware")

    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict) and set(artifacts) == set(LINKED_ARTIFACT_NAMES),
            "linked artifact manifest allowlist changed")
    for name in LINKED_ARTIFACT_NAMES:
        path = build_dir / name
        record = artifacts[name]
        require_plain_file(path, f"linked artifact {name}")
        require(isinstance(record, dict) and record.get("bytes") == path.stat().st_size and
                record.get("sha256") == sha256_file(path),
                f"linked artifact changed after postbuild QA: {name}")

    linked_root = build_dir / "linked-provenance"
    dependencies = manifest.get("dependencies")
    require(isinstance(dependencies, dict), "linked dependency evidence is invalid")
    for name, record in dependencies.items():
        require(isinstance(name, str) and isinstance(record, dict) and
                isinstance(record.get("normalized"), dict),
                "linked normalized dependency record is invalid")
        path = linked_root / f"{name}.normalized"
        normalized = record["normalized"]
        require_plain_file(path, f"normalized linked dependency {name}")
        require(normalized.get("bytes") == path.stat().st_size and
                normalized.get("sha256") == sha256_file(path),
                f"normalized linked dependency changed: {name}")
    exceptions = manifest.get("exceptions")
    require(isinstance(exceptions, dict) and
            isinstance(exceptions.get("build_evidence"), dict),
            "linked exception evidence is invalid")
    exception_record = exceptions["build_evidence"]
    exception_path = build_dir / str(exception_record.get("path", ""))
    require_plain_file(exception_path, "linked exception build evidence")
    require(exception_record.get("bytes") == exception_path.stat().st_size and
            exception_record.get("sha256") == sha256_file(exception_path),
            "linked exception evidence changed after postbuild QA")
    return {key: str(identity[key]) for key in ("build_id", "release_label", "version")}


def validate_qemu_archive(path: Path, prefix: str, build_dir: Path) -> None:
    manifest = read_json(
        build_dir / "linked-provenance/pocket-sync-linked-evidence.json",
        "linked evidence manifest",
    )
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict), "linked QEMU artifact records are invalid")
    expected_names = {f"{prefix}/{name}" for name in QEMU_NAMES}
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            require({info.filename for info in infos} == expected_names and
                    len(infos) == len(expected_names),
                    "QEMU archive member allowlist changed")
            for info in infos:
                name = PurePosixPath(info.filename).name
                record = artifacts.get(name)
                require(isinstance(record, dict), f"QEMU record is missing: {name}")
                digest = hashlib.sha256()
                total = 0
                with archive.open(info, "r") as handle:
                    while chunk := handle.read(1024 * 1024):
                        digest.update(chunk)
                        total += len(chunk)
                require(total == record.get("bytes") and
                        digest.hexdigest() == record.get("sha256"),
                        f"QEMU archive member differs from linked QA: {name}")
    except zipfile.BadZipFile as error:
        raise ReleaseError("QEMU archive is invalid") from error


def main() -> int:
    global ACTIVE_STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, required=True)
    parser.add_argument("--prebuild-report", type=Path, required=True)
    parser.add_argument("--postbuild-report", type=Path, required=True)
    parser.add_argument("--dependency-root", type=Path, required=True,
                        help="portable vendor/platformio-libdeps source directory")
    parser.add_argument("--forbid-file", action="append", default=[], type=Path,
                        help="private newline/JSON marker list consumed only by the sanitizer")
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    parser.add_argument("--source-sha", required=True)
    args = parser.parse_args()

    profile = read_json(ROOT / "release-profile.json", "release profile")
    repo_version = str(profile.get("repository_version", ""))
    firmware_version = str(profile.get("firmware_version", ""))
    require(re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{1,63}", repo_version) is not None,
            "invalid repository version")
    require(re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+-]{1,63}", firmware_version) is not None,
            "invalid firmware version")
    require(re.fullmatch(r"[0-9a-f]{64}", args.source_sha) is not None, "invalid source SHA")

    build_dir = args.build_dir.resolve()
    dependency_root = args.dependency_root.resolve()
    require_plain_dir(build_dir, "authoritative build directory")
    require_plain_dir(dependency_root, "authoritative dependency source root")
    for name in (*QEMU_NAMES, *EVIDENCE_NAMES[:-1]):
        require_plain_file(build_dir / name, f"build output {name}")
    require_plain_dir(build_dir / "linked-provenance", "linked provenance")
    linked_root = build_dir / "linked-provenance"
    for name in PUBLIC_LINKED_EVIDENCE_NAMES:
        require_plain_file(linked_root / name, f"public linked evidence {name}")

    initial_source = current_source_snapshot()
    require(initial_source.get("sha256") == args.source_sha,
            "current firmware source differs from the frozen QA source")
    expected_dependency_root = (FIRMWARE_PROJECT / "vendor/platformio-libdeps").resolve()
    require(dependency_root == expected_dependency_root,
            "dependency source must be this checkout's vendored PlatformIO input")
    verified_dependency_root, dependency_inventory = \
        ready27_cache.verify_portable_dependency_source(FIRMWARE_PROJECT)
    require(verified_dependency_root.resolve() == dependency_root,
            "verified dependency root changed")

    forbidden_markers: list[str] = []
    environment_markers = os.environ.get(sanitizer.FORBIDDEN_MARKERS_ENV, "")
    if environment_markers:
        forbidden_markers.extend(
            sanitizer._parse_list_value(environment_markers, sanitizer.FORBIDDEN_MARKERS_ENV)
        )
    for marker_file in args.forbid_file:
        forbidden_markers.extend(sanitizer._read_marker_file(marker_file.resolve()))

    prebuild = read_json(args.prebuild_report.resolve(), "prebuild report")
    postbuild = read_json(args.postbuild_report.resolve(), "postbuild report")
    report_identity(prebuild, "prebuild", args.source_sha)
    report_identity(postbuild, "postbuild", args.source_sha)
    validate_release_support(prebuild, postbuild)
    validate_release_profile(
        profile,
        args.source_sha,
        build_dir,
        args.prebuild_report.resolve(),
        args.postbuild_report.resolve(),
    )
    linked_identity = validate_linked_generation(postbuild, build_dir, profile)
    firmware_record = postbuild.get("firmware")
    require(isinstance(firmware_record, dict), "postbuild firmware record is missing")
    firmware = build_dir / "firmware.bin"
    require(firmware_record.get("bytes") == firmware.stat().st_size and
            firmware_record.get("sha256") == sha256_file(firmware),
            "postbuild report does not bind firmware.bin")

    final_output = args.output_dir.resolve()
    final_output.mkdir(parents=True, exist_ok=True)
    require_plain_dir(final_output, "release output")
    require(not any(final_output.iterdir()), "release output must start empty")
    output = final_output / ".xtinct-package-stage"
    require(not output.exists(), "release staging directory already exists")
    output.mkdir()
    ACTIVE_STAGE = output

    install_name = f"XTINCT-X3-firmware-{firmware_version}-update.bin"
    install_path = output / install_name
    atomic_copy(firmware, install_path)

    sanitizer_report: dict[str, object] = {
        "schema": "xtinct-public-sanitizer/1",
        "source_sha256": args.source_sha,
        "linked_identity": linked_identity,
        "dependency_source": ready27_cache.inventory_identity(dependency_inventory),
    }
    sanitizer_report["firmware"] = scan_members(
        [(install_path, "update.bin")], "installable firmware", forbidden_markers
    )
    public_source_members = source_members()
    source_identity = member_identity(public_source_members, "public source")
    baseline_members = [item for item in public_source_members if item[1] == OFFICIAL_BASELINE_RELATIVE]
    require(len(baseline_members) == 1,
            "official CrossPoint baseline firmware is missing from the source kit")
    baseline_path = baseline_members[0][0]
    require(baseline_path.stat().st_size == OFFICIAL_BASELINE_BYTES and
            sha256_file(baseline_path) == OFFICIAL_BASELINE_SHA256,
            "official CrossPoint baseline firmware identity changed")
    heuristic_source_members = [
        item for item in public_source_members if item[1] != OFFICIAL_BASELINE_RELATIVE
    ]
    sanitizer_report["source"] = scan_members(
        heuristic_source_members, "source archive", forbidden_markers
    )
    sanitizer_report["source"]["member_identity"] = source_identity
    sanitizer_report["official_baseline"] = {
        "bytes": OFFICIAL_BASELINE_BYTES,
        "path": OFFICIAL_BASELINE_RELATIVE,
        "policy": "exact official CrossPoint v1.5.0 release hash; heuristic binary scan exempt",
        "sha256": OFFICIAL_BASELINE_SHA256,
    }
    source_name = f"XTINCT-X3-Reference-Stack-{repo_version}-source.zip"
    write_zip(output / source_name, public_source_members,
              f"xtinct-x3-reference-stack-{repo_version}")
    require(member_identity(public_source_members, "public source after archive") == source_identity,
            "public source changed while its archive was created")

    qemu_name = f"XTINCT-X3-{firmware_version}-qemu-boot-set.zip"
    qemu_members = [(build_dir / name, name) for name in QEMU_NAMES]
    sanitizer_report["qemu"] = scan_members(qemu_members, "QEMU boot set", forbidden_markers)
    write_zip(
        output / qemu_name,
        qemu_members,
        f"xtinct-x3-{firmware_version}-qemu",
    )
    validate_qemu_archive(
        output / qemu_name, f"xtinct-x3-{firmware_version}-qemu", build_dir
    )

    dependency_members = safe_members(dependency_root, skip_top_names=LOCAL_FREEINK_NAMES)
    dependency_member_identity = member_identity(dependency_members, "dependency source")
    sanitizer_report["dependency_sources"] = scan_members(
        dependency_members,
        "dependency sources",
        forbidden_markers,
        provenance_prefix="vendor/platformio-libdeps",
    )
    dependency_name = f"XTINCT-X3-{firmware_version}-dependency-sources.zip"
    write_zip(
        output / dependency_name,
        dependency_members,
        f"xtinct-x3-{firmware_version}-dependency-sources",
    )
    require(member_identity(dependency_members, "dependency source after archive") ==
            dependency_member_identity,
            "dependency source changed while its archive was created")
    sanitizer_report["dependency_sources"]["member_identity"] = dependency_member_identity

    sbom_name = f"XTINCT-X3-{firmware_version}-dependency-sbom.spdx.json"
    sbom_path = output / sbom_name
    sbom_path.write_text(
        json.dumps(
            dependency_sbom(repo_version, firmware_version, args.source_sha,
                            dependency_inventory),
            indent=2,
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    sanitizer_report["dependency_sbom"] = scan_members(
        [(sbom_path, sbom_name)], "dependency SBOM", forbidden_markers
    )
    attested_names = (install_name, source_name, qemu_name, dependency_name, sbom_name)
    sanitizer_report["attested_assets"] = {
        name: {
            "bytes": (output / name).stat().st_size,
            "sha256": sha256_file(output / name),
        }
        for name in attested_names
    }

    evidence_stage = output / ".evidence-stage"
    evidence_stage.mkdir()
    try:
        replacements = [
            (str(Path.home().resolve()), "$USER_HOME"),
            (str(ROOT.resolve()), "$REPOSITORY_ROOT"),
            (str(build_dir), "$BUILD_DIR"),
            (str(dependency_root), "$DEPENDENCY_ROOT"),
            (str(args.prebuild_report.resolve().parent), "$QA_REPORT_ROOT"),
            (str(args.postbuild_report.resolve().parent), "$QA_REPORT_ROOT"),
        ]
        replacements.extend(
            (marker, f"$PRIVATE_MARKER_{index}")
            for index, marker in enumerate(forbidden_markers, start=1)
        )
        postbuild_evidence = postbuild.get("postbuild_evidence")
        if isinstance(postbuild_evidence, dict):
            resource = postbuild_evidence.get("resource_report")
            if isinstance(resource, dict) and isinstance(resource.get("path"), str):
                replacements.append(
                    (str(Path(resource["path"]).resolve().parent), "$QA_ARTIFACT_ROOT")
                )
        write_public_report(args.prebuild_report.resolve(),
                            evidence_stage / "prebuild-report.json", replacements)
        write_public_report(args.postbuild_report.resolve(),
                            evidence_stage / "postbuild-report.json", replacements)
        atomic_copy(ROOT / "release-profile.json", evidence_stage / "release-profile.json")
        for name in EVIDENCE_NAMES:
            atomic_copy(build_dir / name, evidence_stage / name)
        public_linked = evidence_stage / "linked-provenance"
        public_linked.mkdir()
        for name in PUBLIC_LINKED_EVIDENCE_NAMES:
            source = linked_root / name
            if source.suffix == ".json":
                write_public_report(source, public_linked / name, replacements)
            else:
                atomic_copy(source, public_linked / name)
        if isinstance(postbuild_evidence, dict):
            resource = postbuild_evidence.get("resource_report")
            if isinstance(resource, dict) and isinstance(resource.get("path"), str):
                resource_path = Path(resource["path"])
                require_plain_file(resource_path, "linked resource-budget report")
                require(resource_path.stat().st_size == resource.get("bytes") and
                        sha256_file(resource_path) == resource.get("sha256"),
                        "linked resource-budget report changed")
                write_public_report(resource_path,
                                    evidence_stage / "resource-budget-report.json",
                                    replacements)
        evidence_members = safe_members(evidence_stage)
        sanitizer_report["evidence"] = scan_members(
            evidence_members, "public evidence", forbidden_markers
        )
        sanitizer_path = evidence_stage / "public-sanitizer-report.json"
        sanitizer_path.write_text(
            json.dumps(sanitizer_report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8", newline="\n",
        )
        evidence_name = f"XTINCT-X3-{firmware_version}-evidence.zip"
        write_zip(
            output / evidence_name,
            safe_members(evidence_stage),
            f"xtinct-x3-{firmware_version}-evidence",
        )
    finally:
        if evidence_stage.exists():
            shutil.rmtree(evidence_stage)

    assets: dict[str, dict[str, object]] = {}
    for path in sorted(output.iterdir(), key=lambda item: item.name):
        if path.is_file():
            assets[path.name] = {"bytes": path.stat().st_size, "sha256": sha256_file(path)}
    manifest = {
        "schema": "xtinct-x3-public-release/1",
        "repository_version": repo_version,
        "firmware_version": firmware_version,
        "build_id": profile.get("build_id"),
        "source_sha256": args.source_sha,
        "physical_x3": "required",
        "assets": assets,
    }
    manifest_path = output / "release-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assets[manifest_path.name] = {
        "bytes": manifest_path.stat().st_size,
        "sha256": sha256_file(manifest_path),
    }
    sums = "".join(f"{record['sha256']}  {name}\n" for name, record in sorted(assets.items()))
    (output / "SHA256SUMS.txt").write_text(sums, encoding="ascii", newline="\n")
    # Commit the canonical update and public assets only after every source,
    # binary, dependency and evidence scan has passed. A failed run leaves no
    # installable candidate in the release directory.
    require(current_source_snapshot() == initial_source,
            "firmware source changed during public packaging")
    require(validate_linked_generation(postbuild, build_dir, profile) == linked_identity,
            "linked generation changed during public packaging")
    require(install_path.stat().st_size == firmware_record.get("bytes") and
            sha256_file(install_path) == firmware_record.get("sha256"),
            "staged installable firmware differs from postbuild QA")
    validate_qemu_archive(
        output / qemu_name, f"xtinct-x3-{firmware_version}-qemu", build_dir
    )
    atomic_copy(install_path, ROOT / "update.bin")
    for path in sorted(output.iterdir(), key=lambda item: item.name.casefold()):
        require_plain_file(path, "staged release asset")
        destination = final_output / path.name
        require(not destination.exists(),
                f"release destination already exists: {destination}")
        os.replace(path, destination)
    output.rmdir()
    ACTIVE_STAGE = None
    print("XTINCT_PUBLIC_RELEASE_PACKAGE_OK")
    print(final_output)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ReleaseError, ready27_cache.Ready27CacheError,
            sanitizer.ScannerConfigurationError) as error:
        if ACTIVE_STAGE is not None and ACTIVE_STAGE.is_dir() and not is_reparse(ACTIVE_STAGE):
            shutil.rmtree(ACTIVE_STAGE)
        print(f"XTINCT public release packaging failed closed: {error}", file=os.sys.stderr)
        raise SystemExit(2)
