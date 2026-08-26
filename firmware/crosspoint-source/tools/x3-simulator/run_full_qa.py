#!/usr/bin/env python3
"""Fail-closed XTINCT X3 emulator and firmware release QA orchestrator.

The prebuild phase binds modeled behavior to the exact source snapshot and
executes the local HTTP contracts, browser model, source/security gates and
every Android-target native contract binary on an attached emulator.  The
postbuild phase additionally requires the exact linked generation and offline
ESP32-C3 QEMU smoke.  Physical-only claims are always reported as pending and
never converted into simulator passes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Sequence


SIM_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = SIM_ROOT.parents[1]
WORKSPACE_ROOT = PROJECT_ROOT.parents[1]
QA_ROOT = SIM_ROOT / "qa"
# Reports and assembled QEMU flash are deliberately outside the firmware
# source snapshot. A report cannot be allowed to hash itself into the source
# identity it is attesting.
ARTIFACT_ROOT = WORKSPACE_ROOT / "delivery" / "x3-release-qa"
CANONICAL_FIRMWARE = WORKSPACE_ROOT / "update.bin"
SLEEP_ASSET = WORKSPACE_ROOT / "sleep.bmp"
SLEEP_MASTER: Path | None = None
SLEEP_CHECKER = WORKSPACE_ROOT / "scripts/check_x3_sleep_screen.py"
NATIVE_REMOTE = "/data/local/tmp/xtinct-x3-release-qa"
EXPECTED_NATIVE_BINARIES = 29
REPORT_SCHEMA = 2
LINKED_EVIDENCE_RELATIVE = Path("linked-provenance/pocket-sync-linked-evidence.json")
EXPECTED_LINKED_EVIDENCE_SCHEMA = 4
EXPECTED_BOOT_APP0_BYTES = 0x2000
EXPECTED_GOOGLETEST_COMMIT = "52eb8108c5bdec04579160ae17225d66034bd723"
EXPECTED_GOOGLETEST_BYTES = 4_095_045
EXPECTED_GOOGLETEST_FILES = 250
EXPECTED_GOOGLETEST_SHA256 = "ab5faf09082c7db72d05784384f93a0a313dfd4722fbd27c389e7eacd30fdf7e"
ANDROID_CMAKE_VERSION = "3.22.1"
ANDROID_NDK_VERSION = "27.1.12297006"
ANDROID_ABI = "x86_64"
ANDROID_PLATFORM = "android-28"


class QaError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise QaError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def plain_file_record(path: Path, label: str) -> dict[str, object]:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or linked: {path}")
    return {"bytes": path.stat().st_size, "path": str(path), "sha256": sha256_file(path)}


def directory_inventory(root: Path, label: str) -> dict[str, object]:
    require(root.is_dir() and not root.is_symlink(), f"{label} is missing or linked: {root}")
    digest = hashlib.sha256()
    files = 0
    total_bytes = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        require(not path.is_symlink(), f"{label} contains a link: {path}")
        if not path.is_file() or ".git" in path.relative_to(root).parts:
            continue
        relative = path.relative_to(root).as_posix()
        size = path.stat().st_size
        file_hash = sha256_file(path)
        digest.update(f"{relative}\0{size}\0{file_hash}\n".encode("utf-8"))
        files += 1
        total_bytes += size
    require(files > 0, f"{label} inventory is empty")
    return {"bytes": total_bytes, "files": files, "sha256": digest.hexdigest()}


def read_json(path: Path) -> object:
    require(path.is_file() and not path.is_symlink(), f"Required JSON is missing or linked: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QaError(f"Invalid JSON: {path}: {error}") from error


def configure_runtime_paths(args: argparse.Namespace) -> None:
    """Resolve all machine-local inputs without baking them into the release."""
    global PROJECT_ROOT, WORKSPACE_ROOT, QA_ROOT, ARTIFACT_ROOT
    global CANONICAL_FIRMWARE, SLEEP_ASSET, SLEEP_MASTER, SLEEP_CHECKER

    PROJECT_ROOT = args.project_root.resolve()
    if args.workspace_root is not None:
        WORKSPACE_ROOT = args.workspace_root.resolve()
    elif PROJECT_ROOT.parent.name.lower() == "firmware":
        WORKSPACE_ROOT = PROJECT_ROOT.parent.parent.resolve()
    else:
        WORKSPACE_ROOT = PROJECT_ROOT.parent.resolve()
    QA_ROOT = SIM_ROOT / "qa"
    ARTIFACT_ROOT = (args.artifact_root or
                     (WORKSPACE_ROOT / "delivery" / "x3-release-qa")).resolve()
    CANONICAL_FIRMWARE = (args.canonical_firmware or
                          (WORKSPACE_ROOT / "update.bin")).resolve()
    SLEEP_ASSET = (args.sleep_asset or (WORKSPACE_ROOT / "sleep.bmp")).resolve()
    SLEEP_CHECKER = (WORKSPACE_ROOT / "scripts/check_x3_sleep_screen.py").resolve()
    configured_master = args.sleep_master
    if configured_master is None:
        environment_master = os.environ.get("XTINCT_X3_SLEEP_MASTER", "").strip()
        configured_master = Path(environment_master) if environment_master else None
    SLEEP_MASTER = configured_master.resolve() if configured_master is not None else None


def source_release_identity() -> dict[str, str]:
    """Read the candidate identity from the exact source being attested."""
    path = PROJECT_ROOT / "src/XtinctBuildInfo.h"
    require(path.is_file() and not path.is_symlink(),
            f"Source build identity is missing or linked: {path}")
    text = path.read_text(encoding="utf-8")

    def macro(name: str) -> str:
        match = re.search(
            rf'^\s*#define\s+{re.escape(name)}\s+"([^"\r\n]+)"\s*$',
            text,
            re.MULTILINE,
        )
        require(match is not None, f"Source build identity lacks {name}")
        return str(match.group(1))

    release_label = macro("XTINCT_RELEASE_LABEL")
    build_id = macro("XTINCT_BUILD_ID")
    version = release_label[1:] if release_label.startswith("v") else release_label
    require(bool(version), "Source release label cannot produce a version")
    return {
        "build_id": build_id,
        "release_label": release_label,
        "version": version,
    }


def run(label: str, command: Sequence[str], cwd: Path, timeout: int = 300) -> dict[str, object]:
    started = time.monotonic()
    result = subprocess.run(
        list(command), cwd=cwd, text=True, encoding="utf-8", errors="replace",
        capture_output=True, check=False, timeout=timeout,
    )
    record = {
        "command": list(command),
        "duration_ms": round((time.monotonic() - started) * 1000),
        "label": label,
        "returncode": result.returncode,
        "stderr": result.stderr[-4000:],
        "stdout": result.stdout[-12000:],
    }
    if result.returncode != 0:
        raise QaError(
            f"{label} failed ({result.returncode})\n{(result.stderr or result.stdout)[-4000:]}"
        )
    return record


def source_snapshot() -> dict[str, object]:
    powershell = Path(os.environ.get("SystemRoot", "C:\\Windows")) / \
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    snapshotter = PROJECT_ROOT / "scripts/Get-XtinctSourceSnapshot.ps1"
    result = run(
        "source-snapshot",
        [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-File", str(snapshotter),
         "-SourceRoot", str(PROJECT_ROOT)],
        PROJECT_ROOT,
    )
    value = json.loads(str(result["stdout"]))
    require(value.get("schema") == 1 and value.get("files", 0) > 0 and
            re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", ""))) is not None,
            "Source snapshot envelope is invalid")
    return value


def verify_source_contracts() -> dict[str, int]:
    manifest = read_json(QA_ROOT / "source_contracts.json")
    require(isinstance(manifest, dict) and manifest.get("schema") == 1,
            "Source-contract manifest schema changed")
    checked_files = 0
    checked_tokens = 0
    for contract in manifest.get("contracts", []):
        require(isinstance(contract, dict) and contract.get("id"), "Source contract is invalid")
        for relative, tokens in contract.get("files", {}).items():
            path = PROJECT_ROOT / relative
            require(path.is_file() and not path.is_symlink(),
                    f"Source contract {contract['id']} file is missing: {relative}")
            text = path.read_text(encoding="utf-8")
            checked_files += 1
            for token in tokens:
                require(token in text,
                        f"Source contract {contract['id']} token is missing from {relative}: {token}")
                checked_tokens += 1
    return {"files": checked_files, "tokens": checked_tokens}


def verify_ui_contracts() -> dict[str, int]:
    manifest = read_json(QA_ROOT / "ui_surface_contracts.json")
    require(isinstance(manifest, dict) and manifest.get("schema") == 1,
            "UI surface manifest schema changed")
    text_suffixes = {".css", ".html", ".js", ".json", ".mjs", ".txt"}
    combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (SIM_ROOT / "web").rglob("*")
        if path.is_file() and path.suffix.lower() in text_suffixes
    )
    test_combined = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (SIM_ROOT / "tests").rglob("*")
        if path.is_file() and path.suffix.lower() in text_suffixes
    )
    for placeholder in manifest.get("forbidden_placeholders", []):
        require(placeholder not in combined, f"Simulator contains forbidden placeholder: {placeholder}")
    surfaces = manifest.get("surfaces", [])
    for surface in surfaces:
        for relative, tokens in surface.get("source_tokens", {}).items():
            text = (SIM_ROOT / relative).read_text(encoding="utf-8")
            for token in tokens:
                require(token in text,
                        f"UI surface {surface['id']} token is missing from {relative}: {token}")
        for token in surface.get("test_tokens", []):
            require(token in test_combined,
                    f"UI surface {surface['id']} lacks a named executable test: {token}")
    return {"surfaces": len(surfaces)}


def matrix_status(passed_gates: set[str], phase: str) -> tuple[list[dict[str, object]], dict[str, int]]:
    matrix = read_json(QA_ROOT / "x3_qa_matrix.json")
    require(isinstance(matrix, dict) and matrix.get("schema") == 1,
            "QA matrix schema changed")
    results: list[dict[str, object]] = []
    blocking_failures = 0
    physical_pending = 0
    for scenario in matrix.get("scenarios", []):
        gates = list(scenario.get("gates", []))
        physical = bool(scenario.get("physical_required"))
        missing = [gate for gate in gates if gate not in passed_gates]
        if physical:
            status = "physical-pending"
            physical_pending += 1
        elif not missing:
            status = "pass"
        elif phase == "prebuild" and all(gate in {"firmware-identity", "resource-linked", "qemu-smoke"}
                                         for gate in missing):
            status = "postbuild-pending"
        else:
            status = "fail"
            if scenario.get("release_blocking"):
                blocking_failures += 1
        results.append({
            "area": scenario.get("area"), "claim": scenario.get("claim"),
            "gates": gates, "id": scenario.get("id"), "missing_gates": missing,
            "release_blocking": bool(scenario.get("release_blocking")), "status": status,
        })
    return results, {
        "blocking_failures": blocking_failures,
        "physical_pending": physical_pending,
        "postbuild_pending": sum(item["status"] == "postbuild-pending" for item in results),
        "passed": sum(item["status"] == "pass" for item in results),
        "total": len(results),
    }


def native_binaries(build_dir: Path, started_ns: int) -> list[Path]:
    require(build_dir.is_dir(), f"Fresh Android native-test build is missing: {build_dir}")
    ignored = {"CONTRIBUTORS", "LICENSE", "WORKSPACE"}
    binaries = [path for path in build_dir.rglob("*")
                if path.is_file() and path.suffix == "" and not path.name.startswith(".") and
                path.name not in ignored and
                "_deps" not in path.parts]
    require(len(binaries) == EXPECTED_NATIVE_BINARIES,
            f"Expected {EXPECTED_NATIVE_BINARIES} native test binaries, found {len(binaries)}")
    for binary in binaries:
        require(binary.stat().st_mtime_ns >= started_ns,
                f"Native binary was not freshly linked by this QA run: {binary}")
    return sorted(binaries)


def configure_native_suite(source_sha256: str) -> tuple[Path, int, dict[str, object]]:
    local_app_data = os.environ.get("LOCALAPPDATA", "").strip()
    require(local_app_data, "LOCALAPPDATA is required to locate the pinned Android toolchain")
    sdk = Path(local_app_data) / "Android/Sdk"
    cmake = sdk / f"cmake/{ANDROID_CMAKE_VERSION}/bin/cmake.exe"
    ninja = sdk / f"cmake/{ANDROID_CMAKE_VERSION}/bin/ninja.exe"
    toolchain = sdk / f"ndk/{ANDROID_NDK_VERSION}/build/cmake/android.toolchain.cmake"
    tools = {
        "cmake": plain_file_record(cmake, "Pinned Android CMake"),
        "ninja": plain_file_record(ninja, "Pinned Android Ninja"),
        "toolchain": plain_file_record(toolchain, "Pinned Android NDK toolchain"),
    }
    googletest = PROJECT_ROOT / "vendor/googletest"
    gtest_inventory = directory_inventory(googletest, "Pinned GoogleTest source")
    require(gtest_inventory == {
        "bytes": EXPECTED_GOOGLETEST_BYTES,
        "files": EXPECTED_GOOGLETEST_FILES,
        "sha256": EXPECTED_GOOGLETEST_SHA256,
    }, "Vendored GoogleTest source identity changed")

    native_root = ARTIFACT_ROOT / "native-builds"
    native_root.mkdir(parents=True, exist_ok=True)
    build_dir = Path(tempfile.mkdtemp(prefix=f"{source_sha256[:16]}-", dir=native_root))
    started_ns = time.time_ns()
    configure = run(
        "native-configure",
        [str(cmake), "-S", str(PROJECT_ROOT / "test"), "-B", str(build_dir),
         "-G", "Ninja", f"-DCMAKE_MAKE_PROGRAM={ninja}",
         f"-DCMAKE_TOOLCHAIN_FILE={toolchain}", f"-DANDROID_ABI={ANDROID_ABI}",
         f"-DANDROID_PLATFORM={ANDROID_PLATFORM}", "-DCMAKE_BUILD_TYPE=Release",
         "-DCMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE=PRE_TEST",
         f"-DFETCHCONTENT_SOURCE_DIR_GOOGLETEST={googletest}"],
        PROJECT_ROOT, 300,
    )
    build = run("native-build", [str(cmake), "--build", str(build_dir),
                                  "--config", "Release", "--parallel", "2"],
                PROJECT_ROOT, 600)
    provenance = {
        "abi": ANDROID_ABI,
        "build_command": build,
        "build_dir": str(build_dir),
        "configure_command": configure,
        "googletest": {"commit": EXPECTED_GOOGLETEST_COMMIT, **gtest_inventory},
        "platform": ANDROID_PLATFORM,
        "source_sha256": source_sha256,
        "tools": tools,
    }
    return build_dir, started_ns, provenance


def select_adb_target(active: Sequence[str], requested: str | None) -> str:
    if requested:
        require(requested in active,
                f"Requested adb test target is unavailable: {requested}; active={list(active)}")
        return requested
    require(len(active) == 1, f"Exactly one adb test target is required, found {list(active)}")
    return active[0]


def run_native_suite(source_sha256: str,
                     requested_serial: str | None = None) -> tuple[dict[str, object], int]:
    build_dir, started_ns, provenance = configure_native_suite(source_sha256)
    adb = shutil.which("adb")
    require(adb is not None, "adb is required for Android-target native tests")
    devices = run("adb-devices", [adb, "devices"], PROJECT_ROOT)["stdout"]
    active = [parts[0] for line in str(devices).splitlines()[1:]
              if len(parts := line.split()) >= 2 and parts[1] == "device"]
    serial = select_adb_target(active, requested_serial)
    run("native-remote-create", [adb, "-s", serial, "shell", "mkdir", "-p", NATIVE_REMOTE], PROJECT_ROOT)
    resources = PROJECT_ROOT / "test/hyphenation_eval/resources"
    run("native-resources", [adb, "-s", serial, "push", str(resources), f"{NATIVE_REMOTE}/resources"],
        PROJECT_ROOT, 120)
    test_count = 0
    programs: list[dict[str, object]] = []
    for index, binary in enumerate(native_binaries(build_dir, started_ns)):
        remote = f"{NATIVE_REMOTE}/test-{index:02d}"
        run(f"native-push-{binary.name}", [adb, "-s", serial, "push", str(binary), remote], PROJECT_ROOT, 120)
        run(f"native-chmod-{binary.name}", [adb, "-s", serial, "shell", "chmod", "700", remote], PROJECT_ROOT)
        command = (f"XTINCT_HYPHENATION_RESOURCES_DIR={NATIVE_REMOTE}/resources "
                   f"{remote} --gtest_color=no")
        result = run(f"native-{binary.name}", [adb, "-s", serial, "shell", command], PROJECT_ROOT, 180)
        match = re.search(r"\[==========\] Running (\d+) tests?", str(result["stdout"]))
        require(match is not None, f"Native test count missing for {binary.name}")
        count = int(match.group(1))
        test_count += count
        programs.append({"bytes": binary.stat().st_size, "name": binary.name,
                         "sha256": sha256_file(binary), "tests": count})
    require(test_count >= 285, f"Expected at least 285 native tests, ran {test_count}")
    return {"device": serial, "programs": programs, "provenance": provenance}, test_count


def sleep_asset_evidence() -> dict[str, dict[str, object]]:
    require(SLEEP_MASTER is not None,
            "The unquantized sleep-screen master is required. Pass --sleep-master "
            "or set XTINCT_X3_SLEEP_MASTER; a prior BMP/quantized preview is not valid.")
    return {
        "asset": plain_file_record(SLEEP_ASSET, "Canonical X3 sleep.bmp"),
        "master": plain_file_record(SLEEP_MASTER, "Unquantized sleep-screen master"),
    }


def release_support_evidence() -> dict[str, dict[str, object]]:
    """Bind release-critical support code that lives outside the firmware snapshot."""
    return {
        "sleep_checker": plain_file_record(
            SLEEP_CHECKER, "Canonical X3 sleep-screen checker"
        ),
    }


def pocket_security(core: Path | None) -> dict[str, object] | None:
    if core is None:
        return None
    packages = core / "packages"
    libdeps = core / "libdeps"
    result = run(
        "pocket-source-security",
        [sys.executable, "-B", "scripts/verify_pocket_sync_security.py",
         "--project-root", str(PROJECT_ROOT), "--packages-dir", str(packages),
         "--libdeps-dir", str(libdeps)],
        PROJECT_ROOT, 300,
    )
    return result


def verify_postbuild_identity(build_dir: Path, boot_app0: Path) -> dict[str, object]:
    require(build_dir.is_dir(), "Postbuild artifact directory is missing")
    expected_boot_app0 = build_dir / "boot_app0.bin"
    require(boot_app0 == expected_boot_app0.resolve(),
            "Postbuild --boot-app0 must be the published same-build boot_app0.bin")
    canonical = CANONICAL_FIRMWARE
    require(canonical.is_file(), "Canonical workspace update.bin is missing")
    firmware = build_dir / "firmware.bin"
    require(firmware.is_file() and not firmware.is_symlink(),
            "Published firmware.bin is missing or linked")
    require(sha256_file(firmware) == sha256_file(canonical),
            "Same-build firmware.bin differs from canonical update.bin")
    manifest_path = build_dir / LINKED_EVIDENCE_RELATIVE
    manifest = read_json(manifest_path)
    require(isinstance(manifest, dict) and
            manifest.get("schema") == EXPECTED_LINKED_EVIDENCE_SCHEMA,
            "Published linked-evidence manifest schema changed")
    expected_identity = source_release_identity()
    require(manifest.get("identity") == expected_identity,
            "Published linked-evidence identity differs from the frozen source identity")
    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict), "Published linked-evidence artifact map is invalid")
    boot_record = artifacts.get("boot_app0.bin")
    require(expected_boot_app0.is_file() and not expected_boot_app0.is_symlink(),
            "Published boot_app0.bin is missing or linked")
    actual_boot_record = {
        "bytes": expected_boot_app0.stat().st_size,
        "sha256": sha256_file(expected_boot_app0),
    }
    require(boot_record == actual_boot_record,
            "Published boot_app0.bin differs from its linked-evidence record")
    require(expected_boot_app0.stat().st_size == EXPECTED_BOOT_APP0_BYTES,
            "Published boot_app0.bin does not fill the OTA-data partition")
    build_info = (PROJECT_ROOT / "src/XtinctBuildInfo.h").read_text(encoding="utf-8")
    require(f'#define XTINCT_BUILD_ID "{expected_identity["build_id"]}"' in build_info and
            f'#define XTINCT_RELEASE_LABEL "{expected_identity["release_label"]}"' in build_info,
            "Source build identity no longer matches the postbuild identity")
    return {
        "boot_app0": actual_boot_record,
        "canonical_firmware": {
            "bytes": canonical.stat().st_size,
            "sha256": sha256_file(canonical),
        },
        "identity": expected_identity,
        "linked_evidence_manifest": {
            "bytes": manifest_path.stat().st_size,
            "path": LINKED_EVIDENCE_RELATIVE.as_posix(),
            "sha256": sha256_file(manifest_path),
        },
    }


def postbuild_gates(build_dir: Path, boot_app0: Path,
                    platformio_core: Path) -> tuple[list[dict[str, object]], dict[str, object]]:
    identity = verify_postbuild_identity(build_dir, boot_app0)
    packages = platformio_core / "packages"
    libdeps = platformio_core / "libdeps"
    require(packages.is_dir() and libdeps.is_dir(),
            "Postbuild private core lacks packages or libdeps")
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    flash = ARTIFACT_ROOT / "x3-qemu-flash.bin"
    resource_report = ARTIFACT_ROOT / "x3-linked-resource-budget.json"
    evidence_manifest = build_dir / LINKED_EVIDENCE_RELATIVE
    commands = [
        run("resource-linked", [sys.executable, "-B", "scripts/check_x3_resource_budgets.py",
                                 "--project-root", str(PROJECT_ROOT),
                                 "--firmware-bin", str(build_dir / "firmware.bin"),
                                 "--firmware-map", str(build_dir / "firmware.map"),
                                 "--sdkconfig", str(build_dir / "sdkconfig.h"),
                                 "--report", str(resource_report)], PROJECT_ROOT, 300),
        run("pocket-linked-evidence", [sys.executable, "-B",
                                        "scripts/verify_pocket_sync_security.py",
                                        "--project-root", str(PROJECT_ROOT),
                                        "--packages-dir", str(packages),
                                        "--libdeps-dir", str(libdeps),
                                        "--build-dir", str(build_dir),
                                        "--evidence-manifest", str(evidence_manifest)],
            PROJECT_ROOT, 300),
        run("qemu-status", [sys.executable, "-B", "qemu_firmware.py", "status",
                            "--canonical-update", str(CANONICAL_FIRMWARE),
                            "--contract", str(PROJECT_ROOT / "config/x3-resource-budgets.json"),
                            "--build-dir", str(build_dir), "--boot-app0", str(boot_app0)], SIM_ROOT),
        run("qemu-assemble", [sys.executable, "-B", "qemu_firmware.py", "assemble",
                              "--canonical-update", str(CANONICAL_FIRMWARE),
                              "--contract", str(PROJECT_ROOT / "config/x3-resource-budgets.json"),
                              "--build-dir", str(build_dir), "--boot-app0", str(boot_app0),
                              "--output", str(flash), "--replace"], SIM_ROOT, 300),
        run("qemu-run", [sys.executable, "-B", "qemu_firmware.py", "run",
                         "--canonical-update", str(CANONICAL_FIRMWARE),
                         "--contract", str(PROJECT_ROOT / "config/x3-resource-budgets.json"),
                         "--flash", str(flash), "--timeout-seconds", "15"], SIM_ROOT, 300),
    ]
    require("X3_RESOURCE_BUDGET_LINKED_OK" in str(commands[0]["stdout"]),
            "Linked resource gate did not emit its success attestation")
    linked_stdout = str(commands[1]["stdout"])
    for marker in ("POCKET_SYNC_SOURCE_SECURITY_OK",
                   "POCKET_SYNC_EVIDENCE_MANIFEST_OK",
                   "POCKET_SYNC_LINKED_SECURITY_OK"):
        require(marker in linked_stdout,
                f"Published linked-evidence verifier omitted {marker}")
    require(resource_report.is_file() and not resource_report.is_symlink(),
            "Linked resource report was not retained")
    evidence = {
        **identity,
        "resource_report": {
            "bytes": resource_report.stat().st_size,
            "path": str(resource_report),
            "sha256": sha256_file(resource_report),
        },
    }
    return commands, evidence


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("prebuild", "postbuild"), required=True)
    parser.add_argument(
        "--project-root", type=Path, default=SIM_ROOT.parents[1],
        help="CrossPoint firmware source root (default: inferred from this script)",
    )
    parser.add_argument(
        "--workspace-root", type=Path,
        help="XTINCT workspace root; inferred when the source is under firmware/",
    )
    parser.add_argument(
        "--artifact-root", type=Path,
        help="Outside-source directory for reports, native builds and QEMU flash",
    )
    parser.add_argument(
        "--canonical-firmware", type=Path,
        help="Canonical update.bin used for exact postbuild byte comparison",
    )
    parser.add_argument(
        "--sleep-asset", type=Path,
        help="Canonical X3 528x792 4-bpp sleep.bmp",
    )
    parser.add_argument(
        "--sleep-master", type=Path,
        help="Uncropped, unquantized master used to create sleep.bmp",
    )
    parser.add_argument("--platformio-core", type=Path)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--boot-app0", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument(
        "--adb-serial",
        help="explicit adb target when other user-owned devices must remain connected",
    )
    args = parser.parse_args()
    configure_runtime_paths(args)
    if args.phase == "postbuild":
        require(args.build_dir is not None and args.boot_app0 is not None and
                args.platformio_core is not None,
                "Postbuild requires --build-dir, --boot-app0 and --platformio-core")

    initial_snapshot = source_snapshot()
    report_path = args.report or ARTIFACT_ROOT / \
        f"x3-full-qa-{args.phase}-{initial_snapshot['sha256']}.json"
    require(not report_path.exists() and not report_path.is_symlink(),
            f"QA report already exists; inspect instead of replacing it: {report_path}")
    commands: list[dict[str, object]] = []
    passed_gates: set[str] = set()
    source_contract = verify_source_contracts()
    passed_gates.add("source-contracts")

    commands.append(run("resource-source", [sys.executable, "-B", "scripts/check_x3_resource_budgets.py"], PROJECT_ROOT))
    commands.append(run("resource-self-test", [sys.executable, "-B", "scripts/check_x3_resource_budgets.py", "--self-test"], PROJECT_ROOT))
    commands.append(run("outbox-memory-source-contract",
                        [sys.executable, "-B",
                         "test/xtinct_sync_contract/verify_outbox_memory_contract.py"],
                        PROJECT_ROOT))
    commands.append(run("public-credential-source-contract",
                        [sys.executable, "-B",
                         "test/xtinct_feed_credential_policy/verify_source_contract.py"],
                        PROJECT_ROOT))
    commands.append(run("epub-source-contract",
                        [sys.executable, "-B",
                         "test/epub_safety_bounds/verify_source_contract.py"],
                        PROJECT_ROOT))
    commands.append(run("epub-source-contract-mutations",
                        [sys.executable, "-B",
                         "test/epub_safety_bounds/verify_source_contract_mutations.py"],
                        PROJECT_ROOT))
    commands.append(run("sleep-refresh-source-contract",
                        [sys.executable, "-B",
                         "test/sleep_screen_refresh/verify_source_contract.py"],
                        PROJECT_ROOT))
    commands.append(run("daily-cards-render-wait-source-contract",
                        [sys.executable, "-B",
                         "test/daily_cards_render_wait/verify_source_contract.py",
                         "--self-test"],
                        PROJECT_ROOT))
    commands.append(run("content-recovery-source-contract",
                        [sys.executable, "-B",
                         "test/xtinct_content_recovery/verify_source_contract.py"],
                        PROJECT_ROOT))
    passed_gates.update({
        "resource-source", "resource-self-test", "outbox-memory-source-contract",
        "public-credential-source-contract", "epub-source-contract",
        "epub-source-contract-mutations", "sleep-refresh-source-contract",
        "daily-cards-render-wait-source-contract",
        "content-recovery-source-contract",
    })
    initial_sleep_assets = sleep_asset_evidence()
    initial_release_support = release_support_evidence()
    sleep_master = Path(str(initial_sleep_assets["master"]["path"]))
    sleep_asset = SLEEP_ASSET
    commands.append(run(
        "sleep-asset",
        [sys.executable, "-B", str(SLEEP_CHECKER), str(sleep_asset),
         "--source", str(sleep_master)],
        WORKSPACE_ROOT,
    ))
    passed_gates.add("sleep-asset")
    commands.append(run("file-transfer-security", [sys.executable, "-B", "scripts/verify_xtinct_file_transfer_security.py"], PROJECT_ROOT))
    passed_gates.add("file-transfer-security")
    commands.append(run("crash-security", [sys.executable, "-B", "scripts/check_crash_secret_policy.py", "--self-test"], PROJECT_ROOT))
    passed_gates.add("crash-security")
    commands.append(run("i18n", [sys.executable, "-B", "scripts/verify_xtinct_i18n.py"], PROJECT_ROOT))
    passed_gates.add("i18n")

    commands.append(run("network-source-parity", [sys.executable, "-B", "verify_network_contract_parity.py"], SIM_ROOT))
    commands.append(run("simulator-python", [sys.executable, "-B", "-m", "unittest", "discover", "-s", ".", "-p", "test*.py", "-q"], SIM_ROOT, 300))
    commands.append(run("behavior-pocket-models", [sys.executable, "-B", "-m", "unittest", "discover", "-s", "qa", "-t", ".", "-p", "test*.py", "-v"], SIM_ROOT, 300))
    passed_gates.update({
        "network-source-parity", "simulator-python", "behavior-pocket-models",
        "behavior-model", "simulator-server",
    })
    commands.append(run("simulator-js", ["npm.cmd", "test"], SIM_ROOT, 300))
    passed_gates.update({"simulator-js", "network-simulator", "today-epub"})

    ui_contract = verify_ui_contracts()
    passed_gates.add("ui-surface")
    native_record, native_count = run_native_suite(
        str(initial_snapshot["sha256"]), args.adb_serial
    )
    passed_gates.add("native-contracts")

    if args.phase == "prebuild":
        pocket = pocket_security(
            args.platformio_core.resolve() if args.platformio_core else None
        )
        if pocket is not None:
            commands.append(pocket)
            passed_gates.add("pocket-security")

    postbuild_commands: list[dict[str, object]] = []
    postbuild_evidence: dict[str, object] | None = None
    if args.phase == "postbuild":
        postbuild_commands, postbuild_evidence = postbuild_gates(
            args.build_dir.resolve(), args.boot_app0.resolve(),
            args.platformio_core.resolve())
        commands.extend(postbuild_commands)
        # The postbuild Pocket command is the stronger artifact-bound gate. It
        # validates the rebuilt SDK state together with the exact linked
        # evidence manifest, so do not rerun the source-only vendor-state gate
        # against a core that custom_sdkconfig has intentionally rebuilt.
        passed_gates.update({
            "firmware-identity", "pocket-security", "resource-linked", "qemu-smoke"
        })

    final_snapshot = source_snapshot()
    require(final_snapshot == initial_snapshot, "Source snapshot changed during QA")
    final_sleep_assets = sleep_asset_evidence()
    require(final_sleep_assets == initial_sleep_assets,
            "Sleep asset or unquantized master changed during QA")
    final_release_support = release_support_evidence()
    require(final_release_support == initial_release_support,
            "Release-critical support code changed during QA")
    scenarios, summary = matrix_status(passed_gates, args.phase)
    if args.phase == "prebuild" and args.platformio_core is None:
        # This exploratory preflight may identify only private-core or
        # post-link gates as pending. The frozen prebuild run supplies the
        # core and must have zero release-blocking failures.
        allowed = {"pocket-security", "firmware-identity", "resource-linked", "qemu-smoke"}
        require(all(item["status"] != "fail" or set(item["missing_gates"]).issubset(allowed)
                    for item in scenarios), "Prebuild QA has failures beyond pending private/postbuild evidence")
    else:
        require(summary["blocking_failures"] == 0,
                f"QA matrix has {summary['blocking_failures']} blocking failures")

    report = {
        "commands": commands,
        "firmware": None if args.phase == "prebuild" else {
            "bytes": CANONICAL_FIRMWARE.stat().st_size,
            "sha256": sha256_file(CANONICAL_FIRMWARE),
        },
        "hardware_only": [item for item in scenarios if item["status"] == "physical-pending"],
        "matrix": scenarios,
        "native": {**native_record, "tests": native_count},
        "passed_gates": sorted(passed_gates),
        "phase": args.phase,
        "postbuild_evidence": postbuild_evidence,
        "release_support": initial_release_support,
        "schema": REPORT_SCHEMA,
        "sleep_assets": initial_sleep_assets,
        "source": initial_snapshot,
        "source_contract": source_contract,
        "summary": summary,
        "ui_contract": ui_contract,
    }
    ARTIFACT_ROOT.mkdir(parents=True, exist_ok=True)
    temporary = report_path.with_suffix(report_path.suffix + ".tmp")
    require(not temporary.exists() and not temporary.is_symlink(),
            f"QA temporary report already exists: {temporary}")
    payload = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    temporary.write_bytes(payload)
    os.replace(temporary, report_path)
    print(f"X3_FULL_QA_{args.phase.upper()}_OK")
    print(f"report={report_path}")
    print(f"report_sha256={hashlib.sha256(payload).hexdigest()}")
    print(f"source_sha256={initial_snapshot['sha256']}")
    print(f"native_tests={native_count}")
    print(f"matrix_pass={summary['passed']} physical_pending={summary['physical_pending']} "
          f"postbuild_pending={summary['postbuild_pending']}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (QaError, OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        print(f"X3 full QA failed closed: {error}", file=sys.stderr)
        raise SystemExit(1)
