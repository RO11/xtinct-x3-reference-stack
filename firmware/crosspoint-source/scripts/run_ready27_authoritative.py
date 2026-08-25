#!/usr/bin/env python3
"""Construct one private READY27 core and launch one authoritative build.

This command is intentionally single-shot and fail-closed.  It owns only the
named fresh approved core directly under the user's PlatformIO root.  It never
cleans or replaces an existing lane and never invokes PlatformIO directly;
the reviewed ``build_xtinct.py`` wrapper remains the build authority.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import build_xtinct as build
import xtinct_ready27_cache as cache


MINIMUM_FREE_BYTES = 16 * 1024 * 1024 * 1024
QA_RUNNER_RELATIVE = Path("tools/x3-simulator/run_full_qa.py")
QA_REPORT_DIRECTORY = Path("delivery/x3-release-qa-20260812")
PINNED_PACKAGES_ENV = "XTINCT_PINNED_PACKAGES_DIR"
READY27_PACKAGES_NAME = "packages"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise cache.Ready27CacheError(message)


def platformio_root() -> Path:
    configured = os.environ.get("PLATFORMIO_CORE_DIR", "").strip()
    require(not configured,
            "Refusing inherited PLATFORMIO_CORE_DIR; this orchestrator owns the lane")
    root = (Path.home() / ".platformio").resolve(strict=True)
    cache.require_plain_directory(root, "PlatformIO root")
    return root


def sanitized_environment(core: Path,
                          inherited: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if inherited is None else inherited)
    for name in list(environment):
        normalized_name = name.upper()
        if normalized_name == PINNED_PACKAGES_ENV:
            require(not environment[name].strip(),
                    f"Refusing inherited {PINNED_PACKAGES_ENV}; this orchestrator owns the path")
            environment.pop(name)
            continue
        require(not normalized_name.startswith("PLATFORMIO_") or
                not environment[name].strip(),
                f"Refusing inherited PlatformIO override: {name}")
    cache.require_plain_directory(core, "READY27 private PlatformIO core")
    packages = core / READY27_PACKAGES_NAME
    cache.require_direct_child(core, packages, "READY27 pinned package directory")
    cache.require_plain_directory(packages, "READY27 pinned package directory")
    environment["PLATFORMIO_CORE_DIR"] = str(core)
    environment[PINNED_PACKAGES_ENV] = str(packages)
    environment["PYTHONUTF8"] = "1"
    environment["PYTHONIOENCODING"] = "utf-8"
    return environment


def python_function_source(source: str, name: str) -> str:
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise cache.Ready27CacheError(
            f"Cannot parse authoritative orchestrator while checking {name}: {error}"
        ) from error
    matches = [
        node for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name
    ]
    require(len(matches) == 1,
            f"Authoritative orchestrator must define {name} exactly once")
    fragment = ast.get_source_segment(source, matches[0])
    require(isinstance(fragment, str) and bool(fragment),
            f"Cannot isolate authoritative orchestrator function: {name}")
    return fragment


def python_constant_string(source: str, name: str) -> str:
    tree = ast.parse(source)
    matches = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    require(len(matches) == 1,
            f"Authoritative orchestrator must assign {name} exactly once")
    try:
        value = ast.literal_eval(matches[0].value)
    except (TypeError, ValueError) as error:
        raise cache.Ready27CacheError(
            f"Authoritative orchestrator constant is not literal: {name}") from error
    require(isinstance(value, str),
            f"Authoritative orchestrator constant is not a string: {name}")
    return value


def require_child_environment_source_contract(source: str) -> None:
    require(python_constant_string(source, "PINNED_PACKAGES_ENV") ==
            "XTINCT_PINNED_PACKAGES_DIR",
            "Authoritative pinned-packages environment name changed")
    require(python_constant_string(source, "READY27_PACKAGES_NAME") == "packages",
            "Authoritative private packages directory name changed")
    fragment = python_function_source(source, "sanitized_environment")
    required = (
        "normalized_name == PINNED_PACKAGES_ENV",
        "require(not environment[name].strip(),",
        "environment.pop(name)",
        "packages = core / READY27_PACKAGES_NAME",
        'cache.require_direct_child(core, packages, "READY27 pinned package directory")',
        'cache.require_plain_directory(packages, "READY27 pinned package directory")',
        'environment["PLATFORMIO_CORE_DIR"] = str(core)',
        "environment[PINNED_PACKAGES_ENV] = str(packages)",
    )
    for expected in required:
        require(fragment.count(expected) == 1,
                f"Authoritative child-environment binding changed: {expected}")


def verify_child_environment_source_mutations(source: str) -> None:
    require_child_environment_source_contract(source)
    mutations = (
        (
            source.replace(
                'PINNED_PACKAGES_ENV = "XTINCT_PINNED_PACKAGES_DIR"',
                'PINNED_PACKAGES_ENV = "XTINCT_UNREVIEWED_PACKAGES_DIR"',
                1,
            ),
            "pinned package environment constant",
        ),
        (
            source.replace(
                'READY27_PACKAGES_NAME = "packages"',
                'READY27_PACKAGES_NAME = "unreviewed-packages"',
                1,
            ),
            "private package directory constant",
        ),
        (
            source.replace(
                "normalized_name == PINNED_PACKAGES_ENV",
                'normalized_name == "XTINCT_UNREVIEWED_PACKAGES_DIR"',
                1,
            ),
            "inherited package override rejection",
        ),
        (
            source.replace(
                "packages = core / READY27_PACKAGES_NAME",
                'packages = core / "unreviewed-packages"',
                1,
            ),
            "private package path derivation",
        ),
        (
            source.replace(
                "environment[PINNED_PACKAGES_ENV] = str(packages)",
                'environment[PINNED_PACKAGES_ENV] = "unreviewed"',
                1,
            ),
            "child package environment assignment",
        ),
    )
    for mutated, label in mutations:
        require(mutated != source,
                f"Authoritative child-environment mutation did not change source: {label}")
        try:
            require_child_environment_source_contract(mutated)
        except cache.Ready27CacheError:
            continue
        raise cache.Ready27CacheError(
            f"Authoritative child-environment source gate accepted mutation: {label}")


def verify_child_environment_behavior() -> None:
    with tempfile.TemporaryDirectory(prefix="xtinct-ready27-env-") as temporary_name:
        core = Path(temporary_name) / "core"
        packages = core / READY27_PACKAGES_NAME
        packages.mkdir(parents=True)
        environment = sanitized_environment(core, {"PATH": "fixture"})
        require(environment["PLATFORMIO_CORE_DIR"] == str(core),
                "Child environment did not retain the exact private core")
        require(environment[PINNED_PACKAGES_ENV] == str(packages),
                "Child environment did not bind the exact private packages directory")
        for inherited_name in (PINNED_PACKAGES_ENV, PINNED_PACKAGES_ENV.lower()):
            try:
                sanitized_environment(core, {inherited_name: str(core / "redirected")})
            except cache.Ready27CacheError:
                continue
            raise cache.Ready27CacheError(
                f"Child environment accepted inherited package redirect: {inherited_name}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def verify_sleep_assets(records: object) -> None:
    require(isinstance(records, dict) and set(records) == {"asset", "master"},
            "Frozen X3 QA sleep-asset evidence is invalid")
    for label, record in records.items():
        require(isinstance(record, dict) and set(record) == {"bytes", "path", "sha256"},
                f"Frozen X3 QA {label} evidence is invalid")
        path = Path(str(record["path"]))
        require(path.is_file() and not path.is_symlink(),
                f"Frozen X3 QA {label} is missing or linked")
        require(path.stat().st_size == record["bytes"] and
                sha256_file(path) == record["sha256"],
                f"Frozen X3 QA {label} changed")


def verify_release_support(records: object) -> None:
    require(isinstance(records, dict) and set(records) == {"sleep_checker"},
            "Frozen X3 QA release-support evidence is invalid")
    record = records["sleep_checker"]
    require(isinstance(record, dict) and set(record) == {"bytes", "path", "sha256"},
            "Frozen X3 QA sleep-checker evidence is invalid")
    path = Path(str(record["path"]))
    require(path.is_file() and not path.is_symlink(),
            "Frozen X3 QA sleep checker is missing or linked")
    require(path.stat().st_size == record["bytes"] and
            sha256_file(path) == record["sha256"],
            "Frozen X3 QA sleep checker changed")


def run_frozen_prebuild_qa(project: Path, core: Path, source_sha256: str) -> dict[str, object]:
    runner = project / QA_RUNNER_RELATIVE
    require(runner.is_file() and not runner.is_symlink(),
            "Mandatory X3 full-QA runner is missing or linked")
    workspace = project.parents[1]
    report_dir = workspace / QA_REPORT_DIRECTORY
    report_dir.mkdir(parents=True, exist_ok=True)
    report = report_dir / f"x3-full-qa-frozen-{source_sha256}.json"
    require(not report.exists() and not report.is_symlink(),
            f"Frozen QA report already exists; inspect instead of replacing it: {report}")
    command = [
        sys.executable, "-B", str(runner), "--phase", "prebuild",
        "--platformio-core", str(core), "--report", str(report),
    ]
    selected_adb = os.environ.get("XTINCT_QA_ADB_SERIAL", "").strip()
    if selected_adb:
        command.extend(["--adb-serial", selected_adb])
    result = subprocess.run(command, cwd=project, check=False)
    require(result.returncode == 0, f"Mandatory frozen X3 prebuild QA exited {result.returncode}")
    require(report.is_file() and not report.is_symlink(),
            "Mandatory frozen X3 prebuild QA did not publish its report")
    try:
        value = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise cache.Ready27CacheError("Frozen X3 QA report is invalid") from error
    require(value.get("schema") == 2 and value.get("phase") == "prebuild",
            "Frozen X3 QA report envelope changed")
    require(value.get("source", {}).get("sha256") == source_sha256,
            "Frozen X3 QA report does not bind the requested source SHA")
    verify_sleep_assets(value.get("sleep_assets"))
    verify_release_support(value.get("release_support"))
    require(value.get("summary", {}).get("blocking_failures") == 0,
            "Frozen X3 QA report contains release-blocking failures")
    required_gates = {
        "behavior-model", "crash-security", "file-transfer-security", "native-contracts",
        "network-simulator", "pocket-security", "resource-source", "simulator-js",
        "sleep-asset", "sleep-refresh-source-contract", "source-contracts",
        "today-epub", "ui-surface",
    }
    require(required_gates.issubset(set(value.get("passed_gates", []))),
            "Frozen X3 QA report omitted a mandatory prebuild gate")
    require(build.get_source_snapshot()["sha256"] == source_sha256,
            "Source changed during frozen X3 prebuild QA")
    return {
        "bytes": report.stat().st_size,
        "command": command,
        "path": report,
        "sha256": sha256_file(report),
        "release_support": value["release_support"],
        "sleep_assets": value["sleep_assets"],
    }


def validate_orchestrator_source() -> None:
    source = Path(__file__).read_text(encoding="utf-8")
    verify_child_environment_source_mutations(source)
    verify_child_environment_behavior()
    required = (
        'parser.add_argument("--lane", choices=cache.READY27_LANES, required=True)',
        'require(not os.path.lexists(core)',
        'args.go == build.get_source_snapshot()["sha256"]',
        'cache.prepare_private_core(root, project, args.lane)',
        'run_frozen_prebuild_qa(project, core, args.go)',
        'verify_release_support(value.get("release_support"))',
        '"PLATFORMIO_CORE_DIR"] = str(core)',
        'environment[PINNED_PACKAGES_ENV] = str(packages)',
        '"build_xtinct.py"),\n               "run", "-e", "default"',
        'Frozen X3 prebuild QA report changed during the authoritative build',
        'private lane preserved for inspection',
    )
    for fragment in required:
        require(fragment in source,
                f"authoritative orchestrator invariant is missing: {fragment}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lane", choices=cache.READY27_LANES, required=True)
    parser.add_argument("--go", required=True,
                        help="must be the exact source freeze SHA-256")
    args = parser.parse_args()
    validate_orchestrator_source()

    project = build.PROJECT_ROOT.resolve(strict=True)
    require(Path.cwd().resolve(strict=True) == project,
            "Run from the XTINCT firmware/crosspoint-source root")
    require(args.go == build.get_source_snapshot()["sha256"],
            "--go does not match the current frozen source snapshot")
    require(shutil.disk_usage(project).free >= MINIMUM_FREE_BYTES,
            "At least 16 GiB of free disk is required for private construction/build")

    root = platformio_root()
    core = root / cache.expected_core_name(args.lane)
    require(not os.path.lexists(core),
            f"READY27 lane already exists; inspect it instead of replacing it: {core}")

    construction = cache.prepare_private_core(root, project, args.lane)
    require(construction["core"] == core,
            "Private-core constructor returned the wrong lane")
    require(build.get_source_snapshot()["sha256"] == args.go,
            "Source changed during private-core construction")
    cache.validate_owned_core(core, args.lane, construction["marker"])

    qa_report = run_frozen_prebuild_qa(project, core, args.go)
    require(build.get_source_snapshot()["sha256"] == args.go,
            "Source changed after mandatory frozen X3 prebuild QA")

    command = [sys.executable, "-B", str(project / "scripts" / "build_xtinct.py"),
               "run", "-e", "default"]
    record = {
        "command": command,
        "construction": construction["construction"],
        "core": str(core),
        "lane": args.lane,
        "policy": "ready27-one-authoritative-build-v1",
        "prebuild_qa": qa_report,
        "schema": 1,
        "source_sha256": args.go,
    }
    print("READY27_AUTHORITATIVE_BUILD_START")
    print(json.dumps(record, default=str, sort_keys=True))
    result = subprocess.run(
        command, cwd=project, env=sanitized_environment(core), check=False
    )
    require(result.returncode == 0,
            f"Authoritative build wrapper exited {result.returncode}; "
            f"private lane preserved for inspection: {core}")
    require(build.get_source_snapshot()["sha256"] == args.go,
            "Source changed during the authoritative build")
    require(qa_report["path"].is_file() and not qa_report["path"].is_symlink() and
            qa_report["path"].stat().st_size == qa_report["bytes"] and
            sha256_file(qa_report["path"]) == qa_report["sha256"],
            "Frozen X3 prebuild QA report changed during the authoritative build")
    verify_sleep_assets(qa_report["sleep_assets"])
    verify_release_support(qa_report["release_support"])
    print("READY27_AUTHORITATIVE_BUILD_OK")
    print(core)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (cache.Ready27CacheError, build.BuildWrapperError, OSError,
            UnicodeError, json.JSONDecodeError) as error:
        print(f"READY27 authoritative build failed closed: {error}", file=sys.stderr)
        raise SystemExit(2)
