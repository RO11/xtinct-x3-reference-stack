#!/usr/bin/env python3
"""One non-authoritative READY27 compile from the existing warmed local cache.

This deliberately does not publish, package, stage, flash, upload, or claim
reproducibility.  It owns one fresh build directory, restores every temporary
tool/parser patch in ``finally``, validates the resulting ESP image/ELF and
exception configuration, then preserves firmware.bin plus its exact ELF/map
and a small attestation in a clearly labelled private-test directory.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import build_xtinct as b
import psutil


BUILD_NAME = ".xtinct-ready27-warmed-compile"
BUILD_MARKER_NAME = BUILD_NAME + ".owner"
CANDIDATE_RELATIVE = Path("firmware/xtinct-x3-20260812-inbox-cards1-private-test")
AUDIT_RELATIVE = Path("firmware/ready27-inbox-cards1-build-audit")
# A clean pioarduino custom-sdkconfig change can spend several minutes
# unpacking the pinned 270+ MiB ESP-IDF library archive before the build root
# changes. Keep the watchdog bounded, but do not kill a legitimate reinstall
# halfway through and leave the package directory incomplete.
NO_PROGRESS_TIMEOUT_SECONDS = 300.0
NIMBLE_SERVER_RELATIVE = Path(".pio/libdeps/default/NimBLE-Arduino/src/NimBLEServer.cpp")
NIMBLE_SERVER_ORIGINAL_SHA256 = "af4335cf6b9e5ca3be63770307736fe50d29b53529c0dd3579f7ed515b553895"
NIMBLE_SERVER_PATCHED_SHA256 = "3ef0726e66b5933d3b4a9e5b163a7f249472b2bb76b2b16ab03e96226a5cada0"
IDF_DEPENDENCY_LOCK_SHA256 = "0b891ff47f2ed76daecbf19132d480839ad55510df1e42cc0d9c5f6c75fae951"


def make_environment(core: Path, packages: Path, build_root: Path,
                     build_cache: Path, ca_bundle: Path) -> dict[str, str]:
    env = dict(os.environ)
    for name in list(env):
        if name.startswith("PLATFORMIO_") or name in {
            "PYTHONHOME", "PYTHONPATH", "VIRTUAL_ENV", "GIT_SSL_NO_VERIFY",
            "SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO",
        }:
            env.pop(name, None)
    for name in (
        "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "all_proxy", "http_proxy", "https_proxy", "no_proxy",
    ):
        env.pop(name, None)
    env.update({
        "PIP_NO_INDEX": "1",
        "UV_NO_INDEX": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
        "SOURCE_DATE_EPOCH": b.REPRODUCIBLE_SOURCE_DATE_EPOCH,
        "TZ": b.REPRODUCIBLE_TIMEZONE,
        "PLATFORMIO_BUILD_CACHE_DIR": str(build_cache),
        "PLATFORMIO_BUILD_DIR": str(build_root),
        "PLATFORMIO_CACHE_DIR": str(core / ".cache"),
        "PLATFORMIO_CORE_DIR": str(core),
        "PLATFORMIO_GLOBALLIB_DIR": str(build_root / "global-lib"),
        "PLATFORMIO_PACKAGES_DIR": str(packages),
        "PLATFORMIO_PLATFORMS_DIR": str(core / "platforms"),
        "PLATFORMIO_SETTING_ENABLE_TELEMETRY": "no",
        "REQUESTS_CA_BUNDLE": str(ca_bundle),
        "PIP_CERT": str(ca_bundle),
        "CURL_CA_BUNDLE": str(ca_bundle),
        "UV_SYSTEM_CERTS": "true",
        "XTINCT_PINNED_PACKAGES_DIR": str(packages),
        "XTINCT_REPRO_BUILD_CACHE_ROOT": str(build_cache),
        "XTINCT_REPRO_CORE_ROOT": str(core),
        "XTINCT_REPRO_PROJECT_ROOT": str(b.PROJECT_ROOT),
        "XTINCT_REPRO_USER_ROOT": str(Path.home()),
        "XTINCT_STRICT_CA_BUNDLE": str(ca_bundle),
        "XTINCT_WARMED_COMPILE_ONLY": "1",
    })
    return env


def create_owned_build(core: Path) -> tuple[Path, Path, bytes]:
    build_root = core / BUILD_NAME
    marker = core / BUILD_MARKER_NAME
    b.require(not b.path_lexists(build_root) and not b.path_lexists(marker),
              "Warmed compile-only build state already exists and needs inspection")
    build_root.mkdir()
    payload = (
        "XTINCT_READY27_WARMED_COMPILE_V1\n"
        f"build={build_root.resolve()}\nproject={b.PROJECT_ROOT.resolve()}\n"
        f"pid={os.getpid()}\n"
    ).encode("utf-8")
    b.write_exclusive(marker, payload)
    build_cache = build_root / ".cache"
    build_cache.mkdir()
    (build_root / "global-lib").mkdir()
    return build_root, marker, payload


def cleanup_owned_build(core: Path, build_root: Path, marker: Path,
                        marker_payload: bytes) -> None:
    b.require(build_root.parent.resolve() == core.resolve() and
              build_root.name == BUILD_NAME,
              "Warmed build cleanup target escaped its exact owner")
    b.require_plain_directory(build_root, "Owned warmed compile build")
    b.require_plain_file(marker, "Owned warmed compile marker")
    b.require(marker.read_bytes() == marker_payload,
              "Warmed compile ownership marker changed")
    b.require_tree_without_reparse_points(build_root, "Owned warmed compile build")
    shutil.rmtree(build_root)
    b.require(not b.path_lexists(build_root), "Warmed compile build cleanup failed")
    marker.unlink()
    b.require(not b.path_lexists(marker), "Warmed compile marker cleanup failed")


def validate_outputs(environment_build: Path, packages: Path,
                      started_ns: int) -> dict[str, object]:
    firmware_bin = environment_build / "firmware.bin"
    firmware_elf = environment_build / "firmware.elf"
    firmware_map = environment_build / "firmware.map"
    artifacts: dict[str, dict[str, object]] = {}
    for path in (firmware_bin, firmware_elf, firmware_map):
        _mode, size, digest = b.validate_fresh_artifact(
            path, started_ns, b.MAX_OTA_APP_BYTES if path == firmware_bin else None
        )
        artifacts[path.name] = {"bytes": size, "sha256": digest}
    b.require(firmware_bin.read_bytes()[:1] == b"\xe9",
              "firmware.bin does not have an ESP application-image header")
    b.require(firmware_elf.read_bytes()[:4] == b"\x7fELF",
              "firmware.elf does not have an ELF header")
    b.require_debug_stripped_elf(firmware_elf)
    sections = b.exception_elf_sections(firmware_elf)
    symbols = b.linked_exception_symbols(firmware_elf, packages)
    sdkconfig = (
        packages / "framework-arduinoespressif32-libs" / "esp32c3" /
        "dio_qspi" / "include" / "sdkconfig.h"
    )
    generated = validate_warmed_exception_override(
        firmware_elf, firmware_map, sdkconfig, packages
    )
    dependencies = list(environment_build.rglob("*.cpp.d"))
    b.require(0 < len(dependencies) <= 4096,
              "Warmed build produced an invalid C++ dependency set")
    guard = b.EXCEPTION_GUARD_RELATIVE.as_posix()
    guarded = sum(
        guard in path.read_text(encoding="utf-8", errors="strict").replace("\\", "/")
        for path in dependencies
    )
    b.require(guarded == len(dependencies),
              "At least one compiled C++ translation unit lacks the exception guard")
    resource_budget = b.verify_x3_resource_budget_linked(
        firmware_bin, firmware_map, packages
    )
    return {
        "artifacts": artifacts,
        "exception_elf_sections": sections,
        "exception_linked_symbols": symbols,
        "exception_sdkconfig": generated,
        "guarded_cpp_translation_units": guarded,
        "x3_resource_budget": resource_budget,
    }


def validate_warmed_exception_override(firmware_elf: Path, firmware_map: Path,
                                       sdkconfig: Path,
                                       packages: Path) -> dict[str, object]:
    """Validate the rebuilt exception runtime and its project fail-safe."""
    b.require_plain_file(sdkconfig, "generated ESP-IDF exception configuration")
    defines: dict[str, str] = {}
    for line in sdkconfig.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"#define\s+(CONFIG_[A-Z0-9_]+)(?:\s+(.*))?", line.strip())
        if match is not None:
            defines[match.group(1)] = (match.group(2) or "1").strip()
    b.require(defines.get("CONFIG_COMPILER_CXX_EXCEPTIONS") == "1",
              "Generated ESP-IDF configuration disabled C++ exceptions")
    b.require(defines.get("CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE") == "1024",
              "Rebuilt ESP-IDF exception emergency pool is not 1024 bytes")
    b.require(defines.get("CONFIG_COMPILER_CXX_RTTI") in {None, "0", "n"},
              "Generated ESP-IDF configuration unexpectedly enabled RTTI")

    override = b.PROJECT_ROOT / "src" / "XtinctExceptionRuntime.cpp"
    b.require_plain_file(override, "READY27 exception runtime override")
    override_text = override.read_text(encoding="utf-8")
    b.require(override_text.count("__cxx_eh_arena_size_get") == 1 and
              override_text.count("return 1024U;") == 1 and
              override_text.count("__cxx_init_dummy") == 1,
              "READY27 exception runtime override changed")

    nm = packages / "toolchain-riscv32-esp" / "bin" / "riscv32-esp-elf-nm.exe"
    b.require_plain_file(nm, "pinned RISC-V symbol reader")
    nm_result = subprocess.run(
        [str(nm), "-a", str(firmware_elf)], cwd=b.PROJECT_ROOT,
        text=True, encoding="utf-8", errors="replace", capture_output=True,
        check=False,
    )
    b.require(nm_result.returncode == 0 and not nm_result.stderr,
              "Pinned RISC-V symbol reader failed for pool override evidence")
    for symbol in ("__cxx_eh_arena_size_get", "__cxx_init_dummy"):
        rows = [line for line in nm_result.stdout.splitlines()
                if line.rstrip().endswith(" " + symbol)]
        b.require(len(rows) == 1 and re.search(r"\sT\s+" + re.escape(symbol) + r"$", rows[0]),
                  f"Linked pool override symbol is not one unique global strong T: {symbol}")

    map_text = firmware_map.read_text(encoding="utf-8", errors="strict")
    b.require("XtinctExceptionRuntime.cpp.o" in map_text and
              "__cxx_eh_arena_size_get" in map_text and
              "__cxx_init_dummy" in map_text,
              "Linker map does not attribute the exception pool override to project code")
    b.require("libcxx.a(cxx_init.cpp.o)" not in map_text.replace("\\", "/"),
              "Stale libcxx cxx_init archive member was pulled beside the project override")
    return {
        "CONFIG_COMPILER_CXX_EXCEPTIONS": "1",
        "CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE": "1024",
        "CONFIG_COMPILER_CXX_RTTI": "disabled",
        "effective_emergency_pool_bytes": 1024,
        "override_path": "src/XtinctExceptionRuntime.cpp",
        "override_sha256": b.sha256_file(override),
    }


def build_progress_signature(build_root: Path) -> tuple[int, int, int, int]:
    files = objects = total_bytes = newest_ns = 0
    for path in build_root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        info = path.stat()
        files += 1
        objects += int(path.suffix.lower() == ".o")
        total_bytes += info.st_size
        newest_ns = max(newest_ns, info.st_mtime_ns)
    return files, objects, total_bytes, newest_ns


def log_tail(path: Path, maximum_bytes: int = 16 * 1024) -> str:
    with path.open("rb") as handle:
        size = handle.seek(0, os.SEEK_END)
        handle.seek(max(0, size - maximum_bytes))
        return handle.read(maximum_bytes).decode("utf-8", errors="replace")


def terminate_owned_process_tree(process: subprocess.Popen[bytes]) -> None:
    try:
        parent = psutil.Process(process.pid)
    except psutil.NoSuchProcess:
        return
    descendants = parent.children(recursive=True)
    for child in reversed(descendants):
        try:
            child.terminate()
        except psutil.NoSuchProcess:
            pass
    try:
        parent.terminate()
    except psutil.NoSuchProcess:
        pass
    _gone, alive = psutil.wait_procs([*descendants, parent], timeout=5.0)
    for owned in alive:
        try:
            owned.kill()
        except psutil.NoSuchProcess:
            pass
    _gone, alive = psutil.wait_procs(alive, timeout=5.0)
    b.require(not alive, "Owned stalled PlatformIO process tree did not terminate")


def run_monitored_compile(command: list[str], project_alias: Path,
                          env: dict[str, str], build_root: Path,
                          stdout_path: Path, stderr_path: Path) -> tuple[int, int]:
    signature = build_progress_signature(build_root)
    last_progress = time.monotonic()
    started_ns = time.time_ns()
    with stdout_path.open("xb") as stdout_handle, stderr_path.open("xb") as stderr_handle:
        process = subprocess.Popen(
            command, cwd=project_alias, env=env,
            stdout=stdout_handle, stderr=stderr_handle,
        )
        while process.poll() is None:
            time.sleep(2.0)
            updated = build_progress_signature(build_root)
            if updated != signature:
                signature = updated
                last_progress = time.monotonic()
            elif time.monotonic() - last_progress >= NO_PROGRESS_TIMEOUT_SECONDS:
                terminate_owned_process_tree(process)
                raise b.BuildWrapperError(
                    "Warmed PlatformIO compile made no build-tree I/O progress for "
                    f"{int(NO_PROGRESS_TIMEOUT_SECONDS)} seconds; signature={signature}; "
                    f"stdout tail={log_tail(stdout_path)!r}; "
                    f"stderr tail={log_tail(stderr_path)!r}"
                )
        return process.returncode, started_ns


def main() -> int:
    project = b.PROJECT_ROOT.resolve()
    b.require(Path.cwd().resolve() == project,
              "Run the warmed compile from the XTINCT firmware project root")
    b.require(not b.path_lexists(project / "platformio.local.ini"),
              "platformio.local.ini is not reviewed for this compile-only candidate")
    b.verify_x3_resource_budget_source()
    candidate = project / CANDIDATE_RELATIVE
    b.require(not b.path_lexists(candidate),
              "Private-test candidate directory already exists; refusing overwrite")
    audit = project / AUDIT_RELATIVE
    b.require(not b.path_lexists(audit),
              "READY27 build-audit directory already exists; refusing overwrite")
    audit.mkdir(parents=True)
    stdout_log = audit / "platformio.stdout.log"
    stderr_log = audit / "platformio.stderr.log"

    core = (Path.home() / ".platformio").resolve()
    packages = core / "packages"
    platforms = core / "platforms"
    python_exe = core / "penv" / "Scripts" / "python.exe"
    for path, label in (
        (core, "local PlatformIO root"),
        (packages, "warmed PlatformIO packages"),
        (platforms, "warmed PlatformIO platforms"),
    ):
        b.require_plain_directory(path, label)
    b.require_plain_file(python_exe, "warmed pioarduino Python")

    # The pioarduino custom-library builder creates a temporary ESP-IDF
    # project in PROJECT_DIR but does not copy the package's dependency lock.
    # Stage the exact ESP32-C3 package lock so the official component manager
    # resolves only the reviewed versions and component hashes.  A successful
    # custom-library build removes it itself; every other exit removes it below.
    dependency_lock = project / "dependencies.lock"
    dependency_lock_source = (
        packages / "framework-arduinoespressif32-libs" / "esp32c3" /
        "dependencies.lock"
    )
    b.require(not b.path_lexists(dependency_lock),
              "Project dependency lock already exists; refusing overwrite")
    b.require_plain_file(dependency_lock_source, "pinned ESP32-C3 dependency lock")
    dependency_lock_bytes = dependency_lock_source.read_bytes()
    b.require(b.sha256(dependency_lock_bytes) == IDF_DEPENDENCY_LOCK_SHA256,
              "Pinned ESP32-C3 dependency lock changed")

    nimble_server = project / NIMBLE_SERVER_RELATIVE
    b.require_plain_file(nimble_server, "pinned NimBLE server source")
    nimble_server_original = nimble_server.read_bytes()
    b.require(b.sha256(nimble_server_original) == NIMBLE_SERVER_ORIGINAL_SHA256,
              "Pinned NimBLE server source is not the reviewed original")
    nimble_server_mode = nimble_server.stat().st_mode

    build_root, marker, marker_payload = create_owned_build(core)
    build_cache = build_root / ".cache"
    source_before = b.get_source_snapshot()
    target, original, mode = b.verify_platform(core)
    idf_target, idf_original = b.verify_idf_builder_script(core)
    idf_mode = idf_target.stat().st_mode
    idf_patched = b.patch_idf_builder_source(idf_original)
    web_target, web_original, web_mode, web_patched = \
        b.verify_webserver_parser_source(packages)
    lock_path = b.resolve_pioarduino_platform_dir(core) / ".xtinct-build-wrapper.lock"
    result_record: dict[str, object] | None = None
    build_succeeded = False
    dependency_lock_staged = False

    try:
        b.write_exclusive(dependency_lock, dependency_lock_bytes)
        dependency_lock_staged = True
        with tempfile.TemporaryDirectory(prefix="xtinct-warmed-ca-") as ca_name:
            ca_bundle = b.make_strict_ca_bundle(Path(ca_name))
            env = make_environment(core, packages, build_root, build_cache, ca_bundle)
            with b.WindowsByteLock(lock_path):
                b.recover_interrupted_patch(target, mode)
                b.recover_interrupted_idf_builder_patch(idf_target, idf_mode)
                b.recover_interrupted_webserver_parser_patch(web_target, web_mode)
                penv_backup = idf_backup = web_backup = False
                try:
                    b.create_backup(target, original)
                    penv_backup = True
                    patched = b.patch_source(original)
                    b.atomic_replace_bytes(target, patched, mode)
                    b.create_idf_builder_backup(idf_target, idf_original)
                    idf_backup = True
                    b.atomic_replace_bytes(idf_target, idf_patched, idf_mode)
                    b.create_webserver_parser_backup(web_target, web_original)
                    web_backup = True
                    b.atomic_replace_bytes(web_target, web_patched, web_mode)

                    with b.SubstProjectAlias(core) as project_alias:
                        env["PLATFORMIO_LIBDEPS_DIR"] = str(project_alias / ".pio" / "libdeps")
                        command = [
                            # Isolated mode ignores PYTHONUTF8/PYTHONIOENCODING on
                            # Windows. Force UTF-8 at interpreter startup so
                            # PlatformIO can relay generated i18n output without
                            # killing its stdout-reader thread on cp1252.
                            str(python_exe), "-X", "utf8", "-I", "-m", "platformio",
                            "run", "-e", "default",
                        ]
                        print("NON-AUTHORITATIVE compile:", subprocess.list2cmdline(command))
                        returncode, started_ns = run_monitored_compile(
                            command, project_alias, env, build_root,
                            stdout_log, stderr_log,
                        )
                        if returncode != 0:
                            raise b.BuildWrapperError(
                                f"Warmed PlatformIO compile exited {returncode}; "
                                f"stdout tail={log_tail(stdout_log)!r}; "
                                f"stderr tail={log_tail(stderr_log)!r}"
                            )
                        result_record = validate_outputs(
                            build_root / "default", packages, started_ns
                        )
                        build_succeeded = True
                finally:
                    b.restore_toolchain_patches(
                        target, original, mode, penv_backup,
                        idf_target, idf_original, idf_mode, idf_backup,
                        web_target, web_original, web_mode, web_backup,
                    )

        b.require(target.read_bytes() == original and idf_target.read_bytes() == idf_original and
                  web_target.read_bytes() == web_original,
                  "A temporary global tool/parser patch was not restored")
        if b.path_lexists(dependency_lock):
            b.require_plain_file(dependency_lock, "staged ESP32-C3 dependency lock")
            b.require(dependency_lock.read_bytes() == dependency_lock_bytes,
                      "Staged ESP32-C3 dependency lock changed")
            dependency_lock.unlink()
        dependency_lock_staged = False
        source_after = b.get_source_snapshot()
        b.require(source_after == source_before,
                  "Shared source bytes changed during the compile-only build")
        b.require(build_succeeded and result_record is not None,
                  "Compile completed without a validated result")

        candidate.mkdir(parents=True)
        for artifact_name in ("firmware.bin", "firmware.elf", "firmware.map"):
            source_artifact = build_root / "default" / artifact_name
            destination_artifact = candidate / artifact_name
            shutil.copy2(source_artifact, destination_artifact)
            b.require(
                b.sha256_file(destination_artifact) ==
                result_record["artifacts"][artifact_name]["sha256"],
                f"Private candidate {artifact_name} copy changed",
            )
        destination_bin = candidate / "firmware.bin"
        attestation = {
            "candidate": "READY27 non-authoritative warmed compile-only private test",
            "caveat": (
                "Uses existing local PlatformIO packages/libdeps; not an approved-lane reproducible release "
                "and not approved for staging/flashing."
            ),
            "identity": {
                "build_id": b.READY_BUILD_ID,
                "release_label": b.READY_RELEASE_LABEL,
                "version": b.READY_VERSION,
            },
            "result": result_record,
            "schema": 1,
            "source": source_before,
        }
        attestation_path = candidate / "candidate.json"
        b.write_exclusive(
            attestation_path,
            (json.dumps(attestation, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )
        print("READY27_WARMED_COMPILE_OK")
        print(destination_bin)
        print(json.dumps(result_record["artifacts"]["firmware.bin"], sort_keys=True))
        return 0
    finally:
        if dependency_lock_staged and b.path_lexists(dependency_lock):
            b.require_plain_file(dependency_lock, "staged ESP32-C3 dependency lock")
            b.require(dependency_lock.read_bytes() == dependency_lock_bytes,
                      "Staged ESP32-C3 dependency lock changed")
            dependency_lock.unlink()
        if b.path_lexists(nimble_server):
            nimble_digest = b.sha256_file(nimble_server)
            if nimble_digest == NIMBLE_SERVER_PATCHED_SHA256:
                b.atomic_replace_bytes(
                    nimble_server, nimble_server_original, nimble_server_mode
                )
            b.require(
                nimble_server.read_bytes() == nimble_server_original,
                "Transient NimBLE connection-info patch was not restored",
            )
        if b.path_lexists(build_root) or b.path_lexists(marker):
            cleanup_owned_build(core, build_root, marker, marker_payload)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (b.BuildWrapperError, OSError, UnicodeError, json.JSONDecodeError) as error:
        audit = b.PROJECT_ROOT / AUDIT_RELATIVE
        if audit.is_dir() and not audit.is_symlink():
            try:
                (audit / "launcher-error.log").write_text(
                    f"{type(error).__name__}: {error}\n",
                    encoding="utf-8",
                    newline="\n",
                )
            except OSError:
                pass
        print(f"READY27 warmed compile failed closed: {error}", file=sys.stderr)
        raise SystemExit(2)
