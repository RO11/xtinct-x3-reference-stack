#!/usr/bin/env python3
"""Build XTINCT through a temporary, verified pioarduino compatibility patch.

pioarduino platform 55.03.37 asks uv for a package named ``platformio``, while
its pinned core archive installs distribution metadata named
``pioarduino-core``.  That makes every build try to reinstall the same archive.
This wrapper applies reviewed package-name and nested certificate-environment
compatibility changes only for one blocking PlatformIO build, restores the
installed platform byte-for-byte, preserves quoted ESP-IDF compile fragments,
keeps regenerated root-project names valid through a SUBST drive root, and
publishes verified artifacts from an owned no-space build directory.
The published generation includes the matching bootloader, partition table,
pinned OTA-data initializer and effective sdkconfig required for offline QEMU.
"""

from __future__ import annotations

import ast
import base64
import ctypes
import ctypes.wintypes
import hashlib
import importlib.metadata
import json
import ntpath
import os
import re
import secrets
import shutil
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import BinaryIO, Sequence

from check_bounded_webserver_parser import (
    ParserFixtureError,
    self_test as verify_bounded_webserver_parser_files,
    verify_source_contract as verify_bounded_webserver_parser_source,
)
from check_crash_secret_policy import CrashSecretPolicyError, verify_policy as verify_crash_secret_policy_files
from check_x3_resource_budgets import (
    BudgetError as X3ResourceBudgetError,
    load_contract as load_x3_resource_contract,
    verify_linked as verify_x3_resource_linked_files,
    verify_source as verify_x3_resource_source_files,
)
from verify_pocket_sync_security import (
    PocketSyncSecurityError,
    verify_build_policy as verify_pocket_sync_build_policy_files,
    verify_source_policy as verify_pocket_sync_source_policy_files,
)
from xtinct_ready27_cache import (
    OWNER_MARKER_NAME as READY27_OWNER_MARKER_NAME,
    OWNER_POLICY as READY27_OWNER_POLICY,
    READY27_CORE_PREFIX,
    READY27_LANES,
    expected_core_name,
    verify_private_esptool_construction_evidence,
)


EXPECTED_PLATFORM_VERSION = "55.03.37"
EXPECTED_PIOPM_VERSION = "55.3.37"
EXPECTED_PLATFORM_URI = (
    "https://github.com/pioarduino/platform-espressif32/releases/download/"
    "55.03.37/platform-espressif32.zip"
)
EXPECTED_PLATFORMIO_VERSION = "6.1.19"
EXPECTED_UV_VERSION = "0.12.1"
EXPECTED_SCONS_PACKAGE_VERSION = "4.40801.0"
EXPECTED_PENV_NAME = "pioarduino-core"
EXPECTED_PENV_URL = "https://github.com/pioarduino/platformio-core/archive/refs/tags/v6.1.19.zip"
EXPECTED_IDF_VERSION = "5.5.2"
EXPECTED_IDF_RELEASE = "5.5.2.260206"
EXPECTED_IDF_PACKAGE_VERSION = "3.50502"
EXPECTED_IDF_PIOPM_VERSION = "3.50502.0"
EXPECTED_IDF_PIOPM_URL = (
    "https://github.com/pioarduino/esp-idf/releases/download/"
    "v5.5.2.260206/esp-idf-v5.5.2.tar.xz"
)
EXPECTED_IDF_ENV_VERSION = "1.0.0"
EXPECTED_IDF_PYTHON_VERSION = "3.11.0-final.0"
EXPECTED_IDF_BUILDER_SHA256 = "27039c90e64478e86b21b0a51a4a439ea55a255fc9af1c573fe3622c00791a78"
EXPECTED_PATCHED_IDF_BUILDER_SHA256 = "6a195c3d8ca5bd47ea41e4e71f80ab51ebd3cc7828e78655f89bc9ce3c359ce9"
EXPECTED_SOURCE_SHA256 = "0f57492bb6d9d1025bd05521112245ceb0c755d8bcc412d6a6a8aeebd4217ad2"
EXPECTED_PATCHED_SHA256 = "63d559e268bfc22979eb4c130f1a0aee3be8cf36182a5194a10b6f60df6a1040"
EXPECTED_READY27_PACKAGE_DIRECTORY = "packages"
MAX_PLATFORMIO_JOBS = 2
PUBLIC_RECOVERY_POLICY = "official-crosspoint-v1.5.0-external-reference-v1"
PUBLIC_RECOVERY_VERSION = "v1.5.0"
PUBLIC_RECOVERY_BYTES = 5544112
PUBLIC_RECOVERY_SHA256 = "a7087155757bc63c1fcf60ae8d60a3760ce6d3406aaf7b9f23d0025244434f08"
PUBLIC_RECOVERY_URL = (
    "https://github.com/crosspoint-reader/crosspoint-reader/releases/download/"
    "v1.5.0/firmware.bin"
)
EXPECTED_ARDUINO_FRAMEWORK_URI = (
    "https://github.com/espressif/arduino-esp32/releases/download/"
    "3.3.7/esp32-core-3.3.7.tar.xz"
)
IDF_BUILDER_UNSAFE_STRIP = rb'.strip("\" ")'
IDF_BUILDER_SAFE_STRIP = b".strip()"
IDF_BUILDER_SAFE_APP_FRAGMENT = b'ccfragment.get("fragment", "").strip()'
IDF_BUILDER_SAFE_COMPONENT_FRAGMENT = b'cc.get("fragment", "").strip()'
IDF_BUILDER_UNSAFE_PROJECT_NAME = (
    b'            fp.write(root_cmake_tpl % os.path.basename(project_dir))'
)
IDF_BUILDER_SAFE_PROJECT_NAME = (
    b'            fp.write(root_cmake_tpl % (os.path.basename(project_dir) or "crosspoint"))'
)
IDF_BUILDER_LDGEN_FUNCTION_ANCHOR = b"def generate_project_ld_script(sdk_config, ignore_targets=None):\n"
IDF_BUILDER_BOUNDED_LDGEN_HELPER = b'''def _xtinct_bounded_ldgen_fragment_path(fragment_path):
    """Keep the Windows ldgen command below cmd.exe's fixed command limit."""
    fragment = Path(fragment_path).resolve()
    framework = Path(FRAMEWORK_DIR).resolve()
    if not IS_WINDOWS:
        return fs.to_unix_path(str(fragment))
    try:
        relative = fragment.relative_to(framework)
    except ValueError:
        return fs.to_unix_path(str(fragment))
    candidate = framework / relative
    if not candidate.is_file() or not os.path.samefile(candidate, fragment):
        raise RuntimeError("XTINCT ldgen relative fragment changed identity")
    return fs.to_unix_path(str(relative))


'''
IDF_BUILDER_UNBOUNDED_LDGEN_FRAGMENT = b'fs.to_unix_path(f) for f in linker_script_fragments'
IDF_BUILDER_BOUNDED_LDGEN_FRAGMENT = (
    b'_xtinct_bounded_ldgen_fragment_path(f) for f in linker_script_fragments'
)
IDF_BUILDER_LDGEN_COMMAND_ANCHOR = (
    b'        "objdump": str(Path(TOOLCHAIN_DIR) / "bin" / env.subst("$CC").replace("-gcc", "-objdump")),\n'
    b'    }\n\n'
    b'    cmd = (\n'
)
IDF_BUILDER_LDGEN_COMMAND_BUDGET = (
    b'        "objdump": str(Path(TOOLCHAIN_DIR) / "bin" / env.subst("$CC").replace("-gcc", "-objdump")),\n'
    b'    }\n'
    b'    if IS_WINDOWS and len(args["fragments"]) > 6000:\n'
    b'        raise RuntimeError("XTINCT ldgen fragment command budget exceeded")\n\n'
    b'    cmd = (\n'
)
IDF_BUILDER_LDGEN_FORMAT_ANCHOR = b'    ).format(**args)\n\n'
IDF_BUILDER_LDGEN_WORKING_DIRECTORY = (
    b'    ).format(**args)\n'
    b'    if IS_WINDOWS:\n'
    b'        cmd = \'cd /d "{}" && {}\'.format(FRAMEWORK_DIR, cmd)\n\n'
)

PACKAGE_LIST_BLOCK = (
    b'                    for p in packages:\n'
    b'                        result[p["name"].lower()] = pepver_to_semver(p["version"])\n'
)
PACKAGE_ALIAS_BLOCK = (
    b'                    if "pioarduino-core" in result and "platformio" not in result:\n'
    b'                        result["platformio"] = result["pioarduino-core"]\n'
)
PINNED_CORE_DECLARATION = (
    b'    "platformio": "https://github.com/pioarduino/platformio-core/archive/refs/tags/v6.1.19.zip",\n'
)

CERTIFI_ENV_BLOCK = b'''    # Set environment variables for certificate bundles
    os.environ["CERTIFI_PATH"] = cert_path
    os.environ["SSL_CERT_FILE"] = cert_path
    os.environ["REQUESTS_CA_BUNDLE"] = cert_path
    os.environ["CURL_CA_BUNDLE"] = cert_path
    os.environ["GIT_SSL_CAINFO"] = cert_path

    # Also propagate to SCons environment if available
    if env is not None:
        env_vars = dict(env.get("ENV", {}))
        env_vars.update({
            "CERTIFI_PATH": cert_path,
            "SSL_CERT_FILE": cert_path,
            "REQUESTS_CA_BUNDLE": cert_path,
            "CURL_CA_BUNDLE": cert_path,
            "GIT_SSL_CAINFO": cert_path,
        })
        env.Replace(ENV=env_vars)'''

STRICT_CERTIFI_ENV_BLOCK = b'''    # XTINCT supplies a task-local bundle and native trust. uv treats an
    # SSL_CERT_FILE as an explicit override even with UV_SYSTEM_CERTS enabled,
    # so do not replace native trust with the penv's public-only certifi file.
    strict_cert_path = os.environ.get("XTINCT_STRICT_CA_BUNDLE", "").strip()
    if not strict_cert_path or not os.path.isfile(strict_cert_path):
        raise RuntimeError("XTINCT strict CA bundle is missing")
    if os.environ.get("UV_SYSTEM_CERTS", "").lower() != "true":
        raise RuntimeError("XTINCT native uv certificate verification is disabled")
    if os.environ.get("SSL_CERT_FILE"):
        raise RuntimeError("XTINCT requires SSL_CERT_FILE to remain unset for native uv trust")
    for variable in ("REQUESTS_CA_BUNDLE", "PIP_CERT", "CURL_CA_BUNDLE"):
        if os.environ.get(variable) != strict_cert_path:
            raise RuntimeError("XTINCT strict CA environment mismatch: " + variable)
    cert_path = strict_cert_path

    os.environ["CERTIFI_PATH"] = cert_path
    os.environ.pop("SSL_CERT_FILE", None)
    os.environ["REQUESTS_CA_BUNDLE"] = cert_path
    os.environ["PIP_CERT"] = cert_path
    os.environ["CURL_CA_BUNDLE"] = cert_path
    os.environ["UV_SYSTEM_CERTS"] = "true"
    os.environ.pop("GIT_SSL_CAINFO", None)

    # Propagate the same strict split to nested SCons actions.
    if env is not None:
        env_vars = dict(env.get("ENV", {}))
        env_vars.pop("SSL_CERT_FILE", None)
        env_vars.pop("GIT_SSL_CAINFO", None)
        env_vars.update({
            "CERTIFI_PATH": cert_path,
            "REQUESTS_CA_BUNDLE": cert_path,
            "PIP_CERT": cert_path,
            "CURL_CA_BUNDLE": cert_path,
            "UV_SYSTEM_CERTS": "true",
        })
        env.Replace(ENV=env_vars)'''

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FIRMWARE_RELATIVE = Path(".pio") / "build"
PRIVATE_BUILD_DIRECTORY_NAME = ".xtinct-build-authoritative"
PRIVATE_BUILD_CACHE_DIRECTORY_NAME = ".cache"
PRIVATE_BUILD_MARKER_SUFFIX = ".owner"
LINKED_PROVENANCE_DIRECTORY = "linked-provenance"
LINKED_DEPENDENCY_NAMES = ("NimBLEServer.cpp.d", "PocketSyncBleServer.cpp.d")
EXCEPTION_BUILD_EVIDENCE_NAME = "cxx-exception-build-evidence.json"
EXCEPTION_CONSTRUCTION_EVIDENCE_NAME = "xtinct-exception-construction.json"
EXCEPTION_GUARD_RELATIVE = Path("scripts/xtinct_exception_build_guard.h")
EXCEPTION_POLICY = "effective-fexceptions-forced-guard-all-project-cxx-v1"
EXCEPTION_RUNTIME_PROBE_RELATIVE = Path("test/epub_safety_bounds/EpubSafetyBoundsTest.cpp")
EXCEPTION_RUNTIME_PROBE_TEST = (
    "EpubSafetyBounds.RealAllocatorFailureAfterSuccessfulPreflightIsTransactional"
)
EXCEPTION_REQUIRED_SYMBOLS = (
    "__cxa_begin_catch",
    "__cxa_end_catch",
    "__cxa_throw",
    "__cxx_eh_arena_size_get",
    "__gxx_personality_v0",
    "__register_frame_info",
)
EXCEPTION_FORBIDDEN_STUB_SYMBOLS = (
    "__wrap___cxa_throw",
    "__wrap___gxx_personality_v0",
    "__wrap__Unwind_RaiseException",
)
PRIVATE_DEPENDENCY_DIRECTORY = "private"
NORMALIZED_DEPENDENCY_SUFFIX = ".normalized"
RAW_MAP_EVIDENCE_NAME = "firmware.map.raw"
VIRTUAL_SDK_PATH_ROOT = "//IDF"
VIRTUAL_SDK_COMPONENT = "components"
VIRTUAL_SDK_SEPARATORS = ("/", "\\")
VIRTUAL_SDK_POLICY = "idf-components-map-archive-state-bound-v4"
VIRTUAL_SDK_VENDOR_PROBE_STATE = "vendor-official-archive-v1"
VIRTUAL_SDK_REBUILT_PROBE_STATE = "custom-sdkconfig-rebuilt-v1"
VIRTUAL_SDK_PROBE_STATES = (
    VIRTUAL_SDK_VENDOR_PROBE_STATE,
    VIRTUAL_SDK_REBUILT_PROBE_STATE,
)
VIRTUAL_SDK_ARCHIVE_DIRECTORY = Path(
    "framework-arduinoespressif32-libs/esp32c3/lib"
)
VIRTUAL_SDK_BOOTLOADER_ELF_RELATIVE = Path(
    "framework-arduinoespressif32-libs/esp32c3/bin/bootloader_dio_80m.elf"
)
VIRTUAL_SDK_BOOTLOADER_ELF_BYTES = 486_812
VIRTUAL_SDK_BOOTLOADER_ELF_SHA256 = (
    "12e7c6d6be81fa48876117125eaee8d65ac307454a48b77f3bf1c623c7932c3d"
)
EXPECTED_BOOTLOADER_SOURCE_VIRTUAL_PATH = (
    "//IDF/components/bootloader_support/src/esp32c3/bootloader_esp32c3.c"
)
VIRTUAL_PROJECT_PATH_PREFIX = "//xtinct/"
VIRTUAL_PROJECT_PATH_ROOTS = ("build", "core", "packages", "source", "user")
REPRODUCIBLE_PATH_MAP_TARGETS = tuple(
    f"/xtinct/{root}" for root in VIRTUAL_PROJECT_PATH_ROOTS
)
MINIZ_SOURCE_RELATIVE = Path("lib/miniz/third_party/miniz.c")
EXPECTED_MINIZ_SOURCE_BYTES = 350352
EXPECTED_MINIZ_SOURCE_SHA256 = (
    "e2c1aeb66eef9191d8c3feb164db2def2335a61d039bf04ed849f6b042433b30"
)
EXPECTED_MINIZ_VIRTUAL_SOURCE_PATH = "//xtinct/source/lib/miniz/third_party/miniz.c"
ARTIFACT_PRIVACY_POLICY = "nul-ascii-utf16le-embedded-drive-unc-uri-aware-v3"
ARTIFACT_PRIVACY_SCANNER = "scripts/verify_pocket_sync_security.py"
ARTIFACT_PRIVACY_URI_SCHEMES = ("ftp", "http", "https")
ARTIFACT_PRIVACY_MARKER_CLASSES = (
    "windows-user-root", "project-alias-x", "private-build-directory", "current-profile-boundary"
)
BOOTLOADER_SUPPORT_ARCHIVE_RELATIVE = Path(
    "framework-arduinoespressif32-libs/esp32c3/lib/libbootloader_support.a"
)
VENDOR_BOOTLOADER_SUPPORT_ARCHIVE_BYTES = 834398
VENDOR_BOOTLOADER_SUPPORT_ARCHIVE_SHA256 = (
    "b1785faa5e73eb4b5bdc8acdac67815150a254e936ace48c6feb80485eace16b"
)
REBUILT_BOOTLOADER_SUPPORT_ARCHIVE_BYTES = 821056
REBUILT_BOOTLOADER_SUPPORT_ARCHIVE_SHA256 = (
    "84a546028f555588e884f2ced4cd92f3cdd45cdf9bbe17e7a3b81a09f4819912"
)
EXPECTED_BOOTLOADER_VIRTUAL_PATH = (
    "//IDF/components/bootloader_support/bootloader_flash/src/bootloader_flash.c"
)
EXPECTED_BOOTLOADER_VIRTUAL_PATH_BYTES = 75
EXPECTED_BOOTLOADER_VIRTUAL_PATH_SHA256 = (
    "56d936bc54ab59e53a5cee5bfa5e394fe08959fc25bafe27aa07fc0757b542da"
)
APP_UPDATE_ARCHIVE_RELATIVE = Path(
    "framework-arduinoespressif32-libs/esp32c3/lib/libapp_update.a"
)
VENDOR_APP_UPDATE_ARCHIVE_BYTES = 199542
VENDOR_APP_UPDATE_ARCHIVE_SHA256 = (
    "de2e8af9dd5d6b7af555c797100436bc78bff1c5c5753483a6d2925fed36a13b"
)
REBUILT_APP_UPDATE_ARCHIVE_BYTES = 197484
REBUILT_APP_UPDATE_ARCHIVE_SHA256 = (
    "7df3192d4675072dd39d7c0502aa04ba87ca87c32b937b76f97467ab724c30c0"
)
VENDOR_APP_UPDATE_VIRTUAL_PATH = "//IDF/components/app_update/esp_ota_ops.c"
VENDOR_APP_UPDATE_VIRTUAL_PATH_SHA256 = (
    "b975dcc0e03ac0b3269f808934f30f94e009a3cdaa3f084b75e361ae8519ab04"
)
REBUILT_APP_UPDATE_VIRTUAL_PATH = "//IDF/components/app_update/esp_ota_ops.c"
EXPECTED_APP_UPDATE_VIRTUAL_PATH_BYTES = 41
REBUILT_APP_UPDATE_VIRTUAL_PATH_SHA256 = (
    "b975dcc0e03ac0b3269f808934f30f94e009a3cdaa3f084b75e361ae8519ab04"
)
WEB_SERVER_PARSER_RELATIVE = Path(
    "framework-arduinoespressif32/libraries/WebServer/src/Parsing.cpp"
)
WEB_SERVER_PARSER_PATCH_RELATIVE = Path(
    "patches/arduino-webserver-bounded-Parsing.cpp"
)
WEB_SERVER_PARSER_CHECKER_RELATIVE = Path(
    "scripts/check_bounded_webserver_parser.py"
)
EXPECTED_WEB_SERVER_PARSER_BYTES = 20951
EXPECTED_WEB_SERVER_PARSER_SHA256 = (
    "117ba2a370abf95b7367fff234f9ba2ee42efbb1842df752e7e488c26b04f54b"
)
EXPECTED_PATCHED_WEB_SERVER_PARSER_BYTES = 40356
EXPECTED_PATCHED_WEB_SERVER_PARSER_SHA256 = (
    "d008565080114bf6044a0070952ef9cd63976c887ffd58df66f73b571ba7a20d"
)
EXPECTED_WEB_SERVER_PARSER_CHECKER_BYTES = 52995
EXPECTED_WEB_SERVER_PARSER_CHECKER_SHA256 = (
    "0b840810cc0dc0ed4538d02f21965957067103484e7a12b5a5abac70a9cc410e"
)
EXPECTED_WEB_SERVER_PARSER_BEHAVIOR_PASSES = 159
WEB_SERVER_PARSER_POLICY = "bounded-pre-handler-http-and-multipart-v2"
WEB_SERVER_PARSER_LIMITS = {
    "boundary_bytes": 128,
    "form_field_bytes": 4096,
    "form_field_wire_bytes": 8192,
    "form_retained_bytes": 8192,
    "header_count": 32,
    "header_line_bytes": 1024,
    "plain_body_bytes": 64 * 1024,
    "query_args": 32,
    "query_bytes": 4096,
    "request_line_bytes": 1024,
    "target_bytes": 768,
}
ELF_DEBUG_STRIP_LINK_FLAG = "-Wl,--strip-debug"
LINKED_GATE_LOG_NAME = "pocket-sync-linked-gate.log"
LINKED_EVIDENCE_MANIFEST_NAME = "pocket-sync-linked-evidence.json"
PUBLISH_ROLLBACK_DIRECTORY_NAME = ".xtinct-publish-rollback"
QEMU_FLASH_ARTIFACT_NAMES = (
    "bootloader.bin",
    "partitions.bin",
    "boot_app0.bin",
)
EFFECTIVE_SDKCONFIG_ARTIFACT_NAME = "sdkconfig.h"
MANIFEST_ARTIFACT_NAMES = (
    "firmware.bin",
    "firmware.elf",
    "firmware.map",
    *QEMU_FLASH_ARTIFACT_NAMES,
    EFFECTIVE_SDKCONFIG_ARTIFACT_NAME,
)
BOOT_APP0_PACKAGE_RELATIVE = Path(
    "framework-arduinoespressif32/tools/partitions/boot_app0.bin"
)
BOOT_APP0_BYTES = 0x2000
EXPECTED_BOOT_APP0_SHA256 = (
    "f94c5d786a7a8fab06ac5d10e33bf37711a6697636dc037559ea19cc410a17f0"
)
PUBLISHED_GENERATION_DIRECTORIES = (
    Path(LINKED_PROVENANCE_DIRECTORY),
    Path(LINKED_PROVENANCE_DIRECTORY) / PRIVATE_DEPENDENCY_DIRECTORY,
)
PUBLISHED_GENERATION_FILES = (
    Path("firmware.elf"),
    Path("firmware.map"),
    *(Path(name) for name in QEMU_FLASH_ARTIFACT_NAMES),
    Path(EFFECTIVE_SDKCONFIG_ARTIFACT_NAME),
    *(Path(LINKED_PROVENANCE_DIRECTORY) / name
      for name in (
          *(f"{dependency}{NORMALIZED_DEPENDENCY_SUFFIX}"
            for dependency in LINKED_DEPENDENCY_NAMES),
          EXCEPTION_BUILD_EVIDENCE_NAME,
          LINKED_EVIDENCE_MANIFEST_NAME,
          LINKED_GATE_LOG_NAME,
      )),
    *(Path(LINKED_PROVENANCE_DIRECTORY) / PRIVATE_DEPENDENCY_DIRECTORY / name
      for name in (*LINKED_DEPENDENCY_NAMES, RAW_MAP_EVIDENCE_NAME)),
    Path("firmware.bin"),
)
SOURCE_SNAPSHOT_SCRIPT = "scripts/Get-XtinctSourceSnapshot.ps1"
SUBST_DRIVE_CANDIDATES = ("X",)
SUBST_MARKER_PREFIX = ".xtinct-subst-"
CORE_SUBST_DRIVE_CANDIDATES = ("Y",)
CORE_SUBST_MARKER_PREFIX = ".xtinct-core-subst-"
MAX_OTA_APP_BYTES = 0x640000
REPRODUCIBLE_SOURCE_DATE_EPOCH = "1786182071"
REPRODUCIBLE_TIMEZONE = "UTC"
READY_RELEASE_LABEL = "v1.6.2-xtinct.2"
READY_BUILD_ID = "BUILD-162-XTINCT2-PUBLIC"
READY_VERSION = "1.6.2-xtinct.2"
PLATFORMIO_ROOT_CMAKE_EMPTY = (
    b"cmake_minimum_required(VERSION 3.16.0)\r\n"
    b"include($ENV{IDF_PATH}/tools/cmake/project.cmake)\r\n"
    b"project()\r\n"
)
PLATFORMIO_ROOT_CMAKE = (
    b"cmake_minimum_required(VERSION 3.16.0)\r\n"
    b"include($ENV{IDF_PATH}/tools/cmake/project.cmake)\r\n"
    b"project(crosspoint)\r\n"
)


class BuildWrapperError(RuntimeError):
    """A fail-closed wrapper invariant did not hold."""


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BuildWrapperError(message)


def verify_crash_secret_policy() -> None:
    try:
        verify_crash_secret_policy_files(PROJECT_ROOT)
    except (CrashSecretPolicyError, OSError, UnicodeError) as error:
        raise BuildWrapperError(f"Crash secret-retention policy failed: {error}") from error


def verify_file_transfer_security() -> None:
    verifier = PROJECT_ROOT / "scripts" / "verify_xtinct_file_transfer_security.py"
    require_plain_file(verifier, "XTINCT File Transfer security verifier")
    result = subprocess.run(
        [sys.executable, "-B", str(verifier)],
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise BuildWrapperError(f"File Transfer security policy failed: {detail}")
    if result.stdout:
        print(result.stdout, end="")


def verify_i18n_security() -> None:
    verifier = PROJECT_ROOT / "scripts" / "verify_xtinct_i18n.py"
    require_plain_file(verifier, "XTINCT i18n verifier")
    result = subprocess.run(
        [sys.executable, "-B", str(verifier)],
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise BuildWrapperError(f"XTINCT i18n policy failed: {detail}")
    if result.stdout:
        print(result.stdout, end="")


def verify_x3_resource_budget_source() -> None:
    try:
        contract, _path, digest = load_x3_resource_contract(PROJECT_ROOT)
        require(
            contract["device"]["ota_slot_bytes"] == MAX_OTA_APP_BYTES,
            "X3 resource contract and build-wrapper OTA limits disagree",
        )
        verify_x3_resource_source_files(PROJECT_ROOT, contract, digest)
    except (X3ResourceBudgetError, OSError, UnicodeError, ValueError) as error:
        raise BuildWrapperError(f"X3 resource budget source policy failed: {error}") from error
    print(f"X3_RESOURCE_BUDGET_SOURCE_OK {digest}")


def verify_x3_resource_budget_linked(firmware_bin: Path, firmware_map: Path,
                                     packages_dir: Path) -> dict[str, object]:
    sdkconfig = (
        packages_dir / "framework-arduinoespressif32-libs" / "esp32c3" /
        "dio_qspi" / "include" / "sdkconfig.h"
    )
    try:
        contract, _path, digest = load_x3_resource_contract(PROJECT_ROOT)
        result = verify_x3_resource_linked_files(
            PROJECT_ROOT, contract, digest, firmware_bin, firmware_map, sdkconfig
        )
    except (X3ResourceBudgetError, OSError, UnicodeError, ValueError) as error:
        raise BuildWrapperError(f"X3 linked resource budget failed: {error}") from error
    actual = result["actual"]
    print(
        "X3_RESOURCE_BUDGET_LINKED_OK "
        f"bin={actual['firmware_bin_bytes']} "
        f"headroom={actual['firmware_headroom_bytes']} "
        f"dram={actual['total_dram_image_bytes']} "
        f"rtc={actual['rtc_slow_used_bytes']}"
    )
    for warning in result["warnings"]:
        print(f"X3_RESOURCE_BUDGET_WARNING {warning}")
    return result


def verify_pocket_sync_source_security(core_dir: Path) -> None:
    packages_dir = ready27_packages_dir(core_dir)
    require(packages_dir is not None, "Pocket Sync requires the private READY27 package directory")
    libdeps_dir = core_dir / "libdeps"
    require_plain_directory(libdeps_dir, "Pocket Sync private READY27 dependency seed")
    try:
        verify_pocket_sync_source_policy_files(
            PROJECT_ROOT, packages_dir, libdeps_dir, VIRTUAL_SDK_VENDOR_PROBE_STATE
        )
    except (PocketSyncSecurityError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        raise BuildWrapperError(f"Pocket Sync source security policy failed: {error}") from error
    print("POCKET_SYNC_SOURCE_SECURITY_OK")


def verify_pocket_sync_build_security(source_dir: Path, core_dir: Path) -> None:
    packages_dir = ready27_packages_dir(core_dir)
    require(packages_dir is not None, "Pocket Sync requires the private READY27 package directory")
    libdeps_dir = core_dir / "libdeps"
    require_plain_directory(libdeps_dir, "Pocket Sync private READY27 dependency seed")
    try:
        verify_pocket_sync_build_policy_files(
            PROJECT_ROOT, source_dir, packages_dir, libdeps_dir
        )
    except (PocketSyncSecurityError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        raise BuildWrapperError(f"Pocket Sync linked-image security policy failed: {error}") from error
    print("POCKET_SYNC_LINKED_SECURITY_OK")


def write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(fd)


def atomic_replace_bytes(path: Path, data: bytes, mode: int) -> None:
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.xtinct-", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, stat.S_IMODE(mode))
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def ensure_platformio_root_cmake(project_root: Path) -> None:
    """Keep PlatformIO from deriving an empty project name at a SUBST root.

    Pioarduino generates this ignored scaffold from ``basename(PROJECT_DIR)``.
    A drive-root alias such as ``X:\\`` has an empty basename, producing
    ``project()``; ESP-IDF then calls CMake's project macro without a name and
    configuration fails. Only the exact pioarduino scaffold is repaired. An
    unexpected file is treated as user-owned and fails closed.
    """

    require_plain_directory(project_root, "XTINCT project root for CMake scaffold")
    cmake_path = project_root / "CMakeLists.txt"
    if not path_lexists(cmake_path):
        write_exclusive(cmake_path, PLATFORMIO_ROOT_CMAKE)
        require_plain_file(cmake_path, "Created PlatformIO root CMake scaffold")
        require(cmake_path.read_bytes() == PLATFORMIO_ROOT_CMAKE, "CMake scaffold creation changed bytes")
        print("Created deterministic PlatformIO CMake project scaffold.")
        return

    require_plain_file(cmake_path, "PlatformIO root CMake scaffold")
    current = cmake_path.read_bytes()
    if current == PLATFORMIO_ROOT_CMAKE:
        return
    require(
        current == PLATFORMIO_ROOT_CMAKE_EMPTY,
        "Unexpected ignored CMakeLists.txt; inspect it instead of overwriting user content",
    )
    atomic_replace_bytes(cmake_path, PLATFORMIO_ROOT_CMAKE, cmake_path.stat().st_mode)
    require(cmake_path.read_bytes() == PLATFORMIO_ROOT_CMAKE, "CMake scaffold repair changed bytes")
    print("Repaired empty PlatformIO CMake project name for the no-space alias.")


class WindowsByteLock:
    """An OS-held, non-blocking one-byte lock; the file itself is not the lock."""

    def __init__(self, path: Path):
        self.path = path
        self.handle: BinaryIO | None = None

    def __enter__(self) -> "WindowsByteLock":
        require(os.name == "nt", "This verified build wrapper currently supports Windows only")
        import msvcrt  # Windows-only by design.

        self.handle = self.path.open("a+b")
        self.handle.seek(0, os.SEEK_END)
        if self.handle.tell() == 0:
            self.handle.write(b"\0")
            self.handle.flush()
            os.fsync(self.handle.fileno())
        self.handle.seek(0)
        try:
            msvcrt.locking(self.handle.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            self.handle.close()
            self.handle = None
            raise BuildWrapperError(
                f"Another XTINCT wrapper holds the toolchain lock: {self.path}"
            ) from error
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        if self.handle is None:
            return
        import msvcrt

        self.handle.seek(0)
        msvcrt.locking(self.handle.fileno(), msvcrt.LK_UNLCK, 1)
        self.handle.close()
        self.handle = None


def path_lexists(path: Path) -> bool:
    return os.path.lexists(str(path))


def is_reparse_point(path: Path) -> bool:
    attributes = getattr(os.lstat(path), "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse_flag)


def require_plain_directory(path: Path, description: str) -> None:
    require(path_lexists(path), f"{description} is missing: {path}")
    require(path.is_dir(), f"{description} is not a directory: {path}")
    require(not is_reparse_point(path), f"{description} must not be a reparse point: {path}")


def require_plain_file(path: Path, description: str) -> None:
    require(path_lexists(path), f"{description} is missing: {path}")
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode), f"{description} is not a regular file: {path}")
    require(not is_reparse_point(path), f"{description} must not be a reparse point: {path}")


def require_tree_without_reparse_points(root: Path, description: str = "Private build tree") -> None:
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                entry_path = Path(entry.path)
                require(not is_reparse_point(entry_path), f"{description} contains a reparse point: {entry_path}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(entry_path)


def create_private_build_cache(private_build_dir: Path) -> Path:
    """Create the empty, per-run cache used only by an authoritative build."""
    require_plain_directory(private_build_dir, "XTINCT private build directory")
    cache_dir = private_build_dir / PRIVATE_BUILD_CACHE_DIRECTORY_NAME
    require(cache_dir.parent.resolve() == private_build_dir.resolve(),
            "Private build cache escaped the wrapper-owned build directory")
    require(cache_dir.name == PRIVATE_BUILD_CACHE_DIRECTORY_NAME,
            "Private build cache name is invalid")
    require(not path_lexists(cache_dir),
            f"Private build cache already exists and requires inspection: {cache_dir}")
    cache_dir.mkdir()
    require_plain_directory(cache_dir, "XTINCT private build cache")
    with os.scandir(cache_dir) as entries:
        require(next(entries, None) is None, "New private build cache is not empty")
    return cache_dir


def directory_metadata_snapshot(root: Path) -> dict[str, int | str]:
    """Bind a large excluded cache without re-reading gigabytes of object data."""
    if not path_lexists(root):
        return {"bytes": 0, "entries": 0, "metadata_sha256": hashlib.sha256(b"").hexdigest()}
    require_plain_directory(root, "Project PlatformIO build cache")
    rows: list[tuple[str, str, int, int, int]] = []
    pending = [root]
    total_bytes = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                entry_path = Path(entry.path)
                require(not is_reparse_point(entry_path),
                        f"Project PlatformIO build cache contains a reparse point: {entry_path}")
                info = entry.stat(follow_symlinks=False)
                relative = entry_path.relative_to(root).as_posix()
                attributes = int(getattr(info, "st_file_attributes", 0))
                if entry.is_dir(follow_symlinks=False):
                    rows.append((relative, "D", 0, info.st_mtime_ns, attributes))
                    pending.append(entry_path)
                else:
                    require(stat.S_ISREG(info.st_mode),
                            f"Project PlatformIO build cache contains a non-regular entry: {entry_path}")
                    rows.append((relative, "F", info.st_size, info.st_mtime_ns, attributes))
                    total_bytes += info.st_size
    digest = hashlib.sha256()
    for relative, kind, size, mtime_ns, attributes in sorted(rows, key=lambda row: row[0]):
        digest.update(f"{kind}\0{relative}\0{size}\0{mtime_ns}\0{attributes}\n".encode("utf-8"))
    return {"bytes": total_bytes, "entries": len(rows), "metadata_sha256": digest.hexdigest()}


def elf_section_records(path: Path) -> tuple[tuple[str, int], ...]:
    """Read the ELF32 section-name table without trusting external tooling."""
    require_plain_file(path, "READY27 ELF section-table input")
    with path.open("rb") as handle:
        header = handle.read(52)
        require(len(header) == 52 and header[:7] == b"\x7fELF\x01\x01\x01",
                f"ELF is not a little-endian ELF32 artifact: {path}")
        section_offset = struct.unpack_from("<I", header, 32)[0]
        section_entry_size = struct.unpack_from("<H", header, 46)[0]
        section_count = struct.unpack_from("<H", header, 48)[0]
        string_index = struct.unpack_from("<H", header, 50)[0]
        require(section_offset >= 52 and section_entry_size == 40 and
                1 < section_count < 4096 and 0 < string_index < section_count,
                f"ELF section-table geometry is invalid: {path}")
        file_size = path.stat().st_size
        require(section_offset + section_entry_size * section_count <= file_size,
                f"ELF section table exceeds the artifact: {path}")
        handle.seek(section_offset + section_entry_size * string_index)
        string_header = handle.read(section_entry_size)
        require(len(string_header) == section_entry_size,
                f"ELF section-name header is truncated: {path}")
        string_offset, string_size = struct.unpack_from("<II", string_header, 16)
        require(string_size > 1 and string_offset + string_size <= file_size,
                f"ELF section-name table exceeds the artifact: {path}")
        handle.seek(string_offset)
        string_table = handle.read(string_size)
        require(len(string_table) == string_size and string_table[-1:] == b"\0",
                f"ELF section-name table is truncated: {path}")
        records: list[tuple[str, int]] = []
        for index in range(section_count):
            handle.seek(section_offset + section_entry_size * index)
            section_header = handle.read(section_entry_size)
            require(len(section_header) == section_entry_size,
                    f"ELF section header is truncated: {path}")
            name_offset = struct.unpack_from("<I", section_header, 0)[0]
            section_size = struct.unpack_from("<I", section_header, 20)[0]
            require(name_offset < len(string_table), f"ELF section name escaped its table: {path}")
            end = string_table.find(b"\0", name_offset)
            require(end >= name_offset, f"ELF section name is unterminated: {path}")
            try:
                name = string_table[name_offset:end].decode("ascii")
            except UnicodeDecodeError as error:
                raise BuildWrapperError(f"ELF section name is not ASCII: {path}") from error
            records.append((name, section_size))
    return tuple(records)


def elf_section_names(path: Path) -> tuple[str, ...]:
    return tuple(name for name, _size in elf_section_records(path))


def exception_elf_sections(path: Path) -> dict[str, int]:
    records = elf_section_records(path)
    result: dict[str, int] = {}
    for required_name in (".eh_frame", ".eh_frame_hdr"):
        matches = [size for name, size in records if name == required_name]
        require(len(matches) == 1 and matches[0] > 0,
                f"ELF lacks one nonempty {required_name} section: {path}")
        result[required_name] = matches[0]
    return result


def require_debug_stripped_elf(path: Path) -> None:
    names = elf_section_names(path)
    forbidden = tuple(name for name in names if name.startswith((".debug", ".zdebug")))
    require(not forbidden, f"ELF retains debug sections: {', '.join(forbidden)}")
    require(".symtab" in names and ".strtab" in names,
            "Debug-stripped ELF did not retain its audit symbol tables")


def elf_section_for_file_offset(path: Path, file_offset: int) -> str | None:
    """Return the smallest file-backed ELF section containing an absolute offset."""
    with path.open("rb") as handle:
        header = handle.read(52)
        if len(header) != 52 or header[:7] != b"\x7fELF\x01\x01\x01":
            return None
        section_offset = struct.unpack_from("<I", header, 32)[0]
        section_entry_size = struct.unpack_from("<H", header, 46)[0]
        section_count = struct.unpack_from("<H", header, 48)[0]
        string_index = struct.unpack_from("<H", header, 50)[0]
        file_size = path.stat().st_size
        require(section_offset >= 52 and section_entry_size == 40 and
                1 < section_count < 4096 and 0 < string_index < section_count and
                section_offset + section_entry_size * section_count <= file_size,
                f"ELF diagnostic section-table geometry is invalid: {path}")
        handle.seek(section_offset + section_entry_size * string_index)
        string_header = handle.read(section_entry_size)
        require(len(string_header) == section_entry_size,
                f"ELF diagnostic section-name header is truncated: {path}")
        string_offset, string_size = struct.unpack_from("<II", string_header, 16)
        require(string_size > 1 and string_offset + string_size <= file_size,
                f"ELF diagnostic section-name table exceeds the artifact: {path}")
        handle.seek(string_offset)
        names = handle.read(string_size)
        require(len(names) == string_size and names[-1:] == b"\0",
                f"ELF diagnostic section-name table is truncated: {path}")
        matches: list[tuple[int, str]] = []
        for index in range(section_count):
            handle.seek(section_offset + section_entry_size * index)
            section_header = handle.read(section_entry_size)
            require(len(section_header) == section_entry_size,
                    f"ELF diagnostic section header is truncated: {path}")
            name_offset, section_type = struct.unpack_from("<II", section_header, 0)
            entry_offset, entry_size = struct.unpack_from("<II", section_header, 16)
            if section_type == 8 or entry_size == 0 or not (entry_offset <= file_offset < entry_offset + entry_size):
                continue
            require(name_offset < len(names), f"ELF diagnostic section name escaped its table: {path}")
            end = names.find(b"\0", name_offset)
            require(end >= name_offset, f"ELF diagnostic section name is unterminated: {path}")
            try:
                name = names[name_offset:end].decode("ascii")
            except UnicodeDecodeError as error:
                raise BuildWrapperError(f"ELF diagnostic section name is not ASCII: {path}") from error
            matches.append((entry_size, name))
    return min(matches)[1] if matches else None


def logical_drive_mask() -> int:
    require(os.name == "nt", "SUBST project aliases are supported on Windows only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_logical_drives = kernel32.GetLogicalDrives
    get_logical_drives.argtypes = []
    get_logical_drives.restype = ctypes.wintypes.DWORD
    mask = int(get_logical_drives())
    require(mask != 0, f"GetLogicalDrives failed with Windows error {ctypes.get_last_error()}")
    return mask


def drive_is_logical(letter: str) -> bool:
    require(re.fullmatch(r"[A-Z]", letter) is not None, f"Invalid drive letter: {letter}")
    return bool(logical_drive_mask() & (1 << (ord(letter) - ord("A"))))


def windows_short_directory(path: Path, label: str) -> Path:
    """Return the exact 8.3 view used to keep Windows build commands bounded."""
    require(os.name == "nt", "Windows short paths are supported on Windows only")
    require_plain_directory(path, label)
    resolved = path.resolve()
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_short_path = kernel32.GetShortPathNameW
    get_short_path.argtypes = [
        ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPWSTR, ctypes.wintypes.DWORD,
    ]
    get_short_path.restype = ctypes.wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    length = int(get_short_path(str(resolved), buffer, len(buffer)))
    require(0 < length < len(buffer),
            f"GetShortPathName({label}) failed with Windows error {ctypes.get_last_error()}")
    short_path = Path(buffer.value)
    require(short_path.is_dir() and not short_path.is_symlink() and
            os.path.samefile(short_path, resolved),
            f"Windows short path for {label} changed identity")
    require(not any(character.isspace() for character in str(short_path)) and
            len(str(short_path)) < len(str(resolved)),
            f"Windows short path for {label} is not a shorter no-space alias")
    return short_path


def query_dos_device(letter: str) -> tuple[str, ...]:
    require(re.fullmatch(r"[A-Z]", letter) is not None, f"Invalid drive letter: {letter}")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    query = kernel32.QueryDosDeviceW
    query.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPWSTR, ctypes.wintypes.DWORD]
    query.restype = ctypes.wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    length = int(query(f"{letter}:", buffer, len(buffer)))
    if length == 0:
        error = ctypes.get_last_error()
        if error in (2, 3):  # ERROR_FILE_NOT_FOUND / ERROR_PATH_NOT_FOUND
            return ()
        raise BuildWrapperError(f"QueryDosDevice({letter}:) failed with Windows error {error}")
    return tuple(value for value in buffer[:length].split("\0") if value)


def normalized_device_target(value: str) -> str:
    return os.path.normcase(value.replace("/", "\\").rstrip("\\"))


def expected_subst_target(project_root: Path) -> str:
    return "\\??\\" + str(project_root.resolve()).rstrip("\\")


def require_exact_subst_mapping(letter: str, project_root: Path) -> None:
    expected = normalized_device_target(expected_subst_target(project_root))
    targets = query_dos_device(letter)
    require(len(targets) == 1, f"SUBST drive {letter}: does not have exactly one DOS-device target")
    require(
        normalized_device_target(targets[0]) == expected,
        f"SUBST drive {letter}: target changed from the exact XTINCT project root",
    )
    require(drive_is_logical(letter), f"SUBST drive {letter}: is absent from the logical-drive mask")


def system_subst_executable() -> Path:
    require(os.name == "nt", "SUBST project aliases are supported on Windows only")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_system_directory = kernel32.GetSystemDirectoryW
    get_system_directory.argtypes = [ctypes.wintypes.LPWSTR, ctypes.wintypes.UINT]
    get_system_directory.restype = ctypes.wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = int(get_system_directory(buffer, len(buffer)))
    require(0 < length < len(buffer), f"GetSystemDirectory failed with Windows error {ctypes.get_last_error()}")
    executable = Path(buffer.value) / "subst.exe"
    require_plain_file(executable, "Windows System32 SUBST executable")
    return executable


class SubstProjectAlias:
    """Temporary, owner-marked no-space drive view of the same source tree."""

    def __init__(self, core_dir: Path):
        self.core_dir = core_dir.resolve()
        self.project_root = PROJECT_ROOT.resolve()
        self.letter: str | None = None
        self.alias_root: Path | None = None
        self.marker_path: Path | None = None
        self.marker_bytes: bytes | None = None
        self.active = False

    def _verify_marker(self) -> None:
        require(self.marker_path is not None and self.marker_bytes is not None, "SUBST marker is uninitialized")
        require_plain_file(self.marker_path, "XTINCT SUBST ownership marker")
        require(self.marker_path.read_bytes() == self.marker_bytes, "XTINCT SUBST ownership marker changed")

    def verify(self) -> None:
        require(self.active, "XTINCT SUBST alias is not active")
        require(self.letter is not None and self.alias_root is not None, "XTINCT SUBST alias is incomplete")
        self._verify_marker()
        require_exact_subst_mapping(self.letter, self.project_root)
        require(not any(character.isspace() for character in str(self.alias_root)), "SUBST alias contains whitespace")
        require_plain_directory(self.alias_root, "XTINCT SUBST project root")
        require(os.path.samefile(self.alias_root, self.project_root), "SUBST root is not the XTINCT source directory")

        physical_ini = self.project_root / "platformio.ini"
        alias_ini = self.alias_root / "platformio.ini"
        require_plain_file(physical_ini, "Physical XTINCT platformio.ini")
        require_plain_file(alias_ini, "Aliased XTINCT platformio.ini")
        require(os.path.samefile(alias_ini, physical_ini), "SUBST platformio.ini file identity changed")
        physical_ini_bytes = physical_ini.read_bytes()
        alias_ini_bytes = alias_ini.read_bytes()
        require(alias_ini_bytes == physical_ini_bytes, "SUBST platformio.ini bytes changed")
        require(sha256(alias_ini_bytes) == sha256(physical_ini_bytes), "SUBST platformio.ini hash changed")

        # Public source archives and monorepo checkouts need no nested Git
        # metadata. Bind the alias to the reviewed source snapshotter instead;
        # source bytes are checked again before and after every build.
        physical_snapshotter = self.project_root / SOURCE_SNAPSHOT_SCRIPT
        alias_snapshotter = self.alias_root / SOURCE_SNAPSHOT_SCRIPT
        require_plain_file(physical_snapshotter, "Physical XTINCT source snapshotter")
        require_plain_file(alias_snapshotter, "Aliased XTINCT source snapshotter")
        require(os.path.samefile(alias_snapshotter, physical_snapshotter),
                "SUBST source snapshotter identity changed")
        require(alias_snapshotter.read_bytes() == physical_snapshotter.read_bytes(),
                "SUBST source snapshotter bytes changed")

    def __enter__(self) -> Path:
        require_plain_directory(self.core_dir, "PlatformIO core directory")
        require_plain_directory(self.project_root, "XTINCT physical project root")
        stale_markers = list(self.core_dir.glob(f"{SUBST_MARKER_PREFIX}*.owner"))
        require(not stale_markers, f"Stale XTINCT SUBST ownership markers require inspection: {stale_markers}")

        for candidate in SUBST_DRIVE_CANDIDATES:
            if drive_is_logical(candidate) or query_dos_device(candidate):
                continue
            self.letter = candidate
            break
        require(self.letter is not None, "No unused high drive letter is available for the XTINCT source alias")

        self.alias_root = Path(f"{self.letter}:\\")
        self.marker_path = self.core_dir / f"{SUBST_MARKER_PREFIX}{self.letter}.owner"
        nonce = secrets.token_hex(16)
        self.marker_bytes = (
            "XTINCT_SUBST_V1\n"
            f"drive={self.letter}:\n"
            f"target={self.project_root}\n"
            f"pid={os.getpid()}\n"
            f"nonce={nonce}\n"
        ).encode("utf-8")
        write_exclusive(self.marker_path, self.marker_bytes)
        self._verify_marker()

        command = [str(system_subst_executable()), f"{self.letter}:", str(self.project_root)]
        result = subprocess.run(
            command,
            cwd=self.core_dir,
            text=True,
            errors="replace",
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            if not query_dos_device(self.letter):
                self._verify_marker()
                self.marker_path.unlink()
            raise BuildWrapperError(
                f"System32 subst.exe exited {result.returncode}: {(result.stderr or result.stdout).strip()}"
            )

        self.active = True
        try:
            self.verify()
        except Exception:
            # Removal is attempted only when the exact owner marker and exact
            # mapping can both still be proven by cleanup().
            self.cleanup()
            raise
        return self.alias_root

    def cleanup(self) -> None:
        require(self.active, "XTINCT SUBST cleanup called without an active alias")
        require(self.letter is not None and self.alias_root is not None, "XTINCT SUBST cleanup state is incomplete")
        self.verify()
        command = [str(system_subst_executable()), f"{self.letter}:", "/D"]
        result = subprocess.run(
            command,
            cwd=self.core_dir,
            text=True,
            errors="replace",
            capture_output=True,
            check=False,
        )
        require(
            result.returncode == 0,
            f"System32 subst.exe cleanup exited {result.returncode}: {(result.stderr or result.stdout).strip()}",
        )
        require(not query_dos_device(self.letter), f"SUBST drive {self.letter}: remained mapped after cleanup")
        require(not drive_is_logical(self.letter), f"SUBST drive {self.letter}: remained a logical drive after cleanup")
        self._verify_marker()
        self.marker_path.unlink()
        require(not path_lexists(self.marker_path), "XTINCT SUBST ownership marker cleanup was incomplete")
        self.active = False

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.cleanup()


class SubstCoreAlias:
    """Owned short drive view of the exact private core for Windows commands."""

    def __init__(self, core_dir: Path):
        self.core_dir = core_dir.resolve()
        self.letter: str | None = None
        self.alias_root: Path | None = None
        self.marker_path: Path | None = None
        self.marker_bytes: bytes | None = None
        self.active = False

    def _verify_marker(self) -> None:
        require(self.marker_path is not None and self.marker_bytes is not None,
                "Core SUBST marker is uninitialized")
        require_plain_file(self.marker_path, "XTINCT core SUBST ownership marker")
        require(self.marker_path.read_bytes() == self.marker_bytes,
                "XTINCT core SUBST ownership marker changed")

    def verify(self) -> None:
        require(self.active and self.letter is not None and self.alias_root is not None,
                "XTINCT core SUBST alias is incomplete")
        self._verify_marker()
        require_exact_subst_mapping(self.letter, self.core_dir)
        require(str(self.alias_root) == f"{self.letter}:\\" and
                not any(character.isspace() for character in str(self.alias_root)),
                "XTINCT core SUBST root changed")
        require_plain_directory(self.alias_root, "XTINCT core SUBST root")
        require(os.path.samefile(self.alias_root, self.core_dir),
                "XTINCT core SUBST root changed identity")
        for name in ("packages", "platforms", "libdeps", "penv"):
            physical = self.core_dir / name
            alias = self.alias_root / name
            require_plain_directory(physical, f"Physical private core {name}")
            require_plain_directory(alias, f"Aliased private core {name}")
            require(os.path.samefile(alias, physical),
                    f"XTINCT core SUBST {name} changed identity")

    def __enter__(self) -> Path:
        require_plain_directory(self.core_dir, "Private READY27 core")
        stale = list(self.core_dir.glob(f"{CORE_SUBST_MARKER_PREFIX}*.owner"))
        require(not stale, f"Stale XTINCT core SUBST markers require inspection: {stale}")
        for candidate in CORE_SUBST_DRIVE_CANDIDATES:
            if not drive_is_logical(candidate) and not query_dos_device(candidate):
                self.letter = candidate
                break
        require(self.letter is not None,
                "No unused drive letter is available for the private core alias")
        self.alias_root = Path(f"{self.letter}:\\")
        self.marker_path = self.core_dir / f"{CORE_SUBST_MARKER_PREFIX}{self.letter}.owner"
        self.marker_bytes = (
            "XTINCT_CORE_SUBST_V1\n"
            f"drive={self.letter}:\n"
            f"target={self.core_dir}\n"
            f"pid={os.getpid()}\n"
            f"nonce={secrets.token_hex(16)}\n"
        ).encode("utf-8")
        write_exclusive(self.marker_path, self.marker_bytes)
        self._verify_marker()
        result = subprocess.run(
            [str(system_subst_executable()), f"{self.letter}:", str(self.core_dir)],
            cwd=self.core_dir, text=True, errors="replace", capture_output=True, check=False,
        )
        if result.returncode != 0:
            if not query_dos_device(self.letter):
                self._verify_marker()
                self.marker_path.unlink()
            raise BuildWrapperError(
                f"Core subst.exe exited {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()}"
            )
        self.active = True
        try:
            self.verify()
        except Exception:
            self.cleanup()
            raise
        return self.alias_root

    def cleanup(self) -> None:
        require(self.active and self.letter is not None and self.alias_root is not None,
                "XTINCT core SUBST cleanup called without an active alias")
        self.verify()
        result = subprocess.run(
            [str(system_subst_executable()), f"{self.letter}:", "/D"],
            cwd=self.core_dir, text=True, errors="replace", capture_output=True, check=False,
        )
        require(result.returncode == 0,
                f"Core subst.exe cleanup exited {result.returncode}: "
                f"{(result.stderr or result.stdout).strip()}")
        require(not query_dos_device(self.letter) and not drive_is_logical(self.letter),
                f"Core SUBST drive {self.letter}: remained mapped")
        self._verify_marker()
        self.marker_path.unlink()
        require(not path_lexists(self.marker_path),
                "XTINCT core SUBST marker cleanup was incomplete")
        self.active = False

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.cleanup()


class PrivateBuildDirectory:
    """Deterministic no-space build directory with an adjacent ownership sidecar."""

    def __init__(self, core_dir: Path):
        self.core_dir = core_dir.resolve()
        self.build_root = self.core_dir
        self.path: Path | None = None
        self.marker_path: Path | None = None
        self.marker_bytes: bytes | None = None

    def __enter__(self) -> Path:
        require_plain_directory(self.core_dir, "PlatformIO core directory")
        require_plain_directory(self.build_root, "XTINCT private build root")
        require(
            not any(character.isspace() for character in str(self.build_root)),
            f"Private build root contains whitespace: {self.build_root}",
        )
        require(
            shutil.disk_usage(self.build_root).free >= 4 * 1024 * 1024 * 1024,
            f"Private build root has less than 4 GiB free: {self.build_root}",
        )
        self.path = self.build_root / PRIVATE_BUILD_DIRECTORY_NAME
        self.marker_path = self.path.with_name(self.path.name + PRIVATE_BUILD_MARKER_SUFFIX)
        require(not path_lexists(self.path),
                f"Deterministic private build path already exists and requires inspection: {self.path}")
        require(not path_lexists(self.marker_path),
                f"Deterministic private build marker already exists and requires inspection: {self.marker_path}")
        self.path.mkdir()
        self.marker_bytes = (
            "XTINCT_PRIVATE_BUILD_V1\n"
            f"build={self.path}\n"
            f"project={PROJECT_ROOT}\n"
            f"pid={os.getpid()}\n"
        ).encode("utf-8")
        try:
            require(self.path.parent.resolve() == self.build_root, "Private build escaped its reviewed root")
            require(self.path.name == PRIVATE_BUILD_DIRECTORY_NAME, "Private build name is invalid")
            require(not any(character.isspace() for character in str(self.path)), "Private build path contains whitespace")
            require_plain_directory(self.path, "Private build directory")
            write_exclusive(self.marker_path, self.marker_bytes)
            require(not is_reparse_point(self.marker_path), "Private build ownership marker is a reparse point")
            require(self.marker_path.read_bytes() == self.marker_bytes, "Private build ownership marker verification failed")
        except Exception:
            if path_lexists(self.marker_path):
                self.marker_path.unlink()
            if path_lexists(self.path):
                os.rmdir(self.path)
            raise
        return self.path

    def cleanup(self) -> None:
        require(self.path is not None and self.marker_path is not None and self.marker_bytes is not None,
                "Private build cleanup called before creation")
        require(self.path.parent.resolve() == self.build_root, "Private build cleanup target escaped its parent")
        require(self.path.name == PRIVATE_BUILD_DIRECTORY_NAME, "Private build cleanup target name is invalid")
        require_plain_directory(self.path, "Private build cleanup target")
        require(path_lexists(self.marker_path), "Private build ownership marker is missing")
        require(self.marker_path.is_file(), "Private build ownership marker is not a regular file")
        require(not is_reparse_point(self.marker_path), "Private build ownership marker is a reparse point")
        require(self.marker_path.read_bytes() == self.marker_bytes, "Private build ownership marker changed")
        require_tree_without_reparse_points(self.path)
        shutil.rmtree(self.path)
        require(not path_lexists(self.path), "Private build directory cleanup was incomplete")
        require(self.marker_path.read_bytes() == self.marker_bytes, "Private build marker changed during cleanup")
        self.marker_path.unlink()
        require(not path_lexists(self.marker_path), "Private build marker cleanup was incomplete")

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.cleanup()


def platformio_core_dir() -> Path:
    configured = os.environ.get("PLATFORMIO_CORE_DIR", "").strip()
    require(bool(configured), "READY27 requires an explicit private PLATFORMIO_CORE_DIR")
    core_dir = Path(configured).expanduser().resolve()
    require_plain_directory(core_dir, "READY27 private PlatformIO core")
    expected_parent = (Path.home() / ".platformio").resolve()
    require(core_dir.parent == expected_parent,
            "READY27 private PlatformIO core escaped the reviewed user PlatformIO root")
    require(core_dir.name in {expected_core_name(lane) for lane in READY27_LANES},
            "READY27 private PlatformIO core name changed")
    return core_dir


def ready27_core_lane(core_dir: Path) -> str:
    require_plain_directory(core_dir, "READY27 private PlatformIO core")
    lanes = [lane for lane in READY27_LANES if core_dir.name == expected_core_name(lane)]
    require(len(lanes) == 1, "READY27 private PlatformIO core has no unique approved lane")
    marker = core_dir / READY27_OWNER_MARKER_NAME
    require_plain_file(marker, "READY27 private core ownership marker")
    try:
        marker_value = json.loads(marker.read_text(encoding="ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BuildWrapperError("READY27 private core ownership marker is invalid") from error
    require(marker_value == {
        "lane": lanes[0],
        "policy": READY27_OWNER_POLICY,
        "schema": 1,
    }, "READY27 private core ownership marker changed")
    return lanes[0]


def ready27_packages_dir(core_dir: Path) -> Path | None:
    configured = os.environ.get("XTINCT_PINNED_PACKAGES_DIR", "").strip()
    if not configured:
        return None

    ready27_core_lane(core_dir)
    expected = (core_dir.resolve() / EXPECTED_READY27_PACKAGE_DIRECTORY).resolve()
    requested = Path(configured).expanduser().resolve()
    require(requested == expected,
            "READY27 package directory is not the private core-owned path")
    require(requested.parent == core_dir.resolve(),
            "READY27 package directory escaped the private PlatformIO core")
    require(requested.name == EXPECTED_READY27_PACKAGE_DIRECTORY,
            "READY27 package directory name changed")
    require_plain_directory(requested, "READY27 pinned package directory")

    framework_dir = requested / "framework-arduinoespressif32"
    require_plain_directory(framework_dir, "READY27 pinned Arduino framework")
    metadata_path = framework_dir / ".piopm"
    require_plain_file(metadata_path, "READY27 pinned Arduino framework metadata")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BuildWrapperError("READY27 pinned Arduino framework metadata is invalid") from error
    require(
        metadata.get("spec", {}).get("uri") == EXPECTED_ARDUINO_FRAMEWORK_URI,
        "READY27 pinned Arduino framework URI changed",
    )
    require(
        str(metadata.get("version", "")).startswith("3.3.7"),
        "READY27 pinned Arduino framework version is not 3.3.7",
    )
    return requested


def verify_public_recovery_reference() -> dict[str, object]:
    require(PUBLIC_RECOVERY_URL.startswith("https://github.com/crosspoint-reader/"),
            "Public recovery reference must remain on the official CrossPoint project")
    require(len(PUBLIC_RECOVERY_SHA256) == 64 and PUBLIC_RECOVERY_BYTES > 0,
            "Public recovery reference metadata is invalid")
    return {
        "bytes": PUBLIC_RECOVERY_BYTES,
        "policy": PUBLIC_RECOVERY_POLICY,
        "sha256": PUBLIC_RECOVERY_SHA256,
        "url": PUBLIC_RECOVERY_URL,
        "version": PUBLIC_RECOVERY_VERSION,
    }


def webserver_parser_paths(packages_dir: Path) -> tuple[Path, Path]:
    require_plain_directory(packages_dir, "READY27 pinned package directory")
    target = packages_dir / WEB_SERVER_PARSER_RELATIVE
    patch = PROJECT_ROOT / WEB_SERVER_PARSER_PATCH_RELATIVE
    require_plain_file(target, "Pinned Arduino WebServer parser")
    require_plain_file(patch, "Reviewed bounded Arduino WebServer parser patch")
    require(target.resolve() == packages_dir.resolve() / WEB_SERVER_PARSER_RELATIVE,
            "Arduino WebServer parser escaped the exact READY27 package path")
    require(patch.resolve() == PROJECT_ROOT.resolve() / WEB_SERVER_PARSER_PATCH_RELATIVE,
            "Arduino WebServer parser patch escaped the XTINCT source tree")
    return target.resolve(), patch.resolve()


def reviewed_webserver_parser_patch() -> bytes:
    patch = PROJECT_ROOT / WEB_SERVER_PARSER_PATCH_RELATIVE
    require_plain_file(patch, "Reviewed bounded Arduino WebServer parser patch")
    require(patch.resolve() == PROJECT_ROOT.resolve() / WEB_SERVER_PARSER_PATCH_RELATIVE,
            "Arduino WebServer parser patch escaped the XTINCT source tree")
    patched = patch.read_bytes()
    verify_webserver_parser_patch_bytes(patched)
    return patched


def verify_webserver_parser_patch_bytes(patched: bytes) -> None:
    require(len(patched) == EXPECTED_PATCHED_WEB_SERVER_PARSER_BYTES and
            sha256(patched) == EXPECTED_PATCHED_WEB_SERVER_PARSER_SHA256,
            "Bounded Arduino WebServer parser patch bytes changed")
    try:
        source = patched.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BuildWrapperError("Bounded Arduino WebServer parser patch is not UTF-8") from error
    try:
        verify_bounded_webserver_parser_source(source)
    except ParserFixtureError as error:
        raise BuildWrapperError(
            f"Bounded Arduino WebServer parser source contract failed: {error}"
        ) from error


def verify_webserver_parser_behavior() -> int:
    checker = PROJECT_ROOT / WEB_SERVER_PARSER_CHECKER_RELATIVE
    require_plain_file(checker, "Bounded Arduino WebServer parser behavior checker")
    require(checker.resolve() == PROJECT_ROOT.resolve() / WEB_SERVER_PARSER_CHECKER_RELATIVE,
            "WebServer parser behavior checker escaped the XTINCT source tree")
    checker_bytes = checker.read_bytes()
    require(len(checker_bytes) == EXPECTED_WEB_SERVER_PARSER_CHECKER_BYTES and
            sha256(checker_bytes) == EXPECTED_WEB_SERVER_PARSER_CHECKER_SHA256,
            "Bounded Arduino WebServer parser behavior checker bytes changed")
    try:
        passes = verify_bounded_webserver_parser_files(PROJECT_ROOT)
    except ParserFixtureError as error:
        raise BuildWrapperError(
            f"Bounded Arduino WebServer parser behavior gate failed: {error}"
        ) from error
    require(passes == EXPECTED_WEB_SERVER_PARSER_BEHAVIOR_PASSES,
            "Bounded Arduino WebServer parser behavior pass count changed")
    return passes


def patch_webserver_parser_source(data: bytes) -> bytes:
    patched = reviewed_webserver_parser_patch()
    digest = sha256(data)
    if digest == EXPECTED_PATCHED_WEB_SERVER_PARSER_SHA256:
        require(data == patched, "Installed patched WebServer parser differs from the reviewed patch")
        return data
    require(len(data) == EXPECTED_WEB_SERVER_PARSER_BYTES and
            digest == EXPECTED_WEB_SERVER_PARSER_SHA256,
            "Arduino WebServer parser is neither the reviewed original nor patch")
    require(data != patched, "Arduino WebServer parser transform is not unique")
    return patched


def verify_webserver_parser_source(packages_dir: Path) -> tuple[Path, bytes, int, bytes]:
    target, patch_path = webserver_parser_paths(packages_dir)
    original = target.read_bytes()
    require(len(original) == EXPECTED_WEB_SERVER_PARSER_BYTES and
            sha256(original) == EXPECTED_WEB_SERVER_PARSER_SHA256,
            "Arduino WebServer parser hash is not the reviewed pinned release")
    patched = patch_path.read_bytes()
    verify_webserver_parser_patch_bytes(patched)
    verify_webserver_parser_behavior()
    require(patch_webserver_parser_source(original) == patched and
            patch_webserver_parser_source(patched) == patched,
            "Arduino WebServer parser transform is not exact and idempotent")
    return target, original, os.lstat(target).st_mode, patched


def resolve_pioarduino_platform_dir(core_dir: Path) -> Path:
    platforms_dir = core_dir.resolve() / "platforms"
    require_plain_directory(platforms_dir, "PlatformIO platforms directory")
    matches: list[Path] = []
    for candidate in sorted(platforms_dir.glob("espressif32*"), key=lambda path: path.name.lower()):
        manifest_path = candidate / "platform.json"
        piopm_path = candidate / ".piopm"
        if not candidate.is_dir() or not manifest_path.is_file() or not piopm_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            piopm = json.loads(piopm_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        spec = piopm.get("spec") if isinstance(piopm.get("spec"), dict) else {}
        if (
            manifest.get("name") == "espressif32"
            and manifest.get("version") == EXPECTED_PLATFORM_VERSION
            and piopm.get("version") == EXPECTED_PIOPM_VERSION
            and spec.get("uri") == EXPECTED_PLATFORM_URI
        ):
            require_plain_directory(candidate, "reviewed pioarduino platform directory")
            matches.append(candidate.resolve())
    require(len(matches) == 1, f"Expected one reviewed pioarduino platform install, found {len(matches)}")
    return matches[0]


def platform_paths(core_dir: Path) -> tuple[Path, Path, Path, Path]:
    platform_dir = resolve_pioarduino_platform_dir(core_dir)
    return (
        platform_dir,
        platform_dir / "platform.json",
        platform_dir / ".piopm",
        platform_dir / "builder" / "penv_setup.py",
    )


def verify_idf_builder_bytes(data: bytes) -> None:
    require(data, "ESP-IDF PlatformIO builder is empty")
    require(
        sha256(data) == EXPECTED_IDF_BUILDER_SHA256,
        "ESP-IDF PlatformIO builder hash is not the reviewed release",
    )


def idf_builder_script_path(core_dir: Path) -> Path:
    platform_dir = resolve_pioarduino_platform_dir(core_dir)
    builder_dir = platform_dir / "builder"
    frameworks_dir = builder_dir / "frameworks"
    builder_path = frameworks_dir / "espidf.py"
    for directory, description in (
        (platform_dir, "pioarduino platform directory"),
        (builder_dir, "pioarduino builder directory"),
        (frameworks_dir, "pioarduino framework-builder directory"),
    ):
        require_plain_directory(directory, description)
    require_plain_file(builder_path, "ESP-IDF PlatformIO builder")
    require(
        builder_path.resolve() == frameworks_dir.resolve() / "espidf.py",
        "ESP-IDF PlatformIO builder escaped its exact reviewed path",
    )
    return builder_path.resolve()


def verify_idf_builder_script(core_dir: Path) -> tuple[Path, bytes]:
    builder_path = idf_builder_script_path(core_dir)
    data = builder_path.read_bytes()
    verify_idf_builder_bytes(data)
    patch_idf_builder_source(data)
    return builder_path, data


def patch_idf_builder_source(original: bytes) -> bytes:
    verify_idf_builder_bytes(original)
    require(
        original.count(IDF_BUILDER_UNSAFE_STRIP) == 2,
        "Expected exactly two destructive ESP-IDF compile-fragment strip calls",
    )
    require(
        original.count(IDF_BUILDER_UNSAFE_PROJECT_NAME) == 1,
        "Expected exactly one unsafe ESP-IDF root-project name derivation",
    )
    require(
        IDF_BUILDER_SAFE_PROJECT_NAME not in original,
        "ESP-IDF root-project fallback patch is already present",
    )
    require(
        original.count(IDF_BUILDER_LDGEN_FUNCTION_ANCHOR) == 1
        and original.count(IDF_BUILDER_UNBOUNDED_LDGEN_FRAGMENT) == 1
        and original.count(IDF_BUILDER_LDGEN_COMMAND_ANCHOR) == 1
        and original.count(IDF_BUILDER_LDGEN_FORMAT_ANCHOR) == 1,
        "Expected exact unbounded ESP-IDF ldgen command anchors",
    )
    require(
        IDF_BUILDER_BOUNDED_LDGEN_HELPER not in original
        and IDF_BUILDER_BOUNDED_LDGEN_FRAGMENT not in original
        and IDF_BUILDER_LDGEN_COMMAND_BUDGET not in original
        and IDF_BUILDER_LDGEN_WORKING_DIRECTORY not in original,
        "ESP-IDF bounded ldgen patch is already present",
    )
    patched = original.replace(IDF_BUILDER_UNSAFE_STRIP, IDF_BUILDER_SAFE_STRIP)
    patched = patched.replace(
        IDF_BUILDER_UNSAFE_PROJECT_NAME,
        IDF_BUILDER_SAFE_PROJECT_NAME,
        1,
    )
    patched = patched.replace(
        IDF_BUILDER_LDGEN_FUNCTION_ANCHOR,
        IDF_BUILDER_BOUNDED_LDGEN_HELPER + IDF_BUILDER_LDGEN_FUNCTION_ANCHOR,
        1,
    )
    patched = patched.replace(
        IDF_BUILDER_UNBOUNDED_LDGEN_FRAGMENT,
        IDF_BUILDER_BOUNDED_LDGEN_FRAGMENT,
        1,
    )
    patched = patched.replace(
        IDF_BUILDER_LDGEN_COMMAND_ANCHOR,
        IDF_BUILDER_LDGEN_COMMAND_BUDGET,
        1,
    )
    patched = patched.replace(
        IDF_BUILDER_LDGEN_FORMAT_ANCHOR,
        IDF_BUILDER_LDGEN_WORKING_DIRECTORY,
        1,
    )
    require(IDF_BUILDER_UNSAFE_STRIP not in patched, "Unsafe ESP-IDF fragment stripping survived the patch")
    require(
        IDF_BUILDER_UNSAFE_PROJECT_NAME not in patched,
        "Unsafe ESP-IDF root-project name derivation survived the patch",
    )
    require(
        patched.count(IDF_BUILDER_SAFE_APP_FRAGMENT) == 1,
        "Safe ESP-IDF application-fragment parser anchor is not unique",
    )
    require(
        patched.count(IDF_BUILDER_SAFE_COMPONENT_FRAGMENT) == 1,
        "Safe ESP-IDF component-fragment parser anchor is not unique",
    )
    require(
        patched.count(IDF_BUILDER_SAFE_PROJECT_NAME) == 1,
        "Safe ESP-IDF root-project fallback anchor is not unique",
    )
    require(
        patched.count(IDF_BUILDER_BOUNDED_LDGEN_HELPER) == 1
        and patched.count(IDF_BUILDER_BOUNDED_LDGEN_FRAGMENT) == 1
        and patched.count(IDF_BUILDER_LDGEN_COMMAND_BUDGET) == 1
        and patched.count(IDF_BUILDER_LDGEN_WORKING_DIRECTORY) == 1,
        "Bounded ESP-IDF ldgen patch output is incomplete",
    )
    require(
        sha256(patched) == EXPECTED_PATCHED_IDF_BUILDER_SHA256,
        "ESP-IDF builder compatibility patch output hash drifted",
    )
    ast.parse(patched.decode("utf-8"))
    return patched


def patch_source(original: bytes) -> bytes:
    require(original.count(PINNED_CORE_DECLARATION) == 1, "Pinned pioarduino core declaration drifted")
    require(original.count(PACKAGE_LIST_BLOCK) == 1, "Expected uv package-list block is not unique")
    require(original.count(CERTIFI_ENV_BLOCK) == 1, "Expected pioarduino certifi environment block is not unique")
    require(PACKAGE_ALIAS_BLOCK not in original, "pioarduino compatibility alias is already present")
    require(STRICT_CERTIFI_ENV_BLOCK not in original, "pioarduino strict certificate patch is already present")
    patched = original.replace(PACKAGE_LIST_BLOCK, PACKAGE_LIST_BLOCK + PACKAGE_ALIAS_BLOCK, 1)
    patched = patched.replace(CERTIFI_ENV_BLOCK, STRICT_CERTIFI_ENV_BLOCK, 1)
    require(sha256(patched) == EXPECTED_PATCHED_SHA256, "Compatibility patch output hash drifted")
    return patched


def verify_platform(core_dir: Path) -> tuple[Path, bytes, int]:
    platform_dir, manifest_path, piopm_path, target = platform_paths(core_dir)
    for required_path in (platform_dir, manifest_path, piopm_path, target):
        require(required_path.exists(), f"Required pioarduino path is missing: {required_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    piopm = json.loads(piopm_path.read_text(encoding="utf-8"))
    require(manifest.get("name") == "espressif32", "Unexpected PlatformIO platform name")
    require(manifest.get("version") == EXPECTED_PLATFORM_VERSION, "Unsupported pioarduino platform version")
    require(piopm.get("version") == EXPECTED_PIOPM_VERSION, "pioarduino package metadata version drifted")
    spec = piopm.get("spec") if isinstance(piopm.get("spec"), dict) else {}
    require(spec.get("uri") == EXPECTED_PLATFORM_URI, "pioarduino package origin drifted")

    original = target.read_bytes()
    require(sha256(original) == EXPECTED_SOURCE_SHA256, "penv_setup.py hash is not the reviewed release")
    patch_source(original)
    return target, original, target.stat().st_mode


def backup_paths(target: Path) -> tuple[Path, Path]:
    return (
        target.with_name(target.name + ".xtinct-original.bak"),
        target.with_name(target.name + ".xtinct-original.sha256"),
    )


def remove_backup_files(backup: Path, digest_file: Path) -> None:
    if backup.exists():
        backup.unlink()
    if digest_file.exists():
        digest_file.unlink()


def recover_interrupted_patch(target: Path, mode: int) -> None:
    """Recover only states that can be proven to contain the reviewed bytes."""

    backup, digest_file = backup_paths(target)
    if not backup.exists() and not digest_file.exists():
        return

    current = target.read_bytes()
    if not backup.exists():
        require(
            sha256(current) == EXPECTED_SOURCE_SHA256,
            "Hash sidecar exists without a backup and the installed source is not original",
        )
        require(
            digest_file.read_text(encoding="ascii").strip() == EXPECTED_SOURCE_SHA256,
            "Orphaned hash sidecar is invalid",
        )
        digest_file.unlink()
        return

    original = backup.read_bytes()
    require(sha256(original) == EXPECTED_SOURCE_SHA256, "Interrupted-build backup hash is invalid")
    if digest_file.exists():
        require(
            digest_file.read_text(encoding="ascii").strip() == EXPECTED_SOURCE_SHA256,
            "Interrupted-build hash sidecar is invalid",
        )
    patched = patch_source(original)

    if current == patched:
        atomic_replace_bytes(target, original, mode)
        require(target.read_bytes() == original, "Interrupted patch recovery did not restore exact bytes")
    elif current != original:
        raise BuildWrapperError("Unknown penv_setup.py state found beside an interrupted-build backup")
    remove_backup_files(backup, digest_file)
    print("Recovered and verified an interrupted XTINCT toolchain patch.")


def create_backup(target: Path, original: bytes) -> None:
    backup, digest_file = backup_paths(target)
    require(not backup.exists() and not digest_file.exists(), "Toolchain backup files already exist")
    write_exclusive(backup, original)
    write_exclusive(digest_file, (EXPECTED_SOURCE_SHA256 + "\n").encode("ascii"))
    require(backup.read_bytes() == original, "Toolchain byte backup verification failed")
    require(digest_file.read_text(encoding="ascii").strip() == EXPECTED_SOURCE_SHA256, "Backup hash write failed")


def restore_original(target: Path, expected_original: bytes, mode: int) -> None:
    backup, digest_file = backup_paths(target)
    require(backup.exists(), "Cannot restore pioarduino source: exact byte backup is missing")
    backup_bytes = backup.read_bytes()
    require(backup_bytes == expected_original, "pioarduino backup bytes changed during the build")
    require(sha256(backup_bytes) == EXPECTED_SOURCE_SHA256, "pioarduino backup hash changed during the build")
    atomic_replace_bytes(target, backup_bytes, mode)
    restored = target.read_bytes()
    require(restored == expected_original, "pioarduino source byte restoration failed")
    require(sha256(restored) == EXPECTED_SOURCE_SHA256, "pioarduino source restore hash mismatch")
    remove_backup_files(backup, digest_file)


def recover_interrupted_idf_builder_patch(target: Path, mode: int) -> None:
    """Recover only a proven original/patched ESP-IDF builder pair."""

    backup, digest_file = backup_paths(target)
    if not backup.exists() and not digest_file.exists():
        return

    current = target.read_bytes()
    if not backup.exists():
        require(
            sha256(current) == EXPECTED_IDF_BUILDER_SHA256,
            "ESP-IDF builder hash sidecar exists without a backup and installed bytes are not original",
        )
        require(
            digest_file.read_text(encoding="ascii").strip() == EXPECTED_IDF_BUILDER_SHA256,
            "Orphaned ESP-IDF builder hash sidecar is invalid",
        )
        digest_file.unlink()
        return

    original = backup.read_bytes()
    verify_idf_builder_bytes(original)
    if digest_file.exists():
        require(
            digest_file.read_text(encoding="ascii").strip() == EXPECTED_IDF_BUILDER_SHA256,
            "Interrupted ESP-IDF builder hash sidecar is invalid",
        )
    patched = patch_idf_builder_source(original)
    if current == patched:
        atomic_replace_bytes(target, original, mode)
        require(target.read_bytes() == original, "Interrupted ESP-IDF builder recovery changed original bytes")
    elif current != original:
        raise BuildWrapperError("Unknown ESP-IDF builder state found beside an interrupted-build backup")
    remove_backup_files(backup, digest_file)
    verify_idf_builder_bytes(target.read_bytes())
    print("Recovered and verified an interrupted XTINCT ESP-IDF builder patch.")


def create_idf_builder_backup(target: Path, original: bytes) -> None:
    verify_idf_builder_bytes(original)
    backup, digest_file = backup_paths(target)
    require(not backup.exists() and not digest_file.exists(), "ESP-IDF builder backup files already exist")
    write_exclusive(backup, original)
    write_exclusive(digest_file, (EXPECTED_IDF_BUILDER_SHA256 + "\n").encode("ascii"))
    require(backup.read_bytes() == original, "ESP-IDF builder byte backup verification failed")
    require(
        digest_file.read_text(encoding="ascii").strip() == EXPECTED_IDF_BUILDER_SHA256,
        "ESP-IDF builder backup hash write failed",
    )


def restore_idf_builder_original(target: Path, expected_original: bytes, mode: int) -> None:
    backup, digest_file = backup_paths(target)
    require(backup.exists(), "Cannot restore ESP-IDF builder: exact byte backup is missing")
    backup_bytes = backup.read_bytes()
    require(backup_bytes == expected_original, "ESP-IDF builder backup bytes changed")
    verify_idf_builder_bytes(backup_bytes)
    atomic_replace_bytes(target, backup_bytes, mode)
    restored = target.read_bytes()
    require(restored == expected_original, "ESP-IDF builder byte restoration failed")
    verify_idf_builder_bytes(restored)
    remove_backup_files(backup, digest_file)


def recover_interrupted_webserver_parser_patch(target: Path, mode: int) -> None:
    """Recover only the exact reviewed original/patched WebServer parser pair."""
    backup, digest_file = backup_paths(target)
    if not path_lexists(backup) and not path_lexists(digest_file):
        return
    require_plain_file(target, "Interrupted Arduino WebServer parser target")
    current = target.read_bytes()
    if not path_lexists(backup):
        require(sha256(current) == EXPECTED_WEB_SERVER_PARSER_SHA256,
                "WebServer parser sidecar exists without an original target")
        require_plain_file(digest_file, "Orphaned WebServer parser hash sidecar")
        require(digest_file.read_text(encoding="ascii").strip() ==
                EXPECTED_WEB_SERVER_PARSER_SHA256,
                "Orphaned WebServer parser hash sidecar is invalid")
        digest_file.unlink()
        return
    require_plain_file(backup, "Interrupted WebServer parser byte backup")
    original = backup.read_bytes()
    require(len(original) == EXPECTED_WEB_SERVER_PARSER_BYTES and
            sha256(original) == EXPECTED_WEB_SERVER_PARSER_SHA256,
            "Interrupted WebServer parser backup hash is invalid")
    if path_lexists(digest_file):
        require_plain_file(digest_file, "Interrupted WebServer parser hash sidecar")
        require(digest_file.read_text(encoding="ascii").strip() ==
                EXPECTED_WEB_SERVER_PARSER_SHA256,
                "Interrupted WebServer parser hash sidecar is invalid")
    patched = patch_webserver_parser_source(original)
    if current == patched:
        atomic_replace_bytes(target, original, mode)
        require(target.read_bytes() == original,
                "Interrupted WebServer parser recovery changed original bytes")
    elif current != original:
        raise BuildWrapperError(
            "Unknown WebServer parser state found beside an interrupted-build backup"
        )
    remove_backup_files(backup, digest_file)
    print("Recovered and verified an interrupted XTINCT WebServer parser patch.")


def create_webserver_parser_backup(target: Path, original: bytes) -> None:
    require(len(original) == EXPECTED_WEB_SERVER_PARSER_BYTES and
            sha256(original) == EXPECTED_WEB_SERVER_PARSER_SHA256,
            "WebServer parser backup source is not the reviewed original")
    backup, digest_file = backup_paths(target)
    require(not path_lexists(backup) and not path_lexists(digest_file),
            "WebServer parser backup files already exist")
    write_exclusive(backup, original)
    write_exclusive(
        digest_file, (EXPECTED_WEB_SERVER_PARSER_SHA256 + "\n").encode("ascii")
    )
    require(backup.read_bytes() == original,
            "WebServer parser byte backup verification failed")
    require(digest_file.read_text(encoding="ascii").strip() ==
            EXPECTED_WEB_SERVER_PARSER_SHA256,
            "WebServer parser backup hash write failed")


def restore_webserver_parser_original(target: Path, expected_original: bytes,
                                      mode: int) -> None:
    backup, digest_file = backup_paths(target)
    if not path_lexists(backup) and not path_lexists(digest_file):
        # A pioarduino custom-sdkconfig rebuild reinstalls the complete Arduino
        # framework directory while PlatformIO is running. That legitimately
        # removes our sibling backup together with the transient patch and
        # restores the vendor parser. Accept only the exact pinned original;
        # any other missing-backup state remains fail closed.
        require_plain_file(target, "reinstalled WebServer parser")
        restored = target.read_bytes()
        require(restored == expected_original and
                len(restored) == EXPECTED_WEB_SERVER_PARSER_BYTES and
                sha256(restored) == EXPECTED_WEB_SERVER_PARSER_SHA256,
                "WebServer parser backup vanished without exact vendor restoration")
        return
    require_plain_file(backup, "WebServer parser restoration backup")
    backup_bytes = backup.read_bytes()
    require(backup_bytes == expected_original and
            len(backup_bytes) == EXPECTED_WEB_SERVER_PARSER_BYTES and
            sha256(backup_bytes) == EXPECTED_WEB_SERVER_PARSER_SHA256,
            "WebServer parser restoration backup changed")
    atomic_replace_bytes(target, backup_bytes, mode)
    restored = target.read_bytes()
    require(restored == expected_original and
            sha256(restored) == EXPECTED_WEB_SERVER_PARSER_SHA256,
            "WebServer parser byte restoration failed")
    remove_backup_files(backup, digest_file)


def restore_toolchain_patches(
    penv_target: Path,
    penv_original: bytes,
    penv_mode: int,
    penv_backup_created: bool,
    idf_builder_target: Path,
    idf_builder_original: bytes,
    idf_builder_mode: int,
    idf_builder_backup_created: bool,
    webserver_parser_target: Path,
    webserver_parser_original: bytes,
    webserver_parser_mode: int,
    webserver_parser_backup_created: bool,
) -> None:
    """Attempt every independent restore before reporting any failure."""

    restore_errors: list[tuple[str, BaseException]] = []
    if webserver_parser_backup_created:
        try:
            restore_webserver_parser_original(
                webserver_parser_target, webserver_parser_original, webserver_parser_mode
            )
        except BaseException as error:
            restore_errors.append((WEB_SERVER_PARSER_RELATIVE.as_posix(), error))
    if idf_builder_backup_created:
        try:
            restore_idf_builder_original(idf_builder_target, idf_builder_original, idf_builder_mode)
        except BaseException as error:
            restore_errors.append(("builder/frameworks/espidf.py", error))
    if penv_backup_created:
        try:
            restore_original(penv_target, penv_original, penv_mode)
        except BaseException as error:
            restore_errors.append(("builder/penv_setup.py", error))
    if restore_errors:
        details = "; ".join(f"{name}: {error}" for name, error in restore_errors)
        raise BuildWrapperError(f"Toolchain restoration failed after all restore attempts: {details}") from restore_errors[0][1]


def make_strict_ca_bundle(directory: Path) -> Path:
    try:
        import certifi
    except ImportError as error:
        raise BuildWrapperError("Python 3.11 certifi is required to build the strict CA bundle") from error

    require(hasattr(ssl, "enum_certificates"), "Windows certificate-store access is unavailable")
    certifi_bytes = Path(certifi.where()).read_bytes()
    require(b"-----BEGIN CERTIFICATE-----" in certifi_bytes, "certifi CA bundle is invalid")

    pem_blocks: list[bytes] = []
    seen: set[str] = set()
    for certificate, encoding, _trust in ssl.enum_certificates("ROOT"):
        if encoding != "x509_asn":
            continue
        digest = sha256(certificate)
        if digest in seen:
            continue
        seen.add(digest)
        body = base64.b64encode(certificate)
        lines = [body[index : index + 64] for index in range(0, len(body), 64)]
        pem_blocks.append(b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(lines) + b"\n-----END CERTIFICATE-----\n")
    require(pem_blocks, "No X.509 roots were exported from the Windows ROOT store")

    bundle = directory / "combined-ca.pem"
    payload = certifi_bytes.rstrip() + b"\n" + b"".join(pem_blocks)
    write_exclusive(bundle, payload)
    require(bundle.stat().st_size > len(certifi_bytes), "Combined strict CA bundle is incomplete")
    return bundle


def strict_subprocess_env(
    core_dir: Path, ca_bundle: Path, core_alias: Path | None = None
) -> dict[str, str]:
    inherited = os.environ
    pinned_packages_dir = ready27_packages_dir(core_dir)
    forbidden = {
        "GIT_SSL_NO_VERIFY": lambda value: value.lower() not in ("", "0", "false", "no"),
        "PIP_TRUSTED_HOST": lambda value: bool(value.strip()),
        "UV_INSECURE_HOST": lambda value: bool(value.strip()),
        "PYTHONHTTPSVERIFY": lambda value: value.strip() == "0",
        "NODE_TLS_REJECT_UNAUTHORIZED": lambda value: value.strip() == "0",
        "GIT_CONFIG_PARAMETERS": lambda value: bool(value.strip()),
        "UV_CERT": lambda value: bool(value.strip()),
        "UV_INDEX": lambda value: bool(value.strip()),
        "UV_INDEX_URL": lambda value: bool(value.strip()),
        "UV_DEFAULT_INDEX": lambda value: bool(value.strip()),
        "UV_EXTRA_INDEX_URL": lambda value: bool(value.strip()),
        "UV_FIND_LINKS": lambda value: bool(value.strip()),
        "UV_CONSTRAINT": lambda value: bool(value.strip()),
        "UV_OVERRIDE": lambda value: bool(value.strip()),
        "UV_CONFIG_FILE": lambda value: bool(value.strip()),
        "UV_NO_INDEX": lambda value: value.lower() not in ("", "0", "false", "no"),
        "PIP_INDEX_URL": lambda value: bool(value.strip()),
        "PIP_EXTRA_INDEX_URL": lambda value: bool(value.strip()),
    }
    for name, is_insecure in forbidden.items():
        value = inherited.get(name, "")
        require(not is_insecure(value), f"Refusing insecure inherited environment variable: {name}")

    platformio_overrides = (
        "PLATFORMIO_DEFAULT_ENVS",
        "PLATFORMIO_GLOBALLIB_DIR",
        "PLATFORMIO_PLATFORMS_DIR",
        "PLATFORMIO_PACKAGES_DIR",
        "PLATFORMIO_CACHE_DIR",
        "PLATFORMIO_BUILD_CACHE_DIR",
        "PLATFORMIO_WORKSPACE_DIR",
        "PLATFORMIO_BUILD_DIR",
        "PLATFORMIO_LIBDEPS_DIR",
        "PLATFORMIO_INCLUDE_DIR",
        "PLATFORMIO_SRC_DIR",
        "PLATFORMIO_LIB_DIR",
        "PLATFORMIO_DATA_DIR",
        "PLATFORMIO_TEST_DIR",
        "PLATFORMIO_BOARDS_DIR",
        "PLATFORMIO_MONITOR_DIR",
        "PLATFORMIO_SHARED_DIR",
        "PLATFORMIO_BUILD_FLAGS",
        "PLATFORMIO_BUILD_SRC_FLAGS",
        "PLATFORMIO_BUILD_UNFLAGS",
        "PLATFORMIO_BUILD_SRC_FILTER",
        "PLATFORMIO_UPLOAD_PORT",
        "PLATFORMIO_UPLOAD_FLAGS",
        "PLATFORMIO_LIB_EXTRA_DIRS",
        "PLATFORMIO_EXTRA_SCRIPTS",
        "PLATFORMIO_PROJECT_DIR",
        "PLATFORMIO_PROJECT_CONF",
        "PLATFORMIO_RUN_JOBS",
    )
    for name in platformio_overrides:
        require(not inherited.get(name, "").strip(), f"Refusing inherited PlatformIO override: {name}")

    env = dict(inherited)
    for name in list(env):
        if name.startswith("GIT_CONFIG_KEY_") or name.startswith("GIT_CONFIG_VALUE_"):
            env.pop(name)
    env.pop("GIT_SSL_NO_VERIFY", None)
    env.pop("GIT_SSL_CAINFO", None)
    env.pop("SSL_CERT_FILE", None)
    env.pop("SSL_CERT_DIR", None)
    env.pop("GIT_CONFIG_PARAMETERS", None)
    env.pop("GIT_CONFIG_SYSTEM", None)
    env.pop("GIT_CONFIG_GLOBAL", None)
    env.pop("PYTHONHOME", None)
    env.pop("PYTHONPATH", None)
    env.pop("VIRTUAL_ENV", None)
    for name in (
        "ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
        "all_proxy", "http_proxy", "https_proxy", "no_proxy",
    ):
        env.pop(name, None)
    for name in (
        "XTINCT_PINNED_PACKAGES_DIR",
        "XTINCT_PRIVATE_BUILD_ROOT",
        "XTINCT_REPRO_BUILD_CACHE_ROOT",
        "XTINCT_REPRO_BUILD_ALIAS",
        "XTINCT_REPRO_PACKAGES_ALIAS",
        "XTINCT_REPRO_CORE_ALIAS",
        "XTINCT_REPRO_PROJECT_ROOT",
        "XTINCT_REPRO_CORE_ROOT",
        "XTINCT_REPRO_USER_ROOT",
        "SOURCE_DATE_EPOCH",
        "TZ",
    ):
        env.pop(name, None)
    if pinned_packages_dir is not None:
        env["PLATFORMIO_PACKAGES_DIR"] = str(pinned_packages_dir)
        env["XTINCT_PINNED_PACKAGES_DIR"] = str(pinned_packages_dir)
    private_platforms = core_dir / "platforms"
    private_libdeps = core_dir / "libdeps"
    private_global_lib = core_dir / "lib"
    private_cache = core_dir / ".cache"
    for path, label in (
        (private_platforms, "READY27 private platforms"),
        (private_libdeps, "READY27 private dependency seed"),
        (private_global_lib, "READY27 private global-library directory"),
        (private_cache, "READY27 private cache directory"),
    ):
        require_plain_directory(path, label)
    short_core = (core_alias if core_alias is not None else
                  windows_short_directory(core_dir, "READY27 private core"))
    require(short_core.is_dir() and not short_core.is_symlink() and
            os.path.samefile(short_core, core_dir) and
            not any(character.isspace() for character in str(short_core)),
            "READY27 private core alias changed identity")
    short_packages = short_core / "packages"
    short_platforms = short_core / "platforms"
    short_libdeps = short_core / "libdeps"
    short_global_lib = short_core / "lib"
    short_cache = short_core / ".cache"
    for short_path, physical_path, label in (
        (short_packages, pinned_packages_dir, "READY27 short package root"),
        (short_platforms, private_platforms, "READY27 short platform root"),
        (short_libdeps, private_libdeps, "READY27 short dependency root"),
        (short_global_lib, private_global_lib, "READY27 short global-library root"),
        (short_cache, private_cache, "READY27 short cache root"),
    ):
        require(short_path.is_dir() and not short_path.is_symlink() and
                physical_path is not None and os.path.samefile(short_path, physical_path),
                f"{label} changed identity")
    if pinned_packages_dir is not None:
        env["PLATFORMIO_PACKAGES_DIR"] = str(short_packages)
        env["XTINCT_PINNED_PACKAGES_DIR"] = str(short_packages)
    env.update(
        {
            "ALL_PROXY": "http://127.0.0.1:9",
            "HTTP_PROXY": "http://127.0.0.1:9",
            "HTTPS_PROXY": "http://127.0.0.1:9",
            "NO_PROXY": "",
            "all_proxy": "http://127.0.0.1:9",
            "http_proxy": "http://127.0.0.1:9",
            "https_proxy": "http://127.0.0.1:9",
            "no_proxy": "",
            "PIP_NO_INDEX": "1",
            # The X3 build uses only the fully pinned ESP-IDF/Arduino package
            # trees in this private core.  Do not let the ESP-IDF component
            # manager consult its mutable user cache or the remote registry.
            "IDF_COMPONENT_MANAGER": "0",
            "PLATFORMIO_CACHE_DIR": str(short_cache),
            "PLATFORMIO_CORE_DIR": str(short_core),
            "PLATFORMIO_GLOBALLIB_DIR": str(short_global_lib),
            "PLATFORMIO_LIBDEPS_DIR": str(short_libdeps),
            "PLATFORMIO_PLATFORMS_DIR": str(short_platforms),
            # pioarduino's custom-sdkconfig post-action launches a nested
            # `pio run` without forwarding the outer CLI's `-j` option.  The
            # nested PlatformIO CLI reads this environment variable before it
            # constructs SCons, so pin it to the same host-safety cap.
            "PLATFORMIO_RUN_JOBS": str(MAX_PLATFORMIO_JOBS),
            "PLATFORMIO_SETTING_ENABLE_TELEMETRY": "no",
            "REQUESTS_CA_BUNDLE": str(ca_bundle),
            "PIP_CERT": str(ca_bundle),
            "CURL_CA_BUNDLE": str(ca_bundle),
            "UV_SYSTEM_CERTS": "true",
            "UV_NO_CONFIG": "1",
            "UV_NO_INDEX": "1",
            "UV_CACHE_DIR": str(short_cache / "uv"),
            "XTINCT_STRICT_CA_BUNDLE": str(ca_bundle),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONUTF8": "1",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "NUL",
            "GIT_CONFIG_COUNT": "4",
            "GIT_CONFIG_KEY_0": "http.sslBackend",
            "GIT_CONFIG_VALUE_0": "schannel",
            "GIT_CONFIG_KEY_1": "http.sslVerify",
            "GIT_CONFIG_VALUE_1": "true",
            "GIT_CONFIG_KEY_2": "http.schannelUseSSLCAInfo",
            "GIT_CONFIG_VALUE_2": "false",
            "GIT_CONFIG_KEY_3": "http.https://github.com/.sslVerify",
            "GIT_CONFIG_VALUE_3": "true",
            "GIT_TERMINAL_PROMPT": "0",
            "SOURCE_DATE_EPOCH": REPRODUCIBLE_SOURCE_DATE_EPOCH,
            "TZ": REPRODUCIBLE_TIMEZONE,
            "XTINCT_REPRO_PROJECT_ROOT": str(PROJECT_ROOT.resolve()),
            "XTINCT_REPRO_CORE_ROOT": str(core_dir.resolve()),
            "XTINCT_REPRO_PACKAGES_ALIAS": str(short_packages),
            "XTINCT_REPRO_CORE_ALIAS": str(short_core),
            "XTINCT_REPRO_USER_ROOT": str(Path.home().resolve()),
        }
    )
    return env


def penv_paths(core_dir: Path) -> tuple[Path, Path, Path, Path]:
    penv = core_dir / "penv"
    scripts = penv / "Scripts"
    site_packages = penv / "Lib" / "site-packages"
    return penv, scripts / "python.exe", scripts / "uv.exe", site_packages


def verify_penv_distribution(core_dir: Path) -> tuple[Path, Path]:
    _penv, python_exe, uv_exe, site_packages = penv_paths(core_dir)
    require(python_exe.is_file(), f"pioarduino penv Python is missing: {python_exe}")
    require(uv_exe.is_file(), f"pioarduino penv uv is missing: {uv_exe}")
    dist_infos = list(site_packages.glob("pioarduino_core-*.dist-info"))
    require(len(dist_infos) == 1, "Expected exactly one pioarduino-core distribution in the penv")
    dist_info = dist_infos[0]
    metadata = (dist_info / "METADATA").read_text(encoding="utf-8")
    require(re.search(r"(?m)^Name: pioarduino-core$", metadata) is not None, "Unexpected penv distribution name")
    require(
        re.search(r"(?m)^Version: 6\.1\.19$", metadata) is not None,
        "Unexpected pioarduino-core distribution version",
    )
    direct_url = json.loads((dist_info / "direct_url.json").read_text(encoding="utf-8"))
    require(direct_url.get("url") == EXPECTED_PENV_URL, "pioarduino-core direct URL drifted")
    return python_exe, uv_exe


def list_uv_packages(uv_exe: Path, python_exe: Path, env: dict[str, str]) -> dict[str, str]:
    result = subprocess.run(
        [str(uv_exe), "pip", "list", f"--python={python_exe}", "--format=json"],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, end="", file=sys.stderr)
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        raise BuildWrapperError(f"uv package verification exited {result.returncode}")
    packages = json.loads(result.stdout)
    return {str(item["name"]).lower(): str(item["version"]) for item in packages}


def ensure_strict_penv(core_dir: Path, env: dict[str, str], install: bool) -> None:
    python_exe, uv_exe = verify_penv_distribution(core_dir)
    if install:
        result = subprocess.run(
            [str(uv_exe), "pip", "install", f"--python={python_exe}", "--quiet", "--upgrade", "urllib3<2"],
            cwd=PROJECT_ROOT,
            env=env,
            check=False,
        )
        require(result.returncode == 0, f"Strict urllib3<2 penv preparation exited {result.returncode}")
    packages = list_uv_packages(uv_exe, python_exe, env)
    require("platformio" not in packages, "Unexpected platformio distribution is installed in the pioarduino penv")
    require(packages.get(EXPECTED_PENV_NAME) == EXPECTED_PLATFORMIO_VERSION, "pioarduino-core is missing or wrong")
    urllib3_version = packages.get("urllib3", "")
    require(re.fullmatch(r"\d+(?:\.\d+)+", urllib3_version) is not None, "Cannot parse penv urllib3 version")
    require(int(urllib3_version.split(".", 1)[0]) < 2, "pioarduino penv requires urllib3<2")


def idf_paths(core_dir: Path) -> tuple[Path, Path, Path, Path, Path, Path]:
    framework_dir = core_dir / "packages" / "framework-espidf"
    idf_venv = core_dir / "penv" / f".espidf-{EXPECTED_IDF_VERSION}"
    return (
        framework_dir,
        framework_dir / "tools",
        idf_venv,
        idf_venv / "Scripts" / "python.exe",
        idf_venv / "Lib" / "site-packages",
        idf_venv / "pio-idf-venv.json",
    )


def verify_idf_framework_and_venv(
    core_dir: Path, env: dict[str, str]
) -> tuple[Path, Path, Path, Path]:
    framework_dir, framework_tools, idf_venv, python_exe, site_packages, marker_path = idf_paths(core_dir)
    core_dir = core_dir.resolve()
    expected_venv_parent = (core_dir / "penv").resolve()

    for directory, description in (
        (core_dir, "PlatformIO core directory"),
        (core_dir / "packages", "PlatformIO packages directory"),
        (framework_dir, "Pinned ESP-IDF framework directory"),
        (framework_tools, "Pinned ESP-IDF tools directory"),
        (core_dir / "penv", "PlatformIO penv directory"),
        (idf_venv, "Pinned ESP-IDF virtual environment"),
        (idf_venv / "Scripts", "Pinned ESP-IDF Scripts directory"),
        (idf_venv / "Lib", "Pinned ESP-IDF Lib directory"),
        (site_packages, "Pinned ESP-IDF site-packages directory"),
    ):
        require_plain_directory(directory, description)

    require(idf_venv.name == f".espidf-{EXPECTED_IDF_VERSION}", "ESP-IDF venv name drifted")
    require(idf_venv.resolve().parent == expected_venv_parent, "ESP-IDF venv escaped the PlatformIO penv")
    require(
        idf_venv.resolve() == (expected_venv_parent / f".espidf-{EXPECTED_IDF_VERSION}"),
        "ESP-IDF venv does not resolve to the exact pinned path",
    )
    require_tree_without_reparse_points(idf_venv, "Pinned ESP-IDF virtual environment")

    framework_manifest_path = framework_dir / "package.json"
    framework_piopm_path = framework_dir / ".piopm"
    framework_version_path = framework_dir / "version.txt"
    pyvenv_path = idf_venv / "pyvenv.cfg"
    for path, description in (
        (framework_manifest_path, "ESP-IDF package manifest"),
        (framework_piopm_path, "ESP-IDF PlatformIO metadata"),
        (framework_version_path, "ESP-IDF release marker"),
        (marker_path, "ESP-IDF venv marker"),
        (pyvenv_path, "ESP-IDF pyvenv configuration"),
        (python_exe, "ESP-IDF venv Python"),
    ):
        require_plain_file(path, description)

    framework_manifest = json.loads(framework_manifest_path.read_text(encoding="utf-8"))
    require(framework_manifest.get("name") == "framework-espidf", "Unexpected ESP-IDF package name")
    require(
        framework_manifest.get("version") == EXPECTED_IDF_PACKAGE_VERSION,
        "ESP-IDF package manifest version drifted",
    )
    framework_piopm = json.loads(framework_piopm_path.read_text(encoding="utf-8"))
    require(framework_piopm.get("name") == "framework-espidf", "Unexpected ESP-IDF .piopm name")
    require(framework_piopm.get("version") == EXPECTED_IDF_PIOPM_VERSION, "ESP-IDF .piopm version drifted")
    framework_spec = framework_piopm.get("spec")
    require(isinstance(framework_spec, dict), "ESP-IDF .piopm release spec is invalid")
    require(
        framework_spec.get("uri") == EXPECTED_IDF_PIOPM_URL,
        "ESP-IDF .piopm release URL drifted",
    )
    require(
        framework_version_path.read_text(encoding="utf-8").strip() == EXPECTED_IDF_RELEASE,
        "ESP-IDF framework release drifted",
    )

    marker = json.loads(marker_path.read_text(encoding="utf-8"))
    require(
        marker
        == {
            "version": EXPECTED_IDF_ENV_VERSION,
            "python_version": EXPECTED_IDF_PYTHON_VERSION,
        },
        "ESP-IDF venv marker drifted",
    )
    pyvenv_values: dict[str, str] = {}
    for line in pyvenv_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        pyvenv_values[key.strip()] = value.strip()
    require(pyvenv_values.get("implementation") == "CPython", "ESP-IDF venv implementation drifted")
    require(pyvenv_values.get("uv") == EXPECTED_UV_VERSION, "ESP-IDF venv creator version drifted")
    require(pyvenv_values.get("version_info") == "3.11.0", "ESP-IDF venv Python version marker drifted")
    require(
        pyvenv_values.get("include-system-site-packages", "").lower() == "false",
        "ESP-IDF venv must remain isolated from system site-packages",
    )

    identity_probe = subprocess.run(
        [
            str(python_exe),
            "-c",
            (
                "import json,site,sys; print(json.dumps({"
                "'version':list(sys.version_info[:3]),'prefix':sys.prefix,"
                "'base_prefix':sys.base_prefix,'executable':sys.executable,"
                "'enable_user_site':site.ENABLE_USER_SITE}))"
            ),
        ],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if identity_probe.returncode != 0:
        if identity_probe.stdout:
            print(identity_probe.stdout, end="", file=sys.stderr)
        if identity_probe.stderr:
            print(identity_probe.stderr, end="", file=sys.stderr)
    require(identity_probe.returncode == 0, "ESP-IDF venv Python identity probe failed")
    identity = json.loads(identity_probe.stdout)
    require(identity.get("version") == [3, 11, 0], "ESP-IDF venv Python runtime drifted")
    require(identity.get("enable_user_site") is False, "ESP-IDF venv unexpectedly enables user site-packages")
    require(Path(identity.get("prefix", "")).resolve() == idf_venv.resolve(), "ESP-IDF Python prefix drifted")
    require(
        Path(identity.get("executable", "")).resolve() == python_exe.resolve(),
        "ESP-IDF Python executable drifted",
    )
    require(
        Path(identity.get("base_prefix", "")).resolve() != idf_venv.resolve(),
        "ESP-IDF Python base prefix incorrectly points inside the venv",
    )
    return framework_dir.resolve(), framework_tools.resolve(), idf_venv.resolve(), python_exe.resolve()


def release_tuple(version: str, description: str) -> tuple[int, ...]:
    require(re.fullmatch(r"\d+(?:\.\d+)*", version) is not None, f"Cannot parse {description} version: {version}")
    return tuple(int(part) for part in version.split("."))


def padded_release(version: str, description: str) -> tuple[int, int, int]:
    parts = release_tuple(version, description)
    require(len(parts) <= 3, f"Unexpected {description} release width: {version}")
    return (parts + (0, 0, 0))[:3]


def verify_idf_python_packages(
    core_dir: Path, env: dict[str, str], framework_tools: Path, idf_venv: Path, python_exe: Path
) -> None:
    _outer_python, uv_exe = verify_penv_distribution(core_dir)
    packages = list_uv_packages(uv_exe, python_exe, env)
    expected_names = (
        "urllib3",
        "cryptography",
        "pyparsing",
        "idf-component-manager",
        "esp-idf-kconfig",
        "windows-curses",
    )
    for name in expected_names:
        require(name in packages, f"ESP-IDF venv distribution is missing: {name}")

    urllib3_version = padded_release(packages["urllib3"], "ESP-IDF urllib3")
    cryptography_version = padded_release(packages["cryptography"], "ESP-IDF cryptography")
    pyparsing_version = padded_release(packages["pyparsing"], "ESP-IDF pyparsing")
    component_manager_version = padded_release(
        packages["idf-component-manager"], "ESP-IDF component manager"
    )
    kconfig_version = padded_release(packages["esp-idf-kconfig"], "ESP-IDF kconfig")
    padded_release(packages["windows-curses"], "ESP-IDF windows-curses")
    require(urllib3_version < (2, 0, 0), "ESP-IDF venv requires urllib3<2")
    require(
        (44, 0, 0) <= cryptography_version < (44, 1, 0),
        "ESP-IDF venv requires cryptography~=44.0.0",
    )
    require((3, 1, 0) <= pyparsing_version < (4, 0, 0), "ESP-IDF venv requires pyparsing>=3.1,<4")
    require(
        (2, 4, 6) <= component_manager_version < (2, 5, 0),
        "ESP-IDF venv requires idf-component-manager~=2.4.6",
    )
    require(
        (2, 5, 0) <= kconfig_version < (2, 6, 0),
        "ESP-IDF venv requires esp-idf-kconfig~=2.5.0",
    )

    probe_code = r'''import importlib.metadata
import importlib.util
import json
import pathlib
import sys

framework_tools = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(framework_tools))
import _curses
import cryptography
import curses
import idf_component_manager.prepare_components
import idf_py_actions.constants
import kconfiglib
import pyparsing
import urllib3

idf_tools_spec = importlib.util.find_spec("idf_py_actions.tools")
assert idf_tools_spec is not None and idf_tools_spec.origin

modules = {
    "_curses": _curses,
    "cryptography": cryptography,
    "curses": curses,
    "idf_component_manager.prepare_components": idf_component_manager.prepare_components,
    "idf_py_actions.constants": idf_py_actions.constants,
    "kconfiglib": kconfiglib,
    "pyparsing": pyparsing,
    "urllib3": urllib3,
}
distributions = [
    "urllib3",
    "cryptography",
    "pyparsing",
    "idf-component-manager",
    "esp-idf-kconfig",
    "windows-curses",
]
print(json.dumps({
    "modules": {name: str(pathlib.Path(module.__file__).resolve()) for name, module in modules.items()},
    "idf_tools_source": str(pathlib.Path(idf_tools_spec.origin).resolve()),
    "base_prefix": str(pathlib.Path(sys.base_prefix).resolve()),
    "distributions": {name: importlib.metadata.version(name) for name in distributions},
}))
'''
    probe = subprocess.run(
        [str(python_exe), "-c", probe_code, str(framework_tools)],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        if probe.stdout:
            print(probe.stdout, end="", file=sys.stderr)
        if probe.stderr:
            print(probe.stderr, end="", file=sys.stderr)
    require(probe.returncode == 0, "ESP-IDF venv import probe failed")
    probe_data = json.loads(probe.stdout)
    require(probe_data.get("distributions") == {name: packages[name] for name in expected_names},
            "ESP-IDF import probe distribution versions changed")
    site_packages = (idf_venv / "Lib" / "site-packages").resolve()
    module_paths = probe_data.get("modules", {})
    for name in (
        "_curses",
        "cryptography",
        "idf_component_manager.prepare_components",
        "kconfiglib",
        "pyparsing",
        "urllib3",
    ):
        module_path = Path(module_paths.get(name, "")).resolve()
        require(module_path.is_relative_to(site_packages), f"ESP-IDF module escaped its venv: {name}")
    idf_actions_path = Path(module_paths.get("idf_py_actions.constants", "")).resolve()
    require(idf_actions_path.is_relative_to(framework_tools), "idf_py_actions did not load from pinned ESP-IDF")
    idf_tools_source = Path(probe_data.get("idf_tools_source", "")).resolve()
    require(idf_tools_source.is_relative_to(framework_tools), "idf_py_actions.tools escaped pinned ESP-IDF")
    curses_path = Path(module_paths.get("curses", "")).resolve()
    base_library = Path(probe_data.get("base_prefix", "")).resolve() / "Lib"
    require(curses_path.is_relative_to(base_library), "Python curses module escaped the pinned base runtime")


def verify_or_repair_idf_venv(core_dir: Path, env: dict[str, str], install: bool) -> None:
    verify_idf_builder_script(core_dir)
    framework_dir, framework_tools, idf_venv, python_exe = verify_idf_framework_and_venv(core_dir, env)
    _outer_python, uv_exe = verify_penv_distribution(core_dir)
    original_venv_stat = os.lstat(idf_venv)
    original_venv_identity = (original_venv_stat.st_dev, original_venv_stat.st_ino)
    if install:
        command = [
            str(uv_exe),
            "pip",
            "install",
            f"--python={python_exe}",
            "--no-config",
            "--default-index=https://pypi.org/simple",
            "urllib3<2",
            "cryptography~=44.0.0",
            "pyparsing>=3.1.0,<4",
            "idf-component-manager~=2.4.6",
            "esp-idf-kconfig~=2.5.0",
            "windows-curses",
        ]
        print("Repairing/verifying pinned ESP-IDF venv with:", subprocess.list2cmdline(command))
        result = subprocess.run(
            command,
            cwd=PROJECT_ROOT,
            env=env,
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=False,
            timeout=300,
        )
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr if result.returncode else sys.stdout)
        require(result.returncode == 0, f"ESP-IDF venv repair exited {result.returncode}")

    require_plain_directory(idf_venv, "Pinned ESP-IDF virtual environment after repair")
    repaired_venv_stat = os.lstat(idf_venv)
    require(
        (repaired_venv_stat.st_dev, repaired_venv_stat.st_ino) == original_venv_identity,
        "ESP-IDF venv was replaced during repair",
    )
    require_tree_without_reparse_points(idf_venv, "Repaired ESP-IDF virtual environment")
    verified_framework, verified_tools, verified_venv, verified_python = verify_idf_framework_and_venv(core_dir, env)
    require(verified_framework == framework_dir, "ESP-IDF framework path changed during repair")
    require(verified_tools == framework_tools, "ESP-IDF tools path changed during repair")
    require(verified_venv == idf_venv, "ESP-IDF venv path changed during repair")
    require(verified_python == python_exe, "ESP-IDF Python path changed during repair")
    verify_idf_python_packages(core_dir, env, framework_tools, idf_venv, python_exe)
    print("Verified pinned ESP-IDF 5.5.2 Python environment:", idf_venv)


def verify_patched_certifi_environment(
    core_dir: Path, patched_source: bytes, env: dict[str, str]
) -> None:
    private_python, _private_uv = verify_penv_distribution(core_dir)
    private_python = private_python.resolve()
    require_plain_file(private_python, "Pinned pioarduino penv Python for certifi probe")
    source_text = patched_source.decode("utf-8")
    syntax_tree = ast.parse(source_text)
    function = next(
        (node for node in syntax_tree.body if isinstance(node, ast.FunctionDef) and node.name == "_setup_certifi_env"),
        None,
    )
    require(function is not None, "Patched _setup_certifi_env function is missing")
    function_source = ast.unparse(function)
    probe_code = f'''import os
import subprocess
import sys

{function_source}

class FakeSConsEnv(dict):
    def Replace(self, **values):
        self.update(values)

expected = os.environ.get("XTINCT_STRICT_CA_BUNDLE", "")
scons = FakeSConsEnv(ENV=dict(os.environ))
_setup_certifi_env(scons, sys.executable)
assert "SSL_CERT_FILE" not in os.environ
assert "SSL_CERT_FILE" not in scons["ENV"]
assert "GIT_SSL_CAINFO" not in os.environ
assert "GIT_SSL_CAINFO" not in scons["ENV"]
for variable in ("REQUESTS_CA_BUNDLE", "PIP_CERT", "CURL_CA_BUNDLE"):
    assert os.environ[variable] == expected
    assert scons["ENV"][variable] == expected
assert os.environ["UV_SYSTEM_CERTS"] == "true"
assert scons["ENV"]["UV_SYSTEM_CERTS"] == "true"
print("PATCHED_CERTIFI_ENV_OK")
'''
    result = subprocess.run(
        [str(private_python), "-c", probe_code],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        if result.stdout:
            print(result.stdout, end="", file=sys.stderr)
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
    require(result.returncode == 0, "Patched pioarduino certifi environment probe failed")
    require(
        result.stdout.strip() == "PATCHED_CERTIFI_ENV_OK",
        f"Patched certifi probe returned unexpected output: {result.stdout!r}",
    )

    missing_marker_env = dict(env)
    missing_marker_env.pop("XTINCT_STRICT_CA_BUNDLE", None)
    rejected = subprocess.run(
        [str(private_python), "-c", probe_code],
        cwd=PROJECT_ROOT,
        env=missing_marker_env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    require(rejected.returncode != 0, "Patched certifi environment accepted a missing wrapper CA marker")


def verify_idf_builder_fragment_parsing(
    core_dir: Path, env: dict[str, str], patched_source: bytes
) -> None:
    """Prove the reviewed parser patch preserves CMake's protective quotes."""

    builder_path = idf_builder_script_path(core_dir)
    original = builder_path.read_bytes()
    verify_idf_builder_bytes(original)
    expected_patch = patch_idf_builder_source(original)
    require(patched_source == expected_patch, "ESP-IDF builder parser probe received unexpected patch bytes")
    require(
        sha256(patched_source) == EXPECTED_PATCHED_IDF_BUILDER_SHA256,
        "ESP-IDF builder parser probe patch hash drifted",
    )

    packages_dir = core_dir.resolve() / "packages"
    tool_scons_dir = packages_dir / "tool-scons"
    scons_local_dir = tool_scons_dir / "scons-local-4.8.1"
    for directory, description in (
        (packages_dir, "PlatformIO packages directory for SCons probe"),
        (tool_scons_dir, "Pinned PlatformIO SCons package"),
        (scons_local_dir, "Pinned SCons 4.8.1 local package"),
    ):
        require_plain_directory(directory, description)
    require(
        scons_local_dir.resolve() == tool_scons_dir.resolve() / "scons-local-4.8.1",
        "Pinned SCons local package escaped its exact path",
    )

    manifest_path = tool_scons_dir / "package.json"
    piopm_path = tool_scons_dir / ".piopm"
    require_plain_file(manifest_path, "Pinned SCons package manifest")
    require_plain_file(piopm_path, "Pinned SCons package metadata")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    piopm = json.loads(piopm_path.read_text(encoding="utf-8"))
    for metadata, description in ((manifest, "manifest"), (piopm, ".piopm")):
        require(metadata.get("name") == "tool-scons", f"Pinned SCons {description} name drifted")
        require(
            metadata.get("version") == EXPECTED_SCONS_PACKAGE_VERSION,
            f"Pinned SCons {description} version drifted",
        )

    private_python, _private_uv = verify_penv_distribution(core_dir)
    private_python = private_python.resolve()
    require_plain_file(private_python, "Pinned pioarduino penv Python for SCons probe")
    probe_code = r'''
import sys

scons_path = sys.argv[1]
sys.path.insert(0, scons_path)

import SCons
from SCons.Script import Environment
from click.parser import split_arg_string

assert SCons.__version__ == "4.8.1"
samples = (
    '"-includeC:/xtinct fixture path/source/managed_components/header.h"',
    '"-fmacro-prefix-map=C:/xtinct fixture path/source=."',
)
for raw in samples:
    expected = raw[1:-1]
    safe = raw.strip()
    unsafe = raw.strip('" ')

    safe_scons = Environment(tools=[]).ParseFlags(safe)
    assert safe_scons.get("CCFLAGS") == [expected], safe_scons
    assert safe_scons.get("LIBS") == [], safe_scons
    assert split_arg_string(safe) == [expected]

    unsafe_scons = Environment(tools=[]).ParseFlags(unsafe)
    assert unsafe_scons.get("CCFLAGS") != [expected], unsafe_scons
    assert unsafe_scons.get("LIBS"), unsafe_scons
    assert split_arg_string(unsafe) != [expected]

print("IDF_BUILDER_FRAGMENT_PARSING_OK")
'''
    probe = subprocess.run(
        [str(private_python), "-c", probe_code, str(scons_local_dir)],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    if probe.returncode != 0:
        if probe.stdout:
            print(probe.stdout, end="", file=sys.stderr)
        if probe.stderr:
            print(probe.stderr, end="", file=sys.stderr)
    require(probe.returncode == 0, "ESP-IDF quoted compile-fragment parser probe failed")
    require(
        probe.stdout.strip() == "IDF_BUILDER_FRAGMENT_PARSING_OK",
        f"ESP-IDF compile-fragment probe returned unexpected output: {probe.stdout!r}",
    )


def verify_uv_tls_endpoints(core_dir: Path, env: dict[str, str]) -> None:
    _python_exe, uv_exe = verify_penv_distribution(core_dir)
    version = subprocess.run(
        [str(uv_exe), "--version"],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    require(version.returncode == 0, "Nested pioarduino uv could not report its version")
    require(version.stdout.startswith(f"uv {EXPECTED_UV_VERSION} "), "Nested pioarduino uv version drifted")
    require("SSL_CERT_FILE" not in env, "uv TLS probe must use native trust without SSL_CERT_FILE")
    require(env.get("UV_SYSTEM_CERTS") == "true", "uv TLS probe does not have native system trust enabled")

    command = [
        str(uv_exe),
        "--verbose",
        "pip",
        "install",
        f"--python={sys.executable}",
        "--dry-run",
        "--no-cache",
        "--refresh",
        "--no-config",
        "--default-index=https://pypi.org/simple",
        "idf-component-manager~=2.4.6",
        "windows-curses",
    ]
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
        timeout=180,
    )
    combined_output = result.stdout + result.stderr
    if result.returncode != 0:
        print(combined_output, end="", file=sys.stderr)
    require(result.returncode == 0, "Nested uv failed strict TLS resolution for ESP-IDF dependencies")
    # With no cache/config and an explicit PyPI default index, these two names
    # resolve through the exact /simple/<normalized-name>/ endpoints that failed
    # under pioarduino's public-only certifi override.
    for resolved_package in ("idf-component-manager==", "windows-curses=="):
        require(resolved_package in combined_output, f"Nested uv did not resolve {resolved_package[:-2]}")


def lexical_windows_path(path: str | Path) -> str:
    return os.path.normcase(os.path.normpath(str(path)))


def verify_private_build_config(
    core_dir: Path, env: dict[str, str], expected_build_dir: Path,
    expected_cache_dir: Path, project_cwd: Path
) -> None:
    private_python, _private_uv = verify_penv_distribution(core_dir)
    require(re.fullmatch(r"[A-Z]:\\", str(project_cwd)) is not None, "PlatformIO cwd is not a drive-root alias")
    require(str(project_cwd).upper() == "X:\\", "PlatformIO cwd is not the deterministic X: alias")
    require(not any(character.isspace() for character in str(project_cwd)), "PlatformIO project cwd contains whitespace")
    project_probe_code = (
        "import json,os; from platformio.project.helpers import get_project_dir; "
        "print(json.dumps({'cwd':os.getcwd(),'project_dir':get_project_dir()}))"
    )
    project_probe = subprocess.run(
        [str(private_python), "-c", project_probe_code],
        cwd=project_cwd,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    require(project_probe.returncode == 0, "PlatformIO project-directory alias probe failed")
    project_data = json.loads(project_probe.stdout)
    expected_project = lexical_windows_path(project_cwd)
    require(
        lexical_windows_path(project_data.get("cwd", "")) == expected_project,
        "Child cwd canonicalized away from the no-space SUBST alias",
    )
    require(
        lexical_windows_path(project_data.get("project_dir", "")) == expected_project,
        "PlatformIO PROJECT_DIR did not retain the no-space SUBST alias",
    )

    result = subprocess.run(
        [str(private_python), "-m", "platformio", "project", "config", "--json-output"],
        cwd=project_cwd,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    require(result.returncode == 0, "PlatformIO could not resolve the private build directory")
    sections = {section_name: dict(values) for section_name, values in json.loads(result.stdout)}
    configured = Path(sections.get("platformio", {}).get("build_dir", "")).resolve()
    require(configured == expected_build_dir.resolve(), "PlatformIO did not accept the wrapper-owned build directory")
    require(os.path.samefile(configured.parent,
                             Path(env["XTINCT_REPRO_CORE_ROOT"]).resolve()) and
            configured.name == PRIVATE_BUILD_DIRECTORY_NAME,
            "PlatformIO build directory is not the deterministic READY27 path")
    require(not any(character.isspace() for character in str(configured)), "Resolved PlatformIO build path has whitespace")
    require(
        os.path.samefile(configured.parent, expected_build_dir.resolve().parent),
        "Resolved PlatformIO build path escaped the wrapper-owned build root",
    )

    build_cache_value = sections.get("platformio", {}).get("build_cache_dir", "")
    require(bool(build_cache_value), "PlatformIO build_cache_dir is missing")
    require(not any(character.isspace() for character in build_cache_value),
            "PlatformIO build_cache_dir lost the no-space project alias")
    require(
        lexical_windows_path(build_cache_value) == lexical_windows_path(expected_cache_dir),
        "PlatformIO build_cache_dir is not the wrapper-owned per-run cache",
    )
    configured_cache = Path(build_cache_value).resolve()
    require(os.path.samefile(configured_cache.parent, expected_build_dir.resolve()) and
            configured_cache.name == PRIVATE_BUILD_CACHE_DIRECTORY_NAME,
            "PlatformIO build cache escaped the wrapper-owned private build")
    require_plain_directory(configured_cache, "Configured private PlatformIO build cache")
    with os.scandir(configured_cache) as entries:
        require(next(entries, None) is None,
                "Configured private PlatformIO build cache was not empty before the build")
    require(Path(env.get("XTINCT_REPRO_BUILD_CACHE_ROOT", "")).resolve() == configured_cache,
            "Reproducible build-cache ownership marker disagrees with PlatformIO")

    # A release source ZIP intentionally has no Git metadata.  The wrapper
    # already binds both the physical and SUBST views to the exact reviewed
    # source-snapshot hash, which is the portable identity used by QA and the
    # release manifest.  Do not make an unrelated Git checkout a build input.
    require_plain_file(project_cwd / "scripts" / "git_branch.py",
                       "PlatformIO version helper")


def verify_platformio_entrypoint(core_dir: Path, env: dict[str, str]) -> Path:
    private_python, _private_uv = verify_penv_distribution(core_dir)
    verify_private_esptool_construction_evidence(core_dir, env)
    _penv, _python, _uv, site_packages = penv_paths(core_dir)
    require(private_python.resolve().is_relative_to(core_dir.resolve()),
            "PlatformIO launcher escaped the private READY27 core")
    probe_code = (
        "import importlib.metadata as m,json,pathlib,site,sys,platformio;"
        "d=m.distribution('pioarduino-core');"
        "missing=False;"
        "\ntry:m.distribution('platformio')\nexcept m.PackageNotFoundError:missing=True\n"
        "print(json.dumps({'executable':str(pathlib.Path(sys.executable).resolve()),"
        "'prefix':str(pathlib.Path(sys.prefix).resolve()),"
        "'module':str(pathlib.Path(platformio.__file__).resolve()),"
        "'dist_name':d.metadata['Name'],'dist_version':d.version,"
        "'platformio_dist_missing':missing,'user_site':site.ENABLE_USER_SITE}))"
    )
    identity = subprocess.run(
        [str(private_python), "-I", "-c", probe_code],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        capture_output=True,
        check=False,
    )
    require(identity.returncode == 0 and not identity.stderr,
            "Private pioarduino entrypoint identity probe failed")
    try:
        record = json.loads(identity.stdout)
    except json.JSONDecodeError as error:
        raise BuildWrapperError("Private pioarduino identity probe was not JSON") from error
    require(Path(record.get("executable", "")).resolve() == private_python.resolve(),
            "Private pioarduino probe used the wrong Python executable")
    require(Path(record.get("prefix", "")).resolve() == (core_dir / "penv").resolve(),
            "Private pioarduino Python prefix escaped its copied penv")
    require(Path(record.get("module", "")).resolve() ==
            (site_packages / "platformio" / "__init__.py").resolve(),
            "PlatformIO module did not load from the private copied penv")
    require(record.get("dist_name") == "pioarduino-core" and
            record.get("dist_version") == EXPECTED_PLATFORMIO_VERSION and
            record.get("platformio_dist_missing") is True and
            record.get("user_site") is False,
            "Private pioarduino distribution identity changed")

    result = subprocess.run(
        [str(private_python), "-I", "-m", "platformio", "--version"],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    require(result.returncode == 0, "Python 3.11 cannot launch PlatformIO")
    require(
        result.stdout.strip() == f"PlatformIO Core, version {EXPECTED_PLATFORMIO_VERSION}",
        "Unexpected PlatformIO Core entrypoint output",
    )
    return private_python


def verify_git_tls(env: dict[str, str]) -> None:
    git = shutil.which("git")
    require(git is not None, "Git is required for pinned PlatformIO dependencies")
    origins = (
        "https://github.com/Links2004/arduinoWebSockets.git",
        "https://github.com/wolfSSL/Arduino-wolfSSL.git",
        "https://github.com/bitbank2/JPEGDEC.git",
        "https://github.com/crosspoint-reader/crosspoint-reader.git",
        "https://github.com/pioarduino/platformio-core.git",
    )
    for origin in origins:
        expected = {
            "http.sslVerify": "true",
            "http.sslBackend": "schannel",
            "http.schannelUseSSLCAInfo": "false",
        }
        for key, expected_value in expected.items():
            result = subprocess.run(
                [git, "-C", str(PROJECT_ROOT), "config", "--get-urlmatch", key, origin],
                cwd=PROJECT_ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            require(result.returncode == 0, f"Could not resolve effective Git TLS setting {key} for {origin}")
            require(
                result.stdout.strip().lower() == expected_value,
                f"Effective Git TLS setting {key} is not {expected_value} for {origin}",
            )


def parse_pio_args(argv: Sequence[str]) -> tuple[list[str], str]:
    args = list(argv) or ["run", "-e", "default"]
    if args and args[0] == "--":
        args.pop(0)
    require(args and args[0] == "run", "This wrapper only accepts PlatformIO 'run' builds")
    normalized = ["run"]
    environments: list[str] = []
    requested_jobs: int | None = None
    index = 1
    while index < len(args):
        value = args[index]
        if value in ("-t", "--target") or value.startswith(("--target=", "-t=", "-t")):
            raise BuildWrapperError("PlatformIO targets are forbidden; this wrapper compiles only")
        if value in ("-d", "--project-dir", "-c", "--project-conf") or value.startswith(
            ("--project-dir=", "--project-conf=", "-d=", "-c=", "-d", "-c")
        ):
            raise BuildWrapperError("Project directory/config overrides are forbidden")
        if value in ("-e", "--environment"):
            require(index + 1 < len(args), f"{value} requires an environment")
            environments.append(args[index + 1])
            normalized.extend([value, args[index + 1]])
            index += 2
            continue
        if value.startswith("--environment="):
            environments.append(value.split("=", 1)[1])
            normalized.append(value)
            index += 1
            continue
        if value.startswith("-e=") or (value.startswith("-e") and value != "-e"):
            environment_value = value[3:] if value.startswith("-e=") else value[2:]
            require(bool(environment_value), "-e requires an environment")
            environments.append(environment_value)
            normalized.append(value)
            index += 1
            continue
        if value in ("-v", "--verbose", "-s", "--silent", "--disable-auto-clean"):
            normalized.append(value)
            index += 1
            continue
        if value in ("-j", "--jobs"):
            require(index + 1 < len(args) and args[index + 1].isdigit(), f"{value} requires a numeric value")
            require(requested_jobs is None, "PlatformIO jobs may be specified only once")
            requested_jobs = int(args[index + 1])
            index += 2
            continue
        if value.startswith("--jobs=") or (value.startswith("-j") and value != "-j"):
            jobs_value = value.split("=", 1)[1] if value.startswith("--jobs=") else value[2:]
            require(jobs_value.isdigit(), "Jobs value must be numeric")
            require(requested_jobs is None, "PlatformIO jobs may be specified only once")
            requested_jobs = int(jobs_value)
            index += 1
            continue
        raise BuildWrapperError(f"Unsupported PlatformIO build argument: {value}")

    require(len(environments) <= 1, "Exactly zero or one PlatformIO environment is allowed")
    environment = environments[0] if environments else "default"
    require(environment == "default", "This verified wrapper builds only the X3/X4 default environment")
    jobs = MAX_PLATFORMIO_JOBS if requested_jobs is None else requested_jobs
    require(1 <= jobs <= MAX_PLATFORMIO_JOBS,
            f"PlatformIO jobs must be between 1 and {MAX_PLATFORMIO_JOBS}")
    normalized.extend(["-j", str(jobs)])
    return normalized, environment


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def system_powershell_executable() -> Path:
    windows_root = Path(os.environ.get("SystemRoot", ""))
    require(windows_root.is_absolute(), "SystemRoot is unavailable for source snapshot verification")
    executable = windows_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    require_plain_file(executable, "System Windows PowerShell")
    return executable


def get_source_snapshot() -> dict[str, int | str | dict[str, int | str]]:
    snapshotter = PROJECT_ROOT / SOURCE_SNAPSHOT_SCRIPT
    require_plain_file(snapshotter, "XTINCT source snapshotter")
    result = subprocess.run(
        [str(system_powershell_executable()), "-NoLogo", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-File", str(snapshotter),
         "-SourceRoot", str(PROJECT_ROOT)],
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise BuildWrapperError(
            f"XTINCT source snapshotter failed: {(result.stderr or result.stdout).strip()}"
        )
    require(not result.stderr, "XTINCT source snapshotter wrote to stderr")
    try:
        snapshot = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise BuildWrapperError("XTINCT source snapshotter output is not JSON") from error
    require(isinstance(snapshot, dict) and set(snapshot) == {"schema", "root", "files", "sha256"},
            "XTINCT source snapshot envelope is invalid")
    require(snapshot.get("schema") == 1 and isinstance(snapshot.get("files"), int) and
            snapshot["files"] > 0 and isinstance(snapshot.get("sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", snapshot["sha256"]) is not None,
            "XTINCT source snapshot values are invalid")
    require(Path(snapshot.get("root", "")).resolve() == PROJECT_ROOT.resolve(),
            "XTINCT source snapshot root changed")
    return {
        "files": snapshot["files"],
        "sha256": snapshot["sha256"],
        "snapshotter": {
            "path": SOURCE_SNAPSHOT_SCRIPT,
            "bytes": snapshotter.stat().st_size,
            "sha256": sha256_file(snapshotter),
        },
    }


def ensure_publish_directory(environment: str) -> Path:
    require_plain_directory(PROJECT_ROOT, "XTINCT project root")
    current = PROJECT_ROOT
    for component in (FIRMWARE_RELATIVE / environment).parts:
        candidate = current / component
        if path_lexists(candidate):
            require_plain_directory(candidate, "Artifact publish directory")
        else:
            candidate.mkdir()
            require_plain_directory(candidate, "New artifact publish directory")
        current = candidate
    require(current.resolve().is_relative_to(PROJECT_ROOT), "Artifact publish directory escaped the project")
    return current


def validate_fresh_artifact(path: Path, started_ns: int, maximum_size: int | None = None) -> tuple[int, int, str]:
    require(path_lexists(path), f"Successful PlatformIO run did not create {path}")
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode), f"Build artifact is not a regular file: {path}")
    require(not is_reparse_point(path), f"Build artifact is a reparse point: {path}")
    require(info.st_size > 0, f"Build artifact is empty: {path.name}")
    if maximum_size is not None:
        require(info.st_size <= maximum_size,
                f"{path.name} is {info.st_size} bytes and exceeds OTA slot size {maximum_size}")
    require(info.st_mtime_ns >= started_ns, f"Build artifact was not freshly produced: {path.name}")
    return info.st_mode, info.st_size, sha256_file(path)


def validate_stable_artifact(path: Path, description: str, *,
                             expected_size: int | None = None,
                             expected_digest: str | None = None) -> tuple[Path, int, int, str]:
    """Bind a package-owned companion that is intentionally older than this build."""
    require(path_lexists(path), f"{description} is missing: {path}")
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode), f"{description} is not a regular file: {path}")
    require(not is_reparse_point(path), f"{description} is a reparse point: {path}")
    require(before.st_size > 0, f"{description} is empty: {path}")
    if expected_size is not None:
        require(before.st_size == expected_size,
                f"{description} is {before.st_size} bytes; expected {expected_size}")
    digest = sha256_file(path)
    if expected_digest is not None:
        require(digest == expected_digest,
                f"{description} SHA-256 changed: {digest}")
    after = os.lstat(path)
    require(stat.S_ISREG(after.st_mode) and not is_reparse_point(path) and
            before.st_size == after.st_size and
            before.st_mtime_ns == after.st_mtime_ns and
            stat.S_IMODE(before.st_mode) == stat.S_IMODE(after.st_mode) and
            sha256_file(path) == digest,
            f"{description} changed while it was hashed")
    return path, after.st_mode, after.st_size, digest


def atomic_publish_artifact(source: Path, destination: Path, mode: int, expected_size: int,
                            expected_digest: str) -> None:
    if path_lexists(destination):
        destination_info = os.lstat(destination)
        require(stat.S_ISREG(destination_info.st_mode), f"Publish destination is not a regular file: {destination}")
        require(not is_reparse_point(destination), f"Publish destination is a reparse point: {destination}")

    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.xtinct-publish-", suffix=".tmp", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        copied = 0
        digest = hashlib.sha256()
        with os.fdopen(fd, "wb") as output_handle, source.open("rb") as input_handle:
            while block := input_handle.read(1024 * 1024):
                output_handle.write(block)
                digest.update(block)
                copied += len(block)
            output_handle.flush()
            os.fsync(output_handle.fileno())
        require(copied == expected_size, f"Staged artifact size changed while copying: {source.name}")
        require(digest.hexdigest() == expected_digest, f"Staged artifact hash changed while copying: {source.name}")
        require(not is_reparse_point(temporary), f"Staged artifact became a reparse point: {temporary}")
        os.chmod(temporary, stat.S_IMODE(mode))
        os.replace(temporary, destination)
    finally:
        if path_lexists(temporary):
            require(not is_reparse_point(temporary), f"Refusing to remove reparse-point staging file: {temporary}")
            temporary.unlink()

    published = os.lstat(destination)
    require(stat.S_ISREG(published.st_mode) and not is_reparse_point(destination),
            f"Published artifact is not a plain file: {destination}")
    require(published.st_size == expected_size, f"Published artifact size mismatch: {destination.name}")
    require(sha256_file(destination) == expected_digest, f"Published artifact hash mismatch: {destination.name}")


def find_fresh_dependency(build_dir: Path, name: str, started_ns: int) -> tuple[Path, int, int, str]:
    matches = list(build_dir.rglob(name))
    require(len(matches) == 1, f"Expected exactly one generated dependency file for {name}")
    path = matches[0]
    mode, size, digest = validate_fresh_artifact(path, started_ns)
    return path, mode, size, digest


def replace_dependency_root(text: str, root: Path, replacement: str) -> str:
    root_text = str(root).rstrip("/\\")
    variants = {
        root_text,
        root_text.replace("\\", "/"),
        root_text.replace(" ", "\\ "),
        root_text.replace("\\", "/").replace(" ", "\\ "),
    }
    for variant in sorted(variants, key=len, reverse=True):
        text = re.sub(re.escape(variant), lambda _match: replacement, text, flags=re.IGNORECASE)
    return text


def normalize_dependency_bytes(path: Path, source_dir: Path, packages_dir: Path,
                               libdeps_dir: Path, project_alias: Path) -> bytes:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise BuildWrapperError(f"Generated dependency file is not valid UTF-8: {path}") from error
    require("\0" not in text, f"Generated dependency file contains NUL: {path.name}")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    normalization_roots: list[tuple[Path, str]] = [
        (source_dir, "$BUILD"),
        (source_dir.parent, "$PRIVATE_BUILD"),
        (packages_dir, "$PACKAGES"),
        # Keep this ahead of broader core/project roots.  Pocket Sync's raw
        # dependency file must prove the exact private READY27 libdeps tree it
        # compiled against without publishing a user/core absolute path.
        (libdeps_dir, "$LIBDEPS"),
        (project_alias, "$PROJECT"),
        (PROJECT_ROOT, "$PROJECT"),
    ]
    core_dir = packages_dir.parent.resolve()
    require(libdeps_dir.parent.resolve() == core_dir and source_dir.is_relative_to(core_dir),
            "Dependency evidence roots do not share the private core")
    if os.name == "nt":
        short_core = windows_short_directory(core_dir, "dependency private core")
        short_source = short_core / source_dir.relative_to(core_dir)
        normalization_roots[0:0] = [
            (short_source, "$BUILD"),
            (short_source.parent, "$PRIVATE_BUILD"),
            (short_core / "packages", "$PACKAGES"),
            (short_core / "libdeps", "$LIBDEPS"),
            (short_core, "$PIO"),
        ]
    for root, replacement in normalization_roots:
        text = replace_dependency_root(text, root, replacement)
    require(re.search(r"(?im)(?:^|\s)(?:[a-z]:[/\\]|//)", text) is None,
            f"Normalized dependency file still contains an absolute path: {path.name}")
    require("$BUILD/" in text,
            f"Normalized dependency file lacks its private-build provenance: {path.name}")
    return text.encode("utf-8")


def exception_construction_evidence(source_dir: Path, started_ns: int) -> dict[str, object]:
    path = source_dir / EXCEPTION_CONSTRUCTION_EVIDENCE_NAME
    validate_fresh_artifact(path, started_ns)
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BuildWrapperError("Exception construction evidence is not valid UTF-8 JSON") from error
    guard = PROJECT_ROOT / EXCEPTION_GUARD_RELATIVE
    require_plain_file(guard, "C++ exception build guard")
    expected_guard = {
        "bytes": guard.stat().st_size,
        "path": EXCEPTION_GUARD_RELATIVE.as_posix(),
        "sha256": sha256_file(guard),
    }
    require(record == {
        "effective_exception_switches": ["-fexceptions"],
        "guard": expected_guard,
        "policy": EXCEPTION_POLICY,
        "schema": 1,
    }, "Exception construction evidence does not match the effective reviewed policy")
    return record


def exception_dependency_source(normalized: str, dependency_name: str) -> str:
    source_name = dependency_name[:-2] if dependency_name.endswith(".d") else ""
    require(source_name.endswith(".cpp"),
            f"Exception dependency has an unexpected name: {dependency_name}")
    candidates = {
        token
        for token in re.findall(r"(?<!\S)([^\s\\]+\.cpp)(?=\s|\\|$)", normalized)
        if token.rsplit("/", 1)[-1] == source_name
    }
    require(len(candidates) == 1,
            f"Exception dependency does not identify one C++ source: {dependency_name}")
    return next(iter(candidates))


def build_exception_translation_unit_evidence(
        source_dir: Path, packages_dir: Path, libdeps_dir: Path, project_alias: Path,
        started_ns: int) -> dict[str, object]:
    dependencies = sorted(
        source_dir.rglob("*.cpp.d"),
        key=lambda path: path.relative_to(source_dir).as_posix().encode("utf-8"),
    )
    require(0 < len(dependencies) <= 4096,
            "Exception build found an invalid C++ dependency-file count")
    units: list[dict[str, object]] = []
    guard_suffix = EXCEPTION_GUARD_RELATIVE.as_posix()
    for dependency in dependencies:
        validate_fresh_artifact(dependency, started_ns)
        normalized_bytes = normalize_dependency_bytes(
            dependency, source_dir, packages_dir, libdeps_dir, project_alias
        )
        try:
            normalized = normalized_bytes.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BuildWrapperError(
                f"Normalized exception dependency is not UTF-8: {dependency}"
            ) from error
        require(guard_suffix in normalized,
                f"C++ translation unit did not force-include the exception guard: {dependency}")
        relative = dependency.relative_to(source_dir).as_posix()
        units.append({
            "dependency": relative,
            "dependency_bytes": len(normalized_bytes),
            "dependency_sha256": sha256(normalized_bytes),
            "source": exception_dependency_source(normalized, dependency.name),
        })
    canonical = json.dumps(units, ensure_ascii=True, separators=(",", ":"),
                           sort_keys=True).encode("ascii")
    return {
        "count": len(units),
        "units": units,
        "units_sha256": sha256(canonical),
    }


def build_exception_evidence(source_dir: Path, packages_dir: Path,
                             libdeps_dir: Path, project_alias: Path,
                             started_ns: int) -> dict[str, object]:
    construction = exception_construction_evidence(source_dir, started_ns)
    translation_units = build_exception_translation_unit_evidence(
        source_dir, packages_dir, libdeps_dir, project_alias, started_ns
    )
    runtime_probe = PROJECT_ROOT / EXCEPTION_RUNTIME_PROBE_RELATIVE
    require_plain_file(runtime_probe, "actual C++ allocation throw/catch runtime probe")
    runtime_source = runtime_probe.read_text(encoding="utf-8")
    require(EXCEPTION_RUNTIME_PROBE_TEST.split(".", 1)[1] in runtime_source and
            runtime_source.count("throw std::bad_alloc();") >= 2,
            "actual C++ allocation throw/catch runtime probe changed")
    return {
        "construction": construction,
        "policy": EXCEPTION_POLICY,
        "runtime_probe": {
            "bytes": runtime_probe.stat().st_size,
            "path": EXCEPTION_RUNTIME_PROBE_RELATIVE.as_posix(),
            "proof": "real-bad-alloc-throw-catch-transactional-v1",
            "sha256": sha256_file(runtime_probe),
            "test": EXCEPTION_RUNTIME_PROBE_TEST,
        },
        "schema": 1,
        "translation_units": translation_units,
    }


def generated_exception_sdkconfig(path: Path) -> dict[str, str]:
    require_plain_file(path, "generated ESP-IDF exception configuration")
    defines: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"#define\s+(CONFIG_[A-Z0-9_]+)(?:\s+(.*))?", line.strip())
        if match is None:
            continue
        name = match.group(1)
        require(name not in defines, f"Generated sdkconfig repeats {name}")
        defines[name] = (match.group(2) or "1").strip()
    expected = {
        "CONFIG_COMPILER_CXX_EXCEPTIONS": "1",
        "CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE": "1024",
    }
    for name, value in expected.items():
        require(defines.get(name) == value,
                f"Generated ESP-IDF exception setting changed: {name}={defines.get(name)!r}")
    require(defines.get("CONFIG_COMPILER_CXX_RTTI") in {None, "0", "n"},
            "Generated ESP-IDF configuration unexpectedly enabled RTTI")
    return {**expected, "CONFIG_COMPILER_CXX_RTTI": "disabled"}


def linked_exception_symbols(firmware_elf: Path, packages_dir: Path) -> list[str]:
    nm = packages_dir / "toolchain-riscv32-esp" / "bin" / "riscv32-esp-elf-nm.exe"
    require_plain_file(nm, "pinned RISC-V symbol reader")
    result = subprocess.run(
        [str(nm), "-a", str(firmware_elf)],
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    require(result.returncode == 0 and not result.stderr,
            "Pinned RISC-V symbol reader failed for exception evidence")
    for symbol in EXCEPTION_REQUIRED_SYMBOLS:
        require(re.search(rf"(?<![A-Za-z0-9_]){re.escape(symbol)}(?![A-Za-z0-9_])",
                          result.stdout) is not None,
                f"Linked firmware lacks C++ exception runtime symbol: {symbol}")
    for symbol in EXCEPTION_FORBIDDEN_STUB_SYMBOLS:
        require(re.search(rf"(?<![A-Za-z0-9_]){re.escape(symbol)}(?![A-Za-z0-9_])",
                          result.stdout) is None,
                f"Linked firmware retained fatal C++ exception stub: {symbol}")
    return list(EXCEPTION_REQUIRED_SYMBOLS)


def normalize_linker_map_bytes(path: Path, source_dir: Path, core_dir: Path,
                               packages_dir: Path, project_alias: Path) -> bytes:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise BuildWrapperError(f"Generated linker map is not valid UTF-8: {path}") from error
    require("\0" not in text, "Generated linker map contains NUL")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    normalization_roots: list[tuple[Path, str]] = [
        (source_dir, "$BUILD/default"),
        (source_dir.parent, "$BUILD"),
        (packages_dir, "$PACKAGES"),
        (core_dir, "$PIO"),
        (project_alias, "$PROJECT"),
        (PROJECT_ROOT, "$PROJECT"),
        (Path.home(), "$USER"),
    ]
    if os.name == "nt" and source_dir.is_relative_to(core_dir):
        # PlatformIO/SCons records the private build through the verified DOS
        # 8.3 identity used to keep Windows command lines bounded.  Normalize
        # that byte-distinct spelling to the same provenance anchors as the
        # canonical private-core paths.
        short_core = windows_short_directory(core_dir, "linker-map private core")
        short_source = short_core / source_dir.relative_to(core_dir)
        canonical_packages = core_dir / "packages"
        require_plain_directory(canonical_packages, "linker-map canonical package root")
        require_plain_directory(packages_dir, "linker-map supplied package root")
        require(os.path.samefile(packages_dir, canonical_packages),
                "Linker-map package root changed identity")
        short_packages = short_core / "packages"
        normalization_roots[0:0] = [
            (short_source, "$BUILD/default"),
            (short_source.parent, "$BUILD"),
            (short_packages, "$PACKAGES"),
            (short_core, "$PIO"),
        ]
    for root, replacement in normalization_roots:
        text = replace_dependency_root(text, root, replacement)
    require(re.search(r"(?i)(?:[a-z]:[/\\]|\\\\[^\\])", text) is None,
            "Normalized linker map still contains a host-absolute path")
    require("$BUILD/" in text, "Normalized linker map lacks build provenance")
    require("$PACKAGES/" in text, "Normalized linker map lacks package provenance")
    return text.encode("utf-8")


def is_grammatical_virtual_sdk_path(value: str) -> bool:
    if not value.startswith(VIRTUAL_SDK_PATH_ROOT):
        return False
    remainder = value[len(VIRTUAL_SDK_PATH_ROOT):]
    if not remainder or remainder[0] not in VIRTUAL_SDK_SEPARATORS:
        return False
    remainder = remainder[1:]
    if not remainder.startswith(VIRTUAL_SDK_COMPONENT):
        return False
    remainder = remainder[len(VIRTUAL_SDK_COMPONENT):]
    if not remainder or remainder[0] not in VIRTUAL_SDK_SEPARATORS:
        return False
    suffix = remainder[1:]
    if not suffix:
        return False
    parts = re.split(r"[/\\]", suffix)
    profile_name = Path.home().name.strip().lower()
    forbidden_profile_parts = {"users"}
    if profile_name:
        forbidden_profile_parts.add(profile_name)
    return all(
        part not in ("", ".", "..") and
        re.fullmatch(r"[A-Za-z0-9_.-]+", part) is not None and
        part.lower() not in forbidden_profile_parts
        for part in parts
    )


VIRTUAL_SDK_CANDIDATE_BYTES = re.compile(
    rb"(?<![A-Za-z0-9_.:-])"
    rb"(?P<path>//IDF[\\/]components[\\/]"
    rb"[A-Za-z0-9_.-]+(?:[\\/][A-Za-z0-9_.-]+)*)"
    rb"(?![A-Za-z0-9_.:/\\-])"
)


def extract_virtual_sdk_candidates(payload: bytes) -> set[str]:
    """Extract canonical virtual paths, including GCC's ///IDF spelling."""
    candidates: set[str] = set()
    for match in VIRTUAL_SDK_CANDIDATE_BYTES.finditer(payload):
        value = match.group("path").decode("ascii")
        if is_grammatical_virtual_sdk_path(value):
            candidates.add(value)
    return candidates


def virtual_sdk_candidate_record(value: str) -> dict[str, int | str]:
    encoded = value.encode("ascii")
    return {"bytes": len(encoded), "sha256": sha256(encoded), "value": value}


def virtual_sdk_candidate_set_sha256(values: Sequence[str]) -> str:
    digest = hashlib.sha256()
    digest.update(b"XTINCT-IDF-CANDIDATE-SET-V2\0")
    for value in sorted(set(values)):
        encoded = value.encode("ascii")
        digest.update(str(len(encoded)).encode("ascii"))
        digest.update(b"\0")
        digest.update(encoded)
        digest.update(b"\0")
    return digest.hexdigest()


def virtual_sdk_probe_specs(probe_state: str) -> tuple[tuple[Path, int, str, str, int, str], ...]:
    require(probe_state in VIRTUAL_SDK_PROBE_STATES,
            f"Unrecognized virtual SDK probe state: {probe_state!r}")
    if probe_state == VIRTUAL_SDK_VENDOR_PROBE_STATE:
        bootloader_bytes = VENDOR_BOOTLOADER_SUPPORT_ARCHIVE_BYTES
        bootloader_sha256 = VENDOR_BOOTLOADER_SUPPORT_ARCHIVE_SHA256
        app_update_bytes = VENDOR_APP_UPDATE_ARCHIVE_BYTES
        app_update_sha256 = VENDOR_APP_UPDATE_ARCHIVE_SHA256
        app_update_candidate = VENDOR_APP_UPDATE_VIRTUAL_PATH
        app_update_candidate_sha256 = VENDOR_APP_UPDATE_VIRTUAL_PATH_SHA256
    else:
        bootloader_bytes = REBUILT_BOOTLOADER_SUPPORT_ARCHIVE_BYTES
        bootloader_sha256 = REBUILT_BOOTLOADER_SUPPORT_ARCHIVE_SHA256
        app_update_bytes = REBUILT_APP_UPDATE_ARCHIVE_BYTES
        app_update_sha256 = REBUILT_APP_UPDATE_ARCHIVE_SHA256
        app_update_candidate = REBUILT_APP_UPDATE_VIRTUAL_PATH
        app_update_candidate_sha256 = REBUILT_APP_UPDATE_VIRTUAL_PATH_SHA256
    return (
        (
            BOOTLOADER_SUPPORT_ARCHIVE_RELATIVE,
            bootloader_bytes,
            bootloader_sha256,
            EXPECTED_BOOTLOADER_VIRTUAL_PATH,
            EXPECTED_BOOTLOADER_VIRTUAL_PATH_BYTES,
            EXPECTED_BOOTLOADER_VIRTUAL_PATH_SHA256,
        ),
        (
            APP_UPDATE_ARCHIVE_RELATIVE,
            app_update_bytes,
            app_update_sha256,
            app_update_candidate,
            EXPECTED_APP_UPDATE_VIRTUAL_PATH_BYTES,
            app_update_candidate_sha256,
        ),
    )


def build_virtual_sdk_provenance(normalized_map: bytes,
                                 packages_dir: Path,
                                 probe_state: str) -> tuple[dict[str, object], frozenset[str]]:
    probe_specs = virtual_sdk_probe_specs(probe_state)
    try:
        map_text = normalized_map.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BuildWrapperError("Normalized map is not UTF-8 for SDK provenance") from error
    require("\0" not in map_text, "Normalized map contains NUL during SDK provenance")
    slash_map = map_text.replace("\\", "/")
    linked_relatives: set[str] = set()
    for match in re.finditer(r"\$PACKAGES/([^\s()]+?\.a)\(", slash_map):
        relative_text = match.group(1)
        sdk_prefix = VIRTUAL_SDK_ARCHIVE_DIRECTORY.as_posix() + "/"
        if not relative_text.startswith(sdk_prefix):
            continue
        relative = Path(relative_text)
        require(not relative.is_absolute() and ".." not in relative.parts,
                "Linked SDK archive escaped the package root")
        require(relative.is_relative_to(VIRTUAL_SDK_ARCHIVE_DIRECTORY),
                "Linked SDK archive escaped its reviewed directory")
        linked_relatives.add(relative.as_posix())
    require(linked_relatives, "Normalized map has no linked ESP32-C3 SDK archives")

    archive_records: list[dict[str, object]] = []
    approved_candidates: set[str] = set()
    for relative_text in sorted(linked_relatives):
        relative = Path(relative_text)
        archive = packages_dir / relative
        require_plain_file(archive, "Map-linked SDK archive")
        payload = archive.read_bytes()
        candidates = extract_virtual_sdk_candidates(payload)
        if not candidates:
            continue
        approved_candidates.update(candidates)
        archive_records.append({
            "bytes": len(payload),
            "candidate_count": len(candidates),
            "candidate_set_sha256": virtual_sdk_candidate_set_sha256(tuple(candidates)),
            "candidates": [virtual_sdk_candidate_record(value) for value in sorted(candidates)],
            "map_reference": f"$PACKAGES/{relative.as_posix()}",
            "path": relative.as_posix(),
            "sha256": sha256(payload),
        })

    bootloader_elf = packages_dir / VIRTUAL_SDK_BOOTLOADER_ELF_RELATIVE
    require_plain_file(bootloader_elf, "Pinned DIO/80 MHz bootloader ELF")
    bootloader_elf_payload = bootloader_elf.read_bytes()
    require(
        len(bootloader_elf_payload) == VIRTUAL_SDK_BOOTLOADER_ELF_BYTES and
        sha256(bootloader_elf_payload) == VIRTUAL_SDK_BOOTLOADER_ELF_SHA256,
        "Pinned DIO/80 MHz bootloader ELF changed",
    )
    bootloader_candidates = extract_virtual_sdk_candidates(bootloader_elf_payload)
    require(
        bootloader_candidates and
        EXPECTED_BOOTLOADER_SOURCE_VIRTUAL_PATH in bootloader_candidates,
        "Pinned DIO/80 MHz bootloader ELF lost its required source candidate",
    )
    approved_candidates.update(bootloader_candidates)

    require(archive_records and approved_candidates,
            "Map-linked SDK archives contain no approved virtual candidates")
    archive_by_path = {record["path"]: record for record in archive_records}
    probes: list[dict[str, int | str]] = []
    for relative, archive_bytes, archive_sha256, candidate, candidate_bytes, candidate_sha256 in probe_specs:
        relative_text = relative.as_posix()
        record = archive_by_path.get(relative_text)
        require(record is not None, f"Required virtual SDK probe archive is not map-linked: {relative_text}")
        require(record["bytes"] == archive_bytes and record["sha256"] == archive_sha256,
                f"Required virtual SDK probe archive changed: {relative_text}")
        require(candidate in approved_candidates and
                any(item["value"] == candidate for item in record["candidates"]),
                f"Required virtual SDK probe candidate is absent: {candidate}")
        encoded = candidate.encode("ascii")
        require(len(encoded) == candidate_bytes and sha256(encoded) == candidate_sha256,
                f"Required virtual SDK probe candidate changed: {candidate}")
        probes.append({
            "archive": relative_text,
            "archive_bytes": archive_bytes,
            "archive_sha256": archive_sha256,
            "candidate": candidate,
            "candidate_bytes": candidate_bytes,
            "candidate_sha256": candidate_sha256,
        })

    provenance: dict[str, object] = {
        "archives": archive_records,
        "bootloader_elf": {
            "bytes": len(bootloader_elf_payload),
            "candidate_count": len(bootloader_candidates),
            "candidate_set_sha256": virtual_sdk_candidate_set_sha256(
                tuple(bootloader_candidates)
            ),
            "candidates": [
                virtual_sdk_candidate_record(value)
                for value in sorted(bootloader_candidates)
            ],
            "path": VIRTUAL_SDK_BOOTLOADER_ELF_RELATIVE.as_posix(),
            "sha256": sha256(bootloader_elf_payload),
        },
        "candidate_set": {
            "count": len(approved_candidates),
            "sha256": virtual_sdk_candidate_set_sha256(tuple(approved_candidates)),
        },
        "grammar": {
            "component": VIRTUAL_SDK_COMPONENT,
            "nul_terminated": True,
            "root": VIRTUAL_SDK_PATH_ROOT,
            "segment_pattern": "[A-Za-z0-9_.-]+",
            "separators": list(VIRTUAL_SDK_SEPARATORS),
        },
        "map_linkage": {
            "artifact": "firmware.map",
            "reference_syntax": "$PACKAGES/<relative>.a(<member>)",
            "source": "normalized-from-raw-map",
        },
        "policy": VIRTUAL_SDK_POLICY,
        "probe_state": probe_state,
        "probes": probes,
    }
    return provenance, frozenset(approved_candidates)


def require_private_artifact_paths_absent(paths: Sequence[Path], private_build_dir: Path,
                                          core_dir: Path, packages_dir: Path,
                                          project_alias: Path,
                                          virtual_sdk_candidates: frozenset[str],
                                          probe_state: str) -> None:
    probe_specs = virtual_sdk_probe_specs(probe_state)
    require(all(spec[3] in virtual_sdk_candidates for spec in probe_specs),
            "Virtual SDK candidate provenance lacks required probes")
    miniz_source = PROJECT_ROOT / MINIZ_SOURCE_RELATIVE
    require_plain_file(miniz_source, "Pinned virtual-project source probe")
    require(miniz_source.stat().st_size == EXPECTED_MINIZ_SOURCE_BYTES and
            sha256_file(miniz_source) == EXPECTED_MINIZ_SOURCE_SHA256,
            "Pinned virtual-project source probe provenance changed")
    roots = (
        PROJECT_ROOT.resolve(), private_build_dir.resolve(), core_dir.resolve(),
        packages_dir.resolve(), project_alias, Path.home().resolve(),
    )
    text_needles = {
        "c:/users/", "c:\\users\\", "x:/", "x:\\",
        PRIVATE_BUILD_DIRECTORY_NAME.lower(),
    }
    for root in roots:
        value = str(root).rstrip("/\\")
        if value:
            # A drive-root alias such as X:\ becomes the two-byte string X:
            # after trimming.  Searching arbitrary firmware bytes for that
            # sequence produces nondeterministic machine-code false positives.
            # The explicit x:/ and x:\ needles above retain raw alias checks,
            # while the bounded ASCII/UTF-16 scanners retain semantic checks.
            if re.fullmatch(r"(?i)[a-z]:", value):
                continue
            text_needles.add(value.lower())
            text_needles.add(value.replace("\\", "/").lower())
    profile_name = Path.home().name.strip().lower()
    if profile_name:
        text_needles.add(f"/{profile_name}/")
        text_needles.add(f"\\{profile_name}\\")

    # A UNC candidate needs a syntactically plausible host and share.  Treating
    # any printable bytes after two backslashes as UNC makes arbitrary RISC-V
    # data/code look like a host path (for example ``\\X<`\\X<d``).  The
    # restricted grammar still covers DNS/NetBIOS hosts and ordinary/admin
    # shares while rejecting characters Windows itself forbids in those names.
    embedded_unc_path = re.compile(
        r"(?i)(?P<path>(?:\\\\|//)[A-Za-z0-9][A-Za-z0-9._-]*"
        r"[/\\][A-Za-z0-9$][A-Za-z0-9$._-]*)"
    )
    embedded_drive_path = re.compile(r"(?i)[a-z]:[/\\]")
    uri_scheme = re.compile(r"(?i)(?:^|[^a-z0-9+.-])([a-z][a-z0-9+.-]+)://")

    def first_embedded_drive_path(value: str) -> re.Match[str] | None:
        scheme_drive_offsets = {
            match.start(1) + len(match.group(1)) - 1
            for match in uri_scheme.finditer(value)
            if match.group(1).lower() in ARTIFACT_PRIVACY_URI_SCHEMES
        }
        return next(
            (match for match in embedded_drive_path.finditer(value)
             if match.start() not in scheme_drive_offsets),
            None,
        )

    def bound_uri_authority_offsets(value: str) -> frozenset[int]:
        return frozenset(
            match.end(1) + 1
            for match in uri_scheme.finditer(value)
            if match.group(1).lower() in ARTIFACT_PRIVACY_URI_SCHEMES
        )

    def first_disallowed_host_path(value: str) -> tuple[int, str] | None:
        drive_match = first_embedded_drive_path(value)
        if drive_match is not None:
            return drive_match.start(), value[drive_match.start():]
        for sdk_match in re.finditer(
                r"(?:^|[\s\"'=([{])(?P<path>//IDF.*)", value):
            sdk_candidate = value[sdk_match.start("path"):]
            if not (is_grammatical_virtual_sdk_path(sdk_candidate) and
                    sdk_candidate in virtual_sdk_candidates):
                return sdk_match.start("path"), sdk_candidate
        uri_authority_offsets = bound_uri_authority_offsets(value)
        for match in embedded_unc_path.finditer(value):
            original_candidate = value[match.start("path"):]

            if match.start("path") in uri_authority_offsets:
                continue

            if (is_grammatical_virtual_sdk_path(original_candidate) and
                    original_candidate in virtual_sdk_candidates):
                continue

            project_suffix = (
                original_candidate[len(VIRTUAL_PROJECT_PATH_PREFIX):]
                if original_candidate.startswith(VIRTUAL_PROJECT_PATH_PREFIX) else ""
            )
            project_parts = project_suffix.split("/") if project_suffix else []
            if (len(project_parts) >= 2 and
                    project_parts[0] in VIRTUAL_PROJECT_PATH_ROOTS and
                    all(part not in ("", ".", "..") and
                        re.fullmatch(r"[A-Za-z0-9_.-]+", part) is not None
                        for part in project_parts[1:])):
                continue
            return match.start("path"), original_candidate
        return None

    redaction_roots = (
        (private_build_dir, "$BUILD"),
        (packages_dir, "$PACKAGES"),
        (core_dir, "$PIO"),
        (PROJECT_ROOT, "$PROJECT"),
        (Path.home(), "$USER"),
        (project_alias, "$PROJECT_ALIAS"),
    )

    def diagnostic_record(path: Path, encoding: str, string_offset: int,
                          value: str, violation: tuple[int, str]) -> dict[str, object]:
        character_offset, candidate = violation
        codec = "ascii" if encoding == "ASCII" else "utf-16le"
        encoded_candidate = candidate.encode(codec)
        absolute_offset = string_offset + character_offset * (1 if encoding == "ASCII" else 2)
        redacted = candidate
        for root, replacement in redaction_roots:
            redacted = replace_dependency_root(redacted, root, replacement)
        redacted = re.sub(
            r"(?i)[a-z]:[/\\]users[/\\][^/\\\s]+", "$USER", redacted
        )
        redacted = re.sub(
            re.escape(PRIVATE_BUILD_DIRECTORY_NAME), "$PRIVATE_BUILD_NAME",
            redacted, flags=re.IGNORECASE,
        )
        if profile_name:
            redacted = re.sub(re.escape(profile_name), "$PROFILE", redacted, flags=re.IGNORECASE)
        maximum_characters = 240
        bounded = redacted[:maximum_characters]
        record: dict[str, object] = {
            "artifact": path.name,
            "candidate_bytes": len(encoded_candidate),
            "candidate_sha256": sha256(encoded_candidate),
            "candidate_truncated": len(redacted) > maximum_characters,
            "encoding": encoding,
            "offset": absolute_offset,
            "redacted_candidate": bounded,
            "schema": 1,
            "section": elf_section_for_file_offset(path, absolute_offset),
        }
        serialized = json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
        lowered_serialized = serialized.lower()
        for needle in text_needles:
            require(needle not in lowered_serialized,
                    "Private path diagnostic redaction retained known path material")
        if profile_name:
            require(profile_name not in lowered_serialized,
                    "Private path diagnostic redaction retained the profile name")
        return record

    for path in paths:
        require_plain_file(path, f"READY27 privacy-gated artifact {path.name}")
        payload = path.read_bytes()
        violation_record: dict[str, object] | None = None
        for match in re.finditer(rb"(?:(?<=\x00)|^)[\x20-\x7e]{4,}(?=\x00|$)", payload):
            value = match.group(0).decode("ascii")
            violation = first_disallowed_host_path(value)
            if violation is not None:
                violation_record = diagnostic_record(path, "ASCII", match.start(), value, violation)
                break
        if violation_record is None:
            for alignment in (0, 1):
                for match in re.finditer(
                    rb"(?:^|\x00\x00)((?:[\x20-\x7e]\x00){4,})(?=\x00\x00|$)",
                    payload[alignment:],
                ):
                    value = match.group(1).decode("utf-16le")
                    violation = first_disallowed_host_path(value)
                    if violation is not None:
                        violation_record = diagnostic_record(
                            path, "UTF-16LE", alignment + match.start(1), value, violation
                        )
                        break
                if violation_record is not None:
                    break
        require(
            violation_record is None,
            f"{path.name} contains a generic host-absolute drive or UNC path; "
            "PRIVATE_PATH_DIAGNOSTIC=" + json.dumps(
                violation_record, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            ),
        )
        lowered_payload = payload.lower()
        for needle in sorted(text_needles, key=len, reverse=True):
            ascii_needle = needle.encode("utf-8")
            utf16_needle = needle.encode("utf-16le")
            require(ascii_needle not in lowered_payload and utf16_needle not in lowered_payload,
                    f"{path.name} contains a private/local build path marker: {needle}")


def published_generation_inventory(destination_dir: Path) -> dict[str, object]:
    """Return a validated, content-bound inventory of the published allowlist."""
    require_plain_directory(destination_dir, "Artifact publish directory")
    require_tree_without_reparse_points(destination_dir, "Artifact publish directory")

    provenance_dir = destination_dir / LINKED_PROVENANCE_DIRECTORY
    private_dir = provenance_dir / PRIVATE_DEPENDENCY_DIRECTORY
    directory_modes: dict[str, int | None] = {}
    for relative in PUBLISHED_GENERATION_DIRECTORIES:
        path = destination_dir / relative
        key = relative.as_posix()
        if path_lexists(path):
            require_plain_directory(path, f"Published generation directory {key}")
            directory_modes[key] = stat.S_IMODE(os.lstat(path).st_mode)
        else:
            directory_modes[key] = None

    require(not path_lexists(private_dir) or path_lexists(provenance_dir),
            "Published private evidence directory exists without its provenance parent")
    if path_lexists(provenance_dir):
        allowed_root_files = {
            *(f"{name}{NORMALIZED_DEPENDENCY_SUFFIX}" for name in LINKED_DEPENDENCY_NAMES),
            EXCEPTION_BUILD_EVIDENCE_NAME,
            LINKED_GATE_LOG_NAME,
            LINKED_EVIDENCE_MANIFEST_NAME,
        }
        for child in provenance_dir.iterdir():
            if child == private_dir:
                require_plain_directory(child, "Published private evidence directory")
                continue
            require(child.is_file() and not is_reparse_point(child) and
                    child.name in allowed_root_files,
                    f"Unexpected linked provenance entry: {child}")
    if path_lexists(private_dir):
        allowed_private_files = {*LINKED_DEPENDENCY_NAMES, RAW_MAP_EVIDENCE_NAME}
        for child in private_dir.iterdir():
            require(child.is_file() and not is_reparse_point(child) and
                    child.name in allowed_private_files,
                    f"Unexpected private dependency evidence entry: {child}")

    files: dict[str, dict[str, int | str]] = {}
    for relative in PUBLISHED_GENERATION_FILES:
        path = destination_dir / relative
        if not path_lexists(path):
            continue
        key = relative.as_posix()
        require_plain_file(path, f"Published generation file {key}")
        before = os.lstat(path)
        digest = sha256_file(path)
        after = os.lstat(path)
        require(stat.S_ISREG(after.st_mode) and not is_reparse_point(path) and
                before.st_size == after.st_size and
                before.st_mtime_ns == after.st_mtime_ns and
                stat.S_IMODE(before.st_mode) == stat.S_IMODE(after.st_mode) and
                sha256_file(path) == digest,
                f"Published generation file changed while it was inventoried: {key}")
        files[key] = {
            "bytes": after.st_size,
            "mode": stat.S_IMODE(after.st_mode),
            "sha256": digest,
        }
    return {"directories": directory_modes, "files": files}


def capture_published_generation(destination_dir: Path,
                                 rollback_root: Path) -> dict[str, object]:
    """Copy the complete prior allowlist into the private build tree."""
    require_plain_directory(rollback_root.parent, "Published rollback parent")
    require(not path_lexists(rollback_root),
            f"Published rollback directory already exists: {rollback_root}")
    require(not rollback_root.resolve().is_relative_to(destination_dir.resolve()) and
            not destination_dir.resolve().is_relative_to(rollback_root.resolve()),
            "Published rollback directory must be outside the publish tree")
    inventory = published_generation_inventory(destination_dir)
    rollback_root.mkdir()
    require_plain_directory(rollback_root, "Published rollback directory")
    for relative in PUBLISHED_GENERATION_DIRECTORIES:
        backup_dir = rollback_root / relative
        backup_dir.mkdir()
        require_plain_directory(backup_dir, "Published rollback subdirectory")
    files = inventory["files"]
    require(isinstance(files, dict), "Published generation file inventory is invalid")
    for relative in PUBLISHED_GENERATION_FILES:
        key = relative.as_posix()
        record = files.get(key)
        if record is None:
            continue
        require(isinstance(record, dict), f"Published generation record is invalid: {key}")
        source = destination_dir / relative
        backup = rollback_root / relative
        atomic_publish_artifact(
            source,
            backup,
            int(record["mode"]),
            int(record["bytes"]),
            str(record["sha256"]),
        )
    return {"backup_root": rollback_root, "inventory": inventory}


def expected_published_generation_inventory(
        generation: dict[str, tuple[Path, int, int, str]]) -> dict[str, dict[str, int | str]]:
    expected_keys = {relative.as_posix() for relative in PUBLISHED_GENERATION_FILES}
    require(set(generation) == expected_keys,
            "New published generation does not cover the exact release allowlist")
    records: dict[str, dict[str, int | str]] = {}
    for key in sorted(expected_keys):
        source, mode, size, digest = generation[key]
        require_plain_file(source, f"New published generation source {key}")
        info = os.lstat(source)
        require(info.st_size == size and sha256_file(source) == digest,
                f"New published generation source changed: {key}")
        records[key] = {
            "bytes": size,
            "mode": stat.S_IMODE(mode),
            "sha256": digest,
        }
    return records


def require_generation_file_record(path: Path, expected: dict[str, int | str],
                                   description: str) -> None:
    require_plain_file(path, description)
    info = os.lstat(path)
    require(info.st_size == int(expected["bytes"]) and
            stat.S_IMODE(info.st_mode) == int(expected["mode"]) and
            sha256_file(path) == str(expected["sha256"]),
            f"{description} changed unexpectedly")


def restore_published_generation(destination_dir: Path, snapshot: dict[str, object],
                                 expected_new: dict[str, dict[str, int | str]]) -> None:
    """Restore every prior published file and prior directory topology exactly."""
    backup_root = snapshot.get("backup_root")
    prior = snapshot.get("inventory")
    require(isinstance(backup_root, Path) and isinstance(prior, dict),
            "Published rollback snapshot envelope is invalid")
    prior_files = prior.get("files")
    prior_directories = prior.get("directories")
    require(isinstance(prior_files, dict) and isinstance(prior_directories, dict),
            "Published rollback snapshot inventory is invalid")

    current = published_generation_inventory(destination_dir)
    current_files = current["files"]
    require(isinstance(current_files, dict), "Current published generation inventory is invalid")
    for key, record in current_files.items():
        require(key in expected_new, f"Rollback encountered an unowned release file: {key}")
        prior_record = prior_files.get(key)
        require(record == expected_new[key] or record == prior_record,
                f"Rollback refuses an externally changed release file: {key}")

    firmware_key = Path("firmware.bin").as_posix()
    firmware_path = destination_dir / firmware_key
    prior_firmware = prior_files.get(firmware_key)
    current_firmware = current_files.get(firmware_key)
    if current_firmware is not None and current_firmware != prior_firmware:
        require_generation_file_record(
            firmware_path, expected_new[firmware_key],
            "Rejected published firmware.bin",
        )
        firmware_path.unlink()
        require(not path_lexists(firmware_path),
                "Rejected published firmware.bin removal was incomplete")

    for relative in PUBLISHED_GENERATION_FILES:
        key = relative.as_posix()
        if key == firmware_key:
            continue
        path = destination_dir / relative
        prior_record = prior_files.get(key)
        current_record = current_files.get(key)
        if prior_record is None:
            if current_record is not None:
                require_generation_file_record(
                    path, expected_new[key], f"New rejected release file {key}"
                )
                path.unlink()
                require(not path_lexists(path),
                        f"Rejected release file removal was incomplete: {key}")
            continue
        if current_record != prior_record:
            backup = backup_root / relative
            require_generation_file_record(
                backup, prior_record, f"Published rollback backup {key}"
            )
            atomic_publish_artifact(
                backup,
                path,
                int(prior_record["mode"]),
                int(prior_record["bytes"]),
                str(prior_record["sha256"]),
            )

    for relative in reversed(PUBLISHED_GENERATION_DIRECTORIES):
        key = relative.as_posix()
        path = destination_dir / relative
        prior_mode = prior_directories.get(key)
        if prior_mode is None and path_lexists(path):
            require_plain_directory(path, f"New rejected release directory {key}")
            require(next(path.iterdir(), None) is None,
                    f"Refusing to remove nonempty rejected release directory: {key}")
            path.rmdir()
            require(not path_lexists(path),
                    f"Rejected release directory removal was incomplete: {key}")

    if prior_firmware is not None:
        if not path_lexists(firmware_path):
            backup = backup_root / firmware_key
            require_generation_file_record(
                backup, prior_firmware, "Published rollback backup firmware.bin"
            )
            atomic_publish_artifact(
                backup,
                firmware_path,
                int(prior_firmware["mode"]),
                int(prior_firmware["bytes"]),
                str(prior_firmware["sha256"]),
            )
        else:
            require_generation_file_record(
                firmware_path, prior_firmware, "Restored published firmware.bin"
            )

    restored = published_generation_inventory(destination_dir)
    require(restored == prior,
            "Published generation rollback did not restore the complete prior tree")


def execute_published_generation_transaction(
        destination_dir: Path, rollback_root: Path,
        generation: dict[str, tuple[Path, int, int, str]],
        publish_action) -> bytes:
    """Publish one complete generation or restore the prior generation exactly."""
    expected_new = expected_published_generation_inventory(generation)
    snapshot = capture_published_generation(destination_dir, rollback_root)
    try:
        result = publish_action()
        published = published_generation_inventory(destination_dir)
        published_files = published["files"]
        published_directories = published["directories"]
        require(published_files == expected_new and
                all(published_directories.get(relative.as_posix()) is not None
                    for relative in PUBLISHED_GENERATION_DIRECTORIES),
                "Published release tree does not match the complete new generation")
        require(isinstance(result, bytes), "Published generation action returned invalid evidence")
        return result
    except BaseException:
        try:
            restore_published_generation(destination_dir, snapshot, expected_new)
        except BaseException as rollback_error:
            raise BuildWrapperError(
                "Published generation failed and the complete prior-tree rollback also failed; "
                "release files require private inspection"
            ) from rollback_error
        raise


def self_test_published_generation_rollback(temporary_dir: Path) -> None:
    """Inject mid-publish/final failures and prove exact full-tree restoration."""
    fixture_root = temporary_dir / "published-generation-transaction"
    fixture_root.mkdir()

    def create_generation(name: str) -> dict[str, tuple[Path, int, int, str]]:
        source_root = fixture_root / name
        source_root.mkdir()
        generation: dict[str, tuple[Path, int, int, str]] = {}
        for index, relative in enumerate(PUBLISHED_GENERATION_FILES):
            source = source_root / relative
            source.parent.mkdir(parents=True, exist_ok=True)
            payload = f"{name}:{index}:{relative.as_posix()}\n".encode("ascii")
            source.write_bytes(payload)
            info = os.lstat(source)
            generation[relative.as_posix()] = (
                source, info.st_mode, info.st_size, sha256_file(source)
            )
        return generation

    def exact_fixture_tree(destination: Path) -> tuple[tuple[object, ...], ...]:
        rows: list[tuple[object, ...]] = []
        pending = [destination]
        while pending:
            directory = pending.pop()
            children = sorted(directory.iterdir(), key=lambda item: item.name.encode("utf-8"))
            for child in children:
                require(not is_reparse_point(child),
                        f"Published transaction fixture contains a reparse point: {child}")
                relative = child.relative_to(destination).as_posix()
                info = os.lstat(child)
                if child.is_dir():
                    rows.append(("D", relative, stat.S_IMODE(info.st_mode)))
                    pending.append(child)
                else:
                    require(stat.S_ISREG(info.st_mode),
                            f"Published transaction fixture contains a non-file: {child}")
                    rows.append((
                        "F", relative, stat.S_IMODE(info.st_mode),
                        info.st_size, sha256_file(child),
                    ))
        return tuple(sorted(rows, key=lambda row: str(row[1]).encode("utf-8")))

    def publish_fixture(destination: Path,
                        generation: dict[str, tuple[Path, int, int, str]],
                        omitted: frozenset[str] = frozenset(),
                        prefix_count: int | None = None) -> None:
        ensure_linked_provenance_directories(destination)
        selected = (
            PUBLISHED_GENERATION_FILES if prefix_count is None
            else PUBLISHED_GENERATION_FILES[:prefix_count]
        )
        require(prefix_count is None or 0 < prefix_count < len(PUBLISHED_GENERATION_FILES) - 1,
                "Published transaction failure prefix is not a strict companion-only prefix")
        for relative in selected:
            key = relative.as_posix()
            if key in omitted:
                continue
            source, mode, size, digest = generation[key]
            atomic_publish_artifact(source, destination / relative, mode, size, digest)

    old_generation = create_generation("old")
    new_generation = create_generation("new")
    prior_destination = fixture_root / "prior-destination"
    prior_destination.mkdir()
    prior_missing = frozenset({
        (Path(LINKED_PROVENANCE_DIRECTORY) / PRIVATE_DEPENDENCY_DIRECTORY /
         RAW_MAP_EVIDENCE_NAME).as_posix(),
        *(Path(name).as_posix() for name in
          (*QEMU_FLASH_ARTIFACT_NAMES, EFFECTIVE_SDKCONFIG_ARTIFACT_NAME)),
    })
    publish_fixture(prior_destination, old_generation, prior_missing)
    prior_inventory = published_generation_inventory(prior_destination)
    prior_tree = exact_fixture_tree(prior_destination)

    def fail_after_complete_replacement() -> bytes:
        publish_fixture(prior_destination, new_generation)
        raise BuildWrapperError("Injected final published-gate failure")

    try:
        execute_published_generation_transaction(
            prior_destination,
            fixture_root / "prior-rollback",
            new_generation,
            fail_after_complete_replacement,
        )
    except BuildWrapperError as error:
        require(str(error) == "Injected final published-gate failure",
                "Prior-tree rollback fixture failed for an unexpected reason")
    else:
        raise BuildWrapperError("Prior-tree rollback fixture did not inject failure")
    require(published_generation_inventory(prior_destination) == prior_inventory,
            "Failure injection did not restore the complete prior published tree")
    require(exact_fixture_tree(prior_destination) == prior_tree,
            "Final-gate failure injection left prior-tree residue")
    for relative in prior_missing:
        require(not path_lexists(prior_destination / relative),
                f"Failure injection retained a file absent from the prior tree: {relative}")

    def fail_mid_companion_replacement() -> bytes:
        publish_fixture(prior_destination, new_generation, prefix_count=4)
        raise BuildWrapperError("Injected mid-companion publish failure")

    try:
        execute_published_generation_transaction(
            prior_destination,
            fixture_root / "prior-mid-companion-rollback",
            new_generation,
            fail_mid_companion_replacement,
        )
    except BuildWrapperError as error:
        require(str(error) == "Injected mid-companion publish failure",
                "Prior-tree mid-companion rollback failed for an unexpected reason")
    else:
        raise BuildWrapperError("Prior-tree mid-companion rollback did not inject failure")
    require(published_generation_inventory(prior_destination) == prior_inventory and
            exact_fixture_tree(prior_destination) == prior_tree,
            "Mid-companion failure did not restore the exact prior published tree")

    first_destination = fixture_root / "first-publish-destination"
    first_destination.mkdir()
    empty_inventory = published_generation_inventory(first_destination)
    empty_tree = exact_fixture_tree(first_destination)

    def fail_first_publish_after_complete_replacement() -> bytes:
        publish_fixture(first_destination, new_generation)
        raise BuildWrapperError("Injected first-publish final-gate failure")

    try:
        execute_published_generation_transaction(
            first_destination,
            fixture_root / "first-publish-rollback",
            new_generation,
            fail_first_publish_after_complete_replacement,
        )
    except BuildWrapperError as error:
        require(str(error) == "Injected first-publish final-gate failure",
                "First-publish rollback fixture failed for an unexpected reason")
    else:
        raise BuildWrapperError("First-publish rollback fixture did not inject failure")
    require(published_generation_inventory(first_destination) == empty_inventory,
            "First-publish failure injection left release residue")
    require(exact_fixture_tree(first_destination) == empty_tree,
            "First-publish final-gate failure left temporary tree residue")
    require(not path_lexists(first_destination / LINKED_PROVENANCE_DIRECTORY),
            "First-publish failure injection left a provenance directory")

    def fail_first_publish_mid_companion() -> bytes:
        publish_fixture(first_destination, new_generation, prefix_count=4)
        raise BuildWrapperError("Injected first-publish mid-companion failure")

    try:
        execute_published_generation_transaction(
            first_destination,
            fixture_root / "first-publish-mid-companion-rollback",
            new_generation,
            fail_first_publish_mid_companion,
        )
    except BuildWrapperError as error:
        require(str(error) == "Injected first-publish mid-companion failure",
                "First-publish mid-companion rollback failed for an unexpected reason")
    else:
        raise BuildWrapperError(
            "First-publish mid-companion rollback did not inject failure"
        )
    require(published_generation_inventory(first_destination) == empty_inventory and
            exact_fixture_tree(first_destination) == empty_tree and
            not path_lexists(first_destination / LINKED_PROVENANCE_DIRECTORY),
            "First-publish mid-companion failure left release or temporary residue")


def ensure_linked_provenance_directories(destination_dir: Path) -> tuple[Path, Path]:
    require_tree_without_reparse_points(destination_dir)
    provenance_dir = destination_dir / LINKED_PROVENANCE_DIRECTORY
    if path_lexists(provenance_dir):
        require_plain_directory(provenance_dir, "Linked provenance directory")
    else:
        provenance_dir.mkdir()
        require_plain_directory(provenance_dir, "New linked provenance directory")

    private_dir = provenance_dir / PRIVATE_DEPENDENCY_DIRECTORY
    if path_lexists(private_dir):
        require_plain_directory(private_dir, "Private dependency directory")
    else:
        private_dir.mkdir()
        require_plain_directory(private_dir, "New private dependency directory")

    allowed_root_files = {
        *(f"{name}{NORMALIZED_DEPENDENCY_SUFFIX}" for name in LINKED_DEPENDENCY_NAMES),
        EXCEPTION_BUILD_EVIDENCE_NAME,
        LINKED_GATE_LOG_NAME,
        LINKED_EVIDENCE_MANIFEST_NAME,
    }
    for child in provenance_dir.iterdir():
        if child == private_dir:
            continue
        require(child.is_file() and not is_reparse_point(child) and child.name in allowed_root_files,
                f"Unexpected linked provenance entry: {child}")
    allowed_private_files = {*LINKED_DEPENDENCY_NAMES, RAW_MAP_EVIDENCE_NAME}
    for child in private_dir.iterdir():
        require(child.is_file() and not is_reparse_point(child) and child.name in allowed_private_files,
                f"Unexpected private dependency evidence entry: {child}")
    for name in LINKED_DEPENDENCY_NAMES:
        matches = list(destination_dir.rglob(name))
        require(len(matches) <= 1 and (not matches or matches[0].parent == private_dir),
                f"Duplicate or misplaced published dependency evidence: {name}")
    return provenance_dir, private_dir


def write_fresh_evidence(path: Path, data: bytes, started_ns: int) -> tuple[Path, int, int, str]:
    require_plain_directory(path.parent, "Private linked-evidence directory")
    write_exclusive(path, data)
    mode, size, digest = validate_fresh_artifact(path, started_ns)
    return path, mode, size, digest


def run_artifact_bound_linked_gate(build_dir: Path, packages_dir: Path,
                                   libdeps_dir: Path,
                                   manifest_path: Path, manifest_sha256: str,
                                   label: str) -> bytes:
    verifier = PROJECT_ROOT / "scripts" / "verify_pocket_sync_security.py"
    require_plain_file(verifier, "Pocket Sync linked-evidence verifier")
    result = subprocess.run(
        [
            sys.executable, "-B", str(verifier),
            "--project-root", str(PROJECT_ROOT),
            "--packages-dir", str(packages_dir),
            "--libdeps-dir", str(libdeps_dir),
            "--build-dir", str(build_dir),
            "--evidence-manifest", str(manifest_path),
        ],
        cwd=PROJECT_ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise BuildWrapperError(f"{label} Pocket Sync linked-evidence gate failed: {detail}")
    require(not result.stderr, f"{label} Pocket Sync linked-evidence gate wrote to stderr")
    expected_lines = [
        "POCKET_SYNC_SOURCE_SECURITY_OK",
        f"POCKET_SYNC_EVIDENCE_MANIFEST_OK {manifest_sha256}",
        "POCKET_SYNC_LINKED_SECURITY_OK",
    ]
    require(result.stdout.splitlines() == expected_lines,
            f"{label} Pocket Sync linked-evidence transcript was not exact")
    return result.stdout.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def publish_verified_artifacts(private_build_dir: Path, environment: str, started_ns: int,
                               core_dir: Path, project_alias: Path,
                               project_cache_snapshot: dict[str, int | str],
                               source_snapshot: dict[str, int | str | dict[str, int | str]]) -> None:
    source_dir = private_build_dir / environment
    require_plain_directory(source_dir, "PlatformIO environment build directory")
    packages_dir = ready27_packages_dir(core_dir)
    require(packages_dir is not None, "Pocket Sync requires the private READY27 package directory")
    (_webserver_parser_target, webserver_parser_original, _webserver_parser_mode,
     webserver_parser_patch) = verify_webserver_parser_source(packages_dir)
    libdeps_dir = core_dir / "libdeps"
    require_plain_directory(libdeps_dir, "Pocket Sync private READY27 dependency seed")
    require(libdeps_dir.resolve().parent == core_dir.resolve(),
            "Pocket Sync private dependency seed escaped its READY27 core")

    raw_map_path = source_dir / "firmware.map"
    raw_map_mode, raw_map_size, raw_map_digest = validate_fresh_artifact(raw_map_path, started_ns)
    raw_map_bytes = raw_map_path.read_bytes()
    require(len(raw_map_bytes) == raw_map_size and sha256(raw_map_bytes) == raw_map_digest,
            "Raw linker map changed while preparing normalized evidence")
    normalized_map = normalize_linker_map_bytes(
        raw_map_path, source_dir, core_dir, packages_dir, project_alias
    )
    virtual_sdk_provenance, virtual_sdk_candidates = build_virtual_sdk_provenance(
        normalized_map, packages_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE
    )
    atomic_replace_bytes(raw_map_path, normalized_map, raw_map_mode)
    require(raw_map_path.read_bytes() == normalized_map,
            "Atomic normalized linker-map replacement changed bytes")

    verified: dict[str, tuple[Path, int, int, str]] = {}
    fresh_build_artifacts = (
        "firmware.elf",
        "firmware.map",
        "firmware.bin",
        "bootloader.bin",
        "partitions.bin",
    )
    for name in fresh_build_artifacts:
        source = source_dir / name
        maximum = MAX_OTA_APP_BYTES if name == "firmware.bin" else None
        mode, size, digest = validate_fresh_artifact(source, started_ns, maximum)
        verified[name] = (source, mode, size, digest)

    sdkconfig_relative = Path(
        "framework-arduinoespressif32-libs/esp32c3/dio_qspi/include/sdkconfig.h"
    )
    sdkconfig = packages_dir / sdkconfig_relative
    package_companions = {
        "boot_app0.bin": validate_stable_artifact(
            packages_dir / BOOT_APP0_PACKAGE_RELATIVE,
            "Pinned Arduino OTA-data initializer",
            expected_size=BOOT_APP0_BYTES,
            expected_digest=EXPECTED_BOOT_APP0_SHA256,
        ),
        EFFECTIVE_SDKCONFIG_ARTIFACT_NAME: validate_stable_artifact(
            sdkconfig,
            "Effective ESP32-C3 sdkconfig evidence",
        ),
    }
    # The verifier consumes one self-contained build directory. Copy the two
    # package-owned inputs into that private directory before hashing the
    # manifest, then publish those exact staged bytes with the fresh outputs.
    for name, (source, mode, size, digest) in package_companions.items():
        staged = source_dir / name
        require(not path_lexists(staged),
                f"PlatformIO unexpectedly produced package companion {name}")
        atomic_publish_artifact(source, staged, mode, size, digest)
        staged_mode, staged_size, staged_digest = validate_fresh_artifact(
            staged, started_ns
        )
        require(staged_size == size and staged_digest == digest,
                f"Private same-build companion staging changed {name}")
        verified[name] = (staged, staged_mode, staged_size, staged_digest)

    require_debug_stripped_elf(verified["firmware.elf"][0])
    require_private_artifact_paths_absent(
        [verified[name][0] for name in MANIFEST_ARTIFACT_NAMES],
        private_build_dir, core_dir, packages_dir, project_alias,
        virtual_sdk_candidates, VIRTUAL_SDK_REBUILT_PROBE_STATE,
    )
    # Run the wrapper's bounded/redacted diagnostic scan before the independent
    # linked verifier. Both inspect the same immutable private artifact bytes;
    # a rejection is therefore actionable without publishing or retaining the
    # private build tree.
    verify_pocket_sync_build_security(source_dir, core_dir)
    verify_x3_resource_budget_linked(
        verified["firmware.bin"][0], verified["firmware.map"][0], packages_dir
    )

    dependencies = {
        name: find_fresh_dependency(source_dir, name, started_ns)
        for name in LINKED_DEPENDENCY_NAMES
    }
    normalized_dependencies = {
        name: normalize_dependency_bytes(
            details[0], source_dir, packages_dir, libdeps_dir, project_alias
        )
        for name, details in dependencies.items()
    }
    normalized_server = normalized_dependencies["NimBLEServer.cpp.d"].decode("utf-8")
    require(
        "$PACKAGES/framework-arduinoespressif32-libs/esp32c3/dio_qspi/include/sdkconfig.h"
        in normalized_server,
        "NimBLE normalized dependency evidence lacks pinned SDK provenance",
    )
    normalized_pocket = normalized_dependencies["PocketSyncBleServer.cpp.d"].decode("utf-8")
    require("$LIBDEPS/default/NimBLE-Arduino/src/nimconfig.h" in normalized_pocket,
            "Pocket Sync normalized dependency evidence lacks private NimBLE provenance")
    require(".pio/libdeps/" not in normalized_pocket.replace("\\", "/").lower(),
            "Pocket Sync normalized dependency evidence references the shared project cache")

    # Build every publishable companion inside the private tree and run the
    # artifact-bound gate there before touching the published installable BIN.
    private_provenance_dir = source_dir / LINKED_PROVENANCE_DIRECTORY
    require(not path_lexists(private_provenance_dir),
            "Private build unexpectedly contains a linked provenance directory")
    private_provenance_dir.mkdir()
    require_plain_directory(private_provenance_dir, "Private linked provenance directory")
    private_private_dir = private_provenance_dir / PRIVATE_DEPENDENCY_DIRECTORY
    private_private_dir.mkdir()
    require_plain_directory(private_private_dir, "Private raw linked provenance directory")
    private_raw_map = write_fresh_evidence(
        private_private_dir / RAW_MAP_EVIDENCE_NAME, raw_map_bytes, started_ns
    )
    exception_evidence = build_exception_evidence(
        source_dir, packages_dir, libdeps_dir, project_alias, started_ns
    )
    exception_evidence_bytes = (
        json.dumps(exception_evidence, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    private_exception_evidence = write_fresh_evidence(
        private_provenance_dir / EXCEPTION_BUILD_EVIDENCE_NAME,
        exception_evidence_bytes,
        started_ns,
    )

    dependency_manifest: dict[str, dict[str, dict[str, int | str]]] = {}
    private_normalized: dict[str, tuple[Path, int, int, str]] = {}
    for name in LINKED_DEPENDENCY_NAMES:
        _raw_source, _raw_mode, raw_size, raw_digest = dependencies[name]
        normalized_path = private_provenance_dir / f"{name}{NORMALIZED_DEPENDENCY_SUFFIX}"
        normalized_record = write_fresh_evidence(
            normalized_path, normalized_dependencies[name], started_ns
        )
        private_normalized[name] = normalized_record
        dependency_manifest[name] = {
            "raw": {"bytes": raw_size, "sha256": raw_digest},
            "normalized": {
                "bytes": normalized_record[2],
                "sha256": normalized_record[3],
            },
        }

    exception_sdkconfig = generated_exception_sdkconfig(sdkconfig)
    exception_sections = exception_elf_sections(verified["firmware.elf"][0])
    exception_symbols = linked_exception_symbols(verified["firmware.elf"][0], packages_dir)
    nimconfig_relative = Path("default/NimBLE-Arduino/src/nimconfig.h")
    nimconfig_logical = "$LIBDEPS/" + nimconfig_relative.as_posix()
    nimconfig = libdeps_dir / nimconfig_relative
    require_plain_file(nimconfig, "Effective NimBLE configuration evidence")
    verifier = PROJECT_ROOT / "scripts" / "verify_pocket_sync_security.py"
    require_plain_file(verifier, "Pocket Sync linked-evidence verifier")
    virtual_sdk_provenance["raw_map"] = {
        "bytes": raw_map_size,
        "sha256": raw_map_digest,
    }
    manifest = {
        "schema": 4,
        "artifacts": {
            name: {"bytes": verified[name][2], "sha256": verified[name][3]}
            for name in MANIFEST_ARTIFACT_NAMES
        },
        "dependencies": dependency_manifest,
        "exceptions": {
            "build_evidence": {
                "bytes": private_exception_evidence[2],
                "path": (
                    Path(LINKED_PROVENANCE_DIRECTORY) / EXCEPTION_BUILD_EVIDENCE_NAME
                ).as_posix(),
                "sha256": private_exception_evidence[3],
            },
            "elf_sections": exception_sections,
            "generated_sdkconfig": exception_sdkconfig,
            "linked_symbols": exception_symbols,
        },
        "identity": {
            "build_id": READY_BUILD_ID,
            "release_label": READY_RELEASE_LABEL,
            "version": READY_VERSION,
        },
        "sdkconfig": {
            "artifact": EFFECTIVE_SDKCONFIG_ARTIFACT_NAME,
            "path": sdkconfig_relative.as_posix(),
            "bytes": sdkconfig.stat().st_size,
            "sha256": sha256_file(sdkconfig),
        },
        "nimconfig": {
            "path": nimconfig_logical,
            "bytes": nimconfig.stat().st_size,
            "sha256": sha256_file(nimconfig),
        },
        "raw_map": {
            "bytes": raw_map_size,
            "sha256": raw_map_digest,
        },
        "reproducibility": {
            "artifact_privacy": {
                "marker_classes": list(ARTIFACT_PRIVACY_MARKER_CLASSES),
                "policy": ARTIFACT_PRIVACY_POLICY,
                "scanner": ARTIFACT_PRIVACY_SCANNER,
                "semantic_encodings": ["ASCII", "UTF-16LE"],
                "uri_schemes": list(ARTIFACT_PRIVACY_URI_SCHEMES),
            },
            "build_cache": {
                "directory": PRIVATE_BUILD_CACHE_DIRECTORY_NAME,
                "policy": "fresh-private-per-run",
                "project_cache": project_cache_snapshot,
            },
            "elf_debug": {
                "link_flag": ELF_DEBUG_STRIP_LINK_FLAG,
                "stripped": True,
                "symbol_tables_retained": True,
            },
            "recovery_reference": verify_public_recovery_reference(),
            "virtual_sdk_paths": virtual_sdk_provenance,
            "webserver_parser": {
                "checker": {
                    "bytes": EXPECTED_WEB_SERVER_PARSER_CHECKER_BYTES,
                    "passes": EXPECTED_WEB_SERVER_PARSER_BEHAVIOR_PASSES,
                    "path": WEB_SERVER_PARSER_CHECKER_RELATIVE.as_posix(),
                    "sha256": EXPECTED_WEB_SERVER_PARSER_CHECKER_SHA256,
                },
                "limits": dict(WEB_SERVER_PARSER_LIMITS),
                "original": {
                    "bytes": len(webserver_parser_original),
                    "sha256": sha256(webserver_parser_original),
                },
                "patch": {
                    "bytes": len(webserver_parser_patch),
                    "path": WEB_SERVER_PARSER_PATCH_RELATIVE.as_posix(),
                    "sha256": sha256(webserver_parser_patch),
                },
                "policy": WEB_SERVER_PARSER_POLICY,
                "target": WEB_SERVER_PARSER_RELATIVE.as_posix(),
                "transient": True,
            },
            "virtual_project_paths": {
                "prefix": VIRTUAL_PROJECT_PATH_PREFIX,
                "roots": list(VIRTUAL_PROJECT_PATH_ROOTS),
                "source_probe": {
                    "bytes": EXPECTED_MINIZ_SOURCE_BYTES,
                    "path": MINIZ_SOURCE_RELATIVE.as_posix(),
                    "sha256": EXPECTED_MINIZ_SOURCE_SHA256,
                    "virtual_path": EXPECTED_MINIZ_VIRTUAL_SOURCE_PATH,
                },
            },
            "path_map_targets": list(REPRODUCIBLE_PATH_MAP_TARGETS),
            "private_build_directory": PRIVATE_BUILD_DIRECTORY_NAME,
            "project_alias": "X:/",
            "source_date_epoch": REPRODUCIBLE_SOURCE_DATE_EPOCH,
            "timezone": REPRODUCIBLE_TIMEZONE,
        },
        "selection": {
            "NimBLEServer.cpp.d": (
                "$PACKAGES/framework-arduinoespressif32-libs/esp32c3/dio_qspi/include/sdkconfig.h"
            ),
            "PocketSyncBleServer.cpp.d": nimconfig_logical,
        },
        "source": source_snapshot,
        "verifier": {
            "bytes": verifier.stat().st_size,
            "sha256": sha256_file(verifier),
        },
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    private_manifest_path = private_provenance_dir / LINKED_EVIDENCE_MANIFEST_NAME
    private_manifest = write_fresh_evidence(
        private_manifest_path, manifest_bytes, started_ns
    )
    transcript = run_artifact_bound_linked_gate(
        source_dir, packages_dir, libdeps_dir,
        private_manifest_path, private_manifest[3], "Private"
    )
    private_log_path = private_provenance_dir / LINKED_GATE_LOG_NAME
    private_log = write_fresh_evidence(private_log_path, transcript, started_ns)

    destination_dir = ensure_publish_directory(environment)
    provenance_dir = destination_dir / LINKED_PROVENANCE_DIRECTORY
    private_dir = provenance_dir / PRIVATE_DEPENDENCY_DIRECTORY
    manifest_path = provenance_dir / LINKED_EVIDENCE_MANIFEST_NAME
    log_path = provenance_dir / LINKED_GATE_LOG_NAME
    firmware_destination = destination_dir / "firmware.bin"
    firmware_source, firmware_mode, firmware_size, firmware_digest = verified["firmware.bin"]

    generation: dict[str, tuple[Path, int, int, str]] = {
        name: verified[name] for name in MANIFEST_ARTIFACT_NAMES
    }
    generation.update({
        (Path(LINKED_PROVENANCE_DIRECTORY) / PRIVATE_DEPENDENCY_DIRECTORY /
         RAW_MAP_EVIDENCE_NAME).as_posix(): private_raw_map,
        (Path(LINKED_PROVENANCE_DIRECTORY) /
         LINKED_EVIDENCE_MANIFEST_NAME).as_posix(): private_manifest,
        (Path(LINKED_PROVENANCE_DIRECTORY) /
         EXCEPTION_BUILD_EVIDENCE_NAME).as_posix(): private_exception_evidence,
        (Path(LINKED_PROVENANCE_DIRECTORY) / LINKED_GATE_LOG_NAME).as_posix(): private_log,
    })
    # Raw dependency attestations and the raw linker map are private local
    # evidence, but remain part of the locally published generation and its
    # all-or-nothing rollback transaction.
    for name in LINKED_DEPENDENCY_NAMES:
        generation[(Path(LINKED_PROVENANCE_DIRECTORY) / PRIVATE_DEPENDENCY_DIRECTORY /
                    name).as_posix()] = dependencies[name]
        generation[(Path(LINKED_PROVENANCE_DIRECTORY) /
                    f"{name}{NORMALIZED_DEPENDENCY_SUFFIX}").as_posix()] = private_normalized[name]

    def publish_complete_generation() -> bytes:
        published_provenance_dir, published_private_dir = \
            ensure_linked_provenance_directories(destination_dir)

        # Publish every companion first. firmware.bin is the activation marker
        # and is replaced only after the complete evidence set is durable.
        for name in ("firmware.elf", "firmware.map"):
            source, mode, size, digest = verified[name]
            atomic_publish_artifact(
                source, destination_dir / name, mode, size, digest
            )
        for name in (*QEMU_FLASH_ARTIFACT_NAMES, EFFECTIVE_SDKCONFIG_ARTIFACT_NAME):
            source, mode, size, digest = verified[name]
            atomic_publish_artifact(
                source, destination_dir / name, mode, size, digest
            )
        for name in LINKED_DEPENDENCY_NAMES:
            source, mode, size, digest = dependencies[name]
            atomic_publish_artifact(
                source, published_private_dir / name, mode, size, digest
            )
            normalized_source, normalized_mode, normalized_size, normalized_digest = \
                private_normalized[name]
            atomic_publish_artifact(
                normalized_source,
                published_provenance_dir / f"{name}{NORMALIZED_DEPENDENCY_SUFFIX}",
                normalized_mode,
                normalized_size,
                normalized_digest,
            )
        atomic_publish_artifact(
            private_raw_map[0], published_private_dir / RAW_MAP_EVIDENCE_NAME,
            private_raw_map[1], private_raw_map[2], private_raw_map[3],
        )
        atomic_publish_artifact(
            private_exception_evidence[0],
            published_provenance_dir / EXCEPTION_BUILD_EVIDENCE_NAME,
            private_exception_evidence[1],
            private_exception_evidence[2],
            private_exception_evidence[3],
        )
        atomic_publish_artifact(
            private_manifest[0], manifest_path,
            private_manifest[1], private_manifest[2], private_manifest[3],
        )
        atomic_publish_artifact(
            private_log[0], log_path,
            private_log[1], private_log[2], private_log[3],
        )
        atomic_publish_artifact(
            firmware_source,
            firmware_destination,
            firmware_mode,
            firmware_size,
            firmware_digest,
        )
        published_gate_transcript = run_artifact_bound_linked_gate(
            destination_dir, packages_dir, libdeps_dir,
            manifest_path, private_manifest[3], "Published"
        )
        require(published_gate_transcript == transcript,
                "Published linked-gate transcript differs from the private preflight")
        return published_gate_transcript

    published_transcript = execute_published_generation_transaction(
        destination_dir,
        source_dir / PUBLISH_ROLLBACK_DIRECTORY_NAME,
        generation,
        publish_complete_generation,
    )
    require(published_transcript == transcript,
            "Published generation transaction returned a different linked transcript")

    for name in ("firmware.elf", "firmware.map"):
        _source, _mode, size, digest = verified[name]
        destination = destination_dir / name
        print(f"Published XTINCT audit artifact: {destination}")
        print(f"Size: {size} bytes")
        print(f"SHA-256: {digest}")

    for name in (*QEMU_FLASH_ARTIFACT_NAMES, EFFECTIVE_SDKCONFIG_ARTIFACT_NAME):
        _source, _mode, size, digest = verified[name]
        destination = destination_dir / name
        print(f"Published XTINCT same-build QEMU companion: {destination}")
        print(f"Size: {size} bytes")
        print(f"SHA-256: {digest}")

    print(f"Published XTINCT installable artifact: {firmware_destination}")
    print(f"Size: {firmware_size} bytes")
    print(f"SHA-256: {firmware_digest}")
    print(f"Published XTINCT linked evidence manifest: {manifest_path}")
    print(f"Size: {private_manifest[2]} bytes")
    print(f"SHA-256: {private_manifest[3]}")
    print(f"Published XTINCT linked gate transcript: {log_path}")
    print(f"Size: {private_log[2]} bytes")
    print(f"SHA-256: {private_log[3]}")


def self_test(core_dir: Path) -> int:
    verify_public_recovery_reference()
    verify_crash_secret_policy()
    verify_file_transfer_security()
    verify_i18n_security()
    verify_x3_resource_budget_source()
    verify_pocket_sync_source_security(core_dir)
    packages_dir = ready27_packages_dir(core_dir)
    require(packages_dir is not None, "Self-test requires the private READY27 package directory")
    platform_dir, _manifest, _piopm, target = platform_paths(core_dir)
    lock_path = platform_dir / ".xtinct-build-wrapper.lock"
    with WindowsByteLock(lock_path):
        try:
            with WindowsByteLock(lock_path):
                raise BuildWrapperError("Concurrent lock unexpectedly succeeded")
        except BuildWrapperError as error:
            require("Another XTINCT wrapper holds" in str(error), "Concurrent lock failed for an unexpected reason")

        require(target.exists(), f"pioarduino source is missing: {target}")
        recover_interrupted_patch(target, target.stat().st_mode)
        idf_builder_target = idf_builder_script_path(core_dir)
        recover_interrupted_idf_builder_patch(idf_builder_target, idf_builder_target.stat().st_mode)
        webserver_parser_target, _webserver_patch_path = webserver_parser_paths(packages_dir)
        recover_interrupted_webserver_parser_patch(
            webserver_parser_target, webserver_parser_target.stat().st_mode
        )
        target, original, mode = verify_platform(core_dir)
        idf_builder_target, idf_builder_bytes = verify_idf_builder_script(core_dir)
        idf_builder_mode = idf_builder_target.stat().st_mode
        idf_builder_patched = patch_idf_builder_source(idf_builder_bytes)
        (webserver_parser_target, webserver_parser_bytes, webserver_parser_mode,
         webserver_parser_patched) = verify_webserver_parser_source(packages_dir)
        corrupted_builder = bytearray(idf_builder_bytes)
        corrupted_builder[-1] ^= 0x01
        try:
            verify_idf_builder_bytes(bytes(corrupted_builder))
        except BuildWrapperError as error:
            require("builder hash" in str(error), "ESP-IDF builder drift failed for an unexpected reason")
        else:
            raise BuildWrapperError("ESP-IDF builder hash gate accepted corrupted bytes")
        patched = patch_source(original)
        require(sha256(patched) == EXPECTED_PATCHED_SHA256, "In-memory transient patch test failed")
        require(CERTIFI_ENV_BLOCK not in patched, "Penv certifi SSL override survived the transient patch")
        require(STRICT_CERTIFI_ENV_BLOCK in patched, "Strict nested certificate block is missing")
        with tempfile.TemporaryDirectory(prefix="xtinct-wrapper-selftest-") as temporary_name:
            temporary_dir = Path(temporary_name)

            penv_restore_fixture = temporary_dir / "penv-restore.py"
            penv_restore_fixture.write_bytes(original)
            create_backup(penv_restore_fixture, original)
            atomic_replace_bytes(penv_restore_fixture, patched, mode)
            require(penv_restore_fixture.read_bytes() == patched, "Atomic penv patch self-test failed")

            idf_restore_fixture = temporary_dir / "espidf-restore.py"
            idf_restore_fixture.write_bytes(idf_builder_bytes)
            create_idf_builder_backup(idf_restore_fixture, idf_builder_bytes)
            atomic_replace_bytes(idf_restore_fixture, idf_builder_patched, idf_builder_mode)
            require(
                idf_restore_fixture.read_bytes() == idf_builder_patched,
                "Atomic ESP-IDF builder patch self-test failed",
            )
            webserver_restore_fixture = temporary_dir / "Parsing.cpp"
            webserver_restore_fixture.write_bytes(webserver_parser_bytes)
            create_webserver_parser_backup(
                webserver_restore_fixture, webserver_parser_bytes
            )
            atomic_replace_bytes(
                webserver_restore_fixture, webserver_parser_patched,
                webserver_parser_mode,
            )
            require(webserver_restore_fixture.read_bytes() == webserver_parser_patched,
                    "Atomic WebServer parser patch self-test failed")
            restore_toolchain_patches(
                penv_restore_fixture,
                original,
                mode,
                True,
                idf_restore_fixture,
                idf_builder_bytes,
                idf_builder_mode,
                True,
                webserver_restore_fixture,
                webserver_parser_bytes,
                webserver_parser_mode,
                True,
            )
            require(penv_restore_fixture.read_bytes() == original, "Atomic penv restore self-test failed")
            require(
                not any(path_lexists(path) for path in backup_paths(penv_restore_fixture)),
                "Successful penv restore self-test left backup state",
            )
            require(
                idf_restore_fixture.read_bytes() == idf_builder_bytes,
                "Atomic ESP-IDF builder restore self-test failed",
            )
            require(
                not any(path_lexists(path) for path in backup_paths(idf_restore_fixture)),
                "Successful ESP-IDF builder restore self-test left backup state",
            )
            require(webserver_restore_fixture.read_bytes() == webserver_parser_bytes and
                    not any(path_lexists(path) for path in backup_paths(webserver_restore_fixture)),
                    "Successful WebServer parser restore self-test left changed or backup state")

            dual_penv_fixture = temporary_dir / "penv-dual-restore.py"
            dual_penv_fixture.write_bytes(original)
            create_backup(dual_penv_fixture, original)
            atomic_replace_bytes(dual_penv_fixture, patched, mode)
            dual_idf_fixture = temporary_dir / "espidf-dual-restore.py"
            dual_idf_fixture.write_bytes(idf_builder_bytes)
            create_idf_builder_backup(dual_idf_fixture, idf_builder_bytes)
            atomic_replace_bytes(dual_idf_fixture, idf_builder_patched, idf_builder_mode)
            dual_webserver_fixture = temporary_dir / "dual-Parsing.cpp"
            dual_webserver_fixture.write_bytes(webserver_parser_bytes)
            create_webserver_parser_backup(dual_webserver_fixture, webserver_parser_bytes)
            atomic_replace_bytes(
                dual_webserver_fixture, webserver_parser_patched, webserver_parser_mode
            )
            dual_idf_backup, _dual_idf_digest = backup_paths(dual_idf_fixture)
            dual_idf_backup.write_bytes(b"CORRUPTED")
            try:
                restore_toolchain_patches(
                    dual_penv_fixture,
                    original,
                    mode,
                    True,
                    dual_idf_fixture,
                    idf_builder_bytes,
                    idf_builder_mode,
                    True,
                    dual_webserver_fixture,
                    webserver_parser_bytes,
                    webserver_parser_mode,
                    True,
                )
            except BuildWrapperError as error:
                require(
                    "after all restore attempts" in str(error),
                    "Dual restore failure self-test failed for an unexpected reason",
                )
            else:
                raise BuildWrapperError("Dual restore helper accepted a corrupted ESP-IDF backup")
            require(
                dual_penv_fixture.read_bytes() == original,
                "Penv restore was not attempted after ESP-IDF builder restore failed",
            )
            require(
                not any(path_lexists(path) for path in backup_paths(dual_penv_fixture)),
                "Penv restore after ESP-IDF failure left backup state",
            )
            require(dual_webserver_fixture.read_bytes() == webserver_parser_bytes and
                    not any(path_lexists(path) for path in backup_paths(dual_webserver_fixture)),
                    "WebServer parser restore was not completed after ESP-IDF restore failed")

            parser_failure_penv = temporary_dir / "penv-parser-failure.py"
            parser_failure_penv.write_bytes(original)
            create_backup(parser_failure_penv, original)
            atomic_replace_bytes(parser_failure_penv, patched, mode)
            parser_failure_idf = temporary_dir / "espidf-parser-failure.py"
            parser_failure_idf.write_bytes(idf_builder_bytes)
            create_idf_builder_backup(parser_failure_idf, idf_builder_bytes)
            atomic_replace_bytes(
                parser_failure_idf, idf_builder_patched, idf_builder_mode
            )
            parser_failure_webserver = temporary_dir / "parser-failure-Parsing.cpp"
            parser_failure_webserver.write_bytes(webserver_parser_bytes)
            create_webserver_parser_backup(
                parser_failure_webserver, webserver_parser_bytes
            )
            atomic_replace_bytes(
                parser_failure_webserver, webserver_parser_patched,
                webserver_parser_mode,
            )
            parser_failure_backup, _parser_failure_digest = backup_paths(
                parser_failure_webserver
            )
            parser_failure_backup.write_bytes(b"CORRUPTED")
            try:
                restore_toolchain_patches(
                    parser_failure_penv,
                    original,
                    mode,
                    True,
                    parser_failure_idf,
                    idf_builder_bytes,
                    idf_builder_mode,
                    True,
                    parser_failure_webserver,
                    webserver_parser_bytes,
                    webserver_parser_mode,
                    True,
                )
            except BuildWrapperError as error:
                require(
                    "after all restore attempts" in str(error),
                    "WebServer restore failure self-test failed for an unexpected reason",
                )
            else:
                raise BuildWrapperError(
                    "Restore helper accepted a corrupted WebServer parser backup"
                )
            require(
                parser_failure_penv.read_bytes() == original and
                not any(path_lexists(path) for path in backup_paths(parser_failure_penv)),
                "Penv restore was not completed after WebServer parser restore failed",
            )
            require(
                parser_failure_idf.read_bytes() == idf_builder_bytes and
                not any(path_lexists(path) for path in backup_paths(parser_failure_idf)),
                "ESP-IDF builder restore was not completed after WebServer parser restore failed",
            )

            failure_penv = temporary_dir / "penv-injected-failure.py"
            failure_penv.write_bytes(original)
            create_backup(failure_penv, original)
            atomic_replace_bytes(failure_penv, patched, mode)
            failure_idf = temporary_dir / "espidf-injected-failure.py"
            failure_idf.write_bytes(idf_builder_bytes)
            create_idf_builder_backup(failure_idf, idf_builder_bytes)
            atomic_replace_bytes(failure_idf, idf_builder_patched, idf_builder_mode)
            failure_webserver = temporary_dir / "injected-failure-Parsing.cpp"
            failure_webserver.write_bytes(webserver_parser_bytes)
            create_webserver_parser_backup(failure_webserver, webserver_parser_bytes)
            atomic_replace_bytes(
                failure_webserver, webserver_parser_patched, webserver_parser_mode
            )
            injected_failure_seen = False
            try:
                try:
                    raise KeyboardInterrupt("Injected compile failure")
                finally:
                    restore_toolchain_patches(
                        failure_penv,
                        original,
                        mode,
                        True,
                        failure_idf,
                        idf_builder_bytes,
                        idf_builder_mode,
                        True,
                        failure_webserver,
                        webserver_parser_bytes,
                        webserver_parser_mode,
                        True,
                    )
            except KeyboardInterrupt as error:
                injected_failure_seen = str(error) == "Injected compile failure"
            require(injected_failure_seen,
                    "Injected compile BaseException was not preserved through restoration")
            for fixture, expected, label in (
                (failure_penv, original, "penv"),
                (failure_idf, idf_builder_bytes, "ESP-IDF builder"),
                (failure_webserver, webserver_parser_bytes, "WebServer parser"),
            ):
                require(
                    fixture.read_bytes() == expected and
                    not any(path_lexists(path) for path in backup_paths(fixture)),
                    f"Injected compile failure did not restore exact {label} state",
                )

            penv_recovery_fixture = temporary_dir / "penv-recovery.py"
            penv_recovery_fixture.write_bytes(original)
            create_backup(penv_recovery_fixture, original)
            atomic_replace_bytes(penv_recovery_fixture, patched, mode)
            recover_interrupted_patch(penv_recovery_fixture, mode)
            require(
                penv_recovery_fixture.read_bytes() == original,
                "Interrupted penv patch recovery self-test changed original bytes",
            )
            require(
                not any(path_lexists(path) for path in backup_paths(penv_recovery_fixture)),
                "Interrupted penv recovery self-test left backup state",
            )

            idf_recovery_fixture = temporary_dir / "espidf-recovery.py"
            idf_recovery_fixture.write_bytes(idf_builder_bytes)
            create_idf_builder_backup(idf_recovery_fixture, idf_builder_bytes)
            atomic_replace_bytes(idf_recovery_fixture, idf_builder_patched, idf_builder_mode)
            recover_interrupted_idf_builder_patch(idf_recovery_fixture, idf_builder_mode)
            require(
                idf_recovery_fixture.read_bytes() == idf_builder_bytes,
                "Interrupted ESP-IDF builder recovery self-test changed original bytes",
            )
            require(
                not any(path_lexists(path) for path in backup_paths(idf_recovery_fixture)),
                "Interrupted ESP-IDF builder recovery self-test left backup state",
            )

            webserver_recovery_fixture = temporary_dir / "recovery-Parsing.cpp"
            webserver_recovery_fixture.write_bytes(webserver_parser_bytes)
            create_webserver_parser_backup(
                webserver_recovery_fixture, webserver_parser_bytes
            )
            atomic_replace_bytes(
                webserver_recovery_fixture, webserver_parser_patched,
                webserver_parser_mode,
            )
            recover_interrupted_webserver_parser_patch(
                webserver_recovery_fixture, webserver_parser_mode
            )
            require(webserver_recovery_fixture.read_bytes() == webserver_parser_bytes and
                    not any(path_lexists(path) for path in backup_paths(webserver_recovery_fixture)),
                    "Interrupted WebServer parser recovery did not restore exact original state")

            ca_bundle = make_strict_ca_bundle(Path(temporary_name))
            env = strict_subprocess_env(core_dir, ca_bundle)
            require("SSL_CERT_FILE" not in env, "Child SSL_CERT_FILE must remain unset for native uv trust")
            require(env.get("XTINCT_STRICT_CA_BUNDLE") == str(ca_bundle), "Strict CA ownership marker is missing")
            require(env.get("PYTHONIOENCODING") == "utf-8", "Child Python I/O encoding is not pinned to UTF-8")
            require(env.get("PYTHONUTF8") == "1", "Child Python UTF-8 mode is not enabled")
            require("PYTHONHOME" not in env and "PYTHONPATH" not in env, "Child Python path overrides survived")
            require(env.get("UV_NO_CONFIG") == "1", "Nested uv configuration loading is not disabled")
            require(env.get("UV_NO_INDEX") == "1" and env.get("PIP_NO_INDEX") == "1",
                    "READY27 private build is not package-index isolated")
            require(env.get("IDF_COMPONENT_MANAGER") == "0",
                    "READY27 private build did not disable the remote component manager")
            require(env.get("PLATFORMIO_RUN_JOBS") == str(MAX_PLATFORMIO_JOBS),
                    "Nested PlatformIO compile jobs are not capped")
            require(env.get("HTTPS_PROXY") == "http://127.0.0.1:9" and
                    env.get("https_proxy") == "http://127.0.0.1:9",
                    "READY27 private build is not network fail-closed")
            require(env.get("SOURCE_DATE_EPOCH") == REPRODUCIBLE_SOURCE_DATE_EPOCH and
                    env.get("TZ") == REPRODUCIBLE_TIMEZONE,
                    "Child reproducible compiler time is not pinned")
            require(Path(env.get("XTINCT_REPRO_PROJECT_ROOT", "")).resolve() == PROJECT_ROOT.resolve() and
                    Path(env.get("XTINCT_REPRO_CORE_ROOT", "")).resolve() == core_dir.resolve() and
                    Path(env.get("XTINCT_REPRO_USER_ROOT", "")).resolve() == Path.home().resolve(),
                    "Child reproducible path roots are not wrapper-owned")
            require(Path(env.get("XTINCT_PINNED_PACKAGES_DIR", "")).resolve() ==
                    Path(env.get("PLATFORMIO_PACKAGES_DIR", "")).resolve(),
                    "Child reproducible package roots disagree")
            verify_idf_builder_fragment_parsing(core_dir, env, idf_builder_patched)
            prior_build_override = os.environ.get("PLATFORMIO_BUILD_DIR")
            os.environ["PLATFORMIO_BUILD_DIR"] = "Z:\\caller-controlled"
            try:
                try:
                    strict_subprocess_env(core_dir, ca_bundle)
                except BuildWrapperError as error:
                    require("Refusing inherited PlatformIO override" in str(error),
                            "PlatformIO override failed for an unexpected reason")
                else:
                    raise BuildWrapperError("Inherited PlatformIO build-directory override was accepted")
            finally:
                if prior_build_override is None:
                    os.environ.pop("PLATFORMIO_BUILD_DIR", None)
                else:
                    os.environ["PLATFORMIO_BUILD_DIR"] = prior_build_override
            prior_uv_config = os.environ.get("UV_CONFIG_FILE")
            os.environ["UV_CONFIG_FILE"] = "Z:\\caller-controlled-uv.toml"
            try:
                try:
                    strict_subprocess_env(core_dir, ca_bundle)
                except BuildWrapperError as error:
                    require("UV_CONFIG_FILE" in str(error), "uv config override failed for an unexpected reason")
                else:
                    raise BuildWrapperError("Inherited uv configuration override was accepted")
            finally:
                if prior_uv_config is None:
                    os.environ.pop("UV_CONFIG_FILE", None)
                else:
                    os.environ["UV_CONFIG_FILE"] = prior_uv_config
            unicode_probe = "XTINCT UTF-8 probe: Brisbane - 日本語 - Ελληνικά - Українська"
            probe_code = (
                "import subprocess, sys; "
                f"expected={unicode_probe!r}; "
                "child=subprocess.run([sys.executable, '-c', "
                "'import sys; sys.stdout.write(' + repr(expected) + ')'], "
                "capture_output=True, text=True, check=True); "
                "assert child.stdout == expected; sys.stdout.write(child.stdout)"
            )
            probe = subprocess.run(
                [sys.executable, "-c", probe_code],
                cwd=PROJECT_ROOT,
                env=env,
                text=True,
                encoding="utf-8",
                capture_output=True,
                check=False,
            )
            require(probe.returncode == 0, "Nested UTF-8 child-pipe probe failed")
            require(probe.stdout == unicode_probe, "Nested UTF-8 child-pipe round trip changed text")
            verify_patched_certifi_environment(core_dir, patched, env)
            verify_platformio_entrypoint(core_dir, env)
            ensure_strict_penv(core_dir, env, install=False)
            verify_or_repair_idf_venv(core_dir, env, install=False)
            # A no-install second pass proves that the repaired environment is
            # independently verifiable and that repair did not replace it.
            verify_or_repair_idf_venv(core_dir, env, install=False)

            with tempfile.TemporaryDirectory(prefix="xtinct-cmake-scaffold-test-") as cmake_test_name:
                cmake_test_root = Path(cmake_test_name)
                cmake_test_path = cmake_test_root / "CMakeLists.txt"
                ensure_platformio_root_cmake(cmake_test_root)
                require(
                    cmake_test_path.read_bytes() == PLATFORMIO_ROOT_CMAKE,
                    "CMake scaffold creation self-test failed",
                )
                cmake_test_path.write_bytes(PLATFORMIO_ROOT_CMAKE_EMPTY)
                ensure_platformio_root_cmake(cmake_test_root)
                require(
                    cmake_test_path.read_bytes() == PLATFORMIO_ROOT_CMAKE,
                    "CMake scaffold repair self-test failed",
                )
                canonical_bytes = cmake_test_path.read_bytes()
                canonical_mode = stat.S_IMODE(cmake_test_path.stat().st_mode)
                ensure_platformio_root_cmake(cmake_test_root)
                require(
                    cmake_test_path.read_bytes() == canonical_bytes,
                    "Canonical CMake scaffold idempotence changed bytes",
                )
                require(
                    stat.S_IMODE(cmake_test_path.stat().st_mode) == canonical_mode,
                    "Canonical CMake scaffold idempotence changed mode",
                )

                unknown_cmake_bytes = b"user-owned CMake project\r\n"
                cmake_test_path.write_bytes(unknown_cmake_bytes)
                unknown_cmake_mode = stat.S_IMODE(cmake_test_path.stat().st_mode)
                try:
                    ensure_platformio_root_cmake(cmake_test_root)
                except BuildWrapperError as error:
                    require("Unexpected ignored CMakeLists.txt" in str(error),
                            "Unknown CMake scaffold failed for an unexpected reason")
                else:
                    raise BuildWrapperError("CMake scaffold guard accepted unexpected user content")
                require(
                    cmake_test_path.read_bytes() == unknown_cmake_bytes,
                    "CMake scaffold guard changed unknown user bytes",
                )
                require(
                    stat.S_IMODE(cmake_test_path.stat().st_mode) == unknown_cmake_mode,
                    "CMake scaffold guard changed unknown user mode",
                )

            ensure_platformio_root_cmake(PROJECT_ROOT)
            physical_cwd = Path.cwd()
            require(os.path.samefile(physical_cwd, PROJECT_ROOT), "Wrapper self-test did not start in PROJECT_ROOT")
            owned_alias = SubstProjectAlias(core_dir)
            with owned_alias as project_alias:
                require(os.path.samefile(Path.cwd(), physical_cwd), "Parent process changed cwd for SUBST alias")
                require(owned_alias.letter is not None, "SUBST alias has no drive letter")
                require(
                    ntpath.basename(str(project_alias)) == "",
                    "SUBST root no longer reproduces the empty Windows basename condition",
                )
                alias_cmake_path = project_alias / "CMakeLists.txt"
                require_plain_file(alias_cmake_path, "PlatformIO root CMake scaffold through SUBST alias")
                require(
                    alias_cmake_path.read_bytes() == PLATFORMIO_ROOT_CMAKE,
                    "SUBST alias did not expose the canonical PlatformIO CMake scaffold",
                )
                try:
                    require_exact_subst_mapping(owned_alias.letter, PROJECT_ROOT.parent)
                except BuildWrapperError as error:
                    require("target changed" in str(error), "Wrong SUBST target failed for an unexpected reason")
                else:
                    raise BuildWrapperError("SUBST target verifier accepted the wrong physical directory")
                require_exact_subst_mapping(owned_alias.letter, PROJECT_ROOT)
                owned_alias.verify()
                alias_child_probe = subprocess.run(
                    [sys.executable, "-c", "import os,sys; sys.exit(0 if os.getcwd() == sys.argv[1] else 1)",
                     str(project_alias)],
                    cwd=project_alias,
                    env=env,
                    check=False,
                )
                require(alias_child_probe.returncode == 0, "SUBST child cwd changed during self-test")
                owned_alias.verify()

                owned_build = PrivateBuildDirectory(core_dir)
                with owned_build as private_build:
                    private_cache = create_private_build_cache(private_build)
                    env["PLATFORMIO_BUILD_DIR"] = str(private_build)
                    env["PLATFORMIO_BUILD_CACHE_DIR"] = str(private_cache)
                    env["XTINCT_REPRO_BUILD_CACHE_ROOT"] = str(private_cache)
                    verify_private_build_config(
                        core_dir, env, private_build, private_cache, project_alias
                    )
                    probe_file = private_build / "cleanup-probe.bin"
                    probe_file.write_bytes(b"XTINCT private build cleanup probe")
                    require(probe_file.is_file(), "Private build cleanup fixture was not created")
                    private_path = private_build
                    private_marker = owned_build.marker_path
                alias_letter = owned_alias.letter
                alias_marker = owned_alias.marker_path
            require(not path_lexists(private_path), "Private build cleanup self-test left its directory")
            require(private_marker is not None and not path_lexists(private_marker),
                    "Private build cleanup self-test left its marker")
            require(alias_letter is not None and not query_dos_device(alias_letter),
                    "SUBST alias self-test left a DOS-device mapping")
            require(alias_marker is not None and not path_lexists(alias_marker),
                    "SUBST alias self-test left its ownership marker")
            require(os.path.samefile(Path.cwd(), physical_cwd), "Parent cwd changed after SUBST cleanup")
            env.pop("PLATFORMIO_BUILD_DIR", None)
            env.pop("PLATFORMIO_BUILD_CACHE_DIR", None)
            env.pop("XTINCT_REPRO_BUILD_CACHE_ROOT", None)

            fail_closed_alias = SubstProjectAlias(core_dir)
            fail_closed_alias.__enter__()
            fail_alias_marker = fail_closed_alias.marker_path
            fail_alias_letter = fail_closed_alias.letter
            require(
                fail_alias_marker is not None
                and fail_alias_letter is not None
                and fail_closed_alias.marker_bytes is not None,
                "SUBST fail-closed fixture is incomplete",
            )
            alias_cleanup_rejected = False
            try:
                fail_alias_marker.write_bytes(b"CORRUPTED")
                try:
                    fail_closed_alias.cleanup()
                except BuildWrapperError as error:
                    require("ownership marker changed" in str(error),
                            "SUBST marker corruption failed for an unexpected reason")
                    alias_cleanup_rejected = True
                require_exact_subst_mapping(fail_alias_letter, PROJECT_ROOT)
            finally:
                require_plain_file(fail_alias_marker, "Corrupted SUBST self-test marker")
                fail_alias_marker.write_bytes(fail_closed_alias.marker_bytes)
                if fail_closed_alias.active:
                    fail_closed_alias.cleanup()
            require(alias_cleanup_rejected, "SUBST cleanup accepted a corrupted ownership marker")
            require(not query_dos_device(fail_alias_letter), "Recovered SUBST fixture left its mapping")
            require(not path_lexists(fail_alias_marker), "Recovered SUBST fixture left its marker")

            fail_closed_build = PrivateBuildDirectory(core_dir)
            fail_closed_path = fail_closed_build.__enter__()
            fail_closed_marker = fail_closed_build.marker_path
            require(fail_closed_marker is not None and fail_closed_build.marker_bytes is not None,
                    "Private build fail-closed fixture is incomplete")
            fail_closed_marker.write_bytes(b"CORRUPTED")
            try:
                fail_closed_build.cleanup()
            except BuildWrapperError as error:
                require("ownership marker changed" in str(error), "Marker corruption failed for an unexpected reason")
            else:
                raise BuildWrapperError("Private build cleanup accepted a corrupted ownership marker")
            require(path_lexists(fail_closed_path), "Fail-closed cleanup removed an unowned directory")
            fail_closed_marker.write_bytes(fail_closed_build.marker_bytes)
            fail_closed_build.cleanup()
            require(not path_lexists(fail_closed_path) and not path_lexists(fail_closed_marker),
                    "Recovered private build fixture was not cleaned")

            artifact_source = Path(temporary_name) / "firmware.bin"
            artifact_source.write_bytes(b"XTINCT artifact publish probe")
            artifact_start = artifact_source.stat().st_mtime_ns
            artifact_mode, artifact_size, artifact_digest = validate_fresh_artifact(
                artifact_source, artifact_start, MAX_OTA_APP_BYTES
            )
            artifact_destination = Path(temporary_name) / "published.bin"
            atomic_publish_artifact(
                artifact_source, artifact_destination, artifact_mode, artifact_size, artifact_digest
            )
            require(artifact_destination.read_bytes() == artifact_source.read_bytes(),
                    "Atomic artifact publish changed bytes")
            self_test_published_generation_rollback(temporary_dir)
            require(
                webserver_parser_target.read_bytes() == webserver_parser_bytes and
                not any(path_lexists(path) for path in backup_paths(webserver_parser_target)),
                "Injected publish failures changed the restored WebServer parser",
            )

            oversized = Path(temporary_name) / "oversized.bin"
            with oversized.open("wb") as handle:
                handle.seek(MAX_OTA_APP_BYTES)
                handle.write(b"\0")
            try:
                validate_fresh_artifact(oversized, oversized.stat().st_mtime_ns, MAX_OTA_APP_BYTES)
            except BuildWrapperError:
                pass
            else:
                raise BuildWrapperError("OTA slot size guard accepted an oversized firmware image")

            map_root = Path(temporary_name) / "map-fixture" / "default"
            map_root.mkdir(parents=True)
            packages_fixture = Path(env["PLATFORMIO_PACKAGES_DIR"])
            raw_map_fixture = map_root / "firmware.map"
            raw_map_fixture.write_text(
                f"{map_root.as_posix()}/src.o\r\n"
                f"{packages_fixture.as_posix()}/{BOOTLOADER_SUPPORT_ARCHIVE_RELATIVE.as_posix()}"
                "(bootloader_flash.c.o)\r\n"
                f"{packages_fixture.as_posix()}/{APP_UPDATE_ARCHIVE_RELATIVE.as_posix()}"
                "(esp_ota_ops.c.o)\r\n"
                f"{PROJECT_ROOT.as_posix()}/src/main.cpp\r\n",
                encoding="utf-8",
            )
            normalized_fixture = normalize_linker_map_bytes(
                raw_map_fixture, map_root, core_dir, packages_fixture, Path("X:\\")
            )
            raw_map_fixture.write_bytes(normalized_fixture)
            require(b"$BUILD/" in normalized_fixture and b"$PACKAGES/" in normalized_fixture,
                    "Linker-map normalization self-test lost provenance anchors")
            if os.name == "nt":
                private_map_root = core_dir / ".xtinct-map-normalization-self-test" / "default"
                short_core = windows_short_directory(core_dir, "linker-map self-test core")
                raw_map_fixture.write_text(
                    f"{(short_core / private_map_root.relative_to(core_dir)).as_posix()}/src.o\n"
                    f"{(short_core / 'packages').as_posix()}/"
                    f"{BOOTLOADER_SUPPORT_ARCHIVE_RELATIVE.as_posix()}(bootloader_flash.c.o)\n",
                    encoding="utf-8",
                )
                normalized_short_fixture = normalize_linker_map_bytes(
                    raw_map_fixture, private_map_root, core_dir, packages_fixture, Path("X:\\")
                )
                require(
                    b"$BUILD/" in normalized_short_fixture and
                    b"$PACKAGES/" in normalized_short_fixture and
                    b"PLATFO~" not in normalized_short_fixture,
                    "Linker-map normalization self-test lost DOS 8.3 provenance anchors",
                )
                raw_map_fixture.write_bytes(normalized_short_fixture)
            sdk_provenance_fixture, sdk_candidates_fixture = build_virtual_sdk_provenance(
                normalized_fixture, packages_fixture, VIRTUAL_SDK_VENDOR_PROBE_STATE
            )
            require(sdk_provenance_fixture["probe_state"] == VIRTUAL_SDK_VENDOR_PROBE_STATE and
                    sdk_provenance_fixture["candidate_set"]["count"] == len(sdk_candidates_fixture) and
                    EXPECTED_BOOTLOADER_VIRTUAL_PATH in sdk_candidates_fixture and
                    VENDOR_APP_UPDATE_VIRTUAL_PATH in sdk_candidates_fixture,
                    "Virtual SDK archive-provenance self-test lost its exact probes")
            try:
                build_virtual_sdk_provenance(
                    normalized_fixture, packages_fixture, VIRTUAL_SDK_REBUILT_PROBE_STATE
                )
            except BuildWrapperError:
                pass
            else:
                raise BuildWrapperError(
                    "Virtual SDK provenance accepted vendor packages as rebuilt packages")
            try:
                virtual_sdk_probe_specs("unreviewed-probe-state")
            except BuildWrapperError:
                pass
            else:
                raise BuildWrapperError(
                    "Virtual SDK probe selector accepted an unreviewed state")
            require_private_artifact_paths_absent(
                [raw_map_fixture], map_root.parent, core_dir, packages_fixture, Path("X:\\"),
                sdk_candidates_fixture, VIRTUAL_SDK_VENDOR_PROBE_STATE,
            )
            machine_code_fixture = Path(temporary_name) / "machine-code-unc-lookalike.bin"
            machine_code_fixture.write_bytes(
                b"\0\x5c\x5cX<`\x5cX<d\x5cX<h\x5cX<\0"
            )
            require_private_artifact_paths_absent(
                [machine_code_fixture], map_root.parent, core_dir, packages_fixture,
                Path("X:\\"), sdk_candidates_fixture, VIRTUAL_SDK_VENDOR_PROBE_STATE,
            )
            leak_fixture = Path(temporary_name) / "local-path-leak.bin"
            leak_fixture.write_text(f"leak={Path.home().as_posix()}/private", encoding="utf-8")
            try:
                require_private_artifact_paths_absent(
                    [leak_fixture], map_root.parent, core_dir, packages_fixture, Path("X:\\"),
                    sdk_candidates_fixture, VIRTUAL_SDK_VENDOR_PROBE_STATE,
                )
            except BuildWrapperError as error:
                require("private/local build path marker" in str(error) or
                        "generic host-absolute drive or UNC path" in str(error),
                        "Artifact path leak failed for an unexpected reason")
            else:
                raise BuildWrapperError("Artifact privacy gate accepted a local profile path")
            for encoding, payload in (
                ("ASCII", b"debug=D:/other-host/private/source.cpp\0"),
                ("UTF-16LE", "debug=D:\\other-host\\private\\source.cpp\0".encode("utf-16le")),
                ("UNC", b"debug=\\\\other-host\\private\\source.cpp\0"),
                ("SHORT-FIRST", b"debug=C:\\x\\file.cpp\0"),
                ("SHORT-FIRST-SLASH", b"debug=D:/x/file.cpp\0"),
                ("EMBEDDED-DRIVE", b"prefixD:/secret/file.cpp\0"),
                ("URI-DRIVE", b"uri:file:///D:/secret/file.cpp\0"),
                ("EMBEDDED-DRIVE-UTF16", "prefixD:/secret/file.cpp\0".encode("utf-16le")),
                ("URI-DRIVE-UTF16", "uri:file:///D:/secret/file.cpp\0".encode("utf-16le")),
                ("PREFIX-UNC-SLASH", b"prefix//server/share/file.cpp\0"),
                ("PREFIX-UNC-BACKSLASH", b"prefix\\\\server\\share\\file.cpp\0"),
                ("PREFIX-UNC-SLASH-UTF16",
                 "prefix//server/share/file.cpp\0".encode("utf-16le")),
                ("PREFIX-UNC-BACKSLASH-UTF16",
                 "prefix\\\\server\\share\\file.cpp\0".encode("utf-16le")),
                ("URI-LATER-UNC-SLASH",
                 b"http://host/path//server/share/file.cpp\0"),
                ("URI-LATER-UNC-BACKSLASH",
                 b"https://host/path\\\\server\\share\\file.cpp\0"),
                ("IDF-SHARE", b"debug=//IDF/share/file.cpp\0"),
                ("IDF-UNC", b"debug=\\\\IDF\\share\\file.cpp\0"),
                ("IDF-VALID-UNPROVEN", b"debug=//IDF\\components\\unproven\\file.cpp\0"),
                ("IDF-REAL-UNC", b"debug=\\\\IDF\\components\\app_update\\esp_ota_ops.c\0"),
                ("IDF-CASE", b"debug=//idf/components/app_update/esp_ota_ops.c\0"),
                ("IDF-REPEATED", b"debug=//IDF//components/app_update/esp_ota_ops.c\0"),
                ("IDF-EMPTY", b"debug=//IDF/components//esp_ota_ops.c\0"),
                ("IDF-DOTDOT", b"debug=//IDF/components/../private.c\0"),
                ("IDF-DRIVE", b"debug=//IDF/components/C:/private.c\0"),
                ("IDF-LOOKALIKE", b"debug=//IDF/component/app_update/esp_ota_ops.c\0"),
            ):
                foreign_path_fixture = Path(temporary_name) / f"foreign-path-{encoding}.bin"
                foreign_path_fixture.write_bytes(payload)
                try:
                    require_private_artifact_paths_absent(
                        [foreign_path_fixture], map_root.parent, core_dir,
                        packages_fixture, Path("X:\\"), sdk_candidates_fixture,
                        VIRTUAL_SDK_VENDOR_PROBE_STATE,
                    )
                except BuildWrapperError as error:
                    require("generic host-absolute drive or UNC path" in str(error),
                            f"{encoding} foreign-host path failed for an unexpected reason")
                else:
                    raise BuildWrapperError(
                        f"Artifact privacy gate accepted a foreign-host {encoding} path"
                    )
            for label, payload in (
                ("FTP-URI", b"ftp://example.invalid/article\0"),
                ("HTTP-URI", b"http://example.invalid/article\0"),
                ("HTTPS-URI", b"https://example.invalid/article\0"),
                ("EMBEDDED-HTTP-URI", b"url=https://example.invalid/article\0"),
            ):
                safe_uri_fixture = Path(temporary_name) / f"safe-uri-{label}.bin"
                safe_uri_fixture.write_bytes(payload)
                require_private_artifact_paths_absent(
                    [safe_uri_fixture], map_root.parent, core_dir,
                    packages_fixture, Path("X:\\"), sdk_candidates_fixture,
                    VIRTUAL_SDK_VENDOR_PROBE_STATE,
                )
            virtual_idf_fixture = Path(temporary_name) / "virtual-idf-path.bin"
            virtual_idf_fixture.write_bytes(
                (EXPECTED_BOOTLOADER_VIRTUAL_PATH + "\0" +
                 VENDOR_APP_UPDATE_VIRTUAL_PATH + "\0").encode("ascii")
            )
            require_private_artifact_paths_absent(
                [virtual_idf_fixture], map_root.parent, core_dir, packages_fixture, Path("X:\\"),
                sdk_candidates_fixture, VIRTUAL_SDK_VENDOR_PROBE_STATE,
            )
            virtual_bootloader_fixture = (
                Path(temporary_name) / "virtual-bootloader-path.bin"
            )
            virtual_bootloader_fixture.write_bytes(
                (EXPECTED_BOOTLOADER_SOURCE_VIRTUAL_PATH + "\0").encode("ascii")
            )
            require_private_artifact_paths_absent(
                [virtual_bootloader_fixture], map_root.parent, core_dir,
                packages_fixture, Path("X:\\"), sdk_candidates_fixture,
                VIRTUAL_SDK_VENDOR_PROBE_STATE,
            )
            virtual_project_fixture = Path(temporary_name) / "virtual-project-path.bin"
            virtual_project_fixture.write_bytes(
                (EXPECTED_MINIZ_VIRTUAL_SOURCE_PATH + "\0").encode("ascii")
            )
            require_private_artifact_paths_absent(
                [virtual_project_fixture], map_root.parent, core_dir,
                packages_fixture, Path("X:\\"), sdk_candidates_fixture,
                VIRTUAL_SDK_VENDOR_PROBE_STATE,
            )
            for label, payload in (
                ("UNKNOWN-ROOT", b"//xtinct/share/file.cpp\0"),
                ("PREFIX-CASE", b"//XTINCT/source/file.cpp\0"),
                ("ROOT-CASE", b"//xtinct/Source/file.cpp\0"),
                ("BACKSLASH-UNC", b"\\\\xtinct\\source\\file.cpp\0"),
                ("MIXED-SEPARATORS", b"//xtinct\\source\\file.cpp\0"),
                ("MISSING-SUFFIX", b"//xtinct/source\0"),
                ("EMPTY-SUFFIX", b"//xtinct/source/\0"),
                ("DOT-SUFFIX", b"//xtinct/source/./file.cpp\0"),
                ("DOTDOT-SUFFIX", b"//xtinct/source/../private/file.cpp\0"),
                ("NESTED-DRIVE", b"//xtinct/source/C:/private/file.cpp\0"),
                ("NESTED-PROFILE", b"//xtinct/source/C:/Users/person/private.cpp\0"),
                ("LOOKALIKE-ROOT", b"//xtinct/source.example/file.cpp\0"),
                ("UTF16-DOTDOT", "//xtinct/source/../private/file.cpp\0".encode("utf-16le")),
            ):
                virtual_project_negative = (
                    Path(temporary_name) / f"virtual-project-negative-{label}.bin"
                )
                virtual_project_negative.write_bytes(payload)
                try:
                    require_private_artifact_paths_absent(
                        [virtual_project_negative], map_root.parent, core_dir,
                        packages_fixture, Path("X:\\"), sdk_candidates_fixture,
                        VIRTUAL_SDK_VENDOR_PROBE_STATE,
                    )
                except BuildWrapperError as error:
                    require("generic host-absolute drive or UNC path" in str(error),
                            f"Virtual-project {label} failed for an unexpected reason")
                else:
                    raise BuildWrapperError(
                        f"Artifact privacy gate accepted virtual-project {label}"
                    )
            noise_fixture = Path(temporary_name) / "binary-drive-noise.bin"
            noise_fixture.write_bytes(
                b"\xde\xbe\xd6g:\\w\xe7\x01\xd5n:\\,\x91{m:\\b^!\xdb\xc7\x93x:\xa1"
            )
            require_private_artifact_paths_absent(
                [noise_fixture], map_root.parent, core_dir, packages_fixture, Path("X:\\"),
                sdk_candidates_fixture, VIRTUAL_SDK_VENDOR_PROBE_STATE,
            )
            elf_fixture = Path(temporary_name) / "section-table-fixture.elf"
            section_names = b"\0.shstrtab\0.debug_info\0"
            section_offset = 52
            string_offset = section_offset + 3 * 40
            header = b"\x7fELF\x01\x01\x01" + b"\0" * 9 + struct.pack(
                "<HHIIIIIHHHHHH", 2, 243, 1, 0, 0, section_offset, 0, 52, 0, 0, 40, 3, 1
            )
            null_section = b"\0" * 40
            string_section = struct.pack(
                "<IIIIIIIIII", 1, 3, 0, 0, string_offset, len(section_names), 0, 0, 1, 0
            )
            debug_section = struct.pack(
                "<IIIIIIIIII", 11, 1, 0, 0, string_offset + len(section_names), 0, 0, 0, 1, 0
            )
            elf_fixture.write_bytes(header + null_section + string_section + debug_section + section_names)
            try:
                require_debug_stripped_elf(elf_fixture)
            except BuildWrapperError as error:
                require("retains debug sections" in str(error),
                        "ELF debug-section fixture failed for an unexpected reason")
            else:
                raise BuildWrapperError("ELF debug-section gate accepted .debug_info")

            stripped_names = b"\0.shstrtab\0.symtab\0.strtab\0"
            string_offset = section_offset + 4 * 40
            string_section = struct.pack(
                "<IIIIIIIIII", 1, 3, 0, 0, string_offset, len(stripped_names), 0, 0, 1, 0
            )
            symtab_section = struct.pack(
                "<IIIIIIIIII", 11, 2, 0, 0, string_offset + len(stripped_names), 0, 3, 0, 4, 16
            )
            strtab_section = struct.pack(
                "<IIIIIIIIII", 19, 3, 0, 0, string_offset + len(stripped_names), 0, 0, 0, 1, 0
            )
            stripped_header = b"\x7fELF\x01\x01\x01" + b"\0" * 9 + struct.pack(
                "<HHIIIIIHHHHHH", 2, 243, 1, 0, 0, section_offset, 0, 52, 0, 0, 40, 4, 1
            )
            elf_fixture.write_bytes(
                stripped_header + null_section + string_section + symtab_section +
                strtab_section + stripped_names
            )
            require_debug_stripped_elf(elf_fixture)

            diagnostic_names = b"\0.shstrtab\0.rodata\0"
            diagnostic_string_offset = section_offset + 3 * 40
            candidate_text = str(Path.home() / "private" / "source.cpp")
            diagnostic_payload = b"\0debug=" + candidate_text.encode("ascii") + b"\0"
            diagnostic_data_offset = diagnostic_string_offset + len(diagnostic_names)
            diagnostic_header = b"\x7fELF\x01\x01\x01" + b"\0" * 9 + struct.pack(
                "<HHIIIIIHHHHHH", 2, 243, 1, 0, 0, section_offset, 0, 52, 0, 0, 40, 3, 1
            )
            diagnostic_string_section = struct.pack(
                "<IIIIIIIIII", 1, 3, 0, 0, diagnostic_string_offset,
                len(diagnostic_names), 0, 0, 1, 0
            )
            diagnostic_rodata_section = struct.pack(
                "<IIIIIIIIII", 11, 1, 0, 0, diagnostic_data_offset,
                len(diagnostic_payload), 0, 0, 1, 0
            )
            diagnostic_elf = Path(temporary_name) / "private-path-diagnostic.elf"
            diagnostic_elf.write_bytes(
                diagnostic_header + null_section + diagnostic_string_section +
                diagnostic_rodata_section + diagnostic_names + diagnostic_payload
            )
            candidate_offset = diagnostic_data_offset + len(b"\0debug=")
            try:
                require_private_artifact_paths_absent(
                    [diagnostic_elf], map_root.parent, core_dir, packages_fixture, Path("X:\\"),
                    sdk_candidates_fixture, VIRTUAL_SDK_VENDOR_PROBE_STATE,
                )
            except BuildWrapperError as error:
                marker = "PRIVATE_PATH_DIAGNOSTIC="
                require(marker in str(error), "Private path diagnostic marker is missing")
                diagnostic = json.loads(str(error).split(marker, 1)[1])
                require(set(diagnostic) == {
                    "artifact", "candidate_bytes", "candidate_sha256", "candidate_truncated",
                    "encoding", "offset", "redacted_candidate", "schema", "section"
                }, "Private path diagnostic envelope is invalid")
                require(diagnostic == {
                    "artifact": diagnostic_elf.name,
                    "candidate_bytes": len(candidate_text.encode("ascii")),
                    "candidate_sha256": sha256(candidate_text.encode("ascii")),
                    "candidate_truncated": False,
                    "encoding": "ASCII",
                    "offset": candidate_offset,
                    "redacted_candidate": "$USER\\private\\source.cpp",
                    "schema": 1,
                    "section": ".rodata",
                }, "Private path diagnostic offset/section/hash/redaction changed")
                require(Path.home().name.lower() not in str(error).lower(),
                        "Private path diagnostic exposed the profile name")
            else:
                raise BuildWrapperError("Private path diagnostic fixture was accepted")
        verified_target, verified_original, _verified_mode = verify_platform(core_dir)
        verified_idf_target, verified_idf_original = verify_idf_builder_script(core_dir)
        (verified_parser_target, verified_parser_original, _verified_parser_mode,
         verified_parser_patch) = verify_webserver_parser_source(packages_dir)
        require(verified_target == target and verified_original == original, "Installed penv source changed in self-test")
        require(
            verified_idf_target == idf_builder_target and verified_idf_original == idf_builder_bytes,
            "Installed ESP-IDF builder changed in self-test",
        )
        require(verified_parser_target == webserver_parser_target and
                verified_parser_original == webserver_parser_bytes and
                verified_parser_patch == webserver_parser_patched,
                "Installed Arduino WebServer parser changed in self-test")
        require(
            not any(path_lexists(path) for path in backup_paths(target)),
            "Self-test left installed penv backup state",
        )
        require(
            not any(path_lexists(path) for path in backup_paths(idf_builder_target)),
            "Self-test left installed ESP-IDF builder backup state",
        )
        require(not any(path_lexists(path) for path in backup_paths(webserver_parser_target)),
                "Self-test left installed WebServer parser backup state")
        rejected_args = (
            ("run", "--target=upload"),
            ("run", "-t=upload"),
            ("run", "-tupload"),
            ("run", "-t", "upload"),
            ("run", "--project-dir=Z:/elsewhere"),
            ("run", "-d", "Z:/elsewhere"),
            ("run", "--project-conf=other.ini"),
            ("run", "-c", "other.ini"),
            ("run", "-e", "sticky"),
            ("run", "-e", "default", "-e", "default"),
            ("run", "-j", "3"),
            ("run", "--jobs=4"),
            ("run", "-j", "1", "--jobs=2"),
        )
        for rejected in rejected_args:
            try:
                parse_pio_args(rejected)
            except BuildWrapperError:
                continue
            raise BuildWrapperError(f"Unsafe PlatformIO arguments passed self-test: {rejected}")
        default_args, default_environment = parse_pio_args(("run", "-e", "default"))
        require(default_environment == "default" and default_args == ["run", "-e", "default", "-j", "2"],
                "Default PlatformIO build no longer has the two-job resource cap")
        one_job_args, _ = parse_pio_args(("run", "-j1"))
        require(one_job_args == ["run", "-j", "1"],
                "Explicit single-job PlatformIO build was not normalized safely")
    print("BUILD_XTINCT_SELF_TEST_OK")
    return 0


def run_build(argv: Sequence[str]) -> int:
    verify_crash_secret_policy()
    verify_file_transfer_security()
    verify_i18n_security()
    verify_x3_resource_budget_source()
    recovery_reference_before = verify_public_recovery_reference()
    args, environment = parse_pio_args(argv)
    core_dir = platformio_core_dir()
    packages_dir = ready27_packages_dir(core_dir)
    require(packages_dir is not None, "Build requires the private READY27 package directory")
    verify_pocket_sync_source_security(core_dir)
    source_snapshot_before = get_source_snapshot()
    platform_dir, _manifest, _piopm, target = platform_paths(core_dir)
    lock_path = platform_dir / ".xtinct-build-wrapper.lock"

    with tempfile.TemporaryDirectory(prefix="xtinct-pio-ca-") as ca_directory_name:
        ca_bundle = make_strict_ca_bundle(Path(ca_directory_name))
        env = strict_subprocess_env(core_dir, ca_bundle)
        require(env.get("PLATFORMIO_RUN_JOBS") == str(MAX_PLATFORMIO_JOBS),
                "Nested PlatformIO compile jobs are not capped")
        private_platformio_python = verify_platformio_entrypoint(core_dir, env)

        with WindowsByteLock(lock_path):
            ensure_platformio_root_cmake(PROJECT_ROOT)
            owned_alias = SubstProjectAlias(core_dir)
            with owned_alias as project_alias:
                with PrivateBuildDirectory(core_dir) as private_build_dir:
                    private_cache_dir = create_private_build_cache(private_build_dir)
                    short_core = Path(env["PLATFORMIO_CORE_DIR"])
                    short_private_build = short_core / private_build_dir.name
                    short_private_cache = short_private_build / private_cache_dir.name
                    require(os.path.samefile(short_private_build, private_build_dir) and
                            os.path.samefile(short_private_cache, private_cache_dir),
                            "Short private build paths changed identity")
                    env["PLATFORMIO_BUILD_DIR"] = str(short_private_build)
                    env["PLATFORMIO_BUILD_CACHE_DIR"] = str(short_private_cache)
                    env["XTINCT_REPRO_BUILD_ALIAS"] = str(short_private_build)
                    env["XTINCT_REPRO_BUILD_CACHE_ROOT"] = str(short_private_cache)
                    project_cache_before = directory_metadata_snapshot(PROJECT_ROOT / ".cache")
                    verify_private_build_config(
                        core_dir, env, short_private_build, short_private_cache, project_alias
                    )

                    require(target.exists(), f"pioarduino source is missing: {target}")
                    recover_interrupted_patch(target, target.stat().st_mode)
                    idf_builder_target = idf_builder_script_path(core_dir)
                    recover_interrupted_idf_builder_patch(
                        idf_builder_target, idf_builder_target.stat().st_mode
                    )
                    webserver_parser_target, _webserver_patch_path = \
                        webserver_parser_paths(packages_dir)
                    recover_interrupted_webserver_parser_patch(
                        webserver_parser_target, webserver_parser_target.stat().st_mode
                    )
                    target, original, mode = verify_platform(core_dir)
                    idf_builder_target, idf_builder_original = verify_idf_builder_script(core_dir)
                    idf_builder_mode = idf_builder_target.stat().st_mode
                    idf_builder_patched = patch_idf_builder_source(idf_builder_original)
                    (webserver_parser_target, webserver_parser_original,
                     webserver_parser_mode, webserver_parser_patched) = \
                        verify_webserver_parser_source(packages_dir)
                    verify_penv_distribution(core_dir)

                    child_returncode: int | None = None
                    started_ns = 0
                    penv_backup_created = False
                    idf_builder_backup_created = False
                    webserver_parser_backup_created = False
                    try:
                        create_backup(target, original)
                        penv_backup_created = True
                        patched = patch_source(original)
                        verify_patched_certifi_environment(core_dir, patched, env)
                        atomic_replace_bytes(target, patched, mode)
                        require(target.read_bytes() == patched, "Atomic pioarduino transient patch verification failed")
                        # READY27 is built from a fully pinned private penv and
                        # dependency seed.  Network access is intentionally
                        # fail-closed; repair/install would make the private lane depend on
                        # mutable external state.
                        ensure_strict_penv(core_dir, env, install=False)
                        verify_or_repair_idf_venv(core_dir, env, install=False)

                        # Apply only the exact reviewed builder and bounded
                        # WebServer parser patches after environment repair,
                        # directly before PlatformIO executes the pinned build.
                        verified_builder_target, verified_builder_original = verify_idf_builder_script(core_dir)
                        require(
                            verified_builder_target == idf_builder_target
                            and verified_builder_original == idf_builder_original,
                            "ESP-IDF builder changed before its transient patch",
                        )
                        create_idf_builder_backup(idf_builder_target, idf_builder_original)
                        idf_builder_backup_created = True
                        atomic_replace_bytes(idf_builder_target, idf_builder_patched, idf_builder_mode)
                        require_plain_file(idf_builder_target, "Transiently patched ESP-IDF builder")
                        installed_idf_builder_patch = idf_builder_target.read_bytes()
                        require(
                            installed_idf_builder_patch == idf_builder_patched
                            and sha256(installed_idf_builder_patch) == EXPECTED_PATCHED_IDF_BUILDER_SHA256,
                            "Atomic ESP-IDF builder transient patch verification failed",
                        )

                        create_webserver_parser_backup(
                            webserver_parser_target, webserver_parser_original
                        )
                        webserver_parser_backup_created = True
                        atomic_replace_bytes(
                            webserver_parser_target,
                            webserver_parser_patched,
                            webserver_parser_mode,
                        )
                        require_plain_file(
                            webserver_parser_target,
                            "Transiently patched Arduino WebServer parser",
                        )
                        require(webserver_parser_target.read_bytes() == webserver_parser_patched,
                                "Atomic WebServer parser transient patch verification failed")

                        command = [
                            str(private_platformio_python),
                            "-B",
                            "-X", "utf8",
                            "-I", "-m", "platformio", *args,
                        ]
                        print("Verified no-space project alias:", project_alias)
                        print("Private no-space build directory:", private_build_dir)
                        print("Running:", subprocess.list2cmdline(command))
                        started_ns = time.time_ns()
                        owned_alias.verify()
                        require(
                            idf_builder_target.read_bytes() == idf_builder_patched,
                            "ESP-IDF builder changed immediately before PlatformIO",
                        )
                        require(
                            webserver_parser_target.read_bytes() == webserver_parser_patched,
                            "Arduino WebServer parser changed immediately before PlatformIO",
                        )
                        child_returncode = subprocess.run(
                            command,
                            cwd=project_alias,
                            env=env,
                            check=False,
                        ).returncode
                        owned_alias.verify()
                    finally:
                        restore_toolchain_patches(
                            target,
                            original,
                            mode,
                            penv_backup_created,
                            idf_builder_target,
                            idf_builder_original,
                            idf_builder_mode,
                            idf_builder_backup_created,
                            webserver_parser_target,
                            webserver_parser_original,
                            webserver_parser_mode,
                            webserver_parser_backup_created,
                        )

                    restored_target, restored_original, _restored_mode = verify_platform(core_dir)
                    restored_builder_target, restored_builder_original = verify_idf_builder_script(core_dir)
                    (restored_parser_target, restored_parser_original,
                     _restored_parser_mode, restored_parser_patch) = \
                        verify_webserver_parser_source(packages_dir)
                    require(
                        restored_target == target and restored_original == original,
                        "pioarduino source changed after restoration",
                    )
                    require(
                        restored_builder_target == idf_builder_target
                        and restored_builder_original == idf_builder_original,
                        "ESP-IDF builder changed after restoration",
                    )
                    require(
                        restored_parser_target == webserver_parser_target and
                        restored_parser_original == webserver_parser_original and
                        restored_parser_patch == webserver_parser_patched,
                        "Arduino WebServer parser changed after restoration",
                    )

                    require(child_returncode is not None, "PlatformIO child did not start")
                    if child_returncode != 0:
                        print(
                            f"PlatformIO exited {child_returncode}; reviewed toolchain bytes were restored.",
                            file=sys.stderr,
                        )
                        return child_returncode
                    source_snapshot_after = get_source_snapshot()
                    require(source_snapshot_after == source_snapshot_before,
                            "XTINCT source changed during the authoritative build")
                    project_cache_after = directory_metadata_snapshot(PROJECT_ROOT / ".cache")
                    require(project_cache_after == project_cache_before,
                            "Project PlatformIO build cache changed during the authoritative build")
                    publish_verified_artifacts(
                        private_build_dir, environment, started_ns, core_dir, project_alias,
                        project_cache_after,
                        source_snapshot_after,
                    )
                    require(verify_public_recovery_reference() == recovery_reference_before,
                            "Public recovery reference changed during the authoritative build")
                    print(
                        "Verified XTINCT source snapshot:",
                        f"{source_snapshot_after['files']} files",
                        source_snapshot_after["sha256"],
                    )
                    print("Verified pioarduino source restoration:", EXPECTED_SOURCE_SHA256)
                    print("Verified ESP-IDF builder restoration:", EXPECTED_IDF_BUILDER_SHA256)
                    print("Verified Arduino WebServer parser restoration:",
                          EXPECTED_WEB_SERVER_PARSER_SHA256)
                    return 0


def main(argv: Sequence[str]) -> int:
    require(sys.version_info[:2] == (3, 11), "Run this wrapper with Python 3.11")
    require((PROJECT_ROOT / "platformio.ini").is_file(), "Wrapper is not inside the XTINCT firmware repository")
    if list(argv) == ["--self-test"]:
        return self_test(platformio_core_dir())
    return run_build(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        print("Interrupted; restoration was attempted before exit.", file=sys.stderr)
        raise SystemExit(130)
    except (BuildWrapperError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as error:
        print(f"XTINCT build wrapper failed closed: {error}", file=sys.stderr)
        raise SystemExit(2)
