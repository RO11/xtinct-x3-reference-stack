#!/usr/bin/env python3
"""Fail-closed READY27 Pocket Sync source and linked-image policy.

The source pass is intentionally independent of PlatformIO's generated build
tree. The post-build pass consumes either the private build directory or a
published, artifact-bound evidence directory, verifies the effective sdkconfig,
and checks the final ELF symbol table. A linker map may contain discarded input
sections, so removal of client/scanner roles is proved from defined ELF symbols,
not from a textual absence in the map.
"""

from __future__ import annotations

import argparse
import ast
import configparser
import ctypes
import ctypes.wintypes
import hashlib
import hmac
import json
import os
import re
import subprocess
import struct
import sys
import tempfile
from pathlib import Path

from check_bounded_webserver_parser import (
    ParserFixtureError,
    self_test as verify_bounded_webserver_parser_files,
    verify_source_contract as verify_bounded_webserver_parser_source,
)
from verify_xtinct_network_atomicity import (
    GateError as NetworkAtomicityError,
    verify as verify_network_atomicity_files,
)


PINNED_NIMBLE_COMMIT = "f66f4fe26306747cd8308e77d755da1863219089"
PINNED_NIMCONFIG_PATCH_SHA256 = "332223dd5b0bed8c50608501ac9e99f7da538831d5b48daeae303ad5c948c2ab"
LINKED_PROVENANCE_DIRECTORY = "linked-provenance"
PRIVATE_DEPENDENCY_DIRECTORY = "private"
NORMALIZED_DEPENDENCY_SUFFIX = ".normalized"
LINKED_EVIDENCE_MANIFEST_NAME = "pocket-sync-linked-evidence.json"
LINKED_DEPENDENCY_NAMES = ("NimBLEServer.cpp.d", "PocketSyncBleServer.cpp.d")
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
RAW_MAP_EVIDENCE_NAME = "firmware.map.raw"
SOURCE_SNAPSHOT_SCRIPT = "scripts/Get-XtinctSourceSnapshot.ps1"
REPRODUCIBLE_SOURCE_DATE_EPOCH = "1786182071"
PUBLIC_RECOVERY_POLICY = "official-crosspoint-v1.5.0-external-reference-v1"
PUBLIC_RECOVERY_VERSION = "v1.5.0"
PUBLIC_RECOVERY_BYTES = 5544112
PUBLIC_RECOVERY_SHA256 = "a7087155757bc63c1fcf60ae8d60a3760ce6d3406aaf7b9f23d0025244434f08"
PUBLIC_RECOVERY_URL = (
    "https://github.com/crosspoint-reader/crosspoint-reader/releases/download/"
    "v1.5.0/firmware.bin"
)
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
EXPECTED_MINIZ_SOURCE_BYTES = 358274
EXPECTED_MINIZ_SOURCE_SHA256 = (
    "9fbea1793983dc516c0099a64c7045e21bcdcdeef52c53e299eda2bf5e8348ef"
)
EXPECTED_MINIZ_VIRTUAL_SOURCE_PATH = "//xtinct/source/lib/miniz/third_party/miniz.c"
PRIVATE_BUILD_DIRECTORY_NAME = ".xtinct-build-authoritative"
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
READY_RELEASE_LABEL = "v1.6.2-xtinct.2"
READY_BUILD_ID = "BUILD-162-XTINCT2-PUBLIC"
READY_VERSION = "1.6.2-xtinct.2"
ALLOWED_GATTC_PERIPHERAL_HOST_SYMBOLS = frozenset({
    "ble_gattc_connection_broken",
    "ble_gattc_indicate_custom",
    "ble_gattc_init",
    "ble_gattc_notify_custom",
    "ble_gattc_rx_err",
    "ble_gattc_rx_mtu",
    "ble_gattc_timer",
})
NIMBLE_HOST_HOUSEKEEPING_SOURCE_EVIDENCE = {
    "src/nimble/nimble/host/src/ble_hs.c": (
        "c5677503b264738b692d0e688672011206a308d20c5ca1aa5e32a649443bd48a",
        ("ticks_until_next = ble_gattc_timer();", "rc = ble_gattc_init();"),
    ),
    "src/nimble/nimble/host/src/ble_gap.c": (
        "8cadddeeacfd4e8f0ef010c21f4a7f4d30077459cacdd6821ba33c8b0328ce44",
        ("ble_gattc_connection_broken(conn_handle);",),
    ),
    "src/nimble/nimble/host/src/ble_hs_hci_evt.c": (
        "3719d2b5ef019a296d5759c0ad9730bda942935b742666f9301a9b2a5cc7c4ee",
        ("ble_gattc_connection_broken(ev->conn_handle);",),
    ),
    "src/nimble/nimble/host/src/ble_gattc.c": (
        "6c8e62b26f72ada8bf6a693a5213512bb59528ad269a60cc87dc3157a2820c35",
        (
            "ble_gattc_timer(void)",
            "ble_gattc_connection_broken(uint16_t conn_handle)",
            "ble_gattc_init(void)",
        ),
    ),
    "src/NimBLECharacteristic.cpp": (
        "b711f0a67fee0ce176a865ca41dc0580d5ad88f96b26f2bff5ae5bb01c72fe58",
        (
            "ble_gattc_notify_custom(connHandle, m_handle, om)",
            "ble_gattc_indicate_custom(connHandle, m_handle, om)",
        ),
    ),
    "src/nimble/nimble/host/src/ble_att_clt.c": (
        "3e6a5c34171c43b53c7d1108ab16a5b95b618dafd20ff671434d955c6e66becf",
        (
            "ble_gattc_rx_err(conn_handle, cid, le16toh(rsp->baep_handle),",
            "ble_gattc_rx_mtu(conn_handle, BLE_L2CAP_CID_ATT, rc, mtu);",
        ),
    ),
}


class PocketSyncSecurityError(RuntimeError):
    """A READY27 security, resource, or provenance invariant failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PocketSyncSecurityError(message)


def read_text(path: Path) -> str:
    require(path.is_file(), f"required file is missing: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PocketSyncSecurityError(f"could not read UTF-8 source: {path}") from error


def dependency_path_spellings(path: Path, private_core: Path) -> tuple[str, ...]:
    """Return only filesystem-identical spellings the Windows compiler may emit."""
    resolved_core = private_core.resolve()
    resolved_path = path.resolve()
    try:
        relative = resolved_path.relative_to(resolved_core)
    except ValueError as error:
        raise PocketSyncSecurityError("dependency path escaped the private core") from error
    spellings = [resolved_path.as_posix()]
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        get_short_path = kernel32.GetShortPathNameW
        get_short_path.argtypes = [
            ctypes.wintypes.LPCWSTR, ctypes.wintypes.LPWSTR, ctypes.wintypes.DWORD,
        ]
        get_short_path.restype = ctypes.wintypes.DWORD
        buffer = ctypes.create_unicode_buffer(32768)
        length = int(get_short_path(str(resolved_core), buffer, len(buffer)))
        require(0 < length < len(buffer),
                "could not resolve the private core's verified Windows 8.3 spelling")
        short_core = Path(buffer.value)
        require(short_core.is_dir() and not short_core.is_symlink() and
                os.path.samefile(short_core, resolved_core),
                "private core Windows 8.3 spelling changed filesystem identity")
        short_spelling = (short_core / relative).as_posix()
        if short_spelling.casefold() != spellings[0].casefold():
            spellings.append(short_spelling)
    return tuple(spellings)


def dependency_contains_exact_path(text: str, spellings: tuple[str, ...]) -> bool:
    normalized = text.replace("\\", "/")
    return any(
        re.search(rf"(?im)(?:^|\s){re.escape(spelling)}(?=\s|$)", normalized) is not None
        for spelling in spellings
    )


def parse_platformio_ini(text: str) -> configparser.ConfigParser:
    """Parse PlatformIO's INI dialect while retaining strict duplicate checks.

    PlatformIO permits comments and blank lines inside indented multiline
    values.  Python's configparser ends a value at those blank lines, so remove
    only full-line comments/blank lines before strict structural parsing.
    """
    sanitized = "\n".join(
        line for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith((";", "#"))
    ) + "\n"
    parser = configparser.ConfigParser(
        interpolation=None,
        strict=True,
        empty_lines_in_values=False,
    )
    try:
        parser.read_string(sanitized)
    except configparser.Error as error:
        raise PocketSyncSecurityError("platformio.ini is not structurally unambiguous") from error
    return parser


def multiline_items(value: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in value.splitlines() if line.strip())


def parse_custom_sdkconfig(value: str) -> dict[str, str]:
    settings: dict[str, str] = {}
    for item in multiline_items(value):
        match = re.fullmatch(r"(CONFIG_[A-Za-z0-9_]+)=([^\s]+)", item)
        require(match is not None, f"custom_sdkconfig contains an invalid setting: {item}")
        name, configured = match.groups()
        require(name not in settings,
                f"custom_sdkconfig repeats or contradicts {name}")
        settings[name] = configured
    require(settings, "custom_sdkconfig is empty")
    return settings


def verify_exception_platformio_policy(platformio_text: str) -> None:
    parser = parse_platformio_ini(platformio_text)
    require(parser.has_section("base") and parser.has_section("env:default"),
            "platformio.ini lacks the authoritative base/default environment")
    require(parser.get("platformio", "default_envs", fallback="").strip() == "default",
            "authoritative PlatformIO default environment changed")
    require(parser.get("env:default", "extends", fallback="").strip() == "base",
            "default environment no longer extends the reviewed base")

    base_flags = multiline_items(parser.get("base", "build_flags", fallback=""))
    base_unflags = multiline_items(parser.get("base", "build_unflags", fallback=""))
    default_flags = multiline_items(parser.get("env:default", "build_flags", fallback=""))
    require(base_flags.count("-fexceptions") == 1 and "-fno-exceptions" not in base_flags,
            "base build_flags must contain exactly one -fexceptions and no -fno-exceptions")
    require(base_unflags.count("-fno-exceptions") == 1 and "-fexceptions" not in base_unflags,
            "base build_unflags must remove exactly one -fno-exceptions")
    require(default_flags.count("${base.build_flags}") == 1 and
            not any(flag in {"-fexceptions", "-fno-exceptions"} for flag in default_flags),
            "default environment must inherit the base exception flags without overriding them")

    settings = parse_custom_sdkconfig(parser.get("base", "custom_sdkconfig", fallback=""))
    require(settings.get("CONFIG_COMPILER_CXX_EXCEPTIONS") == "y",
            "custom_sdkconfig must enable the ESP-IDF C++ exception runtime")
    require(settings.get("CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE") == "1024",
            "custom_sdkconfig C++ exception emergency pool must be exactly 1024 bytes")
    require(settings.get("CONFIG_COMPILER_CXX_RTTI") == "n",
            "custom_sdkconfig must keep RTTI disabled independently of exceptions")


def verify_exception_probe_sources(guard: str, runtime_probe: str,
                                   safety_limits: str) -> None:
    for fragment in ("#if !defined(__cpp_exceptions)", "#error", "static_assert(__cpp_exceptions"):
        require(fragment in guard, f"exception force-include guard lost: {fragment}")
    require(EXCEPTION_RUNTIME_PROBE_TEST.split(".", 1)[1] in runtime_probe and
            runtime_probe.count("throw std::bad_alloc();") >= 2 and
            "ScopedRealAllocationFailure" in runtime_probe,
            "actual allocator throw runtime probe is incomplete")
    require("catch (const std::bad_alloc&)" in safety_limits and
            "catch (const std::length_error&)" in safety_limits,
            "production allocation guard lost its real exception catches")


def expect_exception_policy_rejection(action, label: str) -> None:
    try:
        action()
    except PocketSyncSecurityError:
        return
    raise PocketSyncSecurityError(f"exception policy accepted mutation: {label}")


def verify_exception_source_mutations(platformio_text: str, guard: str,
                                      runtime_probe: str, safety_limits: str) -> None:
    mutations = (
        ("exceptions disabled", platformio_text.replace("  -fexceptions\n", "  -fno-exceptions\n", 1)),
        ("unflag removed", platformio_text.replace("  -fno-exceptions\n", "", 1)),
        ("runtime disabled", platformio_text.replace(
            "  CONFIG_COMPILER_CXX_EXCEPTIONS=y\n",
            "  CONFIG_COMPILER_CXX_EXCEPTIONS=n\n", 1)),
        ("zero emergency pool", platformio_text.replace(
            "  CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE=1024\n",
            "  CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE=0\n", 1)),
        ("contradictory duplicate", platformio_text.replace(
            "  CONFIG_COMPILER_CXX_EXCEPTIONS=y\n",
            "  CONFIG_COMPILER_CXX_EXCEPTIONS=y\n  CONFIG_COMPILER_CXX_EXCEPTIONS=n\n", 1)),
    )
    for label, mutated in mutations:
        require(mutated != platformio_text, f"exception mutation fixture did not change: {label}")
        expect_exception_policy_rejection(
            lambda candidate=mutated: verify_exception_platformio_policy(candidate), label
        )
    expect_exception_policy_rejection(
        lambda: verify_exception_probe_sources(
            guard.replace("__cpp_exceptions", "XTINCT_REMOVED_EXCEPTION_MACRO"),
            runtime_probe, safety_limits),
        "force-include feature macro removed",
    )
    expect_exception_policy_rejection(
        lambda: verify_exception_probe_sources(
            guard, runtime_probe.replace("throw std::bad_alloc();", "std::abort();"),
            safety_limits),
        "actual allocator throws removed",
    )
    expect_exception_policy_rejection(
        lambda: verify_exception_probe_sources(
            guard, runtime_probe,
            safety_limits.replace("catch (const std::bad_alloc&)",
                                  "catch (const XTINCT_REMOVED_BAD_ALLOC&)")),
        "production bad_alloc catch removed",
    )


def function_body(source: str, signature: str) -> str:
    """Return a C/C++ function body for narrow, fail-closed source checks."""
    start = source.find(signature)
    require(start >= 0, f"required function is missing: {signature}")
    brace = source.find("{", start + len(signature))
    require(brace >= 0, f"required function body is missing: {signature}")

    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise PocketSyncSecurityError(f"unterminated function body: {signature}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def verify_public_recovery_reference(_project_root: Path) -> dict[str, object]:
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


def elf_section_records(path: Path) -> tuple[tuple[str, int], ...]:
    require(path.is_file() and not path.is_symlink(), "READY27 ELF is missing or linked")
    with path.open("rb") as handle:
        header = handle.read(52)
        require(len(header) == 52 and header[:7] == b"\x7fELF\x01\x01\x01",
                "READY27 ELF is not little-endian ELF32")
        section_offset = struct.unpack_from("<I", header, 32)[0]
        section_entry_size = struct.unpack_from("<H", header, 46)[0]
        section_count = struct.unpack_from("<H", header, 48)[0]
        string_index = struct.unpack_from("<H", header, 50)[0]
        file_size = path.stat().st_size
        require(section_offset >= 52 and section_entry_size == 40 and
                1 < section_count < 4096 and 0 < string_index < section_count and
                section_offset + section_entry_size * section_count <= file_size,
                "READY27 ELF section-table geometry is invalid")
        handle.seek(section_offset + section_entry_size * string_index)
        string_header = handle.read(section_entry_size)
        require(len(string_header) == section_entry_size,
                "READY27 ELF section-name header is truncated")
        string_offset, string_size = struct.unpack_from("<II", string_header, 16)
        require(string_size > 1 and string_offset + string_size <= file_size,
                "READY27 ELF section-name table exceeds the artifact")
        handle.seek(string_offset)
        string_table = handle.read(string_size)
        require(len(string_table) == string_size and string_table[-1:] == b"\0",
                "READY27 ELF section-name table is truncated")
        records: list[tuple[str, int]] = []
        for index in range(section_count):
            handle.seek(section_offset + section_entry_size * index)
            section_header = handle.read(section_entry_size)
            require(len(section_header) == section_entry_size,
                    "READY27 ELF section header is truncated")
            name_offset = struct.unpack_from("<I", section_header, 0)[0]
            section_size = struct.unpack_from("<I", section_header, 20)[0]
            require(name_offset < len(string_table), "READY27 ELF section name escaped its table")
            end = string_table.find(b"\0", name_offset)
            require(end >= name_offset, "READY27 ELF section name is unterminated")
            try:
                name = string_table[name_offset:end].decode("ascii")
            except UnicodeDecodeError as error:
                raise PocketSyncSecurityError("READY27 ELF section name is not ASCII") from error
            records.append((name, section_size))
    return tuple(records)


def elf_section_names(path: Path) -> tuple[str, ...]:
    return tuple(name for name, _size in elf_section_records(path))


def verify_exception_section_records(records: tuple[tuple[str, int], ...]) -> dict[str, int]:
    required = (".eh_frame", ".eh_frame_hdr")
    result: dict[str, int] = {}
    for required_name in required:
        matches = [size for name, size in records if name == required_name]
        require(len(matches) == 1 and matches[0] > 0,
                f"READY27 ELF lacks one nonempty {required_name} section")
        result[required_name] = matches[0]
    return result


def exception_elf_sections(path: Path) -> dict[str, int]:
    return verify_exception_section_records(elf_section_records(path))


def require_debug_stripped_elf(path: Path) -> None:
    names = elf_section_names(path)
    require(not any(name.startswith((".debug", ".zdebug")) for name in names),
            "READY27 ELF retains debug sections")
    require(".symtab" in names and ".strtab" in names,
            "READY27 ELF lost its audit symbol tables")


ABSOLUTE_HOST_PATH = re.compile(
    r"(?i)(?P<path>(?:\\\\|//)[A-Za-z0-9][A-Za-z0-9._-]*"
    r"[/\\][A-Za-z0-9$][A-Za-z0-9$._-]*)"
)
EMBEDDED_DRIVE_PATH = re.compile(r"(?i)[a-z]:[/\\]")
URI_SCHEME = re.compile(r"(?i)(?:^|[^a-z0-9+.-])([a-z][a-z0-9+.-]+)://")
SAFE_VIRTUAL_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+")


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
        SAFE_VIRTUAL_SEGMENT.fullmatch(part) is not None and
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
    return {
        "bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "value": value,
    }


def virtual_sdk_candidate_set_sha256(values: tuple[str, ...]) -> str:
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
            f"unrecognized virtual SDK probe state: {probe_state!r}")
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


def build_virtual_sdk_provenance(map_path: Path,
                                 packages_dir: Path,
                                 probe_state: str) -> tuple[dict[str, object], frozenset[str]]:
    probe_specs = virtual_sdk_probe_specs(probe_state)
    map_text = read_text(map_path)
    require("\0" not in map_text, "normalized map contains NUL during SDK provenance")
    slash_map = map_text.replace("\\", "/")
    linked_relatives: set[str] = set()
    for match in re.finditer(r"\$PACKAGES/([^\s()]+?\.a)\(", slash_map):
        relative_text = match.group(1)
        sdk_prefix = VIRTUAL_SDK_ARCHIVE_DIRECTORY.as_posix() + "/"
        if not relative_text.startswith(sdk_prefix):
            continue
        relative = Path(relative_text)
        require(not relative.is_absolute() and ".." not in relative.parts,
                "linked SDK archive escaped the package root")
        require(relative.is_relative_to(VIRTUAL_SDK_ARCHIVE_DIRECTORY),
                "linked SDK archive escaped its reviewed directory")
        linked_relatives.add(relative.as_posix())
    require(linked_relatives, "normalized map has no linked ESP32-C3 SDK archives")

    archive_records: list[dict[str, object]] = []
    approved_candidates: set[str] = set()
    for relative_text in sorted(linked_relatives):
        relative = Path(relative_text)
        archive = packages_dir / relative
        require(archive.is_file() and not archive.is_symlink(),
                f"map-linked SDK archive is missing or linked: {relative_text}")
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
            "sha256": hashlib.sha256(payload).hexdigest(),
        })

    bootloader_elf = packages_dir / VIRTUAL_SDK_BOOTLOADER_ELF_RELATIVE
    require(bootloader_elf.is_file() and not bootloader_elf.is_symlink(),
            "pinned DIO/80 MHz bootloader ELF is missing or linked")
    bootloader_elf_payload = bootloader_elf.read_bytes()
    require(
        len(bootloader_elf_payload) == VIRTUAL_SDK_BOOTLOADER_ELF_BYTES and
        hashlib.sha256(bootloader_elf_payload).hexdigest() ==
        VIRTUAL_SDK_BOOTLOADER_ELF_SHA256,
        "pinned DIO/80 MHz bootloader ELF changed",
    )
    bootloader_candidates = extract_virtual_sdk_candidates(bootloader_elf_payload)
    require(
        bootloader_candidates and
        EXPECTED_BOOTLOADER_SOURCE_VIRTUAL_PATH in bootloader_candidates,
        "pinned DIO/80 MHz bootloader ELF lost its required source candidate",
    )
    approved_candidates.update(bootloader_candidates)

    require(archive_records and approved_candidates,
            "map-linked SDK archives contain no approved virtual candidates")
    archive_by_path = {record["path"]: record for record in archive_records}
    probes: list[dict[str, int | str]] = []
    for relative, archive_bytes, archive_sha256, candidate, candidate_bytes, candidate_sha256 in probe_specs:
        relative_text = relative.as_posix()
        record = archive_by_path.get(relative_text)
        require(record is not None,
                f"required virtual SDK probe archive is not map-linked: {relative_text}")
        require(record["bytes"] == archive_bytes and record["sha256"] == archive_sha256,
                f"required virtual SDK probe archive changed: {relative_text}")
        require(candidate in approved_candidates and
                any(item["value"] == candidate for item in record["candidates"]),
                f"required virtual SDK probe candidate is absent: {candidate}")
        encoded = candidate.encode("ascii")
        require(len(encoded) == candidate_bytes and
                hashlib.sha256(encoded).hexdigest() == candidate_sha256,
                f"required virtual SDK probe candidate changed: {candidate}")
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
            "sha256": hashlib.sha256(bootloader_elf_payload).hexdigest(),
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


def is_allowed_virtual_artifact_path(candidate: str,
                                     virtual_project_roots: tuple[str, ...],
                                     virtual_sdk_candidates: frozenset[str]) -> bool:
    if (is_grammatical_virtual_sdk_path(candidate) and
            candidate in virtual_sdk_candidates):
        return True

    project_suffix = (
        candidate[len(VIRTUAL_PROJECT_PATH_PREFIX):]
        if candidate.startswith(VIRTUAL_PROJECT_PATH_PREFIX) else ""
    )
    project_parts = project_suffix.split("/") if project_suffix else []
    return (
        len(project_parts) >= 2 and
        project_parts[0] in virtual_project_roots and
        all(part not in ("", ".", "..") and
            SAFE_VIRTUAL_SEGMENT.fullmatch(part) is not None
            for part in project_parts[1:])
    )


def first_disallowed_artifact_path(value: str,
                                   virtual_project_roots: tuple[str, ...],
                                   virtual_sdk_candidates: frozenset[str]) -> str | None:
    scheme_drive_offsets = {
        match.start(1) + len(match.group(1)) - 1
        for match in URI_SCHEME.finditer(value)
        if match.group(1).lower() in ARTIFACT_PRIVACY_URI_SCHEMES
    }
    drive_match = next(
        (match for match in EMBEDDED_DRIVE_PATH.finditer(value)
         if match.start() not in scheme_drive_offsets),
        None,
    )
    if drive_match is not None:
        return value[drive_match.start():]
    uri_authority_offsets = frozenset(
        match.end(1) + 1
        for match in URI_SCHEME.finditer(value)
        if match.group(1).lower() in ARTIFACT_PRIVACY_URI_SCHEMES
    )
    for sdk_match in re.finditer(
            r"(?:^|[\s\"'=([{])(?P<path>//IDF.*)", value):
        sdk_candidate = value[sdk_match.start("path"):]
        if not (is_grammatical_virtual_sdk_path(sdk_candidate) and
                sdk_candidate in virtual_sdk_candidates):
            return sdk_candidate
    for match in ABSOLUTE_HOST_PATH.finditer(value):
        candidate = value[match.start("path"):]
        if match.start("path") in uri_authority_offsets:
            continue
        if is_allowed_virtual_artifact_path(
                candidate, virtual_project_roots, virtual_sdk_candidates):
            continue
        return candidate
    return None


def artifact_privacy_needles(project_root: Path, build_dir: Path,
                             packages_dir: Path) -> tuple[str, ...]:
    needles = {
        "c:/users/", "c:\\users\\", "x:/", "x:\\",
        PRIVATE_BUILD_DIRECTORY_NAME.lower(),
    }
    for root in (project_root, build_dir, packages_dir, packages_dir.parent, Path.home()):
        value = str(root.resolve()).rstrip("/\\")
        if value:
            needles.add(value.lower())
            needles.add(value.replace("\\", "/").lower())
    profile_name = Path.home().name.strip().lower()
    if profile_name:
        needles.add(f"/{profile_name}/")
        needles.add(f"\\{profile_name}\\")
    return tuple(sorted(needles, key=len, reverse=True))


def require_artifact_privacy(paths: tuple[Path, ...], project_root: Path, build_dir: Path,
                             packages_dir: Path,
                             virtual_project_roots: tuple[str, ...],
                             virtual_sdk_candidates: frozenset[str]) -> None:
    require(virtual_project_roots == VIRTUAL_PROJECT_PATH_ROOTS,
            "artifact privacy virtual-project roots are not the manifest-bound allowlist")
    needles = artifact_privacy_needles(project_root, build_dir, packages_dir)
    for path in paths:
        require(path.is_file() and not path.is_symlink(),
                f"artifact privacy input is missing or linked: {path.name}")
        payload = path.read_bytes()
        for match in re.finditer(rb"(?:(?<=\x00)|^)[\x20-\x7e]{4,}(?=\x00|$)", payload):
            value = match.group(0).decode("ascii")
            require(first_disallowed_artifact_path(
                        value, virtual_project_roots, virtual_sdk_candidates) is None,
                    f"published {path.name} contains a host-absolute ASCII path")
        for alignment in (0, 1):
            for match in re.finditer(
                rb"(?:^|\x00\x00)((?:[\x20-\x7e]\x00){4,})(?=\x00\x00|$)",
                payload[alignment:],
            ):
                value = match.group(1).decode("utf-16le")
                require(first_disallowed_artifact_path(
                            value, virtual_project_roots, virtual_sdk_candidates) is None,
                        f"published {path.name} contains a host-absolute UTF-16LE path")
        lowered_payload = payload.lower()
        for needle in needles:
            require(needle.encode("utf-8") not in lowered_payload and
                    needle.encode("utf-16le") not in lowered_payload,
                    f"published {path.name} contains a private/local path marker")


def require_map_privacy(path: Path, project_root: Path, build_dir: Path, packages_dir: Path,
                        virtual_project_roots: tuple[str, ...],
                        virtual_sdk_candidates: frozenset[str]) -> None:
    text = read_text(path)
    for line in text.splitlines():
        require(first_disallowed_artifact_path(
                    line, virtual_project_roots, virtual_sdk_candidates) is None,
                "published linker map contains a host-absolute path")
    lowered_payload = text.lower().encode("utf-8")
    for needle in artifact_privacy_needles(project_root, build_dir, packages_dir):
        require(needle.encode("utf-8") not in lowered_payload,
                "published linker map contains a private/local path marker")


def verify_artifact_privacy_scanner_self_test(project_root: Path, packages_dir: Path,
                                              probe_state: str) -> None:
    require(len(EXPECTED_MINIZ_VIRTUAL_SOURCE_PATH.encode("ascii")) == 45,
            "virtual miniz path probe is no longer the exact 45-byte candidate")
    probe_specs = virtual_sdk_probe_specs(probe_state)
    bootloader_candidate = probe_specs[0][3]
    app_update_candidate = probe_specs[1][3]
    embedded_candidate = "//IDF/components/heap/tlsf/tlsf_block_functions.h"
    require(
        extract_virtual_sdk_candidates(
            ("\0/" + embedded_candidate + "\0").encode("ascii")
        ) == {embedded_candidate},
        "virtual SDK provenance lost GCC's ///IDF archive spelling",
    )
    require(
        not extract_virtual_sdk_candidates(
            ("evil" + embedded_candidate + "\0").encode("ascii")
        ),
        "virtual SDK provenance accepted an embedded unbounded prefix",
    )
    with tempfile.TemporaryDirectory(prefix="xtinct-privacy-verifier-") as temporary_name:
        root = Path(temporary_name)
        provenance_map = root / "firmware.map"
        provenance_map.write_text(
            f"$PACKAGES/{BOOTLOADER_SUPPORT_ARCHIVE_RELATIVE.as_posix()}"
            "(bootloader_flash.c.o)\n"
            f"$PACKAGES/{APP_UPDATE_ARCHIVE_RELATIVE.as_posix()}"
            "(esp_ota_ops.c.o)\n",
            encoding="utf-8",
        )
        sdk_provenance, sdk_candidates = build_virtual_sdk_provenance(
            provenance_map, packages_dir, probe_state
        )
        require(sdk_provenance["probe_state"] == probe_state and
                sdk_provenance["candidate_set"]["count"] == len(sdk_candidates) and
                bootloader_candidate in sdk_candidates and
                app_update_candidate in sdk_candidates,
                "virtual SDK provenance self-test lost exact map-linked probes")
        alternate_state = (VIRTUAL_SDK_REBUILT_PROBE_STATE
                           if probe_state == VIRTUAL_SDK_VENDOR_PROBE_STATE
                           else VIRTUAL_SDK_VENDOR_PROBE_STATE)
        try:
            build_virtual_sdk_provenance(provenance_map, packages_dir, alternate_state)
        except PocketSyncSecurityError:
            pass
        else:
            raise PocketSyncSecurityError(
                "virtual SDK provenance accepted packages under the wrong probe state")
        try:
            virtual_sdk_probe_specs("unreviewed-probe-state")
        except PocketSyncSecurityError:
            pass
        else:
            raise PocketSyncSecurityError(
                "virtual SDK probe selector accepted an unreviewed state")
        positive = root / "published-positive.bin"
        positive.write_bytes(
            (EXPECTED_MINIZ_VIRTUAL_SOURCE_PATH + "\0").encode("ascii") +
            (bootloader_candidate + "\0" + app_update_candidate + "\0").encode("ascii")
        )
        require_artifact_privacy(
            (positive,), project_root, root, packages_dir, VIRTUAL_PROJECT_PATH_ROOTS,
            sdk_candidates,
        )
        bootloader_positive = root / "published-positive-bootloader.bin"
        bootloader_positive.write_bytes(
            (EXPECTED_BOOTLOADER_SOURCE_VIRTUAL_PATH + "\0").encode("ascii")
        )
        require_artifact_privacy(
            (bootloader_positive,), project_root, root, packages_dir,
            VIRTUAL_PROJECT_PATH_ROOTS, sdk_candidates,
        )
        machine_code_positive = root / "published-positive-machine-code-lookalike.bin"
        machine_code_positive.write_bytes(
            positive.read_bytes() + b"\0\x5c\x5cX<`\x5cX<d\x5cX<h\x5cX<\0"
        )
        require_artifact_privacy(
            (machine_code_positive,), project_root, root, packages_dir,
            VIRTUAL_PROJECT_PATH_ROOTS, sdk_candidates,
        )
        for label, payload in (
            ("FTP-URI", b"ftp://example.invalid/article\0"),
            ("HTTP-URI", b"https://example.invalid/article\0"),
            ("PLAIN-HTTP-URI", b"http://example.invalid/article\0"),
            ("EMBEDDED-HTTP-URI", b"url=https://example.invalid/article\0"),
        ):
            safe_uri = root / f"published-positive-{label}.bin"
            safe_uri.write_bytes(positive.read_bytes() + payload)
            require_artifact_privacy(
                (safe_uri,), project_root, root, packages_dir,
                VIRTUAL_PROJECT_PATH_ROOTS, sdk_candidates,
            )

        rejected = (
            ("ASCII-HOST", b"debug=D:/other-host/private/source.cpp\0"),
            ("UTF16-HOST", b"\0" +
             "debug=D:\\other-host\\private\\source.cpp\0".encode("utf-16le")),
            ("EMBEDDED-DRIVE", b"prefixD:/secret/file.cpp\0"),
            ("URI-DRIVE", b"uri:file:///D:/secret/file.cpp\0"),
            ("EMBEDDED-DRIVE-UTF16", b"\0" +
             "prefixD:/secret/file.cpp\0".encode("utf-16le")),
            ("URI-DRIVE-UTF16", b"\0" +
             "uri:file:///D:/secret/file.cpp\0".encode("utf-16le")),
            ("PREFIX-UNC-SLASH", b"prefix//server/share/file.cpp\0"),
            ("PREFIX-UNC-BACKSLASH", b"prefix\\\\server\\share\\file.cpp\0"),
            ("PREFIX-UNC-SLASH-UTF16", b"\0" +
             "prefix//server/share/file.cpp\0".encode("utf-16le")),
            ("PREFIX-UNC-BACKSLASH-UTF16", b"\0" +
             "prefix\\\\server\\share\\file.cpp\0".encode("utf-16le")),
            ("URI-LATER-UNC-SLASH",
             b"http://host/path//server/share/file.cpp\0"),
            ("URI-LATER-UNC-BACKSLASH",
             b"https://host/path\\\\server\\share\\file.cpp\0"),
            ("USER-ROOT-RAW", b"prefixC:/Users/person/private.cpp"),
            ("PROJECT-ALIAS-RAW", b"prefixX:/private.cpp"),
            ("PRIVATE-BUILD-RAW", b"prefix.xtinct-build-authoritative\\default"),
            ("IDF-VALID-UNPROVEN", b"//IDF\\components\\unproven\\file.cpp\0"),
            ("IDF-REAL-UNC", b"\\\\IDF\\components\\app_update\\esp_ota_ops.c\0"),
            ("IDF-CASE", b"//idf/components/app_update/esp_ota_ops.c\0"),
            ("IDF-REPEATED", b"//IDF//components/app_update/esp_ota_ops.c\0"),
            ("IDF-EMPTY", b"//IDF/components//esp_ota_ops.c\0"),
            ("IDF-DOTDOT", b"//IDF/components/../private.c\0"),
            ("IDF-DRIVE", b"//IDF/components/C:/private.c\0"),
            ("IDF-LOOKALIKE", b"//IDF/component/app_update/esp_ota_ops.c\0"),
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
            ("UTF16-DOTDOT", b"\0" +
             "//xtinct/source/../private/file.cpp\0".encode("utf-16le")),
        )
        for label, payload in rejected:
            mutated = root / f"published-mutated-{label}.bin"
            mutated.write_bytes(positive.read_bytes() + payload)
            try:
                require_artifact_privacy(
                    (mutated,), project_root, root, packages_dir, VIRTUAL_PROJECT_PATH_ROOTS,
                    sdk_candidates,
                )
            except PocketSyncSecurityError:
                continue
            raise PocketSyncSecurityError(
                f"artifact privacy verifier accepted the {label} published-artifact mutation"
            )
        require_map_privacy(
            provenance_map, project_root, root, packages_dir, VIRTUAL_PROJECT_PATH_ROOTS,
            sdk_candidates,
        )
        mutated_map = root / "firmware-mutated.map"
        mutated_map.write_text(
            provenance_map.read_text(encoding="utf-8") + "D:/other-host/private/object.o\n",
            encoding="utf-8",
        )
        try:
            require_map_privacy(
                mutated_map, project_root, root, packages_dir, VIRTUAL_PROJECT_PATH_ROOTS,
                sdk_candidates,
            )
        except PocketSyncSecurityError:
            pass
        else:
            raise PocketSyncSecurityError("artifact privacy verifier accepted a mutated map path")


def require_hashed_file(path: Path, record: object, label: str) -> None:
    require(isinstance(record, dict) and set(record) == {"bytes", "sha256"},
            f"{label} evidence record is invalid")
    expected_bytes = record.get("bytes")
    expected_sha256 = record.get("sha256")
    require(isinstance(expected_bytes, int) and expected_bytes > 0,
            f"{label} evidence byte count is invalid")
    require(isinstance(expected_sha256, str) and
            re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
            f"{label} evidence SHA-256 is invalid")
    require(path.is_file() and not path.is_symlink(), f"{label} evidence file is missing or linked")
    require(path.stat().st_size == expected_bytes, f"{label} evidence byte count changed")
    require(sha256_file(path) == expected_sha256, f"{label} evidence SHA-256 changed")


def require_hash_record(record: object, label: str) -> None:
    require(isinstance(record, dict) and set(record) == {"bytes", "sha256"},
            f"{label} hash record is invalid")
    require(isinstance(record.get("bytes"), int) and record["bytes"] > 0,
            f"{label} byte count is invalid")
    require(isinstance(record.get("sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is not None,
            f"{label} SHA-256 is invalid")


def system_powershell() -> Path:
    windows_root = Path(os.environ.get("SystemRoot", ""))
    require(windows_root.is_absolute(), "SystemRoot is unavailable for source snapshot verification")
    executable = windows_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    require(executable.is_file() and not executable.is_symlink(),
            "system Windows PowerShell is unavailable for source snapshot verification")
    return executable


def source_snapshot(project_root: Path) -> dict[str, int | str]:
    snapshotter = project_root / SOURCE_SNAPSHOT_SCRIPT
    require(snapshotter.is_file() and not snapshotter.is_symlink(),
            "source snapshotter is missing or linked")
    result = subprocess.run(
        [str(system_powershell()), "-NoLogo", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-File", str(snapshotter),
         "-SourceRoot", str(project_root)],
        cwd=project_root,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise PocketSyncSecurityError(
            f"source snapshotter failed: {(result.stderr or result.stdout).strip()}"
        )
    require(not result.stderr, "source snapshotter wrote to stderr")
    try:
        snapshot = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PocketSyncSecurityError("source snapshotter output is not JSON") from error
    require(isinstance(snapshot, dict) and set(snapshot) == {"schema", "root", "files", "sha256"},
            "source snapshot envelope is invalid")
    require(snapshot.get("schema") == 1 and isinstance(snapshot.get("files"), int) and
            snapshot["files"] > 0 and isinstance(snapshot.get("sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", snapshot["sha256"]) is not None,
            "source snapshot values are invalid")
    require(Path(snapshot.get("root", "")).resolve() == project_root.resolve(),
            "source snapshot root changed")
    return {"files": snapshot["files"], "sha256": snapshot["sha256"]}


def verify_exception_build_evidence(project_root: Path, build_dir: Path,
                                    record: object) -> dict[str, object]:
    require(isinstance(record, dict) and set(record) == {"bytes", "path", "sha256"},
            "exception build-evidence manifest record is invalid")
    expected_relative = (
        Path(LINKED_PROVENANCE_DIRECTORY) / EXCEPTION_BUILD_EVIDENCE_NAME
    ).as_posix()
    require(record.get("path") == expected_relative,
            "exception build-evidence path changed")
    evidence_path = build_dir / Path(expected_relative)
    require_hashed_file(
        evidence_path,
        {"bytes": record.get("bytes"), "sha256": record.get("sha256")},
        "C++ exception build",
    )
    try:
        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PocketSyncSecurityError("C++ exception build evidence is not UTF-8 JSON") from error
    require(isinstance(evidence, dict) and set(evidence) == {
        "construction", "policy", "runtime_probe", "schema", "translation_units"
    } and evidence.get("schema") == 1 and evidence.get("policy") == EXCEPTION_POLICY,
            "C++ exception build evidence envelope is invalid")

    guard = project_root / EXCEPTION_GUARD_RELATIVE
    require(guard.is_file() and not guard.is_symlink(),
            "C++ exception force-include guard is missing or linked")
    expected_guard = {
        "bytes": guard.stat().st_size,
        "path": EXCEPTION_GUARD_RELATIVE.as_posix(),
        "sha256": sha256_file(guard),
    }
    construction = evidence.get("construction")
    require(construction == {
        "effective_exception_switches": ["-fexceptions"],
        "guard": expected_guard,
        "policy": EXCEPTION_POLICY,
        "schema": 1,
    }, "effective C++ exception construction evidence is invalid")

    runtime_probe = project_root / EXCEPTION_RUNTIME_PROBE_RELATIVE
    require(runtime_probe.is_file() and not runtime_probe.is_symlink(),
            "actual allocator throw/catch runtime probe is missing or linked")
    require(evidence.get("runtime_probe") == {
        "bytes": runtime_probe.stat().st_size,
        "path": EXCEPTION_RUNTIME_PROBE_RELATIVE.as_posix(),
        "proof": "real-bad-alloc-throw-catch-transactional-v1",
        "sha256": sha256_file(runtime_probe),
        "test": EXCEPTION_RUNTIME_PROBE_TEST,
    }, "actual allocator throw/catch runtime-probe evidence is invalid")

    translation_units = evidence.get("translation_units")
    require(isinstance(translation_units, dict) and set(translation_units) == {
        "count", "units", "units_sha256"
    }, "C++ translation-unit exception evidence is invalid")
    units = translation_units.get("units")
    require(isinstance(units, list) and 0 < len(units) <= 4096 and
            translation_units.get("count") == len(units),
            "C++ translation-unit exception evidence count is invalid")
    dependencies: set[str] = set()
    for unit in units:
        require(isinstance(unit, dict) and set(unit) == {
            "dependency", "dependency_bytes", "dependency_sha256", "source"
        }, "C++ translation-unit exception record is invalid")
        dependency = unit.get("dependency")
        source = unit.get("source")
        require(isinstance(dependency, str) and dependency.endswith(".cpp.d") and
                dependency not in dependencies and "\\" not in dependency and
                not dependency.startswith(("/", "../")) and "/../" not in dependency,
                "C++ translation-unit dependency path is unsafe or repeated")
        require(isinstance(source, str) and source.endswith(".cpp") and
                "\\" not in source and not source.startswith(("/", "../")) and
                "/../" not in source and re.match(r"(?i)^[a-z]:", source) is None,
                "C++ translation-unit source path is unsafe")
        require(isinstance(unit.get("dependency_bytes"), int) and
                unit["dependency_bytes"] > 0 and
                isinstance(unit.get("dependency_sha256"), str) and
                re.fullmatch(r"[0-9a-f]{64}", unit["dependency_sha256"]) is not None,
                "C++ translation-unit dependency hash record is invalid")
        dependencies.add(dependency)
    canonical = json.dumps(units, ensure_ascii=True, separators=(",", ":"),
                           sort_keys=True).encode("ascii")
    require(translation_units.get("units_sha256") == hashlib.sha256(canonical).hexdigest(),
            "C++ translation-unit exception evidence set digest changed")

    # The private pre-publication pass still has every generated .d file.  Prove
    # the force-include was recorded in each one and that none were omitted.
    construction_seed = build_dir / EXCEPTION_CONSTRUCTION_EVIDENCE_NAME
    if construction_seed.exists() or construction_seed.is_symlink():
        require(construction_seed.is_file() and not construction_seed.is_symlink(),
                "private exception construction seed is missing or linked")
        try:
            seed = json.loads(construction_seed.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise PocketSyncSecurityError(
                "private exception construction seed is not UTF-8 JSON"
            ) from error
        require(seed == construction,
                "private exception construction seed differs from published evidence")
        actual = sorted(
            path.relative_to(build_dir).as_posix()
            for path in build_dir.rglob("*.cpp.d")
            if not path.is_relative_to(build_dir / LINKED_PROVENANCE_DIRECTORY)
        )
        require(actual == sorted(dependencies),
                "private C++ dependency set differs from exception evidence")
        guard_suffix = EXCEPTION_GUARD_RELATIVE.as_posix()
        for dependency in actual:
            path = build_dir / dependency
            require(path.is_file() and not path.is_symlink() and
                    guard_suffix in read_text(path).replace("\\", "/"),
                    f"private C++ dependency lacks exception guard: {dependency}")
    return evidence


def verify_evidence_manifest(project_root: Path, build_dir: Path, packages_dir: Path,
                             libdeps_dir: Path, manifest_path: Path
                             ) -> tuple[str, tuple[str, ...], frozenset[str]]:
    project_root = project_root.resolve()
    build_dir = build_dir.resolve()
    packages_dir = packages_dir.resolve()
    libdeps_dir = libdeps_dir.resolve()
    require(manifest_path.is_file() and not manifest_path.is_symlink(),
            "linked evidence manifest is missing or linked")
    manifest_path = manifest_path.resolve()
    require(manifest_path.parent == (build_dir / LINKED_PROVENANCE_DIRECTORY).resolve(),
            "linked evidence manifest is outside the published provenance directory")
    require(manifest_path.name == LINKED_EVIDENCE_MANIFEST_NAME,
            "linked evidence manifest has an unexpected name")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise PocketSyncSecurityError("linked evidence manifest is not valid UTF-8 JSON") from error

    require(isinstance(manifest, dict) and set(manifest) == {
        "schema", "artifacts", "dependencies", "exceptions", "identity", "nimconfig", "raw_map",
        "reproducibility", "sdkconfig", "selection", "source", "verifier"
    }, "linked evidence manifest envelope is invalid")
    require(manifest.get("schema") == 4, "linked evidence manifest schema is unsupported")

    require(manifest.get("identity") == {
        "build_id": READY_BUILD_ID,
        "release_label": READY_RELEASE_LABEL,
        "version": READY_VERSION,
    }, "READY27 manifest identity is invalid")

    source_record = manifest.get("source")
    require(isinstance(source_record, dict) and set(source_record) == {
        "files", "sha256", "snapshotter"
    }, "source evidence record is invalid")
    require(isinstance(source_record.get("files"), int) and source_record["files"] > 0 and
            isinstance(source_record.get("sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", source_record["sha256"]) is not None,
            "source evidence values are invalid")
    snapshotter_record = source_record.get("snapshotter")
    require(isinstance(snapshotter_record, dict) and set(snapshotter_record) == {
        "bytes", "path", "sha256"
    } and snapshotter_record.get("path") == SOURCE_SNAPSHOT_SCRIPT,
            "source snapshotter evidence record is invalid")
    require_hashed_file(project_root / SOURCE_SNAPSHOT_SCRIPT,
                        {"bytes": snapshotter_record.get("bytes"),
                         "sha256": snapshotter_record.get("sha256")},
                        "source snapshotter")
    current_snapshot = source_snapshot(project_root)
    require(current_snapshot == {
        "files": source_record["files"], "sha256": source_record["sha256"]
    }, "source snapshot no longer matches the linked artifact manifest")

    reproducibility_record = manifest.get("reproducibility")
    require(isinstance(reproducibility_record, dict) and set(reproducibility_record) == {
        "artifact_privacy", "build_cache", "elf_debug", "path_map_targets",
        "private_build_directory", "project_alias", "source_date_epoch", "timezone",
        "recovery_reference", "virtual_project_paths", "virtual_sdk_paths", "webserver_parser"
    }, "reproducible-build evidence envelope is invalid")
    require({key: value for key, value in reproducibility_record.items()
              if key not in ("artifact_privacy", "build_cache", "elf_debug", "recovery_reference",
                            "virtual_project_paths", "virtual_sdk_paths", "webserver_parser")} == {
        "path_map_targets": list(REPRODUCIBLE_PATH_MAP_TARGETS),
        "private_build_directory": ".xtinct-build-authoritative",
        "project_alias": "X:/",
        "source_date_epoch": REPRODUCIBLE_SOURCE_DATE_EPOCH,
        "timezone": "UTC",
    }, "reproducible-build evidence is invalid")
    require(reproducibility_record.get("artifact_privacy") == {
        "marker_classes": list(ARTIFACT_PRIVACY_MARKER_CLASSES),
        "policy": ARTIFACT_PRIVACY_POLICY,
        "scanner": ARTIFACT_PRIVACY_SCANNER,
        "semantic_encodings": ["ASCII", "UTF-16LE"],
        "uri_schemes": list(ARTIFACT_PRIVACY_URI_SCHEMES),
    }, "artifact privacy evidence is invalid")
    require(reproducibility_record.get("recovery_reference") ==
            verify_public_recovery_reference(project_root),
            "Public recovery reference evidence is invalid")
    parser_record = reproducibility_record.get("webserver_parser")
    require(isinstance(parser_record, dict) and parser_record == {
        "checker": {
            "bytes": EXPECTED_WEB_SERVER_PARSER_CHECKER_BYTES,
            "passes": EXPECTED_WEB_SERVER_PARSER_BEHAVIOR_PASSES,
            "path": WEB_SERVER_PARSER_CHECKER_RELATIVE.as_posix(),
            "sha256": EXPECTED_WEB_SERVER_PARSER_CHECKER_SHA256,
        },
        "limits": dict(WEB_SERVER_PARSER_LIMITS),
        "original": {
            "bytes": EXPECTED_WEB_SERVER_PARSER_BYTES,
            "sha256": EXPECTED_WEB_SERVER_PARSER_SHA256,
        },
        "patch": {
            "bytes": EXPECTED_PATCHED_WEB_SERVER_PARSER_BYTES,
            "path": WEB_SERVER_PARSER_PATCH_RELATIVE.as_posix(),
            "sha256": EXPECTED_PATCHED_WEB_SERVER_PARSER_SHA256,
        },
        "policy": WEB_SERVER_PARSER_POLICY,
        "target": WEB_SERVER_PARSER_RELATIVE.as_posix(),
        "transient": True,
    }, "bounded WebServer parser evidence is invalid")
    require_hashed_file(
        packages_dir / WEB_SERVER_PARSER_RELATIVE,
        parser_record["original"],
        "restored Arduino WebServer parser",
    )
    require_hashed_file(
        project_root / WEB_SERVER_PARSER_PATCH_RELATIVE,
        {
            "bytes": parser_record["patch"]["bytes"],
            "sha256": parser_record["patch"]["sha256"],
        },
        "bounded Arduino WebServer parser patch",
    )
    require_hashed_file(
        project_root / WEB_SERVER_PARSER_CHECKER_RELATIVE,
        {
            "bytes": parser_record["checker"]["bytes"],
            "sha256": parser_record["checker"]["sha256"],
        },
        "bounded Arduino WebServer parser behavior checker",
    )
    build_cache_record = reproducibility_record.get("build_cache")
    require(isinstance(build_cache_record, dict) and set(build_cache_record) == {
        "directory", "policy", "project_cache"
    } and build_cache_record.get("directory") == ".cache" and
            build_cache_record.get("policy") == "fresh-private-per-run",
            "authoritative build-cache evidence is invalid")
    project_cache_record = build_cache_record.get("project_cache")
    require(isinstance(project_cache_record, dict) and set(project_cache_record) == {
        "bytes", "entries", "metadata_sha256"
    } and isinstance(project_cache_record.get("bytes"), int) and project_cache_record["bytes"] >= 0 and
            isinstance(project_cache_record.get("entries"), int) and project_cache_record["entries"] >= 0 and
            isinstance(project_cache_record.get("metadata_sha256"), str) and
            re.fullmatch(r"[0-9a-f]{64}", project_cache_record["metadata_sha256"]) is not None,
            "project build-cache evidence is invalid")
    require(reproducibility_record.get("elf_debug") == {
        "link_flag": ELF_DEBUG_STRIP_LINK_FLAG,
        "stripped": True,
        "symbol_tables_retained": True,
    }, "ELF debug-stripping evidence is invalid")
    raw_map_record = manifest.get("raw_map")
    require_hash_record(raw_map_record, "private raw firmware.map")
    virtual_sdk_record = reproducibility_record.get("virtual_sdk_paths")
    expected_virtual_sdk_record, virtual_sdk_candidates = build_virtual_sdk_provenance(
        build_dir / "firmware.map", packages_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE
    )
    expected_virtual_sdk_record["raw_map"] = raw_map_record
    require(virtual_sdk_record == expected_virtual_sdk_record,
            "virtual SDK path archive/candidate provenance is invalid")
    virtual_project_record = reproducibility_record.get("virtual_project_paths")
    require(isinstance(virtual_project_record, dict) and set(virtual_project_record) == {
        "prefix", "roots", "source_probe"
    } and virtual_project_record.get("prefix") == VIRTUAL_PROJECT_PATH_PREFIX and
            virtual_project_record.get("roots") == list(VIRTUAL_PROJECT_PATH_ROOTS),
            "virtual project path provenance is invalid")
    source_probe_record = virtual_project_record.get("source_probe")
    require(source_probe_record == {
        "bytes": EXPECTED_MINIZ_SOURCE_BYTES,
        "path": MINIZ_SOURCE_RELATIVE.as_posix(),
        "sha256": EXPECTED_MINIZ_SOURCE_SHA256,
        "virtual_path": EXPECTED_MINIZ_VIRTUAL_SOURCE_PATH,
    }, "virtual project source-probe provenance is invalid")
    require_hashed_file(
        project_root / MINIZ_SOURCE_RELATIVE,
        {"bytes": EXPECTED_MINIZ_SOURCE_BYTES, "sha256": EXPECTED_MINIZ_SOURCE_SHA256},
        "virtual project source probe",
    )

    artifacts = manifest.get("artifacts")
    require(isinstance(artifacts, dict) and
            set(artifacts) == set(MANIFEST_ARTIFACT_NAMES),
            "linked evidence artifact set is invalid")
    for name in MANIFEST_ARTIFACT_NAMES:
        require_hashed_file(build_dir / name, artifacts[name], name)
    require(artifacts["boot_app0.bin"] == {
        "bytes": BOOT_APP0_BYTES,
        "sha256": EXPECTED_BOOT_APP0_SHA256,
    }, "boot_app0.bin is not the exact pinned Arduino OTA-data initializer")
    require_hashed_file(
        packages_dir / BOOT_APP0_PACKAGE_RELATIVE,
        artifacts["boot_app0.bin"],
        "pinned Arduino boot_app0.bin",
    )
    require_debug_stripped_elf(build_dir / "firmware.elf")

    raw_map_path = build_dir / LINKED_PROVENANCE_DIRECTORY / PRIVATE_DEPENDENCY_DIRECTORY / RAW_MAP_EVIDENCE_NAME
    if raw_map_path.exists() or raw_map_path.is_symlink():
        require_hashed_file(raw_map_path, raw_map_record, "private raw firmware.map")

    dependencies = manifest.get("dependencies")
    require(isinstance(dependencies, dict) and set(dependencies) == set(LINKED_DEPENDENCY_NAMES),
            "linked dependency evidence set is invalid")
    provenance_dir = build_dir / LINKED_PROVENANCE_DIRECTORY
    private_dir = provenance_dir / PRIVATE_DEPENDENCY_DIRECTORY
    for name in LINKED_DEPENDENCY_NAMES:
        record = dependencies[name]
        require(isinstance(record, dict) and set(record) == {"normalized", "raw"},
                f"{name} dependency evidence record is invalid")
        require_hashed_file(provenance_dir / f"{name}{NORMALIZED_DEPENDENCY_SUFFIX}",
                            record["normalized"], f"normalized {name}")
        raw_path = private_dir / name
        if raw_path.exists() or raw_path.is_symlink():
            require_hashed_file(raw_path, record["raw"], f"private raw {name}")
        else:
            require_hash_record(record["raw"], f"private raw {name}")

    sdkconfig_record = manifest.get("sdkconfig")
    require(isinstance(sdkconfig_record, dict) and set(sdkconfig_record) == {
        "artifact", "bytes", "path", "sha256"
    },
            "sdkconfig evidence record is invalid")
    expected_sdkconfig_relative = (
        "framework-arduinoespressif32-libs/esp32c3/dio_qspi/include/sdkconfig.h"
    )
    require(sdkconfig_record.get("path") == expected_sdkconfig_relative,
            "sdkconfig evidence path changed")
    require(sdkconfig_record.get("artifact") == EFFECTIVE_SDKCONFIG_ARTIFACT_NAME,
            "published sdkconfig artifact name changed")
    require_hashed_file(packages_dir / expected_sdkconfig_relative,
                        {"bytes": sdkconfig_record.get("bytes"), "sha256": sdkconfig_record.get("sha256")},
                        "effective sdkconfig")
    require(artifacts[EFFECTIVE_SDKCONFIG_ARTIFACT_NAME] == {
        "bytes": sdkconfig_record.get("bytes"),
        "sha256": sdkconfig_record.get("sha256"),
    }, "published sdkconfig does not match the effective package sdkconfig")

    exception_record = manifest.get("exceptions")
    require(isinstance(exception_record, dict) and set(exception_record) == {
        "build_evidence", "elf_sections", "generated_sdkconfig", "linked_symbols"
    }, "C++ exception manifest evidence envelope is invalid")
    verify_exception_build_evidence(
        project_root, build_dir, exception_record.get("build_evidence")
    )
    require(exception_record.get("elf_sections") ==
            exception_elf_sections(build_dir / "firmware.elf"),
            "C++ exception ELF section evidence changed")
    require(exception_record.get("generated_sdkconfig") ==
            verify_exception_sdkconfig(parse_defines(packages_dir / expected_sdkconfig_relative)),
            "generated C++ exception sdkconfig evidence changed")
    require(exception_record.get("linked_symbols") == list(EXCEPTION_REQUIRED_SYMBOLS),
            "linked C++ exception symbol evidence changed")

    nimconfig_record = manifest.get("nimconfig")
    expected_nimconfig_relative = "default/NimBLE-Arduino/src/nimconfig.h"
    expected_nimconfig_logical = "$LIBDEPS/" + expected_nimconfig_relative
    require(isinstance(nimconfig_record, dict) and set(nimconfig_record) == {"bytes", "path", "sha256"},
            "nimconfig evidence record is invalid")
    require(nimconfig_record.get("path") == expected_nimconfig_logical,
            "nimconfig evidence path changed")
    require_hashed_file(libdeps_dir / expected_nimconfig_relative,
                        {"bytes": nimconfig_record.get("bytes"), "sha256": nimconfig_record.get("sha256")},
                        "effective nimconfig")
    require(nimconfig_record.get("sha256") == PINNED_NIMCONFIG_PATCH_SHA256,
            "nimconfig evidence does not match the pinned patch hash")

    selection = manifest.get("selection")
    require(selection == {
        "NimBLEServer.cpp.d": (
            "$PACKAGES/framework-arduinoespressif32-libs/esp32c3/dio_qspi/include/sdkconfig.h"
        ),
        "PocketSyncBleServer.cpp.d": expected_nimconfig_logical,
    }, "selected dependency paths changed")

    verifier_record = manifest.get("verifier")
    require(isinstance(verifier_record, dict) and set(verifier_record) == {"bytes", "sha256"},
            "linked verifier evidence record is invalid")
    require_hashed_file(Path(__file__).resolve(), verifier_record, "linked verifier")
    return (
        sha256_file(manifest_path), tuple(virtual_project_record["roots"]),
        virtual_sdk_candidates,
    )


def run_checked(command: list[str], cwd: Path, label: str) -> str:
    result = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise PocketSyncSecurityError(f"{label} failed: {detail}")
    return result.stdout


def require_virtual_sdk_probe_state_wiring(build_wrapper: str, verifier: str) -> None:
    wrapper_required = (
        (
            "verify_pocket_sync_source_policy_files(\n"
            "            PROJECT_ROOT, packages_dir, libdeps_dir, VIRTUAL_SDK_VENDOR_PROBE_STATE",
            "build wrapper source gate is not vendor-state-bound",
        ),
        (
            "normalized_map, packages_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE",
            "build wrapper linked provenance is not rebuilt-state-bound",
        ),
        (
            "virtual_sdk_candidates, VIRTUAL_SDK_REBUILT_PROBE_STATE,",
            "build wrapper linked privacy gate is not rebuilt-state-bound",
        ),
    )
    verifier_required = (
        (
            'build_dir / "firmware.map", packages_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE',
            "manifest verification is not rebuilt-state-bound",
            3,
        ),
        (
            "firmware_map, packages_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE",
            "linked-image verification is not rebuilt-state-bound",
            2,
        ),
        (
            "probe_state = (VIRTUAL_SDK_REBUILT_PROBE_STATE if args.build_dir is not None\n"
            "                   else VIRTUAL_SDK_VENDOR_PROBE_STATE)",
            "CLI source/linked probe-state selection changed",
            1,
        ),
        (
            "verify_source_policy(args.project_root, args.packages_dir, args.libdeps_dir, probe_state)",
            "CLI no longer passes its fail-closed probe-state selection",
            2,
        ),
    )
    for fragment, message in wrapper_required:
        require(build_wrapper.count(fragment) == 1, message)
    for fragment, message, expected_count in verifier_required:
        # Counts include executable call sites plus pinned source/mutation
        # tokens in this checker. Any addition, removal, or substitution fails.
        require(verifier.count(fragment) == expected_count, message)


def verify_virtual_sdk_probe_state_source_mutations(build_wrapper: str, verifier: str) -> None:
    require_virtual_sdk_probe_state_wiring(build_wrapper, verifier)
    mutations = (
        (
            build_wrapper.replace(
                "PROJECT_ROOT, packages_dir, libdeps_dir, VIRTUAL_SDK_VENDOR_PROBE_STATE",
                "PROJECT_ROOT, packages_dir, libdeps_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE",
                1,
            ),
            verifier,
            "source gate rebuilt-state substitution",
        ),
        (
            build_wrapper.replace(
                "normalized_map, packages_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE",
                "normalized_map, packages_dir, VIRTUAL_SDK_VENDOR_PROBE_STATE",
                1,
            ),
            verifier,
            "linked provenance vendor-state substitution",
        ),
        (
            build_wrapper,
            verifier.replace(
                'build_dir / "firmware.map", packages_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE',
                'build_dir / "firmware.map", packages_dir, VIRTUAL_SDK_VENDOR_PROBE_STATE',
                1,
            ),
            "manifest vendor-state substitution",
        ),
        (
            build_wrapper,
            verifier.replace(
                "probe_state = (VIRTUAL_SDK_REBUILT_PROBE_STATE if args.build_dir is not None\n"
                "                   else VIRTUAL_SDK_VENDOR_PROBE_STATE)",
                "probe_state = (VIRTUAL_SDK_REBUILT_PROBE_STATE if args.build_dir is not None\n"
                "                   else VIRTUAL_SDK_REBUILT_PROBE_STATE)",
                1,
            ),
            "CLI source rebuilt-state substitution",
        ),
    )
    for mutated_wrapper, mutated_verifier, label in mutations:
        require(mutated_wrapper != build_wrapper or mutated_verifier != verifier,
                f"virtual SDK source mutation did not change text: {label}")
        try:
            require_virtual_sdk_probe_state_wiring(mutated_wrapper, mutated_verifier)
        except PocketSyncSecurityError:
            continue
        raise PocketSyncSecurityError(
            f"virtual SDK source gate accepted mutation: {label}")


def python_constant_tuple(source: str, name: str) -> tuple[str, ...]:
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        raise PocketSyncSecurityError(
            f"cannot parse Python source while checking {name}: {error}") from error
    assignments = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
    ]
    require(len(assignments) == 1, f"{name} must have exactly one top-level assignment")
    try:
        value = ast.literal_eval(assignments[0].value)
    except (ValueError, TypeError) as error:
        raise PocketSyncSecurityError(f"{name} must be a literal tuple") from error
    require(isinstance(value, tuple) and all(isinstance(item, str) for item in value),
            f"{name} must be a literal tuple of strings")
    return value


def require_ready27_lane_allowlists(reproducible: str, ready27_cache: str) -> None:
    expected = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")
    require(python_constant_tuple(ready27_cache, "READY27_LANES") == expected,
            "READY27 central approved-lane allowlist changed")
    require(python_constant_tuple(reproducible, "EXPECTED_CORE_LANES") == expected,
            "reproducible pre-script approved-lane allowlist drifted from READY27")
    require(
        "core_root.name in {EXPECTED_CORE_PREFIX + lane for lane in EXPECTED_CORE_LANES}"
        in reproducible,
        "reproducible pre-script no longer applies its approved-lane allowlist",
    )


def verify_ready27_lane_allowlist_mutations(reproducible: str,
                                            ready27_cache: str) -> None:
    require_ready27_lane_allowlists(reproducible, ready27_cache)
    mutations = (
        (
            reproducible.replace(
                'EXPECTED_CORE_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")',
                'EXPECTED_CORE_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J")',
                1,
            ),
            ready27_cache,
            "stale A/B/C/D/E/F reproducible assertion",
        ),
        (
            reproducible.replace(
                'EXPECTED_CORE_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")',
                'EXPECTED_CORE_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L")',
                1,
            ),
            ready27_cache,
            "unapproved reproducible lane",
        ),
        (
            reproducible.replace(
                'EXPECTED_CORE_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")',
                'EXPECTED_CORE_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "k")',
                1,
            ),
            ready27_cache,
            "lowercase reproducible lane alias",
        ),
        (
            reproducible,
            ready27_cache.replace(
                'READY27_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")',
                'READY27_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J")',
                1,
            ),
            "central allowlist regression",
        ),
        (
            reproducible,
            ready27_cache.replace(
                'READY27_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")',
                'READY27_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L")',
                1,
            ),
            "unapproved central lane",
        ),
        (
            reproducible,
            ready27_cache.replace(
                'READY27_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")',
                'READY27_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "k")',
                1,
            ),
            "lowercase central lane alias",
        ),
    )
    for mutated_reproducible, mutated_cache, label in mutations:
        require(mutated_reproducible != reproducible or mutated_cache != ready27_cache,
                f"READY27 allowlist mutation did not change source: {label}")
        try:
            require_ready27_lane_allowlists(mutated_reproducible, mutated_cache)
        except PocketSyncSecurityError:
            continue
        raise PocketSyncSecurityError(
            f"READY27 allowlist source gate accepted mutation: {label}")


def verify_platform_configuration(project_root: Path) -> None:
    verify_public_recovery_reference(project_root)
    platformio = read_text(project_root / "platformio.ini")
    verify_exception_platformio_policy(platformio)
    exception_guard = read_text(project_root / EXCEPTION_GUARD_RELATIVE)
    exception_runtime_probe = read_text(project_root / EXCEPTION_RUNTIME_PROBE_RELATIVE)
    exception_safety_limits = read_text(
        project_root / "lib" / "Epub" / "Epub" / "EpubSafetyLimits.h"
    )
    verify_exception_probe_sources(
        exception_guard, exception_runtime_probe, exception_safety_limits
    )
    verify_exception_source_mutations(
        platformio, exception_guard, exception_runtime_probe, exception_safety_limits
    )
    required_fragments = (
        "-DCONFIG_BT_NIMBLE_ROLE_CENTRAL_DISABLED=1",
        "-DCONFIG_BT_NIMBLE_ROLE_OBSERVER_DISABLED=1",
        "-DCONFIG_MDNS_MAX_INTERFACES=3",
        "-DCONFIG_NIMBLE_CPP_LOG_LEVEL=0",
        "CONFIG_BT_ENABLED=y",
        "CONFIG_BT_NIMBLE_ENABLED=y",
        "CONFIG_BT_CONTROLLER_ENABLED=y",
        "CONFIG_BT_NIMBLE_ROLE_CENTRAL=n",
        "CONFIG_BT_NIMBLE_ROLE_OBSERVER=n",
        "CONFIG_BT_NIMBLE_ROLE_PERIPHERAL=y",
        "CONFIG_BT_NIMBLE_ROLE_BROADCASTER=y",
        "CONFIG_BT_NIMBLE_GATT_CLIENT=n",
        "CONFIG_BT_NIMBLE_GATT_SERVER=y",
        "CONFIG_BT_NIMBLE_MAX_CONNECTIONS=1",
        "CONFIG_BT_NIMBLE_MAX_BONDS=1",
        "CONFIG_BT_NIMBLE_MAX_CCCDS=3",
        "CONFIG_BT_NIMBLE_WHITELIST_SIZE=1",
        "CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU=247",
        "CONFIG_BT_NIMBLE_ATT_MAX_PREP_ENTRIES=1",
        "CONFIG_BT_NIMBLE_GATT_MAX_PROCS=1",
        "CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE=4096",
        "CONFIG_BT_NIMBLE_CRYPTO_STACK_MBEDTLS=y",
        "CONFIG_BT_NIMBLE_LOG_LEVEL_NONE=y",
        "CONFIG_BT_NIMBLE_LOG_LEVEL_ERROR=n",
        "CONFIG_BT_NIMBLE_LOG_LEVEL_WARNING=n",
        "CONFIG_BT_NIMBLE_LOG_LEVEL_INFO=n",
        "CONFIG_BT_NIMBLE_LOG_LEVEL_DEBUG=n",
        "CONFIG_BT_NIMBLE_LOG_LEVEL=4",
        "CONFIG_BT_NIMBLE_PRINT_ERR_NAME=n",
        f"https://github.com/h2zero/NimBLE-Arduino.git#{PINNED_NIMBLE_COMMIT}",
    )
    for fragment in required_fragments:
        require(platformio.count(fragment) == 1, f"platformio Pocket Sync setting changed: {fragment}")
    require("lib_ignore =\n  BLE" in platformio, "legacy Arduino BLE library is not excluded")
    require(platformio.count("pre:scripts/configure_reproducible_build.py") == 1,
            "reproducible build pre-script is not wired exactly once")

    reproducible = read_text(project_root / "scripts" / "configure_reproducible_build.py")
    ready27_cache = read_text(project_root / "scripts" / "xtinct_ready27_cache.py")
    verify_ready27_lane_allowlist_mutations(reproducible, ready27_cache)
    for fragment in (
        f'EXPECTED_SOURCE_DATE_EPOCH = "{REPRODUCIBLE_SOURCE_DATE_EPOCH}"',
        'EXPECTED_PRIVATE_BUILD_NAME = ".xtinct-build-authoritative"',
        'EXPECTED_PRIVATE_BUILD_CACHE_NAME = ".cache"',
        'EXPECTED_ESP_IDF_PACKAGE_NAME = "framework-espidf"',
        'VIRTUAL_ESP_IDF_ROOT = "//IDF"',
        'os.path.samefile(canonical_esp_idf, supplied_esp_idf)',
        'owned_directory("XTINCT_REPRO_BUILD_CACHE_ROOT")',
        'os.environ.get("PLATFORMIO_BUILD_CACHE_DIR", "")',
        'project_alias.drive.upper() == "X:"',
        '"-ffile-prefix-map"',
        '"-fmacro-prefix-map"',
        '"-fdebug-prefix-map"',
        '"-fno-record-gcc-switches"',
        'env.AppendUnique(CCFLAGS=flags)',
        'env.Append(CXXFLAGS=["-include", str(guard_alias), "-fexceptions"])',
        'ESP_DSP_PLATFORM_HEADER_SHA256 = (',
        'env.AppendUnique(CPPPATH=[str(esp_dsp_include)])',
        'MDNS_HEADER_SHA256 = (',
        'env.AppendUnique(CPPPATH=[str(mdns_include)])',
        '("XTINCT_REPRO_CORE_ALIAS", "/xtinct/core", core_root)',
        'bool(exception_switches) and exception_switches[-1] == "-fexceptions"',
        'EXCEPTION_CONSTRUCTION_EVIDENCE_NAME = "xtinct-exception-construction.json"',
        'env.AppendUnique(LINKFLAGS=[',
        '"-Wl,--strip-debug",',
        '"/xtinct/source"',
        '"/xtinct/build"',
        '"/xtinct/packages"',
        '"/xtinct/core"',
        '"/xtinct/user"',
        'str(canonical_esp_idf).replace("\\\\", "/").rstrip("/"): VIRTUAL_ESP_IDF_ROOT',
        'sorted(path_maps.items(), key=lambda item: len(item[0]))',
    ):
        require(fragment in reproducible,
                f"reproducible build invariant is missing: {fragment}")
    require(reproducible.count('"-Wl,--strip-debug",') == 1,
            "reproducible build must apply the stripped-debug linker flag exactly once")

    build_wrapper = read_text(project_root / "scripts" / "build_xtinct.py")
    require('def windows_short_directory(path: Path, label: str) -> Path:' in build_wrapper and
            'env = strict_subprocess_env(core_dir, ca_bundle)' in build_wrapper and
            '"PLATFORMIO_CORE_DIR": str(short_core)' in build_wrapper and
            '"XTINCT_REPRO_CORE_ALIAS": str(short_core)' in build_wrapper and
            '"XTINCT_REPRO_PACKAGES_ALIAS": str(short_packages)' in build_wrapper and
             'env["XTINCT_REPRO_BUILD_ALIAS"] = str(short_private_build)' in build_wrapper and
             'env["PLATFORMIO_BUILD_DIR"] = str(short_private_build)' in build_wrapper and
             'MAX_PLATFORMIO_JOBS = 2' in build_wrapper and
             '"PLATFORMIO_RUN_JOBS": str(MAX_PLATFORMIO_JOBS)' in build_wrapper and
             'env.get("PLATFORMIO_RUN_JOBS") == str(MAX_PLATFORMIO_JOBS)' in build_wrapper and
             'IDF_BUILDER_BOUNDED_LDGEN_HELPER' in build_wrapper and
            'os.path.samefile(candidate, fragment)' in build_wrapper and
            'cd /d "{}" && {}' in build_wrapper and
            'format(FRAMEWORK_DIR, cmd)' in build_wrapper and
            'len(args["fragments"]) > 6000' in build_wrapper,
            "Windows short-path build policy is not wired")
    verifier_source = read_text(project_root / "scripts" / "verify_pocket_sync_security.py")
    verify_virtual_sdk_probe_state_source_mutations(build_wrapper, verifier_source)
    for fragment in (
        'VIRTUAL_SDK_PATH_ROOT = "//IDF"',
        'VIRTUAL_SDK_POLICY = "idf-components-map-archive-state-bound-v4"',
        'VIRTUAL_SDK_VENDOR_PROBE_STATE = "vendor-official-archive-v1"',
        'VIRTUAL_SDK_REBUILT_PROBE_STATE = "custom-sdkconfig-rebuilt-v1"',
        'VIRTUAL_PROJECT_PATH_PREFIX = "//xtinct/"',
        'VIRTUAL_PROJECT_PATH_ROOTS = ("build", "core", "packages", "source", "user")',
        'ARTIFACT_PRIVACY_POLICY = "nul-ascii-utf16le-embedded-drive-unc-uri-aware-v3"',
        'ARTIFACT_PRIVACY_URI_SCHEMES = ("ftp", "http", "https")',
        'EXPECTED_MINIZ_VIRTUAL_SOURCE_PATH = "//xtinct/source/lib/miniz/third_party/miniz.c"',
        'virtual_sdk_provenance, virtual_sdk_candidates = build_virtual_sdk_provenance(',
        'is_grammatical_virtual_sdk_path(original_candidate)',
        'original_candidate in virtual_sdk_candidates',
        'original_candidate.startswith(VIRTUAL_PROJECT_PATH_PREFIX)',
        'project_parts[0] in VIRTUAL_PROJECT_PATH_ROOTS',
        'VENDOR_BOOTLOADER_SUPPORT_ARCHIVE_SHA256',
        'REBUILT_BOOTLOADER_SUPPORT_ARCHIVE_SHA256',
        'VENDOR_APP_UPDATE_ARCHIVE_SHA256',
        'REBUILT_APP_UPDATE_ARCHIVE_SHA256',
        'VENDOR_APP_UPDATE_VIRTUAL_PATH_SHA256',
        'REBUILT_APP_UPDATE_VIRTUAL_PATH_SHA256',
        'normalized_map, packages_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE',
        'verify_pocket_sync_source_policy_files(\n            PROJECT_ROOT, packages_dir, libdeps_dir, VIRTUAL_SDK_VENDOR_PROBE_STATE',
        'XTINCT-IDF-CANDIDATE-SET-V2',
        '"map_reference": f"$PACKAGES/{relative.as_posix()}"',
        'project_parts[1:]',
        'elf_section_for_file_offset(path, absolute_offset)',
        'PRIVATE_PATH_DIAGNOSTIC=',
        '"candidate_sha256": sha256(encoded_candidate)',
        'uri_scheme = re.compile(',
        'scheme_drive_offsets',
        'def bound_uri_authority_offsets(',
        'match.start("path") in uri_authority_offsets',
        'def capture_published_generation(',
        'def restore_published_generation(',
        'def execute_published_generation_transaction(',
        'def self_test_published_generation_rollback(',
        'QEMU_FLASH_ARTIFACT_NAMES = (',
        'EFFECTIVE_SDKCONFIG_ARTIFACT_NAME = "sdkconfig.h"',
        'BOOT_APP0_BYTES = 0x2000',
        'EXPECTED_BOOT_APP0_SHA256 = (',
        'EXCEPTION_BUILD_EVIDENCE_NAME = "cxx-exception-build-evidence.json"',
        'def build_exception_translation_unit_evidence(',
        'def generated_exception_sdkconfig(',
        'def linked_exception_symbols(',
        '"schema": 4,',
        'private_exception_evidence',
        '"Published generation rollback did not restore the complete prior tree"',
        '"Injected final published-gate failure"',
        '"Injected first-publish final-gate failure"',
        '"Injected mid-companion publish failure"',
        '"Injected first-publish mid-companion failure"',
        'PUBLIC_RECOVERY_POLICY = "official-crosspoint-v1.5.0-external-reference-v1"',
        'def verify_public_recovery_reference()',
        '"recovery_reference": verify_public_recovery_reference()',
        '"Public recovery reference changed during the authoritative build"',
        'EXPECTED_WEB_SERVER_PARSER_SHA256',
        'EXPECTED_PATCHED_WEB_SERVER_PARSER_SHA256',
        'EXPECTED_WEB_SERVER_PARSER_CHECKER_SHA256',
        'verify_webserver_parser_behavior()',
        'def patch_webserver_parser_source(',
        'def recover_interrupted_webserver_parser_patch(',
        'def restore_webserver_parser_original(',
        'webserver_parser_backup_created',
        '"webserver_parser": {',
    ):
        require(fragment in build_wrapper,
                f"artifact privacy wrapper invariant is missing: {fragment}")
    publish_start = build_wrapper.find("def publish_verified_artifacts(")
    publish_end = build_wrapper.find("\ndef self_test(", publish_start)
    require(0 <= publish_start < publish_end,
            "artifact publish transaction could not be isolated")
    publish_transaction = build_wrapper[publish_start:publish_end]
    wrapper_privacy_index = publish_transaction.find("require_private_artifact_paths_absent(")
    independent_gate_index = publish_transaction.find("verify_pocket_sync_build_security(")
    require(0 <= wrapper_privacy_index < independent_gate_index,
            "bounded wrapper privacy diagnostics must precede the independent linked verifier")
    activation_index = publish_transaction.find(
        "firmware_source,\n            firmware_destination,"
    )
    qemu_companion_index = publish_transaction.find(
        "for name in (*QEMU_FLASH_ARTIFACT_NAMES, EFFECTIVE_SDKCONFIG_ARTIFACT_NAME):"
    )
    published_gate_index = publish_transaction.find(
        "published_gate_transcript = run_artifact_bound_linked_gate("
    )
    transaction_index = publish_transaction.find(
        "published_transcript = execute_published_generation_transaction("
    )
    require(0 <= qemu_companion_index < activation_index < published_gate_index < transaction_index,
            "QEMU companions/firmware activation/final gate/whole-tree transaction order changed")
    require(".xtinct-rollback-firmware.bin" not in publish_transaction and
            "previous_firmware" not in publish_transaction,
            "firmware-only rollback logic returned to the publish transaction")
    parser_patch = project_root / WEB_SERVER_PARSER_PATCH_RELATIVE
    require_hashed_file(
        parser_patch,
        {
            "bytes": EXPECTED_PATCHED_WEB_SERVER_PARSER_BYTES,
            "sha256": EXPECTED_PATCHED_WEB_SERVER_PARSER_SHA256,
        },
        "bounded Arduino WebServer parser patch",
    )
    parser_source = read_text(parser_patch)
    try:
        verify_bounded_webserver_parser_source(parser_source)
    except ParserFixtureError as error:
        raise PocketSyncSecurityError(
            f"bounded Arduino WebServer parser source contract failed: {error}"
        ) from error
    checker = project_root / WEB_SERVER_PARSER_CHECKER_RELATIVE
    require_hashed_file(
        checker,
        {
            "bytes": EXPECTED_WEB_SERVER_PARSER_CHECKER_BYTES,
            "sha256": EXPECTED_WEB_SERVER_PARSER_CHECKER_SHA256,
        },
        "bounded Arduino WebServer parser behavior checker",
    )
    try:
        parser_passes = verify_bounded_webserver_parser_files(project_root)
    except ParserFixtureError as error:
        raise PocketSyncSecurityError(
            f"bounded Arduino WebServer parser behavior failed: {error}"
        ) from error
    require(parser_passes == EXPECTED_WEB_SERVER_PARSER_BEHAVIOR_PASSES,
            "bounded Arduino WebServer parser behavior pass count changed")

    snapshotter = read_text(project_root / SOURCE_SNAPSHOT_SCRIPT)
    for fragment in (
        "$excludedRootDirectories = @('build', '.dummy')",
        "$pending = [Collections.Generic.Stack[string]]::new()",
        "Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop",
        "Source snapshot refuses a reparse point",
        "CMakeLists.txt",
        "sdkconfig.default",
    ):
        require(fragment in snapshotter,
                f"source snapshot exclusion/safety invariant is missing: {fragment}")
    require("Get-ChildItem -LiteralPath $sourceRoot -Recurse" not in snapshotter,
            "source snapshotter regained unsafe recursive traversal")

    bridge = read_text(project_root / "scripts" / "configure_pocket_sync_nimble.py")
    require(PINNED_NIMCONFIG_PATCH_SHA256 in bridge, "NimBLE compatibility patch digest changed")
    require("EXPECTED_ESP_BT_SHA256" in bridge, "ESP32-C3 Bluetooth header provenance gate is missing")
    require("env.AppendUnique(CPPPATH=[str(bt_include)])" in bridge,
            "owned ESP32-C3 Bluetooth include bridge changed")


def verify_private_dependency_root(project_root: Path, packages_dir: Path,
                                   libdeps_dir: Path) -> None:
    project_root = project_root.resolve()
    packages_dir = packages_dir.resolve()
    libdeps_dir = libdeps_dir.resolve()
    require(packages_dir.is_dir() and not packages_dir.is_symlink() and
            libdeps_dir.is_dir() and not libdeps_dir.is_symlink(),
            "READY27 packages/libdeps roots must be plain directories")
    require(packages_dir.name == "packages" and libdeps_dir.name == "libdeps" and
            packages_dir.parent == libdeps_dir.parent,
            "READY27 packages/libdeps roots do not share one private core")
    require(libdeps_dir != (project_root / ".pio" / "libdeps").resolve(),
            "READY27 dependency evidence cannot use the shared project cache")
    require(not libdeps_dir.is_relative_to(project_root),
            "READY27 dependency evidence must live outside the shared project tree")


def verify_private_libdeps_hook_text(jpeg: str, wolfssl: str) -> None:
    jpeg_required = (
        'Path(env.subst("$PROJECT_LIBDEPS_DIR"))',
        '"JPEGDEC hook refuses the shared project .pio/libdeps cache"',
        'not os.path.lexists(library / ".git")',
        'PATCHED_JPEG_INL_BYTES = 252_625',
        'PATCHED_JPEG_INL_SHA256 = "fd5d20da6e01d7900c6b48413bb1b19ed10fe82960231c28346c353820e78967"',
        'actual_patch_names == set(PATCH_SPECS)',
        '"PATCH_JPEGDEC_SELF_TEST_OK"',
    )
    wolfssl_required = (
        'Path(env.subst("$PROJECT_LIBDEPS_DIR"))',
        '"wolfSSL hook refuses the shared project .pio/libdeps cache"',
        'not os.path.lexists(library / ".git")',
        'PATCHED_SETTINGS_BYTES = 20_014',
        'PATCHED_SETTINGS_SHA256 = "311eb5652e2f487f56d45fdbdb6be9d61334a18a1bc2a2e2f962dac749ece5cc"',
        'len(settings_files) == 1',
        '"PATCH_WOLFSSL_SELF_TEST_OK"',
    )
    for fragment in jpeg_required:
        require(fragment in jpeg,
                f"private JPEGDEC dependency hook invariant is missing: {fragment}")
    for fragment in wolfssl_required:
        require(fragment in wolfssl,
                f"private wolfSSL dependency hook invariant is missing: {fragment}")
    forbidden = (
        'env["PROJECT_DIR"], ".pio", "libdeps"',
        'project_dir.glob(f".pio/libdeps/',
        'git apply',
    )
    for fragment in forbidden:
        require(fragment not in jpeg + wolfssl,
                f"private dependency hook regained a shared/mutable fallback: {fragment}")


def verify_private_libdeps_hook_policy(project_root: Path) -> None:
    jpeg_path = project_root / "scripts" / "patch_jpegdec.py"
    wolfssl_path = project_root / "scripts" / "patch_wolfssl.py"
    jpeg = read_text(jpeg_path)
    wolfssl = read_text(wolfssl_path)
    verify_private_libdeps_hook_text(jpeg, wolfssl)

    mutations = (
        (jpeg.replace('Path(env.subst("$PROJECT_LIBDEPS_DIR"))',
                      'Path(env.subst("$PROJECT_DIR")) / ".pio" / "libdeps"', 1),
         wolfssl, "JPEGDEC shared-cache fallback"),
        (jpeg.replace('not os.path.lexists(library / ".git")', "True", 1),
         wolfssl, "JPEGDEC Git metadata accepted"),
        (jpeg.replace("actual_patch_names == set(PATCH_SPECS)", "True", 1),
         wolfssl, "JPEGDEC patch allowlist removed"),
        (jpeg, wolfssl.replace('Path(env.subst("$PROJECT_LIBDEPS_DIR"))',
                               'Path(env.subst("$PROJECT_DIR")) / ".pio" / "libdeps"', 1),
         "wolfSSL shared-cache fallback"),
        (jpeg, wolfssl.replace('not os.path.lexists(library / ".git")', "True", 1),
         "wolfSSL Git metadata accepted"),
        (jpeg, wolfssl.replace("len(settings_files) == 1", "bool(settings_files)", 1),
         "wolfSSL dependency ambiguity accepted"),
    )
    for mutated_jpeg, mutated_wolfssl, label in mutations:
        require(mutated_jpeg != jpeg or mutated_wolfssl != wolfssl,
                f"private dependency hook mutation did not change source: {label}")
        try:
            verify_private_libdeps_hook_text(mutated_jpeg, mutated_wolfssl)
        except PocketSyncSecurityError:
            continue
        raise PocketSyncSecurityError(
            f"private dependency hook source gate accepted mutation: {label}")

    jpeg_output = run_checked(
        [sys.executable, "-B", str(jpeg_path), "--self-test"],
        project_root, "JPEGDEC private dependency hook self-test",
    )
    wolfssl_output = run_checked(
        [sys.executable, "-B", str(wolfssl_path), "--self-test"],
        project_root, "wolfSSL private dependency hook self-test",
    )
    require(jpeg_output.splitlines() == ["PATCH_JPEGDEC_SELF_TEST_OK"],
            "JPEGDEC private dependency hook self-test transcript changed")
    require(wolfssl_output.splitlines() == ["PATCH_WOLFSSL_SELF_TEST_OK"],
            "wolfSSL private dependency hook self-test transcript changed")


def verify_nimble_provenance(libdeps_dir: Path) -> None:
    library = libdeps_dir / "default" / "NimBLE-Arduino"
    require(library.is_dir() and not library.is_symlink(),
            "pinned private NimBLE-Arduino source is missing or linked")
    # READY27 reconstructs a metadata-free dependency source tree from the
    # exact reviewed commit.  Git state is provenance input, never mutable
    # build state inside any approved private core.
    require(not (library / ".git").exists(),
            "private NimBLE dependency unexpectedly retained mutable Git metadata")
    nimconfig = library / "src" / "nimconfig.h"
    require(sha256_file(nimconfig) == PINNED_NIMCONFIG_PATCH_SHA256,
            "NimBLE nimconfig compatibility patch bytes changed")

    for relative_path, (expected_digest, required_call_sites) in \
            NIMBLE_HOST_HOUSEKEEPING_SOURCE_EVIDENCE.items():
        source_path = library / relative_path
        source = read_text(source_path)
        require(sha256_file(source_path) == expected_digest,
                f"NimBLE host housekeeping source changed: {relative_path}")
        for call_site in required_call_sites:
            require(source.count(call_site) >= 1,
                    f"NimBLE host housekeeping evidence is missing: {relative_path}: {call_site}")


def verify_protocol_and_ram_policy(project_root: Path) -> None:
    contract = read_text(project_root / "src" / "util" / "PocketSyncContract.h")
    store_header = read_text(project_root / "src" / "network" / "PocketSyncStore.h")
    store_source = read_text(project_root / "src" / "network" / "PocketSyncStore.cpp")
    syntax_probe = read_text(project_root / "test" / "pocket_sync_contract" /
                             "PocketSyncContractSyntaxProbe.cpp")

    contract_fragments = (
        "MAX_MANIFEST_BYTES = 64U * 1024U",
        "MAX_OBJECTS = 68",
        "MAX_OBJECT_BYTES = 20U * 1024U * 1024U",
        "MAX_PACK_BYTES = 64U * 1024U * 1024U",
        "MAX_V1_CARDS = 4",
        "MAX_V2_CHANGES = 64",
        "MAX_PLAN_OPERATIONS =",
        "MAX_OBJECTS + MAX_V1_CARDS + 2U + MAX_V2_CHANGES + MAX_V2_CHANGES + 1U",
        "validPlanOperationCount",
        "validCommitProgress",
        "resumeStateRequiresReset",
        "validV1SourceTransition",
        "validV2SourceTransition",
        "enrollmentReplayMatches",
    )
    for fragment in contract_fragments:
        require(fragment in contract, f"Pocket Sync contract invariant is missing: {fragment}")
    require("static_assert(MAX_PLAN_OPERATIONS == 203)" in syntax_probe,
            "203-operation SD plan bound is not compile-time probed")
    require("#define Storage" in syntax_probe and "MAX_PLAN_OPERATIONS + 1U" in syntax_probe,
            "macro-collision or +1 plan rejection probe is missing")

    require("class ManifestObjectExtractor" in store_source and "StreamingJsonParser parser" in store_source,
            "manifest is not indexed through the bounded streaming parser")
    require("class HalJsonReader" in store_source, "SD-backed one-slice JSON reader is missing")
    require("writeObjectDescriptor" in store_source and "readObjectDescriptor" in store_source,
            "SD object-descriptor ledger is missing")
    require("static_assert(sizeof(PocketSyncStore) <= 1536" in store_header,
            "persistent Pocket Sync RAM budget assertion is missing")
    require("12U * 1024U" in store_source and "6U * 1024U" in store_source and "1536U" in store_source,
            "bounded card/change/object slice budgets changed")
    require("MAX_PLAN_LINE_BYTES = 768" in store_source,
            "SD-streamed commit-plan line bound changed")

    atomic_promote = function_body(store_source, "bool atomicPromote(")
    write_atomic = function_body(
        store_source, "bool writeAtomic(const char* finalPath, const uint8_t* bytes"
    )
    append_install_known = function_body(store_source, "bool appendInstallKnown(")
    seal_manifest = function_body(store_source, "Result PocketSyncStore::sealManifest()")
    commit = function_body(store_source, "Result PocketSyncStore::commit()")
    discard_stream = function_body(store_source, "bool PocketSyncStore::discardStreamForRetry(")
    resume_stream = function_body(store_source, "bool PocketSyncStore::prepareStreamForResume(")
    select_object = function_body(store_source, "bool PocketSyncStore::selectNextObjectForResume(")
    start_store = function_body(store_source, "Result PocketSyncStore::start(")
    write_store = function_body(store_source, "Result PocketSyncStore::write(")

    require("recoverAtomic(finalPath)" in atomic_promote,
            "atomic promotion no longer recovers interrupted sidecars first")
    require("Storage.remove(finalPath)" not in atomic_promote,
            "atomic promotion deletes the committed file before replacement")
    require("recoverAtomic(finalPath)" in write_atomic,
            "atomic write no longer recovers interrupted sidecars first")
    require('Storage.openFileForWrite("PSYNC", finalPath' not in write_atomic,
            "atomic write opens the committed path directly")
    require("isLowerHex(sha256, 64)" in append_install_known,
            "sealed install plan no longer validates its declared digest")
    require("hashMatches" not in append_install_known,
            "sealed install plan hashes object bytes before they have been downloaded")
    require(0 <= seal_manifest.find("sealed = true") < seal_manifest.find("buildCommitPlan()"),
            "manifest sealing builds object paths before enabling sealed stream routing")
    require("sealed = false" in seal_manifest,
            "manifest sealing does not roll back sealed state after preparation failure")
    require(0 <= commit.find("allObjectsComplete()") < commit.find("runCommitPlan()"),
            "commit can apply the plan before every object is durably complete")
    require("object.size() != 11" in store_source,
            "firmware object schema no longer matches the Android 11-field wire object")
    require("g_psyncDebugLog" not in store_source and "psync-debug.txt" not in store_source,
            "unbounded Pocket Sync debug retention returned")
    require("INCOMING_DIR" not in resume_stream and "openNextFile" not in resume_stream,
            "object resume searches other incoming packs instead of its authenticated pack")
    require("resumeStateRequiresReset" in resume_stream and
            "discardStreamForRetry(stream)" in resume_stream,
            "impossible Pocket resume state no longer self-heals to a clean stream")
    marker_remove = discard_stream.find("Storage.remove(marker)")
    offset_remove = discard_stream.find("Storage.remove(offset)")
    stream_remove = discard_stream.find("Storage.remove(path)")
    require(0 <= marker_remove < offset_remove < stream_remove,
            "Pocket retry cleanup no longer clears marker, offset, then part in order")
    require("if (Storage.exists(okPath))" in select_object and
            "discardStreamForRetry(index)" in select_object and
            "prepareStreamForResume(index, offset)" in select_object,
            "invalid completed Pocket objects no longer clear every resume sidecar")
    require("selectNextObjectForResume(0, nextStream, offset)" in start_store and
            "selectNextObjectForResume(static_cast<uint8_t>(stream + 1U), nextStream, nextOffset)" in write_store and
            "nextStream < manifest.objectCount && nextOffset != 0" in write_store and
            "discardStreamForRetry(nextStream)" in write_store and
            "Phase::Objects, Result::Ok, nextStream, nextOffset" in write_store,
            "post-object advance no longer validates and resumes the next durable stream")

    combined = store_header + "\n" + store_source
    forbidden_patterns = {
        r"ObjectDescriptor\s+objects\s*\[": "in-RAM object descriptor array",
        r"ManifestState\s+\w+\s*\[": "in-RAM manifest-state array",
        r"(?:std::)?vector\s*<\s*ObjectDescriptor": "in-RAM descriptor vector",
        r"(?:char|uint8_t)\s+\w*manifest\w*\s*\[\s*MAX_MANIFEST_BYTES": "64 KiB manifest buffer",
        r"(?:std::string|String)\s+\w*manifest(?:Body|Content)": "whole-manifest string",
        r"readFile\s*\([^\n;]*manifest": "whole-manifest SD read",
        r"encodedCard": "second encoded V1 card buffer",
    }
    for pattern, label in forbidden_patterns.items():
        require(re.search(pattern, combined, flags=re.IGNORECASE) is None,
                f"Pocket Sync RAM policy found {label}")


def verify_ble_lifecycle_policy(project_root: Path) -> None:
    source = read_text(project_root / "src" / "network" / "PocketSyncBleServer.cpp")
    contract = read_text(project_root / "src" / "util" / "PocketSyncContract.h")
    tests = read_text(project_root / "test" / "pocket_sync_contract" /
                      "PocketSyncContractSyntaxProbe.cpp")

    required_source = (
        "std::atomic<bool> running{false}",
        "std::atomic<bool> dataEnabled{false}",
        "std::atomic<PairingState> pairingState{PairingState::Missing}",
        "std::atomic<uint32_t> displayPasskey{0}",
        "std::atomic<uint32_t> enrollmentDeadline{0}",
        "mutable portMUX_TYPE pairingMux",
        "responseState.store(xtinct::pocket_sync::ControlResponseState::Closing)",
        "resetResponseAfterDisconnect()",
        "retireAcknowledgedResponse()",
        "if (quiesceClosing()) return",
        "canAcceptDataFrame(dataEnabled.load(), responseState.load())",
    )
    for fragment in required_source:
        require(fragment in source, f"Pocket Sync BLE lifecycle invariant is missing: {fragment}")
    require(re.search(r"\bdataEnabled\s*=", source) is None,
            "dataEnabled regained a non-atomic direct assignment")

    start = function_body(source, "bool start()")
    accept_control = function_body(source, "void acceptControlFragment(")
    accept_data = function_body(source, "void acceptDataFrame(")
    process_enroll = function_body(source, "void processEnroll(")
    pump = function_body(source, "void pumpIndication(")
    characteristic_start = source.find("controlCharacteristic =")
    characteristic_end = source.find("dataCharacteristic =", characteristic_start)
    require(characteristic_start >= 0 and characteristic_end > characteristic_start,
            "Pocket Sync control characteristic declaration is missing")
    control_characteristic = source[characteristic_start:characteristic_end]

    require("NIMBLE_PROPERTY::INDICATE" in control_characteristic and
            "NIMBLE_PROPERTY::NOTIFY" not in control_characteristic,
            "control responses must use acknowledged BLE indications only")
    require("WiFi.disconnect(true, true)" in start and "WiFi.mode(WIFI_OFF)" in start,
            "Pocket Sync no longer shuts down the competing ESP32-C3 Wi-Fi radio")
    require(start.find("WiFi.mode(WIFI_OFF)") < start.find("NimBLEDevice::init"),
            "Pocket Sync starts NimBLE before the Wi-Fi radio is disabled")
    require("xQueueCreateStatic(WINDOW_CHUNKS" in start and
            "dataQueueStorage[WINDOW_CHUNKS * sizeof(DataItem)]" in source,
            "Pocket Sync receive queue no longer matches the negotiated durable window")
    require(re.search(r"xQueueSend\s*\(\s*dataQueue\s*,\s*&item\s*,\s*0\s*\)", accept_data) is not None,
            "NimBLE data callback can block instead of failing a full bounded window")
    require("pdMS_TO_TICKS" not in accept_data,
            "NimBLE data callback regained a timed queue wait")
    require("const bool enrollAllowed = true" not in accept_control and
            "pairing == PairingState::Missing" in accept_control and
            "enrollmentDeadline.load() - millis()" in accept_control,
            "enrollment is no longer limited to the physical pairing window")
    require("enrollmentReplayMatches" in process_enroll and "if (!replay)" in process_enroll,
            "an enrolled X3 no longer rejects a different phone identity")
    require("Auto-heal" not in process_enroll,
            "pairing auto-heal can silently overwrite the persisted owner")
    require(".notify(" not in pump and "->indicate(" in pump,
            "control response pump bypasses acknowledged indications")
    for fragment in (
        "INDICATION_WAITING",
        "finalResponseFrameInFlight",
        "retireAcknowledgedResponse",
        "requestDisconnect()",
    ):
        require(fragment in pump, f"ordered indication invariant is missing: {fragment}")
    require("clearResponseStorage()" not in pump and "clearResponse()" not in pump,
            "indication failure can clear the response before disconnect cleanup")

    callbacks = source[source.index("void onConnect("):source.index("void acceptControlFragment(")]
    require("updateSnapshot()" not in callbacks,
            "NimBLE callback must not read main-loop store/UI state")
    on_disconnect = callbacks[callbacks.index("void onDisconnect("):
                              callbacks.index("void onMTUChange(")]
    require("startAdvertising" not in on_disconnect and "disconnectObserved = true" in on_disconnect,
            "advertising must wait for main-loop disconnect cleanup")
    on_status = callbacks[callbacks.index("void onStatus("):]
    require("stopping.load()" in on_status and "isCurrentConnection(info)" in on_status,
            "late indication callbacks are not connection/stopping guarded")
    require(on_status.index("compare_exchange_strong") <
            on_status.rindex("indicationStatus.store(static_cast<int16_t>(code))"),
            "final indication ACK publishes EDONE before FinalAcknowledged")

    request_disconnect = source[source.index("void requestDisconnect("):
                                source.index("void serviceDisconnectRequest(")]
    require("ControlResponseState::Closing" in request_disconnect and
            "dataEnabled.store(false)" in request_disconnect,
            "disconnect request does not synchronously latch all dispatch closed")
    require("clearResponse()" not in pump and "requestDisconnect()" in pump,
            "indication failure can reopen Idle before disconnect cleanup")

    required_contract = (
        "Closing = 4",
        "canAcceptDataFrame",
        "responseStateAfterIndication",
    )
    for fragment in required_contract:
        require(fragment in contract, f"Pocket Sync closing policy is missing: {fragment}")
    for fragment in (
        "!canDispatchControlRequest(true, ControlResponseState::Closing)",
        "!canAcceptDataFrame(true, ControlResponseState::Closing)",
        "responseStateAfterIndication(ControlResponseState::InFlight, true, false)",
    ):
        require(fragment in tests, f"Pocket Sync closing regression probe is missing: {fragment}")


def verify_log_policy(project_root: Path) -> None:
    pocket_sources = (
        project_root / "src" / "network" / "PocketSyncBleServer.cpp",
        project_root / "src" / "network" / "PocketSyncStore.cpp",
        project_root / "src" / "activities" / "network" / "PhoneSyncActivity.cpp",
    )
    log_call = re.compile(r"LOG_(?:DBG|INF|WRN|ERR)\s*\((.*?)\)\s*;", re.DOTALL)
    forbidden = (
        "passkey", "appkey", "phoneid", "peerid", "sessionnonce", "hmac", "payload",
        "bearer", "password", "manifestsha", "packdigest", "bluetooth address", "peer address",
    )
    for path in pocket_sources:
        source = read_text(path)
        for match in log_call.finditer(source):
            lowered = re.sub(r"\s+", " ", match.group(1)).lower()
            for secret in forbidden:
                require(secret not in lowered, f"Pocket Sync log may retain {secret}: {path.name}")


def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def verify_fixtures(project_root: Path) -> None:
    fixture_root = project_root / "fixtures" / "pocket-sync"
    wire = json.loads(read_text(fixture_root / "v1-wire-vectors.json"))
    transitions = json.loads(read_text(fixture_root / "source-transition-vectors.json"))
    require(wire.get("schema") == "xtinct-pocket-sync-wire-vectors/1", "wire fixture schema changed")
    capability = bytes.fromhex(wire["capabilities"]["frameHex"])
    require(len(capability) == 43 and capability[:4] == b"XC\x01\x01",
            "capability golden frame is malformed")
    require(capability[6] == 68, "capability object bound is not 68")
    require(int.from_bytes(capability[7:11], "little") == 65536,
            "capability manifest bound is not 64 KiB")
    require(int.from_bytes(capability[11:15], "little") == 20 * 1024 * 1024,
            "capability object byte bound changed")
    require(int.from_bytes(capability[15:19], "little") == 64 * 1024 * 1024,
            "capability aggregate byte bound changed")

    authenticated = wire["authenticatedControlStart"]
    key = bytes.fromhex(authenticated["appKeyHex"])
    hmac_input = bytes.fromhex(authenticated["hmacInputHex"])
    expected_mac = hmac.new(key, hmac_input, hashlib.sha256).digest()[:16]
    require(expected_mac.hex() == authenticated["hmacSha256Truncated16Hex"],
            "authenticated START golden HMAC changed")
    body = bytes.fromhex(authenticated["authenticatedBodyHex"])
    require(body[-16:] == expected_mac and len(authenticated["fragmentsHex"]) == 8,
            "authenticated START fragments are incomplete")

    data = wire["data"]
    payload = data["payloadAscii"].encode("ascii")
    require(f"{crc16_ccitt_false(payload):04x}" == data["crc16CcittFalseHex"],
            "DATA golden CRC changed")
    require(len(bytes.fromhex(wire["status"]["frameHex"])) == 20,
            "STATUS golden frame size changed")

    require(transitions.get("schema") == "xtinct-pocket-sync-source-transition-vectors/1",
            "source transition fixture schema changed")
    v1 = {entry["name"]: entry for entry in transitions.get("v1", [])}
    v2 = {entry["name"]: entry for entry in transitions.get("v2", [])}
    require(v1.get("removed-cached-task-with-no-returned-card-change", {}).get("valid") is True,
            "V1 removed-task fixture is missing")
    require(v2.get("empty-snapshot-advances-over-historical-ledger", {}).get("valid") is True,
            "empty snapshot/cursor fixture is missing")
    require(v2.get("snapshot-tombstone-fails-closed", {}).get("valid") is False,
            "snapshot tombstone rejection fixture is missing")


def verify_paging_policy(project_root: Path) -> None:
    selection = read_text(project_root / "src" / "util" / "InboxNewestSelection.h")
    home_source = read_text(project_root / "src" / "activities" / "home" / "HomeActivity.cpp")
    activity_header = read_text(project_root / "src" / "activities" / "home" / "InboxActivity.h")
    activity_source = read_text(project_root / "src" / "activities" / "home" / "InboxActivity.cpp")
    client = read_text(project_root / "src" / "network" / "XtinctSyncClient.cpp")
    test = read_text(project_root / "test" / "inbox_newest_selection" /
                     "InboxNewestSelectionTest.cpp")
    required = (
        (selection, "isStrictlyOlderThanCursor"),
        (selection, "retainNewestBefore"),
        (selection, "class BoundedPageHistory"),
        (activity_header, "VISIBLE_ITEM_LIMIT = 8"),
        (activity_header, "static_assert(MAX_PAGES == 8)"),
        (activity_header, "sizeof(PageCursor) * MAX_PAGES <= 600"),
        (activity_source, "XtinctSyncClient::loadInboxPage"),
        (activity_source, "tr(STR_PREV_PAGE)"),
        (activity_source, "tr(STR_NEXT_PAGE)"),
        (activity_source, '"%s · %s · %s"'),
        (activity_source, "listBounds(contentTop, contentHeight)"),
        (activity_source, "handleListTouch"),
        (client, "MAX_INBOX_ITEMS"),
        (client, "managedMetadataItemId"),
        (test, "64"),
        (test, "BoundedPageHistory<PageCursor, 8>"),
    )
    for source, fragment in required:
        require(fragment in source, f"bounded generic Inbox paging invariant is missing: {fragment}")
    require("moduleId ==" not in activity_source and "moduleId !=" not in activity_source,
            "Inbox paging introduced a module allowlist")

    home_loop = function_body(home_source, "void HomeActivity::loop()")
    home_render = function_body(home_source, "void HomeActivity::render(RenderLock&&)")
    signed_recent_offset = "selectorIndex - static_cast<int>(recentBooks.size())"
    require(signed_recent_offset in home_loop,
            "Home touch/menu selection still subtracts an unsigned recent-book count")
    require("selectedMenuIndex" in home_render and
            signed_recent_offset in home_render,
            "Home passes the cover-inclusive selection index into the paged menu")
    require("static_cast<int>(menuItems.size()), -1" not in home_render,
            "Home menu selection is forcibly hidden")
    require("tr(STR_RESUME)" in home_render,
            "Home lost the recent-book Resume button hint")
    require(0 <= home_render.find("GUI.drawButtonMenu") < home_render.find("GUI.drawButtonHints") <
            home_render.find("renderer.displayBuffer()"),
            "Home does not draw menu hints and flush the complete frame in order")

    inbox_render = function_body(activity_source, "void InboxActivity::render(RenderLock&&)")
    status_position = inbox_render.find("contentTop + contentHeight + paginationHeight")
    require("const int paginationHeight" in inbox_render and status_position >= 0,
            "Inbox status text can overlap its pagination controls")
    require(status_position > inbox_render.find("const int paginationY = contentTop + contentHeight"),
            "Inbox status placement is not derived after the pagination row")


def verify_inbox_action_contract_policy(project_root: Path) -> None:
    client_header = read_text(project_root / "src" / "network" / "XtinctSyncClient.h")
    client_source = read_text(project_root / "src" / "network" / "XtinctSyncClient.cpp")
    activity_source = read_text(project_root / "src" / "activities" / "home" / "InboxActivity.cpp")
    digest_contract = read_text(project_root / "src" / "util" / "InboxDigestContract.h")
    digest_text = read_text(project_root / "src" / "util" / "InboxDigestText.h")
    paging_policy = read_text(project_root / "src" / "util" / "InboxSyncPagingPolicy.h")
    digest_tests = read_text(project_root / "test" / "inbox_digest" /
                             "InboxDigestTextTest.cpp")
    contract = read_text(project_root / "src" / "util" / "XtinctSyncContract.h")
    tests = read_text(project_root / "test" / "xtinct_sync_contract" / "XtinctSyncContractTest.cpp")
    english = read_text(project_root / "lib" / "I18n" / "translations" / "english.yaml")
    board_profiles = read_text(project_root / "freeink-sdk" / "libs" / "hardware" /
                               "BoardConfig" / "include" / "BoardConfig.h")
    pocket_store = read_text(project_root / "src" / "network" / "PocketSyncStore.cpp")

    required = (
        (client_header, "XTINCT_ACTION_LIKE = 1U << 5"),
        (client_header, "XTINCT_ACTION_DISLIKE = 1U << 6"),
        (client_source, 'std::strcmp(action, "like") == 0'),
        (client_source, 'std::strcmp(action, "dislike") == 0'),
        (client_source, 'actions.add("like")'),
        (client_source, 'actions.add("dislike")'),
        (client_source, 'queueEvent(item.itemId, item.revision, "like", "{}")'),
        (client_source, 'queueEvent(item.itemId, item.revision, "dislike", "{}")'),
        (activity_source, "XTINCT_ACTION_LIKE"),
        (activity_source, "XTINCT_ACTION_DISLIKE"),
        (activity_source, 'actionCodes.emplace_back("like")'),
        (activity_source, 'actionCodes.emplace_back("dislike")'),
        (contract, '"like"'),
        (contract, '"dislike"'),
        (tests, 'EXPECT_TRUE(isAckEventType("like"))'),
        (tests, 'EXPECT_TRUE(isAckEventType("dislike"))'),
        (english, 'STR_LIKE: "Like"'),
        (english, 'STR_DISLIKE: "Dislike"'),
    )
    for source, fragment in required:
        require(fragment in source, f"like/dislike contract parity invariant is missing: {fragment}")

    # X3 has no touch controller, so every Inbox page must remain reachable
    # through the hardware-opened Actions popup. Both page entries precede the
    # item-only action guard so an empty terminal page can still navigate back.
    show_actions = function_body(activity_source, "void InboxActivity::showActions()")
    item_guard = show_actions.find("if (itemCount > 0)")
    require(item_guard >= 0, "Inbox Actions item guard is missing")
    action_prefix = show_actions[:item_guard]
    prev_block = re.search(
        r"if\s*\(pageHistory\.pageIndex\(\)\s*>\s*0\)\s*\{([^{}]*)\}",
        action_prefix,
    )
    next_block = re.search(r"if\s*\(hasOlderItems\)\s*\{([^{}]*)\}", action_prefix)
    require(prev_block is not None and
            "actionNames.emplace_back(tr(STR_PREV_PAGE))" in prev_block.group(1) and
            'actionCodes.emplace_back("page-previous")' in prev_block.group(1),
            "Prev Inbox action is not structurally bound to pageIndex > 0 before the item guard")
    require(next_block is not None and
            "actionNames.emplace_back(tr(STR_NEXT_PAGE))" in next_block.group(1) and
            'actionCodes.emplace_back("page-next")' in next_block.group(1),
            "Next Inbox action is not structurally bound to hasOlderItems before the item guard")

    apply_action = function_body(activity_source, "void InboxActivity::applyAction(const std::string& action)")
    require(re.search(
        r'if\s*\(action\s*==\s*"page-previous"\)\s*\{[^{}]*showPreviousPage\(\);[^{}]*return;[^{}]*\}',
        apply_action,
    ) is not None, "page-previous Inbox action is not structurally bound to showPreviousPage")
    require(re.search(
        r'if\s*\(action\s*==\s*"page-next"\)\s*\{[^{}]*showNextPage\(\);[^{}]*return;[^{}]*\}',
        apply_action,
    ) is not None, "page-next Inbox action is not structurally bound to showNextPage")
    for fragment in (
        "mappedInput.wasTapInRect(0, paginationY, buttonWidth, buttonHeight)",
        "mappedInput.wasTapInRect(buttonWidth, paginationY, buttonWidth, buttonHeight)",
    ):
        require(fragment in activity_source,
                f"optional Inbox pagination touch convenience changed: {fragment}")

    for profile_name in ("XTEINK_X3", "XTEINK_X3_UC8279"):
        profile_start = board_profiles.find(f"constexpr BoardProfile {profile_name}")
        profile_end = board_profiles.find("};", profile_start)
        require(profile_start >= 0 and profile_end > profile_start and
                "NO_TOUCH" in board_profiles[profile_start:profile_end],
                f"{profile_name} is no longer explicitly bound to NO_TOUCH")

    # Opened telemetry and device-local delete must remain usable when the
    # outbox is full/unreadable. Archive/done/etc. retain the strict receipt
    # gate because those actions promise a cloud state transition.
    open_selected = function_body(activity_source, "void InboxActivity::openSelected()")
    open_full_selected = function_body(activity_source, "void InboxActivity::openFullSelected()")
    best_effort_call = "XtinctSyncClient::recordOpenedBestEffort(selected);"
    best_effort_at = open_full_selected.find(best_effort_call)
    epub_dispatch_at = open_full_selected.find("activityManager.goToReader(path)")
    text_dispatch_at = open_full_selected.find("startActivityForResult(std::move(reader)")
    require(0 <= best_effort_at < epub_dispatch_at < text_dispatch_at,
            "Inbox local-open dispatch is no longer downstream of best-effort opened telemetry")
    require("Could not save receipt" not in open_selected and
            'recordAction(selected, "opened")' not in open_selected and
            best_effort_call not in open_selected,
            "Inbox local-open flow regained a caller-visible opened-receipt gate")

    # Inbox now mirrors Daily Cards: it opens directly on the newest local
    # preview, exposes Actions/Open/Next, and keeps the old list as a secondary
    # Browse action. Previewing never queues an opened receipt or starts Wi-Fi;
    # only explicit Open enters the existing full reader path.
    on_enter = function_body(activity_source, "void InboxActivity::onEnter()")
    require(0 <= on_enter.find("loadItems();") <
            on_enter.find("view = itemCount > 0 ? View::PREVIEW : View::LIST;") <
            on_enter.find("loadSelectedPreview();"),
            "Inbox no longer loads its newest cached item directly into preview-first mode")
    require("view = View::PREVIEW;" in open_selected and
            "loadSelectedPreview();" in open_selected and
            "openFullSelected();" not in open_selected,
            "Inbox list selection no longer enters the local preview before full open")

    load_preview = function_body(activity_source, "void InboxActivity::loadSelectedPreview()")
    require("XtinctSyncClient::artifactPath(selected, artifactPath" in load_preview and
            "Storage.exists(artifactPath)" in load_preview,
            "Inbox preview can be rendered without a verified local artifact")
    require('Storage.openFileForRead("XDIGEST"' in load_preview and
            "StreamExtractor extractor(selected.title);" in load_preview and
            "MAX_SCAN_BYTES" in load_preview and
            "STREAM_CHUNK_BYTES" in load_preview,
            "Inbox preview is no longer a bounded streaming read of cached text")
    require("selected.kind == Kind::Card || selected.kind == Kind::Text || selected.kind == Kind::Action" in
            load_preview,
            "Inbox preview textual-kind allowlist changed")
    stored_digest_at = load_preview.find(
        "xtinct::inbox_digest_contract::isPresent(selected.digest)"
    )
    local_excerpt_at = load_preview.find('Storage.openFileForRead("XDIGEST"')
    require(0 <= stored_digest_at < local_excerpt_at and
            "if (!extracted && textual)" in load_preview,
            "Inbox preview no longer prefers persisted digest metadata before text fallback")

    inbox_loop = function_body(activity_source, "void InboxActivity::loop()")
    preview_branch = re.search(
        r"if\s*\(state\s*==\s*State::READY\s*&&\s*view\s*==\s*View::PREVIEW\s*&&\s*itemCount\s*>\s*0\)\s*\{(.+?)\n\s*\}\n\s*if\s*\(state\s*==\s*State::READY\s*&&\s*itemCount\s*>\s*0\)",
        inbox_loop,
        re.DOTALL,
    )
    require(preview_branch is not None,
            "Inbox preview controls no longer precede the secondary list controls")
    preview_controls = preview_branch.group(1)
    for fragment in (
        "MappedInputManager::Button::Back",
        "onGoHome(HomeMenuItem::XTINCT_INBOX)",
        "MappedInputManager::Button::Confirm",
        "showActions();",
        "MappedInputManager::Button::Left",
        "openFullSelected();",
        "MappedInputManager::Button::Right",
        "showNextPreview();",
    ):
        require(fragment in preview_controls,
                f"Inbox Cards-style preview control changed: {fragment}")
    require('actionCodes.emplace_back("browse-list")' in show_actions and
            'if (action == "browse-list")' in apply_action and
            "view = View::LIST;" in apply_action,
            "Inbox lost its secondary Browse list action")

    render_preview = function_body(activity_source, "void InboxActivity::renderPreview() const")
    for fragment in (
        "GUI.drawHeader",
        "GUI.drawSubHeader",
        '"Updated %s"',
        "previewDigest.summary",
        '"KEY POINTS"',
        'mapLabels("Back", "Actions", "Open"',
    ):
        require(fragment in render_preview,
                f"Inbox preview lost Cards-style rendering: {fragment}")
    for forbidden in ("connectSavedWifi", "XtinctFeedClient", "HTTPClient", "client->sync()"):
        require(forbidden not in load_preview and forbidden not in render_preview,
                f"Inbox preview unexpectedly gained a network dependency: {forbidden}")
    for fragment in (
        'sameText(parsed.summary, "WHY THIS FITS")',
        'sameText(parsed.summary, "TAKEAWAY")',
        "isUpperHeading(parsed.summary)",
        "MAX_SCAN_BYTES = 64 * 1024",
    ):
        require(fragment in digest_text,
                f"Inbox digest heading/bounds invariant is missing: {fragment}")
    for fragment in (
        "ReaderGenomeUsesWhyThisFitsAndTakeawayProse",
        "FindsTakeawayWellBeyondTheOldOneKilobyteExcerpt",
        "GenericFallbackSkipsTitleAndHeadingLines",
        "ReadingQueueFallbackSkipsCanonicalUrlLine",
        "AcceptsExactFirmwareCapsWithoutDynamicStorage",
        "RejectsExtraVersionMemberAndMalformedText",
    ):
        require(fragment in digest_tests,
                f"Inbox digest focused regression coverage is missing: {fragment}")

    # The optional metadata.digest contract is copied into fixed storage and
    # persisted with exactly three versioned fields. The firmware's smaller
    # text caps keep each persisted item bounded. Direct Wi-Fi sync admits eight
    # total changes at a time so the response, JSON tree and fixed page copy can
    # coexist on the X3 heap; the shared server/Pocket contract remains 16.
    for source, fragment in (
        (digest_contract, 'SCHEMA[] = "xtinct.inbox-digest/v1"'),
        (digest_contract, "MAX_SUMMARY_BYTES = 144"),
        (digest_contract, "MAX_POINT_BYTES = 64"),
        (digest_contract, "MAX_POINTS = 2"),
        (digest_contract, "sizeof(Digest) == 276"),
        (client_header, "sizeof(XtinctInboxItem) == 796"),
        (client_source, "sizeof(SyncPage) == 7480"),
        (client_source, "sizeof(SyncPage) <= 8 * 1024"),
        (pocket_store, "sizeof(XtinctInboxItem) == 796"),
    ):
        require(fragment in source,
                f"Inbox digest fixed-memory invariant is missing: {fragment}")
    for source, fragment in (
        (paging_policy, "DIRECT_PAGE_CHANGES = 8"),
        (paging_policy, "MAX_PAGES_PER_WAKE = 10"),
        (paging_policy, "MAX_DIRECT_RESPONSE_BYTES = 28 * 1024"),
        (paging_policy, "pagesRequired(77) == 10"),
        (client_source, "deliveries.size() + tombstones.size() >"),
        (client_source, "std::to_string(xtinct::inbox_sync_paging::DIRECT_PAGE_CHANGES)"),
        (tests, "pagesRequired(77), 10U"),
        (tests, "EXPECT_EQ(MAX_DELIVERIES, 16U)"),
    ):
        require(fragment in source,
                f"Inbox direct-sync heap/page invariant is missing: {fragment}")
    digest_parser = function_body(
        client_source,
        "bool parseInboxDigest(const JsonVariantConst value, "
        "xtinct::inbox_digest_contract::Digest& digest)",
    )
    metadata_writer = function_body(
        client_source,
        "bool writeMetadataAtPath(const XtinctInboxItem& item, const char* path,",
    )
    require("hasExactObjectShape" in digest_parser and
            "object.size()" in digest_parser and
            "inbox_digest_contract::assign" in digest_parser and
            '"version"' not in digest_parser,
            "Inbox digest parser no longer enforces the strict three-key schema")
    for fragment in (
        'digest["schema"] = xtinct::inbox_digest_contract::SCHEMA',
        'digest["summary"] = item.digest.summary',
        'JsonArray points = digest["points"].to<JsonArray>()',
    ):
        require(fragment in metadata_writer,
                f"Inbox metadata digest persistence is missing: {fragment}")
    require('digest["version"]' not in metadata_writer and
            "inbox_digest_contract::same(cached.digest, item.digest)" in client_source,
            "Inbox digest persistence added an extra version field or lost change detection")

    best_effort_body = function_body(
        client_source, "void XtinctSyncClient::recordOpenedBestEffort(const XtinctInboxItem& item)"
    )
    require('recordAction(item, "opened")' in best_effort_body and
            'LOG_ERR("XSYNC"' in best_effort_body and "%.32s" in best_effort_body,
            "best-effort opened telemetry lost its durable queue attempt or bounded diagnostic")
    require("const bool receiptQueued = XtinctSyncClient::recordAction(selected, action.c_str())" in apply_action and
            re.search(
                r'if\s*\(action\s*!=\s*"delete"\s*&&\s*!receiptQueued\)\s*'
                r'\{[^{}]*return;[^{}]*\}',
                apply_action,
            ) is not None,
            "non-delete Inbox actions lost their strict durable-receipt gate")
    delete_remove = apply_action.find("XtinctSyncClient::removeFromInbox(selected)")
    require(delete_remove > apply_action.find('action != "delete" && !receiptQueued') and
            'action == "delete" && receiptQueued' in apply_action and
            'Deleted locally - receipt unavailable' in apply_action,
            "device-local delete regained a cloud-receipt prerequisite")

    remove_local = function_body(
        client_source, "bool XtinctSyncClient::removeFromInbox(const XtinctInboxItem& item)"
    )
    metadata_remove = remove_local.find("Storage.remove(path)")
    cache_invalidate = remove_local.find("invalidateFastFirstPage()")
    require(0 <= metadata_remove < cache_invalidate and 'LOG_ERR("XSYNC"' in remove_local,
            "Inbox canonical deletion is blocked by or silent about fast-index cleanup")


def verify_network_response_memory_policy(project_root: Path) -> None:
    buffer_header = read_text(project_root / "src" / "util" / "BoundedResponseBuffer.h")
    buffer_test = read_text(project_root / "test" / "bounded_response_buffer" /
                            "BoundedResponseBufferTest.cpp")
    buffer_probe = read_text(project_root / "test" / "bounded_response_buffer" /
                             "BoundedResponseBufferSyntaxProbe.cpp")
    feed = read_text(project_root / "src" / "network" / "XtinctFeedClient.cpp")
    sync = read_text(project_root / "src" / "network" / "XtinctSyncClient.cpp")
    daily = read_text(project_root / "src" / "activities" / "home" /
                      "DailyCardsActivity.cpp")
    theme_header = read_text(project_root / "src" / "components" / "themes" / "BaseTheme.h")
    theme_source = read_text(project_root / "src" / "components" / "themes" / "BaseTheme.cpp")
    build_info = read_text(project_root / "src" / "XtinctBuildInfo.h")
    version_script = read_text(project_root / "scripts" / "git_branch.py")

    require(f'#define XTINCT_RELEASE_LABEL "{READY_RELEASE_LABEL}"' in build_info and
            f'#define XTINCT_BUILD_ID "{READY_BUILD_ID}"' in build_info and
            f"version_string = '{READY_VERSION}'" in version_script,
            "READY27 firmware identity is stale or internally inconsistent")
    require("HYBRID" not in version_script and "STOCK-SLEEP" not in build_info,
            "a superseded installed-image identity leaked into READY27")
    sd_updater = read_text(project_root / "src" / "activities" / "settings" /
                           "SdFirmwareUpdateActivity.cpp")
    require("__DATE__" not in sd_updater and "__TIME__" not in sd_updater and
            "XTINCT_RELEASE_LABEL" in sd_updater and "XTINCT_BUILD_ID" in sd_updater,
            "SD firmware updater regained host-local compile time or lost stable identity")

    for fragment in (
        "class BoundedResponseBuffer",
        "enum class Failure : uint8_t { None, Limit, Allocation }",
        "maximumBytes - used",
        "failureState = Failure::Allocation",
        "void release()",
        "storage[used] = '\\0'",
    ):
        require(fragment in buffer_header,
                f"bounded no-throw response buffer invariant is missing: {fragment}")
    require("std::string" not in buffer_header and "new " not in buffer_header,
            "bounded response buffer regained a throwing STL/new allocation path")
    for fragment in (
        "AcceptsExactMaximumAndRejectsOneMoreByte",
        "AllocationFailureIsReportedWithoutChangingCommittedBytes",
        "InvalidInputFailsClosed",
        "ceilingReallocate",
        "buffer.limitExceeded()",
        "buffer.allocationFailed()",
    ):
        require(fragment in buffer_test,
                f"bounded response allocation-failure regression test is missing: {fragment}")
    require("BoundedResponseBuffer buffer(48U * 1024U)" in buffer_probe,
            "RISC-V response-buffer syntax probe lost the exact V2 cap")

    for fragment in (
        "constexpr size_t MAX_MANIFEST_BYTES = 8192",
        "constexpr size_t MAX_CARD_BYTES = 16 * 1024",
        "BoundedResponseBuffer body(MAX_CARD_BYTES)",
        "BoundedResponseBuffer body(MAX_MANIFEST_BYTES)",
    ):
        require(fragment in feed, f"V1 exact response bound changed: {fragment}")
    require("std::string body" not in feed,
            "V1 network JSON response regained throwing std::string growth")
    perform_get = function_body(feed, "bool performJsonGet(")
    require("BoundedResponseBuffer& body" in feed and
            "return body.append(data, length)" in perform_get,
            "V1 response callback is not using the bounded no-throw buffer")
    require("body.limitExceeded()" in perform_get and "body.allocationFailed()" in perform_get,
            "V1 response callback failures are not classified fail closed")

    try:
        verify_network_atomicity_files(project_root)
    except NetworkAtomicityError as error:
        raise PocketSyncSecurityError(
            f"V1/V2 network atomicity source gate failed: {error}"
        ) from error

    require("constexpr size_t MAX_SYNC_BODY_BYTES = xtinct::inbox_sync_paging::MAX_DIRECT_RESPONSE_BYTES" in sync and
            "BoundedResponseBuffer body(MAX_SYNC_BODY_BYTES)" in sync,
            "V2 direct response policy binding changed")
    require("std::string body" not in sync and "body.append(reinterpret_cast" not in sync,
            "V2 response regained throwing std::string growth")
    sync_body = function_body(sync, "XtinctSyncClient::SyncResult XtinctSyncClient::sync()")
    sync_order = (
        sync_body.find("const int status = http->GET("),
        sync_body.find("http->end();  // The response body"),
        sync_body.find("parseSyncPage("),
        sync_body.find("body.release();"),
        sync_body.find("page->deliveryCount"),
        sync_body.find("http.reset();  // Release artifact TLS"),
        sync_body.find("page.reset();"),
        sync_body.find("collectUnreferencedArtifacts();"),
    )
    require(all(index >= 0 for index in sync_order) and list(sync_order) == sorted(sync_order),
            "V2 TLS, parse, response release, artifact, page release and GC order changed")
    require("body.allocationFailed()" in sync_body and "body.limitExceeded()" in sync_body,
            "V2 allocation/limit failures are not classified fail closed")

    for stage in (
        "daily-sync-start", "wifi-connected", "clock-ready", "before-v1", "after-v1",
        "before-v2", "after-v2", "wifi-off", "card-loaded",
    ):
        require(f'logHeapStage("{stage}")' in daily,
                f"deterministic no-secret heap stage is missing: {stage}")
    require('LOG_INF("XHEAP", "stage=%s free=%u max=%u min=%u"' in daily,
            "Daily Cards heap/max-block telemetry changed")
    require("tr(STR_UPDATED_FMT)" in daily and "GUI.drawMetricGrid" not in daily and
            "GUI.drawCardSections" not in daily,
            "Daily Cards is not using the proven READY25 inline renderer with translated Updated text")
    require("ThemeCardMetric" not in theme_header + theme_source and
            "ThemeCardSection" not in theme_header + theme_source and
            "drawMetricGrid" not in theme_header + theme_source and
            "drawCardSections" not in theme_header + theme_source,
            "unproven Daily Cards virtual rendering delegation returned")


def verify_riscv_syntax_probe(project_root: Path, packages_dir: Path) -> None:
    compiler = packages_dir / "toolchain-riscv32-esp" / "bin" / "riscv32-esp-elf-g++.exe"
    require(compiler.is_file(), "pinned RISC-V C++ compiler is missing")
    probe = project_root / "test" / "pocket_sync_contract" / "PocketSyncContractSyntaxProbe.cpp"
    run_checked(
        [str(compiler), "-std=gnu++17", "-Wall", "-Wextra", "-Werror", "-fsyntax-only",
         "-I.", str(probe.relative_to(project_root))],
        project_root,
        "RISC-V Pocket Sync macro-collision syntax probe",
    )
    response_probe = project_root / "test" / "bounded_response_buffer" / \
        "BoundedResponseBufferSyntaxProbe.cpp"
    run_checked(
        [str(compiler), "-std=gnu++17", "-Wall", "-Wextra", "-Werror",
         "-fexceptions", "-fno-rtti", "-include",
         EXCEPTION_GUARD_RELATIVE.as_posix(), "-fsyntax-only", "-I.",
         str(response_probe.relative_to(project_root))],
        project_root,
        "RISC-V bounded response global-exception syntax probe",
    )


def verify_source_policy(project_root: Path, packages_dir: Path,
                         libdeps_dir: Path, probe_state: str) -> None:
    virtual_sdk_probe_specs(probe_state)
    project_root = project_root.resolve()
    packages_dir = packages_dir.resolve()
    libdeps_dir = libdeps_dir.resolve()
    verify_private_dependency_root(project_root, packages_dir, libdeps_dir)
    verify_private_libdeps_hook_policy(project_root)
    verify_platform_configuration(project_root)
    verify_exception_link_mutations()
    verify_nimble_provenance(libdeps_dir)
    verify_protocol_and_ram_policy(project_root)
    verify_ble_lifecycle_policy(project_root)
    verify_log_policy(project_root)
    verify_fixtures(project_root)
    verify_paging_policy(project_root)
    verify_inbox_action_contract_policy(project_root)
    verify_network_response_memory_policy(project_root)
    verify_artifact_privacy_scanner_self_test(project_root, packages_dir, probe_state)
    verify_riscv_syntax_probe(project_root, packages_dir)


def parse_defines(path: Path) -> dict[str, str]:
    defines: dict[str, str] = {}
    for line in read_text(path).splitlines():
        match = re.fullmatch(r"#define\s+(CONFIG_[A-Z0-9_]+)(?:\s+(.*))?", line.strip())
        if match:
            name = match.group(1)
            require(name not in defines,
                    f"generated sdkconfig repeats or contradicts {name}")
            defines[name] = (match.group(2) or "1").strip()
    return defines


def verify_exception_sdkconfig(defines: dict[str, str]) -> dict[str, str]:
    expected = {
        "CONFIG_COMPILER_CXX_EXCEPTIONS": "1",
        "CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE": "1024",
    }
    for name, value in expected.items():
        require(defines.get(name) == value,
                f"generated sdkconfig exception value changed: {name}={defines.get(name)!r}")
    require(defines.get("CONFIG_COMPILER_CXX_RTTI") in {None, "0", "n"},
            "generated sdkconfig unexpectedly enabled C++ RTTI")
    return {
        **expected,
        "CONFIG_COMPILER_CXX_RTTI": "disabled",
    }


def verify_exception_symbols(symbols: str) -> tuple[str, ...]:
    for symbol in EXCEPTION_REQUIRED_SYMBOLS:
        require(re.search(rf"(?<![A-Za-z0-9_]){re.escape(symbol)}(?![A-Za-z0-9_])", symbols)
                is not None,
                f"READY27 ELF lacks C++ exception runtime symbol: {symbol}")
    for symbol in EXCEPTION_FORBIDDEN_STUB_SYMBOLS:
        require(re.search(rf"(?<![A-Za-z0-9_]){re.escape(symbol)}(?![A-Za-z0-9_])", symbols)
                is None,
                f"READY27 ELF retained fatal C++ exception stub: {symbol}")
    return EXCEPTION_REQUIRED_SYMBOLS


def verify_exception_link_mutations() -> None:
    good_defines = {
        "CONFIG_COMPILER_CXX_EXCEPTIONS": "1",
        "CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE": "1024",
    }
    verify_exception_sdkconfig(good_defines)
    for name, value in (
        ("CONFIG_COMPILER_CXX_EXCEPTIONS", "0"),
        ("CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE", "0"),
        ("CONFIG_COMPILER_CXX_RTTI", "1"),
    ):
        mutated = dict(good_defines)
        mutated[name] = value
        expect_exception_policy_rejection(
            lambda candidate=mutated: verify_exception_sdkconfig(candidate),
            f"generated {name}={value}",
        )

    good_symbols = "\n".join(f"42000000 T {name}" for name in EXCEPTION_REQUIRED_SYMBOLS)
    verify_exception_symbols(good_symbols)
    for symbol in EXCEPTION_REQUIRED_SYMBOLS:
        mutated = good_symbols.replace(symbol, "XTINCT_REMOVED_SYMBOL", 1)
        expect_exception_policy_rejection(
            lambda candidate=mutated: verify_exception_symbols(candidate),
            f"linked symbol removed: {symbol}",
        )
    for symbol in EXCEPTION_FORBIDDEN_STUB_SYMBOLS:
        mutated = good_symbols + f"\n42000000 T {symbol}\n"
        expect_exception_policy_rejection(
            lambda candidate=mutated: verify_exception_symbols(candidate),
            f"fatal stub linked: {symbol}",
        )

    good_sections = ((".text", 64), (".eh_frame", 128), (".eh_frame_hdr", 32))
    verify_exception_section_records(good_sections)
    for label, mutated in (
        ("missing .eh_frame", ((".text", 64), (".eh_frame_hdr", 32))),
        ("empty .eh_frame", ((".eh_frame", 0), (".eh_frame_hdr", 32))),
        ("duplicate .eh_frame_hdr",
         ((".eh_frame", 128), (".eh_frame_hdr", 32), (".eh_frame_hdr", 32))),
    ):
        expect_exception_policy_rejection(
            lambda candidate=mutated: verify_exception_section_records(candidate), label
        )


def file_contains_all(path: Path, needles: tuple[str, ...]) -> None:
    remaining = set(needles)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            remaining = {needle for needle in remaining if needle not in line}
            if not remaining:
                return
    require(not remaining, f"linker map lacks required Pocket Sync evidence: {sorted(remaining)}")


def effective_sdkconfig(build_dir: Path, packages_dir: Path,
                        libdeps_dir: Path) -> Path:
    # pioarduino's precompiled Arduino core does not copy sdkconfig.h into the
    # application build tree.  Prove which immutable package header both the
    # owned Pocket Sync source and NimBLEServer actually compiled against. A
    # private build uses the original generated dependency files. A public
    # evidence bundle may omit those absolute-path-bearing files and use only
    # their deterministic normalized copies, whose raw byte counts and hashes
    # remain bound in the evidence manifest.
    expected = (packages_dir / "framework-arduinoespressif32-libs" / "esp32c3" /
                "dio_qspi" / "include" / "sdkconfig.h").resolve()
    require(expected.is_file(), "effective ESP32-C3 dio_qspi sdkconfig.h is missing")
    expected_spellings = dependency_path_spellings(expected, packages_dir.parent)

    server_dependencies = list(build_dir.rglob("NimBLEServer.cpp.d"))
    normalized_server_dependencies = list(
        build_dir.rglob(f"NimBLEServer.cpp.d{NORMALIZED_DEPENDENCY_SUFFIX}")
    )
    require(len(server_dependencies) <= 1 and len(normalized_server_dependencies) <= 1 and
            bool(server_dependencies or normalized_server_dependencies),
            "expected one raw or normalized dependency file for NimBLEServer.cpp")
    if server_dependencies:
        server_dependency = read_text(server_dependencies[0]).replace("\\", "/")
        require(dependency_contains_exact_path(server_dependency, expected_spellings),
                "NimBLEServer.cpp did not compile against the attested READY24 sdkconfig")
    if normalized_server_dependencies:
        normalized_server = read_text(normalized_server_dependencies[0]).replace("\\", "/")
        require("$PACKAGES/framework-arduinoespressif32-libs/esp32c3/dio_qspi/include/sdkconfig.h"
                in normalized_server,
                "normalized NimBLEServer dependency evidence lacks the attested sdkconfig")
        require(re.search(r"(?im)(?:^|\s)(?:[a-z]:/|//)", normalized_server) is None,
                "normalized NimBLEServer dependency evidence leaks an absolute path")

    pocket_dependencies = list(build_dir.rglob("PocketSyncBleServer.cpp.d"))
    normalized_pocket_dependencies = list(
        build_dir.rglob(f"PocketSyncBleServer.cpp.d{NORMALIZED_DEPENDENCY_SUFFIX}")
    )
    require(len(pocket_dependencies) <= 1 and len(normalized_pocket_dependencies) <= 1 and
            bool(pocket_dependencies or normalized_pocket_dependencies),
            "expected one raw or normalized dependency file for PocketSyncBleServer.cpp")
    if pocket_dependencies:
        pocket_dependency = read_text(pocket_dependencies[0]).replace("\\", "/")
        expected_nimconfig_path = (
            libdeps_dir / "default" / "NimBLE-Arduino" / "src" / "nimconfig.h"
        ).resolve()
        expected_nimconfig_spellings = dependency_path_spellings(
            expected_nimconfig_path, libdeps_dir.parent
        )
        require(dependency_contains_exact_path(pocket_dependency, expected_nimconfig_spellings),
                "PocketSyncBleServer.cpp did not compile against the private pinned NimBLE configuration")
        shared_fragment = "/.pio/libdeps/default/NimBLE-Arduino/src/nimconfig.h"
        require(shared_fragment.lower() not in pocket_dependency.lower(),
                "PocketSyncBleServer.cpp compiled against the shared project dependency cache")
    if normalized_pocket_dependencies:
        normalized_pocket = read_text(normalized_pocket_dependencies[0]).replace("\\", "/")
        require("$LIBDEPS/default/NimBLE-Arduino/src/nimconfig.h" in normalized_pocket,
                "normalized PocketSyncBleServer dependency evidence lacks pinned nimconfig.h")
        require(re.search(r"(?im)(?:^|\s)(?:[a-z]:/|//)", normalized_pocket) is None,
                "normalized PocketSyncBleServer dependency evidence leaks an absolute path")
    return expected


def verify_build_policy(project_root: Path, build_dir: Path, packages_dir: Path,
                        libdeps_dir: Path,
                        virtual_project_roots: tuple[str, ...] = VIRTUAL_PROJECT_PATH_ROOTS,
                        virtual_sdk_candidates: frozenset[str] | None = None) -> None:
    project_root = project_root.resolve()
    build_dir = build_dir.resolve()
    packages_dir = packages_dir.resolve()
    sdkconfig = effective_sdkconfig(build_dir, packages_dir, libdeps_dir)
    firmware_bin = build_dir / "firmware.bin"
    firmware_elf = build_dir / "firmware.elf"
    firmware_map = build_dir / "firmware.map"
    require(firmware_bin.is_file() and firmware_elf.is_file() and firmware_map.is_file(),
            "linked READY27 evidence is missing")
    if virtual_sdk_candidates is None:
        _virtual_sdk_record, virtual_sdk_candidates = build_virtual_sdk_provenance(
            firmware_map, packages_dir, VIRTUAL_SDK_REBUILT_PROBE_STATE
        )
    require_artifact_privacy(
        (firmware_bin, firmware_elf), project_root, build_dir, packages_dir,
        virtual_project_roots, virtual_sdk_candidates,
    )
    require_map_privacy(
        firmware_map, project_root, build_dir, packages_dir, virtual_project_roots,
        virtual_sdk_candidates,
    )
    firmware_bytes = firmware_bin.read_bytes()
    for identity in (READY_RELEASE_LABEL, READY_BUILD_ID, READY_VERSION):
        require(identity.encode("utf-8") in firmware_bytes,
                f"installable firmware lacks READY27 identity: {identity}")
    for superseded in ("v1.6.1-READY26", "BUILD-161-READY26-HEAP-SAFE"):
        require(superseded.encode("utf-8") not in firmware_bytes,
                f"installable firmware contains superseded identity: {superseded}")

    defines = parse_defines(sdkconfig)
    verify_exception_sdkconfig(defines)
    exception_elf_sections(firmware_elf)

    enabled = (
        "CONFIG_BT_ENABLED", "CONFIG_BT_NIMBLE_ENABLED", "CONFIG_BT_CONTROLLER_ENABLED",
        "CONFIG_BT_NIMBLE_ROLE_PERIPHERAL", "CONFIG_BT_NIMBLE_ROLE_BROADCASTER",
        "CONFIG_BT_NIMBLE_GATT_SERVER", "CONFIG_BT_NIMBLE_CRYPTO_STACK_MBEDTLS",
        "CONFIG_BT_NIMBLE_LOG_LEVEL_NONE",
    )
    disabled = (
        "CONFIG_BT_NIMBLE_ROLE_CENTRAL", "CONFIG_BT_NIMBLE_ROLE_OBSERVER",
        "CONFIG_BT_NIMBLE_GATT_CLIENT", "CONFIG_BT_NIMBLE_LOG_LEVEL_ERROR",
        "CONFIG_BT_NIMBLE_LOG_LEVEL_WARNING", "CONFIG_BT_NIMBLE_LOG_LEVEL_INFO",
        "CONFIG_BT_NIMBLE_LOG_LEVEL_DEBUG", "CONFIG_BT_NIMBLE_PRINT_ERR_NAME",
    )
    exact = {
        "CONFIG_BT_NIMBLE_MAX_CONNECTIONS": "1",
        "CONFIG_BT_NIMBLE_MAX_BONDS": "1",
        "CONFIG_BT_NIMBLE_MAX_CCCDS": "3",
        "CONFIG_BT_NIMBLE_WHITELIST_SIZE": "1",
        "CONFIG_BT_NIMBLE_ATT_PREFERRED_MTU": "247",
        "CONFIG_BT_NIMBLE_ATT_MAX_PREP_ENTRIES": "1",
        "CONFIG_BT_NIMBLE_GATT_MAX_PROCS": "1",
        "CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE": "4096",
        "CONFIG_BT_NIMBLE_LOG_LEVEL": "4",
    }
    for name in enabled:
        require(defines.get(name) == "1", f"generated sdkconfig did not enable {name}")
    for name in disabled:
        require(name not in defines or defines[name] in {"0", "n"},
                f"generated sdkconfig unexpectedly enabled {name}")
    for name, value in exact.items():
        require(defines.get(name) == value,
                f"generated sdkconfig value changed: {name}={defines.get(name)!r}")

    file_contains_all(firmware_map, ("PocketSyncBleServer", "PocketSyncStore", "NimBLEServer", "libbt.a"))
    nm = packages_dir / "toolchain-riscv32-esp" / "bin" / "riscv32-esp-elf-nm.exe"
    require(nm.is_file(), "pinned RISC-V nm is missing")
    symbols = run_checked([str(nm), "-C", "-g", "--defined-only", str(firmware_elf)], project_root,
                          "final ELF symbol policy")
    all_symbols = run_checked([str(nm), "-a", str(firmware_elf)], project_root,
                              "final ELF C++ exception runtime policy")
    verify_exception_symbols(all_symbols)
    for required in ("PocketSyncBleServer", "PocketSyncStore", "NimBLEServer"):
        require(required in symbols, f"final ELF lacks {required}")
    linked_gattc_symbols = set(re.findall(r"\bble_gattc_[A-Za-z0-9_]*\b", symbols))
    require(
        linked_gattc_symbols == ALLOWED_GATTC_PERIPHERAL_HOST_SYMBOLS,
        "final ELF exported GATT-client symbol set is not the exact peripheral-host allowlist: "
        f"found={sorted(linked_gattc_symbols)!r}, "
        f"allowed={sorted(ALLOWED_GATTC_PERIPHERAL_HOST_SYMBOLS)!r}",
    )

    forbidden_symbols = (
        r"\bNimBLEClient(?:::|Callbacks\b|\b)",
        r"\bNimBLEScan(?:::|Callbacks\b|Results\b|\b)",
        r"\bble_gattc_(?:disc|find|read|write|exchange_mtu|reliable)[A-Za-z0-9_]*\b",
        r"\bble_gap_connect(?:\b|_[A-Za-z0-9_]*\b)",
        r"\bble_gap_ext_connect(?:\b|_[A-Za-z0-9_]*\b)",
        r"\bble_gap_disc\b",
        r"\bble_gap_ext_disc\b",
        r"\bble_gap_disc_cancel\b",
    )
    for pattern in forbidden_symbols:
        require(re.search(pattern, symbols) is None,
                f"removed BLE client/scanner role survived in final ELF: {pattern}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--packages-dir", type=Path, required=True)
    parser.add_argument("--libdeps-dir", type=Path, required=True)
    parser.add_argument("--build-dir", type=Path)
    parser.add_argument("--evidence-manifest", type=Path)
    args = parser.parse_args(argv)
    require(args.evidence_manifest is None or args.build_dir is not None,
            "an evidence manifest requires a build directory")
    probe_state = (VIRTUAL_SDK_REBUILT_PROBE_STATE if args.build_dir is not None
                   else VIRTUAL_SDK_VENDOR_PROBE_STATE)
    verify_source_policy(args.project_root, args.packages_dir, args.libdeps_dir, probe_state)
    print("POCKET_SYNC_SOURCE_SECURITY_OK")
    if args.build_dir is not None:
        virtual_project_roots = VIRTUAL_PROJECT_PATH_ROOTS
        virtual_sdk_candidates = None
        if args.evidence_manifest is not None:
            evidence_sha256, virtual_project_roots, virtual_sdk_candidates = verify_evidence_manifest(
                args.project_root, args.build_dir, args.packages_dir,
                args.libdeps_dir, args.evidence_manifest
            )
            print(f"POCKET_SYNC_EVIDENCE_MANIFEST_OK {evidence_sha256}")
        verify_build_policy(
            args.project_root, args.build_dir, args.packages_dir, args.libdeps_dir,
            virtual_project_roots,
            virtual_sdk_candidates,
        )
        print("POCKET_SYNC_LINKED_SECURITY_OK")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (PocketSyncSecurityError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"Pocket Sync security gate failed closed: {error}", file=sys.stderr)
        raise SystemExit(2)
