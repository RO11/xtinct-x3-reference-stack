#!/usr/bin/env python3
"""Fail-closed READY27 package-cache construction primitives.

The READY27 release never reuses an Arduino framework tree that a prior build
may have regenerated in place.  This module validates the immutable reviewed
official archives, extracts them without unsafe archive helpers, inventories
every input/output byte, and copies the remaining PlatformIO tools into a
plain wrapper-owned core.  Symlinks, junctions, destination hard links, path
aliases and case-folding collisions are rejected throughout.  Source-only
hard-link topology may be observed, but it is never copied or treated as a
firmware input.

This file deliberately contains no firmware-build entrypoint.  The release
orchestrator imports these primitives after its own approved-lane checks.
"""

from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Iterable


FILE_ATTRIBUTE_REPARSE_POINT = 0x400
INVENTORY_SCHEMA = 1
COPY_BUFFER_BYTES = 1024 * 1024
MAX_INVENTORY_ENTRIES = 250_000
MAX_RELATIVE_PATH_BYTES = 2048
MAX_PATH_SEGMENT_BYTES = 255
RUNTIME_CACHE_DIRECTORY = "__pycache__"
RUNTIME_CACHE_SUFFIXES = (".pyc", ".pyo")
READY27_CORE_PREFIX = ".xtinct-ready27-core-R27-EXCEPTIONS-20260810-"
READY27_LANES = ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K")
OWNER_MARKER_NAME = ".xtinct-ready27-owner.json"
OWNER_POLICY = "ready27-independent-private-core-v1"
DEPENDENCY_SEED_POLICY = "ready27-portable-vendored-libdeps-v2"
DEPENDENCY_SEED_MARKER_NAME = "dependency-seed-construction.json"
ESPTOOL_REBIND_POLICY = "ready27-offline-private-esptool-editable-v2"
# The copied PlatformIO penv carries this editable-distribution metadata name.
# The reviewed pioarduino package, source module and CLI are all 5.1.2.
ESPTOOL_DISTRIBUTION_VERSION = "5.1.2"
ESPTOOL_MODULE_VERSION = "5.1.2"
ESPTOOL_PLATFORMIO_PACKAGE_VERSION = "5.1.2"
ESPTOOL_VERSION_BANNER = "esptool v5.1.2"
ESPTOOL_GENERATOR_PIP_VERSION = "26.2.1"
ESPTOOL_GENERATOR_DISTLIB_VERSION = "0.4.2"
ESPTOOL_EDITABLE_FINDER = "__editable___esptool_5_1_2_finder.py"
ESPTOOL_EDITABLE_PTH = "__editable__.esptool-5.1.2.pth"
ESPTOOL_LAUNCHERS = (
    "esp_rfc2217_server.exe", "espefuse.exe", "espsecure.exe", "esptool.exe",
)
ESPTOOL_CONSOLE_SPECS = (
    "esp_rfc2217_server = esp_rfc2217_server.__init__:main",
    "espefuse = espefuse.__init__:_main",
    "espsecure = espsecure.__init__:_main",
    "esptool = esptool.__init__:_main",
)
ESPTOOL_TOP_LEVEL_PACKAGES = (
    "esp_rfc2217_server", "espefuse", "espsecure", "esptool",
)
ESPTOOL_NAMESPACES = (
    "espefuse.efuse_defs",
    "esptool.targets.stub_flasher",
    "esptool.targets.stub_flasher.1",
    "esptool.targets.stub_flasher.2",
)
RUNTIME_CACHE_EXCLUDED_PACKAGE_NAMES = frozenset({"tool-esptoolpy"})
GLOBAL_PLATFORM_DIRECTORY_NAME = "espressif32@src-68ff870a2caae2bf860c7b8c395d0be5"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

OFFICIAL_FRAMEWORK_URI = (
    "https://github.com/espressif/arduino-esp32/releases/download/3.3.7/"
    "esp32-core-3.3.7.tar.xz"
)
OFFICIAL_LIBS_URI = (
    "https://github.com/espressif/arduino-esp32/releases/download/3.3.7/"
    "esp32-core-3.3.7-libs.tar.xz"
)

FRAMEWORK_PIOPM = (
    b'{"type": "tool", "name": "framework-arduinoespressif32", '
    b'"version": "3.3.7", "spec": {"owner": null, "id": null, '
    b'"name": "arduino-esp32", "requirements": null, "uri": "'
    + OFFICIAL_FRAMEWORK_URI.encode("ascii")
    + b'"}}'
)
LIBS_PIOPM = (
    b'{"type": "tool", "name": "framework-arduinoespressif32-libs", '
    b'"version": "5.5.0+sha.87912cd291", "spec": {"owner": null, '
    b'"id": null, "name": "arduino-esp32", "requirements": null, '
    b'"uri": "'
    + OFFICIAL_LIBS_URI.encode("ascii")
    + b'"}}'
)


class Ready27CacheError(RuntimeError):
    """A READY27 construction or provenance invariant failed."""


@dataclass(frozen=True)
class ArchiveSpec:
    label: str
    cache_name: str
    archive_bytes: int
    archive_sha256: str
    top_level: str
    destination_name: str
    piopm: bytes
    maximum_entries: int
    maximum_file_bytes: int
    maximum_total_file_bytes: int


@dataclass(frozen=True)
class GitDependencySpec:
    name: str
    commit: str
    origin: str
    piopm_bytes: int
    piopm_sha256: str
    modified_path: str | None = None
    original_bytes: int = 0
    original_sha256: str = EMPTY_SHA256
    patched_bytes: int = 0
    patched_sha256: str = EMPTY_SHA256
    diff_bytes: int = 0
    diff_sha256: str = EMPTY_SHA256
    diff_autocrlf: str = "false"


@dataclass(frozen=True)
class ZipArchiveSpec:
    label: str
    cache_name: str
    archive_bytes: int
    archive_sha256: str
    top_level: str
    destination_name: str
    piopm: bytes
    entries: int
    files: int
    directories: int
    file_bytes: int
    compressed_file_bytes: int
    maximum_file_bytes: int
    mode_counts: tuple[tuple[int, int], ...]
    manifest_bytes: int
    manifest_sha256: str


ARCHIVE_SPECS = (
    ArchiveSpec(
        label="Arduino framework 3.3.7",
        cache_name="0e3774ba0ddbab34e321d93168727c8458632c63",
        archive_bytes=20_697_240,
        archive_sha256="9dd09b11ae75ba25b0610e76ff1265a4e59441cc5fdf3cb20dcd323904814186",
        top_level="esp32-core-3.3.7",
        destination_name="framework-arduinoespressif32",
        piopm=FRAMEWORK_PIOPM,
        maximum_entries=3_000,
        maximum_file_bytes=8 * 1024 * 1024,
        maximum_total_file_bytes=64 * 1024 * 1024,
    ),
    ArchiveSpec(
        label="Arduino ESP-IDF libraries 5.5.0",
        cache_name="48157216b86d951b09333b2b4e19f81076dc6e94",
        archive_bytes=272_921_836,
        archive_sha256="a67e82c5af501db31261b37cae4cf0270b9c08a8d73b68d867f825669e85a2f6",
        top_level="esp32-arduino-libs",
        destination_name="framework-arduinoespressif32-libs",
        piopm=LIBS_PIOPM,
        maximum_entries=45_000,
        maximum_file_bytes=32 * 1024 * 1024,
        maximum_total_file_bytes=2_000_000_000,
    ),
)

OFFICIAL_PLATFORM_URI = (
    "https://github.com/pioarduino/platform-espressif32/releases/download/"
    "55.03.37/platform-espressif32.zip"
)
PLATFORM_PIOPM = (
    b'{"type": "platform", "name": "espressif32", "version": "55.3.37", '
    b'"spec": {"owner": null, "id": null, "name": "platform-espressif32", '
    b'"requirements": null, "uri": "'
    + OFFICIAL_PLATFORM_URI.encode("ascii")
    + b'"}}'
)
PLATFORM_ARCHIVE_SPEC = ZipArchiveSpec(
    label="pioarduino platform 55.03.37",
    cache_name="5798f89f844ab07be4281e122fc8ca4fb5460f00",
    archive_bytes=1_678_517,
    archive_sha256="ffce4a512581abd417c42edf2695a3b49e8b1447849847d3f62d0db695da9efc",
    top_level="platform-espressif32-55.03.37",
    destination_name=GLOBAL_PLATFORM_DIRECTORY_NAME,
    piopm=PLATFORM_PIOPM,
    entries=696,
    files=563,
    directories=133,
    file_bytes=20_465_392,
    compressed_file_bytes=1_511_837,
    maximum_file_bytes=5_383_915,
    mode_counts=((0o040755, 133), (0o100644, 559), (0o100755, 4)),
    manifest_bytes=124_069,
    manifest_sha256="f8db980da24b49a58fb8bf7669af250b5beae0769927a491464446898fb04d8a",
)

OFFICIAL_ESPTOOL_URI = (
    "https://github.com/pioarduino/esptool/releases/download/v5.1.2/esptool.zip"
)
ESPTOOL_REGISTRY_URI = (
    "https://github.com/pioarduino/registry/releases/download/0.0.1/"
    "esptoolpy-v5.1.2.zip"
)
ESPTOOL_PIOPM = (
    b'{"type": "tool", "name": "tool-esptoolpy", "version": "5.1.2", '
    b'"spec": {"owner": null, "id": null, "name": "esptool", '
    b'"requirements": null, "uri": "'
    + OFFICIAL_ESPTOOL_URI.encode("ascii")
    + b'"}}'
)
ESPTOOL_ARCHIVE_SPEC = ZipArchiveSpec(
    label="pioarduino esptool 5.1.2",
    cache_name="3f7d8fe6735053f7ebe9f2dc57e031273d0c3b3c",
    archive_bytes=506_890,
    archive_sha256="07295e31b0499a387f7315c2ce319e6d141bb8157461fe46fa914faeb8462ed1",
    # This official tool ZIP is intentionally rootless. The ZIP validator
    # still requires explicit directories, canonical paths and exact modes.
    top_level="",
    destination_name="tool-esptoolpy",
    piopm=ESPTOOL_PIOPM,
    entries=188,
    files=164,
    directories=24,
    file_bytes=1_898_192,
    compressed_file_bytes=473_908,
    maximum_file_bytes=91_075,
    mode_counts=((0o040755, 24), (0o100644, 159), (0o100755, 5)),
    manifest_bytes=27_714,
    manifest_sha256="c87125d44cfed7bb185c95fab0d0e675b10e335607b4d72b5a984b6a518d5c25",
)

WINDOWS_RESERVED_NAMES = {
    "CON", "PRN", "AUX", "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def pinned_identity(directories: int, entries: int, file_bytes: int, files: int,
                    inventory_bytes: int, inventory_sha256: str, *,
                    hardlink_groups: int = 0,
                    hardlink_sha256: str = EMPTY_SHA256) -> dict[str, object]:
    return {
        "directories": directories,
        "entries": entries,
        "file_bytes": file_bytes,
        "files": files,
        "hardlink_groups": hardlink_groups,
        "hardlink_sha256": hardlink_sha256,
        "inventory_bytes": inventory_bytes,
        "inventory_sha256": inventory_sha256,
        "schema": INVENTORY_SCHEMA,
    }


PINNED_PENV_IDENTITY = pinned_identity(
    946, 7_675, 322_949_944, 6_729, 1_327_424,
    "70b0421e0281e06bc1f72e77c545b8b25b904afd893934bc1f42f8f3b182e53c",
    hardlink_groups=2_960,
    hardlink_sha256="5cb863745e681997a5f5b9d7ef011fa58f1f6b17edc11d4438011dc3619fe8e1",
)
# The Aug 10 baseline above was reconciled on Aug 12 against the only drift:
# two newly materialised __pycache__ directories and ten .pyc files. Removing
# those 12 records (329,176 bytes; canonical record manifest 2,214 bytes,
# SHA-256 224af1bfec1aee9400120a9faf9c4ad083927b128ab39c6f738af785b495771c)
# reproduces PINNED_PENV_IDENTITY exactly. The cacheless identity below is thus
# rooted in that earlier approved baseline, not a blessing of the stale tree.
PINNED_CACHELESS_PENV_IDENTITY = pinned_identity(
    702, 5_574, 287_661_530, 4_872, 927_973,
    "7f528779d5cfcb5cbbdae4e0b10e5b8da29c37d9966d2be4abfeb6aa87423c4f",
    hardlink_groups=2_960,
    hardlink_sha256="5cb863745e681997a5f5b9d7ef011fa58f1f6b17edc11d4438011dc3619fe8e1",
)
# Filled from direct safe extraction of ESPTOOL_ARCHIVE_SPEC plus the exact
# ESPTOOL_PIOPM bytes. Runtime-cache exclusion remains fail-closed for the
# lane-local source even though the official archive contains no bytecode.
PINNED_ESPTOOL_EXTRACTED_IDENTITY = pinned_identity(
    24, 189, 1_898_417, 165, 27_751,
    "6d45ef78a475920ad7ea88c6cb832ae36f07c2c7bf8426d348af3e6f39c0cbf1",
)
# Derived by safe direct extraction from PLATFORM_ARCHIVE_SPEC plus the exact
# PLATFORM_PIOPM bytes. This is not the mutable global-platform aggregate.
PINNED_PLATFORM_EXTRACTED_IDENTITY = pinned_identity(
    132, 696, 20_465_661, 564, 99_589,
    "fda404645d5aa0aa0316653b40af071fba795edcaea5ab2ecd8a94e326e874e4",
)
# The global framework and framework-libs directories are intentionally absent
# here.  They are mutable under pioarduino custom_sdkconfig and READY27 accepts
# them only from the pinned official archives above.
PINNED_COPIED_PACKAGE_IDENTITIES = {
    "contrib-piohome": pinned_identity(
        2, 15, 3_358_744, 13, 1_972,
        "c921786d2262d051144fffc7f575f7ce86c633a5dd2ad5a64c4984e9764897bc"),
    "framework-espidf": pinned_identity(
        4_862, 30_398, 425_445_611, 25_536, 5_202_926,
        "4c3751fec5db3dd3a020af87769633464039c0c0aa51fcffbdbd335d8d9f8c68"),
    "tool-cmake": pinned_identity(
        127, 8_326, 124_335_566, 8_199, 1_473_842,
        "d9f2cbe1040e4d8b59068e0c6698e14fdfa7363dd59161bb8bb70ed8736a95e5"),
    "tool-cppcheck": pinned_identity(
        3, 85, 12_915_309, 82, 11_855,
        "49b14978a17afe88d00b43fc84d00dbbc9a23d4ef2ab46660baf272791766e41"),
    "tool-esp-rom-elfs": pinned_identity(
        0, 14, 6_919_196, 14, 2_046,
        "05a692ab84b5370358a5a490f043009ceb157279611e2079c74487d1d7aa9d4b"),
    "tool-esp_install": pinned_identity(
        2, 14, 204_774, 12, 1_915,
        "4489e15b6387ee3f1ab2b7b19669611bf6e6b162f9b2d855cfab96fcc1a20b8b"),
    "tool-mkfatfs": pinned_identity(
        0, 6, 3_519_100, 6, 844,
        "f2233bc5e94a106167a023154e6560b0d6a8097be73f0da2b6f23f81a6220cd4"),
    "tool-mklittlefs": pinned_identity(
        0, 3, 984_066, 3, 410,
        "c99295798c0029faf5fe1b15c696d0de2db41e87e3a2bd5266aea2f9cf82c07b"),
    "tool-mkspiffs": pinned_identity(
        0, 5, 2_019_304, 5, 749,
        "c8722ed530ad2efeab7946bbc71f7510d272f00c584d6c76d2e757b10adb98f3"),
    "tool-ninja": pinned_identity(
        0, 3, 599_130, 3, 405,
        "2b90a84932f58b2d77dc81e68ebab6d331d73d6583e052d88518e9f9b3af89cf"),
    "tool-scons": pinned_identity(
        27, 313, 3_547_748, 286, 51_004,
        "044c1e21e9077697c496d2efc00fb5a15ef5233dcf56336dfa0f8088b23c6dea"),
    "toolchain-riscv32-esp": pinned_identity(
        262, 2_533, 2_465_248_984, 2_271, 450_207,
        "7fa18be6548e83ecc912e79c699c9bc02823dd6d5f0525747f585d2fb7ccbf88"),
    "toolchain-xtensa-esp-elf": pinned_identity(
        0, 3, 4_426, 3, 404,
        "86dba8d36aa9562eaff74ef38a5c87921470f13c13d85ce367cd0689a3095837"),
    "toolchain-xtensa-esp32": pinned_identity(
        166, 1_622, 416_518_271, 1_456, 274_880,
        "6503b76559e04d3708efd97d19ac11b92186ce9579d3d9124f4092b82965f604"),
}

PINNED_PACKAGE_VERSIONS = {
    "contrib-piohome": "3.4.4",
    "framework-espidf": "3.50502.0",
    "tool-cmake": "4.0.3",
    "tool-cppcheck": "2.11.0+230717",
    "tool-esp-rom-elfs": "2024.10.11",
    "tool-esp_install": "5.3.4",
    # The private source comes from ESPTOOL_ARCHIVE_SPEC rather than this copied
    # package allowlist; this value is retained for exact package verification.
    "tool-esptoolpy": ESPTOOL_PLATFORMIO_PACKAGE_VERSION,
    "tool-mkfatfs": "2.0.1",
    "tool-mklittlefs": "1.203.210628",
    "tool-mkspiffs": "2.230.0",
    "tool-ninja": "1.13.1",
    "tool-scons": "4.40801.0",
    "toolchain-riscv32-esp": "14.2.0+20251107",
    "toolchain-xtensa-esp-elf": "14.2.0+20251107",
    "toolchain-xtensa-esp32": "8.4.0+2021r2-patch5",
}

PINNED_REGISTRY_DEPENDENCY_IDENTITIES = {
    "ArduinoJson": pinned_identity(
        32, 189, 376_196, 157, 28_454,
        "0adbe053aea2fb8d59f14eaf8806a455cdc92229e9d13eac6b441ab465634525"),
    "PNGdec": pinned_identity(
        23, 86, 2_603_398, 63, 11_549,
        "9b36c3df391f8845201e5903a1bcfee545ea0dacdfaab70250ab99c6f3b47ed5"),
    "QRCode": pinned_identity(
        3, 12, 54_739, 9, 1_399,
        "2f146591c78cdb4c4856e456ac9d802c0b60596081919d8ed1fb56f6c8a77d0f"),
    "SdFat": pinned_identity(
        75, 278, 1_189_908, 203, 37_652,
        "9752874b3f71e11db80fbea5b5040c5c3d723889870422d78c021f1e53428372"),
}

PINNED_REGISTRY_DEPENDENCY_VERSIONS = {
    "ArduinoJson": "7.4.2",
    "PNGdec": "1.1.6",
    "QRCode": "0.0.1",
    "SdFat": "2.3.1",
}

GIT_DEPENDENCY_SPECS = (
    GitDependencySpec(
        "JPEGDEC", "86282979224c8a32fd51e091ed5a35b0c699a52b",
        "https://github.com/bitbank2/JPEGDEC.git", 243,
        "4705ccd9f7e5ffa3d16fa1c2521af7e8f8795e93e3e93ca708a4e5b87e1b7481",
        "src/jpeg.inl", 246_671,
        "34c6eb16b56b9ee86108b8ca22ac42bbdf0c31bc3bb4ceb61f844f9ee344e2a9",
        252_625,
        "fd5d20da6e01d7900c6b48413bb1b19ed10fe82960231c28346c353820e78967",
        2_108,
        "f940917903ab4b056675c04b38253a03b9540f1d46a81873dc3cd3172ac899bf",
        "true",
    ),
    GitDependencySpec(
        "NimBLE-Arduino", "f66f4fe26306747cd8308e77d755da1863219089",
        "https://github.com/h2zero/NimBLE-Arduino.git", 263,
        "af3d65e161938f35d08cf79ca29a0e904eca9d92edda48bfcf817ceb1ccb8191",
        "src/nimconfig.h", 13_949,
        "c4caa5fe877b734349dce027ba5037e5e875df085931eb72404ecf0fa10cc830",
        13_996,
        "332223dd5b0bed8c50608501ac9e99f7da538831d5b48daeae303ad5c948c2ab",
        467,
        "e0c7fcc35b4c5e250da5147a95413500ff7ef91691fcfd3103fe0fa44c0832da",
        "false",
    ),
    GitDependencySpec(
        "WebSockets", "1c8b8deaca30b36494a4f6ea4df23ae862b21662",
        "https://github.com/Links2004/arduinoWebSockets.git", 267,
        "a8fb15f5e79fe4902dba176b4556644ea7f9861ea0946c99c42f8f4c5dfbcad2",
    ),
    GitDependencySpec(
        "wolfssl", "9ecc5e79bdcbcf49402a5d967bc232b4c39c0076",
        "https://github.com/wolfSSL/Arduino-wolfSSL.git", 258,
        "ae90ec07dc1951823a492ed55c89a238d70ba0a35140b1835b91fe8ccd879e80",
        "src/user_settings.h", 18_909,
        "26154f04d38aa0d3b140ed8c63ee21cc14cee86335cb399eef8c4b3f631b364d",
        20_014,
        "311eb5652e2f487f56d45fdbdb6be9d61334a18a1bc2a2e2f962dac749ece5cc",
        876,
        "ebdb135b077b8d93278bf684fba196d01fb7604c0fe05f7753de6d335c5516da",
        "true",
    ),
)

PINNED_LIBDEPS_CONTROL_FILES = {
    "integrity.dat": (1_117, "db6a1086991f27030af00d57375da5e8a45557a9e8d3df1f8eef57f865edb6d8"),
}

# Derived from safe ``git archive`` reconstruction of each exact commit plus
# its reviewed working-tree patch (where specified) and exact root .piopm.
# Git metadata itself is never copied into a private READY27 core.
PINNED_GIT_DEPENDENCY_SEED_IDENTITIES = {
    "JPEGDEC": pinned_identity(
        37, 126, 6_194_406, 89, 16_807,
        "114a8a216b825e10a776506d1f51f61c1c74071e10ef9f07b6ab2023530947c7"),
    "NimBLE-Arduino": pinned_identity(
        143, 623, 6_171_102, 480, 91_948,
        "f70a997e776c0dd15c0d4772a143c3d44c1c26091ff82b8bd0b5fcd158032918"),
    "WebSockets": pinned_identity(
        49, 137, 580_326, 88, 18_662,
        "845b9fe63ec1dc9ff2914244e9fbddd18911fc28315370eb80e37ed714d62417"),
    "wolfssl": pinned_identity(
        17, 335, 46_808_379, 318, 49_853,
        "1f1894c7a7dfe6ebd332dfbb85a26dcb99754bc8b2faf28e45356ed66831bbc8"),
}
# Complete portable source input: four registry trees, four Git-origin trees
# reconstructed at their exact commits and one path-independent integrity file.
# Local ``.pio-link`` records are generated into the private lane because their
# ``cwd`` field must name the actual public checkout; absolute paths are never
# shipped or pinned.
PINNED_PORTABLE_DEPENDENCY_SOURCE_IDENTITY = pinned_identity(
    387, 1_795, 63_979_571, 1_408, 276_027,
    "ef2564aa9aa1d1de2e8eaba2b5d5a8664251d8b4a49d228bbc28e2f146b1bf55",
)

LOCAL_LINK_SPECS = {
    "BatteryMonitor": "symlink://freeink-sdk/libs/hardware/BatteryMonitor",
    "BoardConfig": "symlink://freeink-sdk/libs/hardware/BoardConfig",
    "EInkDisplay": "symlink://freeink-sdk/libs/display/FreeInkDisplay",
    "FreeInkUI": "symlink://freeink-sdk/libs/ui/FreeInkUI",
    "Icons": "symlink://freeink-sdk/libs/assets/Icons",
    "Imu": "symlink://freeink-sdk/libs/hardware/Imu",
    "InputManager": "symlink://freeink-sdk/libs/hardware/InputManager",
    "PowerManager": "symlink://freeink-sdk/libs/hardware/PowerManager",
    "Rtc": "symlink://freeink-sdk/libs/hardware/Rtc",
    "SDCardManager": "symlink://freeink-sdk/libs/hardware/SDCardManager",
    "SecureNet": "symlink://freeink-sdk/libs/network/SecureNet",
    "XteinkDetect": "symlink://freeink-sdk/libs/hardware/XteinkDetect",
}

PINNED_SHIPPED_BINARY_INPUTS = {
    "JPEGDEC/linux/examples/jpeg_perf_test/main.o": (
        69_792,
        "8b344ada9e5c11de586b2281925ad25664df71473cbbeeebd3f82ba8c53fd005",
    ),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Ready27CacheError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(COPY_BUFFER_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def stable_file_record(path: Path, label: str, *,
                       allow_source_hardlinks: bool) -> tuple[os.stat_result, str]:
    """Hash one open file descriptor and reject an in-flight metadata change."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
        require(not is_reparse_stat(before), f"{label} is a reparse point")
        require(allow_source_hardlinks or int(getattr(before, "st_nlink", 1)) == 1,
                f"{label} has multiple hard links")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while chunk := handle.read(COPY_BUFFER_BYTES):
                digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable_fields = ("st_mode", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
    require(all(getattr(before, field) == getattr(after, field) for field in stable_fields),
            f"{label} changed while hashing")
    require(path.stat(follow_symlinks=False).st_ino == before.st_ino,
            f"{label} was replaced while hashing")
    return before, digest.hexdigest()


def is_reparse_stat(value: os.stat_result) -> bool:
    attributes = int(getattr(value, "st_file_attributes", 0))
    return bool(attributes & FILE_ATTRIBUTE_REPARSE_POINT)


def require_plain_directory(path: Path, label: str) -> os.stat_result:
    try:
        value = path.stat(follow_symlinks=False)
    except (OSError, ValueError) as error:
        raise Ready27CacheError(f"{label} is unavailable: {path}") from error
    require(stat.S_ISDIR(value.st_mode), f"{label} is not a directory: {path}")
    require(not is_reparse_stat(value), f"{label} is a reparse point: {path}")
    return value


def require_plain_file(path: Path, label: str) -> os.stat_result:
    try:
        value = path.stat(follow_symlinks=False)
    except (OSError, ValueError) as error:
        raise Ready27CacheError(f"{label} is unavailable: {path}") from error
    require(stat.S_ISREG(value.st_mode), f"{label} is not a regular file: {path}")
    require(not is_reparse_stat(value), f"{label} is a reparse point: {path}")
    require(int(getattr(value, "st_nlink", 1)) == 1,
            f"{label} has multiple hard links: {path}")
    return value


def require_direct_child(parent: Path, child: Path, label: str) -> None:
    parent_resolved = parent.resolve(strict=True)
    child_parent = child.parent.resolve(strict=True)
    require(child_parent == parent_resolved,
            f"{label} is not a direct child of its reviewed parent: {child}")


def validate_relative_parts(parts: tuple[str, ...], label: str) -> str:
    require(parts, f"{label} has an empty path")
    relative = "/".join(parts)
    try:
        relative_bytes = relative.encode("ascii")
    except UnicodeEncodeError as error:
        raise Ready27CacheError(f"{label} is not ASCII: {relative!r}") from error
    require(len(relative_bytes) <= MAX_RELATIVE_PATH_BYTES,
            f"{label} is too long: {relative!r}")
    for part in parts:
        part_bytes = part.encode("ascii")
        require(part not in ("", ".", ".."), f"{label} has an unsafe segment")
        require(len(part_bytes) <= MAX_PATH_SEGMENT_BYTES,
                f"{label} has an oversized segment: {part!r}")
        require(not part.endswith((" ", ".")),
                f"{label} has a Windows-aliased segment: {part!r}")
        require(not any(ord(character) < 0x20 for character in part),
                f"{label} contains a control character")
        require(not any(character in '<>:"\\|?*' for character in part),
                f"{label} contains a Windows-reserved character: {part!r}")
        basename = part.split(".", 1)[0].upper()
        require(basename not in WINDOWS_RESERVED_NAMES,
                f"{label} contains a Windows-reserved name: {part!r}")
    return relative


def canonical_relative(parts: tuple[str, ...], label: str) -> str:
    return validate_relative_parts(parts, label).casefold()


def is_runtime_cache_parts(parts: tuple[str, ...], *, is_directory: bool) -> bool:
    folded = tuple(part.casefold() for part in parts)
    if RUNTIME_CACHE_DIRECTORY in folded:
        return True
    return not is_directory and folded[-1].endswith(RUNTIME_CACHE_SUFFIXES)


def validate_excluded_runtime_cache(path: Path, value: os.stat_result,
                                    label: str, parts: tuple[str, ...]) -> None:
    """Prove ignored bytecode state is ordinary and cannot hide a link/special."""
    relative = "/".join(parts)
    if stat.S_ISREG(value.st_mode):
        require(parts[-1].casefold().endswith(RUNTIME_CACHE_SUFFIXES),
                f"{label} excluded runtime file has an unexpected suffix: {relative}")
        stable_file_record(path, f"{label} excluded runtime file {relative}",
                           allow_source_hardlinks=False)
        return

    require(stat.S_ISDIR(value.st_mode) and
            parts[-1].casefold() == RUNTIME_CACHE_DIRECTORY,
            f"{label} excluded runtime entry is not a cache directory: {relative}")
    require(not is_reparse_stat(value),
            f"{label} excluded runtime directory is a reparse point: {relative}")
    try:
        children = list(os.scandir(path))
    except OSError as error:
        raise Ready27CacheError(
            f"Cannot enumerate {label} excluded runtime directory: {relative}") from error
    for child in children:
        child_path = Path(child.path)
        child_parts = (*parts, child.name)
        validate_relative_parts(child_parts, f"{label} excluded runtime entry")
        child_value = child_path.stat(follow_symlinks=False)
        require(not is_reparse_stat(child_value),
                f"{label} excluded runtime entry is a reparse point: {'/'.join(child_parts)}")
        require(stat.S_ISREG(child_value.st_mode),
                f"{label} excluded runtime directory contains a non-file: {'/'.join(child_parts)}")
        require(child.name.casefold().endswith(RUNTIME_CACHE_SUFFIXES),
                f"{label} excluded runtime directory contains non-bytecode: {'/'.join(child_parts)}")
        stable_file_record(
            child_path, f"{label} excluded runtime file {'/'.join(child_parts)}",
            allow_source_hardlinks=False)


def tree_inventory(root: Path, *, label: str,
                   maximum_entries: int = MAX_INVENTORY_ENTRIES,
                   allow_source_hardlinks: bool = False,
                   exclude_runtime_cache: bool = False) -> dict[str, object]:
    """Hash a plain tree including relative path, kind, mode and file bytes."""
    require_plain_directory(root, label)
    records: list[dict[str, object]] = []
    canonical_paths: set[str] = set()
    pending: list[tuple[Path, tuple[str, ...]]] = [(root, ())]
    total_file_bytes = 0
    file_count = 0
    directory_count = 0
    hardlink_paths: dict[tuple[int, int], list[tuple[str, int]]] = {}

    while pending:
        directory, parent_parts = pending.pop()
        require_plain_directory(directory, f"{label} directory")
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError as error:
            raise Ready27CacheError(f"Cannot enumerate {label}: {directory}") from error
        child_directories: list[tuple[Path, tuple[str, ...]]] = []
        for entry in entries:
            parts = (*parent_parts, entry.name)
            relative = validate_relative_parts(parts, f"{label} entry")
            try:
                # CPython's Windows DirEntry stat cache reports st_nlink=0 for
                # ordinary files.  Re-stat the literal path so hard-link
                # rejection uses the kernel-backed link count.
                value = Path(entry.path).stat(follow_symlinks=False)
            except OSError as error:
                raise Ready27CacheError(f"Cannot stat {label} entry: {relative}") from error
            require(not is_reparse_stat(value),
                    f"{label} contains a reparse point: {relative}")
            if exclude_runtime_cache and is_runtime_cache_parts(
                    parts, is_directory=stat.S_ISDIR(value.st_mode)):
                validate_excluded_runtime_cache(
                    Path(entry.path), value, label, parts)
                continue
            canonical = relative.casefold()
            require(canonical not in canonical_paths,
                    f"{label} contains a case-folding duplicate: {relative}")
            canonical_paths.add(canonical)
            require(len(canonical_paths) <= maximum_entries,
                    f"{label} exceeds its entry cap")
            mode = stat.S_IMODE(value.st_mode)
            if stat.S_ISDIR(value.st_mode):
                directory_count += 1
                records.append({"kind": "directory", "mode": mode, "path": relative})
                child_directories.append((Path(entry.path), parts))
            elif stat.S_ISREG(value.st_mode):
                stable_value, digest = stable_file_record(
                    Path(entry.path), f"{label} file {relative}",
                    allow_source_hardlinks=allow_source_hardlinks)
                size = int(stable_value.st_size)
                mode = stat.S_IMODE(stable_value.st_mode)
                link_count = int(getattr(stable_value, "st_nlink", 1))
                if link_count > 1:
                    key = (int(stable_value.st_dev), int(stable_value.st_ino))
                    hardlink_paths.setdefault(key, []).append((relative, link_count))
                file_count += 1
                total_file_bytes += size
                records.append({
                    "bytes": size,
                    "kind": "file",
                    "mode": mode,
                    "path": relative,
                    "sha256": digest,
                })
            else:
                raise Ready27CacheError(f"{label} contains a special file: {relative}")
        pending.extend(reversed(child_directories))

    records.sort(key=lambda record: str(record["path"]).casefold())
    canonical_bytes = b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        for record in records
    )
    hardlink_groups = []
    for paths in hardlink_paths.values():
        sorted_paths = sorted(path for path, _count in paths)
        link_count = paths[0][1]
        require(all(count == link_count for _path, count in paths),
                f"{label} hard-link count changed during inventory")
        hardlink_groups.append({
            "external_links": link_count - len(sorted_paths),
            "links": link_count,
            "paths": sorted_paths,
        })
    hardlink_groups.sort(key=lambda group: tuple(group["paths"]))
    hardlink_bytes = b"".join(
        (json.dumps(group, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        for group in hardlink_groups
    )
    return {
        "directories": directory_count,
        "entries": len(records),
        "file_bytes": total_file_bytes,
        "files": file_count,
        "hardlink_groups": len(hardlink_groups),
        "hardlink_sha256": hashlib.sha256(hardlink_bytes).hexdigest(),
        "inventory_bytes": len(canonical_bytes),
        "inventory_sha256": hashlib.sha256(canonical_bytes).hexdigest(),
        "records": records,
        "schema": INVENTORY_SCHEMA,
    }


def inventory_identity(inventory: dict[str, object]) -> dict[str, object]:
    return {
        key: inventory[key]
        for key in (
            "directories", "entries", "file_bytes", "files",
            "hardlink_groups", "hardlink_sha256", "inventory_bytes",
            "inventory_sha256", "schema",
        )
    }


def inventory_content_identity(inventory: dict[str, object]) -> dict[str, object]:
    """Identity that intentionally ignores source-only hard-link topology."""
    return {
        key: inventory[key]
        for key in (
            "directories", "entries", "file_bytes", "files",
            "inventory_bytes", "inventory_sha256", "schema",
        )
    }


def require_pinned_identity(inventory: dict[str, object], expected: dict[str, object],
                            label: str) -> None:
    actual = inventory_identity(inventory)
    require(actual == expected,
            f"{label} inventory changed: expected {expected}, found {actual}")


def require_pinned_content_identity(inventory: dict[str, object],
                                    expected: dict[str, object], label: str) -> None:
    """Pin paths, modes and bytes while ignoring source-only link topology."""
    actual = inventory_content_identity(inventory)
    expected_content = inventory_content_identity(expected)
    require(actual == expected_content,
            f"{label} content inventory changed: expected {expected_content}, "
            f"found {actual}")


def load_strict_json_object(path: Path, label: str) -> dict[str, object]:
    require_plain_file(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise Ready27CacheError(f"{label} is not valid JSON") from error
    require(isinstance(value, dict), f"{label} is not a JSON object")
    return value


def path_is_within(path: Path, root: Path) -> bool:
    """Case-correct containment check for resolved Windows paths."""
    path_text = os.path.normcase(str(path.resolve()))
    root_text = os.path.normcase(str(root.resolve()))
    try:
        return os.path.commonpath((path_text, root_text)) == root_text
    except ValueError:
        return False


def require_private_path(path_text: object, core: Path, expected: Path,
                         label: str) -> str:
    require(isinstance(path_text, str) and bool(path_text),
            f"{label} path is missing")
    path = Path(path_text).resolve()
    require(path == expected.resolve(), f"{label} path changed: {path}")
    require(path_is_within(path, core), f"{label} escaped the private core")
    return path.relative_to(core.resolve()).as_posix()


def reject_global_platformio_path(path_text: object, core: Path, label: str) -> None:
    """Reject sibling global PlatformIO state while allowing this private lane."""
    if not isinstance(path_text, str) or not path_text or path_text.startswith("__editable__."):
        return
    candidate = Path(path_text).resolve()
    global_root = core.parent.resolve()
    if path_is_within(candidate, global_root):
        require(path_is_within(candidate, core),
                f"{label} resolves through global PlatformIO state: {candidate}")


def package_excludes_runtime_cache(name: str) -> bool:
    """Return the reviewed per-package generated-bytecode policy."""
    return name in RUNTIME_CACHE_EXCLUDED_PACKAGE_NAMES


def esptool_rebind_paths(core: Path) -> tuple[Path, Path, Path, Path]:
    penv = core / "penv"
    return (
        penv / "Scripts" / "python.exe",
        penv / "Scripts" / "uv.exe",
        penv / "Lib" / "site-packages",
        core / "packages" / "tool-esptoolpy",
    )


def esptool_launcher_generator_code() -> str:
    """Small pinned launcher generator; it does not import setuptools or wheel."""
    return r'''import json,pathlib,sys
import pip
from pip._vendor import distlib
from pip._internal.operations.install.wheel import PipScriptMaker
target=pathlib.Path(sys.argv[1]).resolve()
executable=pathlib.Path(sys.argv[2]).resolve()
specs=json.loads(sys.argv[3])
target.mkdir(parents=False,exist_ok=False)
maker=PipScriptMaker(None,str(target))
maker.executable=str(executable)
maker.clobber=True
maker.variants={""}
maker.set_mode=True
created=maker.make_multiple(specs)
print(json.dumps({"created":[str(pathlib.Path(p).resolve()) for p in created],"distlib":distlib.__version__,"pip":pip.__version__},sort_keys=True))'''


def esptool_rebind_command(core: Path, output_directory: Path) -> list[str]:
    python_exe, _uv_exe, _site_packages, _package = esptool_rebind_paths(core)
    return [
        str(python_exe), "-I", "-B", "-c", esptool_launcher_generator_code(),
        str(output_directory), str(python_exe),
        json.dumps(ESPTOOL_CONSOLE_SPECS, separators=(",", ":")),
    ]


def private_esptool_environment(core: Path) -> dict[str, str]:
    """Minimal environment whose package and temporary writes remain lane-local."""
    _python_exe, _uv_exe, _site_packages, _package = esptool_rebind_paths(core)
    cache = core / ".cache"
    require_plain_directory(cache, "READY27 private cache directory")
    temporary = cache / "esptool-rebind-tmp"
    for directory in (temporary,):
        if not directory.exists():
            directory.mkdir()
        require_plain_directory(directory, "READY27 private esptool runtime directory")

    inherited = os.environ
    env = {
        name: inherited[name]
        for name in ("COMSPEC", "PATHEXT", "SYSTEMDRIVE", "SYSTEMROOT", "WINDIR")
        if inherited.get(name)
    }
    env.update({
        "ALL_PROXY": "http://127.0.0.1:9",
        "HTTP_PROXY": "http://127.0.0.1:9",
        "HTTPS_PROXY": "http://127.0.0.1:9",
        "NO_PROXY": "",
        "PIP_NO_INDEX": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONNOUSERSITE": "1",
        "PYTHONUTF8": "1",
        "TEMP": str(temporary),
        "TMP": str(temporary),
        "all_proxy": "http://127.0.0.1:9",
        "http_proxy": "http://127.0.0.1:9",
        "https_proxy": "http://127.0.0.1:9",
        "no_proxy": "",
    })
    return env


def validate_esptool_probe(probe: dict[str, object], core: Path) -> dict[str, object]:
    """Validate and normalize one private-Python esptool identity probe."""
    python_exe, uv_exe, site_packages, package = esptool_rebind_paths(core)
    penv = core / "penv"
    expected_mapping = {
        name: str((package / name).resolve()) for name in ESPTOOL_TOP_LEVEL_PACKAGES
    }
    expected_namespaces = {
        "espefuse.efuse_defs": [str((package / "espefuse" / "efuse_defs").resolve())],
        "esptool.targets.stub_flasher": [
            str((package / "esptool" / "targets" / "stub_flasher").resolve())
        ],
        "esptool.targets.stub_flasher.1": [
            str((package / "esptool" / "targets" / "stub_flasher" / "1").resolve())
        ],
        "esptool.targets.stub_flasher.2": [
            str((package / "esptool" / "targets" / "stub_flasher" / "2").resolve())
        ],
    }
    require(probe.get("version") == ESPTOOL_DISTRIBUTION_VERSION,
            "Private esptool distribution version changed")
    require(probe.get("module_version") == ESPTOOL_MODULE_VERSION,
            "Private esptool module version changed")
    require(probe.get("dist_name") == "esptool",
            "Private esptool distribution name changed")
    require(probe.get("user_site") is False,
            "Private esptool probe enabled the user site")
    executable = require_private_path(
        probe.get("executable"), core, python_exe, "Private esptool Python")
    prefix = require_private_path(probe.get("prefix"), core, penv,
                                  "Private esptool prefix")
    finder = require_private_path(
        probe.get("finder"), core, site_packages / ESPTOOL_EDITABLE_FINDER,
        "Private esptool editable finder")
    dist_info = require_private_path(
        probe.get("dist_info"), core,
        site_packages / f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info",
        "Private esptool distribution metadata")

    direct_url = probe.get("direct_url")
    require(direct_url == {
        "dir_info": {"editable": True},
        "url": package.resolve().as_uri(),
    }, "Private esptool editable direct URL changed")
    mapping = probe.get("mapping")
    namespaces = probe.get("namespaces")
    require(mapping == expected_mapping,
            "Private esptool editable finder mapping changed")
    require(namespaces == expected_namespaces,
            "Private esptool editable namespace mapping changed")

    imports = probe.get("imports")
    require(isinstance(imports, dict), "Private esptool import record is missing")
    normalized_imports: dict[str, str] = {}
    for name in ESPTOOL_TOP_LEVEL_PACKAGES:
        normalized_imports[name] = require_private_path(
            imports.get(name), core, package / name / "__init__.py",
            f"Private esptool import {name}")

    for group_name, group in (("mapping", mapping), ("namespaces", namespaces)):
        require(isinstance(group, dict), f"Private esptool {group_name} is not an object")
        for name, value in group.items():
            values = value if isinstance(value, list) else [value]
            for item in values:
                reject_global_platformio_path(
                    item, core, f"Private esptool {group_name} {name}")
    sys_path = probe.get("sys_path")
    require(isinstance(sys_path, list), "Private esptool sys.path record is missing")
    for index, item in enumerate(sys_path):
        reject_global_platformio_path(item, core, f"Private esptool sys.path[{index}]")

    return {
        "direct_url": direct_url,
        "dist_info": dist_info,
        "distribution": {"name": "esptool", "version": ESPTOOL_DISTRIBUTION_VERSION},
        "module_version": ESPTOOL_MODULE_VERSION,
        "editable": {
            "finder": finder,
            "mapping": {
                name: (package / name).relative_to(core).as_posix()
                for name in ESPTOOL_TOP_LEVEL_PACKAGES
            },
            "namespaces": {
                name: [Path(value).relative_to(core.resolve()).as_posix()
                       for value in expected_namespaces[name]]
                for name in ESPTOOL_NAMESPACES
            },
        },
        "imports": normalized_imports,
        "python": {"executable": executable, "prefix": prefix},
    }


def private_esptool_package_identity(core: Path) -> dict[str, object]:
    """Recompute and pin every non-cache byte in the lane-local esptool source."""
    package = esptool_rebind_paths(core)[3]
    require_plain_directory(package, "READY27 private tool-esptoolpy")
    require(path_is_within(package, core),
            "READY27 private tool-esptoolpy escaped its private core")
    full_inventory = tree_inventory(
        package, label="READY27 private tool-esptoolpy")
    cacheless_inventory = tree_inventory(
        package,
        label="READY27 private cacheless tool-esptoolpy",
        exclude_runtime_cache=True,
    )
    identity = inventory_identity(cacheless_inventory)
    require(identity == PINNED_ESPTOOL_EXTRACTED_IDENTITY,
            "READY27 private cacheless tool-esptoolpy source changed")
    require(inventory_identity(full_inventory) == identity,
            "READY27 private tool-esptoolpy contains runtime-cache state")
    return identity


def verify_esptool_platform_package_contract(core: Path) -> dict[str, object]:
    """Prove PlatformIO will accept the reviewed private package without download."""
    platform = core / "platforms" / GLOBAL_PLATFORM_DIRECTORY_NAME
    package = core / "packages" / ESPTOOL_ARCHIVE_SPEC.destination_name
    require_plain_directory(platform, "READY27 private platform")
    require_plain_directory(package, "READY27 private esptool package")
    platform_json = load_strict_json_object(
        platform / "platform.json", "READY27 private platform.json")
    packages = platform_json.get("packages")
    require(isinstance(packages, dict), "READY27 platform packages are missing")
    requirement = packages.get("tool-esptoolpy")
    require(isinstance(requirement, dict),
            "READY27 platform esptool requirement is missing")
    package_json = load_strict_json_object(
        package / "package.json", "READY27 private esptool package.json")
    piopm = load_strict_json_object(
        package / ".piopm", "READY27 private esptool .piopm")
    piopm_spec = piopm.get("spec")
    require(
        requirement.get("type") == "uploader" and
        requirement.get("optional") is True and
        requirement.get("owner") == "pioarduino" and
        requirement.get("package-version") == ESPTOOL_PLATFORMIO_PACKAGE_VERSION and
        requirement.get("version") == ESPTOOL_REGISTRY_URI and
        package_json.get("name") == "tool-esptoolpy" and
        package_json.get("version") == ESPTOOL_PLATFORMIO_PACKAGE_VERSION and
        piopm.get("type") == "tool" and
        piopm.get("name") == "tool-esptoolpy" and
        piopm.get("version") == ESPTOOL_PLATFORMIO_PACKAGE_VERSION and
        isinstance(piopm_spec, dict) and
        piopm_spec.get("name") == "esptool" and
        piopm_spec.get("uri") == OFFICIAL_ESPTOOL_URI,
        "READY27 platform/private esptool package identity is incompatible",
    )
    return {
        "module_version": ESPTOOL_MODULE_VERSION,
        "package_uri": OFFICIAL_ESPTOOL_URI,
        "package_version": ESPTOOL_PLATFORMIO_PACKAGE_VERSION,
        "platform_requirement_uri": ESPTOOL_REGISTRY_URI,
    }


def validate_esptool_construction_source(
        evidence: dict[str, object], live_identity: dict[str, object]) -> None:
    """Bind current esptool source bytes to the constructor's ZIP record."""
    extracted_tools = evidence.get("extracted_tools")
    require(isinstance(extracted_tools, dict),
            "READY27 construction evidence lacks extracted tools")
    extracted_esptool = extracted_tools.get("tool-esptoolpy")
    require(isinstance(extracted_esptool, dict) and
            set(extracted_esptool) == {"archive", "destination", "tree"},
            "READY27 construction evidence lacks the exact esptool extraction")
    archive = extracted_esptool.get("archive")
    require(isinstance(archive, dict),
            "READY27 construction evidence lacks the esptool archive record")
    require(
        archive.get("archive_bytes") == ESPTOOL_ARCHIVE_SPEC.archive_bytes and
        archive.get("archive_sha256") == ESPTOOL_ARCHIVE_SPEC.archive_sha256 and
        archive.get("entries") == ESPTOOL_ARCHIVE_SPEC.entries and
        archive.get("files") == ESPTOOL_ARCHIVE_SPEC.files and
        archive.get("directories") == ESPTOOL_ARCHIVE_SPEC.directories and
        archive.get("file_bytes") == ESPTOOL_ARCHIVE_SPEC.file_bytes and
        archive.get("compressed_file_bytes") ==
            ESPTOOL_ARCHIVE_SPEC.compressed_file_bytes and
        archive.get("manifest_bytes") == ESPTOOL_ARCHIVE_SPEC.manifest_bytes and
        archive.get("manifest_sha256") == ESPTOOL_ARCHIVE_SPEC.manifest_sha256 and
        archive.get("mode_counts") == {
            f"{mode:06o}": count
            for mode, count in ESPTOOL_ARCHIVE_SPEC.mode_counts
        } and
        archive.get("top_level") == ESPTOOL_ARCHIVE_SPEC.top_level,
        "READY27 construction evidence has an unpinned esptool archive",
    )
    recorded_tree = extracted_esptool.get("tree")
    require(isinstance(recorded_tree, dict) and
            inventory_identity(recorded_tree) == PINNED_ESPTOOL_EXTRACTED_IDENTITY,
            "READY27 construction evidence has an unpinned esptool tree")
    require(live_identity == PINNED_ESPTOOL_EXTRACTED_IDENTITY,
            "READY27 private tool-esptoolpy source differs from construction evidence")


def validate_esptool_launcher_payload(payload: bytes, python_exe: Path,
                                       forbidden_roots: tuple[str, ...],
                                       label: str) -> None:
    """Prove a distlib launcher embeds this lane's exact private interpreter."""
    folded = payload.lower()
    private_python = str(python_exe.resolve()).casefold().encode("utf-8")
    require(private_python in folded,
            f"{label} does not embed the exact private Python path")
    for root in forbidden_roots:
        require(root.encode("utf-8") not in folded and
                root.encode("utf-16le") not in folded,
                f"{label} retains a global PlatformIO path")


def esptool_probe_code() -> str:
    return r'''import importlib,importlib.metadata as m,json,pathlib,site,sys
d=m.distribution("esptool")
finder=importlib.import_module("__editable___esptool_5_1_2_finder")
mods={name:importlib.import_module(name) for name in ("esp_rfc2217_server","espefuse","espsecure","esptool")}
print(json.dumps({
 "direct_url":json.loads(d.read_text("direct_url.json")),
 "dist_info":str(pathlib.Path(d._path).resolve()),
 "dist_name":d.metadata["Name"],
 "executable":str(pathlib.Path(sys.executable).resolve()),
 "finder":str(pathlib.Path(finder.__file__).resolve()),
 "imports":{name:str(pathlib.Path(module.__file__).resolve()) for name,module in mods.items()},
 "mapping":finder.MAPPING,
 "module_version":mods["esptool"].__version__,
 "namespaces":finder.NAMESPACES,
 "prefix":str(pathlib.Path(sys.prefix).resolve()),
 "sys_path":list(sys.path),
 "user_site":site.ENABLE_USER_SITE,
 "version":d.version,
},sort_keys=True))'''


def record_sha256(payload: bytes) -> str:
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def atomic_replace_payload(path: Path, payload: bytes, label: str) -> None:
    """Replace one known plain file through an exclusive same-directory stage."""
    require_plain_file(path, label)
    stage = path.with_name(path.name + ".xtinct-rebind-stage")
    require(not os.path.lexists(stage), f"{label} stage already exists")
    with stage.open("xb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    staged = require_plain_file(stage, f"{label} stage")
    require(staged.st_size == len(payload) and
            hashlib.sha256(stage.read_bytes()).digest() == hashlib.sha256(payload).digest(),
            f"{label} stage changed")
    os.replace(stage, path)
    replaced = require_plain_file(path, label)
    require(replaced.st_size == len(payload) and path.read_bytes() == payload,
            f"{label} replacement changed")


def rewrite_esptool_record(record_path: Path,
                           replacements: dict[str, bytes]) -> bytes:
    """Update only the seven reviewed persistent files in wheel RECORD."""
    original = require_plain_file(record_path, "Private esptool RECORD")
    require(original.st_size <= 16 * 1024, "Private esptool RECORD is unexpectedly large")
    try:
        rows = list(csv.reader(io.StringIO(record_path.read_text(encoding="utf-8"))))
    except (UnicodeError, csv.Error) as error:
        raise Ready27CacheError("Private esptool RECORD is invalid") from error
    expected_counts = {name: (2 if name.startswith("../../Scripts/") else 1)
                       for name in replacements}
    actual_counts = {name: 0 for name in replacements}
    saw_record = False
    for row in rows:
        require(len(row) == 3 and bool(row[0]), "Private esptool RECORD row is invalid")
        if row[0] in replacements:
            payload = replacements[row[0]]
            row[1] = "sha256=" + record_sha256(payload)
            row[2] = str(len(payload))
            actual_counts[row[0]] += 1
        if row[0].endswith("/RECORD"):
            require(not row[1] and not row[2], "Private esptool RECORD self-row changed")
            saw_record = True
    require(actual_counts == expected_counts and saw_record,
            "Private esptool RECORD replacement set changed")
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    return output.getvalue().encode("utf-8")


def private_esptool_metadata_payloads(core: Path) -> dict[str, bytes]:
    """Derive lane-local finder and direct URL from the pinned copied metadata."""
    _python_exe, _uv_exe, site_packages, package = esptool_rebind_paths(core)
    finder = site_packages / ESPTOOL_EDITABLE_FINDER
    direct_url = (
        site_packages / f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info" /
        "direct_url.json"
    )
    require_plain_file(finder, "Private esptool editable finder")
    require_plain_file(direct_url, "Private esptool direct URL")
    try:
        finder_source = finder.read_text(encoding="utf-8")
        direct_value = json.loads(direct_url.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Ready27CacheError("Copied esptool editable metadata is invalid") from error
    global_package = (core.parent / "packages" / "tool-esptoolpy").resolve()
    require(direct_value == {
        "url": global_package.as_uri(), "dir_info": {"editable": True},
    }, "Copied esptool direct URL is not the pinned global source")
    escaped_global = str(global_package).replace("\\", "\\\\")
    escaped_private = str(package.resolve()).replace("\\", "\\\\")
    require(finder_source.count(escaped_global) == 8 and
            escaped_private not in finder_source,
            "Copied esptool finder path set changed")
    rewritten_finder = finder_source.replace(escaped_global, escaped_private)
    try:
        ast.parse(rewritten_finder)
    except SyntaxError as error:
        raise Ready27CacheError("Rewritten esptool finder is invalid Python") from error
    rewritten_direct = json.dumps({
        "url": package.resolve().as_uri(), "dir_info": {"editable": True},
    }, separators=(",", ":")).encode("utf-8")
    return {
        ESPTOOL_EDITABLE_FINDER: rewritten_finder.encode("utf-8"),
        f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info/direct_url.json":
            rewritten_direct,
    }


def generate_private_esptool_launchers(core: Path,
                                       env: dict[str, str]) -> tuple[dict[str, bytes], dict[str, str]]:
    """Generate four launchers with the copied penv's pinned pip/distlib only."""
    python_exe, _uv_exe, _site_packages, _package = esptool_rebind_paths(core)
    stage_directory = core / ".cache" / "esptool-launchers"
    require(not os.path.lexists(stage_directory),
            "Private esptool launcher stage already exists")
    command = esptool_rebind_command(core, stage_directory)
    result = subprocess.run(
        command, cwd=core, env=env, text=True, encoding="utf-8",
        capture_output=True, check=False, timeout=60,
    )
    require(result.returncode == 0 and not result.stderr,
            "Private esptool launcher generation failed")
    try:
        record = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise Ready27CacheError("Private esptool launcher generator output is invalid") from error
    require(record.get("pip") == ESPTOOL_GENERATOR_PIP_VERSION and
            record.get("distlib") == ESPTOOL_GENERATOR_DISTLIB_VERSION,
            "Private esptool launcher generator identity changed")
    expected_paths = {(stage_directory / name).resolve() for name in ESPTOOL_LAUNCHERS}
    require({Path(value).resolve() for value in record.get("created", [])} == expected_paths,
            "Private esptool launcher generator output set changed")
    actual_paths = {item.resolve() for item in stage_directory.iterdir()}
    require(actual_paths == expected_paths,
            "Private esptool launcher stage contains unexpected files")
    payloads = {}
    forbidden_roots = (
        str((core.parent / "packages").resolve()).casefold(),
        str((core.parent / "penv").resolve()).casefold(),
    )
    for name in ESPTOOL_LAUNCHERS:
        path = stage_directory / name
        require_plain_file(path, f"Generated private esptool launcher {name}")
        payload = path.read_bytes()
        require(payload.startswith(b"MZ"),
                f"Generated private esptool launcher {name} is not a Windows executable")
        validate_esptool_launcher_payload(
            payload, python_exe, forbidden_roots,
            f"Generated private esptool launcher {name}")
        payloads[name] = payload
    return payloads, {
        "distlib": ESPTOOL_GENERATOR_DISTLIB_VERSION,
        "pip": ESPTOOL_GENERATOR_PIP_VERSION,
    }


def verify_private_esptool_rebind(core: Path,
                                  env: dict[str, str] | None = None) -> dict[str, object]:
    """Prove esptool, its editable metadata and launchers are lane-local."""
    python_exe, _uv_exe, site_packages, package = esptool_rebind_paths(core)
    for path, label in (
        (core, "READY27 private core"),
        (package, "READY27 private tool-esptoolpy"),
        (python_exe, "READY27 private Python"),
        (site_packages, "READY27 private site-packages"),
    ):
        if path.suffix.casefold() == ".exe":
            require_plain_file(path, label)
        else:
            require_plain_directory(path, label)
        require(path_is_within(path, core), f"{label} escaped its private core")
    package_identity = private_esptool_package_identity(core)
    verify_package_version(package, "tool-esptoolpy")
    esptool_dist_infos = {
        item.name for item in site_packages.glob("esptool-*.dist-info")
    }
    require(esptool_dist_infos == {
        f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info"
    }, "Private penv contains an unexpected esptool distribution")
    editable_files = {
        item.name for item in site_packages.iterdir()
        if "editable" in item.name.casefold() and "esptool" in item.name.casefold()
    }
    require(editable_files == {ESPTOOL_EDITABLE_FINDER, ESPTOOL_EDITABLE_PTH},
            "Private penv contains unexpected esptool editable metadata")

    active_env = dict(env) if env is not None else private_esptool_environment(core)
    active_env["PYTHONDONTWRITEBYTECODE"] = "1"
    probe_result = subprocess.run(
        [str(python_exe), "-I", "-B", "-c", esptool_probe_code()],
        cwd=core, env=active_env, text=True, encoding="utf-8",
        capture_output=True, check=False, timeout=30,
    )
    require(probe_result.returncode == 0 and not probe_result.stderr,
            "Private esptool import/metadata probe failed")
    try:
        probe = json.loads(probe_result.stdout)
    except json.JSONDecodeError as error:
        raise Ready27CacheError("Private esptool probe was not JSON") from error
    require(isinstance(probe, dict), "Private esptool probe was not an object")
    record = validate_esptool_probe(probe, core)

    pth = site_packages / ESPTOOL_EDITABLE_PTH
    finder = site_packages / ESPTOOL_EDITABLE_FINDER
    direct_url_path = (
        site_packages / f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info" /
        "direct_url.json"
    )
    record_path = (
        site_packages / f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info" /
        "RECORD"
    )
    metadata_files = {}
    forbidden_roots = (
        str((core.parent / "packages").resolve()).casefold(),
        str((core.parent / "penv").resolve()).casefold(),
    )
    for path, label in (
        (pth, "Private esptool editable .pth"),
        (finder, "Private esptool editable finder"),
        (direct_url_path, "Private esptool direct URL"),
        (record_path, "Private esptool RECORD"),
    ):
        value = require_plain_file(path, label)
        payload = path.read_bytes()
        decoded = payload.decode("utf-8").casefold()
        require(not any(root in decoded for root in forbidden_roots),
                f"{label} retains a global PlatformIO path")
        metadata_files[path.relative_to(core).as_posix()] = {
            "bytes": value.st_size,
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    launcher_records = {}
    for name in ESPTOOL_LAUNCHERS:
        launcher = core / "penv" / "Scripts" / name
        value = require_plain_file(launcher, f"Private esptool launcher {name}")
        require(path_is_within(launcher, core),
                f"Private esptool launcher {name} escaped the private core")
        launcher_payload = launcher.read_bytes()
        validate_esptool_launcher_payload(
            launcher_payload, python_exe, forbidden_roots,
            f"Private esptool launcher {name}")
        launcher_records[launcher.relative_to(core).as_posix()] = {
            "bytes": value.st_size,
            "sha256": hashlib.sha256(launcher_payload).hexdigest(),
        }
    version_result = subprocess.run(
        [str(core / "penv" / "Scripts" / "esptool.exe"), "version"],
        cwd=core, env=active_env, text=True, encoding="utf-8",
        capture_output=True, check=False, timeout=30,
    )
    require(version_result.returncode == 0 and not version_result.stderr and
            version_result.stdout.splitlines() == [
                ESPTOOL_VERSION_BANNER,
                ESPTOOL_MODULE_VERSION,
            ],
            "Private esptool launcher identity changed")
    record.update({
        "generator": {
            "distlib": ESPTOOL_GENERATOR_DISTLIB_VERSION,
            "persistent_files": 7,
            "pip": ESPTOOL_GENERATOR_PIP_VERSION,
        },
        "launchers": launcher_records,
        "metadata_files": metadata_files,
        "package_identity": package_identity,
        "policy": ESPTOOL_REBIND_POLICY,
        "schema": 1,
    })
    return record


def install_private_esptool_rebind(core: Path) -> dict[str, object]:
    """Rebind copied esptool metadata and launchers without packaging or network."""
    env = private_esptool_environment(core)
    _python_exe, _uv_exe, site_packages, _package = esptool_rebind_paths(core)
    metadata_payloads = private_esptool_metadata_payloads(core)
    launcher_payloads, generator = generate_private_esptool_launchers(core, env)
    require(generator == {
        "distlib": ESPTOOL_GENERATOR_DISTLIB_VERSION,
        "pip": ESPTOOL_GENERATOR_PIP_VERSION,
    }, "Private esptool launcher generator changed")
    replacements = {
        "__editable___esptool_5_1_2_finder.py":
            metadata_payloads[ESPTOOL_EDITABLE_FINDER],
        f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info/direct_url.json":
            metadata_payloads[
                f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info/direct_url.json"],
    }
    for name, payload in launcher_payloads.items():
        replacements[f"../../Scripts/{name}"] = payload
    record_path = (
        site_packages / f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info" / "RECORD"
    )
    record_payload = rewrite_esptool_record(record_path, replacements)
    finder_path = site_packages / ESPTOOL_EDITABLE_FINDER
    direct_url_path = (
        site_packages / f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info" /
        "direct_url.json"
    )
    atomic_replace_payload(
        finder_path, metadata_payloads[ESPTOOL_EDITABLE_FINDER],
        "Private esptool editable finder")
    atomic_replace_payload(
        direct_url_path,
        metadata_payloads[
            f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info/direct_url.json"],
        "Private esptool direct URL")
    for name, payload in launcher_payloads.items():
        atomic_replace_payload(
            core / "penv" / "Scripts" / name, payload,
            f"Private esptool launcher {name}")
    atomic_replace_payload(record_path, record_payload, "Private esptool RECORD")
    return verify_private_esptool_rebind(core, env)


def verify_private_esptool_construction_evidence(
        core: Path, env: dict[str, str] | None = None) -> dict[str, object]:
    """Bind the live private rebind to its exclusive construction record."""
    evidence_path = core / "construction-evidence" / "private-core-construction.json"
    evidence = load_strict_json_object(
        evidence_path, "READY27 private-core construction evidence")
    recorded = evidence.get("esptool_rebind")
    require(isinstance(recorded, dict),
            "READY27 construction evidence lacks the private esptool rebind")
    live_package_identity = private_esptool_package_identity(core)
    validate_esptool_construction_source(evidence, live_package_identity)
    recorded_contract = evidence.get("esptool_package_contract")
    live_contract = verify_esptool_platform_package_contract(core)
    require(recorded_contract == live_contract,
            "READY27 esptool PlatformIO package contract changed")
    live = verify_private_esptool_rebind(core, env)
    require(recorded == live,
            "READY27 private esptool state differs from construction evidence")
    return live


def verify_package_version(package: Path, name: str) -> None:
    expected_version = PINNED_PACKAGE_VERSIONS[name]
    piopm = package / ".piopm"
    if name == "tool-esp_install":
        require(not os.path.lexists(piopm),
                "tool-esp_install unexpectedly gained package-manager metadata")
        metadata = load_strict_json_object(package / "package.json",
                                           "tool-esp_install package manifest")
        require(metadata.get("name") == name and metadata.get("version") == expected_version,
                "tool-esp_install package identity changed")
        return
    metadata = load_strict_json_object(piopm, f"{name} package metadata")
    require(metadata.get("type") == "tool" and metadata.get("name") == name and
            metadata.get("version") == expected_version,
            f"{name} package name/version changed")


def pinned_source_inventory(platformio_root: Path, *, include_records: bool) -> dict[str, object]:
    """Inventory every global byte that READY27 is allowed to copy."""
    require_plain_directory(platformio_root, "PlatformIO root")
    packages_source = platformio_root / "packages"
    require_plain_directory(packages_source, "global PlatformIO packages")
    package_records: dict[str, object] = {}
    for name, expected in PINNED_COPIED_PACKAGE_IDENTITIES.items():
        package = packages_source / name
        require_plain_directory(package, f"global {name} package")
        verify_package_version(package, name)
        inventory = tree_inventory(
            package,
            label=f"global {name} package",
            exclude_runtime_cache=package_excludes_runtime_cache(name),
        )
        require_pinned_identity(inventory, expected, f"global {name} package")
        package_records[name] = inventory if include_records else inventory_identity(inventory)

    penv = platformio_root / "penv"
    penv_inventory = tree_inventory(
        penv, label="global pioarduino penv", allow_source_hardlinks=True,
        exclude_runtime_cache=True)
    # PlatformIO's global Python environment may be deduplicated or flattened
    # by Windows/package maintenance without changing any build input byte.
    # The private core is always copied file-by-file and proves zero retained
    # hard-link groups, so pin the source's complete path/mode/byte identity.
    require_pinned_content_identity(penv_inventory, PINNED_CACHELESS_PENV_IDENTITY,
                                    "global cacheless pioarduino penv")

    return {
        "packages": package_records,
        "penv": penv_inventory if include_records else inventory_identity(penv_inventory),
        "schema": INVENTORY_SCHEMA,
    }


def official_archive_inventory(platformio_root: Path) -> dict[str, object]:
    downloads = platformio_root / ".cache" / "downloads"
    require_plain_directory(downloads, "PlatformIO immutable download cache")
    records = {
        spec.destination_name: inspect_archive(downloads / spec.cache_name, spec)
        for spec in ARCHIVE_SPECS
    }
    records[PLATFORM_ARCHIVE_SPEC.destination_name] = inspect_zip_archive(
        downloads / PLATFORM_ARCHIVE_SPEC.cache_name, PLATFORM_ARCHIVE_SPEC)
    records[ESPTOOL_ARCHIVE_SPEC.destination_name] = inspect_zip_archive(
        downloads / ESPTOOL_ARCHIVE_SPEC.cache_name, ESPTOOL_ARCHIVE_SPEC)
    return records


def write_json_exclusive(path: Path, value: object) -> tuple[int, str]:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")
    write_exclusive(path, payload)
    return len(payload), hashlib.sha256(payload).hexdigest()


def git_readonly(repo: Path, arguments: list[str], label: str, *,
                 stdout_path: Path | None = None,
                 autocrlf: str = "false") -> bytes:
    """Run one bounded, read-only Git provenance command without global config."""
    require_plain_directory(repo, f"{label} repository")
    require(autocrlf in {"false", "true"}, f"{label} autocrlf policy is invalid")
    command = [
        "git", "-c", f"core.autocrlf={autocrlf}", "-c", "core.safecrlf=true",
        "--no-pager", *arguments,
    ]
    environment = dict(os.environ)
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "NUL" if os.name == "nt" else "/dev/null",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    if stdout_path is None:
        result = subprocess.run(
            command, cwd=repo, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        output = result.stdout
    else:
        require_plain_directory(stdout_path.parent, f"{label} archive parent")
        require(not os.path.lexists(stdout_path), f"{label} archive already exists")
        with stdout_path.open("xb") as output_handle:
            result = subprocess.run(
                command, cwd=repo, env=environment, stdout=output_handle,
                stderr=subprocess.PIPE, check=False,
            )
        output = b""
    require(result.returncode == 0,
            f"{label} Git command failed ({result.returncode}): "
            f"{result.stderr.decode('utf-8', errors='replace').strip()}")
    require(result.stderr == b"", f"{label} Git command wrote to stderr")
    return output


def validate_git_member_name(name: str, label: str) -> tuple[str, ...]:
    require("\\" not in name and "\x00" not in name,
            f"{label} archive has an unsafe member name")
    pure = PurePosixPath(name)
    require(not pure.is_absolute(), f"{label} archive has an absolute member")
    parts = pure.parts
    require(bool(parts), f"{label} archive has an empty member")
    normalized = "/".join(parts)
    require(name in (normalized, normalized + "/"),
            f"{label} archive has an aliased member name: {name!r}")
    validate_relative_parts(tuple(parts), f"{label} archive member")
    require(parts[0].casefold() not in {".git", ".piopm"},
            f"{label} archive contains forbidden package metadata")
    return tuple(parts)


def safe_extract_git_archive(archive_path: Path, destination: Path,
                             label: str) -> dict[str, object]:
    """Extract only ordinary files/directories from an exact-commit archive."""
    archive_stat = require_plain_file(archive_path, f"{label} Git archive")
    require(0 < archive_stat.st_size <= 128 * 1024 * 1024,
            f"{label} Git archive exceeds its byte cap")
    require_plain_directory(destination, f"{label} destination")
    directories: dict[tuple[str, ...], int] = {}
    files: list[tuple[tuple[str, ...], int, int, str]] = []
    canonical_paths: set[str] = set()
    total_file_bytes = 0
    with tarfile.open(archive_path, mode="r:") as archive:
        for index, member in enumerate(archive, start=1):
            require(index <= 10_000, f"{label} Git archive exceeds its entry cap")
            parts = validate_git_member_name(member.name, label)
            canonical = canonical_relative(parts, f"{label} Git archive member")
            require(canonical not in canonical_paths,
                    f"{label} Git archive has a case-folding duplicate")
            canonical_paths.add(canonical)
            require(member.linkname == "", f"{label} Git archive member has a link target")
            if member.isdir():
                require(member.mode in (0o755, 0o775),
                        f"{label} Git archive directory mode changed")
                directories[parts] = member.mode
            else:
                require(member.isreg() and member.mode in (0o644, 0o664, 0o755, 0o775),
                        f"{label} Git archive contains a link or special file")
                require(0 <= member.size <= 64 * 1024 * 1024,
                        f"{label} Git archive member exceeds its byte cap")
                total_file_bytes += int(member.size)
                require(total_file_bytes <= 128 * 1024 * 1024,
                        f"{label} Git archive expanded bytes exceed their cap")
                files.append((parts, int(member.size), member.mode, member.name))

    for parts in sorted(directories,
                        key=lambda value: (len(value), tuple(x.casefold() for x in value))):
        target = destination.joinpath(*parts)
        require(target.parent == destination or target.parent.is_relative_to(destination),
                f"{label} Git directory escaped its destination")
        require(target.parent == destination or target.parent.exists(),
                f"{label} Git archive omitted a parent directory")
        target.mkdir(exist_ok=False)
        require_plain_directory(target, f"{label} extracted directory")
        os.chmod(target, directories[parts] & 0o777)

    with tarfile.open(archive_path, mode="r:") as archive:
        for parts, expected_bytes, mode, member_name in files:
            target = destination.joinpath(*parts)
            require(target.parent == destination or target.parent.is_relative_to(destination),
                    f"{label} Git file escaped its destination")
            require_plain_directory(target.parent, f"{label} Git file parent")
            member = archive.getmember(member_name)
            source = archive.extractfile(member)
            require(source is not None, f"{label} Git member has no payload")
            with source:
                copy_member_payload(source, target, expected_bytes, mode)
            require_plain_file(target, f"{label} extracted file")
    fsync_directory(destination)
    return {
        "archive_bytes": archive_stat.st_size,
        "archive_sha256": sha256_file(archive_path),
        "tree": tree_inventory(destination, label=f"{label} extracted commit"),
    }


def validate_dependency_source_allowlist(source: Path) -> None:
    expected = (
        set(PINNED_REGISTRY_DEPENDENCY_IDENTITIES)
        | {spec.name for spec in GIT_DEPENDENCY_SPECS}
        | set(PINNED_LIBDEPS_CONTROL_FILES)
    )
    actual = {entry.name for entry in os.scandir(source)}
    require(actual == expected,
            f"Shared dependency input allowlist changed: expected {sorted(expected)}, "
            f"found {sorted(actual)}")


def validate_registry_dependency(package: Path, name: str) -> None:
    require_pinned_identity(
        tree_inventory(package, label=f"pinned registry dependency {name}"),
        PINNED_REGISTRY_DEPENDENCY_IDENTITIES[name],
        f"pinned registry dependency {name}",
    )
    metadata = load_strict_json_object(package / ".piopm", f"{name} metadata")
    require(metadata.get("type") == "library" and metadata.get("name") == name and
            metadata.get("version") == PINNED_REGISTRY_DEPENDENCY_VERSIONS[name],
            f"{name} registry identity changed")


def construct_git_dependency(source_root: Path, destination_root: Path,
                             spec: GitDependencySpec) -> dict[str, object]:
    repo = source_root / spec.name
    git_dir = repo / ".git"
    require_plain_directory(repo, f"{spec.name} source repository")
    require_plain_directory(git_dir, f"{spec.name} Git metadata")
    piopm_path = git_dir / ".piopm"
    piopm_stat = require_plain_file(piopm_path, f"{spec.name} package metadata")
    piopm_bytes = piopm_path.read_bytes()
    require(piopm_stat.st_size == spec.piopm_bytes and
            hashlib.sha256(piopm_bytes).hexdigest() == spec.piopm_sha256,
            f"{spec.name} .piopm metadata changed")

    head = git_readonly(repo, ["rev-parse", "--verify", "HEAD"], spec.name).strip()
    origin = git_readonly(
        repo, ["config", "--local", "--get", "remote.origin.url"], spec.name
    ).strip()
    require(head == spec.commit.encode("ascii"), f"{spec.name} HEAD changed")
    require(origin == spec.origin.encode("ascii"), f"{spec.name} origin changed")
    status = git_readonly(
        repo, ["status", "--porcelain=v1", "--untracked-files=all"], spec.name
    )
    expected_status = (
        f" M {spec.modified_path}\n".encode("ascii") if spec.modified_path else b""
    )
    require(status.replace(b"\\", b"/") == expected_status,
            f"{spec.name} working-tree status changed: {status!r}")

    patched_payload: bytes | None = None
    if spec.modified_path:
        relative = Path(*PurePosixPath(spec.modified_path).parts)
        original = git_readonly(
            repo, ["show", f"{spec.commit}:{spec.modified_path}"], spec.name
        )
        require(len(original) == spec.original_bytes and
                hashlib.sha256(original).hexdigest() == spec.original_sha256,
                f"{spec.name} original patched input changed")
        patched_path = repo / relative
        patched_stat, patched_digest = stable_file_record(
            patched_path, f"{spec.name} patched source", allow_source_hardlinks=False)
        patched_payload = patched_path.read_bytes()
        require(patched_stat.st_size == spec.patched_bytes and
                patched_digest == spec.patched_sha256 and
                hashlib.sha256(patched_payload).hexdigest() == spec.patched_sha256,
                f"{spec.name} reviewed patched bytes changed")
        diff = git_readonly(
            repo,
            ["--literal-pathspecs", "diff", "--binary", "--no-ext-diff",
             "--no-textconv", "--", spec.modified_path],
            spec.name,
            autocrlf=spec.diff_autocrlf,
        )
        require(len(diff) == spec.diff_bytes and
                hashlib.sha256(diff).hexdigest() == spec.diff_sha256,
                f"{spec.name} reviewed patch diff changed")

    destination = destination_root / spec.name
    require_direct_child(destination_root, destination, f"{spec.name} destination")
    require(not os.path.lexists(destination), f"{spec.name} destination already exists")
    destination.mkdir()
    with tempfile.TemporaryDirectory(prefix=f"xtinct-{spec.name.casefold()}-archive-") \
            as temporary_name:
        archive_path = Path(temporary_name) / "commit.tar"
        git_readonly(
            repo, ["archive", "--format=tar", spec.commit], spec.name,
            stdout_path=archive_path,
        )
        archive_record = safe_extract_git_archive(archive_path, destination, spec.name)

    if spec.modified_path:
        require(patched_payload is not None, f"{spec.name} patched payload is missing")
        patched_path = destination.joinpath(*PurePosixPath(spec.modified_path).parts)
        require_plain_file(patched_path, f"{spec.name} reconstructed patch target")
        reconstructed_original = patched_path.read_bytes()
        require(len(reconstructed_original) == spec.original_bytes and
                hashlib.sha256(reconstructed_original).hexdigest() == spec.original_sha256,
                f"{spec.name} archive did not reproduce the exact original")
        mode = stat.S_IMODE(patched_path.stat(follow_symlinks=False).st_mode)
        replacement = patched_path.with_name(patched_path.name + ".ready27-new")
        write_exclusive(replacement, patched_payload, mode)
        os.replace(replacement, patched_path)
        require_plain_file(patched_path, f"{spec.name} reconstructed patched source")
        require(hashlib.sha256(patched_path.read_bytes()).hexdigest() == spec.patched_sha256,
                f"{spec.name} reconstructed patch changed")

    write_exclusive(destination / ".piopm", piopm_bytes)
    require(not os.path.lexists(destination / ".git"),
            f"{spec.name} private dependency retained Git metadata")
    inventory = tree_inventory(destination, label=f"private {spec.name} dependency")
    require_pinned_identity(
        inventory, PINNED_GIT_DEPENDENCY_SEED_IDENTITIES[spec.name],
        f"private {spec.name} dependency",
    )
    return {
        "archive": archive_record,
        "commit": spec.commit,
        "destination": inventory_identity(inventory),
        "origin": spec.origin,
        "patch": None if not spec.modified_path else {
            "diff_bytes": spec.diff_bytes,
            "diff_sha256": spec.diff_sha256,
            "path": spec.modified_path,
            "patched_bytes": spec.patched_bytes,
            "patched_sha256": spec.patched_sha256,
        },
    }


def copy_vendored_git_dependency(source_root: Path, destination_root: Path,
                                 spec: GitDependencySpec) -> dict[str, object]:
    """Copy a metadata-free, identity-pinned Git-origin dependency."""
    source = source_root / spec.name
    require_plain_directory(source, f"vendored {spec.name} source")
    require(not os.path.lexists(source / ".git"),
            f"vendored {spec.name} must not contain Git metadata")
    source_inventory = tree_inventory(source, label=f"vendored {spec.name} source")
    require_pinned_identity(
        source_inventory,
        PINNED_GIT_DEPENDENCY_SEED_IDENTITIES[spec.name],
        f"vendored {spec.name} source",
    )
    destination = destination_root / spec.name
    copied = copy_plain_tree(
        source, destination, label=f"READY27 vendored {spec.name} dependency"
    )
    require_pinned_identity(
        copied,
        PINNED_GIT_DEPENDENCY_SEED_IDENTITIES[spec.name],
        f"READY27 vendored {spec.name} dependency",
    )
    return {
        "commit": spec.commit,
        "destination": inventory_identity(copied),
        "origin": spec.origin,
        "source": inventory_identity(source_inventory),
        "source_policy": "vendored-plain-tree-exact-identity-v1",
        "patch": None if not spec.modified_path else {
            "diff_bytes": spec.diff_bytes,
            "diff_sha256": spec.diff_sha256,
            "path": spec.modified_path,
            "patched_bytes": spec.patched_bytes,
            "patched_sha256": spec.patched_sha256,
        },
    }


def local_link_payload(project_root: Path, dependency_name: str) -> bytes:
    require(dependency_name in LOCAL_LINK_SPECS,
            f"unknown local dependency link: {dependency_name}")
    record = {
        "cwd": str(project_root.resolve(strict=True)),
        "spec": {
            "owner": None,
            "id": None,
            "name": dependency_name,
            "requirements": None,
            "uri": LOCAL_LINK_SPECS[dependency_name],
        },
    }
    return json.dumps(record).encode("utf-8")


def validate_local_link_payload(payload: bytes, project_root: Path,
                                dependency_name: str) -> None:
    expected = local_link_payload(project_root, dependency_name)
    require(payload == expected,
            f"generated dependency link changed: {dependency_name}.pio-link")
    try:
        record = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Ready27CacheError(
            f"generated dependency link is invalid: {dependency_name}.pio-link"
        ) from error
    require(Path(str(record["cwd"])).resolve() == project_root.resolve(),
            f"generated dependency link escaped project: {dependency_name}.pio-link")


def validate_control_file(source_root: Path, project_root: Path,
                          name: str) -> bytes:
    path = source_root / name
    expected_bytes, expected_sha256 = PINNED_LIBDEPS_CONTROL_FILES[name]
    value, digest = stable_file_record(
        path, f"dependency control file {name}", allow_source_hardlinks=False)
    payload = path.read_bytes()
    require(value.st_size == expected_bytes and digest == expected_sha256 and
            hashlib.sha256(payload).hexdigest() == expected_sha256,
            f"dependency control file changed: {name}")
    if name.endswith(".pio-link"):
        try:
            record = json.loads(payload.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise Ready27CacheError(f"dependency link is invalid JSON: {name}") from error
        dependency_name = name.removesuffix(".pio-link")
        require(isinstance(record, dict) and set(record) == {"cwd", "spec"} and
                Path(str(record["cwd"])).resolve() == project_root.resolve(),
                f"dependency link working directory changed: {name}")
        spec_record = record["spec"]
        require(isinstance(spec_record, dict) and spec_record == {
            "owner": None, "id": None, "name": dependency_name,
            "requirements": None, "uri": LOCAL_LINK_SPECS[dependency_name],
        }, f"dependency link specification changed: {name}")
    else:
        try:
            lines = payload.decode("utf-8").splitlines()
        except UnicodeError as error:
            raise Ready27CacheError("dependency integrity file is not UTF-8") from error
        expected_lines = {
            *(f"{name}={uri}" for name, uri in LOCAL_LINK_SPECS.items()),
            "bblanchon/ArduinoJson @ 7.4.2",
            "ricmoo/QRCode @ 0.0.1",
            "bitbank2/PNGdec @ 1.1.6",
            *(f"{spec.origin}#{spec.commit}" for spec in GIT_DEPENDENCY_SPECS),
        }
        require(len(lines) == len(set(lines)) and set(lines) == expected_lines,
                "dependency integrity specification changed")
    return payload


def prepare_dependency_seed(project_root: Path, core: Path) -> dict[str, object]:
    """Build a pinned metadata-free private libdeps tree with no network I/O."""
    project_root = project_root.resolve(strict=True)
    core = core.resolve(strict=True)
    require_plain_directory(project_root, "XTINCT firmware project")
    require_plain_directory(core, "READY27 private core")
    require(not core.is_relative_to(project_root),
            "READY27 dependency seed cannot live in the project tree")
    source_root, source_before = verify_portable_dependency_source(project_root)

    libdeps_root = core / "libdeps"
    evidence_root = core / "construction-evidence"
    require_plain_directory(libdeps_root, "READY27 private libdeps root")
    require_plain_directory(evidence_root, "READY27 construction evidence root")
    destination = libdeps_root / "default"
    require_direct_child(libdeps_root, destination, "READY27 dependency environment")
    require(not os.path.lexists(destination),
            "READY27 dependency environment already exists")
    destination.mkdir()

    registry: dict[str, object] = {}
    for name, expected in PINNED_REGISTRY_DEPENDENCY_IDENTITIES.items():
        source = source_root / name
        validate_registry_dependency(source, name)
        copied = copy_plain_tree(
            source, destination / name, label=f"READY27 registry dependency {name}"
        )
        require_pinned_identity(copied, expected, f"READY27 registry dependency {name}")
        validate_registry_dependency(destination / name, name)
        registry[name] = inventory_identity(copied)

    git_dependencies = {
        spec.name: copy_vendored_git_dependency(source_root, destination, spec)
        for spec in GIT_DEPENDENCY_SPECS
    }

    controls: dict[str, object] = {}
    for name in sorted(PINNED_LIBDEPS_CONTROL_FILES, key=str.casefold):
        payload = validate_control_file(source_root, project_root, name)
        target = destination / name
        write_exclusive(target, payload)
        require_plain_file(target, f"private dependency control file {name}")
        controls[name] = {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    for dependency_name in sorted(LOCAL_LINK_SPECS, key=str.casefold):
        name = f"{dependency_name}.pio-link"
        payload = local_link_payload(project_root, dependency_name)
        validate_local_link_payload(payload, project_root, dependency_name)
        target = destination / name
        write_exclusive(target, payload)
        require_plain_file(target, f"private generated dependency link {name}")
        validate_local_link_payload(target.read_bytes(), project_root, dependency_name)
        controls[name] = {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "policy": "generated-for-current-project-root-v1",
        }

    for relative, (expected_bytes, expected_sha256) in PINNED_SHIPPED_BINARY_INPUTS.items():
        binary = destination.joinpath(*PurePosixPath(relative).parts)
        value = require_plain_file(binary, f"pinned shipped binary {relative}")
        require(value.st_size == expected_bytes and sha256_file(binary) == expected_sha256,
                f"pinned shipped binary changed: {relative}")

    actual_names = {entry.name for entry in os.scandir(destination)}
    expected_names = (
        set(PINNED_REGISTRY_DEPENDENCY_IDENTITIES)
        | {spec.name for spec in GIT_DEPENDENCY_SPECS}
        | set(PINNED_LIBDEPS_CONTROL_FILES)
        | {f"{name}.pio-link" for name in LOCAL_LINK_SPECS}
    )
    require(actual_names == expected_names,
            "private dependency seed allowlist changed")
    seed_inventory = tree_inventory(
        libdeps_root, label="READY27 complete private dependency seed",
        maximum_entries=10_000,
    )
    source_after = tree_inventory(
        source_root, label="portable vendored dependency input",
        maximum_entries=10_000,
    )
    require(source_after == source_before,
            "Portable vendored dependency input changed during private-seed construction")
    require_pinned_identity(
        source_after,
        PINNED_PORTABLE_DEPENDENCY_SOURCE_IDENTITY,
        "portable vendored dependency input after construction",
    )
    record = {
        "controls": controls,
        "git_dependencies": git_dependencies,
        "identity": inventory_identity(seed_inventory),
        "policy": DEPENDENCY_SEED_POLICY,
        "portable_source_identity": inventory_identity(source_before),
        "registry_dependencies": registry,
        "schema": 1,
        "source_before_after": inventory_identity(source_before),
    }
    marker_path = evidence_root / DEPENDENCY_SEED_MARKER_NAME
    marker_bytes, marker_sha256 = write_json_exclusive(marker_path, record)
    return {
        "construction": {
            "bytes": marker_bytes,
            "path": marker_path,
            "sha256": marker_sha256,
        },
        "record": record,
    }


def verify_portable_dependency_source(project_root: Path) -> tuple[Path, dict[str, object]]:
    """Verify the exact metadata-free dependency source shipped by the public kit."""
    project_root = project_root.resolve(strict=True)
    require_plain_directory(project_root, "XTINCT firmware project")
    source_root = project_root / "vendor" / "platformio-libdeps"
    require_plain_directory(source_root, "portable vendored dependency input")
    validate_dependency_source_allowlist(source_root)
    inventory = tree_inventory(
        source_root, label="portable vendored dependency input",
        maximum_entries=10_000,
    )
    require_pinned_identity(
        inventory,
        PINNED_PORTABLE_DEPENDENCY_SOURCE_IDENTITY,
        "portable vendored dependency input",
    )
    return source_root, inventory


def prepare_private_core(platformio_root: Path, project_root: Path,
                         lane: str) -> dict[str, object]:
    """Create one fresh, plain approved-lane core without mutable frameworks."""
    source_before = pinned_source_inventory(platformio_root, include_records=False)
    archive_before = official_archive_inventory(platformio_root)
    core, marker = create_owned_core(platformio_root, lane)

    packages = core / "packages"
    platforms = core / "platforms"
    libdeps = core / "libdeps"
    global_lib = core / "lib"
    cache = core / ".cache"
    evidence = core / "construction-evidence"
    for directory in (packages, platforms, libdeps, global_lib, cache, evidence):
        directory.mkdir()
        require_plain_directory(directory, "READY27 private core directory")

    dependency_seed = prepare_dependency_seed(project_root, core)

    copied: dict[str, object] = {}
    global_packages = platformio_root / "packages"
    for name, expected in PINNED_COPIED_PACKAGE_IDENTITIES.items():
        source = global_packages / name
        destination = packages / name
        cacheless = package_excludes_runtime_cache(name)
        inventory = copy_plain_tree(
            source, destination, label=f"READY27 {name} copy",
            exclude_runtime_cache=cacheless)
        require_pinned_identity(inventory, expected, f"READY27 {name} source")
        verify_package_version(destination, name)
        destination_inventory = tree_inventory(
            destination, label=f"READY27 private {name} package",
            exclude_runtime_cache=cacheless)
        require(inventory_content_identity(destination_inventory) ==
                inventory_content_identity(inventory),
                f"READY27 private {name} content differs from its pinned source")
        copied[name] = {
            "destination": inventory_identity(destination_inventory),
            "source": inventory_identity(inventory),
        }

    downloads = platformio_root / ".cache" / "downloads"
    platform_destination = platforms / GLOBAL_PLATFORM_DIRECTORY_NAME
    platform_extracted = safe_extract_zip_archive(
        downloads / PLATFORM_ARCHIVE_SPEC.cache_name,
        PLATFORM_ARCHIVE_SPEC,
        platforms,
    )
    esptool_extracted = safe_extract_zip_archive(
        downloads / ESPTOOL_ARCHIVE_SPEC.cache_name,
        ESPTOOL_ARCHIVE_SPEC,
        packages,
    )
    require(inventory_identity(esptool_extracted["tree"]) ==
            PINNED_ESPTOOL_EXTRACTED_IDENTITY,
            "READY27 extracted esptool tree changed")
    esptool_package_contract = verify_esptool_platform_package_contract(core)

    penv_source_inventory = copy_plain_tree(
        platformio_root / "penv", core / "penv", label="READY27 pioarduino penv",
        exclude_runtime_cache=True)
    require_pinned_content_identity(
        penv_source_inventory, PINNED_CACHELESS_PENV_IDENTITY,
        "READY27 cacheless pioarduino penv source")

    # The copied editable esptool installation still contains absolute paths to
    # the global package tree. Rebind exactly seven metadata/launcher files with
    # copied, pinned Python tooling and retain the normalized identity.
    esptool_rebind = install_private_esptool_rebind(core)

    extracted: dict[str, object] = {}
    for spec in ARCHIVE_SPECS:
        extracted[spec.destination_name] = safe_extract_archive(
            downloads / spec.cache_name, spec, packages)

    expected_package_names = set(PINNED_COPIED_PACKAGE_IDENTITIES) | {
        spec.destination_name for spec in ARCHIVE_SPECS
    } | {ESPTOOL_ARCHIVE_SPEC.destination_name}
    actual_package_names = {item.name for item in packages.iterdir()}
    require(actual_package_names == expected_package_names,
            "READY27 private package allowlist changed")
    for item in packages.iterdir():
        require_plain_directory(item, "READY27 private package")

    source_after = pinned_source_inventory(platformio_root, include_records=False)
    archive_after = official_archive_inventory(platformio_root)
    require(source_after == source_before,
            "Global PlatformIO source inventory changed during private-core construction")
    require(archive_after == archive_before,
            "Official archive inventory changed during private-core construction")
    validate_owned_core(core, lane, marker)

    record = {
        "archives": archive_before,
        "copied_packages": copied,
        "dependency_seed": dependency_seed["record"],
        "esptool_package_contract": esptool_package_contract,
        "esptool_rebind": esptool_rebind,
        "extracted_frameworks": extracted,
        "extracted_tools": {
            ESPTOOL_ARCHIVE_SPEC.destination_name: esptool_extracted,
        },
        "lane": lane,
        "penv": {
            "destination": inventory_identity(tree_inventory(
                core / "penv", label="READY27 private pioarduino penv")),
            "source": inventory_identity(penv_source_inventory),
        },
        "platform": {
            "archive": platform_extracted["archive"],
            # Retain every path/mode/byte hash rather than blessing a stale
            # aggregate from the mutable global PlatformIO installation.
            "destination": tree_inventory(
                platform_destination, label="READY27 private pioarduino platform"),
        },
        "policy": OWNER_POLICY,
        "schema": 1,
        "source_before_after": source_before,
    }
    construction_path = evidence / "private-core-construction.json"
    construction_bytes, construction_sha256 = write_json_exclusive(construction_path, record)
    return {
        "construction": {
            "bytes": construction_bytes,
            "path": construction_path,
            "sha256": construction_sha256,
        },
        "core": core,
        "marker": marker,
        "record": record,
    }


def validate_archive_member_name(name: str, spec: ArchiveSpec) -> tuple[str, ...]:
    require("\\" not in name and "\x00" not in name,
            f"{spec.label} archive has an unsafe member name")
    pure = PurePosixPath(name)
    require(not pure.is_absolute(), f"{spec.label} archive has an absolute member")
    parts = pure.parts
    require(parts and parts[0] == spec.top_level,
            f"{spec.label} archive escaped its single top-level directory")
    validate_relative_parts(tuple(parts), f"{spec.label} archive member")
    return tuple(parts[1:])


def inspect_archive(path: Path, spec: ArchiveSpec) -> dict[str, object]:
    value = require_plain_file(path, f"{spec.label} archive")
    require(value.st_size == spec.archive_bytes,
            f"{spec.label} archive byte count changed")
    require(sha256_file(path) == spec.archive_sha256,
            f"{spec.label} archive SHA-256 changed")

    entries = 0
    files = 0
    directories = 0
    total_file_bytes = 0
    canonical_paths: set[str] = set()
    saw_top_directory = False
    with tarfile.open(path, mode="r:xz") as archive:
        for member in archive:
            entries += 1
            require(entries <= spec.maximum_entries,
                    f"{spec.label} archive exceeds its entry cap")
            relative_parts = validate_archive_member_name(member.name, spec)
            canonical = canonical_relative(tuple(PurePosixPath(member.name).parts),
                                             f"{spec.label} archive member")
            require(canonical not in canonical_paths,
                    f"{spec.label} archive has a duplicate member: {member.name}")
            canonical_paths.add(canonical)
            require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE),
                    f"{spec.label} archive has a link or special member: {member.name}")
            require(member.linkname in ("", None),
                    f"{spec.label} archive member unexpectedly has a link target")
            if not relative_parts:
                require(member.isdir(),
                        f"{spec.label} top-level member is not a directory")
                saw_top_directory = True
            elif member.isdir():
                directories += 1
            else:
                require(member.isfile(),
                        f"{spec.label} archive member is not a regular file")
                require(0 <= member.size <= spec.maximum_file_bytes,
                        f"{spec.label} archive member exceeds its file cap: {member.name}")
                files += 1
                total_file_bytes += int(member.size)
                require(total_file_bytes <= spec.maximum_total_file_bytes,
                        f"{spec.label} archive exceeds its expanded-byte cap")
    require(saw_top_directory, f"{spec.label} archive lacks its top-level directory")
    require(files > 0 and directories > 0,
            f"{spec.label} archive has no useful file/directory set")
    require(path.stat(follow_symlinks=False).st_size == spec.archive_bytes and
            sha256_file(path) == spec.archive_sha256,
            f"{spec.label} archive changed during validation")
    return {
        "archive_bytes": spec.archive_bytes,
        "archive_sha256": spec.archive_sha256,
        "directories": directories,
        "entries": entries,
        "file_bytes": total_file_bytes,
        "files": files,
        "top_level": spec.top_level,
    }


def fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_exclusive(path: Path, payload: bytes, mode: int = 0o644) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        os.close(descriptor)
    os.chmod(path, mode)


def copy_member_payload(source: BinaryIO, destination: Path, expected_bytes: int,
                        mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(destination, flags, mode & 0o777)
    copied = 0
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            while copied < expected_bytes:
                chunk = source.read(min(COPY_BUFFER_BYTES, expected_bytes - copied))
                require(bool(chunk), f"Archive member ended early: {destination.name}")
                output.write(chunk)
                copied += len(chunk)
            require(source.read(1) == b"", f"Archive member exceeded its declared size")
            output.flush()
            os.fsync(output.fileno())
    finally:
        os.close(descriptor)
    require(copied == expected_bytes, f"Archive member byte count changed")
    os.chmod(destination, mode & 0o777)


def safe_extract_archive(path: Path, spec: ArchiveSpec, packages_dir: Path) -> dict[str, object]:
    """Safely extract one pinned archive into a new package directory."""
    archive_record = inspect_archive(path, spec)
    require_plain_directory(packages_dir, "READY27 packages directory")
    destination = packages_dir / spec.destination_name
    require_direct_child(packages_dir, destination, f"{spec.label} destination")
    require(not os.path.lexists(destination),
            f"{spec.label} destination already exists: {destination}")
    destination.mkdir()
    require_plain_directory(destination, f"{spec.label} destination")

    directories: dict[tuple[str, ...], int] = {}
    files: list[tuple[tuple[str, ...], int, int, str]] = []
    with tarfile.open(path, mode="r:xz") as archive:
        for member in archive:
            relative_parts = validate_archive_member_name(member.name, spec)
            if not relative_parts:
                continue
            if member.isdir():
                directories[relative_parts] = member.mode
            else:
                files.append((relative_parts, int(member.size), member.mode, member.name))

    for parts in sorted(directories, key=lambda item: (len(item), tuple(x.casefold() for x in item))):
        target = destination.joinpath(*parts)
        require(target.parent == destination or target.parent.is_relative_to(destination),
                f"{spec.label} directory escaped extraction root")
        target.mkdir(exist_ok=False)
        require_plain_directory(target, f"{spec.label} extracted directory")
        os.chmod(target, directories[parts] & 0o777)

    with tarfile.open(path, mode="r:xz") as archive:
        for parts, expected_bytes, mode, member_name in files:
            target = destination.joinpath(*parts)
            require(target.parent == destination or target.parent.is_relative_to(destination),
                    f"{spec.label} file escaped extraction root")
            require_plain_directory(target.parent, f"{spec.label} file parent")
            member = archive.getmember(member_name)
            source = archive.extractfile(member)
            require(source is not None, f"{spec.label} member has no payload: {member_name}")
            with source:
                copy_member_payload(source, target, expected_bytes, mode)
            require_plain_file(target, f"{spec.label} extracted file")

    write_exclusive(destination / ".piopm", spec.piopm)
    fsync_directory(destination)
    inventory = tree_inventory(destination, label=f"{spec.label} extracted tree")
    require(inventory["files"] == archive_record["files"] + 1,
            f"{spec.label} extracted file count changed")
    require(inventory["file_bytes"] == archive_record["file_bytes"] + len(spec.piopm),
            f"{spec.label} extracted byte count changed")
    return {
        "archive": archive_record,
        "destination": spec.destination_name,
        "tree": inventory,
    }


def validate_zip_member_name(name: str, spec: ZipArchiveSpec) -> tuple[str, ...]:
    require("\\" not in name and "\x00" not in name,
            f"{spec.label} ZIP has an unsafe member name")
    pure = PurePosixPath(name)
    require(not pure.is_absolute(), f"{spec.label} ZIP has an absolute member")
    parts = pure.parts
    normalized = "/".join(parts)
    require(name in (normalized, normalized + "/"),
            f"{spec.label} ZIP has an aliased member name: {name!r}")
    require(parts, f"{spec.label} ZIP has an empty member name")
    if spec.top_level:
        require(parts[0] == spec.top_level,
                f"{spec.label} ZIP escaped its single top-level directory")
    validate_relative_parts(tuple(parts), f"{spec.label} ZIP member")
    relative_parts = tuple(parts[1:] if spec.top_level else parts)
    forbidden = {"__pycache__", ".xtinct-build-wrapper.lock"}
    require(not any(part.casefold() in forbidden for part in relative_parts),
            f"{spec.label} ZIP contains excluded runtime state: {name}")
    require(not any(part.casefold().endswith((".pyc", ".pyo")) for part in relative_parts),
            f"{spec.label} ZIP contains excluded Python bytecode: {name}")
    return relative_parts


def zip_manifest_record(member: zipfile.ZipInfo) -> dict[str, object]:
    return {
        "compressed_bytes": int(member.compress_size),
        "compression": int(member.compress_type),
        "crc32": f"{member.CRC:08x}",
        "file_bytes": int(member.file_size),
        "kind": "directory" if member.is_dir() else "file",
        "mode": (int(member.external_attr) >> 16) & 0xFFFF,
        "path": member.filename,
    }


def inspect_zip_archive(path: Path, spec: ZipArchiveSpec) -> dict[str, object]:
    """Validate the exact official platform ZIP and all extraction metadata."""
    value = require_plain_file(path, f"{spec.label} archive")
    require(value.st_size == spec.archive_bytes,
            f"{spec.label} archive byte count changed")
    require(sha256_file(path) == spec.archive_sha256,
            f"{spec.label} archive SHA-256 changed")

    records: list[dict[str, object]] = []
    canonical_paths: set[str] = set()
    file_bytes = 0
    compressed_file_bytes = 0
    files = 0
    directories = 0
    mode_counts: dict[int, int] = {}
    explicit_directories: set[tuple[str, ...]] = set()
    child_paths: list[tuple[tuple[str, ...], bool]] = []
    saw_top_directory = not spec.top_level
    with zipfile.ZipFile(path, mode="r") as archive:
        require(archive.comment == b"", f"{spec.label} ZIP gained an archive comment")
        members = archive.infolist()
        require(len(members) == spec.entries,
                f"{spec.label} ZIP entry count changed")
        for member in members:
            relative_parts = validate_zip_member_name(member.filename, spec)
            canonical = canonical_relative(tuple(PurePosixPath(member.filename).parts),
                                             f"{spec.label} ZIP member")
            require(canonical not in canonical_paths,
                    f"{spec.label} ZIP has a case-folding duplicate: {member.filename}")
            canonical_paths.add(canonical)
            require(member.flag_bits == 0,
                    f"{spec.label} ZIP member has unexpected flags: {member.filename}")
            require(member.create_system == 3 and member.internal_attr == 0,
                    f"{spec.label} ZIP member origin/attributes changed: {member.filename}")
            require(member.comment == b"" and member.volume == 0,
                    f"{spec.label} ZIP member metadata changed: {member.filename}")
            require(member.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED),
                    f"{spec.label} ZIP uses unsupported compression: {member.filename}")

            mode = (int(member.external_attr) >> 16) & 0xFFFF
            mode_counts[mode] = mode_counts.get(mode, 0) + 1
            if not relative_parts:
                require(bool(spec.top_level),
                        f"{spec.label} rootless ZIP has an empty relative member")
                require(member.is_dir() and stat.S_ISDIR(mode) and mode == 0o040755,
                        f"{spec.label} top-level ZIP member is not a directory")
                saw_top_directory = True
            elif member.is_dir():
                require(stat.S_ISDIR(mode) and mode == 0o040755,
                        f"{spec.label} ZIP directory mode changed: {member.filename}")
                require(member.file_size == 0 and member.compress_size == 0,
                        f"{spec.label} ZIP directory has a payload: {member.filename}")
                directories += 1
                explicit_directories.add(relative_parts)
            else:
                require(stat.S_ISREG(mode) and mode in (0o100644, 0o100755),
                        f"{spec.label} ZIP file mode changed: {member.filename}")
                require(0 <= member.file_size <= spec.maximum_file_bytes,
                        f"{spec.label} ZIP file exceeds its cap: {member.filename}")
                files += 1
                file_bytes += int(member.file_size)
                compressed_file_bytes += int(member.compress_size)
            if relative_parts:
                child_paths.append((relative_parts, member.is_dir()))
            records.append(zip_manifest_record(member))

        require(saw_top_directory, f"{spec.label} ZIP lacks its top-level directory")
        for relative_parts, _is_directory in child_paths:
            parent = relative_parts[:-1]
            require(not parent or parent in explicit_directories,
                    f"{spec.label} ZIP omits an explicit parent directory")
        require(archive.testzip() is None, f"{spec.label} ZIP failed its CRC check")

    manifest = b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        for record in records
    )
    actual_mode_counts = tuple(sorted(mode_counts.items()))
    counted_directories = directories + (1 if spec.top_level else 0)
    require(files == spec.files and counted_directories == spec.directories,
            f"{spec.label} ZIP file/directory counts changed")
    require(file_bytes == spec.file_bytes,
            f"{spec.label} ZIP expanded byte count changed")
    require(compressed_file_bytes == spec.compressed_file_bytes,
            f"{spec.label} ZIP compressed byte count changed")
    require(actual_mode_counts == spec.mode_counts,
            f"{spec.label} ZIP mode counts changed")
    require(len(manifest) == spec.manifest_bytes and
            hashlib.sha256(manifest).hexdigest() == spec.manifest_sha256,
            f"{spec.label} ZIP record manifest changed")
    require(path.stat(follow_symlinks=False).st_size == spec.archive_bytes and
            sha256_file(path) == spec.archive_sha256,
            f"{spec.label} archive changed during validation")
    return {
        "archive_bytes": spec.archive_bytes,
        "archive_sha256": spec.archive_sha256,
        "compressed_file_bytes": compressed_file_bytes,
        "directories": spec.directories,
        "entries": len(records),
        "file_bytes": file_bytes,
        "files": files,
        "manifest_bytes": len(manifest),
        "manifest_sha256": hashlib.sha256(manifest).hexdigest(),
        "mode_counts": {f"{mode:06o}": count for mode, count in actual_mode_counts},
        "records": records,
        "top_level": spec.top_level,
    }


def safe_extract_zip_archive(path: Path, spec: ZipArchiveSpec,
                             destination_parent: Path) -> dict[str, object]:
    """Directly construct a plain private package/platform from a pinned ZIP."""
    archive_record = inspect_zip_archive(path, spec)
    require_plain_directory(destination_parent, "READY27 ZIP destination parent")
    destination = destination_parent / spec.destination_name
    require_direct_child(destination_parent, destination, f"{spec.label} destination")
    require(not os.path.lexists(destination),
            f"{spec.label} destination already exists: {destination}")
    destination.mkdir()
    require_plain_directory(destination, f"{spec.label} destination")

    with zipfile.ZipFile(path, mode="r") as archive:
        members = archive.infolist()
        directories: dict[tuple[str, ...], int] = {}
        files: list[tuple[zipfile.ZipInfo, tuple[str, ...], int]] = []
        for member in members:
            relative_parts = validate_zip_member_name(member.filename, spec)
            if not relative_parts:
                continue
            mode = (int(member.external_attr) >> 16) & 0xFFFF
            if member.is_dir():
                directories[relative_parts] = mode
            else:
                files.append((member, relative_parts, mode))

        for parts in sorted(directories,
                            key=lambda item: (len(item), tuple(x.casefold() for x in item))):
            target = destination.joinpath(*parts)
            require(target.parent == destination or target.parent.is_relative_to(destination),
                    f"{spec.label} directory escaped extraction root")
            target.mkdir(exist_ok=False)
            require_plain_directory(target, f"{spec.label} extracted directory")
            os.chmod(target, directories[parts] & 0o777)

        for member, parts, mode in files:
            target = destination.joinpath(*parts)
            require(target.parent == destination or target.parent.is_relative_to(destination),
                    f"{spec.label} file escaped extraction root")
            require_plain_directory(target.parent, f"{spec.label} file parent")
            with archive.open(member, mode="r") as source:
                copy_member_payload(source, target, int(member.file_size), mode)
            require_plain_file(target, f"{spec.label} extracted file")

    write_exclusive(destination / ".piopm", spec.piopm)
    require((destination / ".piopm").read_bytes() == spec.piopm,
            f"{spec.label} exact .piopm metadata changed")
    require(not os.path.lexists(destination / ".xtinct-build-wrapper.lock"),
            f"{spec.label} extraction retained the global build lock")
    fsync_directory(destination)
    inventory = tree_inventory(destination, label=f"{spec.label} extracted tree")
    require(inventory["files"] == spec.files + 1,
            f"{spec.label} extracted file count changed")
    extracted_directories = spec.directories - (1 if spec.top_level else 0)
    require(inventory["directories"] == extracted_directories,
            f"{spec.label} extracted directory count changed")
    require(inventory["file_bytes"] == spec.file_bytes + len(spec.piopm),
            f"{spec.label} extracted byte count changed")
    if spec == PLATFORM_ARCHIVE_SPEC:
        require_pinned_identity(inventory, PINNED_PLATFORM_EXTRACTED_IDENTITY,
                                f"{spec.label} extracted platform")
    return {
        "archive": archive_record,
        "destination": spec.destination_name,
        "tree": inventory,
    }


def runtime_cache_copy_ignore(_directory: str, names: list[str]) -> set[str]:
    return {
        name for name in names
        if name.casefold() == RUNTIME_CACHE_DIRECTORY or
        name.casefold().endswith(RUNTIME_CACHE_SUFFIXES)
    }


def copy_plain_tree(source: Path, destination: Path, *, label: str,
                    maximum_entries: int = MAX_INVENTORY_ENTRIES,
                    exclude_runtime_cache: bool = False) -> dict[str, object]:
    """Copy a reviewed plain tree and prove complete source/destination identity."""
    require_plain_directory(source, f"{label} source")
    require_plain_directory(destination.parent, f"{label} destination parent")
    require_direct_child(destination.parent, destination, f"{label} destination")
    require(not os.path.lexists(destination), f"{label} destination already exists")
    source_before = tree_inventory(
        source, label=f"{label} source", maximum_entries=maximum_entries,
        allow_source_hardlinks=True, exclude_runtime_cache=exclude_runtime_cache)
    shutil.copytree(
        source, destination, copy_function=shutil.copy2, symlinks=False,
        ignore=runtime_cache_copy_ignore if exclude_runtime_cache else None)
    destination_inventory = tree_inventory(
        destination, label=f"{label} destination", maximum_entries=maximum_entries,
        exclude_runtime_cache=exclude_runtime_cache)
    source_after = tree_inventory(
        source, label=f"{label} source", maximum_entries=maximum_entries,
        allow_source_hardlinks=True, exclude_runtime_cache=exclude_runtime_cache)
    require(source_after == source_before, f"{label} source changed during copy")
    require(inventory_content_identity(destination_inventory) ==
            inventory_content_identity(source_before),
            f"{label} copy is not byte/mode/path identical")
    require(destination_inventory["hardlink_groups"] == 0,
            f"{label} copy retained external hard-link topology")
    return source_before


def expected_core_name(lane: str) -> str:
    require(lane in READY27_LANES, f"Unknown READY27 lane: {lane!r}")
    return READY27_CORE_PREFIX + lane


def create_owned_core(platformio_root: Path, lane: str) -> tuple[Path, bytes]:
    require_plain_directory(platformio_root, "PlatformIO root")
    core = platformio_root / expected_core_name(lane)
    require_direct_child(platformio_root, core, "READY27 private core")
    require(not os.path.lexists(core), f"READY27 private core already exists: {core}")
    core.mkdir()
    require_plain_directory(core, "READY27 private core")
    marker_payload = (json.dumps({
        "lane": lane,
        "policy": OWNER_POLICY,
        "schema": 1,
    }, indent=2, sort_keys=True) + "\n").encode("ascii")
    write_exclusive(core / OWNER_MARKER_NAME, marker_payload)
    return core, marker_payload


def validate_owned_core(core: Path, lane: str, marker_payload: bytes) -> None:
    require(core.name == expected_core_name(lane), "READY27 private core name changed")
    require_plain_directory(core.parent, "READY27 private core parent")
    require_direct_child(core.parent, core, "READY27 private core")
    require_plain_directory(core, "READY27 private core")
    marker = core / OWNER_MARKER_NAME
    require_plain_file(marker, "READY27 ownership marker")
    require(marker.read_bytes() == marker_payload, "READY27 ownership marker changed")


def remove_owned_core(core: Path, lane: str, marker_payload: bytes) -> None:
    validate_owned_core(core, lane, marker_payload)
    tree_inventory(core, label="READY27 cleanup tree")
    shutil.rmtree(core)
    require(not os.path.lexists(core), "READY27 private core cleanup was incomplete")


def make_test_archive(path: Path, members: Iterable[tuple[str, bytes | None, str]]) -> None:
    with tarfile.open(path, mode="w:xz", format=tarfile.PAX_FORMAT) as archive:
        for name, payload, kind in members:
            info = tarfile.TarInfo(name)
            info.mtime = 1
            if kind == "directory":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            elif kind == "file":
                require(payload is not None, "Test file payload is missing")
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "target"
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = "root/file.txt"
                archive.addfile(info)
            else:
                raise AssertionError(kind)


def make_test_zip(path: Path, members: Iterable[tuple[str, bytes | None, str]]) -> None:
    with zipfile.ZipFile(path, mode="w") as archive:
        for name, payload, kind in members:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.date_time = (2026, 1, 1, 0, 0, 0)
            if kind == "directory":
                if not info.filename.endswith("/"):
                    info.filename += "/"
                info.external_attr = 0o040755 << 16
                info.compress_type = zipfile.ZIP_STORED
                archive.writestr(info, b"")
            elif kind in ("file", "executable", "bad-mode", "symlink", "special"):
                require(payload is not None, "Test ZIP file payload is missing")
                mode = {
                    "file": 0o100644,
                    "executable": 0o100755,
                    "bad-mode": 0o100600,
                    "symlink": 0o120777,
                    "special": 0o010644,
                }[kind]
                info.external_attr = mode << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, payload)
            else:
                raise AssertionError(kind)


def synthetic_zip_spec(path: Path) -> ZipArchiveSpec:
    with zipfile.ZipFile(path, mode="r") as archive:
        members = archive.infolist()
        records = [zip_manifest_record(member) for member in members]
        files = [member for member in members if not member.is_dir()]
        mode_counts: dict[int, int] = {}
        for member in members:
            mode = (int(member.external_attr) >> 16) & 0xFFFF
            mode_counts[mode] = mode_counts.get(mode, 0) + 1
    manifest = b"".join(
        (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        for record in records
    )
    return ZipArchiveSpec(
        label="synthetic ZIP",
        cache_name=path.name,
        archive_bytes=path.stat().st_size,
        archive_sha256=sha256_file(path),
        top_level="root",
        destination_name="platform",
        piopm=b'{"synthetic":true}',
        entries=len(members),
        files=len(files),
        directories=len(members) - len(files),
        file_bytes=sum(member.file_size for member in files),
        compressed_file_bytes=sum(member.compress_size for member in files),
        maximum_file_bytes=max(member.file_size for member in files),
        mode_counts=tuple(sorted(mode_counts.items())),
        manifest_bytes=len(manifest),
        manifest_sha256=hashlib.sha256(manifest).hexdigest(),
    )


def synthetic_spec(path: Path) -> ArchiveSpec:
    return ArchiveSpec(
        label="synthetic archive",
        cache_name=path.name,
        archive_bytes=path.stat().st_size,
        archive_sha256=sha256_file(path),
        top_level="root",
        destination_name="package",
        piopm=b"{}",
        maximum_entries=16,
        maximum_file_bytes=1024,
        maximum_total_file_bytes=4096,
    )


def expect_rejected(action, label: str) -> None:
    try:
        action()
    except Ready27CacheError:
        return
    raise Ready27CacheError(f"Self-test mutation was accepted: {label}")


def self_test_esptool_rebind(temporary: Path) -> None:
    """Source-only positive/mutation coverage; never installs or invokes tools."""
    require(
        PINNED_PACKAGE_VERSIONS["tool-esptoolpy"] ==
        ESPTOOL_PLATFORMIO_PACKAGE_VERSION == "5.1.2" and
        ESPTOOL_DISTRIBUTION_VERSION == "5.1.2" and
        ESPTOOL_MODULE_VERSION == "5.1.2" and
        ESPTOOL_VERSION_BANNER == "esptool v5.1.2",
        "PlatformIO package, editable metadata and esptool pins changed",
    )
    core = temporary / "platformio" / (READY27_CORE_PREFIX + "E")
    platform_fixture = core / "platforms" / GLOBAL_PLATFORM_DIRECTORY_NAME
    package_fixture = core / "packages" / "tool-esptoolpy"
    platform_fixture.mkdir(parents=True)
    package_fixture.mkdir(parents=True)
    (platform_fixture / "platform.json").write_text(json.dumps({
        "packages": {
            "tool-esptoolpy": {
                "optional": True,
                "owner": "pioarduino",
                "package-version": ESPTOOL_PLATFORMIO_PACKAGE_VERSION,
                "type": "uploader",
                "version": ESPTOOL_REGISTRY_URI,
            },
        },
    }), encoding="utf-8")
    (package_fixture / "package.json").write_text(json.dumps({
        "name": "tool-esptoolpy",
        "version": ESPTOOL_PLATFORMIO_PACKAGE_VERSION,
    }), encoding="utf-8")
    (package_fixture / ".piopm").write_bytes(ESPTOOL_PIOPM)
    require(verify_esptool_platform_package_contract(core) == {
        "module_version": "5.1.2",
        "package_uri": OFFICIAL_ESPTOOL_URI,
        "package_version": "5.1.2",
        "platform_requirement_uri": ESPTOOL_REGISTRY_URI,
    }, "Private esptool PlatformIO package positive contract changed")
    (package_fixture / "package.json").write_text(json.dumps({
        "name": "tool-esptoolpy",
        "version": "5.1.1",
    }), encoding="utf-8")
    expect_rejected(
        lambda: verify_esptool_platform_package_contract(core),
        "esptool PlatformIO package version",
    )
    (package_fixture / "package.json").write_text(json.dumps({
        "name": "tool-esptoolpy",
        "version": ESPTOOL_PLATFORMIO_PACKAGE_VERSION,
    }), encoding="utf-8")
    python_exe, _uv_exe, site_packages, package = esptool_rebind_paths(core)
    finder = site_packages / ESPTOOL_EDITABLE_FINDER
    dist_info = site_packages / f"esptool-{ESPTOOL_DISTRIBUTION_VERSION}.dist-info"
    mapping = {
        name: str((package / name).resolve()) for name in ESPTOOL_TOP_LEVEL_PACKAGES
    }
    namespaces = {
        "espefuse.efuse_defs": [str((package / "espefuse" / "efuse_defs").resolve())],
        "esptool.targets.stub_flasher": [
            str((package / "esptool" / "targets" / "stub_flasher").resolve())
        ],
        "esptool.targets.stub_flasher.1": [
            str((package / "esptool" / "targets" / "stub_flasher" / "1").resolve())
        ],
        "esptool.targets.stub_flasher.2": [
            str((package / "esptool" / "targets" / "stub_flasher" / "2").resolve())
        ],
    }
    probe: dict[str, object] = {
        "direct_url": {
            "dir_info": {"editable": True},
            "url": package.resolve().as_uri(),
        },
        "dist_info": str(dist_info.resolve()),
        "dist_name": "esptool",
        "executable": str(python_exe.resolve()),
        "finder": str(finder.resolve()),
        "imports": {
            name: str((package / name / "__init__.py").resolve())
            for name in ESPTOOL_TOP_LEVEL_PACKAGES
        },
        "mapping": mapping,
        "module_version": ESPTOOL_MODULE_VERSION,
        "namespaces": namespaces,
        "prefix": str((core / "penv").resolve()),
        "sys_path": [str(site_packages.resolve()), "C:\\Python311\\python311.zip"],
        "user_site": False,
        "version": ESPTOOL_DISTRIBUTION_VERSION,
    }
    normalized = validate_esptool_probe(probe, core)
    require(normalized["python"] == {
        "executable": python_exe.relative_to(core).as_posix(),
        "prefix": "penv",
    }, "Private esptool positive probe normalization changed")
    stage = core / ".cache" / "esptool-launchers"
    command = esptool_rebind_command(core, stage)
    require(command[:4] == [str(python_exe), "-I", "-B", "-c"] and
            command[4] == esptool_launcher_generator_code() and
            command[5:] == [
                str(stage), str(python_exe),
                json.dumps(ESPTOOL_CONSOLE_SPECS, separators=(",", ":")),
            ], "Private esptool launcher generator command changed")
    require(ESPTOOL_GENERATOR_PIP_VERSION == "26.2.1" and
            ESPTOOL_GENERATOR_DISTLIB_VERSION == "0.4.2" and
            "PipScriptMaker" in esptool_launcher_generator_code() and
            "maker.executable=str(executable)" in esptool_launcher_generator_code(),
            "Private esptool launcher generator identity changed")
    require(ESPTOOL_CONSOLE_SPECS == (
        "esp_rfc2217_server = esp_rfc2217_server.__init__:main",
        "espefuse = espefuse.__init__:_main",
        "espsecure = espsecure.__init__:_main",
        "esptool = esptool.__init__:_main",
    ), "Private esptool console entry points changed")

    record_fixture = temporary / "esptool-RECORD"
    record_fixture.write_text(
        "../../Scripts/esptool.exe,sha256=old,1\n"
        "../../Scripts/esptool.exe,sha256=old,1\n"
        "__editable___esptool_5_1_2_finder.py,sha256=old,1\n"
        "esptool-5.1.2.dist-info/RECORD,,\n",
        encoding="utf-8",
    )
    record_payloads = {
        "../../Scripts/esptool.exe": b"MZ-private-launcher",
        "__editable___esptool_5_1_2_finder.py": b"private-finder",
    }
    rewritten_record = rewrite_esptool_record(record_fixture, record_payloads)
    require(rewritten_record.count(b"../../Scripts/esptool.exe") == 2 and
            (b"sha256=" + record_sha256(b"MZ-private-launcher").encode("ascii"))
            in rewritten_record,
            "Private esptool RECORD rewrite changed")
    incomplete_record = temporary / "esptool-RECORD-incomplete"
    incomplete_record.write_text(
        "../../Scripts/esptool.exe,sha256=old,1\n"
        "esptool-5.1.2.dist-info/RECORD,,\n",
        encoding="utf-8",
    )
    expect_rejected(
        lambda: rewrite_esptool_record(incomplete_record, record_payloads),
        "incomplete esptool RECORD",
    )
    replace_fixture = temporary / "esptool-atomic-replace"
    replace_fixture.write_bytes(b"old")
    atomic_replace_payload(replace_fixture, b"new", "esptool replace fixture")
    require(replace_fixture.read_bytes() == b"new",
            "Private esptool atomic replacement changed")

    require(package_excludes_runtime_cache("tool-esptoolpy") and
            not package_excludes_runtime_cache("tool-scons") and
            RUNTIME_CACHE_EXCLUDED_PACKAGE_NAMES == frozenset({"tool-esptoolpy"}),
            "Private esptool runtime-cache exclusion scope changed")
    good_archive = {
        "archive_bytes": ESPTOOL_ARCHIVE_SPEC.archive_bytes,
        "archive_sha256": ESPTOOL_ARCHIVE_SPEC.archive_sha256,
        "compressed_file_bytes": ESPTOOL_ARCHIVE_SPEC.compressed_file_bytes,
        "directories": ESPTOOL_ARCHIVE_SPEC.directories,
        "entries": ESPTOOL_ARCHIVE_SPEC.entries,
        "file_bytes": ESPTOOL_ARCHIVE_SPEC.file_bytes,
        "files": ESPTOOL_ARCHIVE_SPEC.files,
        "manifest_bytes": ESPTOOL_ARCHIVE_SPEC.manifest_bytes,
        "manifest_sha256": ESPTOOL_ARCHIVE_SPEC.manifest_sha256,
        "mode_counts": {
            f"{mode:06o}": count for mode, count in ESPTOOL_ARCHIVE_SPEC.mode_counts
        },
        "top_level": ESPTOOL_ARCHIVE_SPEC.top_level,
    }
    good_extraction = {
        "extracted_tools": {
            "tool-esptoolpy": {
                "archive": good_archive,
                "destination": "tool-esptoolpy",
                "tree": dict(PINNED_ESPTOOL_EXTRACTED_IDENTITY),
            },
        },
    }
    validate_esptool_construction_source(
        good_extraction, dict(PINNED_ESPTOOL_EXTRACTED_IDENTITY))
    mutated_source = dict(PINNED_ESPTOOL_EXTRACTED_IDENTITY)
    mutated_source["inventory_sha256"] = "0" * 64
    expect_rejected(
        lambda: validate_esptool_construction_source(good_extraction, mutated_source),
        "esptool source-byte identity",
    )
    mutated_extraction = json.loads(json.dumps(good_extraction))
    mutated_extraction["extracted_tools"]["tool-esptoolpy"]["tree"][
        "inventory_sha256"] = "f" * 64
    expect_rejected(
        lambda: validate_esptool_construction_source(
            mutated_extraction, dict(PINNED_ESPTOOL_EXTRACTED_IDENTITY)),
        "esptool recorded extraction identity",
    )
    mutated_archive = json.loads(json.dumps(good_extraction))
    mutated_archive["extracted_tools"]["tool-esptoolpy"]["archive"][
        "archive_sha256"] = "e" * 64
    expect_rejected(
        lambda: validate_esptool_construction_source(
            mutated_archive, dict(PINNED_ESPTOOL_EXTRACTED_IDENTITY)),
        "esptool archive identity",
    )

    forbidden_roots = (
        str((core.parent / "packages").resolve()).casefold(),
        str((core.parent / "penv").resolve()).casefold(),
    )
    private_launcher = (
        b"MZ-fixture\0#!" + str(python_exe.resolve()).encode("utf-8") + b"\n")
    validate_esptool_launcher_payload(
        private_launcher, python_exe, forbidden_roots,
        "Private esptool launcher fixture")
    foreign_python = core.parent / "other-lane" / "penv" / "Scripts" / "python.exe"
    foreign_launcher = (
        b"MZ-fixture\0#!" + str(foreign_python.resolve()).encode("utf-8") + b"\n")
    expect_rejected(
        lambda: validate_esptool_launcher_payload(
            foreign_launcher, python_exe, forbidden_roots,
            "Private esptool launcher mutation"),
        "esptool launcher target",
    )

    cache_policy_source = temporary / "tool-esptoolpy-cache-policy"
    (cache_policy_source / "esptool" / "__pycache__").mkdir(parents=True)
    source_file = cache_policy_source / "esptool" / "__init__.py"
    source_file.write_bytes(b"source-v1\n")
    (cache_policy_source / "esptool" / "__pycache__" / "module.pyc").write_bytes(
        b"generated")
    cacheless_before = tree_inventory(
        cache_policy_source, label="esptool cache-policy fixture",
        exclude_runtime_cache=True)
    require(cacheless_before["files"] == 1,
            "Esptool cache-policy fixture retained generated bytecode")
    source_file.write_bytes(b"source-v2\n")
    cacheless_after = tree_inventory(
        cache_policy_source, label="esptool source-byte mutation fixture",
        exclude_runtime_cache=True)
    require(cacheless_after["inventory_sha256"] != cacheless_before["inventory_sha256"],
            "Esptool source-byte mutation did not change its cacheless identity")
    (cache_policy_source / "esptool" / "__pycache__" / "hidden.txt").write_bytes(
        b"not bytecode")
    expect_rejected(
        lambda: tree_inventory(
            cache_policy_source, label="esptool unsafe cache fixture",
            exclude_runtime_cache=True),
        "esptool non-bytecode hidden in cache",
    )

    def mutation(path: tuple[object, ...], value: object, label: str) -> None:
        changed = json.loads(json.dumps(probe))
        target: object = changed
        for key in path[:-1]:
            target = target[key]  # type: ignore[index]
        target[path[-1]] = value  # type: ignore[index]
        expect_rejected(lambda: validate_esptool_probe(changed, core), label)

    global_package = core.parent / "packages" / "tool-esptoolpy"
    mutation(("version",), "5.1.1", "esptool version")
    mutation(("module_version",), "5.1.1", "esptool module version")
    mutation(("user_site",), True, "esptool user site")
    mutation(("direct_url", "dir_info", "editable"), False,
             "esptool non-editable direct URL")
    mutation(("direct_url", "url"), global_package.resolve().as_uri(),
             "esptool global direct URL")
    mutation(("mapping", "esptool"), str((global_package / "esptool").resolve()),
             "esptool global editable finder")
    mutation(("namespaces", "espefuse.efuse_defs"),
             [str((global_package / "espefuse" / "efuse_defs").resolve())],
             "esptool global namespace")
    mutation(("imports", "espsecure"),
             str((global_package / "espsecure" / "__init__.py").resolve()),
             "esptool global import")
    changed_sys_path = json.loads(json.dumps(probe))
    changed_sys_path["sys_path"].append(str((core.parent / "penv" / "Lib").resolve()))
    expect_rejected(lambda: validate_esptool_probe(changed_sys_path, core),
                    "esptool global sys.path")


def self_test() -> None:
    with tempfile.TemporaryDirectory(prefix="xtinct-ready27-cache-test-") as temporary_name:
        temporary = Path(temporary_name)
        self_test_esptool_rebind(temporary)
        good = temporary / "good.tar.xz"
        make_test_archive(good, (
            ("root", None, "directory"),
            ("root/sub", None, "directory"),
            ("root/file.txt", b"alpha", "file"),
            ("root/sub/value.bin", b"beta", "file"),
        ))
        spec = synthetic_spec(good)
        packages = temporary / "packages"
        packages.mkdir()
        record = safe_extract_archive(good, spec, packages)
        require(record["tree"]["files"] == 3, "Safe extraction self-test file count changed")
        inventory = tree_inventory(packages / "package", label="safe extraction fixture")
        require(inventory == record["tree"], "Safe extraction inventory is unstable")

        copy_parent = temporary / "copy-parent"
        copy_parent.mkdir()
        copied = copy_parent / "copied"
        source_inventory = copy_plain_tree(packages / "package", copied, label="copy self-test")
        require(tree_inventory(copied, label="copied fixture") == source_inventory,
                "Plain copy self-test identity changed")

        # Source filesystem deduplication is not a firmware input.  Prove that
        # link-topology-only drift is accepted while any path/mode/byte drift
        # remains fail-closed.
        topology_only = dict(source_inventory)
        topology_only["hardlink_groups"] = 17
        topology_only["hardlink_sha256"] = "1" * 64
        require_pinned_content_identity(
            topology_only, source_inventory,
            "source hard-link topology self-test")
        content_changed = dict(topology_only)
        content_changed["inventory_sha256"] = "2" * 64
        expect_rejected(
            lambda: require_pinned_content_identity(
                content_changed, source_inventory,
                "source content mutation self-test"),
            "source content identity mutation",
        )

        (copied / "file.txt").write_bytes(b"changed")
        expect_rejected(
            lambda: require(tree_inventory(copied, label="mutated copy") == source_inventory,
                            "Copied tree mutation was not detected"),
            "copied-byte mutation",
        )

        cache_source = temporary / "cache-source"
        cache_source.mkdir()
        (cache_source / "keep.py").write_bytes(b"print('kept')\n")
        (cache_source / "loose.pyc").write_bytes(b"discarded")
        bytecode = cache_source / "__pycache__"
        bytecode.mkdir()
        (bytecode / "keep.cpython-311.pyc").write_bytes(b"discarded too")
        cacheless = tree_inventory(
            cache_source, label="cacheless fixture", exclude_runtime_cache=True)
        require(cacheless["entries"] == 1 and cacheless["files"] == 1 and
                cacheless["records"][0]["path"] == "keep.py",
                "Runtime-cache inventory exclusion changed")
        cache_destination = temporary / "cache-destination"
        copied_cacheless = copy_plain_tree(
            cache_source, cache_destination, label="cacheless copy fixture",
            exclude_runtime_cache=True)
        require(copied_cacheless == cacheless,
                "Runtime-cache source identity changed during copy")
        require((cache_destination / "keep.py").is_file() and
                not os.path.lexists(cache_destination / "loose.pyc") and
                not os.path.lexists(cache_destination / "__pycache__"),
                "Runtime-cache exclusion copied generated state")
        (bytecode / "not-bytecode.txt").write_bytes(b"must not be hidden")
        expect_rejected(
            lambda: tree_inventory(
                cache_source, label="unsafe cache fixture", exclude_runtime_cache=True),
            "non-bytecode hidden in runtime cache",
        )

        mutations = {
            "traversal": (("root", None, "directory"), ("root/../escape", b"x", "file")),
            "absolute": (("root", None, "directory"), ("/root/escape", b"x", "file")),
            "backslash": (("root", None, "directory"), ("root\\escape", b"x", "file")),
            "case-duplicate": (
                ("root", None, "directory"),
                ("root/File.txt", b"x", "file"),
                ("root/file.txt", b"y", "file"),
            ),
            "symlink": (("root", None, "directory"), ("root/link", None, "symlink")),
            "hardlink": (("root", None, "directory"), ("root/link", None, "hardlink")),
            "second-root": (
                ("root", None, "directory"),
                ("other", None, "directory"),
                ("other/file", b"x", "file"),
            ),
        }
        for label, members in mutations.items():
            archive_path = temporary / f"{label}.tar.xz"
            make_test_archive(archive_path, members)
            mutation_spec = synthetic_spec(archive_path)
            expect_rejected(lambda p=archive_path, s=mutation_spec: inspect_archive(p, s), label)

        wrong_hash = ArchiveSpec(**{
            **spec.__dict__,
            "archive_sha256": "0" * 64,
        })
        expect_rejected(lambda: inspect_archive(good, wrong_hash), "archive hash")

        good_zip = temporary / "good.zip"
        make_test_zip(good_zip, (
            ("root", None, "directory"),
            ("root/sub", None, "directory"),
            ("root/file.txt", b"alpha", "file"),
            ("root/sub/tool.py", b"beta", "executable"),
        ))
        zip_spec = synthetic_zip_spec(good_zip)
        zip_record = inspect_zip_archive(good_zip, zip_spec)
        require(zip_record["entries"] == 4 and len(zip_record["records"]) == 4,
                "ZIP validation did not retain its full record inventory")
        zip_platforms = temporary / "zip-platforms"
        zip_platforms.mkdir()
        extracted_zip = safe_extract_zip_archive(good_zip, zip_spec, zip_platforms)
        extracted_zip_root = zip_platforms / zip_spec.destination_name
        require((extracted_zip_root / ".piopm").read_bytes() == zip_spec.piopm,
                "ZIP extraction changed exact .piopm bytes")
        require(not any(path.name == "__pycache__" or path.suffix.casefold() == ".pyc"
                        for path in extracted_zip_root.rglob("*")),
                "ZIP extraction retained excluded Python bytecode state")
        require(extracted_zip["tree"] == tree_inventory(
            extracted_zip_root, label="ZIP extraction self-test"),
            "ZIP extraction full record inventory is unstable")

        zip_mutations = {
            "traversal": (("root", None, "directory"), ("root/../escape", b"x", "file")),
            "absolute": (("root", None, "directory"), ("/root/escape", b"x", "file")),
            "backslash-traversal": (
                ("root", None, "directory"), ("root\\..\\escape", b"x", "file")
            ),
            "aliased": (("root", None, "directory"), ("root//escape", b"x", "file")),
            "case-duplicate": (
                ("root", None, "directory"),
                ("root/File.txt", b"x", "file"),
                ("root/file.txt", b"y", "file"),
            ),
            "symlink": (("root", None, "directory"), ("root/link", b"target", "symlink")),
            "special": (("root", None, "directory"), ("root/fifo", b"x", "special")),
            "unexpected-mode": (("root", None, "directory"), ("root/private", b"x", "bad-mode")),
            "global-lock": (
                ("root", None, "directory"),
                ("root/.xtinct-build-wrapper.lock", b"x", "file"),
            ),
            "pycache": (
                ("root", None, "directory"),
                ("root/__pycache__", None, "directory"),
                ("root/__pycache__/module.pyc", b"x", "file"),
            ),
            "second-root": (
                ("root", None, "directory"),
                ("other", None, "directory"),
                ("other/file", b"x", "file"),
            ),
        }
        for label, members in zip_mutations.items():
            archive_path = temporary / f"zip-{label}.zip"
            make_test_zip(archive_path, members)
            mutation_spec = synthetic_zip_spec(archive_path)
            expect_rejected(
                lambda p=archive_path, s=mutation_spec: inspect_zip_archive(p, s), label)

        wrong_zip_hash = ZipArchiveSpec(**{
            **zip_spec.__dict__,
            "archive_sha256": "0" * 64,
        })
        expect_rejected(lambda: inspect_zip_archive(good_zip, wrong_zip_hash), "ZIP hash")
        wrong_zip_count = ZipArchiveSpec(**{
            **zip_spec.__dict__,
            "entries": zip_spec.entries + 1,
        })
        expect_rejected(lambda: inspect_zip_archive(good_zip, wrong_zip_count), "ZIP count")
        wrong_zip_size = ZipArchiveSpec(**{
            **zip_spec.__dict__,
            "file_bytes": zip_spec.file_bytes + 1,
        })
        expect_rejected(lambda: inspect_zip_archive(good_zip, wrong_zip_size), "ZIP size")

        require(READY27_LANES == ("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K"),
                "READY27 approved-lane allowlist changed")
        expect_rejected(lambda: expected_core_name("L"), "unapproved lane")
        expect_rejected(lambda: expected_core_name("k"), "lowercase lane alias")

        owned_parent = temporary / "owned"
        owned_parent.mkdir()
        for lane in READY27_LANES:
            core, marker = create_owned_core(owned_parent, lane)
            require(core.name == READY27_CORE_PREFIX + lane,
                    "READY27 owned-core lane name changed")
            validate_owned_core(core, lane, marker)
            (core / "payload").write_bytes(b"owned")
            if lane == "A":
                wrong_marker = marker.replace(b'"A"', b'"B"')
                expect_rejected(
                    lambda: remove_owned_core(core, "A", wrong_marker),
                    "ownership marker",
                )
            remove_owned_core(core, lane, marker)

        # Dependency construction must remain pinned, private and metadata
        # free.  Run source-only mutation tests without reading a project cache.
        expected_dependency_names = (
            set(PINNED_REGISTRY_DEPENDENCY_IDENTITIES)
            | {spec.name for spec in GIT_DEPENDENCY_SPECS}
            | set(PINNED_LIBDEPS_CONTROL_FILES)
        )
        dependency_fixture = temporary / "dependency-allowlist"
        dependency_fixture.mkdir()
        for name in expected_dependency_names:
            target = dependency_fixture / name
            if "." in name and name in PINNED_LIBDEPS_CONTROL_FILES:
                target.write_bytes(b"x")
            else:
                target.mkdir()
        validate_dependency_source_allowlist(dependency_fixture)
        (dependency_fixture / "unexpected").mkdir()
        expect_rejected(
            lambda: validate_dependency_source_allowlist(dependency_fixture),
            "dependency allowlist mutation",
        )

        require(set(PINNED_GIT_DEPENDENCY_SEED_IDENTITIES) ==
                {spec.name for spec in GIT_DEPENDENCY_SPECS},
                "Git dependency seed identity allowlist changed")
        require(PINNED_PORTABLE_DEPENDENCY_SOURCE_IDENTITY == pinned_identity(
            387, 1_795, 63_979_571, 1_408, 276_027,
            "ef2564aa9aa1d1de2e8eaba2b5d5a8664251d8b4a49d228bbc28e2f146b1bf55",
        ), "portable dependency source identity changed")
        require(GIT_DEPENDENCY_SPECS[0].diff_autocrlf == "true" and
                GIT_DEPENDENCY_SPECS[1].diff_autocrlf == "false" and
                GIT_DEPENDENCY_SPECS[3].diff_autocrlf == "true",
                "reviewed Git patch line-ending policy changed")

    print("XTINCT_READY27_CACHE_SELF_TEST_OK")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    require(args.self_test, "Only --self-test is available without the release orchestrator")
    self_test()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Ready27CacheError, OSError, tarfile.TarError, zipfile.BadZipFile) as error:
        print(f"XTINCT READY27 cache gate failed closed: {error}", file=os.sys.stderr)
        raise SystemExit(1)
