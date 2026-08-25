#!/usr/bin/env python3
"""Fail-closed ESP32-C3 QEMU preparation and smoke-test harness for XTINCT.

This tool never talks to an X3 and never flashes hardware.  It accepts only a
complete, same-build PlatformIO output set whose ``firmware.bin`` is byte-for-
byte identical to the workspace's canonical ``update.bin``.  The resulting
16 MiB flash image can be booted by Espressif's ESP32-C3 QEMU for CPU, ROM,
second-stage bootloader, application-entry and UART coverage.

QEMU is not an Xteink board emulator.  It cannot prove the E-Ink panel,
microSD, ADC buttons, Wi-Fi/BLE radios, RTC wake, battery or board timing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


SIMULATOR_ROOT = Path(__file__).resolve().parent
CROSSPOINT_ROOT = SIMULATOR_ROOT.parents[1]
WORKSPACE_ROOT = SIMULATOR_ROOT.parents[3]
CONTRACT_PATH = CROSSPOINT_ROOT / "config" / "x3-resource-budgets.json"
CANONICAL_UPDATE_PATH = WORKSPACE_ROOT / "update.bin"

BOOTLOADER_OFFSET = 0x0000
PARTITION_TABLE_OFFSET = 0x8000
PARTITION_TABLE_LIMIT = 0x9000
OTA_DATA_OFFSET = 0xE000
APP_OFFSET = 0x10000
APP_SLOT_BYTES = 0x640000
BOOT_APP0_BYTES = 0x2000
ESP_IMAGE_MAGIC = 0xE9
ESP32_C3_CHIP_ID = 5
PARTITION_ENTRY_MAGIC = b"\xAA\x50"
FILL_CHUNK = b"\xFF" * (1024 * 1024)
MANIFEST_SUFFIX = ".manifest.json"

KNOWN_QEMU_VERSION = "esp_develop_9.2.2_20250817"
KNOWN_QEMU_ARCHIVE_SHA256 = (
    "9474015f24d27acb7516955ec932e5307226bd9d6652cdc870793ed36010ab73"
)

UNSUPPORTED_PHYSICAL_COVERAGE = (
    "UC8253/UC8279 E-Ink controller, waveform, refresh and ghosting",
    "microSD electrical behavior, brownout and power-loss recovery",
    "ADC-ladder physical buttons",
    "Wi-Fi and BLE radio/link behavior",
    "RTC wake, IMU, battery and board power behavior",
    "physical heap fragmentation, stack high-water marks and watchdog timing",
)


class HarnessError(RuntimeError):
    """A validation or execution refusal suitable for CLI output."""


@dataclass(frozen=True)
class Component:
    name: str
    path: Path
    offset: int
    maximum_bytes: int
    exact_bytes: int | None = None


def _is_reparse_point(path: Path) -> bool:
    try:
        value = path.stat(follow_symlinks=False)
    except (FileNotFoundError, OSError):
        return False
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(value, "st_file_attributes", 0) & flag)


def require_plain_file(path: Path, description: str) -> Path:
    path = path.expanduser()
    try:
        value = path.stat(follow_symlinks=False)
    except FileNotFoundError as error:
        raise HarnessError(f"{description} is missing: {path}") from error
    except OSError as error:
        raise HarnessError(f"Cannot inspect {description}: {path}: {error}") from error
    if stat.S_ISLNK(value.st_mode) or _is_reparse_point(path):
        raise HarnessError(f"{description} must not be a link or reparse point: {path}")
    if not stat.S_ISREG(value.st_mode):
        raise HarnessError(f"{description} is not a regular file: {path}")
    return path.resolve()


def require_plain_directory(path: Path, description: str) -> Path:
    path = path.expanduser()
    try:
        value = path.stat(follow_symlinks=False)
    except FileNotFoundError as error:
        raise HarnessError(f"{description} is missing: {path}") from error
    except OSError as error:
        raise HarnessError(f"Cannot inspect {description}: {path}: {error}") from error
    if stat.S_ISLNK(value.st_mode) or _is_reparse_point(path):
        raise HarnessError(f"{description} must not be a link or reparse point: {path}")
    if not stat.S_ISDIR(value.st_mode):
        raise HarnessError(f"{description} is not a directory: {path}")
    return path.resolve()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, object]:
    contract_path = require_plain_file(path, "X3 resource budget contract")
    try:
        value = json.loads(contract_path.read_text(encoding="utf-8"))
    except (UnicodeError, json.JSONDecodeError, OSError) as error:
        raise HarnessError(f"X3 resource budget contract is invalid: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise HarnessError("X3 resource budget contract schema is not supported")
    return value


def _contract_limits(contract: dict[str, object]) -> tuple[int, int]:
    try:
        device = contract["device"]
        linked = contract["linked_image"]
        assert isinstance(device, dict) and isinstance(linked, dict)
        flash_bytes = int(device["flash_bytes"])
        ota_bytes = int(device["ota_slot_bytes"])
        linked_max = int(linked["firmware_bin_max_bytes"])
    except (KeyError, TypeError, ValueError, AssertionError) as error:
        raise HarnessError("X3 resource budget contract lacks flash/OTA limits") from error
    if flash_bytes != 16 * 1024 * 1024:
        raise HarnessError(f"Unexpected X3 flash size in contract: {flash_bytes}")
    if ota_bytes != APP_SLOT_BYTES or linked_max != APP_SLOT_BYTES:
        raise HarnessError("Partition, device and linked-image OTA limits disagree")
    return flash_bytes, ota_bytes


def validate_esp32c3_image(path: Path, description: str) -> dict[str, int]:
    path = require_plain_file(path, description)
    size = path.stat().st_size
    if size < 24:
        raise HarnessError(f"{description} is too short to be an ESP image: {size} bytes")
    with path.open("rb") as source:
        header = source.read(24)
    magic, segments, flash_mode, flash_size_freq = struct.unpack_from("<BBBB", header, 0)
    chip_id = struct.unpack_from("<H", header, 12)[0]
    if magic != ESP_IMAGE_MAGIC:
        raise HarnessError(f"{description} has invalid ESP image magic 0x{magic:02x}")
    if not 1 <= segments <= 16:
        raise HarnessError(f"{description} has invalid segment count {segments}")
    if flash_mode not in (0, 1, 2, 3):
        raise HarnessError(f"{description} has invalid SPI flash mode {flash_mode}")
    if chip_id != ESP32_C3_CHIP_ID:
        raise HarnessError(
            f"{description} targets chip ID {chip_id}, not ESP32-C3 ID {ESP32_C3_CHIP_ID}"
        )
    return {
        "bytes": size,
        "chip_id": chip_id,
        "flash_mode": flash_mode,
        "flash_size_freq": flash_size_freq,
        "segments": segments,
    }


def validate_partition_table(path: Path) -> dict[str, object]:
    path = require_plain_file(path, "Partition table")
    size = path.stat().st_size
    if not 32 <= size <= PARTITION_TABLE_LIMIT - PARTITION_TABLE_OFFSET:
        raise HarnessError(f"Partition table size is outside its 4 KiB region: {size}")
    data = path.read_bytes()
    magic = data[:2]
    if magic != PARTITION_ENTRY_MAGIC:
        raise HarnessError(
            f"Partition table has invalid first-entry magic {magic.hex() or '<empty>'}"
        )
    entries: dict[str, dict[str, int]] = {}
    for offset in range(0, len(data) - 31, 32):
        record = data[offset : offset + 32]
        if record[:2] == b"\xFF\xFF" or record[:2] == b"\xEB\xEB":
            break
        if record[:2] != PARTITION_ENTRY_MAGIC:
            raise HarnessError(f"Partition table entry at 0x{offset:x} has invalid magic")
        entry_type, subtype = struct.unpack_from("<BB", record, 2)
        flash_offset, flash_size = struct.unpack_from("<II", record, 4)
        try:
            label = record[12:28].split(b"\x00", 1)[0].decode("ascii", errors="strict")
        except UnicodeDecodeError as error:
            raise HarnessError("Partition table contains a non-ASCII label") from error
        if not label or label in entries:
            raise HarnessError("Partition table contains an empty or duplicate label")
        if flash_size == 0 or flash_offset + flash_size > 16 * 1024 * 1024:
            raise HarnessError(f"Partition {label} is outside the X3 16 MiB flash")
        entries[label] = {
            "type": entry_type,
            "subtype": subtype,
            "offset": flash_offset,
            "size": flash_size,
        }

    required = {
        "otadata": {"type": 1, "subtype": 0, "offset": OTA_DATA_OFFSET, "size": BOOT_APP0_BYTES},
        "app0": {"type": 0, "subtype": 0x10, "offset": APP_OFFSET, "size": APP_SLOT_BYTES},
        "app1": {"type": 0, "subtype": 0x11, "offset": APP_OFFSET + APP_SLOT_BYTES, "size": APP_SLOT_BYTES},
    }
    for label, expected in required.items():
        if entries.get(label) != expected:
            raise HarnessError(f"Partition table {label} entry does not match the authoritative X3 layout")

    ordered = sorted(entries.items(), key=lambda item: item[1]["offset"])
    for (left_name, left), (right_name, right) in zip(ordered, ordered[1:]):
        if left["offset"] + left["size"] > right["offset"]:
            raise HarnessError(f"Partitions {left_name} and {right_name} overlap")
    return {"bytes": size, "entries": entries}


def validate_boot_app0(path: Path) -> dict[str, int]:
    path = require_plain_file(path, "OTA-data initializer boot_app0.bin")
    size = path.stat().st_size
    if size != BOOT_APP0_BYTES:
        raise HarnessError(
            f"boot_app0.bin must fill the 0x2000-byte OTA-data partition; got {size}"
        )
    return {"bytes": size}


def _component_record(component: Component) -> dict[str, object]:
    size = component.path.stat().st_size
    if component.exact_bytes is not None and size != component.exact_bytes:
        raise HarnessError(
            f"{component.name} must be exactly {component.exact_bytes} bytes; got {size}"
        )
    if size <= 0 or size > component.maximum_bytes:
        raise HarnessError(
            f"{component.name} size {size} exceeds its {component.maximum_bytes}-byte region"
        )
    return {
        "bytes": size,
        "offset": component.offset,
        "sha256": sha256_file(component.path),
        "source_name": component.path.name,
    }


def components_from_build(build_dir: Path, boot_app0: Path) -> tuple[Component, ...]:
    build_dir = require_plain_directory(build_dir, "Retained PlatformIO build directory")
    return (
        Component(
            "bootloader.bin",
            require_plain_file(build_dir / "bootloader.bin", "Same-build bootloader.bin"),
            BOOTLOADER_OFFSET,
            PARTITION_TABLE_OFFSET - BOOTLOADER_OFFSET,
        ),
        Component(
            "partitions.bin",
            require_plain_file(build_dir / "partitions.bin", "Same-build partitions.bin"),
            PARTITION_TABLE_OFFSET,
            PARTITION_TABLE_LIMIT - PARTITION_TABLE_OFFSET,
        ),
        Component(
            "boot_app0.bin",
            require_plain_file(boot_app0, "Exact build-package boot_app0.bin"),
            OTA_DATA_OFFSET,
            APP_OFFSET - OTA_DATA_OFFSET,
            exact_bytes=BOOT_APP0_BYTES,
        ),
        Component(
            "firmware.bin",
            require_plain_file(build_dir / "firmware.bin", "Same-build firmware.bin"),
            APP_OFFSET,
            APP_SLOT_BYTES,
        ),
    )


def validate_components(
    components: Sequence[Component],
    canonical_update: Path = CANONICAL_UPDATE_PATH,
    contract_path: Path = CONTRACT_PATH,
) -> tuple[int, dict[str, dict[str, object]]]:
    canonical = require_plain_file(canonical_update, "Canonical workspace update.bin")
    contract = load_contract(contract_path)
    flash_bytes, ota_bytes = _contract_limits(contract)

    records = {component.name: _component_record(component) for component in components}
    if set(records) != {
        "bootloader.bin",
        "partitions.bin",
        "boot_app0.bin",
        "firmware.bin",
    }:
        raise HarnessError("Full flash input set is incomplete or contains duplicate names")

    by_name = {component.name: component for component in components}
    validate_esp32c3_image(by_name["bootloader.bin"].path, "Bootloader")
    validate_partition_table(by_name["partitions.bin"].path)
    validate_boot_app0(by_name["boot_app0.bin"].path)
    app_info = validate_esp32c3_image(by_name["firmware.bin"].path, "Application firmware")
    if app_info["bytes"] > ota_bytes:
        raise HarnessError(
            f"Application firmware is {app_info['bytes']} bytes; OTA slot is {ota_bytes}"
        )

    canonical_size = canonical.stat().st_size
    canonical_hash = sha256_file(canonical)
    app_record = records["firmware.bin"]
    if app_record["bytes"] != canonical_size or app_record["sha256"] != canonical_hash:
        raise HarnessError(
            "Retained firmware.bin is not byte-for-byte identical to canonical /update.bin"
        )

    ordered = sorted(components, key=lambda item: item.offset)
    for left, right in zip(ordered, ordered[1:]):
        left_end = left.offset + left.path.stat().st_size
        if left_end > right.offset:
            raise HarnessError(
                f"{left.name} overlaps {right.name}: 0x{left_end:x} > 0x{right.offset:x}"
            )
    if ordered[-1].offset + ordered[-1].path.stat().st_size > flash_bytes:
        raise HarnessError("Application extends beyond the physical flash image")
    return flash_bytes, records


def _write_ff(destination, byte_count: int) -> None:
    remaining = byte_count
    while remaining:
        chunk = FILL_CHUNK if remaining >= len(FILL_CHUNK) else FILL_CHUNK[:remaining]
        destination.write(chunk)
        remaining -= len(chunk)


def _atomic_write_json(path: Path, value: object) -> None:
    payload = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as destination:
            destination.write(payload)
            destination.flush()
            os.fsync(destination.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise


def assemble_flash(
    build_dir: Path,
    boot_app0: Path,
    output: Path,
    *,
    canonical_update: Path = CANONICAL_UPDATE_PATH,
    contract_path: Path = CONTRACT_PATH,
    replace: bool = False,
) -> dict[str, object]:
    output = output.expanduser().absolute()
    if output.exists() and not replace:
        raise HarnessError(f"Output already exists; pass --replace explicitly: {output}")
    if output.exists():
        require_plain_file(output, "Existing output flash image")
    output_parent = require_plain_directory(output.parent, "Output directory")
    output = output_parent / output.name
    manifest_path = output.with_suffix(output.suffix + MANIFEST_SUFFIX)
    if manifest_path.exists() and not replace:
        raise HarnessError(f"Output manifest already exists; pass --replace explicitly: {manifest_path}")
    if manifest_path.exists():
        require_plain_file(manifest_path, "Existing output flash manifest")

    components = components_from_build(build_dir, boot_app0)
    flash_bytes, records = validate_components(components, canonical_update, contract_path)

    fd, temporary_name = tempfile.mkstemp(prefix=f".{output.name}.", suffix=".tmp", dir=output_parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w+b") as destination:
            _write_ff(destination, flash_bytes)
            for component in components:
                destination.seek(component.offset)
                with component.path.open("rb") as source:
                    shutil.copyfileobj(source, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        if temporary.stat().st_size != flash_bytes:
            raise HarnessError(
                f"Assembled flash size changed: {temporary.stat().st_size} != {flash_bytes}"
            )
        for component in components:
            record = records[component.name]
            digest = hashlib.sha256()
            with temporary.open("rb") as assembled:
                assembled.seek(component.offset)
                remaining = int(record["bytes"])
                while remaining:
                    chunk = assembled.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise HarnessError(f"Assembled flash truncated inside {component.name}")
                    digest.update(chunk)
                    remaining -= len(chunk)
            if digest.hexdigest() != record["sha256"]:
                raise HarnessError(f"Read-back hash mismatch inside assembled {component.name}")
        os.replace(temporary, output)
    except BaseException:
        try:
            temporary.unlink(missing_ok=True)
        finally:
            raise

    flash_hash = sha256_file(output)
    manifest: dict[str, object] = {
        "schema": 1,
        "assembled_utc": datetime.now(timezone.utc).isoformat(),
        "canonical_update": {
            "bytes": CANONICAL_UPDATE_PATH.stat().st_size
            if canonical_update == CANONICAL_UPDATE_PATH
            else require_plain_file(canonical_update, "Canonical update.bin").stat().st_size,
            "sha256": sha256_file(require_plain_file(canonical_update, "Canonical update.bin")),
        },
        "components": records,
        "flash": {
            "bytes": output.stat().st_size,
            "sha256": flash_hash,
        },
        "machine": "esp32c3",
        "network": "disabled",
        "scope": "CPU, ROM, second-stage bootloader, application-entry and UART only",
        "unsupported_physical_coverage": list(UNSUPPORTED_PHYSICAL_COVERAGE),
    }
    _atomic_write_json(manifest_path, manifest)
    if output.stat().st_size != flash_bytes or sha256_file(output) != flash_hash:
        raise HarnessError("Final flash image changed after atomic publication")
    return {"flash_path": str(output), "manifest_path": str(manifest_path), **manifest}


def _known_qemu_candidates() -> Iterable[Path]:
    requested = os.environ.get("X3_QEMU_PATH", "").strip()
    if requested:
        yield Path(requested)
    discovered = shutil.which("qemu-system-riscv32")
    if discovered:
        yield Path(discovered)
    local = os.environ.get("LOCALAPPDATA", "").strip()
    if local:
        root = Path(local) / "XTINCT" / "X3Simulator"
        yield (
            root
            / f"qemu-riscv32-{KNOWN_QEMU_VERSION}"
            / "qemu"
            / "bin"
            / "qemu-system-riscv32.exe"
        )
        installed = root / "esp-idf-tools" / "tools" / "qemu-riscv32" / KNOWN_QEMU_VERSION
        yield installed / "qemu" / "bin" / "qemu-system-riscv32.exe"


def locate_qemu() -> Path | None:
    seen: set[str] = set()
    for candidate in _known_qemu_candidates():
        key = str(candidate).casefold()
        if key in seen:
            continue
        seen.add(key)
        try:
            return require_plain_file(candidate, "Espressif qemu-system-riscv32")
        except HarnessError:
            continue
    return None


def _qemu_environment(qemu: Path) -> dict[str, str]:
    environment = dict(os.environ)
    search = [str(qemu.parent)]
    # Espressif's current Win64 archive imports libiconv-2.dll but does not
    # bundle it.  Git for Windows supplies the exact MinGW runtime dependency.
    git_runtime = Path(r"C:\Program Files\Git\mingw64\bin")
    if (git_runtime / "libiconv-2.dll").is_file():
        search.append(str(git_runtime))
    search.append(environment.get("PATH", ""))
    environment["PATH"] = os.pathsep.join(search)
    return environment


def probe_qemu(qemu: Path | None = None) -> dict[str, object]:
    candidate = qemu or locate_qemu()
    if candidate is None:
        return {
            "available": False,
            "error": "Espressif qemu-system-riscv32 was not found",
            "path": None,
            "version": None,
        }
    candidate = require_plain_file(candidate, "Espressif qemu-system-riscv32")
    try:
        result = subprocess.run(
            [str(candidate), "--version"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=_qemu_environment(candidate),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "available": False,
            "error": str(error),
            "path": str(candidate),
            "version": None,
        }
    lines = (result.stdout + "\n" + result.stderr).strip().splitlines()
    version = lines[0].strip() if lines else None
    machine_available = False
    machine_error: str | None = None
    if result.returncode == 0 and version:
        try:
            machine_result = subprocess.run(
                [str(candidate), "-M", "help"],
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=15,
                env=_qemu_environment(candidate),
            )
            machines = machine_result.stdout + "\n" + machine_result.stderr
            machine_available = machine_result.returncode == 0 and any(
                line.split(maxsplit=1)[0] == "esp32c3"
                for line in machines.splitlines()
                if line.strip()
            )
            if not machine_available:
                machine_error = "QEMU does not advertise Espressif's esp32c3 machine"
        except (OSError, subprocess.TimeoutExpired) as error:
            machine_error = str(error)
    return {
        "available": result.returncode == 0 and bool(version) and machine_available,
        "error": (
            None
            if result.returncode == 0 and bool(version) and machine_available
            else machine_error or f"QEMU exited {result.returncode}"
        ),
        "esp32c3_machine": machine_available,
        "path": str(candidate),
        "version": version,
    }


def status(
    build_dir: Path | None = None,
    boot_app0: Path | None = None,
    canonical_update: Path = CANONICAL_UPDATE_PATH,
    contract_path: Path = CONTRACT_PATH,
) -> dict[str, object]:
    qemu = probe_qemu()
    canonical: dict[str, object]
    try:
        canonical_path = require_plain_file(canonical_update, "Canonical workspace update.bin")
        canonical = {
            "available": True,
            "bytes": canonical_path.stat().st_size,
            "sha256": sha256_file(canonical_path),
            **validate_esp32c3_image(canonical_path, "Canonical workspace update.bin"),
        }
    except HarnessError as error:
        canonical = {"available": False, "error": str(error)}

    input_status: dict[str, object] = {
        "ready": False,
        "reason": "Pass --build-dir and --boot-app0 from one retained authoritative build",
    }
    if build_dir is not None or boot_app0 is not None:
        if build_dir is None or boot_app0 is None:
            input_status["reason"] = "Both --build-dir and --boot-app0 are required"
        else:
            try:
                components = components_from_build(build_dir, boot_app0)
                flash_bytes, records = validate_components(
                    components, canonical_update, contract_path
                )
                input_status = {
                    "ready": True,
                    "flash_bytes": flash_bytes,
                    "components": records,
                }
            except HarnessError as error:
                input_status = {"ready": False, "reason": str(error)}
    return {
        "schema": 1,
        "tier": 3,
        "canonical_update": canonical,
        "full_flash_inputs": input_status,
        "qemu": qemu,
        "ready_to_execute": bool(qemu.get("available") and input_status.get("ready")),
        "network": "disabled",
        "unsupported_physical_coverage": list(UNSUPPORTED_PHYSICAL_COVERAGE),
    }


def validate_manifest(
    flash: Path,
    canonical_update: Path = CANONICAL_UPDATE_PATH,
    contract_path: Path = CONTRACT_PATH,
) -> tuple[Path, dict[str, object]]:
    flash = require_plain_file(flash, "QEMU flash image")
    manifest_path = flash.with_suffix(flash.suffix + MANIFEST_SUFFIX)
    manifest_path = require_plain_file(manifest_path, "QEMU flash manifest")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessError(f"QEMU flash manifest is invalid: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema") != 1:
        raise HarnessError("QEMU flash manifest schema is not supported")
    flash_record = manifest.get("flash")
    if not isinstance(flash_record, dict):
        raise HarnessError("QEMU flash manifest lacks its flash record")
    if flash_record.get("bytes") != flash.stat().st_size:
        raise HarnessError("QEMU flash byte count differs from its manifest")
    if flash_record.get("sha256") != sha256_file(flash):
        raise HarnessError("QEMU flash SHA-256 differs from its manifest")
    contract = load_contract(contract_path)
    flash_bytes, _ota_bytes = _contract_limits(contract)
    if flash.stat().st_size != flash_bytes:
        raise HarnessError(
            f"QEMU flash size {flash.stat().st_size} does not match X3 flash {flash_bytes}"
        )
    canonical_record = manifest.get("canonical_update")
    if not isinstance(canonical_record, dict):
        raise HarnessError("QEMU flash manifest lacks its canonical update record")
    canonical = require_plain_file(canonical_update, "Current canonical workspace update.bin")
    if canonical_record.get("bytes") != canonical.stat().st_size:
        raise HarnessError("Canonical /update.bin byte count changed after QEMU assembly")
    if canonical_record.get("sha256") != sha256_file(canonical):
        raise HarnessError("Canonical /update.bin SHA-256 changed after QEMU assembly")
    return flash, manifest


def qemu_command(qemu: Path, flash: Path) -> list[str]:
    return [
        str(qemu),
        "-machine",
        "esp32c3",
        "-drive",
        f"file={flash},if=mtd,format=raw",
        "-nic",
        "none",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
    ]


def classify_uart_coverage(normalized: str) -> dict[str, bool]:
    """Classify only concrete ESP32-C3 ROM, handoff, and app-runtime evidence."""
    lower = normalized.lower()
    rom_booted = "esp-rom:esp32c3" in lower
    rom_loads = re.findall(
        r"(?im)^load:0x[0-9a-f]+,len:0x[0-9a-f]+\s*$", normalized
    )
    rom_entry = re.search(r"(?im)^entry 0x[0-9a-f]{8}\s*$", normalized) is not None
    second_stage = (
        "boot.esp32c3" in lower
        or "bootloader" in lower
        or (len(rom_loads) >= 2 and rom_entry)
    )
    arduino_runtime = re.search(
        r"(?im)^\[\s*\d+\]\[[vdiwe]\]\[[a-z0-9_.+\-]+\.(?:c|cc|cpp|cxx|h):\d+\]",
        normalized,
    ) is not None
    firmware_banner = re.search(
        r"(?im)^\s*(?:xtinct-x3|crosspoint(?:-x3)?)(?:[- :/][a-z0-9][^\r\n]{0,95})?\s*$",
        normalized,
    ) is not None
    app_entered = (
        "app_start" in lower
        or firmware_banner
        or arduino_runtime
    )
    return {
        "rom_booted": rom_booted,
        "second_stage_booted": second_stage,
        "application_entered": app_entered,
    }


def run_smoke(
    flash: Path,
    timeout_seconds: float = 15.0,
    canonical_update: Path = CANONICAL_UPDATE_PATH,
    contract_path: Path = CONTRACT_PATH,
) -> dict[str, object]:
    if timeout_seconds < 1 or timeout_seconds > 120:
        raise HarnessError("Smoke-test timeout must be between 1 and 120 seconds")
    flash, manifest = validate_manifest(flash, canonical_update, contract_path)
    qemu = locate_qemu()
    if qemu is None:
        raise HarnessError("Espressif qemu-system-riscv32 is not installed")
    probe = probe_qemu(qemu)
    if not probe.get("available"):
        raise HarnessError(f"Espressif QEMU cannot start: {probe.get('error')}")

    command = qemu_command(qemu, flash)
    started = time.monotonic()
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_qemu_environment(qemu),
    )
    timed_out = False
    try:
        output, _unused = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.terminate()
        try:
            output, _unused = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            output, _unused = process.communicate(timeout=5)
    elapsed = time.monotonic() - started
    normalized = output.replace("\r\n", "\n").replace("\r", "\n")
    coverage = classify_uart_coverage(normalized)
    return {
        "schema": 1,
        "tier": 3,
        "elapsed_seconds": round(elapsed, 3),
        "qemu_exit_code": process.returncode,
        "timed_out": timed_out,
        "coverage": coverage,
        "passed": all(coverage.values()),
        "network": "disabled",
        "flash_sha256": manifest["flash"]["sha256"],
        "uart": normalized[-65536:],
        "unsupported_physical_coverage": list(UNSUPPORTED_PHYSICAL_COVERAGE),
    }


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_release_inputs(command_parser: argparse.ArgumentParser) -> None:
        command_parser.add_argument(
            "--canonical-update", type=Path, default=CANONICAL_UPDATE_PATH,
            help="Canonical update.bin that retained firmware.bin must match",
        )
        command_parser.add_argument(
            "--contract", type=Path, default=CONTRACT_PATH,
            help="X3 resource-budget JSON used for flash and OTA limits",
        )

    status_parser = subparsers.add_parser("status", help="Report QEMU and full-flash readiness")
    add_release_inputs(status_parser)
    status_parser.add_argument("--build-dir", type=Path)
    status_parser.add_argument("--boot-app0", type=Path)

    assemble_parser = subparsers.add_parser(
        "assemble", help="Build a verified 16 MiB flash image from one retained build"
    )
    add_release_inputs(assemble_parser)
    assemble_parser.add_argument("--build-dir", type=Path, required=True)
    assemble_parser.add_argument("--boot-app0", type=Path, required=True)
    assemble_parser.add_argument("--output", type=Path, required=True)
    assemble_parser.add_argument("--replace", action="store_true")

    run_parser = subparsers.add_parser(
        "run", help="Run a bounded offline UART boot smoke test in Espressif QEMU"
    )
    add_release_inputs(run_parser)
    run_parser.add_argument("--flash", type=Path, required=True)
    run_parser.add_argument("--timeout-seconds", type=float, default=15.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "status":
            _print_json(status(
                args.build_dir, args.boot_app0, args.canonical_update, args.contract
            ))
            return 0
        if args.command == "assemble":
            _print_json(
                assemble_flash(
                    args.build_dir,
                    args.boot_app0,
                    args.output,
                    canonical_update=args.canonical_update,
                    contract_path=args.contract,
                    replace=args.replace,
                )
            )
            return 0
        if args.command == "run":
            result = run_smoke(
                args.flash,
                args.timeout_seconds,
                args.canonical_update,
                args.contract,
            )
            _print_json(result)
            return 0 if result["passed"] else 1
        raise HarnessError(f"Unsupported command: {args.command}")
    except HarnessError as error:
        print(f"X3_QEMU_REFUSED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
