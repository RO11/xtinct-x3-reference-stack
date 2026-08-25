"""Portable, read-only validation helpers for the X3 Preview Lab backend.

This module deliberately has no knowledge of parent workspace folders and no
network client. It validates only explicitly selected local files and probes an
already installed QEMU executable with bounded informational commands.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
from pathlib import Path


ESP_IMAGE_MAGIC = 0xE9
ESP32_C3_CHIP_ID = 5
APP_SLOT_BYTES = 0x640000
BOOT_APP0_BYTES = 0x2000
PARTITION_TABLE_MAX_BYTES = 0x1000
PARTITION_ENTRY_MAGIC = b"\xAA\x50"

UNSUPPORTED_PHYSICAL_COVERAGE = (
    "UC8253/UC8279 E-Ink controller, waveform, refresh and ghosting",
    "microSD electrical behavior, brownout and power-loss recovery",
    "ADC-ladder physical buttons",
    "Wi-Fi and BLE radio/link behavior",
    "RTC wake, IMU, battery and board power behavior",
    "physical heap fragmentation, stack high-water marks and watchdog timing",
)


class HarnessError(RuntimeError):
    """A local validation refusal suitable for a status response."""


def _is_link_or_reparse(path: Path) -> bool:
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & 0x400
    )


def require_plain_file(path: Path, label: str) -> Path:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise HarnessError(f"{label} is missing") from error
    if _is_link_or_reparse(path) or not stat.S_ISREG(info.st_mode):
        raise HarnessError(f"{label} must be a regular non-linked file")
    return path.resolve(strict=True)


def require_plain_directory(path: Path, label: str) -> Path:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise HarnessError(f"{label} is missing") from error
    if _is_link_or_reparse(path) or not stat.S_ISDIR(info.st_mode):
        raise HarnessError(f"{label} must be a regular non-linked directory")
    return path.resolve(strict=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def validate_esp32c3_image(path: Path, label: str) -> dict[str, int]:
    selected = require_plain_file(path, label)
    size = selected.stat().st_size
    if size < 24:
        raise HarnessError(f"{label} is too short to be an ESP image: {size} bytes")
    with selected.open("rb") as source:
        header = source.read(24)
    magic, segments, flash_mode, flash_size_freq = struct.unpack_from("<BBBB", header, 0)
    chip_id = struct.unpack_from("<H", header, 12)[0]
    if magic != ESP_IMAGE_MAGIC:
        raise HarnessError(f"{label} has invalid ESP image magic 0x{magic:02x}")
    if not 1 <= segments <= 16:
        raise HarnessError(f"{label} has invalid segment count {segments}")
    if flash_mode not in (0, 1, 2, 3):
        raise HarnessError(f"{label} has invalid SPI flash mode {flash_mode}")
    if chip_id != ESP32_C3_CHIP_ID:
        raise HarnessError(f"{label} targets chip ID {chip_id}, not ESP32-C3 ID {ESP32_C3_CHIP_ID}")
    return {
        "bytes": size,
        "chip_id": chip_id,
        "flash_mode": flash_mode,
        "flash_size_freq": flash_size_freq,
        "segments": segments,
    }


def _load_contract(path: Path) -> dict[str, object]:
    selected = require_plain_file(path, "X3 resource contract")
    try:
        value = json.loads(selected.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise HarnessError(f"X3 resource contract is invalid: {error}") from error
    if not isinstance(value, dict) or value.get("schema") != 1:
        raise HarnessError("X3 resource contract schema is not supported")
    return value


def _validate_partition_table(path: Path) -> dict[str, object]:
    selected = require_plain_file(path, "Same-build partitions.bin")
    size = selected.stat().st_size
    if not 32 <= size <= PARTITION_TABLE_MAX_BYTES:
        raise HarnessError(f"Partition table size is outside its 4 KiB region: {size}")
    data = selected.read_bytes()
    entries: dict[str, dict[str, int]] = {}
    for offset in range(0, len(data) - 31, 32):
        record = data[offset : offset + 32]
        if record[:2] in (b"\xFF\xFF", b"\xEB\xEB"):
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
        entries[label] = {
            "type": entry_type,
            "subtype": subtype,
            "offset": flash_offset,
            "size": flash_size,
        }
    required = {
        "otadata": {"type": 1, "subtype": 0, "offset": 0xE000, "size": BOOT_APP0_BYTES},
        "app0": {"type": 0, "subtype": 0x10, "offset": 0x10000, "size": APP_SLOT_BYTES},
        "app1": {"type": 0, "subtype": 0x11, "offset": 0x650000, "size": APP_SLOT_BYTES},
    }
    for label, expected in required.items():
        if entries.get(label) != expected:
            raise HarnessError(f"Partition table {label} entry does not match the X3 layout")
    return {"bytes": size, "entries": entries}


def validate_full_flash_inputs(
    build_dir: Path,
    boot_app0: Path,
    firmware: Path,
    contract_path: Path,
) -> dict[str, object]:
    """Validate one complete, matching full-flash input set without writing it."""

    build = require_plain_directory(build_dir, "Retained PlatformIO build directory")
    selected_firmware = require_plain_file(firmware, "Configured firmware image")
    selected_boot_app0 = require_plain_file(boot_app0, "Exact build-package boot_app0.bin")
    bootloader = require_plain_file(build / "bootloader.bin", "Same-build bootloader.bin")
    partitions = require_plain_file(build / "partitions.bin", "Same-build partitions.bin")
    built_firmware = require_plain_file(build / "firmware.bin", "Same-build firmware.bin")

    contract = _load_contract(contract_path)
    try:
        device = contract["device"]
        linked = contract["linked_image"]
        assert isinstance(device, dict) and isinstance(linked, dict)
        flash_bytes = int(device["flash_bytes"])
        ota_slot_bytes = int(device["ota_slot_bytes"])
        linked_max_bytes = int(linked["firmware_bin_max_bytes"])
    except (KeyError, TypeError, ValueError, AssertionError) as error:
        raise HarnessError("X3 resource contract lacks flash/OTA limits") from error
    if flash_bytes != 16 * 1024 * 1024 or ota_slot_bytes != APP_SLOT_BYTES or linked_max_bytes != APP_SLOT_BYTES:
        raise HarnessError("Resource contract does not match the X3 full-flash layout")

    bootloader_info = validate_esp32c3_image(bootloader, "Same-build bootloader.bin")
    if bootloader.stat().st_size > 0x8000:
        raise HarnessError("Same-build bootloader.bin exceeds its flash region")
    partition_info = _validate_partition_table(partitions)
    if selected_boot_app0.stat().st_size != BOOT_APP0_BYTES:
        raise HarnessError(f"boot_app0.bin must be exactly {BOOT_APP0_BYTES} bytes")
    firmware_info = validate_esp32c3_image(built_firmware, "Same-build firmware.bin")
    if built_firmware.stat().st_size > APP_SLOT_BYTES:
        raise HarnessError("Same-build firmware.bin exceeds the X3 OTA slot")
    if (
        built_firmware.stat().st_size != selected_firmware.stat().st_size
        or sha256_file(built_firmware) != sha256_file(selected_firmware)
    ):
        raise HarnessError("Retained firmware.bin is not byte-for-byte identical to configured firmware")
    return {
        "ready": True,
        "flash_bytes": flash_bytes,
        "components": {
            "bootloader.bin": {**bootloader_info, "sha256": sha256_file(bootloader)},
            "partitions.bin": {**partition_info, "sha256": sha256_file(partitions)},
            "boot_app0.bin": {"bytes": BOOT_APP0_BYTES, "sha256": sha256_file(selected_boot_app0)},
            "firmware.bin": {**firmware_info, "sha256": sha256_file(built_firmware)},
        },
    }


def _qemu_candidates() -> tuple[Path, ...]:
    values: list[Path] = []
    requested = os.environ.get("X3_QEMU_PATH", "").strip()
    if requested:
        values.append(Path(requested))
    discovered = shutil.which("qemu-system-riscv32")
    if discovered:
        values.append(Path(discovered))
    local = os.environ.get("LOCALAPPDATA", "").strip()
    if local:
        base = Path(local) / "XTINCT" / "X3Simulator"
        values.extend(base.glob("qemu-riscv32-*/qemu/bin/qemu-system-riscv32.exe"))
        values.extend(base.glob("esp-idf-tools/tools/qemu-riscv32/*/qemu/bin/qemu-system-riscv32.exe"))
    return tuple(values)


def _qemu_environment(qemu: Path) -> dict[str, str]:
    environment = dict(os.environ)
    search = [str(qemu.parent)]
    git_runtime = Path(r"C:\Program Files\Git\mingw64\bin")
    if (git_runtime / "libiconv-2.dll").is_file():
        search.append(str(git_runtime))
    search.append(environment.get("PATH", ""))
    environment["PATH"] = os.pathsep.join(search)
    return environment


def probe_qemu() -> dict[str, object]:
    """Probe only installed local candidates; never download or start a VM."""

    candidate: Path | None = None
    for value in _qemu_candidates():
        try:
            candidate = require_plain_file(value, "Espressif qemu-system-riscv32")
            break
        except HarnessError:
            continue
    if candidate is None:
        return {"available": False, "error": "Espressif QEMU was not found", "version": None}
    try:
        version_result = subprocess.run(
            [str(candidate), "--version"],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            env=_qemu_environment(candidate),
        )
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
    except (OSError, subprocess.TimeoutExpired) as error:
        return {"available": False, "error": str(error), "version": None}
    version_lines = (version_result.stdout + "\n" + version_result.stderr).strip().splitlines()
    version = version_lines[0].strip() if version_lines else None
    machines = machine_result.stdout + "\n" + machine_result.stderr
    esp32c3 = machine_result.returncode == 0 and any(
        line.split(maxsplit=1)[0] == "esp32c3" for line in machines.splitlines() if line.strip()
    )
    available = version_result.returncode == 0 and bool(version) and esp32c3
    return {
        "available": available,
        "error": None if available else "Installed QEMU does not advertise Espressif esp32c3",
        "version": version,
        "esp32c3_machine": esp32c3,
    }
