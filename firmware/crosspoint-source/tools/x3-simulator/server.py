#!/usr/bin/env python3
"""Local-only backend for the XTINCT X3 simulator.

The simulator deliberately has no X3 discovery, WebDAV, Bluetooth, or outbound
HTTP code.  Every browser session receives a private temporary copy of the
curated SD-card fixture.  The workspace and any physical device remain
read-only and unreachable from this process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import mimetypes
import os
import re
import secrets
import shutil
import stat
import struct
import tempfile
import threading
import webbrowser
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO, Sequence
from urllib.parse import parse_qs, unquote, urlsplit

from network_fixture import (
    CORPUS as NETWORK_CORPUS,
    READ_TOKEN as NETWORK_READ_TOKEN,
    SCENARIOS as NETWORK_SCENARIOS,
    NetworkFixtureStore,
    listed_scenarios,
    parse_query as parse_network_query,
    sync_page as network_sync_page,
)
from standalone_inputs import (
    HarnessError,
    UNSUPPORTED_PHYSICAL_COVERAGE,
    probe_qemu,
    validate_esp32c3_image,
    validate_full_flash_inputs,
)


SERVER_ROOT = Path(__file__).resolve().parent
WEB_ROOT = SERVER_ROOT / "web"
FIXTURE_SD_ROOT = SERVER_ROOT / "fixtures" / "sd-card"
DEVICE_FIXTURE_PATH = SERVER_ROOT / "fixtures" / "device.json"
DEMO_CONTRACT_PATH = SERVER_ROOT / "fixtures" / "x3-resource-budgets.demo.json"
RELEASE_PROFILE_PATH = SERVER_ROOT / "release-profile.json"
BUNDLED_BASELINE_RELATIVE = Path("firmware-baseline/crosspoint-v1.5.0/firmware.bin")
BUNDLED_BASELINE_PATH = SERVER_ROOT / BUNDLED_BASELINE_RELATIVE
BUNDLED_BASELINE_BYTES = 5544112
BUNDLED_BASELINE_SHA256 = "a7087155757bc63c1fcf60ae8d60a3760ce6d3406aaf7b9f23d0025244434f08"
LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 8763
SESSION_COOKIE = "X3SIM_SESSION"
SESSION_TOKEN_LENGTH = 32
COPY_CHUNK_BYTES = 64 * 1024
FIRMWARE_BUILD_SCAN_MAX_BYTES = 8 * 1024 * 1024
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
STRICT_BUILD_ID_PATTERN = re.compile(
    rb"XTINCT-X3-[0-9]+\.[0-9]+\.[0-9]+-[A-Za-z0-9][A-Za-z0-9._+-]{0,47}"
)
FALLBACK_BUILD_ID_PATTERN = re.compile(
    rb"XTINCT-X3-[A-Za-z0-9][A-Za-z0-9._+-]{3,63}"
)
XTINCT_BUILD_ID_PATTERN = re.compile(
    rb"BUILD-[0-9]+-[A-Za-z0-9][A-Za-z0-9._+-]{3,63}"
)


@dataclass(frozen=True)
class SimulatorConfig:
    """Resolved local inputs for one simulator process.

    Demo mode deliberately has no implicit dependency on the directory tree
    above this tool. Optional real inputs are accepted only when the operator
    selects them explicitly (or selects a project root with conventional local
    paths). Nothing in this record is a network address.
    """

    contract_path: Path
    project_root: Path | None = None
    firmware_path: Path | None = None
    sleep_path: Path | None = None
    build_dir: Path | None = None
    boot_app0: Path | None = None
    crosspoint_simulator_path: Path | None = None
    session_root: Path | None = None
    contract_source: str = "bundled-demo"
    firmware_source: str = "none"
    sleep_source: str = "synthetic-demo"
    session_root_source: str = "os-temporary"
    session_root_fallback: bool = True

    @property
    def mode(self) -> str:
        operator_firmware = (
            self.firmware_path
            if self.firmware_source in {"project", "explicit"}
            else None
        )
        return "configured" if any(
            (
                self.project_root,
                operator_firmware,
                self.sleep_path,
                self.build_dir,
                self.boot_app0,
                self.crosspoint_simulator_path,
            )
        ) else "demo"


def default_simulator_config() -> SimulatorConfig:
    """Return the portable modeled configuration with its read-only baseline."""

    session_root, session_source, fallback = _resolve_session_root(None)
    return SimulatorConfig(
        contract_path=DEMO_CONTRACT_PATH,
        firmware_path=BUNDLED_BASELINE_PATH,
        session_root=session_root,
        firmware_source="bundled-baseline",
        session_root_source=session_source,
        session_root_fallback=fallback,
    )


class RequestError(Exception):
    """An expected request failure that is safe to return to the browser."""

    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _entry_exists(path: Path) -> bool:
    """Check directory-entry existence without following a link or junction."""

    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _is_link_or_reparse(path: Path) -> bool:
    """Return True for POSIX links and Windows reparse points/junctions."""

    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT
    )


def _require_plain_file(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} is missing") from exc
    if _is_link_or_reparse(path) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"{label} must be a regular non-linked file")


def _require_plain_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} is missing") from exc
    if _is_link_or_reparse(path) or not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{label} must be a regular non-linked directory")


def _resolved_cli_path(value: Path, label: str, *, require_directory: bool) -> Path:
    """Resolve a user-selected local path without accepting links/junctions."""

    candidate = value.expanduser()
    if not candidate.is_absolute():
        candidate = SERVER_ROOT / candidate
    if require_directory:
        _require_plain_directory(candidate, label)
    else:
        _require_plain_file(candidate, label)
    return candidate.resolve(strict=True)


def _optional_project_file(project_root: Path, relative_paths: Sequence[Path]) -> Path | None:
    """Return the first conventional plain file, without recursive discovery."""

    for relative in relative_paths:
        candidate = project_root / relative
        if not _entry_exists(candidate):
            continue
        _require_plain_file(candidate, f"Project input {relative.as_posix()}")
        return candidate.resolve(strict=True)
    return None


def _resolve_session_root(explicit: Path | None) -> tuple[Path | None, str, bool]:
    """Choose a validated disposable-state parent without creating directories."""

    if explicit is not None:
        selected = _resolved_cli_path(
            explicit, "Configured session quarantine", require_directory=True
        )
        return selected, "explicit", False
    environment_value = os.environ.get("X3_LAB_QUARANTINE", "").strip()
    if environment_value:
        selected = _resolved_cli_path(
            Path(environment_value),
            "X3_LAB_QUARANTINE session quarantine",
            require_directory=True,
        )
        return selected, "environment", False
    if os.name == "nt":
        for candidate, source in (
            (Path(r"D:\quarantine"), "D-quarantine"),
            (Path(r"E:\quarantine"), "E-quarantine"),
        ):
            if not _entry_exists(candidate):
                continue
            _require_plain_directory(candidate, "Preferred session quarantine")
            return candidate.resolve(strict=True), source, False
    return None, "os-temporary", True


def _config_from_arguments(arguments: argparse.Namespace) -> SimulatorConfig:
    """Resolve CLI choices into a portable runtime configuration."""

    project_root: Path | None = None
    if arguments.project_root is not None:
        project_root = _resolved_cli_path(
            arguments.project_root, "Configured project root", require_directory=True
        )

    if arguments.resource_contract is not None:
        contract_path = _resolved_cli_path(
            arguments.resource_contract,
            "Configured X3 resource contract",
            require_directory=False,
        )
        contract_source = "explicit"
    else:
        project_contract = (
            _optional_project_file(
                project_root,
                (
                    Path("config/x3-resource-budgets.json"),
                    Path("firmware/crosspoint-source/config/x3-resource-budgets.json"),
                ),
            )
            if project_root is not None
            else None
        )
        contract_path = project_contract or DEMO_CONTRACT_PATH
        contract_source = "project" if project_contract else "bundled-demo"

    if arguments.firmware is not None:
        firmware_path = _resolved_cli_path(
            arguments.firmware, "Configured firmware image", require_directory=False
        )
        firmware_source = "explicit"
    else:
        project_firmware = (
            _optional_project_file(project_root, (Path("update.bin"),))
            if project_root is not None
            else None
        )
        firmware_path = project_firmware or BUNDLED_BASELINE_PATH
        firmware_source = "project" if project_firmware else "bundled-baseline"

    if arguments.sleep is not None:
        sleep_path = _resolved_cli_path(
            arguments.sleep, "Configured sleep image", require_directory=False
        )
        sleep_source = "explicit"
    else:
        sleep_path = (
            _optional_project_file(project_root, (Path("sleep.bmp"),))
            if project_root is not None
            else None
        )
        sleep_source = "project" if sleep_path else "synthetic-demo"

    build_dir = (
        _resolved_cli_path(
            arguments.build_dir, "Configured retained build directory", require_directory=True
        )
        if arguments.build_dir is not None
        else None
    )
    boot_app0 = (
        _resolved_cli_path(
            arguments.boot_app0, "Configured boot_app0.bin", require_directory=False
        )
        if arguments.boot_app0 is not None
        else None
    )
    crosspoint_simulator_path = (
        _resolved_cli_path_any(
            arguments.crosspoint_simulator, "Configured official CrossPoint Simulator"
        )
        if arguments.crosspoint_simulator is not None
        else None
    )
    session_root, session_root_source, session_root_fallback = _resolve_session_root(
        arguments.session_root
    )
    return SimulatorConfig(
        contract_path=contract_path,
        project_root=project_root,
        firmware_path=firmware_path,
        sleep_path=sleep_path,
        build_dir=build_dir,
        boot_app0=boot_app0,
        crosspoint_simulator_path=crosspoint_simulator_path,
        session_root=session_root,
        contract_source=contract_source,
        firmware_source=firmware_source,
        sleep_source=sleep_source,
        session_root_source=session_root_source,
        session_root_fallback=session_root_fallback,
    )


def _resolved_cli_path_any(value: Path, label: str) -> Path:
    """Resolve an explicit regular file or directory, never a link/junction."""

    candidate = value.expanduser()
    if not candidate.is_absolute():
        candidate = SERVER_ROOT / candidate
    try:
        info = candidate.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} is missing") from exc
    if _is_link_or_reparse(candidate) or not (
        stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)
    ):
        raise RuntimeError(f"{label} must be a regular non-linked file or directory")
    return candidate.resolve(strict=True)


def _copy_plain_tree(source: Path, destination: Path) -> None:
    """Copy a fixture tree without ever following links or special files."""

    _require_plain_directory(source, "SD-card fixture directory")
    destination.mkdir(parents=True, exist_ok=True)
    with os.scandir(source) as entries:
        for entry in sorted(entries, key=lambda item: item.name.casefold()):
            source_path = Path(entry.path)
            target_path = destination / entry.name
            info = source_path.lstat()
            if _is_link_or_reparse(source_path):
                raise RuntimeError("SD-card fixtures may not contain links or reparse points")
            if stat.S_ISDIR(info.st_mode):
                _copy_plain_tree(source_path, target_path)
            elif stat.S_ISREG(info.st_mode):
                target_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source_path, target_path)
            else:
                raise RuntimeError("SD-card fixtures may contain only regular files and directories")


def _validate_virtual_sd_path(value: str) -> tuple[str, ...]:
    """Validate an X3-style /path while rejecting host absolute paths."""

    if not value or "\x00" in value or "\\" in value:
        raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid SD-card path")
    # A single leading slash is the virtual SD root, not a host filesystem root.
    if not value.startswith("/") or value.startswith("//"):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Use a virtual SD path such as /sleep.bmp")
    relative = value[1:]
    parts = relative.split("/")
    if not relative or any(part in {"", ".", ".."} for part in parts):
        raise RequestError(HTTPStatus.BAD_REQUEST, "SD-card paths cannot be empty or traverse directories")
    if any(":" in part for part in parts):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Host absolute paths are not allowed")
    return tuple(parts)


def _safe_existing_path(root: Path, parts: tuple[str, ...], *, require_file: bool) -> Path:
    """Resolve an existing path below root and reject links in every component."""

    _require_plain_directory(root, "Simulator SD root")
    current = root
    for part in parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError as exc:
            raise RequestError(HTTPStatus.NOT_FOUND, "SD-card entry not found") from exc
        if _is_link_or_reparse(current):
            raise RequestError(HTTPStatus.BAD_REQUEST, "Linked or reparse-point entries are not allowed")
        if current != root / Path(*parts) and not stat.S_ISDIR(info.st_mode):
            raise RequestError(HTTPStatus.NOT_FOUND, "SD-card entry not found")

    root_resolved = root.resolve(strict=True)
    current_resolved = current.resolve(strict=True)
    try:
        common = Path(os.path.commonpath((root_resolved, current_resolved)))
    except ValueError as exc:
        raise RequestError(HTTPStatus.BAD_REQUEST, "SD-card path escaped its virtual root") from exc
    if common != root_resolved:
        raise RequestError(HTTPStatus.BAD_REQUEST, "SD-card path escaped its virtual root")
    if require_file and not current_resolved.is_file():
        raise RequestError(HTTPStatus.BAD_REQUEST, "Requested SD-card entry is not a file")
    return current_resolved


def _safe_web_file(request_path: str) -> Path:
    decoded = unquote(request_path)
    if "\x00" in decoded or "\\" in decoded or decoded.startswith("//"):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid frontend path")
    if not decoded.startswith("/"):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid frontend path")
    parts = decoded[1:].split("/") if decoded != "/" else ["index.html"]
    if decoded.endswith("/") and decoded != "/":
        parts.append("index.html")
    if any(part in {"", ".", ".."} or ":" in part for part in parts):
        raise RequestError(HTTPStatus.BAD_REQUEST, "Frontend paths cannot traverse directories")
    return _safe_existing_path(WEB_ROOT, tuple(parts), require_file=True)


def _read_release_profile(path: Path = RELEASE_PROFILE_PATH) -> dict[str, object]:
    """Validate and return only the publication-safe release fields."""

    _require_plain_file(path, "Simulator release profile")
    try:
        with path.open("r", encoding="utf-8") as source:
            profile = json.load(source)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Simulator release profile is invalid: {error}") from error

    if not isinstance(profile, dict) or set(profile) != {
        "schema",
        "product",
        "version",
        "target",
        "firmware",
    }:
        raise RuntimeError("Simulator release profile has an unsupported top-level contract")
    if profile.get("schema") != "x3-preview-release-profile/1":
        raise RuntimeError("Simulator release profile has an unsupported schema")
    if profile.get("product") != "X3 Preview & QA Lab for Windows":
        raise RuntimeError("Simulator release profile has an unexpected product")

    version = profile.get("version")
    if not isinstance(version, str) or not re.fullmatch(
        r"0\.[0-9]+\.[0-9]+-alpha\.[1-9][0-9]*", version
    ):
        raise RuntimeError("Simulator release profile has an invalid alpha version")

    target = profile.get("target")
    if target != {"model": "Xteink X3", "mcu": "ESP32-C3"}:
        raise RuntimeError("Simulator release profile has an unsupported target")

    firmware_policy = profile.get("firmware")
    expected_firmware_policy = {
        "bundled": True,
        "runtime_policy": "bundled-official-baseline-read-only",
        "preview_mode": "synthetic-modeled-demo",
        "device_access": "none",
        "baseline": {
            "project": "CrossPoint Reader",
            "version": "v1.5.0",
            "channel": "stable",
            "asset": BUNDLED_BASELINE_RELATIVE.as_posix(),
            "byte_count": BUNDLED_BASELINE_BYTES,
            "sha256": BUNDLED_BASELINE_SHA256,
            "release_url": "https://github.com/crosspoint-reader/crosspoint-reader/releases/tag/v1.5.0",
            "download_url": "https://github.com/crosspoint-reader/crosspoint-reader/releases/download/v1.5.0/firmware.bin",
            "license": "MIT",
            "execution": "inspected-not-executed",
        },
    }
    if (
        firmware_policy != expected_firmware_policy
        or not isinstance(firmware_policy, dict)
        or firmware_policy.get("bundled") is not True
    ):
        raise RuntimeError("Simulator release profile has an unsupported firmware policy")

    # Reconstruct the response instead of returning the parsed object. This
    # prevents future metadata additions from accidentally becoming public API.
    return {
        "product": "X3 Preview & QA Lab for Windows",
        "version": version,
        "target": {"model": "Xteink X3", "mcu": "ESP32-C3"},
        "firmware": dict(expected_firmware_policy),
    }


def _plain_file_sha256(path: Path, label: str) -> str:
    """Hash one validated regular file without exposing its host path."""

    _require_plain_file(path, label)
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(COPY_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _read_contract(config: SimulatorConfig | None = None) -> dict[str, object]:
    runtime = config or default_simulator_config()
    _require_plain_file(runtime.contract_path, "X3 resource contract")
    with runtime.contract_path.open("r", encoding="utf-8") as source:
        contract = json.load(source)
    if not isinstance(contract, dict) or contract.get("schema") != 1:
        raise RuntimeError("X3 resource contract must be a supported schema-1 JSON object")
    payload = dict(contract)
    payload["simulator"] = {
        "api_schema": 1,
        "mode": runtime.mode,
        "local_inputs": "read-only",
        "sd_storage": "per-session temporary copy",
        "device_network": "disabled",
        "bind_host": LOOPBACK_HOST,
        "resource_contract": runtime.contract_source,
        "firmware": runtime.firmware_source,
        "sleep_screen": runtime.sleep_source,
        "session_storage": runtime.session_root_source,
        "session_storage_fallback": runtime.session_root_fallback,
    }
    return payload


def _read_device_fixture() -> dict[str, object]:
    _require_plain_file(DEVICE_FIXTURE_PATH, "Simulator device fixture")
    with DEVICE_FIXTURE_PATH.open("r", encoding="utf-8") as source:
        fixture = json.load(source)
    if not isinstance(fixture, dict) or fixture.get("schema") != "xtinct-x3-simulator/1":
        raise RuntimeError("Simulator device fixture has the wrong schema")
    return fixture


def _extract_firmware_build_id(scanned_bytes: bytes) -> str | None:
    """Extract a bounded ASCII build ID, preferring the release-ID contract."""

    for pattern in (STRICT_BUILD_ID_PATTERN, FALLBACK_BUILD_ID_PATTERN):
        matches = [match.group(0).decode("ascii") for match in pattern.finditer(scanned_bytes)]
        if matches:
            ready_matches = [candidate for candidate in matches if "READY" in candidate.upper()]
            return ready_matches[-1] if ready_matches else matches[-1]
    return None


def _extract_xtinct_build_id(scanned_bytes: bytes) -> str | None:
    matches = [match.group(0).decode("ascii") for match in XTINCT_BUILD_ID_PATTERN.finditer(scanned_bytes)]
    return matches[-1] if matches else None


def _firmware_metadata(
    path: Path | None = None,
    contract_path: Path | None = None,
    *,
    source_kind: str | None = None,
    contract_source: str | None = None,
) -> dict[str, object]:
    """Inspect one selected image, or report a safe modeled-only demo state."""

    selected_contract = contract_path or DEMO_CONTRACT_PATH
    if contract_source is None:
        resolved_contract_source = (
            "bundled-demo"
            if selected_contract == DEMO_CONTRACT_PATH
            else "explicit"
        )
    else:
        resolved_contract_source = contract_source
    if resolved_contract_source not in {"bundled-demo", "project", "explicit"}:
        raise RuntimeError("Configured firmware contract source is invalid")

    if path is None:
        resolved_source_kind = "none"
    elif source_kind in {None, "none"}:
        resolved_source_kind = "explicit"
    else:
        resolved_source_kind = source_kind
    if resolved_source_kind not in {"none", "project", "explicit", "bundled-baseline"}:
        raise RuntimeError("Configured firmware source kind is invalid")

    contract_config = SimulatorConfig(
        contract_path=selected_contract,
        firmware_path=path,
        contract_source=resolved_contract_source,
        firmware_source=resolved_source_kind,
    )
    contract = _read_contract(contract_config)
    contract_digest = _plain_file_sha256(selected_contract, "X3 resource contract")
    provenance = {
        "source_kind": resolved_source_kind,
        "contract_source": resolved_contract_source,
        "contract_sha256": contract_digest,
        "package_firmware_bundled": True,
        "bundled_baseline_available": _entry_exists(BUNDLED_BASELINE_PATH),
        "baseline_version": "v1.5.0",
        "baseline_channel": "stable",
        "baseline_release_url": "https://github.com/crosspoint-reader/crosspoint-reader/releases/tag/v1.5.0",
    }

    if resolved_source_kind == "bundled-baseline":
        if path is None or path.resolve() != BUNDLED_BASELINE_PATH.resolve():
            raise RuntimeError("Bundled firmware path differs from the release contract")

    if path is None or not _entry_exists(path):
        return {
            "path": BUNDLED_BASELINE_RELATIVE.as_posix() if resolved_source_kind == "bundled-baseline" else "/update.bin",
            "exists": False,
            "availability": "unavailable",
            "fidelity": "modelled",
            "reason": (
                "The bundled CrossPoint baseline is missing; UI behavior still uses synthetic fixtures."
                if resolved_source_kind == "bundled-baseline"
                else "No local firmware image is configured; UI behavior uses synthetic fixtures."
            ),
            "inspection": "not-run",
            "execution": "disabled",
            "provenance_status": (
                "synthetic-only"
                if resolved_source_kind == "none"
                else "configured-image-unavailable"
            ),
            **provenance,
        }
    _require_plain_file(path, "Configured firmware image")
    info = path.stat()
    digest = hashlib.sha256()
    scanned = bytearray()
    magic: int | None = None
    with path.open("rb") as firmware:
        while chunk := firmware.read(COPY_CHUNK_BYTES):
            if magic is None and chunk:
                magic = chunk[0]
            digest.update(chunk)
            if len(scanned) < FIRMWARE_BUILD_SCAN_MAX_BYTES:
                remaining = FIRMWARE_BUILD_SCAN_MAX_BYTES - len(scanned)
                scanned.extend(chunk[:remaining])
    image_sha256 = digest.hexdigest()
    if resolved_source_kind == "bundled-baseline":
        if info.st_size != BUNDLED_BASELINE_BYTES:
            raise RuntimeError("Bundled CrossPoint baseline byte count differs from the release contract")
        if image_sha256 != BUNDLED_BASELINE_SHA256:
            raise RuntimeError("Bundled CrossPoint baseline SHA-256 differs from the release contract")

    linked_image = contract.get("linked_image", {})
    if not isinstance(linked_image, dict):
        raise RuntimeError("X3 linked-image contract is invalid")
    ota_max = int(linked_image["firmware_bin_max_bytes"])
    required_headroom = int(linked_image["firmware_bin_min_headroom_bytes"])
    warning_headroom = int(linked_image["firmware_bin_warn_below_headroom_bytes"])
    headroom = ota_max - info.st_size
    if headroom < required_headroom:
        budget_status = "fail"
    elif headroom < warning_headroom:
        budget_status = "warning"
    else:
        budget_status = "pass"

    try:
        image_validation = validate_esp32c3_image(path, "Configured firmware image")
        image_valid = True
        image_error = None
    except HarnessError as error:
        image_validation = {}
        image_valid = False
        image_error = str(error)

    return {
        "path": BUNDLED_BASELINE_RELATIVE.as_posix() if resolved_source_kind == "bundled-baseline" else "/update.bin",
        "exists": True,
        "availability": "available",
        "fidelity": "inspected-not-executed",
        "byte_count": info.st_size,
        "sha256": image_sha256,
        "esp_image_magic": f"0x{magic:02X}" if magic is not None else None,
        "esp_image_magic_valid": magic == 0xE9,
        "esp32c3_image_valid": image_valid,
        "esp32c3_image_error": image_error,
        "esp32c3_chip_id": image_validation.get("chip_id"),
        "esp32c3_segments": image_validation.get("segments"),
        "embedded_release_id": _extract_firmware_build_id(bytes(scanned)),
        "embedded_build_id": _extract_xtinct_build_id(bytes(scanned)) or _extract_firmware_build_id(bytes(scanned)),
        "build_id_scan_bytes": len(scanned),
        "build_id_scan_limit_bytes": FIRMWARE_BUILD_SCAN_MAX_BYTES,
        "ota_slot_bytes": ota_max,
        "ota_headroom_bytes": headroom,
        "minimum_required_headroom_bytes": required_headroom,
        "warning_below_headroom_bytes": warning_headroom,
        "budget_status": budget_status,
        "within_ota_budget": headroom >= required_headroom,
        "modified_utc": datetime.fromtimestamp(info.st_mtime, tz=timezone.utc).isoformat(),
        "inspection": "read-only",
        "execution": "disabled",
        "provenance_status": (
            "bundled-stable-baseline"
            if resolved_source_kind == "bundled-baseline"
            else {
                "bundled-demo": "local-image-demo-contract",
                "project": "local-image-project-contract",
                "explicit": "local-image-explicit-contract",
            }[resolved_contract_source]
        ),
        **provenance,
    }


def _demo_sleep_bmp() -> bytes:
    """Build a deterministic native-size four-gray BMP for portable demo mode.

    This is explicitly synthetic simulator art, not a device delivery artifact.
    """

    width = 528
    height = 792
    row_bytes = width // 2
    pixel_offset = 70
    file_bytes = pixel_offset + row_bytes * height
    header = bytearray(pixel_offset)
    struct.pack_into("<2sIHHI", header, 0, b"BM", file_bytes, 0, 0, pixel_offset)
    struct.pack_into(
        "<IiiHHIIiiII",
        header,
        14,
        40,
        width,
        height,
        1,
        4,
        0,
        row_bytes * height,
        2835,
        2835,
        4,
        4,
    )
    for index, luminance in enumerate((0, 85, 170, 255)):
        struct.pack_into("<BBBB", header, 54 + index * 4, luminance, luminance, luminance, 0)

    pixels = bytearray(row_bytes * height)
    for storage_y in range(height):
        y = height - 1 - storage_y
        row_offset = storage_y * row_bytes
        for x_pair in range(row_bytes):
            x0 = x_pair * 2

            def tone(x: int) -> int:
                base = min(3, (x * 4) // width)
                # A broad diagonal X motif keeps the demo recognisable without
                # pretending to be a user-supplied or checker-approved image.
                diagonal = abs(x * height - y * width) < width * 18
                counter = abs((width - 1 - x) * height - y * width) < width * 18
                if diagonal or counter:
                    return 0 if base >= 2 else 3
                return base

            pixels[row_offset + x_pair] = (tone(x0) << 4) | tone(x0 + 1)
    return bytes(header + pixels)


@dataclass(frozen=True)
class SimulatorSession:
    token: str
    revision: str
    sd_root: Path


class SessionStore:
    """Owns temporary, disposable SD-card clones for browser sessions."""

    def __init__(self, config: SimulatorConfig | None = None) -> None:
        self.config = config or default_simulator_config()
        temporary_parent = (
            str(self.config.session_root) if self.config.session_root is not None else None
        )
        self._temporary_root = tempfile.TemporaryDirectory(
            prefix="xtinct-x3-simulator-",
            dir=temporary_parent,
        )
        self._root = Path(self._temporary_root.name)
        self._sessions: dict[str, SimulatorSession] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _valid_token(token: str | None) -> bool:
        return bool(
            token
            and len(token) == SESSION_TOKEN_LENGTH
            and all(character in "0123456789abcdef" for character in token)
        )

    def _new_token(self) -> str:
        token = secrets.token_hex(SESSION_TOKEN_LENGTH // 2)
        while token in self._sessions:
            token = secrets.token_hex(SESSION_TOKEN_LENGTH // 2)
        return token

    def _seed(self, token: str) -> SimulatorSession:
        revision = secrets.token_hex(8)
        revision_root = self._root / token / revision
        sd_root = revision_root / "sd"
        sd_root.mkdir(parents=True, exist_ok=False)

        if _entry_exists(FIXTURE_SD_ROOT):
            _copy_plain_tree(FIXTURE_SD_ROOT, sd_root)
        if self.config.sleep_path is not None:
            _require_plain_file(self.config.sleep_path, "Configured sleep image")
            shutil.copyfile(self.config.sleep_path, sd_root / "sleep.bmp")
        else:
            (sd_root / "sleep.bmp").write_bytes(_demo_sleep_bmp())
        return SimulatorSession(token=token, revision=revision, sd_root=sd_root)

    def get_or_create(self, requested_token: str | None) -> tuple[SimulatorSession, bool]:
        with self._lock:
            if self._valid_token(requested_token) and requested_token in self._sessions:
                return self._sessions[requested_token], False
            token = self._new_token()
            session = self._seed(token)
            self._sessions[token] = session
            return session, True

    def reset(self, requested_token: str | None) -> tuple[SimulatorSession, bool]:
        """Create a fresh revision; old temporary copies survive only until shutdown."""

        with self._lock:
            known = self._valid_token(requested_token) and requested_token in self._sessions
            token = requested_token if known else self._new_token()
            assert token is not None
            session = self._seed(token)
            self._sessions[token] = session
            return session, not known

    def close(self) -> None:
        self._temporary_root.cleanup()


def _tree_entries(sd_root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []

    def visit(directory: Path) -> None:
        with os.scandir(directory) as children:
            for child in sorted(children, key=lambda item: item.name.casefold()):
                child_path = Path(child.path)
                info = child_path.lstat()
                if _is_link_or_reparse(child_path):
                    raise RequestError(
                        HTTPStatus.BAD_REQUEST,
                        "Linked or reparse-point entries are not allowed in the simulated SD card",
                    )
                relative = child_path.relative_to(sd_root).as_posix()
                virtual_path = f"/{relative}"
                modified = datetime.fromtimestamp(info.st_mtime, tz=timezone.utc).isoformat()
                if stat.S_ISDIR(info.st_mode):
                    entries.append(
                        {
                            "path": virtual_path,
                            "name": child.name,
                            "type": "directory",
                            "modified_utc": modified,
                        }
                    )
                    visit(child_path)
                elif stat.S_ISREG(info.st_mode):
                    entries.append(
                        {
                            "path": virtual_path,
                            "name": child.name,
                            "type": "file",
                            "size": info.st_size,
                            "modified_utc": modified,
                        }
                    )
                else:
                    raise RequestError(
                        HTTPStatus.BAD_REQUEST,
                        "Special files are not allowed in the simulated SD card",
                    )

    _require_plain_directory(sd_root, "Simulator SD root")
    visit(sd_root)
    return entries


def _qemu_status(config: SimulatorConfig) -> dict[str, object]:
    """Report optional offline QEMU readiness using only configured inputs."""

    qemu = probe_qemu()
    if config.firmware_path is None:
        canonical: dict[str, object] = {
            "available": False,
            "fidelity": "modelled",
            "reason": "No firmware image is configured",
        }
    else:
        metadata = _firmware_metadata(
            config.firmware_path,
            config.contract_path,
            source_kind=config.firmware_source,
            contract_source=config.contract_source,
        )
        canonical = {
            "available": bool(metadata.get("exists")),
            "bytes": metadata.get("byte_count"),
            "sha256": metadata.get("sha256"),
            "esp32c3_image_valid": metadata.get("esp32c3_image_valid"),
            "error": metadata.get("esp32c3_image_error"),
        }

    input_status: dict[str, object] = {
        "ready": False,
        "reason": "Configure --firmware, --build-dir and --boot-app0 from one retained build",
    }
    selected = (config.build_dir, config.boot_app0)
    if any(selected):
        if not all(selected):
            input_status["reason"] = "Both --build-dir and --boot-app0 are required"
        elif config.firmware_path is None:
            input_status["reason"] = "A matching --firmware image is also required"
        else:
            assert config.build_dir is not None and config.boot_app0 is not None
            try:
                input_status = validate_full_flash_inputs(
                    config.build_dir,
                    config.boot_app0,
                    config.firmware_path,
                    config.contract_path,
                )
            except HarnessError as error:
                input_status = {"ready": False, "reason": str(error)}
    return {
        "schema": 1,
        "tier": 3,
        "canonical_update": canonical,
        "full_flash_inputs": input_status,
        "qemu": qemu,
        "ready_to_execute": bool(qemu.get("available") and input_status.get("ready")),
        "execution": "not-started",
        "network": "disabled",
        "unsupported_physical_coverage": list(UNSUPPORTED_PHYSICAL_COVERAGE),
    }


def _official_simulator_candidates(config: SimulatorConfig) -> list[tuple[Path, str]]:
    if config.crosspoint_simulator_path is not None:
        return [(config.crosspoint_simulator_path, "explicit")]
    sibling_root = SERVER_ROOT.parent
    return [
        (sibling_root / "crosspoint-simulator", "local-sibling"),
        (sibling_root / "crosspoint-simulator.exe", "local-sibling"),
    ]


def _official_crosspoint_simulator_status(config: SimulatorConfig) -> dict[str, object]:
    """Inspect a local official simulator checkout/executable without running it."""

    base: dict[str, object] = {
        "schema": 1,
        "provider": "crosspoint-reader/crosspoint-simulator",
        "role": "optional-native-renderer",
        "relationship": "complements-preview-lab",
        "available": False,
        "auto_launch": False,
        "launch_state": "not-started",
        "download_attempted": False,
        "network_contacted": False,
        "capabilities": {
            "native_firmware_build": False,
            "sdl_eink_rendering": False,
            "scripted_input": False,
            "screenshot_capture": False,
            "x3_profile": False,
        },
    }
    for candidate, detection in _official_simulator_candidates(config):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            return {**base, "detection": detection, "error": f"Could not inspect local candidate: {error}"}
        if _is_link_or_reparse(candidate):
            return {**base, "detection": detection, "error": "Local candidate is a link or reparse point"}
        if stat.S_ISREG(info.st_mode):
            return {
                **base,
                "available": True,
                "detection": detection,
                "kind": "executable",
                "name": candidate.name,
                "capabilities": {
                    "native_firmware_build": False,
                    "sdl_eink_rendering": True,
                    "scripted_input": True,
                    "screenshot_capture": True,
                    "x3_profile": True,
                },
            }
        if not stat.S_ISDIR(info.st_mode):
            return {**base, "detection": detection, "error": "Local candidate is not a regular file or directory"}

        library_path = candidate / "library.json"
        source_path = candidate / "src"
        readme_path = candidate / "README.md"
        try:
            _require_plain_file(library_path, "Official simulator library.json")
            _require_plain_directory(source_path, "Official simulator source directory")
            _require_plain_file(readme_path, "Official simulator README")
            if readme_path.stat().st_size > 512 * 1024:
                raise RuntimeError("Official simulator README is unexpectedly large")
            library = json.loads(library_path.read_text(encoding="utf-8"))
            readme = readme_path.read_text(encoding="utf-8", errors="strict")
        except (OSError, RuntimeError, UnicodeError, json.JSONDecodeError) as error:
            return {**base, "detection": detection, "error": f"Local checkout markers are invalid: {error}"}
        library_name = library.get("name") if isinstance(library, dict) else None
        if not isinstance(library_name, str) or "simulator" not in library_name.casefold():
            return {**base, "detection": detection, "error": "Local checkout does not identify a simulator library"}
        return {
            **base,
            "available": True,
            "detection": detection,
            "kind": "source-checkout",
            "name": candidate.name,
            "capabilities": {
                "native_firmware_build": True,
                "sdl_eink_rendering": "SDL" in readme,
                "scripted_input": "CROSSPOINT_SIM_INPUT_SCRIPT" in readme,
                "screenshot_capture": "CROSSPOINT_SIM_SCREENSHOTS" in readme,
                "x3_profile": "SIMULATOR_DEVICE_X3" in readme
                or (candidate / "sample-platformio-linux-wsl.ini").is_file(),
            },
        }
    return {
        **base,
        "detection": "none",
        "reason": "No explicit or local sibling official CrossPoint Simulator was found",
    }


class X3SimulatorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], session_store: SessionStore) -> None:
        if address[0] != LOOPBACK_HOST:
            raise ValueError("The X3 simulator may bind only to 127.0.0.1")
        self.session_store = session_store
        self.config = session_store.config
        self.network_store = NetworkFixtureStore()
        super().__init__(address, X3SimulatorRequestHandler)


class X3SimulatorRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "XTINCT-X3-Simulator/1"

    @property
    def simulator_server(self) -> X3SimulatorHTTPServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, message_format: str, *args: object) -> None:
        print(f"[{self.log_date_time_string()}] {message_format % args}")

    def _requested_session_token(self) -> str | None:
        raw_cookie = self.headers.get("Cookie")
        if not raw_cookie:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw_cookie)
        except Exception:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    @staticmethod
    def _session_cookie(session: SimulatorSession) -> str:
        return f"{SESSION_COOKIE}={session.token}; Path=/; HttpOnly; SameSite=Strict"

    def _common_headers(self, *, api: bool) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store" if api else "no-cache")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; "
            "style-src 'self'; script-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )

    def _send_bytes(
        self,
        status: HTTPStatus,
        body: bytes,
        content_type: str,
        *,
        api: bool,
        cookie: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self._common_headers(api=api)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _send_json(
        self,
        status: HTTPStatus,
        payload: object,
        *,
        cookie: str | None = None,
    ) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._send_bytes(
            status,
            body,
            "application/json; charset=utf-8",
            api=True,
            cookie=cookie,
        )

    def _send_error(self, error: RequestError) -> None:
        self._send_json(error.status, {"error": error.message, "status": int(error.status)})

    def _send_file(self, path: Path, *, api: bool, cookie: str | None = None) -> None:
        _require_plain_file(path, "Requested file")
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self._common_headers(api=api)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(path.stat().st_size))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command == "HEAD":
            return
        with path.open("rb") as source:
            self._stream(source)

    def _stream(self, source: BinaryIO) -> None:
        while chunk := source.read(COPY_CHUNK_BYTES):
            self.wfile.write(chunk)

    def _handle_health(self) -> None:
        config = self.simulator_server.config
        self._send_json(
            HTTPStatus.OK,
            {
                "status": "ok",
                "service": "xtinct-x3-simulator",
                "api_schema": 1,
                "bind_host": LOOPBACK_HOST,
                "device_network": "disabled",
                "mode": config.mode,
                "firmware": config.firmware_source,
                "sleep_screen": config.sleep_source,
                "session_storage": config.session_root_source,
                "session_storage_fallback": config.session_root_fallback,
            },
        )

    def _handle_contract(self) -> None:
        self._send_json(HTTPStatus.OK, _read_contract(self.simulator_server.config))

    def _handle_release(self) -> None:
        self._send_json(HTTPStatus.OK, _read_release_profile())

    def _handle_fixture(self) -> None:
        self._send_json(HTTPStatus.OK, _read_device_fixture())

    def _handle_firmware(self) -> None:
        config = self.simulator_server.config
        self._send_json(
            HTTPStatus.OK,
            _firmware_metadata(
                config.firmware_path,
                config.contract_path,
                source_kind=config.firmware_source,
                contract_source=config.contract_source,
            ),
        )

    def _handle_qemu(self) -> None:
        self._send_json(HTTPStatus.OK, _qemu_status(self.simulator_server.config))

    def _handle_official_simulator(self) -> None:
        self._send_json(
            HTTPStatus.OK,
            _official_crosspoint_simulator_status(self.simulator_server.config),
        )

    def _handle_tree(self) -> None:
        session, created = self.simulator_server.session_store.get_or_create(
            self._requested_session_token()
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "root": "/",
                "session_revision": session.revision,
                "entries": _tree_entries(session.sd_root),
            },
            cookie=self._session_cookie(session) if created else None,
        )

    def _handle_sd_file(self, query: str) -> None:
        parameters = parse_qs(query, keep_blank_values=True)
        values = parameters.get("path", [])
        if len(values) != 1:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Exactly one SD-card path is required")
        parts = _validate_virtual_sd_path(values[0])
        session, created = self.simulator_server.session_store.get_or_create(
            self._requested_session_token()
        )
        file_path = _safe_existing_path(session.sd_root, parts, require_file=True)
        self._send_file(
            file_path,
            api=True,
            cookie=self._session_cookie(session) if created else None,
        )

    def _handle_reset(self) -> None:
        content_length = self.headers.get("Content-Length", "0")
        try:
            body_size = int(content_length)
        except ValueError as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid request body length") from exc
        if body_size < 0 or body_size > 4096:
            raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Reset request body is too large")
        if body_size:
            self.rfile.read(body_size)
        session, new_cookie = self.simulator_server.session_store.reset(
            self._requested_session_token()
        )
        self.simulator_server.network_store.reset(session.token)
        self._send_json(
            HTTPStatus.OK,
            {
                "status": "reset",
                "root": "/",
                "session_revision": session.revision,
                "entries": _tree_entries(session.sd_root),
            },
            cookie=self._session_cookie(session) if new_cookie else None,
        )

    def _network_session(self) -> tuple[SimulatorSession, str | None]:
        session, created = self.simulator_server.session_store.get_or_create(
            self._requested_session_token()
        )
        return session, self._session_cookie(session) if created else None

    def _require_mock_authorization(self) -> None:
        if self.headers.get("Authorization") != f"Bearer {NETWORK_READ_TOKEN}":
            raise RequestError(HTTPStatus.UNAUTHORIZED, "Simulator read token is required")

    def _read_json_body(self, maximum_bytes: int) -> object:
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise RequestError(HTTPStatus.LENGTH_REQUIRED, "Content-Length is required")
        try:
            body_size = int(raw_length)
        except ValueError as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Invalid request body length") from exc
        if body_size <= 0 or body_size > maximum_bytes:
            raise RequestError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body is outside the simulator contract")
        try:
            return json.loads(self.rfile.read(body_size))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Request body must be valid UTF-8 JSON") from exc

    def _handle_network_scenarios(self) -> None:
        self._send_json(HTTPStatus.OK, listed_scenarios())

    def _handle_network_status(self) -> None:
        session, cookie = self._network_session()
        self._send_json(
            HTTPStatus.OK,
            self.simulator_server.network_store.snapshot(session.token),
            cookie=cookie,
        )

    def _handle_network_scenario(self) -> None:
        document = self._read_json_body(1024)
        if not isinstance(document, dict) or set(document) != {"scenario"}:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Scenario request must contain only scenario")
        scenario = document.get("scenario")
        if not isinstance(scenario, str) or scenario not in NETWORK_SCENARIOS:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Unknown network scenario")
        session, cookie = self._network_session()
        self.simulator_server.network_store.select(session.token, scenario)
        self._send_json(
            HTTPStatus.OK,
            self.simulator_server.network_store.snapshot(session.token),
            cookie=cookie,
        )

    def _mock_context(self, method: str, path: str, detail: str = "") -> tuple[SimulatorSession, str, str | None]:
        self._require_mock_authorization()
        session, cookie = self._network_session()
        state = self.simulator_server.network_store.record(session.token, method, path, detail)
        return session, state.scenario, cookie

    def _handle_mock_manifest(self) -> None:
        session, scenario, cookie = self._mock_context("GET", "/v1/manifest.json")
        del session
        if scenario == "http-503":
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "simulated service failure"}, cookie=cookie)
            return
        if scenario == "malformed-payload":
            self._send_json(
                HTTPStatus.OK,
                {"schema": 99, "etag": NETWORK_CORPUS.etag, "cards": "not-an-array"},
                cookie=cookie,
            )
            return
        if self.headers.get("If-None-Match") == NETWORK_CORPUS.etag:
            self._send_bytes(
                HTTPStatus.NOT_MODIFIED,
                b"",
                "application/json; charset=utf-8",
                api=True,
                cookie=cookie,
                headers={"ETag": NETWORK_CORPUS.etag},
            )
            return
        self._send_bytes(
            HTTPStatus.OK,
            NETWORK_CORPUS.manifest_body,
            "application/json; charset=utf-8",
            api=True,
            cookie=cookie,
            headers={"ETag": NETWORK_CORPUS.etag},
        )

    def _handle_mock_card(self, path: str, query: str) -> None:
        prefix = "/mock/v1/cards/"
        suffix = ".json"
        if not path.startswith(prefix) or not path.endswith(suffix):
            raise RequestError(HTTPStatus.NOT_FOUND, "Card fixture not found")
        task_id = path[len(prefix) : -len(suffix)]
        parameters = parse_network_query(query)
        revision = parameters.get("revision", "")
        expected = next(
            (entry for entry in NETWORK_CORPUS.manifest["cards"] if entry["id"] == task_id),
            None,
        )
        session, scenario, cookie = self._mock_context("GET", f"/v1/cards/{task_id}.json", revision)
        del session, scenario
        if expected is None or set(parameters) != {"revision"} or revision != expected["revision"]:
            raise RequestError(HTTPStatus.NOT_FOUND, "Pinned card revision not found")
        body = NETWORK_CORPUS.cards[task_id]
        self._send_bytes(
            HTTPStatus.OK,
            body,
            "application/json; charset=utf-8",
            api=True,
            cookie=cookie,
        )

    def _handle_mock_report(self, path: str) -> None:
        prefix = "/mock/v1/reports/"
        relative = path[len(prefix) :] if path.startswith(prefix) else ""
        parts = relative.split("/")
        if len(parts) != 2 or not parts[1].endswith(".txt"):
            raise RequestError(HTTPStatus.NOT_FOUND, "Report fixture not found")
        task_id = parts[0]
        revision = parts[1][:-4]
        session, scenario, cookie = self._mock_context("GET", f"/v1/reports/{task_id}/{revision}.txt")
        body = NETWORK_CORPUS.reports.get((task_id, revision))
        if body is None:
            raise RequestError(HTTPStatus.NOT_FOUND, "Report fixture not found")
        if scenario == "report-short-once" and self.simulator_server.network_store.consume_failure_once(
            session.token, "report-short"
        ):
            body = body[:-1]
        self._send_bytes(
            HTTPStatus.OK,
            body,
            "text/plain; charset=utf-8",
            api=True,
            cookie=cookie,
        )

    def _handle_mock_sync(self, query: str) -> None:
        parameters = parse_network_query(query)
        if set(parameters) != {"cursor", "limit"}:
            raise RequestError(HTTPStatus.BAD_REQUEST, "Sync requires cursor and limit")
        session, scenario, cookie = self._mock_context(
            "GET", "/v2/sync", f"cursor={parameters['cursor']}&limit={parameters['limit']}"
        )
        del session
        if scenario == "http-503":
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "simulated service failure"}, cookie=cookie)
            return
        if scenario == "malformed-payload":
            self._send_json(
                HTTPStatus.OK,
                {"schema": 2, "device_id": "BAD/DEVICE", "cursor": "not-decimal", "deliveries": [], "tombstones": []},
                cookie=cookie,
            )
            return
        try:
            page = network_sync_page(parameters["cursor"], parameters["limit"], scenario)
        except ValueError as exc:
            raise RequestError(HTTPStatus.BAD_REQUEST, str(exc)) from exc
        self._send_json(HTTPStatus.OK, page, cookie=cookie)

    def _handle_mock_artifact(self, path: str) -> None:
        digest = path.removeprefix("/mock/v2/artifacts/")
        session, scenario, cookie = self._mock_context("GET", f"/v2/artifacts/{digest}")
        artifact_request = self.simulator_server.network_store.count_prefix(session.token, "GET /v2/artifacts/")
        if scenario == "artifact-failure-once" and artifact_request == 2 and \
                self.simulator_server.network_store.consume_failure_once(session.token, "artifact"):
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "simulated artifact failure"}, cookie=cookie)
            return
        body = NETWORK_CORPUS.artifacts.get(digest)
        mime = NETWORK_CORPUS.artifact_mimes.get(digest)
        if body is None or mime is None:
            raise RequestError(HTTPStatus.NOT_FOUND, "Artifact fixture not found")
        if scenario == "artifact-short-once" and artifact_request == 2 and \
                self.simulator_server.network_store.consume_failure_once(session.token, "artifact-short"):
            body = body[:-1]
        self._send_bytes(
            HTTPStatus.OK,
            body,
            mime,
            api=True,
            cookie=cookie,
            headers={"ETag": f'"{digest}"'},
        )

    def _handle_mock_acks(self) -> None:
        session, scenario, cookie = self._mock_context("POST", "/v2/acks")
        if scenario == "ack-failure-once" and self.simulator_server.network_store.consume_failure_once(
            session.token, "acks"
        ):
            # Consume the request bytes exactly as a real server would even though
            # this injected response refuses the batch.
            self._read_json_body(4 * 1024)
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "simulated ACK failure"}, cookie=cookie)
            return
        document = self._read_json_body(4 * 1024)
        if not isinstance(document, dict) or set(document) != {"schema", "events"} or document.get("schema") != 2:
            raise RequestError(HTTPStatus.BAD_REQUEST, "ACK payload has the wrong schema")
        events = document.get("events")
        if not isinstance(events, list) or not 1 <= len(events) <= 24:
            raise RequestError(HTTPStatus.BAD_REQUEST, "ACK payload must contain one to 24 events")
        event_ids: list[str] = []
        rejected = 0
        for event in events:
            event_id = event.get("event_id") if isinstance(event, dict) else None
            if not isinstance(event_id, str) or not event_id or len(event_id) > 95:
                rejected += 1
            else:
                event_ids.append(event_id)
        accepted, duplicates = self.simulator_server.network_store.accept_events(session.token, event_ids)
        self._send_json(
            HTTPStatus.OK,
            {"schema": 2, "accepted": accepted, "duplicates": duplicates, "rejected": rejected},
            cookie=cookie,
        )

    def _dispatch_get(self) -> None:
        request = urlsplit(self.path)
        if request.path == "/api/health":
            self._handle_health()
        elif request.path == "/api/release":
            self._handle_release()
        elif request.path == "/api/device-contract":
            self._handle_contract()
        elif request.path == "/api/fixtures":
            self._handle_fixture()
        elif request.path == "/api/firmware":
            self._handle_firmware()
        elif request.path == "/api/qemu":
            self._handle_qemu()
        elif request.path == "/api/crosspoint-simulator":
            self._handle_official_simulator()
        elif request.path == "/api/sd/tree":
            self._handle_tree()
        elif request.path == "/api/sd/file":
            self._handle_sd_file(request.query)
        elif request.path == "/api/network/scenarios":
            self._handle_network_scenarios()
        elif request.path == "/api/network/status":
            self._handle_network_status()
        elif request.path == "/mock/v1/manifest.json":
            self._handle_mock_manifest()
        elif request.path.startswith("/mock/v1/cards/"):
            self._handle_mock_card(request.path, request.query)
        elif request.path.startswith("/mock/v1/reports/"):
            self._handle_mock_report(request.path)
        elif request.path == "/mock/v2/sync":
            self._handle_mock_sync(request.query)
        elif request.path.startswith("/mock/v2/artifacts/"):
            self._handle_mock_artifact(request.path)
        elif request.path.startswith("/api/"):
            raise RequestError(HTTPStatus.NOT_FOUND, "API endpoint not found")
        else:
            self._send_file(_safe_web_file(request.path), api=False)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        try:
            self._dispatch_get()
        except RequestError as error:
            self._send_error(error)
        except (OSError, RuntimeError, json.JSONDecodeError):
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Simulator input validation failed", "status": 500},
            )

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        try:
            request = urlsplit(self.path)
            if request.path == "/api/session/reset":
                self._handle_reset()
            elif request.path == "/api/network/scenario":
                self._handle_network_scenario()
            elif request.path == "/mock/v2/acks":
                self._handle_mock_acks()
            else:
                raise RequestError(HTTPStatus.NOT_FOUND, "API endpoint not found")
        except RequestError as error:
            self._send_error(error)
        except (OSError, RuntimeError):
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Could not reset the simulator session", "status": 500},
            )

    def _read_only_method(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": "The simulator API is read-only", "status": 405},
        )

    do_PUT = _read_only_method
    do_PATCH = _read_only_method
    do_DELETE = _read_only_method


def _parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local XTINCT X3 simulator")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"localhost TCP port (default: {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="do not open the simulator in the default browser",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        help="optional local XTINCT/CrossPoint project root (never searched recursively)",
    )
    parser.add_argument(
        "--firmware",
        type=Path,
        help="optional local firmware.bin/update.bin to inspect read-only",
    )
    parser.add_argument(
        "--sleep",
        type=Path,
        help="optional local sleep.bmp copied into each temporary session",
    )
    parser.add_argument(
        "--resource-contract",
        type=Path,
        help="optional x3-resource-budgets.json; defaults to the bundled demo contract",
    )
    parser.add_argument(
        "--build-dir",
        type=Path,
        help="optional retained PlatformIO build directory for offline QEMU readiness",
    )
    parser.add_argument(
        "--boot-app0",
        type=Path,
        help="optional matching boot_app0.bin for offline QEMU readiness",
    )
    parser.add_argument(
        "--crosspoint-simulator",
        type=Path,
        help="optional official CrossPoint Simulator checkout or executable; detected only",
    )
    parser.add_argument(
        "--session-root",
        type=Path,
        help="existing quarantine directory for disposable sessions (or X3_LAB_QUARANTINE)",
    )
    arguments = parser.parse_args(argv)
    if not 0 <= arguments.port <= 65535:
        parser.error("--port must be between 0 and 65535")
    return arguments


def main() -> int:
    arguments = _parse_arguments()
    try:
        config = _config_from_arguments(arguments)
        _read_release_profile()
        _read_contract(config)
        _read_device_fixture()
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        print(f"X3_SIMULATOR_CONFIGURATION_REFUSED: {error}")
        return 2
    store = SessionStore(config)
    try:
        with X3SimulatorHTTPServer((LOOPBACK_HOST, arguments.port), store) as httpd:
            port = httpd.server_address[1]
            url = f"http://{LOOPBACK_HOST}:{port}/"
            print(f"XTINCT X3 simulator: {url}")
            print(f"Mode: {config.mode}. Local inputs are read-only; device networking is disabled.")
            print("Press Ctrl+C to stop.")
            if not arguments.no_browser:
                threading.Timer(0.25, lambda: webbrowser.open(url)).start()
            try:
                httpd.serve_forever(poll_interval=0.25)
            except KeyboardInterrupt:
                print("\nStopping X3 simulator.")
            finally:
                httpd.shutdown()
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
