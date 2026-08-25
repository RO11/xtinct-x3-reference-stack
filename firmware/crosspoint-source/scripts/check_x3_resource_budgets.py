#!/usr/bin/env python3
"""Validate XTINCT's single-source Xteink X3 resource budget contract.

The JSON contract is the authority.  This checker binds it to the source tree,
the generated human spec, and (when supplied) the final BIN/linker map and
effective sdkconfig.  It intentionally uses only the Python standard library so
the same gate can run before PlatformIO, as a PlatformIO post action, and inside
the release wrappers.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


CONTRACT_RELATIVE = Path("config/x3-resource-budgets.json")
DOC_RELATIVE = Path("docs/X3_RESOURCE_BUDGETS.md")
EXPECTED_TOP_LEVEL = {
    "schema", "device", "linked_image", "task_stacks", "runtime_operations",
    "data_limits", "capabilities",
}


class BudgetError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise BudgetError(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_text(path: Path) -> str:
    require(path.is_file(), f"Required budget source is missing: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise BudgetError(f"Could not read strict UTF-8 budget source: {path}") from error


def integer(value: Any, label: str, *, positive: bool = True) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer")
    if positive:
        require(value > 0, f"{label} must be positive")
    else:
        require(value >= 0, f"{label} must be non-negative")
    return value


def load_contract(project_root: Path) -> tuple[dict[str, Any], Path, str]:
    path = project_root / CONTRACT_RELATIVE
    try:
        raw = path.read_bytes()
        contract = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise BudgetError(f"X3 resource contract is not valid UTF-8 JSON: {path}") from error
    require(isinstance(contract, dict) and set(contract) == EXPECTED_TOP_LEVEL,
            "X3 resource contract envelope changed")
    require(contract.get("schema") == 1, "Unsupported X3 resource contract schema")
    return contract, path, hashlib.sha256(raw).hexdigest()


def format_bytes(value: int) -> str:
    if value % (1024 * 1024) == 0:
        return f"{value:,} B ({value // (1024 * 1024)} MiB)"
    if value % 1024 == 0:
        return f"{value:,} B ({value // 1024} KiB)"
    return f"{value:,} B"


def render_doc(contract: dict[str, Any], contract_sha256: str) -> str:
    device = contract["device"]
    linked = contract["linked_image"]
    stacks = contract["task_stacks"]
    operations = contract["runtime_operations"]
    limits = contract["data_limits"]
    sleep = limits["sleep_screen"]
    capabilities = contract["capabilities"]

    rows = [
        "# X3 resource budgets",
        "",
        "> Generated from `config/x3-resource-budgets.json`. Do not edit this sheet by hand.",
        f"> Contract SHA-256: `{contract_sha256}`",
        "",
        "This is the admission contract for every XTINCT X3 feature. A safety ceiling means",
        "\"reject above this value\"; it does not mean the largest accepted input is physically",
        "fast or pleasant. Runtime rows marked *measured* still require an exact-build X3 test.",
        "",
        "## Fixed hardware envelope",
        "",
        "| Resource | Budget |",
        "|---|---:|",
        f"| MCU | {device['mcu']}, {device['cpu_cores']} core at {device['cpu_hz'] // 1000000} MHz |",
        f"| Internal SRAM | {format_bytes(device['internal_sram_bytes'])} |",
        f"| Linker-visible DRAM | {format_bytes(device['linker_dram_bytes'])} |",
        f"| PSRAM | {format_bytes(device['psram_bytes'])} |",
        f"| Flash | {format_bytes(device['flash_bytes'])} |",
        f"| Each OTA slot | {format_bytes(device['ota_slot_bytes'])} |",
        f"| Display | {device['display_width_pixels']} x {device['display_height_pixels']}, {device['display_levels']} levels |",
        f"| One 1-bit framebuffer | {format_bytes(device['one_bit_framebuffer_bytes'])} |",
        f"| Battery rating | {device['battery_capacity_mah']} mAh |",
        "",
        "## Linked firmware hard gates",
        "",
        "| Metric | Hard gate |",
        "|---|---:|",
        f"| Final `firmware.bin` | <= {format_bytes(linked['firmware_bin_max_bytes'])} |",
        f"| Final BIN OTA reserve | >= {format_bytes(linked['firmware_bin_min_headroom_bytes'])} |",
        f"| Low-headroom warning | < {format_bytes(linked['firmware_bin_warn_below_headroom_bytes'])} |",
        f"| `.data + .bss` | <= {format_bytes(linked['data_plus_bss_max_bytes'])} |",
        f"| IRAM text | <= {format_bytes(linked['iram_text_max_bytes'])} |",
        f"| Total linked DRAM image | <= {format_bytes(linked['total_dram_image_max_bytes'])} |",
        f"| RTC slow memory used | <= {format_bytes(linked['rtc_slow_used_max_bytes'])} |",
        f"| Exception unwind tables | <= {format_bytes(linked['exception_unwind_max_bytes'])} |",
        "",
        "Use the final padded BIN size for OTA admission. PlatformIO's displayed Flash percent",
        "does not account for the whole installable image. Under 128 KiB of final BIN reserve is",
        "red: additions need an equal-or-larger removal. Under the hard reserve fails the build.",
        "BIN, MAP, and effective sdkconfig are one indivisible linked gate; omitting any one fails.",
        "",
        "## Task stack allocations",
        "",
        "| Task | Stack |",
        "|---|---:|",
    ]
    stack_labels = {
        "arduino_loop_bytes": "Arduino loop (effective FreeInk override)",
        "activity_render_bytes": "Activity render",
        "nimble_host_bytes": "NimBLE host",
        "esp_timer_bytes": "ESP timer",
        "freertos_timer_bytes": "FreeRTOS timer service",
        "tcpip_bytes": "TCP/IP",
    }
    rows.extend(f"| {stack_labels[name]} | {format_bytes(value)} |" for name, value in stacks.items())

    rows.extend([
        "",
        "## Per-operation runtime envelope",
        "",
        "| Operation | Free heap | Largest block | Other fixed cost | Evidence class |",
        "|---|---:|---:|---:|---|",
    ])
    operation_labels = {
        "reader_render": "Reader render/prewarm",
        "reader_background_index": "Reader background indexing",
        "epub_checked_growth_reserve": "EPUB checked allocation reserve",
        "css_parse": "CSS parse",
        "jpeg_framebuffer_decode": "JPEG reader decode",
        "jpeg_to_bmp_decode": "JPEG cover-to-BMP",
        "png_framebuffer_decode": "PNG reader decode",
        "font_mini_retain": "Retained mini font",
        "tls_13_sync": "TLS 1.3 sync",
        "inbox_direct_sync": "Inbox direct sync",
        "display": "Display",
        "webdav": "WebDAV transfer",
    }
    for name, value in operations.items():
        free = value.get("min_free_heap_bytes", value.get("min_free_heap_reserve_bytes", value.get("observed_min_free_heap_bytes")))
        block = value.get("min_largest_block_bytes", value.get("min_largest_block_reserve_bytes", value.get("observed_start_largest_block_bytes")))
        other = value.get("decoder_bytes", value.get("fixed_response_plus_page_bytes", value.get("framebuffer_bytes_per_plane", value.get("upload_buffer_bytes"))))
        rows.append(
            f"| {operation_labels[name]} | {format_bytes(free) if free is not None else 'n/a'} | "
            f"{format_bytes(block) if block is not None else 'n/a'} | "
            f"{format_bytes(other) if other is not None else 'n/a'} | {value['kind']} |"
        )

    rows.extend([
        "",
        "PNG is deliberately stricter than JPEG: the pinned PNG decoder object itself is",
        f"{format_bytes(operations['png_framebuffer_decode']['decoder_bytes'])} and must fit in one contiguous block.",
        "TLS numbers are measured watermarks, not a guarantee; changing TLS, Wi-Fi, JSON, or",
        "concurrent buffers requires a physical heap/largest-block trace on the exact firmware.",
        "",
        "## Data and protocol ceilings",
        "",
        "| Area | Limits |",
        "|---|---|",
        ("| Native sleep screen | "
         f"{sleep['portrait_width_pixels']} x {sleep['portrait_height_pixels']} portrait; "
         f"{sleep['bits_per_pixel']}-bpp BI_RGB; {format_bytes(sleep['bmp_file_bytes'])}; "
         "native palette 0/85/170/255; cover-cropped, no one-bit dithering; "
         f"master tone RMSE <= {sleep['low_frequency_rmse_max']}; "
         f"edge correlation >= {sleep['edge_gradient_correlation_min']}; "
         f"periodic score <= {sleep['periodic_autocorrelation_max']} |"),
        ("| Inbox | "
         f"{limits['inbox']['items_on_device']} items; {limits['inbox']['changes_per_direct_page']} changes/page; "
         f"{limits['inbox']['pages_per_wake']} pages/wake; {format_bytes(limits['inbox']['metadata_json_bytes'])} metadata; "
         f"{format_bytes(limits['inbox']['outbox_file_bytes'])} SD outbox |"),
        ("| Pocket Sync | "
         f"{limits['pocket_sync']['objects']} objects; {format_bytes(limits['pocket_sync']['manifest_bytes'])} manifest; "
         f"{format_bytes(limits['pocket_sync']['object_bytes'])}/object; {format_bytes(limits['pocket_sync']['pack_bytes'])}/pack; "
         f"{limits['pocket_sync']['chunk_bytes']}-byte chunks x {limits['pocket_sync']['window_chunks']} |"),
        ("| EPUB | "
         f"{format_bytes(limits['epub']['resource_bytes'])} streamed resource; "
         f"{format_bytes(limits['epub']['in_memory_resource_bytes'])} in-memory resource; "
         f"{format_bytes(limits['epub']['retained_page_bytes'])} retained page |"),
        ("| File Transfer | "
         f"{format_bytes(limits['file_transfer']['single_file_bytes'])} safety ceiling; "
         f"{limits['file_transfer']['path_bytes']}-byte path; {limits['file_transfer']['component_bytes']}-byte component |"),
        "",
        "Large artifacts and packs are streamed safety ceilings. They are not promises that a",
        "maximum-size Bluetooth transfer or nearly-full SD transaction has been physically certified.",
        "",
        "## Hardware capability filter",
        "",
        "| Capability | Available to current firmware? |",
        "|---|---|",
    ])
    capability_labels = {
        "touch": "Touch", "frontlight": "Frontlight", "speaker": "Speaker/audio",
        "microphone": "Microphone", "haptics": "Haptics", "gps": "GPS",
        "cellular": "Cellular", "wifi_5ghz": "5 GHz Wi-Fi", "psram": "PSRAM",
        "current_firmware_nfc_driver": "NFC driver", "wifi_2_4ghz": "2.4 GHz Wi-Fi",
        "ble_peripheral": "BLE peripheral", "micro_sd": "microSD", "rtc": "RTC", "imu": "IMU",
    }
    rows.extend(f"| {capability_labels[name]} | {'yes' if value else 'no'} |" for name, value in capabilities.items())

    rows.extend([
        "",
        "## Mandatory feature admission checklist",
        "",
        "Every X3 change must answer all of these before delivery:",
        "",
        "1. Record final BIN, `.data + .bss`, total DRAM, IRAM, RTC, and unwind-table deltas.",
        "2. State peak dynamic allocation, required free heap, and required largest contiguous block.",
        "3. Declare every new task and stack; physically record stack high-water for new/deeper paths.",
        "4. Bound every network body, JSON document, array, image, file, and retained cache.",
        ("   `/sleep.bmp` must pass the workspace `scripts/check_x3_sleep_screen.py` gate as exact "
         f"{sleep['portrait_width_pixels']} x {sleep['portrait_height_pixels']} native grayscale, using "
         "`--source <explicit-unquantised-master>` for tone/detail/grid comparison."),
        "5. Stream bodies over 28 KiB and avoid holding TLS, response, parse tree, and duplicate payloads together.",
        "6. Service the watchdog/yield in every potentially long SD, network, decode, hash, or directory loop.",
        "7. Budget atomic SD writes for both old and staged files, then test disk-full and power-loss recovery.",
        "8. Convert allocation failure to a safe refusal; no exception may escape an activity/protocol boundary.",
        "9. Run the source budget gate and linked-artifact budget gate. A skipped required gate is a failure.",
        "10. Physically test uncertain runtime paths on the exact firmware and bind results to its SHA-256.",
        "",
        "Commands:",
        "",
        "```powershell",
        "python -B scripts/check_x3_resource_budgets.py",
        "python -B scripts/check_x3_resource_budgets.py --firmware-bin <firmware.bin> --firmware-map <firmware.map> --sdkconfig <sdkconfig.h>",
        "python -B scripts/check_x3_resource_budgets.py --self-test",
        "```",
        "",
    ])
    return "\n".join(rows)


def parse_partitions(path: Path) -> dict[str, int]:
    result: dict[str, int] = {}
    for row in csv.reader(read_text(path).splitlines()):
        if not row or row[0].lstrip().startswith("#"):
            continue
        require(len(row) >= 5, f"Malformed partition row in {path}: {row!r}")
        name, kind, subtype, _offset, size = (value.strip() for value in row[:5])
        if kind == "app" and subtype in {"ota_0", "ota_1"}:
            require(name not in result, f"Duplicate OTA partition {name}")
            try:
                result[name] = int(size, 0)
            except ValueError as error:
                raise BudgetError(f"Invalid OTA partition size: {size}") from error
    return result


def require_snippets(project_root: Path, relative: str, snippets: list[str]) -> None:
    text = read_text(project_root / relative)
    for snippet in snippets:
        require(text.count(snippet) == 1,
                f"X3 resource source contract changed: {relative} must contain exactly once: {snippet}")


def function_body(text: str, signature: str, next_signature: str) -> str:
    start = text.find(signature)
    require(start >= 0, f"Missing function for resource gate: {signature}")
    end = text.find(next_signature, start + len(signature))
    require(end > start, f"Could not bound function for resource gate: {signature}")
    return text[start:end]


def run_python_source_gate(project_root: Path, relative: str, success_marker: str) -> None:
    script = project_root / relative
    require(script.is_file(), f"Required source-contract gate is missing: {relative}")
    environment = os.environ.copy()
    # The EPUB mutation harness owns this variable for its private fixture.
    # An ambient value must never redirect the authoritative source gate.
    environment.pop("EPUB_CONTRACT_ROOT", None)
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(script)],
        cwd=project_root,
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    detail = result.stdout.strip()
    require(result.returncode == 0,
            f"Mandatory source-contract gate failed: {relative}: {detail[-4096:]}")
    require(success_marker in result.stdout,
            f"Mandatory source-contract gate did not report success: {relative}")


def verify_source(project_root: Path, contract: dict[str, Any], contract_sha256: str,
                  *, check_doc: bool = True) -> dict[str, Any]:
    device = contract["device"]
    linked = contract["linked_image"]
    stacks = contract["task_stacks"]
    operations = contract["runtime_operations"]
    limits = contract["data_limits"]
    sleep = limits["sleep_screen"]

    for section in (device, linked, stacks):
        require(isinstance(section, dict) and section, "Budget section is empty or invalid")
        for name, value in section.items():
            if isinstance(value, int):
                integer(value, name, positive=(name != "psram_bytes"))

    require(device["display_width_pixels"] % 8 == 0,
            "X3 one-bit framebuffer requires a byte-aligned display width")
    require(device["one_bit_framebuffer_bytes"] ==
            device["display_width_pixels"] // 8 * device["display_height_pixels"],
            "X3 framebuffer budget does not match the display geometry")
    require(sleep["portrait_width_pixels"] == device["display_height_pixels"] and
            sleep["portrait_height_pixels"] == device["display_width_pixels"],
            "X3 sleep screen must match the physical display in portrait")
    require(sleep["bits_per_pixel"] == 4 and sleep["palette_luminance"] == [0, 85, 170, 255],
            "X3 sleep screen must use the four native gray levels in a standard 4-bpp BMP")
    expected_sleep_row_bytes = ((sleep["portrait_width_pixels"] * sleep["bits_per_pixel"] + 31) // 32) * 4
    require(sleep["bmp_pixel_offset_bytes"] == 70 and
            sleep["bmp_row_bytes"] == expected_sleep_row_bytes and
            sleep["bmp_file_bytes"] == sleep["bmp_pixel_offset_bytes"] +
            sleep["bmp_row_bytes"] * sleep["portrait_height_pixels"],
            "X3 native sleep-screen BMP geometry is inconsistent")
    require(3 <= sleep["minimum_gray_levels_used"] <= 4 and
            1 <= sleep["edge_gutter_scan_pixels"] * 2 < sleep["portrait_width_pixels"] and
            1 <= sleep["edge_gutter_min_white_per_mille"] <= 1000,
            "X3 sleep-screen visual admission thresholds are invalid")
    require(device["ota_slot_bytes"] == linked["firmware_bin_max_bytes"],
            "OTA slot and firmware maximum disagree")
    require(linked["firmware_bin_warn_below_headroom_bytes"] >=
            linked["firmware_bin_min_headroom_bytes"],
            "Firmware warning headroom is below the hard reserve")

    partitions = parse_partitions(project_root / "partitions.csv")
    require(partitions == {"app0": device["ota_slot_bytes"], "app1": device["ota_slot_bytes"]},
            f"OTA partition contract changed: {partitions!r}")

    require_snippets(project_root, "platformio.ini", [
        "board_upload.flash_size = 16MB",
        "board_build.partitions = partitions.csv",
        "-DEINK_DISPLAY_SINGLE_BUFFER_MODE=1",
        f"-DPNG_MAX_BUFFERED_PIXELS={operations['png_framebuffer_decode']['max_buffered_pixels']}",
        f"CONFIG_ESP_TIMER_TASK_STACK_SIZE={stacks['esp_timer_bytes']}",
        f"CONFIG_FREERTOS_TIMER_TASK_STACK_DEPTH={stacks['freertos_timer_bytes']}",
        f"CONFIG_LWIP_TCPIP_TASK_STACK_SIZE={stacks['tcpip_bytes']}",
        f"CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE={stacks['nimble_host_bytes']}",
        "CONFIG_BT_NIMBLE_MAX_CONNECTIONS=1",
        "CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE=1024",
        "post:scripts/register_x3_resource_budget.py",
    ])
    require_snippets(project_root, "scripts/register_x3_resource_budget.py", [
        'X3_ENVIRONMENTS = frozenset({"default", "gh_release", "gh_release_rc", "slim"})',
        'NON_X3_ENVIRONMENTS = frozenset({"sticky"})',
        "run_budget_gate([])",
        '"--firmware-bin", str(firmware_bin)',
        '"--firmware-map", str(firmware_map)',
        '"--sdkconfig", str(sdkconfig)',
        'env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", verify_linked_budget)',
        "elif environment not in NON_X3_ENVIRONMENTS:",
    ])
    register_source = read_text(project_root / "scripts/register_x3_resource_budget.py")
    require(register_source.find("run_budget_gate([])") <
            register_source.find("if environment in X3_ENVIRONMENTS:"),
            "PlatformIO source budget gate must run before any environment may bypass the linked gate")
    require_snippets(project_root, "test/CMakeLists.txt", [
        "find_package(Python3 REQUIRED COMPONENTS Interpreter)",
        "NAME x3_resource_budget_source_contract",
        "NAME x3_resource_budget_checker_self_test",
    ])
    require_snippets(project_root, "test/xtinct_sync_contract/CMakeLists.txt", [
        "NAME xtinct_outbox_memory_source_contract",
    ])
    require_snippets(project_root, "test/epub_safety_bounds/CMakeLists.txt", [
        "NAME epub_safety_source_contract\n  COMMAND",
        "NAME epub_safety_source_contract_mutations\n  COMMAND",
    ])
    require_snippets(project_root, "test/daily_cards_render_wait/CMakeLists.txt", [
        "NAME daily_cards_render_wait_source_contract",
    ])
    run_python_source_gate(
        project_root, "test/xtinct_sync_contract/verify_outbox_memory_contract.py",
        "outbox memory contract: PASS",
    )
    run_python_source_gate(
        project_root, "test/epub_safety_bounds/verify_source_contract.py",
        "EPUB cache/parser source contract: PASS",
    )
    run_python_source_gate(
        project_root, "test/epub_safety_bounds/verify_source_contract_mutations.py",
        "EPUB source-contract mutation checks: PASS",
    )
    run_python_source_gate(
        project_root, "test/daily_cards_render_wait/verify_source_contract.py",
        "DAILY_CARDS_RENDER_WAIT_SOURCE_OK",
    )
    build_wrapper = read_text(project_root / "scripts/build_xtinct.py")
    build_self_test = function_body(
        build_wrapper, "def self_test(core_dir: Path) -> int:",
        "def run_build(argv: Sequence[str]) -> int:"
    )
    build_run = function_body(
        build_wrapper, "def run_build(argv: Sequence[str]) -> int:",
        "def main(argv: Sequence[str]) -> int:"
    )
    build_publish = function_body(
        build_wrapper,
        "def publish_verified_artifacts(private_build_dir: Path, environment: str, started_ns: int,",
        "def self_test(core_dir: Path) -> int:"
    )
    require(build_self_test.count("verify_x3_resource_budget_source()") == 1,
            "Authoritative wrapper self-test must run the X3 source budget gate")
    require(build_run.count("verify_x3_resource_budget_source()") == 1,
            "Authoritative wrapper build must run the X3 source budget gate")
    require(build_publish.count("verify_x3_resource_budget_linked(") == 1,
            "Authoritative wrapper must run the X3 linked budget gate before publication")
    require_snippets(project_root, "scripts/run_ready27_warmed_compile.py", [
        "b.verify_x3_resource_budget_source()",
        "b.verify_x3_resource_budget_linked(",
        '"x3_resource_budget": resource_budget',
    ])
    require_snippets(project_root, "freeink-sdk/libs/ui/FreeInkUI/src/FreeInkUI.cpp", [
        f"getArduinoLoopTaskStackSize(void) {{ return {stacks['arduino_loop_bytes'] // 1024} * 1024; }}",
    ])
    require_snippets(project_root, "src/activities/ActivityManager.cpp", [
        f"{stacks['activity_render_bytes']},               // Stack size",
    ])
    require_snippets(project_root, "lib/GfxRenderer/GfxRenderer.h", [
        f"BW_BUFFER_CHUNK_SIZE = {operations['display']['chunk_bytes']}",
    ])
    require_snippets(project_root, "src/util/InboxSyncPagingPolicy.h", [
        f"DIRECT_PAGE_CHANGES = {limits['inbox']['changes_per_direct_page']}",
        f"MAX_PAGES_PER_WAKE = {limits['inbox']['pages_per_wake']}",
        f"MAX_DIRECT_RESPONSE_BYTES = {operations['inbox_direct_sync']['response_buffer_max_bytes'] // 1024} * 1024",
    ])
    require_snippets(project_root, "src/util/XtinctSyncContract.h", [
        f"MAX_OUTBOX_BYTES = {limits['inbox']['outbox_file_bytes'] // 1024} * 1024",
        f"MAX_OUTBOX_EVENT_LINE_BYTES = {limits['inbox']['outbox_event_line_bytes']}",
        f"MAX_METADATA_BYTES = {limits['inbox']['metadata_json_bytes'] // 1024} * 1024",
        f"MAX_INBOX_ITEMS = {limits['inbox']['items_on_device']}",
        f"X3_SLEEP_BMP_WIDTH = {sleep['portrait_width_pixels']}",
        f"X3_SLEEP_BMP_HEIGHT = {sleep['portrait_height_pixels']}",
        f"X3_SLEEP_BMP_BITS_PER_PIXEL = {sleep['bits_per_pixel']}",
        f"X3_SLEEP_BMP_PIXEL_OFFSET = {sleep['bmp_pixel_offset_bytes']}",
        f"X3_SLEEP_BMP_ROW_BYTES = {sleep['bmp_row_bytes']}",
        "isX3NativeSleepBmpHeader",
    ])
    require_snippets(project_root, "src/network/XtinctSyncClient.cpp", [
        f"MAX_DEVICE_ACK_JSON_BYTES = {operations['inbox_direct_sync']['ack_payload_max_bytes'] // 1024} * 1024",
        f"static_assert(sizeof(SyncPage) == {operations['inbox_direct_sync']['parsed_page_bytes']}",
    ])
    require_snippets(project_root, "src/network/XtinctSyncClient.h", [
        f"static_assert(sizeof(XtinctInboxItem) == {limits['inbox']['item_struct_bytes']}",
    ])
    require_snippets(project_root, "src/util/PocketSyncContract.h", [
        f"MAX_MANIFEST_BYTES = {limits['pocket_sync']['manifest_bytes'] // 1024}U * 1024U",
        f"MAX_OBJECTS = {limits['pocket_sync']['objects']}",
        f"MAX_OBJECT_BYTES = {limits['pocket_sync']['object_bytes'] // (1024 * 1024)}U * 1024U * 1024U",
        f"MAX_PACK_BYTES = {limits['pocket_sync']['pack_bytes'] // (1024 * 1024)}U * 1024U * 1024U",
        f"DEVICE_MAX_CHUNK_BYTES = {limits['pocket_sync']['chunk_bytes']}",
        f"WINDOW_CHUNKS = {limits['pocket_sync']['window_chunks']}",
    ])
    require_snippets(project_root, "lib/Epub/Epub/EpubSafetyLimits.h", [
        f"MAX_EPUB_RESOURCE_BYTES = {limits['epub']['resource_bytes'] // (1024 * 1024)}U * 1024U * 1024U",
        f"MAX_IN_MEMORY_RESOURCE_BYTES = {limits['epub']['in_memory_resource_bytes'] // 1024}U * 1024U",
        f"MAX_RETAINED_CSS_RULE_BYTES = {limits['epub']['retained_css_bytes'] // 1024}U * 1024U",
        f"MAX_RETAINED_PARAGRAPH_BYTES = {limits['epub']['retained_paragraph_bytes'] // 1024}U * 1024U",
        f"MAX_SERIALIZED_PAGE_BYTES = {limits['epub']['serialized_page_bytes'] // 1024}U * 1024U",
        f"MAX_RETAINED_PAGE_BYTES = {limits['epub']['retained_page_bytes'] // 1024}U * 1024U",
        f"MAX_LAYOUT_SCRATCH_BYTES = {limits['epub']['layout_scratch_bytes'] // 1024}U * 1024U",
        f"MAX_METADATA_BATCH_BYTES = {limits['epub']['metadata_batch_bytes'] // 1024}U * 1024U",
        f"EPUB_HEAP_RESERVE_BYTES = {operations['epub_checked_growth_reserve']['min_free_heap_reserve_bytes'] // 1024}U * 1024U",
        f"EPUB_LARGEST_BLOCK_RESERVE_BYTES = {operations['epub_checked_growth_reserve']['min_largest_block_reserve_bytes'] // 1024}U * 1024U",
    ])
    require_snippets(project_root, "src/activities/reader/EpubReaderActivity.h", [
        f"BACKGROUND_BUILD_MIN_FREE_HEAP = {operations['reader_background_index']['min_free_heap_bytes'] // 1024} * 1024",
        f"BACKGROUND_BUILD_MIN_MAX_ALLOC = {operations['reader_background_index']['min_largest_block_bytes'] // 1024} * 1024",
        f"RENDER_MIN_FREE_HEAP = {operations['reader_render']['min_free_heap_bytes'] // 1024} * 1024",
    ])
    require_snippets(project_root, "lib/Epub/Epub/converters/PngToFramebufferConverter.cpp", [
        f"static_assert(PNG_DECODER_SIZE == {operations['png_framebuffer_decode']['decoder_bytes']}",
        "MIN_FREE_HEAP_FOR_PNG = PNG_DECODER_SIZE + 16 * 1024",
    ])
    png_source = read_text(project_root / "lib/Epub/Epub/converters/PngToFramebufferConverter.cpp")
    require(png_source.count("maxBlock < PNG_DECODER_SIZE") == 2,
            "Both PNG entry points must enforce the contiguous decoder-block budget")
    require_snippets(project_root, "lib/Epub/Epub/converters/JpegToFramebufferConverter.cpp", [
        f"JPEG_DECODER_APPROX_SIZE = {operations['jpeg_framebuffer_decode']['decoder_bytes'] // 1024} * 1024",
        "MIN_FREE_HEAP_FOR_JPEG = JPEG_DECODER_APPROX_SIZE + 16 * 1024",
    ])
    require_snippets(project_root, "lib/JpegToBmpConverter/JpegToBmpConverter.cpp", [
        f"JPEG_DECODER_SIZE = {operations['jpeg_to_bmp_decode']['decoder_bytes'] // 1024} * 1024",
        "MIN_FREE_HEAP = JPEG_DECODER_SIZE + 32 * 1024",
    ])
    require_snippets(project_root, "lib/Epub/Epub/css/CssParser.cpp", [
        f"MIN_FREE_HEAP_FOR_CSS = {operations['css_parse']['min_free_heap_bytes'] // 1024} * 1024",
    ])
    require_snippets(project_root, "lib/EpdFont/SdCardFont.cpp", [
        f"MINI_RETAIN_MIN_FREE_HEAP = {operations['font_mini_retain']['min_free_heap_bytes'] // 1024} * 1024",
    ])
    require_snippets(project_root, "src/network/FileTransferSafety.h", [
        f"MAX_PATH_BYTES = {limits['file_transfer']['path_bytes']}",
        f"MAX_COMPONENT_BYTES = {limits['file_transfer']['component_bytes']}",
        "MAX_TRANSFER_FILE_BYTES = 0xffffffffULL",
    ])
    require_snippets(project_root, "src/network/CrossPointWebServer.h", [
        f"UPLOAD_BUFFER_SIZE = {operations['webdav']['upload_buffer_bytes']}",
    ])
    webdav = read_text(project_root / "src/network/WebDAVHandler.cpp")
    get_body = function_body(webdav, "void WebDAVHandler::handleGet(WebServer& s)",
                             "void WebDAVHandler::handleHead(WebServer& s)")
    require(get_body.count(f"uint8_t buffer[{operations['webdav']['download_buffer_bytes']}]") == 1,
            "WebDAV GET chunk budget changed")
    require(re.search(
        r"while\s*\(file\.available\(\)\)\s*\{\s*"
        r"resetTaskWatchdogIfSubscribed\(\);\s*"
        r"int\s+bytesRead\s*=\s*file\.read\(",
        get_body,
    ) is not None, "WebDAV GET must service the watchdog before every SD read chunk")
    require(re.search(
        r"while\s*\(totalWritten\s*<\s*static_cast<size_t>\(bytesRead\)\)\s*\{\s*"
        r"resetTaskWatchdogIfSubscribed\(\);\s*"
        r"size_t\s+wrote\s*=\s*client\.write\(",
        get_body,
    ) is not None, "WebDAV GET must service the watchdog before every network write attempt")

    if check_doc:
        expected_doc = render_doc(contract, contract_sha256)
        actual_doc = read_text(project_root / DOC_RELATIVE)
        require(actual_doc == expected_doc,
                f"Generated X3 budget sheet is stale; regenerate {DOC_RELATIVE}")

    return {
        "contract_path": CONTRACT_RELATIVE.as_posix(),
        "contract_sha256": contract_sha256,
        "source": "pass",
    }


MAP_SECTIONS = {
    "iram_text": ".iram0.text",
    "dram_dummy": ".dram0.dummy",
    "dram_data": ".dram0.data",
    "dram_bss": ".dram0.bss",
    "rtc_text": ".rtc.text",
    "rtc_data": ".rtc.data",
    "rtc_noinit": ".rtc_noinit",
    "eh_frame": ".eh_frame",
    "eh_frame_hdr": ".eh_frame_hdr",
}


def parse_linker_map(path: Path) -> dict[str, int]:
    text = read_text(path)
    values: dict[str, int] = {}
    for name, section in MAP_SECTIONS.items():
        matches = re.findall(rf"(?m)^\s*{re.escape(section)}\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)\s*$", text)
        require(len(matches) == 1, f"Linker map must contain one top-level {section} row")
        values[name] = int(matches[0], 16)
    dram_rows = re.findall(r"(?m)^dram0_0_seg\s+0x[0-9a-fA-F]+\s+(0x[0-9a-fA-F]+)\s+rw\s*$", text)
    require(len(dram_rows) == 1, "Linker map must contain one DRAM capacity row")
    values["dram_capacity"] = int(dram_rows[0], 16)
    return values


def parse_sdkconfig(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in read_text(path).splitlines():
        match = re.fullmatch(r"#define\s+(CONFIG_[A-Z0-9_]+)(?:\s+(.*))?", line.strip())
        if match:
            require(match.group(1) not in values, f"Duplicate generated sdkconfig key: {match.group(1)}")
            values[match.group(1)] = (match.group(2) or "1").strip()
    return values


def enforce_linked_metrics(contract: dict[str, Any], actual: dict[str, int]) -> list[str]:
    linked = contract["linked_image"]
    checks = {
        "firmware_bin_bytes": ("<=", linked["firmware_bin_max_bytes"]),
        "firmware_headroom_bytes": (">=", linked["firmware_bin_min_headroom_bytes"]),
        "data_plus_bss_bytes": ("<=", linked["data_plus_bss_max_bytes"]),
        "iram_text_bytes": ("<=", linked["iram_text_max_bytes"]),
        "total_dram_image_bytes": ("<=", linked["total_dram_image_max_bytes"]),
        "rtc_slow_used_bytes": ("<=", linked["rtc_slow_used_max_bytes"]),
        "exception_unwind_bytes": ("<=", linked["exception_unwind_max_bytes"]),
    }
    for name, (operator, limit) in checks.items():
        value = actual[name]
        if operator == "<=":
            require(value <= limit, f"X3 linked budget exceeded: {name}={value}, max={limit}")
        else:
            require(value >= limit, f"X3 linked reserve exhausted: {name}={value}, min={limit}")
    warnings: list[str] = []
    if actual["firmware_headroom_bytes"] < linked["firmware_bin_warn_below_headroom_bytes"]:
        warnings.append(
            "FLASH_RED: final BIN has less than the 128 KiB warning reserve; new features need a non-positive net delta"
        )
    return warnings


def verify_linked(project_root: Path, contract: dict[str, Any], contract_sha256: str,
                   firmware_bin: Path, firmware_map: Path,
                   sdkconfig: Path) -> dict[str, Any]:
    require(firmware_bin.is_file(), f"Firmware BIN is missing: {firmware_bin}")
    require(firmware_map.is_file(), f"Firmware map is missing: {firmware_map}")
    firmware_bytes = firmware_bin.stat().st_size
    with firmware_bin.open("rb") as handle:
        require(handle.read(1) == b"\xe9", "Firmware BIN lacks the ESP image magic")
    sections = parse_linker_map(firmware_map)
    require(sections["dram_capacity"] == contract["device"]["linker_dram_bytes"],
            "Linked DRAM capacity no longer matches the X3 contract")
    actual = {
        "firmware_bin_bytes": firmware_bytes,
        "firmware_headroom_bytes": contract["device"]["ota_slot_bytes"] - firmware_bytes,
        "data_plus_bss_bytes": sections["dram_data"] + sections["dram_bss"],
        "iram_text_bytes": sections["iram_text"],
        "total_dram_image_bytes": sections["dram_dummy"] + sections["dram_data"] + sections["dram_bss"],
        "rtc_slow_used_bytes": sections["rtc_text"] + sections["rtc_data"] + sections["rtc_noinit"],
        "exception_unwind_bytes": sections["eh_frame"] + sections["eh_frame_hdr"],
    }
    warnings = enforce_linked_metrics(contract, actual)

    effective = parse_sdkconfig(sdkconfig)
    expected = {
        "CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE": contract["task_stacks"]["nimble_host_bytes"],
        "CONFIG_ESP_TIMER_TASK_STACK_SIZE": contract["task_stacks"]["esp_timer_bytes"],
        "CONFIG_FREERTOS_TIMER_TASK_STACK_DEPTH": contract["task_stacks"]["freertos_timer_bytes"],
        "CONFIG_LWIP_TCPIP_TASK_STACK_SIZE": contract["task_stacks"]["tcpip_bytes"],
        "CONFIG_COMPILER_CXX_EXCEPTIONS_EMG_POOL_SIZE": 1024,
    }
    for name, value in expected.items():
        require(effective.get(name) == str(value),
                f"Effective sdkconfig budget changed: {name}={effective.get(name)!r}, expected {value}")
    require(effective.get("CONFIG_SPIRAM") in {None, "0", "n"},
            "X3 build unexpectedly claims PSRAM")

    return {
        "schema": 1,
        "contract": {
            "path": CONTRACT_RELATIVE.as_posix(),
            "sha256": contract_sha256,
        },
        "artifacts": {
            "firmware.bin": {
                "bytes": firmware_bytes,
                "sha256": sha256_file(firmware_bin),
            },
            "firmware.map": {
                "bytes": firmware_map.stat().st_size,
                "sha256": sha256_file(firmware_map),
            },
            "sdkconfig.h": {
                "bytes": sdkconfig.stat().st_size,
                "sha256": sha256_file(sdkconfig),
            },
        },
        "actual": actual,
        "limits": contract["linked_image"],
        "warnings": warnings,
        "effective_sdkconfig_checked": True,
        "verdict": "pass",
    }


def self_test() -> None:
    sample = """Memory Configuration
Name             Origin             Length             Attributes
dram0_0_seg      0x3fc80000         0x0004e710         rw
.rtc.text       0x50000000       0x14
.rtc.data       0x50000014        0x2
.rtc_noinit     0x50000018     0x1034
.iram0.text     0x40380000    0x154ea
.dram0.dummy    0x3fc80000    0x15600
.dram0.data     0x3fc95600     0x4655
.dram0.bss      0x3fc99c60     0x9618
.eh_frame_hdr   0x3c5a032c    0x14da4
.eh_frame       0x3c5b50d0    0x6a840
"""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="x3-budget-selftest-") as name:
        path = Path(name) / "firmware.map"
        path.write_text(sample, encoding="utf-8")
        parsed = parse_linker_map(path)
    require(parsed["dram_capacity"] == 321296 and parsed["eh_frame"] == 436288,
            "Linker-map budget parser self-test failed")
    contract = {
        "linked_image": {
            "firmware_bin_max_bytes": 100,
            "firmware_bin_min_headroom_bytes": 10,
            "firmware_bin_warn_below_headroom_bytes": 20,
            "data_plus_bss_max_bytes": 20,
            "iram_text_max_bytes": 20,
            "total_dram_image_max_bytes": 30,
            "rtc_slow_used_max_bytes": 10,
            "exception_unwind_max_bytes": 20,
        }
    }
    baseline = {
        "firmware_bin_bytes": 100, "firmware_headroom_bytes": 10,
        "data_plus_bss_bytes": 20, "iram_text_bytes": 20,
        "total_dram_image_bytes": 30, "rtc_slow_used_bytes": 10,
        "exception_unwind_bytes": 20,
    }
    require(len(enforce_linked_metrics(contract, baseline)) == 1,
            "Exact hard limits must pass with the expected low-headroom warning")
    for key in ("firmware_bin_bytes", "data_plus_bss_bytes", "iram_text_bytes",
                "total_dram_image_bytes", "rtc_slow_used_bytes", "exception_unwind_bytes"):
        mutated = dict(baseline)
        mutated[key] += 1
        try:
            enforce_linked_metrics(contract, mutated)
        except BudgetError:
            continue
        raise BudgetError(f"One-byte-over mutation was accepted: {key}")
    mutated = dict(baseline)
    mutated["firmware_headroom_bytes"] -= 1
    try:
        enforce_linked_metrics(contract, mutated)
    except BudgetError:
        pass
    else:
        raise BudgetError("One-byte-under reserve mutation was accepted")


def atomic_write(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--firmware-bin", type=Path)
    parser.add_argument("--firmware-map", type=Path)
    parser.add_argument("--sdkconfig", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--write-doc", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.self_test:
            self_test()
            print("X3_RESOURCE_BUDGET_SELF_TEST_OK")
            return 0
        project_root = args.project_root.resolve()
        contract, _contract_path, contract_sha256 = load_contract(project_root)
        if args.write_doc:
            atomic_write(project_root / DOC_RELATIVE, render_doc(contract, contract_sha256))
        source = verify_source(project_root, contract, contract_sha256)
        linked_inputs = (args.firmware_bin, args.firmware_map, args.sdkconfig)
        require(all(value is None for value in linked_inputs) or
                all(value is not None for value in linked_inputs),
                "--firmware-bin, --firmware-map and --sdkconfig must be supplied together")
        require(args.report is None or args.firmware_bin is not None,
                "--report requires the complete linked-artifact gate")
        linked = None
        if args.firmware_bin is not None:
            linked = verify_linked(
                project_root, contract, contract_sha256,
                args.firmware_bin.resolve(), args.firmware_map.resolve(),
                args.sdkconfig.resolve(),
            )
            if args.report:
                atomic_write(args.report.resolve(), json.dumps(linked, indent=2, sort_keys=True) + "\n")
        if args.json_output:
            print(json.dumps({"source": source, "linked": linked}, sort_keys=True))
        else:
            print(f"X3_RESOURCE_BUDGET_SOURCE_OK {contract_sha256}")
            if linked is not None:
                actual = linked["actual"]
                print(
                    "X3_RESOURCE_BUDGET_LINKED_OK "
                    f"bin={actual['firmware_bin_bytes']} "
                    f"headroom={actual['firmware_headroom_bytes']} "
                    f"dram={actual['total_dram_image_bytes']} "
                    f"rtc={actual['rtc_slow_used_bytes']}"
                )
                for warning in linked["warnings"]:
                    print(f"X3_RESOURCE_BUDGET_WARNING {warning}")
        return 0
    except (BudgetError, OSError, UnicodeError, ValueError) as error:
        print(f"X3_RESOURCE_BUDGET_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
