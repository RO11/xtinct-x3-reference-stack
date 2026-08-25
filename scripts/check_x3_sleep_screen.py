#!/usr/bin/env python3
"""Fail-closed preflight for a native Xteink X3 ``/sleep.bmp``.

This is deliberately separate from generic BMP validation.  The X3 panel is
528 x 792 in portrait and has four native gray levels.  A 480 x 800 one-bit
image is an X4/legacy artifact: CrossPoint will center it on the X3 and the
one-bit halftone becomes visible on the E-Ink panel.
"""

from __future__ import annotations

import argparse
import json
import math
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from PIL import Image, ImageDraw, ImageOps
except ImportError as error:  # pragma: no cover - fail closed on release machines
    raise SystemExit("X3_SLEEP_SCREEN_FAIL: Pillow is required for perceptual master validation") from error


WORKSPACE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONTRACT = WORKSPACE_ROOT / "firmware/crosspoint-source/config/x3-resource-budgets.json"


class SleepScreenError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SleepScreenError(message)


def integer(value: Any, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool) and value > 0,
            f"{label} must be a positive integer")
    return value


@dataclass(frozen=True)
class SleepScreenContract:
    width: int
    height: int
    bits_per_pixel: int
    pixel_offset: int
    row_bytes: int
    file_bytes: int
    palette: tuple[int, ...]
    minimum_gray_levels_used: int
    edge_scan_pixels: int
    edge_white_per_mille: int
    perceptual_master_required: bool
    low_frequency_block_pixels: int
    low_frequency_rmse_max: float
    edge_detail_block_pixels: int
    edge_gradient_correlation_min: float
    edge_energy_ratio_min: float
    edge_energy_ratio_max: float
    periodic_residual_block_pixels: int
    periodic_lag_min_pixels: int
    periodic_lag_max_pixels: int
    periodic_autocorrelation_max: float


def load_contract(path: Path) -> SleepScreenContract:
    try:
        root = json.loads(path.read_text(encoding="utf-8"))
        device = root["device"]
        value = root["data_limits"]["sleep_screen"]
    except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise SleepScreenError(f"Could not load the X3 sleep-screen contract: {path}") from error

    contract = SleepScreenContract(
        width=integer(value.get("portrait_width_pixels"), "portrait_width_pixels"),
        height=integer(value.get("portrait_height_pixels"), "portrait_height_pixels"),
        bits_per_pixel=integer(value.get("bits_per_pixel"), "bits_per_pixel"),
        pixel_offset=integer(value.get("bmp_pixel_offset_bytes"), "bmp_pixel_offset_bytes"),
        row_bytes=integer(value.get("bmp_row_bytes"), "bmp_row_bytes"),
        file_bytes=integer(value.get("bmp_file_bytes"), "bmp_file_bytes"),
        palette=tuple(value.get("palette_luminance", ())),
        minimum_gray_levels_used=integer(value.get("minimum_gray_levels_used"),
                                         "minimum_gray_levels_used"),
        edge_scan_pixels=integer(value.get("edge_gutter_scan_pixels"), "edge_gutter_scan_pixels"),
        edge_white_per_mille=integer(value.get("edge_gutter_min_white_per_mille"),
                                     "edge_gutter_min_white_per_mille"),
        perceptual_master_required=value.get("perceptual_master_required") is True,
        low_frequency_block_pixels=integer(value.get("low_frequency_block_pixels"),
                                           "low_frequency_block_pixels"),
        low_frequency_rmse_max=float(value.get("low_frequency_rmse_max", 0)),
        edge_detail_block_pixels=integer(value.get("edge_detail_block_pixels"),
                                         "edge_detail_block_pixels"),
        edge_gradient_correlation_min=float(value.get("edge_gradient_correlation_min", 0)),
        edge_energy_ratio_min=float(value.get("edge_energy_ratio_min", 0)),
        edge_energy_ratio_max=float(value.get("edge_energy_ratio_max", 0)),
        periodic_residual_block_pixels=integer(value.get("periodic_residual_block_pixels"),
                                               "periodic_residual_block_pixels"),
        periodic_lag_min_pixels=integer(value.get("periodic_lag_min_pixels"),
                                        "periodic_lag_min_pixels"),
        periodic_lag_max_pixels=integer(value.get("periodic_lag_max_pixels"),
                                        "periodic_lag_max_pixels"),
        periodic_autocorrelation_max=float(value.get("periodic_autocorrelation_max", 0)),
    )
    require(contract.width == integer(device.get("display_height_pixels"), "display_height_pixels") and
            contract.height == integer(device.get("display_width_pixels"), "display_width_pixels"),
            "Portrait sleep-screen dimensions must be the physical X3 display dimensions rotated once")
    require(contract.bits_per_pixel == 4, "X3 sleep screens must use standard 4-bpp BMP storage")
    require(contract.palette == (0, 85, 170, 255),
            "X3 sleep-screen palette must be the four native gray luminances")
    require(contract.pixel_offset == 14 + 40 + 4 * len(contract.palette),
            "X3 sleep-screen pixel offset does not match its header and palette")
    expected_row_bytes = ((contract.width * contract.bits_per_pixel + 31) // 32) * 4
    require(contract.row_bytes == expected_row_bytes, "X3 sleep-screen row stride is inconsistent")
    require(contract.file_bytes == contract.pixel_offset + contract.row_bytes * contract.height,
            "X3 sleep-screen byte count is inconsistent")
    require(contract.minimum_gray_levels_used <= len(contract.palette),
            "minimum_gray_levels_used exceeds the native palette")
    require(contract.edge_scan_pixels * 2 < min(contract.width, contract.height),
            "edge gutter scan is wider than the image")
    require(1 <= contract.edge_white_per_mille <= 1000,
            "edge_gutter_min_white_per_mille must be between 1 and 1000")
    require(contract.perceptual_master_required,
            "X3 sleep-screen publication must require an explicit master image")
    require(contract.width % contract.low_frequency_block_pixels == 0 and
            contract.height % contract.low_frequency_block_pixels == 0,
            "low-frequency block size must divide the X3 portrait dimensions")
    require(contract.width % contract.edge_detail_block_pixels == 0 and
            contract.height % contract.edge_detail_block_pixels == 0,
            "edge-detail block size must divide the X3 portrait dimensions")
    require(contract.low_frequency_rmse_max > 0,
            "low_frequency_rmse_max must be positive")
    require(0 < contract.edge_gradient_correlation_min <= 1,
            "edge_gradient_correlation_min must be in (0, 1]")
    require(0 < contract.edge_energy_ratio_min <= 1 <= contract.edge_energy_ratio_max,
            "edge-energy ratio bounds must straddle 1")
    require(contract.periodic_lag_min_pixels < contract.periodic_lag_max_pixels and
            contract.periodic_lag_max_pixels < min(contract.width, contract.height),
            "periodic residual lag range is invalid")
    require(0 < contract.periodic_autocorrelation_max < 1,
            "periodic_autocorrelation_max must be in (0, 1)")
    return contract


def unpack_header(data: bytes) -> tuple[int, ...]:
    require(len(data) >= 54, "BMP header is truncated")
    require(data[:2] == b"BM", "File is not a Windows BMP")
    return (
        struct.unpack_from("<I", data, 2)[0],
        struct.unpack_from("<H", data, 6)[0],
        struct.unpack_from("<H", data, 8)[0],
        struct.unpack_from("<I", data, 10)[0],
        struct.unpack_from("<I", data, 14)[0],
        struct.unpack_from("<i", data, 18)[0],
        struct.unpack_from("<i", data, 22)[0],
        struct.unpack_from("<H", data, 26)[0],
        struct.unpack_from("<H", data, 28)[0],
        struct.unpack_from("<I", data, 30)[0],
        struct.unpack_from("<I", data, 34)[0],
        struct.unpack_from("<I", data, 46)[0],
        struct.unpack_from("<I", data, 50)[0],
    )


def decode_pixels(data: bytes, contract: SleepScreenContract, top_down: bool) -> list[bytearray]:
    rows: list[bytearray] = []
    for logical_y in range(contract.height):
        stored_y = logical_y if top_down else contract.height - 1 - logical_y
        start = contract.pixel_offset + stored_y * contract.row_bytes
        packed = data[start:start + contract.row_bytes]
        require(len(packed) == contract.row_bytes, "BMP pixel rows are truncated")
        row = bytearray(contract.width)
        for x in range(contract.width):
            value = packed[x // 2]
            index = value >> 4 if x % 2 == 0 else value & 0x0F
            require(index < len(contract.palette),
                    f"Pixel ({x},{logical_y}) uses palette index {index}; only 0..3 are native")
            row[x] = index
        rows.append(row)
    return rows


def white_per_mille(values: list[int]) -> int:
    return sum(value == 3 for value in values) * 1000 // len(values)


def validate_bytes(data: bytes, contract: SleepScreenContract) -> dict[str, Any]:
    require(len(data) == contract.file_bytes,
            f"Wrong byte count: {len(data)}; expected exactly {contract.file_bytes}")
    (declared_size, reserved1, reserved2, pixel_offset, dib_size, width, raw_height,
     planes, bits_per_pixel, compression, image_bytes, colors_used,
     important_colors) = unpack_header(data)
    require(declared_size == len(data), "BMP declared size does not match the file")
    require(reserved1 == 0 and reserved2 == 0, "BMP reserved header fields must be zero")
    require(pixel_offset == contract.pixel_offset, f"BMP pixel offset must be {contract.pixel_offset}")
    require(dib_size == 40, "BMP must use the 40-byte BITMAPINFOHEADER")
    require(width == contract.width and abs(raw_height) == contract.height,
            f"BMP must be exact portrait {contract.width}x{contract.height}; got {width}x{abs(raw_height)}")
    require(planes == 1, "BMP must contain exactly one plane")
    require(bits_per_pixel == contract.bits_per_pixel,
            f"BMP must be {contract.bits_per_pixel}-bpp native grayscale, not {bits_per_pixel}-bpp")
    require(compression == 0, "BMP must be uncompressed BI_RGB")
    require(image_bytes == contract.row_bytes * contract.height,
            "BMP image byte count must equal the exact native row payload")
    require(colors_used == len(contract.palette), "BMP must declare exactly four palette colors")
    require(important_colors in (0, len(contract.palette)),
            "BMP important-color count must be zero or four")

    expected_palette = b"".join(bytes((level, level, level, 0)) for level in contract.palette)
    actual_palette = data[54:contract.pixel_offset]
    require(actual_palette == expected_palette,
            "BMP palette must be exact native BGRA gray entries 0, 85, 170 and 255")

    rows = decode_pixels(data, contract, raw_height < 0)
    levels_used = sorted({value for row in rows for value in row})
    require(len(levels_used) >= contract.minimum_gray_levels_used,
            "Sleep screen uses too few native gray levels; likely a one-bit dither stored in a 4-bpp wrapper")

    scan = contract.edge_scan_pixels
    bands = {
        "left": [rows[y][x] for y in range(contract.height) for x in range(scan)],
        "right": [rows[y][x] for y in range(contract.height)
                  for x in range(contract.width - scan, contract.width)],
        "top": [rows[y][x] for y in range(scan) for x in range(contract.width)],
        "bottom": [rows[y][x] for y in range(contract.height - scan, contract.height)
                   for x in range(contract.width)],
    }
    edge_white = {name: white_per_mille(values) for name, values in bands.items()}
    for name, per_mille in edge_white.items():
        require(per_mille < contract.edge_white_per_mille,
                f"Obvious white {name} gutter detected ({per_mille / 10:.1f}% white over {scan}px)")

    return {
        "bytes": len(data),
        "width": width,
        "height": abs(raw_height),
        "bits_per_pixel": bits_per_pixel,
        "gray_levels_used": levels_used,
        "edge_white_per_mille": edge_white,
    }


def pooled_values(image: Image.Image, block: int) -> tuple[list[int], int, int]:
    width = image.width // block
    height = image.height // block
    pooled = image.resize((width, height), Image.Resampling.BOX)
    return image_values(pooled), width, height


def image_values(image: Image.Image) -> list[int]:
    flattened = getattr(image, "get_flattened_data", None)
    return list(flattened() if flattened is not None else image.getdata())


def gradients(values: list[int], width: int, height: int) -> list[float]:
    output: list[float] = []
    for y in range(height):
        start = y * width
        output.extend(values[start + x + 1] - values[start + x] for x in range(width - 1))
    for y in range(height - 1):
        start = y * width
        next_start = start + width
        output.extend(values[next_start + x] - values[start + x] for x in range(width))
    return output


def pearson(left: list[float], right: list[float]) -> float:
    require(len(left) == len(right) and len(left) > 1, "Perceptual comparison vectors are invalid")
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    covariance = sum((a - left_mean) * (b - right_mean) for a, b in zip(left, right))
    left_energy = sum((value - left_mean) ** 2 for value in left)
    right_energy = sum((value - right_mean) ** 2 for value in right)
    if left_energy < 1e-9 or right_energy < 1e-9:
        return 1.0 if left_energy < 1e-9 and right_energy < 1e-9 else 0.0
    return covariance / math.sqrt(left_energy * right_energy)


def periodic_residual_score(candidate: list[int], master: list[int],
                            contract: SleepScreenContract) -> tuple[float, str, int]:
    width = contract.width
    height = contract.height
    block = contract.periodic_residual_block_pixels
    residual = [float(value - reference) for value, reference in zip(candidate, master)]
    highpass = [0.0] * len(residual)
    for y0 in range(0, height, block):
        for x0 in range(0, width, block):
            indices = [
                y * width + x
                for y in range(y0, min(y0 + block, height))
                for x in range(x0, min(x0 + block, width))
            ]
            average = sum(residual[index] for index in indices) / len(indices)
            for index in indices:
                highpass[index] = residual[index] - average

    def shifted_correlation(dx: int, dy: int) -> float:
        numerator = 0.0
        left_energy = 0.0
        right_energy = 0.0
        for y in range(height - dy):
            left_start = y * width
            right_start = (y + dy) * width + dx
            for x in range(width - dx):
                left = highpass[left_start + x]
                right = highpass[right_start + x]
                numerator += left * right
                left_energy += left * left
                right_energy += right * right
        if left_energy < 1e-9 or right_energy < 1e-9:
            return 0.0
        return numerator / math.sqrt(left_energy * right_energy)

    best_score = 0.0
    best_axis = "none"
    best_lag = 0
    for lag in range(contract.periodic_lag_min_pixels, contract.periodic_lag_max_pixels + 1):
        for axis, dx, dy in (("horizontal", lag, 0), ("vertical", 0, lag)):
            score = abs(shifted_correlation(dx, dy))
            if score > best_score:
                best_score = score
                best_axis = axis
                best_lag = lag
    return best_score, best_axis, best_lag


def validate_perceptual(rows: list[bytearray], source_path: Path,
                        contract: SleepScreenContract) -> dict[str, Any]:
    require(source_path.is_file(), f"Explicit sleep-screen master is missing: {source_path}")
    try:
        with Image.open(source_path) as opened:
            opened.load()
            source_dimensions = list(opened.size)
            master = ImageOps.fit(
                ImageOps.exif_transpose(opened).convert("L"),
                (contract.width, contract.height),
                method=Image.Resampling.LANCZOS,
                centering=(0.5, 0.5),
            )
    except (OSError, ValueError) as error:
        raise SleepScreenError(f"Could not decode the explicit sleep-screen master: {source_path}") from error

    candidate_values = [contract.palette[index] for row in rows for index in row]
    candidate = Image.new("L", (contract.width, contract.height))
    candidate.putdata(candidate_values)
    master_values = image_values(master)

    candidate_low, low_width, low_height = pooled_values(candidate, contract.low_frequency_block_pixels)
    master_low, _, _ = pooled_values(master, contract.low_frequency_block_pixels)
    low_rmse = math.sqrt(
        sum((value - reference) ** 2 for value, reference in zip(candidate_low, master_low)) /
        len(candidate_low)
    )
    require(low_rmse <= contract.low_frequency_rmse_max,
            f"Low-frequency tone RMSE {low_rmse:.3f} exceeds {contract.low_frequency_rmse_max:.3f}; "
            "the conversion is too flat, biased or posterized relative to its master")

    candidate_edge, edge_width, edge_height = pooled_values(candidate, contract.edge_detail_block_pixels)
    master_edge, _, _ = pooled_values(master, contract.edge_detail_block_pixels)
    candidate_gradients = gradients(candidate_edge, edge_width, edge_height)
    master_gradients = gradients(master_edge, edge_width, edge_height)
    edge_correlation = pearson(candidate_gradients, master_gradients)
    candidate_energy = sum(abs(value) for value in candidate_gradients) / len(candidate_gradients)
    master_energy = sum(abs(value) for value in master_gradients) / len(master_gradients)
    edge_energy_ratio = candidate_energy / master_energy if master_energy > 1e-9 else (
        1.0 if candidate_energy <= 1e-9 else math.inf
    )
    require(edge_correlation >= contract.edge_gradient_correlation_min,
            f"Edge-detail correlation {edge_correlation:.3f} is below "
            f"{contract.edge_gradient_correlation_min:.3f}; subject detail was not retained")
    require(contract.edge_energy_ratio_min <= edge_energy_ratio <= contract.edge_energy_ratio_max,
            f"Edge-energy ratio {edge_energy_ratio:.3f} is outside "
            f"{contract.edge_energy_ratio_min:.3f}..{contract.edge_energy_ratio_max:.3f}")

    periodic_score, periodic_axis, periodic_lag = periodic_residual_score(
        candidate_values, master_values, contract
    )
    require(periodic_score <= contract.periodic_autocorrelation_max,
            f"Periodic conversion pattern detected: residual autocorrelation {periodic_score:.3f} at "
            f"{periodic_lag}px {periodic_axis} lag exceeds {contract.periodic_autocorrelation_max:.3f}")

    return {
        "master": str(source_path),
        "master_dimensions": source_dimensions,
        "master_fit": "center-cover",
        "low_frequency_grid": [low_width, low_height],
        "low_frequency_rmse": round(low_rmse, 6),
        "edge_gradient_correlation": round(edge_correlation, 6),
        "edge_energy_ratio": round(edge_energy_ratio, 6),
        "periodic_residual_autocorrelation": round(periodic_score, 6),
        "periodic_peak_axis": periodic_axis,
        "periodic_peak_lag_pixels": periodic_lag,
    }


def validate_file(path: Path, source_path: Path, contract: SleepScreenContract) -> dict[str, Any]:
    require(path.is_file(), f"Sleep-screen file is missing: {path}")
    try:
        data = path.read_bytes()
        report = validate_bytes(data, contract)
        raw_height = struct.unpack_from("<i", data, 22)[0]
        rows = decode_pixels(data, contract, raw_height < 0)
        report["perceptual"] = validate_perceptual(rows, source_path, contract)
        return report
    except OSError as error:
        raise SleepScreenError(f"Could not read sleep-screen file: {path}") from error


def build_self_test_bmp(contract: SleepScreenContract) -> bytes:
    output = bytearray(contract.file_bytes)
    output[:2] = b"BM"
    struct.pack_into("<I", output, 2, contract.file_bytes)
    struct.pack_into("<I", output, 10, contract.pixel_offset)
    struct.pack_into("<I", output, 14, 40)
    struct.pack_into("<i", output, 18, contract.width)
    struct.pack_into("<i", output, 22, contract.height)
    struct.pack_into("<H", output, 26, 1)
    struct.pack_into("<H", output, 28, contract.bits_per_pixel)
    struct.pack_into("<I", output, 34, contract.row_bytes * contract.height)
    struct.pack_into("<I", output, 46, 4)
    struct.pack_into("<I", output, 50, 4)
    output[54:70] = b"".join(bytes((level, level, level, 0)) for level in contract.palette)
    for y in range(contract.height):
        start = contract.pixel_offset + y * contract.row_bytes
        for x in range(0, contract.width, 2):
            first = (x // 24 + y // 24) % 4
            second = ((x + 1) // 24 + y // 24) % 4
            output[start + x // 2] = (first << 4) | second
    return bytes(output)


def build_4bpp_bmp(contract: SleepScreenContract, indices: list[int]) -> bytes:
    require(len(indices) == contract.width * contract.height,
            "Self-test pixel buffer does not match X3 geometry")
    output = bytearray(contract.file_bytes)
    output[:2] = b"BM"
    struct.pack_into("<I", output, 2, contract.file_bytes)
    struct.pack_into("<I", output, 10, contract.pixel_offset)
    struct.pack_into("<I", output, 14, 40)
    struct.pack_into("<i", output, 18, contract.width)
    struct.pack_into("<i", output, 22, -contract.height)
    struct.pack_into("<H", output, 26, 1)
    struct.pack_into("<H", output, 28, contract.bits_per_pixel)
    struct.pack_into("<I", output, 34, contract.row_bytes * contract.height)
    struct.pack_into("<I", output, 46, 4)
    struct.pack_into("<I", output, 50, 4)
    output[54:70] = b"".join(bytes((level, level, level, 0)) for level in contract.palette)
    for y in range(contract.height):
        row_start = contract.pixel_offset + y * contract.row_bytes
        source_start = y * contract.width
        for x in range(0, contract.width, 2):
            high = indices[source_start + x]
            low = indices[source_start + x + 1]
            require(0 <= high <= 3 and 0 <= low <= 3, "Self-test palette index escaped 0..3")
            output[row_start + x // 2] = (high << 4) | low
    return bytes(output)


def build_quality_master(contract: SleepScreenContract) -> Image.Image:
    image = Image.new("L", (contract.width, contract.height))
    pixels: list[int] = []
    for y in range(contract.height):
        for x in range(contract.width):
            gradient = 26 + 154 * y / max(1, contract.height - 1) + 42 * x / max(1, contract.width - 1)
            texture = 14 * math.sin(x / 17.0) + 9 * math.cos(y / 23.0)
            pixels.append(round(max(10, min(242, gradient + texture))))
    image.putdata(pixels)
    draw = ImageDraw.Draw(image)
    draw.ellipse((120, 190, 410, 690), fill=52, outline=205, width=5)
    draw.polygon(((170, 300), (240, 235), (290, 325), (355, 245), (385, 360)), fill=96)
    draw.line((145, 520, 385, 430), fill=232, width=7)
    draw.rectangle((36, 72, 178, 158), outline=18, width=6)
    return image


def error_diffuse_native_indices(master: Image.Image, contract: SleepScreenContract) -> list[int]:
    source = image_values(master)
    output = [0] * len(source)
    current_errors = [0.0] * (contract.width + 2)
    next_errors = [0.0] * (contract.width + 2)
    for y in range(contract.height):
        row_start = y * contract.width
        for x in range(contract.width):
            value = max(0.0, min(255.0, source[row_start + x] + current_errors[x + 1]))
            index = max(0, min(3, math.floor(value / 85.0 + 0.5)))
            output[row_start + x] = index
            error = value - index * 85
            current_errors[x + 2] += error * 7 / 16
            next_errors[x] += error * 3 / 16
            next_errors[x + 1] += error * 5 / 16
            next_errors[x + 2] += error / 16
        current_errors, next_errors = next_errors, current_errors
        for index in range(len(next_errors)):
            next_errors[index] = 0.0
    return output


def self_test(contract: SleepScreenContract) -> None:
    baseline = build_self_test_bmp(contract)
    validate_bytes(baseline, contract)

    mutations: list[tuple[str, bytes]] = []
    wrong_width = bytearray(baseline)
    struct.pack_into("<i", wrong_width, 18, 480)
    mutations.append(("legacy 480 width", bytes(wrong_width)))
    wrong_bpp = bytearray(baseline)
    struct.pack_into("<H", wrong_bpp, 28, 1)
    mutations.append(("legacy one-bit storage", bytes(wrong_bpp)))
    wrong_palette = bytearray(baseline)
    wrong_palette[58:62] = bytes((64, 64, 64, 0))
    mutations.append(("non-native palette", bytes(wrong_palette)))
    white_edge = bytearray(baseline)
    for y in range(contract.height):
        start = contract.pixel_offset + y * contract.row_bytes
        for x in range(contract.edge_scan_pixels):
            byte_index = start + x // 2
            if x % 2 == 0:
                white_edge[byte_index] = (white_edge[byte_index] & 0x0F) | 0x30
            else:
                white_edge[byte_index] = (white_edge[byte_index] & 0xF0) | 0x03
    mutations.append(("white edge gutter", bytes(white_edge)))
    for label, mutated in mutations:
        try:
            validate_bytes(mutated, contract)
        except SleepScreenError:
            continue
        raise SleepScreenError(f"Self-test accepted forbidden mutation: {label}")

    with tempfile.TemporaryDirectory(prefix="xtinct-x3-sleep-gate-") as directory:
        root = Path(directory)
        master_path = root / "master.png"
        master = build_quality_master(contract)
        master.save(master_path)

        path = root / "sleep.bmp"
        accepted = build_4bpp_bmp(contract, error_diffuse_native_indices(master, contract))
        path.write_bytes(accepted)
        validate_file(path, master_path, contract)

        master_values = image_values(master)
        flat_indices = [
            min(3, (round(255 * ((value / 255) ** 0.78)) + 42) // 85)
            for value in master_values
        ]
        bayer = (
            (0, 8, 2, 10),
            (12, 4, 14, 6),
            (3, 11, 1, 9),
            (15, 7, 13, 5),
        )
        ordered_indices: list[int] = []
        for y in range(contract.height):
            for x in range(contract.width):
                value = master_values[y * contract.width + x]
                base = value // 85
                remainder = value - base * 85
                threshold = (bayer[y % 4][x % 4] + 0.5) * 85 / 16
                ordered_indices.append(min(3, base + (1 if remainder > threshold else 0)))

        for label, indices in (
            ("flat posterized tone map", flat_indices),
            ("periodic ordered dither", ordered_indices),
        ):
            mutated_path = root / (label.replace(" ", "-") + ".bmp")
            mutated_path.write_bytes(build_4bpp_bmp(contract, indices))
            try:
                validate_file(mutated_path, master_path, contract)
            except SleepScreenError:
                continue
            raise SleepScreenError(f"Self-test accepted forbidden perceptual mutation: {label}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sleep_bmp", nargs="?", type=Path)
    parser.add_argument("--source", type=Path,
                        help="explicit unquantised master image used to create the sleep BMP")
    parser.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    parser.add_argument("--json", action="store_true", dest="json_output")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    try:
        contract = load_contract(args.contract.resolve())
        if args.self_test:
            self_test(contract)
            print("X3_SLEEP_SCREEN_SELF_TEST_OK")
            return 0
        require(args.sleep_bmp is not None, "Provide the local sleep.bmp path")
        require(args.source is not None,
                "Provide --source with the explicit unquantised master image")
        path = args.sleep_bmp.resolve()
        source_path = args.source.resolve()
        report = validate_file(path, source_path, contract)
        if args.json_output:
            print(json.dumps({"path": str(path), "verdict": "pass", **report}, sort_keys=True))
        else:
            edges = report["edge_white_per_mille"]
            perceptual = report["perceptual"]
            print(
                "X3_SLEEP_SCREEN_OK "
                f"path={path} bytes={report['bytes']} "
                f"dimensions={report['width']}x{report['height']} "
                f"bpp={report['bits_per_pixel']} levels={report['gray_levels_used']} "
                f"edge_white_per_mille={edges} "
                f"tone_rmse={perceptual['low_frequency_rmse']} "
                f"edge_correlation={perceptual['edge_gradient_correlation']} "
                f"periodic_score={perceptual['periodic_residual_autocorrelation']}"
            )
        return 0
    except (SleepScreenError, OSError, ValueError, struct.error) as error:
        print(f"X3_SLEEP_SCREEN_FAIL: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

