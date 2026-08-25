#!/usr/bin/env python3
"""Export the real Lyra 32px icon bitmaps for the browser simulator."""

from __future__ import annotations

import re
from pathlib import Path


SIM_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = SIM_ROOT.parents[1]
ICON_ROOT = SOURCE_ROOT / "src/components/icons"
OUTPUT = SIM_ROOT / "web/assets/x3-icons.js"

ICONS = {
    "Files": ("folder.h", "FolderIcon"),
    "Recents": ("recent.h", "RecentIcon"),
    "File Transfer": ("transfer.h", "TransferIcon"),
    "XTINCT Inbox": ("inbox.h", "InboxIcon"),
    "Daily Cards": ("cards.h", "CardsIcon"),
    "Phone Sync": ("transfer.h", "TransferIcon"),
    "Phone Wi-Fi": ("wifi.h", "WifiIcon"),
    "Settings": ("settings2.h", "Settings2Icon"),
    "Cover": ("cover.h", "CoverIcon"),
    "Book": ("book.h", "BookIcon"),
}


def read_icon(filename: str, symbol: str) -> list[int]:
    source = (ICON_ROOT / filename).read_text(encoding="utf-8")
    match = re.search(
        rf"static\s+const\s+uint8_t\s+{re.escape(symbol)}\[\]\s*=\s*\{{(.*?)\}};",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise RuntimeError(f"Could not find {symbol} in {filename}")
    values = [int(value, 16) for value in re.findall(r"0x[0-9A-Fa-f]{2}", match.group(1))]
    if len(values) != 128:
        raise RuntimeError(f"{symbol} must be exactly 32x32 1bpp (128 bytes), got {len(values)}")
    return values


def main() -> int:
    lines = [
        "// Generated from src/components/icons by scripts/export_icons.py.",
        "// The firmware format is 32x32, MSB-first, bit 0 = ink.",
        "export const X3_ICONS = Object.freeze({",
    ]
    for label, (filename, symbol) in ICONS.items():
        values = read_icon(filename, symbol)
        byte_text = ", ".join(f"0x{value:02x}" for value in values)
        lines.append(f"  {label!r}: Object.freeze([{byte_text}]),")
    lines.append("});")
    lines.append("")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(f"X3_SIM_ICONS_OK path={OUTPUT} icons={len(ICONS)} bytes={OUTPUT.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
