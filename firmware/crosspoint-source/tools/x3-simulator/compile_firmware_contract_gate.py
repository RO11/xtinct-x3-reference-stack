#!/usr/bin/env python3
"""Compile actual firmware constexpr network policies with the ESP32-C3 C++ compiler."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


SIM_ROOT = Path(__file__).resolve().parent
CROSSPOINT_ROOT = SIM_ROOT.parents[1]
SOURCE = SIM_ROOT / "tests" / "firmware_network_contract_compile.cpp"


def find_compiler() -> Path:
    candidates: list[Path] = []
    configured = os.environ.get("CXX")
    if configured:
        candidates.append(Path(configured))
    for name in ("riscv32-esp-elf-g++.exe", "riscv32-esp-elf-g++", "clang++", "g++"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    user_profile = os.environ.get("USERPROFILE")
    if user_profile:
        candidates.append(
            Path(user_profile)
            / ".platformio"
            / "packages"
            / "toolchain-riscv32-esp"
            / "bin"
            / "riscv32-esp-elf-g++.exe"
        )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise RuntimeError("ESP32-C3/host C++ compiler unavailable; firmware contract compile gate cannot be skipped")


def verify() -> None:
    compiler = find_compiler()
    if not SOURCE.is_file():
        raise RuntimeError("firmware network contract compile source is missing")
    with tempfile.TemporaryDirectory(prefix="xtinct-x3-network-compile-") as temporary:
        output = Path(temporary) / "firmware-network-contract.o"
        command = [
            str(compiler),
            "-std=gnu++20",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-I",
            str(CROSSPOINT_ROOT),
            "-c",
            str(SOURCE),
            "-o",
            str(output),
        ]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if completed.returncode != 0 or not output.is_file() or output.stat().st_size == 0:
            detail = (completed.stdout + "\n" + completed.stderr).strip()
            raise RuntimeError(f"firmware network contract compile gate failed with {compiler}: {detail}")


def main() -> int:
    verify()
    print("firmware network constexpr compile gate: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

