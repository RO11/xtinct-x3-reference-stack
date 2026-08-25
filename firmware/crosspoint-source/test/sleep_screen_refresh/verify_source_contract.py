#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"sleep-screen refresh contract failed: {message}")


sleep = read("src/activities/boot_sleep/SleepActivity.cpp")
hal = read("lib/hal/HalDisplay.cpp")
policy = read("lib/hal/SleepScreenRefreshPolicy.h")
uc8253 = read("freeink-sdk/libs/display/FreeInkDisplay/src/driver/Uc8253X3Driver.cpp")
uc8279 = read("freeink-sdk/libs/display/FreeInkDisplay/src/driver/Uc8279Driver.cpp")

require("renderer.displaySleepGrayscaleBase();" in sleep,
        "custom grayscale sleep image must use its dedicated quality path")
require(sleep.count("renderer.displayGrayBuffer();") == 1,
        "sleep grayscale must emit exactly one final two-plane gray waveform")
require("displayGrayscaleBase(HalDisplay::FULL_REFRESH)" not in sleep,
        "gray LUT must not be fed by the incompatible FULL enum path")
require("X3_VALIDATED_POST_CONDITION_PASSES = 1" in policy,
        "condition count must remain the single hardware-validated pass")
require("X3_MAX_SAFE_POST_CONDITION_PASSES = 1" in policy,
        "arbitrary repeated condition passes must remain blocked")
require("einkDisplay.requestResync(SleepScreenRefreshPolicy::X3_VALIDATED_POST_CONDITION_PASSES);" in hal,
        "sleep path must explicitly request the validated X3 condition pass")
require("convertRefreshMode(RefreshMode::HALF_REFRESH)" in hal,
        "sleep grayscale base must preserve calibrated HALF fallback semantics")

# UC8253: clean full, one NORMAL condition, automatic fast baseline settle,
# then pre-BW-mid and the final gray bank. These source checks prevent a future
# refactor from silently reducing the useful passes or adding blind FULL loops.
for snippet in (
    "_forcedConditionPassesNext = settlePasses",
    "loadBankCdi(bus, 0xA9, 0x07, _cfg.normal)",
    "if (doFullSync)",
    "loadBankCdi(bus, 0x29, 0x07, _cfg.fast)",
    "loadBankCdi(bus, 0xA9, 0x07, _cfg.preBwMid)",
    "loadBankCdi(bus, 0x29, 0x07, _cfg.gc)",
):
    require(snippet in uc8253, f"UC8253 calibrated stage missing: {snippet}")

# UC8279 has different LUT framing. It intentionally ignores a numeric settle
# count and uses its own GC + pre-BW-mid + AA sequence; do not replay UC8253's
# NORMAL bank against this controller.
for snippet in (
    "(void)settlePasses",
    "_forceFullSyncNext = true",
    "kUc8279X3_BwGc",
    "kUc8279X3_XtfPreBwMid",
    "loadXtfAa(bus)",
):
    require(snippet in uc8279, f"UC8279 controller-owned stage missing: {snippet}")

print("sleep-screen refresh source contract: PASS")
