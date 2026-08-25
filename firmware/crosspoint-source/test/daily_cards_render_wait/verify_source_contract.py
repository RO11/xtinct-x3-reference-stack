#!/usr/bin/env python3
"""Fail closed if Daily Cards can assert, deadlock, or sync before its busy paint."""

from __future__ import annotations

import sys
from pathlib import Path


class ContractError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    require(start >= 0, f"Missing function: {signature}")
    brace = source.find("{", start + len(signature))
    require(brace >= 0, f"Missing function body: {signature}")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise ContractError(f"Unterminated function: {signature}")


def verify_sources(manager_cpp: str, manager_h: str, activity_cpp: str,
                   activity_h: str, cards_cpp: str) -> None:
    require("bool requestUpdateAndWait();" in manager_h,
            "ActivityManager render wait must expose success/failure")
    require("virtual bool requestUpdateAndWait();" in activity_h,
            "Activity render wait must expose success/failure")
    require("bool Activity::requestUpdateAndWait()" in activity_cpp and
            "return activityManager.requestUpdateAndWait();" in activity_cpp,
            "Activity drops the bounded render-wait result")

    wait = function_body(manager_cpp, "bool ActivityManager::requestUpdateAndWait()")
    for fragment in (
        "(void)ulTaskNotifyTake(pdTRUE, 0)",
        "if (isRenderTask || alreadyWaiting || holdingRenderLock)",
        "if (xTaskNotify(renderTaskHandle, 1, eIncrement) != pdPASS)",
        "pdMS_TO_TICKS(30000)",
        "if (ulTaskNotifyTake(pdTRUE, RENDER_WAIT_TIMEOUT) == 0)",
        "if (waitingTaskHandle == currTaskHandler) waitingTaskHandle = nullptr",
        "return false",
        "return true",
    ):
        require(fragment in wait, f"Bounded render handshake lost: {fragment}")
    require("assert(" not in wait, "Render handshake may reboot on a recoverable scheduling state")
    require("portMAX_DELAY" not in wait, "Render handshake may wait forever")
    require(wait.count("taskENTER_CRITICAL(&activityManagerSpinlock)") >= 3 and
            wait.count("taskEXIT_CRITICAL(&activityManagerSpinlock)") >= 3,
            "Waiter registration/failure/timeout cleanup is not atomic")

    loop = function_body(cards_cpp, "void DailyCardsActivity::loop()")
    checked_start = "if (!syncScreenPainted && !requestUpdateAndWait())"
    require(checked_start in loop,
            "Daily Cards may start network work without a confirmed busy paint")
    require(loop.find(checked_start) < loop.find("runSync();"),
            "Daily Cards render admission must precede runSync")
    for fragment in (
        "Daily Cards sync cancelled: busy screen was not confirmed",
        "Daily Cards refresh cancelled: busy screen was not confirmed",
        "forcedSyncPending = false",
        "state = cardCount > 0 ? State::CARD_READY : State::NO_CARD",
    ):
        require(fragment in loop, f"Daily Cards render failure is not fail-safe: {fragment}")
    require(loop.count("if (!requestUpdateAndWait())") >= 2,
            "Daily Cards ignores a render-wait failure")


def verify_project(project_root: Path) -> None:
    verify_sources(
        (project_root / "src/activities/ActivityManager.cpp").read_text(encoding="utf-8"),
        (project_root / "src/activities/ActivityManager.h").read_text(encoding="utf-8"),
        (project_root / "src/activities/Activity.cpp").read_text(encoding="utf-8"),
        (project_root / "src/activities/Activity.h").read_text(encoding="utf-8"),
        (project_root / "src/activities/home/DailyCardsActivity.cpp").read_text(encoding="utf-8"),
    )


def self_test(project_root: Path) -> None:
    manager_cpp = (project_root / "src/activities/ActivityManager.cpp").read_text(encoding="utf-8")
    manager_h = (project_root / "src/activities/ActivityManager.h").read_text(encoding="utf-8")
    activity_cpp = (project_root / "src/activities/Activity.cpp").read_text(encoding="utf-8")
    activity_h = (project_root / "src/activities/Activity.h").read_text(encoding="utf-8")
    cards_cpp = (project_root / "src/activities/home/DailyCardsActivity.cpp").read_text(encoding="utf-8")
    verify_sources(manager_cpp, manager_h, activity_cpp, activity_h, cards_cpp)

    mutations = (
        (manager_cpp.replace("pdMS_TO_TICKS(30000)", "portMAX_DELAY", 1), cards_cpp,
         "Bounded render handshake lost"),
        (manager_cpp.replace(
            'LOG_ERR("ACT", "Render wait refused (render=%u waiting=%u lock=%u)",',
            'assert(!alreadyWaiting); LOG_ERR("ACT", "Render wait refused (render=%u waiting=%u lock=%u)",', 1),
         cards_cpp, "Render handshake may reboot"),
        (manager_cpp, cards_cpp.replace(
            "if (!syncScreenPainted && !requestUpdateAndWait())",
            "if (!syncScreenPainted) requestUpdateAndWait(); if (false)", 1),
         "without a confirmed busy paint"),
    )
    for mutated_manager, mutated_cards, expected in mutations:
        try:
            verify_sources(mutated_manager, manager_h, activity_cpp, activity_h, mutated_cards)
        except ContractError as error:
            require(expected in str(error), f"Unexpected mutation failure: {error}")
        else:
            raise ContractError(f"Mutation unexpectedly passed: {expected}")


def main() -> int:
    project_root = Path(__file__).resolve().parents[2]
    try:
        if sys.argv[1:] == ["--self-test"]:
            self_test(project_root)
            print("DAILY_CARDS_RENDER_WAIT_SELF_TEST_OK")
            return 0
        if sys.argv[1:]:
            raise ContractError("Usage: verify_source_contract.py [--self-test]")
        verify_project(project_root)
    except (ContractError, OSError, UnicodeError) as error:
        print(f"DAILY_CARDS_RENDER_WAIT_ERROR: {error}", file=sys.stderr)
        return 1
    print("DAILY_CARDS_RENDER_WAIT_SOURCE_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
