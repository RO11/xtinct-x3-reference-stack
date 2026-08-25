#!/usr/bin/env python3
"""Fail closed if XTINCT can persist secret-bearing crash memory."""

from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path


class CrashSecretPolicyError(RuntimeError):
    """The firmware crash-retention policy is incomplete or has regressed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CrashSecretPolicyError(message)


ESP_IDF_ABORT_PC_PREFIX = "abort() was called at PC 0x"
ESP_IDF_ABORT_PC_CORE_SUFFIX = " on core "


def cpp_function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    require(start >= 0, f"Missing crash-policy function: {signature}")
    brace = source.find("{", start + len(signature))
    require(brace >= 0, f"Missing body for crash-policy function: {signature}")
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : index]
    raise CrashSecretPolicyError(f"Unterminated crash-policy function: {signature}")


def modeled_abort_caller_pc(message: str) -> int | None:
    """Model the fixed, fail-closed ESP-IDF abort() message grammar."""
    if not message.startswith(ESP_IDF_ABORT_PC_PREFIX):
        return None
    remainder = message[len(ESP_IDF_ABORT_PC_PREFIX) :]
    required_length = 8 + len(ESP_IDF_ABORT_PC_CORE_SUFFIX) + 1
    if len(remainder) != required_length:
        return None
    digits = remainder[:8]
    if any(character not in "0123456789abcdefABCDEF" for character in digits):
        return None
    if remainder[8 : 8 + len(ESP_IDF_ABORT_PC_CORE_SUFFIX)] != ESP_IDF_ABORT_PC_CORE_SUFFIX:
        return None
    core = remainder[-1]
    if core not in "0123456789":
        return None
    return int(digits, 16)


def verify_abort_pc_privacy_model() -> None:
    valid = {
        "abort() was called at PC 0x4201A2B3 on core 0": 0x4201A2B3,
        "abort() was called at PC 0xabcdef12 on core 9": 0xABCDEF12,
    }
    invalid = (
        "Abort() was called at PC 0x4201A2B3 on core 0",
        "abort() was called at PC 0x4201A2B on core 0",
        "abort() was called at PC 0x4201A2B30 on core 0",
        "abort() was called at PC 0x4201A2BG on core 0",
        "abort() was called at PC 0x4201A2B3 on core 00",
        "abort() was called at PC 0x4201A2B3 on core 0 SecretTokenABC123",
        "abort() was called at PC 0x4201A2B3 SecretTokenABC123",
        "SecretTokenABC123 abort() was called at PC 0x4201A2B3 on core 0",
    )
    for message, expected in valid.items():
        require(modeled_abort_caller_pc(message) == expected, f"Valid abort PC was rejected: {message!r}")
    for message in invalid:
        require(modeled_abort_caller_pc(message) is None, f"Secret-bearing/lookalike abort was accepted: {message!r}")

    report = "Abort caller PC: 0x%08X" % valid["abort() was called at PC 0x4201A2B3 on core 0"]
    for secret in ("SecretTokenABC123", "SecretToken", "ABC123"):
        require(secret not in report, f"Abort PC report leaked secret text: {secret}")


def sdkconfig_value(platformio_text: str, name: str) -> str | None:
    match = re.search(rf"(?m)^\s*{re.escape(name)}\s*=\s*([^;\s]+)\s*$", platformio_text)
    return match.group(1) if match else None


def verify_policy(project_root: Path) -> None:
    platformio = (project_root / "platformio.ini").read_text(encoding="utf-8")
    hal_system = (project_root / "lib" / "hal" / "HalSystem.cpp").read_text(encoding="utf-8")

    required_sdkconfig = {
        "CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH": "n",
        "CONFIG_ESP_COREDUMP_ENABLE_TO_UART": "n",
        "CONFIG_ESP_COREDUMP_ENABLE_TO_NONE": "y",
        "CONFIG_ESP_COREDUMP_ENABLE": "n",
        "CONFIG_ESP_COREDUMP_CHECK_BOOT": "n",
        "CONFIG_ESP_COREDUMP_LOGS": "n",
        "CONFIG_ESP_SYSTEM_PANIC_PRINT_HALT": "n",
        "CONFIG_ESP_SYSTEM_PANIC_PRINT_REBOOT": "n",
        "CONFIG_ESP_SYSTEM_PANIC_SILENT_REBOOT": "y",
        "CONFIG_ESP_SYSTEM_PANIC_GDBSTUB": "n",
    }
    for name, expected in required_sdkconfig.items():
        actual = sdkconfig_value(platformio, name)
        require(actual == expected, f"Crash policy requires {name}={expected}; found {actual!r}")

    require('Storage.open("/crash_report.txt"' in hal_system, "Sanitized crash report output is missing")
    require("panicProgramCounter" in hal_system, "Crash report no longer records a fault PC")
    require("panicReturnAddress" in hal_system, "Crash report no longer records a return address")
    require("panicMachineCause" in hal_system, "Crash report no longer records the machine cause")
    require("panicAbortCallerProgramCounter" in hal_system, "Crash report no longer records the abort caller PC")
    require("panicAbortCallerPcValidMarker" in hal_system, "Abort caller PC no longer has a retained validity marker")
    require("panicAssertCallerProgramCounter" in hal_system, "Crash report no longer records the assert caller PC")
    require("panicAssertCallerPcValidMarker" in hal_system, "Assert caller PC no longer has a retained validity marker")
    require("--wrap=__assert_func" in platformio, "Newlib assertion callsites are no longer wrapped safely")
    require(
        'PANIC_ABORT_PC_PREFIX[] = "abort() was called at PC 0x"' in hal_system,
        "Crash policy requires the fixed ESP-IDF abort caller prefix",
    )
    require(
        'PANIC_ABORT_PC_CORE_SUFFIX[] = " on core "' in hal_system,
        "Crash policy requires the fixed ESP-IDF abort core suffix",
    )

    abort_parser = cpp_function_body(hal_system, "static bool IRAM_ATTR parsePanicAbortCallerPc")
    for fragment in (
        "message[offset] != PANIC_ABORT_PC_PREFIX[offset]",
        "for (size_t index = 0; index < 8; ++index)",
        "panicHexNibble(message[offset + index], &nibble)",
        "message[offset + suffixIndex] != PANIC_ABORT_PC_CORE_SUFFIX[suffixIndex]",
        "message[offset + 1] != '\\0'",
        "*parsedPc = value",
    ):
        require(fragment in abort_parser, f"Abort caller PC parser lost its exact grammar: {fragment}")
    panic_abort_hook = cpp_function_body(hal_system, "void IRAM_ATTR __wrap_panic_abort")
    for fragment in (
        "panicAbortCallerProgramCounter = 0",
        "panicAbortCallerPcValidMarker = 0",
        "parsePanicAbortCallerPc(message, &parsedAbortCallerPc)",
        "panicAbortCallerProgramCounter = parsedAbortCallerPc",
        "panicAbortCallerPcValidMarker = PANIC_ABORT_CALLER_PC_VALID",
    ):
        require(fragment in panic_abort_hook, f"Panic wrapper lost safe abort-PC handling: {fragment}")
    require(
        "panicMessage[index] = message[index]" not in panic_abort_hook,
        "Panic wrapper may retain secret-bearing input text",
    )
    for forbidden in ("std::", "String", "malloc(", "calloc(", "realloc(", "new ", "strtol", "sscanf", "snprintf"):
        require(forbidden not in abort_parser and forbidden not in panic_abort_hook,
                f"Panic-time abort-PC path is not allocation-free/IRAM-safe: {forbidden}")

    assert_hook = cpp_function_body(hal_system, "__wrap___assert_func(const char* file")
    for fragment in (
        "(void)file",
        "(void)line",
        "(void)function",
        "(void)expression",
        "__builtin_return_address(0)",
        "panicAssertCallerPcValidMarker = PANIC_ASSERT_CALLER_PC_VALID",
        "storePanicReasonCode(PANIC_REASON_ASSERT)",
        "__real___assert_func(file, line, function, expression)",
    ):
        require(fragment in assert_hook, f"Assert caller PC wrapper lost safe handling: {fragment}")
    for forbidden in (
        "file[", "function[", "expression[", "strlen", "memcpy", "strcpy", "snprintf",
        "std::", "String", "malloc(", "calloc(", "realloc(", "new ",
    ):
        require(forbidden not in assert_hook,
                f"Assert wrapper may inspect or retain secret-bearing source text: {forbidden}")

    report_start = hal_system.find("std::string getPanicInfo(bool full)")
    report_end = hal_system.find("bool isRebootFromPanic()", report_start)
    require(report_start >= 0 and report_end > report_start, "Could not isolate the crash report serializer")
    report_source = hal_system[report_start:report_end]
    forbidden_report_fragments = {
        "panicStack": "raw panic stack storage",
        "Stack memory:": "raw stack serialization",
        "getLastLogs(": "retained log serialization",
        ".spp": "raw stack-word serialization",
        "->sp": "stack-pointer traversal",
    }
    for fragment, description in forbidden_report_fragments.items():
        require(fragment not in report_source, f"Crash report contains {description}: {fragment}")
    require("Abort caller PC: 0x" in report_source, "Crash report omits the parsed abort caller PC")
    require("Assert caller PC: 0x" in report_source, "Crash report omits the wrapped assert caller PC")

    begin_body = cpp_function_body(hal_system, "void begin()")
    clear_body = cpp_function_body(hal_system, "void clearPanic()")
    require("panicAbortCallerPcValidMarker != PANIC_ABORT_CALLER_PC_VALID" in begin_body and
            "!storedPanicReasonEquals(PANIC_REASON_ABORT)" in begin_body,
            "Retained abort caller PC is not validated against its marker and reason")
    for field in ("panicAbortCallerProgramCounter = 0", "panicAbortCallerPcValidMarker = 0"):
        require(field in begin_body and field in clear_body, f"Abort caller PC field is not cleared everywhere: {field}")
    require("panicAssertCallerPcValidMarker != PANIC_ASSERT_CALLER_PC_VALID" in begin_body and
            "!storedPanicReasonEquals(PANIC_REASON_ASSERT)" in begin_body,
            "Retained assert caller PC is not validated against its marker and reason")
    for field in ("panicAssertCallerProgramCounter = 0", "panicAssertCallerPcValidMarker = 0"):
        require(field in begin_body and field in clear_body, f"Assert caller PC field is not cleared everywhere: {field}")

    panic_hook_start = hal_system.find("void IRAM_ATTR __wrap_panic_print_backtrace")
    panic_hook_end = hal_system.find("}\n}\n\nnamespace HalSystem", panic_hook_start)
    require(panic_hook_start >= 0 and panic_hook_end > panic_hook_start, "Could not isolate the panic hook")
    panic_hook = hal_system[panic_hook_start:panic_hook_end]
    for required_field in ("registers->mepc", "registers->ra", "registers->mcause"):
        require(required_field in panic_hook, f"Panic hook is missing safe field {required_field}")
    for forbidden_fragment in ("registers->sp", "panicStack", "spp["):
        require(forbidden_fragment not in panic_hook, f"Panic hook reads secret-bearing memory: {forbidden_fragment}")

    verify_abort_pc_privacy_model()


def expect_policy_failure(project_root: Path, expected_fragment: str) -> None:
    try:
        verify_policy(project_root)
    except CrashSecretPolicyError as error:
        require(expected_fragment in str(error), f"Unexpected negative-test failure: {error}")
        return
    raise CrashSecretPolicyError(f"Negative test unexpectedly passed: {expected_fragment}")


def self_test(project_root: Path) -> None:
    verify_policy(project_root)
    with tempfile.TemporaryDirectory(prefix="xtinct-crash-policy-") as temporary_name:
        fixture_root = Path(temporary_name)
        fixture_hal_dir = fixture_root / "lib" / "hal"
        fixture_hal_dir.mkdir(parents=True)
        platformio_source = (project_root / "platformio.ini").read_text(encoding="utf-8")
        hal_source = (project_root / "lib" / "hal" / "HalSystem.cpp").read_text(encoding="utf-8")
        (fixture_root / "platformio.ini").write_text(platformio_source, encoding="utf-8")
        fixture_hal = fixture_hal_dir / "HalSystem.cpp"
        fixture_hal.write_text(hal_source, encoding="utf-8")

        unsafe_config = platformio_source.replace(
            "CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=n", "CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=y", 1
        )
        require(unsafe_config != platformio_source, "Coredump negative-test fixture did not change")
        (fixture_root / "platformio.ini").write_text(unsafe_config, encoding="utf-8")
        expect_policy_failure(fixture_root, "CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH=n")

        (fixture_root / "platformio.ini").write_text(platformio_source, encoding="utf-8")
        unsafe_serial_panic = platformio_source.replace(
            "CONFIG_ESP_SYSTEM_PANIC_PRINT_REBOOT=n", "CONFIG_ESP_SYSTEM_PANIC_PRINT_REBOOT=y", 1
        ).replace(
            "CONFIG_ESP_SYSTEM_PANIC_SILENT_REBOOT=y", "CONFIG_ESP_SYSTEM_PANIC_SILENT_REBOOT=n", 1
        )
        require(unsafe_serial_panic != platformio_source, "Serial-panic negative-test fixture did not change")
        (fixture_root / "platformio.ini").write_text(unsafe_serial_panic, encoding="utf-8")
        expect_policy_failure(fixture_root, "CONFIG_ESP_SYSTEM_PANIC_PRINT_REBOOT=n")

        (fixture_root / "platformio.ini").write_text(platformio_source, encoding="utf-8")
        unsafe_report = hal_source.replace(
            'info += "\\n\\nRaw stack memory and retained logs are intentionally omitted.";',
            'info += "\\n\\nLast logs:\\n" + getLastLogs();',
            1,
        )
        require(unsafe_report != hal_source, "Crash-report negative-test fixture did not change")
        fixture_hal.write_text(unsafe_report, encoding="utf-8")
        expect_policy_failure(fixture_root, "retained log serialization")

        fixture_hal.write_text(hal_source, encoding="utf-8")
        unsafe_abort_prefix = hal_source.replace(
            'PANIC_ABORT_PC_PREFIX[] = "abort() was called at PC 0x"',
            'PANIC_ABORT_PC_PREFIX[] = "abort"',
            1,
        )
        require(unsafe_abort_prefix != hal_source, "Abort-prefix negative-test fixture did not change")
        fixture_hal.write_text(unsafe_abort_prefix, encoding="utf-8")
        expect_policy_failure(fixture_root, "fixed ESP-IDF abort caller prefix")

        unsafe_message_copy = hal_source.replace(
            "panicAbortCallerProgramCounter = parsedAbortCallerPc;",
            "panicMessage[index] = message[index];",
            1,
        )
        require(unsafe_message_copy != hal_source, "Abort-message-copy negative-test fixture did not change")
        fixture_hal.write_text(unsafe_message_copy, encoding="utf-8")
        expect_policy_failure(fixture_root, "safe abort-PC handling")

        fixture_hal.write_text(hal_source, encoding="utf-8")
        unsafe_assert_copy = hal_source.replace(
            "(void)expression;",
            "(void)expression;\n  panicMessage[0] = expression[0];",
            1,
        )
        require(unsafe_assert_copy != hal_source, "Assert-message-copy negative-test fixture did not change")
        fixture_hal.write_text(unsafe_assert_copy, encoding="utf-8")
        expect_policy_failure(fixture_root, "secret-bearing source text")


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    try:
        if sys.argv[1:] == ["--self-test"]:
            self_test(project_root)
            print("CRASH_SECRET_POLICY_SELF_TEST_OK")
            return 0
        if sys.argv[1:]:
            raise CrashSecretPolicyError("Usage: check_crash_secret_policy.py [--self-test]")
        verify_policy(project_root)
    except (CrashSecretPolicyError, OSError, UnicodeError) as error:
        print(f"CRASH_SECRET_POLICY_ERROR: {error}", file=sys.stderr)
        return 1
    print("CRASH_SECRET_POLICY_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
