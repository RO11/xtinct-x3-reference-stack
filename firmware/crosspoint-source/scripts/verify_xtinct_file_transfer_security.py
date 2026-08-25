#!/usr/bin/env python3
"""Static release guard for XTINCT's unauthenticated File Transfer server."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

from check_bounded_webserver_parser import ParserFixtureError, verify_source_contract


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SERVER_CPP = PROJECT_ROOT / "src/network/CrossPointWebServer.cpp"
SERVER_H = PROJECT_ROOT / "src/network/CrossPointWebServer.h"
WEBDAV_CPP = PROJECT_ROOT / "src/network/WebDAVHandler.cpp"
WEBDAV_H = PROJECT_ROOT / "src/network/WebDAVHandler.h"
PATH_POLICY_CPP = PROJECT_ROOT / "src/network/FileTransferPathPolicy.cpp"
PATH_SAFETY_H = PROJECT_ROOT / "src/network/FileTransferSafety.h"
PATH_TEST_CPP = PROJECT_ROOT / "test/file_transfer_safety/FileTransferSafetyTest.cpp"
RECOVERY_H = PROJECT_ROOT / "src/util/XtinctBootRecovery.h"
RECOVERY_TEST_CPP = PROJECT_ROOT / "test/xtinct_boot_recovery/XtinctBootRecoveryTest.cpp"
MAIN_CPP = PROJECT_ROOT / "src/main.cpp"
POCKET_STORE_CPP = PROJECT_ROOT / "src/network/PocketSyncStore.cpp"
POCKET_TEST_CPP = PROJECT_ROOT / "test/pocket_sync_contract/PocketSyncContractTest.cpp"
HAL_STORAGE_CPP = PROJECT_ROOT / "lib/hal/HalStorage.cpp"
PERSISTABLE_CPP = PROJECT_ROOT / "lib/Serialization/PersistableStore.cpp"
PERSISTABLE_POLICY_H = PROJECT_ROOT / "lib/Serialization/PersistableStorePolicy.h"
PERSISTABLE_TEST_CPP = PROJECT_ROOT / "test/persistable_store_policy/PersistableStorePolicyTest.cpp"
PANIC_CPP = PROJECT_ROOT / "lib/hal/HalSystem.cpp"
PARSER_PATCH = PROJECT_ROOT / "patches/arduino-webserver-bounded-Parsing.cpp"
NETWORK_ATOMICITY_GATE = PROJECT_ROOT / "scripts/verify_xtinct_network_atomicity.py"
DAILY_CARDS_DOC = PROJECT_ROOT / "docs/xtinct-daily-cards.md"
ROOT_README = PROJECT_ROOT.parents[1] / "README.md"
SETTINGS_HTML = PROJECT_ROOT / "src/network/html/SettingsPage.html"
PLATFORMIO_INI = PROJECT_ROOT / "platformio.ini"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"XTINCT File Transfer security verification failed: {message}")


def function_body(source: str, signature: str) -> str:
    start = source.find(signature)
    require(start >= 0, f"missing function: {signature}")
    brace = source.find("{", start + len(signature))
    require(brace >= 0, f"missing body for: {signature}")

    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : index]
    raise SystemExit(f"XTINCT File Transfer security verification failed: unterminated function: {signature}")


def modeled_panic_reason(message: str) -> str:
    lowered = message.lower()
    if lowered.startswith("assert"):
        return "assert"
    if lowered.startswith("abort"):
        return "abort"
    if lowered.startswith("stack smashing") or lowered.startswith("stack-smash"):
        return "stack-smash"
    return "other"


def modeled_abort_caller_pc(message: str) -> int | None:
    prefix = "abort() was called at PC 0x"
    suffix = " on core "
    if not message.startswith(prefix):
        return None
    remainder = message[len(prefix) :]
    if len(remainder) != 8 + len(suffix) + 1:
        return None
    digits = remainder[:8]
    if any(character not in "0123456789abcdefABCDEF" for character in digits):
        return None
    if remainder[8 : 8 + len(suffix)] != suffix or remainder[-1] not in "0123456789":
        return None
    return int(digits, 16)


def verify_panic_privacy_mutation(panic_cpp: str) -> None:
    abort_body = function_body(panic_cpp, "void IRAM_ATTR __wrap_panic_abort")
    for fragment in (
        "const char* reason = PANIC_REASON_OTHER",
        "panicStartsWith(message, PANIC_REASON_ASSERT)",
        "panicStartsWith(message, PANIC_REASON_ABORT)",
        "panicStartsWith(message, PANIC_PREFIX_STACK_SMASH)",
        "panicStartsWith(message, PANIC_REASON_STACK_SMASH)",
        "storePanicReasonCode(reason)",
        "panicAbortCallerProgramCounter = 0",
        "panicAbortCallerPcValidMarker = 0",
        "parsePanicAbortCallerPc(message, &parsedAbortCallerPc)",
        "panicAbortCallerProgramCounter = parsedAbortCallerPc",
        "panicAbortCallerPcValidMarker = PANIC_ABORT_CALLER_PC_VALID",
    ):
        require(fragment in abort_body, f"panic classifier invariant is missing: {fragment}")
    require("storePanicReasonCode(message)" not in abort_body and
            "panicMessage[index] = message[index]" not in abort_body,
            "panic classifier can copy verbatim input into retained state")

    assert_body = function_body(panic_cpp, "__wrap___assert_func(const char* file")
    for fragment in (
        "__builtin_return_address(0)",
        "panicAssertCallerPcValidMarker = PANIC_ASSERT_CALLER_PC_VALID",
        "storePanicReasonCode(PANIC_REASON_ASSERT)",
        "__real___assert_func(file, line, function, expression)",
    ):
        require(fragment in assert_body, f"assert caller invariant is missing: {fragment}")
    for forbidden in ("file[", "function[", "expression[", "strlen", "memcpy", "strcpy", "snprintf"):
        require(forbidden not in assert_body,
                f"assert wrapper can retain secret-bearing source text: {forbidden}")

    abort_pc_parser = function_body(panic_cpp, "static bool IRAM_ATTR parsePanicAbortCallerPc")
    for fragment in (
        "message[offset] != PANIC_ABORT_PC_PREFIX[offset]",
        "for (size_t index = 0; index < 8; ++index)",
        "panicHexNibble(message[offset + index], &nibble)",
        "message[offset + suffixIndex] != PANIC_ABORT_PC_CORE_SUFFIX[suffixIndex]",
        "message[offset + 1] != '\\0'",
        "*parsedPc = value",
    ):
        require(fragment in abort_pc_parser, f"abort caller PC parser invariant is missing: {fragment}")
    for forbidden in ("std::", "String", "malloc(", "calloc(", "realloc(", "new ", "strtol", "sscanf"):
        require(forbidden not in abort_body and forbidden not in abort_pc_parser,
                f"panic-time abort parser is not allocation-free/IRAM-safe: {forbidden}")

    canonical_mutation = "SecretTokenABC123\nC:/profile/private"
    fixtures = {
        "ASSERT failed at harmless.cpp:1": "assert",
        "abort called": "abort",
        "Stack smashing protect failure!": "stack-smash",
        "stack-smash": "stack-smash",
        canonical_mutation: "other",
    }
    classified = {message: modeled_panic_reason(message) for message in fixtures}
    require(classified == fixtures,
            "fixed panic assert/abort/stack-smash/other classifier changed")

    valid_abort = "abort() was called at PC 0x4201A2B3 on core 0"
    secret_abort_mutations = (
        "abort() was called at PC 0x4201A2B3 on core 0 SecretTokenABC123",
        "abort() was called at PC 0x4201A2B3 SecretTokenABC123",
        "SecretTokenABC123 abort() was called at PC 0x4201A2B3 on core 0",
        "abort() was called at PC 0x4201A2B30 on core 0",
    )
    require(modeled_abort_caller_pc(valid_abort) == 0x4201A2B3,
            "fixed ESP-IDF abort caller PC was not parsed")
    for mutation in secret_abort_mutations:
        require(modeled_abort_caller_pc(mutation) is None,
                f"secret-bearing/lookalike abort caller was accepted: {mutation!r}")

    panic_message = classified[canonical_mutation]
    crash_report = (
        "CrossPoint version: fixture\n\nPanic reason: " + panic_message +
        "\n\nFault PC: 0x00000000\nReturn address: 0x00000000\n"
        "Machine cause: 0x00000000\nAbort caller PC: 0x4201A2B3"
    )
    require(panic_message == "other" and
            panic_message in ("assert", "abort", "stack-smash", "other"),
            "canonical secret-bearing panic did not collapse to a fixed reason")
    for secret_fragment in (
        canonical_mutation,
        "SecretTokenABC123",
        "SecretToken",
        "ABC123",
        "C:/profile/private",
        "C:/profile",
        "/private",
    ):
        require(secret_fragment not in panic_message and secret_fragment not in crash_report,
                f"panic privacy mutation leaked fragment: {secret_fragment}")


def main() -> None:
    server_cpp = SERVER_CPP.read_text(encoding="utf-8")
    server_h = SERVER_H.read_text(encoding="utf-8")
    webdav_cpp = WEBDAV_CPP.read_text(encoding="utf-8")
    webdav_h = WEBDAV_H.read_text(encoding="utf-8")
    path_policy_cpp = PATH_POLICY_CPP.read_text(encoding="utf-8")
    path_safety_h = PATH_SAFETY_H.read_text(encoding="utf-8")
    path_test_cpp = PATH_TEST_CPP.read_text(encoding="utf-8")
    recovery_h = RECOVERY_H.read_text(encoding="utf-8")
    recovery_test_cpp = RECOVERY_TEST_CPP.read_text(encoding="utf-8")
    main_cpp = MAIN_CPP.read_text(encoding="utf-8")
    pocket_store_cpp = POCKET_STORE_CPP.read_text(encoding="utf-8")
    pocket_test_cpp = POCKET_TEST_CPP.read_text(encoding="utf-8")
    hal_storage_cpp = HAL_STORAGE_CPP.read_text(encoding="utf-8")
    persistable_cpp = PERSISTABLE_CPP.read_text(encoding="utf-8")
    persistable_policy_h = PERSISTABLE_POLICY_H.read_text(encoding="utf-8")
    persistable_test_cpp = PERSISTABLE_TEST_CPP.read_text(encoding="utf-8")
    panic_cpp = PANIC_CPP.read_text(encoding="utf-8")
    parser_patch = PARSER_PATCH.read_text(encoding="utf-8")
    daily_cards_doc = DAILY_CARDS_DOC.read_text(encoding="utf-8")
    root_readme = ROOT_README.read_text(encoding="utf-8")
    settings_html = SETTINGS_HTML.read_text(encoding="utf-8")
    platformio_ini = PLATFORMIO_INI.read_text(encoding="utf-8")

    forbidden_server_fragments = (
        'server->on("/api/wifi"',
        'server->on("/api/wifi/delete"',
        "handleGetWifiNetworks",
        "handlePostWifiNetwork",
        "handleDeleteWifiNetwork",
        'include "WifiCredentialStore.h"',
        "WIFI_STORE",
    )
    for fragment in forbidden_server_fragments:
        require(fragment not in server_cpp, f"legacy Wi-Fi server fragment remains: {fragment}")
        require(fragment not in server_h, f"legacy Wi-Fi header fragment remains: {fragment}")

    forbidden_ui_fragments = (
        "/api/wifi",
        "wifi-container",
        "loadWifiNetworks",
        "saveWifiNetwork",
        "deleteWifiNetwork",
        "Wi-Fi Networks",
    )
    for fragment in forbidden_ui_fragments:
        require(fragment not in settings_html, f"legacy Wi-Fi settings UI remains: {fragment}")

    require("pre:scripts/build_html.py" in platformio_ini, "HTML assets are not regenerated before firmware builds")

    get_body = function_body(server_cpp, "void CrossPointWebServer::handleGetSettings() const")
    post_body = function_body(server_cpp, "void CrossPointWebServer::handlePostSettings()")

    require(
        'std::strcmp(key, "clockUtcOffsetQ") == 0' in server_cpp,
        "clockUtcOffsetQ is not classified as protected",
    )
    require(
        'std::strcmp(key, "clockHasBeenSynced") == 0' in server_cpp,
        "clockHasBeenSynced is not classified as protected",
    )
    require(
        "if (isProtectedFileTransferSetting(s.key)) continue;" in get_body,
        "GET /api/settings still exposes protected Daily Cards clock controls",
    )
    require(
        "for (JsonPairConst requested : doc.as<JsonObjectConst>())" in post_body,
        "POST /api/settings does not inspect every submitted key",
    )
    require(
        "if (isProtectedFileTransferSetting(requested.key().c_str()))" in post_body,
        "POST /api/settings does not reject protected keys",
    )
    require(
        'server->send(403, "text/plain", "Use Phone Wi-Fi Setup to change Daily Cards clock settings")' in post_body,
        "protected settings request does not fail closed",
    )

    reject_position = post_body.find("for (JsonPairConst requested")
    apply_position = post_body.find("const auto& settings = getSettingsList")
    require(0 <= reject_position < apply_position, "protected-key rejection happens after settings application begins")
    require(
        "if (isProtectedFileTransferSetting(s.key)) continue;  // Defense in depth." in post_body,
        "settings loop lacks a second protected-key guard",
    )

    # Unrelated reader settings must remain editable through the inherited page.
    require("SETTINGS.*(s.valuePtr) = val;" in post_body, "toggle setting updates were removed")
    require("SETTINGS.*(s.valuePtr) = static_cast<uint8_t>(val);" in post_body, "numeric setting updates were removed")
    require("SETTINGS.saveToFile();" in post_body, "unrelated settings are no longer persisted")

    # The File Transfer AP is unauthenticated, so every WebDAV verb must keep
    # firmware-owned dot directories and system paths outside the DAV surface.
    raw_body = function_body(webdav_cpp, "void WebDAVHandler::raw(")
    propfind_body = function_body(webdav_cpp, "void WebDAVHandler::handlePropfind(")
    protected_path_body = function_body(webdav_cpp, "bool WebDAVHandler::isProtectedPath(")
    existing_handlers = (
        "void WebDAVHandler::handleGet(", "void WebDAVHandler::handleHead(",
        "void WebDAVHandler::handleDelete(", "void WebDAVHandler::handlePropfind(",
    )
    for signature in existing_handlers:
        body = function_body(webdav_cpp, signature)
        require(
            "isProtectedPath(path, xtinct::file_transfer::PathIntent::Existing)" in body,
            f"{signature} can access protected storage",
        )

    for signature in ("void WebDAVHandler::handlePut(", "void WebDAVHandler::handleMkcol("):
        body = function_body(webdav_cpp, signature)
        require(
            "isProtectedPath(path, xtinct::file_transfer::PathIntent::CreateLeaf)" in body,
            f"{signature} does not validate its creation destination",
        )

    for signature in ("void WebDAVHandler::handleMove(", "void WebDAVHandler::handleCopy("):
        body = function_body(webdav_cpp, signature)
        require(
            "isProtectedPath(srcPath, xtinct::file_transfer::PathIntent::Existing)" in body
            and "isProtectedPath(dstPath, xtinct::file_transfer::PathIntent::CreateLeaf)" in body,
            f"{signature} does not protect both source and destination",
        )

    require("isProtectedPath(_putPath, xtinct::file_transfer::PathIntent::CreateLeaf)" in raw_body,
            "raw PUT streaming can open a protected destination")
    require(raw_body.find("isProtectedPath(_putPath") < raw_body.find("openFileForWrite"),
            "raw PUT opens its file before checking the protected path")
    propfind_guard = propfind_body.find("isProtectedPath(path, xtinct::file_transfer::PathIntent::Existing)")
    require(0 <= propfind_guard < propfind_body.find("Storage.exists") and
            propfind_guard < propfind_body.find("Storage.open"),
            "PROPFIND checks protected paths only after storage enumeration begins")

    # One canonical, allocation-free resolver must open every existing FAT
    # component and inspect its actual LFN. No generated 8.3 spelling is pinned.
    require("checkTransferPath(path, intent)" in protected_path_body,
            "WebDAV bypasses the shared canonical path policy")
    require("Storage.open(path.data())" in path_policy_cpp and
            "entry.getName(actualLongName, capacity)" in path_policy_cpp,
            "canonical FAT LFN resolution is missing")
    require("std::array<char, MAX_PATH_BYTES + 1>" in path_policy_cpp,
            "canonical path resolution is not fixed-capacity")
    require("std::string cumulative" not in path_safety_h and
            "std::string actualLongName" not in path_safety_h and
            "CROSSP~1" not in path_policy_cpp and "CROSSP~1" not in path_safety_h,
            "path resolver regained dynamic or hard-coded alias handling")
    for fixture in ("CROSSP~7", "SYSTEM~4", "XTCACH~9", "%2f", "%2F", "%5c", "%00",
                    "literalNul", "MAX_PATH_COMPONENTS + 1"):
        require(fixture in path_test_cpp, f"missing path-policy fixture: {fixture}")
    for fragment in ("decoded == '/'", "decoded == '\\\\'", "raw < 0x20U", "raw == 0x7fU"):
        require(fragment in path_safety_h, f"raw path validation lost: {fragment}")

    # PUT/MOVE/COPY and HTTP/WS upload completion must be transactional and
    # fault-aware. Never unlink the public destination before promotion.
    for fragment in ("makeUniqueDavSibling", "promotePrepared(", "copyExactly(", "finishDurableWrite("):
        require(fragment in webdav_cpp or fragment in path_safety_h,
                f"transaction primitive missing: {fragment}")
    require("Storage.remove(dstPath.c_str())" not in webdav_cpp and
            "Storage.remove(_putPath.c_str())" not in webdav_cpp,
            "WebDAV deletes a public destination before replacement")
    copy_body = function_body(webdav_cpp, "void WebDAVHandler::handleCopy(")
    require("const bool sourceCloseOk = srcFile.close();" in copy_body and
            "const bool destinationCloseOk = dstFile.close();" in copy_body,
            "COPY does not close source and destination unconditionally")
    require("bool _putCommitted = false;" in webdav_h,
            "PUT has no independent committed/promotion latch")
    require("_putOk = opened && existenceVerified;" in raw_body and
            "_putCommitted = true;" in raw_body,
            "PUT can treat an unowned or unpromoted temporary as success")
    put_body = function_body(webdav_cpp, "void WebDAVHandler::handlePut(")
    require("mayReportPutSuccess(" in put_body and "_putCommitted" in put_body,
            "PUT response does not require its committed latch")
    for fixture in ("failRenameCalls", "failRemoveCalls", "failRead", "failWrite", "failSync", "failClose"):
        require(fixture in path_test_cpp, f"missing transaction fault fixture: {fixture}")

    upload_body = function_body(server_cpp, "void CrossPointWebServer::handleUpload(")
    ws_body = function_body(server_cpp, "void CrossPointWebServer::onWebSocketEvent(")
    delete_body = function_body(server_cpp, "void CrossPointWebServer::handleDelete(")
    require("discardUploadPartial(state)" in upload_body and "state.targetPath" in upload_body,
            "multipart failure does not remove the exact owned partial")
    append_check = upload_body.find("canAppendTransferBytes(received, chunkBytes)")
    size_add = upload_body.find("state.size += upload.currentSize")
    require(0 <= append_check < size_add,
            "multipart cumulative size is updated before overflow/maximum validation")
    require("const bool existenceVerified = Storage.exists(state.targetPath.c_str());" in upload_body and
            "if (!opened || !existenceVerified)" in upload_body,
            "multipart can report an open which did not establish an owned target")
    require("finishDurableWrite(state.file, flushUploadBuffer(state))" in upload_body,
            "multipart completion skips checked write/sync/sticky/close durability")
    upload_response_body = function_body(server_cpp, "void CrossPointWebServer::handleUploadPost(")
    require("state.success = false;" in upload_response_body,
            "multipart route can replay a prior request's success latch")
    require("parseWsStartControl(" in ws_body and "String((char*)payload)" not in ws_body and ".toInt()" not in ws_body,
            "WebSocket START is not parsed from a bounded exact-length span")
    require(ws_body.find("parseWsStartControl(") < ws_body.find("wsUploadFileName ="),
            "WebSocket allocates control tokens before validating the frame")
    require("written != length || wsUploadFile.getWriteError()" in ws_body,
            "WebSocket binary writes ignore the sticky write error")
    require("canAppendTransferBytes(wsUploadReceived, length)" in ws_body and
            "finishDurableWrite(wsUploadFile)" in ws_body,
            "WebSocket cumulative bound or checked durable finish is missing")
    require("const bool existenceVerified = Storage.exists(wsUploadFilePath.c_str());" in ws_body,
            "WebSocket can accept an unverified output target")
    for fragment in ("MAX_DELETE_REQUEST_BYTES", "MAX_DELETE_ITEMS", "MAX_DELETE_FAILURE_BYTES"):
        require(fragment in delete_body or fragment in server_cpp, f"multi-delete is not bounded by {fragment}")
    scan_body = function_body(server_cpp, "void CrossPointWebServer::scanFiles(")
    require("bool shouldHide = !validCanonicalName || isProtectedItemName(fileName);" in scan_body,
            "protected canonical names can appear when show-hidden is enabled")
    require("file.getName(name, sizeof(name))" in scan_body and "validCanonicalName" in scan_body,
            "HTTP listing does not validate the actual enumerated FAT LFN")

    font_data_body = function_body(server_cpp, "void CrossPointWebServer::handleFontUploadData(")
    font_response_body = function_body(server_cpp, "void CrossPointWebServer::handleFontUpload()")
    for fragment in (
        "makeUniqueWebSibling(fontUpload.filePath, \"font\"",
        "fontUpload.ownsTemp = opened || existenceVerified",
        "canAppendTransferBytes(fontUpload.bytesReceived, chunkBytes)",
        "fontUpload.magic.feed(upload.buf, upload.currentSize)",
        "isCompleteFontPayload(",
        "finishDurableWrite(fontUpload.file, exactBytes)",
        "promotePrepared(",
        "discardFontUploadPartial()",
    ):
        require(fragment in font_data_body, f"font upload transaction lost: {fragment}")
    require("mayReportCommittedUploadSuccess(" in font_response_body,
            "font route can report success without a consumed committed temp")
    for fixture in (
        "AcceptsFragmentedMagicAndRejectsShortOrBadPrefixes",
        "RequiresFullMagicAndExactReceivedWrittenCounts",
        "NeverReportsSuccessBeforePromotionConsumesOwnedTemp",
    ):
        require(fixture in path_test_cpp, f"missing font upload regression: {fixture}")

    require("std::array<uint8_t, UPLOAD_BUFFER_SIZE> buffer{};" in server_h and
            "std::array<uint8_t, BUFFER_SIZE> buffer{};" in server_h and
            "std::vector<uint8_t> buffer" not in server_h,
            "upload state regained throwing vector allocation")

    # Keep network/cache ordering assertions function-scoped in their dedicated
    # gate. This avoids matching a cached-file validation which legitimately
    # occurs before the download's http.end().
    network_gate = subprocess.run(
        [sys.executable, str(NETWORK_ATOMICITY_GATE)],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    require(
        network_gate.returncode == 0,
        "network atomicity sub-gate failed: " + (network_gate.stdout + network_gate.stderr).strip(),
    )
    require("bool HalFile::sync()" in hal_storage_cpp and "bool HalFile::getWriteError()" in hal_storage_cpp,
            "checked SdFat durability surface is missing")

    # Owned SD state is always statted and capped before allocation/parsing.
    require("Storage.readFile" not in pocket_store_cpp,
            "Pocket Sync still grows a String before validating protected SD state")
    bounded_pocket_read = function_body(pocket_store_cpp, "bool readBoundedOwnedTextFile(")
    pocket_stat = bounded_pocket_read.find("file.fileSize64()")
    pocket_cap = bounded_pocket_read.find("validBoundedTextFileSize")
    pocket_alloc = bounded_pocket_read.find("new (std::nothrow)")
    pocket_read = bounded_pocket_read.find("file.read(")
    require(0 <= pocket_stat < pocket_cap < pocket_alloc < pocket_read,
            "Pocket Sync allocates/reads protected state before stat/cap validation")
    for limit in ("path, 10", "path, 512", "RECEIPTS_PATH, 4096", "ACTIVE_COMMIT_PATH, 512"):
        require(limit in pocket_store_cpp, f"Pocket Sync owned-file cap is missing: {limit}")
    require("RejectsOversizedOrEmptyProtectedMetadataBeforeAllocation" in pocket_test_cpp and
            "UINT64_MAX" in pocket_test_cpp,
            "Pocket Sync corrupt/oversized SD size regressions are missing")

    persist_body = function_body(persistable_cpp, "bool PersistableStoreBase::readDocFromFile(")
    persist_stat = persist_body.find("file.fileSize64()")
    persist_cap = persist_body.find("validPersistedJsonFileSize")
    persist_parse = persist_body.find("deserializeJson(doc, reader)")
    require(0 <= persist_stat < persist_cap < persist_parse and "Storage.readFile" not in persist_body,
            "generic PersistableStore parses before the 50 KiB file cap")
    require("MAX_PERSISTED_JSON_BYTES = 50U * 1024U" in persistable_policy_h and
            "CapsStateAndSettingsBeforeParserAllocation" in persistable_test_cpp and
            "UINT64_MAX" in persistable_test_cpp,
            "generic settings/state oversize policy or mutation tests are missing")

    # The parser checker owns the complete request/multipart grammar, checked
    # String operations, allocation-failure model and structural mutations.
    # Reuse it here so this route gate cannot drift to a stale substring list.
    try:
        verify_source_contract(parser_patch)
    except ParserFixtureError as error:
        require(False, f"bounded framework parser contract failed: {error}")
    parser_form = function_body(parser_patch, "bool WebServer::_parseForm(")
    end_status = parser_form.find("_currentUpload->status = UPLOAD_FILE_END")
    exact_body = parser_form.find('line != "--" || consumed != len || !finalizeArguments()')
    require(0 <= exact_body < end_status and "_parseFormUploadAborted" not in parser_form,
            "multipart route can commit END outside its exact accounting/single-cleanup path")

    # Panic reports retain only a fixed category plus PC/RA/cause. Unknown
    # printable messages, paths and bearer-like text are never copied.
    for fixed_reason in (
        'PANIC_REASON_ASSERT[] = "assert"',
        'PANIC_REASON_ABORT[] = "abort"',
        'PANIC_REASON_STACK_SMASH[] = "stack-smash"',
        'PANIC_REASON_OTHER[] = "other"',
    ):
        require(fixed_reason in panic_cpp, f"fixed panic reason is missing: {fixed_reason}")
    require('PANIC_ABORT_PC_PREFIX[] = "abort() was called at PC 0x"' in panic_cpp and
            'PANIC_ABORT_PC_CORE_SUFFIX[] = " on core "' in panic_cpp,
            "fixed ESP-IDF abort caller grammar is missing")
    require("Abort caller PC: 0x" in panic_cpp,
            "crash_report.txt no longer contains the parsed abort caller PC")
    require("Assert caller PC: 0x" in panic_cpp,
            "crash_report.txt no longer contains the wrapped assert caller PC")
    require("panicMessage[index] = message[index]" not in panic_cpp and
            "default branch never copies an unknown printable message" in panic_cpp,
            "panic_abort verbatim text may reach crash_report.txt")
    panic_begin = function_body(panic_cpp, "void begin()")
    require("storedPanicReasonIsValid()" in panic_begin and
            "!storedPanicReasonEquals(PANIC_REASON_ABORT)" in panic_begin and
            "panicAbortCallerPcValidMarker != PANIC_ABORT_CALLER_PC_VALID" in panic_begin and
            "!storedPanicReasonEquals(PANIC_REASON_ASSERT)" in panic_begin and
            "panicAssertCallerPcValidMarker != PANIC_ASSERT_CALLER_PC_VALID" in panic_begin and
            main_cpp.find("HalSystem::begin()") < main_cpp.find("HalSystem::checkPanic()"),
            "CPU-lockup boot can construct a String from unvalidated RTC panic bytes")
    verify_panic_privacy_mutation(panic_cpp)

    # Recovery must use a physically representable sequence and run after SD
    # mount but before normal pending-commit recovery, regardless of wake cause.
    require("Power+Up (hold) -> release Up (neutral gap) -> Power+Down (hold)" in recovery_h,
            "recovery sequence is no longer explicit")
    require("if (sample.up && sample.down)" in recovery_h and "partitionRollback = true" in recovery_h,
            "impossible simultaneous ADC state may trigger rollback")
    storage_begin = main_cpp.find("if (!Storage.begin())")
    physical_precheck = main_cpp.find("gpio.isBootRecoveryPowerUpHeldNow()")
    pending_recovery = main_cpp.find("PocketSyncStore::recoverPendingCommit()")
    require(0 <= storage_begin < physical_precheck < pending_recovery,
            "physical recovery is not latched immediately after SD mount")
    require("wakeupReason == HalGPIO::WakeupReason::PowerButton && detectAndHandleBootRecovery" not in main_cpp,
            "panic/software-reset recovery still depends on recorded wake cause")
    require("PowerUpAloneFallsBackToSdRecovery" in recovery_test_cpp and
            "TimersAreWrapSafe" in recovery_test_cpp and
            "ExplicitSdRecoveryPrecedesDamagedPendingCommit" in recovery_test_cpp and
            "LatchedRecoveryBypassesEveryPreRoutingSleepIncludingUsbBoot" in recovery_test_cpp,
            "recovery precedence/release/wrap tests are incomplete")
    require("mayEnterPreRoutingSleep(recoveryFirmwareMode)" in main_cpp and
            "if (recoveryFirmwareMode)" in main_cpp,
            "latched recovery can still deep-sleep in a wake-reason branch")
    execute_commit = function_body(pocket_store_cpp, "bool executeCommit(")
    rollback = execute_commit.find('std::strcmp(active.phase, "rollback") == 0')
    marker_remove = execute_commit.find("Storage.remove(ACTIVE_COMMIT_PATH)", rollback)
    rollback_success = execute_commit.find("return true;", marker_remove)
    require(0 <= rollback < marker_remove < rollback_success,
            "successful rollback-marker cleanup still reports failure")

    impossible_gesture = "Power + Up + Down"
    require(impossible_gesture not in daily_cards_doc and impossible_gesture not in root_readme,
            "documentation still advertises the impossible ADC chord")
    require("actual long filename" in root_readme and "generated collision aliases" in daily_cards_doc,
            "canonical FAT alias acceptance criteria are not documented")
    for documented_contract in (
        "`AfterUSBPower` cold-boot sleep",
        "pinned Arduino WebServer parser boundary",
        "malformed multipart emits ABORT and never END",
        "eight-byte magic split at every boundary",
        "`UINT64_MAX`-sized corrupt Pocket Sync",
        "must not be reported as host-proven",
    ):
        require(documented_contract in daily_cards_doc,
                f"firmware acceptance documentation drifted: {documented_contract}")

    print("XTINCT File Transfer security verification passed")


if __name__ == "__main__":
    main()
