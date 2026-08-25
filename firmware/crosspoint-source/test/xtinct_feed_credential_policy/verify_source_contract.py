#!/usr/bin/env python3
"""Fail closed if the public feed credential can be redirected or split."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def section(text: str, start: str, end: str) -> str:
    begin = text.find(start)
    require(begin >= 0, f"missing source marker: {start}")
    finish = text.find(end, begin + len(start))
    require(finish > begin, f"missing source marker after {start}: {end}")
    return text[begin:finish]


def main() -> int:
    header = (ROOT / "src/XtinctFeedConfigStore.h").read_text(encoding="utf-8")
    store = (ROOT / "src/XtinctFeedConfigStore.cpp").read_text(encoding="utf-8")
    main_cpp = (ROOT / "src/main.cpp").read_text(encoding="utf-8")
    server = (ROOT / "src/network/WifiProvisioningServer.cpp").read_text(encoding="utf-8")
    page = (ROOT / "src/network/html/WifiProvisioningPage.html").read_text(encoding="utf-8")
    v1 = (ROOT / "src/network/XtinctFeedClient.cpp").read_text(encoding="utf-8")
    v2 = (ROOT / "src/network/XtinctSyncClient.cpp").read_text(encoding="utf-8")

    require("DEFAULT_BASE_URL" not in header, "public firmware must not compile a default feed origin")
    require("replaceCredential" in header and "updateSettings" in header,
            "credential and non-secret settings APIs must remain separate")
    require('NVS_CREDENTIAL_KEY[] = "feed_cred_v1"' in store,
            "origin and bearer must use the one versioned NVS record")
    require("writeCredentialRecordToNvs" in store and "readback" in store,
            "bound credential writes must be read back before activation")
    require("eraseLegacyTokenFromNvs" in store and
            "Could not erase obsolete split feed token from NVS" in store and
            "preferences.remove(LEGACY_NVS_TOKEN_KEY)" in store,
            "boot must attempt and verify erasure of the legacy split bearer")

    serializer = section(store, "void XtinctFeedConfigStore::toJson", "bool XtinctFeedConfigStore::fromJson")
    require("base_url" not in serializer and "read_token" not in serializer and "token_obf" not in serializer,
            "removable settings must not serialize origin or bearer")
    loader = section(store, "bool XtinctFeedConfigStore::fromJson", "bool XtinctFeedConfigStore::load")
    for legacy in ('doc["base_url"].isNull()', 'doc["read_token"].isNull()', 'doc["token_obf"].isNull()'):
        require(legacy in loader, f"legacy removable credential field is not stripped: {legacy}")

    require('XTINCT_FEED_CONFIG.load();' in main_cpp,
            "boot must load NVS credential even when the SD settings file is absent")
    require('CMD:XTINCT_FEED:' in main_cpp and "replaceCredential(origin, token)" in main_cpp,
            "physical USB must install the complete origin/token pair")
    require('CMD:XTINCT_TOKEN:' not in main_cpp,
            "token-only provisioning would create an ambiguous first-install path")
    require("readStringUntil" not in main_cpp and
            "MAX_SERIAL_COMMAND_BYTES" in main_cpp and
            "discardOversizedSerialCommand" in main_cpp,
            "physical USB credential input must use a bounded non-blocking line buffer")

    post = section(server, "void WifiProvisioningServer::handlePostConfig", "void WifiProvisioningServer::")
    require('!doc["base_url"].isNull() || !doc["read_token"].isNull()' in post,
            "phone setup must reject both credential fields")
    require("updateSettings(" in post and "replaceCredential" not in post,
            "phone setup may update schedule settings only")
    require("const payload={base_url:" not in page,
            "phone page must not submit the bound origin")

    require(v1.count("setFollowRedirects(0);") >= 2,
            "V1 authenticated requests must explicitly disable redirects")
    require(v2.count("setFollowRedirects(0);") >= 2,
            "V2 authenticated requests must explicitly disable redirects")

    print("XTINCT_PUBLIC_CREDENTIAL_SOURCE_CONTRACT_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
