#!/usr/bin/env python3
"""Fail-closed source/generated-string guard for XTINCT device UI text."""

from __future__ import annotations

import re
from pathlib import Path

from gen_i18n import load_translations


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TRANSLATIONS_DIR = PROJECT_ROOT / "lib" / "I18n" / "translations"
KEYS_HEADER = PROJECT_ROOT / "lib" / "I18n" / "I18nKeys.h"
STRINGS_CPP = PROJECT_ROOT / "lib" / "I18n" / "I18nStrings.cpp"

EXPECTED_FORMATS = {
    "STR_PHONE_SYNC_MANIFEST_PROGRESS": ["%lu"],
    "STR_PHONE_SYNC_OBJECT_PROGRESS": ["%u", "%lu"],
    "STR_PHONE_WIFI_CONNECTED_FMT": ["%s", "%s"],
    "STR_UPDATED_FMT": ["%s"],
}

REQUIRED_UI_TEXT = {
    "STR_DAILY_CARDS": "Daily Cards",
    "STR_DISLIKE": "Dislike",
    "STR_LIKE": "Like",
    "STR_NEXT_PAGE": "Next page",
    "STR_PHONE_SYNC": "Phone Sync",
    "STR_PHONE_WIFI_SETUP": "Phone Wi-Fi Setup",
    "STR_PREV_PAGE": "« Previous Page",
    "STR_RESUME": "Resume",
    "STR_XTINCT_INBOX": "XTINCT Inbox",
}

FORMAT_TOKEN = re.compile(
    r"%(?:[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|j|z|t|L)?[diuoxXfFeEgGaAcsp])"
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"XTINCT i18n verification failed: {message}")


def main() -> None:
    languages, _, string_keys, translations, _ = load_translations(str(TRANSLATIONS_DIR))
    key_set = set(string_keys)

    for key, expected_text in REQUIRED_UI_TEXT.items():
        require(key in key_set, f"English translation key is missing: {key}")
        require(translations[key][0] == expected_text,
                f"English translation is not the approved device text: {key}")

    for key, expected_tokens in EXPECTED_FORMATS.items():
        require(key in key_set, f"format translation key is missing: {key}")
        for language, value in zip(languages, translations[key]):
            actual_tokens = FORMAT_TOKEN.findall(value)
            require(actual_tokens == expected_tokens,
                    f"{language} {key} placeholders are {actual_tokens}, expected {expected_tokens}")

    keys_header = KEYS_HEADER.read_text(encoding="utf-8")
    strings_cpp = STRINGS_CPP.read_text(encoding="utf-8")
    for key in set(REQUIRED_UI_TEXT) | set(EXPECTED_FORMATS):
        require(f"  {key}," in keys_header, f"generated key table is stale: {key}")
    for key, expected_text in REQUIRED_UI_TEXT.items():
        # Non-ASCII text is intentionally emitted as adjacent UTF-8 hex
        # literals, so exact source matching is only meaningful for ASCII.
        if expected_text.isascii():
            require(f'"{expected_text}\\0"' in strings_cpp,
                    f"generated English string table is stale: {key}")
    require(re.search(r'"STR_[A-Z0-9_]+\\0"', strings_cpp) is None,
            "generated string table contains literal STR_* placeholders")

    print("XTINCT i18n verification passed")


if __name__ == "__main__":
    main()
