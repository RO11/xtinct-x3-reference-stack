"""Focused portability tests for the fail-closed release orchestrator."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_full_qa as qa


class ReleaseQaPortabilityTests(unittest.TestCase):
    def test_source_identity_is_release_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src/XtinctBuildInfo.h").write_text(
                '#define XTINCT_RELEASE_LABEL "v9.4.0-CANDIDATE"\n'
                '#define XTINCT_BUILD_ID "BUILD-PUBLIC-ALPHA"\n',
                encoding="utf-8",
            )
            with patch.object(qa, "PROJECT_ROOT", root):
                self.assertEqual(
                    qa.source_release_identity(),
                    {
                        "build_id": "BUILD-PUBLIC-ALPHA",
                        "release_label": "v9.4.0-CANDIDATE",
                        "version": "9.4.0-CANDIDATE",
                    },
                )

    def test_source_identity_rejects_missing_build_macro(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "src").mkdir()
            (root / "src/XtinctBuildInfo.h").write_text(
                '#define XTINCT_RELEASE_LABEL "v1.0.0"\n', encoding="utf-8"
            )
            with patch.object(qa, "PROJECT_ROOT", root):
                with self.assertRaises(qa.QaError):
                    qa.source_release_identity()

    def test_explicit_adb_target_preserves_other_connected_devices(self) -> None:
        self.assertEqual(
            qa.select_adb_target(["emulator-5554", "emulator-5580"], "emulator-5554"),
            "emulator-5554",
        )

    def test_implicit_adb_target_remains_fail_closed(self) -> None:
        with self.assertRaises(qa.QaError):
            qa.select_adb_target(["emulator-5554", "emulator-5580"], None)
        with self.assertRaises(qa.QaError):
            qa.select_adb_target(["emulator-5554"], "emulator-5580")


if __name__ == "__main__":
    unittest.main()
