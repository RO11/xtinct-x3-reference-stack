from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "sanitize_public_release.py"
SPEC = importlib.util.spec_from_file_location("sanitize_public_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
sanitizer = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = sanitizer
SPEC.loader.exec_module(sanitizer)


def category_set(result):
    return {finding.category for finding in result.findings}


class PublicReleaseSanitizerTests(unittest.TestCase):
    def make_root(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_clean_tree_accepts_templates_and_binary(self):
        root = self.make_root()
        (root / ".dev.vars.example").write_text('TOKEN="<replace-me>"\n', encoding="utf-8")
        (root / "README.txt").write_text("Contact owner@example.invalid\n", encoding="utf-8")
        (root / "firmware.bin").write_bytes(b"\x00\xffsafe public build string\x00")

        result = sanitizer.scan_release([root])

        self.assertTrue(result.clean)
        self.assertEqual(result.files_scanned, 3)

    def test_text_detects_secret_email_path_and_live_worker_url(self):
        root = self.make_root()
        email = "release-owner" + "@gmail" + ".com"
        worker = "https://release-owner.workers" + ".dev/private"
        slash = chr(92)
        local_path = "C:" + slash + "Users" + slash + "release-owner" + slash + "Documents" + slash + "build.bin"
        key_name = "API" + "_TOKEN"
        value = "z9Q7v4P2n8M6k3R1s5T0u4W8"
        (root / "config.txt").write_text(
            f"{key_name}={value}\nemail={email}\norigin={worker}\npath={local_path}\n",
            encoding="utf-8",
        )

        result = sanitizer.scan_release([root])

        self.assertTrue({"secret", "personal_email", "personal_path", "live_endpoint"} <= category_set(result))

    def test_worker_allowlist_is_exact(self):
        root = self.make_root()
        allowed = "https://synthetic-fixture.workers" + ".dev"
        other = "https://different-fixture.workers" + ".dev"
        prefix_attack = allowed + ".evil.example"
        (root / "urls.txt").write_text(
            f"{allowed}\n{other}\n{prefix_attack}\n", encoding="utf-8"
        )

        result = sanitizer.scan_release([root], allowed_worker_urls=[allowed])

        worker_findings = [finding for finding in result.findings if finding.category == "live_endpoint"]
        self.assertEqual(len(worker_findings), 2)
        self.assertEqual(worker_findings[0].line, 2)
        self.assertEqual(worker_findings[1].line, 3)

    def test_binary_ascii_and_utf16_strings_are_scanned(self):
        root = self.make_root()
        worker = "https://binary-fixture.workers" + ".dev/path"
        email = "binary-owner" + "@gmail" + ".com"
        marker = "runtime" + "-only-marker"
        secret_name = "API" + "_SECRET"
        secret_value = "B7k2M9v4Q1s8N5x3T6p0R2w9"
        payload = (
            b"\x00\xff"
            + worker.encode("ascii")
            + b"\x01\x02"
            + f"{secret_name}={secret_value}".encode("ascii")
            + b"\x02\x03"
            + email.encode("utf-16-le")
            + b"\x03\x04"
            + marker.encode("utf-16-be")
        )
        (root / "image.bin").write_bytes(payload)

        result = sanitizer.scan_release([root], forbidden_markers=[marker])

        self.assertIn("live_endpoint", category_set(result))
        self.assertIn("personal_email", category_set(result))
        self.assertIn("forbidden_marker", category_set(result))
        self.assertIn("secret", category_set(result))
        self.assertTrue(all(finding.offset is not None for finding in result.findings))

    def test_private_key_blocks_are_detected_but_parser_labels_are_not(self):
        root = self.make_root()
        parser_labels = root / "parser.bin"
        parser_labels.write_bytes(
            b"\x00-----BEGIN PRIVATE KEY-----\x00"
            b"-----BEGIN RSA PRIVATE KEY-----\x00"
            b"-----BEGIN EC PRIVATE KEY-----\x00"
        )
        key_body = "QUFB" * 24
        actual_key = root / "synthetic-key.pem"
        actual_key.write_text(
            "-----BEGIN PRIVATE KEY-----\n"
            + key_body
            + "\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )

        labels_only = sanitizer.scan_release([parser_labels])
        with_key = sanitizer.scan_release([root])

        self.assertTrue(labels_only.clean)
        key_findings = [
            finding for finding in with_key.findings
            if finding.rule == "private_key_block_ascii"
        ]
        self.assertEqual(len(key_findings), 1)
        self.assertEqual(key_findings[0].path, "synthetic-key.pem")

    def test_runtime_marker_from_environment_is_not_echoed(self):
        root = self.make_root()
        marker = "environment" + "-private-fixture"
        (root / "payload.txt").write_text(f"prefix {marker} suffix", encoding="utf-8")
        output = io.StringIO()

        with mock.patch.dict(os.environ, {sanitizer.FORBIDDEN_MARKERS_ENV: json.dumps([marker])}, clear=False):
            with contextlib.redirect_stdout(output):
                exit_code = sanitizer.main(["--json", str(root)])

        rendered = output.getvalue()
        self.assertEqual(exit_code, 1)
        self.assertNotIn(marker, rendered)
        self.assertEqual(json.loads(rendered)["findings"][0]["category"], "forbidden_marker")

    def test_marker_file_and_utf16_text_are_supported(self):
        root = self.make_root()
        marker = "marker" + "-from-file"
        marker_file = root / "markers.list"
        marker_file.write_text(marker + "\n", encoding="utf-8")
        target = root / "payload.txt"
        target.write_text("before " + marker + " after", encoding="utf-16")

        result = sanitizer.scan_release([target], forbidden_markers=sanitizer._read_marker_file(marker_file))

        self.assertIn("forbidden_marker", category_set(result))

    def test_risky_files_and_directories_fail_closed_without_descent(self):
        root = self.make_root()
        (root / ".env").write_text("safe placeholder", encoding="utf-8")
        (root / "credential-backup.json").write_text("{}", encoding="utf-8")
        nested = root / ".git"
        nested.mkdir()
        (nested / "config").write_text("not scanned", encoding="utf-8")

        result = sanitizer.scan_release([root])

        risky = [finding for finding in result.findings if finding.category == "risky_path"]
        self.assertEqual(len(risky), 3)
        self.assertEqual(result.files_scanned, 2)

    def test_large_file_is_a_failure_not_a_skip(self):
        root = self.make_root()
        (root / "large.bin").write_bytes(b"x" * 33)

        result = sanitizer.scan_release([root], max_file_bytes=32)

        self.assertFalse(result.clean)
        self.assertEqual(result.findings[0].rule, "file_exceeds_max_file_bytes")
        self.assertEqual(result.files_scanned, 0)

    def test_code_assignments_and_synthetic_paths_are_not_secrets(self):
        root = self.make_root()
        (root / "policy.cpp").write_text(
            "constexpr size_t MIN_TOKEN_LENGTH = 32;\n"
            "readToken = std::move(credential.token);\n"
            "readToken = newReadToken;\n"
            "path = R'(C:\\Users\\person\\Documents\\fixture.bin)';\n",
            encoding="utf-8",
        )
        (root / "real.env.txt").write_text(
            "API_TOKEN=z9Q7v4P2n8M6k3R1s5T0u4W8\n",
            encoding="utf-8",
        )

        result = sanitizer.scan_release([root])

        findings = [finding for finding in result.findings if finding.category == "secret"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].path, "real.env.txt")

    def test_localization_labels_are_not_credentials(self):
        root = self.make_root()
        translation = root / "lib" / "I18n" / "translations" / "english.yaml"
        translation.parent.mkdir(parents=True)
        translation.write_text(
            'STR_PASSWORD: "Password"\nSTR_ENTER_WIFI_PASSWORD: "Enter Wi-Fi password"\n',
            encoding="utf-8",
        )

        result = sanitizer.scan_release([root])

        self.assertTrue(result.clean)

    def test_lowercase_users_api_route_is_not_a_home_path(self):
        root = self.make_root()
        (root / "client.cpp").write_text(
            'url = base + "/users/auth";\npath = "/Users/real-owner/private.txt";\n',
            encoding="utf-8",
        )

        result = sanitizer.scan_release([root])

        paths = [finding for finding in result.findings if finding.category == "personal_path"]
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].line, 2)

    def test_only_named_worker_fixture_is_tolerated_in_tests(self):
        root = self.make_root()
        tests = root / "tests"
        tests.mkdir()
        (tests / "test_origin.cpp").write_text(
            'valid("https://reader.account.workers.dev/path");\n'
            'invalid("https://real-project.real-owner.workers.dev/path");\n',
            encoding="utf-8",
        )

        result = sanitizer.scan_release([root])

        workers = [finding for finding in result.findings if finding.category == "live_endpoint"]
        self.assertEqual(len(workers), 1)
        self.assertEqual(workers[0].line, 2)

    def test_vendored_public_certificate_and_firmware_map_are_scanned(self):
        root = self.make_root()
        certificate = root / "vendor" / "library" / "ca.pem"
        certificate.parent.mkdir(parents=True)
        certificate.write_text("-----BEGIN CERTIFICATE-----\nsynthetic\n", encoding="utf-8")
        (root / "firmware.map").write_text("public map evidence", encoding="utf-8")

        result = sanitizer.scan_release([root])

        self.assertTrue(result.clean)
        self.assertEqual(result.files_scanned, 2)

    def test_explicit_manifest_preserves_archive_paths(self):
        root = self.make_root()
        source = root / "opaque-name.txt"
        source.write_text("public fixture", encoding="utf-8")

        scanner = sanitizer.ReleaseScanner()
        result = scanner.scan_manifest([(source, "docs/reviewed-name.txt")])

        self.assertTrue(result.clean)
        self.assertEqual(result.files_scanned, 1)
        self.assertEqual(result.entries_seen, 1)

    def test_explicit_manifest_rejects_unsafe_or_duplicate_paths(self):
        root = self.make_root()
        first = root / "first.txt"
        second = root / "second.txt"
        first.write_text("first", encoding="utf-8")
        second.write_text("second", encoding="utf-8")

        with self.assertRaises(sanitizer.ScannerConfigurationError):
            sanitizer.ReleaseScanner().scan_manifest([(first, "../escape.txt")])
        with self.assertRaises(sanitizer.ScannerConfigurationError):
            sanitizer.ReleaseScanner().scan_manifest(
                [(first, "same.txt"), (second, "SAME.TXT")]
            )

    def test_provenance_email_is_allowed_but_runtime_marker_still_wins(self):
        root = self.make_root()
        contributors = root / "third_party" / "library" / "CONTRIBUTORS"
        contributors.parent.mkdir(parents=True)
        email = "upstream-author" + "@gmail" + ".com"
        contributors.write_text(email, encoding="utf-8")

        ordinary = sanitizer.scan_release([root])
        strict = sanitizer.scan_release([root], forbidden_markers=[email])

        self.assertTrue(ordinary.clean)
        self.assertIn("forbidden_marker", category_set(strict))

    def test_symlink_or_reparse_point_is_rejected_without_following(self):
        root = self.make_root()
        outside = self.make_root()
        (outside / "outside.txt").write_text("outside", encoding="utf-8")
        link = root / "linked"
        try:
            link.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            self.skipTest(f"symlink creation is unavailable: {type(error).__name__}")

        result = sanitizer.scan_release([root])

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule, "symlink_or_reparse_point")
        self.assertEqual(result.files_scanned, 0)

    def test_windows_reparse_attribute_is_recognized(self):
        entry_stat = types.SimpleNamespace(st_file_attributes=0x400)
        self.assertTrue(sanitizer._is_reparse(entry_stat))

    def test_invalid_runtime_configuration_returns_exit_two(self):
        root = self.make_root()
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            exit_code = sanitizer.main(["--forbid", "x", str(root)])
        self.assertEqual(exit_code, 2)
        self.assertIn("at least three", output.getvalue())


if __name__ == "__main__":
    unittest.main()
