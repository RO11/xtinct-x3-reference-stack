from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/package_public_release.py"
SPEC = importlib.util.spec_from_file_location("package_public_release", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
package = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = package
SPEC.loader.exec_module(package)


class PublicReleasePackagerTests(unittest.TestCase):
    def make_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def test_qemu_archive_is_bound_to_linked_manifest(self) -> None:
        root = self.make_root()
        provenance = root / "linked-provenance"
        provenance.mkdir()
        artifacts = {}
        members = []
        for index, name in enumerate(package.QEMU_NAMES, start=1):
            path = root / name
            path.write_bytes(bytes([index]) * (index + 3))
            artifacts[name] = {
                "bytes": path.stat().st_size,
                "sha256": package.sha256_file(path),
            }
            members.append((path, name))
        (provenance / "pocket-sync-linked-evidence.json").write_text(
            json.dumps({"artifacts": artifacts}), encoding="utf-8"
        )
        archive = root / "qemu.zip"
        package.write_zip(archive, members, "qemu")

        package.validate_qemu_archive(archive, "qemu", root)

        (root / "firmware.bin").write_bytes(b"changed")
        package.write_zip(root / "changed.zip", members, "qemu")
        with self.assertRaises(package.ReleaseError):
            package.validate_qemu_archive(root / "changed.zip", "qemu", root)

    def test_source_mode_excludes_case_variants_and_all_xtinct_workdirs(self) -> None:
        root = self.make_root()
        (root / "kept.txt").write_text("kept", encoding="utf-8")
        for name in (".Git", "__PyCache__", ".xtinct-any-local-build"):
            directory = root / name
            directory.mkdir()
            (directory / "private.txt").write_text("private", encoding="utf-8")

        members = package.safe_members(root, source_mode=True)

        self.assertEqual([relative for _path, relative in members], ["kept.txt"])

    def test_dependency_sbom_covers_every_vendored_library(self) -> None:
        identity = dict(package.ready27_cache.PINNED_PORTABLE_DEPENDENCY_SOURCE_IDENTITY)
        sbom = package.dependency_sbom(
            "0.1.0-alpha.1",
            "1.6.2-xtinct.1",
            "a" * 64,
            identity,
        )

        self.assertEqual("SPDX-2.3", sbom["spdxVersion"])
        self.assertEqual("CC0-1.0", sbom["dataLicense"])
        expected = (
            set(package.ready27_cache.PINNED_REGISTRY_DEPENDENCY_VERSIONS)
            | {spec.name for spec in package.ready27_cache.GIT_DEPENDENCY_SPECS}
        )
        self.assertEqual(expected, {entry["name"] for entry in sbom["packages"]})
        self.assertEqual(len(expected), len(sbom["relationships"]))
        self.assertIn(identity["inventory_sha256"], sbom["comment"])

    def test_release_profile_is_bound_to_exact_firmware_and_reports(self) -> None:
        root = self.make_root()
        build = root / "build"
        build.mkdir()
        firmware = build / "firmware.bin"
        firmware.write_bytes(b"exact firmware")
        prebuild = root / "prebuild.json"
        postbuild = root / "postbuild.json"
        prebuild.write_bytes(b"prebuild evidence")
        postbuild.write_bytes(b"postbuild evidence")
        source_sha = "a" * 64
        profile = {
            "schema": "xtinct-x3-reference-release/1",
            "status": "qa-passed-physical-pending",
            "firmware": {
                "bytes": firmware.stat().st_size,
                "sha256": package.sha256_file(firmware),
            },
            "evidence": {
                "source_sha256": source_sha,
                "prebuild": {
                    "bytes": prebuild.stat().st_size,
                    "sha256": package.sha256_file(prebuild),
                },
                "postbuild": {
                    "bytes": postbuild.stat().st_size,
                    "sha256": package.sha256_file(postbuild),
                },
                "qemu": "passed",
                "physical_x3": "required",
            },
        }

        package.validate_release_profile(
            profile, source_sha, build, prebuild, postbuild
        )
        profile["status"] = "prebuild-pending"
        with self.assertRaises(package.ReleaseError):
            package.validate_release_profile(
                profile, source_sha, build, prebuild, postbuild
            )

    def test_dependency_provenance_keeps_private_marker_enforcement(self) -> None:
        root = self.make_root()
        source = root / "upstream.cpp"
        public_email = "upstream-author" + "@example.org"
        runtime_marker = "private-runtime-marker"
        slash = "/"
        upstream_path = slash + "Users" + slash + "upstream" + slash + "build"
        source.write_text(
            f"// {public_email}\n// {upstream_path}\n// {runtime_marker}\n",
            encoding="utf-8",
        )
        members = [(source, "Library/src/upstream.cpp")]

        clean = package.scan_members(
            members,
            "dependency fixture",
            [],
            provenance_prefix="vendor/platformio-libdeps",
        )
        self.assertEqual(clean["status"], "clean")
        with self.assertRaises(package.ReleaseError):
            package.scan_members(
                members,
                "dependency fixture",
                [runtime_marker],
                provenance_prefix="vendor/platformio-libdeps",
            )

    def test_public_report_redaction_removes_unlisted_local_paths(self) -> None:
        slash = chr(92)
        private_owner = "private-owner"
        value = {
            "tool": "C:" + slash + "Tools" + slash + "cmake.exe",
            "artifact": (
                "C:" + slash + "Users" + slash + private_owner
                + slash + "build" + slash + "firmware.bin"
            ),
            "relative": "src/main.cpp",
        }

        redacted = package.redact_local_paths(
            value, [(private_owner, "$PRIVATE_MARKER_1")]
        )

        rendered = json.dumps(redacted)
        self.assertNotIn(private_owner, rendered)
        self.assertNotIn("C:" + slash, rendered)
        self.assertEqual(redacted["relative"], "src/main.cpp")


if __name__ == "__main__":
    unittest.main()
