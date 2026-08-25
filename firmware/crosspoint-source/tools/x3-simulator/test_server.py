from __future__ import annotations

import http.client
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.parse import quote
from unittest import mock

import server


def _temporary_directory(prefix: str) -> tempfile.TemporaryDirectory[str]:
    """Keep disposable test state under the lab quarantine policy when available."""

    root, _source, _fallback = server._resolve_session_root(None)
    return tempfile.TemporaryDirectory(prefix=prefix, dir=str(root) if root else None)


class VirtualPathTests(unittest.TestCase):
    def test_accepts_virtual_sd_path(self) -> None:
        self.assertEqual(("books", "daily.epub"), server._validate_virtual_sd_path("/books/daily.epub"))

    def test_rejects_traversal_and_host_paths(self) -> None:
        rejected = (
            "../sleep.bmp",
            "/../sleep.bmp",
            "/folder/../../sleep.bmp",
            "C:/Windows/system.ini",
            "/C:/Windows/system.ini",
            "//server/share/file",
            "/folder\\file",
            "/./sleep.bmp",
            "/",
        )
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(server.RequestError):
                server._validate_virtual_sd_path(value)


class RuntimeConfigTests(unittest.TestCase):
    def test_default_configuration_is_portable_demo_mode(self) -> None:
        config = server.default_simulator_config()
        self.assertEqual("demo", config.mode)
        self.assertEqual(server.SERVER_ROOT / "fixtures" / "x3-resource-budgets.demo.json", config.contract_path)
        self.assertIsNone(config.project_root)
        self.assertEqual(server.BUNDLED_BASELINE_PATH, config.firmware_path)
        self.assertIsNone(config.sleep_path)
        self.assertEqual("bundled-baseline", config.firmware_source)

        contract = server._read_contract(config)
        self.assertEqual("bundled-demo", contract["simulator"]["resource_contract"])
        self.assertEqual("bundled-baseline", contract["simulator"]["firmware"])
        self.assertEqual("synthetic-demo", contract["simulator"]["sleep_screen"])
        self.assertIn(config.session_root_source, {"D-quarantine", "E-quarantine", "environment", "os-temporary"})

    def test_session_root_cli_environment_and_fallback_precedence(self) -> None:
        with _temporary_directory("x3-sim-session-root-") as temporary:
            selected = Path(temporary)
            arguments = server._parse_arguments(["--session-root", str(selected)])
            explicit = server._config_from_arguments(arguments)
            self.assertEqual(selected.resolve(), explicit.session_root)
            self.assertEqual("explicit", explicit.session_root_source)
            self.assertFalse(explicit.session_root_fallback)

            with mock.patch.dict(os.environ, {"X3_LAB_QUARANTINE": str(selected)}):
                environment_root, source, fallback = server._resolve_session_root(None)
            self.assertEqual(selected.resolve(), environment_root)
            self.assertEqual("environment", source)
            self.assertFalse(fallback)

        with mock.patch.object(server.os, "name", "posix"), mock.patch.dict(
            os.environ, {}, clear=True
        ):
            fallback_root, source, fallback = server._resolve_session_root(None)
        self.assertIsNone(fallback_root)
        self.assertEqual("os-temporary", source)
        self.assertTrue(fallback)

    def test_project_root_uses_only_conventional_local_inputs(self) -> None:
        with _temporary_directory("x3-sim-project-") as temporary:
            project = Path(temporary)
            contract = project / "config" / "x3-resource-budgets.json"
            contract.parent.mkdir()
            shutil.copyfile(server.DEMO_CONTRACT_PATH, contract)
            firmware = project / "update.bin"
            firmware.write_bytes(self.valid_firmware_bytes())
            sleep = project / "sleep.bmp"
            sleep.write_bytes(server._demo_sleep_bmp())

            arguments = server._parse_arguments(["--project-root", str(project), "--no-browser"])
            config = server._config_from_arguments(arguments)

            self.assertEqual(project.resolve(), config.project_root)
            self.assertEqual(contract.resolve(), config.contract_path)
            self.assertEqual(firmware.resolve(), config.firmware_path)
            self.assertEqual(sleep.resolve(), config.sleep_path)
            self.assertEqual("project", config.contract_source)
            self.assertEqual("project", config.firmware_source)
            self.assertEqual("project", config.sleep_source)

    def test_all_optional_inputs_are_accepted_explicitly(self) -> None:
        with _temporary_directory("x3-sim-inputs-") as temporary:
            root = Path(temporary)
            project = root / "project"
            project.mkdir()
            firmware = root / "candidate.bin"
            firmware.write_bytes(self.valid_firmware_bytes())
            sleep = root / "candidate.bmp"
            sleep.write_bytes(server._demo_sleep_bmp())
            contract = root / "contract.json"
            shutil.copyfile(server.DEMO_CONTRACT_PATH, contract)
            build = root / "build"
            build.mkdir()
            boot_app0 = root / "boot_app0.bin"
            boot_app0.write_bytes(b"demo")
            official = root / "official-program"
            official.write_bytes(b"local executable marker")
            arguments = server._parse_arguments(
                [
                    "--project-root", str(project),
                    "--firmware", str(firmware),
                    "--sleep", str(sleep),
                    "--resource-contract", str(contract),
                    "--build-dir", str(build),
                    "--boot-app0", str(boot_app0),
                    "--crosspoint-simulator", str(official),
                ]
            )
            config = server._config_from_arguments(arguments)

            self.assertEqual(firmware.resolve(), config.firmware_path)
            self.assertEqual(sleep.resolve(), config.sleep_path)
            self.assertEqual(contract.resolve(), config.contract_path)
            self.assertEqual(build.resolve(), config.build_dir)
            self.assertEqual(boot_app0.resolve(), config.boot_app0)
            self.assertEqual(official.resolve(), config.crosspoint_simulator_path)

    def test_explicit_link_is_refused_when_platform_supports_it(self) -> None:
        with _temporary_directory("x3-sim-link-") as temporary:
            root = Path(temporary)
            target = root / "target.bin"
            target.write_bytes(b"target")
            link = root / "linked.bin"
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest("This Windows account cannot create symbolic links")
            arguments = server._parse_arguments(["--firmware", str(link)])
            with self.assertRaises(RuntimeError):
                server._config_from_arguments(arguments)

    @staticmethod
    def valid_firmware_bytes() -> bytes:
        payload = bytearray(64)
        payload[0] = 0xE9
        payload[1] = 1
        payload[2] = 0
        struct.pack_into("<H", payload, 12, 5)
        payload.extend(b"\x00XTINCT-X3-0.1.0-DEMO\x00BUILD-010-DEMO-PUBLIC\x00")
        return bytes(payload)


class FirmwareInspectionTests(unittest.TestCase):
    def test_extracts_release_build_id_without_unbounded_search(self) -> None:
        sample = b"noise\x00XTINCT-X3-%02X%02X%02X\x00XTINCT-X3-0.1.0-DEMO\x00tail"
        self.assertEqual("XTINCT-X3-0.1.0-DEMO", server._extract_firmware_build_id(sample))

    def test_extracts_specific_xtinct_build_id(self) -> None:
        sample = b"noise\x00BUILD-010-DEMO-PUBLIC\x00tail"
        self.assertEqual("BUILD-010-DEMO-PUBLIC", server._extract_xtinct_build_id(sample))

    def test_absent_firmware_is_unavailable_and_modelled_not_fatal(self) -> None:
        metadata = server._firmware_metadata()
        self.assertFalse(metadata["exists"])
        self.assertEqual("unavailable", metadata["availability"])
        self.assertEqual("modelled", metadata["fidelity"])
        self.assertEqual("not-run", metadata["inspection"])
        self.assertEqual("disabled", metadata["execution"])
        self.assertEqual("none", metadata["source_kind"])
        self.assertEqual("bundled-demo", metadata["contract_source"])
        self.assertEqual("synthetic-only", metadata["provenance_status"])
        self.assertTrue(metadata["package_firmware_bundled"])
        self.assertEqual(
            hashlib.sha256(server.DEMO_CONTRACT_PATH.read_bytes()).hexdigest(),
            metadata["contract_sha256"],
        )

    def test_selected_firmware_metadata_is_read_only_and_budgeted(self) -> None:
        with _temporary_directory("x3-sim-firmware-") as temporary:
            firmware = Path(temporary) / "candidate.bin"
            original = RuntimeConfigTests.valid_firmware_bytes()
            firmware.write_bytes(original)
            metadata = server._firmware_metadata(firmware, server.DEMO_CONTRACT_PATH)
            after = firmware.read_bytes()
        self.assertEqual(original, after)
        self.assertTrue(metadata["exists"])
        self.assertEqual(len(original), metadata["byte_count"])
        self.assertEqual("0xE9", metadata["esp_image_magic"])
        self.assertTrue(metadata["esp_image_magic_valid"])
        self.assertTrue(metadata["esp32c3_image_valid"])
        self.assertEqual(5, metadata["esp32c3_chip_id"])
        self.assertEqual("XTINCT-X3-0.1.0-DEMO", metadata["embedded_release_id"])
        self.assertEqual("BUILD-010-DEMO-PUBLIC", metadata["embedded_build_id"])
        self.assertEqual(metadata["ota_slot_bytes"] - metadata["byte_count"], metadata["ota_headroom_bytes"])
        self.assertEqual("read-only", metadata["inspection"])
        self.assertEqual("disabled", metadata["execution"])
        self.assertEqual("explicit", metadata["source_kind"])
        self.assertEqual("bundled-demo", metadata["contract_source"])
        self.assertEqual("local-image-demo-contract", metadata["provenance_status"])
        self.assertTrue(metadata["package_firmware_bundled"])

    def test_project_and_explicit_contract_provenance_are_distinct(self) -> None:
        with _temporary_directory("x3-sim-provenance-") as temporary:
            root = Path(temporary)
            project = root / "project"
            project_contract = project / "config" / "x3-resource-budgets.json"
            project_contract.parent.mkdir(parents=True)
            shutil.copyfile(server.DEMO_CONTRACT_PATH, project_contract)
            project_firmware = project / "update.bin"
            project_firmware.write_bytes(RuntimeConfigTests.valid_firmware_bytes())
            project_config = server._config_from_arguments(
                server._parse_arguments(["--project-root", str(project)])
            )
            project_metadata = server._firmware_metadata(
                project_config.firmware_path,
                project_config.contract_path,
                source_kind=project_config.firmware_source,
                contract_source=project_config.contract_source,
            )

            explicit_contract = root / "selected-contract.json"
            shutil.copyfile(server.DEMO_CONTRACT_PATH, explicit_contract)
            explicit_firmware = root / "selected-firmware.bin"
            explicit_firmware.write_bytes(RuntimeConfigTests.valid_firmware_bytes())
            explicit_config = server._config_from_arguments(
                server._parse_arguments(
                    [
                        "--firmware", str(explicit_firmware),
                        "--resource-contract", str(explicit_contract),
                    ]
                )
            )
            explicit_metadata = server._firmware_metadata(
                explicit_config.firmware_path,
                explicit_config.contract_path,
                source_kind=explicit_config.firmware_source,
                contract_source=explicit_config.contract_source,
            )

        self.assertEqual("project", project_metadata["source_kind"])
        self.assertEqual("project", project_metadata["contract_source"])
        self.assertEqual("local-image-project-contract", project_metadata["provenance_status"])
        self.assertEqual("explicit", explicit_metadata["source_kind"])
        self.assertEqual("explicit", explicit_metadata["contract_source"])
        self.assertEqual("local-image-explicit-contract", explicit_metadata["provenance_status"])
        for metadata in (project_metadata, explicit_metadata):
            encoded = json.dumps(metadata)
            self.assertNotIn(str(root), encoded)
            self.assertNotIn("contract_path", encoded)
            self.assertNotIn("firmware_path", encoded)

    def test_magic_byte_alone_is_not_reported_as_a_valid_esp32c3_image(self) -> None:
        with _temporary_directory("x3-sim-firmware-") as temporary:
            fake = Path(temporary) / "fake.bin"
            fake.write_bytes(b"\xE9" + b"\x00" * 23)
            metadata = server._firmware_metadata(fake)
        self.assertTrue(metadata["esp_image_magic_valid"])
        self.assertFalse(metadata["esp32c3_image_valid"])
        self.assertIn("segment count", metadata["esp32c3_image_error"])


class ReleaseProfileTests(unittest.TestCase):
    def test_bundled_profile_is_strict_and_api_safe(self) -> None:
        profile = server._read_release_profile()
        self.assertEqual(
            {"product", "version", "target", "firmware"}, set(profile)
        )
        self.assertEqual("0.1.0-alpha.4", profile["version"])
        self.assertEqual({"model": "Xteink X3", "mcu": "ESP32-C3"}, profile["target"])
        self.assertEqual(
            {
                "bundled": True,
                "runtime_policy": "bundled-official-baseline-read-only",
                "preview_mode": "synthetic-modeled-demo",
                "device_access": "none",
                "baseline": {
                    "project": "CrossPoint Reader",
                    "version": "v1.5.0",
                    "channel": "stable",
                    "asset": "firmware-baseline/crosspoint-v1.5.0/firmware.bin",
                    "byte_count": server.BUNDLED_BASELINE_BYTES,
                    "sha256": server.BUNDLED_BASELINE_SHA256,
                    "release_url": "https://github.com/crosspoint-reader/crosspoint-reader/releases/tag/v1.5.0",
                    "download_url": "https://github.com/crosspoint-reader/crosspoint-reader/releases/download/v1.5.0/firmware.bin",
                    "license": "MIT",
                    "execution": "inspected-not-executed",
                },
            },
            profile["firmware"],
        )

    def test_profile_rejects_unexpected_fields_instead_of_exposing_them(self) -> None:
        with _temporary_directory("x3-sim-profile-") as temporary:
            candidate = Path(temporary) / "release-profile.json"
            profile = json.loads(server.RELEASE_PROFILE_PATH.read_text(encoding="utf-8"))
            profile["host_path"] = r"C:\private\workspace"
            candidate.write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaises(RuntimeError):
                server._read_release_profile(candidate)


class DemoSleepTests(unittest.TestCase):
    def test_generated_sleep_is_native_x3_bmp(self) -> None:
        payload = server._demo_sleep_bmp()
        self.assertEqual(209158, len(payload))
        self.assertEqual(b"BM", payload[:2])
        self.assertEqual((528, 792), struct.unpack_from("<ii", payload, 18))
        self.assertEqual(4, struct.unpack_from("<H", payload, 28)[0])
        palette = [payload[54 + index * 4] for index in range(4)]
        self.assertEqual([0, 85, 170, 255], palette)
        self.assertEqual({0, 1, 2, 3}, {nibble for byte in payload[70:] for nibble in (byte >> 4, byte & 0x0F)})


class SessionStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = server.SessionStore()

    def tearDown(self) -> None:
        self.store.close()

    def test_demo_sessions_get_private_synthetic_sleep_copies(self) -> None:
        if self.store.config.session_root is not None:
            self.assertEqual(self.store.config.session_root, self.store._root.parent)
        first, created = self.store.get_or_create(None)
        second, second_created = self.store.get_or_create(None)
        self.assertTrue(created)
        self.assertTrue(second_created)
        self.assertNotEqual(first.token, second.token)
        self.assertNotEqual(first.sd_root, second.sd_root)
        self.assertEqual(server._demo_sleep_bmp(), (first.sd_root / "sleep.bmp").read_bytes())
        self.assertEqual(server._demo_sleep_bmp(), (second.sd_root / "sleep.bmp").read_bytes())

        with (first.sd_root / "sleep.bmp").open("r+b") as target:
            target.write(b"XX")
        self.assertEqual(b"BM", (second.sd_root / "sleep.bmp").read_bytes()[:2])

    def test_explicit_sleep_is_copied_and_source_stays_read_only(self) -> None:
        with _temporary_directory("x3-sim-sleep-") as temporary:
            source = Path(temporary) / "custom.bmp"
            source.write_bytes(server._demo_sleep_bmp())
            config = server.SimulatorConfig(
                contract_path=server.DEMO_CONTRACT_PATH,
                sleep_path=source,
                sleep_source="explicit",
            )
            store = server.SessionStore(config)
            try:
                session, _ = store.get_or_create(None)
                copied = session.sd_root / "sleep.bmp"
                with copied.open("r+b") as target:
                    target.write(b"XX")
                self.assertEqual(b"BM", source.read_bytes()[:2])
                self.assertNotEqual(source.resolve(), copied.resolve())
            finally:
                store.close()

    def test_reset_creates_a_fresh_revision(self) -> None:
        first, _ = self.store.get_or_create(None)
        marker = first.sd_root / "temporary-test.txt"
        marker.write_text("session only", encoding="utf-8")

        second, new_cookie = self.store.reset(first.token)
        self.assertFalse(new_cookie)
        self.assertNotEqual(first.revision, second.revision)
        self.assertNotEqual(first.sd_root, second.sd_root)
        self.assertFalse((second.sd_root / marker.name).exists())
        self.assertTrue((second.sd_root / "sleep.bmp").is_file())

    def test_tree_rejects_link_if_platform_allows_creating_one(self) -> None:
        session, _ = self.store.get_or_create(None)
        link = session.sd_root / "linked-sleep.bmp"
        try:
            os.symlink(session.sd_root / "sleep.bmp", link)
        except (OSError, NotImplementedError):
            self.skipTest("This Windows account cannot create symbolic links")
        with self.assertRaises(server.RequestError):
            server._tree_entries(session.sd_root)


class OfficialSimulatorTests(unittest.TestCase):
    def test_explicit_checkout_is_inspected_but_never_started(self) -> None:
        with _temporary_directory("official-crosspoint-sim-") as temporary:
            checkout = Path(temporary)
            (checkout / "src").mkdir()
            (checkout / "library.json").write_text(
                json.dumps({"name": "CrossPoint Simulator"}), encoding="utf-8"
            )
            (checkout / "README.md").write_text(
                "SDL SIMULATOR_DEVICE_X3 CROSSPOINT_SIM_INPUT_SCRIPT CROSSPOINT_SIM_SCREENSHOTS",
                encoding="utf-8",
            )
            config = server.SimulatorConfig(
                contract_path=server.DEMO_CONTRACT_PATH,
                crosspoint_simulator_path=checkout,
            )
            status = server._official_crosspoint_simulator_status(config)
        self.assertTrue(status["available"])
        self.assertEqual("source-checkout", status["kind"])
        self.assertFalse(status["auto_launch"])
        self.assertEqual("not-started", status["launch_state"])
        self.assertFalse(status["download_attempted"])
        self.assertFalse(status["network_contacted"])
        self.assertTrue(all(status["capabilities"].values()))

    def test_explicit_executable_is_detected_without_execution(self) -> None:
        with _temporary_directory("official-crosspoint-program-") as temporary:
            executable = Path(temporary) / "program"
            executable.write_bytes(b"not actually launched")
            config = server.SimulatorConfig(
                contract_path=server.DEMO_CONTRACT_PATH,
                crosspoint_simulator_path=executable,
            )
            status = server._official_crosspoint_simulator_status(config)
        self.assertTrue(status["available"])
        self.assertEqual("executable", status["kind"])
        self.assertEqual("not-started", status["launch_state"])


class PortableCopyTests(unittest.TestCase):
    def test_demo_server_runs_from_an_isolated_copy_without_parent_inputs(self) -> None:
        with _temporary_directory("x3-preview-portable-") as temporary:
            destination = Path(temporary) / "x3-preview-lab"
            destination.mkdir()
            for name in ("server.py", "standalone_inputs.py", "network_fixture.py"):
                shutil.copyfile(server.SERVER_ROOT / name, destination / name)
            shutil.copytree(server.WEB_ROOT, destination / "web")
            shutil.copytree(
                server.SERVER_ROOT / "firmware-baseline",
                destination / "firmware-baseline",
            )
            fixture_root = destination / "fixtures"
            fixture_root.mkdir()
            shutil.copyfile(server.RELEASE_PROFILE_PATH, destination / "release-profile.json")
            shutil.copyfile(server.DEVICE_FIXTURE_PATH, fixture_root / "device.json")
            shutil.copyfile(
                server.DEMO_CONTRACT_PATH,
                fixture_root / "x3-resource-budgets.demo.json",
            )
            self.assertFalse((destination / "update.bin").exists())
            self.assertFalse((destination / "sleep.bmp").exists())

            smoke_script = """
import http.client
import json
import threading
import server

store = server.SessionStore()
httpd = server.X3SimulatorHTTPServer((server.LOOPBACK_HOST, 0), store)
thread = threading.Thread(target=httpd.serve_forever, daemon=True)
thread.start()
try:
    port = httpd.server_address[1]
    connection = http.client.HTTPConnection(server.LOOPBACK_HOST, port, timeout=5)
    connection.request("GET", "/api/firmware")
    response = connection.getresponse()
    firmware = json.loads(response.read())
    connection.close()
    connection = http.client.HTTPConnection(server.LOOPBACK_HOST, port, timeout=5)
    connection.request("GET", "/api/release")
    response = connection.getresponse()
    release = json.loads(response.read())
    connection.close()
    connection = http.client.HTTPConnection(server.LOOPBACK_HOST, port, timeout=5)
    connection.request("GET", "/api/sd/tree")
    response = connection.getresponse()
    tree = json.loads(response.read())
    connection.close()
    print(json.dumps({"firmware": firmware, "release": release, "tree": tree}))
finally:
    httpd.shutdown()
    httpd.server_close()
    thread.join(timeout=2)
    store.close()
"""
            result = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-c",
                    smoke_script,
                ],
                cwd=destination,
                check=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            output = json.loads(result.stdout.strip().splitlines()[-1])
            self.assertTrue(output["firmware"]["exists"])
            self.assertEqual("inspected-not-executed", output["firmware"]["fidelity"])
            self.assertEqual("bundled-stable-baseline", output["firmware"]["provenance_status"])
            self.assertEqual(server.BUNDLED_BASELINE_SHA256, output["firmware"]["sha256"])
            self.assertEqual("0.1.0-alpha.4", output["release"]["version"])
            self.assertIn("/sleep.bmp", {entry["path"] for entry in output["tree"]["entries"]})


class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.store = server.SessionStore()
        cls.httpd = server.X3SimulatorHTTPServer((server.LOOPBACK_HOST, 0), cls.store)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)
        cls.store.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        cookie: str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection(server.LOOPBACK_HOST, self.port, timeout=3)
        headers = {"Cookie": cookie} if cookie else {}
        connection.request(method, path, headers=headers)
        response = connection.getresponse()
        body = response.read()
        response_headers = {name.lower(): value for name, value in response.getheaders()}
        connection.close()
        return response.status, response_headers, body

    def test_health_contract_and_optional_runtime_status(self) -> None:
        status, _, body = self.request("GET", "/api/health")
        self.assertEqual(200, status)
        health = json.loads(body)
        self.assertEqual("disabled", health["device_network"])
        self.assertEqual("demo", health["mode"])
        self.assertIn(health["session_storage"], {"D-quarantine", "E-quarantine", "environment", "os-temporary"})
        self.assertEqual(
            health["session_storage"] == "os-temporary",
            health["session_storage_fallback"],
        )

        status, _, body = self.request("GET", "/api/release")
        self.assertEqual(200, status)
        release = json.loads(body)
        self.assertEqual(
            {"product", "version", "target", "firmware"}, set(release)
        )
        self.assertEqual("0.1.0-alpha.4", release["version"])
        self.assertTrue(release["firmware"]["bundled"])
        self.assertEqual("none", release["firmware"]["device_access"])

        status, _, body = self.request("GET", "/api/device-contract")
        self.assertEqual(200, status)
        contract = json.loads(body)
        self.assertEqual(528, contract["data_limits"]["sleep_screen"]["portrait_width_pixels"])
        self.assertEqual(792, contract["data_limits"]["sleep_screen"]["portrait_height_pixels"])
        self.assertEqual("127.0.0.1", contract["simulator"]["bind_host"])

        status, _, body = self.request("GET", "/api/fixtures")
        self.assertEqual(200, status)
        fixture = json.loads(body)
        self.assertEqual("xtinct-x3-simulator/1", fixture["schema"])
        self.assertGreaterEqual(len(fixture["cards"]), 1)
        self.assertGreaterEqual(len(fixture["inbox"]), 1)

        status, _, body = self.request("GET", "/api/firmware")
        self.assertEqual(200, status)
        firmware = json.loads(body)
        self.assertTrue(firmware["exists"])
        self.assertEqual("available", firmware["availability"])
        self.assertEqual("inspected-not-executed", firmware["fidelity"])
        self.assertEqual("bundled-baseline", firmware["source_kind"])
        self.assertEqual("bundled-demo", firmware["contract_source"])
        self.assertEqual("bundled-stable-baseline", firmware["provenance_status"])
        self.assertTrue(firmware["package_firmware_bundled"])
        self.assertEqual(server.BUNDLED_BASELINE_BYTES, firmware["byte_count"])
        self.assertEqual(server.BUNDLED_BASELINE_SHA256, firmware["sha256"])
        self.assertNotIn(str(server.SERVER_ROOT), json.dumps(firmware))

        status, _, body = self.request("GET", "/api/qemu")
        self.assertEqual(200, status)
        qemu = json.loads(body)
        self.assertEqual(3, qemu["tier"])
        self.assertEqual("disabled", qemu["network"])
        self.assertTrue(qemu["canonical_update"]["available"])
        self.assertFalse(qemu["ready_to_execute"])

        status, _, body = self.request("GET", "/api/crosspoint-simulator")
        self.assertEqual(200, status)
        official = json.loads(body)
        self.assertEqual("optional-native-renderer", official["role"])
        self.assertFalse(official["auto_launch"])
        self.assertFalse(official["download_attempted"])
        self.assertFalse(official["network_contacted"])

    def test_tree_file_reset_and_read_only_methods(self) -> None:
        status, headers, body = self.request("GET", "/api/sd/tree")
        self.assertEqual(200, status)
        tree = json.loads(body)
        self.assertIn("/sleep.bmp", {entry["path"] for entry in tree["entries"]})
        raw_cookie = headers["set-cookie"].split(";", 1)[0]

        encoded_path = quote("/sleep.bmp", safe="")
        status, _, body = self.request("GET", f"/api/sd/file?path={encoded_path}", cookie=raw_cookie)
        self.assertEqual(200, status)
        self.assertEqual(server._demo_sleep_bmp(), body)

        status, _, reset_body = self.request("POST", "/api/session/reset", cookie=raw_cookie)
        self.assertEqual(200, status)
        self.assertEqual("reset", json.loads(reset_body)["status"])

        status, _, _ = self.request("DELETE", "/api/sd/file", cookie=raw_cookie)
        self.assertEqual(405, status)

    def test_file_endpoint_rejects_escape_attempts(self) -> None:
        attempts = (
            "/../AGENTS.md",
            "C:/Windows/system.ini",
            "//server/share/file",
            "/folder\\file",
        )
        for value in attempts:
            with self.subTest(value=value):
                status, _, _ = self.request("GET", f"/api/sd/file?path={quote(value, safe='')}")
                self.assertEqual(400, status)

    def test_security_headers_and_write_methods(self) -> None:
        status, headers, _ = self.request("GET", "/api/health")
        self.assertEqual(200, status)
        self.assertIn("connect-src 'self'", headers["content-security-policy"])
        self.assertEqual("no-referrer", headers["referrer-policy"])
        for method in ("PUT", "PATCH", "DELETE"):
            with self.subTest(method=method):
                status, _, _ = self.request(method, "/api/firmware")
                self.assertEqual(405, status)

    def test_non_loopback_binding_is_refused(self) -> None:
        temporary_store = server.SessionStore()
        try:
            with self.assertRaises(ValueError):
                server.X3SimulatorHTTPServer(("0.0.0.0", 0), temporary_store)
        finally:
            temporary_store.close()


if __name__ == "__main__":
    unittest.main()
