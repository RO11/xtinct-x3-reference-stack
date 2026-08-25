from __future__ import annotations

import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import qemu_firmware as qf


def esp32c3_image(size: int = 128) -> bytes:
    if size < 24:
        raise ValueError("test ESP image must contain a complete header")
    value = bytearray(b"\x00" * size)
    value[0] = qf.ESP_IMAGE_MAGIC
    value[1] = 1
    value[2] = 2  # DIO
    value[3] = 0x4F  # 16 MiB, 80 MHz
    value[12:14] = qf.ESP32_C3_CHIP_ID.to_bytes(2, "little")
    return bytes(value)


def partition_table(*, app0_offset: int = qf.APP_OFFSET) -> bytes:
    entries = (
        (1, 2, 0x9000, 0x5000, "nvs"),
        (1, 0, qf.OTA_DATA_OFFSET, qf.BOOT_APP0_BYTES, "otadata"),
        (0, 0x10, app0_offset, qf.APP_SLOT_BYTES, "app0"),
        (0, 0x11, qf.APP_OFFSET + qf.APP_SLOT_BYTES, qf.APP_SLOT_BYTES, "app1"),
        (1, 0x82, 0xC90000, 0x360000, "spiffs"),
        (1, 3, 0xFF0000, 0x10000, "coredump"),
    )
    output = bytearray()
    for entry_type, subtype, offset, size, label in entries:
        output.extend(struct.pack("<HBBII16sI", 0x50AA, entry_type, subtype, offset, size, label.encode(), 0))
    output.extend(b"\xFF" * (0xC00 - len(output)))
    return bytes(output)


class QemuFirmwareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="x3-qemu-test-")
        self.root = Path(self.temporary.name)
        self.build = self.root / "build"
        self.build.mkdir()
        (self.build / "bootloader.bin").write_bytes(esp32c3_image(256))
        (self.build / "partitions.bin").write_bytes(partition_table())
        self.boot_app0 = self.root / "boot_app0.bin"
        self.boot_app0.write_bytes(b"\xFF" * qf.BOOT_APP0_BYTES)
        (self.build / "firmware.bin").write_bytes(esp32c3_image(512))
        self.canonical = self.root / "update.bin"
        self.canonical.write_bytes((self.build / "firmware.bin").read_bytes())
        self.contract = self.root / "contract.json"
        self.contract.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "device": {
                        "flash_bytes": 16 * 1024 * 1024,
                        "ota_slot_bytes": qf.APP_SLOT_BYTES,
                    },
                    "linked_image": {"firmware_bin_max_bytes": qf.APP_SLOT_BYTES},
                }
            ),
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_validate_components_requires_canonical_application_identity(self) -> None:
        components = qf.components_from_build(self.build, self.boot_app0)
        flash_bytes, records = qf.validate_components(
            components, self.canonical, self.contract
        )
        self.assertEqual(flash_bytes, 16 * 1024 * 1024)
        self.assertEqual(records["firmware.bin"]["bytes"], 512)

        self.canonical.write_bytes(esp32c3_image(513))
        with self.assertRaisesRegex(qf.HarnessError, "byte-for-byte identical"):
            qf.validate_components(components, self.canonical, self.contract)

    def test_rejects_non_c3_application(self) -> None:
        wrong = bytearray(esp32c3_image(512))
        wrong[12:14] = (9).to_bytes(2, "little")
        (self.build / "firmware.bin").write_bytes(wrong)
        self.canonical.write_bytes(wrong)
        components = qf.components_from_build(self.build, self.boot_app0)
        with self.assertRaisesRegex(qf.HarnessError, "not ESP32-C3"):
            qf.validate_components(components, self.canonical, self.contract)

    def test_rejects_wrong_boot_app0_size(self) -> None:
        self.boot_app0.write_bytes(b"\xFF" * 32)
        components = qf.components_from_build(self.build, self.boot_app0)
        with self.assertRaisesRegex(qf.HarnessError, "exactly"):
            qf.validate_components(components, self.canonical, self.contract)

    def test_rejects_partition_table_with_wrong_app_slot_offset(self) -> None:
        (self.build / "partitions.bin").write_bytes(partition_table(app0_offset=0x20000))
        components = qf.components_from_build(self.build, self.boot_app0)
        with self.assertRaisesRegex(qf.HarnessError, "authoritative X3 layout"):
            qf.validate_components(components, self.canonical, self.contract)

    def test_assemble_writes_exact_offsets_and_readback_manifest(self) -> None:
        output = self.root / "x3-qemu-flash.bin"
        result = qf.assemble_flash(
            self.build,
            self.boot_app0,
            output,
            canonical_update=self.canonical,
            contract_path=self.contract,
        )
        self.assertEqual(output.stat().st_size, 16 * 1024 * 1024)
        with output.open("rb") as flash:
            flash.seek(qf.BOOTLOADER_OFFSET)
            self.assertEqual(flash.read(256), (self.build / "bootloader.bin").read_bytes())
            flash.seek(qf.PARTITION_TABLE_OFFSET)
            partition_bytes = (self.build / "partitions.bin").read_bytes()
            self.assertEqual(flash.read(len(partition_bytes)), partition_bytes)
            flash.seek(qf.OTA_DATA_OFFSET)
            self.assertEqual(flash.read(qf.BOOT_APP0_BYTES), self.boot_app0.read_bytes())
            flash.seek(qf.APP_OFFSET)
            self.assertEqual(flash.read(512), self.canonical.read_bytes())
        manifest_path = output.with_suffix(output.suffix + qf.MANIFEST_SUFFIX)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["network"], "disabled")
        self.assertEqual(
            manifest["flash"]["sha256"], hashlib.sha256(output.read_bytes()).hexdigest()
        )
        self.assertEqual(result["flash"]["bytes"], 16 * 1024 * 1024)
        qf.validate_manifest(output, self.canonical)

    def test_assemble_refuses_implicit_overwrite(self) -> None:
        output = self.root / "existing.bin"
        output.write_bytes(b"do not replace")
        with self.assertRaisesRegex(qf.HarnessError, "--replace"):
            qf.assemble_flash(
                self.build,
                self.boot_app0,
                output,
                canonical_update=self.canonical,
                contract_path=self.contract,
            )

    def test_manifest_detects_flash_tamper(self) -> None:
        output = self.root / "tamper.bin"
        qf.assemble_flash(
            self.build,
            self.boot_app0,
            output,
            canonical_update=self.canonical,
            contract_path=self.contract,
        )
        with output.open("r+b") as destination:
            destination.seek(qf.APP_OFFSET)
            destination.write(b"\x00")
        with self.assertRaisesRegex(qf.HarnessError, "SHA-256"):
            qf.validate_manifest(output, self.canonical)

    def test_manifest_refuses_stale_canonical_update(self) -> None:
        output = self.root / "stale.bin"
        qf.assemble_flash(
            self.build,
            self.boot_app0,
            output,
            canonical_update=self.canonical,
            contract_path=self.contract,
        )
        self.canonical.write_bytes(esp32c3_image(513))
        with self.assertRaisesRegex(qf.HarnessError, "changed after QEMU assembly"):
            qf.validate_manifest(output, self.canonical)

    def test_qemu_command_is_offline_and_uses_raw_mtd(self) -> None:
        command = qf.qemu_command(Path("qemu-system-riscv32"), Path("flash.bin"))
        self.assertIn("esp32c3", command)
        self.assertIn("file=flash.bin,if=mtd,format=raw", command)
        self.assertEqual(command[command.index("-nic") + 1], "none")
        self.assertEqual(command[command.index("-monitor") + 1], "none")

    def test_uart_classifier_accepts_quiet_bootloader_and_arduino_runtime(self) -> None:
        uart = """Adding SPI flash device
ESP-ROM:esp32c3-api1-20210207
load:0x3fcd5820,len:0x1010
load:0x403cbf10,len:0x9f4
load:0x403ce710,len:0x2e94
entry 0x403cbf10
[   892][E][Preferences.cpp:47] begin(): nvs_open failed: NOT_FOUND
[   906][E][esp32-hal-i2c-ng.c:369] i2cWriteReadNonStop(): failed
"""
        self.assertEqual(qf.classify_uart_coverage(uart), {
            "rom_booted": True,
            "second_stage_booted": True,
            "application_entered": True,
        })

    def test_uart_classifier_does_not_call_rom_handoff_an_application(self) -> None:
        uart = """ESP-ROM:esp32c3-api1-20210207
load:0x3fcd5820,len:0x1010
load:0x403cbf10,len:0x9f4
entry 0x403cbf10
"""
        self.assertEqual(qf.classify_uart_coverage(uart), {
            "rom_booted": True,
            "second_stage_booted": True,
            "application_entered": False,
        })

    def test_uart_classifier_rejects_unstructured_runtime_words(self) -> None:
        coverage = qf.classify_uart_coverage(
            "ESP-ROM:esp32c3\nload:0x1,len:0x1\nentry 0x403cbf10\n"
            "Preferences.cpp and Wire.cpp were mentioned but never executed\n"
        )
        self.assertFalse(coverage["second_stage_booted"])
        self.assertFalse(coverage["application_entered"])

    def test_uart_classifier_accepts_release_independent_xtinct_banner(self) -> None:
        coverage = qf.classify_uart_coverage(
            "ESP-ROM:esp32c3\nload:0x1,len:0x1\nload:0x2,len:0x2\n"
            "entry 0x403cbf10\nXTINCT-X3-v9.4.0-CANDIDATE\n"
        )
        self.assertTrue(coverage["second_stage_booted"])
        self.assertTrue(coverage["application_entered"])

    def test_uart_classifier_accepts_structured_crosspoint_banner(self) -> None:
        coverage = qf.classify_uart_coverage(
            "ESP-ROM:esp32c3\nload:0x1,len:0x1\nload:0x2,len:0x2\n"
            "entry 0x403cbf10\nCrossPoint X3 2.0.0\n"
        )
        self.assertTrue(coverage["application_entered"])

    def test_status_does_not_claim_ota_image_is_executable(self) -> None:
        with patch.object(qf, "CANONICAL_UPDATE_PATH", self.canonical), patch.object(
            qf, "probe_qemu", return_value={"available": True, "version": "test"}
        ):
            value = qf.status()
        self.assertFalse(value["ready_to_execute"])
        self.assertFalse(value["full_flash_inputs"]["ready"])


if __name__ == "__main__":
    unittest.main()
