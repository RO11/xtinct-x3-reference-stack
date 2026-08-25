# Optional ESP32-C3 QEMU integration

QEMU is an advanced source-checkout feature, not part of the portable alpha. No QEMU executable, DLL, flash image or firmware component is distributed with X3 Preview & QA Lab.

The harness requires Espressif's ESP32-C3-capable QEMU, discoverable as `qemu-system-riscv32` or through `X3_QEMU_PATH`. Verify the executable and its source before use; never disable TLS verification to acquire it.

From a complete CrossPoint checkout, check readiness with:

```powershell
python -B qemu_firmware.py status
```

Assembly requires one retained build containing `bootloader.bin`, `partitions.bin`, `boot_app0.bin`, and `firmware.bin`. The application must be byte-identical to the canonical image supplied to the harness. The runner fills and verifies a local flash image, records hashes, re-reads every component and starts QEMU with networking disabled.

QEMU does not emulate the X3 E-Ink panel, microSD electrical behavior, physical buttons, radios, RTC/IMU, battery, board power or real watchdog/heap conditions. Those remain `PHYSICAL DEVICE REQUIRED` even after a successful boot.

Never bundle the QEMU runtime or generated flash image into a public Preview Lab archive.
