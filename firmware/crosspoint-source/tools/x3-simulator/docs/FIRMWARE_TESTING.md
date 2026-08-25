# Firmware testing and evidence levels

X3 Preview & QA Lab separates four kinds of evidence. Reports and release notes must preserve these labels.

## MODELED

The portable alpha executes browser and Python models. It can verify screen geometry, four-gray output constraints, button-flow state, synthetic file operations, Cards V1 and Inbox V2 protocol behavior, cursor paging, cache semantics, checksums, receipt retry, malformed responses and failure recovery.

Modeled behavior does not execute ESP32-C3 instructions or prove firmware rendering.

## REAL CONTRACT TEST

In a complete CrossPoint source checkout, the development suite binds the model to current firmware constants and parser seams. It compiles the shared policy headers and refuses known protocol drift. This provides stronger contract evidence, but it still does not run the embedded networking stack.

The source-portable ZIP deliberately omits the firmware source tree and therefore cannot rerun this source-bound gate. Its metadata identifies the distribution as a synthetic preview package. The bundled official stable binary is a reference artifact, not the source required by this gate.

The complete source-checkout release runner also requires the uncropped master used to generate the sleep screen. Supply it explicitly; a quantized preview or prior BMP is not a valid master:

```powershell
python -B run_full_qa.py --phase prebuild `
  --sleep-master .\path\to\uncropped-master.png
```

`XTINCT_X3_SLEEP_MASTER` may provide the same input in CI. A bare full-QA command without this source image is expected to fail closed.

## QEMU

The source repository contains an optional fail-closed ESP32-C3 QEMU harness. QEMU evidence requires a complete, same-build set of bootloader, partition table, OTA data image and application image, plus a canonical application image for byte comparison. A standalone OTA file is insufficient.

The portable package includes neither QEMU binaries nor a complete same-build boot set. Its bundled stable OTA image alone cannot boot the QEMU harness. The lab must show QEMU as unavailable or blocked, not silently downgrade to a modeled pass. Even a successful QEMU boot covers CPU, ROM, bootloader, application entry and UART markers only.

## PHYSICAL DEVICE REQUIRED

Only an exact physical X3 can verify:

- UC8253/UC8279 E-Ink waveform, refresh, ghosting and retained image;
- ADC-ladder buttons;
- microSD electrical behavior and brownout/power-loss recovery;
- Wi-Fi and BLE radio/link behavior;
- RTC wake, IMU, battery and board power;
- task watchdog timing under board drivers;
- fragmented heap, stack high-water marks and long-running thermal/power effects.

## Firmware delivery boundary

This public alpha is not a firmware delivery tool. It contains one unchanged official stable CrossPoint baseline for reference and official-flasher use, but it does not download, upload or flash firmware itself. A new or modified firmware release needs its own frozen-source build, full automated gate, exact artifact hashes and physical-device acceptance evidence.

Do not infer firmware readiness from a Preview Lab screenshot or passing modeled suite.
