# X3 resource budgets

> Generated from `config/x3-resource-budgets.json`. Do not edit this sheet by hand.
> Contract SHA-256: `0644d76a74c3514d5e1dc6eb80f2ab9e39acd8dca844765e5d5734bdf37b5d29`

This is the admission contract for every XTINCT X3 feature. A safety ceiling means
"reject above this value"; it does not mean the largest accepted input is physically
fast or pleasant. Runtime rows marked *measured* still require an exact-build X3 test.

## Fixed hardware envelope

| Resource | Budget |
|---|---:|
| MCU | ESP32-C3, 1 core at 160 MHz |
| Internal SRAM | 409,600 B (400 KiB) |
| Linker-visible DRAM | 321,296 B |
| PSRAM | 0 B (0 MiB) |
| Flash | 16,777,216 B (16 MiB) |
| Each OTA slot | 6,553,600 B (6400 KiB) |
| Display | 792 x 528, 4 levels |
| One 1-bit framebuffer | 52,272 B |
| Battery rating | 650 mAh |

## Linked firmware hard gates

| Metric | Hard gate |
|---|---:|
| Final `firmware.bin` | <= 6,553,600 B (6400 KiB) |
| Final BIN OTA reserve | >= 49,152 B (48 KiB) |
| Low-headroom warning | < 131,072 B (128 KiB) |
| `.data + .bss` | <= 65,536 B (64 KiB) |
| IRAM text | <= 98,304 B (96 KiB) |
| Total linked DRAM image | <= 155,648 B (152 KiB) |
| RTC slow memory used | <= 6,144 B (6 KiB) |
| Exception unwind tables | <= 557,056 B (544 KiB) |

Use the final padded BIN size for OTA admission. PlatformIO's displayed Flash percent
does not account for the whole installable image. Under 128 KiB of final BIN reserve is
red: additions need an equal-or-larger removal. Under the hard reserve fails the build.
BIN, MAP, and effective sdkconfig are one indivisible linked gate; omitting any one fails.

## Task stack allocations

| Task | Stack |
|---|---:|
| Arduino loop (effective FreeInk override) | 16,384 B (16 KiB) |
| Activity render | 8,192 B (8 KiB) |
| NimBLE host | 4,096 B (4 KiB) |
| ESP timer | 4,096 B (4 KiB) |
| FreeRTOS timer service | 2,560 B |
| TCP/IP | 4,096 B (4 KiB) |

## Per-operation runtime envelope

| Operation | Free heap | Largest block | Other fixed cost | Evidence class |
|---|---:|---:|---:|---|
| Reader render/prewarm | 24,576 B (24 KiB) | 16,384 B (16 KiB) | n/a | hard admission |
| Reader background indexing | 32,768 B (32 KiB) | 16,384 B (16 KiB) | n/a | hard admission |
| EPUB checked allocation reserve | 49,152 B (48 KiB) | 4,096 B (4 KiB) | n/a | per-allocation reserve |
| CSS parse | 49,152 B (48 KiB) | n/a | n/a | hard admission |
| JPEG reader decode | 36,864 B (36 KiB) | n/a | 20,480 B (20 KiB) | hard admission |
| JPEG cover-to-BMP | 53,248 B (52 KiB) | n/a | 20,480 B (20 KiB) | hard admission |
| PNG reader decode | 63,520 B | 47,136 B | 47,136 B | hard admission |
| Retained mini font | 40,960 B (40 KiB) | n/a | n/a | hard admission |
| TLS 1.3 sync | 44,032 B (43 KiB) | 74,752 B (73 KiB) | n/a | measured watermark; physical regression required |
| Inbox direct sync | n/a | n/a | 36,152 B | compile-time and source gate |
| Display | n/a | n/a | 52,272 B | compile-time configuration |
| WebDAV transfer | n/a | n/a | 4,096 B (4 KiB) | source gate |

PNG is deliberately stricter than JPEG: the pinned PNG decoder object itself is
47,136 B and must fit in one contiguous block.
TLS numbers are measured watermarks, not a guarantee; changing TLS, Wi-Fi, JSON, or
concurrent buffers requires a physical heap/largest-block trace on the exact firmware.

## Data and protocol ceilings

| Area | Limits |
|---|---|
| Native sleep screen | 528 x 792 portrait; 4-bpp BI_RGB; 209,158 B; native palette 0/85/170/255; cover-cropped, no one-bit dithering; master tone RMSE <= 12.0; edge correlation >= 0.9; periodic score <= 0.45 |
| Inbox | 64 items; 8 changes/page; 10 pages/wake; 2,048 B (2 KiB) metadata; 32,768 B (32 KiB) SD outbox |
| Pocket Sync | 68 objects; 65,536 B (64 KiB) manifest; 20,971,520 B (20 MiB)/object; 67,108,864 B (64 MiB)/pack; 234-byte chunks x 4 |
| EPUB | 20,971,520 B (20 MiB) streamed resource; 262,144 B (256 KiB) in-memory resource; 114,688 B (112 KiB) retained page |
| File Transfer | 4,294,967,295 B safety ceiling; 512-byte path; 255-byte component |

Large artifacts and packs are streamed safety ceilings. They are not promises that a
maximum-size Bluetooth transfer or nearly-full SD transaction has been physically certified.

## Hardware capability filter

| Capability | Available to current firmware? |
|---|---|
| Touch | no |
| Frontlight | no |
| Speaker/audio | no |
| Microphone | no |
| Haptics | no |
| GPS | no |
| Cellular | no |
| 5 GHz Wi-Fi | no |
| PSRAM | no |
| NFC driver | no |
| 2.4 GHz Wi-Fi | yes |
| BLE peripheral | yes |
| microSD | yes |
| RTC | yes |
| IMU | yes |

## Mandatory feature admission checklist

Every X3 change must answer all of these before delivery:

1. Record final BIN, `.data + .bss`, total DRAM, IRAM, RTC, and unwind-table deltas.
2. State peak dynamic allocation, required free heap, and required largest contiguous block.
3. Declare every new task and stack; physically record stack high-water for new/deeper paths.
4. Bound every network body, JSON document, array, image, file, and retained cache.
   `/sleep.bmp` must pass the workspace `scripts/check_x3_sleep_screen.py` gate as exact 528 x 792 native grayscale, using `--source <explicit-unquantised-master>` for tone/detail/grid comparison.
5. Stream bodies over 28 KiB and avoid holding TLS, response, parse tree, and duplicate payloads together.
6. Service the watchdog/yield in every potentially long SD, network, decode, hash, or directory loop.
7. Budget atomic SD writes for both old and staged files, then test disk-full and power-loss recovery.
8. Convert allocation failure to a safe refusal; no exception may escape an activity/protocol boundary.
9. Run the source budget gate and linked-artifact budget gate. A skipped required gate is a failure.
10. Physically test uncertain runtime paths on the exact firmware and bind results to its SHA-256.

Commands:

```powershell
python -B scripts/check_x3_resource_budgets.py
python -B scripts/check_x3_resource_budgets.py --firmware-bin <firmware.bin> --firmware-map <firmware.map> --sdkconfig <sdkconfig.h>
python -B scripts/check_x3_resource_budgets.py --self-test
```
