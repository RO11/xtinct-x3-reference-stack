# Evidence model

Every release should publish one table like this with links and exact hashes. Empty or pending cells block any stronger claim.

| Gate | What it proves | Current public candidate |
| --- | --- | --- |
| Source privacy scan | Bounded scanner found no configured personal endpoint, credential or local identity in the release set | Fail-closed packaging gate; a published release includes its zero-finding sanitizer report |
| Source resource gate | Checked machine-readable X3 flash/RAM/stack/buffer/SD/watchdog contract | Passed on frozen source `c001a496408cdb05fe7e45621dcdc07be602d655ad992f055dbfb8499fd041b7` |
| Native contract tests | Pure firmware policies execute on one explicitly selected Android/ADB target | 293 passed on `emulator-5554`; no physical-X3 implication |
| Simulator HTTP contracts | Cards V1, Inbox V2, Today EPUB, malformed/interrupted/cursor/cache/receipt/action paths | Passed in exact-source prebuild and postbuild suites |
| Prebuild suite | Exact frozen source passed every mandatory modeled gate | Passed; report SHA-256 `6a097c64b4f02af2dc0857efe1e3a868edf5394dda9ffd062c3d6394cc342dca` |
| Authoritative compile | Exact source produced a linked image in one fresh private dependency lane | Passed; `update.bin` is 6,481,008 bytes, SHA-256 `b689b26b47f08e7df955c8a5bbd6453d1f11562b99a161c45af7f913b99c71f4` |
| Linked resource gate | Final BIN/MAP/sdkconfig stayed inside hard budgets | Passed: 72,592 flash bytes remain, linked DRAM 143,809 bytes, RTC slow 4,178 bytes. Flash is below the 128 KiB warning reserve, so additions require a non-positive net delta |
| QEMU postbuild | Exact final app + bootloader + partitions + boot_app0 booted in offline ESP32-C3 QEMU | Passed; report SHA-256 `a8a0a51dd5109e2def278ce3a3e8458ef40c75301b0351d7349280f1ed33b036` |
| Physical X3 | E-Ink waveform, buttons, SD interruption, Wi-Fi/BLE, fragmented heap, watchdog, RTC wake, battery and recovery on exact SHA | Required; not implied by any row above |

Status words:

- **modeled**: deterministic model or fixture behavior only;
- **contract-tested**: real code/HTTP policy tested in a bounded harness;
- **built**: compiled and linked;
- **QEMU-booted**: exact retained parts booted in the emulator;
- **device-verified**: tested on a physical X3 with the exact published SHA.

Release notes must not collapse these into “fully tested.”
