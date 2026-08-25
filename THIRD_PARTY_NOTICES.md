# Third-party notices

The release source preserves component-local license and notice files. The following top-level inventory covers the major code linked into or distributed with the firmware.

| Component | Role | License evidence |
| --- | --- | --- |
| CrossPoint Reader | Upstream reader firmware | `firmware/crosspoint-source/LICENSE`, `LICENSES/MIT-CrossPoint.txt` |
| FreeInk SDK | Display, storage, networking and book stack | `firmware/crosspoint-source/freeink-sdk/LICENSE`, `firmware/crosspoint-source/freeink-sdk/NOTICE` |
| wolfSSL | TLS implementation | `LICENSES/GPL-2.0-or-later.txt`; commercial licensing is also available from wolfSSL |
| WebSockets | WebSocket library | `LICENSES/LGPL-2.1-or-later.txt` |
| NimBLE-Arduino | Bluetooth stack | `LICENSES/Apache-2.0.txt` and component-local notices |
| tinycrypt | Cryptographic routines under NimBLE | `LICENSES/BSD-tinycrypt.txt` |
| ArduinoJson, QRCode, SdFat | Parsing/storage helpers | component-local MIT-style licenses in the complete source/dependency manifest |
| JPEGDEC, PNGdec | Image decoding | component-local Apache-2.0 licenses in the complete source/dependency manifest |
| GoogleTest | Android-target native contract test framework; not linked into firmware | `firmware/crosspoint-source/vendor/googletest/LICENSE` and `vendor/GOOGLETEST_PROVENANCE.md` |
| Wrangler | Pinned development tool for the undeployed Worker reference; not linked into firmware | package metadata and lockfile under `services/xtinct-feed-worker` |

Each release must include an inventory generated from the exact vendored dependency source used for that binary. This file does not replace component-local notices or a legal review.
