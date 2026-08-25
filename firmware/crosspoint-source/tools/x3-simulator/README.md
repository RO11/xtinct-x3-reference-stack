# X3 Preview & QA Lab for Windows

**Version 0.1.0-alpha.4 — public alpha candidate**

X3 Preview & QA Lab is an unofficial, local development tool for people building CrossPoint experiences for the Xteink X3. It provides a fast four-gray screen preview, modeled button navigation, synthetic Daily Cards and Inbox traffic, failure injection, and repeatable contract checks without repeatedly flashing a reader.

It complements the [official CrossPoint Simulator](https://github.com/crosspoint-reader/crosspoint-simulator); it does not replace it. The official simulator is the preferred route for shared firmware rendering. This lab focuses on Windows-friendly product-flow preview and deterministic QA scenarios.

## What the alpha proves

Every result is labelled by evidence level:

- **MODELED** — JavaScript/Python state and screen behavior, not embedded code execution.
- **REAL CONTRACT TEST** — loopback HTTP requests and responses follow the bounded firmware protocol contract and are checked against source in a full CrossPoint checkout.
- **QEMU** — optional ESP32-C3 CPU/boot evidence only; the runtime and complete boot set are not distributed here. The bundled stable OTA image is not enough to boot QEMU.
- **PHYSICAL DEVICE REQUIRED** — E-Ink waveform and ghosting, ADC buttons, microSD power loss, Wi-Fi/BLE radio behavior, RTC wake, watchdog timing, heap fragmentation, battery and board power.

The browser is clamped to the X3's `528 x 792` portrait surface and four native gray levels. It remains a browser-font and mirrored-renderer preview, not a pixel-identical firmware renderer.

## Try the synthetic demo

### Portable Windows ZIP

1. Extract the complete ZIP.
2. Double-click `Launch X3 Preview QA Lab.cmd`.
3. Alpha.4 includes the official 64-bit CPython `3.14.7` Windows embeddable runtime, so no Python installation is needed. `release-metadata.json` records `bundled_runtime: true` and the pinned runtime provenance.
4. The lab opens at a local URL bound only to `127.0.0.1`. Press `Ctrl+C` in the launcher window to stop it.

The synthetic demo needs neither Node nor PlatformIO. The archive includes the unchanged official CrossPoint Reader `v1.5.0` stable `firmware.bin` as a read-only, hash-checked community baseline. It contains no XTINCT private firmware, Xteink stock firmware, credentials, device dumps, production endpoints, QEMU runtime or build output. Its firmware policy is `bundled-official-baseline-read-only`: the baseline is inspected but never executed, uploaded or flashed automatically. Configured source-checkout runs may instead inspect an operator-selected local image.

Bundled baseline: `5,544,112` bytes, SHA-256 `a7087155757bc63c1fcf60ae8d60a3760ce6d3406aaf7b9f23d0025244434f08`. See `firmware-baseline/crosspoint-v1.5.0/` and the [official release](https://github.com/crosspoint-reader/crosspoint-reader/releases/tag/v1.5.0).

Bundled runtime source archive: `python-3.14.7-embed-amd64.zip`, `12,673,227` bytes, SHA-256 `d297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15`. The builder pins both the untouched extracted tree and the packaged tree after adding only the lab's relative application path to `python314._pth`; automatic `site` import remains disabled. See the [official Python 3.14.7 release](https://www.python.org/downloads/release/python-3147/) and [embedding documentation](https://docs.python.org/3/using/windows.html#the-embeddable-package).

### From a source checkout

```powershell
python -B server.py
```

The server uses Python's standard library. Development tests additionally require Node.js 20 or newer and a C++ compiler for the source-parity gate.

## Controls

| X3 input | Keyboard |
|---|---|
| Back | Escape / Backspace |
| Confirm | Enter |
| Left / Right | Left / Right arrow |
| Up / Down | Up / Down arrow, Page Up / Page Down |
| Modeled completed power hold | P |

The on-screen buttons are clickable. Inbox opens in its Cards-style preview. Confirm opens Actions; Left/Up opens the full item; Right/Down advances.

## QA scenarios

Open **Network**, choose a scenario, then select **Run Cards + Inbox**. The loopback service covers:

- valid Cards V1 reports and Inbox V2 artifacts;
- ETag/cache behavior and `8/8/2` cursor paging;
- exact bytes, SHA-256, MIME and revision checks;
- receipt batching, deduplication and retry;
- interrupted or short artifacts and reports;
- malformed payloads and HTTP failures;
- no-config, no-Wi-Fi, clock and storage preflight failures;
- opening, deletion and feedback actions against browser-session state.

No scenario contacts a physical X3 or an external service. Each browser session receives a disposable synthetic SD model.

## Development checks

```powershell
npm test
npm run sanitize
```

`npm test` runs the current firmware-source contract gate, JavaScript loopback suite, Python behavior/server/QEMU-unit suites, and release-engineering tests. The source-contract portions require this directory to remain inside a complete CrossPoint checkout. The portable demo is deliberately smaller and does not claim those source-bound gates.

Build the Windows ZIP with:

```powershell
npm run package:portable
```

On a local Windows workstation the script stages only under a validated `D:\quarantine`, falling back to the same literal folder on `E:` when `D:` is unavailable. The single final ZIP and its checksum stay under `release/`; CI may use its isolated runner temp directory. The builder produces a deterministic ZIP, an external `.sha256` file, an internal per-file `FILES.SHA256`, and schema-2 machine-readable release metadata. `release-profile.json` is the version, target and firmware-policy authority. Provenance records the exact transformed public-payload digest, builder-script hash, demo-contract hash, source epoch, and optional Git commit plus dirty-state context; the payload digest remains authoritative even for a dirty checkout. The builder refuses links, unapproved firmware-like files, secrets, personal paths and non-synthetic payloads. The one exception is the exact allowlisted CrossPoint `v1.5.0` baseline, whose size and SHA-256 are checked in the source tree and again inside the ZIP.

See [DISTRIBUTION.md](docs/DISTRIBUTION.md), [FIRMWARE_TESTING.md](docs/FIRMWARE_TESTING.md), and [BETA_TEST_CHECKLIST.md](BETA_TEST_CHECKLIST.md) before publishing.

## Privacy and security

- The server binds only to `127.0.0.1`.
- The application performs no outbound HTTP and has no physical-device discovery or transfer path.
- Fixtures are synthetic and temporary session state is deleted when the server stops.
- Do not add production data, `.env` files, tokens, logs, device dumps, private SD contents, OEM stock images or private firmware. A firmware binary is allowed only when the release contract identifies an official redistributable baseline and the package gate pins its exact bytes and SHA-256.

Report security issues through the private process in [SECURITY.md](SECURITY.md). General contributions are covered by [CONTRIBUTING.md](CONTRIBUTING.md).

## Alpha status

The automated release checks can establish package integrity and modeled behavior. A public release still requires three outside testers to complete the clean-machine tasks in the beta checklist. Until that evidence exists, this is a candidate package—not a validated general release.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). CrossPoint and Xteink names belong to their respective owners; this project is not endorsed by them.
