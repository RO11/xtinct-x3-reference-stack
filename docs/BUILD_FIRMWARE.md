# Building the firmware

The installable image is not considered releasable merely because PlatformIO compiles it. The authoritative path freezes one source snapshot, runs mandatory prebuild QA, builds through one fresh private dependency lane, checks the linked resource evidence, and runs the postbuild suite against the exact resulting image and QEMU boot set.

## Requirements

- Windows 10/11.
- Python 3.11 available as `py -3.11`.
- The pinned Android SDK/NDK/CMake versions referenced by `tools/x3-simulator/run_full_qa.py`.
- The vendored PlatformIO dependency sources accepted by `scripts/xtinct_ready27_cache.py`.
- At least 16 GiB free for the isolated dependency/build lane.
- One explicit ADB test target for the native contract phase. If other devices
  must remain connected, set `XTINCT_QA_ADB_SERIAL` to the intended serial.
- An explicit original sleep-screen master and the generated exact X3 `sleep.bmp`.

The internal `READY27` filenames are historical names for the reviewed deterministic-build machinery. They are not the public firmware version.

The public archive vendors the exact build-relevant FreeInk snapshot as ordinary files.
Its build-time provenance gate uses the exact tree inventory documented in
`firmware/crosspoint-source/XTINCT_VENDORED_FREEINK.md`; nested `.git` metadata
is neither required nor shipped.

The Android-target native contract lane likewise uses the metadata-free pinned
GoogleTest archive in `vendor/googletest`; a source ZIP does not need a parent
Git checkout to identify or compile that dependency.

## Freeze the exact source

From `firmware/crosspoint-source`:

```powershell
py -3.11 -B scripts/build_html.py
py -3.11 -B scripts/gen_i18n.py
python -B scripts/check_x3_resource_budgets.py
python -B test/xtinct_feed_credential_policy/verify_source_contract.py
py -3.11 -B -c "import json,sys;sys.path.insert(0,'scripts');import build_xtinct;print(json.dumps(build_xtinct.get_source_snapshot(),sort_keys=True))"
```

Record the reported source SHA. Any later source, generated asset, build configuration, resource-contract or simulator-contract change invalidates the result.

## Prebuild and authoritative compile

The high-level orchestrator constructs a single-use private PlatformIO core, runs the mandatory prebuild suite, then invokes the reviewed build wrapper:

```powershell
py -3.11 -B scripts/run_ready27_authoritative.py --lane A --go <SOURCE_SHA256>
```

Choose an unused lane from A–K. A lane is never reused or silently deleted after failure. The wrapper limits compile parallelism to two jobs.

The prebuild command enforced by the orchestrator is equivalent to:

```powershell
py -3.11 -B tools/x3-simulator/run_full_qa.py `
  --phase prebuild `
  --platformio-core <FRESH_PRIVATE_CORE> `
  --workspace-root ..\..
```

## Postbuild

After the exact published generation exists, run:

```powershell
py -3.11 -B tools/x3-simulator/run_full_qa.py `
  --phase postbuild `
  --platformio-core <SAME_PRIVATE_CORE> `
  --build-dir <PUBLISHED_GENERATION> `
  --boot-app0 <PUBLISHED_GENERATION>\boot_app0.bin `
  --workspace-root ..\..
```

Postbuild must use the matching `firmware.bin`, `firmware.map`, effective `sdkconfig.h`, `bootloader.bin`, `partitions.bin` and `boot_app0.bin`. It boots those exact parts in the offline ESP32-C3 QEMU harness.

Before postbuild, atomically replace the repository-root `update.bin` with the
exact published `firmware.bin`, then re-read its byte count and SHA-256. The
postbuild runner rejects any mismatch so the canonical install artifact cannot
silently lag behind the QEMU-tested image.

The source-bound suite also treats content recovery as mandatory. It exercises
an isolated exact-four Daily Cards V1 response, bounded newest-page selection,
unauthorized and malformed responses, Inbox V2 cursor and artifact integrity,
cache-first behavior, retryable receipts/outbox delivery, open/delete actions,
interrupted transfers, and the Today EPUB path. A static screenshot or fixture
render is not a substitute for these contract tests.

## Required release outputs

- `update.bin` copied from the exact verified `firmware.bin`.
- `SHA256SUMS.txt`.
- source-complete archive.
- QEMU boot-set archive.
- release manifest with byte counts and hashes.
- source-bound prebuild and postbuild JSON reports.
- resource-budget report/evidence.
- dependency SBOM and notices.
- privacy/sanitizer reports.

Build-time checks do not prove the physical device gates listed in `EVIDENCE.md`.
