# READY27 deterministic firmware construction

`scripts/xtinct_ready27_cache.py` is the fail-closed constructor for a fresh
private PlatformIO core. It does not use or bless the mutable global
`platforms/espressif32*` directory.

## Pinned platform

The pioarduino 55.03.37 platform comes only from the official cached ZIP:

- bytes: `1,678,517`
- SHA-256: `ffce4a512581abd417c42edf2695a3b49e8b1447849847d3f62d0db695da9efc`
- cache key: `5798f89f844ab07be4281e122fc8ca4fb5460f00`
- top-level directory: `platform-espressif32-55.03.37`
- entries: `696` (`563` files and `133` directories)
- expanded file bytes: `20,465,392`
- record-manifest SHA-256:
  `f8db980da24b49a58fb8bf7669af250b5beae0769927a491464446898fb04d8a`

Extraction is direct and does not call `ZipFile.extract*`. The constructor
rejects path traversal, absolute or aliased paths, case-folding collisions,
links, special files, unexpected modes, missing explicit parents, unexpected
counts or sizes, CRC errors and any archive or record-manifest hash drift. It
adds the exact reviewed 269-byte `.piopm` and retains the complete archive and
destination record inventories in `construction-evidence/private-core-construction.json`.
Generated `__pycache__`, `.pyc`, `.pyo` and `.xtinct-build-wrapper.lock` state is
forbidden in the platform archive.

## Cacheless pioarduino penv

The global penv is a source only for reviewed immutable files. Runtime Python
bytecode is validated as ordinary, single-link files and then excluded from
both identity and private-core copy. An ignored `__pycache__` directory may
contain only `.pyc`/`.pyo` regular files; it cannot hide a link, directory,
special file or unrelated content.

The approved cacheless identity is:

- entries: `5,574` (`4,872` files and `702` directories)
- file bytes: `287,661,530`
- inventory bytes: `927,973`
- inventory SHA-256:
  `7f528779d5cfcb5cbbdae4e0b10e5b8da29c37d9966d2be4abfeb6aa87423c4f`

This identity was reconciled against the prior approved full penv rather than
derived by accepting the current aggregate. The only drift was two generated
`__pycache__` directories and ten `.pyc` files created on 11 August 2026:
12 records and 329,176 bytes. Removing those records exactly reconstructs the
prior 7,675-entry, 322,949,944-byte inventory and its existing SHA-256
`70b0421e0281e06bc1f72e77c545b8b25b904afd893934bc1f42f8f3b182e53c`.
The excluded-record manifest is 2,214 bytes with SHA-256
`224af1bfec1aee9400120a9faf9c4ad083927b128ab39c6f738af785b495771c`.
No global file needs to be deleted.

## Offline private esptool rebind

The copied penv's original editable `esptool` metadata contains absolute paths
to the global PlatformIO package tree. READY27 extracts the official
pioarduino 5.1.2 source ZIP directly into the private package tree. During
construction, READY27 rewrites
only the copied editable finder and direct URL, regenerates the four console
launchers with the copied penv's pinned pip 26.2.1 / vendored distlib 0.4.2,
and updates their hashes in `RECORD`. This deterministic seven-file operation
does not invoke setuptools, wheel, a package installer, or the network.

Construction proves the package, editable-metadata, source-module and CLI
version are all `5.1.2`. Its import paths, editable direct URL, finder
mappings, namespace mappings and four console launchers must all resolve inside
that private core. Each launcher must embed that lane's exact private Python
path. The private `tool-esptoolpy` tree comes from the exact 506,890-byte
official pioarduino archive (SHA-256
`07295e31b0499a387f7315c2ce319e6d141bb8157461fe46fa914faeb8462ed1`)
plus an exact URI-bound `.piopm` record. That source identity, checked paths and file
hashes are retained in
`construction-evidence/private-core-construction.json`. The build wrapper
recomputes the source identity and the same rebind record and requires exact
matches. Generated caches are excluded from the global source copy and must be
absent from the private package, so stale global-path metadata, source-byte or
bytecode changes, and launcher drift fail before PlatformIO can start.

## Offline dependency seed

The authoritative build does not ask PlatformIO to download or clone a
library. The constructor copies four exact registry libraries and reconstructs
four Git libraries with `git archive` from their exact commits. It verifies
the local repository HEAD, origin, complete porcelain status, exact `.piopm`
bytes, exact reviewed patch diff and patched file bytes. Only ordinary commit
files plus the approved patch bytes enter the private tree; `.git` is never
copied. The complete private `libdeps` identity is:

- entries: `1,808` (`1,420` files and `388` directories)
- file bytes: `63,982,192`
- inventory bytes: `292,254`
- inventory SHA-256:
  `9cbe0cac4bd6fe29f3369e31c506202dfbc1242d92df92173d59dc44764c748d`

The JPEGDEC and wolfSSL build hooks resolve only PlatformIO's
`$PROJECT_LIBDEPS_DIR`, reject any dependency root inside the project, require
metadata-free sources and verify the exact prepatched payload. They never fall
back to the shared project `.pio/libdeps` cache and do not modify dependency
source during an authoritative build.

## Required gates and build freeze

Run the construction mutation suite and source resource gate with:

```powershell
py -3.11 -B scripts\xtinct_ready27_cache.py --self-test
py -3.11 -B scripts\check_x3_resource_budgets.py
```

Do not start an authoritative compile until simulator QA, Cards/Inbox network
download parity and the source freeze are complete. After the freeze, make one
fresh private-core construction and one authoritative compile attempt. Preserve
`bootloader.bin`, `partitions.bin`, the exact 8,192-byte `boot_app0.bin`, and
`firmware.bin` from that same build.

Once release QA has produced the exact frozen source snapshot SHA-256, the
single GO command is:

```powershell
py -3.11 -B scripts\run_ready27_authoritative.py --lane A --go <64-lowercase-hex-source-sha256>
```

The command requires the official pinned archives and pinned global tool
packages already verified by `xtinct_ready27_cache.py`, the reviewed warmed
`.pio/libdeps/default` provenance inputs, no pre-existing selected-lane core, no
inherited `PLATFORMIO_*` or `XTINCT_PINNED_PACKAGES_DIR` override, and at least
16 GiB free disk. It constructs the fresh private core and dependency seed,
checks the source SHA again, then invokes exactly one `build_xtinct.py run -e
default` with `PLATFORMIO_CORE_DIR` and `XTINCT_PINNED_PACKAGES_DIR` bound to
that lane's exact core and `core/packages` directory. The wrapper always caps
PlatformIO at two compile jobs (and rejects a request for more) so the firmware
build cannot create the unbounded compiler fan-out that previously destabilised
the host. A failure preserves the private lane for inspection; the command will
never clean or replace it.

Do not run a second build in that lane. Inspect the failure and, only after a
new source freeze and full release-suite rerun, use a fresh unused A/B/C/D/E/F/G/H/I/J/K lane.
Failed lanes are evidence and must remain intact; each newly authorised lane is
only a fresh retry and never deletes or reuses an earlier retained core.

The authoritative `scripts/build_xtinct.py` transaction now enforces that
retention automatically. A successful build atomically publishes
`bootloader.bin`, `partitions.bin`, the pinned 8,192-byte `boot_app0.bin`,
`sdkconfig.h`, ELF, MAP and `firmware.bin` together under
`.pio/build/default`. Schema 4 of
`linked-provenance/pocket-sync-linked-evidence.json` records the byte count and
SHA-256 of every one of those files. `firmware.bin` remains the final activation
marker: a missing companion, a wrong `boot_app0.bin`, a manifest mismatch or a
post-publish gate failure restores the complete previous generation.

Use the retained directory directly for QEMU:

```powershell
py -3.11 -B tools\x3-simulator\qemu_firmware.py status `
  --build-dir .pio\build\default `
  --boot-app0 .pio\build\default\boot_app0.bin
$qemuFlash = Join-Path $env:TEMP 'xtinct-x3-final-flash.bin'
py -3.11 -B tools\x3-simulator\qemu_firmware.py assemble `
  --build-dir .pio\build\default `
  --boot-app0 .pio\build\default\boot_app0.bin `
  --output $qemuFlash --replace
py -3.11 -B tools\x3-simulator\qemu_firmware.py run `
  --flash $qemuFlash
```

The offline QEMU harness may run only if the retained `firmware.bin` is
byte-for-byte identical to the canonical workspace `/update.bin`; otherwise it
must stop. A QEMU pass does not verify the E-Ink panel, SD card, buttons,
Wi-Fi/BLE, power behaviour, watchdog timing, heap fragmentation or physical X3.
No build or QEMU result authorizes upload or promotion.

