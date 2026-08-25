# XTINCT Daily Cards and phone Wi-Fi setup

This branch keeps CrossPoint as the X3 reader and hardware layer, and adds a
private once-daily information surface plus phone-based network provisioning.

## Source pins

- CrossPoint baseline: `4e61903578cb2b9972ea56ae1f98e6b104bcd27c`
- FreeInk SDK baseline: `a485dc46ef5fb2283e4bdb674002ddbef97a9268`
- Branch: `feature/xtinct-daily-cards-wifi-provisioning`
- Worker origin: `https://<worker>.<account>.workers.dev`

The FreeInk SDK TLS verification change is kept as
`patches/freeink-secureclient-verified-tls.patch`. PlatformIO runs
`scripts/apply_xtinct_freeink_patch.py` before the normal WolfSSL patch. The
script checks the pinned SDK commit and accepts either a clean patch target or
the exact already-applied patch.

## Daily Cards flow

The firmware accepts only these task IDs:

- `market-briefing`
- `weekday-freelancer-scan`
- `3d-job-search`
- `outlook-attention-watch`

At the configured local time, the X3 wakes by ESP deep-sleep timer, connects to
at most three saved networks, refreshes UTC from NTP, fetches the manifest with
`If-None-Match`, downloads only changed cards, displays the best cached card and
returns to deep sleep while preserving the E-Ink frame. A 304 is normal success
only when the cached manifest and every referenced card still validate at the
expected revisions. If that cache set is missing or invalid, firmware clears the
ETag and performs exactly one unconditional manifest fetch, re-downloading every
referenced card. It never loops unconditional requests.
Only Wi-Fi and transport failures receive up to three bounded 15-minute retries.
A scheduled failure never starts phone provisioning.

Manifest card URLs remain the backward-compatible
`/v1/cards/<task_id>.json` form. After validating the manifest's strict
32-lowercase-hex revision, current firmware fetches that retained snapshot as
`/v1/cards/<task_id>.json?revision=<revision>`. Older firmware can continue to
request the unqueried current card, while new firmware cannot accidentally pair
manifest A with card B during a concurrent Worker publication.

The manifest and card cache live under `/.crosspoint/xtinct/` on the SD card.
After a valid HTTP 200 manifest and successful card downloads, cached allowlisted
cards absent from that manifest are removed. The dashboard shows each card's
`generated_at` date as, for example, `6 August 2026`. Card input is size-limited
and rejects more than four metrics, three sections, or four lines per section.
The four producers also repeat their Brisbane cadence in the visible summary,
the first metric and the full report. The Monday 3D producer uses the exact
always-visible title `3D Job Search - WEEKLY`. Schedule-aware expiry windows are
72 hours for Market, 100 hours for Freelancer, 216 hours for weekly 3D and 100
hours for Outlook, so the latest complete result survives the longest normal
schedule gap and a bounded late-run allowance until its replacement arrives.

Each compact card can optionally advertise one full report with this exact
metadata shape:

```json
{
  "report": {
    "url": "/v1/reports/<task_id>/<32-lowercase-hex-revision>.txt",
    "bytes": 12345,
    "sha256": "<64-lowercase-hex-digest>"
  }
}
```

Reports are UTF-8 plaintext without embedded NUL bytes, limited to 24 KiB and
fetched with the same bearer authentication as cards. The Worker rejects NUL,
and firmware also rejects it because the font APIs consume C strings. Firmware
streams each response directly into a
revisioned hidden SD file under `/.crosspoint/xtinct/reports/`; it does not hold
the report body in RAM. The byte count and incremental SHA-256 must match before
an atomic promotion replaces the previous cached report. A 304 cache check also
rehashes every referenced report, and replaced or withdrawn revisions are
pruned. If report promotion succeeds but its matching card commit fails, the
unreferenced report is rolled back. After a successful 304 cache validation or
a successful 200 repair/commit, firmware also performs a bounded scan of the
reports directory: only exact allowlisted task/revision `.txt`, `.tmp` and
`.bak` names are considered, paths are rebuilt from fixed components rather
than raw directory entries, active card reports are retained, and stale finals
or interrupted sidecars are removed. The destructive sweep is not run before
cache validation, so a power-loss `.bak` remains recoverable until a valid final
has been confirmed or repaired. Unknown files and subdirectories are never
deleted, and the sweep cannot address anything outside the reports directory.
The Daily Cards controls are **Back**, **Refresh**, **Open** and
**Next**. Opening a report borrows the TXT renderer in a transient mode that
does not modify Recent Books, resume position or reader app state; Back or the
end of the report returns to the originating Daily Card. TXT wrapping uses a
512-byte UTF-8-safe probe cap and substring-free binary width search, yielding
between indexed pages, so even the legal 24 KiB no-whitespace worst case cannot
trigger the former decrement-and-substring quadratic loop. The TXT page-index
cache version is bumped so ordinary cached books rebuild against the same wrap
rules before rendering. Split UTF-8 sequences wait for the next SD read, CRLF
terminators split at the 8 KiB read edge are consumed atomically, and the final
selected prefix is width-verified with a fixed-bound fallback for unusual font
shaping.

The bearer token is stored in ESP32 NVS namespace `xtinct_feed`, key
`read_token`. It is never serialized to SD or returned by the phone portal.
Cached card content is plaintext on the removable SD card; physical possession
of the card can reveal it. CrossPoint HTTP, WebSocket and WebDAV transfer routes
block every hidden path segment, including `/.crosspoint`, but that is not disk
encryption.

ESP-IDF flash and UART coredumps are disabled because their task-stack capture
can retain the NVS bearer or a Wi-Fi password that was live during a crash. The
normal ESP-IDF serial panic dump is also disabled because it prints raw stack
words over USB. `crash_report.txt` remains available for support, but contains
only the firmware version, bounded panic reason, fault program counter, return
address and machine cause. It never includes raw stack words or the retained log
ring. The build wrapper runs `scripts/check_crash_secret_policy.py` before a
build so re-enabling coredumps or serial panic dumps, or serializing stack/log
memory, fails closed.

## Time and wake safety

CrossPoint stores the hardware RTC in UTC. `clockUtcOffsetQ` is a biased number
of 15-minute units: 48 is UTC and 88 is Brisbane UTC+10. The initial target is
04:15 local time, with phone-selectable quarter-hour increments. Existing
XTINCT settings that predate `wake_minute` migrate once to 15 minutes past their
saved wake hour. Installing a feed token does not enable Daily Cards. The phone
portal must explicitly save the UTC offset, wake time and enabled state, and it
refuses to enable until a valid RTC has been NTP-synchronized and persisted.
After first enabling it, exit Phone Wi-Fi Setup and put the X3 to sleep once;
the daily timer is armed when firmware enters deep sleep.

The system clock is restored from the RTC on every boot for TLS certificate
validation. Daily Cards refreshes the RTC from NTP on every network session, so
a stopped but superficially plausible RTC can recover. Normal power-button and
USB-power sleep paths re-arm the configured daily timer. An unattended card
cycle does not overwrite the user's prior reader-resume state.

## Phone provisioning and recovery

Open **Phone Wi-Fi Setup** from Home, or hold **Power + Down** while booting for
the recovery shortcut. The X3 creates a ten-minute WPA2 AP named
`XTINCT-X3-<MAC suffix>`, with a random 12-character password and one allowed
client. Both the Wi-Fi QR code and `http://192.168.4.1/` QR code are shown only
on the E-Ink display.

The portal can scan for networks, enter a hidden SSID, test before saving, list
and forget saved networks, and configure Daily Cards. It accepts an open network,
an 8-63 character WPA passphrase, or an exact 64-hex-digit PSK. Mutations require
an AP-local request, JSON content type and random per-session header. It does not
enable itself after a failed scheduled sync. Every partial startup failure tears
down the AP, DNS and web server.

The X3 supports 2.4 GHz personal Wi-Fi and open networks. Enterprise 802.1X and
captive-login portals are not supported. A phone hotspot must use 2.4 GHz or
compatibility mode.

Hold **Power + Up** through boot to latch CrossPoint's SD firmware recovery
route immediately after `Storage.begin()` and before Pocket Sync pending-commit
recovery. To request sibling-slot rollback, keep Power held, release Up for the
neutral gap, then hold **Power + Down**. Up and Down share one ADC ladder, so a
simultaneous three-button chord cannot be represented and is never accepted.
Releasing Power after the first stage deliberately keeps the safer SD-picker
fallback. The direct physical precheck is independent of the recorded wake
reason, so panic/software-reset boot loops remain recoverable without adding the
detector's settle delay to an ordinary timer wake. The latched route also skips
the normal Power-button hold check and the `AfterUSBPower` cold-boot sleep, so
releasing Power after stage one cannot lose recovery before the picker. A
completed second stage
validates the sibling OTA image before switching and restarting; an absent,
invalid or unswitchable sibling falls back to the already-latched SD picker.

XTINCT removes **Check for updates** from Settings. CrossPoint's inherited
network OTA path downloads unsigned firmware using an insecure TLS client, so
leaving it reachable could allow a network attacker to replace firmware and
recover the NVS bearer. Use physical USB flashing or the Power + Up SD recovery
flow until XTINCT has an authenticated, signed update design.

XTINCT v1 also compiles out these inherited online surfaces because they use the
same generic unverified download/client layer:

- KOReader Sync account setup and reading-progress upload/download
- OPDS catalog setup, browsing and book download
- online font catalog/download

Local EPUB reading, bookmarks, SD caches and the offline position mapper remain.
Books can still arrive by SD, USB or the local phone File Transfer page. Built-in
fonts and custom fonts copied to SD or uploaded through the local `/fonts` page
also remain. The stock File Transfer AP is a local convenience service rather
than a private authenticated channel: an attached client can access ordinary
library/settings routes, while XTINCT's hidden `/.crosspoint` data is blocked.

## Physical USB token command

Send one newline-terminated command at 115200 baud:

```text
CMD:XTINCT_TOKEN:<32-to-256-visible-ASCII-token>
```

The only responses are:

```text
OK:XTINCT_TOKEN
ERR:XTINCT_TOKEN:LOCKED
ERR:XTINCT_TOKEN:LENGTH
ERR:XTINCT_TOKEN:CHARS
ERR:XTINCT_TOKEN:SAVE
```

The firmware never echoes or logs the token. Replacement is locked unless Phone
Wi-Fi Setup is the active physical-device screen. Installing or replacing it
always leaves the feed disabled until the phone portal explicitly enables it.

## TLS trust

TLS peer and hostname verification are mandatory. The narrow Worker trust bundle
contains these public roots, obtained from their official CA publications:

- GTS Root R4 SHA-256:
  `349DFA4058C5E263123B398AE795573C4E1313C83FE68F93556CD5E8031B3C7D`
- ISRG Root X1 SHA-256:
  `96BCEC06264976F37460779ACF28C5A7CFE8A3C0AAE11A8FFCEE05C0BDDF08C6`
- ISRG Root X2 SHA-256:
  `69729B8E15A86EFC177A57AFB7171DFC64ADD28C2FCA8CF1507E34453CCB1470`

Cloudflare can change the CA chain used by `workers.dev`. A future chain outside
these GTS/Let's Encrypt roots will fail closed and requires a firmware trust-store
update; it must never be worked around with `setInsecure()`.

The pinned Arduino-wolfSSL settings enable internal `DEBUG_WOLFSSL` tracing by
default. XTINCT's production patch explicitly undefines it: no build enables the
separate `FREEINK_WOLFSSL_DEBUG` opt-in, so retaining the trace code, strings and
Arduino serial hook would waste constrained memory without adding diagnostics.
This does not disable TLS or XTINCT's numeric connection/error logs. The patch
self-test verifies that debug is off while the required TLS 1.3, Curve25519,
FFDHE and SNI settings remain enabled.

## Build and hardware QA

Generate embedded assets and build with:

```powershell
py -3.11 scripts\build_html.py
py -3.11 scripts\gen_i18n.py lib\I18n\translations lib\I18n
py -3.11 scripts\patch_wolfssl.py --self-test
py -3.11 scripts\check_crash_secret_policy.py --self-test
py -3.11 scripts\build_xtinct.py --self-test
py -3.11 scripts\build_xtinct.py run -e default
```

Use the wrapper rather than invoking `pio run` directly for pioarduino platform
55.03.37. That release installs its pinned core as `pioarduino-core` but checks
for `platformio`, which otherwise triggers a redundant bootstrap on every build.
The wrapper expects that exact pioarduino platform and its pinned Python core to
have already completed their one-time PlatformIO bootstrap on the build PC.
The wrapper verifies the exact reviewed platform, penv and nested `uv` versions,
holds an OS lock, and backs up and atomically applies two narrow compatibility
changes: the package-name alias and suppression of pioarduino's public-only
`SSL_CERT_FILE` override. Nested `uv` uses verified Windows system trust;
user and project `uv` configuration loading is disabled;
Requests, pip and curl receive a task-local bundle containing certifi plus the
Windows trusted roots, and Git receives process-scoped Schannel settings.
Under the same lock, it also validates the exact pioarduino ESP-IDF 5.5.2
framework and its `.espidf-5.5.2` Python environment. If that already-created
environment is empty or incomplete, the wrapper repairs only its pinned Python
packages with an argument-list `uv pip install`; it never deletes or recreates
the environment. The package versions, imports, framework origin, path
boundaries and absence of reparse points are verified again after repair. The
executed `builder/frameworks/espidf.py` is a plain file at its exact expected
path and must match SHA-256
`27039C90E64478E86B21B0A51A4A439EA55A255FC9AF1C573FE3622C00791A78`
before repair. Immediately before PlatformIO runs, the wrapper backs up that
exact file and applies a second exact, two-site parser patch that changes only
the builder's destructive `.strip("\" ")` calls to `.strip()`. This preserves
CMake's protective quotes around compile fragments whose physical source paths
contain spaces. The patched builder must match SHA-256
`C3889D8B7CACD3F4F08D8D17AC63DC538795BB6A5FB9054193FDF05F0CF4559A`;
the self-test proves both quoted `-include` and `-fmacro-prefix-map` fragments
remain one Click/SCons argument and that the former broken form still splits.
Both transient source patches have independent exact-byte backups, interrupted-
run recovery and `finally` restoration. The `finally` path attempts both
restores before reporting either failure, and both reviewed originals are
verified before any artifact can be published.
Because this repository's Windows path contains spaces, the wrapper gives the
same source tree a temporary no-space drive-letter view with the exact
System32 `subst.exe`; it does not copy the source or create a junction. The
drive must be unused in both the logical-drive mask and DOS-device namespace,
and an exclusive owner sidecar records the drive, physical target, process and
random nonce. The wrapper verifies the exact DOS-device target plus
`platformio.ini` and Git-directory file identities, and proves PlatformIO's
`PROJECT_DIR` and build-cache paths retain the alias before compiling.
PlatformIO then builds in a unique, wrapper-owned no-space directory beneath
the PlatformIO core. After a successful compile, the wrapper verifies that
`firmware.bin` is non-empty and no larger than the `0x640000` OTA slot, hashes
the fresh bin/ELF/map outputs, atomically publishes them to
`.pio/build/default`, then safely removes the private directory. The reviewed
pioarduino source is restored and hash-checked in `finally`. The private build
is removed before the drive alias; alias cleanup proceeds only while its exact
mapping and owner sidecar still match, then verifies the DOS-device mapping is
gone. Any mismatch is left in place for inspection and fails closed.
Concurrent direct PlatformIO builds are unsupported while the wrapper is active.
It fails closed on source drift, lock contention, insecure environment flags,
dependency/version drift, unexpected reparse points, artifact boundary/hash
failures, child failure, cleanup failure or any restore mismatch. It never runs
an upload, erase or other flashing target.

Before distribution, test on an X3 without placing real secrets in logs:

1. Flash the local `firmware.bin`; verify **Power + Up** latches SD recovery,
   released Power still reaches that picker, and **Power + Up**, neutral gap,
   then **Power + Down** rolls back to the preserved sibling app slot. Repeat
   from a software reset, an `AfterUSBPower` cold boot and across a simulated
   `millis()` wrap.
2. Install a test token over USB and confirm Daily Cards remains disabled.
3. Start phone setup, join by QR, test valid/invalid and hidden Wi-Fi, a 64-hex
   PSK, forgetting a network, the one-client limit and ten-minute shutdown.
4. Select Brisbane (88), 04:15 and enable only after the portal reports clock
   synchronization. Exit setup and put the X3 to sleep once to arm the first
   timer wake.
5. Verify a timer wake, ETag 304, changed-card/report download, exact report
   byte/SHA rejection, replaced/withdrawn report pruning, offline cached fallback,
   three bounded transport retries and manual refresh.
6. Open every full report, page through it, and confirm Back/end returns to its
   Daily Card without adding a Recent Book or changing the prior book/resume target.
7. Confirm `/.crosspoint`, every dot component, `XTCache` and
   `System Volume Information` cannot be listed, downloaded, uploaded, created,
   renamed, moved, copied or deleted through HTTP, WebSocket or every WebDAV
   verb. Create real FAT long names with generated collision aliases (do not
   assume `CROSSP~1`) and prove each alias resolves to the protected LFN.
   The host gate parses real VFAT LFN/SFN directory entries from a FAT12 image
   and the RISC-V source probe binds the policy to `HalFile::getName()`, but the
   available host libraries cannot mount that image through the embedded SdFat
   block-device layer. The real-card X3 alias test is therefore mandatory and
   must not be reported as host-proven.
8. Reject overlong/many-segment paths and Destination headers, literal or
   percent-encoded NUL, slash and backslash, oversized/non-terminated WebSocket
   START frames, decimal size overflow, and oversized multi-delete bodies. At
   the pinned Arduino WebServer parser boundary, also reject oversized or
   unterminated request/header lines, excess headers, duplicate/conflicting or
   overflowing Content-Length, any Transfer-Encoding, invalid/oversized
   multipart boundaries, and short, overrun or trailing multipart bodies.
   Confirm malformed multipart emits ABORT and never END.
9. Fault-inject read, write, sticky-write, sync, close, remove and rename phases.
   A failed PUT, MOVE, COPY or multipart/WebSocket upload must retain the prior
   destination and remove only the request-owned partial; a failed restore must
   retain the old bytes in the owned backup. No HTTP/WebSocket/PUT response may
   report success unless the opened target exists and its committed latch is set.
10. Upload `.cpfont` files with the eight-byte magic split at every boundary;
    reject a short/bad signature, cumulative-size overflow, short/sticky write,
    sync/close failure and promotion/restore failure. The existing font must
    survive until the complete staged temp is durable, exact-length validated
    and atomically promoted; every rejected owned temp must be removed.
11. Put empty, one-byte-over-limit and `UINT64_MAX`-sized corrupt Pocket Sync
    markers/receipts and generic settings/state files on the SD image. Confirm
    firmware stats and rejects them before allocation or JSON parsing, normal
    boot remains fail-closed, and explicit Power+Up recovery still reaches the
    SD picker ahead of the damaged pending-commit marker.
12. Measure free heap around provisioning, manifest/card/report/artifact TLS,
    manual exit/restart and sleep. Confirm TLS ends before SHA finalization,
    promotion and full readback, and that the raw manifest is durably staged and
    its RAM buffer released before any child download.

This implementation has not been flashed to the connected X3 as part of the
source build. Hardware behavior remains to be verified before calling it a release.
