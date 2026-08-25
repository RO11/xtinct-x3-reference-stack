# XTINCT X3 Reference Stack v0.1.0-alpha.2

Alpha.2 is a maintenance release of the public reference stack. It preserves
the exact alpha.1 firmware image and its source-bound prebuild, linked-resource
and QEMU evidence while repairing the public validation workflow and making the
remaining stability boundary explicit.

## What changed

- The Worker-template job now uses Node.js 22, matching the template's declared
  runtime and its use of the built-in `node:sqlite` test API.
- The Windows simulator unit job now exercises the intentional no-QEMU path in
  a deterministic environment. Optional host QEMU installations can no longer
  turn a three-second HTTP contract test into two unrelated 15-second probes.
- The official, hash-pinned CrossPoint v1.5.0 read-only baseline is now tracked
  in the public checkout, so a clean clone can run the documented portable demo
  and server tests without relying on an ignored local file.
- Repository text is checked out with LF endings on every runner, keeping the
  resource-contract hash and its generated human-readable budget sheet in sync.
- The repository version and generated source package advance to
  `0.1.0-alpha.2`.
- Release wording now states plainly that the custom firmware is
  QA-passed and QEMU-booted but still awaits an exact-image physical X3
  acceptance pass.

## Firmware carried forward unchanged

- Firmware version: `1.6.2-xtinct.1`
- Build ID: `BUILD-162-XTINCT1-PUBLIC`
- Size: `6,481,008` bytes
- SHA-256: `b689b26b47f08e7df955c8a5bbd6453d1f11562b99a161c45af7f913b99c71f4`
- Frozen firmware-source SHA-256:
  `c001a496408cdb05fe7e45621dcdc07be602d655ad992f055dbfb8499fd041b7`

Because the firmware source and linked output are unchanged, this release does
not imply a new compile, flash, or device result. The installable binary should
match alpha.1 byte-for-byte.

## Included device features

- Daily Cards V1 for compact, glanceable items with revisions, checksums,
  cache-first rendering, refresh state and bounded recovery.
- Inbox V2 for cursor-paged deliveries, immutable hash-addressed artifacts,
  text/EPUB/sleep-screen routing, open/delete actions, like/dislike feedback,
  receipts and a retryable outbox.
- Today EPUB reading, scheduled wakes and an exact 528 x 792 four-gray sleep
  image path.
- A sanitized Cloudflare Worker template that implements the public Cards V1
  and Inbox V2 contracts without including any private account, address,
  credential, content or deployment.

The firmware contains no AI model. ChatGPT, Gemini/Spark, Grok, a scheduled
script or any other producer can create content if it emits the documented
contract into an operator-owned relay. AI-guided setup is the best-tested path;
unguided setup has not yet received independent usability testing.

## Evidence and limits

The frozen candidate passed 293 native tests, the mandatory modeled suites,
linked flash/RAM/resource checks and an offline ESP32-C3 QEMU boot using the
matching retained boot set. Those results do not prove the physical E-Ink
waveform, ADC buttons, microSD interruption behavior, Wi-Fi/Bluetooth radios,
heap fragmentation, watchdog timing, RTC wake, battery use or recovery.

Inbox V2 must not be called stable until an exact-SHA physical X3 run records
visible refresh, paging, text and EPUB opening, sleep-screen delivery,
open/delete/like/dislike actions, offline cache behavior, interrupted retry and
the absence of a new crash report.
