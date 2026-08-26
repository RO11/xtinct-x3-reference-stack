# XTINCT X3 Reference Stack v0.1.0-alpha.3

Alpha.3 publishes a new, endpoint-free X3 firmware candidate focused on making
Daily Cards V1 and Inbox V2 recover predictably when a private content relay is
late, incomplete, overfull, unauthorized or temporarily corrupt. It also makes
the full public source and dependency provenance path reproducible from a clean
checkout without relying on private build folders.

## What changed on the X3

- Daily Cards accepts exactly four validated cards. Incomplete or oversized
  candidate sets are rejected without replacing a known-good cache.
- A visible `CATCH_UP_PENDING` state distinguishes a healthy refresh that has
  not yet received today's complete set from a frozen or crashed screen.
- Metadata scans select the newest bounded page even when the relay has more
  than 64 retained objects, instead of becoming stuck on an old page.
- HTTP 401 and 403 responses are classified as unauthorized rather than being
  collapsed into a generic download failure.
- Inbox refresh painting is guarded so a busy/progress screen cannot recurse
  through a second display update during the same operation.
- The existing cursor paging, immutable artifact SHA verification, cache-first
  reads, Today EPUB opening, open/delete actions, like/dislike receipts and
  retryable outbox behavior remain part of the mandatory release matrix.

## Reference relay hardening

The included account-neutral Cloudflare Worker template now enforces the same
bounded recovery contract as the firmware:

- exact-four card publication with deterministic placeholders when a producer
  has not supplied a complete set;
- cache-aware reads and explicit failure for a corrupt retained object;
- a bounded scan with a sentinel beyond the live window, followed by a
  transactional repair of the retained set;
- `503 repair_pending` while a repair is incomplete, so the X3 keeps its known
  good cache and retries instead of accepting a partial snapshot;
- rollback and exact-count tests covering the repair path.

This is a reference implementation only. It contains no account, email,
credential, private Worker address, producer content or deployed service.

## Exact firmware and evidence

- Firmware version: `1.6.2-xtinct.2`
- Build ID: `BUILD-162-XTINCT2-PUBLIC`
- Installable size: `6,481,456` bytes
- Installable SHA-256:
  `0031621d01bfe43d951ba700fa699bc99d64d584e90a33d461f56bd5eb61a196`
- Frozen firmware-source SHA-256:
  `d8baf2b9f2ef7e0a5251a7eb6728c2ea07c2de58d15fe222309aade00bb2665f`
- Linked DRAM: `143,809` bytes
- RTC slow memory: `4,178` bytes
- Remaining OTA image headroom: `72,144` bytes

The exact frozen source passed 293 native tests. The final image and its
matching bootloader, partition table and `boot_app0.bin` passed 82 modeled,
contract and offline ESP32-C3 QEMU checks with zero postbuild checks pending.
The image is below the hard OTA limit but below the 128 KiB warning reserve, so
future features must have a non-positive net flash delta unless space is first
recovered.

## Evidence boundary

This remains a prerelease because simulator and QEMU evidence cannot prove the
physical E-Ink waveform, ADC-ladder buttons, microSD interruption/brownout
behavior, Wi-Fi/Bluetooth radio behavior, fragmented heap, task-watchdog timing,
RTC wake, battery use or recovery on an actual X3. Those eight physical gates
remain explicitly pending for this exact firmware SHA.

The public image is not the private deployment build. It starts unconfigured,
contains no private endpoint, and makes no XTINCT network request until an
operator provisions their own compatible relay and bearer over physical USB.
