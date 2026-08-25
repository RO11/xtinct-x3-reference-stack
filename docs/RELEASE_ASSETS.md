# Release assets

Each firmware release publishes a source-complete, byte-bound set rather than a
standalone mystery BIN.

| Asset | Purpose |
| --- | --- |
| `XTINCT-X3-firmware-<version>-update.bin` | Installable ESP32-C3 application image; upload to the X3 as canonical `/update.bin` |
| `XTINCT-X3-Reference-Stack-<repo-version>-source.zip` | Exact public firmware, FreeInk, tooling, docs, sleep master and service-template source |
| `XTINCT-X3-<version>-qemu-boot-set.zip` | Matching app, bootloader, partition table and `boot_app0.bin` used by postbuild QEMU |
| `XTINCT-X3-<version>-dependency-sources.zip` | Exact external PlatformIO library source tree retained from the authoritative lane |
| `XTINCT-X3-<version>-evidence.zip` | Source-bound prebuild/postbuild reports, linked budget/security evidence and release profile |
| `SHA256SUMS.txt` | SHA-256 for every downloadable asset |
| `release-manifest.json` | Machine-readable byte counts, hashes, source identity and evidence status |

GitHub's automatically generated tag archives are convenient, but the named
source ZIP is the release authority because its contents are generated from an
explicit allowlist and included in the hash manifest.

The dependency-source archive is corresponding source, not a binary SDK or a
claim that every dependency is maintained by XTINCT. Original component
licenses and notices remain authoritative.

