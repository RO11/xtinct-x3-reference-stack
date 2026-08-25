# Distribution contract

The public artifact is named `X3-Preview-QA-Lab-Windows-v0.1.0-alpha.4-bundled-python.zip`. It includes the reviewed official 64-bit CPython `3.14.7` Windows embeddable runtime, so it does not require a system Python installation. The words `self-contained` or `one-click without prerequisites` must not be used for a source-portable archive.

`release-profile.json` is the machine-readable authority for the product name, version, Xteink X3/ESP32-C3 target, and firmware policy. Alpha.4 is a synthetic modeled preview with no device access. It bundles the unchanged official stable CrossPoint Reader `v1.5.0` `firmware.bin` as a read-only baseline. The package verifies the baseline's `5,544,112` bytes and SHA-256 `a7087155757bc63c1fcf60ae8d60a3760ce6d3406aaf7b9f23d0025244434f08`; it never executes or auto-flashes it. A configured source-checkout run may inspect a different explicitly selected local image read-only.

## Package types

| Type | Runtime | Honest launch claim |
|---|---|---|
| `source-portable` | No bundled Python | Double-click launcher after Python 3.10+ is installed |
| `bundled-python` | Reviewed local Python runtime | Double-click launcher; no Python installation needed |
| `pyinstaller` | Reproducible reviewed executable | Self-contained only after clean-machine verification |

The builder detects a local bundled runtime input and names the package from the distribution actually produced. Alpha.4 pins the complete official CPython `3.14.7` embedded source tree to SHA-256 `04cb0c29f815d844dac63b70a47b6905e0676fe03a5603c485b59a286c1f9f97` using the documented path-length-content tree algorithm. Packaging adds only the standard `../../..` application entry to `python314._pth`, keeps automatic `site` import disabled, and pins that configured tree to `73d86e9cc8dae5a0cf207b4b7364a092859679bf1478b920397b6c74bb17a665`. Its source archive is `12,673,227` bytes with SHA-256 `d297e5ff019966817ad8502465176139f2d3d840fa4ed84b13bed399a6ab1f15`. PyInstaller being installed on a build machine does not by itself make an executable reproducible, reviewed or clean-machine verified.

## Required contents

- launcher, standard-library Python application source, and the pinned CPython embedded runtime with its license;
- browser assets and synthetic fixtures;
- exact official stable CrossPoint baseline, its manifest and MIT license notice;
- X3 resource contract used by the preview;
- `release-profile.json` with the exact release and firmware policy;
- README, security, contribution and beta-test documents;
- MIT license and font notices/license texts;
- `FILES.SHA256` and `release-metadata.json`.

## Forbidden contents

- firmware, bootloaders, partition images, ELF/MAP/UF2/HEX files other than the single exact allowlisted stable CrossPoint baseline;
- QEMU executables, DLLs, flash images or caches;
- build, artifact, runtime-log, coverage or dependency directories;
- device dumps, SD-card copies, production data or private screenshots;
- tokens, environment files, credentials, email addresses or personal paths;
- links, junctions, reparse points or special files.

## Reproducibility

Archive entries are sorted, use a fixed ZIP timestamp and normalized permissions, and are created from an explicit allowlist. Two builds from identical bytes and the same source epoch must have the same SHA-256. The external `.sha256` file authenticates the ZIP; the internal `FILES.SHA256` authenticates the extracted payload.

Schema-2 `release-metadata.json` records a path-and-length-framed SHA-256 over every transformed packaged input except the generated metadata and internal manifest, plus the exact builder-script and demo-contract SHA-256 values. It also records a positive source epoch and, when Git is available, the commit ID and whether relevant source inputs were dirty. Git state is useful context but never the artifact authority: the public-payload digest identifies the shipped input bytes even from a dirty checkout.

On local Windows machines, disposable staging is restricted to a validated real `D:\quarantine`, falling back to the same literal folder on `E:` only when `D:` is unavailable. The one final archive and checksum are retained under `release/`. Hosted CI may instead use the isolated runner temp directory. The builder never follows links and removes only its unique staging directory after validating that boundary.

## Publication order

1. Run the full test and sanitization suites on Windows and Ubuntu.
2. Build the deterministic package twice and compare hashes.
3. Verify the external and internal manifests and all schema-2 provenance hashes.
4. Attach the exact ZIP and `.sha256` file to a draft GitHub release.
5. Complete the three outside-tester rows in `BETA_TEST_CHECKLIST.md`.
6. Discuss the alpha with the CrossPoint community before wider promotion.

No script in this repository commits, pushes, publishes or creates a release automatically.
