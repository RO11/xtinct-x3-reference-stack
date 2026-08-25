# Licensing

The distributable XTINCT X3 firmware is offered under **GPL-3.0-or-later**. The full GPLv3 text is in [`LICENSE`](LICENSE).

This choice is driven by the actual embedded dependency graph: the firmware statically incorporates wolfSSL, which is available under GPL-2.0-or-later or commercial terms. GPL-3.0 is compatible with the Apache-2.0 components also present in the image. This repository does not grant commercial wolfSSL rights.

Upstream and third-party files retain their own copyright statements and license notices. In particular:

- CrossPoint Reader: MIT.
- FreeInk SDK and its OpenX4 lineage notice: MIT/notice terms in the included source.
- ArduinoJson, QRCode, SdFat and several small components: MIT-style terms.
- JPEGDEC, PNGdec and NimBLE-Arduino: Apache-2.0.
- WebSockets: LGPL-2.1-or-later.
- tinycrypt components: BSD-style terms.
- wolfSSL: GPL-2.0-or-later, or separate commercial terms obtained from wolfSSL.
- GoogleTest: BSD-3-Clause; test-only and not linked into the device image.

`LICENSES/` contains the principal license texts. Component-local license and notice files remain the authority for each component. `THIRD_PARTY_NOTICES.md` is an engineering inventory, not legal advice. Anyone redistributing a binary should review the exact release SBOM and obtain qualified legal advice.
