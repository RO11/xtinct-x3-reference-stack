# Vendored FreeInk source

Public XTINCT source archives include FreeInk as ordinary source files rather
than requiring a nested Git checkout.

- Upstream repository: `https://github.com/crosspoint-reader/FreeInk`
- Upstream revision: `a485dc46ef5fb2283e4bdb674002ddbef97a9268`
- XTINCT patch: `patches/freeink-secureclient-verified-tls.patch`
- Patched tree inventory: 385 files
- Patched tree SHA-256: `88bc44960c820d66c6bfaf81093b17db89745a486bacbedeb357adedba409674`

The inventory digest is SHA-256 over sorted UTF-8 records in the form
`path NUL byte-count NUL file-sha256 LF`. The build-time
`scripts/apply_xtinct_freeink_patch.py` gate recomputes it, rejects links and
reparse points, and also verifies the exact patch and patched client bytes.

Original licenses and notices remain in `freeink-sdk/` and the repository's
top-level `THIRD_PARTY_NOTICES.md`.
