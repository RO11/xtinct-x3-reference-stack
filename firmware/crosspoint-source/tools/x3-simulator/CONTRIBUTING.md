# Contributing

Thank you for helping improve X3 Preview & QA Lab. Discuss substantial ideas with the CrossPoint community before building a competing firmware simulator; this project is intended to complement the official CrossPoint Simulator.

## Before opening a pull request

1. Use synthetic fixtures only.
2. Keep the server loopback-only and outbound-network-free.
3. Label evidence as `MODELED`, `REAL CONTRACT TEST`, `QEMU`, or `PHYSICAL DEVICE REQUIRED`.
4. Run `npm test` and `npm run sanitize` from this directory.
5. Add a deterministic regression test for behavior changes.
6. Do not commit device dumps, SD-card copies, credentials, environment files, build output, QEMU runtimes, personal paths, private/OEM firmware or screenshots containing private content. A community firmware baseline is allowed only when its redistribution license is recorded and the release contract pins one exact official asset by version, byte count and SHA-256.

## Design scope

The alpha prioritizes repeatable flow preview, failure injection, input replay, visual comparison and sanitized diagnostics. Shared firmware rendering belongs upstream or in collaboration with the official simulator. Hardware claims require evidence from the exact physical device and build under test.

## Commit and review notes

Explain the user-visible change, evidence level, tests run and any physical boundary left unverified. Packaging changes must preserve deterministic ZIP bytes, the per-file manifest and the source-portable/self-contained distinction.
