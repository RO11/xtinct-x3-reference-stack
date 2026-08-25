# Public alpha beta checklist

Target: `0.1.0-alpha.4`

## Automated candidate gate

- [ ] Windows CI passes contract, JavaScript, Python and release-engineering tests.
- [ ] Ubuntu CI passes contract, JavaScript, Python and release-engineering tests.
- [ ] Sanitization reports zero forbidden paths, secrets, unapproved firmware or private payloads.
- [ ] Rebuilding the portable archive twice produces the same SHA-256.
- [ ] The ZIP contains `FILES.SHA256`, `release-metadata.json`, licenses, synthetic fixtures and the exact allowlisted CrossPoint `v1.5.0` baseline.
- [ ] The ZIP and external `.sha256` file are attached to the draft release.

## Clean-machine testers

These are intentionally pending until three people outside the development machine complete them without live help.

- [ ] Tester 1: extract, launch, navigate Home/Inbox, run one failure scenario, stop cleanly.
- [ ] Tester 2: extract, launch, navigate Home/Inbox, run one failure scenario, stop cleanly.
- [ ] Tester 3: extract, launch, navigate Home/Inbox, run one failure scenario, stop cleanly.
- [ ] All testers confirm the bundled package launches without a system Python installation.
- [ ] Without opening the README or receiving help, all testers correctly state that the package includes stable CrossPoint `v1.5.0`, while the device canvas still uses synthetic modeled fixtures rather than firmware execution.
- [ ] Without opening the README or receiving help, all testers correctly distinguish the bundled baseline as read-only metadata and official-flasher input, QEMU as separate and not started, and the physical X3 firmware version as unknown to the app.
- [ ] All testers verify the published ZIP SHA-256 before launch.
- [ ] No tester reports a non-loopback listener, outbound request or private content.

## Maintainer review

- [ ] Screenshots use synthetic data and show the evidence labels.
- [ ] Release notes say "unofficial" and link to the official CrossPoint Simulator.
- [ ] Release notes state that E-Ink, buttons, SD power loss, radios, RTC, watchdog, heap, battery and board power remain physical-device gates.
- [ ] No claim says the package executes arbitrary firmware unless QEMU evidence for that exact image is attached.
- [ ] Community proposal is posted before wider promotion.

Do not mark the alpha generally validated until all three tester rows have evidence attached.
