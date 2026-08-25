# Contributing

XTINCT changes are welcome when they remain reproducible, recovery-safe and
honest about what was actually tested.

## Before opening a change

1. Keep the public firmware unconfigured. Do not add a default relay, bearer,
   mailbox, account ID, device identity or local path.
2. Preserve the atomic origin-plus-token NVS credential record and the explicit
   no-redirect policy for authenticated requests.
3. Check every X3 source change with:

   ```powershell
   cd firmware\crosspoint-source
   python -B scripts/check_x3_resource_budgets.py
   python -B test/xtinct_feed_credential_policy/verify_source_contract.py
   ```

4. Regenerate HTML and translations before freezing a source snapshot.
5. Run the complete prebuild and postbuild release workflow in
   [docs/BUILD_FIRMWARE.md](docs/BUILD_FIRMWARE.md) before attaching a BIN.
6. Run the public sanitizer over the exact proposed repository and release
   assets.

## Evidence language

Use the narrowest accurate term: modeled, contract-tested, built, QEMU-booted
or device-verified. A simulator pass is not physical-X3 proof. Physical release
reports should name the exact firmware SHA-256 and record E-Ink, buttons, SD,
Wi-Fi/BLE, watchdog, RTC wake, battery and recovery separately.

## Resource contract

`firmware/crosspoint-source/config/x3-resource-budgets.json` is authoritative.
A skipped or unavailable required check blocks release; it is not a warning.

## Security and privacy

Use synthetic fixture data. Never commit `.env`, `.dev.vars`, credential-store
exports, Wrangler state, crash dumps, private QA logs or production proofs.
Report vulnerabilities using [SECURITY.md](SECURITY.md).

