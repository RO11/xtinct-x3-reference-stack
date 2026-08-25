# Security policy

Please report suspected credential exposure, unsafe update behavior, path traversal, parser bounds failures or privacy leaks privately to the repository owner before opening a public issue.

Do not include real tokens, private Worker origins, email addresses, device serials, IP addresses, SD-card dumps, crash memory, build-machine paths or personal content in an issue.

## Security boundaries

- The public firmware embeds no deployment endpoint or credential.
- A Worker origin and bearer are provisioned together over physical USB as one versioned NVS record.
- Phone setup can change Wi-Fi and schedule settings but rejects origin and token fields.
- Only canonical Cloudflare Workers HTTPS origins are accepted by the first public release.
- Authenticated V1/V2 requests explicitly disable redirects.
- Artifacts are admitted by bounded metadata and verified byte count/SHA-256 before promotion.
- Credentials are not serialized to the SD card or echoed in normal diagnostics.
- Release archives and firmware artifacts are scanned for personal paths, private endpoints and credential shapes.

These controls reduce risk; they are not a guarantee against physical extraction, malicious firmware, compromised cloud accounts, or vulnerabilities in the ESP32/toolchain/dependencies.
