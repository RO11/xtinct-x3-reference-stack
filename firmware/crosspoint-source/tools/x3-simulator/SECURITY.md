# Security policy

## Supported version

Security fixes are developed against the latest public alpha. Earlier alpha archives may be replaced rather than patched in place.

## Reporting

Please do not publish an exploitable report or include real credentials, private SD contents, firmware, or device dumps in an issue. Contact the maintainer privately through the security-reporting channel listed on the repository profile. Include:

- the alpha version and archive SHA-256;
- Windows and Python versions;
- a minimal synthetic reproduction;
- the expected and observed loopback behavior.

If no private channel is available, open a minimal issue asking the maintainer to establish one; do not post exploit details.

## Security boundary

The intended preview server binds only to `127.0.0.1`, makes no outbound request, does not discover devices, and creates a private temporary session directory. Treat any build that listens on a non-loopback interface, follows links, reads outside its packaged fixture tree, or contacts an external host as a security defect.

The lab is not a firmware flasher or a sandbox for untrusted firmware. The bundled stable CrossPoint baseline is inert and read-only inside the lab. QEMU and physical-device behavior are outside the portable alpha.
