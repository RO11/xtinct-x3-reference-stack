# Recovery

Keep one known recovery path before installing alpha firmware.

The public kit does **not** redistribute stock/private recovery binaries. It records an external reference to the official CrossPoint Reader v1.5.0 firmware:

- Release: <https://github.com/crosspoint-reader/crosspoint-reader/releases/tag/v1.5.0>
- Asset: <https://github.com/crosspoint-reader/crosspoint-reader/releases/download/v1.5.0/firmware.bin>
- Expected bytes: `5,544,112`
- Expected SHA-256: `a7087155757bc63c1fcf60ae8d60a3760ce6d3406aaf7b9f23d0025244434f08`

Verify those values after download. If the upstream asset changes, stop and investigate instead of bypassing the mismatch.

## Normal rollback

If the X3 still boots and File Transfer works, stage the verified official recovery bytes as the canonical `/update.bin`, verify its listed size, then use the physical firmware-update screen.

## If the reader cannot boot normally

Use the upstream CrossPoint recovery documentation for the exact hardware revision. Hardware-level flash recovery can require opening the device and carries real risk to the display, battery and board. This repository does not claim that a simulator or QEMU result proves that recovery path.

Never erase broad storage areas, delete the only known-good image, or improvise with a firmware file for another Xteink model.
