# Install on an Xteink X3

This guide is for the **X3 only**. Do not use X4/legacy 480×800 assets or a binary built for a different MCU/device.

## Before installing

1. Charge the reader and keep USB power connected.
2. Confirm you can reach the official CrossPoint recovery image linked in `RECOVERY.md`.
3. Download the XTINCT release's installable BIN and checksum file.
4. Verify the exact size and SHA-256 shown in the release manifest.
5. Read the evidence report. If physical-X3 verification is pending, understand that you are installing an alpha candidate.

PowerShell checksum example:

```powershell
Get-FileHash -LiteralPath .\XTINCT-X3-firmware-1.6.2-xtinct.1-update.bin -Algorithm SHA256
```

## Stage the canonical update

1. On the X3, open **File Transfer** and leave that screen open.
2. Open the displayed private address from a device on the same Wi-Fi/hotspot.
3. Upload the verified release BIN to the File Transfer root as exactly `/update.bin`.
4. Confirm the X3 accepted the write and re-list `/update.bin` to verify its exact byte count.
5. Exit File Transfer only after the upload finishes.

The release filename is descriptive on your computer. `/update.bin` is the one canonical name on the X3.

## Install

Use the X3's physical firmware-update screen to install the staged image. Keep the device powered and do not close the transfer/update workflow mid-write.

The phone/web stager only stages bytes. It does not remotely trigger a full-device install.

## First setup

The public image starts with no Worker destination and no reader token. It therefore performs no XTINCT network request until you deliberately provision both.

1. Deploy or choose your own compatible private relay.
2. Create a 32–256-character printable reader bearer.
3. Store the bearer in a local secret manager.
4. Connect the X3 over physical USB.
5. Run the release's credential-provisioning helper with your canonical `workers.dev` origin.
6. Open Phone Wi-Fi Setup to configure Wi-Fi, local UTC offset, wake time and the auto-sync switch.

On Windows, create a **Generic Credential** named `XTINCT/Public/X3Feed/Reader` and place the reader bearer in its password field. Then run:

```powershell
.\scripts\Provision-X3FeedCredential.ps1 `
  -Port COM7 `
  -WorkerOrigin 'https://<worker>.<account>.workers.dev'
```

The script requires an explicit COM port, verifies the Espressif USB identity,
then completes a token-free challenge against the exact public X3 build before
it reads the bearer from Windows Credential Manager. It sends one bounded
credential command, recognizes only fixed token-free responses and clears its
owned buffers. The Worker origin is not secret; the bearer is never accepted
as a command-line argument.

Changing a credential later requires physical USB and, when replacing an existing credential, the X3 must be on its Wi-Fi Setup screen. Responses and logs never echo the submitted origin/token payload.

## Sleep screen

The included `/sleep.bmp` is exactly 528×792, uncompressed 4-bpp, full-bleed, and uses only the four native gray palette entries. Upload it separately to the File Transfer root if you want the public reference artwork. Its master, preview and validation evidence are included so the conversion is reproducible.
