<#
.SYNOPSIS
Provisions one bound XTINCT X3 Worker-origin/reader-token credential over USB.

.DESCRIPTION
Waits for one explicitly selected COM port, opens it at 115200 baud, verifies
the public X3 firmware identity, reads the existing Generic Credential from
Windows Credential Manager, and sends exactly one
`CMD:XTINCT_FEED:<canonical-worker-origin> <token>\n` command.

The token is never accepted as a parameter, printed, logged, or written to a
file. It is copied directly from Credential Manager into a byte buffer (never a
managed String), then the owned command/response buffers are cleared in a
finally block. Windows and the serial driver can still make transient internal
copies while transmitting; this script cannot zero memory owned by them.

.PARAMETER Port
The exact Windows serial port to use. No alternate port is auto-selected.

.PARAMETER WorkerOrigin
The canonical Cloudflare Workers origin, for example
https://<worker>.<account>.workers.dev. Paths, ports and custom domains are rejected.

.PARAMETER CredentialTarget
The Windows Generic Credential name containing the reader bearer as its password.

.EXAMPLE
.\scripts\Provision-X3FeedCredential.ps1 -Port COM7 -WorkerOrigin 'https://<worker>.<account>.workers.dev'

Run this only after the custom XTINCT firmware is installed and the X3 is awake.
If a token is already stored, open Phone Wi-Fi Setup on the X3 before replacing it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 192)]
    [string]$WorkerOrigin,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^COM[1-9][0-9]{0,2}$')]
    [string]$Port,

    [Parameter()]
    [ValidateRange(1, 60)]
    [int]$EnumerationTimeoutSeconds = 30,

    [Parameter()]
    [ValidateRange(1, 30)]
    [int]$ResponseTimeoutSeconds = 12,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$CredentialTarget = 'XTINCT/Public/X3Feed/Reader'
)

$ErrorActionPreference = 'Stop'
$baudRate = 115200
$Port = $Port.ToUpperInvariant()

$portNumber = 0
if (-not [int]::TryParse($Port.Substring(3), [ref]$portNumber) -or $portNumber -lt 1 -or $portNumber -gt 256) {
    throw 'Port must be a Windows COM port from COM1 through COM256.'
}

if (-not ('XtinctUsbFeedCommand' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

public static class XtinctUsbFeedCommand
{
    private const UInt32 GenericCredentialType = 1;
    private const int TokenMinimumLength = 32;
    private const int TokenMaximumLength = 256;
    private const int CommandPrefixLength = 16; // ASCII length of CMD:XTINCT_FEED:
    private const int OriginMaximumLength = 192;
    private const string ExpectedIdentity = "OK:XTINCT_IDENTITY:X3:BUILD-162-XTINCT2-PUBLIC";

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CREDENTIAL
    {
        public UInt32 Flags;
        public UInt32 Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public UInt32 CredentialBlobSize;
        public IntPtr CredentialBlob;
        public UInt32 Persist;
        public UInt32 AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, UInt32 type, UInt32 flags, out IntPtr credentialPtr);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern void CredFree(IntPtr credentialPtr);

    // Builds the complete wire command without ever materializing the token as
    // a managed String. The caller owns and must clear the returned byte array.
    public static byte[] Build(string target, string workerOrigin)
    {
        if (String.IsNullOrWhiteSpace(workerOrigin) || workerOrigin.Length > OriginMaximumLength)
        {
            throw new InvalidOperationException("The Worker origin is empty or too long.");
        }
        string canonicalOrigin = workerOrigin.TrimEnd('/').ToLowerInvariant();
        if (!Regex.IsMatch(
                canonicalOrigin,
                @"^https://(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,}[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$",
                RegexOptions.CultureInvariant))
        {
            throw new InvalidOperationException(
                "Use one canonical https://<worker>.<account>.workers.dev origin with no path or port.");
        }
        byte[] originBytes = Encoding.ASCII.GetBytes(canonicalOrigin);

        IntPtr credentialPtr;
        if (!CredRead(target, GenericCredentialType, 0, out credentialPtr))
        {
            int error = Marshal.GetLastWin32Error();
            if (error == 1168)
            {
                throw new InvalidOperationException(
                    "The XTINCT reader credential was not found in Windows Credential Manager.");
            }

            throw new Win32Exception(error, "Windows Credential Manager could not read the XTINCT reader credential.");
        }

        byte[] command = null;
        try
        {
            CREDENTIAL credential = (CREDENTIAL)Marshal.PtrToStructure(credentialPtr, typeof(CREDENTIAL));
            if (credential.CredentialBlob == IntPtr.Zero || credential.CredentialBlobSize == 0 ||
                (credential.CredentialBlobSize % 2) != 0)
            {
                throw new InvalidOperationException("The XTINCT reader credential has an invalid data format.");
            }

            int tokenLength = checked((int)credential.CredentialBlobSize / 2);
            if (tokenLength < TokenMinimumLength || tokenLength > TokenMaximumLength)
            {
                throw new InvalidOperationException("The XTINCT reader credential must contain 32 through 256 characters.");
            }

            int tokenOffset = checked(CommandPrefixLength + originBytes.Length + 1);
            command = new byte[checked(tokenOffset + tokenLength + 1)];
            byte[] prefix = new byte[]
            {
                0x43, 0x4d, 0x44, 0x3a, 0x58, 0x54, 0x49, 0x4e, 0x43,
                0x54, 0x5f, 0x46, 0x45, 0x45, 0x44, 0x3a
            };
            Buffer.BlockCopy(prefix, 0, command, 0, prefix.Length);
            Buffer.BlockCopy(originBytes, 0, command, CommandPrefixLength, originBytes.Length);
            command[tokenOffset - 1] = 0x20;

            for (int index = 0; index < tokenLength; index++)
            {
                ushort value = unchecked((ushort)Marshal.ReadInt16(credential.CredentialBlob, index * 2));
                // Match the firmware's accepted range and exclude whitespace,
                // CR, and LF so one credential can produce only one command.
                if (value < 0x21 || value > 0x7e)
                {
                    throw new InvalidOperationException(
                        "The XTINCT reader credential contains a character that is unsafe for the USB protocol.");
                }

                command[tokenOffset + index] = (byte)value;
            }

            command[command.Length - 1] = 0x0a; // Exactly LF; never CRLF.
            byte[] result = command;
            command = null;
            return result;
        }
        finally
        {
            if (command != null)
            {
                Array.Clear(command, 0, command.Length);
            }

            CredFree(credentialPtr);
        }
    }

    // Returns only fixed, token-free protocol constants. Unknown lines (for
    // example normal firmware logs or an accidental echo) are silently ignored.
    public static string GetSafeResponse(byte[] response, int count, byte[] command)
    {
        if (response == null || command == null || count < 1 || count > response.Length)
        {
            return null;
        }

        while (count > 0 && response[count - 1] == 0x0d)
        {
            count--;
        }

        if (ContainsToken(response, count, command))
        {
            return null;
        }

        if (EqualsAscii(response, count, "OK:XTINCT_FEED")) return "OK:XTINCT_FEED";
        if (EqualsAscii(response, count, "ERR:XTINCT_FEED:LOCKED")) return "ERR:XTINCT_FEED:LOCKED";
        if (EqualsAscii(response, count, "ERR:XTINCT_FEED:FORMAT")) return "ERR:XTINCT_FEED:FORMAT";
        if (EqualsAscii(response, count, "ERR:XTINCT_FEED:ORIGIN")) return "ERR:XTINCT_FEED:ORIGIN";
        if (EqualsAscii(response, count, "ERR:XTINCT_FEED:TOKEN")) return "ERR:XTINCT_FEED:TOKEN";
        if (EqualsAscii(response, count, "ERR:XTINCT_FEED:SAVE")) return "ERR:XTINCT_FEED:SAVE";
        return null;
    }

    public static bool IsExpectedIdentity(byte[] response, int count)
    {
        if (response == null || count < 1 || count > response.Length) return false;
        while (count > 0 && response[count - 1] == 0x0d) count--;
        return EqualsAscii(response, count, ExpectedIdentity);
    }

    private static bool ContainsToken(byte[] response, int responseCount, byte[] command)
    {
        int tokenOffset = -1;
        for (int index = CommandPrefixLength; index < command.Length - 1; index++)
        {
            if (command[index] == 0x20)
            {
                tokenOffset = index + 1;
                break;
            }
        }
        if (tokenOffset < 0) return false;
        int tokenLength = command.Length - tokenOffset - 1;
        if (tokenLength < TokenMinimumLength || responseCount < tokenLength)
        {
            return false;
        }

        for (int offset = 0; offset <= responseCount - tokenLength; offset++)
        {
            bool matches = true;
            for (int index = 0; index < tokenLength; index++)
            {
                if (response[offset + index] != command[tokenOffset + index])
                {
                    matches = false;
                    break;
                }
            }

            if (matches) return true;
        }

        return false;
    }

    private static bool EqualsAscii(byte[] candidate, int count, string expected)
    {
        if (expected.Length != count) return false;
        for (int index = 0; index < count; index++)
        {
            if (candidate[index] != (byte)expected[index]) return false;
        }

        return true;
    }
}
'@
}

function Assert-XtinctComIdentity {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpectedPort
    )

    # SerialPort.GetPortNames proves that the port currently exists; this
    # independent PnP check prevents a different device later assigned the same
    # COM number from receiving the credential.
    $portLabelPattern = '\(' + [regex]::Escape($ExpectedPort) + '\)\s*$'
    $candidates = @(
        Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop |
            Where-Object {
                (($null -ne $_.Name -and $_.Name -match $portLabelPattern) -or
                 ($null -ne $_.Caption -and $_.Caption -match $portLabelPattern))
            }
    )

    if ($candidates.Count -eq 0) {
        throw "Windows did not expose a Win32_PnPEntity identity for $ExpectedPort. Nothing was sent."
    }
    if ($candidates.Count -ne 1) {
        throw "Windows exposed more than one Win32_PnPEntity identity for $ExpectedPort. Nothing was sent."
    }

    $deviceId = [string]$candidates[0].DeviceID
    if ([string]::IsNullOrWhiteSpace($deviceId) -or
        $deviceId.IndexOf('VID_303A&PID_1001', [StringComparison]::OrdinalIgnoreCase) -lt 0) {
        throw "$ExpectedPort is not the expected Espressif USB device (VID_303A&PID_1001). Nothing was sent."
    }

    $deviceId = $null
    $candidates = $null
}

Write-Host "Waiting for the explicitly selected X3 port $Port..."
$enumerationDeadline = [DateTime]::UtcNow.AddSeconds($EnumerationTimeoutSeconds)
$portFound = $false
do {
    foreach ($availablePort in [System.IO.Ports.SerialPort]::GetPortNames()) {
        if ([string]::Equals($availablePort, $Port, [StringComparison]::OrdinalIgnoreCase)) {
            $portFound = $true
            break
        }
    }

    if (-not $portFound) {
        Start-Sleep -Milliseconds 250
    }
} while (-not $portFound -and [DateTime]::UtcNow -lt $enumerationDeadline)

if (-not $portFound) {
    throw "The requested serial port $Port did not enumerate within $EnumerationTimeoutSeconds seconds."
}

Assert-XtinctComIdentity -ExpectedPort $Port

$serialPort = $null
$identityCommand = $null
$identityBytes = $null
$commandBytes = $null
$responseBytes = $null
$safeResponse = $null
try {
    $serialPort = New-Object System.IO.Ports.SerialPort(
        $Port,
        $baudRate,
        [System.IO.Ports.Parity]::None,
        8,
        [System.IO.Ports.StopBits]::One
    )
    $serialPort.Handshake = [System.IO.Ports.Handshake]::None
    $serialPort.DtrEnable = $true
    $serialPort.RtsEnable = $false
    $serialPort.ReadTimeout = 250
    $serialPort.WriteTimeout = 2000
    $serialPort.Open()

    # Give native USB CDC a moment to observe DTR, then remove stale boot logs.
    Start-Sleep -Milliseconds 750
    $serialPort.DiscardInBuffer()

    # Confirm the exact public firmware before Credential Manager is read. A
    # generic ESP32-C3 sharing the USB VID/PID must never receive the bearer.
    $identityCommand = [Text.Encoding]::ASCII.GetBytes("CMD:XTINCT_IDENTITY`n")
    $identityBytes = New-Object byte[] 128
    $identityCount = 0
    $identityDiscard = $false
    $identityMatched = $false
    $identityDeadline = [DateTime]::UtcNow.AddSeconds($ResponseTimeoutSeconds)
    $serialPort.Write($identityCommand, 0, $identityCommand.Length)
    while (-not $identityMatched -and [DateTime]::UtcNow -lt $identityDeadline) {
        try {
            $value = $serialPort.ReadByte()
        }
        catch [System.TimeoutException] {
            continue
        }
        if ($value -eq 0x0a) {
            if (-not $identityDiscard) {
                $identityMatched = [XtinctUsbFeedCommand]::IsExpectedIdentity(
                    $identityBytes,
                    $identityCount
                )
            }
            [Array]::Clear($identityBytes, 0, $identityBytes.Length)
            $identityCount = 0
            $identityDiscard = $false
            continue
        }
        if ($identityDiscard) { continue }
        if ($identityCount -ge $identityBytes.Length) {
            [Array]::Clear($identityBytes, 0, $identityBytes.Length)
            $identityCount = 0
            $identityDiscard = $true
            continue
        }
        $identityBytes[$identityCount] = [byte]$value
        $identityCount++
    }
    if (-not $identityMatched) {
        throw 'The selected USB device did not identify as the expected public XTINCT X3 firmware. Nothing was sent.'
    }
    $serialPort.DiscardInBuffer()

    # Delay secret access until the exact port is present and open.
    $commandBytes = [XtinctUsbFeedCommand]::Build($CredentialTarget, $WorkerOrigin)
    $serialPort.Write($commandBytes, 0, $commandBytes.Length)

    $responseBytes = New-Object byte[] 384
    $responseCount = 0
    $discardUntilLineFeed = $false
    $responseDeadline = [DateTime]::UtcNow.AddSeconds($ResponseTimeoutSeconds)

    while ($null -eq $safeResponse -and [DateTime]::UtcNow -lt $responseDeadline) {
        try {
            $value = $serialPort.ReadByte()
        }
        catch [System.TimeoutException] {
            continue
        }

        if ($value -eq 0x0a) {
            if (-not $discardUntilLineFeed) {
                $safeResponse = [XtinctUsbFeedCommand]::GetSafeResponse(
                    $responseBytes,
                    $responseCount,
                    $commandBytes
                )
            }

            [Array]::Clear($responseBytes, 0, $responseBytes.Length)
            $responseCount = 0
            $discardUntilLineFeed = $false
            continue
        }

        if ($discardUntilLineFeed) {
            continue
        }

        if ($responseCount -ge $responseBytes.Length) {
            [Array]::Clear($responseBytes, 0, $responseBytes.Length)
            $responseCount = 0
            $discardUntilLineFeed = $true
            continue
        }

        $responseBytes[$responseCount] = [byte]$value
        $responseCount++
    }

    if ($null -eq $safeResponse) {
        throw "The X3 did not return a recognized feed-credential response within $ResponseTimeoutSeconds seconds."
    }

    if ($safeResponse -ne 'OK:XTINCT_FEED') {
        throw "The X3 rejected the bound feed credential: $safeResponse"
    }

    Write-Host "X3 Worker origin and reader token provisioned successfully on $Port (OK:XTINCT_FEED)."
}
finally {
    try {
        if ($null -ne $serialPort) {
            try {
                if ($serialPort.IsOpen) {
                    $serialPort.Close()
                }
            }
            finally {
                $serialPort.Dispose()
            }
        }
    }
    finally {
        # Clear our buffers even when closing a disconnected USB device throws.
        if ($null -ne $responseBytes) {
            [Array]::Clear($responseBytes, 0, $responseBytes.Length)
        }
        if ($null -ne $identityBytes) {
            [Array]::Clear($identityBytes, 0, $identityBytes.Length)
        }
        if ($null -ne $identityCommand) {
            [Array]::Clear($identityCommand, 0, $identityCommand.Length)
        }
        if ($null -ne $commandBytes) {
            [Array]::Clear($commandBytes, 0, $commandBytes.Length)
        }

        $safeResponse = $null
        $responseBytes = $null
        $identityBytes = $null
        $identityCommand = $null
        $commandBytes = $null
        $serialPort = $null
        [GC]::Collect()
    }
}
