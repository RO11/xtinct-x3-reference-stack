[CmdletBinding()]
param(
    [string[]]$PlatformIoArguments = @('run', '-e', 'default')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$releaseCacheName = '.xtinct-ready24-packages-R24-POCKET-SYNC-20260808-A'
$frameworkUri = 'https://github.com/espressif/arduino-esp32/releases/download/3.3.7/esp32-core-3.3.7.tar.xz'
$markerText = "XTINCT READY24`nR24-POCKET-SYNC-20260808-A`n$frameworkUri`n"

function Assert-PlainDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$LiteralPath,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $item = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
    if (-not $item.PSIsContainer) {
        throw "$Label is not a directory: $LiteralPath"
    }
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "$Label must not be a reparse point: $LiteralPath"
    }
    return $item
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
    $childFull = [IO.Path]::GetFullPath($Child)
    if (-not $childFull.StartsWith($parentFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "$Label escaped its expected parent: $childFull"
    }
}

$scriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptPath)) {
    throw 'Cannot resolve this script path.'
}
$projectRoot = [IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $scriptPath) '..'))
$platformIoRoot = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('UserProfile')) '.platformio'))
$globalPackages = [IO.Path]::GetFullPath((Join-Path $platformIoRoot 'packages'))
$privatePackages = [IO.Path]::GetFullPath((Join-Path $platformIoRoot $releaseCacheName))
$markerPath = [IO.Path]::GetFullPath((Join-Path $privatePackages '.xtinct-owner'))

Assert-PlainDirectory -LiteralPath $projectRoot -Label 'XTINCT project root' | Out-Null
Assert-PlainDirectory -LiteralPath $platformIoRoot -Label 'PlatformIO core directory' | Out-Null
Assert-PlainDirectory -LiteralPath $globalPackages -Label 'Global PlatformIO package directory' | Out-Null
Assert-ChildPath -Parent $platformIoRoot -Child $globalPackages -Label 'Global package directory'
Assert-ChildPath -Parent $platformIoRoot -Child $privatePackages -Label 'READY24 package cache'

if (-not (Test-Path -LiteralPath $privatePackages)) {
    New-Item -ItemType Directory -Path $privatePackages -ErrorAction Stop | Out-Null
    Assert-PlainDirectory -LiteralPath $privatePackages -Label 'Created READY24 package cache' | Out-Null
    [IO.File]::WriteAllText($markerPath, $markerText, [Text.UTF8Encoding]::new($false))
}

Assert-PlainDirectory -LiteralPath $privatePackages -Label 'READY24 package cache' | Out-Null
if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
    throw "READY24 package cache ownership marker is missing: $markerPath"
}
if ([IO.File]::ReadAllText($markerPath, [Text.Encoding]::UTF8) -cne $markerText) {
    throw "READY24 package cache ownership marker is not the expected immutable value: $markerPath"
}

# Reuse already-verified large tools through directory junctions. The stock
# Arduino framework and its ESP-IDF libraries are deliberately excluded. The
# latter must be an owned READY24 package, not a global junction: changing the
# pinned sdkconfig to enable NimBLE makes pioarduino rebuild those libraries.
# Keeping both private lets that rebuild happen without mutating global tools.
$globalItems = Get-ChildItem -LiteralPath $globalPackages -Directory -Force -ErrorAction Stop |
    Where-Object {
        $_.Name -ne 'framework-arduinoespressif32' -and
        $_.Name -ne 'framework-arduinoespressif32-libs' -and
        (Test-Path -LiteralPath (Join-Path $_.FullName '.piopm') -PathType Leaf)
    }

foreach ($sourceItem in $globalItems) {
    if (($sourceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Global package is unexpectedly a reparse point: $($sourceItem.FullName)"
    }

    $destination = [IO.Path]::GetFullPath((Join-Path $privatePackages $sourceItem.Name))
    Assert-ChildPath -Parent $privatePackages -Child $destination -Label 'Package junction'
    if (-not (Test-Path -LiteralPath $destination)) {
        New-Item -ItemType Junction -Path $destination -Target $sourceItem.FullName -ErrorAction Stop | Out-Null
    }

    $linkItem = Get-Item -LiteralPath $destination -Force -ErrorAction Stop
    if (-not $linkItem.PSIsContainer -or
        ($linkItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0) {
        throw "Expected an owned package junction: $destination"
    }
    $resolvedSource = [IO.Path]::GetFullPath(
        (Resolve-Path -LiteralPath $sourceItem.FullName -ErrorAction Stop).Path
    )
    $linkTargets = @($linkItem.Target)
    if ($linkTargets.Count -ne 1) {
        throw "Package junction does not have exactly one target: $destination"
    }
    $resolvedTarget = [IO.Path]::GetFullPath([string]$linkTargets[0])
    if ($resolvedTarget -cne $resolvedSource) {
        throw "Package junction target changed: $destination"
    }
}

$oldPackagesDir = [Environment]::GetEnvironmentVariable('PLATFORMIO_PACKAGES_DIR', 'Process')
$oldXtinctPackagesDir = [Environment]::GetEnvironmentVariable('XTINCT_PINNED_PACKAGES_DIR', 'Process')
try {
    $frameworkDir = Join-Path $privatePackages 'framework-arduinoespressif32'
    $frameworkMeta = Join-Path $frameworkDir '.piopm'
    if (-not (Test-Path -LiteralPath $frameworkDir)) {
        [Environment]::SetEnvironmentVariable('PLATFORMIO_PACKAGES_DIR', $privatePackages, 'Process')
        & py -3.11 -m platformio pkg install --global --tool $frameworkUri
        if ($LASTEXITCODE -ne 0) {
            throw "Pinned Arduino framework installation failed with exit code $LASTEXITCODE."
        }
    }

    Assert-PlainDirectory -LiteralPath $frameworkDir -Label 'Pinned Arduino framework' | Out-Null
    if (-not (Test-Path -LiteralPath $frameworkMeta -PathType Leaf)) {
        throw "Pinned Arduino framework metadata is missing: $frameworkMeta"
    }
    $metadata = Get-Content -Raw -LiteralPath $frameworkMeta -Encoding UTF8 | ConvertFrom-Json
    if ($metadata.spec.uri -cne $frameworkUri) {
        throw "Pinned Arduino framework URI mismatch: $($metadata.spec.uri)"
    }
    if (-not ([string]$metadata.version).StartsWith('3.3.7', [StringComparison]::Ordinal)) {
        throw "Pinned Arduino framework version mismatch: $($metadata.version)"
    }

    [Environment]::SetEnvironmentVariable('PLATFORMIO_PACKAGES_DIR', $oldPackagesDir, 'Process')
    [Environment]::SetEnvironmentVariable('XTINCT_PINNED_PACKAGES_DIR', $privatePackages, 'Process')
    Write-Host "XTINCT READY24 isolated packages: $privatePackages"
    & py -3.11 (Join-Path $projectRoot 'scripts\build_xtinct.py') @PlatformIoArguments
    if ($LASTEXITCODE -ne 0) {
        throw "XTINCT build wrapper failed with exit code $LASTEXITCODE."
    }

    Assert-PlainDirectory -LiteralPath $frameworkDir -Label 'Pinned Arduino framework' | Out-Null
    if (-not (Test-Path -LiteralPath $frameworkMeta -PathType Leaf)) {
        throw "Pinned Arduino framework metadata is missing: $frameworkMeta"
    }
    $metadata = Get-Content -Raw -LiteralPath $frameworkMeta -Encoding UTF8 | ConvertFrom-Json
    if ($metadata.spec.uri -cne $frameworkUri) {
        throw "Pinned Arduino framework URI mismatch: $($metadata.spec.uri)"
    }
    Write-Host "Verified pinned Arduino framework: $($metadata.version)"
}
finally {
    [Environment]::SetEnvironmentVariable('PLATFORMIO_PACKAGES_DIR', $oldPackagesDir, 'Process')
    [Environment]::SetEnvironmentVariable('XTINCT_PINNED_PACKAGES_DIR', $oldXtinctPackagesDir, 'Process')
}
