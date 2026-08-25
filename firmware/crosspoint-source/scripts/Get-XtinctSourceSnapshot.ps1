[CmdletBinding()]
param(
    [string]$SourceRoot
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module Microsoft.PowerShell.Utility -Force -ErrorAction Stop

if ([string]::IsNullOrWhiteSpace($SourceRoot)) {
    $SourceRoot = Join-Path $PSScriptRoot '..'
}

$sourceRoot = [System.IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
$rootItem = Get-Item -LiteralPath $sourceRoot -Force -ErrorAction Stop
if (-not $rootItem.PSIsContainer -or
    ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Source snapshot root must be a plain directory: $sourceRoot"
}

$excludedDirectoryNames = @(
    '.git', '.pio', '.cache', '__pycache__', '.idea', '.vscode', '.vs',
    '.history', '.venv'
)
$excludedDirectoryPrefixes = @('.xtinct-host-tests', '.xtinct-android-tests', '.xtinct-emulator')
$excludedRootDirectories = @('build', '.dummy')
$excludedRootFiles = @(
    'output3.txt', 'x3root.html', 'CMakeLists.txt', 'dependencies.lock',
    'sdkconfig.default', 'sdkconfig.defaults', 'compile_commands.json'
)

$entries = [Collections.Generic.List[object]]::new()
$pending = [Collections.Generic.Stack[string]]::new()
$pending.Push($sourceRoot)
while ($pending.Count -gt 0) {
    $directory = $pending.Pop()
    foreach ($item in Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Source snapshot refuses a reparse point: $($item.FullName)"
        }
        if (-not $item.FullName.StartsWith(
                $sourceRoot + [System.IO.Path]::DirectorySeparatorChar,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Source snapshot path escaped the repository: $($item.FullName)"
        }

        $relative = $item.FullName.Substring($sourceRoot.Length + 1).Replace('\', '/')
        $rootLevel = -not $relative.Contains('/')
        $generatedDirectory = $false
        foreach ($prefix in $excludedDirectoryPrefixes) {
            if ($item.Name.StartsWith($prefix, [System.StringComparison]::Ordinal)) {
                $generatedDirectory = $true
                break
            }
        }

        if ($item.Name -eq '.git') {
            continue
        }

        if ($item.PSIsContainer) {
            if ($excludedDirectoryNames -contains $item.Name -or
                $generatedDirectory -or
                ($rootLevel -and $excludedRootDirectories -ccontains $item.Name)) {
                continue
            }
            $pending.Push($item.FullName)
            continue
        }

        if (($rootLevel -and $excludedRootFiles -ccontains $item.Name) -or
            $item.Extension -in @('.log', '.pyc') -or
            $item.Name -eq '.DS_Store') {
            continue
        }

        $digest = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $entries.Add([pscustomobject]@{
            Path = $relative
            Length = [int64]$item.Length
            Sha256 = $digest
        })
    }
}

$entries.Sort([Comparison[object]]{
    param($left, $right)
    return [StringComparer]::Ordinal.Compare([string]$left.Path, [string]$right.Path)
})
$entries = @($entries)
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    foreach ($entry in $entries) {
        $record = "{0}`0{1}`0{2}`n" -f $entry.Path, $entry.Length, $entry.Sha256
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($record)
        [void]$sha.TransformBlock($bytes, 0, $bytes.Length, $null, 0)
    }
    [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
    $snapshot = [System.BitConverter]::ToString($sha.Hash).Replace('-', '').ToLowerInvariant()
} finally {
    $sha.Dispose()
}

[pscustomobject]@{
    schema = 1
    root = $sourceRoot
    files = $entries.Count
    sha256 = $snapshot
} | ConvertTo-Json -Compress
