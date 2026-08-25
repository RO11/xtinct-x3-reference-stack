[CmdletBinding()]
param(
    [Parameter()]
    [string]$PythonRuntime
)

$ErrorActionPreference = 'Stop'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$builder = Join-Path $scriptRoot 'build_portable.py'

$pythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($null -ne $pythonCommand) {
    & $pythonCommand.Source -3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'
    if ($LASTEXITCODE -eq 0) {
        $command = @('-3', '-B', $builder)
        if ($PythonRuntime) { $command += @('--python-runtime', $PythonRuntime) }
        & $pythonCommand.Source @command
        exit $LASTEXITCODE
    }
}

$pythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($null -eq $pythonCommand) {
    throw 'Python 3.10 or newer is required to build the portable archive.'
}

& $pythonCommand.Source -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'
if ($LASTEXITCODE -ne 0) {
    throw 'Python 3.10 or newer is required to build the portable archive.'
}

$command = @('-B', $builder)
if ($PythonRuntime) { $command += @('--python-runtime', $PythonRuntime) }
& $pythonCommand.Source @command
exit $LASTEXITCODE
