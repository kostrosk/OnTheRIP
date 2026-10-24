# SPDX-License-Identifier: GPL-3.0-only
[CmdletBinding()]
param(
    [string]$ProgramPath = (Join-Path $PSScriptRoot 'scripts/portable-disc-workflow.py'),

    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config/local.json'),

    [ValidatePattern('^[A-Za-z]:$')]
    [string]$Drive = 'E:',

    [switch]$Watch,

    [string]$PythonCommand = 'python'
)

$ErrorActionPreference = 'Stop'
$programFile = Get-Item -LiteralPath $ProgramPath -ErrorAction Stop
$configFile = Get-Item -LiteralPath $ConfigPath -ErrorAction Stop
if ($programFile.PSIsContainer -or $configFile.PSIsContainer) {
    throw 'ProgramPath and ConfigPath must name existing files.'
}

$mode = if ($Watch) { 'watch' } else { 'once' }
$arguments = @(
    $programFile.FullName,
    '--config', $configFile.FullName,
    $mode,
    '--drive', $Drive,
    '--execute'
)

& $PythonCommand @arguments
exit $LASTEXITCODE
