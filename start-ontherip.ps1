[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ProgramPath,

    [Parameter(Mandatory = $true)]
    [string]$ConfigPath,

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
