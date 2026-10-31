# Forward unparsed arguments to the same Python engine used on Linux.
$ErrorActionPreference = 'Stop'
$aroEntry = Join-Path $PSScriptRoot 'aro.py'
$aroPython = Get-Command python -ErrorAction SilentlyContinue
if ($aroPython) {
    & $aroPython.Source $aroEntry @args
    exit $LASTEXITCODE
}
$aroLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($aroLauncher) {
    & $aroLauncher.Source -3 $aroEntry @args
    exit $LASTEXITCODE
}
Write-Error 'ARO requires Python 3.11 or newer. Install it and retry.'
exit 2
