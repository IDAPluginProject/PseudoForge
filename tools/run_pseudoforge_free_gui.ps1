[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$Venv = ".venv-free-gui",
    [switch]$NoInstall
)

$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")
$venvPath = Join-Path $repoRoot.Path $Venv
$venvPython = Join-Path $venvPath "Scripts\python.exe"

if (-not (Test-Path -LiteralPath $venvPython)) {
    & $Python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

if (-not $NoInstall) {
    & $venvPython -m pip install PySide6
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }
}

& $venvPython -B (Join-Path $PSScriptRoot "pseudoforge_free_gui.py")
exit $LASTEXITCODE
