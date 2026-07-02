param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [string]$Platform = "x64"
)

$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$sampleRoot = Split-Path -Parent $scriptRoot
$solution = Join-Path $sampleRoot "PfIoctlRecovery.sln"

$msbuildCandidates = @(
    "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe"
)

$msbuild = $msbuildCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $msbuild)
{
    throw "MSBuild.exe was not found. Install Visual Studio 2022 with WDK components."
}

& $msbuild $solution /m /p:Configuration=$Configuration /p:Platform=$Platform /p:SpectreMitigation=false /v:minimal
if ($LASTEXITCODE -ne 0)
{
    throw "MSBuild failed with exit code $LASTEXITCODE"
}

$outDir = Join-Path $sampleRoot "$Platform\$Configuration"
Write-Host "Driver: $(Join-Path $outDir 'PfIoctlRecovery.sys')"

