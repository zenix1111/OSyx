# OSyx Win Parity Check: how much of the Windows API the Win32 layer implements.
#
# Wraps scripts/winparity.py. By default it scans the sources and the last
# `scripts/win-test.ps1` serial log (build/test/win.serial.log) and writes
# build/winparity/report.json and report.html, with a history under
# build/winparity/history for progress and regressions between scans.
#
#   .\scripts\win-parity.ps1                      scan
#   .\scripts\win-parity.ps1 -Test                tests of the tool itself
#   .\scripts\win-parity.ps1 -Reference           rebuild the reference dataset
#                                                 from this Windows installation
#   .\scripts\win-parity.ps1 -ExtractSteam        extract the NSIS plug-in DLLs of
#                                                 SteamSetup.exe (needs 7-Zip) so
#                                                 the Steam profile covers them
#   .\scripts\win-parity.ps1 -Runtime             boot OSyx, dump the compiled
#                                                 export tables (`winrun --exports`)
#                                                 and cross-check the source scan
#   .\scripts\win-parity.ps1 -FailOnRegression    exit 2 when a scan is worse
param(
    [switch]$Test,
    [switch]$Reference,
    [switch]$ExtractSteam,
    [switch]$Runtime,
    [switch]$FailOnRegression,
    [string]$TestsLog,
    [string]$Format = 'terminal,json,html',
    [int]$Top = 15
)
. (Join-Path $PSScriptRoot 'common.ps1')
# Native tools print progress to stderr; only exit codes decide.
$ErrorActionPreference = 'Continue'
$py = Find-Tool 'python' @()
if (-not $py) { throw 'python is required (see scripts/check-env.ps1)' }
$tool = Join-Path $PSScriptRoot 'winparity.py'
$outDir = Join-Path $BuildDir 'winparity'

if ($Test) {
    Push-Location $Root
    try { & $py -m unittest (Join-Path 'scripts' 'test_winparity.py'); exit $LASTEXITCODE } finally { Pop-Location }
}
if ($Reference) {
    & $py $tool reference --root $Root
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
if ($ExtractSteam) {
    $setup = Join-Path $BuildDir 'steam\core\SteamSetup.exe'
    $sevenZip = Find-Tool '7z' @('C:\Program Files\7-Zip\7z.exe')
    if (-not (Test-Path $setup)) { throw "missing $setup" }
    if (-not $sevenZip) { throw '7-Zip is required to unpack the NSIS installer' }
    $tmp = Join-Path $BuildDir 'steam\unpack'
    $dest = Join-Path $BuildDir 'steam\plugins'
    New-Item -ItemType Directory -Force $tmp, $dest | Out-Null
    & $sevenZip x -y "-o$tmp" $setup '$PLUGINSDIR\*.dll' | Out-Null
    Get-ChildItem -LiteralPath (Join-Path $tmp '$PLUGINSDIR') -Filter *.dll | Copy-Item -Destination $dest -Force
    Write-Host ("steam plug-ins: " + ((Get-ChildItem $dest -Filter *.dll).Name -join ', '))
}
$scanArgs = @($tool, 'scan', '--root', $Root, '--format', $Format, '--top', $Top)
if ($TestsLog) { $scanArgs += @('--tests-log', $TestsLog) }
if ($FailOnRegression) { $scanArgs += '--fail-on-regression' }
if ($Runtime) {
    New-Item -ItemType Directory -Force $outDir | Out-Null
    $log = Join-Path $outDir 'runtime.serial.log'
    $img = Join-Path $outDir 'runtime.img'
    & (Join-Path $PSScriptRoot 'build.ps1') -NoZen -Cmdline 'init.args=tests,winrun,--exports test.exit' -OutputImage $img *> (Join-Path $outDir 'runtime-build.out')
    if ($LASTEXITCODE -ne 0) { throw 'image build failed (see build\winparity\runtime-build.out)' }
    if (Test-Path $log) { Remove-Item $log }
    $port = Get-Random -Minimum 20000 -Maximum 40000
    $vm = Start-Qemu (Get-QemuArgs -SerialLog $log -Headless -MemoryMiB 1024 -QmpPort $port -DiskFile $img)
    try { [void]$vm.WaitForExit(180 * 1000) } finally { if (-not $vm.HasExited) { $vm.Kill() } }
    Remove-Item $img -ErrorAction SilentlyContinue
    $scanArgs += @('--runtime-exports', $log)
}
& $py @scanArgs
exit $LASTEXITCODE
