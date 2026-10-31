# HID over I2C test: boots OSyx with `init.args=tests,i2c` in QEMU with an extra
# SSDT that adds a touchpad on an I2C controller (PCI 00:15.1) that QEMU does
# not have. Checks, from the serial log, that:
#   * the in-kernel self-test of the I2C stack (simulated controller and device) passed;
#   * i2chidd evaluated the AML (_STA, _CRS, _DSM, SSCN/FMCN) and described the touchpad;
#   * the kernel received the description and refused the missing controller
#     with a reason, claiming nothing (no fake device appears);
#   * i2chidd ended normally.
# What this cannot show: a working controller or touchpad. Only real hardware can.
param([switch]$SkipBuild)
. (Join-Path $PSScriptRoot 'common.ps1')
$testDir = Join-Path $BuildDir 'test'
New-Item -ItemType Directory -Force $testDir | Out-Null
$failed = 0
function Record([string]$Name, [bool]$Ok, [string]$Detail) {
    Write-Host ("[{0}] {1} {2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $Detail)
    if (-not $Ok) { $script:failed++ }
}
$ssdt = Join-Path $testDir 'i2c-hid.ssdt.aml'
python (Join-Path $PSScriptRoot 'gen-i2c-ssdt.py') $ssdt
if ($LASTEXITCODE -ne 0) { throw 'SSDT generation failed' }
$disk = Join-Path $testDir 'i2c-hid.img'
if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot 'build.ps1') -NoZen -Cmdline 'test.exit boot.fast init.args=tests,i2c' -OutputImage $disk | Out-Null
}
$log = Join-Path $testDir 'i2c-hid.serial.log'
Remove-Item $log -ErrorAction SilentlyContinue
Push-Location $Root
try {
    $qemuArgs = Get-QemuArgs -SerialLog $log -Headless -DiskFile ($disk.Substring($Root.Length + 1)) -NoNet
    $qemuArgs += @('-acpitable', 'file=build/test/i2c-hid.ssdt.aml')
    $vm = Start-Qemu $qemuArgs
} finally { Pop-Location }
$exited = $vm.WaitForExit(180000)
if (-not $exited) { $vm.Kill() }
$fs = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
try { $t = (New-Object IO.StreamReader($fs)).ReadToEnd() -replace '\x1b\[[0-9;?]*[a-zA-Z]', '' -replace "`r", '' } finally { $fs.Close() }
Record 'VM ended by itself' $exited ''
Record 'in-kernel I2C stack self-test' ($t -match '\[test\] HID over I2C: controller, protocol, input core \(simulated\) \.\.\. ok') ''
Record 'i2chidd described the touchpad from the AML' ($t -match 'i2chidd: \S*TPD0: address 0x15 on \S*I2C9 \(400000 Hz\), descriptor register 0x0001') ([regex]::Match($t, 'i2chidd: \S*TPD0.*').Value)
Record 'kernel refused the missing controller with a reason' ($t -match 'i2c: controller \S*I2C9 not claimed: no such PCI function') ([regex]::Match($t, 'i2c: controller .*not claimed.*').Value)
Record 'nothing was claimed or registered' ($t -match 'i2c: 0 of 1 HID over I2C device\(s\) claimed' -and $t -match 'i2chidd: the kernel claimed 0 of 1 device\(s\)' -and $t -notmatch 'i2c-hid \S+: \w+:\w+ at') ''
Record 'i2chidd exited normally' ($t -match 'init: i2chidd exit status Some\(0\)') ''
Write-Host "i2c-hid test: $failed failed"
exit $failed
