# USB storage test: a stick on the xHCI controller (label PENDRIVE, in an
# MBR partition like Windows makes them) must be mounted at /media/PENDRIVE,
# refuse a safe eject while a file on it is open, eject cleanly otherwise,
# come back after a replug with the data written before, and survive being
# pulled out while a file is open (see userspace/apps/src/media_checks.rs,
# which prints the MEDIA_* markers this script reacts to). Runs once for a
# FAT32 stick and once for an exFAT one.
param([switch]$SkipBuild, [int]$TimeoutSec = 240, [string[]]$FileSystems = @('fat32', 'exfat'))
. (Join-Path $PSScriptRoot 'common.ps1')
$testDir = Join-Path $BuildDir 'test'
New-Item -ItemType Directory -Force $testDir | Out-Null
$failed = 0
function Record([string]$Name, [bool]$Ok, [string]$Detail) {
    Write-Host ("[{0}] {1} {2}" -f $(if ($Ok) { 'PASS' } else { 'FAIL' }), $Name, $Detail)
    if (-not $Ok) { $script:failed++ }
}
$disk = Join-Path $testDir 'usbstorage.img'
if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot 'build.ps1') -NoZen -Cmdline 'init.args=tests,media' -OutputImage $disk | Out-Null
} elseif (-not (Test-Path $disk)) {
    Copy-Item -LiteralPath $DiskImage -Destination $disk
}

function Text([string]$Log) {
    if (-not (Test-Path $Log)) { return '' }
    $fs = [IO.File]::Open($Log, 'Open', 'Read', 'ReadWrite')
    try { (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Close() }
}
function Wait([string]$Log, [string]$Pattern, [int]$Seconds) {
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end) { $m = [regex]::Match((Text $Log), $Pattern); if ($m.Success) { return $m }; Start-Sleep -Milliseconds 300 }
    return $null
}

function Test-Stick([string]$Fs) {
    Write-Host "==> $Fs stick"
    $log = Join-Path $testDir "usbstorage-$Fs.serial.log"
    $stick = Join-Path $testDir "usbstick-$Fs.img"
    $vol = Join-Path $testDir "usbstick-$Fs-volume.img"
    $src = Join-Path $testDir 'usbstick-src'
    if (Test-Path $src) { Remove-Item $src -Recurse -Force }
    New-Item -ItemType Directory -Force $src | Out-Null
    [IO.File]::WriteAllText((Join-Path $src 'HELLO.TXT'), "Hello from the stick`n")
    Push-Location $Root
    try {
        if ($Fs -eq 'exfat') {
            Invoke-Checked 'stick volume' { cargo run -q -p osyx-exfat --example mkexfat -- $vol 64 PENDRIVE $src }
            Invoke-Checked 'stick MBR' { python (Join-Path $PSScriptRoot 'mkusbmbr.py') $stick $vol 07 }
        } else {
            Invoke-Checked 'stick volume' { cargo run -q -p osyx-fat --example mkfat32 -- $vol 64 PENDRIVE $src }
            Invoke-Checked 'stick MBR' { python (Join-Path $PSScriptRoot 'mkusbmbr.py') $stick $vol 0c }
        }
    } finally { Pop-Location }

    Remove-Item $log -ErrorAction SilentlyContinue
    $qmp = Get-Random -Minimum 20000 -Maximum 40000
    $a = Get-QemuArgs -SerialLog $log -Headless -NoUsb -NoNet -MemoryMiB 1024 -QmpPort $qmp -DiskFile ($disk.Substring($Root.Length + 1))
    $stickRel = ($stick.Substring($Root.Length + 1)).Replace([string][char]92, '/')
    $a += @('-device', 'qemu-xhci,id=xhci',
            # -blockdev (unlike -drive) survives device_del, so the stick can be plugged in again.
            '-blockdev', "driver=file,node-name=stickfile,filename=$stickRel",
            '-blockdev', 'driver=raw,node-name=stick0,file=stickfile',
            '-device', 'usb-storage,bus=xhci.0,drive=stick0,id=stickdev')
    Push-Location $Root
    try { $vm = Start-Qemu $a } finally { Pop-Location }
    try {
        $m = Wait $log "media: usb\d+(p\d)? \($Fs\) mounted at /media/PENDRIVE" $TimeoutSec
        Record "$Fs`: kernel mounted the stick at /media/PENDRIVE" ($null -ne $m) $(if ($m) { $m.Value } else { '' })
        $e = Wait $log 'MEDIA_EJECTED (usb\d+)' 90
        Record "$Fs`: guest ejected the stick" ($null -ne $e) $(if ($e) { $e.Value } else { '' })
        if ($e) {
            $null = Wait $log 'media: usb\d+ ejected: it is safe to remove it' 10
            $r = Invoke-Qmp $qmp '{"execute":"device_del","arguments":{"id":"stickdev"}}'
            $u = Wait $log 'media: usb\d+ unplugged after eject' 30
            Record "$Fs`: unplug after eject cleaned up" ($null -ne $u) $r
            Start-Sleep -Seconds 1
            $r = Invoke-Qmp $qmp '{"execute":"device_add","arguments":{"driver":"usb-storage","bus":"xhci.0","drive":"stick0","id":"stickdev"}}'
            if ($r -match 'error') { Write-Host "  QMP device_add: $r" }
        }
        $y = Wait $log 'MEDIA_READY_YANK (usb\d+)' 90
        Record "$Fs`: replugged stick mounted again" ($null -ne $y) $(if ($y) { $y.Value } else { '' })
        if ($y) {
            $null = Invoke-Qmp $qmp '{"execute":"device_del","arguments":{"id":"stickdev"}}'
        }
        $done = Wait $log 'media checks: (\d+) failed' 60
        Record "$Fs`: guest checks finished" ($null -ne $done) $(if ($done) { $done.Value } else { '' })
        if ($done) { Record "$Fs`: guest checks all passed" ($done.Groups[1].Value -eq '0') '' }
        $t = Text $log
        foreach ($f in [regex]::Matches($t, 'MEDIA_(FAIL|TIMEOUT) [^\r\n]*')) { Write-Host "  $($f.Value)" }
        Record "$Fs`: stick pulled out while mounted was detached" ($t -match 'media: usb\d+ was removed while mounted') ''
        Record "$Fs`: no kernel panic" ($t -notmatch 'KERNEL PANIC') ''
    } finally {
        if (-not $vm.HasExited) { $vm.Kill() }
    }
}

foreach ($fs in $FileSystems) { Test-Stick $fs }
Write-Host "usb storage test: $failed failed"
exit $failed
