# Shared helpers for the OSyx PowerShell scripts. Dot-source this file.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Script:Root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$Script:BuildDir = Join-Path $Root 'build'
$Script:EspDir = Join-Path $BuildDir 'esp'
$Script:DiskImage = Join-Path $BuildDir 'osyx.img'
$Script:EspImage = Join-Path $BuildDir 'esp.img'
$Script:RootImage = Join-Path $BuildDir 'root.img'
$Script:EspSizeMiB = 64

function Find-Tool([string]$Name, [string[]]$Candidates) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($c in $Candidates) { if (Test-Path $c) { return $c } }
    return $null
}

$Script:QemuBinary = Find-Tool 'qemu-system-x86_64' @(
    'C:\msys64\ucrt64\bin\qemu-system-x86_64.exe',
    'C:\Program Files\qemu\qemu-system-x86_64.exe')

function Find-Ovmf {
    $dirs = @('C:\msys64\ucrt64\share\qemu', 'C:\Program Files\qemu\share')
    if ($Script:QemuBinary) { $dirs = @((Join-Path (Split-Path (Split-Path $Script:QemuBinary)) 'share\qemu')) + $dirs }
    foreach ($d in $dirs) {
        $code = Join-Path $d 'edk2-x86_64-code.fd'
        $vars = Join-Path $d 'edk2-i386-vars.fd'
        if ((Test-Path $code) -and (Test-Path $vars)) { return @{ Code = $code; Vars = $vars } }
    }
    return $null
}
$Script:Ovmf = Find-Ovmf

# Runs a native command block and fails on a non-zero exit code. Native stderr
# (cargo prints progress there) must not count as an error, so the
# preference is relaxed while the block runs.
function Invoke-Checked([string]$What, [scriptblock]$Block) {
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Block 2>&1 | ForEach-Object { "$_" } } finally { $ErrorActionPreference = $saved }
    if ($LASTEXITCODE -ne 0) { throw "$What failed with exit code $LASTEXITCODE" }
}

$Script:RootSizeMiB = 256

# The ESP, root image and cargo output belong to one workspace. Serialize
# complete builds, including vendor extraction and copying files through WSL.
function Enter-BuildLock {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Root.ToLowerInvariant())) }
    finally { $sha.Dispose() }
    $name = 'Local\OSyx.Build.' + ([BitConverter]::ToString($digest) -replace '-', '')
    $mutex = New-Object Threading.Mutex($false, $name)
    try {
        try { $owned = $mutex.WaitOne(0) }
        catch [Threading.AbandonedMutexException] { $owned = $true }
        if (-not $owned) {
            Write-Host '==> another build is using this workspace; waiting for it to finish'
            try { $owned = $mutex.WaitOne() }
            catch [Threading.AbandonedMutexException] { $owned = $true }
        }
        return $mutex
    } catch { $mutex.Dispose(); throw }
}

# Path of a Windows file as WSL sees it.
function ConvertTo-WslPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path) -replace '\\', '/'
    return '/mnt/' + $full.Substring(0, 1).ToLower() + $full.Substring(2)
}

# Builds build/root.img (ext4) with mke2fs inside WSL; `$BinDir` holds the
# user programs copied to /bin.
function New-RootImage([string]$BinDir) {
    $wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
    if (-not $wsl) { throw 'WSL with e2fsprogs is needed to build the ext4 root image' }
    $script = ConvertTo-WslPath (Join-Path $PSScriptRoot 'mkrootfs.sh')
    $bin = ConvertTo-WslPath $BinDir
    $out = ConvertTo-WslPath $Script:RootImage
    Invoke-Checked 'root image' { wsl.exe -d Ubuntu-24.04 -u root -- bash $script $bin $out $Script:RootSizeMiB }
}

# Packs the system tree a live build installs (stripped, as Setup copies it)
# as a ustar archive for scripts/release.ps1.
function New-ReleaseTar([string]$BinDir, [string]$Output) {
    $script = ConvertTo-WslPath (Join-Path $PSScriptRoot 'mkrootfs.sh')
    $bin = ConvertTo-WslPath $BinDir
    New-Item -ItemType Directory -Force (Split-Path -Parent $Output) | Out-Null
    $out = ConvertTo-WslPath ([IO.Path]::GetFullPath($Output))
    Invoke-Checked 'release tar' { wsl.exe -d Ubuntu-24.04 -u root -- bash $script $bin $out 0 tar }
}

# Builds build/osyx-live.iso from the ESP files build.ps1 already made
# (BOOTX64.EFI, KERNEL.ELF, CMDLINE.TXT) and `$BinDir`: the tree is packed
# as the compressed live root (stripped, cpio + zlib), the ESP files go
# into a FAT16 El Torito boot image and are also visible in ISO9660 for
# UEFI-aware USB tools such as Rufus. There is no hybrid MBR.
function New-LiveImage([string]$BinDir) {
    $liveDir = Join-Path $BuildDir 'live'
    $esp = Join-Path $liveDir 'esp'
    if (Test-Path -LiteralPath $esp) { Remove-Item -LiteralPath $esp -Recurse -Force }
    New-Item -ItemType Directory -Force (Join-Path $esp 'EFI\BOOT'), (Join-Path $esp 'EFI\OSYX\BIN') | Out-Null
    Copy-Item (Join-Path $EspDir 'EFI\BOOT\BOOTX64.EFI') (Join-Path $esp 'EFI\BOOT\BOOTX64.EFI') -Force
    Copy-Item (Join-Path $EspDir 'EFI\OSYX\CMDLINE.TXT') (Join-Path $esp 'EFI\OSYX\CMDLINE.TXT') -Force
    $kernel = ConvertTo-WslPath (Join-Path $EspDir 'EFI\OSYX\KERNEL.ELF')
    $stripped = ConvertTo-WslPath (Join-Path $esp 'EFI\OSYX\KERNEL.ELF')
    Invoke-Checked 'kernel strip' { wsl.exe -d Ubuntu-24.04 -u root -- bash -c "cp '$kernel' '$stripped' && strip --strip-all '$stripped'" }
    $script = ConvertTo-WslPath (Join-Path $PSScriptRoot 'mkrootfs.sh')
    $bin = ConvertTo-WslPath $BinDir
    $archive = ConvertTo-WslPath (Join-Path $esp 'EFI\OSYX\BIN\rootfs.z')
    Invoke-Checked 'live root' { wsl.exe -d Ubuntu-24.04 -u root -- bash $script $bin $archive 0 live }
    $fat = Join-Path $liveDir 'esp.img'
    Invoke-Checked 'live FAT16' { python (Join-Path $PSScriptRoot 'mkfat16.py') $fat $esp }
    Invoke-Checked 'live ISO' { python (Join-Path $PSScriptRoot 'mkiso.py') (Join-Path $BuildDir 'osyx-live.iso') $fat $esp }
    # The same ESP as a GPT disk image for USB sticks (written byte for
    # byte): FAT32 EFI system partition only, the system runs from RAM.
    $usbEsp = Join-Path $liveDir 'usb-esp.img'
    $espMiB = [math]::Max(64, [int][math]::Ceiling(((Get-ChildItem $esp -Recurse -File | Measure-Object Length -Sum).Sum / 1MB) * 1.3) + 16)
    Invoke-Checked 'USB ESP' { cargo run -q -p osyx-fat --example mkfat32 -- $usbEsp $espMiB OSYX-LIVE $esp }
    Invoke-Checked 'USB image' { cargo run -q -p osyx-part --example mkdisk -- (Join-Path $BuildDir 'osyx-live-usb.img') ($espMiB + 2) "esp:$usbEsp" }
}

# Copies the root partition out of build/osyx.img into build/root.img.
function Save-RootPartition {
    $src = [IO.File]::OpenRead($Script:DiskImage)
    $dst = $null
    try {
        # Read the existing GPT instead of using the unrelated size of the
        # previous build/root.img. The latter can silently truncate a root
        # when switching between test images and a Zen installation.
        $reader = [IO.BinaryReader]::new($src)
        [void]$src.Seek(512, 'Begin')
        if ([Text.Encoding]::ASCII.GetString($reader.ReadBytes(8)) -ne 'EFI PART') { throw 'disk has no GPT header' }
        [void]$src.Seek(512 + 72, 'Begin')
        $entriesLba = $reader.ReadUInt64(); $entryCount = $reader.ReadUInt32(); $entrySize = $reader.ReadUInt32()
        if ($entrySize -lt 128 -or $entrySize -gt 4096 -or $entryCount -gt 16384) { throw 'invalid GPT partition table' }
        $rootType = [Guid]'4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709'
        $offset = $null; $len = $null
        for ($i = 0; $i -lt $entryCount; $i++) {
            $entryOffset = [long]$entriesLba * 512 + [long]$i * $entrySize
            if ($entryOffset -lt 0 -or $entryOffset + $entrySize -gt $src.Length) { throw 'GPT entry outside disk' }
            [void]$src.Seek($entryOffset, 'Begin')
            $kind = [Guid]::new($reader.ReadBytes(16))
            if ($kind -ne $rootType) { continue }
            [void]$src.Seek($entryOffset + 32, 'Begin')
            $first = $reader.ReadUInt64(); $last = $reader.ReadUInt64()
            if ($last -lt $first -or $last -ge [uint64]($src.Length / 512)) { throw 'invalid GPT root extent' }
            if ($null -ne $offset) { throw 'more than one OSyx root partition' }
            $offset = [long]$first * 512; $len = [long]($last - $first + 1) * 512
        }
        if ($null -eq $offset) { throw 'OSyx root partition not found in GPT' }
        $dst = [IO.File]::Create($Script:RootImage)
        [void]$src.Seek($offset, 'Begin')
        $buf = New-Object byte[] (4MB)
        $left = $len
        while ($left -gt 0) {
            $n = $src.Read($buf, 0, [int][math]::Min($buf.Length, $left))
            if ($n -le 0) { throw 'disk image shorter than expected' }
            $dst.Write($buf, 0, $n)
            $left -= $n
        }
    } finally { $src.Close(); if ($null -ne $dst) { $dst.Close() } }
}

# Packs build/esp into a FAT32 image and assembles build/osyx.img: GPT with
# the EFI system partition and, if build/root.img exists, the ext4 root.
function New-DiskImage {
    Invoke-Checked 'ESP image' { cargo run -q -p osyx-fat --example mkfat32 -- $Script:EspImage $Script:EspSizeMiB OSYX-ESP $Script:EspDir }
    $parts = @("esp:$($Script:EspImage)")
    $size = $Script:EspSizeMiB + 2
    if (Test-Path $Script:RootImage) {
        $parts += "root:$($Script:RootImage)"
        $size += [int][math]::Ceiling((Get-Item $Script:RootImage).Length / 1MB)
    }
    # Publish a complete image atomically. Truncating the file in place
    # corrupts the view of any QEMU instance still booted from that image.
    $stagedDisk = Join-Path $BuildDir ("osyx-{0}.tmp.img" -f [guid]::NewGuid().ToString('N'))
    $backupDisk = $stagedDisk + '.previous'
    try {
        Invoke-Checked 'disk image' { cargo run -q -p osyx-part --example mkdisk -- $stagedDisk $size @parts }
        if (Test-Path -LiteralPath $Script:DiskImage) {
            # A real backup path also works in Windows PowerShell 5.1,
            # whose binder converts $null string arguments into "".
            try {
                [IO.File]::Replace($stagedDisk, $Script:DiskImage, $backupDisk)
            } catch [IO.IOException] {
                # Test boots (test.ps1, desktop/net/win-test) run QEMU on
                # build/osyx.img itself; run-qemu.ps1 uses a private copy.
                throw "build/osyx.img is open in another process (a QEMU test run?): $($_.Exception.GetBaseException().Message) Wait for scripts/test.ps1 to finish and build again."
            }
        } else {
            [IO.File]::Move($stagedDisk, $Script:DiskImage)
        }
    } finally {
        if (Test-Path -LiteralPath $stagedDisk) { Remove-Item -LiteralPath $stagedDisk }
        # A VM can still hold the old image open. Keep that backup if so.
        if (Test-Path -LiteralPath $backupDisk) { Remove-Item -LiteralPath $backupDisk -ErrorAction SilentlyContinue }
    }
}

# WHPX gives near-native execution instead of TCG's interpreted one. It is
# usable when QEMU was built with it and a hypervisor is already running
# (Hyper-V / Windows Hypervisor Platform); anything else stays on TCG.
$Script:Whpx = $null
function Test-Whpx {
    if ($null -ne $Script:Whpx) { return $Script:Whpx }
    $Script:Whpx = $false
    if ($Script:QemuBinary) {
        try {
            $help = & $Script:QemuBinary -accel help 2>&1 | Out-String
            if ($help -match 'whpx') {
                $Script:Whpx = [bool](Get-CimInstance Win32_ComputerSystem).HypervisorPresent
            }
        } catch { $Script:Whpx = $false }
    }
    return $Script:Whpx
}

# Returns the QEMU argument list for booting build/osyx.img.
function Get-QemuArgs([string]$SerialLog, [switch]$Headless, [int]$MemoryMiB = 512, [int]$QmpPort = 0, [switch]$Gdb, [switch]$NoRng, [switch]$NoUsb, [switch]$NoNet, [string]$HostFwd = '', [switch]$Gpu, [string]$GpuSize = '', [string]$DiskFile = 'build/osyx.img', [switch]$NoDisk, [string]$Cdrom = '', [ValidateRange(1,16)][int]$CpuCount = 1, [ValidateSet('auto','whpx','tcg')][string]$Accel = 'auto', [string]$Nic = 'virtio-net-pci') {
    if (-not $Script:QemuBinary) { throw 'qemu-system-x86_64 not found (run scripts/check-env.ps1)' }
    if (-not $Script:Ovmf) { throw 'OVMF (edk2-x86_64-code.fd) not found' }
    $accelArgs = @()
    # TCG qemu64 needs xsaveopt for CR4.OSXSAVE to work; without it the guest
    # hangs entering the kernel. AVX exercises the XSAVE context-switch path.
    $cpuModel = 'qemu64,+nx,+xsave,+xsaveopt,+avx'
    if ($Accel -eq 'whpx' -or ($Accel -eq 'auto' -and (Test-Whpx))) {
        $accelArgs = @('-accel', 'whpx')
        $cpuModel = 'host'
    }
    if ($NoRng) { $cpuModel += ',-rdseed,-rdrand' }
    # Fresh firmware variables every boot: stale boot entries for devices
    # that no longer exist would otherwise send OVMF to its shell.
    $firmwareDir = Join-Path $BuildDir 'qemu'
    New-Item -ItemType Directory -Force $firmwareDir | Out-Null
    $vars = Join-Path $firmwareDir ("OVMF_VARS-{0}.fd" -f [guid]::NewGuid().ToString('N'))
    Copy-Item $Script:Ovmf.Vars $vars -Force
    $a = $accelArgs + @(
        # No PS/2 controller: keyboard and mouse input can only arrive over USB.
        '-machine', 'q35,i8042=off',
        '-cpu', $cpuModel,
        '-smp', "$CpuCount,sockets=1,cores=$CpuCount,threads=1",
        '-m', "$MemoryMiB",
        '-drive', "if=pflash,format=raw,unit=0,readonly=on,file=$($Script:Ovmf.Code -replace '\\','/')",
        '-drive', "if=pflash,format=raw,unit=1,file=$($vars -replace '\\','/')",
        '-serial', "file:$($SerialLog -replace '\\','/')",
        '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04',
        '-no-reboot'
    )
    # Relative path: the drive-letter colon would be parsed as an option separator.
    if (-not $NoDisk) { $a += @('-drive', "if=virtio,format=raw,file=$($DiskFile -replace '\\','/')") }
    if ($Cdrom) { $a += @('-cdrom', ($Cdrom -replace '\\','/'), '-boot', 'order=d') }
    if (-not $NoRng) { $a += @('-device', 'virtio-rng-pci') }
    # A virtio-net NIC on QEMU's user-mode network (DHCP 10.0.2.15, gateway
    # and host at 10.0.2.2, DNS 10.0.2.3); $HostFwd adds hostfwd rules.
    if ($NoNet) {
        $a += @('-net', 'none')
    } else {
        $nd = 'user,id=n0'
        if ($HostFwd) { $nd += ',' + $HostFwd }
        $a += @('-netdev', $nd, '-device', "$Nic,netdev=n0,mac=52:54:00:12:34:56")
    }
    # USB input through the native xHCI driver (no PS/2 driver exists, so
    # the keyboard and mouse can only reach OSyx this way).
    if (-not $NoUsb) {
        $a += @('-device', 'qemu-xhci,id=xhci', '-device', 'usb-kbd,bus=xhci.0,id=kbd', '-device', 'usb-mouse,bus=xhci.0,id=mouse')
    }
    # VirtIO-GPU as the only display device (no VGA): the desktop must be
    # presented through the virtio-gpu driver, the GOP framebuffer is gone.
    if ($Gpu) {
        $dev = 'virtio-gpu-pci'
        if ($GpuSize) { $w, $h = $GpuSize -split 'x'; $dev += ",xres=$w,yres=$h" }
        $a += @('-vga', 'none', '-device', $dev)
    }
    if ($Headless) { $a += @('-display', 'none') }
    if ($QmpPort -gt 0) { $a += @('-qmp', "tcp:127.0.0.1:$QmpPort,server,nowait") }
    if ($Gdb) { $a += @('-s', '-S') }
    return $a
}

function Start-Qemu([string[]]$QemuArgs) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Script:QemuBinary
    $psi.WorkingDirectory = $Script:Root
    $psi.UseShellExecute = $false
    $psi.Arguments = ($QemuArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    return [System.Diagnostics.Process]::Start($psi)
}

# Sends one QMP command (after capability negotiation) and returns the reply.
function Invoke-Qmp([int]$Port, [string]$Json) {
    $client = New-Object System.Net.Sockets.TcpClient('127.0.0.1', $Port)
    try {
        $stream = $client.GetStream()
        $stream.ReadTimeout = 15000
        $stream.WriteTimeout = 15000
        $reader = New-Object System.IO.StreamReader($stream)
        $writer = New-Object System.IO.StreamWriter($stream)
        $writer.AutoFlush = $true
        [void]$reader.ReadLine()  # greeting
        $writer.WriteLine('{"execute":"qmp_capabilities"}')
        [void]$reader.ReadLine()
        $writer.WriteLine($Json)
        while ($true) {
            $line = $reader.ReadLine()
            if ($null -eq $line -or $line -match '"return"|"error"') { return $line }
        }
    } finally { $client.Close() }
}

function Save-Screenshot([int]$Port, [string]$Path) {
    $p = $Path -replace '\\', '/'
    return Invoke-Qmp $Port "{`"execute`":`"screendump`",`"arguments`":{`"filename`":`"$p`",`"format`":`"png`"}}"
}

function Wait-ForLog([string]$Log, [string]$Pattern, [int]$TimeoutSec, [System.Diagnostics.Process]$Proc) {
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ((Test-Path $Log) -and (Select-String -Path $Log -Pattern $Pattern -Quiet)) { return $true }
        if ($Proc -and $Proc.HasExited) { return $false }
        Start-Sleep -Milliseconds 200
    }
    return $false
}
