# Builds BOOTX64.EFI and the kernel, validates the kernel image with the boot
# loader's own ELF rules, assembles the EFI system partition in build/esp and
# packs it into the GPT disk image build/osyx.img.
param(
    [string]$Cmdline = 'init.args=desktop',
    [switch]$DebugBuild,
    # Leave \EFI\OSYX\BIN out of the ESP (kernel boots without user programs).
    [switch]$NoInit,
    # Keep the root partition of the current build/osyx.img (e.g. to boot
    # again after a simulated power cut) instead of building a fresh one.
    [switch]$KeepRoot,
    [ValidateRange(128, 16384)][int]$RootMiB = 256,
    # Install the vendor payload, desktop shortcut and default web browser.
    [string]$ZenDirectory = '',
    # Small test/development images can explicitly omit the browser.
    [switch]$NoZen,
    # Build the compressed live ISO (system in RAM, no root partition).
    [switch]$Live,
    # Capture this exact build before another build can replace osyx.img.
    [string]$OutputImage = '',
    # With -Live: also pack the installed system tree as a tar for
    # scripts/release.ps1 (system updates).
    [string]$ReleaseTar = ''
)
. (Join-Path $PSScriptRoot 'common.ps1')
$buildLock = Enter-BuildLock
$stage = $null
Push-Location $Root
try {
$Script:RootSizeMiB = $RootMiB
if ($NoZen -and $ZenDirectory) { throw 'Use either -NoZen or -ZenDirectory' }
if ($Live) {
    if ($ZenDirectory) { throw '-Live cannot include Zen: the package exceeds the 64 MiB boot module limit' }
    if ($NoInit) { throw '-Live needs its programs in the live root' }
    if ($KeepRoot) { throw '-Live does not build a disk image' }
    if ($OutputImage) { throw '-Live writes build/osyx-live.iso' }
} elseif ($ReleaseTar) {
    throw '-ReleaseTar needs -Live (an update carries what Setup installs)'
}
if ($Live) {
    if (-not $PSBoundParameters.ContainsKey('Cmdline')) { $Cmdline = 'init.args=desktop live' }
    $NoZen = $true
}
if (-not $NoZen -and -not $NoInit -and -not $KeepRoot) {
    if (-not $ZenDirectory) {
        $ZenDirectory = Join-Path $BuildDir 'zen/1.23.4b/core'
        if (-not (Test-Path -LiteralPath (Join-Path $ZenDirectory 'zen.exe'))) {
            & (Join-Path $PSScriptRoot 'fetch-zen.ps1') -Version '1.23.4b'
        }
    }
    if (-not $PSBoundParameters.ContainsKey('RootMiB')) { $RootMiB = 8192; $Script:RootSizeMiB = 8192 }
}
    $profileArgs = @(if (-not $DebugBuild) { '--release' })
    $profileDir = if ($DebugBuild) { 'debug' } else { 'release' }

    Write-Host '==> building boot loader (x86_64-unknown-uefi)'
    Invoke-Checked 'loader build' { cargo build -p osyx-uefi-loader --target x86_64-unknown-uefi @profileArgs }
    Write-Host '==> building kernel (x86_64-unknown-none)'
    # OSYX_FRAME_POINTERS=1 keeps the frame-pointer chain the kernel profiler
    # (`prof=<seconds>`, see kernel/src/prof.rs) walks; normal builds omit it.
    $kernelFlags = $env:RUSTFLAGS
    if ($env:OSYX_FRAME_POINTERS -eq '1') { $env:RUSTFLAGS = '-C relocation-model=static -C force-frame-pointers=yes' }
    try {
        Invoke-Checked 'kernel build' { cargo build -p osyx-kernel --target x86_64-unknown-none @profileArgs }
    } finally { $env:RUSTFLAGS = $kernelFlags }

    # User programs use the small code model at low addresses; a separate
    # target dir keeps their flags from invalidating the kernel build cache.
    Write-Host '==> building user programs (x86_64-unknown-none, user code model)'
    $savedFlags = $env:RUSTFLAGS
    # User programs are soft-float: the RustCrypto crates of osyx-web must use
    # their portable code instead of SSE/AVX intrinsics.
    $env:RUSTFLAGS = '-C relocation-model=static -C code-model=small --cfg polyval_force_soft --cfg poly1305_force_soft --cfg aes_force_soft --cfg chacha20_force_soft --cfg curve25519_dalek_backend="serial"'
    try {
        Invoke-Checked 'user build' { cargo build -p osyx-apps -p osyx-desktop -p osyx-nettools -p osyx-win32 -p osyx-web --target x86_64-unknown-none --target-dir target/user @profileArgs }
    } finally { $env:RUSTFLAGS = $savedFlags }
    # Program -> directory on the root file system. The graphical session
    # (PRISM, the desktop shell and its applications) lives in /system/bin.
    $installDirs = [ordered]@{
        init = 'bin'; worker = 'bin'; probe = 'usr/bin'; axis = 'bin'; firstboot = 'bin'; fetch = 'bin'; get = 'bin'; 'osyx-update' = 'bin'; batteryd = 'bin'; i2chidd = 'bin'
        prism = 'system/bin'; desktop = 'system/bin'; terminal = 'system/bin'; files = 'system/bin'; sysinfo = 'system/bin'
        ping = 'bin'; net = 'bin'; netstat = 'bin'; dns = 'bin'; nc = 'bin'; timesync = 'bin'; 'wifi-watch' = 'bin'
        winrun = 'bin'
        taskmgr = 'system/bin'; settings = 'system/bin'; setup = 'system/bin'
        zen = 'system/bin'; open = 'bin'; 'run-app' = 'system/bin'
    }
    $userBins = @($installDirs.Keys)
    # Only these are also boot modules (the fallback root's /bin).
    $moduleBins = @('init', 'worker', 'probe')
    foreach ($bin in $userBins) {
        $path = Join-Path $Root "target\user\x86_64-unknown-none\$profileDir\$bin"
        Invoke-Checked "$bin validation" { cargo run -q -p osyx-elf --example inspect -- --user $path }
    }

    $efi = Join-Path $Root "target\x86_64-unknown-uefi\$profileDir\osyx-uefi-loader.efi"
    $kernel = Join-Path $Root "target\x86_64-unknown-none\$profileDir\osyx-kernel"
    Write-Host '==> validating kernel image'
    Invoke-Checked 'kernel validation' { cargo run -q -p osyx-elf --example inspect -- $kernel }

    New-Item -ItemType Directory -Force (Join-Path $EspDir 'EFI\BOOT'), (Join-Path $EspDir 'EFI\OSYX') | Out-Null
    Copy-Item $efi (Join-Path $EspDir 'EFI\BOOT\BOOTX64.EFI') -Force
    Copy-Item $kernel (Join-Path $EspDir 'EFI\OSYX\KERNEL.ELF') -Force
    # Every file in \EFI\OSYX\BIN becomes a boot module; the kernel installs
    # them as /bin of its fallback root when no root partition is usable.
    $binDir = Join-Path $EspDir 'EFI\OSYX\BIN'
    if (Test-Path $binDir) { Remove-Item $binDir -Recurse -Force }
    $legacyInit = Join-Path $EspDir 'EFI\OSYX\INIT.ELF'
    if (Test-Path $legacyInit) { Remove-Item $legacyInit }
    if (-not $NoInit) {
        New-Item -ItemType Directory -Force $binDir | Out-Null
        foreach ($bin in $moduleBins) {
            Copy-Item (Join-Path $Root "target\user\x86_64-unknown-none\$profileDir\$bin") (Join-Path $binDir $bin) -Force
        }
    }
    $cmdFile = Join-Path $EspDir 'EFI\OSYX\CMDLINE.TXT'
    if ($Cmdline) {
        [IO.File]::WriteAllText($cmdFile, $Cmdline)
    } elseif (Test-Path $cmdFile) {
        Remove-Item $cmdFile
    }
    Write-Host "==> ESP contents in $EspDir"
    Get-ChildItem $EspDir -Recurse -File | ForEach-Object {
        Write-Host ("    {0,-28} {1,10} bytes" -f $_.FullName.Substring($EspDir.Length + 1), $_.Length)
    }
    if ($KeepRoot) {
        Write-Host '==> keeping the root partition of the current disk image'
        Save-RootPartition
    } else {
        # Programs for /bin and /usr/bin of the root (none with -NoInit).
        $stage = Join-Path $BuildDir ('rootfs-programs-' + [Guid]::NewGuid().ToString('N'))
        foreach ($d in 'bin', 'usr\bin', 'system\bin') { New-Item -ItemType Directory -Force (Join-Path $stage $d) | Out-Null }
        # The default desktop wallpaper, converted from PNG to OSXI (cached).
        $wallSrc = Join-Path $Root 'graphics\assets\wallpaper\osyx-default.png'
        $wallOut = Join-Path $BuildDir 'wallpaper-default.osxi'
        if (-not (Test-Path $wallOut) -or (Get-Item $wallSrc).LastWriteTime -gt (Get-Item $wallOut).LastWriteTime) {
            Invoke-Checked 'wallpaper' { python (Join-Path $PSScriptRoot 'png2osxi.py') $wallSrc $wallOut }
        }
        $wallDir = Join-Path $stage 'system\share\wallpapers'
        New-Item -ItemType Directory -Force $wallDir | Out-Null
        Copy-Item $wallOut (Join-Path $wallDir 'default.osxi')
        # Fonts for Windows programs (C:\Windows\Fonts) and the registry's
        # substitutes for the usual Windows font names.
        $fontDir = Join-Path $stage 'Windows\Fonts'
        New-Item -ItemType Directory -Force $fontDir | Out-Null
        Copy-Item (Join-Path $Root 'graphics\assets\fonts\windows\*') $fontDir
        $regDir = Join-Path $stage 'etc\osyx\registry'
        New-Item -ItemType Directory -Force $regDir | Out-Null
        $registryArgs = @(if ($ZenDirectory -and -not $NoInit) { '--zen' })
        Invoke-Checked 'registry seed' { python (Join-Path $PSScriptRoot 'seed-registry.py') (Join-Path $regDir 'machine.reg') @registryArgs }
        # Windows PE32+ test programs (built with clang when available).
        if ($ZenDirectory) {
            $zenSource = (Resolve-Path -LiteralPath $ZenDirectory).Path
            if (-not (Test-Path -LiteralPath (Join-Path $zenSource 'zen.exe'))) { throw 'ZenDirectory has no zen.exe' }
            if ($RootMiB -lt 1024) { throw 'The complete Zen package requires -RootMiB 1024 or larger' }
            $zenStage = Join-Path $stage 'opt/zen'
            New-Item -ItemType Directory -Force $zenStage | Out-Null
            Get-ChildItem -LiteralPath $zenSource -Force | Copy-Item -Destination $zenStage -Recurse
        }
        & (Join-Path $PSScriptRoot 'build-winapps.ps1') | Out-Null
        $winApps = Join-Path $BuildDir 'winapps'
        if (Test-Path (Join-Path $winApps 'textedit.exe')) {
            $appDir = Join-Path $stage 'opt\apps'
            New-Item -ItemType Directory -Force $appDir | Out-Null
            Copy-Item (Join-Path $winApps '*.exe') $appDir
        }
        $testBuild = $Cmdline -match '(^|\s)init.args=tests(,|\s|$)'
        if ($testBuild) { & (Join-Path $PSScriptRoot 'build-wintests.ps1') | Out-Null }
        $winTests = Join-Path $BuildDir 'wintests'
        if ($testBuild -and (Test-Path (Join-Path $winTests 'hello.exe'))) {
            $winDir = Join-Path $stage 'opt\wintests'
            New-Item -ItemType Directory -Force $winDir | Out-Null
            Copy-Item (Join-Path $winTests '*') $winDir -Include *.exe, *.dll
        }
        if (-not $NoInit) {
            foreach ($bin in $userBins) {
                Copy-Item (Join-Path $Root "target\user\x86_64-unknown-none\$profileDir\$bin") (Join-Path $stage "$($installDirs[$bin])\$bin")
            }
        }
        if ($Live) {
            # The installer's payload: the boot files it writes to the new
            # EFI system partition (the kernel is stripped with the tree).
            $payload = Join-Path $stage 'system\share\osyx-setup\esp'
            New-Item -ItemType Directory -Force (Join-Path $payload 'EFI\BOOT'), (Join-Path $payload 'EFI\OSYX') | Out-Null
            Copy-Item (Join-Path $EspDir 'EFI\BOOT\BOOTX64.EFI') (Join-Path $payload 'EFI\BOOT\BOOTX64.EFI')
            Copy-Item (Join-Path $EspDir 'EFI\OSYX\KERNEL.ELF') (Join-Path $payload 'EFI\OSYX\KERNEL.ELF')
            Write-Host '==> packing the compressed live root, the ISO and the USB image (WSL)'
            New-LiveImage $stage
            if ($ReleaseTar) { New-ReleaseTar $stage $ReleaseTar }
        } else {
            Write-Host '==> building ext4 root file system (mke2fs in WSL)'
            New-RootImage $stage
        }
    }
    if (-not $Live) {
        Write-Host '==> assembling GPT disk image'
        New-DiskImage
        if ($OutputImage) {
            Copy-Item -LiteralPath $DiskImage -Destination $OutputImage -Force
        }
    }
} finally {
    Pop-Location
    try {
        if ($stage -and (Test-Path -LiteralPath $stage)) {
            $stagePath = [IO.Path]::GetFullPath($stage)
            $buildPath = [IO.Path]::GetFullPath($BuildDir).TrimEnd('\') + '\'
            if (-not $stagePath.StartsWith($buildPath, [StringComparison]::OrdinalIgnoreCase) -or
                [IO.Path]::GetFileName($stagePath) -notmatch '^rootfs-programs-[a-f0-9]{32}$') {
                throw 'Refusing to remove a staging directory outside this build'
            }
            Remove-Item -LiteralPath $stagePath -Recurse -Force
        }
    } finally { $buildLock.ReleaseMutex(); $buildLock.Dispose() }
}
