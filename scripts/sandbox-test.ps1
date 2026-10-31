# Run the sandbox-specific in-kernel tests from a temporary FAT boot tree.
# This is not the full system test suite and does not exercise Gecko.
param([ValidateRange(10, 300)][int]$TimeoutSec = 60, [switch]$Winrun)
. (Join-Path $PSScriptRoot 'common.ps1')

$baseEsp = Join-Path $BuildDir 'esp/EFI'
if (-not (Test-Path (Join-Path $baseEsp 'BOOT/BOOTX64.EFI'))) {
    throw 'Existing build/esp/EFI/BOOT/BOOTX64.EFI is required'
}
$lock = Enter-BuildLock
$vm = $null
$oldFlags = $env:RUSTFLAGS
Push-Location $Root
try {
    Invoke-Checked 'kernel build' { cargo build -p osyx-kernel --target x86_64-unknown-none --release } | Out-Null
    $env:RUSTFLAGS = '-C relocation-model=static -C code-model=small --cfg polyval_force_soft --cfg poly1305_force_soft --cfg aes_force_soft --cfg chacha20_force_soft --cfg curve25519_dalek_backend="serial"'
    Invoke-Checked 'worker build' { cargo build -p osyx-apps --bin worker --target x86_64-unknown-none --target-dir target/user --release } | Out-Null
    if ($Winrun) {
        Invoke-Checked 'winrun build' { cargo build -p osyx-win32 --target x86_64-unknown-none --target-dir target/user --release } | Out-Null
        $linker = Join-Path (rustc --print sysroot) 'lib/rustlib/x86_64-pc-windows-msvc/bin/rust-lld.exe'
        if (-not (Test-Path $linker)) { throw 'Windows MSVC Rust target with rust-lld is required for -Winrun' }
        Invoke-Checked 'PE fixture build' { rustc compatibility/win32/tests/src/sandbox_smoke.rs --target x86_64-pc-windows-msvc -C panic=abort -C opt-level=2 -C "linker=$linker" -C link-arg=/entry:start -C link-arg=/subsystem:console -C link-arg=/nodefaultlib -o build/sandbox-smoke.exe } | Out-Null
    }
    $env:RUSTFLAGS = $oldFlags

    $name = 'sandbox-test-' + [guid]::NewGuid().ToString('N')
    $stage = Join-Path $BuildDir $name
    New-Item -ItemType Directory -Path $stage | Out-Null
    Copy-Item -LiteralPath $baseEsp -Destination $stage -Recurse
    Copy-Item -LiteralPath 'target/x86_64-unknown-none/release/osyx-kernel' -Destination (Join-Path $stage 'EFI/OSYX/KERNEL.ELF') -Force
    Copy-Item -LiteralPath 'target/user/x86_64-unknown-none/release/worker' -Destination (Join-Path $stage 'EFI/OSYX/BIN/worker') -Force
    $cmdline = 'test.exit boot.fast init.args=tests'
    if ($Winrun) {
        Copy-Item -LiteralPath 'target/user/x86_64-unknown-none/release/winrun' -Destination (Join-Path $stage 'EFI/OSYX/BIN/winrun') -Force
        Copy-Item -LiteralPath 'build/sandbox-smoke.exe' -Destination (Join-Path $stage 'EFI/OSYX/BIN/sandboxpe') -Force
        $cmdline += ' test.sandboxwin'
    }
    Set-Content -LiteralPath (Join-Path $stage 'EFI/OSYX/CMDLINE.TXT') -Value $cmdline -NoNewline
    $log = Join-Path $BuildDir "$name.serial.log"
    $args = Get-QemuArgs -SerialLog $log -Headless -NoDisk -NoNet -NoUsb -Accel tcg
    # QEMU parses a Windows drive-letter colon as a FAT option separator.
    $args += @('-drive', "if=virtio,format=raw,file=fat:rw:build/$name")
    $vm = Start-Qemu $args
    if (-not (Wait-ForLog $log 'self-tests: \d+ passed, \d+ failed' $TimeoutSec $vm)) {
        throw "QEMU did not finish kernel self-tests; log: $log"
    }
    if (-not $vm.HasExited) { $vm.Kill(); $vm.WaitForExit() }
    $output = [IO.File]::ReadAllText($log)
    $tests = @('VFS: restricted opens', 'restricted process: syscall and filesystem inheritance', 'suspended process start and kill')
    if ($Winrun) { $tests += 'Winrun restricted CreateProcess' }
    foreach ($test in $tests) {
        if ($output -notmatch ([regex]::Escape("[test] $test ... ok"))) {
            throw "Sandbox test failed or missing: $test; log: $log"
        }
    }
    Write-Host "Sandbox-specific kernel tests passed; log: $log"
    Write-Host 'Other tests may fail because this boot uses a temporary FAT directory and fallback root.'
} finally {
    if ($vm -and -not $vm.HasExited) { $vm.Kill(); $vm.WaitForExit() }
    $env:RUSTFLAGS = $oldFlags
    Pop-Location
    $lock.ReleaseMutex()
    $lock.Dispose()
}
