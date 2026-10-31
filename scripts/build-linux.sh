#!/bin/bash
# Builds the release artifacts on a Linux host (the release workflow uses
# this): the live ISO, the live USB image and the system tree a live build
# installs, the input of the signed system update. It is the counterpart of
# scripts/build.ps1 -Live -ReleaseTar, which stays the Windows build.
#
#   scripts/build-linux.sh [output dir]      (default: build/release)
#
# Output: <out>/osyx-live.iso, <out>/osyx-live-usb.img, <out>/rootfs.tar.
# Needs: the Rust targets from rust-toolchain.toml, clang (BSD drivers and
# the Windows applications; mingw-w64 import libraries for the latter),
# e2fsprogs, cpio, zstd, binutils and python3. mkrootfs.sh chowns the tree
# to uid 0, so it runs through sudo unless the script already runs as root.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="$ROOT/build"
OUT="${1:-$BUILD/release}"
CARGO="${CARGO:-cargo}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
TARGET="$CARGO_TARGET_DIR"

mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
cd "$ROOT"

stage=""
trap 'if [ -n "$stage" ]; then rm -rf "$stage"; fi' EXIT

run() { echo "==> $*"; "$@"; }
as_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi }

echo '==> building boot loader (x86_64-unknown-uefi)'
$CARGO build --locked --release -p osyx-uefi-loader --target x86_64-unknown-uefi
echo '==> building kernel (x86_64-unknown-none)'
$CARGO build --locked --release -p osyx-kernel --target x86_64-unknown-none
echo '==> building user programs (x86_64-unknown-none, user code model)'
RUSTFLAGS='-C relocation-model=static -C code-model=small --cfg polyval_force_soft --cfg poly1305_force_soft --cfg aes_force_soft --cfg chacha20_force_soft --cfg curve25519_dalek_backend="serial"' \
    $CARGO build --locked --release --target x86_64-unknown-none --target-dir "$TARGET/user" \
    -p osyx-apps -p osyx-desktop -p osyx-nettools -p osyx-win32 -p osyx-web

install_dirs="init:bin worker:bin probe:usr/bin axis:bin firstboot:bin fetch:bin get:bin osyx-update:bin batteryd:bin i2chidd:bin
prism:system/bin desktop:system/bin terminal:system/bin files:system/bin sysinfo:system/bin
ping:bin net:bin netstat:bin dns:bin nc:bin timesync:bin wifi-watch:bin winrun:bin
taskmgr:system/bin settings:system/bin setup:system/bin zen:system/bin open:bin run-app:system/bin"

echo '==> validating user programs'
for entry in $install_dirs; do
    bin="${entry%%:*}"
    $CARGO run -q --locked -p osyx-elf --example inspect -- --user "$TARGET/user/x86_64-unknown-none/release/$bin"
done
kernel="$TARGET/x86_64-unknown-none/release/osyx-kernel"
echo '==> validating kernel image'
$CARGO run -q --locked -p osyx-elf --example inspect -- "$kernel"

esp="$BUILD/esp"
rm -rf "$esp"
mkdir -p "$esp/EFI/BOOT" "$esp/EFI/OSYX" "$esp/EFI/OSYX/BIN"
cp "$TARGET/x86_64-unknown-uefi/release/osyx-uefi-loader.efi" "$esp/EFI/BOOT/BOOTX64.EFI"
cp "$kernel" "$esp/EFI/OSYX/KERNEL.ELF"
cp "$TARGET/user/x86_64-unknown-none/release/init" "$esp/EFI/OSYX/BIN/init"
cp "$TARGET/user/x86_64-unknown-none/release/worker" "$esp/EFI/OSYX/BIN/worker"
cp "$TARGET/user/x86_64-unknown-none/release/probe" "$esp/EFI/OSYX/BIN/probe"
printf 'init.args=desktop live' > "$esp/EFI/OSYX/CMDLINE.TXT"

echo '==> staging the installed system tree'
stage="$(mktemp -d "$BUILD/rootfs-programs.XXXXXX")"
mkdir -p "$stage/bin" "$stage/usr/bin" "$stage/system/bin"
python3 scripts/png2osxi.py graphics/assets/wallpaper/osyx-default.png "$BUILD/wallpaper-default.osxi"
mkdir -p "$stage/system/share/wallpapers"
cp "$BUILD/wallpaper-default.osxi" "$stage/system/share/wallpapers/default.osxi"
mkdir -p "$stage/Windows/Fonts" "$stage/etc/osyx/registry"
cp graphics/assets/fonts/windows/* "$stage/Windows/Fonts/"
python3 scripts/seed-registry.py "$stage/etc/osyx/registry/machine.reg"

# Windows applications (PE32+) for /bin/winrun, built with clang + lld and
# the mingw-w64 import libraries; skipped when the toolchain is incomplete.
winapps_libdir=/usr/x86_64-w64-mingw32/lib
if command -v clang >/dev/null && [ -d "$winapps_libdir" ]; then
    echo '==> building Windows applications'
    winapps="$BUILD/winapps"
    mkdir -p "$winapps"
    win_cflags=(--target=x86_64-w64-windows-gnu -fuse-ld=lld -nostdlib -ffreestanding -O2 -Wall -Werror
        -Wl,--dynamicbase -Wl,--high-entropy-va -Wl,--nxcompat -Wl,--no-insert-timestamp -Wl,--build-id=none
        -Wl,--subsystem,windows -Wl,-e,start)
    for spec in textedit:comdlg32,user32,gdi32,kernel32 diskutil:user32,gdi32,kernel32 \
                devmgr:setupapi,user32,gdi32,kernel32 netcenter:iphlpapi,ws2_32,user32,gdi32,kernel32; do
        name="${spec%%:*}"
        source="compatibility/win32/apps/src/$name.c"
        [ -f "$source" ] || continue
        libs=()
        IFS=',' read -r -a lib_names <<< "${spec#*:}"
        for lib in "${lib_names[@]}"; do libs+=("-l$lib"); done
        run clang "${win_cflags[@]}" "$source" "${libs[@]}" -o "$winapps/$name.exe"
    done
    mkdir -p "$stage/opt/apps"
    cp "$winapps"/*.exe "$stage/opt/apps/"
else
    echo '==> clang with mingw-w64 not found: Windows applications not built'
fi

for entry in $install_dirs; do
    bin="${entry%%:*}"
    dir="${entry#*:}"
    cp "$TARGET/user/x86_64-unknown-none/release/$bin" "$stage/$dir/$bin"
done

# The installer's payload: the boot files it writes to the new EFI system
# partition (the kernel is stripped with the tree below).
payload="$stage/system/share/osyx-setup/esp"
mkdir -p "$payload/EFI/BOOT" "$payload/EFI/OSYX"
cp "$esp/EFI/BOOT/BOOTX64.EFI" "$payload/EFI/BOOT/BOOTX64.EFI"
cp "$esp/EFI/OSYX/KERNEL.ELF" "$payload/EFI/OSYX/KERNEL.ELF"

echo '==> packing the compressed live root, the ISO and the USB image'
live="$BUILD/live"
rm -rf "$live"
mkdir -p "$live/esp/EFI/BOOT" "$live/esp/EFI/OSYX/BIN"
cp "$esp/EFI/BOOT/BOOTX64.EFI" "$live/esp/EFI/BOOT/BOOTX64.EFI"
cp "$esp/EFI/OSYX/CMDLINE.TXT" "$live/esp/EFI/OSYX/CMDLINE.TXT"
cp "$esp/EFI/OSYX/KERNEL.ELF" "$live/esp/EFI/OSYX/KERNEL.ELF"
strip --strip-all "$live/esp/EFI/OSYX/KERNEL.ELF"
as_root bash scripts/mkrootfs.sh "$stage" "$live/esp/EFI/OSYX/BIN/rootfs.z" 0 live
run python3 scripts/mkfat16.py "$live/esp.img" "$live/esp"
run python3 scripts/mkiso.py "$BUILD/osyx-live.iso" "$live/esp.img" "$live/esp"
esp_mib=$(find "$live/esp" -type f -printf '%s\n' |
    python3 -c 'import math, sys; print(max(64, math.ceil(sum(map(int, sys.stdin)) / 1048576 * 1.3) + 16))')
run $CARGO run -q --locked -p osyx-fat --example mkfat32 -- "$live/usb-esp.img" "$esp_mib" OSYX-LIVE "$live/esp"
run $CARGO run -q --locked -p osyx-part --example mkdisk -- "$BUILD/osyx-live-usb.img" "$((esp_mib + 2))" "esp:$live/usb-esp.img"

echo '==> packing the update tar'
as_root bash scripts/mkrootfs.sh "$stage" "$OUT/rootfs.tar" 0 tar

cp "$BUILD/osyx-live.iso" "$OUT/osyx-live.iso"
cp "$BUILD/osyx-live-usb.img" "$OUT/osyx-live-usb.img"
ls -l "$OUT"
