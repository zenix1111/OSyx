# Testing

## Commands

```powershell
.\scripts\check-env.ps1             # tool check, no changes to the system
.\scripts\build.ps1 [-Cmdline '…'] [-NoInit] [-KeepRoot] [-DebugBuild] [-Live]
.\scripts\run-qemu.ps1 [-Cmdline '…'] [-Gdb] [-Follow] [-Headless]
.\scripts\test.ps1 [-SkipHost] [-SkipQemu]
.\scripts\i2c-hid-test.ps1          # HID over I2C discovery and refusal under QEMU (docs/i2c-hid.md)
```

QEMU runs `q35`, `qemu64,+nx`, 512 MiB, OVMF from the MSYS2 QEMU package
with fresh firmware variables each boot, the GPT disk `build/osyx.img` as
virtio-blk (`vda`: ESP `vda1` FAT32 64 MiB, root `vda2` ext4 128 MiB), a
virtio-rng device, COM1 to a log file and `isa-debug-exit` at port `0xf4`.
Logs and screenshots go to `build/test/`. `-KeepRoot` reuses the root
partition of the previous disk image (used after the power-cut boot).
`-Live` builds `build/osyx-live.iso` instead of the GPT disk; boot it with
`qemu ... -cdrom build/osyx-live.iso -boot order=d` and look for
`storage: live root unpacked` in the serial log. The image is a plain
optical disc (ISO9660, zeroed system area, no hybrid MBR), so it does not
boot from a USB stick written byte-for-byte. The ESP tree is also visible
as `/EFI/...` in ISO9660, allowing Rufus in ISO mode to extract it to a
FAT-formatted UEFI USB drive.

Host tools: `osyx-fat` `mkfat32`/`fatcheck`, `osyx-part` `mkdisk`, mtools
from MSYS2, and e2fsprogs 1.47 / sgdisk in WSL Ubuntu 24.04 (`mke2fs -d`
for the root image and test fixtures, `e2fsck -fn`, `debugfs`, `dumpe2fs`;
partitions are addressed inside the image file with `?offset=`).

## USB media

`scripts/usb-storage-test.ps1` boots the kernel with a stick on the xHCI
controller (label PENDRIVE, MBR partition, once FAT32 and once exFAT, images
made by `mkfat32`/`mkexfat` and `scripts/mkusbmbr.py`) and the guest program
`init tests media` (`userspace/apps/src/media_checks.rs`): automount at
`/media/PENDRIVE`, read and write, eject refused while a file is open, eject,
unplug and replug through QMP (`device_del`/`device_add`), the data written
before is still there, and the stick pulled out while a file is open (the
kernel must survive and clean up). `scripts/desktop-test.ps1` repeats the
plug, list, Open, Eject and pull-out through the task bar. Host tests:
`osyx-exfat` (formatting, files, directories, renames, no-space, contiguous
files, dirty flag), `osyx-part` (MBR), `osyx-abi` (`media`, `battery`).

## Battery

`osyx-battery` (host tests): the mock machine speaks the EC protocol with
failures and time-outs; hand-assembled AML tables (batteries, adapter,
`_BIX`, EC-backed fields, firmware arithmetic, `Store` into `Index`) run in
the real interpreter. QEMU has no battery: `init.args=battery-demo` publishes
a charging and then a discharging state for the task bar. The EC and the
firmware of a real ThinkPad are not covered.

## Suite (`scripts/test.ps1`)

| Test | Checks |
|---|---|
| host unit tests | `cargo test` for every host crate: abi, bootinfo, gfx, elf, pe, mm, crypto (RFC 8439 / FIPS 180-4 vectors), vfs, tmpfs, part (sgdisk interop), fat (mtools both ways), ext4 (e2fsprogs images, corruption/fuzz, writes checked by e2fsck and debugfs, power cut after every write), os-sys, os-std |
| clippy | `-D warnings` for host crates, loader (UEFI), kernel and user crates |
| QEMU boot + kernel self-tests | boot stages, 25 in-kernel tests (incl. preemption, FPU, PCI, block I/O, tmpfs, symlinks/cwd/permissions, mount/unmount, devfs, FAT32 `/boot`, ext4 `/`, concurrent writers, program loader), exit 33 |
| ring-3 init checks | 69 user checks: OSyx Std, syscalls, processes, threads, sync, TLS, faults, 19 file system and 13 program loader checks |
| ELF loader | `/bin/init` started from the ext4 root, `probe` found in `/usr/bin`; exact argv (incl. empty and non-ASCII strings, a custom `argv[0]`) and envp in the child; inherited and edited environments; auxv (`AT_ENTRY` = `_start`, `AT_PHDR` headers covering the entry, ids, distinct `AT_RANDOM`); absolute and relative paths; 1000 × 100-byte arguments; no `x` bit / directory → `PermissionDenied`, a 0755 script → `InvalidExecutable`, a binary copied to tmpfs runs once made executable; malformed `ExecArgs` → `Fault` / `InvalidArgument`; `execve` keeps pid, cwd and handle 3, swaps program and environment, failed `execve` leaves the caller running, `Busy` with a second thread, a chain of 5 `execve` ends with the last status; 6 old images released without a leak |
| process teardown | every process returns exactly its frames; 0 processes and 2 threads left |
| preemptive scheduling | three never-yielding children all start before the first finishes; 3×300 ms in < 650 ms |
| storage tree | GPT partitions found, ext4 `/` read-write, FAT32 `/boot`, tmpfs `/tmp` `/run`, devfs `/dev`, DRBG seeded; all 7 VFS self-tests ok |
| OSyx Std fs from ring 3 | 19 `fs` checks; a child dropped to uid 1000 passes 12 permission checks; leaked handles closed |
| ESP checked on the host | mtools read the files init wrote to `/boot`; `fatcheck` finds the volume consistent |
| ext4 root checked on the host | `e2fsck -fn` clean after shutdown; `debugfs` reads init's text, a 200 000-byte pattern (SHA-256), a renamed tree, a symlink, a 0640 mode and confirms a removed file is gone |
| power cut | QEMU stopped while a process holds a removed file open: on disk `needs_recovery`, "not clean", an orphan; the next boot replays the journal and frees the orphan; `e2fsck -fn` clean |
| no entropy source | without virtio-rng, `/dev/random` is not created and the self-tests still pass |
| user page fault | process killed with `#PF`, error code 0x4, kernel survives |
| user panic | panic message printed, status 101 |
| user exit code | status 42 propagates |
| boot without programs | no `\EFI\OSYX\BIN` and an empty `/bin`: the kernel says there is no init program and keeps running |
| fallback root | `root=vdz` (no such disk): tmpfs `/`, the boot modules installed as `/bin/*`, `/bin/init` runs from there |
| exception diagnostics | kernel `#PF`, `#GP`, `#UD`, `#DE`: decoded report + panic exit 37 |
| invalid kernel | ELFCLASS32 kernel rejected with on-screen error |
| screenshots | loader error screen and running kernel screen via QMP `screendump` |

## Last recorded result

All 23 tests passed (181 host unit tests, 24 kernel self-tests, 56 user
checks of which 19 are file system checks, host verification of both
partitions, the power-cut scenario) on Windows 11 build 26300 with Rust
1.99.1, QEMU 11.1.2, mtools 4.0.49 and e2fsprogs 1.47.0 (WSL Ubuntu 24.04).
In the ext4 host tests, a 108-write workload was cut after every possible
write; all 108 states recovered consistently (13 also checked with
e2fsck). QEMU TCG is close to deterministic here, so repeated boots do not
stress the scheduler with different interleavings; the host tests of
OSyx Std's `Mutex`, `Condvar` and threads run on real parallel host threads.
## PE32+ parser corpus sweep

`pe-sweep` (release build with `-C overflow-checks=on`) over the read-only
Windows 11 build 26300 directories of the development host. Files are only
read; nothing is copied into the repository.

| Directory | Files | Parsed | Rejected | Panics | Table errors |
|---|---|---|---|---|---|
| `System32` | 4372 | 4333 | 39 PE32 (32-bit) | 0 | 0 |
| `System32\drivers` | 467 | 466 | 1 PE32 | 0 | 4: `.pdata` with begin > end in four VirtualBox drivers (confirmed in the files with an independent script) |
| `SysWOW64` | 2746 | 3 | 2737 PE32, 6 16-bit NE files | 0 | 0 |

In System32 the sweep walked 648 074 imports from 98 040 import
descriptors, 319 142 exports (4 974 forwarders, every name and ordinal
looked up again), 8 942 918 base relocations, 154 TLS callbacks and
5 117 656 runtime functions with their unwind headers.

The first sweep found three parser defects, now fixed and covered by
regression tests: names longer than the original 512-byte limit (C++
decorated exports of up to 699 bytes; limit raised to 4096), zero-length
`RUNTIME_FUNCTION` entries (`symcryptk.dll`), and empty unwind-code arrays
ending exactly at a section's file data (kernel-mode modules).

## Coverage limits

The recorded result above describes that particular run, not every current feature.
Dedicated scripts cover SMP, USB hubs, networking and other paths; see scripts/.
Real-hardware coverage is limited to selected machines and firmware. QEMU results
do not establish compatibility with other hardware or configurations.
