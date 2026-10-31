# Roadmap

Status of the milestones from the project brief. Audited against the code
on 2026-10-30.

| # | Milestone | Status |
|---|---|---|
| 1 | Repository, toolchain, scripts, docs | Done |
| 2 | Graphical UEFI boot loader | Done |
| 3 | Kernel boot (serial, panic, CPU init, exceptions) | Done |
| 4 | Memory subsystem (frames, paging, heap) | Done |
| 5 | Initial OSyx Std | Done (convenience std; real `std` port planned) |
| 6 | PE32+ parser | Done (host tested) |
| 7 | User-space foundations (ring 3, syscalls, exit, console) | Done |
| 7b | Scheduler, kernel threads, preemption, FPU state, spawn/wait | Done (SMP) |
| 7c | Threads per process, futexes, FS-base TLS, OSyx Std `thread`/`Mutex`/`Condvar` | Done (SMP) |
| 7d | Storage: PCI, virtio-blk, block layer, FAT32, VFS, file handles, OSyx Std `fs` | Done (polled I/O; SMP) |
| 7e | File system architecture: ext4 root (journalled), FAT32 `/boot`, tmpfs, devfs, GPT, permissions, cwd, symlinks, mount/umount | Done (see storage.md for limits) |
| 7f | Native executable loader: ELF64 from the VFS (`/bin`, `/usr/bin`), `execve`, argv/envp/auxv, OSyx Std environment | Done (static `ET_EXEC` only; see kernel.md) |
| 7g | Kernel objects and IPC: pipes, channels, shared memory, wait_handles (ABI v7) | Done |
| 7h | Native xHCI driver, USB enumeration, HID keyboard/mouse, input core | Done (root ports, boot keyboards; see graphics.md) |
| 7i | PRISM compositor, protocol v1, UI toolkit, desktop shell, AXIS Terminal, Files, System Information | Done (software composition; see graphics.md) |
| 8 | Native Windows PE execution | Initial subset implemented (console, files, threads, DLLs, GUI, Winsock; see windows-compatibility.md) |
| 9 | Native networking | Implemented (VirtIO-Net and IPv4 stack; see network/net) |
| 10 | VirtIO-GPU display backend | Implemented (2D scanout/damage/cursor; software composition) |
| 11 | Task Manager, Settings and four PE32+ desktop utilities | Implemented initial versions |
| 12 | Unmodified Windows browser (Zen) on OSyx | Runs and plays YouTube in QEMU; software rendering, Gecko sandbox off (see research/zen-bringup.md, research/performance-profile.md) |
| 13 | Signed system updates and live image | Done (`/bin/osyx-update`, GitHub releases, `scripts/release.ps1`) |
| 14 | Battery indicator (ACPI/EC) | Done in code (multi-battery, hotplug, EC tolerance, AML tests); unverified on most hardware |
| 15 | Kernel profiler and flame graphs | Done (`prof=N`, `scripts/flamegraph.py`) |

## Next steps (in order)

Planned work, roughly by priority. Items marked (in progress) have a branch.

### Near term

1. **USB storage for users**: done. Removable disks are mounted under
   `/media/<label>` on hot-plug (`kernel/src/media.rs`), eject flushes and
   unmounts and refuses when busy, surprise removal keeps the kernel alive,
   and the desktop panel lists disks with size, file system, usage and an
   Eject button (`userspace/desktop/src/drives.rs`).
2. **Settings that work**: done. Accent, wallpaper, keyboard layout, time
   zone, host name and IPv4 configuration are written and read back by the
   applications; About has Check for updates and Install update on top of
   `/bin/osyx-update` (`userspace/desktop/src/bin/settings.rs`).
3. **Battery detection**: done in code. Multiple batteries are aggregated,
   ACPI hotplug is followed, unknown or implausible EC values are filtered,
   and the AML tests cover two batteries, a missing battery and wild values
   (`userspace/battery/`, `tests/acpi.rs`). Still open: verification on real
   ThinkPads.
4. **File formats and multiple files in Files**: partly done. Multi-selection
   (copy, move, delete, pack into tar), Extract here for tar/tar.gz/zip/7z/gz,
   a viewer and hex viewer, and "Open with" with per-extension choices are
   implemented (`userspace/desktop/src/bin/files.rs`,
   `userspace/filekit/src/openwith.rs`). Still open: built-in audio, video
   and PDF viewers (today those kinds need a registered application).
5. **Release hygiene**: partly done. CodSpeed benchmarks run on every pull
   request. Still open: the release workflow builds and signs only; it runs
   neither the host tests nor the Win32, SMP, desktop and Zen QEMU suites.

### Performance (see research/performance-profile.md)

6. Split the global process table lock (handle tables, mappings, page
   faults) and the kernel entry lock. Done: handle tables have their own
   lock (`HANDLES`), so channel, wait and futex lookups no longer queue
   behind mappings and page faults. Still open: mappings and page faults
   share `TABLE`, and `smp::enter_kernel` serialises all system calls.
7. Demand-paged file views, virtio-blk with several requests in flight,
   async readahead. Done: a read-only section loads 256 KiB runs on the
   first touch instead of reading the whole 177 MiB archive at map time;
   writable sections stay eagerly loaded for coherent write-back; virtio-blk
   keeps up to four chains in flight; read-ahead windows run on a background
   kernel thread while the reader gets the first pages immediately.
8. Software WebRender: fewer full-frame copies, damage-based presents in
   PRISM. Done: PRISM renders and presents only damaged rectangles; Gecko
   already runs it with software WebRender. Still open: the Win32
   compatibility path (`winrun`, `vcruntime140`) still copies whole frames.
9. **GPU acceleration**: 2D scan-out (VirtIO-GPU) only. Done: full
   XSAVE/AVX state (XCR0, per-thread AVX state, TCG boot path). Still open:
   a 3D path (VirtIO-GPU virgl or a native driver) behind a
   Direct3D/OpenGL layer for the Windows compatibility code.

### Security

10. Enable a sandbox for browser content processes: Gecko's own sandbox
    needs restricted tokens, job objects and a broker; an OSyx-native
    alternative is per-process file system views and syscall filters.

### Longer term

11. **Real-hardware coverage**: NVMe, AHCI, wired NICs (`e1000`, `rtl8168`)
    and Intel Wi-Fi (`iwm` through the BSD layer) drivers exist; the open
    work is verification and fixes on more machines and firmware. I2C-HID
    touchpads and keyboards have a polled driver (DesignWare controllers,
    `kernel/src/drivers/i2c.rs`) that is untested on real hardware; interrupts
    need an I/O APIC driver and GPIO controller drivers.
12. **Windows compatibility expansion**: cross-process sharing and object
    names, child controls, SEH, delay imports, process creation and the
    runtime dependencies of larger applications; Windows 11 API-set research
    with REA (`research/windows11-apiset-and-forwarding.md`).
13. **Storage**: ext4 htree insertion and deeper extent trees, page cache with
    delayed writes, interrupt-driven virtio (queues are polled). Done: FAT
    entries are stamped with the wall clock on create and write, and `stat`
    reports the stored time (2-second DOS resolution); the write-back thread
    flushes ext4 after 5 s and exFAT after 2 s of quiet. Still open: FAT
    writes its metadata through on every change, and ext4 has no htree
    insertion yet.
14. **SMP**: finer-grained kernel locking (still one kernel entry lock and
    `TABLE` for mappings and page faults) and load balancing policies.
15. **OSyx Std**: `thread`, futex-based `Mutex`, `Condvar`, `RwLock`,
    `Once`/`OnceLock` and `mpsc` are implemented; next is the genuine `std`
    port ([rust-std.md](rust-std.md)).
16. **Desktop**: per-pixel alpha (ARGB8888 windows), raw-report keyboards,
    AXIS redirection (`<`, `>`, `>>`, built-ins included), pipelines with at
    most one built-in stage and `if`/`for` blocks are implemented; still
    open: job control (see [graphics.md](graphics.md)).

## Real hardware: current scope and limits

NVMe, AHCI, physical Ethernet and Intel Wi-Fi drivers are present. The README lists the ThinkPad T495 as tested hardware; support on other machines and firmware varies. NVMe and AHCI use polled I/O.

- **Display**: GOP on physical hardware; VirtIO-GPU under QEMU with EDID
  preferred-mode selection. AMD display functions and their VBIOS are
  identified at boot, but native GPU modesetting is not implemented.
- **SMP**: user threads run in parallel; kernel entry uses a common lock.
- **USB**: xHCI supports hubs; device and topology coverage remains limited.
- **Laptop input**: PS/2 input is supported. HID over I2C (keyboards, mice, precision touchpads behind a DesignWare I2C controller, found through ACPI by `i2chidd`) is implemented but polled and not yet verified on real hardware; touchscreens, gestures (tap, scroll) and interrupt-driven input are not supported.
- **Power**: shutdown requests ACPI S5 using FADT and the static DSDT _S5 package where available. Firmware behavior varies.
