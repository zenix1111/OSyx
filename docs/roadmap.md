# Roadmap

Status of the milestones from the project brief.

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
| 14 | Battery indicator (ACPI/EC) | Initial version; unverified on most hardware |
| 15 | Kernel profiler and flame graphs | Done (`prof=N`, `scripts/flamegraph.py`) |

## Next steps (in order)

Planned work, roughly by priority. Items marked (in progress) have a branch.

### Near term

1. **USB storage for users** (in progress): automatic mount of USB mass
   storage under `/media/<label>`, safe eject (flush, unmount, refuse when
   busy), surprise removal without kernel panics, and a desktop panel that
   lists USB disks (label, size, file system, usage) with an Eject button.
2. **Settings that work** (in progress): every control in the Settings app
   must change and persist its value; add a system update button (current
   version, check for updates, progress and errors) on top of
   `/bin/osyx-update`.
3. **Battery detection** (in progress): reliable charge, charging state, time
   estimate, no-battery and multiple-battery cases, tolerance of EC errors;
   verify on real ThinkPads.
4. **File formats and multiple files in Files**: open more kinds of files
   (images, text and source, archives such as 7z/zip/tar, audio, video, PDF)
   with a built-in viewer or a registered application per type, an "Open
   with" choice, and multi-selection (copy, move, delete, compress several
   files at once). Today Files opens text, HTML and common image types
   through `/bin/open` and the browser.
5. **Release hygiene**: run the Win32, SMP, desktop and Zen suites for every
   release; CodSpeed benchmarks for the host-testable crates on every PR.

### Performance (see research/performance-profile.md)

6. Split the global process table lock (handle tables, mappings, page
   faults) and the kernel entry lock. Done: handle tables have their own
   lock (`HANDLES`), so channel, wait and futex lookups no longer queue
   behind mappings and page faults. Still open: mappings and page faults
   share `TABLE`, and `smp::enter_kernel` serialises all system calls.
7. Demand-paged file views, virtio-blk with several requests in flight,
   async readahead. Done: a read-only section loads 256 KiB runs on the
   first touch instead of reading the whole 177 MiB archive at map time;
   writable sections stay eagerly loaded for coherent write-back. Still
   open: virtio-blk has one request in flight and readahead is synchronous.
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

11. **Real-hardware coverage**: NVMe, AHCI, physical NICs and Wi-Fi on more
    machines; I2C-HID touchpads.
12. **Windows compatibility expansion**: cross-process sharing and object
    names, child controls, SEH, delay imports, process creation and the
    runtime dependencies of larger applications; Windows 11 API-set research
    with REA (`research/windows11-apiset-and-forwarding.md`).
13. **Storage**: ext4 htree insertion and deeper extent trees, page cache with
    delayed writes, FAT timestamps, interrupt-driven virtio.
14. **SMP**: finer-grained kernel locking, load balancing policies.
15. **OSyx Std**: `RwLock`, `Once`/`OnceLock`, `mpsc`; then the genuine `std`
    port ([rust-std.md](rust-std.md)).
16. **Desktop**: per-pixel alpha in the toolkit, report-protocol keyboards,
    AXIS pipelines and blocks (see [graphics.md](graphics.md)).

## Real hardware: current scope and limits

NVMe, AHCI, physical Ethernet and Intel Wi-Fi drivers are present. The README lists the ThinkPad T495 as tested hardware; support on other machines and firmware varies. NVMe and AHCI use polled I/O.

- **Display**: GOP on physical hardware; VirtIO-GPU under QEMU. Native GPU modesetting is not implemented.
- **SMP**: user threads run in parallel; kernel entry uses a common lock.
- **USB**: xHCI supports hubs; device and topology coverage remains limited.
- **Laptop input**: PS/2 input is supported; I2C-HID touchpads and native gesture protocols are not supported.
- **Power**: shutdown requests ACPI S5 using FADT and the static DSDT _S5 package where available. Firmware behavior varies.
