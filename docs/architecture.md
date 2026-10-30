# Architecture

## Components

```
UEFI firmware (OVMF)
  └─ BOOTX64.EFI  ── boot/uefi-loader  (+ boot/gfx, boot/elf, shared/bootinfo)
       │  loads \EFI\OSYX\KERNEL.ELF, \EFI\OSYX\BIN\*, CMDLINE.TXT
       │  builds page tables + BootInfo, ExitBootServices, jumps
       ▼
  kernel (ring 0)  ── kernel (+ kernel/mm, boot/gfx, shared/abi)
       │  GDT/IDT, memory, timer, scheduler, display, self-tests, processes
       │  PCI, virtio-blk/-rng, GPT, VFS: ext4 /, FAT32 /boot, tmpfs, devfs (+ storage/*)
       │  SYSCALL/SYSRET (shared/abi), ELF loader: spawn/execve from /bin, /usr/bin
       ▼
  /bin/init, /bin/worker, /usr/bin/probe (ring 3) ── userspace/apps  (+ runtime/os-std, runtime/os-sys)
```

## Design rules

- **Rust first.** Everything so far is Rust; x86-64 assembly is used only
  where it is the right tool (interrupt stubs, SYSCALL entry, ring
  transitions, fault-tolerant copy routines), via `global_asm!`/`asm!`.
  No C++ yet: no component has needed it (see [cpp-interop.md](cpp-interop.md)).
- **Stable toolchain.** UEFI bindings, ELF parsing,
  allocators, locks and graphics are in-tree. Other components use external crates, including rustls. Builds use stable Rust.
- **Host-testable cores.** Hardware-independent algorithms live in `no_std`
  crates with host unit tests (`boot/elf`, `boot/gfx`, `kernel/mm`,
  `storage/*`, `shared/*`, `runtime/os-std` host back end). Hardware paths are tested by
  in-kernel self-tests and QEMU boots.
- **Untrusted input is validated.** Kernel and user ELF images (programs
  read from disk included), BootInfo, and every user pointer passed to a
  system call.
- **W^X everywhere.** Kernel and user segments, anonymous mappings.

## Status

| Area | Status | Tested |
|---|---|---|
| Graphical UEFI boot manager | Implemented | QEMU boot + error screen screenshots |
| BootInfo protocol v3 (boot modules) | Implemented | host layout tests, QEMU |
| Kernel early init (GDT/TSS/IDT, serial, panic) | Implemented | QEMU |
| Exception diagnostics (#PF/#GP/#UD/#DE) | Implemented | QEMU fault tests |
| Resumable user faults and Win64 vectored exception callbacks | Implemented subset; [protocol and limits](user-exceptions.md) | Native CPU/SSE/security checks and same PE fixture on Windows/QEMU |
| Frame allocator, paging, kernel heap | Implemented | host + in-kernel tests |
| Timer interrupts (PIC/PIT) | Implemented | in-kernel test |
| Framebuffer status screen | Implemented | QEMU screenshot |
| User processes, ring 3, SYSCALL ABI v6 | Implemented | QEMU user tests |
| ELF64 program loader: VFS lookup (`/bin`, `/usr/bin`), `spawn`, `execve`, argv/envp/auxv | Implemented (static `ET_EXEC`) | host tests of the start-up stack layout; in-kernel test; QEMU user tests |
| Threads per process, futexes, FS-base TLS | Implemented (SMP) | in-kernel + QEMU user tests |
| Kernel threads, preemptive scheduler, FPU state | Implemented (SMP) | in-kernel + QEMU user tests |
| spawn / wait / zombies / orphans | Implemented | QEMU user tests |
| OSyx Std (convenience std) | Partially implemented | host tests + running on OSyx |
| Genuine Rust `std` port | Planned | Not tested |
| SMP | Implemented: MADT, INIT/SIPI, per-CPU state, parallel user threads, affinity, NMI TLB invalidation; coarse kernel entry lock | QEMU 2/4 CPUs; native SMP checks and Win32 regressions |
| PCI enumeration (port I/O config space) | Implemented | in-kernel test, QEMU |
| virtio-blk (modern virtio-pci, polled) + block layer | Implemented | in-kernel tests, QEMU |
| GPT partitions (`storage/part`), GPT boot disk with ESP + root | Implemented | host tests incl. sgdisk; QEMU boot |
| FAT32 driver (`storage/fat`), ESP at `/boot` | Implemented (no timestamps) | host tests incl. mtools both ways; QEMU, mtools check of the ESP |
| ext4 driver (`storage/ext4`): read, journalled write, recovery | Implemented (see storage.md for refused features) | host tests on e2fsprogs images, e2fsck after writes and power cuts; QEMU root, e2fsck/debugfs of the root |
| tmpfs (`/tmp`, `/run`), devfs (`/dev`), device manager | Implemented | host + in-kernel + QEMU user tests |
| VFS: driver interface, mounts, symlinks, cwd, permissions, uid/gid | Implemented | in-kernel + QEMU user tests |
| `/dev/random` (ChaCha20 DRBG, virtio-rng / RDRAND seeded) | Implemented | test vectors; QEMU with and without an entropy source |
| Early boot screen, x2APIC, calibrated LAPIC timer, ACPI PM/HPET references, xHCI firmware handoff | Implemented | QEMU; physical machines still require testing |
| AHCI and NVMe storage drivers | Implemented; hardware support varies | Default QEMU suite uses virtio-blk; broader controller coverage is needed |
| Physical NIC drivers | Implemented; hardware support varies | RTL8139 via `scripts/net-test.ps1 -Nic rtl8139`; selected hardware listed in README |
| C++23 components | Planned (no current need) | Not tested |
| PE32+ parser | Implemented (headers, sections, imports, exports, relocations, TLS, exception data) | host: fixtures, malformed, fuzz-style robustness; System32 sweep |
| PE32+ loader | Implemented initial subset | host linker/image tests and QEMU execution |
| NT / Win32 compatibility | Implemented initial subset | PE console/files/threads/TLS/DLL/GUI/Winsock/inventory tests in QEMU |
| Native TCP/IP and VirtIO-Net | Implemented (IPv4) | host stack tests and QEMU/host communication |
| VirtIO-GPU and PRISM display backend | Implemented (software composition) | QEMU desktop and damage-flush measurements |
| Task Manager, Settings and four Windows GUI utilities | Implemented initial versions | USB-driven QEMU desktop tests |
| Windows 11 reverse-engineering research | Started (API sets, forwarding) | research/ notes |
