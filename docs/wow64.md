# 32-bit (PE32) Windows programs: plan and status

OSyx runs 64-bit PE32+ programs through `winrun`. Many installers and older
applications (SteamSetup.exe, NSIS installers) are 32-bit PE32 and are refused:
`optional header magic 0x10b is not PE32+`. This document is the plan for
running them, and the record of what exists.

## Inventory: SteamSetup.exe

Checked with `cargo run -p osyx-pe --example pe32-imports -- SteamSetup.exe`:
PE32, machine 0x14c, GUI subsystem, 166 imports in 8 DLLs: KERNEL32 66,
USER32 65, GDI32 8, ADVAPI32 13, SHELL32 6, COMCTL32 4, ole32 4. That is an
NSIS installer: a bounded, ordinary API surface, and most of those functions
already exist in the 64-bit `winrun`. The installer then downloads the
32-bit Steam client, which needs far more (a browser engine, DirectX); that is
a later milestone and not covered here.

## Design

1. **Compatibility mode.** 32-bit code runs in the same process in x86-64
   compatibility mode, with a 32-bit ring 3 code segment in the GDT
   (D=1, L=0) beside the 64-bit one. All 32-bit images, heap and stacks are
   placed below 4 GiB.
2. **Entering and leaving 32-bit code.** `winrun` far-returns into the
   32-bit segment; a 32-bit API stub far-jumps back to the 64-bit segment
   ("heaven's gate", as Windows' WoW64 does).
3. **FS segment.** 32-bit code finds its TEB at `fs:[0x18]`. Compatibility
   mode takes the FS base from a descriptor, not from the FS base MSR, so the
   kernel needs a per-thread data descriptor whose base is switched with the
   thread.
4. **Loader.** PE32 headers, `IMAGE_REL_BASED_HIGHLOW` relocations, 4-byte
   import thunks, `IMAGE_TLS_DIRECTORY32`, 32-bit export tables.
5. **API bridge.** Every 32-bit import resolves to a small stub that
   switches to 64-bit mode and calls the existing 64-bit implementation
   with the stdcall arguments widened (pointers zero-extended, signed values
   sign-extended per parameter). Functions that take or return structures
   with pointer-sized fields (`WNDCLASSW`, `MSG`, `PAINTSTRUCT`,
   `WIN32_FIND_DATAW`, `STARTUPINFOW`, `LOGFONT`...) need explicit
   conversion. Window procedures and callbacks need the reverse stub (64-bit
   to 32-bit).
6. **Exceptions and SEH.** 32-bit frame-based SEH (`fs:[0]` chain), not the
   table-based x64 scheme.

### winrun at 0x4000_0000 instead of a second `winrun32`

32-bit code can address only the low 4 GiB, so every address a PE32 image
imports must be below that. The built-in DLLs are not separate images: their
exports are `winrun`'s own code. A bridge stub for each one therefore lives
in `winrun`, and 32-bit code reaches it only if `winrun` is linked low.

`winrun` is linked at 0x4000_0000 by `userspace/winrun.ld` (a copy of
`userspace/user.ld` with the base changed); PE32 images keep their usual
linked base of 0x400000, so no image relocations are needed for the common
case. The alternative, a separate `winrun32` binary with a 32-bit copy of
the whole module graph and API tables, would duplicate every built-in and
the loader state with it. One binary keeps one implementation.

Trade-off: the host's own code and data are addressable by the 32-bit
program, so a wild write can corrupt the runtime as it could on 32-bit
Windows in a shared address space. Accepted: the bridge already trusts the
program with the process, and OSyx has no 32-bit kernel split either.

The loader hook is `Host::import_thunk` (defaulted, forwards `address`):
`osyx-pe-loader` calls it for each import of a PE32 image before writing
the 4-byte IAT slot, and `winrun`'s host asks the bridge for a stub. A host
that returns 0 fails the load, so an unbridged import is an error that names
the symbol, never a null thunk. PE32+ images never call the hook.

## Milestones

| # | Milestone | Status |
|---|---|---|
| 1 | `osyx-pe` parses PE32 (`PeFile::parse_any`, `is_pe32`): headers, 4-byte import thunks, TLS directory and callbacks; `pe32-imports` example | Done (host tested on a real installer) |
| 2 | Loader support in `osyx-pe-loader`: HIGHLOW relocations, 32-bit image layout below 4 GiB, imports written as 32-bit stubs | Done in the crate: `relocate` applies HIGHLOW under the 4 GiB limit, `reserve_below` places images, `write_thunk` writes 4-byte slots, `import_thunk` maps built-ins to bridge stubs; `compatibility/pe-loader/tests/pe32.rs` passes, and `winrun`'s `WinHost` implements the hook (`reserve_below` not yet exercised on OSyx) |
| 3 | Kernel: 32-bit user code segment and per-thread FS descriptor, switched on context switch | Done: GDT entries 7/8 built by `osyx_abi::wow64` and installed per CPU, `Thread::fs32_base` restored on every switch, syscall 96 sets the calling thread's base; the four `shared/abi/src/wow64.rs` host tests pass and the milestone 4 bridge enters ring 3 with CS32 on QEMU |
| 4 | Bridge for a console program (`GetStdHandle`, `WriteFile`, `ExitProcess`...) and a 32-bit test program in `compatibility/win32/tests` | Done: `winrun` reserves the arena at `0x2000_0000`, binds the three imports to 12-byte stubs, enters `hello32.exe` through a five-slot `iretq` into CS32, the guest prints `hello32: 32-bit code ran` through `WriteFile` and `ExitProcess(7)` reaches `init`; `win-test.ps1` passes with it (2200 passed, 0 failed) |
| 5 | The 166 imports of SteamSetup.exe: kernel32, advapi32, then user32/gdi32/comctl32 with callbacks | Not started |
| 6 | 32-bit SEH, WOW64-style file system and registry views | Not started |

`winrun` sees a PE32 main image, loads it through the same linker and enters
its entry point through the bridge; the QEMU run in milestone 4 exercises
that path.

## Bridge (milestone 4)

The arena at `0x2000_0000` holds the import stubs (page 0), the TEB32 that
compatibility-mode FS points at, PEB32, a read-only guard page and the
1 MiB main stack. A 32-bit stack slot is 4 bytes, so the far jump from a stub
pushes an 8-byte-aligned 64-bit CS:EIP pair; the gate records the 32-bit RSP
and switches to its own 64 KiB stack before calling `bridge_dispatch`.

Returning works in both directions with the same rule: an `iretq` from
64-bit mode into a compatibility segment reloads SS:RSP from the frame even
at the same privilege. The gate and `osyx_wow64_enter32` therefore push a
five-slot frame (SS, RSP, RFLAGS, CS, RIP) whose RSP is the value the 32-bit
caller resumes with — the gate places it past the return address and the
stdcall arguments, `enter32` places it at the initial stack top.

A fault taken in compatibility mode is delivered through the normal 64-bit
handler: the kernel masks the frame's RSP to 32 bits, remembers the thread's
FS32 base, enters the handler with CS64 and the 64-bit FS, and restores the
TEB base in FS before the continuation `iretq` returns to CS32.

Two defects surfaced only inside `win-test.ps1` (hardware virtualization,
`-Accel auto`), both fixed on this branch:

* **Null DS after `sysret`.** A 64-bit return to user mode leaves DS/ES null.
  QEMU TCG tolerates the null selector, WHPX does not, and the first
  compatibility-mode data access (`GetStdHandle` through the IAT) faulted with
  `#GP(0)` at `0x401005`. The gate, `osyx_wow64_enter32` and the kernel's
  `osyx_fault_resume` now load DS/ES with the flat ring-3 data selector before
  every `iretq` into CS32.
* **Oversized `RaiseException` frame.** The raise entry built its captured
  `NativeContext` in a 720-byte frame while the bridge copies the full
  1024-byte context; called from a shallow stack, that copy ran off the top of
  the stack (`exceptions.exe`, `seh.exe`). The thunk reserves 1088 bytes and
  overlays FXSAVE at the `fx` offset of the context.

`hello32.exe` prints its marker and exits 7 in the suite, and
The test run reported `windows test: 2200 passed, 0 failed`. Its serial log
also reports one separate kernel self-test failure, `FAT32 /boot through the
VFS: contextual Unicode miss invalidated on create`; whether it also occurs on
`main` has not yet been verified.

## Kernel support (milestone 3)

Each CPU has its own GDT (`kernel/src/arch/gdt.rs`, `TABLES`). Entries 0-6
keep their numbers, so STAR/SYSRET and the TSS are unchanged; two entries
after the TSS serve 32-bit code:

| Index | Selector | Descriptor | Use |
|---|---|---|---|
| 0 | 0x00 | 0 | null |
| 1 | 0x08 | `0x00AF_9A00_0000_FFFF` | kernel code |
| 2 | 0x10 | `0x00CF_9200_0000_FFFF` | kernel data |
| 3 | 0x1B | `0x00CF_F200_0000_FFFF` | user data (SS) |
| 4 | 0x23 | `0x00AF_FA00_0000_FFFF` | user code, L=1 |
| 5-6 | 0x28 | TSS low/high | task state segment |
| 7 | 0x3B | `0x00CF_FA00_0000_FFFF` | user code, D=1 L=0 (compatibility mode) |
| 8 | 0x43 | `0x00CF_F200_0000_FFFF` + base | user data for FS, base per thread |

The code and data descriptors are built and decoded by
`osyx_abi::wow64`; the same module defines the selectors, so kernel and
bridge cannot drift. The GDT limit covers all nine slots.

* **FS32 base per thread.** `Thread::fs32_base` follows the thread like
  `fs_base`/`gs_base`: `pick_next` installs it in the calling CPU's GDT
  (`gdt::set_fs32_base`) on every switch, after the `IA32_FS_BASE` MSR is
  written and with interrupts off under the scheduler lock. IA-32e has a
  single hidden FS base: loading FS with 0x43 takes the base from the
  descriptor, while a zero base only patches the descriptor and leaves the
  MSR-written base alone (reloading with a zero base would silently drop a
  normal 64-bit thread's TLS). `execve` clears it.
* **Mode crossings.** A thread that alternates between 32-bit code (FS =
  TEB) and its 64-bit bridge (FS = runtime TLS) must flip the field at each
  crossing: `set_fs32_base(teb)` before entering 32-bit code (it loads FS
  from the descriptor) and `set_fs32_base(0)` before re-entering 64-bit
  code (it restores the thread's 64-bit base). The milestone 4 bridge owns
  those calls; keeping the field equal to the mode the thread is in also
  makes a preemptive switch restore the right base.
* **System call 96, `set_fs32_base(base)`** (ABI version 13) sets the base
  of the calling thread only, immediately (a non-zero base replaces the
  hidden FS base). It rejects bases at or above 4 GiB, bases in the kernel
  half and bases that are not page-aligned. 64-bit `set_fs_base` keeps its
  old meaning.
* **Entering 32-bit code.** `process::enter_compat(entry, rsp, arg)` and
  the `osyx_iret_to_user32` stub build the IRETQ frame from
  `osyx_abi::wow64::CompatIretFrame`: CS 0x3B, SS 0x1B, RFLAGS 0x202. The
  entry point and `rsp` must lie below 4 GiB and `rsp` must be 16-byte
  aligned at a call boundary; `CompatIretFrame::new` refuses anything else.
  The FPU/AVX state is the thread's normal 832-byte XSAVE image; compat
  mode uses the same state components and needs no new area.
* **Bounds.** All 32-bit images, heaps, stacks and TEBs stay below 4 GiB,
  inside the existing user range (`MAP_BASE` and `STACK_TOP` are above it,
  so the loader must place 32-bit images explicitly; see milestone 2).

Tests: four host unit tests in `shared/abi/src/wow64.rs` decode descriptors
7/8 and the IRET frame; the in-kernel self-test `32-bit compatibility
segments` (run with `init.args=tests`) reads the installed GDT entries,
switches the FS32 base on the current thread, checks the FS selector and
the hidden base reported by `IA32_FS_BASE`, restores the previous base and
logs a line starting with `wow64:`. Entering ring 3 with CS=0x3B needs the
bridge of milestone 4, so no self-test executes 32-bit instructions yet.
The host tests pass; the in-kernel self-test has not been run here (the
QEMU session was left to the maintainer).
