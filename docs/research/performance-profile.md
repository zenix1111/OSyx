# Zen performance profile (2026-10-30)

Measured in QEMU (WHPX, 4 CPUs, 6 GiB, SLIRP network, fresh Zen profile, the
YouTube watch page used in `scripts/zen-test.ps1`). Three boots per row,
`build/bench/bench.ps1`; guest seconds until the window title changes. Network
time through SLIRP varies, so compare several runs, never one.

| | Zen window | YouTube title |
|---|---|---|
| before | 10.7 / 9.5 / 11.5 s | tab crash at 13.1-15.6 s, 3 of 3 |
| after | 8.4 / 9.2 / 8.9 s | 14.8 / 15.5 / 16.1 s |

Earlier runs on an already used profile (no crash) reached the title after
25-30 s.

## Tools

* `kernel/src/prof.rs`: sampling profiler, boot option `prof=<seconds>`
  (`scripts/zen-test.ps1 -Prof 40`, which also builds the kernel with frame
  pointers). 1 kHz on every CPU: user RIP (plus return-address candidates from
  the stack page), kernel RIP with frame-pointer walk; CPU 0 also visits every
  blocked or runnable thread (off-CPU view). No locks or allocation in the
  interrupt handler.
* `scripts/flamegraph.py <serial log>`: flame graph SVGs (on-CPU, off-CPU,
  run queue), folded stacks and `report.md`. Symbols come from `nm -C` of the
  kernel and the user programs, module bases from `winrun: module` log lines.
  These are samples of a real run, not instruction counts; profiling itself
  slows the guest (window title at 13-15 s instead of 9-10 s).

## Findings and fixes

1. **Tab crash on a fresh profile.** The parent could not hand a file
   descriptor to a content process (`PNecko::Reply_GetExtensionFD`,
   `DuplicateHandle` of a file failed with error 50), so the content process
   exited. `DuplicateHandle` of a regular file now reopens the path in the
   other process (`compatibility/win32/src/inherit.rs`).
2. **Soft-float arithmetic** (`__adddf3`, `__muldf3`...) took about a third of
   all user CPU, 9.4 s of the 21 s the browser's main thread ran in a 40 s
   window: user programs are built soft-float and the Windows layer implements
   the C math library in Rust. `runtime/os-std/src/fastfloat.rs` now defines
   the add/sub/mul/div and the exact conversions with SSE2 (the kernel already
   saves SSE state).
3. **Process table lock.** `IrqGuard<process::Table>::drop` was the top
   kernel cost (11 s of CPU in 40 s, interrupts off while spinning); futex
   wait/wake alone took 5.9 s of it just to look up shared mappings. Their keys
   are now kept in a separate index (`process::SHARED_KEYS`).
4. **Zeroing pages that are overwritten.** `SharedMemory::new` cleared every
   file-cache and file-mapping page before copying file data into it
   (2.7 s on the main thread). `SharedMemory::page_from` fills the page once.
5. `osyx_net::wire::sum` (flagged by the CodSpeed flame graph as 93 % self
   time of `internet_checksum[65535]`) adds 64-bit words with end-around carry;
   a test compares it with the old 16-bit loop.

## Still open (from the profile)

* The process table lock no longer guards handle lookups: they live in
  their own table (`HANDLES`). Mappings and page faults still share `TABLE`,
  and `smp::enter_kernel` (entry lock) rose to 4.3 s once the browser ran
  faster.
* `omni.ja` (177 MiB) is no longer read when mapped: a read-only section
  loads 256 KiB runs on first touch. virtio-blk still keeps one request in
  flight, so the run is a synchronous disk read.
* PRISM already renders and presents only damaged rectangles. The remaining
  full-frame copies are in the Win32 path (`memcpy` in `winrun` and
  `vcruntime140`, 5-6 s over 40 s); prism recomposes about 27 frames/s while
  the page animates.
* No GPU acceleration beyond XSAVE/AVX state: Gecko runs software WebRender
  (`gfx.webrender.software`) because OSyx has no Direct3D/OpenGL driver;
  VirtIO-GPU is used as a 2D scan-out only.
* The Gecko sandbox is still disabled (`MOZ_DISABLE_*` switches in
  `userspace/apps/src/bin/init.rs`).
