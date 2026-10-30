//! In-kernel self-tests, enabled only by init.args=tests. They exercise the real hardware
//! paths (page tables, CPU exceptions, timer interrupts) that host unit tests
//! cannot reach. Results go to the serial log as `[test] <name> ... ok|FAILED`.

use crate::arch::cpu;
use crate::arch::timer::Deadline;
use crate::fixup::{copy_from_user, copy_to_user, probe_read_u8, probe_write_u8};
use crate::mem::paging::{self, Flags, MapError};
use crate::mem::{self, heap, phys_to_virt, PAGE_SIZE};
use crate::{interrupts, kprintln, sched, BootData};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use osyx_bootinfo::MemoryKind;

/// Scratch virtual address for mapping tests (PML4 slot 416, unused otherwise).
const TEST_VA: u64 = 0xFFFF_D000_0000_0000;

static RODATA_PROBE: [u8; 8] = *b"OSyx-ro\0";
static mut DATA_PROBE: [u8; 8] = *b"OSyx-rw\0";

pub struct Summary {
    pub passed: u32,
    pub failed: u32,
}

type TestResult = Result<(), String>;

macro_rules! ensure {
    ($cond:expr, $($msg:tt)*) => {
        if !$cond {
            return Err(format!($($msg)*));
        }
    };
}

pub fn run(boot: &BootData) -> Summary {
    let tests: [(&str, &dyn Fn() -> TestResult); 27] = [
        ("boot memory map", &|| memory_map(boot)),
        ("frame allocator", &frame_allocator),
        ("page map/unmap", &map_unmap),
        ("exception fixups", &fixups),
        ("identity map removed", &|| identity_removed(boot)),
        ("kernel W^X", &kernel_wx),
        ("kernel heap", &heap_test),
        ("breakpoint exception", &breakpoint),
        ("timer interrupts", &timer),
        ("user copy validation", &user_copy),
        ("address space lifecycle", &address_space),
        ("preemptive kernel threads", &preemption),
        ("sleep and join", &sleep_join),
        ("FPU/SSE state per thread", &fpu_state),
        ("FS base per thread", &fs_base),
        ("32-bit compatibility segments", &compat_segments),
        ("PCI enumeration", &pci_scan),
        ("block device I/O", &block_io),
        ("VFS on tmpfs: files and directories", &crate::selftest_fs::tmpfs_files),
        ("VFS: symlinks, cwd and permissions", &crate::selftest_fs::links_cwd_perms),
        ("VFS: mount, unmount and limits", &crate::selftest_fs::mount_unmount),
        ("devfs devices and /dev/random", &crate::selftest_fs::devfs),
        ("FAT32 /boot through the VFS", &crate::selftest_fs::fat_boot),
        ("ext4 root through the VFS", &crate::selftest_fs::ext4_root),
        ("concurrent writers (tmpfs, FAT32, ext4)", &crate::selftest_fs::concurrent),
        ("program loader: search path, permissions, bad images", &crate::selftest_fs::program_loader),
        ("kernel file reads: whole device firmware", &firmware_read),
    ];
    let mut s = Summary { passed: 0, failed: 0 };
    for (name, t) in tests.iter() {
        match t() {
            Ok(()) => {
                kprintln!("[test] {name} ... ok");
                s.passed += 1;
            }
            Err(e) => {
                kprintln!("[test] {name} ... FAILED: {e}");
                s.failed += 1;
            }
        }
    }
    kprintln!("self-tests: {} passed, {} failed", s.passed, s.failed);
    s
}

fn memory_map(boot: &BootData) -> TestResult {
    let map = boot.memory_map();
    ensure!(!map.is_empty(), "empty memory map");
    for w in map.windows(2) {
        ensure!(w[0].end() <= w[1].phys_start, "regions overlap or unsorted at {:#x}", w[1].phys_start);
    }
    let k = &boot.info.kernel;
    let covered = map
        .iter()
        .any(|d| d.kind == MemoryKind::KernelImage && d.phys_start <= k.phys_base && k.phys_base + k.size <= d.end());
    ensure!(covered, "kernel image {:#x}+{:#x} not reported as KernelImage", k.phys_base, k.size);
    Ok(())
}

fn frame_allocator() -> TestResult {
    let mut frames = Vec::with_capacity(256);
    let mut sorted = Vec::with_capacity(256);
    mem::with_frame_allocator(|fb| {
        let free_before = fb.free_frames();
        for i in 0..256u64 {
            let f = fb.alloc().ok_or("out of frames")?;
            ensure!(f.is_multiple_of(PAGE_SIZE), "unaligned frame {f:#x}");
            // SAFETY: freshly allocated frame, reachable through the HHDM.
            unsafe { (phys_to_virt(f) as *mut u64).write(i ^ 0xA5A5_A5A5) };
            frames.push(f);
        }
        for (i, &f) in frames.iter().enumerate() {
            // SAFETY: as above.
            let v = unsafe { (phys_to_virt(f) as *const u64).read() };
            ensure!(v == i as u64 ^ 0xA5A5_A5A5, "frame {f:#x} content corrupted");
        }
        sorted.extend_from_slice(&frames);
        sorted.sort_unstable();
        sorted.dedup();
        ensure!(sorted.len() == frames.len(), "a frame was handed out twice");
        for f in &frames {
            fb.free(*f).map_err(|e| format!("free {f:#x}: {e:?}"))?;
        }
        ensure!(fb.free(frames[0]).is_err(), "double free not detected");
        let free_after = fb.free_frames();
        ensure!(free_after == free_before, "leak: {free_before} free before, {free_after} after");
        Ok(())
    })
}

fn map_unmap() -> TestResult {
    let frame = mem::alloc_frame().ok_or("out of frames")?;
    paging::map(TEST_VA, frame, Flags::KERNEL_RW).map_err(|e| format!("map: {e:?}"))?;
    // SAFETY: TEST_VA was just mapped writable to `frame`.
    unsafe { (TEST_VA as *mut u64).write_volatile(0x0123_4567_89AB_CDEF) };
    // SAFETY: same frame through the HHDM.
    let via_hhdm = unsafe { (phys_to_virt(frame) as *const u64).read_volatile() };
    ensure!(via_hhdm == 0x0123_4567_89AB_CDEF, "aliasing through HHDM failed");
    let t = paging::translate(TEST_VA).ok_or("translate failed")?;
    ensure!(t.phys == frame && t.writable && t.page_size == PAGE_SIZE, "bad translation {t:?}");
    ensure!(!t.executable || !paging::nx_enabled(), "data page is executable");

    let expect = |r: Result<(), MapError>, e: MapError, what: &str| -> TestResult {
        ensure!(r == Err(e), "{what}: expected {e:?}, got {r:?}");
        Ok(())
    };
    expect(paging::map(TEST_VA, frame, Flags::KERNEL_RW), MapError::AlreadyMapped, "double map")?;
    expect(paging::map(TEST_VA + 8, frame, Flags::KERNEL_RW), MapError::Unaligned, "unaligned va")?;
    expect(paging::map(TEST_VA + PAGE_SIZE, frame + 1, Flags::KERNEL_RW), MapError::Unaligned, "unaligned pa")?;
    expect(paging::map(0x0000_8000_0000_0000, frame, Flags::KERNEL_RW), MapError::NonCanonical, "non-canonical")?;
    expect(paging::map(mem::hhdm_offset(), frame, Flags::KERNEL_RW), MapError::ReservedRange, "HHDM")?;
    expect(
        paging::map(run as *const () as u64 & !0xFFF, frame, Flags::KERNEL_RW),
        MapError::ReservedRange,
        "kernel image",
    )?;

    let pa = paging::unmap(TEST_VA).map_err(|e| format!("unmap: {e:?}"))?;
    ensure!(pa == frame, "unmap returned {pa:#x}, expected {frame:#x}");
    ensure!(paging::translate(TEST_VA).is_none(), "still mapped after unmap");
    ensure!(paging::unmap(TEST_VA) == Err(MapError::NotMapped), "second unmap must fail");
    ensure!(probe_read_u8(TEST_VA).is_err(), "unmapped page still readable");
    mem::free_frame(frame).map_err(|e| format!("free: {e:?}"))?;
    Ok(())
}

fn fixups() -> TestResult {
    ensure!(probe_read_u8(0xDEAD_BEEF_0000_0000).is_err(), "non-canonical read (#GP) not caught");
    ensure!(probe_read_u8(0xFFFF_D100_0000_0000).is_err(), "unmapped read (#PF) not caught");
    let ok = probe_read_u8(RODATA_PROBE.as_ptr() as u64);
    ensure!(ok == Ok(b'O'), "mapped read returned {ok:?}");
    ensure!(cpu::read_cr0() & (1 << 16) != 0, "CR0.WP is clear");
    // SAFETY: the write targets read-only data and must fault; if it did not,
    // it rewrites the byte with its existing value.
    let w = unsafe { probe_write_u8(RODATA_PROBE.as_ptr() as u64, b'O') };
    ensure!(w.is_err(), "write to read-only kernel data succeeded");
    Ok(())
}

fn identity_removed(boot: &BootData) -> TestResult {
    ensure!(probe_read_u8(0x1000).is_err(), "low memory still identity mapped");
    let k = boot.info.kernel.phys_base;
    ensure!(probe_read_u8(k).is_err(), "kernel physical address {k:#x} still identity mapped");
    ensure!(paging::translate(k).is_none(), "translate({k:#x}) succeeded");
    Ok(())
}

fn kernel_wx() -> TestResult {
    let code = paging::translate(run as *const () as u64).ok_or("code not mapped")?;
    ensure!(code.executable && !code.writable, "code page flags {code:?}");
    let ro = paging::translate(RODATA_PROBE.as_ptr() as u64).ok_or("rodata not mapped")?;
    ensure!(!ro.writable, "rodata writable");
    let rw = paging::translate(&raw const DATA_PROBE as u64).ok_or("data not mapped")?;
    ensure!(rw.writable, "data not writable");
    if paging::nx_enabled() {
        ensure!(!ro.executable && !rw.executable, "data executable (ro {ro:?}, rw {rw:?})");
    }
    Ok(())
}

fn heap_test() -> TestResult {
    // The counters cover the whole kernel heap, and background kernel threads
    // (network, klog, writeback, USB) allocate from it too: a short-lived
    // block can be caught mid-use, and a thread can keep a few bytes for good
    // (an ARP entry after the DHCP lease). Retry the workload with a fresh
    // baseline; a leak in the workload itself grows the heap on every round.
    let mut last = (0, 0);
    for _ in 0..3 {
        let before = heap::stats().used;
        heap_workload()?;
        let mut after = heap::stats().used;
        for _ in 0..20 {
            if after <= before {
                return Ok(());
            }
            sched::sleep_ticks(crate::arch::timer::ms_to_ticks(10));
            after = after.min(heap::stats().used);
        }
        last = (before, after);
    }
    Err(format!("leak: {} bytes used before, {} after (3 rounds)", last.0, last.1))
}

fn heap_workload() -> TestResult {
    let b = Box::new(0xDEAD_BEEFu64);
    ensure!(*b == 0xDEAD_BEEF, "box content");
    let v: Vec<u64> = (0..100_000).collect();
    ensure!(v.iter().sum::<u64>() == 4_999_950_000, "vec sum");
    let s = format!("{}-{:x}-{:?}", "OSyx", 0xC0FFEEu32, [1, 2, 3]);
    ensure!(s == "OSyx-c0ffee-[1, 2, 3]", "format produced {s:?}");
    let mut m = BTreeMap::new();
    for i in 0..2000u32 {
        m.insert(i.wrapping_mul(2_654_435_761), i);
    }
    for i in (0..2000u32).step_by(2) {
        m.remove(&i.wrapping_mul(2_654_435_761));
    }
    ensure!(m.len() == 1000, "btreemap len {}", m.len());
    // Larger than the initial heap: forces on-demand growth.
    let big = alloc::vec![0x5Au8; 8 << 20];
    ensure!(big.iter().all(|&b| b == 0x5A), "large allocation content");
    ensure!(heap::stats().capacity > heap::HEAP_INITIAL as usize, "heap did not grow");
    Ok(())
}

/// `bsd::read_file` (iwm and Bluetooth firmware, wifi.conf) must return the
/// whole file once: `File::read` does not move the position by itself.
fn firmware_read() -> TestResult {
    let p = "/etc/firmware/iwm-9260-46";
    let cx = crate::vfs::Lookup::kernel();
    let Ok(st) = crate::vfs::stat(&cx, p) else {
        return Ok(()); // a root without firmware
    };
    let data = crate::bsd::read_file(p).ok_or_else(|| format!("{p}: read failed"))?;
    ensure!(data.len() as u64 == st.size, "{p}: read {} bytes, the file has {}", data.len(), st.size);
    Ok(())
}

fn breakpoint() -> TestResult {
    let before = interrupts::breakpoints();
    // SAFETY: int3 is handled by the breakpoint handler, which returns.
    unsafe { core::arch::asm!("int3") };
    ensure!(interrupts::breakpoints() == before + 1, "breakpoint handler did not run");
    Ok(())
}

fn timer() -> TestResult {
    ensure!(cpu::interrupts_enabled(), "interrupts disabled");
    let start = interrupts::ticks();
    let t0 = crate::arch::timer::tsc();
    let khz = crate::arch::timer::tsc_khz();
    // Spin rather than halt: with no timer interrupt `hlt` would not return.
    let deadline = Deadline::after_ms(1000);
    while !deadline.expired() {
        if interrupts::ticks() >= start + 5 {
            return Ok(());
        }
        core::hint::spin_loop();
    }
    Err(format!(
        "timer stuck at {} ticks (start {}, tsc +{} khz, khz {})",
        interrupts::ticks(),
        start,
        (crate::arch::timer::tsc().wrapping_sub(t0)) / khz.max(1),
        khz
    ))
}

fn user_copy() -> TestResult {
    use osyx_abi::Errno;
    let mut buf = [0u8; 16];
    // Kernel addresses are rejected by the range check, before any access.
    ensure!(copy_from_user(&mut buf, RODATA_PROBE.as_ptr() as u64) == Err(Errno::Fault), "kernel address accepted");
    ensure!(copy_from_user(&mut buf, 0) == Err(Errno::Fault), "null pointer accepted");
    ensure!(copy_from_user(&mut buf, osyx_abi::USER_END - 8) == Err(Errno::Fault), "range crossing USER_END accepted");
    ensure!(copy_from_user(&mut buf, u64::MAX - 4) == Err(Errno::Fault), "overflowing range accepted");
    // In range but unmapped: rejected through the fault fixup.
    ensure!(copy_from_user(&mut buf, 0x40_0000) == Err(Errno::Fault), "unmapped user page readable");
    ensure!(copy_to_user(0x40_0000, &buf) == Err(Errno::Fault), "unmapped user page writable");
    ensure!(copy_from_user(&mut [], 0) == Ok(()), "empty copy must succeed");
    Ok(())
}

fn address_space() -> TestResult {
    let (free_before, _) = mem::frame_stats();
    let root = paging::new_address_space().map_err(|e| format!("create: {e:?}"))?;
    let frame = mem::alloc_frame().ok_or("out of frames")?;
    let va = 0x40_0000;
    paging::map_in(root, va, frame, Flags::user(true, false)).map_err(|e| format!("map_in: {e:?}"))?;
    let t = paging::translate_in(root, va).ok_or("translate_in failed")?;
    ensure!(t.phys == frame && t.user && t.writable, "bad user translation {t:?}");
    ensure!(paging::translate(va).is_none(), "user mapping leaked into the kernel address space");
    let k = paging::translate_in(root, RODATA_PROBE.as_ptr() as u64).ok_or("kernel half not shared")?;
    ensure!(!k.user, "kernel page accessible from user mode");
    ensure!(
        paging::map_in(root, mem::hhdm_offset(), frame, Flags::user(true, false)) == Err(MapError::ReservedRange),
        "user mapping in kernel half accepted"
    );
    ensure!(
        paging::map_in(root, 0x1000, frame, Flags::user(true, false)) == Err(MapError::ReservedRange),
        "user mapping in the null guard accepted"
    );
    // SAFETY: the address space was never activated and owns `frame`.
    let freed = unsafe { paging::destroy_address_space(root) };
    ensure!(freed == 5, "expected 5 frames released (root, PDPT, PD, PT, page), got {freed}");
    let (free_after, _) = mem::frame_stats();
    ensure!(free_after == free_before, "leak: {free_before} free before, {free_after} after");
    Ok(())
}

static SPIN_STOP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
static SPIN_COUNT: [core::sync::atomic::AtomicU64; 2] =
    [core::sync::atomic::AtomicU64::new(0), core::sync::atomic::AtomicU64::new(0)];

/// Busy loop that never yields: it only stops running when preempted.
fn spinner(slot: u64, _: u64) {
    use core::sync::atomic::Ordering;
    while !SPIN_STOP.load(Ordering::Relaxed) {
        SPIN_COUNT[slot as usize].fetch_add(1, Ordering::Relaxed);
    }
}

fn preemption() -> TestResult {
    use core::sync::atomic::Ordering;
    SPIN_STOP.store(false, Ordering::Relaxed);
    let before = sched::stats().switches;
    let a = sched::spawn_kernel("spin-a", spinner, 0, 0);
    let b = sched::spawn_kernel("spin-b", spinner, 1, 0);
    // kmain sleeps; the spinners never yield, so kmain only runs again (and
    // both spinners only make progress) if the timer preempts them.
    sched::sleep_ticks(crate::arch::timer::ms_to_ticks(200));
    let (ca, cb) = (SPIN_COUNT[0].load(Ordering::Relaxed), SPIN_COUNT[1].load(Ordering::Relaxed));
    SPIN_STOP.store(true, Ordering::Relaxed);
    sched::join(a);
    sched::join(b);
    let switches = sched::stats().switches - before;
    kprintln!("[test]   spinners counted {ca} and {cb}, {switches} context switches");
    ensure!(ca > 0 && cb > 0, "a spinner never ran (a={ca}, b={cb})");
    ensure!(switches >= 4, "only {switches} context switches");
    Ok(())
}

static SLEPT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn sleeper(ticks: u64, _: u64) {
    let start = interrupts::ticks();
    sched::sleep_ticks(ticks);
    SLEPT.store(interrupts::ticks() - start, core::sync::atomic::Ordering::Relaxed);
}

fn sleep_join() -> TestResult {
    use core::sync::atomic::Ordering;
    SLEPT.store(0, Ordering::Relaxed);
    let start = interrupts::ticks();
    let t = sched::spawn_kernel("sleeper", sleeper, 5, 0);
    sched::join(t);
    let slept = SLEPT.load(Ordering::Relaxed);
    ensure!(slept >= 5, "sleeper woke after {slept} ticks, expected >= 5");
    ensure!(interrupts::ticks() - start >= 5, "join returned before the thread finished");
    let threads = sched::stats().threads;
    sched::join(t); // joining a finished thread returns at once
    ensure!(sched::stats().threads <= threads, "dead thread not reaped");
    Ok(())
}

static FPU_OK: [core::sync::atomic::AtomicBool; 2] =
    [core::sync::atomic::AtomicBool::new(false), core::sync::atomic::AtomicBool::new(false)];
static AVX_OK: [core::sync::atomic::AtomicBool; 2] =
    [core::sync::atomic::AtomicBool::new(false), core::sync::atomic::AtomicBool::new(false)];

/// Loads xmm0..xmm3 with a per-thread pattern, spins across several time
/// slices (other threads run and load their own patterns), then checks the
/// registers. The kernel is soft-float, so nothing else touches XMM here.
fn fpu_worker(slot: u64, seed: u64) {
    use core::sync::atomic::Ordering;
    let mut out = [0u64; 4];
    // SAFETY: SSE is enabled; the asm only uses xmm0-3 and the listed GPRs.
    unsafe {
        core::arch::asm!(
            "movq xmm0, {s}", "add {s}, 1", "movq xmm1, {s}", "add {s}, 1",
            "movq xmm2, {s}", "add {s}, 1", "movq xmm3, {s}",
            s = inout(reg) seed => _,
        );
    }
    let end = Deadline::after_ticks(8);
    while !end.expired() {
        core::hint::spin_loop();
    }
    // SAFETY: as above; writes four u64 into `out`.
    unsafe {
        core::arch::asm!(
            "movq [{o}], xmm0", "movq [{o} + 8], xmm1", "movq [{o} + 16], xmm2", "movq [{o} + 24], xmm3",
            o = in(reg) out.as_mut_ptr(),
        );
    }
    let ok = out == [seed, seed + 1, seed + 2, seed + 3];
    if !ok {
        kprintln!("[test]   fpu worker {slot}: expected {:#x}.., got {:x?}", seed, out);
    }
    FPU_OK[slot as usize].store(ok, Ordering::Relaxed);
}

fn fpu_state() -> TestResult {
    use core::sync::atomic::Ordering;
    let a = sched::spawn_kernel("fpu-a", fpu_worker, 0, 0x1111_0000_0000_0000);
    let b = sched::spawn_kernel("fpu-b", fpu_worker, 1, 0x2222_0000_0000_0000);
    sched::join(a);
    sched::join(b);
    ensure!(FPU_OK[0].load(Ordering::Relaxed), "thread A lost its XMM registers");
    ensure!(FPU_OK[1].load(Ordering::Relaxed), "thread B lost its XMM registers");
    if crate::arch::cpu::fpu_has_avx() {
        let a = sched::spawn_kernel("avx-a", avx_worker, 0, 0x3333_0000_0000_0000);
        let b = sched::spawn_kernel("avx-b", avx_worker, 1, 0x4444_0000_0000_0000);
        sched::join(a);
        sched::join(b);
        ensure!(AVX_OK[0].load(Ordering::Relaxed), "thread A lost its YMM upper halves");
        ensure!(AVX_OK[1].load(Ordering::Relaxed), "thread B lost its YMM upper halves");
    } else {
        kprintln!("[test]   AVX not enabled; YMM switch check skipped");
    }
    Ok(())
}

/// Same as [`fpu_worker`], but for the YMM upper halves that only XSAVE
/// preserves. Runs only when the kernel enabled AVX.
fn avx_worker(slot: u64, seed: u64) {
    use core::sync::atomic::Ordering;
    let pattern = [seed; 4];
    let mut out = [0u64; 16];
    // SAFETY: AVX is enabled; the asm touches only ymm0-3 and the given GPR.
    unsafe {
        core::arch::asm!(
            "vmovdqu ymm0, [{p}]", "vmovdqu ymm1, [{p}]",
            "vmovdqu ymm2, [{p}]", "vmovdqu ymm3, [{p}]",
            p = in(reg) pattern.as_ptr(),
        );
    }
    let end = Deadline::after_ticks(8);
    while !end.expired() {
        core::hint::spin_loop();
    }
    // SAFETY: as above; writes four u64 into `out` and clears the upper state.
    unsafe {
        core::arch::asm!(
            "vmovdqu [{o}], ymm0", "vmovdqu [{o} + 32], ymm1",
            "vmovdqu [{o} + 64], ymm2", "vmovdqu [{o} + 96], ymm3",
            "vzeroupper",
            o = in(reg) out.as_mut_ptr(),
        );
    }
    let ok = out.iter().all(|&v| v == seed);
    if !ok {
        kprintln!("[test]   avx worker {slot}: expected {:#x}.., got {:x?}", seed, out);
    }
    AVX_OK[slot as usize].store(ok, Ordering::Relaxed);
}

static FS_OK: [core::sync::atomic::AtomicBool; 2] =
    [core::sync::atomic::AtomicBool::new(false), core::sync::atomic::AtomicBool::new(false)];

/// Sets a distinct FS base, gets preempted several times, checks it.
fn fs_worker(slot: u64, value: u64) {
    sched::set_current_fs_base(value);
    let end = Deadline::after_ticks(6);
    while !end.expired() {
        core::hint::spin_loop();
    }
    // SAFETY: IA32_FS_BASE exists on every x86-64 CPU.
    let now = unsafe { cpu::rdmsr(0xC000_0100) };
    FS_OK[slot as usize].store(now == value, core::sync::atomic::Ordering::Relaxed);
}

fn fs_base() -> TestResult {
    use core::sync::atomic::Ordering;
    // SAFETY: as above.
    let mine = unsafe { cpu::rdmsr(0xC000_0100) };
    let a = sched::spawn_kernel("fs-a", fs_worker, 0, 0x0000_1111_0000_0000);
    let b = sched::spawn_kernel("fs-b", fs_worker, 1, 0x0000_2222_0000_0000);
    sched::join(a);
    sched::join(b);
    ensure!(FS_OK[0].load(Ordering::Relaxed) && FS_OK[1].load(Ordering::Relaxed), "a thread saw another FS base");
    // SAFETY: as above.
    let after = unsafe { cpu::rdmsr(0xC000_0100) };
    ensure!(after == mine, "kmain's FS base changed from {mine:#x} to {after:#x}");
    Ok(())
}

/// 32-bit compatibility segments: the descriptors installed in the GDT, the
/// per-thread FS32 base switch and the IRET frame that enters compatibility
/// mode. The ring-3 jump itself is the M4 bridge's job.
fn compat_segments() -> TestResult {
    use osyx_abi::wow64;
    const TEB: u64 = 0x7FFD_F000;

    let code = crate::arch::gdt::descriptor(7);
    ensure!(code == wow64::code32_descriptor(), "GDT entry 7 is {code:#x}, not the 32-bit code descriptor");
    ensure!(wow64::descriptor_d(code) && !wow64::descriptor_l(code), "entry 7 is not 32-bit code");
    ensure!((wow64::descriptor_access(code) & 0x60) == 0x60, "entry 7 is not DPL 3");
    ensure!((wow64::descriptor_access(code) & 0x18) == 0x18, "entry 7 is not a code segment");
    ensure!(wow64::descriptor_base(crate::arch::gdt::descriptor(8)) == 0, "entry 8 has a base before any set");
    // SAFETY: IA32_FS_BASE exists on every x86-64 CPU.
    let prior = unsafe { cpu::rdmsr(0xC000_0100) };

    sched::set_current_fs32_base(TEB);
    let fs = crate::arch::gdt::descriptor(8);
    ensure!(wow64::descriptor_base(fs) == TEB as u32, "entry 8 base {:#x} after set", wow64::descriptor_base(fs));
    ensure!((wow64::descriptor_access(fs) & 0x10) != 0, "entry 8 is not a data segment");
    let sel = fs_selector();
    ensure!(sel == wow64::USER_FS32, "FS selector {sel:#x} after set");
    // The descriptor load must have replaced the one hidden FS base, which is
    // what compatibility-mode code reads at fs:[0x18].
    // SAFETY: as above.
    let hidden = unsafe { cpu::rdmsr(0xC000_0100) };
    ensure!(hidden == TEB, "hidden FS base {hidden:#x}, not the descriptor base");

    let frame = wow64::CompatIretFrame::new(0x0040_1000, 0x7FFE_0000).ok_or("compat IRET frame rejected")?;
    ensure!(frame.cs == 0x3B && frame.ss == 0x1B, "frame selectors {:#x}/{:#x}", frame.cs, frame.ss);
    ensure!(frame.rflags == 0x202, "frame rflags {:#x}", frame.rflags);
    kprintln!(
        "wow64: CS32 {:#x} desc {code:#x}, FS32 {:#x} base {:#x} (FS selector {:#x}, hidden base {hidden:#x}), iret rip {:#x} cs {:#x} rsp {:#x} ss {:#x}",
        wow64::USER_CS32,
        wow64::USER_FS32,
        TEB,
        sel,
        frame.rip,
        frame.cs,
        frame.rsp,
        frame.ss
    );

    sched::set_current_fs32_base(0);
    ensure!(wow64::descriptor_base(crate::arch::gdt::descriptor(8)) == 0, "entry 8 base not cleared");
    // SAFETY: as above.
    let restored = unsafe { cpu::rdmsr(0xC000_0100) };
    ensure!(restored == prior, "FS base {restored:#x} after clear, was {prior:#x}");
    Ok(())
}

/// The FS selector currently loaded (reads the visible part only).
fn fs_selector() -> u16 {
    let sel: u16;
    // SAFETY: reading a segment register has no side effects.
    unsafe { core::arch::asm!("mov {sel:x}, fs", sel = out(reg) sel, options(nomem, nostack, preserves_flags)) };
    sel
}

fn pci_scan() -> TestResult {
    let devs = crate::pci::enumerate();
    ensure!(!devs.is_empty(), "no PCI functions found");
    let host = devs.iter().find(|d| d.addr.bus == 0 && d.addr.device == 0 && d.addr.function == 0);
    ensure!(host.is_some_and(|d| d.class == 0x06 && d.subclass == 0x00), "00:00.0 is not a host bridge");
    for d in &devs {
        ensure!(devs.iter().filter(|e| e.addr == d.addr).count() == 1, "{} enumerated twice", d.addr);
        // The capability walk must terminate and stay inside config space.
        ensure!(d.capabilities().iter().all(|&(off, _)| off >= 0x40), "{}: capability below 0x40", d.addr);
    }
    // BAR placement for functions the firmware left unassigned.
    use crate::pci::first_fit;
    let used = [(0xD000_0000, 0xD010_0000), (0xD020_0000, 0xD030_0000), (0xD010_0000, 0xD010_4000)];
    ensure!(first_fit(0xD000_0000, 0xD040_0000, 0x4000, 0x4000, &used) == Some(0xD010_4000), "first fit after the ranges it overlaps");
    ensure!(first_fit(0xD000_0000, 0xD040_0000, 0x10_0000, 0x10_0000, &used) == Some(0xD030_0000), "first aligned gap");
    ensure!(first_fit(0xD000_0000, 0xD030_0000, 0x10_0000, 0x10_0000, &used).is_none(), "full window");
    ensure!(first_fit(0xD000_1000, 0xD000_8000, 0x4000, 0x4000, &[]) == Some(0xD000_4000), "aligned start");
    Ok(())
}

/// Sector I/O through the block layer: boot signature, chunked transfers
/// that cross the driver's request size, range checks, and a write of
/// identical data to the FAT32 backup boot sector (sector 6).
fn block_io() -> TestResult {
    use crate::block::{self, BlockError, SECTOR_SIZE};
    let devices = block::devices();
    let Some(dev) = devices.iter().find(|d| !d.read_only()) else {
        kprintln!("[test]   skipped: no writable disk attached");
        return Ok(());
    };
    let mut s0 = [0u8; SECTOR_SIZE];
    block::read(&**dev, 0, &mut s0).map_err(|e| format!("read sector 0: {e:?}"))?;
    ensure!(s0[510] == 0x55 && s0[511] == 0xAA, "{}: sector 0 has no boot signature", dev.name());
    let n = dev.max_sectors() * 2 + 3;
    let mut big = alloc::vec![0u8; n * SECTOR_SIZE];
    block::read(&**dev, 0, &mut big).map_err(|e| format!("read {n} sectors: {e:?}"))?;
    for i in [0, dev.max_sectors() - 1, dev.max_sectors(), n - 1] {
        let mut one = [0u8; SECTOR_SIZE];
        block::read(&**dev, i as u64, &mut one).map_err(|e| format!("read sector {i}: {e:?}"))?;
        ensure!(one[..] == big[i * SECTOR_SIZE..(i + 1) * SECTOR_SIZE], "sector {i} differs in a chunked read");
    }
    let end = dev.sector_count();
    ensure!(block::read(&**dev, end, &mut s0) == Err(BlockError::InvalidRequest), "read past the end accepted");
    ensure!(block::read(&**dev, end - 1, &mut [0u8; 1024]) == Err(BlockError::InvalidRequest), "read across the end accepted");
    ensure!(block::read(&**dev, 0, &mut [0u8; 100]) == Err(BlockError::InvalidRequest), "partial sector accepted");
    let mut backup = [0u8; SECTOR_SIZE];
    block::read(&**dev, 6, &mut backup).map_err(|e| format!("read sector 6: {e:?}"))?;
    block::write(&**dev, 6, &backup).map_err(|e| format!("write sector 6: {e:?}"))?;
    let mut again = [0u8; SECTOR_SIZE];
    block::read(&**dev, 6, &mut again).map_err(|e| format!("re-read sector 6: {e:?}"))?;
    ensure!(again == backup, "sector 6 changed after rewriting it");
    dev.flush().map_err(|e| format!("flush: {e:?}"))?;
    if let Some(ro) = devices.iter().find(|d| d.read_only()) {
        ensure!(block::write(&**ro, 0, &s0) == Err(BlockError::ReadOnly), "write to read-only {} accepted", ro.name());
    }
    kprintln!("[test]   {} ({}): {} sectors, {} per request", dev.name(), dev.describe(), end, dev.max_sectors());
    Ok(())
}
