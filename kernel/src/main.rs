//! OSyx kernel entry point and early initialisation.
//!
//! Init order matters:
//!  1. serial and the early framebuffer log (diagnostics), BootInfo
//!     validation and copy into kernel memory
//!  2. own GDT/TSS/IDT (firmware tables live in memory we are about to reuse)
//!  3. frame allocator, NX state, removal of the boot identity map
//!  4. kernel heap, then reclaim of bootloader memory
//!  5. local APIC, tick source (APIC timer, PIT fallback), interrupts on
//!  6. scheduler (this flow becomes thread "kmain")
//!  7. PCI enumeration, disk drivers, volume mounts (drivers sleep, so they
//!     need the scheduler), then the framebuffer status screen, self-tests
//!     and the init program in ring 3

#![no_std]
#![no_main]

extern crate alloc;

mod acpi;
mod arch;
mod firmware;
mod audio;
mod block;
mod bluetooth;
mod bsd;
mod devices;
mod display;
mod drivers;
mod earlycon;
mod exec;
mod filecache;
mod filemap;
mod fixup;
mod futex;
mod image;
mod input;
mod interrupts;
mod ipc;
mod irq;
mod live;
mod mem;
mod media;
mod modules;
mod net;
mod object;
mod pci;
mod pipe;
mod power;
mod process;
mod prof;
mod qemu;
mod random;
mod sched;
mod smp;
mod selftest;
mod selftest_fs;
mod serial;
mod shm;
mod storage;
mod sync;
mod sys_objects;
mod syscall;
mod user_fault;
mod time;
mod vfs;
mod waitq;
mod wireless;

use alloc::vec::Vec;
use arch::cpu;
use core::fmt::Write as _;
use osyx_bootinfo::{BootInfo, MemoryDescriptor, MemoryKind};
use sync::BootCell;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_MEMORY_REGIONS: usize = 512;
const MAX_CMDLINE: usize = 4096;

/// Everything the kernel keeps from the boot loader, copied out of
/// bootloader-owned memory so that memory can be reclaimed.
pub struct BootData {
    pub info: BootInfo,
    map: [MemoryDescriptor; MAX_MEMORY_REGIONS],
    map_len: usize,
    cmdline: [u8; MAX_CMDLINE],
    cmdline_len: usize,
}

impl BootData {
    pub fn memory_map(&self) -> &[MemoryDescriptor] {
        &self.map[..self.map_len]
    }

    pub fn cmdline(&self) -> &str {
        core::str::from_utf8(&self.cmdline[..self.cmdline_len]).unwrap_or("")
    }

    pub fn has_option(&self, opt: &str) -> bool {
        self.cmdline().split_ascii_whitespace().any(|w| w == opt)
    }

    pub fn option_value(&self, key: &str) -> Option<&str> {
        self.cmdline().split_ascii_whitespace().find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
    }
}

static BOOT: BootCell<BootData> = BootCell::new();

/// Whether the boot command line carries `opt`. Diagnostics opt in with
/// `stats` so normal desktop boots do not pay for serial dumps.
pub fn has_boot_option(opt: &str) -> bool {
    BOOT.get().is_some_and(|b| b.has_option(opt))
}

/// The value of a `key=value` boot option.
pub fn boot_option_value(key: &str) -> Option<&'static str> {
    BOOT.get().and_then(|b| b.option_value(key))
}

/// Kernel entry, reached from the boot loader with the HHDM address of the
/// BootInfo in RDI, interrupts disabled and a 128 KiB stack.
///
/// # Safety
/// Only the OSyx boot loader may call this, as described in `osyx_bootinfo`.
#[no_mangle]
#[link_section = ".text.entry"]
pub unsafe extern "C" fn _start(info: *const BootInfo) -> ! {
    if info.is_null() {
        serial::init();
        kprintln!("FATAL: no BootInfo");
        cpu::halt_forever();
    }
    // SAFETY: the loader passes a mapped BootInfo; validation precedes use of
    // its pointers, including the framebuffer's physical address and HHDM.
    let raw = unsafe { info.read() };
    let valid = raw.validate().is_ok();
    let mark = |stage| {
        if valid && raw.has_framebuffer() {
            earlycon::marker(&raw.framebuffer, raw.hhdm_offset, raw.hhdm_size, stage);
        }
    };
    mark(1);
    if valid && raw.has_framebuffer() {
        earlycon::init(&raw.framebuffer, raw.hhdm_offset, raw.hhdm_size);
    }
    mark(2);
    serial::init();
    mark(3);
    // Do not enter firmware descriptors after ExitBootServices.
    unsafe { arch::gdt::init() };
    mark(4);
    unsafe { smp::init_boot_cpu() };
    mark(5);
    unsafe { arch::idt::init() };
    mark(6);
    kprintln!("kernel entry reached");
    kprintln!("OSyx kernel {} (x86_64) starting", VERSION);
    if let Err(e) = raw.validate() {
        kprintln!("FATAL: invalid BootInfo: {:?}", e);
        cpu::halt_forever();
    }
    // SAFETY: the header is valid, so the map and command line pointers come
    // from the OSyx loader and point into its (still intact) BootInfo region.
    let boot = unsafe { BOOT.init(copy_boot_data(&raw)) };
    kprintln!(
        "boot loader {}.{}.{}, command line: {:?}",
        raw.bootloader_version >> 16,
        (raw.bootloader_version >> 8) & 0xFF,
        raw.bootloader_version & 0xFF,
        boot.cmdline()
    );

    // SAFETY: single CPU, interrupts disabled, called exactly once.
    unsafe { syscall::init() };
    let cpuinfo = cpu::CpuInfo::detect();
    kprintln!("cpu: {}", cpuinfo);
    // SAFETY: CR0.WP makes read-only pages read-only for ring 0 too; SSE is
    // enabled for user code (the kernel itself is soft-float).
    unsafe {
        core::arch::asm!("mov rax, cr0", "or rax, 0x10000", "mov cr0, rax", out("rax") _);
        cpu::enable_sse(0);
    }

    log_memory_map(boot.memory_map());
    // SAFETY: own GDT/IDT are loaded; called once.
    unsafe { mem::init(boot.memory_map(), raw.hhdm_offset, raw.hhdm_size) };
    mem::paging::init();
    let removed = mem::paging::remove_identity_map();
    kprintln!("paging: NX {}, removed {} identity-map PML4 entries", mem::paging::nx_enabled(), removed);
    let heap = mem::heap::init();
    kprintln!("heap: {} KiB mapped at {:#x}", heap >> 10, mem::heap::HEAP_START);
    // Boot modules live in bootloader memory: copy them before reclaiming.
    // SAFETY: BootInfo was validated; nothing has been reclaimed yet.
    unsafe { modules::init(&raw) };
    let reclaimed = mem::reclaim_bootloader_memory(boot.memory_map());
    let (free, total) = mem::frame_stats();
    kprintln!("reclaimed {} KiB of boot loader memory; {} / {} MiB free", reclaimed * 4, free >> 8, total >> 8);

    if let Some((cols, rows)) = earlycon::geometry() {
        kprintln!("console: early framebuffer log, {} x {} characters", cols, rows);
    }
    acpi::init(if raw.flags & osyx_bootinfo::FLAG_ACPI != 0 { raw.acpi_rsdp } else { 0 });
    // SAFETY: IDT is loaded, interrupts still disabled.
    unsafe { arch::pic::init() };
    // The local APIC receives device MSIs and provides the tick timer.
    arch::apic::init(cpuinfo.has_apic(), cpuinfo.has_x2apic(), boot.option_value("apic") == Some("x2apic"));
    arch::timer::init(boot.option_value("timer"), boot.option_value("timer.calib"));
    cpu::enable_interrupts();
    arch::timer::verify();
    sched::init();
    smp::start(boot);
    prof::init();
    kprintln!("scheduler: round robin, {} ms time slice", sched::TIME_SLICE_TICKS * 1000 / arch::timer::TIMER_HZ);
    let pci_devices = pci::enumerate();
    pci::log_devices(&pci_devices);
    if let Some(location) = boot.option_value("pci.unassign") {
        pci::unassign(&pci_devices, location);
    }
    firmware::init(boot.memory_map());
    let firmware_memory: Vec<(u64, u64)> =
        boot.memory_map().iter().map(|r| (r.phys_start, r.phys_start + r.page_count * 4096)).collect();
    pci::assign_bars(&pci_devices, &firmware_memory);
    wireless::scan_pci(&pci_devices);
    match time::init() {
        Some(secs) => kprintln!("time: RTC says {} UTC", time::format_utc(secs)),
        None => kprintln!("time: RTC unreadable; timestamps count from boot"),
    }
    block::probe(&pci_devices);
    random::init(&pci_devices);
    // USB comes up in its own threads: input devices and USB disks appear
    // asynchronously. Boot waits (bounded) only so a root filesystem on a
    // USB disk is found before the partition scan.
    input::init(boot.has_option("input.log"));
    let usb_controllers = drivers::xhci::probe(&pci_devices);
    kprintln!("usb: {} xHCI controller(s)", usb_controllers);
    if usb_controllers > 0 {
        drivers::xhci::wait_ready(10_000);
    }
    // After the xHCI handoff, which ends USB legacy emulation of ports 0x60/0x64.
    drivers::ps2::start();
    let partitions = block::scan_partitions();
    devices::init();
    let disks = block::devices().len();
    let mounted = storage::mount_all(boot);
    bluetooth::after_mount();
    serial::start_log_file();
    let nics = net::init(&pci_devices, boot);
    kprintln!("net: {} interface(s)", nics);
    vfs::start_writeback();
    filecache::start_readahead();
    // Compressed memory for cold pages; `swap.off` turns it off.
    if !boot.has_option("swap.off") {
        process::start_swap();
    }
    kprintln!(
        "storage: {} PCI functions, {} disks, {} partitions, {} mounts, root: {}",
        pci_devices.len(),
        disks,
        partitions,
        mounted.mounts,
        mounted.root
    );

    let mut footer = Line::new();
    let fb = &raw.framebuffer;
    let _ = write!(footer, "{}x{}  {} MiB RAM", fb.width, fb.height, total >> 8);
    let keep_log = boot.has_option("log.screen");
    // A VirtIO-GPU is preferred over the firmware framebuffer (with one,
    // GOP is usually Blt-only anyway); `display=gop` keeps GOP.
    let gpu = if boot.option_value("display") == Some("gop") { None } else { drivers::virtio_gpu::find(&pci_devices) };
    let mode = boot.option_value("display.mode").and_then(|m| {
        let (w, h) = m.split_once('x')?;
        Some((w.parse().ok()?, h.parse().ok()?))
    });
    let testing = boot.option_value("init.args").is_some_and(|s| s.split(',').next() == Some("tests"));
    let has_display = match gpu {
        Some(g) if display::init_gpu(g.clone(), footer.as_str(), mode) => {
            if testing { match display::cursor_selftest() {
                Ok(what) => kprintln!("display: cursor check ok: {}", what),
                Err(e) => kprintln!("display: cursor check FAILED: {}", e),
            } }
            true
        }
        _ => raw.has_framebuffer() && display::init(fb, footer.as_str(), keep_log),
    };
    kprintln!(
        "display: {}",
        match (has_display, earlycon::active()) {
            (true, true) => "status screen ready; the boot log stays until a process takes the display (log.screen)",
            (true, false) if display::info().is_some_and(|d| d.backend == osyx_abi::ipc::BACKEND_VIRTIO_GPU) => "status screen active on virtio-gpu",
            (true, false) => "status screen active on the GOP framebuffer",
            (false, true) => "status screen unavailable; the boot log stays",
            (false, false) => "none",
        }
    );
    let summary = if testing {
        display::status("Running self-tests", osyx_gfx::splash::TEXT, &[]);
        selftest::run(boot)
    } else {
        kprintln!("normal boot: tests disabled (enable with init.args=tests)");
        selftest::Summary { passed: 0, failed: 0 }
    };
    let mut line1 = Line::new();
    let (free, _) = mem::frame_stats();
    if testing {
        let _ = write!(line1, "Self-tests: {} passed, {} failed  |  {} MiB free", summary.passed, summary.failed, free >> 8);
    } else {
        let _ = write!(line1, "{} MiB free", free >> 8);
    }
    let mut ok = summary.failed == 0;
    display::status("Starting init", osyx_gfx::splash::TEXT, &[line1.as_str()]);

    let mut line2 = Line::new();
    let init_name = boot.option_value("init").unwrap_or("init");
    ok &= run_init(boot, init_name, &mut line2);
    // With init gone, retained read-only pages are cache, not live mappings.
    exec::clear();
    filecache::clear();
    log_subsystems();
    let color = if ok { osyx_gfx::splash::OK } else { osyx_gfx::splash::ERROR };
    let title = if ok { "OSyx kernel is running" } else { "OSyx: a check failed" };
    display::status(title, color, &[line1.as_str(), line2.as_str()]);

    if let Some(kind) = boot.option_value("test.fault").filter(|_| testing) {
        trigger_fault(kind);
    }
    if testing && boot.has_option("test.exit") {
        let (pages, bytes, out, input) = process::swap_stats();
        kprintln!("swap: stats pages={pages} bytes={bytes} out={out} in={input}");
        let (refaults, protected) = process::swap_adaptive_stats();
        kprintln!("swap: adaptive quick_refaults={refaults} protected_scans={protected}");
        if boot.has_option("test.power-cut") {
            // Simulated power loss: no unmount, no flush of anything pending.
            kprintln!("test.power-cut: stopping without unmounting");
        } else {
            vfs::shutdown();
        }
        kprintln!("test.exit: leaving QEMU ({})", if ok { "success" } else { "failure" });
        qemu::exit(if ok { qemu::ExitCode::Success } else { qemu::ExitCode::TestFailure });
    }
    kprintln!("entering idle loop");
    idle(line1, line2, ok)
}

/// Environment of the init program.
const INIT_ENV: [&str; 3] = ["PATH=/bin:/usr/bin", "HOME=/", "TERM=osyx"];

/// Runs the init program (`init=<name or path>`, searched in /bin and
/// /usr/bin like any program) with `init.args=a,b,c` and checks its exit
/// status against `init.expect=N` (default 0). Returns whether it matched;
/// a missing init program is not an error.
fn run_init(boot: &BootData, name: &str, summary: &mut Line) -> bool {
    let mut args: Vec<&str> = alloc::vec![name];
    if let Some(extra) = boot.option_value("init.args") {
        args.extend(extra.split(',').filter(|a| !a.is_empty()));
    }
    let expect = boot.option_value("init.expect").and_then(parse_int).unwrap_or(0);
    let req = match exec::ExecRequest::new(name, &args, &INIT_ENV) {
        Ok(r) => r,
        Err(e) => {
            kprintln!("init: bad arguments: {}", e.name());
            let _ = write!(summary, "init: bad arguments");
            return false;
        }
    };
    let spawned = process::spawn(process::KERNEL_PID, &req);
    if let Err(process::ExecError::Load(osyx_abi::Errno::NotFound)) = spawned {
        kprintln!("no init program {:?} in {}", name, osyx_abi::PROGRAM_PATH.join(" or "));
        let _ = write!(summary, "No init program (/bin/{})", name);
        return true;
    }
    let result = spawned
        .map_err(|e| alloc::format!("{e}"))
        .and_then(|pid| process::wait(process::KERNEL_PID, pid).map_err(|e| alloc::format!("{e:?}")));
    match result {
        Ok((_, status)) => {
            let st = sched::stats();
            kprintln!(
                "scheduler: {} context switches, {} threads alive ({} ready), {} processes left",
                st.switches,
                st.threads,
                st.ready,
                process::count()
            );
            sched::dump();
            let ok = status == expect;
            kprintln!(
                "init: exit status {:#x}, expected {:#x}: {}",
                status,
                expect,
                if ok { "ok" } else { "MISMATCH" }
            );
            let tail = process::output_tail();
            let last = tail.last().map(|s| s.as_str()).unwrap_or("");
            let _ = write!(summary, "init exited with {}: \"{}\"", status, last);
            ok
        }
        Err(e) => {
            kprintln!("init: failed to start: {}", e);
            let _ = write!(summary, "init failed to start: {}", e);
            false
        }
    }
}

/// Logs the state of USB, input, interrupts and IPC once init has finished
/// (integration tests read these lines as evidence).
fn log_subsystems() {
    for i in 0..drivers::xhci::controllers() {
        kprintln!("usb: controller {} took {} interrupts", i, drivers::xhci::interrupts_of(i));
    }
    for line in drivers::xhci::status() {
        kprintln!("usb: {}", line);
    }
    kprintln!("input: {} events in total", input::total_events());
    for (vector, n) in irq::counts() {
        kprintln!("irq: vector {:#x} fired {} times", vector, n);
    }
    let services = ipc::services();
    kprintln!("ipc: {} live service(s) {:?}, {} shared frames mapped", services.len(), services, shm::shared_frames());
    net::log_summary();
    if let Some(line) = display::gpu_summary() {
        kprintln!("{}", line);
    }
}

fn parse_int(s: &str) -> Option<i32> {
    match s.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok().map(|v| v as i32),
        None => s.parse().ok(),
    }
}

/// kmain's final loop: animates the status screen while the idle thread
/// halts the CPU in between.
fn idle(line1: Line, line2: Line, ok: bool) -> ! {
    let mut last = 0;
    let hz = arch::timer::TIMER_HZ as u64;
    loop {
        sched::sleep_ticks(arch::timer::ms_to_ticks(40));
        let t = interrupts::ticks();
        display::spin((t * 400 / hz) as u32);
        if t / hz != last / hz {
            display::poll_hotplug();
        }
        if t / hz != last / hz {
            let mut up = Line::new();
            let _ = write!(up, "Uptime {} s", t / hz);
            let (title, color) = if ok {
                ("OSyx kernel is running", osyx_gfx::splash::OK)
            } else {
                ("OSyx: a check failed", osyx_gfx::splash::ERROR)
            };
            display::status(title, color, &[line1.as_str(), line2.as_str(), up.as_str()]);
        }
        last = t;
    }
}

/// Deliberately raises a CPU exception to exercise the diagnostics path.
fn trigger_fault(kind: &str) {
    kprintln!("test.fault: triggering {kind}");
    // SAFETY: every branch intentionally faults; the handler reports and panics.
    unsafe {
        match kind {
            "pf" => {
                let _ = core::ptr::read_volatile(0xFFFF_D100_0000_1000 as *const u64);
            }
            "gp" => {
                let _ = core::ptr::read_volatile(0x8000_0000_0000_0000u64 as *const u64);
            }
            "ud" => core::arch::asm!("ud2"),
            "de" => {
                core::arch::asm!("xor edx, edx", "xor eax, eax", "xor ecx, ecx", "div ecx", out("eax") _, out("edx") _, out("ecx") _)
            }
            _ => kprintln!("test.fault: unknown kind {kind:?} (pf, gp, ud, de)"),
        }
    }
}

/// # Safety
/// `raw` must have passed `validate()` so its pointers are the loader's.
unsafe fn copy_boot_data(raw: &BootInfo) -> BootData {
    let mut b = BootData {
        info: *raw,
        map: [MemoryDescriptor { phys_start: 0, page_count: 0, kind: MemoryKind::Reserved, _reserved: 0 };
            MAX_MEMORY_REGIONS],
        map_len: 0,
        cmdline: [0; MAX_CMDLINE],
        cmdline_len: 0,
    };
    let src = raw.memory_map();
    if src.len() > MAX_MEMORY_REGIONS {
        kprintln!("warning: {} memory regions, only {} kept", src.len(), MAX_MEMORY_REGIONS);
    }
    let n = src.len().min(MAX_MEMORY_REGIONS);
    b.map[..n].copy_from_slice(&src[..n]);
    b.map_len = n;
    let cmd = raw.cmdline().as_bytes();
    let n = cmd.len().min(MAX_CMDLINE);
    b.cmdline[..n].copy_from_slice(&cmd[..n]);
    b.cmdline_len = n;
    b
}

fn log_memory_map(map: &[MemoryDescriptor]) {
    let mut usable = 0;
    for d in map {
        if d.kind == MemoryKind::Usable {
            usable += d.byte_len();
        }
    }
    kprintln!("memory map: {} regions, {} MiB usable", map.len(), usable >> 20);
    for d in map.iter().filter(|d| d.kind != MemoryKind::Usable && d.kind != MemoryKind::Reserved) {
        kprintln!("  {:#012x}-{:#012x} {:?}", d.phys_start, d.end(), d.kind);
    }
}

/// Small fixed-capacity string for status lines (usable in the panic path).
pub struct Line {
    buf: [u8; 96],
    len: usize,
}

impl Line {
    pub const fn new() -> Line {
        Line { buf: [0; 96], len: 0 }
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

impl Default for Line {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for ch in s.chars() {
            let mut tmp = [0u8; 4];
            let e = ch.encode_utf8(&mut tmp).as_bytes();
            if self.len + e.len() > self.buf.len() {
                return Err(core::fmt::Error);
            }
            self.buf[self.len..self.len + e.len()].copy_from_slice(e);
            self.len += e.len();
        }
        Ok(())
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    cpu::disable_interrupts();
    // SAFETY: we never return to whoever may hold the serial lock.
    unsafe { serial::SERIAL.force_unlock() };
    kprintln!("KERNEL PANIC: {}", info);
    let mut msg = Line::new();
    let _ = write!(msg, "{}", info.message());
    display::panic_screen(msg.as_str());
    if BOOT.get().is_some_and(|b| b.cmdline().contains("test.")) {
        qemu::exit(qemu::ExitCode::Panic);
    }
    cpu::halt_forever()
}
