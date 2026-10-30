//! x86-64 SMP bootstrap and CPU-local state. A coarse kernel entry lock
//! preserves the existing kernel lock order while user threads run in
//! parallel. NMI TLB shootdowns bypass that lock and take no other locks.
use crate::arch::{apic, cpu, gdt, idt, timer};
use crate::sync::IrqSpinLock;
use crate::{kprintln, mem, sched, syscall, BootData};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub const MAX_CPUS: usize = 16;
const GS_BASE: u32 = 0xC0000101;
pub const USER_GS_BASE: u32 = 0xC0000102;
const TRAMPOLINE: u64 = 0x8000;
const PARAMS: usize = 0xF00;

#[repr(C, align(64))]
struct CpuLocal {
    kernel_rsp: UnsafeCell<u64>, // GS:0
    user_rsp: UnsafeCell<u64>,   // GS:8
    index: AtomicU64,            // GS:16
    apic: AtomicU32,
    online: AtomicBool,
    flush: AtomicBool,
    allowed: AtomicBool,
    root: AtomicU64,
    /// Tid of the running thread, so GETTID and current_pid never take the
    /// scheduler lock (they are called hundreds of thousands of times a
    /// second by Firefox's thread primitives).
    tid: AtomicU64, // GS:40
    pid: AtomicU64, // GS:48
}
const _: () = assert!(core::mem::offset_of!(CpuLocal,kernel_rsp)==0 && core::mem::offset_of!(CpuLocal,user_rsp)==8 && core::mem::offset_of!(CpuLocal,index)==16);
// SAFETY: stack pointers are accessed only by their CPU with interrupts
// disabled; shared bookkeeping uses atomics and index never changes online.
unsafe impl Sync for CpuLocal {}
impl CpuLocal {
    const fn new() -> Self {
        Self {
            kernel_rsp: UnsafeCell::new(0),
            user_rsp: UnsafeCell::new(0),
            index: AtomicU64::new(0),
            apic: AtomicU32::new(0),
            online: AtomicBool::new(false),
            flush: AtomicBool::new(false),
            allowed: AtomicBool::new(false),
            root: AtomicU64::new(0),
            tid: AtomicU64::new(0),
            pid: AtomicU64::new(0),
        }
    }
}
static CPUS: [CpuLocal; MAX_CPUS] = [const { CpuLocal::new() }; MAX_CPUS];

/// Vector of the reschedule IPI that wakes an idle CPU whose timer is off.
pub const RESCHED_VECTOR: u8 = 0xF1;
/// Idle application processors halt with their timer stopped; this marks
/// one in that state, so whoever gives it work must send it an IPI.
static TICKLESS: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// Marks this CPU as halting without its timer.
pub fn set_tickless(on: bool) {
    TICKLESS[index()].store(on, Ordering::SeqCst);
}

/// Restarts this CPU's timer if it halted without it. Runs first in every
/// interrupt: a handler may switch to a thread, which must be preemptible.
pub fn leave_tickless() -> bool {
    let cpu = index();
    if cpu != 0 && TICKLESS[cpu].swap(false, Ordering::SeqCst) {
        crate::arch::timer::start_secondary();
        true
    } else {
        false
    }
}

/// Wakes CPU `cpu` if it halts without its timer. Called with the scheduler
/// lock held after queueing work there; see `sched::idle_without_tick`.
pub fn kick(cpu: usize) {
    if cpu != index() && cpu < MAX_CPUS && TICKLESS[cpu].load(Ordering::SeqCst) {
        // Fixed delivery, level assert (ICR bit 14), physical destination.
        let _ = apic::send_ipi(CPUS[cpu].apic.load(Ordering::Relaxed), 0x4000 | RESCHED_VECTOR as u32);
    }
}
static READY: AtomicBool = AtomicBool::new(false);
static ONLINE: AtomicU32 = AtomicU32::new(1);
// zero = free, otherwise the owning CPU's index + 1. The lock follows a
// context switch on the same CPU; it is released before entering ring 3.
static KERNEL_OWNER: AtomicU32 = AtomicU32::new(1);
static BOOT_PAT: AtomicU64 = AtomicU64::new(0);

pub fn index() -> usize {
    if !READY.load(Ordering::Relaxed) {
        return 0;
    }
    let index: u64;
    // SAFETY: every kernel entry installs the CPU GS base with SWAPGS.
    unsafe {
        asm!("mov {}, gs:[16]",out(reg) index,options(nostack,readonly,preserves_flags));
    }
    index as usize
}

/// Records which thread runs on this CPU; called on every context switch.
pub fn set_current(tid: u64, pid: u64) {
    if !READY.load(Ordering::Relaxed) {
        return;
    }
    let local = &CPUS[index()];
    local.tid.store(tid, Ordering::Relaxed);
    local.pid.store(pid, Ordering::Relaxed);
}

/// Tid of the running thread, or 0 before the scheduler has run one.
pub fn cached_tid() -> u64 {
    if !READY.load(Ordering::Relaxed) {
        return 0;
    }
    let tid: u64;
    // SAFETY: as in `index`.
    unsafe {
        asm!("mov {}, gs:[40]",out(reg) tid,options(nostack,readonly,preserves_flags));
    }
    tid
}

/// Owning process of the running thread (0 for kernel threads).
pub fn cached_pid() -> u64 {
    if !READY.load(Ordering::Relaxed) {
        return 0;
    }
    let pid: u64;
    // SAFETY: as in `index`.
    unsafe {
        asm!("mov {}, gs:[48]",out(reg) pid,options(nostack,readonly,preserves_flags));
    }
    pid
}
pub fn online() -> usize {
    ONLINE.load(Ordering::Acquire) as usize
}

unsafe fn install_local(index: usize) {
    let local = &CPUS[index];
    local.index.store(index as u64, Ordering::Relaxed);
    cpu::wrmsr(GS_BASE, local as *const CpuLocal as u64);
    cpu::wrmsr(USER_GS_BASE, 0);
    local.root.store(cpu::read_cr3(), Ordering::Release);
}

/// BSP only, after loading its GDT (loading GS clears its base).
pub unsafe fn init_boot_cpu() {
    install_local(0);
    CPUS[0].apic.store(cpu::cpuid(1, 0).1 >> 24, Ordering::Relaxed);
    CPUS[0].online.store(true, Ordering::Release);
    READY.store(true, Ordering::Release);
}

pub unsafe fn set_kernel_stack(top: u64) {
    *CPUS[index()].kernel_rsp.get() = top;
}

// TEMP kernel entry lock diagnostics.
static LOCK_ENTERS: AtomicU64 = AtomicU64::new(0);
static LOCK_WAITS: AtomicU64 = AtomicU64::new(0);
static LOCK_SPIN_CYCLES: AtomicU64 = AtomicU64::new(0);
static LOCK_MAX_SPIN_CYCLES: AtomicU64 = AtomicU64::new(0);
static HOLD_START: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static HOLD_NR: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
static HOLD_COUNT: AtomicU64 = AtomicU64::new(0);
static HOLD_CYCLES: AtomicU64 = AtomicU64::new(0);
static HOLD_MAX_CYCLES: AtomicU64 = AtomicU64::new(0);
static HOLD_SLOW: AtomicU64 = AtomicU64::new(0);
static HOLD_LOGS: AtomicU32 = AtomicU32::new(0);

/// (entries, contended entries, spin cycles, longest spin cycles)
pub fn lock_stats() -> (u64, u64, u64, u64) {
    (
        LOCK_ENTERS.load(Ordering::Relaxed),
        LOCK_WAITS.load(Ordering::Relaxed),
        LOCK_SPIN_CYCLES.load(Ordering::Relaxed),
        LOCK_MAX_SPIN_CYCLES.load(Ordering::Relaxed),
    )
}

/// (holds, hold cycles, longest hold, holds over 10 ms)
pub fn hold_stats() -> (u64, u64, u64, u64) {
    (
        HOLD_COUNT.load(Ordering::Relaxed),
        HOLD_CYCLES.load(Ordering::Relaxed),
        HOLD_MAX_CYCLES.load(Ordering::Relaxed),
        HOLD_SLOW.load(Ordering::Relaxed),
    )
}

// TEMP per-syscall counts and hold TSC cycles for the iostat line.
static NR_COUNTS: [AtomicU64; 128] = [const { AtomicU64::new(0) }; 128];
static NR_HOLD_CYCLES: [AtomicU64; 128] = [const { AtomicU64::new(0) }; 128];

pub fn nr_hold_cycles() -> [u64; 128] {
    core::array::from_fn(|i| NR_HOLD_CYCLES[i].load(Ordering::Relaxed))
}

pub fn note_syscall(nr: u64) {
    if (nr as usize) < NR_COUNTS.len() {
        NR_COUNTS[nr as usize].fetch_add(1, Ordering::Relaxed);
    }
}

pub fn nr_counts() -> [u64; 128] {
    core::array::from_fn(|i| NR_COUNTS[i].load(Ordering::Relaxed))
}

// TEMP per-process attribution of the idle pollers (CHANNEL_RECV / CLOCK).
const PID_SLOTS: usize = 24;
static PID_OF: [AtomicU64; PID_SLOTS] = [const { AtomicU64::new(0) }; PID_SLOTS];
static PID_RECV: [AtomicU64; PID_SLOTS] = [const { AtomicU64::new(0) }; PID_SLOTS];
static PID_CLOCK: [AtomicU64; PID_SLOTS] = [const { AtomicU64::new(0) }; PID_SLOTS];
static PID_STAT: [AtomicU64; PID_SLOTS] = [const { AtomicU64::new(0) }; PID_SLOTS];

pub fn note_pid_syscall(pid: u64, nr: u64) {
    if pid == 0 || (nr != 47 && nr != 5 && nr != 21 && nr != 33) {
        return;
    }
    let counter = match nr {
        47 => &PID_RECV,
        5 => &PID_CLOCK,
        _ => &PID_STAT,
    };
    for i in 0..PID_SLOTS {
        let p = PID_OF[i].load(Ordering::Relaxed);
        if p == pid {
            counter[i].fetch_add(1, Ordering::Relaxed);
            return;
        }
        if p == 0 {
            if PID_OF[i].compare_exchange(0, pid, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                counter[i].fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    }
}

/// (pid, channel_recv, clock, stat) for every seen process.
pub fn pid_counters() -> [(u64, u64, u64, u64); PID_SLOTS] {
    core::array::from_fn(|i| {
        (
            PID_OF[i].load(Ordering::Relaxed),
            PID_RECV[i].load(Ordering::Relaxed),
            PID_CLOCK[i].load(Ordering::Relaxed),
            PID_STAT[i].load(Ordering::Relaxed),
        )
    })
}

// TEMP per-thread attribution (same counters).
const TID_SLOTS: usize = 48;
static TID_OF: [AtomicU64; TID_SLOTS] = [const { AtomicU64::new(0) }; TID_SLOTS];
static TID_RECV: [AtomicU64; TID_SLOTS] = [const { AtomicU64::new(0) }; TID_SLOTS];
static TID_CLOCK: [AtomicU64; TID_SLOTS] = [const { AtomicU64::new(0) }; TID_SLOTS];
static TID_STAT: [AtomicU64; TID_SLOTS] = [const { AtomicU64::new(0) }; TID_SLOTS];

pub fn note_tid_syscall(tid: u64, nr: u64) {
    if tid == 0 || (nr != 47 && nr != 5 && nr != 21 && nr != 33) {
        return;
    }
    let counter = match nr {
        47 => &TID_RECV,
        5 => &TID_CLOCK,
        _ => &TID_STAT,
    };
    for i in 0..TID_SLOTS {
        let t = TID_OF[i].load(Ordering::Relaxed);
        if t == tid {
            counter[i].fetch_add(1, Ordering::Relaxed);
            return;
        }
        if t == 0 {
            if TID_OF[i].compare_exchange(0, tid, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                counter[i].fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    }
}

// TEMP per-thread futex/yield attribution.
static TID_FW: [AtomicU64; TID_SLOTS] = [const { AtomicU64::new(0) }; TID_SLOTS];
static TID_FK: [AtomicU64; TID_SLOTS] = [const { AtomicU64::new(0) }; TID_SLOTS];
static TID_YD: [AtomicU64; TID_SLOTS] = [const { AtomicU64::new(0) }; TID_SLOTS];

pub fn note_tid_futex(tid: u64, kind: u64) {
    if tid == 0 {
        return;
    }
    let counter = match kind {
        12 => &TID_FW,
        13 => &TID_FK,
        _ => &TID_YD,
    };
    for i in 0..TID_SLOTS {
        let t = TID_OF[i].load(Ordering::Relaxed);
        if t == tid {
            counter[i].fetch_add(1, Ordering::Relaxed);
            return;
        }
        if t == 0 && TID_OF[i].compare_exchange(0, tid, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
            counter[i].fetch_add(1, Ordering::Relaxed);
            return;
        }
    }
}

/// (tid, futex_wait, futex_wake, yield) for every seen thread.
pub fn tid_futex_counters() -> [(u64, u64, u64, u64); TID_SLOTS] {
    core::array::from_fn(|i| {
        (
            TID_OF[i].load(Ordering::Relaxed),
            TID_FW[i].load(Ordering::Relaxed),
            TID_FK[i].load(Ordering::Relaxed),
            TID_YD[i].load(Ordering::Relaxed),
        )
    })
}

/// (tid, channel_recv, clock, stat) for every seen thread.
pub fn tid_counters() -> [(u64, u64, u64, u64); TID_SLOTS] {
    core::array::from_fn(|i| {
        (
            TID_OF[i].load(Ordering::Relaxed),
            TID_RECV[i].load(Ordering::Relaxed),
            TID_CLOCK[i].load(Ordering::Relaxed),
            TID_STAT[i].load(Ordering::Relaxed),
        )
    })
}

// TEMP user-RIP sampling (timer interrupt, the browser process only).
static SAMPLE_PID: AtomicU64 = AtomicU64::new(0);
pub fn set_sample_pid(pid: u64) {
    SAMPLE_PID.store(pid, Ordering::Relaxed);
}
pub const SAMPLE_SLOTS: usize = 512;
static S_TID: [AtomicU64; SAMPLE_SLOTS] = [const { AtomicU64::new(0) }; SAMPLE_SLOTS];
static S_RIP: [AtomicU64; SAMPLE_SLOTS] = [const { AtomicU64::new(0) }; SAMPLE_SLOTS];
static S_COUNT: [AtomicU64; SAMPLE_SLOTS] = [const { AtomicU64::new(0) }; SAMPLE_SLOTS];
pub const STACK_SLOTS: usize = 256;
static K_TID: [AtomicU64; STACK_SLOTS] = [const { AtomicU64::new(0) }; STACK_SLOTS];
static K_RIP: [AtomicU64; STACK_SLOTS] = [const { AtomicU64::new(0) }; STACK_SLOTS];
static K_COUNT: [AtomicU64; STACK_SLOTS] = [const { AtomicU64::new(0) }; STACK_SLOTS];

pub fn sample_user(rip: u64, rsp: u64) {
    if cached_pid() != SAMPLE_PID.load(Ordering::Relaxed) {
        return;
    }
    let tid = cached_tid();
    // Direct-mapped by (tid, rip): the previous linear table filled up with
    // the startup thread's diverse call sites and then dropped every new
    // pair, hiding the thread that was actually burning the core.
    let i = ((tid.wrapping_mul(0x9E37_79B1) ^ (rip >> 4)) as usize) & (SAMPLE_SLOTS - 1);
    if S_TID[i].load(Ordering::Relaxed) == tid && S_RIP[i].load(Ordering::Relaxed) == rip {
        S_COUNT[i].fetch_add(1, Ordering::Relaxed);
    } else {
        S_RIP[i].store(rip, Ordering::Relaxed);
        S_TID[i].store(tid, Ordering::Relaxed);
        S_COUNT[i].store(1, Ordering::Relaxed);
    }

    // Stack attribution: the soft-float builtins are leaves, so the words at
    // user RSP are return addresses. Record the first one that belongs to
    // winrun's own code outside the builtins and the ucrt math module, which
    // is the caller that keeps invoking them.
    // Reading user pages from the timer ISR can fault on pages the thread has
    // not touched yet; that path panicked under load, so attribution stays
    // off until it can go through `paging::translate_in`.
    const SCAN_STACK: bool = false;
    let off = (rsp & 0xfff) as usize;
    let n = if SCAN_STACK { ((4096 - off) / 8).min(48) } else { 0 };
    let mut picked = 0;
    for j in 0..n {
        let addr = rsp.wrapping_add((j as u64) * 8);
        // Probed: the top of the stack can already point into a page the
        // function has not touched yet.
        let Ok(w) = crate::fixup::probe_read_u64(addr) else { break };
        if (0x4000f0..0x648000).contains(&w) {
            if picked == 0 {
                picked = w;
            }
            if !(0x586700..0x600100).contains(&w) {
                picked = w;
                break;
            }
        }
    }
    if picked != 0 {
        let i = ((tid.wrapping_mul(0x9E37_79B1) ^ (picked >> 4)) as usize) & (STACK_SLOTS - 1);
        if K_TID[i].load(Ordering::Relaxed) == tid && K_RIP[i].load(Ordering::Relaxed) == picked {
            K_COUNT[i].fetch_add(1, Ordering::Relaxed);
        } else {
            K_RIP[i].store(picked, Ordering::Relaxed);
            K_TID[i].store(tid, Ordering::Relaxed);
            K_COUNT[i].store(1, Ordering::Relaxed);
        }
    }
}

pub fn stack_samples() -> [(u64, u64, u64); STACK_SLOTS] {
    core::array::from_fn(|i| {
        (
            K_TID[i].load(Ordering::Relaxed),
            K_RIP[i].load(Ordering::Relaxed),
            K_COUNT[i].load(Ordering::Relaxed),
        )
    })
}

pub fn rip_samples() -> [(u64, u64, u64); SAMPLE_SLOTS] {
    core::array::from_fn(|i| {
        (
            S_TID[i].load(Ordering::Relaxed),
            S_RIP[i].load(Ordering::Relaxed),
            S_COUNT[i].load(Ordering::Relaxed),
        )
    })
}

// TEMP last syscall per thread, including threads blocked outside futexes.
const LAST_SYSCALL_SLOTS: usize = 256;
static LAST_SYSCALL_NR: [AtomicU64; LAST_SYSCALL_SLOTS] = [const { AtomicU64::new(0) }; LAST_SYSCALL_SLOTS];
static LAST_SYSCALL_RIP: [AtomicU64; LAST_SYSCALL_SLOTS] = [const { AtomicU64::new(0) }; LAST_SYSCALL_SLOTS];

pub fn note_last_syscall(tid: u64, rip: u64, nr: u64) {
    if tid != 0 && (tid as usize) < LAST_SYSCALL_SLOTS {
        LAST_SYSCALL_RIP[tid as usize].store(rip, Ordering::Relaxed);
        LAST_SYSCALL_NR[tid as usize].store(nr, Ordering::Relaxed);
    }
}

pub fn last_syscall(tid: u64) -> (u64, u64) {
    if tid == 0 || tid as usize >= LAST_SYSCALL_SLOTS {
        return (0, 0);
    }
    (
        LAST_SYSCALL_NR[tid as usize].load(Ordering::Relaxed),
        LAST_SYSCALL_RIP[tid as usize].load(Ordering::Relaxed),
    )
}

// TEMP syscall calling-site attribution (user return RIP for CLOCK/RECV).
pub const CALL_SLOTS: usize = 256;
static C_TID: [AtomicU64; CALL_SLOTS] = [const { AtomicU64::new(0) }; CALL_SLOTS];
static C_RIP: [AtomicU64; CALL_SLOTS] = [const { AtomicU64::new(0) }; CALL_SLOTS];
static C_NR: [AtomicU64; CALL_SLOTS] = [const { AtomicU64::new(0) }; CALL_SLOTS];
static C_COUNT: [AtomicU64; CALL_SLOTS] = [const { AtomicU64::new(0) }; CALL_SLOTS];

pub fn note_callsite(tid: u64, rip: u64, nr: u64) {
    if tid == 0 || (nr != 47 && nr != 5 && nr != 18 && nr != 19 && nr != 12 && nr != 13) {
        return;
    }
    let mut free = usize::MAX;
    for i in 0..CALL_SLOTS {
        let t = C_TID[i].load(Ordering::Relaxed);
        if t == tid && C_RIP[i].load(Ordering::Relaxed) == rip && C_NR[i].load(Ordering::Relaxed) == nr {
            C_COUNT[i].fetch_add(1, Ordering::Relaxed);
            return;
        }
        if t == 0 && free == usize::MAX {
            free = i;
        }
    }
    if free != usize::MAX && C_TID[free].compare_exchange(0, tid, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
        C_RIP[free].store(rip, Ordering::Relaxed);
        C_NR[free].store(nr, Ordering::Relaxed);
        C_COUNT[free].fetch_add(1, Ordering::Relaxed);
    }
}

/// (tid, user rip, syscall nr, count)
pub fn call_sites() -> [(u64, u64, u64, u64); CALL_SLOTS] {
    core::array::from_fn(|i| {
        (
            C_TID[i].load(Ordering::Relaxed),
            C_RIP[i].load(Ordering::Relaxed),
            C_NR[i].load(Ordering::Relaxed),
            C_COUNT[i].load(Ordering::Relaxed),
        )
    })
}

/// Records the syscall number whose kernel work currently holds the lock.
pub fn set_lock_nr(nr: u64) {
    HOLD_NR[index()].store(nr, Ordering::Relaxed);
    note_syscall(nr);
}

/// Hold-time slots past the syscall numbers, for lock holders that are not
/// system calls (see [`set_hold_kind`]).
pub const HOLD_TIMER: u64 = 120;
pub const HOLD_IRQ: u64 = 121;
pub const HOLD_EXCEPTION: u64 = 122;
pub const HOLD_RESUMED: u64 = 123;

static LOCK_FREE_CALLS: AtomicU64 = AtomicU64::new(0);

/// Counts a system call completed without the entry lock.
pub fn note_lock_free(_nr: u64) {
    LOCK_FREE_CALLS.fetch_add(1, Ordering::Relaxed);
}

pub fn lock_free_calls() -> u64 {
    LOCK_FREE_CALLS.load(Ordering::Relaxed)
}

/// Attributes the current hold of the entry lock to `kind` (a HOLD_* slot).
pub fn set_hold_kind(kind: u64) {
    HOLD_NR[index()].store(kind, Ordering::Relaxed);
}

pub fn enter_kernel() -> bool {
    // A waiter must not migrate after reading its CPU index. In particular,
    // SYSCALL may enable interrupts only after this lock has been acquired.
    cpu::disable_interrupts();
    acquire(false)
}

/// Entry from syscall context: a thread that keeps losing the lock sleeps
/// instead of burning its CPU. Contended acquisitions are a small fraction of
/// all entries, but spinning on them saturated both vCPUs (and starved the
/// host I/O thread), so a loser now parks on a kernel wait queue that the
/// releaser drains. Interrupt and scheduler contexts must keep
/// [`enter_kernel`]: they cannot block.
pub fn enter_kernel_yielding() -> bool {
    cpu::disable_interrupts();
    acquire(true)
}

/// Spin iterations before a yielding waiter blocks. Short handoffs still
/// complete inside the spin.
const SPIN_BEFORE_BLOCK: u64 = 2000;

/// Syscall-context threads parked on the entry lock (FIFO).
static BKL_WAITERS: IrqSpinLock<Vec<sched::Tid>> = IrqSpinLock::new(Vec::new());
static BKL_WAITING: AtomicBool = AtomicBool::new(false);

fn acquire(yielding: bool) -> bool {
    if KERNEL_OWNER.load(Ordering::Relaxed) == index() as u32 + 1 {
        return false;
    }
    LOCK_ENTERS.fetch_add(1, Ordering::Relaxed);
    let mut started = 0u64;
    let mut spins = 0u64;
    loop {
        // The CPU index is re-read every attempt: a waiter can be scheduled
        // on the other CPU, and claiming the lock under its old id would
        // leave an owner that CPU's `osyx_kernel_leave` never clears.
        let me = index() as u32 + 1;
        if KERNEL_OWNER.compare_exchange_weak(0, me, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            break;
        }
        if spins == 0 {
            started = crate::arch::timer::tsc();
        }
        spins += 1;
        if yielding && spins.is_multiple_of(SPIN_BEFORE_BLOCK) {
            wait_for_bkl();
        }
        core::hint::spin_loop();
    }
    if spins != 0 {
        let spent = crate::arch::timer::tsc().wrapping_sub(started);
        LOCK_WAITS.fetch_add(1, Ordering::Relaxed);
        LOCK_SPIN_CYCLES.fetch_add(spent, Ordering::Relaxed);
        LOCK_MAX_SPIN_CYCLES.fetch_max(spent, Ordering::Relaxed);
    }
    HOLD_START[index()].store(crate::arch::timer::tsc(), Ordering::Relaxed);
    true
}

/// Parks the current thread until the entry lock is released. A releaser
/// clears the owner before draining [`BKL_WAITERS`], so checking the owner
/// under the waiter-list lock makes a missed wake-up impossible: either the
/// lock is free (retry the CAS) or the releaser will find this thread.
fn wait_for_bkl() {
    let tid = sched::current_tid();
    {
        let mut w = BKL_WAITERS.lock();
        if KERNEL_OWNER.load(Ordering::Acquire) == 0 {
            return;
        }
        w.push(tid);
        BKL_WAITING.store(true, Ordering::Relaxed);
    }
    sched::mark_current_blocked();
    sched::schedule();
}

/// Wakes the next thread parked on the entry lock. Must not be called while
/// the scheduler lock is held (see [`release_for_switch`]).
pub fn wake_bkl_waiters() {
    if !BKL_WAITING.load(Ordering::Relaxed) {
        return;
    }
    let mut w = BKL_WAITERS.lock();
    let next = if w.is_empty() { None } else { Some(w.remove(0)) };
    if w.is_empty() {
        BKL_WAITING.store(false, Ordering::Relaxed);
    }
    drop(w);
    if let Some(tid) = next {
        sched::wake(tid);
    }
}

/// True while this CPU holds the kernel entry lock.
pub fn owner_is_me() -> bool {
    KERNEL_OWNER.load(Ordering::Relaxed) == index() as u32 + 1
}

/// Releases the kernel entry lock if this CPU owns it. A thread that was
/// switched in without holding it (a fresh user thread, an idle CPU) must
/// not clear another CPU's ownership.
#[no_mangle]
pub extern "C" fn osyx_kernel_leave() {
    if release_lock() {
        wake_bkl_waiters();
    }
}

/// Release performed by the scheduler while it still holds its own lock:
/// waking a waiter there would take that lock again, so the incoming
/// thread's `after_switch` does it once the scheduler lock is dropped.
pub fn release_for_switch() {
    release_lock();
}

/// True when no CPU holds the entry lock.
pub fn bkl_is_free() -> bool {
    KERNEL_OWNER.load(Ordering::Relaxed) == 0
}

fn release_lock() -> bool {
    cpu::disable_interrupts();
    let me = index() as u32 + 1;
    let cpu = index();
    let released = KERNEL_OWNER.compare_exchange(me, 0, Ordering::Release, Ordering::Relaxed).is_ok();
    if released {
        let started = HOLD_START[cpu].swap(0, Ordering::Relaxed);
        if started != 0 {
            let held = crate::arch::timer::tsc().wrapping_sub(started);
            HOLD_COUNT.fetch_add(1, Ordering::Relaxed);
            HOLD_CYCLES.fetch_add(held, Ordering::Relaxed);
            let nr = (HOLD_NR[cpu].load(Ordering::Relaxed) & 0x7f) as usize;
            NR_HOLD_CYCLES[nr].fetch_add(held, Ordering::Relaxed);
            HOLD_MAX_CYCLES.fetch_max(held, Ordering::Relaxed);
            let khz = crate::arch::timer::tsc_khz().max(1);
            if held / khz >= 10 {
                HOLD_SLOW.fetch_add(1, Ordering::Relaxed);
                if HOLD_LOGS.fetch_add(1, Ordering::Relaxed) < 60 {
                    crate::kprintln!(
                        "lock: held {} ms nr={:#x} cpu={cpu}",
                        held / khz,
                        HOLD_NR[cpu].load(Ordering::Relaxed)
                    );
                }
            }
        }
    }
    released
}

pub struct KernelEntry(bool);
impl KernelEntry {
    pub fn new() -> Self {
        Self(enter_kernel())
    }

    /// Syscall entry: a thread that loses the lock sleeps on the entry wait
    /// queue instead of spinning until the holder (possibly the other vCPU)
    /// finishes.
    pub fn new_yielding() -> Self {
        Self(enter_kernel_yielding())
    }

    /// True if this entry took the lock (it was not already held here).
    pub fn acquired(&self) -> bool {
        self.0
    }
}
impl Drop for KernelEntry {
    fn drop(&mut self) {
        if self.0 {
            osyx_kernel_leave();
        }
    }
}

/// NMI path: do not use GS (an NMI may arrive in a SWAPGS transition),
/// the scheduler, allocator, or any lock. A reload flushes this CPU's TLB.
pub fn handle_tlb_nmi() -> bool {
    if online() < 2 {
        return false;
    }
    let id = apic::local_id();
    for local in &CPUS {
        if local.online.load(Ordering::Acquire)
            && local.apic.load(Ordering::Relaxed) == id
            && local.flush.load(Ordering::Acquire)
        {
            unsafe {
                cpu::write_cr3(cpu::read_cr3());
            }
            local.flush.store(false, Ordering::Release);
            return true;
        }
    }
    false
}

/// A mapping must be invalidated before its former frame can be reused.
/// NMIs remain deliverable even while a remote CPU waits for the kernel
/// entry lock with ordinary interrupts masked.
pub fn set_root(root: u64) {
    CPUS[index()].root.store(root, Ordering::Release);
}

pub fn flush_remote(root: u64, kernel_mapping: bool) {
    if online() < 2 {
        return;
    }
    let were_enabled = cpu::interrupts_enabled();
    cpu::disable_interrupts();
    // The page table stores before this call must be visible before the
    // roots are read (x86 may order a later load before an earlier store);
    // pairs with `set_root` preceding the CR3 load in the scheduler.
    core::sync::atomic::fence(Ordering::SeqCst);
    let me = index();
    for (i, local) in CPUS.iter().enumerate() {
        if i != me
            && local.online.load(Ordering::Acquire)
            && (kernel_mapping || local.root.load(Ordering::Acquire) == root)
        {
            local.flush.store(true, Ordering::Release);
            assert!(apic::send_ipi(local.apic.load(Ordering::Relaxed), 0x400), "TLB NMI delivery failed");
        }
    }
    for (i, local) in CPUS.iter().enumerate() {
        if i != me {
            let deadline = timer::Deadline::after_ms(1000);
            while local.flush.load(Ordering::Acquire) {
                assert!(!deadline.expired(), "TLB shootdown timed out on CPU {i}");
                core::hint::spin_loop();
            }
        }
    }
    if were_enabled { cpu::enable_interrupts(); }
}

global_asm!(
    r#"
    .section .rodata.smp_trampoline,"a"
    .balign 16
    .global osyx_ap_trampoline_start
    .global osyx_ap_trampoline_end
osyx_ap_trampoline_start:
    .code16
    cli
    cld
    xor ax,ax
    mov ds,ax
    mov es,ax
    mov ss,ax
    // The pseudo-descriptor has a fixed offset in the copied page. LLVM's
    // x86 parser cannot encode a difference of labels as a memory operand.
    lgdt [0x8ef0]
    mov eax,cr0
    or eax,1
    mov cr0,eax
    .byte 0x66,0xea
    .long 0x8000 + (.Lap_protected - osyx_ap_trampoline_start)
    .word 0x08
.Lap_protected:
    .code32
    mov ax,0x10
    mov ds,ax
    mov es,ax
    mov ss,ax
    mov esp,0x9ff0
    mov eax,cr4
    or eax,0x20
    mov cr4,eax
    mov eax,dword ptr [0x8f00]
    mov cr3,eax
    mov ecx,0xc0000080
    rdmsr
    or eax,dword ptr [0x8f20]
    wrmsr
    mov eax,cr0
    // INIT leaves caching disabled. Enable it before sharing cached RAM
    // and MMIO page tables with the boot processor.
    and eax,0x9fffffff
    or eax,0x80010000
    mov cr0,eax
    .byte 0xea
    .long 0x8000 + (.Lap_long - osyx_ap_trampoline_start)
    .word 0x18
.Lap_long:
    .code64
    mov rsp,qword ptr [0x8f08]
    sub rsp,8
    mov qword ptr [rsp],0
    xor ebp,ebp
    mov rdi,qword ptr [0x8f18]
    mov rax,qword ptr [0x8f10]
    jmp rax
    .org osyx_ap_trampoline_start + 0xed0
.Lap_gdt:
    .quad 0
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00af9a000000ffff
.Lap_gdt_pointer:
    .word 31
    .long 0x8000 + (.Lap_gdt - osyx_ap_trampoline_start)
osyx_ap_trampoline_end:
    .code64
"#
);
extern "C" {
    static osyx_ap_trampoline_start: u8;
    static osyx_ap_trampoline_end: u8;
}

fn processor_ids() -> alloc::vec::Vec<u32> {
    let mut ids = alloc::vec::Vec::new();
    let Some((pa, len)) = crate::acpi::find(b"APIC") else {
        return ids;
    };
    if len < 44 {
        return ids;
    }
    let data = unsafe { core::slice::from_raw_parts(mem::phys_to_virt(pa) as *const u8, len) };
    let mut at = 44;
    while at + 2 <= len {
        let size = data[at + 1] as usize;
        if size < 2 || at + size > len {
            break;
        }
        if data[at] == 0 && size >= 8 {
            let flags = u32::from_le_bytes(data[at + 4..at + 8].try_into().unwrap());
            if flags & 1 != 0 {
                ids.push(data[at + 3] as u32);
            }
        } else if data[at] == 9 && size >= 16 {
            let flags = u32::from_le_bytes(data[at + 8..at + 12].try_into().unwrap());
            if flags & 1 != 0 {
                ids.push(u32::from_le_bytes(data[at + 4..at + 8].try_into().unwrap()));
            }
        }
        at += size;
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// The APs need one temporary identity-mapped low page while enabling
/// paging. Normal process roots never inherit this bootstrap mapping.
fn bootstrap_root() -> Option<(u64, u64, u64)> {
    let root = mem::alloc_frame()?;
    let pdpt = mem::alloc_frame()?;
    let pd = mem::alloc_frame()?;
    if root > u32::MAX as u64 || pdpt > u32::MAX as u64 || pd > u32::MAX as u64 {
        return None;
    }
    unsafe {
        let dest = mem::phys_to_virt(root) as *mut u64;
        core::ptr::copy_nonoverlapping(mem::phys_to_virt(mem::paging::kernel_root()) as *const u64, dest, 512);
        *dest = pdpt | 3;
        *(mem::phys_to_virt(pdpt) as *mut u64) = pd | 3;
        *(mem::phys_to_virt(pd) as *mut u64) = 0x83; // first 2 MiB, supervisor RW
    }
    Some((root, pdpt, pd))
}

pub fn start(boot: &BootData) {
    if boot.option_value("smp") == Some("off") || !apic::available() || !timer::secondary_available() {
        kprintln!("smp: 1 CPU online (secondary CPUs disabled or no APIC timer)");
        return;
    }
    let ids = processor_ids();
    let bsp = apic::local_id();
    CPUS[0].apic.store(bsp, Ordering::Relaxed);
    if ids.len() < 2 {
        kprintln!("smp: 1 CPU online");
        return;
    }
    if !boot.memory_map().iter().any(|region| region.phys_start<=TRAMPOLINE && region.end()>=0xa000 && matches!(region.kind,osyx_bootinfo::MemoryKind::Usable|osyx_bootinfo::MemoryKind::BootloaderReclaimable)) {
        kprintln!("smp: low bootstrap pages are not usable RAM; keeping one CPU");
        return;
    }
    let Some((root, pdpt, pd)) = bootstrap_root() else {
        kprintln!("smp: cannot allocate AP bootstrap page tables");
        return;
    };
    BOOT_PAT.store(unsafe { cpu::rdmsr(0x277) }, Ordering::Relaxed);
    let len = (&raw const osyx_ap_trampoline_end) as usize - (&raw const osyx_ap_trampoline_start) as usize;
    assert!(len < PARAMS);
    unsafe {
        core::ptr::copy_nonoverlapping(
            &raw const osyx_ap_trampoline_start,
            mem::phys_to_virt(TRAMPOLINE) as *mut u8,
            len,
        );
    }
    let mut count = 1;
    for id in ids.into_iter().filter(|id| *id != bsp).take(MAX_CPUS - 1) {
        if !apic::x2apic() && id > 255 {
            continue;
        }
        let stack = Box::leak(alloc::vec![0u128;64*1024/16].into_boxed_slice());
        let top = stack.as_mut_ptr() as u64 + 64 * 1024;
        let params = (mem::phys_to_virt(TRAMPOLINE) + PARAMS as u64) as *mut u64;
        unsafe {
            params.write_volatile(root);
            params.add(1).write_volatile(top);
            params.add(2).write_volatile(ap_main as *const () as u64);
            params.add(3).write_volatile(count as u64);
            params.add(4).write_volatile((1 << 8) | if mem::paging::nx_enabled() { 1 << 11 } else { 0 });
        }
        CPUS[count].apic.store(id, Ordering::Relaxed);
        if !apic::send_ipi(id, 0xc500) {
            break;
        } // INIT assert, level
        timer::spin_ms(10);
        let _ = apic::send_ipi(id, 0x8500); // INIT deassert
        timer::spin_ms(1);
        let _ = apic::send_ipi(id, 0x608); // SIPI vector 8 -> 0x8000
        timer::spin_ms(1);
        if !CPUS[count].online.load(Ordering::Acquire) {
            let _ = apic::send_ipi(id, 0x608);
        }
        let deadline = timer::Deadline::after_ms(1000);
        while !CPUS[count].online.load(Ordering::Acquire) && !deadline.expired() {
            core::hint::spin_loop();
        }
        if !CPUS[count].online.load(Ordering::Acquire) {
            // Keep the bootstrap tables in case a late AP still reaches
            // them. Its slot and stack are never reused for another CPU.
            kprintln!("smp: APIC {id} startup timed out; bootstrap memory retained");
            return;
        }
        kprintln!("smp: CPU {count} (APIC {id}) online");
        count += 1;
        ONLINE.store(count as u32, Ordering::Release);
        CPUS[count - 1].allowed.store(true, Ordering::Release);
    }
    // Every acknowledged AP has already switched to the shared kernel root.
    let _ = mem::free_frame(pd);
    let _ = mem::free_frame(pdpt);
    let _ = mem::free_frame(root);
    kprintln!("smp: {} CPUs online", online());
}

extern "C" fn ap_main(index: usize) -> ! {
    unsafe {
        cpu::enable_sse(index);
        gdt::init_cpu(index);
        install_local(index);
        idt::load();
        syscall::init();
        cpu::wrmsr(0x277, BOOT_PAT.load(Ordering::Relaxed));
        cpu::write_cr3(mem::paging::kernel_root());
        set_root(mem::paging::kernel_root());
    }
    apic::init_secondary();
    CPUS[index].online.store(true, Ordering::Release);
    let deadline = timer::Deadline::after_ms(1000);
    while !CPUS[index].allowed.load(Ordering::Acquire) {
        if deadline.expired() {
            cpu::halt_forever();
        }
        core::hint::spin_loop();
    }
    enter_kernel();
    let rsp: u64;
    unsafe {
        asm!("mov {},rsp",out(reg) rsp,options(nomem,nostack,preserves_flags));
    }
    sched::init_secondary(rsp);
    timer::start_secondary();
    cpu::enable_interrupts();
    sched::secondary_idle()
}
