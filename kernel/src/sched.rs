//! Threads and the preemptive round-robin scheduler (SMP, one current/idle thread per CPU).
//!
//! * Every thread has its own 64 KiB kernel stack (the boot thread keeps the
//!   loader's stack), a saved stack pointer and a 64-byte aligned XSAVE area
//!   (832 bytes: x87, SSE and AVX YMM upper halves; FXSAVE fallback).
//! * [`schedule`] picks the next ready thread and calls `osyx_switch`, which
//!   saves the callee-saved registers and RFLAGS on the old stack and resumes
//!   the new one. Caller-saved registers are already saved by whoever called
//!   `schedule` (the compiler, or the interrupt stub when preempting).
//! * The timer interrupt calls [`tick`]: it wakes sleepers and, when the
//!   running thread has used its time slice and another thread is ready,
//!   switches from inside the interrupt handler. The interrupted thread later
//!   resumes inside that handler and returns with `iretq`.
//! * x87/SSE/AVX state is switched eagerly (`xsave`/`xrstor`, or
//!   `fxsave`/`fxrstor` when XSAVE is unavailable, on every switch).
//! * CR3, TSS.RSP0 and the SYSCALL kernel stack follow the incoming thread.
//! * A thread that exits cannot free the stack it runs on; the next thread
//!   frees it right after the switch ([`after_switch`]).
//!
//! Every lock in the kernel disables interrupts while held, so a thread can
//! never be preempted while holding one. `SCHED` is the innermost lock any
//! scheduler path takes except HEAP (thread creation/reaping allocate).

use crate::arch::{cpu, gdt};
use crate::mem::paging;
use crate::sync::IrqSpinLock;
use crate::{interrupts, syscall};
use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BinaryHeap, VecDeque};
use core::cmp::Reverse;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::arch::global_asm;

pub type Tid = u64;

/// Timer ticks (1 ms each) a thread may run before it can be preempted.
pub const TIME_SLICE_TICKS: u32 = 10;
const KERNEL_STACK_SIZE: usize = 64 * 1024;
// TEMP stack-overflow detector: the bottom words of every kernel stack keep a
// pattern no frame reaches; an overflow reaches them first.
const STACK_CANARY: u64 = 0xC0DE_5A5A_1234_5678;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Running,
    Blocked,
    Dead,
}

/// XSAVE image (x87 + SSE + AVX when enabled), 64-byte aligned.
#[repr(C, align(64))]
pub struct FpuState([u8; cpu::FPU_AREA_SIZE]);

impl FpuState {
    /// The state after `fninit` + default MXCSR: all exceptions masked,
    /// round to nearest. XSTATE_BV marks x87 and SSE as initialized; AVX
    /// upper halves are left in their initial (zero) state.
    fn initial() -> Box<FpuState> {
        let mut s = Box::new(FpuState([0; cpu::FPU_AREA_SIZE]));
        s.0[0..2].copy_from_slice(&0x037Fu16.to_le_bytes()); // FCW
        s.0[24..28].copy_from_slice(&0x1F80u32.to_le_bytes()); // MXCSR
        s.0[512..520].copy_from_slice(&0x3u64.to_le_bytes()); // XSTATE_BV
        s
    }
}

pub struct Thread {
    pub tid: Tid,
    pub name: String,
    /// Owning process, 0 for kernel threads.
    pub pid: u64,
    state: State,
    rsp: u64,
    /// Page table root active while this thread runs.
    root: u64,
    /// Empty for the boot thread, which runs on the loader-provided stack.
    _kstack: Vec<u128>,
    kstack_top: u64,
    fpu: Box<FpuState>,
    wake_at: Option<u64>,
    joiners: Vec<Tid>,
    slice: u32,
    /// FS base (user TLS thread pointer), switched with the thread.
    fs_base: u64,
    /// GS base (the Windows runtime's TEB pointer), switched likewise.
    gs_base: u64,
    /// Base of the 32-bit FS data descriptor: where compatibility-mode code
    /// finds its TEB (`fs:[0x18]`). Installed in this CPU's GDT with the
    /// thread; 0 for threads that never run 32-bit code.
    fs32_base: u64,
    /// Set when the owning process is exiting: the thread ends at its next
    /// safe point (return to user mode or an interrupted blocking call).
    kill_pending: bool,
    /// A wake-up arrived while the thread was still running, i.e. between its
    /// condition check and marking itself blocked. The next block is skipped.
    wake_pending: bool,
    /// The thread is on its way off its CPU: it has marked itself blocked or
    /// dead, or was preempted, but the switch is not complete. It must not be
    /// queued (woken, timed out) until `after_switch`; otherwise another CPU
    /// could run it while it still runs here.
    leaving: bool,
    /// This thread's kernel context held the kernel entry lock when it was
    /// switched out. The CPU gives the lock up at every switch and takes it
    /// back here before the thread continues, so a sleeping thread never
    /// keeps other CPUs out of the kernel.
    bkl: bool,
    cpu_ticks: u64,
    affinity: u64,
    /// The CPU this thread last ran on: it is queued there again while its
    /// caches are warm, unless another allowed CPU is idle.
    last_cpu: usize,
    /// Scheduling priority (`osyx_abi::priority`, IDLE 0 .. REALTIME 6).
    priority: u8,
    /// Temporary levels on top of `priority` after a wait ended by an event
    /// (input, IPC, a released lock); one level drops per used time slice.
    boost: u8,
    /// Priority lent by threads waiting on a lock this thread holds
    /// (priority inheritance, see `futex`); 0 when none waits.
    inherited: u8,
    /// Tick at which it was last queued, for aging (see `score`).
    queued_at: u64,
    /// TEMP deepest kernel-stack pointer seen at a switch-out.
    low_rsp: u64,
    /// TEMP one-shot flag for the overflow report.
    stack_warned: bool,
    /// SuspendThread count: while non-zero the thread stops at its next
    /// return to user mode (see [`park_if_suspended`]).
    suspend: u32,
    /// The thread is blocked in [`park_if_suspended`].
    parked: bool,
}

const IA32_FS_BASE: u32 = 0xC000_0100;
const IA32_GS_BASE: u32 = crate::smp::USER_GS_BASE;

struct Scheduler {
    threads: BTreeMap<Tid, Box<Thread>>,
    /// Ready threads, one queue per CPU. A CPU whose queue is empty takes
    /// the oldest runnable thread from the longest other queue.
    ready: [VecDeque<Tid>; crate::smp::MAX_CPUS],
    /// (deadline tick, thread) of timed waits, earliest first. Entries whose
    /// thread was woken earlier stay until their deadline and are skipped.
    sleepers: BinaryHeap<Reverse<(u64, Tid)>>,
    current: [Tid; crate::smp::MAX_CPUS],
    idle: [Tid; crate::smp::MAX_CPUS],
    next_tid: Tid,
    reap: [Option<Tid>; crate::smp::MAX_CPUS],
    /// A thread switched out on that CPU, published to the ready queue by the
    /// next thread only after the switch completes. Publishing it earlier
    /// would let another CPU pick and run it while it is still running here.
    publish: [Option<Tid>; crate::smp::MAX_CPUS],
    switches: u64,
    ticks: u64,
    idle_ticks: u64,
    last_wake_tick: u64,
}

static SCHED: IrqSpinLock<Option<Scheduler>> = IrqSpinLock::new(None);

global_asm!(
    r#"
    .section .text
    // void osyx_switch(u64 *save_rsp, u64 new_rsp)
    .global osyx_switch
osyx_switch:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    pushfq
    mov [rdi], rsp
    mov rsp, rsi
    popfq
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

    // First "return" of a new thread: r12 = entry, r13/r14 = arguments.
    .global osyx_thread_trampoline
osyx_thread_trampoline:
    mov rdi, r12
    mov rsi, r13
    mov rdx, r14
    call osyx_thread_start
    ud2
    "#
);

extern "C" {
    fn osyx_switch(save_rsp: *mut u64, new_rsp: u64);
    fn osyx_thread_trampoline();
}

/// Thread entry point: `entry(a, b)`; returning ends the thread.
pub type Entry = fn(u64, u64);

#[no_mangle]
extern "C" fn osyx_thread_start(entry: u64, a: u64, b: u64) -> ! {
    after_switch();
    cpu::enable_interrupts();
    // SAFETY: `entry` was produced from an `Entry` in `spawn`.
    let f: Entry = unsafe { core::mem::transmute::<u64, Entry>(entry) };
    f(a, b);
    exit_current()
}

fn idle_loop(_: u64, _: u64) { secondary_idle(); }

pub fn secondary_idle() -> ! {
    loop {
        schedule();
        crate::smp::osyx_kernel_leave();
        if crate::smp::index() != 0 && crate::arch::timer::secondary_available() {
            idle_without_tick();
        } else {
            cpu::enable_and_halt();
        }
        crate::smp::enter_kernel();
    }
}

/// Halts an idle application processor with its timer stopped, so it takes
/// no interrupts until work arrives (a reschedule IPI from `enqueue`) or a
/// device or shootdown interrupt does. CPU 0 keeps ticking: it advances the
/// clock and wakes timed sleepers.
fn idle_without_tick() {
    cpu::disable_interrupts();
    crate::smp::set_tickless(true);
    // Checked after publishing the flag, under the scheduler lock that
    // `enqueue` holds while it reads the flag: work queued before this check
    // is seen here, work queued after it sends the IPI.
    let work = SCHED.lock().as_ref().is_some_and(Scheduler::any_ready);
    if work {
        crate::smp::set_tickless(false);
        cpu::enable_interrupts();
        return;
    }
    let since = interrupts::ticks();
    crate::arch::apic::timer_stop();
    cpu::enable_and_halt();
    cpu::disable_interrupts();
    // Usually done already by the interrupt that ended the halt.
    crate::smp::leave_tickless();
    // Count the halted ticks as idle time, as the stopped timer would have.
    let slept = interrupts::ticks().saturating_sub(since);
    if let Some(s) = SCHED.lock().as_mut() {
        s.ticks = s.ticks.saturating_add(slept);
        s.idle_ticks = s.idle_ticks.saturating_add(slept);
    }
    cpu::enable_interrupts();
}

#[allow(clippy::too_many_arguments)]
fn new_thread(tid: Tid, name: &str, pid: u64, root: u64, entry: Entry, a: u64, b: u64, fs_base: u64) -> Box<Thread> {
    let mut stack = alloc::vec![0u128; KERNEL_STACK_SIZE / 16];
    stack[0] = STACK_CANARY as u128;
    stack[1] = STACK_CANARY as u128;
    let top = stack.as_mut_ptr() as u64 + KERNEL_STACK_SIZE as u64;
    // Frame consumed by osyx_switch: rflags, r15, r14, r13, r12, rbx, rbp, ret.
    let frame: [u64; 8] = [0x2, 0, b, a, entry as *const () as u64, 0, 0, osyx_thread_trampoline as *const () as u64];
    let rsp = top - 64;
    // SAFETY: the frame lies inside the freshly allocated stack.
    unsafe { core::ptr::copy_nonoverlapping(frame.as_ptr(), rsp as *mut u64, 8) };
    Box::new(Thread {
        tid,
        name: name.to_string(),
        pid,
        state: State::Ready,
        rsp,
        root,
        _kstack: stack,
        kstack_top: top,
        fpu: FpuState::initial(),
        wake_at: None,
        joiners: Vec::new(),
        slice: TIME_SLICE_TICKS,
        fs_base,
        gs_base: 0,
        fs32_base: 0,
        kill_pending: false,
        wake_pending: false,
        leaving: false,
        bkl: false,
        cpu_ticks: 0,
        affinity: u64::MAX,
        last_cpu: crate::smp::index(),
        priority: NORMAL,
        boost: 0,
        inherited: 0,
        queued_at: 0,
        low_rsp: top,
        stack_warned: false,
        suspend: 0,
        parked: false,
    })
}

/// Turns the boot flow into thread 1 ("kmain") and creates the idle thread.
pub fn init() {
    let root = paging::kernel_root();
    let boot = Box::new(Thread {
        tid: 1,
        name: "kmain".to_string(),
        pid: 0,
        state: State::Running,
        rsp: 0,
        root,
        _kstack: Vec::new(),
        kstack_top: 0,
        fpu: FpuState::initial(),
        wake_at: None,
        joiners: Vec::new(),
        slice: TIME_SLICE_TICKS,
        fs_base: 0,
        gs_base: 0,
        fs32_base: 0,
        kill_pending: false,
        wake_pending: false,
        leaving: false,
        bkl: false,
        cpu_ticks: 0,
        affinity: u64::MAX,
        last_cpu: 0,
        priority: NORMAL,
        boost: 0,
        inherited: 0,
        queued_at: 0,
        low_rsp: 0,
        stack_warned: false,
        suspend: 0,
        parked: false,
    });
    let idle = new_thread(2, "idle", 0, root, idle_loop, 0, 0, 0);
    let mut threads = BTreeMap::new();
    threads.insert(1, boot);
    threads.insert(2, idle);
    *SCHED.lock() = Some(Scheduler {
        threads,
        ready: core::array::from_fn(|_| VecDeque::with_capacity(64)),
        sleepers: BinaryHeap::new(),
        current: { let mut a=[0;crate::smp::MAX_CPUS]; a[0]=1; a },
        idle: { let mut a=[0;crate::smp::MAX_CPUS]; a[0]=2; a },
        next_tid: 3,
        reap: [None;crate::smp::MAX_CPUS],
        publish: [None;crate::smp::MAX_CPUS],
        switches: 0,
        ticks: 0,
        idle_ticks: 0,
        last_wake_tick: u64::MAX,
    });
    crate::smp::set_current(1, 0);
}

/// Adopts an AP's bootstrap stack as that CPU's permanent idle thread.
pub fn init_secondary(top: u64) {
    let index=crate::smp::index();
    let mut guard=SCHED.lock();
    let s=guard.as_mut().expect("scheduler initialized");
    let tid=s.next_tid; s.next_tid+=1;
    let t=Box::new(Thread {
        tid,name:alloc::format!("idle/{index}"),pid:0,state:State::Running,rsp:0,
        root:paging::kernel_root(),_kstack:Vec::new(),kstack_top:top,
        fpu:FpuState::initial(),wake_at:None,joiners:Vec::new(),slice:TIME_SLICE_TICKS,
        fs_base:0,gs_base:0,fs32_base:0,kill_pending:false,wake_pending:false,leaving:false,bkl:false,cpu_ticks:0,affinity:u64::MAX,last_cpu:index,priority:NORMAL,boost:0,inherited:0,queued_at:0,low_rsp:top,stack_warned:false,suspend:0,parked:false,
    });
    s.threads.insert(tid,t);s.current[index]=tid;s.idle[index]=tid;
    crate::smp::set_current(tid, 0);
    unsafe { gdt::set_kernel_stack(top);syscall::set_kernel_stack(top); }
}

/// Creates a ready thread running `entry(a, b)` with page table `root` and
/// FS base `fs_base`. A thread of the caller's own process starts with the
/// caller's priority.
#[allow(clippy::too_many_arguments)]
pub fn spawn(name: &str, pid: u64, root: u64, entry: Entry, a: u64, b: u64, fs_base: u64) -> Tid {
    let mut g = SCHED.lock();
    let s = g.as_mut().expect("scheduler not initialised");
    let tid = s.next_tid;
    s.next_tid += 1;
    let mut t = new_thread(tid, name, pid, root, entry, a, b, fs_base);
    if let Some(parent) = s.threads.get(&s.current[crate::smp::index()]) {
        if parent.pid == pid && pid != 0 {
            t.priority = parent.priority;
        }
    }
    s.threads.insert(tid, t);
    s.enqueue(tid);
    tid
}

/// Spawns a kernel thread (kernel page tables, no process).
pub fn spawn_kernel(name: &str, entry: Entry, a: u64, b: u64) -> Tid {
    spawn(name, 0, paging::kernel_root(), entry, a, b, 0)
}

type SwitchPlan = (*mut u64, u64, *mut FpuState, *const FpuState);

/// `osyx_abi::priority::NORMAL`.
const NORMAL: u8 = 3;
const MAX_PRIORITY: u8 = 6;
/// A queued thread gains one priority level per this many ticks it waits,
/// so a busy high-priority thread cannot starve the others.
const AGING_TICKS: u64 = 20;

/// A boost never lifts a thread above HIGH; REALTIME stays reserved for
/// threads that asked for it.
const BOOST_CEILING: u8 = 5;
/// Levels a thread gains when an event ends its wait.
pub const WAKE_BOOST: u8 = 1;
/// Levels for a thread woken by user input (keyboard, mouse).
pub const INPUT_BOOST: u8 = 2;

/// The priority the scheduler uses: the thread's own, raised by a boost (up
/// to `BOOST_CEILING`) and by priority lent to it by waiters.
fn effective(t: &Thread) -> u8 {
    let boosted = (t.priority + t.boost).min(BOOST_CEILING.max(t.priority));
    boosted.max(t.inherited)
}

/// Effective priority of a queued thread: its own plus its waiting time.
fn score(t: &Thread, now: u64) -> u64 {
    let aged = now.saturating_sub(t.queued_at) / AGING_TICKS;
    effective(t) as u64 + aged.min(MAX_PRIORITY as u64)
}

impl Scheduler {
    /// Queues ready thread `tid`: on the CPU it last ran on if that CPU is
    /// idle, else on another idle CPU it may run on, else on its last CPU.
    /// A thread of higher priority than the one running there ends that
    /// one's time slice, so it runs at that CPU's next tick at the latest.
    fn enqueue(&mut self, tid: Tid) {
        let online = crate::smp::online().clamp(1, crate::smp::MAX_CPUS);
        let now = interrupts::ticks();
        let (affinity, last, priority) = match self.threads.get_mut(&tid) {
            Some(t) => {
                t.queued_at = now;
                (t.affinity, t.last_cpu, effective(t))
            }
            None => (u64::MAX, 0, NORMAL),
        };
        let allowed = |c: usize| c < online && affinity & (1 << c) != 0;
        let idle_now = |c: usize| self.idle[c] != 0 && self.current[c] == self.idle[c] && self.ready[c].is_empty();
        let cpu = if allowed(last) && idle_now(last) {
            last
        } else if let Some(c) = (0..online).find(|&c| allowed(c) && idle_now(c)) {
            c
        } else if allowed(last) {
            last
        } else {
            (0..online).find(|&c| allowed(c)).unwrap_or(0)
        };
        self.ready[cpu].push_back(tid);
        let running = self.current[cpu];
        if running != self.idle[cpu] {
            if let Some(r) = self.threads.get_mut(&running) {
                if effective(r) < priority {
                    r.slice = 0;
                }
            }
        }
        crate::smp::kick(cpu);
    }

    /// Position and score of the best thread CPU `me` may take from queue
    /// `q` (highest score; the oldest among equals).
    fn best_in(&self, q: usize, me: usize, now: u64) -> Option<(usize, u64)> {
        let mut best: Option<(usize, u64)> = None;
        for (i, n) in self.ready[q].iter().enumerate() {
            if let Some(t) = self.threads.get(n).filter(|t| t.state == State::Ready && t.affinity & (1 << me) != 0) {
                let sc = score(t, now);
                if best.is_none_or(|(_, b)| sc > b) {
                    best = Some((i, sc));
                }
            }
        }
        best
    }

    /// The next thread for CPU `me`: the best of its own queue, or else the
    /// best it may run from the longest other queue. Only a thread scoring
    /// at least `at_least` is taken.
    fn take_ready(&mut self, me: usize, at_least: u64) -> Option<Tid> {
        // Drop entries that are no longer runnable; move threads whose
        // affinity changed after they were queued here.
        let mut moved = Vec::new();
        {
            let Scheduler { ready, threads, .. } = self;
            ready[me].retain(|n| match threads.get(n) {
                Some(t) if t.state == State::Ready && t.affinity & (1 << me) != 0 => true,
                Some(t) if t.state == State::Ready => {
                    moved.push(*n);
                    false
                }
                _ => false,
            });
        }
        for n in moved {
            self.enqueue(n);
        }
        let now = interrupts::ticks();
        if let Some((pos, sc)) = self.best_in(me, me, now) {
            return if sc >= at_least { self.ready[me].remove(pos) } else { None };
        }
        let online = crate::smp::online().clamp(1, crate::smp::MAX_CPUS);
        let mut victim: Option<(usize, usize, usize)> = None; // (queue length, cpu, position)
        for c in (0..online).filter(|&c| c != me) {
            let len = self.ready[c].len();
            if len <= victim.map_or(0, |v| v.0) {
                continue;
            }
            if let Some((pos, sc)) = self.best_in(c, me, now) {
                if sc >= at_least {
                    victim = Some((len, c, pos));
                }
            }
        }
        let (_, c, pos) = victim?;
        self.ready[c].remove(pos)
    }

    fn any_ready(&self) -> bool {
        self.ready.iter().any(|q| !q.is_empty())
    }

    fn pick_next(&mut self) -> Option<SwitchPlan> {
        let me = crate::smp::index();
        let cur = self.current[me];
        let mut still_runnable = false;
        let mut keep_above = 0;
        if let Some(t) = self.threads.get_mut(&cur) {
            if t.state == State::Running {
                t.state = State::Ready;
                // Not if its affinity no longer includes this CPU: then it
                // is queued where it may run once the switch completes.
                still_runnable = cur != self.idle[me] && t.affinity & (1 << me) != 0;
                // A runnable thread yields only to one scoring at least its
                // own priority (equals take turns).
                keep_above = if still_runnable { effective(t) as u64 } else { 0 };
            }
        }
        // With nothing else to run, a thread that is still runnable keeps
        // the CPU instead of going through the idle thread.
        let next = self.take_ready(me, keep_above).unwrap_or(if still_runnable { cur } else { self.idle[me] });
        let nt = self.threads.get_mut(&next).expect("next thread exists");
        nt.last_cpu = me;
        nt.state = State::Running;
        nt.slice = TIME_SLICE_TICKS;
        if next == cur {
            return None;
        }
        crate::smp::set_current(nt.tid, nt.pid);
        let (new_rsp, new_root, new_top, new_fs, new_gs, new_fs32) =
            (nt.rsp, nt.root, nt.kstack_top, nt.fs_base, nt.gs_base, nt.fs32_base);
        let new_fpu: *const FpuState = &*nt.fpu;
        let old = self.threads.get_mut(&cur).expect("current thread exists");
        // From here until `after_switch` the outgoing context is neither
        // running nor runnable: it must not be queued even if it is woken,
        // because its registers have not been saved yet.
        let outgoing = if cur == self.idle[crate::smp::index()] { None } else { Some(cur) };
        if outgoing.is_some() {
            old.leaving = true;
        }
        self.publish[crate::smp::index()] = outgoing;
        if old.state == State::Dead {
            self.reap[crate::smp::index()] = Some(cur);
        }
        // Hand the kernel entry lock back: the thread keeps the right to
        // re-acquire it when it resumes, but no CPU may hold it on behalf of
        // a thread that is off-CPU (a blocked syscall would otherwise stall
        // every other CPU for the whole wait).
        old.bkl = crate::smp::owner_is_me();
        if old.bkl {
            // The scheduler lock is held here; waking parked waiters is left
            // to `after_switch`, which runs with that lock dropped.
            crate::smp::release_for_switch();
        }
        // FS is userspace TLS. The inactive GS base holds the thread's
        // Windows TEB while the active kernel GS stays CPU-local.
        unsafe {
            // With a 32-bit FS descriptor installed, FS holds that descriptor's
            // base, so it is not the outgoing thread's 64-bit TLS base. Every
            // change of the 64-bit base goes through `set_current_fs_base`,
            // which already updated the field.
            if old.fs32_base == 0 {
                old.fs_base = cpu::rdmsr(IA32_FS_BASE);
            }
            cpu::wrmsr(IA32_FS_BASE, new_fs);
            old.gs_base = cpu::rdmsr(IA32_GS_BASE);
            cpu::wrmsr(IA32_GS_BASE, new_gs);
            // 32-bit code reads its TEB through the FS descriptor, not the
            // MSR. The descriptor lives in this CPU's GDT, so it is installed
            // for the incoming thread on every switch, after the FS MSR is
            // written: for a non-zero base the descriptor load replaces the
            // hidden FS base with the 32-bit TEB. Interrupts are off under the
            // scheduler lock.
            gdt::set_fs32_base(new_fs32);
        }
        let old_rsp: *mut u64 = &mut old.rsp;
        let old_fpu: *mut FpuState = &mut *old.fpu;
        self.current[crate::smp::index()] = next;
        self.switches += 1;
        // Publish the root before loading it: a CPU changing that address
        // space's mappings sends its TLB shootdown to every CPU whose recorded
        // root matches, and must not miss this one while it already uses the
        // root (speculative TLB fills included). The CR3 load is serializing,
        // so the store is visible before any translation through it.
        crate::smp::set_root(new_root);
        if new_root != paging::current_root() {
            // SAFETY: every thread root maps the kernel half (shared PDPTs).
            unsafe { cpu::write_cr3(new_root) };
        }
        if new_top != 0 {
            // SAFETY: the thread's kernel stack lives as long as the thread.
            unsafe {
                gdt::set_kernel_stack(new_top);
                syscall::set_kernel_stack(new_top);
            }
        }
        Some((old_rsp, new_rsp, old_fpu, new_fpu))
    }
}

/// Gives the CPU to the next ready thread (round robin). Returns when the
/// current thread is scheduled again (immediately if nothing else is ready).
pub fn schedule() {
    let were_enabled = cpu::interrupts_enabled();
    cpu::disable_interrupts();
    // Interrupts are already off, so dropping the guard keeps them off.
    let plan = SCHED.lock().as_mut().and_then(Scheduler::pick_next);
    if let Some((old_rsp, new_rsp, old_fpu, new_fpu)) = plan {
        // SAFETY: the pointers refer to boxed fields of threads that stay
        // alive across the switch (a dead thread is reaped only after it).
        unsafe {
            cpu::fpu_save(old_fpu as *mut u8);
            cpu::fpu_restore(new_fpu as *const u8);
            osyx_switch(old_rsp, new_rsp);
        }
        after_switch();
    }
    if were_enabled {
        cpu::enable_interrupts();
    }
}

/// Runs on the new thread right after every switch: the thread that was
/// switched out is only now off its CPU, so it becomes runnable here, and a
/// thread that exited before the switch is freed.
fn after_switch() {
    let cpu = crate::smp::index();
    let mut g = SCHED.lock();
    let mut dead = None;
    let mut reacquire = false;
    if let Some(s) = g.as_mut() {
        if let Some(t) = s.publish[cpu].take() {
            let mut requeue = false;
            if let Some(th) = s.threads.get_mut(&t) {
                th.leaving = false;
                th.low_rsp = th.low_rsp.min(th.rsp);
                requeue = th.state == State::Ready;
                if !th._kstack.is_empty() {
                    let base = th._kstack.as_ptr() as u64;
                    if th.low_rsp < base && !th.stack_warned {
                        th.stack_warned = true;
                        let low = th.low_rsp;
                        let top = th.kstack_top;
                        crate::kprintln!(
                            "sched: stack overrun tid {} ({}) base={:#x} low={:#x} under={:#x}",
                            th.tid,
                            th.name,
                            base,
                            low,
                            base - low
                        );
                        let mut a = low.max(base.saturating_sub(0x2000));
                        let mut shown = 0;
                        while a < top && shown < 10 {
                            // SAFETY: `a` stays inside this thread's stack block.
                            let w = unsafe { core::ptr::read_volatile(a as *const u64) };
                            if (0xffff_ffff_8000_0000..0xffff_ffff_c000_0000).contains(&w) {
                                crate::kprintln!("sched:   ra @{a:#x} = {w:#x}");
                                shown += 1;
                            }
                            a += 8;
                        }
                    }
                }
            }
            if requeue {
                s.enqueue(t);
            }
        }
        dead = s.reap[cpu].take().and_then(|t| s.threads.remove(&t));
        if dead.as_ref().is_some_and(|t| t.kill_pending) {
            KILLS_PENDING.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
        }
        if dead.as_ref().is_some_and(|t| t.suspend > 0) {
            SUSPENDS_PENDING.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
        }
        reacquire = s.threads.get(&s.current[cpu]).is_some_and(|t| t.bkl);
    }
    drop(g);
    drop(dead);
    if reacquire {
        // The thread was executing kernel code under the entry lock when it
        // was switched out; it must not continue without it.
        if crate::smp::enter_kernel() {
            crate::smp::set_hold_kind(crate::smp::HOLD_RESUMED);
        }
    } else if crate::smp::bkl_is_free() {
        // It was released while switching (a blocked syscall, an idle CPU);
        // hand it to the next parked syscall waiter.
        crate::smp::wake_bkl_waiters();
    }
}

/// Timer interrupt hook: wakes sleepers and preempts an expired time slice.
pub fn tick(now: u64) {
    let resched = {
        let mut g = SCHED.lock();
        let Some(s) = g.as_mut() else { return };
        s.ticks = s.ticks.saturating_add(1);
        if s.current[crate::smp::index()] == s.idle[crate::smp::index()] {
            s.idle_ticks = s.idle_ticks.saturating_add(1);
        }
        // AP timers account/preempt their own CPU, but expired sleepers are
        // collected once per global tick, from the deadline heap (not by
        // visiting every thread).
        if s.last_wake_tick != now {
            s.last_wake_tick = now;
            while let Some(&Reverse((at, tid))) = s.sleepers.peek() {
                if at > now {
                    break;
                }
                s.sleepers.pop();
                let queue = s.threads.get_mut(&tid).is_some_and(|t| {
                    if t.state != State::Blocked || t.wake_at != Some(at) {
                        return false; // woken earlier, or waiting again
                    }
                    t.wake_at = None;
                    t.state = State::Ready;
                    !t.leaving
                });
                if queue {
                    s.enqueue(tid);
                }
            }
            // Waits that end early leave their entries behind; drop them
            // before they outnumber the threads by far.
            if s.sleepers.len() > 4 * s.threads.len() + 1024 {
                let Scheduler { threads, sleepers, .. } = s;
                sleepers.retain(|&Reverse((at, tid))| threads.get(&tid).is_some_and(|t| t.state == State::Blocked && t.wake_at == Some(at)));
            }
        }
        let ci = crate::smp::index();
        let idle = s.idle[ci];
        let cur_tid = s.current[ci];
        let cur = match s.threads.get_mut(&cur_tid) {
            Some(cur) => cur,
            None => panic!(
                "current thread missing: cpu {ci}, current {cur_tid}, idle {idle}, threads {}, online {}",
                s.threads.len(),
                crate::smp::online()
            ),
        };
        cur.cpu_ticks = cur.cpu_ticks.saturating_add(1);
        if !cur._kstack.is_empty() {
            // SAFETY: the block is owned by this thread and alive right now.
            let bottom = unsafe { core::ptr::read_volatile(cur._kstack.as_ptr()) } as u64;
            if bottom != STACK_CANARY {
                let base = cur._kstack.as_ptr() as u64;
                let rsp: u64;
                // SAFETY: reading the stack pointer has no side effects.
                unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
                crate::kprintln!(
                    "stack canary: tid {} ({}) base={:#x} top={:#x} rsp={:#x} low={:#x} canary={:#x}",
                    cur.tid, cur.name, base, cur.kstack_top, rsp, cur.low_rsp, bottom
                );
                for i in 0..12u64 {
                    let w = unsafe { core::ptr::read_volatile((base + i * 8) as *const u64) };
                    crate::kprintln!("stack canary: +{:#x} = {:#x}", i * 8, w);
                }
                panic!("kernel stack overflow: tid {} ({})", cur.tid, cur.name);
            }
        }
        cur.slice = cur.slice.saturating_sub(1);
        if cur.slice == 0 && cur.boost > 0 {
            cur.boost -= 1;
        }
        let expired = cur.slice == 0 || cur.tid == idle;
        // A busy CPU switches for its own queue; an idle one also steals.
        expired && (!s.ready[ci].is_empty() || (cur_tid == idle && s.any_ready()))
    };
    if resched {
        schedule();
    }
}

/// Profiler: visits every switched-out thread (blocked or waiting for a CPU)
/// with its saved kernel stack pointer and the top of that stack.
pub fn prof_threads(mut f: impl FnMut(Tid, u64, State, u64, u64)) {
    let g = SCHED.lock();
    let Some(s) = g.as_ref() else { return };
    for t in s.threads.values() {
        if t.leaving || !matches!(t.state, State::Blocked | State::Ready) || s.idle.contains(&t.tid) {
            continue;
        }
        let hi = if t.kstack_top != 0 { t.kstack_top } else { t.rsp + 64 * 1024 };
        f(t.tid, t.pid, t.state, t.rsp, hi);
    }
}

pub fn cpu_stats() -> (u64, u64) {
    SCHED.lock().as_ref().map_or((0, 0), |s| (s.ticks, s.idle_ticks))
}

pub fn cpu_ticks(tid: Tid) -> u64 {
    SCHED.lock().as_ref().and_then(|s| s.threads.get(&tid)).map_or(0, |t| t.cpu_ticks)
}

/// TEMP per-thread CPU ticks (tid, pid, ticks) for the 1 s stats line.
pub fn thread_cpu() -> alloc::vec::Vec<(Tid, u64, u64)> {
    let g = SCHED.lock();
    let Some(s) = g.as_ref() else { return alloc::vec::Vec::new() };
    s.threads.values().map(|t| (t.tid, t.pid, t.cpu_ticks)).collect()
}

/// From an interrupt handler: switches away from the idle thread if the
/// handler made another thread ready (instead of halting until the next
/// timer tick).
pub fn preempt_if_idle() {
    let resched = SCHED.lock().as_ref().is_some_and(|s| s.current[crate::smp::index()] == s.idle[crate::smp::index()] && s.any_ready());
    if resched {
        schedule();
    }
}

/// Gives up the rest of the time slice.
pub fn yield_now() {
    schedule();
}

/// Blocks the current thread for at least `ticks` timer ticks.
pub fn sleep_ticks(ticks: u64) {
    if ticks == 0 {
        return yield_now();
    }
    let were_enabled = cpu::interrupts_enabled();
    cpu::disable_interrupts();
    {
        let mut g = SCHED.lock();
        let s = g.as_mut().expect("scheduler not initialised");
        let tid = s.current[crate::smp::index()];
        let t = s.threads.get_mut(&tid).expect("current thread exists");
        let at = interrupts::ticks() + ticks;
        t.wake_at = Some(at);
        t.state = State::Blocked;
        // A waker must not queue this thread before its own CPU has saved
        // its context (`after_switch` clears the flag).
        t.leaving = true;
        s.sleepers.push(Reverse((at, tid)));
    }
    schedule();
    if were_enabled {
        cpu::enable_interrupts();
    }
}

/// Marks the current thread blocked. The caller must have registered a
/// wake-up (see [`wake`]) and must call [`schedule`] next, all with
/// interrupts disabled so the wake-up cannot be lost.
pub fn mark_current_blocked() {
    mark_current_blocked_until(None);
}

/// Like [`mark_current_blocked`], but the timer also wakes the thread at
/// tick `deadline`.
pub fn mark_current_blocked_until(deadline: Option<u64>) {
    let mut g = SCHED.lock();
    let s = g.as_mut().expect("scheduler not initialised");
    let tid = s.current[crate::smp::index()];
    let t = s.threads.get_mut(&tid).expect("current thread exists");
    if t.wake_pending {
        // Another CPU woke us after the caller's last check. Stay runnable so
        // `schedule` returns to the caller, which re-checks its condition.
        t.wake_pending = false;
        return;
    }
    t.state = State::Blocked;
    t.wake_at = deadline;
    // See `sleep_ticks`: the caller switches out next, and until that switch
    // completes another CPU must not run this thread.
    t.leaving = true;
    if let Some(at) = deadline {
        s.sleepers.push(Reverse((at, tid)));
    }
}

/// Asks thread `tid` to end at its next safe point and wakes it if blocked
/// so that it gets there.
pub fn request_kill(tid: Tid) {
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else { return };
    if let Some(t) = s.threads.get_mut(&tid) {
        if !t.kill_pending {
            KILLS_PENDING.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
        t.kill_pending = true;
        if t.state == State::Blocked {
            t.state = State::Ready;
            t.wake_at = None;
            if !t.leaving {
                s.enqueue(tid);
            }
        } else {
            t.wake_pending = true;
        }
    }
}

/// Threads asked to end that still exist. Every system call and every timer
/// interrupt from user mode asks [`current_kill_pending`]; while no thread
/// anywhere is being killed, that needs no scheduler lock.
static KILLS_PENDING: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// True if the current thread has been asked to end.
pub fn current_kill_pending() -> bool {
    if KILLS_PENDING.load(core::sync::atomic::Ordering::SeqCst) == 0 {
        return false;
    }
    SCHED.lock().as_ref().is_some_and(|s| s.threads.get(&s.current[crate::smp::index()]).is_some_and(|t| t.kill_pending))
}

/// Threads with a non-zero suspend count. Every return to user mode asks
/// [`park_if_suspended`]; while none is suspended that needs no scheduler lock.
static SUSPENDS_PENDING: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Stops the current thread here while its suspend count is non-zero. Called
/// where the thread is about to return to user mode with no kernel lock
/// held; a thread being killed is let through.
pub fn park_if_suspended() {
    if SUSPENDS_PENDING.load(core::sync::atomic::Ordering::SeqCst) == 0 {
        return;
    }
    let were_enabled = cpu::interrupts_enabled();
    loop {
        cpu::disable_interrupts();
        {
            let mut g = SCHED.lock();
            let Some(s) = g.as_mut() else { break };
            let tid = s.current[crate::smp::index()];
            let Some(t) = s.threads.get_mut(&tid) else { break };
            if t.suspend == 0 || t.kill_pending {
                t.parked = false;
                break;
            }
            t.parked = true;
            if t.wake_pending {
                // A resume (or another wake) arrived since the check above:
                // look at the count again instead of blocking.
                t.wake_pending = false;
                continue;
            }
            t.state = State::Blocked;
            t.wake_at = None;
            t.leaving = true;
        }
        schedule();
    }
    if were_enabled {
        cpu::enable_interrupts();
    }
}

/// `nr::THREAD_SUSPEND`: changes or reads the suspend count of a thread of
/// the caller's process and returns the previous count. Suspending another
/// thread returns once it has stopped (or is waiting inside the kernel, where
/// it stops when the wait ends).
pub fn thread_suspend(tid: Tid, op: u64) -> Result<u64, osyx_abi::Errno> {
    use osyx_abi::{suspend, Errno};
    let me = current_tid();
    let tid = if tid == 0 { me } else { tid };
    let pid = current_pid();
    let (previous, wake) = {
        let mut guard = SCHED.lock();
        let s = guard.as_mut().ok_or(Errno::NotSupported)?;
        let t = s.threads.get_mut(&tid).ok_or(Errno::NotFound)?;
        if t.pid != pid {
            return Err(Errno::PermissionDenied);
        }
        let previous = t.suspend as u64;
        let mut wake = false;
        match op {
            suspend::QUERY => {}
            suspend::SUSPEND => {
                if t.suspend >= suspend::MAX {
                    return Err(Errno::Busy);
                }
                if t.suspend == 0 {
                    SUSPENDS_PENDING.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
                }
                t.suspend += 1;
            }
            suspend::RESUME => {
                if t.suspend > 0 {
                    t.suspend -= 1;
                    if t.suspend == 0 {
                        SUSPENDS_PENDING.fetch_sub(1, core::sync::atomic::Ordering::SeqCst);
                        wake = t.parked;
                    }
                }
            }
            _ => return Err(Errno::InvalidArgument),
        }
        (previous, wake)
    };
    if wake {
        wake_boosted(tid, 0);
    }
    if op == suspend::SUSPEND && previous == 0 && tid != me {
        // Wait (a few ticks at most) until the thread is off user code.
        for _ in 0..20 {
            let settled = SCHED.lock().as_ref().and_then(|s| s.threads.get(&tid)).is_none_or(|t| t.parked || t.state == State::Blocked || t.state == State::Dead);
            if settled {
                break;
            }
            sleep_ticks(1);
        }
    }
    Ok(previous)
}

/// `nr::THREAD_TIMES`: scheduler samples the thread has used.
pub fn thread_times(tid: Tid) -> Result<u64, osyx_abi::Errno> {
    use osyx_abi::Errno;
    let tid = if tid == 0 { current_tid() } else { tid };
    let pid = current_pid();
    let guard = SCHED.lock();
    let s = guard.as_ref().ok_or(Errno::NotSupported)?;
    let t = s.threads.get(&tid).ok_or(Errno::NotFound)?;
    if t.pid != pid {
        return Err(Errno::PermissionDenied);
    }
    Ok(t.cpu_ticks)
}

/// Sets the GS base of the current thread and loads it into the CPU.
pub fn set_current_gs_base(value: u64) {
    let mut g = SCHED.lock();
    let s = g.as_mut().expect("scheduler not initialised");
    let t = s.threads.get_mut(&s.current[crate::smp::index()]).expect("current thread exists");
    t.gs_base = value;
    // SAFETY: inactive GS is the user TEB; active GS stays CPU-local.
    unsafe { cpu::wrmsr(IA32_GS_BASE, value) };
}

/// Sets the FS base of the current thread and loads it into the CPU.
pub fn set_current_fs_base(value: u64) {
    let mut g = SCHED.lock();
    let s = g.as_mut().expect("scheduler not initialised");
    let t = s.threads.get_mut(&s.current[crate::smp::index()]).expect("current thread exists");
    t.fs_base = value;
    // SAFETY: see `pick_next`; the kernel does not use FS.
    unsafe { cpu::wrmsr(IA32_FS_BASE, value) };
}

/// Sets the FS base that 32-bit compatibility-mode code of the current thread
/// sees (`fs:[0x18]`) and installs it in this CPU's GDT.
///
/// A non-zero `value` also loads FS from the descriptor, which replaces the
/// single hidden FS base (there is one such register, aliased by
/// `IA32_FS_BASE`): from then on 64-bit code of the same thread re-establishes
/// its TLS with [`set_current_fs_base`]. Clearing the base puts the thread's
/// 64-bit FS base back. The value is stored on the thread and reinstalled by
/// [`Scheduler::pick_next`] whenever the thread runs again, so it follows the
/// thread across CPUs.
pub fn current_fs32_base() -> u64 {
    let g = SCHED.lock();
    let s = g.as_ref().expect("scheduler not initialised");
    s.threads.get(&s.current[crate::smp::index()]).map_or(0, |t| t.fs32_base)
}

pub fn set_current_fs32_base(value: u64) {
    let mut g = SCHED.lock();
    let s = g.as_mut().expect("scheduler not initialised");
    let t = s.threads.get_mut(&s.current[crate::smp::index()]).expect("current thread exists");
    t.fs32_base = value;
    // SAFETY: the scheduler lock keeps interrupts off; the GDT is this CPU's.
    unsafe {
        gdt::set_fs32_base(value);
        if value == 0 {
            // Installing a base replaced the hidden FS base, so clearing it
            // has to restore the 64-bit one (the thread's field is current:
            // only `set_current_fs_base` changes it).
            cpu::wrmsr(IA32_FS_BASE, t.fs_base);
        }
    }
}

/// Loads the initial x87/SSE/AVX state into the CPU for the current thread
/// (`execve`: nothing of the old program's registers survives). The saved
/// copy is refreshed from the CPU at the next switch.
pub fn reset_current_fpu() {
    let init = FpuState::initial();
    // SAFETY: a valid, 64-byte aligned XSAVE image.
    unsafe { cpu::fpu_restore(&*init as *const FpuState as *const u8) };
}

pub fn rename_current(name: &str) {
    let mut g = SCHED.lock();
    if let Some(t) = g.as_mut().and_then(|s| s.threads.get_mut(&s.current[crate::smp::index()])) {
        t.name = name.to_string();
    }
}

/// Makes a blocked thread ready again (no effect on other states).
pub fn wake(tid: Tid) {
    wake_boosted(tid, WAKE_BOOST);
}

/// Like [`wake`], and the thread runs `levels` above its priority for its
/// next time slices (dynamic priority boost).
pub fn wake_boosted(tid: Tid, levels: u8) {
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else { return };
    let mut queue = false;
    if let Some(t) = s.threads.get_mut(&tid) {
        if t.state == State::Blocked {
            // Only a wait that ends gains the boost, not a running thread.
            t.boost = t.boost.max(levels);
            t.state = State::Ready;
            t.wake_at = None;
            // A thread whose context is still being saved is queued by
            // `after_switch` on its old CPU; queueing it here would let
            // another CPU run it before the switch completes.
            queue = !t.leaving;
        } else if !t.leaving {
            // The thread may be about to block (it checked its condition, not
            // yet marked itself blocked). Remember the wake for that block.
            t.wake_pending = true;
        }
    }
    if queue {
        s.enqueue(tid);
    }
}

/// Ends the current thread. Its stack is freed by the next thread.
pub fn exit_current() -> ! {
    cpu::disable_interrupts();
    let joiners = {
        let mut g = SCHED.lock();
        let s = g.as_mut().expect("scheduler not initialised");
        let t = s.threads.get_mut(&s.current[crate::smp::index()]).expect("current thread exists");
        assert!(t.kstack_top != 0, "the boot thread cannot exit");
        t.state = State::Dead;
        t.leaving = true;
        core::mem::take(&mut t.joiners)
    };
    for j in joiners {
        wake(j);
    }
    schedule();
    unreachable!("dead thread was scheduled again");
}

/// Waits until thread `tid` has exited (returns at once if it does not exist).
pub fn join(tid: Tid) {
    loop {
        let were_enabled = cpu::interrupts_enabled();
        cpu::disable_interrupts();
        let waiting = {
            let mut g = SCHED.lock();
            let s = g.as_mut().expect("scheduler not initialised");
            let me = s.current[crate::smp::index()];
            match s.threads.get_mut(&tid) {
                Some(t) if t.state != State::Dead => {
                    t.joiners.push(me);
                    let j = s.threads.get_mut(&me).expect("current thread exists");
                    j.state = State::Blocked;
                    j.leaving = true;
                    true
                }
                _ => false,
            }
        };
        if waiting {
            schedule();
        }
        if were_enabled {
            cpu::enable_interrupts();
        }
        if !waiting {
            return;
        }
    }
}

pub fn current_tid() -> Tid {
    let tid = crate::smp::cached_tid();
    if tid != 0 {
        return tid;
    }
    SCHED.lock().as_ref().map_or(1, |s| s.current[crate::smp::index()])
}

pub fn set_affinity(tid:Tid,mask:u64)->Result<u64,osyx_abi::Errno> {
    let available=(1u64<<crate::smp::online())-1;
    if mask & !available !=0 { return Err(osyx_abi::Errno::InvalidArgument); }
    let me=current_tid();
    let tid=if tid==0 {me}else{tid};
    let pid=current_pid();
    let old={
        let mut guard=SCHED.lock();
        let s=guard.as_mut().ok_or(osyx_abi::Errno::NotSupported)?;
        let thread=s.threads.get_mut(&tid).ok_or(osyx_abi::Errno::NotFound)?;
        if thread.pid!=pid {return Err(osyx_abi::Errno::PermissionDenied);}
        let old=thread.affinity&available;
        if mask==0 { return Ok(old); }
        thread.affinity=mask;
        old
    };
    if tid==me && mask & (1<<crate::smp::index())==0 { schedule(); }
    Ok(old)
}

/// Sets (or with `priority::QUERY` reads) the priority of a thread of the
/// caller's process (tid 0 = the caller); returns the previous one.
pub fn set_priority(tid: Tid, priority: u64) -> Result<u64, osyx_abi::Errno> {
    let me = current_tid();
    let tid = if tid == 0 { me } else { tid };
    let pid = current_pid();
    let mut guard = SCHED.lock();
    let s = guard.as_mut().ok_or(osyx_abi::Errno::NotSupported)?;
    let t = s.threads.get_mut(&tid).ok_or(osyx_abi::Errno::NotFound)?;
    if t.pid != pid {
        return Err(osyx_abi::Errno::PermissionDenied);
    }
    let old = t.priority as u64;
    if priority == osyx_abi::priority::INFO {
        return Ok(old | (effective(t) as u64) << 8 | (t.boost as u64) << 16 | (t.inherited as u64) << 24);
    }
    if priority != osyx_abi::priority::QUERY {
        if priority > MAX_PRIORITY as u64 {
            return Err(osyx_abi::Errno::InvalidArgument);
        }
        t.priority = priority as u8;
    }
    Ok(old)
}

/// Current effective priority of thread `tid` (0 if it does not exist).
pub fn effective_priority(tid: Tid) -> u8 {
    SCHED.lock().as_ref().and_then(|s| s.threads.get(&tid)).map_or(0, |t| effective(t))
}

/// Lends priority `level` to thread `tid` of process `pid` (0 takes it
/// back); a thread of another process is left alone. If that raises it
/// above the thread running on the CPU it is queued for, that thread's
/// time slice ends.
pub fn set_inherited(tid: Tid, pid: u64, level: u8) {
    let mut g = SCHED.lock();
    let Some(s) = g.as_mut() else { return };
    let Some(t) = s.threads.get_mut(&tid).filter(|t| t.pid == pid) else { return };
    t.inherited = level.min(MAX_PRIORITY);
    let now = effective(t);
    if t.state != State::Ready {
        return;
    }
    let online = crate::smp::online().clamp(1, crate::smp::MAX_CPUS);
    if let Some(cpu) = (0..online).find(|&c| s.ready[c].contains(&tid)) {
        let running = s.current[cpu];
        if running != s.idle[cpu] {
            if let Some(r) = s.threads.get_mut(&running) {
                if effective(r) < now {
                    r.slice = 0;
                    crate::smp::kick(cpu);
                }
            }
        }
    }
}

pub fn current_pid() -> u64 {
    if crate::smp::cached_tid() != 0 {
        return crate::smp::cached_pid();
    }
    SCHED.lock().as_ref().and_then(|s| s.threads.get(&s.current[crate::smp::index()]).map(|t| t.pid)).unwrap_or(0)
}

/// Changes the page table root recorded for the current thread (used when a
/// process leaves its address space on exit).
pub fn set_current_root(root: u64) {
    crate::smp::set_root(root);
    let mut g = SCHED.lock();
    if let Some(s) = g.as_mut() {
        if let Some(t) = s.threads.get_mut(&s.current[crate::smp::index()]) {
            t.root = root;
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub threads: usize,
    pub ready: usize,
    pub switches: u64,
}

/// Logs every thread with its state (diagnostics).
pub fn dump() {
    let g = SCHED.lock();
    let Some(s) = g.as_ref() else { return };
    for t in s.threads.values() {
        let (nr, rip) = crate::smp::last_syscall(t.tid);
        crate::kprintln!(
            "  thread {:3} {:<10} pid {:2} {:?} wake {:?} syscall {:#x}@{:#x}",
            t.tid,
            t.name,
            t.pid,
            t.state,
            t.wake_at,
            nr,
            rip
        );
    }
}

pub fn stats() -> Stats {
    let g = SCHED.lock();
    let s = g.as_ref().expect("scheduler not initialised");
    Stats { threads: s.threads.len(), ready: s.ready.iter().map(VecDeque::len).sum(), switches: s.switches }
}
