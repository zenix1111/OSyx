//! User processes: creation from executable files, `execve`, exit, zombies
//! and `wait`.
//!
//! A process owns an address space and one or more threads scheduled by
//! `sched`. On exit the address space is destroyed at once; the process
//! stays in the table as a zombie holding its exit status until the parent
//! collects it with [`wait`]. Children of an exiting process are re-parented
//! to the kernel (pid 0) and released automatically when they exit.
//!
//! Programs are static ELF64 executables read from the VFS (see `exec`).
//! `execve` builds the new image in a fresh address space and only then
//! swaps it in, so a failure leaves the caller untouched.
//!
//! Every frame a process causes to be allocated (page tables included) is
//! counted, and teardown checks that exactly that many frames come back.
//!
//! User address space layout:
//! * `0x0000_0000_0000_0000..0x0000_0000_0001_0000` never mapped (null guard)
//! * ELF segments at their link addresses, below `MAP_BASE`
//! * anonymous memory from `MAP_BASE` upwards, a guard page after each region
//! * stack: `STACK_PAGES` pages below `STACK_TOP`, guard page below that;
//!   at its top the System V start-up data (`osyx_abi::startup`)

use crate::arch::cpu;
use crate::exec::{self, ExecRequest, Program};
use crate::image::{self, ImageSection};
use crate::kprintln;
use crate::mem::paging::{self, Flags, MapError};
use crate::mem::{alloc_frame, free_frame, phys_to_virt, PAGE_SIZE};
use crate::object::Object;
use crate::sched::{self, Tid};
use crate::shm::SharedMemory;
use crate::sync::{IrqSpinLock, KMutex};
use crate::vfs::{self, Lookup};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};
use osyx_abi::{auxv, startup, wow64, Errno};
use osyx_elf::{AddressRange, ElfError, ElfImage};
use osyx_vfs::Cred;

pub type Pid = u64;
/// Parent id of processes started (or adopted) by the kernel.
pub const KERNEL_PID: Pid = 0;

pub const STACK_TOP: u64 = 0x0000_7FFF_FFFF_0000;
const STACK_PAGES: u64 = 128; // 512 KiB
/// Fixed mappings must end below the main stack and its guard page.
const STACK_LIMIT: u64 = STACK_TOP - (STACK_PAGES + 1) * PAGE_SIZE;
const MAP_BASE: u64 = 0x0000_1000_0000_0000;
/// Where program segments may lie: above the null guard, below `MAP_BASE`.
const PROGRAM_RANGE: AddressRange = AddressRange { start: osyx_elf::USER_RANGE.start, end: MAP_BASE };
/// Per-process cap on anonymous address space (64 GiB). Anonymous memory
/// is demand-zero: a frame is taken on the first access to a page, so this
/// bounds reservations (a browser reserves far more than it touches), and
/// physical memory bounds what is actually used.
const MAP_LIMIT_PAGES: u64 = 16 * 1024 * 1024;
const MAX_PROCESSES: usize = 512;
const OUTPUT_TAIL_LINES: usize = 3;

/// Why a program could not be started or executed.
#[derive(Debug)]
pub enum ExecError {
    /// Finding or reading the program, or the arguments (an `Errno` of `exec`).
    Load(Errno),
    BadImage(ElfError),
    Map(MapError),
    /// The start-up data does not fit on the stack.
    ArgsTooLarge,
    TooManyProcesses,
    /// `execve` in a process with more than one thread.
    Busy,
}

impl core::fmt::Display for ExecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ExecError::Load(e) => write!(f, "{}", e.name()),
            ExecError::BadImage(e) => write!(f, "invalid executable: {}", e.describe()),
            ExecError::Map(e) => write!(f, "cannot map memory: {e:?}"),
            ExecError::ArgsTooLarge => write!(f, "arguments do not fit on the stack"),
            ExecError::TooManyProcesses => write!(f, "process limit of {MAX_PROCESSES} reached"),
            ExecError::Busy => write!(f, "process has other threads"),
        }
    }
}

impl ExecError {
    pub fn errno(&self) -> Errno {
        match self {
            ExecError::Load(e) => *e,
            ExecError::BadImage(_) => Errno::BadExecutable,
            ExecError::ArgsTooLarge => Errno::InvalidArgument,
            ExecError::Map(_) | ExecError::TooManyProcesses => Errno::NoMemory,
            ExecError::Busy => Errno::Busy,
        }
    }
}

/// A page-table root and the number of frames it owns (itself, page
/// tables and mapped pages).
struct Space {
    root: u64,
    frames: u64,
    program_shared: BTreeMap<u64, (Arc<SharedMemory>, u64)>,
}

/// An anonymous mapping. Its pages get frames on first access; until then
/// only their protection is kept, as runs of equal protection.
struct Region {
    pages: u64,
    /// Page index where a run starts -> `PROT_*` of the run (to the next key).
    prot: BTreeMap<u64, u64>,
    /// A shared executable image behind the region (page `i` of the region
    /// is page `i` of the image). A page whose entry points at the image's
    /// frame is shared and mapped read-only; a write copies it first.
    image: Option<Arc<ImageSection>>,
    /// A file section behind the region, mapping pages on first touch. The
    /// frames belong to the section's backing, not to this address space.
    file: Option<FileRegion>,
    /// Pages moved to compressed memory: page index -> compressed bytes
    /// (empty: an all-zero page). Restored on the next access.
    swapped: BTreeMap<u64, SwappedPage>,
    refault_guard: osyx_mm::adaptive::RefaultGuard,
    /// Next page to inspect during compressed-memory reclaim.
    reclaim_cursor: u64,
}

struct FileRegion {
    section: Arc<crate::filemap::Section>,
    /// Page index in the file of the region's first page.
    first_page: u64,
}

impl Region {
    fn new(pages: u64, prot: u64) -> Region {
        let mut runs = BTreeMap::new();
        runs.insert(0, prot);
        Region {
            pages,
            prot: runs,
            image: None,
            file: None,
            swapped: BTreeMap::new(),
            reclaim_cursor: 0,
            refault_guard: Default::default(),
        }
    }

    /// Whether `frame` at page `page` of the region is the shared image frame.
    fn shares(&self, page: u64, frame: u64) -> bool {
        self.image.as_ref().is_some_and(|i| i.frame(page) == Some(frame))
    }

    fn prot_at(&self, page: u64) -> u64 {
        self.prot.range(..=page).next_back().map_or(0, |(_, &p)| p)
    }

    /// Sets the protection of pages `first..last`.
    fn set_prot(&mut self, first: u64, last: u64, prot: u64) {
        let after = self.prot_at(last);
        let inside: Vec<u64> = self.prot.range(first..last).map(|(&k, _)| k).collect();
        for k in inside {
            self.prot.remove(&k);
        }
        self.prot.insert(first, prot);
        if last < self.pages {
            self.prot.entry(last).or_insert(after);
        }
    }
}

struct SwappedPage {
    data: alloc::boxed::Box<[u8]>,
    evicted_at: u64,
}

impl Space {
    fn new() -> Result<Space, MapError> {
        Ok(Space { root: paging::new_address_space()?, frames: 1, program_shared: BTreeMap::new() })
    }

    fn map_zeroed(&mut self, va: u64, flags: Flags) -> Result<u64, MapError> {
        let frame = alloc_frame().ok_or(MapError::OutOfMemory)?;
        match paging::map_in(self.root, va, frame, flags) {
            Ok(tables) => {
                self.frames += 1 + tables;
                Ok(frame)
            }
            Err(e) => {
                let _ = free_frame(frame);
                Err(e)
            }
        }
    }

    fn map_shared(&mut self, va: u64, page: Arc<SharedMemory>, flags: Flags) -> Result<(), MapError> {
        let tables = paging::map_in(self.root, va, page.frames()[0], flags)?;
        self.frames += tables;
        self.program_shared.insert(va, (page, 1));
        Ok(())
    }

    /// Maps the ELF segments and the start-up stack pages; the remaining
    /// stack pages are demand-zero. Returns (entry, initial rsp).
    fn populate(
        &mut self,
        elf: &ElfImage,
        prog: &Program,
        req: &ExecRequest,
        cred: Cred,
    ) -> Result<(u64, u64), ExecError> {
        for seg in elf.segments() {
            let file = elf.file_bytes(seg);
            let flags = Flags::user(seg.writable(), seg.executable());
            let mut va = seg.vaddr;
            while va < seg.page_end() {
                if seg.writable() {
                    let frame = self.map_zeroed(va, flags).map_err(ExecError::Map)?;
                    let end = (va + PAGE_SIZE).min(seg.vaddr + file.len() as u64);
                    if end > va {
                        let offset = (va - seg.vaddr) as usize;
                        let src = &file[offset..offset + (end - va) as usize];
                        // SAFETY: the frame was just allocated and is reachable via the HHDM.
                        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), phys_to_virt(frame) as *mut u8, src.len()) };
                    }
                } else {
                    let pages = exec::shared_pages(prog, seg).map_err(|_| ExecError::Map(MapError::OutOfMemory))?;
                    for page in pages {
                        self.map_shared(va, page, flags).map_err(ExecError::Map)?;
                        va += PAGE_SIZE;
                    }
                    continue;
                }
                va += PAGE_SIZE;
            }
        }
        let (uid, gid) = (cred.uid as u64, cred.gid as u64);
        let mut aux = Vec::with_capacity(11);
        if let Some(phdr) = elf.phdr_vaddr() {
            aux.push((auxv::AT_PHDR, phdr));
        }
        aux.extend_from_slice(&[
            (auxv::AT_PHENT, 56),
            (auxv::AT_PHNUM, elf.phnum() as u64),
            (auxv::AT_PAGESZ, PAGE_SIZE),
            (auxv::AT_ENTRY, elf.entry()),
            (auxv::AT_UID, uid),
            (auxv::AT_EUID, uid),
            (auxv::AT_GID, gid),
            (auxv::AT_EGID, gid),
            (auxv::AT_SECURE, 0),
        ]);
        let argv: Vec<&[u8]> = req.argv.iter().map(|s| s.as_bytes()).collect();
        let envp: Vec<&[u8]> = req.envp.iter().map(|s| s.as_bytes()).collect();
        let image = startup::Image {
            argv: &argv,
            envp: &envp,
            aux: &aux,
            random: exec::random_bytes(),
            execfn: prog.path.as_bytes(),
        };
        // Keep at least a quarter of the stack for the program itself.
        let size = image.size();
        if size as u64 > STACK_PAGES * PAGE_SIZE * 3 / 4 {
            return Err(ExecError::ArgsTooLarge);
        }
        let mut bytes = alloc::vec![0u8; size];
        let sp = image.build(STACK_TOP, &mut bytes).ok_or(ExecError::ArgsTooLarge)?;
        let mut va = sp & !(PAGE_SIZE - 1);
        while va < STACK_TOP {
            self.map_zeroed(va, Flags::user(true, false)).map_err(ExecError::Map)?;
            va += PAGE_SIZE;
        }
        self.poke(sp, &bytes).map_err(ExecError::Map)?;
        Ok((elf.entry(), sp))
    }

    /// Writes `bytes` at user address `va` of this (not active) address space.
    fn poke(&self, mut va: u64, mut bytes: &[u8]) -> Result<(), MapError> {
        while !bytes.is_empty() {
            let t = paging::translate_in(self.root, va).ok_or(MapError::NotMapped)?;
            let room = (PAGE_SIZE - (va % PAGE_SIZE)) as usize;
            let n = room.min(bytes.len());
            // SAFETY: `t.phys` is a frame of this address space, reachable via the HHDM.
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), phys_to_virt(t.phys) as *mut u8, n) };
            va += n as u64;
            bytes = &bytes[n..];
        }
        Ok(())
    }

    /// Destroys the address space; returns (frames owned, frames freed).
    ///
    /// # Safety
    /// The space must not be active on any CPU.
    unsafe fn release(&mut self) -> (u64, u64) {
        unmap_shared_from(self.root, core::mem::take(&mut self.program_shared));
        // SAFETY: forwarded caller contract; the frames belong to us.
        let freed = unsafe { paging::destroy_address_space(self.root) };
        let owned = self.frames;
        self.frames = 0;
        self.root = 0;
        (owned, freed)
    }
}

/// Reads, validates and maps `req`'s program into a new address space as
/// `cx` (whose credentials and current directory apply); returns the space,
/// the entry point, the initial rsp and the canonical program path.
fn build_image(cx: &Lookup, req: &ExecRequest) -> Result<(Space, u64, u64, String), ExecError> {
    let prog = exec::load(cx, &req.path).map_err(ExecError::Load)?;
    let elf = ElfImage::parse_with(&prog.image, PROGRAM_RANGE).map_err(|e| {
        kprintln!("exec {}: rejected: {}", prog.path, e.describe());
        ExecError::BadImage(e)
    })?;
    let mut space = Space::new().map_err(ExecError::Map)?;
    match space.populate(&elf, &prog, req, cx.cred) {
        Ok((entry, sp)) => Ok((space, entry, sp, prog.path)),
        Err(e) => {
            // SAFETY: the space was never activated.
            unsafe { space.release() };
            Err(e)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Life {
    Running,
    Zombie(i32),
}

pub struct Process {
    pub pid: Pid,
    pub name: String,
    parent: Pid,
    /// Set when the parent exited: released immediately on exit.
    orphan: bool,
    life: Life,
    space: Space,
    /// Anonymous mappings by base address (demand-zero).
    regions: BTreeMap<u64, Region>,
    /// Shared memory mapped into this process: address -> (object, pages).
    /// The frames belong to the object; they are unmapped (never freed)
    /// before the address space is destroyed.
    shared: BTreeMap<u64, (Arc<SharedMemory>, u64)>,
    program_shared: BTreeMap<u64, (Arc<SharedMemory>, u64)>,
    next_map: u64,
    mapped_pages: u64,
    line: Vec<u8>,
    /// Live threads; the process is finalised when the last one ends.
    threads: Vec<Tid>,
    exited_cpu_ticks: u64,
    /// Set by `exit`: the status reported once the last thread has ended.
    exit_status: Option<i32>,
    /// User and group for permission checks (inherited by children).
    cred: Cred,
    /// Canonical absolute current directory (inherited by children).
    cwd: String,
}

/// An open file shared by the handle table and in-flight system calls.
pub type FileHandle = Arc<KMutex<vfs::OpenFile>>;

struct Table {
    procs: BTreeMap<Pid, Process>,
    /// Threads blocked in `wait`, keyed by the parent they wait as.
    waiters: Vec<(Pid, Tid)>,
}

static NEXT_PID: AtomicU64 = AtomicU64::new(1);
static TABLE: IrqSpinLock<Table> = IrqSpinLock::new(Table { procs: BTreeMap::new(), waiters: Vec::new() });
/// Open objects by process and handle number: 0-2 only if standard streams
/// were redirected at spawn, the rest from `FIRST_FILE_HANDLE`. Separate from
/// [`TABLE`]: channel and wait system calls look handles up on every message,
/// and they must not queue behind mappings or page faults. Lock order:
/// TABLE, then this table.
static HANDLES: IrqSpinLock<BTreeMap<Pid, BTreeMap<u64, Object>>> = IrqSpinLock::new(BTreeMap::new());
static OUTPUT_TAIL: IrqSpinLock<VecDeque<String>> = IrqSpinLock::new(VecDeque::new());

global_asm!(
    r#"
    .section .text
    // ! osyx_iret_to_user(entry: u64, user_rsp: u64, arg: u64)
    // Enters ring 3 at `entry` with rsp = user_rsp, rdi = arg and every
    // other general purpose register zero.
    .global osyx_iret_to_user
osyx_iret_to_user:
    cli
    push rdi
    push rsi
    push rdx
    call osyx_kernel_leave
    pop rdx
    pop rsi
    pop rdi
    push 0x1B           // SS  = USER_DS
    push rsi            // RSP
    push 0x202          // RFLAGS: IF set
    push 0x23           // CS  = USER_CS
    push rdi            // RIP
    mov rdi, rdx
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    swapgs
    iretq
    "#
);

extern "C" {
    fn osyx_iret_to_user(entry: u64, user_rsp: u64, arg: u64) -> !;
}

global_asm!(
    r#"
    .section .text
    // ! osyx_iret_to_user32(frame: *const osyx_abi::wow64::CompatIretFrame,
    //                      arg: u64)
    // Enters ring 3 in compatibility mode. The frame carries RIP, CS
    // (USER_CS32), RFLAGS, RSP and SS (USER_DS) in the order iretq pops them;
    // rdi = arg and every other general purpose register is zero.
    .global osyx_iret_to_user32
osyx_iret_to_user32:
    cli
    push rdi
    push rsi
    push rdx
    call osyx_kernel_leave
    pop rdx
    pop rsi
    pop rdi
    push qword ptr [rdi + 32]   // SS  = USER_DS (0x1B)
    push qword ptr [rdi + 24]   // RSP, below 4 GiB and 16-byte aligned
    push qword ptr [rdi + 16]   // RFLAGS: IF set
    push qword ptr [rdi + 8]    // CS  = USER_CS32 (0x3B)
    push qword ptr [rdi + 0]    // RIP, below 4 GiB
    mov rdi, rsi
    xor eax, eax
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    xor esi, esi
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    swapgs
    iretq
    "#
);

extern "C" {
    fn osyx_iret_to_user32(frame: *const wow64::CompatIretFrame, arg: u64) -> !;
}

/// Enters `entry` in 32-bit compatibility mode with `rsp` and `rdi = arg`.
///
/// The IRET frame selects CS = [`wow64::USER_CS32`] (D=1, L=0, DPL 3) and
/// SS = [`wow64::USER_DS`]; the CPU switches to compatibility mode. The entry
/// point and the stack must lie below 4 GiB (compatibility mode has 32-bit
/// address size) and `rsp` must be 16-byte aligned at a call boundary. FS is
/// loaded from the thread's 32-bit descriptor, so 32-bit code finds its TEB
/// at `fs:[0x18]`; the FPU/AVX state is the thread's usual 832-byte XSAVE
/// image (compat mode uses the same state components, no new area).
///
/// # Safety
/// `entry` and `user_rsp` must lie in the current process's user address
/// space, which must be active; a bad value only faults in ring 3.
#[allow(dead_code)] // First caller: the M4 32-bit bridge.
pub unsafe fn enter_compat(entry: u64, user_rsp: u64, arg: u64) -> ! {
    let frame = wow64::CompatIretFrame::new(entry, user_rsp)
        .expect("32-bit entry point or stack outside compatibility mode");
    // The CPU keeps one hidden FS base. The 32-bit descriptor of this CPU
    // carries the calling thread's base (the scheduler installs it with the
    // thread), so load it here rather than relying on what the caller left.
    // SAFETY: a ring-0 load of a ring-3 data selector; the kernel does not use
    // FS and the stub runs with interrupts off until `iretq`.
    unsafe {
        core::arch::asm!("mov fs, {sel:x}", sel = in(reg) wow64::USER_FS32 as u64, options(nostack, preserves_flags))
    };
    // SAFETY: forwarded caller contract; `frame` lives on this kernel stack
    // until `iretq` consumes it.
    unsafe { osyx_iret_to_user32(&frame, arg) }
}

/// Where a user thread starts in ring 3.
struct UserStart {
    rip: u64,
    rsp: u64,
    arg: u64,
}

/// Kernel-side entry of every user thread: drop to ring 3. The scheduler has
/// already loaded the process's CR3, kernel stack and FS base.
fn user_thread_entry(start: u64, _: u64) {
    // SAFETY: `start` is a `Box<UserStart>` leaked by `start_thread`.
    let s = unsafe { alloc::boxed::Box::from_raw(start as *mut UserStart) };
    let (rip, rsp, arg) = (s.rip, s.rsp, s.arg);
    drop(s);
    // SAFETY: the entry and stack lie in the user half of the address space
    // that is active for this thread; a bad value only faults in ring 3.
    unsafe { osyx_iret_to_user(rip, rsp, arg) }
}

/// Creates a thread of process `p` (caller holds no locks and has
/// interrupts disabled, so the tid is recorded before the thread can run).
fn start_thread(p: &mut Process, rip: u64, rsp: u64, arg: u64, fs_base: u64) -> Tid {
    let start = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(UserStart { rip, rsp, arg })) as u64;
    let tid = sched::spawn(&p.name, p.pid, p.space.root, user_thread_entry, start, 0, fs_base);
    p.threads.push(tid);
    tid
}

/// Logs the frame accounting of a released address space.
fn report_release(pid: Pid, name: &str, what: &str, (owned, freed): (u64, u64)) {
    if freed == owned {
        kprintln!("process {} ({}): {}released {} frames, no leak", pid, name, what, freed);
    } else {
        kprintln!("process {} ({}): {}FRAME LEAK: owned {}, released {}", pid, name, what, owned, freed);
    }
}

impl Process {
    fn new(parent: Pid, name: &str, cred: Cred, cwd: String, mut space: Space) -> Process {
        let program_shared = core::mem::take(&mut space.program_shared);
        Process {
            pid: NEXT_PID.fetch_add(1, Ordering::Relaxed),
            name: name.to_string(),
            parent,
            orphan: false,
            life: Life::Running,
            space,
            regions: BTreeMap::new(),
            shared: BTreeMap::new(),
            program_shared,
            next_map: MAP_BASE,
            mapped_pages: 0,
            line: Vec::new(),
            threads: Vec::new(),
            exited_cpu_ticks: 0,
            exit_status: None,
            cred,
            cwd,
        }
    }

    /// Removes every shared memory mapping (the frames stay with their
    /// objects; page tables stay with the address space).
    fn unmap_shared(&mut self) {
        shared_keys_clear(self.pid);
        unmap_shared_from(self.space.root, core::mem::take(&mut self.shared));
    }

    /// Releases the address space and checks the frame accounting.
    fn release_memory(&mut self) {
        unmap_images_from(self.space.root, core::mem::take(&mut self.regions));
        unmap_shared_from(self.space.root, core::mem::take(&mut self.program_shared));
        self.unmap_shared();
        // SAFETY: the address space is not active (the caller switched to the
        // kernel root or never activated it).
        let r = unsafe { self.space.release() };
        report_release(self.pid, &self.name, "", r);
    }

    fn flush_line(&mut self) {
        let line = String::from_utf8_lossy(&self.line).into_owned();
        self.line.clear();
        emit_line(&self.name, self.pid, line);
    }
}

/// Logs one line of a process's console output and keeps it in the tail.
fn emit_line(name: &str, pid: Pid, line: String) {
    kprintln!("[{}:{}] {}", name, pid, line);
    let mut tail = OUTPUT_TAIL.lock();
    if tail.len() == OUTPUT_TAIL_LINES {
        tail.pop_front();
    }
    tail.push_back(line);
}

/// Removes the page entries that point at shared image frames (the frames
/// belong to their sections, not to the address space).
fn unmap_images_from(root: u64, regions: BTreeMap<u64, Region>) {
    for (start, r) in regions {
        for d in r.swapped.values() {
            swap_stats_remove(d.data.len());
        }
        if r.image.is_some() {
            unmap_image_pages(root, start, &r, 0, r.pages);
        }
        if r.file.is_some() {
            unmap_file_pages(root, start, r.pages);
        }
    }
}

/// Clears the page entries of a file view: every frame belongs to the
/// section's backing and must not be freed with the address space.
fn unmap_file_pages(root: u64, start: u64, pages: u64) {
    paging::edit_range_in(root, start, start + pages * PAGE_SIZE, |_, _| paging::Leaf::Clear);
}

/// Clears the shared image entries among pages `first..last` of `r` (at
/// `start`); private pages stay mapped.
fn unmap_image_pages(root: u64, start: u64, r: &Region, first: u64, last: u64) {
    paging::edit_range_in(root, start + first * PAGE_SIZE, start + last * PAGE_SIZE, |va, frame| {
        if r.shares((va - start) / PAGE_SIZE, frame) {
            paging::Leaf::Clear
        } else {
            paging::Leaf::Keep
        }
    });
}

fn unmap_shared_from(root: u64, shared: BTreeMap<u64, (Arc<SharedMemory>, u64)>) {
    for (addr, (shm, pages)) in shared {
        for i in 0..pages {
            let _ = paging::unmap_in(root, addr + i * PAGE_SIZE, true);
        }
        drop(shm);
    }
}

/// Starts the program of `req` as a child of `parent`, with the parent's
/// credentials and current directory (root and `/` for the kernel).
/// Returns the new pid; the process runs concurrently.
pub fn spawn(parent: Pid, req: &ExecRequest) -> Result<Pid, ExecError> {
    spawn_with_stdio(parent, req, [None, None, None])
}

/// [`spawn`] with the child's handles 0, 1 and 2 set to `stdio`.
pub fn spawn_with_stdio(parent: Pid, req: &ExecRequest, stdio: [Option<Object>; 3]) -> Result<Pid, ExecError> {
    if TABLE.lock().procs.len() >= MAX_PROCESSES {
        return Err(ExecError::TooManyProcesses);
    }
    let cx = {
        let t = TABLE.lock();
        match t.procs.get(&parent) {
            Some(p) => Lookup { cred: p.cred, cwd: p.cwd.clone(), case_insensitive: false },
            None => Lookup::kernel(),
        }
    };
    let (space, entry, rsp, path) = build_image(&cx, req)?;
    let mut p = Process::new(parent, req.name(), cx.cred, cx.cwd, space);
    let pid = p.pid;
    {
        let mut handles = HANDLES.lock();
        let table = handles.entry(pid).or_default();
        for (i, o) in stdio.into_iter().enumerate() {
            if let Some(o) = o {
                table.insert(i as u64, o);
            }
        }
    }
    if p.name == "winrun" && !req.argv.iter().any(|a| a == "-contentproc") {
        crate::smp::set_sample_pid(pid);
    }
    const LOGGED_ARGS: usize = 8;
    let more = match req.argv.len() {
        n if n > LOGGED_ARGS => alloc::format!(" and {} more", n - LOGGED_ARGS),
        _ => String::new(),
    };
    let shown = &req.argv[..req.argv.len().min(LOGGED_ARGS)];
    kprintln!(
        "process {} ({}): {} spawned by {}, entry {:#x}, args {:?}{}",
        pid,
        p.name,
        path,
        parent,
        entry,
        shown,
        more
    );
    // With interrupts off the main thread cannot run (and exit) before the
    // process and its thread list are in the table.
    let were_enabled = cpu::interrupts_enabled();
    cpu::disable_interrupts();
    start_thread(&mut p, entry, rsp, 0, 0);
    TABLE.lock().procs.insert(pid, p);
    if were_enabled {
        cpu::enable_interrupts();
    }
    Ok(pid)
}

/// `thread_spawn` back end: a new thread in the current process.
pub fn spawn_thread(entry: u64, stack_top: u64, arg: u64, fs_base: u64) -> Result<Tid, Errno> {
    let user = paging::USER_START..osyx_abi::USER_END;
    if !user.contains(&entry) || !user.contains(&(stack_top.wrapping_sub(16))) || !stack_top.is_multiple_of(16) {
        return Err(Errno::InvalidArgument);
    }
    if fs_base != 0 && !user.contains(&fs_base) {
        return Err(Errno::InvalidArgument);
    }
    let pid = sched::current_pid();
    let were_enabled = cpu::interrupts_enabled();
    cpu::disable_interrupts();
    let r = {
        let mut t = TABLE.lock();
        match t.procs.get_mut(&pid) {
            Some(p) if p.exit_status.is_some() => Err(Errno::Interrupted),
            Some(p) if p.threads.len() >= osyx_abi::MAX_THREADS => Err(Errno::NoMemory),
            Some(p) => Ok(start_thread(p, entry, stack_top, arg, fs_base)),
            None => Err(Errno::NotSupported),
        }
    };
    if were_enabled {
        cpu::enable_interrupts();
    }
    r
}

/// `execve` back end: replaces the current process's program. Returns only
/// on failure, with the old program untouched. On success the old address
/// space is released and the thread drops to ring 3 at the new entry point;
/// the kernel stack of this system call is abandoned, so the caller must
/// not own anything that needs dropping (`req` is consumed here).
pub fn exec_current(req: ExecRequest) -> ExecError {
    let pid = sched::current_pid();
    let one_thread = |t: &Table| t.procs.get(&pid).is_some_and(|p| p.threads.len() == 1);
    if !one_thread(&TABLE.lock()) {
        return ExecError::Busy;
    }
    let cx = Lookup::current();
    let (mut space, entry, rsp, path) = match build_image(&cx, &req) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let name = String::from(req.name());
    drop(req);
    cpu::disable_interrupts();
    let old = {
        let mut t = TABLE.lock();
        if !one_thread(&t) {
            None
        } else {
            let p = t.procs.get_mut(&pid).expect("current process exists");
            core::mem::swap(&mut p.space, &mut space);
            let old_regions = core::mem::take(&mut p.regions);
            let new_program_shared = core::mem::take(&mut p.space.program_shared);
            let old_program_shared = core::mem::replace(&mut p.program_shared, new_program_shared);
            let old_shared = core::mem::take(&mut p.shared);
            shared_keys_clear(pid);
            p.next_map = MAP_BASE;
            p.mapped_pages = 0;
            p.name = name.clone();
            kprintln!("process {} ({}): exec {}, entry {:#x}", pid, name, path, entry);
            Some((p.space.root, old_shared, old_program_shared, old_regions))
        }
    };
    let Some((root, old_shared, old_program_shared, old_regions)) = old else {
        cpu::enable_interrupts();
        // SAFETY: the new space was never activated.
        unsafe { space.release() };
        return ExecError::Busy;
    };
    // `space` now holds the old image: leave it, then destroy it.
    // SAFETY: the new root maps the kernel half like every process root.
    unsafe { cpu::write_cr3(root) };
    sched::set_current_root(root);
    sched::rename_current(&name);
    sched::set_current_fs_base(0);
    sched::set_current_gs_base(0);
    sched::set_current_fs32_base(0);
    sched::reset_current_fpu();
    crate::user_fault::clear_process(pid);
    unmap_shared_from(space.root, old_shared);
    unmap_shared_from(space.root, old_program_shared);
    unmap_images_from(space.root, old_regions);
    // SAFETY: the old space is no longer active anywhere.
    let r = unsafe { space.release() };
    report_release(pid, &name, "old image ", r);
    drop((name, path));
    // SAFETY: entry and stack were mapped into the now active address space.
    unsafe { osyx_iret_to_user(entry, rsp, 0) }
}

/// Waits for child `target` of `parent` (any child if `target` is 0) to exit,
/// releases it and returns (pid, exit status).
pub fn wait(parent: Pid, target: Pid) -> Result<(Pid, i32), Errno> {
    loop {
        let were_enabled = cpu::interrupts_enabled();
        cpu::disable_interrupts();
        let outcome = {
            let mut t = TABLE.lock();
            let mut any = false;
            let mut done = None;
            for (pid, p) in t.procs.iter() {
                if p.parent == parent && !p.orphan && (target == 0 || *pid == target) {
                    any = true;
                    if let Life::Zombie(status) = p.life {
                        done = Some((*pid, status));
                        break;
                    }
                }
            }
            match (any, done) {
                (false, _) => Some(Err(Errno::NoChild)),
                (true, Some((pid, status))) => {
                    t.procs.remove(&pid);
                    Some(Ok((pid, status)))
                }
                (true, None) if sched::current_kill_pending() => Some(Err(Errno::Interrupted)),
                (true, None) => {
                    t.waiters.push((parent, sched::current_tid()));
                    sched::mark_current_blocked();
                    None
                }
            }
        };
        if outcome.is_none() {
            sched::schedule();
        }
        if were_enabled {
            cpu::enable_interrupts();
        }
        if let Some(r) = outcome {
            return r;
        }
    }
}

/// Terminates the current process with `status` and never returns. Called
/// from `exit` and when a CPU exception hits user code. Other threads of the
/// process are asked to end at their next safe point; the last thread to end
/// tears the process down.
pub fn exit_current(status: i32) -> ! {
    cpu::disable_interrupts();
    let pid = sched::current_pid();
    assert_ne!(pid, KERNEL_PID, "exit_current called by a kernel thread");
    let me = sched::current_tid();
    let others: Vec<Tid> = {
        let mut t = TABLE.lock();
        let p = t.procs.get_mut(&pid).expect("current process exists");
        p.exit_status.get_or_insert(status);
        p.threads.iter().copied().filter(|&t| t != me).collect()
    };
    for t in others {
        sched::request_kill(t);
    }
    finish_current_thread(status)
}

/// `thread_exit` back end: publishes `done_word` (store 1 + futex wake, now
/// that the thread no longer runs on its user stack) and ends the thread.
pub fn thread_exit(code: i32, done_word: u64) -> ! {
    if done_word != 0 && crate::fixup::copy_to_user(done_word, &1u32.to_le_bytes()).is_ok() {
        let _ = crate::futex::wake(done_word, u32::MAX);
    }
    finish_current_thread(code)
}

/// Ends the current user thread. The last thread of a process finalises it:
/// address space released, zombie with the exit status, parent woken.
pub fn finish_current_thread(code: i32) -> ! {
    cpu::disable_interrupts();
    let pid = sched::current_pid();
    let me = sched::current_tid();
    crate::user_fault::clear_thread(pid,me);
    let last = {
        let mut t = TABLE.lock();
        let p = t.procs.get_mut(&pid).expect("current process exists");
        p.exited_cpu_ticks = p.exited_cpu_ticks.saturating_add(sched::cpu_ticks(me));
        p.threads.retain(|&t| t != me);
        p.threads.is_empty()
    };
    if !last {
        sched::exit_current();
    }
    crate::user_fault::clear_process(pid);
    // Leave the process address space before destroying it.
    // SAFETY: the kernel root maps everything the kernel needs.
    unsafe { cpu::write_cr3(paging::kernel_root()) };
    sched::set_current_root(paging::kernel_root());
    crate::futex::forget_process(pid);
    let mut to_wake = Vec::new();
    let closed = HANDLES.lock().remove(&pid).unwrap_or_default();
    {
        let mut t = TABLE.lock();
        let Table { procs, waiters } = &mut *t;
        let p = procs.get_mut(&pid).expect("current process exists");
        let status = *p.exit_status.get_or_insert(code);
        if !p.line.is_empty() {
            p.flush_line();
        }
        p.release_memory();
        if !closed.is_empty() {
            kprintln!("process {} ({}): closed {} open handles", pid, p.name, closed.len());
        }
        p.life = Life::Zombie(status);
        let (parent, orphan) = (p.parent, p.orphan);
        // Threads of this process that were blocked in `wait` are gone.
        waiters.retain(|&(ppid, _)| ppid != pid);
        kprintln!("process {} ({}) exited with status {} ({:#x})", pid, p.name, status, status);
        // Children: zombies are released, running ones become kernel orphans.
        procs.retain(|_, c| !(c.parent == pid && c.life != Life::Running));
        for c in procs.values_mut().filter(|c| c.parent == pid) {
            c.parent = KERNEL_PID;
            c.orphan = true;
        }
        if orphan {
            procs.remove(&pid);
        } else {
            waiters.retain(|&(ppid, tid)| {
                if ppid == parent {
                    to_wake.push(tid);
                    false
                } else {
                    true
                }
            });
        }
    }
    // Volume metadata is written through, so dropping the files needs no I/O.
    // Pipe and channel ends wake their peers as they go.
    drop(closed);
    crate::display::owner_exited(pid);
    for tid in to_wake {
        sched::wake(tid);
    }
    sched::exit_current()
}

/// Adds an open file to the current process; returns the lowest free handle.
pub fn add_handle(f: vfs::OpenFile) -> Result<u64, Errno> {
    add_object(Object::File(Arc::new(KMutex::new(f))))
}

/// Adds objects to the current process: all of them or none; returns their
/// handles (lowest free numbers from `FIRST_FILE_HANDLE`).
pub fn add_objects(objects: Vec<Object>) -> Result<Vec<u64>, Errno> {
    let pid = sched::current_pid();
    let mut handles = HANDLES.lock();
    let p = handles.entry(pid).or_default();
    if p.len() + objects.len() > osyx_abi::MAX_HANDLES {
        return Err(Errno::TooManyHandles);
    }
    let mut out = Vec::with_capacity(objects.len());
    let mut h = osyx_abi::FIRST_FILE_HANDLE;
    for o in objects {
        while p.contains_key(&h) {
            h += 1;
        }
        p.insert(h, o);
        out.push(h);
    }
    Ok(out)
}

pub fn add_object(o: Object) -> Result<u64, Errno> {
    add_objects(alloc::vec![o]).map(|v| v[0])
}

/// The open file behind handle `h` (`BadHandle` for other objects).
pub fn get_handle(h: u64) -> Result<FileHandle, Errno> {
    match get_object(h)? {
        Object::File(f) => Ok(f),
        _ => Err(Errno::BadHandle),
    }
}

/// The object behind handle `h` of the current process.
pub fn get_object(h: u64) -> Result<Object, Errno> {
    let pid = sched::current_pid();
    let handles = HANDLES.lock();
    handles.get(&pid).and_then(|p| p.get(&h)).cloned().ok_or(Errno::BadHandle)
}

/// The shared memory object (as its address) and the offset in it behind
/// `addr`, if `addr` lies in one of the current process's shared mappings:
/// the futex key processes sharing that memory agree on.
pub fn shared_key(addr: u64) -> Option<(usize, u64)> {
    let pid = sched::current_pid();
    let index = SHARED_KEYS.lock();
    let (&(_, base), &(object, offset, pages)) = index.range((pid, 0)..=(pid, addr)).next_back()?;
    (addr < base + pages * PAGE_SIZE).then(|| (object, offset + (addr - base)))
}

/// Every process's shared mappings as (pid, base) -> (object, offset of the
/// base in it, pages): a copy of `Process::shared` for the futex fast path.
/// Futex wait and wake run on every contended Windows lock, and looking the
/// word up under the process table lock made them queue behind page faults
/// and mappings of all CPUs (the table lock was the top kernel cost in a
/// Zen profile). Lock order: the process table, then this index.
static SHARED_KEYS: IrqSpinLock<BTreeMap<(Pid, u64), (usize, u64, u64)>> = IrqSpinLock::new(BTreeMap::new());

fn shared_keys_add(pid: Pid, base: u64, shm: &SharedMemory, pages: u64) {
    let (object, offset) = shm.key(0);
    SHARED_KEYS.lock().insert((pid, base), (object, offset, pages));
}

fn shared_keys_remove(pid: Pid, base: u64) {
    SHARED_KEYS.lock().remove(&(pid, base));
}

fn shared_keys_clear(pid: Pid) {
    let mut index = SHARED_KEYS.lock();
    let bases: Vec<u64> = index.range((pid, 0)..=(pid, u64::MAX)).map(|(&(_, b), _)| b).collect();
    for b in bases {
        index.remove(&(pid, b));
    }
}

/// Maps `[offset, offset + len)` of a file section into the current process.
/// The region reserves the address range only: every page is loaded from the
/// section's backing on its first touch, so mapping a 177 MiB archive costs
/// no reads until it is used.
pub fn map_section(
    section: Arc<crate::filemap::Section>,
    offset: u64,
    len: u64,
    writable: bool,
) -> Result<u64, Errno> {
    use osyx_abi::{PROT_READ, PROT_WRITE};
    let prot = if writable { PROT_READ | PROT_WRITE } else { PROT_READ };
    let pages = len.div_ceil(PAGE_SIZE);
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    if p.mapped_pages + pages > MAP_LIMIT_PAGES {
        return Err(Errno::NoMemory);
    }
    let base = free_run(p, p.next_map, pages, PAGE_SIZE).ok_or(Errno::NoMemory)?;
    let mut region = Region::new(pages, prot);
    region.file = Some(FileRegion { section, first_page: offset / PAGE_SIZE });
    p.regions.insert(base, region);
    p.mapped_pages += pages;
    p.next_map = base + (pages + 1) * PAGE_SIZE; // leave a guard page
    Ok(base)
}

/// Maps all of `shm` into the current process (read-only unless
/// `writable`); returns the address.
pub fn map_shared(shm: Arc<SharedMemory>, writable: bool) -> Result<u64, Errno> {
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    let pages = shm.pages();
    if p.mapped_pages + pages > MAP_LIMIT_PAGES {
        return Err(Errno::NoMemory);
    }
    let base = free_run(p, p.next_map, pages, PAGE_SIZE).ok_or(Errno::NoMemory)?;
    let mut flags = Flags::user(writable, false);
    flags.write_combining = shm.write_combining;
    for (i, &frame) in shm.frames().iter().enumerate() {
        match paging::map_in(p.space.root, base + i as u64 * PAGE_SIZE, frame, flags) {
            Ok(tables) => p.space.frames += tables,
            Err(_) => {
                for j in 0..i as u64 {
                    let _ = paging::unmap_in(p.space.root, base + j * PAGE_SIZE, true);
                }
                return Err(Errno::NoMemory);
            }
        }
    }
    shared_keys_add(pid, base, &shm, pages);
    p.shared.insert(base, (shm, pages));
    p.mapped_pages += pages;
    p.next_map = base + (pages + 1) * PAGE_SIZE; // leave a guard page
    Ok(base)
}

/// Ends process `pid` on behalf of the current process (root, or the same
/// user). Its threads stop at their next safe point.
pub fn kill(pid: Pid) -> Result<(), Errno> {
    let me = sched::current_pid();
    let (my_cred, _) = current_identity();
    let threads: Vec<Tid> = {
        let mut t = TABLE.lock();
        let p = t.procs.get_mut(&pid).ok_or(Errno::NotFound)?;
        if !my_cred.is_root() && p.cred.uid != my_cred.uid {
            return Err(Errno::PermissionDenied);
        }
        if p.life != Life::Running {
            return Err(Errno::NotFound);
        }
        p.exit_status.get_or_insert(osyx_abi::KILLED_STATUS);
        p.threads.clone()
    };
    kprintln!("process {} killed by {}", pid, me);
    for t in threads {
        sched::request_kill(t);
    }
    Ok(())
}

fn make_info(p: &Process) -> osyx_abi::ipc::ProcInfo {
    let mut info = osyx_abi::ipc::ProcInfo {
        pid: p.pid,
        parent: p.parent,
        uid: p.cred.uid,
        gid: p.cred.gid,
        threads: p.threads.len() as u32,
        state: if p.life == Life::Running { osyx_abi::ipc::PROC_RUNNING } else { osyx_abi::ipc::PROC_ZOMBIE },
        frames: p.space.frames,
        name: [0; 32],
        cpu_ticks: p.exited_cpu_ticks.saturating_add(p.threads.iter().map(|&tid| sched::cpu_ticks(tid)).sum()),
    };
    osyx_abi::ipc::fill_field(&mut info.name, &p.name);
    info
}

/// The page table root of process `pid` for `working_set`: the caller's own
/// process, or another one if the caller is root or owns it.
pub fn working_set_root(pid: Pid, caller: Pid) -> Result<u64, Errno> {
    let t = TABLE.lock();
    let me = t.procs.get(&caller).map(|p| p.cred).unwrap_or(Cred::ROOT);
    let p = t.procs.get(&pid).ok_or(Errno::NotFound)?;
    if pid != caller && !me.is_root() && p.cred.uid != me.uid {
        return Err(Errno::PermissionDenied);
    }
    Ok(p.space.root)
}

/// The record for one process (for `proc_info`).
pub fn info(pid: Pid) -> Result<osyx_abi::ipc::ProcInfo, Errno> {
    TABLE.lock().procs.get(&pid).map(make_info).ok_or(Errno::NotFound)
}

/// One record per process (for `proc_list`).
pub fn list() -> Vec<osyx_abi::ipc::ProcInfo> {
    TABLE.lock().procs.values().map(make_info).collect()
}

/// Removes a handle. A system call still using the file keeps it alive
/// until that call returns.
pub fn close_handle(h: u64) -> Result<(), Errno> {
    let pid = sched::current_pid();
    let removed = HANDLES.lock().get_mut(&pid).and_then(|p| p.remove(&h));
    removed.map(drop).ok_or(Errno::BadHandle)
}

/// Last lines written by user processes (for the status screen).
pub fn output_tail() -> Vec<String> {
    OUTPUT_TAIL.lock().iter().cloned().collect()
}

/// Number of processes in the table (running and zombie).
pub fn count() -> usize {
    TABLE.lock().procs.len()
}

/// `write` back end: line-buffered output to the kernel log.
pub fn write_output(bytes: &[u8]) {
    let pid = sched::current_pid();
    // Lines are printed after the process table is unlocked: the serial
    // port is slow, and every handle lookup and page fault needs the table.
    let mut done = Vec::new();
    let name = {
        let mut t = TABLE.lock();
        let Some(p) = t.procs.get_mut(&pid) else { return };
        for &b in bytes {
            if b == b'\n' {
                done.push(String::from_utf8_lossy(&p.line).into_owned());
                p.line.clear();
            } else if p.line.len() < 4096 {
                p.line.push(b);
            }
        }
        if done.is_empty() {
            return;
        }
        p.name.clone()
    };
    for line in done {
        emit_line(&name, pid, line);
    }
}

/// Page flags for `prot`, W^X enforced.
fn prot_flags(prot: u64) -> Result<Flags, Errno> {
    use osyx_abi::{PROT_EXEC, PROT_READ, PROT_WRITE};
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return Err(Errno::InvalidArgument);
    }
    if prot & PROT_WRITE != 0 && prot & PROT_EXEC != 0 {
        return Err(Errno::PermissionDenied);
    }
    Ok(Flags::user(prot & PROT_WRITE != 0, prot & PROT_EXEC != 0))
}

/// `map` back end: zeroed anonymous memory, W^X enforced.
pub fn map_anonymous(len: u64, prot: u64) -> Result<u64, Errno> {
    map_ex(0, len, prot, 0)
}

/// `map_ex` back end: like `map`, at a fixed address (`MAP_FIXED`) or
/// 64 KiB aligned (`MAP_ALIGN_64K`).
pub fn map_ex(addr: u64, len: u64, prot: u64, mflags: u64) -> Result<u64, Errno> {
    use osyx_abi::{MAP_ALIGN_64K, MAP_FIXED};
    if len == 0 || mflags & !(MAP_FIXED | MAP_ALIGN_64K) != 0 {
        return Err(Errno::InvalidArgument);
    }
    prot_flags(prot)?;
    let pages = len.div_ceil(PAGE_SIZE);
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    if p.mapped_pages + pages > MAP_LIMIT_PAGES {
        return Err(Errno::NoMemory);
    }
    let base = if mflags & MAP_FIXED != 0 {
        let end = addr.checked_add(pages * PAGE_SIZE).ok_or(Errno::InvalidArgument)?;
        if !addr.is_multiple_of(PAGE_SIZE) || addr < paging::USER_START || end > STACK_LIMIT {
            return Err(Errno::InvalidArgument);
        }
        // Nothing may be mapped there yet: program, stack, shared memory,
        // or a region (whose untouched pages are not in the page tables).
        let overlaps = |m: &BTreeMap<u64, u64>| m.range(..end).next_back().is_some_and(|(&b, &n)| b + n * PAGE_SIZE > addr);
        let regions: BTreeMap<u64, u64> = p.regions.range(..end).next_back().map(|(&b, r)| (b, r.pages)).into_iter().collect();
        let shared: BTreeMap<u64, u64> = p.shared.range(..end).next_back().map(|(&b, s)| (b, s.1)).into_iter().collect();
        if overlaps(&regions)
            || overlaps(&shared)
            || (0..pages).any(|i| paging::translate_in(p.space.root, addr + i * PAGE_SIZE).is_some())
        {
            return Err(Errno::AlreadyExists);
        }
        addr
    } else {
        let align = if mflags & MAP_ALIGN_64K != 0 { 0x10000 } else { PAGE_SIZE };
        let base = free_run(p, p.next_map, pages, align).ok_or(Errno::NoMemory)?;
        // Leave a guard page. Fixed regions never move the cursor, so a
        // loader can keep images at the same far addresses in every process.
        p.next_map = base + (pages + 1) * PAGE_SIZE;
        base
    };
    // No frames yet: each page is filled with zeros on first access
    // (`demand_fault`).
    p.regions.insert(base, Region::new(pages, prot));
    p.mapped_pages += pages;
    Ok(base)
}

/// The first address at or above `from`, aligned to `align`, where `pages`
/// pages and the guard page after them overlap no region or shared mapping
/// (fixed mappings may lie above the cursor).
fn free_run(p: &Process, from: u64, pages: u64, align: u64) -> Option<u64> {
    let mut at = from.next_multiple_of(align);
    loop {
        let end = at.checked_add((pages + 1) * PAGE_SIZE)?;
        if end > STACK_LIMIT {
            return None;
        }
        // Mappings do not overlap, so only the last one starting before
        // `end` can reach into the run.
        let region = p.regions.range(..end).next_back().map(|(&b, r)| b + (r.pages + 1) * PAGE_SIZE);
        let shared = p.shared.range(..end).next_back().map(|(&b, s)| b + (s.1 + 1) * PAGE_SIZE);
        match region.into_iter().chain(shared).filter(|&e| e > at).max() {
            Some(e) => at = e.next_multiple_of(align),
            None => return Some(at),
        }
    }
}

/// `protect` back end: new protection for whole pages that all lie in one
/// anonymous region (W^X enforced; shared memory and program images keep
/// theirs).
pub fn protect(addr: u64, len: u64, prot: u64) -> Result<(), Errno> {
    let flags = prot_flags(prot)?;
    if len == 0 || !addr.is_multiple_of(PAGE_SIZE) {
        return Err(Errno::InvalidArgument);
    }
    let pages = len.div_ceil(PAGE_SIZE);
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    let root = p.space.root;
    let (&start, r) = p.regions.range_mut(..=addr).next_back().ok_or(Errno::InvalidArgument)?;
    if addr + pages * PAGE_SIZE > start + r.pages * PAGE_SIZE {
        return Err(Errno::InvalidArgument);
    }
    if let Some(f) = r.file.as_ref() {
        if flags.writable && !f.section.writable {
            return Err(Errno::PermissionDenied);
        }
    }
    // A page already touched keeps its frame under the new flags; the others
    // get them when first touched. Rewriting the leaf entries in one pass
    // avoids a page-table walk and a TLB shootdown per page, which matters
    // when a loader protects a whole image section.
    let first = (addr - start) / PAGE_SIZE;
    if r.image.is_some() && flags.writable {
        let shared = Flags { writable: false, ..flags };
        paging::edit_range_in(root, addr, addr + pages * PAGE_SIZE, |va, frame| {
            paging::Leaf::Flags(if r.shares((va - start) / PAGE_SIZE, frame) { shared } else { flags })
        });
    } else {
        paging::reprotect_range_in(root, addr, addr + pages * PAGE_SIZE, flags);
    }
    r.set_prot(first, first + pages, prot);
    Ok(())
}

/// Frees the frames of the touched pages in `addr..addr + pages` of region
/// `r` at `start` (the untouched ones have none; shared image frames are
/// only unmapped).
fn release_frames(space: &mut Space, start: u64, r: &Region, addr: u64, pages: u64) {
    if r.image.is_some() {
        let first = (addr - start) / PAGE_SIZE;
        unmap_image_pages(space.root, start, r, first, first + pages);
    }
    if r.file.is_some() {
        // Section frames, never owned by this address space.
        unmap_file_pages(space.root, addr, pages);
        return;
    }
    for i in 0..pages {
        let va = addr + i * PAGE_SIZE;
        if paging::translate_in(space.root, va).is_some() {
            if let Ok(frame) = paging::unmap_in(space.root, va, true) {
                let _ = free_frame(frame);
                space.frames -= 1;
            }
        }
    }
}

/// `discard` back end: whole pages inside one anonymous region lose their
/// contents and frames; the next access reads zeros again.
pub fn discard(addr: u64, len: u64) -> Result<(), Errno> {
    if len == 0 || !addr.is_multiple_of(PAGE_SIZE) {
        return Err(Errno::InvalidArgument);
    }
    let pages = len.div_ceil(PAGE_SIZE);
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    let (&start, r) = p.regions.range_mut(..=addr).next_back().ok_or(Errno::InvalidArgument)?;
    if addr + pages * PAGE_SIZE > start + r.pages * PAGE_SIZE || r.file.is_some() {
        return Err(Errno::InvalidArgument);
    }
    release_frames(&mut p.space, start, r, addr, pages);
    let first = (addr - start) / PAGE_SIZE;
    let gone: Vec<u64> = r.swapped.range(first..first + pages).map(|(&k, _)| k).collect();
    for k in gone {
        if let Some(d) = r.swapped.remove(&k) {
            swap_stats_remove(d.data.len());
        }
    }
    Ok(())
}

/// Pages mapped per chunk of a bulk prefault: each chunk takes the process
/// table only for the pages it maps, so a long run never waits on the entry
/// lock it does not need.
const PREFAULT_CHUNK_PAGES: u64 = 256;

/// TEMP prefault diagnostics: pages requested, chunks whose pages were
/// mapped, chunks skipped because the process table was busy, and TSC cycles
/// spent inside prefault_write.
pub static PF_STATS: [core::sync::atomic::AtomicU64; 4] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 4];

pub fn prefault_stats() -> [u64; 4] {
    PF_STATS.each_ref().map(|a| a.load(core::sync::atomic::Ordering::Relaxed))
}

/// Allocates the anonymous destination pages of a bulk copy without taking
/// one user page-fault round trip per page. Invalid addresses and allocation
/// failures are left for the copy's usual fault handling. Locks only what it
/// touches (process table, paging, frames): the run is private to the calling
/// process, and the entry lock is what made an image prefault wait most of a
/// second behind other CPUs' disk work.
pub fn prefault_write(addr: u64, len: usize) {
    if len < PAGE_SIZE as usize {
        return;
    }
    let t0 = unsafe { core::arch::x86_64::_rdtsc() };
    let end = (addr + len as u64).next_multiple_of(PAGE_SIZE);
    let mut page = addr & !(PAGE_SIZE - 1);
    let (mut chunks, mut skipped) = (0u64, 0u64);
    PF_STATS[0].fetch_add((end - page) / PAGE_SIZE, core::sync::atomic::Ordering::Relaxed);
    while page < end {
        let stop = end.min(page + PREFAULT_CHUNK_PAGES * PAGE_SIZE);
        let next = prefault_range(page, stop);
        if next == stop { chunks += 1 } else { skipped += 1 };
        page = next;
    }
    PF_STATS[1].fetch_add(chunks, core::sync::atomic::Ordering::Relaxed);
    PF_STATS[2].fetch_add(skipped, core::sync::atomic::Ordering::Relaxed);
    let t1 = unsafe { core::arch::x86_64::_rdtsc() };
    PF_STATS[3].fetch_add(t1.wrapping_sub(t0), core::sync::atomic::Ordering::Relaxed);
}

/// Maps the writable anonymous pages of `[page, end)` and returns the address
/// to continue from (`end` if the process table is busy).
fn prefault_range(mut page: u64, end: u64) -> u64 {
    let pid = sched::current_pid();
    let Some(mut t) = TABLE.try_lock() else { return end };
    let Some(p) = t.procs.get_mut(&pid) else { return end };
    while page < end {
        let Some((&start, r)) = p.regions.range(..=page).next_back() else {
            page += PAGE_SIZE;
            continue;
        };
        if page >= start + r.pages * PAGE_SIZE {
            page += PAGE_SIZE;
            continue;
        }
        // A file view gets its frames from the section, never zeroed here.
        if r.file.is_some() {
            page += PAGE_SIZE;
            continue;
        }
        let prot = r.prot_at((page - start) / PAGE_SIZE);
        let Ok(flags) = prot_flags(prot) else {
            page += PAGE_SIZE;
            continue;
        };
        if !flags.writable || r.swapped.contains_key(&((page - start) / PAGE_SIZE)) {
            page += PAGE_SIZE;
            continue;
        }
        let mut run_end = page + PAGE_SIZE;
        while run_end < end {
            let Some((&next_start, next)) = p.regions.range(..=run_end).next_back() else { break };
            if run_end >= next_start + next.pages * PAGE_SIZE
                || prot_flags(next.prot_at((run_end - next_start) / PAGE_SIZE)) != Ok(flags)
                || next.swapped.contains_key(&((run_end - next_start) / PAGE_SIZE))
            {
                break;
            }
            run_end += PAGE_SIZE;
        }
        let (mapped, tables) = paging::map_zeroed_range_in(p.space.root, page, run_end, flags);
        p.space.frames += mapped + tables;
        page = run_end;
    }
    page
}

/// Pages mapped per fault when the following pages of the same run are
/// mapped too: sequential copies (image layout, reads) then take one trap
/// per 64 KiB instead of one per page.
const FAULT_AROUND_PAGES: u64 = 16;

/// A page fault on a not-present page at `va`: if it lies in an anonymous
/// region or the main stack of the current process, maps zeroed frames there
/// and returns true (the access is retried). False for any other address, an
/// access the mapping's protection forbids, a busy process table (the faulting
/// code holds it) or exhausted memory: the fault then takes its usual path.
pub fn demand_fault(va: u64, write: bool, fetch: bool) -> bool {
    demand_fault_in(va, write, fetch, false) == Demand::Mapped
}

/// [`demand_fault`] for a fault raised by user code. User code cannot hold the
/// process table, so waiting for a busy one is safe — and necessary: another
/// CPU entering the kernel must not turn a first touch of heap or stack into
/// an access violation in the process.
pub fn demand_fault_user(va: u64, write: bool, fetch: bool) -> bool {
    // Only user faults may sleep: a kernel fault can hold locks needed by
    // reclaim. Bound the wait in case no pages can be reclaimed.
    for _ in 0..1000 {
        match demand_fault_in(va, write, fetch, true) {
            Demand::Mapped => return true,
            Demand::Refused => return false,
            Demand::NoMemory => {
                let worker = SWAP_THREAD.load(Ordering::Acquire);
                if worker == 0 {
                    return false;
                }
                sched::wake(worker);
                sched::sleep_ticks(crate::arch::timer::ms_to_ticks(1));
            }
        }
    }
    false
}

/// How long a fault in a kernel copy waits for a busy process table. The
/// copy may run on behalf of the holder itself, so it must not wait without
/// bound; every other holder (a fault on another CPU, the swap thread, a
/// bulk prefault) releases it within a few milliseconds.
const KERNEL_FAULT_WAIT_MS: u64 = 20;

/// The process table for a fault in a kernel copy (see
/// [`KERNEL_FAULT_WAIT_MS`]); `None` when it stayed busy.
fn lock_table_briefly() -> Option<crate::sync::IrqGuard<'static, Table>> {
    if let Some(t) = TABLE.try_lock() {
        return Some(t);
    }
    let deadline = crate::arch::timer::Deadline::after_ms(KERNEL_FAULT_WAIT_MS);
    loop {
        core::hint::spin_loop();
        if let Some(t) = TABLE.try_lock() {
            return Some(t);
        }
        if deadline.expired() {
            return None;
        }
    }
}

// ---- compressed memory ------------------------------------------------------------------

/// The swap thread starts compressing when free memory falls below
/// 1/`SWAP_LOW_DIVISOR` of all memory (at least `SWAP_MIN_LOW_FRAMES`)
/// and stops at twice that.
const SWAP_LOW_DIVISOR: u64 = 16;
const SWAP_MIN_LOW_FRAMES: u64 = 8192;
/// Pages examined per process table hold.
const SWAP_BATCH: u64 = 64;
/// Bound a single scan, including pages that are hot or incompressible.
const SWAP_SCAN_PAGES: u64 = 256;
/// Continue aging a bounded number of windows even if none yielded a page.
const SWAP_EMPTY_SCANS: u32 = 16;
/// Pages compressed to at most this many bytes are kept; others stay.
const SWAP_MAX_COMPRESSED: usize = (PAGE_SIZE as usize) * 3 / 4;
/// Compressed pages live on the kernel heap (at most 1 GiB, shared with
/// everything else): beyond this many bytes only all-zero pages, which
/// take no space, are still moved out.
const SWAP_MAX_BYTES: u64 = 256 << 20;

static SWAPPED_PAGES: AtomicU64 = AtomicU64::new(0);
static SWAP_THREAD: AtomicU64 = AtomicU64::new(0);
static SWAPPED_BYTES: AtomicU64 = AtomicU64::new(0);
static SWAP_OUT: AtomicU64 = AtomicU64::new(0);
static SWAP_IN: AtomicU64 = AtomicU64::new(0);
static SWAP_QUICK_REFAULTS: AtomicU64 = AtomicU64::new(0);
static SWAP_PROTECTED_SCANS: AtomicU64 = AtomicU64::new(0);
/// Next process the reclaim scan starts with (round robin).
static SWAP_CURSOR: AtomicU64 = AtomicU64::new(0);

fn swap_stats_remove(len: usize) {
    SWAPPED_PAGES.fetch_sub(1, Ordering::Relaxed);
    SWAPPED_BYTES.fetch_sub(len as u64, Ordering::Relaxed);
}

/// (pages in compressed memory, bytes they use, pages compressed, pages
/// restored) since boot.
pub fn swap_stats() -> (u64, u64, u64, u64) {
    (
        SWAPPED_PAGES.load(Ordering::Relaxed),
        SWAPPED_BYTES.load(Ordering::Relaxed),
        SWAP_OUT.load(Ordering::Relaxed),
        SWAP_IN.load(Ordering::Relaxed),
    )
}

pub fn swap_adaptive_stats() -> (u64, u64) {
    (SWAP_QUICK_REFAULTS.load(Ordering::Relaxed), SWAP_PROTECTED_SCANS.load(Ordering::Relaxed))
}

/// Compresses up to `want` cold (not recently accessed) writable private
/// pages of user processes and frees their frames; returns how many.
/// Shared memory, file views and image sections are never touched. A page
/// is unmapped before it is read, so no thread can change it unseen; its
/// next access faults and `demand_fault` restores it.
pub fn reclaim(want: u64) -> u64 {
    let mut done = 0u64;
    let pids: Vec<Pid> = TABLE.lock().procs.keys().copied().collect();
    if pids.is_empty() {
        return 0;
    }
    let first = SWAP_CURSOR.fetch_add(1, Ordering::Relaxed) as usize % pids.len();
    let (free, total) = crate::mem::frame_stats();
    let emergency = free < (total / SWAP_LOW_DIVISOR).max(SWAP_MIN_LOW_FRAMES) / 2;
    let mut buf = alloc::vec![0u8; SWAP_MAX_COMPRESSED];
    for k in 0..pids.len() {
        if done >= want {
            break;
        }
        let pid = pids[(first + k) % pids.len()];
        let mut t = TABLE.lock();
        let Some(p) = t.procs.get_mut(&pid) else { continue };
        if !matches!(p.life, Life::Running) {
            continue;
        }
        let root = p.space.root;
        // File views are clean copies owned by their section: compressing
        // them would duplicate data and break the frame accounting.
        let starts: Vec<u64> =
            p.regions.iter().filter(|(_, r)| r.image.is_none() && r.file.is_none()).map(|(&s, _)| s).collect();
        for start in starts {
            if done >= want {
                break;
            }
            let r = &p.regions[&start];
            if r.refault_guard.protects(crate::interrupts::ticks(), emergency) {
                SWAP_PROTECTED_SCANS.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let scan_start = start + r.reclaim_cursor * PAGE_SIZE;
            let scan_end = (scan_start + SWAP_SCAN_PAGES * PAGE_SIZE).min(start + r.pages * PAGE_SIZE);
            // Reserved up front: the visit holds the paging lock, and a heap
            // that had to grow inside it would take that lock again.
            let mut cold = Vec::with_capacity(SWAP_BATCH as usize);
            let mut aged = false;
            let mut next = scan_end;
            paging::age_range_in(root, scan_start, scan_end, |va, frame, accessed, writable| {
                aged |= accessed;
                if !accessed && writable {
                    cold.push((va, frame));
                }
                if cold.len() as u64 >= SWAP_BATCH {
                    next = va + PAGE_SIZE;
                    false
                } else {
                    true
                }
            });
            let r = p.regions.get_mut(&start).expect("region exists");
            r.reclaim_cursor = if next >= start + r.pages * PAGE_SIZE { 0 } else { (next - start) / PAGE_SIZE };
            if aged {
                // Cached translations would not set the cleared bits again:
                // every page used from now on must look used to the next scan.
                crate::smp::flush_remote(root, false);
            }
            for (va, _frame) in cold {
                if done >= want {
                    break;
                }
                let full = SWAPPED_BYTES.load(Ordering::Relaxed) >= SWAP_MAX_BYTES;
                let Ok(frame) = paging::unmap_in(root, va, true) else { continue };
                // SAFETY: the frame is no longer mapped anywhere; it stays
                // owned by this address space until freed below.
                let page = unsafe { &*(phys_to_virt(frame) as *const [u8; PAGE_SIZE as usize]) };
                let stored: Option<alloc::boxed::Box<[u8]>> = if page.iter().all(|&b| b == 0) {
                    Some(alloc::boxed::Box::new([]))
                } else if full {
                    None
                } else {
                    osyx_mm::lz::compress(page, &mut buf).and_then(|n| {
                        if n as u64 > SWAP_MAX_BYTES.saturating_sub(SWAPPED_BYTES.load(Ordering::Relaxed)) {
                            return None;
                        }
                        // A heap that cannot grow keeps the page as it is.
                        let mut data = Vec::new();
                        data.try_reserve_exact(n).ok()?;
                        data.extend_from_slice(&buf[..n]);
                        Some(data.into_boxed_slice())
                    })
                };
                let r = p.regions.get_mut(&start).expect("region exists");
                match stored {
                    Some(data) => {
                        SWAPPED_PAGES.fetch_add(1, Ordering::Relaxed);
                        SWAPPED_BYTES.fetch_add(data.len() as u64, Ordering::Relaxed);
                        SWAP_OUT.fetch_add(1, Ordering::Relaxed);
                        r.swapped.insert((va - start) / PAGE_SIZE, SwappedPage { data, evicted_at: crate::interrupts::ticks() });
                        let _ = free_frame(frame);
                        p.space.frames -= 1;
                        done += 1;
                    }
                    None => {
                        // Not worth keeping compressed: put it back unchanged.
                        // Its page table is still there, so this cannot fail
                        // for lack of memory.
                        let flags = prot_flags(r.prot_at((va - start) / PAGE_SIZE)).unwrap_or(Flags::user(true, false));
                        if paging::map_in(root, va, frame, flags).is_err() {
                            kprintln!("swap: cannot put back {va:#x} of process {pid}; its contents are lost");
                            let _ = free_frame(frame);
                            p.space.frames -= 1;
                        }
                    }
                }
            }
        }
    }
    done
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestoreError {
    NotCompressed,
    NoMemory,
    Corrupt,
    Map(MapError),
}

/// Brings page `index` of region `r` (at `start`) back from compressed
/// memory and maps it under `flags`; returns the page tables added. The
/// compressed copy stays when this fails.
fn restore_page(root: u64, start: u64, r: &mut Region, index: u64, flags: Flags) -> Result<u64, RestoreError> {
    let data = r.swapped.get(&index).ok_or(RestoreError::NotCompressed)?;
    let frame = alloc_frame().ok_or(RestoreError::NoMemory)?;
    if !data.data.is_empty() {
        // SAFETY: a fresh frame owned here, reachable through the HHDM.
        let dst = unsafe { &mut *(phys_to_virt(frame) as *mut [u8; PAGE_SIZE as usize]) };
        if osyx_mm::lz::decompress(&data.data, dst).is_err() {
            let _ = free_frame(frame);
            return Err(RestoreError::Corrupt);
        }
    }
    match paging::map_in(root, start + index * PAGE_SIZE, frame, flags) {
        Ok(tables) => {
            let page = r.swapped.remove(&index).expect("compressed page exists");
            let len = page.data.len();
            let now = crate::interrupts::ticks();
            if r.refault_guard.restored(page.evicted_at, now, crate::arch::timer::ms_to_ticks(2000), 8, crate::arch::timer::ms_to_ticks(2000)) {
                SWAP_QUICK_REFAULTS.fetch_add(1, Ordering::Relaxed);
            }
            swap_stats_remove(len);
            SWAP_IN.fetch_add(1, Ordering::Relaxed);
            Ok(tables)
        }
        Err(MapError::OutOfMemory) => {
            let _ = free_frame(frame);
            Err(RestoreError::NoMemory)
        }
        Err(e) => {
            let _ = free_frame(frame);
            Err(RestoreError::Map(e))
        }
    }
}

/// Restores every compressed page of `r` (at `start`) under its region
/// protection, counting the frames in `frames`. Code that reads a region's
/// frames through the page tables, not by user accesses that fault, must
/// call this first.
fn restore_swapped(root: u64, frames: &mut u64, start: u64, r: &mut Region) -> Result<(), Errno> {
    let pages: Vec<u64> = r.swapped.keys().copied().collect();
    for index in pages {
        let flags = prot_flags(r.prot_at(index)).unwrap_or(Flags::user(false, false));
        let tables = restore_page(root, start, r, index, flags).map_err(|_| Errno::NoMemory)?;
        *frames += 1 + tables;
    }
    Ok(())
}

/// Starts the thread that keeps free memory above the low watermark by
/// compressing cold pages.
pub fn start_swap() {
    let tid = sched::spawn_kernel("swap", swap_thread, 0, 0);
    SWAP_THREAD.store(tid, Ordering::Release);
}

fn swap_thread(_: u64, _: u64) {
    let mut reported = 0u64;
    let (_, total) = crate::mem::frame_stats();
    let low = (total / SWAP_LOW_DIVISOR).max(SWAP_MIN_LOW_FRAMES);
    let high = low * 2;
    kprintln!("swap: compressing cold pages below {} MiB free (up to {} MiB of compressed data)", low >> 8, SWAP_MAX_BYTES >> 20);
    loop {
        // Use the scheduler's remembered wake-up so a request arriving just
        // before the worker blocks cannot be lost.
        let enabled = crate::arch::cpu::interrupts_enabled();
        crate::arch::cpu::disable_interrupts();
        let deadline = crate::interrupts::ticks() + crate::arch::timer::ms_to_ticks(200);
        sched::mark_current_blocked_until(Some(deadline));
        sched::schedule();
        if enabled {
            crate::arch::cpu::enable_interrupts();
        }
        let (free, _) = crate::mem::frame_stats();
        if free >= low {
            continue;
        }
        let mut freed = 0;
        let mut empty_scans = 0;
        while crate::mem::frame_stats().0 < high {
            let n = reclaim(SWAP_BATCH);
            // Give the entry lock and the CPU back between batches.
            sched::yield_now();
            if n == 0 {
                empty_scans += 1;
                if empty_scans >= SWAP_EMPTY_SCANS {
                    break;
                }
            } else {
                empty_scans = 0;
            }
            freed += n;
        }
        let (pages, bytes, _, _) = swap_stats();
        if freed > 0 && (reported == 0 || pages >> 12 != reported >> 12) {
            reported = pages;
            kprintln!("swap: {} pages ({} MiB) in {} KiB of compressed memory", pages, pages >> 8, bytes >> 10);
        }
    }
}

/// Outcome of [`demand_fault_in`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Demand {
    /// The page is there now: retry the access.
    Mapped,
    /// No free frame; reclaim may make one.
    NoMemory,
    /// Not a page this process may have (or the table stayed busy).
    Refused,
}

fn demand_fault_in(va: u64, write: bool, fetch: bool, wait: bool) -> Demand {
    if !(paging::USER_START..osyx_abi::USER_END).contains(&va) {
        return Demand::Refused;
    }
    let pid = sched::current_pid();
    let mut t = if wait {
        TABLE.lock()
    } else {
        match lock_table_briefly() {
            Some(t) => t,
            None => return Demand::Refused,
        }
    };
    let Some(p) = t.procs.get_mut(&pid) else { return Demand::Refused };
    let page = va & !(PAGE_SIZE - 1);
    let around = page + FAULT_AROUND_PAGES * PAGE_SIZE;
    let (flags, run_end) = if (STACK_TOP - STACK_PAGES * PAGE_SIZE..STACK_TOP).contains(&page) {
        if fetch {
            return Demand::Refused;
        }
        (Flags::user(true, false), around.min(STACK_TOP))
    } else {
        let root = p.space.root;
        let Some((&start, r)) = p.regions.range_mut(..=page).next_back() else { return Demand::Refused };
        let region_end = start + r.pages * PAGE_SIZE;
        if page >= region_end {
            return Demand::Refused;
        }
        let prot = r.prot_at((page - start) / PAGE_SIZE);
        let Ok(flags) = prot_flags(prot) else { return Demand::Refused };
        if (write && !flags.writable) || (fetch && !flags.executable) {
            return Demand::Refused;
        }
        let index = (page - start) / PAGE_SIZE;
        // A file view: load the page outside the process table, then map it
        // under the table again (the region may have been unmapped meanwhile).
        if let Some(f) = r.file.as_ref() {
            let first = f.first_page + index;
            let section = f.section.clone();
            drop(t);
            return file_fault(page, first, section, write, fetch, wait);
        }
        if r.swapped.contains_key(&index) {
            if paging::translate_in(root, page).is_some() {
                return Demand::Mapped;
            }
            return match restore_page(root, start, r, index, flags) {
                Ok(tables) => {
                    p.space.frames += 1 + tables;
                    Demand::Mapped
                }
                Err(RestoreError::NoMemory) => Demand::NoMemory,
                Err(e) => {
                    kprintln!("process {pid}: cannot restore {page:#x} from compressed memory: {e:?}");
                    Demand::Refused
                }
            };
        }
        // Only pages with the same protection may be mapped in one run, and
        // never over a page that lives in compressed memory.
        let mut end = page + PAGE_SIZE;
        while end < region_end
            && end < around
            && prot_flags(r.prot_at((end - start) / PAGE_SIZE)) == Ok(flags)
            && !r.swapped.contains_key(&((end - start) / PAGE_SIZE))
        {
            end += PAGE_SIZE;
        }
        (flags, end)
    };
    if paging::translate_in(p.space.root, page).is_some() {
        return Demand::Mapped; // mapped meanwhile: retry
    }
    let (mapped, tables) = paging::map_zeroed_range_in(p.space.root, page, run_end, flags);
    p.space.frames += mapped + tables;
    if mapped != 0 {
        Demand::Mapped
    } else {
        Demand::NoMemory
    }
}

/// Maps one page of a file view after loading it from the section. The disk
/// read runs without the process table; the region is re-validated before the
/// frame goes in, so a concurrent `unmap` or `execve` wins.
fn file_fault(page: u64, file_page: u64, section: Arc<crate::filemap::Section>, write: bool, fetch: bool, wait: bool) -> Demand {
    let shm = match section.page(file_page) {
        Ok(shm) => shm,
        Err(Errno::NoMemory) => return Demand::NoMemory,
        Err(e) => {
            kprintln!("filemap: read page {} failed: {}", file_page, e.name());
            return Demand::Refused;
        }
    };
    let pid = sched::current_pid();
    let mut t = if wait {
        TABLE.lock()
    } else {
        match lock_table_briefly() {
            Some(t) => t,
            None => return Demand::Refused,
        }
    };
    let Some(p) = t.procs.get_mut(&pid) else { return Demand::Refused };
    let Some((&start, r)) = p.regions.range(..=page).next_back() else { return Demand::Refused };
    // The section must still be there: the region may have been replaced.
    if !r.file.as_ref().is_some_and(|f| Arc::ptr_eq(&f.section, &section)) {
        return Demand::Refused;
    }
    let index = (page - start) / PAGE_SIZE;
    if index >= r.pages {
        return Demand::Refused;
    }
    let flags = match prot_flags(r.prot_at(index)) {
        Ok(flags) => flags,
        Err(_) => return Demand::Refused,
    };
    if (write && !flags.writable) || (fetch && !flags.executable) {
        return Demand::Refused;
    }
    if paging::translate_in(p.space.root, page).is_some() {
        return Demand::Mapped;
    }
    match paging::map_in(p.space.root, page, shm.frames()[0], flags) {
        Ok(tables) => {
            p.space.frames += tables;
            Demand::Mapped
        }
        Err(MapError::OutOfMemory) => Demand::NoMemory,
        Err(_) => Demand::Refused,
    }
}

/// `unmap` back end: releases exactly one region previously returned by
/// `map` or `shm_map`.
pub fn unmap_region(addr: u64, len: u64) -> Result<(), Errno> {
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    if let Some((_, pages)) = p.shared.get(&addr) {
        if len.div_ceil(PAGE_SIZE) != *pages {
            return Err(Errno::InvalidArgument);
        }
        let pages = *pages;
        let entry = p.shared.remove(&addr).expect("checked above");
        shared_keys_remove(pid, addr);
        p.mapped_pages -= pages;
        let root = p.space.root;
        let mut one = BTreeMap::new();
        one.insert(addr, entry);
        unmap_shared_from(root, one);
        return Ok(());
    }
    let pages = p.regions.get(&addr).ok_or(Errno::InvalidArgument)?.pages;
    if len.div_ceil(PAGE_SIZE) != pages {
        return Err(Errno::InvalidArgument);
    }
    let r = p.regions.remove(&addr).expect("checked above");
    release_frames(&mut p.space, addr, &r, addr, pages);
    for d in r.swapped.values() {
        swap_stats_remove(d.data.len());
    }
    p.mapped_pages -= pages;
    Ok(())
}

/// A write to a present read-only page at `va`: if the page is a shared
/// image frame in a region the process may write, it gets a private copy and
/// the access is retried. False for every other protection fault. `wait`
/// as in [`demand_fault_user`]: kernel copies must not wait for a process
/// table they might hold.
pub fn cow_fault(va: u64, wait: bool) -> bool {
    if !(paging::USER_START..osyx_abi::USER_END).contains(&va) {
        return false;
    }
    let pid = sched::current_pid();
    let mut t = if wait {
        TABLE.lock()
    } else {
        match lock_table_briefly() {
            Some(t) => t,
            None => return false,
        }
    };
    let Some(p) = t.procs.get_mut(&pid) else { return false };
    let page = va & !(PAGE_SIZE - 1);
    let Some((&start, r)) = p.regions.range(..=page).next_back() else { return false };
    if r.image.is_none() || page >= start + r.pages * PAGE_SIZE {
        return false;
    }
    let index = (page - start) / PAGE_SIZE;
    let Ok(flags) = prot_flags(r.prot_at(index)) else { return false };
    if !flags.writable {
        return false;
    }
    let Some(now) = paging::translate_in(p.space.root, page) else {
        return true; // unmapped meanwhile: the retry takes the demand path
    };
    if now.writable {
        return true; // another thread copied it already
    }
    let shared = now.phys & !(PAGE_SIZE - 1);
    if !r.shares(index, shared) {
        return false;
    }
    let Some(frame) = alloc_frame() else {
        kprintln!("process {pid}: out of memory copying image page {page:#x}");
        return false;
    };
    // SAFETY: `frame` is fresh and `shared` is kept alive by the region's
    // section; both are RAM pages reachable through the HHDM.
    unsafe {
        core::ptr::copy_nonoverlapping(phys_to_virt(shared) as *const u8, phys_to_virt(frame) as *mut u8, PAGE_SIZE as usize)
    };
    match paging::replace_in(p.space.root, page, frame, flags) {
        Ok(_) => {
            p.space.frames += 1;
            true
        }
        Err(_) => {
            let _ = free_frame(frame);
            false
        }
    }
}

/// The region `[addr, addr + len)` exactly, if it is an anonymous mapping
/// of the current process without an image yet.
fn image_region(regions: &mut BTreeMap<u64, Region>, addr: u64, len: u64) -> Result<&mut Region, Errno> {
    let r = regions.get_mut(&addr).ok_or(Errno::InvalidArgument)?;
    if len == 0 || len.div_ceil(PAGE_SIZE) != r.pages {
        return Err(Errno::InvalidArgument);
    }
    if r.image.is_some() {
        return Err(Errno::AlreadyExists);
    }
    Ok(r)
}

/// `image_publish` back end: the image laid out in the region at `addr`
/// becomes section `key`. Its pages move into the section (untouched ones
/// become zeroed frames) and stay mapped read-only in this process.
pub fn image_publish(key: image::Key) -> Result<Arc<ImageSection>, Errno> {
    let (addr, len) = (key.base, key.pages * PAGE_SIZE);
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    let root = p.space.root;
    let r = image_region(&mut p.regions, addr, len)?;
    let pages = r.pages;
    let (free, _) = crate::mem::frame_stats();
    if pages + 4096 > free {
        return Err(Errno::NoMemory);
    }
    // Pages of the laid-out image may have gone to compressed memory; the
    // section is built from the page tables, so they must be back first.
    restore_swapped(root, &mut p.space.frames, addr, r)?;
    // Collect the frames under read-only entries in one pass (one shootdown).
    let mut frames = alloc::vec![0u64; pages as usize];
    let mut moved = 0u64;
    paging::edit_range_in(root, addr, addr + len, |va, frame| {
        frames[((va - addr) / PAGE_SIZE) as usize] = frame;
        moved += 1;
        let prot = prot_flags(r.prot_at((va - addr) / PAGE_SIZE)).unwrap_or(Flags::user(false, false));
        paging::Leaf::Flags(Flags { writable: false, ..prot })
    });
    // Pages never touched read zeros: give them zeroed frames too.
    let (mut tables, mut added) = (0, 0);
    for (i, f) in frames.iter_mut().enumerate() {
        if *f != 0 {
            continue;
        }
        let va = addr + i as u64 * PAGE_SIZE;
        let prot = prot_flags(r.prot_at(i as u64)).unwrap_or(Flags::user(false, false));
        let Some(new) = alloc_frame() else { break };
        match paging::map_in(root, va, new, Flags { writable: false, ..prot }) {
            Ok(n) => {
                *f = new;
                tables += n;
                added += 1;
            }
            Err(_) => {
                let _ = free_frame(new);
                break;
            }
        }
    }
    p.space.frames += tables + added;
    if frames.contains(&0) {
        // Out of memory: every page stays an ordinary private page.
        paging::edit_range_in(root, addr, addr + len, |va, _| {
            paging::Leaf::Flags(prot_flags(r.prot_at((va - addr) / PAGE_SIZE)).unwrap_or(Flags::user(false, false)))
        });
        return Err(Errno::NoMemory);
    }
    let section = ImageSection::new(key, frames);
    r.image = Some(section.clone());
    // The frames now belong to the section; the page tables stay ours.
    p.space.frames -= moved + added;
    Ok(section)
}

/// `image_map` back end: maps `section` into the untouched region at its
/// base, every page read-only (writes copy).
pub fn image_map(section: Arc<ImageSection>) -> Result<(), Errno> {
    let key = *section.key();
    let (addr, len) = (key.base, key.pages * PAGE_SIZE);
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    let root = p.space.root;
    let r = image_region(&mut p.regions, addr, len)?;
    if (0..r.pages).any(|i| paging::translate_in(root, addr + i * PAGE_SIZE).is_some()) {
        return Err(Errno::Busy);
    }
    let mut tables = 0;
    for (i, &frame) in section.frames().iter().enumerate() {
        let va = addr + i as u64 * PAGE_SIZE;
        let prot = prot_flags(r.prot_at(i as u64)).unwrap_or(Flags::user(false, false));
        match paging::map_in(root, va, frame, Flags { writable: false, ..prot }) {
            Ok(n) => tables += n,
            Err(_) => {
                for j in 0..i as u64 {
                    let _ = paging::unmap_in(root, addr + j * PAGE_SIZE, true);
                }
                p.space.frames += tables;
                return Err(Errno::NoMemory);
            }
        }
    }
    p.space.frames += tables;
    r.image = Some(section);
    Ok(())
}

/// Credentials and current directory of the calling process (root and `/`
/// for kernel threads).
pub fn current_identity() -> (Cred, String) {
    let pid = sched::current_pid();
    let t = TABLE.lock();
    t.procs.get(&pid).map_or((Cred::ROOT, String::from("/")), |p| (p.cred, p.cwd.clone()))
}

pub fn set_current_cwd(cwd: String) -> Result<(), Errno> {
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    p.cwd = cwd;
    Ok(())
}

/// `setuid`: only root may change identity (permanently, for this process
/// and its future children).
pub fn set_current_cred(cred: Cred) -> Result<(), Errno> {
    let pid = sched::current_pid();
    let mut t = TABLE.lock();
    let p = t.procs.get_mut(&pid).ok_or(Errno::NotSupported)?;
    if !p.cred.is_root() {
        return Err(Errno::PermissionDenied);
    }
    p.cred = cred;
    Ok(())
}
