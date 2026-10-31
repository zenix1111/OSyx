//! OSyx back end: system calls, process start-up, heap and panic handling.

use crate::error::{Error, Result};
use crate::io::ChunkWriter;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use osyx_abi::{SystemInfo, PROT_READ, PROT_WRITE};
use osyx_mm::heap::Heap;

pub const NAME: &str = "osyx";

pub fn write(fd: u64, buf: &[u8]) -> Result<usize> {
    os_sys::write(fd, buf).map_err(Error::from)
}

pub fn read_stdin(buf: &mut [u8]) -> Result<usize> {
    os_sys::read(osyx_abi::STDIN, buf).map_err(Error::from)
}

pub fn read_handle(handle: u64, buf: &mut [u8]) -> Result<usize> {
    os_sys::read(handle, buf).map_err(Error::from)
}

pub fn exit(code: i32) -> ! {
    os_sys::exit(code)
}

pub fn monotonic_ns() -> Result<u64> {
    os_sys::clock(osyx_abi::CLOCK_MONOTONIC).map_err(Error::from)
}

pub fn sysinfo() -> Result<SystemInfo> {
    os_sys::sysinfo().map_err(Error::from)
}

pub fn spawn(path: &str, argv: &[u8], envp: &[u8]) -> Result<u64> {
    os_sys::spawn(path, argv, envp).map_err(Error::from)
}

pub fn execve(path: &str, argv: &[u8], envp: &[u8]) -> Error {
    Error::from(os_sys::execve(path, argv, envp))
}

pub fn wait(pid: u64) -> Result<(u64, i32)> {
    os_sys::wait(pid).map_err(Error::from)
}

pub fn sleep_ns(ns: u64) {
    os_sys::sleep(ns)
}

pub fn yield_now() {
    os_sys::yield_now()
}

pub fn realtime_ns() -> Result<i64> {
    os_sys::clock(osyx_abi::CLOCK_REALTIME).map(|v| v as i64).map_err(Error::from)
}

// ---- files -------------------------------------------------------------------

pub mod fs {
    use crate::error::{Error, ErrorKind, Result};
    use alloc::string::String;
    use alloc::vec::Vec;
    use osyx_abi::{DirRecord, FileStat, FsStat};

    /// A kernel file handle, closed on drop.
    pub struct RawFile(u64);

    impl RawFile {
        pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
            let n = buf.len().min(osyx_abi::MAX_READ);
            os_sys::read(self.0, &mut buf[..n]).map_err(Error::from)
        }

        pub fn write(&self, buf: &[u8]) -> Result<usize> {
            let n = buf.len().min(osyx_abi::MAX_WRITE);
            os_sys::write(self.0, &buf[..n]).map_err(Error::from)
        }

        pub fn seek(&self, offset: i64, whence: u64) -> Result<u64> {
            os_sys::seek(self.0, offset, whence).map_err(Error::from)
        }

        pub fn stat(&self) -> Result<FileStat> {
            os_sys::fstat(self.0).map_err(Error::from)
        }

        pub fn set_len(&self, len: u64) -> Result<()> {
            os_sys::ftruncate(self.0, len).map_err(Error::from)
        }

        pub fn sync(&self) -> Result<()> {
            os_sys::fsync(self.0).map_err(Error::from)
        }

        pub fn handle(&self) -> u64 {
            self.0
        }
    }

    impl Drop for RawFile {
        fn drop(&mut self) {
            let _ = os_sys::close(self.0);
        }
    }

    pub fn open(path: &str, flags: u64, mode: u32) -> Result<RawFile> {
        os_sys::open(path, flags, mode).map(RawFile).map_err(Error::from)
    }

    pub fn stat(path: &str) -> Result<FileStat> {
        os_sys::stat(path).map_err(Error::from)
    }

    pub fn lstat(path: &str) -> Result<FileStat> {
        os_sys::lstat(path).map_err(Error::from)
    }

    /// The whole listing of a directory: (name, ino, kind).
    pub fn read_dir(path: &str) -> Result<Vec<(String, u64, u32)>> {
        let dir = open(path, osyx_abi::OPEN_READ | osyx_abi::OPEN_DIRECTORY, 0)?;
        let mut buf = alloc::vec![0u8; 4096];
        let mut out = Vec::new();
        loop {
            let n = os_sys::readdir(dir.0, &mut buf).map_err(Error::from)?;
            if n == 0 {
                return Ok(out);
            }
            let mut off = 0;
            while off < n {
                let bad = || Error::new(ErrorKind::InvalidData, "malformed directory record");
                let (r, name, len) = DirRecord::decode(&buf[off..n]).ok_or_else(bad)?;
                let name = core::str::from_utf8(name).map_err(|_| bad())?;
                out.push((String::from(name), r.ino, r.kind));
                off += len;
            }
        }
    }

    pub fn mkdir(path: &str, mode: u32) -> Result<()> {
        os_sys::mkdir(path, mode).map_err(Error::from)
    }

    pub fn unlink(path: &str) -> Result<()> {
        os_sys::unlink(path).map_err(Error::from)
    }

    pub fn rmdir(path: &str) -> Result<()> {
        os_sys::rmdir(path).map_err(Error::from)
    }

    pub fn rename(from: &str, to: &str) -> Result<()> {
        os_sys::rename(from, to).map_err(Error::from)
    }

    pub fn symlink(target: &str, path: &str) -> Result<()> {
        os_sys::symlink(target, path).map_err(Error::from)
    }

    pub fn readlink(path: &str) -> Result<String> {
        let mut buf = alloc::vec![0u8; osyx_abi::MAX_PATH];
        let n = os_sys::readlink(path, &mut buf).map_err(Error::from)?;
        String::from_utf8(buf[..n].to_vec()).map_err(|_| Error::new(ErrorKind::InvalidData, "link target is not UTF-8"))
    }

    pub fn chmod(path: &str, mode: u32) -> Result<()> {
        os_sys::chmod(path, mode).map_err(Error::from)
    }

    pub fn chdir(path: &str) -> Result<()> {
        os_sys::chdir(path).map_err(Error::from)
    }

    pub fn getcwd() -> Result<String> {
        let mut buf = alloc::vec![0u8; osyx_abi::MAX_PATH];
        let n = os_sys::getcwd(&mut buf).map_err(Error::from)?;
        String::from_utf8(buf[..n].to_vec()).map_err(|_| Error::new(ErrorKind::InvalidData, "cwd is not UTF-8"))
    }

    pub fn statfs(path: &str) -> Result<FsStat> {
        os_sys::statfs(path).map_err(Error::from)
    }

    pub fn mount(source: &str, target: &str, fstype: &str, flags: u64, size_limit: u64) -> Result<()> {
        os_sys::mount(source, target, fstype, flags, size_limit).map_err(Error::from)
    }

    pub fn umount(path: &str) -> Result<()> {
        os_sys::umount(path).map_err(Error::from)
    }

    pub fn getuid() -> (u32, u32) {
        os_sys::getuid()
    }

    pub fn setuid(uid: u32, gid: u32) -> Result<()> {
        os_sys::setuid(uid, gid).map_err(Error::from)
    }

    pub fn set_time(unix_ns: u64) -> Result<()> {
        os_sys::set_time(unix_ns).map_err(Error::from)
    }
}
// ---- threads, futexes, TLS --------------------------------------------------

/// Stack size of threads created with `thread::spawn` (the region `map`
/// returns is followed by a guard page; the previous region's guard page
/// lies below it).
pub const DEFAULT_STACK: usize = 256 * 1024;

/// A started thread whose stack must be released once it has finished.
pub struct RawThread {
    stack: *mut u8,
    stack_len: usize,
}

// SAFETY: the stack is only touched by the thread itself and freed after it
// has provably left it (its done word is 1).
unsafe impl Send for RawThread {}

struct Start {
    entry: fn(usize),
    arg: usize,
    done: *const AtomicU32,
}

global_asm!(
    r#"
    .section .text
    // First instruction of every thread created by thread_spawn: rdi = Start.
    .global osyx_rt_thread_entry
osyx_rt_thread_entry:
    and rsp, -16
    xor ebp, ebp
    call osyx_rt_thread_start
    ud2
    "#
);

extern "C" {
    fn osyx_rt_thread_entry();
}

#[no_mangle]
unsafe extern "C" fn osyx_rt_thread_start(start: *mut Start) -> ! {
    // SAFETY: leaked by `thread_spawn` for exactly this thread.
    let s = alloc::boxed::Box::from_raw(start);
    let (entry, arg, done) = (s.entry, s.arg, s.done);
    drop(s);
    entry(arg);
    // The kernel publishes `done` after we have left this stack.
    os_sys::thread_exit(0, done as *const u32)
}

/// Starts `entry(arg)` on a new thread with thread pointer `tcb`. When it
/// returns the kernel stores 1 to `done` and wakes its futex waiters.
pub fn thread_spawn(entry: fn(usize), arg: usize, tcb: usize, done: &AtomicU32, stack: usize) -> Result<RawThread> {
    let stack_len = stack.max(16 * 1024).next_multiple_of(4096);
    let base = os_sys::map(stack_len, PROT_READ | PROT_WRITE).map_err(Error::from)?;
    let start = alloc::boxed::Box::into_raw(alloc::boxed::Box::new(Start { entry, arg, done }));
    let top = base as usize + stack_len;
    match os_sys::thread_spawn(osyx_rt_thread_entry as *const () as usize, top, start as usize, tcb) {
        Ok(_) => Ok(RawThread { stack: base, stack_len }),
        Err(e) => {
            // SAFETY: the thread was not created, so nothing else owns these.
            unsafe {
                drop(alloc::boxed::Box::from_raw(start));
                let _ = os_sys::unmap(base, stack_len);
            }
            Err(Error::from(e))
        }
    }
}

/// Frees the stack of a thread whose done word is 1.
pub fn thread_release(t: RawThread) {
    // SAFETY: the thread has exited, nothing references its stack.
    let _ = unsafe { os_sys::unmap(t.stack, t.stack_len) };
}

/// Blocks while `word == expected`; false if the timeout expired.
pub fn futex_wait(word: &AtomicU32, expected: u32, timeout: Option<core::time::Duration>) -> bool {
    let ns = timeout.map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX).max(1));
    !matches!(os_sys::futex_wait(word.as_ptr(), expected, ns), Err(osyx_abi::Errno::TimedOut))
}

/// Like [`futex_wait`] without a timeout, on a lock held by thread `owner`
/// (0: unknown), which inherits the caller's priority while it waits.
pub fn futex_wait_owned(word: &AtomicU32, expected: u32, owner: u64) {
    let _ = os_sys::futex_wait_owned(word.as_ptr(), expected, 0, owner);
}

pub fn futex_wake(word: *const AtomicU32, count: u32) {
    os_sys::futex_wake(word as *const u32, count);
}

/// The current thread pointer (`fs:[0]`, which holds the TCB's own address).
pub fn tcb() -> usize {
    let p: usize;
    // SAFETY: the runtime installs a TCB before any code can ask for it
    // (main thread in `osyx_rt_start`, other threads in `thread::spawn`).
    unsafe { core::arch::asm!("mov {}, fs:[0]", out(reg) p, options(nostack, readonly, preserves_flags)) };
    p
}

pub fn set_tcb(p: usize) {
    os_sys::set_fs_base(p).expect("set_fs_base rejected the TCB address");
}

pub fn current_tid() -> u64 {
    os_sys::gettid()
}

// ---- start-up -------------------------------------------------------------

static ARGC: AtomicUsize = AtomicUsize::new(0);
static ARGV: AtomicUsize = AtomicUsize::new(0);
static ENVC: AtomicUsize = AtomicUsize::new(0);
static ENVP: AtomicUsize = AtomicUsize::new(0);
static AUXV: AtomicUsize = AtomicUsize::new(0);

/// Environment strings scanned at most (the kernel's own limit).
const MAX_ENV: u64 = osyx_abi::MAX_EXEC_STRINGS as u64;
/// Auxiliary pairs scanned at most.
const MAX_AUX: u64 = 64;

/// Reads a start-up stack word.
fn word(addr: u64) -> u64 {
    // SAFETY: only called with addresses inside the start-up data the kernel
    // placed on the main stack, which stays mapped for the whole run.
    unsafe { core::ptr::read(addr as *const u64) }
}

global_asm!(
    r#"
    .section .text._start, "ax"
    .global _start
_start:
    mov rdi, rsp        // -> argc, argv[], NULL, envp[], NULL, auxv
    and rsp, -16
    xor ebp, ebp        // terminate frame-pointer chains
    call osyx_rt_start
    ud2
    "#
);

extern "Rust" {
    /// Defined by `os_std::entry!` in the program.
    fn __osyx_user_main() -> i32;
}

#[no_mangle]
unsafe extern "C" fn osyx_rt_start(sp: *const usize) -> ! {
    // The kernel builds the start-up stack described in `osyx_abi::startup`:
    // pointers to NUL-terminated strings that live for the whole run.
    let Some(l) = osyx_abi::startup::locate(sp as u64, MAX_ENV, word) else {
        let _ = os_sys::write(osyx_abi::STDERR, b"OSyx Std: malformed start-up stack\n");
        exit(127)
    };
    ARGC.store(l.argc as usize, Ordering::Relaxed);
    ARGV.store(l.argv as usize, Ordering::Relaxed);
    ENVC.store(l.envc as usize, Ordering::Relaxed);
    ENVP.store(l.envp as usize, Ordering::Relaxed);
    AUXV.store(l.auxv as usize, Ordering::Relaxed);
    crate::tls::init_main_thread();
    let code = __osyx_user_main();
    // Returning from main ends the whole process (other threads included).
    exit(code)
}

/// The NUL-terminated string at `p`.
///
/// # Safety
/// `p` must point to a NUL-terminated string that stays valid.
unsafe fn c_str(p: *const u8) -> &'static [u8] {
    let mut len = 0;
    while *p.add(len) != 0 {
        len += 1;
    }
    core::slice::from_raw_parts(p, len)
}

/// `count` strings from the pointer array at `array`.
fn strings(array: usize, count: usize) -> Vec<String> {
    (0..count)
        // SAFETY: the array and its strings come from the start-up stack.
        .map(|i| unsafe { String::from_utf8_lossy(c_str(*(array as *const *const u8).add(i))).into_owned() })
        .collect()
}

pub fn args() -> Vec<String> {
    strings(ARGV.load(Ordering::Relaxed), ARGC.load(Ordering::Relaxed))
}

/// The environment the program was started with (`KEY=value` strings).
pub fn initial_env() -> Vec<String> {
    strings(ENVP.load(Ordering::Relaxed), ENVC.load(Ordering::Relaxed))
}

/// Value of auxiliary vector entry `key` (`osyx_abi::auxv`).
pub fn aux_value(key: u64) -> Option<u64> {
    match AUXV.load(Ordering::Relaxed) {
        0 => None,
        a => osyx_abi::startup::aux_value(a as u64, key, MAX_AUX, word),
    }
}

/// The program path the kernel loaded (`AT_EXECFN`).
pub fn current_exe() -> Result<String> {
    let p = aux_value(osyx_abi::auxv::AT_EXECFN).ok_or_else(|| Error::unsupported("no AT_EXECFN entry"))?;
    // SAFETY: AT_EXECFN points to a NUL-terminated string on the start-up stack.
    Ok(String::from_utf8_lossy(unsafe { c_str(p as *const u8) }).into_owned())
}

// ---- heap -----------------------------------------------------------------

/// Minimum amount of address space requested from the kernel per growth.
const GROW_MIN: usize = 256 * 1024;
/// Blocks this large get a kernel mapping of their own, returned to the
/// kernel when freed (the heap never shrinks its regions).
const LARGE: usize = 1024 * 1024;

fn is_large(layout: Layout) -> bool {
    layout.size() >= LARGE && layout.align() <= 4096
}

struct UserHeap {
    locked: AtomicBool,
    heap: UnsafeCell<Heap>,
    /// Used instead of `heap` once `os_sys::set_low_map` is on: its regions
    /// lie below 4 GiB, where 32-bit (WoW64) code can reach them. Blocks
    /// of `heap` mapped earlier still go back to `heap`.
    low: UnsafeCell<Heap>,
}

// SAFETY: all access to `heap` happens while `locked` is held.
unsafe impl Sync for UserHeap {}

impl UserHeap {
    fn with<R>(&self, f: impl FnOnce(&mut Heap) -> R) -> R {
        self.with_heap(os_sys::low_map(), f)
    }

    fn with_heap<R>(&self, low: bool, f: impl FnOnce(&mut Heap) -> R) -> R {
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        let heap = if low { &self.low } else { &self.heap };
        // SAFETY: the lock gives exclusive access.
        let r = f(unsafe { &mut *heap.get() });
        self.locked.store(false, Ordering::Release);
        r
    }
}

#[global_allocator]
static HEAP: UserHeap =
    UserHeap { locked: AtomicBool::new(false), heap: UnsafeCell::new(Heap::new()), low: UnsafeCell::new(Heap::new()) };

// SAFETY: blocks come from `Heap`, which hands out disjoint, aligned ranges
// of memory the kernel mapped for this process.
unsafe impl GlobalAlloc for UserHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if is_large(layout) {
            // Page aligned and zeroed by the kernel.
            return os_sys::map(layout.size().next_multiple_of(4096), PROT_READ | PROT_WRITE).unwrap_or(core::ptr::null_mut());
        }
        self.with(|h| {
            if let Some(p) = h.alloc(layout) {
                return p.as_ptr();
            }
            let need = Heap::block_size(layout) + layout.align() + 16;
            let size = need.max(GROW_MIN).next_multiple_of(4096);
            match os_sys::map(size, PROT_READ | PROT_WRITE) {
                Ok(base) => {
                    // SAFETY: fresh, zeroed, writable mapping owned by the heap.
                    unsafe { h.add_region(base as usize, size) };
                    h.alloc(layout).map_or(core::ptr::null_mut(), |p| p.as_ptr())
                }
                Err(_) => core::ptr::null_mut(),
            }
        })
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if is_large(layout) {
            // SAFETY: forwarded; kernel mappings are already zeroed.
            return unsafe { self.alloc(layout) };
        }
        // SAFETY: forwarded.
        let p = unsafe { self.alloc(layout) };
        if !p.is_null() {
            // SAFETY: `p` holds `layout.size()` bytes.
            unsafe { core::ptr::write_bytes(p, 0, layout.size()) };
        }
        p
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if is_large(layout) {
            // SAFETY: a mapping made by `alloc` above for this layout.
            let _ = unsafe { os_sys::unmap(ptr, layout.size().next_multiple_of(4096)) };
            return;
        }
        if let Some(p) = core::ptr::NonNull::new(ptr) {
            // A block below 4 GiB comes from the low heap only once low
            // mode is on (the normal heap's regions lie far higher).
            let low = os_sys::low_map() && (ptr as usize) < 1 << 32;
            // SAFETY: forwarded caller contract.
            self.with_heap(low, |h| unsafe { h.dealloc(p, layout) });
        }
    }
}

/// Heap statistics, for diagnostics.
pub fn heap_stats() -> osyx_mm::heap::HeapStats {
    HEAP.with(|h| h.stats())
}

// ---- panics ---------------------------------------------------------------

static PANICKING: AtomicBool = AtomicBool::new(false);

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    if PANICKING.swap(true, Ordering::Relaxed) {
        exit(101); // panic while panicking: do not try to print again
    }
    let mut w = ChunkWriter::<256, _>::new(|c: &[u8]| {
        let _ = os_sys::write(osyx_abi::STDERR, c);
        Ok(())
    });
    let _ = core::fmt::write(&mut w, format_args!("program panicked: {}\n", info));
    let _ = w.finish();
    exit(101)
}
