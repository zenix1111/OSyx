//! Host back end, used only to unit-test OSyx Std on the development machine.
//! It is implemented with the host's Rust std; nothing here runs on OSyx.
// thread_local! initializers here are `const` already; clippy 1.99 still
// reports missing_const_for_thread_local for them.
#![allow(clippy::missing_const_for_thread_local)]

use crate::error::{Error, ErrorKind, Result};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use osyx_abi::SystemInfo;
use std::io::Write as _;

pub const NAME: &str = "host";

pub fn write(fd: u64, buf: &[u8]) -> Result<usize> {
    let r = match fd {
        osyx_abi::STDOUT => std::io::stdout().write(buf),
        osyx_abi::STDERR => std::io::stderr().write(buf),
        _ => return Err(Error::from(osyx_abi::Errno::BadHandle)),
    };
    r.map_err(|_| Error::new(ErrorKind::Other, "host write failed"))
}

pub fn read_stdin(buf: &mut [u8]) -> Result<usize> {
    use std::io::Read;
    std::io::stdin().read(buf).map_err(|_| Error::new(ErrorKind::Other, "host read failed"))
}

pub fn read_handle(_handle: u64, buf: &mut [u8]) -> Result<usize> {
    read_stdin(buf)
}

pub fn exit(code: i32) -> ! {
    std::process::exit(code)
}

pub fn monotonic_ns() -> Result<u64> {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(std::time::Instant::now);
    Ok(start.elapsed().as_nanos() as u64)
}

pub fn sysinfo() -> Result<SystemInfo> {
    Err(Error::unsupported("sysinfo is only available on OSyx"))
}

pub fn args() -> Vec<String> {
    std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect()
}

pub fn spawn(_path: &str, _argv: &[u8], _envp: &[u8]) -> Result<u64> {
    Err(Error::unsupported("starting OSyx programs is only possible on OSyx"))
}

pub fn execve(_path: &str, _argv: &[u8], _envp: &[u8]) -> Error {
    Error::unsupported("execve of OSyx programs is only possible on OSyx")
}

/// The host process's environment as `KEY=value` strings.
pub fn initial_env() -> Vec<String> {
    std::env::vars_os().map(|(k, v)| alloc::format!("{}={}", k.to_string_lossy(), v.to_string_lossy())).collect()
}

pub fn current_exe() -> Result<String> {
    std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|_| Error::new(ErrorKind::Other, "host current_exe failed"))
}

pub fn wait(_pid: u64) -> Result<(u64, i32)> {
    Err(Error::unsupported("waiting for OSyx processes is only possible on OSyx"))
}

pub fn sleep_ns(ns: u64) {
    std::thread::sleep(std::time::Duration::from_nanos(ns))
}

pub fn yield_now() {
    std::thread::yield_now()
}

pub fn realtime_ns() -> Result<i64> {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| ErrorKind::Other)?;
    Ok(d.as_nanos() as i64)
}

// Files: OSyx paths are mapped below a per-process scratch directory of the
// host, so the OSyx Std file API can be unit-tested against a real file
// system. This says nothing about the OSyx kernel's VFS or its drivers.
// Symbolic links, ownership and mounts are not emulated (`Unsupported`).
pub mod fs {
    use crate::error::{Error, ErrorKind, Result};
    use alloc::string::String;
    use alloc::vec::Vec;
    use osyx_abi::{FileStat, FsStat};
    use std::io::{Read as _, Seek as _, Write as _};

    pub struct RawFile(std::fs::File);

    fn err(e: std::io::Error) -> Error {
        use std::io::ErrorKind as K;
        Error::from(match e.kind() {
            K::NotFound => ErrorKind::NotFound,
            K::AlreadyExists => ErrorKind::AlreadyExists,
            K::PermissionDenied => ErrorKind::PermissionDenied,
            K::InvalidInput | K::InvalidFilename => ErrorKind::InvalidInput,
            K::NotADirectory => ErrorKind::NotADirectory,
            K::IsADirectory => ErrorKind::IsADirectory,
            K::DirectoryNotEmpty => ErrorKind::DirectoryNotEmpty,
            K::UnexpectedEof => ErrorKind::UnexpectedEof,
            _ => ErrorKind::Other,
        })
    }

    /// Host directory that plays the OSyx root (created on first use).
    pub fn host_root() -> &'static std::path::Path {
        static ROOT: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        ROOT.get_or_init(|| {
            let dir = std::env::temp_dir().join(alloc::format!("os-std-fs-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
            dir
        })
    }

    static CWD: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

    /// Lexically resolved OSyx path (absolute, or relative to the emulated cwd).
    fn resolve(path: &str) -> Result<String> {
        let cwd = {
            let c = CWD.lock().unwrap_or_else(|e| e.into_inner());
            if c.is_empty() { String::from("/") } else { c.clone() }
        };
        osyx_vfs_free_normalize(&cwd, path)
    }

    fn osyx_vfs_free_normalize(cwd: &str, path: &str) -> Result<String> {
        if path.is_empty() || path.contains('\0') {
            return Err(Error::new(ErrorKind::InvalidInput, "empty path"));
        }
        let mut parts: Vec<&str> = Vec::new();
        let base = if path.starts_with('/') { "" } else { cwd };
        for c in base.split('/').chain(path.split('/')) {
            match c {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                c => parts.push(c),
            }
        }
        Ok(alloc::format!("/{}", parts.join("/")))
    }

    fn map(path: &str) -> Result<std::path::PathBuf> {
        let abs = resolve(path)?;
        let mut p = host_root().to_path_buf();
        p.extend(abs.split('/').filter(|c| !c.is_empty()));
        Ok(p)
    }

    fn stat_of(md: &std::fs::Metadata) -> FileStat {
        let ro = md.permissions().readonly();
        let (kind, mode) = if md.is_dir() {
            (osyx_abi::KIND_DIR, 0o755)
        } else {
            (osyx_abi::KIND_FILE, if ro { 0o444 } else { 0o644 })
        };
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos() as i64);
        FileStat {
            size: if md.is_dir() { 0 } else { md.len() },
            kind,
            mode,
            nlink: 1,
            mtime_ns: mtime,
            atime_ns: mtime,
            ctime_ns: mtime,
            attributes: if ro { osyx_abi::ATTR_READ_ONLY } else { 0 },
            ..Default::default()
        }
    }

    impl RawFile {
        pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
            (&self.0).read(buf).map_err(err)
        }

        pub fn write(&self, buf: &[u8]) -> Result<usize> {
            (&self.0).write(buf).map_err(err)
        }

        pub fn seek(&self, offset: i64, whence: u64) -> Result<u64> {
            let pos = match whence {
                osyx_abi::SEEK_SET => std::io::SeekFrom::Start(u64::try_from(offset).map_err(|_| ErrorKind::InvalidInput)?),
                osyx_abi::SEEK_CUR => std::io::SeekFrom::Current(offset),
                _ => std::io::SeekFrom::End(offset),
            };
            (&self.0).seek(pos).map_err(err)
        }

        pub fn stat(&self) -> Result<FileStat> {
            self.0.metadata().map(|m| stat_of(&m)).map_err(err)
        }

        pub fn set_len(&self, len: u64) -> Result<()> {
            self.0.set_len(len).map_err(err)
        }

        pub fn sync(&self) -> Result<()> {
            self.0.sync_all().map_err(err)
        }
    }

    pub fn open(path: &str, flags: u64, _mode: u32) -> Result<RawFile> {
        use osyx_abi::*;
        let target = map(path)?;
        if target.is_dir() {
            return Err(Error::new(ErrorKind::Unsupported, "the host back end cannot open directories as files"));
        }
        std::fs::OpenOptions::new()
            .read(flags & OPEN_READ != 0)
            .write(flags & OPEN_WRITE != 0 && flags & OPEN_APPEND == 0)
            .append(flags & OPEN_APPEND != 0)
            .truncate(flags & OPEN_TRUNCATE != 0)
            .create(flags & OPEN_CREATE != 0 && flags & OPEN_EXCLUSIVE == 0)
            .create_new(flags & OPEN_EXCLUSIVE != 0)
            .open(target)
            .map(RawFile)
            .map_err(err)
    }

    pub fn stat(path: &str) -> Result<FileStat> {
        std::fs::metadata(map(path)?).map(|m| stat_of(&m)).map_err(err)
    }

    pub fn lstat(path: &str) -> Result<FileStat> {
        stat(path)
    }

    pub fn read_dir(path: &str) -> Result<Vec<(String, u64, u32)>> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(map(path)?).map_err(err)? {
            let e = e.map_err(err)?;
            let kind = if e.file_type().map_err(err)?.is_dir() { osyx_abi::KIND_DIR } else { osyx_abi::KIND_FILE };
            out.push((e.file_name().to_string_lossy().into_owned(), 0, kind));
        }
        Ok(out)
    }

    pub fn mkdir(path: &str, _mode: u32) -> Result<()> {
        std::fs::create_dir(map(path)?).map_err(err)
    }

    pub fn unlink(path: &str) -> Result<()> {
        std::fs::remove_file(map(path)?).map_err(err)
    }

    pub fn rmdir(path: &str) -> Result<()> {
        std::fs::remove_dir(map(path)?).map_err(err)
    }

    pub fn rename(from: &str, to: &str) -> Result<()> {
        std::fs::rename(map(from)?, map(to)?).map_err(err)
    }

    pub fn symlink(_target: &str, _path: &str) -> Result<()> {
        Err(Error::unsupported("symbolic links are not emulated by the host back end"))
    }

    pub fn readlink(_path: &str) -> Result<String> {
        Err(Error::unsupported("symbolic links are not emulated by the host back end"))
    }

    pub fn chmod(path: &str, mode: u32) -> Result<()> {
        let p = map(path)?;
        let mut perm = std::fs::metadata(&p).map_err(err)?.permissions();
        perm.set_readonly(mode & 0o222 == 0);
        std::fs::set_permissions(p, perm).map_err(err)
    }

    pub fn chdir(path: &str) -> Result<()> {
        let abs = resolve(path)?;
        if !map(&abs)?.is_dir() {
            return Err(Error::from(ErrorKind::NotADirectory));
        }
        *CWD.lock().unwrap_or_else(|e| e.into_inner()) = abs;
        Ok(())
    }

    pub fn getcwd() -> Result<String> {
        resolve(".")
    }

    pub fn statfs(_path: &str) -> Result<FsStat> {
        Err(Error::unsupported("statfs is only available on OSyx"))
    }

    pub fn mount(_s: &str, _t: &str, _f: &str, _flags: u64, _limit: u64) -> Result<()> {
        Err(Error::unsupported("mounting is only possible on OSyx"))
    }

    pub fn umount(_path: &str) -> Result<()> {
        Err(Error::unsupported("mounting is only possible on OSyx"))
    }

    pub fn getuid() -> (u32, u32) {
        (0, 0)
    }

    pub fn setuid(_uid: u32, _gid: u32) -> Result<()> {
        Err(Error::unsupported("identities are only available on OSyx"))
    }

    pub fn set_time(_unix_ns: u64) -> Result<()> {
        Err(Error::unsupported("setting the clock is only available on OSyx"))
    }
}
// Threads, futexes and TLS are emulated with the host's std so the OSyx Std
// synchronisation code can be tested with real, parallel host threads.

pub const DEFAULT_STACK: usize = 256 * 1024;

pub struct RawThread;

/// Wake generation per futex address. A waiter returns when the generation
/// of *its* address changes (a `futex_wake` on it) or its timeout expires;
/// the shared condition variable only serves to sleep.
static FUTEX: std::sync::Mutex<alloc::collections::BTreeMap<usize, u64>> =
    std::sync::Mutex::new(alloc::collections::BTreeMap::new());
static FUTEX_CV: std::sync::Condvar = std::sync::Condvar::new();

pub fn futex_wait(word: &AtomicU32, expected: u32, timeout: Option<core::time::Duration>) -> bool {
    let addr = word as *const AtomicU32 as usize;
    let mut map = FUTEX.lock().unwrap_or_else(|e| e.into_inner());
    if word.load(Ordering::SeqCst) != expected {
        return true;
    }
    let gen = *map.get(&addr).unwrap_or(&0);
    let deadline = timeout.map(|d| std::time::Instant::now() + d);
    loop {
        map = match deadline {
            None => FUTEX_CV.wait(map).unwrap_or_else(|e| e.into_inner()),
            Some(dl) => {
                let left = dl.saturating_duration_since(std::time::Instant::now());
                FUTEX_CV.wait_timeout(map, left).unwrap_or_else(|e| e.into_inner()).0
            }
        };
        if *map.get(&addr).unwrap_or(&0) != gen {
            return true;
        }
        if deadline.is_some_and(|dl| std::time::Instant::now() >= dl) {
            return false;
        }
    }
}

pub fn futex_wait_owned(word: &AtomicU32, expected: u32, _owner: u64) {
    futex_wait(word, expected, None);
}

/// Only uses `word` as a key (never dereferences it), like the kernel.
pub fn futex_wake(word: *const AtomicU32, _count: u32) {
    let mut map = FUTEX.lock().unwrap_or_else(|e| e.into_inner());
    *map.entry(word as usize).or_insert(0) += 1;
    FUTEX_CV.notify_all();
}

pub fn thread_spawn(entry: fn(usize), arg: usize, tcb: usize, done: &AtomicU32, stack: usize) -> Result<RawThread> {
    let done_addr = done as *const AtomicU32 as usize;
    std::thread::Builder::new()
        .stack_size(stack.max(64 * 1024))
        .spawn(move || {
            set_tcb(tcb);
            entry(arg);
            // Like the kernel: publish completion, then use the address only
            // as a wake-up key (the joiner may free it right after the store).
            // SAFETY: the joiner keeps the word alive until it reads 1.
            unsafe { (*(done_addr as *const AtomicU32)).store(1, Ordering::Release) };
            futex_wake(done_addr as *const AtomicU32, u32::MAX);
        })
        .map(|_| RawThread)
        .map_err(|_| Error::new(ErrorKind::OutOfMemory, "host thread creation failed"))
}

pub fn thread_release(_t: RawThread) {}

std::thread_local! {
    static TCB: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static TID: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

pub fn tcb() -> usize {
    TCB.with(|t| t.get())
}

pub fn set_tcb(p: usize) {
    TCB.with(|t| t.set(p));
}

pub fn current_tid() -> u64 {
    static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);
    TID.with(|t| {
        if t.get() == 0 {
            t.set(NEXT.fetch_add(1, Ordering::Relaxed));
        }
        t.get()
    })
}
