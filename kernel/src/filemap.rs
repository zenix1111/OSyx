//! Shared file views. Frames are cached by volume/inode, so independent
//! sections and processes see the same bytes, including after file growth.
//! The cache retains dirty backing after a process exits; a kernel worker
//! writes and retires unused entries outside all process/interrupt locks.
//! Read-only backing pages are shared with the read cache; creating a writable
//! view invalidates that cache first, retaining the frames for coherent views.
//! Lock order: CACHE -> Backing.state -> OpenFile -> filesystem. Explicit
//! truncation enters CACHE before locking its file; section mapping releases
//! Backing.state before entering the process table.
use crate::{mem, process, sched, shm::SharedMemory, sync::KMutex};
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};
use osyx_abi::Errno;

type Key = (u64, u64);
const MAX_FILEMAP: u64 = 512 * 1024 * 1024;
static CACHE: KMutex<BTreeMap<Key, Arc<Backing>>> = KMutex::new(BTreeMap::new());
static WORKER: AtomicBool = AtomicBool::new(false);

/// Serialize explicit file truncation against creation and delayed writeback.
/// Callers must not hold an open-file lock: the cache precedes file locks.
pub fn truncate<T>(key: (u64, u64), size: u64, operation: impl FnOnce() -> Result<T, Errno>) -> Result<T, Errno> {
    crate::filecache::forget(key);
    crate::exec::invalidate(key);
    let mut cache = CACHE.lock();
    if let Some(backing) = cache.get(&key) {
        if Arc::strong_count(backing) != 1 {
            return Err(Errno::Busy);
        }
        if size != 0 {
            let old_size = backing.state.lock().size;
            backing.flush(0, old_size, false)?;
        }
    }
    let result = operation()?;
    crate::exec::invalidate(key);
    cache.remove(&key);
    Ok(result)
}

struct State {
    /// Page index -> contents. Read-only views fill pages on first touch, so
    /// indices may be missing; writable views are filled when they are made.
    pages: BTreeMap<u64, Arc<SharedMemory>>,
    size: u64,
    file: process::FileHandle,
    can_write: bool,
}
struct Backing {
    key: Key,
    state: KMutex<State>,
}

pub struct Section {
    backing: Arc<Backing>,
    pub size: u64,
    pub writable: bool,
}

pub fn create(file: process::FileHandle, requested: u64, writable: bool) -> Result<Arc<Section>, Errno> {
    let (key, size) = {
        let mut f = file.lock();
        f.mapping_access(writable)?;
        let stat = f.stat()?;
        let size = if requested == 0 { stat.size } else { requested };
        if size == 0 {
            return Err(Errno::InvalidArgument);
        }
        if size > MAX_FILEMAP {
            return Err(Errno::NotSupported);
        }
        if size > stat.size && !writable {
            return Err(Errno::PermissionDenied);
        }
        ((stat.dev, stat.ino), size)
    };
    let backing = {
        if writable {
            // Mapped writes do not go through the read cache's invalidation.
            crate::filecache::forget(key);
        }
        let mut cache = CACHE.lock();
        let backing = match cache.get(&key) {
            Some(b) => b.clone(),
            None => Arc::new(Backing {
                key,
                state: KMutex::new(State { pages: BTreeMap::new(), size: 0, file: file.clone(), can_write: writable }),
            }),
        };
        if writable {
            backing.grow(file, size, writable)?;
        } else {
            // Read-only views load pages from the first page fault: a browser
            // archive of 177 MiB is mapped whole but touches only a fraction.
            let mut state = backing.state.lock();
            state.size = state.size.max(size);
        }
        cache.insert(key, backing.clone());
        backing
    };
    if !WORKER.swap(true, Ordering::SeqCst) {
        sched::spawn_kernel("filemap-writeback", writeback_worker, 0, 0);
    }
    Ok(Arc::new(Section { backing, size, writable }))
}

/// One file system read at most. A DLL is fetched in runs of this size so the
/// block layer sees large requests instead of one 4 KiB read per page.
const READ_RUN: u64 = 1024 * 1024;
/// Writeback granularity: one file-system transaction (and one block request
/// per contiguous extent) per run instead of one transaction per page.
const WRITE_RUN: u64 = 1024 * 1024;

impl Backing {
    fn grow(&self, file: process::FileHandle, size: u64, writable: bool) -> Result<(), Errno> {
        let mut state = self.state.lock();
        if writable && !state.can_write {
            state.file = file;
            state.can_write = true;
        }
        if size <= state.size {
            return Ok(());
        }
        let source = state.file.clone();
        let mut source = source.lock();
        if size > source.stat()?.size {
            source.truncate(size)?;
        }
        let old_size = state.size;
        let total = size.div_ceil(mem::PAGE_SIZE);
        let started = crate::interrupts::uptime_ms();
        let mut scratch: Vec<u8> = Vec::new();
        let mut index = 0;
        while index < total {
            if state.pages.contains_key(&index) {
                index += 1;
                continue;
            }
            let offset = index * mem::PAGE_SIZE;
            let bytes = (size - offset).min(READ_RUN) as usize;
            scratch.resize(bytes, 0);
            read_run(&source, offset, &mut scratch)?;
            let pages = bytes.div_ceil(mem::PAGE_SIZE as usize);
            for k in 0..pages {
                let at = index + k as u64;
                if state.pages.contains_key(&at) {
                    continue;
                }
                let start = k * mem::PAGE_SIZE as usize;
                let count = (bytes - start).min(mem::PAGE_SIZE as usize);
                state.pages.insert(at, SharedMemory::page_from(&scratch[start..start + count])?);
            }
            index += pages as u64;
        }
        // A section may grow within the final page of an earlier view.
        // Load only the newly covered bytes, preserving live mapped data.
        if old_size != 0 && !old_size.is_multiple_of(mem::PAGE_SIZE) {
            let index = old_size / mem::PAGE_SIZE;
            let within = old_size % mem::PAGE_SIZE;
            let count = (size - old_size).min(mem::PAGE_SIZE - within) as usize;
            if let Some(page) = state.pages.get(&index) {
                // SAFETY: the backing retains this RAM page throughout the copy.
                let bytes = unsafe {
                    core::slice::from_raw_parts_mut((mem::phys_to_virt(page.frames()[0]) + within) as *mut u8, count)
                };
                read_run(&source, old_size, bytes)?;
            }
        }
        let elapsed = crate::interrupts::uptime_ms().saturating_sub(started);
        if elapsed >= 200 {
            crate::kprintln!("filemap: {} MiB read in {} ms", size >> 20, elapsed);
        }
        state.size = size;
        Ok(())
    }

    fn flush(&self, offset: u64, len: u64, sync: bool) -> Result<(), Errno> {
        let state = self.state.lock();
        if offset > state.size || len > state.size - offset {
            return Err(Errno::InvalidArgument);
        }
        if !state.can_write {
            return Ok(());
        }
        let mut file = state.file.lock();
        let mut scratch: Vec<u8> = Vec::new();
        let mut at = offset;
        let end = offset + len;
        while at < end {
            let run = (end - at).min(WRITE_RUN);
            scratch.clear();
            scratch.reserve(run as usize);
            let mut copied = 0u64;
            while copied < run {
                let pos = at + copied;
                let index = pos / mem::PAGE_SIZE;
                let within = pos % mem::PAGE_SIZE;
                let count = (run - copied).min(mem::PAGE_SIZE - within);
                match state.pages.get(&index) {
                    // SAFETY: this cached RAM page remains owned while state is held.
                    Some(page) => {
                        let bytes = unsafe {
                            core::slice::from_raw_parts(
                                (mem::phys_to_virt(page.frames()[0]) + within) as *const u8,
                                count as usize,
                            )
                        };
                        scratch.extend_from_slice(bytes);
                    }
                    // Never loaded (read-only view): the file already holds
                    // the same bytes, so write zeros only to keep the run
                    // length; a writable view is always fully loaded.
                    None => scratch.resize(scratch.len() + count as usize, 0),
                }
                copied += count;
            }
            let mut done = 0;
            while done < scratch.len() {
                let n = file.write_at(at + done as u64, &scratch[done..])?;
                if n == 0 {
                    return Err(Errno::Io);
                }
                done += n;
            }
            at += run;
        }
        if sync {
            file.sync()?;
        }
        crate::filecache::forget(self.key);
        Ok(())
    }
}

fn read_run(file: &crate::vfs::OpenFile, offset: u64, out: &mut [u8]) -> Result<(), Errno> {
    let mut done = 0;
    while done < out.len() {
        let n = file.read_direct(offset + done as u64, &mut out[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    Ok(())
}

/// Bytes read into the backing on one page fault: the faulting page and the
/// following ones, so a sequential reader faults once per 256 KiB instead of
/// once per page. The disk request overlaps nothing, but the run bounds the
/// latency of a single fault.
const FAULT_READ_RUN: u64 = 256 * 1024;

impl Section {
    /// Reserves `[offset, offset + len)` of the section in the current
    /// process. Read-only sections map no frames yet: the first touch of each
    /// run loads it from the file (see [`Section::page`]).
    pub fn map(section: &Arc<Section>, offset: u64, len: u64, writable: bool) -> Result<u64, Errno> {
        if writable && !section.writable {
            return Err(Errno::PermissionDenied);
        }
        if !offset.is_multiple_of(mem::PAGE_SIZE) || len == 0 || offset >= section.size || len > section.size - offset {
            return Err(Errno::InvalidArgument);
        }
        process::map_section(section.clone(), offset, len, writable)
    }

    /// Page `index` of the section, loading it (and the rest of its read run)
    /// from the file on a miss. Called from a page fault without the process
    /// table held; the backing state lock serialises concurrent faults and
    /// the delayed writeback.
    pub fn page(&self, index: u64) -> Result<Arc<SharedMemory>, Errno> {
        let mut state = self.backing.state.lock();
        if let Some(page) = state.pages.get(&index) {
            return Ok(page.clone());
        }
        let total = self.size.div_ceil(mem::PAGE_SIZE);
        if index >= total {
            return Err(Errno::InvalidArgument);
        }
        let offset = index * mem::PAGE_SIZE;
        let bytes = (self.size - offset).min(FAULT_READ_RUN) as usize;
        let mut buf = alloc::vec![0u8; bytes];
        {
            let file = state.file.lock();
            read_run(&file, offset, &mut buf)?;
        }
        let pages = bytes.div_ceil(mem::PAGE_SIZE as usize);
        for k in 0..pages {
            let start = k * mem::PAGE_SIZE as usize;
            let count = (bytes - start).min(mem::PAGE_SIZE as usize);
            state.pages.entry(index + k as u64).or_insert(SharedMemory::page_from(&buf[start..start + count])?);
        }
        state.pages.get(&index).cloned().ok_or(Errno::Io)
    }

    pub fn flush(&self, offset: u64, len: u64) -> Result<(), Errno> {
        if offset > self.size || len > self.size - offset {
            return Err(Errno::InvalidArgument);
        }
        self.backing.flush(offset, len, false)
    }
}

fn writeback_worker(_: u64, _: u64) {
    let khz = crate::arch::timer::tsc_khz().max(1);
    let mut last_spin = 0u64;
    let mut last_waits = 0u64;
    let mut last_holds = 0u64;
    let mut last_hold_cycles = 0u64;
    let mut last_slow = 0u64;
    let mut last_read = 0u64;
    let mut last_nr = [0u64; 128];
    let mut last_nr_hold = [0u64; 128];
    let mut last_pid = [(0u64, 0u64, 0u64, 0u64); 24];
    let mut last_tid = [(0u64, 0u64, 0u64, 0u64); 48];
    let mut last_futex = [(0u64, 0u64, 0u64, 0u64); 48];
    let mut last_thrcpu: alloc::collections::BTreeMap<u64, u64> = alloc::collections::BTreeMap::new();
    let mut last_samples = [0u64; crate::smp::SAMPLE_SLOTS];
    let mut last_stk = [0u64; crate::smp::STACK_SLOTS];
    let mut last_calls = [0u64; crate::smp::CALL_SLOTS];
    let mut last_dev = [(0u64, 0u64, 0u64, 0u64, 0u64); 3];
    let mut last_wc = [0u64; 8];
    let (mut last_fh, mut last_fm, mut last_rh) = (0u64, 0u64, 0u64);
    let mut last_pf = [0u64; 4];
    loop {
        sched::sleep_ticks(crate::arch::timer::ms_to_ticks(1000));
        if crate::has_boot_option("stats") {
        // TEMP I/O diagnostics.
        let (wc, wb) = osyx_ext4::write_stats();
        let (tc, tb) = osyx_ext4::commit_stats();
        let (rb, _) = crate::block::io_bytes();
        let (_, waits, spin, max_spin) = crate::smp::lock_stats();
        let (holds, hold_cycles, hold_max, slow) = crate::smp::hold_stats();
        crate::kprintln!(
            "iostat: wcalls={wc} wKiB={} rKiB={} commits={tc} cblocks={tb} lock_waits={} spin_ms={} max_spin_us={} holds={} hold_ms={} hold_max_ms={} slow={}",
            wb / 1024,
            (rb - last_read) / 1024,
            waits - last_waits,
            (spin - last_spin) / khz,
            max_spin * 1000 / khz,
            holds - last_holds,
            (hold_cycles - last_hold_cycles) / khz,
            hold_max / khz,
            slow - last_slow
        );
        // TEMP device request counts, latency, queue wait and size, per second.
        let dev = crate::drivers::virtio_blk::request_stats();
        let mut s = alloc::string::String::new();
        for (i, name) in ["rd", "wr", "fl"].iter().enumerate() {
            let (c, cyc, mx, bytes, wait) = dev[i];
            let (lc, lcyc, _, lbytes, lwait) = last_dev[i];
            last_dev[i] = (c, cyc, mx, bytes, wait);
            let dc = c - lc;
            let (avg, wavg, kib) = match ((cyc - lcyc).checked_div(dc), (wait - lwait).checked_div(dc)) {
                (Some(a), Some(w)) => (a * 1000 / khz, w * 1000 / khz, (bytes - lbytes) / 1024),
                _ => (0, 0, 0),
            };
            core::fmt::Write::write_fmt(&mut s, format_args!(" {name}={dc}/{kib}K/{avg}us/w{wavg}us/m{}us", mx * 1000 / khz)).ok();
        }
        crate::kprintln!("devio:{s}");
        // TEMP prefault cost per second.
        let pf = crate::process::prefault_stats();
        if pf[0] != last_pf[0] {
            crate::kprintln!(
                "prefault: pages={} chunks={} skipped={} ms={}",
                pf[0] - last_pf[0],
                pf[1] - last_pf[1],
                pf[2] - last_pf[2],
                (pf[3] - last_pf[3]) / khz
            );
        }
        last_pf = pf;
        // TEMP write volume by file kind (and fsync count) per second.
        let wc = crate::vfs::write_cat_bytes();
        let mut line = alloc::string::String::new();
        for (i, name) in ["idb", "places", "session", "cache2", "journal", "other"].iter().enumerate() {
            let d = wc[i].saturating_sub(last_wc[i]);
            last_wc[i] = wc[i];
            if d != 0 {
                core::fmt::Write::write_fmt(&mut line, format_args!(" {name}={}K", d / 1024)).ok();
            }
        }
        let syncs = wc[6].saturating_sub(last_wc[6]);
        last_wc[6] = wc[6];
        crate::kprintln!("writecat:{line} syncs={syncs}");
        // TEMP cache hit rates and the last IndexedDB writer.
        let (fh, fm, rh) = crate::filecache::hit_stats();
        let dh = fh.saturating_sub(last_fh);
        let dm = fm.saturating_sub(last_fm);
        let dr = rh.saturating_sub(last_rh);
        last_fh = fh;
        last_fm = fm;
        last_rh = rh;
        let (wtid, woff, wlen) = crate::vfs::last_idb_write();
        crate::kprintln!("fcache: hit={dh} miss={dm} recent={dr} idbw=tid{wtid}@{woff}+{wlen}");
        // TEMP TCP flow-control snapshot (connections with traffic).
        for line in crate::net::debug_lines() {
            crate::kprintln!("tcpdbg: {line}");
        }
        // TEMP syscall histogram (top six by count in the last second).
        let counts = crate::smp::nr_counts();
        let mut top: [(usize, u64); 6] = [(0, 0); 6];
        for (i, &c) in counts.iter().enumerate() {
            let d = c - last_nr[i];
            last_nr[i] = c;
            if d > top[5].1 {
                top[5] = (i, d);
                top.sort_unstable_by_key(|a| core::cmp::Reverse(a.1));
            }
        }
        let mut line = alloc::string::String::new();
        for (i, d) in top {
            if d != 0 {
                core::fmt::Write::write_fmt(&mut line, format_args!(" {:#x}={d}", i)).ok();
            }
        }
        crate::kprintln!("syscalls:{line}");
        // TEMP lock time by syscall (top six, milliseconds in the last second).
        let holds_by_nr = crate::smp::nr_hold_cycles();
        let mut top: [(usize, u64); 6] = [(0, 0); 6];
        for (i, &c) in holds_by_nr.iter().enumerate() {
            let d = (c - last_nr_hold[i]) / khz;
            last_nr_hold[i] = c;
            if d > top[5].1 {
                top[5] = (i, d);
                top.sort_unstable_by_key(|a| core::cmp::Reverse(a.1));
            }
        }
        let mut line = alloc::string::String::new();
        for (i, d) in top {
            if d != 0 {
                core::fmt::Write::write_fmt(&mut line, format_args!(" {:#x}={d}ms", i)).ok();
            }
        }
        crate::kprintln!("holdtime:{line} lockfree={}", crate::smp::lock_free_calls());
        // TEMP per-process attribution of CLOCK / CHANNEL_RECV pollers.
        let pids = crate::smp::pid_counters();
        let mut line = alloc::string::String::new();
        for (i, &(pid, recv, clock, stat)) in pids.iter().enumerate() {
            let (_, lr, lc, ls) = last_pid[i];
            let dr = recv.saturating_sub(lr);
            let dc = clock.saturating_sub(lc);
            let ds = stat.saturating_sub(ls);
            last_pid[i] = (pid, recv, clock, stat);
            if pid != 0 && (dr != 0 || dc != 0 || ds != 0) {
                core::fmt::Write::write_fmt(&mut line, format_args!(" pid{pid}:recv={dr} clock={dc} stat={ds}"))
                    .ok();
            }
        }
        if !line.is_empty() {
            crate::kprintln!("pidstat:{line}");
        }
        // TEMP per-thread attribution.
        let tids = crate::smp::tid_counters();
        let mut line = alloc::string::String::new();
        for (i, &(tid, recv, clock, stat)) in tids.iter().enumerate() {
            let (_, lr, lc, ls) = last_tid[i];
            let dr = recv.saturating_sub(lr);
            let dc = clock.saturating_sub(lc);
            let ds = stat.saturating_sub(ls);
            last_tid[i] = (tid, recv, clock, stat);
            if tid != 0 && (dr != 0 || dc != 0 || ds != 0) {
                core::fmt::Write::write_fmt(&mut line, format_args!(" tid{tid}:recv={dr} clock={dc} stat={ds}"))
                    .ok();
            }
        }
        if !line.is_empty() {
            crate::kprintln!("tidstat:{line}");
        }
        // TEMP per-thread futex/yield attribution.
        let futs = crate::smp::tid_futex_counters();
        let mut line = alloc::string::String::new();
        for (i, &(tid, wait, wake, yield_)) in futs.iter().enumerate() {
            let (_, lw, lk, ly) = last_futex[i];
            let dw = wait.saturating_sub(lw);
            let dk = wake.saturating_sub(lk);
            let dy = yield_.saturating_sub(ly);
            last_futex[i] = (tid, wait, wake, yield_);
            if tid != 0 && (dw != 0 || dk != 0 || dy != 0) {
                core::fmt::Write::write_fmt(&mut line, format_args!(" tid{tid}:wait={dw} wake={dk} yield={dy}"))
                    .ok();
            }
        }
        if !line.is_empty() {
            crate::kprintln!("futexstat:{line}");
        }
        crate::futex::dump_waiters();
        sched::dump();
        // TEMP per-thread CPU ticks (top six by delta) for the browser's process.
        let tcpu = sched::thread_cpu();
        let mut top: [(u64, u64, u64); 6] = [(0, 0, 0); 6];
        for (tid, pid, ticks) in tcpu {
            let before = last_thrcpu.get(&tid).copied().unwrap_or(ticks);
            last_thrcpu.insert(tid, ticks);
            let d = ticks.saturating_sub(before);
            if d > top[5].2 {
                top[5] = (tid, pid, d);
                top.sort_unstable_by_key(|a| core::cmp::Reverse(a.2));
            }
        }
        let mut line = alloc::string::String::new();
        for (tid, pid, d) in top {
            if d != 0 {
                core::fmt::Write::write_fmt(&mut line, format_args!(" tid{tid}/p{pid}={d}")).ok();
            }
        }
        if !line.is_empty() {
            crate::kprintln!("thrcpu:{line}");
        }
        // TEMP user-RIP samples from the timer (top six by delta).
        let samples = crate::smp::rip_samples();
        let mut top: [(usize, u64); 6] = [(0, 0); 6];
        for (i, &(_, _, count)) in samples.iter().enumerate() {
            let d = count.saturating_sub(last_samples[i]);
            last_samples[i] = count;
            if d > top[5].1 {
                top[5] = (i, d);
                top.sort_unstable_by_key(|a| core::cmp::Reverse(a.1));
            }
        }
        let mut line = alloc::string::String::new();
        for (i, d) in top {
            if d != 0 {
                let (tid, rip, _) = samples[i];
                core::fmt::Write::write_fmt(&mut line, format_args!(" tid{tid}@{rip:#x}={d}")).ok();
            }
        }
        if !line.is_empty() {
            crate::kprintln!("rips:{line}");
        }
        // TEMP stack attribution at user samples (top six by delta).
        let stk = crate::smp::stack_samples();
        let mut top: [(usize, u64); 6] = [(0, 0); 6];
        for (i, &(_, _, count)) in stk.iter().enumerate() {
            let d = count.saturating_sub(last_stk[i]);
            last_stk[i] = count;
            if d > top[5].1 {
                top[5] = (i, d);
                top.sort_unstable_by_key(|a| core::cmp::Reverse(a.1));
            }
        }
        let mut line = alloc::string::String::new();
        for (i, d) in top {
            if d != 0 {
                let (tid, rip, _) = stk[i];
                core::fmt::Write::write_fmt(&mut line, format_args!(" tid{tid}@{rip:#x}={d}")).ok();
            }
        }
        if !line.is_empty() {
            crate::kprintln!("stk:{line}");
        }
        // TEMP syscall call sites (top eight by delta).
        let sites = crate::smp::call_sites();
        let mut top: [(usize, u64); 8] = [(0, 0); 8];
        for (i, &(_, _, _, count)) in sites.iter().enumerate() {
            let d = count.saturating_sub(last_calls[i]);
            last_calls[i] = count;
            if d > top[7].1 {
                top[7] = (i, d);
                top.sort_unstable_by_key(|a| core::cmp::Reverse(a.1));
            }
        }
        let mut line = alloc::string::String::new();
        for (i, d) in top {
            if d != 0 {
                let (tid, rip, nr, _) = sites[i];
                core::fmt::Write::write_fmt(&mut line, format_args!(" tid{tid}#{nr}@{rip:#x}={d}")).ok();
            }
        }
        if !line.is_empty() {
            crate::kprintln!("calls:{line}");
        }
        last_spin = spin;
        last_waits = waits;
        last_holds = holds;
        last_hold_cycles = hold_cycles;
        last_slow = slow;
        last_read = rb;
        }
        // Only the cache holds an unused backing. The flush itself runs without
        // the global lock: it holds the backing's state lock, so a concurrent
        // create() waits for the write instead of blocking every other mapping.
        let unused: Vec<(Key, Arc<Backing>)> = {
            let cache = CACHE.lock();
            cache.iter().filter(|(_, b)| Arc::strong_count(b) == 1).map(|(k, b)| (*k, b.clone())).collect()
        };
        for (key, backing) in unused {
            let size = backing.state.lock().size;
            if backing.flush(0, size, true).is_ok() {
                let mut cache = CACHE.lock();
                // A create() may have picked the entry up meanwhile; keep it.
                if cache.get(&key).is_some_and(|b| Arc::ptr_eq(b, &backing) && Arc::strong_count(b) == 2) {
                    cache.remove(&key);
                }
            }
        }
    }
}
