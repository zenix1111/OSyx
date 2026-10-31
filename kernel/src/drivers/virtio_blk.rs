//! virtio-blk (virtio specification section 5.2): a disk of 512-byte
//! sectors behind one request queue.
//!
//! Every request is a descriptor chain: a 16-byte header (type, sector), the
//! data pages and a one-byte status the device writes last. Data goes
//! through DMA pages owned by the driver (bounce buffers), so callers can
//! pass any kernel buffer. A transfer larger than one chain is split into
//! several chains submitted together, so the device overlaps them.

use super::virtio::{AsyncQueue, Buffer, Transport, VirtioError};
use crate::arch::timer::Deadline;
use crate::block::{BlockDev, BlockError, SECTOR_SIZE};
use crate::mem::{alloc_frame, phys_to_virt, PAGE_SIZE};
use crate::pci;
use crate::sync::KMutex;
use alloc::{format, string::String, vec::Vec};

/// Transitional and modern virtio-blk PCI device ids.
pub const DEVICE_IDS: [u16; 2] = [0x1001, 0x1042];

const F_RO: u64 = 1 << 5;
const F_FLUSH: u64 = 1 << 9;

const T_IN: u32 = 0;
const T_OUT: u32 = 1;
const T_FLUSH: u32 = 4;
const S_OK: u8 = 0;

/// Largest DMA run per request: 1 MiB. The queue size caps it; probes with a
/// smaller queue use fewer pages.
const MAX_DATA_PAGES: usize = 256;
const PAGE: usize = PAGE_SIZE as usize;
/// Chains submitted together for one call: the device works on them
/// concurrently, so a read-ahead run overlaps disk latency.
const SLOTS: usize = 4;
const TIMEOUT_MS: u64 = 5000;
const SPIN_POLLS: u32 = 1000;

// TEMP per-request timing.
static OPS: [core::sync::atomic::AtomicU64; 3] = [const { core::sync::atomic::AtomicU64::new(0) }; 3];
static OP_CYCLES: [core::sync::atomic::AtomicU64; 3] = [const { core::sync::atomic::AtomicU64::new(0) }; 3];
static OP_MAX: [core::sync::atomic::AtomicU64; 3] = [const { core::sync::atomic::AtomicU64::new(0) }; 3];
static OP_BYTES: [core::sync::atomic::AtomicU64; 3] = [const { core::sync::atomic::AtomicU64::new(0) }; 3];
static OP_WAIT: [core::sync::atomic::AtomicU64; 3] = [const { core::sync::atomic::AtomicU64::new(0) }; 3];

fn slot(dir: Dir) -> usize {
    match dir {
        Dir::Read => 0,
        Dir::Write => 1,
        Dir::Flush => 2,
    }
}

/// (calls, total TSC cycles, max cycles, bytes, queue-wait cycles) per
/// direction: read, write, flush.
pub fn request_stats() -> [(u64, u64, u64, u64, u64); 3] {
    core::array::from_fn(|i| {
        let l = |a: &core::sync::atomic::AtomicU64| a.load(core::sync::atomic::Ordering::Relaxed);
        (l(&OPS[i]), l(&OP_CYCLES[i]), l(&OP_MAX[i]), l(&OP_BYTES[i]), l(&OP_WAIT[i]))
    })
}

struct Inner {
    queue: AsyncQueue,
    /// One header/status frame per slot: request header at offset 0, status
    /// byte at offset 16.
    headers: Vec<u64>,
    /// DMA data pages, `pages_per_slot` per slot.
    data: Vec<u64>,
    /// Descriptor chain templates side by side, `pages_per_slot + 2` per
    /// slot. Kept off the stack because the request path runs on deep
    /// write-back stacks.
    chains: alloc::boxed::Box<[Buffer]>,
    pages_per_slot: usize,
    /// Set after a timeout: the device may still own the buffers.
    failed: bool,
}

pub struct VirtioBlk {
    name: String,
    location: pci::Address,
    capacity: u64,
    read_only: bool,
    can_flush: bool,
    data_pages: usize,
    inner: KMutex<Inner>,
    _transport: Transport,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    Read,
    Write,
    Flush,
}

impl VirtioBlk {
    pub fn probe(dev: &pci::Device, name: String) -> Result<VirtioBlk, VirtioError> {
        let t = Transport::new(dev)?;
        let features = t.negotiate(F_RO | F_FLUSH)?;
        let queue = t.setup_async_queue(0, None)?;
        // Each slot owns a chain and a status byte; keep one chain's worth of
        // descriptors for every slot.
        let pages_per_slot = (queue.size() as usize - 2 * SLOTS) / SLOTS;
        let pages_per_slot = pages_per_slot.min(MAX_DATA_PAGES / SLOTS);
        if pages_per_slot < 2 {
            return Err(VirtioError::NoQueue);
        }
        let pages = pages_per_slot * SLOTS;
        let mut headers = Vec::with_capacity(SLOTS);
        for _ in 0..SLOTS {
            headers.push(alloc_frame().ok_or(VirtioError::OutOfMemory)?);
        }
        let mut data = Vec::with_capacity(pages);
        for _ in 0..pages {
            data.push(alloc_frame().ok_or(VirtioError::OutOfMemory)?);
        }
        let chains = alloc::vec![Buffer { phys: 0, len: 0, device_writes: false }; SLOTS * (pages_per_slot + 2)]
            .into_boxed_slice();
        t.driver_ok();
        let capacity = t.device_config_u64(0);
        crate::kprintln!(
            "virtio-blk {}: {} at {}, {} sectors ({} MiB){}{}, queue {} entries at {:#x}",
            name,
            format!("{:04x}:{:04x}", dev.vendor, dev.device),
            dev.addr,
            capacity,
            capacity >> 11,
            if features & F_RO != 0 { ", read-only" } else { "" },
            if features & F_FLUSH != 0 { ", flush" } else { "" },
            queue.size(),
            queue.phys()
        );
        Ok(VirtioBlk {
            name,
            location: dev.addr,
            capacity,
            read_only: features & F_RO != 0,
            can_flush: features & F_FLUSH != 0,
            data_pages: pages,
            inner: KMutex::new(Inner {
                queue,
                headers,
                data,
                chains,
                pages_per_slot,
                failed: false,
            }),
            _transport: t,
        })
    }

    /// Runs one request. `len` bytes of data are staged in the DMA pages.
    fn request(&self, dir: Dir, lba: u64, len: usize, stage: impl FnOnce(&[u64]), fetch: impl FnOnce(&[u64])) -> Result<(), BlockError> {
        let t0 = crate::arch::timer::tsc();
        let mut g = self.inner.lock();
        let t1 = crate::arch::timer::tsc();
        if g.failed {
            return Err(BlockError::Io);
        }
        let kind = match dir {
            Dir::Read => T_IN,
            Dir::Write => T_OUT,
            Dir::Flush => T_FLUSH,
        };
        let pages = len.div_ceil(PAGE);
        let per_slot = g.pages_per_slot;
        if pages > per_slot * SLOTS {
            return Err(BlockError::InvalidRequest);
        }
        let inner = &mut *g;
        stage(&inner.data[..pages]);
        let chunks = pages.div_ceil(per_slot).max(1);
        for i in 0..chunks {
            let first = i * per_slot;
            let count = pages.saturating_sub(first).min(per_slot);
            let header = inner.headers[i];
            let hv = phys_to_virt(header);
            // SAFETY: the header frame belongs to this slot and the device
            // does not own it until the chain below is queued.
            unsafe {
                core::ptr::write_volatile(hv as *mut u32, kind);
                core::ptr::write_volatile((hv + 4) as *mut u32, 0);
                core::ptr::write_volatile((hv + 8) as *mut u64, lba + (first * PAGE / SECTOR_SIZE) as u64);
                core::ptr::write_volatile((hv + 16) as *mut u8, 0xFF);
            }
            let base = i * (per_slot + 2);
            let chain = &mut inner.chains[base..base + count + 2];
            chain[0] = Buffer { phys: header, len: 16, device_writes: false };
            for j in 0..count {
                let n = (len - (first + j) * PAGE).min(PAGE) as u32;
                chain[1 + j] = Buffer { phys: inner.data[first + j], len: n, device_writes: dir == Dir::Read };
            }
            chain[1 + count] = Buffer { phys: header + 16, len: 1, device_writes: true };
        }
        // All chains of this call are queued before the doorbell: the device
        // then reads them concurrently instead of one round trip each.
        let mut pending = [(0u16, 0usize); SLOTS];
        {
            let Inner { queue, chains, .. } = &mut *inner;
            for (i, p) in pending.iter_mut().take(chunks).enumerate() {
                let base = i * (per_slot + 2);
                let count = pages.saturating_sub(i * per_slot).min(per_slot);
                // The slot sizing above guarantees room for every chain.
                let head = queue.add(&chains[base..base + count + 2]).expect("chains fit the queue");
                *p = (head, i);
            }
            queue.kick();
        }
        let deadline = Deadline::after_ms(TIMEOUT_MS);
        let mut polls = 0;
        let mut done = 0;
        while done < chunks {
            if let Some((head, _len)) = inner.queue.pop_used() {
                if pending[..chunks].iter().any(|&(h, _)| h == head) {
                    done += 1;
                    polls = 0;
                    continue;
                }
                crate::kprintln!("virtio-blk {}: used an unknown descriptor {}; disk disabled", self.name, head);
                inner.failed = true;
                return Err(BlockError::Io);
            }
            if deadline.expired() {
                crate::kprintln!("virtio-blk {}: request timed out; disk disabled", self.name);
                inner.failed = true;
                return Err(BlockError::Io);
            }
            if polls < SPIN_POLLS {
                polls += 1;
                core::hint::spin_loop();
            } else {
                crate::sched::yield_now();
            }
        }
        for &header in &inner.headers[..chunks] {
            // SAFETY: the device has returned every chain.
            let status = unsafe { core::ptr::read_volatile((phys_to_virt(header) + 16) as *const u8) };
            if status != S_OK {
                return Err(BlockError::Io);
            }
        }
        fetch(&inner.data[..pages]);
        let dt = crate::arch::timer::tsc().wrapping_sub(t0);
        let s = slot(dir);
        OPS[s].fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        OP_CYCLES[s].fetch_add(dt, core::sync::atomic::Ordering::Relaxed);
        OP_MAX[s].fetch_max(dt, core::sync::atomic::Ordering::Relaxed);
        OP_BYTES[s].fetch_add(len as u64, core::sync::atomic::Ordering::Relaxed);
        OP_WAIT[s].fetch_add(t1.wrapping_sub(t0), core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

fn stage_pages(pages: &[u64], buf: &[u8]) {
    for (chunk, &page) in buf.chunks(PAGE).zip(pages) {
        // SAFETY: each DMA page is a whole frame owned by the driver.
        unsafe { core::ptr::copy_nonoverlapping(chunk.as_ptr(), phys_to_virt(page) as *mut u8, chunk.len()) };
    }
}

fn fetch_pages(pages: &[u64], buf: &mut [u8]) {
    for (chunk, &page) in buf.chunks_mut(PAGE).zip(pages) {
        // SAFETY: as in `stage_pages`; the device has finished with the page.
        unsafe { core::ptr::copy_nonoverlapping(phys_to_virt(page) as *const u8, chunk.as_mut_ptr(), chunk.len()) };
    }
}

impl BlockDev for VirtioBlk {
    fn name(&self) -> &str {
        &self.name
    }

    fn describe(&self) -> String {
        format!("virtio-blk at PCI {}", self.location)
    }

    fn sector_count(&self) -> u64 {
        self.capacity
    }

    fn read_only(&self) -> bool {
        self.read_only
    }

    fn max_sectors(&self) -> usize {
        self.data_pages * PAGE / SECTOR_SIZE
    }

    fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let len = buf.len();
        self.request(Dir::Read, lba, len, |_| {}, |pages| fetch_pages(pages, buf))
    }

    fn write_blocks(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.request(Dir::Write, lba, buf.len(), |pages| stage_pages(pages, buf), |_| {})
    }

    fn flush(&self) -> Result<(), BlockError> {
        if !self.can_flush {
            return Ok(());
        }
        self.request(Dir::Flush, 0, 0, |_| {}, |_| {})
    }
}
