//! USB mass storage: SCSI over the Bulk-Only Transport, on top of the xHCI
//! driver.
//!
//! Commands come from other threads through a global request queue; the
//! controller thread executes them between events, one BOT transaction at
//! a time (CBW, optional data stage, CSW). Data moves through one DMA page
//! per request, so a block request is at most 8 sectors.

use super::dma::DmaPage;
use super::{Xhci, XhciError};
use crate::arch::timer::{self, Deadline};
use crate::block::{self, BlockDev, BlockError, SECTOR_SIZE};
use crate::interrupts;
use crate::kprintln;
use crate::sync::IrqSpinLock;
use crate::waitq::{block_on, WaitQueue};
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use osyx_usb::xhci::trb::{CompletionCode, Trb};

/// The BOT data stage fits in one DMA page.
pub(super) const MAX_TRANSFER: usize = 4096;
const BOT_TIMEOUT_MS: u64 = 15_000;
const REQUEST_TIMEOUT_MS: u64 = 30_000;

const CBW_SIGNATURE: u32 = 0x4342_5355; // "USBC"
const CSW_SIGNATURE: u32 = 0x5342_5355; // "USBS"

const SCSI_TEST_UNIT_READY: u8 = 0x00;
const SCSI_INQUIRY: u8 = 0x12;
const SCSI_READ_CAPACITY_10: u8 = 0x25;
const SCSI_READ_10: u8 = 0x28;
const SCSI_WRITE_10: u8 = 0x2A;
const SCSI_SYNC_CACHE_10: u8 = 0x35;
const SCSI_START_STOP_UNIT: u8 = 0x1B;
const SCSI_READ_CAPACITY_16: u8 = 0x9E;

static DISKS: AtomicUsize = AtomicUsize::new(0);
static GENERATIONS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Op {
    Read,
    Write,
    Flush,
    /// Flush the drive's cache and spin it down (START STOP UNIT).
    Eject,
}

pub(super) struct Request {
    controller: usize,
    slot: u8,
    generation: u64,
    op: Op,
    lba: u64,
    data: IrqSpinLock<Vec<u8>>,
    done: AtomicBool,
    ok: AtomicBool,
}

static QUEUE: IrqSpinLock<VecDeque<Arc<Request>>> = IrqSpinLock::new(VecDeque::new());
pub(super) static WAKE: WaitQueue = WaitQueue::new();

fn enqueue(request: Request) -> Arc<Request> {
    let request = Arc::new(request);
    QUEUE.lock().push_back(request.clone());
    WAKE.wake_all();
    request
}

pub(super) fn take(controller: usize) -> Option<Arc<Request>> {
    let mut queue = QUEUE.lock();
    let i = queue.iter().position(|r| r.controller == controller)?;
    queue.remove(i)
}

pub(super) fn has_work(controller: usize) -> bool {
    QUEUE.lock().iter().any(|r| r.controller == controller)
}

/// Fails every queued request for a device that was unplugged, so no
/// caller waits for the full request timeout.
pub(super) fn fail_pending(controller: usize, slot: u8) {
    let failed: Vec<Arc<Request>> = {
        let mut queue = QUEUE.lock();
        let mut keep = VecDeque::new();
        let mut failed = Vec::new();
        while let Some(r) = queue.pop_front() {
            if r.controller == controller && r.slot == slot {
                failed.push(r);
            } else {
                keep.push_back(r);
            }
        }
        *queue = keep;
        failed
    };
    for r in failed {
        r.ok.store(false, Ordering::Release);
        r.done.store(true, Ordering::Release);
    }
    WAKE.wake_all();
}

/// Per-disk SCSI state, stored with the USB device in the controller.
pub(super) struct StorageState {
    pub(super) dci_in: u8,
    pub(super) dci_out: u8,
    pub(super) cbw: DmaPage,
    pub(super) csw: DmaPage,
    pub(super) data: DmaPage,
    pub(super) tag: u32,
    pub(super) generation: u64,
    pub(super) failed: bool,
    /// Shared with the block device: set when the drive is unplugged or
    /// ejected, after which its I/O fails at once.
    pub(super) gone: Arc<AtomicBool>,
    /// Block device name, for the storage manager when the drive vanishes.
    pub(super) disk_name: String,
}

/// A USB disk seen by the block layer.
pub struct UsbDisk {
    controller: usize,
    slot: u8,
    generation: u64,
    name: String,
    what: String,
    model: String,
    sectors: u64,
    gone: Arc<AtomicBool>,
}

impl UsbDisk {
    fn request(&self, op: Op, lba: u64, len: usize, data: Option<&[u8]>) -> Result<Vec<u8>, BlockError> {
        if self.gone.load(Ordering::Acquire) {
            return Err(BlockError::Io);
        }
        if len > MAX_TRANSFER || !len.is_multiple_of(SECTOR_SIZE) {
            return Err(BlockError::InvalidRequest);
        }
        let buffer = match op {
            Op::Write => data.ok_or(BlockError::InvalidRequest)?.to_vec(),
            _ => alloc::vec![0u8; len],
        };
        let request = enqueue(Request {
            controller: self.controller,
            slot: self.slot,
            generation: self.generation,
            op,
            lba,
            data: IrqSpinLock::new(buffer),
            done: AtomicBool::new(false),
            ok: AtomicBool::new(false),
        });
        let deadline = interrupts::ticks().saturating_add(timer::ms_to_ticks(REQUEST_TIMEOUT_MS));
        if block_on(&[&WAKE], Some(deadline), || request.done.load(Ordering::Acquire).then_some(())).is_err() {
            return Err(BlockError::Io);
        }
        if !request.ok.load(Ordering::Acquire) {
            return Err(BlockError::Io);
        }
        let out = core::mem::take(&mut *request.data.lock());
        Ok(out)
    }
}

impl BlockDev for UsbDisk {
    fn name(&self) -> &str {
        &self.name
    }

    fn describe(&self) -> String {
        alloc::format!("USB mass storage {} ({} MiB)", self.what, self.sectors >> 11)
    }

    fn sector_count(&self) -> u64 {
        self.sectors
    }

    fn read_only(&self) -> bool {
        false
    }

    fn max_sectors(&self) -> usize {
        MAX_TRANSFER / SECTOR_SIZE
    }

    fn read_blocks(&self, lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        let out = self.request(Op::Read, lba, buf.len(), None)?;
        buf.copy_from_slice(&out);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.request(Op::Write, lba, buf.len(), Some(buf)).map(|_| ())
    }

    fn flush(&self) -> Result<(), BlockError> {
        self.request(Op::Flush, 0, 0, None).map(|_| ())
    }

    fn removable(&self) -> bool {
        true
    }

    fn present(&self) -> bool {
        !self.gone.load(Ordering::Acquire)
    }

    fn model(&self) -> String {
        self.model.clone()
    }

    fn eject(&self) -> Result<(), BlockError> {
        // The stop command may be refused by sticks that cannot spin
        // down; the cache flush before it is what matters, and its failure
        // is reported.
        let r = self.request(Op::Eject, 0, 0, None).map(|_| ());
        self.gone.store(true, Ordering::Release);
        r
    }
}

fn ascii(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b == 0 {
            break;
        }
        if b.is_ascii_graphic() || b == b' ' {
            out.push(b as char);
        }
    }
    String::from(out.trim())
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

fn read_cdb(lba: u64, sectors: usize) -> [u8; 10] {
    let mut cdb = [0u8; 10];
    cdb[0] = SCSI_READ_10;
    cdb[2] = (lba >> 24) as u8;
    cdb[3] = (lba >> 16) as u8;
    cdb[4] = (lba >> 8) as u8;
    cdb[5] = lba as u8;
    cdb[7] = ((sectors >> 8) & 0xFF) as u8;
    cdb[8] = sectors as u8;
    cdb
}

fn write_cdb(lba: u64, sectors: usize) -> [u8; 10] {
    let mut cdb = read_cdb(lba, sectors);
    cdb[0] = SCSI_WRITE_10;
    cdb
}

impl Xhci {
    /// Runs one queued block request (called on the controller thread).
    pub(super) fn service_storage(&mut self) {
        while let Some(request) = take(self.index) {
            let outcome = self.storage_command(&request);
            let ok = match &outcome {
                Ok(()) => true,
                Err(e) => {
                    kprintln!("usb-storage: command failed: {}", e);
                    // A transport failure leaves the device unusable; a SCSI
                    // status only fails this command.
                    if !matches!(e, XhciError::Scsi(_)) {
                        if let Some(state) = self.devices.get_mut(&request.slot).and_then(|d| d.storage.as_mut()) {
                            state.failed = true;
                        }
                    }
                    false
                }
            };
            request.ok.store(ok, Ordering::Release);
            request.done.store(true, Ordering::Release);
            WAKE.wake_all();
        }
    }

    fn storage_command(&mut self, request: &Request) -> Result<(), XhciError> {
        {
            let device = self.devices.get(&request.slot).ok_or(XhciError::BadSlot)?;
            let state = device.storage.as_ref().ok_or(XhciError::Unsupported("no mass storage state"))?;
            if state.generation != request.generation {
                return Err(XhciError::Unsupported("disk was replaced"));
            }
            if state.failed {
                return Err(XhciError::Unsupported("disk failed earlier"));
            }
        }
        let len = request.data.lock().len();
        match request.op {
            Op::Read => {
                let cdb = read_cdb(request.lba, len / SECTOR_SIZE);
                let done = self.scsi(request.slot, &cdb, true, len, None)?;
                if done != len {
                    return Err(XhciError::Unsupported("short data stage"));
                }
                let mut data = request.data.lock();
                let state = self.devices.get(&request.slot).and_then(|d| d.storage.as_ref()).ok_or(XhciError::PortGone)?;
                state.data.copy_out(&mut data);
            }
            Op::Write => {
                let cdb = write_cdb(request.lba, len / SECTOR_SIZE);
                let data = request.data.lock();
                self.scsi(request.slot, &cdb, false, len, Some(&data))?;
            }
            Op::Flush => {
                let cdb = [SCSI_SYNC_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                self.scsi(request.slot, &cdb, false, 0, None)?;
            }
            Op::Eject => {
                let cdb = [SCSI_SYNC_CACHE_10, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                self.scsi(request.slot, &cdb, false, 0, None)?;
                // IMMED = 0, START = 0, LOEJ = 0: stop the unit. Drives that
                // do not implement it answer with a SCSI status; the data is
                // on the medium by now.
                let stop = [SCSI_START_STOP_UNIT, 0, 0, 0, 0, 0];
                if let Err(e) = self.scsi(request.slot, &stop, false, 0, None) {
                    if !matches!(e, XhciError::Scsi(_)) {
                        return Err(e);
                    }
                }
            }
        }
        Ok(())
    }

    /// One Bulk-Only Transport transaction. Returns the data-stage bytes
    /// actually transferred.
    fn scsi(&mut self, slot: u8, cdb: &[u8], dir_in: bool, data_len: usize, out: Option<&[u8]>) -> Result<usize, XhciError> {
        if cdb.len() > 16 || data_len > MAX_TRANSFER {
            return Err(XhciError::Unsupported("SCSI request too large"));
        }
        let tag = {
            let device = self.devices.get_mut(&slot).ok_or(XhciError::BadSlot)?;
            let state = device.storage.as_mut().ok_or(XhciError::Unsupported("no mass storage state"))?;
            if state.failed {
                return Err(XhciError::Unsupported("disk failed earlier"));
            }
            state.tag = state.tag.wrapping_add(1);
            state.tag
        };
        let mut cbw = [0u8; 31];
        cbw[0..4].copy_from_slice(&CBW_SIGNATURE.to_le_bytes());
        cbw[4..8].copy_from_slice(&tag.to_le_bytes());
        cbw[8..12].copy_from_slice(&(data_len as u32).to_le_bytes());
        cbw[12] = if dir_in { 0x80 } else { 0 };
        cbw[13] = 0; // LUN 0
        cbw[14] = cdb.len() as u8;
        cbw[15..15 + cdb.len()].copy_from_slice(cdb);
        let (cbw_phys, csw_phys, data_phys, dci_in, dci_out) = {
            let device = self.devices.get(&slot).ok_or(XhciError::BadSlot)?;
            let state = device.storage.as_ref().ok_or(XhciError::Unsupported("no mass storage state"))?;
            state.cbw.copy_in(&cbw);
            if let Some(data) = out {
                state.data.copy_in(data);
            }
            (state.cbw.phys(), state.csw.phys(), state.data.phys(), state.dci_in, state.dci_out)
        };
        if self.bulk(slot, dci_out, cbw_phys, 31)? != 31 {
            return Err(XhciError::Transfer(CompletionCode::ShortPacket));
        }
        if data_len > 0 {
            let dci = if dir_in { dci_in } else { dci_out };
            self.bulk(slot, dci, data_phys, data_len)?;
        }
        if self.bulk(slot, dci_in, csw_phys, 13)? != 13 {
            return Err(XhciError::Transfer(CompletionCode::ShortPacket));
        }
        let mut csw = [0u8; 13];
        {
            let device = self.devices.get(&slot).ok_or(XhciError::PortGone)?;
            let state = device.storage.as_ref().ok_or(XhciError::Unsupported("no mass storage state"))?;
            state.csw.copy_out(&mut csw);
        }
        let signature = u32::from_le_bytes([csw[0], csw[1], csw[2], csw[3]]);
        let status_tag = u32::from_le_bytes([csw[4], csw[5], csw[6], csw[7]]);
        let residue = u32::from_le_bytes([csw[8], csw[9], csw[10], csw[11]]);
        if signature != CSW_SIGNATURE || status_tag != tag {
            return Err(XhciError::Unsupported("malformed command status wrapper"));
        }
        if csw[12] != 0 {
            return Err(XhciError::Scsi(csw[12]));
        }
        Ok(data_len.saturating_sub(residue.min(data_len as u32) as usize))
    }

    /// A single bulk transfer (one TRB) on endpoint `dci`.
    fn bulk(&mut self, slot: u8, dci: u8, phys: u64, len: usize) -> Result<usize, XhciError> {
        let ptr = {
            let device = self.devices.get_mut(&slot).ok_or(XhciError::BadSlot)?;
            let ep = device.bulk.iter_mut().find(|e| e.dci == dci).ok_or(XhciError::Unsupported("bulk endpoint missing"))?;
            ep.pending = None;
            ep.last = None;
            let trb = Trb::normal(phys, len as u32, true);
            let ptr = ep.ring.push_td(&mut ep.mem, &[trb])?;
            ep.pending = Some(ptr);
            ptr
        };
        self.ring_doorbell(slot, dci);
        let deadline = Deadline::after_ms(BOT_TIMEOUT_MS);
        loop {
            self.pump();
            let done = {
                let device = self.devices.get(&slot).ok_or(XhciError::PortGone)?;
                let ep = device.bulk.iter().find(|e| e.dci == dci).ok_or(XhciError::Unsupported("bulk endpoint missing"))?;
                ep.last.filter(|(p, _, _)| *p == ptr).map(|(_, code, residual)| (code, residual))
            };
            if let Some((code, residual)) = done {
                if code.is_ok() {
                    return Ok(len - (residual as usize).min(len));
                }
                if code.halts_endpoint() {
                    self.recover_endpoint(slot, dci);
                }
                return Err(XhciError::Transfer(code));
            }
            if deadline.expired() {
                self.recover_endpoint(slot, dci);
                return Err(XhciError::Timeout("bulk transfer"));
            }
            self.wait_activity(deadline.tick(), false);
        }
    }

    /// Prepares a mass-storage function that was just configured: SCSI
    /// handshake, capacity, and the block device registration.
    pub(super) fn setup_storage(&mut self, slot: u8) -> Result<(), XhciError> {
        let ac64 = self.caps.ac64;
        let (dci_in, dci_out, port) = {
            let device = self.devices.get(&slot).ok_or(XhciError::BadSlot)?;
            let mut din = None;
            let mut dout = None;
            for ep in &device.bulk {
                if ep.in_endpoint {
                    din = Some(ep.dci);
                } else {
                    dout = Some(ep.dci);
                }
            }
            (
                din.ok_or(XhciError::Unsupported("no bulk IN endpoint"))?,
                dout.ok_or(XhciError::Unsupported("no bulk OUT endpoint"))?,
                device.port,
            )
        };
        let generation = GENERATIONS.fetch_add(1, Ordering::Relaxed) + 1;
        let gone = Arc::new(AtomicBool::new(false));
        {
            let device = self.devices.get_mut(&slot).ok_or(XhciError::BadSlot)?;
            device.storage = Some(StorageState {
                dci_in,
                dci_out,
                cbw: DmaPage::new(ac64)?,
                csw: DmaPage::new(ac64)?,
                data: DmaPage::new(ac64)?,
                tag: 0,
                generation,
                failed: false,
                gone: gone.clone(),
                disk_name: String::new(),
            });
        }

        // TEST UNIT READY: a spinning disk may need several seconds.
        let mut ready = false;
        let mut last_error = None;
        for attempt in 0..20 {
            match self.scsi(slot, &[SCSI_TEST_UNIT_READY, 0, 0, 0, 0, 0], false, 0, None) {
                Ok(_) => {
                    ready = true;
                    break;
                }
                Err(e) => {
                    last_error = Some(e);
                    if attempt < 19 {
                        timer::sleep_ms(200);
                    }
                }
            }
        }
        if !ready {
            return Err(last_error.unwrap_or(XhciError::Timeout("device not ready")));
        }

        let mut inq = [0u8; 36];
        let n = self.scsi(slot, &[SCSI_INQUIRY, 0, 0, 0, 36, 0], true, 36, None)?;
        if let Some(state) = self.devices.get(&slot).and_then(|d| d.storage.as_ref()) {
            state.data.copy_out(&mut inq[..n.min(36)]);
        }
        let vendor = ascii(&inq[8..16]);
        let product = ascii(&inq[16..32]);
        let revision = ascii(&inq[32..36]);

        let mut cap = [0u8; 8];
        let n = self.scsi(slot, &[SCSI_READ_CAPACITY_10, 0, 0, 0, 0, 0, 0, 0, 0, 0], true, 8, None)?;
        if let Some(state) = self.devices.get(&slot).and_then(|d| d.storage.as_ref()) {
            state.data.copy_out(&mut cap[..n.min(8)]);
        }
        let mut last_lba = be32(&cap[0..4]) as u64;
        let mut block_len = be32(&cap[4..8]);
        if last_lba == 0xFFFF_FFFF {
            // Larger than 2 TiB: READ CAPACITY(16).
            let mut cap16 = [0u8; 32];
            let n = self.scsi(slot, &[SCSI_READ_CAPACITY_16, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], true, 32, None)?;
            if let Some(state) = self.devices.get(&slot).and_then(|d| d.storage.as_ref()) {
                state.data.copy_out(&mut cap16[..n.min(32)]);
            }
            last_lba = be64(&cap16[0..8]);
            block_len = be32(&cap16[8..12]);
        }
        if block_len != 512 {
            return Err(XhciError::Unsupported("logical block size is not 512 bytes"));
        }
        let sectors = last_lba.saturating_add(1);
        if sectors == 0 {
            return Err(XhciError::Unsupported("device reports no sectors"));
        }
        let index = DISKS.fetch_add(1, Ordering::Relaxed);
        let name = alloc::format!("usb{index}");
        let what = if product.is_empty() {
            alloc::format!("on port {}", port)
        } else {
            alloc::format!("\"{}\" rev {} on port {}", product, revision, port)
        };
        kprintln!(
            "usb-storage {}: {} sectors ({} MiB), {} {}",
            name,
            sectors,
            sectors >> 11,
            vendor,
            what
        );
        let model = match (vendor.is_empty(), product.is_empty()) {
            (false, false) => alloc::format!("{vendor} {product}"),
            (true, false) => product.clone(),
            (false, true) => vendor.clone(),
            (true, true) => String::new(),
        };
        if let Some(state) = self.devices.get_mut(&slot).and_then(|d| d.storage.as_mut()) {
            state.disk_name = name.clone();
        }
        block::register(Arc::new(UsbDisk { controller: self.index, slot, generation, name, what, model, sectors, gone }));
        Ok(())
    }
}
