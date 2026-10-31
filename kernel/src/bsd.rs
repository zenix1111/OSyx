//! Host side of the OpenBSD driver compatibility layer (`drivers/bsd`).
//!
//! OpenBSD's own network drivers (C, compiled by `build.rs` with clang)
//! run on top of `drivers/bsd/compat/compat.c`, which implements the
//! OpenBSD kernel interfaces they use with the `osyx_bsd_*` services
//! below. Currently built in: re(4) (RTL8111/8168/8101/8169), rl(4)
//! (RTL8139), the MII PHY drivers rgephy, rlphy and ukphy, and Wi-Fi:
//! iwm(4) (Intel 7260 .. 9560, including the Wireless-AC 9260) on the
//! net80211 stack, with firmware from `/etc/firmware`; and sound: azalia(4)
//! (Intel High Definition Audio), used by [`crate::audio`].
//!
//! Wi-Fi is configured through files, without new system calls: the bsd
//! thread rereads `/etc/osyx/wifi.conf` (`ssid=` and `psk=` lines) when
//! it changes and writes the state and the scan results to
//! `/run/wifi.status` every two seconds.
//!
//! All C code runs under [`BIG_LOCK`]; its interrupt handlers, timeouts
//! and tasks are run by the "bsd" thread every tick. Attached interfaces
//! join the network stack as [`BsdNic`] devices.

use crate::mem::{self, PAGE_SIZE};
use crate::sync::{IrqSpinLock, KMutex};
use crate::{interrupts, kprintln, pci};
use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use osyx_net::wire::MacAddr;

/// Serialises every call into the C drivers.
pub(crate) static BIG_LOCK: KMutex<()> = KMutex::new(());
/// Interfaces by the handle `osyx_bsd_ether_attach` returned.
static NICS: IrqSpinLock<Vec<Arc<BsdNic>>> = IrqSpinLock::new(Vec::new());
/// Receive queue bound so a stalled stack cannot exhaust memory.
const RX_QUEUE_MAX: usize = 512;
/// DMA memory for drivers that only address 32 bits.
const DMA_LIMIT: u64 = 1 << 32;

#[cfg(osyx_bsd)]
extern "C" {
    fn osyx_bsd_service();
    fn osyx_bsd_pci_attach(tag: u32, bus: u32, dev: u32, func: u32) -> i32;
    fn osyx_bsd_ifup(ifp: *mut c_void) -> i32;
    fn osyx_bsd_output(ifp: *mut c_void, frame: *const u8, len: usize) -> i32;
    fn osyx_bsd_link_is_up(ifp: *mut c_void) -> i32;
    fn osyx_bsd_counters(ifp: *mut c_void, out: *mut u64);
    fn osyx_bsd_media(ifp: *mut c_void, active: *mut u64) -> u64;
    fn osyx_bsd_is_wireless(ifp: *mut c_void) -> i32;
    fn osyx_bsd_mountroot();
    fn osyx_bsd_wifi_join(ifp: *mut c_void, ssid: *const u8, ssid_len: usize, pass: *const u8) -> i32;
    fn osyx_bsd_wifi_status(ifp: *mut c_void, buf: *mut u8, cap: usize) -> usize;
    fn osyx_bsd_mac_address(ifp: *mut c_void, mac: *mut u8);
    fn osyx_bsd_audio_count() -> i32;
}

const WIFI_CONF: &str = "/etc/osyx/wifi.conf";
const WIFI_STATUS: &str = "/run/wifi.status";
#[cfg(osyx_bsd)]
const WIFI_RECONNECT: &str = "/run/wifi.reconnect";
/// Networks that connected once: `ssid<TAB>passphrase` lines, most recent
/// first. Written by the kernel only, readable by root only.
const WIFI_KNOWN: &str = "/etc/osyx/wifi-known.conf";
/// The Wi-Fi firmware is loaded and the interface started.
#[cfg(osyx_bsd)]
static WIFI_READY: AtomicBool = AtomicBool::new(false);

/// One interface of a C driver.
pub struct BsdNic {
    pub name: String,
    pub location: pci::Address,
    pub mac: MacAddr,
    ifp: usize,
    rx: IrqSpinLock<VecDeque<Vec<u8>>>,
    link: AtomicBool,
    wireless: AtomicBool,
}

impl BsdNic {
    pub fn is_wireless(&self) -> bool {
        self.wireless.load(Ordering::Acquire)
    }

    pub fn mac_address(&self) -> MacAddr {
        #[cfg(osyx_bsd)]
        {
            let mut mac = [0; 6];
            let _g = BIG_LOCK.lock();
            // SAFETY: the interface remains attached and mac has six bytes.
            unsafe { osyx_bsd_mac_address(self.ifp as *mut c_void, mac.as_mut_ptr()) };
            MacAddr(mac)
        }
        #[cfg(not(osyx_bsd))]
        { self.mac }
    }

    pub fn link_up(&self) -> bool {
        self.link.load(Ordering::Acquire)
    }

    pub fn has_interrupts(&self) -> bool {
        // The bsd thread polls the driver every tick and wakes the network
        // thread when frames arrive.
        true
    }

    pub fn counters(&self) -> crate::drivers::virtio_net::Counters {
        let mut c = [0u64; 4];
        #[cfg(osyx_bsd)]
        {
            let _g = BIG_LOCK.lock();
            // SAFETY: `ifp` is a live ifnet of an attached driver; the lock is held.
            unsafe { osyx_bsd_counters(self.ifp as *mut c_void, c.as_mut_ptr()) };
        }
        crate::drivers::virtio_net::Counters { rx_frames: c[0], tx_frames: c[1], rx_errors: c[2], ..Default::default() }
    }

    pub fn receive(&self, out: &mut Vec<Vec<u8>>) {
        out.extend(self.rx.lock().drain(..));
    }

    pub fn transmit(&self, frames: &[Vec<u8>]) -> usize {
        let mut sent = 0;
        #[cfg(osyx_bsd)]
        {
            let _g = BIG_LOCK.lock();
            for f in frames {
                // SAFETY: as in `counters`; the frame outlives the call (copied into an mbuf).
                if unsafe { osyx_bsd_output(self.ifp as *mut c_void, f.as_ptr(), f.len()) } == 0 {
                    sent += 1;
                }
            }
        }
        #[cfg(not(osyx_bsd))]
        let _ = frames;
        sent
    }

    pub fn recover(&self) -> bool {
        #[cfg(osyx_bsd)]
        {
            let _g = BIG_LOCK.lock();
            // SAFETY: as in `counters`.
            let up = unsafe { osyx_bsd_link_is_up(self.ifp as *mut c_void) } != 0;
            self.link.store(up, Ordering::Release);
        }
        false
    }
}

/// Interfaces attached during one probe call (filled by the C side).
static PENDING: IrqSpinLock<Vec<Arc<BsdNic>>> = IrqSpinLock::new(Vec::new());
static LOCATION: IrqSpinLock<Option<pci::Address>> = IrqSpinLock::new(None);

/// Offers each PCI function to the OpenBSD drivers. Returns the attached
/// interfaces and the functions they took.
pub fn probe(devices: &[pci::Device]) -> Vec<Arc<BsdNic>> {
    #[cfg(not(osyx_bsd))]
    {
        let _ = devices;
        Vec::new()
    }
    #[cfg(osyx_bsd)]
    {
        let mut all = Vec::new();
        {
            let _g = BIG_LOCK.lock();
            // Network controllers and High Definition Audio controllers.
            for d in devices.iter().filter(|d| d.class == 0x02 || (d.class == 0x04 && d.subclass == 0x03)) {
                *LOCATION.lock() = Some(d.addr);
                // A driver can hang a real machine: the live stick's log
                // copy must end before the attach.
                kprintln!("bsd: offering {} ({:04x}:{:04x}) to the drivers", d.addr, d.vendor, d.device);
                crate::serial::sync_log_file();
                let tag = (d.addr.bus as u32) << 16 | (d.addr.device as u32) << 11 | (d.addr.function as u32) << 8;
                // SAFETY: the lock is held; C only reads the arguments.
                unsafe { osyx_bsd_pci_attach(tag, d.addr.bus as u32, d.addr.device as u32, d.addr.function as u32) };
                for nic in PENDING.lock().drain(..) {
                    // SAFETY: a freshly attached ifnet; the lock is held.
                    let wireless = unsafe { osyx_bsd_is_wireless(nic.ifp as *mut c_void) } != 0;
                    nic.wireless.store(wireless, Ordering::Relaxed);
                    // Wi-Fi needs its firmware from the root file system:
                    // it comes up in `after_mount`.
                    if !wireless {
                        // SAFETY: as above.
                        let e = unsafe { osyx_bsd_ifup(nic.ifp as *mut c_void) };
                        if e != 0 {
                            kprintln!("bsd: {}: bringing the interface up failed (error {})", nic.name, e);
                        }
                    }
                    all.push(nic);
                }
            }
        }
        // SAFETY: the C side only reads its table.
        let sound = unsafe { osyx_bsd_audio_count() } > 0;
        if !all.is_empty() || sound {
            crate::sched::spawn_kernel("bsd", service_thread, 0, 0);
        }
        all
    }
}

/// Runs the deferred attach steps that need the root file system (iwm
/// reads its firmware there) and brings the Wi-Fi interfaces up.
pub fn after_mount() {
    #[cfg(osyx_bsd)]
    {
        let wifi: Vec<Arc<BsdNic>> = NICS.lock().iter().filter(|n| n.wireless.load(Ordering::Relaxed)).cloned().collect();
        let _g = BIG_LOCK.lock();
        kprintln!("bsd: deferred attach steps (Wi-Fi firmware)");
        crate::serial::sync_log_file();
        // SAFETY: the lock is held.
        unsafe { osyx_bsd_mountroot() };
        for nic in wifi {
            kprintln!("bsd: {}: bringing Wi-Fi up", nic.name);
            crate::serial::sync_log_file();
            // SAFETY: an attached ifnet; the lock is held.
            let e = unsafe { osyx_bsd_ifup(nic.ifp as *mut c_void) };
            if e != 0 {
                kprintln!("bsd: {}: Wi-Fi did not come up (error {}): is /etc/firmware complete?", nic.name, e);
            } else {
                kprintln!("bsd: {}: Wi-Fi up, scanning", nic.name);
            }
        }
        // Joins (wifi.conf, saved networks) wait for the firmware.
        WIFI_READY.store(true, Ordering::Release);
    }
    // /dev/audio and the status file need devfs and /run.
    crate::audio::init();
}

#[cfg(osyx_bsd)]
fn service_thread(_: u64, _: u64) {
    let mut last_conf: Option<(i64, u64)> = None;
    let mut last_state = String::new();
    let mut last_reconnect = None;
    let mut watch = JoinWatch::default();
    let mut memory = WifiMemory::default();
    let mut media: Vec<(u64, u64)> = Vec::new();
    let mut next_wifi = 0;
    loop {
        {
            let _g = BIG_LOCK.lock();
            // SAFETY: the lock is held.
            unsafe { osyx_bsd_service() };
        }
        let now = interrupts::ticks();
        if now >= next_wifi {
            next_wifi = now + crate::arch::timer::ms_to_ticks(2000);
            wifi_housekeeping(&mut last_conf, &mut last_reconnect, &mut last_state, &mut watch, &mut memory);
            log_wired_media(&mut media);
        }
        crate::arch::timer::sleep_ms(1);
    }
}

/// Logs what the PHY of each wired interface reports whenever it changes
/// (`last`: status and media per interface): tells a PHY that sees no cable
/// from a link that does not reach the network stack.
#[cfg(osyx_bsd)]
fn log_wired_media(last: &mut Vec<(u64, u64)>) {
    const IFM_AVALID: u64 = 1;
    const IFM_ACTIVE: u64 = 2;
    let nics: Vec<Arc<BsdNic>> = NICS.lock().iter().filter(|n| !n.wireless.load(Ordering::Relaxed)).cloned().collect();
    last.resize(nics.len(), (u64::MAX, u64::MAX));
    for (nic, seen) in nics.iter().zip(last.iter_mut()) {
        let mut active = 0u64;
        let status = {
            let _g = BIG_LOCK.lock();
            // SAFETY: an attached ifnet; `active` outlives the call; the lock is held.
            unsafe { osyx_bsd_media(nic.ifp as *mut c_void, &mut active) }
        };
        if (status, active) != *seen {
            let cable = match (status & IFM_AVALID != 0, status & IFM_ACTIVE != 0) {
                (true, true) => "cable connected",
                (true, false) => "no cable or no link partner",
                (false, _) => "status unknown",
            };
            kprintln!("bsd: {}: PHY {cable} (status {status:#x}, media {active:#x})", nic.name);
            *seen = (status, active);
        }
    }
}

/// How long an association may stay without keys before the passphrase is
/// taken to be wrong. The access point repeats message 1 of the 4-way
/// handshake while it rejects message 2; a correct key needs well under a
/// second.
#[cfg(osyx_bsd)]
const HANDSHAKE_LIMIT_MS: u64 = 8000;

/// The network last joined and how its WPA handshake goes.
#[cfg(osyx_bsd)]
#[derive(Default)]
struct JoinWatch {
    /// When the association without keys began (ticks).
    keyless_since: Option<u64>,
    /// The handshake failed: `/run/wifi.status` says "error wrong-password"
    /// until the next join.
    wrong_password: bool,
    /// Frame counters (in, out, in errors, out errors) last logged, and the
    /// housekeeping rounds since the join: they go to the log every 10 s
    /// while they change, to tell a silent data path from a quiet one.
    counters: [u64; 4],
    rounds: u32,
    /// Joins applied so far: `/run/wifi.status` says "join N", so the
    /// desktop can tell the outcome of its own attempt from an older one.
    joins: u64,
    /// Previously successful credentials should be retried after transient failures.
    trusted: bool,
    last_error: Option<String>,
}

/// Saved networks and the attempt in progress (across joins).
#[cfg(osyx_bsd)]
#[derive(Default)]
struct WifiMemory {
    /// (SSID, passphrase; empty for an open network), most recent first.
    known: Vec<(String, String)>,
    loaded: bool,
    /// The network of the current attempt and its passphrase.
    target: Option<(String, String)>,
    /// The current attempt connected and is saved.
    saved: bool,
    /// When the last join started (ticks; 0: none yet).
    last_join: u64,
    /// Saved networks tried automatically since the last connection.
    tried: Vec<String>,
    /// Saved networks whose passphrase the access point rejected.
    rejected: Vec<String>,
}

/// How long an attempt may take before a saved network is tried instead.
#[cfg(osyx_bsd)]
const AUTO_JOIN_AFTER_MS: u64 = 30_000;

#[cfg(osyx_bsd)]
impl WifiMemory {
    fn load(&mut self) {
        if self.loaded {
            return;
        }
        self.loaded = true;
        let Some(data) = read_file(WIFI_KNOWN) else { return };
        for line in String::from_utf8_lossy(&data).lines() {
            if let Some((ssid, pass)) = line.split_once('\t') {
                if !ssid.is_empty() && !self.known.iter().any(|k| k.0 == ssid) {
                    self.known.push((String::from(ssid), String::from(pass)));
                }
            }
        }
    }

    fn save(&self) {
        use osyx_abi::{OPEN_CREATE, OPEN_TRUNCATE, OPEN_WRITE};
        let mut text = String::new();
        for (ssid, pass) in &self.known {
            text.push_str(ssid);
            text.push('\t');
            text.push_str(pass);
            text.push('\n');
        }
        let cx = crate::vfs::Lookup::kernel();
        match crate::vfs::open(&cx, WIFI_KNOWN, OPEN_WRITE | OPEN_CREATE | OPEN_TRUNCATE, 0o600) {
            Ok(mut f) => {
                if f.write(text.as_bytes()).is_err() || f.sync().is_err() {
                    kprintln!("bsd: cannot write {WIFI_KNOWN}");
                }
            }
            Err(e) => kprintln!("bsd: cannot write {WIFI_KNOWN}: {e:?}"),
        }
    }

    fn passphrase(&self, ssid: &str) -> Option<&str> {
        self.known.iter().find(|k| k.0 == ssid).map(|k| k.1.as_str())
    }
}

/// Starts joining `ssid` (an empty passphrase: an open network).
#[cfg(osyx_bsd)]
fn wifi_join(nic: &BsdNic, ssid: &str, pass: &str, watch: &mut JoinWatch, memory: &mut WifiMemory, why: &str) {
    let mut p = pass.as_bytes().to_vec();
    p.push(0);
    let e = {
        let _g = BIG_LOCK.lock();
        // SAFETY: an attached ifnet; the strings outlive the call; the lock is held.
        unsafe { osyx_bsd_wifi_join(nic.ifp as *mut c_void, ssid.as_ptr(), ssid.len(), p.as_ptr()) }
    };
    p.fill(0);
    let trusted = memory.passphrase(ssid) == Some(pass);
    *watch = JoinWatch { joins: watch.joins + 1, trusted, ..JoinWatch::default() };
    memory.target = Some((String::from(ssid), String::from(pass)));
    memory.saved = false;
    memory.last_join = interrupts::ticks().max(1);
    match e {
        0 => kprintln!("bsd: {}: joining \"{}\" ({why})", nic.name, ssid),
        e => {
            watch.last_error = Some(alloc::format!("Join failed (error {e})"));
            kprintln!("bsd: {}: cannot join \"{}\" (error {})", nic.name, ssid, e);
        }
    }
}

/// Applies a changed `/etc/osyx/wifi.conf` (`ssid=` and `psk=` to join, a
/// saved network's passphrase when `psk=` is left out; `forget=` to drop a
/// saved network), saves networks that connect, joins the strongest saved
/// network in range when nothing is connected, and refreshes
/// `/run/wifi.status`; changes of the association state go to the log.
#[cfg(osyx_bsd)]
fn wifi_housekeeping(last_conf: &mut Option<(i64, u64)>, last_reconnect: &mut Option<(i64, u64)>, last_state: &mut String, watch: &mut JoinWatch, memory: &mut WifiMemory) {
    let Some(nic) = NICS.lock().iter().find(|n| n.wireless.load(Ordering::Relaxed)).cloned() else { return };
    if !WIFI_READY.load(Ordering::Acquire) {
        return;
    }
    memory.load();
    let cx = crate::vfs::Lookup::kernel();
    let stamp = crate::vfs::stat(&cx, WIFI_CONF).ok().map(|s| (s.mtime_ns, s.size));
    if stamp.is_some() && stamp != *last_conf {
        *last_conf = stamp;
        if let Some(text) = read_file(WIFI_CONF) {
            let text = String::from_utf8_lossy(&text);
            let field = |k: &str| text.lines().find_map(|l| l.trim().strip_prefix(k).map(String::from));
            if let Some(gone) = field("forget=") {
                memory.known.retain(|k| k.0 != gone);
                memory.rejected.retain(|r| *r != gone);
                memory.save();
                kprintln!("bsd: {}: forgot \"{}\"", nic.name, gone);
            }
            if let Some(ssid) = field("ssid=").filter(|s| !s.is_empty()) {
                let pass = match field("psk=").filter(|p| !p.is_empty()) {
                    Some(p) => p,
                    None => String::from(memory.passphrase(&ssid).unwrap_or("")),
                };
                memory.rejected.retain(|r| *r != ssid);
                wifi_join(&nic, &ssid, &pass, watch, memory, "requested");
            }
        }
    }
    // A separate request file avoids overwriting saved Wi-Fi credentials.
    let reconnect = crate::vfs::stat(&cx, WIFI_RECONNECT).ok().map(|s| (s.mtime_ns, s.size));
    if reconnect.is_some() && reconnect != *last_reconnect {
        *last_reconnect = reconnect;
        let target = memory.target.clone().or_else(|| memory.known.first().cloned());
        if let Some((ssid, pass)) = target {
            memory.rejected.retain(|s| *s != ssid);
            wifi_join(&nic, &ssid, &pass, watch, memory, "reconnect requested");
        } else {
            watch.last_error = Some(String::from("No saved network to reconnect"));
        }
    }
    let mut buf = alloc::vec![0u8; 8192];
    let n = {
        let _g = BIG_LOCK.lock();
        // SAFETY: as above; `buf` has the given capacity.
        unsafe { osyx_bsd_wifi_status(nic.ifp as *mut c_void, buf.as_mut_ptr(), buf.len()) }
    };
    buf.truncate(n);
    // The association lines come before the scan results ("net\t...").
    let text = String::from_utf8_lossy(&buf);
    let state: String =
        text.lines().take_while(|l| !l.starts_with("net\t")).filter(|l| !l.starts_with("rssi ")).collect::<Vec<_>>().join(", ");
    if state != *last_state {
        kprintln!("bsd: {}: {}", nic.name, state);
        *last_state = state;
    }
    // Only keys end the watch: the access point dropping the station after
    // failed handshakes is part of the same failed attempt.
    let now = interrupts::ticks();
    match text.lines().find_map(|l| l.strip_prefix("keys ")) {
        Some("yes") => watch.keyless_since = None,
        Some(_) => match watch.keyless_since {
            None => watch.keyless_since = Some(now),
            Some(since) if !watch.trusted && !memory.saved && !watch.wrong_password && now.saturating_sub(since) >= crate::arch::timer::ms_to_ticks(HANDSHAKE_LIMIT_MS) => {
                kprintln!("bsd: {}: the WPA handshake does not finish: wrong password", nic.name);
                watch.wrong_password = true;
                watch.last_error = Some(String::from("WPA handshake failed; check password"));
            }
            Some(_) => {}
        },
        None => {}
    }
    let connected = text.lines().any(|l| l == "keys yes");
    let current_ssid = text.lines().find_map(|l| l.strip_prefix("ssid ")).map(String::from);
    // In range: (SSID, RSSI) of the scan results.
    let seen: Vec<(String, u32)> = text
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() >= 5 && f[0] == "net").then(|| (String::from(f[1]), f[2].parse().unwrap_or(0)))
        })
        .collect();
    drop(text);
    // A network that connected is saved (most recent first).
    if connected && !memory.saved {
        if let Some((ssid, pass)) = memory.target.clone().filter(|t| current_ssid.as_deref() == Some(t.0.as_str())) {
            memory.known.retain(|k| k.0 != ssid);
            memory.known.insert(0, (ssid.clone(), pass));
            memory.save();
            memory.saved = true;
            watch.trusted = true;
            watch.wrong_password = false;
            watch.last_error = None;
            memory.rejected.retain(|r| *r != ssid);
            memory.tried.clear();
            kprintln!("bsd: {}: \"{}\" saved", nic.name, ssid);
        }
    }
    if watch.wrong_password {
        if let Some((ssid, _)) = &memory.target {
            if !memory.rejected.contains(ssid) {
                memory.rejected.push(ssid.clone());
            }
        }
    }
    // Nothing connected for a while: the strongest saved network in range
    // that was not tried yet (all tried: start over).
    let idle = memory.last_join == 0 || now.saturating_sub(memory.last_join) >= crate::arch::timer::ms_to_ticks(AUTO_JOIN_AFTER_MS);
    if !connected && idle {
        let best = |memory: &WifiMemory, tried: &[String]| {
            seen.iter()
                .filter(|(s, _)| memory.passphrase(s).is_some() && !memory.rejected.contains(s) && !tried.contains(s))
                .max_by_key(|(_, rssi)| *rssi)
                .map(|(s, _)| s.clone())
        };
        let mut pick = best(memory, &memory.tried);
        if pick.is_none() && !memory.tried.is_empty() {
            memory.tried.clear();
            pick = best(memory, &[]);
        }
        if pick.is_none() {
            pick = memory.target.as_ref().filter(|(s, _)| memory.passphrase(s).is_some() && !memory.rejected.contains(s)).map(|(s, _)| s.clone());
        }
        if let Some(ssid) = pick {
            let pass = String::from(memory.passphrase(&ssid).unwrap_or(""));
            memory.tried.push(ssid.clone());
            wifi_join(&nic, &ssid, &pass, watch, memory, "saved network");
        }
    }
    buf.extend_from_slice(alloc::format!("join {}\n", watch.joins).as_bytes());
    if watch.wrong_password {
        buf.extend_from_slice(b"error wrong-password\n");
    }
    if let Some(error) = &watch.last_error {
        buf.extend_from_slice(alloc::format!("last_error {error}\n").as_bytes());
    }
    for (ssid, _) in &memory.known {
        buf.extend_from_slice(alloc::format!("known\t{ssid}\n").as_bytes());
    }
    write_file(WIFI_STATUS, &buf);
    watch.rounds += 1;
    if watch.rounds % 5 == 0 {
        let mut c = [0u64; 4];
        {
            let _g = BIG_LOCK.lock();
            // SAFETY: an attached ifnet; `c` has room for the four counters.
            unsafe { osyx_bsd_counters(nic.ifp as *mut c_void, c.as_mut_ptr()) };
        }
        if c != watch.counters {
            kprintln!("bsd: {}: frames in {} out {}, errors in {} out {}", nic.name, c[0], c[1], c[2], c[3]);
            watch.counters = c;
        }
    }
}

pub(crate) fn read_file(path: &str) -> Option<Vec<u8>> {
    use osyx_abi::OPEN_READ;
    let cx = crate::vfs::Lookup::kernel();
    let mut f = crate::vfs::open(&cx, path, OPEN_READ, 0).ok()?;
    let mut out = Vec::new();
    let mut chunk = alloc::vec![0u8; 64 * 1024];
    loop {
        match f.read(&mut chunk) {
            Ok(0) => return Some(out),
            Ok(n) => {
                // `File::read` leaves the position alone: without this the
                // first chunk is read again forever and `out` grows until
                // the kernel heap is exhausted.
                out.extend_from_slice(&chunk[..n]);
                f.advance(n);
            }
            Err(_) => return None,
        }
    }
}

pub(crate) fn write_file(path: &str, data: &[u8]) {
    use osyx_abi::{OPEN_CREATE, OPEN_TRUNCATE, OPEN_WRITE};
    let cx = crate::vfs::Lookup::kernel();
    if let Ok(mut f) = crate::vfs::open(&cx, path, OPEN_WRITE | OPEN_CREATE | OPEN_TRUNCATE, 0o644) {
        let _ = f.write(data);
    }
}

#[no_mangle]
extern "C" fn osyx_bsd_file_size(path: *const u8) -> i64 {
    // SAFETY: C passes a NUL-terminated path.
    let p = unsafe { core::ffi::CStr::from_ptr(path as *const core::ffi::c_char) };
    let Ok(p) = p.to_str() else { return -1 };
    crate::vfs::stat(&crate::vfs::Lookup::kernel(), p).map_or(-1, |s| s.size as i64)
}

#[no_mangle]
extern "C" fn osyx_bsd_file_read(path: *const u8, buf: *mut u8, len: usize) -> i64 {
    // SAFETY: C passes a NUL-terminated path and `len` writable bytes.
    let (p, out) = unsafe { (core::ffi::CStr::from_ptr(path as *const core::ffi::c_char), core::slice::from_raw_parts_mut(buf, len)) };
    let Some(data) = p.to_str().ok().and_then(read_file) else { return -1 };
    let n = data.len().min(len);
    out[..n].copy_from_slice(&data[..n]);
    n as i64
}

// ---- services for the C side ------------------------------------------------------------

#[no_mangle]
extern "C" fn osyx_bsd_alloc(size: usize, align: usize) -> *mut c_void {
    let Ok(layout) = core::alloc::Layout::from_size_align(size.max(1), align.max(8)) else { return core::ptr::null_mut() };
    // SAFETY: non-zero size.
    unsafe { alloc::alloc::alloc(layout) as *mut c_void }
}

#[no_mangle]
extern "C" fn osyx_bsd_free(p: *mut c_void, size: usize, align: usize) {
    if p.is_null() {
        return;
    }
    let layout = core::alloc::Layout::from_size_align(size.max(1), align.max(8)).expect("layout used for the allocation");
    // SAFETY: allocated by `osyx_bsd_alloc` with the same layout.
    unsafe { alloc::alloc::dealloc(p as *mut u8, layout) }
}

#[no_mangle]
extern "C" fn osyx_bsd_dma_alloc(size: usize, align: usize) -> u64 {
    let pages = (size as u64).div_ceil(PAGE_SIZE).max(1);
    mem::alloc_frames_contiguous(pages, (align as u64).max(PAGE_SIZE), DMA_LIMIT).unwrap_or(0)
}

#[no_mangle]
extern "C" fn osyx_bsd_dma_free(pa: u64, size: usize) {
    let pages = (size as u64).div_ceil(PAGE_SIZE).max(1);
    for i in 0..pages {
        if let Err(e) = mem::free_frame(pa + i * PAGE_SIZE) {
            kprintln!("bsd: DMA free of {:#x}: {:?}", pa + i * PAGE_SIZE, e);
        }
    }
}

#[no_mangle]
extern "C" fn osyx_bsd_phys_to_virt(pa: u64) -> u64 {
    mem::phys_to_virt(pa)
}

#[no_mangle]
extern "C" fn osyx_bsd_virt_to_phys(va: u64) -> u64 {
    let (base, size) = (mem::hhdm_offset(), mem::hhdm_size());
    if va >= base && va < base + size {
        return va - base;
    }
    mem::paging::translate(va).map_or(0, |t| (t.phys & !(t.page_size - 1)) + (va & (t.page_size - 1)))
}

#[no_mangle]
extern "C" fn osyx_bsd_log(s: *const u8, len: usize) {
    // SAFETY: C passes `len` readable bytes.
    let b = unsafe { core::slice::from_raw_parts(s, len) };
    kprintln!("bsd: {}", core::str::from_utf8(b).unwrap_or("<invalid utf-8>"));
}

#[no_mangle]
extern "C" fn osyx_bsd_delay_us(us: u64) {
    let t = crate::arch::timer::tsc;
    let end = t().saturating_add(crate::arch::timer::tsc_khz().saturating_mul(us) / 1000);
    while t() < end {
        core::hint::spin_loop();
    }
}

/// Milliseconds from the TSC. Not the timer tick count: CPU 0 counts ticks
/// only after taking the kernel entry lock, so a BSD sleeper holding it on
/// another CPU would wait for a deadline that never comes.
#[no_mangle]
extern "C" fn osyx_bsd_ticks() -> u64 {
    crate::arch::timer::tsc() / crate::arch::timer::tsc_khz().max(1)
}

/// Gives the CPU away for about a tick (and with it the kernel entry lock),
/// so the rest of the system runs while a BSD driver sleeps.
#[no_mangle]
extern "C" fn osyx_bsd_yield() {
    crate::arch::timer::sleep_ms(1);
}

#[no_mangle]
extern "C" fn osyx_bsd_panic(msg: *const u8) -> ! {
    // SAFETY: C passes a NUL-terminated string.
    let s = unsafe { core::ffi::CStr::from_ptr(msg as *const core::ffi::c_char) };
    panic!("OpenBSD driver: {}", s.to_str().unwrap_or("<invalid utf-8>"));
}

fn tag_address(tag: u32) -> pci::Address {
    pci::Address { bus: (tag >> 16) as u8, device: ((tag >> 11) & 0x1f) as u8, function: ((tag >> 8) & 7) as u8 }
}

#[no_mangle]
extern "C" fn osyx_bsd_pci_read(tag: u32, reg: i32) -> u32 {
    if !(0..256).contains(&reg) {
        return u32::MAX;
    }
    tag_address(tag).read32(reg as u8)
}

#[no_mangle]
extern "C" fn osyx_bsd_pci_write(tag: u32, reg: i32, v: u32) {
    if (0..256).contains(&reg) {
        tag_address(tag).write32(reg as u8, v);
    }
}

#[no_mangle]
extern "C" fn osyx_bsd_map_mmio(pa: u64, size: u64) -> u64 {
    mem::map_mmio(pa, size).unwrap_or(0)
}

#[no_mangle]
extern "C" fn osyx_bsd_random(buf: *mut u8, len: usize) {
    // SAFETY: C passes `len` writable bytes.
    let b = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    let _ = crate::random::fill(b);
}

#[no_mangle]
extern "C" fn osyx_bsd_ether_attach(ifp: *mut c_void, mac: *const u8, name: *const u8) -> i32 {
    // SAFETY: C passes a 6-byte address and a NUL-terminated name.
    let (mac, name) = unsafe {
        let mut m = [0u8; 6];
        m.copy_from_slice(core::slice::from_raw_parts(mac, 6));
        (m, core::ffi::CStr::from_ptr(name as *const core::ffi::c_char))
    };
    let nic = Arc::new(BsdNic {
        name: String::from(name.to_str().unwrap_or("bsd?")),
        location: LOCATION.lock().unwrap_or(pci::Address { bus: 0, device: 0, function: 0 }),
        mac: MacAddr(mac),
        ifp: ifp as usize,
        rx: IrqSpinLock::new(VecDeque::new()),
        link: AtomicBool::new(false),
        wireless: AtomicBool::new(false),
    });
    let mut nics = NICS.lock();
    nics.push(nic.clone());
    PENDING.lock().push(nic);
    (nics.len() - 1) as i32
}

#[no_mangle]
extern "C" fn osyx_bsd_ether_input(handle: i32, frame: *const u8, len: usize) {
    let Some(nic) = NICS.lock().get(handle as usize).cloned() else { return };
    // SAFETY: C passes `len` readable bytes.
    let f = unsafe { core::slice::from_raw_parts(frame, len) }.to_vec();
    let mut q = nic.rx.lock();
    if q.len() < RX_QUEUE_MAX {
        q.push_back(f);
    }
    drop(q);
    crate::net::wake();
}

#[no_mangle]
extern "C" fn osyx_bsd_link_state(handle: i32, up: i32) {
    let Some(nic) = NICS.lock().get(handle as usize).cloned() else { return };
    let up = up != 0;
    if nic.link.swap(up, Ordering::AcqRel) != up {
        kprintln!("bsd: {}: link {}", nic.name, if up { "up" } else { "down" });
        crate::net::wake();
    }
}
