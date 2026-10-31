//! IPv4 adapter data and synchronous ICMP echo over OSyx's native stack.
//! Layouts follow the Windows x64 public IP Helper structures.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{fail, out_a, out_w},
    teb,
};
use alloc::{collections::BTreeMap, format, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use os_std::{
    net::{self, Ipv4Addr, PingSocket},
    sync::Mutex,
    time::{Duration, Instant},
};

fn ip(a: [u8; 4]) -> alloc::string::String {
    format!("{}", Ipv4Addr(a))
}
fn mask(prefix: u8) -> [u8; 4] {
    (u32::MAX.checked_shl(32 - prefix.min(32) as u32).unwrap_or(0)).to_be_bytes()
}
fn list() -> Result<Vec<net::NetIface>, u32> {
    net::interfaces().map_err(|_| ERROR_GEN_FAILURE)
}
// IP_ADDR_STRING (48 bytes): pointer, address[16], mask[16], context.
fn addr_string(p: u64, addr: [u8; 4], prefix: u8) {
    out_a(&ip(addr), (p + 8) as *mut u8, 16);
    out_a(&ip(mask(prefix)), (p + 24) as *mut u8, 16);
}
extern "win64" fn GetAdaptersInfo(out: u64, len: *mut u32) -> u32 {
    if len.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let ifs = match list() {
        Ok(v) => v,
        Err(e) => return e,
    };
    let ifs: Vec<_> = ifs.into_iter().filter(|i| i.flags & net::IFF_LOOPBACK == 0).collect();
    if ifs.is_empty() {
        return 232;
    } // ERROR_NO_DATA
    let need = ifs.len() as u32 * 704;
    let cap = unsafe {
        let n = *len;
        *len = need;
        n
    };
    if out == 0 || cap < need {
        return 111;
    } // ERROR_BUFFER_OVERFLOW
    unsafe {
        core::ptr::write_bytes(out as *mut u8, 0, need as usize);
    }
    for (k, i) in ifs.iter().enumerate() {
        let p = out + k as u64 * 704;
        unsafe {
            if k + 1 < ifs.len() {
                teb::put(p, 0, p + 704);
            }
            teb::put(p, 8, i.index as u32);
            teb::put(p, 404, 6u32);
            core::ptr::copy_nonoverlapping(i.mac.as_ptr(), (p + 408) as *mut u8, 6);
            teb::put(p, 416, i.index as u32);
            teb::put(p, 420, if i.flags & net::IFF_WIRELESS != 0 { 71u32 } else { 6u32 });
            teb::put(p, 424, u32::from(i.method == net::CONFIG_DHCP));
        }
        out_a(net::field(&i.name), (p + 12) as *mut u8, 260);
        out_a(&format!("OSyx {}", net::field(&i.name)), (p + 272) as *mut u8, 132);
        addr_string(p + 440, i.addr, i.prefix);
        addr_string(p + 488, i.gateway, 0);
        // OSyx does not expose DHCP server identity or lease start time.
    }
    0
}
extern "win64" fn GetIfTable(out: u64, len: *mut u32, ordered: i32) -> u32 {
    if len.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let mut ifs = match list() {
        Ok(v) => v,
        Err(e) => return e,
    };
    if ordered != 0 {
        ifs.sort_by_key(|i| i.index);
    }
    let need = 4 + ifs.len() as u32 * 860;
    let cap = unsafe {
        let n = *len;
        *len = need;
        n
    };
    if out == 0 || cap < need {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    unsafe {
        core::ptr::write_bytes(out as *mut u8, 0, need as usize);
        teb::put(out, 0, ifs.len() as u32);
    }
    for (k, i) in ifs.iter().enumerate() {
        let p = out + 4 + k as u64 * 860;
        let loopback = i.flags & net::IFF_LOOPBACK != 0;
        let name = net::field(&i.name);
        out_w(name, p as *mut u16, 256);
        unsafe {
            teb::put(p, 512, i.index as u32);
            teb::put(p, 516, if loopback { 24u32 } else if i.flags & net::IFF_WIRELESS != 0 { 71u32 } else { 6u32 });
            teb::put(p, 520, i.mtu);
            // Link speed is not provided by OSyx: leave it unknown (zero).
            if !loopback {
                teb::put(p, 528, 6u32);
                core::ptr::copy_nonoverlapping(i.mac.as_ptr(), (p + 532) as *mut u8, 6);
            }
            teb::put(p, 540, if i.flags & net::IFF_UP != 0 { 1u32 } else { 2u32 });
            teb::put(p, 544, if i.flags & net::IFF_LINK != 0 { 5u32 } else { 0u32 });
            for (off, n) in [
                (552, i.rx_bytes),
                (556, i.rx_packets),
                (564, i.rx_dropped),
                (568, i.rx_errors),
                (576, i.tx_bytes),
                (580, i.tx_packets),
                (588, i.tx_dropped),
            ] {
                teb::put(p, off, n as u32);
            }
            teb::put(p, 600, name.len() as u32);
            core::ptr::copy_nonoverlapping(name.as_ptr(), (p + 604) as *mut u8, name.len());
        }
    }
    0
}
extern "win64" fn GetNetworkParams(out: u64, len: *mut u32) -> u32 {
    if len.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let servers = match net::dns_servers() {
        Ok(v) => v,
        Err(_) => return ERROR_GEN_FAILURE,
    };
    let need = 600 + servers.len().saturating_sub(1) as u32 * 48;
    let cap = unsafe {
        let n = *len;
        *len = need;
        n
    };
    if out == 0 || cap < need {
        return 111;
    }
    unsafe {
        core::ptr::write_bytes(out as *mut u8, 0, need as usize);
    }
    let host = os_std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    out_a(host.trim(), out as *mut u8, 132);
    for (k, server) in servers.iter().enumerate() {
        let p = if k == 0 { out + 272 } else { out + 600 + (k - 1) as u64 * 48 };
        addr_string(p, server.0, 0);
        if k + 1 < servers.len() {
            unsafe {
                teb::put(p, 0, out + 600 + k as u64 * 48);
            }
        }
    }
    unsafe {
        teb::put(out, 320, 8u32);
        teb::put(out, 592, 1u32);
    }
    0
}

static PINGS: Mutex<BTreeMap<u64, Arc<Mutex<PingSocket>>>> = Mutex::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(0x6000_0000);
static SEQ: AtomicU32 = AtomicU32::new(0);
extern "win64" fn IcmpCreateFile() -> u64 {
    match PingSocket::new() {
        Ok(s) => {
            let h = NEXT.fetch_add(4, Ordering::Relaxed);
            PINGS.lock().unwrap().insert(h, Arc::new(Mutex::new(s)));
            h
        }
        Err(_) => fail(ERROR_GEN_FAILURE, u64::MAX),
    }
}
extern "win64" fn IcmpCloseHandle(h: u64) -> i32 {
    if PINGS.lock().unwrap().remove(&h).is_some() {
        1
    } else {
        fail(ERROR_INVALID_HANDLE, 0)
    }
}
extern "win64" fn IcmpSendEcho(
    h: u64,
    dest: u32,
    request: *const u8,
    size: u16,
    options: u64,
    reply: u64,
    reply_size: u32,
    timeout: u32,
) -> u32 {
    if options != 0 {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    if reply == 0 || reply_size < 40 + size as u32 || (size != 0 && request.is_null()) || size > 65000 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(sock) = PINGS.lock().unwrap().get(&h).cloned() else {
        return fail(ERROR_INVALID_HANDLE, 0);
    };
    let sock = sock.lock().unwrap();
    let seq = SEQ.fetch_add(1, Ordering::Relaxed) as u16;
    let data = if size == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(request, size as usize) } };
    let start = Instant::now();
    if sock.send(Ipv4Addr(dest.to_ne_bytes()), seq, data).is_err() {
        return fail(ERROR_GEN_FAILURE, 0);
    }
    let mut buf = vec![0u8; 65536];
    loop {
        let left = Duration::from_millis(timeout as u64).saturating_sub(start.elapsed());
        if left.is_zero() {
            return fail(11010, 0);
        } // IP_REQ_TIMED_OUT
        if sock.set_read_timeout(Some(left)).is_err() {
            return fail(ERROR_GEN_FAILURE, 0);
        }
        let received = match sock.recv(&mut buf) {
            Ok(r) => r,
            Err(_) => return fail(11010, 0),
        };
        if received.seq != seq || received.from.0 != dest.to_ne_bytes() {
            continue;
        }
        if reply_size < 40 + received.len as u32 {
            return fail(ERROR_INSUFFICIENT_BUFFER, 0);
        }
        unsafe {
            core::ptr::write_bytes(reply as *mut u8, 0, 40);
            teb::put(reply, 0, dest);
            teb::put(reply, 8, start.elapsed().as_millis().min(u32::MAX as u128) as u32);
            teb::put(reply, 12, received.len as u16);
            teb::put(reply, 16, reply + 40);
            teb::put(reply, 24, received.ttl);
            core::ptr::copy_nonoverlapping(buf.as_ptr(), (reply + 40) as *mut u8, received.len);
        }
        return 1;
    }
}
// ---- interface change notifications -----------------------------------------

/// IP interface, address and route registrations: (handle, callback,
/// context). OSyx's interfaces are fixed for the life of the boot (DHCP
/// configures the one adapter once), so a registered callback is never
/// called. Windows sends one initial notification when the caller asks for
/// it; OSyx does not, so a program that needs the current state has to query
/// it (GetAdaptersInfo/GetIfTable), not wait for the callback.
static CHANGES: Mutex<Vec<(u64, u64, u64)>> = Mutex::new(Vec::new());
static NEXT_CHANGE: AtomicU64 = AtomicU64::new(1);

extern "win64" fn NotifyIpInterfaceChange(family: u16, callback: u64, context: u64, initial: u8, out: *mut u64) -> u32 {
    register_change(family, callback, context, initial, out)
}

extern "win64" fn NotifyUnicastIpAddressChange(family: u16, callback: u64, context: u64, initial: u8, out: *mut u64) -> u32 {
    register_change(family, callback, context, initial, out)
}

extern "win64" fn NotifyRouteChange2(_family: u16, callback: u64, context: u64, initial: u8, out: *mut u64) -> u32 {
    register_change(0, callback, context, initial, out)
}

fn register_change(_family: u16, callback: u64, context: u64, _initial: u8, out: *mut u64) -> u32 {
    if callback == 0 || out.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let h = NEXT_CHANGE.fetch_add(1, Ordering::SeqCst);
    CHANGES.lock().unwrap().push((h, callback, context));
    // SAFETY: the caller's out pointer.
    unsafe { *out = h };
    0 // NO_ERROR
}

extern "win64" fn CancelMibChangeNotify2(h: u64) -> u32 {
    let removed = {
        let mut c = CHANGES.lock().unwrap();
        c.iter().position(|(id, _, _)| *id == h).map(|i| c.remove(i))
    };
    if removed.is_some() {
        0 // NO_ERROR
    } else {
        ERROR_INVALID_PARAMETER
    }
}

struct Layout {
    bytes: Vec<u8>,
    fixups: Vec<(usize, usize)>,
}

impl Layout {
    fn new() -> Self {
        Self { bytes: Vec::new(), fixups: Vec::new() }
    }
    fn reserve(&mut self, n: usize) -> usize {
        while !self.bytes.len().is_multiple_of(8) {
            self.bytes.push(0);
        }
        let at = self.bytes.len();
        self.bytes.resize(at + n, 0);
        at
    }
    fn put16(&mut self, at: usize, v: u16) {
        self.bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put32(&mut self, at: usize, v: u32) {
        self.bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put64(&mut self, at: usize, v: u64) {
        self.bytes[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn link(&mut self, at: usize, target: usize) {
        self.fixups.push((at, target));
    }
    fn cstr(&mut self, at: usize, s: &str) {
        let dst = self.reserve(s.len() + 1);
        self.bytes[dst..dst + s.len()].copy_from_slice(s.as_bytes());
        self.link(at, dst);
    }
    fn wstr(&mut self, at: usize, s: &str) {
        let units: Vec<u16> = s.encode_utf16().chain(core::iter::once(0)).collect();
        let dst = self.reserve(units.len() * 2);
        for (k, u) in units.into_iter().enumerate() {
            self.put16(dst + k * 2, u);
        }
        self.link(at, dst);
    }
    fn sockaddr_in(&mut self, addr_field: usize, ip: [u8; 4]) {
        let sa = self.reserve(16);
        self.put16(sa, 2); // AF_INET
        self.bytes[sa + 4..sa + 8].copy_from_slice(&ip);
        self.link(addr_field, sa);
        self.put32(addr_field + 8, 16);
    }
    fn finish(mut self, base: u64) -> Vec<u8> {
        for (at, target) in self.fixups {
            self.bytes[at..at + 8].copy_from_slice(&(base + target as u64).to_le_bytes());
        }
        self.bytes
    }
}

fn iface_type(flags: u16) -> u32 {
    if flags & net::IFF_LOOPBACK != 0 {
        24 // IF_TYPE_SOFTWARE_LOOPBACK
    } else if flags & net::IFF_WIRELESS != 0 {
        71 // IF_TYPE_IEEE80211
    } else {
        6 // IF_TYPE_ETHERNET_CSMACD
    }
}

fn iface_luid(flags: u16, index: u8) -> u64 {
    ((iface_type(flags) as u64) << 48) | ((index as u64 & 0xff_ffff) << 24)
}

/// IP_ADAPTER_ADDRESSES_LH (448 bytes) and its linked address lists.
extern "win64" fn GetAdaptersAddresses(family: u32, flags: u32, reserved: u64, out: u64, size: *mut u32) -> u32 {
    if size.is_null() || reserved != 0 || !matches!(family, 0 | 2 | 23) {
        return ERROR_INVALID_PARAMETER;
    }
    if family == 23 {
        unsafe { *size = 0 };
        return 232; // ERROR_NO_DATA: OSyx is IPv4-only
    }
    let ifs = match list() {
        Ok(v) => v,
        Err(e) => return e,
    };
    if ifs.is_empty() {
        unsafe { *size = 0 };
        return 232;
    }
    let dns = net::dns_servers().unwrap_or_default();
    let mut b = Layout::new();
    let mut heads = Vec::with_capacity(ifs.len());
    for _ in &ifs {
        heads.push(b.reserve(448));
    }
    for (k, i) in ifs.iter().enumerate() {
        let a = heads[k];
        if k + 1 < heads.len() {
            b.link(a + 8, heads[k + 1]);
        }
        let loopback = i.flags & net::IFF_LOOPBACK != 0;
        let name = net::field(&i.name);
        let desc = format!("OSyx {name}");
        let if_type = iface_type(i.flags);
        let up = i.flags & net::IFF_UP != 0 && (loopback || i.flags & net::IFF_LINK != 0);
        b.put32(a, 448);
        b.put32(a + 4, i.index as u32);
        b.cstr(a + 16, name);
        b.wstr(a + 56, "");
        b.wstr(a + 64, &desc);
        b.wstr(a + 72, name);
        if !loopback {
            b.bytes[a + 80..a + 86].copy_from_slice(&i.mac);
            b.put32(a + 88, 6);
        }
        let mut aflags = 0x80u32; // IP_ADAPTER_IPV4_ENABLED
        if i.method == net::CONFIG_DHCP {
            aflags |= 0x04; // IP_ADAPTER_DHCP_ENABLED
        }
        b.put32(a + 92, aflags);
        b.put32(a + 96, i.mtu);
        b.put32(a + 100, if_type);
        b.put32(a + 104, if up { 1 } else { 2 }); // IfOperStatusUp / IfOperStatusDown
        b.put32(a + 216, 1); // Ipv4Metric
        b.put64(a + 224, iface_luid(i.flags, i.index));
        b.put32(a + 240, 1); // CompartmentId
        b.put32(a + 260, 1); // NET_IF_CONNECTION_DEDICATED

        // GAA_FLAG_SKIP_UNICAST = 0x0001
        if flags & 0x0001 == 0 && i.addr != [0, 0, 0, 0] {
            let u = b.reserve(64);
            b.link(a + 24, u);
            b.put32(u, 64);
            b.sockaddr_in(u + 16, i.addr);
            let origin = if i.method == net::CONFIG_DHCP { 3 } else { 1 };
            b.put32(u + 32, origin);
            b.put32(u + 36, origin);
            b.put32(u + 40, 4); // IpDadStatePreferred
            b.put32(u + 44, u32::MAX);
            b.put32(u + 48, u32::MAX);
            b.put32(u + 52, u32::MAX);
            b.bytes[u + 56] = i.prefix;
        }
        // GAA_FLAG_SKIP_DNS_SERVER = 0x0008
        if flags & 0x0008 == 0 && !loopback && !dns.is_empty() {
            let mut prev = None;
            for srv in &dns {
                let d = b.reserve(32);
                match prev {
                    None => b.link(a + 48, d),
                    Some(p) => b.link(p + 8, d),
                }
                b.put32(d, 32);
                b.sockaddr_in(d + 16, srv.0);
                prev = Some(d);
            }
        }
        // GAA_FLAG_INCLUDE_PREFIX = 0x0010
        if flags & 0x0010 != 0 && i.addr != [0, 0, 0, 0] {
            let p = b.reserve(40);
            b.link(a + 176, p);
            b.put32(p, 40);
            let m = mask(i.prefix);
            let net_ip = [i.addr[0] & m[0], i.addr[1] & m[1], i.addr[2] & m[2], i.addr[3] & m[3]];
            b.sockaddr_in(p + 16, net_ip);
            b.put32(p + 32, i.prefix as u32);
        }
        // GAA_FLAG_INCLUDE_GATEWAYS = 0x0080
        if flags & 0x0080 != 0 && !loopback && i.gateway != [0, 0, 0, 0] {
            let g = b.reserve(32);
            b.link(a + 208, g);
            b.put32(g, 32);
            b.sockaddr_in(g + 16, i.gateway);
        }
    }
    let need = b.bytes.len() as u32;
    let cap = unsafe {
        let n = *size;
        *size = need;
        n
    };
    if out == 0 || cap < need {
        return 111; // ERROR_BUFFER_OVERFLOW
    }
    let bytes = b.finish(out);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, bytes.len());
    }
    0
}

/// MIB_IPINTERFACE_TABLE: NumEntries (4) + 4 pad + N * MIB_IPINTERFACE_ROW (168).
extern "win64" fn GetIpInterfaceTable(family: u16, table: *mut u64) -> u32 {
    if table.is_null() || !matches!(family, 0 | 2 | 23) {
        return ERROR_INVALID_PARAMETER;
    }
    let ifs = if family == 23 {
        Vec::new()
    } else {
        match list() {
            Ok(v) => v,
            Err(e) => return e,
        }
    };
    let total = 8 + ifs.len() * 168;
    let Some(base) = crate::kernel32::heap_alloc(total, true) else {
        return ERROR_NOT_ENOUGH_MEMORY;
    };
    unsafe {
        teb::put(base, 0, ifs.len() as u32);
        for (k, i) in ifs.iter().enumerate() {
            let row = base + 8 + k as u64 * 168;
            teb::put(row, 0, 2u16); // AF_INET
            teb::put(row, 8, iface_luid(i.flags, i.index));
            teb::put(row, 16, i.index as u32);
            teb::put(row, 20, 65535u32); // MaxReassemblySize
            teb::put(row, 53, u8::from(i.flags & net::IFF_UP != 0)); // Connected
            teb::put(row, 108, i.mtu);
            teb::put(row, 112, 1u32); // Metric
            teb::put(row, 136, i.prefix); // SitePrefixLength
        }
        *table = base;
    }
    0
}

extern "win64" fn FreeMibTable(memory: u64) {
    if memory != 0 {
        crate::kernel32::heap_free(memory);
    }
}

extern "win64" fn GetBestInterfaceEx(dest: *const u8, index: *mut u32) -> u32 {
    if dest.is_null() || index.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    let family = unsafe { *(dest as *const u16) };
    if family == 23 {
        return 1231; // ERROR_NETWORK_UNREACHABLE: no IPv6 routes
    }
    if family != 2 {
        return ERROR_INVALID_PARAMETER;
    }
    let target = unsafe { [*(dest.add(4)), *(dest.add(5)), *(dest.add(6)), *(dest.add(7))] };
    let ifs = match list() {
        Ok(v) => v,
        Err(e) => return e,
    };
    let chosen = ifs
        .iter()
        .find(|i| i.addr == target || (target[0] == 127 && i.flags & net::IFF_LOOPBACK != 0))
        .or_else(|| {
            ifs.iter().find(|i| {
                let m = mask(i.prefix);
                i.addr != [0, 0, 0, 0]
                    && (0..4).all(|k| (i.addr[k] & m[k]) == (target[k] & m[k]))
            })
        })
        .or_else(|| ifs.iter().find(|i| i.flags & net::IFF_LOOPBACK == 0 && i.gateway != [0, 0, 0, 0]))
        .or_else(|| ifs.first());
    match chosen {
        Some(i) => {
            unsafe { *index = i.index as u32 };
            0
        }
        None => 1231, // ERROR_NETWORK_UNREACHABLE
    }
}

extern "win64" fn if_indextoname(index: u32, name: *mut u8) -> *mut u8 {
    if name.is_null() {
        return core::ptr::null_mut();
    }
    let Ok(ifs) = list() else {
        return core::ptr::null_mut();
    };
    let Some(i) = ifs.iter().find(|i| i.index as u32 == index) else {
        return core::ptr::null_mut();
    };
    out_a(net::field(&i.name), name, 256);
    name
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        GetAdaptersInfo,
        GetAdaptersAddresses,
        GetIfTable,
        GetIpInterfaceTable,
        FreeMibTable,
        GetBestInterfaceEx,
        if_indextoname,
        GetNetworkParams,
        IcmpCreateFile,
        IcmpCloseHandle,
        IcmpSendEcho,
        NotifyIpInterfaceChange,
        NotifyUnicastIpAddressChange,
        NotifyRouteChange2,
        CancelMibChangeNotify2
    ]
}
