//! DHCPv4 client (RFC 2131, options from RFC 2132).
//!
//! INIT â†’ SELECTING (DISCOVER, wait for OFFER) â†’ REQUESTING (REQUEST, wait
//! for ACK) â†’ BOUND; at T1 RENEWING (unicast REQUEST to the server), at T2
//! REBINDING (broadcast REQUEST), and when the lease expires back to INIT.
//! A NAK at any point restarts from INIT. Retransmissions back off
//! exponentially from [`FIRST_RETRY_MS`] up to [`MAX_RETRY_MS`].

use crate::wire::{be32, ip_at, mask_prefix, put16, put32, Ipv4Addr, MacAddr};
use alloc::vec::Vec;

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;
const MAGIC: [u8; 4] = [99, 130, 83, 99];
const FIXED_LEN: usize = 236;

pub const DISCOVER: u8 = 1;
pub const OFFER: u8 = 2;
pub const REQUEST: u8 = 3;
pub const DECLINE: u8 = 4;
pub const ACK: u8 = 5;
pub const NAK: u8 = 6;
pub const RELEASE: u8 = 7;

const OPT_PAD: u8 = 0;
const OPT_SUBNET: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_HOSTNAME: u8 = 12;
const OPT_DOMAIN: u8 = 15;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE: u8 = 51;
const OPT_OVERLOAD: u8 = 52;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAMS: u8 = 55;
const OPT_T1: u8 = 58;
const OPT_T2: u8 = 59;
const OPT_CLIENT_ID: u8 = 61;
const OPT_END: u8 = 255;

pub const FIRST_RETRY_MS: u64 = 1_000;
pub const MAX_RETRY_MS: u64 = 32_000;
/// Lease used when a server sends none (and the shortest we accept).
const MIN_LEASE_S: u32 = 60;

/// A decoded DHCP message (only the fields the client uses).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub op: u8,
    pub xid: u32,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub chaddr: MacAddr,
    pub msg_type: u8,
    pub server_id: Option<Ipv4Addr>,
    pub subnet: Option<Ipv4Addr>,
    pub routers: Vec<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub lease_s: Option<u32>,
    pub t1_s: Option<u32>,
    pub t2_s: Option<u32>,
    pub domain: Option<alloc::string::String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DhcpError {
    Truncated,
    BadMagic,
    BadOption,
    NotBootReply,
}

fn addrs(v: &[u8]) -> Vec<Ipv4Addr> {
    v.as_chunks::<4>().0.iter().map(|c| Ipv4Addr(*c)).collect()
}

impl Message {
    pub fn parse(b: &[u8]) -> Result<Message, DhcpError> {
        if b.len() < FIXED_LEN + 4 {
            return Err(DhcpError::Truncated);
        }
        if b[FIXED_LEN..FIXED_LEN + 4] != MAGIC {
            return Err(DhcpError::BadMagic);
        }
        let mut chaddr = [0; 6];
        chaddr.copy_from_slice(&b[28..34]);
        let mut m = Message {
            op: b[0],
            xid: be32(b, 4),
            ciaddr: ip_at(b, 12),
            yiaddr: ip_at(b, 16),
            chaddr: MacAddr(chaddr),
            ..Default::default()
        };
        let mut overload = 0;
        Self::parse_options(&b[FIXED_LEN + 4..], &mut m, &mut overload)?;
        // Option overload: options continue in the file / sname fields.
        if overload & 1 != 0 {
            Self::parse_options(&b[108..236], &mut m, &mut 0)?;
        }
        if overload & 2 != 0 {
            Self::parse_options(&b[44..108], &mut m, &mut 0)?;
        }
        Ok(m)
    }

    fn parse_options(mut o: &[u8], m: &mut Message, overload: &mut u8) -> Result<(), DhcpError> {
        while let Some(&code) = o.first() {
            if code == OPT_PAD {
                o = &o[1..];
                continue;
            }
            if code == OPT_END {
                break;
            }
            let len = *o.get(1).ok_or(DhcpError::BadOption)? as usize;
            let v = o.get(2..2 + len).ok_or(DhcpError::BadOption)?;
            let u32v = || (v.len() == 4).then(|| be32(v, 0));
            match code {
                OPT_MSG_TYPE if len == 1 => m.msg_type = v[0],
                OPT_SERVER_ID if len == 4 => m.server_id = Some(ip_at(v, 0)),
                OPT_SUBNET if len == 4 => m.subnet = Some(ip_at(v, 0)),
                OPT_ROUTER => m.routers = addrs(v),
                OPT_DNS => m.dns = addrs(v),
                OPT_LEASE => m.lease_s = u32v(),
                OPT_T1 => m.t1_s = u32v(),
                OPT_T2 => m.t2_s = u32v(),
                OPT_OVERLOAD if len == 1 => *overload = v[0],
                OPT_DOMAIN => m.domain = core::str::from_utf8(v).ok().map(alloc::string::String::from),
                _ => {}
            }
            o = &o[2 + len..];
        }
        Ok(())
    }
}

/// Builds a client message (BOOTREQUEST).
#[allow(clippy::too_many_arguments)]
pub fn build_request(
    kind: u8,
    xid: u32,
    mac: MacAddr,
    ciaddr: Ipv4Addr,
    requested: Option<Ipv4Addr>,
    server: Option<Ipv4Addr>,
    secs: u16,
    hostname: &str,
) -> Vec<u8> {
    let mut b = alloc::vec![0u8; FIXED_LEN + 4];
    b[0] = 1; // BOOTREQUEST
    b[1] = 1; // Ethernet
    b[2] = 6;
    put32(&mut b, 4, xid);
    put16(&mut b, 8, secs);
    // Ask for broadcast replies while we have no address.
    if ciaddr.is_unspecified() {
        put16(&mut b, 10, 0x8000);
    }
    b[12..16].copy_from_slice(&ciaddr.0);
    b[28..34].copy_from_slice(&mac.0);
    b[FIXED_LEN..FIXED_LEN + 4].copy_from_slice(&MAGIC);
    b.extend_from_slice(&[OPT_MSG_TYPE, 1, kind]);
    b.extend_from_slice(&[OPT_CLIENT_ID, 7, 1]);
    b.extend_from_slice(&mac.0);
    if let Some(r) = requested {
        b.extend_from_slice(&[OPT_REQUESTED_IP, 4]);
        b.extend_from_slice(&r.0);
    }
    if let Some(s) = server {
        b.extend_from_slice(&[OPT_SERVER_ID, 4]);
        b.extend_from_slice(&s.0);
    }
    if !hostname.is_empty() && hostname.len() < 64 {
        b.extend_from_slice(&[OPT_HOSTNAME, hostname.len() as u8]);
        b.extend_from_slice(hostname.as_bytes());
    }
    if kind != RELEASE && kind != DECLINE {
        b.extend_from_slice(&[OPT_PARAMS, 7, OPT_SUBNET, OPT_ROUTER, OPT_DNS, OPT_DOMAIN, OPT_LEASE, OPT_T1, OPT_T2]);
    }
    b.push(OPT_END);
    // Some servers ignore requests shorter than a BOOTP packet (300 bytes).
    if b.len() < 300 {
        b.resize(300, 0);
    }
    b
}

/// An acquired lease (times in ms of the stack clock).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Lease {
    pub addr: Ipv4Addr,
    pub prefix: u8,
    pub router: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub domain: Option<alloc::string::String>,
    pub server: Ipv4Addr,
    pub obtained: u64,
    pub lease_ms: u64,
    pub t1: u64,
    pub t2: u64,
}

impl Lease {
    pub fn expires(&self) -> u64 {
        self.obtained + self.lease_ms
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    Stopped,
}

impl Phase {
    pub fn name(self) -> &'static str {
        match self {
            Phase::Init => "init",
            Phase::Selecting => "selecting",
            Phase::Requesting => "requesting",
            Phase::Bound => "bound",
            Phase::Renewing => "renewing",
            Phase::Rebinding => "rebinding",
            Phase::Stopped => "stopped",
        }
    }
}

/// A message for the stack to send from port 68 to port 67.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// Source address (0.0.0.0 until bound).
    pub src: Ipv4Addr,
    /// Broadcast, or the server when renewing.
    pub dst: Ipv4Addr,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A new lease (configure the interface).
    Bound(Lease),
    /// The same address was extended.
    Renewed(Lease),
    /// The lease ended or the server refused it: remove the address.
    Lost,
}

pub struct Client {
    mac: MacAddr,
    hostname: alloc::string::String,
    phase: Phase,
    xid: u32,
    rng: u32,
    started: u64,
    next_send: u64,
    retry: u64,
    offer: Option<(Ipv4Addr, Ipv4Addr)>,
    lease: Option<Lease>,
    pub discovers: u32,
    pub requests: u32,
}

impl Client {
    pub fn new(mac: MacAddr, seed: u32, hostname: &str) -> Client {
        Client {
            mac,
            hostname: hostname.into(),
            phase: Phase::Init,
            xid: seed | 1,
            rng: seed | 1,
            started: 0,
            next_send: 0,
            retry: FIRST_RETRY_MS,
            offer: None,
            lease: None,
            discovers: 0,
            requests: 0,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    pub fn stop(&mut self) {
        self.phase = Phase::Stopped;
    }

    fn rand(&mut self) -> u32 {
        // xorshift32
        let mut x = self.rng;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.rng = x;
        x
    }

    fn new_xid(&mut self) {
        self.xid = self.rand();
    }

    fn backoff(&mut self, now: u64) {
        // RFC 2131 4.1: doubling delays with +/- 1 s of randomisation.
        let jitter = (self.rand() % 1000) as u64;
        self.next_send = now + self.retry + jitter / 2;
        self.retry = (self.retry * 2).min(MAX_RETRY_MS);
    }

    fn secs(&self, now: u64) -> u16 {
        (now.saturating_sub(self.started) / 1000).min(u16::MAX as u64) as u16
    }

    /// Timers: returns a message to send, and possibly an event.
    pub fn poll(&mut self, now: u64) -> (Option<Transmit>, Option<Event>) {
        let mut event = None;
        if let Some(l) = &self.lease {
            if now >= l.expires() && matches!(self.phase, Phase::Bound | Phase::Renewing | Phase::Rebinding) {
                self.lease = None;
                self.phase = Phase::Init;
                event = Some(Event::Lost);
            } else if matches!(self.phase, Phase::Bound | Phase::Renewing) && now >= l.t2 {
                self.phase = Phase::Rebinding;
                self.new_xid();
                self.next_send = now;
            } else if self.phase == Phase::Bound && now >= l.t1 {
                self.phase = Phase::Renewing;
                self.new_xid();
                self.next_send = now;
            }
        }
        let tx = match self.phase {
            Phase::Init => {
                self.phase = Phase::Selecting;
                self.started = now;
                self.retry = FIRST_RETRY_MS;
                self.new_xid();
                self.next_send = now;
                self.send_discover(now)
            }
            Phase::Selecting if now >= self.next_send => self.send_discover(now),
            Phase::Requesting if now >= self.next_send => {
                if self.retry > 16_000 {
                    // No ACK after several tries: start over.
                    self.phase = Phase::Init;
                    self.offer = None;
                    None
                } else {
                    self.send_request(now)
                }
            }
            Phase::Renewing | Phase::Rebinding if now >= self.next_send => {
                let Some(l) = self.lease.clone() else { return (None, event) };
                let rebinding = self.phase == Phase::Rebinding;
                let payload =
                    build_request(REQUEST, self.xid, self.mac, l.addr, None, None, self.secs(now), &self.hostname);
                // RFC 2131 4.4.5: wait half the remaining time, at least 60 s.
                let until = if rebinding { l.expires() } else { l.t2 };
                self.next_send = now + (until.saturating_sub(now) / 2).max(60_000);
                self.requests += 1;
                Some(Transmit { src: l.addr, dst: if rebinding { Ipv4Addr::BROADCAST } else { l.server }, payload })
            }
            _ => None,
        };
        (tx, event)
    }

    fn send_discover(&mut self, now: u64) -> Option<Transmit> {
        self.backoff(now);
        self.discovers += 1;
        let requested = self.lease.as_ref().map(|l| l.addr);
        let payload = build_request(DISCOVER, self.xid, self.mac, Ipv4Addr::UNSPECIFIED, requested, None, self.secs(now), &self.hostname);
        Some(Transmit { src: Ipv4Addr::UNSPECIFIED, dst: Ipv4Addr::BROADCAST, payload })
    }

    fn send_request(&mut self, now: u64) -> Option<Transmit> {
        let (addr, server) = self.offer?;
        self.backoff(now);
        self.requests += 1;
        let payload =
            build_request(REQUEST, self.xid, self.mac, Ipv4Addr::UNSPECIFIED, Some(addr), Some(server), self.secs(now), &self.hostname);
        Some(Transmit { src: Ipv4Addr::UNSPECIFIED, dst: Ipv4Addr::BROADCAST, payload })
    }

    /// A datagram that arrived on port 68.
    pub fn input(&mut self, payload: &[u8], now: u64) -> (Option<Transmit>, Option<Event>) {
        let Ok(m) = Message::parse(payload) else { return (None, None) };
        if m.op != 2 || m.xid != self.xid || m.chaddr != self.mac {
            return (None, None);
        }
        if matches!(m.msg_type, ACK | NAK) {
            if m.msg_type == ACK && matches!(self.phase, Phase::Renewing | Phase::Rebinding) {
                let Some(lease) = &self.lease else { return (None, None) };
                if (!m.yiaddr.is_unspecified() && m.yiaddr != lease.addr)
                    || (!m.ciaddr.is_unspecified() && m.ciaddr != lease.addr)
                {
                    return (None, None);
                }
            }
            match self.phase {
                Phase::Requesting => {
                    let Some((addr, server)) = self.offer else { return (None, None) };
                    if m.server_id.is_some_and(|id| id != server) || (m.msg_type == ACK && m.yiaddr != addr) {
                        return (None, None);
                    }
                }
                Phase::Renewing => {
                    let Some(lease) = &self.lease else { return (None, None) };
                    if m.server_id.is_some_and(|server| server != lease.server) {
                        return (None, None);
                    }
                }
                _ => {}
            }
        }
        match (self.phase, m.msg_type) {
            (Phase::Selecting, OFFER) => {
                let Some(server) = m.server_id else { return (None, None) };
                if m.yiaddr.is_unspecified() || m.yiaddr.is_broadcast() || m.yiaddr.is_multicast() {
                    return (None, None);
                }
                self.offer = Some((m.yiaddr, server));
                self.phase = Phase::Requesting;
                self.retry = FIRST_RETRY_MS;
                (self.send_request(now), None)
            }
            (Phase::Requesting | Phase::Renewing | Phase::Rebinding, ACK) => {
                let Some(lease) = self.lease_from(&m, now) else { return (None, None) };
                let renewed = self.lease.as_ref().is_some_and(|l| l.addr == lease.addr) && self.phase != Phase::Requesting;
                self.lease = Some(lease.clone());
                self.phase = Phase::Bound;
                self.retry = FIRST_RETRY_MS;
                (None, Some(if renewed { Event::Renewed(lease) } else { Event::Bound(lease) }))
            }
            (Phase::Requesting | Phase::Renewing | Phase::Rebinding, NAK) => {
                let had = self.lease.take().is_some();
                self.phase = Phase::Init;
                self.offer = None;
                (None, had.then_some(Event::Lost))
            }
            _ => (None, None),
        }
    }

    fn lease_from(&self, m: &Message, now: u64) -> Option<Lease> {
        let addr = if !m.yiaddr.is_unspecified() {
            m.yiaddr
        } else if !m.ciaddr.is_unspecified() {
            m.ciaddr
        } else {
            self.lease.as_ref().map_or(Ipv4Addr::UNSPECIFIED, |l| l.addr)
        };
        if addr.is_unspecified() {
            return None;
        }
        let server = m.server_id.or(self.offer.map(|o| o.1)).or(self.lease.as_ref().map(|l| l.server))?;
        let lease_s = m.lease_s.unwrap_or(MIN_LEASE_S).max(MIN_LEASE_S) as u64;
        let defaults = (lease_s / 2, lease_s * 7 / 8);
        let proposed = (m.t1_s.map(u64::from).unwrap_or(defaults.0), m.t2_s.map(u64::from).unwrap_or(defaults.1));
        let (t1, t2) = if proposed.0 > 0 && proposed.0 < proposed.1 && proposed.1 < lease_s { proposed } else { defaults };
        let prior = self.lease.as_ref().filter(|l| l.addr == addr);
        let prefix = m.subnet.and_then(mask_prefix).or_else(|| prior.map(|l| l.prefix)).unwrap_or(24);
        Some(Lease {
            addr,
            prefix,
            router: m.routers.first().copied().or_else(|| prior.and_then(|l| l.router)),
            dns: if m.dns.is_empty() { prior.map_or_else(Vec::new, |l| l.dns.clone()) } else { m.dns.clone() },
            domain: m.domain.clone().or_else(|| prior.and_then(|l| l.domain.clone())),
            server,
            obtained: now,
            lease_ms: lease_s * 1000,
            t1: now + t1 * 1000,
            t2: now + t2 * 1000,
        })
    }

    /// Earliest time `poll` has work.
    pub fn next_deadline(&self) -> Option<u64> {
        match self.phase {
            Phase::Init => Some(0),
            Phase::Selecting | Phase::Requesting => Some(self.next_send),
            Phase::Renewing => Some(self.lease.as_ref().map_or(self.next_send, |l| l.t2.min(self.next_send))),
            Phase::Rebinding => Some(self.lease.as_ref().map_or(self.next_send, |l| l.expires().min(self.next_send))),
            Phase::Bound => self.lease.as_ref().map(|l| l.t1),
            Phase::Stopped => None,
        }
    }
}

/// Test helper and server-side building block: a server reply.
#[allow(clippy::too_many_arguments)]
pub fn build_reply(
    kind: u8,
    xid: u32,
    mac: MacAddr,
    yiaddr: Ipv4Addr,
    server: Ipv4Addr,
    mask: Ipv4Addr,
    router: Ipv4Addr,
    dns: Ipv4Addr,
    lease_s: u32,
) -> Vec<u8> {
    let mut b = alloc::vec![0u8; FIXED_LEN + 4];
    b[0] = 2;
    b[1] = 1;
    b[2] = 6;
    put32(&mut b, 4, xid);
    b[16..20].copy_from_slice(&yiaddr.0);
    b[20..24].copy_from_slice(&server.0);
    b[28..34].copy_from_slice(&mac.0);
    b[FIXED_LEN..FIXED_LEN + 4].copy_from_slice(&MAGIC);
    b.extend_from_slice(&[OPT_MSG_TYPE, 1, kind, OPT_SERVER_ID, 4]);
    b.extend_from_slice(&server.0);
    b.extend_from_slice(&[OPT_SUBNET, 4]);
    b.extend_from_slice(&mask.0);
    b.extend_from_slice(&[OPT_ROUTER, 4]);
    b.extend_from_slice(&router.0);
    b.extend_from_slice(&[OPT_DNS, 4]);
    b.extend_from_slice(&dns.0);
    b.extend_from_slice(&[OPT_LEASE, 4]);
    b.extend_from_slice(&lease_s.to_be_bytes());
    b.push(OPT_END);
    b
}
