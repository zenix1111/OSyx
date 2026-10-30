//! DNS (RFC 1035) A-record queries: message codec, answer chasing and a
//! TTL cache.
//!
//! Parsing is defensive: every offset is bounds checked, a compression
//! pointer must point strictly backwards (so pointer chains terminate) and
//! at most [`MAX_POINTERS`] are followed per name, names are limited to
//! 255 bytes, and CNAME chains to [`MAX_CNAMES`] hops.

use crate::wire::{be16, be32, put16, Ipv4Addr};
use alloc::string::String;
use alloc::vec::Vec;

pub const PORT: u16 = 53;
pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const CLASS_IN: u16 = 1;
pub const MAX_NAME: usize = 255;
pub const MAX_POINTERS: usize = 32;
pub const MAX_CNAMES: usize = 8;
pub const MAX_UDP: usize = 512;

pub const RCODE_OK: u8 = 0;
pub const RCODE_FORMAT: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsError {
    Truncated,
    BadName,
    BadPointer,
    NotAResponse,
    IdMismatch,
    /// The question section does not repeat our question.
    QuestionMismatch,
    /// A CNAME chain longer than `MAX_CNAMES` or a loop.
    CnameLoop,
}

/// Lower-cases a host name and strips one trailing dot; checks label
/// lengths and characters (letters, digits, `-`, `_`).
pub fn normalize(name: &str) -> Option<String> {
    let n = name.strip_suffix('.').unwrap_or(name);
    if n.is_empty() || n.len() > 253 {
        return None;
    }
    for label in n.split('.') {
        if label.is_empty() || label.len() > 63 || !label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
            return None;
        }
    }
    Some(n.to_ascii_lowercase())
}

/// Builds a recursive query for `name` (already normalised).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = alloc::vec![0u8; 12];
    put16(&mut q, 0, id);
    put16(&mut q, 2, 0x0100); // RD
    put16(&mut q, 4, 1);
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    q
}

/// Reads a (possibly compressed) name at `off`; returns it lower-cased and
/// the offset after it in the original position.
pub fn read_name(msg: &[u8], mut off: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(off).ok_or(DnsError::Truncated)? as usize;
        match len >> 6 {
            0 => {
                if len == 0 {
                    return Ok((name, end.unwrap_or(off + 1)));
                }
                let label = msg.get(off + 1..off + 1 + len).ok_or(DnsError::Truncated)?;
                if !name.is_empty() {
                    name.push('.');
                }
                for &c in label {
                    if c == b'.' || !(0x21..0x7F).contains(&c) {
                        return Err(DnsError::BadName);
                    }
                    name.push((c as char).to_ascii_lowercase());
                }
                if name.len() > MAX_NAME {
                    return Err(DnsError::BadName);
                }
                off += 1 + len;
            }
            3 => {
                let lo = *msg.get(off + 1).ok_or(DnsError::Truncated)? as usize;
                let target = ((len & 0x3F) << 8) | lo;
                // Pointers must go backwards: no loops, no forward references.
                if target >= off || jumps >= MAX_POINTERS {
                    return Err(DnsError::BadPointer);
                }
                jumps += 1;
                if end.is_none() {
                    end = Some(off + 2);
                }
                off = target;
            }
            _ => return Err(DnsError::BadName),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Data {
    A(Ipv4Addr),
    Cname(String),
    Other(u16),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub name: String,
    pub ttl: u32,
    pub data: Data,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub id: u16,
    pub rcode: u8,
    pub truncated: bool,
    pub answers: Vec<Record>,
    /// Smallest TTL of the authority section's SOA (negative caching), if any.
    pub negative_ttl: Option<u32>,
}

/// Parses a response to query `id` for `qname`.
pub fn parse_response(msg: &[u8], id: u16, qname: &str, qtype: u16) -> Result<Response, DnsError> {
    if msg.len() < 12 {
        return Err(DnsError::Truncated);
    }
    let flags = be16(msg, 2);
    if flags & 0x8000 == 0 {
        return Err(DnsError::NotAResponse);
    }
    if be16(msg, 0) != id {
        return Err(DnsError::IdMismatch);
    }
    let qd = be16(msg, 4) as usize;
    let an = be16(msg, 6) as usize;
    let ns = be16(msg, 8) as usize;
    let truncated = flags & 0x0200 != 0;
    let rcode = (flags & 0x000F) as u8;
    let mut off = 12;
    if qd != 1 {
        // A truncated response may carry no question; others must echo ours.
        if !(truncated && qd == 0) {
            return Err(DnsError::QuestionMismatch);
        }
    } else {
        let (name, next) = read_name(msg, off)?;
        let t = msg.get(next..next + 4).ok_or(DnsError::Truncated)?;
        if name != qname || be16(t, 0) != qtype || be16(t, 2) != CLASS_IN {
            return Err(DnsError::QuestionMismatch);
        }
        off = next + 4;
    }
    let mut answers = Vec::new();
    let mut negative_ttl = None;
    for i in 0..an + ns {
        let (name, next) = match read_name(msg, off) {
            Ok(v) => v,
            Err(DnsError::Truncated) if truncated => break,
            Err(e) => return Err(e),
        };
        let Some(h) = msg.get(next..next + 10) else {
            if truncated {
                break;
            }
            return Err(DnsError::Truncated);
        };
        let rtype = be16(h, 0);
        let class = be16(h, 2);
        let ttl = be32(h, 4).min(0x7FFF_FFFF);
        let rdlen = be16(h, 8) as usize;
        let rdata_off = next + 10;
        let rdata = msg.get(rdata_off..rdata_off + rdlen).ok_or(DnsError::Truncated)?;
        off = rdata_off + rdlen;
        if class != CLASS_IN {
            continue;
        }
        if i >= an {
            if rtype == 6 && rdata.len() >= 22 {
                // SOA: the MINIMUM field (last 4 bytes) bounds negative caching.
                let min = be32(rdata, rdata.len() - 4);
                negative_ttl = Some(ttl.min(min));
            }
            continue;
        }
        let data = match rtype {
            TYPE_A if rdlen == 4 => Data::A(Ipv4Addr([rdata[0], rdata[1], rdata[2], rdata[3]])),
            TYPE_A => return Err(DnsError::Truncated),
            TYPE_CNAME => {
                let (target, next) = read_name(msg, rdata_off)?;
                if next > rdata_off + rdlen {
                    return Err(DnsError::Truncated);
                }
                Data::Cname(target)
            }
            other => Data::Other(other),
        };
        answers.push(Record { name, ttl, data });
    }
    Ok(Response { id, rcode, truncated, answers, negative_ttl })
}

/// Outcome of a resolved question: addresses and the TTL to cache them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The name the addresses belong to (after following CNAMEs).
    pub canonical: String,
    pub addrs: Vec<Ipv4Addr>,
    pub ttl: u32,
}

/// Follows CNAMEs from `qname` through the answer section. Returns
/// `Ok(None)` when the chain ends in a name without A records.
pub fn chase(qname: &str, answers: &[Record]) -> Result<Option<Answer>, DnsError> {
    let mut name = String::from(qname);
    let mut ttl = u32::MAX;
    let mut seen: Vec<String> = Vec::new();
    for _ in 0..=MAX_CNAMES {
        let addrs: Vec<(Ipv4Addr, u32)> = answers
            .iter()
            .filter(|r| r.name == name)
            .filter_map(|r| match r.data {
                Data::A(a) => Some((a, r.ttl)),
                _ => None,
            })
            .collect();
        if !addrs.is_empty() {
            let t = addrs.iter().map(|a| a.1).min().unwrap_or(0).min(ttl);
            return Ok(Some(Answer { canonical: name, addrs: addrs.into_iter().map(|a| a.0).collect(), ttl: t }));
        }
        let next = answers.iter().find(|r| r.name == name).and_then(|r| match &r.data {
            Data::Cname(c) => Some((c.clone(), r.ttl)),
            _ => None,
        });
        match next {
            Some((target, t)) => {
                if seen.contains(&target) || target == qname {
                    return Err(DnsError::CnameLoop);
                }
                seen.push(name);
                ttl = ttl.min(t);
                name = target;
            }
            None => return Ok(None),
        }
    }
    Err(DnsError::CnameLoop)
}

#[derive(Clone, Debug)]
struct CacheEntry {
    name: String,
    /// Empty for a negative entry (the name does not exist).
    addrs: Vec<Ipv4Addr>,
    expires: u64,
}

/// Resolved names with their TTL; negative answers are cached too.
#[derive(Default)]
pub struct Cache {
    entries: Vec<CacheEntry>,
    pub hits: u64,
    pub misses: u64,
}

pub const CACHE_ENTRIES: usize = 128;
/// TTLs are clamped to this range (seconds).
pub const MIN_TTL: u32 = 5;
pub const MAX_TTL: u32 = 86_400;
pub const NEGATIVE_TTL: u32 = 60;

impl Cache {
    pub fn new() -> Cache {
        Cache::default()
    }

    /// `Some(addrs)` for a fresh entry (`addrs` empty: known not to exist).
    pub fn get(&mut self, name: &str, now: u64) -> Option<Vec<Ipv4Addr>> {
        self.entries.retain(|e| e.expires > now);
        match self.entries.iter().find(|e| e.name == name) {
            Some(e) => {
                self.hits += 1;
                Some(e.addrs.clone())
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    pub fn put(&mut self, name: &str, addrs: Vec<Ipv4Addr>, ttl_s: u32, now: u64) {
        let ttl = ttl_s.clamp(MIN_TTL, MAX_TTL) as u64;
        self.entries.retain(|e| e.name != name && e.expires > now);
        if self.entries.len() >= CACHE_ENTRIES {
            if let Some(i) = self.entries.iter().enumerate().min_by_key(|(_, e)| e.expires).map(|(i, _)| i) {
                self.entries.remove(i);
            }
        }
        self.entries.push(CacheEntry { name: name.into(), addrs, expires: now + ttl * 1000 });
    }

    /// (name, addresses, seconds left).
    pub fn entries(&self, now: u64) -> Vec<(String, Vec<Ipv4Addr>, u64)> {
        self.entries
            .iter()
            .filter(|e| e.expires > now)
            .map(|e| (e.name.clone(), e.addrs.clone(), (e.expires - now) / 1000))
            .collect()
    }

    pub fn flush(&mut self) {
        self.entries.clear();
    }
}
