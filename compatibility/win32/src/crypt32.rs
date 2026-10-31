//! crypt32: reading signed data and certificates.
//!
//! Decodes DER: PKCS#7 SignedData (as files, blobs and the Authenticode
//! signature embedded in a PE image's certificate table) with its
//! certificates and signer information, X.509 certificates and their
//! names. It verifies nothing: no signature, chain or trust checks, which
//! on Windows are WinVerifyTrust's and CertGetCertificateChain's (not
//! provided). Stores are in-memory collections of the certificates read;
//! OSyx has no Windows system certificate stores (CERT_STORE_PROV_SYSTEM
//! fails with ERROR_FILE_NOT_FOUND). Also CryptBinaryToString.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{self, fail},
    path,
};
use alloc::{collections::BTreeMap, string::String, sync::Arc, vec::Vec};
use os_std::sync::Mutex;

const ERROR_MORE_DATA: u32 = 234;
const CRYPT_E_ASN1_BADTAG: u32 = 0x8009_310b;
const CRYPT_E_MSG_ERROR: u32 = 0x8009_1001;
const CRYPT_E_NO_MATCH: u32 = 0x8009_2009;
const CRYPT_E_NOT_FOUND: u32 = 0x8009_2004;
const CRYPT_E_INVALID_MSG_TYPE: u32 = 0x8009_1004;
const CRYPT_E_STREAM_MSG_NOT_READY: u32 = 0x8009_1010;
const CRYPT_E_INVALID_INDEX: u32 = 0x8009_1008;

const X509_ASN_ENCODING: u32 = 1;
const PKCS_7_ASN_ENCODING: u32 = 0x1_0000;
const ENCODING: u32 = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;

// ---- DER --------------------------------------------------------------------------------

/// One DER element: tag, the whole encoding and its contents.
#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u8,
    raw: &'a [u8],
    body: &'a [u8],
}

/// CRYPT_E_ASN1_ERROR: malformed DER.
const ASN1: u32 = 0x8009_3100;
fn bad<T>() -> Result<T, u32> {
    Err(ASN1)
}

/// The element at the start of `d` and what follows it.
fn tlv(d: &[u8]) -> Result<(Tlv<'_>, &[u8]), u32> {
    if d.len() < 2 {
        return bad();
    }
    let tag = d[0];
    if tag & 0x1f == 0x1f {
        return bad(); // high tag numbers do not occur in these structures
    }
    let (len, hdr) = match d[1] {
        n if n < 0x80 => (n as usize, 2),
        0x81..=0x84 => {
            let k = (d[1] & 0x7f) as usize;
            if d.len() < 2 + k {
                return bad();
            }
            (d[2..2 + k].iter().fold(0usize, |a, &b| a << 8 | b as usize), 2 + k)
        }
        _ => return bad(), // indefinite or oversized lengths are not DER
    };
    let end = hdr.checked_add(len).filter(|&e| e <= d.len()).ok_or(ASN1)?;
    Ok((Tlv { tag, raw: &d[..end], body: &d[hdr..end] }, &d[end..]))
}

/// The elements of a constructed element's contents.
fn items(d: &[u8]) -> Result<Vec<Tlv<'_>>, u32> {
    let mut out = Vec::new();
    let mut rest = d;
    while !rest.is_empty() {
        let (t, r) = tlv(rest)?;
        out.push(t);
        rest = r;
    }
    Ok(out)
}

fn expect(t: Tlv<'_>, tag: u8) -> Result<Tlv<'_>, u32> {
    if t.tag == tag { Ok(t) } else { Err(CRYPT_E_ASN1_BADTAG) }
}

const SEQ: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const INT: u8 = 0x02;

/// An OBJECT IDENTIFIER's dotted form.
fn oid_string(b: &[u8]) -> String {
    let mut parts: Vec<u64> = Vec::new();
    let mut v = 0u64;
    for &x in b {
        v = v << 7 | (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            if parts.is_empty() {
                let first = if v < 80 { v / 40 } else { 2 };
                parts.push(first);
                parts.push(v - first * 40);
            } else {
                parts.push(v);
            }
            v = 0;
        }
    }
    parts.iter().map(|p| alloc::format!("{p}")).collect::<Vec<_>>().join(".")
}

const OID_SIGNED_DATA: &str = "1.2.840.113549.1.7.2";

/// An AlgorithmIdentifier: (OID, parameters encoding).
#[derive(Clone)]
struct Alg {
    oid: String,
    params: Vec<u8>,
}

fn alg(t: Tlv<'_>) -> Result<Alg, u32> {
    let i = items(expect(t, SEQ)?.body)?;
    let oid = oid_string(expect(*i.first().ok_or(ASN1)?, OID)?.body);
    Ok(Alg { oid, params: i.get(1).map(|p| p.raw.to_vec()).unwrap_or_default() })
}

// ---- certificates -------------------------------------------------------------------------

#[derive(Clone)]
struct Cert {
    der: Vec<u8>,
    version: u32,
    /// The serial number's DER contents (big-endian).
    serial: Vec<u8>,
    sig_alg: Alg,
    /// Issuer and subject Name encodings.
    issuer: Vec<u8>,
    subject: Vec<u8>,
    not_before: u64,
    not_after: u64,
    key_alg: Alg,
    /// subjectPublicKey: (bytes, unused bits).
    key: (Vec<u8>, u8),
    /// Extensions: (OID, critical, value).
    extensions: Vec<(String, bool, Vec<u8>)>,
}

/// UTCTime / GeneralizedTime as a FILETIME.
fn time(t: Tlv<'_>) -> Result<u64, u32> {
    let s = core::str::from_utf8(t.body).map_err(|_| ASN1)?;
    let s = s.strip_suffix('Z').ok_or(ASN1)?;
    let (year, rest) = match t.tag {
        0x17 if s.len() == 12 => {
            let y: i64 = s[..2].parse().map_err(|_| ASN1)?;
            (if y < 50 { 2000 + y } else { 1900 + y }, &s[2..])
        }
        0x18 if s.len() == 14 => (s[..4].parse().map_err(|_| ASN1)?, &s[4..]),
        _ => return bad(),
    };
    let n = |i: usize| rest[i..i + 2].parse::<i64>().map_err(|_| ASN1);
    let (mo, d, h, mi, se) = (n(0)?, n(2)?, n(4)?, n(6)?, n(8)?);
    // Days from 1970-01-01 (civil calendar).
    let y = if mo <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + h * 3600 + mi * 60 + se;
    Ok(((secs + 11_644_473_600) * 10_000_000) as u64)
}

fn parse_cert(der: &[u8]) -> Result<Cert, u32> {
    let (outer, _) = tlv(der)?;
    let parts = items(expect(outer, SEQ)?.body)?;
    let tbs = items(expect(*parts.first().ok_or(ASN1)?, SEQ)?.body)?;
    let mut i = 0;
    let mut version = 0;
    if tbs.first().is_some_and(|t| t.tag == 0xa0) {
        let (v, _) = tlv(tbs[0].body)?;
        version = expect(v, INT)?.body.last().copied().unwrap_or(0) as u32;
        i = 1;
    }
    let get = |k: usize| tbs.get(k).copied().ok_or(ASN1);
    let serial = expect(get(i)?, INT)?.body.to_vec();
    let sig_alg = alg(get(i + 1)?)?;
    let issuer = expect(get(i + 2)?, SEQ)?.raw.to_vec();
    let validity = items(expect(get(i + 3)?, SEQ)?.body)?;
    let (not_before, not_after) = (time(*validity.first().ok_or(ASN1)?)?, time(*validity.get(1).ok_or(ASN1)?)?);
    let subject = expect(get(i + 4)?, SEQ)?.raw.to_vec();
    let spki = items(expect(get(i + 5)?, SEQ)?.body)?;
    let key_alg = alg(*spki.first().ok_or(ASN1)?)?;
    let bits = expect(*spki.get(1).ok_or(ASN1)?, 0x03)?.body;
    let key = (bits.get(1..).unwrap_or_default().to_vec(), bits.first().copied().unwrap_or(0));
    let mut extensions = Vec::new();
    for t in &tbs[i + 6..] {
        if t.tag == 0xa3 {
            let (seq, _) = tlv(t.body)?;
            for e in items(expect(seq, SEQ)?.body)? {
                let f = items(expect(e, SEQ)?.body)?;
                let oid = oid_string(expect(*f.first().ok_or(ASN1)?, OID)?.body);
                let (critical, value) = match f.len() {
                    3 => (f[1].body.first().is_some_and(|&b| b != 0), f[2].body.to_vec()),
                    2 => (false, f[1].body.to_vec()),
                    _ => return bad(),
                };
                extensions.push((oid, critical, value));
            }
        }
    }
    Ok(Cert { der: outer.raw.to_vec(), version, serial, sig_alg, issuer, subject, not_before, not_after, key_alg, key, extensions })
}

/// The attributes of a Name: (OID, string value), in order.
fn name_attrs(name: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok((seq, _)) = tlv(name) else { return out };
    let Ok(rdns) = items(seq.body) else { return out };
    for rdn in rdns {
        let Ok(atvs) = items(rdn.body) else { continue };
        for atv in atvs {
            let Ok(f) = items(atv.body) else { continue };
            if f.len() == 2 && f[0].tag == OID {
                out.push((oid_string(f[0].body), directory_string(f[1])));
            }
        }
    }
    out
}

/// A DirectoryString (or IA5String) as text.
fn directory_string(t: Tlv<'_>) -> String {
    match t.tag {
        0x1e => {
            let units: Vec<u16> = t.body.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        }
        0x1c => t.body.as_chunks::<4>().0.iter().filter_map(|c| char::from_u32(u32::from_be_bytes(*c))).collect(),
        0x14 => t.body.iter().map(|&b| b as char).collect(), // T61String as Latin-1
        _ => String::from_utf8_lossy(t.body).into_owned(),
    }
}

const OID_CN: &str = "2.5.4.3";
const OID_O: &str = "2.5.4.10";
const OID_OU: &str = "2.5.4.11";
const OID_EMAIL: &str = "1.2.840.113549.1.9.1";
const OID_SAN: &str = "2.5.29.17";

/// Short names of attributes in CERT_X500_NAME_STR form.
fn attr_label(oid: &str) -> String {
    let short = [
        ("2.5.4.3", "CN"),
        ("2.5.4.6", "C"),
        ("2.5.4.7", "L"),
        ("2.5.4.8", "S"),
        ("2.5.4.9", "STREET"),
        ("2.5.4.10", "O"),
        ("2.5.4.11", "OU"),
        ("2.5.4.12", "T"),
        ("2.5.4.42", "G"),
        ("2.5.4.4", "SN"),
        ("2.5.4.5", "SERIALNUMBER"),
        ("0.9.2342.19200300.100.1.25", "DC"),
        ("1.2.840.113549.1.9.1", "E"),
    ];
    short.iter().find(|s| s.0 == oid).map_or_else(|| alloc::format!("OID.{oid}"), |s| String::from(s.1))
}

/// Subject alternative names of a kind ([1] rfc822Name, [2] dNSName, [6] URI).
fn alt_names(c: &Cert, tag: u8) -> Vec<String> {
    let Some(ext) = c.extensions.iter().find(|e| e.0 == OID_SAN) else { return Vec::new() };
    let Ok((seq, _)) = tlv(&ext.2) else { return Vec::new() };
    items(seq.body).unwrap_or_default().into_iter().filter(|t| t.tag == 0x80 | tag).map(|t| String::from_utf8_lossy(t.body).into_owned()).collect()
}

// ---- PKCS#7 ---------------------------------------------------------------------------------

/// An attribute: (OID, value encodings).
type Attribute = (String, Vec<Vec<u8>>);

#[derive(Clone)]
struct Signer {
    version: u32,
    issuer: Vec<u8>,
    serial: Vec<u8>,
    digest: Alg,
    encryption: Alg,
    signature: Vec<u8>,
    /// Authenticated and unauthenticated attributes: (OID, value encodings).
    auth: Vec<Attribute>,
    unauth: Vec<Attribute>,
}

#[derive(Clone)]
struct Signed {
    content_type: String,
    content: Vec<u8>,
    certs: Vec<Vec<u8>>,
    signers: Vec<Signer>,
}

fn attributes(t: Tlv<'_>) -> Result<Vec<Attribute>, u32> {
    items(t.body)?
        .into_iter()
        .map(|a| {
            let f = items(expect(a, SEQ)?.body)?;
            let oid = oid_string(expect(*f.first().ok_or(ASN1)?, OID)?.body);
            let values = items(expect(*f.get(1).ok_or(ASN1)?, SET)?.body)?.into_iter().map(|v| v.raw.to_vec()).collect();
            Ok((oid, values))
        })
        .collect()
}

/// A PKCS#7 ContentInfo holding SignedData.
fn parse_signed(der: &[u8]) -> Result<Signed, u32> {
    let (ci, _) = tlv(der)?;
    let f = items(expect(ci, SEQ)?.body)?;
    if oid_string(expect(*f.first().ok_or(ASN1)?, OID)?.body) != OID_SIGNED_DATA {
        return Err(CRYPT_E_INVALID_MSG_TYPE);
    }
    let (sd, _) = tlv(expect(*f.get(1).ok_or(ASN1)?, 0xa0)?.body)?;
    let s = items(expect(sd, SEQ)?.body)?;
    let encap = items(expect(*s.get(2).ok_or(ASN1)?, SEQ)?.body)?;
    let content_type = oid_string(expect(*encap.first().ok_or(ASN1)?, OID)?.body);
    let content = match encap.get(1) {
        Some(c) if c.tag == 0xa0 => {
            let (inner, _) = tlv(c.body)?;
            // Data is an OCTET STRING; other types (Authenticode's
            // SpcIndirectDataContent) are kept whole.
            if inner.tag == 0x04 { inner.body.to_vec() } else { inner.raw.to_vec() }
        }
        _ => Vec::new(),
    };
    let mut certs = Vec::new();
    let mut signer_set = None;
    for t in &s[3..] {
        match t.tag {
            0xa0 => certs = items(t.body)?.into_iter().filter(|c| c.tag == SEQ).map(|c| c.raw.to_vec()).collect(),
            0xa1 => {} // CRLs
            SET => signer_set = Some(*t),
            _ => return bad(),
        }
    }
    let mut signers = Vec::new();
    for si in items(signer_set.ok_or(ASN1)?.body)? {
        let f = items(expect(si, SEQ)?.body)?;
        let version = expect(*f.first().ok_or(ASN1)?, INT)?.body.last().copied().unwrap_or(0) as u32;
        // Signers named by subjectKeyIdentifier ([0]) are not supported.
        let sid = expect(*f.get(1).ok_or(ASN1)?, SEQ).map_err(|_| ERROR_NOT_SUPPORTED)?;
        let ias = items(sid.body)?;
        let issuer = expect(*ias.first().ok_or(ASN1)?, SEQ)?.raw.to_vec();
        let serial = expect(*ias.get(1).ok_or(ASN1)?, INT)?.body.to_vec();
        let digest = alg(*f.get(2).ok_or(ASN1)?)?;
        let mut k = 3;
        let mut auth = Vec::new();
        if f.get(k).is_some_and(|t| t.tag == 0xa0) {
            auth = attributes(f[k])?;
            k += 1;
        }
        let encryption = alg(*f.get(k).ok_or(ASN1)?)?;
        let signature = expect(*f.get(k + 1).ok_or(ASN1)?, 0x04)?.body.to_vec();
        let unauth = match f.get(k + 2) {
            Some(t) if t.tag == 0xa1 => attributes(*t)?,
            _ => Vec::new(),
        };
        signers.push(Signer { version, issuer, serial, digest, encryption, signature, auth, unauth });
    }
    Ok(Signed { content_type, content, certs, signers })
}

/// The PKCS#7 signature in a PE image's certificate table.
fn embedded_signature(file: &[u8]) -> Result<Vec<u8>, u32> {
    let pe = osyx_pe::PeFile::parse(file).map_err(|_| CRYPT_E_NO_MATCH)?;
    let d = pe.directory(4); // IMAGE_DIRECTORY_ENTRY_SECURITY: a file offset
    if !d.is_present() {
        return Err(CRYPT_E_NO_MATCH);
    }
    let (start, size) = (d.virtual_address as usize, d.size as usize);
    let table = file.get(start..start.checked_add(size).ok_or(CRYPT_E_NO_MATCH)?).ok_or(CRYPT_E_NO_MATCH)?;
    let mut at = 0;
    while at + 8 <= table.len() {
        let len = u32::from_le_bytes([table[at], table[at + 1], table[at + 2], table[at + 3]]) as usize;
        let kind = u16::from_le_bytes([table[at + 6], table[at + 7]]);
        if len < 8 || at + len > table.len() {
            break;
        }
        if kind == 2 {
            // WIN_CERT_TYPE_PKCS_SIGNED_DATA
            let (t, _) = tlv(&table[at + 8..at + len])?;
            return Ok(t.raw.to_vec());
        }
        at += (len + 7) & !7;
    }
    Err(CRYPT_E_NO_MATCH)
}

/// Whether a PE image's embedded Authenticode signature is structurally
/// valid and names at least one signer and one certificate. This checks the
/// encoding only: no digest, chain or trust evaluation.
pub(crate) fn authenticode_has_signer(der: &[u8]) -> bool {
    parse_signed(der).is_ok_and(|s| !s.signers.is_empty() && !s.certs.is_empty())
}

// ---- handles ---------------------------------------------------------------------------------

struct Store {
    certs: Mutex<Vec<Vec<u8>>>,
}

struct Msg {
    data: Vec<u8>,
    decoded: Option<Signed>,
}

/// A CERT_CONTEXT handed out: its block, reference count and source.
struct Context {
    refs: u32,
    store: u64,
    index: usize,
}

struct Handles {
    next: u64,
    stores: BTreeMap<u64, Arc<Store>>,
    msgs: BTreeMap<u64, Msg>,
    contexts: BTreeMap<u64, Context>,
}

static HANDLES: Mutex<Handles> = Mutex::new(Handles { next: 0x5c00_0010, stores: BTreeMap::new(), msgs: BTreeMap::new(), contexts: BTreeMap::new() });

fn new_handle(h: &mut Handles) -> u64 {
    let v = h.next;
    h.next += 0x10;
    v
}

fn new_store(certs: Vec<Vec<u8>>) -> u64 {
    let mut h = HANDLES.lock().unwrap();
    let id = new_handle(&mut h);
    h.stores.insert(id, Arc::new(Store { certs: Mutex::new(certs) }));
    id
}

fn new_msg(data: Vec<u8>, decoded: Option<Signed>) -> u64 {
    let mut h = HANDLES.lock().unwrap();
    let id = new_handle(&mut h);
    h.msgs.insert(id, Msg { data, decoded });
    id
}

/// Lays out structures with pointers into one heap block: `fixed` bytes
/// of structure first, then appended data.
struct Block {
    bytes: Vec<u8>,
    /// (offset of a pointer field, offset of its target).
    fixups: Vec<(usize, usize)>,
}

impl Block {
    fn new(fixed: usize) -> Block {
        Block { bytes: alloc::vec![0; fixed], fixups: Vec::new() }
    }
    fn put32(&mut self, at: usize, v: u32) {
        self.bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    /// Appends `data` (8-aligned) and points the field at `at` to it.
    fn point(&mut self, at: usize, data: &[u8]) {
        while !self.bytes.len().is_multiple_of(8) {
            self.bytes.push(0);
        }
        self.fixups.push((at, self.bytes.len()));
        self.bytes.extend_from_slice(data);
    }
    /// A blob {cbData, pbData} at `at`.
    fn blob(&mut self, at: usize, data: &[u8]) {
        self.put32(at, data.len() as u32);
        if !data.is_empty() {
            self.point(at + 8, data);
        }
    }
    /// A CRYPT_ALGORITHM_IDENTIFIER at `at` (24 bytes).
    fn alg(&mut self, at: usize, a: &Alg) {
        let mut s = a.oid.clone().into_bytes();
        s.push(0);
        self.point(at, &s);
        self.blob(at + 8, &a.params);
    }
    /// Reserves `n` zero bytes (8-aligned), returning their offset.
    fn reserve(&mut self, n: usize) -> usize {
        while !self.bytes.len().is_multiple_of(8) {
            self.bytes.push(0);
        }
        let at = self.bytes.len();
        self.bytes.resize(at + n, 0);
        at
    }
    /// The block relocated to `base`.
    fn finish(mut self, base: u64) -> Vec<u8> {
        for (at, target) in core::mem::take(&mut self.fixups) {
            self.bytes[at..at + 8].copy_from_slice(&(base + target as u64).to_le_bytes());
        }
        self.bytes
    }
}

/// A CERT_INFO (208 bytes) at `at`.
fn cert_info(b: &mut Block, at: usize, c: &Cert) {
    b.put32(at, c.version);
    let mut serial = c.serial.clone();
    serial.reverse(); // CRYPT_INTEGER_BLOB is little-endian
    b.blob(at + 8, &serial);
    b.alg(at + 24, &c.sig_alg);
    b.blob(at + 48, &c.issuer);
    b.bytes[at + 64..at + 72].copy_from_slice(&c.not_before.to_le_bytes());
    b.bytes[at + 72..at + 80].copy_from_slice(&c.not_after.to_le_bytes());
    b.blob(at + 80, &c.subject);
    b.alg(at + 96, &c.key_alg);
    b.blob(at + 120, &c.key.0);
    b.put32(at + 136, c.key.1 as u32);
    b.put32(at + 192, c.extensions.len() as u32);
    if !c.extensions.is_empty() {
        let ext = b.reserve(24 * c.extensions.len());
        b.fixups.push((at + 200, ext));
        for (i, (oid, critical, value)) in c.extensions.iter().enumerate() {
            let e = ext + 24 * i;
            let mut s = oid.clone().into_bytes();
            s.push(0);
            b.point(e, &s);
            b.put32(e + 8, *critical as u32);
            b.blob(e + 16, value);
        }
    }
}

/// Copies a finished block to the heap.
fn to_heap(b: Block) -> Option<u64> {
    let p = kernel32::heap_alloc(b.bytes.len(), false)?;
    let bytes = b.finish(p);
    // SAFETY: a fresh block of bytes.len() bytes.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), p as *mut u8, bytes.len()) };
    Some(p)
}

/// A new CERT_CONTEXT for certificate `index` of `store`.
fn make_context(store: u64, index: usize, der: &[u8]) -> Result<u64, u32> {
    let c = parse_cert(der)?;
    let mut b = Block::new(40 + 208);
    b.put32(0, X509_ASN_ENCODING);
    b.point(8, &c.der);
    b.put32(16, c.der.len() as u32);
    b.fixups.push((24, 40));
    b.bytes[32..40].copy_from_slice(&store.to_le_bytes());
    cert_info(&mut b, 40, &c);
    let p = to_heap(b).ok_or(ERROR_NOT_ENOUGH_MEMORY)?;
    HANDLES.lock().unwrap().contexts.insert(p, Context { refs: 1, store, index });
    Ok(p)
}

/// The DER of a CERT_CONTEXT we handed out.
fn context_der(ctx: u64) -> Option<Vec<u8>> {
    if !HANDLES.lock().unwrap().contexts.contains_key(&ctx) {
        return None;
    }
    // SAFETY: a CERT_CONTEXT this module built.
    unsafe {
        let p = *((ctx + 8) as *const u64) as *const u8;
        let n = *((ctx + 16) as *const u32) as usize;
        Some(core::slice::from_raw_parts(p, n).to_vec())
    }
}

// ---- the API ---------------------------------------------------------------------------------

const CERT_QUERY_OBJECT_FILE: u32 = 1;
const CERT_QUERY_OBJECT_BLOB: u32 = 2;
const CERT_QUERY_CONTENT_CERT: u32 = 1;
const CERT_QUERY_CONTENT_PKCS7_SIGNED: u32 = 8;
const CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED: u32 = 10;
const CERT_QUERY_FORMAT_BINARY: u32 = 1;

#[allow(clippy::too_many_arguments)]
extern "win64" fn CryptQueryObject(
    kind: u32,
    object: *const u8,
    content_flags: u32,
    format_flags: u32,
    _flags: u32,
    encoding: *mut u32,
    content_type: *mut u32,
    format: *mut u32,
    store: *mut u64,
    msg: *mut u64,
    context: *mut u64,
) -> i32 {
    let data = match kind {
        CERT_QUERY_OBJECT_FILE => {
            // SAFETY: a NUL-terminated file name.
            let Some(name) = (unsafe { path::wide_to_string(object as *const u16) }) else { return fail(ERROR_INVALID_PARAMETER, 0) };
            let p = match path::to_osyx(&name, &kernel32::cwd_win()) {
                Ok(p) => p,
                Err(e) => return fail(e, 0),
            };
            match os_std::fs::read(&p) {
                Ok(d) => d,
                Err(_) => return fail(ERROR_FILE_NOT_FOUND, 0),
            }
        }
        CERT_QUERY_OBJECT_BLOB => {
            // SAFETY: the caller's CRYPT_DATA_BLOB.
            unsafe {
                let n = *(object as *const u32) as usize;
                let p = *(object.add(8) as *const u64) as *const u8;
                if p.is_null() && n != 0 {
                    return fail(ERROR_INVALID_PARAMETER, 0);
                }
                core::slice::from_raw_parts(p, n).to_vec()
            }
        }
        _ => return fail(ERROR_NOT_SUPPORTED, 0),
    };
    if format_flags & (1 << CERT_QUERY_FORMAT_BINARY) == 0 {
        return fail(CRYPT_E_NO_MATCH, 0); // Base64 forms are not supported
    }
    // (content type, the PKCS#7 bytes or a certificate)
    let mut found: Option<(u32, Vec<u8>)> = None;
    if content_flags & (1 << CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED) != 0 {
        if let Ok(sig) = embedded_signature(&data) {
            found = Some((CERT_QUERY_CONTENT_PKCS7_SIGNED_EMBED, sig));
        }
    }
    if found.is_none() && content_flags & (1 << CERT_QUERY_CONTENT_PKCS7_SIGNED) != 0 && parse_signed(&data).is_ok() {
        found = Some((CERT_QUERY_CONTENT_PKCS7_SIGNED, data.clone()));
    }
    if found.is_none() && content_flags & (1 << CERT_QUERY_CONTENT_CERT) != 0 && parse_cert(&data).is_ok() {
        found = Some((CERT_QUERY_CONTENT_CERT, data.clone()));
    }
    let Some((ctype, bytes)) = found else { return fail(CRYPT_E_NO_MATCH, 0) };
    // SAFETY: the caller's optional out pointers.
    unsafe {
        if !encoding.is_null() {
            *encoding = ENCODING;
        }
        if !content_type.is_null() {
            *content_type = ctype;
        }
        if !format.is_null() {
            *format = CERT_QUERY_FORMAT_BINARY;
        }
        if ctype == CERT_QUERY_CONTENT_CERT {
            let s = new_store(alloc::vec![bytes.clone()]);
            if !context.is_null() {
                match make_context(s, 0, &bytes) {
                    Ok(c) => *context = c,
                    Err(e) => return fail(e, 0),
                }
            }
            if !store.is_null() {
                *store = s;
            }
            if !msg.is_null() {
                *msg = 0;
            }
            return 1;
        }
        let signed = match parse_signed(&bytes) {
            Ok(s) => s,
            Err(e) => return fail(e, 0),
        };
        if !store.is_null() {
            *store = new_store(signed.certs.clone());
        }
        if !msg.is_null() {
            *msg = new_msg(bytes, Some(signed));
        }
        if !context.is_null() {
            *context = 0;
        }
    }
    1
}

extern "win64" fn CryptMsgOpenToDecode(encoding: u32, _flags: u32, kind: u32, _prov: u64, _recipient: u64, stream: u64) -> u64 {
    if encoding & PKCS_7_ASN_ENCODING == 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if stream != 0 || (kind != 0 && kind != 2) {
        return fail(ERROR_NOT_SUPPORTED, 0); // streaming; types other than signed
    }
    new_msg(Vec::new(), None)
}

extern "win64" fn CryptMsgUpdate(msg: u64, data: *const u8, len: u32, last: i32) -> i32 {
    let mut h = HANDLES.lock().unwrap();
    let Some(m) = h.msgs.get_mut(&msg) else { return fail(ERROR_INVALID_HANDLE, 0) };
    if m.decoded.is_some() {
        return fail(CRYPT_E_INVALID_MSG_TYPE, 0); // already complete
    }
    if last == 0 {
        return fail(CRYPT_E_MSG_ERROR, 0); // a message that is not streamed comes whole
    }
    if len != 0 {
        // SAFETY: the caller's `len` bytes.
        m.data.extend_from_slice(unsafe { core::slice::from_raw_parts(data, len as usize) });
    }
    match parse_signed(&m.data) {
        Ok(s) => m.decoded = Some(s),
        Err(e) => return fail(e, 0),
    }
    1
}

extern "win64" fn CryptMsgClose(msg: u64) -> i32 {
    if msg == 0 {
        return 1;
    }
    match HANDLES.lock().unwrap().msgs.remove(&msg) {
        Some(_) => 1,
        None => fail(ERROR_INVALID_HANDLE, 0),
    }
}

const CMSG_TYPE_PARAM: u32 = 1;
const CMSG_CONTENT_PARAM: u32 = 2;
const CMSG_SIGNER_COUNT_PARAM: u32 = 5;
const CMSG_SIGNER_INFO_PARAM: u32 = 6;
const CMSG_SIGNER_CERT_INFO_PARAM: u32 = 7;
const CMSG_CERT_COUNT_PARAM: u32 = 11;
const CMSG_CERT_PARAM: u32 = 12;
const CMSG_INNER_CONTENT_TYPE_PARAM: u32 = 4;

/// CRYPT_ATTRIBUTES (16 bytes) at `at`.
fn put_attributes(b: &mut Block, at: usize, attrs: &[Attribute]) {
    b.put32(at, attrs.len() as u32);
    if attrs.is_empty() {
        return;
    }
    let arr = b.reserve(24 * attrs.len());
    b.fixups.push((at + 8, arr));
    for (i, (oid, values)) in attrs.iter().enumerate() {
        let a = arr + 24 * i;
        let mut s = oid.clone().into_bytes();
        s.push(0);
        b.point(a, &s);
        b.put32(a + 8, values.len() as u32);
        let vals = b.reserve(16 * values.len());
        b.fixups.push((a + 16, vals));
        for (j, v) in values.iter().enumerate() {
            b.blob(vals + 16 * j, v);
        }
    }
}

/// Writes a parameter whose pointers point into the caller's buffer.
fn put_param(out: *mut u8, size: *mut u32, b: Block) -> i32 {
    let need = b.bytes.len() as u32;
    // SAFETY: the caller's size pointer and buffer of *size bytes.
    unsafe {
        if out.is_null() {
            *size = need;
            return 1;
        }
        if *size < need {
            *size = need;
            return fail(ERROR_MORE_DATA, 0);
        }
        *size = need;
        let bytes = b.finish(out as u64);
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    }
    1
}

fn raw_param(data: &[u8]) -> Block {
    Block { bytes: data.to_vec(), fixups: Vec::new() }
}

extern "win64" fn CryptMsgGetParam(msg: u64, param: u32, index: u32, out: *mut u8, size: *mut u32) -> i32 {
    if size.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let h = HANDLES.lock().unwrap();
    let Some(m) = h.msgs.get(&msg) else { return fail(ERROR_INVALID_HANDLE, 0) };
    let Some(s) = m.decoded.clone() else { return fail(CRYPT_E_STREAM_MSG_NOT_READY, 0) };
    drop(h);
    let signer = |i: u32| s.signers.get(i as usize).cloned().ok_or(CRYPT_E_INVALID_INDEX);
    let block = match param {
        CMSG_TYPE_PARAM => raw_param(&2u32.to_le_bytes()), // CMSG_SIGNED
        CMSG_CONTENT_PARAM => raw_param(&s.content),
        CMSG_INNER_CONTENT_TYPE_PARAM => {
            let mut v = s.content_type.clone().into_bytes();
            v.push(0);
            raw_param(&v)
        }
        CMSG_SIGNER_COUNT_PARAM => raw_param(&(s.signers.len() as u32).to_le_bytes()),
        CMSG_CERT_COUNT_PARAM => raw_param(&(s.certs.len() as u32).to_le_bytes()),
        CMSG_CERT_PARAM => match s.certs.get(index as usize) {
            Some(c) => raw_param(c),
            None => return fail(CRYPT_E_INVALID_INDEX, 0),
        },
        CMSG_SIGNER_INFO_PARAM => {
            let si = match signer(index) {
                Ok(v) => v,
                Err(e) => return fail(e, 0),
            };
            let mut b = Block::new(136);
            b.put32(0, si.version);
            b.blob(8, &si.issuer);
            let mut serial = si.serial.clone();
            serial.reverse();
            b.blob(24, &serial);
            b.alg(40, &si.digest);
            b.alg(64, &si.encryption);
            b.blob(88, &si.signature);
            put_attributes(&mut b, 104, &si.auth);
            put_attributes(&mut b, 120, &si.unauth);
            b
        }
        CMSG_SIGNER_CERT_INFO_PARAM => {
            let si = match signer(index) {
                Ok(v) => v,
                Err(e) => return fail(e, 0),
            };
            // A CERT_INFO with only the issuer and serial number set.
            let mut b = Block::new(208);
            let mut serial = si.serial.clone();
            serial.reverse();
            b.blob(8, &serial);
            b.blob(48, &si.issuer);
            b
        }
        _ => return fail(CRYPT_E_INVALID_MSG_TYPE, 0),
    };
    put_param(out, size, block)
}

const CERT_STORE_PROV_MSG: u64 = 1;
const CERT_STORE_PROV_MEMORY: u64 = 2;
const CERT_STORE_PROV_PKCS7: u64 = 5;
const CERT_STORE_PROV_SYSTEM_A: u64 = 9;
const CERT_STORE_PROV_SYSTEM_W: u64 = 10;

extern "win64" fn CertOpenStore(provider: u64, _encoding: u32, _prov: u64, _flags: u32, para: u64) -> u64 {
    match provider {
        CERT_STORE_PROV_MEMORY => new_store(Vec::new()),
        CERT_STORE_PROV_MSG => {
            let h = HANDLES.lock().unwrap();
            let certs = h.msgs.get(&para).and_then(|m| m.decoded.as_ref()).map(|s| s.certs.clone());
            drop(h);
            match certs {
                Some(c) => new_store(c),
                None => fail(ERROR_INVALID_HANDLE, 0),
            }
        }
        CERT_STORE_PROV_PKCS7 => {
            // SAFETY: the caller's CRYPT_DATA_BLOB.
            let data = unsafe {
                let p = para as *const u8;
                if p.is_null() {
                    return fail(ERROR_INVALID_PARAMETER, 0);
                }
                core::slice::from_raw_parts(*(p.add(8) as *const u64) as *const u8, *(p as *const u32) as usize).to_vec()
            };
            match parse_signed(&data) {
                Ok(s) => new_store(s.certs),
                Err(e) => fail(e, 0),
            }
        }
        // OSyx has no Windows system certificate stores.
        CERT_STORE_PROV_SYSTEM_A | CERT_STORE_PROV_SYSTEM_W => fail(ERROR_FILE_NOT_FOUND, 0),
        _ => fail(ERROR_NOT_SUPPORTED, 0),
    }
}

extern "win64" fn CertCloseStore(store: u64, _flags: u32) -> i32 {
    if store == 0 {
        return 1;
    }
    match HANDLES.lock().unwrap().stores.remove(&store) {
        Some(_) => 1,
        None => fail(ERROR_INVALID_HANDLE, 0),
    }
}

extern "win64" fn CertFreeCertificateContext(ctx: u64) -> i32 {
    if ctx == 0 {
        return 1;
    }
    let mut h = HANDLES.lock().unwrap();
    let Some(c) = h.contexts.get_mut(&ctx) else { return 1 };
    c.refs -= 1;
    if c.refs == 0 {
        h.contexts.remove(&ctx);
        drop(h);
        kernel32::heap_free(ctx);
    }
    1
}

extern "win64" fn CertDuplicateCertificateContext(ctx: u64) -> u64 {
    if let Some(c) = HANDLES.lock().unwrap().contexts.get_mut(&ctx) {
        c.refs += 1;
    }
    ctx
}

const CERT_FIND_ANY: u32 = 0;
const CERT_FIND_ISSUER_NAME: u32 = 0x2_0004;
const CERT_FIND_SUBJECT_NAME: u32 = 0x2_0007;
const CERT_FIND_SUBJECT_CERT: u32 = 0xb_0000;
const CERT_FIND_EXISTING: u32 = 0xd_0000;

extern "win64" fn CertFindCertificateInStore(store: u64, _encoding: u32, _flags: u32, kind: u32, para: *const u8, prev: u64) -> u64 {
    let s = {
        let h = HANDLES.lock().unwrap();
        match h.stores.get(&store) {
            Some(s) => s.clone(),
            None => return fail(ERROR_INVALID_HANDLE, 0),
        }
    };
    let start = if prev == 0 {
        0
    } else {
        let h = HANDLES.lock().unwrap();
        let i = h.contexts.get(&prev).filter(|c| c.store == store).map(|c| c.index + 1);
        drop(h);
        CertFreeCertificateContext(prev);
        match i {
            Some(i) => i,
            None => return fail(ERROR_INVALID_PARAMETER, 0),
        }
    };
    // SAFETY: a CERT_NAME_BLOB / CERT_INFO / CERT_CONTEXT, per the find type.
    let blob = |p: *const u8| unsafe { core::slice::from_raw_parts(*(p.add(8) as *const u64) as *const u8, *(p as *const u32) as usize).to_vec() };
    let certs = s.certs.lock().unwrap().clone();
    for (i, der) in certs.iter().enumerate().skip(start) {
        let Ok(c) = parse_cert(der) else { continue };
        let hit = match kind {
            CERT_FIND_ANY => true,
            CERT_FIND_SUBJECT_NAME => !para.is_null() && blob(para) == c.subject,
            CERT_FIND_ISSUER_NAME => !para.is_null() && blob(para) == c.issuer,
            CERT_FIND_SUBJECT_CERT => {
                if para.is_null() {
                    return fail(ERROR_INVALID_PARAMETER, 0);
                }
                // SAFETY: the caller's CERT_INFO: SerialNumber at 8, Issuer at 48.
                let mut serial = blob(unsafe { para.add(8) });
                serial.reverse();
                let issuer = blob(unsafe { para.add(48) });
                strip_zeros(&serial) == strip_zeros(&c.serial) && issuer == c.issuer
            }
            CERT_FIND_EXISTING => context_der(para as u64).is_some_and(|d| d == *der),
            _ => return fail(ERROR_NOT_SUPPORTED, 0),
        };
        if hit {
            return make_context(store, i, der).unwrap_or_else(|e| fail(e, 0));
        }
    }
    fail(CRYPT_E_NOT_FOUND, 0)
}

/// An INTEGER's magnitude without leading zero bytes.
fn strip_zeros(b: &[u8]) -> &[u8] {
    let n = b.iter().take_while(|&&x| x == 0).count();
    &b[n.min(b.len().saturating_sub(1))..]
}

const CERT_NAME_EMAIL_TYPE: u32 = 1;
const CERT_NAME_RDN_TYPE: u32 = 2;
const CERT_NAME_ATTR_TYPE: u32 = 3;
const CERT_NAME_SIMPLE_DISPLAY_TYPE: u32 = 4;
const CERT_NAME_FRIENDLY_DISPLAY_TYPE: u32 = 5;
const CERT_NAME_DNS_TYPE: u32 = 6;
const CERT_NAME_URL_TYPE: u32 = 7;
const CERT_NAME_UPN_TYPE: u32 = 8;
const CERT_NAME_ISSUER_FLAG: u32 = 1;

fn cert_name(c: &Cert, kind: u32, flags: u32, para: *const u8) -> String {
    let issuer = flags & CERT_NAME_ISSUER_FLAG != 0;
    let attrs = name_attrs(if issuer { &c.issuer } else { &c.subject });
    let first = |oid: &str| attrs.iter().find(|a| a.0 == oid).map(|a| a.1.clone());
    match kind {
        CERT_NAME_EMAIL_TYPE => (if issuer { None } else { alt_names(c, 1).into_iter().next() }).or_else(|| first(OID_EMAIL)).unwrap_or_default(),
        CERT_NAME_RDN_TYPE => attrs.iter().map(|(o, v)| alloc::format!("{}={}", attr_label(o), v)).collect::<Vec<_>>().join(", "),
        CERT_NAME_ATTR_TYPE => {
            // SAFETY: NULL or the caller's NUL-terminated OID string.
            let oid = unsafe { path::ansi_to_string(para) }.unwrap_or_default();
            first(&oid).unwrap_or_default()
        }
        CERT_NAME_SIMPLE_DISPLAY_TYPE | CERT_NAME_FRIENDLY_DISPLAY_TYPE => first(OID_CN)
            .or_else(|| first(OID_OU))
            .or_else(|| first(OID_O))
            .or_else(|| (if issuer { None } else { alt_names(c, 1).into_iter().next() }).or_else(|| first(OID_EMAIL)))
            .or_else(|| attrs.first().map(|a| a.1.clone()))
            .unwrap_or_default(),
        CERT_NAME_DNS_TYPE => (if issuer { None } else { alt_names(c, 2).into_iter().next() }).or_else(|| first(OID_CN)).unwrap_or_default(),
        CERT_NAME_URL_TYPE => (if issuer { None } else { alt_names(c, 6).into_iter().next() }).unwrap_or_default(),
        CERT_NAME_UPN_TYPE => String::new(), // otherName UPNs are not decoded
        _ => String::new(),
    }
}

extern "win64" fn CertGetNameStringW(ctx: u64, kind: u32, flags: u32, para: *const u8, out: *mut u16, len: u32) -> u32 {
    let name = context_der(ctx).and_then(|d| parse_cert(&d).ok()).map(|c| cert_name(&c, kind, flags, para)).unwrap_or_default();
    let w: Vec<u16> = name.encode_utf16().collect();
    if out.is_null() || len == 0 {
        return w.len() as u32 + 1;
    }
    let n = w.len().min(len as usize - 1);
    // SAFETY: the caller's buffer of `len` characters.
    unsafe {
        core::ptr::copy_nonoverlapping(w.as_ptr(), out, n);
        *out.add(n) = 0;
    }
    n as u32 + 1
}

// ---- binary to string -----------------------------------------------------------------------

const CRYPT_STRING_BASE64HEADER: u32 = 0;
const CRYPT_STRING_BASE64: u32 = 1;
const CRYPT_STRING_BINARY: u32 = 2;
const CRYPT_STRING_BASE64REQUESTHEADER: u32 = 3;
const CRYPT_STRING_HEX: u32 = 4;
const CRYPT_STRING_BASE64X509CRLHEADER: u32 = 9;
const CRYPT_STRING_HEXRAW: u32 = 0xc;
const CRYPT_STRING_NOCRLF: u32 = 0x4000_0000;
const CRYPT_STRING_NOCR: u32 = 0x8000_0000;

fn base64(data: &[u8], eol: &str) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for (i, c) in data.chunks(3).enumerate() {
        if i > 0 && i % 16 == 0 {
            out.push_str(eol); // 64 characters per line
        }
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for k in 0..4 {
            out.push(if k <= c.len() { T[(n >> (18 - 6 * k) & 63) as usize] as char } else { '=' });
        }
    }
    if !data.is_empty() {
        out.push_str(eol);
    }
    out
}

fn binary_string(data: &[u8], flags: u32) -> Result<String, u32> {
    let eol = if flags & CRYPT_STRING_NOCRLF != 0 { "" } else if flags & CRYPT_STRING_NOCR != 0 { "\n" } else { "\r\n" };
    let hex = |b: &u8| alloc::format!("{b:02x}");
    Ok(match flags & 0xffff {
        CRYPT_STRING_BASE64 => base64(data, eol),
        f @ (CRYPT_STRING_BASE64HEADER | CRYPT_STRING_BASE64REQUESTHEADER | CRYPT_STRING_BASE64X509CRLHEADER) => {
            let label = match f {
                CRYPT_STRING_BASE64HEADER => "CERTIFICATE",
                CRYPT_STRING_BASE64REQUESTHEADER => "NEW CERTIFICATE REQUEST",
                _ => "X509 CRL",
            };
            let nl = if eol.is_empty() { "\r\n" } else { eol };
            alloc::format!("-----BEGIN {label}-----{nl}{}-----END {label}-----{nl}", base64(data, nl))
        }
        CRYPT_STRING_HEXRAW => {
            let mut s: String = data.iter().map(hex).collect();
            s.push_str(eol);
            s
        }
        CRYPT_STRING_HEX => {
            let mut s = String::new();
            for (i, line) in data.chunks(16).enumerate() {
                if i > 0 {
                    s.push_str(eol);
                }
                for (j, b) in line.iter().enumerate() {
                    if j > 0 {
                        s.push_str(if j == 8 { "  " } else { " " });
                    }
                    s.push_str(&hex(b));
                }
            }
            if !data.is_empty() {
                s.push_str(eol);
            }
            s
        }
        CRYPT_STRING_BINARY => return Err(ERROR_INVALID_PARAMETER), // not a string form
        _ => return Err(ERROR_NOT_SUPPORTED),
    })
}

extern "win64" fn CryptBinaryToStringW(data: *const u8, len: u32, flags: u32, out: *mut u16, size: *mut u32) -> i32 {
    if size.is_null() || (data.is_null() && len != 0) {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's `len` bytes.
    let bytes = if len == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(data, len as usize) } };
    let s = match binary_string(bytes, flags) {
        Ok(s) => s,
        Err(e) => return fail(e, 0),
    };
    let w: Vec<u16> = s.encode_utf16().collect();
    // SAFETY: the caller's size pointer and buffer of *size characters.
    unsafe {
        if out.is_null() {
            *size = w.len() as u32 + 1;
            return 1;
        }
        if (*size as usize) < w.len() + 1 {
            *size = w.len() as u32 + 1;
            return fail(ERROR_MORE_DATA, 0);
        }
        core::ptr::copy_nonoverlapping(w.as_ptr(), out, w.len());
        *out.add(w.len()) = 0;
        *size = w.len() as u32;
    }
    1
}

const OID_EKU: &str = "2.5.29.37";
const CRYPT_E_NO_KEY_PROPERTY: u32 = 0x8009_200b;

extern "win64" fn CertNameToStrA(_encoding: u32, name_blob: *const u8, str_type: u32, psz: *mut u8, csz: u32) -> u32 {
    if name_blob.is_null() {
        return 0;
    }
    let der = unsafe {
        let n = *(name_blob as *const u32) as usize;
        let p = *(name_blob.add(8) as *const u64) as *const u8;
        if p.is_null() || n == 0 {
            &[][..]
        } else {
            core::slice::from_raw_parts(p, n)
        }
    };
    let mut attrs = name_attrs(der);
    if str_type & 0x0200_0000 != 0 {
        // CERT_NAME_STR_REVERSE_FLAG
        attrs.reverse();
    }
    let sep = if str_type & 0x4000_0000 != 0 {
        "; "
    } else if str_type & 0x0800_0000 != 0 {
        "\r\n"
    } else {
        ", "
    };
    let kind = str_type & 0xffff;
    let text = attrs
        .into_iter()
        .map(|(o, v)| match kind {
            2 => alloc::format!("{o}={v}"),
            3 => alloc::format!("{}={v}", attr_label(&o)),
            _ => v,
        })
        .collect::<Vec<_>>()
        .join(sep);
    let bytes = text.as_bytes();
    if psz.is_null() || csz == 0 {
        return bytes.len() as u32 + 1;
    }
    let n = bytes.len().min(csz as usize - 1);
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), psz, n);
        *psz.add(n) = 0;
    }
    n as u32 + 1
}

extern "win64" fn CertGetEnhancedKeyUsage(ctx: u64, flags: u32, usage: *mut u8, pcb_usage: *mut u32) -> i32 {
    if pcb_usage.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let Some(der) = context_der(ctx) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    let Ok(cert) = parse_cert(&der) else {
        return fail(ASN1, 0);
    };
    // CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG = 2: OSyx stores no extended cert properties.
    if flags == 2 {
        unsafe { *pcb_usage = 16 };
        return fail(CRYPT_E_NOT_FOUND, 0);
    }
    let mut oids = Vec::new();
    if let Some(ext) = cert.extensions.iter().find(|e| e.0 == OID_EKU) {
        if let Ok((seq, _)) = tlv(&ext.2) {
            for item in items(seq.body).unwrap_or_default() {
                if item.tag == OID {
                    oids.push(oid_string(item.body));
                }
            }
        }
    }
    let mut b = Block::new(16);
    b.put32(0, oids.len() as u32);
    if !oids.is_empty() {
        let arr = b.reserve(8 * oids.len());
        b.fixups.push((8, arr));
        for (i, oid) in oids.iter().enumerate() {
            let mut s = oid.clone().into_bytes();
            s.push(0);
            b.point(arr + 8 * i, &s);
        }
    }
    put_param(usage, pcb_usage, b)
}

extern "win64" fn CertFindChainInStore(
    _store: u64,
    _encoding: u32,
    _find_flags: u32,
    _find_type: u32,
    _find_para: *const u8,
    _prev_chain: u64,
) -> u64 {
    fail(CRYPT_E_NOT_FOUND, 0)
}

extern "win64" fn CryptAcquireCertificatePrivateKey(
    _cert: u64,
    _flags: u32,
    _parameters: u64,
    key: *mut u64,
    spec: *mut u32,
    caller_free: *mut i32,
) -> i32 {
    unsafe {
        if !key.is_null() {
            *key = 0;
        }
        if !spec.is_null() {
            *spec = 0;
        }
        if !caller_free.is_null() {
            *caller_free = 0;
        }
    }
    fail(CRYPT_E_NO_KEY_PROPERTY, 0)
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        CryptQueryObject,
        CryptMsgOpenToDecode,
        CryptMsgUpdate,
        CryptMsgGetParam,
        CryptMsgClose,
        CertOpenStore,
        CertCloseStore,
        CertFindCertificateInStore,
        CertDuplicateCertificateContext,
        CertFreeCertificateContext,
        CertGetNameStringW,
        CertNameToStrA,
        CertGetEnhancedKeyUsage,
        CertFindChainInStore,
        CryptAcquireCertificatePrivateKey,
        CryptBinaryToStringW,
    ]
}
