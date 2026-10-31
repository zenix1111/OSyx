//! CryptoAPI hashing (advapi32): verify-only provider contexts and hash
//! objects for MD5, SHA-1 and SHA-256. Key containers do not exist, so a
//! context that names one fails with NTE_BAD_KEYSET and there is no key
//! to sign with (NTE_NO_KEY). Errors are the NTE_* codes Windows sets.
#![allow(non_snake_case)]
use crate::{kernel32::fail, path};
use alloc::{collections::BTreeMap, vec::Vec};
use os_std::sync::Mutex;

const NTE_BAD_HASH: u32 = 0x8009_0002;
const NTE_BAD_ALGID: u32 = 0x8009_0008;
const NTE_BAD_FLAGS: u32 = 0x8009_0009;
const NTE_BAD_TYPE: u32 = 0x8009_000A;
const NTE_NO_KEY: u32 = 0x8009_000D;
const NTE_BAD_HASH_STATE: u32 = 0x8009_000C;
const NTE_BAD_UID: u32 = 0x8009_0001;
const NTE_BAD_KEYSET: u32 = 0x8009_0016;
const ERROR_MORE_DATA: u32 = 234;
const ERROR_INVALID_PARAMETER: u32 = 87;

const CRYPT_VERIFYCONTEXT: u32 = 0xF000_0000;
const CRYPT_SILENT: u32 = 0x40;
const CALG_MD5: u32 = 0x8003;
const CALG_SHA1: u32 = 0x8004;
const CALG_SHA_256: u32 = 0x800C;
const HP_ALGID: u32 = 1;
const HP_HASHVAL: u32 = 2;
const HP_HASHSIZE: u32 = 4;

#[derive(Clone)]
enum State {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(osyx_crypto::Sha256),
}

struct Hash {
    alg: u32,
    state: State,
    /// Set once the value was read: no more data may be hashed.
    done: Option<Vec<u8>>,
}

static CONTEXTS: Mutex<BTreeMap<u64, u32>> = Mutex::new(BTreeMap::new());
static HASHES: Mutex<BTreeMap<u64, Hash>> = Mutex::new(BTreeMap::new());
static NEXT: Mutex<u64> = Mutex::new(0x6c00_0004);

fn next() -> u64 {
    let mut n = NEXT.lock().unwrap();
    let h = *n;
    *n += 4;
    h
}

/// Provider types 1 (PROV_RSA_FULL), 12 (PROV_RSA_SCHANNEL) and 24
/// (PROV_RSA_AES) hash with these algorithms; the provider name is not
/// checked against Microsoft's (they all share the algorithms used here).
extern "win64" fn CryptAcquireContextW(out: *mut u64, container: *const u16, _provider: *const u16, kind: u32, flags: u32) -> i32 {
    if out.is_null() || flags & !(CRYPT_VERIFYCONTEXT | CRYPT_SILENT | 0x8 | 0x10 | 0x20) != 0 {
        return fail(NTE_BAD_FLAGS, 0);
    }
    if ![1, 12, 24].contains(&kind) {
        return fail(NTE_BAD_TYPE, 0);
    }
    // SAFETY: NULL or a NUL-terminated name.
    let named = unsafe { path::wide_to_string(container) }.is_some_and(|c| !c.is_empty());
    if flags & CRYPT_VERIFYCONTEXT == 0 || named {
        return fail(NTE_BAD_KEYSET, 0); // no key containers
    }
    let h = next();
    CONTEXTS.lock().unwrap().insert(h, kind);
    // SAFETY: the caller's out pointer.
    unsafe { *out = h };
    1
}

extern "win64" fn CryptReleaseContext(h: u64, flags: u32) -> i32 {
    if flags != 0 {
        return fail(NTE_BAD_FLAGS, 0);
    }
    if CONTEXTS.lock().unwrap().remove(&h).is_none() {
        return fail(NTE_BAD_UID, 0);
    }
    1
}

extern "win64" fn CryptCreateHash(prov: u64, alg: u32, key: u64, flags: u32, out: *mut u64) -> i32 {
    if !CONTEXTS.lock().unwrap().contains_key(&prov) {
        return fail(NTE_BAD_UID, 0);
    }
    if key != 0 {
        return fail(NTE_NO_KEY, 0); // keyed (MAC) hashes need a key
    }
    if flags != 0 || out.is_null() {
        return fail(NTE_BAD_FLAGS, 0);
    }
    let state = match alg {
        CALG_MD5 => State::Md5(Md5::new()),
        CALG_SHA1 => State::Sha1(Sha1::new()),
        CALG_SHA_256 => State::Sha256(osyx_crypto::Sha256::new()),
        _ => return fail(NTE_BAD_ALGID, 0),
    };
    let h = next();
    HASHES.lock().unwrap().insert(h, Hash { alg, state, done: None });
    // SAFETY: the caller's out pointer.
    unsafe { *out = h };
    1
}

extern "win64" fn CryptHashData(h: u64, data: *const u8, len: u32, flags: u32) -> i32 {
    if flags & !1 != 0 {
        return fail(NTE_BAD_FLAGS, 0); // CRYPT_USERDATA only
    }
    let mut all = HASHES.lock().unwrap();
    let Some(hash) = all.get_mut(&h) else { return fail(NTE_BAD_HASH, 0) };
    if hash.done.is_some() {
        return fail(NTE_BAD_HASH_STATE, 0);
    }
    if len == 0 {
        return 1;
    }
    if data.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: the caller's `len` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(data, len as usize) };
    match &mut hash.state {
        State::Md5(s) => s.update(bytes),
        State::Sha1(s) => s.update(bytes),
        State::Sha256(s) => s.update(bytes),
    }
    1
}

fn value(hash: &mut Hash) -> Vec<u8> {
    if hash.done.is_none() {
        let v = match hash.state.clone() {
            State::Md5(s) => s.finish().to_vec(),
            State::Sha1(s) => s.finish().to_vec(),
            State::Sha256(s) => s.finish().to_vec(),
        };
        hash.done = Some(v);
    }
    hash.done.clone().unwrap_or_default()
}

extern "win64" fn CryptGetHashParam(h: u64, param: u32, buf: *mut u8, len: *mut u32, flags: u32) -> i32 {
    if flags != 0 || len.is_null() {
        return fail(NTE_BAD_FLAGS, 0);
    }
    let mut all = HASHES.lock().unwrap();
    let Some(hash) = all.get_mut(&h) else { return fail(NTE_BAD_HASH, 0) };
    let size = match hash.alg {
        CALG_MD5 => 16u32,
        CALG_SHA1 => 20,
        _ => 32,
    };
    let out: Vec<u8> = match param {
        HP_ALGID => hash.alg.to_le_bytes().to_vec(),
        HP_HASHSIZE => size.to_le_bytes().to_vec(),
        HP_HASHVAL => {
            if buf.is_null() {
                // A size query does not finish the hash.
                // SAFETY: the caller's out length.
                unsafe { *len = size };
                return 1;
            }
            value(hash)
        }
        _ => return fail(NTE_BAD_TYPE, 0),
    };
    // SAFETY: the caller's in/out length and buffer of that size.
    unsafe {
        if buf.is_null() {
            *len = out.len() as u32;
            return 1;
        }
        if (*len as usize) < out.len() {
            *len = out.len() as u32;
            return fail(ERROR_MORE_DATA, 0);
        }
        core::ptr::copy_nonoverlapping(out.as_ptr(), buf, out.len());
        *len = out.len() as u32;
    }
    1
}

/// HP_HASHVAL sets a finished value (to be signed); nothing else is
/// settable for these hashes.
extern "win64" fn CryptSetHashParam(h: u64, param: u32, data: *const u8, flags: u32) -> i32 {
    if flags != 0 {
        return fail(NTE_BAD_FLAGS, 0);
    }
    let mut all = HASHES.lock().unwrap();
    let Some(hash) = all.get_mut(&h) else { return fail(NTE_BAD_HASH, 0) };
    if param != HP_HASHVAL || data.is_null() {
        return fail(NTE_BAD_TYPE, 0);
    }
    let size = match hash.alg {
        CALG_MD5 => 16,
        CALG_SHA1 => 20,
        _ => 32,
    };
    // SAFETY: the caller's hash-sized value.
    hash.done = Some(unsafe { core::slice::from_raw_parts(data, size) }.to_vec());
    1
}

extern "win64" fn CryptDestroyHash(h: u64) -> i32 {
    if HASHES.lock().unwrap().remove(&h).is_none() {
        return fail(NTE_BAD_HASH, 0);
    }
    1
}

/// Signing needs a key pair in a key container; there are none.
extern "win64" fn CryptSignHashW(h: u64, _spec: u32, _desc: *const u16, _flags: u32, _sig: *mut u8, _len: *mut u32) -> i32 {
    if !HASHES.lock().unwrap().contains_key(&h) {
        return fail(NTE_BAD_HASH, 0);
    }
    fail(NTE_NO_KEY, 0)
}

// ---- MD5 (RFC 1321) and SHA-1 (FIPS 180-4) ---------------------------------------------

/// The common Merkle-Damgard buffering of 64-byte blocks.
#[derive(Clone)]
struct Blocks {
    buf: [u8; 64],
    used: usize,
    total: u64,
}

impl Blocks {
    fn new() -> Blocks {
        Blocks { buf: [0; 64], used: 0, total: 0 }
    }

    fn update(&mut self, mut data: &[u8], mut block: impl FnMut(&[u8; 64])) {
        self.total += data.len() as u64;
        while !data.is_empty() {
            let n = (64 - self.used).min(data.len());
            self.buf[self.used..self.used + n].copy_from_slice(&data[..n]);
            self.used += n;
            data = &data[n..];
            if self.used == 64 {
                block(&self.buf);
                self.used = 0;
            }
        }
    }

    /// Pads with 0x80, zeros and the bit length (`big` endian or little).
    fn finish(mut self, big: bool, mut block: impl FnMut(&[u8; 64])) {
        let bits = self.total.wrapping_mul(8);
        let mut pad = alloc::vec![0x80u8];
        pad.resize(if self.used < 56 { 56 - self.used } else { 120 - self.used }, 0);
        pad.extend_from_slice(&if big { bits.to_be_bytes() } else { bits.to_le_bytes() });
        let total = self.total;
        self.update(&pad, &mut block);
        self.total = total;
    }
}

#[derive(Clone)]
pub(crate) struct Md5 {
    s: [u32; 4],
    b: Blocks,
}

impl Md5 {
    pub(crate) fn new() -> Md5 {
        Md5 { s: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476], b: Blocks::new() }
    }

    fn block(s: &mut [u32; 4], m: &[u8; 64]) {
        const R: [u32; 16] = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
        let w: Vec<u32> = m.chunks(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
        let [mut a, mut b, mut c, mut d] = *s;
        for i in 0..64 {
            let (f, g) = match i / 16 {
                0 => ((b & c) | (!b & d), i),
                1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
                2 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | !d), (7 * i) % 16),
            };
            // K[i] = floor(abs(sin(i + 1)) * 2^32), precomputed.
            let k = MD5_K[i];
            let t = d;
            d = c;
            c = b;
            b = b.wrapping_add(a.wrapping_add(f).wrapping_add(k).wrapping_add(w[g]).rotate_left(R[(i / 16) * 4 + i % 4]));
            a = t;
        }
        for (x, y) in s.iter_mut().zip([a, b, c, d]) {
            *x = x.wrapping_add(y);
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let s = &mut self.s;
        self.b.update(data, |m| Md5::block(s, m));
    }

    pub(crate) fn finish(mut self) -> [u8; 16] {
        let s = &mut self.s;
        self.b.finish(false, |m| Md5::block(s, m));
        let mut out = [0u8; 16];
        for (i, v) in self.s.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }
}

const MD5_K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
    0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
    0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[derive(Clone)]
pub(crate) struct Sha1 {
    s: [u32; 5],
    b: Blocks,
}

impl Sha1 {
    pub(crate) fn new() -> Sha1 {
        Sha1 { s: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0], b: Blocks::new() }
    }

    fn block(s: &mut [u32; 5], m: &[u8; 64]) {
        let mut w = [0u32; 80];
        for (i, c) in m.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = *s;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i / 20 {
                0 => ((b & c) | (!b & d), 0x5A82_7999),
                1 => (b ^ c ^ d, 0x6ED9_EBA1),
                2 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in s.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }

    pub(crate) fn update(&mut self, data: &[u8]) {
        let s = &mut self.s;
        self.b.update(data, |m| Sha1::block(s, m));
    }

    pub(crate) fn finish(mut self) -> [u8; 20] {
        let s = &mut self.s;
        self.b.finish(true, |m| Sha1::block(s, m));
        let mut out = [0u8; 20];
        for (i, v) in self.s.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        out
    }
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        CryptAcquireContextW,
        CryptReleaseContext,
        CryptCreateHash,
        CryptHashData,
        CryptGetHashParam,
        CryptSetHashParam,
        CryptDestroyHash,
        CryptSignHashW,
    ]
}
