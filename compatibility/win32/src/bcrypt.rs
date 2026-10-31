//! `bcrypt.dll`: the CNG primitives OSyx can back with real code: the hash
//! functions MD5, SHA-1 and SHA-256 (plain and HMAC) and the random-number
//! generator. Other algorithms (ciphers, SHA-384/512, key exchange,
//! signatures) are refused with STATUS_NOT_SUPPORTED so a caller does not
//! mistake a missing primitive for a result.
#![allow(non_snake_case)]

use crate::capi::{Md5, Sha1};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use os_std::sync::Mutex;

type NtStatus = u32;
const STATUS_SUCCESS: NtStatus = 0;
const STATUS_UNSUCCESSFUL: NtStatus = 0xC000_0001;
const STATUS_INVALID_HANDLE: NtStatus = 0xC000_0008;
const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D;
const STATUS_NO_MEMORY: NtStatus = 0xC000_0017;
const STATUS_BUFFER_TOO_SMALL: NtStatus = 0xC000_0023;
const STATUS_NOT_SUPPORTED: NtStatus = 0xC000_00BB;
const STATUS_NOT_FOUND: NtStatus = 0xC000_0225;

const BCRYPT_ALG_HANDLE_HMAC_FLAG: u32 = 0x8;
const BCRYPT_HASH_REUSABLE_FLAG: u32 = 0x20;
const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Alg {
    Md5,
    Sha1,
    Sha256,
    Rng,
}

impl Alg {
    fn name(self) -> &'static str {
        match self {
            Alg::Md5 => "MD5",
            Alg::Sha1 => "SHA1",
            Alg::Sha256 => "SHA256",
            Alg::Rng => "RNG",
        }
    }

    fn digest_len(self) -> usize {
        match self {
            Alg::Md5 => 16,
            Alg::Sha1 => 20,
            Alg::Sha256 => 32,
            Alg::Rng => 0,
        }
    }
}

/// Algorithm identifiers Windows has that OSyx does not implement: they are
/// "not supported" rather than "not found".
const KNOWN_UNSUPPORTED: &[&str] = &[
    "SHA384", "SHA512", "MD2", "MD4", "AES", "DES", "DESX", "3DES", "3DES_112", "RC2", "RC4", "RSA", "DSA", "DH", "ECDH_P256", "ECDH_P384",
    "ECDH_P521", "ECDSA_P256", "ECDSA_P384", "ECDSA_P521", "ECDH", "ECDSA", "AES-CMAC", "AES-GMAC", "HKDF", "PBKDF2", "SP800_108_CTR_HMAC",
    "XTS-AES", "SP800_56A_CONCAT", "CAPI_KDF", "RNG", "FIPS186DSARNG", "DUALECRNG",
];

fn algorithm(name: &str) -> Result<Alg, NtStatus> {
    match name.to_ascii_uppercase().as_str() {
        "MD5" => Ok(Alg::Md5),
        "SHA1" => Ok(Alg::Sha1),
        "SHA256" => Ok(Alg::Sha256),
        // The RNG provider is real: BCryptGenRandom below.
        "RNG" => Ok(Alg::Rng),
        other if KNOWN_UNSUPPORTED.contains(&other) => Err(STATUS_NOT_SUPPORTED),
        _ => Err(STATUS_NOT_FOUND),
    }
}

enum State {
    Md5(Md5),
    Sha1(Sha1),
    Sha256(osyx_crypto::Sha256),
}

impl State {
    fn new(alg: Alg) -> State {
        match alg {
            Alg::Md5 => State::Md5(Md5::new()),
            Alg::Sha1 => State::Sha1(Sha1::new()),
            _ => State::Sha256(osyx_crypto::Sha256::new()),
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            State::Md5(s) => s.update(data),
            State::Sha1(s) => s.update(data),
            State::Sha256(s) => s.update(data),
        }
    }

    fn finish(self) -> Vec<u8> {
        match self {
            State::Md5(s) => s.finish().to_vec(),
            State::Sha1(s) => s.finish().to_vec(),
            State::Sha256(s) => s.finish().to_vec(),
        }
    }
}

/// One-shot digest.
fn digest(alg: Alg, data: &[u8]) -> Vec<u8> {
    let mut s = State::new(alg);
    s.update(data);
    s.finish()
}

/// MD5, SHA-1 and SHA-256 all work on 64-byte blocks.
const BLOCK: usize = 64;

/// The two padded keys of HMAC (RFC 2104): key xor 0x36 and key xor 0x5c.
fn hmac_pads(alg: Alg, key: &[u8]) -> ([u8; BLOCK], [u8; BLOCK]) {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let d = digest(alg, key);
        k[..d.len()].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let (mut inner, mut outer) = ([0u8; BLOCK], [0u8; BLOCK]);
    for i in 0..BLOCK {
        inner[i] = k[i] ^ 0x36;
        outer[i] = k[i] ^ 0x5c;
    }
    (inner, outer)
}

struct Provider {
    alg: Alg,
    hmac: bool,
    reusable: bool,
}

struct Hash {
    alg: Alg,
    state: State,
    /// HMAC: the outer padded key, and what the inner hash started with.
    outer: Option<[u8; BLOCK]>,
    secret: Vec<u8>,
    reusable: bool,
    /// FinishHash was called on a hash that is not reusable: only
    /// BCryptDestroyHash is still allowed.
    finished: bool,
}

enum Object {
    Provider(Provider),
    Hash(Hash),
}

static OBJECTS: Mutex<BTreeMap<u64, Object>> = Mutex::new(BTreeMap::new());
static NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x7000_0000);

fn insert(o: Object) -> u64 {
    let h = NEXT.fetch_add(4, core::sync::atomic::Ordering::Relaxed) + 4;
    OBJECTS.lock().unwrap().insert(h, o);
    h
}

fn wide(p: *const u16) -> Option<String> {
    if p.is_null() {
        return None;
    }
    // SAFETY: a NUL-terminated string.
    unsafe { crate::path::wide_to_string(p) }
}

/// `BCryptOpenAlgorithmProvider(&handle, L"SHA256", NULL, flags)`.
extern "win64" fn BCryptOpenAlgorithmProvider(out: *mut u64, id: *const u16, implementation: *const u16, flags: u32) -> NtStatus {
    if out.is_null() || id.is_null() || flags & !(BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG) != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if let Some(i) = wide(implementation) {
        if !i.eq_ignore_ascii_case("Microsoft Primitive Provider") {
            return STATUS_NOT_FOUND;
        }
    }
    let Some(name) = wide(id) else { return STATUS_INVALID_PARAMETER };
    let alg = match algorithm(&name) {
        Ok(a) => a,
        Err(e) => return e,
    };
    if alg == Alg::Rng && flags != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let h = insert(Object::Provider(Provider { alg, hmac: flags & BCRYPT_ALG_HANDLE_HMAC_FLAG != 0, reusable: flags & BCRYPT_HASH_REUSABLE_FLAG != 0 }));
    // SAFETY: the caller's out pointer.
    unsafe { *out = h };
    STATUS_SUCCESS
}

extern "win64" fn BCryptCloseAlgorithmProvider(handle: u64, flags: u32) -> NtStatus {
    if flags != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut o = OBJECTS.lock().unwrap();
    if matches!(o.get(&handle), Some(Object::Provider(_))) {
        o.remove(&handle);
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// Writes `value` to the caller's property buffer: STATUS_BUFFER_TOO_SMALL
/// with the needed size in `*result` if it does not fit.
fn property(value: &[u8], out: *mut u8, size: u32, result: *mut u32) -> NtStatus {
    if result.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's result pointer.
    unsafe { *result = value.len() as u32 };
    if out.is_null() || (size as usize) < value.len() {
        return if out.is_null() && size == 0 { STATUS_SUCCESS } else { STATUS_BUFFER_TOO_SMALL };
    }
    // SAFETY: the caller's buffer of `size` bytes.
    unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len()) };
    STATUS_SUCCESS
}

/// ObjectLength (a hash object is kept inside OSyx; the caller's buffer is
/// not used), HashDigestLength, HashBlockLength, AlgorithmName, IsReusable.
extern "win64" fn BCryptGetProperty(handle: u64, name: *const u16, out: *mut u8, size: u32, result: *mut u32, flags: u32) -> NtStatus {
    if flags != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(prop) = wide(name) else { return STATUS_INVALID_PARAMETER };
    let (alg, reusable) = match OBJECTS.lock().unwrap().get(&handle) {
        Some(Object::Provider(p)) => (p.alg, p.reusable),
        Some(Object::Hash(h)) => (h.alg, h.reusable),
        None => return STATUS_INVALID_HANDLE,
    };
    match prop.as_str() {
        "ObjectLength" => property(&16u32.to_le_bytes(), out, size, result),
        "HashDigestLength" if alg != Alg::Rng => property(&(alg.digest_len() as u32).to_le_bytes(), out, size, result),
        "HashBlockLength" if alg != Alg::Rng => property(&(BLOCK as u32).to_le_bytes(), out, size, result),
        "IsReusable" if alg != Alg::Rng => property(&u32::from(reusable).to_le_bytes(), out, size, result),
        "AlgorithmName" => {
            let units: Vec<u8> = alg.name().encode_utf16().chain(core::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect();
            property(&units, out, size, result)
        }
        _ => STATUS_NOT_SUPPORTED,
    }
}

fn start_hash(alg: Alg, hmac: bool, reusable: bool, secret: &[u8]) -> Hash {
    let mut state = State::new(alg);
    let mut outer = None;
    if hmac {
        let (inner, o) = hmac_pads(alg, secret);
        state.update(&inner);
        outer = Some(o);
    }
    Hash { alg, state, outer, secret: secret.to_vec(), reusable, finished: false }
}

fn finish(mut h: Hash) -> (Vec<u8>, Hash) {
    let alg = h.alg;
    let fresh = start_hash(alg, h.outer.is_some(), h.reusable, &h.secret);
    let inner = core::mem::replace(&mut h.state, State::new(alg)).finish();
    let out = match h.outer {
        Some(o) => {
            let mut s = State::new(alg);
            s.update(&o);
            s.update(&inner);
            s.finish()
        }
        None => inner,
    };
    (out, fresh)
}

extern "win64" fn BCryptCreateHash(provider: u64, out: *mut u64, _object: *mut u8, _object_len: u32, secret: *const u8, secret_len: u32, flags: u32) -> NtStatus {
    if out.is_null() || flags & !BCRYPT_HASH_REUSABLE_FLAG != 0 || (secret.is_null() && secret_len != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    let (alg, hmac, reusable) = match OBJECTS.lock().unwrap().get(&provider) {
        Some(Object::Provider(p)) if p.alg != Alg::Rng => (p.alg, p.hmac, p.reusable || flags & BCRYPT_HASH_REUSABLE_FLAG != 0),
        Some(Object::Provider(_)) => return STATUS_NOT_SUPPORTED,
        _ => return STATUS_INVALID_HANDLE,
    };
    // SAFETY: the caller's secret of `secret_len` bytes.
    let key = if secret_len == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(secret, secret_len as usize) } };
    let h = insert(Object::Hash(start_hash(alg, hmac, reusable, if hmac { key } else { &[] })));
    // SAFETY: the caller's out pointer.
    unsafe { *out = h };
    STATUS_SUCCESS
}

extern "win64" fn BCryptHashData(handle: u64, data: *const u8, len: u32, flags: u32) -> NtStatus {
    if flags != 0 || (data.is_null() && len != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    let mut o = OBJECTS.lock().unwrap();
    let Some(Object::Hash(h)) = o.get_mut(&handle) else { return STATUS_INVALID_HANDLE };
    if h.finished {
        return STATUS_INVALID_HANDLE;
    }
    if len != 0 {
        // SAFETY: the caller's data of `len` bytes.
        h.state.update(unsafe { core::slice::from_raw_parts(data, len as usize) });
    }
    STATUS_SUCCESS
}

/// The digest, whose size must be exactly the digest length. A hash made
/// reusable starts over afterwards; any other cannot be used again.
extern "win64" fn BCryptFinishHash(handle: u64, out: *mut u8, out_len: u32, flags: u32) -> NtStatus {
    if flags != 0 || out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let mut o = OBJECTS.lock().unwrap();
    let Some(Object::Hash(h)) = o.get(&handle) else { return STATUS_INVALID_HANDLE };
    if h.finished {
        return STATUS_INVALID_HANDLE;
    }
    if out_len as usize != h.alg.digest_len() {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(Object::Hash(h)) = o.remove(&handle) else { return STATUS_INVALID_HANDLE };
    let reusable = h.reusable;
    let (digest, mut fresh) = finish(h);
    // SAFETY: the caller's buffer of exactly the digest length.
    unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, digest.len()) };
    // The handle stays valid until BCryptDestroyHash, as on Windows; a
    // hash that is not reusable can do nothing else.
    fresh.finished = !reusable;
    o.insert(handle, Object::Hash(fresh));
    STATUS_SUCCESS
}

extern "win64" fn BCryptDestroyHash(handle: u64) -> NtStatus {
    let mut o = OBJECTS.lock().unwrap();
    if matches!(o.get(&handle), Some(Object::Hash(_))) {
        o.remove(&handle);
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// `BCryptHash`: create, hash and finish in one call (HMAC if the provider
/// was opened with the HMAC flag).
extern "win64" fn BCryptHash(provider: u64, secret: *const u8, secret_len: u32, input: *const u8, input_len: u32, out: *mut u8, out_len: u32) -> NtStatus {
    if out.is_null() || (input.is_null() && input_len != 0) || (secret.is_null() && secret_len != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    let (alg, hmac) = match OBJECTS.lock().unwrap().get(&provider) {
        Some(Object::Provider(p)) if p.alg != Alg::Rng => (p.alg, p.hmac),
        Some(Object::Provider(_)) => return STATUS_NOT_SUPPORTED,
        _ => return STATUS_INVALID_HANDLE,
    };
    if out_len as usize != alg.digest_len() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: the caller's buffers of the stated sizes.
    let (key, data) = unsafe {
        (
            if secret_len == 0 { &[][..] } else { core::slice::from_raw_parts(secret, secret_len as usize) },
            if input_len == 0 { &[][..] } else { core::slice::from_raw_parts(input, input_len as usize) },
        )
    };
    let mut h = start_hash(alg, hmac, false, if hmac { key } else { &[] });
    h.state.update(data);
    let (digest, _) = finish(h);
    // SAFETY: as above.
    unsafe { core::ptr::copy_nonoverlapping(digest.as_ptr(), out, digest.len()) };
    STATUS_SUCCESS
}

/// Random bytes from the system generator: with BCRYPT_USE_SYSTEM_PREFERRED_RNG
/// the handle must be NULL, otherwise it must be an RNG provider. If the
/// entropy device cannot be read nothing is invented: STATUS_UNSUCCESSFUL.
extern "win64" fn BCryptGenRandom(provider: u64, out: *mut u8, len: u32, flags: u32) -> NtStatus {
    if flags & !BCRYPT_USE_SYSTEM_PREFERRED_RNG != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if flags & BCRYPT_USE_SYSTEM_PREFERRED_RNG == 0 {
        match OBJECTS.lock().unwrap().get(&provider) {
            Some(Object::Provider(p)) if p.alg == Alg::Rng => {}
            _ => return STATUS_INVALID_HANDLE,
        }
    } else if provider != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if out.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if len == 0 {
        return STATUS_SUCCESS;
    }
    // SAFETY: the caller's buffer of `len` bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(out, len as usize) };
    if crate::ucrt::entropy(buf) { STATUS_SUCCESS } else { STATUS_UNSUCCESSFUL }
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        BCryptOpenAlgorithmProvider,
        BCryptCloseAlgorithmProvider,
        BCryptGetProperty,
        BCryptCreateHash,
        BCryptHashData,
        BCryptFinishHash,
        BCryptDestroyHash,
        BCryptHash,
        BCryptGenRandom,
    ]
}

#[allow(dead_code)]
const _: NtStatus = STATUS_NO_MEMORY;
