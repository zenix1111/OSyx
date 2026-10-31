//! WPA2-Personal (RSN with PSK and CCMP) for a station: the key hierarchy
//! and the EAPOL-Key 4-way and group key handshakes (IEEE 802.11-2016
//! 12.7). The driver hands every received EAPOL frame to [`Supplicant`]
//! and sends the frames it returns; the keys it reports go to the chip,
//! which does the CCMP encryption itself.

use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes128;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

/// EAPOL packet type "Key".
pub const EAPOL_KEY: u8 = 3;
/// EAPOL-Key descriptor type for RSN.
pub const DESC_RSN: u8 = 2;

pub mod info {
    /// Descriptor version 2: HMAC-SHA1-128 MIC, AES key wrap.
    pub const VERSION_AES: u16 = 2;
    pub const VERSION_MASK: u16 = 7;
    pub const PAIRWISE: u16 = 1 << 3;
    pub const INSTALL: u16 = 1 << 6;
    pub const ACK: u16 = 1 << 7;
    pub const MIC: u16 = 1 << 8;
    pub const SECURE: u16 = 1 << 9;
    pub const ERROR: u16 = 1 << 10;
    pub const REQUEST: u16 = 1 << 11;
    pub const ENCRYPTED: u16 = 1 << 12;
}

/// Offsets in an EAPOL frame (4-byte 802.1X header included).
const HDR: usize = 4;
const OFF_INFO: usize = HDR + 1;
const OFF_KEYLEN: usize = HDR + 3;
const OFF_REPLAY: usize = HDR + 5;
const OFF_NONCE: usize = HDR + 13;
const OFF_MIC: usize = HDR + 77;
const OFF_DATALEN: usize = HDR + 93;
const OFF_DATA: usize = HDR + 95;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WpaError {
    /// Not an RSN EAPOL-Key frame, or truncated.
    Malformed,
    /// Descriptor version other than 2 (TKIP-only or newer AKMs).
    Unsupported,
    /// Replay counter not newer than the last accepted one.
    Replay,
    /// MIC wrong: most often a wrong passphrase.
    BadMic,
    /// Message 3 carried another ANonce than message 1.
    NonceMismatch,
    /// AES key unwrap integrity check failed.
    BadKeyData,
    /// No GTK in the key data of message 3 / group message 1.
    NoGroupKey,
    /// A message out of order (e.g. message 3 before message 1).
    UnexpectedMessage,
}

/// PMK from a passphrase (8..=63 characters) and SSID (802.11 J.4).
pub fn pmk_from_passphrase(passphrase: &str, ssid: &[u8]) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha1>(passphrase.as_bytes(), ssid, 4096, &mut pmk);
    pmk
}

fn hmac_sha1(key: &[u8], parts: &[&[u8]]) -> [u8; 20] {
    let mut m = <HmacSha1 as hmac::digest::KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// PRF-X of 802.11 12.7.1.2 (HMAC-SHA1), filling `out`.
pub fn prf(key: &[u8], label: &[u8], data: &[u8], out: &mut [u8]) {
    let mut done = 0;
    let mut i = 0u8;
    while done < out.len() {
        let block = hmac_sha1(key, &[label, &[0], data, &[i]]);
        let n = (out.len() - done).min(20);
        out[done..done + n].copy_from_slice(&block[..n]);
        done += n;
        i += 1;
    }
}

/// Pairwise transient key for CCMP: key confirmation, key encryption and
/// temporal key, 16 bytes each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ptk {
    pub kck: [u8; 16],
    pub kek: [u8; 16],
    pub tk: [u8; 16],
}

pub fn derive_ptk(pmk: &[u8; 32], aa: &[u8; 6], spa: &[u8; 6], anonce: &[u8; 32], snonce: &[u8; 32]) -> Ptk {
    let mut data = [0u8; 76];
    let (lo, hi) = if aa <= spa { (aa, spa) } else { (spa, aa) };
    data[..6].copy_from_slice(lo);
    data[6..12].copy_from_slice(hi);
    let (lo, hi) = if anonce <= snonce { (anonce, snonce) } else { (snonce, anonce) };
    data[12..44].copy_from_slice(lo);
    data[44..76].copy_from_slice(hi);
    let mut k = [0u8; 48];
    prf(pmk, b"Pairwise key expansion", &data, &mut k);
    let mut ptk = Ptk { kck: [0; 16], kek: [0; 16], tk: [0; 16] };
    ptk.kck.copy_from_slice(&k[..16]);
    ptk.kek.copy_from_slice(&k[16..32]);
    ptk.tk.copy_from_slice(&k[32..48]);
    ptk
}

const KW_IV: u64 = 0xA6A6_A6A6_A6A6_A6A6;

/// AES key wrap (RFC 3394) of `plain` (a multiple of 8 bytes, at least 16).
pub fn aes_wrap(kek: &[u8; 16], plain: &[u8]) -> Option<Vec<u8>> {
    if plain.len() < 16 || plain.len() % 8 != 0 {
        return None;
    }
    let c = Aes128::new(kek.into());
    let n = plain.len() / 8;
    let mut a = KW_IV;
    let mut r: Vec<u64> = plain.chunks(8).map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes"))).collect();
    for j in 0..6u64 {
        for i in 0..n {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a.to_be_bytes());
            b[8..].copy_from_slice(&r[i].to_be_bytes());
            let mut blk = b.into();
            c.encrypt_block(&mut blk);
            let t = n as u64 * j + i as u64 + 1;
            a = u64::from_be_bytes(blk[..8].try_into().expect("8 bytes")) ^ t;
            r[i] = u64::from_be_bytes(blk[8..].try_into().expect("8 bytes"));
        }
    }
    let mut out = Vec::with_capacity(plain.len() + 8);
    out.extend_from_slice(&a.to_be_bytes());
    for x in r {
        out.extend_from_slice(&x.to_be_bytes());
    }
    Some(out)
}

/// AES key unwrap (RFC 3394); `None` if the integrity check fails.
pub fn aes_unwrap(kek: &[u8; 16], wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
        return None;
    }
    let c = Aes128::new(kek.into());
    let n = wrapped.len() / 8 - 1;
    let mut a = u64::from_be_bytes(wrapped[..8].try_into().ok()?);
    let mut r: Vec<u64> = wrapped[8..].chunks(8).map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes"))).collect();
    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = n as u64 * j + i as u64 + 1;
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&(a ^ t).to_be_bytes());
            b[8..].copy_from_slice(&r[i].to_be_bytes());
            let mut blk = b.into();
            c.decrypt_block(&mut blk);
            a = u64::from_be_bytes(blk[..8].try_into().ok()?);
            r[i] = u64::from_be_bytes(blk[8..].try_into().ok()?);
        }
    }
    if a != KW_IV {
        return None;
    }
    let mut out = Vec::with_capacity(n * 8);
    for x in r {
        out.extend_from_slice(&x.to_be_bytes());
    }
    Some(out)
}

/// Cipher suite selectors (00-0F-AC-x).
pub mod suite {
    pub const TKIP: u8 = 2;
    pub const CCMP: u8 = 4;
    pub const AKM_PSK: u8 = 2;
}

/// The station's RSN element for WPA2-PSK with CCMP as pairwise cipher and
/// the AP's group cipher (`suite::CCMP` or `suite::TKIP`).
pub fn rsn_ie_psk(group_cipher: u8) -> Vec<u8> {
    alloc::vec![
        0x30, 0x14, 0x01, 0x00, // element id, length, version 1
        0x00, 0x0f, 0xac, group_cipher, // group cipher
        0x01, 0x00, 0x00, 0x0f, 0xac, suite::CCMP, // one pairwise cipher
        0x01, 0x00, 0x00, 0x0f, 0xac, suite::AKM_PSK, // one AKM
        0x00, 0x00, // capabilities
    ]
}

/// A group temporal key from the key data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gtk {
    pub key_id: u8,
    pub key: Vec<u8>,
}

/// Finds the GTK KDE (DD len 00-0F-AC 01) in decrypted key data.
pub fn find_gtk(data: &[u8]) -> Option<Gtk> {
    let mut i = 0;
    while i + 2 <= data.len() {
        let (id, len) = (data[i], data[i + 1] as usize);
        if id == 0xdd && len == 0 {
            break; // padding
        }
        let body = data.get(i + 2..i + 2 + len)?;
        if id == 0xdd && len >= 6 && body[..4] == [0x00, 0x0f, 0xac, 0x01] {
            return Some(Gtk { key_id: body[4] & 3, key: body[6..].to_vec() });
        }
        i += 2 + len;
    }
    None
}

/// The fields of a received EAPOL-Key frame the station needs.
struct KeyFrame<'a> {
    info: u16,
    replay: u64,
    nonce: [u8; 32],
    data: &'a [u8],
}

fn parse(frame: &[u8]) -> Result<KeyFrame<'_>, WpaError> {
    if frame.len() < OFF_DATA || frame[1] != EAPOL_KEY || frame[HDR] != DESC_RSN {
        return Err(WpaError::Malformed);
    }
    let body_len = u16::from_be_bytes([frame[2], frame[3]]) as usize;
    let frame = frame.get(..HDR + body_len).ok_or(WpaError::Malformed)?;
    let info = u16::from_be_bytes([frame[OFF_INFO], frame[OFF_INFO + 1]]);
    if info & info::VERSION_MASK != info::VERSION_AES {
        return Err(WpaError::Unsupported);
    }
    let replay = u64::from_be_bytes(frame[OFF_REPLAY..OFF_REPLAY + 8].try_into().expect("8 bytes"));
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&frame[OFF_NONCE..OFF_NONCE + 32]);
    let data_len = u16::from_be_bytes([frame[OFF_DATALEN], frame[OFF_DATALEN + 1]]) as usize;
    let data = frame.get(OFF_DATA..OFF_DATA + data_len).ok_or(WpaError::Malformed)?;
    Ok(KeyFrame { info, replay, nonce, data })
}

/// HMAC-SHA1-128 over the frame with its MIC field zeroed.
pub fn mic(kck: &[u8; 16], frame: &[u8]) -> [u8; 16] {
    let mut copy = frame.to_vec();
    copy[OFF_MIC..OFF_MIC + 16].fill(0);
    let full = hmac_sha1(kck, &[&copy]);
    let mut m = [0u8; 16];
    m.copy_from_slice(&full[..16]);
    m
}

fn check_mic(kck: &[u8; 16], frame: &[u8]) -> bool {
    let want = mic(kck, frame);
    // Constant time: the MIC check must not leak how many bytes matched.
    want.iter().zip(&frame[OFF_MIC..OFF_MIC + 16]).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// Builds an EAPOL-Key frame (802.1X version 2) and signs it with `kck`.
pub fn build(info: u16, key_len: u16, replay: u64, nonce: &[u8; 32], data: &[u8], kck: Option<&[u8; 16]>) -> Vec<u8> {
    let body = 95 + data.len();
    let mut f = alloc::vec![0u8; HDR + body];
    f[0] = 2;
    f[1] = EAPOL_KEY;
    f[2..4].copy_from_slice(&(body as u16).to_be_bytes());
    f[HDR] = DESC_RSN;
    f[OFF_INFO..OFF_INFO + 2].copy_from_slice(&info.to_be_bytes());
    f[OFF_KEYLEN..OFF_KEYLEN + 2].copy_from_slice(&key_len.to_be_bytes());
    f[OFF_REPLAY..OFF_REPLAY + 8].copy_from_slice(&replay.to_be_bytes());
    f[OFF_NONCE..OFF_NONCE + 32].copy_from_slice(nonce);
    f[OFF_DATALEN..OFF_DATALEN + 2].copy_from_slice(&(data.len() as u16).to_be_bytes());
    f[OFF_DATA..].copy_from_slice(data);
    if let Some(kck) = kck {
        let m = mic(kck, &f);
        f[OFF_MIC..OFF_MIC + 16].copy_from_slice(&m);
    }
    f
}

/// What the driver must do after a frame was processed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send this EAPOL frame to the AP (EtherType 0x888E).
    Send(Vec<u8>),
    /// Install the pairwise temporal key (CCMP, 16 bytes).
    InstallPairwise([u8; 16]),
    /// Install a group key.
    InstallGroup(Gtk),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Waiting for message 1.
    Start,
    /// Message 2 sent, waiting for message 3.
    WaitMsg3,
    /// Keys installed: the link is usable.
    Done,
}

/// The station side of WPA2-PSK for one association.
pub struct Supplicant {
    pmk: [u8; 32],
    aa: [u8; 6],
    spa: [u8; 6],
    rsn_ie: Vec<u8>,
    snonce: [u8; 32],
    anonce: Option<[u8; 32]>,
    ptk: Option<Ptk>,
    replay: Option<u64>,
    pub state: State,
}

impl Supplicant {
    /// `aa`: the AP's MAC, `spa`: ours, `rsn_ie`: the RSN element sent in
    /// the association request, `snonce`: 32 fresh random bytes.
    pub fn new(pmk: [u8; 32], aa: [u8; 6], spa: [u8; 6], rsn_ie: Vec<u8>, snonce: [u8; 32]) -> Supplicant {
        Supplicant { pmk, aa, spa, rsn_ie, snonce, anonce: None, ptk: None, replay: None, state: State::Start }
    }

    fn accept_replay(&mut self, r: u64) -> Result<(), WpaError> {
        if self.replay.is_some_and(|last| r <= last) {
            return Err(WpaError::Replay);
        }
        Ok(())
    }

    /// Processes one received EAPOL frame (802.1X header first).
    pub fn receive(&mut self, frame: &[u8]) -> Result<Vec<Action>, WpaError> {
        let k = parse(frame)?;
        let pairwise = k.info & info::PAIRWISE != 0;
        let has_mic = k.info & info::MIC != 0;
        if k.info & info::ACK == 0 {
            return Err(WpaError::UnexpectedMessage);
        }
        match (pairwise, has_mic) {
            // Message 1: no MIC yet (the AP cannot compute one before message 2).
            (true, false) => {
                self.accept_replay(k.replay)?;
                let ptk = derive_ptk(&self.pmk, &self.aa, &self.spa, &k.nonce, &self.snonce);
                self.anonce = Some(k.nonce);
                self.ptk = Some(ptk);
                self.state = State::WaitMsg3;
                let msg2 = build(info::VERSION_AES | info::PAIRWISE | info::MIC, 0, k.replay, &self.snonce, &self.rsn_ie, Some(&ptk.kck));
                Ok(alloc::vec![Action::Send(msg2)])
            }
            // Message 3.
            (true, true) => {
                let ptk = self.ptk.ok_or(WpaError::UnexpectedMessage)?;
                if !check_mic(&ptk.kck, &frame[..HDR + u16::from_be_bytes([frame[2], frame[3]]) as usize]) {
                    return Err(WpaError::BadMic);
                }
                self.accept_replay(k.replay)?;
                if self.anonce != Some(k.nonce) {
                    return Err(WpaError::NonceMismatch);
                }
                let data = if k.info & info::ENCRYPTED != 0 {
                    aes_unwrap(&ptk.kek, k.data).ok_or(WpaError::BadKeyData)?
                } else {
                    k.data.to_vec()
                };
                let gtk = find_gtk(&data).ok_or(WpaError::NoGroupKey)?;
                self.replay = Some(k.replay);
                let msg4 = build(info::VERSION_AES | info::PAIRWISE | info::MIC | info::SECURE, 0, k.replay, &[0; 32], &[], Some(&ptk.kck));
                self.state = State::Done;
                Ok(alloc::vec![Action::Send(msg4), Action::InstallPairwise(ptk.tk), Action::InstallGroup(gtk)])
            }
            // Group key handshake message 1 (rekeying).
            (false, true) => {
                let ptk = self.ptk.filter(|_| self.state == State::Done).ok_or(WpaError::UnexpectedMessage)?;
                if !check_mic(&ptk.kck, &frame[..HDR + u16::from_be_bytes([frame[2], frame[3]]) as usize]) {
                    return Err(WpaError::BadMic);
                }
                self.accept_replay(k.replay)?;
                let data = aes_unwrap(&ptk.kek, k.data).ok_or(WpaError::BadKeyData)?;
                let gtk = find_gtk(&data).ok_or(WpaError::NoGroupKey)?;
                self.replay = Some(k.replay);
                let reply = build(info::VERSION_AES | info::MIC | info::SECURE, 0, k.replay, &[0; 32], &[], Some(&ptk.kck));
                Ok(alloc::vec![Action::Send(reply), Action::InstallGroup(gtk)])
            }
            (false, false) => Err(WpaError::UnexpectedMessage),
        }
    }
}
