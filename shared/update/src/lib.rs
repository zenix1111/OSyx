//! OSyx system updates: what a release publishes and how a system checks it.
//!
//! A release is three files next to each other (GitHub Releases):
//!
//! * `manifest.txt`: the version and every file of the update with its
//!   size, mode and SHA-256, in payload order;
//! * `manifest.sig`: the Ed25519 signature (64 bytes) of `manifest.txt`,
//!   made with the release key whose public half is built into every
//!   system ([`PUBLIC_KEY_HEX`]);
//! * `payload.bin`: the files concatenated in manifest order.
//!
//! Manifest text:
//!
//! ```text
//! osyx-update 1
//! version 0.2.0
//! payload <sha256> <size>
//! file <sha256> <size> <mode, octal> <path>
//! ```
//!
//! Paths are relative. Those below `esp/` go to the EFI system partition
//! (the kernel and the boot loader); all others to the root file system,
//! only below [`SYSTEM_DIRS`]: an update never touches the machine's own
//! settings and data in /etc, /home and /var.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const MAGIC: &str = "osyx-update 1";
pub const MANIFEST: &str = "manifest.txt";
pub const SIGNATURE: &str = "manifest.sig";
pub const PAYLOAD: &str = "payload.bin";
/// Suffix used for files staged beside update targets.
pub const STAGED_SUFFIX: &str = ".osyx-new";

/// Preserve custom update servers while following the repository transfer.
pub fn update_url(url: &str) -> &str {
    let url = url.trim_end_matches('/');
    if url == "https://github.com/v3nn7/OSyx/releases/latest/download" {
        "https://github.com/OSyxSoftware/OSyx/releases/latest/download"
    } else {
        url
    }
}


/// Public half of the release signing key (hex), built into every system.
/// The secret half stays with whoever publishes releases, outside the
/// repository (scripts/release.ps1).
pub const PUBLIC_KEY_HEX: &str = include_str!("../release.pub");

/// Manifest paths below this go to the EFI system partition.
pub const ESP_PREFIX: &str = "esp/";
/// The boot files an update may replace on the EFI system partition.
pub const ESP_FILES: &[&str] = &["esp/EFI/OSYX/KERNEL.ELF", "esp/EFI/BOOT/BOOTX64.EFI"];
/// Parts of the root file system that belong to the system.
pub const SYSTEM_DIRS: &[&str] = &["bin/", "usr/", "system/", "Windows/", "opt/apps/", "etc/firmware/"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub version: String,
    pub payload_size: u64,
    pub payload_sha256: [u8; 32],
    pub files: Vec<Entry>,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_hex<const N: usize>(s: &str) -> Option<[u8; N]> {
    let s = s.as_bytes();
    if s.len() != 2 * N {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16);
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = (digit(s[2 * i])? * 16 + digit(s[2 * i + 1])?) as u8;
    }
    Some(out)
}

/// May an update write `path`? Relative, no `.`/`..`/empty components or
/// backslashes, and below [`SYSTEM_DIRS`] or one of [`ESP_FILES`].
pub fn allowed_path(path: &str) -> bool {
    let clean = !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(|c| c.is_control())
        && path.split('/').all(|p| !p.is_empty() && p != "." && p != "..");
    clean && (ESP_FILES.contains(&path) || SYSTEM_DIRS.iter().any(|d| path.starts_with(d) && path.len() > d.len()))
}

/// Dotted version order, numerically per part ("0.10.0" is newer than
/// "0.9.1"); missing parts count as 0. Anything that is not a dotted
/// number is never newer.
pub fn newer(candidate: &str, current: &str) -> bool {
    fn parts(v: &str) -> Option<Vec<u64>> {
        v.trim().split('.').map(|p| p.parse().ok()).collect()
    }
    let (Some(a), Some(b)) = (parts(candidate), parts(current)) else { return false };
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i).copied().unwrap_or(0), b.get(i).copied().unwrap_or(0));
        if x != y {
            return x > y;
        }
    }
    false
}

/// The version in `/etc/osyx-release` ("OSyx 0.1.0").
pub fn release_version(text: &str) -> Option<&str> {
    text.split_whitespace().last()
}

impl Manifest {
    pub fn to_text(&self) -> String {
        let mut s = format!("{MAGIC}\nversion {}\npayload {} {}\n", self.version, hex(&self.payload_sha256), self.payload_size);
        for f in &self.files {
            s.push_str(&format!("file {} {} {:o} {}\n", hex(&f.sha256), f.size, f.mode, f.path));
        }
        s
    }

    pub fn parse(text: &str) -> Result<Manifest, String> {
        let mut lines = text.lines();
        if lines.next() != Some(MAGIC) {
            return Err(String::from("not an OSyx update manifest"));
        }
        let mut version = None;
        let mut payload = None;
        let mut files: Vec<Entry> = Vec::new();
        for (n, line) in lines.enumerate() {
            let bad = || format!("manifest line {}: {line}", n + 2);
            let mut f = line.splitn(5, ' ');
            match f.next() {
                Some("version") => {
                    let v = f.next().ok_or_else(bad)?;
                    if v.split('.').any(|part| part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) || part.parse::<u64>().is_err()) {
                        return Err(bad());
                    }
                    version = Some(v.to_string());
                }
                Some("payload") => {
                    let sha = f.next().and_then(parse_hex::<32>).ok_or_else(bad)?;
                    let size = f.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
                    payload = Some((sha, size));
                }
                Some("file") => {
                    let sha256 = f.next().and_then(parse_hex::<32>).ok_or_else(bad)?;
                    let size = f.next().and_then(|s| s.parse().ok()).ok_or_else(bad)?;
                    let mode = f.next().and_then(|s| u32::from_str_radix(s, 8).ok()).filter(|m| *m <= 0o777).ok_or_else(bad)?;
                    let path = f.next().ok_or_else(bad)?;
                    if !allowed_path(path) {
                        return Err(format!("manifest line {}: an update may not write {path}", n + 2));
                    }
                    if files.iter().any(|e| e.path == path) {
                        return Err(format!("manifest line {}: {path} listed twice", n + 2));
                    }
                    if files.iter().any(|e| e.path.strip_suffix(STAGED_SUFFIX) == Some(path) || path.strip_suffix(STAGED_SUFFIX) == Some(e.path.as_str())) {
                        return Err(format!("manifest line {}: {path} conflicts with a staged file", n + 2));
                    }
                    files.push(Entry { path: path.to_string(), size, mode, sha256 });
                }
                Some("") if line.is_empty() => {}
                _ => return Err(bad()),
            }
        }
        let version = version.ok_or("manifest without a version")?;
        let (payload_sha256, payload_size) = payload.ok_or("manifest without a payload")?;
        if files.iter().try_fold(0u64, |sum, f| sum.checked_add(f.size)) != Some(payload_size) {
            return Err(String::from("the files do not add up to the payload size"));
        }
        Ok(Manifest { version, payload_size, payload_sha256, files })
    }
}

/// The built-in release key.
pub fn public_key() -> Option<[u8; 32]> {
    parse_hex(PUBLIC_KEY_HEX.trim())
}

/// Does `signature` (64 bytes) sign `manifest` with `key`? Strict Ed25519
/// verification (RFC 8032, no malleable signatures or weak keys).
pub fn verify(manifest: &[u8], signature: &[u8], key: &[u8; 32]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(signature) else { return false };
    let Ok(key) = VerifyingKey::from_bytes(key) else { return false };
    key.verify_strict(manifest, &Signature::from_bytes(&sig)).is_ok()
}

/// Signs `manifest` with the 32-byte Ed25519 secret key (release tool).
pub fn sign(manifest: &[u8], secret: &[u8; 32]) -> [u8; 64] {
    SigningKey::from_bytes(secret).sign(manifest).to_bytes()
}

pub fn public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(secret).verifying_key().to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn entry(path: &str, size: u64) -> Entry {
        Entry { path: path.to_string(), size, mode: 0o755, sha256: [7; 32] }
    }

    #[test]
    fn rfc8032_test_vector_1() {
        let secret = parse_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let public = parse_hex::<32>("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        let expected = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b";
        assert_eq!(public_from_secret(&secret), public);
        let sig = sign(b"", &secret);
        assert_eq!(hex(&sig), expected);
        assert!(verify(b"", &sig, &public));
        assert!(!verify(b"x", &sig, &public));
        let mut bad = sig;
        bad[10] ^= 1;
        assert!(!verify(b"", &bad, &public));
        assert!(!verify(b"", &sig[..63], &public));
    }

    #[test]
    fn manifest_round_trip_and_checks() {
        let m = Manifest {
            version: "0.2.0".to_string(),
            payload_size: 30,
            payload_sha256: [1; 32],
            files: vec![entry("bin/init", 10), entry("esp/EFI/OSYX/KERNEL.ELF", 20)],
        };
        assert_eq!(Manifest::parse(&m.to_text()).unwrap(), m);
        let short = m.to_text().replace(" 30\n", " 31\n");
        assert!(Manifest::parse(&short).is_err(), "sizes must add up");
        let evil = m.to_text().replace("bin/init", "etc/shadow");
        assert!(Manifest::parse(&evil).is_err());
        assert!(Manifest::parse("osyx-update 2\nversion 1\n").is_err());
    }

    #[test]
    fn manifest_rejects_overflowing_file_sizes() {
        let m = Manifest {
            version: "1.0".to_string(),
            payload_size: 0,
            payload_sha256: [0; 32],
            files: vec![entry("bin/a", u64::MAX), entry("bin/b", 1)],
        };
        assert!(Manifest::parse(&m.to_text()).is_err());
    }

    #[test]
    fn manifest_rejects_staging_path_collisions_in_either_order() {
        for files in [vec![entry("bin/a", 1), entry("bin/a.osyx-new", 1)], vec![entry("bin/a.osyx-new", 1), entry("bin/a", 1)]] {
            let manifest = Manifest { version: "1.0".to_string(), payload_size: 2, payload_sha256: [0; 32], files };
            assert!(Manifest::parse(&manifest.to_text()).is_err());
        }
        let manifest = Manifest { version: "1.0".to_string(), payload_size: 2, payload_sha256: [0; 32], files: vec![entry("bin/a", 1), entry("bin/b.osyx-new", 1)] };
        assert!(Manifest::parse(&manifest.to_text()).is_ok());
    }

    #[test]
    fn manifest_rejects_invalid_version_components() {
        let manifest = Manifest { version: "1.2".to_string(), payload_size: 0, payload_sha256: [0; 32], files: vec![] };
        assert!(Manifest::parse(&manifest.to_text()).is_ok());
        for version in [".", ".1", "1.", "1..2", "1.18446744073709551616"] {
            let mut malformed = manifest.clone();
            malformed.version = version.to_string();
            assert!(Manifest::parse(&malformed.to_text()).is_err(), "{version}");
        }
    }

    #[test]
    fn paths() {
        for ok in ["bin/axis", "system/bin/desktop", "Windows/Fonts/Lato.ttf", "esp/EFI/BOOT/BOOTX64.EFI", "etc/firmware/iwm-9260-46"] {
            assert!(allowed_path(ok), "{ok}");
        }
        for bad in ["etc/passwd", "/bin/x", "bin/../etc/shadow", "bin//x", "bin/", "bin", "home/user/a", "esp/EFI/OSYX/CMDLINE.TXT", "opt/zen/zen.exe", "bin\\x"] {
            assert!(!allowed_path(bad), "{bad}");
        }
    }

    #[test]
    fn version_order() {
        assert!(newer("0.2.0", "0.1.0"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(newer("1.0.1", "1.0"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.1", "0.1.0"));
        assert!(!newer("0.1.0", "0.2.0"));
        assert!(!newer("x", "0.1.0"));
        assert_eq!(release_version("OSyx 0.1.0\n"), Some("0.1.0"));
    }
}

#[cfg(test)]
mod update_url_tests {
    #[test]
    fn migrates_only_the_old_official_url() {
        let new = "https://github.com/OSyxSoftware/OSyx/releases/latest/download";
        assert_eq!(super::update_url("https://github.com/v3nn7/OSyx/releases/latest/download/"), new);
        assert_eq!(super::update_url(new), new);
        assert_eq!(super::update_url("https://example.org/releases/"), "https://example.org/releases");
    }
}
