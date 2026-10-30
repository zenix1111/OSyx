//! Release tool for OSyx system updates (runs on the build host).
//!
//! cargo run -p osyx-update --example release -- keygen <secret key file> <public key file>
//! cargo run -p osyx-update --example release -- build <rootfs.tar> <version> <secret key file> <output dir>
//!
//! `keygen` makes the Ed25519 release key: the secret half (hex) must stay
//! private and outside the repository; the public half goes to
//! shared/update/release.pub and is built into every system.
//!
//! `build` reads the system tree a live build installs (a ustar archive
//! from scripts/mkrootfs.sh ... tar), keeps the files an update may write
//! (osyx_update::allowed_path; the installer's boot files become `esp/`),
//! and writes manifest.txt, manifest.sig and payload.bin.

use osyx_update::{allowed_path, hex, parse_hex, public_from_secret, public_key, sign, Entry, Manifest};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::Path;

/// Where the installer's boot files sit in a live system's tree.
const SETUP_ESP: &str = "system/share/osyx-setup/esp/";
const SETUP_DIR: &str = "system/share/osyx-setup/";

fn octal(field: &[u8]) -> Result<u64, String> {
    let start = field.iter().position(|&b| b != b' ').unwrap_or(field.len());
    let end = field[start..].iter().position(|&b| b == 0 || b == b' ').map_or(field.len(), |i| start + i);
    if field[end..].iter().any(|&b| b != 0 && b != b' ') {
        return Err(String::from("bad octal field padding"));
    }
    let s: String = field[start..end].iter().map(|&b| b as char).collect();
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| format!("bad octal field {s:?}"))
}

fn text(field: &[u8]) -> Result<&str, String> {
    std::str::from_utf8(&field[..field.iter().position(|&b| b == 0).unwrap_or(field.len())])
        .map_err(|_| String::from("archive path is not UTF-8"))
}

/// Regular files of a ustar archive: (path without "./", mode, data).
fn tar_files(data: &[u8]) -> Result<Vec<(String, u32, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 512 <= data.len() {
        let h = &data[at..at + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let checksum = octal(&h[148..156])?;
        let actual: u64 = h.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { b as u64 }).sum();
        if checksum != actual {
            return Err(String::from("archive header checksum mismatch"));
        }
        let mut name = text(&h[0..100])?.to_string();
        if &h[257..262] == b"ustar" {
            let prefix = text(&h[345..500])?;
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let mode = octal(&h[100..108])? as u32;
        let size = octal(&h[124..136])? as usize;
        let kind = h[156];
        let body = at + 512;
        if body + size > data.len() {
            return Err(format!("{name}: archive truncated"));
        }
        if kind == b'0' || kind == 0 {
            let path = name.trim_start_matches("./").to_string();
            out.push((path, mode & 0o777, data[body..body + size].to_vec()));
        } else if kind != b'5' && kind != b'2' {
            return Err(format!("{name}: unsupported archive entry type {:?} (use --format=ustar)", kind as char));
        }
        at = body.checked_add(size.div_ceil(512).checked_mul(512).ok_or("archive size overflow")?).ok_or("archive size overflow")?;
        if at > data.len() {
            return Err(format!("{name}: archive padding truncated"));
        }
    }
    if at < data.len() && data.len() - at < 512 {
        return Err(String::from("archive header truncated"));
    }
    Ok(out)
}

fn read_secret(path: &str) -> Result<[u8; 32], String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    parse_hex::<32>(s.trim()).ok_or_else(|| format!("{path}: not a 64-digit hex Ed25519 secret key"))
}

fn keygen(secret_path: &str, public_path: &str) -> Result<(), String> {
    if Path::new(secret_path).exists() {
        return Err(format!("{secret_path} exists; refusing to replace a release key"));
    }
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|e| format!("no randomness: {e}"))?;
    if let Some(dir) = Path::new(secret_path).parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(secret_path).map_err(|e| format!("{secret_path}: {e}"))?;
    f.write_all(format!("{}\n", hex(&secret)).as_bytes()).map_err(|e| format!("{secret_path}: {e}"))?;
    std::fs::write(public_path, format!("{}\n", hex(&public_from_secret(&secret)))).map_err(|e| format!("{public_path}: {e}"))?;
    println!("secret key: {secret_path} (keep it private, back it up)");
    println!("public key: {public_path}");
    Ok(())
}

fn build(tar: &str, version: &str, secret_path: &str, out_dir: &str) -> Result<(), String> {
    let secret = read_secret(secret_path)?;
    let built_in = public_key().ok_or("shared/update/release.pub is not a public key")?;
    if public_from_secret(&secret) != built_in {
        return Err(format!("{secret_path} does not match shared/update/release.pub: systems would reject this release"));
    }
    let data = std::fs::read(tar).map_err(|e| format!("{tar}: {e}"))?;
    let mut files: Vec<(String, u32, Vec<u8>)> = Vec::new();
    for (path, mode, body) in tar_files(&data)? {
        let path = if let Some(rest) = path.strip_prefix(SETUP_ESP) {
            format!("esp/{rest}")
        } else if path.starts_with(SETUP_DIR) {
            continue;
        } else {
            path
        };
        if allowed_path(&path) {
            files.push((path, mode, body));
        }
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    for needed in osyx_update::ESP_FILES {
        if !files.iter().any(|f| f.0 == *needed) {
            return Err(format!("{tar} has no {needed} (build with build.ps1 -Live)"));
        }
    }
    let mut payload = Vec::new();
    let mut entries = Vec::new();
    for (path, mode, body) in &files {
        entries.push(Entry { path: path.clone(), size: body.len() as u64, mode: *mode, sha256: Sha256::digest(body).into() });
        payload.extend_from_slice(body);
    }
    let manifest = Manifest {
        version: version.to_string(),
        payload_size: payload.len() as u64,
        payload_sha256: Sha256::digest(&payload).into(),
        files: entries,
    };
    let text = manifest.to_text();
    Manifest::parse(&text)?;
    let sig = sign(text.as_bytes(), &secret);
    if !osyx_update::verify(text.as_bytes(), &sig, &built_in) {
        return Err(String::from("the new signature does not verify"));
    }
    std::fs::create_dir_all(out_dir).map_err(|e| format!("{out_dir}: {e}"))?;
    let w = |name: &str, bytes: &[u8]| {
        let p = Path::new(out_dir).join(name);
        std::fs::write(&p, bytes).map_err(|e| format!("{}: {e}", p.display()))
    };
    w(osyx_update::PAYLOAD, &payload)?;
    w(osyx_update::MANIFEST, text.as_bytes())?;
    w(osyx_update::SIGNATURE, &sig)?;
    println!("OSyx {version}: {} files, {} MiB payload, signed", manifest.files.len(), payload.len() >> 20);
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("keygen") if args.len() == 4 => keygen(&args[2], &args[3]),
        Some("build") if args.len() == 6 => build(&args[2], &args[3], &args[4], &args[5]),
        _ => Err(String::from(
            "usage: release keygen <secret key file> <public key file>\n       release build <rootfs.tar> <version> <secret key file> <output dir>",
        )),
    };
    if let Err(e) = r {
        eprintln!("release: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let sum: u64 = header[..512].iter().map(|&b| b as u64).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    #[test]
    fn octal_rejects_non_padding_after_terminator() {
        assert_eq!(octal(b"  0017\0 ").unwrap(), 15);
        assert_eq!(octal(b"        ").unwrap(), 0);
        assert!(octal(b"1 7\0").is_err());
        assert!(octal(b"1\0x ").is_err());
    }

    #[test]
    fn rejects_truncated_header_and_padding() {
        assert!(tar_files(&[1; 100]).is_err());
        let mut archive = vec![0; 513];
        archive[..4].copy_from_slice(b"test");
        archive[124..126].copy_from_slice(b"1\0");
        set_checksum(&mut archive);
        assert!(tar_files(&archive).is_err());
        archive.resize(1024, 0);
        assert_eq!(tar_files(&archive).unwrap().len(), 1);
    }

    #[test]
    fn rejects_corrupted_header() {
        let mut archive = vec![0; 512];
        archive[..4].copy_from_slice(b"test");
        set_checksum(&mut archive);
        assert!(tar_files(&archive).is_ok());
        archive[0] ^= 1;
        assert!(tar_files(&archive).is_err());
    }

    #[test]
    fn rejects_non_utf8_path() {
        let mut archive = vec![0; 512];
        archive[0] = 0xff;
        set_checksum(&mut archive);
        assert!(tar_files(&archive).is_err());
    }

    #[test]
    fn reads_generated_ustar_archive() {
        let dir = std::env::temp_dir();
        let name = format!("osyx-ustar-test-{}", std::process::id());
        let path = dir.join(&name);
        std::fs::write(&path, b"test data").unwrap();
        let executable = if Path::new("C:/msys64/usr/bin/tar.exe").exists() { "C:/msys64/usr/bin/tar.exe" } else { "tar" };
        let result = std::process::Command::new(executable).arg("--format=ustar").args(["-cf", "-", "-C"]).arg(&dir).arg(&name).output();
        std::fs::remove_file(&path).unwrap();
        let output = result.expect("tar must be available for archive interoperability testing");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let files = tar_files(&output.stdout).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, name);
        assert_eq!(files[0].2, b"test data");
    }
}
