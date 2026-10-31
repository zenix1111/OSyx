//! Live root: when `rootfs.z` is among the boot modules, its contents are
//! the system image. The file is an "OSYXLR2" header (uncompressed size,
//! little endian u64) followed by a Zstandard frame ("OSYXLR1": a zlib
//! stream) that decompresses to a cpio "newc" archive; [`unpack`] replays
//! that archive into the tmpfs that
//! serves as `/` when no root partition is used.

use crate::vfs::{self, Lookup};
use crate::{kprintln, modules};
use alloc::string::String;
use alloc::vec::Vec;
use osyx_abi::{Errno, MODE_PERMS, OPEN_CREATE, OPEN_TRUNCATE, OPEN_WRITE, ROOT_UID};
use osyx_vfs::Cred;

/// Name of the boot module carrying the compressed root (the loader
/// lower-cases module names).
pub const ARCHIVE: &str = "rootfs.z";
const MAGIC: &[u8; 8] = b"OSYXLR1\0";
/// The same with a Zstandard frame instead of the zlib stream.
const MAGIC_ZSTD: &[u8; 8] = b"OSYXLR2\0";
const HEADER_LEN: usize = 16;
/// Decompression bound; a live root larger than this is rejected before
/// any memory is committed.
const MAX_ROOT: u64 = 256 << 20;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const CPIO_HEADER: usize = 110;

struct Entry<'a> {
    mode: u32,
    uid: u32,
    gid: u32,
    data: &'a [u8],
    name: &'a str,
}

/// Whether the boot modules include a live root archive.
pub fn present() -> bool {
    modules::all().iter().any(|(name, _)| name == ARCHIVE)
}

/// Inflates and unpacks the live root into the tmpfs mounted at `/`.
/// Returns the number of archive entries applied.
pub fn unpack() -> Result<usize, &'static str> {
    let (_, data) = modules::all().iter().find(|(name, _)| name == ARCHIVE).ok_or("no rootfs.z module")?;
    if data.len() < HEADER_LEN + 6 || (&data[..8] != MAGIC && &data[..8] != MAGIC_ZSTD) {
        return Err("rootfs.z has no OSYXLR1/OSYXLR2 header");
    }
    let declared = u64::from_le_bytes(data[8..16].try_into().map_err(|_| "truncated header")?);
    if declared == 0 || declared > MAX_ROOT {
        return Err("rootfs.z declares an implausible size");
    }
    let started = crate::interrupts::uptime_ms();
    let raw = if &data[..8] == MAGIC_ZSTD {
        let mut out = Vec::with_capacity(declared as usize);
        ruzstd::decoding::FrameDecoder::new().decode_all_to_vec(&data[HEADER_LEN..], &mut out).map_err(|e| {
            kprintln!("live: zstd failed: {e:?}");
            "rootfs.z does not decompress"
        })?;
        out
    } else {
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&data[HEADER_LEN..], declared as usize).map_err(|e| {
            kprintln!("live: inflate failed: {:?}", e.status);
            "rootfs.z does not decompress"
        })?
    };
    kprintln!("live: decompressed in {} ms", crate::interrupts::uptime_ms().saturating_sub(started));
    if raw.len() as u64 != declared {
        return Err("rootfs.z inflated to an unexpected size");
    }
    kprintln!("live: {} KiB compressed, {} KiB of cpio archive", data.len() >> 10, raw.len() >> 10);
    let applied = unpack_cpio(&raw)?;
    Ok(applied)
}

/// Splits a newc archive into its entries.
fn entries(raw: &[u8]) -> Result<Vec<Entry<'_>>, &'static str> {
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        let hdr = raw.get(at..at + CPIO_HEADER).ok_or("cpio: truncated header")?;
        if &hdr[..6] != b"070701" {
            return Err("cpio: bad magic");
        }
        let field = |i: usize| -> Result<u64, &'static str> {
            let s = core::str::from_utf8(&hdr[6 + i * 8..14 + i * 8]).map_err(|_| "cpio: bad field")?;
            u64::from_str_radix(s, 16).map_err(|_| "cpio: bad field")
        };
        let mode = field(1)? as u32;
        let uid = field(2)? as u32;
        let gid = field(3)? as u32;
        let size = field(6)? as usize;
        let namesize = field(11)? as usize;
        let name_at = at + CPIO_HEADER;
        let name_raw = raw.get(name_at..name_at + namesize).ok_or("cpio: truncated name")?;
        let name = core::str::from_utf8(&name_raw[..namesize.saturating_sub(1)]).map_err(|_| "cpio: bad name")?;
        let data_at = (name_at + namesize).next_multiple_of(4);
        let data = raw.get(data_at..data_at + size).ok_or("cpio: truncated data")?;
        at = (data_at + size).next_multiple_of(4);
        if name == "TRAILER!!!" {
            return Ok(out);
        }
        out.push(Entry { mode, uid, gid, data, name });
    }
}

fn unpack_cpio(raw: &[u8]) -> Result<usize, &'static str> {
    let all = entries(raw)?;
    let root = Lookup::kernel();
    let mut applied = 0;
    for e in &all {
        let name = e.name.trim_start_matches("./").trim_end_matches('/');
        if name.is_empty() || name == "." {
            continue;
        }
        if name.starts_with('/') || name.split('/').any(|c| c == "..") {
            return Err("cpio: archive names a path outside the root");
        }
        let path = alloc::format!("/{name}");
        let cred = Cred { uid: e.uid, gid: e.gid };
        let cx = Lookup { cred, cwd: String::from("/"), case_insensitive: false, path_policy: None };
        // A node owned by an unprivileged user needs a parent that user may
        // search (and, for the immediate one, write).
        let widened = widen_parents(&root, &path, cred.uid)?;
        let r = match e.mode & S_IFMT {
            S_IFDIR => match vfs::mkdir(&cx, &path, e.mode & MODE_PERMS) {
                // mount points the kernel created before unpacking
                Err(Errno::AlreadyExists) => vfs::chmod(&root, &path, e.mode & MODE_PERMS),
                r => r,
            },
            S_IFREG => make_file(&cx, &path, e),
            S_IFLNK => make_symlink(&root, &cx, &path, e),
            // device nodes, fifos and sockets have no place in the archive
            _ => Ok(()),
        };
        for (dir, mode) in widened.into_iter().rev() {
            let _ = vfs::chmod(&root, &dir, mode);
        }
        if let Err(err) = r {
            kprintln!("live: {path}: {:?}", err);
            return Err("cpio: unpacking an entry failed");
        }
        applied += 1;
    }
    Ok(applied)
}

fn make_file(cx: &Lookup, path: &str, e: &Entry<'_>) -> vfs::Result<()> {
    let flags = OPEN_WRITE | OPEN_CREATE | OPEN_TRUNCATE;
    let mut f = vfs::open(cx, path, flags, e.mode & MODE_PERMS)?;
    let mut data = e.data;
    while !data.is_empty() {
        match f.write(data)? {
            0 => return Err(osyx_abi::Errno::NoSpace),
            n => data = &data[n..],
        }
    }
    Ok(())
}

fn make_symlink(root: &Lookup, cx: &Lookup, path: &str, e: &Entry<'_>) -> vfs::Result<()> {
    let target = core::str::from_utf8(e.data).map_err(|_| Errno::InvalidArgument)?;
    match vfs::symlink(cx, target, path) {
        Err(Errno::AlreadyExists) => {
            vfs::unlink(root, path)?;
            vfs::symlink(cx, target, path)
        }
        r => r,
    }
}

/// Makes every directory above `path` traversable by `uid`, and the
/// immediate parent writable, remembering the original modes. Directories
/// already searched or owned by `uid` are left alone.
fn widen_parents(root: &Lookup, path: &str, uid: u32) -> Result<Vec<(String, u32)>, &'static str> {
    if uid == ROOT_UID {
        return Ok(Vec::new());
    }
    let comps: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    let mut dirs = Vec::with_capacity(comps.len());
    dirs.push(String::from("/"));
    let mut at = String::new();
    for c in &comps[..comps.len().saturating_sub(1)] {
        at.push('/');
        at.push_str(c);
        dirs.push(at.clone());
    }
    let mut saved = Vec::new();
    let last = dirs.len() - 1;
    for (i, dir) in dirs.iter().enumerate() {
        let st = vfs::stat(root, dir).map_err(|_| "cpio: a parent is missing")?;
        if st.uid == uid {
            continue;
        }
        let want = if i == last { 0o003 } else { 0o001 };
        if st.mode & want == want {
            continue;
        }
        let old = st.mode & MODE_PERMS;
        vfs::chmod(root, dir, old | want).map_err(|_| "cpio: cannot widen a parent")?;
        saved.push((dir.clone(), old));
    }
    Ok(saved)
}
