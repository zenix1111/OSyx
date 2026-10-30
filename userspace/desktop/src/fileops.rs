//! File operations of Files that touch many files: copy trees, pack into a
//! tar archive, unpack tar, zip and 7z archives. Pure archive formats are in
//! `osyx_filekit`; this is the part that talks to the file system.

use os_std::fs;
use os_std::io::{Read, Write};
use os_std::prelude::*;
use osyx_filekit::tar::{self, EntryKind};
use osyx_filekit::{classify, zip, Kind};

/// Archives larger than this are not unpacked from memory (tar, zip).
const ARCHIVE_LIMIT: u64 = 256 << 20;
const CHUNK: usize = 128 * 1024;
/// Largest result of decompressing a .gz or .tar.gz in memory.
const DECOMPRESSED_LIMIT: usize = 256 << 20;

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

fn secs(m: &fs::Metadata) -> u64 {
    m.modified().ok().and_then(|t| t.duration_since(os_std::time::SystemTime::UNIX_EPOCH).ok()).map_or(0, |d| d.as_secs())
}

/// Copies a file or folder (symbolic links are skipped). Returns the
/// number of files copied.
pub fn copy_tree(from: &str, to: &str) -> Result<u64, String> {
    let m = fs::symlink_metadata(from).map_err(|e| format!("{from}: {e}"))?;
    if m.is_symlink() {
        return Ok(0);
    }
    if m.is_dir() {
        fs::create_dir(to).map_err(|e| format!("{to}: {e}"))?;
        let mut n = 0;
        for e in fs::read_dir(from).map_err(|e| format!("{from}: {e}"))? {
            let name = String::from(e.file_name());
            n += copy_tree(&join(from, &name), &join(to, &name))?;
        }
        Ok(n)
    } else {
        fs::copy(from, to).map_err(|e| format!("{from}: {e}"))?;
        Ok(1)
    }
}

fn pack_entry(out: &mut fs::File, path: &str, rel: &str, count: &mut usize) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if m.is_symlink() {
        return Ok(());
    }
    let mode = m.permissions().mode();
    if m.is_dir() {
        out.write_all(&tar::header(rel, EntryKind::Dir, 0, mode, secs(&m))?).map_err(|e| format!("write: {e}"))?;
        *count += 1;
        let mut names: Vec<String> = fs::read_dir(path).map_err(|e| format!("{path}: {e}"))?.map(|e| String::from(e.file_name())).collect();
        names.sort();
        for n in names {
            pack_entry(out, &join(path, &n), &format!("{rel}/{n}"), count)?;
        }
        return Ok(());
    }
    let size = m.len();
    out.write_all(&tar::header(rel, EntryKind::File, size, mode, secs(&m))?).map_err(|e| format!("write: {e}"))?;
    let mut f = fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let mut buf = vec![0u8; CHUNK];
    let mut left = size;
    while left > 0 {
        let n = f.read(&mut buf[..(left as usize).min(CHUNK)]).map_err(|e| format!("{path}: {e}"))?;
        if n == 0 {
            // The file shrank while it was packed: keep the archive valid.
            out.write_all(&vec![0u8; left as usize]).map_err(|e| format!("write: {e}"))?;
            break;
        }
        out.write_all(&buf[..n]).map_err(|e| format!("write: {e}"))?;
        left -= n as u64;
    }
    out.write_all(&vec![0u8; tar::padding(size)]).map_err(|e| format!("write: {e}"))?;
    *count += 1;
    Ok(())
}

/// Packs the entries `names` of folder `dir` into the tar archive `out`.
/// Returns the number of files and folders packed.
pub fn pack(dir: &str, names: &[String], out: &str) -> Result<usize, String> {
    let mut f = fs::File::create(out).map_err(|e| format!("{out}: {e}"))?;
    let mut count = 0;
    let r = names.iter().try_for_each(|n| pack_entry(&mut f, &join(dir, n), n, &mut count));
    let r = r.and_then(|_| f.write_all(&tar::END).map_err(|e| format!("write: {e}")));
    match r {
        Ok(()) => {
            f.sync_all().map_err(|e| format!("{out}: {e}"))?;
            Ok(count)
        }
        Err(e) => {
            drop(f);
            let _ = fs::remove_file(out);
            Err(e)
        }
    }
}

fn write_file(dest: &str, rel: &str, data: &[u8], mode: u32) -> Result<(), String> {
    let target = join(dest, rel);
    if let Some((parent, _)) = target.rsplit_once('/') {
        fs::create_dir_all(parent).map_err(|e| format!("{parent}: {e}"))?;
    }
    fs::write(&target, data).map_err(|e| format!("{target}: {e}"))?;
    if mode & 0o111 != 0 {
        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode & 0o777));
    }
    Ok(())
}

fn read_limited(path: &str) -> Result<Vec<u8>, String> {
    let len = fs::metadata(path).map_err(|e| format!("{path}: {e}"))?.len();
    if len > ARCHIVE_LIMIT {
        return Err(format!("{path} is larger than {} MiB: too big to unpack here", ARCHIVE_LIMIT >> 20));
    }
    fs::read(path).map_err(|e| format!("{path}: {e}"))
}

struct SevenSource(fs::File, u64);

impl osyx_7z::Source for SevenSource {
    fn size(&self) -> u64 {
        self.1
    }
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> osyx_7z::Result<usize> {
        use os_std::io::{Seek, SeekFrom};
        self.0.seek(SeekFrom::Start(offset)).map_err(|_| osyx_7z::Error::Io)?;
        self.0.read(buf).map_err(|_| osyx_7z::Error::Io)
    }
}

struct SevenSink {
    dest: String,
    file: Option<fs::File>,
    count: usize,
}

impl osyx_7z::Sink for SevenSink {
    fn dir(&mut self, path: &str) -> osyx_7z::Result<()> {
        if !tar::safe_path(path) {
            return Err(osyx_7z::Error::Sink);
        }
        fs::create_dir_all(join(&self.dest, path)).map_err(|_| osyx_7z::Error::Sink)
    }
    fn file_start(&mut self, path: &str, _size: u64) -> osyx_7z::Result<()> {
        if !tar::safe_path(path) {
            return Err(osyx_7z::Error::Sink);
        }
        let target = join(&self.dest, path);
        if let Some((parent, _)) = target.rsplit_once('/') {
            fs::create_dir_all(parent).map_err(|_| osyx_7z::Error::Sink)?;
        }
        self.file = Some(fs::File::create(&target).map_err(|_| osyx_7z::Error::Sink)?);
        self.count += 1;
        Ok(())
    }
    fn file_data(&mut self, data: &[u8]) -> osyx_7z::Result<()> {
        match &mut self.file {
            Some(f) => f.write_all(data).map_err(|_| osyx_7z::Error::Sink),
            None => Ok(()),
        }
    }
    fn file_end(&mut self) -> osyx_7z::Result<()> {
        self.file = None;
        Ok(())
    }
}

/// Unpacks the archive `path` (tar, zip or 7z) into the new folder `dest`.
/// Returns the number of files written. Entries that would leave `dest`
/// (absolute paths, `..`) stop the extraction.
pub fn extract(path: &str, dest: &str) -> Result<usize, String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    let osyx_filekit::Kind::Archive(kind) = classify(name) else { return Err(format!("{name} is not an archive")) };
    fs::create_dir(dest).map_err(|e| format!("{dest}: {e}"))?;
    let result = (|| -> Result<usize, String> {
        match kind {
            osyx_filekit::kind::ArchiveKind::Gz => {
                let (data, stored) = osyx_filekit::gzip::decompress(&read_limited(path)?, DECOMPRESSED_LIMIT)?;
                let stem = name.rsplit_once('.').map_or(name, |(s, _)| s);
                let file = stored.filter(|n| tar::safe_path(n)).unwrap_or_else(|| String::from(stem));
                write_file(dest, &file, &data, 0o644)?;
                Ok(1)
            }
            osyx_filekit::kind::ArchiveKind::Tar | osyx_filekit::kind::ArchiveKind::TarGz => {
                let raw = read_limited(path)?;
                let data = if kind == osyx_filekit::kind::ArchiveKind::TarGz {
                    osyx_filekit::gzip::decompress(&raw, DECOMPRESSED_LIMIT)?.0
                } else {
                    raw
                };
                let entries = tar::parse(&data)?;
                let mut n = 0;
                for e in &entries {
                    if !tar::safe_path(&e.path) {
                        return Err(format!("{}: unsafe path in the archive", e.path));
                    }
                    match e.kind {
                        EntryKind::Dir => fs::create_dir_all(join(dest, &e.path)).map_err(|er| format!("{}: {er}", e.path))?,
                        EntryKind::File => {
                            write_file(dest, &e.path, &data[e.data.clone()], e.mode)?;
                            n += 1;
                        }
                    }
                }
                Ok(n)
            }
            osyx_filekit::kind::ArchiveKind::Zip => {
                let data = read_limited(path)?;
                let entries = zip::list(&data)?;
                let mut n = 0;
                for e in &entries {
                    if !tar::safe_path(&e.path) {
                        return Err(format!("{}: unsafe path in the archive", e.path));
                    }
                    if e.is_dir {
                        fs::create_dir_all(join(dest, &e.path)).map_err(|er| format!("{}: {er}", e.path))?;
                    } else {
                        write_file(dest, &e.path, &zip::extract(&data, e)?, 0o644)?;
                        n += 1;
                    }
                }
                Ok(n)
            }
            osyx_filekit::kind::ArchiveKind::SevenZ => {
                let file = fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
                let len = file.metadata().map_err(|e| format!("{path}: {e}"))?.len();
                let mut src = SevenSource(file, len);
                let base = osyx_7z::find(&mut src, 8 << 20).map_err(|e| format!("{name}: {e}"))?;
                let mut sink = SevenSink { dest: String::from(dest), file: None, count: 0 };
                osyx_7z::extract(src, base, &mut sink).map_err(|e| format!("{name}: {e}"))?;
                Ok(sink.count)
            }
        }
    })();
    if result.is_err() {
        // A half-unpacked folder is worse than none.
        let _ = fs::remove_dir_all(dest);
    }
    result
}

/// True for kinds Files unpacks.
pub fn is_archive(name: &str) -> bool {
    matches!(classify(name), Kind::Archive(_))
}
