//! Files and directories, like `std::fs`.
//!
//! ```ignore
//! use os_std::fs;
//! fs::create_dir("/tmp/example")?;
//! fs::write("/tmp/example/hello.txt", b"Hello OSyx!")?;
//! assert_eq!(fs::read("/tmp/example/hello.txt")?, b"Hello OSyx!");
//! for entry in fs::read_dir("/tmp/example")? {
//!     println!("{} {}", entry.file_name(), entry.metadata()?.len());
//! }
//! ```
//!
//! Paths are absolute or relative to the current directory
//! ([`crate::env::set_current_dir`]). On OSyx the kernel VFS resolves them
//! across the mounted file systems (ext4 `/`, FAT32 `/boot`, tmpfs `/tmp`
//! and `/run`, devfs `/dev`); FAT32 names are case-insensitive and have no
//! owners, symbolic links or permission bits beyond read-only. Files and
//! directories are created with modes 0644 / 0755 unless
//! [`OpenOptions::mode`] says otherwise (there is no umask). The host back
//! end maps paths below a scratch directory and only exists to unit-test
//! this module; it does not emulate symbolic links or ownership.

use crate::error::{Error, ErrorKind, Result};
use crate::io::{Read, Seek, SeekFrom, Write};
use crate::path::{Path, PathBuf};
use crate::sys::fs as imp;
use crate::time::SystemTime;
use alloc::string::String;
use alloc::vec::Vec;
use osyx_abi::FileStat;

/// An open file, directory or device node. Closed on drop.
pub struct File {
    inner: imp::RawFile,
}

impl File {
    /// Opens an existing file for reading.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<File> {
        OpenOptions::new().read(true).open(path)
    }

    /// Opens a file for writing, creating it or truncating it to zero length.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<File> {
        OpenOptions::new().write(true).create(true).truncate(true).open(path)
    }

    /// Creates a new file for reading and writing; fails if it exists.
    pub fn create_new<P: AsRef<Path>>(path: P) -> Result<File> {
        OpenOptions::new().read(true).write(true).create_new(true).open(path)
    }

    pub fn options() -> OpenOptions {
        OpenOptions::new()
    }

    pub fn metadata(&self) -> Result<Metadata> {
        self.inner.stat().map(Metadata)
    }

    /// Truncates or extends (with zeros) the file to `len` bytes.
    pub fn set_len(&self, len: u64) -> Result<()> {
        self.inner.set_len(len)
    }

    /// Writes cached data and metadata and flushes the disk's write cache.
    pub fn sync_all(&self) -> Result<()> {
        self.inner.sync()
    }

    pub fn sync_data(&self) -> Result<()> {
        self.inner.sync()
    }

    /// The kernel handle (for `ipc::wait` on device nodes such as
    /// `/dev/input/seat0`, or as a child's standard stream). It stays owned
    /// by this `File`.
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    pub fn handle(&self) -> u64 {
        self.inner.handle()
    }
}

impl Read for File {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for File {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        self.inner.write(buf)
    }
}

impl Seek for File {
    fn seek(&mut self, pos: SeekFrom) -> Result<u64> {
        let (offset, whence) = match pos {
            SeekFrom::Start(n) => (i64::try_from(n).map_err(|_| ErrorKind::InvalidInput)?, osyx_abi::SEEK_SET),
            SeekFrom::Current(n) => (n, osyx_abi::SEEK_CUR),
            SeekFrom::End(n) => (n, osyx_abi::SEEK_END),
        };
        self.inner.seek(offset, whence)
    }
}

impl core::fmt::Debug for File {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("File")
    }
}

/// How to open a file, like `std::fs::OpenOptions`.
#[derive(Clone, Copy, Debug)]
pub struct OpenOptions {
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    mode: u32,
    case_insensitive: bool,
}

impl Default for OpenOptions {
    fn default() -> Self {
        OpenOptions::new()
    }
}

impl OpenOptions {
    pub fn new() -> OpenOptions {
        OpenOptions {
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            mode: 0o644,
            case_insensitive: false,
        }
    }

    pub fn read(&mut self, on: bool) -> &mut OpenOptions {
        self.read = on;
        self
    }

    pub fn write(&mut self, on: bool) -> &mut OpenOptions {
        self.write = on;
        self
    }

    /// Every write goes to the end of the file (implies `write`).
    pub fn append(&mut self, on: bool) -> &mut OpenOptions {
        self.append = on;
        self
    }

    pub fn truncate(&mut self, on: bool) -> &mut OpenOptions {
        self.truncate = on;
        self
    }

    pub fn create(&mut self, on: bool) -> &mut OpenOptions {
        self.create = on;
        self
    }

    /// Create the file; fail with `AlreadyExists` if it exists.
    pub fn create_new(&mut self, on: bool) -> &mut OpenOptions {
        self.create_new = on;
        self
    }

    /// Permission bits of a file this call creates (default 0644).
    pub fn mode(&mut self, mode: u32) -> &mut OpenOptions {
        self.mode = mode;
        self
    }

    /// Resolve every path component case-insensitively (exact matches
    /// first), as Windows does. OSyx extension.
    pub fn case_insensitive(&mut self, on: bool) -> &mut OpenOptions {
        self.case_insensitive = on;
        self
    }

    fn flags(&self) -> Result<u64> {
        use osyx_abi::*;
        let write = self.write || self.append;
        if !self.read && !write {
            return Err(Error::new(ErrorKind::InvalidInput, "neither read nor write access requested"));
        }
        if (self.truncate || self.create || self.create_new) && !write {
            return Err(Error::new(ErrorKind::InvalidInput, "create and truncate need write access"));
        }
        if self.truncate && self.append {
            return Err(Error::new(ErrorKind::InvalidInput, "truncate and append are exclusive"));
        }
        let mut flags = 0;
        for (on, bit) in [
            (self.read, OPEN_READ),
            (write, OPEN_WRITE),
            (self.append, OPEN_APPEND),
            (self.truncate, OPEN_TRUNCATE),
            (self.create || self.create_new, OPEN_CREATE),
            (self.create_new, OPEN_EXCLUSIVE),
            (self.case_insensitive, OPEN_CASE_INSENSITIVE),
        ] {
            if on {
                flags |= bit;
            }
        }
        Ok(flags)
    }

    pub fn open<P: AsRef<Path>>(&self, path: P) -> Result<File> {
        let flags = self.flags()?;
        imp::open(path_str(path.as_ref())?, flags, self.mode).map(|inner| File { inner })
    }
}

/// The kind of a file system object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileType(u32);

impl FileType {
    pub fn is_dir(&self) -> bool {
        self.0 == osyx_abi::KIND_DIR
    }

    pub fn is_file(&self) -> bool {
        self.0 == osyx_abi::KIND_FILE
    }

    pub fn is_symlink(&self) -> bool {
        self.0 == osyx_abi::KIND_SYMLINK
    }

    pub fn is_char_device(&self) -> bool {
        self.0 == osyx_abi::KIND_CHAR_DEVICE
    }

    pub fn is_block_device(&self) -> bool {
        self.0 == osyx_abi::KIND_BLOCK_DEVICE
    }
}

/// Permission bits of a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Permissions(u32);

impl Permissions {
    pub fn from_mode(mode: u32) -> Permissions {
        Permissions(mode & osyx_abi::MODE_PERMS)
    }

    pub fn mode(&self) -> u32 {
        self.0
    }

    /// True if nobody has write permission.
    pub fn readonly(&self) -> bool {
        self.0 & 0o222 == 0
    }

    pub fn set_readonly(&mut self, on: bool) {
        if on {
            self.0 &= !0o222;
        } else {
            self.0 |= 0o200;
        }
    }
}

/// Size, kind, ownership, permissions and times of a file system object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata(FileStat);

impl Metadata {
    pub fn file_type(&self) -> FileType {
        FileType(self.0.kind)
    }

    pub fn is_dir(&self) -> bool {
        self.file_type().is_dir()
    }

    pub fn is_file(&self) -> bool {
        self.file_type().is_file()
    }

    pub fn is_symlink(&self) -> bool {
        self.file_type().is_symlink()
    }

    /// Size in bytes (for symbolic links: the length of the target).
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.0.size
    }

    pub fn permissions(&self) -> Permissions {
        Permissions(self.0.mode)
    }

    pub fn uid(&self) -> u32 {
        self.0.uid
    }

    pub fn gid(&self) -> u32 {
        self.0.gid
    }

    /// Inode number, unique within [`Metadata::dev`].
    pub fn ino(&self) -> u64 {
        self.0.ino
    }

    /// Id of the mounted volume.
    pub fn dev(&self) -> u64 {
        self.0.dev
    }

    pub fn nlink(&self) -> u32 {
        self.0.nlink
    }

    /// Storage used, in 512-byte units.
    pub fn blocks(&self) -> u64 {
        self.0.blocks
    }

    /// FAT attribute bits (`osyx_abi::ATTR_*`), 0 on other file systems.
    pub fn attributes(&self) -> u32 {
        self.0.attributes
    }

    pub fn modified(&self) -> Result<SystemTime> {
        time_of(self.0.mtime_ns)
    }

    pub fn accessed(&self) -> Result<SystemTime> {
        time_of(self.0.atime_ns)
    }

    /// Time of the last metadata change.
    pub fn changed(&self) -> Result<SystemTime> {
        time_of(self.0.ctime_ns)
    }
}

fn time_of(ns: i64) -> Result<SystemTime> {
    if ns == 0 {
        return Err(Error::new(ErrorKind::Unsupported, "the file system does not record this time"));
    }
    Ok(SystemTime::from_unix_nanos(ns))
}

/// One entry of [`read_dir`].
#[derive(Clone, Debug)]
pub struct DirEntry {
    dir: PathBuf,
    name: String,
    ino: u64,
    kind: u32,
}

impl DirEntry {
    pub fn file_name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(self.name.as_str())
    }

    pub fn ino(&self) -> u64 {
        self.ino
    }

    /// The entry's kind, without following a symbolic link.
    pub fn file_type(&self) -> FileType {
        FileType(self.kind)
    }

    /// Metadata of the entry itself (a symbolic link is not followed).
    pub fn metadata(&self) -> Result<Metadata> {
        symlink_metadata(self.path())
    }
}

/// Iterator over a directory listing, without `.` and `..`. The listing is
/// read completely when [`read_dir`] is called.
pub struct ReadDir {
    entries: alloc::vec::IntoIter<DirEntry>,
}

impl Iterator for ReadDir {
    type Item = DirEntry;
    fn next(&mut self) -> Option<DirEntry> {
        self.entries.next()
    }
}

fn path_str(p: &Path) -> Result<&str> {
    let s = p.as_str();
    if s.is_empty() || s.len() > osyx_abi::MAX_PATH || s.contains('\0') {
        return Err(Error::new(ErrorKind::InvalidInput, "invalid path"));
    }
    Ok(s)
}

/// Metadata of `path`, following symbolic links.
pub fn metadata<P: AsRef<Path>>(path: P) -> Result<Metadata> {
    imp::stat(path_str(path.as_ref())?).map(Metadata)
}

/// Metadata of `path` itself, even if it is a symbolic link.
pub fn symlink_metadata<P: AsRef<Path>>(path: P) -> Result<Metadata> {
    imp::lstat(path_str(path.as_ref())?).map(Metadata)
}

/// True if `path` exists; errors other than `NotFound` are reported.
pub fn exists<P: AsRef<Path>>(path: P) -> Result<bool> {
    match metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

/// The whole contents of a file.
pub fn read<P: AsRef<Path>>(path: P) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    // The whole file at once (no doubling copies of a large file); a size
    // that cannot be reserved falls back to growing while reading.
    let mut buf = Vec::new();
    if let Ok(m) = f.metadata() {
        let _ = buf.try_reserve_exact(m.len() as usize);
    }
    f.read_to_end(&mut buf)?;
    Ok(buf)
}

/// The whole contents of a UTF-8 text file.
pub fn read_to_string<P: AsRef<Path>>(path: P) -> Result<String> {
    let mut s = String::new();
    File::open(path)?.read_to_string(&mut s)?;
    Ok(s)
}

/// Creates or replaces the file at `path` with `contents`.
pub fn write<P: AsRef<Path>, C: AsRef<[u8]>>(path: P, contents: C) -> Result<()> {
    File::create(path)?.write_all(contents.as_ref())
}

/// Copies a file's contents; returns the number of bytes copied.
pub fn copy<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<u64> {
    let mut src = File::open(from)?;
    let mut dst = File::create(to)?;
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        match src.read(&mut buf)? {
            0 => return Ok(total),
            n => {
                dst.write_all(&buf[..n])?;
                total += n as u64;
            }
        }
    }
}

pub fn read_dir<P: AsRef<Path>>(path: P) -> Result<ReadDir> {
    let dir = path.as_ref();
    let list = imp::read_dir(path_str(dir)?)?;
    let entries: Vec<DirEntry> = list
        .into_iter()
        .filter(|(name, _, _)| name != "." && name != "..")
        .map(|(name, ino, kind)| DirEntry { dir: dir.to_path_buf(), name, ino, kind })
        .collect();
    Ok(ReadDir { entries: entries.into_iter() })
}

/// Creates a directory (mode 0755).
pub fn create_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    imp::mkdir(path_str(path.as_ref())?, 0o755)
}

/// Creates `path` and any missing parents.
pub fn create_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    path_str(path)?;
    let mut cur = PathBuf::from(if path.is_absolute() { "/" } else { "." });
    for c in path.components() {
        if c == ".." {
            return Err(Error::new(ErrorKind::InvalidInput, "create_dir_all does not accept `..`"));
        }
        cur.push(c);
        match create_dir(&cur) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists && metadata(&cur)?.is_dir() => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Removes a file, symbolic link or device node.
pub fn remove_file<P: AsRef<Path>>(path: P) -> Result<()> {
    imp::unlink(path_str(path.as_ref())?)
}

/// Removes an empty directory.
pub fn remove_dir<P: AsRef<Path>>(path: P) -> Result<()> {
    imp::rmdir(path_str(path.as_ref())?)
}

/// Removes a directory and everything below it (symbolic links are
/// removed, not followed).
pub fn remove_dir_all<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    for entry in read_dir(path)? {
        if entry.file_type().is_dir() {
            remove_dir_all(entry.path())?;
        } else {
            remove_file(entry.path())?;
        }
    }
    remove_dir(path)
}

/// Moves `from` to `to` on the same volume, replacing an existing file.
pub fn rename<P: AsRef<Path>, Q: AsRef<Path>>(from: P, to: Q) -> Result<()> {
    imp::rename(path_str(from.as_ref())?, path_str(to.as_ref())?)
}

/// Creates a symbolic link at `link` pointing to `target` (stored as given).
pub fn symlink<P: AsRef<Path>, Q: AsRef<Path>>(target: P, link: Q) -> Result<()> {
    imp::symlink(path_str(target.as_ref())?, path_str(link.as_ref())?)
}

/// The target of a symbolic link.
pub fn read_link<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    imp::readlink(path_str(path.as_ref())?).map(PathBuf::from)
}

/// The absolute path with symbolic links, `.` and `..` resolved.
///
/// Every component of `path` must exist. More than 40 symbolic links in one
/// resolution is reported as [`ErrorKind::InvalidInput`].
pub fn canonicalize<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
    let p = path.as_ref();
    let mut resolved = if p.is_absolute() { PathBuf::from("/") } else { crate::env::current_dir()? };
    let mut parts = Vec::new();
    push_parts(&mut parts, path_str(p)?);
    let mut followed = 0;
    while let Some(part) = parts.pop() {
        match part.as_str() {
            "." => {}
            // Above the root is the root, as in POSIX.
            ".." => {
                resolved.pop();
            }
            name => {
                let candidate = resolved.join(name);
                if symlink_metadata(&candidate)?.file_type().is_symlink() {
                    followed += 1;
                    if followed > 40 {
                        return Err(Error::new(ErrorKind::InvalidInput, "too many levels of symbolic links"));
                    }
                    let target = read_link(&candidate)?;
                    if target.as_str().starts_with('/') {
                        resolved = PathBuf::from("/");
                    }
                    push_parts(&mut parts, target.as_str());
                } else {
                    resolved = candidate;
                }
            }
        }
    }
    Ok(resolved)
}

/// Queues the components of `s` so that popping yields them left to right.
fn push_parts(parts: &mut Vec<String>, s: &str) {
    for part in s.split('/').filter(|p| !p.is_empty()).rev() {
        parts.push(String::from(part));
    }
}

pub fn set_permissions<P: AsRef<Path>>(path: P, perm: Permissions) -> Result<()> {
    imp::chmod(path_str(path.as_ref())?, perm.mode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// A fresh directory per test (tests run in parallel in one process).
    fn scratch(name: &str) -> PathBuf {
        let p = PathBuf::from(alloc::format!("/{name}"));
        let _ = remove_dir_all(&p);
        create_dir(&p).unwrap();
        p
    }

    #[test]
    fn write_read_append_and_metadata() {
        let d = scratch("t-basic");
        let f = d.join("a.txt");
        write(&f, "hello").unwrap();
        assert_eq!(read_to_string(&f).unwrap(), "hello");
        OpenOptions::new().append(true).open(&f).unwrap().write_all(b", OSyx").unwrap();
        assert_eq!(read(&f).unwrap(), b"hello, OSyx");
        let m = metadata(&f).unwrap();
        assert!(m.is_file() && !m.is_dir() && m.len() == 11);
        assert!(m.modified().is_ok());
        assert!(metadata(&d).unwrap().is_dir());
        assert!(exists(&f).unwrap() && !exists(d.join("missing")).unwrap());
        assert_eq!(File::open(d.join("missing")).unwrap_err().kind(), ErrorKind::NotFound);
        assert_eq!(File::create_new(&f).unwrap_err().kind(), ErrorKind::AlreadyExists);
        let mut p = m.permissions();
        p.set_readonly(true);
        set_permissions(&f, p).unwrap();
        assert!(metadata(&f).unwrap().permissions().readonly());
        p.set_readonly(false);
        set_permissions(&f, p).unwrap();
    }

    #[test]
    fn canonicalize_resolves_dots_and_requires_existence() {
        let d = scratch("t-canon");
        create_dir(&d.join("a")).unwrap();
        write(d.join("a/f.txt"), "x").unwrap();
        assert_eq!(canonicalize(d.join("a/../a/./f.txt")).unwrap().as_str(), "/t-canon/a/f.txt");
        assert_eq!(canonicalize(&d).unwrap().as_str(), "/t-canon");
        assert_eq!(canonicalize("/../../t-canon/a").unwrap().as_str(), "/t-canon/a");
        assert_eq!(canonicalize(d.join("missing")).unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn seek_set_len_and_partial_reads() {
        let d = scratch("t-seek");
        let p = d.join("data.bin");
        let mut f = File::create_new(&p).unwrap();
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7) as u8).collect();
        f.write_all(&data).unwrap();
        assert_eq!(f.seek(SeekFrom::Start(100)).unwrap(), 100);
        let mut buf = [0u8; 4];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(buf, data[100..104]);
        assert_eq!(f.seek(SeekFrom::Current(-4)).unwrap(), 100);
        assert_eq!(f.seek(SeekFrom::End(-1)).unwrap(), 9_999);
        f.set_len(50).unwrap();
        assert_eq!(f.metadata().unwrap().len(), 50);
        f.set_len(60).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let back = read(&p).unwrap();
        assert_eq!(&back[..50], &data[..50]);
        assert_eq!(&back[50..], &[0u8; 10]);
    }

    #[test]
    fn directories_listing_rename_and_removal() {
        let d = scratch("t-dirs");
        create_dir_all(d.join("x/y/z")).unwrap();
        create_dir_all(d.join("x/y")).unwrap();
        write(d.join("x/one.txt"), [1u8; 3]).unwrap();
        write(d.join("x/y/two.txt"), vec![2u8; 5]).unwrap();
        let mut names: Vec<(String, bool, u64)> = read_dir(d.join("x"))
            .unwrap()
            .map(|e| (String::from(e.file_name()), e.file_type().is_dir(), e.metadata().unwrap().len()))
            .collect();
        names.sort();
        assert_eq!(names, [(String::from("one.txt"), false, 3), (String::from("y"), true, 0)]);
        rename(d.join("x/one.txt"), d.join("x/y/moved.txt")).unwrap();
        assert!(!exists(d.join("x/one.txt")).unwrap());
        assert_eq!(copy(d.join("x/y/moved.txt"), d.join("copy.txt")).unwrap(), 3);
        assert_eq!(remove_dir(d.join("x")).unwrap_err().kind(), ErrorKind::DirectoryNotEmpty);
        remove_dir_all(d.join("x")).unwrap();
        assert!(!exists(d.join("x")).unwrap());
        remove_file(d.join("copy.txt")).unwrap();
        assert_eq!(read_dir(&d).unwrap().count(), 0);
    }

    #[test]
    fn invalid_options_and_paths_are_rejected() {
        assert_eq!(OpenOptions::new().open("/x").unwrap_err().kind(), ErrorKind::InvalidInput);
        assert_eq!(OpenOptions::new().read(true).create(true).open("/x").unwrap_err().kind(), ErrorKind::InvalidInput);
        assert_eq!(
            OpenOptions::new().append(true).truncate(true).open("/x").unwrap_err().kind(),
            ErrorKind::InvalidInput
        );
        assert_eq!(read("").unwrap_err().kind(), ErrorKind::InvalidInput);
        let long = alloc::format!("/{}", "a".repeat(osyx_abi::MAX_PATH));
        assert_eq!(metadata(long).unwrap_err().kind(), ErrorKind::InvalidInput);
        assert_eq!(create_dir_all("/a/../b").unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn permissions_bits() {
        let mut p = Permissions::from_mode(0o100644);
        assert_eq!(p.mode(), 0o644);
        assert!(!p.readonly());
        p.set_readonly(true);
        assert_eq!(p.mode(), 0o444);
        assert!(p.readonly());
    }
}
