//! Path-based file operations.

use crate::dir::{validate_name, DirRef, Item};
use crate::time::unix_with_offset;
use crate::{BlockDevice, Cursor, DirEntryInfo, FileRef, FileSystem, FsError, Result, ATTR_DIRECTORY, FAT_EOC};
use alloc::vec;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub is_dir: bool,
    pub size: u64,
    pub attributes: u16,
    pub first_cluster: u32,
    pub modified: i64,
    pub accessed: i64,
    pub created: i64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OpenOptions {
    /// Create the file if it does not exist.
    pub create: bool,
    /// With `create`: fail with `AlreadyExists` if it exists.
    pub create_new: bool,
    /// Cut an existing file to length 0.
    pub truncate: bool,
}

enum Node {
    Root,
    Item(Item),
}

/// Splits an absolute path into its names; `.` is skipped and `..` refused.
fn components(path: &str) -> Result<Vec<&str>> {
    if !path.starts_with('/') {
        return Err(FsError::InvalidInput("path must be absolute"));
    }
    let mut out = Vec::new();
    for c in path.split('/') {
        match c {
            "" | "." => {}
            ".." => return Err(FsError::InvalidInput("'..' in a path")),
            c => out.push(c),
        }
    }
    Ok(out)
}

fn split_parent(path: &str) -> Result<(Vec<&str>, &str)> {
    let mut c = components(path)?;
    let last = c.pop().ok_or(FsError::InvalidInput("the root directory has no parent"))?;
    Ok((c, last))
}

impl<D: BlockDevice> FileSystem<D> {
    fn resolve_components(&mut self, comps: &[&str]) -> Result<Node> {
        let mut dir = self.root_dir();
        let mut node = Node::Root;
        for (i, c) in comps.iter().enumerate() {
            let name = c.encode_utf16().collect::<Vec<u16>>();
            let item = self.find_in_dir(&dir, &name)?.ok_or(FsError::NotFound)?;
            if i + 1 < comps.len() {
                if !item.file.is_dir() {
                    return Err(FsError::NotADirectory);
                }
                dir = item.file.dir();
            }
            node = Node::Item(item);
        }
        Ok(node)
    }

    fn resolve(&mut self, path: &str) -> Result<Node> {
        let c = components(path)?;
        self.resolve_components(&c)
    }

    fn dir_at(&mut self, comps: &[&str]) -> Result<DirRef> {
        match self.resolve_components(comps)? {
            Node::Root => Ok(self.root_dir()),
            Node::Item(it) if it.file.is_dir() => Ok(it.file.dir()),
            Node::Item(_) => Err(FsError::NotADirectory),
        }
    }

    fn root_ref(&mut self) -> FileRef {
        let mut f = self.new_ref(ATTR_DIRECTORY);
        f.first = self.geo.root_cluster;
        f
    }

    fn metadata_of(f: &FileRef) -> Metadata {
        Metadata {
            is_dir: f.is_dir(),
            size: if f.is_dir() { 0 } else { f.size },
            attributes: f.attr,
            first_cluster: f.first,
            modified: unix_with_offset(f.times.modify, f.times.modify_off),
            accessed: unix_with_offset(f.times.access, f.times.access_off),
            created: unix_with_offset(f.times.create, f.times.create_off),
        }
    }

    pub fn metadata(&mut self, path: &str) -> Result<Metadata> {
        Ok(match self.resolve(path)? {
            Node::Root => Self::metadata_of(&self.root_ref()),
            Node::Item(it) => Self::metadata_of(&it.file),
        })
    }

    pub fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntryInfo>> {
        let dir = match self.resolve(path)? {
            Node::Root => self.root_dir(),
            Node::Item(it) if it.file.is_dir() => it.file.dir(),
            Node::Item(_) => return Err(FsError::NotADirectory),
        };
        let bytes = self.load_dir(&dir)?;
        Ok(self
            .parse_dir(&bytes, &dir)
            .into_iter()
            .map(|it| DirEntryInfo { name: it.name(), is_dir: it.file.is_dir(), size: it.file.size, attributes: it.file.attr })
            .collect())
    }

    pub fn open(&mut self, path: &str, opts: OpenOptions) -> Result<FileRef> {
        match self.resolve(path) {
            Ok(Node::Root) => Ok(self.root_ref()),
            Ok(Node::Item(it)) => {
                if opts.create && opts.create_new {
                    return Err(FsError::AlreadyExists);
                }
                let mut f = it.file;
                if opts.truncate && !f.is_dir() {
                    self.truncate(&mut f, 0)?;
                }
                Ok(f)
            }
            Err(FsError::NotFound) if opts.create => {
                let (parent, name) = split_parent(path)?;
                let dir = self.dir_at(&parent)?;
                self.create_entry(&dir, name, 0)
            }
            Err(e) => Err(e),
        }
    }

    /// Adds an empty file (`attr` 0 = archive) or directory to `dir`.
    fn create_entry(&mut self, dir: &DirRef, name: &str, attr: u16) -> Result<FileRef> {
        let name16 = validate_name(name)?;
        if self.find_in_dir(dir, &name16)?.is_some() {
            return Err(FsError::AlreadyExists);
        }
        let mut f = self.new_ref(if attr == 0 { crate::ATTR_ARCHIVE } else { attr });
        if attr & ATTR_DIRECTORY != 0 {
            let cb = self.geo.cluster_bytes();
            let c = self.alloc_cluster()?;
            let r = self.fat_set(c, FAT_EOC).and_then(|_| self.write_at(self.cluster_off(c), &vec![0u8; cb as usize]));
            if let Err(e) = r {
                self.free_cluster(c);
                return Err(e);
            }
            f.first = c;
            f.size = cb;
            f.valid = cb;
        }
        let set = self.build_set(&name16, &f);
        match self.insert_set(dir, &set) {
            Ok(pos) => {
                f.pos = Some(pos);
                Ok(f)
            }
            Err(e) => {
                if f.first != 0 {
                    let _ = self.fat_set(f.first, 0);
                    self.free_cluster(f.first);
                }
                Err(e)
            }
        }
    }

    pub fn create_dir(&mut self, path: &str) -> Result<()> {
        let (parent, name) = split_parent(path)?;
        let dir = self.dir_at(&parent)?;
        self.create_entry(&dir, name, ATTR_DIRECTORY).map(|_| ())
    }

    fn free_file(&mut self, f: &FileRef) -> Result<()> {
        if f.first == 0 || f.size == 0 {
            return Ok(());
        }
        let clusters = f.size.div_ceil(self.geo.cluster_bytes());
        self.free_run(f.first, f.nofat, clusters)
    }

    pub fn remove_file(&mut self, path: &str) -> Result<()> {
        match self.resolve(path)? {
            Node::Root => Err(FsError::IsADirectory),
            Node::Item(it) if it.file.is_dir() => Err(FsError::IsADirectory),
            Node::Item(it) => {
                let pos = it.file.pos.ok_or(FsError::Corrupt("entry without a position"))?;
                self.delete_set(&pos)?;
                self.free_file(&it.file)
            }
        }
    }

    pub fn remove_dir(&mut self, path: &str) -> Result<()> {
        match self.resolve(path)? {
            Node::Root => Err(FsError::InvalidInput("cannot remove the root directory")),
            Node::Item(it) if !it.file.is_dir() => Err(FsError::NotADirectory),
            Node::Item(it) => {
                let dir = it.file.dir();
                let bytes = self.load_dir(&dir)?;
                if !self.parse_dir(&bytes, &dir).is_empty() {
                    return Err(FsError::DirectoryNotEmpty);
                }
                let pos = it.file.pos.ok_or(FsError::Corrupt("entry without a position"))?;
                self.delete_set(&pos)?;
                self.free_file(&it.file)
            }
        }
    }

    /// Renames or moves a file or directory. An existing *file* at `to` is
    /// replaced; an existing directory is an error.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let from_c = components(from)?;
        let it = match self.resolve_components(&from_c)? {
            Node::Root => return Err(FsError::InvalidInput("cannot rename the root directory")),
            Node::Item(it) => it,
        };
        let (to_parent, to_name) = split_parent(to)?;
        let name16 = validate_name(to_name)?;
        if it.file.is_dir() && to_parent.len() >= from_c.len() {
            let inside = from_c.iter().zip(&to_parent).all(|(a, b)| {
                let (a, b): (Vec<u16>, Vec<u16>) = (a.encode_utf16().collect(), b.encode_utf16().collect());
                self.names_equal(&a, &b)
            });
            if inside {
                return Err(FsError::InvalidInput("cannot move a directory into itself"));
            }
        }
        let to_dir = self.dir_at(&to_parent)?;
        let old_pos = it.file.pos.ok_or(FsError::Corrupt("entry without a position"))?;
        if let Some(existing) = self.find_in_dir(&to_dir, &name16)? {
            if existing.file.pos == Some(old_pos) {
                // The same entry (e.g. a case change): rewrite the name below.
            } else if existing.file.is_dir() {
                return Err(FsError::AlreadyExists);
            } else if it.file.is_dir() {
                return Err(FsError::NotADirectory);
            } else {
                let pos = existing.file.pos.ok_or(FsError::Corrupt("entry without a position"))?;
                self.delete_set(&pos)?;
                self.free_file(&existing.file)?;
            }
        }
        // Insert the new name before removing the old one, so a failure
        // leaves the original entry intact.
        let set = self.build_set(&name16, &it.file);
        self.insert_set(&to_dir, &set)?;
        self.delete_set(&old_pos)
    }

    // ---- file contents --------------------------------------------------------------------

    pub fn read(&mut self, f: &mut FileRef, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if f.is_dir() {
            return Err(FsError::IsADirectory);
        }
        if offset >= f.size || buf.is_empty() {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(f.size - offset) as usize;
        let on_disk = if offset >= f.valid { 0 } else { (n as u64).min(f.valid - offset) as usize };
        if on_disk > 0 {
            let mut done = 0;
            for (dev, len) in self.segments(f.first, f.nofat, offset, on_disk, &mut f.cursor)? {
                self.read_at(dev, &mut buf[done..done + len])?;
                done += len;
            }
        }
        buf[on_disk..n].fill(0);
        Ok(n)
    }

    /// Makes room for a file of `new_size` bytes (clusters only; the
    /// size field is the caller's).
    fn grow_to(&mut self, f: &mut FileRef, new_size: u64) -> Result<()> {
        let cb = self.geo.cluster_bytes();
        let have = if f.first == 0 { 0 } else { f.size.div_ceil(cb) };
        let need = new_size.div_ceil(cb);
        if need <= have {
            return Ok(());
        }
        if need > self.geo.cluster_count as u64 {
            return Err(FsError::NoSpace);
        }
        if f.nofat && have > 0 {
            self.make_chain(f.first, have)?;
            f.nofat = false;
        }
        let mut added: Vec<u32> = Vec::new();
        let mut last = if have == 0 {
            0
        } else {
            let mut cursor = Cursor::default();
            self.cluster_for(f.first, false, (have - 1) as u32, &mut cursor)?
        };
        let old_last = last;
        let mut first_new = 0;
        let mut failure = None;
        for _ in have..need {
            let c = match self.alloc_cluster() {
                Ok(c) => c,
                Err(e) => {
                    failure = Some(e);
                    break;
                }
            };
            added.push(c);
            let linked = if last != 0 { self.fat_set(last, c) } else { Ok(()) }.and_then(|_| self.fat_set(c, FAT_EOC));
            if let Err(e) = linked {
                failure = Some(e);
                break;
            }
            if first_new == 0 {
                first_new = c;
            }
            last = c;
        }
        if let Some(e) = failure {
            for &c in &added {
                let _ = self.fat_set(c, 0);
                self.free_cluster(c);
            }
            if old_last != 0 {
                let _ = self.fat_set(old_last, FAT_EOC);
            }
            return Err(e);
        }
        if have == 0 {
            f.first = first_new;
            f.nofat = false;
        }
        f.cursor = Cursor::default();
        Ok(())
    }

    /// Frees the clusters past `new_size`.
    fn shrink_to(&mut self, f: &mut FileRef, new_size: u64) -> Result<()> {
        let cb = self.geo.cluster_bytes();
        let have = if f.first == 0 { 0 } else { f.size.div_ceil(cb) };
        let need = new_size.div_ceil(cb);
        if need >= have {
            return Ok(());
        }
        if need == 0 {
            self.free_run(f.first, f.nofat, have)?;
            f.first = 0;
            f.nofat = false;
        } else if f.nofat {
            self.free_run(f.first + need as u32, true, have - need)?;
        } else {
            let mut cursor = Cursor::default();
            let keep = self.cluster_for(f.first, false, (need - 1) as u32, &mut cursor)?;
            let tail = self.fat_next(keep)?;
            self.fat_set(keep, FAT_EOC)?;
            self.free_run(tail, false, have - need)?;
        }
        f.cursor = Cursor::default();
        Ok(())
    }

    pub fn write(&mut self, f: &mut FileRef, offset: u64, data: &[u8]) -> Result<usize> {
        if f.is_dir() {
            return Err(FsError::IsADirectory);
        }
        if data.is_empty() {
            return Ok(0);
        }
        let end = offset.checked_add(data.len() as u64).ok_or(FsError::NoSpace)?;
        if end > f.size {
            self.grow_to(f, end)?;
            f.size = end;
        }
        // Bytes between the valid length and the write must read as zero.
        if offset > f.valid {
            let mut at = f.valid;
            let zeros = vec![0u8; 64 << 10];
            while at < offset {
                let n = (offset - at).min(zeros.len() as u64) as usize;
                for (dev, len) in self.segments(f.first, f.nofat, at, n, &mut f.cursor)? {
                    self.write_at(dev, &zeros[..len])?;
                }
                at += n as u64;
            }
        }
        let mut done = 0;
        for (dev, len) in self.segments(f.first, f.nofat, offset, data.len(), &mut f.cursor)? {
            self.write_at(dev, &data[done..done + len])?;
            done += len;
        }
        f.valid = f.valid.max(end);
        self.persist(f, true)?;
        Ok(data.len())
    }

    pub fn truncate(&mut self, f: &mut FileRef, new_size: u64) -> Result<()> {
        if f.is_dir() {
            return Err(FsError::IsADirectory);
        }
        if new_size > f.size {
            // New space reads as zero: the valid length stays where it is.
            self.grow_to(f, new_size)?;
        } else if new_size < f.size {
            self.shrink_to(f, new_size)?;
            f.valid = f.valid.min(new_size);
        }
        f.size = new_size;
        self.persist(f, true)
    }
}
