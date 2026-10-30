//! Path-level operations. Paths are absolute or relative to the root,
//! components separated by `/`; `.` and `..` are resolved; names compare
//! case-insensitively, as on Windows.

use crate::dir::{Item, ATTR_ARCHIVE, ATTR_DIRECTORY, ENTRY_SIZE};
use crate::{BlockDevice, DirEntryInfo, FileRef, FileSystem, FsError, Result};
use alloc::vec::Vec;

/// File or directory attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub is_dir: bool,
    pub size: u32,
    pub attributes: u8,
    pub first_cluster: u32,
}

/// How [`FileSystem::open`] treats missing and existing files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpenOptions {
    /// Create the file if it does not exist.
    pub create: bool,
    /// Fail with `AlreadyExists` if it exists (requires `create`).
    pub create_new: bool,
    /// Truncate an existing file to zero length.
    pub truncate: bool,
}

/// What a path resolves to.
enum Node {
    Root,
    Item(Item),
}

fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|c| !c.is_empty() && *c != ".")
}

/// Splits a path into (parent components, final name).
fn split_parent(path: &str) -> Result<(Vec<&str>, &str)> {
    let mut parts: Vec<&str> = components(path).collect();
    let name = parts.pop().ok_or(FsError::InvalidName)?;
    if name == ".." {
        return Err(FsError::InvalidName);
    }
    Ok((parts, name))
}

impl<D: BlockDevice> FileSystem<D> {
    /// First cluster of a directory item (`..` entries store 0 for the root).
    fn dir_cluster(&self, it: &Item) -> u32 {
        if it.first_cluster == 0 {
            self.geo.root_cluster
        } else {
            it.first_cluster
        }
    }

    fn resolve_parts(&mut self, parts: &[&str]) -> Result<Node> {
        let mut node = Node::Root;
        for part in parts {
            let dir = match &node {
                Node::Root => {
                    if *part == ".." {
                        continue; // the root is its own parent
                    }
                    self.geo.root_cluster
                }
                Node::Item(it) if it.is_dir() => self.dir_cluster(it),
                Node::Item(_) => return Err(FsError::NotADirectory),
            };
            let found = self.find(dir, part)?.ok_or(FsError::NotFound)?;
            let root_parent = found.short == *b"..         " && found.first_cluster == 0;
            if found.is_dir() && !root_parent && !self.geo.is_valid_cluster(found.first_cluster) {
                return Err(FsError::Corrupt("directory starts at an invalid cluster"));
            }
            node = if root_parent { Node::Root } else { Node::Item(found) };
        }
        Ok(node)
    }

    fn resolve(&mut self, path: &str) -> Result<Node> {
        let parts: Vec<&str> = components(path).collect();
        self.resolve_parts(&parts)
    }

    /// Cluster of the directory at `parts`.
    fn dir_at(&mut self, parts: &[&str]) -> Result<u32> {
        match self.resolve_parts(parts)? {
            Node::Root => Ok(self.geo.root_cluster),
            Node::Item(it) if it.is_dir() => Ok(self.dir_cluster(&it)),
            Node::Item(_) => Err(FsError::NotADirectory),
        }
    }

    pub fn metadata(&mut self, path: &str) -> Result<Metadata> {
        Ok(match self.resolve(path)? {
            Node::Root => Metadata { is_dir: true, size: 0, attributes: ATTR_DIRECTORY, first_cluster: self.geo.root_cluster },
            Node::Item(it) => Metadata { is_dir: it.is_dir(), size: it.size, attributes: it.attr, first_cluster: it.first_cluster },
        })
    }

    /// Opens (and optionally creates or truncates) a file.
    pub fn open(&mut self, path: &str, opts: OpenOptions) -> Result<FileRef> {
        let (parent, name) = split_parent(path)?;
        let dir = self.dir_at(&parent)?;
        match self.find(dir, name)? {
            Some(it) => {
                if opts.create_new {
                    return Err(FsError::AlreadyExists);
                }
                if it.is_dir() {
                    return Err(FsError::IsADirectory);
                }
                let mut f = FileRef::new(it.sfn, it.first_cluster, it.size, false);
                if opts.truncate && it.size != 0 {
                    self.truncate(&mut f, 0)?;
                }
                Ok(f)
            }
            None if opts.create || opts.create_new => {
                let pos = self.insert(dir, name, ATTR_ARCHIVE, 0, 0)?;
                Ok(FileRef::new(pos, 0, 0, false))
            }
            None => Err(FsError::NotFound),
        }
    }

    /// Lists a directory (without `.` and `..`).
    pub fn read_dir(&mut self, path: &str) -> Result<Vec<DirEntryInfo>> {
        let parts: Vec<&str> = components(path).collect();
        let dir = self.dir_at(&parts)?;
        Ok(self
            .read_items(dir)?
            .into_iter()
            .filter(|it| !it.is_dot())
            .map(|it| DirEntryInfo { is_dir: it.is_dir(), size: it.size, attributes: it.attr, name: it.name })
            .collect())
    }

    /// Creates a directory (its parent must exist).
    pub fn create_dir(&mut self, path: &str) -> Result<()> {
        let (parent, name) = split_parent(path)?;
        let dir = self.dir_at(&parent)?;
        if self.find(dir, name)?.is_some() {
            return Err(FsError::AlreadyExists);
        }
        crate::dir::validate_name(name)?;
        let c = self.alloc_cluster(None, true)?;
        // "." and ".." entries; ".." of a child of the root stores 0.
        let parent_ref = if dir == self.geo.root_cluster { 0 } else { dir };
        let mut dot = [0u8; ENTRY_SIZE];
        dot[..11].copy_from_slice(b".          ");
        dot[11] = ATTR_DIRECTORY;
        dot[20..22].copy_from_slice(&((c >> 16) as u16).to_le_bytes());
        dot[26..28].copy_from_slice(&(c as u16).to_le_bytes());
        let mut dotdot = dot;
        dotdot[..11].copy_from_slice(b"..         ");
        dotdot[20..22].copy_from_slice(&((parent_ref >> 16) as u16).to_le_bytes());
        dotdot[26..28].copy_from_slice(&(parent_ref as u16).to_le_bytes());
        let lba = self.geo.cluster_lba(c);
        self.write_entry(crate::dir::Pos { lba, offset: 0 }, &dot)?;
        self.write_entry(crate::dir::Pos { lba, offset: ENTRY_SIZE }, &dotdot)?;
        if let Err(e) = self.insert(dir, name, ATTR_DIRECTORY, c, 0) {
            self.free_chain(c)?;
            return Err(e);
        }
        Ok(())
    }

    /// Deletes a file.
    pub fn remove_file(&mut self, path: &str) -> Result<()> {
        match self.resolve(path)? {
            Node::Root => Err(FsError::IsADirectory),
            Node::Item(it) if it.is_dir() => Err(FsError::IsADirectory),
            Node::Item(it) => {
                self.remove_entries(&it)?;
                self.free_chain(it.first_cluster)
            }
        }
    }

    /// Deletes an empty directory.
    pub fn remove_dir(&mut self, path: &str) -> Result<()> {
        match self.resolve(path)? {
            Node::Root => Err(FsError::InvalidInput("cannot remove the root directory")),
            Node::Item(it) if !it.is_dir() => Err(FsError::NotADirectory),
            Node::Item(it) => {
                if it.is_dot() {
                    return Err(FsError::InvalidName);
                }
                let c = self.dir_cluster(&it);
                if self.read_items(c)?.iter().any(|x| !x.is_dot()) {
                    return Err(FsError::DirectoryNotEmpty);
                }
                self.remove_entries(&it)?;
                self.free_chain(it.first_cluster)
            }
        }
    }

    /// Renames or moves a file or directory. An existing *file* at `to` is
    /// replaced; an existing directory is an error.
    pub fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let it = match self.resolve(from)? {
            Node::Root => return Err(FsError::InvalidInput("cannot rename the root directory")),
            Node::Item(it) if it.is_dot() => return Err(FsError::InvalidName),
            Node::Item(it) => it,
        };
        let (to_parent, to_name) = split_parent(to)?;
        crate::dir::validate_name(to_name)?;
        let to_dir = self.dir_at(&to_parent)?;
        if it.is_dir() {
            // Refuse to move a directory into itself or a descendant.
            let mut c = to_dir;
            for _ in 0..self.geo.cluster_count {
                if c == self.dir_cluster(&it) {
                    return Err(FsError::InvalidInput("cannot move a directory into itself"));
                }
                if c == self.geo.root_cluster {
                    break;
                }
                let up = self.find(c, "..")?.ok_or(FsError::Corrupt("directory without '..'"))?;
                c = self.dir_cluster(&up);
            }
        }
        if let Some(existing) = self.find(to_dir, to_name)? {
            if existing.sfn == it.sfn {
                // Same entry (e.g. a case change): rewrite the name below.
            } else if existing.is_dir() {
                return Err(FsError::AlreadyExists);
            } else if it.is_dir() {
                return Err(FsError::NotADirectory);
            } else {
                self.remove_entries(&existing)?;
                self.free_chain(existing.first_cluster)?;
            }
        }
        // Insert the new name before removing the old one, so a failure (e.g.
        // a full directory) leaves the original entry intact. The old slots
        // are occupied, so the insertion cannot reuse them.
        self.insert(to_dir, to_name, it.attr, it.first_cluster, it.size)?;
        self.remove_entries(&it)?;
        if it.is_dir() {
            // Point the moved directory's ".." at its new parent.
            let c = self.dir_cluster(&it);
            if let Some(dd) = self.find(c, "..")? {
                let parent_ref = if to_dir == self.geo.root_cluster { 0 } else { to_dir };
                self.update_entry(dd.sfn, parent_ref, 0)?;
            }
        }
        Ok(())
    }
}
