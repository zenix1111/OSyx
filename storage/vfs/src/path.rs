//! Path syntax: `/`-separated UTF-8 with no NUL bytes.
//!
//! Resolution itself (symbolic links, mount points, `..` across mounts) is
//! done component by component by the kernel VFS; these helpers only deal
//! with the text.

use crate::Result;
use alloc::string::String;
use alloc::vec::Vec;
use osyx_abi::{Errno, MAX_NAME_LEN, MAX_PATH};

/// Checks a whole path argument: non-empty, at most `MAX_PATH` bytes, no NUL.
pub fn validate(path: &str) -> Result<()> {
    if path.is_empty() || path.len() > MAX_PATH || path.contains('\0') {
        return Err(Errno::InvalidArgument);
    }
    Ok(())
}

/// Checks a single name for a new directory entry.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.contains('\0') {
        return Err(Errno::InvalidArgument);
    }
    if name.len() > MAX_NAME_LEN {
        return Err(Errno::InvalidArgument);
    }
    Ok(())
}

/// Components of `path` in order, empty ones (from `//`) dropped. `.` and
/// `..` are kept: their meaning depends on symbolic links met on the way.
pub fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|c| !c.is_empty())
}

/// Splits off the last component: (parent part, name). Trailing slashes are
/// ignored; `None` for paths without a final name (`/`, `.`, `..`, `a/..`).
pub fn split_last(path: &str) -> Option<(&str, &str)> {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let (parent, name) = match trimmed.rfind('/') {
        Some(0) => ("/", &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (".", trimmed),
    };
    if name == "." || name == ".." {
        return None;
    }
    Some((parent, name))
}

/// Lowercase form for case-insensitive name comparison. Unicode lowercase
/// turns a final capital sigma into `ς`; FAT compares through its upcase
/// table, where `ς` and `σ` are the same letter, so fold it back to `σ`.
pub fn fold_case(name: &str) -> String {
    name.to_lowercase().replace('ς', "σ")
}

/// Appends `name` to a canonical absolute directory path.
pub fn join(dir: &str, name: &str) -> String {    let mut s = String::with_capacity(dir.len() + 1 + name.len());
    s.push_str(dir);
    if !dir.ends_with('/') {
        s.push('/');
    }
    s.push_str(name);
    s
}

/// The canonical parent of a canonical absolute path (`/` for `/`).
pub fn parent(canon: &str) -> &str {
    match canon.rfind('/') {
        Some(0) | None => "/",
        Some(i) => &canon[..i],
    }
}

/// Lexical normalisation of `path` against the absolute directory `cwd`
/// (`.` and `..` are applied textually). Used where no file system is
/// consulted, e.g. for mount point bookkeeping; never for access checks.
pub fn normalize(cwd: &str, path: &str) -> Result<String> {
    validate(path)?;
    let mut parts: Vec<&str> = Vec::new();
    if !path.starts_with('/') {
        parts.extend(components(cwd).filter(|c| *c != "."));
    }
    for c in components(path) {
        match c {
            "." => {}
            ".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    Ok(out)
}

/// True if `path` equals `prefix` or lies below it (both canonical).
pub fn is_within(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    path == prefix || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_paths_are_validated() {
        assert!(validate("").is_err());
        assert!(validate("a\0b").is_err());
        assert!(validate(&"x".repeat(MAX_PATH + 1)).is_err());
        assert!(validate("/a/b").is_ok());
        for bad in ["", ".", "..", "a/b", "nul\0"] {
            assert_eq!(validate_name(bad), Err(Errno::InvalidArgument), "{bad:?}");
        }
        assert!(validate_name(&"n".repeat(MAX_NAME_LEN)).is_ok());
        assert!(validate_name(&"n".repeat(MAX_NAME_LEN + 1)).is_err());
        assert!(validate_name("ünïcode ok.txt").is_ok());
    }

    #[test]
    fn split_and_join() {
        assert_eq!(split_last("/a/b/c"), Some(("/a/b", "c")));
        assert_eq!(split_last("/a/"), Some(("/", "a")));
        assert_eq!(split_last("rel"), Some((".", "rel")));
        assert_eq!(split_last("x/y"), Some(("x", "y")));
        assert_eq!(split_last("/"), None);
        assert_eq!(split_last("a/.."), None);
        assert_eq!(split_last("."), None);
        assert_eq!(join("/", "a"), "/a");
        assert_eq!(join("/a", "b"), "/a/b");
        assert_eq!(parent("/a/b"), "/a");
        assert_eq!(parent("/a"), "/");
        assert_eq!(parent("/"), "/");
        assert_eq!(components("//a/./b//").collect::<Vec<_>>(), ["a", ".", "b"]);
    }

    #[test]
    fn lexical_normalisation() {
        assert_eq!(normalize("/", "/a/./b/../c/").unwrap(), "/a/c");
        assert_eq!(normalize("/home/u", "docs/../x").unwrap(), "/home/u/x");
        assert_eq!(normalize("/home", "../../../..").unwrap(), "/");
        assert_eq!(normalize("/w", ".").unwrap(), "/w");
        assert!(normalize("/", "").is_err());
    }

    #[test]
    fn case_folding_handles_final_sigma() {
        assert_eq!(fold_case("ΟΣ.txt"), fold_case("Ος.txt"));
        assert_eq!(fold_case("Ż.txt"), "ż.txt");
        assert_ne!(fold_case("a.txt"), fold_case("b.txt"));
    }

    #[test]
    fn prefix_containment() {
        assert!(is_within("/tmp/x", "/tmp"));
        assert!(is_within("/tmp", "/tmp"));
        assert!(!is_within("/tmpfoo", "/tmp"));
        assert!(is_within("/anything", "/"));
    }
}
