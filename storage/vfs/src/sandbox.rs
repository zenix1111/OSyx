//! Building blocks for filesystem sandbox policies.
//!
//! These rules do not enforce a sandbox on their own. The kernel must check
//! resolved paths and all existing or transferred handles before use.

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::{path, Access, Result};
use osyx_abi::Errno;

/// An immutable allowlist of canonical, absolute filesystem subtrees.
///
/// Callers must resolve symbolic links and mount crossings before checking a
/// path. Never pass a lexically normalised user-supplied path as a resolved
/// path. Permissions from overlapping rules are combined.
#[derive(Clone, Debug, Default)]
pub struct PathPolicy {
    rules: Vec<(String, Access)>,
}

impl PathPolicy {
    /// Reject ambiguous paths instead of silently normalising them.
    pub fn new(rules: &[(&str, Access)]) -> Result<Self> {
        let mut out = Vec::with_capacity(rules.len());
        for &(prefix, access) in rules {
            canonical(prefix)?;
            out.push((prefix.to_string(), access));
        }
        Ok(Self { rules: out })
    }

    /// Check access to a resolved node. No matching rule means denial.
    pub fn allows(&self, resolved: &str, want: Access) -> bool {
        if canonical(resolved).is_err() {
            return false;
        }
        let mut granted = Access::default();
        let mut matched = false;
        for (prefix, access) in &self.rules {
            if path::is_within(resolved, prefix) {
                matched = true;
                granted.read |= access.read;
                granted.write |= access.write;
                granted.exec |= access.exec;
            }
        }
        matched && (!want.read || granted.read) && (!want.write || granted.write) && (!want.exec || granted.exec)
    }

    /// Ancestors may be traversed to reach a permitted subtree, but traversal
    /// does not grant permission to list or otherwise access those ancestors.
    pub fn may_traverse(&self, resolved_dir: &str) -> bool {
        canonical(resolved_dir).is_ok()
            && self.rules.iter().any(|(prefix, access)| {
                (access.read || access.write || access.exec)
                    && (path::is_within(prefix, resolved_dir) || path::is_within(resolved_dir, prefix))
            })
    }

    /// Metadata of an ancestor is needed for component-by-component lookup.
    /// This does not authorize opening or listing that directory.
    pub fn may_inspect_ancestor(&self, resolved: &str) -> bool {
        canonical(resolved).is_ok()
            && self.rules.iter().any(|(prefix, access)| {
                (access.read || access.write || access.exec)
                    && prefix != resolved && path::is_within(prefix, resolved)
            })
    }
}

fn canonical(p: &str) -> Result<()> {
    path::validate(p)?;
    if !p.starts_with('/') || (p != "/" && (p.ends_with('/') || p.split('/').skip(1).any(|c| c.is_empty() || c == "." || c == ".."))) {
        return Err(Errno::InvalidArgument);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_deny_and_matches_component_boundaries() {
        let empty = PathPolicy::default();
        assert!(!empty.allows("/", Access::READ));
        assert!(!empty.may_traverse("/"));
        let policy = PathPolicy::new(&[("/app/data", Access::READ)]).unwrap();
        assert!(policy.allows("/app/data/file", Access::READ));
        assert!(!policy.allows("/app/database", Access::READ));
        assert!(!policy.allows("/app/data/file", Access::WRITE));
        assert!(policy.may_traverse("/app"));
        assert!(policy.may_inspect_ancestor("/app"));
        assert!(!policy.may_inspect_ancestor("/app/data"));
        assert!(!policy.may_inspect_ancestor("/other"));
        assert!(!policy.allows("/app", Access::READ));
        assert!(!policy.may_traverse("/other"));
    }

    #[test]
    fn rejects_ambiguous_paths_and_combines_overlapping_rules() {
        for bad in ["", "relative", "/a/", "/a//b", "/a/./b", "/a/../b", "/a\0b"] {
            assert!(PathPolicy::new(&[(bad, Access::READ)]).is_err(), "{bad:?}");
        }
        let policy = PathPolicy::new(&[("/app", Access::READ), ("/app/data", Access::WRITE)]).unwrap();
        assert!(policy.allows("/app/data/file", Access { read: true, write: true, exec: false }));
        assert!(!policy.allows("/app/data/../secret", Access::READ));
        assert!(!policy.allows("/APP/data", Access::READ));
        assert!(!policy.allows("/app/data/file", Access::EXEC));
    }

    #[test]
    fn root_rule_and_empty_permissions() {
        let policy = PathPolicy::new(&[("/", Access::READ)]).unwrap();
        assert!(policy.allows("/", Access::READ));
        assert!(policy.allows("/x", Access::READ));
        let no_access = PathPolicy::new(&[("/x", Access::default())]).unwrap();
        assert!(!no_access.may_traverse("/"));
        assert!(!no_access.allows("/x", Access::READ));
    }
}
