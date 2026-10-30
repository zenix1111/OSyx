//! Multi-selection and copy naming.

use alloc::string::String;
use alloc::vec::Vec;

/// Rows from `a` to `b`, both included, whichever comes first.
pub fn range(a: usize, b: usize) -> Vec<usize> {
    (a.min(b)..=a.max(b)).collect()
}

/// Rows whose vertical span `[row * h, row * h + h)` meets `[y0, y1]`
/// (pixels from the top of the list), for a rubber band; `rows` limits.
pub fn rows_in_band(y0: i32, y1: i32, row_height: u32, rows: usize) -> Vec<usize> {
    if rows == 0 || row_height == 0 {
        return Vec::new();
    }
    let (lo, hi) = (y0.min(y1).max(0), y0.max(y1));
    if hi < 0 {
        return Vec::new();
    }
    let first = lo as u32 / row_height;
    let last = hi as u32 / row_height;
    (first..=last).map(|r| r as usize).filter(|&r| r < rows).collect()
}

/// A name for `name` that is not in `taken`: `name` itself, else
/// `name (copy)`, `name (copy 2)`, ... with the extension kept at the end.
pub fn free_name(name: &str, taken: impl Fn(&str) -> bool) -> String {
    if !taken(name) {
        return String::from(name);
    }
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    for n in 1u32.. {
        let candidate = if n == 1 { alloc::format!("{stem} (copy){ext}") } else { alloc::format!("{stem} (copy {n}){ext}") };
        if !taken(&candidate) {
            return candidate;
        }
    }
    unreachable!()
}

/// True if `inner` is `outer` or lies below it (paths without a trailing slash).
pub fn is_inside(inner: &str, outer: &str) -> bool {
    let outer = outer.trim_end_matches('/');
    inner == outer || inner.strip_prefix(outer).is_some_and(|r| r.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(range(2, 4), [2, 3, 4]);
        assert_eq!(range(4, 2), [2, 3, 4]);
        assert_eq!(range(3, 3), [3]);
    }

    #[test]
    fn bands() {
        // 30 px rows: 10..70 touches rows 0, 1 and 2.
        assert_eq!(rows_in_band(10, 70, 30, 10), [0, 1, 2]);
        assert_eq!(rows_in_band(70, 10, 30, 10), [0, 1, 2]);
        assert_eq!(rows_in_band(-50, 20, 30, 10), [0]);
        assert_eq!(rows_in_band(100, 400, 30, 5), [3, 4]);
        assert!(rows_in_band(0, 10, 30, 0).is_empty());
        assert!(rows_in_band(-20, -5, 30, 4).is_empty());
    }

    #[test]
    fn copy_names() {
        let taken = |n: &str| matches!(n, "a.txt" | "a (copy).txt" | "dir" | ".rc");
        assert_eq!(free_name("b.txt", taken), "b.txt");
        assert_eq!(free_name("a.txt", taken), "a (copy 2).txt");
        assert_eq!(free_name("dir", taken), "dir (copy)");
        assert_eq!(free_name(".rc", taken), ".rc (copy)");
    }

    #[test]
    fn nesting() {
        assert!(is_inside("/a/b", "/a"));
        assert!(is_inside("/a", "/a/"));
        assert!(!is_inside("/ab", "/a"));
        assert!(is_inside("/a/b/c", "/a/b"));
    }
}
