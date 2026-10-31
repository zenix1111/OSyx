//! Initialization files: GetPrivateProfileStringW and
//! WritePrivateProfileStringW (kernel32). Section and key names compare
//! case-insensitively; a file name without a directory lives in
//! C:\Windows, as on Windows. Files are read as UTF-16 (with a BOM), UTF-8
//! or ANSI (Latin-1), and written back in the encoding they had (UTF-8
//! for new files). Values in matching single or double quotes are
//! returned without them.

#![allow(non_snake_case)] // Win32 API names

use crate::kernel32::{cwd_win, fail};
use crate::path;
use alloc::string::String;
use alloc::vec::Vec;

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_MORE_DATA: u32 = 234;

struct Ini {
    /// (section, [(key, value)]), in file order; lines that are neither
    /// are kept as keys without `=` so writing preserves them.
    sections: Vec<(String, Vec<(String, Option<String>)>)>,
    encoding: Encoding,
}

#[derive(Clone, Copy, PartialEq)]
enum Encoding {
    Utf16,
    /// UTF-8, with the byte order mark the file had.
    Utf8 { bom: bool },
    /// Bytes that are not UTF-8: one character per byte (Latin-1), so a
    /// rewrite keeps every byte of the other lines.
    Ansi,
}

fn file_path(name: &str) -> Result<String, u32> {
    let win = if name.contains(['\\', '/', ':']) { String::from(name) } else { alloc::format!("C:\\Windows\\{name}") };
    path::to_osyx(&win, &cwd_win())
}

fn parse(bytes: &[u8]) -> Ini {
    let (text, encoding) = if bytes.starts_with(&[0xFF, 0xFE]) {
        let units: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        (String::from_utf16_lossy(&units), Encoding::Utf16)
    } else {
        let (b, bom) = match bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
            Some(rest) => (rest, true),
            None => (bytes, false),
        };
        match core::str::from_utf8(b) {
            Ok(t) => (String::from(t), Encoding::Utf8 { bom }),
            Err(_) => (b.iter().map(|&c| c as char).collect(), Encoding::Ansi),
        }
    };
    let mut sections: Vec<(String, Vec<(String, Option<String>)>)> = alloc::vec![(String::new(), Vec::new())];
    for line in text.lines() {
        let t = line.trim();
        if let Some(name) = t.strip_prefix('[').and_then(|r| r.split_once(']')).map(|(n, _)| n.trim()) {
            sections.push((String::from(name), Vec::new()));
        } else if let Some((k, v)) = t.split_once('=') {
            sections.last_mut().expect("one section").1.push((String::from(k.trim()), Some(String::from(v.trim()))));
        } else if !t.is_empty() {
            sections.last_mut().expect("one section").1.push((String::from(t), None));
        }
    }
    Ini { sections, encoding }
}

fn render(ini: &Ini) -> Vec<u8> {
    let mut text = String::new();
    for (i, (name, entries)) in ini.sections.iter().enumerate() {
        if i > 0 {
            text.push_str(&alloc::format!("[{name}]\r\n"));
        }
        for (k, v) in entries {
            match v {
                Some(v) => text.push_str(&alloc::format!("{k}={v}\r\n")),
                None => text.push_str(&alloc::format!("{k}\r\n")),
            }
        }
    }
    match ini.encoding {
        Encoding::Utf16 => {
            let mut out = alloc::vec![0xFF, 0xFE];
            for u in text.encode_utf16() {
                out.extend_from_slice(&u.to_le_bytes());
            }
            out
        }
        Encoding::Utf8 { bom } => {
            let mut out = if bom { alloc::vec![0xEF, 0xBB, 0xBF] } else { Vec::new() };
            out.extend_from_slice(text.as_bytes());
            out
        }
        // A character the code page cannot hold becomes '?', as
        // WideCharToMultiByte's default character does.
        Encoding::Ansi => text.chars().map(|c| u8::try_from(c as u32).unwrap_or(b'?')).collect(),
    }
}

/// A value as GetPrivateProfileString returns it: without one pair of
/// matching enclosing quotes.
fn unquote(v: &str) -> &str {
    let b = v.as_bytes();
    if b.len() >= 2 && (b[0] == b'"' || b[0] == b'\'') && b[b.len() - 1] == b[0] {
        &v[1..v.len() - 1]
    } else {
        v
    }
}

fn find<'a>(ini: &'a Ini, section: &str) -> Option<&'a Vec<(String, Option<String>)>> {
    ini.sections.iter().skip(1).find(|(n, _)| n.eq_ignore_ascii_case(section)).map(|(_, e)| e)
}

/// Copies `items` into `buf` (`size` characters) as Windows does: one
/// string, or a NUL-separated list ending with two NULs; returns the
/// characters copied without the final NUL.
fn put(buf: *mut u16, size: u32, items: &[String], list: bool) -> u32 {
    if buf.is_null() || size == 0 {
        return 0;
    }
    let size = size as usize;
    let mut out: Vec<u16> = Vec::new();
    for s in items {
        out.extend(s.encode_utf16());
        if list {
            out.push(0);
        }
    }
    let (n, truncated) = if list {
        // Room for the terminating extra NUL.
        if out.len() + 1 > size { (size.saturating_sub(2), true) } else { (out.len(), false) }
    } else if out.len() + 1 > size {
        (size - 1, true)
    } else {
        (out.len(), false)
    };
    // SAFETY: the caller's buffer holds `size` characters; n + 2 <= size.
    unsafe {
        core::ptr::copy_nonoverlapping(out.as_ptr(), buf, n);
        *buf.add(n) = 0;
        if list && n + 1 < size {
            *buf.add(n + 1) = 0;
        }
    }
    if truncated {
        crate::teb::set_last_error(ERROR_MORE_DATA);
    }
    n as u32
}

pub extern "win64" fn GetPrivateProfileStringW(
    section: *const u16,
    key: *const u16,
    default: *const u16,
    buf: *mut u16,
    size: u32,
    file: *const u16,
) -> u32 {
    // SAFETY: Windows contract: NUL-terminated strings or null.
    let (section, key, default, file) =
        unsafe { (path::wide_to_string(section), path::wide_to_string(key), path::wide_to_string(default), path::wide_to_string(file)) };
    let Some(file) = file else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let default = String::from(default.unwrap_or_default().trim_end());
    let ini = file_path(&file).ok().and_then(|p| os_std::fs::read(&p).ok()).map(|b| parse(&b));
    let Some(ini) = ini else {
        crate::teb::set_last_error(ERROR_FILE_NOT_FOUND);
        // Section and key lists of a missing file are empty; only a value
        // lookup falls back to the default.
        return match (&section, &key) {
            (Some(_), Some(_)) => put(buf, size, &[default], false),
            _ => put(buf, size, &[], true),
        };
    };
    match (section, key) {
        (None, _) => put(buf, size, &ini.sections.iter().skip(1).map(|(n, _)| n.clone()).collect::<Vec<_>>(), true),
        (Some(s), None) => {
            let keys: Vec<String> = find(&ini, &s).map(|e| e.iter().filter(|(_, v)| v.is_some()).map(|(k, _)| k.clone()).collect()).unwrap_or_default();
            put(buf, size, &keys, true)
        }
        (Some(s), Some(k)) => {
            let value = find(&ini, &s).and_then(|e| e.iter().find(|(n, v)| v.is_some() && n.eq_ignore_ascii_case(&k))).and_then(|(_, v)| v.clone());
            put(buf, size, &[value.map_or(default, |v| String::from(unquote(&v)))], false)
        }
    }
}

pub extern "win64" fn WritePrivateProfileStringW(section: *const u16, key: *const u16, value: *const u16, file: *const u16) -> i32 {
    // SAFETY: Windows contract: NUL-terminated strings or null.
    let (section, key, value, file) =
        unsafe { (path::wide_to_string(section), path::wide_to_string(key), path::wide_to_string(value), path::wide_to_string(file)) };
    let (Some(section), Some(file)) = (section, file) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let path = match file_path(&file) {
        Ok(p) => p,
        Err(e) => return fail(e, 0),
    };
    // Only a missing file starts empty: any other read error must not
    // let the write below replace a file whose entries were not read.
    let mut ini = match os_std::fs::read(&path) {
        Ok(b) => parse(&b),
        Err(e) if e.kind() == os_std::error::ErrorKind::NotFound => {
            Ini { sections: alloc::vec![(String::new(), Vec::new())], encoding: Encoding::Utf8 { bom: false } }
        }
        Err(e) if e.kind() == os_std::error::ErrorKind::PermissionDenied => return fail(ERROR_ACCESS_DENIED, 0),
        Err(_) => return fail(ERROR_FILE_NOT_FOUND, 0),
    };
    let at = ini.sections.iter().skip(1).position(|(n, _)| n.eq_ignore_ascii_case(&section)).map(|i| i + 1);
    match (key, at) {
        // No key: the whole section goes.
        (None, Some(i)) => {
            ini.sections.remove(i);
        }
        (None, None) => return 1,
        (Some(k), at) => {
            let i = at.unwrap_or_else(|| {
                ini.sections.push((section.clone(), Vec::new()));
                ini.sections.len() - 1
            });
            let entries = &mut ini.sections[i].1;
            let pos = entries.iter().position(|(n, v)| v.is_some() && n.eq_ignore_ascii_case(&k));
            match (value, pos) {
                (Some(v), Some(p)) => entries[p].1 = Some(v),
                (Some(v), None) => entries.push((k, Some(v))),
                (None, Some(p)) => {
                    entries.remove(p);
                }
                (None, None) => {}
            }
        }
    }
    match os_std::fs::write(&path, render(&ini)) {
        Ok(()) => 1,
        Err(_) => fail(ERROR_FILE_NOT_FOUND, 0),
    }
}
