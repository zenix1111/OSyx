//! TrueType and OpenType font files: the table directory (also inside a
//! TrueType collection), names, metrics, the character map and glyph
//! outlines from `glyf` (simple and composite glyphs). Fonts with CFF
//! outlines are parsed for everything except their outlines.
//!
//! Every read is bounds-checked: a malformed font yields None or empty
//! results, never a panic.
use alloc::string::String;
use alloc::vec::Vec;

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(at..at + 2)?.try_into().ok()?))
}

fn i16_at(d: &[u8], at: usize) -> Option<i16> {
    u16_at(d, at).map(|v| v as i16)
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

pub fn tag(s: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*s)
}

/// One face of a font file.
pub struct Face {
    pub data: alloc::sync::Arc<Vec<u8>>,
    index: u32,
    /// Offset of the face's table directory (non-zero inside a collection).
    dir: usize,
    tables: Vec<(u32, usize, usize)>,
    pub units_per_em: u16,
    pub glyph_count: u16,
    long_loca: bool,
    hmetrics: u16,
    vmetrics: u16,
    cmap: Option<(usize, u16)>,
}

/// A point of an outline in font units; `on` is false for a quadratic
/// control point.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
    pub on: bool,
}

/// Closed contours of points, as `glyf` stores them.
pub type Outline = Vec<Vec<Point>>;

/// Faces in a file: 1, or the count of a TrueType collection.
pub fn face_count(d: &[u8]) -> u32 {
    if d.get(0..4) == Some(b"ttcf") {
        u32_at(d, 8).unwrap_or(0)
    } else {
        1
    }
}

impl Face {
    pub fn parse(data: alloc::sync::Arc<Vec<u8>>, index: u32) -> Option<Face> {
        let d = &data[..];
        let dir = if d.get(0..4) == Some(b"ttcf") {
            if index >= u32_at(d, 8)? {
                return None;
            }
            u32_at(d, 12 + 4 * index as usize)? as usize
        } else if index == 0 {
            0
        } else {
            return None;
        };
        let version = u32_at(d, dir)?;
        if version != 0x0001_0000 && version != tag(b"OTTO") && version != tag(b"true") {
            return None;
        }
        let n = u16_at(d, dir + 4)? as usize;
        let mut tables = Vec::with_capacity(n);
        for i in 0..n {
            let r = dir + 12 + 16 * i;
            let (t, off, len) = (u32_at(d, r)?, u32_at(d, r + 8)? as usize, u32_at(d, r + 12)? as usize);
            if off.checked_add(len)? <= d.len() {
                tables.push((t, off, len));
            }
        }
        let mut f = Face { data: data.clone(), index, dir, tables, units_per_em: 0, glyph_count: 0, long_loca: false, hmetrics: 0, vmetrics: 0, cmap: None };
        let head = f.table(b"head")?;
        let (upem, long_loca) = (u16_at(head, 18).filter(|&u| (16..=16384).contains(&u))?, i16_at(head, 50)? == 1);
        f.units_per_em = upem;
        f.long_loca = long_loca;
        f.glyph_count = u16_at(f.table(b"maxp")?, 4)?;
        f.hmetrics = f.table(b"hhea").and_then(|h| u16_at(h, 34)).unwrap_or(0);
        f.vmetrics = f.table(b"vhea").and_then(|h| u16_at(h, 34)).unwrap_or(0);
        f.cmap = f.pick_cmap();
        Some(f)
    }

    pub fn is_collection(&self) -> bool {
        self.dir != 0 || self.data.get(0..4) == Some(b"ttcf")
    }

    pub fn has_glyf(&self) -> bool {
        self.table(b"glyf").is_some() && self.table(b"loca").is_some()
    }

    pub fn has_outlines(&self) -> bool {
        self.has_glyf() || self.table(b"CFF ").is_some() || self.table(b"CFF2").is_some()
    }

    pub fn table(&self, t: &[u8; 4]) -> Option<&[u8]> {
        let t = tag(t);
        self.tables.iter().find(|e| e.0 == t).map(|&(_, off, len)| &self.data[off..off + len])
    }

    /// A table by its OpenType tag value (as DirectWrite passes it, which
    /// is the tag's bytes in little-endian order).
    pub fn table_by_tag(&self, t: u32) -> Option<&[u8]> {
        self.tables.iter().find(|e| e.0 == t).map(|&(_, off, len)| &self.data[off..off + len])
    }

    // ---- names ----------------------------------------------------------------------------

    /// Name `id`, preferring a Windows English name.
    pub fn name(&self, id: u16) -> Option<String> {
        let t = self.table(b"name")?;
        let count = u16_at(t, 2)? as usize;
        let strings = u16_at(t, 4)? as usize;
        let mut best: Option<(u32, String)> = None;
        for i in 0..count {
            let r = 6 + 12 * i;
            let (platform, encoding, language, nid) = (u16_at(t, r)?, u16_at(t, r + 2)?, u16_at(t, r + 4)?, u16_at(t, r + 6)?);
            if nid != id {
                continue;
            }
            let (len, off) = (u16_at(t, r + 8)? as usize, u16_at(t, r + 10)? as usize);
            let Some(bytes) = t.get(strings + off..strings + off + len) else { continue };
            let (rank, text) = match (platform, encoding) {
                (3, 1) | (3, 10) | (0, _) => {
                    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_be_bytes(*c)).collect();
                    let rank = if platform == 3 && language == 0x409 { 0 } else if platform == 3 { 1 } else { 2 };
                    (rank, String::from_utf16_lossy(&units))
                }
                (1, 0) => (3, bytes.iter().map(|&b| b as char).collect()),
                _ => continue,
            };
            if best.as_ref().is_none_or(|(r, _)| rank < *r) {
                best = Some((rank, text));
            }
        }
        best.map(|(_, s)| s)
    }

    /// The family name programs group faces by (typographic, else legacy).
    pub fn family(&self) -> String {
        self.name(16).or_else(|| self.name(1)).unwrap_or_default()
    }

    pub fn subfamily(&self) -> String {
        self.name(17).or_else(|| self.name(2)).unwrap_or_else(|| String::from("Regular"))
    }

    // ---- style and metrics ------------------------------------------------------------------

    fn os2(&self) -> Option<&[u8]> {
        self.table(b"OS/2")
    }

    pub fn weight(&self) -> u16 {
        self.os2().and_then(|t| u16_at(t, 4)).filter(|&w| (1..=1000).contains(&w)).unwrap_or(400)
    }

    pub fn width_class(&self) -> u16 {
        self.os2().and_then(|t| u16_at(t, 6)).filter(|&w| (1..=9).contains(&w)).unwrap_or(5)
    }

    /// 0 normal, 1 oblique, 2 italic (DWRITE_FONT_STYLE).
    pub fn style(&self) -> u32 {
        let sel = self.os2().and_then(|t| u16_at(t, 62)).unwrap_or(0);
        let mac = self.table(b"head").and_then(|t| u16_at(t, 44)).unwrap_or(0);
        if sel & 0x200 != 0 {
            1
        } else if sel & 1 != 0 || mac & 2 != 0 {
            2
        } else {
            0
        }
    }

    pub fn is_symbol(&self) -> bool {
        self.cmap.is_some_and(|(_, enc)| enc == 0)
    }

    /// (ascent, descent, line gap) in font units, the Windows way:
    /// usWinAscent/Descent with hhea's gap (typo metrics when fsSelection
    /// USE_TYPO_METRICS is set).
    pub fn vertical_metrics(&self) -> (u16, u16, i16) {
        let hhea = self.table(b"hhea");
        let os2 = self.os2();
        let use_typo = os2.and_then(|t| u16_at(t, 62)).is_some_and(|s| s & 0x80 != 0);
        if let Some(t) = os2 {
            if use_typo {
                if let (Some(a), Some(d), Some(g)) = (i16_at(t, 68), i16_at(t, 70), i16_at(t, 72)) {
                    return (a.max(0) as u16, d.unsigned_abs(), g);
                }
            }
            if let (Some(a), Some(d)) = (u16_at(t, 74), u16_at(t, 76)) {
                let gap = hhea.and_then(|h| i16_at(h, 8)).unwrap_or(0);
                // The win metrics already include the gap Windows applies.
                let gap = (gap as i32 - ((a as i32 + d as i32) - (self.hhea_ascent() as i32 - self.hhea_descent() as i32))).max(0) as i16;
                return (a, d, gap);
            }
        }
        (self.hhea_ascent().max(0) as u16, self.hhea_descent().unsigned_abs(), hhea.and_then(|h| i16_at(h, 8)).unwrap_or(0))
    }

    fn hhea_ascent(&self) -> i16 {
        self.table(b"hhea").and_then(|h| i16_at(h, 4)).unwrap_or(self.units_per_em as i16 * 4 / 5)
    }

    fn hhea_descent(&self) -> i16 {
        self.table(b"hhea").and_then(|h| i16_at(h, 6)).unwrap_or(-(self.units_per_em as i16) / 5)
    }

    pub fn cap_height(&self) -> u16 {
        self.os2().filter(|t| u16_at(t, 0).unwrap_or(0) >= 2).and_then(|t| i16_at(t, 88)).map(|v| v.max(0) as u16).unwrap_or(self.units_per_em * 7 / 10)
    }

    pub fn x_height(&self) -> u16 {
        self.os2().filter(|t| u16_at(t, 0).unwrap_or(0) >= 2).and_then(|t| i16_at(t, 86)).map(|v| v.max(0) as u16).unwrap_or(self.units_per_em / 2)
    }

    /// (position, thickness) of the underline (post), in font units.
    pub fn underline(&self) -> (i16, u16) {
        let t = self.table(b"post");
        let pos = t.and_then(|t| i16_at(t, 8)).unwrap_or(-(self.units_per_em as i16) / 10);
        let thick = t.and_then(|t| i16_at(t, 10)).map(|v| v.max(1) as u16).unwrap_or(self.units_per_em / 20);
        (pos, thick)
    }

    /// (position, thickness) of the strikethrough (OS/2), in font units.
    pub fn strikeout(&self) -> (i16, u16) {
        let t = self.os2();
        let size = t.and_then(|t| i16_at(t, 26)).map(|v| v.max(1) as u16).unwrap_or(self.units_per_em / 20);
        let pos = t.and_then(|t| i16_at(t, 28)).unwrap_or(self.units_per_em as i16 * 3 / 10);
        (pos, size)
    }

    // ---- glyph metrics ------------------------------------------------------------------

    /// (advance width, left side bearing).
    pub fn h_metrics(&self, glyph: u16) -> (u16, i16) {
        let Some(t) = self.table(b"hmtx") else { return (self.units_per_em / 2, 0) };
        let n = self.hmetrics.max(1);
        if glyph < n {
            let r = 4 * glyph as usize;
            (u16_at(t, r).unwrap_or(0), i16_at(t, r + 2).unwrap_or(0))
        } else {
            let adv = u16_at(t, 4 * (n as usize - 1)).unwrap_or(0);
            let lsb = i16_at(t, 4 * n as usize + 2 * (glyph - n) as usize).unwrap_or(0);
            (adv, lsb)
        }
    }

    /// (advance height, top side bearing); synthesized from the vertical
    /// metrics without a vmtx table.
    pub fn v_metrics(&self, glyph: u16) -> (u16, i16) {
        match self.table(b"vmtx") {
            Some(t) if self.vmetrics > 0 => {
                let n = self.vmetrics;
                if glyph < n {
                    let r = 4 * glyph as usize;
                    (u16_at(t, r).unwrap_or(0), i16_at(t, r + 2).unwrap_or(0))
                } else {
                    (u16_at(t, 4 * (n as usize - 1)).unwrap_or(0), i16_at(t, 4 * n as usize + 2 * (glyph - n) as usize).unwrap_or(0))
                }
            }
            _ => {
                let (a, d, _) = self.vertical_metrics();
                let top = self.glyph_box(glyph).map_or(0, |b| a as i32 - b.3 as i32);
                ((a as u32 + d as u32).min(u16::MAX as u32) as u16, top as i16)
            }
        }
    }

    // ---- character map ---------------------------------------------------------------------

    /// The best subtable: (offset in cmap, its encoding: 1 BMP, 10 full, 0 symbol).
    fn pick_cmap(&self) -> Option<(usize, u16)> {
        let t = self.table(b"cmap")?;
        let n = u16_at(t, 2)? as usize;
        let mut best: Option<(u8, usize, u16)> = None;
        for i in 0..n {
            let r = 4 + 8 * i;
            let (platform, encoding, off) = (u16_at(t, r)?, u16_at(t, r + 2)?, u32_at(t, r + 4)? as usize);
            let format = u16_at(t, off)?;
            let rank = match (platform, encoding, format) {
                (3, 10, 12) => 0,
                (0, 4, 12) | (0, 6, 12) => 1,
                (3, 1, 4) => 2,
                (0, _, 4) => 3,
                (3, 0, 4) => 4,
                _ => continue,
            };
            if best.is_none_or(|b| rank < b.0) {
                best = Some((rank, off, if platform == 3 { encoding } else { 1 }));
            }
        }
        best.map(|(_, off, enc)| (off, enc))
    }

    /// The glyph of a character (0: none).
    pub fn glyph_index(&self, c: u32) -> u16 {
        let (Some(t), Some((off, encoding))) = (self.table(b"cmap"), self.cmap) else { return 0 };
        // Symbol fonts map U+0020-00FF to F020-F0FF too.
        let lookup = |c: u32| -> Option<u16> {
            match u16_at(t, off)? {
                4 => {
                    if c > 0xFFFF {
                        return None;
                    }
                    let segs = u16_at(t, off + 6)? as usize / 2;
                    let ends = off + 14;
                    let starts = ends + 2 * segs + 2;
                    let deltas = starts + 2 * segs;
                    let ranges = deltas + 2 * segs;
                    // Binary search over the segments' end codes.
                    let (mut lo, mut hi) = (0, segs);
                    while lo < hi {
                        let mid = (lo + hi) / 2;
                        if (u16_at(t, ends + 2 * mid)? as u32) < c {
                            lo = mid + 1;
                        } else {
                            hi = mid;
                        }
                    }
                    if lo >= segs {
                        return None;
                    }
                    let start = u16_at(t, starts + 2 * lo)? as u32;
                    if c < start {
                        return None;
                    }
                    let delta = u16_at(t, deltas + 2 * lo)?;
                    let range = u16_at(t, ranges + 2 * lo)? as usize;
                    if range == 0 {
                        return Some((c as u16).wrapping_add(delta));
                    }
                    let at = ranges + 2 * lo + range + 2 * (c - start) as usize;
                    let g = u16_at(t, at)?;
                    Some(if g == 0 { 0 } else { g.wrapping_add(delta) })
                }
                12 => {
                    let n = u32_at(t, off + 12)? as usize;
                    let (mut lo, mut hi) = (0, n);
                    while lo < hi {
                        let mid = (lo + hi) / 2;
                        let r = off + 16 + 12 * mid;
                        let (s, e) = (u32_at(t, r)?, u32_at(t, r + 4)?);
                        if c < s {
                            hi = mid;
                        } else if c > e {
                            lo = mid + 1;
                        } else {
                            return Some((u32_at(t, r + 8)? + (c - s)) as u16);
                        }
                    }
                    None
                }
                _ => None,
            }
        };
        let g = lookup(c).or_else(|| (encoding == 0 && c <= 0xFF).then(|| lookup(0xF000 + c)).flatten()).unwrap_or(0);
        if g < self.glyph_count { g } else { 0 }
    }

    // ---- outlines --------------------------------------------------------------------------

    fn glyph_data(&self, glyph: u16) -> Option<&[u8]> {
        let loca = self.table(b"loca")?;
        let glyf = self.table(b"glyf")?;
        let i = glyph as usize;
        let (a, b) = if self.long_loca {
            (u32_at(loca, 4 * i)? as usize, u32_at(loca, 4 * i + 4)? as usize)
        } else {
            (u16_at(loca, 2 * i)? as usize * 2, u16_at(loca, 2 * i + 2)? as usize * 2)
        };
        if a >= b {
            return Some(&[]);
        }
        glyf.get(a..b)
    }

    /// The glyph's box (xMin, yMin, xMax, yMax) from its header.
    pub fn glyph_box(&self, glyph: u16) -> Option<(i16, i16, i16, i16)> {
        if !self.has_glyf() {
            return osyx_font::glyph_box(&self.data, self.index, glyph);
        }
        let g = self.glyph_data(glyph)?;
        if g.len() < 10 {
            return None;
        }
        Some((i16_at(g, 2)?, i16_at(g, 4)?, i16_at(g, 6)?, i16_at(g, 8)?))
    }

    /// The glyph's contours in font units (empty for a space).
    pub fn outline(&self, glyph: u16) -> Outline {
        if !self.has_glyf() {
            return osyx_font::outline(&self.data, self.index, glyph)
                .unwrap_or_default().into_iter()
                .map(|contour| contour.into_iter().map(|p| Point { x: p.x, y: p.y, on: p.on }).collect())
                .collect();
        }
        let mut out = Vec::new();
        self.add_outline(glyph, [65536, 0, 0, 65536, 0, 0], &mut out, 0);
        out
    }

    /// Adds `glyph` transformed by a 16.16 matrix (xx, xy, yx, yy, dx, dy).
    fn add_outline(&self, glyph: u16, m: [i64; 6], out: &mut Outline, depth: u32) {
        if depth > 8 {
            return;
        }
        let Some(g) = self.glyph_data(glyph) else { return };
        let Some(contours) = i16_at(g, 0) else { return };
        if contours >= 0 {
            if let Some(cs) = simple(g, contours as usize) {
                let tx = |p: Point| Point {
                    x: ((p.x as i64 * m[0] + p.y as i64 * m[2]) / 65536 + m[4]) as i32,
                    y: ((p.x as i64 * m[1] + p.y as i64 * m[3]) / 65536 + m[5]) as i32,
                    on: p.on,
                };
                out.extend(cs.into_iter().map(|c| c.into_iter().map(tx).collect()));
            }
            return;
        }
        // A composite: components with their offsets and scales.
        let mut at = 10;
        loop {
            let (Some(flags), Some(child)) = (u16_at(g, at), u16_at(g, at + 2)) else { return };
            at += 4;
            let (dx, dy) = if flags & 1 != 0 {
                let r = (i16_at(g, at), i16_at(g, at + 2));
                at += 4;
                (r.0.unwrap_or(0) as i64, r.1.unwrap_or(0) as i64)
            } else {
                let r = (g.get(at).map(|&b| b as i8), g.get(at + 1).map(|&b| b as i8));
                at += 2;
                (r.0.unwrap_or(0) as i64, r.1.unwrap_or(0) as i64)
            };
            let f2 = |at: usize| i16_at(g, at).unwrap_or(0) as i64 * 4; // F2Dot14 to 16.16
            let (mut a, mut b, mut c, mut d) = (65536, 0, 0, 65536);
            if flags & 0x8 != 0 {
                a = f2(at);
                d = a;
                at += 2;
            } else if flags & 0x40 != 0 {
                a = f2(at);
                d = f2(at + 2);
                at += 4;
            } else if flags & 0x80 != 0 {
                a = f2(at);
                b = f2(at + 2);
                c = f2(at + 4);
                d = f2(at + 6);
                at += 8;
            }
            // Only offsets given as x/y values (ARGS_ARE_XY_VALUES) are
            // supported; point matching places the component unmoved.
            let (dx, dy) = if flags & 2 != 0 { (dx, dy) } else { (0, 0) };
            // Child matrix, then the parent's.
            let cm = [a, b, c, d, dx, dy];
            let comb = [
                (cm[0] * m[0] + cm[1] * m[2]) / 65536,
                (cm[0] * m[1] + cm[1] * m[3]) / 65536,
                (cm[2] * m[0] + cm[3] * m[2]) / 65536,
                (cm[2] * m[1] + cm[3] * m[3]) / 65536,
                (cm[4] * m[0] + cm[5] * m[2]) / 65536 + m[4],
                (cm[4] * m[1] + cm[5] * m[3]) / 65536 + m[5],
            ];
            self.add_outline(child, comb, out, depth + 1);
            if flags & 0x20 == 0 {
                return;
            }
        }
    }
}

/// The contours of a simple glyph with `n` contours.
fn simple(g: &[u8], n: usize) -> Option<Outline> {
    let mut ends = Vec::with_capacity(n);
    for i in 0..n {
        ends.push(u16_at(g, 10 + 2 * i)? as usize);
    }
    let points = ends.last().map_or(0, |&e| e + 1);
    if points > 0xFFFF {
        return None;
    }
    let ins = u16_at(g, 10 + 2 * n)? as usize;
    let mut at = 12 + 2 * n + ins;
    let mut flags = Vec::with_capacity(points);
    while flags.len() < points {
        let f = *g.get(at)?;
        at += 1;
        flags.push(f);
        if f & 8 != 0 {
            let repeat = *g.get(at)?;
            at += 1;
            for _ in 0..repeat {
                flags.push(f);
            }
        }
    }
    flags.truncate(points);
    let mut coord = |short: u8, same: u8| -> Option<Vec<i32>> {
        let mut v = 0i32;
        let mut out = Vec::with_capacity(points);
        for &f in &flags {
            if f & short != 0 {
                let d = *g.get(at)? as i32;
                at += 1;
                v += if f & same != 0 { d } else { -d };
            } else if f & same == 0 {
                v += i16_at(g, at)? as i32;
                at += 2;
            }
            out.push(v);
        }
        Some(out)
    };
    let xs = coord(2, 16)?;
    let ys = coord(4, 32)?;
    let mut contours = Vec::with_capacity(n);
    let mut start = 0;
    for &e in &ends {
        if e < start || e >= points {
            return None;
        }
        contours.push((start..=e).map(|i| Point { x: xs[i], y: ys[i], on: flags[i] & 1 != 0 }).collect());
        start = e + 1;
    }
    Some(contours)
}
