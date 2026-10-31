//! Software GDI surfaces and state. DIB storage never moves while its handle
//! lives: applications may keep the pointer returned by CreateDIBSection.
use super::*;

const MAX_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_BITMAP: u64 = STOCK_BASE + 21;
const GDI_ERROR: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub(super) struct Xform {
    a: f32,
    b: f32,
    c: f32,
    d: f32,
    x: f32,
    y: f32,
}
impl Xform {
    pub const IDENTITY: Self = Self { a: 1.0, b: 0.0, c: 0.0, d: 1.0, x: 0.0, y: 0.0 };
    pub fn point(self, x: i32, y: i32) -> (i32, i32) {
        let (x, y) = (x as f32, y as f32);
        ((x * self.a + y * self.c + self.x) as i32, (x * self.b + y * self.d + self.y) as i32)
    }
    pub fn rect(self, r: Rect4) -> Rect {
        let p = [self.point(r.0, r.1), self.point(r.2, r.1), self.point(r.0, r.3), self.point(r.2, r.3)];
        let l = p.iter().map(|p| p.0).min().unwrap();
        let t = p.iter().map(|p| p.1).min().unwrap();
        let r = p.iter().map(|p| p.0).max().unwrap();
        let b = p.iter().map(|p| p.1).max().unwrap();
        Rect::new(l, t, r.saturating_sub(l) as u32, b.saturating_sub(t) as u32)
    }
    fn then(self, n: Self) -> Self {
        Self {
            a: self.a * n.a + self.b * n.c,
            b: self.a * n.b + self.b * n.d,
            c: self.c * n.a + self.d * n.c,
            d: self.c * n.b + self.d * n.d,
            x: self.x * n.a + self.y * n.c + n.x,
            y: self.x * n.b + self.y * n.d + n.y,
        }
    }
    fn valid(self) -> bool {
        [self.a, self.b, self.c, self.d, self.x, self.y].iter().all(|v| v.is_finite())
    }
}

#[derive(Clone)]
struct Dib {
    w: u32,
    h: u32,
    top: bool,
    bpp: u16,
    stride: usize,
    compression: u32,
    masks: [u32; 3],
    palette: Vec<Color>,
}
impl Dib {
    fn new(w: i32, h: i32, bpp: u16) -> Option<Self> {
        if w <= 0 || h == 0 || h == i32::MIN || !matches!(bpp, 1 | 8 | 16 | 24 | 32) {
            return None;
        }
        let stride = (w as usize).checked_mul(bpp as usize)?.div_ceil(32).checked_mul(4)?;
        if stride.checked_mul(h.unsigned_abs() as usize)? > MAX_BYTES {
            return None;
        }
        let palette = if bpp <= 8 {
            (0..1u32 << bpp)
                .map(|i| {
                    if bpp == 8 {
                        rgb(((i >> 5) * 255 / 7) as u8, (((i >> 2) & 7) * 255 / 7) as u8, ((i & 3) * 255 / 3) as u8)
                    } else {
                        let v = (i * 255 / ((1 << bpp) - 1)) as u8;
                        rgb(v, v, v)
                    }
                })
                .collect()
        } else {
            Vec::new()
        };
        Some(Self {
            w: w as u32,
            h: h.unsigned_abs(),
            top: h < 0,
            bpp,
            stride,
            compression: 0,
            masks: if bpp == 16 { [0x7c00, 0x3e0, 0x1f] } else { [0xff0000, 0xff00, 0xff] },
            palette,
        })
    }
    fn read(p: *const u8, usage: u32) -> Option<Self> {
        if p.is_null() || usage != 0 {
            return None;
        }
        // SAFETY: caller supplies BITMAPINFO including masks / palette.
        unsafe {
            let size = teb::get::<u32>(p as u64, 0);
            if !(40..=124).contains(&size) || teb::get::<u16>(p as u64, 12) != 1 {
                return None;
            }
            let mut d = Self::new(teb::get(p as u64, 4), teb::get(p as u64, 8), teb::get(p as u64, 14))?;
            d.compression = teb::get(p as u64, 16);
            match d.compression {
                0 => (),
                3 if matches!(d.bpp, 16 | 32) => {
                    let off = if size >= 52 { 40 } else { size as usize };
                    for i in 0..3 {
                        d.masks[i] = teb::get(p as u64, off + i * 4);
                    }
                    if d.masks.contains(&0)
                        || d.masks[0] & d.masks[1] != 0
                        || d.masks[1] & d.masks[2] != 0
                        || d.masks[0] & d.masks[2] != 0
                    {
                        return None;
                    }
                }
                _ => return None,
            }
            if d.bpp <= 8 {
                let n = teb::get::<u32>(p as u64, 32);
                let n = if n == 0 { 1 << d.bpp } else { n };
                if n > 1 << d.bpp {
                    return None;
                }
                for i in 0..n as usize {
                    d.palette[i] = teb::get::<u32>(p as u64, size as usize + i * 4) | 0xff000000;
                }
            }
            Some(d)
        }
    }
    fn bytes(&self) -> usize {
        self.stride * self.h as usize
    }
    fn header(&self, out: *mut u8) {
        // SAFETY: output points to a BITMAPINFOHEADER (40 bytes).
        unsafe {
            core::ptr::write_bytes(out, 0, 40);
            teb::put(out as u64, 0, 40u32);
            teb::put(out as u64, 4, self.w as i32);
            teb::put(out as u64, 8, if self.top { -(self.h as i32) } else { self.h as i32 });
            teb::put(out as u64, 12, 1u16);
            teb::put(out as u64, 14, self.bpp);
            teb::put(out as u64, 16, self.compression);
            teb::put(out as u64, 20, self.bytes() as u32);
        }
    }
    fn offset(&self, x: u32, y: u32) -> usize {
        let row = if self.top { y } else { self.h - 1 - y };
        row as usize * self.stride + x as usize * self.bpp as usize / 8
    }
    fn pixel(&self, bits: &[u8], x: u32, y: u32) -> Color {
        let off = self.offset(x, y);
        if self.bpp == 32 && self.compression == 0 {
            return u32::from_le_bytes(bits[off..off + 4].try_into().unwrap());
        }
        match self.bpp {
            1 => self.palette[((bits[off] >> (7 - x % 8)) & 1) as usize],
            8 => self.palette[bits[off] as usize],
            24 => rgb(bits[off + 2], bits[off + 1], bits[off]),
            _ => {
                let v = if self.bpp == 16 {
                    u16::from_le_bytes([bits[off], bits[off + 1]]) as u32
                } else {
                    u32::from_le_bytes(bits[off..off + 4].try_into().unwrap())
                };
                let c = self.masks.map(|m| {
                    let n = m >> m.trailing_zeros();
                    (((v & m) >> m.trailing_zeros()) as u64 * 255 / n as u64) as u8
                });
                rgb(c[0], c[1], c[2])
            }
        }
    }
    fn put(&self, bits: &mut [u8], x: u32, y: u32, color: Color) {
        let off = self.offset(x, y);
        if self.bpp == 32 && self.compression == 0 {
            bits[off..off + 4].copy_from_slice(&color.to_le_bytes());
            return;
        }
        let c = [(color >> 16) & 255, (color >> 8) & 255, color & 255];
        match self.bpp {
            1 | 8 => {
                let index = self
                    .palette
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, p)| {
                        let pc = [(*p >> 16) & 255, (*p >> 8) & 255, *p & 255];
                        pc.iter().zip(c).map(|(a, b)| (*a as i32 - b as i32).pow(2)).sum::<i32>()
                    })
                    .map(|(i, _)| i)
                    .unwrap_or(0) as u8;
                if self.bpp == 8 {
                    bits[off] = index;
                } else {
                    let mask = 1 << (7 - x % 8);
                    bits[off] = (bits[off] & !mask) | if index != 0 { mask } else { 0 };
                }
            }
            24 => bits[off..off + 3].copy_from_slice(&[c[2] as u8, c[1] as u8, c[0] as u8]),
            _ => {
                let mut v = 0;
                for (m, c) in self.masks.iter().zip(c) {
                    let shift = m.trailing_zeros();
                    v |= ((c as u64 * (m >> shift) as u64 / 255) as u32) << shift;
                }
                let bytes = v.to_le_bytes();
                let n = self.bpp as usize / 8;
                bits[off..off + n].copy_from_slice(&bytes[..n]);
            }
        }
    }
}

pub(super) struct Bitmap {
    dib: Dib,
    storage: Vec<u32>,
    section: bool,
}
impl Bitmap {
    fn new(dib: Dib, section: bool) -> Self {
        let words = dib.bytes().div_ceil(4);
        Self::with_storage(dib, section, alloc::vec![0; words])
    }
    fn with_storage(dib: Dib, section: bool, mut storage: Vec<u32>) -> Self {
        let words = dib.bytes().div_ceil(4);
        if storage.len() < words {
            storage.resize(words, 0);
        } else {
            storage.truncate(words);
        }
        Self { dib, storage, section }
    }
    pub(super) fn into_storage(self) -> Vec<u32> {
        self.storage
    }
    fn bits(&self) -> &[u8] {
        // SAFETY: owned word storage is large enough for the DIB.
        unsafe { core::slice::from_raw_parts(self.storage.as_ptr().cast(), self.dib.bytes()) }
    }
    fn bits_mut(&mut self) -> &mut [u8] {
        // SAFETY: exclusive owned word storage, allocated once for this DIB.
        unsafe { core::slice::from_raw_parts_mut(self.storage.as_mut_ptr().cast(), self.dib.bytes()) }
    }
    fn pixels(&self) -> Vec<Color> {
        (0..self.dib.h).flat_map(|y| (0..self.dib.w).map(move |x| self.dib.pixel(self.bits(), x, y))).collect()
    }
    fn store(&mut self, pixels: &[Color]) {
        let d = self.dib.clone();
        let bits = self.bits_mut();
        for y in 0..d.h {
            for x in 0..d.w {
                d.put(bits, x, y, pixels[(y * d.w + x) as usize]);
            }
        }
    }
}

/// An independent copy of a bitmap (icons keep their own), or None.
pub(super) fn duplicate_bitmap(g: &mut Gui, h: u64) -> Option<u64> {
    let b = g.bitmaps.get(&h)?;
    let copy = Bitmap { dib: b.dib.clone(), storage: b.storage.clone(), section: false };
    Some(insert_bitmap(g, copy))
}

fn insert_bitmap(g: &mut Gui, b: Bitmap) -> u64 {
    let h = g.handle();
    g.bitmaps.insert(h, b);
    g.gdi.insert(h, Gdi::Bitmap);
    h
}
pub(super) fn display_dc() -> u64 {
    let r = screen_rect();
    with(|g| new_dc(g, 0, Rect::new(0, 0, r.2 as u32, r.3 as u32)))
}
extern "win64" fn CreateDCW(driver: *const u16, device: *const u16, _output: *const u16, _mode: *const u8) -> u64 {
    // SAFETY: optional caller-supplied NUL-terminated device names.
    let name = unsafe { path::wide_to_string(driver).or_else(|| path::wide_to_string(device)) }.unwrap_or_default();
    if name.eq_ignore_ascii_case("DISPLAY") || name.starts_with("\\\\.\\DISPLAY") {
        display_dc()
    } else {
        fail(ERROR_NOT_SUPPORTED, 0)
    }
}
extern "win64" fn CreateDCA(driver: *const u8, device: *const u8, _output: *const u8, _mode: *const u8) -> u64 {
    // SAFETY: optional caller-supplied NUL-terminated device names.
    let name = unsafe { path::ansi_to_string(driver).or_else(|| path::ansi_to_string(device)) }.unwrap_or_default();
    if name.eq_ignore_ascii_case("DISPLAY") || name.starts_with("\\\\.\\DISPLAY") {
        display_dc()
    } else {
        fail(ERROR_NOT_SUPPORTED, 0)
    }
}
extern "win64" fn CreateICW(a: *const u16, b: *const u16, c: *const u16, d: *const u8) -> u64 {
    CreateDCW(a, b, c, d)
}
extern "win64" fn CreateCompatibleDC(dc: u64) -> u64 {
    with(|g| {
        if dc != 0 && !g.dcs.contains_key(&dc) {
            return fail(ERROR_INVALID_HANDLE, 0);
        }
        if let alloc::collections::btree_map::Entry::Vacant(e) = g.bitmaps.entry(DEFAULT_BITMAP) {
            e.insert(Bitmap::new(Dib::new(1, 1, 1).unwrap(), false));
            g.gdi.insert(DEFAULT_BITMAP, Gdi::Bitmap);
        }
        let h = new_dc(g, 0, Rect::new(0, 0, i32::MAX as u32, i32::MAX as u32));
        let d = g.dcs.get_mut(&h).unwrap();
        d.memory = true;
        d.bitmap = DEFAULT_BITMAP;
        h
    })
}
extern "win64" fn DeleteDC(dc: u64) -> Bool {
    with(|g| g.dcs.remove(&dc).is_some()) as Bool
}
extern "win64" fn CreateCompatibleBitmap(dc: u64, w: i32, h: i32) -> u64 {
    with(|g| {
        let Some(d) = g.dcs.get(&dc) else { return 0 };
        let bpp = if d.memory { g.bitmaps.get(&d.bitmap).map(|b| b.dib.bpp).unwrap_or(1) } else { 32 };
        let Some(dib) = Dib::new(w.max(1), h.max(1), bpp) else { return 0 };
        if w < 0 || h < 0 {
            return 0;
        }
        let words = dib.bytes().div_ceil(4);
        let storage = g.take_bitmap_storage(words);
        insert_bitmap(g, Bitmap::with_storage(dib, false, storage))
    })
}
extern "win64" fn CreateBitmap(w: i32, h: i32, planes: u32, bpp: u32, bits: *const u8) -> u64 {
    if planes != 1 || bpp > u16::MAX as u32 {
        return 0;
    }
    let Some(dib) = Dib::new(w, h, bpp as u16) else { return 0 };
    let mut bitmap = Bitmap::new(dib, false);
    if !bits.is_null() {
        // DDB source rows are WORD aligned, unlike DIB rows (DWORD aligned).
        let stride = (w as usize * bpp as usize).div_ceil(16) * 2;
        let dst_stride = bitmap.dib.stride;
        for y in 0..bitmap.dib.h as usize {
            // SAFETY: caller provides initialized DDB data, height WORD-aligned rows.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    bits.add(y * stride),
                    bitmap.bits_mut().as_mut_ptr().add(y * dst_stride),
                    stride,
                );
            }
        }
    }
    with(|g| insert_bitmap(g, bitmap))
}
extern "win64" fn CreateDIBSection(
    _dc: u64,
    info: *const u8,
    usage: u32,
    out: *mut *mut u8,
    section: u64,
    _offset: u32,
) -> u64 {
    if out.is_null() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    // SAFETY: caller's output pointer; clear it on all failure paths.
    unsafe {
        *out = core::ptr::null_mut();
    }
    if section != 0 {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    let Some(dib) = Dib::read(info, usage) else { return fail(ERROR_INVALID_PARAMETER, 0) };
    let words = dib.bytes().div_ceil(4);
    let storage = with(|g| g.take_bitmap_storage(words));
    let mut b = Bitmap::with_storage(dib, true, storage);
    // SAFETY: storage remains at this address until DeleteObject.
    unsafe {
        *out = b.storage.as_mut_ptr().cast();
    }
    with(|g| insert_bitmap(g, b))
}
extern "win64" fn CreateDIBitmap(
    dc: u64,
    header: *const u8,
    init: u32,
    bits: *const u8,
    info: *const u8,
    usage: u32,
) -> u64 {
    if header.is_null() || !with(|g| g.dcs.contains_key(&dc)) {
        return 0;
    }
    // SAFETY: caller's BITMAPINFOHEADER.
    let (w, h) = unsafe { (teb::get::<i32>(header as u64, 4), teb::get::<i32>(header as u64, 8)) };
    let Some(dib) = Dib::new(w, h, 32) else { return 0 };
    let handle = with(|g| insert_bitmap(g, Bitmap::new(dib, false)));
    if init & 4 != 0 && SetDIBits(dc, handle, 0, h.unsigned_abs(), bits, info, usage) == 0 {
        DeleteObject(handle);
        return 0;
    }
    handle
}
extern "win64" fn GetObjectW(obj: u64, size: i32, out: *mut u8) -> i32 {
    with(|g| {
        let Some(b) = g.bitmaps.get(&obj) else { return 0 };
        if out.is_null() {
            return 32;
        }
        if size < 32 {
            return 0;
        }
        let n = if b.section && size >= 104 { 104 } else { 32 };
        // BITMAP: 32 bytes; DIBSECTION: 104 bytes on Windows x64.
        // SAFETY: caller provided at least n output bytes.
        unsafe {
            core::ptr::write_bytes(out, 0, n);
            teb::put(out as u64, 4, b.dib.w as i32);
            teb::put(out as u64, 8, b.dib.h as i32);
            teb::put(
                out as u64,
                12,
                if b.section {
                    b.dib.stride as i32
                } else {
                    (b.dib.w as u64 * b.dib.bpp as u64).div_ceil(16) as i32 * 2
                },
            );
            teb::put(out as u64, 16, 1u16);
            teb::put(out as u64, 18, b.dib.bpp);
            if b.section {
                teb::put(out as u64, 24, b.storage.as_ptr() as u64);
            }
            if n == 104 {
                b.dib.header(out.add(32));
                teb::put(out as u64, 40, b.dib.h as i32);
                for i in 0..3 {
                    teb::put(out as u64, 72 + i * 4, b.dib.masks[i]);
                }
            }
        }
        n as i32
    })
}

extern "win64" fn GetDIBits(
    dc: u64,
    bmp: u64,
    start: u32,
    lines: u32,
    bits: *mut u8,
    info: *mut u8,
    usage: u32,
) -> i32 {
    if info.is_null() || usage != 0 {
        return 0;
    }
    with(|g| {
        if !g.dcs.contains_key(&dc) {
            return 0;
        }
        let Some(b) = g.bitmaps.get(&bmp) else { return 0 };
        // SAFETY: caller supplies BITMAPINFOHEADER and palette when necessary.
        unsafe {
            if teb::get::<u32>(info as u64, 0) < 40 {
                return 0;
            }
            if teb::get::<u16>(info as u64, 14) == 0 {
                b.dib.header(info);
                return b.dib.h as i32;
            }
        }
        let Some(mut d) = Dib::read(info, usage) else { return 0 };
        if d.w != b.dib.w {
            return 0;
        }
        if d.bpp <= 8 {
            d.palette = Dib::new(d.w as i32, d.h as i32, d.bpp).unwrap().palette;
            for (i, c) in d.palette.iter().enumerate() {
                // SAFETY: caller supplies color table space for the requested format.
                unsafe {
                    teb::put(info as u64, 40 + i * 4, *c & 0xffffff);
                }
            }
        }
        d.header(info);
        if bits.is_null() {
            return d.h as i32;
        }
        let n = lines.min(b.dib.h.saturating_sub(start)).min(d.h.saturating_sub(start));
        // SAFETY: caller's output holds n requested scan lines, not the full bitmap.
        let out = unsafe { core::slice::from_raw_parts_mut(bits, n as usize * d.stride) };
        let mut one = d.clone();
        one.h = n;
        one.top = true;
        for row in 0..n {
            for x in 0..d.w {
                let y = if d.top { b.dib.h - start - n + row } else { b.dib.h - 1 - start - row };
                let color = b.dib.pixel(b.bits(), x, y);
                one.put(out, x, row, color);
            }
        }
        n as i32
    })
}
extern "win64" fn SetDIBits(
    dc: u64,
    bmp: u64,
    start: u32,
    lines: u32,
    bits: *const u8,
    info: *const u8,
    usage: u32,
) -> i32 {
    if bits.is_null() || !with(|g| g.dcs.contains_key(&dc)) {
        return 0;
    }
    let Some(d) = Dib::read(info, usage) else { return 0 };
    with(|g| {
        let Some(b) = g.bitmaps.get_mut(&bmp) else { return 0 };
        let n = lines.min(d.h.saturating_sub(start)).min(b.dib.h.saturating_sub(start));
        // SAFETY: input has n scan lines in the requested DIB format.
        let input = unsafe { core::slice::from_raw_parts(bits, n as usize * d.stride) };
        let mut src = d.clone();
        src.h = n;
        src.top = true;
        let dst = b.dib.clone();
        for row in 0..n {
            for x in 0..d.w.min(dst.w) {
                let y = if d.top { dst.h - start - n + row } else { dst.h - 1 - start - row };
                dst.put(b.bits_mut(), x, y, src.pixel(input, x, row));
            }
        }
        n as i32
    })
}

/// Both PRISM and memory DCs use this path, so all old primitives inherit
/// bitmap selection, paint clipping and application regions.
pub(super) fn draw_dc<R>(
    dc: u64,
    mut f: impl FnMut(&mut Surface, &Dc, &BTreeMap<u64, Gdi>, Rect) -> (R, Rect),
) -> Option<R> {
    with(|g| {
        let d = g.dcs.get(&dc)?;
        let mut bitmap = if d.memory { g.bitmaps.remove(&d.bitmap) } else { None };
        let mut pixels = bitmap.as_ref().map(|b| b.pixels());
        let mut surface = if let (Some(b), Some(p)) = (&bitmap, &mut pixels) {
            Surface::new(p, b.dib.w, b.dib.h, b.dib.w).ok()?
        } else {
            g.windows.get_mut(&d.hwnd)?.win.surface().ok()?
        };
        let full = surface.bounds().intersect(&d.paint);
        let clips = d.clip.clone().unwrap_or_else(|| Region::from_rect(full));
        let mut result = None;
        let mut touched = Rect::EMPTY;
        for r in &clips.0 {
            let clip = r.intersect(&full);
            if clip.w == 0 || clip.h == 0 {
                continue;
            }
            let (v, t) = f(&mut surface, d, &g.gdi, clip);
            touched = touched.union(&t.intersect(&clip));
            result = Some(v);
        }
        // An empty clip still permits successful no-op drawing.
        if result.is_none() {
            result = Some(f(&mut surface, d, &g.gdi, Rect::EMPTY).0);
        }

        if let (Some(b), Some(p)) = (&mut bitmap, pixels) {
            b.store(&p);
        }
        if let Some(b) = bitmap {
            g.bitmaps.insert(d.bitmap, b);
        }
        if let Some(w) = g.windows.get_mut(&d.hwnd) {
            w.drawn = Some(w.drawn.map(|r| r.union(&touched)).unwrap_or(touched));
        }
        result
    })
}

struct Snapshot {
    pixels: Vec<Color>,
    area: Rect,
    width: u32,
    height: u32,
}
impl Snapshot {
    fn pixel(&self, x: i32, y: i32) -> Option<Color> {
        let (x, y) = (x as i64 - self.area.x as i64, y as i64 - self.area.y as i64);
        if x < 0 || y < 0 || x >= self.area.w as i64 || y >= self.area.h as i64 {
            return None;
        }
        self.pixels.get((y as u32 * self.area.w + x as u32) as usize).copied()
    }
}

/// Copies only the requested source rectangle. Taking the snapshot before the
/// destination is changed preserves overlapping self-blits; PRISM rows retain
/// their stride instead of being expanded into a full-surface temporary.
fn snapshot(dc: u64, requested: Rect) -> Option<Snapshot> {
    with(|g| {
        let d = g.dcs.get(&dc)?;
        if d.memory {
            let b = g.bitmaps.get(&d.bitmap)?;
            let (width, height) = (b.dib.w, b.dib.h);
            let area = requested.intersect(&Rect::new(0, 0, width, height));
            let mut pixels = Vec::with_capacity(area.w as usize * area.h as usize);
            for y in area.y as u32..area.bottom() as u32 {
                pixels.extend((area.x as u32..area.right() as u32).map(|x| b.dib.pixel(b.bits(), x, y)));
            }
            Some(Snapshot { pixels, area, width, height })
        } else {
            let s = g.windows.get_mut(&d.hwnd)?.win.surface().ok()?;
            let (width, height) = (s.width(), s.height());
            let area = requested.intersect(&Rect::new(0, 0, width, height));
            let mut pixels = Vec::with_capacity(area.w as usize * area.h as usize);
            for y in area.y as u32..area.bottom() as u32 {
                let start = y as usize * s.stride() as usize + area.x as usize;
                pixels.extend_from_slice(&s.pixels()[start..start + area.w as usize]);
            }
            Some(Snapshot { pixels, area, width, height })
        }
    })
}
/// A source buffer as rows of pixels, top- or bottom-up.
struct SrcView<'a> {
    bits: &'a [Color],
    w: u32,
    h: u32,
    stride: usize,
    top: bool,
}
impl SrcView<'_> {
    fn row(&self, y: usize) -> &[Color] {
        let r = if self.top { y } else { self.h as usize - 1 - y };
        &self.bits[r * self.stride..r * self.stride + self.w as usize]
    }
}

/// The source owned either by a DIB or by a window surface.
enum SrcHolder<'a> {
    Bits { bits: &'a [Color], w: u32, h: u32, stride: usize, top: bool },
    Surface(Surface<'a>),
}
impl SrcHolder<'_> {
    fn view(&self) -> SrcView<'_> {
        match self {
            SrcHolder::Bits { bits, w, h, stride, top } => SrcView { bits, w: *w, h: *h, stride: *stride, top: *top },
            SrcHolder::Surface(s) => SrcView {
                bits: s.pixels(),
                w: s.width(),
                h: s.height(),
                stride: s.stride() as usize,
                top: true,
            },
        }
    }
}

// Mirrors the BitBlt-style argument list of its callers.
#[allow(clippy::too_many_arguments)]
fn copy_rows_view(
    src: &SrcView,
    sx: usize,
    sy: usize,
    dst: &mut [Color],
    dh: u32,
    dtop: bool,
    dstride: usize,
    x: usize,
    y: usize,
    w: usize,
    h: usize,
) {
    for row in 0..h {
        let s = src.row(sy + row);
        let drow = if dtop { y + row } else { dh as usize - 1 - y - row };
        let d0 = drow * dstride + x;
        dst[d0..d0 + w].copy_from_slice(&s[sx..sx + w]);
    }
}

/// SRCCOPY with identical sources and destinations, row by row. Zen's software
/// compositor blits the whole window every frame; the generic per-pixel path
/// costs ~120 ms for a 1280x972 window. None: the general path must run.
// Mirrors the BitBlt-style argument list of its callers.
#[allow(clippy::too_many_arguments)]
fn fast_blit(dst: u64, x: i32, y: i32, w: i32, h: i32, src: u64, sx: i32, sy: i32) -> Option<Bool> {
    with(|g| {
        let d = g.dcs.get(&dst)?;
        let t = d.transform;
        if t.a != 1.0 || t.b != 0.0 || t.c != 0.0 || t.d != 1.0 || t.x != 0.0 || t.y != 0.0 {
            return None;
        }
        let sd = g.dcs.get(&src)?;
        let (src_memory, src_hwnd, src_bitmap) = (sd.memory, sd.hwnd, sd.bitmap);
        let (dst_bitmap, dst_memory, dst_hwnd) = (d.bitmap, d.memory, d.hwnd);
        if dst_memory && src_memory && src_bitmap == dst_bitmap {
            return None;
        }
        if !dst_memory && !src_memory && src_hwnd == dst_hwnd {
            return None;
        }
        if !src_memory && src_hwnd == 0 {
            return None;
        }
        let paint = d.paint;
        let clip = d.clip.clone();
        let (sw, sh) = if src_memory {
            let s = &g.bitmaps.get(&src_bitmap)?.dib;
            if s.bpp != 32 || s.compression != 0 {
                return None;
            }
            (s.w, s.h)
        } else {
            g.windows.get(&src_hwnd)?.size
        };
        let srect = Rect::new(sx, sy, w as u32, h as u32).intersect(&Rect::new(0, 0, sw, sh));
        if srect.is_empty() {
            return Some(TRUE);
        }
        let dx0 = x + (srect.x - sx);
        let dy0 = y + (srect.y - sy);
        let drect = Rect::new(dx0, dy0, srect.w, srect.h);
        let (dw, dh) = if dst_memory {
            let b = g.bitmaps.get(&dst_bitmap)?;
            if b.dib.bpp != 32 || b.dib.compression != 0 {
                return None;
            }
            (b.dib.w, b.dib.h)
        } else {
            g.windows.get(&dst_hwnd)?.size
        };
        let full = Rect::new(0, 0, dw, dh).intersect(&paint);
        let clips = clip.unwrap_or_else(|| Region::from_rect(full));
        let mut touched = Rect::EMPTY;
        for c in &clips.0 {
            let part = drect.intersect(c).intersect(&full);
            if part.is_empty() {
                continue;
            }
            let sxi = (srect.x + (part.x - dx0)) as usize;
            let syi = (srect.y + (part.y - dy0)) as usize;
            let (px, py, pw, ph) = (part.x as usize, part.y as usize, part.w as usize, part.h as usize);
            if dst_memory {
                let mut db = g.bitmaps.remove(&dst_bitmap)?;
                {
                    let holder = if src_memory {
                        let b = g.bitmaps.get(&src_bitmap)?;
                        SrcHolder::Bits {
                            bits: &b.storage,
                            w: b.dib.w,
                            h: b.dib.h,
                            stride: b.dib.stride / 4,
                            top: b.dib.top,
                        }
                    } else {
                        let win = g.windows.get_mut(&src_hwnd)?;
                        SrcHolder::Surface(win.win.surface().ok()?)
                    };
                    let dtop = db.dib.top;
                    let dstride = db.dib.stride / 4;
                    copy_rows_view(&holder.view(), sxi, syi, &mut db.storage, dh, dtop, dstride, px, py, pw, ph);
                }
                g.bitmaps.insert(dst_bitmap, db);
            } else {
                let b = g.bitmaps.get(&src_bitmap)?;
                let view =
                    SrcView { bits: &b.storage, w: b.dib.w, h: b.dib.h, stride: b.dib.stride / 4, top: b.dib.top };
                let win = g.windows.get_mut(&dst_hwnd)?;
                let mut surface = win.win.surface().ok()?;
                for row in 0..ph {
                    let s = view.row(syi + row);
                    if (py + row) as u32 >= surface.height() {
                        break;
                    }
                    let drow = surface.row_mut((py + row) as u32);
                    let Some(d) = drow.get_mut(px..px + pw) else { continue };
                    d.copy_from_slice(&s[sxi..sxi + pw]);
                }
            }
            touched = touched.union(&part);
        }
        if let Some(win) = g.windows.get_mut(&dst_hwnd) {
            if !touched.is_empty() {
                win.drawn = Some(win.drawn.map(|r| r.union(&touched)).unwrap_or(touched));
            }
        }
        Some(TRUE)
    })
}

pub(super) extern "win64" fn BitBlt(dst: u64, x: i32, y: i32, w: i32, h: i32, src: u64, sx: i32, sy: i32, rop: u32) -> Bool {
    if !matches!(rop & !0x40000000, 0xcc0020 | 0x42 | 0xff0062) || w < 0 || h < 0 {
        return fail(ERROR_NOT_SUPPORTED, FALSE);
    }
    let rop = rop & !0x40000000;
    if rop == 0xcc0020 {
        if let Some(ok) = fast_blit(dst, x, y, w, h, src, sx, sy) {
            return ok;
        }
    }
    let source = if rop == 0xcc0020 {
        let Some(s) = snapshot(src, Rect::new(sx, sy, w as u32, h as u32)) else { return FALSE };
        Some(s)
    } else {
        None
    };
    if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) && with(|g| g.dcs.get(&dst).is_some_and(|d| !d.memory && d.hwnd != 0)) {
        static TRACE_BLITS: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
        if TRACE_BLITS.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 32 {
            if let Some(source) = &source {
                let (sw, sh) = (source.width, source.height);
                os_std::eprintln!("winrun: GDI present: dc {dst:#x}, dst ({x},{y}) {w}x{h}, source {src:#x} {sw}x{sh} at ({sx},{sy}), first pixels {:x?}", &source.pixels[..source.pixels.len().min(8)]);
            }
        }
    }
    draw(dst, |s, d, _, clip| {
        let (x, y) = d.transform.point(x, y);
        let r = Rect::new(x, y, w as u32, h as u32).intersect(&clip);
        for dy in r.y..r.y + r.h as i32 {
            for dx in r.x..r.x + r.w as i32 {
                let c = if let Some(source) = &source {
                    let (px, py) = (sx + dx - x, sy + dy - y);
                    let Some(c) = source.pixel(px, py) else { continue };
                    c
                } else if rop == 0x42 {
                    rgb(0, 0, 0)
                } else {
                    rgb(255, 255, 255)
                };
                s.put(dx, dy, c);
            }
        }
        (TRUE, r)
    })
    .unwrap_or(FALSE)
}
extern "win64" fn StretchDIBits(
    dc: u64,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    sx: i32,
    sy: i32,
    sw: i32,
    sh: i32,
    bits: *const u8,
    info: *const u8,
    usage: u32,
    rop: u32,
) -> i32 {
    if !matches!(rop, 0xcc0020 | 0x42 | 0xff0062) || w == 0 || h == 0 || sw == 0 || sh == 0 {
        return 0;
    }
    let Some(dib) = Dib::read(info, usage) else { return 0 };
    if bits.is_null() && rop == 0xcc0020 {
        return 0;
    }
    // SAFETY: caller provides the DIB's complete pixel array for SRCCOPY.
    let input = if bits.is_null() { &[][..] } else { unsafe { core::slice::from_raw_parts(bits, dib.bytes()) } };
    draw(dc, |s, d, _, clip| {
        let (x, y) = d.transform.point(x, y);
        let r = Rect::new(x.min(x.saturating_add(w)), y.min(y.saturating_add(h)), w.unsigned_abs(), h.unsigned_abs())
            .intersect(&clip);
        for dy in r.y..r.y + r.h as i32 {
            for dx in r.x..r.x + r.w as i32 {
                let px = sx + (((dx - x) as i64 * sw as i64) / w as i64) as i32;
                let py = sy + (((dy - y) as i64 * sh as i64) / h as i64) as i32;
                let c = if rop == 0x42 {
                    rgb(0, 0, 0)
                } else if rop == 0xff0062 {
                    rgb(255, 255, 255)
                } else {
                    if px < 0 || py < 0 || px >= dib.w as i32 || py >= dib.h as i32 {
                        continue;
                    }
                    dib.pixel(input, px as u32, if dib.top { py as u32 } else { dib.h - 1 - py as u32 })
                };
                s.put(dx, dy, c);
            }
        }
        (sh.unsigned_abs().min(dib.h) as i32, r)
    })
    .unwrap_or(0)
}
extern "win64" fn GetPixel(dc: u64, x: i32, y: i32) -> u32 {
    let point = with(|g| {
        let d = g.dcs.get(&dc)?;
        let (x, y) = d.transform.point(x, y);
        if !visible(g, d).contains(x, y) || d.clip.as_ref().is_some_and(|r| !r.contains(x, y)) {
            return None;
        }
        Some((x, y))
    });
    let Some((x, y)) = point else { return GDI_ERROR };
    let Some(p) = snapshot(dc, Rect::new(x, y, 1, 1)) else { return GDI_ERROR };
    p.pixel(x, y).map(to_colorref).unwrap_or(GDI_ERROR)
}

/// Nonoverlapping rectangles. Boolean operations split at the input edges;
/// holes stay holes instead of being replaced by their bounding rectangle.
#[derive(Clone, Default)]
pub(super) struct Region(pub Vec<Rect>);
impl Region {
    fn from_rect(r: Rect) -> Self {
        Self(if r.w > 0 && r.h > 0 { alloc::vec![r] } else { Vec::new() })
    }
    fn bounds(&self) -> Rect {
        self.0.iter().copied().reduce(|a, b| a.union(&b)).unwrap_or(Rect::EMPTY)
    }
    fn kind(&self) -> i32 {
        if self.0.is_empty() {
            1
        } else if self.0.len() == 1 {
            2
        } else {
            3
        }
    }
    fn contains(&self, x: i32, y: i32) -> bool {
        self.0.iter().any(|r| {
            x >= r.x && y >= r.y && (x as i64) < r.x as i64 + r.w as i64 && (y as i64) < r.y as i64 + r.h as i64
        })
    }
    fn combine(&self, other: &Self, mode: i32) -> Option<Self> {
        if mode == 5 {
            return Some(other.clone());
        }
        if !(1..=4).contains(&mode) {
            return None;
        }
        let mut xs = Vec::new();
        let mut ys = Vec::new();
        for r in self.0.iter().chain(&other.0) {
            xs.extend([r.x, r.x.saturating_add(r.w as i32)]);
            ys.extend([r.y, r.y.saturating_add(r.h as i32)]);
        }
        xs.sort_unstable();
        xs.dedup();
        ys.sort_unstable();
        ys.dedup();
        // A bounded software region avoids hostile cross products.
        if xs.len().saturating_mul(ys.len()) > 1_000_000 {
            return None;
        }
        let mut rects: Vec<Rect> = Vec::new();
        for y in ys.windows(2) {
            let mut row: Vec<Rect> = Vec::new();
            for x in xs.windows(2) {
                let (a, b) = (self.contains(x[0], y[0]), other.contains(x[0], y[0]));
                if match mode {
                    1 => a && b,
                    2 => a || b,
                    3 => a != b,
                    4 => a && !b,
                    _ => false,
                } {
                    if let Some(last) = row.last_mut().filter(|r| r.x + r.w as i32 == x[0]) {
                        last.w += (x[1] - x[0]) as u32;
                    } else {
                        row.push(Rect::new(x[0], y[0], (x[1] - x[0]) as u32, (y[1] - y[0]) as u32));
                    }
                }
            }
            for r in row {
                if let Some(old) =
                    rects.iter_mut().find(|old| old.x == r.x && old.w == r.w && old.y + old.h as i32 == r.y)
                {
                    old.h += r.h;
                } else {
                    rects.push(r);
                }
            }
        }
        rects.sort_by_key(|r| (r.y, r.x));
        Some(Self(rects))
    }
}
fn insert_region(region: Region) -> u64 {
    with(|g| {
        let h = g.handle();
        g.regions.insert(h, region);
        g.gdi.insert(h, Gdi::Region);
        h
    })
}
extern "win64" fn CreateRectRgn(l: i32, t: i32, r: i32, b: i32) -> u64 {
    let rect = Rect::new(l.min(r), t.min(b), l.abs_diff(r), t.abs_diff(b));
    insert_region(Region::from_rect(rect))
}
extern "win64" fn ExtCreateRegion(transform: *const Xform, size: u32, data: *const u8) -> u64 {
    if data.is_null() || size < 32 {
        return 0;
    }
    // SAFETY: caller supplied at least size bytes of RGNDATA.
    unsafe {
        let count = teb::get::<u32>(data as u64, 8) as usize;
        if teb::get::<u32>(data as u64, 0) != 32
            || teb::get::<u32>(data as u64, 4) != 1
            || count > (size as usize - 32) / 16
            || count > 4096
        {
            return 0;
        }
        let transform = if transform.is_null() { Xform::IDENTITY } else { core::ptr::read_unaligned(transform) };
        if !transform.valid() {
            return 0;
        }
        let mut region = Region::default();
        for i in 0..count {
            let r = rect_at(data.add(32 + i * 16));
            if r.0 >= r.2 || r.1 >= r.3 {
                continue;
            }
            let Some(next) = region.combine(&Region::from_rect(transform.rect(r)), 2) else { return 0 };
            region = next;
        }
        insert_region(region)
    }
}
extern "win64" fn GetRgnBox(rgn: u64, out: *mut u8) -> i32 {
    if out.is_null() {
        return 0;
    }
    with(|g| {
        let Some(r) = g.regions.get(&rgn) else { return 0 };
        write_rect(out.cast(), r.bounds());
        r.kind()
    })
}
extern "win64" fn GetRegionData(rgn: u64, size: u32, out: *mut u8) -> u32 {
    with(|g| {
        let Some(r) = g.regions.get(&rgn) else { return 0 };
        let need = 32 + r.0.len() * 16;
        if out.is_null() {
            return need as u32;
        }
        if (size as usize) < need {
            return 0;
        }
        // SAFETY: RGNDATAHEADER followed by exactly nCount RECTs.
        unsafe {
            teb::put(out as u64, 0, 32u32);
            teb::put(out as u64, 4, 1u32);
            teb::put(out as u64, 8, r.0.len() as u32);
            teb::put(out as u64, 12, (r.0.len() * 16) as u32);
            write_rect(out.add(16).cast(), r.bounds());
            for (i, rect) in r.0.iter().enumerate() {
                write_rect(out.add(32 + i * 16).cast(), *rect);
            }
        }
        need as u32
    })
}
extern "win64" fn OffsetRgn(rgn: u64, dx: i32, dy: i32) -> i32 {
    with(|g| {
        let Some(r) = g.regions.get_mut(&rgn) else { return 0 };
        if r.0.iter().any(|r| r.x.checked_add(dx).is_none() || r.y.checked_add(dy).is_none()) {
            return 0;
        }
        for r in &mut r.0 {
            r.x += dx;
            r.y += dy;
        }
        r.kind()
    })
}
fn visible(g: &Gui, d: &Dc) -> Region {
    let full = if d.memory {
        g.bitmaps.get(&d.bitmap).map(|b| Rect::new(0, 0, b.dib.w, b.dib.h)).unwrap_or(Rect::EMPTY)
    } else {
        g.windows.get(&d.hwnd).map(|w| Rect::new(0, 0, w.size.0, w.size.1)).unwrap_or(d.paint)
    };
    Region::from_rect(full.intersect(&d.paint))
}
extern "win64" fn ExtSelectClipRgn(dc: u64, rgn: u64, mode: i32) -> i32 {
    with(|g| {
        let Some(d) = g.dcs.get(&dc) else { return 0 };
        if rgn == 0 && mode == 5 {
            let r = visible(g, d);
            g.dcs.get_mut(&dc).unwrap().clip = None;
            return r.kind();
        }
        let Some(r) = g.regions.get(&rgn) else { return 0 };
        let old = d.clip.clone().unwrap_or_else(|| visible(g, d));
        let Some(new) = old.combine(r, mode) else { return 0 };
        let kind = new.kind();
        g.dcs.get_mut(&dc).unwrap().clip = Some(new);
        kind
    })
}
extern "win64" fn SelectClipRgn(dc: u64, rgn: u64) -> i32 {
    ExtSelectClipRgn(dc, rgn, 5)
}
extern "win64" fn GetClipRgn(dc: u64, rgn: u64) -> i32 {
    with(|g| {
        let Some(d) = g.dcs.get(&dc) else { return -1 };
        let Some(region) = d.clip.clone() else { return 0 };
        let Some(r) = g.regions.get_mut(&rgn) else { return -1 };
        *r = region;
        1
    })
}
extern "win64" fn GetRandomRgn(dc: u64, rgn: u64, kind: i32) -> i32 {
    if kind == 1 {
        return GetClipRgn(dc, rgn);
    }
    with(|g| {
        let Some(d) = g.dcs.get(&dc) else { return -1 };
        let region = match kind {
            4 => visible(g, d),
            2 | 3 => return 0,
            _ => return -1,
        };
        let Some(r) = g.regions.get_mut(&rgn) else { return -1 };
        *r = region;
        1
    })
}
extern "win64" fn GetClipBox(dc: u64, out: *mut u8) -> i32 {
    if out.is_null() {
        return 0;
    }
    with(|g| {
        let Some(d) = g.dcs.get(&dc) else { return 0 };
        let base = visible(g, d);
        let r = d.clip.as_ref().and_then(|c| base.combine(c, 1)).unwrap_or(base);
        write_rect(out.cast(), r.bounds());
        r.kind()
    })
}
extern "win64" fn IntersectClipRect(dc: u64, l: i32, t: i32, r: i32, b: i32) -> i32 {
    with(|g| {
        let Some(d) = g.dcs.get(&dc) else { return 0 };
        let region = Region::from_rect(d.transform.rect((l, t, r, b)));
        let old = d.clip.clone().unwrap_or_else(|| visible(g, d));
        let Some(new) = old.combine(&region, 1) else { return 0 };
        let kind = new.kind();
        g.dcs.get_mut(&dc).unwrap().clip = Some(new);
        kind
    })
}

#[derive(Clone, Default)]
pub(super) struct GdiPath {
    pub active: bool,
    ready: bool,
    figures: Vec<Vec<(i32, i32)>>,
    rects: Region,
}
impl GdiPath {
    pub fn move_to(&mut self, p: (i32, i32)) {
        self.figures.push(alloc::vec![p]);
    }
    pub fn line_to(&mut self, p: (i32, i32)) {
        if let Some(f) = self.figures.last_mut() {
            f.push(p);
        } else {
            self.move_to(p);
        }
    }
    pub fn rect(&mut self, r: Rect) {
        self.rects = self.rects.combine(&Region::from_rect(r), 2).unwrap_or_default();
    }
    fn region(&self) -> Option<Region> {
        let mut region = self.rects.clone();
        // Scan conversion produces rectangle runs, preserving polygon holes.
        let ymin = self.figures.iter().flatten().map(|p| p.1).min().unwrap_or(0);
        let ymax = self.figures.iter().flatten().map(|p| p.1).max().unwrap_or(0);
        if ymax as i64 - ymin as i64 > 16384 {
            return None;
        }
        let mut rows = Vec::new();
        for y in ymin..ymax {
            let mut crossings = Vec::new();
            for f in &self.figures {
                for (a, b) in f.iter().zip(f.iter().cycle().skip(1)).take(f.len()) {
                    if (a.1 <= y && b.1 > y) || (b.1 <= y && a.1 > y) {
                        crossings.push(
                            a.0 as i64 + (2 * (y - a.1) as i64 + 1) * (b.0 - a.0) as i64 / (2 * (b.1 - a.1) as i64),
                        );
                    }
                }
            }
            crossings.sort_unstable();
            for pair in crossings.as_chunks::<2>().0 {
                if pair[1] > pair[0] {
                    rows.push(Rect::new(pair[0] as i32, y, (pair[1] - pair[0]) as u32, 1));
                }
            }
        }
        // Rows are already disjoint. Union each rectangle path with the rows.
        if !rows.is_empty() {
            region = region.combine(&Region(rows), 2)?;
        }
        Some(region)
    }
}
extern "win64" fn BeginPath(dc: u64) -> Bool {
    dc_set(dc, |d| {
        d.path = GdiPath { active: true, ..GdiPath::default() };
        d.path.move_to(d.transform.point(d.pos.0, d.pos.1));
    })
    .is_some() as Bool
}
extern "win64" fn EndPath(dc: u64) -> Bool {
    dc_set(dc, |d| {
        if !d.path.active {
            return FALSE;
        }
        d.path.active = false;
        d.path.ready = true;
        TRUE
    })
    .unwrap_or(FALSE)
}
extern "win64" fn CloseFigure(dc: u64) -> Bool {
    dc_set(dc, |d| {
        if !d.path.active {
            return FALSE;
        }
        if let Some(f) = d.path.figures.last_mut() {
            if let Some(p) = f.first().copied() {
                f.push(p);
            }
        }
        TRUE
    })
    .unwrap_or(FALSE)
}
extern "win64" fn FillPath(dc: u64) -> Bool {
    let path = dc_set(dc, |d| if d.path.ready { Some(core::mem::take(&mut d.path)) } else { None }).flatten();
    let Some(r) = path.and_then(|p| p.region()) else { return FALSE };
    draw(dc, |s, d, gdi, clip| {
        if let Some(c) = brush_color(gdi, d.brush) {
            for rect in &r.0 {
                s.fill_rect(rect.intersect(&clip), c);
            }
        }
        (TRUE, r.bounds())
    })
    .unwrap_or(FALSE)
}
extern "win64" fn StrokePath(dc: u64) -> Bool {
    let path = dc_set(dc, |d| if d.path.ready { Some(core::mem::take(&mut d.path)) } else { None }).flatten();
    let Some(mut path) = path else { return FALSE };
    for r in &path.rects.0 {
        path.figures.push(alloc::vec![
            (r.x, r.y),
            (r.x + r.w as i32 - 1, r.y),
            (r.x + r.w as i32 - 1, r.y + r.h as i32 - 1),
            (r.x, r.y + r.h as i32 - 1),
            (r.x, r.y)
        ]);
    }
    draw(dc, |s, d, gdi, clip| {
        if let Some(Gdi::Pen(c, w)) = gdi.get(&d.pen) {
            for f in &path.figures {
                for p in f.windows(2) {
                    for off in 0..*w as i32 {
                        line_clipped(s, p[0].0, p[0].1 + off, p[1].0, p[1].1 + off, *c, clip);
                    }
                }
            }
        }
        (TRUE, clip)
    })
    .unwrap_or(FALSE)
}
extern "win64" fn SelectClipPath(dc: u64, mode: i32) -> Bool {
    let path = dc_set(dc, |d| if d.path.ready { Some(core::mem::take(&mut d.path)) } else { None }).flatten();
    let Some(region) = path.and_then(|p| p.region()) else { return FALSE };
    let rgn = insert_region(region);
    let result = ExtSelectClipRgn(dc, rgn, mode) != 0;
    DeleteObject(rgn);
    result as Bool
}
extern "win64" fn WidenPath(dc: u64) -> Bool {
    with(|g| {
        let Some(d) = g.dcs.get(&dc) else { return FALSE };
        if !d.path.ready {
            return FALSE;
        }
        let width = match g.gdi.get(&d.pen) {
            Some(Gdi::Pen(_, w)) => *w,
            _ => return FALSE,
        };
        // A widened stroke is a union of rectangle runs, like our clip paths.
        // Geometric joins use the rectangular software approximation.
        let mut path = d.path.clone();
        for r in &path.rects.0 {
            path.figures.push(alloc::vec![
                (r.x, r.y),
                (r.x + r.w as i32, r.y),
                (r.x + r.w as i32, r.y + r.h as i32),
                (r.x, r.y + r.h as i32),
                (r.x, r.y)
            ]);
        }
        let mut rects = Region::default();
        for f in &path.figures {
            for p in f.windows(2) {
                let (dx, dy) = ((p[1].0 as i64 - p[0].0 as i64).abs(), (p[1].1 as i64 - p[0].1 as i64).abs());
                let steps = dx.max(dy).max(1);
                if steps > 16384 {
                    return fail(ERROR_NOT_SUPPORTED, FALSE);
                }
                let mut runs = Vec::new();
                for step in 0..steps {
                    let x = p[0].0 as i64 + (p[1].0 as i64 - p[0].0 as i64) * step / steps;
                    let y = p[0].1 as i64 + (p[1].1 as i64 - p[0].1 as i64) * step / steps;
                    runs.push(Rect::new(x as i32 - width as i32 / 2, y as i32 - width as i32 / 2, width, width));
                }
                // Merge runs incrementally, keeping boolean-region bounds small.
                for r in runs {
                    let Some(next) = rects.combine(&Region::from_rect(r), 2) else { return FALSE };
                    rects = next;
                }
            }
        }
        let d = g.dcs.get_mut(&dc).unwrap();
        d.path = GdiPath { ready: true, rects, ..GdiPath::default() };
        TRUE
    })
}
extern "win64" fn PolyBezierTo(dc: u64, points: *const i32, count: u32) -> Bool {
    if points.is_null() || !count.is_multiple_of(3) || count > 12288 {
        return FALSE;
    }
    let Some(mut pos) = with(|g| g.dcs.get(&dc).map(|d| d.pos)) else { return FALSE };
    // SAFETY: caller supplies count POINTs, each 8 bytes.
    let points = unsafe { core::slice::from_raw_parts(points, count as usize * 2) };
    for curve in points.as_chunks::<6>().0 {
        let start = pos;
        for step in 1..=24i64 {
            let t = step;
            let u = 24 - t;
            let eval = |a: i32, b: i32, c: i32, d: i32| {
                ((u * u * u * a as i64 + 3 * u * u * t * b as i64 + 3 * u * t * t * c as i64 + t * t * t * d as i64)
                    / 24i64.pow(3)) as i32
            };
            pos = (eval(start.0, curve[0], curve[2], curve[4]), eval(start.1, curve[1], curve[3], curve[5]));
            if LineTo(dc, pos.0, pos.1) == FALSE {
                return FALSE;
            }
        }
    }
    TRUE
}
extern "win64" fn ExtCreatePen(style: u32, width: u32, brush: *const u8, count: u32, styles: *const u32) -> u64 {
    if brush.is_null() || (count > 0 && styles.is_null()) {
        return 0;
    }
    // SAFETY: caller supplies LOGBRUSH, 16 bytes on Windows x64.
    let (kind, color) = unsafe { (teb::get::<u32>(brush as u64, 0), teb::get::<u32>(brush as u64, 4)) };
    if kind != 0 && kind != 1 {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    CreatePen(if style & 15 == 5 || kind == 1 { 5 } else { 0 }, width.min(16384) as i32, color)
}

extern "win64" fn SaveDC(dc: u64) -> i32 {
    dc_set(dc, |d| {
        let mut saved = d.clone();
        saved.saved.clear();
        d.saved.push(saved);
        d.saved.len() as i32
    })
    .unwrap_or(0)
}
extern "win64" fn RestoreDC(dc: u64, level: i32) -> Bool {
    dc_set(dc, |d| {
        let n = if level < 0 { d.saved.len() as i64 + level as i64 } else { level as i64 - 1 };
        if n < 0 || n >= d.saved.len() as i64 {
            return FALSE;
        }
        let mut stack = core::mem::take(&mut d.saved);
        let mut saved = stack[n as usize].clone();
        stack.truncate(n as usize);
        saved.saved = stack;
        saved.path = core::mem::take(&mut d.path);
        *d = saved;
        TRUE
    })
    .unwrap_or(FALSE)
}
extern "win64" fn SetMapMode(dc: u64, mode: i32) -> i32 {
    if mode != 1 {
        return fail(ERROR_NOT_SUPPORTED, 0);
    }
    dc_set(dc, |d| core::mem::replace(&mut d.map_mode, mode)).unwrap_or(0)
}
extern "win64" fn SetTextAlign(dc: u64, align: u32) -> u32 {
    if align & !0x11f != 0 || align & 6 == 4 || align & 24 == 16 {
        return GDI_ERROR;
    }
    dc_set(dc, |d| core::mem::replace(&mut d.align, align)).unwrap_or(GDI_ERROR)
}
extern "win64" fn SetPolyFillMode(dc: u64, mode: i32) -> i32 {
    if !matches!(mode, 1 | 2) {
        return 0;
    }
    dc_set(dc, |d| core::mem::replace(&mut d.poly_mode, mode)).unwrap_or(0)
}
extern "win64" fn SetStretchBltMode(dc: u64, mode: i32) -> i32 {
    if !(1..=4).contains(&mode) {
        return 0;
    }
    dc_set(dc, |d| core::mem::replace(&mut d.stretch_mode, mode)).unwrap_or(0)
}
extern "win64" fn set_miter(dc: u64, limit: f32, old: *mut f32) -> Bool {
    if !limit.is_finite() || limit < 1.0 {
        return FALSE;
    }
    dc_set(dc, |d| {
        if !old.is_null() {
            /* SAFETY: optional output FLOAT. */
            unsafe {
                *old = d.miter;
            }
        }
        d.miter = limit;
        TRUE
    })
    .unwrap_or(FALSE)
}
// Soft-float target: the second Windows argument arrives in xmm1.
#[unsafe(naked)]
extern "win64" fn SetMiterLimit() {
    core::arch::naked_asm!("movd edx, xmm1", "sub rsp, 40", "call {imp}", "add rsp, 40", "ret",imp=sym set_miter);
}
extern "win64" fn GetGraphicsMode(dc: u64) -> i32 {
    with(|g| g.dcs.get(&dc).map(|d| d.graphics_mode).unwrap_or(0))
}
extern "win64" fn SetGraphicsMode(dc: u64, mode: i32) -> i32 {
    if !matches!(mode, 1 | 2) {
        return 0;
    }
    dc_set(dc, |d| {
        if mode == 1 && d.transform != Xform::IDENTITY {
            return 0;
        }
        core::mem::replace(&mut d.graphics_mode, mode)
    })
    .unwrap_or(0)
}
extern "win64" fn SetWorldTransform(dc: u64, transform: *const Xform) -> Bool {
    if transform.is_null() {
        return FALSE;
    }
    // SAFETY: caller's XFORM (24 bytes), floats passed in memory.
    let t = unsafe { core::ptr::read_unaligned(transform) };
    if !t.valid() {
        return FALSE;
    }
    dc_set(dc, |d| {
        if d.graphics_mode != 2 {
            return FALSE;
        }
        d.transform = t;
        TRUE
    })
    .unwrap_or(FALSE)
}
extern "win64" fn GetWorldTransform(dc: u64, out: *mut Xform) -> Bool {
    if out.is_null() {
        return FALSE;
    }
    dc_set(dc, |d| {
        /* SAFETY: caller's XFORM. */
        unsafe {
            core::ptr::write_unaligned(out, d.transform);
        }
        TRUE
    })
    .unwrap_or(FALSE)
}
extern "win64" fn ModifyWorldTransform(dc: u64, transform: *const Xform, mode: u32) -> Bool {
    if mode != 1 && transform.is_null() {
        return FALSE;
    }
    let t = if mode == 1 {
        Xform::IDENTITY
    } else {
        /* SAFETY: caller's XFORM. */
        unsafe { core::ptr::read_unaligned(transform) }
    };
    if !t.valid() {
        return FALSE;
    }
    dc_set(dc, |d| {
        if d.graphics_mode != 2 {
            return FALSE;
        }
        d.transform = match mode {
            1 => Xform::IDENTITY,
            2 => t.then(d.transform),
            3 => d.transform.then(t),
            _ => return FALSE,
        };
        TRUE
    })
    .unwrap_or(FALSE)
}
extern "win64" fn GetCurrentObject(dc: u64, kind: u32) -> u64 {
    with(|g| {
        g.dcs
            .get(&dc)
            .map(|d| match kind {
                1 | 11 => d.pen,
                2 => d.brush,
                6 => d.font,
                7 => d.bitmap,
                _ => 0,
            })
            .unwrap_or(0)
    })
}

fn ascent(k: FontKind) -> i32 {
    (match k {
        FontKind::Sans => fonts().sans.ascent(),
        FontKind::SansBold => fonts().bold.ascent(),
        FontKind::Large => fonts().large.ascent(),
        FontKind::Mono => line_height(k) * 4 / 5,
    }) as i32
}
pub(super) fn text_out_ex(
    dc: u64,
    x: i32,
    y: i32,
    text: &str,
    flags: u32,
    rect: Option<Rect>,
    advances: Option<&[i32]>,
) -> Bool {
    if flags & !(2 | 4 | 16 | 128 | 0x2000) != 0 {
        return fail(ERROR_NOT_SUPPORTED, FALSE);
    }
    if flags & 6 != 0 && rect.is_none() {
        return FALSE;
    }
    let mut end = None;
    let result = draw(dc, |s, d, gdi, clip| {
        let k = font_of(gdi, d.font);
        let width = advances
            .map(|a| a.iter().step_by(if flags & 0x2000 != 0 { 2 } else { 1 }).sum::<i32>())
            .unwrap_or(measure(k, text) as i32);
        let (mut x, mut y) = if d.align & 1 != 0 { d.pos } else { (x, y) };
        if d.align & 6 == 6 {
            x -= width / 2;
        } else if d.align & 2 != 0 {
            x -= width;
        }
        if d.align & 24 == 24 {
            y -= ascent(k);
        } else if d.align & 8 != 0 {
            y -= line_height(k) as i32;
        }
        let start = (x, y);
        let clip = if flags & 4 != 0 { clip.intersect(&d.transform.rect(rect4(rect.unwrap()))) } else { clip };
        if flags & 2 != 0 {
            s.fill_rect(d.transform.rect(rect4(rect.unwrap())).intersect(&clip), d.bk);
        } else if d.opaque {
            s.fill_rect(d.transform.rect((x, y, x + width, y + line_height(k) as i32)).intersect(&clip), d.bk);
        }
        for (i, ch) in text.chars().enumerate() {
            let mut buf = [0; 4];
            let t = ch.encode_utf8(&mut buf);
            let (px, py) = d.transform.point(x, y);
            draw_text(s, k, px, py, t, d.text, clip);
            let step = if flags & 0x2000 != 0 { 2 } else { 1 };
            x += advances.and_then(|a| a.get(i * step)).copied().unwrap_or(measure(k, t) as i32);
            if step == 2 {
                y += advances.and_then(|a| a.get(i * step + 1)).copied().unwrap_or(0);
            }
        }
        end = Some((x, start.1));
        (TRUE, rect.unwrap_or_else(|| d.transform.rect((start.0, start.1, x, start.1 + line_height(k) as i32))))
    })
    .unwrap_or(FALSE);
    if let Some(pos) = end {
        dc_set(dc, |d| {
            if d.align & 1 != 0 {
                d.pos = pos;
            }
        });
    }
    result
}
fn rect4(r: Rect) -> Rect4 {
    (r.x, r.y, r.x + r.w as i32, r.y + r.h as i32)
}
extern "win64" fn ExtTextOutW(
    dc: u64,
    x: i32,
    y: i32,
    flags: u32,
    rect: *const u8,
    text: *const u16,
    n: u32,
    dx: *const i32,
) -> Bool {
    if n > 8192 || (n > 0 && text.is_null()) {
        return FALSE;
    }
    // SAFETY: caller supplies n UTF-16 units (or our identity glyph indices).
    let units = if n == 0 { &[][..] } else { unsafe { core::slice::from_raw_parts(text, n as usize) } };
    let t: String = char::decode_utf16(units.iter().copied()).map(|c| c.unwrap_or('\u{fffd}')).collect();
    let advances = if dx.is_null() {
        None
    } else {
        // SAFETY: dx has n entries, or 2*n with ETO_PDY.
        Some(unsafe { core::slice::from_raw_parts(dx, n as usize * if flags & 0x2000 != 0 { 2 } else { 1 }) })
    };
    text_out_ex(dc, x, y, &t, flags, read_rect(rect.cast()), advances)
}
extern "win64" fn GetCharWidth32A(dc: u64, first: u32, last: u32, widths: *mut i32) -> Bool {
    if widths.is_null() || first > last || last > 255 {
        return FALSE;
    }
    let Some(k) = with(|g| g.dcs.get(&dc).map(|d| font_of(&g.gdi, d.font))) else { return FALSE };
    for (i, c) in (first..=last).enumerate() {
        let ch = char::from_u32(c).unwrap_or('?');
        let mut buf = [0; 4];
        // SAFETY: output contains last-first+1 integer widths.
        unsafe {
            *widths.add(i) = measure(k, ch.encode_utf8(&mut buf)) as i32;
        }
    }
    TRUE
}
extern "win64" fn GetFontData(_dc: u64, _table: u32, _offset: u32, _out: *mut u8, _size: u32) -> u32 {
    fail(ERROR_NOT_SUPPORTED, GDI_ERROR) // Atlas fonts have no sfnt tables.
}
fn has_glyph(k: FontKind, ch: char) -> bool {
    match k {
        FontKind::Sans => fonts().sans.has(ch),
        FontKind::SansBold => fonts().bold.has(ch),
        FontKind::Large => fonts().large.has(ch),
        FontKind::Mono => (' '..='~').contains(&ch),
    }
}
extern "win64" fn GetFontUnicodeRanges(dc: u64, out: *mut u8) -> u32 {
    let Some(k) = with(|g| g.dcs.get(&dc).map(|d| font_of(&g.gdi, d.font))) else { return 0 };
    let mut ranges: Vec<(u16, u16)> = Vec::new();
    for c in 0..=u16::MAX {
        if !char::from_u32(c as u32).is_some_and(|ch| has_glyph(k, ch)) {
            continue;
        }
        if let Some((start, n)) = ranges.last_mut().filter(|(start, n)| *start as u32 + *n as u32 == c as u32) {
            let _ = start;
            *n += 1;
        } else {
            ranges.push((c, 1));
        }
    }
    let size = 16 + ranges.len() * 4;
    if !out.is_null() {
        // SAFETY: GLYPHSET buffer was sized by the caller's initial query.
        unsafe {
            teb::put(out as u64, 0, size as u32);
            teb::put(out as u64, 4, 0u32);
            teb::put(out as u64, 8, ranges.iter().map(|(_, n)| *n as u32).sum::<u32>());
            teb::put(out as u64, 12, ranges.len() as u32);
            for (i, (start, n)) in ranges.iter().enumerate() {
                teb::put(out as u64, 16 + i * 4, *start);
                teb::put(out as u64, 18 + i * 4, *n);
            }
        }
    }
    size as u32
}
extern "win64" fn GetGlyphIndicesW(dc: u64, text: *const u16, n: i32, out: *mut u16, flags: u32) -> u32 {
    if !(0..=65536).contains(&n) || (n > 0 && (text.is_null() || out.is_null())) {
        return GDI_ERROR;
    }
    let Some(k) = with(|g| g.dcs.get(&dc).map(|d| font_of(&g.gdi, d.font))) else { return GDI_ERROR };
    for i in 0..n as usize {
        // SAFETY: input and output each contain n WCHAR / WORD entries.
        unsafe {
            let c = *text.add(i);
            *out.add(i) = if char::from_u32(c as u32).is_some_and(|ch| has_glyph(k, ch)) {
                c
            } else if flags & 1 != 0 {
                0xffff
            } else {
                '?' as u16
            };
        }
    }
    n as u32
}
extern "win64" fn GetGlyphOutlineW(
    dc: u64,
    ch: u32,
    format: u32,
    metrics: *mut u8,
    size: u32,
    out: *mut u8,
    matrix: *const u8,
) -> u32 {
    if metrics.is_null() || matrix.is_null() {
        return GDI_ERROR;
    }
    let Some(k) = with(|g| g.dcs.get(&dc).map(|d| font_of(&g.gdi, d.font))) else { return GDI_ERROR };
    // Native outlines don't exist in the bitmap atlas. Only identity MAT2
    // is supported; fail rather than silently return untransformed data.
    let identity = [0u8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0];
    // SAFETY: caller's MAT2 consists of four 16.16 FIXED values (16 bytes).
    if unsafe { core::slice::from_raw_parts(matrix, 16) } != identity {
        return fail(ERROR_NOT_SUPPORTED, GDI_ERROR);
    }
    let base = format & !0x180;
    if !matches!(base, 0 | 1 | 4 | 5 | 6) {
        return fail(ERROR_NOT_SUPPORTED, GDI_ERROR);
    }
    let ch = char::from_u32(ch).unwrap_or('?');
    let mut buf = [0; 4];
    let t = ch.encode_utf8(&mut buf);
    let advance = measure(k, t);
    let height = line_height(k);
    let width = advance.max(1);
    // SAFETY: GLYPHMETRICS is 20 bytes, including SHORT cell increments.
    unsafe {
        core::ptr::write_bytes(metrics, 0, 20);
        teb::put(metrics as u64, 0, width);
        teb::put(metrics as u64, 4, height);
        teb::put(metrics as u64, 12, ascent(k));
        teb::put(metrics as u64, 16, advance as i16);
    }
    if base == 0 {
        return 0;
    }
    let stride = if base == 1 { width.div_ceil(32) * 4 } else { width.next_multiple_of(4) };
    let need = stride * height;
    if out.is_null() || size == 0 {
        return need;
    }
    if size < need {
        return GDI_ERROR;
    }
    let mut pixels = alloc::vec![rgb(0,0,0);(width*height) as usize];
    let mut surface = Surface::new(&mut pixels, width, height, width).unwrap();
    draw_text(&mut surface, k, 0, 0, t, rgb(255, 255, 255), Rect::new(0, 0, width, height));
    // SAFETY: caller provided need bytes for the glyph bitmap.
    let output = unsafe { core::slice::from_raw_parts_mut(out, need as usize) };
    output.fill(0);
    for y in 0..height {
        for x in 0..width {
            let cov = (pixels[(y * width + x) as usize] & 255) as u8;
            if base == 1 {
                if cov >= 128 {
                    output[(y * stride + x / 8) as usize] |= 1 << (7 - x % 8);
                }
            } else {
                output[(y * stride + x) as usize] = (cov as u32
                    * match base {
                        4 => 4,
                        5 => 16,
                        _ => 64,
                    }
                    / 255) as u8;
            }
        }
    }
    need
}
extern "win64" fn GetOutlineTextMetricsA(_dc: u64, _size: u32, _out: *mut u8) -> u32 {
    0
}
extern "win64" fn GetICMProfileW(dc: u64, size: *mut u32, _out: *mut u16) -> Bool {
    if size.is_null() {
        return fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    if !with(|g| g.dcs.contains_key(&dc)) {
        return fail(ERROR_INVALID_HANDLE, FALSE);
    }
    fail(ERROR_FILE_NOT_FOUND, FALSE) // The compositor has no installed ICC profile.
}
extern "win64" fn ChoosePixelFormat(_dc: u64, _pfd: *const u8) -> i32 {
    fail(ERROR_NOT_SUPPORTED, 0)
}
extern "win64" fn SetPixelFormat(_dc: u64, _format: i32, _pfd: *const u8) -> Bool {
    fail(ERROR_NOT_SUPPORTED, FALSE)
}
extern "win64" fn SwapBuffers(_dc: u64) -> Bool {
    fail(ERROR_NOT_SUPPORTED, FALSE)
}
extern "win64" fn ExtEscape(
    _dc: u64,
    _escape: i32,
    _count: i32,
    _input: *const u8,
    _out_count: i32,
    _output: *mut u8,
) -> i32 {
    0
}

pub(super) fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        CreateDCW,
        CreateDCA,
        CreateICW,
        CreateCompatibleDC,
        DeleteDC,
        CreateBitmap,
        CreateCompatibleBitmap,
        CreateDIBitmap,
        CreateDIBSection,
        GetObjectW,
        GetDIBits,
        SetDIBits,
        BitBlt,
        StretchDIBits,
        GetPixel,
        BeginPath,
        EndPath,
        CloseFigure,
        FillPath,
        StrokePath,
        WidenPath,
        SelectClipPath,
        SelectClipRgn,
        ExtSelectClipRgn,
        CreateRectRgn,
        ExtCreateRegion,
        GetClipRgn,
        GetRgnBox,
        GetRegionData,
        GetRandomRgn,
        OffsetRgn,
        ExtCreatePen,
        PolyBezierTo,
        SaveDC,
        RestoreDC,
        SetMapMode,
        SetTextAlign,
        SetPolyFillMode,
        SetStretchBltMode,
        SetMiterLimit,
        GetGraphicsMode,
        SetGraphicsMode,
        GetCurrentObject,
        GetClipBox,
        IntersectClipRect,
        SetWorldTransform,
        GetWorldTransform,
        ModifyWorldTransform,
        ExtTextOutW,
        GetCharWidth32A,
        GetFontData,
        GetFontUnicodeRanges,
        GetGlyphIndicesW,
        GetGlyphOutlineW,
        GetOutlineTextMetricsA,
        GetICMProfileW,
        ChoosePixelFormat,
        SetPixelFormat,
        SwapBuffers,
        ExtEscape
    ]
    .into_iter()
    .chain([("CreateDC", CreateDCA as *const () as usize as u64)])
    .collect()
}
