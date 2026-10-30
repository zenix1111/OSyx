//! dwrite: DirectWrite's font model (IDWriteFactory version 1) over the
//! TrueType fonts in C:\Windows\Fonts and fonts a program loads itself
//! (custom font file loaders, as browsers do for web fonts).
//!
//! The system collection groups faces by their typographic family name.
//! Font faces answer metrics, glyph indices, tables and outlines from the
//! font file (ttf.rs); glyph-run analysis rasterizes outlines with
//! grayscale coverage (raster.rs), handed out as the ClearType 3x1 texture
//! with equal channels, or as a bilevel 1x1 texture for aliased rendering.
//! There is no hinting and no ClearType filtering. CreateFontFromLOGFONT
//! applies HKLM\...\FontSubstitutes as GDI does. Text layout, text
//! analysis and newer factory versions are not provided: QueryInterface
//! for them fails, which programs check. An interface method that is not
//! implemented returns E_NOTIMPL and, under -v, names itself.
#![allow(non_snake_case)]
mod iids;
pub mod raster;
pub mod ttf;

use crate::path;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};
use os_std::sync::Mutex;

pub type Guid = [u8; 16];

pub const fn guid(d1: u32, d2: u16, d3: u16, d4: [u8; 8]) -> Guid {
    let a = d1.to_le_bytes();
    let b = d2.to_le_bytes();
    let c = d3.to_le_bytes();
    [a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]]
}

const IID_IUNKNOWN: Guid = guid(0, 0, 0, [0xC0, 0, 0, 0, 0, 0, 0, 0x46]);

const S_OK: u32 = 0;
const E_NOTIMPL: u32 = 0x8000_4001;
const E_NOINTERFACE: u32 = 0x8000_4002;
const E_POINTER: u32 = 0x8000_4003;
const E_FAIL: u32 = 0x8000_4005;
const E_INVALIDARG: u32 = 0x8007_0057;
const E_NOT_SUFFICIENT_BUFFER: u32 = 0x8007_007A;
const DWRITE_E_FILEFORMAT: u32 = 0x8898_5000;
const DWRITE_E_NOFONT: u32 = 0x8898_5002;
const DWRITE_E_FILENOTFOUND: u32 = 0x8898_5003;
const DWRITE_E_ALREADYREGISTERED: u32 = 0x8898_5006;

/// Floats travel in xmm registers, which soft-float winrun code cannot
/// read: these entry points move them to integer registers (as raw bits)
/// and jump to the implementation, so stack arguments stay in place.
macro_rules! xmm_jmp {
    ($($name:ident => $imp:ident [$($mv:literal),*];)*) => {$(
        #[unsafe(naked)]
        extern "win64" fn $name() {
            core::arch::naked_asm!($($mv,)* "jmp {imp}", imp = sym $imp)
        }
    )*};
}

/// A float result: the implementation returns its bits in eax.
macro_rules! xmm_ret {
    ($($name:ident => $imp:ident;)*) => {$(
        #[unsafe(naked)]
        extern "win64" fn $name() {
            core::arch::naked_asm!("sub rsp, 40", "call {imp}", "add rsp, 40", "movd xmm0, eax", "ret", imp = sym $imp)
        }
    )*};
}

// ---- COM objects --------------------------------------------------------------------------

/// The start of every object: vtable, references, interface name and the
/// interfaces QueryInterface grants.
#[repr(C)]
struct Header {
    vtbl: *const *const (),
    refs: AtomicU32,
    name: &'static str,
    iids: &'static [Guid],
}

#[repr(C)]
struct Com<T> {
    h: Header,
    data: T,
}

struct Slots<const N: usize>([*const (); N]);
// SAFETY: function pointers only.
unsafe impl<const N: usize> Sync for Slots<N> {}

fn new<T, const N: usize>(vtbl: &'static Slots<N>, name: &'static str, iids: &'static [Guid], data: T) -> u64 {
    let b = Box::new(Com { h: Header { vtbl: vtbl.0.as_ptr(), refs: AtomicU32::new(1), name, iids }, data });
    Box::into_raw(b) as u64
}

fn data<'a, T>(this: u64) -> &'a T {
    // SAFETY: `this` is a Com<T> made by `new` with the vtable that routed
    // the call here (each vtable belongs to one data type).
    unsafe { &(*(this as *const Com<T>)).data }
}

fn header<'a>(this: u64) -> &'a Header {
    // SAFETY: every object starts with a Header.
    unsafe { &*(this as *const Header) }
}

/// Whether `obj` is one of ours made with `vtbl` (programs may pass their
/// own objects where ours are expected).
fn is<const N: usize>(obj: u64, vtbl: &'static Slots<N>) -> bool {
    obj != 0 && header(obj).vtbl == vtbl.0.as_ptr()
}

extern "win64" fn qi(this: u64, riid: *const Guid, out: *mut u64) -> u32 {
    if riid.is_null() || out.is_null() {
        return E_POINTER;
    }
    // SAFETY: the caller's IID and out pointer.
    unsafe {
        if *riid == IID_IUNKNOWN || header(this).iids.contains(&*riid) {
            add_ref(this);
            *out = this;
            return S_OK;
        }
        *out = 0;
    }
    E_NOINTERFACE
}

extern "win64" fn add_ref(this: u64) -> u32 {
    header(this).refs.fetch_add(1, Ordering::AcqRel) + 1
}

extern "win64" fn release<T>(this: u64) -> u32 {
    let left = header(this).refs.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        // SAFETY: the last reference to a Box made by `new`.
        drop(unsafe { Box::from_raw(this as *mut Com<T>) });
    }
    left
}

/// A method this implementation does not provide.
extern "win64" fn stub<const N: usize>(this: u64) -> u32 {
    if crate::VERBOSE.load(Ordering::Relaxed) {
        os_std::eprintln!("winrun: dwrite: {} method {} is not implemented", header(this).name, N);
    }
    E_NOTIMPL
}

/// Calls IUnknown::AddRef (1) or Release (2) on a program's object.
fn com_ref(obj: u64, slot: usize) -> u32 {
    // SAFETY: a COM object.
    unsafe {
        let f: extern "win64" fn(u64) -> u32 = core::mem::transmute(*(*(obj as *const *const u64)).add(slot));
        f(obj)
    }
}

/// Slot `n` of a program's COM object's vtable.
fn method(obj: u64, n: usize) -> u64 {
    // SAFETY: a COM object with at least `n + 1` methods.
    unsafe { *(*(obj as *const *const u64)).add(n) }
}

fn put<T: Copy>(p: *mut T, v: T) {
    if !p.is_null() {
        // SAFETY: the caller's out pointer.
        unsafe { *p = v };
    }
}

fn wide_bytes(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

// ---- font files -----------------------------------------------------------------------------

struct FileData {
    bytes: Arc<Vec<u8>>,
    /// A file on disk: its Windows path and FILETIME (the local loader's key).
    local: Option<(String, u64)>,
    /// A program's loader and key (AddRef'd loader).
    custom: Option<(u64, Vec<u8>)>,
}

impl Drop for FileData {
    fn drop(&mut self) {
        if let Some((loader, _)) = self.custom {
            com_ref(loader, 2);
        }
    }
}

/// A face of a font file as fonts and font faces share it.
struct FaceData {
    file: Arc<FileData>,
    face: ttf::Face,
    index: u32,
    simulations: u32,
}

fn read_local(win: &str) -> Option<(Arc<Vec<u8>>, u64)> {
    let p = path::to_osyx(win, &crate::kernel32::cwd_win()).ok()?;
    let bytes = os_std::fs::read(&p).ok()?;
    // FILETIME: 100 ns units since 1601.
    let mtime = os_sys::stat(&p).map(|s| (s.mtime_ns / 100) as u64 + 116_444_736_000_000_000).unwrap_or(0);
    Some((Arc::new(bytes), mtime))
}

// ---- the system font collection -------------------------------------------------------------

struct FontEntry {
    face: Arc<FaceData>,
    family: usize,
    weight: u32,
    stretch: u32,
    style: u32,
    face_name: String,
}

struct System {
    /// (family name, its fonts).
    families: Vec<(String, Vec<Arc<FontEntry>>)>,
}

static SYSTEM: Mutex<Option<Arc<System>>> = Mutex::new(None);

const FONTS_DIR: &str = "C:\\Windows\\Fonts";

fn system() -> Arc<System> {
    let mut s = SYSTEM.lock().unwrap();
    s.get_or_insert_with(|| Arc::new(scan())).clone()
}

fn scan() -> System {
    let mut files = Vec::new();
    let dir = path::to_osyx(FONTS_DIR, "C:\\").unwrap_or_default();
    let mut names: Vec<String> = os_std::fs::read_dir(&dir)
        .map(|it| it.map(|e| String::from(e.file_name())).collect())
        .unwrap_or_default();
    names.sort();
    for name in names {
        let lower = name.to_lowercase();
        if !(lower.ends_with(".ttf") || lower.ends_with(".ttc") || lower.ends_with(".otf")) {
            continue;
        }
        let win = alloc::format!("{FONTS_DIR}\\{name}");
        let Some((bytes, mtime)) = read_local(&win) else { continue };
        files.push(Arc::new(FileData { bytes, local: Some((win, mtime)), custom: None }));
    }
    build(&files)
}

/// A collection of the faces in `files`, grouped into families.
fn build(files: &[Arc<FileData>]) -> System {
    let mut families: Vec<(String, Vec<Arc<FontEntry>>)> = Vec::new();
    for file in files {
        let bytes = file.bytes.clone();
        for index in 0..ttf::face_count(&bytes) {
            let Some(face) = ttf::Face::parse(bytes.clone(), index) else { continue };
            // Faces without supported outlines would draw nothing.
            if !face.has_outlines() {
                continue;
            }
            let family_name = face.family();
            let fi = match families.iter().position(|f| f.0.eq_ignore_ascii_case(&family_name)) {
                Some(i) => i,
                None => {
                    families.push((family_name, Vec::new()));
                    families.len() - 1
                }
            };
            let entry = FontEntry {
                weight: face.weight() as u32,
                stretch: face.width_class() as u32,
                style: face.style(),
                face_name: face.subfamily(),
                face: Arc::new(FaceData { file: file.clone(), face, index, simulations: 0 }),
                family: fi,
            };
            families[fi].1.push(Arc::new(entry));
        }
    }
    System { families }
}

/// How far a font is from a requested weight, stretch and style (lower is
/// closer); style first, then stretch, then weight, as DirectWrite ranks.
fn distance(f: &FontEntry, weight: u32, stretch: u32, style: u32) -> u32 {
    let style_cost = if f.style == style { 0 } else if f.style != 0 && style != 0 { 1 } else { 2 };
    style_cost * 100_000 + f.stretch.abs_diff(stretch) * 1000 + f.weight.abs_diff(weight)
}

// ---- localized strings ----------------------------------------------------------------------

static STRINGS_VT: Slots<9> = Slots([
    qi as *const (),
    add_ref as _,
    release::<Vec<(String, String)>> as _,
    StrGetCount as _,
    StrFindLocaleName as _,
    StrGetLocaleNameLength as _,
    StrGetLocaleName as _,
    StrGetStringLength as _,
    StrGetString as _,
]);
static STRINGS_IIDS: [Guid; 1] = [iids::LOCALIZED_STRINGS];

fn strings(list: Vec<(String, String)>) -> u64 {
    new(&STRINGS_VT, "IDWriteLocalizedStrings", &STRINGS_IIDS, list)
}

fn english(s: String) -> u64 {
    strings(alloc::vec![(String::from("en-us"), s)])
}

extern "win64" fn StrGetCount(this: u64) -> u32 {
    data::<Vec<(String, String)>>(this).len() as u32
}

extern "win64" fn StrFindLocaleName(this: u64, name: *const u16, index: *mut u32, exists: *mut i32) -> u32 {
    if name.is_null() || index.is_null() || exists.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: a NUL-terminated locale name.
    let want = unsafe { path::wide_to_string(name) }.unwrap_or_default();
    match data::<Vec<(String, String)>>(this).iter().position(|(l, _)| l.eq_ignore_ascii_case(&want)) {
        Some(i) => {
            put(index, i as u32);
            put(exists, 1);
        }
        None => {
            put(index, u32::MAX);
            put(exists, 0);
        }
    }
    S_OK
}

fn str_len(s: &str, len: *mut u32) -> u32 {
    if len.is_null() {
        return E_INVALIDARG;
    }
    put(len, wide_bytes(s).len() as u32);
    S_OK
}

fn str_copy(s: &str, buf: *mut u16, size: u32) -> u32 {
    let w = wide_bytes(s);
    if buf.is_null() || (size as usize) < w.len() + 1 {
        // Windows leaves as much as fits, terminated.
        if !buf.is_null() && size > 0 {
            let n = size as usize - 1;
            // SAFETY: the caller's buffer of `size` units.
            unsafe {
                core::ptr::copy_nonoverlapping(w.as_ptr(), buf, n);
                *buf.add(n) = 0;
            }
        }
        return E_NOT_SUFFICIENT_BUFFER;
    }
    // SAFETY: the caller's buffer of `size` units.
    unsafe {
        core::ptr::copy_nonoverlapping(w.as_ptr(), buf, w.len());
        *buf.add(w.len()) = 0;
    }
    S_OK
}

extern "win64" fn StrGetLocaleNameLength(this: u64, i: u32, len: *mut u32) -> u32 {
    match data::<Vec<(String, String)>>(this).get(i as usize) {
        Some((l, _)) => str_len(l, len),
        None => E_INVALIDARG,
    }
}

extern "win64" fn StrGetLocaleName(this: u64, i: u32, buf: *mut u16, size: u32) -> u32 {
    match data::<Vec<(String, String)>>(this).get(i as usize) {
        Some((l, _)) => str_copy(l, buf, size),
        None => E_INVALIDARG,
    }
}

extern "win64" fn StrGetStringLength(this: u64, i: u32, len: *mut u32) -> u32 {
    match data::<Vec<(String, String)>>(this).get(i as usize) {
        Some((_, s)) => str_len(s, len),
        None => E_INVALIDARG,
    }
}

extern "win64" fn StrGetString(this: u64, i: u32, buf: *mut u16, size: u32) -> u32 {
    match data::<Vec<(String, String)>>(this).get(i as usize) {
        Some((_, s)) => str_copy(s, buf, size),
        None => E_INVALIDARG,
    }
}

// ---- collection, families, fonts -----------------------------------------------------------

static COLLECTION_VT: Slots<7> = Slots([
    qi as *const (),
    add_ref as _,
    release::<Arc<System>> as _,
    ColGetFontFamilyCount as _,
    ColGetFontFamily as _,
    ColFindFamilyName as _,
    ColGetFontFromFontFace as _,
]);
static COLLECTION_IIDS: [Guid; 1] = [iids::FONT_COLLECTION];

fn collection(s: Arc<System>) -> u64 {
    new(&COLLECTION_VT, "IDWriteFontCollection", &COLLECTION_IIDS, s)
}

extern "win64" fn ColGetFontFamilyCount(this: u64) -> u32 {
    data::<Arc<System>>(this).families.len() as u32
}

extern "win64" fn ColGetFontFamily(this: u64, i: u32, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let s = data::<Arc<System>>(this);
    if i as usize >= s.families.len() {
        put(out, 0);
        return E_INVALIDARG;
    }
    put(out, family(s.clone(), i as usize));
    S_OK
}

extern "win64" fn ColFindFamilyName(this: u64, name: *const u16, index: *mut u32, exists: *mut i32) -> u32 {
    if name.is_null() || index.is_null() || exists.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: a NUL-terminated family name.
    let want = unsafe { path::wide_to_string(name) }.unwrap_or_default();
    match data::<Arc<System>>(this).families.iter().position(|f| f.0.eq_ignore_ascii_case(&want)) {
        Some(i) => {
            put(index, i as u32);
            put(exists, 1);
        }
        None => {
            put(index, u32::MAX);
            put(exists, 0);
        }
    }
    S_OK
}

extern "win64" fn ColGetFontFromFontFace(this: u64, face: u64, out: *mut u64) -> u32 {
    if out.is_null() || !is(face, &FACE_VT) {
        return E_INVALIDARG;
    }
    let fd = data::<Arc<FaceData>>(face);
    let s = data::<Arc<System>>(this);
    for fam in &s.families {
        if let Some(f) = fam.1.iter().find(|f| Arc::ptr_eq(&f.face.file.bytes, &fd.file.bytes) && f.face.index == fd.index) {
            put(out, font(s.clone(), f.clone()));
            return S_OK;
        }
    }
    put(out, 0);
    DWRITE_E_NOFONT
}

struct FamilyData {
    system: Arc<System>,
    index: usize,
}

static FAMILY_VT: Slots<9> = Slots([
    qi as *const (),
    add_ref as _,
    release::<FamilyData> as _,
    FamGetFontCollection as _,
    FamGetFontCount as _,
    FamGetFont as _,
    FamGetFamilyNames as _,
    FamGetFirstMatchingFont as _,
    FamGetMatchingFonts as _,
]);
static FAMILY_IIDS: [Guid; 2] = [iids::FONT_FAMILY, iids::FONT_LIST];

fn family(system: Arc<System>, index: usize) -> u64 {
    new(&FAMILY_VT, "IDWriteFontFamily", &FAMILY_IIDS, FamilyData { system, index })
}

fn fonts_of(this: u64) -> (&'static Arc<System>, &'static [Arc<FontEntry>]) {
    let d = data::<FamilyData>(this);
    (&d.system, &d.system.families[d.index].1)
}

extern "win64" fn FamGetFontCollection(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    put(out, collection(data::<FamilyData>(this).system.clone()));
    S_OK
}

extern "win64" fn FamGetFontCount(this: u64) -> u32 {
    fonts_of(this).1.len() as u32
}

extern "win64" fn FamGetFont(this: u64, i: u32, out: *mut u64) -> u32 {
    let (s, fonts) = fonts_of(this);
    match fonts.get(i as usize) {
        Some(f) if !out.is_null() => {
            put(out, font(s.clone(), f.clone()));
            S_OK
        }
        _ => {
            put(out, 0);
            E_INVALIDARG
        }
    }
}

extern "win64" fn FamGetFamilyNames(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let d = data::<FamilyData>(this);
    put(out, english(d.system.families[d.index].0.clone()));
    S_OK
}

extern "win64" fn FamGetFirstMatchingFont(this: u64, weight: u32, stretch: u32, style: u32, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let (s, fonts) = fonts_of(this);
    match fonts.iter().min_by_key(|f| distance(f, weight, stretch, style)) {
        Some(f) => {
            put(out, font(s.clone(), f.clone()));
            S_OK
        }
        None => {
            put(out, 0);
            DWRITE_E_NOFONT
        }
    }
}

struct ListData {
    system: Arc<System>,
    fonts: Vec<Arc<FontEntry>>,
}

static LIST_VT: Slots<6> = Slots([
    qi as *const (),
    add_ref as _,
    release::<ListData> as _,
    ListGetFontCollection as _,
    ListGetFontCount as _,
    ListGetFont as _,
]);
static LIST_IIDS: [Guid; 1] = [iids::FONT_LIST];

extern "win64" fn FamGetMatchingFonts(this: u64, weight: u32, stretch: u32, style: u32, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let (s, fonts) = fonts_of(this);
    let mut v: Vec<Arc<FontEntry>> = fonts.to_vec();
    v.sort_by_key(|f| distance(f, weight, stretch, style));
    put(out, new(&LIST_VT, "IDWriteFontList", &LIST_IIDS, ListData { system: s.clone(), fonts: v }));
    S_OK
}

extern "win64" fn ListGetFontCollection(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    put(out, collection(data::<ListData>(this).system.clone()));
    S_OK
}

extern "win64" fn ListGetFontCount(this: u64) -> u32 {
    data::<ListData>(this).fonts.len() as u32
}

extern "win64" fn ListGetFont(this: u64, i: u32, out: *mut u64) -> u32 {
    let d = data::<ListData>(this);
    match d.fonts.get(i as usize) {
        Some(f) if !out.is_null() => {
            put(out, font(d.system.clone(), f.clone()));
            S_OK
        }
        _ => {
            put(out, 0);
            E_INVALIDARG
        }
    }
}

struct FontData {
    system: Arc<System>,
    entry: Arc<FontEntry>,
}

static FONT_VT: Slots<14> = Slots([
    qi as *const (),
    add_ref as _,
    release::<FontData> as _,
    FontGetFontFamily as _,
    FontGetWeight as _,
    FontGetStretch as _,
    FontGetStyle as _,
    FontIsSymbolFont as _,
    FontGetFaceNames as _,
    FontGetInformationalStrings as _,
    FontGetSimulations as _,
    FontGetMetrics as _,
    FontHasCharacter as _,
    FontCreateFontFace as _,
]);
static FONT_IIDS: [Guid; 1] = [iids::FONT];

fn font(system: Arc<System>, entry: Arc<FontEntry>) -> u64 {
    new(&FONT_VT, "IDWriteFont", &FONT_IIDS, FontData { system, entry })
}

fn entry(this: u64) -> &'static Arc<FontEntry> {
    &data::<FontData>(this).entry
}

extern "win64" fn FontGetFontFamily(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let d = data::<FontData>(this);
    put(out, family(d.system.clone(), d.entry.family));
    S_OK
}

extern "win64" fn FontGetWeight(this: u64) -> u32 {
    entry(this).weight
}

extern "win64" fn FontGetStretch(this: u64) -> u32 {
    entry(this).stretch
}

extern "win64" fn FontGetStyle(this: u64) -> u32 {
    entry(this).style
}

extern "win64" fn FontIsSymbolFont(this: u64) -> i32 {
    entry(this).face.face.is_symbol() as i32
}

extern "win64" fn FontGetFaceNames(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    put(out, english(entry(this).face_name.clone()));
    S_OK
}

/// DWRITE_INFORMATIONAL_STRING_ID to an OpenType name ID.
fn name_id(id: u32) -> Option<u16> {
    Some(match id {
        1 => 0,
        2 => 5,
        3 => 7,
        4 => 8,
        5 => 9,
        6 => 12,
        7 => 10,
        8 => 11,
        9 => 13,
        10 => 14,
        11 => 1,
        12 => 2,
        13 => 16,
        14 => 17,
        15 => 19,
        16 => 4,
        17 => 6,
        18 => 20,
        _ => return None,
    })
}

extern "win64" fn FontGetInformationalStrings(this: u64, id: u32, out: *mut u64, exists: *mut i32) -> u32 {
    if out.is_null() || exists.is_null() {
        return E_INVALIDARG;
    }
    match name_id(id).and_then(|n| entry(this).face.face.name(n)) {
        Some(s) => {
            put(out, english(s));
            put(exists, 1);
        }
        None => {
            put(out, 0);
            put(exists, 0);
        }
    }
    S_OK
}

extern "win64" fn FontGetSimulations(this: u64) -> u32 {
    entry(this).face.simulations
}

/// DWRITE_FONT_METRICS (20 bytes).
fn metrics(f: &ttf::Face, out: *mut u16) {
    if out.is_null() {
        return;
    }
    let (ascent, descent, gap) = f.vertical_metrics();
    let (up, ut) = f.underline();
    let (sp, st) = f.strikeout();
    let v: [u16; 10] = [f.units_per_em, ascent, descent, gap as u16, f.cap_height(), f.x_height(), up as u16, ut, sp as u16, st];
    // SAFETY: the caller's DWRITE_FONT_METRICS.
    unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), out, 10) };
}

extern "win64" fn FontGetMetrics(this: u64, out: *mut u16) {
    metrics(&entry(this).face.face, out);
}

extern "win64" fn FontHasCharacter(this: u64, c: u32, exists: *mut i32) -> u32 {
    if exists.is_null() {
        return E_INVALIDARG;
    }
    put(exists, (entry(this).face.face.glyph_index(c) != 0) as i32);
    S_OK
}

extern "win64" fn FontCreateFontFace(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    put(out, face(entry(this).face.clone()));
    S_OK
}

// ---- font faces --------------------------------------------------------------------------------

static FACE_VT: Slots<18> = Slots([
    qi as *const (),
    add_ref as _,
    release::<Arc<FaceData>> as _,
    FaceGetType as _,
    FaceGetFiles as _,
    FaceGetIndex as _,
    FaceGetSimulations as _,
    FaceIsSymbolFont as _,
    FaceGetMetrics as _,
    FaceGetGlyphCount as _,
    FaceGetDesignGlyphMetrics as _,
    FaceGetGlyphIndices as _,
    FaceTryGetFontTable as _,
    FaceReleaseFontTable as _,
    FaceGetGlyphRunOutline as _,
    FaceGetRecommendedRenderingMode as _,
    FaceGetGdiCompatibleMetrics as _,
    FaceGetGdiCompatibleGlyphMetrics as _,
]);
static FACE_IIDS: [Guid; 1] = [iids::FONT_FACE];

fn face(d: Arc<FaceData>) -> u64 {
    new(&FACE_VT, "IDWriteFontFace", &FACE_IIDS, d)
}

fn face_of(this: u64) -> &'static Arc<FaceData> {
    data::<Arc<FaceData>>(this)
}

/// DWRITE_FONT_FACE_TYPE: CFF 0, TrueType 1, collection 2.
fn face_type(f: &ttf::Face) -> u32 {
    if f.is_collection() {
        2
    } else if f.has_glyf() {
        1
    } else {
        0
    }
}

extern "win64" fn FaceGetType(this: u64) -> u32 {
    face_type(&face_of(this).face)
}

extern "win64" fn FaceGetFiles(this: u64, count: *mut u32, files: *mut u64) -> u32 {
    if count.is_null() {
        return E_INVALIDARG;
    }
    // SAFETY: the caller's count.
    let have = unsafe { *count };
    put(count, 1);
    if !files.is_null() {
        if have < 1 {
            return E_INVALIDARG;
        }
        put(files, file(face_of(this).file.clone()));
    }
    S_OK
}

extern "win64" fn FaceGetIndex(this: u64) -> u32 {
    face_of(this).index
}

extern "win64" fn FaceGetSimulations(this: u64) -> u32 {
    face_of(this).simulations
}

extern "win64" fn FaceIsSymbolFont(this: u64) -> i32 {
    face_of(this).face.is_symbol() as i32
}

extern "win64" fn FaceGetMetrics(this: u64, out: *mut u16) {
    metrics(&face_of(this).face, out);
}

extern "win64" fn FaceGetGlyphCount(this: u64) -> u16 {
    face_of(this).face.glyph_count
}

/// DWRITE_GLYPH_METRICS (7 x 32 bits) of one glyph, in design units.
fn glyph_metrics(f: &ttf::Face, g: u16) -> [i32; 7] {
    let (adv, lsb) = f.h_metrics(g);
    let (vadv, tsb) = f.v_metrics(g);
    let (ascent, _, _) = f.vertical_metrics();
    match f.glyph_box(g) {
        Some((x0, y0, x1, y1)) if x1 > x0 || y1 > y0 => {
            let rsb = adv as i32 - (lsb as i32 + (x1 as i32 - x0 as i32));
            let top = if f.table(b"vmtx").is_some() { tsb as i32 } else { ascent as i32 - y1 as i32 };
            let bsb = vadv as i32 - (top + (y1 as i32 - y0 as i32));
            [lsb as i32, adv as i32, rsb, top, vadv as i32, bsb, ascent as i32]
        }
        // An empty glyph: the advances are all side bearing, measured from
        // the origin (the vertical origin is the ascent).
        _ => [0, adv as i32, adv as i32, ascent as i32, vadv as i32, vadv as i32 - ascent as i32, ascent as i32],
    }
}

extern "win64" fn FaceGetDesignGlyphMetrics(this: u64, glyphs: *const u16, n: u32, out: *mut [i32; 7], _sideways: i32) -> u32 {
    if glyphs.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    let f = &face_of(this).face;
    for i in 0..n as usize {
        // SAFETY: the caller's arrays of `n` elements.
        unsafe {
            let g = *glyphs.add(i);
            // Windows answers glyphs past the font's count, with nothing.
            *out.add(i) = if g < f.glyph_count { glyph_metrics(f, g) } else { [0; 7] };
        }
    }
    S_OK
}

extern "win64" fn FaceGetGlyphIndices(this: u64, chars: *const u32, n: u32, out: *mut u16) -> u32 {
    if (chars.is_null() || out.is_null()) && n > 0 {
        return E_INVALIDARG;
    }
    let f = &face_of(this).face;
    for i in 0..n as usize {
        // SAFETY: the caller's arrays of `n` elements.
        unsafe { *out.add(i) = f.glyph_index(*chars.add(i)) };
    }
    S_OK
}

extern "win64" fn FaceTryGetFontTable(this: u64, tag: u32, out: *mut *const u8, size: *mut u32, ctx: *mut u64, exists: *mut i32) -> u32 {
    if out.is_null() || size.is_null() || ctx.is_null() || exists.is_null() {
        return E_INVALIDARG;
    }
    put(ctx, 0);
    // DWRITE_MAKE_OPENTYPE_TAG puts the first character in the low byte.
    match face_of(this).face.table_by_tag(tag.swap_bytes()) {
        Some(t) => {
            put(out, t.as_ptr());
            put(size, t.len() as u32);
            put(exists, 1);
        }
        None => {
            put(out, core::ptr::null());
            put(size, 0);
            put(exists, 0);
        }
    }
    S_OK
}

/// Tables point into the face's file data, which lives as long as the face.
extern "win64" fn FaceReleaseFontTable(_this: u64, _ctx: u64) {}

/// D2D1_POINT_2F as the 64-bit value it travels in.
fn point(x: f32, y: f32) -> u64 {
    x.to_bits() as u64 | (y.to_bits() as u64) << 32
}

extern "win64" fn face_glyph_run_outline(
    this: u64,
    em_bits: u32,
    glyphs: *const u16,
    advances: *const u32,
    offsets: *const [u32; 2],
    n: u32,
    _sideways: i32,
    rtl: i32,
    sink: u64,
) -> u32 {
    if sink == 0 || (glyphs.is_null() && n > 0) {
        return E_INVALIDARG;
    }
    let f = &face_of(this).face;
    let em = f32::from_bits(em_bits);
    let s = em / f.units_per_em as f32;
    type Begin = extern "win64" fn(u64, u64, u32);
    type Points = extern "win64" fn(u64, *const u64, u32);
    type End = extern "win64" fn(u64, u32);
    // SAFETY: the sink's ID2D1SimplifiedGeometrySink methods BeginFigure,
    // AddLines, AddBeziers and EndFigure.
    let (begin, lines, beziers, end) = unsafe {
        (
            core::mem::transmute::<u64, Begin>(method(sink, 5)),
            core::mem::transmute::<u64, Points>(method(sink, 6)),
            core::mem::transmute::<u64, Points>(method(sink, 7)),
            core::mem::transmute::<u64, End>(method(sink, 8)),
        )
    };
    let mut pen = 0f32;
    for i in 0..n as usize {
        // SAFETY: the caller's arrays of `n` elements (advances and offsets optional).
        let (g, adv, off) = unsafe {
            (
                *glyphs.add(i),
                if advances.is_null() { None } else { Some(f32::from_bits(*advances.add(i))) },
                if offsets.is_null() { (0f32, 0f32) } else { let o = *offsets.add(i); (f32::from_bits(o[0]), f32::from_bits(o[1])) },
            )
        };
        let adv = adv.unwrap_or_else(|| f.h_metrics(g).0 as f32 * s);
        if rtl != 0 {
            pen -= adv;
        }
        let ox = pen + if rtl != 0 { -off.0 } else { off.0 };
        let oy = -off.1;
        let pt = |p: ttf::Point| (ox + p.x as f32 * s, oy - p.y as f32 * s);
        for contour in f.outline(g) {
            let segs = segments(&contour);
            let Some(&first) = segs.first() else { continue };
            let start = pt(first.1);
            begin(sink, point(start.0, start.1), 0); // D2D1_FIGURE_BEGIN_FILLED
            let mut cur = start;
            for &(c, p) in &segs[1..] {
                let p = pt(p);
                match c {
                    None => lines(sink, &point(p.0, p.1), 1),
                    Some(c) => {
                        let c = pt(c);
                        // The quadratic as a cubic Bezier.
                        let c1 = (cur.0 + (c.0 - cur.0) * 2.0 / 3.0, cur.1 + (c.1 - cur.1) * 2.0 / 3.0);
                        let c2 = (p.0 + (c.0 - p.0) * 2.0 / 3.0, p.1 + (c.1 - p.1) * 2.0 / 3.0);
                        let seg = [point(c1.0, c1.1), point(c2.0, c2.1), point(p.0, p.1)];
                        beziers(sink, seg.as_ptr(), 1);
                    }
                }
                cur = p;
            }
            end(sink, 1); // D2D1_FIGURE_END_CLOSED
        }
        if rtl == 0 {
            pen += adv;
        }
    }
    S_OK
}

/// A contour as a start point and then (control, end) segments, closed.
fn segments(c: &[ttf::Point]) -> Vec<(Option<ttf::Point>, ttf::Point)> {
    let n = c.len();
    let mut out = Vec::new();
    if n < 2 {
        return out;
    }
    let mid = |a: ttf::Point, b: ttf::Point| ttf::Point { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2, on: true };
    let first_on = c.iter().position(|p| p.on);
    let start = match first_on {
        Some(i) => c[i],
        None => mid(c[0], c[1]),
    };
    let s = first_on.unwrap_or(0);
    out.push((None, start));
    let mut ctrl: Option<ttf::Point> = None;
    for k in 1..=n {
        let p = c[(s + k) % n];
        match (p.on, ctrl) {
            (true, None) => out.push((None, p)),
            (true, Some(q)) => {
                out.push((Some(q), p));
                ctrl = None;
            }
            (false, None) => ctrl = Some(p),
            (false, Some(q)) => {
                out.push((Some(q), mid(q, p)));
                ctrl = Some(p);
            }
        }
    }
    if let Some(q) = ctrl {
        out.push((Some(q), start));
    }
    out
}

/// DWRITE_RENDERING_MODE: outlines from 100 pixels per em, else natural
/// symmetric (antialiased in both directions).
extern "win64" fn face_recommended_rendering_mode(_this: u64, em_bits: u32, ppd_bits: u32, _measuring: u32, _params: u64, out: *mut u32) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let px = f32::from_bits(em_bits) * f32::from_bits(ppd_bits);
    put(out, if px >= 100.0 { 6 } else { 5 });
    S_OK
}

/// Without hinting, GDI-compatible metrics are the design metrics.
extern "win64" fn face_gdi_compatible_metrics(this: u64, _em: u32, _ppd: u32, _transform: u64, out: *mut u16) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    metrics(&face_of(this).face, out);
    S_OK
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn face_gdi_compatible_glyph_metrics(
    this: u64,
    _em: u32,
    _ppd: u32,
    _transform: u64,
    _natural: i32,
    glyphs: *const u16,
    n: u32,
    out: *mut [i32; 7],
    sideways: i32,
) -> u32 {
    FaceGetDesignGlyphMetrics(this, glyphs, n, out, sideways)
}

xmm_jmp! {
    FaceGetGlyphRunOutline => face_glyph_run_outline ["movd edx, xmm1"];
    FaceGetRecommendedRenderingMode => face_recommended_rendering_mode ["movd edx, xmm1", "movd r8d, xmm2"];
    FaceGetGdiCompatibleMetrics => face_gdi_compatible_metrics ["movd edx, xmm1", "movd r8d, xmm2"];
    FaceGetGdiCompatibleGlyphMetrics => face_gdi_compatible_glyph_metrics ["movd edx, xmm1", "movd r8d, xmm2"];
}

// ---- font files and loaders -------------------------------------------------------------------

static FILE_VT: Slots<6> = Slots([
    qi as *const (),
    add_ref as _,
    release::<Arc<FileData>> as _,
    FileGetReferenceKey as _,
    FileGetLoader as _,
    FileAnalyze as _,
]);
static FILE_IIDS: [Guid; 1] = [iids::FONT_FILE];

fn file(d: Arc<FileData>) -> u64 {
    new(&FILE_VT, "IDWriteFontFile", &FILE_IIDS, d)
}

/// The local loader's key: the FILETIME, then the path in UTF-16 with NUL.
fn local_key(path: &str, mtime: u64) -> Vec<u8> {
    let mut k = mtime.to_le_bytes().to_vec();
    for u in path.encode_utf16().chain(core::iter::once(0)) {
        k.extend_from_slice(&u.to_le_bytes());
    }
    k
}

fn parse_key(key: *const u8, size: u32) -> Option<(String, u64)> {
    if key.is_null() || size < 10 {
        return None;
    }
    // SAFETY: the caller's key of `size` bytes.
    let k = unsafe { core::slice::from_raw_parts(key, size as usize) };
    let mtime = u64::from_le_bytes(k[0..8].try_into().ok()?);
    let units: Vec<u16> = k[8..].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&u| u != 0).collect();
    Some((String::from_utf16_lossy(&units), mtime))
}

/// Keys handed out by GetReferenceKey, kept as long as their file.
static KEYS: Mutex<Vec<(usize, Vec<u8>)>> = Mutex::new(Vec::new());

extern "win64" fn FileGetReferenceKey(this: u64, key: *mut *const u8, size: *mut u32) -> u32 {
    if key.is_null() || size.is_null() {
        return E_INVALIDARG;
    }
    let d = data::<Arc<FileData>>(this);
    let (ptr, len) = match (&d.local, &d.custom) {
        (_, Some((_, k))) => (k.as_ptr(), k.len()),
        (Some((p, t)), None) => {
            let id = Arc::as_ptr(d) as usize;
            let mut keys = KEYS.lock().unwrap();
            if !keys.iter().any(|(i, _)| *i == id) {
                keys.push((id, local_key(p, *t)));
            }
            let k = &keys.iter().find(|(i, _)| *i == id).unwrap().1;
            (k.as_ptr(), k.len())
        }
        (None, None) => (core::ptr::null(), 0),
    };
    put(key, ptr);
    put(size, len as u32);
    S_OK
}

extern "win64" fn FileGetLoader(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    match &data::<Arc<FileData>>(this).custom {
        Some((loader, _)) => {
            com_ref(*loader, 1);
            put(out, *loader);
        }
        None => put(out, local_loader()),
    }
    S_OK
}

extern "win64" fn FileAnalyze(this: u64, supported: *mut i32, file_type: *mut u32, face_type: *mut u32, faces: *mut u32) -> u32 {
    if supported.is_null() || file_type.is_null() || face_type.is_null() || faces.is_null() {
        return E_INVALIDARG;
    }
    let bytes = data::<Arc<FileData>>(this).bytes.clone();
    let n = ttf::face_count(&bytes);
    match ttf::Face::parse(bytes, 0) {
        Some(f) => {
            put(supported, 1);
            // DWRITE_FONT_FILE_TYPE: CFF 1, TrueType 2, collection 3.
            put(file_type, if f.is_collection() { 3 } else if f.has_glyf() { 2 } else { 1 });
            put(face_type, face_type_of(&f));
            put(faces, n);
        }
        None => {
            put(supported, 0);
            put(file_type, 0);
            put(face_type, 6); // DWRITE_FONT_FACE_TYPE_UNKNOWN
            put(faces, 0);
        }
    }
    S_OK
}

fn face_type_of(f: &ttf::Face) -> u32 {
    face_type(f)
}

static LOADER_VT: Slots<7> = Slots([
    qi as *const (),
    loader_ref as _,
    loader_ref as _,
    LoaderCreateStreamFromKey as _,
    LoaderGetFilePathLengthFromKey as _,
    LoaderGetFilePathFromKey as _,
    LoaderGetLastWriteTimeFromKey as _,
]);
static LOADER_IIDS: [Guid; 2] = [iids::FONT_FILE_LOADER, iids::LOCAL_FONT_FILE_LOADER];

/// The local loader is a process-wide singleton: references do nothing.
extern "win64" fn loader_ref(_this: u64) -> u32 {
    1
}

static LOCAL_LOADER: Mutex<u64> = Mutex::new(0);

fn local_loader() -> u64 {
    let mut l = LOCAL_LOADER.lock().unwrap();
    if *l == 0 {
        *l = new(&LOADER_VT, "IDWriteLocalFontFileLoader", &LOADER_IIDS, ());
    }
    *l
}

extern "win64" fn LoaderCreateStreamFromKey(_this: u64, key: *const u8, size: u32, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    let Some((p, _)) = parse_key(key, size) else { return E_INVALIDARG };
    match read_local(&p) {
        Some((bytes, mtime)) => {
            put(out, stream(bytes, mtime));
            S_OK
        }
        None => {
            put(out, 0);
            DWRITE_E_FILENOTFOUND
        }
    }
}

extern "win64" fn LoaderGetFilePathLengthFromKey(_this: u64, key: *const u8, size: u32, len: *mut u32) -> u32 {
    match parse_key(key, size) {
        Some((p, _)) => str_len(&p, len),
        None => E_INVALIDARG,
    }
}

extern "win64" fn LoaderGetFilePathFromKey(_this: u64, key: *const u8, size: u32, buf: *mut u16, n: u32) -> u32 {
    match parse_key(key, size) {
        Some((p, _)) => str_copy(&p, buf, n),
        None => E_INVALIDARG,
    }
}

extern "win64" fn LoaderGetLastWriteTimeFromKey(_this: u64, key: *const u8, size: u32, out: *mut u64) -> u32 {
    match parse_key(key, size) {
        Some((_, t)) if !out.is_null() => {
            put(out, t);
            S_OK
        }
        _ => E_INVALIDARG,
    }
}

struct StreamData {
    bytes: Arc<Vec<u8>>,
    mtime: u64,
}

static STREAM_VT: Slots<7> = Slots([
    qi as *const (),
    add_ref as _,
    release::<StreamData> as _,
    StreamReadFileFragment as _,
    StreamReleaseFileFragment as _,
    StreamGetFileSize as _,
    StreamGetLastWriteTime as _,
]);
static STREAM_IIDS: [Guid; 1] = [iids::FONT_FILE_STREAM];

fn stream(bytes: Arc<Vec<u8>>, mtime: u64) -> u64 {
    new(&STREAM_VT, "IDWriteFontFileStream", &STREAM_IIDS, StreamData { bytes, mtime })
}

extern "win64" fn StreamReadFileFragment(this: u64, start: *mut *const u8, offset: u64, size: u64, ctx: *mut u64) -> u32 {
    if start.is_null() || ctx.is_null() {
        return E_INVALIDARG;
    }
    let d = data::<StreamData>(this);
    put(ctx, 0);
    match offset.checked_add(size) {
        Some(e) if e <= d.bytes.len() as u64 => {
            // SAFETY: within the stream's data, which lives with the stream.
            put(start, unsafe { d.bytes.as_ptr().add(offset as usize) });
            S_OK
        }
        _ => {
            put(start, core::ptr::null());
            E_FAIL
        }
    }
}

extern "win64" fn StreamReleaseFileFragment(_this: u64, _ctx: u64) {}

extern "win64" fn StreamGetFileSize(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    put(out, data::<StreamData>(this).bytes.len() as u64);
    S_OK
}

extern "win64" fn StreamGetLastWriteTime(this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    put(out, data::<StreamData>(this).mtime);
    S_OK
}

// ---- rendering parameters ---------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Params {
    gamma: u32,
    contrast: u32,
    cleartype: u32,
    geometry: u32,
    mode: u32,
}

/// Windows' defaults: gamma 1.8, enhanced contrast 0.5, ClearType level
/// 1.0, RGB stripes, default mode.
fn default_params() -> Params {
    Params { gamma: 1.8f32.to_bits(), contrast: 0.5f32.to_bits(), cleartype: 1.0f32.to_bits(), geometry: 1, mode: 0 }
}

static PARAMS_VT: Slots<8> = Slots([
    qi as *const (),
    add_ref as _,
    release::<Params> as _,
    ParamsGetGamma as _,
    ParamsGetEnhancedContrast as _,
    ParamsGetClearTypeLevel as _,
    ParamsGetPixelGeometry as _,
    ParamsGetRenderingMode as _,
]);
static PARAMS_IIDS: [Guid; 1] = [iids::RENDERING_PARAMS];

fn params(p: Params) -> u64 {
    new(&PARAMS_VT, "IDWriteRenderingParams", &PARAMS_IIDS, p)
}

extern "win64" fn params_gamma(this: u64) -> u32 {
    data::<Params>(this).gamma
}

extern "win64" fn params_contrast(this: u64) -> u32 {
    data::<Params>(this).contrast
}

extern "win64" fn params_cleartype(this: u64) -> u32 {
    data::<Params>(this).cleartype
}

xmm_ret! {
    ParamsGetGamma => params_gamma;
    ParamsGetEnhancedContrast => params_contrast;
    ParamsGetClearTypeLevel => params_cleartype;
}

extern "win64" fn ParamsGetPixelGeometry(this: u64) -> u32 {
    data::<Params>(this).geometry
}

extern "win64" fn ParamsGetRenderingMode(this: u64) -> u32 {
    data::<Params>(this).mode
}

// ---- glyph run analysis -----------------------------------------------------------------------

struct Analysis {
    /// (left, top, right, bottom) in pixels; None when nothing is drawn.
    bounds: Option<(i32, i32, i32, i32)>,
    coverage: Vec<u8>,
    aliased: bool,
}

static ANALYSIS_VT: Slots<6> = Slots([
    qi as *const (),
    add_ref as _,
    release::<Analysis> as _,
    AnaGetAlphaTextureBounds as _,
    AnaCreateAlphaTexture as _,
    AnaGetAlphaBlendParams as _,
]);
static ANALYSIS_IIDS: [Guid; 1] = [iids::GLYPH_RUN_ANALYSIS];

const DWRITE_RENDERING_MODE_ALIASED: u32 = 1;
const DWRITE_RENDERING_MODE_OUTLINE: u32 = 6;
const DWRITE_TEXTURE_ALIASED_1X1: u32 = 0;
const DWRITE_TEXTURE_CLEARTYPE_3X1: u32 = 1;

/// The texture type this analysis provides.
fn texture_ok(a: &Analysis, kind: u32) -> bool {
    kind == if a.aliased { DWRITE_TEXTURE_ALIASED_1X1 } else { DWRITE_TEXTURE_CLEARTYPE_3X1 }
}

extern "win64" fn AnaGetAlphaTextureBounds(this: u64, kind: u32, out: *mut [i32; 4]) -> u32 {
    if out.is_null() || kind > 1 {
        return E_INVALIDARG;
    }
    let a = data::<Analysis>(this);
    let r = match a.bounds {
        Some((l, t, r, b)) if texture_ok(a, kind) => [l, t, r, b],
        _ => [0, 0, 0, 0],
    };
    put(out, r);
    S_OK
}

extern "win64" fn AnaCreateAlphaTexture(this: u64, kind: u32, rect: *const [i32; 4], buf: *mut u8, size: u32) -> u32 {
    if rect.is_null() || buf.is_null() || kind > 1 {
        return E_INVALIDARG;
    }
    let a = data::<Analysis>(this);
    // SAFETY: the caller's RECT.
    let [l, t, r, b] = unsafe { *rect };
    if r < l || b < t {
        return E_INVALIDARG;
    }
    let bpp = if kind == DWRITE_TEXTURE_CLEARTYPE_3X1 { 3 } else { 1 };
    let (w, h) = ((r - l) as usize, (b - t) as usize);
    if (size as usize) < w * h * bpp {
        return E_NOT_SUFFICIENT_BUFFER;
    }
    // SAFETY: the caller's buffer of at least w * h * bpp bytes.
    let out = unsafe { core::slice::from_raw_parts_mut(buf, w * h * bpp) };
    out.fill(0);
    let (Some((bl, bt, br, bb)), true) = (a.bounds, texture_ok(a, kind)) else { return S_OK };
    let bw = (br - bl) as usize;
    for y in t.max(bt)..b.min(bb) {
        for x in l.max(bl)..r.min(br) {
            let c = a.coverage[(y - bt) as usize * bw + (x - bl) as usize];
            let c = if a.aliased { if c >= 128 { 255 } else { 0 } } else { c };
            let at = ((y - t) as usize * w + (x - l) as usize) * bpp;
            out[at..at + bpp].fill(c);
        }
    }
    S_OK
}

extern "win64" fn AnaGetAlphaBlendParams(_this: u64, params: u64, gamma: *mut u32, contrast: *mut u32, cleartype: *mut u32) -> u32 {
    if gamma.is_null() || contrast.is_null() || cleartype.is_null() {
        return E_INVALIDARG;
    }
    let p = if is(params, &PARAMS_VT) { *data::<Params>(params) } else { default_params() };
    put(gamma, p.gamma);
    put(contrast, p.contrast);
    put(cleartype, p.cleartype);
    S_OK
}

/// DWRITE_GLYPH_RUN: fontFace, fontEmSize @8, glyphCount @12, indices
/// @16, advances @24, offsets @32, isSideways @40, bidiLevel @44.
#[allow(clippy::too_many_arguments)]
extern "win64" fn factory_glyph_run_analysis(
    _this: u64,
    run: *const u8,
    ppd_bits: u32,
    transform: *const [u32; 6],
    mode: u32,
    _measuring: u32,
    bx_bits: u32,
    by_bits: u32,
    out: *mut u64,
) -> u32 {
    if run.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    put(out, 0);
    if mode == DWRITE_RENDERING_MODE_OUTLINE {
        return E_INVALIDARG;
    }
    let r = run as u64;
    // SAFETY: the caller's DWRITE_GLYPH_RUN.
    let (fface, em, n, glyphs, advances, offsets, bidi) = unsafe {
        (
            crate::teb::get::<u64>(r, 0),
            f32::from_bits(crate::teb::get::<u32>(r, 8)),
            crate::teb::get::<u32>(r, 12),
            crate::teb::get::<u64>(r, 16) as *const u16,
            crate::teb::get::<u64>(r, 24) as *const u32,
            crate::teb::get::<u64>(r, 32) as *const [u32; 2],
            crate::teb::get::<u32>(r, 44),
        )
    };
    if !is(fface, &FACE_VT) || (glyphs.is_null() && n > 0) {
        return E_INVALIDARG;
    }
    let f = &face_of(fface).face;
    let ppd = f32::from_bits(ppd_bits) as f64;
    let m: [f64; 6] = if transform.is_null() {
        [1.0, 0.0, 0.0, 1.0, 0.0, 0.0]
    } else {
        // SAFETY: the caller's DWRITE_MATRIX.
        unsafe { *transform }.map(|v| f32::from_bits(v) as f64)
    };
    let (bx, by) = (f32::from_bits(bx_bits) as f64, f32::from_bits(by_bits) as f64);
    let s = em as f64 / f.units_per_em as f64;
    let rtl = bidi & 1 != 0;
    let mut lines = raster::Lines::new();
    let mut pen = 0f64;
    for i in 0..n as usize {
        // SAFETY: the caller's arrays of `n` elements (advances and offsets optional).
        let (g, adv, off) = unsafe {
            (
                *glyphs.add(i),
                if advances.is_null() { None } else { Some(f32::from_bits(*advances.add(i)) as f64) },
                if offsets.is_null() { (0.0, 0.0) } else { let o = *offsets.add(i); (f32::from_bits(o[0]) as f64, f32::from_bits(o[1]) as f64) },
            )
        };
        let adv = adv.unwrap_or_else(|| f.h_metrics(g).0 as f64 * s);
        if rtl {
            pen -= adv;
        }
        // Glyph origin in pixels, before the transform.
        let ox = (bx + pen + if rtl { -off.0 } else { off.0 }) * ppd;
        let oy = (by - off.1) * ppd;
        let k = 256.0 * 65536.0;
        let x = raster::Xform {
            a: (m[0] * ppd * s * k) as i64,
            b: (m[1] * ppd * s * k) as i64,
            c: (-m[2] * ppd * s * k) as i64,
            d: (-m[3] * ppd * s * k) as i64,
            dx: ((m[0] * ox + m[2] * oy + m[4]) * 256.0) as i64,
            dy: ((m[1] * ox + m[3] * oy + m[5]) * 256.0) as i64,
        };
        lines.extend(raster::flatten(&f.outline(g), &x));
        if !rtl {
            pen += adv;
        }
    }
    let bounds = raster::bounds(&lines);
    let coverage = bounds.map(|b| raster::coverage(&lines, b)).unwrap_or_default();
    put(out, new(&ANALYSIS_VT, "IDWriteGlyphRunAnalysis", &ANALYSIS_IIDS, Analysis { bounds, coverage, aliased: mode == DWRITE_RENDERING_MODE_ALIASED }));
    S_OK
}

// ---- GDI interop -----------------------------------------------------------------------------

static GDI_VT: Slots<8> = Slots([
    qi as *const (),
    add_ref as _,
    release::<()> as _,
    GdiCreateFontFromLOGFONT as _,
    GdiConvertFontToLOGFONT as _,
    GdiConvertFontFaceToLOGFONT as _,
    stub::<6> as _,
    stub::<7> as _,
]);
static GDI_IIDS: [Guid; 1] = [iids::GDI_INTEROP];

/// A family by name, or by its HKLM FontSubstitutes replacement.
fn find_family(s: &System, name: &str) -> Option<usize> {
    let by = |n: &str| s.families.iter().position(|f| f.0.eq_ignore_ascii_case(n));
    by(name).or_else(|| {
        let subs = crate::registry::machine_strings("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\FontSubstitutes");
        // Values may name a charset after a comma ("Arial,0").
        let base = name.split(',').next().unwrap_or(name);
        subs.iter().find(|(k, _)| k.split(',').next().unwrap_or(k).eq_ignore_ascii_case(base)).and_then(|(_, v)| by(v.split(',').next().unwrap_or(v)))
    })
}

/// LOGFONTW: lfWeight @16, lfItalic @20, lfFaceName @28 (32 WCHARs).
extern "win64" fn GdiCreateFontFromLOGFONT(_this: u64, lf: *const u8, out: *mut u64) -> u32 {
    if lf.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    put(out, 0);
    // SAFETY: the caller's LOGFONTW.
    let (weight, italic, name) = unsafe {
        let units: Vec<u16> = (0..32).map(|i| *(lf.add(28 + 2 * i) as *const u16)).take_while(|&u| u != 0).collect();
        (*(lf.add(16) as *const i32), *lf.add(20) != 0, String::from_utf16_lossy(&units))
    };
    let s = system();
    let Some(fi) = find_family(&s, &name) else { return DWRITE_E_NOFONT };
    let weight = if weight <= 0 { 400 } else { weight as u32 };
    let style = if italic { 2 } else { 0 };
    match s.families[fi].1.iter().min_by_key(|f| distance(f, weight, 5, style)) {
        Some(f) => {
            put(out, font(s.clone(), f.clone()));
            S_OK
        }
        None => DWRITE_E_NOFONT,
    }
}

fn fill_logfont(lf: *mut u8, family: &str, weight: u32, italic: bool) {
    // SAFETY: the caller's LOGFONTW (92 bytes).
    unsafe {
        core::ptr::write_bytes(lf, 0, 92);
        *(lf.add(16) as *mut i32) = weight as i32;
        *lf.add(20) = italic as u8;
        *lf.add(23) = 1; // DEFAULT_CHARSET
        for (i, u) in family.encode_utf16().take(31).enumerate() {
            *(lf.add(28 + 2 * i) as *mut u16) = u;
        }
    }
}

extern "win64" fn GdiConvertFontToLOGFONT(_this: u64, f: u64, lf: *mut u8, system_font: *mut i32) -> u32 {
    if !is(f, &FONT_VT) || lf.is_null() || system_font.is_null() {
        return E_INVALIDARG;
    }
    let d = data::<FontData>(f);
    fill_logfont(lf, &d.system.families[d.entry.family].0, d.entry.weight, d.entry.style != 0);
    put(system_font, 1);
    S_OK
}

extern "win64" fn GdiConvertFontFaceToLOGFONT(_this: u64, face: u64, lf: *mut u8) -> u32 {
    if !is(face, &FACE_VT) || lf.is_null() {
        return E_INVALIDARG;
    }
    let f = &face_of(face).face;
    fill_logfont(lf, &f.family(), f.weight() as u32, f.style() != 0);
    S_OK
}

// ---- the factory -------------------------------------------------------------------------------

static FACTORY_VT: Slots<24> = Slots([
    qi as *const (),
    add_ref as _,
    release::<Mutex<Vec<u64>>> as _,
    FactoryGetSystemFontCollection as _,
    FactoryCreateCustomFontCollection as _,
    FactoryRegisterFontCollectionLoader as _,
    FactoryUnregisterFontCollectionLoader as _,
    FactoryCreateFontFileReference as _,
    FactoryCreateCustomFontFileReference as _,
    FactoryCreateFontFace as _,
    FactoryCreateRenderingParams as _,
    FactoryCreateMonitorRenderingParams as _,
    FactoryCreateCustomRenderingParams as _,
    FactoryRegisterFontFileLoader as _,
    FactoryUnregisterFontFileLoader as _,
    stub::<15> as _,
    stub::<16> as _,
    FactoryGetGdiInterop as _,
    stub::<18> as _,
    stub::<19> as _,
    stub::<20> as _,
    stub::<21> as _,
    stub::<22> as _,
    FactoryCreateGlyphRunAnalysis as _,
]);
static FACTORY_IIDS: [Guid; 1] = [iids::FACTORY];

/// The registered font file and font collection loaders (factory data).
fn loaders(this: u64) -> &'static Mutex<Vec<u64>> {
    data::<Mutex<Vec<u64>>>(this)
}

/// A collection of the files the program's collection loader enumerates
/// for `key` (IDWriteFontCollectionLoader::CreateEnumeratorFromKey, then
/// IDWriteFontFileEnumerator::MoveNext and GetCurrentFontFile).
extern "win64" fn FactoryCreateCustomFontCollection(this: u64, loader: u64, key: *const u8, size: u32, out: *mut u64) -> u32 {
    if loader == 0 || out.is_null() {
        return E_INVALIDARG;
    }
    put(out, 0);
    if !loaders(this).lock().unwrap().contains(&loader) {
        return E_INVALIDARG;
    }
    let mut en = 0u64;
    // SAFETY: the loader's CreateEnumeratorFromKey (slot 3).
    let hr = unsafe {
        let f: extern "win64" fn(u64, u64, *const u8, u32, *mut u64) -> u32 = core::mem::transmute(method(loader, 3));
        f(loader, this, key, size, &mut en)
    };
    if hr != S_OK || en == 0 {
        return if hr == S_OK { E_FAIL } else { hr };
    }
    let mut files = Vec::new();
    loop {
        let mut more = 0i32;
        // SAFETY: the enumerator's MoveNext (3) and GetCurrentFontFile (4).
        let (hr, file) = unsafe {
            let next: extern "win64" fn(u64, *mut i32) -> u32 = core::mem::transmute(method(en, 3));
            let hr = next(en, &mut more);
            if hr != S_OK || more == 0 {
                (hr, 0)
            } else {
                let current: extern "win64" fn(u64, *mut u64) -> u32 = core::mem::transmute(method(en, 4));
                let mut f = 0u64;
                (current(en, &mut f), f)
            }
        };
        if hr != S_OK || more == 0 {
            break;
        }
        if is(file, &FILE_VT) {
            files.push(data::<Arc<FileData>>(file).clone());
        }
        if file != 0 {
            com_ref(file, 2);
        }
    }
    com_ref(en, 2);
    put(out, collection(Arc::new(build(&files))));
    S_OK
}

extern "win64" fn FactoryRegisterFontCollectionLoader(this: u64, loader: u64) -> u32 {
    FactoryRegisterFontFileLoader(this, loader)
}

extern "win64" fn FactoryUnregisterFontCollectionLoader(this: u64, loader: u64) -> u32 {
    FactoryUnregisterFontFileLoader(this, loader)
}

extern "win64" fn FactoryGetSystemFontCollection(_this: u64, out: *mut u64, _check: i32) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    put(out, collection(system()));
    S_OK
}

extern "win64" fn FactoryCreateFontFileReference(_this: u64, path: *const u16, _time: *const u64, out: *mut u64) -> u32 {
    if path.is_null() || out.is_null() {
        return E_INVALIDARG;
    }
    put(out, 0);
    // SAFETY: a NUL-terminated path.
    let Some(win) = (unsafe { path::wide_to_string(path) }) else { return E_INVALIDARG };
    match read_local(&win) {
        Some((bytes, mtime)) => {
            put(out, file(Arc::new(FileData { bytes, local: Some((win, mtime)), custom: None })));
            S_OK
        }
        None => DWRITE_E_FILENOTFOUND,
    }
}

/// Reads the whole file through the program's loader (CreateStreamFromKey,
/// then IDWriteFontFileStream::GetFileSize and ReadFileFragment).
fn read_custom(loader: u64, key: &[u8]) -> Result<Vec<u8>, u32> {
    let mut stream = 0u64;
    // SAFETY: IDWriteFontFileLoader::CreateStreamFromKey (slot 3).
    let hr = unsafe {
        let f: extern "win64" fn(u64, *const u8, u32, *mut u64) -> u32 = core::mem::transmute(method(loader, 3));
        f(loader, key.as_ptr(), key.len() as u32, &mut stream)
    };
    if hr != S_OK || stream == 0 {
        return Err(if hr == S_OK { E_FAIL } else { hr });
    }
    let result = (|| {
        let mut size = 0u64;
        // SAFETY: IDWriteFontFileStream::GetFileSize (5) and ReadFileFragment (3), ReleaseFileFragment (4).
        unsafe {
            let get_size: extern "win64" fn(u64, *mut u64) -> u32 = core::mem::transmute(method(stream, 5));
            let hr = get_size(stream, &mut size);
            if hr != S_OK {
                return Err(hr);
            }
            if size > 64 << 20 {
                return Err(DWRITE_E_FILEFORMAT);
            }
            let read: extern "win64" fn(u64, *mut *const u8, u64, u64, *mut u64) -> u32 = core::mem::transmute(method(stream, 3));
            let release: extern "win64" fn(u64, u64) = core::mem::transmute(method(stream, 4));
            let (mut p, mut ctx) = (core::ptr::null(), 0u64);
            let hr = read(stream, &mut p, 0, size, &mut ctx);
            if hr != S_OK || p.is_null() {
                return Err(if hr == S_OK { E_FAIL } else { hr });
            }
            let v = core::slice::from_raw_parts(p, size as usize).to_vec();
            release(stream, ctx);
            Ok(v)
        }
    })();
    com_ref(stream, 2);
    result
}

extern "win64" fn FactoryCreateCustomFontFileReference(_this: u64, key: *const u8, size: u32, loader: u64, out: *mut u64) -> u32 {
    if out.is_null() || loader == 0 || (key.is_null() && size > 0) {
        return E_INVALIDARG;
    }
    put(out, 0);
    let k = if size == 0 {
        Vec::new()
    } else {
        // SAFETY: the caller's key of `size` bytes.
        unsafe { core::slice::from_raw_parts(key, size as usize) }.to_vec()
    };
    if loader == local_loader() {
        let Some((p, _)) = parse_key(key, size) else { return E_INVALIDARG };
        return FactoryCreateFontFileReference(0, wide_bytes(&p).into_iter().chain(core::iter::once(0)).collect::<Vec<u16>>().as_ptr(), core::ptr::null(), out);
    }
    match read_custom(loader, &k) {
        Ok(bytes) => {
            com_ref(loader, 1);
            put(out, file(Arc::new(FileData { bytes: Arc::new(bytes), local: None, custom: Some((loader, k)) })));
            S_OK
        }
        Err(e) => e,
    }
}

extern "win64" fn FactoryCreateFontFace(_this: u64, _kind: u32, nfiles: u32, files: *const u64, index: u32, simulations: u32, out: *mut u64) -> u32 {
    if out.is_null() || files.is_null() || nfiles == 0 {
        return E_INVALIDARG;
    }
    put(out, 0);
    // SAFETY: the caller's array of `nfiles` files.
    let f = unsafe { *files };
    if !is(f, &FILE_VT) {
        return E_INVALIDARG;
    }
    let fd = data::<Arc<FileData>>(f).clone();
    match ttf::Face::parse(fd.bytes.clone(), index) {
        Some(face_) => {
            put(out, face(Arc::new(FaceData { file: fd, face: face_, index, simulations })));
            S_OK
        }
        None => DWRITE_E_FILEFORMAT,
    }
}

extern "win64" fn FactoryCreateRenderingParams(_this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    put(out, params(default_params()));
    S_OK
}

extern "win64" fn FactoryCreateMonitorRenderingParams(_this: u64, _monitor: u64, out: *mut u64) -> u32 {
    FactoryCreateRenderingParams(0, out)
}

extern "win64" fn factory_custom_rendering_params(_this: u64, gamma: u32, contrast: u32, cleartype: u32, geometry: u32, mode: u32, out: *mut u64) -> u32 {
    let (g, c, t) = (f32::from_bits(gamma), f32::from_bits(contrast), f32::from_bits(cleartype));
    if out.is_null() || !(g > 0.0 && g <= 256.0) || c < 0.0 || !(0.0..=1.0).contains(&t) || geometry > 2 || mode > 6 {
        return E_INVALIDARG;
    }
    put(out, params(Params { gamma, contrast, cleartype, geometry, mode }));
    S_OK
}

xmm_jmp! {
    FactoryCreateCustomRenderingParams => factory_custom_rendering_params ["movd edx, xmm1", "movd r8d, xmm2", "movd r9d, xmm3"];
    FactoryCreateGlyphRunAnalysis => factory_glyph_run_analysis ["movd r8d, xmm2"];
}

extern "win64" fn FactoryRegisterFontFileLoader(this: u64, loader: u64) -> u32 {
    if loader == 0 {
        return E_INVALIDARG;
    }
    let mut l = loaders(this).lock().unwrap();
    if l.contains(&loader) || loader == local_loader() {
        return DWRITE_E_ALREADYREGISTERED;
    }
    com_ref(loader, 1);
    l.push(loader);
    S_OK
}

extern "win64" fn FactoryUnregisterFontFileLoader(this: u64, loader: u64) -> u32 {
    let mut l = loaders(this).lock().unwrap();
    match l.iter().position(|&x| x == loader) {
        Some(i) => {
            l.remove(i);
            drop(l);
            com_ref(loader, 2);
            S_OK
        }
        None => E_INVALIDARG,
    }
}

extern "win64" fn FactoryGetGdiInterop(_this: u64, out: *mut u64) -> u32 {
    if out.is_null() {
        return E_INVALIDARG;
    }
    put(out, new(&GDI_VT, "IDWriteGdiInterop", &GDI_IIDS, ()));
    S_OK
}

/// DWriteCreateFactory: shared and isolated factories behave the same.
extern "win64" fn DWriteCreateFactory(kind: u32, riid: *const Guid, out: *mut u64) -> u32 {
    if out.is_null() || riid.is_null() {
        return E_INVALIDARG;
    }
    put(out, 0);
    if kind > 1 {
        return E_INVALIDARG;
    }
    let f = new(&FACTORY_VT, "IDWriteFactory", &FACTORY_IIDS, Mutex::new(Vec::<u64>::new()));
    let hr = qi(f, riid, out);
    release::<Mutex<Vec<u64>>>(f);
    hr
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![DWriteCreateFactory]
}
