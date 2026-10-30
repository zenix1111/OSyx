//! 32-bit (PE32) images in the loader: layout, HIGHLOW relocations, 4-byte
//! import thunks, placement below 4 GiB and width checks. The fixtures are
//! built in memory in the style of `compatibility/pe-parser/tests/pe32.rs`:
//! a console executable with `.text` and `.rdata`, one HIGHLOW relocation at
//! RVA 0x2080 (holding 0x00400010), one import descriptor for KERNEL32 with
//! one by-name import, and a one-function export table (so the same fixture
//! can stand in for a PE32 DLL).

use osyx_pe::PeFile;
use osyx_pe_loader::image::{self, ADDRESS_LIMIT32};
use osyx_pe_loader::link::{BuiltinModule, Host, LinkError, Linker, Source, Symbol};
use std::collections::BTreeMap;

const HELLO: &[u8] = include_bytes!("../../pe-parser/tests/fixtures/hello.exe");
const SAMPLE: &[u8] = include_bytes!("../../pe-parser/tests/fixtures/sample.dll");

/// The fixture's linked image base.
const IMAGE_BASE: u32 = 0x0040_0000;
/// The fixture's SizeOfImage (two 0x1000 sections after the headers).
const SIZE_OF_IMAGE: u32 = 0x3000;
const TEXTHDR: usize = 0x178;
const RDATAHDR: usize = 0x1A0;
/// Raw file offset of the `.rdata` section body (RVA 0x2000 maps here).
const RDATA_RAW: usize = 0x400;
/// RVA of the HIGHLOW-patched field, its file value and its RVA in the ILT.
const HIGHLOW_RVA: u32 = 0x2080;
const IAT_RVA: u32 = 0x2050;
const ILT_RVA: u32 = 0x2040;
/// A sentinel right after the 4-byte IAT slot: an 8-byte write would clobber it.
const IAT_SENTINEL: u32 = 0xDEAD_BEEF;
const CHARS_OFFSET: usize = 0x80 + 4 + 18;
const DIRS: usize = 0x98 + 96;

fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
/// Raw file offset of an RVA inside `.rdata` (the only section with data
/// directories).
fn rdata(rva: u32) -> usize {
    RDATA_RAW + (rva as usize - 0x2000)
}

/// A PE32 console executable (or, with [`as_dll`], DLL) importing `import`
/// by name and exporting `WriteFile` at RVA 0x1000.
fn pe32_image(import: &str) -> Vec<u8> {
    assert!(import.len() <= 12, "the import name slot holds 13 bytes");
    let mut b = vec![0u8; 0x800];
    b[0..2].copy_from_slice(b"MZ");
    put32(&mut b, 0x3C, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    let c = 0x84;
    put16(&mut b, c, osyx_pe::MACHINE_I386);
    put16(&mut b, c + 2, 2); // .text and .rdata
    put16(&mut b, c + 16, 96 + 16 * 8); // optional header with 16 directories
    put16(&mut b, c + 18, 0x0102); // executable, 32-bit machine
    let o = c + 20;
    put16(&mut b, o, 0x10B); // PE32
    put32(&mut b, o + 16, 0x1000); // entry point
    put32(&mut b, o + 20, 0x1000); // base of code
    put32(&mut b, o + 24, 0x2000); // base of data
    put32(&mut b, o + 28, IMAGE_BASE);
    put32(&mut b, o + 32, 0x1000); // section alignment
    put32(&mut b, o + 36, 0x200); // file alignment
    put16(&mut b, o + 48, 6); // subsystem version 6.0
    put32(&mut b, o + 56, SIZE_OF_IMAGE);
    put32(&mut b, o + 60, 0x200); // size of headers
    put16(&mut b, o + 68, 3); // console subsystem
    put16(&mut b, o + 70, 0x0140); // dynamic base, NX compatible
    put32(&mut b, o + 72, 0x10_0000); // stack reserve
    put32(&mut b, o + 76, 0x1000); // stack commit
    put32(&mut b, o + 80, 0x10_0000); // heap reserve
    put32(&mut b, o + 84, 0x1000); // heap commit
    put32(&mut b, o + 92, 16); // number of data directories

    // .text: RVA 0x1000, 0x1000 bytes, 0x200 from file offset 0x200.
    let s = TEXTHDR;
    b[s..s + 5].copy_from_slice(b".text");
    put32(&mut b, s + 8, 0x1000);
    put32(&mut b, s + 12, 0x1000);
    put32(&mut b, s + 16, 0x200);
    put32(&mut b, s + 20, 0x200);
    put32(&mut b, s + 36, 0x6000_0020); // code, execute, read

    // .rdata: RVA 0x2000, 0x1000 bytes, 0x400 from file offset 0x400.
    let s = RDATAHDR;
    b[s..s + 6].copy_from_slice(b".rdata");
    put32(&mut b, s + 8, 0x1000);
    put32(&mut b, s + 12, 0x2000);
    put32(&mut b, s + 16, 0x400);
    put32(&mut b, s + 20, 0x400);
    put32(&mut b, s + 36, 0x4000_0040); // initialised data, read

    // Data directories: exports at 0x2200, imports at 0x2000, relocations
    // at 0x2100.
    let d = DIRS;
    put32(&mut b, d, 0x2200);
    put32(&mut b, d + 4, 0x50);
    put32(&mut b, d + 8, 0x2000); // import directory
    put32(&mut b, d + 12, 40);
    put32(&mut b, d + 5 * 8, 0x2100); // base relocations
    put32(&mut b, d + 5 * 8 + 4, 12);

    // Import descriptor for `import` (RVA 0x2000) and its null terminator.
    put32(&mut b, rdata(0x2000), ILT_RVA);
    put32(&mut b, rdata(0x2000) + 12, 0x20A0); // DLL name
    put32(&mut b, rdata(0x2000) + 16, IAT_RVA);
    // ILT: one by-name thunk, hint/name at 0x2060.
    put32(&mut b, rdata(ILT_RVA), 0x2060);
    // IAT slot (4 bytes) starts zero; a sentinel follows it.
    put32(&mut b, rdata(IAT_RVA + 4), IAT_SENTINEL);
    // Hint 0, name "WriteFile" at 0x2062.
    b[rdata(0x2062)..rdata(0x2062) + 10].copy_from_slice(b"WriteFile\0");
    // An absolute address of the linked image, patched by HIGHLOW.
    put32(&mut b, rdata(HIGHLOW_RVA), IMAGE_BASE + 0x10);
    // DLL name of the imported module.
    b[rdata(0x20A0)..rdata(0x20AD)].copy_from_slice(b"KERNEL32.dll\0");
    let at = rdata(0x20A0);
    b[at..at + import.len()].copy_from_slice(import.as_bytes());
    b[at + import.len()] = 0;
    for x in &mut b[at + import.len() + 1..at + 13] {
        *x = 0;
    }

    // One BASERELOC block: page 0x2000, size 12, one HIGHLOW entry at 0x2080
    // (type 3 << 12 | 0x80) and a padding entry.
    put32(&mut b, rdata(0x2100), 0x2000);
    put32(&mut b, rdata(0x2100) + 4, 12);
    put16(&mut b, rdata(0x2100) + 8, 0x3080);
    put16(&mut b, rdata(0x2100) + 10, 0x0000);

    // Export directory at 0x2200: one function, `WriteFile`, at RVA 0x1000.
    let x = rdata(0x2200);
    put32(&mut b, x + 12, 0x2230); // DLL name
    put32(&mut b, x + 16, 1); // ordinal base
    put32(&mut b, x + 20, 1); // number of functions
    put32(&mut b, x + 24, 1); // number of names
    put32(&mut b, x + 28, 0x2240); // address table
    put32(&mut b, x + 32, 0x2244); // name pointer table
    put32(&mut b, x + 36, 0x2248); // ordinal table
    put32(&mut b, rdata(0x2240), 0x1000);
    put32(&mut b, rdata(0x2244), 0x2250);
    put16(&mut b, rdata(0x2248), 0);
    b[rdata(0x2230)..rdata(0x2230) + 12].copy_from_slice(b"pe32fix.dll\0");
    b[rdata(0x2250)..rdata(0x2250) + 10].copy_from_slice(b"WriteFile\0");

    // Some code in .text, to prove the section body is copied.
    for (i, x) in b[0x200..0x210].iter_mut().enumerate() {
        *x = 0x40 + i as u8;
    }
    b
}

/// The same fixture marked IMAGE_FILE_DLL.
fn as_dll(mut b: Vec<u8>) -> Vec<u8> {
    let ch = u16::from_le_bytes([b[CHARS_OFFSET], b[CHARS_OFFSET + 1]]) | osyx_pe::IMAGE_FILE_DLL;
    put16(&mut b, CHARS_OFFSET, ch);
    b
}

/// IMAGE_FILE_RELOCS_STRIPPED and no base relocation directory.
fn strip_relocations(mut b: Vec<u8>) -> Vec<u8> {
    let ch = u16::from_le_bytes([b[CHARS_OFFSET], b[CHARS_OFFSET + 1]]) | 0x0001;
    put16(&mut b, CHARS_OFFSET, ch);
    put32(&mut b, DIRS + 5 * 8, 0);
    put32(&mut b, DIRS + 5 * 8 + 4, 0);
    b
}

fn with_base(mut b: Vec<u8>, base: u32) -> Vec<u8> {
    put32(&mut b, 0x98 + 28, base);
    b
}

// ---- host ---------------------------------------------------------------

struct Kernel32(BTreeMap<String, u64>);

impl BuiltinModule for Kernel32 {
    fn by_name(&self, name: &str) -> Option<u64> {
        self.0.get(name).copied()
    }
}

fn kernel32() -> Kernel32 {
    let names = [("GetStdHandle", 0x7000_0010), ("WriteFile", 0x7000_0020), ("ExitProcess", 0x7000_0030)];
    Kernel32(names.iter().map(|(n, a)| (n.to_string(), *a)).collect())
}

/// An in-memory host with no usable memory above 4 GiB: `reserve` (64-bit
/// images) places images at 0x5_0000_0000, `reserve_below` (32-bit images)
/// below the limit it is given and refuses a fixed base that would not fit.
#[derive(Default)]
struct Host32 {
    files: BTreeMap<String, Vec<u8>>,
    images: BTreeMap<u64, Vec<u8>>,
    /// Every `max` the linker passed to `reserve_below`.
    limits: Vec<u64>,
    /// Every successful reservation below a limit: (base, size).
    reservations: Vec<(u64, u64)>,
    /// Bases another process offers for sharing.
    shared: BTreeMap<String, u64>,
    next: u64,
}

impl Host32 {
    fn with(files: &[(&str, Vec<u8>)]) -> Self {
        let mut h = Host32::default();
        for (name, bytes) in files {
            h.files.insert((*name).to_string(), bytes.clone());
        }
        h
    }
}

impl Host for Host32 {
    type Image = Vec<u8>;

    fn open(&mut self, name: &str) -> Result<Option<Source>, LinkError> {
        if name == "kernel32.dll" {
            return Ok(Some(Source::Builtin(Box::new(kernel32()))));
        }
        Ok(self.files.get(name).cloned().map(Source::Pe))
    }

    fn reserve(&mut self, size: u64, _preferred: u64, _fixed: bool) -> Result<(u64, Self::Image), LinkError> {
        let base = 0x5_0000_0000 + self.next;
        self.next += size.next_multiple_of(0x10000);
        Ok((base, vec![0; size as usize]))
    }

    fn shared_base(&mut self, name: &str) -> Option<u64> {
        self.shared.get(name).copied()
    }

    fn reserve_below(
        &mut self,
        size: u64,
        preferred: u64,
        fixed: bool,
        max: u64,
    ) -> Result<(u64, Self::Image), LinkError> {
        self.limits.push(max);
        let base = if fixed { preferred } else { 0x1000_0000 + self.next };
        if base.checked_add(size).is_none_or(|end| end > max) {
            return Err(LinkError::NoMemory);
        }
        if !fixed {
            self.next += size.next_multiple_of(0x10000);
        }
        self.reservations.push((base, size));
        Ok((base, vec![0; size as usize]))
    }

    fn commit(&mut self, base: u64, image: Self::Image, _prot: &[image::Protection]) -> Result<(), LinkError> {
        self.images.insert(base, image);
        Ok(())
    }

    fn release(&mut self, base: u64, _size: u64) {
        self.images.remove(&base);
        self.reservations.retain(|(b, _)| *b != base);
    }
}

// ---- tests --------------------------------------------------------------

/// The fixture itself: PE32, one HIGHLOW relocation, imports and exports.
#[test]
fn pe32_fixture_has_one_highlow_relocation_and_a_four_byte_iat() {
    let bytes = pe32_image("KERNEL32.dll");
    assert!(PeFile::parse(&bytes).is_err(), "strict parse still refuses PE32");
    let pe = PeFile::parse_any(&bytes).unwrap();
    assert!(pe.is_pe32());
    assert_eq!(pe.machine(), osyx_pe::MACHINE_I386);
    assert_eq!(image::pointer_size(&pe), 4);
    assert_eq!(image::kind(&pe), image::PeKind::Pe32);
    image::check(&pe, false).unwrap();
    let relocs: Vec<_> = pe.relocations().unwrap().map(|r| r.unwrap()).collect();
    assert_eq!(relocs.len(), 2);
    assert_eq!(relocs[0].kind, osyx_pe::RelocationKind::HighLow);
    assert_eq!(relocs[0].rva, HIGHLOW_RVA);
    assert_eq!(u32::from_le_bytes(pe.read_mapped::<4>(HIGHLOW_RVA).unwrap()), IMAGE_BASE + 0x10);
    let imports: Vec<_> = pe.imports().unwrap().map(|d| d.unwrap()).collect();
    assert_eq!(imports.len(), 1);
    assert_eq!(imports[0].dll, "KERNEL32.dll");
    let entries: Vec<_> = imports[0].entries().map(|e| e.unwrap()).collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].iat_rva(), IAT_RVA);
}

/// Sections at their RVAs, the HIGHLOW field moved by the delta, and the IAT
/// slot 4 bytes wide holding the low 32 bits of the resolved stub address.
#[test]
fn pe32_image_sections_thunks_and_highlow_relocation() {
    let bytes = pe32_image("KERNEL32.dll");
    let pe = PeFile::parse_any(&bytes).unwrap();
    let mut l = Linker::new(Host32::default(), None);
    let exe = l.load_executable("app32.exe", bytes.clone()).unwrap();
    let m = &l.modules[exe];
    assert_eq!(m.is_pe32(), Some(true));
    assert_eq!(m.relocations, 1, "one HIGHLOW field patched");
    assert_eq!(m.imports_bound, 1);
    assert!(m.base < ADDRESS_LIMIT32, "base {:#x} below 4 GiB", m.base);
    assert_eq!(l.host.limits, [ADDRESS_LIMIT32], "the host was told the limit");
    assert!(l.host.reservations.iter().all(|&(b, s)| b + s <= ADDRESS_LIMIT32));

    let img = &l.host.images[&m.base];
    assert_eq!(img.len(), pe.size_of_image() as usize);
    // Sections land at their RVAs with their file contents. `.rdata` is
    // compared except for the two fields the loader patches: the bound IAT
    // slot (0x2050) and the relocated absolute address (0x2080).
    for s in pe.sections() {
        let at = s.virtual_address as usize;
        let n = s.file_size() as usize;
        let file = pe.slice_at_rva(s.virtual_address, n).unwrap();
        if s.name() == ".rdata" {
            for (i, (&loaded, &from_file)) in img[at..at + n].iter().zip(file).enumerate() {
                let rva = (at + i) as u32;
                if (IAT_RVA..IAT_RVA + 4).contains(&rva) || (HIGHLOW_RVA..HIGHLOW_RVA + 4).contains(&rva) {
                    continue;
                }
                assert_eq!(loaded, from_file, "{} at {rva:#x}", s.name());
            }
            continue;
        }
        assert_eq!(&img[at..at + n], file, "{}", s.name());
    }
    assert_eq!(&img[0x1000..0x1004], &[0x40, 0x41, 0x42, 0x43]);
    // The absolute address is relocated by (base - linked base).
    let delta = m.base - pe.image_base();
    assert!(delta > 0, "loaded away from the linked base");
    let field = image::read_thunk(img, HIGHLOW_RVA, true).unwrap();
    assert_eq!(field, (IMAGE_BASE + 0x10) as u64 + delta);
    // The IAT slot is 4 bytes: it holds the low 32 bits of the stub address
    // and the 4-byte sentinel right after it is untouched.
    assert_eq!(image::read_thunk(img, IAT_RVA, true).unwrap(), 0x7000_0020);
    assert_eq!(image::read_thunk(img, IAT_RVA + 4, true).unwrap(), IAT_SENTINEL as u64, "no 8-byte write");
    // The built-in stub address was written into a slot 32-bit code reads.
    assert_eq!(&img[IAT_RVA as usize..IAT_RVA as usize + 4], &0x7000_0020u32.to_le_bytes());
}

/// Without relocations the image must stay where it was linked: exactly
/// 0x400000, no relocation.
#[test]
fn pe32_relocs_stripped_image_stays_at_its_linked_base() {
    let bytes = strip_relocations(pe32_image("KERNEL32.dll"));
    let pe = PeFile::parse_any(&bytes).unwrap();
    assert!(!image::relocatable(&pe));
    assert!(!pe.directory(osyx_pe::dir::BASERELOC).is_present());
    let mut l = Linker::new(Host32::default(), None);
    let exe = l.load_executable("app32.exe", bytes.clone()).unwrap();
    assert_eq!(l.modules[exe].base, IMAGE_BASE as u64, "fixed at the linked base");
    assert_eq!(l.modules[exe].relocations, 0);
    assert_eq!(l.host.reservations, [(IMAGE_BASE as u64, SIZE_OF_IMAGE as u64)]);
    let img = &l.host.images[&(IMAGE_BASE as u64)];
    assert_eq!(image::read_thunk(img, HIGHLOW_RVA, true).unwrap(), (IMAGE_BASE + 0x10) as u64);
}

/// A PE32 image that would extend past 4 GiB is rejected and never mapped.
#[test]
fn pe32_image_is_never_placed_above_four_gigabytes() {
    let bytes = strip_relocations(with_base(pe32_image("KERNEL32.dll"), 0xFFFF_F000));
    let pe = PeFile::parse_any(&bytes).unwrap();
    assert_eq!(pe.image_base(), 0xFFFF_F000);
    // Even at its linked base it would end above 4 GiB.
    let mut img = image::layout(&pe).unwrap();
    assert_eq!(image::relocate(&pe, &mut img, 0xFFFF_F000), Err(image::ImageError::BaseTooHigh));
    assert_eq!(image::relocate(&pe, &mut img, ADDRESS_LIMIT32), Err(image::ImageError::BaseTooHigh));

    let mut l = Linker::new(Host32::default(), None);
    let e = l.load_executable("app32.exe", bytes).unwrap_err();
    assert!(matches!(e, LinkError::NoMemory | LinkError::Image { error: image::ImageError::BaseTooHigh, .. }), "{e:?}");
    assert_eq!(l.host.limits, [ADDRESS_LIMIT32], "host told the image must stay below 4 GiB");
    assert!(l.host.reservations.is_empty(), "nothing reserved");
    assert!(l.modules.is_empty() && l.host.images.is_empty());

    // A host offering a shared base above 4 GiB for a PE32 DLL: the loader
    // asks for a base below 4 GiB and the DLL is never mapped up there.
    let mut host = Host32::with(&[("pe32fix.dll", as_dll(pe32_image("KERNEL32.dll")))]);
    host.shared.insert("pe32fix.dll".into(), 0x1_0000_1000);
    let mut l = Linker::new(host, None);
    let dll = l.load_dll("pe32fix.dll", "t.exe").unwrap();
    assert!(l.modules[dll].base < ADDRESS_LIMIT32, "base {:#x} below 4 GiB", l.modules[dll].base);
    assert_eq!(l.host.limits, [ADDRESS_LIMIT32]);
    assert!(l.host.reservations.iter().all(|&(b, s)| b + s <= ADDRESS_LIMIT32));
}

/// PE32 and PE32+ images cannot import each other; a PE32 image imports a
/// PE32 DLL or a built-in module.
#[test]
fn pe32_and_pe32plus_images_cannot_import_each_other() {
    // PE32 executable importing a PE32+ DLL (sample.dll).
    let mut l = Linker::new(Host32::with(&[("sample.dll", SAMPLE.to_vec())]), None);
    let e = l.load_executable("app32.exe", pe32_image("sample.dll")).unwrap_err();
    match e {
        LinkError::WidthMismatch { importer, module } => {
            assert_eq!((importer.as_str(), module.as_str()), ("app32.exe", "sample.dll"));
        }
        other => panic!("{other:?}"),
    }
    assert!(l.modules.is_empty() && l.host.images.is_empty(), "the importer is not kept");

    // PE32+ executable (hello.exe) importing a PE32 DLL: the same import name
    // slot, rewritten to point at the 32-bit fixture.
    let mut exe = HELLO.to_vec();
    let from = b"KERNEL32.dll";
    let at = exe.windows(from.len()).position(|w| w == from).unwrap();
    exe[at..at + 11].copy_from_slice(b"pe32fix.dll");
    exe[at + 11] = 0; // "KERNEL32.dll" is one byte longer.
    let mut l = Linker::new(Host32::with(&[("pe32fix.dll", as_dll(pe32_image("KERNEL32.dll")))]), None);
    let e = l.load_executable("hello.exe", exe).unwrap_err();
    match e {
        LinkError::WidthMismatch { importer, module } => {
            assert_eq!((importer.as_str(), module.as_str()), ("hello.exe", "pe32fix.dll"));
        }
        other => panic!("{other:?}"),
    }
    assert!(l.modules.is_empty() && l.host.images.is_empty(), "neither image is kept");

    // A PE32 image may import another PE32 DLL.
    let mut l = Linker::new(Host32::with(&[("pe32fix.dll", as_dll(pe32_image("KERNEL32.dll")))]), None);
    let exe = l.load_executable("app32.exe", pe32_image("pe32fix.dll")).unwrap();
    let m = &l.modules[exe];
    assert_eq!(m.imports_bound, 1);
    assert_eq!(m.deps.len(), 1);
    let dll = m.deps[0];
    assert_eq!(l.modules[dll].is_pe32(), Some(true));
    assert!(l.modules[dll].base < ADDRESS_LIMIT32);
    let img = &l.host.images[&m.base];
    let stub = (l.modules[dll].base + 0x1000) as u32;
    assert_eq!(image::read_thunk(img, IAT_RVA, true).unwrap(), stub as u64);
    // And the built-in module case is fine (a 32-bit slot in width).
    let mut l = Linker::new(Host32::default(), None);
    let exe = l.load_executable("app32.exe", pe32_image("KERNEL32.dll")).unwrap();
    assert_eq!(l.modules[exe].deps.len(), 1);
    assert!(l.modules[exe].deps.iter().all(|&d| l.modules[d].is_builtin()));
}

/// A forwarder that crosses widths is an error too: sample.dll (PE32+) is
/// pointed at the PE32 fixture.
#[test]
fn forwarders_cannot_cross_widths() {
    let mut dll = SAMPLE.to_vec();
    let from = b"kernel32.GetTickCount";
    let at = dll.windows(from.len()).position(|w| w == from).unwrap();
    // Same-length replacement inside the export directory string.
    dll[at..at + from.len()].copy_from_slice(b"pe32fix.WriteFile\0\0\0\0");
    let files = [("sample.dll", dll), ("pe32fix.dll", as_dll(pe32_image("KERNEL32.dll")))];
    let mut l = Linker::new(Host32::with(&files), None);
    let dll = l.load_dll("sample.dll", "t.exe").unwrap();
    assert_eq!(l.modules[dll].is_pe32(), Some(false));
    let e = l.resolve(dll, Symbol::Name("forwarded_tick"), "t.exe", 0).unwrap_err();
    match e {
        LinkError::WidthMismatch { importer, module } => {
            assert_eq!((importer.as_str(), module.as_str()), ("sample.dll", "pe32fix.dll"));
        }
        other => panic!("{other:?}"),
    }
}

/// The machine type must agree with the header magic in both directions.
#[test]
fn pe32_and_pe32plus_machines_are_checked_against_the_magic() {
    let bytes = pe32_image("KERNEL32.dll");
    {
        let pe = PeFile::parse_any(&bytes).unwrap();
        image::check(&pe, false).unwrap();
    }
    let mut wrong = bytes.clone();
    put16(&mut wrong, 0x84, osyx_pe::MACHINE_AMD64);
    let w = PeFile::parse_any(&wrong).unwrap();
    assert_eq!(image::check(&w, false), Err(image::ImageError::Machine(osyx_pe::MACHINE_AMD64)));
    let mut wrong = bytes;
    put16(&mut wrong, 0x84, osyx_pe::MACHINE_ARM64);
    let w = PeFile::parse_any(&wrong).unwrap();
    assert_eq!(image::check(&w, false), Err(image::ImageError::Machine(osyx_pe::MACHINE_ARM64)));
    // A PE32+ image is still an x86-64 image.
    let hello = PeFile::parse(HELLO).unwrap();
    assert_eq!(image::kind(&hello), image::PeKind::Pe32Plus);
    assert_eq!(image::pointer_size(&hello), 8);

    // A Dir64 relocation in a PE32 image is reported, not applied.
    let mut b = pe32_image("KERNEL32.dll");
    put16(&mut b, rdata(0x2100) + 8, 0xA080); // type 10 (DIR64) instead of 3
    let b = b;
    let pe = PeFile::parse_any(&b).unwrap();
    let mut img = image::layout(&pe).unwrap();
    assert_eq!(image::relocate(&pe, &mut img, 0x1000_0000), Err(image::ImageError::Relocation(10)));
}
