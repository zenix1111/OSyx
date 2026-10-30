//! Bounds-checked, zero-copy parser for PE32+ images (Windows x64 `.exe` and
//! `.dll` files), written from the published PE/COFF specification.
//!
//! Design rules:
//! * Every read goes through a checked accessor; every offset and size is
//!   combined with checked arithmetic. Malformed input produces a [`PeError`],
//!   never a panic, an out-of-bounds read or an overflow.
//! * Nothing is copied: names and tables borrow from the input. The crate is
//!   `no_std` without `alloc`, so the kernel can use it later.
//! * [`PeFile::parse`] validates the headers and section table; the data
//!   directories (imports, exports, relocations, TLS, exception data) are
//!   validated lazily by their own accessors, so one damaged directory does
//!   not hide the rest of the file.
//! * Parsing never executes anything; this crate only reads bytes.
//!
//! What "valid" means here is structural consistency. Loader policy (which
//! machine types, relocation types or subsystems OSyx accepts) belongs to the
//! loader.

#![no_std]

mod exception;
mod exports;
mod imports;
mod relocs;
mod tls;
mod resources;

pub use exception::{RuntimeFunction, RuntimeFunctions, UnwindInfo};
pub use exports::{Export, ExportTarget, Exports};
pub use imports::{DelayImport, DelayImportDescriptors, Import, ImportDescriptors, ImportEntries, ImportEntry};
pub use relocs::{BaseRelocations, Relocation, RelocationKind};
pub use tls::{TlsCallbacks, TlsInfo};
pub use resources::{version_value, VersionValue};

use core::fmt;

pub const MACHINE_AMD64: u16 = 0x8664;

impl core::error::Error for PeError {}
pub const MACHINE_I386: u16 = 0x014C;
pub const MACHINE_ARM64: u16 = 0xAA64;
pub const PE32_MAGIC: u16 = 0x10B;
pub const PE32PLUS_MAGIC: u16 = 0x20B;

/// COFF characteristics.
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// Optional header DllCharacteristics.
pub const DLLCHAR_HIGH_ENTROPY_VA: u16 = 0x0020;
pub const DLLCHAR_DYNAMIC_BASE: u16 = 0x0040;
pub const DLLCHAR_NX_COMPAT: u16 = 0x0100;

/// Section characteristics.
pub const SCN_CNT_CODE: u32 = 0x0000_0020;
pub const SCN_CNT_INITIALIZED_DATA: u32 = 0x0000_0040;
pub const SCN_CNT_UNINITIALIZED_DATA: u32 = 0x0000_0080;
pub const SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const SCN_MEM_SHARED: u32 = 0x1000_0000;
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

/// Data directory indices.
pub mod dir {
    pub const EXPORT: usize = 0;
    pub const IMPORT: usize = 1;
    pub const RESOURCE: usize = 2;
    pub const EXCEPTION: usize = 3;
    /// Certificate table: holds a *file offset*, not an RVA.
    pub const SECURITY: usize = 4;
    pub const BASERELOC: usize = 5;
    pub const DEBUG: usize = 6;
    pub const ARCHITECTURE: usize = 7;
    pub const GLOBALPTR: usize = 8;
    pub const TLS: usize = 9;
    pub const LOAD_CONFIG: usize = 10;
    pub const BOUND_IMPORT: usize = 11;
    pub const IAT: usize = 12;
    pub const DELAY_IMPORT: usize = 13;
    pub const CLR: usize = 14;
    pub const RESERVED: usize = 15;
}

/// Upper bound from the PE specification.
pub const MAX_SECTIONS: usize = 96;
const DOS_HEADER_SIZE: usize = 64;
const COFF_HEADER_SIZE: usize = 20;
/// Fixed part of the PE32+ optional header (before the data directories).
const OPT64_FIXED_SIZE: usize = 112;
const OPT32_FIXED_SIZE: usize = 96;
const SECTION_HEADER_SIZE: usize = 40;
/// Longest name (DLL, function, forwarder) the parser accepts. MSVC
/// decorated C++ names reach several hundred bytes (seen: 699 in a Windows
/// DLL); 4096 is MSVC's limit for decorated names.
pub const MAX_NAME_LEN: usize = 4096;

/// Where a structural problem was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeError {
    /// The file ends before a structure that must be present.
    Truncated {
        what: &'static str,
    },
    BadDosSignature,
    /// `e_lfanew` points outside the file or into the DOS header.
    BadPeOffset(u32),
    BadPeSignature,
    /// A PE32 (32-bit) image; only PE32+ is supported.
    NotPe32Plus {
        magic: u16,
    },
    BadOptionalHeaderSize(u16),
    TooManyDataDirectories(u32),
    TooManySections(u16),
    NoSections,
    BadAlignment {
        section_alignment: u32,
        file_alignment: u32,
    },
    BadSizeOfImage(u32),
    BadSizeOfHeaders(u32),
    /// Section `index` is malformed (`reason` says how).
    BadSection {
        index: usize,
        reason: &'static str,
    },
    EntryPointOutsideImage(u32),
    /// Data directory `index` points outside the image (or the file, for
    /// the certificate table).
    BadDataDirectory {
        index: usize,
    },
    /// An RVA does not lie in file-backed data of any section or the headers.
    RvaNotInFile(u32),
    /// A NUL-terminated name is missing its terminator, too long or not UTF-8.
    BadName {
        rva: u32,
    },
    BadImport {
        reason: &'static str,
    },
    BadResource {
        reason: &'static str,
    },
    BadExport {
        reason: &'static str,
    },
    BadRelocation {
        reason: &'static str,
    },
    BadTls {
        reason: &'static str,
    },
    BadExceptionData {
        reason: &'static str,
    },
}

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeError::Truncated { what } => write!(f, "file truncated in {what}"),
            PeError::BadDosSignature => f.write_str("missing MZ signature"),
            PeError::BadPeOffset(o) => write!(f, "e_lfanew {o:#x} is out of range"),
            PeError::BadPeSignature => f.write_str("missing PE signature"),
            PeError::NotPe32Plus { magic } => write!(f, "optional header magic {magic:#x} is not PE32+"),
            PeError::BadOptionalHeaderSize(s) => write!(f, "optional header size {s} is invalid"),
            PeError::TooManyDataDirectories(n) => write!(f, "{n} data directories (maximum 16)"),
            PeError::TooManySections(n) => write!(f, "{n} sections (maximum {MAX_SECTIONS})"),
            PeError::NoSections => f.write_str("image has no sections"),
            PeError::BadAlignment { section_alignment, file_alignment } => {
                write!(f, "invalid alignment (section {section_alignment:#x}, file {file_alignment:#x})")
            }
            PeError::BadSizeOfImage(s) => write!(f, "SizeOfImage {s:#x} is invalid"),
            PeError::BadSizeOfHeaders(s) => write!(f, "SizeOfHeaders {s:#x} is invalid"),
            PeError::BadSection { index, reason } => write!(f, "section {index}: {reason}"),
            PeError::EntryPointOutsideImage(e) => write!(f, "entry point {e:#x} outside the image"),
            PeError::BadDataDirectory { index } => write!(f, "data directory {index} out of range"),
            PeError::RvaNotInFile(r) => write!(f, "RVA {r:#x} is not backed by file data"),
            PeError::BadName { rva } => write!(f, "invalid name at RVA {rva:#x}"),
            PeError::BadImport { reason } => write!(f, "import table: {reason}"),
            PeError::BadResource { reason } => write!(f, "resource: {reason}"),
            PeError::BadExport { reason } => write!(f, "export table: {reason}"),
            PeError::BadRelocation { reason } => write!(f, "base relocations: {reason}"),
            PeError::BadTls { reason } => write!(f, "TLS directory: {reason}"),
            PeError::BadExceptionData { reason } => write!(f, "exception data: {reason}"),
        }
    }
}

pub type Result<T> = core::result::Result<T, PeError>;

// ---- checked little-endian readers ------------------------------------------

pub(crate) fn bytes<'a>(d: &'a [u8], off: usize, len: usize, what: &'static str) -> Result<&'a [u8]> {
    let end = off.checked_add(len).ok_or(PeError::Truncated { what })?;
    d.get(off..end).ok_or(PeError::Truncated { what })
}

pub(crate) fn u16_at(d: &[u8], off: usize, what: &'static str) -> Result<u16> {
    let b = bytes(d, off, 2, what)?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

pub(crate) fn u32_at(d: &[u8], off: usize, what: &'static str) -> Result<u32> {
    let b = bytes(d, off, 4, what)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

pub(crate) fn u64_at(d: &[u8], off: usize, what: &'static str) -> Result<u64> {
    let b = bytes(d, off, 8, what)?;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(u64::from_le_bytes(a))
}

// ---- headers ----------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoffHeader {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OptionalHeader {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DataDirectory {
    pub virtual_address: u32,
    pub size: u32,
}

impl DataDirectory {
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 && self.size != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section<'a> {
    /// Raw 8-byte name (NUL padded; long names via the string table are not
    /// resolved because images rarely use them).
    pub raw_name: &'a [u8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
}

impl<'a> Section<'a> {
    /// The section name up to the first NUL, if it is UTF-8.
    pub fn name(&self) -> &'a str {
        let end = self.raw_name.iter().position(|&b| b == 0).unwrap_or(self.raw_name.len());
        core::str::from_utf8(&self.raw_name[..end]).unwrap_or("")
    }

    /// Size of the section in memory (VirtualSize, or SizeOfRawData when the
    /// former is zero, as the Windows loader does).
    pub fn mapped_size(&self) -> u32 {
        if self.virtual_size != 0 {
            self.virtual_size
        } else {
            self.size_of_raw_data
        }
    }

    /// Bytes of the section that come from the file.
    pub fn file_size(&self) -> u32 {
        self.size_of_raw_data.min(self.mapped_size())
    }

    pub fn is_executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }

    pub fn is_writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }

    pub fn is_readable(&self) -> bool {
        self.characteristics & SCN_MEM_READ != 0
    }

    fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.virtual_address && (rva - self.virtual_address) < self.mapped_size()
    }
}

/// A validated PE32+ image.
#[derive(Clone, Copy, Debug)]
pub struct PeFile<'a> {
    data: &'a [u8],
    pe_offset: usize,
    coff: CoffHeader,
    opt: OptionalHeader,
    dirs: [DataDirectory; 16],
    section_table: usize,
}

fn is_pow2(x: u32) -> bool {
    x != 0 && x & (x - 1) == 0
}

impl<'a> PeFile<'a> {
    /// Validates the DOS header, PE headers, data directory bounds and the
    /// section table.
    pub fn parse(data: &'a [u8]) -> Result<PeFile<'a>> {
        Self::parse_inner(data, false)
    }

    /// Like [`PeFile::parse`], but also accepts a 32-bit PE32 image (see
    /// [`PeFile::is_pe32`]); its addresses and sizes are widened to 64 bits.
    pub fn parse_any(data: &'a [u8]) -> Result<PeFile<'a>> {
        Self::parse_inner(data, true)
    }

    /// Whether this is a 32-bit PE32 image (optional header magic 0x10B).
    pub fn is_pe32(&self) -> bool {
        self.opt.magic == PE32_MAGIC
    }

    fn parse_inner(data: &'a [u8], allow_pe32: bool) -> Result<PeFile<'a>> {
        if data.len() < DOS_HEADER_SIZE {
            return Err(PeError::Truncated { what: "DOS header" });
        }
        if &data[0..2] != b"MZ" {
            return Err(PeError::BadDosSignature);
        }
        let e_lfanew = u32_at(data, 0x3C, "DOS header")?;
        let pe_offset = e_lfanew as usize;
        if pe_offset < 4 || pe_offset.checked_add(4 + COFF_HEADER_SIZE).is_none_or(|e| e > data.len()) {
            return Err(PeError::BadPeOffset(e_lfanew));
        }
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(PeError::BadPeSignature);
        }
        let c = pe_offset + 4;
        let coff = CoffHeader {
            machine: u16_at(data, c, "COFF header")?,
            number_of_sections: u16_at(data, c + 2, "COFF header")?,
            time_date_stamp: u32_at(data, c + 4, "COFF header")?,
            pointer_to_symbol_table: u32_at(data, c + 8, "COFF header")?,
            number_of_symbols: u32_at(data, c + 12, "COFF header")?,
            size_of_optional_header: u16_at(data, c + 16, "COFF header")?,
            characteristics: u16_at(data, c + 18, "COFF header")?,
        };
        let o = c + COFF_HEADER_SIZE;
        let magic = u16_at(data, o, "optional header")?;
        let pe32 = magic == PE32_MAGIC;
        if magic != PE32PLUS_MAGIC && !(pe32 && allow_pe32) {
            return Err(PeError::NotPe32Plus { magic });
        }
        let fixed = if pe32 { OPT32_FIXED_SIZE } else { OPT64_FIXED_SIZE };
        let opt_size = coff.size_of_optional_header as usize;
        if opt_size < fixed {
            return Err(PeError::BadOptionalHeaderSize(coff.size_of_optional_header));
        }
        bytes(data, o, opt_size, "optional header")?;
        let opt = if pe32 {
            OptionalHeader {
                magic,
                major_linker_version: data[o + 2],
                minor_linker_version: data[o + 3],
                size_of_code: u32_at(data, o + 4, "optional header")?,
                size_of_initialized_data: u32_at(data, o + 8, "optional header")?,
                size_of_uninitialized_data: u32_at(data, o + 12, "optional header")?,
                address_of_entry_point: u32_at(data, o + 16, "optional header")?,
                base_of_code: u32_at(data, o + 20, "optional header")?,
                image_base: u32_at(data, o + 28, "optional header")? as u64,
                section_alignment: u32_at(data, o + 32, "optional header")?,
                file_alignment: u32_at(data, o + 36, "optional header")?,
                major_operating_system_version: u16_at(data, o + 40, "optional header")?,
                minor_operating_system_version: u16_at(data, o + 42, "optional header")?,
                major_image_version: u16_at(data, o + 44, "optional header")?,
                minor_image_version: u16_at(data, o + 46, "optional header")?,
                major_subsystem_version: u16_at(data, o + 48, "optional header")?,
                minor_subsystem_version: u16_at(data, o + 50, "optional header")?,
                win32_version_value: u32_at(data, o + 52, "optional header")?,
                size_of_image: u32_at(data, o + 56, "optional header")?,
                size_of_headers: u32_at(data, o + 60, "optional header")?,
                check_sum: u32_at(data, o + 64, "optional header")?,
                subsystem: u16_at(data, o + 68, "optional header")?,
                dll_characteristics: u16_at(data, o + 70, "optional header")?,
                size_of_stack_reserve: u32_at(data, o + 72, "optional header")? as u64,
                size_of_stack_commit: u32_at(data, o + 76, "optional header")? as u64,
                size_of_heap_reserve: u32_at(data, o + 80, "optional header")? as u64,
                size_of_heap_commit: u32_at(data, o + 84, "optional header")? as u64,
                loader_flags: u32_at(data, o + 88, "optional header")?,
                number_of_rva_and_sizes: u32_at(data, o + 92, "optional header")?,
            }
        } else {
        OptionalHeader {
            magic,
            major_linker_version: data[o + 2],
            minor_linker_version: data[o + 3],
            size_of_code: u32_at(data, o + 4, "optional header")?,
            size_of_initialized_data: u32_at(data, o + 8, "optional header")?,
            size_of_uninitialized_data: u32_at(data, o + 12, "optional header")?,
            address_of_entry_point: u32_at(data, o + 16, "optional header")?,
            base_of_code: u32_at(data, o + 20, "optional header")?,
            image_base: u64_at(data, o + 24, "optional header")?,
            section_alignment: u32_at(data, o + 32, "optional header")?,
            file_alignment: u32_at(data, o + 36, "optional header")?,
            major_operating_system_version: u16_at(data, o + 40, "optional header")?,
            minor_operating_system_version: u16_at(data, o + 42, "optional header")?,
            major_image_version: u16_at(data, o + 44, "optional header")?,
            minor_image_version: u16_at(data, o + 46, "optional header")?,
            major_subsystem_version: u16_at(data, o + 48, "optional header")?,
            minor_subsystem_version: u16_at(data, o + 50, "optional header")?,
            win32_version_value: u32_at(data, o + 52, "optional header")?,
            size_of_image: u32_at(data, o + 56, "optional header")?,
            size_of_headers: u32_at(data, o + 60, "optional header")?,
            check_sum: u32_at(data, o + 64, "optional header")?,
            subsystem: u16_at(data, o + 68, "optional header")?,
            dll_characteristics: u16_at(data, o + 70, "optional header")?,
            size_of_stack_reserve: u64_at(data, o + 72, "optional header")?,
            size_of_stack_commit: u64_at(data, o + 80, "optional header")?,
            size_of_heap_reserve: u64_at(data, o + 88, "optional header")?,
            size_of_heap_commit: u64_at(data, o + 96, "optional header")?,
            loader_flags: u32_at(data, o + 104, "optional header")?,
            number_of_rva_and_sizes: u32_at(data, o + 108, "optional header")?,
        }
        };
        let ndirs = opt.number_of_rva_and_sizes;
        if ndirs > 16 {
            return Err(PeError::TooManyDataDirectories(ndirs));
        }
        if fixed + ndirs as usize * 8 > opt_size {
            return Err(PeError::BadOptionalHeaderSize(coff.size_of_optional_header));
        }
        let mut dirs = [DataDirectory::default(); 16];
        for (i, d) in dirs.iter_mut().enumerate().take(ndirs as usize) {
            let at = o + fixed + i * 8;
            *d = DataDirectory {
                virtual_address: u32_at(data, at, "data directories")?,
                size: u32_at(data, at + 4, "data directories")?,
            };
        }

        // Alignment rules from the specification.
        let (sa, fa) = (opt.section_alignment, opt.file_alignment);
        let fa_ok = is_pow2(fa) && (512..=0x10000).contains(&fa);
        let sa_ok = is_pow2(sa) && sa >= fa && (sa >= 0x1000 || sa == fa);
        // Small alignment (< page) is legal when file and section alignment
        // match; such images have fa < 512, so accept that combination too.
        let small_ok = is_pow2(fa) && sa == fa && fa < 512;
        if !(fa_ok && sa_ok) && !small_ok {
            return Err(PeError::BadAlignment { section_alignment: sa, file_alignment: fa });
        }
        if opt.size_of_image == 0 || !opt.size_of_image.is_multiple_of(sa) {
            return Err(PeError::BadSizeOfImage(opt.size_of_image));
        }

        let nsec = coff.number_of_sections as usize;
        if nsec == 0 {
            return Err(PeError::NoSections);
        }
        if nsec > MAX_SECTIONS {
            return Err(PeError::TooManySections(coff.number_of_sections));
        }
        let section_table = o + opt_size;
        let table_end = section_table + nsec * SECTION_HEADER_SIZE;
        if table_end > data.len() {
            return Err(PeError::Truncated { what: "section table" });
        }
        let soh = opt.size_of_headers as usize;
        if soh < table_end || soh > data.len() || opt.size_of_headers > opt.size_of_image {
            return Err(PeError::BadSizeOfHeaders(opt.size_of_headers));
        }

        let pe = PeFile { data, pe_offset, coff, opt, dirs, section_table };
        pe.check_sections()?;
        let ep = opt.address_of_entry_point;
        if ep != 0 && ep >= opt.size_of_image {
            return Err(PeError::EntryPointOutsideImage(ep));
        }
        for (index, d) in dirs.iter().enumerate() {
            if !d.is_present() {
                continue;
            }
            let end = d.virtual_address.checked_add(d.size);
            let limit = if index == dir::SECURITY { data.len() as u64 } else { opt.size_of_image as u64 };
            if end.is_none_or(|e| e as u64 > limit) {
                return Err(PeError::BadDataDirectory { index });
            }
        }
        Ok(pe)
    }

    fn check_sections(&self) -> Result<()> {
        let sa = self.opt.section_alignment;
        let mut prev_end = self.opt.size_of_headers.next_multiple_of(sa);
        for index in 0..self.section_count() {
            let s = self.section(index)?;
            let bad = |reason| Err(PeError::BadSection { index, reason });
            if !s.virtual_address.is_multiple_of(sa) {
                return bad("virtual address not section-aligned");
            }
            if s.virtual_address < prev_end {
                return bad("overlaps the headers or the previous section");
            }
            let Some(end) = s.virtual_address.checked_add(s.mapped_size()) else {
                return bad("virtual range overflows");
            };
            if end > self.opt.size_of_image {
                return bad("extends past SizeOfImage");
            }
            if s.size_of_raw_data != 0 {
                let raw_end = s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64;
                if raw_end > self.data.len() as u64 {
                    return bad("raw data extends past the end of the file");
                }
            }
            prev_end = end.next_multiple_of(sa).max(end);
        }
        Ok(())
    }

    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn pe_offset(&self) -> usize {
        self.pe_offset
    }

    pub fn coff(&self) -> &CoffHeader {
        &self.coff
    }

    pub fn optional(&self) -> &OptionalHeader {
        &self.opt
    }

    pub fn machine(&self) -> u16 {
        self.coff.machine
    }

    pub fn is_dll(&self) -> bool {
        self.coff.characteristics & IMAGE_FILE_DLL != 0
    }

    pub fn image_base(&self) -> u64 {
        self.opt.image_base
    }

    pub fn entry_point(&self) -> u32 {
        self.opt.address_of_entry_point
    }

    pub fn size_of_image(&self) -> u32 {
        self.opt.size_of_image
    }

    /// Data directory `index` (all zero if absent).
    pub fn directory(&self, index: usize) -> DataDirectory {
        self.dirs.get(index).copied().unwrap_or_default()
    }

    pub fn section_count(&self) -> usize {
        self.coff.number_of_sections as usize
    }

    pub fn section(&self, index: usize) -> Result<Section<'a>> {
        if index >= self.section_count() {
            return Err(PeError::BadSection { index, reason: "no such section" });
        }
        let at = self.section_table + index * SECTION_HEADER_SIZE;
        let d = self.data;
        Ok(Section {
            raw_name: bytes(d, at, 8, "section table")?,
            virtual_size: u32_at(d, at + 8, "section table")?,
            virtual_address: u32_at(d, at + 12, "section table")?,
            size_of_raw_data: u32_at(d, at + 16, "section table")?,
            pointer_to_raw_data: u32_at(d, at + 20, "section table")?,
            characteristics: u32_at(d, at + 36, "section table")?,
        })
    }

    pub fn sections(&self) -> impl Iterator<Item = Section<'a>> + 'a {
        let pe = *self;
        (0..pe.section_count()).filter_map(move |i| pe.section(i).ok())
    }

    /// The section whose memory range contains `rva`.
    pub fn section_for_rva(&self, rva: u32) -> Option<Section<'a>> {
        self.sections().find(|s| s.contains_rva(rva))
    }

    /// File offset of the byte at `rva`, if that byte comes from the file
    /// (headers, or the initialised part of a section).
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        if rva < self.opt.size_of_headers {
            return Some(rva as usize);
        }
        let s = self.section_for_rva(rva)?;
        let delta = rva - s.virtual_address;
        if delta >= s.file_size() {
            return None;
        }
        let off = s.pointer_to_raw_data as usize + delta as usize;
        (off < self.data.len()).then_some(off)
    }

    /// `len` file-backed bytes starting at `rva`, all within one section (or
    /// the headers).
    pub fn slice_at_rva(&self, rva: u32, len: usize) -> Result<&'a [u8]> {
        if len == 0 {
            // An empty range is valid anywhere inside the image, including
            // exactly at the end of a section's file data.
            return if rva <= self.opt.size_of_image { Ok(&[]) } else { Err(PeError::RvaNotInFile(rva)) };
        }
        let off = self.rva_to_offset(rva).ok_or(PeError::RvaNotInFile(rva))?;
        let limit = if rva < self.opt.size_of_headers {
            self.opt.size_of_headers as usize
        } else {
            let s = self.section_for_rva(rva).ok_or(PeError::RvaNotInFile(rva))?;
            s.pointer_to_raw_data as usize + s.file_size() as usize
        };
        let end = off.checked_add(len).ok_or(PeError::RvaNotInFile(rva))?;
        if end > limit.min(self.data.len()) {
            return Err(PeError::RvaNotInFile(rva));
        }
        Ok(&self.data[off..end])
    }

    /// Reads `N` bytes at `rva` as the loader would see them in the mapped
    /// image: the part of a section beyond its file data reads as zeros. The
    /// whole read must lie in the headers or inside one section's memory range.
    pub fn read_mapped<const N: usize>(&self, rva: u32) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        let end = rva.checked_add(N as u32).ok_or(PeError::RvaNotInFile(rva))?;
        if end <= self.opt.size_of_headers {
            let src = self.data.get(rva as usize..end as usize).ok_or(PeError::RvaNotInFile(rva))?;
            out.copy_from_slice(src);
            return Ok(out);
        }
        let s = self.section_for_rva(rva).ok_or(PeError::RvaNotInFile(rva))?;
        let delta = rva - s.virtual_address;
        if delta as u64 + N as u64 > s.mapped_size() as u64 {
            return Err(PeError::RvaNotInFile(rva));
        }
        for (i, b) in out.iter_mut().enumerate() {
            let d = delta + i as u32;
            if d < s.file_size() {
                *b = *self.data.get(s.pointer_to_raw_data as usize + d as usize).ok_or(PeError::RvaNotInFile(rva))?;
            }
        }
        Ok(out)
    }

    pub(crate) fn u16_at_rva(&self, rva: u32) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_mapped(rva)?))
    }

    pub(crate) fn u32_at_rva(&self, rva: u32) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_mapped(rva)?))
    }

    pub(crate) fn u64_at_rva(&self, rva: u32) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_mapped(rva)?))
    }

    /// A NUL-terminated UTF-8 string of at most [`MAX_NAME_LEN`] bytes.
    pub fn cstr_at_rva(&self, rva: u32) -> Result<&'a str> {
        let off = self.rva_to_offset(rva).ok_or(PeError::BadName { rva })?;
        let s = self.section_for_rva(rva);
        let limit = match s {
            Some(s) if rva >= self.opt.size_of_headers => s.pointer_to_raw_data as usize + s.file_size() as usize,
            _ => self.opt.size_of_headers as usize,
        }
        .min(self.data.len());
        let window = &self.data[off..limit.max(off)];
        let len = window.iter().take(MAX_NAME_LEN + 1).position(|&b| b == 0).ok_or(PeError::BadName { rva })?;
        core::str::from_utf8(&window[..len]).map_err(|_| PeError::BadName { rva })
    }

    /// Converts a virtual address (as stored in TLS directories) to an RVA
    /// inside the image.
    pub fn va_to_rva(&self, va: u64) -> Option<u32> {
        let rva = va.checked_sub(self.opt.image_base)?;
        (rva < self.opt.size_of_image as u64).then_some(rva as u32)
    }

    /// The import descriptors (data directory 1).
    pub fn imports(&self) -> Result<ImportDescriptors<'a>> {
        imports::descriptors(*self)
    }

    /// Read-only modern RVA-based delay-load descriptors (directory 13).
    pub fn delay_imports(&self) -> Result<DelayImportDescriptors<'a>> {
        imports::delay_descriptors(*self)
    }

    /// Numeric PE resource lookup. None selects the first name/language.
    /// Every directory offset stays inside the resource directory; payload
    /// RVAs must reference file-backed image bytes. No host APIs are called.
    pub fn resource(&self, kind: u16, name: Option<u16>, language: Option<u16>) -> Result<Option<&'a [u8]>> {
        resources::resource(*self, kind, name, language)
    }

    /// The export table (data directory 0), if present.
    pub fn exports(&self) -> Result<Option<Exports<'a>>> {
        exports::parse(*self)
    }

    /// The base relocations (data directory 5).
    pub fn relocations(&self) -> Result<BaseRelocations<'a>> {
        relocs::parse(*self)
    }

    /// The TLS directory (data directory 9), if present.
    pub fn tls(&self) -> Result<Option<TlsInfo<'a>>> {
        tls::parse(*self)
    }

    /// The function table of the exception directory (data directory 3).
    pub fn runtime_functions(&self) -> Result<RuntimeFunctions<'a>> {
        exception::parse(*self)
    }
}
