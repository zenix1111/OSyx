//! Import directory: `IMAGE_IMPORT_DESCRIPTOR` array (20 bytes each, ended
//! by an all-zero entry), each naming a DLL and pointing to its import lookup
//! table (ILT) and import address table (IAT) of 64-bit thunks.

use crate::{dir, PeError, PeFile, Result};

const DESCRIPTOR_SIZE: u32 = 20;
/// Hard caps that keep iteration bounded on hostile input.
const MAX_DESCRIPTORS: u32 = 4096;
const MAX_THUNKS: u32 = 65536;
const ORDINAL_FLAG: u64 = 1 << 63;

#[derive(Clone, Copy, Debug)]
pub struct DelayImport<'a> {
    pub import: Import<'a>,
    pub module_handle_rva: u32,
    pub bound_table_rva: u32,
    pub unload_table_rva: u32,
}
pub struct DelayImportDescriptors<'a> {
    pe: PeFile<'a>,
    next: u32,
    remaining: u32,
    count: u32,
    done: bool,
}
pub(crate) fn delay_descriptors(pe: PeFile<'_>) -> Result<DelayImportDescriptors<'_>> {
    let d = pe.directory(dir::DELAY_IMPORT);
    Ok(DelayImportDescriptors { pe, next: d.virtual_address, remaining: d.size, count: 0, done: !d.is_present() })
}
impl<'a> DelayImportDescriptors<'a> {
    fn read(&mut self) -> Result<Option<DelayImport<'a>>> {
        let bad = |reason| PeError::BadImport { reason };
        if self.count >= MAX_DESCRIPTORS {
            return Err(bad("too many delay descriptors"));
        }
        if self.remaining < 32 {
            return Err(bad("delay descriptor array not terminated"));
        }
        let raw = self.pe.slice_at_rva(self.next, 32).map_err(|_| bad("delay descriptor not in file"))?;
        let f = |i| u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
        if raw.iter().all(|&b| b == 0) {
            return Ok(None);
        }
        if f(0) != 1 {
            return Err(bad("unsupported delay attributes (RVA form required)"));
        }
        let (name, handle, iat, int, bound, unload) = (f(4), f(8), f(12), f(16), f(20), f(24));
        if name == 0 || iat == 0 || int == 0 {
            return Err(bad("delay descriptor without name, IAT or INT"));
        }
        for rva in [handle, iat, int, bound, unload].into_iter().filter(|&r| r != 0) {
            if rva.checked_add(8).is_none_or(|end| end > self.pe.size_of_image()) {
                return Err(bad("delay table outside image"));
            }
        }
        let dll = self.pe.cstr_at_rva(name).map_err(|_| bad("invalid delay DLL name"))?;
        if dll.is_empty() {
            return Err(bad("empty delay DLL name"));
        }
        self.next = self.next.checked_add(32).ok_or(bad("delay array overflows"))?;
        self.remaining -= 32;
        self.count += 1;
        Ok(Some(DelayImport {
            import: Import {
                pe: self.pe,
                dll,
                lookup_table_rva: int,
                address_table_rva: iat,
                time_date_stamp: f(28),
                forwarder_chain: 0,
            },
            module_handle_rva: handle,
            bound_table_rva: bound,
            unload_table_rva: unload,
        }))
    }
}
impl<'a> Iterator for DelayImportDescriptors<'a> {
    type Item = Result<DelayImport<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read() {
            Ok(Some(d)) => Some(Ok(d)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// One imported DLL.
#[derive(Clone, Copy, Debug)]
pub struct Import<'a> {
    pe: PeFile<'a>,
    pub dll: &'a str,
    /// RVA of the import lookup table (0 if absent; the IAT is used then).
    pub lookup_table_rva: u32,
    /// RVA of the import address table, patched by the loader.
    pub address_table_rva: u32,
    pub time_date_stamp: u32,
    pub forwarder_chain: u32,
}

/// One imported symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportEntry<'a> {
    ByName { hint: u16, name: &'a str, iat_rva: u32 },
    ByOrdinal { ordinal: u16, iat_rva: u32 },
}

impl ImportEntry<'_> {
    /// RVA of the IAT slot the loader must fill for this entry.
    pub fn iat_rva(&self) -> u32 {
        match *self {
            ImportEntry::ByName { iat_rva, .. } | ImportEntry::ByOrdinal { iat_rva, .. } => iat_rva,
        }
    }
}

/// Iterator over import descriptors. Yields `Err` once on a malformed
/// descriptor and then stops.
pub struct ImportDescriptors<'a> {
    pe: PeFile<'a>,
    next: u32,
    count: u32,
    done: bool,
}

pub(crate) fn descriptors(pe: PeFile<'_>) -> Result<ImportDescriptors<'_>> {
    let d = pe.directory(dir::IMPORT);
    if !d.is_present() {
        return Ok(ImportDescriptors { pe, next: 0, count: 0, done: true });
    }
    // The directory bounds were checked against SizeOfImage in `parse`.
    Ok(ImportDescriptors { pe, next: d.virtual_address, count: 0, done: false })
}

impl<'a> ImportDescriptors<'a> {
    fn read(&mut self) -> Result<Option<Import<'a>>> {
        let bad = |reason| PeError::BadImport { reason };
        if self.count == MAX_DESCRIPTORS {
            return Err(bad("too many descriptors"));
        }
        // Descriptors may legitimately run past the declared directory size
        // in some linkers' output, but never past the image.
        let raw =
            self.pe.slice_at_rva(self.next, DESCRIPTOR_SIZE as usize).map_err(|_| bad("descriptor not in file"))?;
        let f = |i: usize| u32::from_le_bytes([raw[i], raw[i + 1], raw[i + 2], raw[i + 3]]);
        let (ilt, stamp, chain, name, iat) = (f(0), f(4), f(8), f(12), f(16));
        if ilt == 0 && stamp == 0 && chain == 0 && name == 0 && iat == 0 {
            return Ok(None);
        }
        if name == 0 || iat == 0 {
            return Err(bad("descriptor without name or IAT"));
        }
        let dll = self.pe.cstr_at_rva(name).map_err(|_| bad("DLL name invalid"))?;
        if dll.is_empty() {
            return Err(bad("empty DLL name"));
        }
        let image = self.pe.size_of_image();
        if iat >= image || ilt >= image {
            return Err(bad("thunk table outside the image"));
        }
        self.next = self.next.checked_add(DESCRIPTOR_SIZE).ok_or(bad("descriptor array overflows"))?;
        self.count += 1;
        Ok(Some(Import {
            pe: self.pe,
            dll,
            lookup_table_rva: ilt,
            address_table_rva: iat,
            time_date_stamp: stamp,
            forwarder_chain: chain,
        }))
    }
}

impl<'a> Iterator for ImportDescriptors<'a> {
    type Item = Result<Import<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read() {
            Ok(Some(i)) => Some(Ok(i)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

impl<'a> Import<'a> {
    /// The imported symbols. Reads the ILT if present, otherwise the IAT
    /// (which holds the same thunks in an unbound file).
    pub fn entries(&self) -> ImportEntries<'a> {
        let table = if self.lookup_table_rva != 0 { self.lookup_table_rva } else { self.address_table_rva };
        ImportEntries { pe: self.pe, table, iat: self.address_table_rva, index: 0, done: false }
    }
}

pub struct ImportEntries<'a> {
    pe: PeFile<'a>,
    table: u32,
    iat: u32,
    index: u32,
    done: bool,
}

impl<'a> ImportEntries<'a> {
    fn read(&mut self) -> Result<Option<ImportEntry<'a>>> {
        let bad = |reason| PeError::BadImport { reason };
        if self.index == MAX_THUNKS {
            return Err(bad("thunk table not terminated"));
        }
        let width: u32 = if self.pe.is_pe32() { 4 } else { 8 };
        let offset = self.index.checked_mul(width).ok_or(bad("thunk index overflows"))?;
        let rva = self.table.checked_add(offset).ok_or(bad("thunk table overflows"))?;
        let iat_rva = self.iat.checked_add(offset).ok_or(bad("IAT overflows"))?;
        // A PE32 thunk is 32 bits wide with the ordinal flag in bit 31.
        let (thunk, ordinal_flag) = if self.pe.is_pe32() {
            (self.pe.u32_at_rva(rva).map_err(|_| bad("thunk not in file"))? as u64, 1u64 << 31)
        } else {
            (self.pe.u64_at_rva(rva).map_err(|_| bad("thunk not in file"))?, ORDINAL_FLAG)
        };
        if thunk == 0 {
            return Ok(None);
        }
        if iat_rva.checked_add(width).is_none_or(|e| e > self.pe.size_of_image()) {
            return Err(bad("IAT slot outside the image"));
        }
        self.index += 1;
        if thunk & ordinal_flag != 0 {
            if thunk & !ordinal_flag & !0xFFFF != 0 {
                return Err(bad("reserved bits set in an ordinal thunk"));
            }
            return Ok(Some(ImportEntry::ByOrdinal { ordinal: thunk as u16, iat_rva }));
        }
        if thunk >> 31 != 0 {
            return Err(bad("hint/name RVA does not fit in 31 bits"));
        }
        let hn = thunk as u32;
        let hint = self.pe.u16_at_rva(hn).map_err(|_| bad("hint/name entry not in file"))?;
        let name_rva = hn.checked_add(2).ok_or(bad("hint/name RVA overflows"))?;
        let name = self.pe.cstr_at_rva(name_rva).map_err(|_| bad("import name invalid"))?;
        if name.is_empty() {
            return Err(bad("empty import name"));
        }
        Ok(Some(ImportEntry::ByName { hint, name, iat_rva }))
    }
}

impl<'a> Iterator for ImportEntries<'a> {
    type Item = Result<ImportEntry<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.read() {
            Ok(Some(e)) => Some(Ok(e)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}
