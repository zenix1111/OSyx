//! The module graph: loads an executable and its DLLs, binds imports
//! (by name and by ordinal), follows export forwarders and API set
//! contracts, and computes the initialisation order.
//!
//! Where modules come from and where they go is the [`Host`]'s business:
//! it opens a DLL by name (an OSyx built-in module implemented by the
//! runtime, or a PE file from the VFS), reserves address space for an
//! image and commits the finished image with its protections. That keeps
//! this crate free of system calls and testable on the build host.
//!
//! Rules (Windows-compatible where it matters for real programs):
//! * DLL names compare ASCII case-insensitively; `.dll` is implied when the
//!   name has no extension;
//! * `api-*` / `ext-*` names go through the API set schema, with the
//!   importing module as the importer;
//! * import cycles are legal (a module already being loaded is bound
//!   against as is: export addresses do not depend on its imports) and are
//!   reported; initialisation follows dependency order, cycles broken at
//!   the edge that closes them;
//! * forwarder chains are bounded ([`MAX_FORWARD_DEPTH`]);
//! * a PE32 image and a PE32+ image cannot import each other (their thunks
//!   are different widths) and 32-bit images are never placed above 4 GiB.

use crate::apiset::{self, Schema};
use crate::image::{self, ImageError, Protection};
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use osyx_pe::{ExportTarget, ImportEntry, PeFile};

pub const MAX_FORWARD_DEPTH: u32 = 16;
/// An import to bind: (name, or None for by-ordinal), ordinal, IAT slot RVA.
type WantedSymbol = (Option<String>, u16, u32);
pub const MAX_MODULES: usize = 256;

/// A module's exports when the runtime implements it (no PE file).
pub trait BuiltinModule: Send {
    /// Address of export `name`, if implemented.
    fn by_name(&self, name: &str) -> Option<u64>;
    /// Address of export `ordinal`, if implemented.
    fn by_ordinal(&self, _ordinal: u16) -> Option<u64> {
        None
    }
}

pub trait PeMapping: Send {
    fn bytes(&self) -> &[u8];
}

pub enum PeData {
    Owned(Vec<u8>),
    Mapped(Box<dyn PeMapping>),
}

impl AsRef<[u8]> for PeData {
    fn as_ref(&self) -> &[u8] {
        match self {
            PeData::Owned(bytes) => bytes,
            PeData::Mapped(mapping) => mapping.bytes(),
        }
    }
}

pub enum Source {
    Builtin(Box<dyn BuiltinModule>),
    /// The bytes of a PE image (PE32 or PE32+).
    Pe(Vec<u8>),
    PeMapped(Box<dyn PeMapping>),
}

pub trait Host {
    /// A zero-filled image reservation with writable access for linking. It is
    /// consumed by `commit` before the final protections are applied.
    type Image: AsMut<[u8]>;

    /// Opens DLL `name` (lower-case, with extension). `Ok(None)`: not found.
    fn open(&mut self, name: &str) -> Result<Option<Source>, LinkError>;
    /// Reserves `size` bytes for an image linked at `preferred`. With
    /// `fixed` the image cannot be relocated and must go exactly there (or
    /// the host fails); otherwise `preferred` is only a hint. Returns the
    /// base actually used and its writable mapping.
    fn reserve(&mut self, size: u64, preferred: u64, fixed: bool) -> Result<(u64, Self::Image), LinkError>;
    /// [`Host::reserve`], but the image must lie entirely below `max`: a
    /// 32-bit image cannot be placed at or above 4 GiB. Hosts that can place
    /// memory low override this; the default ignores `max` and delegates to
    /// [`Host::reserve`], which the linker then checks as well.
    fn reserve_below(
        &mut self,
        size: u64,
        preferred: u64,
        fixed: bool,
        max: u64,
    ) -> Result<(u64, Self::Image), LinkError> {
        let _ = max;
        self.reserve(size, preferred, fixed)
    }
    /// Resolves one import of a PE32 image to the value written into its
    /// 4-byte IAT slot. A 32-bit image cannot hold a 64-bit address, so a
    /// host may return the address of a bridge stub instead; 0 refuses the
    /// import and fails the load. `address` is the resolved export (a
    /// built-in's own entry point or a PE32 module's address). `pe32` is
    /// false for PE32+ images, whose slots keep `address` unchanged: hosts
    /// that do not bridge 32-bit code leave the default.
    fn import_thunk(&mut self, symbol: Option<&str>, ordinal: u16, address: u64, pe32: bool) -> u64 {
        let _ = (symbol, ordinal, pe32);
        address
    }
    /// Finishes the image at `base` and applies the protections (RVAs relative
    /// to `base`). Consuming the mapping ends writable access to the image.
    fn commit(&mut self, base: u64, image: Self::Image, prot: &[Protection]) -> Result<(), LinkError>;
    /// Releases an image reservation after a failed load.
    fn release(&mut self, _base: u64, _size: u64) {}

    /// Where another process already laid out `name`: the loader prefers
    /// that base so the image can be shared instead of built again.
    fn shared_base(&mut self, _name: &str) -> Option<u64> {
        None
    }
    /// Called with the fresh, zeroed reservation before layout. True when
    /// the host put `name` there already laid out and relocated for `base`
    /// (a shared image); the loader then only binds the imports.
    fn prepare(&mut self, _name: &str, _base: u64, _image: &mut [u8]) -> bool {
        false
    }
    /// `image` is laid out and relocated for `base`; imports are not bound
    /// yet. A host may offer it to later [`Host::prepare`] calls.
    fn publish(&mut self, _name: &str, _base: u64, _image: &[u8]) {}

    // TEMP load-phase timing: hosts that keep a clock return marks and
    // report how long the phase between two marks took.
    fn mark(&mut self) -> u64 {
        0
    }
    fn note(&mut self, _module: &str, _phase: &str, _start: u64, _end: u64) {}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    Image {
        module: String,
        error: ImageError,
    },
    DllNotFound {
        name: String,
        importer: String,
    },
    /// An API set contract with no host on this system.
    NoApiSetHost {
        name: String,
        importer: String,
    },
    SymbolNotFound {
        module: String,
        symbol: String,
        importer: String,
    },
    ForwarderTooDeep {
        module: String,
        symbol: String,
    },
    /// A PE32 image tried to use a PE32+ module (or the reverse): a 32-bit
    /// IAT slot cannot hold a 64-bit address.
    WidthMismatch {
        importer: String,
        module: String,
    },
    TooManyModules,
    /// The host could not provide memory.
    NoMemory,
    Host(String),
}

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LinkError::Image { module, error } => write!(f, "{module}: invalid image: {error:?}"),
            LinkError::DllNotFound { name, importer } => write!(f, "{name} (needed by {importer}) was not found"),
            LinkError::NoApiSetHost { name, importer } => {
                write!(f, "API set {name} (needed by {importer}) has no host")
            }
            LinkError::SymbolNotFound { module, symbol, importer } => {
                write!(f, "{module}!{symbol} (needed by {importer}) does not exist")
            }
            LinkError::ForwarderTooDeep { module, symbol } => {
                write!(f, "forwarder chain from {module}!{symbol} is too long or circular")
            }
            LinkError::WidthMismatch { importer, module } => {
                write!(f, "{importer} cannot import {module}: 32-bit and 64-bit images cannot be mixed")
            }
            LinkError::TooManyModules => f.write_str("too many modules"),
            LinkError::NoMemory => f.write_str("out of memory"),
            LinkError::Host(s) => f.write_str(s),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Imports are being bound (part of a cycle if seen again).
    Binding,
    Ready,
}

pub enum Kind {
    Builtin(Box<dyn BuiltinModule>),
    Pe {
        file: PeData,
        size: u32,
        entry: u32,
        is_dll: bool,
        /// A 32-bit PE32 image (4-byte thunks, low 4 GiB addresses).
        pe32: bool,
    },
}

pub struct Module {
    /// Lower-case file name (`kernel32.dll`).
    pub name: String,
    pub base: u64,
    pub kind: Kind,
    pub deps: Vec<usize>,
    pub state: State,
    /// Base relocations applied and imports bound (diagnostics).
    pub relocations: usize,
    pub imports_bound: usize,
}

impl Module {
    pub fn is_builtin(&self) -> bool {
        matches!(self.kind, Kind::Builtin(_))
    }

    /// Whether this is a 32-bit PE32 module. `None` for a built-in module,
    /// which serves both widths.
    pub fn is_pe32(&self) -> Option<bool> {
        match &self.kind {
            Kind::Pe { pe32, .. } => Some(*pe32),
            Kind::Builtin(_) => None,
        }
    }

    /// Entry point address (0 for built-in modules or no entry point).
    pub fn entry(&self) -> u64 {
        match self.kind {
            Kind::Pe { entry, .. } if entry != 0 => self.base + entry as u64,
            _ => 0,
        }
    }

    pub fn pe(&self) -> Option<PeFile<'_>> {
        match &self.kind {
            Kind::Pe { file, .. } => PeFile::parse_any(file.as_ref()).ok(),
            Kind::Builtin(_) => None,
        }
    }
}

/// Symbol reference used in errors and lookups.
#[derive(Clone, Copy, Debug)]
pub enum Symbol<'a> {
    Name(&'a str),
    Ordinal(u16),
}

impl Symbol<'_> {
    fn describe(&self) -> String {
        match self {
            Symbol::Name(n) => n.to_string(),
            Symbol::Ordinal(o) => alloc::format!("#{o}"),
        }
    }
}

/// Normalises a DLL reference: lower-case, `.dll` appended when the name
/// has no extension.
pub fn normalize(name: &str) -> String {
    let mut n = name.to_ascii_lowercase();
    if !n.contains('.') {
        n.push_str(".dll");
    }
    n
}

pub struct Linker<'s, H: Host> {
    pub host: H,
    pub modules: Vec<Module>,
    schema: Option<Schema<'s>>,
    /// (importer, imported) edges that closed a cycle.
    pub cycles: Vec<(String, String)>,
}

impl<'s, H: Host> Linker<'s, H> {
    pub fn new(host: H, schema: Option<Schema<'s>>) -> Self {
        Linker { host, modules: Vec::new(), schema, cycles: Vec::new() }
    }

    pub fn find(&self, name: &str) -> Option<usize> {
        let n = normalize(name);
        self.modules.iter().position(|m| m.name == n)
    }

    /// Resolves an API set contract to a DLL name; other names unchanged.
    fn map_name(&self, name: &str, importer: &str) -> Result<String, LinkError> {
        if apiset::is_api_set_name(name) {
            let host = self.schema.as_ref().and_then(|s| s.resolve(name, Some(importer)).ok().flatten());
            return match host {
                Some(h) => Ok(normalize(&h)),
                None => Err(LinkError::NoApiSetHost { name: normalize(name), importer: importer.to_string() }),
            };
        }
        Ok(normalize(name))
    }

    /// Rejects a PE module of a different width: a 32-bit image cannot import
    /// a 64-bit module and a 64-bit image cannot import a 32-bit one.
    /// Built-in modules are width-agnostic.
    fn check_width(&self, importer: usize, module: usize) -> Result<(), LinkError> {
        match (self.modules[importer].is_pe32(), self.modules[module].is_pe32()) {
            (Some(a), Some(b)) if a != b => Err(LinkError::WidthMismatch {
                importer: self.modules[importer].name.clone(),
                module: self.modules[module].name.clone(),
            }),
            _ => Ok(()),
        }
    }

    /// Loads the main executable from its bytes. Returns its index.
    pub fn load_executable(&mut self, name: &str, file: Vec<u8>) -> Result<usize, LinkError> {
        self.load_pe(normalize(name), PeData::Owned(file), false)
    }

    /// Loads (or finds) DLL `name` as needed by `importer`.
    pub fn load_dll(&mut self, name: &str, importer: &str) -> Result<usize, LinkError> {
        let real = self.map_name(name, importer)?;
        if let Some(i) = self.modules.iter().position(|m| m.name == real) {
            if self.modules[i].state == State::Binding {
                self.cycles.push((importer.to_string(), real));
            }
            return Ok(i);
        }
        match self.host.open(&real)? {
            None => Err(LinkError::DllNotFound { name: real, importer: importer.to_string() }),
            Some(Source::Builtin(b)) => {
                if self.modules.len() >= MAX_MODULES {
                    return Err(LinkError::TooManyModules);
                }
                self.modules.push(Module {
                    name: real,
                    base: 0,
                    kind: Kind::Builtin(b),
                    deps: Vec::new(),
                    state: State::Ready,
                    relocations: 0,
                    imports_bound: 0,
                });
                Ok(self.modules.len() - 1)
            }
            Some(Source::Pe(bytes)) => self.load_pe(real, PeData::Owned(bytes), true),
            Some(Source::PeMapped(mapping)) => self.load_pe(real, PeData::Mapped(mapping), true),
        }
    }

    fn load_pe(&mut self, name: String, file: PeData, dll: bool) -> Result<usize, LinkError> {
        let first = self.modules.len();
        let cycles = self.cycles.len();
        let result = self.load_pe_inner(name, file, dll);
        if result.is_err() {
            // A failed image, including dependencies bound back to it in a
            // cycle, must never be found by a later LoadLibrary call.
            for m in self.modules.drain(first..) {
                if let Kind::Pe { size, .. } = m.kind {
                    self.host.release(m.base, size as u64);
                }
            }
            self.cycles.truncate(cycles);
        }
        result
    }

    fn load_pe_inner(&mut self, name: String, file: PeData, dll: bool) -> Result<usize, LinkError> {
        if self.modules.len() >= MAX_MODULES {
            return Err(LinkError::TooManyModules);
        }
        let bad = |name: &str, error| LinkError::Image { module: name.to_string(), error };
        let pe = PeFile::parse_any(file.as_ref()).map_err(|e| bad(&name, e.into()))?;
        image::check(&pe, dll).map_err(|e| bad(&name, e))?;
        if dll != pe.is_dll() {
            return Err(bad(&name, ImageError::Subsystem(pe.optional().subsystem)));
        }
        let pe32 = pe.is_pe32();
        let size = pe.size_of_image();
        let prot = image::protections(&pe).map_err(|e| bad(&name, e))?;
        let m0 = self.host.mark();
        let relocatable = image::relocatable(&pe);
        let preferred = match self.host.shared_base(&name) {
            Some(b) if relocatable => b,
            _ => pe.image_base(),
        };
        // A 32-bit image must be mapped below 4 GiB; the host is told the
        // limit and the result is checked in case it cannot honour it.
        let limit = if pe32 { image::ADDRESS_LIMIT32 } else { u64::MAX };
        let (base, mut img) = if pe32 {
            self.host.reserve_below(size as u64, preferred, !relocatable, limit)?
        } else {
            self.host.reserve(size as u64, preferred, !relocatable)?
        };
        if base.checked_add(size as u64).is_none_or(|end| end > limit) {
            self.host.release(base, size as u64);
            return Err(bad(&name, ImageError::BaseTooHigh));
        }
        let m1 = self.host.mark();
        let shared = self.host.prepare(&name, base, img.as_mut());
        if !shared {
            if let Err(e) = image::layout_into(&pe, img.as_mut()) {
                self.host.release(base, size as u64);
                return Err(bad(&name, e));
            }
        }
        let m2 = self.host.mark();
        let relocations = if shared {
            0
        } else {
            match image::relocate(&pe, img.as_mut(), base) {
                Ok(n) => {
                    self.host.publish(&name, base, img.as_mut());
                    n
                }
                Err(e) => {
                    self.host.release(base, size as u64);
                    return Err(bad(&name, e));
                }
            }
        };
        let m3 = self.host.mark();
        let entry = pe.entry_point();
        let idx = self.modules.len();
        // The module is registered before its imports are bound so that a
        // cycle back to it finds it (and its exports) instead of loading it twice.
        self.modules.push(Module {
            name: name.clone(),
            base,
            kind: Kind::Pe { file: PeData::Owned(Vec::new()), size, entry, is_dll: dll, pe32 },
            deps: Vec::new(),
            state: State::Binding,
            relocations,
            imports_bound: 0,
        });
        // Collect the imports first (they borrow `file`), then move the
        // file into the module so forwarders into it can be resolved.
        let mut wanted: Vec<(String, Vec<WantedSymbol>)> = Vec::new();
        for d in pe.imports().map_err(|e| bad(&name, e.into()))? {
            let d = d.map_err(|e| bad(&name, e.into()))?;
            let mut entries = Vec::new();
            for e in d.entries() {
                match e.map_err(|e| bad(&name, e.into()))? {
                    ImportEntry::ByName { name: n, iat_rva, .. } => entries.push((Some(n.to_string()), 0, iat_rva)),
                    ImportEntry::ByOrdinal { ordinal, iat_rva } => entries.push((None, ordinal, iat_rva)),
                }
            }
            wanted.push((d.dll.to_string(), entries));
        }
        if let Kind::Pe { file: f, .. } = &mut self.modules[idx].kind {
            *f = file;
        }
        let mut bound = 0;
        for (dll_name, entries) in wanted {
            let dep = self.load_dll(&dll_name, &name)?;
            // A PE32 image may only use built-in modules and other PE32
            // modules; mixing widths would put a 64-bit address in a 32-bit
            // slot (or the reverse).
            self.check_width(idx, dep)?;
            if !self.modules[idx].deps.contains(&dep) {
                self.modules[idx].deps.push(dep);
            }
            let addresses = self.resolve_group(dep, &entries, &name)?;
            for ((symbol, ordinal, iat), addr) in entries.into_iter().zip(addresses) {
                // Only a 32-bit image needs a thunk usable by 32-bit code;
                // PE32+ writes the resolved address as before.
                let addr = if pe32 { self.host.import_thunk(symbol.as_deref(), ordinal, addr, true) } else { addr };
                if pe32 && addr == 0 {
                    // A 32-bit import the host cannot bridge must fail the
                    // load instead of becoming a null slot (an ordinal has
                    // no name, so the ordinal is what the error reports).
                    let symbol = symbol.map_or_else(|| alloc::format!("#{ordinal}"), String::from);
                    return Err(LinkError::SymbolNotFound {
                        module: self.modules[dep].name.clone(),
                        symbol,
                        importer: name.clone(),
                    });
                }
                image::write_thunk(img.as_mut(), iat, addr, pe32).ok_or_else(|| bad(&name, ImageError::TooLarge))?;
                bound += 1;
            }
        }
        let m4 = self.host.mark();
        self.host.commit(base, img, &prot)?;
        let m5 = self.host.mark();
        // Each phase on its own; "imports" includes loading the dependencies.
        self.host.note(&name, "reserve", m0, m1);
        self.host.note(&name, if shared { "shared map" } else { "layout" }, m1, m2);
        self.host.note(&name, "relocate", m2, m3);
        self.host.note(&name, "imports", m3, m4);
        self.host.note(&name, "commit", m4, m5);
        let m = &mut self.modules[idx];
        m.imports_bound = bound;
        m.state = State::Ready;
        Ok(idx)
    }

    fn resolve_group(&mut self, idx: usize, symbols: &[WantedSymbol], importer: &str) -> Result<Vec<u64>, LinkError> {
        let mut addresses = Vec::with_capacity(symbols.len());
        while addresses.len() < symbols.len() {
            if matches!(self.modules[idx].kind, Kind::Builtin(_)) {
                let (name, ordinal, _) = &symbols[addresses.len()];
                let sym = match name {
                    Some(n) => Symbol::Name(n),
                    None => Symbol::Ordinal(*ordinal),
                };
                addresses.push(self.resolve(idx, sym, importer, 0)?);
                continue;
            }
            let mut forwarded = false;
            {
                let m = &self.modules[idx];
                let Kind::Pe { file, .. } = &m.kind else { unreachable!() };
                let not_found = |sym: Symbol<'_>| LinkError::SymbolNotFound {
                    module: m.name.clone(),
                    symbol: sym.describe(),
                    importer: importer.to_string(),
                };
                let pe = PeFile::parse_any(file.as_ref())
                    .map_err(|e| LinkError::Image { module: m.name.clone(), error: e.into() })?;
                let (name, ordinal, _) = &symbols[addresses.len()];
                let first = match name {
                    Some(n) => Symbol::Name(n),
                    None => Symbol::Ordinal(*ordinal),
                };
                let exports = pe.exports().ok().flatten().ok_or_else(|| not_found(first))?;
                for (name, ordinal, _) in &symbols[addresses.len()..] {
                    let sym = match name {
                        Some(n) => Symbol::Name(n),
                        None => Symbol::Ordinal(*ordinal),
                    };
                    let e = match sym {
                        Symbol::Name(n) => exports.by_name(n),
                        Symbol::Ordinal(o) => exports.by_ordinal(o),
                    };
                    let e = e.ok().flatten().ok_or_else(|| not_found(sym))?;
                    match e.target {
                        ExportTarget::Rva(rva) => addresses.push(m.base + rva as u64),
                        ExportTarget::Forwarder { .. } => {
                            forwarded = true;
                            break;
                        }
                    }
                }
            }
            if forwarded {
                let (name, ordinal, _) = &symbols[addresses.len()];
                let sym = match name {
                    Some(n) => Symbol::Name(n),
                    None => Symbol::Ordinal(*ordinal),
                };
                addresses.push(self.resolve(idx, sym, importer, 0)?);
            }
        }
        Ok(addresses)
    }

    /// Address of `sym` exported by module `idx`, following forwarders.
    pub fn resolve(&mut self, idx: usize, sym: Symbol<'_>, importer: &str, depth: u32) -> Result<u64, LinkError> {
        let not_found = |m: &Module| LinkError::SymbolNotFound {
            module: m.name.clone(),
            symbol: sym.describe(),
            importer: importer.to_string(),
        };
        if depth > MAX_FORWARD_DEPTH {
            return Err(LinkError::ForwarderTooDeep { module: self.modules[idx].name.clone(), symbol: sym.describe() });
        }
        let m = &self.modules[idx];
        let forward = match &m.kind {
            Kind::Builtin(b) => {
                let a = match sym {
                    Symbol::Name(n) => b.by_name(n),
                    Symbol::Ordinal(o) => b.by_ordinal(o),
                };
                return a.ok_or_else(|| not_found(m));
            }
            Kind::Pe { file, .. } => {
                let pe = PeFile::parse_any(file.as_ref())
                    .map_err(|e| LinkError::Image { module: m.name.clone(), error: e.into() })?;
                let exports = pe.exports().ok().flatten().ok_or_else(|| not_found(m))?;
                let e = match sym {
                    Symbol::Name(n) => exports.by_name(n),
                    Symbol::Ordinal(o) => exports.by_ordinal(o),
                };
                let e = e.ok().flatten().ok_or_else(|| not_found(m))?;
                match e.target {
                    ExportTarget::Rva(rva) => return Ok(m.base + rva as u64),
                    ExportTarget::Forwarder { dll, name, ordinal, .. } => {
                        (dll.to_string(), name.map(|s| s.to_string()), ordinal)
                    }
                }
            }
        };
        let from = self.modules[idx].name.clone();
        let (dll, name, ordinal) = forward;
        let target = self.load_dll(&dll, &from)?;
        // A forwarder must not cross widths either.
        self.check_width(idx, target)?;
        let s = match (&name, ordinal) {
            (Some(n), _) => Symbol::Name(n),
            (None, Some(o)) => Symbol::Ordinal(o),
            (None, None) => return Err(not_found(&self.modules[idx])),
        };
        self.resolve(target, s, importer, depth + 1)
    }

    /// Initialisation order: every module after the modules it imports
    /// (depth-first post-order from `root`; an edge back into a module still
    /// on the path is skipped).
    pub fn init_order(&self, root: usize) -> Vec<usize> {
        let mut order = Vec::new();
        let mut mark = alloc::vec![0u8; self.modules.len()]; // 0 new, 1 on path, 2 done
        let mut stack: Vec<(usize, usize)> = alloc::vec![(root, 0)];
        mark[root] = 1;
        while let Some((m, i)) = stack.pop() {
            if let Some(&d) = self.modules[m].deps.get(i) {
                stack.push((m, i + 1));
                if mark[d] == 0 {
                    mark[d] = 1;
                    stack.push((d, 0));
                }
            } else {
                mark[m] = 2;
                order.push(m);
            }
        }
        order
    }
}
