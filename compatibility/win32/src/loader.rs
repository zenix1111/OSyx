//! The Windows process: loading the program and its DLLs (through
//! `osyx_pe_loader`), the built-in system DLLs, the PEB/TEB/TLS set-up, DLL
//! and TLS-callback notifications, and the run-time loader API behind
//! `LoadLibrary`, `GetProcAddress`, `GetModuleHandle` and `FreeLibrary`.
//!
//! Search order for a DLL name: the OSyx built-in system DLLs (ntdll,
//! kernel32, kernelbase, user32, gdi32, ws2_32: like Windows' KnownDLLs,
//! they cannot be replaced by a file), then the program's directory, then
//! the current directory (names matched case-insensitively).
//!
//! Windows code is never called while the loader lock is held: linking and
//! mapping happen under it, notifications (DllMain, TLS callbacks) after.

use crate::error::*;
use crate::{mem, path, teb, wow64};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::arch::global_asm;
use os_std::ipc::{Mapping, OwnedHandle};
use os_std::sync::Mutex;
use os_std::time::Instant;
use osyx_pe::PeFile;
use osyx_pe_loader::apiset::{Schema, SchemaBuilder};
use osyx_pe_loader::image::{self, Protection};
use osyx_pe_loader::link::{normalize, BuiltinModule, Host, Kind, LinkError, Linker, PeMapping, Source, Symbol};

pub const DLL_PROCESS_DETACH: u32 = 0;
pub const DLL_PROCESS_ATTACH: u32 = 1;
pub const DLL_THREAD_ATTACH: u32 = 2;
pub const DLL_THREAD_DETACH: u32 = 3;

// ---- calling Windows code ----------------------------------------------------

// win_call_on_stack(func, arg, stack_top, frame) runs `func(arg)` with the
// Windows x64 convention on another stack (16-byte aligned, 32 bytes of
// shadow space) and returns its RAX. It records where to come back in
// *frame so that win_exit_to(frame, code) can end the Windows code from any
// depth (ExitThread): it restores the callee-saved registers pushed here
// and returns `code` from win_call_on_stack.
global_asm!(
    r#"
    .global osyx_win_call_on_stack
osyx_win_call_on_stack:
    push rbp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 8
    mov r12, rcx
    mov [r12], rsp
    mov rsp, rdx
    and rsp, -16
    sub rsp, 32
    mov rcx, rsi
    call rdi
    mov rsp, [r12]
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret

    .global osyx_win_exit_to
osyx_win_exit_to:
    mov rax, rsi
    mov rsp, [rdi]
    add rsp, 8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    pop rbp
    ret
    "#
);

extern "sysv64" {
    fn osyx_win_call_on_stack(func: u64, arg: u64, stack_top: u64, frame: *mut u64) -> u64;
    fn osyx_win_exit_to(frame: *const u64, code: u64) -> !;
}

/// Per thread: where `exit_thread` returns to.
static EXIT_FRAMES: Mutex<BTreeMap<u64, usize>> = Mutex::new(BTreeMap::new());

/// Runs Windows function `func(arg)` on the stack `[.., stack_top)` until it
/// returns or the thread calls ExitThread; returns its result.
pub fn run_on_stack(func: u64, arg: u64, stack_top: u64) -> u64 {
    let frame = Box::into_raw(Box::new(0u64));
    let tid = os_sys::gettid();
    EXIT_FRAMES.lock().unwrap().insert(tid, frame as usize);
    // SAFETY: `func` is Windows code from a mapped image (its entry point
    // or a thread start routine); the stack is a fresh mapping owned by
    // this thread; `frame` lives until after the call.
    let r = unsafe { osyx_win_call_on_stack(func, arg, stack_top, frame) };
    EXIT_FRAMES.lock().unwrap().remove(&tid);
    // SAFETY: allocated above, no longer referenced.
    drop(unsafe { Box::from_raw(frame) });
    r
}

/// The Windows part of a new thread: its start routine and the DLL
/// notifications around it.
pub struct ThreadStart {
    pub start: u64,
    pub param: u64,
}

/// Runs on the thread's Windows stack: DllMain (and the TLS callbacks) must
/// see the stack the thread is going to use, as on Windows.
extern "win64" fn thread_main(env: *const ThreadStart) -> u64 {
    // SAFETY: `env` points into `run_thread`'s frame, which outlives this call.
    let env = unsafe { &*env };
    notify_threads(DLL_THREAD_ATTACH);
    // SAFETY: a thread start routine of a mapped image, Windows x64 ABI.
    let f: extern "win64" fn(u64) -> u32 = unsafe { core::mem::transmute(env.start as usize) };
    let code = f(env.param);
    crate::fls::thread_exit();
    crate::oleaut32::thread_exit();
    notify_threads(DLL_THREAD_DETACH);
    code as u64
}

/// Runs a thread's Windows part on the stack `[.., stack_top)` it was given.
pub fn run_thread(env: &ThreadStart, stack_top: u64) -> u64 {
    run_on_stack(thread_main as *const () as u64, env as *const ThreadStart as u64, stack_top)
}

/// The DLLs waiting for their first DllMain: (base, entry, TLS callbacks,
/// is a DLL).
pub type AttachList = Vec<(u64, u64, Vec<u64>, bool)>;

/// Runs the DLL_PROCESS_ATTACH delivery on the main thread's Windows stack.
/// Returns false if a DllMain refused.
pub fn run_attach(todo: &AttachList, stack_top: u64) -> bool {
    run_on_stack(attach_on_stack as *const () as u64, todo as *const AttachList as u64, stack_top) != 0
}

extern "win64" fn attach_on_stack(todo: *const AttachList) -> u64 {
    // SAFETY: `todo` points into `run_attach`'s caller, alive across the call.
    deliver_attach(unsafe { &*todo }) as u64
}


pub fn exit_thread(code: u32) -> ! {
    crate::oleaut32::thread_exit();
    let frame = EXIT_FRAMES.lock().unwrap().get(&os_sys::gettid()).copied();
    match frame {
        // SAFETY: the frame belongs to the run_on_stack call that is still
        // active on this thread below the current Windows frames.
        Some(f) => unsafe { osyx_win_exit_to(f as *const u64, code as u64) },
        None => os_sys::thread_exit(code as i32, core::ptr::null()),
    }
}

type DllMain = extern "win64" fn(u64, u32, u64) -> i32;
type TlsCallback = extern "win64" fn(u64, u32, u64);

// ---- built-in DLLs -------------------------------------------------------------

pub struct Builtin {
    pub name: &'static str,
    by_name: Vec<(&'static str, u64)>,
    by_ordinal: Vec<(u16, u64)>,
    /// The HMODULE programs see: a page starting with "MZ".
    pub base: u64,
}

struct BuiltinRef(Arc<Builtin>);

impl BuiltinModule for BuiltinRef {
    fn by_name(&self, name: &str) -> Option<u64> {
        let i = self.0.by_name.binary_search_by(|(n, _)| (*n).cmp(name)).ok()?;
        Some(self.0.by_name[i].1)
    }
    fn by_ordinal(&self, o: u16) -> Option<u64> {
        let i = self.0.by_ordinal.binary_search_by_key(&o, |(ordinal, _)| *ordinal).ok()?;
        Some(self.0.by_ordinal[i].1)
    }
}

fn builtin(name: &'static str, mut exports: Vec<(&'static str, u64)>, mut ordinals: Vec<(u16, u64)>) -> Arc<Builtin> {
    exports.sort_by(|a, b| a.0.cmp(b.0));
    exports.dedup_by(|next, previous| {
        if next.0 != previous.0 { return false; }
        previous.1 = next.1;
        true
    });
    ordinals.sort_by_key(|(ordinal, _)| *ordinal);
    ordinals.dedup_by(|next, previous| {
        if next.0 != previous.0 { return false; }
        previous.1 = next.1;
        true
    });
    let base = mem::alloc_pages(mem::PAGE, mem::Prot::ReadWrite).expect("memory for a module handle");
    // SAFETY: a fresh page.
    unsafe { core::ptr::copy_nonoverlapping(b"MZ".as_ptr(), base as *mut u8, 2) };
    let _ = mem::protect(base, mem::PAGE, mem::Prot::ReadOnly);
    Arc::new(Builtin { name, by_name: exports, by_ordinal: ordinals, base })
}

fn builtins() -> Vec<Arc<Builtin>> {
    let k32 = crate::kernel32::exports();
    alloc::vec![
        builtin("ntdll.dll", crate::ntdll::exports(), Vec::new()),
        builtin("kernel32.dll", k32.clone(), Vec::new()),
        builtin("kernelbase.dll", k32, Vec::new()),
        builtin("user32.dll", [crate::user32::exports(), crate::winsta::exports()].concat(), Vec::new()),
        builtin("gdi32.dll", crate::user32::gdi_exports(), Vec::new()),
        builtin("ws2_32.dll", crate::ws2_32::exports(), crate::ws2_32::ordinals()),
        builtin("wsock32.dll", crate::ws2_32::exports(), crate::ws2_32::legacy_ordinals()),
        builtin("setupapi.dll", crate::setupapi::exports(), Vec::new()),
        builtin("iphlpapi.dll", crate::iphlpapi::exports(), Vec::new()),
        builtin("version.dll", crate::version::exports(), Vec::new()),
        builtin("psapi.dll", crate::psapi::exports(), Vec::new()),
        builtin(
            "advapi32.dll",
            [crate::security::exports(), crate::tokens::exports(), crate::objsec::exports(), crate::eventlog::exports(), crate::registry::exports(), crate::etw::exports(), crate::credman::exports(), crate::accounts::exports(), crate::capi::exports(), crate::cryptbase::exports()].concat(),
            Vec::new()
        ),
        builtin("shlwapi.dll", crate::shlwapi::exports(), crate::shlwapi::ordinals()),
        // ole32's COM entry points live in combase on Windows.
        builtin("combase.dll", [crate::shlwapi::combase_exports(), crate::ole32::exports()].concat(), Vec::new()),
        builtin("ucrtbase.dll", crate::ucrt::exports(), Vec::new()),
        builtin("shell32.dll", [crate::shell32::exports(), crate::commdlg::shell_exports()].concat(), crate::shell32::ordinals()),
        builtin("comdlg32.dll", crate::commdlg::exports(), Vec::new()),
        builtin("ole32.dll", crate::ole32::exports(), Vec::new()),
        builtin("winmm.dll", crate::winmm::exports(), Vec::new()),
        builtin("oleaut32.dll", crate::oleaut32::exports(), crate::oleaut32::ordinals()),
        builtin("userenv.dll", crate::userenv::exports(), Vec::new()),
        builtin("dbghelp.dll", crate::dbghelp::exports(), Vec::new()),
        builtin("crypt32.dll", crate::crypt32::exports(), Vec::new()),
        builtin("cryptbase.dll", crate::cryptbase::exports(), Vec::new()),
        builtin("rpcrt4.dll", crate::minordlls::rpcrt4_exports(), Vec::new()),
        builtin("cfgmgr32.dll", crate::minordlls::cfgmgr32_exports(), Vec::new()),
        builtin("ktmw32.dll", crate::minordlls::ktmw32_exports(), Vec::new()),
        builtin("windowscodecs.dll", crate::minordlls::windowscodecs_exports(), Vec::new()),
        builtin("bcryptprimitives.dll", crate::minordlls::bcryptprimitives_exports(), Vec::new()),
        builtin("shcore.dll", crate::minordlls::shcore_exports(), Vec::new()),
        builtin("uxtheme.dll", crate::minordlls::uxtheme_exports(), Vec::new()),
        builtin("avrt.dll", crate::minordlls::avrt_exports(), Vec::new()),
        builtin("propsys.dll", crate::propsys::exports(), Vec::new()),
        builtin("dwmapi.dll", crate::dwmapi::exports(), Vec::new()),
        builtin("imm32.dll", crate::dwmapi::imm32_exports(), Vec::new()),
        builtin("wtsapi32.dll", crate::dwmapi::wtsapi32_exports(), Vec::new()),
        builtin("d3d11.dll", crate::dwmapi::d3d11_exports(), Vec::new()),
        builtin("dwrite.dll", crate::dwrite::exports(), Vec::new()),
        builtin("dnsapi.dll", crate::dwmapi::dnsapi_exports(), Vec::new()),
        builtin("wininet.dll", crate::minordlls::wininet_exports(), Vec::new()),
        builtin("wintrust.dll", crate::minordlls::wintrust_exports(), Vec::new()),
        builtin("dxgi.dll", crate::dwmapi::dxgi_exports(), Vec::new()),
        builtin("d3dcompiler_47.dll", crate::dwmapi::d3dcompiler_exports(), Vec::new()),
    ]
}

/// The API set contracts OSyx implements, mapped to its built-in DLLs.
/// (A real Windows schema maps hundreds more to DLLs OSyx does not have;
/// imports through those fail with "no host".)
fn schema() -> Vec<u8> {
    let mut b = SchemaBuilder::new();
    b.add("api-ms-win-core-version-l1-1-1", "version.dll", &[]).expect("version contract");
    b.add("api-ms-win-security-base-l1-1-0", "advapi32.dll", &[]).expect("security contract");
    let k32 = [
        "api-ms-win-core-psapi-l1-1-0",
        "api-ms-win-core-synch-l1-1-0",
        "api-ms-win-core-processthreads-l1-1-3",
        "api-ms-win-core-synch-l1-2-1",
        "api-ms-win-core-file-l1-2-4",
        "api-ms-win-core-file-l2-1-4",
        "api-ms-win-core-handle-l1-1-0",
        "api-ms-win-core-heap-l1-2-0",
        "api-ms-win-core-memory-l1-1-8",
        "api-ms-win-core-libraryloader-l1-2-3",
        "api-ms-win-core-sysinfo-l1-2-6",
        "api-ms-win-core-errorhandling-l1-1-3",
        "api-ms-win-core-console-l1-2-2",
        "api-ms-win-core-debug-l1-1-2",
        "api-ms-win-core-profile-l1-1-0",
        "api-ms-win-core-string-l1-1-0",
        "api-ms-win-core-processenvironment-l1-2-0",
        "api-ms-win-core-timezone-l1-1-1",
        "api-ms-win-core-datetime-l1-1-2",
        "api-ms-win-core-fibers-l1-1-1",
        "api-ms-win-core-util-l1-1-1",
        // Older revisions mozglue imports (kernelbase hosts them on Windows).
        "api-ms-win-core-file-l1-1-0",
        "api-ms-win-core-heap-l2-1-0",
        "api-ms-win-core-interlocked-l1-1-0",
        "api-ms-win-core-localization-l1-2-0",
        "api-ms-win-core-processenvironment-l1-1-0",
        "api-ms-win-core-realtime-l1-1-1",
        "api-ms-win-core-sysinfo-l1-1-0",
    ];
    for c in k32 {
        b.add(c, "kernel32.dll", &[("kernel32.dll", "kernelbase.dll")]).expect("valid contract name");
    }
    b.add("api-ms-win-core-rtlsupport-l1-2-0", "ntdll.dll", &[]).expect("valid contract name");
    b.add("api-ms-win-shcore-scaling-l1-1-1", "shcore.dll", &[]).expect("valid contract name");
    // The Windows 7 "downlevel" contracts that programs still import.
    b.add("api-ms-win-downlevel-shell32-l1-1-0", "shell32.dll", &[]).expect("valid contract name");
    b.add("api-ms-win-core-path-l1-1-0", "kernelbase.dll", &[]).expect("valid contract name");
    b.add("api-ms-win-core-rtlsupport-l1-1-0", "ntdll.dll", &[]).expect("valid contract name");
    b.add("api-ms-win-core-registry-l1-1-0", "advapi32.dll", &[]).expect("valid contract name");
    b.add("api-ms-win-core-winrt-l1-1-0", "combase.dll", &[]).expect("valid contract name");
    b.add("api-ms-win-core-winrt-string-l1-1-0", "combase.dll", &[]).expect("valid contract name");
    b.add("ext-ms-win-ntuser-window-l1-1-4", "user32.dll", &[]).expect("valid contract name");
    b.add("ext-ms-win-gdi-dc-l1-2-0", "gdi32.dll", &[]).expect("valid contract name");
    // The Universal C Runtime.
    for c in ["runtime", "heap", "string", "convert", "stdio", "locale", "math", "environment", "filesystem", "time", "utility", "multibyte"] {
        b.add(&alloc::format!("api-ms-win-crt-{c}-l1-1-0"), "ucrtbase.dll", &[]).expect("valid contract name");
    }
    b.build()
}

/// Reports the actual compiled export tables and API-set schema, for
/// dependency auditing. This does not claim full semantics for an API.
pub fn print_capabilities() {
    for module in builtins() {
        for (name, _) in &module.by_name { os_std::println!("WIN_EXPORT {} {}", module.name, name); }
        for (ordinal, _) in &module.by_ordinal { os_std::println!("WIN_ORDINAL {} #{}", module.name, ordinal); }
    }
    let ns = schema();
    if let Ok(s) = Schema::parse(&ns) {
        for i in 0..s.len() {
            if let Ok(name) = s.name(i) {
                if let Ok(Some(host)) = s.resolve(&name, None) { os_std::println!("WIN_APISET {} {}", name, host); }
            }
        }
    }
}

// ---- the host -------------------------------------------------------------------

struct Image {
    base: u64,
    size: u64,
}

struct WritableImage {
    base: u64,
    size: usize,
}

impl AsMut<[u8]> for WritableImage {
    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: `reserve` returns this mapping only for its live, writable
        // reservation, and `commit` consumes it before changing protections.
        unsafe { core::slice::from_raw_parts_mut(self.base as *mut u8, self.size) }
    }
}

struct WinHost {
    builtins: Vec<Arc<Builtin>>,
    /// OSyx directories searched for DLL files.
    search: Vec<String>,
    /// LoadLibrary with a path: (normalised name, OSyx path).
    explicit: Option<(String, String)>,
    images: Vec<Image>,
    /// When each reservation was made, by base, to time image layout.
    starts: Vec<(u64, Instant)>,
    /// OSyx paths of the DLL files loaded, by module name.
    paths: BTreeMap<String, String>,
    /// The 32-bit bridge, which turns 64-bit addresses into stubs that
    /// 32-bit code can call. None when it could not be created: PE32+
    /// programs then run as before, and a PE32 import fails to bind.
    bridge: Option<wow64::Bridge>,
}

struct FileView {
    mapping: Mapping,
    len: usize,
}

impl PeMapping for FileView {
    fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping outlives the returned slice and is read-only.
        unsafe { core::slice::from_raw_parts(self.mapping.as_ptr(), self.len) }
    }
}

fn map_pe(p: &str) -> Result<Option<FileView>, LinkError> {
    let started = Instant::now();
    let file = os_std::fs::File::open(p).map_err(|e| LinkError::Host(alloc::format!("{p}: {e}")))?;
    let len = file.metadata().map_err(|e| LinkError::Host(alloc::format!("{p}: {e}")))?.len();
    let section = match os_sys::filemap_create(file.handle(), len, false) {
        Ok(h) => {
            // SAFETY: a fresh section handle owned by this guard.
            unsafe { OwnedHandle::from_raw(h) }
        }
        Err(os_sys::Errno::NotSupported) => return Ok(None),
        Err(e) => return Err(LinkError::Host(alloc::format!("{p}: file mapping: {e:?}"))),
    };
    let elapsed = started.elapsed().as_millis();
    if elapsed >= 50 {
        os_std::eprintln!("winrun: mapped {p} ({} KiB) in {} ms", len >> 10, elapsed);
    }
    let ptr = match os_sys::filemap_map(section.raw(), 0, len, false) {
        Ok(ptr) => ptr,
        Err(os_sys::Errno::NotSupported) => return Ok(None),
        Err(e) => return Err(LinkError::Host(alloc::format!("{p}: file mapping: {e:?}"))),
    };
    // SAFETY: this is a new mapping of `len` bytes with no other owner.
    let mapping = unsafe { Mapping::from_raw(ptr, len as usize) };
    Ok(Some(FileView { mapping, len: len as usize }))
}

impl WinHost {
    /// The host for `winrun`. `bridge` is the 32-bit bridge when the caller
    /// has one; it is only used by PE32 images.
    fn new(search: Vec<String>, bridge: Option<wow64::Bridge>) -> WinHost {
        WinHost {
            builtins: builtins(),
            search,
            explicit: None,
            images: Vec::new(),
            starts: Vec::new(),
            paths: BTreeMap::new(),
            bridge,
        }
    }

    /// Records a successful reservation and returns its writable mapping.
    fn adopt(&mut self, base: u64, size: u64) -> (u64, WritableImage) {
        self.images.push(Image { base, size });
        self.starts.push((base, Instant::now()));
        (base, WritableImage { base, size: size as usize })
    }

    /// The file a PE module was loaded from, opened again to identify it to
    /// the kernel's shared image cache.
    fn image_file(&self, name: &str) -> Option<os_std::fs::File> {
        os_std::fs::File::open(self.paths.get(name)?).ok()
    }

    /// The Windows path of a module (built-ins: the system directory).
    fn file_name(&self, name: &str) -> String {
        self.paths.get(name).map_or_else(|| alloc::format!("C:\\Windows\\OSyx\\{name}"), |p| path::to_windows(p))
    }
}

impl Host for WinHost {
    type Image = WritableImage;

    fn open(&mut self, name: &str) -> Result<Option<Source>, LinkError> {
        if let Some(b) = self.builtins.iter().find(|b| b.name == name) {
            return Ok(Some(Source::Builtin(Box::new(BuiltinRef(b.clone())))));
        }
        let mut candidates: Vec<String> = Vec::new();
        if let Some((n, p)) = &self.explicit {
            if n == name {
                candidates.push(p.clone());
            }
        }
        for d in &self.search {
            candidates.push(alloc::format!("{}/{}", d.trim_end_matches('/'), name));
        }
        for c in candidates {
            if let Ok((p, true)) = path::resolve(&c) {
                let source = match map_pe(&p)? {
                    Some(view) => Source::PeMapped(Box::new(view)),
                    None => match os_std::fs::read(&p) {
                        Ok(bytes) => Source::Pe(bytes),
                        Err(e) => return Err(LinkError::Host(alloc::format!("{p}: {e}"))),
                    },
                };
                self.paths.insert(String::from(name), p);
                return Ok(Some(source));
            }
        }
        Ok(None)
    }

    fn reserve(&mut self, size: u64, preferred: u64, fixed: bool) -> Result<(u64, Self::Image), LinkError> {
        let base = if fixed {
            mem::alloc_fixed(preferred, size as usize, mem::Prot::ReadWrite)
        } else {
            let at_preferred = if preferred == 0 {
                None
            } else {
                mem::alloc_fixed(preferred, size as usize, mem::Prot::ReadWrite)
            };
            at_preferred.or_else(|| mem::alloc_pages(size as usize, mem::Prot::ReadWrite))
        };
        let base = base.ok_or(LinkError::NoMemory)?;
        self.images.push(Image { base, size });
        self.starts.push((base, Instant::now()));
        Ok((base, WritableImage { base, size: size as usize }))
    }

    /// A 32-bit image must lie entirely below `max` (4 GiB): its code can
    /// address nothing above that. The preferred base is tried first; a
    /// fallback allocation is kept only when it fits, and released
    /// otherwise, because the linker would reject it and leak the pages.
    fn reserve_below(
        &mut self,
        size: u64,
        preferred: u64,
        fixed: bool,
        max: u64,
    ) -> Result<(u64, Self::Image), LinkError> {
        let fits = |base: u64| base.checked_add(size).is_some_and(|end| end <= max);
        if fixed {
            // No relocations: only the linked base is acceptable.
            if !fits(preferred) {
                return Err(LinkError::NoMemory);
            }
            let base = mem::alloc_fixed(preferred, size as usize, mem::Prot::ReadWrite).ok_or(LinkError::NoMemory)?;
            return Ok(self.adopt(base, size));
        }
        if preferred != 0 && fits(preferred) {
            if let Some(base) = mem::alloc_fixed(preferred, size as usize, mem::Prot::ReadWrite) {
                if fits(base) {
                    return Ok(self.adopt(base, size));
                }
                mem::free_pages(base, size as usize);
            }
        }
        let base = mem::alloc_pages(size as usize, mem::Prot::ReadWrite).ok_or(LinkError::NoMemory)?;
        if !fits(base) {
            mem::free_pages(base, size as usize);
            return Err(LinkError::NoMemory);
        }
        Ok(self.adopt(base, size))
    }

    fn import_thunk(&mut self, symbol: Option<&str>, _ordinal: u16, address: u64, pe32: bool) -> u64 {
        // PE32+ slots hold the resolved address itself.
        if !pe32 {
            return address;
        }
        // A by-ordinal import has no name to bridge; report it as unbound.
        let (Some(symbol), Some(bridge)) = (symbol, self.bridge.as_mut()) else { return 0 };
        bridge.import(symbol, address).map_or(0, u64::from)
    }

    fn commit(&mut self, base: u64, _image: Self::Image, prot: &[Protection]) -> Result<(), LinkError> {
        if let Some(i) = self.starts.iter().position(|(b, _)| *b == base) {
            let (_, started) = self.starts.remove(i);
            let elapsed = started.elapsed().as_millis();
            if elapsed >= 50 {
                let size = self.images.iter().find(|i| i.base == base).map_or(0, |i| i.size);
                os_std::eprintln!("winrun: image {} KiB laid out in {} ms", size >> 10, elapsed);
            }
        }
        for p in prot {
            let m = match (p.write, p.execute) {
                (true, false) => mem::Prot::ReadWrite,
                (false, true) => mem::Prot::ExecuteRead,
                (false, false) => mem::Prot::ReadOnly,
                (true, true) => return Err(LinkError::Host(String::from("writable code section"))),
            };
            if m != mem::Prot::ReadWrite {
                mem::protect(base + p.rva as u64, p.size as usize, m)
                    .map_err(|e| LinkError::Host(alloc::format!("protect: {e:?}")))?;
            }
        }
        Ok(())
    }

    fn release(&mut self, base: u64, size: u64) {
        mem::free_pages(base, size as usize);
        self.images.retain(|image| image.base != base);
    }

    fn shared_base(&mut self, name: &str) -> Option<u64> {
        let file = self.image_file(name)?;
        os_sys::image_query(file.handle()).ok()
    }

    fn prepare(&mut self, name: &str, base: u64, image: &mut [u8]) -> bool {
        let size = image.len() as u64;
        // `prof` runs: where each module sits, for the profiler's user samples.
        if os_std::env::var("OSYX_WINRUN_MODULES").is_ok_and(|v| v == "1") {
            os_std::eprintln!("winrun: module {name} base={base:#x} size={size:#x}");
        }
        if self.image_file(name).is_some_and(|f| os_sys::image_map(f.handle(), base, size).is_ok()) {
            return true;
        }
        // Warm the destination in bounded runs: mapping the whole reservation
        // in one syscall would hold the kernel entry lock for most of a
        // second on a large image (xul.dll is ~170 MiB) and freeze every
        // other process. A small run keeps each hold short while still
        // avoiding one page fault per image page during layout.
        const WARM_RUN: u64 = 2 * 1024 * 1024;
        let mut at = 0;
        while at < size {
            let len = (size - at).min(WARM_RUN) as usize;
            // SAFETY: `base + at` is inside the fresh writable reservation.
            unsafe { let _ = os_sys::prefault((base + at) as *mut u8, len); };
            at += len as u64;
        }
        false
    }

    fn publish(&mut self, name: &str, base: u64, image: &[u8]) {
        if let Some(file) = self.image_file(name) {
            // Not supported by older kernels, or already published: either
            // way this process simply keeps its private copy.
            let _ = os_sys::image_publish(file.handle(), base, image.len() as u64);
        }
    }

    fn mark(&mut self) -> u64 {
        Instant::now().as_nanos_since_boot()
    }

    fn note(&mut self, module: &str, phase: &str, start: u64, end: u64) {
        let ns = end.saturating_sub(start);
        if ns >= 20_000_000 {
            os_std::eprintln!("winrun: {module} {phase} {} ms", ns / 1_000_000);
        }
    }
}

// ---- loader state --------------------------------------------------------------

struct TlsModule {
    template: Vec<u8>,
    zero_fill: usize,
}

struct ModState {
    /// Loader entry in the PEB lists (0 for built-ins).
    ldr: u64,
    refs: u32,
    attached: bool,
    tls_callbacks: Vec<u64>,
}

struct Loader {
    linker: Linker<'static, WinHost>,
    exe: usize,
    state: Vec<ModState>,
    tls: Vec<TlsModule>,
}

static LOADER: Mutex<Option<Loader>> = Mutex::new(None);

fn with<R>(f: impl FnOnce(&mut Loader) -> R) -> R {
    let mut g = LOADER.lock().unwrap();
    f(g.as_mut().expect("loader initialised"))
}

/// HMODULE of module `i`: its image base, or the built-in's handle page.
fn module_handle(l: &Loader, i: usize) -> u64 {
    let m = &l.linker.modules[i];
    match &m.kind {
        Kind::Builtin(_) => l.linker.host.builtins.iter().find(|b| b.name == m.name).map_or(0, |b| b.base),
        Kind::Pe { .. } => m.base,
    }
}

fn module_by_handle(l: &Loader, h: u64) -> Option<usize> {
    (0..l.linker.modules.len()).find(|&i| module_handle(l, i) == h)
}

/// Registers modules that were just linked: PEB loader entries, TLS slots.
/// Returns the notifications to deliver (outside the lock), in init order.
fn register_new(l: &mut Loader, root: usize) -> Vec<(u64, u64, Vec<u64>, bool)> {
    let order = l.linker.init_order(root);
    while l.state.len() < l.linker.modules.len() {
        l.state.push(ModState { ldr: 0, refs: 0, attached: false, tls_callbacks: Vec::new() });
    }
    let mut todo = Vec::new();
    for i in order {
        if l.state[i].attached {
            continue;
        }
        l.state[i].attached = true;
        let m = &l.linker.modules[i];
        let Kind::Pe { file, size, is_dll, .. } = &m.kind else { continue };
        let (base, size, is_dll) = (m.base, *size, *is_dll);
        let full = l.linker.host.file_name(&m.name);
        let entry = if is_dll { m.entry() } else { 0 };
        l.state[i].ldr = teb::add_ldr_entry(base, m.entry(), size, &full, &m.name);
        let Ok(pe) = PeFile::parse(file.as_ref()) else { continue };
        if let Ok(Some(tls)) = pe.tls() {
            let index = l.tls.len() as u32;
            // SAFETY: the TLS directory lies in the mapped image (validated
            // by the parser against SizeOfImage); the index slot is in a
            // writable data section.
            unsafe {
                let start = base + tls.raw_data_start_rva as u64;
                let len = tls.raw_data_end_rva.saturating_sub(tls.raw_data_start_rva) as usize;
                let template = core::slice::from_raw_parts(start as *const u8, len).to_vec();
                l.tls.push(TlsModule { template, zero_fill: tls.size_of_zero_fill as usize });
                if tls.index_rva != 0 {
                    core::ptr::write_unaligned((base + tls.index_rva as u64) as *mut u32, index);
                }
            }
            let cbs: Vec<u64> = tls.callbacks().filter_map(|c| c.ok()).map(|rva| base + rva as u64).collect();
            l.state[i].tls_callbacks = cbs;
        }
        todo.push((base, entry, l.state[i].tls_callbacks.clone(), is_dll));
    }
    todo
}

/// Delivers DLL_PROCESS_ATTACH (TLS callbacks, then DllMain). Returns false
/// if a DllMain refused.
fn deliver_attach(todo: &[(u64, u64, Vec<u64>, bool)]) -> bool {
    for (base, entry, cbs, _) in todo {
        for &cb in cbs {
            // SAFETY: a TLS callback of a mapped image.
            let f: TlsCallback = unsafe { core::mem::transmute(cb as usize) };
            f(*base, DLL_PROCESS_ATTACH, 0);
        }
        if *entry != 0 {
            // SAFETY: the entry point of a mapped DLL image.
            let f: DllMain = unsafe { core::mem::transmute(*entry as usize) };
            let ok = f(*base, DLL_PROCESS_ATTACH, 0);
            if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
                let name = where_is(*entry).map_or_else(|| alloc::format!("{base:#x}"), |(n, _)| n);
                os_std::eprintln!("winrun: DllMain(PROCESS_ATTACH) {name} = {ok}");
            }
            if ok == 0 {
                return false;
            }
        }
    }
    true
}

/// Slots reserved in every thread's TLS array. A program loads its DLLs over
/// time (Firefox loads NSS's modules lazily), so the array is sized once and
/// both thread creation and later loads fill it in.
const TLS_SLOTS: usize = 256;

/// TLS blocks for the calling thread (call after `teb::install`).
///
/// A module loaded later needs a block too, and the thread may already have
/// data in its earlier blocks: Windows keeps those, so this only adds the
/// missing ones. Rebuilding the array would silently wipe every thread-local
/// the program had stored (jemalloc's thread cache, NSS's, Gecko's).
pub fn setup_thread_tls(teb_addr: u64) {
    with(|l| {
        if l.tls.is_empty() {
            return;
        }
        // SAFETY: `teb_addr` is a TEB; its TLS pointer is either 0 or an array
        // this function allocated with TLS_SLOTS entries.
        let existing = unsafe { teb::get::<u64>(teb_addr, teb::TEB_TLS_POINTER) };
        let array: &'static mut [u64] = if existing == 0 {
            let a = Vec::leak(alloc::vec![0u64; TLS_SLOTS]);
            // SAFETY: as above.
            unsafe { teb::put(teb_addr, teb::TEB_TLS_POINTER, a.as_mut_ptr() as u64) };
            a
        } else {
            // SAFETY: as above.
            unsafe { core::slice::from_raw_parts_mut(existing as *mut u64, TLS_SLOTS) }
        };
        for (i, t) in l.tls.iter().enumerate() {
            if i >= TLS_SLOTS || array[i] != 0 {
                continue;
            }
            let mut b = t.template.clone();
            b.resize(t.template.len() + t.zero_fill, 0);
            // Leaked deliberately: the block lives as long as the thread.
            array[i] = Vec::leak(b).as_mut_ptr() as u64;
        }
    });
}

/// DLL_THREAD_ATTACH / DETACH for the calling thread (TLS callbacks and
/// DllMain of every attached DLL, in load order).
///
/// This is Windows code: it must be called with the stack pointer inside the
/// thread's Windows stack (`run_thread`, `run_main`), because a function
/// prologue there probes `[gs:0x10]`/`[gs:0x08]` and a mismatch faults at the
/// stack limit instead of growing the stack.
pub fn notify_threads(reason: u32) {
    let list: Vec<(u64, u64, Vec<u64>)> = with(|l| {
        (0..l.linker.modules.len())
            .filter(|&i| l.state.get(i).is_some_and(|s| s.attached))
            .filter_map(|i| {
                let m = &l.linker.modules[i];
                match &m.kind {
                    Kind::Pe { is_dll, .. } => {
                        Some((m.base, if *is_dll { m.entry() } else { 0 }, l.state[i].tls_callbacks.clone()))
                    }
                    Kind::Builtin(_) => None,
                }
            })
            .collect()
    });
    for (base, entry, cbs) in list {
        for cb in cbs {
            // SAFETY: as in `deliver_attach`.
            let f: TlsCallback = unsafe { core::mem::transmute(cb as usize) };
            f(base, reason, 0);
        }
        if entry != 0 {
            // SAFETY: as in `deliver_attach`.
            let f: DllMain = unsafe { core::mem::transmute(entry as usize) };
            f(base, reason, 0);
        }
    }
}

/// DLL_PROCESS_DETACH for every attached DLL, in reverse order (ExitProcess).
pub fn notify_process_detach() {
    let list: Vec<(u64, u64, Vec<u64>)> = match LOADER.try_lock() {
        Ok(mut g) => match g.as_mut() {
            Some(l) => {
                let order = l.linker.init_order(l.exe);
                order
                    .into_iter()
                    .rev()
                    .filter_map(|i| {
                        let m = &l.linker.modules[i];
                        match &m.kind {
                            Kind::Pe { is_dll, .. } if l.state.get(i).is_some_and(|s| s.attached) => {
                                Some((m.base, if *is_dll { m.entry() } else { 0 }, l.state[i].tls_callbacks.clone()))
                            }
                            _ => None,
                        }
                    })
                    .collect()
            }
            None => return,
        },
        Err(_) => return,
    };
    for (base, entry, cbs) in list {
        for cb in cbs {
            // SAFETY: as in `deliver_attach`.
            let f: TlsCallback = unsafe { core::mem::transmute(cb as usize) };
            f(base, DLL_PROCESS_DETACH, 1);
        }
        if entry != 0 {
            // SAFETY: as in `deliver_attach`.
            let f: DllMain = unsafe { core::mem::transmute(entry as usize) };
            f(base, DLL_PROCESS_DETACH, 1);
        }
    }
}

// ---- process start --------------------------------------------------------------

pub struct Started {
    pub entry: u64,
    pub stack_top: u64,
    pub stack_limit: u64,
    pub peb: u64,
}

/// Loads `exe_path` (an OSyx path) and everything it imports, builds the
/// process environment and the main thread's TEB, and runs the DLL
/// initialisation. Returns where to start the program.
pub fn start(exe_path: &str, command_line: &str, environment: &[String]) -> Result<Started, String> {
    let bytes = os_std::fs::read(exe_path).map_err(|e| alloc::format!("{exe_path}: {e}"))?;
    let pe = PeFile::parse(&bytes).map_err(|e| alloc::format!("{exe_path}: not a valid PE32+ image: {e}"))?;
    let stack_size = (pe.optional().size_of_stack_reserve as usize).clamp(256 << 10, 64 << 20);
    crate::kernel32::EXE_STACK_RESERVE.store(stack_size, core::sync::atomic::Ordering::Relaxed);
    let exe_dir = exe_path.rsplit_once('/').map_or("/", |(d, _)| if d.is_empty() { "/" } else { d }).to_string();
    let exe_name = exe_path.rsplit('/').next().unwrap_or(exe_path).to_string();
    let cwd = os_std::env::current_dir().map(|p| p.as_str().to_string()).unwrap_or_else(|_| String::from("/"));
    let schema_bytes: &'static [u8] = Vec::leak(schema());
    let schema = Schema::parse(schema_bytes).map_err(|e| alloc::format!("API set schema: {e:?}"))?;
    let host = WinHost::new(
        alloc::vec![exe_dir.clone(), cwd.clone()],
        // Built here so a PE32 module loaded at run time can bind imports;
        // a PE32+ program runs as before when the bridge is unavailable.
        wow64::Bridge::new().ok(),
    );
    let mut linker = Linker::new(host, Some(schema));
    // Known before loading so the image can be shared with other processes.
    linker.host.paths.insert(normalize(&exe_name), String::from(exe_path));
    let exe = linker.load_executable(&exe_name, bytes).map_err(|e| alloc::format!("cannot load {exe_name}: {e}"))?;
    let exe_module = linker.modules[exe].name.clone();
    linker.host.paths.insert(exe_module, String::from(exe_path));
    let image_base = linker.modules[exe].base;
    let entry = linker.modules[exe].entry();
    // Process environment.
    let heap = crate::kernel32::process_heap();
    let win_path = path::to_windows(exe_path);
    teb::create_peb(&teb::ProcessInfo {
        image_base,
        image_path: &win_path,
        command_line,
        current_dir: &path::to_windows(&cwd),
        environment,
        heap,
    });
    let stack = mem::alloc_stack(stack_size).ok_or("no memory for the main thread's stack")?;
    let stack_top = stack + stack_size as u64;
    let main_teb = teb::create_teb(stack_top, stack, crate::kernel32::pid(), os_sys::gettid());
    teb::install(main_teb);
    let mut l = Loader { linker, exe, state: Vec::new(), tls: Vec::new() };
    let todo = register_new(&mut l, exe);
    for s in l.state.iter_mut() {
        s.refs = 1;
    }
    *LOADER.lock().unwrap() = Some(l);
    setup_thread_tls(main_teb);
    // The program's own TLS callbacks run with the DLLs' attach (Windows
    // runs them before the entry point too); DllMain only for DLLs. Both are
    // Windows code, so they run on the stack the program will use.
    if !run_attach(&todo, stack_top) {
        return Err(String::from("a DLL failed to initialise (DllMain returned FALSE)"));
    }
    Ok(Started { entry, stack_top, stack_limit: stack, peb: teb::peb() })
}

/// Loads and runs a 32-bit (PE32) program. Its image and everything it
/// imports stay below 4 GiB; `winrun` itself is linked at 0x4000_0000 for
/// the same reason, so 32-bit code can reach every built-in's bridge stub.
///
/// `args` is the program's argument vector as typed, the program first;
/// `cmd` and `env` are its Windows command line and environment.
pub fn run_pe32(bytes: Vec<u8>, args: &[String], cmd: &str, env: &[String]) -> Result<(), String> {
    // The image's TLS directory is not set up here: a 32-bit image reads its
    // TLS array through the 32-bit TEB, which belongs to the bridge. This
    // path maps, relocates and binds imports, then enters compatibility mode.
    let cwd = os_std::env::current_dir().map(|p| p.as_str().to_string()).unwrap_or_else(|_| String::from("/"));
    let program = args.first().cloned().unwrap_or_else(|| String::from("program.exe"));
    let osyx = if program.starts_with('/') {
        program.clone()
    } else {
        path::to_osyx(&program, &cwd).unwrap_or(program.clone())
    };
    let name = osyx.rsplit('/').next().filter(|n| !n.is_empty()).unwrap_or("program.exe").to_string();
    let dir = osyx.rsplit_once('/').map_or_else(
        || String::from("/"),
        |(d, _)| if d.is_empty() { String::from("/") } else { String::from(d) },
    );
    let schema_bytes: &'static [u8] = Vec::leak(schema());
    let schema = Schema::parse(schema_bytes).map_err(|e| alloc::format!("API set schema: {e:?}"))?;
    let bridge = wow64::Bridge::new().map_err(|e| alloc::format!("32-bit bridge: {e}"))?;
    let mut linker = Linker::new(WinHost::new(alloc::vec![dir, cwd.clone()], Some(bridge)), Some(schema));
    // Known before loading so the image can be shared with other processes.
    linker.host.paths.insert(normalize(&name), osyx.clone());
    let exe = linker.load_executable(&name, bytes).map_err(|e| alloc::format!("cannot load {name}: {e}"))?;
    linker.host.paths.insert(linker.modules[exe].name.clone(), osyx.clone());
    let entry = linker.modules[exe].entry();
    if entry == 0 {
        return Err(alloc::format!("{name} has no entry point"));
    }
    if entry >= image::ADDRESS_LIMIT32 {
        return Err(alloc::format!("{name}: entry {entry:#x} is not addressable by 32-bit code"));
    }
    // Built-in modules have no DllMain, so the computed order is recorded
    // only: there is no 32-bit DllMain delivery on this path yet.
    let order = linker.init_order(exe);
    if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
        os_std::eprintln!("winrun: 32-bit program {name} entry {entry:#x}, {} modules", order.len());
    }
    let Some(mut bridge) = linker.host.bridge.take() else {
        return Err(String::from("the 32-bit bridge is unavailable"));
    };
    // The 64-bit side (the bridge, the built-in DLLs and the exception
    // handler) still runs as a Windows thread: it needs a PEB and a TEB in
    // GS. Both describe the 32-bit stack, which is the one Windows code
    // here runs on (the bridge enters on its own dispatch stack).
    let base = linker.modules[exe].base;
    let (limit, top) = bridge.stack();
    teb::create_peb(&teb::ProcessInfo {
        image_base: base,
        image_path: &path::to_windows(&osyx),
        command_line: cmd,
        current_dir: &path::to_windows(&cwd),
        environment: env,
        heap: crate::kernel32::process_heap(),
    });
    let main_teb = teb::create_teb(top, limit, crate::kernel32::pid(), os_sys::gettid());
    teb::install(main_teb);
    crate::kernel32::EXE_STACK_RESERVE.store((top - limit) as usize, core::sync::atomic::Ordering::Relaxed);
    bridge.enter(entry as u32)
}

/// Modules loaded, for the start-up log: (name, base, built-in, relocations, imports).
pub fn summary() -> Vec<(String, u64, bool, usize, usize)> {
    with(|l| {
        l.linker
            .modules
            .iter()
            .enumerate()
            .map(|(i, m)| (m.name.clone(), module_handle(l, i), m.is_builtin(), m.relocations, m.imports_bound))
            .collect()
    })
}

/// A loaded module, for debugging help.
pub struct ModuleInfo {
    pub name: String,
    /// Its Windows path.
    pub path: String,
    pub base: u64,
    pub size: u64,
    pub time_date_stamp: u32,
    pub checksum: u32,
    /// The code and data it exports, sorted by address: (address, name).
    pub symbols: Vec<(u64, String)>,
}

/// Every loaded module with its exported symbols. A built-in module's
/// image is its handle page; its exports live in winrun's own code.
pub fn modules() -> Vec<ModuleInfo> {
    with(|l| {
        (0..l.linker.modules.len())
            .map(|i| {
                let m = &l.linker.modules[i];
                let base = module_handle(l, i);
                let (mut size, mut stamp, mut checksum, mut symbols) = (mem::PAGE as u64, 0, 0, Vec::new());
                match &m.kind {
                    Kind::Pe { size: s, .. } => {
                        size = *s as u64;
                        if let Some(pe) = m.pe() {
                            stamp = pe.coff().time_date_stamp;
                            checksum = pe.optional().check_sum;
                            if let Ok(Some(e)) = pe.exports() {
                                let names: BTreeMap<u16, &str> = e.names().filter_map(|r| r.ok()).map(|(n, o)| (o, n)).collect();
                                for (ordinal, target) in e.functions().filter_map(|r| r.ok()) {
                                    if let osyx_pe::ExportTarget::Rva(rva) = target {
                                        let name = names.get(&ordinal).map_or_else(|| alloc::format!("Ordinal{ordinal}"), |n| String::from(*n));
                                        symbols.push((m.base + rva as u64, name));
                                    }
                                }
                            }
                        }
                    }
                    Kind::Builtin(_) => {
                        if let Some(b) = l.linker.host.builtins.iter().find(|b| b.name == m.name) {
                            symbols = b.by_name.iter().map(|(n, a)| (*a, String::from(*n))).collect();
                        }
                    }
                }
                symbols.sort();
                ModuleInfo { name: m.name.clone(), path: l.linker.host.file_name(&m.name), base, size, time_date_stamp: stamp, checksum, symbols }
            })
            .collect()
    })
}

// ---- run-time loader API -------------------------------------------------------

/// `GetModuleHandle`: None = the program.
pub fn get_module_handle(name: Option<&str>) -> Option<u64> {
    let base = name.map(|n| normalize(n.rsplit(['\\', '/']).next().unwrap_or(n)));
    let found = with(|l| match &base {
        None => Some(l.linker.modules[l.exe].base),
        Some(n) => {
            let i = l.linker.find(n)?;
            Some(module_handle(l, i))
        }
    });
    // ntdll, kernel32 and kernelbase are in every Windows process, whether
    // the program imports them or not: these built-ins load when first named.
    match (found, base) {
        (None, Some(n)) if ["ntdll.dll", "kernel32.dll", "kernelbase.dll"].contains(&n.as_str()) => load_library(&n).ok(),
        (f, _) => f,
    }
}

/// `GetModuleFileName` of a module handle (None = the program).
pub fn module_file_name(h: Option<u64>, exe_path: &str) -> Option<String> {
    with(|l| {
        let i = match h {
            None => l.exe,
            Some(h) => module_by_handle(l, h)?,
        };
        Some(if i == l.exe {
            path::to_windows(exe_path)
        } else {
            l.linker.host.file_name(&l.linker.modules[i].name)
        })
    })
}

/// `GetProcAddress`: a name, or an ordinal (`name` < 0x10000).
pub fn get_proc_address(h: u64, sym: Symbol<'_>) -> Result<u64, u32> {
    with(|l| {
        let i = module_by_handle(l, h).ok_or(ERROR_MOD_NOT_FOUND)?;
        let importer = l.linker.modules[l.exe].name.clone();
        l.linker.resolve(i, sym, &importer, 0).map_err(|_| ERROR_PROC_NOT_FOUND)
    })
}

/// `LoadLibrary`: a DLL name or a Windows path. Returns its handle.
pub fn load_library(name: &str) -> Result<u64, u32> {
    let (todo, h) = {
        let mut g = LOADER.lock().unwrap();
        let l = g.as_mut().expect("loader initialised");
        let file = name.rsplit(['\\', '/']).next().unwrap_or(name);
        let n = normalize(file);
        if name.contains(['\\', '/']) {
            let cwd = os_std::env::current_dir()
                .map(|p| path::to_windows(p.as_str()))
                .unwrap_or_else(|_| String::from("C:\\"));
            let p = path::to_osyx(name, &cwd)?;
            l.linker.host.explicit = Some((n.clone(), p));
        }
        let importer = l.linker.modules[l.exe].name.clone();
        let started = Instant::now();
        let r = l.linker.load_dll(&n, &importer);
        let elapsed = started.elapsed().as_millis();
        if elapsed >= 100 {
            os_std::eprintln!("winrun: LoadLibrary({name}) took {elapsed} ms");
        }
        l.linker.host.explicit = None;
        let i = r.map_err(|e| {
            // Preserve the dependency error before reducing it to a Win32
            // code. A browser otherwise reports only "Couldn't load XPCOM".
            os_std::eprintln!("winrun: LoadLibrary({name}) failed: {e}");
            match e {
                LinkError::DllNotFound { .. } | LinkError::NoApiSetHost { .. } => ERROR_MOD_NOT_FOUND,
                LinkError::SymbolNotFound { .. } | LinkError::ForwarderTooDeep { .. } => ERROR_PROC_NOT_FOUND,
                LinkError::NoMemory => ERROR_NOT_ENOUGH_MEMORY,
                _ => 193, // ERROR_BAD_EXE_FORMAT
            }
        })?;
        let todo = register_new(l, i);
        while l.state.len() < l.linker.modules.len() {
            l.state.push(ModState { ldr: 0, refs: 0, attached: true, tls_callbacks: Vec::new() });
        }
        l.state[i].refs += 1;
        (todo, module_handle(l, i))
    };
    if crate::VERBOSE.load(core::sync::atomic::Ordering::Relaxed) {
        os_std::eprintln!("winrun: loaded {name} at {h:#x}");
    }
    if !todo.is_empty() {
        // New TLS indices need blocks for this thread too.
        setup_thread_tls(teb::current());
    }
    if !deliver_attach(&todo) {
        return Err(ERROR_DLL_INIT_FAILED);
    }
    Ok(h)
}

/// The handle of the module whose image contains `addr`. Built-in modules'
/// code is winrun's own, so only their handle page belongs to them.
pub fn module_from_address(addr: u64) -> Option<u64> {
    with(|l| {
        (0..l.linker.modules.len()).map(|i| module_handle(l, i)).zip(l.linker.modules.iter()).find_map(|(h, m)| {
            let size = match &m.kind {
                Kind::Pe { size, .. } => *size as u64,
                Kind::Builtin(_) => mem::PAGE as u64,
            };
            (addr >= h && addr < h + size).then_some(h)
        })
    })
}

/// `GetModuleHandleEx` without UNCHANGED_REFCOUNT: one more reference,
/// or a reference that is never dropped (PIN).
pub fn add_module_reference(h: u64, pin: bool) {
    with(|l| {
        if let Some(i) = module_by_handle(l, h) {
            if let Some(s) = l.state.get_mut(i) {
                s.refs = if pin { u32::MAX } else { s.refs.saturating_add(1) };
            }
        }
    })
}

/// `FreeLibrary`: drops a reference. The image stays mapped (OSyx does not
/// unload DLLs yet); the last reference delivers DLL_PROCESS_DETACH.
pub fn free_library(h: u64) -> Result<(), u32> {
    let detach = {
        let mut g = LOADER.lock().unwrap();
        let l = g.as_mut().expect("loader initialised");
        let i = module_by_handle(l, h).ok_or(ERROR_MOD_NOT_FOUND)?;
        if i == l.exe || l.linker.modules[i].is_builtin() {
            return Ok(());
        }
        let s = &mut l.state[i];
        s.refs = s.refs.saturating_sub(1);
        if s.refs == 0 && s.attached {
            s.attached = false;
            let m = &l.linker.modules[i];
            Some((m.base, m.entry()))
        } else {
            None
        }
    };
    if let Some((base, entry)) = detach {
        if entry != 0 {
            // SAFETY: the entry point of a mapped DLL image.
            let f: DllMain = unsafe { core::mem::transmute(entry as usize) };
            f(base, DLL_PROCESS_DETACH, 0);
        }
    }
    Ok(())
}

/// DLL file search after the application directory: an optional
/// SetDllDirectory directory (OSyx path), then the current directory when
/// `include_cwd`. Built-in DLLs (the "system" directory) always resolve.
pub fn set_dll_search(dll_dir: Option<String>, include_cwd: bool) {
    let mut g = LOADER.lock().unwrap();
    let Some(l) = g.as_mut() else { return };
    let app = l.linker.host.search[0].clone();
    let mut search = alloc::vec![app];
    search.extend(dll_dir);
    if include_cwd {
        if let Ok(cwd) = os_std::env::current_dir() {
            search.push(String::from(cwd.as_str()));
        }
    }
    l.linker.host.search = search;
}

/// Whether the image section containing `addr` is executable (from the
/// mapped section headers).
pub fn is_executable(addr: u64) -> bool {
    let Some((base, _)) = image_containing(addr) else { return false };
    let rd32 = |a: u64| unsafe { core::ptr::read_unaligned(a as *const u32) };
    let rd16 = |a: u64| unsafe { core::ptr::read_unaligned(a as *const u16) };
    // SAFETY (closures): the headers of a mapped image.
    let nt = base + rd32(base + 0x3c) as u64;
    let count = rd16(nt + 6) as u64;
    let sections = nt + 24 + rd16(nt + 20) as u64;
    let rva = addr - base;
    (0..count).map(|i| sections + i * 40).any(|s| {
        let (va, size, flags) = (rd32(s + 12) as u64, rd32(s + 8).max(rd32(s + 16)) as u64, rd32(s + 36));
        rva >= va && rva < va + size && flags & 0x2000_0000 != 0
    })
}

/// (base, size) of the mapped PE image containing `addr`.
pub fn image_containing(addr: u64) -> Option<(u64, u64)> {
    let g = LOADER.lock().ok()?;
    let l = g.as_ref()?;
    let img = l.linker.host.images.iter().find(|i| addr >= i.base && addr < i.base + i.size)?;
    Some((img.base, img.size))
}

/// The module a code address belongs to, as its name and offset — the form
/// crash reports use. Only PE images (not built-in DLLs) have code here.
pub fn where_is(addr: u64) -> Option<(String, u64)> {
    let g = LOADER.lock().ok()?;
    let l = g.as_ref()?;
    let image = l.linker.host.images.iter().find(|i| addr >= i.base && addr < i.base + i.size)?;
    let name = l.linker.modules.iter().find(|m| m.base == image.base)?.name.clone();
    Some((name, addr - image.base))
}

/// `VirtualQuery` for addresses inside loaded images.
pub fn query_image(addr: u64) -> Option<mem::Info> {
    let g = LOADER.lock().ok()?;
    let l = g.as_ref()?;
    let img = l.linker.host.images.iter().find(|i| addr >= i.base && addr < i.base + i.size)?;
    Some(mem::Info {
        base: addr & !(mem::PAGE as u64 - 1),
        allocation_base: img.base,
        allocation_protect: mem::PAGE_EXECUTE_WRITECOPY,
        size: mem::PAGE as u64,
        state: mem::MEM_COMMIT,
        protect: mem::PAGE_READONLY,
        kind: mem::MEM_IMAGE,
    })
}
