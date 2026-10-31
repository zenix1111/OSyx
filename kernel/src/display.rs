//! The display: kernel status screen, ownership by a user-space compositor,
//! and the output that pixels go to.
//!
//! After hand-off the kernel redraws the boot screen itself (proving it owns
//! the display without firmware help) and keeps a live status area:
//! self-test results, memory statistics and an uptime-driven spinner. A
//! root process (PRISM) can take the display over and draws into the same
//! buffer the kernel used.
//!
//! Outputs:
//! * **linear**: the UEFI GOP framebuffer; the hardware scans it out, so
//!   writes are visible at once;
//! * **virtio-gpu**: a 2D resource on a VirtIO-GPU scanout. The buffer is
//!   guest RAM attached as the resource's backing store (mapped linearly
//!   into the kernel and into the owner); changed rectangles reach the
//!   screen with `TRANSFER_TO_HOST_2D` + `RESOURCE_FLUSH` (`flush`). Modes
//!   can be changed (`set_mode`): a new resource and buffer replace the old.
//!
//! Lock order: device commands sleep, so they never run under the
//! `DISPLAY` spinlock; functions collect a [`Flush`] under the lock and
//! submit it after releasing it.

use crate::drivers::virtio_gpu::{self, VirtioGpu};
use crate::mem::phys_to_virt;
use crate::shm::SharedMemory;
use crate::sync::IrqSpinLock;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use osyx_abi::Errno;
use osyx_bootinfo::{FramebufferInfo, PixelFormat};
use osyx_gfx::splash::{self, Assets, Layout};
use osyx_gfx::{Color, Rect, Surface};

/// A VirtIO-GPU scanout showing one resource.
struct GpuOutput {
    gpu: Arc<VirtioGpu>,
    scanout: u32,
    resource: u32,
    /// The resource's backing store (RAM frames).
    backing: Arc<SharedMemory>,
}

enum Output {
    Linear { phys: u64 },
    Gpu(GpuOutput),
}

struct Display {
    /// The buffer as the kernel addresses it.
    fb: *mut u32,
    /// Bytes of the buffer (what `display_acquire` maps).
    size: u64,
    /// Pixels per row.
    stride: u32,
    rgb: bool,
    width: u32,
    height: u32,
    frame: Vec<u32>,
    bg: Vec<u32>,
    layout: Layout,
    assets: Assets<'static>,
    footer: String,
    /// pid of the process that owns the display (0: the kernel draws).
    owner: u64,
    output: Output,
    outputs: u32,
    native: (u32, u32),
}

// SAFETY: the buffer pointer is only dereferenced under the DISPLAY lock.
unsafe impl Send for Display {}

static DISPLAY: IrqSpinLock<Option<Display>> = IrqSpinLock::new(None);

/// A rectangle to push to a VirtIO-GPU scanout once the lock is released.
#[must_use]
pub struct Flush {
    gpu: Arc<VirtioGpu>,
    resource: u32,
    rect: virtio_gpu::Rect,
    stride_bytes: u32,
}

impl Flush {
    fn run(self) {
        if let Err(e) = self.gpu.present(self.resource, self.rect, self.stride_bytes) {
            crate::kprintln!("display: virtio-gpu present failed: {}", e.describe());
        }
    }
}

fn run(f: Option<Flush>) {
    if let Some(f) = f {
        f.run();
    }
}

impl Display {
    fn surfaces(&mut self) -> (Surface<'_>, Surface<'_>) {
        let (w, h) = (self.width, self.height);
        (
            Surface::new(&mut self.frame, w, h, w).expect("frame geometry"),
            Surface::new(&mut self.bg, w, h, w).expect("bg geometry"),
        )
    }

    fn present(&mut self, r: Rect) -> Option<Flush> {
        if self.owner != 0 {
            return None; // a user-space compositor draws now
        }
        if crate::earlycon::active() {
            return None; // `log.screen`: the boot log keeps the screen
        }
        self.force_present(r)
    }

    fn force_present(&mut self, r: Rect) -> Option<Flush> {
        let (fb, stride, rgb) = (self.fb, self.stride, self.rgb);
        let (frame, _) = self.surfaces();
        // SAFETY: `fb` maps the whole buffer (stride * height pixels); checked
        // in `init` / `init_gpu`.
        unsafe { osyx_gfx::present(&frame, r, fb, stride, rgb) };
        self.flush_rect(r)
    }

    /// The device work to show `r` (nothing for a linear framebuffer).
    fn flush_rect(&self, r: Rect) -> Option<Flush> {
        let Output::Gpu(g) = &self.output else { return None };
        let r = r.intersect(&Rect::new(0, 0, self.width, self.height));
        if r.w == 0 || r.h == 0 {
            return None;
        }
        Some(Flush {
            gpu: g.gpu.clone(),
            resource: g.resource,
            rect: virtio_gpu::Rect { x: r.x as u32, y: r.y as u32, w: r.w, h: r.h },
            stride_bytes: self.stride * 4,
        })
    }

    /// Lays out and draws the status screen for the current geometry.
    fn redraw_splash(&mut self) {
        let (w, h) = (self.width, self.height);
        self.frame = vec![0; (w * h) as usize];
        self.bg = vec![0; (w * h) as usize];
        self.layout = Layout::new(w, h, &self.assets);
        let (l, a) = (self.layout, self.assets);
        let footer = core::mem::take(&mut self.footer);
        {
            let (_, mut bg) = self.surfaces();
            splash::draw_background(&mut bg, &l, &a, concat!("OSyx kernel ", env!("CARGO_PKG_VERSION")), &footer);
        }
        self.footer = footer;
        self.frame.copy_from_slice(&self.bg);
        let (mut f, bg) = self.surfaces();
        splash::draw_logo(&mut f, &bg, &l, &a, 255);
        splash::draw_progress(&mut f, &bg, &l, 1000, splash::ACCENT);
    }
}

/// Takes over the GOP framebuffer. Returns false if there is none or it is
/// unusable (the early boot log then stays). With `keep_log` the early log
/// keeps the screen until a process acquires the display; the status screen
/// is still prepared, but only drawn once that process releases it.
pub fn init(info: &FramebufferInfo, footer_right: &str, keep_log: bool) -> bool {
    let rgb = match info.format {
        PixelFormat::Rgb => true,
        PixelFormat::Bgr => false,
        _ => return false,
    };
    let needed = info.stride as u64 * info.height as u64 * 4;
    if info.base == 0 || info.width == 0 || info.stride < info.width || info.size < needed {
        return false;
    }
    if info.base + info.size > crate::mem::hhdm_size() {
        return false;
    }
    let Ok(assets) = Assets::embedded() else { return false };
    if !keep_log {
        crate::earlycon::stop();
    }
    let (w, h) = (info.width, info.height);
    let mut d = Display {
        fb: phys_to_virt(info.base) as *mut u32,
        size: needed,
        owner: 0,
        stride: info.stride,
        rgb,
        width: w,
        height: h,
        frame: Vec::new(),
        bg: Vec::new(),
        layout: Layout::new(w, h, &assets),
        assets,
        footer: String::from(footer_right),
        output: Output::Linear { phys: info.base },
        outputs: 1,
        native: (w, h),
    };
    d.redraw_splash();
    let f = d.present(Rect::new(0, 0, w, h));
    *DISPLAY.lock() = Some(d);
    run(f);
    true
}

/// Creates a resource of `w` x `h` with fresh backing memory and shows it
/// on `scanout`. Returns the output and the kernel's linear view of it.
fn create_gpu_output(gpu: &Arc<VirtioGpu>, scanout: u32, w: u32, h: u32) -> Result<(GpuOutput, u64), &'static str> {
    let backing = SharedMemory::new(w as u64 * h as u64 * 4).map_err(|_| "out of memory for the display buffer")?;
    let resource = gpu.create_resource(w, h, virtio_gpu::FORMAT_B8G8R8X8).map_err(|e| e.describe())?;
    let undo = |gpu: &VirtioGpu| {
        let _ = gpu.unref_resource(resource);
    };
    if let Err(e) = gpu.attach_backing(resource, backing.frames()) {
        undo(gpu);
        return Err(e.describe());
    }
    if let Err(e) = gpu.set_scanout(scanout, resource, virtio_gpu::Rect { x: 0, y: 0, w, h }) {
        let _ = gpu.detach_backing(resource);
        undo(gpu);
        return Err(e.describe());
    }
    let va = crate::mem::map_frames(backing.frames()).map_err(|_| "no kernel address space for the display buffer")?;
    Ok((GpuOutput { gpu: gpu.clone(), scanout, resource, backing }, va))
}

/// Retires an output that is no longer shown.
fn destroy_gpu_output(o: GpuOutput) {
    let _ = o.gpu.detach_backing(o.resource);
    let _ = o.gpu.unref_resource(o.resource);
    // The backing frames are freed when the last mapping (the owner's)
    // drops its reference.
}

/// Takes over a VirtIO-GPU: the first enabled scanout at its preferred
/// mode (or `mode`). Returns false (and logs why) if the device does not
/// work; the caller then keeps the GOP path.
pub fn init_gpu(gpu: Arc<VirtioGpu>, footer_right: &str, mode: Option<(u32, u32)>) -> bool {
    let scanouts = match gpu.display_info() {
        Ok(s) => s,
        Err(e) => {
            crate::kprintln!("display: virtio-gpu GET_DISPLAY_INFO failed: {}", e.describe());
            return false;
        }
    };
    let (index, native) = match scanouts.iter().enumerate().find(|(_, s)| s.enabled && s.rect.w > 0 && s.rect.h > 0) {
        Some((i, s)) => (i as u32, (s.rect.w, s.rect.h)),
        None => (0, (1024, 768)),
    };
    let edid = if gpu.has_edid() { gpu.edid(index).ok().filter(|e| e.len() >= osyx_display::edid::BLOCK_LEN) } else { None };
    let edid_len = edid.as_ref().map(|e| e.len()).unwrap_or(0);
    let edid = match edid.as_deref().map(osyx_display::Edid::parse) {
        Some(Ok(edid)) => {
            let name = edid.name.as_deref().unwrap_or("(unnamed)");
            let (pw, ph, refresh) = edid.preferred_mode().map(|m| (m.width as u32, m.height as u32, m.refresh_mhz)).unwrap_or((0, 0, 0));
            crate::kprintln!(
                "display: EDID {} {} {:04x}: {}x{} cm, {} mode(s), preferred {}x{}@{} Hz, {} extension(s)",
                edid.vendor(),
                name,
                edid.product,
                edid.width_cm,
                edid.height_cm,
                edid.modes.len(),
                pw,
                ph,
                (refresh + 500) / 1000,
                edid.extensions
            );
            Some(edid)
        }
        Some(Err(e)) => {
            crate::kprintln!("display: EDID rejected: {:?}", e);
            None
        }
        None => None,
    };
    let mut chosen = mode.or_else(|| {
        edid.as_ref().and_then(|e| e.preferred_mode()).map(|m| {
            crate::kprintln!("display: EDID preferred mode {}x{}@{} Hz", m.width, m.height, (m.refresh_mhz + 500) / 1000);
            (m.width as u32, m.height as u32)
        })
    });
    // Never let a monitor-supplied mode take the output down: retry the
    // scanout's own size when the preferred mode cannot be set.
    let (out, va) = loop {
        let (w, h) = chosen.unwrap_or(native);
        match create_gpu_output(&gpu, index, w, h) {
            Ok(x) => break x,
            Err(e) if mode.is_none() && chosen != Some(native) => {
                crate::kprintln!("display: mode {}x{} failed ({}); using the scanout mode {}x{}", w, h, e, native.0, native.1);
                chosen = Some(native);
            }
            Err(e) => {
                crate::kprintln!("display: virtio-gpu scanout setup failed: {}", e);
                return false;
            }
        }
    };
    let (w, h) = chosen.unwrap_or(native);
    crate::kprintln!(
        "display: virtio-gpu at {}: {} scanout(s), using scanout {} at {}x{} (preferred {}x{}), resource {}, {} KiB backing in {} frames, EDID {}, cursor queue {}",
        gpu.location,
        gpu.num_scanouts,
        index,
        w,
        h,
        native.0,
        native.1,
        out.resource,
        out.backing.size() / 1024,
        out.backing.pages(),
        edid_len,
        if gpu.has_cursor() { "yes" } else { "no" }
    );
    let Ok(assets) = Assets::embedded() else { return false };
    crate::earlycon::stop();
    let mut d = Display {
        fb: va as *mut u32,
        size: w as u64 * h as u64 * 4,
        owner: 0,
        stride: w,
        rgb: false, // B8G8R8X8: 0x00RRGGBB in a little-endian word
        width: w,
        height: h,
        frame: Vec::new(),
        bg: Vec::new(),
        layout: Layout::new(w, h, &assets),
        assets,
        footer: String::from(footer_right),
        output: Output::Gpu(out),
        outputs: gpu.num_scanouts,
        native,
    };
    d.redraw_splash();
    let f = d.present(Rect::new(0, 0, w, h));
    *DISPLAY.lock() = Some(d);
    run(f);
    true
}

/// Shows a status line and up to three detail lines.
pub fn status(text: &str, color: Color, details: &[&str]) {
    let f = {
        let mut g = DISPLAY.lock();
        let Some(d) = g.as_mut() else { return };
        let (l, a) = (d.layout, d.assets);
        let n = details.len().min(3);
        let r = {
            let (mut f, bg) = d.surfaces();
            splash::draw_status(&mut f, &bg, &l, &a, text, color).union(&splash::draw_details(&mut f, &bg, &l, &a, &details[..n], splash::TEXT_DIM))
        };
        d.present(r)
    };
    run(f);
}

/// Advances the activity spinner (called from kmain's final loop).
pub fn spin(phase: u32) {
    let f = {
        let mut g = DISPLAY.lock();
        let Some(d) = g.as_mut() else { return };
        let l = d.layout;
        let r = {
            let (mut f, bg) = d.surfaces();
            splash::draw_spinner(&mut f, &bg, &l, phase, 255, splash::ACCENT)
        };
        d.present(r)
    };
    run(f);
}

/// Best-effort panic screen; never blocks. Drawn even over a user-space
/// compositor: the system is halting.
pub fn panic_screen(message: &str) {
    if crate::earlycon::active() {
        return; // the panic message is the last line of the boot log
    }
    let f = {
        let Some(mut g) = DISPLAY.try_lock() else { return };
        let Some(d) = g.as_mut() else { return };
        let (l, a) = (d.layout, d.assets);
        let owned = d.owner != 0;
        let r = {
            let (mut f, bg) = d.surfaces();
            splash::draw_progress(&mut f, &bg, &l, 1000, splash::ERROR)
                .union(&splash::draw_status(&mut f, &bg, &l, &a, "Kernel panic", splash::ERROR))
                .union(&splash::draw_details(&mut f, &bg, &l, &a, &[message, "System halted"], splash::TEXT))
                .union(&splash::draw_spinner(&mut f, &bg, &l, 0, 0, splash::ACCENT))
        };
        let full = Rect::new(0, 0, d.width, d.height);
        d.force_present(if owned { full } else { r })
    };
    // Only if the device is idle: a command in flight would make us wait.
    if let Some(f) = f {
        if f.gpu.is_idle() {
            f.run();
        }
    }
}

/// Geometry of the display for `display_info`.
pub fn info() -> Option<osyx_abi::ipc::DisplayInfo> {
    let g = DISPLAY.lock();
    let d = g.as_ref()?;
    Some(osyx_abi::ipc::DisplayInfo {
        width: d.width,
        height: d.height,
        stride: d.stride,
        format: if d.rgb { osyx_abi::ipc::pixel::RGBX } else { osyx_abi::ipc::pixel::BGRX },
        size: d.size,
        owner: d.owner,
        backend: match d.output {
            Output::Linear { .. } => osyx_abi::ipc::BACKEND_LINEAR,
            Output::Gpu(_) => osyx_abi::ipc::BACKEND_VIRTIO_GPU,
        },
        outputs: d.outputs,
        native_width: d.native.0,
        native_height: d.native.1,
    })
}

/// Makes `pid` the display owner; returns the buffer as a memory object to
/// map into it. The current owner may acquire again (after `execve` or a
/// mode change, for example).
pub fn acquire(pid: u64) -> Result<Arc<SharedMemory>, Errno> {
    let mut g = DISPLAY.lock();
    let d = g.as_mut().ok_or(Errno::NotSupported)?;
    if d.owner != 0 && d.owner != pid {
        return Err(Errno::Busy);
    }
    let first = d.owner == 0;
    d.owner = pid;
    // The new owner draws now; the early log (`log.screen`) ends here.
    crate::earlycon::stop();
    if first {
        crate::kprintln!("display: process {} owns the display ({}x{})", pid, d.width, d.height);
    }
    Ok(match &d.output {
        Output::Linear { phys } => SharedMemory::device(*phys, d.size),
        Output::Gpu(o) => o.backing.clone(),
    })
}

/// The owner presents rectangle (x, y, w, h) of its buffer.
pub fn flush(pid: u64, x: u32, y: u32, w: u32, h: u32) -> Result<(), Errno> {
    let f = {
        let g = DISPLAY.lock();
        let d = g.as_ref().ok_or(Errno::NotSupported)?;
        if d.owner != pid {
            return Err(Errno::PermissionDenied);
        }
        if x >= d.width || y >= d.height {
            return Err(Errno::InvalidArgument);
        }
        d.flush_rect(Rect::new(x as i32, y as i32, w.min(d.width - x), h.min(d.height - y)))
    };
    run(f);
    Ok(())
}

/// Switches to `width` x `height` (VirtIO-GPU: any size the device takes;
/// a linear framebuffer only has its boot mode). Allowed while the kernel
/// or the caller owns the display.
pub fn set_mode(pid: u64, width: u32, height: u32) -> Result<(), Errno> {
    if width == 0 || height == 0 {
        return Err(Errno::InvalidArgument);
    }
    let (gpu, scanout) = {
        let g = DISPLAY.lock();
        let d = g.as_ref().ok_or(Errno::NotSupported)?;
        if d.owner != 0 && d.owner != pid {
            return Err(Errno::Busy);
        }
        if (width, height) == (d.width, d.height) {
            return Ok(());
        }
        match &d.output {
            Output::Linear { .. } => return Err(Errno::NotSupported),
            Output::Gpu(o) => (o.gpu.clone(), o.scanout),
        }
    };
    let (out, va) = create_gpu_output(&gpu, scanout, width, height).map_err(|e| {
        crate::kprintln!("display: mode {}x{} failed: {}", width, height, e);
        Errno::InvalidArgument
    })?;
    let (old, f, from) = {
        let mut g = DISPLAY.lock();
        let d = g.as_mut().ok_or(Errno::NotSupported)?;
        let from = (d.width, d.height);
        let old = core::mem::replace(&mut d.output, Output::Gpu(out));
        d.fb = va as *mut u32;
        d.size = width as u64 * height as u64 * 4;
        d.stride = width;
        d.width = width;
        d.height = height;
        d.redraw_splash();
        let f = d.present(Rect::new(0, 0, width, height));
        (old, f, from)
    };
    run(f);
    if let Output::Gpu(o) = old {
        destroy_gpu_output(o);
    }
    crate::kprintln!("display: mode {}x{} -> {}x{} (process {})", from.0, from.1, width, height, pid);
    Ok(())
}

/// Gives the display back to the kernel if `pid` owns it; the status
/// screen is drawn again (the diagnostic fallback when a compositor dies).
pub fn release(pid: u64) -> bool {
    let f = {
        let mut g = DISPLAY.lock();
        let Some(d) = g.as_mut() else { return false };
        if d.owner != pid || pid == 0 {
            return false;
        }
        d.owner = 0;
        let full = Rect::new(0, 0, d.width, d.height);
        d.present(full)
    };
    run(f);
    crate::kprintln!("display: released by process {}, kernel status screen restored", pid);
    true
}

/// Process exit hook.
pub fn owner_exited(pid: u64) {
    release(pid);
}

/// Exercises the VirtIO-GPU cursor queue: a 64x64 cursor image as its own
/// resource, shown, moved and hidden again. Returns what was done.
pub fn cursor_selftest() -> Result<&'static str, &'static str> {
    let (gpu, scanout) = {
        let g = DISPLAY.lock();
        match g.as_ref().map(|d| &d.output) {
            Some(Output::Gpu(o)) => (o.gpu.clone(), o.scanout),
            _ => return Ok("no virtio-gpu"),
        }
    };
    if !gpu.has_cursor() {
        return Err("device has no cursor queue");
    }
    let n = virtio_gpu::CURSOR_SIZE;
    let shm = SharedMemory::new(n as u64 * n as u64 * 4).map_err(|_| "out of memory")?;
    // An arrow-ish triangle, opaque white with a black edge.
    let va = crate::mem::map_frames(shm.frames()).map_err(|_| "no address space")?;
    for y in 0..n {
        for x in 0..n {
            let px = if x <= y / 2 { if x == y / 2 || x == 0 { 0xFF00_0000 } else { 0xFFFF_FFFF } } else { 0 };
            // SAFETY: `va` maps n*n*4 bytes of the cursor buffer.
            unsafe { core::ptr::write_volatile((va as *mut u32).add((y * n + x) as usize), px) };
        }
    }
    let res = gpu.create_resource(n, n, virtio_gpu::FORMAT_B8G8R8A8).map_err(|e| e.describe())?;
    let r = (|| {
        gpu.attach_backing(res, shm.frames())?;
        gpu.transfer(res, virtio_gpu::Rect { x: 0, y: 0, w: n, h: n }, n * 4)?;
        gpu.update_cursor(scanout, 100, 100, res, 0, 0)?;
        gpu.move_cursor(scanout, 140, 120)?;
        gpu.update_cursor(scanout, 0, 0, 0, 0, 0)?; // hide
        gpu.detach_backing(res)
    })();
    let _ = gpu.unref_resource(res);
    r.map(|_| "cursor resource created, shown, moved, hidden, destroyed").map_err(|e| e.describe())
}

/// One line of VirtIO-GPU counters for the kernel log (`None` on GOP).
pub fn gpu_summary() -> Option<String> {
    let gpu = {
        let g = DISPLAY.lock();
        match g.as_ref().map(|d| &d.output) {
            Some(Output::Gpu(o)) => o.gpu.clone(),
            _ => return None,
        }
    };
    let s = gpu.stats();
    let avg_us = (s.present_ns / 1000).checked_div(s.transfers).unwrap_or(0);
    Some(alloc::format!(
        "display: virtio-gpu {} commands, {} presents ({} Mpx transferred, avg {} us per present), {} cursor updates, {} moves, {} resources created, {} destroyed, {} errors",
        s.commands,
        s.transfers,
        s.transferred_pixels / 1_000_000,
        avg_us,
        s.cursor_updates,
        s.cursor_moves,
        s.resources_created,
        s.resources_destroyed,
        s.errors
    ))
}

/// Checks for a VirtIO-GPU display-change event (output connected,
/// disconnected or resized by the host) and logs the new configuration.
/// The current mode stays until someone calls `set_mode`.
pub fn poll_hotplug() {
    let gpu = {
        let g = DISPLAY.lock();
        match g.as_ref().map(|d| &d.output) {
            Some(Output::Gpu(o)) => o.gpu.clone(),
            _ => return,
        }
    };
    if !gpu.take_display_event() {
        return;
    }
    match gpu.display_info() {
        Ok(s) => {
            let list: Vec<String> = s.iter().enumerate().map(|(i, o)| alloc::format!("{}: {}x{}{}", i, o.rect.w, o.rect.h, if o.enabled { "" } else { " (off)" })).collect();
            crate::kprintln!("display: output configuration changed: {}", list.join(", "));
            if let Some(o) = s.iter().find(|o| o.enabled) {
                if let Some(d) = DISPLAY.lock().as_mut() {
                    d.native = (o.rect.w, o.rect.h);
                }
            }
        }
        Err(e) => crate::kprintln!("display: output configuration changed; query failed: {}", e.describe()),
    }
}
