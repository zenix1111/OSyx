//! System calls of ABI v7: pipes, standard stream redirection, channels,
//! shared memory, waiting on handles, the display, process and mount
//! listings, kill and power control.

use crate::exec::ExecRequest;
use crate::fixup::{copy_from_user, copy_to_user, user_range_ok};
use crate::object::{self, Object};
use crate::{ipc, pipe, process, sched, shm};
use alloc::sync::Arc;
use alloc::vec::Vec;
use osyx_abi::ipc::{
    ChannelMsg, MountInfo, WaitItem, MAX_MESSAGE, MAX_MESSAGE_HANDLES, MAX_SERVICE_NAME, MAX_WAIT_ITEMS,
};
use osyx_abi::{Errno, HANDLE_NONE, PROT_EXEC, PROT_READ, PROT_WRITE};

/// Reads a plain `repr(C)` value from user memory.
fn get_user<T: Copy + Default>(addr: u64) -> Result<T, Errno> {
    let mut v = T::default();
    // SAFETY: only used with padding-free repr(C) ABI structs, for which
    // every byte pattern is a valid value.
    let bytes = unsafe { core::slice::from_raw_parts_mut(&mut v as *mut T as *mut u8, core::mem::size_of::<T>()) };
    copy_from_user(bytes, addr)?;
    Ok(v)
}

fn put_user<T: Copy>(addr: u64, v: &T) -> Result<(), Errno> {
    // SAFETY: as in `get_user`.
    let bytes = unsafe { core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>()) };
    copy_to_user(addr, bytes)
}

fn put_slice<T: Copy>(addr: u64, len: u64, items: &[T]) -> Result<u64, Errno> {
    let size = core::mem::size_of::<T>();
    let n = (len as usize / size).min(items.len());
    // SAFETY: as in `get_user`; `n` items of `T`.
    let bytes = unsafe { core::slice::from_raw_parts(items.as_ptr() as *const u8, n * size) };
    copy_to_user(addr, bytes)?;
    Ok((n * size) as u64)
}

pub fn pipe(out: u64) -> Result<u64, Errno> {
    if !user_range_ok(out, 16) {
        return Err(Errno::Fault);
    }
    let (r, w) = pipe::new();
    let handles = process::add_objects(alloc::vec![Object::Pipe(Arc::new(r)), Object::Pipe(Arc::new(w))])?;
    let pair = [handles[0], handles[1]];
    if let Err(e) = put_user(out, &pair) {
        let _ = process::close_handle(pair[0]);
        let _ = process::close_handle(pair[1]);
        return Err(e);
    }
    Ok(0)
}

pub fn spawn_stdio(args: u64, stdio: u64) -> Result<u64, Errno> {
    let req = ExecRequest::from_user(args)?;
    let raw: [u64; 3] = get_user(stdio)?;
    let mut objs: [Option<Object>; 3] = [None, None, None];
    for (i, &h) in raw.iter().enumerate() {
        if h != HANDLE_NONE {
            let o = process::get_object(h)?;
            if !matches!(o, Object::File(_) | Object::Pipe(_)) {
                return Err(Errno::InvalidArgument);
            }
            objs[i] = Some(o);
        }
    }
    process::spawn_with_stdio(sched::current_pid(), &req, objs).map_err(|e| e.errno())
}

/// Reads standard input (handle 0) when it was redirected.
pub fn read_stdio(handle: u64, buf: u64, len: u64) -> Result<u64, Errno> {
    let o = process::get_object(handle)?;
    let len = len.min(osyx_abi::MAX_READ as u64).min(osyx_abi::ipc::PIPE_CAPACITY as u64) as usize;
    if !user_range_ok(buf, len as u64) {
        return Err(Errno::Fault);
    }
    match o {
        Object::Pipe(p) => {
            let mut k = alloc::vec![0u8; len];
            let n = p.read(&mut k)?;
            copy_to_user(buf, &k[..n])?;
            Ok(n as u64)
        }
        _ => Err(Errno::BadHandle),
    }
}

/// Writes to a pipe handle (any handle number, including redirected 1/2).
pub fn write_pipe(p: &pipe::PipeEnd, buf: u64, len: u64) -> Result<u64, Errno> {
    let mut done = 0u64;
    let mut chunk = alloc::vec![0u8; (len as usize).min(16 * 1024)];
    while done < len {
        let n = (len - done).min(chunk.len() as u64) as usize;
        copy_from_user(&mut chunk[..n], buf + done)?;
        match p.write(&chunk[..n]) {
            Ok(w) => {
                done += w as u64;
                if w < n {
                    break;
                }
            }
            Err(e) if done == 0 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(done)
}

fn user_name(ptr: u64, len: u64) -> Result<alloc::string::String, Errno> {
    if len == 0 || len > MAX_SERVICE_NAME as u64 {
        return Err(Errno::InvalidArgument);
    }
    let mut b = alloc::vec![0u8; len as usize];
    copy_from_user(&mut b, ptr)?;
    alloc::string::String::from_utf8(b).map_err(|_| Errno::InvalidArgument)
}

pub fn channel_listen(name: u64, len: u64) -> Result<u64, Errno> {
    let name = user_name(name, len)?;
    let (cred, _) = process::current_identity();
    // System-wide services stay privileged. Applications may create
    // services only in their own UID namespace; the kernel checks peers
    // when they connect, so another user cannot claim or access it.
    if !cred.is_root() && !name.starts_with(&alloc::format!("user.{}.", cred.uid)) {
        return Err(Errno::PermissionDenied);
    }
    let l = ipc::listen(&name, sched::current_pid(), cred.uid)?;
    crate::kprintln!("ipc: process {} listens as \"{}\"", sched::current_pid(), name);
    process::add_object(Object::Listener(l))
}

pub fn channel_connect(name: u64, len: u64) -> Result<u64, Errno> {
    let name = user_name(name, len)?;
    let (cred, _) = process::current_identity();
    let ep = ipc::connect(&name, sched::current_pid(), cred.uid)?;
    process::add_object(Object::Channel(Arc::new(ep)))
}

pub fn channel_accept(listener: u64) -> Result<u64, Errno> {
    let Object::Listener(l) = process::get_object(listener)? else { return Err(Errno::BadHandle) };
    let ep = l.accept()?;
    process::add_object(Object::Channel(Arc::new(ep)))
}

fn channel(handle: u64) -> Result<Arc<ipc::Endpoint>, Errno> {
    match process::get_object(handle)? {
        Object::Channel(c) => Ok(c),
        _ => Err(Errno::BadHandle),
    }
}

/// `channel_send` without the entry lock, for messages without handles
/// (`None` otherwise, before anything happened). The channel, the handle
/// table and the wait queues have their own spinlocks; user copies happen
/// while none of them is held.
pub fn channel_send_unlocked(handle: u64, msg: u64) -> Option<Result<u64, Errno>> {
    crate::arch::cpu::enable_interrupts();
    let m: ChannelMsg = match get_user(msg) {
        Ok(m) => m,
        Err(_) => return None,
    };
    if m.handle_count != 0 {
        return None;
    }
    Some((|| {
        let c = channel(handle)?;
        if m.len > MAX_MESSAGE as u64 {
            return Err(Errno::InvalidArgument);
        }
        let mut data = alloc::vec![0u8; m.len as usize];
        copy_from_user(&mut data, m.data)?;
        c.send(data, Vec::new()).map(|_| 0)
    })())
}

/// `channel_recv` for a caller that accepts no handles, without the entry
/// lock (`None` for other callers).
pub fn channel_recv_unlocked(handle: u64, msg: u64) -> Option<Result<u64, Errno>> {
    crate::arch::cpu::enable_interrupts();
    let m: ChannelMsg = match get_user(msg) {
        Ok(m) => m,
        Err(_) => return None,
    };
    if m.handle_count != 0 {
        return None;
    }
    Some((|| {
        let c = channel(handle)?;
        let cap = (m.len as usize).min(MAX_MESSAGE);
        if !user_range_ok(m.data, cap as u64) {
            return Err(Errno::Fault);
        }
        let received = c.recv(cap, 0)?;
        copy_to_user(m.data, &received.data)?;
        Ok(received.data.len() as u64)
    })())
}

/// `wait_handles` without the entry lock when every object polls under its
/// own spinlocks (devices take the normal path).
pub fn wait_handles_unlocked(items_ptr: u64, count: u64, timeout_ns: u64) -> Option<Result<u64, Errno>> {
    if count == 0 || count > MAX_WAIT_ITEMS as u64 {
        return None;
    }
    crate::arch::cpu::enable_interrupts();
    let mut items = alloc::vec![WaitItem::default(); count as usize];
    // SAFETY: plain repr(C) array.
    let bytes = unsafe { core::slice::from_raw_parts_mut(items.as_mut_ptr() as *mut u8, items.len() * 16) };
    copy_from_user(bytes, items_ptr).ok()?;
    let mut waitables = Vec::with_capacity(items.len());
    for it in &items {
        let w = process::get_object(it.handle).ok()?.waitable();
        if matches!(w, object::Waitable::Device(_)) {
            return None;
        }
        waitables.push((w, it.events));
    }
    Some(finish_wait(items, items_ptr, &waitables, timeout_ns))
}

fn finish_wait(mut items: Vec<WaitItem>, items_ptr: u64, waitables: &[(object::Waitable, u32)], timeout_ns: u64) -> Result<u64, Errno> {
    let deadline = if timeout_ns == 0 { Some(0) } else { crate::waitq::deadline_after_ns(timeout_ns) };
    let revents = object::wait_any(waitables, deadline)?;
    let mut ready = 0;
    for (it, r) in items.iter_mut().zip(revents) {
        it.revents = r;
        if r != 0 {
            ready += 1;
        }
    }
    // SAFETY: plain repr(C) array.
    let bytes = unsafe { core::slice::from_raw_parts(items.as_ptr() as *const u8, items.len() * 16) };
    copy_to_user(items_ptr, bytes)?;
    Ok(ready)
}

pub fn channel_send(handle: u64, msg: u64) -> Result<u64, Errno> {
    let c = channel(handle)?;
    let m: ChannelMsg = get_user(msg)?;
    if m.len > MAX_MESSAGE as u64 || m.handle_count > MAX_MESSAGE_HANDLES as u64 {
        return Err(Errno::InvalidArgument);
    }
    let mut data = alloc::vec![0u8; m.len as usize];
    copy_from_user(&mut data, m.data)?;
    let mut objects = Vec::new();
    if m.handle_count > 0 {
        let mut hs = [0u64; MAX_MESSAGE_HANDLES];
        // SAFETY: plain u64 array.
        let bytes = unsafe { core::slice::from_raw_parts_mut(hs.as_mut_ptr() as *mut u8, m.handle_count as usize * 8) };
        copy_from_user(bytes, m.handles)?;
        for &h in &hs[..m.handle_count as usize] {
            let o = process::get_object(h)?;
            if !o.transferable() {
                return Err(Errno::InvalidArgument);
            }
            objects.push(o);
        }
    }
    c.send(data, objects).map(|_| 0)
}

pub fn channel_recv(handle: u64, msg: u64) -> Result<u64, Errno> {
    let c = channel(handle)?;
    let m: ChannelMsg = get_user(msg)?;
    let cap = (m.len as usize).min(MAX_MESSAGE);
    let max_objects = (m.handle_count as usize).min(MAX_MESSAGE_HANDLES);
    if !user_range_ok(m.data, cap as u64) || (max_objects > 0 && !user_range_ok(m.handles, max_objects as u64 * 8)) {
        return Err(Errno::Fault);
    }
    let received = c.recv(cap, max_objects)?;
    let len = received.data.len();
    copy_to_user(m.data, &received.data)?;
    let handles = if received.objects.is_empty() { Vec::new() } else { process::add_objects(received.objects)? };
    if !handles.is_empty() {
        // SAFETY: plain u64 array.
        let bytes = unsafe { core::slice::from_raw_parts(handles.as_ptr() as *const u8, handles.len() * 8) };
        copy_to_user(m.handles, bytes)?;
    }
    let out = ChannelMsg { handle_count: handles.len() as u64, ..m };
    put_user(msg, &out)?;
    Ok(len as u64)
}

pub fn channel_peer(handle: u64) -> Result<u64, Errno> {
    let (pid, uid) = channel(handle)?.peer_identity();
    Ok(pid | (uid as u64) << 32)
}

pub fn shm_create(size: u64) -> Result<u64, Errno> {
    process::add_object(Object::Shm(shm::SharedMemory::new(size)?))
}

pub fn shm_map(handle: u64, prot: u64) -> Result<u64, Errno> {
    if prot & PROT_EXEC != 0 || prot & PROT_READ == 0 || prot & !(PROT_READ | PROT_WRITE) != 0 {
        return Err(Errno::InvalidArgument);
    }
    let o = process::get_object(handle)?;
    let s = o.shm()?.clone();
    process::map_shared(s, prot & PROT_WRITE != 0)
}

pub fn shm_size(handle: u64) -> Result<u64, Errno> {
    Ok(process::get_object(handle)?.shm()?.size())
}

pub fn filemap_create(file: u64, size: u64, writable: u64) -> Result<u64, Errno> {
    if writable > 1 { return Err(Errno::InvalidArgument); }
    let Object::File(file) = process::get_object(file)? else { return Err(Errno::BadHandle) };
    let section = crate::filemap::create(file, size, writable != 0)?;
    process::add_object(Object::FileMap(section))
}

pub fn filemap_map(handle: u64, offset: u64, len: u64, writable: u64) -> Result<u64, Errno> {
    if writable > 1 { return Err(Errno::InvalidArgument); }
    let Object::FileMap(section) = process::get_object(handle)? else { return Err(Errno::BadHandle) };
    crate::filemap::Section::map(&section, offset, len, writable != 0)
}

/// The shared-image key of `file` at `[addr, addr + len)` for the caller.
fn image_key(file: u64, addr: u64, len: u64) -> Result<crate::image::Key, Errno> {
    let Object::File(file) = process::get_object(file)? else { return Err(Errno::BadHandle) };
    let st = file.lock().stat()?;
    if st.kind != osyx_abi::KIND_FILE || len == 0 || !addr.is_multiple_of(crate::mem::PAGE_SIZE) {
        return Err(Errno::InvalidArgument);
    }
    let (cred, _) = process::current_identity();
    Ok(crate::image::Key {
        dev: st.dev,
        ino: st.ino,
        size: st.size,
        mtime_ns: st.mtime_ns,
        base: addr,
        pages: len.div_ceil(crate::mem::PAGE_SIZE),
        uid: cred.uid,
    })
}

pub fn image_map(file: u64, addr: u64, len: u64) -> Result<u64, Errno> {
    let key = image_key(file, addr, len)?;
    let section = crate::image::lookup(&key).ok_or(Errno::NotFound)?;
    process::image_map(section).map(|_| 0)
}

pub fn image_query(file: u64) -> Result<u64, Errno> {
    let key = image_key(file, 0, crate::mem::PAGE_SIZE)?;
    crate::image::base_of(&key).ok_or(Errno::NotFound)
}

pub fn image_publish(file: u64, addr: u64, len: u64) -> Result<u64, Errno> {
    let key = image_key(file, addr, len)?;
    if crate::image::lookup(&key).is_some() {
        return Err(Errno::AlreadyExists);
    }
    let section = process::image_publish(key)?;
    crate::image::insert(&section);
    let (live, frames, hits, published) = crate::image::stats();
    crate::kprintln!(
        "image: published {} KiB at {addr:#x} ({live} live, {} MiB, {hits} reuses, {published} published)",
        len >> 10,
        frames >> 8
    );
    Ok(0)
}

pub fn filemap_flush(handle: u64, offset: u64, len: u64) -> Result<u64, Errno> {
    let Object::FileMap(section) = process::get_object(handle)? else { return Err(Errno::BadHandle) };
    section.flush(offset, len).map(|_| 0)
}

pub fn wait_handles(items_ptr: u64, count: u64, timeout_ns: u64) -> Result<u64, Errno> {
    if count == 0 || count > MAX_WAIT_ITEMS as u64 {
        return Err(Errno::InvalidArgument);
    }
    let mut items = alloc::vec![WaitItem::default(); count as usize];
    // SAFETY: plain repr(C) array.
    let bytes = unsafe { core::slice::from_raw_parts_mut(items.as_mut_ptr() as *mut u8, items.len() * 16) };
    copy_from_user(bytes, items_ptr)?;
    let mut waitables = Vec::with_capacity(items.len());
    for it in &items {
        waitables.push((process::get_object(it.handle)?.waitable(), it.events));
    }
    finish_wait(items, items_ptr, &waitables, timeout_ns)
}

pub fn display_info(out: u64) -> Result<u64, Errno> {
    let info = crate::display::info().ok_or(Errno::NotSupported)?;
    put_user(out, &info)?;
    Ok(0)
}

pub fn display_acquire() -> Result<u64, Errno> {
    let (cred, _) = process::current_identity();
    if !cred.is_root() {
        return Err(Errno::PermissionDenied);
    }
    let pid = sched::current_pid();
    let fb = crate::display::acquire(pid)?;
    match process::map_shared(fb, true) {
        Ok(addr) => Ok(addr),
        Err(e) => {
            crate::display::release(pid);
            Err(e)
        }
    }
}

pub fn display_flush(x: u64, y: u64, w: u64, h: u64) -> Result<u64, Errno> {
    let clamp = |v: u64| v.min(u32::MAX as u64) as u32;
    crate::display::flush(sched::current_pid(), clamp(x), clamp(y), clamp(w), clamp(h)).map(|_| 0)
}

pub fn display_set_mode(width: u64, height: u64) -> Result<u64, Errno> {
    let (cred, _) = process::current_identity();
    if !cred.is_root() {
        return Err(Errno::PermissionDenied);
    }
    if width > 16384 || height > 16384 {
        return Err(Errno::InvalidArgument);
    }
    crate::display::set_mode(sched::current_pid(), width as u32, height as u32).map(|_| 0)
}

pub fn display_release() -> Result<u64, Errno> {
    if crate::display::release(sched::current_pid()) {
        Ok(0)
    } else {
        Err(Errno::PermissionDenied)
    }
}

pub fn proc_info(pid: u64, out: u64) -> Result<u64, Errno> {
    put_user(out, &process::info(pid)?)?;
    Ok(0)
}

pub fn proc_list(buf: u64, len: u64) -> Result<u64, Errno> {
    put_slice(buf, len, &process::list())
}

pub fn device_list(buf: u64, len: u64) -> Result<u64, Errno> {
    use osyx_abi::ipc::{fill_field, DeviceInfo};
    let mut list = Vec::new();
    for d in crate::pci::enumerate() {
        let mut info = DeviceInfo::default();
        let wifi = crate::wireless::pci_name(&d);
        let description = match &wifi {
            Some(name) => name.clone(),
            None => alloc::format!("PCI {:04x}:{:04x} {}", d.vendor, d.device, crate::pci::class_name(d.class, d.subclass)),
        };
        fill_field(&mut info.description, &description);
        fill_field(
            &mut info.class,
            match d.class {
                _ if wifi.is_some() => "Wireless",
                1 => "Storage",
                2 => "Net",
                3 => "Display",
                0x0c if d.subclass == 3 => "USB",
                _ => "System",
            },
        );
        fill_field(&mut info.hardware_id, &alloc::format!("PCI\\VEN_{:04X}&DEV_{:04X}", d.vendor, d.device));
        fill_field(&mut info.location, &alloc::format!("PCI {}", d.addr));
        list.push(info);
    }
    for b in crate::wireless::bluetooth() {
        let mut info = DeviceInfo::default();
        fill_field(&mut info.description, &b.name);
        fill_field(&mut info.class, "Bluetooth");
        fill_field(&mut info.hardware_id, &b.hardware_id);
        fill_field(&mut info.location, &alloc::format!("USB {}", b.location));
        list.push(info);
    }
    for (id, name, class, _) in crate::input::devices() {
        let mut info = DeviceInfo::default();
        fill_field(&mut info.description, &name);
        fill_field(&mut info.class, if class == osyx_input::class::KEYBOARD { "Keyboard" } else { "Mouse" });
        fill_field(&mut info.hardware_id, &alloc::format!("OSYX\\INPUT_{id}"));
        fill_field(&mut info.location, &alloc::format!("/dev/input/event{id}"));
        list.push(info);
    }
    put_slice(buf, len, &list)
}

pub fn mount_list(buf: u64, len: u64) -> Result<u64, Errno> {
    let list: Vec<MountInfo> = crate::vfs::mounts()
        .iter()
        .map(|m| {
            let mut info = MountInfo { dev: m.id, flags: m.flags, ..Default::default() };
            osyx_abi::ipc::fill_field(&mut info.path, &m.path);
            osyx_abi::ipc::fill_field(&mut info.source, &m.source);
            osyx_abi::ipc::fill_field(&mut info.fstype, m.fs.fs_type());
            info
        })
        .collect();
    put_slice(buf, len, &list)
}

pub fn kill(pid: u64) -> Result<u64, Errno> {
    if pid == 0 {
        return Err(Errno::InvalidArgument);
    }
    process::kill(pid).map(|_| 0)
}

pub fn power(cmd: u64) -> Result<u64, Errno> {
    let (cred, _) = process::current_identity();
    if !cred.is_root() {
        return Err(Errno::PermissionDenied);
    }
    match cmd {
        osyx_abi::ipc::POWER_OFF | osyx_abi::ipc::POWER_REBOOT => {
            crate::power::request(cmd == osyx_abi::ipc::POWER_REBOOT)
        }
        _ => Err(Errno::InvalidArgument),
    }
}
