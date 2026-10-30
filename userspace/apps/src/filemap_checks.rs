//! Exercise kernel file-section capabilities without the Windows shim.
use os_std::{fs, os::raw, prelude::*, thread, time::Duration};
use raw::Errno;

pub fn run() -> i32 {
    let mut failed = 0;
    for path in ["/tmp/filemap-kernel.bin", "/osyx-filemap-kernel.bin"] {
        let result = checks(path);
        println!("filemap: {path}: {result:?}");
        failed += result.is_err() as i32;
    }
    failed
}

fn checks(path: &str) -> Result<(), Errno> {
    let fd = raw::open(path, raw::OPEN_READ | raw::OPEN_WRITE | raw::OPEN_CREATE | raw::OPEN_TRUNCATE, 0o600)?;
    let section = raw::filemap_create(fd, 8192, true)?;
    let view = raw::filemap_map(section, 0, 8192, true)?;
    // SAFETY: the writable mapping covers both bytes.
    unsafe {
        view.add(17).write(0x41);
        view.add(4101).write(0x52);
    }
    let ro_fd = raw::open(path, raw::OPEN_READ, 0)?;
    let ro = raw::filemap_create(ro_fd, 0, false)?;
    let alias = raw::filemap_map(ro, 4096, 4096, false)?;
    let rights = raw::filemap_map(ro, 0, 4096, true) == Err(Errno::PermissionDenied)
        && raw::filemap_create(ro_fd, 8192, true) == Err(Errno::PermissionDenied)
        && raw::shm_map(ro, true) == Err(Errno::BadHandle)
        && raw::filemap_map(ro, 1, 4096, false) == Err(Errno::InvalidArgument)
        && raw::filemap_map(ro, 4096, 8192, false) == Err(Errno::InvalidArgument)
        && raw::filemap_flush(section, 8191, 2) == Err(Errno::InvalidArgument)
        && raw::ftruncate(fd, 0) == Err(Errno::Busy)
        && raw::open(path, raw::OPEN_WRITE | raw::OPEN_TRUNCATE, 0) == Err(Errno::Busy);
    // SAFETY: alias is a readable mapping of the second file page.
    let shared = unsafe { alias.add(5).read() == 0x52 };
    raw::close(section)?;
    raw::close(ro)?;
    raw::close(ro_fd)?;
    // Handles can close before their views; delayed writeback must retain
    // modifications when the last view disappears, on tmpfs and ext4.
    unsafe {
        raw::unmap(alias, 4096)?;
        raw::unmap(view, 8192)?;
    }
    raw::close(fd)?;
    let mut persisted = false;
    for _ in 0..30 {
        thread::sleep(Duration::from_millis(100));
        if fs::read(path).is_ok_and(|b| b.len() == 8192 && b[17] == 0x41 && b[4101] == 0x52) {
            persisted = true;
            break;
        }
    }
    // Truncating an unused backing must never resurrect stale pages.
    let fd = raw::open(path, raw::OPEN_READ | raw::OPEN_WRITE | raw::OPEN_TRUNCATE, 0)?;
    let section = raw::filemap_create(fd, 100, true)?;
    let fresh = raw::filemap_map(section, 0, 100, false)?;
    let zero = unsafe { fresh.add(17).read() == 0 } && raw::fstat(fd)?.size == 100;
    raw::close(section)?;
    unsafe {
        raw::unmap(fresh, 4096)?;
    }
    raw::ftruncate(fd, 0)?;
    raw::close(fd)?;
    // A read-only view of a fresh backing reads its pages on the first
    // touch, not when the section is mapped.
    let mut content = [0u8; 8192];
    content[7] = 0x5A;
    content[4096 + 9] = 0x6B;
    fs::write(path, content).map_err(|_| Errno::Io)?;
    let lazy_fd = raw::open(path, raw::OPEN_READ, 0)?;
    let lazy_section = raw::filemap_create(lazy_fd, 0, false)?;
    let lazy = raw::filemap_map(lazy_section, 4096, 4096, false)?;
    let lazy_ok = unsafe { lazy.add(9).read() == 0x6B };
    raw::close(lazy_section)?;
    raw::close(lazy_fd)?;
    unsafe {
        raw::unmap(lazy, 4096)?;
    }
    let _ = fs::remove_file(path);
    if rights && shared && persisted && zero && lazy_ok {
        Ok(())
    } else {
        println!(
            "filemap: rights={rights} shared={shared} persisted={persisted} fresh={zero} lazy={lazy_ok}"
        );
        Err(Errno::Io)
    }
}
