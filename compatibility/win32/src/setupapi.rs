//! Read-only SetupAPI inventory. No device installation or registry emulation.
#![allow(non_snake_case)]
use crate::{
    error::*,
    kernel32::{fail, out_w},
    teb,
};
use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use os_std::{sync::Mutex, system};
use osyx_abi::ipc::DeviceInfo;

static SETS: Mutex<BTreeMap<u64, Vec<DeviceInfo>>> = Mutex::new(BTreeMap::new());
static NEXT: AtomicU64 = AtomicU64::new(0x4000_0000);

extern "win64" fn SetupDiGetClassDevsW(guid: u64, enumerator: u64, _parent: u64, flags: u32) -> u64 {
    if guid != 0 || enumerator != 0 || flags & !6 != 0 || flags & 4 == 0 {
        return fail(ERROR_NOT_SUPPORTED, u64::MAX);
    }
    match system::devices() {
        Ok(list) => {
            let h = NEXT.fetch_add(4, Ordering::Relaxed);
            SETS.lock().unwrap().insert(h, list);
            h
        }
        Err(_) => fail(ERROR_GEN_FAILURE, u64::MAX),
    }
}

fn class_id(class: &str) -> u32 {
    match class {
        "Display" => 0x4d36e968,
        "Keyboard" => 0x4d36e96b,
        "Mouse" => 0x4d36e96f,
        "Net" => 0x4d36e972,
        "USB" => 0x36fc9e60,
        "Storage" => 0x4d36e97b,
        _ => 0x4d36e97d,
    }
}

extern "win64" fn SetupDiEnumDeviceInfo(set: u64, index: u32, data: u64) -> i32 {
    if data == 0 || unsafe { teb::get::<u32>(data, 0) } != 32 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let sets = SETS.lock().unwrap();
    let Some(list) = sets.get(&set) else {
        return fail(ERROR_INVALID_HANDLE, 0);
    };
    let Some(d) = list.get(index as usize) else {
        return fail(ERROR_NO_MORE_ITEMS, 0);
    };
    let usb = system::field_str(&d.class) == "USB";
    // SP_DEVINFO_DATA's GUID, DevInst, and private index. Output is 32 bytes.
    unsafe {
        core::ptr::write_bytes((data + 4) as *mut u8, 0, 28);
        teb::put(data, 4, class_id(system::field_str(&d.class)));
        teb::put(data, 8, if usb { 0xc465u16 } else { 0xe325u16 });
        teb::put(data, 10, if usb { 0x11cfu16 } else { 0x11ceu16 });
        let tail: [u8; 8] =
            if usb { [0x80, 0x56, 0x44, 0x45, 0x53, 0x54, 0, 0] } else { [0xbf, 0xc1, 8, 0, 0x2b, 0xe1, 3, 0x18] };
        core::ptr::copy_nonoverlapping(tail.as_ptr(), (data + 12) as *mut u8, 8);
        teb::put(data, 20, index + 1);
        teb::put(data, 24, index as u64);
    }
    1
}

extern "win64" fn SetupDiGetDeviceRegistryPropertyW(
    set: u64,
    data: u64,
    prop: u32,
    kind: *mut u32,
    buf: *mut u16,
    bytes: u32,
    required: *mut u32,
) -> i32 {
    if data == 0 || unsafe { teb::get::<u32>(data, 0) } != 32 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let sets = SETS.lock().unwrap();
    let Some(list) = sets.get(&set) else {
        return fail(ERROR_INVALID_HANDLE, 0);
    };
    let index = unsafe { teb::get::<u64>(data, 24) } as usize;
    let Some(d) = list.get(index) else {
        return fail(ERROR_INVALID_PARAMETER, 0);
    };
    let text = match prop {
        0 | 12 => system::field_str(&d.description),
        1 => system::field_str(&d.hardware_id),
        7 => system::field_str(&d.class),
        13 => system::field_str(&d.location),
        _ => return fail(ERROR_NOT_SUPPORTED, 0),
    };
    let n = text.encode_utf16().count() + if prop == 1 { 2 } else { 1 };
    unsafe {
        if !required.is_null() {
            *required = n as u32 * 2;
        }
        if !kind.is_null() {
            *kind = if prop == 1 { 7 } else { 1 };
        }
    }
    if buf.is_null() || bytes < (n * 2) as u32 {
        return fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    out_w(text, buf, bytes / 2);
    if prop == 1 {
        unsafe {
            *buf.add(n - 1) = 0;
        }
    }
    1
}

extern "win64" fn SetupDiDestroyDeviceInfoList(set: u64) -> i32 {
    if SETS.lock().unwrap().remove(&set).is_some() {
        1
    } else {
        fail(ERROR_INVALID_HANDLE, 0)
    }
}

extern "win64" fn SetupDiEnumDeviceInterfaces(set: u64, _dev: u64, guid: u64, _index: u32, data: u64) -> i32 {
    if guid == 0 || data == 0 || unsafe { teb::get::<u32>(data, 0) } != 32 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if !SETS.lock().unwrap().contains_key(&set) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    fail(ERROR_NO_MORE_ITEMS, 0)
}

extern "win64" fn SetupDiGetDeviceInterfaceDetailW(
    set: u64,
    iface_data: u64,
    _detail: u64,
    _detail_size: u32,
    _required: *mut u32,
    _dev_data: u64,
) -> i32 {
    if iface_data == 0 || unsafe { teb::get::<u32>(iface_data, 0) } != 32 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    if !SETS.lock().unwrap().contains_key(&set) {
        return fail(ERROR_INVALID_HANDLE, 0);
    }
    fail(ERROR_NO_MORE_ITEMS, 0)
}

#[allow(clippy::too_many_arguments)]
extern "win64" fn SetupDiGetDevicePropertyW(
    set: u64,
    data: u64,
    key: u64,
    prop_type: *mut u32,
    _buf: *mut u8,
    _size: u32,
    _required: *mut u32,
    flags: u32,
) -> i32 {
    if data == 0 || unsafe { teb::get::<u32>(data, 0) } != 32 || key == 0 || prop_type.is_null() || flags != 0 {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    let sets = SETS.lock().unwrap();
    let Some(list) = sets.get(&set) else {
        return fail(ERROR_INVALID_HANDLE, 0);
    };
    let index = unsafe { teb::get::<u64>(data, 24) } as usize;
    if index >= list.len() {
        return fail(ERROR_INVALID_PARAMETER, 0);
    }
    fail(ERROR_NOT_FOUND, 0)
}

extern "win64" fn SetupDiOpenDevRegKey(
    set: u64,
    data: u64,
    _scope: u32,
    _hw_profile: u32,
    _key_type: u32,
    _sam: u32,
) -> u64 {
    if data == 0 || unsafe { teb::get::<u32>(data, 0) } != 32 {
        return fail(ERROR_INVALID_PARAMETER, u64::MAX);
    }
    if !SETS.lock().unwrap().contains_key(&set) {
        return fail(ERROR_INVALID_HANDLE, u64::MAX);
    }
    fail(ERROR_FILE_NOT_FOUND, u64::MAX)
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        SetupDiGetClassDevsW,
        SetupDiEnumDeviceInfo,
        SetupDiEnumDeviceInterfaces,
        SetupDiGetDeviceInterfaceDetailW,
        SetupDiGetDeviceRegistryPropertyW,
        SetupDiGetDevicePropertyW,
        SetupDiOpenDevRegKey,
        SetupDiDestroyDeviceInfoList
    ]
}
