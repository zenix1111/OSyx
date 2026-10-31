//! Common-control class registration and owned image lists.
#![allow(non_snake_case)]
use alloc::vec::Vec;

extern "win64" fn ImageList_Create(cx: i32, cy: i32, _flags: u32, initial: i32, grow: i32) -> u64 {
    crate::user32::image_list_create(cx, cy, initial, grow)
}

extern "win64" fn ImageList_AddMasked(list: u64, bitmap: u64, mask: u32) -> i32 {
    crate::user32::image_list_add_masked(list, bitmap, mask)
}

extern "win64" fn ImageList_Destroy(list: u64) -> i32 {
    crate::user32::image_list_destroy(list)
}

extern "win64" fn InitCommonControls() {
    crate::user32::register_common_controls();
}

pub(crate) fn init_address() -> u64 { InitCommonControls as *const () as u64 }

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![ImageList_Create, ImageList_AddMasked, ImageList_Destroy, InitCommonControls]
}

pub fn ordinals() -> Vec<(u16, u64)> {
    alloc::vec![(17, init_address())]
}
