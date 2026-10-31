//! Minimal PE fixture for the experimental content-process launch path.
#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! { loop {} }

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetCommandLineW() -> *const u16;
    fn CreateProcessW(app: *const u16, cmd: *mut u16, psa: usize, tsa: usize, inherit: i32, flags: u32, env: usize, cwd: usize, startup: *const u8, info: *mut u64) -> i32;
    fn WaitForSingleObject(handle: u64, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(handle: u64, code: *mut u32) -> i32;
    fn CreateFileW(name: *const u16, access: u32, share: u32, security: usize, disposition: u32, flags: u32, template: u64) -> u64;
    fn CloseHandle(handle: u64) -> i32;
    fn CreateEventW(attributes: usize, manual: i32, initial: i32, name: *const u16) -> u64;
    fn SetHandleInformation(handle: u64, mask: u32, flags: u32) -> i32;
    fn ResumeThread(handle: u64) -> u32;
    fn GetStdHandle(which: u32) -> u64;
    fn GetLastError() -> u32;
    fn DuplicateHandle(source_process: u64, source: u64, target_process: u64, target: *mut u64, access: u32, inherit: i32, options: u32) -> i32;
    fn CreateNamedPipeW(name: *const u16, open: u32, mode: u32, max: u32, out_size: u32, in_size: u32, timeout: u32, security: usize) -> u64;
    fn ConnectNamedPipe(pipe: u64, overlapped: usize) -> i32;
    fn WriteFile(handle: u64, buffer: *const u8, len: u32, done: *mut u32, overlapped: usize) -> i32;
    fn ReadFile(handle: u64, buffer: *mut u8, len: u32, done: *mut u32, overlapped: usize) -> i32;
    fn ExitProcess(code: u32) -> !;
}

#[link(name = "bcryptprimitives", kind = "raw-dylib")]
unsafe extern "system" {
    fn ProcessPrng(buffer: *mut u8, len: usize) -> i32;
}

#[no_mangle]
pub extern "system" fn start() -> ! {
    unsafe {
        let mut p = GetCommandLineW();
        let mut child = false;
        while *p != 0 {
            if *p == b'-' as u16 { child = true; break; }
            p = p.add(1);
        }
        if child && *p.add(1) == b'h' as u16 { ExitProcess(7); }
        let mut other_device = [0u16; 32];
        for (i, b) in b"C:\\dev\\zero".iter().enumerate() { *other_device.as_mut_ptr().add(i) = *b as u16; }
        let device = CreateFileW(other_device.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        if child && device != u64::MAX { ExitProcess(34); }
        if !child && device == u64::MAX { ExitProcess(35); }
        if device != u64::MAX { let _ = CloseHandle(device); }
        let mut secret = [0u16; 64];
        for (i, b) in b"C:\\tmp\\sandbox-winrun-secret".iter().enumerate() { *secret.as_mut_ptr().add(i) = *b as u16; }
        let file = CreateFileW(secret.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        if child {
            if file != u64::MAX { ExitProcess(14); }
            let mut random = [0u8; 32];
            if ProcessPrng(random.as_mut_ptr(), 32) == 0 { ExitProcess(33); }
            if GetStdHandle((-10i32) as u32) != u64::MAX || GetStdHandle((-11i32) as u32) != 0 { ExitProcess(25); }
            while *p != 0 && *p != b' ' as u16 { p = p.add(1); }
            if *p == 0 { ExitProcess(15); }
            p = p.add(1);
            let mut event = 0u64;
            while *p >= b'0' as u16 && *p <= b'9' as u16 {
                event = event.wrapping_mul(10).wrapping_add((*p - b'0' as u16) as u64);
                p = p.add(1);
            }
            if event == 0 || WaitForSingleObject(event, 0) != 0 { ExitProcess(16); }
            if *p != b' ' as u16 { ExitProcess(26); }
            p = p.add(1);
            let mut pipe = 0u64;
            while *p >= b'0' as u16 && *p <= b'9' as u16 {
                pipe = pipe.wrapping_mul(10).wrapping_add((*p - b'0' as u16) as u64);
                p = p.add(1);
            }
            let mut written = 0;
            if WriteFile(pipe, b"ping".as_ptr(), 4, &mut written, 0) == 0 { ExitProcess(100 + GetLastError()); }
            if written != 4 { ExitProcess(27); }
            let mut response = [0u8; 4];
            let mut read = 0;
            if ReadFile(pipe, response.as_mut_ptr(), 4, &mut read, 0) == 0 || read != 4 || u32::from_le_bytes(response) != u32::from_le_bytes(*b"pong") { ExitProcess(31); }
            let mut duplicate = [0u64; 2];
            if ReadFile(pipe, duplicate.as_mut_ptr().cast(), 16, &mut read, 0) == 0 || read != 16 || WaitForSingleObject(*duplicate.as_ptr(), 0) != 0 { ExitProcess(36); }
            if WriteFile(*duplicate.as_ptr().add(1), b"late".as_ptr(), 4, &mut written, 0) == 0 || written != 4 { ExitProcess(40); }
            ExitProcess(0);
        }
        if file == u64::MAX { ExitProcess(13); }
        let _ = CloseHandle(file);
        let app: [u16; 20] = [67,58,92,111,112,116,92,122,101,110,92,122,101,110,46,101,120,101,0,0];
        let mut held_cmd = [0u16; 64];
        for (i, b) in b"C:\\opt\\zen\\zen.exe -holdchild".iter().enumerate() { *held_cmd.as_mut_ptr().add(i) = *b as u16; }
        let mut held_startup = [0u64; 13];
        held_startup[0] = 104;
        let mut held_info = [0u64; 3];
        if CreateProcessW(app.as_ptr(), held_cmd.as_mut_ptr(), 0, 0, 0, 4, 0, 0, held_startup.as_ptr() as *const u8, held_info.as_mut_ptr()) == 0 { ExitProcess(18); }
        if WaitForSingleObject(held_info[0], 0) != 258 { ExitProcess(19); }
        if ResumeThread(held_info[1]) != 1 { ExitProcess(20); }
        if WaitForSingleObject(held_info[0], 20_000) != 0 { ExitProcess(21); }
        let mut held_code = 0;
        if GetExitCodeProcess(held_info[0], &mut held_code) == 0 || held_code != 7 { ExitProcess(22); }
        let _ = CloseHandle(held_info[0]);
        let _ = CloseHandle(held_info[1]);
        let event = CreateEventW(0, 1, 1, core::ptr::null());
        if event == 0 || SetHandleInformation(event, 1, 1) == 0 { ExitProcess(17); }
        let mut pipe_name = [0u16; 64];
        for (i, b) in b"\\\\.\\pipe\\osyx-sandbox-test".iter().enumerate() { *pipe_name.as_mut_ptr().add(i) = *b as u16; }
        let server = CreateNamedPipeW(pipe_name.as_ptr(), 3, 0, 1, 4096, 4096, 0, 0);
        if server == u64::MAX { ExitProcess(28); }
        let client = CreateFileW(pipe_name.as_ptr(), 0xc000_0000, 0, 0, 3, 0, 0);
        if client == u64::MAX || SetHandleInformation(client, 1, 1) == 0 { ExitProcess(29); }
        let _ = ConnectNamedPipe(server, 0);
        let mut cmd = [0u16; 100];
        let prefix = b"C:\\opt\\zen\\zen.exe -contentproc ";
        for (i, b) in prefix.iter().enumerate() { *cmd.as_mut_ptr().add(i) = *b as u16; }
        let mut digits = [0u16; 20];
        let mut value = event;
        let mut count = 0;
        while value > 0 { *digits.as_mut_ptr().add(count) = b'0' as u16 + (value % 10) as u16; value /= 10; count += 1; }
        for i in 0..count { *cmd.as_mut_ptr().add(prefix.len() + i) = *digits.as_ptr().add(count - i - 1); }
        let pipe_at = prefix.len() + count;
        *cmd.as_mut_ptr().add(pipe_at) = b' ' as u16;
        value = client;
        count = 0;
        while value > 0 { *digits.as_mut_ptr().add(count) = b'0' as u16 + (value % 10) as u16; value /= 10; count += 1; }
        for i in 0..count { *cmd.as_mut_ptr().add(pipe_at + 1 + i) = *digits.as_ptr().add(count - i - 1); }
        let mut startup = [0u64; 13];
        startup[0] = 104;
        (startup.as_mut_ptr() as *mut u8).add(60).cast::<u32>().write_unaligned(0x100);
        startup[10] = GetStdHandle((-10i32) as u32);
        startup[11] = GetStdHandle((-11i32) as u32);
        startup[12] = GetStdHandle((-12i32) as u32);
        let mut info = [0u64; 3];
        startup[10] = event;
        if CreateProcessW(app.as_ptr(), cmd.as_mut_ptr(), 0, 0, 1, 4, 0, 0, startup.as_ptr() as *const u8, info.as_mut_ptr()) != 0 { ExitProcess(24); }
        startup[10] = u64::MAX;
        startup[11] = 0;
        if CreateProcessW(app.as_ptr(), cmd.as_mut_ptr(), 0, 0, 1, 4, 0, 0, startup.as_ptr() as *const u8, info.as_mut_ptr()) == 0 {
            ExitProcess(10);
        }
        if WaitForSingleObject(info[0], 0) != 258 || ResumeThread(info[1]) != 1 { ExitProcess(23); }
        let mut received = [0u8; 4];
        let mut read = 0;
        if ReadFile(server, received.as_mut_ptr(), 4, &mut read, 0) == 0 || read != 4 || u32::from_le_bytes(received) != u32::from_le_bytes(*b"ping") { ExitProcess(30); }
        let mut written = 0;
        if WriteFile(server, b"pong".as_ptr(), 4, &mut written, 0) == 0 || written != 4 { ExitProcess(32); }
        let late_event = CreateEventW(0, 1, 1, core::ptr::null());
        let mut remote_event = 0u64;
        if DuplicateHandle(u64::MAX, late_event, info[0], &mut remote_event, 0, 0, 2) == 0 { ExitProcess(37); }
        let secret_file = CreateFileW(secret.as_ptr(), 0x8000_0000, 7, 0, 3, 0, 0);
        let mut remote_file = 0u64;
        if secret_file == u64::MAX || DuplicateHandle(u64::MAX, secret_file, info[0], &mut remote_file, 0, 0, 2) != 0 { ExitProcess(39); }
        let mut late_name = [0u16; 64];
        for (i, b) in b"\\\\.\\pipe\\osyx-sandbox-late".iter().enumerate() { *late_name.as_mut_ptr().add(i) = *b as u16; }
        let late_server = CreateNamedPipeW(late_name.as_ptr(), 3, 0, 1, 4096, 4096, 0, 0);
        let late_client = CreateFileW(late_name.as_ptr(), 0xc000_0000, 0, 0, 3, 0, 0);
        if late_server == u64::MAX || late_client == u64::MAX { ExitProcess(41); }
        let _ = ConnectNamedPipe(late_server, 0);
        let mut remote_pipe = 0u64;
        if DuplicateHandle(u64::MAX, late_client, info[0], &mut remote_pipe, 0, 0, 2) == 0 { ExitProcess(42); }
        let handles = [remote_event, remote_pipe];
        if WriteFile(server, handles.as_ptr().cast(), 16, &mut written, 0) == 0 || written != 16 { ExitProcess(38); }
        if ReadFile(late_server, received.as_mut_ptr(), 4, &mut read, 0) == 0 || read != 4 || u32::from_le_bytes(received) != u32::from_le_bytes(*b"late") { ExitProcess(43); }
        if WaitForSingleObject(info[0], 20_000) != 0 { ExitProcess(11); }
        let mut code = 0;
        if GetExitCodeProcess(info[0], &mut code) == 0 || code != 0 { ExitProcess(12); }
        ExitProcess(0);
    }
}
