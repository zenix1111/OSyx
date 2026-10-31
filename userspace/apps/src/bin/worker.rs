//! Child program used by `init` to exercise processes and the scheduler.
//!
//! Modes (first argument):
//! * `exit N`      exit with status N
//! * `spin MS`     busy-loop for MS milliseconds without ever yielding
//! * `fpu SEED MS` keep a pattern in xmm0-xmm15 while spinning MS ms; exit 0
//!   if the registers survived preemption, 1 otherwise
//! * `sleep MS`    sleep; exit 0 if at least MS ms passed
//! * `fault`       read an unmapped address (the kernel terminates us)
//! * `child N`     spawn `worker exit N`, wait, exit with its status
//! * `orphan`      spawn `worker sleep 100` and exit without waiting
//! * `threads-exit` return 42 from main while 4 threads are blocked/spinning
//! * `thread-last` main thread exits first (5); the last thread exits with 9
//! * `thread-fault` / `thread-panic`: a spawned thread faults / panics
//! * `fs-write PATH` write "written by worker <pid>" to PATH
//! * `fs-leak PATH`  write PATH, then exit with 11 handles still open
//! * `pwd DIR`       exit 0 if the inherited current directory is DIR
//! * `hold-orphan P` create P (1 MiB), remove it, keep it open, sleep
//! * `as-user UID`   drop root, then check that permissions confine us;
//!   exit status = number of failed checks
//! * `exec-report HANDLE_FILE REPORT` open HANDLE_FILE (handle 3), change
//!   to /tmp, then `exec` `probe report REPORT` with `FROM=worker` added
//! * `exec-fail`     failing `exec`s must return the right errors and leave
//!   this program running; exit 0 if they did
//! * `exec-threads`  `exec` with a second thread alive must fail with
//!   `ResourceBusy`; exit 0 if it did
//! * `echo-stdin`    copy standard input to standard output in upper case,
//!   then print "stdin bytes: N"
//! * `ipc-client S`  connect to service S, fill the shared memory it sends,
//!   answer "done <pid>"

#![no_std]
#![no_main]

use os_std::prelude::*;
use os_std::process::{self, Command};
use os_std::sync::atomic::AtomicU32;
use os_std::time::{Duration, Instant};
use os_std::fs::{self, File};
use os_std::{env, thread};
#[path="../fault_checks.rs"]
mod fault_checks;
#[path = "../filemap_checks.rs"]
mod filemap_checks;

#[path = "../fpu.rs"]
mod fpu;

os_std::entry!(main);

fn arg_num(args: &[String], i: usize) -> u64 {
    args.get(i).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn main() -> i32 {
    let args: Vec<String> = env::args().collect();
    let pid = process::id().unwrap_or(0);
    match args.get(1).map(String::as_str) {
        Some("suspend-test") => {
            if os_sys::resume_child(pid) != Err(osyx_abi::Errno::PermissionDenied) { return 53; }
            let marker = "/tmp/suspended-process-test";
            let _ = fs::remove_file(marker);
            let stdio = [os_sys::HANDLE_NONE; 3];
            let pid = match os_sys::spawn_stdio_suspended("/bin/worker", b"worker\0suspend-child\0", b"", stdio) {
                Ok(pid) => pid, Err(_) => return 40,
            };
            thread::sleep(Duration::from_millis(40));
            if fs::metadata(marker).is_ok() { return 41; }
            if os_sys::resume_child(pid) != Ok(1) || os_sys::resume_child(pid) != Ok(0) { return 42; }
            if !matches!(os_sys::wait(pid), Ok((_, 0))) || fs::metadata(marker).is_err() { return 43; }
            let _ = fs::remove_file(marker);
            let pid = match os_sys::spawn_stdio_suspended("/bin/worker", b"worker\0suspend-child\0", b"", stdio) {
                Ok(pid) => pid, Err(_) => return 44,
            };
            if os_sys::kill(pid).is_err() || !matches!(os_sys::wait(pid), Ok((_, osyx_abi::KILLED_STATUS))) { return 45; }
            if fs::metadata(marker).is_ok() { return 46; }
            let pid_file = "/tmp/suspended-orphan-test";
            let _ = fs::remove_file(pid_file);
            if !matches!(Command::new("/bin/worker").arg("suspend-orphan").status(), Ok(s) if s.raw() == 0) { return 48; }
            let orphan = match fs::read_to_string(pid_file).ok().and_then(|s| s.parse::<u64>().ok()) { Some(pid) => pid, None => return 49 };
            let _ = fs::remove_file(pid_file);
            for _ in 0..100 {
                if matches!(os_sys::proc_info(orphan), Err(osyx_abi::Errno::NotFound)) { return 0; }
                thread::sleep(Duration::from_millis(10));
            }
            return 50;
        }
        Some("suspend-orphan") => {
            let pid = match os_sys::spawn_stdio_suspended("/bin/worker", b"worker\0suspend-child\0", b"", [os_sys::HANDLE_NONE; 3]) {
                Ok(pid) => pid, Err(_) => return 51,
            };
            if fs::write("/tmp/suspended-orphan-test", format!("{pid}")).is_ok() { 0 } else { 52 }
        }
        Some("suspend-child") => {
            thread::sleep(Duration::from_millis(50));
            if fs::write("/tmp/suspended-process-test", b"ran").is_ok() { 0 } else { 47 }
        }
        Some("sandbox-broker") => {
            use osyx_abi::sandbox::{PathRule, SpawnPolicy, MAX_PATH_RULES, PATH_EXEC, PATH_READ};
            let invalid = SpawnPolicy { path_count: MAX_PATH_RULES + 1, ..SpawnPolicy::default() };
            if os_std::os::raw::raw_syscall(osyx_abi::nr::SPAWN_RESTRICTED, 0, &invalid as *const _ as u64, 0)
                != Err(osyx_abi::Errno::InvalidArgument) {
                return 23;
            }
            if os_std::os::raw::raw_syscall(osyx_abi::nr::CHANNEL_PAIR, 0, 0, 0) != Err(osyx_abi::Errno::Fault) {
                return 33;
            }
            let path = "/bin";
            let rules = [PathRule { path: path.as_ptr() as u64, path_len: path.len() as u64, access: PATH_READ | PATH_EXEC }];
            let calls: Vec<u64> = (0..256).filter(|n| *n != osyx_abi::nr::CPU_INFO).collect();
            let pid = match os_sys::spawn_restricted("/bin/worker", b"worker\0sandbox\0", b"", &rules, &calls) {
                Ok(pid) => pid,
                Err(_) => return 20,
            };
            if !matches!(os_sys::wait(pid), Ok((_, 0))) { return 21; }
            let (peer, endpoint) = match os_sys::channel_pair() { Ok(pair) => pair, Err(_) => return 24 };
            let file = match os_sys::open("/bin/worker", osyx_abi::OPEN_READ, 0) { Ok(file) => file, Err(_) => return 34 };
            if os_sys::spawn_restricted_with_channels("/bin/worker", b"worker\0exit\00\0", b"", &rules, &calls, endpoint, 0, &[file]) != Err(osyx_abi::Errno::InvalidArgument) { return 35; }
            if os_sys::grant_child_channel(process::id().unwrap_or(0), file) != Err(osyx_abi::Errno::InvalidArgument) { return 38; }
            let _ = os_sys::close(file);
            if os_sys::grant_child_channel(process::id().unwrap_or(0), endpoint) != Err(osyx_abi::Errno::PermissionDenied) { return 39; }
            let too_many = [endpoint; 33];
            if os_sys::spawn_restricted_with_channels("/bin/worker", b"worker\0exit\00\0", b"", &rules, &calls, endpoint, 0, &too_many) != Err(osyx_abi::Errno::InvalidArgument) { return 36; }
            if os_sys::spawn_restricted_with_channels("/bin/worker", b"worker\0exit\00\0", b"", &rules, &calls, os_sys::HANDLE_NONE, 0, &[endpoint]) != Err(osyx_abi::Errno::InvalidArgument) { return 37; }
            if os_sys::channel_send(peer, b"request", &[]).is_err() { return 27; }
            let pid = match os_sys::spawn_restricted_with_broker("/bin/worker", b"worker\0sandbox-channel\0", b"", &rules, &calls, endpoint) {
                Ok(pid) => pid,
                Err(_) => return 28,
            };
            let _ = os_sys::close(endpoint);
            if !matches!(os_sys::wait(pid), Ok((_, 0))) { return 29; }
            let mut reply = [0u8; 16];
            if !matches!(os_sys::channel_recv(peer, &mut reply, &mut []), Ok((5, 0))) || &reply[..5] != b"reply" { return 30; }
            let _ = os_sys::close(peer);
            return 0;
        }
        Some("sandbox-channel") => {
            if os_sys::grant_child_channel(process::id().unwrap_or(0), 3) != Err(osyx_abi::Errno::PermissionDenied) { return 40; }
            let mut request = [0u8; 16];
            if !matches!(os_sys::channel_recv(3, &mut request, &mut []), Ok((7, 0))) || &request[..7] != b"request" { return 31; }
            if os_sys::channel_send(3, b"reply", &[]).is_err() { return 32; }
            0
        }
        Some("sandbox") | Some("sandbox-child") | Some("sandbox-exec") => {
            use os_std::os::raw;
            if raw::raw_syscall(raw::nr::CPU_INFO, 0, 0, 0) != Err(raw::Errno::PermissionDenied) {
                return 10;
            }
            if raw::open("/tmp/sandbox-secret", raw::OPEN_READ, 0) != Err(raw::Errno::PermissionDenied) {
                return 11;
            }
            if raw::raw_syscall(raw::nr::GETTID, 0, 0, 0).is_err() {
                return 12;
            }
            if raw::raw_syscall(raw::nr::KILL, u64::MAX, 0, 0) != Err(raw::Errno::PermissionDenied) {
                return 17;
            }
            if raw::raw_syscall(raw::nr::CHANNEL_LISTEN, 0, 0, 0) != Err(raw::Errno::PermissionDenied)
                || raw::raw_syscall(raw::nr::CHANNEL_CONNECT, 0, 0, 0) != Err(raw::Errno::PermissionDenied) {
                return 18;
            }
            if raw::raw_syscall(raw::nr::SPAWN_RESTRICTED, 0, 0, 0) != Err(raw::Errno::PermissionDenied) {
                return 22;
            }
            let file = match raw::open("/bin/worker", raw::OPEN_READ, 0) {
                Ok(file) => file,
                Err(_) => return 14,
            };
            if raw::raw_syscall(raw::nr::IMAGE_PUBLISH, file, 0, 0) != Err(raw::Errno::PermissionDenied) {
                return 15;
            }
            let result = Command::new("/bin/worker").arg("exit").arg("0")
                .spawn_stdio([file, raw::HANDLE_NONE, raw::HANDLE_NONE]);
            if !matches!(result, Err(ref error) if error.kind() == os_std::error::ErrorKind::PermissionDenied) {
                return 16;
            }
            let _ = raw::close(file);
            if args[1] == "sandbox" {
                return match Command::new("/bin/worker").arg("sandbox-child").status() {
                    Ok(status) => status.raw(),
                    Err(_) => 13,
                };
            }
            if args[1] == "sandbox-child" {
                let _ = Command::new("/bin/worker").arg("sandbox-exec").exec();
                return 19;
            }
            0
        }
        Some("exit") => arg_num(&args, 2) as i32,
        Some("spin") => {
            let ms = arg_num(&args, 2);
            let start = Instant::now();
            println!("spin {pid}: started at {} ms", start.as_nanos_since_boot() / 1_000_000);
            let mut rounds = 0u64;
            while start.elapsed() < Duration::from_millis(ms) {
                rounds = rounds.wrapping_add(1);
            }
            println!(
                "spin {pid}: finished at {} ms after {rounds} rounds",
                Instant::now().as_nanos_since_boot() / 1_000_000
            );
            0
        }
        Some("fpu") => {
            let seed = arg_num(&args, 2) << 32;
            let ms = arg_num(&args, 3);
            let spin = || {
                let start = Instant::now();
                while start.elapsed() < Duration::from_millis(ms) {
                    core::hint::spin_loop();
                }
            };
            if fpu::preserved_across(seed, spin) {
                0
            } else {
                eprintln!("fpu {pid}: XMM registers were corrupted");
                1
            }
        }
        Some("sleep") => {
            let ms = arg_num(&args, 2);
            let start = Instant::now();
            thread::sleep(Duration::from_millis(ms));
            (start.elapsed() < Duration::from_millis(ms)) as i32
        }
        Some("fault") => {
            // SAFETY: deliberately invalid; the kernel terminates the process.
            let v = unsafe { core::ptr::read_volatile(0x1000 as *const u64) };
            v as i32
        }
        Some("child") => match Command::new("worker").arg("exit").arg(&args[2]).status() {
            Ok(s) => s.raw(),
            Err(e) => {
                eprintln!("child {pid}: {e}");
                100
            }
        },
        Some("orphan") => match Command::new("worker").args(["sleep", "100"]).spawn() {
            Ok(c) => {
                println!("orphan {pid}: leaving child {} behind", c.id());
                0
            }
            Err(_) => 1,
        },
        Some("threads-exit") => {
            // Leave threads blocked in every way possible, then return from
            // main: the process must end with 42 instead of hanging.
            static NEVER: AtomicU32 = AtomicU32::new(0);
            thread::spawn(|| os_std::os::raw::futex_wait(NEVER.as_ptr(), 0, 0));
            thread::spawn(|| thread::sleep(Duration::from_secs(3600)));
            thread::spawn(|| loop {
                core::hint::spin_loop();
            });
            let pair = Arc::new((Mutex::new(false), Condvar::new()));
            let p2 = pair.clone();
            thread::spawn(move || {
                let (m, cv) = &*p2;
                drop(cv.wait_while(m.lock().unwrap(), |go| !*go));
            });
            thread::sleep(Duration::from_millis(50));
            println!("threads-exit {pid}: returning with 4 threads still blocked");
            42
        }
        Some("thread-last") => {
            // The main thread ends first; the process lives on until its last
            // thread exits, whose code becomes the exit status.
            thread::spawn(|| {
                thread::sleep(Duration::from_millis(50));
                println!("thread-last: second thread finishing");
                os_std::os::raw::thread_exit(9, core::ptr::null())
            });
            os_std::os::raw::thread_exit(5, core::ptr::null())
        }
        Some("thread-fault") => {
            let h = thread::spawn(|| {
                // SAFETY: deliberately invalid; the kernel ends the process.
                unsafe { core::ptr::read_volatile(0x1000 as *const u64) }
            });
            let _ = h.join();
            3
        }
        Some("thread-panic") => {
            let h = thread::spawn(|| -> u32 { panic!("panic in a spawned thread") });
            let _ = h.join();
            3
        }
        Some("fs-write") => {
            let text = format!("written by worker {pid}\n");
            match args.get(2).map(|p| fs::write(p, &text)) {
                Some(Ok(())) => 0,
                Some(Err(e)) => {
                    eprintln!("fs-write {pid}: {e}");
                    1
                }
                None => 2,
            }
        }
        Some("fs-leak") => {
            // Write a file, then exit without running destructors: the open
            // handles must be closed by the kernel, and the data kept.
            let Some(path) = args.get(2) else { return 2 };
            let mut files = Vec::new();
            for _ in 0..10 {
                match File::open("/dev/null") {
                    Ok(f) => files.push(f),
                    Err(_) => return 1,
                }
            }
            let Ok(mut f) = File::create(path) else { return 1 };
            if f.write_all(b"still here\n").is_err() {
                return 1;
            }
            files.push(f);
            core::mem::forget(files);
            process::exit(0)
        }
        Some("pwd") => {
            let cwd = env::current_dir();
            println!("pwd {pid}: {cwd:?}");
            (cwd.ok().as_deref().map(|p| p.as_str()) != args.get(2).map(String::as_str)) as i32
        }
        Some("as-user") => as_user(arg_num(&args, 2) as u32),
        Some("fault-checks")=>fault_checks::run(),
        Some("filemap-checks") => filemap_checks::run(),
        Some(mode @ ("fault-no-handler"|"fault-exec-reset"|"fault-nested"|"fault-bad-stack"))=>fault_checks::helper(mode),
        Some("exec-as") => {
            let (Some(uid),Some(program))=(args.get(2).and_then(|s|s.parse::<u32>().ok()),args.get(3)) else {return 2};
            if os_std::os::setuid(uid,uid).is_err() {return 1;}
            let e=Command::new(program).args(&args[4..]).exec();
            eprintln!("exec-as: {e}");1
        }
        Some("exec-report") => {
            let (Some(handle_file), Some(report)) = (args.get(2), args.get(3)) else { return 2 };
            // The first file this process opens gets handle 3.
            let Ok(f) = File::create(handle_file) else { return 1 };
            if env::set_current_dir("/tmp").is_err() {
                return 1;
            }
            let e = Command::new("probe").args(["report", report, "after-exec"]).env("FROM", "worker").exec();
            drop(f);
            eprintln!("exec-report {pid}: exec failed: {e}");
            1
        }
        Some("exec-fail") => {
            use os_std::error::ErrorKind;
            let kind = |c: &mut Command| c.exec().kind();
            let results = [
                kind(&mut Command::new("no-such-program")) == ErrorKind::NotFound,
                kind(&mut Command::new("/tmp")) == ErrorKind::PermissionDenied,
                kind(&mut Command::new("/osyx-seed/hello.txt")) == ErrorKind::PermissionDenied,
                kind(&mut Command::new("/tmp/exec-script")) == ErrorKind::InvalidExecutable,
                kind(Command::new("probe").env("BAD=KEY", "x")) == ErrorKind::InvalidInput,
            ];
            println!("exec-fail {pid}: still running after failed execs: {results:?}");
            results.iter().filter(|ok| !**ok).count() as i32
        }
        Some("exec-threads") => {
            let h = thread::spawn(|| thread::sleep(Duration::from_millis(100)));
            let busy = Command::new("probe").args(["chain", "0"]).exec().kind() == os_std::error::ErrorKind::ResourceBusy;
            let joined = h.join().is_ok();
            (!(busy && joined)) as i32
        }
        Some("hold-orphan") => {
            // Keeps a removed file open until the machine stops.
            let Some(path) = args.get(2) else { return 2 };
            let Ok(mut f) = File::create(path) else { return 1 };
            if f.write_all(&vec![0x0Fu8; 1 << 20]).is_err() || f.sync_all().is_err() || fs::remove_file(path).is_err() {
                return 1;
            }
            println!("hold-orphan {pid}: holding removed {path} open");
            thread::sleep(Duration::from_secs(3600));
            drop(f);
            0
        }
        Some("echo-stdin") => {
            // Standard input to standard output, upper-cased, then a count.
            let mut input = Vec::new();
            if os_std::io::stdin().read_to_end(&mut input).is_err() {
                return 3;
            }
            print!("{}", String::from_utf8_lossy(&input).to_uppercase());
            println!("stdin bytes: {}", input.len());
            0
        }
        Some("ipc-client") => ipc_client(args.get(2).map_or("", String::as_str)),
        Some("user-ipc") => {
            // Privileged objects must be refused to an ordinary user.
            use os_std::error::ErrorKind;
            let uid = arg_num(&args, 2) as u32;
            if os_std::os::setuid(uid, uid).is_err() {
                return 20;
            }
            let denied = |r: Option<ErrorKind>| r == Some(ErrorKind::PermissionDenied);
            let mut failed = 0;
            if !denied(os_std::ipc::Listener::listen("user-service").err().map(|e| e.kind())) {
                failed += 1;
            }
            if !denied(os_std::system::display_acquire().err().map(|e| e.kind())) {
                failed += 1;
            }
            if !denied(File::open("/dev/input/seat0").err().map(|e| e.kind())) {
                failed += 1;
            }
            if !denied(os_std::system::kill(1).err().map(|e| e.kind())) {
                failed += 1;
            }
            failed
        }
        other => {
            eprintln!("worker: unknown mode {other:?}");
            2
        }
    }
}

/// Connects to `service`, receives a shared memory object with the message
/// "fill", writes a text into it and answers "done <pid>".
fn ipc_client(service: &str) -> i32 {
    use os_std::ipc::{item, wait, Channel, SharedMemory, WAIT_READABLE};
    let Ok(ch) = Channel::connect(service) else { return 10 };
    let mut items = [item(ch.handle(), WAIT_READABLE)];
    if wait(&mut items, Some(Duration::from_secs(5))) != Ok(1) {
        return 11;
    }
    let mut buf = [0u8; 64];
    let Ok(Some((n, mut handles))) = ch.recv(&mut buf) else { return 12 };
    if &buf[..n] != b"fill" || handles.len() != 1 {
        return 13;
    }
    let Ok(shm) = SharedMemory::from_handle(handles.remove(0)) else { return 14 };
    let Ok(mut map) = shm.map(true) else { return 15 };
    let msg = b"written by the worker through shared memory";
    map.bytes_mut()[..msg.len()].copy_from_slice(msg);
    let pid = process::id().unwrap_or(0);
    if ch.send(format!("done {pid}").as_bytes(), &[]).is_err() {
        return 16;
    }
    0
}

/// Permission checks as an ordinary user (`init` prepares `/tmp/root-only`,
/// mode 0600, owned by root).
fn as_user(uid: u32) -> i32 {
    use os_std::error::ErrorKind;
    use os_std::os;
    if os::setuid(uid, uid).is_err() || os::getuid() != (uid, uid) {
        eprintln!("as-user: setuid failed");
        return 100;
    }
    let kind = |r: os_std::error::Result<()>| r.err().map(|e| e.kind());
    let checks: [(&str, bool); 12] = [
        ("ext4: 0600 root file unreadable", kind(File::open("/osyx-seed/secret").map(|_| ())) == Some(ErrorKind::PermissionDenied)),
        ("ext4: /etc is read-only for users", kind(fs::write("/etc/user.txt", "x")) == Some(ErrorKind::PermissionDenied)),
        ("ext4: own home directory is writable", fs::write("/home/user/note.txt", "mine").is_ok()
            && fs::metadata("/home/user/note.txt").is_ok_and(|m| m.uid() == uid && m.gid() == uid)
            && fs::remove_file("/home/user/note.txt").is_ok()),
        ("cannot become root again", kind(os::setuid(0, 0)) == Some(ErrorKind::PermissionDenied)),
        ("raw disks are root-only", fs::read_dir("/dev/disks").is_ok_and(|d| {
            d.into_iter().all(|e| File::open(e.path()).err().map(|e| e.kind()) == Some(ErrorKind::PermissionDenied))
        })),
        ("0600 root file unreadable", kind(File::open("/tmp/root-only").map(|_| ())) == Some(ErrorKind::PermissionDenied)),
        ("/boot is read-only for users", kind(fs::write("/boot/user.txt", "x")) == Some(ErrorKind::PermissionDenied)),
        ("/run is root's", kind(fs::write("/run/user.txt", "x")) == Some(ErrorKind::PermissionDenied)),
        ("/tmp is writable (sticky)", fs::write("/tmp/user-file", "mine").is_ok()
            && fs::metadata("/tmp/user-file").is_ok_and(|m| m.uid() == uid)),
        ("others' files in /tmp are protected", kind(fs::remove_file("/tmp/root-only")) == Some(ErrorKind::PermissionDenied)),
        ("mount is root-only", kind(os::mount("", "/tmp", "tmpfs", false, 0)) == Some(ErrorKind::PermissionDenied)),
        ("chmod of root's file refused", kind(fs::set_permissions("/tmp/root-only", fs::Permissions::from_mode(0o666))) == Some(ErrorKind::PermissionDenied)),
    ];
    let mut failed = 0;
    for (name, ok) in checks {
        if !ok {
            eprintln!("as-user {uid}: {name} ... FAILED");
            failed += 1;
        }
    }
    println!("as-user {uid}: {} of {} permission checks passed", 12 - failed, 12);
    failed
}
