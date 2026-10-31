//! winmm's multimedia timer functions. timeGetTime is the monotonic clock
//! in milliseconds. The OSyx kernel ticks at a fixed 1 kHz
//! (kernel/src/arch/pic.rs, TIMER_HZ), so waits have 1 ms resolution:
//! timeGetDevCaps reports the 1 ms floor, timeBeginPeriod accepts periods
//! the kernel already provides and refuses finer ones with TIMERR_NOCANDO
//! instead of claiming a resolution OSyx does not have.
#![allow(non_snake_case)]
use alloc::{collections::BTreeMap, vec::Vec};
use os_std::sync::Mutex;

const TIMERR_NOERROR: u32 = 0;
const TIMERR_NOCANDO: u32 = 97;
/// The kernel tick, in milliseconds.
const PERIOD_MIN: u32 = 1;
const PERIOD_MAX: u32 = 1_000_000;

/// Outstanding timeBeginPeriod requests by period.
static PERIODS: Mutex<BTreeMap<u32, u32>> = Mutex::new(BTreeMap::new());

extern "win64" fn timeGetTime() -> u32 {
    (crate::kernel32::now_ns() / 1_000_000) as u32
}

extern "win64" fn timeBeginPeriod(period: u32) -> u32 {
    if !(PERIOD_MIN..=PERIOD_MAX).contains(&period) {
        return TIMERR_NOCANDO;
    }
    *PERIODS.lock().unwrap().entry(period).or_insert(0) += 1;
    TIMERR_NOERROR
}

extern "win64" fn timeEndPeriod(period: u32) -> u32 {
    let mut p = PERIODS.lock().unwrap();
    match p.get_mut(&period) {
        Some(n) => {
            *n -= 1;
            if *n == 0 {
                p.remove(&period);
            }
            TIMERR_NOERROR
        }
        None => TIMERR_NOCANDO, // no matching timeBeginPeriod
    }
}

/// TIMECAPS: wPeriodMin, wPeriodMax (two UINTs).
extern "win64" fn timeGetDevCaps(caps: *mut u32, size: u32) -> u32 {
    if caps.is_null() || size < 8 {
        return TIMERR_NOCANDO;
    }
    // SAFETY: the caller's TIMECAPS of `size` >= 8 bytes.
    unsafe {
        *caps = PERIOD_MIN;
        *caps.add(1) = PERIOD_MAX;
    }
    TIMERR_NOERROR
}

const SND_PURGE: u32 = 0x40;

/// OSyx has no sound output: stopping (no sound, or SND_PURGE) succeeds and
/// every sound fails to play, as when Windows cannot find or open it.
extern "win64" fn PlaySoundW(sound: *const u16, _module: u64, flags: u32) -> i32 {
    (sound.is_null() || flags & SND_PURGE != 0) as i32
}

// ---- waveform and MIDI devices ------------------------------------------------------------
//
// Wave output plays on `/dev/audio` (48 kHz, signed 16-bit, stereo: see
// kernel/src/audio.rs); a program's PCM format (8 or 16 bits, mono or stereo,
// any rate from 4 kHz to 192 kHz) is converted to it. MIDI ports are the
// `/dev/midiN` nodes and wave capture the `/dev/audioinN` nodes, when the
// kernel provides them. Each open device is a Windows thread that feeds the
// queued headers and reports them back through the callback the program
// chose, as winmm does. Device ids and handles are looked up in the tables
// below, so with no such device every id is MMSYSERR_BADDEVICEID and every
// handle MMSYSERR_INVALHANDLE (the answers of Windows, checked with bogus
// arguments).

use alloc::{collections::VecDeque, string::String, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};

const MMSYSERR_NOERROR: u32 = 0;
const MMSYSERR_BADDEVICEID: u32 = 2;
const MMSYSERR_ALLOCATED: u32 = 4;
const MMSYSERR_INVALHANDLE: u32 = 5;
const MMSYSERR_NODRIVER: u32 = 6;
const MMSYSERR_NOMEM: u32 = 7;
const MMSYSERR_NOTSUPPORTED: u32 = 8;
const MMSYSERR_INVALFLAG: u32 = 10;
const MMSYSERR_INVALPARAM: u32 = 11;
const WAVERR_BADFORMAT: u32 = 32;
const WAVERR_STILLPLAYING: u32 = 33;
const WAVERR_UNPREPARED: u32 = 34;
const MIDIERR_UNPREPARED: u32 = 64;
const MIDIERR_STILLPLAYING: u32 = 65;

const CALLBACK_TYPEMASK: u32 = 0x7_0000;
const CALLBACK_NULL: u32 = 0;
const CALLBACK_WINDOW: u32 = 0x1_0000;
const CALLBACK_FUNCTION: u32 = 0x3_0000;
const CALLBACK_EVENT: u32 = 0x5_0000;
const WAVE_FORMAT_QUERY: u32 = 1;
const WAVE_ALLOWSYNC: u32 = 2;
const WAVE_FORMAT_DIRECT: u32 = 8;
const MIDI_IO_STATUS: u32 = 0x20;

const WHDR_DONE: u32 = 1;
const WHDR_PREPARED: u32 = 2;
const WHDR_BEGINLOOP: u32 = 4;
const WHDR_ENDLOOP: u32 = 8;
const WHDR_INQUEUE: u32 = 0x10;
/// sizeof(WAVEHDR) and sizeof(MIDIHDR) on x64.
const WAVEHDR_SIZE: u32 = 48;
const MIDIHDR_SIZE: u32 = 120;

const WOM_OPEN: u32 = 0x3BB;
const WOM_CLOSE: u32 = 0x3BC;
const WOM_DONE: u32 = 0x3BD;
const WIM_OPEN: u32 = 0x3BE;
const WIM_CLOSE: u32 = 0x3BF;
const WIM_DATA: u32 = 0x3C0;
const MIM_OPEN: u32 = 0x3C1;
const MIM_CLOSE: u32 = 0x3C2;
const MIM_DATA: u32 = 0x3C3;
const MIM_LONGDATA: u32 = 0x3C4;
const MOM_OPEN: u32 = 0x3C7;
const MOM_CLOSE: u32 = 0x3C8;
const MOM_DONE: u32 = 0x3C9;

/// The sound card format: 48 kHz, 16 bits, stereo.
const DEVICE_RATE: u64 = 48_000;
const CHUNK_FRAMES: usize = 2048;

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(0x7700_0001);

fn new_handle() -> u64 {
    NEXT_HANDLE.fetch_add(4, Ordering::Relaxed)
}

/// How a program wants to hear about finished buffers and device events.
#[derive(Clone, Copy)]
struct Callback {
    kind: u32,
    target: u64,
    instance: u64,
}

impl Callback {
    fn new(target: u64, instance: u64, flags: u32) -> Result<Callback, u32> {
        let kind = flags & CALLBACK_TYPEMASK;
        match kind {
            CALLBACK_NULL | CALLBACK_WINDOW | CALLBACK_FUNCTION | CALLBACK_EVENT => Ok(Callback { kind, target, instance }),
            _ => Err(MMSYSERR_INVALFLAG),
        }
    }

    /// Delivers `msg` for the device `handle` with the two message parameters.
    fn send(&self, handle: u64, msg: u32, p1: u64, p2: u64) {
        match self.kind {
            CALLBACK_FUNCTION if self.target != 0 => {
                // SAFETY: a driver callback is `void CALLBACK (HANDLE, UINT, DWORD_PTR, DWORD_PTR, DWORD_PTR)`.
                let f: extern "win64" fn(u64, u32, u64, u64, u64) = unsafe { core::mem::transmute(self.target as usize) };
                f(handle, msg, self.instance, p1, p2);
            }
            CALLBACK_WINDOW => {
                crate::user32::PostMessageW(self.target, msg, handle, p1 as i64);
            }
            CALLBACK_EVENT => {
                crate::kernel32::SetEvent(self.target);
            }
            _ => {}
        }
    }
}

fn dev_names(prefix: &str) -> alloc::vec::Vec<String> {
    let mut names: alloc::vec::Vec<String> = match os_std::fs::read_dir("/dev") {
        Ok(d) => d
            .map(|e| String::from(e.file_name()))
            .filter(|n| n.starts_with(prefix) && n[prefix.len()..].bytes().all(|b| b.is_ascii_digit()))
            .collect(),
        Err(_) => alloc::vec::Vec::new(),
    };
    names.sort();
    names
}

/// The sound card the kernel drives, from `/run/audio.status`.
fn sound_card() -> Option<String> {
    let text = os_std::fs::read_to_string("/run/audio.status").ok()?;
    text.lines().find_map(|l| l.strip_prefix("device=")).map(|d| String::from(d.trim()))
}

fn midi_ports() -> alloc::vec::Vec<String> {
    dev_names("midi")
}

fn capture_nodes() -> alloc::vec::Vec<String> {
    dev_names("audioin")
}

/// An id names a device when it is below the count (WAVE_MAPPER, -1, picks the first).
fn device_index(id: u64, count: usize) -> Option<usize> {
    let id = id as u32;
    if id == u32::MAX {
        return if count > 0 { Some(0) } else { None };
    }
    if (id as usize) < count { Some(id as usize) } else { None }
}

fn read_u32(p: *const u8, at: usize) -> u32 {
    // SAFETY: callers pass a structure of at least `at + 4` bytes.
    unsafe { core::ptr::read_unaligned(p.add(at) as *const u32) }
}

fn header_flags(h: u64) -> u32 {
    read_u32(h as *const u8, 24)
}

fn set_header_flags(h: u64, flags: u32) {
    // SAFETY: a WAVEHDR/MIDIHDR the program prepared; its flags are at 24.
    unsafe { core::ptr::write_unaligned((h + 24) as *mut u32, flags) };
}

/// Marks a header done and gives it back through the callback.
fn finish_header(cb: &Callback, handle: u64, done_msg: u32, h: u64, recorded: Option<u32>) {
    let mut flags = header_flags(h);
    flags &= !WHDR_INQUEUE;
    flags |= WHDR_DONE;
    if let Some(n) = recorded {
        // SAFETY: dwBytesRecorded sits at 12 in both header types.
        unsafe { core::ptr::write_unaligned((h + 12) as *mut u32, n) };
    }
    set_header_flags(h, flags);
    cb.send(handle, done_msg, h, 0);
}

fn start_thread(entry: extern "win64" fn(u64) -> u32, handle: u64) -> bool {
    let t = crate::kernel32::CreateThread(0, 0, entry as usize as u64, handle, 0, core::ptr::null_mut());
    if t == 0 {
        return false;
    }
    crate::kernel32::CloseHandle(t);
    true
}

fn wait_ms(ms: u64) {
    os_std::thread::sleep(core::time::Duration::from_millis(ms));
}

/// A square-wave tone on the sound card, played by a detached thread, for
/// MessageBeep. Returns whether a card exists to play it.
pub(crate) fn play_tone(freq: u32, ms: u32) -> bool {
    if sound_card().is_none() {
        return false;
    }
    os_std::thread::Builder::new()
        .stack_size(64 << 10)
        .spawn(move || {
            use os_std::io::Write;
            let frames = (DEVICE_RATE as u32 / 1000 * ms) as usize;
            let half = (DEVICE_RATE as u32 / (2 * freq.max(1))).max(1) as usize;
            let mut pcm = alloc::vec::Vec::with_capacity(frames * 4);
            for i in 0..frames {
                let level: i16 = if (i / half) % 2 == 0 { 6000 } else { -6000 };
                pcm.extend_from_slice(&level.to_le_bytes());
                pcm.extend_from_slice(&level.to_le_bytes());
            }
            if let Ok(mut f) = os_std::fs::OpenOptions::new().write(true).open("/dev/audio") {
                let _ = f.write_all(&pcm);
            }
        })
        .is_ok()
}

// ---- wave output ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct Format {
    channels: u32,
    bits: u32,
    rate: u64,
}

impl Format {
    fn frame_bytes(&self) -> u64 {
        (self.channels * self.bits / 8) as u64
    }
}

/// A WAVEFORMATEX the sound card path can convert: PCM, 8 or 16 bits, one or
/// two channels, 4 kHz to 192 kHz.
fn parse_format(p: *const u8) -> Option<Format> {
    if p.is_null() {
        return None;
    }
    // SAFETY: a WAVEFORMATEX (16 bytes of PCM fields).
    let (tag, channels, rate, align, bits) = unsafe {
        (
            core::ptr::read_unaligned(p as *const u16),
            core::ptr::read_unaligned(p.add(2) as *const u16) as u32,
            core::ptr::read_unaligned(p.add(4) as *const u32) as u64,
            core::ptr::read_unaligned(p.add(12) as *const u16) as u32,
            core::ptr::read_unaligned(p.add(14) as *const u16) as u32,
        )
    };
    let ok = tag == 1 && (channels == 1 || channels == 2) && (bits == 8 || bits == 16) && (4_000..=192_000).contains(&rate) && align == channels * bits / 8;
    ok.then_some(Format { channels, bits, rate })
}

struct OutState {
    queue: VecDeque<u64>,
    paused: bool,
    /// The header being played, 0 when idle.
    current: u64,
    /// Source bytes played (the position winmm reports).
    played: u64,
    /// Set by waveOutReset: the current header ends early.
    abort: bool,
    closing: bool,
}

struct WaveOut {
    format: Format,
    cb: Callback,
    file: Mutex<os_std::fs::File>,
    state: Mutex<OutState>,
}

static WAVE_OUTS: Mutex<BTreeMap<u64, Arc<WaveOut>>> = Mutex::new(BTreeMap::new());

fn wave_out(h: u64) -> Option<Arc<WaveOut>> {
    WAVE_OUTS.lock().unwrap().get(&h).cloned()
}

/// Converts `frames` source frames of the program's format starting at
/// `first` into the sound card's 48 kHz 16-bit stereo, by nearest sample.
fn convert(f: &Format, src: &[u8], first_out: u64, count_out: usize, out: &mut alloc::vec::Vec<u8>) {
    let fb = f.frame_bytes() as usize;
    let frames_in = src.len() / fb;
    for i in 0..count_out as u64 {
        let idx = (((first_out + i) * f.rate / DEVICE_RATE) as usize).min(frames_in.saturating_sub(1));
        let frame = &src[idx * fb..idx * fb + fb];
        let sample = |c: usize| -> i16 {
            if f.bits == 8 {
                ((frame[c] as i16) - 128) << 8
            } else {
                i16::from_le_bytes([frame[c * 2], frame[c * 2 + 1]])
            }
        };
        let left = sample(0);
        let right = if f.channels == 2 { sample(1) } else { left };
        out.extend_from_slice(&left.to_le_bytes());
        out.extend_from_slice(&right.to_le_bytes());
    }
}

/// Plays one header, honouring pause, reset and the loop count.
fn play_header(w: &WaveOut, handle: u64, hdr: u64) {
    use os_std::io::Write;
    let h = hdr as *const u8;
    // SAFETY: a prepared WAVEHDR: lpData at 0, dwBufferLength at 8.
    let (data, len) = unsafe { (core::ptr::read_unaligned(h as *const u64) as *const u8, read_u32(h, 8) as usize) };
    let flags = header_flags(hdr);
    let loops = if flags & WHDR_BEGINLOOP != 0 && flags & WHDR_ENDLOOP != 0 { read_u32(h, 28).max(1) } else { 1 };
    let fb = w.format.frame_bytes() as usize;
    let frames_in = len / fb;
    let frames_out = (frames_in as u64 * DEVICE_RATE / w.format.rate) as usize;
    for _ in 0..loops {
        let mut done = 0usize;
        while done < frames_out {
            loop {
                let s = w.state.lock().unwrap();
                if s.abort {
                    return;
                }
                if !s.paused {
                    break;
                }
                drop(s);
                wait_ms(2);
            }
            let n = (frames_out - done).min(CHUNK_FRAMES);
            let mut pcm = alloc::vec::Vec::with_capacity(n * 4);
            // SAFETY: the program keeps its buffer valid until the header is returned.
            let src = unsafe { core::slice::from_raw_parts(data, frames_in * fb) };
            convert(&w.format, src, done as u64, n, &mut pcm);
            let ok = w.file.lock().unwrap().write_all(&pcm).is_ok();
            let before = done as u64 * w.format.rate / DEVICE_RATE;
            done += n;
            let after = done as u64 * w.format.rate / DEVICE_RATE;
            w.state.lock().unwrap().played += (after - before) * fb as u64;
            if !ok {
                return;
            }
        }
    }
    let _ = handle;
}

extern "win64" fn wave_out_worker(handle: u64) -> u32 {
    let Some(w) = wave_out(handle) else { return 0 };
    loop {
        let next = {
            let mut s = w.state.lock().unwrap();
            if s.closing {
                break;
            }
            if s.paused || s.queue.is_empty() {
                None
            } else {
                let h = s.queue.pop_front();
                s.current = h.unwrap_or(0);
                h
            }
        };
        let Some(hdr) = next else {
            wait_ms(2);
            continue;
        };
        play_header(&w, handle, hdr);
        w.state.lock().unwrap().current = 0;
        finish_header(&w.cb, handle, WOM_DONE, hdr, None);
    }
    0
}

/// Number of waveform output devices: the sound card the kernel drives.
extern "win64" fn waveOutGetNumDevs() -> u32 {
    sound_card().is_some() as u32
}

/// WAVEOUTCAPSW (84 bytes) or WAVEOUTCAPSA (52 bytes): the card name, the
/// formats the converter accepts (11.025 to 48 kHz, 8/16 bit, mono/stereo),
/// two channels, volume control and sample-accurate position.
fn wave_out_caps(id: u64, caps: *mut u8, size: u32, wide: bool) -> u32 {
    let Some(name) = sound_card().filter(|_| device_index(id, 1).is_some()) else {
        return MMSYSERR_BADDEVICEID;
    };
    if caps.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    let mut block = [0u8; 84];
    let (formats, channels, support) = (0xFFFFu32, 2u16, 0x4u32 | 0x20);
    let name_end;
    if wide {
        for (i, c) in name.encode_utf16().take(31).enumerate() {
            block[8 + i * 2..10 + i * 2].copy_from_slice(&c.to_le_bytes());
        }
        name_end = 72;
    } else {
        for (i, b) in name.bytes().take(31).enumerate() {
            block[8 + i] = b;
        }
        name_end = 40;
    }
    block[name_end..name_end + 4].copy_from_slice(&formats.to_le_bytes());
    block[name_end + 4..name_end + 6].copy_from_slice(&channels.to_le_bytes());
    block[name_end + 8..name_end + 12].copy_from_slice(&support.to_le_bytes());
    let total = if wide { 84 } else { 52 };
    let n = (size as usize).min(total);
    // SAFETY: the caller's WAVEOUTCAPS of `size` bytes.
    unsafe { core::ptr::copy_nonoverlapping(block.as_ptr(), caps, n) };
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutGetDevCapsA(id: u64, caps: *mut u8, size: u32) -> u32 {
    wave_out_caps(id, caps, size, false)
}
extern "win64" fn waveOutGetDevCapsW(id: u64, caps: *mut u8, size: u32) -> u32 {
    wave_out_caps(id, caps, size, true)
}

/// waveOutOpen(&handle, id, &format, callback, instance, flags).
extern "win64" fn waveOutOpen(handle: *mut u64, id: u32, format: *const u8, callback: u64, instance: u64, flags: u32) -> u32 {
    let query = flags & WAVE_FORMAT_QUERY != 0;
    if flags & !(CALLBACK_TYPEMASK | WAVE_FORMAT_QUERY | WAVE_ALLOWSYNC | WAVE_FORMAT_DIRECT | 0x4 | 0x10) != 0 {
        return MMSYSERR_INVALFLAG;
    }
    if sound_card().is_none() || device_index(id as u64, 1).is_none() {
        return MMSYSERR_BADDEVICEID;
    }
    if format.is_null() || (handle.is_null() && !query) {
        return MMSYSERR_INVALPARAM;
    }
    let Some(fmt) = parse_format(format) else { return WAVERR_BADFORMAT };
    let cb = match Callback::new(callback, instance, flags) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if query {
        return MMSYSERR_NOERROR;
    }
    let file = match os_std::fs::OpenOptions::new().write(true).open("/dev/audio") {
        Ok(f) => f,
        Err(_) => return MMSYSERR_NODRIVER,
    };
    let h = new_handle();
    let w = Arc::new(WaveOut {
        format: fmt,
        cb,
        file: Mutex::new(file),
        state: Mutex::new(OutState { queue: VecDeque::new(), paused: false, current: 0, played: 0, abort: false, closing: false }),
    });
    WAVE_OUTS.lock().unwrap().insert(h, w.clone());
    if !start_thread(wave_out_worker, h) {
        WAVE_OUTS.lock().unwrap().remove(&h);
        return MMSYSERR_NOMEM;
    }
    // SAFETY: the caller's handle out pointer.
    unsafe { *handle = h };
    cb.send(h, WOM_OPEN, 0, 0);
    MMSYSERR_NOERROR
}

/// The header checks every wave call makes: size and pointer first, then the handle.
fn wave_header(header: *const u8, size: u32) -> Result<u64, u32> {
    if header.is_null() || size != WAVEHDR_SIZE {
        Err(MMSYSERR_INVALPARAM)
    } else {
        Ok(header as u64)
    }
}

extern "win64" fn waveOutPrepareHeader(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match wave_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if wave_out(h).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    set_header_flags(hdr, header_flags(hdr) | WHDR_PREPARED);
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutUnprepareHeader(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match wave_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if wave_out(h).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    let flags = header_flags(hdr);
    if flags & WHDR_INQUEUE != 0 {
        return WAVERR_STILLPLAYING;
    }
    set_header_flags(hdr, flags & !(WHDR_PREPARED | WHDR_DONE));
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutWrite(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match wave_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(w) = wave_out(h) else { return MMSYSERR_INVALHANDLE };
    let flags = header_flags(hdr);
    if flags & WHDR_PREPARED == 0 {
        return WAVERR_UNPREPARED;
    }
    if flags & WHDR_INQUEUE != 0 {
        return WAVERR_STILLPLAYING;
    }
    set_header_flags(hdr, (flags & !WHDR_DONE) | WHDR_INQUEUE);
    w.state.lock().unwrap().queue.push_back(hdr);
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutPause(h: u64) -> u32 {
    let Some(w) = wave_out(h) else { return MMSYSERR_INVALHANDLE };
    w.state.lock().unwrap().paused = true;
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutRestart(h: u64) -> u32 {
    let Some(w) = wave_out(h) else { return MMSYSERR_INVALHANDLE };
    w.state.lock().unwrap().paused = false;
    MMSYSERR_NOERROR
}

/// Stops playback, returns every queued header and rewinds the position.
extern "win64" fn waveOutReset(h: u64) -> u32 {
    let Some(w) = wave_out(h) else { return MMSYSERR_INVALHANDLE };
    {
        let mut s = w.state.lock().unwrap();
        s.paused = false;
        s.abort = true;
    }
    // The worker returns the header it was playing; wait for it.
    while w.state.lock().unwrap().current != 0 {
        wait_ms(1);
    }
    let queued: alloc::vec::Vec<u64> = w.state.lock().unwrap().queue.drain(..).collect();
    for hdr in queued {
        finish_header(&w.cb, h, WOM_DONE, hdr, None);
    }
    let mut s = w.state.lock().unwrap();
    s.abort = false;
    s.played = 0;
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutClose(h: u64) -> u32 {
    let Some(w) = wave_out(h) else { return MMSYSERR_INVALHANDLE };
    {
        let mut s = w.state.lock().unwrap();
        if !s.queue.is_empty() || s.current != 0 {
            return WAVERR_STILLPLAYING;
        }
        s.closing = true;
    }
    WAVE_OUTS.lock().unwrap().remove(&h);
    w.cb.send(h, WOM_CLOSE, 0, 0);
    MMSYSERR_NOERROR
}

const TIME_MS: u32 = 1;
const TIME_SAMPLES: u32 = 2;
const TIME_BYTES: u32 = 4;

/// waveOutGetPosition(handle, &mmtime, size): MMTIME is packed, the type at 0
/// and the value at 4. TIME_MS, TIME_SAMPLES and TIME_BYTES are answered; any
/// other requested unit is reported in bytes, as winmm does.
extern "win64" fn waveOutGetPosition(h: u64, time: *mut u8, size: u32) -> u32 {
    let Some(w) = wave_out(h) else { return MMSYSERR_INVALHANDLE };
    if time.is_null() || size < 8 {
        return MMSYSERR_INVALPARAM;
    }
    let played = w.state.lock().unwrap().played;
    // SAFETY: the caller's MMTIME of at least 8 bytes.
    unsafe {
        let want = core::ptr::read_unaligned(time as *const u32);
        let (kind, value) = match want {
            TIME_MS => (TIME_MS, played * 1000 / (w.format.rate * w.format.frame_bytes())),
            TIME_SAMPLES => (TIME_SAMPLES, played / w.format.frame_bytes()),
            _ => (TIME_BYTES, played),
        };
        core::ptr::write_unaligned(time as *mut u32, kind);
        core::ptr::write_unaligned(time.add(4) as *mut u32, value as u32);
    }
    MMSYSERR_NOERROR
}

/// waveOutGetID(handle, &id): the one sound card is device 0.
extern "win64" fn waveOutGetID(h: u64, id: *mut u32) -> u32 {
    if wave_out(h).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    if id.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    // SAFETY: the caller's out pointer.
    unsafe { *id = 0 };
    MMSYSERR_NOERROR
}

/// The kernel mixer volume (0 to 100 percent) as winmm's packed 16-bit
/// left/right pair.
extern "win64" fn waveOutGetVolume(h: u64, volume: *mut u32) -> u32 {
    if volume.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    if wave_out(h).is_none() && device_index(h, 1).is_none() {
        return MMSYSERR_BADDEVICEID;
    }
    let text = os_std::fs::read_to_string("/run/audio.status").unwrap_or_default();
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).map(str::trim));
    let percent: u32 = field("volume=").and_then(|v| v.parse().ok()).unwrap_or(0).min(100);
    let level = percent * 0xFFFF / 100;
    // SAFETY: the caller's out pointer.
    unsafe { *volume = level | (level << 16) };
    MMSYSERR_NOERROR
}

extern "win64" fn waveOutSetVolume(h: u64, volume: u32) -> u32 {
    use os_std::io::Write;
    if wave_out(h).is_none() && device_index(h, 1).is_none() {
        return MMSYSERR_BADDEVICEID;
    }
    let level = ((volume & 0xFFFF) + (volume >> 16)) / 2;
    let line = alloc::format!("volume={}\n", level * 100 / 0xFFFF);
    match os_std::fs::OpenOptions::new().write(true).open("/dev/mixer") {
        Ok(mut f) => {
            let _ = f.write_all(line.as_bytes());
            MMSYSERR_NOERROR
        }
        Err(_) => MMSYSERR_NODRIVER,
    }
}

/// Driver messages of a wave device: none beyond the winmm API are defined.
extern "win64" fn waveOutMessage(h: u64, _message: u32, _a: u64, _b: u64) -> u32 {
    if wave_out(h).is_some() {
        MMSYSERR_NOTSUPPORTED
    } else {
        MMSYSERR_BADDEVICEID
    }
}

// ---- wave input ----------------------------------------------------------------------------

struct InState {
    queue: VecDeque<u64>,
    started: bool,
    recorded: u64,
    closing: bool,
}

struct WaveIn {
    format: Format,
    cb: Callback,
    file: Mutex<os_std::fs::File>,
    state: Mutex<InState>,
}

static WAVE_INS: Mutex<BTreeMap<u64, Arc<WaveIn>>> = Mutex::new(BTreeMap::new());

fn wave_in(h: u64) -> Option<Arc<WaveIn>> {
    WAVE_INS.lock().unwrap().get(&h).cloned()
}

extern "win64" fn wave_in_worker(handle: u64) -> u32 {
    use os_std::io::Read;
    let Some(w) = wave_in(handle) else { return 0 };
    loop {
        let hdr = {
            let s = w.state.lock().unwrap();
            if s.closing {
                break;
            }
            if s.started { s.queue.front().copied() } else { None }
        };
        let Some(hdr) = hdr else {
            wait_ms(2);
            continue;
        };
        let h = hdr as *const u8;
        // SAFETY: a prepared WAVEHDR: lpData at 0, dwBufferLength at 8.
        let (data, len) = unsafe { (core::ptr::read_unaligned(h as *const u64) as *mut u8, read_u32(h, 8) as usize) };
        // SAFETY: the program keeps its buffer valid until the header is returned.
        let buf = unsafe { core::slice::from_raw_parts_mut(data, len) };
        let got = w.file.lock().unwrap().read(buf).unwrap_or(0);
        if got == 0 {
            wait_ms(2);
            continue;
        }
        w.state.lock().unwrap().recorded += got as u64;
        // A header is returned when it is full (or on stop/reset, below).
        let mut filled = got;
        while filled < len && !w.state.lock().unwrap().closing {
            let n = w.file.lock().unwrap().read(&mut buf[filled..]).unwrap_or(0);
            if n == 0 {
                wait_ms(2);
            }
            filled += n;
            w.state.lock().unwrap().recorded += n as u64;
        }
        w.state.lock().unwrap().queue.pop_front();
        finish_header(&w.cb, handle, WIM_DATA, hdr, Some(filled as u32));
    }
    0
}

extern "win64" fn waveInGetNumDevs() -> u32 {
    capture_nodes().len() as u32
}

fn wave_in_caps(id: u64, caps: *mut u8, size: u32, wide: bool) -> u32 {
    let nodes = capture_nodes();
    let Some(i) = device_index(id, nodes.len()) else { return MMSYSERR_BADDEVICEID };
    if caps.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    let mut block = [0u8; 80];
    let name_end;
    if wide {
        for (n, c) in nodes[i].encode_utf16().take(31).enumerate() {
            block[8 + n * 2..10 + n * 2].copy_from_slice(&c.to_le_bytes());
        }
        name_end = 72;
    } else {
        for (n, b) in nodes[i].bytes().take(31).enumerate() {
            block[8 + n] = b;
        }
        name_end = 40;
    }
    // Capture is the card's own format: 48 kHz, 16 bits, stereo.
    block[name_end..name_end + 4].copy_from_slice(&0x8000u32.to_le_bytes());
    block[name_end + 4..name_end + 6].copy_from_slice(&2u16.to_le_bytes());
    let total = if wide { 80 } else { 48 };
    // SAFETY: the caller's WAVEINCAPS of `size` bytes.
    unsafe { core::ptr::copy_nonoverlapping(block.as_ptr(), caps, (size as usize).min(total)) };
    MMSYSERR_NOERROR
}

extern "win64" fn waveInGetDevCapsA(id: u64, caps: *mut u8, size: u32) -> u32 {
    wave_in_caps(id, caps, size, false)
}
extern "win64" fn waveInGetDevCapsW(id: u64, caps: *mut u8, size: u32) -> u32 {
    wave_in_caps(id, caps, size, true)
}

extern "win64" fn waveInOpen(handle: *mut u64, id: u32, format: *const u8, callback: u64, instance: u64, flags: u32) -> u32 {
    let nodes = capture_nodes();
    let query = flags & WAVE_FORMAT_QUERY != 0;
    if flags & !(CALLBACK_TYPEMASK | WAVE_FORMAT_QUERY | WAVE_ALLOWSYNC | WAVE_FORMAT_DIRECT | 0x4 | 0x10) != 0 {
        return MMSYSERR_INVALFLAG;
    }
    let Some(i) = device_index(id as u64, nodes.len()) else { return MMSYSERR_BADDEVICEID };
    if format.is_null() || (handle.is_null() && !query) {
        return MMSYSERR_INVALPARAM;
    }
    let fmt = match parse_format(format) {
        Some(f) if f.rate == DEVICE_RATE && f.bits == 16 && f.channels == 2 => f,
        _ => return WAVERR_BADFORMAT,
    };
    let cb = match Callback::new(callback, instance, flags) {
        Ok(c) => c,
        Err(e) => return e,
    };
    if query {
        return MMSYSERR_NOERROR;
    }
    let path = alloc::format!("/dev/{}", nodes[i]);
    let Ok(file) = os_std::fs::OpenOptions::new().read(true).open(path.as_str()) else { return MMSYSERR_ALLOCATED };
    let h = new_handle();
    let w = Arc::new(WaveIn { format: fmt, cb, file: Mutex::new(file), state: Mutex::new(InState { queue: VecDeque::new(), started: false, recorded: 0, closing: false }) });
    WAVE_INS.lock().unwrap().insert(h, w);
    if !start_thread(wave_in_worker, h) {
        WAVE_INS.lock().unwrap().remove(&h);
        return MMSYSERR_NOMEM;
    }
    // SAFETY: the caller's handle out pointer.
    unsafe { *handle = h };
    cb.send(h, WIM_OPEN, 0, 0);
    MMSYSERR_NOERROR
}

extern "win64" fn waveInPrepareHeader(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match wave_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if wave_in(h).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    set_header_flags(hdr, header_flags(hdr) | WHDR_PREPARED);
    MMSYSERR_NOERROR
}

extern "win64" fn waveInUnprepareHeader(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match wave_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if wave_in(h).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    let flags = header_flags(hdr);
    if flags & WHDR_INQUEUE != 0 {
        return WAVERR_STILLPLAYING;
    }
    set_header_flags(hdr, flags & !(WHDR_PREPARED | WHDR_DONE));
    MMSYSERR_NOERROR
}

extern "win64" fn waveInAddBuffer(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match wave_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(w) = wave_in(h) else { return MMSYSERR_INVALHANDLE };
    let flags = header_flags(hdr);
    if flags & WHDR_PREPARED == 0 {
        return WAVERR_UNPREPARED;
    }
    if flags & WHDR_INQUEUE != 0 {
        return WAVERR_STILLPLAYING;
    }
    set_header_flags(hdr, (flags & !WHDR_DONE) | WHDR_INQUEUE);
    w.state.lock().unwrap().queue.push_back(hdr);
    MMSYSERR_NOERROR
}

extern "win64" fn waveInStart(h: u64) -> u32 {
    let Some(w) = wave_in(h) else { return MMSYSERR_INVALHANDLE };
    w.state.lock().unwrap().started = true;
    MMSYSERR_NOERROR
}

extern "win64" fn waveInStop(h: u64) -> u32 {
    let Some(w) = wave_in(h) else { return MMSYSERR_INVALHANDLE };
    w.state.lock().unwrap().started = false;
    MMSYSERR_NOERROR
}

/// Stops capture and returns every queued header with the bytes it holds (none).
extern "win64" fn waveInReset(h: u64) -> u32 {
    let Some(w) = wave_in(h) else { return MMSYSERR_INVALHANDLE };
    let queued: alloc::vec::Vec<u64> = {
        let mut s = w.state.lock().unwrap();
        s.started = false;
        s.recorded = 0;
        s.queue.drain(..).collect()
    };
    for hdr in queued {
        finish_header(&w.cb, h, WIM_DATA, hdr, Some(0));
    }
    MMSYSERR_NOERROR
}

extern "win64" fn waveInClose(h: u64) -> u32 {
    let Some(w) = wave_in(h) else { return MMSYSERR_INVALHANDLE };
    {
        let mut s = w.state.lock().unwrap();
        if !s.queue.is_empty() {
            return WAVERR_STILLPLAYING;
        }
        s.closing = true;
    }
    WAVE_INS.lock().unwrap().remove(&h);
    w.cb.send(h, WIM_CLOSE, 0, 0);
    MMSYSERR_NOERROR
}

extern "win64" fn waveInGetPosition(h: u64, time: *mut u8, size: u32) -> u32 {
    let Some(w) = wave_in(h) else { return MMSYSERR_INVALHANDLE };
    if time.is_null() || size < 8 {
        return MMSYSERR_INVALPARAM;
    }
    let recorded = w.state.lock().unwrap().recorded;
    // SAFETY: the caller's MMTIME of at least 8 bytes.
    unsafe {
        let want = core::ptr::read_unaligned(time as *const u32);
        let (kind, value) = match want {
            TIME_MS => (TIME_MS, recorded * 1000 / (w.format.rate * w.format.frame_bytes())),
            TIME_SAMPLES => (TIME_SAMPLES, recorded / w.format.frame_bytes()),
            _ => (TIME_BYTES, recorded),
        };
        core::ptr::write_unaligned(time as *mut u32, kind);
        core::ptr::write_unaligned(time.add(4) as *mut u32, value as u32);
    }
    MMSYSERR_NOERROR
}

extern "win64" fn waveInMessage(h: u64, _message: u32, _a: u64, _b: u64) -> u32 {
    if wave_in(h).is_some() {
        MMSYSERR_NOTSUPPORTED
    } else {
        MMSYSERR_BADDEVICEID
    }
}

// ---- MIDI output ---------------------------------------------------------------------------

/// Data bytes that follow a MIDI status byte (None for sysex start, which
/// travels as a long message).
fn midi_length(status: u8) -> Option<usize> {
    match status {
        0x80..=0xBF | 0xE0..=0xEF => Some(2),
        0xC0..=0xDF => Some(1),
        0xF1 | 0xF3 => Some(1),
        0xF2 => Some(2),
        0xF0 | 0xF7 => None,
        _ => Some(0),
    }
}

struct MidiOut {
    cb: Callback,
    file: Mutex<os_std::fs::File>,
}

static MIDI_OUTS: Mutex<BTreeMap<u64, Arc<MidiOut>>> = Mutex::new(BTreeMap::new());

fn midi_out(h: u64) -> Option<Arc<MidiOut>> {
    MIDI_OUTS.lock().unwrap().get(&h).cloned()
}

extern "win64" fn midiOutGetNumDevs() -> u32 {
    midi_ports().len() as u32
}

/// MIDIOUTCAPS(W): manufacturer/product ids, driver version, the name,
/// technology (MOD_MIDIPORT, 1), voices, notes, channel mask (all 16), support.
fn midi_caps(id: u64, caps: *mut u8, size: u32, wide: bool, input: bool) -> u32 {
    let ports = midi_ports();
    let Some(i) = device_index(id, ports.len()) else { return MMSYSERR_BADDEVICEID };
    if caps.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    let mut block = [0u8; 84];
    let name_end;
    if wide {
        for (n, c) in ports[i].encode_utf16().take(31).enumerate() {
            block[8 + n * 2..10 + n * 2].copy_from_slice(&c.to_le_bytes());
        }
        name_end = 72;
    } else {
        for (n, b) in ports[i].bytes().take(31).enumerate() {
            block[8 + n] = b;
        }
        name_end = 40;
    }
    if input {
        // MIDIINCAPS ends after the name and the support flags.
        let total = if wide { 76 } else { 44 };
        // SAFETY: the caller's MIDIINCAPS of `size` bytes.
        unsafe { core::ptr::copy_nonoverlapping(block.as_ptr(), caps, (size as usize).min(total)) };
        return MMSYSERR_NOERROR;
    }
    block[name_end..name_end + 2].copy_from_slice(&1u16.to_le_bytes());
    block[name_end + 6..name_end + 8].copy_from_slice(&0xFFFFu16.to_le_bytes());
    let total = if wide { 84 } else { 52 };
    // SAFETY: the caller's MIDIOUTCAPS of `size` bytes.
    unsafe { core::ptr::copy_nonoverlapping(block.as_ptr(), caps, (size as usize).min(total)) };
    MMSYSERR_NOERROR
}

extern "win64" fn midiOutGetDevCapsA(id: u64, caps: *mut u8, size: u32) -> u32 {
    midi_caps(id, caps, size, false, false)
}
extern "win64" fn midiOutGetDevCapsW(id: u64, caps: *mut u8, size: u32) -> u32 {
    midi_caps(id, caps, size, true, false)
}

extern "win64" fn midiOutOpen(handle: *mut u64, id: u32, callback: u64, instance: u64, flags: u32) -> u32 {
    let ports = midi_ports();
    let Some(i) = device_index(id as u64, ports.len()) else { return MMSYSERR_BADDEVICEID };
    if handle.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    let cb = match Callback::new(callback, instance, flags) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let path = alloc::format!("/dev/{}", ports[i]);
    let Ok(file) = os_std::fs::OpenOptions::new().write(true).open(path.as_str()) else { return MMSYSERR_ALLOCATED };
    let h = new_handle();
    MIDI_OUTS.lock().unwrap().insert(h, Arc::new(MidiOut { cb, file: Mutex::new(file) }));
    // SAFETY: the caller's handle out pointer.
    unsafe { *handle = h };
    cb.send(h, MOM_OPEN, 0, 0);
    MMSYSERR_NOERROR
}

fn midi_write(m: &MidiOut, bytes: &[u8]) -> u32 {
    use os_std::io::Write;
    match m.file.lock().unwrap().write_all(bytes) {
        Ok(()) => MMSYSERR_NOERROR,
        Err(_) => MMSYSERR_NODRIVER,
    }
}

/// midiOutShortMsg: status in the low byte, then up to two data bytes.
extern "win64" fn midiOutShortMsg(h: u64, message: u32) -> u32 {
    let Some(m) = midi_out(h) else { return MMSYSERR_INVALHANDLE };
    let bytes = message.to_le_bytes();
    if bytes[0] < 0x80 {
        return MMSYSERR_INVALPARAM;
    }
    match midi_length(bytes[0]) {
        Some(n) => midi_write(&m, &bytes[..1 + n]),
        None => MMSYSERR_INVALPARAM,
    }
}

fn midi_header(header: *const u8, size: u32) -> Result<u64, u32> {
    if header.is_null() || size != MIDIHDR_SIZE {
        Err(MMSYSERR_INVALPARAM)
    } else {
        Ok(header as u64)
    }
}

extern "win64" fn midiOutPrepareHeader(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match midi_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if midi_out(h).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    set_header_flags(hdr, header_flags(hdr) | WHDR_PREPARED);
    MMSYSERR_NOERROR
}

extern "win64" fn midiOutUnprepareHeader(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match midi_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if midi_out(h).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    let flags = header_flags(hdr);
    if flags & WHDR_INQUEUE != 0 {
        return MIDIERR_STILLPLAYING;
    }
    set_header_flags(hdr, flags & !(WHDR_PREPARED | WHDR_DONE));
    MMSYSERR_NOERROR
}

/// A system-exclusive message from a prepared header, written at once.
extern "win64" fn midiOutLongMsg(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match midi_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(m) = midi_out(h) else { return MMSYSERR_INVALHANDLE };
    let flags = header_flags(hdr);
    if flags & WHDR_PREPARED == 0 {
        return MIDIERR_UNPREPARED;
    }
    if flags & WHDR_INQUEUE != 0 {
        return MIDIERR_STILLPLAYING;
    }
    // SAFETY: a prepared MIDIHDR: lpData at 0, dwBufferLength at 8.
    let bytes = unsafe { core::slice::from_raw_parts(core::ptr::read_unaligned(header as *const u64) as *const u8, read_u32(header, 8) as usize) };
    let r = midi_write(&m, bytes);
    finish_header(&m.cb, h, MOM_DONE, hdr, None);
    r
}

/// Silences the port: All Notes Off (controller 123) on the 16 channels.
extern "win64" fn midiOutReset(h: u64) -> u32 {
    let Some(m) = midi_out(h) else { return MMSYSERR_INVALHANDLE };
    let mut off = alloc::vec::Vec::with_capacity(48);
    for ch in 0..16u8 {
        off.extend_from_slice(&[0xB0 | ch, 123, 0]);
    }
    midi_write(&m, &off)
}

extern "win64" fn midiOutClose(h: u64) -> u32 {
    let Some(m) = MIDI_OUTS.lock().unwrap().remove(&h) else { return MMSYSERR_INVALHANDLE };
    m.cb.send(h, MOM_CLOSE, 0, 0);
    MMSYSERR_NOERROR
}

extern "win64" fn midiOutMessage(h: u64, _message: u32, _a: u64, _b: u64) -> u32 {
    if midi_out(h).is_some() {
        MMSYSERR_NOTSUPPORTED
    } else {
        MMSYSERR_BADDEVICEID
    }
}

// ---- MIDI input ----------------------------------------------------------------------------

struct MidiInState {
    queue: VecDeque<u64>,
    started: bool,
    closing: bool,
    epoch_ms: u64,
}

struct MidiIn {
    cb: Callback,
    file: Mutex<os_std::fs::File>,
    state: Mutex<MidiInState>,
}

static MIDI_INS: Mutex<BTreeMap<u64, Arc<MidiIn>>> = Mutex::new(BTreeMap::new());

fn midi_in(h: u64) -> Option<Arc<MidiIn>> {
    MIDI_INS.lock().unwrap().get(&h).cloned()
}

/// Reads the port and turns the byte stream into MIM_DATA short messages
/// (with running status) and MIM_LONGDATA sysex buffers.
extern "win64" fn midi_in_worker(handle: u64) -> u32 {
    use os_std::io::Read;
    let Some(m) = midi_in(handle) else { return 0 };
    let mut running = 0u8;
    let mut pending = [0u8; 3];
    let mut have = 0usize;
    let mut need = 0usize;
    let mut sysex: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
    let mut in_sysex = false;
    let mut byte = [0u8; 1];
    loop {
        if m.state.lock().unwrap().closing {
            break;
        }
        if m.file.lock().unwrap().read(&mut byte).unwrap_or(0) == 0 {
            wait_ms(2);
            continue;
        }
        let b = byte[0];
        let (started, epoch) = {
            let s = m.state.lock().unwrap();
            (s.started, s.epoch_ms)
        };
        let stamp = (crate::kernel32::now_ns() / 1_000_000).wrapping_sub(epoch);
        if b >= 0xF8 {
            if started {
                m.cb.send(handle, MIM_DATA, b as u64, stamp);
            }
            continue;
        }
        if in_sysex {
            sysex.push(b);
            if b == 0xF7 {
                in_sysex = false;
                let hdr = m.state.lock().unwrap().queue.pop_front();
                if let (Some(hdr), true) = (hdr, started) {
                    // SAFETY: a prepared MIDIHDR: lpData at 0, dwBufferLength at 8.
                    let (data, cap) = unsafe { (core::ptr::read_unaligned(hdr as *const u64) as *mut u8, read_u32(hdr as *const u8, 8) as usize) };
                    let n = sysex.len().min(cap);
                    // SAFETY: the program's buffer holds `cap` bytes.
                    unsafe { core::ptr::copy_nonoverlapping(sysex.as_ptr(), data, n) };
                    finish_header(&m.cb, handle, MIM_LONGDATA, hdr, Some(n as u32));
                }
                sysex.clear();
            }
            continue;
        }
        if b == 0xF0 {
            in_sysex = true;
            sysex.clear();
            sysex.push(b);
            running = 0;
            continue;
        }
        if b >= 0x80 {
            pending[0] = b;
            have = 1;
            need = 1 + midi_length(b).unwrap_or(0);
            if b < 0xF0 {
                running = b;
            } else {
                running = 0;
            }
        } else if have == 0 && running != 0 {
            pending[0] = running;
            pending[1] = b;
            have = 2;
            need = 1 + midi_length(running).unwrap_or(0);
        } else if have > 0 {
            pending[have] = b;
            have += 1;
        } else {
            continue;
        }
        if have == need {
            let msg = pending[0] as u64 | (pending[1] as u64) << 8 | (pending[2] as u64) << 16;
            if started {
                m.cb.send(handle, MIM_DATA, msg, stamp);
            }
            have = 0;
        }
    }
    0
}

extern "win64" fn midiInGetNumDevs() -> u32 {
    midi_ports().len() as u32
}

extern "win64" fn midiInGetDevCapsA(id: u64, caps: *mut u8, size: u32) -> u32 {
    midi_caps(id, caps, size, false, true)
}
extern "win64" fn midiInGetDevCapsW(id: u64, caps: *mut u8, size: u32) -> u32 {
    midi_caps(id, caps, size, true, true)
}

extern "win64" fn midiInOpen(handle: *mut u64, id: u32, callback: u64, instance: u64, flags: u32) -> u32 {
    let ports = midi_ports();
    let Some(i) = device_index(id as u64, ports.len()) else { return MMSYSERR_BADDEVICEID };
    if handle.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    let cb = match Callback::new(callback, instance, flags & !MIDI_IO_STATUS) {
        Ok(c) => c,
        Err(e) => return e,
    };
    let path = alloc::format!("/dev/{}", ports[i]);
    let Ok(file) = os_std::fs::OpenOptions::new().read(true).open(path.as_str()) else { return MMSYSERR_ALLOCATED };
    let h = new_handle();
    let m = Arc::new(MidiIn { cb, file: Mutex::new(file), state: Mutex::new(MidiInState { queue: VecDeque::new(), started: false, closing: false, epoch_ms: crate::kernel32::now_ns() / 1_000_000 }) });
    MIDI_INS.lock().unwrap().insert(h, m);
    if !start_thread(midi_in_worker, h) {
        MIDI_INS.lock().unwrap().remove(&h);
        return MMSYSERR_NOMEM;
    }
    // SAFETY: the caller's handle out pointer.
    unsafe { *handle = h };
    cb.send(h, MIM_OPEN, 0, 0);
    MMSYSERR_NOERROR
}

extern "win64" fn midiInPrepareHeader(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match midi_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if midi_in(h).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    set_header_flags(hdr, header_flags(hdr) | WHDR_PREPARED);
    MMSYSERR_NOERROR
}

extern "win64" fn midiInUnprepareHeader(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match midi_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if midi_in(h).is_none() {
        return MMSYSERR_INVALHANDLE;
    }
    let flags = header_flags(hdr);
    if flags & WHDR_INQUEUE != 0 {
        return MIDIERR_STILLPLAYING;
    }
    set_header_flags(hdr, flags & !(WHDR_PREPARED | WHDR_DONE));
    MMSYSERR_NOERROR
}

extern "win64" fn midiInAddBuffer(h: u64, header: *const u8, size: u32) -> u32 {
    let hdr = match midi_header(header, size) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(m) = midi_in(h) else { return MMSYSERR_INVALHANDLE };
    let flags = header_flags(hdr);
    if flags & WHDR_PREPARED == 0 {
        return MIDIERR_UNPREPARED;
    }
    if flags & WHDR_INQUEUE != 0 {
        return MIDIERR_STILLPLAYING;
    }
    set_header_flags(hdr, (flags & !WHDR_DONE) | WHDR_INQUEUE);
    m.state.lock().unwrap().queue.push_back(hdr);
    MMSYSERR_NOERROR
}

extern "win64" fn midiInStart(h: u64) -> u32 {
    let Some(m) = midi_in(h) else { return MMSYSERR_INVALHANDLE };
    let mut s = m.state.lock().unwrap();
    s.started = true;
    s.epoch_ms = crate::kernel32::now_ns() / 1_000_000;
    MMSYSERR_NOERROR
}

extern "win64" fn midiInStop(h: u64) -> u32 {
    let Some(m) = midi_in(h) else { return MMSYSERR_INVALHANDLE };
    m.state.lock().unwrap().started = false;
    MMSYSERR_NOERROR
}

/// Stops input and returns the queued sysex buffers empty.
extern "win64" fn midiInReset(h: u64) -> u32 {
    let Some(m) = midi_in(h) else { return MMSYSERR_INVALHANDLE };
    let queued: alloc::vec::Vec<u64> = {
        let mut s = m.state.lock().unwrap();
        s.started = false;
        s.queue.drain(..).collect()
    };
    for hdr in queued {
        finish_header(&m.cb, h, MIM_LONGDATA, hdr, Some(0));
    }
    MMSYSERR_NOERROR
}

extern "win64" fn midiInClose(h: u64) -> u32 {
    let Some(m) = midi_in(h) else { return MMSYSERR_INVALHANDLE };
    if !m.state.lock().unwrap().queue.is_empty() {
        return MIDIERR_STILLPLAYING;
    }
    m.state.lock().unwrap().closing = true;
    MIDI_INS.lock().unwrap().remove(&h);
    m.cb.send(h, MIM_CLOSE, 0, 0);
    MMSYSERR_NOERROR
}

extern "win64" fn midiInMessage(h: u64, _message: u32, _a: u64, _b: u64) -> u32 {
    if midi_in(h).is_some() {
        MMSYSERR_NOTSUPPORTED
    } else {
        MMSYSERR_BADDEVICEID
    }
}

// ---- error texts ---------------------------------------------------------------------------

fn mm_error_text(code: u32) -> Option<&'static str> {
    Some(match code {
        0 => "The specified command was carried out.",
        1 => "Undefined external error.",
        2 => "A device ID has been used that is out of range for your system.",
        3 => "The driver was not enabled.",
        4 => "The specified device is already in use.  Wait until it is free, and then try again.",
        5 => "The specified device handle is invalid.",
        6 => "There is no driver installed on your system !\n",
        7 => "Not enough memory available for this task.  Quit one or more applications to increase available memory, and then try again.",
        8 => "This function is not supported.  Use the Capabilities function to determine which functions and messages the driver supports.",
        9 => "An error number was specified that is not defined in the system.",
        10 => "An invalid flag was passed to a system function.",
        11 => "An invalid parameter was passed to a system function.",
        32 => "The specified format is not supported or cannot be translated.  Use the Capabilities function to determine the supported formats",
        33 => "Cannot perform this operation while media data is still playing.  Reset the device, or wait until the data is finished playing.",
        34 => "The wave header was not prepared.  Use the Prepare function to prepare the header, and then try again.",
        64 => "The MIDI header was not prepared.  Use the Prepare function to prepare the header, and then try again.",
        65 => "Cannot perform this operation while media data is still playing.  Reset the device, or wait until the data is finished playing.",
        _ => return None,
    })
}

/// waveOutGetErrorTextW / midiOutGetErrorTextW and their input and ANSI forms.
fn error_text(code: u32, out: *mut u8, chars: u32, wide: bool) -> u32 {
    let Some(text) = mm_error_text(code) else { return MMSYSERR_BADERRNUM };
    if out.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    if wide {
        crate::kernel32::out_w(text, out as *mut u16, chars);
    } else {
        crate::kernel32::out_a(text, out, chars);
    }
    MMSYSERR_NOERROR
}

const MMSYSERR_BADERRNUM: u32 = 9;

extern "win64" fn waveOutGetErrorTextA(code: u32, out: *mut u8, chars: u32) -> u32 {
    error_text(code, out, chars, false)
}
extern "win64" fn waveOutGetErrorTextW(code: u32, out: *mut u8, chars: u32) -> u32 {
    error_text(code, out, chars, true)
}
extern "win64" fn waveInGetErrorTextA(code: u32, out: *mut u8, chars: u32) -> u32 {
    error_text(code, out, chars, false)
}
extern "win64" fn waveInGetErrorTextW(code: u32, out: *mut u8, chars: u32) -> u32 {
    error_text(code, out, chars, true)
}
extern "win64" fn midiOutGetErrorTextA(code: u32, out: *mut u8, chars: u32) -> u32 {
    error_text(code, out, chars, false)
}
extern "win64" fn midiOutGetErrorTextW(code: u32, out: *mut u8, chars: u32) -> u32 {
    error_text(code, out, chars, true)
}
extern "win64" fn midiInGetErrorTextA(code: u32, out: *mut u8, chars: u32) -> u32 {
    error_text(code, out, chars, false)
}
extern "win64" fn midiInGetErrorTextW(code: u32, out: *mut u8, chars: u32) -> u32 {
    error_text(code, out, chars, true)
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        timeGetTime,
        timeBeginPeriod,
        timeEndPeriod,
        timeGetDevCaps,
        PlaySoundW,
        waveOutGetNumDevs,
        waveOutGetDevCapsA,
        waveOutGetDevCapsW,
        waveOutOpen,
        waveOutClose,
        waveOutPrepareHeader,
        waveOutUnprepareHeader,
        waveOutWrite,
        waveOutPause,
        waveOutRestart,
        waveOutReset,
        waveOutGetPosition,
        waveOutGetID,
        waveOutGetVolume,
        waveOutSetVolume,
        waveOutMessage,
        waveOutGetErrorTextA,
        waveOutGetErrorTextW,
        waveInGetNumDevs,
        waveInGetDevCapsA,
        waveInGetDevCapsW,
        waveInOpen,
        waveInClose,
        waveInPrepareHeader,
        waveInUnprepareHeader,
        waveInAddBuffer,
        waveInStart,
        waveInStop,
        waveInReset,
        waveInGetPosition,
        waveInMessage,
        waveInGetErrorTextA,
        waveInGetErrorTextW,
        midiOutGetNumDevs,
        midiOutGetDevCapsA,
        midiOutGetDevCapsW,
        midiOutOpen,
        midiOutClose,
        midiOutShortMsg,
        midiOutLongMsg,
        midiOutPrepareHeader,
        midiOutUnprepareHeader,
        midiOutReset,
        midiOutMessage,
        midiOutGetErrorTextA,
        midiOutGetErrorTextW,
        midiInGetNumDevs,
        midiInGetDevCapsA,
        midiInGetDevCapsW,
        midiInOpen,
        midiInClose,
        midiInPrepareHeader,
        midiInUnprepareHeader,
        midiInAddBuffer,
        midiInStart,
        midiInStop,
        midiInReset,
        midiInMessage,
        midiInGetErrorTextA,
        midiInGetErrorTextW,
    ]
}
