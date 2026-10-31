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

// ---- wave and MIDI device inventory (no audio/MIDI hardware) ----------------------------

const MMSYSERR_NOERROR: u32 = 0;
const MMSYSERR_BADDEVICEID: u32 = 2;
const MMSYSERR_INVALHANDLE: u32 = 5;
const MMSYSERR_BADERRNUM: u32 = 9;
const MMSYSERR_INVALPARAM: u32 = 11;

extern "win64" fn waveOutGetNumDevs() -> u32 {
    0
}
extern "win64" fn waveInGetNumDevs() -> u32 {
    0
}
extern "win64" fn midiOutGetNumDevs() -> u32 {
    0
}
extern "win64" fn midiInGetNumDevs() -> u32 {
    0
}

extern "win64" fn waveOutGetDevCapsW(_id: u64, caps: *mut u8, _size: u32) -> u32 {
    if caps.is_null() { MMSYSERR_INVALPARAM } else { MMSYSERR_BADDEVICEID }
}
extern "win64" fn waveInGetDevCapsW(_id: u64, caps: *mut u8, _size: u32) -> u32 {
    if caps.is_null() { MMSYSERR_INVALPARAM } else { MMSYSERR_BADDEVICEID }
}
extern "win64" fn midiOutGetDevCapsW(_id: u64, caps: *mut u8, _size: u32) -> u32 {
    if caps.is_null() { MMSYSERR_INVALPARAM } else { MMSYSERR_BADDEVICEID }
}
extern "win64" fn midiInGetDevCapsW(_id: u64, caps: *mut u8, _size: u32) -> u32 {
    if caps.is_null() { MMSYSERR_INVALPARAM } else { MMSYSERR_BADDEVICEID }
}

extern "win64" fn waveOutOpen(out: *mut u64, _id: u32, fmt: *const u8, _cb: u64, _inst: u64, _flags: u32) -> u32 {
    if out.is_null() || fmt.is_null() { MMSYSERR_INVALPARAM } else { MMSYSERR_BADDEVICEID }
}
extern "win64" fn waveInOpen(out: *mut u64, _id: u32, fmt: *const u8, _cb: u64, _inst: u64, _flags: u32) -> u32 {
    if out.is_null() || fmt.is_null() { MMSYSERR_INVALPARAM } else { MMSYSERR_BADDEVICEID }
}
extern "win64" fn midiOutOpen(out: *mut u64, _id: u32, _cb: u64, _inst: u64, _flags: u32) -> u32 {
    if out.is_null() { MMSYSERR_INVALPARAM } else { MMSYSERR_BADDEVICEID }
}
extern "win64" fn midiInOpen(out: *mut u64, _id: u32, _cb: u64, _inst: u64, _flags: u32) -> u32 {
    if out.is_null() { MMSYSERR_INVALPARAM } else { MMSYSERR_BADDEVICEID }
}

extern "win64" fn waveOutClose(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveOutPrepareHeader(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveOutUnprepareHeader(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveOutWrite(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveOutPause(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveOutRestart(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveOutReset(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveOutGetPosition(_h: u64, _mmt: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }

extern "win64" fn waveInClose(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveInPrepareHeader(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveInUnprepareHeader(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveInAddBuffer(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveInStart(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveInStop(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn waveInReset(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }

extern "win64" fn midiOutClose(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiOutPrepareHeader(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiOutUnprepareHeader(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiOutShortMsg(_h: u64, _msg: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiOutLongMsg(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiOutReset(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }

extern "win64" fn midiInClose(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiInPrepareHeader(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiInUnprepareHeader(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiInAddBuffer(_h: u64, _hdr: *mut u8, _cb: u32) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiInStart(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiInStop(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }
extern "win64" fn midiInReset(_h: u64) -> u32 { MMSYSERR_INVALHANDLE }

fn midi_error_text(err: u32, out: *mut u16, cch: u32) -> u32 {
    if out.is_null() {
        return MMSYSERR_INVALPARAM;
    }
    let msg = match err {
        0 => "No error.",
        1 => "Unspecified error.",
        2 => "Device ID out of range.",
        4 => "Specified resource is already allocated.",
        5 => "Specified device handle is invalid.",
        6 => "No device driver is present.",
        7 => "Unable to allocate or lock memory.",
        11 => "Invalid parameter passed.",
        _ => return MMSYSERR_BADERRNUM,
    };
    if cch > 0 {
        crate::kernel32::out_w(msg, out, cch);
    }
    MMSYSERR_NOERROR
}

extern "win64" fn midiOutGetErrorTextW(err: u32, out: *mut u16, cch: u32) -> u32 {
    midi_error_text(err, out, cch)
}

extern "win64" fn midiInGetErrorTextW(err: u32, out: *mut u16, cch: u32) -> u32 {
    midi_error_text(err, out, cch)
}

pub fn exports() -> Vec<(&'static str, u64)> {
    export_table![
        timeGetTime,
        timeBeginPeriod,
        timeEndPeriod,
        timeGetDevCaps,
        PlaySoundW,
        waveOutGetNumDevs,
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
        waveInGetNumDevs,
        waveInGetDevCapsW,
        waveInOpen,
        waveInClose,
        waveInPrepareHeader,
        waveInUnprepareHeader,
        waveInAddBuffer,
        waveInStart,
        waveInStop,
        waveInReset,
        midiOutGetNumDevs,
        midiOutGetDevCapsW,
        midiOutOpen,
        midiOutClose,
        midiOutPrepareHeader,
        midiOutUnprepareHeader,
        midiOutShortMsg,
        midiOutLongMsg,
        midiOutReset,
        midiOutGetErrorTextW,
        midiInGetNumDevs,
        midiInGetDevCapsW,
        midiInOpen,
        midiInClose,
        midiInPrepareHeader,
        midiInUnprepareHeader,
        midiInAddBuffer,
        midiInStart,
        midiInStop,
        midiInReset,
        midiInGetErrorTextW
    ]
}
