//! exFAT timestamps: a 32-bit DOS date and time (2-second resolution,
//! years 1980-2107) plus a UTC offset byte in the file entry.

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The DOS timestamp of `secs` seconds after the Unix epoch (UTC); times
/// outside 1980..=2107 are clamped.
pub fn dos_from_unix(secs: i64) -> u32 {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    if y < 1980 {
        return 0x0021_0000;
    }
    if y > 2107 {
        return 0xFF9F_BF7D;
    }
    (((y - 1980) as u32) << 25) | ((m as u32) << 21) | ((d as u32) << 16) | (((rem / 3600) as u32) << 11) | ((((rem / 60) % 60) as u32) << 5) | ((rem % 60) as u32 / 2)
}

/// Seconds after the Unix epoch of a DOS timestamp read as UTC.
pub fn unix_from_dos(dos: u32) -> i64 {
    let year = 1980 + (dos >> 25) as i64;
    let month = ((dos >> 21) & 0xF).clamp(1, 12) as i64;
    let day = ((dos >> 16) & 0x1F).max(1) as i64;
    let hour = ((dos >> 11) & 0x1F) as i64;
    let minute = ((dos >> 5) & 0x3F) as i64;
    let second = ((dos & 0x1F) * 2) as i64;
    days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
}

/// A timestamp with its UTC offset byte (bit 7: valid, bits 0..=6: signed
/// quarter hours) as seconds after the Unix epoch.
pub(crate) fn unix_with_offset(dos: u32, offset: u8) -> i64 {
    let local = unix_from_dos(dos);
    if offset & 0x80 == 0 {
        return local;
    }
    let quarters = if offset & 0x40 != 0 { (offset | 0x80) as i8 as i64 } else { (offset & 0x7F) as i64 };
    local - quarters * 900
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        // 2026-10-30 12:34:56 UTC
        let secs = 1_793_363_696;
        let d = dos_from_unix(secs);
        assert_eq!(unix_from_dos(d), secs - secs % 2);
        assert_eq!(unix_from_dos(0x0021_0000), 315_532_800);
        assert_eq!(dos_from_unix(0), 0x0021_0000);
    }

    #[test]
    fn offsets() {
        let d = dos_from_unix(1_700_000_000);
        assert_eq!(unix_with_offset(d, 0), unix_from_dos(d));
        // UTC+1 (4 quarters): the stored local time is one hour ahead of UTC.
        assert_eq!(unix_with_offset(d, 0x80 | 4), unix_from_dos(d) - 3600);
        // UTC-5 (-20 quarters = 0x6C in 7-bit two's complement).
        assert_eq!(unix_with_offset(d, 0x80 | 0x6C), unix_from_dos(d) + 5 * 3600);
    }
}
