//! EDID 1.3/1.4 base blocks and CEA-861 extension blocks.
//!
//! [`Edid::parse`] validates the mandatory blocks and returns the monitor
//! identification, feature flags and the modes the display describes:
//! established timings, standard timings, detailed timing descriptors (DTDs)
//! from the base block and from CEA-861 extensions, and the video formats of
//! CEA data blocks. Modes without an explicit pixel clock stay in the list
//! with `pixel_clock_khz == None`.
//!
//! Only the first 128 bytes of a base block and the 128-byte extension
//! blocks are interpreted. Extensions other than CEA-861 are ignored after
//! their checksum passes.
//!
//! References: VESA Enhanced EDID Standard 1.4, CEA-861-F.

use alloc::string::String;
use alloc::vec::Vec;

/// Every EDID block is 128 bytes.
pub const BLOCK_LEN: usize = 128;

const HEADER: [u8; 8] = [0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00];

/// A detailed timing in the terms of a DTD.
///
/// All counts are pixels or lines; the blanking fields include the sync
/// pulse and the front porch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    pub pixel_clock_khz: u32,
    pub h_active: u16,
    pub h_blank: u16,
    pub h_front: u16,
    pub h_sync: u16,
    pub v_active: u16,
    pub v_blank: u16,
    pub v_front: u16,
    pub v_sync: u16,
    pub h_size_mm: u16,
    pub v_size_mm: u16,
    pub h_border: u8,
    pub v_border: u8,
    pub interlaced: bool,
    /// Meaningful only when the sync type is digital separate.
    pub h_sync_positive: bool,
    /// Meaningful only when the sync type is digital separate.
    pub v_sync_positive: bool,
    /// The sync type bits were digital separate, so the polarities above are
    /// real; composite and analog sync leave them false.
    pub digital_separate: bool,
}

impl Timing {
    pub fn htotal(&self) -> u32 {
        self.h_active as u32 + self.h_blank as u32
    }

    pub fn vtotal(&self) -> u32 {
        self.v_active as u32 + self.v_blank as u32
    }

    /// Refresh rate in millihertz. An interlaced timing reports its field
    /// rate (twice the frame rate), as DRM and Windows do.
    pub fn refresh_mhz(&self) -> u32 {
        let lines = self.htotal() as u64 * self.vtotal() as u64;
        if lines == 0 {
            return 0;
        }
        let mut num = self.pixel_clock_khz as u64 * 1_000_000;
        if self.interlaced {
            num *= 2;
        }
        (num / lines) as u32
    }

    /// `h_front + h_sync + h_back` and the vertical equivalent.
    pub fn h_back(&self) -> u16 {
        self.h_blank.saturating_sub(self.h_front + self.h_sync)
    }

    pub fn v_back(&self) -> u16 {
        self.v_blank.saturating_sub(self.v_front + self.v_sync)
    }

    /// The mode this timing describes, without a preference flag.
    pub fn mode(&self) -> Mode {
        Mode {
            width: self.h_active,
            height: self.v_active,
            refresh_mhz: self.refresh_mhz(),
            pixel_clock_khz: Some(self.pixel_clock_khz),
            interlaced: self.interlaced,
            preferred: false,
            timing: Some(*self),
        }
    }
}

/// One display mode. A mode without a pixel clock (a standard timing or a
/// CEA short video descriptor) is still usable to match a requested format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mode {
    pub width: u16,
    pub height: u16,
    /// Vertical refresh in millihertz (field rate when interlaced).
    pub refresh_mhz: u32,
    pub pixel_clock_khz: Option<u32>,
    pub interlaced: bool,
    /// The monitor marked this mode as preferred.
    pub preferred: bool,
    pub timing: Option<Timing>,
}

/// Which power-saving modes and optional features the monitor advertises.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features {
    pub standby: bool,
    pub suspend: bool,
    pub active_off: bool,
    pub srgb: bool,
    /// The first detailed timing descriptor is preferred.
    pub preferred_timing: bool,
    /// Continuous-frequency displays (EDID 1.4).
    pub continuous_frequency: bool,
}

/// A parsed EDID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edid {
    /// Three-letter PNP manufacturer ID, for example `DEL`.
    pub manufacturer: [u8; 3],
    pub product: u16,
    pub serial: u32,
    /// Week of manufacture (0 or 0xFF mean "unspecified"/model year).
    pub week: u8,
    /// Year of manufacture, or the model year when `model_year` is set.
    pub year: u16,
    pub model_year: bool,
    /// Major and minor EDID version.
    pub version: (u8, u8),
    pub digital: bool,
    pub width_cm: u8,
    pub height_cm: u8,
    /// Gamma times 100 (220 means 2.20); `None` when the monitor leaves it
    /// undefined.
    pub gamma_hundredths: Option<u16>,
    pub features: Features,
    /// Monitor name from the `0xFC` display descriptor.
    pub name: Option<String>,
    /// Serial number from the `0xFF` display descriptor.
    pub serial_text: Option<String>,
    /// Number of 128-byte extensions the base block declares.
    pub extensions: u8,
    pub modes: Vec<Mode>,
}

impl Edid {
    pub fn parse(bytes: &[u8]) -> Result<Edid, EdidError> {
        if bytes.len() < BLOCK_LEN {
            return Err(EdidError::TooShort);
        }
        let base = &bytes[..BLOCK_LEN];
        if base[..8] != HEADER {
            return Err(EdidError::BadHeader);
        }
        checksum(base, 0)?;
        let version = (base[18], base[19]);
        if version.0 != 1 {
            return Err(EdidError::UnsupportedVersion { major: version.0, minor: version.1 });
        }
        let extensions = base[126];
        let available = bytes.len() / BLOCK_LEN - 1;
        if extensions as usize > available {
            return Err(EdidError::MissingExtensions { declared: extensions as usize, available });
        }

        let features = Features {
            standby: base[24] & 0x80 != 0,
            suspend: base[24] & 0x40 != 0,
            active_off: base[24] & 0x20 != 0,
            srgb: base[24] & 0x04 != 0,
            preferred_timing: base[24] & 0x02 != 0,
            continuous_frequency: base[24] & 0x01 != 0,
        };
        let manufacturer = decode_manufacturer(u16::from_be_bytes([base[8], base[9]]));
        let gamma_hundredths = (base[23] != 0xFF).then(|| base[23] as u16 + 100);

        let mut modes = Vec::new();
        push_established(&mut modes, &base[35..38]);
        push_standard(&mut modes, &base[38..54]);

        let mut name = None;
        let mut serial_text = None;
        let mut dtds = Vec::new();
        for descriptor in base[54..126].as_chunks::<18>().0 {
            if descriptor[0] == 0 && descriptor[1] == 0 && descriptor[2] == 0 {
                read_display_descriptor(descriptor, &mut name, &mut serial_text);
            } else if let Some(t) = parse_dtd(descriptor) {
                dtds.push(t);
            }
        }
        // Only the first detailed timing descriptor can be the preferred one.
        let mut preferred_taken = false;
        for (i, t) in dtds.into_iter().enumerate() {
            let mut mode = t.mode();
            mode.preferred = i == 0 && features.preferred_timing;
            preferred_taken |= mode.preferred;
            push_mode(&mut modes, mode);
        }

        for index in 0..extensions as usize {
            let block = &bytes[(index + 1) * BLOCK_LEN..(index + 2) * BLOCK_LEN];
            checksum(block, index + 1)?;
            if block[0] == 0x02 {
                parse_cea(block, &mut modes, &mut preferred_taken)?;
            }
        }

        Ok(Edid {
            manufacturer,
            product: u16::from_le_bytes([base[10], base[11]]),
            serial: u32::from_le_bytes([base[12], base[13], base[14], base[15]]),
            week: base[16],
            year: 1990 + base[17] as u16,
            model_year: base[16] == 0xFF,
            version,
            digital: base[20] & 0x80 != 0,
            width_cm: base[21],
            height_cm: base[22],
            gamma_hundredths,
            features,
            name,
            serial_text,
            extensions,
            modes,
        })
    }

    /// The preferred mode, or the closest stand-in when the monitor does not
    /// mark one: the first mode with a pixel clock, then any mode.
    pub fn preferred_mode(&self) -> Option<Mode> {
        self.modes
            .iter()
            .find(|m| m.preferred && m.pixel_clock_khz.is_some())
            .or_else(|| self.modes.iter().find(|m| m.preferred))
            .or_else(|| self.modes.iter().find(|m| m.pixel_clock_khz.is_some()))
            .or_else(|| self.modes.first())
            .copied()
    }

    /// The manufacturer ID as text (always three ASCII letters after a
    /// successful parse).
    pub fn vendor(&self) -> &str {
        core::str::from_utf8(&self.manufacturer).unwrap_or("???")
    }
}

/// Why an EDID buffer was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdidError {
    /// Fewer than 128 bytes.
    TooShort,
    /// The fixed eight-byte header is missing.
    BadHeader,
    /// Block `block` (0 is the base block) has a non-zero byte sum.
    BadChecksum { block: usize },
    /// Only EDID major version 1 is understood.
    UnsupportedVersion { major: u8, minor: u8 },
    /// The base block declares more extensions than the buffer holds.
    MissingExtensions { declared: usize, available: usize },
    /// A CEA-861 extension block has an inconsistent layout.
    MalformedCea,
}

fn checksum(block: &[u8], index: usize) -> Result<(), EdidError> {
    let sum = block[..BLOCK_LEN].iter().fold(0u8, |a, &b| a.wrapping_add(b));
    if sum == 0 {
        Ok(())
    } else {
        Err(EdidError::BadChecksum { block: index })
    }
}

fn decode_manufacturer(id: u16) -> [u8; 3] {
    let letter = |v: u16| match v {
        1..=26 => b'A' - 1 + v as u8,
        _ => b'?',
    };
    [letter((id >> 10) & 0x1F), letter((id >> 5) & 0x1F), letter(id & 0x1F)]
}

/// Established timings, most significant bit first: byte 0, byte 1, then bit
/// 7 of byte 2.
const ESTABLISHED: [(u16, u16, u16, bool); 17] = [
    (720, 400, 70, false),
    (720, 400, 88, false),
    (640, 480, 60, false),
    (640, 480, 67, false),
    (640, 480, 72, false),
    (640, 480, 75, false),
    (800, 600, 56, false),
    (800, 600, 60, false),
    (800, 600, 72, false),
    (800, 600, 75, false),
    (832, 624, 75, false),
    (1024, 768, 87, true),
    (1024, 768, 60, false),
    (1024, 768, 70, false),
    (1024, 768, 75, false),
    (1280, 1024, 75, false),
    (1152, 870, 75, false),
];

fn push_established(modes: &mut Vec<Mode>, bitmap: &[u8]) {
    for (i, &(width, height, refresh, interlaced)) in ESTABLISHED.iter().enumerate() {
        let (byte, mask) = match i {
            0..=7 => (bitmap[0], 0x80 >> i),
            8..=15 => (bitmap[1], 0x80 >> (i - 8)),
            _ => (bitmap[2], 0x80),
        };
        if byte & mask != 0 {
            push_mode(
                modes,
                Mode {
                    width,
                    height,
                    refresh_mhz: refresh as u32 * 1000,
                    pixel_clock_khz: None,
                    interlaced,
                    preferred: false,
                    timing: None,
                },
            );
        }
    }
}

fn push_standard(modes: &mut Vec<Mode>, records: &[u8]) {
    for record in records.as_chunks::<2>().0 {
        let (x, y) = (record[0], record[1]);
        // 0x00 0x00 and 0x01 0x01 mark an unused entry.
        if x == 0 || (x == 0x01 && y == 0x01) {
            continue;
        }
        let width = (x as u16 + 31) * 8;
        let height = match y >> 6 {
            0 => round_div(width as u32 * 10, 16) as u16,
            1 => round_div(width as u32 * 3, 4) as u16,
            2 => round_div(width as u32 * 4, 5) as u16,
            // EDID rounds 16:9 heights up to a multiple of 8, which keeps
            // 1360x768 and 1366x768 in the same format.
            _ => ((width as u32 * 9 / 16 + 7) & !7) as u16,
        };
        let refresh = (y & 0x3F) as u32 + 60;
        push_mode(
            modes,
            Mode {
                width,
                height,
                refresh_mhz: refresh * 1000,
                pixel_clock_khz: None,
                interlaced: false,
                preferred: false,
                timing: None,
            },
        );
    }
}

fn round_div(num: u32, den: u32) -> u32 {
    (num + den / 2) / den
}

fn read_display_descriptor(d: &[u8], name: &mut Option<String>, serial_text: &mut Option<String>) {
    // A zero tag is a dummy descriptor; only the first name and serial count.
    let text = |bytes: &[u8]| -> Option<String> {
        let end = bytes.iter().position(|&b| b == 0x0A || b == 0x00).unwrap_or(bytes.len());
        let s: String = bytes[..end].iter().filter(|b| (0x20..=0x7E).contains(*b)).map(|&b| b as char).collect();
        let trimmed = s.trim();
        (!trimmed.is_empty()).then(|| String::from(trimmed))
    };
    match d[3] {
        0xFC if name.is_none() => *name = text(&d[5..18]),
        0xFF if serial_text.is_none() => *serial_text = text(&d[5..18]),
        _ => {}
    }
}

fn parse_dtd(d: &[u8]) -> Option<Timing> {
    if d.len() < 18 {
        return None;
    }
    let pixel_clock_10khz = u16::from_le_bytes([d[0], d[1]]) as u32;
    if pixel_clock_10khz == 0 {
        return None;
    }
    let h_active = d[2] as u16 | ((d[4] as u16 & 0xF0) << 4);
    let h_blank = d[3] as u16 | ((d[4] as u16 & 0x0F) << 8);
    let v_active = d[5] as u16 | ((d[7] as u16 & 0xF0) << 4);
    let v_blank = d[6] as u16 | ((d[7] as u16 & 0x0F) << 8);
    let h_front = d[8] as u16 | ((d[11] as u16 & 0xC0) << 2);
    let h_sync = d[9] as u16 | ((d[11] as u16 & 0x30) << 4);
    let v_front = (d[10] as u16 >> 4) | ((d[11] as u16 & 0x0C) << 2);
    let v_sync = (d[10] as u16 & 0x0F) | ((d[11] as u16 & 0x03) << 4);
    let h_size_mm = d[12] as u16 | ((d[13] as u16 & 0xF0) << 4);
    let v_size_mm = d[14] as u16 | ((d[13] as u16 & 0x0F) << 8);
    let interlaced = d[17] & 0x80 != 0;
    let digital_separate = (d[17] >> 3) & 3 == 3;
    if h_active == 0 || v_active == 0 || h_blank < h_front + h_sync || v_blank < v_front + v_sync {
        return None;
    }
    Some(Timing {
        pixel_clock_khz: pixel_clock_10khz * 10,
        h_active,
        h_blank,
        h_front,
        h_sync,
        v_active,
        v_blank,
        v_front,
        v_sync,
        h_size_mm,
        v_size_mm,
        h_border: d[15],
        v_border: d[16],
        interlaced,
        h_sync_positive: digital_separate && d[17] & 0x02 != 0,
        v_sync_positive: digital_separate && d[17] & 0x04 != 0,
        digital_separate,
    })
}

fn push_mode(modes: &mut Vec<Mode>, mode: Mode) {
    if let Some(existing) = modes.iter_mut().find(|e| {
        e.width == mode.width
            && e.height == mode.height
            && e.refresh_mhz == mode.refresh_mhz
            && e.interlaced == mode.interlaced
    }) {
        existing.preferred |= mode.preferred;
        if existing.pixel_clock_khz.is_none() && mode.pixel_clock_khz.is_some() {
            existing.pixel_clock_khz = mode.pixel_clock_khz;
            existing.timing = mode.timing;
        }
        return;
    }
    modes.push(mode);
}

/// CEA-861 short video descriptor VICs. Only progressive and interlaced
/// formats a desktop uses are listed; unknown VICs are skipped.
const VICS: [(u8, u16, u16, u32, bool); 33] = [
    (1, 640, 480, 60, false),
    (2, 720, 480, 60, false),
    (3, 720, 480, 60, false),
    (4, 1280, 720, 60, false),
    (5, 1920, 1080, 60, true),
    (6, 1440, 480, 60, true),
    (7, 1440, 480, 60, true),
    (8, 1440, 240, 60, false),
    (9, 1440, 240, 60, false),
    (10, 2880, 480, 60, true),
    (11, 2880, 480, 60, true),
    (12, 2880, 240, 60, false),
    (13, 2880, 240, 60, false),
    (14, 1440, 480, 60, false),
    (15, 1440, 480, 60, false),
    (16, 1920, 1080, 60, false),
    (17, 720, 576, 50, false),
    (18, 1280, 720, 50, false),
    (19, 1920, 1080, 50, true),
    (20, 1440, 576, 50, true),
    (21, 1440, 576, 50, true),
    (22, 1440, 288, 50, false),
    (23, 1440, 288, 50, false),
    (24, 2880, 576, 50, true),
    (25, 2880, 576, 50, true),
    (26, 2880, 288, 50, false),
    (27, 2880, 288, 50, false),
    (28, 1440, 576, 50, false),
    (29, 1440, 576, 50, false),
    (30, 1440, 576, 50, false),
    (31, 1920, 1080, 50, false),
    (32, 1920, 1080, 24, false),
    (33, 1920, 1080, 25, false),
];

fn vic_mode(vic: u8) -> Option<Mode> {
    let &(_, width, height, refresh, interlaced) = VICS.iter().find(|v| v.0 == vic)?;
    Some(Mode {
        width,
        height,
        refresh_mhz: refresh * 1000,
        pixel_clock_khz: None,
        interlaced,
        preferred: false,
        timing: None,
    })
}

fn parse_cea(block: &[u8], modes: &mut Vec<Mode>, preferred_taken: &mut bool) -> Result<(), EdidError> {
    let dtd_offset = block[2] as usize;
    if !(4..=127).contains(&dtd_offset) {
        return Err(EdidError::MalformedCea);
    }
    let mut i = 4;
    while i < dtd_offset {
        let header = block[i];
        if header == 0 {
            break; // padding up to the DTD area
        }
        let len = (header & 0x1F) as usize;
        let end = i + 1 + len;
        if end > dtd_offset {
            return Err(EdidError::MalformedCea);
        }
        if header >> 5 == 2 {
            for &svd in &block[i + 1..end] {
                if let Some(mut mode) = vic_mode(svd & 0x7F) {
                    if svd & 0x80 != 0 && !*preferred_taken {
                        mode.preferred = true;
                        *preferred_taken = true;
                    }
                    push_mode(modes, mode);
                }
            }
        }
        i = end;
    }

    // Data blocks may end before the DTD area; the gap is padding.
    i = dtd_offset;
    let native = block[3] & 0x0F;
    let mut dtds = 0u8;
    while i + 18 <= BLOCK_LEN {
        let d = &block[i..i + 18];
        if d[0..3] == [0, 0, 0] {
            break;
        }
        if let Some(t) = parse_dtd(d) {
            let mut mode = t.mode();
            if dtds < native && !*preferred_taken {
                mode.preferred = true;
                *preferred_taken = true;
            }
            push_mode(modes, mode);
        }
        dtds = dtds.saturating_add(1);
        i += 18;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a 128-byte base block with one 1920x1080@60 DTD, a name, a
    /// serial, an established 640x480@60 and a 1280x1024@60 standard timing.
    fn base_block() -> [u8; BLOCK_LEN] {
        let mut b = [0u8; BLOCK_LEN];
        b[..8].copy_from_slice(&HEADER);
        // Manufacturer "DEL" = 0x10AC, product 0x1234, serial 0x01020304.
        b[8..10].copy_from_slice(&0x10ACu16.to_be_bytes());
        b[10..12].copy_from_slice(&0x1234u16.to_le_bytes());
        b[12..16].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        b[16] = 10;
        b[17] = 30; // 2020
        b[18] = 1;
        b[19] = 3;
        b[20] = 0x80; // digital
        b[21] = 53;
        b[22] = 30;
        b[23] = 120; // gamma 2.20
        b[24] = 0x02; // preferred timing
        b[35] = 0x20; // 640x480@60
                      // Standard timing 1: 1280x1024@60 (5:4).
        b[38] = (1280 / 8 - 31) as u8;
        b[39] = 0x80; // aspect 5:4, refresh 60
                      // Descriptor 1: 1920x1080@60 DTD.
        let dtd: [u8; 18] = [
            2, 58, // 14850 * 10 kHz
            0x80, 0x18, 0x71, // 1920 active, 280 blank
            0x38, 0x2D, 0x40, // 1080 active, 45 blank
            88, 44, 0x45, // front 88, sync 44, vsync front 4, pulse 5
            0x00, // high bits
            0x12, 0x21, 0x2C, 0x00, // image size 53x30 cm
            0x00, // borders
            0x1E, // digital separate, +H +V
        ];
        b[54..72].copy_from_slice(&dtd);
        // Descriptor 2: monitor name.
        b[72] = 0;
        b[73] = 0;
        b[74] = 0;
        b[75] = 0xFC;
        b[77..77 + 8].copy_from_slice(b"TestMon\x0A");
        // Descriptor 3: serial text.
        b[90] = 0;
        b[91] = 0;
        b[92] = 0;
        b[93] = 0xFF;
        b[95..95 + 6].copy_from_slice(b"SN1234");
        fix_checksum(&mut b);
        b
    }

    fn fix_checksum(b: &mut [u8; BLOCK_LEN]) {
        b[127] = 0;
        let sum = b[..BLOCK_LEN].iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[127] = 0u8.wrapping_sub(sum);
    }

    fn cea_block(vic: u8) -> [u8; BLOCK_LEN] {
        let mut b = [0u8; BLOCK_LEN];
        b[0] = 0x02;
        b[1] = 3;
        b[2] = 6; // DTD starts after the two-byte video block
        b[3] = 1; // one native DTD
        b[4] = (2 << 5) | 1; // video data block, one SVD
        b[5] = vic;
        // A 1920x1080@60 DTD, same encoding as the base block's.
        let dtd: [u8; 18] =
            [2, 58, 0x80, 0x18, 0x71, 0x38, 0x2D, 0x40, 88, 44, 0x45, 0x00, 0x12, 0x21, 0x2C, 0x00, 0x00, 0x1E];
        b[6..24].copy_from_slice(&dtd);
        fix_checksum(&mut b);
        b
    }

    #[test]
    fn parses_base_block_identity_and_modes() {
        let e = Edid::parse(&base_block()).unwrap();
        assert_eq!(e.vendor(), "DEL");
        assert_eq!(e.product, 0x1234);
        assert_eq!(e.serial, 0x0102_0304);
        assert_eq!((e.version, e.year, e.week), ((1, 3), 2020, 10));
        assert!(e.digital);
        assert_eq!(e.gamma_hundredths, Some(220));
        assert_eq!(e.width_cm, 53);
        assert_eq!(e.name.as_deref(), Some("TestMon"));
        assert_eq!(e.serial_text.as_deref(), Some("SN1234"));
        assert!(e.features.preferred_timing);
        assert_eq!(e.extensions, 0);

        let preferred = e.preferred_mode().unwrap();
        assert_eq!((preferred.width, preferred.height, preferred.refresh_mhz), (1920, 1080, 60_000));
        assert!(preferred.preferred);
        assert_eq!(preferred.pixel_clock_khz, Some(148_500));
        let t = preferred.timing.unwrap();
        assert_eq!((t.htotal(), t.vtotal()), (2200, 1125));
        assert_eq!((t.h_front, t.h_sync, t.h_back()), (88, 44, 148));
        assert_eq!((t.v_front, t.v_sync, t.v_back()), (4, 5, 36));
        assert_eq!((t.h_size_mm, t.v_size_mm), (530, 300));
        assert!(t.digital_separate && t.h_sync_positive && t.v_sync_positive);
        assert!(e.modes.iter().any(|m| (m.width, m.height, m.refresh_mhz) == (640, 480, 60_000)));
        // 1280x1024@60 standard timing; duplicates of DTDs merge.
        assert!(e
            .modes
            .iter()
            .any(|m| (m.width, m.height, m.refresh_mhz, m.pixel_clock_khz) == (1280, 1024, 60_000, None)));
        assert!(e.modes.iter().filter(|m| (m.width, m.height) == (1920, 1080)).all(|m| m.pixel_clock_khz.is_some()));
    }

    #[test]
    fn rejects_bad_structure_without_panicking() {
        let mut b = base_block();
        b[0] = 1;
        assert_eq!(Edid::parse(&b), Err(EdidError::BadHeader));

        let mut b = base_block();
        b[127] ^= 1;
        assert_eq!(Edid::parse(&b), Err(EdidError::BadChecksum { block: 0 }));

        let b = base_block();
        assert_eq!(Edid::parse(&b[..127]), Err(EdidError::TooShort));

        let mut b = base_block();
        b[18] = 2;
        fix_checksum(&mut b);
        assert_eq!(Edid::parse(&b), Err(EdidError::UnsupportedVersion { major: 2, minor: 3 }));

        let mut b = base_block();
        b[126] = 2;
        fix_checksum(&mut b);
        assert_eq!(Edid::parse(&b), Err(EdidError::MissingExtensions { declared: 2, available: 0 }));

        // A DTD with impossible blanking is skipped, not trusted.
        let mut b = base_block();
        b[54 + 3] = 0; // h blank low byte
        b[54 + 4] = 0x70; // h active high nibble stays, h blank high nibble 0
        fix_checksum(&mut b);
        let e = Edid::parse(&b).unwrap();
        assert!(e.modes.iter().all(|m| m.pixel_clock_khz.is_none()));
    }

    #[test]
    fn parses_cea_extension_and_marks_native_dtd() {
        let mut bytes = [0u8; 2 * BLOCK_LEN];
        let mut base = base_block();
        base[24] = 0; // no preferred base DTD
        base[126] = 1;
        fix_checksum(&mut base);
        bytes[..BLOCK_LEN].copy_from_slice(&base);
        bytes[BLOCK_LEN..].copy_from_slice(&cea_block(16));

        let e = Edid::parse(&bytes).unwrap();
        assert_eq!(e.extensions, 1);
        assert!(e.modes.iter().any(|m| (m.width, m.height, m.refresh_mhz) == (1920, 1080, 60_000)));
        let preferred = e.preferred_mode().unwrap();
        assert!(preferred.preferred);
        assert_eq!((preferred.width, preferred.height), (1920, 1080));

        // The extension checksum is verified as block 1.
        let mut bad = bytes;
        bad[BLOCK_LEN + 127] ^= 0x80;
        assert_eq!(Edid::parse(&bad), Err(EdidError::BadChecksum { block: 1 }));

        // A data block that overruns the DTD offset is rejected.
        let mut bad = bytes;
        bad[BLOCK_LEN + 4] = (2 << 5) | 30;
        fix_checksum((&mut bad[BLOCK_LEN..]).try_into().unwrap());
        assert_eq!(Edid::parse(&bad), Err(EdidError::MalformedCea));
    }

    #[test]
    fn cea_padding_before_dtds_is_skipped() {
        let mut bytes = [0u8; 2 * BLOCK_LEN];
        let mut base = base_block();
        base[24] = 0;
        base[126] = 1;
        base[54] = 0;
        base[55] = 0; // no base DTD
        fix_checksum(&mut base);
        bytes[..BLOCK_LEN].copy_from_slice(&base);

        let mut ext = [0u8; BLOCK_LEN];
        ext[0] = 0x02;
        ext[1] = 3;
        ext[2] = 8; // two padding bytes after the video block
        ext[3] = 1;
        ext[4] = (2 << 5) | 1;
        ext[5] = 4; // 1280x720@60
        let dtd: [u8; 18] =
            [2, 58, 0x80, 0x18, 0x71, 0x38, 0x2D, 0x40, 88, 44, 0x45, 0x00, 0x12, 0x21, 0x2C, 0x00, 0x00, 0x1E];
        ext[8..26].copy_from_slice(&dtd);
        fix_checksum(&mut ext);
        bytes[BLOCK_LEN..].copy_from_slice(&ext);

        let e = Edid::parse(&bytes).unwrap();
        let preferred = e.preferred_mode().unwrap();
        assert_eq!((preferred.width, preferred.height), (1920, 1080));
        assert_eq!(preferred.pixel_clock_khz, Some(148_500));
        assert!(preferred.preferred);
    }

    #[test]
    fn mutated_blocks_never_panic() {
        let mut bytes = [0u8; 2 * BLOCK_LEN];
        let mut base = base_block();
        base[126] = 1;
        fix_checksum(&mut base);
        bytes[..BLOCK_LEN].copy_from_slice(&base);
        bytes[BLOCK_LEN..].copy_from_slice(&cea_block(16));
        let mut state = 0x1234_5678u32;
        let mut next = || {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            state
        };
        for _ in 0..4000 {
            let mut m = bytes;
            for _ in 0..(next() % 6 + 1) {
                let i = next() as usize % m.len();
                m[i] = (next() >> 24) as u8;
            }
            // Repair the checksums so the mutated fields are actually parsed.
            let (a, b) = m.split_at_mut(BLOCK_LEN);
            fix_checksum(a.try_into().unwrap());
            fix_checksum(b.try_into().unwrap());
            let _ = Edid::parse(&m);
            let cut = next() as usize % m.len();
            let _ = Edid::parse(&m[..cut]);
        }
    }

    #[test]
    fn standard_timing_rounding_and_established_interlace() {
        let mut b = base_block();
        b[38] = (1360 / 8 - 31) as u8;
        b[39] = 0xC0; // 16:9, 60 Hz
        b[35] = 0; // drop established 640x480@60
        fix_checksum(&mut b);
        let e = Edid::parse(&b).unwrap();
        assert!(e.modes.iter().any(|m| (m.width, m.height, m.refresh_mhz) == (1360, 768, 60_000)));

        let mut b = base_block();
        b[36] = 0x10; // 1024x768@87 interlaced
        fix_checksum(&mut b);
        let e = Edid::parse(&b).unwrap();
        assert!(e.modes.iter().any(|m| (m.width, m.height, m.refresh_mhz, m.interlaced) == (1024, 768, 87_000, true)));
    }

    #[test]
    fn interlaced_refresh_is_the_field_rate() {
        let t = Timing {
            pixel_clock_khz: 74_250,
            h_active: 1920,
            h_blank: 280,
            h_front: 88,
            h_sync: 44,
            v_active: 1080,
            v_blank: 45,
            v_front: 4,
            v_sync: 5,
            h_size_mm: 0,
            v_size_mm: 0,
            h_border: 0,
            v_border: 0,
            interlaced: true,
            h_sync_positive: true,
            v_sync_positive: true,
            digital_separate: true,
        };
        assert_eq!(t.refresh_mhz(), 60_000);
        assert_eq!(t.mode().refresh_mhz, 60_000);
    }

    #[test]
    fn unknown_and_harmless_blocks_are_ignored() {
        // A non-CEA extension with a valid checksum does not affect modes.
        let mut bytes = [0u8; 2 * BLOCK_LEN];
        let mut base = base_block();
        base[126] = 1;
        fix_checksum(&mut base);
        bytes[..BLOCK_LEN].copy_from_slice(&base);
        let mut ext = [0u8; BLOCK_LEN];
        ext[0] = 0x70;
        fix_checksum(&mut ext);
        bytes[BLOCK_LEN..].copy_from_slice(&ext);
        let e = Edid::parse(&bytes).unwrap();
        assert_eq!(e.extensions, 1);
        assert!(e.preferred_mode().is_some());

        // Unknown VIC values add nothing and do not fail the parse.
        let mut bytes = [0u8; 2 * BLOCK_LEN];
        let mut base = base_block();
        base[126] = 1;
        fix_checksum(&mut base);
        bytes[..BLOCK_LEN].copy_from_slice(&base);
        bytes[BLOCK_LEN..].copy_from_slice(&cea_block(250));
        assert!(Edid::parse(&bytes).is_ok());
    }
}
