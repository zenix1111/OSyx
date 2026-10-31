//! Identification data for AMD display hardware.
//!
//! The display core on AMD APUs is DCN (Display Core Next). Programming it
//! needs register bases from the VBIOS IP discovery table, display firmware
//! and the DCN state tables; none of that is hardware-independent. This
//! module only carries the parts needed before a driver can start: the PCI
//! vendor/class check, which DCN generation a known device belongs to, and
//! the location of the ATOM header in a legacy VBIOS image.
//!
//! The device list is a small, confirmed subset. Unknown IDs return `None`;
//! add entries only together with a reference for the mapping.

/// PCI vendor ID of Advanced Micro Devices.
pub const AMD_VENDOR: u16 = 0x1002;

/// PCI class code of a display controller (`0x03`; subclass 0x00 or 0x80).
pub const DISPLAY_CLASS: u8 = 0x03;

/// The 0x55AA header of a legacy option ROM.
pub const ROM_SIGNATURE: [u8; 2] = [0x55, 0xAA];

/// The four-byte text that starts the ATOM ROM header inside a VBIOS image.
pub const ATOM_SIGNATURE: [u8; 4] = *b"ATOM";

/// Display Core Next generations of the devices listed below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DcnVersion {
    /// Raven, Raven2, Picasso.
    Dcn1,
    /// Renoir, Cezanne.
    Dcn21,
    /// Rembrandt.
    Dcn31,
}

impl DcnVersion {
    /// The display core of a known AMD display device.
    pub fn for_device(device: u16) -> Option<DcnVersion> {
        match device {
            0x15DD | 0x15D8 => Some(DcnVersion::Dcn1),
            0x1636 | 0x1638 => Some(DcnVersion::Dcn21),
            0x1681 => Some(DcnVersion::Dcn31),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            DcnVersion::Dcn1 => "DCN 1.0",
            DcnVersion::Dcn21 => "DCN 2.1",
            DcnVersion::Dcn31 => "DCN 3.1",
        }
    }
}

/// True for an AMD PCI function that drives a display.
pub fn is_amd_display(vendor: u16, class: u8) -> bool {
    vendor == AMD_VENDOR && class == DISPLAY_CLASS
}

/// Finds the ATOM ROM header in a VBIOS image read from the expansion ROM
/// BAR.
///
/// The image must start with the legacy ROM signature. The ATOM header is
/// located by its text because its offset depends on the VBIOS version; the
/// search is limited to the first eight KiB, where every known VBIOS places
/// it. This is identification only: nothing from the header is interpreted
/// yet.
pub fn atom_header_offset(image: &[u8]) -> Option<usize> {
    if image.len() < 16 || image[..2] != ROM_SIGNATURE {
        return None;
    }
    let limit = image.len().min(8192);
    image[..limit].windows(ATOM_SIGNATURE.len()).position(|w| w == ATOM_SIGNATURE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_devices_and_known_generations() {
        assert!(is_amd_display(AMD_VENDOR, DISPLAY_CLASS));
        assert!(!is_amd_display(AMD_VENDOR, 0x0C)); // audio function
        assert!(!is_amd_display(0x8086, DISPLAY_CLASS));
        assert_eq!(DcnVersion::for_device(0x15D8), Some(DcnVersion::Dcn1));
        assert_eq!(DcnVersion::for_device(0x15DD), Some(DcnVersion::Dcn1));
        assert_eq!(DcnVersion::for_device(0x1636), Some(DcnVersion::Dcn21));
        assert_eq!(DcnVersion::for_device(0x1681), Some(DcnVersion::Dcn31));
        assert_eq!(DcnVersion::for_device(0x1234), None);
        assert_eq!(DcnVersion::Dcn1.name(), "DCN 1.0");
        assert_eq!(DcnVersion::Dcn21.name(), "DCN 2.1");
        assert_eq!(DcnVersion::Dcn31.name(), "DCN 3.1");
    }

    #[test]
    fn atom_header_requires_a_legacy_rom() {
        let mut rom = [0u8; 256];
        rom[..2].copy_from_slice(&ROM_SIGNATURE);
        rom[0x30..0x34].copy_from_slice(&ATOM_SIGNATURE);
        assert_eq!(atom_header_offset(&rom), Some(0x30));

        rom[0] = 0;
        assert_eq!(atom_header_offset(&rom), None);

        let no_atom = [0x55, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(atom_header_offset(&no_atom), None);
        assert_eq!(atom_header_offset(&[]), None);

        // An ATOM header beyond the search window is not found.
        let mut far = [0u8; 16 * 1024];
        far[..2].copy_from_slice(&ROM_SIGNATURE);
        far[8192..8196].copy_from_slice(&ATOM_SIGNATURE);
        assert_eq!(atom_header_offset(&far), None);
    }
}
