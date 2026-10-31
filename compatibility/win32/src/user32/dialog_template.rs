//! Bounded parsing of standard and extended Windows dialog resources.
use alloc::{string::String, vec::Vec};

pub(super) struct Control {
    pub style: u32, pub ex: u32, pub x: i16, pub y: i16, pub w: i16, pub h: i16,
    pub id: u32, pub class: String, pub title: String, pub data: Vec<u8>,
}
pub(super) struct Dialog {
    pub style: u32, pub ex: u32, pub x: i16, pub y: i16, pub w: i16, pub h: i16,
    pub title: String, pub controls: Vec<Control>,
}

enum Field { None, Ordinal(u16), Text(String) }
struct Reader<'a> { bytes: &'a [u8], at: usize }
impl Reader<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8], u32> {
        let end = self.at.checked_add(count).ok_or(13u32)?;
        let bytes = self.bytes.get(self.at..end).ok_or(13u32)?;
        self.at = end;
        Ok(bytes)
    }
    fn u16(&mut self) -> Result<u16, u32> { let b = self.take(2)?; Ok(u16::from_le_bytes([b[0], b[1]])) }
    fn i16(&mut self) -> Result<i16, u32> { Ok(self.u16()? as i16) }
    fn u32(&mut self) -> Result<u32, u32> { let b = self.take(4)?; Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]])) }
    fn align4(&mut self) -> Result<(), u32> { let n = (4 - self.at % 4) % 4; self.take(n)?; Ok(()) }
    fn field(&mut self) -> Result<Field, u32> {
        let first = self.u16()?;
        if first == 0 { return Ok(Field::None); }
        if first == 0xffff { return Ok(Field::Ordinal(self.u16()?)); }
        let mut chars = alloc::vec![first];
        loop {
            let c = self.u16()?;
            if c == 0 { break; }
            if chars.len() >= 4096 { return Err(206); }
            chars.push(c);
        }
        String::from_utf16(&chars).map(Field::Text).map_err(|_| 13)
    }
}

fn text(field: Field) -> Result<String, u32> {
    match field { Field::None => Ok(String::new()), Field::Text(s) => Ok(s), Field::Ordinal(_) => Err(50) }
}
fn class(field: Field) -> Result<String, u32> {
    match field {
        Field::Text(s) => Ok(s),
        Field::Ordinal(id) => match id {
            0x80 => Ok(String::from("BUTTON")), 0x81 => Ok(String::from("EDIT")),
            0x82 => Ok(String::from("STATIC")), 0x83 => Ok(String::from("LISTBOX")),
            0x84 => Ok(String::from("SCROLLBAR")), 0x85 => Ok(String::from("COMBOBOX")),
            _ => Err(50),
        },
        Field::None => Err(13),
    }
}

pub(super) fn parse(bytes: &[u8]) -> Result<Dialog, u32> {
    let mut r = Reader { bytes, at: 0 };
    let extended = bytes.get(..4) == Some(&[1, 0, 0xff, 0xff]);
    let (style, ex, count) = if extended {
        r.take(4)?; r.u32()?; let ex = r.u32()?; let style = r.u32()?; (style, ex, r.u16()?)
    } else { let style = r.u32()?; let ex = r.u32()?; (style, ex, r.u16()?) };
    if count > 4096 { return Err(13); }
    let (x, y, w, h) = (r.i16()?, r.i16()?, r.i16()?, r.i16()?);
    if !matches!(r.field()?, Field::None) { return Err(50); } // dialog menus
    match r.field()? { Field::None => {}, _ => return Err(50) } // custom dialog classes
    let title = text(r.field()?)?;
    if style & 0x40 != 0 { // DS_SETFONT
        r.u16()?;
        if extended { r.u16()?; r.take(2)?; }
        text(r.field()?)?;
    }
    let mut controls = Vec::new();
    for _ in 0..count {
        r.align4()?;
        let (style, ex) = if extended { r.u32()?; let ex = r.u32()?; (r.u32()?, ex) } else { (r.u32()?, r.u32()?) };
        let (x, y, w, h) = (r.i16()?, r.i16()?, r.i16()?, r.i16()?);
        let id = if extended { r.u32()? } else { r.u16()? as u32 };
        let class = class(r.field()?)?;
        let title = text(r.field()?)?;
        let len = r.u16()? as usize;
        let data = if len == 0 { Vec::new() } else {
            if !extended && len < 2 { return Err(13); }
            r.take(if extended { len } else { len - 2 })?.to_vec()
        };
        controls.push(Control { style, ex, x, y, w, h, id, class, title, data });
    }
    Ok(Dialog { style, ex, x, y, w, h, title, controls })
}
