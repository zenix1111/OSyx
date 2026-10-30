//! Font outline decoding shared by OSyx text renderers.
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

/// One quadratic outline point, in font units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
    pub on: bool,
}

#[derive(Default)]
struct Builder {
    contours: Vec<Vec<Point>>,
    current: Vec<Point>,
}

impl Builder {
    fn point(x: f32, y: f32, on: bool) -> Point {
        // Bound malformed outlines before the rasterizer transforms them.
        Point { x: (x as i32).clamp(-65535, 65535), y: (y as i32).clamp(-65535, 65535), on }
    }

    fn finish(&mut self) {
        if !self.current.is_empty() {
            self.contours.push(core::mem::take(&mut self.current));
        }
    }
}

impl ttf_parser::OutlineBuilder for Builder {
    fn move_to(&mut self, x: f32, y: f32) {
        self.finish();
        self.current.push(Self::point(x, y, true));
    }

    fn line_to(&mut self, x: f32, y: f32) {
        self.current.push(Self::point(x, y, true));
    }

    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        self.current.push(Self::point(x1, y1, false));
        self.current.push(Self::point(x, y, true));
    }

    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        let Some(start) = self.current.last().copied() else { return };
        let a = Self::point(x1, y1, true);
        let b = Self::point(x2, y2, true);
        let end = Self::point(x, y, true);
        // Flatten cubic CFF curves to sixteen line segments. Existing OSyx
        // renderers consume quadratic outlines and can draw on-curve points.
        const N: i64 = 16;
        for t in 1..=N {
            let u = N - t;
            let calc = |p: i32, q: i32, r: i32, s: i32| {
                ((u*u*u*p as i64 + 3*u*u*t*q as i64 + 3*u*t*t*r as i64 + t*t*t*s as i64) / (N*N*N)) as i32
            };
            self.current.push(Point { x: calc(start.x, a.x, b.x, end.x), y: calc(start.y, a.y, b.y, end.y), on: true });
        }
    }

    fn close(&mut self) {
        self.finish();
    }
}

/// Decode a glyph's contours from a TrueType or CFF-based OpenType face.
pub fn outline(data: &[u8], face_index: u32, glyph: u16) -> Option<Vec<Vec<Point>>> {
    let face = ttf_parser::Face::parse(data, face_index).ok()?;
    let mut builder = Builder::default();
    face.outline_glyph(ttf_parser::GlyphId(glyph), &mut builder)?;
    builder.finish();
    Some(builder.contours)
}

/// Bounding box of an outlined glyph, in font units.
pub fn glyph_box(data: &[u8], face_index: u32, glyph: u16) -> Option<(i16, i16, i16, i16)> {
    let face = ttf_parser::Face::parse(data, face_index).ok()?;
    let b = face.glyph_bounding_box(ttf_parser::GlyphId(glyph))?;
    Some((b.x_min, b.y_min, b.x_max, b.y_max))
}
