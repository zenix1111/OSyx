//! Exercises the Windows DirectWrite parser and rasterizer on a real CFF font.
extern crate alloc;

#[path = "../../../compatibility/win32/src/dwrite/ttf.rs"]
mod ttf;
#[path = "../../../compatibility/win32/src/dwrite/raster.rs"]
mod raster;

use alloc::sync::Arc;

#[test]
fn cff_custom_font_rasterizes_visible_glyphs() {
    let bytes = include_bytes!("fixtures/SourceSans3-Regular.otf");
    let face = ttf::Face::parse(Arc::new(bytes.to_vec()), 0).expect("parse CFF OpenType");
    assert!(!face.has_glyf());
    assert!(face.has_outlines());
    for character in ['A', 'g', 'ż'] {
        let glyph = face.glyph_index(character as u32);
        assert_ne!(glyph, 0, "missing {character}");
        assert!(face.glyph_box(glyph).is_some());
        let outline = face.outline(glyph);
        assert!(!outline.is_empty(), "no outline for {character}");
        let scale = 20 * 256 * 65536 / i64::from(face.units_per_em);
        let transform = raster::Xform { a: scale, b: 0, c: 0, d: -scale, dx: 0, dy: 20 * 256 };
        let lines = raster::flatten(&outline, &transform);
        let bounds = raster::bounds(&lines).expect("visible bounds");
        assert!(raster::coverage(&lines, bounds).iter().any(|&pixel| pixel != 0), "blank {character}");
    }
}

#[test]
fn malformed_font_is_rejected() {
    assert!(osyx_font::outline(b"not a font", 0, 1).is_none());
}

#[test]
fn cff2_default_instance_rasterizes_visible_glyph() {
    let bytes = include_bytes!("fixtures/SourceSansVariable-Roman.otf");
    let face = ttf::Face::parse(Arc::new(bytes.to_vec()), 0).expect("parse CFF2 OpenType");
    assert!(face.table(b"CFF2").is_some());
    assert!(face.has_outlines());
    let glyph = face.glyph_index('A' as u32);
    assert_ne!(glyph, 0);
    let scale = 20 * 256 * 65536 / i64::from(face.units_per_em);
    let transform = raster::Xform { a: scale, b: 0, c: 0, d: -scale, dx: 0, dy: 20 * 256 };
    let lines = raster::flatten(&face.outline(glyph), &transform);
    let bounds = raster::bounds(&lines).expect("visible bounds");
    assert!(raster::coverage(&lines, bounds).iter().any(|&pixel| pixel != 0));
}
