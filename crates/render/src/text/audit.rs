//! Content a human does not see but a text extractor does: the raw material of prompt-injection
//! audits. A page device that records every glyph a text extractor would read, with what makes
//! it invisible (or nearly) to a reader: render modes 3/7 (`GlyphDrawMode::Invisible`), glyphs
//! wholly off the displayed page, and the solid fill colour a near-invisible paint would use.
//! ISO 32000-2 §9.3.3 defines the render modes; what counts as "invisible" is our
//! classification, not the format's.
//!
//! Unlike text extraction ([`super::device`]) nothing is dropped: invisible and off-page glyphs
//! are the point. Only hostile volume is capped, and visibly: past the cap glyphs are counted
//! in [`PageAudit::dropped`] instead of recorded.

use super::{
    Affine, BezPath, BlendMode, ClipPath, Context, Device, Glyph, GlyphDrawMode, Image, InterpreterCache, InterpreterSettings, Paint, PathDrawMode,
    Pdf, Rect, Shape, SoftMask, TransformExt, interpret_page,
};

/// Most glyphs audited on one page.
const MAX_GLYPHS: usize = 100_000;

/// One glyph a text extractor reads, with what makes it invisible (or nearly) to a reader.
#[derive(Clone, Debug, PartialEq)]
pub struct GlyphAudit {
    /// The glyph's Unicode text (one character, or several for a ligature).
    pub text: String,
    /// Em-box bounding rect in page view space (points, origin top-left, y down): [x0, y0, x1, y1].
    pub rect: [f32; 4],
    /// Painted by no render mode: `Tr 3`/`Tr 7` (invisible), or a clip-shaping glyph.
    pub unpainted: bool,
    /// Wholly outside the displayed page (the crop box after rotation).
    pub off_page: bool,
    /// Solid fill colour, RGBA 0–255; `None` for patterns and strokes.
    pub fill: Option<[u8; 4]>,
}

/// The audit of one page: every glyph an extractor reads, in content order.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PageAudit {
    pub glyphs: Vec<GlyphAudit>,
    /// Glyphs past [`MAX_GLYPHS`]: counted, not recorded.
    pub dropped: usize,
}

struct AuditDevice {
    page: Rect,
    glyphs: Vec<GlyphAudit>,
    dropped: usize,
}

impl<'a> Device<'a> for AuditDevice {
    fn set_soft_mask(&mut self, _: Option<SoftMask<'a>>) {}
    fn set_blend_mode(&mut self, _: BlendMode) {}
    fn draw_path(&mut self, _: &BezPath, _: Affine, _: &Paint<'a>, _: &PathDrawMode) {}
    fn push_clip_path(&mut self, _: &ClipPath) {}
    fn push_transparency_group(&mut self, _: f32, _: Option<SoftMask<'a>>, _: BlendMode) {}
    fn pop_clip_path(&mut self) {}
    fn pop_transparency_group(&mut self) {}
    fn begin_marked_content(&mut self, _: &[u8], _: Option<i32>) {}
    fn actual_text(&mut self, _: &[u8]) {}
    fn end_marked_content(&mut self) {}

    fn draw_glyph(&mut self, glyph: &Glyph<'a>, transform: Affine, glyph_transform: Affine, paint: &Paint<'a>, mode: &GlyphDrawMode) {
        if self.glyphs.len() >= MAX_GLYPHS {
            self.dropped += 1;
            return;
        }
        let text = match glyph.as_unicode() {
            Some(hayro::hayro_interpret::hayro_cmap::BfString::Char(c)) => c.to_string(),
            Some(hayro::hayro_interpret::hayro_cmap::BfString::String(s)) => s,
            None => return,
        };
        if text.chars().all(char::is_control) {
            return;
        }
        let fill = match paint {
            Paint::Color(c) => Some(c.to_rgba().to_rgba8()),
            Paint::Pattern(_) => None,
        };
        // Clip-shaping glyphs paint no text of their own (pdfcraft patch note on
        // `GlyphDrawMode::Clip`): an extractor reads them, a reader sees at most their clip.
        let unpainted = !matches!(mode, GlyphDrawMode::Fill | GlyphDrawMode::Stroke(_));
        // Glyph space → view space, as text extraction reads it: 1000 units per em, the em box
        // spanning descender (−200) to ascender (800). Vertical fonts advance along −y and keep
        // the outline upright; the em-box bounding rect is the same either way.
        let t = transform * glyph_transform;
        let advance = match glyph {
            Glyph::Outline(g) => {
                g.advance_width().filter(|a| *a > 0.0).map(f64::from).unwrap_or_else(|| g.outline().bounding_box().width().max(500.0))
            }
            Glyph::Type3(g) => g.advance_width().filter(|a| a.is_finite() && *a > 0.0).map(f64::from).unwrap_or(600.0),
        };
        let em = Rect::new(0.0, -200.0, advance, 800.0);
        let corners = [(em.x0, em.y0), (em.x1, em.y0), (em.x1, em.y1), (em.x0, em.y1)].map(|(x, y)| t * kurbo::Point::new(x, y));
        let b = corners.iter().fold(Rect::new(f64::INFINITY, f64::INFINITY, f64::NEG_INFINITY, f64::NEG_INFINITY), |b, p| {
            Rect::new(b.x0.min(p.x), b.y0.min(p.y), b.x1.max(p.x), b.y1.max(p.y))
        });
        if !(b.x0.is_finite() && b.y0.is_finite() && b.x1.is_finite() && b.y1.is_finite()) || b.width() > 10_000.0 || b.height() > 10_000.0 {
            // A hostile or broken transform: the text still goes to extractors, so record it
            // without a box, flagged off-page.
            self.glyphs.push(GlyphAudit { text, rect: [0.0; 4], unpainted, off_page: true, fill });
            return;
        }
        let off_page = b.x0.max(self.page.x0) >= b.x1.min(self.page.x1) || b.y0.max(self.page.y0) >= b.y1.min(self.page.y1);
        self.glyphs.push(GlyphAudit { text, rect: [b.x0 as f32, b.y0 as f32, b.x1 as f32, b.y1 as f32], unpainted, off_page, fill });
    }

    fn draw_image(&mut self, _: Image<'a, '_>, _: Affine) {}
}

/// Audit one page: every glyph an extractor reads, with what makes it invisible to a reader.
/// Panics inside the interpreter are the caller's to catch (`crate::guard`).
pub fn audit_page(pdf: &Pdf, page: usize, settings: &InterpreterSettings) -> Result<PageAudit, String> {
    let pages = pdf.pages();
    let p = pages.get(page).ok_or("the page could not be read")?;
    let (w, h) = p.render_dimensions();
    let cache = InterpreterCache::new();
    let settings = settings.clone();
    let initial = p.initial_transform(true).to_kurbo();
    let c = p.intersected_crop_box();
    let mut ctx = Context::new(initial, Rect::new(0.0, 0.0, f64::from(w), f64::from(h)), &cache, p.xref(), settings);
    let mut dev = AuditDevice { page: initial.transform_rect_bbox(Rect::new(c.x0, c.y0, c.x1, c.y1)), glyphs: Vec::new(), dropped: 0 };
    interpret_page(p, &mut ctx, &mut dev);
    Ok(PageAudit { glyphs: dev.glyphs, dropped: dev.dropped })
}

#[cfg(test)]
mod tests {
    use super::super::tests::marked_pages;

    use super::*;

    fn audit(content: &str) -> PageAudit {
        audit_page(&marked_pages(&[content]), 0, &InterpreterSettings::default()).unwrap()
    }

    #[test]
    fn visible_text_is_not_flagged() {
        let audit = audit("BT /F1 20 Tf 1 0 0 1 100 150 Tm (Hello) Tj ET");
        assert_eq!(audit.glyphs.len(), 5);
        assert!(audit.glyphs.iter().all(|g| !g.unpainted && !g.off_page), "{:?}", audit.glyphs);
        assert!(audit.glyphs.iter().all(|g| g.fill.is_some_and(|[r, g, b, _]| r == 0 && g == 0 && b == 0)), "{:?}", audit.glyphs);
    }

    #[test]
    fn render_mode_3_text_is_unpainted() {
        let audit = audit("BT /F1 20 Tf 1 0 0 1 100 150 Tm (See) Tj 3 Tr 1 0 0 1 100 100 Tm (Hide) Tj ET");
        assert_eq!(audit.glyphs.len(), 7);
        assert_eq!(audit.glyphs.iter().filter(|g| g.unpainted).count(), 4, "{:?}", audit.glyphs);
        assert_eq!(audit.dropped, 0);
    }

    #[test]
    fn off_page_text_is_flagged_but_recorded() {
        let audit = audit("BT /F1 20 Tf 1 0 0 1 100 150 Tm (On) Tj 1 0 0 1 500 150 Tm (Off) Tj ET");
        assert_eq!(audit.glyphs.len(), 5);
        assert_eq!(audit.glyphs.iter().filter(|g| g.off_page).count(), 3, "{:?}", audit.glyphs);
    }

    #[test]
    fn white_fill_is_recorded_as_white() {
        let audit = audit("BT /F1 20 Tf 1 1 1 rg 1 0 0 1 100 150 Tm (Ghost) Tj ET");
        assert_eq!(audit.glyphs.len(), 5);
        assert!(audit.glyphs.iter().all(|g| g.fill.is_some_and(|[r, g, b, _]| r == 255 && g == 255 && b == 255)), "{:?}", audit.glyphs);
    }
}
