//! Unlink unused Type 3 font glyph programs and prune exclusive graphical resources (F-011).

use std::collections::{HashMap, HashSet};

use pdfcraft_content::Pieces;
use pdfcraft_cos::{CosError, Dict, Document, ObjRef, Object};

use crate::{RedactError, page_streams};

const MAX_DEPTH: usize = 64;
const MAX_HOLDERS: usize = 1_000_000;

fn res_dict(doc: &Document, res: &Dict, key: &[u8]) -> Dict {
    res.get(key).and_then(|o| doc.resolve(o).as_dict().cloned()).unwrap_or_default()
}

/// Identifies a font in the document.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum FontKey {
    Ref(ObjRef),
    Inline(ObjRef, usize),
}

/// Build the mapping from character code (0..=255) to glyph name in a Type 3 font.
/// Fails closed if the encoding cannot be safely resolved or parsed.
pub(crate) fn type3_code_to_glyph(doc: &Document, font_dict: &Dict) -> Result<[Option<Vec<u8>>; 256], CosError> {
    let Some(enc_obj) = font_dict.get(b"Encoding") else {
        return Err(CosError::Syntax { offset: 0, detail: "redaction could not establish safe Type 3 font cleanup: missing Encoding".into() });
    };
    let resolved_enc = doc.resolve(enc_obj);

    let mut differences = HashMap::new();
    let base_name: Option<Vec<u8>>;

    match &*resolved_enc {
        Object::Dict(enc_dict) => {
            if let Some(diffs) = enc_dict.get(b"Differences").and_then(|d| doc.resolve(d).as_array().cloned()) {
                let mut cur_code = 0i64;
                for item in &diffs {
                    match &*doc.resolve(item) {
                        Object::Int(n) => cur_code = *n,
                        Object::Name(name) => {
                            if let Ok(c) = u8::try_from(cur_code) {
                                differences.insert(c, name.clone());
                            }
                            cur_code = cur_code.saturating_add(1);
                        }
                        _ => {}
                    }
                }
            }
            if let Some(base) = enc_dict.name(b"BaseEncoding") {
                base_name = Some(base.to_vec());
            } else {
                // ISO 32000 §9.6.6.1: default base encoding for Type 3 fonts is StandardEncoding.
                base_name = Some(b"StandardEncoding".to_vec());
            }
        }
        Object::Name(name) => {
            base_name = Some(name.clone());
        }
        _ => {
            return Err(CosError::Syntax {
                offset: 0,
                detail: "redaction could not establish safe Type 3 font cleanup: invalid Encoding object".into(),
            });
        }
    }

    let base_table: Option<&'static [Option<&'static [u8]>; 256]> = match base_name.as_deref() {
        Some(b"StandardEncoding") => Some(&crate::type3_tables::STANDARD),
        Some(b"WinAnsiEncoding") => Some(&crate::type3_tables::WIN_ANSI),
        Some(b"MacRomanEncoding") => Some(&crate::type3_tables::MAC_ROMAN),
        Some(b"MacExpertEncoding") => Some(&crate::type3_tables::MAC_EXPERT),
        Some(other) => {
            return Err(CosError::Syntax {
                offset: 0,
                detail: format!(
                    "redaction could not establish safe Type 3 font cleanup: unsupported BaseEncoding: {}",
                    String::from_utf8_lossy(other)
                ),
            });
        }
        None => None,
    };

    let mut map: [Option<Vec<u8>>; 256] = std::array::from_fn(|_| None);
    for (code, entry) in map.iter_mut().enumerate() {
        let c = code as u8;
        if let Some(diff_glyph) = differences.get(&c) {
            *entry = Some(diff_glyph.clone());
        } else if let Some(table) = base_table
            && let Some(base_glyph) = table[code]
        {
            *entry = Some(base_glyph.to_vec());
        }
    }

    Ok(map)
}

fn resolve_font_in_res(doc: &Document, holder_ref: ObjRef, res: &Dict, font_name: &[u8]) -> Option<(FontKey, Dict)> {
    let fonts = res_dict(doc, res, b"Font");
    let (idx, (_, font_obj)) = fonts.iter().enumerate().find(|(_, (k, _))| k.as_slice() == font_name)?;
    let font_ref = font_obj.as_ref();
    let resolved = doc.resolve(font_obj);
    let dict = resolved.as_dict()?.clone();
    if dict.name(b"Subtype") == Some(b"Type3") {
        let key = match font_ref {
            Some(r) => FontKey::Ref(r),
            None => FontKey::Inline(holder_ref, idx),
        };
        Some((key, dict))
    } else {
        None
    }
}

fn resolve_extgstate_font(doc: &Document, holder_ref: ObjRef, res: &Dict, gs_name: &[u8]) -> Option<(FontKey, Dict)> {
    let extg = res_dict(doc, res, b"ExtGState");
    let state_obj = extg.get(gs_name)?;
    let state = doc.resolve(state_obj).as_dict().cloned()?;
    let font_entry = state.get(b"Font").and_then(|f| doc.resolve(f).as_array().cloned())?;
    let font_obj = font_entry.first()?;
    let font_ref = font_obj.as_ref();
    let resolved = doc.resolve(font_obj);
    let dict = resolved.as_dict()?.clone();
    if dict.name(b"Subtype") == Some(b"Type3") {
        let key = match font_ref {
            Some(r) => FontKey::Ref(r),
            None => FontKey::Inline(holder_ref, 0),
        };
        Some((key, dict))
    } else {
        None
    }
}

#[derive(Default)]
struct UsedInGlyphs {
    xobjects: HashSet<Vec<u8>>,
    colorspaces: HashSet<Vec<u8>>,
    patterns: HashSet<Vec<u8>>,
    shadings: HashSet<Vec<u8>>,
    extgstates: HashSet<Vec<u8>>,
    fonts: HashSet<Vec<u8>>,
    properties: HashSet<Vec<u8>>,
}

fn collect_used_resources_in_stream(data: &[u8], used: &mut UsedInGlyphs) -> Result<(), CosError> {
    let parsed = pdfcraft_content::parse(data);
    if parsed.skipped > 0 {
        return Err(CosError::Syntax { offset: 0, detail: "redaction could not fully inspect glyph stream syntax".into() });
    }
    for op in parsed.ops {
        match op.op.as_slice() {
            b"Do" => {
                if let Some(n) = op.last_name() {
                    used.xobjects.insert(n.to_vec());
                }
            }
            b"cs" | b"CS" => {
                if let Some(n) = op.name(0) {
                    used.colorspaces.insert(n.to_vec());
                }
            }
            b"scn" | b"SCN" => {
                if let Some(n) = op.last_name() {
                    used.patterns.insert(n.to_vec());
                }
            }
            b"sh" => {
                if let Some(n) = op.last_name() {
                    used.shadings.insert(n.to_vec());
                }
            }
            b"gs" => {
                if let Some(n) = op.name(0) {
                    used.extgstates.insert(n.to_vec());
                }
            }
            b"Tf" => {
                if let Some(n) = op.name(0) {
                    used.fonts.insert(n.to_vec());
                }
            }
            b"BDC" | b"DP" => {
                if let Some(n) = op.name(1) {
                    used.properties.insert(n.to_vec());
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn prune_type3_font_resources(doc: &Document, font_res: &mut Dict, used: &UsedInGlyphs) -> bool {
    let mut changed = false;

    macro_rules! prune_category {
        ($cat:expr, $used_set:expr) => {
            if let Some(sub_obj) = font_res.get($cat) {
                let mut sub = doc.resolve(sub_obj).as_dict().cloned().unwrap_or_default();
                let names: Vec<Vec<u8>> = sub.iter().map(|(n, _)| n.to_vec()).collect();
                let mut cat_changed = false;
                for n in names {
                    if !$used_set.contains(&n) {
                        sub.remove(&n);
                        cat_changed = true;
                    }
                }
                if cat_changed {
                    changed = true;
                    if sub.is_empty() {
                        font_res.remove($cat);
                    } else {
                        font_res.set($cat.to_vec(), Object::Dict(sub));
                    }
                }
            }
        };
    }

    prune_category!(b"XObject", used.xobjects);
    prune_category!(b"ColorSpace", used.colorspaces);
    prune_category!(b"Pattern", used.patterns);
    prune_category!(b"Shading", used.shadings);
    prune_category!(b"ExtGState", used.extgstates);
    prune_category!(b"Font", used.fonts);
    prune_category!(b"Properties", used.properties);

    changed
}

struct ScanContext<'a> {
    doc: &'a Document,
    font_maps: &'a HashMap<FontKey, [Option<Vec<u8>>; 256]>,
    used_glyphs: &'a mut HashMap<FontKey, HashSet<Vec<u8>>>,
    seen_forms: &'a mut HashSet<ObjRef>,
}

fn scan_content_stream(
    ctx: &mut ScanContext<'_>,
    content: &[Vec<u8>],
    holder_ref: ObjRef,
    res: &Dict,
    initial_font: Option<FontKey>,
    depth: usize,
) -> Result<(), CosError> {
    if depth > MAX_DEPTH {
        return Err(CosError::Syntax { offset: 0, detail: "redaction exceeded max depth inspecting Type 3 font content".into() });
    }
    let joined = Pieces::join(content);
    let parsed = joined.parse();
    if parsed.skipped > 0 {
        return Err(CosError::Syntax { offset: 0, detail: "redaction could not fully inspect content stream syntax".into() });
    }

    let mut stack: Vec<Option<FontKey>> = Vec::new();
    let mut current_font = initial_font;

    for op in parsed.ops {
        match op.op.as_slice() {
            b"q" => stack.push(current_font),
            b"Q" => current_font = stack.pop().unwrap_or(None),
            b"Tf" => {
                if let Some(name) = op.name(0) {
                    current_font = resolve_font_in_res(ctx.doc, holder_ref, res, name).map(|(k, _)| k);
                }
            }
            b"gs" => {
                if let Some(name) = op.name(0)
                    && let Some((k, _)) = resolve_extgstate_font(ctx.doc, holder_ref, res, name)
                {
                    current_font = Some(k);
                }
            }
            b"Tj" | b"'" => {
                if let Some(fk) = current_font
                    && let Some(map) = ctx.font_maps.get(&fk)
                    && let Some(s) = op.operands.last().and_then(Object::as_string)
                {
                    for b in &s.bytes {
                        if let Some(g) = &map[*b as usize] {
                            ctx.used_glyphs.entry(fk).or_default().insert(g.clone());
                        }
                    }
                }
            }
            b"TJ" => {
                if let Some(fk) = current_font
                    && let Some(map) = ctx.font_maps.get(&fk)
                    && let Some(arr) = op.operands.last().and_then(Object::as_array)
                {
                    for item in arr {
                        if let Some(s) = item.as_string() {
                            for b in &s.bytes {
                                if let Some(g) = &map[*b as usize] {
                                    ctx.used_glyphs.entry(fk).or_default().insert(g.clone());
                                }
                            }
                        }
                    }
                }
            }
            b"\"" => {
                if let Some(fk) = current_font
                    && let Some(map) = ctx.font_maps.get(&fk)
                    && let Some(s) = op.operands.last().and_then(Object::as_string)
                {
                    for b in &s.bytes {
                        if let Some(g) = &map[*b as usize] {
                            ctx.used_glyphs.entry(fk).or_default().insert(g.clone());
                        }
                    }
                }
            }
            b"Do" => {
                if let Some(name) = op.last_name() {
                    let xo = res_dict(ctx.doc, res, b"XObject");
                    if let Some(r) = xo.get(name).and_then(Object::as_ref)
                        && ctx.seen_forms.insert(r)
                    {
                        let obj = ctx.doc.get(r);
                        if let Object::Stream(s) = &*obj
                            && s.dict.name(b"Subtype") == Some(b"Form")
                        {
                            let data = s.decoded()?;
                            let form_own_res = s.dict.get(b"Resources").and_then(|ro| ctx.doc.resolve(ro).as_dict().cloned());
                            if let Some(form_res) = form_own_res {
                                scan_content_stream(ctx, std::slice::from_ref(&data), r, &form_res, current_font, depth + 1)?;
                            } else {
                                scan_content_stream(ctx, std::slice::from_ref(&data), holder_ref, res, current_font, depth + 1)?;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Prune Type 3 fonts from a rewritten page or form's `/Resources` dictionary if the rewritten
/// content no longer draws any text using that font name.
pub(crate) fn prune_type3_from_resources(doc: &Document, res: &mut Dict, content: &[Vec<u8>]) -> Result<(), CosError> {
    let mut fonts = res_dict(doc, res, b"Font");
    if fonts.is_empty() {
        return Ok(());
    }

    let joined = Pieces::join(content);
    let parsed = joined.parse();
    if parsed.skipped > 0 {
        return Err(CosError::Syntax { offset: 0, detail: "redaction could not fully inspect content stream syntax".into() });
    }

    let mut drawn_font_names = HashSet::new();
    for op in &parsed.ops {
        if op.is("Tf") {
            if let Some(name) = op.name(0) {
                drawn_font_names.insert(name.to_vec());
            }
        } else if op.is("gs")
            && let Some(name) = op.name(0)
        {
            let extg = res_dict(doc, res, b"ExtGState");
            if let Some(state_obj) = extg.get(name)
                && let Some(state) = doc.resolve(state_obj).as_dict()
                && let Some(font_entry) = doc.resolve(state.get(b"Font").unwrap_or(&Object::Null)).as_array()
                && let Some(font_obj) = font_entry.first()
            {
                for (fn_name, fn_obj) in fonts.iter() {
                    if fn_obj == font_obj || (fn_obj.as_ref().is_some() && fn_obj.as_ref() == font_obj.as_ref()) {
                        drawn_font_names.insert(fn_name.to_vec());
                    }
                }
            }
        }
    }

    let mut changed = false;
    let font_names: Vec<Vec<u8>> = fonts.iter().map(|(n, _)| n.to_vec()).collect();
    for name in font_names {
        if let Some(font_obj) = fonts.get(&name) {
            let resolved = doc.resolve(font_obj);
            if let Some(d) = resolved.as_dict()
                && d.name(b"Subtype") == Some(b"Type3")
                && !drawn_font_names.contains(&name)
            {
                fonts.remove(&name);
                changed = true;
            }
        }
    }

    if changed {
        if fonts.is_empty() {
            res.remove(b"Font");
        } else {
            res.set(b"Font".to_vec(), Object::Dict(fonts));
        }
    }

    Ok(())
}

/// Unlink unused Type 3 glyph programs from `CharProcs`, prune their exclusive resources from the
/// font's `/Resources`, and remove completely unused Type 3 fonts across all reachable resource
/// holders in the document. Fails closed if safe cleanup cannot be established.
pub(crate) fn unlink_type3(doc: &mut Document) -> Result<(), RedactError> {
    let Some(top) = doc.root().and_then(|root| doc.get(root).as_dict().and_then(|d| d.reference(b"Pages"))) else {
        return Ok(());
    };

    // Find all page-tree nodes with /Resources of their own, and the pages that draw through them.
    let mut holders: Vec<(ObjRef, Vec<ObjRef>)> = Vec::new();
    let mut seen = HashSet::new();
    let mut stack: Vec<(ObjRef, Option<usize>)> = vec![(top, None)];
    while let Some((node, mut holder)) = stack.pop() {
        if !seen.insert(node) || seen.len() > MAX_HOLDERS {
            continue;
        }
        let obj = doc.get(node);
        let Some(d) = obj.as_dict() else { continue };
        if d.contains(b"Resources") {
            holders.push((node, Vec::new()));
            holder = Some(holders.len() - 1);
        }
        let is_pages = d.name(b"Type") == Some(b"Pages") || (d.contains(b"Kids") && d.name(b"Type") != Some(b"Page"));
        if is_pages {
            let kids = d.get(b"Kids").map(|k| doc.resolve(k)).and_then(|k| k.as_array().cloned()).unwrap_or_default();
            stack.extend(kids.iter().filter_map(Object::as_ref).map(|k| (k, holder)));
        } else if let Some(h) = holder.and_then(|i| holders.get_mut(i)) {
            h.1.push(node);
        }
    }

    // Find all reachable Form XObjects with resources of their own.
    let mut form_holders: Vec<(ObjRef, Dict)> = Vec::new();
    let mut pending_res: Vec<Dict> = holders
        .iter()
        .filter_map(|(r, _)| doc.get(*r).as_dict().and_then(|d| d.get(b"Resources")).and_then(|ro| doc.resolve(ro).as_dict().cloned()))
        .collect();
    let mut seen_forms = HashSet::new();
    while let Some(res) = pending_res.pop() {
        for (_, value) in res_dict(doc, &res, b"XObject").iter() {
            let Some(reference) = value.as_ref() else { continue };
            if !seen_forms.insert(reference) {
                continue;
            }
            if seen_forms.len() > MAX_HOLDERS {
                return Err(CosError::Syntax { offset: 0, detail: "redaction exceeded max depth inspecting form resources".into() }.into());
            }
            let object = doc.get(reference);
            let Object::Stream(form) = &*object else { continue };
            if form.dict.name(b"Subtype") != Some(b"Form") {
                continue;
            }
            if let Some(r) = form.dict.get(b"Resources").and_then(|ro| doc.resolve(ro).as_dict().cloned()) {
                form_holders.push((reference, r.clone()));
                pending_res.push(r);
            }
        }
    }

    // Discover all Type 3 fonts in holders and forms.
    let mut type3_fonts: HashMap<FontKey, Dict> = HashMap::new();
    let check_res_fonts = |doc: &Document, holder_ref: ObjRef, res: &Dict, t3_fonts: &mut HashMap<FontKey, Dict>| {
        let fonts = res_dict(doc, res, b"Font");
        for (idx, (_, font_obj)) in fonts.iter().enumerate() {
            let font_ref = font_obj.as_ref();
            if let Some(dict) = doc.resolve(font_obj).as_dict().cloned()
                && dict.name(b"Subtype") == Some(b"Type3")
            {
                let key = match font_ref {
                    Some(r) => FontKey::Ref(r),
                    None => FontKey::Inline(holder_ref, idx),
                };
                t3_fonts.entry(key).or_insert(dict);
            }
        }
        let extg = res_dict(doc, res, b"ExtGState");
        for (idx, (_, state_obj)) in extg.iter().enumerate() {
            if let Some(state) = doc.resolve(state_obj).as_dict()
                && let Some(font_arr) = doc.resolve(state.get(b"Font").unwrap_or(&Object::Null)).as_array()
                && let Some(font_obj) = font_arr.first()
            {
                let font_ref = font_obj.as_ref();
                if let Some(dict) = doc.resolve(font_obj).as_dict().cloned()
                    && dict.name(b"Subtype") == Some(b"Type3")
                {
                    let key = match font_ref {
                        Some(r) => FontKey::Ref(r),
                        None => FontKey::Inline(holder_ref, idx),
                    };
                    t3_fonts.entry(key).or_insert(dict);
                }
            }
        }
    };

    for (node, _) in &holders {
        if let Some(res) = doc.get(*node).as_dict().and_then(|d| d.get(b"Resources")).and_then(|r| doc.resolve(r).as_dict().cloned()) {
            check_res_fonts(doc, *node, &res, &mut type3_fonts);
        }
    }
    for (form_ref, form_res) in &form_holders {
        check_res_fonts(doc, *form_ref, form_res, &mut type3_fonts);
    }

    if type3_fonts.is_empty() {
        return Ok(());
    }

    // Build code-to-glyph mappings for each Type 3 font. Fails closed on error.
    let mut font_maps: HashMap<FontKey, [Option<Vec<u8>>; 256]> = HashMap::new();
    for (key, font_dict) in &type3_fonts {
        let map = type3_code_to_glyph(doc, font_dict)?;
        font_maps.insert(*key, map);
    }

    // Scan all page contents and reachable forms to discover surviving glyph usage.
    let page_list = pdfcraft_model::pages(doc);
    let mut used_glyphs: HashMap<FontKey, HashSet<Vec<u8>>> = HashMap::new();
    let mut seen_drawn_forms = HashSet::new();

    let mut ctx = ScanContext { doc, font_maps: &font_maps, used_glyphs: &mut used_glyphs, seen_forms: &mut seen_drawn_forms };

    for (pi, p) in page_list.iter().enumerate() {
        let (_, content) = page_streams(ctx.doc, &p.dict, pi)?;
        let page_res = p
            .dict
            .get(b"Resources")
            .and_then(|r| ctx.doc.resolve(r).as_dict().cloned())
            .or_else(|| {
                holders.iter().find(|(_, users)| users.contains(&p.obj)).and_then(|(h, _)| {
                    ctx.doc.get(*h).as_dict().and_then(|d| d.get(b"Resources")).and_then(|ro| ctx.doc.resolve(ro).as_dict().cloned())
                })
            })
            .unwrap_or_default();

        scan_content_stream(&mut ctx, &content, p.obj, &page_res, None, 0)?;
    }

    // Also scan any surviving form that wasn't reached by page streams directly.
    for (form_ref, form_res) in &form_holders {
        if !ctx.seen_forms.contains(form_ref) {
            let Object::Stream(s) = &*ctx.doc.get(*form_ref) else { continue };
            let data = s.decoded()?;
            scan_content_stream(&mut ctx, std::slice::from_ref(&data), *form_ref, form_res, None, 0)?;
        }
    }

    // For each Type 3 font: unlink unused glyphs from CharProcs and prune exclusive resources.
    for (font_key, font_dict) in &type3_fonts {
        let surviving = used_glyphs.get(font_key).cloned().unwrap_or_default();
        let Some(char_procs_val) = font_dict.get(b"CharProcs") else {
            return Err(
                CosError::Syntax { offset: 0, detail: "redaction could not establish safe Type 3 font cleanup: missing CharProcs".into() }.into()
            );
        };
        let char_procs_ref = char_procs_val.as_ref();
        let mut char_procs = doc.resolve(char_procs_val).as_dict().cloned().ok_or_else(|| CosError::Syntax {
            offset: 0,
            detail: "redaction could not establish safe Type 3 font cleanup: CharProcs is not a dict".into(),
        })?;

        let mut procs_changed = false;
        let glyph_names: Vec<Vec<u8>> = char_procs.iter().map(|(n, _)| n.to_vec()).collect();
        for g in glyph_names {
            if !surviving.contains(&g) {
                char_procs.remove(&g);
                procs_changed = true;
            }
        }

        if char_procs.is_empty() {
            // The font has no surviving glyphs: remove font from /Font across all holders.
            remove_font_from_holders(doc, &holders, &form_holders, font_key)?;
        } else {
            if procs_changed {
                if let Some(r) = char_procs_ref {
                    doc.update_dict(r, |d| *d = char_procs.clone())?;
                } else if let FontKey::Ref(fr) = font_key {
                    doc.update_dict(*fr, |d| {
                        d.set(b"CharProcs".to_vec(), Object::Dict(char_procs.clone()));
                    })?;
                }
            }

            // Clean exclusive resources from the Type 3 font's /Resources.
            if let Some(f_res_val) = font_dict.get(b"Resources") {
                let f_res_ref = f_res_val.as_ref();
                let mut f_res = doc.resolve(f_res_val).as_dict().cloned().unwrap_or_default();

                let mut used_in_glyphs = UsedInGlyphs::default();
                for (_, proc_val) in char_procs.iter() {
                    let resolved = doc.resolve(proc_val);
                    let Object::Stream(s) = &*resolved else {
                        return Err(CosError::Syntax {
                            offset: 0,
                            detail: "redaction could not establish safe Type 3 font cleanup: CharProc is not a stream".into(),
                        }
                        .into());
                    };
                    let data = s.decoded()?;
                    collect_used_resources_in_stream(&data, &mut used_in_glyphs)?;
                }

                if prune_type3_font_resources(doc, &mut f_res, &used_in_glyphs) {
                    if let Some(rr) = f_res_ref {
                        doc.update_dict(rr, |d| *d = f_res.clone())?;
                    } else if let FontKey::Ref(fr) = font_key {
                        doc.update_dict(*fr, |d| {
                            if f_res.is_empty() {
                                d.remove(b"Resources");
                            } else {
                                d.set(b"Resources".to_vec(), Object::Dict(f_res.clone()));
                            }
                        })?;
                    }
                }
            }
        }
    }

    Ok(())
}

fn remove_font_from_holders(
    doc: &mut Document,
    holders: &[(ObjRef, Vec<ObjRef>)],
    form_holders: &[(ObjRef, Dict)],
    target_key: &FontKey,
) -> Result<(), RedactError> {
    let clean_res = |doc: &Document, res: &mut Dict| -> bool {
        let mut fonts = res_dict(doc, res, b"Font");
        let mut changed = false;
        let names: Vec<Vec<u8>> = fonts.iter().map(|(n, _)| n.to_vec()).collect();
        for (idx, n) in names.into_iter().enumerate() {
            if let Some(val) = fonts.get(&n) {
                let key = match val.as_ref() {
                    Some(r) => FontKey::Ref(r),
                    None => FontKey::Inline(ObjRef::new(0, 0), idx), // matched below if target is Ref
                };
                let matches = match (target_key, key) {
                    (FontKey::Ref(target_r), FontKey::Ref(key_r)) => *target_r == key_r,
                    (FontKey::Inline(target_h, target_idx), _) => {
                        // Compare by value
                        if let Some(target_dict) = doc.get(*target_h).as_dict() {
                            fonts.get(&n) == target_dict.get(n.as_slice()) && *target_idx == idx
                        } else {
                            false
                        }
                    }
                    _ => false,
                };
                if matches {
                    fonts.remove(&n);
                    changed = true;
                }
            }
        }
        if changed {
            if fonts.is_empty() {
                res.remove(b"Font");
            } else {
                res.set(b"Font".to_vec(), Object::Dict(fonts));
            }
        }
        changed
    };

    for (node, _) in holders {
        if let Some(mut res) = doc.get(*node).as_dict().and_then(|d| d.get(b"Resources")).and_then(|r| doc.resolve(r).as_dict().cloned())
            && clean_res(doc, &mut res)
        {
            doc.update_dict(*node, |d| {
                d.set(b"Resources".to_vec(), Object::Dict(res));
            })?;
        }
    }

    for (form_ref, _) in form_holders {
        let obj = doc.get(*form_ref);
        if let Object::Stream(s) = &*obj
            && let Some(mut res) = s.dict.get(b"Resources").and_then(|r| doc.resolve(r).as_dict().cloned())
            && clean_res(doc, &mut res)
        {
            doc.update_dict(*form_ref, |d| {
                d.set(b"Resources".to_vec(), Object::Dict(res));
            })?;
        }
    }

    Ok(())
}
