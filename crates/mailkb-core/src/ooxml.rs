//! Pure Rust ZIP / OOXML (`.xlsx`, `.xlsm`, `.docx`) reader with strict S1 decompression bounds.

use crate::error::{KbError, KbResult};
use crate::security::{collapse_ws, read_file_readonly};
use quick_xml::events::Event;
use quick_xml::Reader;
use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::Path;
use zip::ZipArchive;

pub const MAX_OOXML_FILE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OOXML_ENTRY_OUT: usize = 8 * 1024 * 1024;
pub const MAX_OOXML_ENTRIES: usize = 1024;
pub const OOXML_PREVIEW_MAX_CHARS: usize = 4000;
pub const DEFAULT_MAX_XLSX_SHEETS: usize = 8;
pub const DEFAULT_MAX_XLSX_ROWS: usize = 250;
const MAX_XLSX_COLS: usize = 512;

/// Configuration bounds for OOXML extraction.
#[derive(Debug, Clone)]
pub struct OoxmlOptions {
    pub max_file_bytes: usize,
    pub max_entry_bytes: usize,
    pub max_entries: usize,
    pub max_sheets: usize,
    pub max_rows: usize,
    pub preview_max_chars: Option<usize>,
    pub include_headers_footers_in_docx: bool,
}

impl OoxmlOptions {
    /// Strict S1 preview profile used during mail indexing (`8 sheets x 250 rows`, `4000`-char preview).
    pub fn mail_preview() -> Self {
        Self {
            max_file_bytes: MAX_OOXML_FILE_BYTES,
            max_entry_bytes: MAX_OOXML_ENTRY_OUT,
            max_entries: MAX_OOXML_ENTRIES,
            max_sheets: DEFAULT_MAX_XLSX_SHEETS,
            max_rows: DEFAULT_MAX_XLSX_ROWS,
            preview_max_chars: Some(OOXML_PREVIEW_MAX_CHARS),
            include_headers_footers_in_docx: false,
        }
    }

    /// Structured full-table profile.
    pub fn full_table() -> Self {
        Self {
            max_file_bytes: MAX_OOXML_FILE_BYTES,
            max_entry_bytes: MAX_OOXML_ENTRY_OUT,
            max_entries: MAX_OOXML_ENTRIES,
            max_sheets: 32,
            max_rows: 50_000,
            preview_max_chars: None,
            include_headers_footers_in_docx: true,
        }
    }
}

impl Default for OoxmlOptions {
    fn default() -> Self {
        Self::mail_preview()
    }
}

/// Extracted `.xlsx`/`.xlsm` text preview and structured sheet grids.
#[derive(Debug, Clone, Default)]
pub struct XlsxExtractResult {
    pub preview: String,
    pub sheets: Vec<(String, Vec<Vec<String>>)>,
}

fn read_bounded_zip_entry<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    name: &str,
    max_entry_bytes: usize,
) -> KbResult<Option<Vec<u8>>> {
    let entry = match archive.by_name(name) {
        Ok(e) => e,
        Err(zip::result::ZipError::FileNotFound) => return Ok(None),
        Err(e) => return Err(KbError::Ooxml(format!("zip entry '{name}' error: {e}"))),
    };

    let mut out =
        Vec::with_capacity((entry.size() as usize).min(max_entry_bytes).min(256 * 1024));
    let mut limited = entry.take((max_entry_bytes as u64).saturating_add(1));
    limited
        .read_to_end(&mut out)
        .map_err(|e| KbError::Ooxml(format!("decompress '{name}' failed: {e}")))?;
    if out.len() > max_entry_bytes {
        return Err(KbError::Ooxml(format!(
            "zip entry '{name}' exceeds max uncompressed size ({max_entry_bytes} bytes)"
        )));
    }
    Ok(Some(out))
}

fn open_bounded_zip<'a>(
    data: &'a [u8],
    opts: &OoxmlOptions,
) -> KbResult<ZipArchive<Cursor<&'a [u8]>>> {
    if data.len() > opts.max_file_bytes {
        return Err(KbError::Ooxml(format!(
            "OOXML input {} bytes exceeds limit {} bytes",
            data.len(),
            opts.max_file_bytes
        )));
    }
    let archive = ZipArchive::new(Cursor::new(data))
        .map_err(|e| KbError::Ooxml(format!("invalid zip archive: {e}")))?;
    if archive.len() > opts.max_entries {
        return Err(KbError::Ooxml(format!(
            "zip contains {} entries, exceeding limit {}",
            archive.len(),
            opts.max_entries
        )));
    }
    Ok(archive)
}

#[inline]
fn local_name(bytes: &[u8]) -> &[u8] {
    match bytes.iter().rposition(|&b| b == b':') {
        Some(pos) => &bytes[pos + 1..],
        None => bytes,
    }
}

fn parse_shared_strings(xml: &[u8]) -> Vec<String> {
    let mut sst = Vec::new();
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut in_si = false;
    let mut in_t = false;
    let mut cur_si = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let qn = e.name();
                let lname = local_name(qn.as_ref());
                if lname == b"si" {
                    in_si = true;
                    cur_si.clear();
                } else if in_si && lname == b"t" {
                    in_t = true;
                }
            }
            Ok(Event::Empty(e)) => {
                let qn = e.name();
                let lname = local_name(qn.as_ref());
                if lname == b"si" {
                    sst.push(String::new());
                }
            }
            Ok(Event::End(e)) => {
                let qn = e.name();
                let lname = local_name(qn.as_ref());
                if lname == b"t" && in_si {
                    in_t = false;
                } else if lname == b"si" {
                    if in_si {
                        sst.push(std::mem::take(&mut cur_si));
                    }
                    in_si = false;
                    in_t = false;
                }
            }
            Ok(Event::Text(e)) => {
                if in_si && in_t {
                    if let Ok(txt) = e.unescape() {
                        cur_si.push_str(&txt);
                    }
                }
            }
            Ok(Event::CData(e)) => {
                if in_si && in_t {
                    if let Ok(txt) = std::str::from_utf8(e.as_ref()) {
                        cur_si.push_str(txt);
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
    sst
}

fn normalize_xl_target(raw_target: &str) -> String {
    let trimmed = raw_target.trim_start_matches('/');
    let joined = if trimmed.starts_with("xl/") {
        trimmed.to_string()
    } else {
        format!("xl/{trimmed}")
    };
    let mut stack: Vec<&str> = Vec::new();
    for seg in joined.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    stack.join("/")
}

fn resolve_sheet_list<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    opts: &OoxmlOptions,
) -> KbResult<Vec<(String, String)>> {
    let names_set: std::collections::HashSet<String> =
        archive.file_names().map(|s| s.to_string()).collect();

    let mut rels_map: HashMap<String, String> = HashMap::new();
    if let Some(rxml) =
        read_bounded_zip_entry(archive, "xl/_rels/workbook.xml.rels", opts.max_entry_bytes)?
    {
        let mut reader = Reader::from_reader(rxml.as_slice());
        let mut buf = Vec::new();
        loop {
            match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                    if local_name(e.name().as_ref()) == b"Relationship" {
                        let mut id = String::new();
                        let mut target = String::new();
                        for attr in e.attributes().flatten() {
                            let k = local_name(attr.key.as_ref());
                            if k == b"Id" {
                                id = attr
                                    .unescape_value()
                                    .map(|v| v.into_owned())
                                    .unwrap_or_default();
                            } else if k == b"Target" {
                                target = attr
                                    .unescape_value()
                                    .map(|v| v.into_owned())
                                    .unwrap_or_default();
                            }
                        }
                        if !id.is_empty() && !target.is_empty() {
                            rels_map.insert(id, normalize_xl_target(&target));
                        }
                    }
                }
                Ok(Event::Eof) | Err(_) => break,
                _ => {}
            }
            buf.clear();
        }
    }

    let mut sheets: Vec<(String, String)> = Vec::new();
    if !rels_map.is_empty() {
        if let Some(wxml) =
            read_bounded_zip_entry(archive, "xl/workbook.xml", opts.max_entry_bytes)?
        {
            let mut reader = Reader::from_reader(wxml.as_slice());
            let mut buf = Vec::new();
            loop {
                match reader.read_event_into(&mut buf) {
                    Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                        if local_name(e.name().as_ref()) == b"sheet" {
                            let mut sname = String::new();
                            let mut rid = String::new();
                            for attr in e.attributes().flatten() {
                                let k = local_name(attr.key.as_ref());
                                if k == b"name" {
                                    sname = attr
                                        .unescape_value()
                                        .map(|v| v.into_owned())
                                        .unwrap_or_default();
                                } else if k == b"id" {
                                    rid = attr
                                        .unescape_value()
                                        .map(|v| v.into_owned())
                                        .unwrap_or_default();
                                }
                            }
                            if let Some(spath) = rels_map.get(&rid) {
                                if names_set.contains(spath) {
                                    let display = if sname.is_empty() {
                                        spath.clone()
                                    } else {
                                        sname
                                    };
                                    sheets.push((display, spath.clone()));
                                }
                            }
                        }
                    }
                    Ok(Event::Eof) | Err(_) => break,
                    _ => {}
                }
                buf.clear();
            }
        }
    }

    if sheets.is_empty() {
        let mut fallback: Vec<String> = names_set
            .into_iter()
            .filter(|n| n.starts_with("xl/worksheets/sheet") && n.ends_with(".xml"))
            .collect();
        fallback.sort();
        for sp in fallback {
            let name = sp.rsplit('/').next().unwrap_or(&sp).to_string();
            sheets.push((name, sp));
        }
    }

    Ok(sheets)
}

fn col_from_cell_ref(cell_ref: &str) -> Option<usize> {
    let mut col: usize = 0;
    let mut any = false;
    for b in cell_ref.bytes() {
        if b.is_ascii_uppercase() {
            col = col.checked_mul(26)?.checked_add((b - b'A' + 1) as usize)?;
            any = true;
        } else if b.is_ascii_lowercase() {
            col = col.checked_mul(26)?.checked_add((b - b'a' + 1) as usize)?;
            any = true;
        } else {
            break;
        }
    }
    if any && col > 0 {
        Some(col - 1)
    } else {
        None
    }
}

fn parse_worksheet_grid(xml: &[u8], sst: &[String], max_rows: usize) -> Vec<Vec<String>> {
    let mut grid: Vec<Vec<String>> = Vec::new();
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut in_row = false;
    let mut in_c = false;
    let mut in_v = false;
    let mut in_t = false;
    let mut c_type = String::new();
    let mut cur_col: isize = -1;
    let mut max_col: isize = -1;
    let mut row_cells: Vec<(usize, String)> = Vec::new();
    let mut cell_txt = String::new();
    let mut buf = Vec::new();

    let flush_cell = |in_c: &mut bool,
                      in_v: &mut bool,
                      in_t: &mut bool,
                      c_type: &str,
                      cur_col: isize,
                      max_col: &mut isize,
                      row_cells: &mut Vec<(usize, String)>,
                      cell_txt: &mut String| {
        if !*in_c {
            return;
        }
        let mut val = collapse_ws(cell_txt);
        if c_type == "s" && !val.is_empty() {
            if let Ok(idx) = val.parse::<usize>() {
                val = sst.get(idx).map(|s| collapse_ws(s)).unwrap_or_default();
            } else {
                val.clear();
            }
        } else if c_type == "b" && !val.is_empty() {
            val = match val.as_str() {
                "1" => "TRUE".to_string(),
                "0" => "FALSE".to_string(),
                _ => val,
            };
        }
        if !val.is_empty() && cur_col >= 0 && (cur_col as usize) < MAX_XLSX_COLS {
            let col = cur_col as usize;
            row_cells.push((col, val));
            if cur_col > *max_col {
                *max_col = cur_col;
            }
        }
        cell_txt.clear();
        *in_c = false;
        *in_v = false;
        *in_t = false;
    };

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let qn = e.name();
                let lname = local_name(qn.as_ref());
                if lname == b"row" {
                    in_row = true;
                    row_cells.clear();
                    max_col = -1;
                    cur_col = -1;
                } else if in_row && lname == b"c" {
                    c_type.clear();
                    let mut ref_attr = String::new();
                    for attr in e.attributes().flatten() {
                        let k = local_name(attr.key.as_ref());
                        if k == b"t" {
                            c_type = attr
                                .unescape_value()
                                .map(|v| v.into_owned())
                                .unwrap_or_default();
                        } else if k == b"r" {
                            ref_attr = attr
                                .unescape_value()
                                .map(|v| v.into_owned())
                                .unwrap_or_default();
                        }
                    }
                    cur_col = col_from_cell_ref(&ref_attr)
                        .map(|c| c as isize)
                        .unwrap_or(cur_col + 1);
                    cell_txt.clear();
                    in_c = true;
                    in_v = false;
                    in_t = false;
                } else if in_c && lname == b"v" {
                    in_v = true;
                } else if in_c && lname == b"t" {
                    in_t = true;
                }
            }
            Ok(Event::End(e)) => {
                let qn = e.name();
                let lname = local_name(qn.as_ref());
                if lname == b"v" && in_c {
                    in_v = false;
                } else if lname == b"t" && in_c {
                    in_t = false;
                } else if lname == b"c" && in_row {
                    flush_cell(
                        &mut in_c,
                        &mut in_v,
                        &mut in_t,
                        &c_type,
                        cur_col,
                        &mut max_col,
                        &mut row_cells,
                        &mut cell_txt,
                    );
                } else if lname == b"row" && in_row {
                    flush_cell(
                        &mut in_c,
                        &mut in_v,
                        &mut in_t,
                        &c_type,
                        cur_col,
                        &mut max_col,
                        &mut row_cells,
                        &mut cell_txt,
                    );
                    if !row_cells.is_empty() && max_col >= 0 {
                        let width = (max_col as usize + 1).min(MAX_XLSX_COLS);
                        let mut row_vec = vec![String::new(); width];
                        for (ci, val) in row_cells.drain(..) {
                            if ci < width {
                                row_vec[ci] = val;
                            }
                        }
                        grid.push(row_vec);
                        if grid.len() >= max_rows {
                            break;
                        }
                    }
                    row_cells.clear();
                    max_col = -1;
                    in_row = false;
                }
            }
            Ok(Event::Text(e)) => {
                if in_c && (in_v || in_t) {
                    if let Ok(txt) = e.unescape() {
                        cell_txt.push_str(&txt);
                    }
                }
            }
            Ok(Event::CData(e)) => {
                if in_c && (in_v || in_t) {
                    if let Ok(txt) = std::str::from_utf8(e.as_ref()) {
                        cell_txt.push_str(txt);
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    grid
}

fn truncate_preview_utf8(s: &mut String, max_chars: usize) {
    if s.chars().count() > max_chars {
        if let Some((idx, _)) = s.char_indices().nth(max_chars) {
            s.truncate(idx);
        }
    }
}

/// Extracts structured sheet rows and a compact text preview from `.xlsx`/`.xlsm` bytes.
pub fn extract_xlsx_from_bytes(data: &[u8], opts: &OoxmlOptions) -> KbResult<XlsxExtractResult> {
    let mut archive = open_bounded_zip(data, opts)?;

    let sst =
        match read_bounded_zip_entry(&mut archive, "xl/sharedStrings.xml", opts.max_entry_bytes)? {
            Some(bytes) => parse_shared_strings(&bytes),
            None => Vec::new(),
        };

    let sheet_list = resolve_sheet_list(&mut archive, opts)?;
    let mut res = XlsxExtractResult::default();
    let max_preview = opts.preview_max_chars.unwrap_or(usize::MAX);

    for (sname, spath) in sheet_list.into_iter().take(opts.max_sheets) {
        let Some(sxml) = read_bounded_zip_entry(&mut archive, &spath, opts.max_entry_bytes)? else {
            continue;
        };
        let grid = parse_worksheet_grid(&sxml, &sst, opts.max_rows);
        if grid.is_empty() {
            continue;
        }
        if res.preview.len() < max_preview {
            res.preview.push_str("[Sheet: ");
            res.preview.push_str(&sname);
            res.preview.push_str("]\n");
            for row in &grid {
                if res.preview.len() >= max_preview {
                    break;
                }
                let line: String = row
                    .iter()
                    .filter(|c| !c.is_empty())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" | ");
                if !line.is_empty() {
                    res.preview.push_str(&line);
                    res.preview.push('\n');
                }
            }
        }
        res.sheets.push((sname, grid));
    }

    if let Some(limit) = opts.preview_max_chars {
        truncate_preview_utf8(&mut res.preview, limit);
    }
    Ok(res)
}

/// Reads an `.xlsx`/`.xlsm` file safely via `open_readonly_nofollow`.
pub fn extract_xlsx_from_path(path: &Path, opts: &OoxmlOptions) -> KbResult<XlsxExtractResult> {
    let (bytes, truncated) = read_file_readonly(path, Some(opts.max_file_bytes))?;
    if truncated {
        return Err(KbError::Ooxml(format!(
            "OOXML file {} exceeds limit {} bytes",
            path.display(),
            opts.max_file_bytes
        )));
    }
    extract_xlsx_from_bytes(&bytes, opts)
}

fn parse_docx_xml(xml: &[u8], out: &mut String, max_chars: usize) {
    let mut reader = Reader::from_reader(xml);
    reader.config_mut().trim_text(false);

    let mut in_p = false;
    let mut in_t = false;
    let mut in_tbl = false;
    let mut in_tr = false;
    let mut in_tc = false;
    let mut para_buf = String::new();
    let mut row_cells: Vec<String> = Vec::new();
    let mut cell_buf = String::new();
    let mut buf = Vec::new();

    loop {
        if out.chars().count() >= max_chars {
            break;
        }
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let qn = e.name();
                let lname = local_name(qn.as_ref());
                match lname {
                    b"tbl" => in_tbl = true,
                    b"tr" if in_tbl => {
                        in_tr = true;
                        row_cells.clear();
                    }
                    b"tc" if in_tr => {
                        in_tc = true;
                        cell_buf.clear();
                    }
                    b"p" => {
                        in_p = true;
                        para_buf.clear();
                    }
                    b"t" if in_p => in_t = true,
                    b"tab" if in_p => para_buf.push('\t'),
                    b"br" if in_p => para_buf.push(' '),
                    _ => {}
                }
            }
            Ok(Event::Empty(e)) => {
                let qn = e.name();
                let lname = local_name(qn.as_ref());
                if lname == b"tab" && in_p {
                    para_buf.push('\t');
                } else if lname == b"br" && in_p {
                    para_buf.push(' ');
                }
            }
            Ok(Event::End(e)) => {
                let qn = e.name();
                let lname = local_name(qn.as_ref());
                match lname {
                    b"t" if in_p => in_t = false,
                    b"p" if in_p => {
                        let p = collapse_ws(&para_buf);
                        if !p.is_empty() {
                            if in_tc {
                                if !cell_buf.is_empty() {
                                    cell_buf.push_str(" / ");
                                }
                                cell_buf.push_str(&p);
                            } else {
                                out.push_str(&p);
                                out.push('\n');
                            }
                        }
                        para_buf.clear();
                        in_p = false;
                        in_t = false;
                    }
                    b"tc" if in_tr => {
                        row_cells.push(collapse_ws(&cell_buf));
                        cell_buf.clear();
                        in_tc = false;
                    }
                    b"tr" if in_tbl => {
                        if row_cells.iter().any(|c| !c.is_empty()) {
                            out.push_str(&row_cells.join(" | "));
                            out.push('\n');
                        }
                        row_cells.clear();
                        in_tr = false;
                    }
                    b"tbl" => {
                        in_tbl = false;
                        in_tr = false;
                        in_tc = false;
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(e)) => {
                if in_p && in_t {
                    if let Ok(txt) = e.unescape() {
                        para_buf.push_str(&txt);
                    }
                }
            }
            Ok(Event::CData(e)) => {
                if in_p && in_t {
                    if let Ok(txt) = std::str::from_utf8(e.as_ref()) {
                        para_buf.push_str(txt);
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
        buf.clear();
    }
}

/// Extracts paragraphs and table rows from `.docx` bytes under strict S1 bounds.
pub fn extract_docx_from_bytes(data: &[u8], opts: &OoxmlOptions) -> KbResult<String> {
    let mut archive = open_bounded_zip(data, opts)?;
    let max_chars = opts.preview_max_chars.unwrap_or(usize::MAX);

    let mut targets: Vec<String> = Vec::new();
    let names: Vec<String> = {
        let mut v: Vec<String> = archive.file_names().map(|s| s.to_string()).collect();
        v.sort();
        v
    };
    for name in names {
        if name == "word/document.xml"
            || (opts.include_headers_footers_in_docx
                && name.starts_with("word/")
                && name.ends_with(".xml")
                && (name.starts_with("word/header") || name.starts_with("word/footer")))
        {
            targets.push(name);
        }
    }
    if targets.is_empty() {
        return Ok(String::new());
    }

    let mut out = String::new();
    for target in targets {
        if out.chars().count() >= max_chars {
            break;
        }
        if let Some(xml) = read_bounded_zip_entry(&mut archive, &target, opts.max_entry_bytes)? {
            parse_docx_xml(&xml, &mut out, max_chars);
        }
    }

    if let Some(limit) = opts.preview_max_chars {
        truncate_preview_utf8(&mut out, limit);
    }
    while out.ends_with('\n') || out.ends_with(' ') {
        out.pop();
    }
    Ok(out)
}

/// Reads a `.docx` file safely via `open_readonly_nofollow` and extracts its text.
pub fn extract_docx_from_path(path: &Path, opts: &OoxmlOptions) -> KbResult<String> {
    let (bytes, truncated) = read_file_readonly(path, Some(opts.max_file_bytes))?;
    if truncated {
        return Err(KbError::Ooxml(format!(
            "OOXML file {} exceeds limit {} bytes",
            path.display(),
            opts.max_file_bytes
        )));
    }
    extract_docx_from_bytes(&bytes, opts)
}
