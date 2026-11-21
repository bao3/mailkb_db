//! Linear-time HTML entity decoder, text extractor, and 2D HTML table parser.

use mailkb_core::security::collapse_ws;
use mailkb_core::strutil::{is_ascii_ws_byte, trim_ascii_ws, utf8_trunc_sv};

pub type Table2D = Vec<Vec<String>>;

#[derive(Debug, Clone, Default)]
pub struct HtmlParseResult {
    pub text: String,
    pub tables: Vec<Table2D>,
}

pub fn decode_html_entities_utf8(s: &str) -> String {
    if !s.contains('&') {
        return s.to_string();
    }
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'&' {
            let ch = s[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
            continue;
        }
        let search_end = (i + 13).min(bytes.len());
        let semi_rel = bytes[i + 1..search_end].iter().position(|&b| b == b';');
        let Some(rel) = semi_rel else {
            out.push('&');
            i += 1;
            continue;
        };
        let semi = i + 1 + rel;
        let ent = &s[i + 1..semi];
        let mut consumed = true;
        match ent {
            "nbsp" => out.push(' '),
            "amp" => out.push('&'),
            "lt" => out.push('<'),
            "gt" => out.push('>'),
            "quot" => out.push('"'),
            "apos" | "#39" => out.push('\''),
            "yen" => out.push('¥'),
            "euro" => out.push('€'),
            "pound" => out.push('£'),
            "mdash" => out.push('—'),
            "ndash" => out.push('–'),
            "ldquo" => out.push('“'),
            "rdquo" => out.push('”'),
            "lsquo" => out.push('‘'),
            "rsquo" => out.push('’'),
            "bull" => out.push('•'),
            "middot" => out.push('·'),
            "hellip" => out.push('…'),
            "copy" => out.push('©'),
            "reg" => out.push('®'),
            "trade" => out.push('™'),
            "times" => out.push('×'),
            "divide" => out.push('÷'),
            "plusmn" => out.push('±'),
            "deg" => out.push('°'),
            _ if ent.starts_with('#') && ent.len() >= 2 => {
                let parsed = if ent.starts_with("#x") || ent.starts_with("#X") {
                    u32::from_str_radix(&ent[2..], 16).ok()
                } else {
                    ent[1..].parse::<u32>().ok()
                };
                if let Some(cp) = parsed.filter(|&c| c > 0 && c <= 0x10FFFF) {
                    if cp == 160 || cp == 0x3000 {
                        out.push(' ');
                    } else if let Some(ch) = char::from_u32(cp) {
                        out.push(ch);
                    } else {
                        consumed = false;
                    }
                } else {
                    consumed = false;
                }
            }
            _ => {
                consumed = false;
            }
        }
        if consumed {
            i = semi + 1;
        } else {
            out.push('&');
            i += 1;
        }
    }
    out
}

#[derive(Default)]
struct TableState {
    rows: Table2D,
    in_tr: bool,
    in_cell: bool,
    cur_row: Vec<String>,
    cur_cell: String,
}

pub fn parse_html_clean_and_tables(html: &str) -> HtmlParseResult {
    let mut res = HtmlParseResult::default();
    if html.is_empty() {
        return res;
    }
    let html = utf8_trunc_sv(html, 2 * 1024 * 1024);
    res.text.reserve(html.len().min(65_536));

    let mut skip_depth: i32 = 0;
    let mut tbl_stack: Vec<TableState> = Vec::new();

    let emit_text = |chunk: &str,
                     skip_depth: i32,
                     text: &mut String,
                     tbl_stack: &mut Vec<TableState>| {
        if skip_depth > 0 || chunk.is_empty() {
            return;
        }
        let dec = decode_html_entities_utf8(chunk);
        for ch in dec.chars() {
            if ch == '\r' {
                continue;
            }
            if ch == '\n' || ch == '\t' {
                if text.is_empty() || (!text.ends_with('\n') && !text.ends_with(' ')) {
                    text.push(' ');
                }
                if let Some(ts) = tbl_stack.last_mut() {
                    if ts.in_cell {
                        ts.cur_cell.push(if ch == '\n' { '\n' } else { ' ' });
                    }
                }
            } else {
                text.push(ch);
                if let Some(ts) = tbl_stack.last_mut() {
                    if ts.in_cell {
                        ts.cur_cell.push(ch);
                    }
                }
            }
        }
    };

    let push_nl = |skip_depth: i32, text: &mut String| {
        if skip_depth > 0 {
            return;
        }
        while text.ends_with(' ') {
            text.pop();
        }
        if text.is_empty() || !text.ends_with("\n\n") {
            text.push('\n');
        }
    };

    let mut i = 0;
    while i < html.len() {
        let Some(lt_rel) = html[i..].find('<') else {
            emit_text(&html[i..], skip_depth, &mut res.text, &mut tbl_stack);
            break;
        };
        let lt = i + lt_rel;
        if lt > i {
            emit_text(&html[i..lt], skip_depth, &mut res.text, &mut tbl_stack);
        }

        if html[lt..].starts_with("<!--") {
            let Some(end_rel) = html[lt + 4..].find("-->") else {
                break;
            };
            i = lt + 4 + end_rel + 3;
            continue;
        }

        let Some(gt_rel) = html[lt + 1..].find('>') else {
            break;
        };
        let gt = lt + 1 + gt_rel;
        let inside = &html[lt + 1..gt];
        let ib = inside.as_bytes();
        let mut tp = 0;
        while tp < ib.len() && is_ascii_ws_byte(ib[tp]) {
            tp += 1;
        }
        let mut is_close = false;
        if tp < ib.len() && ib[tp] == b'/' {
            is_close = true;
            tp += 1;
        }
        let ts = tp;
        while tp < ib.len() && (ib[tp].is_ascii_alphanumeric() || ib[tp] == b':' || ib[tp] == b'-')
        {
            tp += 1;
        }
        let tname = inside[ts..tp].to_ascii_lowercase();

        if matches!(
            tname.as_str(),
            "script" | "style" | "head" | "title" | "xml"
        ) {
            if is_close {
                if skip_depth > 0 {
                    skip_depth -= 1;
                }
            } else if !inside.ends_with('/') {
                skip_depth += 1;
            }
        } else if skip_depth == 0 {
            match tname.as_str() {
                "br" => {
                    push_nl(skip_depth, &mut res.text);
                    if let Some(st) = tbl_stack.last_mut() {
                        if st.in_cell {
                            st.cur_cell.push('\n');
                        }
                    }
                }
                "p" | "div" | "li" | "h1" | "h2" | "h3" | "h4" | "blockquote" | "hr" => {
                    push_nl(skip_depth, &mut res.text);
                    if is_close {
                        if let Some(st) = tbl_stack.last_mut() {
                            if st.in_cell {
                                st.cur_cell.push('\n');
                            }
                        }
                    }
                }
                "table" => {
                    if !is_close {
                        if tbl_stack.len() < 6 {
                            tbl_stack.push(TableState::default());
                        }
                    } else if let Some(st) = tbl_stack.pop() {
                        if st.rows.len() >= 2 && res.tables.len() < 24 {
                            let max_cols = st.rows.iter().map(|r| r.len()).max().unwrap_or(0);
                            if max_cols >= 2 {
                                res.tables.push(st.rows);
                            }
                        }
                        push_nl(skip_depth, &mut res.text);
                    }
                }
                "tr" => {
                    if let Some(st) = tbl_stack.last_mut() {
                        if !is_close {
                            st.in_tr = true;
                            st.cur_row.clear();
                        } else {
                            if st.in_cell {
                                st.cur_row.push(trim_ascii_ws(&st.cur_cell).to_string());
                                st.cur_cell.clear();
                                st.in_cell = false;
                            }
                            if st.cur_row.iter().any(|c| !c.is_empty()) && st.rows.len() < 250 {
                                st.rows.push(std::mem::take(&mut st.cur_row));
                            }
                            st.cur_row.clear();
                            st.in_tr = false;
                            push_nl(skip_depth, &mut res.text);
                        }
                    }
                }
                "td" | "th" => {
                    if let Some(st) = tbl_stack.last_mut() {
                        if !is_close {
                            if st.in_cell {
                                st.cur_row.push(trim_ascii_ws(&st.cur_cell).to_string());
                            }
                            st.in_cell = true;
                            st.cur_cell.clear();
                        } else {
                            if st.in_cell {
                                let mut cell_norm = String::new();
                                for part in st.cur_cell.split('\n') {
                                    let cp = collapse_ws(part);
                                    if !cp.is_empty() {
                                        if !cell_norm.is_empty() {
                                            cell_norm.push('\n');
                                        }
                                        cell_norm.push_str(&cp);
                                    }
                                }
                                st.cur_row.push(cell_norm);
                                st.cur_cell.clear();
                                st.in_cell = false;
                            }
                            if !res.text.is_empty()
                                && !res.text.ends_with('\n')
                                && !res.text.ends_with(' ')
                            {
                                res.text.push(' ');
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        i = gt + 1;
    }

    res.text = trim_ascii_ws(&res.text).to_string();
    res
}
