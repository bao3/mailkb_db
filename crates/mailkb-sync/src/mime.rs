//! Pure Rust RFC2047/RFC2231, Base64, Quoted-Printable, MIME tree parser,
//! `.emlx` slicer, RFC5322/ISO8601 date parser, and reply-chain splitter.

use encoding_rs::Encoding;
use mailkb_core::publish::sha256_bytes;
use mailkb_core::security::{collapse_ws, sanitize_utf8};
use mailkb_core::strutil::{
    find_ci, find_ci_bytes, is_ascii_ws_byte, safe_slice_after, starts_with_ci,
    starts_with_ci_bytes, trim_ascii_ws, trim_ascii_ws_bytes, utf8_trunc_sv,
};
use mailkb_core::time::{format_local_datetime, parts_to_unix_secs};
use std::collections::HashMap;

pub const MAX_MIME_PART_OUT: usize = 2 * 1024 * 1024;
pub const MAX_ICONV_OUT: usize = 16 * 1024 * 1024;
pub const MAX_MIME_DEPTH: usize = 8;

const B64_TABLE: [i8; 256] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1,
    -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -2, -1, -1, -1, 0, 1, 2, 3, 4, 5,
    6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1,
    -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
    47, 48, 49, 50, 51, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

pub fn base64_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity((input.len() * 3) / 4);
    let mut val: u32 = 0;
    let mut bits: i32 = -8;
    for &b in input {
        let d = B64_TABLE[b as usize];
        if d == -1 {
            continue;
        }
        if d == -2 {
            break;
        }
        val = (val << 6) | (d as u32);
        bits += 6;
        if bits >= 0 {
            out.push(((val >> bits) & 0xFF) as u8);
            bits -= 8;
        }
    }
    out
}

#[inline]
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub fn qp_decode(input: &[u8], underscore_to_space: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let b = input[i];
        if underscore_to_space && b == b'_' {
            out.push(b' ');
            i += 1;
            continue;
        }
        if b == b'=' && i + 1 < input.len() {
            if input[i + 1] == b'\n' {
                i += 2;
                continue;
            }
            if input[i + 1] == b'\r' && i + 2 < input.len() && input[i + 2] == b'\n' {
                i += 3;
                continue;
            }
            if i + 2 < input.len() {
                if let (Some(h1), Some(h2)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                    out.push((h1 << 4) | h2);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(b);
        i += 1;
    }
    out
}

pub fn percent_decode_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' && i + 2 < input.len() {
            if let (Some(h1), Some(h2)) = (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                out.push((h1 << 4) | h2);
                i += 3;
                continue;
            }
        }
        out.push(input[i]);
        i += 1;
    }
    out
}

pub fn percent_decode(input: &[u8]) -> String {
    sanitize_utf8(&percent_decode_bytes(input))
}

pub fn normalize_charset_name(cs: &[u8]) -> String {
    let trimmed = trim_ascii_ws_bytes(cs);
    let mut lo = sanitize_utf8(trimmed).to_ascii_lowercase();
    if let Some(star) = lo.find('*') {
        lo.truncate(star);
    }
    if lo.len() >= 2 && lo.starts_with('"') && lo.ends_with('"') {
        lo = lo[1..lo.len() - 1].to_string();
    }
    match lo.as_str() {
        "gb2312" | "gbk" | "cp936" | "ms936" | "csgb2312" | "gb18030" => "GB18030".to_string(),
        "big5" | "csbig5" | "big5-hkscs" => "BIG5".to_string(),
        "utf8" | "utf-8" | "" | "us-ascii" | "ascii" => "UTF-8".to_string(),
        "iso-8859-1" | "latin1" | "windows-1252" => "WINDOWS-1252".to_string(),
        _ => lo.to_ascii_uppercase(),
    }
}

pub fn decode_charset_bytes(bytes: &[u8], from_cs: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let cs = normalize_charset_name(from_cs);
    let capped = if bytes.len() > MAX_ICONV_OUT {
        &bytes[..MAX_ICONV_OUT]
    } else {
        bytes
    };
    if cs == "UTF-8" {
        return sanitize_utf8(capped);
    }

    let enc = Encoding::for_label(cs.as_bytes()).or_else(|| {
        if cs.starts_with("BIG5") {
            Some(encoding_rs::BIG5)
        } else if cs.starts_with("GB") {
            Some(encoding_rs::GB18030)
        } else {
            None
        }
    });

    let Some(encoding) = enc else {
        return sanitize_utf8(capped);
    };
    let (decoded, _, _) = encoding.decode(capped);
    let clean = sanitize_utf8(decoded.as_bytes());
    if clean.len() > MAX_ICONV_OUT {
        utf8_trunc_sv(&clean, MAX_ICONV_OUT).to_string()
    } else {
        clean
    }
}

pub fn decode_rfc2047_header(raw: &[u8]) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut unfolded = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'\r' && i + 1 < raw.len() && raw[i + 1] == b'\n' {
            if i + 2 < raw.len() && (raw[i + 2] == b' ' || raw[i + 2] == b'\t') {
                unfolded.push(b' ');
                i += 3;
                while i < raw.len() && (raw[i] == b' ' || raw[i] == b'\t') {
                    i += 1;
                }
                continue;
            }
            i += 2;
            continue;
        }
        if raw[i] == b'\n' {
            if i + 1 < raw.len() && (raw[i + 1] == b' ' || raw[i + 1] == b'\t') {
                unfolded.push(b' ');
                i += 2;
                while i < raw.len() && (raw[i] == b' ' || raw[i] == b'\t') {
                    i += 1;
                }
                continue;
            }
            i += 1;
            continue;
        }
        unfolded.push(raw[i]);
        i += 1;
    }

    if !unfolded.windows(2).any(|w| w == b"=?") {
        return sanitize_utf8(trim_ascii_ws_bytes(&unfolded));
    }

    struct Chunk {
        enc: bool,
        cs: String,
        bytes: Vec<u8>,
    }

    let mut chunks: Vec<Chunk> = Vec::new();
    let mut pos = 0;
    while pos < unfolded.len() {
        let Some(st_rel) = unfolded[pos..].windows(2).position(|w| w == b"=?") else {
            chunks.push(Chunk {
                enc: false,
                cs: String::new(),
                bytes: unfolded[pos..].to_vec(),
            });
            break;
        };
        let st = pos + st_rel;
        if st > pos {
            let gap = &unfolded[pos..st];
            let only_ws = gap.iter().all(|&c| c == b' ' || c == b'\t');
            let prev_enc = chunks.last().map(|c| c.enc).unwrap_or(false);
            if !(only_ws && prev_enc) {
                chunks.push(Chunk {
                    enc: false,
                    cs: String::new(),
                    bytes: gap.to_vec(),
                });
            }
        }
        let win_end = unfolded.len().min(st + 512);
        let win = &unfolded[..win_end];
        let q1 = win[st + 2..].iter().position(|&b| b == b'?').map(|x| st + 2 + x);
        let q2 = q1.and_then(|p1| {
            win.get(p1 + 1..)
                .and_then(|s| s.iter().position(|&b| b == b'?'))
                .map(|x| p1 + 1 + x)
        });
        let end_ew = q2.and_then(|p2| {
            win.get(p2 + 1..)
                .and_then(|s| s.windows(2).position(|w| w == b"?="))
                .map(|x| p2 + 1 + x)
        });

        let valid_ew = match (q1, q2, end_ew) {
            (Some(p1), Some(p2), Some(pe)) if p2 - p1 == 2 => {
                let e = unfolded[p1 + 1];
                if matches!(e, b'B' | b'b' | b'Q' | b'q') {
                    Some((p1, p2, pe, e))
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some((p1, p2, pe, enc_ch)) = valid_ew {
            let cs = normalize_charset_name(&win[st + 2..p1]);
            let payload = &win[p2 + 1..pe];
            let dec = if enc_ch == b'B' || enc_ch == b'b' {
                base64_decode(payload)
            } else {
                qp_decode(payload, true)
            };
            if let Some(last) = chunks.last_mut().filter(|c| c.enc && c.cs == cs) {
                last.bytes.extend_from_slice(&dec);
            } else {
                chunks.push(Chunk {
                    enc: true,
                    cs,
                    bytes: dec,
                });
            }
            pos = pe + 2;
        } else {
            chunks.push(Chunk {
                enc: false,
                cs: String::new(),
                bytes: b"=?".to_vec(),
            });
            pos = st + 2;
        }
    }

    let mut out = String::new();
    for c in chunks {
        if c.enc {
            out.push_str(&decode_charset_bytes(&c.bytes, c.cs.as_bytes()));
        } else {
            out.push_str(&sanitize_utf8(&c.bytes));
        }
    }
    trim_ascii_ws(&out).to_string()
}

pub fn extract_header_param(val: &str, param: &str) -> String {
    let mut pos = 0;
    while let Some(hit) = find_ci(val, param, pos) {
        let left_ok = hit == 0 || {
            let prev = val.as_bytes()[hit - 1];
            prev == b';' || is_ascii_ws_byte(prev)
        };
        if !left_ok {
            pos = hit + 1;
            continue;
        }
        let bytes = val.as_bytes();
        let mut j = hit + param.len();
        while j < bytes.len() && is_ascii_ws_byte(bytes[j]) {
            j += 1;
        }
        if j < bytes.len() && bytes[j] == b'=' {
            j += 1;
            while j < bytes.len() && is_ascii_ws_byte(bytes[j]) {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'"' {
                j += 1;
                if let Some(end_rel) = val[j..].find('"') {
                    return val[j..j + end_rel].to_string();
                }
            } else {
                let mut end = j;
                while end < bytes.len() && bytes[end] != b';' && !is_ascii_ws_byte(bytes[end]) {
                    end += 1;
                }
                while end > j && !val.is_char_boundary(end) {
                    end -= 1;
                }
                if val.is_char_boundary(j) {
                    return val[j..end].to_string();
                }
            }
        }
        pos = hit + 1;
    }
    String::new()
}

fn decode_rfc2231_param(val: &str, base_param: &str) -> String {
    let direct = extract_header_param(val, base_param);
    if !direct.is_empty() {
        return direct;
    }
    let star_key = format!("{base_param}*");
    let ext = extract_header_param(val, &star_key);
    if !ext.is_empty() {
        return decode_rfc2231_value(&ext);
    }
    let mut joined = String::new();
    let mut charset = "UTF-8".to_string();
    for idx in 0..16 {
        let part_star = format!("{base_param}*{idx}*");
        let pval = extract_header_param(val, &part_star);
        if !pval.is_empty() {
            if idx == 0 {
                if let Some((cs, rest)) = split_rfc2231_prefix(&pval) {
                    charset = cs;
                    joined.push_str(rest);
                    continue;
                }
            }
            joined.push_str(&pval);
            continue;
        }
        let part_plain = format!("{base_param}*{idx}");
        let pval2 = extract_header_param(val, &part_plain);
        if !pval2.is_empty() {
            joined.push_str(&pval2);
            continue;
        }
        break;
    }
    if joined.is_empty() {
        return String::new();
    }
    let bytes = percent_decode_bytes(joined.as_bytes());
    decode_charset_bytes(&bytes, charset.as_bytes())
}

fn split_rfc2231_prefix(s: &str) -> Option<(String, &str)> {
    let q1 = s.find('\'')?;
    let q2_rel = s[q1 + 1..].find('\'')?;
    let cs = normalize_charset_name(s[..q1].as_bytes());
    let rest = &s[q1 + 1 + q2_rel + 1..];
    Some((cs, rest))
}

fn decode_rfc2231_value(raw: &str) -> String {
    if let Some((cs, rest)) = split_rfc2231_prefix(raw) {
        let bytes = percent_decode_bytes(rest.as_bytes());
        decode_charset_bytes(&bytes, cs.as_bytes())
    } else {
        percent_decode(raw.as_bytes())
    }
}

pub fn split_mime_headers_body(mut raw: &[u8]) -> (HashMap<String, Vec<u8>>, &[u8]) {
    if raw.starts_with(b">From ") || raw.starts_with(b"From ") {
        if let Some(nl) = raw.iter().position(|&b| b == b'\n') {
            raw = &raw[nl + 1..];
        }
    }
    let mut hdr_end = raw.len();
    let mut body_start = raw.len();
    if raw.starts_with(b"\n") {
        hdr_end = 0;
        body_start = 1;
    } else if raw.starts_with(b"\r\n") {
        hdr_end = 0;
        body_start = 2;
    } else {
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'\n' {
                if i + 1 < raw.len() && raw[i + 1] == b'\n' {
                    hdr_end = i;
                    body_start = i + 2;
                    break;
                }
                if i + 2 < raw.len() && raw[i + 1] == b'\r' && raw[i + 2] == b'\n' {
                    hdr_end = i;
                    body_start = i + 3;
                    break;
                }
            }
            i += 1;
        }
    }

    let hdr_block = &raw[..hdr_end];
    let body = &raw[body_start..];
    let mut headers: HashMap<String, Vec<u8>> = HashMap::new();
    let mut cur_key = String::new();
    let mut cur_val: Vec<u8> = Vec::new();

    let flush = |headers: &mut HashMap<String, Vec<u8>>,
                 cur_key: &mut String,
                 cur_val: &mut Vec<u8>| {
        if !cur_key.is_empty() {
            let k = cur_key.to_ascii_lowercase();
            let v = std::mem::take(cur_val);
            if matches!(k.as_str(), "to" | "cc") {
                if let Some(existing) = headers.get_mut(&k) {
                    if !existing.is_empty() && !v.is_empty() {
                        existing.extend_from_slice(b", ");
                    }
                    existing.extend_from_slice(&v);
                } else {
                    headers.insert(k, v);
                }
            } else {
                headers.insert(k, v);
            }
            cur_key.clear();
        }
    };

    let mut pos = 0;
    while pos < hdr_block.len() {
        let nl_rel = hdr_block[pos..].iter().position(|&b| b == b'\n');
        let lend = nl_rel.map(|r| pos + r).unwrap_or(hdr_block.len());
        let mut line = &hdr_block[pos..lend];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        if !line.is_empty() && (line[0] == b' ' || line[0] == b'\t') {
            if !cur_key.is_empty() {
                cur_val.push(b'\n');
                cur_val.extend_from_slice(line);
            }
        } else if let Some(col) = line.iter().position(|&b| b == b':') {
            flush(&mut headers, &mut cur_key, &mut cur_val);
            cur_key = sanitize_utf8(trim_ascii_ws_bytes(&line[..col]));
            cur_val = trim_ascii_ws_bytes(&line[col + 1..]).to_vec();
        }
        if nl_rel.is_none() {
            break;
        }
        pos = lend + 1;
    }
    flush(&mut headers, &mut cur_key, &mut cur_val);
    (headers, body)
}

#[derive(Debug, Clone)]
pub struct MimeInlineAtt {
    pub filename: String,
    pub mime_type: String,
    pub is_inline: bool,
    pub bytes: Vec<u8>,
}

pub fn collect_mime_parts(
    raw: &[u8],
    best_plain: &mut String,
    best_html: &mut String,
    mut opt_atts: Option<&mut Vec<MimeInlineAtt>>,
    depth: usize,
) {
    if depth > MAX_MIME_DEPTH || raw.is_empty() {
        return;
    }
    let (hdrs, body) = split_mime_headers_body(raw);

    let mut ct = "text/plain".to_string();
    let mut charset = "UTF-8".to_string();
    let mut boundary = String::new();
    let mut ct_name = String::new();
    if let Some(raw_ct) = hdrs.get("content-type") {
        let unfolded = decode_rfc2047_header(raw_ct);
        let head = unfolded.split(';').next().unwrap_or(&unfolded);
        ct = trim_ascii_ws(head).to_ascii_lowercase();
        let pcs = extract_header_param(&unfolded, "charset");
        if !pcs.is_empty() {
            charset = pcs;
        }
        boundary = extract_header_param(&unfolded, "boundary");
        ct_name = decode_rfc2231_param(&unfolded, "name");
    }

    if ct.starts_with("multipart/") && !boundary.is_empty() {
        let delim = format!("--{boundary}");
        let delim_b = delim.as_bytes();
        let nl_delim = format!("\n--{boundary}");
        let nl_delim_b = nl_delim.as_bytes();

        let mut pos_opt = body.windows(delim_b.len()).position(|w| w == delim_b);
        while let Some(pos) = pos_opt {
            let after = pos + delim_b.len();
            if after + 2 <= body.len() && &body[after..after + 2] == b"--" {
                break;
            }
            let Some(nl_rel) = body[after..].iter().position(|&b| b == b'\n') else {
                break;
            };
            let part_start = after + nl_rel + 1;
            if part_start >= body.len() {
                break;
            }
            let next_b = if let Some(rel) = body[part_start..]
                .windows(nl_delim_b.len())
                .position(|w| w == nl_delim_b)
            {
                let mut nb = part_start + rel;
                if nb > part_start && body[nb - 1] == b'\r' {
                    nb -= 1;
                }
                Some(nb)
            } else {
                body[part_start..]
                    .windows(delim_b.len())
                    .position(|w| w == delim_b)
                    .map(|r| part_start + r)
            };
            let part_end = next_b.unwrap_or(body.len());
            if part_end > part_start {
                collect_mime_parts(
                    &body[part_start..part_end],
                    best_plain,
                    best_html,
                    opt_atts.as_deref_mut(),
                    depth + 1,
                );
            }
            pos_opt = next_b.and_then(|nb| {
                let search_from = nb.max(part_start);
                body[search_from..]
                    .windows(delim_b.len())
                    .position(|w| w == delim_b)
                    .map(|r| search_from + r)
            });
        }
        return;
    }

    let mut disp = String::new();
    let mut disp_fn = String::new();
    if let Some(raw_cd) = hdrs.get("content-disposition") {
        let unfolded = decode_rfc2047_header(raw_cd);
        disp = unfolded.to_ascii_lowercase();
        disp_fn = decode_rfc2231_param(&unfolded, "filename");
    }
    let fn_name = if !disp_fn.is_empty() { disp_fn } else { ct_name };
    let is_att = !fn_name.is_empty() || disp.starts_with("attachment");

    let cte = hdrs
        .get("content-transfer-encoding")
        .map(|v| sanitize_utf8(trim_ascii_ws_bytes(v)).to_ascii_lowercase())
        .unwrap_or_default();

    if (ct == "text/plain" || ct == "text/html") && !disp.starts_with("attachment") {
        let mut decoded = match cte.as_str() {
            "base64" => {
                let lim = (MAX_MIME_PART_OUT / 3 * 4 + 4).min(body.len());
                base64_decode(&body[..lim])
            }
            "quoted-printable" => {
                let lim = (MAX_MIME_PART_OUT * 3).min(body.len());
                qp_decode(&body[..lim], false)
            }
            _ => {
                let lim = MAX_MIME_PART_OUT.min(body.len());
                body[..lim].to_vec()
            }
        };
        if decoded.len() > MAX_MIME_PART_OUT {
            decoded.truncate(MAX_MIME_PART_OUT);
        }
        let utf8 = decode_charset_bytes(&decoded, charset.as_bytes());
        if ct == "text/plain" && utf8.len() > best_plain.len() {
            *best_plain = utf8;
        } else if ct == "text/html" && utf8.len() > best_html.len() {
            *best_html = utf8;
        }
        return;
    }

    if let Some(atts) = opt_atts {
        if is_att && !fn_name.is_empty() {
            let is_inline = disp.starts_with("inline") || hdrs.contains_key("content-id");
            let bytes = if cte == "base64" && body.len() <= 22 * 1024 * 1024 {
                base64_decode(body)
            } else if cte == "quoted-printable" && body.len() <= 16 * 1024 * 1024 {
                qp_decode(body, false)
            } else if body.len() <= 16 * 1024 * 1024 {
                body.to_vec()
            } else {
                Vec::new()
            };
            atts.push(MimeInlineAtt {
                filename: fn_name,
                mime_type: ct,
                is_inline,
                bytes,
            });
        }
    }
}

pub fn slice_emlx_rfc822(raw: &[u8]) -> &[u8] {
    if let Some(nl) = raw.iter().position(|&b| b == b'\n') {
        if nl < 24 {
            let l1 = trim_ascii_ws_bytes(&raw[..nl]);
            if !l1.is_empty() && l1.iter().all(|b| b.is_ascii_digit()) {
                if let Ok(s) = std::str::from_utf8(l1) {
                    if let Ok(byte_cnt) = s.parse::<usize>() {
                        let start = nl + 1;
                        if start < raw.len()
                            && byte_cnt > 0
                            && start.saturating_add(byte_cnt) <= raw.len()
                        {
                            return &raw[start..start + byte_cnt];
                        }
                        if start < raw.len() {
                            let pat = b"\n<?xml version=";
                            if let Some(pl_rel) =
                                raw[start..].windows(pat.len()).position(|w| w == pat)
                            {
                                return &raw[start..start + pl_rel];
                            }
                            return &raw[start..];
                        }
                    }
                }
            }
        }
    }
    raw
}

fn parse_month_name(m: &str) -> Option<u32> {
    let lo = m.chars().take(3).collect::<String>().to_ascii_lowercase();
    match lo.as_str() {
        "jan" => Some(1),
        "feb" => Some(2),
        "mar" => Some(3),
        "apr" => Some(4),
        "may" => Some(5),
        "jun" => Some(6),
        "jul" => Some(7),
        "aug" => Some(8),
        "sep" => Some(9),
        "oct" => Some(10),
        "nov" => Some(11),
        "dec" => Some(12),
        _ => None,
    }
}

fn parse_iso8601_date(cleaned: &str) -> String {
    let b = cleaned.as_bytes();
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return String::new();
    }
    let Ok(year) = cleaned[0..4].parse::<i32>() else {
        return String::new();
    };
    let Ok(mon) = cleaned[5..7].parse::<u32>() else {
        return String::new();
    };
    let Ok(day) = cleaned[8..10].parse::<u32>() else {
        return String::new();
    };
    if !(1970..=2100).contains(&year) || !(1..=12).contains(&mon) || !(1..=31).contains(&day) {
        return String::new();
    }
    if b.len() >= 19 && (b[10] == b'T' || b[10] == b' ') && b[13] == b':' && b[16] == b':' {
        if let (Ok(hh), Ok(mm), Ok(ss)) = (
            cleaned[11..13].parse::<u32>(),
            cleaned[14..16].parse::<u32>(),
            cleaned[17..19].parse::<u32>(),
        ) {
            if hh <= 23 && mm <= 59 && ss <= 60 {
                let tz_part = cleaned[19..].trim();
                let mut tz_off = 0i64;
                if !tz_part.is_empty() && tz_part != "Z" && tz_part != "z" {
                    let tb = tz_part.as_bytes();
                    if (tb[0] == b'+' || tb[0] == b'-') && tb.len() >= 5 {
                        let digits: String = tz_part[1..]
                            .chars()
                            .filter(|c| c.is_ascii_digit())
                            .take(4)
                            .collect();
                        if digits.len() == 4 {
                            if let (Ok(h), Ok(m)) =
                                (digits[0..2].parse::<i64>(), digits[2..4].parse::<i64>())
                            {
                                tz_off =
                                    (h * 3600 + m * 60) * if tb[0] == b'-' { -1 } else { 1 };
                            }
                        }
                    }
                    if let Some(unix_utc) = parts_to_unix_secs(year, mon, day, hh, mm, ss, tz_off)
                    {
                        return format_local_datetime(unix_utc);
                    }
                } else if tz_part == "Z" || tz_part == "z" {
                    if let Some(unix_utc) = parts_to_unix_secs(year, mon, day, hh, mm, ss, 0) {
                        return format_local_datetime(unix_utc);
                    }
                }
                return format!("{year:04}-{mon:02}-{day:02} {hh:02}:{mm:02}:{ss:02}");
            }
        }
    }
    format!("{year:04}-{mon:02}-{day:02} 00:00:00")
}

pub fn parse_rfc5322_date(s: &str) -> String {
    let cleaned = collapse_ws(s);
    if cleaned.is_empty() {
        return String::new();
    }
    if cleaned.len() >= 10 && cleaned.as_bytes()[4] == b'-' && cleaned.as_bytes()[7] == b'-' {
        let iso = parse_iso8601_date(&cleaned);
        if !iso.is_empty() {
            return iso;
        }
    }

    let sv = match cleaned.find(',') {
        Some(comma) if comma < 10 => cleaned[comma + 1..].trim_start(),
        _ => cleaned.as_str(),
    };
    let mut parts = sv.split_whitespace();
    let (Some(day_s), Some(mon_s), Some(year_s), Some(time_s)) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return String::new();
    };
    let tz_str = parts.next().unwrap_or("");
    let Ok(day) = day_s.parse::<u32>() else {
        return String::new();
    };
    let Some(mon) = parse_month_name(mon_s) else {
        return String::new();
    };
    let Ok(mut year) = year_s.parse::<i32>() else {
        return String::new();
    };
    if year < 100 {
        year += if year >= 70 { 1900 } else { 2000 };
    }
    if !(1970..=2100).contains(&year) || !(1..=31).contains(&day) {
        return String::new();
    }
    let mut tparts = time_s.split(':');
    let (Some(hs), Some(ms)) = (tparts.next(), tparts.next()) else {
        return String::new();
    };
    let (Ok(hh), Ok(mm)) = (hs.parse::<u32>(), ms.parse::<u32>()) else {
        return String::new();
    };
    let ss = tparts.next().and_then(|x| x.parse::<u32>().ok()).unwrap_or(0);
    if hh > 23 || mm > 59 || ss > 60 {
        return String::new();
    }

    let mut tz_off: i64 = 0;
    let tb = tz_str.as_bytes();
    if tb.len() == 5
        && (tb[0] == b'+' || tb[0] == b'-')
        && tb[1..].iter().all(|b| b.is_ascii_digit())
    {
        if let (Ok(tzh), Ok(tzm)) = (tz_str[1..3].parse::<i64>(), tz_str[3..5].parse::<i64>()) {
            tz_off = (tzh * 3600 + tzm * 60) * if tb[0] == b'-' { -1 } else { 1 };
        }
    } else {
        tz_off = match tz_str.to_ascii_uppercase().as_str() {
            "UTC" | "GMT" | "Z" | "UT" => 0,
            "EST" | "CDT" => -5 * 3600,
            "EDT" => -4 * 3600,
            "CST" => {
                // Ambiguous CST: China Standard Time (+8) vs US Central (-6). Preserve +8 parity.
                8 * 3600
            }
            "MDT" => -6 * 3600,
            "MST" | "PDT" => -7 * 3600,
            "PST" => -8 * 3600,
            "CET" => 3600,
            "CEST" => 2 * 3600,
            "IST" => 5 * 3600 + 1800,
            "HKT" | "SGT" => 8 * 3600,
            "JST" | "KST" => 9 * 3600,
            _ => 0,
        };
    }

    let Some(unix_utc) = parts_to_unix_secs(year, mon, day, hh, mm, ss, tz_off) else {
        return String::new();
    };
    format_local_datetime(unix_utc)
}

pub fn find_reply_split_offset(text: &str) -> Option<usize> {
    let mut best: Option<usize> = None;
    let consider = |best: &mut Option<usize>, pos: usize| {
        if best.is_none_or(|b| pos < b) {
            *best = Some(pos);
        }
    };

    for marker in [
        "-----Original Message-----",
        "-----原始邮件-----",
        "-----邮件原件-----",
        "--- Original Message ---",
        "---------- Forwarded message ---------",
        "Begin forwarded message:",
    ] {
        if let Some(p) = find_ci(text, marker, 0) {
            consider(&mut best, p);
        }
    }

    let mut check_hdr_pair = |h1: &str, h2s: &[&str], ci: bool| {
        let mut pos = 0;
        let bytes = text.as_bytes();
        while pos < text.len() {
            let hit_opt = if ci {
                find_ci(text, h1, pos)
            } else {
                text[pos..].find(h1).map(|r| pos + r)
            };
            let Some(hit) = hit_opt else {
                break;
            };
            let left_ok = hit == 0 || is_ascii_ws_byte(bytes[hit - 1]);
            if left_ok {
                let mut j = hit + h1.len();
                while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                    j += 1;
                }
                let colon =
                    (j < bytes.len() && bytes[j] == b':') || text[j..].starts_with('：');
                if colon {
                    let win = safe_slice_after(text, j, 400);
                    for &h2 in h2s {
                        let p2_opt = if ci { find_ci(win, h2, 0) } else { win.find(h2) };
                        if let Some(p2) = p2_opt {
                            let mut k = p2 + h2.len();
                            let wb = win.as_bytes();
                            while k < wb.len() && (wb[k] == b' ' || wb[k] == b'\t') {
                                k += 1;
                            }
                            if (k < wb.len() && wb[k] == b':') || win[k..].starts_with('：') {
                                consider(&mut best, hit);
                                return;
                            }
                        }
                    }
                }
            }
            pos = hit + h1.len();
        }
    };

    check_hdr_pair("From", &["Date", "Sent"], true);
    check_hdr_pair("发件人", &["发送时间", "日期"], false);
    check_hdr_pair("發件人", &["傳送時間", "日期"], false);
    check_hdr_pair("寄件者", &["日期", "傳送時間", "時間"], false);

    let mut pos = 0;
    while pos < text.len() {
        let nl = text[pos..].find('\n').map(|r| pos + r);
        let lend = nl.unwrap_or(text.len());
        let line = &text[pos..lend];
        if line.len() >= 10
            && line.len() <= 220
            && (line.starts_with("On ") || line.starts_with("在 "))
        {
            let span = safe_slice_after(text, pos, 240);
            if (span.contains("wrote:")
                || span.contains("写道：")
                || span.contains("写道:")
                || span.contains("寫道："))
                && span.bytes().any(|b| b.is_ascii_digit())
            {
                consider(&mut best, pos);
                if best == Some(pos) {
                    break;
                }
            }
        }
        let Some(nl_idx) = nl else {
            break;
        };
        pos = nl_idx + 1;
    }

    best
}

pub fn norm_uid_from_fields(
    mid: &str,
    date_iso: &str,
    sender: &str,
    subject: &str,
    body_hint: &str,
) -> String {
    let trimmed = trim_ascii_ws(mid).trim_matches(|c| c == '<' || c == '>');
    if !trimmed.is_empty() {
        return trimmed.to_ascii_lowercase();
    }
    let hint = utf8_trunc_sv(body_hint, 500);
    let raw = format!("{date_iso}|{sender}|{subject}|{hint}");
    format!("h:{}", sha256_bytes(raw.as_bytes()))
}

pub fn format_header_address_from_env(addr: &str, comment: &str) -> String {
    let cmt = trim_ascii_ws(comment);
    let adr = trim_ascii_ws(addr);
    if !cmt.is_empty() && !adr.is_empty() && cmt != adr {
        format!("{cmt} <{adr}>")
    } else if !adr.is_empty() {
        adr.to_string()
    } else {
        cmt.to_string()
    }
}

pub fn extract_header_str(hdrs: &HashMap<String, Vec<u8>>, key: &str) -> String {
    hdrs.get(key)
        .map(|v| decode_rfc2047_header(v))
        .unwrap_or_default()
}

pub fn starts_with_ci_ascii(s: &str, pat: &str) -> bool {
    starts_with_ci(s, 0, pat)
}

pub fn starts_with_ci_slice(b: &[u8], pat: &[u8]) -> bool {
    starts_with_ci_bytes(b, 0, pat)
}

pub fn find_ci_in_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    find_ci_bytes(hay, needle, 0)
}
