//! Safe FTS5 query builders, CJK unigram/bigram tokenizer, LIKE escaping, and key normalization.

use crate::security::sanitize_utf8;

pub const MAX_FTS_KEYWORDS: usize = 32;
pub const MAX_FTS_TOKEN_BYTES: usize = 128;
pub const MAX_FTS_CJK_RUN: usize = 32;
pub const MAX_FTS_EXPR_BYTES: usize = 4096;

/// Returns `true` if `ch` falls within the unified CJK Han Ideograph ranges.
#[inline]
pub fn is_cjk(ch: char) -> bool {
    let cp = ch as u32;
    (0x4E00..=0x9FFF).contains(&cp)
        || (0x3400..=0x4DBF).contains(&cp)
        || (0xF900..=0xFAFF).contains(&cp)
        || (0x20000..=0x2A6DF).contains(&cp)
}

/// Escapes SQL `LIKE` wildcards (`\`, `%`, `_`) for use with `ESCAPE '\'`.
pub fn like_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for ch in s.chars() {
        if ch == '\\' || ch == '%' || ch == '_' {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Strips non-alphanumeric / non-CJK characters and uppercases ASCII for hyphen-insensitive key matching.
pub fn normalize_model_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        if ch.is_ascii_alphanumeric() || is_cjk(ch) {
            out.push(ch.to_ascii_uppercase());
        }
    }
    out
}

/// Truncates `s` to at most `max_bytes` along a valid UTF-8 character boundary.
pub fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> (&str, bool) {
    if s.len() <= max_bytes {
        return (s, false);
    }
    let mut cut = max_bytes;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    (&s[..cut], true)
}

fn quote_fts_literal(tok: &str) -> String {
    let mut out = String::with_capacity(tok.len() + 2);
    out.push('"');
    for ch in tok.chars() {
        if ch == '"' {
            out.push_str("\"\"");
        } else {
            out.push(ch);
        }
    }
    out.push('"');
    out
}

#[inline]
fn is_ascii_u61_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-')
}

#[inline]
fn is_mail_ascii_run_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '/')
}

/// Builds a safe FTS5 `unicode61` query expression respecting S12 bounds.
pub fn build_unicode61_fts_query<S: AsRef<str>>(keywords: &[S]) -> (String, bool) {
    let mut truncated = false;
    let mut tokens: Vec<String> = Vec::new();

    for kw_ref in keywords {
        let kw = kw_ref.as_ref();
        if kw.trim().is_empty() {
            continue;
        }
        if tokens.len() >= MAX_FTS_KEYWORDS {
            truncated = true;
            break;
        }

        let chars: Vec<(usize, char)> = kw.char_indices().collect();
        let mut idx = 0;
        while idx < chars.len() {
            if tokens.len() >= MAX_FTS_KEYWORDS {
                truncated = true;
                break;
            }
            let (start_byte, ch) = chars[idx];
            if is_ascii_u61_char(ch) {
                idx += 1;
                while idx < chars.len() && is_ascii_u61_char(chars[idx].1) {
                    idx += 1;
                }
                let end_byte = if idx < chars.len() {
                    chars[idx].0
                } else {
                    kw.len()
                };
                let clean = kw[start_byte..end_byte]
                    .trim_matches(|c| c == '-' || c == '_' || c == '.');
                if !clean.is_empty() {
                    let (cut, was_cut) = truncate_utf8_bytes(clean, MAX_FTS_TOKEN_BYTES);
                    if was_cut {
                        truncated = true;
                    }
                    if !cut.is_empty() {
                        tokens.push(quote_fts_literal(cut));
                    }
                }
            } else if is_cjk(ch) {
                let mut cjk_count = 1;
                idx += 1;
                while idx < chars.len() && is_cjk(chars[idx].1) {
                    cjk_count += 1;
                    idx += 1;
                }
                let end_byte = if idx < chars.len() {
                    chars[idx].0
                } else {
                    kw.len()
                };
                let mut slice = &kw[start_byte..end_byte];
                if cjk_count > MAX_FTS_CJK_RUN {
                    if let Some((b_end, _)) = slice.char_indices().nth(MAX_FTS_CJK_RUN) {
                        slice = &slice[..b_end];
                    }
                    truncated = true;
                }
                let (cut, was_cut) = truncate_utf8_bytes(slice, MAX_FTS_TOKEN_BYTES);
                if was_cut {
                    truncated = true;
                }
                if !cut.is_empty() {
                    tokens.push(quote_fts_literal(cut));
                }
            } else {
                idx += 1;
            }
        }
    }

    while !tokens.is_empty() {
        let expr = tokens.join(" AND ");
        if expr.len() <= MAX_FTS_EXPR_BYTES {
            return (expr, truncated);
        }
        tokens.pop();
        truncated = true;
    }
    (String::new(), truncated)
}

/// Tokenizes arbitrary text into space-separated CJK unigrams + bigrams and lowercased
/// ASCII / hyphen-joined tokens for `unicode61` FTS5 indexing.
pub fn tokenize_for_fts(text: &str) -> String {
    let clean = sanitize_utf8(text.as_bytes());
    let mut out = String::with_capacity(clean.len() * 2 + 16);
    let mut cjk_run: Vec<char> = Vec::new();
    let mut ascii_run = String::new();

    let flush_cjk = |cjk_run: &mut Vec<char>, out: &mut String| {
        if cjk_run.is_empty() {
            return;
        }
        for &ch in cjk_run.iter() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push(ch);
        }
        for pair in cjk_run.windows(2) {
            out.push(' ');
            out.push(pair[0]);
            out.push(pair[1]);
        }
        cjk_run.clear();
    };

    let flush_ascii = |ascii_run: &mut String, out: &mut String| {
        if ascii_run.is_empty() {
            return;
        }
        let mut parts: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut joined = String::new();
        for ch in ascii_run.chars() {
            if ch.is_ascii_alphanumeric() {
                let lo = ch.to_ascii_lowercase();
                cur.push(lo);
                if joined.len() < 40 {
                    joined.push(lo);
                }
            } else if !cur.is_empty() {
                parts.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            parts.push(cur);
        }
        if !parts.is_empty() {
            for p in &parts {
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(p);
            }
            if parts.len() > 1 && (3..=32).contains(&joined.len()) {
                out.push(' ');
                out.push_str(&joined);
            }
        }
        ascii_run.clear();
    };

    for ch in clean.chars() {
        if is_cjk(ch) {
            flush_ascii(&mut ascii_run, &mut out);
            cjk_run.push(ch);
        } else if is_mail_ascii_run_char(ch) {
            flush_cjk(&mut cjk_run, &mut out);
            ascii_run.push(ch);
        } else {
            flush_cjk(&mut cjk_run, &mut out);
            flush_ascii(&mut ascii_run, &mut out);
        }
    }
    flush_cjk(&mut cjk_run, &mut out);
    flush_ascii(&mut ascii_run, &mut out);
    out
}

fn term_to_fts_clause(term: &str, truncated: &mut bool) -> String {
    let owned_clean = sanitize_utf8(term.as_bytes());
    let (clean, was_cut) = truncate_utf8_bytes(&owned_clean, MAX_FTS_TOKEN_BYTES);
    if was_cut {
        *truncated = true;
    }

    let mut clauses: Vec<String> = Vec::new();
    let mut cjk_run: Vec<char> = Vec::new();
    let mut ascii_run = String::new();

    let flush_cjk = |cjk_run: &mut Vec<char>, clauses: &mut Vec<String>, truncated: &mut bool| {
        if cjk_run.is_empty() {
            return;
        }
        if cjk_run.len() > MAX_FTS_CJK_RUN {
            cjk_run.truncate(MAX_FTS_CJK_RUN);
            *truncated = true;
        }
        if cjk_run.len() == 1 {
            let mut s = String::with_capacity(4);
            s.push(cjk_run[0]);
            clauses.push(quote_fts_literal(&s));
        } else {
            let mut sub = String::new();
            for (k, pair) in cjk_run.windows(2).enumerate() {
                if k > 0 {
                    sub.push_str(" AND ");
                }
                let mut bg = String::with_capacity(8);
                bg.push(pair[0]);
                bg.push(pair[1]);
                sub.push_str(&quote_fts_literal(&bg));
            }
            if cjk_run.len() > 2 {
                clauses.push(format!("({sub})"));
            } else {
                clauses.push(sub);
            }
        }
        cjk_run.clear();
    };

    let flush_ascii = |ascii_run: &mut String, clauses: &mut Vec<String>| {
        if ascii_run.is_empty() {
            return;
        }
        let mut parts: Vec<String> = Vec::new();
        let mut cur = String::new();
        let mut joined = String::new();
        for ch in ascii_run.chars() {
            if ch.is_ascii_alphanumeric() {
                let lo = ch.to_ascii_lowercase();
                cur.push(lo);
                if joined.len() < 40 {
                    joined.push(lo);
                }
            } else if !cur.is_empty() {
                parts.push(std::mem::take(&mut cur));
            }
        }
        if !cur.is_empty() {
            parts.push(cur);
        }
        if parts.len() == 1 {
            clauses.push(quote_fts_literal(&parts[0]));
        } else if parts.len() > 1 {
            let phrase = parts.join(" ");
            if (3..=32).contains(&joined.len()) {
                clauses.push(format!(
                    "({} OR {})",
                    quote_fts_literal(&phrase),
                    quote_fts_literal(&joined)
                ));
            } else {
                clauses.push(quote_fts_literal(&phrase));
            }
        }
        ascii_run.clear();
    };

    for ch in clean.chars() {
        if is_cjk(ch) {
            flush_ascii(&mut ascii_run, &mut clauses);
            cjk_run.push(ch);
        } else if is_mail_ascii_run_char(ch) {
            flush_cjk(&mut cjk_run, &mut clauses, truncated);
            ascii_run.push(ch);
        } else {
            flush_cjk(&mut cjk_run, &mut clauses, truncated);
            flush_ascii(&mut ascii_run, &mut clauses);
        }
    }
    flush_cjk(&mut cjk_run, &mut clauses, truncated);
    flush_ascii(&mut ascii_run, &mut clauses);

    match clauses.len() {
        0 => String::new(),
        1 => clauses.into_iter().next().unwrap_or_default(),
        _ => format!("({})", clauses.join(" AND ")),
    }
}

/// Builds a safe FTS5 query expression for pre-tokenized CJK-bigram indexes.
pub fn build_cjk_bigram_fts_query<S: AsRef<str>>(keywords: &[S]) -> (String, bool) {
    let mut trunc = false;
    let mut words: Vec<String> = Vec::new();

    for kw in keywords {
        for w in kw.as_ref().split_whitespace() {
            if words.len() >= MAX_FTS_KEYWORDS {
                trunc = true;
                break;
            }
            let (cut, was_cut) = truncate_utf8_bytes(w, MAX_FTS_TOKEN_BYTES);
            if was_cut {
                trunc = true;
            }
            words.push(cut.to_string());
        }
        if words.len() >= MAX_FTS_KEYWORDS {
            break;
        }
    }

    if words.is_empty() {
        return (String::new(), trunc);
    }

    enum Item {
        Op(&'static str),
        Clause(String),
    }

    let mut items: Vec<Item> = Vec::new();
    for w in &words {
        if w == "OR" || w == "AND" {
            let can_op = matches!(items.last(), Some(Item::Clause(_)));
            if can_op {
                items.push(Item::Op(if w == "OR" { "OR" } else { "AND" }));
            }
        } else {
            let c = term_to_fts_clause(w, &mut trunc);
            if !c.is_empty() {
                items.push(Item::Clause(c));
            }
        }
    }

    while matches!(items.last(), Some(Item::Op(_))) {
        items.pop();
    }
    if items.is_empty() {
        return (String::new(), trunc);
    }

    let mut out = String::new();
    let mut need_op = false;
    for it in items {
        let next_piece = match it {
            Item::Op(op) => {
                need_op = false;
                format!(" {op} ")
            }
            Item::Clause(c) => {
                let piece = if need_op {
                    format!(" AND {c}")
                } else {
                    c
                };
                need_op = true;
                piece
            }
        };
        if out.len() + next_piece.len() > MAX_FTS_EXPR_BYTES {
            trunc = true;
            break;
        }
        out.push_str(&next_piece);
    }

    if out.ends_with(" AND ") {
        out.truncate(out.len() - 5);
    } else if out.ends_with(" OR ") {
        out.truncate(out.len() - 4);
    }

    (out, trunc)
}
