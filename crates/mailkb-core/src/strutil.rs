//! Shared panic-free ASCII case-insensitive matching and UTF-8 boundary helpers.

#[inline]
pub fn is_ascii_ws_byte(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | 0x0B | 0x0C)
}

#[inline]
pub fn is_ascii_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

#[inline]
pub fn trim_ascii_ws_bytes(mut b: &[u8]) -> &[u8] {
    while let Some(&first) = b.first() {
        if is_ascii_ws_byte(first) {
            b = &b[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = b.last() {
        if is_ascii_ws_byte(last) {
            b = &b[..b.len() - 1];
        } else {
            break;
        }
    }
    b
}

#[inline]
pub fn trim_ascii_ws(s: &str) -> &str {
    let trimmed = trim_ascii_ws_bytes(s.as_bytes());
    // SAFETY: stripping only ASCII whitespace bytes preserves UTF-8 validity.
    unsafe { std::str::from_utf8_unchecked(trimmed) }
}

#[inline]
pub fn starts_with_ci_bytes(hay: &[u8], pos: usize, pat: &[u8]) -> bool {
    if pos.saturating_add(pat.len()) > hay.len() {
        return false;
    }
    hay[pos..pos + pat.len()].eq_ignore_ascii_case(pat)
}

#[inline]
pub fn find_ci_bytes(hay: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() {
        return (start <= hay.len()).then_some(start);
    }
    if hay.len() < needle.len() || start > hay.len() - needle.len() {
        return None;
    }
    let first = needle[0].to_ascii_lowercase();
    let end = hay.len() - needle.len();
    let mut i = start;
    while i <= end {
        if hay[i].to_ascii_lowercase() == first
            && hay[i..i + needle.len()].eq_ignore_ascii_case(needle)
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[inline]
pub fn starts_with_ci(s: &str, pos: usize, pat: &str) -> bool {
    starts_with_ci_bytes(s.as_bytes(), pos, pat.as_bytes())
}

#[inline]
pub fn find_ci(hay: &str, needle: &str, start: usize) -> Option<usize> {
    if needle.is_empty() {
        return (start <= hay.len() && hay.is_char_boundary(start)).then_some(start);
    }
    let hb = hay.as_bytes();
    let nb = needle.as_bytes();
    let mut i = start;
    while let Some(hit) = find_ci_bytes(hb, nb, i) {
        if hay.is_char_boundary(hit) && hay.is_char_boundary(hit + nb.len()) {
            return Some(hit);
        }
        i = hit + 1;
    }
    None
}

#[inline]
pub fn contains_ci(hay: &str, needle: &str) -> bool {
    find_ci(hay, needle, 0).is_some()
}

#[inline]
pub fn contains_any_ci(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| contains_ci(hay, n))
}

#[inline]
pub fn floor_char_boundary_idx(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

#[inline]
pub fn ceil_char_boundary_idx(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[inline]
pub fn utf8_trunc_sv(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        s
    } else {
        &s[..floor_char_boundary_idx(s, max_bytes)]
    }
}

#[inline]
pub fn utf8_char_len(s: &str) -> usize {
    s.chars().count()
}

#[inline]
pub fn utf8_slice_chars(s: &str, max_chars: usize) -> &str {
    if max_chars == 0 {
        return "";
    }
    match s.char_indices().nth(max_chars) {
        Some((idx, _)) => &s[..idx],
        None => s,
    }
}

#[inline]
pub fn safe_slice_before(s: &str, end: usize, max_bytes: usize) -> &str {
    let end = floor_char_boundary_idx(s, end);
    let start = ceil_char_boundary_idx(s, end.saturating_sub(max_bytes));
    if start <= end {
        &s[start..end]
    } else {
        ""
    }
}

#[inline]
pub fn safe_slice_after(s: &str, start: usize, max_bytes: usize) -> &str {
    let start = ceil_char_boundary_idx(s, start);
    let end = floor_char_boundary_idx(s, start.saturating_add(max_bytes));
    if start <= end {
        &s[start..end]
    } else {
        ""
    }
}

#[inline]
pub fn prev_char(s: &str, pos: usize) -> Option<(usize, char)> {
    s[..pos].char_indices().next_back()
}

#[inline]
pub fn next_char(s: &str, pos: usize) -> Option<(usize, char)> {
    let ch = s[pos..].chars().next()?;
    Some((pos + ch.len_utf8(), ch))
}
