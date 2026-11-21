//! ReDoS-safe `MiniRegex` engine supporting ASCII `\b`, character classes,
//! bounded repetition, and lookarounds (`(?<!...)`, `(?!...)`, `(?=[...])`),
//! with both boolean search and span extraction.

use crate::strutil::{find_ci, is_ascii_word_byte, next_char, prev_char, starts_with_ci};

#[inline]
fn is_regex_ws_char(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '\t' | '\r' | '\n' | '\x0C' | '\x0B' | '\u{00A0}' | '\u{3000}'
    )
}

#[derive(Debug, Clone, Default)]
struct CharClass {
    negated: bool,
    include_ws: bool,
    include_digit: bool,
    ranges: Vec<(u32, u32)>,
}

impl CharClass {
    fn matches(&self, ch: char) -> bool {
        let cp = ch as u32;
        if cp == 0 {
            return false;
        }
        let mut hit = false;
        if self.include_ws && is_regex_ws_char(ch) {
            hit = true;
        }
        if !hit && self.include_digit && ch.is_ascii_digit() {
            hit = true;
        }
        if !hit {
            let cl = if (b'A' as u32..=b'Z' as u32).contains(&cp) {
                cp + 32
            } else {
                cp
            };
            for &(lo, hi) in &self.ranges {
                if (cp >= lo && cp <= hi) || (cl >= lo && cl <= hi) {
                    hit = true;
                    break;
                }
            }
        }
        if self.negated {
            !hit
        } else {
            hit
        }
    }
}

#[derive(Debug, Clone)]
enum AtomKind {
    Literal(String),
    Dot,
    Ws,
    Digit,
    CClass(CharClass),
    WordBound,
    NegLookBehind(CharClass),
    NegLookAheadCc(CharClass),
    NegLookAheadLit(String),
    PosLookAhead(CharClass),
    Group(Vec<Vec<Atom>>),
}

#[derive(Debug, Clone)]
struct Atom {
    kind: AtomKind,
    min_rep: u16,
    max_rep: u16,
    lazy: bool,
}

impl Atom {
    fn single(kind: AtomKind) -> Self {
        Self {
            kind,
            min_rep: 1,
            max_rep: 1,
            lazy: false,
        }
    }
}

#[derive(Debug, Clone)]
enum FastKind {
    None,
    Literal(String),
    BoundedWord(String),
}

/// Safe, linear/bounded-backtracking regex engine supporting lookarounds (`(?<!...)`, `(?!...)`, `(?=[...])`).
#[derive(Debug, Clone)]
pub struct MiniRegex {
    alts: Vec<Vec<Atom>>,
    fast_kind: FastKind,
}

impl MiniRegex {
    pub fn compile(pat: &str) -> Option<Self> {
        if pat.is_empty() {
            return None;
        }
        let mut pos = 0;
        let alts = parse_alts(pat, &mut pos, false)?;
        if pos != pat.len() {
            return None;
        }
        let fast_kind = detect_fast_path(&alts);
        Some(Self { alts, fast_kind })
    }

    pub fn search(&self, text: &str) -> bool {
        if text.is_empty() {
            return false;
        }
        match &self.fast_kind {
            FastKind::Literal(lit) => find_ci(text, lit, 0).is_some(),
            FastKind::BoundedWord(lit) => {
                let bytes = text.as_bytes();
                let mut pos = 0;
                while let Some(hit) = find_ci(text, lit, pos) {
                    let left_ok = hit == 0 || !is_ascii_word_byte(bytes[hit - 1]);
                    let end = hit + lit.len();
                    let right_ok = end == bytes.len() || !is_ascii_word_byte(bytes[end]);
                    if left_ok && right_ok {
                        return true;
                    }
                    pos = hit + 1;
                }
                false
            }
            FastKind::None => {
                if self.alts.is_empty() {
                    return false;
                }
                for (idx, _) in text.char_indices() {
                    if match_alts_at(text, idx, &self.alts) {
                        return true;
                    }
                }
                match_alts_at(text, text.len(), &self.alts)
            }
        }
    }

    /// Returns non-overlapping `(start_byte, end_byte)` match spans in left-to-right order.
    pub fn find_all(&self, text: &str) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        if text.is_empty() {
            return out;
        }
        match &self.fast_kind {
            FastKind::Literal(lit) => {
                let mut pos = 0;
                while let Some(hit) = find_ci(text, lit, pos) {
                    let end = hit + lit.len();
                    out.push((hit, end));
                    pos = end.max(pos + 1);
                }
            }
            FastKind::BoundedWord(lit) => {
                let bytes = text.as_bytes();
                let mut pos = 0;
                while let Some(hit) = find_ci(text, lit, pos) {
                    let left_ok = hit == 0 || !is_ascii_word_byte(bytes[hit - 1]);
                    let end = hit + lit.len();
                    let right_ok = end == bytes.len() || !is_ascii_word_byte(bytes[end]);
                    if left_ok && right_ok {
                        out.push((hit, end));
                        pos = end.max(pos + 1);
                    } else {
                        pos = hit + 1;
                    }
                }
            }
            FastKind::None => {
                let mut idx = 0;
                while idx < text.len() {
                    if let Some(end) = find_alts_end_at(text, idx, &self.alts) {
                        if end > idx {
                            out.push((idx, end));
                            idx = end;
                            continue;
                        }
                    }
                    let Some((next_idx, _)) = next_char(text, idx) else {
                        break;
                    };
                    idx = next_idx;
                }
            }
        }
        out
    }
}

fn detect_fast_path(alts: &[Vec<Atom>]) -> FastKind {
    if alts.len() != 1 {
        return FastKind::None;
    }
    let seq = &alts[0];
    if seq.len() == 1 && seq[0].min_rep == 1 && seq[0].max_rep == 1 {
        if let AtomKind::Literal(ref lit) = seq[0].kind {
            return FastKind::Literal(lit.clone());
        }
    }
    if seq.len() == 3
        && matches!(seq[0].kind, AtomKind::WordBound)
        && seq[1].min_rep == 1
        && seq[1].max_rep == 1
        && matches!(seq[2].kind, AtomKind::WordBound)
    {
        if let AtomKind::Literal(ref lit) = seq[1].kind {
            return FastKind::BoundedWord(lit.clone());
        }
    }
    FastKind::None
}

fn parse_char_class(pat: &str, pos: &mut usize) -> Option<CharClass> {
    if !pat[*pos..].starts_with('[') {
        return None;
    }
    *pos += 1;
    let mut cc = CharClass::default();
    if pat[*pos..].starts_with('^') {
        cc.negated = true;
        *pos += 1;
    }
    let mut first = true;
    let mut prev_cp: Option<u32> = None;

    while *pos < pat.len() {
        let rest = &pat[*pos..];
        if rest.starts_with(']') && !first {
            *pos += 1;
            return Some(cc);
        }
        first = false;
        if rest.starts_with('\\') && rest.len() >= 2 {
            let (next_pos, esc) = next_char(pat, *pos + 1)?;
            *pos = next_pos;
            if esc == 's' {
                cc.include_ws = true;
                prev_cp = None;
                continue;
            }
            if esc == 'd' {
                cc.include_digit = true;
                prev_cp = None;
                continue;
            }
            let cp = esc as u32;
            cc.ranges.push((cp, cp));
            prev_cp = Some(cp);
            continue;
        }
        if rest.starts_with('-')
            && prev_cp.is_some()
            && pat.len() > *pos + 1
            && !pat[*pos + 1..].starts_with(']')
        {
            *pos += 1;
            let end_cp = if pat[*pos..].starts_with('\\') && pat.len() > *pos + 1 {
                let (next_pos, esc) = next_char(pat, *pos + 1)?;
                *pos = next_pos;
                esc as u32
            } else {
                let (next_pos, ch) = next_char(pat, *pos)?;
                *pos = next_pos;
                ch as u32
            };
            if let (Some(pcp), Some(last)) = (prev_cp, cc.ranges.last_mut()) {
                if end_cp >= pcp {
                    last.1 = end_cp;
                }
            }
            prev_cp = None;
            continue;
        }
        let (next_pos, ch) = next_char(pat, *pos)?;
        *pos = next_pos;
        let cp = ch as u32;
        cc.ranges.push((cp, cp));
        prev_cp = Some(cp);
    }
    None
}

fn parse_quantifier(pat: &str, pos: &mut usize, atom: &mut Atom) {
    let Some(q) = pat.as_bytes().get(*pos).copied() else {
        return;
    };
    match q {
        b'?' => {
            atom.min_rep = 0;
            atom.max_rep = 1;
            *pos += 1;
        }
        b'*' => {
            atom.min_rep = 0;
            atom.max_rep = u16::MAX;
            *pos += 1;
        }
        b'+' => {
            atom.min_rep = 1;
            atom.max_rep = u16::MAX;
            *pos += 1;
        }
        b'{' => {
            let rest = &pat[*pos + 1..];
            if let Some(close_rel) = rest.find('}') {
                let inner = &rest[..close_rel];
                if let Some((a_s, b_s)) = inner.split_once(',') {
                    if let Ok(min_r) = a_s.trim().parse::<u16>() {
                        let max_r = if b_s.trim().is_empty() {
                            u16::MAX
                        } else if let Ok(v) = b_s.trim().parse::<u16>() {
                            v
                        } else {
                            return;
                        };
                        if max_r >= min_r {
                            atom.min_rep = min_r;
                            atom.max_rep = max_r;
                            *pos += close_rel + 2;
                        }
                    }
                } else if let Ok(exact_r) = inner.trim().parse::<u16>() {
                    atom.min_rep = exact_r;
                    atom.max_rep = exact_r;
                    *pos += close_rel + 2;
                }
            }
        }
        _ => return,
    }
    if pat.as_bytes().get(*pos).copied() == Some(b'?') {
        atom.lazy = true;
        *pos += 1;
    }
}

fn push_literal_atom(seq: &mut Vec<Atom>, atom: Atom) {
    if atom.min_rep == 1 && atom.max_rep == 1 {
        if let AtomKind::Literal(ref new_lit) = atom.kind {
            if let Some(last) = seq.last_mut() {
                if last.min_rep == 1 && last.max_rep == 1 {
                    if let AtomKind::Literal(ref mut old_lit) = last.kind {
                        old_lit.push_str(new_lit);
                        return;
                    }
                }
            }
        }
    }
    seq.push(atom);
}

fn parse_alts(pat: &str, pos: &mut usize, stop_paren: bool) -> Option<Vec<Vec<Atom>>> {
    let mut out_alts: Vec<Vec<Atom>> = vec![Vec::new()];
    while *pos < pat.len() {
        let ch = pat.as_bytes()[*pos];
        if stop_paren && ch == b')' {
            *pos += 1;
            return Some(out_alts);
        }
        if ch == b')' && !stop_paren {
            return None;
        }
        if ch == b'|' {
            out_alts.push(Vec::new());
            *pos += 1;
            continue;
        }
        let seq = out_alts.last_mut()?;
        if ch == b'(' {
            let rest = &pat[*pos..];
            if rest.starts_with("(?<!") {
                *pos += 4;
                let cc = parse_char_class(pat, pos)?;
                if !pat[*pos..].starts_with(')') {
                    return None;
                }
                *pos += 1;
                seq.push(Atom::single(AtomKind::NegLookBehind(cc)));
                continue;
            }
            if rest.starts_with("(?!") {
                *pos += 3;
                if pat[*pos..].starts_with('[') {
                    let cc = parse_char_class(pat, pos)?;
                    if !pat[*pos..].starts_with(')') {
                        return None;
                    }
                    *pos += 1;
                    seq.push(Atom::single(AtomKind::NegLookAheadCc(cc)));
                } else {
                    let start = *pos;
                    let rel_end = pat[start..].find(')')?;
                    let lit = pat[start..start + rel_end].to_string();
                    *pos = start + rel_end + 1;
                    seq.push(Atom::single(AtomKind::NegLookAheadLit(lit)));
                }
                continue;
            }
            if rest.starts_with("(?=") {
                *pos += 3;
                let cc = parse_char_class(pat, pos)?;
                if !pat[*pos..].starts_with(')') {
                    return None;
                }
                *pos += 1;
                seq.push(Atom::single(AtomKind::PosLookAhead(cc)));
                continue;
            }
            if rest.starts_with("(?:") {
                *pos += 3;
            } else {
                *pos += 1;
            }
            let sub_alts = parse_alts(pat, pos, true)?;
            let mut atom = Atom::single(AtomKind::Group(sub_alts));
            parse_quantifier(pat, pos, &mut atom);
            seq.push(atom);
            continue;
        }
        if ch == b'[' {
            let cc = parse_char_class(pat, pos)?;
            let mut atom = Atom::single(AtomKind::CClass(cc));
            parse_quantifier(pat, pos, &mut atom);
            seq.push(atom);
            continue;
        }
        if ch == b'.' {
            *pos += 1;
            let mut atom = Atom::single(AtomKind::Dot);
            parse_quantifier(pat, pos, &mut atom);
            seq.push(atom);
            continue;
        }
        if ch == b'\\' {
            if *pos + 1 >= pat.len() {
                return None;
            }
            let (next_pos, esc) = next_char(pat, *pos + 1)?;
            *pos = next_pos;
            match esc {
                'b' => seq.push(Atom::single(AtomKind::WordBound)),
                's' => {
                    let mut atom = Atom::single(AtomKind::Ws);
                    parse_quantifier(pat, pos, &mut atom);
                    seq.push(atom);
                }
                'd' => {
                    let mut atom = Atom::single(AtomKind::Digit);
                    parse_quantifier(pat, pos, &mut atom);
                    seq.push(atom);
                }
                _ => {
                    let mut s = String::new();
                    s.push(esc);
                    let mut atom = Atom::single(AtomKind::Literal(s));
                    parse_quantifier(pat, pos, &mut atom);
                    push_literal_atom(seq, atom);
                }
            }
            continue;
        }
        let (next_pos, literal_ch) = next_char(pat, *pos)?;
        *pos = next_pos;
        let mut s = String::new();
        s.push(literal_ch);
        let mut atom = Atom::single(AtomKind::Literal(s));
        parse_quantifier(pat, pos, &mut atom);
        push_literal_atom(seq, atom);
    }
    if stop_paren {
        None
    } else {
        Some(out_alts)
    }
}

fn match_alts_at(text: &str, pos: usize, alts: &[Vec<Atom>]) -> bool {
    alts.iter().any(|seq| match_seq_end(text, pos, seq, 0).is_some())
}

fn find_alts_end_at(text: &str, pos: usize, alts: &[Vec<Atom>]) -> Option<usize> {
    for seq in alts {
        if let Some(end) = match_seq_end(text, pos, seq, 0) {
            return Some(end);
        }
    }
    None
}

fn match_single_atom(
    text: &str,
    pos: usize,
    atom: &Atom,
    next_positions: &mut Vec<usize>,
) -> bool {
    next_positions.clear();
    let bytes = text.as_bytes();
    match &atom.kind {
        AtomKind::Literal(lit) => {
            if starts_with_ci(text, pos, lit) {
                next_positions.push(pos + lit.len());
                true
            } else {
                false
            }
        }
        AtomKind::Dot => {
            let Some((np, ch)) = next_char(text, pos) else {
                return false;
            };
            if ch == '\n' {
                return false;
            }
            next_positions.push(np);
            true
        }
        AtomKind::Ws => {
            let Some((np, ch)) = next_char(text, pos) else {
                return false;
            };
            if !is_regex_ws_char(ch) {
                return false;
            }
            next_positions.push(np);
            true
        }
        AtomKind::Digit => {
            if pos >= bytes.len() || !bytes[pos].is_ascii_digit() {
                return false;
            }
            next_positions.push(pos + 1);
            true
        }
        AtomKind::CClass(cc) => {
            let Some((np, ch)) = next_char(text, pos) else {
                return false;
            };
            if !cc.matches(ch) {
                return false;
            }
            next_positions.push(np);
            true
        }
        AtomKind::WordBound => {
            let prev_w = pos > 0 && is_ascii_word_byte(bytes[pos - 1]);
            let next_w = pos < bytes.len() && is_ascii_word_byte(bytes[pos]);
            if prev_w == next_w {
                return false;
            }
            next_positions.push(pos);
            true
        }
        AtomKind::NegLookBehind(cc) => {
            if let Some((_, ch)) = prev_char(text, pos) {
                if cc.matches(ch) {
                    return false;
                }
            }
            next_positions.push(pos);
            true
        }
        AtomKind::NegLookAheadCc(cc) => {
            if let Some((_, ch)) = next_char(text, pos) {
                if cc.matches(ch) {
                    return false;
                }
            }
            next_positions.push(pos);
            true
        }
        AtomKind::NegLookAheadLit(lit) => {
            if !lit.is_empty() && starts_with_ci(text, pos, lit) {
                return false;
            }
            next_positions.push(pos);
            true
        }
        AtomKind::PosLookAhead(cc) => {
            let Some((_, ch)) = next_char(text, pos) else {
                return false;
            };
            if !cc.matches(ch) {
                return false;
            }
            next_positions.push(pos);
            true
        }
        AtomKind::Group(branches) => {
            for branch in branches {
                collect_seq_ends(text, pos, branch, 0, next_positions);
            }
            !next_positions.is_empty()
        }
    }
}

fn collect_seq_ends(
    text: &str,
    pos: usize,
    seq: &[Atom],
    idx: usize,
    out: &mut Vec<usize>,
) {
    if idx == seq.len() {
        out.push(pos);
        return;
    }
    let atom = &seq[idx];
    if atom.min_rep == 1 && atom.max_rep == 1 {
        let mut nx = Vec::new();
        if !match_single_atom(text, pos, atom, &mut nx) {
            return;
        }
        for np in nx {
            collect_seq_ends(text, np, seq, idx + 1, out);
        }
        return;
    }
    let mut frontier = vec![pos];
    if atom.min_rep == 0 {
        collect_seq_ends(text, pos, seq, idx + 1, out);
    }
    let cap = atom.max_rep.min(256);
    let is_group = matches!(atom.kind, AtomKind::Group(_));
    for rep in 1..=cap {
        if frontier.is_empty() {
            break;
        }
        let mut next_f = Vec::new();
        let mut nx = Vec::new();
        for &p in &frontier {
            if match_single_atom(text, p, atom, &mut nx) {
                for &np in &nx {
                    if np > p || is_group {
                        next_f.push(np);
                    }
                }
            }
        }
        next_f.sort_unstable();
        next_f.dedup();
        if rep >= atom.min_rep {
            for &np in &next_f {
                collect_seq_ends(text, np, seq, idx + 1, out);
            }
        }
        if next_f == frontier {
            break;
        }
        frontier = next_f;
    }
}

fn match_seq_end(text: &str, pos: usize, seq: &[Atom], idx: usize) -> Option<usize> {
    if idx == seq.len() {
        return Some(pos);
    }
    let atom = &seq[idx];
    if atom.min_rep == 1 && atom.max_rep == 1 && !matches!(atom.kind, AtomKind::Group(_)) {
        let mut nx = Vec::new();
        if !match_single_atom(text, pos, atom, &mut nx) {
            return None;
        }
        for np in nx {
            if let Some(end) = match_seq_end(text, np, seq, idx + 1) {
                return Some(end);
            }
        }
        return None;
    }
    if atom.lazy && atom.max_rep > 1 {
        let mut frontier = vec![pos];
        if atom.min_rep == 0 {
            if let Some(end) = match_seq_end(text, pos, seq, idx + 1) {
                return Some(end);
            }
        }
        let cap = atom.max_rep.min(256);
        for rep in 1..=cap {
            if frontier.is_empty() {
                break;
            }
            let mut next_f = Vec::new();
            let mut nx = Vec::new();
            for &p in &frontier {
                if match_single_atom(text, p, atom, &mut nx) {
                    for &np in &nx {
                        if np > p {
                            next_f.push(np);
                        }
                    }
                }
            }
            next_f.sort_unstable();
            next_f.dedup();
            if rep >= atom.min_rep {
                for &np in &next_f {
                    if let Some(end) = match_seq_end(text, np, seq, idx + 1) {
                        return Some(end);
                    }
                }
            }
            frontier = next_f;
        }
        return None;
    }

    let mut all_ends = Vec::new();
    let mut frontier = vec![pos];
    if atom.min_rep == 0 {
        all_ends.push(pos);
    }
    let cap = atom.max_rep.min(256);
    let is_group = matches!(atom.kind, AtomKind::Group(_));
    for rep in 1..=cap {
        if frontier.is_empty() {
            break;
        }
        let mut next_f = Vec::new();
        let mut nx = Vec::new();
        for &p in &frontier {
            if match_single_atom(text, p, atom, &mut nx) {
                for &np in &nx {
                    if np > p || is_group {
                        next_f.push(np);
                    }
                }
            }
        }
        next_f.sort_unstable();
        next_f.dedup();
        if rep >= atom.min_rep {
            all_ends.extend_from_slice(&next_f);
        }
        if next_f == frontier {
            break;
        }
        frontier = next_f;
    }
    all_ends.sort_unstable_by(|a, b| b.cmp(a));
    all_ends.dedup();
    for np in all_ends {
        if let Some(end) = match_seq_end(text, np, seq, idx + 1) {
            return Some(end);
        }
    }
    None
}
