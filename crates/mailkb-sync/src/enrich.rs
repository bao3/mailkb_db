//! Universal + `CompiledDomainPack`-driven message enrichment:
//! direction classification, entity/code & custom dimension extraction,
//! organization & topic resolution, intent & summary synthesis, and
//! inline/HTML-table/OOXML amount & commercial-terms extraction.

use crate::html::Table2D;
use mailkb_core::domain_pack::{CompiledCodeRule, CompiledDomainPack, CompiledPattern};
use mailkb_core::fts::tokenize_for_fts;
use mailkb_core::publish::sha256_bytes;
use mailkb_core::security::{collapse_ws, sanitize_utf8};
use mailkb_core::strutil::{
    contains_any_ci, contains_ci, find_ci, safe_slice_after, safe_slice_before, starts_with_ci,
    trim_ascii_ws, utf8_char_len, utf8_slice_chars, utf8_trunc_sv,
};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

pub const MAX_BODY_LATEST_BYTES: usize = 128 * 1024;
pub const MAX_BODY_QUOTED_STORE: usize = 16 * 1024;
pub const MAX_BODY_QUOTED_FTS: usize = 8 * 1024;

#[derive(Debug, Clone)]
pub struct EmailAddr {
    pub addr: String,
    pub domain: String,
    pub local: String,
}

#[derive(Debug, Clone, Default)]
pub struct InferredIdentity {
    pub self_emails: Vec<String>,
    pub internal_domains: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ResolvedIdentity {
    pub self_emails: HashSet<String>,
    pub self_name_tokens: Vec<String>,
    pub internal_domains: HashSet<String>,
    pub system_senders: HashSet<String>,
    pub system_domains: HashSet<String>,
    pub system_subject_prefixes: Vec<String>,
    pub system_body_markers: Vec<String>,
    pub noise_attachment_prefixes: Vec<String>,
}

impl ResolvedIdentity {
    /// Combines explicit pack identity rules with auto-inferred Sent identities.
    pub fn from_pack_and_inferred(pack: &CompiledDomainPack, inferred: &InferredIdentity) -> Self {
        let mut out = Self {
            self_emails: pack.self_emails.clone(),
            self_name_tokens: pack.self_name_tokens.clone(),
            internal_domains: pack.internal_domains.clone(),
            system_senders: pack.system_senders.clone(),
            system_domains: pack.system_domains.clone(),
            system_subject_prefixes: pack.system_subject_prefixes.clone(),
            system_body_markers: pack.system_body_markers.clone(),
            noise_attachment_prefixes: pack.noise_attachment_prefixes.clone(),
        };

        // Supplement self_emails from Sent folder auto-inference when pack identity is empty/partial.
        for em in &inferred.self_emails {
            let clean = em.trim().to_ascii_lowercase();
            if !clean.is_empty() {
                out.self_emails.insert(clean);
            }
        }
        // Only infer internal_domains if explicit internal_domains is empty,
        // or add non-freemail domains of self_emails when not excluded.
        if out.internal_domains.is_empty() {
            for dom in &inferred.internal_domains {
                let clean = dom.trim().to_ascii_lowercase();
                if !clean.is_empty() && !is_freemail_domain(&clean) {
                    out.internal_domains.insert(clean);
                }
            }
            for em in &out.self_emails {
                if let Some((_, dom)) = em.split_once('@') {
                    if !is_freemail_domain(dom) && !out.system_domains.contains(dom) {
                        out.internal_domains.insert(dom.to_string());
                    }
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Default)]
pub struct RawAttachmentInput {
    pub filename: String,
    pub clean_filename: String,
    pub ext: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub mtime: i64,
    pub mtime_iso: String,
    pub storage_relpath: String,
    pub is_inline: i32,
    pub is_noise: i32,
    pub sha256: String,
    pub text_preview: String,
    pub ooxml_sheets: Vec<(String, Table2D)>,
}

#[derive(Debug, Clone, Default)]
pub struct RawMessageInput {
    pub uid_key: String,
    pub account_id: String,
    pub source: String,
    pub source_ref: String,
    pub rfc_message_id: String,
    pub subject: String,
    pub sender: String,
    pub recipients: String,
    pub cc: String,
    pub date_iso: String,
    pub folder_path: String,
    pub completeness: String,
    pub body_latest: String,
    pub body_quoted: String,
    pub body_quoted_for_amount: String,
    pub html_tables: Vec<Table2D>,
    pub attachments: Vec<RawAttachmentInput>,
}

#[derive(Debug, Clone)]
pub struct EntityRow {
    pub entity_type: String,
    pub entity_key: String,
    pub canonical_value: String,
    pub category: String,
    pub sub_group: String,
    pub quantity: Option<f64>,
    pub unit: String,
    pub role: String,
    pub confidence: String,
    pub snippet: String,
    pub attrs_json: String,
}

#[derive(Debug, Clone)]
pub struct AmountRow {
    pub amount_type: String,
    pub subject_entity: String,
    pub category: String,
    pub topic_name: String,
    pub org_name: String,
    pub currency: String,
    pub unit_amount: Option<f64>,
    pub total_amount: Option<f64>,
    pub quantity: Option<f64>,
    pub tax_mode: String,
    pub moq: String,
    pub lead_time: String,
    pub discount_info: String,
    pub terms_json: String,
    pub effective_date_iso: String,
    pub valid_until: String,
    pub source_kind: String,
    pub evidence_snippet: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Default)]
pub struct EnrichedAttachment {
    pub filename: String,
    pub clean_filename: String,
    pub ext: String,
    pub mime_type: String,
    pub size_bytes: i64,
    pub mtime: i64,
    pub mtime_iso: String,
    pub storage_relpath: String,
    pub is_inline: i32,
    pub is_noise: i32,
    pub sha256: String,
    pub text_preview: String,
    pub entity_tags: String,
    pub topic_tags: String,
    pub fn_tok: String,
    pub meta_tok: String,
}

#[derive(Debug, Clone, Default)]
pub struct EnrichedMsg {
    pub uid_key: String,
    pub account_id: String,
    pub source: String,
    pub source_ref: String,
    pub rfc_message_id: String,
    pub subject: String,
    pub thread_topic: String,
    pub sender: String,
    pub recipients: String,
    pub cc: String,
    pub date_iso: String,
    pub folder_path: String,
    pub completeness: String,
    pub direction: String,
    pub intent_type: String,
    pub summary_line: String,
    pub body_latest: String,
    pub body_quoted: String,
    pub body_quoted_for_amount: String,
    pub content_hash: String,
    pub primary_entities: String,
    pub primary_entities_vec: Vec<String>,
    pub primary_category: String,
    pub topic_tags: String,
    pub topic_vec: Vec<String>,
    pub org_tags: String,
    pub org_vec: Vec<String>,
    pub has_amount: i32,
    pub amount_summary: String,
    pub event_dates_json: String,
    pub custom_dims_json: String,
    pub custom_dims_map: BTreeMap<String, Vec<String>>,
    pub entities: Vec<EntityRow>,
    pub amounts: Vec<AmountRow>,
    pub attachments: Vec<EnrichedAttachment>,
    /// Lexicon hits as `(dimension, key)` for accumulating `domain_lexicon.hit_count`.
    pub lexicon_hits: Vec<(String, String)>,
    pub mfts_subj: String,
    pub mfts_sender: String,
    pub mfts_meta: String,
    pub mfts_latest: String,
    pub mfts_quoted: String,
    pub dfts_title: String,
    pub dfts_meaning: String,
    pub dfts_intent: String,
    pub dfts_entities: String,
    pub dfts_orgs: String,
    pub dfts_topics: String,
    pub dfts_amounts: String,
}

const FREEMAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "yahoo.com",
    "yahoo.co.jp",
    "yahoo.com.cn",
    "yahoo.com.tw",
    "ymail.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "tutanota.com",
    "tuta.io",
    "fastmail.com",
    "zoho.com",
    "gmx.com",
    "gmx.de",
    "web.de",
    "mail.ru",
    "yandex.ru",
    "qq.com",
    "163.com",
    "126.com",
    "yeah.net",
    "sina.com",
    "sohu.com",
    "foxmail.com",
    "aliyun.com",
    "139.com",
    "189.cn",
    "naver.com",
    "daum.net",
    "hanmail.net",
    "mail.com",
    "inbox.com",
    "hey.com",
];

const GENERIC_CODE_EXCLUDE_TOKENS: &[&str] = &[
    "EN", "IEC", "IEEE", "ISO", "RFC", "ANSI", "ASTM", "DIN", "CISPR", "UTF", "SHA", "TLS", "SSL",
    "HTTP", "HTTPS", "MIME", "HTML", "XML", "JSON", "SMTP", "IMAP", "POP3", "UUID", "ISBN", "ISSN",
    "COVID", "JIRA", "CASE", "TKT", "PO", "SO", "PI", "RFQ", "PR", "SPR", "NDA", "SLA", "SKU",
    "MPN", "BOM", "ECCN", "HS", "VAT", "GST", "USD", "EUR", "CNY", "RMB", "TWD", "HKD", "JPY",
    "GBP", "AUD", "CAD", "SGD", "CHF", "KRW", "INR", "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
    "JUL", "AUG", "SEP", "OCT", "NOV", "DEC", "MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN",
    "INV", "DOC", "REF", "REV", "ID", "NO", "TEL", "FAX",
];

const GENERIC_SYS_SUBJ_PREFIXES: &[&str] = &[
    "accepted:",
    "declined:",
    "canceled:",
    "cancelled:",
    "tentative:",
    "automatic reply:",
    "auto-reply:",
    "out of office:",
    "undeliverable:",
    "mail delivery failed",
    "delivery status notification",
    "已接受:",
    "已接受：",
    "已拒绝:",
    "已拒绝：",
    "已拒絕:",
    "已拒絕：",
    "已取消:",
    "已取消：",
    "已暂定:",
    "自动回复:",
    "自动回复：",
    "自动答复:",
    "自動回覆:",
    "自動答覆:",
    "撤回:",
];

pub fn is_freemail_domain(domain: &str) -> bool {
    let lo = domain.trim().to_ascii_lowercase();
    FREEMAIL_DOMAINS.contains(&lo.as_str())
}

pub fn is_noreply_local(local: &str) -> bool {
    let lo = local.trim().to_ascii_lowercase();
    matches!(
        lo.as_str(),
        "noreply"
            | "no-reply"
            | "no_reply"
            | "donotreply"
            | "do-not-reply"
            | "do_not_reply"
            | "mailer-daemon"
            | "postmaster"
            | "bounce"
            | "bounces"
            | "notifications"
            | "notification"
            | "automated"
            | "auto-confirm"
            | "calendar-notification"
    ) || lo.starts_with("noreply+")
        || lo.starts_with("no-reply+")
        || lo.starts_with("bounces+")
}

pub fn is_sent_folder(folder_path: &str) -> bool {
    if folder_path.is_empty() {
        return false;
    }
    let last = folder_path
        .rsplit('/')
        .next()
        .unwrap_or(folder_path)
        .trim()
        .to_ascii_lowercase();
    matches!(
        last.as_str(),
        "sent"
            | "sent messages"
            | "sent items"
            | "sent mail"
            | "sent-mail"
            | "已发送"
            | "已发送邮件"
            | "寄件備份"
            | "已傳送"
            | "已寄郵件"
    ) || contains_ci(folder_path, "sent messages")
        || contains_ci(folder_path, "sent items")
        || contains_ci(folder_path, "sent mail")
        || folder_path.contains("已发送")
        || folder_path.contains("寄件備份")
}

pub fn extract_emails(text: &str) -> Vec<EmailAddr> {
    let is_local_ch = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-');
    let is_dom_ch = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-');
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let Some(at_rel) = text[i..].find('@') else {
            break;
        };
        let at = i + at_rel;
        let mut ls = at;
        while ls > 0 && is_local_ch(bytes[ls - 1]) {
            ls -= 1;
        }
        let mut de = at + 1;
        while de < bytes.len() && is_dom_ch(bytes[de]) {
            de += 1;
        }
        if ls < at && de > at + 3 {
            let loc = &text[ls..at];
            let dom = text[at + 1..de].trim_end_matches('.');
            if let Some(last_dot) = dom.rfind('.') {
                if dom.len() - last_dot >= 3 {
                    let dom_lo = dom.to_ascii_lowercase();
                    let local_lo = loc.to_ascii_lowercase();
                    out.push(EmailAddr {
                        addr: format!("{local_lo}@{dom_lo}"),
                        domain: dom_lo,
                        local: local_lo,
                    });
                }
            }
        }
        i = at + 1;
    }
    out
}

pub fn strip_subject_prefixes(subj: &str) -> String {
    let mut s = String::with_capacity(subj.len());
    for ch in subj.chars() {
        if matches!(
            ch,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' | '\u{FEFF}'
        ) {
            continue;
        }
        s.push(ch);
    }
    let s_trimmed = trim_ascii_ws(&s);
    let mut sv = s_trimmed;

    const PREFIXES: &[&str] = &[
        "re:",
        "fw:",
        "fwd:",
        "回复:",
        "回复：",
        "答复:",
        "答复：",
        "转发:",
        "转发：",
        "回覆:",
        "回覆：",
        "轉發:",
        "轉寄:",
        "automatic reply:",
        "自动回复:",
        "自动回复：",
        "自动答复:",
        "[external]",
        "[外部]",
        "[外部邮件]",
        "【外部邮件】",
        "ext:",
        "external:",
    ];

    for _ in 0..12 {
        sv = sv.trim_start_matches(|c: char| c.is_ascii() && mailkb_core::strutil::is_ascii_ws_byte(c as u8));
        let mut stripped = false;
        for &pfx in PREFIXES {
            if starts_with_ci(sv, 0, pfx) {
                sv = &sv[pfx.len()..];
                while let Some(first) = sv.as_bytes().first().copied() {
                    if mailkb_core::strutil::is_ascii_ws_byte(first) || first == b':' {
                        sv = &sv[1..];
                    } else {
                        break;
                    }
                }
                stripped = true;
                break;
            }
        }
        if !stripped
            && sv.len() >= 3
            && (starts_with_ci(sv, 0, "re") || starts_with_ci(sv, 0, "fw"))
        {
            let b = sv.as_bytes();
            let mut k = 2;
            if k < b.len() && (b[k] == b'd' || b[k] == b'D') {
                k += 1;
            }
            if k < b.len() && b[k] == b'[' {
                if let Some(rb) = sv[k..].find(']') {
                    k += rb + 1;
                }
            }
            while k < b.len() && mailkb_core::strutil::is_ascii_ws_byte(b[k]) {
                k += 1;
            }
            if k < b.len() && (b[k] == b':' || sv[k..].starts_with('：')) {
                sv = if b[k] == b':' {
                    &sv[k + 1..]
                } else {
                    &sv[k + '：'.len_utf8()..]
                };
                stripped = true;
            }
        }
        if !stripped {
            break;
        }
    }

    let out = trim_ascii_ws(sv);
    if contains_ci(out, "Caution: This is an external email")
        || out.starts_with("注意：这是一封外部邮件")
        || out.starts_with("注意: 这是一封外部邮件")
    {
        return String::new();
    }
    if out.is_empty() {
        s_trimmed.to_string()
    } else {
        out.to_string()
    }
}

pub fn classify_direction(
    identity: &ResolvedIdentity,
    sender: &str,
    recipients: &str,
    cc: &str,
    subject: &str,
    folder_path: &str,
    body_latest: &str,
) -> String {
    let s_emails = extract_emails(sender);
    let rc_combined = format!("{recipients} {cc}");
    let r_emails = extract_emails(&rc_combined);

    for em in &s_emails {
        if identity.system_senders.contains(&em.addr)
            || identity.system_domains.contains(&em.domain)
            || is_noreply_local(&em.local)
        {
            return "system_notice".to_string();
        }
    }

    let subj_tr = trim_ascii_ws(subject);
    for &p in GENERIC_SYS_SUBJ_PREFIXES {
        if starts_with_ci(subj_tr, 0, p) {
            return "system_notice".to_string();
        }
    }
    for p in &identity.system_subject_prefixes {
        if starts_with_ci(subj_tr, 0, p) {
            return "system_notice".to_string();
        }
    }
    if subj_tr.contains("撤回报告") && subj_tr.contains("邮件") {
        return "system_notice".to_string();
    }
    for marker in &identity.system_body_markers {
        if !marker.is_empty() && contains_ci(body_latest, marker) {
            return "system_notice".to_string();
        }
    }
    if body_latest.starts_with("SUMMARY:") && body_latest.contains("DTSTART:") {
        return "system_notice".to_string();
    }

    let mut is_self_or_internal = s_emails.iter().any(|em| {
        identity.self_emails.contains(&em.addr) || identity.internal_domains.contains(&em.domain)
    });

    if !is_self_or_internal && s_emails.is_empty() && !identity.self_name_tokens.is_empty() {
        is_self_or_internal = identity
            .self_name_tokens
            .iter()
            .any(|tok| !tok.is_empty() && contains_ci(sender, tok));
    }

    if !is_self_or_internal && s_emails.is_empty() && is_sent_folder(folder_path) {
        is_self_or_internal = true;
    }

    if !is_self_or_internal {
        return "external_inbound".to_string();
    }

    if r_emails.is_empty() {
        // Sent email with missing recipient header -> treat as external_outbound if from Sent, else internal.
        if is_sent_folder(folder_path) {
            return "external_outbound".to_string();
        }
        return "internal".to_string();
    }

    for em in &r_emails {
        let is_rcpt_internal = identity.self_emails.contains(&em.addr)
            || identity.internal_domains.contains(&em.domain)
            || identity.system_domains.contains(&em.domain);
        if !is_rcpt_internal {
            return "external_outbound".to_string();
        }
    }
    "internal".to_string()
}

pub fn lower_ext_of(fn_name: &str) -> String {
    let Some(dot) = fn_name.rfind('.') else {
        return String::new();
    };
    if dot + 1 >= fn_name.len() || fn_name.len() - dot > 12 {
        return String::new();
    }
    fn_name[dot + 1..].to_ascii_lowercase()
}

pub fn mime_from_ext(ext: &str) -> &'static str {
    match ext {
        "xlsx" | "xlsm" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "pdf" => "application/pdf",
        "xls" => "application/vnd.ms-excel",
        "doc" => "application/msword",
        "csv" => "text/csv",
        "txt" => "text/plain",
        "eml" | "emlx" => "message/rfc822",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ics" => "text/calendar",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

fn looks_like_uuid_prefix(s: &str) -> bool {
    if s.len() < 32 {
        return false;
    }
    let mut hex = 0;
    let mut hy = 0;
    for b in s.bytes().take(36) {
        if b.is_ascii_hexdigit() {
            hex += 1;
        } else if b == b'-' {
            hy += 1;
        } else {
            break;
        }
    }
    hex >= 28 && hy >= 3
}

pub fn classify_att_noise(
    fn_name: &str,
    ext: &str,
    size_bytes: i64,
    is_inline: i32,
    identity: &ResolvedIdentity,
) -> i32 {
    if matches!(
        ext,
        "ics" | "vcs" | "vcf" | "p7s" | "p7m" | "emz" | "wmz" | "mso" | "odttf" | "thmx"
    ) {
        return 1;
    }
    if identity
        .noise_attachment_prefixes
        .iter()
        .any(|p| !p.is_empty() && starts_with_ci(fn_name, 0, p))
    {
        return 1;
    }
    if matches!(
        ext,
        "png" | "jpg" | "jpeg" | "gif" | "bmp" | "webp" | "ico" | "svg"
    ) && (starts_with_ci(fn_name, 0, "Outlook-")
        || (starts_with_ci(fn_name, 0, "image")
            && fn_name.as_bytes().get(5).is_some_and(|b| b.is_ascii_digit()))
        || starts_with_ci(fn_name, 0, "ATT00")
        || looks_like_uuid_prefix(fn_name)
        || size_bytes < 16384
        || (is_inline != 0 && size_bytes < 65536))
    {
        return 1;
    }
    if matches!(ext, "txt" | "htm" | "html")
        && (starts_with_ci(fn_name, 0, "ATT00") || size_bytes < 128)
    {
        return 1;
    }
    0
}

#[derive(Debug, Clone)]
pub struct MatchedCode {
    pub entity_key: String,
    pub canonical_value: String,
    pub category: String,
    pub sub_group: String,
    pub extra_terms: Vec<String>,
    pub start: usize,
    pub end: usize,
}

fn is_part_of_email_or_url(text: &str, start: usize, end: usize) -> bool {
    let bytes = text.as_bytes();
    if start > 0 && bytes[start - 1] == b'@' {
        return true;
    }
    if end < bytes.len() && bytes[end] == b'@' {
        return true;
    }
    let before = safe_slice_before(text, start, 32);
    if let Some(http_pos) = before.rfind("http") {
        let between = &before[http_pos..];
        if !between.bytes().any(|b| b.is_ascii_whitespace()) {
            return true;
        }
    }
    let after = safe_slice_after(text, end, 8).to_ascii_lowercase();
    if after.starts_with(".com")
        || after.starts_with(".cn")
        || after.starts_with(".net")
        || after.starts_with(".org")
        || after.starts_with(".io")
    {
        return true;
    }
    false
}

fn preceded_by_standard(text: &str, start: usize) -> bool {
    let mut bef = safe_slice_before(text, start, 12);
    while let Some(&last) = bef.as_bytes().last() {
        if mailkb_core::strutil::is_ascii_ws_byte(last) {
            bef = &bef[..bef.len() - 1];
        } else {
            break;
        }
    }
    for std_p in ["EN", "IEC", "IEEE", "GB/T", "TB/T", "ISO", "RFC"] {
        if bef.len() >= std_p.len() && starts_with_ci(bef, bef.len() - std_p.len(), std_p) {
            return true;
        }
    }
    false
}

fn is_excluded_code_token(tok_upper: &str, pack: &CompiledDomainPack) -> bool {
    if pack.exclude_code_tokens.contains(tok_upper) {
        return true;
    }
    let head = tok_upper
        .split(['-', ' ', '('])
        .next()
        .unwrap_or(tok_upper);
    if pack.exclude_code_tokens.contains(head) || GENERIC_CODE_EXCLUDE_TOKENS.contains(&head) {
        return true;
    }
    if let Some((a, b)) = tok_upper.split_once('-') {
        let two = format!("{a}-{}", b.split(['-', ' ']).next().unwrap_or(b));
        if pack.exclude_code_tokens.contains(&two) {
            return true;
        }
    }
    // Reject obvious year-suffix tags like FOO-2026 unless a pack explicitly opted in?
    // Wait: generic fallback rejects -20xx; pack rules can use `exclude_if_matches`.
    false
}

pub fn normalize_code_key(raw: &str) -> String {
    let collapsed = collapse_ws(raw);
    if collapsed.is_empty() {
        return String::new();
    }
    if let Some((head, tail)) = collapsed.split_once(' ') {
        let has_lower = head.bytes().any(|b| b.is_ascii_lowercase());
        let has_upper = head.bytes().any(|b| b.is_ascii_uppercase());
        if has_lower && has_upper {
            return format!("{head} {}", tail.to_ascii_uppercase());
        }
    }
    collapsed.to_ascii_uppercase()
}

pub fn generic_sub_group(code: &str) -> String {
    let clean = code.split('(').next().unwrap_or(code).trim();
    if let Some((head, tail)) = clean.split_once(' ') {
        let series_tok = tail.split('-').next().unwrap_or(tail);
        return format!("{head} {series_tok}");
    }
    let segs: Vec<&str> = clean.split('-').filter(|s| !s.is_empty()).collect();
    if segs.len() >= 2 {
        format!("{}-{}", segs[0], segs[1])
    } else {
        clean.to_string()
    }
}

fn infer_sub_group_from_rule(rule: &CompiledCodeRule, raw_tok: &str, norm_tok: &str) -> String {
    if let Some(ref tmpl) = rule.sub_group {
        let expanded = rule.pattern.expand_template(raw_tok, tmpl);
        let clean = collapse_ws(&expanded);
        if !clean.is_empty() {
            return clean;
        }
    }
    if let Some(ref srx) = rule.series_regex {
        if let Some(caps) = srx.captures(norm_tok).or_else(|| srx.captures(raw_tok)) {
            if let Some(m) = caps.get(1).or_else(|| caps.get(0)) {
                let s = collapse_ws(m.as_str());
                if !s.is_empty() {
                    return s.to_ascii_uppercase();
                }
            }
        }
    }
    generic_sub_group(norm_tok)
}

fn generic_code_regex() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(r"(?-i:\b[A-Z][A-Za-z0-9]{1,7}(?:-[A-Z][A-Za-z0-9]{0,7}){0,2}-(?:[A-Za-z]{0,3}\d{2,6}[A-Za-z0-9]*|\d{1,3}[A-Za-z]{1,6}[A-Za-z0-9]*)(?:-[A-Za-z0-9]{1,12})*\b)")
            .expect("valid generic code regex")
    })
}

fn looks_like_date_or_year_code(tok_upper: &str) -> bool {
    let segs: Vec<&str> = tok_upper.split('-').collect();
    if segs.len() >= 2 && segs.iter().all(|s| s.bytes().all(|b| b.is_ascii_digit())) {
        return true;
    }
    if let Some(last) = segs.last() {
        if last.len() == 4
            && last.starts_with("20")
            && last.bytes().all(|b| b.is_ascii_digit())
            && segs.len() == 2
        {
            return true;
        }
    }
    false
}

/// Extracts item/model codes using `CompiledDomainPack::code_rules`, or generic hyphenated code
/// fallback when `pack.code_rules` is empty.
pub fn extract_item_codes(text: &str, pack: &CompiledDomainPack) -> Vec<MatchedCode> {
    if text.is_empty() {
        return Vec::new();
    }
    let mut candidates: Vec<(i32, MatchedCode)> = Vec::new();

    if !pack.code_rules.is_empty() {
        for rule in &pack.code_rules {
            for (start, end) in rule.pattern.find_spans(text) {
                if start > end || end > text.len() {
                    continue;
                }
                let raw_tok = &text[start..end];
                let norm = normalize_code_key(raw_tok);
                if norm.len() < 3 {
                    continue;
                }
                if is_part_of_email_or_url(text, start, end) {
                    continue;
                }
                let upper = norm.to_ascii_uppercase();
                if is_excluded_code_token(&upper, pack) {
                    continue;
                }
                let ctx_win = format!("{}{}", safe_slice_before(text, start, 10), raw_tok);
                let excluded = rule.exclude_if_matches.iter().any(|ep| {
                    let target = if ep.raw().contains(' ') || ep.raw().contains("\\s") {
                        ctx_win.as_str()
                    } else {
                        raw_tok
                    };
                    ep.is_match(target) || ep.is_match(&norm)
                });
                if excluded {
                    continue;
                }
                if preceded_by_standard(text, start) && !contains_ci(&rule.category, "standard") {
                    continue;
                }

                let sub_group = infer_sub_group_from_rule(rule, raw_tok, &norm);
                candidates.push((
                    rule.priority,
                    MatchedCode {
                        entity_key: norm.clone(),
                        canonical_value: norm,
                        category: rule.category.clone(),
                        sub_group,
                        extra_terms: rule.extra_terms.clone(),
                        start,
                        end,
                    },
                ));
            }
        }
    } else {
        // Zero-pack universal mode: conservative uppercase/TitleCase hyphenated alphanumeric codes
        for m in generic_code_regex().find_iter(text) {
            let start = m.start();
            let end = m.end();
            if is_part_of_email_or_url(text, start, end) {
                continue;
            }
            if preceded_by_standard(text, start) {
                continue;
            }
            let raw_tok = m.as_str();
            let norm = normalize_code_key(raw_tok);
            let upper = norm.to_ascii_uppercase();
            if is_excluded_code_token(&upper, pack) || looks_like_date_or_year_code(&upper) {
                continue;
            }
            let digit_count = upper.bytes().filter(|b| b.is_ascii_digit()).count();
            let alpha_count = upper.bytes().filter(|b| b.is_ascii_alphabetic()).count();
            if digit_count == 0 || alpha_count < 2 {
                continue;
            }
            let prefix = upper.split('-').next().unwrap_or(&upper);
            let category = if prefix.len() >= 2 {
                prefix.to_string()
            } else {
                pack.default_category.clone()
            };
            let sub_group = generic_sub_group(&norm);
            candidates.push((
                0,
                MatchedCode {
                    entity_key: norm.clone(),
                    canonical_value: norm,
                    category,
                    sub_group,
                    extra_terms: Vec::new(),
                    start,
                    end,
                },
            ));
        }
    }

    if candidates.is_empty() {
        return Vec::new();
    }

    // Resolve overlaps: higher priority first, then earlier start, then longer span.
    candidates.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| a.1.start.cmp(&b.1.start))
            .then_with(|| (b.1.end - b.1.start).cmp(&(a.1.end - a.1.start)))
    });

    let mut accepted: Vec<MatchedCode> = Vec::new();
    for (_, item) in candidates {
        let overlaps = accepted
            .iter()
            .any(|ac| !(item.end <= ac.start || item.start >= ac.end));
        if !overlaps {
            accepted.push(item);
        }
    }

    // Re-order left-to-right by appearance and deduplicate by uppercase key.
    accepted.sort_by_key(|a| a.start);
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for mc in accepted {
        if seen.insert(mc.entity_key.to_ascii_uppercase()) {
            out.push(mc);
        }
    }
    out
}

pub fn infer_category_from_fallbacks(text: &str, pack: &CompiledDomainPack) -> String {
    for fb in &pack.category_fallbacks {
        if fb.patterns.iter().any(|p| p.is_match(text)) {
            return fb.category.clone();
        }
    }
    pack.default_category.clone()
}

pub fn extract_custom_dimensions(
    text: &str,
    pack: &CompiledDomainPack,
    lexicon_hits: &mut Vec<(String, String)>,
) -> (BTreeMap<String, Vec<String>>, Vec<EntityRow>) {
    let mut dim_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut entity_rows = Vec::new();

    for dim in &pack.dimensions {
        let mut keys: Vec<String> = Vec::new();
        let mut seen = HashSet::new();
        for entry in &dim.entries {
            if entry.patterns.iter().any(|p| p.is_match(text)) {
                if seen.insert(entry.key.clone()) {
                    keys.push(entry.key.clone());
                    lexicon_hits.push((dim.name.clone(), entry.key.clone()));
                    entity_rows.push(EntityRow {
                        entity_type: dim.entity_type.clone(),
                        entity_key: entry.key.clone(),
                        canonical_value: entry.canonical_name.clone(),
                        category: dim.name.clone(),
                        sub_group: String::new(),
                        quantity: None,
                        unit: String::new(),
                        role: "dimension_match".to_string(),
                        confidence: "high".to_string(),
                        snippet: entry.canonical_name.clone(),
                        attrs_json: entry.metadata_json.clone(),
                    });
                }
            }
        }
        if !keys.is_empty() {
            dim_map.insert(dim.name.clone(), keys);
        }
    }

    (dim_map, entity_rows)
}

pub fn extract_orgs(
    pack: &CompiledDomainPack,
    identity: &ResolvedIdentity,
    sender: &str,
    recipients: &str,
    cc: &str,
    subject: &str,
    att_names: &str,
    clean_body_and_quoted: &str,
    lexicon_hits: &mut Vec<(String, String)>,
) -> Vec<String> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    let mut add_org = |name: &str, track_lex: bool, found: &mut Vec<String>| {
        let trimmed = trim_ascii_ws(name);
        if trimmed.is_empty() {
            return;
        }
        let lo = trimmed.to_ascii_lowercase();
        if pack.org_exclude_names.contains(&lo) {
            return;
        }
        if seen.insert(lo) {
            found.push(trimmed.to_string());
            if track_lex {
                lexicon_hits.push(("organization".to_string(), trimmed.to_string()));
            }
        }
    };

    let s_emails = extract_emails(sender);
    for em in &s_emails {
        if identity.internal_domains.contains(&em.domain)
            || identity.system_domains.contains(&em.domain)
            || pack.org_exclude_domains.contains(&em.domain)
        {
            continue;
        }
        if let Some(org) = pack.email_to_org.get(&em.addr) {
            add_org(org, true, &mut found);
        } else if let Some(org) = pack.domain_to_org.get(&em.domain) {
            add_org(org, true, &mut found);
        }
    }

    let rc = format!("{recipients} {cc}");
    let ext_r: Vec<EmailAddr> = extract_emails(&rc)
        .into_iter()
        .filter(|em| {
            !identity.internal_domains.contains(&em.domain)
                && !identity.self_emails.contains(&em.addr)
                && !identity.system_domains.contains(&em.domain)
                && !pack.org_exclude_domains.contains(&em.domain)
        })
        .collect();
    if ext_r.len() <= 8 {
        for em in &ext_r {
            if let Some(org) = pack.email_to_org.get(&em.addr) {
                add_org(org, true, &mut found);
            } else if let Some(org) = pack.domain_to_org.get(&em.domain) {
                add_org(org, true, &mut found);
            }
        }
    }

    let body_slice = utf8_trunc_sv(clean_body_and_quoted, 3500);
    let scan = format!("{subject}\n{sender}\n{att_names}\n{body_slice}");
    for rule in &pack.org_entries {
        if rule.patterns.iter().any(|pat| pat.is_match(&scan)) {
            add_org(&rule.canonical_name, true, &mut found);
        }
        if found.len() >= 8 {
            break;
        }
    }

    // Generic domain fallback when pack rules yielded nothing
    if found.is_empty() {
        for em in &s_emails {
            if !identity.internal_domains.contains(&em.domain)
                && !identity.self_emails.contains(&em.addr)
                && !identity.system_domains.contains(&em.domain)
                && !pack.org_exclude_domains.contains(&em.domain)
                && !is_freemail_domain(&em.domain)
                && !is_noreply_local(&em.local)
            {
                add_org(&em.domain, false, &mut found);
            }
        }
        if ext_r.len() <= 5 {
            for em in &ext_r {
                if !is_freemail_domain(&em.domain) && !is_noreply_local(&em.local) {
                    add_org(&em.domain, false, &mut found);
                }
                if found.len() >= 4 {
                    break;
                }
            }
        }
    }

    found
}

fn extract_bracket_topic_fallback(thread_topic: &str) -> Option<String> {
    for (open, close) in [('[', ']'), ('【', '】')] {
        let mut pos = 0;
        while let Some(o_rel) = thread_topic[pos..].find(open) {
            let start = pos + o_rel + open.len_utf8();
            let Some(c_rel) = thread_topic[start..].find(close) else {
                break;
            };
            let candidate = collapse_ws(&thread_topic[start..start + c_rel]);
            let char_len = utf8_char_len(&candidate);
            if (2..=36).contains(&char_len)
                && !candidate.bytes().all(|b| b.is_ascii_digit())
                && !matches!(
                    candidate.to_ascii_lowercase().as_str(),
                    "external" | "外部" | "外部邮件" | "auto" | "fwd" | "re" | "urgent" | "spam"
                )
            {
                return Some(candidate);
            }
            pos = start + c_rel + close.len_utf8();
        }
    }
    None
}

pub fn extract_topics(
    pack: &CompiledDomainPack,
    subject: &str,
    thread_topic: &str,
    att_names: &str,
    clean_body_and_quoted: &str,
    lexicon_hits: &mut Vec<(String, String)>,
) -> Vec<String> {
    if pack
        .amount_exclude_subjects
        .iter()
        .any(|p| p.is_match(subject))
    {
        return Vec::new();
    }

    let mut topics = Vec::new();
    let mut seen = HashSet::new();
    let body_slice = utf8_trunc_sv(clean_body_and_quoted, 3000);

    for ch in [subject, att_names, body_slice] {
        if ch.is_empty() {
            continue;
        }
        for rule in &pack.topic_entries {
            if rule.patterns.iter().any(|pat| pat.is_match(ch)) {
                let lo = rule.canonical_name.to_ascii_lowercase();
                if seen.insert(lo) {
                    topics.push(rule.canonical_name.clone());
                    lexicon_hits.push(("topic".to_string(), rule.canonical_name.clone()));
                    if topics.len() >= 3 {
                        return topics;
                    }
                }
            }
        }
    }

    if !topics.is_empty() {
        return topics;
    }

    // Fallback 1: topic_generic_suffixes patterns on subject / thread_topic
    for pat in &pack.topic_generic_suffixes {
        let spans = pat.find_spans(thread_topic);
        if let Some((s, e)) = spans.first().copied() {
            let cand = match pat {
                CompiledPattern::Std { rx, .. } => rx
                    .captures(&thread_topic[s..e])
                    .and_then(|c| c.get(1).or_else(|| c.get(0)))
                    .map(|m| collapse_ws(m.as_str()))
                    .unwrap_or_else(|| collapse_ws(&thread_topic[s..e])),
                CompiledPattern::Mini { .. } => collapse_ws(&thread_topic[s..e]),
            };
            if utf8_char_len(&cand) >= 2 && seen.insert(cand.to_ascii_lowercase()) {
                topics.push(cand);
                return topics;
            }
        }
    }

    // Fallback 2: generic [Bracket] or 【Bracket】 tag in thread_topic
    if let Some(tag) = extract_bracket_topic_fallback(thread_topic) {
        topics.push(tag);
    }

    topics
}

pub fn classify_intent(
    pack: &CompiledDomainPack,
    subj: &str,
    clean_body: &str,
    direction: &str,
    entities: &[String],
) -> String {
    if direction == "system_notice" {
        return "system_notice".to_string();
    }
    let s_tr = trim_ascii_ws(subj);
    for &p in GENERIC_SYS_SUBJ_PREFIXES {
        if starts_with_ci(s_tr, 0, p) {
            return "system_notice".to_string();
        }
    }
    if clean_body.starts_with("SUMMARY:") && clean_body.contains("DTSTART:") {
        return "system_notice".to_string();
    }

    let body_head = utf8_trunc_sv(clean_body, 3500);

    // 1) Evaluate compiled Domain Pack intent rules
    if !pack.intent_rules.is_empty() {
        let mut best_intent: Option<&str> = None;
        let mut best_score = 0.0f64;
        let mut best_pri = i32::MIN;
        for rule in &pack.intent_rules {
            let s_hit = rule.patterns.iter().any(|p| p.is_match(subj));
            let b_hit = !body_head.is_empty() && rule.patterns.iter().any(|p| p.is_match(body_head));
            let score = (if s_hit { 2.2 } else { 0.0 }) + (if b_hit { 1.0 } else { 0.0 });
            if score > 0.0
                && (score > best_score || ((score - best_score).abs() < 0.01 && rule.priority > best_pri))
            {
                best_score = score;
                best_pri = rule.priority;
                best_intent = Some(rule.intent.as_str());
            }
        }
        if let Some(intent) = best_intent {
            return intent.to_string();
        }
    }

    // 2) Zero-pack / unmatched universal commercial & operational intent classifier
    let score_kw = |kws: &[&str], w: f64| -> f64 {
        let mut sc = 0.0;
        let s_hit = kws.iter().any(|&k| contains_ci(subj, k));
        let b_hit = !body_head.is_empty() && kws.iter().any(|&k| contains_ci(body_head, k));
        if s_hit {
            sc += w * 2.2;
        }
        if b_hit {
            sc += w;
        }
        sc
    };

    let mut cands = [
        (
            "pricing_quote",
            score_kw(
                &[
                    "quote",
                    "quotation",
                    "pricing",
                    "unit price",
                    "list price",
                    "moq",
                    "rfq",
                    "discount",
                    "报价",
                    "询价",
                    "核价",
                    "特价",
                    "单价",
                    "总价",
                    "含税",
                    "未税",
                ],
                3.2,
            ),
        ),
        (
            "order_delivery",
            score_kw(
                &[
                    "purchase order",
                    "invoice",
                    "shipment",
                    "delivery",
                    "lead time",
                    "tracking",
                    "schedule",
                    "backlog",
                    "订单",
                    "下单",
                    "交期",
                    "货期",
                    "出货",
                    "发货",
                    "发票",
                ],
                3.0,
            ),
        ),
        (
            "support_issue",
            score_kw(
                &[
                    "support",
                    "troubleshoot",
                    "issue",
                    "bug",
                    "error",
                    "failure",
                    "rma",
                    "warranty",
                    "故障",
                    "异常",
                    "排查",
                    "返修",
                    "维修",
                    "售后",
                    "客诉",
                ],
                3.0,
            ),
        ),
        (
            "compliance_cert",
            score_kw(
                &[
                    "compliance",
                    "certification",
                    "certificate",
                    "audit",
                    "soc2",
                    "gdpr",
                    "hipaa",
                    "认证",
                    "证书",
                    "合规",
                    "检测报告",
                ],
                2.8,
            ),
        ),
        (
            "contract_proposal",
            score_kw(
                &[
                    "rfp",
                    "tender",
                    "bid",
                    "proposal",
                    "contract",
                    "agreement",
                    "renewal",
                    "msa",
                    "sow",
                    "招标",
                    "投标",
                    "标书",
                    "合同",
                    "协议",
                ],
                2.8,
            ),
        ),
    ];

    if has_standalone_word_ci(subj, "PO") {
        cands[1].1 += 6.0;
    }
    if has_standalone_word_ci(body_head, "PO") {
        cands[1].1 += 2.8;
    }
    if !body_head.is_empty() && contains_any_ci(body_head, &["USD", "EUR", "RMB", "CNY", "¥", "$", "€"]) {
        cands[0].1 += 1.4;
    }

    let mut best = &cands[0];
    for c in &cands[1..] {
        if c.1 > best.1 {
            best = c;
        }
    }
    if best.1 >= 2.0 {
        return best.0.to_string();
    }
    if !entities.is_empty() {
        return "technical_discussion".to_string();
    }
    "general_discussion".to_string()
}

fn has_standalone_word_ci(hay: &str, word: &str) -> bool {
    let sb = hay.as_bytes();
    let mut pos = 0;
    while let Some(hit) = find_ci(hay, word, pos) {
        let l = hit == 0 || !sb[hit - 1].is_ascii_alphanumeric();
        let r = hit + word.len() >= sb.len() || !sb[hit + word.len()].is_ascii_alphanumeric();
        if l && r {
            return true;
        }
        pos = hit + word.len();
    }
    false
}

pub fn clean_body_for_meaning(raw_body: &str) -> String {
    if raw_body.is_empty() {
        return String::new();
    }
    let s = crate::html::decode_html_entities_utf8(raw_body);
    let mut cleaned = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if matches!(
            ch,
            '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{200E}' | '\u{200F}' | '\u{FEFF}'
        ) {
            continue;
        }
        if ch == '\u{00A0}' || ch == '\u{3000}' {
            cleaned.push(' ');
            continue;
        }
        if ch == '\r' {
            if chars.peek() != Some(&'\n') {
                cleaned.push('\n');
            }
            continue;
        }
        cleaned.push(ch);
    }

    let strip_banner = |txt: &mut String, marker: &str| {
        if let Some(p) = find_ci(txt, marker, 0) {
            if p < 600 {
                if let Some(nl_rel) = txt[p..].find('\n') {
                    txt.drain(p..p + nl_rel + 1);
                } else {
                    txt.truncate(p);
                }
            }
        }
    };
    strip_banner(&mut cleaned, "Caution: This is an external email.");
    strip_banner(&mut cleaned, "注意：这是一封外部邮件");
    strip_banner(&mut cleaned, "注意：這是一封外部郵件");

    let mut no_urls = String::with_capacity(cleaned.len());
    let cb = cleaned.as_bytes();
    let mut i = 0;
    while i < cb.len() {
        let b = cb[i];
        if (b == b'<' || b == b'h' || b == b'H')
            && (starts_with_ci(&cleaned, i, "https://")
                || starts_with_ci(&cleaned, i, "http://")
                || starts_with_ci(&cleaned, i, "<https://")
                || starts_with_ci(&cleaned, i, "<http://")
                || starts_with_ci(&cleaned, i, "<mailto:"))
        {
            let mut e = i + 1;
            while e < cb.len()
                && !mailkb_core::strutil::is_ascii_ws_byte(cb[e])
                && cb[e] != b'>'
                && cb[e] != b'"'
                && cb[e] != b'\''
            {
                e += 1;
            }
            if e < cb.len() && cb[e] == b'>' {
                e += 1;
            }
            i = e;
            continue;
        }
        if b == b'['
            && i + 5 < cb.len()
            && (starts_with_ci(&cleaned, i, "[cid:") || starts_with_ci(&cleaned, i, "[image"))
        {
            if let Some(rb_rel) = cleaned[i + 1..].find(']') {
                if rb_rel + 1 < 160 {
                    i = i + 1 + rb_rel + 1;
                    continue;
                }
            }
        }
        let ch = cleaned[i..].chars().next().unwrap();
        no_urls.push(ch);
        i += ch.len_utf8();
    }

    let mut kept: Vec<String> = Vec::new();
    let mut prev_line = String::new();
    for raw_ln in no_urls.split('\n') {
        let ls = collapse_ws(raw_ln);
        if ls.is_empty() || ls == prev_line {
            continue;
        }
        prev_line = ls.clone();

        if ls.starts_with("-----Original Message-----")
            || ls.starts_with("----- 原始邮件 -----")
            || ls.starts_with("________")
            || starts_with_ci(&ls, 0, "From:")
            || ls.starts_with("发件人:")
            || ls.starts_with("发件人：")
            || ls.starts_with("寄件者:")
            || starts_with_ci(&ls, 0, "Begin forwarded message:")
        {
            break;
        }
        if starts_with_ci(&ls, 0, "Best regards")
            || starts_with_ci(&ls, 0, "Thanks & Regards")
            || starts_with_ci(&ls, 0, "Kind regards")
            || starts_with_ci(&ls, 0, "Sincerely")
            || starts_with_ci(&ls, 0, "B.R.")
            || ls.starts_with("顺颂商祺")
            || ls.starts_with("祝好")
            || ls.starts_with("此致")
            || starts_with_ci(&ls, 0, "Tel:")
            || starts_with_ci(&ls, 0, "Mobile:")
            || ls.starts_with("电话:")
            || ls.starts_with("电话：")
        {
            if !kept.is_empty() {
                break;
            }
            continue;
        }
        if matches!(
            ls.as_str(),
            "Hi" | "Hello" | "Dear" | "您好" | "你好" | "Hi all," | "Hi All," | "各位好" | "大家好"
        ) {
            continue;
        }
        if ls.len() > 140 && !ls.contains(' ') {
            continue;
        }
        kept.push(ls);
        if kept.len() >= 160 {
            break;
        }
    }

    if kept.len() >= 2 && kept.len().is_multiple_of(2) {
        let half = kept.len() / 2;
        if kept[..half] == kept[half..] {
            kept.truncate(half);
        }
    }

    kept.join("\n")
}

pub fn clip_meaning_cleanly(text: &str, max_chars: usize) -> String {
    let s = collapse_ws(text);
    if utf8_char_len(&s) <= max_chars {
        return s;
    }
    let cut = utf8_slice_chars(&s, max_chars.saturating_sub(1));
    let half = cut.len() / 2;
    for sep in ["。", "；", "，", ";", ","] {
        if let Some(p) = cut.rfind(sep) {
            if p >= 45.max(half) {
                let mut r = cut[..p + sep.len()].to_string();
                if r.ends_with("，") {
                    r.truncate(r.len() - "，".len());
                } else if r.ends_with(',') {
                    r.pop();
                }
                return r;
            }
        }
    }
    if let Some(dp) = cut.rfind(". ") {
        if dp >= 45.max(half) {
            return cut[..dp + 1].to_string();
        }
    }
    format!("{cut}…")
}

#[allow(clippy::too_many_arguments)]
pub fn build_summary_line(
    subj: &str,
    sender: &str,
    clean_body: &str,
    intent: &str,
    thread_topic: &str,
    entities: &[String],
    topics: &[String],
    orgs: &[String],
    tables: &[Table2D],
    is_preview_only: bool,
) -> String {
    let finalize = |s: &str| -> String {
        if is_preview_only {
            let mut b = clip_meaning_cleanly(s, 148);
            if !b.contains("[preview]") {
                b.push_str(" [preview]");
            }
            b
        } else {
            clip_meaning_cleanly(s, 158)
        }
    };

    let t_label = if thread_topic.is_empty() {
        "email"
    } else {
        thread_topic
    };
    let who_raw = trim_ascii_ws(sender.split('<').next().unwrap_or(sender));
    let who = if who_raw.is_empty() { "Sender" } else { who_raw };
    let primary_topic = topics.first().map(String::as_str).unwrap_or("");

    if subj.starts_with("自动回复")
        || subj.starts_with("自动答复")
        || starts_with_ci(subj, 0, "Automatic reply")
        || starts_with_ci(subj, 0, "Out of Office")
    {
        let flat = collapse_ws(clean_body);
        let snip = utf8_slice_chars(&flat, 80);
        return finalize(&format!("[{intent}] Auto-reply from {who} ({t_label}): {snip}"));
    }

    struct Sent {
        sc: f64,
        idx: usize,
        text: String,
    }
    let mut scored: Vec<Sent> = Vec::new();
    let mut idx = 0usize;
    let cb = utf8_trunc_sv(clean_body, 6000);
    for ln in cb.split('\n') {
        if idx >= 80 {
            break;
        }
        let l = trim_ascii_ws(ln);
        let clen = utf8_char_len(l);
        if clen < 3 {
            continue;
        }
        if matches!(
            l,
            "收到" | "好的" | "谢谢" | "辛苦了" | "OK" | "ok" | "Thanks" | "Noted" | "Thank you"
        ) {
            continue;
        }
        let mut sc = 0.0;
        if contains_any_ci(
            l,
            &[
                "USD", "EUR", "RMB", "CNY", "¥", "$", "€", "元", "pcs", "units", "台", "套",
                "week", "weeks", "周", "%", "MOQ",
            ],
        ) {
            sc += 4.5;
        }
        if l.bytes().any(|b| b.is_ascii_digit()) {
            sc += 1.5;
        }
        if contains_any_ci(
            l,
            &[
                "confirm", "approve", "quote", "price", "support", "order", "deliver", "ship",
                "update", "schedule", "issue", "request", "确认", "申请", "报价", "支持", "批准",
                "修改", "变更", "需要", "提供", "安排", "预计", "交期", "货期", "回复", "问题",
                "故障", "测试",
            ],
        ) {
            sc += 3.0;
        }
        if entities.iter().take(3).any(|s| contains_ci(l, s)) {
            sc += 2.0;
        }
        if !primary_topic.is_empty() && l.contains(utf8_slice_chars(primary_topic, 2)) {
            sc += 1.5;
        }
        if clen < 8 {
            sc -= 2.0;
        }
        if idx < 4 {
            sc += 0.5;
        }
        scored.push(Sent {
            sc,
            idx,
            text: l.to_string(),
        });
        idx += 1;
    }

    scored.sort_by(|a, b| b.sc.total_cmp(&a.sc).then_with(|| a.idx.cmp(&b.idx)));

    let mut chosen: Vec<Sent> = Vec::new();
    let mut tchars = 0usize;
    for s in scored.into_iter().take(4) {
        let clen = utf8_char_len(&s.text);
        if chosen.is_empty() || tchars + clen <= 115 {
            tchars += clen;
            chosen.push(s);
        }
        if tchars >= 85 {
            break;
        }
    }
    chosen.sort_by_key(|c| c.idx);
    let mut chosen_text = chosen
        .into_iter()
        .map(|c| c.text)
        .collect::<Vec<_>>()
        .join(" ");

    if !tables.is_empty() {
        let mut tbl_parts = Vec::new();
        for t in tables.iter().take(2) {
            if t.len() < 2 {
                continue;
            }
            let scells = t[1]
                .iter()
                .filter(|c| !c.is_empty())
                .take(3)
                .map(|c| utf8_slice_chars(c, 16))
                .collect::<Vec<_>>()
                .join("/");
            if !scells.is_empty() {
                tbl_parts.push(format!("{} rows ({scells})", t.len() - 1));
            }
        }
        if !tbl_parts.is_empty() {
            let tbl_s = tbl_parts.join(", ");
            if chosen_text.is_empty() {
                chosen_text = tbl_s;
            } else {
                chosen_text = format!("{chosen_text} [{tbl_s}]");
            }
        }
    }

    let mut ctx_miss = String::new();
    if let Some(org) = orgs.first() {
        ctx_miss.push_str(org);
    }
    if !primary_topic.is_empty() && !t_label.contains(utf8_slice_chars(primary_topic, 3)) {
        if !ctx_miss.is_empty() {
            ctx_miss.push_str(", ");
        }
        ctx_miss.push_str(primary_topic);
    }

    if chosen_text.is_empty() {
        let flat = collapse_ws(clean_body);
        let sc = utf8_slice_chars(&flat, 45);
        if !sc.is_empty() {
            return finalize(&format!("[{intent}] {who} re \"{t_label}\": {sc}"));
        }
        let ent_part = if entities.is_empty() {
            String::new()
        } else {
            format!(" ({})", entities.iter().take(2).cloned().collect::<Vec<_>>().join(", "))
        };
        return finalize(&format!("[{intent}] \"{t_label}\"{ent_part}"));
    }

    let mut head = format!("[{intent}] \"{}\"", utf8_slice_chars(t_label, 34));
    if !ctx_miss.is_empty() {
        head.push_str(&format!(" ({ctx_miss})"));
    }
    head.push_str(": ");
    head.push_str(&chosen_text);
    finalize(&head)
}

fn iso_date_regex() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| Regex::new(r"\b(20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))\b").unwrap())
}

pub fn extract_event_dates_json(date_iso: &str, subj: &str, clean_body: &str) -> String {
    let mut sent_date = String::new();
    let mut sent_ym = String::new();
    let mut sent_quarter = String::new();
    if date_iso.len() >= 10 && date_iso.as_bytes()[4] == b'-' && date_iso.as_bytes()[7] == b'-' {
        if let (Ok(y), Ok(m), Ok(d)) = (
            date_iso[0..4].parse::<i32>(),
            date_iso[5..7].parse::<u32>(),
            date_iso[8..10].parse::<u32>(),
        ) {
            if y >= 1990 && (1..=12).contains(&m) && (1..=31).contains(&d) {
                sent_date = format!("{y:04}-{m:02}-{d:02}");
                sent_ym = sent_date[..7].to_string();
                sent_quarter = format!("{y:04}-Q{}", (m - 1) / 3 + 1);
            }
        }
    }

    let txt = format!("{subj}\n{}", utf8_trunc_sv(clean_body, 3000));
    let tb = txt.as_bytes();
    let mut lead_times: Vec<String> = Vec::new();
    let mut i = 0;
    while i < tb.len() && lead_times.len() < 6 {
        if tb[i].is_ascii_digit() {
            let mut j = i;
            while j < tb.len() && (tb[j].is_ascii_digit() || tb[j] == b'-' || tb[j] == b'~') {
                j += 1;
            }
            if j > i && j - i <= 6 && j < tb.len() {
                let mut after = safe_slice_after(&txt, j, 10);
                after = after.trim_start_matches(' ');
                if after.starts_with('周')
                    || starts_with_ci(after, 0, "weeks")
                    || starts_with_ci(after, 0, "week")
                    || starts_with_ci(after, 0, "wks")
                {
                    let ctx_start =
                        mailkb_core::strutil::ceil_char_boundary_idx(&txt, i.saturating_sub(24));
                    let ctx_end =
                        mailkb_core::strutil::floor_char_boundary_idx(&txt, (j + 6).min(tb.len()));
                    let ctx = if ctx_start <= ctx_end {
                        &txt[ctx_start..ctx_end]
                    } else {
                        ""
                    };
                    if contains_any_ci(
                        ctx,
                        &["货期", "交期", "交货", "交付", "lead", "lt", "周", "week", "wk"],
                    ) {
                        let unit = if after.starts_with('周') {
                            "周"
                        } else {
                            " weeks"
                        };
                        let lt = format!("{}{unit}", &txt[i..j]);
                        if !lead_times.contains(&lt) {
                            lead_times.push(lt);
                        }
                    }
                }
            }
            i = j;
        } else {
            i += 1;
        }
    }

    let mut mentioned_dates: Vec<String> = Vec::new();
    let mut valid_until: Vec<String> = Vec::new();
    for m in iso_date_regex().find_iter(&txt) {
        let d = m.as_str().to_string();
        let before = safe_slice_before(&txt, m.start(), 28);
        if contains_any_ci(
            before,
            &["valid until", "valid thru", "validity", "expires", "expiry", "有效期", "有效至"],
        ) {
            if !valid_until.contains(&d) && valid_until.len() < 4 {
                valid_until.push(d.clone());
            }
        }
        if d != sent_date && !mentioned_dates.contains(&d) && mentioned_dates.len() < 8 {
            mentioned_dates.push(d);
        }
    }

    let root: Value = json!({
        "sent_date": sent_date,
        "sent_ym": sent_ym,
        "sent_quarter": sent_quarter,
        "lead_times": lead_times,
        "mentioned_dates": mentioned_dates,
        "valid_until": valid_until,
    });
    serde_json::to_string(&root).unwrap_or_else(|_| "{}".to_string())
}

pub fn is_excluded_amount_message(
    pack: &CompiledDomainPack,
    identity: &ResolvedIdentity,
    subject: &str,
    sender: &str,
) -> bool {
    let s_emails = extract_emails(sender);
    for em in &s_emails {
        if identity.system_senders.contains(&em.addr) || identity.system_domains.contains(&em.domain) {
            return true;
        }
    }
    const GENERIC_EXCL_SENDERS: &[&str] = &[
        "no-reply@microsoft.com",
        "no-reply@teams.mail.microsoft",
        "ctrip.com",
        "booking.com",
        "agoda.com",
        "airbnb.com",
        "12306",
    ];
    if contains_any_ci(sender, GENERIC_EXCL_SENDERS) {
        return true;
    }
    if pack
        .amount_exclude_subjects
        .iter()
        .any(|p| p.is_match(subject))
    {
        return true;
    }
    if contains_any_ci(
        subject,
        &[
            "机票出票确认单",
            "机票成交",
            "机票待审批",
            "行程单",
            "酒店预订",
            "酒店住宿",
            "住宿费用",
            "入住确认",
            "Check in online",
            "差旅报销",
            "Newsletter",
            "Webinar",
        ],
    ) {
        return true;
    }
    false
}

pub fn determine_context_role(subject: &str, intent_type: &str) -> String {
    if contains_any_ci(
        subject,
        &["特价", "价格申请", "价格沟通", "价格授权", "SPR", "special price"],
    ) {
        return "special_price".to_string();
    }
    if intent_type == "pricing_quote"
        || contains_any_ci(subject, &["报价", "询价", "Quotation", "Quote", "Pricing", "Price"])
    {
        return "quote".to_string();
    }
    if intent_type == "order_delivery"
        || contains_any_ci(subject, &["订单", "订货", "Purchase Order", "交期", "出货"])
        || has_standalone_word_ci(subject, "PO")
    {
        return "order".to_string();
    }
    if contains_any_ci(subject, &["样机", "测试", "FAI", "Pilot", "Trial", "Sample"]) {
        return "sample_test".to_string();
    }
    if contains_any_ci(subject, &["停产", "PCN", "EOL", "PDN", "Deprecation"]) {
        return "pcn_eol".to_string();
    }
    "general_mention".to_string()
}

pub fn apply_currency_alias(raw_curr: &str, pack: &CompiledDomainPack) -> String {
    let up = raw_curr.trim().to_ascii_uppercase();
    if up.is_empty() {
        return String::new();
    }
    if let Some(mapped) = pack.currency_aliases.get(&up) {
        return mapped.clone();
    }
    up
}

pub fn detect_currency_str(
    txt: &str,
    default_cjk_rmb: bool,
    pack: &CompiledDomainPack,
) -> String {
    let detected = if contains_any_ci(txt, &["NTD", "NT$", "TWD", "新台币"]) {
        "TWD"
    } else if contains_any_ci(txt, &["USD", "US$", "美元", "美金"]) {
        "USD"
    } else if contains_any_ci(txt, &["EUR", "欧元", "€"]) {
        "EUR"
    } else if contains_any_ci(txt, &["GBP", "英镑", "£"]) {
        "GBP"
    } else if contains_any_ci(txt, &["HKD", "HK$", "港币"]) {
        "HKD"
    } else if contains_any_ci(txt, &["SGD", "S$"]) {
        "SGD"
    } else if contains_any_ci(txt, &["CAD", "C$"]) {
        "CAD"
    } else if contains_any_ci(txt, &["AUD", "A$"]) {
        "AUD"
    } else if contains_any_ci(txt, &["JPY", "日元", "円"]) {
        "JPY"
    } else if contains_any_ci(txt, &["RMB", "CNY", "¥", "￥", "人民币"]) {
        "RMB"
    } else if txt.contains('$') {
        if contains_any_ci(txt, &["NT", "TWD"]) {
            "TWD"
        } else {
            "USD"
        }
    } else if default_cjk_rmb && txt.contains('元') {
        "RMB"
    } else {
        ""
    };
    apply_currency_alias(detected, pack)
}

pub fn detect_tax_mode_str(txt: &str) -> String {
    if contains_any_ci(
        txt,
        &[
            "未税",
            "未稅",
            "不含税",
            "不含稅",
            "excl. vat",
            "excl vat",
            "excl. tax",
            "excl tax",
            "without vat",
            "without tax",
            "tax excluded",
            "ex-tax",
        ],
    ) {
        return "未税".to_string();
    }
    if contains_any_ci(
        txt,
        &[
            "含税",
            "含稅",
            "incl. vat",
            "incl vat",
            "incl. tax",
            "incl tax",
            "with vat",
            "tax included",
            "13%",
        ],
    ) {
        return "含税".to_string();
    }
    String::new()
}

pub fn detect_amount_type_and_conf(
    txt: &str,
    default_type: &str,
    default_conf: Option<&str>,
    pack: &CompiledDomainPack,
) -> (String, Option<String>) {
    for rule in &pack.amount_type_rules {
        if rule.patterns.iter().any(|p| p.is_match(txt)) {
            return (rule.amount_type.clone(), rule.confidence.clone());
        }
    }
    let fallback = if contains_any_ci(txt, &["采购", "成本", "进货", "cost"]) {
        "cost"
    } else if contains_any_ci(txt, &["List Price", "公开价", "目录价", "标准价", "MSRP"]) {
        "list_price"
    } else if contains_any_ci(txt, &["历史价", "歷史價", "历史价格", "historical"]) {
        "historical_price"
    } else if contains_any_ci(txt, &["order price", "po price", "订单价", "采购价"]) {
        "order_price"
    } else {
        default_type
    };
    (fallback.to_string(), default_conf.map(String::from))
}

pub fn parse_price_number(num_sv: &str, scale_sv: &str) -> f64 {
    let clean: String = num_sv
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if clean.is_empty() {
        return -1.0;
    }
    let Ok(mut v) = clean.parse::<f64>() else {
        return -1.0;
    };
    if !v.is_finite() || v <= 0.0 {
        return -1.0;
    }
    if !scale_sv.is_empty() {
        if contains_any_ci(scale_sv, &["k", "千"]) {
            v *= 1000.0;
        } else if contains_any_ci(scale_sv, &["w", "万"]) {
            v *= 10000.0;
        }
    }
    v
}

pub fn classify_table_col(hdr: &str) -> &'static str {
    let h = collapse_ws(hdr);
    if h.is_empty() {
        return "other";
    }
    if contains_any_ci(&h, &["汇率", "exchange rate"])
        && !contains_any_ci(&h, &["单价", "price"])
    {
        return "ignore";
    }
    let hl = h.to_ascii_lowercase();
    if matches!(
        hl.as_str(),
        "序号"
            | "no"
            | "no."
            | "#"
            | "line"
            | "hs code"
            | "vendor"
            | "interface"
            | "speed"
            | "size"
            | "uom"
            | "unit"
    ) {
        return "ignore";
    }
    if contains_any_ci(
        &h,
        &[
            "型号",
            "型號",
            "机型",
            "料号",
            "part no",
            "part number",
            "part #",
            "model",
            "sku",
            "mpn",
            "item code",
            "product code",
        ],
    ) {
        return "sku";
    }
    if contains_any_ci(
        &h,
        &[
            "进货商",
            "客户",
            "经销商",
            "customer",
            "client",
            "buyer",
            "organization",
            "company",
            "account",
        ],
    ) {
        return "customer";
    }
    if contains_any_ci(
        &h,
        &["project name", "项目名称", "专案", "project", "topic", "deal", "opportunity"],
    ) {
        return "project";
    }
    if contains_any_ci(
        &h,
        &[
            "总价",
            "總價",
            "金额",
            "金額",
            "小计",
            "合计",
            "total",
            "amount",
            "subtotal",
            "extended price",
            "ext. price",
            "arr",
            "tcv",
            "acv",
        ],
    ) {
        return "total";
    }
    if contains_any_ci(
        &h,
        &[
            "单价",
            "單價",
            "未税价",
            "含税价",
            "未稅價",
            "含稅價",
            "历史价",
            "歷史價",
            "申请未税",
            "申请含税",
            "申请单价",
            "申请价格",
            "申请报价",
            "支持未税",
            "支持含税",
            "支持单价",
            "支持价格",
            "unit price",
            "selling price",
            "list price",
            "net price",
            "rate",
            "price",
            "价格",
            "價格",
            "cost",
            "fee",
        ],
    ) {
        return "unit_price";
    }
    if contains_any_ci(
        &h,
        &["总数量", "總數量", "数量", "數量", "qty", "quantity", "q'ty", "订购数量", "seats", "users"],
    ) {
        return "qty";
    }
    if contains_any_ci(&h, &["moq", "起订量", "minimum order"]) {
        return "moq";
    }
    if contains_any_ci(&h, &["交期", "货期", "lead time", "l/t", "delivery"]) {
        return "lead_time";
    }
    if contains_any_ci(&h, &["折扣", "discount", "rebate"]) {
        return "discount";
    }
    if contains_any_ci(&h, &["valid until", "validity", "expires", "有效期", "有效至"]) {
        return "valid_until";
    }
    if contains_any_ci(&h, &["名称", "名稱", "描述", "description", "产品", "品名", "item", "plan", "tier"])
    {
        return "desc";
    }
    "other"
}

fn moq_inline_regex() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(r"(?i)\bMOQ\s*[:=]?\s*(\d+(?:\s*(?:pcs|pc|units|sets|台|套))?)").unwrap()
    })
}

fn lead_time_inline_regex() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(r"(?i)(?:lead\s*time|L/T|交期|货期)\s*[:：=]?\s*(\d+(?:\s*[-~]\s*\d+)?\s*(?:weeks?|wks?|days?|months?|周|天|个月))").unwrap()
    })
}

fn discount_inline_regex() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(r"(?i)(?:(\d+(?:\.\d+)?%\s*(?:off|discount))|(?:discount\s*(?:of\s*)?\d+(?:\.\d+)?%)|(\d+(?:\.\d+)?折))").unwrap()
    })
}

fn extract_inline_terms(line: &str) -> (String, String, String, String) {
    let moq = moq_inline_regex()
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| collapse_ws(m.as_str()))
        .unwrap_or_default();
    let lt = lead_time_inline_regex()
        .captures(line)
        .and_then(|c| c.get(1))
        .map(|m| collapse_ws(m.as_str()))
        .unwrap_or_default();
    let disc = discount_inline_regex()
        .find(line)
        .map(|m| collapse_ws(m.as_str()))
        .unwrap_or_default();
    let valid_until = iso_date_regex()
        .find_iter(line)
        .find(|m| {
            let bef = safe_slice_before(line, m.start(), 24);
            contains_any_ci(bef, &["valid", "expires", "expiry", "有效期", "有效至"])
        })
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    (moq, lt, disc, valid_until)
}

pub fn build_terms_json(moq: &str, lead_time: &str, discount_info: &str) -> String {
    if moq.is_empty() && lead_time.is_empty() && discount_info.is_empty() {
        return "{}".to_string();
    }
    let mut map = Map::new();
    if !moq.is_empty() {
        map.insert("moq".to_string(), Value::String(moq.to_string()));
    }
    if !lead_time.is_empty() {
        map.insert("lead_time".to_string(), Value::String(lead_time.to_string()));
    }
    if !discount_info.is_empty() {
        map.insert(
            "discount_info".to_string(),
            Value::String(discount_info.to_string()),
        );
    }
    serde_json::to_string(&Value::Object(map)).unwrap_or_else(|_| "{}".to_string())
}

pub fn is_false_price_context(
    line: &str,
    num_start: usize,
    num_end: usize,
    val: f64,
    has_explicit_curr: bool,
) -> bool {
    if val <= 0.0 || val > 50_000_000.0 {
        return true;
    }
    let raw_num = &line[num_start..num_end];
    let digits = raw_num.bytes().filter(|b| b.is_ascii_digit()).count();
    if digits >= 9 {
        return true;
    }
    if val < 10.0 && !(has_explicit_curr && val >= 1.0) {
        return true;
    }

    let before = safe_slice_before(line, num_start, 36);
    let after = safe_slice_after(line, num_end, 28);
    let bs = num_start - before.len();
    let win_end = num_end + after.len();
    let window = &line[bs..win_end];

    if contains_any_ci(
        before,
        &[
            "EN ", "EN-", "IEC ", "IEC-", "IEEE ", "GB/T", "TB/T", "ETSI ", "UL ", "CSA ",
            "CISPR", "ISO ", "RFC ",
        ],
    ) {
        return true;
    }

    let aft_t = after.trim_start_matches(' ');
    if aft_t.starts_with('%')
        || aft_t.starts_with('％')
        || aft_t.starts_with("个点")
        || aft_t.starts_with('折')
        || aft_t.starts_with('倍')
        || aft_t.starts_with('年')
        || aft_t.starts_with('月')
    {
        return true;
    }

    if contains_any_ci(
        before,
        &[
            "增加", "涨价", "漲價", "上涨", "上调", "上調", "下调", "下調", "降价", "降價",
            "差价", "差價", "价差", "相差", "加了", "减了", "涨了", "降了", "加价", "便宜",
            "优惠", "上浮", "波动", "压低", "省下",
        ],
    ) {
        return true;
    }
    if contains_any_ci(
        aft_t,
        &[
            "降价", "降價", "涨价", "漲價", "加价", "减价", "降幅", "涨幅", "差价", "优惠",
            "折扣",
        ],
    ) {
        return true;
    }

    if !has_explicit_curr && raw_num.len() == 4 && raw_num.starts_with("20") {
        let rb = raw_num.as_bytes();
        if matches!(rb[2], b'1' | b'2' | b'3') {
            return true;
        }
    }

    if (1.0..=20.0).contains(&val) && contains_any_ci(window, &["汇率", "中间价", "exchange rate"]) {
        return true;
    }

    if aft_t.starts_with("元/人") || aft_t.starts_with("/人") {
        return true;
    }
    if !has_explicit_curr && !after.is_empty() {
        let ab = after.as_bytes()[0];
        let atb = aft_t.as_bytes();
        let is_unit_after = ab.is_ascii_alphabetic() && !matches!(ab, b'k' | b'K' | b'w' | b'W');
        let is_electrical = !atb.is_empty()
            && matches!(atb[0], b'A' | b'a' | b'V' | b'v' | b'W' | b'w')
            && (atb.len() == 1 || !atb[1].is_ascii_alphanumeric());
        if is_unit_after || is_electrical {
            return true;
        }
    }
    if !has_explicit_curr
        && contains_any_ci(
            aft_t,
            &[
                "VDC", "VAC", "mA", "kW", "MHz", "GHz", "Hz", "Mbps", "Gbps", "KB", "MB", "GB",
                "TB", "mm", "cm", "kg", "℃", "°C", "hrs", "wks", "weeks",
            ],
        )
    {
        return true;
    }
    if !has_explicit_curr
        && (starts_with_ci(aft_t, 0, "pcs")
            || starts_with_ci(aft_t, 0, "pc")
            || aft_t.starts_with('台')
            || aft_t.starts_with('套')
            || aft_t.starts_with('个')
            || aft_t.starts_with('只'))
    {
        return true;
    }

    if contains_any_ci(
        before,
        &[
            "Tel:", "Fax:", "Mobile:", "电话", "手机", "工号", "订单号", "MOQ=", "MOQ:",
            "192.168.",
        ],
    ) {
        return true;
    }

    if before.ends_with('-')
        && before.len() >= 2
        && before.as_bytes()[before.len() - 2].is_ascii_alphanumeric()
    {
        return true;
    }
    if after.starts_with('-')
        && after.len() >= 2
        && after.as_bytes()[1].is_ascii_alphanumeric()
    {
        return true;
    }

    if contains_any_ci(
        window,
        &[
            "房费", "机票", "航意险", "民航基金", "餐费", "打车费", "报销", "元/人", "/人",
            "每人", "人均", "团费", "导游", "门票", "旅游", "行程",
        ],
    ) {
        return true;
    }

    false
}

#[allow(clippy::too_many_arguments)]
pub fn extract_amounts_from_body(
    text: &str,
    pack: &CompiledDomainPack,
    topic_name: &str,
    org_name: &str,
    effective_date_iso: &str,
    default_tax_mode: &str,
    subject_single_entity: &str,
    source_kind: &str,
    is_preview_only: bool,
    out_amounts: &mut Vec<AmountRow>,
) {
    if text.is_empty() {
        return;
    }
    if contains_any_ci(
        text,
        &[
            "首日房费",
            "机票款",
            "民航基金",
            "航意险",
            "退票费",
            "酒店入住",
            "酒店城市",
            "离店日期",
            "间夜",
            "元/晚",
            "二人一间",
            "元/人",
            "旅游团",
        ],
    ) {
        return;
    }

    struct RecentEntities {
        ne_idx: i32,
        entities: Vec<MatchedCode>,
    }
    let mut recent: Vec<RecentEntities> = Vec::new();
    let mut ne_idx: i32 = 0;

    for raw_ln in text.split('\n') {
        let line = collapse_ws(raw_ln);
        if line.is_empty() {
            continue;
        }
        ne_idx += 1;

        if starts_with_ci(&line, 0, "Hi ")
            || starts_with_ci(&line, 0, "Dear ")
            || line.starts_with("您好")
            || line.starts_with("各位")
            || starts_with_ci(&line, 0, "From:")
            || line.starts_with("发件人:")
            || line.starts_with("____")
        {
            recent.clear();
        }

        let line_codes = extract_item_codes(&line, pack);
        if contains_any_ci(&line, &["汇率", "exchange rate"])
            && !contains_any_ci(&line, &["单价", "价格", "未税", "含税", "price"])
        {
            if !line_codes.is_empty() {
                recent.push(RecentEntities {
                    ne_idx,
                    entities: line_codes,
                });
                if recent.len() > 3 {
                    recent.remove(0);
                }
            }
            continue;
        }

        struct Cand {
            val: f64,
            curr: String,
            tax: String,
            atype: String,
            conf_override: Option<String>,
            is_total: bool,
        }
        let mut cands: Vec<Cand> = Vec::new();
        let lb = line.as_bytes();
        let mut i = 0;
        while i < lb.len() {
            if !lb[i].is_ascii_digit() {
                i += 1;
                continue;
            }
            if i > 0 && (lb[i - 1].is_ascii_alphanumeric() || lb[i - 1] == b'.') {
                i += 1;
                continue;
            }
            let mut ne = i;
            while ne < lb.len() && (lb[ne].is_ascii_digit() || lb[ne] == b',' || lb[ne] == b'.')
            {
                if (lb[ne] == b',' || lb[ne] == b'.')
                    && (ne + 1 >= lb.len() || !lb[ne + 1].is_ascii_digit())
                {
                    break;
                }
                ne += 1;
            }
            if ne == i {
                i += 1;
                continue;
            }

            let pre_sv = safe_slice_before(&line, i, 18);
            let pre_curr = detect_currency_str(pre_sv, false, pack);
            let mut has_pre_curr = false;
            if !pre_curr.is_empty() {
                let mut tail = pre_sv.trim_end_matches([' ', ':']);
                if tail.ends_with('：') {
                    tail = &tail[..tail.len() - '：'.len_utf8()];
                }
                if !tail.is_empty()
                    && !detect_currency_str(safe_slice_before(tail, tail.len(), 6), false, pack)
                        .is_empty()
                {
                    has_pre_curr = true;
                }
            }

            let mut aft_p = ne;
            while aft_p < lb.len() && lb[aft_p] == b' ' {
                aft_p += 1;
            }
            let mut scale_sv = "";
            if aft_p < lb.len() {
                if matches!(lb[aft_p], b'k' | b'K' | b'w' | b'W') {
                    if aft_p + 1 == lb.len() || !lb[aft_p + 1].is_ascii_alphabetic() {
                        scale_sv = &line[aft_p..aft_p + 1];
                        aft_p += 1;
                    }
                } else if line[aft_p..].starts_with('万') || line[aft_p..].starts_with('千') {
                    scale_sv = &line[aft_p..aft_p + 3];
                    aft_p += 3;
                }
            }
            while aft_p < lb.len() && lb[aft_p] == b' ' {
                aft_p += 1;
            }

            let post_sv = safe_slice_after(&line, aft_p, 16);
            let raw_post_curr = if post_sv.starts_with('¥')
                || post_sv.starts_with('￥')
                || starts_with_ci(post_sv, 0, "RMB")
                || starts_with_ci(post_sv, 0, "CNY")
                || post_sv.starts_with('元')
            {
                "RMB"
            } else if starts_with_ci(post_sv, 0, "USD")
                || post_sv.starts_with("美金")
                || post_sv.starts_with("美元")
            {
                "USD"
            } else if starts_with_ci(post_sv, 0, "EUR") || post_sv.starts_with("欧元") {
                "EUR"
            } else if starts_with_ci(post_sv, 0, "GBP") {
                "GBP"
            } else if starts_with_ci(post_sv, 0, "TWD") || starts_with_ci(post_sv, 0, "NTD") {
                "TWD"
            } else if starts_with_ci(post_sv, 0, "HKD") {
                "HKD"
            } else if starts_with_ci(post_sv, 0, "JPY") {
                "JPY"
            } else if starts_with_ci(post_sv, 0, "SGD") {
                "SGD"
            } else {
                ""
            };
            let post_curr = apply_currency_alias(raw_post_curr, pack);

            let has_explicit_curr = has_pre_curr || !post_curr.is_empty();
            let has_price_kw = contains_any_ci(
                pre_sv,
                &[
                    "单价",
                    "未税",
                    "含税",
                    "报价",
                    "特价",
                    "申请价",
                    "支持价",
                    "出货价",
                    "采购价",
                    "Unit Price",
                    "Selling Price",
                    "List Price",
                    "Net Price",
                    "Price",
                    "价格",
                ],
            );

            if !has_explicit_curr && !has_price_kw {
                i = ne;
                continue;
            }

            let val = parse_price_number(&line[i..ne], scale_sv);
            if val <= 0.0 || is_false_price_context(&line, i, ne, val, has_explicit_curr) {
                i = ne;
                continue;
            }
            if is_preview_only
                && ne + 3 >= lb.len()
                && post_curr.is_empty()
                && scale_sv.is_empty()
            {
                i = ne;
                continue;
            }

            let mut curr = if !post_curr.is_empty() {
                post_curr
            } else if !pre_curr.is_empty() {
                pre_curr
            } else {
                detect_currency_str(&line, true, pack)
            };
            if curr.is_empty() {
                curr = apply_currency_alias("USD", pack);
            }

            let win_before = safe_slice_before(&line, i, 28);
            let win_after = safe_slice_after(&line, ne, 28);
            let loc_win = &line[i - win_before.len()..ne + win_after.len()];

            let mut tax = detect_tax_mode_str(loc_win);
            if tax.is_empty() {
                tax = default_tax_mode.to_string();
            }
            let (mut atype, conf_override) =
                detect_amount_type_and_conf(loc_win, "quote", None, pack);

            let is_total = (contains_any_ci(
                loc_win,
                &[
                    "总价",
                    "總價",
                    "总计",
                    "合计",
                    "总金额",
                    "总报价",
                    "Total Amount",
                    "Total Price",
                    "Order Total",
                    "Grand Total",
                    "Subtotal",
                    "ARR",
                    "TCV",
                    "ACV",
                ],
            ) && !contains_any_ci(loc_win, &["unit price", "单价", "單價"]))
                || (scale_sv == "万"
                    && val >= 50000.0
                    && !contains_any_ci(loc_win, &["/台", "/套", "/pcs"]));
            if is_total && atype == "quote" {
                atype = "project_bid_total".to_string();
            }

            cands.push(Cand {
                val,
                curr,
                tax,
                atype,
                conf_override,
                is_total,
            });
            i = ne;
        }

        if cands.is_empty() {
            if !line_codes.is_empty() {
                recent.push(RecentEntities {
                    ne_idx,
                    entities: line_codes,
                });
                if recent.len() > 3 {
                    recent.remove(0);
                }
            }
            continue;
        }

        let (moq, lead_time, discount_info, valid_until) = extract_inline_terms(&line);
        let terms_json = build_terms_json(&moq, &lead_time, &discount_info);

        let mut target_codes = line_codes.clone();
        if target_codes.is_empty() {
            if let Some(last) = recent.last() {
                if ne_idx - last.ne_idx <= 2
                    && !(last.entities.len() == 1
                        && last.entities[0].category.eq_ignore_ascii_case("Accessory"))
                {
                    target_codes = last.entities.clone();
                }
            }
            if target_codes.is_empty() && !subject_single_entity.is_empty() {
                target_codes.push(MatchedCode {
                    entity_key: subject_single_entity.to_string(),
                    canonical_value: subject_single_entity.to_string(),
                    category: pack.default_category.clone(),
                    sub_group: generic_sub_group(subject_single_entity),
                    extra_terms: Vec::new(),
                    start: 0,
                    end: 0,
                });
            }
        }
        if !line_codes.is_empty()
            && !(line_codes.len() == 1
                && line_codes[0].category.eq_ignore_ascii_case("Accessory"))
        {
            recent.push(RecentEntities {
                ne_idx,
                entities: line_codes.clone(),
            });
            if recent.len() > 3 {
                recent.remove(0);
            }
        }

        for c in cands {
            let mut bound = target_codes.clone();
            if bound.is_empty() {
                if !contains_any_ci(
                    &line,
                    &[
                        "报价",
                        "单价",
                        "未税",
                        "含税",
                        "Selling Price",
                        "Unit Price",
                        "List Price",
                        "Quote",
                    ],
                ) {
                    continue;
                }
                bound.push(MatchedCode {
                    entity_key: String::new(),
                    canonical_value: String::new(),
                    category: pack.default_category.clone(),
                    sub_group: String::new(),
                    extra_terms: Vec::new(),
                    start: 0,
                    end: 0,
                });
            } else if line_codes.is_empty() && bound.len() == 1 {
                let cat_lo = bound[0].category.to_ascii_lowercase();
                if cat_lo != "accessory"
                    && cat_lo != "software"
                    && ((c.curr == "RMB" || c.curr == "CNY") && c.val < 50.0)
                {
                    bound[0].entity_key.clear();
                }
            }
            for ent in bound {
                let rounded = (c.val * 100.0).round() / 100.0;
                let conf = if let Some(ref ov) = c.conf_override {
                    ov.clone()
                } else if !line_codes.is_empty()
                    && !c.curr.is_empty()
                    && (!c.tax.is_empty() || c.atype != "quote")
                {
                    "high".to_string()
                } else {
                    "medium".to_string()
                };
                out_amounts.push(AmountRow {
                    amount_type: c.atype.clone(),
                    subject_entity: ent.entity_key,
                    category: ent.category,
                    topic_name: topic_name.to_string(),
                    org_name: org_name.to_string(),
                    currency: c.curr.clone(),
                    unit_amount: if c.is_total { None } else { Some(rounded) },
                    total_amount: if c.is_total { Some(rounded) } else { None },
                    quantity: None,
                    tax_mode: c.tax.clone(),
                    moq: moq.clone(),
                    lead_time: lead_time.clone(),
                    discount_info: discount_info.clone(),
                    terms_json: terms_json.clone(),
                    effective_date_iso: effective_date_iso.to_string(),
                    valid_until: valid_until.clone(),
                    source_kind: source_kind.to_string(),
                    evidence_snippet: utf8_trunc_sv(&line, 220).to_string(),
                    confidence: conf,
                });
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn extract_from_tables(
    tables: &[Table2D],
    pack: &CompiledDomainPack,
    topic_name: &str,
    org_name: &str,
    effective_date_iso: &str,
    default_tax_mode: &str,
    subject: &str,
    subject_single_entity: &str,
    context_role: &str,
    mut skip_amounts: bool,
    strict_col_align: bool,
    source_kind: &str,
    att_name: &str,
    sheet_curr_hint: &str,
    out_entities: &mut Vec<EntityRow>,
    out_amounts: &mut Vec<AmountRow>,
) {
    if !att_name.is_empty() && contains_any_ci(att_name, &["行程", "机票", "酒店", "旅游"]) {
        skip_amounts = true;
    }

    for table in tables {
        if table.len() < 2 {
            continue;
        }
        let mut flat_top = String::new();
        for r in table.iter().take(12) {
            for c in r {
                flat_top.push_str(c);
                flat_top.push(' ');
            }
        }
        if contains_any_ci(
            &flat_top,
            &[
                "机票费",
                "民航基金",
                "退票条件",
                "首日房费",
                "航意险",
                "酒店城市",
                "入住日期",
                "元/人",
                "团费",
                "导游",
            ],
        ) {
            continue;
        }

        let mut hdr_idx: Option<usize> = None;
        let mut best_score = 0;
        let mut col_roles: Vec<&'static str> = Vec::new();
        for (r, row) in table.iter().take(3).enumerate() {
            if row.len() < 2 {
                continue;
            }
            let roles: Vec<&'static str> = row.iter().map(|c| classify_table_col(c)).collect();
            let has_sku = roles.iter().any(|&x| x == "sku" || x == "desc");
            let has_price = roles.iter().any(|&x| x == "unit_price" || x == "total");
            let has_qty = roles.contains(&"qty");
            let sc = if has_sku { 2 } else { 0 }
                + if has_price { 3 } else { 0 }
                + if has_qty { 1 } else { 0 };
            if sc > best_score {
                best_score = sc;
                hdr_idx = Some(r);
                col_roles = roles;
            }
        }
        if best_score < 3 {
            hdr_idx = None;
        }

        let Some(hi) = hdr_idx else {
            for row in table {
                if row.len() == 2 {
                    let codes = extract_item_codes(&row[0], pack);
                    let q_tr = trim_ascii_ws(&row[1]);
                    if !codes.is_empty()
                        && q_tr.as_bytes().first().is_some_and(|b| b.is_ascii_digit())
                    {
                        let qv = parse_price_number(q_tr, "");
                        if qv > 0.0 && qv <= 1_000_000.0 {
                            let snip = format!("{} | {}", row[0], row[1]);
                            for mc in codes {
                                out_entities.push(EntityRow {
                                    entity_type: "item_code".to_string(),
                                    entity_key: mc.entity_key,
                                    canonical_value: mc.canonical_value,
                                    category: mc.category,
                                    sub_group: mc.sub_group,
                                    quantity: Some(qv),
                                    unit: "pcs".to_string(),
                                    role: context_role.to_string(),
                                    confidence: "high".to_string(),
                                    snippet: utf8_trunc_sv(&snip, 160).to_string(),
                                    attrs_json: "{}".to_string(),
                                });
                            }
                        }
                    }
                }
            }
            continue;
        };

        let headers = &table[hi];
        let mut tbl_curr = sheet_curr_hint.to_string();
        for (ci, hdr) in headers.iter().enumerate() {
            if col_roles[ci] == "unit_price" || col_roles[ci] == "total" {
                let c = detect_currency_str(hdr, false, pack);
                if !c.is_empty() {
                    tbl_curr = c;
                    break;
                }
            }
        }
        let is_order_tbl =
            contains_any_ci(att_name, &["Backlog", "出货明细", "订货清单", "订单", "Order"])
                || contains_any_ci(subject, &["Backlog", "出货明细", "订货清单", "订单"]);
        let hdr_joined = headers.join(" ");

        for row in &table[hi + 1..] {
            let row_joined = row
                .iter()
                .map(|c| trim_ascii_ws(c))
                .filter(|c| !c.is_empty())
                .collect::<Vec<_>>()
                .join(" | ");
            if row_joined.is_empty() {
                continue;
            }
            if starts_with_ci(&row_joined, 0, "总计")
                || starts_with_ci(&row_joined, 0, "合计")
                || starts_with_ci(&row_joined, 0, "小计")
                || starts_with_ci(&row_joined, 0, "Total")
                || starts_with_ci(&row_joined, 0, "Grand Total")
            {
                continue;
            }

            if row.len() == 1 && !skip_amounts {
                extract_amounts_from_body(
                    &row[0],
                    pack,
                    topic_name,
                    org_name,
                    effective_date_iso,
                    default_tax_mode,
                    subject_single_entity,
                    source_kind,
                    false,
                    out_amounts,
                );
                continue;
            }
            if strict_col_align && row.len() != headers.len() {
                let ok = col_roles.iter().zip(row.iter()).any(|(&role, cell)| {
                    role == "sku" && !extract_item_codes(cell, pack).is_empty()
                });
                if !ok {
                    continue;
                }
            }

            let mut row_codes: Vec<MatchedCode> = Vec::new();
            let mut seen_rsku = HashSet::new();
            for (&role, cell) in col_roles.iter().zip(row.iter()) {
                if role == "sku" || role == "desc" {
                    for mc in extract_item_codes(cell, pack) {
                        if seen_rsku.insert(mc.entity_key.clone()) {
                            row_codes.push(mc);
                        }
                    }
                }
            }
            if row_codes.is_empty() {
                for (&role, cell) in col_roles.iter().zip(row.iter()) {
                    if role == "other" {
                        for mc in extract_item_codes(cell, pack) {
                            if seen_rsku.insert(mc.entity_key.clone()) {
                                row_codes.push(mc);
                            }
                        }
                    }
                }
            }

            let mut row_org = String::new();
            let mut row_topic = String::new();
            let mut qty_val: Option<f64> = None;
            let mut qty_unit = String::new();
            let mut best_q_pri = -1;
            let mut total_val: Option<f64> = None;
            let mut row_curr = tbl_curr.clone();
            let mut row_moq = String::new();
            let mut row_lt = String::new();
            let mut row_disc = String::new();
            let mut row_valid = String::new();

            for (ci, (&role, cell)) in col_roles.iter().zip(row.iter()).enumerate() {
                match role {
                    "customer" if row_org.is_empty() => {
                        row_org = utf8_trunc_sv(trim_ascii_ws(cell), 80).to_string();
                    }
                    "project" if row_topic.is_empty() => {
                        row_topic = utf8_trunc_sv(trim_ascii_ws(cell), 120).to_string();
                    }
                    "qty" => {
                        let pri = if contains_any_ci(&headers[ci], &["总", "total"]) {
                            2
                        } else {
                            1
                        };
                        let q = parse_price_number(cell, "");
                        if q > 0.0 && q <= 10_000_000.0 && pri > best_q_pri {
                            qty_val = Some(q);
                            qty_unit = "pcs".to_string();
                            best_q_pri = pri;
                        }
                    }
                    "total" => {
                        let c = detect_currency_str(cell, false, pack);
                        if !c.is_empty() && row_curr.is_empty() {
                            row_curr = c;
                        }
                        let tv = parse_price_number(cell, "");
                        if tv > 0.0 && tv <= 50_000_000.0 {
                            total_val = Some((tv * 100.0).round() / 100.0);
                        }
                    }
                    "moq" if row_moq.is_empty() => {
                        row_moq = utf8_trunc_sv(trim_ascii_ws(cell), 40).to_string();
                    }
                    "lead_time" if row_lt.is_empty() => {
                        row_lt = utf8_trunc_sv(trim_ascii_ws(cell), 40).to_string();
                    }
                    "discount" if row_disc.is_empty() => {
                        row_disc = utf8_trunc_sv(trim_ascii_ws(cell), 40).to_string();
                    }
                    "valid_until" if row_valid.is_empty() => {
                        row_valid = utf8_trunc_sv(trim_ascii_ws(cell), 32).to_string();
                    }
                    _ => {}
                }
            }

            for mc in &row_codes {
                out_entities.push(EntityRow {
                    entity_type: "item_code".to_string(),
                    entity_key: mc.entity_key.clone(),
                    canonical_value: mc.canonical_value.clone(),
                    category: mc.category.clone(),
                    sub_group: mc.sub_group.clone(),
                    quantity: qty_val,
                    unit: qty_unit.clone(),
                    role: context_role.to_string(),
                    confidence: "high".to_string(),
                    snippet: utf8_trunc_sv(&row_joined, 160).to_string(),
                    attrs_json: "{}".to_string(),
                });
            }
            if skip_amounts {
                continue;
            }

            let terms_json = build_terms_json(&row_moq, &row_lt, &row_disc);

            let mut emitted_unit_price = false;
            for (ci, (&role, cell)) in col_roles.iter().zip(row.iter()).enumerate() {
                if role != "unit_price" || cell.is_empty() {
                    continue;
                }
                let hdr_txt = &headers[ci];
                let mut hdr_curr = detect_currency_str(hdr_txt, false, pack);
                if hdr_curr.is_empty() {
                    hdr_curr = row_curr.clone();
                }
                let hdr_tax = detect_tax_mode_str(hdr_txt);
                let def_type = if is_order_tbl { "order_price" } else { "quote" };

                for cln in cell.split('\n') {
                    let cl = trim_ascii_ws(cln);
                    if cl.is_empty() || matches!(cl, "N/A" | "NA" | "-" | "—" | "0") {
                        continue;
                    }
                    if contains_any_ci(
                        cl,
                        &["EN ", "IEC ", "VDC", "VAC", "GHz", "MHz", "Gbps", "元/人", "/人"],
                    ) {
                        continue;
                    }

                    let tb = cl.as_bytes();
                    let mut ni = 0;
                    while ni < tb.len() && !tb[ni].is_ascii_digit() {
                        ni += 1;
                    }
                    let mut nj = ni;
                    while nj < tb.len()
                        && (tb[nj].is_ascii_digit() || tb[nj] == b',' || tb[nj] == b'.')
                    {
                        nj += 1;
                    }
                    if nj == ni {
                        continue;
                    }
                    let val = parse_price_number(&cl[ni..nj], "");
                    if val <= 0.0 || val > 50_000_000.0 {
                        continue;
                    }

                    let mut curr = detect_currency_str(cl, true, pack);
                    if curr.is_empty() {
                        curr = hdr_curr.clone();
                    }
                    if val < 10.0 && curr.is_empty() {
                        continue;
                    }
                    if curr.is_empty() {
                        curr = apply_currency_alias("USD", pack);
                    }

                    let mut tax = detect_tax_mode_str(cl);
                    if tax.is_empty() {
                        tax = hdr_tax.clone();
                    }
                    if tax.is_empty() {
                        tax = detect_tax_mode_str(&hdr_joined);
                    }
                    if tax.is_empty() {
                        tax = default_tax_mode.to_string();
                    }

                    let type_ctx = format!("{hdr_txt} {cl} {row_joined}");
                    let (atype, conf_ov) =
                        detect_amount_type_and_conf(&type_ctx, def_type, Some("high"), pack);
                    let conf = conf_ov.unwrap_or_else(|| "high".to_string());

                    let mut targets: Vec<MatchedCode> = row_codes.clone();
                    if targets.is_empty() && !subject_single_entity.is_empty() {
                        targets.push(MatchedCode {
                            entity_key: subject_single_entity.to_string(),
                            canonical_value: subject_single_entity.to_string(),
                            category: pack.default_category.clone(),
                            sub_group: generic_sub_group(subject_single_entity),
                            extra_terms: Vec::new(),
                            start: 0,
                            end: 0,
                        });
                    } else if targets.is_empty() {
                        // Allow row with explicit unit_price even without item_code
                        targets.push(MatchedCode {
                            entity_key: String::new(),
                            canonical_value: String::new(),
                            category: pack.default_category.clone(),
                            sub_group: String::new(),
                            extra_terms: Vec::new(),
                            start: 0,
                            end: 0,
                        });
                    }

                    let pfx = if att_name.is_empty() {
                        String::new()
                    } else {
                        format!("[{att_name}] ")
                    };
                    let evid =
                        utf8_trunc_sv(&format!("{pfx}{hdr_txt}: {row_joined}"), 220).to_string();

                    emitted_unit_price = true;
                    for mc in targets {
                        out_amounts.push(AmountRow {
                            amount_type: atype.clone(),
                            subject_entity: mc.entity_key,
                            category: mc.category,
                            topic_name: if !row_topic.is_empty() {
                                row_topic.clone()
                            } else {
                                topic_name.to_string()
                            },
                            org_name: if !row_org.is_empty() {
                                row_org.clone()
                            } else {
                                org_name.to_string()
                            },
                            currency: curr.clone(),
                            unit_amount: Some((val * 100.0).round() / 100.0),
                            total_amount: total_val,
                            quantity: qty_val,
                            tax_mode: tax.clone(),
                            moq: row_moq.clone(),
                            lead_time: row_lt.clone(),
                            discount_info: row_disc.clone(),
                            terms_json: terms_json.clone(),
                            effective_date_iso: effective_date_iso.to_string(),
                            valid_until: row_valid.clone(),
                            source_kind: source_kind.to_string(),
                            evidence_snippet: evid.clone(),
                            confidence: conf.clone(),
                        });
                    }
                }
            }

            // If table has total column without unit_price column, still emit total amount rows
            if !emitted_unit_price {
                if let Some(tot) = total_val {
                    let curr = if !row_curr.is_empty() {
                        row_curr.clone()
                    } else {
                        apply_currency_alias("USD", pack)
                    };
                    let tax = if !default_tax_mode.is_empty() {
                        default_tax_mode.to_string()
                    } else {
                        detect_tax_mode_str(&hdr_joined)
                    };
                    let pfx = if att_name.is_empty() {
                        String::new()
                    } else {
                        format!("[{att_name}] ")
                    };
                    let evid = utf8_trunc_sv(&format!("{pfx}{row_joined}"), 220).to_string();
                    let targets = if row_codes.is_empty() {
                        vec![MatchedCode {
                            entity_key: subject_single_entity.to_string(),
                            canonical_value: subject_single_entity.to_string(),
                            category: pack.default_category.clone(),
                            sub_group: String::new(),
                            extra_terms: Vec::new(),
                            start: 0,
                            end: 0,
                        }]
                    } else {
                        row_codes.clone()
                    };
                    for mc in targets {
                        out_amounts.push(AmountRow {
                            amount_type: if is_order_tbl {
                                "order_price".to_string()
                            } else {
                                "project_bid_total".to_string()
                            },
                            subject_entity: mc.entity_key,
                            category: mc.category,
                            topic_name: if !row_topic.is_empty() {
                                row_topic.clone()
                            } else {
                                topic_name.to_string()
                            },
                            org_name: if !row_org.is_empty() {
                                row_org.clone()
                            } else {
                                org_name.to_string()
                            },
                            currency: curr.clone(),
                            unit_amount: None,
                            total_amount: Some(tot),
                            quantity: qty_val,
                            tax_mode: tax.clone(),
                            moq: row_moq.clone(),
                            lead_time: row_lt.clone(),
                            discount_info: row_disc.clone(),
                            terms_json: terms_json.clone(),
                            effective_date_iso: effective_date_iso.to_string(),
                            valid_until: row_valid.clone(),
                            source_kind: source_kind.to_string(),
                            evidence_snippet: evid.clone(),
                            confidence: "high".to_string(),
                        });
                    }
                }
            }
        }
    }
}

pub fn format_amount_rollup(amounts: &[AmountRow]) -> String {
    if amounts.is_empty() {
        return String::new();
    }
    let mut parts: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for p in amounts {
        let ent = if p.subject_entity.is_empty() {
            "Amount"
        } else {
            &p.subject_entity
        };
        let Some(val) = p.unit_amount.or(p.total_amount) else {
            continue;
        };
        if val <= 0.0 {
            continue;
        }
        let vbuf = if (val - val.round()).abs() < 0.005 {
            format!("{}", val.round() as i64)
        } else {
            format!("{val:.2}")
        };
        let mut tags = String::new();
        if let Some(q) = p.quantity.filter(|&q| q >= 0.0) {
            let qb = if (q - q.round()).abs() < 0.01 {
                format!("x{}", q.round() as i64)
            } else {
                format!("x{q:.1}")
            };
            tags.push_str(&qb);
        }
        if !p.tax_mode.is_empty() {
            if !tags.is_empty() {
                tags.push_str(", ");
            }
            tags.push_str(&p.tax_mode);
        }
        if !p.amount_type.is_empty() && p.amount_type != "quote" {
            if !tags.is_empty() {
                tags.push_str(", ");
            }
            tags.push_str(&p.amount_type);
        }
        let item = if tags.is_empty() {
            format!("{ent}: {} {vbuf}", p.currency)
        } else {
            format!("{ent}: {} {vbuf} ({tags})", p.currency)
        };
        if seen.insert(item.clone()) {
            parts.push(item);
        }
        if parts.len() >= 5 {
            break;
        }
    }
    if amounts.len() > 5 && parts.len() == 5 {
        parts.push(format!("(+{} total)", amounts.len()));
    }
    parts.join("; ")
}

/// Enriches a parsed/raw message using `CompiledDomainPack` and `ResolvedIdentity`.
pub fn enrich_message(
    raw: &RawMessageInput,
    pack: &CompiledDomainPack,
    identity: &ResolvedIdentity,
) -> EnrichedMsg {
    let mut em = EnrichedMsg {
        uid_key: raw.uid_key.clone(),
        account_id: raw.account_id.clone(),
        source: raw.source.clone(),
        source_ref: raw.source_ref.clone(),
        rfc_message_id: raw.rfc_message_id.clone(),
        subject: sanitize_utf8(raw.subject.as_bytes()),
        sender: sanitize_utf8(raw.sender.as_bytes()),
        recipients: sanitize_utf8(raw.recipients.as_bytes()),
        cc: sanitize_utf8(raw.cc.as_bytes()),
        date_iso: raw.date_iso.clone(),
        folder_path: sanitize_utf8(raw.folder_path.as_bytes()),
        completeness: if raw.completeness.is_empty() {
            "full_body".to_string()
        } else {
            raw.completeness.clone()
        },
        body_latest: sanitize_utf8(raw.body_latest.as_bytes()),
        body_quoted: sanitize_utf8(raw.body_quoted.as_bytes()),
        body_quoted_for_amount: sanitize_utf8(raw.body_quoted_for_amount.as_bytes()),
        primary_category: pack.default_category.clone(),
        event_dates_json: "{}".to_string(),
        custom_dims_json: "{}".to_string(),
        ..Default::default()
    };

    em.thread_topic = strip_subject_prefixes(&em.subject);
    em.direction = classify_direction(
        identity,
        &em.sender,
        &em.recipients,
        &em.cc,
        &em.subject,
        &em.folder_path,
        &em.body_latest,
    );

    let clean_body = clean_body_for_meaning(&em.body_latest);
    let att_names = raw
        .attachments
        .iter()
        .map(|a| a.clean_filename.as_str())
        .collect::<Vec<_>>()
        .join(" ");

    let mut tbl_text = String::new();
    for tbl in raw.html_tables.iter().take(5) {
        for row in tbl.iter().take(30) {
            for c in row {
                if !c.is_empty() {
                    tbl_text.push_str(c);
                    tbl_text.push(' ');
                }
            }
        }
    }
    let quoted_hint = if clean_body.len() < 25 && !em.body_quoted.is_empty() {
        utf8_trunc_sv(&em.body_quoted, 1200)
    } else {
        ""
    };
    let body_and_q = format!("{clean_body}\n{quoted_hint}");
    let entity_text = format!(
        "{}\n{att_names}\n{clean_body}\n{tbl_text}\n{quoted_hint}",
        em.subject
    );

    let matched_codes = extract_item_codes(&entity_text, pack);
    let mut extra_terms_buf: Vec<String> = Vec::new();
    for mc in &matched_codes {
        if em.primary_entities_vec.len() < 12 {
            em.primary_entities_vec.push(mc.entity_key.clone());
        }
        for et in &mc.extra_terms {
            if !extra_terms_buf.contains(et) {
                extra_terms_buf.push(et.clone());
            }
        }
    }
    em.primary_entities = em.primary_entities_vec.join(",");
    if let Some(first) = matched_codes.first() {
        em.primary_category = first.category.clone();
    } else {
        em.primary_category = infer_category_from_fallbacks(&entity_text, pack);
    }

    em.org_vec = extract_orgs(
        pack,
        identity,
        &em.sender,
        &em.recipients,
        &em.cc,
        &em.subject,
        &att_names,
        &body_and_q,
        &mut em.lexicon_hits,
    );
    em.org_tags = em.org_vec.join(",");

    em.topic_vec = extract_topics(
        pack,
        &em.subject,
        &em.thread_topic,
        &att_names,
        &body_and_q,
        &mut em.lexicon_hits,
    );
    em.topic_tags = em.topic_vec.join(",");

    let (dim_map, mut dim_entities) =
        extract_custom_dimensions(&entity_text, pack, &mut em.lexicon_hits);
    em.custom_dims_map = dim_map;
    if !em.custom_dims_map.is_empty() {
        em.custom_dims_json =
            serde_json::to_string(&em.custom_dims_map).unwrap_or_else(|_| "{}".to_string());
    }

    em.intent_type = classify_intent(
        pack,
        &em.subject,
        &clean_body,
        &em.direction,
        &em.primary_entities_vec,
    );

    let is_preview = em.completeness != "full_body";
    em.summary_line = build_summary_line(
        &em.subject,
        &em.sender,
        &clean_body,
        &em.intent_type,
        &em.thread_topic,
        &em.primary_entities_vec,
        &em.topic_vec,
        &em.org_vec,
        &raw.html_tables,
        is_preview,
    );
    em.event_dates_json = extract_event_dates_json(&em.date_iso, &em.subject, &clean_body);
    em.content_hash = sha256_bytes(
        format!(
            "{}\n{}\n{}\n{}",
            em.account_id, em.subject, em.date_iso, em.body_latest
        )
        .as_bytes(),
    );

    let ctx_role = determine_context_role(&em.subject, &em.intent_type);
    let skip_amounts = is_excluded_amount_message(pack, identity, &em.subject, &em.sender);
    let subj_codes = extract_item_codes(&em.subject, pack);
    let subj_single = if subj_codes.len() == 1 {
        subj_codes[0].entity_key.as_str()
    } else {
        ""
    };
    let eff_date = if em.date_iso.len() >= 10 {
        &em.date_iso[..10]
    } else {
        ""
    };
    let def_tax = detect_tax_mode_str(&em.subject);

    let mut raw_entities: Vec<EntityRow> = Vec::new();
    let mut raw_amounts: Vec<AmountRow> = Vec::new();

    if !raw.html_tables.is_empty() {
        extract_from_tables(
            &raw.html_tables,
            pack,
            &em.topic_tags,
            &em.org_tags,
            eff_date,
            &def_tax,
            &em.subject,
            subj_single,
            &ctx_role,
            skip_amounts,
            false,
            "html_table",
            "",
            "",
            &mut raw_entities,
            &mut raw_amounts,
        );
    }

    for ra in &raw.attachments {
        let att_skip =
            skip_amounts || contains_any_ci(&ra.clean_filename, &["行程", "机票", "酒店", "旅游"]);
        if !ra.ooxml_sheets.is_empty() {
            for (sname, grid) in &ra.ooxml_sheets {
                let sh_curr = detect_currency_str(sname, false, pack);
                let one_tbl = std::slice::from_ref(grid);
                extract_from_tables(
                    one_tbl,
                    pack,
                    &em.topic_tags,
                    &em.org_tags,
                    eff_date,
                    &def_tax,
                    &em.subject,
                    subj_single,
                    &ctx_role,
                    att_skip,
                    true,
                    "mime_attachment",
                    &ra.clean_filename,
                    &sh_curr,
                    &mut raw_entities,
                    &mut raw_amounts,
                );
            }
        }
        if !ra.text_preview.is_empty() {
            if ra.ooxml_sheets.is_empty() && !att_skip {
                let before = raw_amounts.len();
                extract_amounts_from_body(
                    &ra.text_preview,
                    pack,
                    &em.topic_tags,
                    &em.org_tags,
                    eff_date,
                    &def_tax,
                    subj_single,
                    "mime_attachment",
                    false,
                    &mut raw_amounts,
                );
                for amt in &mut raw_amounts[before..] {
                    let s = format!("[{}] {}", ra.clean_filename, amt.evidence_snippet);
                    amt.evidence_snippet = utf8_trunc_sv(&s, 220).to_string();
                }
            }
            for mc in extract_item_codes(&ra.text_preview, pack) {
                let snip = format!("[{}] {}", ra.clean_filename, mc.entity_key);
                raw_entities.push(EntityRow {
                    entity_type: "item_code".to_string(),
                    entity_key: mc.entity_key,
                    canonical_value: mc.canonical_value,
                    category: mc.category,
                    sub_group: mc.sub_group,
                    quantity: None,
                    unit: String::new(),
                    role: ctx_role.clone(),
                    confidence: "medium".to_string(),
                    snippet: utf8_trunc_sv(&snip, 160).to_string(),
                    attrs_json: "{}".to_string(),
                });
            }
        }

        let att_codes = extract_item_codes(&ra.clean_filename, pack);
        let att_ent_tags = att_codes
            .iter()
            .map(|c| c.entity_key.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let att_topics = extract_topics(
            pack,
            &ra.clean_filename,
            &ra.clean_filename,
            "",
            "",
            &mut Vec::new(),
        );
        let att_topic_tags = if att_topics.is_empty() {
            em.topic_tags.clone()
        } else {
            att_topics.join(",")
        };
        let fn_tok = tokenize_for_fts(&format!("{} {}", ra.clean_filename, ra.ext));
        let meta_tok = tokenize_for_fts(&format!(
            "{} {} {} {}",
            att_ent_tags, att_topic_tags, em.primary_category, em.org_tags
        ));

        em.attachments.push(EnrichedAttachment {
            filename: ra.filename.clone(),
            clean_filename: ra.clean_filename.clone(),
            ext: ra.ext.clone(),
            mime_type: ra.mime_type.clone(),
            size_bytes: ra.size_bytes,
            mtime: ra.mtime,
            mtime_iso: ra.mtime_iso.clone(),
            storage_relpath: ra.storage_relpath.clone(),
            is_inline: ra.is_inline,
            is_noise: ra.is_noise,
            sha256: ra.sha256.clone(),
            text_preview: ra.text_preview.clone(),
            entity_tags: att_ent_tags,
            topic_tags: att_topic_tags,
            fn_tok,
            meta_tok,
        });
    }

    for mc in extract_item_codes(&em.subject, pack) {
        raw_entities.push(EntityRow {
            entity_type: "item_code".to_string(),
            entity_key: mc.entity_key,
            canonical_value: mc.canonical_value,
            category: mc.category,
            sub_group: mc.sub_group,
            quantity: None,
            unit: String::new(),
            role: ctx_role.clone(),
            confidence: "high".to_string(),
            snippet: utf8_trunc_sv(&em.subject, 160).to_string(),
            attrs_json: "{}".to_string(),
        });
    }
    for mc in extract_item_codes(&em.body_latest, pack) {
        let key_c = mc.entity_key.clone();
        raw_entities.push(EntityRow {
            entity_type: "item_code".to_string(),
            entity_key: mc.entity_key,
            canonical_value: mc.canonical_value,
            category: mc.category,
            sub_group: mc.sub_group,
            quantity: None,
            unit: String::new(),
            role: ctx_role.clone(),
            confidence: "medium".to_string(),
            snippet: key_c,
            attrs_json: "{}".to_string(),
        });
    }
    if !skip_amounts && (raw_amounts.is_empty() || em.body_latest.len() > 10) {
        extract_amounts_from_body(
            &em.body_latest,
            pack,
            &em.topic_tags,
            &em.org_tags,
            eff_date,
            &def_tax,
            subj_single,
            "body_latest",
            is_preview,
            &mut raw_amounts,
        );
    }

    raw_entities.sort_by_key(|a| if a.quantity.is_some() { 0 } else { 1 });
    let mut seen_ent = HashSet::new();
    for ent in raw_entities {
        if seen_ent.insert((ent.entity_type.clone(), ent.entity_key.clone())) {
            em.entities.push(ent);
        }
    }
    for de in dim_entities.drain(..) {
        if seen_ent.insert((de.entity_type.clone(), de.entity_key.clone())) {
            em.entities.push(de);
        }
    }

    raw_amounts.sort_by_key(|a| {
        let ca = if a.confidence == "high" { 0 } else { 1 };
        let ta = if a.source_kind == "html_table" || a.source_kind == "mime_attachment" {
            0
        } else {
            1
        };
        (ca, ta)
    });
    let mut seen_amt = HashSet::new();
    for amt in raw_amounts {
        let up = amt.unit_amount.unwrap_or(-1.0);
        let tot = amt.total_amount.unwrap_or(-1.0);
        let key = format!(
            "{}|{}|{:.2}|{:.2}|{}|{}",
            amt.subject_entity, amt.currency, up, tot, amt.amount_type, amt.tax_mode
        );
        if seen_amt.insert(key) {
            em.amounts.push(amt);
        }
    }
    if !em.amounts.is_empty() {
        em.has_amount = 1;
        em.amount_summary = format_amount_rollup(&em.amounts);
    }

    rebuild_fts_tokens(&mut em, &extra_terms_buf);
    em
}

/// Recomputes FTS5 tokenized columns (called initially and after thread/quoted fallbacks).
pub fn rebuild_fts_tokens(em: &mut EnrichedMsg, extra_terms: &[String]) {
    let dim_vals = em
        .custom_dims_map
        .values()
        .flat_map(|v| v.iter().map(String::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    let extra_str = extra_terms.join(" ");
    let mut meta_str = format!(
        "{} {} {} {} {} {}",
        em.primary_entities, em.primary_category, em.topic_tags, em.org_tags, dim_vals, extra_str
    );
    if !em.account_id.is_empty() {
        meta_str.push(' ');
        meta_str.push_str(&em.account_id);
    }

    em.mfts_subj = tokenize_for_fts(&em.subject);
    em.mfts_sender = tokenize_for_fts(&format!("{} {} {}", em.sender, em.recipients, em.cc));
    em.mfts_meta = tokenize_for_fts(&meta_str);
    em.mfts_latest = tokenize_for_fts(&em.body_latest);
    em.mfts_quoted = tokenize_for_fts(utf8_trunc_sv(&em.body_quoted, MAX_BODY_QUOTED_FTS));

    let extra_entities = em
        .entities
        .iter()
        .filter(|e| !e.entity_key.is_empty())
        .map(|e| format!("{} {}", e.entity_key, e.canonical_value))
        .collect::<Vec<_>>()
        .join(" ");

    em.dfts_title = tokenize_for_fts(&format!("{} {}", em.subject, em.thread_topic));
    em.dfts_meaning = tokenize_for_fts(&em.summary_line);
    em.dfts_intent = tokenize_for_fts(&format!(
        "{} {} {}",
        em.intent_type, em.direction, em.completeness
    ));
    em.dfts_entities = tokenize_for_fts(&format!(
        "{} {} {} {} {}",
        em.primary_entities, em.primary_category, dim_vals, extra_entities, extra_str
    ));
    em.dfts_orgs = tokenize_for_fts(&format!("{} {} {}", em.org_tags, em.sender, em.recipients));
    em.dfts_topics = tokenize_for_fts(&em.topic_tags);
    em.dfts_amounts = tokenize_for_fts(&em.amount_summary);
}
