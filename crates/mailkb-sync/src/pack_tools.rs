//! Corpus profiler (`profile-corpus`) and domain-pack evaluator (`test-pack`)
//! operating strictly read-only over Apple Mail V10, `--eml-dir`, or staged `--from-db`.

use crate::apple_mail::{
    copy_envelope_index_to_dir, discover_accounts_and_filter, infer_identity_from_envelope_db,
    infer_identity_from_messages, load_all_mailboxes, mail_master_state, open_staged_envelope_ro,
    parse_work_item_to_raw, query_envelope_rows, scan_all_eml_dirs, DiscoveredAccount, MasterState,
    WorkItem,
};
use crate::enrich::{
    apply_currency_alias, enrich_message, extract_emails, is_freemail_domain, is_noreply_local,
    strip_subject_prefixes, EnrichedMsg, InferredIdentity, RawMessageInput, ResolvedIdentity,
};
use crate::sync::{
    build_apple_mail_work_items, load_raw_messages_from_db, merge_eml_work_items,
    stage_and_open_external_ro,
};
use mailkb_core::config::MailKbConfig;
use mailkb_core::domain_pack::{validate_pack_file, CompiledDomainPack};
use mailkb_core::error::{KbError, KbResult};
use mailkb_core::publish::TempBuildDir;
use mailkb_core::security::{collapse_ws, term_safe};
use mailkb_core::strutil::{contains_any_ci, utf8_char_len, utf8_trunc_sv};
use rayon::prelude::*;
use regex::Regex;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::OnceLock;

/// Corpus profiling options (`profile-corpus`).
#[derive(Debug, Clone)]
pub struct ProfileOpts {
    pub limit: usize,
    pub from_db: Option<PathBuf>,
}

impl Default for ProfileOpts {
    fn default() -> Self {
        Self {
            limit: 2000,
            from_db: None,
        }
    }
}

/// Pack evaluation options (`test-pack`).
#[derive(Debug, Clone)]
pub struct TestPackOpts {
    pub pack_path: PathBuf,
    pub sample: usize,
    pub from_db: Option<PathBuf>,
}

struct CorpusSample {
    source_label: String,
    accounts: Vec<DiscoveredAccount>,
    inferred_identity: InferredIdentity,
    raw_messages: Vec<RawMessageInput>,
    warnings: Vec<String>,
}

fn strided_indices(total: usize, want: usize) -> Vec<usize> {
    if total <= want || want == 0 {
        return (0..total).collect();
    }
    let mut out = Vec::with_capacity(want);
    for i in 0..want {
        let idx = (i * total) / want;
        if out.last().copied() != Some(idx) {
            out.push(idx);
        }
    }
    out
}

fn load_corpus_sample(
    cfg: &MailKbConfig,
    from_db: Option<&PathBuf>,
    limit: usize,
    strided: bool,
    identity_for_parse: &ResolvedIdentity,
) -> KbResult<CorpusSample> {
    let mut warnings = Vec::new();
    let cap = limit.max(1);
    let build_dir = TempBuildDir::new(cfg, "mailkb-db-tools-")?;

    if let Some(db_path) = from_db {
        let stage_dir = build_dir.path().join("from_db");
        let conn = stage_and_open_external_ro(cfg, db_path, &stage_dir)?;
        let all_msgs = load_raw_messages_from_db(&conn, if strided { None } else { Some(cap) })?;
        drop(conn);

        let selected: Vec<RawMessageInput> = if strided && all_msgs.len() > cap {
            let idxs = strided_indices(all_msgs.len(), cap);
            let mut by_idx: HashMap<usize, RawMessageInput> = all_msgs
                .into_iter()
                .enumerate()
                .collect();
            idxs.into_iter().filter_map(|i| by_idx.remove(&i)).collect()
        } else {
            all_msgs.into_iter().take(cap).collect()
        };

        let inferred_identity = infer_identity_from_messages(
            selected
                .iter()
                .map(|m| (m.folder_path.as_str(), m.sender.as_str())),
        );

        let mut acct_map: BTreeMap<String, DiscoveredAccount> = BTreeMap::new();
        for m in &selected {
            let aid = if m.account_id.is_empty() {
                m.source.clone()
            } else {
                m.account_id.clone()
            };
            let entry = acct_map.entry(aid.clone()).or_insert_with(|| DiscoveredAccount {
                account_id: aid,
                scheme: m.source.clone(),
                mailbox_count: 0,
                message_count: 0,
                inferred_emails: Vec::new(),
                folders: Vec::new(),
            });
            entry.message_count += 1;
            if !m.folder_path.is_empty() && !entry.folders.contains(&m.folder_path) {
                entry.folders.push(m.folder_path.clone());
            }
        }
        let accounts: Vec<DiscoveredAccount> = acct_map
            .into_values()
            .map(|mut a| {
                a.mailbox_count = a.folders.len();
                a
            })
            .collect();

        return Ok(CorpusSample {
            source_label: "from_db".to_string(),
            accounts,
            inferred_identity,
            raw_messages: selected,
            warnings,
        });
    }

    let has_eml = !cfg.eml_dirs.is_empty();
    let mut use_am = false;
    match mail_master_state(cfg) {
        MasterState::Master => use_am = true,
        MasterState::AccessDenied(why) => {
            if !has_eml {
                return Err(KbError::Other(format!(
                    "{why} -- grant Full Disk Access or pass --eml-dir / --from-db"
                )));
            }
            warnings.push(why);
        }
        MasterState::NotMaster(why) => {
            if !has_eml {
                return Err(KbError::NotFound(format!(
                    "no mail sources available: {why} (pass --eml-dir or --from-db)"
                )));
            }
            if cfg.apple_mail_v10_dir.is_some() {
                warnings.push(format!("apple_mail_skipped: {why}"));
            }
        }
    }

    let mut accounts = Vec::new();
    let mut inferred_identity = InferredIdentity::default();
    let mut work_items: Vec<WorkItem> = Vec::new();

    if use_am {
        if let Some(ref v10) = cfg.apple_mail_v10_dir {
            let env_dir = build_dir.path().join("env_idx");
            let staged = copy_envelope_index_to_dir(v10, &env_dir)?;
            let edb = open_staged_envelope_ro(&staged.env_path)?;
            let mailboxes = load_all_mailboxes(&edb, v10)?;
            let (inf, per_acct_emails) = infer_identity_from_envelope_db(&edb, &mailboxes)?;
            inferred_identity = inf;
            let (accts, mb_ids) = discover_accounts_and_filter(
                &edb,
                &mailboxes,
                &per_acct_emails,
                &cfg.account_filters,
            )?;
            accounts = accts;
            let (rows, _) = query_envelope_rows(&edb, &mb_ids, 0)?;
            drop(edb);
            work_items = build_apple_mail_work_items(rows, &mailboxes);
        }
    }

    let eml_files = scan_all_eml_dirs(&cfg.eml_dirs);
    let eml_inf = merge_eml_work_items(&mut work_items, &eml_files);
    for e in eml_inf.self_emails {
        if !inferred_identity.self_emails.contains(&e) {
            inferred_identity.self_emails.push(e);
        }
    }
    for d in eml_inf.internal_domains {
        if !inferred_identity.internal_domains.contains(&d) {
            inferred_identity.internal_domains.push(d);
        }
    }

    work_items.sort_by(|a, b| {
        b.date_iso
            .cmp(&a.date_iso)
            .then_with(|| b.sort_ts.cmp(&a.sort_ts))
            .then_with(|| a.uid_key.cmp(&b.uid_key))
    });

    let chosen_items: Vec<WorkItem> = if strided && work_items.len() > cap {
        let idxs = strided_indices(work_items.len(), cap);
        idxs.into_iter().map(|i| work_items[i].clone()).collect()
    } else {
        work_items.into_iter().take(cap).collect()
    };

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.max_threads.max(1))
        .build()
        .map_err(|e| KbError::Other(format!("failed to create rayon pool: {e}")))?;

    let v10_ref = cfg.apple_mail_v10_dir.as_deref();
    let eml_trunc = AtomicU64::new(0);
    let raw_messages: Vec<RawMessageInput> = pool.install(|| {
        chosen_items
            .par_iter()
            .map(|wi| parse_work_item_to_raw(wi, v10_ref, identity_for_parse, &eml_trunc))
            .collect()
    });

    let source_label = match (use_am, has_eml) {
        (true, true) => "apple_mail_and_eml",
        (true, false) => "apple_mail",
        (false, true) => "eml",
        (false, false) => "none",
    }
    .to_string();

    Ok(CorpusSample {
        source_label,
        accounts,
        inferred_identity,
        raw_messages,
        warnings,
    })
}

fn candidate_code_regex() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(r"(?-i:\b[A-Z][A-Za-z0-9]{1,7}(?:-[A-Z][A-Za-z0-9]{0,7}){0,2}-(?:[A-Za-z]{0,3}\d{2,6}[A-Za-z0-9]*|\d{1,3}[A-Za-z]{1,6}[A-Za-z0-9]*)(?:-[A-Za-z0-9]{1,12})*\b|\b[A-Z][A-Za-z0-9]{2,10}\s+[A-Z]?\d{3,5}[A-Za-z0-9-]*\b)").unwrap()
    })
}

fn currency_token_regex() -> &'static Regex {
    static RX: OnceLock<Regex> = OnceLock::new();
    RX.get_or_init(|| {
        Regex::new(r"(?i)(?:US\$|NT\$|HK\$|S\$|C\$|A\$|\b(?:USD|EUR|GBP|RMB|CNY|TWD|NTD|HKD|JPY|SGD|CAD|AUD|CHF|KRW|INR)\b|[€£¥￥\$])").unwrap()
    })
}

fn is_candidate_excluded(upper: &str) -> bool {
    let head = upper.split(['-', ' ']).next().unwrap_or(upper);
    if matches!(
        head,
        "EN" | "IEC"
            | "IEEE"
            | "ISO"
            | "RFC"
            | "ANSI"
            | "ASTM"
            | "DIN"
            | "UTF"
            | "SHA"
            | "TLS"
            | "SSL"
            | "HTTP"
            | "HTTPS"
            | "MIME"
            | "HTML"
            | "XML"
            | "JSON"
            | "UUID"
            | "ISBN"
            | "ISSN"
            | "JAN"
            | "FEB"
            | "MAR"
            | "APR"
            | "MAY"
            | "JUN"
            | "JUL"
            | "AUG"
            | "SEP"
            | "OCT"
            | "NOV"
            | "DEC"
    ) {
        return true;
    }
    let segs: Vec<&str> = upper.split('-').collect();
    if segs.len() == 2
        && segs[1].len() == 4
        && segs[1].starts_with("20")
        && segs[1].bytes().all(|b| b.is_ascii_digit())
    {
        return true;
    }
    false
}

/// Profiles a user mailbox (`V10` / `--eml-dir`) or staged SQLite DB (`--from-db`)
/// to guide Domain Pack authoring.
pub fn run_profile_corpus(cfg: &MailKbConfig, opts: &ProfileOpts) -> KbResult<Value> {
    let empty_pack = CompiledDomainPack::empty();
    let empty_id = ResolvedIdentity::default();
    let sample = load_corpus_sample(
        cfg,
        opts.from_db.as_ref(),
        opts.limit,
        false,
        &empty_id,
    )?;

    let internal_dom_set: HashSet<String> = sample
        .inferred_identity
        .internal_domains
        .iter()
        .cloned()
        .collect();
    let self_email_set: HashSet<String> = sample
        .inferred_identity
        .self_emails
        .iter()
        .cloned()
        .collect();

    struct DomainAgg {
        count: usize,
        sample_senders: Vec<String>,
    }
    let mut ext_domains: HashMap<String, DomainAgg> = HashMap::new();
    let mut topic_counts: HashMap<(String, String), usize> = HashMap::new();
    struct CodeAgg {
        count: usize,
        family: String,
        sample_subject: String,
    }
    let mut code_counts: HashMap<String, CodeAgg> = HashMap::new();
    let mut table_header_counts: HashMap<String, usize> = HashMap::new();
    let mut currency_counts: HashMap<String, usize> = HashMap::new();

    let mut att_total = 0usize;
    let mut att_clean = 0usize;
    let mut att_noise = 0usize;
    let mut att_ext_counts: HashMap<String, usize> = HashMap::new();
    let mut sample_subjects: Vec<String> = Vec::new();
    let mut seen_subjects: HashSet<String> = HashSet::new();

    for msg in &sample.raw_messages {
        let subj_clean = term_safe(&msg.subject, true);
        if !subj_clean.is_empty()
            && sample_subjects.len() < 30
            && seen_subjects.insert(subj_clean.to_ascii_lowercase())
        {
            sample_subjects.push(subj_clean.clone());
        }

        // External domains from sender and recipients
        let mut msg_dom_seen = HashSet::new();
        for em in extract_emails(&msg.sender) {
            if !self_email_set.contains(&em.addr)
                && !internal_dom_set.contains(&em.domain)
                && !is_freemail_domain(&em.domain)
                && !is_noreply_local(&em.local)
                && msg_dom_seen.insert(em.domain.clone())
            {
                let ag = ext_domains.entry(em.domain).or_insert_with(|| DomainAgg {
                    count: 0,
                    sample_senders: Vec::new(),
                });
                ag.count += 1;
                if ag.sample_senders.len() < 3 && !ag.sample_senders.contains(&em.addr) {
                    ag.sample_senders.push(em.addr);
                }
            }
        }
        for em in extract_emails(&format!("{} {}", msg.recipients, msg.cc)) {
            if !self_email_set.contains(&em.addr)
                && !internal_dom_set.contains(&em.domain)
                && !is_freemail_domain(&em.domain)
                && !is_noreply_local(&em.local)
                && msg_dom_seen.insert(em.domain.clone())
            {
                let ag = ext_domains.entry(em.domain).or_insert_with(|| DomainAgg {
                    count: 0,
                    sample_senders: Vec::new(),
                });
                ag.count += 1;
                if ag.sample_senders.len() < 3 && !ag.sample_senders.contains(&em.addr) {
                    ag.sample_senders.push(em.addr);
                }
            }
        }

        // Subject topic candidates: [Bracket] / 【Bracket】 tags and repeated prefix stems
        let tt = strip_subject_prefixes(&msg.subject);
        for (open, close) in [('[', ']'), ('【', '】')] {
            let mut pos = 0;
            while let Some(o_rel) = tt[pos..].find(open) {
                let st = pos + o_rel + open.len_utf8();
                let Some(c_rel) = tt[st..].find(close) else {
                    break;
                };
                let tag = collapse_ws(&tt[st..st + c_rel]);
                if (2..=36).contains(&utf8_char_len(&tag))
                    && !tag.bytes().all(|b| b.is_ascii_digit())
                {
                    *topic_counts
                        .entry((tag, "bracket_tag".to_string()))
                        .or_insert(0) += 1;
                }
                pos = st + c_rel + close.len_utf8();
            }
        }
        if let Some((head, _)) = tt.split_once(" - ").or_else(|| tt.split_once(": ")) {
            let stem = collapse_ws(head);
            if (3..=36).contains(&utf8_char_len(&stem)) {
                *topic_counts
                    .entry((stem, "prefix_phrase".to_string()))
                    .or_insert(0) += 1;
            }
        }

        // Code token candidates
        let scan_txt = format!(
            "{}\n{}",
            msg.subject,
            utf8_trunc_sv(&msg.body_latest, 6000)
        );
        let mut msg_codes_seen = HashSet::new();
        for m in candidate_code_regex().find_iter(&scan_txt) {
            let tok = collapse_ws(m.as_str());
            let upper = tok.to_ascii_uppercase();
            if is_candidate_excluded(&upper) || !msg_codes_seen.insert(upper.clone()) {
                continue;
            }
            let fam = upper.split(['-', ' ']).next().unwrap_or(&upper).to_string();
            let entry = code_counts.entry(tok).or_insert_with(|| CodeAgg {
                count: 0,
                family: fam,
                sample_subject: utf8_trunc_sv(&subj_clean, 80).to_string(),
            });
            entry.count += 1;
        }

        // Table headers from HTML tables
        for tbl in &msg.html_tables {
            if let Some(hdr_row) = tbl.first() {
                for cell in hdr_row {
                    let h = collapse_ws(cell);
                    if (2..=40).contains(&utf8_char_len(&h)) {
                        *table_header_counts.entry(h).or_insert(0) += 1;
                    }
                }
            }
        }

        // Currencies in subject/body
        for cm in currency_token_regex().find_iter(&scan_txt) {
            let raw_c = cm.as_str();
            let norm = match raw_c {
                "$" | "US$" => "USD".to_string(),
                "€" => "EUR".to_string(),
                "£" => "GBP".to_string(),
                "¥" | "￥" => "RMB".to_string(),
                "NT$" | "NTD" => "TWD".to_string(),
                "HK$" => "HKD".to_string(),
                "S$" => "SGD".to_string(),
                "C$" => "CAD".to_string(),
                "A$" => "AUD".to_string(),
                other => apply_currency_alias(other, &empty_pack),
            };
            if !norm.is_empty() {
                *currency_counts.entry(norm).or_insert(0) += 1;
            }
        }

        // Attachments & OOXML headers
        for att in &msg.attachments {
            att_total += 1;
            if att.is_noise != 0 {
                att_noise += 1;
            } else {
                att_clean += 1;
            }
            if !att.ext.is_empty() {
                *att_ext_counts.entry(att.ext.clone()).or_insert(0) += 1;
            }
            for (_, grid) in &att.ooxml_sheets {
                if let Some(hdr_row) = grid.first() {
                    for cell in hdr_row {
                        let h = collapse_ws(cell);
                        if (2..=40).contains(&utf8_char_len(&h)) {
                            *table_header_counts.entry(h).or_insert(0) += 1;
                        }
                    }
                }
            }
            if att.ooxml_sheets.is_empty() && !att.text_preview.is_empty() {
                let mut next_is_hdr = false;
                for ln in att.text_preview.lines() {
                    if ln.starts_with("[Sheet:") {
                        next_is_hdr = true;
                        continue;
                    }
                    if next_is_hdr && ln.contains(" | ") {
                        for cell in ln.split(" | ") {
                            let h = collapse_ws(cell);
                            if (2..=40).contains(&utf8_char_len(&h)) {
                                *table_header_counts.entry(h).or_insert(0) += 1;
                            }
                        }
                        next_is_hdr = false;
                    }
                }
            }
        }
    }

    let mut top_external_domains: Vec<(String, DomainAgg)> = ext_domains.into_iter().collect();
    top_external_domains.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
    let top_external_domains_json: Vec<Value> = top_external_domains
        .into_iter()
        .take(30)
        .map(|(dom, ag)| {
            json!({
                "domain": dom,
                "count": ag.count,
                "sample_senders": ag.sample_senders,
            })
        })
        .collect();

    let mut topic_vec: Vec<((String, String), usize)> = topic_counts
        .into_iter()
        .filter(|((_, kind), cnt)| kind == "bracket_tag" || *cnt >= 2)
        .collect();
    topic_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let subject_topic_candidates_json: Vec<Value> = topic_vec
        .into_iter()
        .take(30)
        .map(|((cand, kind), cnt)| {
            json!({
                "candidate": cand,
                "kind": kind,
                "count": cnt,
            })
        })
        .collect();

    let mut code_vec: Vec<(String, CodeAgg)> = code_counts.into_iter().collect();
    code_vec.sort_by(|a, b| b.1.count.cmp(&a.1.count).then_with(|| a.0.cmp(&b.0)));
    let code_token_candidates_json: Vec<Value> = code_vec
        .into_iter()
        .take(50)
        .map(|(tok, ag)| {
            json!({
                "token": tok,
                "pattern_family": ag.family,
                "count": ag.count,
                "sample_subject": ag.sample_subject,
            })
        })
        .collect();

    let mut hdr_vec: Vec<(String, usize)> = table_header_counts.into_iter().collect();
    hdr_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let hdrs_json: Vec<Value> = hdr_vec
        .into_iter()
        .take(40)
        .map(|(h, c)| json!({ "header": h, "count": c }))
        .collect();

    let mut curr_vec: Vec<(String, usize)> = currency_counts.into_iter().collect();
    curr_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let currs_json: Vec<Value> = curr_vec
        .into_iter()
        .map(|(c, n)| json!({ "currency": c, "count": n }))
        .collect();

    let mut ext_vec: Vec<(String, usize)> = att_ext_counts.into_iter().collect();
    ext_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let by_ext_json: Vec<Value> = ext_vec
        .into_iter()
        .take(20)
        .map(|(e, c)| json!({ "ext": e, "count": c }))
        .collect();

    Ok(json!({
        "status": "ok",
        "source": sample.source_label,
        "sampled_messages": sample.raw_messages.len(),
        "accounts": sample.accounts,
        "inferred_identity": {
            "self_emails": sample.inferred_identity.self_emails,
            "internal_domains": sample.inferred_identity.internal_domains,
        },
        "top_external_domains": top_external_domains_json,
        "subject_topic_candidates": subject_topic_candidates_json,
        "code_token_candidates": code_token_candidates_json,
        "table_headers_and_currencies": {
            "table_headers": hdrs_json,
            "currencies": currs_json,
        },
        "attachment_stats": {
            "total": att_total,
            "clean": att_clean,
            "noise": att_noise,
            "by_ext": by_ext_json,
        },
        "sample_subjects": sample_subjects,
        "warnings": sample.warnings,
    }))
}

fn rate4(hits: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        ((hits as f64 / total as f64) * 10000.0).round() / 10000.0
    }
}

/// Evaluates a `domain-pack.v1` JSON file over sampled messages and reports hit rates,
/// dimension/intent distributions, top entities, and unmatched subjects.
pub fn run_test_pack(cfg: &MailKbConfig, opts: &TestPackOpts) -> KbResult<Value> {
    let val_report = validate_pack_file(&opts.pack_path)?;
    let pack = CompiledDomainPack::from_files(&[opts.pack_path.clone()])?;
    let mut warnings = val_report.warnings;

    let pre_identity = ResolvedIdentity::from_pack_and_inferred(&pack, &InferredIdentity::default());
    let sample = load_corpus_sample(
        cfg,
        opts.from_db.as_ref(),
        opts.sample.max(1),
        true,
        &pre_identity,
    )?;
    warnings.extend(sample.warnings);

    let final_identity = ResolvedIdentity::from_pack_and_inferred(&pack, &sample.inferred_identity);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.max_threads.max(1))
        .build()
        .map_err(|e| KbError::Other(format!("failed to create rayon pool: {e}")))?;

    let enriched: Vec<EnrichedMsg> = pool.install(|| {
        sample
            .raw_messages
            .par_iter()
            .map(|raw| enrich_message(raw, &pack, &final_identity))
            .collect()
    });

    let sampled = enriched.len();
    let mut entity_hits = 0usize;
    let mut org_hits = 0usize;
    let mut topic_hits = 0usize;
    let mut amount_hits = 0usize;

    let mut intent_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut direction_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut category_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut dimension_counts: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    let mut entity_freq: HashMap<(String, String), usize> = HashMap::new();
    let mut org_freq: HashMap<String, usize> = HashMap::new();
    let mut topic_freq: HashMap<String, usize> = HashMap::new();
    let mut unmatched_sample_subjects: Vec<String> = Vec::new();

    for em in &enriched {
        let has_ent = !em.primary_entities_vec.is_empty();
        let has_org = !em.org_vec.is_empty();
        let has_top = !em.topic_vec.is_empty();
        if has_ent {
            entity_hits += 1;
        }
        if has_org {
            org_hits += 1;
        }
        if has_top {
            topic_hits += 1;
        }
        if em.has_amount != 0 {
            amount_hits += 1;
        }
        if !has_ent && !has_org && !has_top && unmatched_sample_subjects.len() < 20 {
            let s = term_safe(&em.subject, true);
            if !s.is_empty() && !contains_any_ci(&s, &["automatic reply", "自动回复"]) {
                unmatched_sample_subjects.push(s);
            }
        }

        *intent_counts.entry(em.intent_type.clone()).or_insert(0) += 1;
        *direction_counts.entry(em.direction.clone()).or_insert(0) += 1;
        *category_counts
            .entry(em.primary_category.clone())
            .or_insert(0) += 1;

        for (dim_name, vals) in &em.custom_dims_map {
            let dmap = dimension_counts.entry(dim_name.clone()).or_default();
            for v in vals {
                *dmap.entry(v.clone()).or_insert(0) += 1;
            }
        }
        for ent in &em.entities {
            if ent.entity_type == "item_code" {
                *entity_freq
                    .entry((ent.entity_key.clone(), ent.category.clone()))
                    .or_insert(0) += 1;
            }
        }
        for o in &em.org_vec {
            *org_freq.entry(o.clone()).or_insert(0) += 1;
        }
        for t in &em.topic_vec {
            *topic_freq.entry(t.clone()).or_insert(0) += 1;
        }
    }

    let mut top_ent_vec: Vec<((String, String), usize)> = entity_freq.into_iter().collect();
    top_ent_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_entities: Vec<Value> = top_ent_vec
        .into_iter()
        .take(25)
        .map(|((k, cat), c)| json!({ "entity_key": k, "category": cat, "count": c }))
        .collect();

    let mut top_org_vec: Vec<(String, usize)> = org_freq.into_iter().collect();
    top_org_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_orgs: Vec<Value> = top_org_vec
        .into_iter()
        .take(15)
        .map(|(k, c)| json!({ "org": k, "count": c }))
        .collect();

    let mut top_topic_vec: Vec<(String, usize)> = topic_freq.into_iter().collect();
    top_topic_vec.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let top_topics: Vec<Value> = top_topic_vec
        .into_iter()
        .take(15)
        .map(|(k, c)| json!({ "topic": k, "count": c }))
        .collect();

    Ok(json!({
        "status": "ok",
        "pack_id": val_report.pack_id,
        "pack_version": val_report.version,
        "source": sample.source_label,
        "sampled": sampled,
        "entity_hits": entity_hits,
        "entity_hit_rate": rate4(entity_hits, sampled),
        "org_hits": org_hits,
        "org_hit_rate": rate4(org_hits, sampled),
        "topic_hits": topic_hits,
        "topic_hit_rate": rate4(topic_hits, sampled),
        "amount_hits": amount_hits,
        "amount_hit_rate": rate4(amount_hits, sampled),
        "intent_counts": intent_counts,
        "direction_counts": direction_counts,
        "category_counts": category_counts,
        "dimension_counts": dimension_counts,
        "top_entities": top_entities,
        "top_orgs": top_orgs,
        "top_topics": top_topics,
        "unmatched_sample_subjects": unmatched_sample_subjects,
        "warnings": warnings,
    }))
}
