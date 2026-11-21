//! Terminal-safe (`term_safe` / S11) human output formatters for `mailkb-query`.

use mailkb_core::security::{term_safe, trunc_chars};
use serde_json::Value;
use std::fmt::Write as _;

fn val_str(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}

fn val_or_dash(v: &Value, key: &str) -> String {
    let s = val_str(v, key);
    if s.is_empty() {
        "-".to_string()
    } else {
        term_safe(&s, true)
    }
}

fn val_i64(v: &Value, key: &str) -> i64 {
    v.get(key).and_then(Value::as_i64).unwrap_or(0)
}

fn val_f64(v: &Value, key: &str) -> f64 {
    v.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

fn val_arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

fn char_prefix(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

pub fn render_search(v: &Value) -> String {
    let rows = val_arr(v, "results");
    let mode = val_str(v, "mode");
    let ms = val_f64(v, "elapsed_ms");
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[mailkb search] hits={} mode={} elapsed={ms:.2}ms",
        rows.len(),
        if mode.is_empty() { "both" } else { &mode }
    );
    for hr in rows {
        let id = val_i64(hr, "id");
        let date_iso = char_prefix(&val_str(hr, "date_iso"), 19);
        let acct = val_or_dash(hr, "account_id");
        let intent = val_or_dash(hr, "intent_type");
        let topic = val_or_dash(hr, "topic_tags");
        let org = val_or_dash(hr, "org_tags");
        let _ = writeln!(
            out,
            "#{id} [{}/{}:{}] {date_iso} intent={intent} topic={topic} org={org} amt={}",
            term_safe(&val_str(hr, "source"), true),
            term_safe(&val_str(hr, "completeness"), true),
            acct,
            val_i64(hr, "has_amount"),
        );
        let _ = writeln!(out, "  subj   : {}", trunc_chars(&val_str(hr, "subject"), 100));
        let summary = val_str(hr, "summary_line");
        if !summary.is_empty() {
            let _ = writeln!(out, "  summary: {}", trunc_chars(&summary, 120));
        }
        let ents = val_str(hr, "primary_entities");
        if !ents.is_empty() {
            let _ = writeln!(out, "  entity : {}", trunc_chars(&ents, 100));
        }
        let amt_sum = val_str(hr, "amount_summary");
        if !amt_sum.is_empty() {
            let _ = writeln!(out, "  amounts: {}", trunc_chars(&amt_sum, 120));
        }
    }
    out
}

pub fn render_read(v: &Value, full: bool) -> String {
    let msg = v.get("message").unwrap_or(&Value::Null);
    let mid = val_i64(msg, "id");
    let dir = val_or_dash(msg, "direction");
    let acct = val_or_dash(msg, "account_id");
    let ms = val_f64(v, "elapsed_ms");
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[mailkb read] id={mid} account={acct} source={} completeness={} direction={dir} elapsed={ms:.2}ms",
        term_safe(&val_str(msg, "source"), true),
        term_safe(&val_str(msg, "completeness"), true),
    );
    let _ = writeln!(out, "{}", "=".repeat(80));
    let _ = writeln!(out, "Subject   : {}", term_safe(&val_str(msg, "subject"), true));
    let _ = writeln!(
        out,
        "Thread    : {}",
        term_safe(&val_str(msg, "thread_topic"), true)
    );
    let _ = writeln!(out, "Date      : {}", term_safe(&val_str(msg, "date_iso"), true));
    let _ = writeln!(out, "From      : {}", term_safe(&val_str(msg, "sender"), true));
    let _ = writeln!(
        out,
        "To        : {}",
        term_safe(&val_str(msg, "recipients"), true)
    );
    let cc = val_str(msg, "cc");
    if !cc.is_empty() {
        let _ = writeln!(out, "Cc        : {}", term_safe(&cc, true));
    }
    let _ = writeln!(
        out,
        "Folder    : {}",
        term_safe(&val_str(msg, "folder_path"), true)
    );
    let _ = writeln!(
        out,
        "Intent    : {} | Orgs: {} | Topics: {}",
        val_or_dash(msg, "intent_type"),
        val_or_dash(msg, "org_tags"),
        val_or_dash(msg, "topic_tags")
    );
    let _ = writeln!(
        out,
        "Entities  : {} | Category: {}",
        val_or_dash(msg, "primary_entities"),
        val_or_dash(msg, "primary_category")
    );
    let summary = val_str(msg, "summary_line");
    if !summary.is_empty() {
        let _ = writeln!(out, "Summary   : {}", term_safe(&summary, false));
    }
    let amt_sum = val_str(msg, "amount_summary");
    if !amt_sum.is_empty() {
        let _ = writeln!(out, "Amounts   : {}", term_safe(&amt_sum, false));
    }
    let _ = writeln!(out, "{}", "-".repeat(80));
    let _ = writeln!(out, "{}", term_safe(&val_str(msg, "body_latest"), false));

    let entities = val_arr(v, "entities");
    if !entities.is_empty() {
        out.push_str("\n--- Extracted Entities ---\n");
        for e in entities {
            let _ = writeln!(
                out,
                "  [{}] {} | cat={} sub={} qty={} {}",
                term_safe(&val_str(e, "entity_type"), true),
                term_safe(&val_str(e, "entity_key"), true),
                val_or_dash(e, "category"),
                val_or_dash(e, "sub_group"),
                val_or_dash(e, "quantity"),
                term_safe(&val_str(e, "unit"), true),
            );
        }
    }

    let amounts = val_arr(v, "amounts");
    if !amounts.is_empty() {
        out.push_str("\n--- Extracted Amounts ---\n");
        for a in amounts {
            let _ = writeln!(
                out,
                "  {} | {} unit={} qty={} tot={} [{}] {}",
                val_or_dash(a, "subject_entity"),
                val_or_dash(a, "currency"),
                val_or_dash(a, "unit_amount"),
                val_or_dash(a, "quantity"),
                val_or_dash(a, "total_amount"),
                val_or_dash(a, "confidence"),
                trunc_chars(&val_str(a, "evidence_snippet"), 100)
            );
        }
    }

    let atts = val_arr(v, "attachments");
    if !atts.is_empty() {
        out.push_str("\n--- Attachments ---\n");
        for a in atts {
            let mut flags = Vec::new();
            if val_i64(a, "is_inline") != 0 {
                flags.push("inline");
            }
            if val_i64(a, "is_noise") != 0 {
                flags.push("noise");
            }
            let _ = writeln!(
                out,
                "  {} ({}, {}B, {})",
                term_safe(&val_str(a, "filename"), true),
                val_or_dash(a, "ext"),
                val_i64(a, "size_bytes"),
                if flags.is_empty() {
                    "file".to_string()
                } else {
                    flags.join(",")
                }
            );
        }
    }

    let quoted = val_str(msg, "body_quoted");
    if full && !quoted.is_empty() {
        let _ = writeln!(out, "\n--- Quoted Thread ---\n{}", term_safe(&quoted, false));
    }
    out
}

pub fn render_entities(v: &Value) -> String {
    let ms = val_f64(v, "elapsed_ms");
    let mut out = String::new();
    let rows = val_arr(v, "results");
    let query_ent = val_str(v, "query_entity");

    if query_ent.is_empty() {
        let _ = writeln!(out, "[mailkb entities] count={} elapsed={ms:.2}ms", rows.len());
        for r in rows {
            let _ = writeln!(
                out,
                "  {:<24} type={:<12} cat={:<12} msgs={:<5} mentions={:<5} amts={:<4} {}~{}",
                trunc_chars(&val_str(r, "entity_key"), 24),
                trunc_chars(&val_str(r, "entity_type"), 12),
                trunc_chars(&val_str(r, "category"), 12),
                val_i64(r, "message_count"),
                val_i64(r, "mention_count"),
                val_i64(r, "amount_count"),
                char_prefix(&val_str(r, "first_date_iso"), 10),
                char_prefix(&val_str(r, "last_date_iso"), 10),
            );
        }
        return out;
    }

    let mentions = val_arr(v, "entity_mentions");
    let amts = val_arr(v, "amount_history");
    let msgs = val_arr(v, "messages");
    let _ = writeln!(
        out,
        "[mailkb entities] query={} agg={} mentions={} amounts={} msgs={} elapsed={ms:.2}ms",
        term_safe(&query_ent, true),
        rows.len(),
        mentions.len(),
        amts.len(),
        msgs.len(),
    );
    for a in amts.iter().take(10) {
        let _ = writeln!(
            out,
            "  [AMOUNT] #{} {} {} {} {} topic={}",
            val_i64(a, "message_id"),
            char_prefix(&val_str(a, "effective_date_iso"), 10),
            val_or_dash(a, "subject_entity"),
            val_or_dash(a, "currency"),
            val_or_dash(a, "unit_amount"),
            val_or_dash(a, "topic_name"),
        );
    }
    for m in msgs.iter().take(10) {
        let _ = writeln!(
            out,
            "  [MSG]    #{} {} [{}] {}",
            val_i64(m, "id"),
            char_prefix(&val_str(m, "date_iso"), 10),
            val_or_dash(m, "intent_type"),
            trunc_chars(&val_str(m, "subject"), 80)
        );
    }
    out
}

pub fn render_amounts(v: &Value) -> String {
    let rows = val_arr(v, "results");
    let ms = val_f64(v, "elapsed_ms");
    let mut out = String::new();
    let _ = writeln!(out, "[mailkb amounts] rows={} elapsed={ms:.2}ms", rows.len());
    for rv in rows {
        let _ = writeln!(
            out,
            "#{} {} | {:<22} | {:<3} unit={} qty={} tot={} [{}/{}]",
            val_i64(rv, "message_id"),
            char_prefix(&val_str(rv, "effective_date_iso"), 10),
            trunc_chars(&val_or_dash(rv, "subject_entity"), 22),
            val_or_dash(rv, "currency"),
            val_or_dash(rv, "unit_amount"),
            val_or_dash(rv, "quantity"),
            val_or_dash(rv, "total_amount"),
            val_or_dash(rv, "confidence"),
            val_or_dash(rv, "source_kind"),
        );
        let topic = val_or_dash(rv, "topic_name");
        let org = val_or_dash(rv, "org_name");
        let atype = val_or_dash(rv, "amount_type");
        if topic != "-" || org != "-" || atype != "-" {
            let _ = writeln!(out, "    topic={topic} org={org} type={atype}");
        }
        let moq = val_str(rv, "moq");
        let lead = val_str(rv, "lead_time");
        let disc = val_str(rv, "discount_info");
        if !moq.is_empty() || !lead.is_empty() || !disc.is_empty() {
            let _ = writeln!(
                out,
                "    terms: moq={} lead={} disc={}",
                if moq.is_empty() { "-" } else { &moq },
                if lead.is_empty() { "-" } else { &lead },
                if disc.is_empty() { "-" } else { &disc }
            );
        }
        let evid = val_str(rv, "evidence_snippet");
        if !evid.is_empty() {
            let _ = writeln!(out, "    evid: {}", trunc_chars(&evid, 120));
        }
    }
    out
}

pub fn render_topics(v: &Value) -> String {
    let ms = val_f64(v, "elapsed_ms");
    let mut out = String::new();
    let q = val_str(v, "query_topic");
    if q.is_empty() {
        let rows = val_arr(v, "results");
        let _ = writeln!(out, "[mailkb topics] count={} elapsed={ms:.2}ms", rows.len());
        for r in rows {
            let _ = writeln!(
                out,
                "  {:<26} msgs={:<5} full={:<4} amt={:<4} {}~{}",
                trunc_chars(&val_str(r, "topic_name"), 26),
                val_i64(r, "message_count"),
                val_i64(r, "full_body_count"),
                val_i64(r, "amount_message_count"),
                char_prefix(&val_str(r, "first_date_iso"), 10),
                char_prefix(&val_str(r, "last_date_iso"), 10),
            );
        }
        return out;
    }

    let msgs = val_arr(v, "messages");
    let amts = val_arr(v, "amounts");
    let _ = writeln!(
        out,
        "[mailkb topics] query={} msgs={} amounts={} elapsed={ms:.2}ms",
        term_safe(&q, true),
        msgs.len(),
        amts.len(),
    );
    for m in msgs.iter().take(15) {
        let _ = writeln!(
            out,
            "  #{} {} [{}] {}",
            val_i64(m, "id"),
            char_prefix(&val_str(m, "date_iso"), 10),
            val_or_dash(m, "intent_type"),
            trunc_chars(&val_str(m, "subject"), 80)
        );
    }
    out
}

pub fn render_orgs(v: &Value) -> String {
    let ms = val_f64(v, "elapsed_ms");
    let mut out = String::new();
    let q = val_str(v, "query_org");
    if q.is_empty() {
        let rows = val_arr(v, "results");
        let _ = writeln!(out, "[mailkb orgs] count={} elapsed={ms:.2}ms", rows.len());
        for r in rows {
            let _ = writeln!(
                out,
                "  {:<26} msgs={:<5} full={:<4} amt={:<4} {}~{}",
                trunc_chars(&val_str(r, "org_name"), 26),
                val_i64(r, "message_count"),
                val_i64(r, "full_body_count"),
                val_i64(r, "amount_message_count"),
                char_prefix(&val_str(r, "first_date_iso"), 10),
                char_prefix(&val_str(r, "last_date_iso"), 10),
            );
        }
        return out;
    }

    let msgs = val_arr(v, "messages");
    let amts = val_arr(v, "amounts");
    let _ = writeln!(
        out,
        "[mailkb orgs] query={} msgs={} amounts={} elapsed={ms:.2}ms",
        term_safe(&q, true),
        msgs.len(),
        amts.len(),
    );
    for m in msgs.iter().take(15) {
        let _ = writeln!(
            out,
            "  #{} {} [{}] {}",
            val_i64(m, "id"),
            char_prefix(&val_str(m, "date_iso"), 10),
            val_or_dash(m, "intent_type"),
            trunc_chars(&val_str(m, "subject"), 80)
        );
    }
    out
}

pub fn render_timeline(v: &Value) -> String {
    let gran = val_str(v, "granularity");
    let rows = val_arr(v, "results");
    let ms = val_f64(v, "elapsed_ms");
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[mailkb timeline] granularity={gran} periods={} elapsed={ms:.2}ms",
        rows.len()
    );
    for r in rows {
        let p = {
            let s = val_str(r, "period");
            if s.is_empty() {
                val_str(r, "ym")
            } else {
                s
            }
        };
        let amt_cnt = if r.get("amount_message_count").is_some() {
            val_i64(r, "amount_message_count")
        } else {
            val_i64(r, "price_message_count")
        };
        let _ = writeln!(
            out,
            "  {:<10} msgs={:<5} full={:<4} amt={:<4} in={:<4} out={:<4} topics={}",
            term_safe(&p, true),
            val_i64(r, "message_count"),
            val_i64(r, "full_body_count"),
            amt_cnt,
            val_i64(r, "inbound_count"),
            val_i64(r, "outbound_count"),
            val_i64(r, "active_topics")
        );
    }
    out
}

pub fn render_att(v: &Value) -> String {
    let rows = val_arr(v, "results");
    let ms = val_f64(v, "elapsed_ms");
    let mut out = String::new();
    let _ = writeln!(out, "[mailkb att] hits={} elapsed={ms:.2}ms", rows.len());
    if !rows.is_empty() {
        let _ = writeln!(
            out,
            "{:<6} | {:<7} | {:<6} | {:<9} | {:<14} | {:<19} | {}",
            "ID", "MSG_ID", "EXT", "SIZE", "ENTITIES", "MTIME", "FILENAME"
        );
        let _ = writeln!(out, "{}", "-".repeat(110));
        for r in rows {
            let kb = (val_i64(r, "size_bytes") as f64) / 1024.0;
            let noise_tag = if val_i64(r, "is_noise") != 0 {
                " [NOISE]"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "{:<6} | {:<7} | {:<6} | {:6.1} KB | {:<14} | {:<19} | {}{}",
                val_i64(r, "id"),
                val_i64(r, "message_id"),
                char_prefix(&term_safe(&val_str(r, "ext"), true), 6),
                kb,
                char_prefix(&term_safe(&val_str(r, "entity_tags"), true), 14),
                char_prefix(&term_safe(&val_str(r, "mtime_iso"), true), 19),
                term_safe(&val_str(r, "clean_filename"), true),
                noise_tag
            );
        }
    }
    out
}

pub fn render_stats(v: &Value) -> String {
    let counts = v.get("counts").unwrap_or(&Value::Null);
    let db_bytes = val_i64(v, "db_bytes");
    let ms = val_f64(v, "elapsed_ms");

    let mut out = String::new();
    let _ = writeln!(
        out,
        "[mailkb stats] messages={} (with_amount={}, entities={}, amounts={}, attachments={}, clean_att={}, lexicon={}) db={:.2}MB elapsed={:.2}ms",
        val_i64(counts, "mail_messages"),
        val_i64(counts, "messages_with_amount"),
        val_i64(counts, "message_entities"),
        val_i64(counts, "message_amounts"),
        val_i64(counts, "message_attachments"),
        val_i64(counts, "attachments_clean"),
        val_i64(counts, "domain_lexicon"),
        (db_bytes as f64) / (1024.0 * 1024.0),
        ms
    );
    let _ = writeln!(
        out,
        "  Schema={} | Writer={} | Packs={} | Range={} ~ {}",
        term_safe(&val_str(v, "schema_version"), true),
        term_safe(&val_str(v, "writer_version"), true),
        val_or_dash(v, "pack_ids"),
        term_safe(&val_str(v, "date_min"), true),
        term_safe(&val_str(v, "date_max"), true),
    );
    let _ = writeln!(
        out,
        "  Runtime={} (staging={})",
        term_safe(&val_str(v, "runtime_db"), true),
        term_safe(&val_str(v, "staging"), true)
    );

    let write_kv_list = |out: &mut String, label: &str, arr: &[Value], key_col: &str| {
        if arr.is_empty() {
            return;
        }
        let _ = write!(out, "\n{label}: ");
        for (idx, r) in arr.iter().enumerate() {
            if idx > 0 {
                out.push_str(", ");
            }
            let _ = write!(
                out,
                "{}:{}",
                val_or_dash(r, key_col),
                val_i64(r, "count")
            );
        }
    };

    write_kv_list(&mut out, "Accounts", val_arr(v, "by_account"), "account_id");
    write_kv_list(&mut out, "Sources", val_arr(v, "by_source"), "source");
    write_kv_list(&mut out, "Directions", val_arr(v, "by_direction"), "direction");
    write_kv_list(&mut out, "Categories", val_arr(v, "by_category"), "primary_category");
    out.push('\n');

    let intents = val_arr(v, "by_intent");
    if !intents.is_empty() {
        out.push_str("\nTop Intents:\n");
        for r in intents {
            let _ = writeln!(
                out,
                "  {:<24} {}",
                trunc_chars(&val_str(r, "intent_type"), 24),
                val_i64(r, "count")
            );
        }
    }

    let topics = val_arr(v, "top_topics");
    if !topics.is_empty() {
        out.push_str("\nTop Topics:\n");
        for r in topics.iter().take(10) {
            let _ = writeln!(
                out,
                "  {:<26} msgs={} full={} amt={}",
                trunc_chars(&val_str(r, "topic_name"), 26),
                val_i64(r, "message_count"),
                val_i64(r, "full_body_count"),
                val_i64(r, "amount_message_count")
            );
        }
    }
    out
}

pub fn render_audit(v: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[mailkb audit] status={} schema={} host={} elapsed={:.2}ms",
        term_safe(&val_str(v, "status"), true),
        term_safe(&val_str(v, "schema_version"), true),
        term_safe(&val_str(v, "host"), true),
        val_f64(v, "elapsed_ms")
    );
    let _ = writeln!(
        out,
        "  Source={} | Runtime={}",
        term_safe(&val_str(v, "source_db"), true),
        term_safe(&val_str(v, "runtime_db"), true),
    );
    for c in val_arr(v, "checks") {
        let ok = c.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let sev = val_str(c, "severity");
        let badge = if ok {
            "PASS"
        } else if sev == "warn" {
            "WARN"
        } else {
            "FAIL"
        };
        let _ = writeln!(
            out,
            "  {:<28} [{:<4}] {}",
            val_str(c, "name"),
            badge,
            term_safe(&val_str(c, "detail"), true)
        );
    }
    let warnings = val_arr(v, "warnings");
    if !warnings.is_empty() {
        out.push_str("  Warnings:\n");
        for w in warnings {
            if let Some(s) = w.as_str() {
                let _ = writeln!(out, "    - {}", term_safe(s, true));
            }
        }
    }
    out
}

pub fn render_selftest(v: &Value) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[mailkb selftest] engine={} schema={} host={} sqlite={} threads={} elapsed={:.2}ms",
        term_safe(&val_str(v, "engine"), true),
        term_safe(&val_str(v, "schema_version"), true),
        term_safe(&val_str(v, "host"), true),
        term_safe(&val_str(v, "sqlite_version"), true),
        val_i64(v, "threads"),
        val_f64(v, "elapsed_ms"),
    );
    for c in val_arr(v, "checks") {
        let ok = c.get("ok").and_then(Value::as_bool).unwrap_or(false);
        let _ = writeln!(
            out,
            "  {:<32} {:<4} {}",
            val_str(c, "name"),
            if ok { "PASS" } else { "FAIL" },
            term_safe(&val_str(c, "detail"), true)
        );
    }
    let all = val_str(v, "status") == "ok";
    let _ = writeln!(out, "{}", if all { "ALL PASS" } else { "FAILURES PRESENT" });
    out
}
