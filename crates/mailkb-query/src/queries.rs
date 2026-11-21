//! Multi-threaded read-only query engines (`search`, `read`, `entities`, `amounts`,
//! `topics`, `orgs`, `timeline`, `att`, `stats`) against `1.0-universal` schema.

use crate::audit::{mail_master_state, MasterState};
use crate::db::{
    attach_runtime_fields, elapsed_ms, kb_meta_all, open_staged_worker, query_rows_json,
    query_scalar_i64, query_scalar_str, remap_stored_path, resolve_attachment_path, row_to_map,
    stage_and_open, AttachmentPathInfo, WarningBag,
};
use crate::{
    AmountListOpts, AttOpts, AutoSyncCallback, EntityListOpts, OrgListOpts, ReadOpts, SearchOpts,
    TimelineOpts, TopicListOpts,
};
use mailkb_core::config::MailKbConfig;
use mailkb_core::error::{KbError, KbResult};
use mailkb_core::fts::{build_cjk_bigram_fts_query, like_escape, normalize_model_key};
use mailkb_core::staging::StageInfo;
use rusqlite::{params_from_iter, Connection, ToSql};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

fn validate_limit(limit: usize) -> KbResult<i64> {
    if !(1..=500).contains(&limit) {
        return Err(KbError::InvalidArgument(
            "--limit must be 1..500".to_string(),
        ));
    }
    Ok(limit as i64)
}

fn until_bound(until: &str) -> String {
    let b = until.as_bytes();
    if b.len() == 10 && b[4] == b'-' && b[7] == b'-' {
        // '~' (0x7E) sorts after both ' ' (0x20) and 'T' (0x54), covering both date formats.
        format!("{until}~")
    } else {
        until.to_string()
    }
}

fn validate_dim_key(raw: &str) -> KbResult<String> {
    let k = raw.trim();
    if k.is_empty()
        || k.len() > 64
        || !k
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err(KbError::InvalidArgument(format!(
            "Invalid --dim key '{raw}': expected [A-Za-z0-9_-]{{1,64}}"
        )));
    }
    Ok(k.to_string())
}

fn json_member_path(key: &str) -> String {
    format!("$.\"{key}\"")
}

fn finish_response(
    stage: &StageInfo,
    warnings: &WarningBag,
    ms: f64,
    extra: Vec<(&str, Value)>,
) -> Value {
    let mut map = Map::new();
    attach_runtime_fields(&mut map, stage, warnings);
    map.insert("elapsed_ms".to_string(), json!(ms));
    for (k, v) in extra {
        map.insert(k.to_string(), v);
    }
    Value::Object(map)
}

fn attach_att_path_fields(
    map: &mut Map<String, Value>,
    info: AttachmentPathInfo,
) {
    map.insert(
        "local_path".to_string(),
        info.local_path.map(Value::String).unwrap_or(Value::Null),
    );
    if let Some(cp) = info.container_path {
        map.insert("container_path".to_string(), Value::String(cp));
    }
    map.insert("local_exists".to_string(), Value::Bool(info.local_exists));
    if info.path_rejected {
        map.insert("path_rejected".to_string(), Value::Bool(true));
    }
}

fn attach_source_path_fields(
    cfg: &MailKbConfig,
    map: &mut Map<String, Value>,
    source: &str,
    source_ref: &str,
    account_id: &str,
) {
    if source == "eml" || source == "emlx" {
        let acct = (!account_id.is_empty()).then_some(account_id);
        let (resolved, rejected) = remap_stored_path(cfg, source_ref, acct);
        map.insert(
            "eml_path".to_string(),
            resolved.map(Value::String).unwrap_or(Value::Null),
        );
        if rejected {
            map.insert("path_rejected".to_string(), Value::Bool(true));
        }
    }
}

#[derive(Debug, Clone)]
struct HitRow {
    id: i64,
    date_iso: String,
    rank: f64,
    hit_in: Vec<&'static str>,
    map: Map<String, Value>,
}

const SEARCH_COLS: &str = "m.id, m.uid_key, m.account_id, m.source, m.source_ref, m.rfc_message_id, \
    m.completeness, m.direction, m.folder_path, m.date_iso, m.subject, m.thread_topic, \
    m.sender, m.recipients, m.primary_entities, m.primary_category, m.topic_tags, m.org_tags, \
    m.intent_type, m.summary_line, m.has_amount, m.amount_summary, m.custom_dims_json";

pub fn run_search_impl(
    cfg: &MailKbConfig,
    opts: &SearchOpts,
    sync: Option<AutoSyncCallback<'_>>,
) -> KbResult<Value> {
    let lim = validate_limit(opts.limit)?;
    if !matches!(opts.mode.as_str(), "both" | "dim" | "msg") {
        return Err(KbError::InvalidArgument(
            "--mode must be both|dim|msg".to_string(),
        ));
    }

    let mut pre_warnings: Vec<String> = Vec::new();
    if opts.auto_sync {
        match mail_master_state(cfg) {
            MasterState::NotMaster(why) => {
                pre_warnings.push(format!("auto_sync_skipped_non_master_host: {why}"));
            }
            MasterState::AccessDenied(why) => {
                pre_warnings.push(format!("auto_sync_skipped_access_denied: {why}"));
            }
            MasterState::Master => {
                if let Some(cb) = sync {
                    if let Err(e) = cb(cfg) {
                        pre_warnings.push(format!("auto_sync_failed: {e}"));
                    }
                } else {
                    pre_warnings.push("auto_sync_skipped_no_sync_callback".to_string());
                }
            }
        }
    }

    let t0 = Instant::now();
    let (stage, conn, mut warnings) = stage_and_open(cfg)?;
    warnings.extend(pre_warnings);

    let mut where_clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(acct_raw) = opts.account.as_deref().filter(|s| !s.trim().is_empty()) {
        let parts: Vec<&str> = acct_raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if parts.len() == 1 {
            where_clauses.push("LOWER(m.account_id) LIKE LOWER(?) ESCAPE '\\'".to_string());
            params.push(format!("%{}%", like_escape(parts[0])));
        } else if parts.len() > 1 {
            let mut ors = Vec::with_capacity(parts.len());
            for p in parts {
                ors.push("LOWER(m.account_id) LIKE LOWER(?) ESCAPE '\\'");
                params.push(format!("%{}%", like_escape(p)));
            }
            where_clauses.push(format!("({})", ors.join(" OR ")));
        }
    }
    if let Some(ent) = opts.entity.as_deref().filter(|s| !s.trim().is_empty()) {
        let norm = normalize_model_key(ent);
        if !norm.is_empty() {
            let esc = format!("%{}%", like_escape(&norm));
            where_clauses.push(
                "(REPLACE(REPLACE(UPPER(m.primary_entities), '-', ''), ' ', '') LIKE ? ESCAPE '\\' \
                 OR REPLACE(REPLACE(UPPER(m.subject), '-', ''), ' ', '') LIKE ? ESCAPE '\\' \
                 OR EXISTS (SELECT 1 FROM message_entities me WHERE me.message_id = m.id \
                 AND REPLACE(REPLACE(UPPER(me.entity_key), '-', ''), ' ', '') LIKE ? ESCAPE '\\'))"
                    .to_string(),
            );
            params.push(esc.clone());
            params.push(esc.clone());
            params.push(esc);
        } else {
            where_clauses.push("1=0".to_string());
        }
    }
    if let Some(cat) = opts.category.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push(
            "(UPPER(m.primary_category) = UPPER(?) \
             OR EXISTS (SELECT 1 FROM message_entities me WHERE me.message_id = m.id AND UPPER(me.category) = UPPER(?)))"
                .to_string(),
        );
        params.push(cat.trim().to_string());
        params.push(cat.trim().to_string());
    }
    if let Some(topic) = opts.topic.as_deref().filter(|s| !s.trim().is_empty()) {
        let esc = format!("%{}%", like_escape(topic.trim()));
        where_clauses
            .push("(m.topic_tags LIKE ? ESCAPE '\\' OR m.subject LIKE ? ESCAPE '\\')".to_string());
        params.push(esc.clone());
        params.push(esc);
    }
    if let Some(org) = opts.org.as_deref().filter(|s| !s.trim().is_empty()) {
        let esc = format!("%{}%", like_escape(org.trim()));
        where_clauses.push(
            "(m.org_tags LIKE ? ESCAPE '\\' OR m.sender LIKE ? ESCAPE '\\' OR m.recipients LIKE ? ESCAPE '\\')"
                .to_string(),
        );
        params.push(esc.clone());
        params.push(esc.clone());
        params.push(esc);
    }
    if let Some(intent) = opts.intent.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("m.intent_type LIKE ? ESCAPE '\\'".to_string());
        params.push(format!("%{}%", like_escape(intent.trim())));
    }
    if let Some(dir) = opts.direction.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("m.direction = ?".to_string());
        params.push(dir.trim().to_string());
    }
    if let Some(comp) = opts.completeness.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("m.completeness = ?".to_string());
        params.push(comp.trim().to_string());
    }
    if let Some(src) = opts.source.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("m.source = ?".to_string());
        params.push(src.trim().to_string());
    }
    if let Some(sender) = opts.sender.as_deref().filter(|s| !s.trim().is_empty()) {
        let esc = format!("%{}%", like_escape(sender.trim()));
        where_clauses.push(
            "(LOWER(m.sender) LIKE LOWER(?) ESCAPE '\\' OR LOWER(m.recipients) LIKE LOWER(?) ESCAPE '\\')"
                .to_string(),
        );
        params.push(esc.clone());
        params.push(esc);
    }
    if opts.has_amount {
        where_clauses.push("m.has_amount = 1".to_string());
    }
    if let Some(since) = opts.since.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("m.date_iso >= ?".to_string());
        params.push(since.trim().to_string());
    }
    if let Some(until) = opts.until.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("m.date_iso <= ?".to_string());
        params.push(until_bound(until.trim()));
    }

    for (raw_k, raw_v) in &opts.dim_filters {
        let key = validate_dim_key(raw_k)?;
        let val = raw_v.trim();
        if val.is_empty() {
            return Err(KbError::InvalidArgument(format!(
                "Empty value for --dim {key}="
            )));
        }
        let jpath = json_member_path(&key);
        let like_val = format!("%{}%", like_escape(val));
        let norm_val = normalize_model_key(val);
        if !norm_val.is_empty() {
            let norm_like = format!("%{}%", like_escape(&norm_val));
            where_clauses.push(
                "(EXISTS (SELECT 1 FROM message_entities me WHERE me.message_id = m.id \
                 AND LOWER(me.entity_type) = LOWER(?) \
                 AND (REPLACE(REPLACE(UPPER(me.entity_key), '-', ''), ' ', '') LIKE ? ESCAPE '\\' \
                 OR REPLACE(REPLACE(UPPER(me.canonical_value), '-', ''), ' ', '') LIKE ? ESCAPE '\\' \
                 OR LOWER(me.entity_key) LIKE LOWER(?) ESCAPE '\\' \
                 OR LOWER(me.canonical_value) LIKE LOWER(?) ESCAPE '\\')) \
                 OR REPLACE(REPLACE(UPPER(COALESCE(CAST(json_extract(m.custom_dims_json, ?) AS TEXT), '')), '-', ''), ' ', '') LIKE ? ESCAPE '\\' \
                 OR LOWER(COALESCE(CAST(json_extract(m.custom_dims_json, ?) AS TEXT), '')) LIKE LOWER(?) ESCAPE '\\')"
                    .to_string(),
            );
            params.push(key);
            params.push(norm_like.clone());
            params.push(norm_like.clone());
            params.push(like_val.clone());
            params.push(like_val.clone());
            params.push(jpath.clone());
            params.push(norm_like);
            params.push(jpath);
            params.push(like_val);
        } else {
            where_clauses.push(
                "(EXISTS (SELECT 1 FROM message_entities me WHERE me.message_id = m.id \
                 AND LOWER(me.entity_type) = LOWER(?) \
                 AND (LOWER(me.entity_key) LIKE LOWER(?) ESCAPE '\\' \
                 OR LOWER(me.canonical_value) LIKE LOWER(?) ESCAPE '\\')) \
                 OR LOWER(COALESCE(CAST(json_extract(m.custom_dims_json, ?) AS TEXT), '')) LIKE LOWER(?) ESCAPE '\\')"
                    .to_string(),
            );
            params.push(key);
            params.push(like_val.clone());
            params.push(like_val.clone());
            params.push(jpath);
            params.push(like_val);
        }
    }

    let (fts_q, was_trunc) = build_cjk_bigram_fts_query(&opts.keywords);
    if was_trunc {
        warnings.push("query_truncated");
    }

    let mut where_and = String::new();
    for w in &where_clauses {
        where_and.push_str(" AND ");
        where_and.push_str(w);
    }

    let results: Vec<HitRow> = if !fts_q.is_empty() {
        match opts.mode.as_str() {
            "dim" => {
                let sql = format!(
                    "SELECT {SEARCH_COLS}, bm25(dimensions_fts, 8.0, 6.0, 3.0, 5.0, 4.0, 4.0, 4.0) AS rank \
                     FROM dimensions_fts JOIN mail_messages m ON m.id = dimensions_fts.rowid \
                     WHERE dimensions_fts MATCH ?{where_and} \
                     ORDER BY rank ASC, m.date_iso DESC, m.id ASC LIMIT ?"
                );
                let mut bp = Vec::with_capacity(params.len() + 1);
                bp.push(fts_q.clone());
                bp.extend(params.iter().cloned());
                run_search_select(&conn, cfg, &sql, &bp, lim, Some("dimensions_fts"))?
            }
            "msg" => {
                let sql = format!(
                    "SELECT {SEARCH_COLS}, bm25(messages_fts, 10.0, 4.0, 6.0, 3.0, 1.0) AS rank \
                     FROM messages_fts JOIN mail_messages m ON m.id = messages_fts.rowid \
                     WHERE messages_fts MATCH ?{where_and} \
                     ORDER BY rank ASC, m.date_iso DESC, m.id ASC LIMIT ?"
                );
                let mut bp = Vec::with_capacity(params.len() + 1);
                bp.push(fts_q.clone());
                bp.extend(params.iter().cloned());
                run_search_select(&conn, cfg, &sql, &bp, lim, Some("messages_fts"))?
            }
            _ => {
                let dim_sql = format!(
                    "SELECT {SEARCH_COLS}, bm25(dimensions_fts, 8.0, 6.0, 3.0, 5.0, 4.0, 4.0, 4.0) AS rank \
                     FROM dimensions_fts JOIN mail_messages m ON m.id = dimensions_fts.rowid \
                     WHERE dimensions_fts MATCH ?{where_and} \
                     ORDER BY rank ASC, m.date_iso DESC LIMIT ?"
                );
                let msg_sql = format!(
                    "SELECT {SEARCH_COLS}, bm25(messages_fts, 10.0, 4.0, 6.0, 3.0, 1.0) AS rank \
                     FROM messages_fts JOIN mail_messages m ON m.id = messages_fts.rowid \
                     WHERE messages_fts MATCH ?{where_and} \
                     ORDER BY rank ASC, m.date_iso DESC LIMIT ?"
                );
                let mut bp = Vec::with_capacity(params.len() + 1);
                bp.push(fts_q.clone());
                bp.extend(params.iter().cloned());
                let double_lim = lim * 2;
                let rt_path = &stage.runtime_db;

                let (dim_res, msg_res) = std::thread::scope(|scope| {
                    let t2 = scope.spawn(|| {
                        let conn2 = open_staged_worker(rt_path)?;
                        run_search_select(
                            &conn2,
                            cfg,
                            &msg_sql,
                            &bp,
                            double_lim,
                            Some("messages_fts"),
                        )
                    });
                    let dim_res = run_search_select(
                        &conn,
                        cfg,
                        &dim_sql,
                        &bp,
                        double_lim,
                        Some("dimensions_fts"),
                    );
                    let msg_res = t2.join().expect("msg search worker panicked");
                    (dim_res, msg_res)
                });
                let dim_rows = dim_res?;
                let msg_rows = msg_res?;

                let mut merged: Vec<HitRow> = Vec::with_capacity(dim_rows.len() + msg_rows.len());
                let mut by_id: HashMap<i64, usize> =
                    HashMap::with_capacity(dim_rows.len() + msg_rows.len());
                for dr in dim_rows {
                    by_id.insert(dr.id, merged.len());
                    merged.push(dr);
                }
                for mr in msg_rows {
                    if let Some(&idx) = by_id.get(&mr.id) {
                        merged[idx].rank = merged[idx].rank.min(mr.rank) - 1.0;
                        merged[idx].hit_in.push("messages_fts");
                    } else {
                        by_id.insert(mr.id, merged.len());
                        merged.push(mr);
                    }
                }
                for hr in &mut merged {
                    hr.map.insert("rank".to_string(), json!(hr.rank));
                    let hits: Vec<Value> = hr
                        .hit_in
                        .iter()
                        .map(|s| Value::String((*s).to_string()))
                        .collect();
                    hr.map.insert("hit_in".to_string(), Value::Array(hits));
                }
                merged.sort_by(|a, b| {
                    let ar = (a.rank * 1e8).round() / 1e8;
                    let br = (b.rank * 1e8).round() / 1e8;
                    if ar != br {
                        ar.total_cmp(&br)
                    } else if a.date_iso != b.date_iso {
                        b.date_iso.cmp(&a.date_iso)
                    } else {
                        a.id.cmp(&b.id)
                    }
                });
                if merged.len() > opts.limit {
                    merged.truncate(opts.limit);
                }
                merged
            }
        }
    } else {
        let mut sql = format!("SELECT {SEARCH_COLS}, 0.0 AS rank FROM mail_messages m");
        if !where_clauses.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_clauses.join(" AND "));
        }
        sql.push_str(" ORDER BY m.date_iso DESC, m.id ASC LIMIT ?");
        run_search_select(&conn, cfg, &sql, &params, lim, None)?
    };
    drop(conn);

    let ms = elapsed_ms(t0);
    let result_objs: Vec<Value> = results.into_iter().map(|hr| Value::Object(hr.map)).collect();
    let count = result_objs.len();

    Ok(finish_response(
        &stage,
        &warnings,
        ms,
        vec![
            ("mode", Value::String(opts.mode.clone())),
            ("count", json!(count)),
            ("fts_query", Value::String(fts_q)),
            ("truncated", Value::Bool(was_trunc)),
            ("results", Value::Array(result_objs)),
        ],
    ))
}

fn run_search_select(
    conn: &Connection,
    cfg: &MailKbConfig,
    sql: &str,
    bparams: &[String],
    lim: i64,
    tag: Option<&'static str>,
) -> KbResult<Vec<HitRow>> {
    let mut stmt = conn.prepare(sql)?;
    let mut bind_vals: Vec<&dyn ToSql> = Vec::with_capacity(bparams.len() + 1);
    for p in bparams {
        bind_vals.push(p);
    }
    bind_vals.push(&lim);

    let mut rows = stmt.query(params_from_iter(bind_vals))?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let id: i64 = row.get(0)?;
        let acct: String = row.get(2)?;
        let src: String = row.get(3)?;
        let sref: String = row.get(4)?;
        let date_iso: String = row.get(9)?;
        let rank: f64 = row.get(23)?;
        let mut map = row_to_map(row.as_ref(), row)?;
        attach_source_path_fields(cfg, &mut map, &src, &sref, &acct);
        let mut hit_in = Vec::new();
        if let Some(t) = tag {
            hit_in.push(t);
            map.insert("hit_in".to_string(), json!([t]));
        }
        out.push(HitRow {
            id,
            date_iso,
            rank,
            hit_in,
            map,
        });
    }
    Ok(out)
}

pub fn run_read_impl(cfg: &MailKbConfig, opts: &ReadOpts) -> KbResult<Value> {
    let key = opts.id_or_uid.trim();
    if key.is_empty() {
        return Err(KbError::InvalidArgument(
            "Missing <id_or_uid> for read".to_string(),
        ));
    }

    let t0 = Instant::now();
    let (stage, conn, warnings) = stage_and_open(cfg)?;

    let all_dig = key.bytes().all(|b| b.is_ascii_digit());
    let mut msg_map: Option<Map<String, Value>> = None;
    let mut mid: i64 = 0;

    if all_dig {
        let parsed_id = key.parse::<i64>().unwrap_or(-1);
        let mut stmt = conn.prepare("SELECT * FROM mail_messages WHERE id = ?")?;
        let mut rows = stmt.query([parsed_id])?;
        if let Some(row) = rows.next()? {
            mid = row.get(0)?;
            msg_map = Some(row_to_map(row.as_ref(), row)?);
        }
    } else {
        let norm_rfc = key
            .trim_start_matches('<')
            .trim_end_matches('>')
            .trim()
            .to_ascii_lowercase();
        let mut stmt = if !norm_rfc.is_empty() && !key.starts_with("h:") {
            conn.prepare(
                "SELECT * FROM mail_messages \
                 WHERE uid_key = ?1 OR uid_key = ?2 OR LOWER(TRIM(rfc_message_id, '<> ')) = ?2",
            )?
        } else {
            conn.prepare("SELECT * FROM mail_messages WHERE uid_key = ?1")?
        };
        let mut rows = if !norm_rfc.is_empty() && !key.starts_with("h:") {
            stmt.query([key, norm_rfc.as_str()])?
        } else {
            stmt.query([key])?
        };
        if let Some(row) = rows.next()? {
            mid = row.get(0)?;
            msg_map = Some(row_to_map(row.as_ref(), row)?);
        }
    }

    let Some(mut msg_fields) = msg_map else {
        return Err(KbError::NotFound(format!("Message not found: {key}")));
    };

    let account_id = msg_fields
        .get("account_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let source = msg_fields
        .get("source")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let source_ref = msg_fields
        .get("source_ref")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    attach_source_path_fields(cfg, &mut msg_fields, &source, &source_ref, &account_id);

    let quoted_val = msg_fields
        .get("body_quoted")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if !opts.full {
        msg_fields.remove("body_quoted");
    }
    msg_fields.insert("quoted_bytes".to_string(), json!(quoted_val.len()));
    msg_fields.insert("has_quoted".to_string(), json!(!quoted_val.is_empty()));

    let entities = {
        let mut stmt = conn.prepare(
            "SELECT id, message_id, uid_key, entity_type, entity_key, canonical_value, category, \
             sub_group, quantity, unit, role, confidence, snippet, attrs_json \
             FROM message_entities WHERE message_id = ? ORDER BY id ASC",
        )?;
        let mut rows = stmt.query([mid])?;
        let mut arr = Vec::new();
        while let Some(row) = rows.next()? {
            arr.push(Value::Object(row_to_map(row.as_ref(), row)?));
        }
        arr
    };

    let amounts = {
        let mut stmt = conn.prepare(
            "SELECT id, message_id, uid_key, amount_type, subject_entity, category, topic_name, \
             org_name, currency, unit_amount, total_amount, quantity, tax_mode, terms_json, \
             COALESCE(json_extract(terms_json, '$.moq'), '') AS moq, \
             COALESCE(json_extract(terms_json, '$.lead_time'), '') AS lead_time, \
             COALESCE(json_extract(terms_json, '$.discount_info'), '') AS discount_info, \
             effective_date_iso, valid_until, source_kind, evidence_snippet, confidence \
             FROM message_amounts WHERE message_id = ? ORDER BY id ASC",
        )?;
        let mut rows = stmt.query([mid])?;
        let mut arr = Vec::new();
        while let Some(row) = rows.next()? {
            arr.push(Value::Object(row_to_map(row.as_ref(), row)?));
        }
        arr
    };

    let attachments = {
        let mut stmt = conn.prepare(
            "SELECT id, message_id, uid_key, filename, clean_filename, ext, mime_type, size_bytes, \
             mtime, mtime_iso, storage_relpath, is_inline, is_noise, sha256, text_preview, \
             entity_tags, topic_tags \
             FROM message_attachments WHERE message_id = ? ORDER BY id ASC",
        )?;
        let mut rows = stmt.query([mid])?;
        let mut arr = Vec::new();
        while let Some(row) = rows.next()? {
            let mut map = row_to_map(row.as_ref(), row)?;
            let rel = map
                .get("storage_relpath")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let acct = (!account_id.is_empty()).then_some(account_id.as_str());
            let info = resolve_attachment_path(cfg, &rel, acct);
            attach_att_path_fields(&mut map, info);
            arr.push(Value::Object(map));
        }
        arr
    };

    drop(conn);
    let ms = elapsed_ms(t0);

    Ok(finish_response(
        &stage,
        &warnings,
        ms,
        vec![
            ("message", Value::Object(msg_fields)),
            ("entities", Value::Array(entities)),
            ("amounts", Value::Array(amounts)),
            ("attachments", Value::Array(attachments)),
        ],
    ))
}

pub fn run_entities_impl(cfg: &MailKbConfig, opts: &EntityListOpts) -> KbResult<Value> {
    let lim = validate_limit(opts.limit)?;
    let t0 = Instant::now();
    let (stage, conn, warnings) = stage_and_open(cfg)?;

    let mut where_clauses = vec!["me.entity_key != ''".to_string()];
    let mut params: Vec<String> = Vec::new();

    let entity_q = opts
        .entity
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    if let Some(ent) = entity_q {
        let norm = normalize_model_key(ent);
        if !norm.is_empty() {
            let esc = format!("%{}%", like_escape(&norm));
            where_clauses.push(
                "(REPLACE(REPLACE(UPPER(me.entity_key), '-', ''), ' ', '') LIKE ? ESCAPE '\\' \
                 OR REPLACE(REPLACE(UPPER(me.canonical_value), '-', ''), ' ', '') LIKE ? ESCAPE '\\')"
                    .to_string(),
            );
            params.push(esc.clone());
            params.push(esc);
        } else {
            let esc = format!("%{}%", like_escape(ent));
            where_clauses.push(
                "(LOWER(me.entity_key) LIKE LOWER(?) ESCAPE '\\' \
                 OR LOWER(me.canonical_value) LIKE LOWER(?) ESCAPE '\\')"
                    .to_string(),
            );
            params.push(esc.clone());
            params.push(esc);
        }
    }
    if let Some(etype) = opts.entity_type.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("LOWER(me.entity_type) = LOWER(?)".to_string());
        params.push(etype.trim().to_string());
    }
    if let Some(cat) = opts.category.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("UPPER(me.category) = UPPER(?)".to_string());
        params.push(cat.trim().to_string());
    }

    let agg_sql = format!(
        "SELECT me.entity_key, me.entity_type, MAX(me.canonical_value) AS canonical_value, \
         me.category, me.sub_group, \
         COUNT(DISTINCT me.message_id) AS message_count, COUNT(*) AS mention_count, \
         MIN(NULLIF(m.date_iso, '')) AS first_date_iso, \
         MAX(NULLIF(m.date_iso, '')) AS last_date_iso, \
         (SELECT COUNT(*) FROM message_amounts ma WHERE ma.subject_entity = me.entity_key) AS amount_count \
         FROM message_entities me \
         JOIN mail_messages m ON m.id = me.message_id \
         WHERE {} \
         GROUP BY me.entity_key, me.entity_type, me.category, me.sub_group \
         ORDER BY message_count DESC, mention_count DESC, me.entity_key ASC LIMIT ?",
        where_clauses.join(" AND ")
    );
    let agg_rows = query_rows_json(&conn, &agg_sql, &params, Some(lim))?;

    let Some(ent_str) = entity_q else {
        drop(conn);
        let ms = elapsed_ms(t0);
        let count = agg_rows.len();
        return Ok(finish_response(
            &stage,
            &warnings,
            ms,
            vec![("count", json!(count)), ("results", Value::Array(agg_rows))],
        ));
    };

    // Concurrent 3-thread drill-down when --entity / <ENTITY> is provided
    let norm = normalize_model_key(ent_str);
    let like_key = if !norm.is_empty() {
        format!("%{}%", like_escape(&norm))
    } else {
        format!("%{}%", like_escape(ent_str))
    };
    let p_vec = vec![like_key];
    let rt_path = &stage.runtime_db;

    let (mentions_res, amounts_res, msgs_res) = std::thread::scope(|scope| {
        let t2 = scope.spawn(|| {
            let c2 = open_staged_worker(rt_path)?;
            query_rows_json(
                &c2,
                "SELECT * FROM v_amount_history \
                 WHERE REPLACE(REPLACE(UPPER(subject_entity), '-', ''), ' ', '') LIKE ? ESCAPE '\\' LIMIT ?",
                &p_vec,
                Some(lim),
            )
        });
        let t3 = scope.spawn(|| {
            let c3 = open_staged_worker(rt_path)?;
            query_rows_json(
                &c3,
                "SELECT id, account_id, date_iso, source, completeness, subject, primary_entities, \
                 primary_category, topic_tags, org_tags, intent_type, summary_line, has_amount, amount_summary \
                 FROM mail_messages \
                 WHERE REPLACE(REPLACE(UPPER(primary_entities), '-', ''), ' ', '') LIKE ? ESCAPE '\\' \
                 ORDER BY date_iso DESC, id ASC LIMIT ?",
                &p_vec,
                Some(lim),
            )
        });
        let mentions_res = query_rows_json(
            &conn,
            "SELECT me.entity_type, me.entity_key, me.canonical_value, me.category, me.sub_group, \
             me.quantity, me.unit, me.role, me.confidence, me.snippet, me.message_id, \
             m.date_iso, m.subject, m.topic_tags, m.org_tags \
             FROM message_entities me JOIN mail_messages m ON m.id = me.message_id \
             WHERE REPLACE(REPLACE(UPPER(me.entity_key), '-', ''), ' ', '') LIKE ? ESCAPE '\\' \
             ORDER BY m.date_iso DESC, me.id ASC LIMIT ?",
            &p_vec,
            Some(lim),
        );
        (
            mentions_res,
            t2.join().expect("entity amounts worker panicked"),
            t3.join().expect("entity messages worker panicked"),
        )
    });

    drop(conn);
    let mentions = mentions_res?;
    let amount_history = amounts_res?;
    let messages = msgs_res?;
    let ms = elapsed_ms(t0);
    let count = agg_rows.len();

    Ok(finish_response(
        &stage,
        &warnings,
        ms,
        vec![
            ("query_entity", Value::String(ent_str.to_string())),
            ("count", json!(count)),
            ("results", Value::Array(agg_rows)),
            ("entity_mentions", Value::Array(mentions)),
            ("amount_history", Value::Array(amount_history)),
            ("messages", Value::Array(messages)),
        ],
    ))
}

#[derive(Default)]
struct CurAgg {
    cnt: i64,
    mn: f64,
    mx: f64,
    sum: f64,
}

pub fn run_amounts_impl(cfg: &MailKbConfig, opts: &AmountListOpts) -> KbResult<Value> {
    let lim = validate_limit(opts.limit)?;
    let t0 = Instant::now();
    let (stage, conn, warnings) = stage_and_open(cfg)?;

    let mut where_clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if let Some(ent) = opts.entity.as_deref().filter(|s| !s.trim().is_empty()) {
        let norm = normalize_model_key(ent);
        if !norm.is_empty() {
            where_clauses.push(
                "REPLACE(REPLACE(UPPER(a.subject_entity), '-', ''), ' ', '') LIKE ? ESCAPE '\\'"
                    .to_string(),
            );
            params.push(format!("%{}%", like_escape(&norm)));
        } else {
            where_clauses.push("LOWER(a.subject_entity) LIKE LOWER(?) ESCAPE '\\'".to_string());
            params.push(format!("%{}%", like_escape(ent.trim())));
        }
    }
    if let Some(cur) = opts.currency.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("UPPER(a.currency) = UPPER(?)".to_string());
        params.push(cur.trim().to_string());
    }
    if let Some(topic) = opts.topic.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses
            .push("COALESCE(NULLIF(a.topic_name, ''), m.topic_tags) LIKE ? ESCAPE '\\'".to_string());
        params.push(format!("%{}%", like_escape(topic.trim())));
    }
    if let Some(org) = opts.org.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses
            .push("COALESCE(NULLIF(a.org_name, ''), m.org_tags) LIKE ? ESCAPE '\\'".to_string());
        params.push(format!("%{}%", like_escape(org.trim())));
    }
    if let Some(at) = opts.amount_type.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("a.amount_type LIKE ? ESCAPE '\\'".to_string());
        params.push(format!("%{}%", like_escape(at.trim())));
    }
    if let Some(conf) = opts.confidence.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses.push("LOWER(a.confidence) = LOWER(?)".to_string());
        params.push(conf.trim().to_string());
    }
    if let Some(since) = opts.since.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses
            .push("COALESCE(NULLIF(a.effective_date_iso, ''), m.date_iso) >= ?".to_string());
        params.push(since.trim().to_string());
    }
    if let Some(until) = opts.until.as_deref().filter(|s| !s.trim().is_empty()) {
        where_clauses
            .push("COALESCE(NULLIF(a.effective_date_iso, ''), m.date_iso) <= ?".to_string());
        params.push(until_bound(until.trim()));
    }
    for kw in &opts.keywords {
        let t = kw.trim();
        if t.is_empty() {
            continue;
        }
        let esc = format!("%{}%", like_escape(t));
        where_clauses.push(
            "(a.subject_entity LIKE ? ESCAPE '\\' \
             OR COALESCE(NULLIF(a.topic_name, ''), m.topic_tags) LIKE ? ESCAPE '\\' \
             OR COALESCE(NULLIF(a.org_name, ''), m.org_tags) LIKE ? ESCAPE '\\' \
             OR a.evidence_snippet LIKE ? ESCAPE '\\' \
             OR m.subject LIKE ? ESCAPE '\\')"
                .to_string(),
        );
        for _ in 0..5 {
            params.push(esc.clone());
        }
    }

    let mut sql = "SELECT a.id, a.message_id, a.uid_key, a.amount_type, a.subject_entity, \
        a.category, COALESCE(NULLIF(a.topic_name, ''), m.topic_tags) AS topic_name, \
        COALESCE(NULLIF(a.org_name, ''), m.org_tags) AS org_name, a.currency, \
        a.unit_amount, a.total_amount, a.quantity, a.tax_mode, a.terms_json, \
        COALESCE(json_extract(a.terms_json, '$.moq'), '') AS moq, \
        COALESCE(json_extract(a.terms_json, '$.lead_time'), '') AS lead_time, \
        COALESCE(json_extract(a.terms_json, '$.discount_info'), '') AS discount_info, \
        COALESCE(NULLIF(a.effective_date_iso, ''), m.date_iso) AS effective_date_iso, \
        a.valid_until, a.source_kind, a.evidence_snippet, a.confidence, \
        m.subject, m.sender, m.account_id, m.rfc_message_id \
        FROM message_amounts a JOIN mail_messages m ON m.id = a.message_id"
        .to_string();
    if !where_clauses.is_empty() {
        sql.push_str(" WHERE ");
        sql.push_str(&where_clauses.join(" AND "));
    }
    sql.push_str(" ORDER BY COALESCE(NULLIF(a.effective_date_iso, ''), m.date_iso) DESC, a.id DESC LIMIT ?");

    let rows = query_rows_json(&conn, &sql, &params, Some(lim))?;
    drop(conn);

    let mut by_cur: BTreeMap<String, CurAgg> = BTreeMap::new();
    for rv in &rows {
        let amt_opt = rv
            .get("unit_amount")
            .and_then(Value::as_f64)
            .or_else(|| rv.get("total_amount").and_then(Value::as_f64));
        if let Some(v) = amt_opt {
            let cur = rv
                .get("currency")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .unwrap_or("UNKNOWN")
                .to_string();
            let agg = by_cur.entry(cur).or_insert_with(|| CurAgg {
                cnt: 0,
                mn: f64::INFINITY,
                mx: f64::NEG_INFINITY,
                sum: 0.0,
            });
            agg.cnt += 1;
            agg.mn = agg.mn.min(v);
            agg.mx = agg.mx.max(v);
            agg.sum += v;
        }
    }

    let mut cs_map = Map::new();
    for (cur, agg) in by_cur {
        let avg = ((agg.sum / agg.cnt as f64) * 100.0).round() / 100.0;
        cs_map.insert(
            cur,
            json!({
                "count": agg.cnt,
                "min": agg.mn,
                "max": agg.mx,
                "avg": avg,
            }),
        );
    }

    let ms = elapsed_ms(t0);
    let count = rows.len();
    Ok(finish_response(
        &stage,
        &warnings,
        ms,
        vec![
            ("count", json!(count)),
            ("currency_summary", Value::Object(cs_map)),
            ("results", Value::Array(rows)),
        ],
    ))
}

pub fn run_topics_impl(cfg: &MailKbConfig, opts: &TopicListOpts) -> KbResult<Value> {
    let lim = validate_limit(opts.limit)?;
    let t0 = Instant::now();
    let (stage, conn, warnings) = stage_and_open(cfg)?;

    let topic_q = opts
        .topic
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let Some(tname) = topic_q else {
        let rows = query_rows_json(
            &conn,
            "SELECT * FROM v_topic_overview LIMIT ?",
            &[],
            Some(lim),
        )?;
        let lexicon = query_rows_json(
            &conn,
            "SELECT pack_id, key, canonical_name, aliases, hit_count, metadata_json \
             FROM domain_lexicon WHERE dimension = 'topic' ORDER BY hit_count DESC, canonical_name ASC LIMIT ?",
            &[],
            Some(lim),
        )?;
        drop(conn);
        let ms = elapsed_ms(t0);
        let count = rows.len();
        return Ok(finish_response(
            &stage,
            &warnings,
            ms,
            vec![
                ("count", json!(count)),
                ("results", Value::Array(rows)),
                ("lexicon", Value::Array(lexicon)),
            ],
        ));
    };

    let esc = format!("%{}%", like_escape(tname));
    let p_vec = vec![esc];
    let rt_path = &stage.runtime_db;

    let (ov_res, amts_res, msgs_res) = std::thread::scope(|scope| {
        let t2 = scope.spawn(|| {
            let c2 = open_staged_worker(rt_path)?;
            query_rows_json(
                &c2,
                "SELECT * FROM v_amount_history WHERE topic_name LIKE ? ESCAPE '\\' LIMIT ?",
                &p_vec,
                Some(lim),
            )
        });
        let t3 = scope.spawn(|| {
            let c3 = open_staged_worker(rt_path)?;
            query_rows_json(
                &c3,
                "SELECT id, account_id, date_iso, source, completeness, subject, sender, \
                 primary_entities, primary_category, topic_tags, org_tags, intent_type, \
                 summary_line, has_amount, amount_summary \
                 FROM mail_messages WHERE topic_tags LIKE ? ESCAPE '\\' \
                 ORDER BY date_iso DESC, id ASC LIMIT ?",
                &p_vec,
                Some(lim),
            )
        });
        let ov_res = query_rows_json(
            &conn,
            "SELECT * FROM v_topic_overview WHERE topic_name LIKE ? ESCAPE '\\' LIMIT ?",
            &p_vec,
            Some(lim),
        );
        (
            ov_res,
            t2.join().expect("topic amounts worker panicked"),
            t3.join().expect("topic msgs worker panicked"),
        )
    });

    let lexicon = query_rows_json(
        &conn,
        "SELECT pack_id, key, canonical_name, aliases, hit_count, metadata_json \
         FROM domain_lexicon WHERE dimension = 'topic' AND (canonical_name LIKE ? ESCAPE '\\' OR aliases LIKE ? ESCAPE '\\') \
         ORDER BY hit_count DESC LIMIT ?",
        &[p_vec[0].clone(), p_vec[0].clone()],
        Some(lim),
    )?;
    drop(conn);

    let overview = ov_res?;
    let amounts = amts_res?;
    let messages = msgs_res?;
    let ms = elapsed_ms(t0);
    let count = messages.len();

    Ok(finish_response(
        &stage,
        &warnings,
        ms,
        vec![
            ("query_topic", Value::String(tname.to_string())),
            ("count", json!(count)),
            ("overview", Value::Array(overview)),
            ("amounts", Value::Array(amounts)),
            ("messages", Value::Array(messages.clone())),
            ("lexicon", Value::Array(lexicon)),
            ("results", Value::Array(messages)),
        ],
    ))
}

pub fn run_orgs_impl(cfg: &MailKbConfig, opts: &OrgListOpts) -> KbResult<Value> {
    let lim = validate_limit(opts.limit)?;
    let t0 = Instant::now();
    let (stage, conn, warnings) = stage_and_open(cfg)?;

    let org_q = opts
        .org
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let Some(oname) = org_q else {
        let rows = query_rows_json(&conn, "SELECT * FROM v_org_overview LIMIT ?", &[], Some(lim))?;
        let lexicon = query_rows_json(
            &conn,
            "SELECT pack_id, key, canonical_name, aliases, hit_count, metadata_json \
             FROM domain_lexicon WHERE dimension = 'organization' ORDER BY hit_count DESC, canonical_name ASC LIMIT ?",
            &[],
            Some(lim),
        )?;
        drop(conn);
        let ms = elapsed_ms(t0);
        let count = rows.len();
        return Ok(finish_response(
            &stage,
            &warnings,
            ms,
            vec![
                ("count", json!(count)),
                ("results", Value::Array(rows)),
                ("lexicon", Value::Array(lexicon)),
            ],
        ));
    };

    let esc = format!("%{}%", like_escape(oname));
    let p_vec = vec![esc];
    let rt_path = &stage.runtime_db;

    let (ov_res, amts_res, msgs_res) = std::thread::scope(|scope| {
        let t2 = scope.spawn(|| {
            let c2 = open_staged_worker(rt_path)?;
            query_rows_json(
                &c2,
                "SELECT * FROM v_amount_history WHERE org_name LIKE ? ESCAPE '\\' LIMIT ?",
                &p_vec,
                Some(lim),
            )
        });
        let t3 = scope.spawn(|| {
            let c3 = open_staged_worker(rt_path)?;
            query_rows_json(
                &c3,
                "SELECT id, account_id, date_iso, source, completeness, direction, subject, sender, \
                 primary_entities, primary_category, topic_tags, org_tags, intent_type, \
                 summary_line, has_amount, amount_summary \
                 FROM mail_messages WHERE org_tags LIKE ? ESCAPE '\\' \
                 ORDER BY date_iso DESC, id ASC LIMIT ?",
                &p_vec,
                Some(lim),
            )
        });
        let ov_res = query_rows_json(
            &conn,
            "SELECT * FROM v_org_overview WHERE org_name LIKE ? ESCAPE '\\' LIMIT ?",
            &p_vec,
            Some(lim),
        );
        (
            ov_res,
            t2.join().expect("org amounts worker panicked"),
            t3.join().expect("org msgs worker panicked"),
        )
    });

    let lexicon = query_rows_json(
        &conn,
        "SELECT pack_id, key, canonical_name, aliases, hit_count, metadata_json \
         FROM domain_lexicon WHERE dimension = 'organization' AND (canonical_name LIKE ? ESCAPE '\\' OR aliases LIKE ? ESCAPE '\\') \
         ORDER BY hit_count DESC LIMIT ?",
        &[p_vec[0].clone(), p_vec[0].clone()],
        Some(lim),
    )?;
    drop(conn);

    let overview = ov_res?;
    let amounts = amts_res?;
    let messages = msgs_res?;
    let ms = elapsed_ms(t0);
    let count = messages.len();

    Ok(finish_response(
        &stage,
        &warnings,
        ms,
        vec![
            ("query_org", Value::String(oname.to_string())),
            ("count", json!(count)),
            ("overview", Value::Array(overview)),
            ("amounts", Value::Array(amounts)),
            ("messages", Value::Array(messages.clone())),
            ("lexicon", Value::Array(lexicon)),
            ("results", Value::Array(messages)),
        ],
    ))
}

pub fn run_timeline_impl(cfg: &MailKbConfig, opts: &TimelineOpts) -> KbResult<Value> {
    let lim = validate_limit(opts.limit)?;
    if !matches!(opts.granularity.as_str(), "month" | "day" | "quarter" | "year") {
        return Err(KbError::InvalidArgument(
            "--granularity must be month|day|quarter|year".to_string(),
        ));
    }

    let t0 = Instant::now();
    let (stage, conn, warnings) = stage_and_open(cfg)?;

    let since = opts.since.as_deref().map(str::trim).unwrap_or("");
    let until = opts.until.as_deref().map(str::trim).unwrap_or("");
    let topic = opts.topic.as_deref().map(str::trim).unwrap_or("");
    let org = opts.org.as_deref().map(str::trim).unwrap_or("");

    let rows = if opts.granularity == "month"
        && since.is_empty()
        && until.is_empty()
        && topic.is_empty()
        && org.is_empty()
    {
        query_rows_json(
            &conn,
            "SELECT ym AS period, ym, message_count, full_body_count, amount_message_count, \
             price_message_count, inbound_count, outbound_count, active_topics \
             FROM v_timeline_monthly LIMIT ?",
            &[],
            Some(lim),
        )?
    } else {
        let mut where_clauses = vec![
            "LENGTH(date_iso) >= 7".to_string(),
            "SUBSTR(date_iso, 5, 1) = '-'".to_string(),
        ];
        if opts.granularity == "day" {
            where_clauses.push("LENGTH(date_iso) >= 10".to_string());
            where_clauses.push("SUBSTR(date_iso, 8, 1) = '-'".to_string());
        }
        let mut params = Vec::new();
        if !since.is_empty() {
            where_clauses.push("date_iso >= ?".to_string());
            params.push(since.to_string());
        }
        if !until.is_empty() {
            where_clauses.push("date_iso <= ?".to_string());
            params.push(until_bound(until));
        }
        if !topic.is_empty() {
            where_clauses.push("topic_tags LIKE ? ESCAPE '\\'".to_string());
            params.push(format!("%{}%", like_escape(topic)));
        }
        if !org.is_empty() {
            where_clauses.push("org_tags LIKE ? ESCAPE '\\'".to_string());
            params.push(format!("%{}%", like_escape(org)));
        }
        let bucket = match opts.granularity.as_str() {
            "day" => "SUBSTR(date_iso, 1, 10)",
            "year" => "SUBSTR(date_iso, 1, 4)",
            "quarter" => "SUBSTR(date_iso, 1, 4) || '-Q' || CAST(((CAST(SUBSTR(date_iso, 6, 2) AS INTEGER) - 1) / 3) + 1 AS TEXT)",
            _ => "SUBSTR(date_iso, 1, 7)",
        };
        let wsql = where_clauses.join(" AND ");
        let sql = format!(
            "SELECT {bucket} AS period, COUNT(*) AS message_count, \
             SUM(CASE WHEN completeness = 'full_body' THEN 1 ELSE 0 END) AS full_body_count, \
             SUM(CASE WHEN has_amount = 1 THEN 1 ELSE 0 END) AS amount_message_count, \
             SUM(CASE WHEN has_amount = 1 THEN 1 ELSE 0 END) AS price_message_count, \
             SUM(CASE WHEN direction = 'external_inbound' THEN 1 ELSE 0 END) AS inbound_count, \
             SUM(CASE WHEN direction = 'external_outbound' THEN 1 ELSE 0 END) AS outbound_count, \
             COUNT(DISTINCT NULLIF(topic_tags, '')) AS active_topics \
             FROM mail_messages WHERE {wsql} GROUP BY period ORDER BY period DESC LIMIT ?"
        );
        query_rows_json(&conn, &sql, &params, Some(lim))?
    };
    drop(conn);

    let ms = elapsed_ms(t0);
    let count = rows.len();
    Ok(finish_response(
        &stage,
        &warnings,
        ms,
        vec![
            ("granularity", Value::String(opts.granularity.clone())),
            ("count", json!(count)),
            ("results", Value::Array(rows)),
        ],
    ))
}

pub fn run_att_impl(cfg: &MailKbConfig, opts: &AttOpts) -> KbResult<Value> {
    let lim = validate_limit(opts.limit)?;
    let t0 = Instant::now();
    let (stage, conn, mut warnings) = stage_and_open(cfg)?;

    let mut where_clauses: Vec<String> = Vec::new();
    let mut params: Vec<String> = Vec::new();

    if !opts.include_noise {
        where_clauses.push("a.is_noise = 0".to_string());
    }
    if let Some(ent) = opts.entity.as_deref().filter(|s| !s.trim().is_empty()) {
        let norm = normalize_model_key(ent);
        if !norm.is_empty() {
            let esc = format!("%{}%", like_escape(&norm));
            where_clauses.push(
                "(REPLACE(REPLACE(UPPER(a.entity_tags), '-', ''), ' ', '') LIKE ? ESCAPE '\\' \
                 OR REPLACE(REPLACE(UPPER(a.clean_filename), '-', ''), ' ', '') LIKE ? ESCAPE '\\')"
                    .to_string(),
            );
            params.push(esc.clone());
            params.push(esc);
        } else {
            where_clauses.push("1=0".to_string());
        }
    }
    if let Some(topic) = opts.topic.as_deref().filter(|s| !s.trim().is_empty()) {
        let esc = format!("%{}%", like_escape(topic.trim()));
        where_clauses.push(
            "(a.topic_tags LIKE ? ESCAPE '\\' OR a.clean_filename LIKE ? ESCAPE '\\')".to_string(),
        );
        params.push(esc.clone());
        params.push(esc);
    }
    if let Some(ext) = opts.ext.as_deref().filter(|s| !s.trim().is_empty()) {
        let ex = ext.trim().strip_prefix('.').unwrap_or(ext.trim());
        where_clauses.push("LOWER(a.ext) = LOWER(?)".to_string());
        params.push(ex.to_string());
    }

    let (fts_q, was_trunc) = build_cjk_bigram_fts_query(&opts.keywords);
    if was_trunc {
        warnings.push("query_truncated");
    }

    let mut bparams: Vec<String> = Vec::new();
    let select_cols = "a.id, a.message_id, a.uid_key, m.account_id, a.filename, a.clean_filename, \
        a.ext, a.mime_type, a.size_bytes, a.mtime, a.mtime_iso, a.storage_relpath, a.is_inline, \
        a.is_noise, a.sha256, a.text_preview, a.entity_tags, a.topic_tags, \
        m.subject AS message_subject, m.date_iso AS message_date_iso";

    let sql = if !fts_q.is_empty() {
        let mut s = format!(
            "SELECT {select_cols} FROM attachments_fts \
             JOIN message_attachments a ON a.id = attachments_fts.rowid \
             JOIN mail_messages m ON m.id = a.message_id \
             WHERE attachments_fts MATCH ?"
        );
        bparams.push(fts_q.clone());
        for w in &where_clauses {
            s.push_str(" AND ");
            s.push_str(w);
        }
        bparams.extend(params);
        s.push_str(" ORDER BY bm25(attachments_fts, 4.0, 2.0) ASC, a.mtime DESC, a.id ASC LIMIT ?");
        s
    } else {
        let mut s = format!(
            "SELECT {select_cols} FROM message_attachments a \
             JOIN mail_messages m ON m.id = a.message_id"
        );
        if !where_clauses.is_empty() {
            s.push_str(" WHERE ");
            s.push_str(&where_clauses.join(" AND "));
            bparams = params;
        }
        s.push_str(" ORDER BY a.mtime DESC, a.id ASC LIMIT ?");
        s
    };

    let mut stmt = conn.prepare(&sql)?;
    let mut bind_vals: Vec<&dyn ToSql> = Vec::with_capacity(bparams.len() + 1);
    for p in &bparams {
        bind_vals.push(p);
    }
    bind_vals.push(&lim);

    let mut rows = Vec::new();
    let mut qrows = stmt.query(params_from_iter(bind_vals))?;
    while let Some(row) = qrows.next()? {
        let mut map = row_to_map(row.as_ref(), row)?;
        let acct = map
            .get("account_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let rel = map
            .get("storage_relpath")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let acct_opt = (!acct.is_empty()).then_some(acct.as_str());
        let info = resolve_attachment_path(cfg, &rel, acct_opt);
        attach_att_path_fields(&mut map, info);
        rows.push(Value::Object(map));
    }
    drop(qrows);
    drop(stmt);
    drop(conn);

    let ms = elapsed_ms(t0);
    let count = rows.len();
    Ok(finish_response(
        &stage,
        &warnings,
        ms,
        vec![
            ("count", json!(count)),
            ("fts_query", Value::String(fts_q)),
            ("truncated", Value::Bool(was_trunc)),
            ("results", Value::Array(rows)),
        ],
    ))
}

#[derive(Default)]
struct StatsResults {
    kb_meta: BTreeMap<String, String>,
    date_min: String,
    date_max: String,
    msg_total: i64,
    msg_amount: i64,
    att_total: i64,
    att_clean: i64,
    ent_total: i64,
    amt_total: i64,
    lex_total: i64,
    dist_entities: i64,
    dist_amount_entities: i64,
    by_acct: Vec<Value>,
    by_src: Vec<Value>,
    by_comp: Vec<Value>,
    by_dir: Vec<Value>,
    by_cat: Vec<Value>,
    by_int: Vec<Value>,
    by_cur: Vec<Value>,
    lex_summary: Vec<Value>,
    top_entities: Vec<Value>,
    top_topics: Vec<Value>,
    top_orgs: Vec<Value>,
}

pub fn run_stats_impl(cfg: &MailKbConfig) -> KbResult<Value> {
    let t0 = Instant::now();
    let (stage, conn, warnings) = stage_and_open(cfg)?;
    let rt_path = &stage.runtime_db;

    const NUM_TASKS: usize = 5;
    let next_task = AtomicUsize::new(0);
    let results = Mutex::new(StatsResults::default());
    let first_err: Mutex<Option<KbError>> = Mutex::new(None);

    let run_task = |tid: usize, c: &Connection| -> KbResult<()> {
        match tid {
            0 => {
                let top_orgs = query_rows_json(
                    c,
                    "SELECT org_name, message_count, full_body_count, amount_message_count \
                     FROM v_org_overview LIMIT 15",
                    &[],
                    None,
                )?;
                results.lock().unwrap().top_orgs = top_orgs;
            }
            1 => {
                let top_topics = query_rows_json(
                    c,
                    "SELECT topic_name, message_count, full_body_count, amount_message_count \
                     FROM v_topic_overview LIMIT 15",
                    &[],
                    None,
                )?;
                results.lock().unwrap().top_topics = top_topics;
            }
            2 => {
                let top_entities = query_rows_json(
                    c,
                    "SELECT entity_key, entity_type, category, \
                     COUNT(DISTINCT message_id) AS message_count, COUNT(*) AS mentions \
                     FROM message_entities WHERE entity_key != '' \
                     GROUP BY entity_key, entity_type, category \
                     ORDER BY message_count DESC, mentions DESC LIMIT 15",
                    &[],
                    None,
                )?;
                let dist_entities = query_scalar_i64(
                    c,
                    "SELECT COUNT(DISTINCT entity_key) FROM message_entities WHERE entity_key != ''",
                )?;
                let dist_amount_entities = query_scalar_i64(
                    c,
                    "SELECT COUNT(DISTINCT subject_entity) FROM message_amounts WHERE subject_entity != ''",
                )?;
                let lex_summary = query_rows_json(
                    c,
                    "SELECT pack_id, dimension, COUNT(*) AS entry_count, \
                     COALESCE(SUM(hit_count), 0) AS total_hits \
                     FROM domain_lexicon GROUP BY pack_id, dimension \
                     ORDER BY total_hits DESC, entry_count DESC",
                    &[],
                    None,
                )?;
                let mut g = results.lock().unwrap();
                g.top_entities = top_entities;
                g.dist_entities = dist_entities;
                g.dist_amount_entities = dist_amount_entities;
                g.lex_summary = lex_summary;
            }
            3 => {
                let by_acct = query_rows_json(
                    c,
                    "SELECT account_id, COUNT(*) AS count FROM mail_messages GROUP BY account_id ORDER BY count DESC",
                    &[],
                    None,
                )?;
                let by_src = query_rows_json(
                    c,
                    "SELECT source, COUNT(*) AS count FROM mail_messages GROUP BY source ORDER BY count DESC",
                    &[],
                    None,
                )?;
                let by_comp = query_rows_json(
                    c,
                    "SELECT completeness, COUNT(*) AS count FROM mail_messages GROUP BY completeness ORDER BY count DESC",
                    &[],
                    None,
                )?;
                let by_dir = query_rows_json(
                    c,
                    "SELECT direction, COUNT(*) AS count FROM mail_messages GROUP BY direction ORDER BY count DESC",
                    &[],
                    None,
                )?;
                let by_cat = query_rows_json(
                    c,
                    "SELECT primary_category, COUNT(*) AS count FROM mail_messages GROUP BY primary_category ORDER BY count DESC LIMIT 15",
                    &[],
                    None,
                )?;
                let by_int = query_rows_json(
                    c,
                    "SELECT intent_type, COUNT(*) AS count FROM mail_messages WHERE intent_type != '' \
                     GROUP BY intent_type ORDER BY count DESC LIMIT 15",
                    &[],
                    None,
                )?;
                let by_cur = query_rows_json(
                    c,
                    "SELECT currency, COUNT(*) AS count FROM message_amounts GROUP BY currency ORDER BY count DESC",
                    &[],
                    None,
                )?;
                let mut g = results.lock().unwrap();
                g.by_acct = by_acct;
                g.by_src = by_src;
                g.by_comp = by_comp;
                g.by_dir = by_dir;
                g.by_cat = by_cat;
                g.by_int = by_int;
                g.by_cur = by_cur;
            }
            4 => {
                let msg_total = query_scalar_i64(c, "SELECT COUNT(*) FROM mail_messages")?;
                let msg_amount =
                    query_scalar_i64(c, "SELECT COUNT(*) FROM mail_messages WHERE has_amount = 1")?;
                let att_total = query_scalar_i64(c, "SELECT COUNT(*) FROM message_attachments")?;
                let att_clean = query_scalar_i64(
                    c,
                    "SELECT COUNT(*) FROM message_attachments WHERE is_noise = 0",
                )?;
                let ent_total = query_scalar_i64(c, "SELECT COUNT(*) FROM message_entities")?;
                let amt_total = query_scalar_i64(c, "SELECT COUNT(*) FROM message_amounts")?;
                let lex_total = query_scalar_i64(c, "SELECT COUNT(*) FROM domain_lexicon")?;
                let dmin = query_scalar_str(
                    c,
                    "SELECT COALESCE(MIN(date_iso), '') FROM mail_messages WHERE date_iso != ''",
                )?;
                let dmax = query_scalar_str(
                    c,
                    "SELECT COALESCE(MAX(date_iso), '') FROM mail_messages WHERE date_iso != ''",
                )?;
                let meta = kb_meta_all(c)?;
                let mut g = results.lock().unwrap();
                g.msg_total = msg_total;
                g.msg_amount = msg_amount;
                g.att_total = att_total;
                g.att_clean = att_clean;
                g.ent_total = ent_total;
                g.amt_total = amt_total;
                g.lex_total = lex_total;
                g.date_min = dmin;
                g.date_max = dmax;
                g.kb_meta = meta;
            }
            _ => {}
        }
        Ok(())
    };

    let workers = cfg.max_threads.clamp(1, NUM_TASKS);
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers.saturating_sub(1));
        for _ in 1..workers {
            handles.push(scope.spawn(|| {
                let local_conn = match open_staged_worker(rt_path) {
                    Ok(c) => c,
                    Err(e) => {
                        let mut fe = first_err.lock().unwrap();
                        if fe.is_none() {
                            *fe = Some(e);
                        }
                        return;
                    }
                };
                loop {
                    let tid = next_task.fetch_add(1, Ordering::Relaxed);
                    if tid >= NUM_TASKS {
                        break;
                    }
                    if let Err(e) = run_task(tid, &local_conn) {
                        let mut fe = first_err.lock().unwrap();
                        if fe.is_none() {
                            *fe = Some(e);
                        }
                        break;
                    }
                }
            }));
        }
        loop {
            let tid = next_task.fetch_add(1, Ordering::Relaxed);
            if tid >= NUM_TASKS {
                break;
            }
            if let Err(e) = run_task(tid, &conn) {
                let mut fe = first_err.lock().unwrap();
                if fe.is_none() {
                    *fe = Some(e);
                }
                break;
            }
        }
        for h in handles {
            h.join().expect("stats worker panicked");
        }
    });
    drop(conn);

    if let Some(err) = first_err.into_inner().unwrap() {
        return Err(err);
    }

    let r = results.into_inner().unwrap();
    let db_bytes = std::fs::metadata(&stage.source_db)
        .or_else(|_| std::fs::metadata(&stage.runtime_db))
        .map(|m| m.len() as i64)
        .unwrap_or(0);
    let ms = elapsed_ms(t0);

    let meta_get = |k: &str| r.kb_meta.get(k).cloned().unwrap_or_default();
    let schema_version = meta_get("schema_version");
    let writer_version = meta_get("writer_version");
    let last_sync_iso = meta_get("last_sync_iso");
    let pack_ids = meta_get("pack_ids");
    let rules_fingerprint = meta_get("rules_fingerprint");

    let counts = json!({
        "mail_messages": r.msg_total,
        "messages_with_amount": r.msg_amount,
        "message_entities": r.ent_total,
        "message_amounts": r.amt_total,
        "message_attachments": r.att_total,
        "attachments_clean": r.att_clean,
        "domain_lexicon": r.lex_total,
        "distinct_entities": r.dist_entities,
        "distinct_amount_entities": r.dist_amount_entities,
    });

    Ok(finish_response(
        &stage,
        &warnings,
        ms,
        vec![
            ("db_path", Value::String(stage.source_db.to_string_lossy().into_owned())),
            ("db_bytes", json!(db_bytes)),
            ("schema_version", Value::String(schema_version)),
            ("writer_version", Value::String(writer_version)),
            ("last_sync_iso", Value::String(last_sync_iso)),
            ("pack_ids", Value::String(pack_ids)),
            ("rules_fingerprint", Value::String(rules_fingerprint)),
            ("kb_meta", json!(r.kb_meta)),
            ("date_min", Value::String(r.date_min)),
            ("date_max", Value::String(r.date_max)),
            ("counts", counts),
            ("by_account", Value::Array(r.by_acct)),
            ("by_source", Value::Array(r.by_src)),
            ("by_completeness", Value::Array(r.by_comp)),
            ("by_direction", Value::Array(r.by_dir)),
            ("by_category", Value::Array(r.by_cat)),
            ("by_intent", Value::Array(r.by_int)),
            ("amounts_by_currency", Value::Array(r.by_cur)),
            ("lexicon_summary", Value::Array(r.lex_summary)),
            ("top_entities", Value::Array(r.top_entities)),
            ("top_topics", Value::Array(r.top_topics)),
            ("top_orgs", Value::Array(r.top_orgs)),
        ],
    ))
}
