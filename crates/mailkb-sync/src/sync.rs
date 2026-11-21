//! Native Rust `mailkb_db sync` engine (`1.0-universal` schema, multi-account Apple Mail V10,
//! standalone `.eml`/`.emlx` ingestion, legacy DB import, incremental stat/WAL/delta sync,
//! S8/S9/T2/T3/T4/C6 safety).

use crate::apple_mail::{
    copy_envelope_index_to_dir, discover_accounts_and_filter, folder_rank_bonus,
    infer_identity_from_envelope_db, infer_identity_from_messages, load_all_mailboxes,
    mail_master_state, meta_mtime_ns, open_staged_envelope_ro, process_work_item,
    query_envelope_counts, query_envelope_rows, resolve_copy_location, scan_all_eml_dirs,
    serialize_eml_snapshot, CopyLocation, DiscoveredAccount, EnvelopeRow, MasterState,
    ScannedEmlInfo, StagedEnvelopeInfo, WorkItem,
};
use crate::enrich::{
    detect_tax_mode_str, enrich_message, extract_amounts_from_body, extract_item_codes,
    format_amount_rollup, is_excluded_amount_message, rebuild_fts_tokens, EnrichedAttachment,
    EnrichedMsg, InferredIdentity, RawAttachmentInput, RawMessageInput, ResolvedIdentity,
};
use crate::mime::{
    norm_uid_from_fields, parse_rfc5322_date, slice_emlx_rfc822, split_mime_headers_body,
    extract_header_str,
};
use crate::schema::{ENGINE_VERSION, RULES_VERSION, SCHEMA_VERSION, UNIVERSAL_SCHEMA_SQL};
use mailkb_core::config::{MailKbConfig, DEFAULT_DB_STEM};
use mailkb_core::domain_pack::CompiledDomainPack;
use mailkb_core::error::{KbError, KbResult};
use mailkb_core::fts::tokenize_for_fts;
use mailkb_core::publish::{
    backup_clone, check_disk_space, publish_clean_sqlite, reap_stale_build_dirs, sha256_bytes,
    TempBuildDir,
};
use mailkb_core::security::{
    assert_not_in_mail_container, ensure_private_dir, open_readonly_nofollow, read_file_readonly,
    sanitize_utf8, NonBlockingFlock,
};
use mailkb_core::staging::{
    check_sqlite_magic, is_valid_runtime_sqlite, open_staged_ro, stage_primary_db,
    DEFAULT_MMAP_BYTES, StagingState,
};
use mailkb_core::time::{format_local_datetime, now_unix_secs};
use rayon::prelude::*;
use rusqlite::{Connection, OpenFlags, Statement};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::ffi::CStr;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub const STREAM_BATCH_SIZE: usize = 1000;
const BUILD_DIR_PREFIX: &str = "mailkb-db-build-";

/// Sync execution options (kept compatible with `crate::SyncOpts`).
#[derive(Debug, Clone, Default)]
pub struct SyncOpts {
    pub full: bool,
    pub dry_run: bool,
    pub limit: Option<usize>,
    /// Optional path to a legacy `3.0-multidim` (or `1.0-universal`) SQLite database to stage
    /// read-only (`?mode=ro&immutable=1`) and migrate/re-enrich into `1.0-universal`.
    pub import_legacy_db: Option<PathBuf>,
}

fn host_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

fn host_arch() -> &'static str {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "arm64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else {
        std::env::consts::ARCH
    }
}

fn get_hostname() -> String {
    let mut buf = [0u8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len() - 1) };
    if rc != 0 {
        return "unknown".to_string();
    }
    buf[255] = 0;
    unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) }
        .to_string_lossy()
        .into_owned()
}

fn get_peak_rss_bytes() -> u64 {
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 || ru.ru_maxrss <= 0 {
        return 0;
    }
    #[cfg(target_os = "macos")]
    {
        ru.ru_maxrss as u64
    }
    #[cfg(not(target_os = "macos"))]
    {
        (ru.ru_maxrss as u64).saturating_mul(1024)
    }
}

fn push_unique_warning(warnings: &mut Vec<String>, w: impl Into<String>) {
    let s = w.into();
    if !warnings.iter().any(|x| x == &s) {
        warnings.push(s);
    }
}

fn read_existing_meta(runtime_db: &Path) -> KbResult<HashMap<String, String>> {
    let conn = open_staged_ro(runtime_db, DEFAULT_MMAP_BYTES)?;
    let mut stmt = conn.prepare("SELECT key, value FROM kb_meta")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
    let mut map = HashMap::new();
    for res in rows {
        let (k, v) = res?;
        map.insert(k, v);
    }
    if map.is_empty() {
        return Err(KbError::Staging(
            "kb_meta is empty in staged runtime snapshot".to_string(),
        ));
    }
    Ok(map)
}

fn join_paths_str(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(";")
}

fn copy_file_private_stream(src: &Path, dst: &Path) -> KbResult<()> {
    let mut in_f = open_readonly_nofollow(src)?;
    let mut out_f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dst)?;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = match in_f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(KbError::Io(e)),
        };
        out_f.write_all(&buf[..n])?;
    }
    out_f.sync_all()?;
    Ok(())
}

/// Safely stages an external SQLite database into `dst_dir` without modifying the source,
/// and opens it with `?mode=ro&immutable=1`.
pub(crate) fn stage_and_open_external_ro(
    cfg: &MailKbConfig,
    src_db: &Path,
    dst_dir: &Path,
) -> KbResult<Connection> {
    assert_not_in_mail_container(cfg, src_db)?;
    check_sqlite_magic(src_db)?;
    ensure_private_dir(dst_dir)?;

    let raw_copy = dst_dir.join("external_raw.sqlite");
    let _ = fs::remove_file(&raw_copy);
    copy_file_private_stream(src_db, &raw_copy)?;

    let mut wal_os = src_db.as_os_str().to_os_string();
    wal_os.push("-wal");
    let src_wal = PathBuf::from(wal_os);
    let has_nonempty_wal = fs::symlink_metadata(&src_wal)
        .map(|m| !m.file_type().is_symlink() && m.is_file() && m.len() > 0)
        .unwrap_or(false);

    let staged_ro_target = if has_nonempty_wal {
        let wal_copy = dst_dir.join("external_raw.sqlite-wal");
        let _ = copy_file_private_stream(&src_wal, &wal_copy);
        let mut shm_os = src_db.as_os_str().to_os_string();
        shm_os.push("-shm");
        let src_shm = PathBuf::from(shm_os);
        if fs::symlink_metadata(&src_shm)
            .map(|m| !m.file_type().is_symlink() && m.is_file())
            .unwrap_or(false)
        {
            let _ = copy_file_private_stream(&src_shm, &dst_dir.join("external_raw.sqlite-shm"));
        }
        let clean_copy = dst_dir.join("external_clean.sqlite");
        backup_clone(&raw_copy, &clean_copy)?;
        clean_copy
    } else {
        raw_copy
    };

    open_staged_ro(&staged_ro_target, DEFAULT_MMAP_BYTES)
}

fn table_has_columns(conn: &Connection, table: &str) -> KbResult<HashSet<String>> {
    let mut cols = HashSet::new();
    let sql = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&sql)?;
    let iter = stmt.query_map([], |r| r.get::<_, String>(1))?;
    for c in iter.flatten() {
        cols.insert(c.to_ascii_lowercase());
    }
    Ok(cols)
}

/// Reads messages and attachments read-only from an external legacy `3.0-multidim`
/// or `1.0-universal` SQLite database into `RawMessageInput` records.
pub(crate) fn load_raw_messages_from_db(
    conn: &Connection,
    limit: Option<usize>,
) -> KbResult<Vec<RawMessageInput>> {
    let mmsg_cols = table_has_columns(conn, "mail_messages").unwrap_or_default();
    let msg_cols = table_has_columns(conn, "messages").unwrap_or_default();

    let (table_name, cols) = if !mmsg_cols.is_empty() {
        ("mail_messages", mmsg_cols)
    } else if !msg_cols.is_empty() {
        ("messages", msg_cols)
    } else {
        return Err(KbError::NotFound(
            "source database has neither 'mail_messages' nor 'messages' table".to_string(),
        ));
    };

    let col_expr = |name: &str, alias: &str, fallback_sql: &str| -> String {
        if cols.contains(name) {
            format!("COALESCE({name}, {fallback_sql}) AS {alias}")
        } else {
            format!("{fallback_sql} AS {alias}")
        }
    };

    let rfc_col = if cols.contains("rfc_message_id") {
        "COALESCE(rfc_message_id, '') AS rfc_message_id".to_string()
    } else if cols.contains("message_id") {
        "COALESCE(message_id, '') AS rfc_message_id".to_string()
    } else {
        "'' AS rfc_message_id".to_string()
    };

    let limit_clause = match limit {
        Some(n) => format!(" LIMIT {n}"),
        None => String::new(),
    };

    let sql = format!(
        "SELECT id, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {} \
         FROM {table_name} ORDER BY date_iso DESC, id DESC{limit_clause}",
        col_expr("uid_key", "uid_key", "''"),
        col_expr("account_id", "account_id", "''"),
        col_expr("source", "source", "'legacy_import'"),
        col_expr("source_ref", "source_ref", "''"),
        rfc_col,
        col_expr("subject", "subject", "''"),
        col_expr("sender", "sender", "''"),
        col_expr("recipients", "recipients", "''"),
        col_expr("cc", "cc", "''"),
        col_expr("date_iso", "date_iso", "''"),
        col_expr("folder_path", "folder_path", "''"),
        col_expr("completeness", "completeness", "'full_body'"),
        col_expr("body_latest", "body_latest", "''"),
        col_expr("body_quoted", "body_quoted", "''"),
    );

    let mut rows: Vec<(i64, RawMessageInput)> = Vec::new();
    {
        let mut stmt = conn.prepare(&sql)?;
        let iter = stmt.query_map([], |r| {
            let old_id: i64 = r.get(0)?;
            let uid_key: String = r.get(1)?;
            let account_id: String = r.get(2)?;
            let source: String = r.get(3)?;
            let mut source_ref: String = r.get(4)?;
            let rfc_raw: String = r.get(5)?;
            let subject: String = r.get(6)?;
            let sender: String = r.get(7)?;
            let recipients: String = r.get(8)?;
            let cc: String = r.get(9)?;
            let date_iso: String = r.get(10)?;
            let folder_path: String = r.get(11)?;
            let completeness: String = r.get(12)?;
            let body_latest: String = r.get(13)?;
            let body_quoted: String = r.get(14)?;

            if source_ref.is_empty() {
                source_ref = format!("legacy:{old_id}");
            }
            let rfc_message_id = rfc_raw.trim().trim_matches(|c| c == '<' || c == '>').to_string();
            let resolved_uid = if uid_key.is_empty() {
                norm_uid_from_fields(&rfc_message_id, &date_iso, &sender, &subject, &body_latest)
            } else {
                uid_key
            };
            Ok((
                old_id,
                RawMessageInput {
                    uid_key: resolved_uid,
                    account_id,
                    source,
                    source_ref,
                    rfc_message_id,
                    subject,
                    sender,
                    recipients,
                    cc,
                    date_iso,
                    folder_path,
                    completeness,
                    body_latest,
                    body_quoted: body_quoted.clone(),
                    body_quoted_for_amount: body_quoted,
                    html_tables: Vec::new(),
                    attachments: Vec::new(),
                },
            ))
        })?;
        for res in iter {
            rows.push(res?);
        }
    }

    // Load attachments from `message_attachments` or `message_attachments_mime`
    let matt_full = table_has_columns(conn, "message_attachments").unwrap_or_default();
    let matt_mime = table_has_columns(conn, "message_attachments_mime").unwrap_or_default();
    let (att_table, att_cols) = if !matt_full.is_empty() {
        ("message_attachments", matt_full)
    } else if !matt_mime.is_empty() {
        ("message_attachments_mime", matt_mime)
    } else {
        ("", HashSet::new())
    };

    if !att_table.is_empty() && !rows.is_empty() {
        let mut by_msg_id: HashMap<i64, Vec<RawAttachmentInput>> = HashMap::new();
        let acol = |name: &str, def: &str| -> String {
            if att_cols.contains(name) {
                format!("COALESCE({name}, {def})")
            } else {
                def.to_string()
            }
        };
        let asql = format!(
            "SELECT message_id, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {} FROM {att_table}",
            acol("filename", "''"),
            acol("clean_filename", "''"),
            acol("ext", "''"),
            acol("mime_type", "''"),
            acol("size_bytes", "0"),
            acol("mtime", "0"),
            acol("mtime_iso", "''"),
            acol("storage_relpath", "''"),
            acol("is_inline", "0"),
            acol("is_noise", "0"),
            acol("sha256", "''"),
            acol("text_preview", "''"),
        );
        if let Ok(mut stmt) = conn.prepare(&asql) {
            if let Ok(iter) = stmt.query_map([], |r| {
                let msg_id: i64 = r.get(0)?;
                let filename: String = r.get(1)?;
                let clean_fn_raw: String = r.get(2)?;
                let clean_filename = if clean_fn_raw.is_empty() {
                    filename.clone()
                } else {
                    clean_fn_raw
                };
                let ext: String = r.get(3)?;
                let mime_type: String = r.get(4)?;
                let size_bytes: i64 = r.get(5)?;
                let mtime: i64 = r.get(6)?;
                let mtime_iso: String = r.get(7)?;
                let storage_relpath: String = r.get(8)?;
                let is_inline: i32 = r.get(9)?;
                let is_noise: i32 = r.get(10)?;
                let sha256: String = r.get(11)?;
                let text_preview: String = r.get(12)?;
                Ok((
                    msg_id,
                    RawAttachmentInput {
                        filename,
                        clean_filename,
                        ext,
                        mime_type,
                        size_bytes,
                        mtime,
                        mtime_iso,
                        storage_relpath,
                        is_inline,
                        is_noise,
                        sha256,
                        text_preview,
                        ooxml_sheets: Vec::new(),
                    },
                ))
            }) {
                for item in iter.flatten() {
                    by_msg_id.entry(item.0).or_default().push(item.1);
                }
            }
        }
        for (old_id, msg) in &mut rows {
            if let Some(atts) = by_msg_id.remove(old_id) {
                msg.attachments = atts;
            }
        }
    }

    Ok(rows.into_iter().map(|(_, m)| m).collect())
}

#[derive(Default)]
struct ThreadCtx {
    topics: Vec<String>,
    orgs: Vec<String>,
    entities: Vec<String>,
    category: String,
}

fn apply_thread_context_fallback(em: &mut EnrichedMsg, tctx: &HashMap<String, ThreadCtx>) {
    if em.completeness == "full_body" || em.thread_topic.is_empty() {
        return;
    }
    let Some(ctx) = tctx.get(&em.thread_topic) else {
        return;
    };
    let mut changed = false;
    if em.primary_entities_vec.is_empty() && !ctx.entities.is_empty() {
        em.primary_entities_vec = ctx.entities.clone();
        em.primary_entities = em.primary_entities_vec.join(",");
        if !ctx.category.is_empty() {
            em.primary_category = ctx.category.clone();
        }
        changed = true;
    }
    if em.topic_vec.is_empty() && !ctx.topics.is_empty() {
        em.topic_vec = ctx.topics.clone();
        em.topic_tags = em.topic_vec.join(",");
        changed = true;
    }
    if em.org_vec.is_empty() && !ctx.orgs.is_empty() {
        em.org_vec = ctx.orgs.clone();
        em.org_tags = em.org_vec.join(",");
        changed = true;
    }
    if changed {
        rebuild_fts_tokens(em, &[]);
    }
}

fn apply_quoted_amount_fallback(
    em: &mut EnrichedMsg,
    pack: &CompiledDomainPack,
    identity: &ResolvedIdentity,
    thread_latest_amounts: &mut HashSet<String>,
) {
    let pkey = |topic: &str, a: &crate::enrich::AmountRow| -> String {
        let v = a.unit_amount.or(a.total_amount).unwrap_or(-1.0);
        format!("{topic}|{}|{}|{v:.2}", a.subject_entity, a.currency)
    };
    if !em.amounts.is_empty() {
        for a in &em.amounts {
            thread_latest_amounts.insert(pkey(&em.thread_topic, a));
        }
        return;
    }
    if em.body_quoted_for_amount.is_empty() {
        return;
    }
    if is_excluded_amount_message(pack, identity, &em.subject, &em.sender) {
        return;
    }

    let s_codes = extract_item_codes(&em.subject, pack);
    let s_single = if s_codes.len() == 1 {
        s_codes[0].entity_key.as_str()
    } else {
        ""
    };
    let eff_date = if em.date_iso.len() >= 10 {
        &em.date_iso[..10]
    } else {
        ""
    };
    let dt = detect_tax_mode_str(&em.subject);
    let mut q_amts = Vec::new();
    extract_amounts_from_body(
        &em.body_quoted_for_amount,
        pack,
        &em.topic_tags,
        &em.org_tags,
        eff_date,
        &dt,
        s_single,
        "body_quoted",
        false,
        &mut q_amts,
    );
    for mut qa in q_amts {
        let k = pkey(&em.thread_topic, &qa);
        if thread_latest_amounts.insert(k) {
            qa.confidence = "medium".to_string();
            em.amounts.push(qa);
        }
    }
    if !em.amounts.is_empty() {
        em.has_amount = 1;
        em.amount_summary = format_amount_rollup(&em.amounts);
        em.dfts_amounts = tokenize_for_fts(&em.amount_summary);
    }
}

fn update_thread_ctx(em: &EnrichedMsg, tctx: &mut HashMap<String, ThreadCtx>) {
    if em.completeness != "full_body" || em.thread_topic.is_empty() {
        return;
    }
    if em.primary_entities_vec.is_empty() && em.topic_vec.is_empty() && em.org_vec.is_empty() {
        return;
    }
    let c = tctx.entry(em.thread_topic.clone()).or_default();
    if c.entities.is_empty() && !em.primary_entities_vec.is_empty() {
        c.entities = em.primary_entities_vec.clone();
        c.category = em.primary_category.clone();
    }
    if c.topics.is_empty() && !em.topic_vec.is_empty() {
        c.topics = em.topic_vec.clone();
    }
    if c.orgs.is_empty() && !em.org_vec.is_empty() {
        c.orgs = em.org_vec.clone();
    }
}

struct InsertStmts<'conn> {
    msg: Statement<'conn>,
    mfts: Statement<'conn>,
    dfts: Statement<'conn>,
    att: Statement<'conn>,
    afts: Statement<'conn>,
    ment: Statement<'conn>,
    mamt: Statement<'conn>,
}

impl<'conn> InsertStmts<'conn> {
    fn prepare(db: &'conn Connection) -> KbResult<Self> {
        Ok(Self {
            msg: db.prepare(
                "INSERT INTO mail_messages (uid_key, account_id, source, source_ref, rfc_message_id, \
                 subject, thread_topic, sender, recipients, cc, date_iso, folder_path, completeness, \
                 direction, intent_type, summary_line, body_latest, body_quoted, content_hash, \
                 primary_entities, primary_category, topic_tags, org_tags, has_amount, amount_summary, \
                 event_dates_json, custom_dims_json) \
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )?,
            mfts: db.prepare(
                "INSERT INTO messages_fts (rowid, subject_tok, sender_tok, meta_tok, body_latest_tok, body_quoted_tok) \
                 VALUES (?,?,?,?,?,?)",
            )?,
            dfts: db.prepare(
                "INSERT INTO dimensions_fts (rowid, title_tok, meaning_tok, intent_tok, entities_tok, orgs_tok, topics_tok, amounts_tok) \
                 VALUES (?,?,?,?,?,?,?,?)",
            )?,
            att: db.prepare(
                "INSERT INTO message_attachments (message_id, uid_key, filename, clean_filename, ext, mime_type, \
                 size_bytes, mtime, mtime_iso, storage_relpath, is_inline, is_noise, sha256, text_preview, \
                 entity_tags, topic_tags) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )?,
            afts: db.prepare(
                "INSERT INTO attachments_fts (rowid, filename_tok, meta_tok) VALUES (?,?,?)",
            )?,
            ment: db.prepare(
                "INSERT INTO message_entities (message_id, uid_key, entity_type, entity_key, canonical_value, \
                 category, sub_group, quantity, unit, role, confidence, snippet, attrs_json) \
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )?,
            mamt: db.prepare(
                "INSERT INTO message_amounts (message_id, uid_key, amount_type, subject_entity, category, \
                 topic_name, org_name, currency, unit_amount, total_amount, quantity, tax_mode, terms_json, \
                 effective_date_iso, valid_until, source_kind, evidence_snippet, confidence) \
                 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            )?,
        })
    }
}

#[derive(Default)]
struct InsertCounters {
    att_clean: i64,
    att_noise: i64,
    entities: i64,
    amounts: i64,
    attachments: i64,
}

fn insert_attachment_row(
    db: &Connection,
    st: &mut InsertStmts<'_>,
    mid: i64,
    uid_key: &str,
    a: &EnrichedAttachment,
) -> KbResult<()> {
    st.att.execute(rusqlite::params![
        mid,
        uid_key,
        a.filename,
        a.clean_filename,
        a.ext,
        a.mime_type,
        a.size_bytes,
        a.mtime,
        a.mtime_iso,
        a.storage_relpath,
        a.is_inline,
        a.is_noise,
        a.sha256,
        a.text_preview,
        a.entity_tags,
        a.topic_tags,
    ])?;
    let aid = db.last_insert_rowid();
    st.afts
        .execute(rusqlite::params![aid, a.fn_tok, a.meta_tok])?;
    Ok(())
}

fn insert_one_message(
    db: &Connection,
    st: &mut InsertStmts<'_>,
    em: &EnrichedMsg,
    seen_hashes: &mut HashSet<String>,
    cnt: &mut InsertCounters,
    lex_hits: &mut HashMap<(String, String), i64>,
) -> KbResult<()> {
    let mut chash = em.content_hash.clone();
    if !seen_hashes.insert(chash.clone()) {
        chash = sha256_bytes(format!("{chash}:{}:{}", em.uid_key, em.source_ref).as_bytes());
        let mut tries = 0;
        while !seen_hashes.insert(chash.clone()) && tries < 8 {
            tries += 1;
            chash = sha256_bytes(format!("{chash}:{tries}").as_bytes());
        }
    }

    st.msg.execute(rusqlite::params![
        em.uid_key,
        em.account_id,
        em.source,
        em.source_ref,
        em.rfc_message_id,
        em.subject,
        em.thread_topic,
        em.sender,
        em.recipients,
        em.cc,
        em.date_iso,
        em.folder_path,
        em.completeness,
        em.direction,
        em.intent_type,
        em.summary_line,
        em.body_latest,
        em.body_quoted,
        chash,
        em.primary_entities,
        em.primary_category,
        em.topic_tags,
        em.org_tags,
        em.has_amount,
        em.amount_summary,
        em.event_dates_json,
        em.custom_dims_json,
    ])?;
    let mid = db.last_insert_rowid();

    st.mfts.execute(rusqlite::params![
        mid,
        em.mfts_subj,
        em.mfts_sender,
        em.mfts_meta,
        em.mfts_latest,
        em.mfts_quoted,
    ])?;

    st.dfts.execute(rusqlite::params![
        mid,
        em.dfts_title,
        em.dfts_meaning,
        em.dfts_intent,
        em.dfts_entities,
        em.dfts_orgs,
        em.dfts_topics,
        em.dfts_amounts,
    ])?;

    for a in &em.attachments {
        insert_attachment_row(db, st, mid, &em.uid_key, a)?;
        cnt.attachments += 1;
        if a.is_noise != 0 {
            cnt.att_noise += 1;
        } else {
            cnt.att_clean += 1;
        }
    }

    for ent in &em.entities {
        st.ment.execute(rusqlite::params![
            mid,
            em.uid_key,
            ent.entity_type,
            ent.entity_key,
            ent.canonical_value,
            ent.category,
            ent.sub_group,
            ent.quantity,
            ent.unit,
            ent.role,
            ent.confidence,
            ent.snippet,
            ent.attrs_json,
        ])?;
        cnt.entities += 1;
    }

    for amt in &em.amounts {
        st.mamt.execute(rusqlite::params![
            mid,
            em.uid_key,
            amt.amount_type,
            amt.subject_entity,
            amt.category,
            amt.topic_name,
            amt.org_name,
            amt.currency,
            amt.unit_amount,
            amt.total_amount,
            amt.quantity,
            amt.tax_mode,
            amt.terms_json,
            amt.effective_date_iso,
            amt.valid_until,
            amt.source_kind,
            amt.evidence_snippet,
            amt.confidence,
        ])?;
        cnt.amounts += 1;
    }

    for (dim, key) in &em.lexicon_hits {
        *lex_hits.entry((dim.clone(), key.clone())).or_insert(0) += 1;
    }

    Ok(())
}

pub(crate) fn build_apple_mail_work_items(
    env_rows: Vec<EnvelopeRow>,
    mailboxes: &HashMap<i64, crate::apple_mail::MailboxInfo>,
) -> Vec<WorkItem> {
    let better_loc = |a: &CopyLocation, a_sz: i64, b: &CopyLocation, b_sz: i64| -> bool {
        let ra = folder_rank_bonus(&a.folder_path);
        let rb = folder_rank_bonus(&b.folder_path);
        if ra != rb {
            return ra > rb;
        }
        let ea = match (&a.emlx_path, a.is_partial) {
            (Some(_), false) => 2,
            (Some(_), true) => 1,
            _ => 0,
        };
        let eb = match (&b.emlx_path, b.is_partial) {
            (Some(_), false) => 2,
            (Some(_), true) => 1,
            _ => 0,
        };
        if ea != eb {
            return ea > eb;
        }
        a_sz > b_sz
    };

    let mut uid_to_wi: HashMap<String, usize> = HashMap::with_capacity(env_rows.len());
    let mut work_items: Vec<WorkItem> = Vec::with_capacity(env_rows.len());

    for er in env_rows {
        let mb = mailboxes.get(&er.mailbox_id);
        let loc = resolve_copy_location(&er, mb);
        let acct_id = mb.map(|m| m.account_id.clone()).unwrap_or_default();
        let sort_ts = if er.date_sent > 0 {
            er.date_sent
        } else {
            er.date_received
        };
        let date_iso = format_local_datetime(sort_ts);
        let mut uid = norm_uid_from_fields(
            &er.message_id_header,
            &date_iso,
            &er.sender,
            &er.subject,
            &er.summary,
        );
        if er.message_id_header.is_empty() {
            if let Some(ref emlx_p) = loc.emlx_path {
                if let Ok((hdr_only, _)) = read_file_readonly(emlx_p, Some(16_384)) {
                    if !hdr_only.is_empty() {
                        let rfc = slice_emlx_rfc822(&hdr_only);
                        let (hdrs, _) = split_mime_headers_body(rfc);
                        if let Some(mid_raw) = hdrs.get("message-id") {
                            let mid_s = sanitize_utf8(mid_raw);
                            if !mid_s.is_empty() {
                                uid = norm_uid_from_fields(
                                    &mid_s,
                                    &date_iso,
                                    &er.sender,
                                    &er.subject,
                                    &er.summary,
                                );
                            }
                        }
                    }
                }
            }
        }

        if let Some(&idx) = uid_to_wi.get(&uid) {
            let wi = &mut work_items[idx];
            if better_loc(&loc, er.size_bytes, &wi.primary_loc, wi.env.size_bytes) {
                let old_loc = std::mem::replace(&mut wi.primary_loc, loc);
                wi.secondary_locs.push(old_loc);
                wi.env = er;
                wi.account_id = acct_id;
            } else {
                wi.secondary_locs.push(loc);
                if wi.env.recipients.is_empty() && !er.recipients.is_empty() {
                    wi.env.recipients = er.recipients;
                }
                if wi.env.cc.is_empty() && !er.cc.is_empty() {
                    wi.env.cc = er.cc;
                }
            }
        } else {
            uid_to_wi.insert(uid.clone(), work_items.len());
            work_items.push(WorkItem {
                is_eml: false,
                is_emlx_standalone: false,
                sort_ts,
                uid_key: uid,
                account_id: acct_id,
                date_iso,
                env: er,
                primary_loc: loc,
                secondary_locs: Vec::new(),
                eml_abs_path: PathBuf::new(),
                eml_rel_path: String::new(),
                merged_eml_relpaths: Vec::new(),
            });
        }
    }

    work_items
}

pub(crate) fn merge_eml_work_items(
    work_items: &mut Vec<WorkItem>,
    eml_files: &[ScannedEmlInfo],
) -> InferredIdentity {
    let mut uid_to_wi: HashMap<String, usize> = HashMap::with_capacity(work_items.len() + eml_files.len());
    for (idx, wi) in work_items.iter().enumerate() {
        if !wi.uid_key.is_empty() {
            uid_to_wi.insert(wi.uid_key.clone(), idx);
        }
    }

    let mut sent_pairs: Vec<(String, String)> = Vec::new();
    for ef in eml_files {
        let mut uid = String::new();
        let mut date_iso = String::new();
        if let Ok((hdr_only, _)) = read_file_readonly(&ef.abs_path, Some(32_768)) {
            if !hdr_only.is_empty() {
                let rfc = if ef.is_emlx {
                    slice_emlx_rfc822(&hdr_only)
                } else {
                    hdr_only.as_slice()
                };
                let (hdrs, bv) = split_mime_headers_body(rfc);
                let subj = extract_header_str(&hdrs, "subject");
                let snd = extract_header_str(&hdrs, "from");
                if let Some((dir, _)) = ef.rel_path.rsplit_once('/') {
                    sent_pairs.push((dir.to_string(), snd.clone()));
                }
                date_iso = if hdrs.contains_key("date") {
                    parse_rfc5322_date(&extract_header_str(&hdrs, "date"))
                } else {
                    String::new()
                };
                let mid = hdrs
                    .get("message-id")
                    .map(|v| sanitize_utf8(v))
                    .unwrap_or_default();
                let hint = sanitize_utf8(&bv[..bv.len().min(500)]);
                uid = norm_uid_from_fields(&mid, &date_iso, &snd, &subj, &hint);
            }
        }
        if !uid.is_empty() {
            if let Some(&idx) = uid_to_wi.get(&uid) {
                work_items[idx].merged_eml_relpaths.push(ef.rel_path.clone());
                continue;
            }
            uid_to_wi.insert(uid.clone(), work_items.len());
        }
        work_items.push(WorkItem {
            is_eml: true,
            is_emlx_standalone: ef.is_emlx,
            sort_ts: ef.mtime_ns / 1_000_000_000,
            uid_key: uid,
            account_id: "eml".to_string(),
            date_iso,
            env: EnvelopeRow::default(),
            primary_loc: CopyLocation::default(),
            secondary_locs: Vec::new(),
            eml_abs_path: ef.abs_path.clone(),
            eml_rel_path: ef.rel_path.clone(),
            merged_eml_relpaths: Vec::new(),
        });
    }

    infer_identity_from_messages(
        sent_pairs
            .iter()
            .map(|(f, s)| (f.as_str(), s.as_str())),
    )
}

/// Executes incremental or full sync into `cfg.primary_db_path()` and updates runtime cache.
pub fn run_sync(cfg: &MailKbConfig, opts: &SyncOpts) -> KbResult<Value> {
    let t0 = Instant::now();
    let mut warnings: Vec<String> = Vec::new();
    let writer_host = get_hostname();

    let runtime_db = cfg.runtime_db_for_path(DEFAULT_DB_STEM, cfg.primary_db_path());
    let build_base = TempBuildDir::build_base_dir();
    let db_parent = cfg
        .db_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    // S9 zero-write verification
    for p in [
        &cfg.db_path,
        &db_parent,
        &cfg.runtime_dir,
        &runtime_db,
        &build_base,
    ] {
        assert_not_in_mail_container(cfg, p)?;
    }

    let pack = if cfg.no_packs || cfg.pack_paths.is_empty() {
        CompiledDomainPack::empty()
    } else {
        CompiledDomainPack::from_files(&cfg.pack_paths)?
    };
    let rules_fp = pack.rules_fingerprint();

    let has_legacy = opts.import_legacy_db.is_some();
    let has_eml_dirs = !cfg.eml_dirs.is_empty();
    let mut use_apple_mail = false;

    if !has_legacy {
        match mail_master_state(cfg) {
            MasterState::Master => {
                use_apple_mail = true;
            }
            MasterState::AccessDenied(why) => {
                if !has_eml_dirs {
                    return Err(KbError::Other(format!(
                        "{why} -- grant Full Disk Access or pass --eml-dir / --import-legacy-db"
                    )));
                }
                push_unique_warning(&mut warnings, why);
            }
            MasterState::NotMaster(why) => {
                if !has_eml_dirs {
                    let elapsed = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
                    return Ok(json!({
                        "status": "skipped_non_master_host",
                        "host_os": host_os(),
                        "reason": why,
                        "message": "No Apple Mail store, --eml-dir, or --import-legacy-db source available on this host",
                        "db_path": cfg.db_path.display().to_string(),
                        "db_modified": false,
                        "warnings": warnings,
                        "elapsed_ms": elapsed,
                    }));
                }
                if cfg.apple_mail_v10_dir.is_some() {
                    push_unique_warning(&mut warnings, format!("apple_mail_skipped: {why}"));
                }
            }
        }
    }

    // T4 exclusive writer lock (skipped in --dry-run)
    let _writer_lock = if !opts.dry_run {
        ensure_private_dir(&cfg.runtime_dir)?;
        let lock_path = cfg.runtime_dir.join("mailkb_db.sync.lock");
        let lk = NonBlockingFlock::try_acquire(&lock_path)?.ok_or_else(|| {
            KbError::LockBusy("another mailkb_db sync process holds the writer lock".to_string())
        })?;
        Some(lk)
    } else {
        None
    };

    reap_stale_build_dirs(&build_base, BUILD_DIR_PREFIX, 86_400);

    // Inspect existing cold DB via staged runtime snapshot (T2)
    let mut old_meta: HashMap<String, String> = HashMap::new();
    let mut last_staging = String::new();
    if !opts.dry_run && fs::symlink_metadata(&cfg.db_path).is_ok() {
        if let Ok(si) = stage_primary_db(cfg) {
            last_staging = si.staging.as_str().to_string();
            for w in si.warnings {
                push_unique_warning(&mut warnings, w);
            }
            if !matches!(
                si.staging,
                StagingState::CachedDuringSync | StagingState::CachedSourceMissing
            ) {
                if let Ok(m) = read_existing_meta(&si.runtime_db) {
                    old_meta = m;
                }
            }
        }
    }

    let eml_files = scan_all_eml_dirs(&cfg.eml_dirs);
    let eml_snap = serialize_eml_snapshot(&eml_files);
    let cfg_filters_str = cfg.account_filters.join(",");
    let cfg_eml_dirs_str = join_paths_str(&cfg.eml_dirs);

    let (mut live_idx_sz, mut live_idx_mt, mut live_wal_sz, mut live_wal_mt) =
        (0i64, 0i64, 0i64, 0i64);
    if use_apple_mail {
        if let Some(ref v10) = cfg.apple_mail_v10_dir {
            let md = v10.join("MailData");
            if let Ok(m) = fs::symlink_metadata(md.join("Envelope Index")) {
                live_idx_sz = m.len() as i64;
                live_idx_mt = meta_mtime_ns(&m);
            }
            if let Ok(m) = fs::symlink_metadata(md.join("Envelope Index-wal")) {
                live_wal_sz = m.len() as i64;
                live_wal_mt = meta_mtime_ns(&m);
            }
        }
    }

    let meta_base_match = !opts.full
        && !opts.dry_run
        && opts.limit.is_none()
        && !has_legacy
        && !old_meta.is_empty()
        && old_meta.get("schema_version").map(String::as_str) == Some(SCHEMA_VERSION)
        && old_meta.get("rules_version").map(String::as_str) == Some(RULES_VERSION)
        && old_meta.get("rules_fingerprint").map(String::as_str) == Some(rules_fp.as_str())
        && old_meta.get("cfg_account_filters").map(String::as_str) == Some(cfg_filters_str.as_str())
        && old_meta.get("cfg_eml_dirs").map(String::as_str) == Some(cfg_eml_dirs_str.as_str())
        && old_meta.get("snap_eml_files").map(String::as_str) == Some(eml_snap.as_str());

    let make_skip_outcome = |skip_mode: &str, warnings: &[String]| -> Value {
        let msgs_total = old_meta
            .get("messages_total")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let atts_total = old_meta
            .get("attachments_total")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let rss = get_peak_rss_bytes();
        let elapsed = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
        json!({
            "status": "up_to_date",
            "mode": skip_mode,
            "schema_version": SCHEMA_VERSION,
            "writer_version": ENGINE_VERSION,
            "db_path": cfg.db_path.display().to_string(),
            "db_modified": false,
            "messages_total": msgs_total,
            "attachments_total": atts_total,
            "source_db": cfg.db_path.display().to_string(),
            "runtime_db": runtime_db.display().to_string(),
            "staging": if last_staging.is_empty() { "reused" } else { last_staging.as_str() },
            "peak_rss_bytes": rss,
            "warnings": warnings,
            "elapsed_ms": elapsed,
        })
    };

    if meta_base_match {
        let mail_stat_same = if !use_apple_mail {
            old_meta
                .get("apple_mail_msg_rows")
                .is_none_or(|s| s == "0" || s.is_empty())
        } else {
            old_meta.get("apple_mail_env_idx_size").map(String::as_str)
                == Some(&live_idx_sz.to_string())
                && old_meta.get("apple_mail_env_idx_mtime").map(String::as_str)
                    == Some(&live_idx_mt.to_string())
                && old_meta.get("apple_mail_env_wal_size").map(String::as_str)
                    == Some(&live_wal_sz.to_string())
                && old_meta.get("apple_mail_env_wal_mtime").map(String::as_str)
                    == Some(&live_wal_mt.to_string())
        };
        if mail_stat_same {
            return Ok(make_skip_outcome("incremental_stat_skip", &warnings));
        }
    }

    // Create private 0700 build dir
    let build_dir = TempBuildDir::new(cfg, BUILD_DIR_PREFIX)?;
    let work_path = build_dir.path().join("work.sqlite");
    let clean_path = build_dir.path().join("clean.sqlite");
    let env_idx_dir = build_dir.path().join("env_idx");

    let mut staged_env_info = StagedEnvelopeInfo::default();
    let mut env_db: Option<Connection> = None;
    let mut mailboxes = HashMap::new();
    let mut discovered_accounts: Vec<DiscoveredAccount> = Vec::new();
    let mut selected_mailbox_ids: Vec<i64> = Vec::new();
    let mut am_inferred = InferredIdentity::default();
    let mut cur_max_rowid: i64 = 0;
    let mut cur_msg_rows: i64 = 0;

    if use_apple_mail {
        if let Some(ref v10) = cfg.apple_mail_v10_dir {
            staged_env_info = copy_envelope_index_to_dir(v10, &env_idx_dir)?;
            let edb = open_staged_envelope_ro(&staged_env_info.env_path)?;
            mailboxes = load_all_mailboxes(&edb, v10)?;
            let (inf, per_acct_emails) = infer_identity_from_envelope_db(&edb, &mailboxes)?;
            am_inferred = inf;
            let (accts, mb_ids) = discover_accounts_and_filter(
                &edb,
                &mailboxes,
                &per_acct_emails,
                &cfg.account_filters,
            )?;
            discovered_accounts = accts;
            selected_mailbox_ids = mb_ids;
            let (mr, mrows) = query_envelope_counts(&edb, &selected_mailbox_ids)?;
            cur_max_rowid = mr;
            cur_msg_rows = mrows;
            env_db = Some(edb);
        }
    }

    let old_max_rowid = old_meta
        .get("apple_mail_max_rowid")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);
    let old_msg_rows = old_meta
        .get("apple_mail_msg_rows")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(0);

    if meta_base_match
        && use_apple_mail
        && cur_max_rowid <= old_max_rowid
        && cur_msg_rows == old_msg_rows
    {
        drop(env_db);
        return Ok(make_skip_outcome("incremental_wal_skip", &warnings));
    }

    let can_incremental_delta = meta_base_match
        && use_apple_mail
        && old_max_rowid > 0
        && cur_max_rowid > old_max_rowid
        && cur_msg_rows >= old_msg_rows
        && (cur_msg_rows - old_msg_rows) <= 2000
        && is_valid_runtime_sqlite(&runtime_db);

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.max_threads.max(1))
        .build()
        .map_err(|e| KbError::Other(format!("failed to create rayon pool: {e}")))?;

    let parse_errors = AtomicU64::new(0);
    let eml_truncated = AtomicU64::new(0);
    let mut cnt = InsertCounters::default();
    let mut cnt_msgs_total: i64 = 0;
    let mut cnt_am_msgs: i64 = 0;
    let mut cnt_eml_msgs: i64 = 0;
    let mut cnt_legacy_msgs: i64 = 0;
    let mut lex_hits: HashMap<(String, String), i64> = HashMap::new();
    let mode_label: String;

    let mut final_inferred = am_inferred.clone();
    let resolved_identity = ResolvedIdentity::from_pack_and_inferred(&pack, &final_inferred);

    if can_incremental_delta {
        mode_label = "incremental_delta".to_string();
        let edb = env_db.take().expect("env_db present");
        let (delta_rows, max_rid) =
            query_envelope_rows(&edb, &selected_mailbox_ids, old_max_rowid)?;
        if max_rid > cur_max_rowid {
            cur_max_rowid = max_rid;
        }
        drop(edb);
        let _ = fs::remove_dir_all(&env_idx_dir);

        let old_db_bytes = fs::metadata(&cfg.db_path).map(|m| m.len()).unwrap_or(0);
        check_disk_space(&build_base, &db_parent, &cfg.runtime_dir, old_db_bytes)?;

        fs::copy(&runtime_db, &work_path)
            .map_err(|e| KbError::Publish(format!("incremental clone failed: {e}")))?;

        let db = Connection::open_with_flags(
            &work_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.execute_batch(
            "PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF; PRAGMA temp_store=FILE; PRAGMA cache_size=-32768; BEGIN IMMEDIATE;",
        )?;

        let mut seen_hashes: HashSet<String> = HashSet::new();
        {
            let mut hs = db.prepare("SELECT content_hash FROM mail_messages")?;
            let iter = hs.query_map([], |r| r.get::<_, String>(0))?;
            for s in iter.flatten() {
                seen_hashes.insert(s);
            }
        }

        let work_items = build_apple_mail_work_items(delta_rows, &mailboxes);
        let v10_ref = cfg.apple_mail_v10_dir.as_deref();
        let parsed: Vec<Option<EnrichedMsg>> = pool.install(|| {
            work_items
                .par_iter()
                .map(|wi| {
                    match catch_unwind(AssertUnwindSafe(|| {
                        process_work_item(wi, v10_ref, &pack, &resolved_identity, &eml_truncated)
                    })) {
                        Ok(em) => Some(em),
                        Err(_) => {
                            parse_errors.fetch_add(1, Ordering::Relaxed);
                            None
                        }
                    }
                })
                .collect()
        });

        let mut thread_latest_amounts: HashSet<String> = HashSet::new();
        {
            let mut st = InsertStmts::prepare(&db)?;
            for em_opt in parsed {
                let Some(mut em) = em_opt else { continue };
                let existing_mid: Option<i64> = db
                    .query_row(
                        "SELECT id FROM mail_messages WHERE uid_key = ?1 LIMIT 1",
                        [&em.uid_key],
                        |r| r.get(0),
                    )
                    .ok();
                if let Some(mid) = existing_mid {
                    for a in &em.attachments {
                        let exists: i64 = db
                            .query_row(
                                "SELECT COUNT(*) FROM message_attachments WHERE message_id = ?1 AND clean_filename = ?2 AND size_bytes = ?3",
                                rusqlite::params![mid, a.clean_filename, a.size_bytes],
                                |r| r.get(0),
                            )
                            .unwrap_or(0);
                        if exists == 0 {
                            insert_attachment_row(&db, &mut st, mid, &em.uid_key, a)?;
                        }
                    }
                    continue;
                }
                apply_quoted_amount_fallback(
                    &mut em,
                    &pack,
                    &resolved_identity,
                    &mut thread_latest_amounts,
                );
                insert_one_message(&db, &mut st, &em, &mut seen_hashes, &mut cnt, &mut lex_hits)?;
            }
        }

        // Update domain_lexicon hit_counts from delta
        if !lex_hits.is_empty() {
            let mut up = db.prepare(
                "UPDATE domain_lexicon SET hit_count = hit_count + ?1 WHERE dimension = ?2 AND key = ?3",
            )?;
            for ((dim, key), delta) in &lex_hits {
                up.execute(rusqlite::params![delta, dim, key])?;
            }
        }

        let q1 = |sql: &str| -> i64 { db.query_row(sql, [], |r| r.get(0)).unwrap_or(0) };
        cnt_msgs_total = q1("SELECT COUNT(*) FROM mail_messages;");
        cnt_am_msgs = q1("SELECT COUNT(*) FROM mail_messages WHERE source='apple_mail';");
        cnt_eml_msgs = q1("SELECT COUNT(*) FROM mail_messages WHERE source='eml';");
        cnt_legacy_msgs = cnt_msgs_total - cnt_am_msgs - cnt_eml_msgs;
        cnt.att_clean = q1("SELECT COUNT(*) FROM message_attachments WHERE is_noise=0;");
        cnt.att_noise = q1("SELECT COUNT(*) FROM message_attachments WHERE is_noise=1;");
        cnt.entities = q1("SELECT COUNT(*) FROM message_entities;");
        cnt.amounts = q1("SELECT COUNT(*) FROM message_amounts;");
        cnt.attachments = q1("SELECT COUNT(*) FROM message_attachments;");

        {
            let mut st_meta = db.prepare("INSERT OR REPLACE INTO kb_meta (key, value) VALUES (?,?)")?;
            let meta_updates = [
                ("last_sync_iso", format_local_datetime(now_unix_secs())),
                ("writer_host", writer_host.clone()),
                ("writer_version", ENGINE_VERSION.to_string()),
                ("pack_ids", pack.loaded_pack_ids.join(",")),
                ("rules_fingerprint", rules_fp.clone()),
                ("apple_mail_max_rowid", cur_max_rowid.to_string()),
                ("apple_mail_msg_rows", cur_msg_rows.to_string()),
                (
                    "apple_mail_env_idx_size",
                    staged_env_info.idx_size.to_string(),
                ),
                (
                    "apple_mail_env_idx_mtime",
                    staged_env_info.idx_mtime_ns.to_string(),
                ),
                (
                    "apple_mail_env_wal_size",
                    staged_env_info.wal_size.to_string(),
                ),
                (
                    "apple_mail_env_wal_mtime",
                    staged_env_info.wal_mtime_ns.to_string(),
                ),
                ("messages_total", cnt_msgs_total.to_string()),
                ("apple_mail_messages", cnt_am_msgs.to_string()),
                ("eml_messages", cnt_eml_msgs.to_string()),
                ("legacy_import_messages", cnt_legacy_msgs.to_string()),
                ("attachments_total", cnt.attachments.to_string()),
                ("attachments_clean", cnt.att_clean.to_string()),
                ("attachments_noise", cnt.att_noise.to_string()),
                ("message_entities_count", cnt.entities.to_string()),
                ("message_amounts_count", cnt.amounts.to_string()),
                ("message_attachments_count", cnt.attachments.to_string()),
            ];
            for (k, v) in meta_updates {
                st_meta.execute(rusqlite::params![k, v])?;
            }
        }

        db.execute_batch(
            "COMMIT;\
             INSERT INTO messages_fts(messages_fts) VALUES('optimize');\
             INSERT INTO attachments_fts(attachments_fts) VALUES('optimize');\
             INSERT INTO dimensions_fts(dimensions_fts) VALUES('optimize');",
        )?;
    } else {
        // Full / Import / Dry-Run build
        mode_label = if opts.dry_run {
            "dry_run"
        } else if has_legacy {
            "import_legacy_db"
        } else if opts.full {
            "full"
        } else if !use_apple_mail {
            "eml_only"
        } else {
            "rebuild"
        }
        .to_string();

        // Collect Raw/Work items
        let mut work_items: Vec<WorkItem> = Vec::new();
        if let Some(edb) = env_db.take() {
            let (rows, mr) = query_envelope_rows(&edb, &selected_mailbox_ids, 0)?;
            if mr > cur_max_rowid {
                cur_max_rowid = mr;
            }
            drop(edb);
            let _ = fs::remove_dir_all(&env_idx_dir);
            work_items = build_apple_mail_work_items(rows, &mailboxes);
        }

        let eml_inferred = merge_eml_work_items(&mut work_items, &eml_files);
        for em in eml_inferred.self_emails {
            if !final_inferred.self_emails.contains(&em) {
                final_inferred.self_emails.push(em);
            }
        }
        for dom in eml_inferred.internal_domains {
            if !final_inferred.internal_domains.contains(&dom) {
                final_inferred.internal_domains.push(dom);
            }
        }

        let mut legacy_raws: Vec<RawMessageInput> = Vec::new();
        if let Some(ref legacy_path) = opts.import_legacy_db {
            let legacy_dir = build_dir.path().join("legacy_import");
            let legacy_conn = stage_and_open_external_ro(cfg, legacy_path, &legacy_dir)?;
            legacy_raws = load_raw_messages_from_db(&legacy_conn, opts.limit)?;
            drop(legacy_conn);
            let _ = fs::remove_dir_all(&legacy_dir);
            let leg_inf = infer_identity_from_messages(
                legacy_raws
                    .iter()
                    .map(|m| (m.folder_path.as_str(), m.sender.as_str())),
            );
            for em in leg_inf.self_emails {
                if !final_inferred.self_emails.contains(&em) {
                    final_inferred.self_emails.push(em);
                }
            }
            for dom in leg_inf.internal_domains {
                if !final_inferred.internal_domains.contains(&dom) {
                    final_inferred.internal_domains.push(dom);
                }
            }
        }

        let final_identity = ResolvedIdentity::from_pack_and_inferred(&pack, &final_inferred);

        // Sort newest-first and apply `--limit`
        work_items.sort_by(|a, b| {
            b.date_iso
                .cmp(&a.date_iso)
                .then_with(|| b.sort_ts.cmp(&a.sort_ts))
                .then_with(|| a.uid_key.cmp(&b.uid_key))
        });
        if let Some(lim) = opts.limit {
            work_items.truncate(lim);
        }

        if opts.dry_run {
            // In dry-run, run enrichment across batches in memory without publishing
            let v10_ref = cfg.apple_mail_v10_dir.as_deref();
            let mut entity_hits = 0usize;
            let mut amount_hits = 0usize;
            let mut org_hits = 0usize;
            let mut topic_hits = 0usize;

            for chunk in work_items.chunks(STREAM_BATCH_SIZE) {
                let batch: Vec<Option<EnrichedMsg>> = pool.install(|| {
                    chunk
                        .par_iter()
                        .map(|wi| {
                            match catch_unwind(AssertUnwindSafe(|| {
                                process_work_item(
                                    wi,
                                    v10_ref,
                                    &pack,
                                    &final_identity,
                                    &eml_truncated,
                                )
                            })) {
                                Ok(em) => Some(em),
                                Err(_) => {
                                    parse_errors.fetch_add(1, Ordering::Relaxed);
                                    None
                                }
                            }
                        })
                        .collect()
                });
                for em in batch.into_iter().flatten() {
                    cnt_msgs_total += 1;
                    if em.source == "apple_mail" {
                        cnt_am_msgs += 1;
                    } else {
                        cnt_eml_msgs += 1;
                    }
                    if !em.primary_entities_vec.is_empty() {
                        entity_hits += 1;
                    }
                    if em.has_amount != 0 {
                        amount_hits += 1;
                    }
                    if !em.org_vec.is_empty() {
                        org_hits += 1;
                    }
                    if !em.topic_vec.is_empty() {
                        topic_hits += 1;
                    }
                    cnt.entities += em.entities.len() as i64;
                    cnt.amounts += em.amounts.len() as i64;
                    cnt.attachments += em.attachments.len() as i64;
                }
            }
            for chunk in legacy_raws.chunks(STREAM_BATCH_SIZE) {
                let batch: Vec<EnrichedMsg> = pool.install(|| {
                    chunk
                        .par_iter()
                        .map(|raw| enrich_message(raw, &pack, &final_identity))
                        .collect()
                });
                for em in batch {
                    cnt_msgs_total += 1;
                    cnt_legacy_msgs += 1;
                    if !em.primary_entities_vec.is_empty() {
                        entity_hits += 1;
                    }
                    if em.has_amount != 0 {
                        amount_hits += 1;
                    }
                    if !em.org_vec.is_empty() {
                        org_hits += 1;
                    }
                    if !em.topic_vec.is_empty() {
                        topic_hits += 1;
                    }
                    cnt.entities += em.entities.len() as i64;
                    cnt.amounts += em.amounts.len() as i64;
                    cnt.attachments += em.attachments.len() as i64;
                }
            }

            let rss_bytes = get_peak_rss_bytes();
            let elapsed = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;
            return Ok(json!({
                "status": "dry_run",
                "mode": "dry_run",
                "schema_version": SCHEMA_VERSION,
                "writer_version": ENGINE_VERSION,
                "db_path": cfg.db_path.display().to_string(),
                "db_modified": false,
                "pack_ids": pack.loaded_pack_ids,
                "accounts": discovered_accounts,
                "inferred_identity": {
                    "self_emails": final_inferred.self_emails,
                    "internal_domains": final_inferred.internal_domains,
                },
                "messages_total": cnt_msgs_total,
                "apple_mail_messages": cnt_am_msgs,
                "eml_messages": cnt_eml_msgs,
                "legacy_import_messages": cnt_legacy_msgs,
                "entity_hits": entity_hits,
                "org_hits": org_hits,
                "topic_hits": topic_hits,
                "amount_hits": amount_hits,
                "message_entities_count": cnt.entities,
                "message_amounts_count": cnt.amounts,
                "message_attachments_count": cnt.attachments,
                "parse_errors": parse_errors.load(Ordering::Relaxed),
                "eml_truncated": eml_truncated.load(Ordering::Relaxed),
                "peak_rss_bytes": rss_bytes,
                "warnings": warnings,
                "elapsed_ms": elapsed,
            }));
        }

        // C6 disk space check
        let old_db_bytes = fs::metadata(&cfg.db_path).map(|m| m.len()).unwrap_or(0);
        check_disk_space(&build_base, &db_parent, &cfg.runtime_dir, old_db_bytes)?;

        let old_msgs_total = old_meta
            .get("messages_total")
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        let planned_total = (work_items.len() + legacy_raws.len()) as i64;
        if opts.limit.is_none()
            && !has_legacy
            && old_msgs_total >= 50
            && planned_total.saturating_mul(2) < old_msgs_total
        {
            push_unique_warning(
                &mut warnings,
                format!("message_count_drop: {old_msgs_total} -> {planned_total}"),
            );
        }

        let db = Connection::open_with_flags(
            &work_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.execute_batch(
            "PRAGMA page_size = 4096; PRAGMA journal_mode = OFF; PRAGMA synchronous = OFF; \
             PRAGMA temp_store = FILE; PRAGMA cache_size = -32768;",
        )?;
        db.execute_batch(UNIVERSAL_SCHEMA_SQL)?;
        db.execute_batch("BEGIN IMMEDIATE;")?;

        let mut seen_hashes: HashSet<String> =
            HashSet::with_capacity(work_items.len() + legacy_raws.len() + 256);
        let mut seen_uids: HashSet<String> =
            HashSet::with_capacity(work_items.len() + legacy_raws.len() + 256);
        let mut thread_latest_amounts: HashSet<String> = HashSet::new();
        let mut thread_ctx: HashMap<String, ThreadCtx> = HashMap::new();

        {
            let mut st = InsertStmts::prepare(&db)?;
            let v10_ref = cfg.apple_mail_v10_dir.as_deref();

            for chunk in work_items.chunks(STREAM_BATCH_SIZE) {
                let batch: Vec<Option<EnrichedMsg>> = pool.install(|| {
                    chunk
                        .par_iter()
                        .map(|wi| {
                            match catch_unwind(AssertUnwindSafe(|| {
                                process_work_item(
                                    wi,
                                    v10_ref,
                                    &pack,
                                    &final_identity,
                                    &eml_truncated,
                                )
                            })) {
                                Ok(em) => Some(em),
                                Err(_) => {
                                    parse_errors.fetch_add(1, Ordering::Relaxed);
                                    None
                                }
                            }
                        })
                        .collect()
                });

                for em_opt in batch {
                    let Some(mut em) = em_opt else { continue };
                    if em.uid_key.is_empty() && em.subject.is_empty() && em.body_latest.is_empty() {
                        continue;
                    }
                    if !em.uid_key.is_empty() {
                        seen_uids.insert(em.uid_key.clone());
                    }
                    apply_thread_context_fallback(&mut em, &thread_ctx);
                    apply_quoted_amount_fallback(
                        &mut em,
                        &pack,
                        &final_identity,
                        &mut thread_latest_amounts,
                    );
                    update_thread_ctx(&em, &mut thread_ctx);
                    insert_one_message(&db, &mut st, &em, &mut seen_hashes, &mut cnt, &mut lex_hits)?;
                    cnt_msgs_total += 1;
                    if em.source == "apple_mail" {
                        cnt_am_msgs += 1;
                    } else if em.source == "eml" {
                        cnt_eml_msgs += 1;
                    }
                }
            }

            for chunk in legacy_raws.chunks(STREAM_BATCH_SIZE) {
                let batch: Vec<Option<EnrichedMsg>> = pool.install(|| {
                    chunk
                        .par_iter()
                        .map(|raw| {
                            match catch_unwind(AssertUnwindSafe(|| {
                                enrich_message(raw, &pack, &final_identity)
                            })) {
                                Ok(em) => Some(em),
                                Err(_) => {
                                    parse_errors.fetch_add(1, Ordering::Relaxed);
                                    None
                                }
                            }
                        })
                        .collect()
                });

                for em_opt in batch {
                    let Some(mut em) = em_opt else { continue };
                    if em.uid_key.is_empty() && em.subject.is_empty() && em.body_latest.is_empty() {
                        continue;
                    }
                    if !em.uid_key.is_empty() && !seen_uids.insert(em.uid_key.clone()) {
                        continue;
                    }
                    apply_thread_context_fallback(&mut em, &thread_ctx);
                    apply_quoted_amount_fallback(
                        &mut em,
                        &pack,
                        &final_identity,
                        &mut thread_latest_amounts,
                    );
                    update_thread_ctx(&em, &mut thread_ctx);
                    insert_one_message(&db, &mut st, &em, &mut seen_hashes, &mut cnt, &mut lex_hits)?;
                    cnt_msgs_total += 1;
                    if em.source == "apple_mail" {
                        cnt_am_msgs += 1;
                    } else if em.source == "eml" {
                        cnt_eml_msgs += 1;
                    } else {
                        cnt_legacy_msgs += 1;
                    }
                }
            }
        }
        drop(work_items);
        drop(legacy_raws);
        drop(seen_hashes);
        drop(seen_uids);
        drop(thread_latest_amounts);
        drop(thread_ctx);

        // Insert domain_lexicon rows with accumulated hit_counts
        {
            let mut st_lex = db.prepare(
                "INSERT OR REPLACE INTO domain_lexicon (pack_id, dimension, key, canonical_name, aliases, hit_count, metadata_json) \
                 VALUES (?,?,?,?,?,?,?)",
            )?;
            for lr in &pack.lexicon_rows {
                let hits = lex_hits
                    .get(&(lr.dimension.clone(), lr.key.clone()))
                    .copied()
                    .unwrap_or(0);
                st_lex.execute(rusqlite::params![
                    lr.pack_id,
                    lr.dimension,
                    lr.key,
                    lr.canonical_name,
                    lr.aliases,
                    hits,
                    lr.metadata_json,
                ])?;
            }
        }

        // Populate kb_meta
        {
            let mut st_meta =
                db.prepare("INSERT OR REPLACE INTO kb_meta (key, value) VALUES (?,?)")?;
            let sqlite_ver: String = db
                .query_row("SELECT sqlite_version()", [], |r| r.get(0))
                .unwrap_or_else(|_| rusqlite::version().to_string());
            let accts_json =
                serde_json::to_string(&discovered_accounts).unwrap_or_else(|_| "[]".to_string());
            let mut meta_rows: Vec<(&str, String)> = vec![
                ("schema_version", SCHEMA_VERSION.to_string()),
                ("rules_version", RULES_VERSION.to_string()),
                ("writer_version", ENGINE_VERSION.to_string()),
                ("writer_host", writer_host.clone()),
                ("writer_os", host_os().to_string()),
                ("writer_arch", host_arch().to_string()),
                ("sqlite_version", sqlite_ver),
                ("last_sync_iso", format_local_datetime(now_unix_secs())),
                ("pack_ids", pack.loaded_pack_ids.join(",")),
                ("rules_fingerprint", rules_fp.clone()),
                ("accounts_discovered", accts_json),
                ("cfg_account_filters", cfg_filters_str),
                ("cfg_eml_dirs", cfg_eml_dirs_str),
                ("inferred_self_emails", final_inferred.self_emails.join(",")),
                (
                    "inferred_internal_domains",
                    final_inferred.internal_domains.join(","),
                ),
                ("snap_eml_files", eml_snap),
                ("eml_count", eml_files.len().to_string()),
                ("messages_total", cnt_msgs_total.to_string()),
                ("apple_mail_messages", cnt_am_msgs.to_string()),
                ("eml_messages", cnt_eml_msgs.to_string()),
                ("legacy_import_messages", cnt_legacy_msgs.to_string()),
                ("attachments_total", cnt.attachments.to_string()),
                ("attachments_clean", cnt.att_clean.to_string()),
                ("attachments_noise", cnt.att_noise.to_string()),
                ("message_entities_count", cnt.entities.to_string()),
                ("message_amounts_count", cnt.amounts.to_string()),
                ("message_attachments_count", cnt.attachments.to_string()),
                (
                    "domain_lexicon_count",
                    pack.lexicon_rows.len().to_string(),
                ),
            ];
            if use_apple_mail {
                meta_rows.push(("apple_mail_max_rowid", cur_max_rowid.to_string()));
                meta_rows.push(("apple_mail_msg_rows", cur_msg_rows.to_string()));
                meta_rows.push((
                    "apple_mail_env_idx_size",
                    staged_env_info.idx_size.to_string(),
                ));
                meta_rows.push((
                    "apple_mail_env_idx_mtime",
                    staged_env_info.idx_mtime_ns.to_string(),
                ));
                meta_rows.push((
                    "apple_mail_env_wal_size",
                    staged_env_info.wal_size.to_string(),
                ));
                meta_rows.push((
                    "apple_mail_env_wal_mtime",
                    staged_env_info.wal_mtime_ns.to_string(),
                ));
            }
            for (k, v) in meta_rows {
                st_meta.execute(rusqlite::params![k, v])?;
            }
        }

        db.execute_batch(
            "COMMIT;\
             INSERT INTO messages_fts(messages_fts) VALUES('optimize');\
             INSERT INTO attachments_fts(attachments_fts) VALUES('optimize');\
             INSERT INTO dimensions_fts(dimensions_fts) VALUES('optimize');",
        )?;

        let freelist: i64 = db
            .query_row("PRAGMA freelist_count;", [], |r| r.get(0))
            .unwrap_or(0);
        if freelist != 0 {
            db.execute_batch("VACUUM;")?;
        }
    }

    let pub_res = publish_clean_sqlite(
        cfg,
        &work_path,
        &clean_path,
        cfg.primary_db_path(),
        DEFAULT_DB_STEM,
    )?;

    for w in pub_res.warnings {
        push_unique_warning(&mut warnings, w);
    }
    let perrs = parse_errors.load(Ordering::Relaxed);
    if perrs > 0 {
        push_unique_warning(&mut warnings, format!("parse_errors: {perrs}"));
    }
    let rss_bytes = get_peak_rss_bytes();
    let rss_mb = ((rss_bytes as f64 / (1024.0 * 1024.0)) * 100.0).round() / 100.0;
    let elapsed = (t0.elapsed().as_secs_f64() * 1000.0 * 100.0).round() / 100.0;

    Ok(json!({
        "status": "ok",
        "mode": mode_label,
        "schema_version": SCHEMA_VERSION,
        "writer_version": ENGINE_VERSION,
        "db_path": pub_res.db_path.display().to_string(),
        "db_bytes": pub_res.db_bytes,
        "db_modified": true,
        "sha256": pub_res.sha256,
        "sha256_sidecar": pub_res.sha256_path.display().to_string(),
        "journal_mode": pub_res.journal_mode,
        "quick_check": pub_res.quick_check,
        "runtime_db": pub_res.runtime_db.display().to_string(),
        "staging": if pub_res.runtime_updated { "fresh" } else { "stale" },
        "writer_host": writer_host,
        "pack_ids": pack.loaded_pack_ids,
        "accounts": discovered_accounts,
        "inferred_identity": {
            "self_emails": final_inferred.self_emails,
            "internal_domains": final_inferred.internal_domains,
        },
        "apple_mail_max_rowid": cur_max_rowid,
        "apple_mail_msg_rows": cur_msg_rows,
        "eml_total": eml_files.len(),
        "eml_truncated": eml_truncated.load(Ordering::Relaxed),
        "parse_errors": perrs,
        "messages_total": cnt_msgs_total,
        "messages_by_source": {
            "apple_mail": cnt_am_msgs,
            "eml": cnt_eml_msgs,
            "legacy_import": cnt_legacy_msgs,
        },
        "attachments_total": cnt.attachments,
        "attachments_clean": cnt.att_clean,
        "attachments_noise": cnt.att_noise,
        "message_entities_count": cnt.entities,
        "message_amounts_count": cnt.amounts,
        "message_attachments_count": cnt.attachments,
        "domain_lexicon_count": pack.lexicon_rows.len(),
        "threads": cfg.max_threads,
        "peak_rss_bytes": rss_bytes,
        "peak_rss_mb": rss_mb,
        "warnings": warnings,
        "elapsed_ms": elapsed,
    }))
}
