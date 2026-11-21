//! Staged read-only SQLite connection helpers, warning collection, JSON conversion,
//! and S10 path remapping for `mailkb-query`.

use mailkb_core::config::{MailKbConfig, DEFAULT_DB_STEM};
use mailkb_core::error::{KbError, KbResult};
use mailkb_core::security::{
    assert_not_in_mail_container, remap_relpath, safe_relpath, sanitize_utf8,
};
use mailkb_core::staging::{
    open_staged_ro, stage_primary_db, StageInfo, DEFAULT_MMAP_BYTES,
};
use rusqlite::types::ValueRef;
use rusqlite::{params_from_iter, Connection, Row, Statement, ToSql};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Ordered, deduplicated warning accumulator.
#[derive(Debug, Default, Clone)]
pub struct WarningBag {
    items: Vec<String>,
}

impl WarningBag {
    pub fn from_stage(stage: &StageInfo) -> Self {
        let mut bag = Self::default();
        for w in &stage.warnings {
            bag.push(w.clone());
        }
        bag
    }

    pub fn push(&mut self, w: impl Into<String>) {
        let s = w.into();
        if !s.is_empty() && !self.items.iter().any(|existing| existing == &s) {
            self.items.push(s);
        }
    }

    pub fn extend(&mut self, iter: impl IntoIterator<Item = String>) {
        for w in iter {
            self.push(w);
        }
    }

    pub fn as_slice(&self) -> &[String] {
        &self.items
    }

    pub fn to_json_array(&self) -> Value {
        Value::Array(self.items.iter().cloned().map(Value::String).collect())
    }
}

/// Checks S9 container guard on `runtime_dir` and the resolved `runtime_db` slot.
pub fn check_runtime_s9(cfg: &MailKbConfig) -> KbResult<()> {
    let runtime_db = cfg.runtime_db_for_path(DEFAULT_DB_STEM, cfg.primary_db_path());
    assert_not_in_mail_container(cfg, &cfg.runtime_dir)?;
    assert_not_in_mail_container(cfg, &runtime_db)?;
    Ok(())
}

/// Stages `cfg.primary_db_path()` into `cfg.runtime_dir` (never opening cold DB directly),
/// opens the staged snapshot in immutable read-only mode (`?mode=ro&immutable=1`),
/// and verifies the `1.0-universal` core tables exist.
pub fn stage_and_open(cfg: &MailKbConfig) -> KbResult<(StageInfo, Connection, WarningBag)> {
    check_runtime_s9(cfg)?;
    let stage = stage_primary_db(cfg)?;
    let conn = open_staged_worker(&stage.runtime_db)?;
    let cnt: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master \
         WHERE type='table' AND name IN ('kb_meta', 'mail_messages', 'message_entities', 'message_amounts', 'message_attachments')",
        [],
        |r| r.get(0),
    )?;
    if cnt != 5 {
        return Err(KbError::Staging(format!(
            "runtime snapshot {} lacks 1.0-universal schema (found {cnt}/5 core tables)",
            stage.runtime_db.display()
        )));
    }
    let warnings = WarningBag::from_stage(&stage);
    Ok((stage, conn, warnings))
}

/// Opens an already-staged runtime SQLite snapshot with `2 GiB` mmap, `128 MiB` cache,
/// `temp_store = MEMORY`, and `query_only = ON`.
pub fn open_staged_worker(runtime_db: &Path) -> KbResult<Connection> {
    open_staged_ro(runtime_db, DEFAULT_MMAP_BYTES)
}

/// Inserts standard runtime metadata fields (`source_db`, `runtime_db`, `staging`, `warnings`).
pub fn attach_runtime_fields(
    map: &mut Map<String, Value>,
    stage: &StageInfo,
    warnings: &WarningBag,
) {
    map.insert(
        "source_db".to_string(),
        Value::String(stage.source_db.to_string_lossy().into_owned()),
    );
    map.insert(
        "runtime_db".to_string(),
        Value::String(stage.runtime_db.to_string_lossy().into_owned()),
    );
    map.insert(
        "staging".to_string(),
        Value::String(stage.staging.as_str().to_string()),
    );
    map.insert("warnings".to_string(), warnings.to_json_array());
}

/// Inserts standard fallback runtime metadata fields when no DB was staged (e.g. audit).
pub fn attach_unopened_runtime_fields(
    map: &mut Map<String, Value>,
    cfg: &MailKbConfig,
    staging_label: &str,
    warnings: &WarningBag,
) {
    let runtime_db = cfg.runtime_db_for_path(DEFAULT_DB_STEM, cfg.primary_db_path());
    map.insert(
        "source_db".to_string(),
        Value::String(cfg.primary_db_path().to_string_lossy().into_owned()),
    );
    map.insert(
        "runtime_db".to_string(),
        Value::String(runtime_db.to_string_lossy().into_owned()),
    );
    map.insert(
        "staging".to_string(),
        Value::String(staging_label.to_string()),
    );
    map.insert("warnings".to_string(), warnings.to_json_array());
}

/// Returns elapsed milliseconds rounded to 2 decimal places.
pub fn elapsed_ms(t0: Instant) -> f64 {
    let ms = t0.elapsed().as_secs_f64() * 1000.0;
    (ms * 100.0).round() / 100.0
}

/// S10-safe attachment path resolution result.
#[derive(Debug, Clone, Default)]
pub struct AttachmentPathInfo {
    pub local_path: Option<String>,
    pub container_path: Option<String>,
    pub local_exists: bool,
    pub path_rejected: bool,
}

/// Resolves `message_attachments.storage_relpath` safely under S10.
/// Handles both disk attachment paths (`<account_id>/<mbox>/.../Attachments/...`)
/// and inline MIME part references (`<rel_path>#part<idx>` or `am:<rowid>#part<idx>`).
pub fn resolve_attachment_path(
    cfg: &MailKbConfig,
    stored: &str,
    account_id: Option<&str>,
) -> AttachmentPathInfo {
    let trimmed = stored.trim();
    if trimmed.is_empty() {
        return AttachmentPathInfo::default();
    }

    if let Some((base, part_sfx)) = trimmed.rsplit_once("#part") {
        if !part_sfx.is_empty() && part_sfx.bytes().all(|b| b.is_ascii_digit()) {
            if base.starts_with("am:") {
                return AttachmentPathInfo::default();
            }
            let (container_path, rejected) = remap_stored_path(cfg, base, account_id);
            return AttachmentPathInfo {
                local_path: None,
                container_path,
                local_exists: false,
                path_rejected: rejected,
            };
        }
    }

    let (local_path, rejected) = remap_stored_path(cfg, trimmed, account_id);
    let local_exists = local_path
        .as_deref()
        .is_some_and(|p| Path::new(p).is_file());
    AttachmentPathInfo {
        local_path,
        container_path: None,
        local_exists,
        path_rejected: rejected,
    }
}

/// S10-safe remapping of a stored relative path against configured local roots.
/// Returns `(resolved_path, path_rejected)`.
pub fn remap_stored_path(
    cfg: &MailKbConfig,
    stored: &str,
    account_id: Option<&str>,
) -> (Option<String>, bool) {
    let trimmed = stored.trim();
    if trimmed.is_empty() {
        return (None, false);
    }
    if !safe_relpath(trimmed) {
        return (None, true);
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    for dir in &cfg.eml_dirs {
        if let Ok(p) = remap_relpath(trimmed, dir) {
            candidates.push(p);
        }
    }
    if let Some(ref v10) = cfg.apple_mail_v10_dir {
        if let Ok(p) = remap_relpath(trimmed, v10) {
            candidates.push(p);
        }
        if let Some(acct) = account_id.map(str::trim).filter(|s| !s.is_empty()) {
            if safe_relpath(acct) && !acct.contains('/') {
                if let Ok(p) = remap_relpath(trimmed, &v10.join(acct)) {
                    candidates.push(p);
                }
            }
        }
    }
    if let Ok(p) = remap_relpath(trimmed, &cfg.db_dir) {
        candidates.push(p);
    }

    for cand in &candidates {
        if cand.is_file() {
            return (Some(cand.to_string_lossy().into_owned()), false);
        }
    }

    if trimmed.contains(".mbox/") {
        if let Some(ref v10) = cfg.apple_mail_v10_dir {
            if let Ok(p) = remap_relpath(trimmed, v10) {
                if let Some(acct) = account_id.map(str::trim).filter(|s| !s.is_empty()) {
                    if !trimmed.starts_with(acct) && safe_relpath(acct) && !acct.contains('/') {
                        if let Ok(p2) = remap_relpath(trimmed, &v10.join(acct)) {
                            return (Some(p2.to_string_lossy().into_owned()), false);
                        }
                    }
                }
                return (Some(p.to_string_lossy().into_owned()), false);
            }
        }
    }

    if let Some(first) = candidates.into_iter().next() {
        (Some(first.to_string_lossy().into_owned()), false)
    } else {
        (None, false)
    }
}

/// Converts a SQLite column value to `serde_json::Value`, sanitizing UTF-8.
pub fn col_to_value(row: &Row<'_>, idx: usize) -> rusqlite::Result<Value> {
    match row.get_ref(idx)? {
        ValueRef::Null => Ok(Value::Null),
        ValueRef::Integer(i) => Ok(Value::Number(i.into())),
        ValueRef::Real(f) => {
            if !f.is_finite() {
                Ok(Value::Null)
            } else {
                Ok(serde_json::Number::from_f64(f)
                    .map(Value::Number)
                    .unwrap_or(Value::Null))
            }
        }
        ValueRef::Text(b) | ValueRef::Blob(b) => Ok(Value::String(sanitize_utf8(b))),
    }
}

/// Converts an entire SQLite row into a `serde_json::Map<String, Value>`.
pub fn row_to_map(stmt: &Statement<'_>, row: &Row<'_>) -> rusqlite::Result<Map<String, Value>> {
    let n = stmt.column_count();
    let mut map = Map::with_capacity(n);
    for i in 0..n {
        let cname = stmt.column_name(i).unwrap_or("").to_string();
        map.insert(cname, col_to_value(row, i)?);
    }
    Ok(map)
}

/// Executes a parameterized SQL query and collects each row as `Value::Object`.
pub fn query_rows_json(
    conn: &Connection,
    sql: &str,
    str_params: &[String],
    limit: Option<i64>,
) -> KbResult<Vec<Value>> {
    let mut stmt = conn.prepare(sql)?;
    let mut bind_vals: Vec<&dyn ToSql> = Vec::with_capacity(str_params.len() + 1);
    for s in str_params {
        bind_vals.push(s);
    }
    if let Some(ref lim) = limit {
        bind_vals.push(lim);
    }
    let mut out = Vec::new();
    let mut rows = stmt.query(params_from_iter(bind_vals))?;
    while let Some(row) = rows.next()? {
        out.push(Value::Object(row_to_map(row.as_ref(), row)?));
    }
    Ok(out)
}

/// Reads a single scalar `i64` from SQL.
pub fn query_scalar_i64(conn: &Connection, sql: &str) -> KbResult<i64> {
    let v: i64 = conn.query_row(sql, [], |r| r.get(0))?;
    Ok(v)
}

/// Reads a single scalar `String` from SQL.
pub fn query_scalar_str(conn: &Connection, sql: &str) -> KbResult<String> {
    let v: String = conn.query_row(sql, [], |r| match r.get_ref(0)? {
        ValueRef::Null => Ok(String::new()),
        ValueRef::Text(b) | ValueRef::Blob(b) => Ok(sanitize_utf8(b)),
        ValueRef::Integer(i) => Ok(i.to_string()),
        ValueRef::Real(f) => Ok(f.to_string()),
    })?;
    Ok(v)
}

/// Reads a key from `kb_meta`, returning `""` if missing.
pub fn kb_meta_value(conn: &Connection, key: &str) -> KbResult<String> {
    let mut stmt = conn.prepare("SELECT value FROM kb_meta WHERE key = ?")?;
    let mut rows = stmt.query([key])?;
    if let Some(row) = rows.next()? {
        match row.get_ref(0)? {
            ValueRef::Text(b) | ValueRef::Blob(b) => Ok(sanitize_utf8(b)),
            ValueRef::Integer(i) => Ok(i.to_string()),
            ValueRef::Real(f) => Ok(f.to_string()),
            ValueRef::Null => Ok(String::new()),
        }
    } else {
        Ok(String::new())
    }
}

/// Reads all key/value pairs from `kb_meta`.
pub fn kb_meta_all(conn: &Connection) -> KbResult<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let mut stmt = conn.prepare("SELECT key, value FROM kb_meta ORDER BY key ASC")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let k: String = match row.get_ref(0)? {
            ValueRef::Text(b) | ValueRef::Blob(b) => sanitize_utf8(b),
            ValueRef::Integer(i) => i.to_string(),
            ValueRef::Real(f) => f.to_string(),
            ValueRef::Null => String::new(),
        };
        let v: String = match row.get_ref(1)? {
            ValueRef::Text(b) | ValueRef::Blob(b) => sanitize_utf8(b),
            ValueRef::Integer(i) => i.to_string(),
            ValueRef::Real(f) => f.to_string(),
            ValueRef::Null => String::new(),
        };
        if !k.is_empty() {
            out.insert(k, v);
        }
    }
    Ok(out)
}
