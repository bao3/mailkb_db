//! Safety/integrity audit (`run_audit`) and self-verification (`run_selftest`)
//! for `mailkb-query`.

use crate::db::{attach_unopened_runtime_fields, elapsed_ms, WarningBag};
use mailkb_core::config::{MailKbConfig, DEFAULT_DB_FILENAME, DEFAULT_DB_STEM};
use mailkb_core::domain_pack::{validate_pack_file, CompiledDomainPack, DomainPack};
use mailkb_core::error::{KbError, KbResult};
use mailkb_core::fts::{build_cjk_bigram_fts_query, tokenize_for_fts};
use mailkb_core::ooxml::{extract_xlsx_from_bytes, OoxmlOptions};
use mailkb_core::publish::{publish_clean_sqlite, sha256_bytes, sha256_file, TempBuildDir};
use mailkb_core::security::{
    assert_not_in_mail_container, assert_safe_out_path, open_readonly_nofollow, remap_relpath,
    safe_relpath, sanitize_utf8, term_safe,
};
use mailkb_core::staging::{
    check_sqlite_header, open_staged_ro, parse_stamp, quick_check_snapshot, read_sidecar_sha256,
    sidecar_path_for, stage_primary_db, stamp_path_for, DEFAULT_MMAP_BYTES,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions, Permissions};
use std::io::{self, Cursor, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::Instant;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
const SCHEMA_VERSION: &str = "1.0-universal";

/// Host capability state for reading the local macOS Apple Mail store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterState {
    Master,
    NotMaster(String),
    AccessDenied(String),
}

pub fn host_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        std::env::consts::OS
    }
}

pub fn host_arch() -> &'static str {
    if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        std::env::consts::ARCH
    }
}

/// Checks whether the current host has readable access to Apple Mail `Envelope Index`
/// and account directories (strictly read-only).
pub fn mail_master_state(cfg: &MailKbConfig) -> MasterState {
    let Some(ref v10_dir) = cfg.apple_mail_v10_dir else {
        return MasterState::NotMaster(format!(
            "no Apple Mail store configured on host ({})",
            host_os()
        ));
    };

    let env_idx = v10_dir.join("MailData/Envelope Index");
    let is_denied = |e: &io::Error| e.kind() == io::ErrorKind::PermissionDenied;

    match fs::metadata(&env_idx) {
        Err(e) if is_denied(&e) => {
            return MasterState::AccessDenied(format!(
                "mail_access_denied (grant Full Disk Access): {}",
                env_idx.display()
            ));
        }
        Err(_) => {
            return MasterState::NotMaster(format!(
                "Envelope Index missing: {}",
                env_idx.display()
            ));
        }
        Ok(meta) if !meta.is_file() => {
            return MasterState::NotMaster(format!(
                "Envelope Index is not regular file: {}",
                env_idx.display()
            ));
        }
        Ok(_) => {}
    }

    match open_readonly_nofollow(&env_idx) {
        Ok(f) => drop(f),
        Err(KbError::Io(e)) if is_denied(&e) => {
            return MasterState::AccessDenied(format!(
                "mail_access_denied (grant Full Disk Access): {e}"
            ));
        }
        Err(e) => {
            return MasterState::NotMaster(format!("cannot open Envelope Index: {e}"));
        }
    }

    match fs::read_dir(v10_dir) {
        Ok(_) => MasterState::Master,
        Err(e) if is_denied(&e) => MasterState::AccessDenied(format!(
            "mail_access_denied (grant Full Disk Access): opendir V10: {e}"
        )),
        Err(e) => MasterState::NotMaster(format!("cannot read V10 dir: {e}")),
    }
}

fn check_entry(name: &str, ok: bool, detail: impl Into<String>, severity: &str) -> Value {
    json!({
        "name": name,
        "ok": ok,
        "severity": severity,
        "detail": detail.into(),
    })
}

/// Runs read-only safety & integrity audit:
/// - S9 container checks
/// - Cold DB & `.sha256` sidecar checksum verification
/// - Runtime cache `.stamp` / checksum / `quick_check` verification
/// - Apple Mail container & multi-account readiness
/// - Configured `--eml-dir` and Domain Pack validation
pub fn run_audit_impl(cfg: &MailKbConfig) -> KbResult<Value> {
    let t0 = Instant::now();
    let mut warnings = WarningBag::default();
    let mut checks: Vec<Value> = Vec::new();
    let mut has_error = false;
    let mut has_warn = false;

    // 1. S9 container guards on configured paths + negative probes
    let runtime_db = cfg.runtime_db_for_path(DEFAULT_DB_STEM, cfg.primary_db_path());
    let s9_targets = [
        ("db_dir", cfg.db_dir.as_path()),
        ("db_path", cfg.db_path.as_path()),
        ("runtime_dir", cfg.runtime_dir.as_path()),
        ("runtime_db", runtime_db.as_path()),
        ("packs_dir", cfg.packs_dir.as_path()),
    ];
    let mut s9_bad = Vec::new();
    for (label, p) in s9_targets {
        if let Err(e) = assert_not_in_mail_container(cfg, p) {
            s9_bad.push(format!("{label}: {e}"));
        }
    }
    let home = std::env::var("HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/nonexistent-home".to_string());
    let s9_blocks_ok = assert_not_in_mail_container(cfg, Path::new(&format!("{home}/Library/Mail/V10/x")))
        .is_err()
        && assert_not_in_mail_container(
            cfg,
            Path::new(&format!("{home}/Library/Group Containers/UBF8T346G9.Office/x")),
        )
        .is_err()
        && assert_not_in_mail_container(cfg, Path::new(&format!("{home}/Library/Thunderbird/Profiles")))
            .is_err();

    let s9_ok = s9_bad.is_empty() && s9_blocks_ok;
    if !s9_ok {
        has_error = true;
    }
    checks.push(check_entry(
        "s9_container_guards",
        s9_ok,
        if s9_ok {
            "all configured paths outside mail containers and protected containers blocked"
                .to_string()
        } else {
            format!("S9 guard failure: {}", s9_bad.join("; "))
        },
        if s9_ok { "pass" } else { "error" },
    ));

    // 2. Cold DB & sidecar sha256 verification
    let cold_path = cfg.primary_db_path();
    let sidecar_path = sidecar_path_for(cold_path);
    let mut cold_sha256: Option<String> = None;
    let sidecar_sha256: Option<String> = read_sidecar_sha256(&sidecar_path);
    let mut cold_exists = false;
    let mut cold_header_ok = false;
    let mut cold_checksum_match: Option<bool> = None;

    match fs::symlink_metadata(cold_path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                has_error = true;
                checks.push(check_entry(
                    "cold_db_header",
                    false,
                    format!("cold DB is symlink or non-regular file: {}", cold_path.display()),
                    "error",
                ));
            } else {
                cold_exists = true;
                match check_sqlite_header(cold_path) {
                    Ok(()) => {
                        cold_header_ok = true;
                        checks.push(check_entry(
                            "cold_db_header",
                            true,
                            format!("DELETE-mode SQLite header ok ({} bytes)", meta.len()),
                            "pass",
                        ));
                    }
                    Err(e) => {
                        has_error = true;
                        checks.push(check_entry(
                            "cold_db_header",
                            false,
                            format!("invalid cold DB header: {e}"),
                            "error",
                        ));
                    }
                }
                match sha256_file(cold_path) {
                    Ok(hex) => {
                        cold_sha256 = Some(hex.clone());
                        if let Some(ref sc) = sidecar_sha256 {
                            let matched = &hex == sc;
                            cold_checksum_match = Some(matched);
                            if !matched {
                                has_error = true;
                                warnings.push("cold_db_sidecar_sha256_mismatch");
                            }
                            checks.push(check_entry(
                                "cold_db_sidecar_sha256",
                                matched,
                                if matched {
                                    format!("sha256 verified ({})", &hex[..12])
                                } else {
                                    format!("sha256 mismatch: file={} sidecar={}", &hex[..12], &sc[..12])
                                },
                                if matched { "pass" } else { "error" },
                            ));
                        } else {
                            has_warn = true;
                            warnings.push("cold_db_sidecar_missing");
                            checks.push(check_entry(
                                "cold_db_sidecar_sha256",
                                false,
                                format!("sidecar missing or malformed: {}", sidecar_path.display()),
                                "warn",
                            ));
                        }
                    }
                    Err(e) => {
                        has_error = true;
                        checks.push(check_entry(
                            "cold_db_sidecar_sha256",
                            false,
                            format!("failed hashing cold DB: {e}"),
                            "error",
                        ));
                    }
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            has_warn = true;
            warnings.push("cold_db_missing");
            checks.push(check_entry(
                "cold_db_header",
                false,
                format!("cold DB not yet built: {}", cold_path.display()),
                "warn",
            ));
        }
        Err(e) => {
            has_error = true;
            checks.push(check_entry(
                "cold_db_header",
                false,
                format!("failed stat on cold DB: {e}"),
                "error",
            ));
        }
    }

    // 3. Runtime cache directory & snapshot integrity
    let stamp_path = stamp_path_for(&runtime_db);
    let mut rt_exists = false;
    let mut rt_sha256: Option<String> = None;
    let mut rt_quick_check_ok = false;
    let mut rt_stamp_match: Option<bool> = None;

    let rt_dir_info = match fs::symlink_metadata(&cfg.runtime_dir) {
        Ok(m) => {
            let euid = unsafe { libc::geteuid() };
            let dir_ok = !m.file_type().is_symlink()
                && m.is_dir()
                && m.uid() == euid
                && (m.mode() & 0o077) == 0;
            if !dir_ok {
                has_error = true;
            }
            checks.push(check_entry(
                "runtime_dir_s13",
                dir_ok,
                format!(
                    "mode={:04o} uid={} dir={}",
                    m.mode() & 0o7777,
                    m.uid(),
                    cfg.runtime_dir.display()
                ),
                if dir_ok { "pass" } else { "error" },
            ));
            dir_ok
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            has_warn = true;
            checks.push(check_entry(
                "runtime_dir_s13",
                false,
                format!("runtime_dir does not exist yet: {}", cfg.runtime_dir.display()),
                "warn",
            ));
            false
        }
        Err(e) => {
            has_error = true;
            checks.push(check_entry(
                "runtime_dir_s13",
                false,
                format!("runtime_dir stat failed: {e}"),
                "error",
            ));
            false
        }
    };

    if rt_dir_info {
        match fs::symlink_metadata(&runtime_db) {
            Ok(meta) if !meta.file_type().is_symlink() && meta.is_file() => {
                rt_exists = true;
                let hdr_ok = check_sqlite_header(&runtime_db).is_ok();
                let qc_ok = hdr_ok && quick_check_snapshot(&runtime_db).is_ok();
                rt_quick_check_ok = qc_ok;
                if !qc_ok {
                    has_error = true;
                    warnings.push("runtime_db_quick_check_failed");
                }
                if let Ok(hex) = sha256_file(&runtime_db) {
                    rt_sha256 = Some(hex.clone());
                    if let Some(ref cold_hex) = cold_sha256 {
                        let same = &hex == cold_hex;
                        if !same {
                            has_warn = true;
                            warnings.push("runtime_db_differs_from_cold_db");
                        }
                        checks.push(check_entry(
                            "runtime_db_checksum",
                            same,
                            if same {
                                format!("runtime sha256 matches cold DB ({})", &hex[..12])
                            } else {
                                format!(
                                    "runtime sha256 ({}) != cold DB ({}) (stale cache)",
                                    &hex[..12],
                                    &cold_hex[..12]
                                )
                            },
                            if same { "pass" } else { "warn" },
                        ));
                    }
                }
                if let Ok(stamp_raw) = fs::read_to_string(&stamp_path) {
                    if let Some((sz, mt, ino, sc)) = parse_stamp(&stamp_raw) {
                        if let Ok(cmeta) = fs::metadata(cold_path) {
                            let cmt = cmeta
                                .mtime()
                                .saturating_mul(1_000_000_000)
                                .saturating_add(cmeta.mtime_nsec());
                            let csc = sidecar_sha256.as_deref().unwrap_or("-");
                            let ok = (sz, mt, ino, sc.as_str()) == (cmeta.len(), cmt, cmeta.ino(), csc);
                            rt_stamp_match = Some(ok);
                        }
                    }
                }
                checks.push(check_entry(
                    "runtime_db_quick_check",
                    qc_ok,
                    if qc_ok {
                        format!("runtime SQLite DELETE-mode + quick_check ok ({} bytes)", meta.len())
                    } else {
                        "runtime SQLite header or PRAGMA quick_check failed".to_string()
                    },
                    if qc_ok { "pass" } else { "error" },
                ));
            }
            Ok(_) => {
                has_error = true;
                checks.push(check_entry(
                    "runtime_db_quick_check",
                    false,
                    format!("runtime_db is symlink or non-regular file: {}", runtime_db.display()),
                    "error",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                has_warn = true;
                checks.push(check_entry(
                    "runtime_db_quick_check",
                    false,
                    format!("runtime snapshot not staged yet: {}", runtime_db.display()),
                    "warn",
                ));
            }
            Err(e) => {
                has_error = true;
                checks.push(check_entry(
                    "runtime_db_quick_check",
                    false,
                    format!("runtime_db stat failed: {e}"),
                    "error",
                ));
            }
        }
    }

    // 4. Apple Mail container readiness (strictly read-only; copies Envelope Index to TempBuildDir if Master)
    let mut apple_mail_info = Map::new();
    let master_state = mail_master_state(cfg);
    match &master_state {
        MasterState::Master => {
            apple_mail_info.insert("state".to_string(), json!("master"));
            if let Some(ref v10_dir) = cfg.apple_mail_v10_dir {
                apple_mail_info.insert("v10_dir".to_string(), json!(v10_dir.to_string_lossy()));
                match inspect_apple_mail_accounts(cfg, v10_dir) {
                    Ok(summary) => {
                        apple_mail_info.insert("accounts".to_string(), summary);
                        checks.push(check_entry(
                            "apple_mail_readiness",
                            true,
                            "Envelope Index readable; multi-account mailboxes inspected read-only",
                            "pass",
                        ));
                    }
                    Err(e) => {
                        has_warn = true;
                        warnings.push(format!("apple_mail_inspect_warn: {e}"));
                        checks.push(check_entry(
                            "apple_mail_readiness",
                            false,
                            format!("Envelope Index inspection warning: {e}"),
                            "warn",
                        ));
                    }
                }
            }
        }
        MasterState::AccessDenied(why) => {
            has_warn = true;
            warnings.push("apple_mail_access_denied");
            apple_mail_info.insert("state".to_string(), json!("access_denied"));
            apple_mail_info.insert("reason".to_string(), json!(why));
            checks.push(check_entry("apple_mail_readiness", false, why.clone(), "warn"));
        }
        MasterState::NotMaster(why) => {
            apple_mail_info.insert("state".to_string(), json!("not_master"));
            apple_mail_info.insert("reason".to_string(), json!(why));
            checks.push(check_entry("apple_mail_readiness", true, why.clone(), "info"));
        }
    }

    // 5. Standalone --eml-dir readability
    let mut eml_checks = Vec::new();
    for dir in &cfg.eml_dirs {
        let readable = dir.is_dir() && fs::read_dir(dir).is_ok();
        if !readable {
            has_warn = true;
            warnings.push(format!("eml_dir_unreadable: {}", dir.display()));
        }
        eml_checks.push(json!({
            "path": dir.to_string_lossy(),
            "readable": readable,
        }));
    }

    // 6. Domain pack validation
    let mut pack_reports = Vec::new();
    if !cfg.no_packs {
        for p in &cfg.pack_paths {
            match validate_pack_file(p) {
                Ok(rep) => pack_reports.push(json!({
                    "path": p.to_string_lossy(),
                    "valid": true,
                    "pack_id": rep.pack_id,
                    "version": rep.version,
                    "sha256": rep.sha256,
                    "pattern_count": rep.pattern_count,
                    "warnings": rep.warnings,
                })),
                Err(e) => {
                    has_error = true;
                    warnings.push(format!("invalid_pack: {}", p.display()));
                    pack_reports.push(json!({
                        "path": p.to_string_lossy(),
                        "valid": false,
                        "error": e.to_string(),
                    }));
                }
            }
        }
    }
    let packs_all_valid = pack_reports
        .iter()
        .all(|v| v.get("valid").and_then(Value::as_bool).unwrap_or(false));
    checks.push(check_entry(
        "domain_packs",
        packs_all_valid,
        if cfg.no_packs {
            "universal mode (--no-packs)".to_string()
        } else {
            format!("{} pack(s) checked", pack_reports.len())
        },
        if packs_all_valid { "pass" } else { "error" },
    ));

    let status = if has_error {
        "error"
    } else if has_warn {
        "warn"
    } else {
        "ok"
    };

    let ms = elapsed_ms(t0);
    let mut out = Map::new();
    out.insert("status".to_string(), Value::String(status.to_string()));
    out.insert(
        "schema_version".to_string(),
        Value::String(SCHEMA_VERSION.to_string()),
    );
    out.insert(
        "host".to_string(),
        Value::String(format!("{}-{}", host_os(), host_arch())),
    );
    attach_unopened_runtime_fields(&mut out, cfg, "audit", &warnings);
    out.insert("elapsed_ms".to_string(), json!(ms));
    out.insert(
        "cold_db".to_string(),
        json!({
            "exists": cold_exists,
            "header_ok": cold_header_ok,
            "sha256": cold_sha256,
            "sidecar_sha256": sidecar_sha256,
            "checksum_match": cold_checksum_match,
        }),
    );
    out.insert(
        "runtime_cache".to_string(),
        json!({
            "exists": rt_exists,
            "quick_check_ok": rt_quick_check_ok,
            "sha256": rt_sha256,
            "stamp_match": rt_stamp_match,
        }),
    );
    out.insert("apple_mail".to_string(), Value::Object(apple_mail_info));
    out.insert("eml_dirs".to_string(), Value::Array(eml_checks));
    out.insert(
        "domain_packs".to_string(),
        json!({
            "no_packs": cfg.no_packs,
            "packs": pack_reports,
        }),
    );
    out.insert("checks".to_string(), Value::Array(checks.clone()));
    out.insert("results".to_string(), Value::Array(checks));
    let _ = sidecar_sha256;
    Ok(Value::Object(out))
}

fn inspect_apple_mail_accounts(cfg: &MailKbConfig, v10_dir: &Path) -> KbResult<Value> {
    let bg = TempBuildDir::new(cfg, "mailkb-audit-")?;
    let env_dir = bg.path().join("env");
    fs::create_dir_all(&env_dir)?;
    fs::set_permissions(&env_dir, Permissions::from_mode(0o700))?;

    let mail_data = v10_dir.join("MailData");
    for fname in ["Envelope Index", "Envelope Index-wal", "Envelope Index-shm"] {
        let src = mail_data.join(fname);
        let Ok(meta) = fs::symlink_metadata(&src) else {
            if fname == "Envelope Index" {
                return Err(KbError::NotFound(format!("missing {}", src.display())));
            }
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            continue;
        }
        let mut in_f = open_readonly_nofollow(&src)?;
        let dst = env_dir.join(fname);
        let mut out_f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&dst)?;
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
    }

    let env_cp = env_dir.join("Envelope Index");
    let edb = Connection::open_with_flags(
        &env_cp,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    #[derive(Default)]
    struct AcctStat {
        scheme: String,
        mailbox_count: i64,
        message_count: i64,
        dir_readable: bool,
    }
    let mut by_acct: BTreeMap<String, AcctStat> = BTreeMap::new();
    let mut mb_schemes: BTreeMap<i64, (String, String)> = BTreeMap::new();

    {
        let mut stmt = edb.prepare("SELECT ROWID, url FROM mailboxes")?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let rowid: i64 = r.get(0)?;
            let url: String = r.get(1)?;
            if let Some((scheme, rest)) = url.split_once("://") {
                let acct = rest.split('/').next().unwrap_or("").to_string();
                if acct.is_empty() {
                    continue;
                }
                let entry = by_acct.entry(acct.clone()).or_insert_with(|| AcctStat {
                    scheme: scheme.to_string(),
                    mailbox_count: 0,
                    message_count: 0,
                    dir_readable: fs::read_dir(v10_dir.join(&acct)).is_ok(),
                });
                entry.mailbox_count += 1;
                mb_schemes.insert(rowid, (scheme.to_string(), acct));
            }
        }
    }

    {
        let mut stmt = edb.prepare(
            "SELECT mailbox, COUNT(*) FROM messages WHERE COALESCE(deleted, 0) = 0 GROUP BY mailbox",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(r) = rows.next()? {
            let mb: i64 = r.get(0)?;
            let cnt: i64 = r.get(1)?;
            if let Some((_, acct)) = mb_schemes.get(&mb) {
                if let Some(st) = by_acct.get_mut(acct) {
                    st.message_count += cnt;
                }
            }
        }
    }

    let filter_set: BTreeSet<String> = cfg
        .account_filters
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect();
    let list: Vec<Value> = by_acct
        .into_iter()
        .map(|(acct, st)| {
            let included = filter_set.is_empty()
                || filter_set.iter().any(|f| acct.to_ascii_lowercase().contains(f));
            json!({
                "account_id": acct,
                "scheme": st.scheme,
                "mailbox_count": st.mailbox_count,
                "message_count": st.message_count,
                "dir_readable": st.dir_readable,
                "selected": included,
            })
        })
        .collect();
    Ok(Value::Array(list))
}

/// Runs in-memory & TempDir `1.0-universal` + FTS5 + `MiniRegex`/DomainPack + S9/S10/S11/OOXML self-test.
pub fn run_selftest_impl(cfg: &MailKbConfig, pack_sample: Option<&Path>) -> KbResult<Value> {
    let t0 = Instant::now();
    let mut checks: Vec<Value> = Vec::new();

    // 1. SHA-256 FIPS 180-4 vectors
    let million_a = vec![b'a'; 1_000_000];
    let sha_ok = sha256_bytes(b"")
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        && sha256_bytes(b"abc")
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        && sha256_bytes(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
            == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        && sha256_bytes(&million_a)
            == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    checks.push(check_entry(
        "sha256_fips180_4",
        sha_ok,
        "empty, abc, 448-bit, and 1M-byte SHA-256 vectors",
        if sha_ok { "pass" } else { "error" },
    ));

    // 2. SQLite FTS5 & threadsafe
    let (fts5_ok, ts_ok) = check_sqlite_fts5_and_threadsafe();
    checks.push(check_entry(
        "sqlite_fts5_and_threadsafe",
        fts5_ok && ts_ok,
        format!("ENABLE_FTS5={fts5_ok}, sqlite3_threadsafe={ts_ok}"),
        if fts5_ok && ts_ok { "pass" } else { "error" },
    ));

    // 3. TempDir 1.0-universal SQLite + publish + stage + FTS5 + json_extract roundtrip
    let (schema_ok, schema_detail) = check_universal_tempdb_roundtrip(cfg);
    checks.push(check_entry(
        "universal_1_0_schema_staging_fts",
        schema_ok,
        schema_detail,
        if schema_ok { "pass" } else { "error" },
    ));

    // 4. Security guards (S9/S10/S11)
    let sec_ok = check_security_guards(cfg);
    checks.push(check_entry(
        "security_guards_s9_s10_s11",
        sec_ok,
        "S9 container guards, S10 path traversal rejection, S11 ANSI/OSC sanitization",
        if sec_ok { "pass" } else { "error" },
    ));

    // 5. Pure-Rust OOXML .xlsx
    let ooxml_ok = check_pure_rust_ooxml();
    checks.push(check_entry(
        "pure_rust_ooxml_xlsx",
        ooxml_ok,
        "bounded in-memory OOXML .xlsx decompression & cell extraction",
        if ooxml_ok { "pass" } else { "error" },
    ));

    // 6. MiniRegex + DomainPack compilation & matching
    let (pack_ok, pack_detail) = check_minire_domain_pack();
    checks.push(check_entry(
        "minire_and_domain_pack",
        pack_ok,
        pack_detail,
        if pack_ok { "pass" } else { "error" },
    ));

    // 7. Optional external pack sample validation
    if let Some(sample_path) = pack_sample {
        match validate_pack_file(sample_path) {
            Ok(rep) => {
                checks.push(check_entry(
                    "pack_sample_validation",
                    rep.valid,
                    format!(
                        "pack_id={} version={} patterns={} warnings={}",
                        rep.pack_id,
                        rep.version,
                        rep.pattern_count,
                        rep.warnings.len()
                    ),
                    if rep.valid { "pass" } else { "error" },
                ));
            }
            Err(e) => {
                checks.push(check_entry(
                    "pack_sample_validation",
                    false,
                    e.to_string(),
                    "error",
                ));
            }
        }
    }

    let all_pass = checks
        .iter()
        .all(|c| c.get("ok").and_then(Value::as_bool).unwrap_or(false));
    let sqlite_ver = rusqlite::version().to_string();
    let host = format!("{}-{}", host_os(), host_arch());
    let ms = elapsed_ms(t0);

    Ok(json!({
        "status": if all_pass { "ok" } else { "error" },
        "engine": ENGINE_VERSION,
        "schema_version": SCHEMA_VERSION,
        "host": host,
        "sqlite_version": sqlite_ver,
        "threads": cfg.max_threads,
        "elapsed_ms": ms,
        "checks": checks,
    }))
}

fn check_sqlite_fts5_and_threadsafe() -> (bool, bool) {
    let ts_ok = unsafe { rusqlite::ffi::sqlite3_threadsafe() != 0 };
    let Ok(conn) = Connection::open_in_memory() else {
        return (false, ts_ok);
    };
    let compiled: bool = conn
        .query_row(
            "SELECT sqlite_compileoption_used('ENABLE_FTS5')",
            [],
            |r| r.get::<_, i64>(0),
        )
        .map(|v| v == 1)
        .unwrap_or(false);
    if !compiled {
        return (false, ts_ok);
    }
    let fts_ok = conn
        .execute_batch(
            "CREATE VIRTUAL TABLE _st_fts USING fts5(x, tokenize='unicode61');
             INSERT INTO _st_fts(x) VALUES ('acme switch acme-sw-2400');",
        )
        .is_ok()
        && conn
            .query_row(
                "SELECT count(*) FROM _st_fts WHERE _st_fts MATCH '\"acme\" AND \"2400\"'",
                [],
                |r| r.get::<_, i64>(0),
            )
            .map(|c| c == 1)
            .unwrap_or(false);
    (fts_ok, ts_ok)
}

fn check_universal_tempdb_roundtrip(cfg: &MailKbConfig) -> (bool, String) {
    let Ok(bg) = TempBuildDir::new(cfg, "mailkb-selftest-") else {
        return (false, "failed to create private TempBuildDir".to_string());
    };
    let data_dir = bg.path().join("data");
    let rt_dir = bg.path().join("runtime");
    let work_db = bg.path().join("work.sqlite");
    let clean_db = bg.path().join("clean.sqlite");
    if fs::create_dir_all(&data_dir).is_err() || fs::create_dir_all(&rt_dir).is_err() {
        return (false, "failed to create temp directories".to_string());
    }
    let test_cfg = cfg
        .with_db_dir_override(&data_dir)
        .with_runtime_dir_override(&rt_dir);

    let Ok(conn) = Connection::open(&work_db) else {
        return (false, "failed to open temp work sqlite".to_string());
    };
    let ddl = r#"
        CREATE TABLE kb_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE mail_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            uid_key TEXT NOT NULL DEFAULT '',
            account_id TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL,
            source_ref TEXT NOT NULL,
            rfc_message_id TEXT NOT NULL DEFAULT '',
            subject TEXT NOT NULL,
            thread_topic TEXT NOT NULL DEFAULT '',
            sender TEXT NOT NULL DEFAULT '',
            recipients TEXT NOT NULL DEFAULT '',
            cc TEXT NOT NULL DEFAULT '',
            date_iso TEXT NOT NULL DEFAULT '',
            folder_path TEXT NOT NULL DEFAULT '',
            completeness TEXT NOT NULL DEFAULT 'full_body',
            direction TEXT NOT NULL DEFAULT '',
            intent_type TEXT NOT NULL DEFAULT '',
            summary_line TEXT NOT NULL DEFAULT '',
            body_latest TEXT NOT NULL,
            body_quoted TEXT NOT NULL DEFAULT '',
            content_hash TEXT NOT NULL UNIQUE,
            primary_entities TEXT NOT NULL DEFAULT '',
            primary_category TEXT NOT NULL DEFAULT 'General',
            topic_tags TEXT NOT NULL DEFAULT '',
            org_tags TEXT NOT NULL DEFAULT '',
            has_amount INTEGER NOT NULL DEFAULT 0,
            amount_summary TEXT NOT NULL DEFAULT '',
            event_dates_json TEXT NOT NULL DEFAULT '{}',
            custom_dims_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE message_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL REFERENCES mail_messages(id),
            uid_key TEXT NOT NULL DEFAULT '',
            entity_type TEXT NOT NULL,
            entity_key TEXT NOT NULL,
            canonical_value TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'General',
            sub_group TEXT NOT NULL DEFAULT '',
            quantity REAL,
            unit TEXT NOT NULL DEFAULT '',
            role TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'medium',
            snippet TEXT NOT NULL DEFAULT '',
            attrs_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE TABLE message_amounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL REFERENCES mail_messages(id),
            uid_key TEXT NOT NULL DEFAULT '',
            amount_type TEXT NOT NULL DEFAULT '',
            subject_entity TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT 'General',
            topic_name TEXT NOT NULL DEFAULT '',
            org_name TEXT NOT NULL DEFAULT '',
            currency TEXT NOT NULL DEFAULT '',
            unit_amount REAL,
            total_amount REAL,
            quantity REAL,
            tax_mode TEXT NOT NULL DEFAULT '',
            terms_json TEXT NOT NULL DEFAULT '{}',
            effective_date_iso TEXT NOT NULL DEFAULT '',
            valid_until TEXT NOT NULL DEFAULT '',
            source_kind TEXT NOT NULL DEFAULT '',
            evidence_snippet TEXT NOT NULL DEFAULT '',
            confidence TEXT NOT NULL DEFAULT 'medium'
        );
        CREATE TABLE message_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL REFERENCES mail_messages(id),
            uid_key TEXT NOT NULL DEFAULT '',
            filename TEXT NOT NULL DEFAULT '',
            clean_filename TEXT NOT NULL DEFAULT '',
            ext TEXT NOT NULL DEFAULT '',
            mime_type TEXT NOT NULL DEFAULT '',
            size_bytes INTEGER NOT NULL DEFAULT 0,
            mtime INTEGER NOT NULL DEFAULT 0,
            mtime_iso TEXT NOT NULL DEFAULT '',
            storage_relpath TEXT NOT NULL DEFAULT '',
            is_inline INTEGER NOT NULL DEFAULT 0,
            is_noise INTEGER NOT NULL DEFAULT 0,
            sha256 TEXT NOT NULL DEFAULT '',
            text_preview TEXT NOT NULL DEFAULT '',
            entity_tags TEXT NOT NULL DEFAULT '',
            topic_tags TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE domain_lexicon (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pack_id TEXT NOT NULL DEFAULT '',
            dimension TEXT NOT NULL,
            key TEXT NOT NULL,
            canonical_name TEXT NOT NULL DEFAULT '',
            aliases TEXT NOT NULL DEFAULT '',
            hit_count INTEGER NOT NULL DEFAULT 0,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );
        CREATE VIRTUAL TABLE messages_fts USING fts5(subject_tok, sender_tok, meta_tok, body_latest_tok, body_quoted_tok, tokenize='unicode61');
        CREATE VIRTUAL TABLE dimensions_fts USING fts5(title_tok, meaning_tok, intent_tok, entities_tok, orgs_tok, topics_tok, amounts_tok, tokenize='unicode61');
        CREATE VIRTUAL TABLE attachments_fts USING fts5(filename_tok, meta_tok, tokenize='unicode61');
    "#;
    if let Err(e) = conn.execute_batch(ddl) {
        return (false, format!("DDL failed: {e}"));
    }

    let subj = "报价单 ACME-SW-2400 工业交换机";
    let body = "请查收工业交换机 ACME-SW-2400 报价 USD 450";
    let subj_tok = tokenize_for_fts(subj);
    let body_tok = tokenize_for_fts(body);
    let dim_tok = tokenize_for_fts("ACME-SW-2400 Northstar ProjectAlpha");

    let ins = conn.execute(
        "INSERT INTO mail_messages (uid_key, account_id, source, source_ref, rfc_message_id, subject, sender, date_iso, body_latest, content_hash, primary_entities, primary_category, topic_tags, org_tags, has_amount, amount_summary, custom_dims_json)
         VALUES ('u1', 'acct-1', 'eml', 'quotes/q1.eml', '<q1@acme.test>', ?1, 'sales@acme.test', '2026-04-01 10:00:00', ?2, 'hash1', 'ACME-SW-2400', 'Switch', 'ProjectAlpha', 'Northstar', 1, 'USD 450', '{\"standards\":\"IEC-61850\"}')",
        [subj, body],
    );
    if let Err(e) = ins {
        return (false, format!("insert mail_messages failed: {e}"));
    }
    let msg_id = conn.last_insert_rowid();
    if conn
        .execute(
            "INSERT INTO messages_fts(rowid, subject_tok, sender_tok, meta_tok, body_latest_tok, body_quoted_tok) VALUES (?1, ?2, 'sales acme test', '', ?3, '')",
            rusqlite::params![msg_id, subj_tok, body_tok],
        )
        .is_err()
        || conn
            .execute(
                "INSERT INTO dimensions_fts(rowid, title_tok, meaning_tok, intent_tok, entities_tok, orgs_tok, topics_tok, amounts_tok) VALUES (?1, ?2, '', 'quote', ?3, 'northstar', 'projectalpha', 'usd 450')",
                rusqlite::params![msg_id, subj_tok, dim_tok],
            )
            .is_err()
        || conn
            .execute(
                "INSERT INTO kb_meta(key, value) VALUES ('schema_version', '1.0-universal')",
                [],
            )
            .is_err()
    {
        return (false, "insert FTS/meta failed".to_string());
    }
    drop(conn);

    let dst_db = data_dir.join(DEFAULT_DB_FILENAME);
    if let Err(e) = publish_clean_sqlite(&test_cfg, &work_db, &clean_db, &dst_db, DEFAULT_DB_STEM)
    {
        return (false, format!("publish_clean_sqlite failed: {e}"));
    }

    let stage = match stage_primary_db(&test_cfg) {
        Ok(s) => s,
        Err(e) => return (false, format!("stage_primary_db failed: {e}")),
    };
    let ro = match open_staged_ro(&stage.runtime_db, DEFAULT_MMAP_BYTES) {
        Ok(c) => c,
        Err(e) => return (false, format!("open_staged_ro failed: {e}")),
    };

    let (fts_q, _) = build_cjk_bigram_fts_query(&["工业交换机", "ACME-SW-2400"]);
    let cnt: i64 = ro
        .query_row(
            "SELECT COUNT(*) FROM messages_fts JOIN mail_messages m ON m.id = messages_fts.rowid
             WHERE messages_fts MATCH ?1 AND json_extract(m.custom_dims_json, '$.\"standards\"') = 'IEC-61850'",
            [&fts_q],
            |r| r.get(0),
        )
        .unwrap_or(0);
    if cnt != 1 {
        return (
            false,
            format!("expected 1 CJK bigram + json_extract match, got {cnt} (q={fts_q})"),
        );
    }
    (
        true,
        format!("published, staged ({:?}), queried FTS5 CJK bigram + JSON1", stage.staging),
    )
}

fn check_security_guards(cfg: &MailKbConfig) -> bool {
    let home = std::env::var("HOME")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "/nonexistent-home".to_string());
    let s9_ok = assert_not_in_mail_container(cfg, Path::new(&format!("{home}/Library/Mail/V10/x")))
        .is_err()
        && assert_not_in_mail_container(
            cfg,
            Path::new(&format!("{home}/Library/Group Containers/UBF8T346G9.Office/x")),
        )
        .is_err()
        && assert_not_in_mail_container(cfg, Path::new(&format!("{home}/Library/Thunderbird/Profiles")))
            .is_err()
        && assert_not_in_mail_container(cfg, Path::new("/tmp/mailkb-selftest-safe")).is_ok()
        && assert_safe_out_path(cfg, &cfg.db_dir.join("leak.json")).is_err();

    let s10_ok = safe_relpath("projects/alpha/quote.eml")
        && !safe_relpath("/etc/passwd")
        && !safe_relpath("../secret.eml")
        && !safe_relpath("a\\..\\b.eml")
        && remap_relpath("../../etc/passwd", Path::new("/tmp/root")).is_err();

    let s11_ok = term_safe("ok\x1b]52;c;x\x07line\u{009b}1", false) == "ok]52;c;xline1"
        && sanitize_utf8(b"hi\0there") == "hithere";

    s9_ok && s10_ok && s11_ok
}

fn check_pure_rust_ooxml() -> bool {
    let mut cursor = Cursor::new(Vec::new());
    {
        let mut zw = ZipWriter::new(&mut cursor);
        let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        let files: [(&str, &str); 4] = [
            (
                "xl/workbook.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="BOM" sheetId="1" r:id="rId1"/></sheets>
</workbook>"#,
            ),
            (
                "xl/_rels/workbook.xml.rels",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"#,
            ),
            (
                "xl/sharedStrings.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>ACME-SW-2400</t></si></sst>"#,
            ),
            (
                "xl/worksheets/sheet1.xml",
                r#"<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData>
</worksheet>"#,
            ),
        ];
        for (name, body) in files {
            if zw.start_file(name, opts).is_err() || zw.write_all(body.as_bytes()).is_err() {
                return false;
            }
        }
        if zw.finish().is_err() {
            return false;
        }
    }
    let bytes = cursor.into_inner();
    match extract_xlsx_from_bytes(&bytes, &OoxmlOptions::mail_preview()) {
        Ok(res) => res.preview.contains("ACME-SW-2400"),
        Err(_) => false,
    }
}

fn check_minire_domain_pack() -> (bool, String) {
    let raw = r#"{
      "schema_version": "domain-pack.v1",
      "pack_id": "selftest-sample",
      "version": "1.0",
      "entity_rules": {
        "default_category": "General",
        "code_patterns": [
          {
            "name": "acme_std",
            "pattern": "\\bACME-[A-Z]{2}-\\d{4}\\b",
            "category": "Switch",
            "sub_group": "ACME-SW"
          },
          {
            "name": "short_lookaround",
            "pattern": "(?<![A-Za-z0-9])SW-\\d{3}(?![A-Za-z0-9])",
            "category": "Switch"
          }
        ]
      }
    }"#;
    let pack: DomainPack = match serde_json::from_str(raw) {
        Ok(p) => p,
        Err(e) => return (false, format!("pack parse failed: {e}")),
    };
    let sha = sha256_bytes(raw.as_bytes());
    let compiled = match CompiledDomainPack::from_packs(vec![(pack, sha)]) {
        Ok(c) => c,
        Err(e) => return (false, format!("pack compile failed: {e}")),
    };
    let std_rule = &compiled.code_rules[0];
    let mini_rule = &compiled.code_rules[1];
    let ok = std_rule.pattern.is_match("Quote ACME-SW-2400")
        && mini_rule.pattern.is_match("Order SW-205 today")
        && !mini_rule.pattern.is_match("Order XSW-205A today");
    (
        ok,
        "compiled standard regex + MiniRegex lookaround rules in domain-pack.v1".to_string(),
    )
}
