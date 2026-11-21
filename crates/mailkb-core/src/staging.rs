//! T2 Hot Runtime Staging state machine & immutable read-only SQLite connection helpers.

use crate::config::{MailKbConfig, DEFAULT_DB_STEM};
use crate::error::{KbError, KbResult};
use crate::security::{
    assert_not_in_mail_container, ensure_private_dir, fsync_dir, open_readonly_nofollow,
    read_file_readonly, BlockingFlock,
};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Default mmap budget (`2 GiB`) for large staged read-only queries.
pub const DEFAULT_MMAP_BYTES: i64 = 2 * 1024 * 1024 * 1024;

const COPY_CHUNK_BYTES: usize = 1024 * 1024;
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// T2 runtime staging outcome state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StagingState {
    Fresh,
    Reused,
    SidecarMissing,
    CachedDuringSync,
    CachedSourceMissing,
}

impl StagingState {
    pub fn as_str(self) -> &'static str {
        match self {
            StagingState::Fresh => "fresh",
            StagingState::Reused => "reused",
            StagingState::SidecarMissing => "sidecar_missing",
            StagingState::CachedDuringSync => "cached_during_sync",
            StagingState::CachedSourceMissing => "cached_source_missing",
        }
    }
}

/// Metadata describing the staged read-only runtime snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageInfo {
    pub source_db: PathBuf,
    pub runtime_db: PathBuf,
    pub staging: StagingState,
    pub warnings: Vec<String>,
    pub sha256: Option<String>,
}

/// Percent-encodes a filesystem path into a SQLite immutable read-only URI:
/// `file:<pct_encoded>?mode=ro&immutable=1`.
pub fn sqlite_ro_uri(path: &Path) -> String {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    };
    let bytes = abs.as_os_str().as_bytes();
    let mut out = String::with_capacity(bytes.len() + 32);
    out.push_str("file:");
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'/' | b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0F) as usize] as char);
        }
    }
    out.push_str("?mode=ro&immutable=1");
    out
}

/// Opens an already-staged runtime SQLite snapshot using `SQLITE_OPEN_READ_ONLY |
/// SQLITE_OPEN_URI | SQLITE_OPEN_NO_MUTEX` and applies read-only memory/cache pragmas.
pub fn open_staged_ro(runtime_db: &Path, mmap_bytes: i64) -> KbResult<Connection> {
    let uri = sqlite_ro_uri(runtime_db);
    let flags =
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(uri, flags)?;
    let pragmas = format!(
        "PRAGMA mmap_size = {}; PRAGMA cache_size = -131072; PRAGMA temp_store = MEMORY; PRAGMA query_only = ON;",
        mmap_bytes.max(0)
    );
    conn.execute_batch(&pragmas)?;
    Ok(conn)
}

/// Validates that `path` is a regular non-symlink SQLite database in `DELETE` journal mode.
pub fn check_sqlite_header(path: &Path) -> KbResult<()> {
    let mut f = open_readonly_nofollow(path)?;
    let mut hdr = [0u8; 100];
    let n = read_exact_or_eof(&mut f, &mut hdr)?;
    if n < 100 {
        return Err(KbError::Staging(
            "file shorter than 100-byte SQLite header".to_string(),
        ));
    }
    if &hdr[..16] != SQLITE_MAGIC {
        return Err(KbError::Staging("missing SQLite format 3 magic".to_string()));
    }
    if hdr[18] != 1 || hdr[19] != 1 {
        return Err(KbError::Staging(
            "header bytes 18/19 != 1 (not DELETE journal mode)".to_string(),
        ));
    }
    Ok(())
}

/// Validates that `path` is a regular non-symlink SQLite file with valid SQLite magic (any journal mode, used for external read-only DB staging).
pub fn check_sqlite_magic(path: &Path) -> KbResult<()> {
    let mut f = open_readonly_nofollow(path)?;
    let mut hdr = [0u8; 100];
    let n = read_exact_or_eof(&mut f, &mut hdr)?;
    if n < 100 {
        return Err(KbError::Staging(
            "file shorter than 100-byte SQLite header".to_string(),
        ));
    }
    if &hdr[..16] != SQLITE_MAGIC {
        return Err(KbError::Staging("missing SQLite format 3 magic".to_string()));
    }
    Ok(())
}

/// Returns `true` if `path` exists as a non-symlink regular file with valid `DELETE`-mode header.
pub fn is_valid_runtime_sqlite(path: &Path) -> bool {
    check_sqlite_header(path).is_ok()
}

/// Reads a `<db>.sha256` sidecar file, returning lowercase 64-hex digest if valid.
pub fn read_sidecar_sha256(sidecar_path: &Path) -> Option<String> {
    let (raw, _) = read_file_readonly(sidecar_path, Some(4096)).ok()?;
    let text = std::str::from_utf8(&raw).ok()?;
    let first_line = text.lines().next()?.trim();
    let tok = first_line.split_whitespace().next()?;
    if tok.len() == 64 && tok.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(tok.to_ascii_lowercase())
    } else {
        None
    }
}

/// Formats the 4-field `.stamp` payload.
pub fn format_stamp(size: u64, mtime_ns: i64, ino: u64, sidecar_or_dash: &str) -> String {
    format!("{size} {mtime_ns} {ino} {sidecar_or_dash}\n")
}

/// Parses a 4-field `.stamp` file payload.
pub fn parse_stamp(raw: &str) -> Option<(u64, i64, u64, String)> {
    let mut parts = raw.split_whitespace();
    let size: u64 = parts.next()?.parse().ok()?;
    let mtime_ns: i64 = parts.next()?.parse().ok()?;
    let ino: u64 = parts.next()?.parse().ok()?;
    let sidecar = parts.next()?.to_string();
    if parts.next().is_some() {
        return None;
    }
    Some((size, mtime_ns, ino, sidecar))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SrcIdentity {
    pub size: u64,
    pub mtime_ns: i64,
    pub ino: u64,
    pub sidecar: String,
}

impl SrcIdentity {
    pub fn to_stamp(&self) -> String {
        format_stamp(self.size, self.mtime_ns, self.ino, &self.sidecar)
    }

    pub fn from_paths(src_db: &Path, sidecar_path: &Path) -> Option<Self> {
        let meta = fs::metadata(src_db).ok()?;
        if !meta.is_file() || meta.len() < 100 {
            return None;
        }
        let mtime_ns = meta
            .mtime()
            .saturating_mul(1_000_000_000)
            .saturating_add(meta.mtime_nsec());
        let sidecar = read_sidecar_sha256(sidecar_path).unwrap_or_else(|| "-".to_string());
        Some(Self {
            size: meta.len(),
            mtime_ns,
            ino: meta.ino(),
            sidecar,
        })
    }
}

/// Stages the primary cold database `cfg.primary_db_path()` into `cfg.runtime_dir`.
pub fn stage_primary_db(cfg: &MailKbConfig) -> KbResult<StageInfo> {
    stage_db_path(cfg, cfg.primary_db_path(), DEFAULT_DB_STEM)
}

/// Stages `source_db` into `cfg.runtime_dir` using slot `<default_stem>` (or custom `<stem>-<h12>`).
pub fn stage_db_path(
    cfg: &MailKbConfig,
    source_db: &Path,
    default_stem: &str,
) -> KbResult<StageInfo> {
    assert_not_in_mail_container(cfg, source_db)?;
    let runtime_db = cfg.runtime_db_for_path(default_stem, source_db);
    assert_not_in_mail_container(cfg, &cfg.runtime_dir)?;
    assert_not_in_mail_container(cfg, &runtime_db)?;
    ensure_private_dir(&cfg.runtime_dir)?;

    let sidecar_path = sidecar_path_for(source_db);
    let stamp_path = stamp_path_for(&runtime_db);

    if let Some(res) = check_fast_path(source_db, &sidecar_path, &runtime_db, &stamp_path)? {
        return Ok(res);
    }

    let rt_stem = runtime_db
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(default_stem);
    let lock_path = cfg.runtime_dir.join(format!(".{rt_stem}.stage.lock"));
    let _guard = BlockingFlock::acquire(&lock_path)?;

    if let Some(res) = check_fast_path(source_db, &sidecar_path, &runtime_db, &stamp_path)? {
        return Ok(res);
    }

    let before = match SrcIdentity::from_paths(source_db, &sidecar_path) {
        Some(id) => id,
        None => {
            if is_valid_runtime_sqlite(&runtime_db) {
                return Ok(StageInfo {
                    source_db: source_db.to_path_buf(),
                    runtime_db,
                    staging: StagingState::CachedSourceMissing,
                    warnings: vec![format!(
                        "source_missing_using_cached_runtime: {}",
                        source_db.display()
                    )],
                    sha256: None,
                });
            }
            return Err(KbError::NotFound(format!(
                "Database not found and no cached runtime copy: {}",
                source_db.display()
            )));
        }
    };

    let rt_ok = is_valid_runtime_sqlite(&runtime_db);
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = cfg.runtime_dir.join(format!(
        ".{rt_stem}.sqlite.tmp.{}.{seq}",
        std::process::id()
    ));

    let copy_outcome = copy_and_verify_snapshot(source_db, &sidecar_path, &tmp_path, &before);
    match copy_outcome {
        Ok((computed_hex, sidecar_missing)) => {
            if let Err(e) = fs::rename(&tmp_path, &runtime_db) {
                let _ = fs::remove_file(&tmp_path);
                return Err(KbError::Staging(format!(
                    "rename {} -> {} failed: {e}",
                    tmp_path.display(),
                    runtime_db.display()
                )));
            }
            let mut warnings = Vec::new();
            if sidecar_missing {
                warnings.push("sidecar_missing".to_string());
            }
            if let Err(e) = write_stamp_atomic(&cfg.runtime_dir, &stamp_path, &before) {
                warnings.push(format!("runtime_stamp_not_written: {e}"));
            }
            fsync_dir(&cfg.runtime_dir);
            Ok(StageInfo {
                source_db: source_db.to_path_buf(),
                runtime_db,
                staging: if sidecar_missing {
                    StagingState::SidecarMissing
                } else {
                    StagingState::Fresh
                },
                warnings,
                sha256: Some(computed_hex),
            })
        }
        Err(reason) => {
            let _ = fs::remove_file(&tmp_path);
            if rt_ok {
                Ok(StageInfo {
                    source_db: source_db.to_path_buf(),
                    runtime_db,
                    staging: StagingState::CachedDuringSync,
                    warnings: vec![format!("using_cached_runtime_during_sync: {reason}")],
                    sha256: None,
                })
            } else {
                Err(KbError::Staging(format!(
                    "source_db_unverified_and_no_runtime_copy: {reason}"
                )))
            }
        }
    }
}

fn check_fast_path(
    source_db: &Path,
    sidecar_path: &Path,
    runtime_db: &Path,
    stamp_path: &Path,
) -> KbResult<Option<StageInfo>> {
    let rt_ok = is_valid_runtime_sqlite(runtime_db);
    let Some(id) = SrcIdentity::from_paths(source_db, sidecar_path) else {
        if rt_ok {
            return Ok(Some(StageInfo {
                source_db: source_db.to_path_buf(),
                runtime_db: runtime_db.to_path_buf(),
                staging: StagingState::CachedSourceMissing,
                warnings: vec![format!(
                    "source_missing_using_cached_runtime: {}",
                    source_db.display()
                )],
                sha256: None,
            }));
        }
        return Err(KbError::NotFound(format!(
            "Database not found and no cached runtime copy: {}",
            source_db.display()
        )));
    };

    if rt_ok {
        if let Ok((stamp_bytes, _)) = read_file_readonly(stamp_path, Some(512)) {
            if let Ok(stamp_str) = std::str::from_utf8(&stamp_bytes) {
                if let Some((sz, mt, ino, sc)) = parse_stamp(stamp_str) {
                    if (sz, mt, ino, sc.as_str())
                        == (id.size, id.mtime_ns, id.ino, id.sidecar.as_str())
                    {
                        let mut warnings = Vec::new();
                        let sha256 = if id.sidecar == "-" {
                            warnings.push("sidecar_missing".to_string());
                            None
                        } else {
                            Some(id.sidecar)
                        };
                        return Ok(Some(StageInfo {
                            source_db: source_db.to_path_buf(),
                            runtime_db: runtime_db.to_path_buf(),
                            staging: StagingState::Reused,
                            warnings,
                            sha256,
                        }));
                    }
                }
            }
        }
    }

    Ok(None)
}

fn copy_and_verify_snapshot(
    source_db: &Path,
    sidecar_path: &Path,
    tmp_path: &Path,
    before: &SrcIdentity,
) -> Result<(String, bool), String> {
    let mut src_file = open_readonly_nofollow(source_db)
        .map_err(|e| format!("open source {}: {e}", source_db.display()))?;

    let mut tmp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(tmp_path)
        .map_err(|e| format!("create temp {}: {e}", tmp_path.display()))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; COPY_CHUNK_BYTES];
    let mut total_bytes: u64 = 0;

    loop {
        let n = match src_file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("read source {}: {e}", source_db.display())),
        };
        hasher.update(&buf[..n]);
        tmp_file
            .write_all(&buf[..n])
            .map_err(|e| format!("write temp {}: {e}", tmp_path.display()))?;
        total_bytes = total_bytes.saturating_add(n as u64);
    }

    tmp_file
        .set_permissions(Permissions::from_mode(0o600))
        .map_err(|e| format!("chmod temp {}: {e}", tmp_path.display()))?;
    tmp_file
        .sync_all()
        .map_err(|e| format!("fsync temp {}: {e}", tmp_path.display()))?;
    drop(tmp_file);
    drop(src_file);

    let computed_hex = format!("{:x}", hasher.finalize());

    let after = SrcIdentity::from_paths(source_db, sidecar_path)
        .ok_or_else(|| "source disappeared during staging copy".to_string())?;
    if &after != before {
        return Err("source or sidecar changed during staging copy".to_string());
    }
    if total_bytes != before.size {
        return Err(format!(
            "copied size {} differs from source size {}",
            total_bytes, before.size
        ));
    }

    check_sqlite_header(tmp_path).map_err(|e| e.to_string())?;

    let sidecar_missing = before.sidecar == "-";
    if !sidecar_missing {
        if computed_hex != before.sidecar {
            return Err(format!("sha256 mismatch vs {}", sidecar_path.display()));
        }
    } else {
        quick_check_snapshot(tmp_path)
            .map_err(|e| format!("no .sha256 sidecar and quick_check failed: {e}"))?;
    }

    Ok((computed_hex, sidecar_missing))
}

/// Runs `PRAGMA quick_check;` against a staged/temporary SQLite snapshot using immutable RO mode.
pub fn quick_check_snapshot(path: &Path) -> KbResult<()> {
    let conn = open_staged_ro(path, 0)?;
    let status: String = conn.query_row("PRAGMA quick_check;", [], |row| row.get(0))?;
    if status.eq_ignore_ascii_case("ok") {
        Ok(())
    } else {
        Err(KbError::Staging(format!(
            "PRAGMA quick_check returned: {status}"
        )))
    }
}

pub(crate) fn write_stamp_atomic(
    rt_dir: &Path,
    stamp_path: &Path,
    id: &SrcIdentity,
) -> KbResult<()> {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let fname = stamp_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("db.sqlite.stamp");
    let tmp_stamp = rt_dir.join(format!(".{fname}.tmp.{}.{seq}", std::process::id()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp_stamp)?;
    let content = id.to_stamp();
    f.write_all(content.as_bytes())?;
    f.set_permissions(Permissions::from_mode(0o600))?;
    f.sync_all()?;
    drop(f);
    if let Err(e) = fs::rename(&tmp_stamp, stamp_path) {
        let _ = fs::remove_file(&tmp_stamp);
        return Err(KbError::Io(e));
    }
    Ok(())
}

/// Returns `<db_path>.sha256`.
pub fn sidecar_path_for(db_path: &Path) -> PathBuf {
    let mut os = db_path.as_os_str().to_os_string();
    os.push(".sha256");
    PathBuf::from(os)
}

/// Returns `<runtime_db>.stamp`.
pub fn stamp_path_for(runtime_db: &Path) -> PathBuf {
    let mut os = runtime_db.as_os_str().to_os_string();
    os.push(".stamp");
    PathBuf::from(os)
}

fn read_exact_or_eof(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut off = 0;
    while off < buf.len() {
        match file.read(&mut buf[off..]) {
            Ok(0) => break,
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(off)
}
