//! S8 Private temporary build directories, C6 disk free checks, and T3 atomic
//! `DELETE`-mode SQLite publishing with `.sha256` sidecars and runtime cache refresh.

use crate::config::MailKbConfig;
use crate::error::{KbError, KbResult};
use crate::security::{
    assert_not_in_mail_container, ensure_private_dir, fsync_dir, open_readonly_nofollow,
    real_allow_missing, BlockingFlock,
};
use crate::staging::{
    check_sqlite_header, quick_check_snapshot, sidecar_path_for, stamp_path_for,
    write_stamp_atomic, SrcIdentity,
};
use crate::time::now_unix_secs;
use rusqlite::backup::Backup;
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const HASH_CHUNK_BYTES: usize = 256 * 1024;
static PUB_SEQ: AtomicU64 = AtomicU64::new(0);

/// Summary returned by [`publish_clean_sqlite`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishResult {
    pub db_path: PathBuf,
    pub sha256_path: PathBuf,
    pub runtime_db: PathBuf,
    pub sha256: String,
    pub db_bytes: u64,
    pub journal_mode: String,
    pub quick_check: String,
    pub runtime_updated: bool,
    pub warnings: Vec<String>,
}

/// S8 RAII private `0700` build directory created via `mkdtemp` inside `$TMPDIR` (or `/tmp`),
/// automatically reaping >24h stale build directories owned by the current effective UID.
pub struct TempBuildDir {
    path: PathBuf,
    disarmed: bool,
}

impl TempBuildDir {
    pub fn build_base_dir() -> PathBuf {
        let base = std::env::var_os("TMPDIR")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        real_allow_missing(&base)
    }

    pub fn new(cfg: &MailKbConfig, prefix: &str) -> KbResult<Self> {
        let base = Self::build_base_dir();
        assert_not_in_mail_container(cfg, &base)?;
        ensure_dir_exists(&base)?;
        reap_stale_build_dirs(&base, prefix, 86_400);

        let template = base.join(format!("{prefix}{}-XXXXXX", std::process::id()));
        let mut c_bytes = template.as_os_str().as_bytes().to_vec();
        c_bytes.push(0);

        let ptr = unsafe { libc::mkdtemp(c_bytes.as_mut_ptr() as *mut libc::c_char) };
        if ptr.is_null() {
            return Err(KbError::Io(io::Error::last_os_error()));
        }
        c_bytes.pop();
        let dir_path = PathBuf::from(std::ffi::OsStr::from_bytes(&c_bytes));
        ensure_private_dir(&dir_path)?;

        Ok(Self {
            path: dir_path,
            disarmed: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for TempBuildDir {
    fn drop(&mut self) {
        if !self.disarmed && !self.path.as_os_str().is_empty() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub fn reap_stale_build_dirs(base: &Path, prefix: &str, max_age_secs: u64) {
    let Ok(entries) = fs::read_dir(base) else {
        return;
    };
    let euid = unsafe { libc::geteuid() };
    let now = now_unix_secs();
    let self_pid_prefix = format!("{prefix}{}-", std::process::id());

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if !name_str.starts_with(prefix) || name_str.starts_with(&self_pid_prefix) {
            continue;
        }
        let full = entry.path();
        let Ok(meta) = fs::symlink_metadata(&full) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != euid {
            continue;
        }
        if now.saturating_sub(meta.mtime()) > max_age_secs as i64 {
            let _ = fs::remove_dir_all(&full);
        }
    }
}

/// C6: Returns available bytes on the filesystem containing `dir`.
pub fn free_bytes(dir: &Path) -> KbResult<u64> {
    let mut cur = real_allow_missing(dir);
    while !cur.exists() {
        let Some(parent) = cur.parent() else {
            break;
        };
        if parent == cur {
            break;
        }
        cur = parent.to_path_buf();
    }
    let c_dir = CString::new(cur.as_os_str().as_bytes()).map_err(|_| {
        KbError::InvalidArgument(format!("path contains NUL byte: {}", dir.display()))
    })?;
    let mut sv: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c_dir.as_ptr(), &mut sv) } != 0 {
        return Err(KbError::Io(io::Error::last_os_error()));
    }
    Ok((sv.f_bavail as u64).saturating_mul(sv.f_frsize as u64))
}

/// C6 pre-flight disk check ensuring sufficient free space in temp, destination, and runtime dirs.
pub fn check_disk_space(
    tmp_base: &Path,
    dst_dir: &Path,
    runtime_dir: &Path,
    old_db_bytes: u64,
) -> KbResult<()> {
    let need_tmp = old_db_bytes.saturating_mul(3).max(32 * 1024 * 1024);
    let need_dst = old_db_bytes.saturating_mul(2).max(16 * 1024 * 1024);

    if free_bytes(tmp_base)? < need_tmp {
        return Err(KbError::Publish(format!(
            "insufficient_disk_space in temp dir {}",
            tmp_base.display()
        )));
    }
    if free_bytes(dst_dir)? < need_dst {
        return Err(KbError::Publish(format!(
            "insufficient_disk_space in destination dir {}",
            dst_dir.display()
        )));
    }
    if free_bytes(runtime_dir)? < need_dst {
        return Err(KbError::Publish(format!(
            "insufficient_disk_space in runtime dir {}",
            runtime_dir.display()
        )));
    }
    Ok(())
}

/// Computes lowercase hex SHA-256 of an in-memory byte slice.
pub fn sha256_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Streams a regular file via [`open_readonly_nofollow`] to compute its lowercase hex SHA-256.
pub fn sha256_file(path: &Path) -> KbResult<String> {
    let mut file = open_readonly_nofollow(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK_BYTES];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(KbError::Io(e)),
        };
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Atomically writes UTF-8 text to `path`.
pub fn write_text_atomic(path: &Path, content: &str, mode: u32) -> KbResult<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_dir_exists(dir)?;
    let fname = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let seq = PUB_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{fname}.tmp.{}.{seq}", std::process::id()));

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    f.write_all(content.as_bytes())?;
    f.set_permissions(Permissions::from_mode(mode))?;
    f.sync_all()?;
    drop(f);

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(KbError::Io(e));
    }
    fsync_dir(dir);
    Ok(())
}

/// Streams `src` to a sibling hidden temp file, verifies `expect_hex`, and atomically renames to `dst`.
pub fn install_file_atomic_hashed(
    src: &Path,
    dst: &Path,
    mode: u32,
    expect_hex: Option<&str>,
) -> KbResult<(String, u64)> {
    let dir = dst
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let fname = dst
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("db.sqlite");
    let seq = PUB_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp = dir.join(format!(".{fname}.tmp.{}.{seq}", std::process::id()));

    let mut in_f = open_readonly_nofollow(src)?;
    let mut out_f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_CHUNK_BYTES];
    let mut bytes_written: u64 = 0;

    let copy_res: KbResult<()> = (|| {
        loop {
            let n = match in_f.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(KbError::Io(e)),
            };
            hasher.update(&buf[..n]);
            out_f.write_all(&buf[..n])?;
            bytes_written = bytes_written.saturating_add(n as u64);
        }
        out_f.set_permissions(Permissions::from_mode(mode))?;
        out_f.sync_all()?;
        Ok(())
    })();

    drop(out_f);
    drop(in_f);

    if let Err(e) = copy_res {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    let hex = format!("{:x}", hasher.finalize());
    if let Some(expected) = expect_hex {
        if hex != expected {
            let _ = fs::remove_file(&tmp);
            return Err(KbError::Publish(format!(
                "hash mismatch while installing {}",
                dst.display()
            )));
        }
    }

    if let Err(e) = fs::rename(&tmp, dst) {
        let _ = fs::remove_file(&tmp);
        return Err(KbError::Io(e));
    }
    fsync_dir(dir);
    Ok((hex, bytes_written))
}

/// Copies `src_path` into a clean, single-file `DELETE`-mode SQLite snapshot at `clean_dst_path`.
pub fn backup_clone(src_path: &Path, clean_dst_path: &Path) -> KbResult<()> {
    remove_sqlite_and_sidecars(clean_dst_path);

    let src = Connection::open_with_flags(
        src_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let mut dst = Connection::open_with_flags(
        clean_dst_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;

    dst.execute_batch("PRAGMA page_size = 4096; PRAGMA journal_mode = DELETE;")?;

    {
        let backup = Backup::new(&src, &mut dst)?;
        backup.run_to_completion(4096, Duration::from_millis(0), None)?;
    }

    drop(src);
    drop(dst);

    let verify_conn = Connection::open_with_flags(
        clean_dst_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let jm: String = verify_conn.query_row("PRAGMA journal_mode = DELETE;", [], |r| r.get(0))?;
    drop(verify_conn);

    if !jm.eq_ignore_ascii_case("delete") {
        return Err(KbError::Publish(format!(
            "clean.sqlite journal_mode is '{jm}' (expected 'delete')"
        )));
    }
    Ok(())
}

/// T3 clean publish pipeline producing `dst_db`, `<dst_db>.sha256`, and hot runtime cache `<runtime_dir>/mailkb_db.sqlite`.
pub fn publish_clean_sqlite(
    cfg: &MailKbConfig,
    work_db: &Path,
    clean_db: &Path,
    dst_db: &Path,
    default_stem: &str,
) -> KbResult<PublishResult> {
    assert_not_in_mail_container(cfg, dst_db)?;
    let dst_dir = dst_db
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    assert_not_in_mail_container(cfg, dst_dir)?;
    ensure_dir_exists(dst_dir)?;

    backup_clone(work_db, clean_db)?;

    for sfx in ["-wal", "-shm", "-journal"] {
        let mut os = clean_db.as_os_str().to_os_string();
        os.push(sfx);
        if fs::symlink_metadata(Path::new(&os)).is_ok() {
            return Err(KbError::Publish(format!(
                "unexpected SQLite sidecar present after DELETE-mode backup: {}",
                Path::new(&os).display()
            )));
        }
    }

    check_sqlite_header(clean_db).map_err(|e| KbError::Publish(e.to_string()))?;
    quick_check_snapshot(clean_db).map_err(|e| KbError::Publish(e.to_string()))?;

    let expected_sha = sha256_file(clean_db)?;
    let (sha_hex, db_bytes) =
        install_file_atomic_hashed(clean_db, dst_db, 0o640, Some(&expected_sha))?;

    let sha_path = sidecar_path_for(dst_db);
    let dst_name = dst_db
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("db.sqlite");
    write_text_atomic(&sha_path, &format!("{sha_hex}  {dst_name}\n"), 0o640)?;
    fsync_dir(dst_dir);

    let runtime_db = cfg.runtime_db_for_path(default_stem, dst_db);
    let mut warnings = Vec::new();
    let mut runtime_updated = false;
    if let Err(e) = assert_not_in_mail_container(cfg, &cfg.runtime_dir)
        .and_then(|_| assert_not_in_mail_container(cfg, &runtime_db))
        .and_then(|_| ensure_private_dir(&cfg.runtime_dir))
    {
        warnings.push(format!("runtime_not_updated: {e}"));
    } else {
        let rt_stem = runtime_db
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(default_stem);
        let lock_path = cfg.runtime_dir.join(format!(".{rt_stem}.stage.lock"));
        match BlockingFlock::acquire(&lock_path) {
            Ok(_lock) => {
                match install_file_atomic_hashed(clean_db, &runtime_db, 0o600, Some(&sha_hex)) {
                    Ok(_) => {
                        if let Some(id) = SrcIdentity::from_paths(dst_db, &sha_path) {
                            let stamp_path = stamp_path_for(&runtime_db);
                            if let Err(e) = write_stamp_atomic(&cfg.runtime_dir, &stamp_path, &id)
                            {
                                warnings.push(format!("runtime_stamp_not_written: {e}"));
                            } else {
                                runtime_updated = true;
                            }
                        } else {
                            warnings
                                .push("runtime_stamp_not_written: source stat failed".to_string());
                        }
                    }
                    Err(e) => warnings.push(format!("runtime_not_updated: {e}")),
                }
            }
            Err(e) => warnings.push(format!("runtime_lock_failed: {e}")),
        }
    }

    Ok(PublishResult {
        db_path: dst_db.to_path_buf(),
        sha256_path: sha_path,
        runtime_db,
        sha256: sha_hex,
        db_bytes,
        journal_mode: "delete".to_string(),
        quick_check: "ok".to_string(),
        runtime_updated,
        warnings,
    })
}

fn ensure_dir_exists(dir: &Path) -> KbResult<()> {
    if !dir.exists() {
        DirBuilder::new().recursive(true).mode(0o750).create(dir)?;
    }
    Ok(())
}

fn remove_sqlite_and_sidecars(path: &Path) {
    let _ = fs::remove_file(path);
    for sfx in ["-wal", "-shm", "-journal"] {
        let mut os = path.as_os_str().to_os_string();
        os.push(sfx);
        let _ = fs::remove_file(Path::new(&os));
    }
}
