//! Security primitives: S4 nofollow reads, S9 mail container guards, S10 path
//! remapping, S11 terminal sanitization, S13 private directories, and T4 file locks.

use crate::config::MailKbConfig;
use crate::error::{KbError, KbResult};
use std::ffi::CString;
use std::fs::{self, DirBuilder, File, Permissions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Component, Path, PathBuf};

/// Expands a leading `~` or `~/` against `$HOME`.
pub fn expand_tilde(raw: &str) -> PathBuf {
    if raw == "~" {
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(home);
        }
    } else if let Some(rest) = raw.strip_prefix("~/") {
        if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(raw)
}

/// Lexically normalizes `.` and `..` components without touching the filesystem.
pub fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => out.push(p.as_os_str()),
            Component::RootDir => out.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() && !path.is_absolute() {
                    out.push("..");
                }
            }
            Component::Normal(seg) => out.push(seg),
        }
    }
    if out.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        out
    }
}

/// Resolves symlinks along the longest existing prefix of `path`, preserving
/// non-existent trailing components.
pub fn real_allow_missing(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else if let Ok(cwd) = std::env::current_dir() {
        cwd.join(path)
    } else {
        path.to_path_buf()
    };

    if let Ok(canon) = fs::canonicalize(&abs) {
        return canon;
    }

    let norm = lexical_normalize(&abs);
    if let Ok(canon) = fs::canonicalize(&norm) {
        return canon;
    }

    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur: &Path = &norm;
    while let Some(name) = cur.file_name() {
        let Some(parent) = cur.parent() else {
            break;
        };
        tail.push(name.to_os_string());
        if let Ok(canon) = fs::canonicalize(parent) {
            let mut res = canon;
            for seg in tail.into_iter().rev() {
                res.push(seg);
            }
            return res;
        }
        cur = parent;
    }
    norm
}

/// Returns `true` if `child` is identical to or strictly nested within `parent`
/// after resolving existing path prefixes.
pub fn path_is_within(child: &Path, parent: &Path) -> bool {
    if child.as_os_str().is_empty() || parent.as_os_str().is_empty() {
        return false;
    }
    let c = real_allow_missing(child);
    let p = real_allow_missing(parent);
    c.starts_with(&p)
}

/// S9 Guard: refuses any write/staging/build path inside Apple Mail, Outlook Live Profile,
/// or Thunderbird containers, returning `KbError::MailContainerViolation` (exit code 2).
pub fn assert_not_in_mail_container(cfg: &MailKbConfig, path: &Path) -> KbResult<()> {
    let mut forbidden: Vec<PathBuf> = Vec::new();
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        let h = PathBuf::from(home);
        forbidden.push(h.join("Library/Mail"));
        forbidden.push(h.join("Library/Group Containers/UBF8T346G9.Office"));
        forbidden.push(h.join("Library/Thunderbird"));
    }
    if let Some(ref v10) = cfg.apple_mail_v10_dir {
        forbidden.push(v10.clone());
    }
    if let Some(ref prof) = cfg.outlook_profile_dir {
        forbidden.push(prof.clone());
    }
    if let Some(env_v10) = std::env::var_os("APPLE_MAIL_V10_DIR").filter(|v| !v.is_empty()) {
        forbidden.push(expand_tilde(&env_v10.to_string_lossy()));
    }
    if let Some(env_prof) = std::env::var_os("OUTLOOK_PROFILE_DIR").filter(|v| !v.is_empty()) {
        forbidden.push(expand_tilde(&env_prof.to_string_lossy()));
    }

    for fb in forbidden {
        if path_is_within(path, &fb) {
            return Err(KbError::MailContainerViolation {
                path: path.to_path_buf(),
                detail: format!("protected container {}", fb.display()),
            });
        }
    }
    Ok(())
}

/// Verifies that an output path is neither inside any mail container (S9) nor
/// inside `cfg.db_dir`.
pub fn assert_safe_out_path(cfg: &MailKbConfig, path: &Path) -> KbResult<()> {
    assert_not_in_mail_container(cfg, path)?;
    if path_is_within(path, &cfg.db_dir) {
        return Err(KbError::SafeOutputViolation {
            path: path.to_path_buf(),
            detail: "refusing_to_write_inside_mailkb_db_dir".to_string(),
        });
    }
    Ok(())
}

/// Validates a database-stored relative path against traversal and platform hazards (S10).
pub fn safe_relpath(rel: &str) -> bool {
    if rel.is_empty() || rel.starts_with('/') {
        return false;
    }
    if rel.contains('\\') || rel.contains('\0') {
        return false;
    }
    let bytes = rel.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        return false;
    }
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return false;
        }
    }
    true
}

/// Safely remaps a database-stored `relpath` into `<root>/<relpath>` (S10).
pub fn remap_relpath(relpath: &str, root: &Path) -> KbResult<PathBuf> {
    if !safe_relpath(relpath) {
        return Err(KbError::PathRejected {
            path: relpath.to_string(),
            reason: "unsafe_relpath".to_string(),
        });
    }
    let root_real = real_allow_missing(root);
    let cand = root_real.join(relpath);
    if cand == root_real || !cand.starts_with(&root_real) {
        return Err(KbError::PathRejected {
            path: relpath.to_string(),
            reason: "escapes_root".to_string(),
        });
    }
    let cand_real = real_allow_missing(&cand);
    if cand_real == root_real || !cand_real.starts_with(&root_real) {
        return Err(KbError::PathRejected {
            path: relpath.to_string(),
            reason: "symlink_escapes_root".to_string(),
        });
    }
    Ok(cand)
}

/// S4: Opens a regular file read-only with `O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`,
/// verifies `S_ISREG` via `fstat`, and clears `O_NONBLOCK` before returning the `File`.
pub fn open_readonly_nofollow(path: &Path) -> KbResult<File> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        KbError::InvalidArgument(format!("path contains NUL byte: {}", path.display()))
    })?;
    let flags = libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if fd < 0 {
        return Err(KbError::Io(io::Error::last_os_error()));
    }

    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(KbError::Io(err));
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_size < 0 {
        unsafe { libc::close(fd) };
        return Err(KbError::Io(io::Error::from_raw_os_error(libc::EINVAL)));
    }

    let cur_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if cur_flags >= 0 && (cur_flags & libc::O_NONBLOCK) != 0 {
        unsafe {
            libc::fcntl(fd, libc::F_SETFL, cur_flags & !libc::O_NONBLOCK);
        }
    }

    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Reads a regular file safely via [`open_readonly_nofollow`], optionally capping
/// output at `max_bytes`. Returns `(bytes, was_truncated)`.
pub fn read_file_readonly(path: &Path, max_bytes: Option<usize>) -> KbResult<(Vec<u8>, bool)> {
    let mut file = open_readonly_nofollow(path)?;
    let meta_len = file.metadata().map(|m| m.len() as usize).unwrap_or(0);
    match max_bytes {
        None => {
            let mut buf = Vec::with_capacity(meta_len);
            file.read_to_end(&mut buf)?;
            Ok((buf, false))
        }
        Some(cap) => {
            let mut buf = Vec::with_capacity(meta_len.min(cap));
            let mut limited = file.take((cap as u64).saturating_add(1));
            limited.read_to_end(&mut buf)?;
            let truncated = buf.len() > cap;
            if truncated {
                buf.truncate(cap);
            }
            Ok((buf, truncated))
        }
    }
}

/// Strips NUL bytes and replaces invalid UTF-8 sequences with U+FFFD.
pub fn sanitize_utf8(bytes: &[u8]) -> String {
    if let Ok(s) = std::str::from_utf8(bytes) {
        if !s.contains('\0') {
            return s.to_owned();
        }
        return s.replace('\0', "");
    }
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid();
        if valid.contains('\0') {
            for ch in valid.chars() {
                if ch != '\0' {
                    out.push(ch);
                }
            }
        } else {
            out.push_str(valid);
        }
        if !chunk.invalid().is_empty() {
            out.push('\u{FFFD}');
        }
    }
    out
}

/// Collapses ASCII whitespace, NBSP (`U+00A0`), and fullwidth space (`U+3000`)
/// into single `' '` characters and trims leading/trailing whitespace.
pub fn collapse_ws(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_ws = true;
    for ch in s.chars() {
        let is_ws = matches!(
            ch,
            ' ' | '\t' | '\r' | '\n' | '\x0B' | '\x0C' | '\u{00A0}' | '\u{3000}'
        );
        if is_ws {
            if !in_ws {
                out.push(' ');
                in_ws = true;
            }
        } else {
            out.push(ch);
            in_ws = false;
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// S11: Sanitizes untrusted text for terminal output.
pub fn term_safe(raw: &str, single_line: bool) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let code = ch as u32;
        if code == 0 {
            continue;
        }
        if code < 0x20 {
            if single_line && (ch == '\r' || ch == '\n' || ch == '\t') {
                out.push(' ');
            } else if ch == '\n' || ch == '\t' {
                out.push(ch);
            }
            continue;
        }
        if code == 0x7F || (0x80..=0x9F).contains(&code) {
            continue;
        }
        out.push(ch);
    }
    if single_line {
        collapse_ws(&out)
    } else {
        out
    }
}

/// Sanitizes `raw` as a single line and truncates to at most `max_chars` Unicode scalar values.
pub fn trunc_chars(raw: &str, max_chars: usize) -> String {
    let flat = term_safe(raw, true);
    let total = flat.chars().count();
    if total <= max_chars {
        return flat;
    }
    let keep = if max_chars > 3 {
        max_chars - 3
    } else {
        max_chars
    };
    let mut out: String = flat.chars().take(keep).collect();
    out.push_str("...");
    out
}

/// S13: Ensures `dir` exists as a real directory (not symlink), owned by `geteuid()`, with `0700` perms.
pub fn ensure_private_dir(dir: &Path) -> KbResult<()> {
    match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        Err(e) => return Err(KbError::Io(e)),
        Ok(_) => {}
    }

    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() {
        return Err(KbError::Staging(format!(
            "refusing symlink private dir: {}",
            dir.display()
        )));
    }
    if !meta.is_dir() {
        return Err(KbError::Staging(format!(
            "private path is not directory: {}",
            dir.display()
        )));
    }
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != euid {
        return Err(KbError::Staging(format!(
            "private dir not owned by effective user (uid={} != euid={}): {}",
            meta.uid(),
            euid,
            dir.display()
        )));
    }
    if (meta.mode() & 0o077) != 0 {
        fs::set_permissions(dir, Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// T4: Non-blocking exclusive advisory file lock (`flock(LOCK_EX | LOCK_NB)`).
pub struct NonBlockingFlock {
    fd: RawFd,
}

impl NonBlockingFlock {
    pub fn try_acquire(path: &Path) -> KbResult<Option<Self>> {
        let fd = open_lock_fd(path)?;
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc == 0 {
            return Ok(Some(Self { fd }));
        }
        let err = io::Error::last_os_error();
        let raw = err.raw_os_error().unwrap_or(0);
        unsafe { libc::close(fd) };
        if raw == libc::EWOULDBLOCK || raw == libc::EAGAIN {
            return Ok(None);
        }
        Err(KbError::Lock(format!("flock {}: {err}", path.display())))
    }
}

impl Drop for NonBlockingFlock {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::flock(self.fd, libc::LOCK_UN);
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

/// Blocking exclusive advisory file lock (`flock(LOCK_EX)`).
pub struct BlockingFlock {
    fd: RawFd,
}

impl BlockingFlock {
    pub fn acquire(path: &Path) -> KbResult<Self> {
        let fd = open_lock_fd(path)?;
        loop {
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if rc == 0 {
                return Ok(Self { fd });
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            unsafe { libc::close(fd) };
            return Err(KbError::Lock(format!("flock {}: {err}", path.display())));
        }
    }
}

impl Drop for BlockingFlock {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::flock(self.fd, libc::LOCK_UN);
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

fn open_lock_fd(path: &Path) -> KbResult<RawFd> {
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        KbError::InvalidArgument(format!("lock path contains NUL byte: {}", path.display()))
    })?;
    let flags = libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    let fd = unsafe { libc::open(c_path.as_ptr(), flags, 0o600 as libc::c_uint) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        return Err(KbError::Lock(format!("open lock {}: {err}", path.display())));
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 || (st.st_mode & libc::S_IFMT) != libc::S_IFREG {
        unsafe { libc::close(fd) };
        return Err(KbError::Lock(format!(
            "lock path is not a regular file: {}",
            path.display()
        )));
    }
    if (st.st_mode & 0o077) != 0 {
        unsafe {
            libc::fchmod(fd, 0o600);
        }
    }
    Ok(fd)
}

/// Calls `fsync` on a directory descriptor (best-effort).
pub fn fsync_dir(dir: &Path) {
    let Ok(c_dir) = CString::new(dir.as_os_str().as_bytes()) else {
        return;
    };
    let fd = unsafe {
        libc::open(
            c_dir.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd >= 0 {
        unsafe {
            libc::fsync(fd);
            libc::close(fd);
        }
    }
}
