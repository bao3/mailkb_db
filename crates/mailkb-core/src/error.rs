use std::fmt;
use std::path::PathBuf;

/// Unified result alias for `mailkb-core` and downstream crates.
pub type KbResult<T> = Result<T, KbError>;

/// Common error type across `mailkb_db`.
///
/// Deterministic process exit codes:
/// - `2`: security / validation / invalid CLI argument errors
/// - `3`: exclusive lock busy
/// - `4`: runtime / I/O / SQLite / staging / publish errors
#[derive(Debug)]
pub enum KbError {
    /// Attempted to write, stage, build inside, or directly open a protected mail container (S9).
    MailContainerViolation { path: PathBuf, detail: String },
    /// Attempted to write arbitrary output inside `db_dir`.
    SafeOutputViolation { path: PathBuf, detail: String },
    /// Untrusted relative path rejected by `safe_relpath` / `remap_relpath` (S10).
    PathRejected { path: String, reason: String },
    /// Invalid CLI flag, argument, or input format.
    InvalidArgument(String),
    /// Domain pack schema or regex validation error.
    PackValidation(String),
    /// Non-blocking exclusive lock is held by another sync process.
    LockBusy(String),
    /// Missing database, file, or record.
    NotFound(String),
    /// SQLite error.
    Sqlite(rusqlite::Error),
    /// Filesystem / OS I/O error.
    Io(std::io::Error),
    /// Runtime staging verification failure (T2).
    Staging(String),
    /// Atomic database publish failure (T3).
    Publish(String),
    /// Bounded OOXML/ZIP extraction failure (S1).
    Ooxml(String),
    /// File locking failure (T4).
    Lock(String),
    /// Generic operational error.
    Other(String),
}

impl KbError {
    /// Process exit code convention:
    /// - `2` for safety/validation/argument errors
    /// - `3` for lock busy
    /// - `4` for runtime/I/O/SQLite errors
    pub fn exit_code(&self) -> i32 {
        match self {
            KbError::MailContainerViolation { .. }
            | KbError::SafeOutputViolation { .. }
            | KbError::PathRejected { .. }
            | KbError::InvalidArgument(_)
            | KbError::PackValidation(_) => 2,
            KbError::LockBusy(_) => 3,
            KbError::NotFound(_)
            | KbError::Sqlite(_)
            | KbError::Io(_)
            | KbError::Staging(_)
            | KbError::Publish(_)
            | KbError::Ooxml(_)
            | KbError::Lock(_)
            | KbError::Other(_) => 4,
        }
    }

    /// Returns `true` when the error represents an S9 mail container guard violation.
    pub fn is_mail_container_violation(&self) -> bool {
        matches!(self, KbError::MailContainerViolation { .. })
    }

    /// Formats the error as a JSON object suitable for `--json` CLI output.
    pub fn to_json_value(&self, warnings: &[String]) -> serde_json::Value {
        serde_json::json!({
            "status": "error",
            "exit_code": self.exit_code(),
            "error": self.to_string(),
            "warnings": warnings,
        })
    }
}

impl fmt::Display for KbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KbError::MailContainerViolation { path, detail } => {
                if detail.is_empty() {
                    write!(f, "refusing_mail_container_violation: {}", path.display())
                } else {
                    write!(
                        f,
                        "refusing_mail_container_violation: {} ({})",
                        path.display(),
                        detail
                    )
                }
            }
            KbError::SafeOutputViolation { path, detail } => {
                write!(f, "{detail}: {}", path.display())
            }
            KbError::PathRejected { path, reason } => {
                write!(f, "path_rejected ({reason}): {path}")
            }
            KbError::InvalidArgument(msg) => write!(f, "{msg}"),
            KbError::PackValidation(msg) => write!(f, "pack_validation_error: {msg}"),
            KbError::LockBusy(msg) => write!(f, "lock_busy: {msg}"),
            KbError::NotFound(msg) => write!(f, "{msg}"),
            KbError::Sqlite(err) => write!(f, "sqlite error: {err}"),
            KbError::Io(err) => write!(f, "io error: {err}"),
            KbError::Staging(msg) => write!(f, "{msg}"),
            KbError::Publish(msg) => write!(f, "{msg}"),
            KbError::Ooxml(msg) => write!(f, "ooxml error: {msg}"),
            KbError::Lock(msg) => write!(f, "lock error: {msg}"),
            KbError::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for KbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KbError::Sqlite(e) => Some(e),
            KbError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for KbError {
    fn from(value: std::io::Error) -> Self {
        KbError::Io(value)
    }
}

impl From<rusqlite::Error> for KbError {
    fn from(value: rusqlite::Error) -> Self {
        KbError::Sqlite(value)
    }
}

impl From<serde_json::Error> for KbError {
    fn from(value: serde_json::Error) -> Self {
        KbError::Other(format!("json error: {value}"))
    }
}
