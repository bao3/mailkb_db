//! Environment, database path, runtime cache, pack discovery, and thread configuration.

use crate::security::{expand_tilde, real_allow_missing};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

/// Canonical cold database filename (`mailkb_db.sqlite`).
pub const DEFAULT_DB_FILENAME: &str = "mailkb_db.sqlite";

/// Canonical filename stem (`mailkb_db`).
pub const DEFAULT_DB_STEM: &str = "mailkb_db";

/// Cross-platform environment and path configuration shared by all `mailkb_db` engines.
#[derive(Debug, Clone)]
pub struct MailKbConfig {
    /// Directory containing the cold published database (`~/.local/share/mailkb_db`).
    pub db_dir: PathBuf,
    /// Full path to the cold SQLite database (`~/.local/share/mailkb_db/mailkb_db.sqlite`).
    pub db_path: PathBuf,
    /// Private `0700` hot staging runtime cache directory (`~/.cache/mailkb_db`).
    pub runtime_dir: PathBuf,
    /// Directory searched for auto-loaded domain packs (`~/.config/mailkb_db/packs`).
    pub packs_dir: PathBuf,
    /// Explicit or auto-discovered JSON domain pack file paths.
    pub pack_paths: Vec<PathBuf>,
    /// Explicitly disable loading all domain packs (pure universal mode).
    pub no_packs: bool,
    /// Apple Mail V10 directory (`~/Library/Mail/V10` on macOS).
    pub apple_mail_v10_dir: Option<PathBuf>,
    /// Optional account UUID / email filters; empty means auto-discover all accounts.
    pub account_filters: Vec<String>,
    /// Standalone `.eml` / `.emlx` directories to ingest in addition to / instead of Apple Mail.
    pub eml_dirs: Vec<PathBuf>,
    /// Outlook macOS profile directory (protected by S9 write guards).
    pub outlook_profile_dir: Option<PathBuf>,
    /// Bounded worker thread count (`1..=12` auto, up to `64` explicit).
    pub max_threads: usize,
}

impl MailKbConfig {
    /// Discovers defaults from environment variables and standard XDG/macOS directories.
    pub fn discover() -> Self {
        let home = env_non_empty("HOME").map(PathBuf::from);

        let db_dir_raw = env_non_empty("MAILKB_DB_DIR")
            .map(|v| expand_tilde(&v))
            .unwrap_or_else(|| {
                if let Some(ref h) = home {
                    h.join(".local/share/mailkb_db")
                } else {
                    let uid = unsafe { libc::getuid() };
                    PathBuf::from(format!("/tmp/mailkb-db-data-{uid}"))
                }
            });
        let db_dir = real_allow_missing(&db_dir_raw);

        let db_path = env_non_empty("MAILKB_DB_PATH")
            .map(|v| real_allow_missing(&expand_tilde(&v)))
            .unwrap_or_else(|| db_dir.join(DEFAULT_DB_FILENAME));

        let runtime_dir_raw = env_non_empty("MAILKB_DB_RUNTIME_DIR")
            .or_else(|| env_non_empty("MAILKB_RUNTIME_DIR"))
            .map(|v| expand_tilde(&v))
            .unwrap_or_else(|| {
                if let Some(ref h) = home {
                    h.join(".cache/mailkb_db")
                } else {
                    let uid = unsafe { libc::getuid() };
                    PathBuf::from(format!("/tmp/mailkb-db-runtime-{uid}"))
                }
            });
        let runtime_dir = real_allow_missing(&runtime_dir_raw);

        let packs_dir_raw = env_non_empty("MAILKB_DB_PACKS_DIR")
            .map(|v| expand_tilde(&v))
            .unwrap_or_else(|| {
                if let Some(ref h) = home {
                    h.join(".config/mailkb_db/packs")
                } else {
                    let uid = unsafe { libc::getuid() };
                    PathBuf::from(format!("/tmp/mailkb-db-packs-{uid}"))
                }
            });
        let packs_dir = real_allow_missing(&packs_dir_raw);

        let no_packs = env_non_empty("MAILKB_DB_NO_PACKS")
            .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
            .unwrap_or(false);

        let pack_paths = if no_packs {
            Vec::new()
        } else if let Some(raw_packs) = env_non_empty("MAILKB_DB_PACK") {
            split_path_list(&raw_packs)
        } else {
            discover_packs_in_dir(&packs_dir)
        };

        let apple_mail_v10_dir = env_non_empty("APPLE_MAIL_V10_DIR")
            .map(|v| expand_tilde(&v))
            .or_else(|| {
                #[cfg(target_os = "macos")]
                {
                    home.as_ref().map(|h| h.join("Library/Mail/V10"))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    None
                }
            });

        let account_filters = env_non_empty("MAILKB_DB_ACCOUNTS")
            .or_else(|| env_non_empty("MAILKB_DB_ACCOUNT"))
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let eml_dirs = env_non_empty("MAILKB_DB_EML_DIR")
            .map(|raw| split_path_list(&raw))
            .unwrap_or_default();

        let outlook_profile_dir = env_non_empty("OUTLOOK_PROFILE_DIR")
            .map(|v| expand_tilde(&v))
            .or_else(|| {
                #[cfg(target_os = "macos")]
                {
                    home.as_ref().map(|h| {
                        h.join("Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/Main Identity")
                    })
                }
                #[cfg(not(target_os = "macos"))]
                {
                    None
                }
            });

        let max_threads = detect_max_threads();

        Self {
            db_dir,
            db_path,
            runtime_dir,
            packs_dir,
            pack_paths,
            no_packs,
            apple_mail_v10_dir,
            account_filters,
            eml_dirs,
            outlook_profile_dir,
            max_threads,
        }
    }

    /// Returns the configured cold database path.
    pub fn primary_db_path(&self) -> &Path {
        &self.db_path
    }

    /// Returns a cloned config with `db_path` overridden (supporting `~/`).
    pub fn with_db_override(&self, db_path: &Path) -> Self {
        let mut cloned = self.clone();
        let expanded = real_allow_missing(&expand_tilde(&db_path.to_string_lossy()));
        if let Some(parent) = expanded.parent().filter(|p| !p.as_os_str().is_empty()) {
            cloned.db_dir = parent.to_path_buf();
        }
        cloned.db_path = expanded;
        cloned
    }

    /// Returns a cloned config with `db_dir` overridden (and `db_path` updated to `<db_dir>/mailkb_db.sqlite`).
    pub fn with_db_dir_override(&self, db_dir: &Path) -> Self {
        let mut cloned = self.clone();
        let expanded = real_allow_missing(&expand_tilde(&db_dir.to_string_lossy()));
        cloned.db_dir = expanded.clone();
        cloned.db_path = expanded.join(DEFAULT_DB_FILENAME);
        cloned
    }

    /// Returns a cloned config with `runtime_dir` overridden (supporting `~/`).
    pub fn with_runtime_dir_override(&self, runtime_dir: &Path) -> Self {
        let mut cloned = self.clone();
        cloned.runtime_dir = real_allow_missing(&expand_tilde(&runtime_dir.to_string_lossy()));
        cloned
    }

    /// Returns a cloned config with explicit domain pack selection or `no_packs`.
    pub fn with_pack_overrides(&self, packs: &[PathBuf], no_packs: bool) -> Self {
        let mut cloned = self.clone();
        cloned.no_packs = no_packs;
        if no_packs {
            cloned.pack_paths.clear();
        } else if !packs.is_empty() {
            cloned.pack_paths = packs
                .iter()
                .map(|p| real_allow_missing(&expand_tilde(&p.to_string_lossy())))
                .collect();
        }
        cloned
    }

    /// Computes `<stem>-<sha256(realpath(src))[..12]>.sqlite` for non-canonical DB paths.
    pub fn custom_db_slot_name(stem: &str, src_db: &Path) -> String {
        let src_real = real_allow_missing(src_db);
        let mut hasher = Sha256::new();
        hasher.update(src_real.to_string_lossy().as_bytes());
        let hex = format!("{:x}", hasher.finalize());
        format!("{stem}-{}.sqlite", &hex[..12])
    }

    /// Resolves the hot runtime staging path inside `runtime_dir`.
    /// Canonical default `<db_dir>/mailkb_db.sqlite` maps to `<runtime_dir>/mailkb_db.sqlite`
    /// so external readers (e.g. macOS Mail extensions) have a stable path.
    pub fn runtime_db_for_path(&self, default_stem: &str, src_db: &Path) -> PathBuf {
        let canonical_default =
            real_allow_missing(&self.db_dir.join(format!("{default_stem}.sqlite")));
        let src_real = real_allow_missing(src_db);
        if src_real == canonical_default {
            self.runtime_dir.join(format!("{default_stem}.sqlite"))
        } else {
            self.runtime_dir
                .join(Self::custom_db_slot_name(default_stem, src_db))
        }
    }
}

/// Discovers readable `*.json` pack files in `packs_dir` in deterministic lexical order.
pub fn discover_packs_in_dir(packs_dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(packs_dir) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| !n.starts_with('.'))
        })
        .collect();
    found.sort();
    found
}

fn split_path_list(raw: &str) -> Vec<PathBuf> {
    raw.split([',', ':'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| real_allow_missing(&expand_tilde(s)))
        .collect()
}

fn env_non_empty(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parses Linux cgroup v2 `cpu.max` content into a ceiling integer CPU count.
pub fn parse_cgroup_cpu_max(content: &str) -> Option<usize> {
    let trimmed = content.trim();
    if trimmed.is_empty() || trimmed.starts_with("max") {
        return None;
    }
    let mut parts = trimmed.split_whitespace();
    let quota: i64 = parts.next()?.parse().ok()?;
    let period: i64 = parts.next()?.parse().ok()?;
    if quota > 0 && period > 0 {
        let cpus = (quota + period - 1) / period;
        Some(cpus.max(1) as usize)
    } else {
        None
    }
}

/// Detects bounded worker thread concurrency (`MAILKB_DB_THREADS` or host CPU quota, clamped `1..=12` auto).
pub fn detect_max_threads() -> usize {
    if let Some(raw) = env_non_empty("MAILKB_DB_THREADS") {
        if let Ok(v) = raw.parse::<usize>() {
            if (1..=64).contains(&v) {
                return v;
            }
        }
    }

    #[allow(unused_mut)]
    let mut n = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(1)
        .max(1);

    #[cfg(target_os = "linux")]
    {
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            if libc::sched_getaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &mut set) == 0 {
                let c = libc::CPU_COUNT(&set);
                if c > 0 {
                    n = n.min(c as usize);
                }
            }
        }
        if let Ok(v2) = std::fs::read_to_string("/sys/fs/cgroup/cpu.max") {
            if let Some(c) = parse_cgroup_cpu_max(&v2) {
                n = n.min(c);
            }
        }
    }

    n.clamp(1, 12)
}
