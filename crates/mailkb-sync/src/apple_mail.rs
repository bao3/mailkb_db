//! Multi-account Apple Mail `V10` (`ews://`, `imap://`, `pop://`, `local://`) discovery,
//! `Envelope Index` safe staging, Sent-folder identity inference, `.emlx`/`.eml` parsing,
//! and disk/MIME attachment extraction.

use crate::enrich::{
    classify_att_noise, enrich_message, extract_emails, is_freemail_domain, is_noreply_local,
    is_sent_folder, lower_ext_of, mime_from_ext, EnrichedMsg, InferredIdentity, RawAttachmentInput,
    RawMessageInput, ResolvedIdentity, MAX_BODY_LATEST_BYTES, MAX_BODY_QUOTED_STORE,
};
use crate::html::parse_html_clean_and_tables;
use crate::mime::{
    collect_mime_parts, extract_header_str, find_reply_split_offset,
    format_header_address_from_env, norm_uid_from_fields, parse_rfc5322_date, percent_decode,
    slice_emlx_rfc822, split_mime_headers_body, MimeInlineAtt,
};
use mailkb_core::config::MailKbConfig;
use mailkb_core::domain_pack::CompiledDomainPack;
use mailkb_core::error::{KbError, KbResult};
use mailkb_core::ooxml::{extract_docx_from_bytes, extract_xlsx_from_bytes, OoxmlOptions};
use mailkb_core::publish::sha256_bytes;
use mailkb_core::security::{
    ensure_private_dir, open_readonly_nofollow, read_file_readonly, safe_relpath, sanitize_utf8,
};
use mailkb_core::strutil::{contains_any_ci, contains_ci, trim_ascii_ws, utf8_trunc_sv};
use mailkb_core::time::format_local_datetime;
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_EMLX_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_EML_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MasterState {
    Master,
    NotMaster(String),
    AccessDenied(String),
}

fn is_perm_denied(err: &io::Error) -> bool {
    if err.kind() == io::ErrorKind::PermissionDenied {
        return true;
    }
    matches!(err.raw_os_error(), Some(libc::EACCES | libc::EPERM))
}

/// Inspects `cfg.apple_mail_v10_dir` readability without writing to the Mail container.
pub fn mail_master_state(cfg: &MailKbConfig) -> MasterState {
    let host_os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    let Some(ref v10_dir) = cfg.apple_mail_v10_dir else {
        return MasterState::NotMaster(format!("no Apple Mail store configured ({host_os})"));
    };
    if v10_dir.as_os_str().is_empty() {
        return MasterState::NotMaster(format!("no Apple Mail store configured ({host_os})"));
    }

    let env_idx = v10_dir.join("MailData/Envelope Index");
    match fs::metadata(&env_idx) {
        Err(e) => {
            if is_perm_denied(&e) {
                return MasterState::AccessDenied(format!(
                    "mail_access_denied (grant Full Disk Access): {}",
                    env_idx.display()
                ));
            }
            return MasterState::NotMaster(format!(
                "Envelope Index missing: {}",
                env_idx.display()
            ));
        }
        Ok(meta) => {
            if !meta.is_file() {
                return MasterState::NotMaster(format!(
                    "Envelope Index is not regular file: {}",
                    env_idx.display()
                ));
            }
        }
    }

    match open_readonly_nofollow(&env_idx) {
        Err(KbError::Io(e)) => {
            if is_perm_denied(&e) {
                return MasterState::AccessDenied(format!(
                    "mail_access_denied (grant Full Disk Access): {e}"
                ));
            }
            return MasterState::NotMaster(format!("cannot open Envelope Index: {e}"));
        }
        Err(e) => {
            return MasterState::NotMaster(format!("cannot open Envelope Index: {e}"));
        }
        Ok(_f) => {}
    }

    if let Err(e) = fs::read_dir(v10_dir) {
        if is_perm_denied(&e) {
            return MasterState::AccessDenied(format!(
                "mail_access_denied (grant Full Disk Access): opendir V10: {e}"
            ));
        }
        return MasterState::NotMaster(format!("cannot opendir V10: {e}"));
    }

    MasterState::Master
}

#[inline]
pub fn meta_mtime_ns(meta: &fs::Metadata) -> i64 {
    meta.mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(meta.mtime_nsec())
}

#[derive(Debug, Clone, Default)]
pub struct StagedEnvelopeInfo {
    pub env_path: PathBuf,
    pub idx_size: i64,
    pub idx_mtime_ns: i64,
    pub wal_size: i64,
    pub wal_mtime_ns: i64,
}

fn copy_file_private(src: &Path, dst: &Path) -> KbResult<fs::Metadata> {
    let mut in_f = open_readonly_nofollow(src)?;
    let meta = in_f.metadata()?;
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
    Ok(meta)
}

/// Copies `Envelope Index` (+ optional `-wal` / `-shm`) read-only into a private staging dir.
pub fn copy_envelope_index_to_dir(
    v10_dir: &Path,
    dst_dir: &Path,
) -> KbResult<StagedEnvelopeInfo> {
    ensure_private_dir(dst_dir)?;
    let mail_data = v10_dir.join("MailData");
    let mut info = StagedEnvelopeInfo {
        env_path: dst_dir.join("Envelope Index"),
        ..Default::default()
    };

    for fname in ["Envelope Index", "Envelope Index-wal", "Envelope Index-shm"] {
        let src = mail_data.join(fname);
        let lmeta = match fs::symlink_metadata(&src) {
            Ok(m) => m,
            Err(e) => {
                if fname == "Envelope Index" {
                    return Err(KbError::NotFound(format!(
                        "missing {}: {e}",
                        src.display()
                    )));
                }
                continue;
            }
        };
        if lmeta.file_type().is_symlink() || !lmeta.is_file() {
            if fname == "Envelope Index" {
                return Err(KbError::Staging(format!(
                    "Envelope Index is not a regular file: {}",
                    src.display()
                )));
            }
            continue;
        }
        let meta = copy_file_private(&src, &dst_dir.join(fname))?;
        if fname == "Envelope Index" {
            info.idx_size = meta.len() as i64;
            info.idx_mtime_ns = meta_mtime_ns(&meta);
        } else if fname == "Envelope Index-wal" {
            info.wal_size = meta.len() as i64;
            info.wal_mtime_ns = meta_mtime_ns(&meta);
        }
    }
    Ok(info)
}

pub fn open_staged_envelope_ro(env_path: &Path) -> KbResult<Connection> {
    let conn = Connection::open_with_flags(
        env_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.execute_batch("PRAGMA query_only = ON;")?;
    Ok(conn)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMailboxUrl {
    pub scheme: String,
    pub account_id: String,
    pub folder_path: String,
}

/// Parses an Apple Mail `Envelope Index` `mailboxes.url` across `ews://`, `imap://`, `pop://`,
/// and `local://` schemes.
pub fn parse_mailbox_url(url: &str) -> Option<ParsedMailboxUrl> {
    let (raw_scheme, rest) = url.split_once("://")?;
    let scheme = raw_scheme.trim().to_ascii_lowercase();
    if !matches!(scheme.as_str(), "ews" | "imap" | "pop" | "local") {
        return None;
    }

    if scheme == "local" {
        if let Some(after_empty_host) = rest.strip_prefix('/') {
            let folder = percent_decode(after_empty_host.trim_matches('/').as_bytes());
            return Some(ParsedMailboxUrl {
                scheme,
                account_id: "local".to_string(),
                folder_path: folder,
            });
        }
        if let Some((raw_acct, raw_sub)) = rest.split_once('/') {
            let acct = percent_decode(raw_acct.as_bytes());
            let folder = percent_decode(raw_sub.trim_matches('/').as_bytes());
            return Some(ParsedMailboxUrl {
                scheme,
                account_id: if acct.is_empty() {
                    "local".to_string()
                } else {
                    acct
                },
                folder_path: folder,
            });
        }
        let folder = percent_decode(rest.trim_matches('/').as_bytes());
        return Some(ParsedMailboxUrl {
            scheme,
            account_id: "local".to_string(),
            folder_path: folder,
        });
    }

    let (raw_acct, raw_sub) = match rest.split_once('/') {
        Some((a, s)) => (a, s),
        None => (rest, ""),
    };
    let account_id = percent_decode(raw_acct.as_bytes());
    if account_id.is_empty() {
        return None;
    }
    let folder_path = percent_decode(raw_sub.trim_matches('/').as_bytes());
    Some(ParsedMailboxUrl {
        scheme,
        account_id,
        folder_path,
    })
}

#[derive(Debug, Clone, Default)]
pub struct MailboxInfo {
    pub rowid: i64,
    pub url: String,
    pub scheme: String,
    pub account_id: String,
    pub folder_path: String,
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DiscoveredAccount {
    pub account_id: String,
    pub scheme: String,
    pub mailbox_count: usize,
    pub message_count: i64,
    pub inferred_emails: Vec<String>,
    pub folders: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct EnvelopeRow {
    pub rowid: i64,
    pub mailbox_id: i64,
    pub date_sent: i64,
    pub date_received: i64,
    pub size_bytes: i64,
    pub subject: String,
    pub sender: String,
    pub recipients: String,
    pub cc: String,
    pub summary: String,
    pub message_id_header: String,
}

#[derive(Debug, Clone, Default)]
pub struct CopyLocation {
    pub rowid: i64,
    pub mailbox_id: i64,
    pub account_id: String,
    pub emlx_path: Option<PathBuf>,
    pub shard_dir: Option<PathBuf>,
    pub is_partial: bool,
    pub folder_path: String,
}

#[derive(Debug, Clone)]
pub struct WorkItem {
    pub is_eml: bool,
    pub is_emlx_standalone: bool,
    pub sort_ts: i64,
    pub uid_key: String,
    pub account_id: String,
    pub date_iso: String,
    pub env: EnvelopeRow,
    pub primary_loc: CopyLocation,
    pub secondary_locs: Vec<CopyLocation>,
    pub eml_abs_path: PathBuf,
    pub eml_rel_path: String,
    pub merged_eml_relpaths: Vec<String>,
}

pub fn reversed_shard_path(rowid: i64) -> String {
    let bucket = rowid / 1000;
    if bucket <= 0 {
        return String::new();
    }
    let s = bucket.to_string();
    s.bytes()
        .rev()
        .map(|b| (b as char).to_string())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn find_data_dir_for_mbox(mbox_dir: &Path) -> Option<PathBuf> {
    let direct_data = mbox_dir.join("Data");
    if let Ok(meta) = fs::metadata(&direct_data) {
        if meta.is_dir() {
            return Some(direct_data);
        }
    }
    let entries = fs::read_dir(mbox_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(ns) = name.to_str() else { continue };
        if ns.starts_with('.') {
            continue;
        }
        let nb = ns.as_bytes();
        if nb.len() == 36 && nb[8] == b'-' && nb[13] == b'-' && nb[18] == b'-' && nb[23] == b'-' {
            let cand = mbox_dir.join(ns).join("Data");
            if let Ok(meta) = fs::metadata(&cand) {
                if meta.is_dir() {
                    return Some(cand);
                }
            }
        }
    }
    None
}

fn resolve_mbox_data_dir(v10_dir: &Path, account_id: &str, folder_path: &str) -> Option<PathBuf> {
    let push_mbox_segs = |base: &Path, folder: &str| -> PathBuf {
        let mut p = base.to_path_buf();
        for seg in folder.split('/') {
            if !seg.is_empty() {
                if seg.ends_with(".mbox") {
                    p.push(seg);
                } else {
                    p.push(format!("{seg}.mbox"));
                }
            }
        }
        p
    };

    let direct_root = v10_dir.join(account_id);
    if direct_root.is_dir() {
        let mbox_path = push_mbox_segs(&direct_root, folder_path);
        if let Some(d) = find_data_dir_for_mbox(&mbox_path) {
            return Some(d);
        }
    }

    if account_id == "local" {
        if let Ok(entries) = fs::read_dir(v10_dir) {
            for ent in entries.flatten() {
                let p = ent.path();
                if p.is_dir() {
                    let mbox_path = push_mbox_segs(&p, folder_path);
                    if let Some(d) = find_data_dir_for_mbox(&mbox_path) {
                        return Some(d);
                    }
                }
            }
        }
    }
    None
}

pub fn folder_rank_bonus(fp: &str) -> i32 {
    if fp.is_empty() {
        return 0;
    }
    if fp.contains("已删除")
        || contains_any_ci(fp, &["deleted", "trash", "junk", "垃圾邮件"])
    {
        return -2;
    }
    if fp == "收件箱" || fp.eq_ignore_ascii_case("INBOX") {
        return 3;
    }
    if fp.starts_with("收件箱/") || contains_ci(fp, "inbox") {
        return 2;
    }
    1
}

pub fn resolve_copy_location(er: &EnvelopeRow, mb: Option<&MailboxInfo>) -> CopyLocation {
    let mut loc = CopyLocation {
        rowid: er.rowid,
        mailbox_id: er.mailbox_id,
        account_id: mb.map(|m| m.account_id.clone()).unwrap_or_default(),
        folder_path: mb.map(|m| m.folder_path.clone()).unwrap_or_default(),
        ..Default::default()
    };
    let Some(data_dir) = mb.and_then(|m| m.data_dir.as_ref()) else {
        return loc;
    };
    let shard = reversed_shard_path(er.rowid);
    let shard_dir = if shard.is_empty() {
        data_dir.clone()
    } else {
        data_dir.join(&shard)
    };
    let p_emlx = shard_dir.join(format!("Messages/{}.emlx", er.rowid));
    if let Ok(st) = fs::symlink_metadata(&p_emlx) {
        if !st.file_type().is_symlink() && st.is_file() {
            loc.shard_dir = Some(shard_dir);
            loc.emlx_path = Some(p_emlx);
            loc.is_partial = false;
            return loc;
        }
    }
    let p_part = shard_dir.join(format!("Messages/{}.partial.emlx", er.rowid));
    if let Ok(st) = fs::symlink_metadata(&p_part) {
        if !st.file_type().is_symlink() && st.is_file() {
            loc.shard_dir = Some(shard_dir);
            loc.emlx_path = Some(p_part);
            loc.is_partial = true;
            return loc;
        }
    }
    loc.shard_dir = Some(shard_dir);
    loc
}

/// Discovers all mailboxes across `ews://`, `imap://`, `pop://`, and `local://` in `Envelope Index`.
pub fn load_all_mailboxes(
    env_db: &Connection,
    v10_dir: &Path,
) -> KbResult<HashMap<i64, MailboxInfo>> {
    let mut map = HashMap::new();
    let mut stmt = env_db.prepare("SELECT ROWID, url FROM mailboxes")?;
    let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
    for row_res in rows {
        let (rowid, url) = row_res?;
        let Some(parsed) = parse_mailbox_url(&url) else {
            continue;
        };
        let data_dir = resolve_mbox_data_dir(v10_dir, &parsed.account_id, &parsed.folder_path);
        map.insert(
            rowid,
            MailboxInfo {
                rowid,
                url,
                scheme: parsed.scheme,
                account_id: parsed.account_id,
                folder_path: parsed.folder_path,
                data_dir,
            },
        );
    }
    Ok(map)
}

/// Auto-infers `self_emails` and non-freemail `internal_domains` from `Sent` / `已发送` /
/// `Sent Messages` / `Sent Items` mailbox senders in `Envelope Index`.
pub fn infer_identity_from_envelope_db(
    env_db: &Connection,
    mailboxes: &HashMap<i64, MailboxInfo>,
) -> KbResult<(InferredIdentity, HashMap<String, Vec<String>>)> {
    let mut sent_ids: Vec<i64> = mailboxes
        .values()
        .filter(|mb| is_sent_folder(&mb.folder_path))
        .map(|mb| mb.rowid)
        .collect();
    sent_ids.sort_unstable();

    let mut per_acct_counts: BTreeMap<String, HashMap<String, i64>> = BTreeMap::new();
    let mut global_counts: HashMap<String, i64> = HashMap::new();

    if !sent_ids.is_empty() {
        let id_list = sent_ids
            .iter()
            .map(i64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT m.mailbox, LOWER(TRIM(COALESCE(a.address, ''))), COUNT(*) \
             FROM messages m LEFT JOIN addresses a ON m.sender = a.ROWID \
             WHERE m.mailbox IN ({id_list}) AND COALESCE(m.deleted, 0) = 0 \
             GROUP BY m.mailbox, LOWER(TRIM(COALESCE(a.address, '')))"
        );
        if let Ok(mut stmt) = env_db.prepare(&sql) {
            let iter = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            });
            if let Ok(rows) = iter {
                for row in rows.flatten() {
                    let (mb_id, raw_addr, cnt) = row;
                    if raw_addr.is_empty() || cnt <= 0 {
                        continue;
                    }
                    let Some(mb) = mailboxes.get(&mb_id) else {
                        continue;
                    };
                    for em in extract_emails(&raw_addr) {
                        if is_noreply_local(&em.local) {
                            continue;
                        }
                        *per_acct_counts
                            .entry(mb.account_id.clone())
                            .or_default()
                            .entry(em.addr.clone())
                            .or_insert(0) += cnt;
                        *global_counts.entry(em.addr).or_insert(0) += cnt;
                    }
                }
            }
        }
    }

    let mut per_account_emails: HashMap<String, Vec<String>> = HashMap::new();
    let mut self_emails_set: BTreeSet<String> = BTreeSet::new();
    let mut internal_domains_set: BTreeSet<String> = BTreeSet::new();

    for (acct_id, counts) in per_acct_counts {
        let total: i64 = counts.values().sum();
        let mut ranked: Vec<(String, i64)> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut acct_list = Vec::new();
        for (idx, (addr, cnt)) in ranked.into_iter().enumerate() {
            let min_ratio_ok = total <= 5 || (cnt * 10 >= total); // >= 10% of Sent
            if idx == 0 || (cnt >= 2 && min_ratio_ok) {
                self_emails_set.insert(addr.clone());
                if let Some((_, dom)) = addr.split_once('@') {
                    if !is_freemail_domain(dom) {
                        internal_domains_set.insert(dom.to_string());
                    }
                }
                acct_list.push(addr);
                if acct_list.len() >= 4 {
                    break;
                }
            }
        }
        per_account_emails.insert(acct_id, acct_list);
    }

    let inferred = InferredIdentity {
        self_emails: self_emails_set.into_iter().collect(),
        internal_domains: internal_domains_set.into_iter().collect(),
    };
    Ok((inferred, per_account_emails))
}

/// Auto-infers Sent identities from already-loaded `(folder_path, sender)` pairs (for `.eml` / legacy DB).
pub fn infer_identity_from_messages<'a, I>(items: I) -> InferredIdentity
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    let mut counts: HashMap<String, i64> = HashMap::new();
    for (folder, sender) in items {
        if !is_sent_folder(folder) {
            continue;
        }
        for em in extract_emails(sender) {
            if !is_noreply_local(&em.local) {
                *counts.entry(em.addr).or_insert(0) += 1;
            }
        }
    }
    let total: i64 = counts.values().sum();
    let mut ranked: Vec<(String, i64)> = counts.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let mut self_emails = Vec::new();
    let mut doms = BTreeSet::new();
    for (idx, (addr, cnt)) in ranked.into_iter().enumerate() {
        if idx == 0 || (cnt >= 2 && (total <= 5 || cnt * 10 >= total)) {
            if let Some((_, dom)) = addr.split_once('@') {
                if !is_freemail_domain(dom) {
                    doms.insert(dom.to_string());
                }
            }
            self_emails.push(addr);
            if self_emails.len() >= 5 {
                break;
            }
        }
    }
    InferredIdentity {
        self_emails,
        internal_domains: doms.into_iter().collect(),
    }
}

pub fn discover_accounts_and_filter(
    env_db: &Connection,
    mailboxes: &HashMap<i64, MailboxInfo>,
    per_account_emails: &HashMap<String, Vec<String>>,
    account_filters: &[String],
) -> KbResult<(Vec<DiscoveredAccount>, Vec<i64>)> {
    let mut msg_counts_by_mb: HashMap<i64, i64> = HashMap::new();
    if let Ok(mut stmt) = env_db.prepare(
        "SELECT mailbox, COUNT(*) FROM messages WHERE COALESCE(deleted, 0) = 0 GROUP BY mailbox",
    ) {
        if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?))) {
            for r in rows.flatten() {
                msg_counts_by_mb.insert(r.0, r.1);
            }
        }
    }

    let mut by_acct: BTreeMap<String, DiscoveredAccount> = BTreeMap::new();
    for mb in mailboxes.values() {
        let entry = by_acct
            .entry(mb.account_id.clone())
            .or_insert_with(|| DiscoveredAccount {
                account_id: mb.account_id.clone(),
                scheme: mb.scheme.clone(),
                mailbox_count: 0,
                message_count: 0,
                inferred_emails: per_account_emails
                    .get(&mb.account_id)
                    .cloned()
                    .unwrap_or_default(),
                folders: Vec::new(),
            });
        entry.mailbox_count += 1;
        entry.message_count += msg_counts_by_mb.get(&mb.rowid).copied().unwrap_or(0);
        if !mb.folder_path.is_empty() && !entry.folders.contains(&mb.folder_path) {
            entry.folders.push(mb.folder_path.clone());
        }
    }
    for acct in by_acct.values_mut() {
        acct.folders.sort();
    }

    let filters_lo: Vec<String> = account_filters
        .iter()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let mut allowed_accts: HashSet<String> = HashSet::new();
    let mut accounts_out: Vec<DiscoveredAccount> = Vec::new();
    for acct in by_acct.into_values() {
        let matched = if filters_lo.is_empty() {
            true
        } else {
            let aid_lo = acct.account_id.to_ascii_lowercase();
            filters_lo.iter().any(|flt| {
                aid_lo == *flt
                    || acct
                        .inferred_emails
                        .iter()
                        .any(|e| e == flt || e.ends_with(&format!("@{flt}")))
            })
        };
        if matched {
            allowed_accts.insert(acct.account_id.clone());
            accounts_out.push(acct);
        }
    }

    let mut selected_mbs: Vec<i64> = mailboxes
        .values()
        .filter(|mb| allowed_accts.contains(&mb.account_id))
        .map(|mb| mb.rowid)
        .collect();
    selected_mbs.sort_unstable();

    Ok((accounts_out, selected_mbs))
}

pub fn query_envelope_counts(env_db: &Connection, mailbox_ids: &[i64]) -> KbResult<(i64, i64)> {
    if mailbox_ids.is_empty() {
        return Ok((0, 0));
    }
    let id_list = mailbox_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT COALESCE(MAX(m.ROWID), 0), COUNT(*) \
         FROM messages m \
         WHERE m.mailbox IN ({id_list}) AND COALESCE(m.deleted, 0) = 0"
    );
    let res = env_db.query_row(&sql, [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?)))?;
    Ok(res)
}

pub fn query_envelope_rows(
    env_db: &Connection,
    mailbox_ids: &[i64],
    after_rowid: i64,
) -> KbResult<(Vec<EnvelopeRow>, i64)> {
    if mailbox_ids.is_empty() {
        return Ok((Vec::new(), 0));
    }
    let id_list = mailbox_ids
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");

    let mut rows = Vec::new();
    let mut idx_by_rowid: HashMap<i64, usize> = HashMap::new();
    let mut max_rowid = 0i64;

    {
        let sql = format!(
            "SELECT m.ROWID, m.mailbox, COALESCE(s.subject,''), COALESCE(a.address,''), COALESCE(a.comment,''), \
             COALESCE(sum.summary,''), COALESCE(m.date_sent,0), COALESCE(m.date_received,0), \
             COALESCE(mgd.message_id_header,''), COALESCE(m.size,0) \
             FROM messages m \
             LEFT JOIN subjects s ON m.subject = s.ROWID \
             LEFT JOIN addresses a ON m.sender = a.ROWID \
             LEFT JOIN summaries sum ON m.summary = sum.ROWID \
             LEFT JOIN message_global_data mgd ON m.global_message_id = mgd.ROWID \
             WHERE m.mailbox IN ({id_list}) AND COALESCE(m.deleted, 0) = 0 AND m.ROWID > ?1 \
             ORDER BY m.ROWID ASC"
        );
        let mut stmt = env_db.prepare(&sql)?;
        let iter = stmt.query_map([after_rowid], |r| {
            let rowid: i64 = r.get(0)?;
            let mailbox_id: i64 = r.get(1)?;
            let subject: String = r.get(2)?;
            let addr: String = r.get(3)?;
            let cmt: String = r.get(4)?;
            let summary: String = r.get(5)?;
            let date_sent: i64 = r.get(6)?;
            let date_received: i64 = r.get(7)?;
            let message_id_header: String = r.get(8)?;
            let size_bytes: i64 = r.get(9)?;
            Ok(EnvelopeRow {
                rowid,
                mailbox_id,
                date_sent,
                date_received,
                size_bytes,
                subject,
                sender: format_header_address_from_env(&addr, &cmt),
                recipients: String::new(),
                cc: String::new(),
                summary,
                message_id_header,
            })
        })?;
        for er_res in iter {
            let er = er_res?;
            if er.rowid > max_rowid {
                max_rowid = er.rowid;
            }
            idx_by_rowid.insert(er.rowid, rows.len());
            rows.push(er);
        }
    }

    if !rows.is_empty() {
        let qrec = format!(
            "SELECT r.message, r.type, COALESCE(a.comment,''), COALESCE(a.address,'') \
             FROM recipients r JOIN messages m ON r.message = m.ROWID \
             LEFT JOIN addresses a ON r.address = a.ROWID \
             WHERE m.mailbox IN ({id_list}) AND COALESCE(m.deleted, 0) = 0 AND m.ROWID > ?1 \
             ORDER BY r.message ASC, r.position ASC"
        );
        let mut stmt = env_db.prepare(&qrec)?;
        let iter = stmt.query_map([after_rowid], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, i32>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        for item in iter {
            let (msg_id, rtype, cmt, addr) = item?;
            let Some(&idx) = idx_by_rowid.get(&msg_id) else {
                continue;
            };
            let fmt = format_header_address_from_env(&addr, &cmt);
            if fmt.is_empty() {
                continue;
            }
            let tgt = if rtype == 1 {
                &mut rows[idx].cc
            } else {
                &mut rows[idx].recipients
            };
            if !tgt.is_empty() {
                tgt.push_str("; ");
            }
            tgt.push_str(&fmt);
        }
    }

    Ok((rows, max_rowid))
}

pub fn parse_ooxml_or_text_attachment(att: &mut RawAttachmentInput, bytes: &[u8]) {
    att.sha256 = sha256_bytes(bytes);

    if att.ext == "xlsx" || att.ext == "xlsm" {
        if let Ok(xr) = extract_xlsx_from_bytes(bytes, &OoxmlOptions::mail_preview()) {
            att.text_preview = sanitize_utf8(xr.preview.as_bytes());
            for (sname, grid) in xr.sheets {
                if grid.len() >= 2 {
                    att.ooxml_sheets.push((sname, grid));
                }
            }
        }
    } else if att.ext == "docx" {
        if let Ok(txt) = extract_docx_from_bytes(bytes, &OoxmlOptions::mail_preview()) {
            att.text_preview = sanitize_utf8(txt.as_bytes());
        }
    } else if att.ext == "csv" || att.ext == "txt" {
        let mut slice = &bytes[..bytes.len().min(65_536)];
        if slice.starts_with(&[0xEF, 0xBB, 0xBF]) {
            slice = &slice[3..];
        }
        let clean = sanitize_utf8(slice);
        att.text_preview = utf8_trunc_sv(&clean, 4000).to_string();
    } else if att.ext == "eml" {
        let sv = &bytes[..bytes.len().min(524_288)];
        let (hdrs, _) = split_mime_headers_body(sv);
        let subj = extract_header_str(&hdrs, "subject");
        let from = extract_header_str(&hdrs, "from");
        let mut pl = String::new();
        let mut ht = String::new();
        collect_mime_parts(sv, &mut pl, &mut ht, None, 0);
        if pl.is_empty() && !ht.is_empty() {
            pl = parse_html_clean_and_tables(&ht).text;
        }
        let mut prev = String::new();
        if !subj.is_empty() {
            prev.push_str(&format!("Subject: {subj}\n"));
        }
        if !from.is_empty() {
            prev.push_str(&format!("From: {from}\n"));
        }
        prev.push_str(&pl);
        let clean = sanitize_utf8(prev.as_bytes());
        att.text_preview = utf8_trunc_sv(&clean, 4000).to_string();
    }
}

fn scan_disk_attachments_for_rowid(
    shard_dir: Option<&Path>,
    v10_dir: Option<&Path>,
    rowid: i64,
    identity: &ResolvedIdentity,
    out: &mut Vec<RawAttachmentInput>,
    seen_att_keys: &mut HashSet<String>,
) {
    let Some(sd) = shard_dir else { return };
    let att_msg_dir = sd.join(format!("Attachments/{rowid}"));
    let Ok(md) = fs::read_dir(&att_msg_dir) else {
        return;
    };
    for part_ent in md.flatten() {
        let pname = part_ent.file_name();
        let Some(pstr) = pname.to_str() else { continue };
        if pstr.starts_with('.') {
            continue;
        }
        let part_dir = part_ent.path();
        let Ok(pd) = fs::read_dir(&part_dir) else {
            continue;
        };
        for f_ent in pd.flatten() {
            let fname_os = f_ent.file_name();
            let Some(fname_str) = fname_os.to_str() else {
                continue;
            };
            if fname_str.starts_with('.') {
                continue;
            }
            let fpath = f_ent.path();
            let Ok(st) = fs::symlink_metadata(&fpath) else {
                continue;
            };
            if st.file_type().is_symlink() || !st.is_file() {
                continue;
            }

            let fn_clean = sanitize_utf8(fname_str.as_bytes());
            let size_bytes = st.len() as i64;
            let k = format!("{}|{}", fn_clean.to_ascii_lowercase(), size_bytes);
            if !seen_att_keys.insert(k) {
                continue;
            }

            let ext = lower_ext_of(&fn_clean);
            let mime_type = mime_from_ext(&ext).to_string();
            let mtime = st.mtime();
            let mtime_iso = format_local_datetime(mtime);

            let storage_relpath = if let Some(v10) = v10_dir {
                if let Ok(rel) = fpath.strip_prefix(v10) {
                    let s = rel.to_string_lossy().into_owned();
                    if safe_relpath(&s) {
                        s
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                }
            } else {
                String::new()
            };

            let is_noise = classify_att_noise(&fn_clean, &ext, size_bytes, 0, identity);
            let mut att = RawAttachmentInput {
                filename: fn_clean.clone(),
                clean_filename: fn_clean,
                ext,
                mime_type,
                size_bytes,
                mtime,
                mtime_iso,
                storage_relpath,
                is_inline: 0,
                is_noise,
                sha256: String::new(),
                text_preview: String::new(),
                ooxml_sheets: Vec::new(),
            };

            if att.is_noise == 0
                && att.size_bytes > 0
                && ((att.size_bytes <= 16 * 1024 * 1024
                    && matches!(att.ext.as_str(), "xlsx" | "xlsm" | "docx"))
                    || (att.size_bytes <= 1024 * 1024
                        && matches!(att.ext.as_str(), "csv" | "txt" | "eml")))
            {
                if let Ok((bytes, _)) = read_file_readonly(&fpath, Some(16 * 1024 * 1024)) {
                    parse_ooxml_or_text_attachment(&mut att, &bytes);
                }
            }
            out.push(att);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ScannedEmlInfo {
    pub root_idx: usize,
    pub abs_path: PathBuf,
    pub rel_path: String,
    pub is_emlx: bool,
    pub size: i64,
    pub mtime_ns: i64,
}

fn is_standalone_mail_file(name: &str) -> Option<bool> {
    let lo = name.to_ascii_lowercase();
    if lo.ends_with(".eml") && name.len() > 4 {
        Some(false)
    } else if lo.ends_with(".emlx") && name.len() > 5 {
        Some(true)
    } else {
        None
    }
}

/// Recursively scans `root` for standalone `.eml` and `.emlx` files (skipping hidden/lock/symlink entries).
pub fn scan_eml_dir(
    root_idx: usize,
    root: &Path,
    rel_prefix: &str,
    out: &mut Vec<ScannedEmlInfo>,
) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    for ent in entries.flatten() {
        let name_os = ent.file_name();
        let Some(nm) = name_os.to_str() else { continue };
        if nm.starts_with('.') || nm.starts_with("~$") || nm.ends_with(".!sync") {
            continue;
        }
        let full = ent.path();
        let rel = if rel_prefix.is_empty() {
            nm.to_string()
        } else {
            format!("{rel_prefix}/{nm}")
        };
        let Ok(st) = fs::symlink_metadata(&full) else {
            continue;
        };
        if st.file_type().is_symlink() {
            continue;
        }
        if st.is_dir() {
            scan_eml_dir(root_idx, &full, &rel, out);
        } else if st.is_file() {
            if let Some(is_emlx) = is_standalone_mail_file(nm) {
                if safe_relpath(&rel) {
                    out.push(ScannedEmlInfo {
                        root_idx,
                        abs_path: full,
                        rel_path: rel,
                        is_emlx,
                        size: st.len() as i64,
                        mtime_ns: meta_mtime_ns(&st),
                    });
                }
            }
        }
    }
}

pub fn scan_all_eml_dirs(dirs: &[PathBuf]) -> Vec<ScannedEmlInfo> {
    let mut out = Vec::new();
    for (idx, dir) in dirs.iter().enumerate() {
        if dir.is_dir() {
            scan_eml_dir(idx, dir, "", &mut out);
        }
    }
    out
}

pub fn serialize_eml_snapshot(files: &[ScannedEmlInfo]) -> String {
    let mut sorted: Vec<&ScannedEmlInfo> = files.iter().collect();
    sorted.sort_by(|a, b| a.root_idx.cmp(&b.root_idx).then_with(|| a.rel_path.cmp(&b.rel_path)));
    let mut out = String::with_capacity(sorted.len() * 48);
    for f in sorted {
        out.push_str(&format!("{}\t{}\t{}\t{}\n", f.root_idx, f.rel_path, f.size, f.mtime_ns));
    }
    sha256_bytes(out.as_bytes())
}

fn append_inline_mime_attachments(
    inline_atts: Vec<MimeInlineAtt>,
    base_rel: &str,
    identity: &ResolvedIdentity,
    out: &mut Vec<RawAttachmentInput>,
    seen_att_keys: &mut HashSet<String>,
) {
    for (idx, ia) in inline_atts.into_iter().enumerate() {
        let size_bytes = ia.bytes.len() as i64;
        let k = format!("{}|{}", ia.filename.to_ascii_lowercase(), size_bytes);
        if !seen_att_keys.insert(k) {
            continue;
        }
        let ext = lower_ext_of(&ia.filename);
        let mime_type = if ia.mime_type.is_empty() {
            mime_from_ext(&ext).to_string()
        } else {
            ia.mime_type
        };
        let is_inline = i32::from(ia.is_inline);
        let is_noise = classify_att_noise(&ia.filename, &ext, size_bytes, is_inline, identity);
        let storage_relpath = format!("{base_rel}#part{idx}");
        let mut att = RawAttachmentInput {
            filename: ia.filename.clone(),
            clean_filename: ia.filename,
            ext,
            mime_type,
            size_bytes,
            mtime: 0,
            mtime_iso: String::new(),
            storage_relpath: if safe_relpath(&storage_relpath) {
                storage_relpath
            } else {
                String::new()
            },
            is_inline,
            is_noise,
            sha256: String::new(),
            text_preview: String::new(),
            ooxml_sheets: Vec::new(),
        };
        if !ia.bytes.is_empty()
            && att.is_noise == 0
            && matches!(
                att.ext.as_str(),
                "xlsx" | "xlsm" | "docx" | "csv" | "txt" | "eml"
            )
        {
            parse_ooxml_or_text_attachment(&mut att, &ia.bytes);
        }
        out.push(att);
    }
}

/// Parses a `WorkItem` (Apple Mail `.emlx` or standalone `.eml`/`.emlx`) into a `RawMessageInput`.
pub fn parse_work_item_to_raw(
    wi: &WorkItem,
    v10_dir: Option<&Path>,
    identity: &ResolvedIdentity,
    eml_truncated_counter: &AtomicU64,
) -> RawMessageInput {
    let mut raw_msg = RawMessageInput {
        uid_key: wi.uid_key.clone(),
        account_id: wi.account_id.clone(),
        completeness: "header_only".to_string(),
        ..Default::default()
    };

    let mut plain_body = String::new();
    let mut html_body = String::new();
    let mut inline_atts: Vec<MimeInlineAtt> = Vec::new();
    let mut seen_att = HashSet::new();

    if !wi.is_eml {
        let er = &wi.env;
        raw_msg.source = "apple_mail".to_string();
        raw_msg.source_ref = format!("am:{}", er.rowid);
        raw_msg.folder_path = wi.primary_loc.folder_path.clone();
        raw_msg.subject = sanitize_utf8(er.subject.as_bytes());
        raw_msg.sender = sanitize_utf8(er.sender.as_bytes());
        raw_msg.recipients = sanitize_utf8(er.recipients.as_bytes());
        raw_msg.cc = sanitize_utf8(er.cc.as_bytes());
        raw_msg.date_iso = if !wi.date_iso.is_empty() {
            wi.date_iso.clone()
        } else {
            format_local_datetime(if er.date_sent > 0 {
                er.date_sent
            } else {
                er.date_received
            })
        };
        raw_msg.rfc_message_id = trim_ascii_ws(&er.message_id_header)
            .trim_matches(|c| c == '<' || c == '>')
            .to_string();

        let mut read_copy_msg = |loc: &CopyLocation| -> bool {
            let Some(ref p) = loc.emlx_path else {
                return false;
            };
            let Ok((raw, _)) = read_file_readonly(p, Some(MAX_EMLX_BYTES)) else {
                return false;
            };
            if raw.is_empty() {
                return false;
            }
            let rfc = slice_emlx_rfc822(&raw);
            let (hdrs, _) = split_mime_headers_body(rfc);
            if raw_msg.subject.is_empty() && hdrs.contains_key("subject") {
                raw_msg.subject = extract_header_str(&hdrs, "subject");
            }
            if raw_msg.sender.is_empty() && hdrs.contains_key("from") {
                raw_msg.sender = extract_header_str(&hdrs, "from");
            }
            if raw_msg.recipients.is_empty() && hdrs.contains_key("to") {
                raw_msg.recipients = extract_header_str(&hdrs, "to");
            }
            if raw_msg.cc.is_empty() && hdrs.contains_key("cc") {
                raw_msg.cc = extract_header_str(&hdrs, "cc");
            }
            if raw_msg.date_iso.is_empty() && hdrs.contains_key("date") {
                raw_msg.date_iso = parse_rfc5322_date(&extract_header_str(&hdrs, "date"));
            }
            if raw_msg.rfc_message_id.is_empty() {
                if let Some(mid_raw) = hdrs.get("message-id") {
                    let s = sanitize_utf8(mid_raw);
                    raw_msg.rfc_message_id = trim_ascii_ws(&s)
                        .trim_matches(|c| c == '<' || c == '>')
                        .to_string();
                }
            }
            collect_mime_parts(rfc, &mut plain_body, &mut html_body, Some(&mut inline_atts), 0);
            !plain_body.is_empty() || !html_body.is_empty()
        };

        if !read_copy_msg(&wi.primary_loc) {
            for sl in &wi.secondary_locs {
                if read_copy_msg(sl) {
                    break;
                }
            }
        }

        scan_disk_attachments_for_rowid(
            wi.primary_loc.shard_dir.as_deref(),
            v10_dir,
            wi.primary_loc.rowid,
            identity,
            &mut raw_msg.attachments,
            &mut seen_att,
        );
        for sl in &wi.secondary_locs {
            scan_disk_attachments_for_rowid(
                sl.shard_dir.as_deref(),
                v10_dir,
                sl.rowid,
                identity,
                &mut raw_msg.attachments,
                &mut seen_att,
            );
        }
        let base_rel = format!("am/{}", er.rowid);
        append_inline_mime_attachments(
            inline_atts,
            &base_rel,
            identity,
            &mut raw_msg.attachments,
            &mut seen_att,
        );
    } else {
        raw_msg.source = "eml".to_string();
        raw_msg.source_ref = wi.eml_rel_path.clone();
        if raw_msg.account_id.is_empty() {
            raw_msg.account_id = "eml".to_string();
        }
        raw_msg.folder_path = wi
            .eml_rel_path
            .rsplit_once('/')
            .map(|(dir, _)| dir.to_string())
            .unwrap_or_else(|| "workspace_eml".to_string());

        if let Ok((raw, trunc)) = read_file_readonly(&wi.eml_abs_path, Some(MAX_EML_BYTES)) {
            if trunc {
                eml_truncated_counter.fetch_add(1, Ordering::Relaxed);
            }
            if !raw.is_empty() {
                let rfc = if wi.is_emlx_standalone {
                    slice_emlx_rfc822(&raw)
                } else {
                    raw.as_slice()
                };
                let (hdrs, _) = split_mime_headers_body(rfc);
                if hdrs.contains_key("subject") {
                    raw_msg.subject = extract_header_str(&hdrs, "subject");
                }
                if hdrs.contains_key("from") {
                    raw_msg.sender = extract_header_str(&hdrs, "from");
                }
                if hdrs.contains_key("to") {
                    raw_msg.recipients = extract_header_str(&hdrs, "to");
                }
                if hdrs.contains_key("cc") {
                    raw_msg.cc = extract_header_str(&hdrs, "cc");
                }
                if hdrs.contains_key("date") {
                    raw_msg.date_iso = parse_rfc5322_date(&extract_header_str(&hdrs, "date"));
                }
                if let Some(mid_raw) = hdrs.get("message-id") {
                    let s = sanitize_utf8(mid_raw);
                    raw_msg.rfc_message_id = trim_ascii_ws(&s)
                        .trim_matches(|c| c == '<' || c == '>')
                        .to_string();
                }
                collect_mime_parts(
                    rfc,
                    &mut plain_body,
                    &mut html_body,
                    Some(&mut inline_atts),
                    0,
                );
            }
        }
        append_inline_mime_attachments(
            inline_atts,
            &wi.eml_rel_path,
            identity,
            &mut raw_msg.attachments,
            &mut seen_att,
        );
    }

    if !html_body.is_empty() {
        let hp = parse_html_clean_and_tables(&html_body);
        raw_msg.html_tables = hp.tables;
        if plain_body.is_empty() || hp.text.len() > plain_body.len() + 80 {
            plain_body = hp.text;
        }
    }
    plain_body = sanitize_utf8(plain_body.as_bytes());

    if !plain_body.is_empty() {
        raw_msg.completeness = "full_body".to_string();
        if let Some(split) = find_reply_split_offset(&plain_body).filter(|&s| s > 0) {
            raw_msg.body_latest =
                utf8_trunc_sv(trim_ascii_ws(&plain_body[..split]), MAX_BODY_LATEST_BYTES)
                    .to_string();
            let q_raw = trim_ascii_ws(&plain_body[split..]);
            raw_msg.body_quoted_for_amount = utf8_trunc_sv(q_raw, 32 * 1024).to_string();
            raw_msg.body_quoted = utf8_trunc_sv(q_raw, MAX_BODY_QUOTED_STORE).to_string();
        } else {
            raw_msg.body_latest =
                utf8_trunc_sv(trim_ascii_ws(&plain_body), MAX_BODY_LATEST_BYTES).to_string();
        }
    } else if !wi.is_eml && !wi.env.summary.is_empty() {
        raw_msg.completeness = "header_preview".to_string();
        raw_msg.body_latest = sanitize_utf8(wi.env.summary.as_bytes());
    } else {
        raw_msg.completeness = "header_only".to_string();
    }

    if raw_msg.uid_key.is_empty() {
        raw_msg.uid_key = norm_uid_from_fields(
            &raw_msg.rfc_message_id,
            &raw_msg.date_iso,
            &raw_msg.sender,
            &raw_msg.subject,
            &raw_msg.body_latest,
        );
    }

    raw_msg
}

pub fn process_work_item(
    wi: &WorkItem,
    v10_dir: Option<&Path>,
    pack: &CompiledDomainPack,
    identity: &ResolvedIdentity,
    eml_truncated_counter: &AtomicU64,
) -> EnrichedMsg {
    let raw = parse_work_item_to_raw(wi, v10_dir, identity, eml_truncated_counter);
    enrich_message(&raw, pack, identity)
}
