//! Read-only staged query, audit, rendering, and self-test engine for `mailkb_db`.

pub mod audit;
pub mod db;
pub mod queries;
pub mod render;

#[cfg(test)]
mod tests;

use mailkb_core::{KbResult, MailKbConfig};
use serde_json::Value;
use std::path::Path;

pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SCHEMA_VERSION: &str = "1.0-universal";

#[derive(Debug, Clone)]
pub struct SearchOpts {
    pub keywords: Vec<String>,
    pub mode: String,
    pub account: Option<String>,
    pub entity: Option<String>,
    pub category: Option<String>,
    pub topic: Option<String>,
    pub org: Option<String>,
    pub intent: Option<String>,
    pub direction: Option<String>,
    pub completeness: Option<String>,
    pub source: Option<String>,
    pub sender: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub has_amount: bool,
    pub dim_filters: Vec<(String, String)>,
    pub limit: usize,
    pub auto_sync: bool,
}

impl Default for SearchOpts {
    fn default() -> Self {
        Self {
            keywords: Vec::new(),
            mode: "both".to_string(),
            account: None,
            entity: None,
            category: None,
            topic: None,
            org: None,
            intent: None,
            direction: None,
            completeness: None,
            source: None,
            sender: None,
            since: None,
            until: None,
            has_amount: false,
            dim_filters: Vec::new(),
            limit: 30,
            auto_sync: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReadOpts {
    pub id_or_uid: String,
    pub full: bool,
}

#[derive(Debug, Clone)]
pub struct EntityListOpts {
    pub entity: Option<String>,
    pub entity_type: Option<String>,
    pub category: Option<String>,
    pub limit: usize,
}

impl Default for EntityListOpts {
    fn default() -> Self {
        Self {
            entity: None,
            entity_type: None,
            category: None,
            limit: 30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AmountListOpts {
    pub keywords: Vec<String>,
    pub entity: Option<String>,
    pub currency: Option<String>,
    pub topic: Option<String>,
    pub org: Option<String>,
    pub amount_type: Option<String>,
    pub confidence: Option<String>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub limit: usize,
}

impl Default for AmountListOpts {
    fn default() -> Self {
        Self {
            keywords: Vec::new(),
            entity: None,
            currency: None,
            topic: None,
            org: None,
            amount_type: None,
            confidence: None,
            since: None,
            until: None,
            limit: 30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TopicListOpts {
    pub topic: Option<String>,
    pub limit: usize,
}

impl Default for TopicListOpts {
    fn default() -> Self {
        Self {
            topic: None,
            limit: 30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OrgListOpts {
    pub org: Option<String>,
    pub limit: usize,
}

impl Default for OrgListOpts {
    fn default() -> Self {
        Self {
            org: None,
            limit: 30,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TimelineOpts {
    pub granularity: String,
    pub since: Option<String>,
    pub until: Option<String>,
    pub topic: Option<String>,
    pub org: Option<String>,
    pub limit: usize,
}

impl Default for TimelineOpts {
    fn default() -> Self {
        Self {
            granularity: "month".to_string(),
            since: None,
            until: None,
            topic: None,
            org: None,
            limit: 36,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AttOpts {
    pub keywords: Vec<String>,
    pub entity: Option<String>,
    pub topic: Option<String>,
    pub ext: Option<String>,
    pub include_noise: bool,
    pub limit: usize,
}

impl Default for AttOpts {
    fn default() -> Self {
        Self {
            keywords: Vec::new(),
            entity: None,
            topic: None,
            ext: None,
            include_noise: false,
            limit: 30,
        }
    }
}

pub type AutoSyncCallback<'a> = &'a dyn Fn(&MailKbConfig) -> KbResult<()>;

pub fn run_search(
    cfg: &MailKbConfig,
    opts: &SearchOpts,
    sync: Option<AutoSyncCallback<'_>>,
) -> KbResult<Value> {
    queries::run_search_impl(cfg, opts, sync)
}

pub fn run_read(cfg: &MailKbConfig, opts: &ReadOpts) -> KbResult<Value> {
    queries::run_read_impl(cfg, opts)
}

pub fn run_entities(cfg: &MailKbConfig, opts: &EntityListOpts) -> KbResult<Value> {
    queries::run_entities_impl(cfg, opts)
}

pub fn run_amounts(cfg: &MailKbConfig, opts: &AmountListOpts) -> KbResult<Value> {
    queries::run_amounts_impl(cfg, opts)
}

pub fn run_topics(cfg: &MailKbConfig, opts: &TopicListOpts) -> KbResult<Value> {
    queries::run_topics_impl(cfg, opts)
}

pub fn run_orgs(cfg: &MailKbConfig, opts: &OrgListOpts) -> KbResult<Value> {
    queries::run_orgs_impl(cfg, opts)
}

pub fn run_timeline(cfg: &MailKbConfig, opts: &TimelineOpts) -> KbResult<Value> {
    queries::run_timeline_impl(cfg, opts)
}

pub fn run_att(cfg: &MailKbConfig, opts: &AttOpts) -> KbResult<Value> {
    queries::run_att_impl(cfg, opts)
}

pub fn run_stats(cfg: &MailKbConfig) -> KbResult<Value> {
    queries::run_stats_impl(cfg)
}

pub fn run_audit(cfg: &MailKbConfig) -> KbResult<Value> {
    audit::run_audit_impl(cfg)
}

pub fn run_selftest(cfg: &MailKbConfig, pack_sample: Option<&Path>) -> KbResult<Value> {
    audit::run_selftest_impl(cfg, pack_sample)
}
