//! Shared foundation library for `mailkb_db`.
//!
//! Provides environment & domain-pack discovery, S4/S8/S9/S10/S11/S13 security
//! primitives, T2 hot runtime SQLite staging (`?mode=ro&immutable=1`), FTS5 query
//! builders & CJK bigram tokenization, S1-bounded pure-Rust OOXML extraction,
//! T3 atomic `DELETE`-mode SQLite publishing, and the `domain-pack.v1` compiler.

pub mod config;
pub mod domain_pack;
pub mod error;
pub mod fts;
pub mod minire;
pub mod ooxml;
pub mod publish;
pub mod security;
pub mod staging;
pub mod strutil;
pub mod time;

pub use config::MailKbConfig;
pub use domain_pack::{
    validate_pack_file, AmountRules, AmountTypeRule, CategoryFallbackRule, CodePatternRule,
    CompiledDomainPack, CompiledPattern, DimensionSpec, DomainPack, EntityRules, IntentRule,
    LexiconRuleEntry, OrgRuleEntry, OrgRules, PackIdentity, PackValidationReport, TopicRuleEntry,
    TopicRules, DOMAIN_PACK_SCHEMA_V1,
};
pub use error::{KbError, KbResult};
pub use minire::MiniRegex;
pub use staging::{
    open_staged_ro, stage_db_path, stage_primary_db, StageInfo, StagingState, DEFAULT_MMAP_BYTES,
};
