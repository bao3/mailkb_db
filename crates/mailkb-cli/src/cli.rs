//! Clap v4 derive CLI definition and argument conversion for `mailkb_db`.

use clap::{ArgAction, Args, Parser, Subcommand};
use mailkb_core::config::MailKbConfig;
use mailkb_core::error::{KbError, KbResult};
use mailkb_core::security::{expand_tilde, real_allow_missing};
use mailkb_query::{
    AmountListOpts, AttOpts, EntityListOpts, OrgListOpts, ReadOpts, SearchOpts, TimelineOpts,
    TopicListOpts,
};
use mailkb_sync::{ProfileOpts, SyncOpts, TestPackOpts};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "mailkb_db",
    version,
    about = "Universal multi-account local mail knowledge base & domain-pack CLI"
)]
pub struct Cli {
    #[command(flatten)]
    pub global: GlobalOpts,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Clone, Args, Default)]
pub struct GlobalOpts {
    /// Override cold SQLite database file path.
    #[arg(long, global = true, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Override cold SQLite database directory.
    #[arg(long, global = true, value_name = "DIR")]
    pub db_dir: Option<PathBuf>,

    /// Override private runtime cache directory.
    #[arg(long, global = true, value_name = "DIR")]
    pub runtime_dir: Option<PathBuf>,

    /// Load explicit domain pack JSON file (repeatable).
    #[arg(long = "pack", global = true, value_name = "PATH", action = ArgAction::Append)]
    pub packs: Vec<PathBuf>,

    /// Disable all domain packs (pure universal mode).
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub no_packs: bool,

    /// Filter Apple Mail accounts by UUID or email substring (repeatable).
    #[arg(long = "account", global = true, value_name = "ID", action = ArgAction::Append)]
    pub accounts: Vec<String>,

    /// Ingest standalone .eml/.emlx directory (repeatable).
    #[arg(long = "eml-dir", global = true, value_name = "DIR", action = ArgAction::Append)]
    pub eml_dirs: Vec<PathBuf>,

    /// Emit structured JSON output.
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub json: bool,

    /// Suppress non-essential human output.
    #[arg(short = 'q', long, global = true, action = ArgAction::SetTrue)]
    pub quiet: bool,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Sync Apple Mail / EML directories / legacy DB into 1.0-universal SQLite.
    Sync(SyncArgs),

    /// Multi-dimensional FTS5 search across dimensions and message bodies.
    #[command(visible_alias = "md-search")]
    Search(SearchArgs),

    /// Read full or summary message with extracted entities, amounts, and attachments.
    #[command(visible_alias = "md-read")]
    Read(ReadArgs),

    /// Aggregate extracted entities or drill down into a specific entity.
    #[command(visible_alias = "sku")]
    Entities(EntitiesArgs),

    /// Query extracted commercial/financial amounts with terms & currency summary.
    #[command(visible_alias = "price")]
    Amounts(AmountsArgs),

    /// Topic/project overview or single-topic drill-down.
    #[command(visible_alias = "project")]
    Topics(TopicsArgs),

    /// Organization/customer overview or single-organization drill-down.
    #[command(visible_alias = "customer")]
    Orgs(OrgsArgs),

    /// Monthly, daily, quarterly, or yearly message activity timeline.
    Timeline(TimelineArgs),

    /// Search/list indexed attachments with S10 safe path resolution.
    Att(AttArgs),

    /// Multi-threaded database statistics and loaded domain-pack summary.
    #[command(alias = "md-stats")]
    Stats,

    /// Read-only security, checksum, runtime cache, and Apple Mail readiness audit.
    #[command(alias = "mail-audit")]
    Audit,

    /// Profile local mail corpus to guide custom domain-pack authoring.
    #[command(name = "profile-corpus")]
    ProfileCorpus(ProfileCorpusArgs),

    /// Validate a domain-pack.v1 JSON file (schema, regex syntax, hazard checks).
    #[command(name = "validate-pack")]
    ValidatePack(ValidatePackArgs),

    /// Dry-run a domain pack against sampled messages and report hit metrics.
    #[command(name = "test-pack")]
    TestPack(TestPackArgs),

    /// Run self-verification suite (SHA-256, SQLite 1.0-universal, FTS5, MiniRegex, S9/S10/S11).
    Selftest(SelftestArgs),
}

#[derive(Debug, Clone, Args)]
pub struct SyncArgs {
    /// Rebuild database from scratch instead of incremental reuse.
    #[arg(long)]
    pub full: bool,

    /// Parse and enrich without writing cold SQLite database.
    #[arg(long)]
    pub dry_run: bool,

    /// Cap maximum messages processed.
    #[arg(long, value_name = "N")]
    pub limit: Option<usize>,

    /// Stage and migrate/re-enrich an existing 3.0-multidim legacy SQLite DB.
    #[arg(long, value_name = "PATH")]
    pub import_legacy_db: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct SearchArgs {
    /// Search keywords (supports CJK bigrams and AND/OR operators).
    pub keywords: Vec<String>,

    /// FTS search mode: both, dim, or msg.
    #[arg(long, default_value = "both")]
    pub mode: String,

    /// Filter by entity/SKU key (hyphen/case-insensitive).
    #[arg(long, visible_alias = "sku")]
    pub entity: Option<String>,

    /// Filter by category / product family.
    #[arg(long, visible_alias = "family")]
    pub category: Option<String>,

    /// Filter by topic / project tag.
    #[arg(long, visible_alias = "project")]
    pub topic: Option<String>,

    /// Filter by organization / customer tag.
    #[arg(long, visible_alias = "customer")]
    pub org: Option<String>,

    /// Filter by intent classification.
    #[arg(long)]
    pub intent: Option<String>,

    /// Filter by direction (external_inbound, external_outbound, internal, system_notice).
    #[arg(long)]
    pub direction: Option<String>,

    /// Filter by completeness (full_body, partial_header, etc.).
    #[arg(long)]
    pub completeness: Option<String>,

    /// Filter by ingestion source (apple_mail, eml, legacy_import).
    #[arg(long)]
    pub source: Option<String>,

    /// Filter by sender or recipient substring.
    #[arg(long)]
    pub sender: Option<String>,

    /// Filter messages on or after ISO date (YYYY-MM-DD).
    #[arg(long)]
    pub since: Option<String>,

    /// Filter messages on or before ISO date (YYYY-MM-DD).
    #[arg(long)]
    pub until: Option<String>,

    /// Only return messages containing extracted amounts/prices.
    #[arg(long, visible_alias = "has-price")]
    pub has_amount: bool,

    /// Filter by custom dimension KEY=VALUE (repeatable).
    #[arg(long = "dim", value_name = "KEY=VAL", action = ArgAction::Append)]
    pub dims: Vec<String>,

    /// Maximum rows to return (1..=500).
    #[arg(long, default_value_t = 30)]
    pub limit: usize,

    /// Trigger incremental sync before querying on master hosts.
    #[arg(long)]
    pub auto_sync: bool,
}

#[derive(Debug, Clone, Args)]
pub struct ReadArgs {
    /// Numeric message ID, uid_key, or RFC Message-ID.
    pub id_or_uid: String,

    /// Include full quoted thread body_quoted.
    #[arg(long)]
    pub full: bool,
}

#[derive(Debug, Clone, Args)]
pub struct EntitiesArgs {
    /// Optional entity/SKU key for drill-down.
    pub positional_entity: Option<String>,

    /// Filter or drill down by entity/SKU key.
    #[arg(long = "entity", visible_alias = "sku")]
    pub entity_flag: Option<String>,

    /// Filter by entity_type (e.g. item_code, standards).
    #[arg(long = "type")]
    pub entity_type: Option<String>,

    /// Filter by category / product family.
    #[arg(long, visible_alias = "family")]
    pub category: Option<String>,

    /// Maximum rows to return (1..=500).
    #[arg(long, default_value_t = 30)]
    pub limit: usize,
}

#[derive(Debug, Clone, Args)]
pub struct AmountsArgs {
    /// Keyword filters across entity, topic, org, subject, or evidence snippet.
    pub keywords: Vec<String>,

    /// Filter by subject entity / SKU.
    #[arg(long, visible_alias = "sku")]
    pub entity: Option<String>,

    /// Filter by normalized currency code (e.g. USD, EUR, CNY).
    #[arg(long)]
    pub currency: Option<String>,

    /// Filter by topic / project name.
    #[arg(long, visible_alias = "project")]
    pub topic: Option<String>,

    /// Filter by organization / customer name.
    #[arg(long, visible_alias = "customer")]
    pub org: Option<String>,

    /// Filter by amount_type / price_type.
    #[arg(long = "type", visible_alias = "price-type")]
    pub amount_type: Option<String>,

    /// Filter by extraction confidence (high, medium, low).
    #[arg(long)]
    pub confidence: Option<String>,

    /// Filter amounts on or after ISO date (YYYY-MM-DD).
    #[arg(long)]
    pub since: Option<String>,

    /// Filter amounts on or before ISO date (YYYY-MM-DD).
    #[arg(long)]
    pub until: Option<String>,

    /// Maximum rows to return (1..=500).
    #[arg(long, default_value_t = 30)]
    pub limit: usize,
}

#[derive(Debug, Clone, Args)]
pub struct TopicsArgs {
    /// Optional topic/project name for drill-down.
    pub positional_topic: Option<String>,

    /// Filter or drill down by topic/project name.
    #[arg(long = "topic", visible_alias = "project")]
    pub topic_flag: Option<String>,

    /// Maximum rows to return (1..=500).
    #[arg(long, default_value_t = 30)]
    pub limit: usize,
}

#[derive(Debug, Clone, Args)]
pub struct OrgsArgs {
    /// Optional organization/customer name for drill-down.
    pub positional_org: Option<String>,

    /// Filter or drill down by organization/customer name.
    #[arg(long = "org", visible_alias = "customer")]
    pub org_flag: Option<String>,

    /// Maximum rows to return (1..=500).
    #[arg(long, default_value_t = 30)]
    pub limit: usize,
}

#[derive(Debug, Clone, Args)]
pub struct TimelineArgs {
    /// Aggregation granularity: month, day, quarter, or year.
    #[arg(long, default_value = "month")]
    pub granularity: String,

    /// Start ISO date (YYYY-MM-DD).
    #[arg(long)]
    pub since: Option<String>,

    /// End ISO date (YYYY-MM-DD).
    #[arg(long)]
    pub until: Option<String>,

    /// Filter by topic / project tag.
    #[arg(long, visible_alias = "project")]
    pub topic: Option<String>,

    /// Filter by organization / customer tag.
    #[arg(long, visible_alias = "customer")]
    pub org: Option<String>,

    /// Maximum periods to return (1..=500).
    #[arg(long, default_value_t = 36)]
    pub limit: usize,
}

#[derive(Debug, Clone, Args)]
pub struct AttArgs {
    /// FTS keywords across attachment filename and metadata.
    pub keywords: Vec<String>,

    /// Filter by entity/SKU tag or filename.
    #[arg(long, visible_alias = "sku")]
    pub entity: Option<String>,

    /// Filter by topic/project tag or filename.
    #[arg(long, visible_alias = "project")]
    pub topic: Option<String>,

    /// Filter by file extension (e.g. pdf, xlsx).
    #[arg(long)]
    pub ext: Option<String>,

    /// Include inline/signature noise attachments.
    #[arg(long)]
    pub include_noise: bool,

    /// Maximum rows to return (1..=500).
    #[arg(long, default_value_t = 30)]
    pub limit: usize,
}

#[derive(Debug, Clone, Args)]
pub struct ProfileCorpusArgs {
    /// Maximum messages to sample during profiling.
    #[arg(long, default_value_t = 2000)]
    pub limit: usize,

    /// Profile an existing SQLite DB (staged read-only) instead of live mail stores.
    #[arg(long, value_name = "PATH")]
    pub from_db: Option<PathBuf>,

    /// Write JSON report safely to output file (validated by S9/assert_safe_out_path).
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct ValidatePackArgs {
    /// Path to domain-pack.v1 JSON file.
    pub pack_json: PathBuf,
}

#[derive(Debug, Clone, Args)]
pub struct TestPackArgs {
    /// Path to domain-pack.v1 JSON file.
    pub pack_json: PathBuf,

    /// Number of messages to sample for evaluation.
    #[arg(long, default_value_t = 200)]
    pub sample: usize,

    /// Evaluate against an existing SQLite DB (staged read-only).
    #[arg(long, value_name = "PATH")]
    pub from_db: Option<PathBuf>,
}

#[derive(Debug, Clone, Args)]
pub struct SelftestArgs {
    /// Optional domain-pack.v1 JSON file to validate as part of selftest.
    #[arg(long, value_name = "PATH")]
    pub pack_sample: Option<PathBuf>,
}

/// Applies global CLI overrides on top of discovered `MailKbConfig`.
pub fn apply_global_opts(base: &MailKbConfig, global: &GlobalOpts) -> MailKbConfig {
    let mut cfg = base.clone();
    if let Some(ref dir) = global.db_dir {
        cfg = cfg.with_db_dir_override(dir);
    }
    if let Some(ref db) = global.db {
        cfg = cfg.with_db_override(db);
    }
    if let Some(ref rt) = global.runtime_dir {
        cfg = cfg.with_runtime_dir_override(rt);
    }
    if global.no_packs || !global.packs.is_empty() {
        cfg = cfg.with_pack_overrides(&global.packs, global.no_packs);
    }
    if !global.accounts.is_empty() {
        cfg.account_filters = global.accounts.clone();
    }
    if !global.eml_dirs.is_empty() {
        cfg.eml_dirs = global
            .eml_dirs
            .iter()
            .map(|p| real_allow_missing(&expand_tilde(&p.to_string_lossy())))
            .collect();
    }
    cfg
}

pub fn expand_path(p: &std::path::Path) -> PathBuf {
    expand_tilde(&p.to_string_lossy())
}

pub fn parse_dim_pair(raw: &str) -> KbResult<(String, String)> {
    let Some((k, v)) = raw.split_once('=') else {
        return Err(KbError::InvalidArgument(format!(
            "Invalid --dim '{raw}': expected KEY=VAL"
        )));
    };
    let kt = k.trim();
    let vt = v.trim();
    if kt.is_empty() || vt.is_empty() {
        return Err(KbError::InvalidArgument(format!(
            "Invalid --dim '{raw}': both KEY and VAL must be non-empty"
        )));
    }
    Ok((kt.to_string(), vt.to_string()))
}

pub fn build_sync_opts(a: &SyncArgs) -> SyncOpts {
    SyncOpts {
        full: a.full,
        dry_run: a.dry_run,
        limit: a.limit,
        import_legacy_db: a.import_legacy_db.as_deref().map(expand_path),
    }
}

pub fn build_search_opts(a: &SearchArgs, global: &GlobalOpts) -> KbResult<SearchOpts> {
    let mut dim_filters = Vec::with_capacity(a.dims.len());
    for raw in &a.dims {
        dim_filters.push(parse_dim_pair(raw)?);
    }
    let account = if global.accounts.is_empty() {
        None
    } else {
        Some(global.accounts.join(","))
    };
    Ok(SearchOpts {
        keywords: a.keywords.clone(),
        mode: a.mode.clone(),
        account,
        entity: a.entity.clone(),
        category: a.category.clone(),
        topic: a.topic.clone(),
        org: a.org.clone(),
        intent: a.intent.clone(),
        direction: a.direction.clone(),
        completeness: a.completeness.clone(),
        source: a.source.clone(),
        sender: a.sender.clone(),
        since: a.since.clone(),
        until: a.until.clone(),
        has_amount: a.has_amount,
        dim_filters,
        limit: a.limit,
        auto_sync: a.auto_sync,
    })
}

pub fn build_read_opts(a: &ReadArgs) -> ReadOpts {
    ReadOpts {
        id_or_uid: a.id_or_uid.clone(),
        full: a.full,
    }
}

pub fn build_entity_opts(a: &EntitiesArgs) -> KbResult<EntityListOpts> {
    if a.positional_entity.is_some() && a.entity_flag.is_some() {
        return Err(KbError::InvalidArgument(
            "Specify entity either positionally or with --entity, not both".to_string(),
        ));
    }
    Ok(EntityListOpts {
        entity: a.entity_flag.clone().or_else(|| a.positional_entity.clone()),
        entity_type: a.entity_type.clone(),
        category: a.category.clone(),
        limit: a.limit,
    })
}

pub fn build_amount_opts(a: &AmountsArgs) -> AmountListOpts {
    AmountListOpts {
        keywords: a.keywords.clone(),
        entity: a.entity.clone(),
        currency: a.currency.clone(),
        topic: a.topic.clone(),
        org: a.org.clone(),
        amount_type: a.amount_type.clone(),
        confidence: a.confidence.clone(),
        since: a.since.clone(),
        until: a.until.clone(),
        limit: a.limit,
    }
}

pub fn build_topic_opts(a: &TopicsArgs) -> KbResult<TopicListOpts> {
    if a.positional_topic.is_some() && a.topic_flag.is_some() {
        return Err(KbError::InvalidArgument(
            "Specify topic either positionally or with --topic, not both".to_string(),
        ));
    }
    Ok(TopicListOpts {
        topic: a.topic_flag.clone().or_else(|| a.positional_topic.clone()),
        limit: a.limit,
    })
}

pub fn build_org_opts(a: &OrgsArgs) -> KbResult<OrgListOpts> {
    if a.positional_org.is_some() && a.org_flag.is_some() {
        return Err(KbError::InvalidArgument(
            "Specify organization either positionally or with --org, not both".to_string(),
        ));
    }
    Ok(OrgListOpts {
        org: a.org_flag.clone().or_else(|| a.positional_org.clone()),
        limit: a.limit,
    })
}

pub fn build_timeline_opts(a: &TimelineArgs) -> TimelineOpts {
    TimelineOpts {
        granularity: a.granularity.clone(),
        since: a.since.clone(),
        until: a.until.clone(),
        topic: a.topic.clone(),
        org: a.org.clone(),
        limit: a.limit,
    }
}

pub fn build_att_opts(a: &AttArgs) -> AttOpts {
    AttOpts {
        keywords: a.keywords.clone(),
        entity: a.entity.clone(),
        topic: a.topic.clone(),
        ext: a.ext.clone(),
        include_noise: a.include_noise,
        limit: a.limit,
    }
}

pub fn build_profile_opts(a: &ProfileCorpusArgs) -> ProfileOpts {
    ProfileOpts {
        limit: a.limit,
        from_db: a.from_db.as_deref().map(expand_path),
    }
}

pub fn build_test_pack_opts(a: &TestPackArgs) -> TestPackOpts {
    TestPackOpts {
        pack_path: expand_path(&a.pack_json),
        sample: a.sample,
        from_db: a.from_db.as_deref().map(expand_path),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("CLI parse failed")
    }

    #[test]
    fn parse_global_flags_before_and_after_subcommand() {
        let cli = parse(&[
            "mailkb_db",
            "--db",
            "/tmp/custom.sqlite",
            "--db-dir",
            "/tmp/dbdir",
            "--runtime-dir",
            "/tmp/rt",
            "--pack",
            "/tmp/a.json",
            "--pack",
            "/tmp/b.json",
            "--account",
            "acct-1",
            "--account",
            "acct-2",
            "--eml-dir",
            "/tmp/eml1",
            "--eml-dir",
            "/tmp/eml2",
            "--json",
            "--quiet",
            "stats",
        ]);
        assert!(cli.global.json);
        assert!(cli.global.quiet);
        assert_eq!(cli.global.packs.len(), 2);
        assert_eq!(cli.global.accounts, vec!["acct-1", "acct-2"]);
        assert_eq!(cli.global.eml_dirs.len(), 2);
        assert!(matches!(cli.command, Commands::Stats));

        let cli_no_packs = parse(&["mailkb_db", "audit", "--no-packs", "--json"]);
        assert!(cli_no_packs.global.no_packs);
        assert!(cli_no_packs.global.json);
        assert!(matches!(cli_no_packs.command, Commands::Audit));
    }

    #[test]
    fn parse_sync_and_pack_commands() {
        let s = parse(&[
            "mailkb_db",
            "sync",
            "--full",
            "--dry-run",
            "--limit",
            "150",
            "--import-legacy-db",
            "/tmp/legacy.sqlite",
        ]);
        match s.command {
            Commands::Sync(sa) => {
                assert!(sa.full);
                assert!(sa.dry_run);
                assert_eq!(sa.limit, Some(150));
                assert_eq!(
                    sa.import_legacy_db.as_deref(),
                    Some(std::path::Path::new("/tmp/legacy.sqlite"))
                );
            }
            other => panic!("unexpected: {other:?}"),
        }

        let pc = parse(&[
            "mailkb_db",
            "profile-corpus",
            "--limit",
            "500",
            "--from-db",
            "/tmp/in.sqlite",
            "--out",
            "/tmp/profile.json",
        ]);
        match pc.command {
            Commands::ProfileCorpus(p) => {
                assert_eq!(p.limit, 500);
                assert_eq!(
                    p.from_db.as_deref(),
                    Some(std::path::Path::new("/tmp/in.sqlite"))
                );
                assert_eq!(
                    p.out.as_deref(),
                    Some(std::path::Path::new("/tmp/profile.json"))
                );
            }
            other => panic!("unexpected: {other:?}"),
        }

        let vp = parse(&["mailkb_db", "validate-pack", "/tmp/pack.json"]);
        match vp.command {
            Commands::ValidatePack(v) => {
                assert_eq!(v.pack_json, PathBuf::from("/tmp/pack.json"));
            }
            other => panic!("unexpected: {other:?}"),
        }

        let tp = parse(&[
            "mailkb_db",
            "test-pack",
            "/tmp/pack.json",
            "--sample",
            "75",
            "--from-db",
            "/tmp/test.sqlite",
        ]);
        match tp.command {
            Commands::TestPack(t) => {
                assert_eq!(t.pack_json, PathBuf::from("/tmp/pack.json"));
                assert_eq!(t.sample, 75);
                assert_eq!(
                    t.from_db.as_deref(),
                    Some(std::path::Path::new("/tmp/test.sqlite"))
                );
            }
            other => panic!("unexpected: {other:?}"),
        }

        let st = parse(&["mailkb_db", "selftest", "--pack-sample", "/tmp/sample.json"]);
        match st.command {
            Commands::Selftest(s) => {
                assert_eq!(
                    s.pack_sample.as_deref(),
                    Some(std::path::Path::new("/tmp/sample.json"))
                );
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn verify_clap_command_tree_has_no_conflicts() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn parse_search_and_legacy_aliases() {
        let cli = parse(&[
            "mailkb_db",
            "md-search",
            "switch",
            "quote",
            "--mode",
            "dim",
            "--account",
            "acct-sales",
            "--sku",
            "ACME-SW-2400",
            "--family",
            "Switch",
            "--project",
            "ProjectHorizon",
            "--customer",
            "Northstar",
            "--intent",
            "quotation",
            "--direction",
            "external_outbound",
            "--completeness",
            "full_body",
            "--source",
            "eml",
            "--sender",
            "alice@acme.test",
            "--since",
            "2026-01-01",
            "--until",
            "2026-04-30",
            "--has-price",
            "--dim",
            "standards=IEC-61850",
            "--dim",
            "tier=industrial",
            "--limit",
            "25",
            "--auto-sync",
        ]);
        match cli.command {
            Commands::Search(sa) => {
                let opts = build_search_opts(&sa, &cli.global).unwrap();
                assert_eq!(opts.keywords, vec!["switch", "quote"]);
                assert_eq!(opts.mode, "dim");
                assert_eq!(opts.account.as_deref(), Some("acct-sales"));
                assert_eq!(opts.entity.as_deref(), Some("ACME-SW-2400"));
                assert_eq!(opts.category.as_deref(), Some("Switch"));
                assert_eq!(opts.topic.as_deref(), Some("ProjectHorizon"));
                assert_eq!(opts.org.as_deref(), Some("Northstar"));
                assert!(opts.has_amount);
                assert_eq!(
                    opts.dim_filters,
                    vec![
                        ("standards".to_string(), "IEC-61850".to_string()),
                        ("tier".to_string(), "industrial".to_string()),
                    ]
                );
                assert_eq!(opts.limit, 25);
                assert!(opts.auto_sync);
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Canonical search flags (--entity, --category, --topic, --org, --has-amount)
        let cli2 = parse(&[
            "mailkb_db",
            "search",
            "--entity",
            "NS-ENT-100",
            "--category",
            "SaaS",
            "--topic",
            "Renewal",
            "--org",
            "Northstar",
            "--has-amount",
        ]);
        match cli2.command {
            Commands::Search(sa) => {
                let opts = build_search_opts(&sa, &cli2.global).unwrap();
                assert_eq!(opts.entity.as_deref(), Some("NS-ENT-100"));
                assert_eq!(opts.category.as_deref(), Some("SaaS"));
                assert_eq!(opts.topic.as_deref(), Some("Renewal"));
                assert_eq!(opts.org.as_deref(), Some("Northstar"));
                assert!(opts.has_amount);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn parse_read_entities_amounts_topics_orgs_timeline_att_aliases() {
        let rd = parse(&["mailkb_db", "md-read", "uid-101", "--full"]);
        match rd.command {
            Commands::Read(r) => {
                assert_eq!(r.id_or_uid, "uid-101");
                assert!(r.full);
            }
            other => panic!("unexpected: {other:?}"),
        }

        let sku = parse(&["mailkb_db", "sku", "ACME-SW-2400", "--type", "item_code", "--family", "Switch"]);
        match sku.command {
            Commands::Entities(e) => {
                let o = build_entity_opts(&e).unwrap();
                assert_eq!(o.entity.as_deref(), Some("ACME-SW-2400"));
                assert_eq!(o.entity_type.as_deref(), Some("item_code"));
                assert_eq!(o.category.as_deref(), Some("Switch"));
            }
            other => panic!("unexpected: {other:?}"),
        }

        let price = parse(&[
            "mailkb_db",
            "price",
            "switch",
            "--sku",
            "ACME-SW-2400",
            "--currency",
            "USD",
            "--project",
            "Horizon",
            "--customer",
            "Northstar",
            "--price-type",
            "quote",
            "--confidence",
            "high",
            "--since",
            "2026-01-01",
            "--until",
            "2026-12-31",
            "--limit",
            "15",
        ]);
        match price.command {
            Commands::Amounts(a) => {
                let o = build_amount_opts(&a);
                assert_eq!(o.keywords, vec!["switch"]);
                assert_eq!(o.entity.as_deref(), Some("ACME-SW-2400"));
                assert_eq!(o.currency.as_deref(), Some("USD"));
                assert_eq!(o.topic.as_deref(), Some("Horizon"));
                assert_eq!(o.org.as_deref(), Some("Northstar"));
                assert_eq!(o.amount_type.as_deref(), Some("quote"));
                assert_eq!(o.confidence.as_deref(), Some("high"));
                assert_eq!(o.limit, 15);
            }
            other => panic!("unexpected: {other:?}"),
        }

        let proj = parse(&["mailkb_db", "project", "Horizon"]);
        match proj.command {
            Commands::Topics(t) => {
                assert_eq!(build_topic_opts(&t).unwrap().topic.as_deref(), Some("Horizon"));
            }
            other => panic!("unexpected: {other:?}"),
        }

        let cust = parse(&["mailkb_db", "customer", "Northstar"]);
        match cust.command {
            Commands::Orgs(o) => {
                assert_eq!(build_org_opts(&o).unwrap().org.as_deref(), Some("Northstar"));
            }
            other => panic!("unexpected: {other:?}"),
        }

        let tl = parse(&[
            "mailkb_db",
            "timeline",
            "--granularity",
            "day",
            "--since",
            "2026-03-01",
            "--until",
            "2026-03-31",
            "--topic",
            "Horizon",
            "--org",
            "Northstar",
            "--limit",
            "60",
        ]);
        match tl.command {
            Commands::Timeline(t) => {
                assert_eq!(t.granularity, "day");
                assert_eq!(t.limit, 60);
            }
            other => panic!("unexpected: {other:?}"),
        }

        let att = parse(&[
            "mailkb_db",
            "att",
            "datasheet",
            "--entity",
            "ACME-SW-2400",
            "--topic",
            "Horizon",
            "--ext",
            "pdf",
            "--include-noise",
            "--limit",
            "10",
        ]);
        match att.command {
            Commands::Att(a) => {
                assert_eq!(a.keywords, vec!["datasheet"]);
                assert!(a.include_noise);
                assert_eq!(a.ext.as_deref(), Some("pdf"));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn dim_validation_rejects_malformed() {
        assert_eq!(parse_dim_pair("missing_eq").unwrap_err().exit_code(), 2);
        assert_eq!(parse_dim_pair("=val").unwrap_err().exit_code(), 2);
        assert_eq!(parse_dim_pair("key=").unwrap_err().exit_code(), 2);
        assert_eq!(
            parse_dim_pair("standards=IEC-61850").unwrap(),
            ("standards".to_string(), "IEC-61850".to_string())
        );
    }
}
