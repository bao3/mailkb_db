//! Pluggable JSON Domain Pack (`domain-pack.v1`) schema, compiler, and validator.
//!
//! Domain Packs move all industry-specific SKU/entity codes, taxonomy categories,
//! custom dimensions, organization aliases, topic/project lexicons, intent patterns,
//! and amount/price rules into external declarative JSON files so the `mailkb_db`
//! binary stays 100% domain-agnostic.

use crate::error::{KbError, KbResult};
use crate::minire::MiniRegex;
use crate::publish::sha256_bytes;
use crate::security::read_file_readonly;
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

/// Expected `schema_version` string for v1 domain packs.
pub const DOMAIN_PACK_SCHEMA_V1: &str = "domain-pack.v1";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DomainPack {
    pub schema_version: String,
    pub pack_id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_pack_version")]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub identity: PackIdentity,
    #[serde(default)]
    pub entity_rules: EntityRules,
    #[serde(default)]
    pub dimensions: Vec<DimensionSpec>,
    #[serde(default)]
    pub organizations: OrgRules,
    #[serde(default)]
    pub topics: TopicRules,
    #[serde(default)]
    pub intents: Vec<IntentRule>,
    #[serde(default)]
    pub amounts: AmountRules,
}

fn default_pack_version() -> String {
    "1.0".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PackIdentity {
    #[serde(default)]
    pub self_emails: Vec<String>,
    #[serde(default)]
    pub self_name_tokens: Vec<String>,
    #[serde(default)]
    pub internal_domains: Vec<String>,
    #[serde(default)]
    pub system_senders: Vec<String>,
    #[serde(default)]
    pub system_domains: Vec<String>,
    #[serde(default)]
    pub system_subject_prefixes: Vec<String>,
    #[serde(default)]
    pub system_body_markers: Vec<String>,
    #[serde(default)]
    pub noise_attachment_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityRules {
    #[serde(default = "default_general_category")]
    pub default_category: String,
    #[serde(default)]
    pub code_patterns: Vec<CodePatternRule>,
    #[serde(default)]
    pub category_fallbacks: Vec<CategoryFallbackRule>,
    #[serde(default)]
    pub exclude_code_tokens: Vec<String>,
}

fn default_general_category() -> String {
    "General".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CodePatternRule {
    #[serde(default)]
    pub name: String,
    pub pattern: String,
    #[serde(default = "default_general_category")]
    pub category: String,
    /// Optional template or static string for `sub_group` (e.g. `"SW-$1"` or `"ACME-SW"`).
    #[serde(default)]
    pub sub_group: Option<String>,
    /// Optional regex run against the matched token; first capture group forms sub_group if `sub_group` is unset.
    #[serde(default)]
    pub series_regex: Option<String>,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub exclude_if_matches: Vec<String>,
    #[serde(default)]
    pub extra_terms: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CategoryFallbackRule {
    pub category: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub priority: i32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DimensionSpec {
    pub name: String,
    #[serde(default)]
    pub entity_type: String,
    #[serde(default)]
    pub entries: Vec<LexiconRuleEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LexiconRuleEntry {
    pub key: String,
    #[serde(default)]
    pub canonical_name: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrgRules {
    #[serde(default)]
    pub exclude_domains: Vec<String>,
    #[serde(default)]
    pub exclude_names: Vec<String>,
    #[serde(default)]
    pub domain_to_org: BTreeMap<String, String>,
    #[serde(default)]
    pub email_to_org: BTreeMap<String, String>,
    #[serde(default)]
    pub entries: Vec<OrgRuleEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrgRuleEntry {
    pub canonical_name: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub emails: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TopicRules {
    #[serde(default)]
    pub generic_suffix_patterns: Vec<String>,
    #[serde(default)]
    pub entries: Vec<TopicRuleEntry>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TopicRuleEntry {
    pub canonical_name: String,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IntentRule {
    pub intent: String,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AmountRules {
    #[serde(default)]
    pub exclude_subject_patterns: Vec<String>,
    #[serde(default)]
    pub type_rules: Vec<AmountTypeRule>,
    #[serde(default)]
    pub currency_aliases: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AmountTypeRule {
    pub amount_type: String,
    #[serde(default)]
    pub confidence: Option<String>,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub patterns: Vec<String>,
}

/// Hybrid compiled regex supporting both `regex::Regex` and lookaround-capable `MiniRegex`.
#[derive(Debug, Clone)]
pub enum CompiledPattern {
    Std { raw: String, rx: Regex },
    Mini { raw: String, rx: MiniRegex },
}

impl CompiledPattern {
    pub fn compile(pat: &str) -> Result<Self, String> {
        let trimmed = pat.trim();
        if trimmed.is_empty() {
            return Err("empty regex pattern".to_string());
        }
        let needs_mini = trimmed.contains("(?<!")
            || trimmed.contains("(?!")
            || trimmed.contains("(?=");
        if !needs_mini {
            if let Ok(rx) = RegexBuilder::new(trimmed)
                .case_insensitive(true)
                .size_limit(4 * 1024 * 1024)
                .build()
            {
                return Ok(CompiledPattern::Std {
                    raw: trimmed.to_string(),
                    rx,
                });
            }
        }
        if let Some(rx) = MiniRegex::compile(trimmed) {
            return Ok(CompiledPattern::Mini {
                raw: trimmed.to_string(),
                rx,
            });
        }
        Err(format!("failed to compile pattern: {trimmed}"))
    }

    pub fn raw(&self) -> &str {
        match self {
            CompiledPattern::Std { raw, .. } | CompiledPattern::Mini { raw, .. } => raw,
        }
    }

    pub fn is_match(&self, text: &str) -> bool {
        if text.is_empty() {
            return false;
        }
        match self {
            CompiledPattern::Std { rx, .. } => rx.is_match(text),
            CompiledPattern::Mini { rx, .. } => rx.search(text),
        }
    }

    pub fn find_spans(&self, text: &str) -> Vec<(usize, usize)> {
        if text.is_empty() {
            return Vec::new();
        }
        match self {
            CompiledPattern::Std { rx, .. } => {
                rx.find_iter(text).map(|m| (m.start(), m.end())).collect()
            }
            CompiledPattern::Mini { rx, .. } => rx.find_all(text),
        }
    }

    /// Expands optional capture template (`$1`, `$2`) for std `Regex`; falls back to substring if `MiniRegex`.
    pub fn expand_template(&self, matched_slice: &str, template: &str) -> String {
        if !template.contains('$') {
            return template.to_string();
        }
        match self {
            CompiledPattern::Std { rx, .. } => {
                if let Some(caps) = rx.captures(matched_slice) {
                    let mut out = template.to_string();
                    for idx in (1..=9).rev() {
                        let placeholder = format!("${idx}");
                        if out.contains(&placeholder) {
                            let val = caps.get(idx).map(|m| m.as_str()).unwrap_or("");
                            out = out.replace(&placeholder, val);
                        }
                    }
                    out
                } else {
                    template.to_string()
                }
            }
            CompiledPattern::Mini { .. } => template.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledCodeRule {
    pub name: String,
    pub pattern: CompiledPattern,
    pub category: String,
    pub sub_group: Option<String>,
    pub series_regex: Option<Regex>,
    pub priority: i32,
    pub exclude_if_matches: Vec<CompiledPattern>,
    pub extra_terms: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CompiledCategoryFallback {
    pub category: String,
    pub patterns: Vec<CompiledPattern>,
    pub priority: i32,
}

#[derive(Debug, Clone)]
pub struct CompiledDimensionEntry {
    pub key: String,
    pub canonical_name: String,
    pub patterns: Vec<CompiledPattern>,
    pub aliases: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone)]
pub struct CompiledDimension {
    pub name: String,
    pub entity_type: String,
    pub entries: Vec<CompiledDimensionEntry>,
}

#[derive(Debug, Clone)]
pub struct CompiledOrgEntry {
    pub canonical_name: String,
    pub patterns: Vec<CompiledPattern>,
    pub aliases: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone)]
pub struct CompiledTopicEntry {
    pub canonical_name: String,
    pub patterns: Vec<CompiledPattern>,
    pub aliases: String,
    pub metadata_json: String,
}

#[derive(Debug, Clone)]
pub struct CompiledIntentRule {
    pub intent: String,
    pub priority: i32,
    pub patterns: Vec<CompiledPattern>,
}

#[derive(Debug, Clone)]
pub struct CompiledAmountTypeRule {
    pub amount_type: String,
    pub confidence: Option<String>,
    pub priority: i32,
    pub patterns: Vec<CompiledPattern>,
}

#[derive(Debug, Clone)]
pub struct DomainLexiconSeedRow {
    pub pack_id: String,
    pub dimension: String,
    pub key: String,
    pub canonical_name: String,
    pub aliases: String,
    pub metadata_json: String,
}

/// Merged, compiled runtime representation of zero or more `domain-pack.v1` JSON packs.
#[derive(Debug, Clone, Default)]
pub struct CompiledDomainPack {
    pub loaded_pack_ids: Vec<String>,
    pub pack_hashes: BTreeMap<String, String>,
    pub self_emails: HashSet<String>,
    pub self_name_tokens: Vec<String>,
    pub internal_domains: HashSet<String>,
    pub system_senders: HashSet<String>,
    pub system_domains: HashSet<String>,
    pub system_subject_prefixes: Vec<String>,
    pub system_body_markers: Vec<String>,
    pub noise_attachment_prefixes: Vec<String>,
    pub default_category: String,
    pub exclude_code_tokens: HashSet<String>,
    pub code_rules: Vec<CompiledCodeRule>,
    pub category_fallbacks: Vec<CompiledCategoryFallback>,
    pub dimensions: Vec<CompiledDimension>,
    pub org_exclude_domains: HashSet<String>,
    pub org_exclude_names: HashSet<String>,
    pub domain_to_org: BTreeMap<String, String>,
    pub email_to_org: BTreeMap<String, String>,
    pub org_entries: Vec<CompiledOrgEntry>,
    pub topic_generic_suffixes: Vec<CompiledPattern>,
    pub topic_entries: Vec<CompiledTopicEntry>,
    pub intent_rules: Vec<CompiledIntentRule>,
    pub amount_exclude_subjects: Vec<CompiledPattern>,
    pub amount_type_rules: Vec<CompiledAmountTypeRule>,
    pub currency_aliases: BTreeMap<String, String>,
    pub lexicon_rows: Vec<DomainLexiconSeedRow>,
}

impl CompiledDomainPack {
    /// Returns a clean empty universal pack (zero domain pack mode).
    pub fn empty() -> Self {
        Self {
            default_category: default_general_category(),
            ..Default::default()
        }
    }

    /// Loads and merges an ordered slice of `domain-pack.v1` JSON files.
    pub fn from_files(paths: &[PathBuf]) -> KbResult<Self> {
        let mut parsed = Vec::with_capacity(paths.len());
        for path in paths {
            let (bytes, truncated) = read_file_readonly(path, Some(32 * 1024 * 1024))?;
            if truncated || bytes.is_empty() {
                return Err(KbError::PackValidation(format!(
                    "pack file {} is empty or exceeds 32 MiB",
                    path.display()
                )));
            }
            let sha = sha256_bytes(&bytes);
            let pack: DomainPack = serde_json::from_slice(&bytes).map_err(|e| {
                KbError::PackValidation(format!("parse JSON {}: {e}", path.display()))
            })?;
            parsed.push((pack, sha));
        }
        Self::from_packs(parsed)
    }

    /// Compiles and merges already-parsed `DomainPack` definitions.
    pub fn from_packs(packs: Vec<(DomainPack, String)>) -> KbResult<Self> {
        let mut out = Self::empty();
        if packs.is_empty() {
            return Ok(out);
        }

        let mut seen_pack_ids = HashSet::new();
        for (pack, sha) in packs {
            if pack.schema_version != DOMAIN_PACK_SCHEMA_V1 {
                return Err(KbError::PackValidation(format!(
                    "pack '{}' schema_version '{}' != '{}'",
                    pack.pack_id, pack.schema_version, DOMAIN_PACK_SCHEMA_V1
                )));
            }
            let pack_id = pack.pack_id.trim().to_string();
            if pack_id.is_empty() {
                return Err(KbError::PackValidation("pack_id must not be empty".to_string()));
            }
            if !seen_pack_ids.insert(pack_id.clone()) {
                return Err(KbError::PackValidation(format!(
                    "duplicate pack_id '{pack_id}'"
                )));
            }
            out.loaded_pack_ids.push(pack_id.clone());
            out.pack_hashes.insert(pack_id.clone(), sha);

            for e in pack.identity.self_emails {
                let s = e.trim().to_ascii_lowercase();
                if !s.is_empty() {
                    out.self_emails.insert(s);
                }
            }
            for t in pack.identity.self_name_tokens {
                let s = t.trim().to_string();
                if !s.is_empty() {
                    out.self_name_tokens.push(s);
                }
            }
            for d in pack.identity.internal_domains {
                let s = d.trim().to_ascii_lowercase();
                if !s.is_empty() {
                    out.internal_domains.insert(s);
                }
            }
            for s in pack.identity.system_senders {
                let v = s.trim().to_ascii_lowercase();
                if !v.is_empty() {
                    out.system_senders.insert(v);
                }
            }
            for d in pack.identity.system_domains {
                let v = d.trim().to_ascii_lowercase();
                if !v.is_empty() {
                    out.system_domains.insert(v);
                }
            }
            for p in pack.identity.system_subject_prefixes {
                let v = p.trim().to_string();
                if !v.is_empty() {
                    out.system_subject_prefixes.push(v);
                }
            }
            for m in pack.identity.system_body_markers {
                let v = m.trim().to_string();
                if !v.is_empty() {
                    out.system_body_markers.push(v);
                }
            }
            for np in pack.identity.noise_attachment_prefixes {
                let v = np.trim().to_string();
                if !v.is_empty() {
                    out.noise_attachment_prefixes.push(v);
                }
            }

            if !pack.entity_rules.default_category.trim().is_empty() {
                out.default_category = pack.entity_rules.default_category.trim().to_string();
            }
            for tok in pack.entity_rules.exclude_code_tokens {
                let v = tok.trim().to_ascii_uppercase();
                if !v.is_empty() {
                    out.exclude_code_tokens.insert(v);
                }
            }
            for cr in pack.entity_rules.code_patterns {
                let pat = CompiledPattern::compile(&cr.pattern).map_err(|e| {
                    KbError::PackValidation(format!("pack '{pack_id}' code_pattern '{}': {e}", cr.pattern))
                })?;
                let mut ex_pats = Vec::with_capacity(cr.exclude_if_matches.len());
                for ep in cr.exclude_if_matches {
                    ex_pats.push(CompiledPattern::compile(&ep).map_err(|e| {
                        KbError::PackValidation(format!(
                            "pack '{pack_id}' exclude_if_matches '{ep}': {e}"
                        ))
                    })?);
                }
                let series_regex = match cr.series_regex {
                    Some(ref sr) if !sr.trim().is_empty() => Some(
                        RegexBuilder::new(sr.trim())
                            .case_insensitive(true)
                            .build()
                            .map_err(|e| {
                                KbError::PackValidation(format!(
                                    "pack '{pack_id}' series_regex '{sr}': {e}"
                                ))
                            })?,
                    ),
                    _ => None,
                };
                out.code_rules.push(CompiledCodeRule {
                    name: cr.name,
                    pattern: pat,
                    category: if cr.category.trim().is_empty() {
                        out.default_category.clone()
                    } else {
                        cr.category.trim().to_string()
                    },
                    sub_group: cr.sub_group,
                    series_regex,
                    priority: cr.priority,
                    exclude_if_matches: ex_pats,
                    extra_terms: cr.extra_terms,
                });
            }

            for fb in pack.entity_rules.category_fallbacks {
                let mut pats = Vec::new();
                for p in fb.patterns {
                    pats.push(CompiledPattern::compile(&p).map_err(|e| {
                        KbError::PackValidation(format!(
                            "pack '{pack_id}' category_fallback '{}': {e}",
                            fb.category
                        ) + &format!(" ({e})"))
                    })?);
                }
                out.category_fallbacks.push(CompiledCategoryFallback {
                    category: fb.category,
                    patterns: pats,
                    priority: fb.priority,
                });
            }

            for dim in pack.dimensions {
                let d_name = dim.name.trim().to_string();
                if d_name.is_empty() {
                    return Err(KbError::PackValidation(format!(
                        "pack '{pack_id}' dimension name must not be empty"
                    )));
                }
                let entity_type = if dim.entity_type.trim().is_empty() {
                    d_name.clone()
                } else {
                    dim.entity_type.trim().to_string()
                };
                let mut compiled_entries = Vec::new();
                for entry in dim.entries {
                    let key = entry.key.trim().to_string();
                    if key.is_empty() {
                        continue;
                    }
                    let canonical_name = if entry.canonical_name.trim().is_empty() {
                        key.clone()
                    } else {
                        entry.canonical_name.trim().to_string()
                    };
                    let mut pats = Vec::new();
                    for p in &entry.patterns {
                        pats.push(CompiledPattern::compile(p).map_err(|e| {
                            KbError::PackValidation(format!(
                                "pack '{pack_id}' dimension '{d_name}' entry '{key}': {e}"
                            ))
                        })?);
                    }
                    let aliases = entry.aliases.join(",");
                    let metadata_json = if entry.metadata.is_null() {
                        "{}".to_string()
                    } else {
                        entry.metadata.to_string()
                    };
                    out.lexicon_rows.push(DomainLexiconSeedRow {
                        pack_id: pack_id.clone(),
                        dimension: d_name.clone(),
                        key: key.clone(),
                        canonical_name: canonical_name.clone(),
                        aliases: aliases.clone(),
                        metadata_json: metadata_json.clone(),
                    });
                    compiled_entries.push(CompiledDimensionEntry {
                        key,
                        canonical_name,
                        patterns: pats,
                        aliases,
                        metadata_json,
                    });
                }
                if let Some(existing) = out.dimensions.iter_mut().find(|d| d.name == d_name) {
                    existing.entries.extend(compiled_entries);
                } else {
                    out.dimensions.push(CompiledDimension {
                        name: d_name,
                        entity_type,
                        entries: compiled_entries,
                    });
                }
            }

            for d in pack.organizations.exclude_domains {
                let v = d.trim().to_ascii_lowercase();
                if !v.is_empty() {
                    out.org_exclude_domains.insert(v);
                }
            }
            for n in pack.organizations.exclude_names {
                let v = n.trim().to_ascii_lowercase();
                if !v.is_empty() {
                    out.org_exclude_names.insert(v);
                }
            }
            for (k, v) in pack.organizations.domain_to_org {
                out.domain_to_org
                    .insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
            for (k, v) in pack.organizations.email_to_org {
                out.email_to_org
                    .insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
            for org in pack.organizations.entries {
                let canonical = org.canonical_name.trim().to_string();
                if canonical.is_empty() {
                    continue;
                }
                for dom in &org.domains {
                    let dl = dom.trim().to_ascii_lowercase();
                    if !dl.is_empty() {
                        out.domain_to_org.entry(dl).or_insert_with(|| canonical.clone());
                    }
                }
                for em in &org.emails {
                    let el = em.trim().to_ascii_lowercase();
                    if !el.is_empty() {
                        out.email_to_org.entry(el).or_insert_with(|| canonical.clone());
                    }
                }
                let mut pats = Vec::new();
                for p in &org.patterns {
                    pats.push(CompiledPattern::compile(p).map_err(|e| {
                        KbError::PackValidation(format!(
                            "pack '{pack_id}' organization '{canonical}': {e}"
                        ))
                    })?);
                }
                let aliases = org.aliases.join(",");
                let metadata_json = if org.metadata.is_null() {
                    "{}".to_string()
                } else {
                    org.metadata.to_string()
                };
                out.lexicon_rows.push(DomainLexiconSeedRow {
                    pack_id: pack_id.clone(),
                    dimension: "organization".to_string(),
                    key: canonical.clone(),
                    canonical_name: canonical.clone(),
                    aliases: aliases.clone(),
                    metadata_json: metadata_json.clone(),
                });
                out.org_entries.push(CompiledOrgEntry {
                    canonical_name: canonical,
                    patterns: pats,
                    aliases,
                    metadata_json,
                });
            }

            for sp in pack.topics.generic_suffix_patterns {
                out.topic_generic_suffixes
                    .push(CompiledPattern::compile(&sp).map_err(|e| {
                        KbError::PackValidation(format!(
                            "pack '{pack_id}' topic generic_suffix_pattern '{sp}': {e}"
                        ))
                    })?);
            }
            for top in pack.topics.entries {
                let canonical = top.canonical_name.trim().to_string();
                if canonical.is_empty() {
                    continue;
                }
                let mut pats = Vec::new();
                for p in &top.patterns {
                    pats.push(CompiledPattern::compile(p).map_err(|e| {
                        KbError::PackValidation(format!(
                            "pack '{pack_id}' topic '{canonical}': {e}"
                        ))
                    })?);
                }
                let aliases = top.aliases.join(",");
                let metadata_json = if top.metadata.is_null() {
                    "{}".to_string()
                } else {
                    top.metadata.to_string()
                };
                out.lexicon_rows.push(DomainLexiconSeedRow {
                    pack_id: pack_id.clone(),
                    dimension: "topic".to_string(),
                    key: canonical.clone(),
                    canonical_name: canonical.clone(),
                    aliases: aliases.clone(),
                    metadata_json: metadata_json.clone(),
                });
                out.topic_entries.push(CompiledTopicEntry {
                    canonical_name: canonical,
                    patterns: pats,
                    aliases,
                    metadata_json,
                });
            }

            for ir in pack.intents {
                let intent = ir.intent.trim().to_string();
                if intent.is_empty() {
                    continue;
                }
                let mut pats = Vec::new();
                for p in &ir.patterns {
                    pats.push(CompiledPattern::compile(p).map_err(|e| {
                        KbError::PackValidation(format!(
                            "pack '{pack_id}' intent '{intent}': {e}"
                        ))
                    })?);
                }
                out.intent_rules.push(CompiledIntentRule {
                    intent,
                    priority: ir.priority,
                    patterns: pats,
                });
            }

            for sp in pack.amounts.exclude_subject_patterns {
                out.amount_exclude_subjects
                    .push(CompiledPattern::compile(&sp).map_err(|e| {
                        KbError::PackValidation(format!(
                            "pack '{pack_id}' amount exclude_subject_pattern '{sp}': {e}"
                        ))
                    })?);
            }
            for tr in pack.amounts.type_rules {
                let mut pats = Vec::new();
                for p in &tr.patterns {
                    pats.push(CompiledPattern::compile(p).map_err(|e| {
                        KbError::PackValidation(format!(
                            "pack '{pack_id}' amount_type_rule '{}': {e}",
                            tr.amount_type
                        ))
                    })?);
                }
                out.amount_type_rules.push(CompiledAmountTypeRule {
                    amount_type: tr.amount_type,
                    confidence: tr.confidence,
                    priority: tr.priority,
                    patterns: pats,
                });
            }
            for (k, v) in pack.amounts.currency_aliases {
                out.currency_aliases
                    .insert(k.trim().to_ascii_uppercase(), v.trim().to_ascii_uppercase());
            }
        }

        // Highest priority first, preserving declaration order on ties.
        out.code_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        out.category_fallbacks.sort_by(|a, b| b.priority.cmp(&a.priority));
        out.intent_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        out.amount_type_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        Ok(out)
    }

    /// Concatenated sha256 fingerprint across all loaded packs (or `"universal-none"`).
    pub fn rules_fingerprint(&self) -> String {
        if self.pack_hashes.is_empty() {
            return "universal-none".to_string();
        }
        let mut s = String::new();
        for (id, sha) in &self.pack_hashes {
            if !s.is_empty() {
                s.push(';');
            }
            s.push_str(id);
            s.push(':');
            s.push_str(&sha[..sha.len().min(12)]);
        }
        s
    }
}

/// Summary produced by `validate_pack_file`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackValidationReport {
    pub path: PathBuf,
    pub schema_version: String,
    pub pack_id: String,
    pub version: String,
    pub sha256: String,
    pub pattern_count: usize,
    pub dimension_count: usize,
    pub organization_count: usize,
    pub topic_count: usize,
    pub intent_count: usize,
    pub warnings: Vec<String>,
    pub valid: bool,
}

fn check_hazard_pattern(pat: &CompiledPattern, label: &str, warnings: &mut Vec<String>) -> KbResult<()> {
    let raw = pat.raw().trim();
    if matches!(
        raw,
        ".*" | ".+" | "^.*$" | "^.+$" | "\\d+" | "^\\d+$" | "[a-z]+" | "[a-z0-9]+" | "\\w+"
    ) {
        return Err(KbError::PackValidation(format!(
            "overly broad hazard pattern in {label}: '{raw}'"
        )));
    }
    let probe = "hello world 12345 2026-01-01 test status update";
    if pat.is_match("") {
        return Err(KbError::PackValidation(format!(
            "pattern matches empty string in {label}: '{raw}'"
        )));
    }
    if pat.is_match(probe) {
        warnings.push(format!(
            "broad_pattern_matched_benign_probe in {label}: '{raw}'"
        ));
    }
    Ok(())
}

/// Validates a `domain-pack.v1` JSON file against structural, duplicate, regex compilation,
/// and hazard pattern rules.
pub fn validate_pack_file(path: &Path) -> KbResult<PackValidationReport> {
    let (bytes, truncated) = read_file_readonly(path, Some(32 * 1024 * 1024))?;
    if truncated || bytes.is_empty() {
        return Err(KbError::PackValidation(format!(
            "pack file {} is empty or exceeds 32 MiB",
            path.display()
        )));
    }
    let sha256 = sha256_bytes(&bytes);
    let pack: DomainPack = serde_json::from_slice(&bytes)
        .map_err(|e| KbError::PackValidation(format!("parse JSON {}: {e}", path.display())))?;

    if pack.schema_version != DOMAIN_PACK_SCHEMA_V1 {
        return Err(KbError::PackValidation(format!(
            "unsupported schema_version '{}' (expected '{}')",
            pack.schema_version, DOMAIN_PACK_SCHEMA_V1
        )));
    }
    if pack.pack_id.trim().is_empty() {
        return Err(KbError::PackValidation("pack_id must not be empty".to_string()));
    }

    let mut warnings = Vec::new();
    let mut dup_keys = HashSet::new();
    for dim in &pack.dimensions {
        for e in &dim.entries {
            let k = (dim.name.trim().to_ascii_lowercase(), e.key.trim().to_ascii_lowercase());
            if !dup_keys.insert(k) {
                warnings.push(format!(
                    "duplicate dimension entry key '{}' in '{}'",
                    e.key, dim.name
                ));
            }
        }
    }
    let mut dup_orgs = HashSet::new();
    for o in &pack.organizations.entries {
        if !dup_orgs.insert(o.canonical_name.trim().to_ascii_lowercase()) {
            warnings.push(format!("duplicate organization '{}'", o.canonical_name));
        }
    }
    let mut dup_topics = HashSet::new();
    for t in &pack.topics.entries {
        if !dup_topics.insert(t.canonical_name.trim().to_ascii_lowercase()) {
            warnings.push(format!("duplicate topic '{}'", t.canonical_name));
        }
    }

    let compiled = CompiledDomainPack::from_packs(vec![(pack.clone(), sha256.clone())])?;

    let mut pattern_count = 0usize;
    for r in &compiled.code_rules {
        pattern_count += 1 + r.exclude_if_matches.len();
        check_hazard_pattern(&r.pattern, &format!("code_pattern:{}", r.name), &mut warnings)?;
    }
    for fb in &compiled.category_fallbacks {
        for p in &fb.patterns {
            pattern_count += 1;
            check_hazard_pattern(p, &format!("category_fallback:{}", fb.category), &mut warnings)?;
        }
    }
    for dim in &compiled.dimensions {
        for e in &dim.entries {
            for p in &e.patterns {
                pattern_count += 1;
                check_hazard_pattern(p, &format!("dimension:{}:{}", dim.name, e.key), &mut warnings)?;
            }
        }
    }
    for o in &compiled.org_entries {
        for p in &o.patterns {
            pattern_count += 1;
            check_hazard_pattern(p, &format!("organization:{}", o.canonical_name), &mut warnings)?;
        }
    }
    for t in &compiled.topic_entries {
        for p in &t.patterns {
            pattern_count += 1;
            check_hazard_pattern(p, &format!("topic:{}", t.canonical_name), &mut warnings)?;
        }
    }
    for ir in &compiled.intent_rules {
        for p in &ir.patterns {
            pattern_count += 1;
            check_hazard_pattern(p, &format!("intent:{}", ir.intent), &mut warnings)?;
        }
    }
    for ar in &compiled.amount_type_rules {
        for p in &ar.patterns {
            pattern_count += 1;
            check_hazard_pattern(p, &format!("amount_type:{}", ar.amount_type), &mut warnings)?;
        }
    }

    Ok(PackValidationReport {
        path: path.to_path_buf(),
        schema_version: pack.schema_version,
        pack_id: pack.pack_id,
        version: pack.version,
        sha256,
        pattern_count,
        dimension_count: pack.dimensions.len(),
        organization_count: pack.organizations.entries.len(),
        topic_count: pack.topics.entries.len(),
        intent_count: pack.intents.len(),
        warnings,
        valid: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_pattern_supports_std_and_lookaround() {
        let p_std = CompiledPattern::compile(r"\bACME-[A-Z]{2}-\d{3,4}\b").unwrap();
        assert_eq!(p_std.find_spans("Quote for ACME-SW-2400 and ACME-GW-100."), vec![(10, 22), (27, 38)]);

        let p_mini = CompiledPattern::compile(r"(?<![A-Za-z0-9])SW-\d{3}(?![A-Za-z0-9])").unwrap();
        assert!(p_mini.is_match("Order SW-205 today"));
        assert!(!p_mini.is_match("Order XSW-205A today"));
        assert_eq!(p_mini.find_spans("Order SW-205 and SW-408"), vec![(6, 12), (17, 23)]);
    }

    #[test]
    fn hazard_pattern_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("bad.json");
        std::fs::write(
            &p,
            r#"{
              "schema_version": "domain-pack.v1",
              "pack_id": "bad",
              "entity_rules": {
                "code_patterns": [{"name": "all_digits", "pattern": "^\\d+$", "category": "Switch"}]
              }
            }"#,
        )
        .unwrap();
        let err = validate_pack_file(&p).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }
}
