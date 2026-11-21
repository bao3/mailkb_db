# Domain Pack Authoring Guide (`domain-pack.v1`)

Detailed reference for designing, tuning, and validating `domain-pack.v1` JSON packs consumed by `mailkb_db`. Canonical Rust definitions live in [domain_pack.rs](../../../crates/mailkb-core/src/domain_pack.rs) and [minire.rs](../../../crates/mailkb-core/src/minire.rs); the formal schema is [domain-pack.v1.schema.json](../../../schemas/domain-pack.v1.schema.json).

---

## 1. Discovery, Loading & Multi-Pack Merge Semantics

By default, `mailkb_db` auto-loads all non-hidden `*.json` files in `~/.config/mailkb_db/packs/` (override directory with `MAILKB_DB_PACKS_DIR`) sorted lexically by filename.

Override options:
- `--pack <PATH>` (repeatable) or `MAILKB_DB_PACK=<path1>:<path2>` — load an explicit list instead of auto-discovery.
- `--no-packs` or `MAILKB_DB_NO_PACKS=1` — disable all Domain Packs (pure universal extraction mode).

Merge rules when multiple packs are loaded:
- Every pack must have `schema_version == "domain-pack.v1"` and a unique non-empty `pack_id` (duplicate `pack_id` fails validation).
- Sets/maps (`self_emails`, `internal_domains`, `exclude_code_tokens`, `domain_to_org`, `email_to_org`, `currency_aliases`) union across packs; later packs overwrite conflicting map keys in `domain_to_org`, `email_to_org`, and `currency_aliases`.
- `dimensions` entries with matching `name` append into the same compiled dimension.
- Priority-ranked rule lists (`code_patterns`, `category_fallbacks`, `intents`, `amounts.type_rules`) merge and sort descending by `priority` (ties preserve declaration order).
- `CompiledDomainPack::rules_fingerprint()` hashes every loaded pack's SHA-256 into `kb_meta` so `mailkb_db sync` knows when rules changed.

---

## 2. Regex Engine & Lookaround Rules

Every regex field in `domain-pack.v1` (except `series_regex`) compiles through `CompiledPattern::compile` in case-insensitive mode (`case_insensitive(true)`):

### Engine Routing
1. **Standard Rust `regex::Regex`** (4 MiB compiled size limit): selected when the pattern does **not** contain `(?<!`, `(?!`, or `(?=`.
   - Supports `\b`, Unicode classes, non-capturing groups `(?:...)`, and capturing groups `(...)` used by `sub_group` templates (`$1`..`$9`).
   - **CJK Adjacency Gotcha**: Rust's `regex` engine runs in Unicode mode by default, meaning `\b` treats CJK ideographs as word characters (`\w`). A pattern like `\bACME-SW-2400\b` will **not** match inside `"请报价ACME-SW-2400谢谢"` because there is no `\b` between `价` and `A`! For multilingual / CJK emails, prefer `MiniRegex` ASCII lookarounds `(?<![A-Za-z0-9])ACME-SW-\d{3,4}(?![A-Za-z0-9])` paired with `series_regex`.
2. **ReDoS-Safe `MiniRegex`** ([minire.rs](../../../crates/mailkb-core/src/minire.rs)): automatically selected whenever the pattern contains `(?<!`, `(?!`, or `(?=`.
   - Supported features:
     - Negative lookbehind with a character class: `(?<![A-Za-z0-9])`
     - Negative lookahead with a character class: `(?![A-Za-z0-9])` or literal prefix: `(?!-DEV)`
     - Positive lookahead with a character class: `(?=[A-Z0-9-])`
     - ASCII `\b`, `\s`, `\d`, `.`, character classes `[...]`, alternation `|`, `(?:...)` groups, and bounded/standard quantifiers (`?`, `*`, `+`, `{m,n}`, lazy `*?`/`+?`).
   - **Important `MiniRegex` limits**:
     - Does **not** expand `$1`..`$9` capture templates in `sub_group` (returns the template string literally).
     - Does **not** treat `^` or `$` as start/end anchors outside `[...]`.
     - If you use lookarounds in `CodePatternRule.pattern` and want dynamic series extraction, pair it with `series_regex` instead of `$1` in `sub_group`.

### `series_regex` Constraint
`CodePatternRule.series_regex` compiles directly with `regex::RegexBuilder` (standard Rust regex), **not** `MiniRegex`. Never put lookarounds inside `series_regex`.

Example pairing lookaround matching with standard `series_regex`:
```json
{
  "name": "acme_gateway_lookaround",
  "pattern": "(?<![A-Za-z0-9])ACME-GW-\\d{3,4}[A-Z]?(?:-[A-Z0-9]{1,6})*(?![A-Za-z0-9])",
  "category": "Gateway",
  "series_regex": "^(ACME-GW-\\d{3,4})",
  "priority": 95
}
```

### Hazard & Benign-Probe Validation
`validate-pack` enforces two levels of safety:
1. **Hard errors (`exit_code = 2`)**:
   - Banned wildcard patterns: `.*`, `.+`, `^.*$`, `^.+$`, `\d+`, `^\d+$`, `[a-z]+`, `[a-z0-9]+`, `\w+`.
   - Any pattern that matches the empty string `""`.
   - Any regex syntax failure or oversized regex (>4 MiB).
2. **Warnings**:
   - `broad_pattern_matched_benign_probe`: emitted when a pattern matches the probe string `"hello world 12345 2026-01-01 test status update"`.
   - Duplicate dimension keys, duplicate organization `canonical_name`s, or duplicate topic `canonical_name`s.

---

## 3. Section-by-Section Authoring Reference

### `identity` (`PackIdentity`)
Controls message `direction` (`internal`, `external_inbound`, `external_outbound`, `system_notice`) and signature image filtering (`is_noise = 1`):
- `self_emails` / `self_name_tokens` / `internal_domains`: Leave empty if you want `mailkb_db` to auto-infer solely from `Sent` mailboxes, or populate explicitly when mailboxes include aliases, distribution lists, or multiple corporate domains. Never put freemail domains (`gmail.com`, `outlook.com`) in `internal_domains`.
- `system_senders`, `system_domains`, `system_subject_prefixes`, `system_body_markers`: Route automated CRM/ERP/DocuSign/bounce notifications to `direction = "system_notice"` so automated noise does not skew commercial timelines.
- `noise_attachment_prefixes`: Suppresses recurring logo/banner filenames (`image00`, `company_logo`, `email_banner`) from `mailkb_db att` default results.

### `entity_rules` (`EntityRules`)
Extracts structured `item_code` entities into `message_entities` and sets `mail_messages.primary_category`:
- **`code_patterns`**: Put most-specific patterns at higher `priority` (e.g., `100` before `60`).
  - Use `sub_group` (`"$1"` with standard regex capture groups, or static string `"ACME-SFP"`) or `series_regex` (`"^(ACME-GW-\\d{3,4})"`) so variant SKUs (`ACME-SW-2400-24P-POE`) roll up cleanly under `ACME-SW-2400`.
  - Use `exclude_if_matches` to reject placeholder or test codes (e.g., `\\bACME-SW-0000\\b`).
  - Use `extra_terms` to inject domain synonyms into `dimensions_fts` for better semantic search recall.
- **`exclude_code_tokens`**: Uppercase tokens frequently mistaken for SKUs—for example `ISO-9001`, `IEC-61000`, `UTF-8`, `RFC-2047`, `HTTP-404`, `PO-BOX`, `WIN-11`.
- **`category_fallbacks`**: Prose patterns evaluated when no explicit SKU/code identifies the product/service family (e.g., `\\bModbus\\s+TCP\\s+gateway\\b` -> `Gateway`).

### `dimensions` (`Vec<DimensionSpec>`)
Creates custom structured taxonomy dimensions beyond SKUs, orgs, and topics:
- Each `DimensionSpec` defines `name` (stored in `custom_dims_json` and `domain_lexicon.dimension`) and `entity_type` (stored in `message_entities.entity_type`; defaults to `name`).
- Examples by domain:
  - **B2B Hardware**: `standards` (`IEC-61850-3`, `EN-50155`, `UL-C1D2`), `subsystems` (`SCADA`, `CCTV_Backbone`).
  - **SaaS Commercial**: `compliance` (`SOC2_Type_II`, `ISO_27001`, `GDPR_DPA`), `deployment_tier` (`Dedicated_VPC`, `BYOC_Hybrid`).
  - **Legal / Procurement**: `clauses` (`Limitation_of_Liability`, `Indemnity`, `Auto_Renewal`), `jurisdiction` (`Delaware`, `EU_SCC`).
  - **Logistics / Freight**: `incoterms` (`EXW`, `FOB`, `DDP`, `CIF`), `mode` (`Ocean_FCL`, `Air_Express`).
- Queryable directly via `mailkb_db search --dim <name>=<key>` (for example, `--dim standards=EN-50155`).

### `organizations` (`OrgRules`)
Normalizes sender/recipient domains and body mentions to canonical customer/partner/vendor names:
- Always list freemail and generic relay domains (`gmail.com`, `outlook.com`, `yahoo.com`, `icloud.com`, `qq.com`, `163.com`) in `exclude_domains`.
- Put generic role names (`unknown`, `sales`, `support`, `billing`, `info`) in `exclude_names`.
- Use `domain_to_org` and `email_to_org` for deterministic sender/recipient mapping, and `entries` for multi-domain accounts, aliases, body-mention regexes (crucial when an intermediary forwards a third-party end-customer quote!), and metadata (`tier`, `vertical`, `region`).

### `topics` (`TopicRules`)
Extracts projects, deals, engagements, or matters into `topic_tags`:
- Use `generic_suffix_patterns` to strip recurring noise like `\s*-\s*quotation$`, `\s*-\s*follow\s*up$`, or `\s*\[external\]$`.
- Register active project codes and multi-alias deal names in `entries`.

### `intents` (`Vec<IntentRule>`)
Assigns a primary `intent_type` per message (`priority` descending):
- Order narrow, high-value commercial actions (`purchase_order`, `order_form_contract`, `special_pricing_approval`, `renewal`) above broad conversational ones (`rfq_quote`, `technical_spec`, `general_followup`).

### `amounts` (`AmountRules`)
Governs commercial price/amount extraction from inline text, HTML tables, and `.xlsx`/`.xlsm` attachments:
- `exclude_subject_patterns`: Suppress false-positive currency extraction in newsletters, release notes, payroll/HR notices, or status alerts.
- `type_rules`: Classify amounts (`order_price`, `quote`, `special_price`, `contract_acv`, `renewal_quote`, `invoice`, `budget_estimate`) with priority and optional `confidence` (`"high"`, `"medium"`, `"low"`).
- `currency_aliases`: Normalize symbols and non-ISO abbreviations into standard ISO-4217 codes (`"US$": "USD"`, `"$": "USD"`, `"RMB": "CNY"`, `"¥": "CNY"`, `"€": "EUR"`, `"NTD": "TWD"`).

---

## 4. Iterative Tuning Playbook

1. **Bootstrap from `profile-corpus`**:
   - Convert top `inferred_identity` into `identity` (if explicit pinning is needed).
   - Convert top non-freemail `top_external_domains` into `organizations.domain_to_org` / `entries`.
   - Convert valid `code_token_candidates` into `entity_rules.code_patterns`, and junk tokens into `exclude_code_tokens`.
2. **Validate early and often**:
   - Run `mailkb_db validate-pack ~/.config/mailkb_db/packs/<domain>.json --json`.
   - Eliminate all `broad_pattern_matched_benign_probe` warnings before testing on full mail.
3. **Evaluate with `test-pack`**:
   - Run `mailkb_db test-pack ~/.config/mailkb_db/packs/<domain>.json --sample 200 --json`.
   - Review `top_entities`: if generic headers (`HTTP-200`, `REV-02`, `Q1-2026`) appear, add them to `exclude_code_tokens` or add `exclude_if_matches`.
   - Review `unmatched_sample_subjects`: spot missed customer abbreviations, project codes, or industry keywords and add rules carefully.
4. **Publish & Verify**:
   - Run `mailkb_db sync --full` and verify real queries with `mailkb_db search`, `mailkb_db entities`, `mailkb_db amounts`, and `mailkb_db stats`.
