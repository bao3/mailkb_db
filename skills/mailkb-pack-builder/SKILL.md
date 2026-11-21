---
name: mailkb-pack-builder
description: Profile a user's mailbox and local reference documents (read-only), enrich with public industry terminology, and synthesize, validate, and test a custom domain-pack.v1 JSON pack (~/.config/mailkb_db/packs/<domain>.json) for mailkb_db. Use whenever a user wants to adapt mailkb_db to a new industry, company, SKU/code format, custom taxonomy dimension, or commercial pricing/intent workflow.
---

# mailkb_db Domain Pack Builder

Generate and verify a declarative `domain-pack.v1` JSON Domain Pack at `~/.config/mailkb_db/packs/<domain>.json` so `mailkb_db` indexes any user's industry mailboxes with high precision while keeping the `mailkb_db` binary 100% domain-agnostic.

This skill works across Antigravity, Claude Code, Codex, and Cursor. Before authoring rules, consult:
- Schema: [domain-pack.v1.schema.json](../../schemas/domain-pack.v1.schema.json)
- Authoring guide & regex engine details: [pack-authoring-guide.md](references/pack-authoring-guide.md)
- Fictional reference packs: [b2b-hardware.sample.json](../../packs/examples/b2b-hardware.sample.json) and [saas-commercial.sample.json](../../packs/examples/saas-commercial.sample.json)

## Hard Safety & Privacy Guardrails

1. **Never write inside mail client containers**: Never create, edit, stage, or run SQLite writes inside `~/Library/Mail`, `~/Library/Group Containers/UBF8T346G9.Office`, or `~/Library/Thunderbird`. `mailkb_db` enforces S9 write guards (`exit_code = 2`) and always reads mail sources read-only.
2. **Never embed secrets or commit private packs**: Never store passwords, API keys, tokens, or auth cookies in a Domain Pack. Save personal/company packs outside public git repositories in `~/.config/mailkb_db/packs/<domain>.json` with `chmod 600` (or gitignored `packs/local/`).
3. **Prefer boundary-guarded regexes over noisy wildcards**: Always guard entity/code patterns with `\b...\b` or lookarounds `(?<![A-Za-z0-9])...(?![A-Za-z0-9])`. Never emit bare wildcards (`.*`, `.+`, `\d+`, `\w+`, `[a-z0-9]+`) or patterns matching empty strings or ordinary prose.
4. **Permission-gate local reference reading**: Never scan local document folders (quotes, spreadsheets, CRM exports, contracts) without explicit user approval, and open them strictly read-only.
5. **Never bypass staged SQLite reads**: Never open `~/.local/share/mailkb_db/mailkb_db.sqlite` directly with read-write SQLite tools; always use `mailkb_db` commands.

## 4-Phase Closed-Loop Workflow

### Phase 1: Profile Mailbox (Read-Only)

Run the built-in corpus profiler to inspect the user's real mail metadata without modifying any source container:

```bash
mailkb_db profile-corpus --limit 2000 --json --out /tmp/mailkb-profile.json
```

Optional source scopes:
- Standalone `.eml`/`.emlx` directory: add `--eml-dir /path/to/archive`
- Existing SQLite database: add `--from-db /path/to/existing.sqlite`
- Specific accounts: add `--account <id>` (repeatable)

Read `/tmp/mailkb-profile.json` and capture:
- `accounts` and `inferred_identity` (`self_emails`, `internal_domains` inferred from Sent mailboxes)
- `top_external_domains` (separate true counterparties/customers/vendors from freemail domains to place in `organizations.exclude_domains`)
- `code_token_candidates` (frequent SKU, part, ticket, contract, or plan tokens vs false-positive noise like `ISO-9001` or `UTF-8` for `exclude_code_tokens`)
- `subject_topic_candidates` (recurring `[Tag]` prefixes, project codes, and noisy trailing suffixes for `topics.generic_suffix_patterns`)
- `table_headers_and_currencies` (`table_headers` and `currencies` for `amounts.currency_aliases` & `type_rules`)
- `attachment_stats` (common inline logo/banner prefixes for `identity.noise_attachment_prefixes`)
- `sample_subjects` (representative traffic to classify `intents` and `amounts.exclude_subject_patterns`)

### Phase 2: Learn Local Knowledge (Permission-Gated, Read-Only)

Ask the user whether they want to share any local reference folders (read-only) to raise precision beyond mailbox headers alone—for example:
- Product catalogs, datasheets, BOMs, or price lists (`.xlsx`, `.csv`, `.pdf`, `.md`)
- CRM/ERP account exports (canonical customer names, domains, partner tiers)
- Active project trackers, SOWs, contracts, or support runbooks

With explicit permission, inspect only the approved paths read-only to harvest:
- Authoritative SKU / part-number / plan-code prefixes and family/category mappings
- Canonical organization names, subsidiaries, domains, and known contact emails
- Official project / deal / engagement names and aliases
- Domain-specific standards, compliance frameworks, product tiers, or subsystems

### Phase 3: Enrich from Web Industry Knowledge

When the user's industry relies on standardized public taxonomies or part-numbering conventions, perform targeted web/reference research to broaden recall without overfitting to single emails:
- **Standards & compliance**: e.g., `IEC-61850`, `EN-50155`, `SOC 2`, `ISO 27001`, `HIPAA`, `FDA 21 CFR`, `AS9100`, `Incoterms 2020`.
- **Industry terminology & intents**: common RFQ, PO, SLA, RMA, renewal, subrogation, bill-of-lading, or milestone phrases.
- **Synonym & abbreviation expansion**: map acronyms and multilingual variants into `aliases`, `patterns`, and `currency_aliases` (e.g., `RMB` / `¥` -> `CNY`, `US$` -> `USD`).

Keep public enrichment conservative: every added regex must remain specific enough not to match generic conversational prose.

### Phase 4: Synthesize, Validate & Iterate

1. **Create private pack storage**:
   ```bash
   mkdir -p ~/.config/mailkb_db/packs
   chmod 700 ~/.config/mailkb_db ~/.config/mailkb_db/packs
   ```
2. **Write `~/.config/mailkb_db/packs/<domain>.json`** following `domain-pack.v1`:
   - Set `schema_version: "domain-pack.v1"` and a unique kebab-case `pack_id`.
   - Populate `identity`, `entity_rules`, `dimensions`, `organizations`, `topics`, `intents`, and `amounts`.
   - Enforce restrictive file permissions immediately:
     ```bash
     chmod 600 ~/.config/mailkb_db/packs/<domain>.json
     ```
3. **Validate schema, regex compilation, and hazard rules**:
   ```bash
   mailkb_db validate-pack ~/.config/mailkb_db/packs/<domain>.json --json
   ```
   Confirm `"valid": true` and resolve every error or warning:
   - Fix invalid syntax or unsupported lookarounds inside `series_regex` (see [pack-authoring-guide.md](references/pack-authoring-guide.md)).
   - Deduplicate dimension keys, organizations, and topics.
   - Tighten any pattern flagged with `broad_pattern_matched_benign_probe`.
4. **Dry-run against real corpus samples**:
   ```bash
   mailkb_db test-pack ~/.config/mailkb_db/packs/<domain>.json --sample 200 --json
   ```
   Inspect `entity_hit_rate`, `org_hit_rate`, `topic_hit_rate`, `amount_hit_rate`, `intent_counts`, `category_counts`, `dimension_counts`, `top_entities`, `top_orgs`, `top_topics`, and `unmatched_sample_subjects`.
   - If noisy tokens dominate `top_entities`, add `exclude_code_tokens` or `exclude_if_matches`, or tighten boundary assertions.
   - If key messages appear in `unmatched_sample_subjects`, add `code_patterns`, `category_fallbacks`, `organizations.entries`, `topics.entries`, or `intents`.
   - Repeat `validate-pack` + `test-pack` until precision and coverage are clean.
5. **Publish the full enriched SQLite index**:
   ```bash
   mailkb_db sync --full
   ```
   If testing a pack before enabling it globally, pass `--pack /path/to/candidate.json` (or `MAILKB_DB_PACK=/path/to/candidate.json`). To verify pure universal baseline behavior without any packs, pass `--no-packs`.

## Quick Checklist Before Handing Back to User

- [ ] Pack saved at `~/.config/mailkb_db/packs/<domain>.json` with mode `0600` (not committed to a public repo).
- [ ] `mailkb_db validate-pack ... --json` returns `"valid": true` with zero unexpected warnings.
- [ ] `mailkb_db test-pack ... --sample 200 --json` confirms clean `top_entities`, accurate `intent_counts`, and expected `dimension_counts`.
- [ ] `mailkb_db sync --full` completed cleanly and `mailkb_db stats --json` reflects the loaded `pack_id`.
