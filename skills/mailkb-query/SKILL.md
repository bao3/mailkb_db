---
name: mailkb-query
description: Query, search, and audit the mailkb_db SQLite email knowledge base safely using staged read-only access (search, read, amounts, entities, topics, orgs, timeline, att, stats, audit, selftest) and understand its 1.0-universal schema and MailKBAI.app compatibility views. Use whenever an AI agent needs to find emails, prices/quotes, SKUs/entities, organizations, topics, attachments, or timeline metrics from mailkb_db.
---

# mailkb_db Query Guide

Safely search and analyze emails, commercial prices/quotes, SKU/entity codes, custom taxonomy dimensions, organizations, topics, and attachments indexed in `mailkb_db`.

## Core Safety Rules

1. **Always query via `mailkb_db` (or the staged immutable runtime DB)**: Never open `~/.local/share/mailkb_db/mailkb_db.sqlite` directly with read-write SQLite tools. `mailkb_db` stages snapshots into `~/.cache/mailkb_db/mailkb_db.sqlite` and opens them with `?mode=ro&immutable=1`.
2. **Never write inside mail containers**: `mailkb_db` refuses operations targeting `~/Library/Mail`, `~/Library/Group Containers/UBF8T346G9.Office`, or `~/Library/Thunderbird` (`exit_code = 2`).
3. **Prefer `--json` for agent workflows**: Pass `--json` to receive structured output with `source_db`, `runtime_db`, `staging`, `warnings`, `elapsed_ms`, plus command-specific payload fields (`results`, `message`/`entities`/`amounts`/`attachments`, `overview`, `counts`, etc.).

## Global Options

Place global options before or after the subcommand as supported by CLI:

- `--db <PATH>`: Override cold database path (default `~/.local/share/mailkb_db/mailkb_db.sqlite` or `$MAILKB_DB_PATH`).
- `--db-dir <DIR>`: Override cold database directory (`$MAILKB_DB_DIR`).
- `--runtime-dir <DIR>`: Override hot staging directory (default `~/.cache/mailkb_db` or `$MAILKB_DB_RUNTIME_DIR`).
- `--pack <PATH>` (repeatable): Override auto-discovered packs from `~/.config/mailkb_db/packs`.
- `--no-packs`: Ignore all Domain Packs (universal baseline mode).
- `--account <ID>` (repeatable): Scope sync/profile operations to specific accounts.
- `--eml-dir <DIR>` (repeatable): Include standalone `.eml`/`.emlx` directories.
- `--json`: Output machine-readable JSON.
- `--quiet`: Suppress non-essential output.

## Query Subcommands & Examples

### 1. Multi-Dimensional Search (`search`, alias `md-search`)

Combines CJK-bigram + ASCII FTS5 search (`dimensions_fts` and `messages_fts`) with structured metadata filters:

```bash
# Keyword search (both FTS indexes)
mailkb_db search "ACME-SW-2400" "quotation" --json

# OR / AND boolean terms inside keywords
mailkb_db search "ACME-SW-2400 OR ACME-GW-300" --limit 20 --json

# Structured commercial & custom-dimension filtering
mailkb_db search \
  --org "GridWorks" \
  --category "Switch" \
  --intent "rfq_quote" \
  --dim standards=IEC-61850-3 \
  --has-amount \
  --since 2026-01-01 \
  --json
```

Useful filters:
- `--account <ID>`, `--source <SRC>`, `--direction <DIR>`, `--completeness <MODE>`
- `--entity <KEY>` (alias `--sku`), `--category <CAT>` (alias `--family`)
- `--topic <NAME>` (alias `--project`), `--org <NAME>` (alias `--customer`)
- `--intent <INTENT>`, `--sender <PATTERN>`, `--since <YYYY-MM-DD>`, `--until <YYYY-MM-DD>`
- `--has-amount` (alias `--has-price`)
- `--dim <KEY>=<VAL>` (repeatable; `KEY` matches `[A-Za-z0-9_-]{1,64}`; matches custom Domain Pack dimensions in `message_entities` or `custom_dims_json`)
- `--mode both|dim|msg` (`dim` searches `dimensions_fts`, `msg` searches `messages_fts`, `both` combines both)
- `--limit <N>` (`1..=500`, default `30`), `--auto-sync`

### 2. Read Full Message & Extracted Records (`read`, alias `md-read`)

Fetch a single message by integer `id`, `uid_key`, or `rfc_message_id` along with its extracted `entities`, `amounts`, and `attachments` (with S10-remapped local paths where available; response contains `message`, `entities`, `amounts`, `attachments`):

```bash
mailkb_db read 42 --json
mailkb_db read 42 --full --json
mailkb_db read "<msg-id@acme-industrial.example>" --full --json
```

### 3. Commercial Amounts & Pricing History (`amounts`, alias `price`)

Query monetary quotes, purchase orders, invoices, renewals, and Excel/HTML table prices (returns `count`, `currency_summary`, `results`):

```bash
mailkb_db amounts --entity "ACME-SW-2400" --currency USD --json
mailkb_db amounts "annual" --org "Cascade" --type contract_acv --since 2026-01-01 --json
```

Filters: positional keywords, `--entity` (`--sku`), `--currency`, `--topic` (`--project`), `--org` (`--customer`), `--type` (`--price-type`), `--confidence`, `--since`, `--until`, `--limit` (`1..=500`). Surfaces `unit_amount`, `total_amount`, `quantity`, `tax_mode`, `valid_until`, `evidence_snippet`, and parsed `terms_json` (`moq`, `lead_time`, `discount_info`).

### 4. Entities & Custom Dimension Rollups (`entities`, alias `sku`)

Aggregate extracted SKU/entity codes and custom dimension hits by `(entity_key, entity_type, category, sub_group)` (drill down with either positional `<ENTITY>` or `--entity`/`--sku`, not both):

```bash
mailkb_db entities --category Switch --limit 50 --json
mailkb_db entities --type standard --json
mailkb_db entities "NS-ENT-100" --json
```

When drilling down into a specific entity, `--json` includes `query_entity`, `results`, `entity_mentions`, `amount_history`, and `messages`.

### 5. Topics & Organizations (`topics` / `project`, `orgs` / `customer`)

Inspect active projects/deals (`v_topic_overview`) and counterparties (`v_org_overview`). Drill down using either a positional argument or `--topic`/`--project` (`--org`/`--customer`), not both:

```bash
mailkb_db topics --limit 30 --json
mailkb_db topics "Northbay" --json
mailkb_db orgs --org "GridWorks" --json
```

List mode returns `results` + `lexicon`; drill-down returns `overview`, `amounts`, `messages`, `lexicon`, and `results`.

### 6. Activity Timeline (`timeline`)

Aggregate inbound, outbound, amount-bearing, and total message volume over time (`--granularity month|day|quarter|year`):

```bash
mailkb_db timeline --granularity month --since 2026-01-01 --json
mailkb_db timeline --granularity day --topic "Harbor Rail" --limit 60 --json
mailkb_db timeline --granularity quarter --org "GridWorks" --json
```

### 7. Attachment Search (`att`)

Search `message_attachments` via `attachments_fts` and metadata filters (signature noise `is_noise = 1` is excluded by default unless `--include-noise` is passed):

```bash
mailkb_db att "BOM" --ext xlsx --json
mailkb_db att --entity "ACME-SW-2400" --topic "Northbay" --json
mailkb_db att --include-noise --limit 20 --json
```

### 8. Diagnostics (`stats` / `md-stats`, `audit` / `mail-audit`, `selftest`)

```bash
# Corpus counts, loaded pack_ids, account/source/category/intent breakdowns
mailkb_db stats --json

# Security & staging verification (S9 guards, sidecar SHA-256, Apple Mail readiness)
mailkb_db audit --json

# Built-in 1.0-universal + FTS5 + MiniRegex self-check suite (optionally validate a sample pack)
mailkb_db selftest --pack-sample packs/examples/b2b-hardware.sample.json --json
```

## Recommended Agent Investigation Loop

1. **Discover scope**: Run `mailkb_db stats --json` (or `topics` / `orgs`) to learn loaded packs, active accounts, and naming conventions.
2. **Search narrowly**: Run `mailkb_db search ... --json` with `--org`, `--entity`, `--dim`, or `--since` filters.
3. **Cross-check prices/terms**: Run `mailkb_db amounts ... --json` when comparing historical quotes, MOQs, lead times, or renewal ACVs.
4. **Verify primary evidence**: Run `mailkb_db read <id> --full --json` before citing exact terms, dates, or email commitments.

## `1.0-universal` Schema & `MailKBAI.app` Compatibility Views

For Swift/GUI consumers (`MailKBAI.app`) or read-only SQL analytics against `~/.cache/mailkb_db/mailkb_db.sqlite?mode=ro&immutable=1`:

| Layer | Objects | Purpose |
| --- | --- | --- |
| **Core Tables** | `kb_meta`, `mail_messages`, `message_entities`, `message_amounts`, `message_attachments`, `domain_lexicon` | Domain-agnostic universal mail & enrichment store |
| **FTS5 Indexes** | `messages_fts`, `dimensions_fts`, `attachments_fts` | Pre-tokenized CJK unigram/bigram + ASCII `unicode61` search |
| **Universal Views** | `v_amount_history`, `v_topic_overview`, `v_org_overview`, `v_timeline_monthly` | Normalized analytics over universal column names |
| **`MailKBAI.app` Views** | `messages`, `message_prices`, `message_products`, `message_attachments_mime`, `v_sku_price_history`, `v_project_overview`, `v_customer_overview` | Drop-in SQL compatibility (`sku_guess`, `product_family`, `project_name`, `customers_orgs`, `main_meaning`, `has_price`, `unit_price`, `price_type`, `moq`, `lead_time`, `discount_info`, `quote_date_iso`) |

## Process Exit Codes

- `0`: Success
- `2`: Security, validation, or invalid argument error (e.g., S9 mail container violation, invalid Domain Pack, unsafe output path)
- `3`: Exclusive sync lock busy (`LockBusy`)
- `4`: Runtime, I/O, SQLite, staging, or publish error
