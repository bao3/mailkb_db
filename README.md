# `mailkb_db` — Universal Local Email Knowledge Base Engine

**`mailkb_db`** is a pure-Rust, security-hardened email indexing and semantic query engine for macOS Apple Mail (`V10`) and standalone `.eml`/`.emlx` archives. It builds a fast, single-file `DELETE`-mode SQLite knowledge base (`1.0-universal`) with CJK-bigram FTS5 full-text search, HTML/OOXML table amount extraction, and pluggable JSON **Domain Packs (`domain-pack.v1`)** so the compiled binary stays 100% domain-agnostic.

---

## Key Capabilities

- **Zero-Pack Universal Mode & Pluggable Domain Packs**: Works out-of-the-box with zero configuration by auto-discovering mail accounts, inferring `self_emails` / `internal_domains` from `Sent` mailboxes, parsing MIME/HTML/OOXML (`.xlsx`/`.xlsm`/`.docx`), and extracting generic code tokens, `[Bracket]` topics, non-freemail organizations, and monetary amounts. Drop one or more `domain-pack.v1` JSON files into `~/.config/mailkb_db/packs/` to unlock custom entity/SKU patterns, custom taxonomy dimensions, normalized customers/partners, priority intents, and commercial amount typing.
- **Multi-Account & Cross-Format Ingestion**: Auto-discovers `ews://`, `imap://`, `pop://`, and `local://` accounts inside Apple Mail `V10`, recursively scans standalone `--eml-dir` folders, and supports read-only migration from legacy `3.0-multidim` SQLite databases (`--import-legacy-db`).
- **`MailKBAI.app` Drop-In Compatibility**: Exposes both `1.0-universal` tables/views and exact `3.0-multidim` compatibility SQL views (`messages`, `message_prices`, `message_products`, `message_attachments_mime`, `v_sku_price_history`, `v_project_overview`, `v_customer_overview`).
- **AI-Native Pack Authoring & Query Skills**: Includes portable `SKILL.md` skills (`skills/mailkb-pack-builder` and `skills/mailkb-query`) usable in Antigravity, Claude Code, Codex, and Cursor to profile a real mailbox, generate a tailored Domain Pack, validate/test it in a closed loop, and query the resulting knowledge base.

---

## Workspace Architecture

| Crate | Role |
| --- | --- |
| [`crates/mailkb-core`](crates/mailkb-core) | Configuration & pack discovery (`config.rs`), `domain-pack.v1` schema/compiler/validator (`domain_pack.rs`), ReDoS-safe `MiniRegex` lookaround engine (`minire.rs`), S1-bounded OOXML reader (`ooxml.rs`), CJK-bigram FTS5 query/tokenizer (`fts.rs`), T2 hot runtime staging (`staging.rs`), T3 atomic publisher (`publish.rs`), and S4/S8/S9/S10/S11/S13/T4 security primitives (`security.rs`). |
| [`crates/mailkb-sync`](crates/mailkb-sync) | `1.0-universal` SQLite schema & compatibility views (`schema.rs`), MIME/`.emlx`/HTML 2D table parsers, Apple Mail `V10` & `.eml` discovery, zero-pack + Domain Pack enrichment, incremental/full `sync`, `profile-corpus`, and `test-pack`. |
| [`crates/mailkb-query`](crates/mailkb-query) | Staged immutable read-only query engine (`?mode=ro&immutable=1`) powering `search`, `read`, `entities`, `amounts`, `topics`, `orgs`, `timeline`, `att`, `stats`, `audit`, and `selftest`. |
| [`crates/mailkb-cli`](crates/mailkb-cli) | `mailkb_db` CLI (`clap` v4) with structured `--json` output, terminal-safe human rendering, and deterministic exit codes (`0`, `2`, `3`, `4`). |

---

## Zero-Pack Mode vs. Domain Pack Mode

| Aspect | Zero-Pack Mode (`--no-packs` / empty pack dir) | Domain Pack Mode (`~/.config/mailkb_db/packs/*.json`) |
| --- | --- | --- |
| **Identity & Direction** | Auto-infers `self_emails` and non-freemail `internal_domains` from `Sent` / `已发送` / `Sent Messages` / `Sent Items` mailboxes | Merges explicit `self_emails`, `internal_domains`, automated `system_senders`/`system_domains`, and `noise_attachment_prefixes` |
| **Entities & Categories** | Extracts generic uppercase alphanumeric hyphenated codes into `General` | Priority-ranked `code_patterns` with `category`, `sub_group` (`$1` or `series_regex`), `exclude_code_tokens`, `category_fallbacks` |
| **Custom Dimensions** | Empty (`{}`) | Arbitrary custom dimensions (`standards`, `subsystems`, `compliance`, `deployment_tier`, etc.) indexed in `custom_dims_json`, `message_entities`, and `domain_lexicon`, queryable via `--dim key=value` |
| **Organizations & Topics** | Generic email-domain/display-name inference + subject `[Bracket]` extraction | Deterministic `domain_to_org` / `email_to_org`, alias/body regexes, `generic_suffix_patterns`, canonical projects |
| **Intents & Amounts** | Generic monetary/table extraction with ISO currency detection | Priority `intents` + `amount_type_rules` (`order_price`, `quote`, `contract_acv`, etc.), `exclude_subject_patterns`, `currency_aliases` |

### Domain Pack Resources

- JSON Schema (Draft 2020-12): [`schemas/domain-pack.v1.schema.json`](schemas/domain-pack.v1.schema.json)
- Fictional Example Packs (100% synthetic companies & SKUs):
  - [`packs/examples/b2b-hardware.sample.json`](packs/examples/b2b-hardware.sample.json) — Industrial networking switches/gateways, `standards` (`IEC-61850-3`, `EN-50155`), `subsystems` (`SCADA`, `CCTV_Backbone`), quotes & POs.
  - [`packs/examples/saas-commercial.sample.json`](packs/examples/saas-commercial.sample.json) — SaaS subscription plans, `compliance` (`SOC2_Type_II`, `ISO_27001`, `GDPR_DPA`), `deployment_tier`, renewals & ACV.
- AI Skills:
  - [`skills/mailkb-pack-builder/SKILL.md`](skills/mailkb-pack-builder/SKILL.md) & [`pack-authoring-guide.md`](skills/mailkb-pack-builder/references/pack-authoring-guide.md) — 4-phase closed-loop workflow (`profile-corpus` -> local reference inspection -> industry enrichment -> `validate-pack` + `test-pack` + `sync`).
  - [`skills/mailkb-query/SKILL.md`](skills/mailkb-query/SKILL.md) — Practical agent guide for searching and auditing indexed mail.

---

## `1.0-universal` Schema & `MailKBAI.app` Compatibility Views

### Core Universal Tables & FTS5 Indexes

- `kb_meta (key, value)` — `schema_version` (`1.0-universal`), `rules_fingerprint`, `pack_ids`, sync watermarks, and corpus counters.
- `mail_messages` — Normalized email headers, `direction`, `intent_type`, `summary_line`, `body_latest`, `body_quoted`, `primary_entities`, `primary_category`, `topic_tags`, `org_tags`, `has_amount`, `amount_summary`, `event_dates_json`, `custom_dims_json`.
- `message_entities` — Extracted `item_code` tokens and custom dimension hits (`entity_type`, `entity_key`, `canonical_value`, `category`, `sub_group`, `quantity`, `unit`, `role`, `confidence`, `snippet`, `attrs_json`).
- `message_amounts` — Inline, HTML table, and `.xlsx` monetary amounts (`amount_type`, `subject_entity`, `currency`, `unit_amount`, `total_amount`, `quantity`, `tax_mode`, `terms_json`, `effective_date_iso`, `valid_until`, `source_kind`, `evidence_snippet`).
- `message_attachments` — Attachment metadata, S10-safe `storage_relpath`, `is_inline`, `is_noise`, `sha256`, `text_preview`.
- `domain_lexicon` — Seeded pack lexicon entries and live `hit_count` statistics.
- FTS5 (`tokenize='unicode61'`): `messages_fts`, `dimensions_fts`, `attachments_fts` (pre-tokenized with CJK unigrams/bigrams and hyphen-joined ASCII tokens).

### Views

- **Universal Views**: `v_amount_history`, `v_topic_overview`, `v_org_overview`, `v_timeline_monthly`.
- **`MailKBAI.app` Compatibility Views**: `messages`, `message_prices`, `message_products`, `message_attachments_mime`, `v_sku_price_history`, `v_project_overview`, `v_customer_overview`.

---

## Safety Architecture

- **S1 (Bounded OOXML/ZIP)**: Pure-Rust `.xlsx`/`.xlsm`/`.docx` reader capped at 16 MiB file size, 8 MiB per entry, 1024 ZIP entries, and `8 sheets x 250 rows` (`4000` chars) for mail previews.
- **S4 (Nofollow Read-Only)**: Source reads open via `O_RDONLY | O_NOFOLLOW | O_CLOEXEC` verified as regular files (`S_ISREG`).
- **S8 / T3 (Private Staging & Atomic Publish)**: Builds in `0700` `mkdtemp` directories (auto-reaping >24h stale dirs), snapshots clean `DELETE`-mode SQLite without `-wal`/`-shm` sidecars, verifies `PRAGMA quick_check`, writes `<db>.sha256`, and atomically swaps cold and hot copies.
- **S9 (Mail Container Guard)**: Hard-blocks any write, staging, or build path inside `~/Library/Mail`, `~/Library/Group Containers/UBF8T346G9.Office`, or `~/Library/Thunderbird` (`exit_code = 2`).
- **S10 / S11 (Path & Terminal Hygiene)**: Rejects path traversal / absolute / Windows-drive `storage_relpath` values (`safe_relpath`/`remap_relpath`) and strips ANSI/control characters from human output (`term_safe`).
- **S12 (Bounded Search & Regex)**: Enforces FTS5 token/clause caps (`MAX_FTS_KEYWORDS = 32`, `MAX_FTS_EXPR_BYTES = 4096`) and routes lookaround pack regexes to linear/bounded `MiniRegex`.
- **T2 / T4 (Hot Runtime Cache & Locking)**: `flock` advisory locking prevents concurrent write races; readers always copy/verify into `~/.cache/mailkb_db/mailkb_db.sqlite` (`0700` dir) and open with `?mode=ro&immutable=1`.

---

## Default Paths & Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `MAILKB_DB_DIR` | `~/.local/share/mailkb_db` | Cold published database directory |
| `MAILKB_DB_PATH` | `~/.local/share/mailkb_db/mailkb_db.sqlite` | Cold SQLite database file path |
| `MAILKB_DB_RUNTIME_DIR` | `~/.cache/mailkb_db` | Private `0700` hot staged read-only cache directory |
| `MAILKB_DB_PACKS_DIR` | `~/.config/mailkb_db/packs` | Auto-discovered `*.json` Domain Pack directory |
| `MAILKB_DB_PACK` | *(unset)* | Explicit colon/comma-separated Domain Pack paths |
| `MAILKB_DB_NO_PACKS` | `0` | Set `1`/`true` to run in pure universal mode |
| `MAILKB_DB_ACCOUNTS` | *(unset)* | Optional comma-separated account filters |
| `MAILKB_DB_EML_DIR` | *(unset)* | Colon/comma-separated standalone `.eml`/`.emlx` dirs |
| `MAILKB_DB_THREADS` | auto (`1..=12`) | Worker thread cap (explicit `1..=64`) |
| `APPLE_MAIL_V10_DIR` | `~/Library/Mail/V10` | Override Apple Mail `V10` root (macOS) |

---

## Quickstart (English)

```bash
# 1. Build release binary
cargo build --release --workspace
# Binary: ./target/release/mailkb_db

# 2. Self-check & validate sample Domain Packs
./target/release/mailkb_db selftest --json
./target/release/mailkb_db validate-pack packs/examples/b2b-hardware.sample.json --json

# 3. Profile your mailbox (read-only) to inspect accounts, domains, SKUs, and currencies
./target/release/mailkb_db profile-corpus --limit 2000 --json --out /tmp/mailkb-profile.json

# 4. Sync in zero-pack universal mode (or after creating ~/.config/mailkb_db/packs/<domain>.json)
./target/release/mailkb_db sync --full

# 5. Query messages, prices, entities, and custom dimensions
./target/release/mailkb_db stats --json
./target/release/mailkb_db search "quotation" --has-amount --limit 20 --json
./target/release/mailkb_db amounts --currency USD --limit 20 --json
./target/release/mailkb_db read 1 --full --json
```

---

## 中文快速上手 (Chinese Quickstart)

`mailkb_db` 是**完全领域无关（100% domain-agnostic）**的本地邮件知识库与 SQLite/FTS5 索引引擎：二进制程序本身不包含任何特定公司、型号或个人隐私硬编码。所有行业规则都通过外部声明式 JSON **Domain Pack（领域包，`domain-pack.v1`）** 注入。

### 1. 编译与自检

```bash
cargo build --release --workspace
./target/release/mailkb_db selftest --json
./target/release/mailkb_db validate-pack packs/examples/b2b-hardware.sample.json --json
```

### 2. 零配置通用模式同步（Zero-Pack Mode）

即使不配置任何 Domain Pack，也可直接索引 Apple Mail（`V10` 多账户自动发现）或独立 `.eml`/`.emlx` 目录：

```bash
# 全量同步（默认写入 ~/.local/share/mailkb_db/mailkb_db.sqlite，并同步更新 ~/.cache/mailkb_db/ 热点只读缓存）
./target/release/mailkb_db sync --full

# 仅索引指定 .eml/.emlx 归档目录
./target/release/mailkb_db sync --full --eml-dir /path/to/eml_archive
```

### 3. 常用查询命令

```bash
# 查看统计与已加载领域包
./target/release/mailkb_db stats --json

# 全文 + 多维过滤搜索（内置中文 bigram 分词）
./target/release/mailkb_db search "报价" --has-amount --limit 20 --json

# 按行业自定义维度过滤（需加载对应 Domain Pack）
./target/release/mailkb_db search --dim standards=EN-50155 --org "MetroLine" --json

# 查询历史报价/金额、产品/实体汇总、项目/客户总览、附件
./target/release/mailkb_db amounts --currency CNY --limit 20 --json
./target/release/mailkb_db entities --limit 30 --json
./target/release/mailkb_db topics --json
./target/release/mailkb_db orgs --json
./target/release/mailkb_db att "报价单" --ext xlsx --json

# 读取单封完整邮件及提取的实体/金额/附件
./target/release/mailkb_db read 1 --full --json
```

### 4. 使用 `mailkb-pack-builder` 技能为你的行业生成专属 Domain Pack

仓库内置的 [`skills/mailkb-pack-builder/SKILL.md`](skills/mailkb-pack-builder/SKILL.md) 遵循标准 `SKILL.md` 规范，可直接用于 Antigravity、Claude Code、Codex 或 Cursor，按 4 阶段闭环生成私人领域包 `~/.config/mailkb_db/packs/<domain>.json`（权限 `0600`，不进入公共代码库）：

1. **阶段 1（只读画像）**：运行 `mailkb_db profile-corpus --limit 2000 --json --out /tmp/mailkb-profile.json`，自动提取账户、发件身份（`self_emails`/`internal_domains`）、外部往来域名、候选 SKU/编码、`[标签]` 主题与表格币种。
2. **阶段 2（授权只读参考资料）**：在用户授权下只读参考本地报价单、Excel BOM、产品手册或 CRM 导出，补全标准命名与客户别名。
3. **阶段 3（公开行业知识增强）**：结合行业公开标准与术语扩展 `dimensions`、`intents` 与多语言同义词。
4. **阶段 4（生成、校验与闭环测试）**：写入 `~/.config/mailkb_db/packs/<domain>.json`（`chmod 600`），依次运行：
   ```bash
   mailkb_db validate-pack ~/.config/mailkb_db/packs/<domain>.json --json
   mailkb_db test-pack ~/.config/mailkb_db/packs/<domain>.json --sample 200 --json
   mailkb_db sync --full
   ```

> **安全边界提示**：`mailkb_db` 严格禁止对 `~/Library/Mail`、Outlook Profile 或 Thunderbird 容器执行任何写入或就地构建（触发 S9 保护并返回退出码 `2`）；所有查询统一通过 `~/.cache/mailkb_db/mailkb_db.sqlite`（`?mode=ro&immutable=1`）只读快照执行，并保留完整的 `MailKBAI.app` 兼容 SQL 视图。

---

## License

MIT License — see [LICENSE](LICENSE).
