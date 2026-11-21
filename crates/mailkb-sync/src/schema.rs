//! Universal `1.0-universal` SQLite schema DDL with FTS5 full-text indexes,
//! universal analytics views, and `MailKBAI.app` (`3.0-multidim`) compatibility views.

use mailkb_core::KbResult;
use rusqlite::Connection;

pub const SCHEMA_VERSION: &str = "1.0-universal";
pub const RULES_VERSION: &str = "1.0";
pub const ENGINE_VERSION: &str = "1.0.0-universal";

pub const UNIVERSAL_SCHEMA_SQL: &str = r#"
CREATE TABLE kb_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE mail_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid_key TEXT NOT NULL DEFAULT '',
    account_id TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    source_ref TEXT NOT NULL,
    rfc_message_id TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL,
    thread_topic TEXT NOT NULL DEFAULT '',
    sender TEXT NOT NULL DEFAULT '',
    recipients TEXT NOT NULL DEFAULT '',
    cc TEXT NOT NULL DEFAULT '',
    date_iso TEXT NOT NULL DEFAULT '',
    folder_path TEXT NOT NULL DEFAULT '',
    completeness TEXT NOT NULL DEFAULT 'full_body',
    direction TEXT NOT NULL DEFAULT '',
    intent_type TEXT NOT NULL DEFAULT '',
    summary_line TEXT NOT NULL DEFAULT '',
    body_latest TEXT NOT NULL,
    body_quoted TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL UNIQUE,
    primary_entities TEXT NOT NULL DEFAULT '',
    primary_category TEXT NOT NULL DEFAULT 'General',
    topic_tags TEXT NOT NULL DEFAULT '',
    org_tags TEXT NOT NULL DEFAULT '',
    has_amount INTEGER NOT NULL DEFAULT 0,
    amount_summary TEXT NOT NULL DEFAULT '',
    event_dates_json TEXT NOT NULL DEFAULT '{}',
    custom_dims_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_mmsg_date ON mail_messages(date_iso DESC);
CREATE INDEX idx_mmsg_account ON mail_messages(account_id);
CREATE INDEX idx_mmsg_source ON mail_messages(source);
CREATE INDEX idx_mmsg_cat ON mail_messages(primary_category);
CREATE INDEX idx_mmsg_entities ON mail_messages(primary_entities);
CREATE INDEX idx_mmsg_topics ON mail_messages(topic_tags);
CREATE INDEX idx_mmsg_intent ON mail_messages(intent_type);
CREATE INDEX idx_mmsg_has_amount ON mail_messages(has_amount);
CREATE INDEX idx_mmsg_uid ON mail_messages(uid_key);
CREATE INDEX idx_mmsg_direction ON mail_messages(direction);
CREATE INDEX idx_mmsg_completeness ON mail_messages(completeness);
CREATE INDEX idx_mmsg_orgs ON mail_messages(org_tags);
CREATE INDEX idx_mmsg_rfc_id ON mail_messages(LOWER(TRIM(rfc_message_id, '<> ')));

CREATE TABLE message_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL REFERENCES mail_messages(id),
    uid_key TEXT NOT NULL DEFAULT '',
    entity_type TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    canonical_value TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'General',
    sub_group TEXT NOT NULL DEFAULT '',
    quantity REAL,
    unit TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'medium',
    snippet TEXT NOT NULL DEFAULT '',
    attrs_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_ment_msg ON message_entities(message_id);
CREATE INDEX idx_ment_uid ON message_entities(uid_key);
CREATE INDEX idx_ment_type ON message_entities(entity_type);
CREATE INDEX idx_ment_key ON message_entities(entity_key);
CREATE INDEX idx_ment_cat ON message_entities(category);
CREATE INDEX idx_ment_sub ON message_entities(sub_group);
CREATE INDEX idx_ment_type_key ON message_entities(entity_type, entity_key);

CREATE TABLE message_amounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL REFERENCES mail_messages(id),
    uid_key TEXT NOT NULL DEFAULT '',
    amount_type TEXT NOT NULL DEFAULT '',
    subject_entity TEXT NOT NULL DEFAULT '',
    category TEXT NOT NULL DEFAULT 'General',
    topic_name TEXT NOT NULL DEFAULT '',
    org_name TEXT NOT NULL DEFAULT '',
    currency TEXT NOT NULL DEFAULT '',
    unit_amount REAL,
    total_amount REAL,
    quantity REAL,
    tax_mode TEXT NOT NULL DEFAULT '',
    terms_json TEXT NOT NULL DEFAULT '{}',
    effective_date_iso TEXT NOT NULL DEFAULT '',
    valid_until TEXT NOT NULL DEFAULT '',
    source_kind TEXT NOT NULL DEFAULT '',
    evidence_snippet TEXT NOT NULL DEFAULT '',
    confidence TEXT NOT NULL DEFAULT 'medium'
);

CREATE INDEX idx_mamt_msg ON message_amounts(message_id);
CREATE INDEX idx_mamt_uid ON message_amounts(uid_key);
CREATE INDEX idx_mamt_entity ON message_amounts(subject_entity);
CREATE INDEX idx_mamt_type ON message_amounts(amount_type);
CREATE INDEX idx_mamt_curr ON message_amounts(currency);
CREATE INDEX idx_mamt_topic ON message_amounts(topic_name);
CREATE INDEX idx_mamt_org ON message_amounts(org_name);
CREATE INDEX idx_mamt_date ON message_amounts(effective_date_iso DESC);
CREATE INDEX idx_mamt_conf ON message_amounts(confidence);

CREATE TABLE message_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL REFERENCES mail_messages(id),
    uid_key TEXT NOT NULL DEFAULT '',
    filename TEXT NOT NULL DEFAULT '',
    clean_filename TEXT NOT NULL DEFAULT '',
    ext TEXT NOT NULL DEFAULT '',
    mime_type TEXT NOT NULL DEFAULT '',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    mtime INTEGER NOT NULL DEFAULT 0,
    mtime_iso TEXT NOT NULL DEFAULT '',
    storage_relpath TEXT NOT NULL DEFAULT '',
    is_inline INTEGER NOT NULL DEFAULT 0,
    is_noise INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL DEFAULT '',
    text_preview TEXT NOT NULL DEFAULT '',
    entity_tags TEXT NOT NULL DEFAULT '',
    topic_tags TEXT NOT NULL DEFAULT ''
);

CREATE INDEX idx_matt_msg ON message_attachments(message_id);
CREATE INDEX idx_matt_uid ON message_attachments(uid_key);
CREATE INDEX idx_matt_ext ON message_attachments(ext);
CREATE INDEX idx_matt_noise ON message_attachments(is_noise);
CREATE INDEX idx_matt_sha ON message_attachments(sha256);
CREATE INDEX idx_matt_relpath ON message_attachments(storage_relpath);

CREATE TABLE domain_lexicon (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pack_id TEXT NOT NULL DEFAULT '',
    dimension TEXT NOT NULL,
    key TEXT NOT NULL,
    canonical_name TEXT NOT NULL DEFAULT '',
    aliases TEXT NOT NULL DEFAULT '',
    hit_count INTEGER NOT NULL DEFAULT 0,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_dlex_pack ON domain_lexicon(pack_id);
CREATE INDEX idx_dlex_dim ON domain_lexicon(dimension);
CREATE INDEX idx_dlex_key ON domain_lexicon(key);
CREATE UNIQUE INDEX idx_dlex_pack_dim_key ON domain_lexicon(pack_id, dimension, key);

CREATE VIRTUAL TABLE messages_fts USING fts5(
    subject_tok,
    sender_tok,
    meta_tok,
    body_latest_tok,
    body_quoted_tok,
    tokenize='unicode61'
);

CREATE VIRTUAL TABLE dimensions_fts USING fts5(
    title_tok,
    meaning_tok,
    intent_tok,
    entities_tok,
    orgs_tok,
    topics_tok,
    amounts_tok,
    tokenize='unicode61'
);

CREATE VIRTUAL TABLE attachments_fts USING fts5(
    filename_tok,
    meta_tok,
    tokenize='unicode61'
);

-- Universal Views

CREATE VIEW v_amount_history AS
SELECT
    a.id,
    a.message_id,
    a.uid_key,
    a.amount_type,
    a.subject_entity,
    a.category,
    COALESCE(NULLIF(a.topic_name, ''), m.topic_tags) AS topic_name,
    COALESCE(NULLIF(a.org_name, ''), m.org_tags) AS org_name,
    a.currency,
    a.unit_amount,
    a.total_amount,
    a.quantity,
    a.tax_mode,
    a.terms_json,
    COALESCE(json_extract(a.terms_json, '$.moq'), '') AS moq,
    COALESCE(json_extract(a.terms_json, '$.lead_time'), '') AS lead_time,
    COALESCE(json_extract(a.terms_json, '$.discount_info'), '') AS discount_info,
    COALESCE(NULLIF(a.effective_date_iso, ''), m.date_iso) AS effective_date_iso,
    a.valid_until,
    a.source_kind,
    a.evidence_snippet,
    a.confidence,
    m.subject,
    m.sender,
    m.account_id,
    m.rfc_message_id
FROM message_amounts a
JOIN mail_messages m ON m.id = a.message_id
ORDER BY COALESCE(NULLIF(a.effective_date_iso, ''), m.date_iso) DESC, a.id DESC;

CREATE VIEW v_topic_overview AS
WITH RECURSIVE split_topic(msg_id, date_iso, has_amount, completeness, org_tags, primary_category, intent_type, item, rest) AS (
    SELECT id, date_iso, has_amount, completeness, org_tags, primary_category, intent_type, '', topic_tags || ','
    FROM mail_messages WHERE topic_tags != ''
    UNION ALL
    SELECT msg_id, date_iso, has_amount, completeness, org_tags, primary_category, intent_type,
           TRIM(SUBSTR(rest, 1, INSTR(rest, ',') - 1)), SUBSTR(rest, INSTR(rest, ',') + 1)
    FROM split_topic WHERE rest != ''
)
SELECT
    item AS topic_name,
    COUNT(DISTINCT msg_id) AS message_count,
    SUM(CASE WHEN completeness = 'full_body' THEN 1 ELSE 0 END) AS full_body_count,
    SUM(CASE WHEN has_amount = 1 THEN 1 ELSE 0 END) AS amount_message_count,
    MIN(NULLIF(date_iso, '')) AS first_date_iso,
    MAX(NULLIF(date_iso, '')) AS last_date_iso,
    GROUP_CONCAT(DISTINCT NULLIF(primary_category, 'General')) AS categories,
    GROUP_CONCAT(DISTINCT NULLIF(org_tags, '')) AS org_tags,
    GROUP_CONCAT(DISTINCT NULLIF(intent_type, '')) AS intent_types
FROM split_topic WHERE item != '' GROUP BY item ORDER BY message_count DESC, last_date_iso DESC;

CREATE VIEW v_org_overview AS
WITH RECURSIVE split_org(msg_id, date_iso, has_amount, completeness, topic_tags, primary_category, intent_type, item, rest) AS (
    SELECT id, date_iso, has_amount, completeness, topic_tags, primary_category, intent_type, '', org_tags || ','
    FROM mail_messages WHERE org_tags != ''
    UNION ALL
    SELECT msg_id, date_iso, has_amount, completeness, topic_tags, primary_category, intent_type,
           TRIM(SUBSTR(rest, 1, INSTR(rest, ',') - 1)), SUBSTR(rest, INSTR(rest, ',') + 1)
    FROM split_org WHERE rest != ''
)
SELECT
    item AS org_name,
    COUNT(DISTINCT msg_id) AS message_count,
    SUM(CASE WHEN completeness = 'full_body' THEN 1 ELSE 0 END) AS full_body_count,
    SUM(CASE WHEN has_amount = 1 THEN 1 ELSE 0 END) AS amount_message_count,
    MIN(NULLIF(date_iso, '')) AS first_date_iso,
    MAX(NULLIF(date_iso, '')) AS last_date_iso,
    GROUP_CONCAT(DISTINCT NULLIF(topic_tags, '')) AS topics,
    GROUP_CONCAT(DISTINCT NULLIF(primary_category, 'General')) AS categories
FROM split_org WHERE item != '' GROUP BY item ORDER BY message_count DESC, last_date_iso DESC;

CREATE VIEW v_timeline_monthly AS
SELECT
    SUBSTR(date_iso, 1, 7) AS ym,
    COUNT(*) AS message_count,
    SUM(CASE WHEN completeness = 'full_body' THEN 1 ELSE 0 END) AS full_body_count,
    SUM(CASE WHEN has_amount = 1 THEN 1 ELSE 0 END) AS amount_message_count,
    SUM(CASE WHEN has_amount = 1 THEN 1 ELSE 0 END) AS price_message_count,
    SUM(CASE WHEN direction = 'external_inbound' THEN 1 ELSE 0 END) AS inbound_count,
    SUM(CASE WHEN direction = 'external_outbound' THEN 1 ELSE 0 END) AS outbound_count,
    COUNT(DISTINCT NULLIF(topic_tags, '')) AS active_topics
FROM mail_messages WHERE LENGTH(date_iso) >= 7 AND SUBSTR(date_iso, 5, 1) = '-' GROUP BY ym ORDER BY ym DESC;

-- Compatibility SQL VIEWs for MailKBAI.app (HistoricalPriceLookupService.swift)

CREATE VIEW messages AS
SELECT
    id,
    source,
    source_ref,
    uid_key,
    account_id,
    rfc_message_id AS message_id,
    subject,
    thread_topic,
    sender,
    recipients,
    cc,
    date_iso,
    folder_path,
    completeness,
    direction,
    intent_type,
    body_latest,
    body_quoted,
    content_hash,
    primary_entities AS sku_guess,
    primary_category AS product_family,
    topic_tags AS project_name,
    org_tags AS customers_orgs,
    summary_line AS main_meaning,
    has_amount AS has_price,
    amount_summary AS price_summary,
    event_dates_json,
    custom_dims_json
FROM mail_messages;

CREATE VIEW message_prices AS
SELECT
    id,
    message_id,
    uid_key,
    subject_entity AS sku,
    category AS product_family,
    topic_name AS project_name,
    org_name AS customer_org,
    currency,
    unit_amount AS unit_price,
    total_amount,
    quantity,
    amount_type AS price_type,
    tax_mode,
    COALESCE(json_extract(terms_json, '$.moq'), '') AS moq,
    COALESCE(json_extract(terms_json, '$.lead_time'), '') AS lead_time,
    COALESCE(json_extract(terms_json, '$.discount_info'), '') AS discount_info,
    valid_until,
    effective_date_iso AS quote_date_iso,
    source_kind,
    evidence_snippet,
    confidence
FROM message_amounts;

CREATE VIEW message_products AS
SELECT
    id,
    message_id,
    uid_key,
    entity_key AS sku,
    sub_group AS base_series,
    category AS product_family,
    quantity,
    unit,
    role AS context_role,
    snippet
FROM message_entities
WHERE entity_type = 'item_code';

CREATE VIEW message_attachments_mime AS
SELECT
    id,
    message_id,
    uid_key,
    filename,
    ext,
    mime_type,
    size_bytes,
    is_inline,
    sha256,
    text_preview
FROM message_attachments
WHERE is_noise = 0;

CREATE VIEW v_sku_price_history AS
SELECT
    p.sku,
    p.product_family,
    p.currency,
    p.unit_price,
    p.total_amount,
    p.quantity,
    p.price_type,
    p.tax_mode,
    p.moq,
    p.lead_time,
    p.discount_info,
    p.valid_until,
    COALESCE(NULLIF(p.quote_date_iso, ''), m.date_iso) AS quote_date_iso,
    COALESCE(NULLIF(p.project_name, ''), m.project_name) AS project_name,
    COALESCE(NULLIF(p.customer_org, ''), m.customers_orgs) AS customer_org,
    p.confidence,
    p.source_kind,
    p.evidence_snippet,
    p.message_id,
    p.uid_key,
    m.subject,
    m.sender
FROM message_prices p
JOIN messages m ON m.id = p.message_id
ORDER BY COALESCE(NULLIF(p.quote_date_iso, ''), m.date_iso) DESC, p.id DESC;

CREATE VIEW v_project_overview AS
SELECT
    topic_name AS project_name,
    message_count,
    full_body_count,
    amount_message_count AS price_message_count,
    first_date_iso,
    last_date_iso,
    categories AS product_families,
    org_tags AS customers_orgs,
    intent_types
FROM v_topic_overview;

CREATE VIEW v_customer_overview AS
SELECT
    org_name AS customer_org,
    message_count,
    full_body_count,
    amount_message_count AS price_message_count,
    first_date_iso,
    last_date_iso,
    topics AS projects,
    categories AS product_families
FROM v_org_overview;
"#;

/// Initializes the `1.0-universal` schema inside a newly created SQLite database connection.
pub fn init_schema(conn: &Connection) -> KbResult<()> {
    conn.execute_batch(UNIVERSAL_SCHEMA_SQL)?;
    Ok(())
}
