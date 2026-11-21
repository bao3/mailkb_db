use super::*;
use mailkb_core::config::{MailKbConfig, DEFAULT_DB_FILENAME, DEFAULT_DB_STEM};
use mailkb_core::fts::tokenize_for_fts;
use mailkb_core::publish::publish_clean_sqlite;
use mailkb_core::security::real_allow_missing;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

const FIXTURE_SCHEMA_SQL: &str = r#"
CREATE TABLE kb_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);

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

CREATE VIRTUAL TABLE messages_fts USING fts5(subject_tok, sender_tok, meta_tok, body_latest_tok, body_quoted_tok, tokenize='unicode61');
CREATE VIRTUAL TABLE dimensions_fts USING fts5(title_tok, meaning_tok, intent_tok, entities_tok, orgs_tok, topics_tok, amounts_tok, tokenize='unicode61');
CREATE VIRTUAL TABLE attachments_fts USING fts5(filename_tok, meta_tok, tokenize='unicode61');

CREATE VIEW v_amount_history AS
SELECT
    a.id, a.message_id, a.uid_key, a.amount_type, a.subject_entity, a.category,
    COALESCE(NULLIF(a.topic_name, ''), m.topic_tags) AS topic_name,
    COALESCE(NULLIF(a.org_name, ''), m.org_tags) AS org_name,
    a.currency, a.unit_amount, a.total_amount, a.quantity, a.tax_mode, a.terms_json,
    COALESCE(json_extract(a.terms_json, '$.moq'), '') AS moq,
    COALESCE(json_extract(a.terms_json, '$.lead_time'), '') AS lead_time,
    COALESCE(json_extract(a.terms_json, '$.discount_info'), '') AS discount_info,
    COALESCE(NULLIF(a.effective_date_iso, ''), m.date_iso) AS effective_date_iso,
    a.valid_until, a.source_kind, a.evidence_snippet, a.confidence,
    m.subject, m.sender, m.account_id, m.rfc_message_id
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
"#;

struct TestFixture {
    _tmp: TempDir,
    cfg: MailKbConfig,
    eml_dir: PathBuf,
}

fn setup_fixture() -> TestFixture {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let data_dir = root.join("data");
    let rt_dir = root.join("runtime");
    let eml_dir = root.join("emls");
    let packs_dir = root.join("packs");
    fs::create_dir_all(&data_dir).unwrap();
    fs::create_dir_all(&rt_dir).unwrap();
    fs::create_dir_all(eml_dir.join("quotes")).unwrap();
    fs::create_dir_all(&packs_dir).unwrap();
    fs::write(eml_dir.join("quotes/q1.eml"), b"Subject: Quote\r\n\r\nBody").unwrap();
    fs::write(eml_dir.join("quotes/bom.xlsx"), b"dummy-xlsx-bytes").unwrap();

    let mut cfg = MailKbConfig::discover()
        .with_db_dir_override(&data_dir)
        .with_runtime_dir_override(&rt_dir);
    cfg.packs_dir = packs_dir;
    cfg.eml_dirs = vec![eml_dir.clone()];
    cfg.apple_mail_v10_dir = None;

    let work_db = root.join("work.sqlite");
    let clean_db = root.join("clean.sqlite");
    let conn = Connection::open(&work_db).unwrap();
    conn.execute_batch(FIXTURE_SCHEMA_SQL).unwrap();

    let meta_rows = [
        ("schema_version", "1.0-universal"),
        ("writer_version", "1.0.0-test"),
        ("last_sync_iso", "2026-04-15T12:00:00+0000"),
        ("pack_ids", "b2b-hardware-sample"),
        ("rules_fingerprint", "b2b-hardware-sample:1234567890ab"),
    ];
    for (k, v) in meta_rows {
        conn.execute("INSERT INTO kb_meta(key, value) VALUES (?1, ?2)", [k, v])
            .unwrap();
    }

    // Message 1: EML quote with CJK + ANSI control test in subject, entity, amount, and disk + traversal attachments
    let subj1 = "工业交换机报价 ACME-SW-2400\x1b[31m ALERT\x1b[0m";
    let body1 = "请查收 Northstar 项目 ProjectHorizon 的 ACME-SW-2400 报价，单价 USD 450。";
    conn.execute(
        "INSERT INTO mail_messages (
            uid_key, account_id, source, source_ref, rfc_message_id, subject, thread_topic,
            sender, recipients, cc, date_iso, folder_path, completeness, direction, intent_type,
            summary_line, body_latest, body_quoted, content_hash, primary_entities, primary_category,
            topic_tags, org_tags, has_amount, amount_summary, event_dates_json, custom_dims_json
        ) VALUES (
            'uid-101', 'acct-sales', 'eml', 'quotes/q1.eml', '<Msg-101@acme.test>', ?1, 'ACME-SW-2400',
            'alice@acme.test', 'buyer@northstar.test', '', '2026-04-10 09:30:00', 'Sent', 'full_body',
            'external_outbound', 'quotation', 'Quoted ACME-SW-2400 at USD 450', ?2, 'Previous quoted thread',
            'hash-101', 'ACME-SW-2400', 'Switch', 'ProjectHorizon', 'Northstar Corp', 1,
            'USD 450 x 10', '{}', '{\"standards\":\"IEC-61850\",\"deploy-tier\":\"industrial\"}'
        )",
        params![subj1, body1],
    ).unwrap();
    let m1 = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO messages_fts(rowid, subject_tok, sender_tok, meta_tok, body_latest_tok, body_quoted_tok)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            m1,
            tokenize_for_fts(subj1),
            tokenize_for_fts("alice@acme.test"),
            tokenize_for_fts("Switch ProjectHorizon Northstar Corp"),
            tokenize_for_fts(body1),
            tokenize_for_fts("Previous quoted thread"),
        ],
    ).unwrap();
    conn.execute(
        "INSERT INTO dimensions_fts(rowid, title_tok, meaning_tok, intent_tok, entities_tok, orgs_tok, topics_tok, amounts_tok)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            m1,
            tokenize_for_fts(subj1),
            tokenize_for_fts("Quoted ACME-SW-2400 at USD 450"),
            tokenize_for_fts("quotation"),
            tokenize_for_fts("ACME-SW-2400 IEC-61850"),
            tokenize_for_fts("Northstar Corp"),
            tokenize_for_fts("ProjectHorizon"),
            tokenize_for_fts("USD 450"),
        ],
    ).unwrap();

    // Entities for msg 1
    conn.execute(
        "INSERT INTO message_entities (message_id, uid_key, entity_type, entity_key, canonical_value, category, sub_group, quantity, unit, role, confidence, snippet)
         VALUES (?1, 'uid-101', 'item_code', 'ACME-SW-2400', 'ACME-SW-2400', 'Switch', 'ACME-SW', 10.0, 'pcs', 'quoted', 'high', 'ACME-SW-2400 x 10')",
        [m1],
    ).unwrap();
    conn.execute(
        "INSERT INTO message_entities (message_id, uid_key, entity_type, entity_key, canonical_value, category, sub_group, confidence, snippet)
         VALUES (?1, 'uid-101', 'standards', 'IEC-61850', 'IEC 61850', 'Compliance', '', 'high', 'IEC-61850 substation')",
        [m1],
    ).unwrap();

    // Amount for msg 1
    conn.execute(
        "INSERT INTO message_amounts (message_id, uid_key, amount_type, subject_entity, category, topic_name, org_name, currency, unit_amount, total_amount, quantity, tax_mode, terms_json, effective_date_iso, valid_until, source_kind, evidence_snippet, confidence)
         VALUES (?1, 'uid-101', 'quote', 'ACME-SW-2400', 'Switch', 'ProjectHorizon', 'Northstar Corp', 'USD', 450.0, 4500.0, 10.0, 'EXW', '{\"moq\":\"5 pcs\",\"lead_time\":\"2 weeks\",\"discount_info\":\"5% tier\"}', '2026-04-10', '2026-05-10', 'body_table', 'ACME-SW-2400 unit USD 450 MOQ 5', 'high')",
        [m1],
    ).unwrap();

    // Attachments for msg 1 (one safe local file, one inline MIME part, one noise, one unsafe traversal)
    conn.execute(
        "INSERT INTO message_attachments (message_id, uid_key, filename, clean_filename, ext, mime_type, size_bytes, mtime, mtime_iso, storage_relpath, is_inline, is_noise, sha256, text_preview, entity_tags, topic_tags)
         VALUES (?1, 'uid-101', 'BOM_ACME-SW-2400.xlsx', 'BOM_ACME-SW-2400.xlsx', 'xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 16, 1775813400, '2026-04-10 09:30:00', 'quotes/bom.xlsx', 0, 0, 'abc123', 'ACME-SW-2400 USD 450', 'ACME-SW-2400', 'ProjectHorizon')",
        [m1],
    ).unwrap();
    let att1 = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO attachments_fts(rowid, filename_tok, meta_tok) VALUES (?1, ?2, ?3)",
        params![att1, tokenize_for_fts("BOM_ACME-SW-2400.xlsx"), tokenize_for_fts("ACME-SW-2400 ProjectHorizon")],
    ).unwrap();

    conn.execute(
        "INSERT INTO message_attachments (message_id, uid_key, filename, clean_filename, ext, mime_type, size_bytes, mtime, mtime_iso, storage_relpath, is_inline, is_noise, sha256, text_preview, entity_tags, topic_tags)
         VALUES (?1, 'uid-101', 'logo.png', 'logo.png', 'png', 'image/png', 1024, 1775813400, '2026-04-10 09:30:00', 'quotes/q1.eml#part1', 1, 1, 'noise1', '', '', '')",
        [m1],
    ).unwrap();
    let att2 = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO attachments_fts(rowid, filename_tok, meta_tok) VALUES (?1, ?2, '')",
        params![att2, tokenize_for_fts("logo.png")],
    ).unwrap();

    conn.execute(
        "INSERT INTO message_attachments (message_id, uid_key, filename, clean_filename, ext, mime_type, size_bytes, mtime, mtime_iso, storage_relpath, is_inline, is_noise, sha256, text_preview, entity_tags, topic_tags)
         VALUES (?1, 'uid-101', 'evil.pdf', 'evil.pdf', 'pdf', 'application/pdf', 99, 1775813400, '2026-04-10 09:30:00', '../../etc/passwd', 0, 0, 'badsha', '', 'ACME-SW-2400', 'ProjectHorizon')",
        [m1],
    ).unwrap();
    let att3 = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO attachments_fts(rowid, filename_tok, meta_tok) VALUES (?1, ?2, ?3)",
        params![att3, tokenize_for_fts("evil.pdf"), tokenize_for_fts("ACME-SW-2400")],
    ).unwrap();

    // Message 2: Apple Mail message in different account & month
    let subj2 = "NS-ENT-100 Renewal Order";
    let body2 = "Confirmed renewal order for NS-ENT-100 subscription, total EUR 1200.";
    conn.execute(
        "INSERT INTO mail_messages (
            uid_key, account_id, source, source_ref, rfc_message_id, subject, thread_topic,
            sender, recipients, cc, date_iso, folder_path, completeness, direction, intent_type,
            summary_line, body_latest, body_quoted, content_hash, primary_entities, primary_category,
            topic_tags, org_tags, has_amount, amount_summary, event_dates_json, custom_dims_json
        ) VALUES (
            'uid-202', 'acct-eu', 'apple_mail', 'am:202', '<Msg-202@northstar.test>', ?1, 'NS-ENT-100',
            'procurement@northstar.test', 'eu@acme.test', '', '2026-03-22T14:00:00+0000', 'INBOX', 'full_body',
            'external_inbound', 'purchase_order', 'PO for NS-ENT-100 EUR 1200', ?2, '',
            'hash-202', 'NS-ENT-100', 'SaaS', 'ProjectHorizon,RenewalQ1', 'Northstar Corp', 1,
            'EUR 1200', '{}', '{\"compliance\":\"SOC2\"}'
        )",
        params![subj2, body2],
    ).unwrap();
    let m2 = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO messages_fts(rowid, subject_tok, sender_tok, meta_tok, body_latest_tok, body_quoted_tok)
         VALUES (?1, ?2, ?3, ?4, ?5, '')",
        params![
            m2,
            tokenize_for_fts(subj2),
            tokenize_for_fts("procurement@northstar.test"),
            tokenize_for_fts("SaaS ProjectHorizon RenewalQ1 Northstar Corp"),
            tokenize_for_fts(body2),
        ],
    ).unwrap();
    conn.execute(
        "INSERT INTO dimensions_fts(rowid, title_tok, meaning_tok, intent_tok, entities_tok, orgs_tok, topics_tok, amounts_tok)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            m2,
            tokenize_for_fts(subj2),
            tokenize_for_fts("PO for NS-ENT-100 EUR 1200"),
            tokenize_for_fts("purchase_order"),
            tokenize_for_fts("NS-ENT-100 SOC2"),
            tokenize_for_fts("Northstar Corp"),
            tokenize_for_fts("ProjectHorizon RenewalQ1"),
            tokenize_for_fts("EUR 1200"),
        ],
    ).unwrap();

    conn.execute(
        "INSERT INTO message_entities (message_id, uid_key, entity_type, entity_key, canonical_value, category, sub_group, quantity, unit, role, confidence, snippet)
         VALUES (?1, 'uid-202', 'item_code', 'NS-ENT-100', 'NS-ENT-100', 'SaaS', 'NS-ENT', 1.0, 'seat', 'ordered', 'high', 'NS-ENT-100')",
        [m2],
    ).unwrap();
    conn.execute(
        "INSERT INTO message_amounts (message_id, uid_key, amount_type, subject_entity, category, topic_name, org_name, currency, unit_amount, total_amount, quantity, tax_mode, terms_json, effective_date_iso, valid_until, source_kind, evidence_snippet, confidence)
         VALUES (?1, 'uid-202', 'order', 'NS-ENT-100', 'SaaS', 'RenewalQ1', 'Northstar Corp', 'EUR', 1200.0, 1200.0, 1.0, '', '{}', '2026-03-22', '', 'body_inline', 'total EUR 1200', 'medium')",
        [m2],
    ).unwrap();

    conn.execute(
        "INSERT INTO domain_lexicon (pack_id, dimension, key, canonical_name, aliases, hit_count, metadata_json)
         VALUES ('b2b-hardware-sample', 'topic', 'ProjectHorizon', 'ProjectHorizon', 'Horizon', 2, '{\"phase\":\"pilot\"}')",
        [],
    ).unwrap();
    conn.execute(
        "INSERT INTO domain_lexicon (pack_id, dimension, key, canonical_name, aliases, hit_count, metadata_json)
         VALUES ('b2b-hardware-sample', 'organization', 'Northstar Corp', 'Northstar Corp', 'Northstar', 2, '{}')",
        [],
    ).unwrap();

    drop(conn);
    let dst_db = data_dir.join(DEFAULT_DB_FILENAME);
    publish_clean_sqlite(&cfg, &work_db, &clean_db, &dst_db, DEFAULT_DB_STEM).unwrap();

    TestFixture {
        _tmp: tmp,
        cfg,
        eml_dir,
    }
}

#[test]
fn search_fts_cjk_and_filters() {
    let fx = setup_fixture();

    // CJK bigram + mode=both
    let res = run_search(
        &fx.cfg,
        &SearchOpts {
            keywords: vec!["工业交换机".to_string()],
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(res["count"], 1);
    assert_eq!(res["results"][0]["uid_key"], "uid-101");
    assert_eq!(res["staging"], "reused"); // published updated runtime cache!
    assert!(res["results"][0]["eml_path"]
        .as_str()
        .unwrap()
        .ends_with("quotes/q1.eml"));

    // Term-safe rendering strips ANSI ESC from subject
    let rendered = render::render_search(&res);
    assert!(!rendered.contains('\x1b'));
    assert!(rendered.contains("ACME-SW-2400"));

    // Hyphen-insensitive entity filter + account filter + dim filter via message_entities
    let res2 = run_search(
        &fx.cfg,
        &SearchOpts {
            account: Some("acct-sales".to_string()),
            entity: Some("acmesw2400".to_string()),
            category: Some("switch".to_string()),
            has_amount: true,
            dim_filters: vec![("standards".to_string(), "iec61850".to_string())],
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(res2["count"], 1);

    // Hyphenated key in custom_dims_json via --dim
    let res_hyphen_dim = run_search(
        &fx.cfg,
        &SearchOpts {
            dim_filters: vec![("deploy-tier".to_string(), "industrial".to_string())],
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(res_hyphen_dim["count"], 1);
    assert_eq!(res_hyphen_dim["results"][0]["uid_key"], "uid-101");

    // Date range filter covering ISO-8601 'T' timestamp with YYYY-MM-DD until
    let res_date = run_search(
        &fx.cfg,
        &SearchOpts {
            since: Some("2026-03-01".to_string()),
            until: Some("2026-03-22".to_string()),
            direction: Some("external_inbound".to_string()),
            ..Default::default()
        },
        None,
    )
    .unwrap();
    assert_eq!(res_date["count"], 1);
    assert_eq!(res_date["results"][0]["uid_key"], "uid-202");

    // Invalid mode / invalid dim key -> exit_code 2
    let bad_mode = run_search(
        &fx.cfg,
        &SearchOpts {
            mode: "bogus".to_string(),
            ..Default::default()
        },
        None,
    )
    .unwrap_err();
    assert_eq!(bad_mode.exit_code(), 2);

    let bad_dim = run_search(
        &fx.cfg,
        &SearchOpts {
            dim_filters: vec![("bad.key$".to_string(), "x".to_string())],
            ..Default::default()
        },
        None,
    )
    .unwrap_err();
    assert_eq!(bad_dim.exit_code(), 2);
}

#[test]
fn read_by_id_uid_and_rfc_message_id_with_s10() {
    let fx = setup_fixture();

    // By RFC message id (case-insensitive & angle brackets stripped)
    let r_rfc = run_read(
        &fx.cfg,
        &ReadOpts {
            id_or_uid: "<msg-101@ACME.TEST>".to_string(),
            full: false,
        },
    )
    .unwrap();
    assert_eq!(r_rfc["message"]["uid_key"], "uid-101");
    assert!(r_rfc["message"].get("body_quoted").is_none());
    assert_eq!(r_rfc["message"]["has_quoted"], true);
    assert_eq!(r_rfc["entities"].as_array().unwrap().len(), 2);
    assert_eq!(r_rfc["amounts"].as_array().unwrap().len(), 1);
    assert_eq!(r_rfc["amounts"][0]["moq"], "5 pcs");
    assert_eq!(r_rfc["amounts"][0]["lead_time"], "2 weeks");

    // Verify S10 resolution on the 3 attachments
    let atts = r_rfc["attachments"].as_array().unwrap();
    assert_eq!(atts.len(), 3);
    assert_eq!(atts[0]["local_exists"], true);
    assert_eq!(
        atts[0]["local_path"].as_str().unwrap(),
        real_allow_missing(&fx.eml_dir.join("quotes/bom.xlsx")).to_string_lossy()
    );
    assert_eq!(atts[1]["local_exists"], false);
    assert!(atts[1]["container_path"]
        .as_str()
        .unwrap()
        .ends_with("quotes/q1.eml"));
    assert_eq!(atts[2]["local_path"], Value::Null);
    assert_eq!(atts[2]["local_exists"], false);
    assert_eq!(atts[2]["path_rejected"], true);

    // By integer id with --full
    let id = r_rfc["message"]["id"].as_i64().unwrap();
    let r_full = run_read(
        &fx.cfg,
        &ReadOpts {
            id_or_uid: id.to_string(),
            full: true,
        },
    )
    .unwrap();
    assert_eq!(r_full["message"]["body_quoted"], "Previous quoted thread");
    let txt = render::render_read(&r_full, true);
    assert!(!txt.contains('\x1b'));
    assert!(txt.contains("Quoted Thread"));
}

#[test]
fn entities_amounts_topics_orgs_timeline_att_stats_audit_selftest() {
    let fx = setup_fixture();

    // Entities aggregation & drill-down
    let ents = run_entities(
        &fx.cfg,
        &EntityListOpts {
            entity_type: Some("item_code".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(ents["count"], 2);

    let ent_drill = run_entities(
        &fx.cfg,
        &EntityListOpts {
            entity: Some("ACME-SW-2400".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(ent_drill["count"], 1);
    assert_eq!(ent_drill["amount_history"].as_array().unwrap().len(), 1);
    assert_eq!(ent_drill["messages"].as_array().unwrap().len(), 1);
    assert!(!render::render_entities(&ent_drill).is_empty());

    // Amounts query
    let amts = run_amounts(
        &fx.cfg,
        &AmountListOpts {
            currency: Some("usd".to_string()),
            topic: Some("Horizon".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(amts["count"], 1);
    assert_eq!(amts["results"][0]["moq"], "5 pcs");
    assert_eq!(amts["currency_summary"]["USD"]["avg"], 450.0);
    assert!(!render::render_amounts(&amts).is_empty());

    // Topics list & drill-down
    let topics = run_topics(&fx.cfg, &TopicListOpts::default()).unwrap();
    assert_eq!(topics["count"], 2);
    let topic_drill = run_topics(
        &fx.cfg,
        &TopicListOpts {
            topic: Some("ProjectHorizon".to_string()),
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(topic_drill["messages"].as_array().unwrap().len(), 2);
    assert!(!render::render_topics(&topics).is_empty());

    // Orgs list & drill-down
    let orgs = run_orgs(&fx.cfg, &OrgListOpts::default()).unwrap();
    assert_eq!(orgs["count"], 1);
    assert_eq!(orgs["results"][0]["org_name"], "Northstar Corp");
    let org_drill = run_orgs(
        &fx.cfg,
        &OrgListOpts {
            org: Some("Northstar".to_string()),
            limit: 10,
        },
    )
    .unwrap();
    assert_eq!(org_drill["messages"].as_array().unwrap().len(), 2);
    assert!(!render::render_orgs(&org_drill).is_empty());

    // Timeline monthly & daily
    let tl_m = run_timeline(&fx.cfg, &TimelineOpts::default()).unwrap();
    assert_eq!(tl_m["count"], 2);
    let tl_d = run_timeline(
        &fx.cfg,
        &TimelineOpts {
            granularity: "day".to_string(),
            topic: Some("RenewalQ1".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(tl_d["count"], 1);
    assert_eq!(tl_d["results"][0]["period"], "2026-03-22");
    assert!(!render::render_timeline(&tl_d).is_empty());

    // Attachments search (noise excluded by default, traversal path rejected)
    let att_clean = run_att(
        &fx.cfg,
        &AttOpts {
            keywords: vec!["BOM".to_string()],
            ext: Some(".xlsx".to_string()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(att_clean["count"], 1);
    assert_eq!(att_clean["results"][0]["local_exists"], true);

    let att_all = run_att(
        &fx.cfg,
        &AttOpts {
            include_noise: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(att_all["count"], 3);
    assert!(!render::render_att(&att_all).is_empty());

    // Stats
    let stats = run_stats(&fx.cfg).unwrap();
    assert_eq!(stats["counts"]["mail_messages"], 2);
    assert_eq!(stats["counts"]["messages_with_amount"], 2);
    assert_eq!(stats["counts"]["domain_lexicon"], 2);
    assert_eq!(stats["pack_ids"], "b2b-hardware-sample");
    assert_eq!(stats["by_account"].as_array().unwrap().len(), 2);
    assert!(!render::render_stats(&stats).is_empty());

    // Audit
    let audit = run_audit(&fx.cfg).unwrap();
    assert_eq!(audit["status"], "ok");
    assert_eq!(audit["cold_db"]["checksum_match"], true);
    assert_eq!(audit["runtime_cache"]["quick_check_ok"], true);
    assert!(!render::render_audit(&audit).is_empty());

    // Selftest (with optional pack_sample)
    let pack_path = fx._tmp.path().join("packs/sample.json");
    fs::write(
        &pack_path,
        r#"{
          "schema_version": "domain-pack.v1",
          "pack_id": "sample-test",
          "entity_rules": {
            "code_patterns": [
              { "name": "sw", "pattern": "\\bACME-[A-Z]{2}-\\d{4}\\b", "category": "Switch" }
            ]
          }
        }"#,
    )
    .unwrap();
    let st = run_selftest(&fx.cfg, Some(&pack_path)).unwrap();
    assert_eq!(st["status"], "ok");
    assert!(st["checks"].as_array().unwrap().len() >= 7);
    assert!(!render::render_selftest(&st).is_empty());
}

#[test]
fn s9_rejects_runtime_inside_mail_container() {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let bad_rt = PathBuf::from(home).join("Library/Mail/V10/bad_runtime");
    let cfg = MailKbConfig::discover().with_runtime_dir_override(&bad_rt);
    let err = run_stats(&cfg).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert!(err.is_mail_container_violation());
}

#[test]
fn search_auto_sync_and_read_not_found_exit_codes() {
    let fx = setup_fixture();

    // Non-master host emits warning without failing search
    let called = std::sync::atomic::AtomicBool::new(false);
    let cb = |_c: &MailKbConfig| -> KbResult<()> {
        called.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    };
    let res = run_search(
        &fx.cfg,
        &SearchOpts {
            auto_sync: true,
            ..Default::default()
        },
        Some(&cb),
    )
    .unwrap();
    assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    let warnings = res["warnings"].as_array().unwrap();
    assert!(warnings
        .iter()
        .any(|w| w.as_str().unwrap_or("").starts_with("auto_sync_skipped_non_master_host")));

    // Master host (mock V10 dir with Envelope Index) invokes auto_sync callback
    let mock_v10 = fx._tmp.path().join("mock_v10");
    fs::create_dir_all(mock_v10.join("MailData")).unwrap();
    fs::write(mock_v10.join("MailData/Envelope Index"), b"SQLite format 3\0").unwrap();
    let mut master_cfg = fx.cfg.clone();
    master_cfg.apple_mail_v10_dir = Some(mock_v10);
    let res2 = run_search(
        &master_cfg,
        &SearchOpts {
            auto_sync: true,
            ..Default::default()
        },
        Some(&cb),
    )
    .unwrap();
    assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(res2["count"], 2);

    // NotFound returns exit_code 4
    let err = run_read(
        &fx.cfg,
        &ReadOpts {
            id_or_uid: "nonexistent-uid-999".to_string(),
            full: false,
        },
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), 4);
}
