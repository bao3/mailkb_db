use mailkb_core::{open_staged_ro, MailKbConfig, DEFAULT_MMAP_BYTES};
use mailkb_sync::apple_mail::{
    discover_accounts_and_filter, infer_identity_from_envelope_db, load_all_mailboxes,
    mail_master_state, parse_mailbox_url, reversed_shard_path, MasterState,
};
use mailkb_sync::enrich::{enrich_message, InferredIdentity, RawMessageInput, ResolvedIdentity};
use mailkb_sync::html::parse_html_clean_and_tables;
use mailkb_sync::mime::{
    collect_mime_parts, decode_rfc2047_header, parse_rfc5322_date, slice_emlx_rfc822,
};
use mailkb_sync::schema::{SCHEMA_VERSION, UNIVERSAL_SCHEMA_SQL};
use mailkb_sync::{
    run_profile_corpus, run_sync, run_test_pack, ProfileOpts, SyncOpts, TestPackOpts,
};
use rusqlite::{Connection, OpenFlags};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

fn test_cfg(tmp: &TempDir) -> MailKbConfig {
    let base = tmp.path();
    MailKbConfig {
        db_dir: base.join("data"),
        db_path: base.join("data/mailkb_db.sqlite"),
        runtime_dir: base.join("runtime"),
        packs_dir: base.join("packs"),
        pack_paths: Vec::new(),
        no_packs: true,
        apple_mail_v10_dir: None,
        account_filters: Vec::new(),
        eml_dirs: Vec::new(),
        outlook_profile_dir: None,
        max_threads: 2,
    }
}

fn build_test_xlsx_bytes() -> Vec<u8> {
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut zip = ZipWriter::new(&mut buf);
        let opts = SimpleFileOptions::default();

        zip.start_file("[Content_Types].xml", opts).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
</Types>"#,
        )
        .unwrap();

        zip.start_file("xl/_rels/workbook.xml.rels", opts).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"#,
        )
        .unwrap();

        zip.start_file("xl/workbook.xml", opts).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
          xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Quote_USD" sheetId="1" r:id="rId1"/>
  </sheets>
</workbook>"#,
        )
        .unwrap();

        let strings = [
            "Part Number",
            "Description",
            "Qty",
            "Unit Price (USD)",
            "Total Amount",
            "MOQ",
            "Lead Time",
            "Discount",
            "ACME-SW-2400-HV",
            "24-Port Industrial Switch",
            "$450.00",
            "$22,500.00",
            "10 pcs",
            "4 weeks",
            "5% off",
        ];
        let mut sst = String::from(
            r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">"#,
        );
        for s in strings {
            sst.push_str(&format!("<si><t>{s}</t></si>"));
        }
        sst.push_str("</sst>");
        zip.start_file("xl/sharedStrings.xml", opts).unwrap();
        zip.write_all(sst.as_bytes()).unwrap();

        zip.start_file("xl/worksheets/sheet1.xml", opts).unwrap();
        zip.write_all(
            br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1">
      <c r="A1" t="s"><v>0</v></c>
      <c r="B1" t="s"><v>1</v></c>
      <c r="C1" t="s"><v>2</v></c>
      <c r="D1" t="s"><v>3</v></c>
      <c r="E1" t="s"><v>4</v></c>
      <c r="F1" t="s"><v>5</v></c>
      <c r="G1" t="s"><v>6</v></c>
      <c r="H1" t="s"><v>7</v></c>
    </row>
    <row r="2">
      <c r="A2" t="s"><v>8</v></c>
      <c r="B2" t="s"><v>9</v></c>
      <c r="C2"><v>50</v></c>
      <c r="D2" t="s"><v>10</v></c>
      <c r="E2" t="s"><v>11</v></c>
      <c r="F2" t="s"><v>12</v></c>
      <c r="G2" t="s"><v>13</v></c>
      <c r="H2" t="s"><v>14</v></c>
    </row>
  </sheetData>
</worksheet>"#,
        )
        .unwrap();
        zip.finish().unwrap();
    }
    buf.into_inner()
}

fn write_sample_pack(path: &Path) {
    let json = r#"{
      "schema_version": "domain-pack.v1",
      "pack_id": "acme-industrial-sample",
      "name": "Acme Industrial & Cloud Pack",
      "version": "1.0",
      "identity": {
        "self_emails": [],
        "internal_domains": [],
        "system_senders": ["noreply@alerts.example"],
        "system_domains": ["alerts.example"],
        "system_subject_prefixes": ["Automated Digest:"],
        "noise_attachment_prefixes": ["Acme_Banner"]
      },
      "entity_rules": {
        "default_category": "General",
        "exclude_code_tokens": ["ISO", "IEC", "RFC"],
        "code_patterns": [
          {
            "name": "acme_switch",
            "pattern": "\\bACME-(SW|GW)-\\d{3,4}(?:-[A-Z0-9]+)*\\b",
            "category": "Industrial Switch",
            "sub_group": "ACME-$1",
            "priority": 20,
            "exclude_if_matches": ["-202[0-9]$"],
            "extra_terms": ["ethernet", "switch"]
          },
          {
            "name": "northstar_cloud",
            "pattern": "(?<![A-Za-z0-9])NS-[A-Z]{2,4}-\\d{3}(?![A-Za-z0-9])",
            "category": "Cloud Tier",
            "series_regex": "^(NS-[A-Z]{2,4})",
            "priority": 15
          }
        ],
        "category_fallbacks": [
          {
            "category": "Industrial Switch",
            "patterns": ["\\bmanaged switch\\b", "工业交换机"],
            "priority": 5
          }
        ]
      },
      "dimensions": [
        {
          "name": "compliance",
          "entity_type": "compliance_standard",
          "entries": [
            {
              "key": "SOC2",
              "canonical_name": "SOC 2 Type II",
              "patterns": ["\\bSOC\\s*2\\b", "\\bSOC2\\b"],
              "aliases": ["SOC2", "SOC 2"]
            },
            {
              "key": "IEC-62443",
              "canonical_name": "IEC 62443 Cybersecurity",
              "patterns": ["IEC[-\\s]?62443"],
              "aliases": ["IEC62443"]
            }
          ]
        },
        {
          "name": "region",
          "entity_type": "geo_region",
          "entries": [
            {
              "key": "EMEA",
              "canonical_name": "Europe Middle East Africa",
              "patterns": ["\\bEMEA\\b", "\\bFrankfurt\\b"]
            }
          ]
        }
      ],
      "organizations": {
        "exclude_domains": ["example-ignore.invalid"],
        "domain_to_org": {
          "northstar.example": "Northstar Cloud Inc",
          "zenith-rail.example": "Zenith Rail Systems"
        },
        "email_to_org": {
          "vip@partner.example": "Partner Global Ltd"
        },
        "entries": [
          {
            "canonical_name": "Northstar Cloud Inc",
            "patterns": ["Northstar Cloud", "\\bNorthstar\\b"],
            "domains": ["northstar.example"],
            "aliases": ["Northstar"]
          }
        ]
      },
      "topics": {
        "generic_suffix_patterns": ["([A-Za-z0-9_\\s]{3,24}Project)"],
        "entries": [
          {
            "canonical_name": "Grid Modernization",
            "patterns": ["Grid Modernization", "智能电网改造"],
            "aliases": ["GridMod"]
          }
        ]
      },
      "intents": [
        {
          "intent": "Quote & Pricing",
          "priority": 20,
          "patterns": ["\\bquote\\b", "\\bquotation\\b", "\\bpricing\\b", "报价"]
        },
        {
          "intent": "Compliance Review",
          "priority": 15,
          "patterns": ["\\bSOC\\s*2\\b", "IEC[-\\s]?62443", "compliance"]
        }
      ],
      "amounts": {
        "exclude_subject_patterns": ["Travel Receipt"],
        "currency_aliases": {
          "CNY": "RMB",
          "US$": "USD"
        },
        "type_rules": [
          {
            "amount_type": "order_price",
            "confidence": "high",
            "priority": 20,
            "patterns": ["Purchase Order", "\\bPO\\b", "订单价"]
          },
          {
            "amount_type": "spr_support",
            "confidence": "high",
            "priority": 15,
            "patterns": ["Special Support", "特价支持"]
          }
        ]
      }
    }"#;
    fs::write(path, json).unwrap();
}

fn write_emlx_file(path: &Path, rfc822: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut data = format!("{}\n", rfc822.len()).into_bytes();
    data.extend_from_slice(rfc822);
    data.extend_from_slice(b"\n<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict/></plist>");
    fs::write(path, data).unwrap();
}

fn create_fake_apple_mail_v10(v10_dir: &Path) -> PathBuf {
    let mail_data = v10_dir.join("MailData");
    fs::create_dir_all(&mail_data).unwrap();
    let env_path = mail_data.join("Envelope Index");
    let conn = Connection::open(&env_path).unwrap();

    conn.execute_batch(
        r#"
        CREATE TABLE mailboxes (ROWID INTEGER PRIMARY KEY, url TEXT NOT NULL);
        CREATE TABLE subjects (ROWID INTEGER PRIMARY KEY, subject TEXT);
        CREATE TABLE addresses (ROWID INTEGER PRIMARY KEY, address TEXT, comment TEXT);
        CREATE TABLE summaries (ROWID INTEGER PRIMARY KEY, summary TEXT);
        CREATE TABLE message_global_data (ROWID INTEGER PRIMARY KEY, message_id_header TEXT);
        CREATE TABLE messages (
            ROWID INTEGER PRIMARY KEY,
            mailbox INTEGER,
            subject INTEGER,
            sender INTEGER,
            summary INTEGER,
            date_sent INTEGER,
            date_received INTEGER,
            global_message_id INTEGER,
            size INTEGER,
            deleted INTEGER DEFAULT 0
        );
        CREATE TABLE recipients (
            ROWID INTEGER PRIMARY KEY,
            message INTEGER,
            type INTEGER,
            position INTEGER,
            address INTEGER
        );
        "#,
    )
    .unwrap();

    let acct_work = "11111111-1111-4111-8111-111111111111";
    let acct_personal = "22222222-2222-4222-8222-222222222222";
    let work_mbox_uuid = "33333333-3333-4333-8333-333333333333";
    let pers_mbox_uuid = "44444444-4444-4444-8444-444444444444";

    conn.execute(
        "INSERT INTO mailboxes (ROWID, url) VALUES (1, ?1), (2, ?2), (3, ?3), (4, ?4)",
        rusqlite::params![
            format!("ews://{acct_work}/INBOX"),
            format!("ews://{acct_work}/Sent%20Messages"),
            format!("imap://{acct_personal}/%5BGmail%5D/Sent%20Mail"),
            "local:///Archive/Notes",
        ],
    )
    .unwrap();

    conn.execute_batch(
        r#"
        INSERT INTO addresses (ROWID, address, comment) VALUES
            (1, 'alice@acme-corp.example', 'Alice'),
            (2, 'bob@northstar.example', 'Bob'),
            (3, 'alice@gmail.com', 'Alice Personal');
        INSERT INTO subjects (ROWID, subject) VALUES
            (1, 'Re: [Grid Modernization] ACME-SW-2400-HV Quote & SOC 2'),
            (2, 'Outbound quote ACME-SW-2400-HV for Northstar'),
            (3, 'Personal note on NS-ENT-100');
        INSERT INTO summaries (ROWID, summary) VALUES
            (1, 'Quote for ACME-SW-2400-HV'),
            (2, 'Sent ACME-SW-2400-HV pricing'),
            (3, 'Personal note');
        INSERT INTO message_global_data (ROWID, message_id_header) VALUES
            (1, '<msg-work-001@northstar.example>'),
            (2, '<msg-work-002@acme-corp.example>'),
            (3, '<msg-pers-003@gmail.com>');
        INSERT INTO messages (ROWID, mailbox, subject, sender, summary, date_sent, date_received, global_message_id, size, deleted) VALUES
            (1, 1, 1, 2, 1, 1775000000, 1775000000, 1, 4096, 0),
            (2, 2, 2, 1, 2, 1775001000, 1775001000, 2, 2048, 0),
            (3, 3, 3, 3, 3, 1775002000, 1775002000, 3, 1024, 0);
        INSERT INTO recipients (ROWID, message, type, position, address) VALUES
            (1, 1, 0, 0, 1),
            (2, 2, 0, 0, 2),
            (3, 3, 0, 0, 2);
        "#,
    )
    .unwrap();

    // Write .emlx for message 1 (with XLSX disk attachment) and message 2
    let work_inbox_data = v10_dir
        .join(acct_work)
        .join("INBOX.mbox")
        .join(work_mbox_uuid)
        .join("Data");
    let msg1_emlx = work_inbox_data.join("Messages/1.emlx");
    let raw1 = concat!(
        "From: Bob <bob@northstar.example>\r\n",
        "To: Alice <alice@acme-corp.example>\r\n",
        "Subject: Re: [Grid Modernization] ACME-SW-2400-HV Quote & SOC 2\r\n",
        "Message-ID: <msg-work-001@northstar.example>\r\n",
        "Date: Wed, 01 Apr 2026 10:00:00 +0800\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Hi Alice,\r\nPlease confirm Purchase Order price for ACME-SW-2400-HV at USD 450.00 (excl. tax), MOQ 10 pcs, lead time 4 weeks.\r\n",
        "Also confirming SOC 2 Type II and IEC 62443 compliance.\r\n"
    );
    write_emlx_file(&msg1_emlx, raw1.as_bytes());

    let att_path = work_inbox_data.join("Attachments/1/2/acme_quote.xlsx");
    fs::create_dir_all(att_path.parent().unwrap()).unwrap();
    fs::write(&att_path, build_test_xlsx_bytes()).unwrap();
    // Noise attachment (< 16 KiB small inline icon) should be recorded as is_noise=1
    // in message_attachments and filtered out of MailKBAI's message_attachments_mime view.
    let noise_att_path = work_inbox_data.join("Attachments/1/3/image001.png");
    fs::create_dir_all(noise_att_path.parent().unwrap()).unwrap();
    fs::write(&noise_att_path, b"tiny-png-icon").unwrap();

    let work_sent_data = v10_dir
        .join(acct_work)
        .join("Sent Messages.mbox")
        .join(work_mbox_uuid)
        .join("Data");
    let msg2_emlx = work_sent_data.join("Messages/2.emlx");
    let raw2 = concat!(
        "From: Alice <alice@acme-corp.example>\r\n",
        "To: Bob <bob@northstar.example>\r\n",
        "Subject: Outbound quote ACME-SW-2400-HV for Northstar\r\n",
        "Message-ID: <msg-work-002@acme-corp.example>\r\n",
        "Date: Wed, 01 Apr 2026 10:15:00 +0800\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Hi Bob, ACME-SW-2400-HV Special Support unit price is $430.00.\r\n"
    );
    write_emlx_file(&msg2_emlx, raw2.as_bytes());

    let pers_sent_data = v10_dir
        .join(acct_personal)
        .join("[Gmail].mbox/Sent Mail.mbox")
        .join(pers_mbox_uuid)
        .join("Data");
    let msg3_emlx = pers_sent_data.join("Messages/3.emlx");
    let raw3 = concat!(
        "From: Alice Personal <alice@gmail.com>\r\n",
        "To: Bob <bob@northstar.example>\r\n",
        "Subject: Personal note on NS-ENT-100\r\n",
        "Message-ID: <msg-pers-003@gmail.com>\r\n",
        "Date: Wed, 01 Apr 2026 10:30:00 +0800\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "Check NS-ENT-100 availability in EMEA.\r\n"
    );
    write_emlx_file(&msg3_emlx, raw3.as_bytes());

    env_path
}

#[test]
fn multi_account_url_parsing_and_shard_paths() {
    let ews = parse_mailbox_url("ews://UUID-1/INBOX").unwrap();
    assert_eq!(ews.scheme, "ews");
    assert_eq!(ews.account_id, "UUID-1");
    assert_eq!(ews.folder_path, "INBOX");

    let imap = parse_mailbox_url("imap://UUID-2/%5BGmail%5D/Sent%20Mail").unwrap();
    assert_eq!(imap.scheme, "imap");
    assert_eq!(imap.account_id, "UUID-2");
    assert_eq!(imap.folder_path, "[Gmail]/Sent Mail");

    let pop = parse_mailbox_url("pop://UUID-3/Sent%20Items").unwrap();
    assert_eq!(pop.scheme, "pop");
    assert_eq!(pop.account_id, "UUID-3");
    assert_eq!(pop.folder_path, "Sent Items");

    let loc1 = parse_mailbox_url("local://UUID-4/Archive/2026").unwrap();
    assert_eq!(loc1.scheme, "local");
    assert_eq!(loc1.account_id, "UUID-4");
    assert_eq!(loc1.folder_path, "Archive/2026");

    let loc2 = parse_mailbox_url("local:///Notes/Drafts").unwrap();
    assert_eq!(loc2.scheme, "local");
    assert_eq!(loc2.account_id, "local");
    assert_eq!(loc2.folder_path, "Notes/Drafts");

    assert_eq!(reversed_shard_path(42), "");
    assert_eq!(reversed_shard_path(123_456), "3/2/1");
}

#[test]
fn sent_identity_inference_and_account_filtering() {
    let tmp = TempDir::new().unwrap();
    let v10 = tmp.path().join("V10");
    let env_path = create_fake_apple_mail_v10(&v10);

    let mut cfg = test_cfg(&tmp);
    cfg.apple_mail_v10_dir = Some(v10.clone());
    assert_eq!(mail_master_state(&cfg), MasterState::Master);

    cfg.apple_mail_v10_dir = Some(tmp.path().join("MissingV10"));
    assert!(matches!(mail_master_state(&cfg), MasterState::NotMaster(_)));

    let conn = Connection::open_with_flags(&env_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mbs = load_all_mailboxes(&conn, &v10).unwrap();
    assert_eq!(mbs.len(), 4);

    let (inferred, per_acct) = infer_identity_from_envelope_db(&conn, &mbs).unwrap();
    assert!(inferred
        .self_emails
        .contains(&"alice@acme-corp.example".to_string()));
    assert!(inferred.self_emails.contains(&"alice@gmail.com".to_string()));
    // Freemail domain gmail.com MUST NOT be inferred as internal_domain
    assert!(inferred
        .internal_domains
        .contains(&"acme-corp.example".to_string()));
    assert!(!inferred.internal_domains.contains(&"gmail.com".to_string()));

    // Filter by email matches only work account
    let (accts, mb_ids) = discover_accounts_and_filter(
        &conn,
        &mbs,
        &per_acct,
        &["alice@acme-corp.example".to_string()],
    )
    .unwrap();
    assert_eq!(accts.len(), 1);
    assert_eq!(accts[0].account_id, "11111111-1111-4111-8111-111111111111");
    assert_eq!(mb_ids, vec![1, 2]);
}

#[test]
fn mime_html_and_rfc5322_parsing() {
    let subj = decode_rfc2047_header(b"=?UTF-8?B?5oql5Lu35Y2V?= Quote");
    assert_eq!(subj, "报价单 Quote");

    let dt = parse_rfc5322_date("Wed, 01 Apr 2026 10:00:00 +0800");
    assert!(dt.starts_with("2026-04-0"));

    let rfc = concat!(
        "From: vendor@example.com\r\n",
        "Content-Type: multipart/mixed; boundary=\"B1\"\r\n",
        "\r\n",
        "--B1\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<p>Pricing table &amp; terms:</p><table><tr><th>SKU</th><th>Unit Price (USD)</th><th>MOQ</th></tr><tr><td>ACME-SW-100</td><td>$250.00</td><td>5 pcs</td></tr></table>\r\n",
        "--B1\r\n",
        "Content-Type: application/octet-stream\r\n",
        "Content-Disposition: attachment; filename*=UTF-8''%E6%8A%A5%E4%BB%B7%E5%8D%95.xlsx\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "QUJD\r\n",
        "--B1--\r\n"
    );
    let emlx_raw = format!("{}\n{rfc}\n<?xml version=\"1.0\"?>", rfc.len());
    let sliced = slice_emlx_rfc822(emlx_raw.as_bytes());
    let mut plain = String::new();
    let mut html = String::new();
    let mut atts = Vec::new();
    collect_mime_parts(sliced, &mut plain, &mut html, Some(&mut atts), 0);
    assert_eq!(atts.len(), 1);
    assert_eq!(atts[0].filename, "报价单.xlsx");
    assert_eq!(atts[0].bytes, b"ABC");

    let hp = parse_html_clean_and_tables(&html);
    assert_eq!(hp.tables.len(), 1);
    assert_eq!(hp.tables[0][1], vec!["ACME-SW-100", "$250.00", "5 pcs"]);
}

#[test]
fn zero_pack_universal_mode_eml_only_sync_and_dry_run() {
    let tmp = TempDir::new().unwrap();
    let eml_dir = tmp.path().join("emls");
    fs::create_dir_all(eml_dir.join("Sent")).unwrap();

    fs::write(
        eml_dir.join("quote1.eml"),
        concat!(
            "From: Sales <sales@vendor.example>\r\n",
            "To: Buyer <buyer@company.example>\r\n",
            "Subject: [Project Atlas] Quote for ACME-SW-2400 and NS-ENT-100\r\n",
            "Message-ID: <quote1@vendor.example>\r\n",
            "Date: Thu, 02 Apr 2026 09:00:00 +0000\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "Unit Price for ACME-SW-2400 is USD 450.00 excl. tax, MOQ 10 pcs, lead time 4 weeks, 5% off.\r\n"
        ),
    )
    .unwrap();

    fs::write(
        eml_dir.join("Sent/outbound.emlx"),
        {
            let body = concat!(
                "From: Buyer <buyer@company.example>\r\n",
                "To: Sales <sales@vendor.example>\r\n",
                "Subject: Re: [Project Atlas] Quote for ACME-SW-2400\r\n",
                "Message-ID: <outbound1@company.example>\r\n",
                "Date: Thu, 02 Apr 2026 10:00:00 +0000\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n",
                "\r\n",
                "Confirmed PO price for ACME-SW-2400 at $440.00.\r\n"
            );
            format!("{}\n{body}", body.len())
        },
    )
    .unwrap();

    let mut cfg = test_cfg(&tmp);
    cfg.eml_dirs = vec![eml_dir];
    cfg.no_packs = true;

    // Dry run should NOT write db_path
    let dry = run_sync(
        &cfg,
        &SyncOpts {
            dry_run: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(dry["status"], "dry_run");
    assert_eq!(dry["db_modified"], false);
    assert_eq!(dry["messages_total"], 2);
    assert!(!cfg.db_path.exists());

    // Real sync
    let res = run_sync(&cfg, &SyncOpts::default()).unwrap();
    assert_eq!(res["status"], "ok");
    assert_eq!(res["schema_version"], SCHEMA_VERSION);
    assert_eq!(res["messages_total"], 2);
    assert!(cfg.db_path.exists());

    let runtime_db = cfg.runtime_db_for_path("mailkb_db", &cfg.db_path);
    assert!(runtime_db.exists());

    let conn = open_staged_ro(&runtime_db, DEFAULT_MMAP_BYTES).unwrap();
    let entities: String = conn
        .query_row(
            "SELECT primary_entities FROM mail_messages WHERE rfc_message_id = 'quote1@vendor.example'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(entities.contains("ACME-SW-2400"));
    assert!(entities.contains("NS-ENT-100"));

    let (dir_out, topic): (String, String) = conn
        .query_row(
            "SELECT direction, topic_tags FROM mail_messages WHERE rfc_message_id = 'outbound1@company.example'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(dir_out, "external_outbound");
    assert_eq!(topic, "Project Atlas");

    let terms: String = conn
        .query_row(
            "SELECT terms_json FROM message_amounts WHERE subject_entity = 'ACME-SW-2400' AND unit_amount = 450.0",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(terms.contains("10 pcs"));
    assert!(terms.contains("4 weeks"));

    // Second sync should stat-skip
    let res2 = run_sync(&cfg, &SyncOpts::default()).unwrap();
    assert_eq!(res2["status"], "up_to_date");
    assert_eq!(res2["mode"], "incremental_stat_skip");
}

#[test]
fn sample_domain_pack_apple_mail_sync_incremental_delta_and_mailkbai_sql_compat() {
    let tmp = TempDir::new().unwrap();
    let v10 = tmp.path().join("V10");
    create_fake_apple_mail_v10(&v10);
    let pack_path = tmp.path().join("acme-pack.json");
    write_sample_pack(&pack_path);

    let mut cfg = test_cfg(&tmp);
    cfg.apple_mail_v10_dir = Some(v10.clone());
    cfg.no_packs = false;
    cfg.pack_paths = vec![pack_path.clone()];

    let res = run_sync(&cfg, &SyncOpts::default()).unwrap();
    assert_eq!(res["status"], "ok");
    assert_eq!(res["messages_total"], 3);
    assert!(res["message_amounts_count"].as_i64().unwrap() >= 2);
    assert!(res["domain_lexicon_count"].as_i64().unwrap() >= 5);

    let runtime_db = cfg.runtime_db_for_path("mailkb_db", &cfg.db_path);
    let conn = open_staged_ro(&runtime_db, DEFAULT_MMAP_BYTES).unwrap();

    // Verify custom_dims_json & message_entities & domain_lexicon hit_count
    let custom_dims: String = conn
        .query_row(
            "SELECT custom_dims_json FROM mail_messages WHERE rfc_message_id = 'msg-work-001@northstar.example'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(custom_dims.contains("SOC2"));
    assert!(custom_dims.contains("IEC-62443"));

    let dim_ent_cnt: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM message_entities WHERE entity_type = 'compliance_standard' AND entity_key = 'SOC2'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(dim_ent_cnt, 1);

    let lex_hits: i64 = conn
        .query_row(
            "SELECT hit_count FROM domain_lexicon WHERE dimension = 'organization' AND key = 'Northstar Cloud Inc'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(lex_hits >= 1);

    // Execute ALL 5 exact SQL statements from MailKBAI.app HistoricalPriceLookupService.swift!
    // Statement 1: preparePriceQueryStatement
    {
        let sql1 = r#"
        SELECT
            v.sku,
            v.currency,
            v.unit_price,
            v.quantity,
            v.price_type,
            v.tax_mode,
            v.customer_org,
            v.project_name,
            v.quote_date_iso,
            v.subject,
            m.message_id AS rfc_message_id,
            v.evidence_snippet,
            v.confidence,
            COALESCE(m.thread_topic, '') AS thread_topic,
            v.message_id AS message_row_id
        FROM v_sku_price_history v
        JOIN messages m ON m.id = v.message_id
        WHERE v.unit_price IS NOT NULL
          AND v.unit_price > 0
          AND (UPPER(v.sku) = UPPER(?1) OR UPPER(v.sku) LIKE UPPER(?2) || '%' ESCAPE '\')
        ORDER BY v.quote_date_iso DESC,
                 CASE LOWER(v.confidence) WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                 v.message_id DESC
        LIMIT 400
        "#;
        let mut stmt1 = conn.prepare(sql1).unwrap();
        let rows1: Vec<(String, String, f64, String, String, i64)> = stmt1
            .query_map(["ACME-SW-2400-HV", "ACME-SW"], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(6)?,
                    r.get(10)?,
                    r.get(14)?,
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!rows1.is_empty());
        assert!(rows1.iter().any(|r| r.0 == "ACME-SW-2400-HV" && (r.2 - 450.0).abs() < 0.01));
    }

    // Statement 2: resolveMessageRowIDs
    let resolved_mid: i64 = {
        let sql2 = r#"
        SELECT id
        FROM messages
        WHERE LOWER(TRIM(message_id, '<> ')) = LOWER(?1)
        ORDER BY date_iso DESC, id DESC
        LIMIT ?2
        "#;
        let mut stmt2 = conn.prepare(sql2).unwrap();
        stmt2
            .query_row(rusqlite::params!["msg-work-001@northstar.example", 8], |r| {
                r.get(0)
            })
            .unwrap()
    };
    assert!(resolved_mid > 0);

    // Statement 3: prepareSingleMessageStatement
    {
        let sql3 = r#"
        SELECT
            id,
            source,
            message_id,
            subject,
            sender,
            recipients,
            cc,
            date_iso,
            COALESCE(folder_path, '') AS folder_path,
            project_name,
            customers_orgs,
            COALESCE(main_meaning, '') AS main_meaning,
            body_latest,
            body_quoted
        FROM messages
        WHERE id = ?1
        LIMIT 1
        "#;
        let mut stmt3 = conn.prepare(sql3).unwrap();
        let (id3, proj3, cust3): (i64, String, String) = stmt3
            .query_row([resolved_mid], |r| Ok((r.get(0)?, r.get(9)?, r.get(10)?)))
            .unwrap();
        assert_eq!(id3, resolved_mid);
        assert_eq!(proj3, "Grid Modernization");
        assert!(cust3.contains("Northstar Cloud Inc"));
    }

    // Statement 4: queryPriceEvidences
    {
        let sql4 = r#"
        SELECT
            id,
            sku,
            currency,
            unit_price,
            quantity,
            total_amount,
            price_type,
            tax_mode,
            customer_org,
            project_name,
            source_kind,
            evidence_snippet
        FROM message_prices
        WHERE message_id = ?1
          AND unit_price IS NOT NULL
          AND unit_price > 0
        ORDER BY
            CASE
                WHEN UPPER(sku) = UPPER(?2) THEN 0
                WHEN UPPER(sku) LIKE UPPER(?3) || '%' ESCAPE '\' THEN 1
                ELSE 2
            END,
            id ASC
        LIMIT 24
        "#;
        let mut stmt4 = conn.prepare(sql4).unwrap();
        let count4 = stmt4
            .query_map(
                rusqlite::params![resolved_mid, "ACME-SW-2400-HV", "ACME-SW"],
                |r| r.get::<_, f64>(3),
            )
            .unwrap()
            .count();
        assert!(count4 >= 1);
    }

    // Statement 5: queryEmailAttachments
    {
        let sql5 = r#"
        SELECT
            id,
            filename,
            COALESCE(size_bytes, 0),
            COALESCE(text_preview, '')
        FROM message_attachments_mime
        WHERE message_id = ?1
          AND COALESCE(is_inline, 0) = 0
        ORDER BY id ASC
        LIMIT 16
        "#;
        let mut stmt5 = conn.prepare(sql5).unwrap();
        let atts5: Vec<(i64, String, i64, String)> = stmt5
            .query_map([resolved_mid], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(atts5.len(), 1);
        assert_eq!(atts5[0].1, "acme_quote.xlsx");
        assert!(atts5[0].3.contains("ACME-SW-2400-HV"));

        let total_att_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM message_attachments WHERE message_id = ?1",
                [resolved_mid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total_att_rows, 2);
    }

    // Also verify other compatibility and universal views prepare cleanly
    for view in [
        "v_amount_history",
        "v_topic_overview",
        "v_org_overview",
        "v_timeline_monthly",
        "v_project_overview",
        "v_customer_overview",
        "message_products",
    ] {
        let cnt: i64 = conn
            .query_row(&format!("SELECT COUNT(*) FROM {view}"), [], |r| r.get(0))
            .unwrap();
        assert!(cnt >= 0, "view {view} query failed");
    }

    // Drop staged connection and simulate incremental_delta by inserting a new message into Envelope Index
    drop(conn);
    {
        let env_db = Connection::open(v10.join("MailData/Envelope Index")).unwrap();
        env_db
            .execute_batch(
                r#"
                INSERT INTO subjects (ROWID, subject) VALUES (4, 'Delta update ACME-GW-500');
                INSERT INTO summaries (ROWID, summary) VALUES (4, 'ACME-GW-500 $199');
                INSERT INTO message_global_data (ROWID, message_id_header) VALUES (4, '<msg-delta-004@northstar.example>');
                INSERT INTO messages (ROWID, mailbox, subject, sender, summary, date_sent, date_received, global_message_id, size, deleted)
                    VALUES (4, 1, 4, 2, 4, 1775003000, 1775003000, 4, 1024, 0);
                "#,
            )
            .unwrap();
        let msg4_emlx = v10
            .join("11111111-1111-4111-8111-111111111111")
            .join("INBOX.mbox")
            .join("33333333-3333-4333-8333-333333333333")
            .join("Data/Messages/4.emlx");
        let raw4 = "From: Bob <bob@northstar.example>\r\nSubject: Delta update ACME-GW-500\r\nMessage-ID: <msg-delta-004@northstar.example>\r\nDate: Wed, 01 Apr 2026 11:00:00 +0800\r\n\r\nACME-GW-500 quoted at USD 199.00.\r\n";
        write_emlx_file(&msg4_emlx, raw4.as_bytes());
    }
    let res_delta = run_sync(&cfg, &SyncOpts::default()).unwrap();
    assert_eq!(res_delta["status"], "ok");
    assert_eq!(res_delta["mode"], "incremental_delta");
    assert_eq!(res_delta["messages_total"], 4);

    // Test profile-corpus & test-pack on the published DB (staged ?mode=ro&immutable=1)
    let prof = run_profile_corpus(
        &cfg,
        &ProfileOpts {
            limit: 100,
            from_db: Some(cfg.db_path.clone()),
        },
    )
    .unwrap();
    assert_eq!(prof["status"], "ok");
    assert_eq!(prof["sampled_messages"], 4);
    assert!(prof["accounts"].is_array());
    assert!(prof["inferred_identity"]["self_emails"].is_array());
    assert!(!prof["top_external_domains"].as_array().unwrap().is_empty());
    assert!(!prof["code_token_candidates"].as_array().unwrap().is_empty());
    assert!(!prof["sample_subjects"].as_array().unwrap().is_empty());

    let tpack = run_test_pack(
        &cfg,
        &TestPackOpts {
            pack_path: pack_path.clone(),
            sample: 50,
            from_db: Some(cfg.db_path.clone()),
        },
    )
    .unwrap();
    assert_eq!(tpack["status"], "ok");
    assert_eq!(tpack["sampled"], 4);
    assert!(tpack["entity_hit_rate"].as_f64().unwrap() > 0.5);
    assert!(tpack["dimension_counts"]["compliance"]["SOC2"].as_u64().unwrap() >= 1);
    assert!(tpack["intent_counts"].is_object());
    assert!(tpack["top_entities"].is_array());
}

#[test]
fn legacy_3_0_db_import_migrates_into_universal_schema() {
    let tmp = TempDir::new().unwrap();
    let legacy_db = tmp.path().join("legacy_v3.sqlite");
    {
        let conn = Connection::open(&legacy_db).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                message_id TEXT NOT NULL DEFAULT '',
                subject TEXT NOT NULL,
                sender TEXT NOT NULL DEFAULT '',
                recipients TEXT NOT NULL DEFAULT '',
                cc TEXT NOT NULL DEFAULT '',
                date_iso TEXT NOT NULL DEFAULT '',
                body_latest TEXT NOT NULL,
                body_quoted TEXT NOT NULL DEFAULT '',
                content_hash TEXT NOT NULL UNIQUE,
                folder_path TEXT NOT NULL DEFAULT '',
                completeness TEXT NOT NULL DEFAULT 'full_body',
                uid_key TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE message_attachments_mime (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER NOT NULL,
                uid_key TEXT NOT NULL DEFAULT '',
                filename TEXT NOT NULL DEFAULT '',
                ext TEXT NOT NULL DEFAULT '',
                mime_type TEXT NOT NULL DEFAULT '',
                size_bytes INTEGER NOT NULL DEFAULT 0,
                is_inline INTEGER NOT NULL DEFAULT 0,
                sha256 TEXT NOT NULL DEFAULT '',
                text_preview TEXT NOT NULL DEFAULT ''
            );
            INSERT INTO messages (source, source_ref, message_id, subject, sender, recipients, date_iso, body_latest, content_hash, folder_path, uid_key)
            VALUES ('outlook', 'ol:101', '<leg-101@zenith-rail.example>', 'Grid Modernization Quote ACME-SW-2400-HV', 'rep@zenith-rail.example', 'sales@acme-corp.example', '2025-11-10 09:00:00', 'Please quote ACME-SW-2400-HV at USD 460.00 with SOC 2 compliance.', 'hash-leg-101', 'Inbox', 'leg-101@zenith-rail.example');
            INSERT INTO message_attachments_mime (message_id, uid_key, filename, ext, mime_type, size_bytes, is_inline, sha256, text_preview)
            VALUES (1, 'leg-101@zenith-rail.example', 'bom.xlsx', 'xlsx', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 2048, 0, 'abc123', 'ACME-SW-2400-HV | $460.00');
            "#,
        )
        .unwrap();
    }

    let pack_path = tmp.path().join("acme-pack.json");
    write_sample_pack(&pack_path);

    let mut cfg = test_cfg(&tmp);
    cfg.no_packs = false;
    cfg.pack_paths = vec![pack_path];

    let res = run_sync(
        &cfg,
        &SyncOpts {
            import_legacy_db: Some(legacy_db),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res["status"], "ok");
    assert_eq!(res["mode"], "import_legacy_db");
    assert_eq!(res["messages_total"], 1);

    let runtime_db = cfg.runtime_db_for_path("mailkb_db", &cfg.db_path);
    let conn = open_staged_ro(&runtime_db, DEFAULT_MMAP_BYTES).unwrap();
    let orgs: String = conn
        .query_row("SELECT org_tags FROM mail_messages LIMIT 1", [], |r| r.get(0))
        .unwrap();
    assert_eq!(orgs, "Zenith Rail Systems");
    let amt: f64 = conn
        .query_row(
            "SELECT unit_amount FROM message_amounts WHERE subject_entity = 'ACME-SW-2400-HV' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!((amt - 460.0).abs() < 0.01);
}

#[test]
fn enrich_unit_zero_pack_and_schema_ddl() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(UNIVERSAL_SCHEMA_SQL).unwrap();

    let pack = mailkb_core::CompiledDomainPack::empty();
    let identity = ResolvedIdentity::from_pack_and_inferred(
        &pack,
        &InferredIdentity {
            self_emails: vec!["me@acme.example".to_string()],
            internal_domains: vec!["acme.example".to_string()],
        },
    );
    let raw = RawMessageInput {
        uid_key: "u1".to_string(),
        account_id: "a1".to_string(),
        source: "eml".to_string(),
        source_ref: "q.eml".to_string(),
        rfc_message_id: "u1".to_string(),
        subject: "Quote [Alpha Launch] WIDGET-900X".to_string(),
        sender: "vendor@partner.example".to_string(),
        recipients: "me@acme.example".to_string(),
        date_iso: "2026-04-01 12:00:00".to_string(),
        folder_path: "INBOX".to_string(),
        completeness: "full_body".to_string(),
        body_latest: "WIDGET-900X unit price is EUR 120.50 excl. tax.".to_string(),
        ..Default::default()
    };
    let em = enrich_message(&raw, &pack, &identity);
    assert_eq!(em.direction, "external_inbound");
    assert_eq!(em.topic_tags, "Alpha Launch");
    assert_eq!(em.org_tags, "partner.example");
    assert_eq!(em.primary_entities, "WIDGET-900X");
    assert_eq!(em.has_amount, 1);
    assert_eq!(em.amounts[0].currency, "EUR");
}

#[test]
fn crate_has_zero_pii_or_private_employer_literals() {
    // Construct forbidden tokens dynamically so this test contains no literal matches.
    let forbidden: Vec<String> = vec![
        format!("{}{}", "mo", "xa"),
        format!("{}{}", "bao", "shan"),
        format!("{}{}", "王", "宝山"),
        format!("{}{}", "exchange", "labs"),
        format!("{}{}", "ge", "dcc"),
        format!("{}{}", "/Users/", "bao3"),
    ];

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut stack = vec![manifest_dir];
    while let Some(dir) = stack.pop() {
        for ent in fs::read_dir(&dir).unwrap().flatten() {
            let p = ent.path();
            if p.is_dir() {
                if p.file_name().and_then(|s| s.to_str()) != Some("target") {
                    stack.push(p);
                }
            } else if matches!(
                p.extension().and_then(|s| s.to_str()),
                Some("rs" | "toml" | "json")
            ) {
                let text = fs::read_to_string(&p).unwrap().to_ascii_lowercase();
                for bad in &forbidden {
                    assert!(
                        !text.contains(&bad.to_ascii_lowercase()),
                        "forbidden private literal '{}' found in {}",
                        bad,
                        p.display()
                    );
                }
            }
        }
    }
}

#[test]
fn sync_limit_s9_guard_fts_and_direct_eml_profile_test_pack() {
    let tmp = TempDir::new().unwrap();
    let eml_dir = tmp.path().join("emls");
    fs::create_dir_all(&eml_dir).unwrap();

    fs::write(
        eml_dir.join("cjk_quote.eml"),
        concat!(
            "From: Sales <sales@northstar.example>\r\n",
            "To: Buyer <buyer@acme-corp.example>\r\n",
            "Subject: 智能电网改造 ACME-SW-2400 报价单\r\n",
            "Message-ID: <cjk1@northstar.example>\r\n",
            "Date: Fri, 03 Apr 2026 09:00:00 +0800\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<p>智能电网改造项目报价：</p><table><tr><th>Model</th><th>Unit Price (USD)</th></tr><tr><td>ACME-SW-2400</td><td>$495.00</td></tr></table>\r\n"
        ),
    )
    .unwrap();
    fs::write(
        eml_dir.join("older.eml"),
        concat!(
            "From: Bob <bob@northstar.example>\r\n",
            "Subject: Follow-up ACME-GW-300\r\n",
            "Message-ID: <old1@northstar.example>\r\n",
            "Date: Thu, 02 Apr 2026 09:00:00 +0800\r\n",
            "\r\n",
            "Check ACME-GW-300 pricing USD 210.00.\r\n"
        ),
    )
    .unwrap();

    let pack_path = tmp.path().join("acme-pack.json");
    write_sample_pack(&pack_path);

    let mut cfg = test_cfg(&tmp);
    cfg.eml_dirs = vec![eml_dir];
    cfg.no_packs = false;
    cfg.pack_paths = vec![pack_path.clone()];

    // S9 guard: refusing to write db inside apple_mail_v10_dir
    let mut bad_cfg = cfg.clone();
    let v10_fake = tmp.path().join("FakeV10");
    fs::create_dir_all(&v10_fake).unwrap();
    bad_cfg.apple_mail_v10_dir = Some(v10_fake.clone());
    bad_cfg.db_path = v10_fake.join("mailkb_db.sqlite");
    let err = run_sync(&bad_cfg, &SyncOpts::default()).unwrap_err();
    assert_eq!(err.exit_code(), 2);
    assert!(err.is_mail_container_violation());

    // Direct profile-corpus over --eml-dir
    let prof = run_profile_corpus(
        &cfg,
        &ProfileOpts {
            limit: 50,
            from_db: None,
        },
    )
    .unwrap();
    assert_eq!(prof["sampled_messages"], 2);
    let hdrs = prof["table_headers_and_currencies"]["table_headers"]
        .as_array()
        .unwrap();
    assert!(hdrs.iter().any(|h| h["header"] == "Unit Price (USD)"));

    // Direct test-pack over --eml-dir
    let tpack = run_test_pack(
        &cfg,
        &TestPackOpts {
            pack_path,
            sample: 50,
            from_db: None,
        },
    )
    .unwrap();
    assert_eq!(tpack["sampled"], 2);
    assert_eq!(tpack["entity_hits"], 2);

    // Sync with limit = 1 (picks newest message first)
    let res_lim = run_sync(
        &cfg,
        &SyncOpts {
            limit: Some(1),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res_lim["messages_total"], 1);

    // Sync full (2 messages) and verify CJK bigram FTS5 queries
    let res_full = run_sync(
        &cfg,
        &SyncOpts {
            full: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(res_full["messages_total"], 2);

    let runtime_db = cfg.runtime_db_for_path("mailkb_db", &cfg.db_path);
    let conn = open_staged_ro(&runtime_db, DEFAULT_MMAP_BYTES).unwrap();
    let (fts_q, _) = mailkb_core::fts::build_cjk_bigram_fts_query(&["智能电网"]);
    let hits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages_fts WHERE messages_fts MATCH ?1",
            [&fts_q],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(hits, 1);

    let dim_hits: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM dimensions_fts WHERE dimensions_fts MATCH 'acme'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(dim_hits, 2);
}
