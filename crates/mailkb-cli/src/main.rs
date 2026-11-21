//! `mailkb_db` CLI entrypoint and command dispatcher.

pub mod cli;

use crate::cli::{
    apply_global_opts, build_amount_opts, build_att_opts, build_entity_opts, build_org_opts,
    build_profile_opts, build_read_opts, build_search_opts, build_sync_opts, build_test_pack_opts,
    build_timeline_opts, build_topic_opts, expand_path, Cli, Commands, GlobalOpts,
};
use clap::Parser;
use mailkb_core::config::MailKbConfig;
use mailkb_core::domain_pack::{validate_pack_file, PackValidationReport};
use mailkb_core::error::{KbError, KbResult};
use mailkb_core::publish::write_text_atomic;
use mailkb_core::security::{assert_safe_out_path, term_safe, trunc_chars};
use mailkb_query::{
    render, run_amounts, run_att, run_audit, run_entities, run_orgs, run_read, run_search,
    run_selftest, run_stats, run_timeline, run_topics, AutoSyncCallback,
};
use mailkb_sync::{run_profile_corpus, run_sync, run_test_pack, SyncOpts};
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::process;

fn main() {
    // Restore standard Unix SIGPIPE behavior so piping to `head` never panics.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let raw_args: Vec<String> = std::env::args().collect();
    let json_hint = raw_args.iter().any(|a| a == "--json");

    let parsed = match Cli::try_parse_from(&raw_args) {
        Ok(c) => c,
        Err(e) => {
            if !e.use_stderr() {
                e.exit();
            }
            if json_hint {
                let err = KbError::InvalidArgument(e.to_string());
                let body = serde_json::to_string_pretty(&err.to_json_value(&[]))
                    .unwrap_or_else(|_| "{\"status\":\"error\",\"exit_code\":2}".to_string());
                println!("{body}");
                process::exit(err.exit_code());
            }
            e.exit();
        }
    };

    let base_cfg = MailKbConfig::discover();
    let (code, stdout, stderr) = execute(parsed, &base_cfg);
    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }
    process::exit(code);
}

/// Executes a parsed `Cli` command against `base_cfg`, returning `(exit_code, stdout, stderr)`.
pub fn execute(cli: Cli, base_cfg: &MailKbConfig) -> (i32, String, String) {
    let cfg = apply_global_opts(base_cfg, &cli.global);

    match dispatch(&cfg, &cli.command, &cli.global) {
        Ok((code, out)) => (code, out, String::new()),
        Err(err) => {
            let code = err.exit_code();
            if cli.global.json {
                let body = serde_json::to_string_pretty(&err.to_json_value(&[]))
                    .unwrap_or_else(|_| "{\"status\":\"error\"}".to_string());
                (code, format!("{body}\n"), String::new())
            } else {
                (
                    code,
                    String::new(),
                    format!("[mailkb_db error] {}\n", term_safe(&err.to_string(), false)),
                )
            }
        }
    }
}

fn format_output(val: &Value, json_mode: bool, quiet: bool, human: impl FnOnce(&Value) -> String) -> String {
    if json_mode {
        let s = serde_json::to_string_pretty(val).unwrap_or_else(|_| "{}".to_string());
        format!("{s}\n")
    } else if quiet {
        String::new()
    } else {
        human(val)
    }
}

fn dispatch(
    cfg: &MailKbConfig,
    cmd: &Commands,
    global: &GlobalOpts,
) -> KbResult<(i32, String)> {
    let json_mode = global.json;
    let quiet = global.quiet;
    match cmd {
        Commands::Sync(args) => {
            let opts = build_sync_opts(args);
            let val = run_sync(cfg, &opts)?;
            let code = if val.get("status").and_then(Value::as_str) == Some("error") {
                4
            } else {
                0
            };
            Ok((code, format_output(&val, json_mode, quiet, render_sync)))
        }
        Commands::Search(args) => {
            let opts = build_search_opts(args, global)?;
            let auto_sync_cb = |sync_cfg: &MailKbConfig| -> KbResult<()> {
                let _ = run_sync(sync_cfg, &SyncOpts::default())?;
                Ok(())
            };
            let cb: Option<AutoSyncCallback<'_>> = opts.auto_sync.then_some(&auto_sync_cb as AutoSyncCallback<'_>);
            let val = run_search(cfg, &opts, cb)?;
            Ok((0, format_output(&val, json_mode, quiet, render::render_search)))
        }
        Commands::Read(args) => {
            let opts = build_read_opts(args);
            let val = run_read(cfg, &opts)?;
            Ok((
                0,
                format_output(&val, json_mode, quiet, |v| render::render_read(v, opts.full)),
            ))
        }
        Commands::Entities(args) => {
            let opts = build_entity_opts(args)?;
            let val = run_entities(cfg, &opts)?;
            Ok((0, format_output(&val, json_mode, quiet, render::render_entities)))
        }
        Commands::Amounts(args) => {
            let opts = build_amount_opts(args);
            let val = run_amounts(cfg, &opts)?;
            Ok((0, format_output(&val, json_mode, quiet, render::render_amounts)))
        }
        Commands::Topics(args) => {
            let opts = build_topic_opts(args)?;
            let val = run_topics(cfg, &opts)?;
            Ok((0, format_output(&val, json_mode, quiet, render::render_topics)))
        }
        Commands::Orgs(args) => {
            let opts = build_org_opts(args)?;
            let val = run_orgs(cfg, &opts)?;
            Ok((0, format_output(&val, json_mode, quiet, render::render_orgs)))
        }
        Commands::Timeline(args) => {
            let opts = build_timeline_opts(args);
            let val = run_timeline(cfg, &opts)?;
            Ok((0, format_output(&val, json_mode, quiet, render::render_timeline)))
        }
        Commands::Att(args) => {
            let opts = build_att_opts(args);
            let val = run_att(cfg, &opts)?;
            Ok((0, format_output(&val, json_mode, quiet, render::render_att)))
        }
        Commands::Stats => {
            let val = run_stats(cfg)?;
            Ok((0, format_output(&val, json_mode, quiet, render::render_stats)))
        }
        Commands::Audit => {
            let val = run_audit(cfg)?;
            let code = if val.get("status").and_then(Value::as_str) == Some("error") {
                4
            } else {
                0
            };
            Ok((code, format_output(&val, json_mode, quiet, render::render_audit)))
        }
        Commands::ProfileCorpus(args) => {
            let out_path_opt = args.out.as_deref().map(expand_path);
            if let Some(ref out_path) = out_path_opt {
                assert_safe_out_path(cfg, out_path)?;
                if out_path.is_dir() {
                    return Err(KbError::InvalidArgument(format!(
                        "--out target is a directory: {}",
                        out_path.display()
                    )));
                }
            }
            let opts = build_profile_opts(args);
            let val = run_profile_corpus(cfg, &opts)?;
            if let Some(ref out_path) = out_path_opt {
                let pretty = serde_json::to_string_pretty(&val)?;
                write_text_atomic(out_path, &format!("{pretty}\n"), 0o600)?;
                if quiet {
                    return Ok((0, String::new()));
                }
                if json_mode {
                    return Ok((0, format!("{pretty}\n")));
                }
                return Ok((
                    0,
                    format!(
                        "[mailkb profile-corpus] wrote {}\n",
                        term_safe(&out_path.to_string_lossy(), true)
                    ),
                ));
            }
            Ok((
                0,
                format_output(&val, json_mode, quiet, render_profile_corpus),
            ))
        }
        Commands::ValidatePack(args) => {
            let p = expand_path(&args.pack_json);
            let report = validate_pack_file(&p)?;
            let val = serde_json::to_value(&report)?;
            let code = if report.valid { 0 } else { 2 };
            Ok((
                code,
                format_output(&val, json_mode, quiet, |_| render_validate_pack(&report)),
            ))
        }
        Commands::TestPack(args) => {
            let opts = build_test_pack_opts(args);
            let val = run_test_pack(cfg, &opts)?;
            Ok((
                0,
                format_output(&val, json_mode, quiet, render_test_pack),
            ))
        }
        Commands::Selftest(args) => {
            let sample = args.pack_sample.as_deref().map(expand_path);
            let val = run_selftest(cfg, sample.as_deref())?;
            let code = if val.get("status").and_then(Value::as_str) == Some("ok") {
                0
            } else {
                4
            };
            Ok((code, format_output(&val, json_mode, quiet, render::render_selftest)))
        }
    }
}

fn render_sync(v: &Value) -> String {
    let status = v.get("status").and_then(Value::as_str).unwrap_or("ok");
    let mut out = String::new();
    let _ = writeln!(out, "[mailkb sync] status={}", term_safe(status, true));
    if let Some(obj) = v.as_object() {
        for (k, val) in obj {
            if k == "status" {
                continue;
            }
            if val.is_string() || val.is_number() || val.is_boolean() {
                let s = match val {
                    Value::String(s) => s.clone(),
                    _ => val.to_string(),
                };
                let _ = writeln!(out, "  {k}: {}", trunc_chars(&s, 140));
            }
        }
    }
    out
}

fn render_profile_corpus(v: &Value) -> String {
    let pretty = serde_json::to_string_pretty(v).unwrap_or_else(|_| json!({}).to_string());
    format!("{}\n", term_safe(&pretty, false))
}

fn render_validate_pack(r: &PackValidationReport) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "[mailkb validate-pack] valid={} pack_id={} version={} patterns={} dims={} orgs={} topics={} intents={} sha256={} warnings={}",
        r.valid,
        term_safe(&r.pack_id, true),
        term_safe(&r.version, true),
        r.pattern_count,
        r.dimension_count,
        r.organization_count,
        r.topic_count,
        r.intent_count,
        &r.sha256[..r.sha256.len().min(12)],
        r.warnings.len()
    );
    for w in &r.warnings {
        let _ = writeln!(out, "  warning: {}", term_safe(w, true));
    }
    out
}

fn render_test_pack(v: &Value) -> String {
    let mut out = String::new();
    let sampled = v.get("sampled").and_then(Value::as_i64).unwrap_or(0);
    let _ = writeln!(out, "[mailkb test-pack] sampled={sampled}");
    for key in [
        "entity_hit_rate",
        "org_hit_rate",
        "topic_hit_rate",
        "amount_hit_rate",
    ] {
        if let Some(val) = v.get(key) {
            let _ = writeln!(out, "  {key}: {val}");
        }
    }
    if let Some(obj) = v.get("intent_counts").and_then(Value::as_object) {
        if !obj.is_empty() {
            out.push_str("  intents:");
            for (k, c) in obj {
                let _ = write!(out, " {}={}", term_safe(k, true), c);
            }
            out.push('\n');
        }
    }
    if let Some(obj) = v.get("dimension_counts").and_then(Value::as_object) {
        if !obj.is_empty() {
            out.push_str("  dimensions:");
            for (k, c) in obj {
                let _ = write!(out, " {}={}", term_safe(k, true), c);
            }
            out.push('\n');
        }
    }
    if let Some(warnings) = v.get("warnings").and_then(Value::as_array) {
        for w in warnings {
            if let Some(s) = w.as_str() {
                let _ = writeln!(out, "  warning: {}", term_safe(s, true));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn validate_pack_success_and_hazard_exit_code_2() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = MailKbConfig::discover()
            .with_db_dir_override(&tmp.path().join("db"))
            .with_runtime_dir_override(&tmp.path().join("rt"));

        let good = tmp.path().join("good.json");
        fs::write(
            &good,
            r#"{
              "schema_version": "domain-pack.v1",
              "pack_id": "acme-test",
              "entity_rules": {
                "code_patterns": [
                  { "name": "sw", "pattern": "\\bACME-[A-Z]{2}-\\d{4}\\b", "category": "Switch" }
                ]
              }
            }"#,
        )
        .unwrap();

        let cli_ok = Cli::try_parse_from([
            "mailkb_db",
            "--json",
            "validate-pack",
            good.to_str().unwrap(),
        ])
        .unwrap();
        let (code, out, err) = execute(cli_ok, &cfg);
        assert_eq!(code, 0, "stderr={err}");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["valid"], true);
        assert_eq!(v["pack_id"], "acme-test");

        let bad = tmp.path().join("bad.json");
        fs::write(
            &bad,
            r#"{
              "schema_version": "domain-pack.v1",
              "pack_id": "bad-test",
              "entity_rules": {
                "code_patterns": [
                  { "name": "hazard", "pattern": "^\\d+$", "category": "Switch" }
                ]
              }
            }"#,
        )
        .unwrap();

        let cli_bad = Cli::try_parse_from([
            "mailkb_db",
            "--json",
            "validate-pack",
            bad.to_str().unwrap(),
        ])
        .unwrap();
        let (code_bad, out_bad, _) = execute(cli_bad, &cfg);
        assert_eq!(code_bad, 2);
        let vb: Value = serde_json::from_str(&out_bad).unwrap();
        assert_eq!(vb["status"], "error");
        assert_eq!(vb["exit_code"], 2);
    }

    #[test]
    fn profile_corpus_out_blocks_db_dir_and_mail_container() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");
        fs::create_dir_all(&db_dir).unwrap();
        let cfg = MailKbConfig::discover()
            .with_db_dir_override(&db_dir)
            .with_runtime_dir_override(&tmp.path().join("rt"));

        let inside_db = db_dir.join("leak.json");
        let cli = Cli::try_parse_from([
            "mailkb_db",
            "--json",
            "profile-corpus",
            "--out",
            inside_db.to_str().unwrap(),
        ])
        .unwrap();
        let (code, out, _) = execute(cli, &cfg);
        assert_eq!(code, 2);
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["exit_code"], 2);

        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let inside_mail = format!("{home}/Library/Mail/V10/leak.json");
        let cli_mail = Cli::try_parse_from([
            "mailkb_db",
            "profile-corpus",
            "--out",
            &inside_mail,
        ])
        .unwrap();
        let (code_m, _, err_m) = execute(cli_mail, &cfg);
        assert_eq!(code_m, 2);
        assert!(err_m.contains("refusing_mail_container_violation"));
    }

    #[test]
    fn selftest_and_audit_run_cleanly_via_cli() {
        let tmp = tempfile::tempdir().unwrap();
        let mut cfg = MailKbConfig::discover()
            .with_db_dir_override(&tmp.path().join("db"))
            .with_runtime_dir_override(&tmp.path().join("rt"));
        cfg.apple_mail_v10_dir = None;

        let cli_st = Cli::try_parse_from(["mailkb_db", "--json", "selftest"]).unwrap();
        let (code, out, err) = execute(cli_st, &cfg);
        assert_eq!(code, 0, "stderr={err}");
        let v: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["status"], "ok");

        let cli_au = Cli::try_parse_from(["mailkb_db", "--json", "audit"]).unwrap();
        let (code_a, out_a, err_a) = execute(cli_au, &cfg);
        assert_eq!(code_a, 0, "stderr={err_a}");
        let va: Value = serde_json::from_str(&out_a).unwrap();
        assert!(matches!(va["status"].as_str(), Some("ok" | "warn")));

        // Missing DB maps NotFound to exit code 4 cleanly in both JSON & human modes
        let cli_missing = Cli::try_parse_from(["mailkb_db", "--json", "stats"]).unwrap();
        let (code_m, out_m, _) = execute(cli_missing, &cfg);
        assert_eq!(code_m, 4);
        let vm: Value = serde_json::from_str(&out_m).unwrap();
        assert_eq!(vm["status"], "error");
        assert_eq!(vm["exit_code"], 4);
    }
}
