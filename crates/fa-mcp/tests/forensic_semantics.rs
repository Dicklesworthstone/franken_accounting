//! fa-v0m2: MCP and CLI agree byte-for-byte on party attribution, balance-sheet
//! contra-asset and explicit valuation solvency, cash-flow maturity-schedule
//! solvency, retained findings/workpaper replay, and parameter/scope/authority
//! refusals (without mutating guarded book state on refusal).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::LaunchProfile;
use fa_cli::json::{self, Json};
use fa_mcp::server::{Adapter, ServerConfig};
use fastmcp_rust::{JsonValue, json};

fn tmp_dir(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let dir = std::env::temp_dir().join(format!(
            "fa-mcp-forensic-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        if std::fs::create_dir(&dir).is_ok() {
            return dir;
        }
    }
}

fn write_file(dir: &Path, name: &str, content: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path.display().to_string()
}

fn run_cli(book: &Path, argv: &[&str]) -> (u8, Json) {
    let mut full: Vec<String> = argv.iter().map(|s| (*s).into()).collect();
    full.extend([
        "--book".into(),
        book.display().to_string(),
        "--json".into(),
        "--via".into(),
        "direct".into(),
    ]);
    let (exit, captured) = fa_cli::entry::fa_with(&full, fa_cli::cli::Files::default(), true);
    let line = json::parse(captured.stdout.trim_end()).expect("robot line");
    (exit, line)
}

fn cli_ok_data(book: &Path, argv: &[&str]) -> String {
    let (exit, line) = run_cli(book, argv);
    assert_eq!(exit, 0, "{argv:?}: {}", line.render());
    line.get("data").expect("data").render()
}

fn frontier(book: &Path) -> i128 {
    let info = json::parse(&cli_ok_data(book, &["book", "info"])).unwrap();
    match info
        .get("coordinate")
        .and_then(|c| c.get("known_at"))
        .expect("known_at")
    {
        Json::Int(n) => *n,
        other => panic!("expected integer known_at, got {other:?}"),
    }
}

fn make_adapter(book: &Path, grants: &[&str]) -> Adapter {
    Adapter::new(ServerConfig {
        book: Some(book.to_path_buf()),
        principal: "cpa-local".into(),
        profile: LaunchProfile::Human,
        grants: grants.iter().map(|g| (*g).into()).collect(),
        clusters: vec!["fa.findings".into()],
        ..ServerConfig::default()
    })
    .expect("adapter")
}

fn mcp_ok(adapter: &Adapter, wire: &str, args: &JsonValue) -> String {
    let tool = adapter.mcp.tool_by_wire(wire).expect(wire);
    adapter
        .call(tool, args)
        .unwrap_or_else(|e| panic!("{wire} {args}: {e:?}"))
        .data
}

#[test]
fn solvency_inputs_and_refusals_match_cli() {
    let dir = tmp_dir("solvency-parity");
    let book = dir.join("book");
    cli_ok_data(&book, &["book", "create", "--name", "MCP Forensic Parity"]);

    let chart = write_file(
        &dir,
        "chart.json",
        r#"{"accounts":[
{"code":"1000","name":"Operating cash","type":"Asset","unit":"USD","roles":["cash"]},
{"code":"1510","name":"Equipment","type":"Asset","unit":"USD"},
{"code":"1590","name":"Accumulated depreciation","type":"Asset","normal_balance":"credit","unit":"USD"},
{"code":"2000","name":"Accounts payable","type":"Liability","unit":"USD"},
{"code":"3000","name":"Investor capital","type":"Equity","unit":"USD"},
{"code":"6000","name":"Rent","type":"Expense","unit":"USD"},
{"code":"7000","name":"Utilities","type":"Expense","unit":"USD"}]}"#,
    );
    cli_ok_data(&book, &["chart", "import", &chart]);
    cli_ok_data(&book, &["period", "create", "--fiscal-year", "2026"]);
    for period in ["FY2026-P01", "FY2026-P02", "FY2026-P03", "FY2026-P04"] {
        cli_ok_data(&book, &["period", "open", period]);
    }
    let src = write_file(&dir, "support.txt", "Forensic parity support document.");
    let doc_added = json::parse(&cli_ok_data(
        &book,
        &[
            "document",
            "add",
            &src,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ],
    ))
    .unwrap();
    let evidence = doc_added
        .get("oid")
        .and_then(Json::as_str)
        .unwrap()
        .to_string();

    for (code, kind) in [
        ("VEND-A", "Vendor"),
        ("VEND-B", "Vendor"),
        ("INV-A", "Counterparty"),
        ("INV-B", "Counterparty"),
    ] {
        let p = write_file(
            &dir,
            &format!("{code}.json"),
            &format!(r#"{{"code":"{code}","kind":"{kind}","name":"{code}"}}"#),
        );
        cli_ok_data(&book, &["party", "add", &p]);
    }

    // 1. Post batched investor subscriptions (100/200) and vendor bills/payments (100/200)
    // plus long-term vs inside-horizon scheduled AP obligations.
    let sub_intent = write_file(
        &dir,
        "subs.json",
        r#"{"effective_date":"2026-01-10","idempotency_key":"subs","legs":[
{"side":"debit","account":"1000","amount":"400.00 USD"},
{"side":"debit","account":"6000","amount":"900.00 USD"},
{"side":"credit","account":"3000","amount":"100.00 USD","party":"INV-A"},
{"side":"credit","account":"3000","amount":"200.00 USD","party":"INV-B"},
{"side":"credit","account":"2000","amount":"1000.00 USD"}
],"obligation_maturity":[{"ordinal":4,"status":"contractual","installments":[{"due_date":"2026-12-31","amount":"1000.00 USD"}]}]}"#,
    );
    cli_ok_data(
        &book,
        &["post", "--intent", &sub_intent, "--evidence", &evidence],
    );

    for (key, date, acct, party, amt) in [
        ("bill-a", "2026-02-01", "6000", "VEND-A", "100.00 USD"),
        ("bill-b", "2026-02-20", "7000", "VEND-B", "200.00 USD"),
    ] {
        let f = write_file(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[
{{"side":"debit","account":"{acct}","amount":"{amt}","party":"{party}"}},
{{"side":"credit","account":"2000","amount":"{amt}","party":"{party}"}}
]}}"#
            ),
        );
        cli_ok_data(&book, &["post", "--intent", &f, "--evidence", &evidence]);
    }

    let pay_intent = write_file(
        &dir,
        "pay-ab.json",
        r#"{"effective_date":"2026-04-15","idempotency_key":"pay-ab","legs":[
{"side":"debit","account":"2000","amount":"100.00 USD","party":"VEND-A"},
{"side":"debit","account":"2000","amount":"200.00 USD","party":"VEND-B"},
{"side":"credit","account":"1000","amount":"300.00 USD"}
]}"#,
    );
    cli_ok_data(
        &book,
        &["post", "--intent", &pay_intent, "--evidence", &evidence],
    );

    // Remaining cash at 2026-04-30 is 400 - 300 = 100.00 USD.
    // Add short-term scheduled obligations: 40.00 due May 15, 35.00 due May 30, 50.00 due May 31.
    for (key, due, amt) in [
        ("ob-may15", "2026-05-15", "40.00 USD"),
        ("ob-may30", "2026-05-30", "35.00 USD"),
        ("ob-may31", "2026-05-31", "50.00 USD"),
    ] {
        let f = write_file(
            &dir,
            &format!("{key}.json"),
            &format!(
                r#"{{"effective_date":"2026-04-18","idempotency_key":"{key}","legs":[
{{"side":"debit","account":"6000","amount":"{amt}"}},
{{"side":"credit","account":"2000","amount":"{amt}"}}
],"obligation_maturity":[{{"ordinal":1,"status":"contractual","installments":[{{"due_date":"{due}","amount":"{amt}"}}]}}]}}"#
            ),
        );
        cli_ok_data(&book, &["post", "--intent", &f, "--evidence", &evidence]);
    }

    let adapter = make_adapter(&book, &["read", "produce"]);

    // Verify CLI and MCP byte-for-byte parity on lookback.preferences, ponzi.net_investment,
    // distribution.pro_rata, solvency.cash_flow_test (30d and 31d), and solvency.balance_sheet_test.
    for (cli_args, mcp_args) in [
        (
            vec![
                "procedure",
                "run",
                "lookback.preferences",
                "--effective-through",
                "2026-04-30",
            ],
            json!({
                "action": "run",
                "id": "lookback.preferences",
                "effective_through": "2026-04-30"
            }),
        ),
        (
            vec!["procedure", "run", "ponzi.net_investment"],
            json!({
                "action": "run",
                "id": "ponzi.net_investment"
            }),
        ),
        (
            vec![
                "procedure",
                "run",
                "distribution.pro_rata",
                "--param",
                "distributable_pool=9000",
            ],
            json!({
                "action": "run",
                "id": "distribution.pro_rata",
                "param": ["distributable_pool=9000"]
            }),
        ),
        (
            vec![
                "procedure",
                "run",
                "solvency.cash_flow_test",
                "--effective-through",
                "2026-04-30",
                "--param",
                "horizon_days=30",
            ],
            json!({
                "action": "run",
                "id": "solvency.cash_flow_test",
                "effective_through": "2026-04-30",
                "param": ["horizon_days=30"]
            }),
        ),
        (
            vec![
                "procedure",
                "run",
                "solvency.cash_flow_test",
                "--effective-through",
                "2026-04-30",
                "--param",
                "horizon_days=31",
            ],
            json!({
                "action": "run",
                "id": "solvency.cash_flow_test",
                "effective_through": "2026-04-30",
                "param": ["horizon_days=31"]
            }),
        ),
    ] {
        let cli_data = cli_ok_data(&book, &cli_args);
        let mcp_data = mcp_ok(&adapter, "fa_forensics_procedure", &mcp_args);
        assert_eq!(mcp_data, cli_data, "mismatch on {cli_args:?}");
    }

    // Record and export/replay cash-flow solvency findings through MCP (`fa_findings_record`,
    // `fa_findings_list`, `fa_findings_export`, `fa_findings_replay`).
    let rec_str = mcp_ok(
        &adapter,
        "fa_findings_record",
        &json!({
            "procedure": "solvency.cash_flow_test",
            "effective_through": "2026-04-30",
            "param": ["horizon_days=31"]
        }),
    );
    let rec_json = json::parse(&rec_str).unwrap();
    let cert = rec_json
        .get("certificate")
        .and_then(Json::as_str)
        .unwrap()
        .to_string();
    let cert_ref = format!("C:{cert}");

    let cli_list = cli_ok_data(&book, &["finding", "list", "--certificate", &cert_ref]);
    let mcp_list = mcp_ok(
        &adapter,
        "fa_findings_list",
        &json!({"certificate": cert_ref}),
    );
    assert_eq!(mcp_list, cli_list);

    let exported = json::parse(&mcp_ok(
        &adapter,
        "fa_findings_export",
        &json!({"certificate": cert_ref, "export_format": "canonical"}),
    ))
    .unwrap();
    let bytes_hex = exported
        .get("bytes_hex")
        .and_then(Json::as_str)
        .unwrap()
        .to_string();
    let replayed = json::parse(&mcp_ok(
        &adapter,
        "fa_findings_replay",
        &json!({"workpaper": bytes_hex}),
    ))
    .unwrap();
    assert_eq!(
        replayed.get("verified"),
        Some(&Json::Bool(true)),
        "{}",
        replayed.render()
    );

    // 2. Refusal parity and non-mutation of book state on invalid inputs:
    let head_before = frontier(&book);

    // (a) Invalid parameter `horizon_days=0` is refused by both CLI and MCP without mutating `known_at`.
    let (cli_exit, cli_err_line) = run_cli(
        &book,
        &[
            "procedure",
            "run",
            "solvency.cash_flow_test",
            "--effective-through",
            "2026-04-30",
            "--param",
            "horizon_days=0",
        ],
    );
    assert_ne!(cli_exit, 0, "{}", cli_err_line.render());
    let proc_tool = adapter
        .mcp
        .tool_by_wire("fa_forensics_procedure")
        .expect("procedure tool");
    let mcp_err = adapter
        .call(
            proc_tool,
            &json!({
                "action": "run",
                "id": "solvency.cash_flow_test",
                "effective_through": "2026-04-30",
                "param": ["horizon_days=0"]
            }),
        )
        .expect_err("horizon_days=0 must refuse");
    assert_eq!(i128::from(mcp_err.exit), i128::from(cli_exit));
    assert_eq!(frontier(&book), head_before);

    // (b) Unauthorized MCP session (read-only adapter without `produce`) refuses `fa_findings_record`
    // before mutating the book.
    let ro_adapter = make_adapter(&book, &["read"]);
    let rec_tool = ro_adapter
        .mcp
        .tool_by_wire("fa_findings_record")
        .expect("record tool");
    let auth_err = ro_adapter
        .call(
            rec_tool,
            &json!({
                "procedure": "solvency.cash_flow_test",
                "effective_through": "2026-04-30",
                "param": ["horizon_days=31"]
            }),
        )
        .expect_err("read-only adapter must refuse finding record");
    assert_eq!(auth_err.exit, 3);
    assert_eq!(frontier(&book), head_before);

    // (c) Balance-sheet solvency with contra-assets, explicit valuation input, and stale valuation refusal:
    let bs_dir = tmp_dir("bs-mcp-parity");
    let bs_book = bs_dir.join("book");
    cli_ok_data(&bs_book, &["book", "create", "--name", "BS MCP Parity"]);
    cli_ok_data(&bs_book, &["chart", "import", &chart]);
    cli_ok_data(&bs_book, &["period", "create", "--fiscal-year", "2026"]);
    cli_ok_data(&bs_book, &["period", "open", "FY2026-P04"]);
    let bs_doc = json::parse(&cli_ok_data(
        &bs_book,
        &[
            "document",
            "add",
            &src,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
        ],
    ))
    .unwrap();
    let bs_ev = bs_doc
        .get("oid")
        .and_then(Json::as_str)
        .unwrap()
        .to_string();

    for (key, date, legs_json) in [
        (
            "bs-fund",
            "2026-04-01",
            r#"[{"side":"debit","account":"1510","amount":"100.00 USD"},{"side":"credit","account":"2000","amount":"50.00 USD"},{"side":"credit","account":"3000","amount":"50.00 USD"}]"#,
        ),
        (
            "bs-dep",
            "2026-04-15",
            r#"[{"side":"debit","account":"6000","amount":"80.00 USD"},{"side":"credit","account":"1590","amount":"80.00 USD"}]"#,
        ),
    ] {
        let f = write_file(
            &bs_dir,
            &format!("{key}.json"),
            &format!(r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":{legs_json}}}"#),
        );
        cli_ok_data(&bs_book, &["post", "--intent", &f, "--evidence", &bs_ev]);
    }

    let bs_adapter = make_adapter(&bs_book, &["read", "produce"]);
    let cli_bs = cli_ok_data(
        &bs_book,
        &[
            "procedure",
            "run",
            "solvency.balance_sheet_test",
            "--effective-through",
            "2026-04-30",
        ],
    );
    let mcp_bs = mcp_ok(
        &bs_adapter,
        "fa_forensics_procedure",
        &json!({
            "action": "run",
            "id": "solvency.balance_sheet_test",
            "effective_through": "2026-04-30"
        }),
    );
    assert_eq!(mcp_bs, cli_bs);

    // Post an entry with an ExactAsOf valuation for 2026-04-20; running at 2026-04-20 succeeds
    // and matches CLI, whereas running at 2026-04-30 refuses the stale ExactAsOf valuation on
    // both CLI and MCP without mutating the book!
    let val_f = write_file(
        &bs_dir,
        "bs-val.json",
        r#"{"effective_date":"2026-04-20","idempotency_key":"bs-val","legs":[
{"side":"debit","account":"6000","amount":"1.00 USD"},
{"side":"credit","account":"3000","amount":"1.00 USD"}
],"valuation_adjustments":[{"valuation_id":"VAL-APR20","account":"1510","basis_law":"signed_delta","effective_date":"2026-04-20","amount":"22.00 USD"}]}"#,
    );
    cli_ok_data(
        &bs_book,
        &["post", "--intent", &val_f, "--evidence", &bs_ev],
    );

    let cli_bs_apr20 = cli_ok_data(
        &bs_book,
        &[
            "procedure",
            "run",
            "solvency.balance_sheet_test",
            "--effective-through",
            "2026-04-20",
        ],
    );
    let mcp_bs_apr20 = mcp_ok(
        &bs_adapter,
        "fa_forensics_procedure",
        &json!({
            "action": "run",
            "id": "solvency.balance_sheet_test",
            "effective_through": "2026-04-20"
        }),
    );
    assert_eq!(mcp_bs_apr20, cli_bs_apr20);

    let bs_head = frontier(&bs_book);
    let (cli_stale_exit, _) = run_cli(
        &bs_book,
        &[
            "procedure",
            "run",
            "solvency.balance_sheet_test",
            "--effective-through",
            "2026-04-30",
        ],
    );
    assert_ne!(cli_stale_exit, 0);
    let bs_proc_tool = bs_adapter
        .mcp
        .tool_by_wire("fa_forensics_procedure")
        .unwrap();
    let mcp_stale_err = bs_adapter
        .call(
            bs_proc_tool,
            &json!({
                "action": "run",
                "id": "solvency.balance_sheet_test",
                "effective_through": "2026-04-30"
            }),
        )
        .expect_err("stale ExactAsOf valuation must refuse at 2026-04-30");
    assert_eq!(i128::from(mcp_stale_err.exit), i128::from(cli_stale_exit));
    assert_eq!(frontier(&bs_book), bs_head);
}
