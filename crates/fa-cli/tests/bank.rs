//! Real binary bank intake/reconciliation: retained source and parser closure,
//! atomicity, exact signs, stable repeats, and refusal before source consumption.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Files, Stdin};
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json};

fn data(value: &Json) -> &Json {
    value.get("data").expect("robot data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match value.get(key).expect(key) {
        Json::Int(value) => *value,
        other => panic!("{key} is not an integer: {other:?}"),
    }
}

fn rows<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    match value.get(key).expect(key) {
        Json::Arr(rows) => rows,
        other => panic!("{key} is not an array: {other:?}"),
    }
}

fn run(book: &Path, args: &[&str]) -> (i32, Json) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{args:?}: {stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{args:?}: {error}\n{stdout}\n{stderr}"));
    (
        output.status.code().unwrap(),
        json::parse(lines[0]).unwrap(),
    )
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (status, output) = run(book, args);
    assert_eq!(status, 0, "{args:?}: {}", output.render());
    output
}

fn head(book: &Path) -> i128 {
    let output = ok(book, &["book", "info"]);
    integer(output.get("coordinate").unwrap(), "known_at")
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    evidence: String,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-bank-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create retained fixture {}: {error}", dir.display()),
            }
        };
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Bank intake"]);
        let chart = dir.join("chart.json");
        std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Expenses","type":"Expense","unit":"USD"}]}"#).unwrap();
        ok(&book, &["chart", "import", chart.to_str().unwrap()]);
        ok(&book, &["period", "create", "--fiscal-year", "2026"]);
        ok(&book, &["period", "open", "FY2026-P03"]);
        let source = dir.join("source.txt");
        std::fs::write(
            &source,
            "Bank workflow source receipt for posted transactions.",
        )
        .unwrap();
        let document = ok(
            &book,
            &[
                "document",
                "add",
                source.to_str().unwrap(),
                "--kind",
                "Receipt",
                "--grade",
                "HumanUpload",
            ],
        );
        Self {
            dir,
            book,
            evidence: text(data(&document), "oid").into(),
        }
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.display().to_string()
    }

    fn post(&self, key: &str, date: &str, side: &str, amount: &str, reference: &str) -> Json {
        let (other_side, other_account) = if side == "debit" {
            ("credit", "4000")
        } else {
            ("debit", "6000")
        };
        let path = self.file(&format!("{key}.json"), &format!(
            r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"{side}","account":"1000","amount":"{amount} USD","memo":"{reference}"}},{{"side":"{other_side}","account":"{other_account}","amount":"{amount} USD"}}]}}"#));
        ok(
            &self.book,
            &["post", "--intent", &path, "--evidence", &self.evidence],
        )
    }

    fn import(&self, name: &str, format: &str, contents: &str) -> Json {
        let path = self.file(name, contents);
        ok(
            &self.book,
            &[
                "bank",
                "import",
                &path,
                "--bank-format",
                format,
                "--account",
                "1000",
            ],
        )
    }
}

const CSV_HEADER: &str = "sequence_number,instrument_id,currency,statement_date,opening_balance,closing_balance,booking_date,value_date,side,amount,counterparty,reference\n";

fn statement_csv(closing: &str) -> String {
    format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,{closing},2026-03-05,2026-03-05,CRDT,150.00,Customer,SALE-1\n1,BANK-123,USD,2026-03-31,0.00,{closing},2026-03-06,2026-03-06,DBIT,50.00,Vendor,BILL-1\n1,BANK-123,USD,2026-03-31,0.00,{closing},2026-03-07,2026-03-07,DBIT,5.00,Bank,FEE-1\n"
    )
}

#[test]
fn import_is_atomic_keeps_source_and_line_closure_and_is_content_idempotent() {
    let f = Fixture::new();
    let raw = statement_csv("95.00");
    let before = head(&f.book);
    let imported = f.import("statement.csv", "csv", &raw);
    assert_eq!(text(&imported, "event"), "bank_imported");
    let result = data(&imported);
    assert_eq!(integer(result, "line_count"), 3);
    assert_eq!(text(result, "closing_balance"), "95.00 USD");
    assert_eq!(
        head(&f.book),
        before + 1,
        "source, lines and manifest are one commit"
    );
    let source = ok(
        &f.book,
        &["document", "read", text(result, "statement_oid")],
    );
    assert_eq!(text(data(&source), "kind"), "BankStatement");
    assert_eq!(
        text(data(&source).get("text").unwrap(), "untrusted_content"),
        raw
    );
    for oid in rows(result, "line_oids") {
        let line = ok(&f.book, &["document", "read", oid.as_str().unwrap()]);
        assert_eq!(
            text(data(&line), "grade"),
            "AgentUpload",
            "derived text never upgrades provenance"
        );
        assert_eq!(
            text(data(&line), "mime"),
            "application/vnd.frankenaccounting.bank-line"
        );
    }
    let after = head(&f.book);
    let repeated = f.import("repeat.csv", "csv", &raw);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(data(&repeated), "manifest_oid"),
        text(result, "manifest_oid")
    );
    assert_eq!(
        text(data(&repeated), "receipt_hash"),
        text(result, "receipt_hash")
    );
    assert_eq!(head(&f.book), after);
    let other_path = f.file("other-uploader.csv", &raw);
    let other = ok(
        &f.book,
        &[
            "bank",
            "import",
            &other_path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--as",
            "second-uploader",
        ],
    );
    assert_eq!(
        data(&other).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        head(&f.book),
        after,
        "another authorized uploader does not duplicate an import"
    );
    ok(&f.book, &["verify", "registers"]);
}

#[test]
fn exact_matches_reopen_with_bound_account_and_parser_and_never_confirm_or_post_fees() {
    let f = Fixture::new();
    f.post("sale", "2026-03-05", "debit", "150.00", "SALE-1");
    f.post("bill", "2026-03-06", "credit", "50.00", "BILL-1");
    f.post("in-transit", "2026-03-10", "debit", "20.00", "NEXT-STMT");
    let before_import = head(&f.book);
    let imported = f.import("match.csv", "csv", &statement_csv("95.00"));
    let manifest = text(data(&imported), "manifest_oid");
    let before = head(&f.book);
    let (status, unavailable) = run(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as-known-at",
            &before_import.to_string(),
        ],
    );
    assert_eq!(status, 2, "{}", unavailable.render());
    assert_eq!(text(data(&unavailable), "refusal_id"), "FA-REF-103");
    assert_eq!(head(&f.book), before);
    let matched = ok(&f.book, &["bank", "match", "--import", manifest]);
    let result = data(&matched);
    assert_eq!(text(&matched, "event"), "bank_matches_proposed");
    assert_eq!(result.get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(integer(result, "proposed_count"), 2);
    assert_eq!(integer(result, "unmatched_count"), 1);
    assert_eq!(integer(result, "outstanding_count"), 1);
    assert_eq!(text(result, "candidate_from"), "2026-03-02");
    assert_eq!(text(result, "candidate_through"), "2026-04-03");
    assert_eq!(
        text(result, "outstanding_scope"),
        "unmatched_cash_legs_in_candidate_window"
    );
    assert_eq!(result.get("outstanding_complete"), Some(&Json::Bool(false)));
    assert_eq!(text(result, "book_closing_balance"), "120.00 USD");
    assert_eq!(text(result, "closing_difference"), "-25.00 USD");
    let proposals = rows(result, "proposals");
    assert_eq!(text(&proposals[0], "direction"), "inflow");
    assert_eq!(text(&proposals[1], "direction"), "outflow");
    assert_eq!(text(&proposals[2], "status"), "unmatched");
    for row in &proposals[..2] {
        assert_eq!(text(row, "status"), "proposed");
        assert!(
            row.get("entry_ref")
                .is_some_and(|value| value != &Json::Null)
        );
        assert_eq!(text(row, "decision_card_digest").len(), 64);
        assert!(!text(row, "decision_card").is_empty());
    }
    assert_eq!(head(&f.book), before);
    let replay = ok(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(
        matched, replay,
        "same retained inputs and prefix yield identical proposals"
    );
    f.post("late-booking", "2026-03-07", "credit", "5.00", "FEE-1");
    let original = ok(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as-known-at",
            &before.to_string(),
        ],
    );
    assert_eq!(integer(data(&original), "proposed_count"), 2);
    assert_eq!(
        integer(original.get("coordinate").unwrap(), "known_at"),
        before
    );
    let current = ok(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(integer(data(&current), "proposed_count"), 3);
    assert_eq!(integer(data(&current), "unmatched_count"), 0);
}

#[test]
fn invalid_balances_float_syntax_and_wrong_account_unit_publish_nothing() {
    let f = Fixture::new();
    let cases = [
        ("unbalanced.csv", statement_csv("96.00"), "1000"),
        (
            "float.csv",
            statement_csv("95.00").replace("150.00", "1.5e2"),
            "1000",
        ),
        (
            "currency.csv",
            statement_csv("95.00").replace("USD", "EUR"),
            "1000",
        ),
        ("revenue.csv", statement_csv("95.00"), "4000"),
    ];
    let before = head(&f.book);
    for (name, raw, account) in cases {
        let path = f.file(name, &raw);
        let (status, output) = run(
            &f.book,
            &[
                "bank",
                "import",
                &path,
                "--bank-format",
                "csv",
                "--account",
                account,
            ],
        );
        assert!(status == 2 || status == 3, "{name}: {}", output.render());
        assert_eq!(text(&output, "event"), "error");
        assert_eq!(
            head(&f.book),
            before,
            "{name}: a refused statement leaves no document or import receipt"
        );
    }
}

#[test]
fn missing_authority_and_agent_import_refuse_before_reading_missing_input() {
    let f = Fixture::new();
    let before = head(&f.book);
    for (profile, ops, expected) in [
        (LaunchProfile::Preparer, &["post"][..], "FA-REF-011"),
        (
            LaunchProfile::Agent,
            &["read", "post", "reconcile"][..],
            "FA-REF-013",
        ),
    ] {
        let authority =
            LaunchAuthority::new(f.book.clone(), None, "bank-bound-agent", profile, ops).unwrap();
        let args = [
            "bank",
            "import",
            "never-created.csv",
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--json",
        ]
        .map(str::to_string);
        let (code, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(f.dir.clone()),
                stdin: Stdin::Missing,
            },
            &authority,
            true,
        );
        assert_eq!(code, 7, "{captured:?}");
        let output = json::parse(captured.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(text(data(&output), "refusal_id"), expected);
        assert!(!captured.stdout.contains("No such file"));
        assert_eq!(head(&f.book), before);
    }
}

#[test]
fn one_entry_with_multiple_cash_legs_preserves_each_selected_ordinal() {
    let f = Fixture::new();
    let intent = f.file("two-cash-legs.json", r#"{"effective_date":"2026-03-05","idempotency_key":"two-cash","legs":[{"side":"debit","account":"1000","amount":"60.00 USD","memo":"A"},{"side":"debit","account":"1000","amount":"40.00 USD","memo":"B"},{"side":"credit","account":"4000","amount":"100.00 USD"}]}"#);
    ok(
        &f.book,
        &["post", "--intent", &intent, "--evidence", &f.evidence],
    );
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,40.00,Customer,B\n1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,60.00,Customer,A\n"
    );
    let imported = f.import("split.csv", "csv", &raw);
    let matched = ok(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    assert_eq!(integer(data(&matched), "proposed_count"), 2);
    let proposals = rows(data(&matched), "proposals");
    assert_eq!(integer(&proposals[0], "leg_ordinal"), 1);
    assert_eq!(integer(&proposals[1], "leg_ordinal"), 0);
    assert_eq!(proposals[0].get("entry_ref"), proposals[1].get("entry_ref"));
}

#[test]
fn real_camt_date_choices_and_currency_attributes_import_and_match() {
    let f = Fixture::new();
    // These unresolved cash legs precede the first bank line and cancel in
    // the closing balance. A zero candidate count cannot attest that they
    // have been reconciled or that the outstanding inventory is complete.
    f.post("earlier-inflow", "2026-03-01", "debit", "20.00", "EARLY-IN");
    f.post(
        "earlier-outflow",
        "2026-03-01",
        "credit",
        "20.00",
        "EARLY-OUT",
    );
    f.post("camt-sale", "2026-03-05", "debit", "125.00", "WIRE-125");
    let statement = r#"<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="urn:iso:std:iso:20022:tech:xsd:camt.053.001.08">
  <BkToCstmrStmt><Stmt><Id>March bank statement</Id><ElctrncSeqNb>1</ElctrncSeqNb>
    <Acct><Id><IBAN>GB29NWBK60161331926819</IBAN></Id><Ccy>USD</Ccy></Acct>
    <Bal><Tp><CdOrPrtry><Cd>OPBD</Cd></CdOrPrtry></Tp><Amt Ccy="USD">0.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-03-01</Dt></Dt></Bal>
    <Bal><Tp><CdOrPrtry><Cd>CLBD</Cd></CdOrPrtry></Tp><Amt Ccy="USD">125.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Dt><Dt>2026-03-31</Dt></Dt></Bal>
    <Ntry><Amt Ccy="USD">125.00</Amt><CdtDbtInd>CRDT</CdtDbtInd><Sts><Cd>BOOK</Cd></Sts>
      <BookgDt><Dt>2026-03-05</Dt></BookgDt><ValDt><Dt>2026-03-05</Dt></ValDt><AcctSvcrRef>WIRE-125</AcctSvcrRef>
      <NtryDtls><TxDtls><RltdPties><Dbtr><Pty><Nm>Customer &amp; Co</Nm></Pty></Dbtr></RltdPties></TxDtls></NtryDtls>
    </Ntry>
  </Stmt></BkToCstmrStmt>
</Document>"#;
    let intraday = statement
        .replace("camt.053", "camt.052")
        .replace("BkToCstmrStmt", "BkToCstmrAcctRpt")
        .replace("<Stmt>", "<Rpt>")
        .replace("</Stmt>", "</Rpt>")
        .replace("CLBD", "ITBD");
    for (format, raw) in [("camt053", statement), ("camt052", intraday.as_str())] {
        let imported = f.import(&format!("{format}.xml"), format, raw);
        assert_eq!(text(data(&imported), "bank_format"), format);
        let after_import = head(&f.book);
        let matched = ok(
            &f.book,
            &[
                "bank",
                "match",
                "--import",
                text(data(&imported), "manifest_oid"),
                "--date-window",
                "0",
            ],
        );
        let report = data(&matched);
        assert_eq!(integer(report, "proposed_count"), 1);
        assert_eq!(integer(report, "unmatched_count"), 0);
        assert_eq!(integer(report, "outstanding_count"), 0);
        assert_eq!(text(report, "candidate_from"), "2026-03-05");
        assert_eq!(text(report, "candidate_through"), "2026-03-31");
        assert_eq!(
            text(report, "outstanding_scope"),
            "unmatched_cash_legs_in_candidate_window"
        );
        assert_eq!(report.get("outstanding_complete"), Some(&Json::Bool(false)));
        assert_eq!(report.get("confirmed"), Some(&Json::Bool(false)));
        assert_eq!(text(report, "closing_difference"), "0.00 USD");
        assert_eq!(head(&f.book), after_import);
        let row = &rows(report, "proposals")[0];
        assert_eq!(text(row, "booking_date"), "2026-03-05");
        assert_eq!(text(row, "value_date"), "2026-03-05");
    }
    let entry_start = statement.find("<Ntry>").unwrap();
    let entry_end = statement.find("</Ntry>").unwrap() + "</Ntry>".len();
    let empty = format!("{}{}", &statement[..entry_start], &statement[entry_end..]).replace(
        "<Amt Ccy=\"USD\">0.00</Amt>",
        "<Amt Ccy=\"USD\">125.00</Amt>",
    );
    let imported = f.import("empty-camt053.xml", "camt053", &empty);
    let after_import = head(&f.book);
    let matched = ok(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    let report = data(&matched);
    assert_eq!(integer(report, "line_count"), 0);
    assert_eq!(integer(report, "proposed_count"), 0);
    assert_eq!(integer(report, "outstanding_count"), 0);
    assert_eq!(report.get("candidate_from"), Some(&Json::Null));
    assert_eq!(report.get("candidate_through"), Some(&Json::Null));
    assert_eq!(
        text(report, "outstanding_scope"),
        "unmatched_cash_legs_in_candidate_window"
    );
    assert_eq!(report.get("outstanding_complete"), Some(&Json::Bool(false)));
    assert_eq!(report.get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(text(report, "closing_difference"), "0.00 USD");
    assert_eq!(head(&f.book), after_import);
}

#[test]
fn an_ambiguous_candidate_set_cannot_emit_an_undecodable_decision_card() {
    let f = Fixture::new();
    let mut legs = Vec::new();
    for _ in 0..43 {
        legs.push(r#"{"side":"debit","account":"1000","amount":"1.00 USD"}"#);
    }
    legs.push(r#"{"side":"credit","account":"4000","amount":"43.00 USD"}"#);
    let intent = f.file(
        "many-candidates.json",
        &format!(
            r#"{{"effective_date":"2026-03-05","idempotency_key":"many-candidates","legs":[{}]}}"#,
            legs.join(",")
        ),
    );
    ok(
        &f.book,
        &["post", "--intent", &intent, "--evidence", &f.evidence],
    );
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,1.00,2026-03-05,2026-03-05,CRDT,1.00,Customer,\n"
    );
    let imported = f.import("ambiguous.csv", "csv", &raw);
    let before = head(&f.book);
    let (code, output) = run(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    assert_eq!(code, 2, "{}", output.render());
    assert_eq!(text(data(&output), "refusal_id"), "FA-REF-083");
    assert!(output.render().contains("decision card"));
    assert_eq!(head(&f.book), before);
}

#[test]
fn missing_bank_descriptions_remain_valid_robot_data_and_present_text_cites_its_document() {
    let f = Fixture::new();
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,1.00,2026-03-05,2026-03-05,CRDT,1.00,,\n"
    );
    let imported = f.import("no-descriptions.csv", "csv", &raw);
    let before = head(&f.book);
    let matched = ok(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    let proposal = &rows(data(&matched), "proposals")[0];
    assert_eq!(proposal.get("counterparty"), Some(&Json::Null));
    assert_eq!(proposal.get("reference"), Some(&Json::Null));
    assert_eq!(head(&f.book), before);

    let imported = f.import("described.csv", "csv", &statement_csv("95.00"));
    let matched = ok(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&imported), "manifest_oid"),
        ],
    );
    for proposal in rows(data(&matched), "proposals") {
        let expected_source = format!("D:{}", text(proposal, "line_document_oid"));
        for field in ["counterparty", "reference"] {
            assert_eq!(
                text(proposal.get(field).unwrap(), "source"),
                expected_source
            );
        }
    }
}

#[test]
fn bank_ties_are_explicit_and_reference_selection_can_resolve_them() {
    let f = Fixture::new();
    f.post("same-one", "2026-03-05", "debit", "100.00", "ONE");
    f.post("same-two", "2026-03-05", "debit", "100.00", "TWO");
    let raw = format!("{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,100.00,,\n");
    let imported = f.import("tie.csv", "csv", &raw);
    let before = head(&f.book);
    let matched = ok(&f.book, &["bank", "match", "--import", text(data(&imported), "manifest_oid"), "--date-window", "0"]);
    let report = data(&matched);
    assert_eq!(integer(report, "ambiguous_count"), 1);
    assert_eq!(integer(report, "proposed_count"), 1);
    assert_eq!(report.get("confirmed"), Some(&Json::Bool(false)));
    let row = &rows(report, "proposals")[0];
    assert_eq!(integer(row, "eligible_candidate_count"), 2);
    assert_eq!(row.get("ambiguous"), Some(&Json::Bool(true)));
    assert_eq!(row.get("competing_bank_lines"), Some(&Json::Bool(false)));
    assert_eq!(row.get("counterparty"), Some(&Json::Null));
    assert_eq!(row.get("reference"), Some(&Json::Null));
    assert_eq!(head(&f.book), before, "diagnostics and proposals do not write");

    let selective = raw.replace("100.00,,\n", "100.00,,one\n");
    let imported = f.import("specific-reference.csv", "csv", &selective);
    let matched = ok(&f.book, &["bank", "match", "--import", text(data(&imported), "manifest_oid"), "--date-window", "0"]);
    let row = &rows(data(&matched), "proposals")[0];
    assert_eq!(integer(data(&matched), "ambiguous_count"), 0);
    assert_eq!(integer(row, "eligible_candidate_count"), 1);
    assert_eq!(row.get("ambiguous"), Some(&Json::Bool(false)));
}

#[test]
fn a_consumed_cash_leg_does_not_hide_competition_between_statement_lines() {
    let f = Fixture::new();
    f.post("one-cash-leg", "2026-03-05", "debit", "100.00", "ONE");
    let raw = format!("{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,200.00,2026-03-05,2026-03-05,CRDT,100.00,,\n1,BANK-123,USD,2026-03-31,0.00,200.00,2026-03-05,2026-03-05,CRDT,100.00,,\n");
    let imported = f.import("competing-lines.csv", "csv", &raw);
    let before = head(&f.book);
    let matched = ok(&f.book, &["bank", "match", "--import", text(data(&imported), "manifest_oid"), "--date-window", "0"]);
    let report = data(&matched);
    assert_eq!(integer(report, "ambiguous_count"), 2);
    assert_eq!(integer(report, "proposed_count"), 1);
    assert_eq!(integer(report, "unmatched_count"), 1);
    assert_eq!(text(report, "closing_difference"), "100.00 USD");
    let proposals = rows(report, "proposals");
    assert_eq!(text(&proposals[0], "status"), "proposed");
    assert_eq!(text(&proposals[1], "status"), "unmatched");
    for row in proposals {
        assert_eq!(integer(row, "eligible_candidate_count"), 1);
        assert_eq!(row.get("ambiguous"), Some(&Json::Bool(true)));
        assert_eq!(row.get("competing_bank_lines"), Some(&Json::Bool(true)));
    }
    assert_eq!(head(&f.book), before);
}
