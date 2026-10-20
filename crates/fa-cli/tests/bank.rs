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

// Replaying the original governed BankStatement is an explicit owner choice;
// the ordinary reader and every launch-bound template retain their ceilings.
fn run_privileged(book: &Path, args: &[&str]) -> (i32, Json) {
    let mut granted = args.to_vec();
    granted.extend(["--grant", "privileged"]);
    run(book, &granted)
}

fn ok_privileged(book: &Path, args: &[&str]) -> Json {
    let (status, output) = run_privileged(book, args);
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

fn confirmation_args(matched: &Json, index: usize, confirmer: &str) -> Vec<String> {
    let report = data(matched);
    let proposal = &rows(report, "proposals")[index];
    let mut args = vec![
        "bank".into(),
        "confirm".into(),
        "--import".into(),
        text(report, "manifest_oid").into(),
        "--line-ordinal".into(),
        integer(proposal, "line_ordinal").to_string(),
        "--proposal-digest".into(),
        text(proposal, "proposal_digest").into(),
        "--source-known-at".into(),
        integer(report, "known_at").to_string(),
        "--proposer".into(),
        text(proposal, "proposer").into(),
        "--as".into(),
        confirmer.into(),
    ];
    // Omit the default deliberately: a three-day proposal must be usable with
    // the CLI default, while a narrower selection carries its original window.
    let window = integer(report, "date_window");
    if window != 3 {
        args.extend(["--date-window".into(), window.to_string()]);
    }
    args
}

fn confirm_selection(book: &Path, args: &[String]) -> Json {
    ok_privileged(book, &args.iter().map(String::as_str).collect::<Vec<_>>())
}

#[test]
fn exact_confirmations_reopen_and_retry_without_changing_cash_or_reconciliation_state() {
    let f = Fixture::new();
    f.post("confirmed-sale", "2026-03-05", "debit", "150.00", "SALE-1");
    f.post("confirmed-bill", "2026-03-06", "credit", "50.00", "BILL-1");
    let imported = f.import("confirmation.csv", "csv", &statement_csv("95.00"));
    let manifest = text(data(&imported), "manifest_oid");
    let before_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as",
            "bank-preparer",
        ],
    );
    let proposals = rows(data(&matched), "proposals");
    let proposer = format!("{:032x}", fa_model::principal_vid("bank-preparer").0);
    for proposal in &proposals[..2] {
        assert_eq!(text(proposal, "proposer"), proposer);
        let command = text(proposal, "confirmation_command");
        assert!(command.contains("bank confirm"));
        assert!(command.contains(text(proposal, "proposal_digest")));
        assert!(command.contains(&proposer));
    }
    assert_eq!(proposals[2].get("confirmation_command"), Some(&Json::Null));
    let source_known_at = integer(data(&matched), "known_at");
    let before = head(&f.book);
    let args = confirmation_args(&matched, 0, "bank-reviewer");
    let confirmed = confirm_selection(&f.book, &args);
    assert_eq!(text(&confirmed, "event"), "bank_match_confirmed");
    let receipt = data(&confirmed);
    assert_eq!(receipt.get("already_recorded"), Some(&Json::Bool(false)));
    assert_eq!(integer(receipt, "recorded_at"), before + 1);
    assert_eq!(head(&f.book), before + 1);
    assert_eq!(text(receipt, "manifest_oid"), manifest);
    assert_eq!(
        integer(receipt, "line_ordinal"),
        integer(&proposals[0], "line_ordinal")
    );
    assert_eq!(
        text(receipt, "bank_line_oid"),
        text(&proposals[0], "bank_line_id")
    );
    assert_eq!(
        text(receipt, "line_document_oid"),
        text(&proposals[0], "line_document_oid")
    );
    assert_eq!(receipt.get("entry_ref"), proposals[0].get("entry_ref"));
    assert_eq!(receipt.get("leg_ordinal"), proposals[0].get("leg_ordinal"));
    assert_eq!(integer(receipt, "source_known_at"), source_known_at);
    assert_eq!(
        text(receipt, "proposal_digest"),
        text(&proposals[0], "proposal_digest")
    );
    assert_eq!(text(receipt, "proposer"), proposer);
    assert_eq!(
        text(receipt, "confirmed_by"),
        format!("{:032x}", fa_model::principal_vid("bank-reviewer").0)
    );
    assert_eq!(text(receipt, "match_vid").len(), 32);
    assert_eq!(text(receipt, "match_digest").len(), 64);
    assert_eq!(
        text(confirmed.get("authority").unwrap(), "principal"),
        "bank-reviewer"
    );

    // Every helper starts a fresh process. A different authorized caller must
    // recover the original decision and attribution after reopening the book.
    let after = head(&f.book);
    let retry = confirm_selection(
        &f.book,
        &confirmation_args(&matched, 0, "bank-retry-operator"),
    );
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    for key in [
        "match_vid",
        "match_digest",
        "recorded_at",
        "manifest_oid",
        "line_ordinal",
        "line_document_oid",
        "bank_line_oid",
        "entry_ref",
        "leg_ordinal",
        "proposer",
        "confirmed_by",
        "source_known_at",
        "proposal_digest",
    ] {
        assert_eq!(data(&retry).get(key), receipt.get(key), "retained {key}");
    }
    assert_eq!(
        text(retry.get("authority").unwrap(), "principal"),
        "bank-retry-operator"
    );
    assert_eq!(head(&f.book), after);

    let status = ok_privileged(&f.book, &["bank", "status", "--import", manifest]);
    assert_eq!(text(&status, "event"), "bank_confirmation_status");
    let inventory = data(&status);
    assert_eq!(text(inventory, "scope"), "recorded_confirmations");
    assert_eq!(integer(inventory, "line_count"), 3);
    assert_eq!(integer(inventory, "confirmed_lines"), 1);
    assert_eq!(integer(inventory, "remaining_lines"), 2);
    assert_eq!(inventory.get("reconciled_through"), Some(&Json::Null));
    let saved = rows(inventory, "confirmations");
    assert_eq!(saved.len(), 1);
    for key in [
        "match_vid",
        "match_digest",
        "recorded_at",
        "confirmed_by",
        "entry_ref",
        "leg_ordinal",
    ] {
        assert_eq!(saved[0].get(key), receipt.get(key), "inventory {key}");
    }
    let historical = ok_privileged(
        &f.book,
        &[
            "bank",
            "status",
            "--import",
            manifest,
            "--as-known-at",
            &source_known_at.to_string(),
        ],
    );
    assert_eq!(integer(data(&historical), "known_at"), source_known_at);
    assert_eq!(
        integer(historical.get("coordinate").unwrap(), "known_at"),
        source_known_at
    );
    assert_eq!(integer(data(&historical), "confirmed_lines"), 0);
    assert_eq!(integer(data(&historical), "remaining_lines"), 3);
    assert!(rows(data(&historical), "confirmations").is_empty());
    assert_eq!(head(&f.book), after);

    // The original report also authorizes its distinct outflow selection. Its
    // unmatched bank fee remains a missing posting, never an automatic entry.
    let bill = confirm_selection(&f.book, &confirmation_args(&matched, 1, "bank-reviewer"));
    assert_eq!(data(&bill).get("entry_ref"), proposals[1].get("entry_ref"));
    let status = ok_privileged(&f.book, &["bank", "status", "--import", manifest]);
    assert_eq!(integer(data(&status), "confirmed_lines"), 2);
    assert_eq!(integer(data(&status), "remaining_lines"), 1);
    assert_eq!(data(&status).get("reconciled_through"), Some(&Json::Null));
    let after_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    for key in ["rows", "unit_totals", "pending_unit_totals", "balanced"] {
        assert_eq!(
            data(&after_tb).get(key),
            data(&before_tb).get(key),
            "unchanged {key}"
        );
    }
}

#[test]
fn confirmation_identity_preserves_two_cash_leg_ordinals_in_one_entry() {
    let f = Fixture::new();
    let intent = f.file(
        "two-confirmable-legs.json",
        r#"{"effective_date":"2026-03-05","idempotency_key":"two-confirmable-legs","legs":[{"side":"debit","account":"1000","amount":"60.00 USD","memo":"A"},{"side":"debit","account":"1000","amount":"40.00 USD","memo":"B"},{"side":"credit","account":"4000","amount":"100.00 USD"}]}"#,
    );
    ok(
        &f.book,
        &["post", "--intent", &intent, "--evidence", &f.evidence],
    );
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,40.00,Customer,B\n1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,60.00,Customer,A\n"
    );
    let imported = f.import("two-confirmable-legs.csv", "csv", &raw);
    let manifest = text(data(&imported), "manifest_oid");
    let before_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let matched = ok_privileged(
        &f.book,
        &["bank", "match", "--import", manifest, "--date-window", "0"],
    );
    let proposals = rows(data(&matched), "proposals");
    assert_eq!(proposals[0].get("entry_ref"), proposals[1].get("entry_ref"));
    assert_eq!(integer(&proposals[0], "leg_ordinal"), 1);
    assert_eq!(integer(&proposals[1], "leg_ordinal"), 0);
    let first = confirm_selection(&f.book, &confirmation_args(&matched, 0, "bank-reviewer"));
    let second = confirm_selection(&f.book, &confirmation_args(&matched, 1, "bank-reviewer"));
    assert_eq!(
        data(&first).get("entry_ref"),
        data(&second).get("entry_ref")
    );
    assert_eq!(integer(data(&first), "leg_ordinal"), 1);
    assert_eq!(integer(data(&second), "leg_ordinal"), 0);
    assert_ne!(
        text(data(&first), "match_vid"),
        text(data(&second), "match_vid")
    );
    assert_ne!(
        text(data(&first), "match_digest"),
        text(data(&second), "match_digest")
    );
    let status = ok_privileged(&f.book, &["bank", "status", "--import", manifest]);
    assert_eq!(integer(data(&status), "confirmed_lines"), 2);
    assert_eq!(integer(data(&status), "remaining_lines"), 0);
    assert_eq!(data(&status).get("reconciled_through"), Some(&Json::Null));
    let mut ordinals: Vec<_> = rows(data(&status), "confirmations")
        .iter()
        .map(|row| integer(row, "leg_ordinal"))
        .collect();
    ordinals.sort_unstable();
    assert_eq!(ordinals, [0, 1]);
    let after_tb = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    assert_eq!(data(&after_tb).get("rows"), data(&before_tb).get("rows"));
}

#[test]
fn different_statements_cannot_confirm_the_same_cash_leg_twice() {
    let f = Fixture::new();
    f.post("single-claimed-leg", "2026-03-05", "debit", "100.00", "ONE");
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,100.00,Customer,ONE\n"
    );
    let first = f.import("first-claim.csv", "csv", &raw);
    let second = f.import(
        "second-claim.csv",
        "csv",
        &raw.replace("\n1,BANK-123", "\n2,BANK-123"),
    );
    let first_manifest = text(data(&first), "manifest_oid");
    let second_manifest = text(data(&second), "manifest_oid");
    assert_ne!(first_manifest, second_manifest);
    let first_match = ok_privileged(&f.book, &["bank", "match", "--import", first_manifest]);
    let second_match = ok_privileged(&f.book, &["bank", "match", "--import", second_manifest]);
    let first_proposal = &rows(data(&first_match), "proposals")[0];
    let second_proposal = &rows(data(&second_match), "proposals")[0];
    assert_eq!(
        first_proposal.get("entry_ref"),
        second_proposal.get("entry_ref")
    );
    assert_eq!(
        first_proposal.get("leg_ordinal"),
        second_proposal.get("leg_ordinal")
    );
    assert_eq!(integer(first_proposal, "eligible_candidate_count"), 1);
    assert_eq!(integer(second_proposal, "eligible_candidate_count"), 1);
    let recorded = confirm_selection(
        &f.book,
        &confirmation_args(&first_match, 0, "first-reviewer"),
    );
    let before = head(&f.book);
    let conflicting = confirmation_args(&second_match, 0, "second-reviewer");
    let (status, refusal) = run_privileged(
        &f.book,
        &conflicting.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(status, 6, "{}", refusal.render());
    assert_eq!(
        text(data(&refusal), "refusal_id"),
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(head(&f.book), before);
    let first_status = ok_privileged(&f.book, &["bank", "status", "--import", first_manifest]);
    assert_eq!(integer(data(&first_status), "confirmed_lines"), 1);
    assert_eq!(
        rows(data(&first_status), "confirmations")[0].get("match_digest"),
        data(&recorded).get("match_digest")
    );
    let second_status = ok_privileged(&f.book, &["bank", "status", "--import", second_manifest]);
    assert_eq!(integer(data(&second_status), "confirmed_lines"), 0);
    assert_eq!(integer(data(&second_status), "remaining_lines"), 1);
    assert!(rows(data(&second_status), "confirmations").is_empty());
    assert_eq!(head(&f.book), before);
}

#[test]
fn confirmation_refuses_unprivileged_forged_and_historically_unavailable_selections() {
    let f = Fixture::new();
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,25.00,2026-03-05,2026-03-05,CRDT,25.00,Customer,PAY-25\n"
    );
    let imported = f.import("selection-boundary.csv", "csv", &raw);
    let imported_at = head(&f.book);
    f.post("later-known-cash", "2026-03-04", "debit", "25.00", "PAY-25");
    let manifest = text(data(&imported), "manifest_oid");
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            manifest,
            "--as",
            "bank-preparer",
        ],
    );
    assert_eq!(integer(data(&matched), "proposed_count"), 1);
    let args = confirmation_args(&matched, 0, "bank-reviewer");
    let before = head(&f.book);
    let (status, refusal) = run(
        &f.book,
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(status, 3, "{}", refusal.render());
    assert_eq!(text(data(&refusal), "refusal_id"), "FA-REF-142");
    assert!(!refusal.render().contains("PAY-25"));
    assert_eq!(head(&f.book), before);

    let digest = text(&rows(data(&matched), "proposals")[0], "proposal_digest");
    let forged_digest = format!(
        "{}{}",
        if digest.starts_with('0') { '1' } else { '0' },
        &digest[1..]
    );
    for (flag, value) in [
        ("--proposal-digest", forged_digest),
        ("--source-known-at", imported_at.to_string()),
        ("--date-window", "0".into()),
    ] {
        let mut forged = args.clone();
        if let Some(position) = forged.iter().position(|arg| arg == flag) {
            forged[position + 1] = value;
        } else {
            forged.extend([flag.into(), value]);
        }
        let (status, refusal) = run_privileged(
            &f.book,
            &forged.iter().map(String::as_str).collect::<Vec<_>>(),
        );
        assert_eq!(status, 3, "{flag}: {}", refusal.render());
        assert_eq!(text(data(&refusal), "refusal_id"), "FA-REF-168", "{flag}");
        assert_eq!(
            head(&f.book),
            before,
            "{flag} must claim neither line nor leg"
        );
    }
    let recorded = confirm_selection(&f.book, &args);
    assert_eq!(
        data(&recorded).get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(integer(data(&recorded), "recorded_at"), before + 1);
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
    let source = ok_privileged(
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
    ok(&f.book, &["verify", "registers", "--fiscal-year", "2026"]);
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
    let (status, unavailable) = run_privileged(
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
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
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
    let replay = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(
        matched, replay,
        "same retained inputs and prefix yield identical proposals"
    );
    f.post("late-booking", "2026-03-07", "credit", "5.00", "FEE-1");
    let original = ok_privileged(
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
    let current = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
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
            "-",
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
        assert!(!captured.stdout.contains("no input reached the daemon"));
        assert_eq!(head(&f.book), before);
    }
}

#[test]
fn governed_sources_need_explicit_privilege_and_redacted_views_never_enable_matching() {
    let f = Fixture::new();
    let raw = statement_csv("95.00");
    let imported = f.import("governed.csv", "csv", &raw);
    let source = text(data(&imported), "statement_oid");
    let manifest = text(data(&imported), "manifest_oid");
    let before = head(&f.book);
    for args in [
        vec!["document", "read", source],
        vec!["bank", "match", "--import", manifest],
    ] {
        let (status, refused) = run(&f.book, &args);
        assert_eq!(status, 3, "{}", refused.render());
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-142");
        assert!(!refused.render().contains("BANK-123"));
        assert!(!refused.render().contains("SALE-1"));
        if args[0] == "bank" {
            assert!(text(data(&refused), "fix").contains("--grant privileged"));
        }
        assert_eq!(head(&f.book), before);
    }

    ok(&f.book, &["document", "redact", source]);
    let after_view = head(&f.book);
    let redacted = ok(&f.book, &["document", "read", source]);
    assert_eq!(text(data(&redacted), "view"), "redacted");
    assert_eq!(data(&redacted).get("bytes_hex"), Some(&Json::Null));
    assert_eq!(data(&redacted).get("text"), Some(&Json::Null));
    let (status, refused) = run(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(status, 7, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
    assert!(text(data(&refused), "fix").contains("--grant privileged"));

    for profile in [LaunchProfile::Agent, LaunchProfile::Preparer] {
        assert!(
            LaunchAuthority::new(
                f.book.clone(),
                None,
                "bank-template",
                profile,
                &["read", "reconcile", "privileged"],
            )
            .is_err(),
            "matching must not broaden a launch template's privilege ceiling"
        );
        let authority = LaunchAuthority::new(
            f.book.clone(),
            None,
            "bank-template",
            profile,
            &["read", "reconcile"],
        )
        .unwrap();
        let args = ["bank", "match", "--import", manifest, "--json"].map(str::to_string);
        let (status, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(f.dir.clone()),
                stdin: Stdin::Missing,
            },
            &authority,
            true,
        );
        assert_eq!(status, 7, "{captured:?}");
        let refused = json::parse(captured.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-011");
        assert!(!captured.stdout.contains("SALE-1"));
        assert_eq!(head(&f.book), after_view);
    }

    let full = ok_privileged(&f.book, &["document", "read", source]);
    assert_eq!(text(data(&full), "view"), "full");
    assert_eq!(
        text(data(&full).get("text").unwrap(), "untrusted_content"),
        raw
    );
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(integer(data(&matched), "line_count"), 3);
    assert_eq!(data(&matched).get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(head(&f.book), after_view);
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
    let matched = ok_privileged(
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
        let matched = ok_privileged(
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
    let matched = ok_privileged(
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
    let mut legs = vec![r#"{"side":"debit","account":"1000","amount":"1.00 USD"}"#; 43];
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
    let (code, output) = run_privileged(
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
    let matched = ok_privileged(
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
    let matched = ok_privileged(
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
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,100.00,,\n"
    );
    let imported = f.import("tie.csv", "csv", &raw);
    let before = head(&f.book);
    let matched = ok_privileged(
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
    assert_eq!(integer(report, "ambiguous_count"), 1);
    assert_eq!(integer(report, "proposed_count"), 1);
    assert_eq!(report.get("confirmed"), Some(&Json::Bool(false)));
    let row = &rows(report, "proposals")[0];
    assert_eq!(integer(row, "eligible_candidate_count"), 2);
    assert_eq!(row.get("ambiguous"), Some(&Json::Bool(true)));
    assert_eq!(row.get("competing_bank_lines"), Some(&Json::Bool(false)));
    assert_eq!(row.get("counterparty"), Some(&Json::Null));
    assert_eq!(row.get("reference"), Some(&Json::Null));
    assert_eq!(row.get("confirmation_command"), Some(&Json::Null));
    let selection = confirmation_args(&matched, 0, "tie-reviewer");
    let (status, refused) = run_privileged(
        &f.book,
        &selection.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(status, 3, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
    assert_eq!(
        head(&f.book),
        before,
        "diagnostics and an ambiguous confirmation do not write"
    );

    let selective = raw.replace("100.00,,\n", "100.00,,one\n");
    let imported = f.import("specific-reference.csv", "csv", &selective);
    let matched = ok_privileged(
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
    let row = &rows(data(&matched), "proposals")[0];
    assert_eq!(integer(data(&matched), "ambiguous_count"), 0);
    assert_eq!(integer(row, "eligible_candidate_count"), 1);
    assert_eq!(row.get("ambiguous"), Some(&Json::Bool(false)));
    assert!(text(row, "confirmation_command").contains("bank confirm"));
}

#[test]
fn a_consumed_cash_leg_does_not_hide_competition_between_statement_lines() {
    let f = Fixture::new();
    f.post("one-cash-leg", "2026-03-05", "debit", "100.00", "ONE");
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,200.00,2026-03-05,2026-03-05,CRDT,100.00,,\n1,BANK-123,USD,2026-03-31,0.00,200.00,2026-03-05,2026-03-05,CRDT,100.00,,\n"
    );
    let imported = f.import("competing-lines.csv", "csv", &raw);
    let before = head(&f.book);
    let matched = ok_privileged(
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
        assert_eq!(row.get("confirmation_command"), Some(&Json::Null));
    }
    let selection = confirmation_args(&matched, 0, "competition-reviewer");
    let (status, refused) = run_privileged(
        &f.book,
        &selection.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(status, 3, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-168");
    assert_eq!(head(&f.book), before);
}

#[test]
fn quoted_csv_descriptions_survive_retention_reopen_and_exact_matching() {
    let f = Fixture::new();
    f.post("quoted-reference", "2026-03-05", "debit", "1.00", "SALE,1");
    let raw = format!(
        "{CSV_HEADER}1,BANK-123,USD,2026-03-31,0.00,1.00,2026-03-05,2026-03-05,CRDT,1.00,\"Acme,\n\"\"Ltd\"\"\",\"SALE,1\"\n"
    );
    let imported = f.import("quoted-fields.csv", "csv", &raw);
    let manifest = text(data(&imported), "manifest_oid");
    assert_eq!(integer(data(&imported), "line_count"), 1);
    let after_import = head(&f.book);
    let source = ok_privileged(
        &f.book,
        &["document", "read", text(data(&imported), "statement_oid")],
    );
    assert_eq!(
        text(data(&source).get("text").unwrap(), "untrusted_content"),
        raw,
    );
    let matched = ok_privileged(
        &f.book,
        &["bank", "match", "--import", manifest, "--date-window", "0"],
    );
    assert_eq!(integer(data(&matched), "proposed_count"), 1);
    assert_eq!(integer(data(&matched), "ambiguous_count"), 0);
    assert_eq!(text(data(&matched), "closing_difference"), "0.00 USD");
    let row = &rows(data(&matched), "proposals")[0];
    assert_eq!(
        text(row.get("counterparty").unwrap(), "untrusted_content"),
        "Acme,\n\"Ltd\"",
    );
    assert_eq!(
        text(row.get("reference").unwrap(), "untrusted_content"),
        "SALE,1",
    );
    let source = format!("D:{}", text(row, "line_document_oid"));
    assert_eq!(text(row.get("counterparty").unwrap(), "source"), source);
    assert_eq!(text(row.get("reference").unwrap(), "source"), source);
    assert_eq!(head(&f.book), after_import);
    let repeated = f.import("quoted-fields-again.csv", "csv", &raw);
    assert_eq!(text(data(&repeated), "manifest_oid"), manifest);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&f.book), after_import);
}

fn continuity_csv(
    sequence: u64,
    bank: &str,
    date: &str,
    opening: &str,
    closing: &str,
    reference: &str,
) -> String {
    format!(
        "{CSV_HEADER}{sequence},{bank},USD,{date},{opening},{closing},{date},{date},CRDT,25.00,Customer,{reference}\n"
    )
}

fn linked_import(f: &Fixture, name: &str, raw: &str, previous: &str) -> Json {
    let path = f.file(name, raw);
    ok_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            previous,
        ],
    )
}

#[test]
fn explicit_predecessors_bind_original_receipts_and_replay_the_retained_chain() {
    let f = Fixture::new();
    let first = f.import(
        "chain-first.csv",
        "csv",
        &continuity_csv(10, "BANK-CHAIN", "2026-03-31", "0.00", "25.00", "FIRST"),
    );
    let first_data = data(&first);
    let first_oid = text(first_data, "manifest_oid");
    assert_eq!(text(first_data, "continuity"), "unlinked");
    assert_eq!(integer(first_data, "verified_predecessors"), 0);
    assert_eq!(first_data.get("predecessor"), Some(&Json::Null));

    let second_raw = continuity_csv(11, "BANK-CHAIN", "2026-04-30", "25.00", "50.00", "SECOND");
    let before = head(&f.book);
    let path = f.file("second-unprivileged.csv", &second_raw);
    let (status, refusal) = run(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            first_oid,
        ],
    );
    assert_ne!(
        status, 0,
        "replaying retained source requires explicit disclosure authority"
    );
    assert!(refusal.render().contains("privileged"));
    assert_eq!(head(&f.book), before);

    let second = linked_import(&f, "chain-second.csv", &second_raw, first_oid);
    let second_data = data(&second);
    assert_eq!(
        head(&f.book),
        before + 1,
        "link, documents, native provenance and import publish together"
    );
    assert_eq!(text(second_data, "continuity"), "verified_predecessor");
    assert_eq!(integer(second_data, "verified_predecessors"), 1);
    let predecessor = second_data.get("predecessor").unwrap();
    assert_eq!(text(predecessor, "manifest_oid"), first_oid);
    assert_eq!(
        text(predecessor, "statement_oid"),
        text(first_data, "statement_oid")
    );
    assert_eq!(
        text(predecessor, "statement_commit"),
        text(first_data, "statement_commit")
    );
    assert_eq!(
        text(predecessor, "receipt_hash"),
        text(first_data, "receipt_hash")
    );
    assert_eq!(
        integer(predecessor, "recorded_at"),
        integer(first_data, "recorded_at")
    );
    assert_eq!(integer(predecessor, "sequence_number"), 10);
    assert_eq!(text(predecessor, "closing_balance"), "25.00 USD");

    let after = head(&f.book);
    let other_path = f.file("chain-second-retry.csv", &second_raw);
    let repeated = ok_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &other_path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            first_oid,
            "--as",
            "another-authorized-uploader",
        ],
    );
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(data(&repeated), "manifest_oid"),
        text(second_data, "manifest_oid")
    );
    assert_eq!(
        text(data(&repeated), "receipt_hash"),
        text(second_data, "receipt_hash")
    );
    assert_eq!(
        data(&repeated).get("predecessor"),
        second_data.get("predecessor")
    );
    assert_eq!(head(&f.book), after);

    let third = linked_import(
        &f,
        "chain-third.csv",
        &continuity_csv(12, "BANK-CHAIN", "2026-05-31", "50.00", "75.00", "THIRD"),
        text(second_data, "manifest_oid"),
    );
    assert_eq!(integer(data(&third), "verified_predecessors"), 2);
    let before_match = head(&f.book);
    let matched = ok_privileged(
        &f.book,
        &[
            "bank",
            "match",
            "--import",
            text(data(&third), "manifest_oid"),
        ],
    );
    assert_eq!(integer(data(&matched), "verified_predecessors"), 2);
    assert_eq!(text(data(&matched), "continuity"), "verified_predecessor");
    assert_eq!(data(&matched).get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(
        head(&f.book),
        before_match,
        "continuity replay does not confirm reconciliation"
    );
    let original = ok_privileged(&f.book, &["bank", "match", "--import", first_oid]);
    assert_eq!(
        text(data(&original), "continuity"),
        "unlinked",
        "v1 remains explicitly readable"
    );
    assert_eq!(integer(data(&original), "verified_predecessors"), 0);
}

#[test]
fn predecessor_mismatches_refuse_without_publishing_any_new_import() {
    let f = Fixture::new();
    let first_raw = continuity_csv(20, "BANK-STRICT", "2026-03-31", "0.00", "25.00", "FIRST");
    let first = f.import("strict-first.csv", "csv", &first_raw);
    let previous = text(data(&first), "manifest_oid");
    let before = head(&f.book);
    for (name, raw) in [
        (
            "gap",
            continuity_csv(22, "BANK-STRICT", "2026-04-30", "25.00", "50.00", "NEXT"),
        ),
        (
            "opening",
            continuity_csv(21, "BANK-STRICT", "2026-04-30", "20.00", "45.00", "NEXT"),
        ),
        (
            "date",
            continuity_csv(21, "BANK-STRICT", "2026-03-20", "25.00", "50.00", "NEXT"),
        ),
        (
            "bank",
            continuity_csv(21, "DIFFERENT-BANK", "2026-04-30", "25.00", "50.00", "NEXT"),
        ),
        ("self", first_raw),
    ] {
        let path = f.file(&format!("strict-{name}.csv"), &raw);
        let (status, refusal) = run_privileged(
            &f.book,
            &[
                "bank",
                "import",
                &path,
                "--bank-format",
                "csv",
                "--account",
                "1000",
                "--previous-import",
                previous,
            ],
        );
        assert_eq!(status, 3, "{name}: {}", refusal.render());
        assert_eq!(
            text(data(&refusal), "refusal_id"),
            "FA-REF-165",
            "{name}: a continuity failure is an accounting refusal, not a malformed upload"
        );
        assert_eq!(
            head(&f.book),
            before,
            "{name} must not record its source, manifest or run"
        );
    }
    let overflow = f.import(
        "overflow-first.csv",
        "csv",
        &continuity_csv(
            u64::MAX,
            "BANK-OVERFLOW",
            "2026-03-31",
            "0.00",
            "25.00",
            "LAST",
        ),
    );
    let overflow_head = head(&f.book);
    let path = f.file(
        "overflow-next.csv",
        &continuity_csv(
            0,
            "BANK-OVERFLOW",
            "2026-04-30",
            "25.00",
            "50.00",
            "WRAPPED",
        ),
    );
    let (status, refusal) = run_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            text(data(&overflow), "manifest_oid"),
        ],
    );
    assert_eq!(
        status,
        3,
        "sequence addition must not wrap: {}",
        refusal.render()
    );
    assert_eq!(text(data(&refusal), "refusal_id"), "FA-REF-165");
    assert_eq!(head(&f.book), overflow_head);
}

#[test]
fn a_valid_alternative_predecessor_cannot_fork_an_already_linked_statement() {
    let f = Fixture::new();
    let left = f.import(
        "fork-left.csv",
        "csv",
        &continuity_csv(1, "BANK-FORK", "2026-03-31", "0.00", "25.00", "LEFT"),
    );
    let right = f.import(
        "fork-right.csv",
        "csv",
        &continuity_csv(1, "BANK-FORK", "2026-03-31", "0.00", "25.00", "RIGHT"),
    );
    let raw = continuity_csv(2, "BANK-FORK", "2026-04-30", "25.00", "50.00", "NEXT");
    let selected = linked_import(&f, "fork-next.csv", &raw, text(data(&left), "manifest_oid"));
    let before = head(&f.book);
    let path = f.file("fork-conflict.csv", &raw);
    let (status, refusal) = run_privileged(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
            "--previous-import",
            text(data(&right), "manifest_oid"),
            "--as",
            "different-uploader",
        ],
    );
    assert_ne!(status, 0);
    assert_eq!(
        text(data(&refusal), "refusal_id"),
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert!(
        refusal
            .render()
            .contains(text(data(&selected), "manifest_oid"))
    );
    assert_eq!(head(&f.book), before);

    let (status, refusal) = run(
        &f.book,
        &[
            "bank",
            "import",
            &path,
            "--bank-format",
            "csv",
            "--account",
            "1000",
        ],
    );
    assert_ne!(
        status, 0,
        "omitting the predecessor cannot replace a recorded choice"
    );
    assert_eq!(
        text(data(&refusal), "refusal_id"),
        fa_journal::refusal::code::IDEMPOTENCY_CONFLICT
    );
    assert_eq!(head(&f.book), before);
}

#[test]
fn an_unlinked_import_recorded_before_its_statement_was_linked_retries_to_its_receipt() {
    // Import unlinked first and link later (the continuity refusal's fix
    // offers exactly that). An exact repeat of the original unlinked import
    // is still the recorded import, not a competing choice: it returns the
    // original receipt and publishes nothing. A new unlinked import of a
    // linked statement stays refused (the fork test above).
    let f = Fixture::new();
    let first = f.import(
        "retry-first.csv",
        "csv",
        &continuity_csv(30, "BANK-RETRY", "2026-03-31", "0.00", "25.00", "FIRST"),
    );
    let raw = continuity_csv(31, "BANK-RETRY", "2026-04-30", "25.00", "50.00", "NEXT");
    let unlinked = f.import("retry-next.csv", "csv", &raw);
    assert_eq!(text(data(&unlinked), "continuity"), "unlinked");
    let linked = linked_import(
        &f,
        "retry-next-linked.csv",
        &raw,
        text(data(&first), "manifest_oid"),
    );
    assert_eq!(text(data(&linked), "continuity"), "verified_predecessor");
    assert_ne!(
        text(data(&linked), "manifest_oid"),
        text(data(&unlinked), "manifest_oid")
    );
    let after = head(&f.book);
    let repeated = f.import("retry-next-again.csv", "csv", &raw);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(data(&repeated), "manifest_oid"),
        text(data(&unlinked), "manifest_oid")
    );
    assert_eq!(
        text(data(&repeated), "receipt_hash"),
        text(data(&unlinked), "receipt_hash")
    );
    assert_eq!(text(data(&repeated), "continuity"), "unlinked");
    assert_eq!(head(&f.book), after);
}

fn unmatch_args(confirmed: &Json) -> Vec<String> {
    let recorded = data(confirmed);
    vec![
        "bank".into(),
        "unmatch".into(),
        "--match".into(),
        text(recorded, "match_vid").into(),
        "--digest".into(),
        text(recorded, "match_digest").into(),
    ]
}

#[test]
fn explicit_unmatch_retains_history_retries_and_allows_a_fresh_confirmation() {
    let f = Fixture::new();
    f.post("release-sale", "2026-03-05", "debit", "100.00", "RELEASE");
    let source = format!(
        "{CSV_HEADER}1,BANK-RELEASE,USD,2026-03-31,0.00,100.00,2026-03-05,2026-03-05,CRDT,100.00,Customer,RELEASE\n"
    );
    let imported = f.import("release.csv", "csv", &source);
    let manifest = text(data(&imported), "manifest_oid");
    let money_before = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    let initial_proposal = &rows(data(&matched), "proposals")[0];
    let original_args = confirmation_args(&matched, 0, "release-reviewer");
    let first = confirm_selection(&f.book, &original_args);
    let first_at = integer(data(&first), "recorded_at");
    let before = head(&f.book);

    // History is an authorized metadata fold; full source status keeps its
    // separate governed disclosure requirement.
    let history = ok(&f.book, &["bank", "history", "--import", manifest]);
    assert_eq!(text(&history, "event"), "bank_match_history");
    assert_eq!(text(data(&history), "scope"), "match_history");
    assert_eq!(integer(data(&history), "confirmation_count"), 1);
    assert_eq!(integer(data(&history), "unmatch_count"), 0);
    assert_eq!(integer(data(&history), "active_count"), 1);
    assert_eq!(
        rows(data(&history), "active")[0].get("match_vid"),
        data(&first).get("match_vid")
    );
    let (status, _) = run(&f.book, &["bank", "status", "--import", manifest]);
    assert_ne!(
        status, 0,
        "full-source status still requires governed disclosure"
    );
    assert_eq!(head(&f.book), before);

    let claimed = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(integer(data(&claimed), "confirmed_count"), 1);
    assert_eq!(integer(data(&claimed), "unmatched_count"), 0);
    assert_eq!(integer(data(&claimed), "outstanding_count"), 0);
    let retained = &rows(data(&claimed), "proposals")[0];
    assert_eq!(text(retained, "status"), "confirmed");
    assert_eq!(retained.get("confirmation_command"), Some(&Json::Null));
    for key in [
        "entry_ref",
        "leg_ordinal",
        "candidate_ordinal",
        "decision_card",
        "decision_card_digest",
        "proposal_digest",
        "proposer",
    ] {
        assert_eq!(
            retained.get(key),
            initial_proposal.get(key),
            "original {key}"
        );
    }
    assert_eq!(
        retained.get("confirmed_match").unwrap().get("match_vid"),
        data(&first).get("match_vid")
    );

    let args = unmatch_args(&first);
    let argv: Vec<_> = args.iter().map(String::as_str).collect();
    let (status, refusal) = run(&f.book, &argv);
    assert_ne!(status, 0, "unmatch must be explicitly acknowledged");
    assert!(refusal.render().contains("--yes"));
    assert_eq!(head(&f.book), before);
    let wrong_digest = "ab".repeat(32);
    let (status, _) = run(
        &f.book,
        &[
            "bank",
            "unmatch",
            "--match",
            text(data(&first), "match_vid"),
            "--digest",
            &wrong_digest,
            "--yes",
        ],
    );
    assert_ne!(
        status, 0,
        "a release must bind the exact original match digest"
    );
    assert_eq!(head(&f.book), before);

    let mut release_args = args.clone();
    release_args.push("--yes".into());
    let release_argv: Vec<_> = release_args.iter().map(String::as_str).collect();
    let release = ok(&f.book, &release_argv);
    assert_eq!(text(&release, "event"), "bank_match_unmatched");
    let released = data(&release);
    assert_eq!(integer(released, "recorded_at"), before + 1);
    assert_eq!(released.get("already_recorded"), Some(&Json::Bool(false)));
    assert_eq!(
        released.get("target").unwrap().get("vid"),
        data(&first).get("match_vid")
    );
    assert_eq!(
        released.get("target").unwrap().get("digest"),
        data(&first).get("match_digest")
    );
    let released_at = head(&f.book);
    let retry = ok(&f.book, &release_argv);
    assert_eq!(
        data(&retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    for key in [
        "unmatch_vid",
        "unmatch_digest",
        "recorded_at",
        "target",
        "unmatched_by",
    ] {
        assert_eq!(
            data(&retry).get(key),
            released.get(key),
            "release retry {key}"
        );
    }
    assert_eq!(head(&f.book), released_at);

    let original_retry = confirm_selection(&f.book, &original_args);
    assert_eq!(
        data(&original_retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        data(&original_retry).get("match_vid"),
        data(&first).get("match_vid")
    );
    assert_eq!(head(&f.book), released_at);
    let released_history = ok(&f.book, &["bank", "history", "--import", manifest]);
    assert_eq!(integer(data(&released_history), "confirmation_count"), 1);
    assert_eq!(integer(data(&released_history), "unmatch_count"), 1);
    assert_eq!(integer(data(&released_history), "active_count"), 0);
    let historical = ok(
        &f.book,
        &[
            "bank",
            "history",
            "--import",
            manifest,
            "--as-known-at",
            &first_at.to_string(),
        ],
    );
    assert_eq!(integer(data(&historical), "known_at"), first_at);
    assert_eq!(
        integer(historical.get("coordinate").unwrap(), "known_at"),
        first_at
    );
    assert_eq!(integer(data(&historical), "active_count"), 1);
    assert_eq!(integer(data(&historical), "unmatch_count"), 0);

    let fresh = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
    assert_eq!(integer(data(&fresh), "confirmed_count"), 0);
    assert_eq!(
        text(&rows(data(&fresh), "proposals")[0], "status"),
        "proposed"
    );
    let second = confirm_selection(&f.book, &confirmation_args(&fresh, 0, "fresh-reviewer"));
    assert_ne!(
        data(&second).get("match_vid"),
        data(&first).get("match_vid")
    );
    assert!(integer(data(&second), "source_known_at") >= released_at);
    let history = ok(&f.book, &["bank", "history", "--import", manifest]);
    assert_eq!(integer(data(&history), "confirmation_count"), 2);
    assert_eq!(integer(data(&history), "unmatch_count"), 1);
    assert_eq!(integer(data(&history), "active_count"), 1);
    assert_eq!(
        rows(data(&history), "active")[0].get("match_vid"),
        data(&second).get("match_vid")
    );

    let current_head = head(&f.book);
    let retry_old_release = ok(&f.book, &release_argv);
    assert_eq!(
        data(&retry_old_release).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&f.book), current_head);
    let source_status = ok_privileged(&f.book, &["bank", "status", "--import", manifest]);
    assert_eq!(
        text(data(&source_status), "scope"),
        "recorded_confirmations"
    );
    assert_eq!(integer(data(&source_status), "line_count"), 1);
    assert_eq!(integer(data(&source_status), "confirmed_lines"), 1);
    assert_eq!(integer(data(&source_status), "remaining_lines"), 0);
    assert_eq!(rows(data(&source_status), "confirmations").len(), 2);
    assert_eq!(
        data(&source_status).get("reconciled_through"),
        Some(&Json::Null)
    );
    let money_after = ok(&f.book, &["tb", "--period", "FY2026-P03"]);
    for key in ["rows", "unit_totals", "pending_unit_totals", "balanced"] {
        assert_eq!(
            data(&money_after).get(key),
            data(&money_before).get(key),
            "unchanged {key}"
        );
    }
}

#[test]
fn reports_exclude_other_statements_cash_claims_until_an_explicit_release() {
    let f = Fixture::new();
    f.post("global-cash", "2026-03-05", "debit", "50.00", "GLOBAL");
    let source = |sequence| {
        format!(
            "{CSV_HEADER}{sequence},BANK-GLOBAL,USD,2026-03-31,0.00,50.00,2026-03-05,2026-03-05,CRDT,50.00,Customer,GLOBAL\n"
        )
    };
    let first_import = f.import("global-first.csv", "csv", &source(1));
    let second_import = f.import("global-second.csv", "csv", &source(2));
    let first_manifest = text(data(&first_import), "manifest_oid");
    let second_manifest = text(data(&second_import), "manifest_oid");
    let first_report = ok_privileged(&f.book, &["bank", "match", "--import", first_manifest]);
    let second_report = ok_privileged(&f.book, &["bank", "match", "--import", second_manifest]);
    let stale_args = confirmation_args(&second_report, 0, "other-reviewer");
    let first = confirm_selection(
        &f.book,
        &confirmation_args(&first_report, 0, "first-reviewer"),
    );

    let occupied = ok_privileged(&f.book, &["bank", "match", "--import", second_manifest]);
    let row = &rows(data(&occupied), "proposals")[0];
    assert_eq!(text(row, "status"), "unmatched");
    assert_eq!(integer(row, "eligible_candidate_count"), 0);
    assert_eq!(row.get("confirmation_command"), Some(&Json::Null));
    assert_eq!(integer(data(&occupied), "confirmed_count"), 0);
    assert_eq!(integer(data(&occupied), "outstanding_count"), 0);
    let mut release_args = unmatch_args(&first);
    release_args.push("--yes".into());
    ok(
        &f.book,
        &release_args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    let before = head(&f.book);
    let (status, _) = run_privileged(
        &f.book,
        &stale_args.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_ne!(
        status, 0,
        "the new cash generation requires a post-release review"
    );
    assert_eq!(head(&f.book), before);

    let fresh = ok_privileged(&f.book, &["bank", "match", "--import", second_manifest]);
    assert_eq!(
        integer(
            &rows(data(&fresh), "proposals")[0],
            "eligible_candidate_count"
        ),
        1
    );
    let second = confirm_selection(&f.book, &confirmation_args(&fresh, 0, "other-reviewer"));
    assert_eq!(
        data(&second).get("entry_ref"),
        data(&first).get("entry_ref")
    );
    assert_eq!(
        data(&second).get("leg_ordinal"),
        data(&first).get("leg_ordinal")
    );
    let first_history = ok(&f.book, &["bank", "history", "--import", first_manifest]);
    assert_eq!(integer(data(&first_history), "confirmation_count"), 1);
    assert_eq!(integer(data(&first_history), "unmatch_count"), 1);
    assert_eq!(integer(data(&first_history), "active_count"), 0);
    let second_history = ok(&f.book, &["bank", "history", "--import", second_manifest]);
    assert_eq!(integer(data(&second_history), "confirmation_count"), 1);
    assert_eq!(integer(data(&second_history), "unmatch_count"), 0);
    assert_eq!(integer(data(&second_history), "active_count"), 1);
    let all_history = ok(&f.book, &["bank", "history", "--account", "1000"]);
    assert_eq!(text(data(&all_history), "account"), "1000");
    assert_eq!(integer(data(&all_history), "confirmation_count"), 2);
    assert_eq!(integer(data(&all_history), "unmatch_count"), 1);
    assert_eq!(integer(data(&all_history), "active_count"), 1);
}
