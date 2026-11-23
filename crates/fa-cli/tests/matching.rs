//! Real CLI source-bound matching and historical replay, including authority
//! refusal before opening a book and malformed unselected source records.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::Files;
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json};

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value.get(key).and_then(Json::as_str).expect(key)
}

fn data(value: &Json) -> &Json {
    value.get("data").expect("robot data")
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
        .expect("run fa");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lines: Vec<_> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{args:?}: {stdout}\n{stderr}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(lines[0])
        .unwrap_or_else(|error| panic!("{args:?}: {error}\n{stdout}\n{stderr}"));
    let result = json::parse(lines[0]).unwrap();
    let status = output.status.code().expect("normal process exit");
    eprintln!(
        "argv={args:?} exit={status} event={} known_at={:?} refusal={:?}",
        text(&result, "event"),
        result.get("coordinate").and_then(|v| v.get("known_at")),
        data(&result).get("refusal_id")
    );
    (status, result)
}

fn ok(book: &Path, args: &[&str]) -> Json {
    let (status, result) = run(book, args);
    assert_eq!(status, 0, "{args:?}: {}", result.render());
    result
}

fn head(book: &Path) -> i128 {
    let result = ok(book, &["book", "info"]);
    match result.get("coordinate").unwrap().get("known_at").unwrap() {
        Json::Int(value) => *value,
        other => panic!("known-at is not an integer: {other:?}"),
    }
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    po: String,
    receipt: String,
    invoice: String,
}

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let dir = std::env::temp_dir().join(format!(
                "fa-three-way-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&dir) {
                Ok(()) => break dir,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create {}: {error}", dir.display()),
            }
        };
        let book = dir.join("book");
        ok(&book, &["book", "create", "--name", "Purchase evidence"]);
        let mut f = Self {
            dir,
            book,
            po: String::new(),
            receipt: String::new(),
            invoice: String::new(),
        };
        f.po = f.source("po.csv", "PurchaseOrder",
            "vendor,item_code,quantity,unit_price,currency\n\"Vendor, Inc\",SKU-1,4,2.50,USD\n\"Vendor, Inc\",SKU-2,2,1.00,USD\n");
        f.receipt = f.source(
            "receipt.csv",
            "ReceivingReport",
            &format!(
                "purchase_order_oid,item_code,quantity_received\n{},SKU-1,4\n{},SKU-2,2\n",
                f.po, f.po
            ),
        );
        f.invoice = f.invoice_source("invoice.csv", "Vendor, Inc", "4", "2.50", "10.00");
        f
    }

    fn source(&self, filename: &str, kind: &str, content: &str) -> String {
        let path = self.dir.join(filename);
        std::fs::write(&path, content).unwrap();
        let added = ok(
            &self.book,
            &[
                "document",
                "add",
                path.to_str().unwrap(),
                "--kind",
                kind,
                "--mime",
                "text/csv",
                "--grade",
                "HumanUpload",
            ],
        );
        text(data(&added), "oid").to_string()
    }

    fn invoice_source(
        &self,
        file: &str,
        vendor: &str,
        quantity: &str,
        price: &str,
        total: &str,
    ) -> String {
        self.source(file, "Invoice", &format!(
            "purchase_order_oid,vendor,item_code,quantity_billed,unit_price_billed,total_billed,currency\n{},\"{vendor}\",SKU-1,{quantity},{price},{total},USD\n", self.po))
    }

    fn args<'a>(&'a self, invoice: &'a str) -> Vec<&'a str> {
        vec![
            "match",
            "three-way",
            "--purchase-order",
            &self.po,
            "--receiving-report",
            &self.receipt,
            "--invoice-document",
            invoice,
            "--item",
            "SKU-1",
        ]
    }
}

#[test]
fn three_way_matching_replays_retained_sources_without_posting_or_upgrading_evidence() {
    let f = Fixture::new();
    let before = head(&f.book);
    let matched = ok(&f.book, &f.args(&f.invoice));
    let result = data(&matched);
    assert_eq!(text(&matched, "event"), "three_way_match");
    assert_eq!(text(result, "verdict"), "matched");
    assert_eq!(result.get("advisory"), Some(&Json::Bool(true)));
    assert_eq!(result.get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(text(result, "quantity_ordered"), "4");
    assert_eq!(text(result, "quantity_received"), "4");
    assert_eq!(text(result, "quantity_billed"), "4");
    assert_eq!(text(result, "po_unit_price"), "2.50 USD");
    assert_eq!(text(result, "invoice_total"), "10.00 USD");
    assert_eq!(text(result, "invoice_expected_total"), "10.00 USD");
    assert_eq!(
        text(result.get("vendor").unwrap(), "untrusted_content"),
        "Vendor, Inc"
    );
    for (field, oid) in [
        ("purchase_order_source", &f.po),
        ("receiving_report_source", &f.receipt),
        ("invoice_source", &f.invoice),
    ] {
        let source = result.get(field).unwrap();
        assert_eq!(text(source, "oid"), oid);
        assert_eq!(text(source, "grade"), "HumanUpload");
        assert_eq!(source.get("line_ordinal"), Some(&Json::Int(1)));
        assert_eq!(text(source, "doc_commit").len(), 64);
    }
    assert_eq!(
        head(&f.book),
        before,
        "matching publishes no accounting state"
    );
    let card_hex = text(result, "decision_card");
    let card_bytes: Vec<u8> = card_hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let card = fa_policy::DecisionCard::decode(&card_bytes).expect("canonical decision card");
    assert_eq!(card.canonical_bytes().unwrap(), card_bytes);

    // Later source intake changes HEAD, but cannot change a pinned result.
    f.invoice_source("later.csv", "Vendor, Inc", "4", "2.50", "11.00");
    let replay = match result.get("replay_argv").unwrap() {
        Json::Arr(values) => values
            .iter()
            .skip(1)
            .map(|v| v.as_str().unwrap())
            .filter(|arg| *arg != "--json")
            .collect::<Vec<_>>(),
        other => panic!("replay argv: {other:?}"),
    };
    let replayed = ok(&f.book, &replay);
    assert_eq!(
        data(&replayed),
        result,
        "the full source-bound result replays exactly"
    );
    let mut wrong_digest = replay.clone();
    let digest_index = wrong_digest
        .iter()
        .position(|a| *a == "--expect-digest")
        .unwrap()
        + 1;
    let forged = "00".repeat(32);
    wrong_digest[digest_index] = &forged;
    let (status, refused) = run(&f.book, &wrong_digest);
    assert_eq!(status, 8, "{}", refused.render());
    let mut moving = f.args(&f.invoice);
    moving.extend([
        "--as-known-at",
        "HEAD",
        "--expect-digest",
        text(result, "result_digest"),
    ]);
    assert_eq!(run(&f.book, &moving).0, 2);
}

#[test]
fn three_way_matching_reports_exact_variances_and_refuses_unrelated_or_malformed_sources() {
    let f = Fixture::new();
    for (file, quantity, price, total, expected) in [
        ("qty.csv", "3", "2.50", "7.50", "quantity_variance"),
        ("price.csv", "4", "3.00", "12.00", "price_variance"),
        ("total.csv", "4", "2.50", "10.01", "extension_mismatch"),
    ] {
        let invoice = f.invoice_source(file, "Vendor, Inc", quantity, price, total);
        let result = ok(&f.book, &f.args(&invoice));
        assert_eq!(text(data(&result), "verdict"), expected);
        assert_eq!(data(&result).get("matched"), Some(&Json::Bool(false)));
    }
    let wrong_vendor =
        f.invoice_source("wrong-vendor.csv", "Unrelated Vendor", "4", "2.50", "10.00");
    assert_eq!(run(&f.book, &f.args(&wrong_vendor)).0, 2);
    let wrong_po = f.source("wrong-po.csv", "Invoice", &format!(
        "purchase_order_oid,vendor,item_code,quantity_billed,unit_price_billed,total_billed,currency\n{},\"Vendor, Inc\",SKU-1,4,2.50,10.00,USD\n", "01".repeat(32)));
    assert_eq!(run(&f.book, &f.args(&wrong_po)).0, 2);
    let malformed_remainder = f.source("malformed.csv", "Invoice", &format!(
        "purchase_order_oid,vendor,item_code,quantity_billed,unit_price_billed,total_billed,currency\n{},\"Vendor, Inc\",SKU-1,4,2.50,10.00,USD\n{},\"Vendor, Inc\",UNSELECTED,not-a-count,2.50,10.00,USD\n", f.po, f.po));
    assert_eq!(run(&f.book, &f.args(&malformed_remainder)).0, 2);
    let duplicate = f.source("duplicate.csv", "Invoice", &format!(
        "purchase_order_oid,vendor,item_code,quantity_billed,unit_price_billed,total_billed,currency\n{},\"Vendor, Inc\",SKU-1,4,2.50,10.00,USD\n{},\"Vendor, Inc\",SKU-1,4,2.50,10.00,USD\n", f.po, f.po));
    assert_eq!(run(&f.book, &f.args(&duplicate)).0, 2);
    assert_eq!(
        run(&f.book, &f.args(&f.receipt)).0,
        2,
        "one retained document cannot occupy two source roles"
    );
    let wrong_kind = f.source(
        "invoice-wrong-kind.csv",
        "PurchaseOrder",
        &format!(
            "purchase_order_oid,vendor,item_code,quantity_billed,unit_price_billed,total_billed,currency\n{},\"Vendor, Inc\",SKU-1,4,2.50,10.00,USD\n",
            f.po
        ),
    );
    assert_eq!(
        run(&f.book, &f.args(&wrong_kind)).0,
        2,
        "a distinct source with the wrong registered kind cannot supply an invoice"
    );
    let old = "0";
    let mut invisible = f.args(&f.invoice);
    invisible.extend(["--as-known-at", old]);
    assert_ne!(
        run(&f.book, &invisible).0,
        0,
        "sources did not exist at sequence zero"
    );
}

#[test]
fn three_way_matching_requires_launch_reconcile_before_book_observation() {
    let f = Fixture::new();
    let absent = f.dir.join("not-a-book");
    let authority = LaunchAuthority::new(
        absent.clone(),
        None,
        "purchase-observer",
        LaunchProfile::Preparer,
        &["read"],
    )
    .unwrap();
    let args: Vec<_> = f
        .args(&f.invoice)
        .into_iter()
        .chain(["--json"])
        .map(str::to_string)
        .collect();
    let (status, output) = fa_with_authority(&args, Files::default(), &authority, true);
    assert_eq!(status, 7, "{:?}", output);
    assert!(
        !absent.exists(),
        "refused launch did not create or open a book"
    );
}

#[test]
fn complete_purchase_matching_exposes_omitted_items_and_replays_exact_inventory() {
    let f = Fixture::new();
    let before = head(&f.book);
    let mut args = f.args(&f.invoice);
    args.truncate(args.len() - 2);
    args.push("--all-items");
    let complete = ok(&f.book, &args);
    assert_eq!(text(&complete, "event"), "three_way_document_match");
    let result = data(&complete);
    assert_eq!(text(result, "verdict"), "exceptions");
    assert_eq!(result.get("matched"), Some(&Json::Bool(false)));
    assert_eq!(result.get("advisory"), Some(&Json::Bool(true)));
    assert_eq!(result.get("confirmed"), Some(&Json::Bool(false)));
    assert_eq!(result.get("item_count"), Some(&Json::Int(2)));
    assert_eq!(result.get("matched_count"), Some(&Json::Int(1)));
    assert_eq!(result.get("exception_count"), Some(&Json::Int(1)));
    assert_eq!(result.get("missing_source_count"), Some(&Json::Int(1)));
    let Json::Arr(items) = result.get("items").unwrap() else {
        panic!("item union");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(
        text(items[0].get("item_code").unwrap(), "untrusted_content"),
        "SKU-1"
    );
    assert_eq!(text(&items[0], "verdict"), "matched");
    assert_eq!(
        text(items[1].get("item_code").unwrap(), "untrusted_content"),
        "SKU-2"
    );
    assert_eq!(text(&items[1], "verdict"), "missing_sources");
    assert_eq!(
        items[1].get("missing_sources"),
        Some(&Json::Arr(vec![Json::Str("Invoice".into())]))
    );
    assert_eq!(items[1].get("invoice_line"), Some(&Json::Null));
    assert_eq!(items[1].get("quantity_billed"), Some(&Json::Null));
    assert_eq!(items[1].get("decision_card"), Some(&Json::Null));
    assert_eq!(text(&items[1], "quantity_ordered"), "2");
    assert_eq!(text(&items[1], "quantity_received"), "2");
    assert_eq!(
        result.get("invoice_source").unwrap().get("line_count"),
        Some(&Json::Int(1))
    );
    assert_eq!(head(&f.book), before);

    let extra = f.source("whole-extra.csv", "Invoice", &format!(
        "purchase_order_oid,vendor,item_code,quantity_billed,unit_price_billed,total_billed,currency\n{},\"Vendor, Inc\",SKU-1,4,2.50,10.00,USD\n{},\"Vendor, Inc\",UNORDERED,1,999.00,999.00,USD\n", f.po, f.po
    ));
    let Json::Arr(replay) = result.get("replay_argv").unwrap() else {
        panic!("replay argv");
    };
    let replay: Vec<_> = replay
        .iter()
        .skip(1)
        .map(|v| v.as_str().unwrap())
        .filter(|arg| *arg != "--json")
        .collect();
    assert_eq!(data(&ok(&f.book, &replay)), result);
    let mut changed = f.args(&extra);
    changed.truncate(changed.len() - 2);
    changed.push("--all-items");
    let report = ok(&f.book, &changed);
    assert_eq!(data(&report).get("item_count"), Some(&Json::Int(3)));
    assert_eq!(
        data(&report).get("missing_source_count"),
        Some(&Json::Int(2))
    );
    let Json::Arr(items) = data(&report).get("items").unwrap() else {
        panic!("items");
    };
    let extra = &items[2];
    assert_eq!(
        text(extra.get("item_code").unwrap(), "untrusted_content"),
        "UNORDERED"
    );
    assert_eq!(extra.get("purchase_order_line"), Some(&Json::Null));
    assert_eq!(extra.get("receiving_report_line"), Some(&Json::Null));
    assert_eq!(text(extra, "invoice_total"), "999.00 USD");
    assert_ne!(
        text(data(&report), "result_digest"),
        text(result, "result_digest")
    );
    changed.extend([
        "--as-known-at",
        "HEAD",
        "--expect-digest",
        text(result, "result_digest"),
    ]);
    assert_eq!(run(&f.book, &changed).0, 2);
}

#[test]
fn complete_purchase_matching_requires_exact_selection_and_current_launch_authority() {
    let f = Fixture::new();
    let mut both = f.args(&f.invoice);
    both.push("--all-items");
    assert_eq!(run(&f.book, &both).0, 2);
    let mut neither = f.args(&f.invoice);
    neither.truncate(neither.len() - 2);
    assert_eq!(run(&f.book, &neither).0, 2);
    let absent = f.dir.join("no-document-match-book");
    let authority = LaunchAuthority::new(
        absent.clone(),
        None,
        "whole-purchase-observer",
        LaunchProfile::Preparer,
        &["read"],
    )
    .unwrap();
    let mut args = neither;
    args.extend(["--all-items", "--json"]);
    let args = args.into_iter().map(str::to_string).collect::<Vec<_>>();
    let (status, output) = fa_with_authority(&args, Files::default(), &authority, true);
    assert_eq!(status, 7, "{output:?}");
    assert!(
        !absent.exists(),
        "authority refusal must precede book observation"
    );
}

#[test]
fn recon_post_usage_names_every_encodable_bridge_reason() {
    let registry = fa_cli::verbs::registry().unwrap();
    let recon = registry.verb("recon").unwrap();
    let names = recon
        .usage
        .iter()
        .find_map(|line| line.strip_prefix("recon post --reason-code <"))
        .and_then(|line| line.split_once('>'))
        .expect("recon post usage lists its reason codes")
        .0;
    let mut listed: Vec<_> = names.split('|').collect();
    let mut encodable: Vec<_> = fa::BookToBookReasonCode::ALL
        .iter()
        .map(|reason| reason.as_str())
        .collect();
    listed.sort_unstable();
    encodable.sort_unstable();
    assert_eq!(listed, encodable);
}

#[test]
fn nested_adjustment_layers_replay_historical_ancestry_on_cli() {
    static NEXT_CHAIN: AtomicU64 = AtomicU64::new(0);
    let dir = loop {
        let path = std::env::temp_dir().join(format!(
            "fa-recon-chain-cli-{}-{}",
            std::process::id(),
            NEXT_CHAIN.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create {}: {error}", path.display()),
        }
    };
    let books: Vec<_> = ["primary", "tax", "statutory", "management"]
        .iter()
        .map(|name| dir.join(name))
        .collect();
    let chart = dir.join("chart.json");
    std::fs::write(
        &chart,
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"3000","name":"Capital","type":"Equity","unit":"USD"}
        ]}"#,
    )
    .unwrap();
    let evidence = dir.join("basis.txt");
    std::fs::write(&evidence, "Synthetic adjustment-layer ancestry fixture").unwrap();
    let mut documents = Vec::new();
    for (index, book) in books.iter().enumerate() {
        ok(book, &["book", "create", "--name", "Layer chain fixture"]);
        ok(book, &["chart", "import", chart.to_str().unwrap()]);
        ok(book, &["period", "create", "--fiscal-year", "2026"]);
        ok(book, &["period", "open", "FY2026-P03"]);
        let document = ok(
            book,
            &[
                "document",
                "add",
                evidence.to_str().unwrap(),
                "--kind",
                "Memo",
                "--grade",
                "HumanUpload",
            ],
        );
        documents.push(text(data(&document), "oid").to_string());
        if index > 0 {
            ok(
                book,
                &[
                    "recon",
                    "anchor",
                    "--parent-book",
                    books[index - 1].to_str().unwrap(),
                    "--grant",
                    "schema_change",
                ],
            );
        }
        let amount = ["1000.00", "100.00", "20.00", "5.00"][index];
        let intent = dir.join(format!("entry-{index}.json"));
        std::fs::write(
            &intent,
            format!(
                r#"{{"idempotency_key":"chain-{index}","effective_date":"2026-03-31",
                "description":"Synthetic basis adjustment",
                "legs":[{{"side":"debit","account":"1000","amount":"{amount} USD"}},
                {{"side":"credit","account":"3000","amount":"{amount} USD"}}]}}"#
            ),
        )
        .unwrap();
        let mut args = if index == 0 {
            vec!["post"]
        } else {
            vec!["recon", "post", "--reason-code", "STAT-RECLASS"]
        };
        args.extend([
            "--intent",
            intent.to_str().unwrap(),
            "--evidence",
            documents[index].as_str(),
        ]);
        if index == 1 {
            let before = head(book);
            let mut invalid = args.clone();
            invalid[3] = "STAT-RESERVE-BASIS";
            let (exit, error) = run(book, &invalid);
            assert_eq!(exit, 2, "{}", error.render());
            assert!(
                text(data(&error), "message")
                    .contains("unknown --reason-code `STAT-RESERVE-BASIS`"),
                "{}",
                error.render()
            );
            assert_eq!(head(book), before);
        }
        ok(book, &args);
    }
    let primary = books[0].to_str().unwrap();
    let tax = books[1].to_str().unwrap();
    let statutory = books[2].to_str().unwrap();
    let args = [
        "recon",
        "book-to-book",
        "--period",
        "FY2026-P03",
        "--parent-book",
        statutory,
        "--ancestor-book",
        tax,
        "--ancestor-book",
        primary,
    ];
    let original_heads: Vec<_> = books.iter().map(|book| head(book)).collect();
    let first = ok(&books[3], &args);
    let rows = data(&first).get("rows").and_then(Json::as_arr).unwrap();
    let cash = rows.iter().find(|row| text(row, "code") == "1000").unwrap();
    assert_eq!(text(cash, "parent_net"), "1120.00 USD");
    assert_eq!(text(cash, "adjustments_net"), "5.00 USD");
    assert_eq!(text(cash, "layered_net"), "1125.00 USD");
    let explanations = cash.get("explanations").and_then(Json::as_arr).unwrap();
    assert_eq!(explanations.len(), 1);
    assert_eq!(text(&explanations[0], "reason_code"), "STAT-RECLASS");
    let ancestry = data(&first)
        .get("parent_ancestry")
        .and_then(Json::as_arr)
        .unwrap();
    assert_eq!(ancestry.len(), 3);
    for (index, coordinate) in ancestry.iter().enumerate() {
        assert_eq!(
            coordinate.get("known_at"),
            Some(&Json::Int(original_heads[index]))
        );
        assert_eq!(text(coordinate, "book_id").len(), 32);
    }
    assert_eq!(
        books.iter().map(|book| head(book)).collect::<Vec<_>>(),
        original_heads,
        "complete source replay is read-only"
    );

    // Missing, reversed and unused ancestor directories are explicit failures.
    for ancestors in [
        vec![],
        vec![tax],
        vec![primary, tax],
        vec![tax, primary, primary],
    ] {
        let mut invalid = vec![
            "recon",
            "book-to-book",
            "--as-of",
            "2026-03-31",
            "--parent-book",
            statutory,
        ];
        for ancestor in ancestors {
            invalid.extend(["--ancestor-book", ancestor]);
        }
        let (status, error) = run(&books[3], &invalid);
        assert_eq!(status, 2, "{}", error.render());
    }
    assert_eq!(
        books.iter().map(|book| head(book)).collect::<Vec<_>>(),
        original_heads,
        "ancestor refusals preserve every source and target head"
    );

    // Later primary activity and a later tax anchor must not affect statutory's
    // already-recorded tax prefix, including the recursive source commitment.
    let late = dir.join("late-primary.json");
    std::fs::write(
        &late,
        r#"{"idempotency_key":"late-primary","effective_date":"2026-03-31",
            "description":"Later primary correction",
            "legs":[{"side":"debit","account":"1000","amount":"900.00 USD"},
            {"side":"credit","account":"3000","amount":"900.00 USD"}]}"#,
    )
    .unwrap();
    ok(
        &books[0],
        &[
            "post",
            "--intent",
            late.to_str().unwrap(),
            "--evidence",
            &documents[0],
        ],
    );
    ok(
        &books[1],
        &[
            "recon",
            "anchor",
            "--parent-book",
            primary,
            "--grant",
            "schema_change",
        ],
    );
    let after = ok(&books[3], &args);
    assert_eq!(data(&after), data(&first));
    assert_eq!(head(&books[2]), original_heads[2]);
    assert_eq!(head(&books[3]), original_heads[3]);
}

#[test]
fn book_to_book_schedule_m1_bridge_and_planted_negatives() {
    static NEXT_RECON: AtomicU64 = AtomicU64::new(0);
    let dir = loop {
        let d = std::env::temp_dir().join(format!(
            "fa-recon-cli-{}-{}",
            std::process::id(),
            NEXT_RECON.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&d) {
            Ok(()) => break d,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create {}: {e}", d.display()),
        }
    };
    let gaap = dir.join("gaap");
    let tax = dir.join("tax");
    ok(&gaap, &["book", "create", "--name", "GAAP Primary"]);
    ok(
        &tax,
        &["book", "create", "--name", "Tax Schedule M-1 Layer"],
    );

    let chart_path = dir.join("chart.json");
    std::fs::write(
        &chart_path,
        r#"{"accounts":[
            {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
            {"code":"1500","name":"Accumulated Depreciation","type":"Asset","unit":"USD"},
            {"code":"3100","name":"Schedule M-1 Tax Clearing","type":"Equity","unit":"USD"},
            {"code":"5000","name":"Depreciation Expense","type":"Expense","unit":"USD"},
            {"code":"6200","name":"Meals and Entertainment","type":"Expense","unit":"USD"}
        ]}"#,
    )
    .unwrap();
    for b in [&gaap, &tax] {
        ok(b, &["chart", "import", chart_path.to_str().unwrap()]);
        ok(b, &["period", "create", "--fiscal-year", "2026"]);
        ok(b, &["period", "open", "FY2026-P03"]);
    }

    let doc_path = dir.join("workpaper.txt");
    std::fs::write(&doc_path, "Q1 2026 fixed-asset and meals schedule").unwrap();
    let gaap_doc = text(
        data(&ok(
            &gaap,
            &[
                "document",
                "add",
                doc_path.to_str().unwrap(),
                "--kind",
                "Memo",
                "--grade",
                "HumanUpload",
            ],
        )),
        "oid",
    )
    .to_string();
    let tax_doc = text(
        data(&ok(
            &tax,
            &[
                "document",
                "add",
                doc_path.to_str().unwrap(),
                "--kind",
                "Memo",
                "--grade",
                "HumanUpload",
            ],
        )),
        "oid",
    )
    .to_string();

    // Post GAAP primary entries: 100.00 USD depreciation + 80.00 USD meals.
    let gaap_entry = dir.join("gaap_q1.json");
    std::fs::write(
        &gaap_entry,
        r#"{
            "idempotency_key": "gaap-q1",
            "effective_date": "2026-03-31",
            "description": "GAAP Q1 depreciation and meals",
            "legs": [
                {"side": "debit", "account": "5000", "amount": "100.00 USD"},
                {"side": "credit", "account": "1500", "amount": "100.00 USD"},
                {"side": "debit", "account": "6200", "amount": "80.00 USD"},
                {"side": "credit", "account": "1000", "amount": "80.00 USD"}
            ]
        }"#,
    )
    .unwrap();
    ok(
        &gaap,
        &[
            "post",
            "--intent",
            gaap_entry.to_str().unwrap(),
            "--evidence",
            &gaap_doc,
        ],
    );

    // Anchor Tax book to GAAP book at current head.
    let anchored = ok(
        &tax,
        &[
            "recon",
            "anchor",
            "--parent-book",
            gaap.to_str().unwrap(),
            "--grant",
            "schema_change",
        ],
    );
    assert_eq!(text(&anchored, "event"), "adjustment_layer_anchored");
    assert_eq!(
        data(&anchored).get("already_recorded"),
        Some(&Json::Bool(false))
    );

    // Post coded Schedule M-1 temporary & permanent adjustments into the Tax layer.
    let m1_depr = dir.join("m1_depr.json");
    std::fs::write(
        &m1_depr,
        r#"{
            "idempotency_key": "m1-macrs-depr",
            "effective_date": "2026-03-31",
            "description": "MACRS bonus depreciation excess over book",
            "legs": [
                {"side": "debit", "account": "5000", "amount": "50.00 USD"},
                {"side": "credit", "account": "1500", "amount": "50.00 USD"}
            ]
        }"#,
    )
    .unwrap();
    ok(
        &tax,
        &[
            "recon",
            "post",
            "--reason-code",
            "M1-TEMP-DEPRECIATION",
            "--intent",
            m1_depr.to_str().unwrap(),
            "--evidence",
            &tax_doc,
        ],
    );

    let m1_meals = dir.join("m1_meals.json");
    std::fs::write(
        &m1_meals,
        r#"{
            "idempotency_key": "m1-meals-50pct",
            "effective_date": "2026-03-31",
            "description": "IRC 274(n) 50% non-deductible meals",
            "legs": [
                {"side": "debit", "account": "3100", "amount": "40.00 USD"},
                {"side": "credit", "account": "6200", "amount": "40.00 USD"}
            ]
        }"#,
    )
    .unwrap();
    ok(
        &tax,
        &[
            "recon",
            "post",
            "--reason-code",
            "M1-PERM-MEALS",
            "--intent",
            m1_meals.to_str().unwrap(),
            "--evidence",
            &tax_doc,
        ],
    );

    // Reconcile via --parent-book and decode canonical BookToBookBridge bytes.
    let native_parent_head = head(&gaap);
    let native_layer_head = head(&tax);
    let reconciled = ok(
        &tax,
        &[
            "recon",
            "book-to-book",
            "--period",
            "FY2026-P03",
            "--parent-book",
            gaap.to_str().unwrap(),
        ],
    );
    assert_eq!(text(&reconciled, "event"), "book_to_book_reconciled");
    assert_eq!(
        head(&gaap),
        native_parent_head,
        "internal source certification is read-only"
    );
    assert_eq!(
        head(&tax),
        native_layer_head,
        "native-source reconciliation is read-only"
    );
    let bridge_data = data(&reconciled);
    let bridge_digest = text(bridge_data, "bridge_digest").to_string();
    let bridge_hex = text(bridge_data, "bytes");
    let bridge_bytes: Vec<u8> = bridge_hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let decoded = fa::BookToBookBridge::decode(&bridge_bytes).expect("decode BookToBookBridge");
    assert_eq!(decoded.canonical_bytes().unwrap(), bridge_bytes);

    let rows = bridge_data.get("rows").and_then(Json::as_arr).unwrap();
    let depr_row = rows.iter().find(|r| text(r, "code") == "5000").unwrap();
    assert_eq!(text(depr_row, "parent_net"), "100.00 USD");
    assert_eq!(text(depr_row, "adjustments_net"), "50.00 USD");
    assert_eq!(text(depr_row, "layered_net"), "150.00 USD");
    let depr_exp = &depr_row.get("explanations").and_then(Json::as_arr).unwrap()[0];
    assert_eq!(text(depr_exp, "reason_code"), "M1-TEMP-DEPRECIATION");
    assert_eq!(depr_exp.get("permanent"), Some(&Json::Bool(false)));

    let meals_row = rows.iter().find(|r| text(r, "code") == "6200").unwrap();
    assert_eq!(text(meals_row, "parent_net"), "80.00 USD");
    assert_eq!(text(meals_row, "adjustments_net"), "-40.00 USD");
    assert_eq!(text(meals_row, "layered_net"), "40.00 USD");
    let meals_exp = &meals_row
        .get("explanations")
        .and_then(Json::as_arr)
        .unwrap()[0];
    assert_eq!(text(meals_exp, "reason_code"), "M1-PERM-MEALS");
    assert_eq!(meals_exp.get("permanent"), Some(&Json::Bool(true)));

    // A supplied certificate must replay against the native parent. Its
    // self-consistent hashes alone grant no cross-book source authority.
    let cert_out = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(&gaap)
        .args(["tb", "--period", "FY2026-P03", "--certify", "--json"])
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .output()
        .expect("certify parent tb");
    assert!(cert_out.status.success());
    let cert_stdout = String::from_utf8(cert_out.stdout).unwrap();
    let cert_line = cert_stdout
        .lines()
        .map(|l| json::parse(l).unwrap())
        .find(|j| text(j, "event") == "report_certificate")
        .expect("report_certificate event");
    let cert_hex = text(data(&cert_line), "bytes");
    let layer_head = head(&tax);
    let parent_head = head(&gaap);
    for args in [
        vec!["recon", "anchor", "--parent-certificate", cert_hex],
        vec![
            "recon",
            "book-to-book",
            "--period",
            "FY2026-P03",
            "--parent-certificate",
            cert_hex,
        ],
    ] {
        let (status, refused) = run(&tax, &args);
        assert_eq!(status, 3, "{}", refused.render());
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-194");
        assert!(text(data(&refused), "message").contains("does not authenticate"));
    }
    let via_cert = ok(
        &tax,
        &[
            "recon",
            "book-to-book",
            "--period",
            "FY2026-P03",
            "--parent-certificate",
            cert_hex,
            "--parent-book",
            gaap.to_str().unwrap(),
        ],
    );
    assert_eq!(text(data(&via_cert), "bridge_digest"), bridge_digest);
    let anchor_retry = ok(
        &tax,
        &[
            "recon",
            "anchor",
            "--parent-book",
            gaap.to_str().unwrap(),
            "--parent-certificate",
            cert_hex,
        ],
    );
    assert_eq!(
        data(&anchor_retry).get("already_recorded"),
        Some(&Json::Bool(true))
    );

    // Plant a balanced false parent output and repair both public hashes.
    // The artifact still decodes; only replay against the original parent
    // can establish that these monetary amounts were never its report.
    let certificate_bytes: Vec<u8> = cert_hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect();
    let mut forged = fa::ReportCertificate::decode(&certificate_bytes).unwrap();
    let mut false_output = fa_registers::TrialBalance::decode(&forged.output).unwrap();
    let debit = false_output
        .rows
        .iter_mut()
        .find(|row| row.code == "5000")
        .unwrap();
    debit.debits += 1;
    let unit = debit.unit_id;
    false_output
        .rows
        .iter_mut()
        .find(|row| row.code == "1500")
        .unwrap()
        .credits += 1;
    let totals = false_output.unit_totals.get_mut(&unit).unwrap();
    totals.0 += 1;
    totals.1 += 1;
    forged.output = false_output.canonical_bytes().unwrap();
    forged.output_digest = fa_verify::blake3::hash_parts(b"fa:report-output:v1", &[&forged.output]);
    let body = forged.canonical_bytes().unwrap();
    forged.digest = fa_verify::blake3::hash_parts(
        fa::certificate::CERTIFICATE_FORMAT,
        &[&body[..body.len() - 32]],
    );
    let forged_bytes = forged.canonical_bytes().unwrap();
    fa::ReportCertificate::decode(&forged_bytes).expect("forgery has consistent public hashes");
    let forged_hex = fa_verify::blake3::hex(&forged_bytes);
    for args in [
        vec![
            "recon",
            "anchor",
            "--parent-book",
            gaap.to_str().unwrap(),
            "--parent-certificate",
            forged_hex.as_str(),
        ],
        vec![
            "recon",
            "book-to-book",
            "--period",
            "FY2026-P03",
            "--parent-book",
            gaap.to_str().unwrap(),
            "--parent-certificate",
            forged_hex.as_str(),
        ],
    ] {
        let (status, refused) = run(&tax, &args);
        assert_ne!(status, 0, "{}", refused.render());
        assert_eq!(text(&refused, "event"), "error");
    }
    assert_eq!(
        head(&tax),
        layer_head,
        "parent reads and refusals do not publish in the layer"
    );
    assert_eq!(
        head(&gaap),
        parent_head,
        "parent verification never publishes in its source"
    );

    let absent_parent = dir.join("unopened-parent");
    let authority = LaunchAuthority::new(
        tax.clone(),
        None,
        "tax-reader",
        LaunchProfile::Preparer,
        &["read", "reconcile"],
    )
    .unwrap();
    let bound_args: Vec<_> = [
        "recon",
        "book-to-book",
        "--period",
        "FY2026-P03",
        "--parent-book",
        absent_parent.to_str().unwrap(),
        "--json",
    ]
    .into_iter()
    .map(str::to_string)
    .collect();
    let (status, output) = fa_with_authority(&bound_args, Files::default(), &authority, true);
    assert_eq!(status, 2, "{output:?}");
    assert!(
        !absent_parent.exists(),
        "a bound request cannot open a second host book"
    );

    // Planted negative 1 (ParentBookRestated): advancing GAAP parent without re-anchoring refuses.
    let gaap_late = dir.join("gaap_late.json");
    std::fs::write(
        &gaap_late,
        r#"{
            "idempotency_key": "gaap-late-meals",
            "effective_date": "2026-03-31",
            "description": "Late Q1 meal receipt",
            "legs": [
                {"side": "debit", "account": "6200", "amount": "20.00 USD"},
                {"side": "credit", "account": "1000", "amount": "20.00 USD"}
            ]
        }"#,
    )
    .unwrap();
    ok(
        &gaap,
        &[
            "post",
            "--intent",
            gaap_late.to_str().unwrap(),
            "--evidence",
            &gaap_doc,
        ],
    );
    let (restated_exit, restated_err) = run(
        &tax,
        &[
            "recon",
            "book-to-book",
            "--period",
            "FY2026-P03",
            "--parent-book",
            gaap.to_str().unwrap(),
        ],
    );
    assert_eq!(restated_exit, 3, "{}", restated_err.render());
    assert_eq!(text(data(&restated_err), "refusal_id"), "FA-REF-194");

    // Re-anchoring Tax to the new GAAP frontier restores reconciliation.
    ok(
        &tax,
        &[
            "recon",
            "anchor",
            "--parent-book",
            gaap.to_str().unwrap(),
            "--grant",
            "schema_change",
        ],
    );
    let reanchored = ok(
        &tax,
        &[
            "recon",
            "book-to-book",
            "--period",
            "FY2026-P03",
            "--parent-book",
            gaap.to_str().unwrap(),
        ],
    );
    assert_eq!(text(&reanchored, "event"), "book_to_book_reconciled");

    // Planted negative 2 (UnexplainedBookDifference): uncoded `fa post` in Tax layer refuses.
    let uncoded = dir.join("tax_uncoded.json");
    std::fs::write(
        &uncoded,
        r#"{
            "idempotency_key": "tax-uncoded-diff",
            "effective_date": "2026-03-31",
            "description": "Uncoded manual tax plug",
            "legs": [
                {"side": "debit", "account": "5000", "amount": "10.00 USD"},
                {"side": "credit", "account": "1500", "amount": "10.00 USD"}
            ]
        }"#,
    )
    .unwrap();
    ok(
        &tax,
        &[
            "post",
            "--intent",
            uncoded.to_str().unwrap(),
            "--evidence",
            &tax_doc,
        ],
    );
    let (unexp_exit, unexp_err) = run(
        &tax,
        &[
            "recon",
            "book-to-book",
            "--period",
            "FY2026-P03",
            "--parent-book",
            gaap.to_str().unwrap(),
        ],
    );
    assert_eq!(unexp_exit, 3, "{}", unexp_err.render());
    assert_eq!(text(data(&unexp_err), "refusal_id"), "FA-REF-194");
    assert!(
        text(data(&unexp_err), "message").contains("unexplained book-to-book difference"),
        "{}",
        unexp_err.render()
    );
}
