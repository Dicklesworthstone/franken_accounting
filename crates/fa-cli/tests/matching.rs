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
        .chunks_exact(2)
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
