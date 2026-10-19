//! Original legacy exports through the real CLI and native migration laws.
//!
//! These tests retain independent source/TB documents, approve the exact saved
//! proposals as separate principals, reopen between commands, and prove that
//! staging stays invisible until native finalization. Negative cases inspect
//! the durable frontier so parser, mapping, authorization and package failures
//! cannot masquerade as partial imports.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa::{Book, BookKeys, Entropy};
use fa_cli::authority::{LaunchAuthority, LaunchProfile};
use fa_cli::cli::{Files, Stdin};
use fa_cli::entry::fa_with_authority;
use fa_cli::json::{self, Json, obj, s};
use fa_journal::DocumentRead;
use fa_model::{Entry, Erasable, Oid, Reader, Writer};
use fa_policy::Capability;
use fgdb_types::VId;

const OPENING: &str = "FY2026-OPEN";
const LEGACY_CASH: &str = "Private legacy checking account";
const LEGACY_EQUITY: &str = "Private legacy opening equity";
const QB: &str = "Transaction ID,Date,Account,Debit,Credit,Currency,Memo/Description,Created At,Created By\nprivate-source-entry-one,2025-12-20,Private legacy checking account,100.00,,USD,Private retained cash memo,2025-12-20T12:30:00Z,private-legacy-author\nprivate-source-entry-one,2025-12-20,Private legacy opening equity,,100.00,USD,Private retained equity memo,2025-12-20T12:30:00Z,private-legacy-author\nprivate-source-entry-two,2025-12-29,Private legacy checking account,25.50,,USD,Second cash memo,2025-12-29T09:00:00Z,private-legacy-author\nprivate-source-entry-two,2025-12-29,Private legacy opening equity,,25.50,USD,Second equity memo,2025-12-29T09:00:00Z,private-legacy-author\n";
const COLUMNS: &str = "[columns]\nsource_system = \"legacy-csv\"\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\nrecorded_at_column = \"recorded\"\naccount_column = \"account\"\nsigned_amount_column = \"amount\"\ndescription_column = \"description\"\nmemo_column = \"memo\"\nentered_by_column = \"entered\"\napproved_by_column = \"approved\"\n";
const GENERIC: &str = "entry,date,recorded,account,amount,description,memo,entered,approved\nprivate-source-entry-one,2025-12-30,2025-12-30T15:20:00Z,Private legacy checking account,125.50,Private retained description,Private retained cash memo,legacy-preparer,legacy-reviewer\nprivate-source-entry-one,2025-12-30,2025-12-30T15:20:00Z,Private legacy opening equity,-125.50,Private retained description,Private retained equity memo,legacy-preparer,legacy-reviewer\n";

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

fn parse_oid(text: &str) -> Oid {
    assert_eq!(text.len(), 64);
    let mut bytes = [0; 32];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    Oid(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    unit: String,
    source: String,
    trial_balance: String,
    run_vid: String,
    format: String,
}

impl Fixture {
    fn new(format: &str, source: &str, unit: &str, kind: &str, go_live: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let path = std::env::temp_dir().join(format!(
                "fa-legacy-migration-cli-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => break path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create retained fixture {}: {error}", path.display()),
            }
        };
        let book = dir.join("book");
        ok(
            &book,
            &[
                "book",
                "create",
                "--name",
                "Legacy opening import",
                "--base-unit",
                unit,
                "--opening-date",
                go_live,
            ],
        );
        let mut fixture = Self {
            dir,
            book,
            unit: unit.into(),
            source: String::new(),
            trial_balance: String::new(),
            run_vid: String::new(),
            format: format.into(),
        };
        let chart = fixture.file("chart.json", &format!(r#"{{"accounts":[{{"code":"1000","name":"Cash","type":"Asset","unit":"{unit}"}},{{"code":"3000","name":"Opening equity","type":"Equity","unit":"{unit}"}}]}}"#));
        ok(&fixture.book, &["chart", "import", &chart]);
        ok(
            &fixture.book,
            &["period", "create", "--fiscal-year", "2026"],
        );
        fixture.source = fixture.document("original-source.txt", source, kind);
        fixture.trial_balance = fixture.document(
            "independent-trial-balance.csv",
            &format!("account,unit,debit,credit\n1000,{unit},125.50,\n3000,{unit},,125.50\n"),
            "Spreadsheet",
        );
        fixture.run_vid = fixture.open_run("opening-import", "125.50");
        fixture
    }

    fn quickbooks() -> Self {
        Self::new("quickbooks-csv", QB, "USD", "Spreadsheet", "2026-07-01")
    }

    fn file(&self, name: &str, content: &str) -> String {
        let path = self.dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.display().to_string()
    }

    fn document(&self, name: &str, content: &str, kind: &str) -> String {
        let path = self.file(name, content);
        let output = ok(
            &self.book,
            &[
                "document",
                "add",
                &path,
                "--kind",
                kind,
                "--mime",
                "text/csv",
                "--grade",
                "HumanUpload",
            ],
        );
        text(data(&output), "oid").into()
    }

    fn open_run(&self, key: &str, total: &str) -> String {
        let system = if self.format == "csv" {
            "legacy-csv"
        } else {
            &self.format
        };
        let intent = obj(vec![
            ("run_key", s(key)),
            ("source_system", s(system)),
            ("mode", s("OpeningOnly")),
            ("trial_balance", s(&self.trial_balance)),
            ("opening_date", s("2026-01-01")),
            (
                "lines",
                Json::Arr(vec![
                    obj(vec![
                        ("account", s("1000")),
                        ("unit", s(&self.unit)),
                        ("debit", s(total)),
                    ]),
                    obj(vec![
                        ("account", s("3000")),
                        ("unit", s(&self.unit)),
                        ("credit", s(total)),
                    ]),
                ]),
            ),
        ]);
        let path = self.file(&format!("{key}.json"), &intent.render());
        let opened = ok(&self.book, &["migrate", "open", "--intent", &path]);
        text(data(&opened), "run_vid").into()
    }

    fn intent(&self) -> Json {
        let mut fields = vec![
            ("run", s(format!("MR:{}", self.run_vid))),
            ("source", s(format!("D:{}", self.source))),
            ("format", s(&self.format)),
            (
                "account_map",
                obj(vec![(LEGACY_CASH, s("1000")), (LEGACY_EQUITY, s("3000"))]),
            ),
        ];
        if self.format == "csv" {
            fields.push(("column_map", s(COLUMNS)));
        }
        obj(fields)
    }

    fn prepare(&self) -> Json {
        let path = self.file("import.json", &self.intent().render());
        ok(
            &self.book,
            &[
                "migrate", "import", "--action", "prepare", "--intent", &path,
            ],
        )
    }

    fn approve(&self, digest: &str, principal: &str) -> String {
        let approved = ok(
            &self.book,
            &["approve", "--proposal", digest, "--as", principal],
        );
        text(data(&approved), "approval_vid").into()
    }

    fn show(&self, package: &str) -> Json {
        ok(
            &self.book,
            &[
                "migrate",
                "import",
                "--action",
                "show",
                "--package",
                package,
            ],
        )
    }

    fn stage(&self, package: &str, index: usize, approvals: &[&str]) -> Json {
        let index = index.to_string();
        let mut args = vec![
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--chunk",
            &index,
        ];
        for approval in approvals {
            args.extend(["--approval", approval]);
        }
        ok(&self.book, &args)
    }

    fn cash(&self, known_at: Option<i128>) -> String {
        let at = known_at.map(|value| value.to_string());
        let mut args = vec!["tb", "--period", OPENING];
        if let Some(at) = &at {
            args.extend(["--as-known-at", at]);
        }
        let result = ok(&self.book, &args);
        rows(data(&result), "rows")
            .iter()
            .find(|row| text(row, "code") == "1000")
            .map_or_else(
                || format!("0.00 {}", self.unit),
                |row| text(row, "net").to_string(),
            )
    }

    fn open(&self) -> Book {
        Book::open_dir(
            &self.book,
            BookKeys::load(&self.book.join("book.keys")).unwrap(),
            Entropy::deterministic(223),
        )
        .unwrap()
    }

    fn complete(&self) {
        let prepared = self.prepare();
        assert_eq!(text(&prepared, "event"), "migration_import_prepared");
        let package = text(data(&prepared), "package_oid").to_string();
        assert_eq!(integer(data(&prepared), "recorded_count"), 0);
        let before_prepare_retry = head(&self.book);
        let repeated_prepare = self.prepare();
        assert_eq!(text(data(&repeated_prepare), "package_oid"), package);
        assert_eq!(
            integer(data(&repeated_prepare), "recorded_at"),
            integer(data(&prepared), "recorded_at")
        );
        assert_eq!(
            data(&repeated_prepare).get("already_recorded"),
            Some(&Json::Bool(true)),
            "a lost preparation response never regenerates approval bytes"
        );
        assert_eq!(
            data(&repeated_prepare).get("chunks"),
            data(&prepared).get("chunks")
        );
        assert_eq!(head(&self.book), before_prepare_retry);
        assert_eq!(self.cash(None), format!("0.00 {}", self.unit));
        let shown = self.show(&package);
        assert_eq!(data(&shown).get("chunks"), data(&prepared).get("chunks"));
        let count = rows(data(&prepared), "chunks").len();
        assert!(count > 0);
        let mut first_approvals = Vec::new();
        for (index, chunk) in rows(data(&prepared), "chunks").iter().enumerate() {
            assert_eq!(text(chunk, "effective_date"), "2026-01-01");
            assert!(text(chunk, "document_date").starts_with("2025-12-"));
            assert_eq!(integer(chunk, "leg_count"), 2);
            let legs = rows(chunk, "legs");
            assert_eq!(text(&legs[0], "account"), "1000");
            assert_eq!(text(&legs[0], "side"), "debit");
            assert_eq!(text(&legs[1], "account"), "3000");
            assert_eq!(text(&legs[1], "side"), "credit");
            let digest = text(chunk, "proposal_digest");
            let first = self.approve(digest, "independent-reviewer-one");
            let second = self.approve(digest, "independent-reviewer-two");
            let staged = self.stage(&package, index, &[&first, &second]);
            assert_eq!(text(&staged, "event"), "migration_import_staged");
            assert_eq!(text(data(&staged), "entry_vid"), text(chunk, "entry_vid"));
            assert_eq!(text(data(&staged), "proposal_digest"), digest);
            assert_eq!(
                data(&staged).get("already_recorded"),
                Some(&Json::Bool(false))
            );
            assert_eq!(
                integer(data(&staged), "recorded_count"),
                (index + 1) as i128
            );
            assert_eq!(
                data(&staged).get("ready_to_finalize"),
                Some(&Json::Bool(index + 1 == count))
            );
            assert_eq!(
                self.cash(None),
                format!("0.00 {}", self.unit),
                "staging never activates balances"
            );
            let before_retry = head(&self.book);
            let repeated = self.stage(&package, index, &[&first, &second]);
            assert_eq!(
                data(&repeated).get("already_recorded"),
                Some(&Json::Bool(true))
            );
            assert_eq!(
                integer(data(&repeated), "recorded_at"),
                integer(data(&staged), "recorded_at")
            );
            assert_eq!(head(&self.book), before_retry);
            if index == 0 {
                first_approvals = vec![first, second];
            }
        }
        let staged = self.show(&package);
        assert_eq!(integer(data(&staged), "recorded_count"), count as i128);
        assert_eq!(data(&staged).get("ties_out"), Some(&Json::Bool(true)));
        assert_eq!(text(data(&staged), "run_state"), "Open");
        let before_finalize = head(&self.book);
        let plan = self.dir.join("finalize.plan").display().to_string();
        let planned = ok(
            &self.book,
            &["migrate", "finalize", &self.run_vid, "--plan-out", &plan],
        );
        let digest = text(data(&planned), "proposal_digest");
        let first = self.approve(digest, "finalize-reviewer-one");
        let second = self.approve(digest, "finalize-reviewer-two");
        let finalized = ok(
            &self.book,
            &[
                "migrate",
                "finalize",
                &self.run_vid,
                "--plan",
                &plan,
                "--approval",
                &first,
                "--approval",
                &second,
            ],
        );
        assert_eq!(text(data(&finalized), "to"), "Finalized");
        assert_eq!(self.cash(None), format!("125.50 {}", self.unit));
        assert_eq!(
            self.cash(Some(before_finalize)),
            format!("0.00 {}", self.unit)
        );
        assert_eq!(text(data(&self.show(&package)), "run_state"), "Finalized");
        let before_retry = head(&self.book);
        let repeated = self.stage(&package, 0, &[&first_approvals[0], &first_approvals[1]]);
        assert_eq!(
            data(&repeated).get("already_recorded"),
            Some(&Json::Bool(true)),
            "exact retained chunk retries survive run finalization"
        );
        assert_eq!(head(&self.book), before_retry);
        ok(&self.book, &["verify", "registers", "--period", OPENING]);
    }
}

#[test]
fn all_five_legacy_exports_complete_the_approved_opening_workflow() {
    let iif = "!TRNS\tTRNSID\tTRNSTYPE\tDATE\tACCNT\tAMOUNT\tMEMO\tTIMESTAMP\n!SPL\tSPLID\tTRNSTYPE\tDATE\tACCNT\tAMOUNT\tMEMO\n!ENDTRNS\nTRNS\tprivate-source-entry-one\tGENERAL JOURNAL\t2025-12-20\tPrivate legacy checking account\t125.50\tPrivate retained cash memo\t2025-12-20T10:00:00Z\nSPL\tprivate-source-split\tGENERAL JOURNAL\t2025-12-20\tPrivate legacy opening equity\t-125.50\tPrivate retained equity memo\nENDTRNS\n";
    let xero = "JournalNumber,JournalDate,CreatedDateUTC,AccountCode,Description,Debit,Credit,Gross,Reference,Currency,CreatedBy\nprivate-source-entry-one,2025-12-20,2025-12-20T09:15:00Z,Private legacy checking account,Private retained description,125.50,,125.50,Private retained cash memo,USD,private-legacy-author\nprivate-source-entry-one,2025-12-20,2025-12-20T09:15:00Z,Private legacy opening equity,Private retained description,,125.50,-125.50,Private retained equity memo,USD,private-legacy-author\n";
    let netsuite = "Internal ID,Date,System Date,Document Number,Account,Debit,Credit,Currency,Memo,Created By,Approved By\nprivate-source-entry-one,2025-12-20,2025-12-20T18:00:00Z,Private retained cash memo,Private legacy checking account,125.50,,USD,Private retained description,legacy-preparer,legacy-reviewer\nprivate-source-entry-one,2025-12-20,2025-12-20T18:00:00Z,Private retained equity memo,Private legacy opening equity,,125.50,USD,Private retained description,legacy-preparer,legacy-reviewer\n";
    for (format, source) in [
        ("quickbooks-iif", iif),
        ("quickbooks-csv", QB),
        ("xero-csv", xero),
        ("netsuite-csv", netsuite),
        ("csv", GENERIC),
    ] {
        Fixture::new(format, source, "USD", "Spreadsheet", "2026-07-01").complete();
    }
}

#[test]
fn generic_csv_uses_the_book_base_unit_without_an_implicit_usd_fallback() {
    let fixture = Fixture::new("csv", GENERIC, "EUR", "Spreadsheet", "2026-07-01");
    let mut conflict = fixture.intent();
    set_field(
        &mut conflict,
        "column_map",
        s(format!("{COLUMNS}default_unit = \"USD\"\n")),
    );
    let path = fixture.file("conflicting-default.json", &conflict.render());
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert!(refused.render().contains("default_unit conflicts"));
    assert_eq!(head(&fixture.book), before);
    fixture.complete();
}

fn set_field(value: &mut Json, key: &str, replacement: Json) {
    let Json::Obj(fields) = value else {
        panic!("object expected");
    };
    if let Some((_, value)) = fields.iter_mut().find(|(name, _)| name == key) {
        *value = replacement;
    } else {
        fields.push((key.into(), replacement));
    }
}

#[test]
fn invalid_source_mapping_and_trial_balance_never_publish_a_partial_package() {
    let fixture = Fixture::quickbooks();
    let original = fixture.intent();
    let mut cases = Vec::new();
    let mut bad = original.clone();
    set_field(&mut bad, "account_map", obj(vec![(LEGACY_CASH, s("1000"))]));
    cases.push(("unmapped-account", bad));
    let mut bad = original.clone();
    set_field(
        &mut bad,
        "account_map",
        obj(vec![(LEGACY_CASH, s("9999")), (LEGACY_EQUITY, s("3000"))]),
    );
    cases.push(("absent-target-leaf", bad));
    let mut bad = original.clone();
    set_field(
        &mut bad,
        "run",
        s(fixture.open_run("different-tb", "200.00")),
    );
    cases.push(("declared-tb-mismatch", bad));
    let future = fixture.document(
        "future.csv",
        &QB.replace("2025-12-29", "2026-02-01"),
        "Spreadsheet",
    );
    let mut bad = original.clone();
    set_field(&mut bad, "source", s(future));
    cases.push(("post-opening-source", bad));
    let conflicting_leg = fixture.document(
        "conflicting-leg-date.csv",
        &QB.replacen(
            "private-source-entry-one,2025-12-20,Private legacy opening equity",
            "private-source-entry-one,2026-02-01,Private legacy opening equity",
            1,
        ),
        "Spreadsheet",
    );
    let mut bad = original.clone();
    set_field(&mut bad, "source", s(conflicting_leg));
    cases.push(("later-leg-cannot-hide-a-future-date", bad));
    let fractional = fixture.document(
        "fractional.csv",
        &QB.replace("100.00", "100.001"),
        "Spreadsheet",
    );
    let mut bad = original.clone();
    set_field(&mut bad, "source", s(fractional));
    cases.push(("precision-loss", bad));
    let unbalanced = fixture.document(
        "unbalanced.csv",
        &QB.replacen(",100.00,,USD", ",101.00,,USD", 1),
        "Spreadsheet",
    );
    let mut bad = original.clone();
    set_field(&mut bad, "source", s(unbalanced));
    cases.push(("unbalanced-source", bad));
    let mut bad = original.clone();
    set_field(&mut bad, "source", s(&fixture.trial_balance));
    cases.push(("source-is-own-independent-tb", bad));
    let mut bad = original.clone();
    set_field(&mut bad, "source_file", s("must-not-be-opened.csv"));
    cases.push(("undeclared-host-path", bad));
    for (name, intent) in cases {
        let path = fixture.file(&format!("{name}.json"), &intent.render());
        let before = head(&fixture.book);
        let (status, output) = run(
            &fixture.book,
            &[
                "migrate", "import", "--action", "prepare", "--intent", &path,
            ],
        );
        assert_eq!(status, 2, "{name}: {}", output.render());
        assert_eq!(text(&output, "event"), "error");
        assert_eq!(
            head(&fixture.book),
            before,
            "{name}: no package or chunk may survive a refused preparation"
        );
    }
    let prepared = fixture.prepare();
    assert_eq!(
        integer(data(&prepared), "chunk_count"),
        2,
        "failed attempts do not consume the run"
    );
}

#[test]
fn locked_opening_period_and_nonoverwriting_output_are_explicit_preparation_boundaries() {
    let future_period = Fixture::new("quickbooks-csv", QB, "USD", "Spreadsheet", "2026-01-01");
    let intent = future_period.file("import.json", &future_period.intent().render());
    let before = head(&future_period.book);
    let (status, refused) = run(
        &future_period.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &intent,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert!(refused.render().contains("Locked"));
    assert_eq!(head(&future_period.book), before);

    let fixture = Fixture::quickbooks();
    let path = fixture.file("import.json", &fixture.intent().render());
    let existing = fixture.file("existing.package", "preserve this unrelated file");
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "prepare",
            "--intent",
            &path,
            "--plan-out",
            &existing,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert_eq!(
        std::fs::read_to_string(&existing).unwrap(),
        "preserve this unrelated file"
    );
    assert_eq!(head(&fixture.book), before);
    let copy = fixture.dir.join("fresh.package").display().to_string();
    let prepared = ok(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "prepare",
            "--intent",
            &path,
            "--plan-out",
            &copy,
        ],
    );
    assert_eq!(text(data(&prepared), "plan"), copy);
    let raw = std::fs::read(&copy).unwrap();
    for private in [
        LEGACY_CASH,
        LEGACY_EQUITY,
        "private-source-entry-one",
        "Private retained cash memo",
        "private-legacy-author",
    ] {
        assert!(
            !raw.windows(private.len())
                .any(|window| window == private.as_bytes()),
            "private source/configuration text must be sealed: {private}"
        );
    }
    let mut book = fixture.open();
    let capability = Capability::embedded(VId(501), &["read"]).unwrap();
    let DocumentRead::Full(document) = book
        .read_document_for(
            &capability,
            &parse_oid(text(data(&prepared), "package_oid")),
        )
        .unwrap()
        .unwrap()
    else {
        panic!("the exact package must be retained");
    };
    assert_eq!(document.bytes, raw);
    assert_eq!(
        hex(&document.doc_commit()),
        text(data(&prepared), "package_commit")
    );
}

#[test]
fn chunk_approvals_are_independent_digest_bound_and_staging_resumes_the_same_bytes() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let package = text(data(&prepared), "package_oid");
    let chunks = rows(data(&prepared), "chunks");
    let digest = text(&chunks[0], "proposal_digest");
    let first = fixture.approve(digest, "independent-reviewer-one");
    let second = fixture.approve(digest, "independent-reviewer-two");
    let own = fixture.approve(digest, "operator");
    let other_digest = fixture.approve(
        text(&chunks[1], "proposal_digest"),
        "independent-reviewer-three",
    );
    for approvals in [
        vec![],
        vec![first.as_str()],
        vec![first.as_str(), first.as_str()],
        vec![own.as_str(), first.as_str()],
        vec![first.as_str(), other_digest.as_str()],
    ] {
        let mut args = vec![
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--chunk",
            "0",
        ];
        for approval in approvals {
            args.extend(["--approval", approval]);
        }
        let before = head(&fixture.book);
        let (status, refused) = run(&fixture.book, &args);
        assert_ne!(status, 0, "{}", refused.render());
        assert_eq!(
            head(&fixture.book),
            before,
            "a refused chunk leaves no partial entry"
        );
        assert_eq!(integer(data(&fixture.show(package)), "recorded_count"), 0);
    }
    let staged = fixture.stage(package, 0, &[&first, &second]);
    let before = head(&fixture.book);
    let repeated = fixture.stage(package, 0, &[&first, &second]);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        integer(data(&staged), "recorded_at"),
        integer(data(&repeated), "recorded_at")
    );
    assert_eq!(head(&fixture.book), before);
    let repeated_prepare = fixture.prepare();
    assert_eq!(text(data(&repeated_prepare), "package_oid"), package);
    assert_eq!(
        data(&repeated_prepare).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(integer(data(&repeated_prepare), "recorded_count"), 1);
    assert_eq!(
        text(
            &rows(data(&repeated_prepare), "chunks")[0],
            "proposal_digest"
        ),
        text(&chunks[0], "proposal_digest")
    );
    assert_eq!(head(&fixture.book), before);
    let mut changed_mapping = fixture.intent();
    set_field(
        &mut changed_mapping,
        "account_map",
        obj(vec![
            (LEGACY_CASH, s("1000")),
            (LEGACY_EQUITY, s("3000")),
            ("unused additional mapping", s("1000")),
        ]),
    );
    let path = fixture.file("changed-mapping.json", &changed_mapping.render());
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert!(refused.render().contains("different source or mapping"));
    assert_eq!(head(&fixture.book), before);
    assert_eq!(fixture.cash(None), "0.00 USD");
    let incomplete = fixture
        .dir
        .join("incomplete-finalize.plan")
        .display()
        .to_string();
    let (status, _) = run(
        &fixture.book,
        &[
            "migrate",
            "finalize",
            &fixture.run_vid,
            "--plan-out",
            &incomplete,
        ],
    );
    assert_ne!(status, 0, "an incomplete package cannot activate the run");
    assert_eq!(head(&fixture.book), before);
    assert_eq!(text(data(&fixture.show(package)), "run_state"), "Open");
    let abandon_plan = fixture.dir.join("abandon.plan").display().to_string();
    ok(
        &fixture.book,
        &[
            "migrate",
            "abandon",
            &fixture.run_vid,
            "--plan-out",
            &abandon_plan,
        ],
    );
    let abandoned = ok(
        &fixture.book,
        &[
            "migrate",
            "abandon",
            &fixture.run_vid,
            "--plan",
            &abandon_plan,
        ],
    );
    assert_eq!(text(data(&abandoned), "to"), "Abandoned");
    assert_eq!(fixture.cash(None), "0.00 USD");
    let shown = fixture.show(package);
    assert_eq!(text(data(&shown), "run_state"), "Abandoned");
    assert_eq!(
        integer(data(&shown), "recorded_count"),
        1,
        "abandon preserves durable staged entries"
    );
    let before = head(&fixture.book);
    let repeated = fixture.stage(package, 0, &[&first, &second]);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&repeated), "run_state"), "Abandoned");
    assert_eq!(head(&fixture.book), before);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--chunk",
            "1",
        ],
    );
    assert_ne!(status, 0, "{}", refused.render());
    assert_eq!(head(&fixture.book), before);
}

#[test]
fn governed_original_sources_remain_required_after_a_readable_package_is_retained() {
    let fixture = Fixture::new("quickbooks-csv", QB, "USD", "BankStatement", "2026-07-01");
    let path = fixture.file("import.json", &fixture.intent().render());
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(status, 3, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-142");
    assert!(!refused.render().contains("private-source-entry-one"));
    assert_eq!(head(&fixture.book), before);
    let prepared = ok(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "prepare",
            "--intent",
            &path,
            "--grant",
            "privileged",
        ],
    );
    let package = text(data(&prepared), "package_oid");
    for args in [
        vec![
            "migrate",
            "import",
            "--action",
            "show",
            "--package",
            package,
        ],
        vec![
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--chunk",
            "0",
        ],
    ] {
        let before = head(&fixture.book);
        let (status, refused) = run(&fixture.book, &args);
        assert_eq!(status, 3, "{}", refused.render());
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-142");
        assert!(!refused.render().contains(LEGACY_CASH));
        assert_eq!(head(&fixture.book), before);
    }
    let shown = ok(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "show",
            "--package",
            package,
            "--grant",
            "privileged",
        ],
    );
    assert_eq!(integer(data(&shown), "chunk_count"), 2);
}

#[test]
fn launch_templates_cannot_self_grant_migration_or_consume_input_before_admission() {
    let fixture = Fixture::quickbooks();
    for profile in [LaunchProfile::Agent, LaunchProfile::Preparer] {
        assert!(
            LaunchAuthority::new(
                fixture.book.clone(),
                None,
                "migration-bound",
                profile,
                &["read", "post", "migrate"]
            )
            .is_err(),
            "launch ceilings do not acquire migrate"
        );
        let authority = LaunchAuthority::new(
            fixture.book.clone(),
            None,
            "migration-bound",
            profile,
            &["read", "post"],
        )
        .unwrap();
        let args = [
            "migrate", "import", "--action", "prepare", "--intent", "-", "--json",
        ]
        .map(str::to_string);
        let before = head(&fixture.book);
        let (status, captured) = fa_with_authority(
            &args,
            Files {
                cwd: Some(fixture.dir.clone()),
                stdin: Stdin::Missing,
            },
            &authority,
            true,
        );
        assert_eq!(status, 7, "{captured:?}");
        let output = json::parse(captured.stdout.lines().last().unwrap()).unwrap();
        assert_eq!(text(data(&output), "refusal_id"), "FA-REF-011");
        assert!(!captured.stdout.contains("no input reached the daemon"));
        assert_eq!(head(&fixture.book), before);
    }
}

// Create cryptographically well-formed but dishonest generated material as a
// hostile native caller could. Rehashing both Entry envelopes and the Document
// is deliberately insufficient: the CLI must replay the original source.
fn forged_package(fixture: &Fixture, package: &str, change_memo: bool) -> String {
    let mut book = fixture.open();
    let cap = Capability::embedded(VId(502), &["read"]).unwrap();
    let DocumentRead::Full(mut document) = book
        .read_document_for(&cap, &parse_oid(package))
        .unwrap()
        .unwrap()
    else {
        panic!("full package");
    };
    let mut reader = Reader::new(&document.bytes);
    let domain: [u8; b"FA-LEGACY-OPENING-IMPORT\0".len()] = reader.fixed("domain").unwrap();
    assert_eq!(&domain, b"FA-LEGACY-OPENING-IMPORT\0");
    assert_eq!(reader.u16("version").unwrap(), 1);
    let _: [u8; 16] = reader.fixed("book").unwrap();
    reader.u128("run").unwrap();
    let _: [u8; 32] = reader.fixed("run body").unwrap();
    let _: [u8; 32] = reader.fixed("source").unwrap();
    let _: [u8; 32] = reader.fixed("source commitment").unwrap();
    let _: Erasable<String> = Erasable::decode(&mut reader, 1024 * 1024).unwrap();
    let count = reader.count(4096, "proposals").unwrap();
    let prefix = document.bytes[..reader.offset()].to_vec();
    let mut proposals = Vec::new();
    for _ in 0..count {
        proposals.push(
            Entry::decode(
                reader
                    .bytes(fa_model::limits::MAX_ENTRY_BYTES, "proposal")
                    .unwrap(),
            )
            .unwrap()
            .proposal,
        );
    }
    reader.finish().unwrap();
    if change_memo {
        proposals[0].legs[0].memo = Some(book.seal_text("forged private source memo").unwrap());
    } else {
        proposals[0].legs[0].amount.mantissa += 1;
        proposals[0].legs[1].amount.mantissa += 1;
        proposals[0].unit_totals =
            fa_model::EntryPayload::fold_unit_totals(&proposals[0].legs).unwrap();
    }
    let mut writer = Writer::new();
    writer.fixed(&prefix);
    for proposal in proposals {
        writer.bytes(&proposal.seal(Vec::new(), None).unwrap().encode().unwrap());
    }
    document.bytes = writer.finish().unwrap();
    let added = book.add_document(&document).unwrap().unwrap();
    hex(&added.oid.0)
}

#[test]
fn recomputed_package_and_entry_hashes_do_not_authorize_changed_amounts_or_private_provenance() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let original = text(data(&prepared), "package_oid");
    for private_memo in [false, true] {
        let forged = forged_package(&fixture, original, private_memo);
        assert_ne!(forged, original);
        for action in ["show", "stage"] {
            let mut args = vec![
                "migrate",
                "import",
                "--action",
                action,
                "--package",
                &forged,
            ];
            if action == "stage" {
                args.extend(["--chunk", "0"]);
            }
            let before = head(&fixture.book);
            let (status, refused) = run(&fixture.book, &args);
            assert_eq!(status, 8, "{}", refused.render());
            assert!(refused.render().contains("source"));
            assert_eq!(head(&fixture.book), before);
        }
    }
    assert_eq!(integer(data(&fixture.show(original)), "recorded_count"), 0);
    assert_eq!(fixture.cash(None), "0.00 USD");
}
