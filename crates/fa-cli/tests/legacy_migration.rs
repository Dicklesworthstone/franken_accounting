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
use fa_model::{Entry, EntryPayload, Erasable, Oid, Reader, Writer};
use fa_policy::Capability;
use fgdb_types::VId;

const OPENING: &str = "FY2026-OPEN";
const LEGACY_CASH: &str = "Private legacy checking account";
const LEGACY_EQUITY: &str = "Private legacy opening equity";
const LEGACY_REVENUE: &str = "Private legacy revenue";
const LEGACY_EXPENSE: &str = "Private legacy expense";
const QB: &str = "Transaction ID,Date,Account,Debit,Credit,Currency,Memo/Description,Created At,Created By\nprivate-source-entry-one,2025-12-20,Private legacy checking account,100.00,,USD,Private retained cash memo,2025-12-20T12:30:00Z,private-legacy-author\nprivate-source-entry-one,2025-12-20,Private legacy opening equity,,100.00,USD,Private retained equity memo,2025-12-20T12:30:00Z,private-legacy-author\nprivate-source-entry-two,2025-12-29,Private legacy checking account,25.50,,USD,Second cash memo,2025-12-29T09:00:00Z,private-legacy-author\nprivate-source-entry-two,2025-12-29,Private legacy opening equity,,25.50,USD,Second equity memo,2025-12-29T09:00:00Z,private-legacy-author\n";
const COLUMNS: &str = "[columns]\nsource_system = \"legacy-csv\"\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\nrecorded_at_column = \"recorded\"\naccount_column = \"account\"\nsigned_amount_column = \"amount\"\ndescription_column = \"description\"\nmemo_column = \"memo\"\nentered_by_column = \"entered\"\napproved_by_column = \"approved\"\n";
const GENERIC: &str = "entry,date,recorded,account,amount,description,memo,entered,approved\nprivate-source-entry-one,2025-12-30,2025-12-30T15:20:00Z,Private legacy checking account,125.50,Private retained description,Private retained cash memo,legacy-preparer,legacy-reviewer\nprivate-source-entry-one,2025-12-30,2025-12-30T15:20:00Z,Private legacy opening equity,-125.50,Private retained description,Private retained equity memo,legacy-preparer,legacy-reviewer\n";
const PERIOD_ACTIVITY: &str = "private-january-revenue,2026-01-01,Private legacy checking account,20.00,,USD,Private January cash,2026-01-02T12:30:00Z,private-period-author\nprivate-january-revenue,2026-01-01,Private legacy revenue,,20.00,USD,Private January revenue,2026-01-02T12:30:00Z,private-period-author\nprivate-january-expense,2026-01-20,Private legacy expense,5.00,,USD,Private January expense,2026-01-21T12:30:00Z,private-period-author\nprivate-january-expense,2026-01-20,Private legacy checking account,,5.00,USD,Private January payment,2026-01-21T12:30:00Z,private-period-author\nprivate-march-revenue,2026-03-15,Private legacy checking account,30.00,,USD,Private March cash,2026-03-16T12:30:00Z,private-period-author\nprivate-march-revenue,2026-03-15,Private legacy revenue,,30.00,USD,Private March revenue,2026-03-16T12:30:00Z,private-period-author\n";

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
    opening_entries: Option<Vec<String>>,
    period_trial_balances: Vec<String>,
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
            opening_entries: None,
            period_trial_balances: Vec::new(),
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

    fn period_balances(format: &str, source: &str, middle_tb_kind: &str) -> Self {
        let mut fixture = Self::new(format, source, "USD", "Spreadsheet", "2026-04-01");
        let chart = fixture.file("period-chart.json", r#"{"accounts":[{"code":"4000","name":"Legacy revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Legacy expense","type":"Expense","unit":"USD"}]}"#);
        ok(&fixture.book, &["chart", "import", &chart]);
        fixture.opening_entries = Some(vec![
            "private-source-entry-one".into(),
            "private-source-entry-two".into(),
        ]);
        (fixture.run_vid, fixture.period_trial_balances) = fixture.open_period_run(
            "midyear-import",
            [
                ("140.50", "20.00"),
                ("140.50", "20.00"),
                ("170.50", "50.00"),
            ],
            middle_tb_kind,
        );
        fixture
    }

    fn open_period_run(
        &self,
        key: &str,
        balances: [(&str, &str); 3],
        middle_tb_kind: &str,
    ) -> (String, Vec<String>) {
        let mut periods = Vec::new();
        let mut documents = Vec::new();
        for (index, (cash, revenue)) in balances.into_iter().enumerate() {
            let period = format!("FY2026-P{:02}", index + 1);
            let document = self.document(
                &format!("{key}-{period}.csv"),
                &format!("period,{period}\naccount,unit,debit,credit\n1000,USD,{cash},\n3000,USD,,125.50\n4000,USD,,{revenue}\n6000,USD,5.00,\n"),
                if index == 1 { middle_tb_kind } else { "Spreadsheet" },
            );
            periods.push(obj(vec![
                ("period", s(period)),
                ("trial_balance", s(&document)),
                (
                    "lines",
                    Json::Arr(vec![
                        obj(vec![
                            ("account", s("1000")),
                            ("unit", s("USD")),
                            ("debit", s(cash)),
                        ]),
                        obj(vec![
                            ("account", s("3000")),
                            ("unit", s("USD")),
                            ("credit", s("125.50")),
                        ]),
                        obj(vec![
                            ("account", s("4000")),
                            ("unit", s("USD")),
                            ("credit", s(revenue)),
                        ]),
                        obj(vec![
                            ("account", s("6000")),
                            ("unit", s("USD")),
                            ("debit", s("5.00")),
                        ]),
                    ]),
                ),
            ]));
            documents.push(document);
        }
        let system = if self.format == "csv" {
            "legacy-csv"
        } else {
            &self.format
        };
        let intent = obj(vec![
            ("run_key", s(key)),
            ("source_system", s(system)),
            ("mode", s("PeriodBalances")),
            ("trial_balance", s(&self.trial_balance)),
            ("opening_date", s("2026-01-01")),
            (
                "lines",
                Json::Arr(vec![
                    obj(vec![
                        ("account", s("1000")),
                        ("unit", s("USD")),
                        ("debit", s("125.50")),
                    ]),
                    obj(vec![
                        ("account", s("3000")),
                        ("unit", s("USD")),
                        ("credit", s("125.50")),
                    ]),
                ]),
            ),
            ("periods", Json::Arr(periods)),
        ]);
        let path = self.file(&format!("{key}.json"), &intent.render());
        let opened = ok(&self.book, &["migrate", "open", "--intent", &path]);
        (text(data(&opened), "run_vid").into(), documents)
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
        let mut mappings = vec![(LEGACY_CASH, s("1000")), (LEGACY_EQUITY, s("3000"))];
        if self.opening_entries.is_some() {
            mappings.extend([(LEGACY_REVENUE, s("4000")), (LEGACY_EXPENSE, s("6000"))]);
        }
        let mut fields = vec![
            ("run", s(format!("MR:{}", self.run_vid))),
            ("source", s(format!("D:{}", self.source))),
            ("format", s(&self.format)),
            ("account_map", obj(mappings)),
        ];
        if self.format == "csv" {
            fields.push(("column_map", s(COLUMNS)));
        }
        if let Some(entries) = &self.opening_entries {
            fields.push((
                "opening_entries",
                Json::Arr(entries.iter().map(s).collect()),
            ));
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
        self.cash_at(OPENING, known_at)
    }

    fn cash_at(&self, period: &str, known_at: Option<i128>) -> String {
        let at = known_at.map(|value| value.to_string());
        let mut args = vec!["tb", "--period", period];
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

    fn cash_activity(&self, period: &str) -> String {
        let result = ok(&self.book, &["tb", "--period", period, "--activity"]);
        rows(data(&result), "rows")
            .iter()
            .find(|row| text(row, "code") == "1000")
            .map_or_else(|| "0.00 USD".to_owned(), |row| text(row, "net").to_owned())
    }

    fn open(&self) -> Book {
        Book::open_dir(
            &self.book,
            BookKeys::load(&self.book.join("book.keys")).unwrap(),
            Entropy::deterministic(223),
        )
        .unwrap()
    }

    fn finalize(&self, name: &str) -> Json {
        let plan = self.dir.join(name).display().to_string();
        let planned = ok(
            &self.book,
            &["migrate", "finalize", &self.run_vid, "--plan-out", &plan],
        );
        let digest = text(data(&planned), "proposal_digest");
        let first = self.approve(digest, "finalize-reviewer-one");
        let second = self.approve(digest, "finalize-reviewer-two");
        ok(
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
        )
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
fn period_balances_preserves_dated_activity_and_activates_elapsed_periods_atomically() {
    let mut fixture = Fixture::period_balances(
        "quickbooks-csv",
        &format!("{QB}{PERIOD_ACTIVITY}"),
        "Spreadsheet",
    );
    let prepared = fixture.prepare();
    assert_eq!(text(data(&prepared), "mode"), "PeriodBalances");
    let package = text(data(&prepared), "package_oid").to_owned();
    let chunks = rows(data(&prepared), "chunks");
    assert_eq!(chunks.len(), 5);
    for (chunk, (period, date)) in chunks.iter().zip([
        (OPENING, "2026-01-01"),
        (OPENING, "2026-01-01"),
        ("FY2026-P01", "2026-01-01"),
        ("FY2026-P01", "2026-01-20"),
        ("FY2026-P03", "2026-03-15"),
    ]) {
        assert_eq!(text(chunk, "effective_period"), period);
        assert_eq!(text(chunk, "effective_date"), date);
    }
    assert_eq!(text(&chunks[2], "document_date"), "2026-01-01");
    assert!(!prepared.render().contains("private-january-revenue"));
    assert!(!prepared.render().contains(LEGACY_CASH));
    let shown = fixture.show(&package);
    assert_eq!(data(&shown).get("chunks"), data(&prepared).get("chunks"));
    let mut approvals = Vec::new();
    for chunk in chunks {
        let digest = text(chunk, "proposal_digest");
        approvals.push((
            fixture.approve(digest, "period-reviewer-one"),
            fixture.approve(digest, "period-reviewer-two"),
        ));
    }
    for (count, index) in [4, 2, 0, 3, 1].into_iter().enumerate() {
        let (first, second) = &approvals[index];
        let staged = fixture.stage(&package, index, &[first, second]);
        assert_eq!(
            integer(data(&staged), "recorded_count"),
            (count + 1) as i128
        );
        assert_eq!(
            data(&staged).get("ready_to_finalize"),
            Some(&Json::Bool(count == 4))
        );
        for period in [OPENING, "FY2026-P01", "FY2026-P02", "FY2026-P03"] {
            assert_eq!(
                fixture.cash_at(period, None),
                "0.00 USD",
                "{period} is staged, not active"
            );
        }
        let before = head(&fixture.book);
        let retried = fixture.stage(&package, index, &[first, second]);
        assert_eq!(
            data(&retried).get("already_recorded"),
            Some(&Json::Bool(true))
        );
        assert_eq!(
            integer(data(&retried), "recorded_at"),
            integer(data(&staged), "recorded_at")
        );
        assert_eq!(head(&fixture.book), before);
        if count == 0 {
            let path = fixture
                .dir
                .join("incomplete-period-finalize.plan")
                .display()
                .to_string();
            let (status, _) = run(
                &fixture.book,
                &["migrate", "finalize", &fixture.run_vid, "--plan-out", &path],
            );
            assert_ne!(
                status, 0,
                "a partial source cannot activate elapsed periods"
            );
            assert_eq!(head(&fixture.book), before);
        }
    }
    let before_retry = head(&fixture.book);
    fixture.opening_entries.as_mut().unwrap().reverse();
    let retried = fixture.prepare();
    assert_eq!(text(data(&retried), "package_oid"), package);
    assert_eq!(
        data(&retried).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        head(&fixture.book),
        before_retry,
        "canonical opening selection reuses exact sealed bytes"
    );
    assert_eq!(
        data(&fixture.show(&package)).get("ties_out"),
        Some(&Json::Bool(true))
    );
    let before_finalize = head(&fixture.book);
    assert_eq!(
        text(data(&fixture.finalize("period-finalize.plan")), "to"),
        "Finalized"
    );
    for (period, cash, movement) in [
        ("FY2026-P01", "140.50 USD", "15.00 USD"),
        ("FY2026-P02", "140.50 USD", "0.00 USD"),
        ("FY2026-P03", "170.50 USD", "30.00 USD"),
    ] {
        assert_eq!(fixture.cash_at(period, None), cash, "cumulative {period}");
        assert_eq!(fixture.cash_activity(period), movement, "activity {period}");
        assert_eq!(fixture.cash_at(period, Some(before_finalize)), "0.00 USD");
        ok(&fixture.book, &["verify", "registers", "--period", period]);
    }
    assert_eq!(
        fixture.cash_activity(OPENING),
        "125.50 USD",
        "January 1 activity is not opening stock"
    );
    ok(&fixture.book, &["verify", "registers", "--period", OPENING]);
    let before_retry = head(&fixture.book);
    let retried = fixture.prepare();
    assert_eq!(text(data(&retried), "package_oid"), package);
    assert_eq!(text(data(&retried), "run_state"), "Finalized");
    assert_eq!(
        data(&retried).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    let retried = fixture.stage(&package, 2, &[&approvals[2].0, &approvals[2].1]);
    assert_eq!(
        data(&retried).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&fixture.book), before_retry);
}

#[test]
fn period_balances_rejects_wrong_intermediate_balances_opening_selection_and_dates_before_publication()
 {
    let fixture = Fixture::period_balances(
        "quickbooks-csv",
        &format!("{QB}{PERIOD_ACTIVITY}"),
        "Spreadsheet",
    );
    let original = fixture.intent();
    let mut cases = Vec::new();
    let mut missing = original.clone();
    let Json::Obj(fields) = &mut missing else {
        panic!("intent object")
    };
    fields.retain(|(key, _)| key != "opening_entries");
    cases.push((
        "missing-selection",
        missing,
        "requires explicit opening_entries",
    ));
    for (name, entries, message) in [
        (
            "duplicate-selection",
            vec!["private-source-entry-one", "private-source-entry-one"],
            "repeats a source entry ID",
        ),
        (
            "unknown-selection",
            vec![
                "private-source-entry-one",
                "private-source-entry-two",
                "unknown-source-entry",
            ],
            "absent from the complete source",
        ),
        (
            "unselected-opening",
            vec!["private-source-entry-two"],
            "outside the run's declared Historical periods",
        ),
        (
            "same-day-activity-is-not-opening",
            vec![
                "private-source-entry-one",
                "private-source-entry-two",
                "private-january-revenue",
            ],
            "at the opening",
        ),
        (
            "later-activity-is-not-opening",
            vec![
                "private-source-entry-one",
                "private-source-entry-two",
                "private-january-expense",
            ],
            "dated after the run opening date",
        ),
    ] {
        let mut intent = original.clone();
        set_field(
            &mut intent,
            "opening_entries",
            Json::Arr(entries.into_iter().map(s).collect()),
        );
        cases.push((name, intent, message));
    }
    let mut current_period = original.clone();
    let source = fixture.document(
        "current-period-source.csv",
        &format!(
            "{QB}{}",
            PERIOD_ACTIVITY.replace("2026-03-15", "2026-04-01")
        ),
        "Spreadsheet",
    );
    set_field(&mut current_period, "source", s(source));
    cases.push((
        "current-period-activity",
        current_period,
        "outside the run's declared Historical periods",
    ));
    let (wrong_run, _) = fixture.open_period_run(
        "incorrect-intermediate",
        [
            ("140.50", "20.00"),
            ("141.50", "21.00"),
            ("170.50", "50.00"),
        ],
        "Spreadsheet",
    );
    let mut wrong_period = original.clone();
    set_field(&mut wrong_period, "run", s(wrong_run));
    cases.push((
        "wrong-middle-tb-final-still-ties",
        wrong_period,
        "through `FY2026-P02`",
    ));
    let mut shared_source = original.clone();
    set_field(
        &mut shared_source,
        "source",
        s(&fixture.period_trial_balances[1]),
    );
    cases.push((
        "source-is-period-tb",
        shared_source,
        "must be distinct retained Documents",
    ));
    for (name, intent, message) in cases {
        let path = fixture.file(&format!("{name}.json"), &intent.render());
        let before = head(&fixture.book);
        let (status, refusal) = run(
            &fixture.book,
            &[
                "migrate", "import", "--action", "prepare", "--intent", &path,
            ],
        );
        assert_eq!(status, 2, "{name}: {}", refusal.render());
        assert!(
            refusal.render().contains(message),
            "{name}: {}",
            refusal.render()
        );
        assert_eq!(
            head(&fixture.book),
            before,
            "{name} must not retain a partial package"
        );
    }
    let prepared = fixture.prepare();
    assert_eq!(integer(data(&prepared), "recorded_count"), 0);
    assert_eq!(fixture.cash_at("FY2026-P03", None), "0.00 USD");
}

#[test]
fn period_balances_refuses_ambiguous_iif_opening_ids_and_an_opening_only_selection_extension() {
    let iif = "!TRNS\tTRNSID\tDATE\tACCNT\tAMOUNT\n!SPL\tSPLID\tDATE\tACCNT\tAMOUNT\n!ENDTRNS\nTRNS\tprivate-source-entry-one\t2025-12-20\tPrivate legacy checking account\t100.00\nSPL\tprivate-split-one\t2025-12-20\tPrivate legacy opening equity\t-100.00\nENDTRNS\nTRNS\tprivate-source-entry-one\t2025-12-29\tPrivate legacy checking account\t25.50\nSPL\tprivate-split-two\t2025-12-29\tPrivate legacy opening equity\t-25.50\nENDTRNS\n";
    let fixture = Fixture::period_balances("quickbooks-iif", iif, "Spreadsheet");
    let path = fixture.file("ambiguous-opening.json", &fixture.intent().render());
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert!(
        refused
            .render()
            .contains("identifies more than one source entry")
    );
    assert_eq!(head(&fixture.book), before);

    let fixture = Fixture::quickbooks();
    let mut intent = fixture.intent();
    set_field(
        &mut intent,
        "opening_entries",
        Json::Arr(vec![s("private-source-entry-one")]),
    );
    let path = fixture.file("opening-only-selection.json", &intent.render());
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert!(refused.render().contains("applies only to PeriodBalances"));
    assert_eq!(head(&fixture.book), before);
}

#[test]
fn period_balances_replay_reauthorizes_every_declared_trial_balance() {
    let fixture = Fixture::period_balances(
        "quickbooks-csv",
        &format!("{QB}{PERIOD_ACTIVITY}"),
        "BankStatement",
    );
    let path = fixture.file("governed-period-import.json", &fixture.intent().render());
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(status, 3, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-142");
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
    let original = rewrite_package(&fixture, package, |_, proposals| {
        assert!(
            proposals
                .iter()
                .all(|proposal| proposal.evidence.len() == 5),
            "every approved proposal cites the source, opening TB and all three period TBs"
        );
    });
    assert_eq!(
        original, package,
        "inspection must preserve the exact package bytes"
    );
    for args in [
        vec![
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
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
            "2",
        ],
    ] {
        let before = head(&fixture.book);
        let (status, refused) = run(&fixture.book, &args);
        assert_eq!(status, 3, "{args:?}: {}", refused.render());
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-142");
        assert!(!refused.render().contains("private-january-revenue"));
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
    assert_eq!(data(&shown).get("chunks"), data(&prepared).get("chunks"));
    let digest = text(&rows(data(&shown), "chunks")[2], "proposal_digest");
    let first = fixture.approve(digest, "governed-period-reviewer-one");
    let second = fixture.approve(digest, "governed-period-reviewer-two");
    let staged = ok(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--chunk",
            "2",
            "--approval",
            &first,
            "--approval",
            &second,
            "--grant",
            "privileged",
        ],
    );
    assert_eq!(integer(data(&staged), "recorded_count"), 1);
    assert_eq!(fixture.cash_at("FY2026-P03", None), "0.00 USD");
}

#[test]
fn period_balances_replay_rejects_rehashed_period_routing_and_evidence_changes() {
    let fixture = Fixture::period_balances(
        "quickbooks-csv",
        &format!("{QB}{PERIOD_ACTIVITY}"),
        "Spreadsheet",
    );
    let prepared = fixture.prepare();
    let package = text(data(&prepared), "package_oid");
    for change_period in [true, false] {
        let forged = rewrite_package(&fixture, package, |_, proposals| {
            if change_period {
                assert_eq!(proposals[2].effective_date.render(), "2026-01-01");
                proposals[2].effective_period.as_mut().unwrap().code = OPENING.into();
            } else {
                assert_eq!(proposals[2].evidence.len(), 5);
                proposals[2].evidence.pop().unwrap();
            }
        });
        assert_ne!(forged, package);
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
                args.extend(["--chunk", "2"]);
            }
            let before = head(&fixture.book);
            let (status, refused) = run(&fixture.book, &args);
            assert_eq!(status, 8, "{}", refused.render());
            assert!(
                refused
                    .render()
                    .contains("retained proposal structure differs")
            );
            assert_eq!(head(&fixture.book), before);
        }
    }
    let shown = fixture.show(package);
    assert_eq!(integer(data(&shown), "recorded_count"), 0);
    assert_eq!(
        text(&rows(data(&shown), "chunks")[2], "effective_period"),
        "FY2026-P01"
    );
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
fn package_intake_records_human_custody_without_claiming_generated_provenance() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let package = parse_oid(text(data(&prepared), "package_oid"));
    let principal = fa_model::principal_vid("operator");
    let reader = Capability::embedded(VId(503), &["read"]).unwrap();
    let mut book = fixture.open();
    let DocumentRead::Full(document) = book.read_document_for(&reader, &package).unwrap().unwrap()
    else {
        panic!("retained package must be readable under current authority");
    };
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded().unwrap();
    assert_eq!(
        document.grade,
        policy.grade_by_name("HumanUpload").unwrap().tag
    );
    assert!(!policy.grade_by_name("Generated").unwrap().intake);
    assert_eq!(document.retrieved_by, principal);
    let custody = book.custody_chain(&package).unwrap();
    assert_eq!(custody.len(), 1);
    assert_eq!(
        custody[0].0.body,
        fa_journal::CustodyBody::Receipt {
            source: fa_model::IntakeSource::Upload { principal },
            received_by: principal,
            digest_at_receipt: document.doc_commit(),
            run_ref: None,
        }
    );
    assert_eq!(
        i128::from(custody[0].1.0),
        integer(data(&prepared), "recorded_at")
    );
    drop(book);

    let before = head(&fixture.book);
    let repeated = fixture.prepare();
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    for field in ["package_oid", "package_commit", "chunks", "recorded_at"] {
        assert_eq!(data(&repeated).get(field), data(&prepared).get(field));
    }
    assert_eq!(head(&fixture.book), before);
    let mut book = fixture.open();
    assert_eq!(
        book.read_document_for(&reader, &package).unwrap().unwrap(),
        DocumentRead::Full(document)
    );
    assert_eq!(book.custody_chain(&package).unwrap(), custody);
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
    rewrite_package(fixture, package, |book, proposals| {
        if change_memo {
            proposals[0].legs[0].memo = Some(book.seal_text("forged private source memo").unwrap());
        } else {
            proposals[0].legs[0].amount.mantissa += 1;
            proposals[0].legs[1].amount.mantissa += 1;
            proposals[0].unit_totals = EntryPayload::fold_unit_totals(&proposals[0].legs).unwrap();
        }
    })
}

fn rewrite_package(
    fixture: &Fixture,
    package: &str,
    change: impl FnOnce(&Book, &mut [EntryPayload]),
) -> String {
    let mut book = fixture.open();
    let cap = Capability::embedded(VId(502), &["read"]).unwrap();
    let DocumentRead::Full(mut document) = book
        .read_document_for(&cap, &parse_oid(package))
        .unwrap()
        .unwrap()
    else {
        panic!("full package");
    };
    let domain: &[u8] = if document
        .bytes
        .starts_with(b"FA-LEGACY-PERIOD-BALANCES-IMPORT\0")
    {
        assert_eq!(
            document.mime,
            "application/vnd.frankenaccounting.legacy-period-balances-import.v1"
        );
        b"FA-LEGACY-PERIOD-BALANCES-IMPORT\0"
    } else {
        assert!(document.bytes.starts_with(b"FA-LEGACY-OPENING-IMPORT\0"));
        assert_eq!(
            document.mime,
            "application/vnd.frankenaccounting.legacy-opening-import.v1"
        );
        b"FA-LEGACY-OPENING-IMPORT\0"
    };
    let mut reader = Reader::new(&document.bytes[domain.len()..]);
    assert_eq!(reader.u16("version").unwrap(), 1);
    let _: [u8; 16] = reader.fixed("book").unwrap();
    reader.u128("run").unwrap();
    let _: [u8; 32] = reader.fixed("run body").unwrap();
    let _: [u8; 32] = reader.fixed("source").unwrap();
    let _: [u8; 32] = reader.fixed("source commitment").unwrap();
    let _: Erasable<String> = Erasable::decode(&mut reader, 1024 * 1024).unwrap();
    let count = reader.count(4096, "proposals").unwrap();
    let prefix = document.bytes[..domain.len() + reader.offset()].to_vec();
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
    change(&book, &mut proposals);
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
