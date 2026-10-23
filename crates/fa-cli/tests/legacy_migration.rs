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
const BEAN_CASH: &str = "Assets:Legacy:Checking";
const BEAN_EQUITY: &str = "Equity:Legacy:Opening";
const HLEDGER_CASH: &str = "assets:legacy:checking";
const HLEDGER_EQUITY: &str = "equity:legacy opening";
const HLEDGER: &str = "; A legacy hledger journal, as hledger print writes it.\naccount assets:legacy:checking\ncommodity USD 1,000.00\n\n2025-12-20 * (A-1) Legacy bank | Private retained opening deposit  ; migration\n    assets:legacy:checking    USD 100.00  ; private retained cash memo\n    equity:legacy opening\n\n2025/12/29 Private second deposit\n    assets:legacy:checking      25.50 USD = USD 125.50\n    equity:legacy opening      -25.50 USD\n";
const BEANCOUNT: &str = "option \"operating_currency\" \"USD\"\n2025-01-01 open Assets:Legacy:Checking USD\n2025-01-01 open Equity:Legacy:Opening USD\n\n2025-12-20 * \"Legacy bank\" \"Private retained opening deposit\" #migration\n  Assets:Legacy:Checking   100.00 USD ; private retained cash memo\n  Equity:Legacy:Opening\n\n2025-12-29 txn \"Private second deposit\"\n  Assets:Legacy:Checking    25.50 USD\n  Equity:Legacy:Opening    -25.50 USD\n\n2025-12-31 balance Assets:Legacy:Checking 125.50 USD\n";
const QB: &str = "Transaction ID,Date,Account,Debit,Credit,Currency,Memo/Description,Created At,Created By\nprivate-source-entry-one,2025-12-20,Private legacy checking account,100.00,,USD,Private retained cash memo,2025-12-20T12:30:00Z,private-legacy-author\nprivate-source-entry-one,2025-12-20,Private legacy opening equity,,100.00,USD,Private retained equity memo,2025-12-20T12:30:00Z,private-legacy-author\nprivate-source-entry-two,2025-12-29,Private legacy checking account,25.50,,USD,Second cash memo,2025-12-29T09:00:00Z,private-legacy-author\nprivate-source-entry-two,2025-12-29,Private legacy opening equity,,25.50,USD,Second equity memo,2025-12-29T09:00:00Z,private-legacy-author\n";
const COLUMNS: &str = "[columns]\nsource_system = \"legacy-csv\"\nentry_id_column = \"entry\"\neffective_date_column = \"date\"\nrecorded_at_column = \"recorded\"\naccount_column = \"account\"\nsigned_amount_column = \"amount\"\ndescription_column = \"description\"\nmemo_column = \"memo\"\nentered_by_column = \"entered\"\napproved_by_column = \"approved\"\n";
const GENERIC: &str = "entry,date,recorded,account,amount,description,memo,entered,approved\nprivate-source-entry-one,2025-12-30,2025-12-30T15:20:00Z,Private legacy checking account,125.50,Private retained description,Private retained cash memo,legacy-preparer,legacy-reviewer\nprivate-source-entry-one,2025-12-30,2025-12-30T15:20:00Z,Private legacy opening equity,-125.50,Private retained description,Private retained equity memo,legacy-preparer,legacy-reviewer\n";
const PERIOD_ACTIVITY: &str = "private-january-revenue,2026-01-01,Private legacy checking account,20.00,,USD,Private January cash,2026-01-02T12:30:00Z,private-period-author\nprivate-january-revenue,2026-01-01,Private legacy revenue,,20.00,USD,Private January revenue,2026-01-02T12:30:00Z,private-period-author\nprivate-january-expense,2026-01-20,Private legacy expense,5.00,,USD,Private January expense,2026-01-21T12:30:00Z,private-period-author\nprivate-january-expense,2026-01-20,Private legacy checking account,,5.00,USD,Private January payment,2026-01-21T12:30:00Z,private-period-author\nprivate-march-revenue,2026-03-15,Private legacy checking account,30.00,,USD,Private March cash,2026-03-16T12:30:00Z,private-period-author\nprivate-march-revenue,2026-03-15,Private legacy revenue,,30.00,USD,Private March revenue,2026-03-16T12:30:00Z,private-period-author\n";

fn full_detail_source(sole: bool) -> String {
    let mut source = format!("{}\n", QB.lines().next().unwrap());
    if sole {
        source.push_str("private-history-funding,2025-01-01,Private legacy checking account,100.00,,USD,Private founding deposit,2025-01-02T12:00:00Z,private-history-author\nprivate-history-funding,2025-01-01,Private legacy opening equity,,100.00,USD,Private founding capital,2025-01-02T12:00:00Z,private-history-author\n");
    }
    source.push_str("private-history-revenue,2025-12-15,Private legacy checking account,20.00,,USD,Private prior-year cash,2025-12-16T12:00:00Z,private-history-author\nprivate-history-revenue,2025-12-15,Private legacy revenue,,20.00,USD,Private prior-year revenue,2025-12-16T12:00:00Z,private-history-author\n");
    if sole {
        source.push_str("private-history-adjustment,2025-12-31,Private legacy expense,2.00,,USD,Private year-end adjustment,2025-12-31T12:00:00Z,private-history-author\nprivate-history-adjustment,2025-12-31,Private legacy checking account,,2.00,USD,Private year-end payment,2025-12-31T12:00:00Z,private-history-author\nprivate-history-close,2025-12-31,Private legacy revenue,20.00,,USD,Private close revenue,2025-12-31T18:00:00Z,private-history-author\nprivate-history-close,2025-12-31,Private legacy expense,,2.00,USD,Private close expense,2025-12-31T18:00:00Z,private-history-author\nprivate-history-close,2025-12-31,Private legacy opening equity,,18.00,USD,Private close earnings,2025-12-31T18:00:00Z,private-history-author\n");
    } else {
        source.push_str("private-history-close,2025-12-31,Private legacy revenue,20.00,,USD,Private close revenue,2025-12-31T18:00:00Z,private-history-author\nprivate-history-close,2025-12-31,Private legacy opening equity,,20.00,USD,Private close earnings,2025-12-31T18:00:00Z,private-history-author\nprivate-full-opening,2025-12-31,Private legacy checking account,120.00,,USD,Private next-year opening cash,2025-12-31T19:00:00Z,private-history-author\nprivate-full-opening,2025-12-31,Private legacy opening equity,,120.00,USD,Private next-year opening equity,2025-12-31T19:00:00Z,private-history-author\nprivate-full-january-sale,2026-01-01,Private legacy checking account,5.00,,USD,Private January sale cash,2026-01-02T12:00:00Z,private-history-author\nprivate-full-january-sale,2026-01-01,Private legacy revenue,,5.00,USD,Private January sale revenue,2026-01-02T12:00:00Z,private-history-author\nprivate-full-january-payment,2026-01-20,Private legacy expense,3.00,,USD,Private January expense,2026-01-21T12:00:00Z,private-history-author\nprivate-full-january-payment,2026-01-20,Private legacy checking account,,3.00,USD,Private January payment,2026-01-21T12:00:00Z,private-history-author\nprivate-full-march-sale,2026-03-15,Private legacy checking account,10.00,,USD,Private March sale cash,2026-03-16T12:00:00Z,private-history-author\nprivate-full-march-sale,2026-03-15,Private legacy revenue,,10.00,USD,Private March sale revenue,2026-03-16T12:00:00Z,private-history-author\n");
    }
    source
}

fn tb_lines(lines: &[(&str, &str)]) -> Json {
    Json::Arr(
        lines
            .iter()
            .map(|(account, net)| {
                obj(vec![
                    ("account", s(*account)),
                    ("unit", s("USD")),
                    ("net", s(*net)),
                ])
            })
            .collect(),
    )
}

fn tb_document(period: &str, lines: &[(&str, &str)]) -> String {
    let mut document = format!("period,{period}\naccount,unit,debit,credit\n");
    for (account, net) in lines {
        if let Some(credit) = net.strip_prefix('-') {
            document.push_str(&format!("{account},USD,,{credit}\n"));
        } else {
            document.push_str(&format!("{account},USD,{net},\n"));
        }
    }
    document
}

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
    entry_periods: Option<Json>,
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
            entry_periods: None,
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

    fn full_detail(sole: bool, source_kind: &str) -> (Self, Json) {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = loop {
            let path = std::env::temp_dir().join(format!(
                "fa-full-detail-migration-cli-{}-{}",
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
                "Full historical legacy import",
                "--base-unit",
                "USD",
                "--opening-date",
                if sole { "2026-01-01" } else { "2026-04-01" },
            ],
        );
        let mut fixture = Self {
            dir,
            book,
            unit: "USD".into(),
            source: String::new(),
            trial_balance: String::new(),
            run_vid: String::new(),
            format: "quickbooks-csv".into(),
            opening_entries: (!sole).then(|| vec!["private-full-opening".into()]),
            entry_periods: Some(obj(vec![("private-history-close", s("FY2025-CLOSE"))])),
            period_trial_balances: Vec::new(),
        };
        if sole {
            fixture.entry_periods = Some(obj(vec![
                ("private-history-funding", s("FY2025-OPEN")),
                ("private-history-adjustment", s("FY2025-A1")),
                ("private-history-close", s("FY2025-CLOSE")),
            ]));
        }
        let chart = fixture.file("full-detail-chart.json", r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Opening equity","type":"Equity","unit":"USD"},{"code":"4000","name":"Legacy revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Legacy expense","type":"Expense","unit":"USD"}]}"#);
        ok(&fixture.book, &["chart", "import", &chart]);
        ok(
            &fixture.book,
            &["period", "create", "--fiscal-year", "2025"],
        );
        if !sole {
            ok(
                &fixture.book,
                &["period", "create", "--fiscal-year", "2026"],
            );
        }
        fixture.source = fixture.document(
            "full-detail-original.csv",
            &full_detail_source(sole),
            source_kind,
        );
        let opening: &[(&str, &str)] = if sole {
            &[]
        } else {
            &[("1000", "120.00"), ("3000", "-120.00")]
        };
        fixture.trial_balance = fixture.document(
            "full-detail-opening-tb.csv",
            &tb_document("separate-opening", opening),
            "Spreadsheet",
        );
        let mut balances = Vec::new();
        if sole {
            for month in 1..=11 {
                balances.push((
                    format!("FY2025-P{month:02}"),
                    vec![("1000", "100.00"), ("3000", "-100.00")],
                ));
            }
        }
        balances.push((
            "FY2025-P12".to_owned(),
            vec![("1000", "120.00"), ("3000", "-100.00"), ("4000", "-20.00")],
        ));
        if !sole {
            for (period, cash, revenue) in [
                ("FY2026-P01", "122.00", "-5.00"),
                ("FY2026-P02", "122.00", "-5.00"),
                ("FY2026-P03", "132.00", "-15.00"),
            ] {
                balances.push((
                    period.to_owned(),
                    vec![
                        ("1000", cash),
                        ("3000", "-120.00"),
                        ("4000", revenue),
                        ("6000", "3.00"),
                    ],
                ));
            }
        }
        let mut periods = Vec::new();
        for (period, lines) in balances {
            let document = fixture.document(
                &format!("full-detail-{period}.csv"),
                &tb_document(&period, &lines),
                "Spreadsheet",
            );
            periods.push(obj(vec![
                ("period", s(period)),
                ("trial_balance", s(&document)),
                ("lines", tb_lines(&lines)),
            ]));
            fixture.period_trial_balances.push(document);
        }
        let body = obj(vec![
            ("run_key", s("full-detail-history")),
            ("source_system", s("quickbooks-csv")),
            ("mode", s("FullDetail")),
            ("trial_balance", s(&fixture.trial_balance)),
            ("opening_date", s("2026-01-01")),
            ("lines", tb_lines(opening)),
            ("periods", Json::Arr(periods)),
            (
                "detail_base",
                tb_lines(if sole {
                    &[]
                } else {
                    &[("1000", "100.00"), ("3000", "-100.00")]
                }),
            ),
            ("sole_opening_source", Json::Bool(sole)),
        ]);
        let path = fixture.file("full-detail-run.json", &body.render());
        let opened = ok(&fixture.book, &["migrate", "open", "--intent", &path]);
        fixture.run_vid = text(data(&opened), "run_vid").into();
        (fixture, body)
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
        let (cash, equity) = match self.format.as_str() {
            "beancount" => (BEAN_CASH, BEAN_EQUITY),
            "hledger" => (HLEDGER_CASH, HLEDGER_EQUITY),
            _ => (LEGACY_CASH, LEGACY_EQUITY),
        };
        let mut mappings = vec![(cash, s("1000")), (equity, s("3000"))];
        if self.opening_entries.is_some() || self.entry_periods.is_some() {
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
        if let Some(periods) = &self.entry_periods {
            fields.push(("entry_periods", periods.clone()));
        }
        obj(fields)
    }

    fn prepare(&self) -> Json {
        let path = self.file("import.json", &self.intent().render());
        let prepared = ok(
            &self.book,
            &[
                "migrate", "import", "--action", "prepare", "--intent", &path,
            ],
        );
        assert_eq!(data(&prepared).get("plan"), Some(&Json::Null));
        if text(data(&prepared), "mode") != "FullDetail" {
            assert_eq!(
                data(&prepared).get("sole_opening_source"),
                Some(&Json::Null)
            );
            for chunk in rows(data(&prepared), "chunks") {
                assert_eq!(chunk.get("counts_after_finalize"), Some(&Json::Null));
                if text(data(&prepared), "mode") == "OpeningOnly" {
                    assert_eq!(chunk.get("effective_period"), Some(&Json::Null));
                }
            }
        }
        if integer(data(&prepared), "recorded_count") == 0 {
            for chunk in rows(data(&prepared), "chunks") {
                assert_eq!(chunk.get("recorded_at"), Some(&Json::Null));
            }
        }
        prepared
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
        // Migration controls publish journal facts; register maintenance is
        // a separate operation, and verification never initializes a cache.
        ok(&self.book, &["registers", "advance", "--period", OPENING]);
        ok(&self.book, &["verify", "registers", "--period", OPENING]);
    }
}

fn stage_full_detail(fixture: &Fixture, prepared: &Json, period: &str) -> Vec<(String, String)> {
    let package = text(data(prepared), "package_oid");
    let chunks = rows(data(prepared), "chunks");
    let approvals: Vec<_> = chunks
        .iter()
        .map(|chunk| {
            let digest = text(chunk, "proposal_digest");
            (
                fixture.approve(digest, "full-detail-reviewer-one"),
                fixture.approve(digest, "full-detail-reviewer-two"),
            )
        })
        .collect();
    for (count, index) in (0..chunks.len()).rev().enumerate() {
        let (first, second) = &approvals[index];
        let before = head(&fixture.book);
        let staged = fixture.stage(package, index, &[first, second]);
        assert_eq!(text(&staged, "event"), "migration_import_staged");
        assert_eq!(
            text(data(&staged), "entry_vid"),
            text(&chunks[index], "entry_vid")
        );
        assert_eq!(
            integer(data(&staged), "recorded_count"),
            (count + 1) as i128
        );
        assert_eq!(
            data(&staged).get("ready_to_finalize"),
            Some(&Json::Bool(count + 1 == chunks.len()))
        );
        assert!(integer(data(&staged), "recorded_at") > before);
        assert_eq!(fixture.cash_at(period, None), "0.00 USD");
        let book = fixture.open();
        let vid = VId(u128::from_str_radix(text(data(&staged), "entry_vid"), 16).unwrap());
        let (entry, recorded) = book.read_entry(vid).unwrap().unwrap();
        assert_eq!(
            i128::from(recorded.0),
            integer(data(&staged), "recorded_at")
        );
        assert_eq!(
            entry.proposal.effective_date.render(),
            text(&chunks[index], "effective_date")
        );
        assert_eq!(
            entry.proposal.effective_period.as_ref().unwrap().code,
            text(&chunks[index], "effective_period")
        );
        assert_eq!(
            entry.proposal.legs.len() as i128,
            integer(&chunks[index], "leg_count")
        );
        drop(book);
        let before_retry = head(&fixture.book);
        let retried = fixture.stage(package, index, &[first, second]);
        assert_eq!(
            data(&retried).get("already_recorded"),
            Some(&Json::Bool(true))
        );
        assert_eq!(
            data(&retried).get("recorded_at"),
            data(&staged).get("recorded_at")
        );
        assert_eq!(head(&fixture.book), before_retry);
    }
    assert_eq!(
        data(&fixture.show(package)).get("ties_out"),
        Some(&Json::Bool(true))
    );
    approvals
}

fn assert_cash_open_items(fixture: &Fixture, before_finalize: i128, expected: &[(&str, i128)]) {
    let book = fixture.open();
    let account = fa_model::account_vid(book.context().book_id, "1000");
    let before = fgdb_types::CommitSeq(u64::try_from(before_finalize).unwrap());
    assert!(
        book.open_items(Some(account), Some(before))
            .unwrap()
            .is_empty()
    );
    let mut actual: Vec<_> = book
        .open_items(Some(account), None)
        .unwrap()
        .iter()
        .map(|item| {
            assert_eq!(item.applied, 0);
            assert_eq!(item.applied_out, 0);
            assert_eq!(item.open, item.original);
            let signed = match item.side {
                fa_money::Side::Debit => item.open,
                fa_money::Side::Credit => item.open.checked_neg().unwrap(),
            };
            (item.effective_date.render(), signed)
        })
        .collect();
    actual.sort();
    let expected: Vec<_> = expected
        .iter()
        .map(|(date, net)| (date.to_string(), *net))
        .collect();
    assert_eq!(
        actual, expected,
        "open items obey the same native migration cutoff as stock balances"
    );
}

#[test]
fn full_detail_preserves_history_and_counts_only_the_separate_opening_and_later_detail() {
    let (fixture, _) = Fixture::full_detail(false, "Spreadsheet");
    let prepared = fixture.prepare();
    assert_eq!(text(data(&prepared), "mode"), "FullDetail");
    assert_eq!(
        data(&prepared).get("sole_opening_source"),
        Some(&Json::Bool(false))
    );
    assert_eq!(integer(data(&prepared), "chunk_count"), 6);
    assert!(!prepared.render().contains("private-"));
    let package = text(data(&prepared), "package_oid").to_owned();
    let chunks = rows(data(&prepared), "chunks");
    let mut before_opening = 0;
    let mut own_opening = 0;
    for chunk in chunks {
        let period = text(chunk, "effective_period");
        let date = text(chunk, "effective_date");
        let historical = period.starts_with("FY2025-");
        assert_eq!(
            chunk.get("counts_after_finalize"),
            Some(&Json::Bool(!historical))
        );
        if historical {
            before_opening += 1;
            assert_eq!(date, text(chunk, "document_date"));
            assert!(matches!(period, "FY2025-P12" | "FY2025-CLOSE"));
        } else if period == OPENING {
            own_opening += 1;
            assert_eq!(date, "2026-01-01");
            assert_eq!(text(chunk, "document_date"), "2025-12-31");
        } else {
            assert_eq!(date, text(chunk, "document_date"));
            assert!(matches!(period, "FY2026-P01" | "FY2026-P03"));
        }
    }
    assert_eq!((before_opening, own_opening), (2, 1));
    let before_retry = head(&fixture.book);
    let repeated = fixture.prepare();
    assert_eq!(data(&repeated).get("chunks"), data(&prepared).get("chunks"));
    assert_eq!(text(data(&repeated), "package_oid"), package);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&fixture.book), before_retry);
    let approvals = stage_full_detail(&fixture, &prepared, "FY2026-P03");
    let before_finalize = head(&fixture.book);
    assert_eq!(
        text(data(&fixture.finalize("full-detail-finalize.plan")), "to"),
        "Finalized"
    );
    for (period, cash, movement) in [
        (OPENING, "125.00 USD", "120.00 USD"),
        ("FY2026-P01", "122.00 USD", "2.00 USD"),
        ("FY2026-P02", "122.00 USD", "0.00 USD"),
        ("FY2026-P03", "132.00 USD", "10.00 USD"),
    ] {
        assert_eq!(fixture.cash_at(period, None), cash, "stock at {period}");
        assert_eq!(
            fixture.cash_activity(period),
            movement,
            "movement in {period}"
        );
        assert_eq!(fixture.cash_at(period, Some(before_finalize)), "0.00 USD");
        ok(&fixture.book, &["registers", "advance", "--period", period]);
        ok(&fixture.book, &["verify", "registers", "--period", period]);
    }
    for period in ["FY2025-P12", "FY2025-CLOSE"] {
        assert_eq!(fixture.cash_at(period, None), "0.00 USD");
        let report = ok(&fixture.book, &["tb", "--period", period, "--activity"]);
        assert!(
            rows(data(&report), "rows").is_empty(),
            "old {period} stays drill-down evidence"
        );
    }
    assert_cash_open_items(
        &fixture,
        before_finalize,
        &[
            ("2026-01-01", 500),
            ("2026-01-01", 12_000),
            ("2026-01-20", -300),
            ("2026-03-15", 1_000),
        ],
    );
    let before_retry = head(&fixture.book);
    let repeated = fixture.prepare();
    assert_eq!(text(data(&repeated), "run_state"), "Finalized");
    assert_eq!(text(data(&repeated), "package_oid"), package);
    let retried = fixture.stage(&package, 0, &[&approvals[0].0, &approvals[0].1]);
    assert_eq!(
        data(&retried).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(head(&fixture.book), before_retry);
}

#[test]
fn sole_full_detail_imports_older_opening_adjustment_and_closing_without_an_own_opening_period() {
    let (fixture, _) = Fixture::full_detail(true, "Spreadsheet");
    {
        let book = fixture.open();
        assert!(
            book.periods()
                .unwrap()
                .iter()
                .all(|period| !period.code.starts_with("FY2026-"))
        );
    }
    let prepared = fixture.prepare();
    assert_eq!(text(data(&prepared), "mode"), "FullDetail");
    assert_eq!(
        data(&prepared).get("sole_opening_source"),
        Some(&Json::Bool(true))
    );
    assert_eq!(text(data(&prepared), "opening_period"), OPENING);
    let chunks = rows(data(&prepared), "chunks");
    assert_eq!(chunks.len(), 4);
    let mut periods: Vec<_> = chunks
        .iter()
        .map(|chunk| text(chunk, "effective_period"))
        .collect();
    periods.sort_unstable();
    assert_eq!(
        periods,
        ["FY2025-A1", "FY2025-CLOSE", "FY2025-OPEN", "FY2025-P12"]
    );
    for chunk in chunks {
        assert_eq!(chunk.get("counts_after_finalize"), Some(&Json::Bool(true)));
        assert_eq!(text(chunk, "effective_date"), text(chunk, "document_date"));
        let expected_legs = if text(chunk, "effective_period") == "FY2025-CLOSE" {
            3
        } else {
            2
        };
        assert_eq!(integer(chunk, "leg_count"), expected_legs);
    }
    let package = text(data(&prepared), "package_oid").to_owned();
    let mut book = fixture.open();
    let reader = Capability::embedded(VId(504), &["read"]).unwrap();
    let DocumentRead::Full(document) = book
        .read_document_for(&reader, &parse_oid(&package))
        .unwrap()
        .unwrap()
    else {
        panic!("full-detail package is retained under current read authority");
    };
    assert_eq!(
        document.mime,
        "application/vnd.frankenaccounting.legacy-full-detail-import.v1"
    );
    assert!(
        document
            .bytes
            .starts_with(b"FA-LEGACY-FULL-DETAIL-IMPORT\0")
    );
    drop(book);
    let approvals = stage_full_detail(&fixture, &prepared, "FY2025-P12");
    let before_finalize = head(&fixture.book);
    assert_eq!(
        text(data(&fixture.finalize("sole-finalize.plan")), "to"),
        "Finalized"
    );
    assert_eq!(fixture.cash_at("FY2025-P01", None), "100.00 USD");
    assert_eq!(fixture.cash_at("FY2025-P12", None), "118.00 USD");
    assert_eq!(
        fixture.cash_at("FY2025-P12", Some(before_finalize)),
        "0.00 USD"
    );
    for (period, movement) in [
        ("FY2025-OPEN", "100.00 USD"),
        ("FY2025-P01", "0.00 USD"),
        ("FY2025-P12", "20.00 USD"),
        ("FY2025-A1", "-2.00 USD"),
        ("FY2025-CLOSE", "0.00 USD"),
    ] {
        assert_eq!(fixture.cash_activity(period), movement);
        ok(&fixture.book, &["registers", "advance", "--period", period]);
        ok(&fixture.book, &["verify", "registers", "--period", period]);
    }
    assert_cash_open_items(
        &fixture,
        before_finalize,
        &[
            ("2025-01-01", 10_000),
            ("2025-12-15", 2_000),
            ("2025-12-31", -200),
        ],
    );
    let book = fixture.open();
    assert!(
        book.periods()
            .unwrap()
            .iter()
            .all(|period| !period.code.starts_with("FY2026-"))
    );
    drop(book);
    let before_retry = head(&fixture.book);
    let repeated = fixture.stage(&package, 0, &[&approvals[0].0, &approvals[0].1]);
    assert_eq!(
        data(&repeated).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(data(&fixture.show(&package)), "run_state"),
        "Finalized"
    );
    assert_eq!(head(&fixture.book), before_retry);
}

fn full_detail_variant(fixture: &Fixture, mut body: Json, key: &str) -> String {
    set_field(&mut body, "run_key", s(key));
    let path = fixture.file(&format!("{key}-run.json"), &body.render());
    let opened = ok(&fixture.book, &["migrate", "open", "--intent", &path]);
    text(data(&opened), "run_vid").to_owned()
}

#[test]
fn full_detail_rejects_ambiguous_routes_and_every_wrong_chain_checkpoint_without_publication() {
    let (fixture, body) = Fixture::full_detail(false, "Spreadsheet");
    let original = fixture.intent();
    let mut cases = Vec::new();
    let mut missing = original.clone();
    let Json::Obj(fields) = &mut missing else {
        panic!("import object")
    };
    fields.retain(|(key, _)| key != "opening_entries");
    cases.push((
        "missing-opening-selection",
        missing,
        Some("requires explicit opening_entries"),
    ));
    for (name, periods, message) in [
        (
            "ambiguous-december-31",
            obj(Vec::new()),
            Some("unambiguous FullDetail period"),
        ),
        (
            "unknown-source-id",
            obj(vec![
                ("private-history-close", s("FY2025-CLOSE")),
                ("unknown-source-id", s("FY2025-P12")),
            ]),
            Some("absent from the complete source"),
        ),
        (
            "overlapping-opening",
            obj(vec![
                ("private-history-close", s("FY2025-CLOSE")),
                ("private-full-opening", s("FY2026-P01")),
            ]),
            Some("both opening_entries and entry_periods"),
        ),
        (
            "wrong-source-date",
            obj(vec![("private-history-close", s("FY2026-P01"))]),
            Some("outside its source date"),
        ),
        (
            "outside-declared-span",
            obj(vec![("private-history-close", s("FY2025-P11"))]),
            Some("outside its source date"),
        ),
        (
            "unknown-period",
            obj(vec![("private-history-close", s("FY2025-UNKNOWN"))]),
            Some("outside its source date"),
        ),
        (
            "duplicate-source-routing",
            Json::Obj(vec![
                ("private-history-close".into(), s("FY2025-CLOSE")),
                ("private-history-close".into(), s("FY2025-P12")),
            ]),
            None,
        ),
    ] {
        let mut intent = original.clone();
        set_field(&mut intent, "entry_periods", periods);
        cases.push((name, intent, message));
    }
    let mut unknown_opening = original.clone();
    set_field(
        &mut unknown_opening,
        "opening_entries",
        Json::Arr(vec![s("private-full-opening"), s("unknown-opening-source")]),
    );
    cases.push((
        "unknown-opening-selection",
        unknown_opening,
        Some("absent from the complete source"),
    ));
    let mut duplicate_opening = original.clone();
    set_field(
        &mut duplicate_opening,
        "opening_entries",
        Json::Arr(vec![s("private-full-opening"), s("private-full-opening")]),
    );
    cases.push((
        "duplicate-opening-selection",
        duplicate_opening,
        Some("repeats a source entry ID"),
    ));
    let source = fixture.document(
        "full-detail-late-opening.csv",
        &full_detail_source(false).replace(
            "private-full-opening,2025-12-31",
            "private-full-opening,2026-01-02",
        ),
        "Spreadsheet",
    );
    let mut late_opening = original.clone();
    set_field(&mut late_opening, "source", s(source));
    cases.push((
        "opening-stock-after-opening",
        late_opening,
        Some("dated after the run opening date"),
    ));
    let without_close = full_detail_source(false)
        .lines()
        .filter(|line| !line.starts_with("private-history-close,"))
        .collect::<Vec<_>>()
        .join("\n");
    let source = fixture.document(
        "full-detail-missing-close.csv",
        &without_close,
        "Spreadsheet",
    );
    let mut missing_close = original.clone();
    set_field(&mut missing_close, "source", s(source));
    set_field(&mut missing_close, "entry_periods", obj(Vec::new()));
    cases.push((
        "historical-close-missing",
        missing_close,
        Some("historical opening boundary"),
    ));
    let iif = "!TRNS\tTRNSID\tDATE\tACCNT\tAMOUNT\n!SPL\tSPLID\tDATE\tACCNT\tAMOUNT\n!ENDTRNS\nTRNS\tprivate-history-duplicate\t2025-12-15\tPrivate legacy checking account\t20.00\nSPL\tprivate-duplicate-split-one\t2025-12-15\tPrivate legacy revenue\t-20.00\nENDTRNS\nTRNS\tprivate-history-duplicate\t2025-12-16\tPrivate legacy checking account\t20.00\nSPL\tprivate-duplicate-split-two\t2025-12-16\tPrivate legacy revenue\t-20.00\nENDTRNS\n";
    let source = fixture.document("full-detail-ambiguous.iif", iif, "Spreadsheet");
    let mut iif_body = body.clone();
    set_field(&mut iif_body, "source_system", s("quickbooks-iif"));
    let iif_run = full_detail_variant(&fixture, iif_body, "ambiguous-source-journals");
    let mut ambiguous_source = original.clone();
    set_field(&mut ambiguous_source, "run", s(iif_run));
    set_field(&mut ambiguous_source, "source", s(source));
    set_field(&mut ambiguous_source, "format", s("quickbooks-iif"));
    set_field(&mut ambiguous_source, "entry_periods", obj(Vec::new()));
    cases.push((
        "ambiguous-source-journals",
        ambiguous_source,
        Some("FullDetail source journal IDs are ambiguous"),
    ));
    let mut wrong_base_body = body.clone();
    set_field(
        &mut wrong_base_body,
        "detail_base",
        tb_lines(&[("1000", "101.00"), ("3000", "-101.00")]),
    );
    let wrong_base = full_detail_variant(&fixture, wrong_base_body, "wrong-detail-base");
    let mut wrong_base_intent = original.clone();
    set_field(&mut wrong_base_intent, "run", s(wrong_base));
    cases.push((
        "wrong-detail-base",
        wrong_base_intent,
        Some("through `FY2025-P12`"),
    ));
    let mut wrong_later_body = body;
    let mut periods = rows(&wrong_later_body, "periods").to_vec();
    let wrong_lines = [
        ("1000", "123.00"),
        ("3000", "-120.00"),
        ("4000", "-6.00"),
        ("6000", "3.00"),
    ];
    let wrong_tb = fixture.document(
        "wrong-full-detail-february.csv",
        &tb_document("FY2026-P02", &wrong_lines),
        "Spreadsheet",
    );
    set_field(&mut periods[2], "trial_balance", s(wrong_tb));
    set_field(&mut periods[2], "lines", tb_lines(&wrong_lines));
    set_field(&mut wrong_later_body, "periods", Json::Arr(periods));
    let wrong_later = full_detail_variant(&fixture, wrong_later_body, "wrong-later-checkpoint");
    let mut wrong_later_intent = original.clone();
    set_field(&mut wrong_later_intent, "run", s(wrong_later));
    cases.push((
        "wrong-february-final-march-still-ties",
        wrong_later_intent,
        Some("through `FY2026-P02`"),
    ));
    for (name, intent, message) in cases {
        let path = fixture.file(&format!("{name}.json"), &intent.render());
        let before = head(&fixture.book);
        let (status, refused) = run(
            &fixture.book,
            &[
                "migrate", "import", "--action", "prepare", "--intent", &path,
            ],
        );
        assert_eq!(status, 2, "{name}: {}", refused.render());
        if let Some(message) = message {
            assert!(
                refused.render().contains(message),
                "{name}: {}",
                refused.render()
            );
        }
        assert_eq!(
            head(&fixture.book),
            before,
            "{name}: no partial package or chunk"
        );
    }
    let prepared = fixture.prepare();
    assert_eq!(integer(data(&prepared), "recorded_count"), 0);
    assert_eq!(integer(data(&prepared), "chunk_count"), 6);
    assert_eq!(fixture.cash_at("FY2026-P03", None), "0.00 USD");
    let package = text(data(&prepared), "package_oid");
    let (opening_index, opening) = rows(data(&prepared), "chunks")
        .iter()
        .enumerate()
        .find(|(_, chunk)| text(chunk, "effective_period") == OPENING)
        .unwrap();
    let digest = text(opening, "proposal_digest");
    let first = fixture.approve(digest, "abandon-reviewer-one");
    let second = fixture.approve(digest, "abandon-reviewer-two");
    fixture.stage(package, opening_index, &[&first, &second]);
    let before_abandon = head(&fixture.book);
    let plan = fixture
        .dir
        .join("full-detail-abandon.plan")
        .display()
        .to_string();
    ok(
        &fixture.book,
        &["migrate", "abandon", &fixture.run_vid, "--plan-out", &plan],
    );
    let abandoned = ok(
        &fixture.book,
        &["migrate", "abandon", &fixture.run_vid, "--plan", &plan],
    );
    assert_eq!(text(data(&abandoned), "to"), "Abandoned");
    let after_abandon = head(&fixture.book);
    let shown = fixture.show(package);
    assert_eq!(text(data(&shown), "run_state"), "Abandoned");
    assert_eq!(integer(data(&shown), "recorded_count"), 1);
    assert!(
        rows(data(&shown), "chunks")
            .iter()
            .all(|chunk| { chunk.get("counts_after_finalize") == Some(&Json::Bool(false)) })
    );
    assert_eq!(fixture.cash_at("FY2026-P03", None), "0.00 USD");
    assert_eq!(fixture.cash_at(OPENING, None), "0.00 USD");
    assert_cash_open_items(&fixture, before_abandon, &[]);
    assert_eq!(head(&fixture.book), after_abandon);

    let (sole, _) = Fixture::full_detail(true, "Spreadsheet");
    let mut invalid = sole.intent();
    set_field(
        &mut invalid,
        "opening_entries",
        Json::Arr(vec![s("private-history-funding")]),
    );
    let path = sole.file("sole-with-separate-opening.json", &invalid.render());
    let before = head(&sole.book);
    let (status, refused) = run(
        &sole.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert!(
        refused
            .render()
            .contains("sole-source FullDetail has no opening_entries")
    );
    assert_eq!(head(&sole.book), before);

    let opening_only = Fixture::quickbooks();
    let mut invalid = opening_only.intent();
    set_field(
        &mut invalid,
        "entry_periods",
        obj(vec![("private-source-entry-one", s(OPENING))]),
    );
    let path = opening_only.file("opening-only-with-detail-routing.json", &invalid.render());
    let before = head(&opening_only.book);
    let (status, refused) = run(
        &opening_only.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert!(
        refused
            .render()
            .contains("entry_periods applies only to FullDetail")
    );
    assert_eq!(head(&opening_only.book), before);
}

#[test]
fn full_detail_replay_requires_original_source_authority_and_rejects_rehashed_period_routing() {
    let (fixture, _) = Fixture::full_detail(false, "BankStatement");
    let path = fixture.file("full-detail-governed.json", &fixture.intent().render());
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(status, 3, "{}", refused.render());
    assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-142");
    assert!(!refused.render().contains("private-history-close"));
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
    for action in ["show", "stage"] {
        let mut args = vec![
            "migrate",
            "import",
            "--action",
            action,
            "--package",
            package,
        ];
        if action == "stage" {
            args.extend(["--chunk", "0"]);
        }
        let before = head(&fixture.book);
        let (status, refused) = run(&fixture.book, &args);
        assert_eq!(status, 3, "{}", refused.render());
        assert_eq!(text(data(&refused), "refusal_id"), "FA-REF-142");
        assert!(!refused.render().contains(LEGACY_CASH));
        assert_eq!(head(&fixture.book), before);
    }
    for change_date in [false, true] {
        let forged = rewrite_package(&fixture, package, |_, proposals| {
            let closing = proposals
                .iter_mut()
                .find(|proposal| {
                    proposal
                        .effective_period
                        .as_ref()
                        .is_some_and(|period| period.code == "FY2025-CLOSE")
                })
                .unwrap();
            if change_date {
                closing.effective_date = fa_time::DateDay::parse("2025-12-30").unwrap();
            } else {
                closing.effective_period.as_mut().unwrap().code = "FY2025-P12".into();
            }
        });
        for action in ["show", "stage"] {
            let mut args = vec![
                "migrate",
                "import",
                "--action",
                action,
                "--package",
                &forged,
                "--grant",
                "privileged",
            ];
            if action == "stage" {
                args.extend(["--chunk", "0"]);
            }
            let before = head(&fixture.book);
            let (status, refused) = run(&fixture.book, &args);
            assert_eq!(
                status,
                8,
                "date={change_date}, action={action}: {}",
                refused.render()
            );
            assert_eq!(head(&fixture.book), before);
        }
    }
    let before_retry = head(&fixture.book);
    let repeated = ok(
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
    assert_eq!(text(data(&repeated), "package_oid"), package);
    assert_eq!(data(&repeated).get("chunks"), data(&prepared).get("chunks"));
    assert_eq!(integer(data(&repeated), "recorded_count"), 0);
    assert_eq!(head(&fixture.book), before_retry);
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
        ok(&fixture.book, &["registers", "advance", "--period", period]);
        ok(&fixture.book, &["verify", "registers", "--period", period]);
    }
    assert_eq!(
        fixture.cash_activity(OPENING),
        "125.50 USD",
        "January 1 activity is not opening stock"
    );
    ok(
        &fixture.book,
        &["registers", "advance", "--period", OPENING],
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

/// fa-waow: a Beancount v3 ledger is a legacy source like the five exports.
/// Its full account names map through account_map, the posting without an
/// amount takes the remainder, and the approved opening workflow completes.
#[test]
fn a_beancount_ledger_completes_the_approved_opening_workflow() {
    Fixture::new("beancount", BEANCOUNT, "USD", "Other", "2026-07-01").complete();
}

/// fa-waow: an hledger journal is a legacy source the same way. Its
/// account names (one with a space) map through account_map, the posting
/// without an amount takes the remainder, commodities stand before or after
/// the number, the assertion is not re-checked, and the approved opening
/// workflow completes.
#[test]
fn an_hledger_journal_completes_the_approved_opening_workflow() {
    Fixture::new("hledger", HLEDGER, "USD", "Other", "2026-07-01").complete();
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
    let without_copy = fixture.prepare();
    assert_eq!(
        data(&without_copy).get("already_recorded"),
        Some(&Json::Bool(false))
    );
    let before_copy = head(&fixture.book);
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
    assert_eq!(
        data(&prepared).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    for field in ["package_oid", "package_commit", "chunks", "recorded_at"] {
        assert_eq!(data(&prepared).get(field), data(&without_copy).get(field));
    }
    assert_eq!(head(&fixture.book), before_copy);
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
    drop(book);
    let repeated_without_copy = fixture.prepare();
    assert_eq!(
        data(&repeated_without_copy).get("already_recorded"),
        Some(&Json::Bool(true))
    );
    for field in ["package_oid", "package_commit", "chunks", "recorded_at"] {
        assert_eq!(
            data(&repeated_without_copy).get(field),
            data(&prepared).get(field)
        );
    }
    assert_eq!(std::fs::read(&copy).unwrap(), raw);
    assert_eq!(head(&fixture.book), before_copy);
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
    } else if document
        .bytes
        .starts_with(b"FA-LEGACY-FULL-DETAIL-IMPORT\0")
    {
        assert_eq!(
            document.mime,
            "application/vnd.frankenaccounting.legacy-full-detail-import.v1"
        );
        b"FA-LEGACY-FULL-DETAIL-IMPORT\0"
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

/// A stock trial balance's non-zero rows as `(code, net without the unit)`.
fn stock_lines(book: &Path, period: &str) -> Vec<(String, String)> {
    let result = ok(book, &["tb", "--period", period]);
    rows(data(&result), "rows")
        .iter()
        .filter_map(|row| {
            let net = text(row, "net").strip_suffix(" USD").expect("a USD net");
            (net != "0.00").then(|| (text(row, "code").to_owned(), net.to_owned()))
        })
        .collect()
}

/// fa-eid6, export→import identity (plan §16): a book's own Beancount export,
/// imported into a new book as the sole full-detail history before its
/// opening date, folds to the source book's stock balance in every period,
/// with the source's trial balances as the run's independent tie-outs. A
/// tampered export (one sale moved by 1.00 on both legs, still balanced) no
/// longer ties to its period's trial balance and publishes nothing.
#[test]
fn a_books_beancount_export_imports_as_history_with_identical_period_balances() {
    export_import_identity("beancount");
}

/// The same identity through the book's hledger export and the hledger
/// reader (fa-waow).
#[test]
fn a_books_hledger_export_imports_as_history_with_identical_period_balances() {
    export_import_identity("hledger");
}

fn export_import_identity(format: &str) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let dir = loop {
        let path = std::env::temp_dir().join(format!(
            "fa-export-import-identity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => break path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    };
    let chart_json = r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Owner equity","type":"Equity","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#;

    // The source book posts across FY2025.
    let source = dir.join("source-book");
    ok(
        &source,
        &[
            "book",
            "create",
            "--name",
            "Export source",
            "--base-unit",
            "USD",
        ],
    );
    let chart = dir.join("chart.json");
    std::fs::write(&chart, chart_json).unwrap();
    let chart = chart.display().to_string();
    ok(&source, &["chart", "import", &chart]);
    ok(&source, &["period", "create", "--fiscal-year", "2025"]);
    for period in ["FY2025-P01", "FY2025-P03", "FY2025-P12"] {
        ok(&source, &["period", "open", period]);
    }
    let receipt = dir.join("receipt.txt");
    std::fs::write(&receipt, "RECEIPT (export identity fixture)").unwrap();
    let receipt = receipt.display().to_string();
    let added = ok(
        &source,
        &[
            "document",
            "add",
            &receipt,
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ],
    );
    let evidence = text(data(&added), "oid").to_owned();
    for (key, date, debit, credit, amount, memo) in [
        (
            "capital",
            "2025-01-05",
            "1000",
            "3000",
            "1000.00",
            "Owner capital",
        ),
        (
            "march-sale",
            "2025-03-10",
            "1000",
            "4000",
            "250.00",
            "March sale",
        ),
        (
            "march-rent",
            "2025-03-20",
            "6000",
            "1000",
            "75.25",
            "March rent",
        ),
        (
            "december-sale",
            "2025-12-15",
            "1000",
            "4000",
            "40.00",
            "December sale",
        ),
    ] {
        let intent = dir.join(format!("{key}.json"));
        std::fs::write(
            &intent,
            format!(
                r#"{{"effective_date":"{date}","idempotency_key":"{key}","legs":[{{"side":"debit","account":"{debit}","amount":"{amount} USD"}},{{"side":"credit","account":"{credit}","amount":"{amount} USD"}}],"description":"{memo}"}}"#
            ),
        )
        .unwrap();
        let intent = intent.display().to_string();
        ok(
            &source,
            &["post", "--intent", &intent, "--evidence", &evidence],
        );
    }
    let periods: Vec<String> = (1..=12).map(|m| format!("FY2025-P{m:02}")).collect();
    let expected: Vec<Vec<(String, String)>> =
        periods.iter().map(|p| stock_lines(&source, p)).collect();
    assert_eq!(
        expected[11],
        [
            ("1000".to_owned(), "1214.75".to_owned()),
            ("3000".to_owned(), "-1000.00".to_owned()),
            ("4000".to_owned(), "-290.00".to_owned()),
            ("6000".to_owned(), "75.25".to_owned()),
        ],
        "the source's year-end balances"
    );

    // Its Beancount export.
    let exported = dir.join(format!("export.{format}"));
    let exported_path = exported.display().to_string();
    let written = ok(
        &source,
        &[
            "export",
            format,
            "--as-of",
            "2025-12-31",
            "--out",
            &exported_path,
        ],
    );
    assert_eq!(integer(data(&written), "entries"), 4);
    let ledger = std::fs::read_to_string(&exported).unwrap();

    // The importing book opens on 2026-01-01; FY2025 is its history.
    let book = dir.join("import-book");
    ok(
        &book,
        &[
            "book",
            "create",
            "--name",
            "Imported history",
            "--base-unit",
            "USD",
            "--opening-date",
            "2026-01-01",
        ],
    );
    let fixture = Fixture {
        dir: dir.clone(),
        book,
        unit: "USD".into(),
        source: String::new(),
        trial_balance: String::new(),
        run_vid: String::new(),
        format: format.into(),
        opening_entries: None,
        entry_periods: None,
        period_trial_balances: Vec::new(),
    };
    ok(&fixture.book, &["chart", "import", &chart]);
    ok(
        &fixture.book,
        &["period", "create", "--fiscal-year", "2025"],
    );
    let opening = fixture.document(
        "separate-opening-tb.csv",
        &tb_document("separate-opening", &[]),
        "Spreadsheet",
    );
    let mut period_rows = Vec::new();
    for (period, lines) in periods.iter().zip(&expected) {
        let lines: Vec<(&str, &str)> = lines
            .iter()
            .map(|(code, net)| (code.as_str(), net.as_str()))
            .collect();
        let document = fixture.document(
            &format!("source-tb-{period}.csv"),
            &tb_document(period, &lines),
            "Spreadsheet",
        );
        period_rows.push(obj(vec![
            ("period", s(period)),
            ("trial_balance", s(&document)),
            ("lines", tb_lines(&lines)),
        ]));
    }
    let run_body = obj(vec![
        ("run_key", s("export-identity")),
        ("source_system", s(format)),
        ("mode", s("FullDetail")),
        ("trial_balance", s(&opening)),
        ("opening_date", s("2026-01-01")),
        ("lines", tb_lines(&[])),
        ("periods", Json::Arr(period_rows)),
        ("detail_base", tb_lines(&[])),
        ("sole_opening_source", Json::Bool(true)),
    ]);
    let run_path = fixture.file("export-identity-run.json", &run_body.render());
    let opened = ok(&fixture.book, &["migrate", "open", "--intent", &run_path]);
    let run_vid = text(data(&opened), "run_vid").to_owned();
    let import = |source_oid: &str| {
        obj(vec![
            ("run", s(format!("MR:{run_vid}"))),
            ("source", s(format!("D:{source_oid}"))),
            ("format", s(format)),
            (
                "account_map",
                obj(vec![
                    ("Assets:A1000", s("1000")),
                    ("Equity:A3000", s("3000")),
                    ("Income:A4000", s("4000")),
                    ("Expenses:A6000", s("6000")),
                ]),
            ),
        ])
    };

    // Planted: the March sale moved by 1.00 on both legs still balances, but
    // no longer ties to March's trial balance; nothing is published.
    let tampered = ledger
        .replace("  250.00 USD\n", "  251.00 USD\n")
        .replace("  -250.00 USD\n", "  -251.00 USD\n");
    assert_ne!(tampered, ledger, "the planted edit applies");
    let tampered_oid = fixture.document(&format!("tampered.{format}"), &tampered, "Other");
    let tampered_intent = fixture.file("tampered-import.json", &import(&tampered_oid).render());
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "prepare",
            "--intent",
            &tampered_intent,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert_eq!(text(&refused, "event"), "error");
    assert_eq!(
        head(&fixture.book),
        before,
        "a refused preparation publishes nothing"
    );

    // The true export imports and folds to the source in every period.
    let source_oid = fixture.document(&format!("export.{format}"), &ledger, "Other");
    let intent = fixture.file("import.json", &import(&source_oid).render());
    let prepared = ok(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &intent,
        ],
    );
    assert_eq!(text(data(&prepared), "mode"), "FullDetail");
    assert_eq!(rows(data(&prepared), "chunks").len(), 4);
    let fixture = Fixture { run_vid, ..fixture };
    stage_full_detail(&fixture, &prepared, "FY2025-P12");
    assert_eq!(
        text(data(&fixture.finalize("export-identity.plan")), "to"),
        "Finalized"
    );
    for (period, lines) in periods.iter().zip(&expected) {
        assert_eq!(
            &stock_lines(&fixture.book, period),
            lines,
            "{period}: the imported history folds to the source's balances"
        );
    }
}
