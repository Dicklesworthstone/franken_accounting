//! Older native symbol births remain reportable after checkpoint and reopen.
//! Each command runs the real binary against cold retained history; the fixture
//! creates the historical Book at genesis, never by rewriting a current Book.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use asupersync::Budget;
use asupersync::fs::UnixVfs;
use asupersync::runtime::RuntimeBuilder;
use fa::{Book, BookKeys, Entropy, ReportArtifact};
use fa_cli::json::{self, Json};
use fa_journal::BookSpec;
use fa_journal::blob::DurableDirectory;
use fa_journal::rows::{book_root, bytes};
use fa_model::symbols::{SYMBOLS_DIGEST_DOMAIN, label, property, relation};
use fa_model::{Id128, SymbolTable, domain_digest};
use fa_policy::{CapabilityToken, Op};
use fgdb::{Database, DatabaseKeys, ReadError, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::ids::DatabaseSecurityNamespaceId;
use fgdb_types::{CanonicalScalar, CommitSeq};

const SEED: u8 = 182;
const BOOK: Id128 = Id128([SEED; 16]);
const PERIOD: &str = "FY2026-P03";
const READER: &str = "reader.token";
const PRODUCER: &str = "producer.token";

fn temporary() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let path = std::env::temp_dir().join(format!(
            "fa-report-symbol-compatibility-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create {}: {error}", path.display()),
        }
    }
}

fn data(event: &Json) -> &Json {
    event.get("data").expect("event data")
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_else(|| panic!("{key}: {value:?}"))
}

fn number(value: &Json, key: &str) -> i128 {
    match value.get(key) {
        Some(Json::Int(value)) => *value,
        _ => panic!("{key}: {value:?}"),
    }
}

fn array<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    value
        .get(key)
        .and_then(Json::as_arr)
        .unwrap_or_else(|| panic!("{key}: {value:?}"))
}

fn row<'a>(value: &'a Json, collection: &str, code: &str) -> &'a Json {
    array(value, collection)
        .iter()
        .find(|row| text(row, "code") == code)
        .unwrap_or_else(|| panic!("{collection}/{code}: {value:?}"))
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn db_keys() -> DatabaseKeys {
    DatabaseKeys::new(
        [SEED; 32],
        DatabaseSecurityNamespaceId([SEED.wrapping_add(1); 32]),
        [SEED.wrapping_add(2); 32],
    )
}

fn prefix_digest() -> [u8; 32] {
    let mut symbols = fa_registry::Symbols::embedded().unwrap();
    let digest = |symbols: &fa_registry::Symbols| {
        // Symbols use raw domain || canonical bytes. No length-framed part is
        // added; validate the construction against the complete compiled table.
        let mut preimage = SYMBOLS_DIGEST_DOMAIN.to_vec();
        preimage.extend_from_slice(&symbols.canonical_bytes());
        domain_digest(&preimage, &[])
    };
    assert_eq!(digest(&symbols), SymbolTable::compiled().digest().0);
    symbols.labels.retain(|_, id| *id <= 43);
    let prefix = digest(&symbols);
    assert_ne!(prefix, SymbolTable::compiled().digest().0);
    prefix
}

fn create_historical_book(parent: &Path, book: &Path) -> [u8; 32] {
    let symbols = prefix_digest();
    let keys = BookKeys::for_development(SEED);
    let template_path = parent.join("current-genesis-template");
    let template = Book::create_dir(
        &template_path,
        keys.clone(),
        BookSpec {
            book_id: BOOK,
            name: "Native older symbol birth".into(),
            base_unit: fa_money::UnitRegistry::embedded()
                .unwrap()
                .lookup("USD")
                .unwrap(),
            calendar: fa_time::FiscalCalendar::monthly("historical-symbol-cli", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(u64::from(SEED)),
    )
    .unwrap();
    assert_eq!(template.head().unwrap(), CommitSeq(1));
    drop(template);

    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let template = runtime
        .block_on(Database::open(
            &cx.commit(),
            &template_path.join("store"),
            db_keys(),
        ))
        .unwrap();
    let mut rows = template.vertices_at(CommitSeq(1)).unwrap();
    rows.sort_by_key(|row| row.birth_ordinal);
    let edges = template.edges_at(CommitSeq(1)).unwrap();
    assert!(rows.iter().all(
        |row| row.labels.as_slice() == [label::BOOK] || row.labels.as_slice() == [label::UNIT]
    ));
    let mut genesis = WriteBatch::new(relation::IN_BOOK);
    for mut row in rows {
        if row.vid == book_root() {
            let (_, value) = row
                .props
                .iter_mut()
                .find(|(key, _)| *key == property::SYMBOLS_DIGEST)
                .unwrap();
            *value = CanonicalScalar::bytes(symbols.to_vec()).unwrap();
        }
        genesis.create_vertex(row.vid, row.labels, row.props);
    }
    for edge in edges {
        assert_eq!(edge.entry.relation, relation::IN_BOOK);
        genesis.add_edge(edge.entry.eid, edge.entry.src, edge.entry.dst, edge.props);
    }
    drop(template);
    let commit = cx.commit();
    let directory = runtime
        .block_on(DurableDirectory::create(&commit, UnixVfs, book))
        .unwrap();
    runtime.block_on(directory.child(&commit, "blobs")).unwrap();
    let mut db = runtime
        .block_on(Database::create_with_vfs(
            &commit,
            UnixVfs,
            directory.path().join("store"),
            db_keys(),
        ))
        .unwrap();
    let born = runtime.block_on(db.write(&commit, genesis)).unwrap();
    assert_eq!(born, CommitSeq(1));
    let original = db.vertex_at(book_root(), born).unwrap().unwrap();
    assert_eq!(
        bytes(&original, property::SYMBOLS_DIGEST, "original symbols").unwrap(),
        symbols
    );
    drop(db);
    keys.save(&book.join("book.keys")).unwrap();
    symbols
}

struct Fixture {
    dir: PathBuf,
    book: PathBuf,
    symbols: [u8; 32],
    evidence: String,
    capital: String,
    sale: String,
    selected: CommitSeq,
}

impl Fixture {
    fn new() -> Self {
        let dir = temporary();
        let book = dir.join("book");
        let symbols = create_historical_book(&dir, &book);
        let mut fixture = Self {
            dir,
            book,
            symbols,
            evidence: String::new(),
            capital: String::new(),
            sale: String::new(),
            selected: CommitSeq(0),
        };
        std::fs::write(fixture.dir.join("chart.json"), r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"},{"code":"4000","name":"Sales","type":"Revenue","unit":"USD"}]}"#).unwrap();
        fixture.ok(&["chart", "import", "chart.json"]);
        fixture.ok(&["period", "create", "--fiscal-year", "2026"]);
        fixture.ok(&["period", "open", PERIOD]);
        std::fs::write(
            fixture.dir.join("source.txt"),
            b"Retained funding and sale evidence for historical symbol compatibility",
        )
        .unwrap();
        let document = fixture.ok(&[
            "document",
            "add",
            "source.txt",
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ]);
        fixture.evidence = text(data(&document[0]), "oid").into();
        fixture.capital = fixture.post("capital", "2026-03-01", "3000", "100.00 USD");
        fixture.sale = fixture.post("sale", "2026-03-15", "4000", "25.00 USD");
        for (holder, path, ops) in [
            ("prefix-reader", READER, vec!["read"]),
            ("prefix-producer", PRODUCER, vec!["read", "produce"]),
        ] {
            let mut args = vec![
                "capability",
                "issue",
                "--holder",
                holder,
                "--profile",
                "human",
                "--out",
                path,
                "--grant",
                "issue_capability",
            ];
            for op in ops {
                args.extend(["--op", op, "--grant", op]);
            }
            fixture.ok(&args);
        }
        let reader =
            CapabilityToken::decode(&std::fs::read(fixture.dir.join(READER)).unwrap()).unwrap();
        assert_eq!(
            reader
                .capability()
                .ops()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![Op::Read]
        );
        let producer =
            CapabilityToken::decode(&std::fs::read(fixture.dir.join(PRODUCER)).unwrap()).unwrap();
        assert_eq!(
            producer
                .capability()
                .ops()
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![Op::Read, Op::Produce]
        );
        fixture.selected = fixture.head();
        fixture
    }

    fn run(&self, args: &[&str]) -> (i32, Vec<Json>) {
        let output = Command::new(env!("CARGO_BIN_EXE_fa"))
            .current_dir(&self.dir)
            .args(["--book", "book", "--via", "direct"])
            .args(args)
            .arg("--json")
            .env_remove("FA_BOOK")
            .env_remove("FA_TOKEN")
            .env_remove("FA_KEYS")
            .output()
            .expect("run fa");
        let stdout = String::from_utf8(output.stdout).unwrap();
        let registry = fa_cli::verbs::registry().unwrap();
        let events = stdout
            .lines()
            .map(|line| {
                registry
                    .check_line(line)
                    .unwrap_or_else(|error| panic!("args={args:?}: {error}\n{line}"));
                json::parse(line).unwrap()
            })
            .collect::<Vec<_>>();
        assert!(
            !events.is_empty(),
            "args={args:?}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        (output.status.code().unwrap_or(-1), events)
    }

    fn ok(&self, args: &[&str]) -> Vec<Json> {
        let (status, events) = self.run(args);
        assert_eq!(status, 0, "args={args:?}: {events:?}");
        events
    }

    fn head(&self) -> CommitSeq {
        Book::open_dir(
            &self.book,
            BookKeys::for_development(SEED),
            Entropy::deterministic(183),
        )
        .unwrap()
        .head()
        .unwrap()
    }

    fn compact(&self) {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let mut db = runtime
            .block_on(Database::open(
                &cx.commit(),
                &self.book.join("store"),
                db_keys(),
            ))
            .unwrap();
        let at = db.frontier().unwrap();
        runtime.block_on(db.compact(&cx.commit())).unwrap();
        assert_eq!(db.frontier().unwrap(), at);
        drop(db);
        let reopened = runtime
            .block_on(Database::open(
                &cx.commit(),
                &self.book.join("store"),
                db_keys(),
            ))
            .unwrap();
        assert!(
            matches!(
                reopened.delta_since(CommitSeq(0)),
                Err(ReadError::DeltaCursorRetired { .. })
            ),
            "fixture must start with retired in-memory genesis history"
        );
        let current = reopened.vertex_at(book_root(), at).unwrap().unwrap();
        assert_eq!(
            bytes(
                &current,
                property::SYMBOLS_DIGEST,
                "unchanged original symbols"
            )
            .unwrap(),
            self.symbols
        );
        assert_eq!(reopened.frontier().unwrap(), at);
    }

    fn post(&self, key: &str, date: &str, credit: &str, amount: &str) -> String {
        let name = format!("{key}.json");
        std::fs::write(self.dir.join(&name), format!(r#"{{"idempotency_key":"{key}","effective_date":"{date}","legs":[{{"side":"debit","account":"1000","amount":"{amount}"}},{{"side":"credit","account":"{credit}","amount":"{amount}"}}]}}"#)).unwrap();
        let posted = self.ok(&["post", "--intent", &name, "--evidence", &self.evidence]);
        text(data(&posted[0]), "vid").into()
    }

    fn certify(&self, name: &str, args: &[&str], selected: CommitSeq, family: &str) -> Saved {
        self.compact();
        let before = self.head();
        let file = format!("{name}.certificate");
        let mut command = args.to_vec();
        command.extend(["--certificate-out", &file]);
        let events = self.ok(&command);
        assert_eq!(events.len(), 2, "{events:?}");
        assert_eq!(text(&events[1], "event"), "report_certificate");
        let receipt = data(&events[1]);
        let oid = text(receipt, "oid").to_owned();
        let bytes = std::fs::read(self.dir.join(&file)).unwrap();
        let artifact = ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(artifact.family().name(), family);
        assert_eq!(artifact.canonical_bytes().unwrap(), bytes);
        assert_eq!(hex(artifact.digest()), oid);
        assert_eq!(artifact.known_at(), selected);
        assert_eq!(artifact.book_id(), BOOK);
        assert!(!artifact.source_certificate().inputs.is_empty());
        assert_eq!(text(&events[0], "certificate"), oid);
        assert_eq!(number(receipt, "known_at"), i128::from(selected.0));
        let recorded_at = number(receipt, "recorded_at");
        assert!(recorded_at > i128::from(before.0));
        assert_eq!(i128::from(self.head().0), recorded_at);
        Saved {
            name: name.into(),
            file,
            command: args.iter().map(|arg| (*arg).to_string()).collect(),
            original: events[0].clone(),
            artifact,
            oid,
            recorded_at,
        }
    }

    fn retry(&self, saved: &Saved) {
        self.compact();
        let before = self.head();
        let mut args: Vec<_> = saved.command.iter().map(String::as_str).collect();
        args.push("--certify");
        let retried = self.ok(&args);
        assert_eq!(data(&retried[0]), data(&saved.original));
        assert_eq!(text(data(&retried[1]), "oid"), saved.oid);
        assert_eq!(number(data(&retried[1]), "recorded_at"), saved.recorded_at);
        assert_eq!(self.head(), before, "retained retry writes nothing");
    }

    fn replay(&self, saved: &Saved) {
        let handle = format!("C:{}", saved.oid);
        for (kind, input) in [("file", saved.file.as_str()), ("retained", handle.as_str())] {
            self.compact();
            let before = self.head();
            let output = format!("{}-{kind}.report", saved.name);
            let replay = self.ok(&["--token", READER, "replay", input, "--output", &output]);
            assert_eq!(replay.len(), 2);
            assert_eq!(text(&replay[0], "event"), text(&saved.original, "event"));
            assert_eq!(data(&replay[0]), data(&saved.original));
            assert_eq!(text(&replay[0], "certificate"), saved.oid);
            assert_eq!(
                number(replay[0].get("coordinate").unwrap(), "known_at"),
                i128::from(saved.artifact.known_at().0)
            );
            assert_eq!(text(&replay[1], "event"), "report_replayed");
            assert_eq!(
                std::fs::read(self.dir.join(output)).unwrap(),
                saved.artifact.output()
            );
            assert_eq!(
                self.head(),
                before,
                "cold replay publishes no metadata or entries"
            );
        }
    }
}

struct Saved {
    name: String,
    file: String,
    command: Vec<String>,
    original: Json,
    artifact: ReportArtifact,
    oid: String,
    recorded_at: i128,
}

#[test]
fn checkpointed_prefix_books_certify_and_replay_native_reports_with_only_issued_read() {
    let fixture = Fixture::new();
    let selected = fixture.selected.0.to_string();
    let mut saved = Vec::new();
    for (name, command, event) in [
        (
            "trial-balance",
            vec!["tb", "--period", PERIOD],
            "trial_balance",
        ),
        (
            "income",
            vec!["statement", "income-statement", "--for", PERIOD],
            "statement",
        ),
        (
            "cash-items",
            vec!["open-items", "--account", "1000"],
            "open_items",
        ),
        (
            "cash-explanation",
            vec!["explain", "balance", "1000", "--period", PERIOD],
            "balance_explained",
        ),
    ] {
        let mut args = command;
        args.extend(["--as-known-at", &selected, "--token", READER]);
        let ordinary = if name == "income" {
            fixture.compact();
            let before = fixture.head();
            let original = fixture.ok(&args);
            assert_eq!(fixture.head(), before);
            Some(original[0].clone())
        } else {
            None
        };
        let certificate = fixture.certify(name, &args, fixture.selected, "native");
        assert_eq!(text(&certificate.original, "event"), event);
        let report = data(&certificate.original);
        match name {
            "trial-balance" => {
                assert_eq!(array(report, "rows").len(), 3);
                assert_eq!(text(row(report, "rows", "1000"), "net"), "125.00 USD");
                assert_eq!(text(row(report, "rows", "3000"), "net"), "-100.00 USD");
                assert_eq!(text(row(report, "rows", "4000"), "net"), "-25.00 USD");
                assert_eq!(report.get("balanced"), Some(&Json::Bool(true)));
            }
            "income" => {
                assert_eq!(
                    array(row(report, "lines", "net_income"), "amounts"),
                    &[Json::Str("25.00 USD".into())]
                );
                assert_eq!(report, data(ordinary.as_ref().unwrap()));
            }
            "cash-items" => {
                assert_eq!(number(report, "count"), 2);
                let mut items: Vec<_> = array(report, "items")
                    .iter()
                    .map(|item| (text(item, "entry"), text(item, "open")))
                    .collect();
                items.sort_unstable();
                let mut expected = vec![
                    (fixture.capital.as_str(), "100.00 USD"),
                    (fixture.sale.as_str(), "25.00 USD"),
                ];
                expected.sort_unstable();
                assert_eq!(items, expected);
                assert!(
                    array(report, "items")
                        .iter()
                        .all(|item| array(item, "applications").is_empty())
                );
            }
            "cash-explanation" => {
                assert_eq!(array(report, "cells").len(), 1);
                assert_eq!(text(&array(report, "cells")[0], "net"), "125.00 USD");
                assert_eq!(array(report, "contributions").len(), 2);
                assert!(
                    array(report, "contributions")
                        .iter()
                        .all(|item| array(item, "evidence").len() == 1)
                );
            }
            _ => unreachable!(),
        }
        fixture.retry(&certificate);
        saved.push(certificate);
    }
    fixture.post("later-backdated-sale", "2026-03-12", "4000", "7.00 USD");
    for certificate in &saved {
        fixture.replay(certificate);
    }
    let current = fixture.ok(&["tb", "--period", PERIOD]);
    assert_eq!(
        text(row(data(&current[0]), "rows", "1000"), "net"),
        "132.00 USD"
    );

    let token = CapabilityToken::decode(&std::fs::read(fixture.dir.join(READER)).unwrap()).unwrap();
    fixture.ok(&[
        "capability",
        "revoke",
        "--commitment",
        &hex(&token.capability().commitment().unwrap()),
        "--grant",
        "issue_capability",
        "--yes",
    ]);
    for (name, command) in [
        (
            "revoked-cert",
            vec![
                "tb",
                "--period",
                PERIOD,
                "--as-known-at",
                &selected,
                "--certificate-out",
                "revoked.certificate",
            ],
        ),
        (
            "revoked-replay",
            vec![
                "replay",
                saved[0].file.as_str(),
                "--output",
                "revoked.report",
            ],
        ),
    ] {
        fixture.compact();
        let before = fixture.head();
        let mut args = command;
        args.extend(["--token", READER]);
        let (status, events) = fixture.run(&args);
        assert_eq!(status, 7, "{name}: {events:?}");
        assert_eq!(events.len(), 1);
        assert_eq!(text(data(&events[0]), "refusal_id"), "FA-REF-023");
        assert_eq!(events[0].get("book"), Some(&Json::Null));
        assert_eq!(events[0].get("coordinate"), Some(&Json::Null));
        assert!(!fixture.dir.join("revoked.certificate").exists());
        assert!(!fixture.dir.join("revoked.report").exists());
        assert_eq!(fixture.head(), before);
    }
}

#[test]
fn checkpointed_prefix_statement_bridges_read_and_certify_every_retained_frontier() {
    let fixture = Fixture::new();
    let before = fixture.selected;
    fixture.post("bridge-sale", "2026-03-20", "4000", "5.00 USD");
    let after = fixture.head();
    assert_eq!(after.0, before.0 + 1);
    let before_arg = before.0.to_string();
    let after_arg = after.0.to_string();
    let mut saved = Vec::new();
    for mode in ["diff", "trace"] {
        let base = vec![
            "statement",
            mode,
            "--definition",
            "income-statement",
            "--for",
            PERIOD,
            "--before",
            &before_arg,
            "--after",
            &after_arg,
        ];
        fixture.compact();
        let frontier = fixture.head();
        let mut reader = base.clone();
        reader.extend(["--token", READER]);
        let plain = fixture.ok(&reader);
        assert_eq!(plain.len(), 1);
        assert_eq!(fixture.head(), frontier);
        reader.push("--certify");
        let (status, refused) = fixture.run(&reader);
        assert_eq!(status, 7, "{refused:?}");
        assert_eq!(refused.len(), 1);
        assert_eq!(refused[0].get("book"), Some(&Json::Null));
        assert_eq!(refused[0].get("coordinate"), Some(&Json::Null));
        assert_eq!(fixture.head(), frontier);
        let mut producer = base;
        producer.extend(["--token", PRODUCER]);
        let certificate = fixture.certify(mode, &producer, after, &format!("statement-{mode}"));
        assert_eq!(data(&certificate.original), data(&plain[0]));
        let report = data(&certificate.original);
        assert_eq!(number(report, "before_known_at"), i128::from(before.0));
        assert_eq!(number(report, "after_known_at"), i128::from(after.0));
        let income = row(report, "lines", "net_income");
        assert_eq!(array(income, "before"), &[Json::Str("25.00 USD".into())]);
        assert_eq!(array(income, "after"), &[Json::Str("30.00 USD".into())]);
        assert_eq!(array(income, "delta"), &[Json::Str("5.00 USD".into())]);
        if mode == "trace" {
            assert_eq!(number(report, "publication_count"), 1);
            assert_eq!(array(report, "publications").len(), 1);
            let trace = fa::StatementTraceCertificate::decode(
                &std::fs::read(fixture.dir.join(&certificate.file)).unwrap(),
            )
            .unwrap();
            assert_eq!(
                trace
                    .sources()
                    .iter()
                    .map(|source| source.known_at)
                    .collect::<Vec<_>>(),
                vec![before, after]
            );
        } else {
            let diff = fa::StatementDiffCertificate::decode(
                &std::fs::read(fixture.dir.join(&certificate.file)).unwrap(),
            )
            .unwrap();
            assert_eq!(diff.sources().0.known_at, before);
            assert_eq!(diff.sources().1.known_at, after);
        }
        fixture.retry(&certificate);
        saved.push(certificate);
    }
    fixture.post("later-bridge-correction", "2026-03-18", "4000", "9.00 USD");
    for certificate in &saved {
        fixture.replay(certificate);
    }
}
