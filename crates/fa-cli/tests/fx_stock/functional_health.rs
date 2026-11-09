//! Real CLI processes expose functional currentness and fail whole-book
//! verification for a damaged optional cache without repairing it implicitly.

use super::*;

const VERIFY: &[&str] = &[
    "verify",
    "registers",
    "--functional",
    "--period",
    "FY2026-P01",
];
const ADVANCE: &[&str] = &[
    "registers",
    "advance",
    "--functional",
    "--period",
    "FY2026-P01",
];

fn health(output: &Json) -> &Json {
    &rows(data(output), "periods")[0]
}

fn strict() -> Vec<&'static str> {
    let mut args = VERIFY.to_vec();
    args.push("--require-materialized");
    args
}

fn run_book(book: &Path) -> (i32, Vec<Json>) {
    let output = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(["--via", "direct", "verify", "book", "--json"])
        .env_remove("FA_BOOK")
        .env_remove("FA_TOKEN")
        .env_remove("FA_KEYS")
        .output()
        .expect("run whole-book verification");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let registry = fa_cli::verbs::registry().unwrap();
    let events = stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|error| panic!("{error}\n{stdout}\n{stderr}"));
            json::parse(line).unwrap()
        })
        .collect();
    (output.status.code().unwrap(), events)
}

fn summary(events: &[Json]) -> &Json {
    data(
        events
            .iter()
            .find(|event| text(event, "event") == "book_verification")
            .unwrap_or_else(|| panic!("no whole-book verdict: {events:?}")),
    )
}

#[test]
fn functional_health_survives_cold_reopen_and_refuses_retired_history() {
    let seed = 0xc6;
    let fixture = Fixture::create(Some(seed));
    fixture.post("functional-health-initial", "2026-01-05", "100.00", 11);
    let original = head(&fixture.book).to_string();
    let absent = ok(&fixture.book, VERIFY);
    assert_eq!(text(health(&absent), "status"), "absent");
    assert_eq!(health(&absent).get("stale"), Some(&Json::Bool(true)));
    assert!(integer(health(&absent), "lag_entries") > 0);
    let strict = strict();
    let (code, refusal) = run(&fixture.book, &strict);
    assert_eq!(code, 8, "{}", refusal.render());
    assert!(
        refusal
            .render()
            .contains("registers advance --functional --period FY2026-P01")
    );
    assert_eq!(head(&fixture.book).to_string(), original);
    let (code, events) = run_book(&fixture.book);
    assert_eq!(code, 0, "{events:?}");
    assert_eq!(summary(&events).get("green"), Some(&Json::Bool(true)));

    let initial = ok(&fixture.book, ADVANCE);
    let publication = integer(data(&initial), "recorded_at");
    let through = integer(data(&initial), "through");
    assert!(publication > through);
    let current = ok(&fixture.book, &strict);
    assert_eq!(health(&current).get("stale"), Some(&Json::Bool(false)));
    assert_eq!(integer(health(&current), "lag_entries"), 0);
    assert_eq!(integer(health(&current), "through"), through);

    // A document and maintenance of either family advance the database
    // frontier without creating Entry work. A daemon maintaining both
    // families must not perpetually report that they made one another stale.
    fixture.rate("functional-health-unused-rate", "2026-01-06", 13);
    ok(
        &fixture.book,
        &["registers", "advance", "--period", "FY2026-P01"],
    );
    ok(
        &fixture.book,
        &[
            "registers",
            "advance",
            "--functional",
            "--period",
            "FY2026-P02",
        ],
    );
    let current = ok(&fixture.book, &strict);
    assert_eq!(health(&current).get("stale"), Some(&Json::Bool(false)));
    assert_eq!(integer(health(&current), "lag_entries"), 0);
    assert_eq!(integer(health(&current), "through"), through);
    let before_tail = head(&fixture.book).to_string();

    // Another period still contributes to this book-wide continuation
    // cursor. Its one Entry, not its Rate document, is the unread work.
    fixture.post("functional-health-february", "2026-02-05", "20.00", 12);
    let before_check = head(&fixture.book);
    let lagging = ok(&fixture.book, VERIFY);
    assert_eq!(text(health(&lagging), "status"), "verified_prefix");
    assert_eq!(health(&lagging).get("stale"), Some(&Json::Bool(true)));
    assert_eq!(integer(health(&lagging), "lag_entries"), 1);
    let (code, refusal) = run(&fixture.book, &strict);
    assert_eq!(code, 8, "{}", refusal.render());
    assert!(refusal.render().contains("unread journal entries"));
    assert_eq!(head(&fixture.book), before_check);

    let mut historical = strict.clone();
    historical.extend(["--as-known-at", &before_tail]);
    let old = ok(&fixture.book, &historical);
    assert_eq!(health(&old).get("stale"), Some(&Json::Bool(false)));
    assert_eq!(integer(health(&old), "lag_entries"), 0);
    let mut absent_history = strict.clone();
    absent_history.extend(["--as-known-at", &original]);
    let (code, refusal) = run(&fixture.book, &absent_history);
    assert_eq!(code, 8, "{}", refusal.render());
    assert!(refusal.render().contains("\"status\":\"absent\""));

    ok(&fixture.book, ADVANCE);
    let caught_up = ok(&fixture.book, &strict);
    assert_eq!(health(&caught_up).get("stale"), Some(&Json::Bool(false)));
    assert_eq!(integer(health(&caught_up), "lag_entries"), 0);

    let selected = ok(
        &fixture.book,
        &[
            "verify",
            "registers",
            "--functional",
            "--period",
            "FY2026-P02",
            "--period",
            "FY2026-P01",
        ],
    );
    let periods = rows(data(&selected), "periods");
    assert_eq!(periods.len(), 2);
    assert_eq!(text(&periods[0], "period"), "FY2026-P01");
    assert_eq!(integer(&periods[0], "lag_entries"), 0);
    assert_eq!(text(&periods[1], "period"), "FY2026-P02");
    assert_eq!(integer(&periods[1], "lag_entries"), 1);

    // Every command above reopened the book and verified retained source
    // history. Actual storage compaction retires that native evidence;
    // neither a current cache nor relaxed currentness can replace it.
    let before_compact = head(&fixture.book);
    fixture.compact(seed);
    for args in [VERIFY, strict.as_slice()] {
        let (code, refusal) = run(&fixture.book, args);
        assert_eq!(code, 5, "{}", refusal.render());
        assert!(
            refusal
                .render()
                .contains(fa_journal::refusal::code::REPLAY_UNSUPPORTED)
        );
        assert_eq!(head(&fixture.book), before_compact);
    }
}

#[test]
fn whole_book_verification_detects_damaged_functional_cache_and_explicit_repair() {
    let seed = 0xc7;
    let fixture = Fixture::create(Some(seed));
    fixture.post("functional-health-damage", "2026-01-05", "100.00", 11);
    let advanced = ok(&fixture.book, ADVANCE);
    let intact = head(&fixture.book).to_string();
    let reference = fa_registers::functional_maintainer::CheckpointRef {
        through: CommitSeq(u64::try_from(integer(data(&advanced), "checkpoint_through")).unwrap()),
        body_digest: unhex(text(data(&advanced), "checkpoint_digest"))
            .try_into()
            .unwrap(),
    };
    let snapshot = fa_registers::functional_maintainer::checkpoint_vid(
        fa_model::Id128([seed; 16]),
        "FY2026-P01",
        reference,
    );
    let runtime = RuntimeBuilder::new().build().unwrap();
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let cx = PurposeContexts::narrow_runtime_root(&root);
    let mut db = runtime
        .block_on(Database::open(
            &cx.commit(),
            &fixture.book.join("store"),
            db_keys(seed),
        ))
        .unwrap();
    let mut damage = WriteBatch::new(relation::IN_PERIOD);
    damage.set_vertex_property(
        snapshot,
        property::FA_PAYLOAD,
        Some(fa_journal::rows::scalar_bytes("damaged functional snapshot", vec![0]).unwrap()),
    );
    runtime.block_on(db.write(&cx.commit(), damage)).unwrap();
    drop(db);

    let damaged_at = head(&fixture.book);
    let (code, events) = run_book(&fixture.book);
    assert_eq!(code, 8, "{events:?}");
    let verdict = summary(&events);
    assert_eq!(verdict.get("green"), Some(&Json::Bool(false)));
    for target in rows(verdict, "targets") {
        assert_eq!(
            text(target, "verdict"),
            if text(target, "target") == "functional-registers" {
                "fail"
            } else {
                "pass"
            },
            "{events:?}",
        );
    }
    assert!(
        events
            .iter()
            .any(|event| event.render().contains("fa verify registers --functional"))
    );
    let (code, failure) = run(&fixture.book, &strict());
    assert_eq!(code, 8, "{}", failure.render());
    assert!(failure.render().contains("\"status\":\"drift\""));
    assert!(failure.render().contains("\"stale\":false"));
    assert!(
        failure
            .render()
            .contains("registers materialize --functional")
    );
    assert_eq!(head(&fixture.book), damaged_at);
    let historical = ok(
        &fixture.book,
        &[
            "verify",
            "registers",
            "--functional",
            "--period",
            "FY2026-P01",
            "--require-materialized",
            "--as-known-at",
            &intact,
        ],
    );
    assert_eq!(text(health(&historical), "status"), "verified_prefix");
    let report = ok(
        &fixture.book,
        &["tb", "--functional", "--activity", "--period", "FY2026-P01"],
    );
    assert_eq!(total_debits(&report), "110.00 USD");
    assert_eq!(
        head(&fixture.book),
        damaged_at,
        "literal fallback does not repair the cache"
    );
    let (code, failure) = run(&fixture.book, ADVANCE);
    assert_eq!(code, 8, "{}", failure.render());
    assert_eq!(head(&fixture.book), damaged_at);
    ok(
        &fixture.book,
        &[
            "registers",
            "materialize",
            "--functional",
            "--period",
            "FY2026-P01",
            "--yes",
        ],
    );
    let repaired = ok(&fixture.book, &strict());
    assert_eq!(health(&repaired).get("stale"), Some(&Json::Bool(false)));
    let (code, events) = run_book(&fixture.book);
    assert_eq!(code, 0, "{events:?}");
    assert_eq!(summary(&events).get("green"), Some(&Json::Bool(true)));
}
