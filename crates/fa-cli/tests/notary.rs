//! Real persisted-book coverage for the entry accumulator and its signed checkpoints (fa-l3c).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use fa_cli::json::{self, Json};
use fa_cli::verbs::registry;

fn run(book: &Path, args: &[&str]) -> (i32, String, String) {
    let result = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .env_remove("FA_BOOK")
        .output()
        .expect("run fa");
    let code = result.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&result.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
    if args.contains(&"--json") {
        let lines: Vec<_> = stdout.lines().collect();
        assert_eq!(lines.len(), 1, "args={args:?}: {stdout}\n{stderr}");
        registry()
            .expect("verb registry")
            .check_line(lines[0])
            .unwrap_or_else(|error| panic!("args={args:?}: {error}\n{stdout}"));
    }
    (code, stdout, stderr)
}

fn ok(book: &Path, args: &[&str]) -> String {
    let (code, stdout, stderr) = run(book, args);
    assert_eq!(code, 0, "args={args:?}\n{stdout}\n{stderr}");
    stdout
}

fn parsed(text: &str) -> Json {
    json::parse(text.trim()).expect("one JSON object")
}

/// `key` of a robot line's event fields (its `data`, plan Appendix D), or of
/// a nested object (which has no `data`).
fn get<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    value
        .get("data")
        .and_then(|data| data.get(key))
        .or_else(|| value.get(key))
}

fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    get(value, key).and_then(Json::as_str).expect(key)
}

fn integer(value: &Json, key: &str) -> i128 {
    match get(value, key) {
        Some(Json::Int(n)) => *n,
        other => panic!("{key}: expected an integer, got {other:?}"),
    }
}

fn array<'a>(value: &'a Json, key: &str) -> &'a [Json] {
    get(value, key).and_then(Json::as_arr).expect(key)
}

fn fixture() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("fa-notary-cli-{}-{id}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => panic!("create retained fixture {}: {error}", path.display()),
        }
    }
}

fn write(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write fixture");
    path.display().to_string()
}

#[test]
fn checkpoints_and_verification_survive_reopen_and_include_later_postings() {
    let dir = fixture();
    let book = dir.join("book");
    ok(
        &book,
        &["book", "create", "--name", "Checkpoint Co", "--json"],
    );

    let initial = parsed(&ok(&book, &["verify", "accumulator", "--json"]));
    assert_eq!(text(&initial, "status"), "no_checkpoints");
    assert_eq!(integer(&initial, "states_checked"), 0);
    assert_eq!(get(&initial, "verified_through"), Some(&Json::Null));
    assert!(array(&initial, "states").is_empty());

    let first = parsed(&ok(
        &book,
        &["checkpoint", "create", "--grant", "witness", "--json"],
    ));
    assert_eq!(text(&first, "event"), "checkpoint_created");
    assert_eq!(text(&first, "signatures"), "ed25519");
    assert_eq!(text(&first, "public_key").len(), 64);
    assert_eq!(text(&first, "checkpoint_oid").len(), 64);
    assert_eq!(text(&first, "scope"), "entry_prefix");
    assert_eq!(integer(&first, "leaf_count"), 0);
    assert_eq!(get(&first, "prev_state_oid"), Some(&Json::Null));
    assert!(integer(&first, "recorded_at") > integer(&first, "through_seq"));
    let once = parsed(&ok(&book, &["verify", "accumulator", "--json"]));
    assert_eq!(text(&once, "status"), "verified");
    assert_eq!(integer(&once, "states_checked"), 1);
    assert_eq!(text(&array(&once, "states")[0], "oid"), text(&first, "oid"));

    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"}]}"#,
    );
    ok(&book, &["chart", "import", &chart, "--json"]);
    ok(
        &book,
        &["period", "create", "--fiscal-year", "2026", "--json"],
    );
    ok(&book, &["period", "open", "FY2026-P03", "--json"]);
    let source = write(
        &dir,
        "receipt.txt",
        "Fixture receipt: 12.34 USD received for services.",
    );
    let document = parsed(&ok(
        &book,
        &[
            "document",
            "add",
            &source,
            "--kind",
            "Receipt",
            "--grade",
            "HumanUpload",
            "--json",
        ],
    ));
    let intent = write(
        &dir,
        "sale.json",
        r#"{"effective_date":"2026-03-10","idempotency_key":"sale","legs":[{"side":"debit","account":"1000","amount":"12.34 USD"},{"side":"credit","account":"4000","amount":"12.34 USD"}]}"#,
    );
    let posted = parsed(&ok(
        &book,
        &[
            "post",
            "--intent",
            &intent,
            "--evidence",
            text(&document, "oid"),
            "--json",
        ],
    ));
    // Verification of the old checkpoint never claims coverage of this later post.
    let before = parsed(&ok(&book, &["verify", "accumulator", "--json"]));
    assert_eq!(
        integer(&before, "verified_through"),
        integer(&first, "through_seq")
    );
    assert!(integer(&before, "verified_through") < integer(&posted, "recorded_at"));

    let second = parsed(&ok(
        &book,
        &["checkpoint", "create", "--grant", "witness", "--json"],
    ));
    assert_eq!(text(&second, "prev_state_oid"), text(&first, "oid"));
    assert_ne!(text(&second, "oid"), text(&first, "oid"));
    assert_ne!(text(&second, "root"), text(&first, "root"));
    // Chart, period-open control, and posting are all the entry leaves.
    // Book/period creation, documents, and accumulator states are not entries.
    assert_eq!(integer(&second, "leaf_count"), 3);
    assert!(integer(&second, "through_seq") >= integer(&posted, "recorded_at"));
    let verified_bytes = ok(&book, &["verify", "accumulator", "--json"]);
    let verified = parsed(&verified_bytes);
    assert_eq!(text(&verified, "status"), "verified");
    assert_eq!(text(&verified, "signatures"), "ed25519");
    assert_eq!(text(&verified, "scope"), "entry_prefix");
    assert_eq!(get(&verified, "broken"), Some(&Json::Null));
    assert_eq!(integer(&verified, "states_checked"), 2);
    assert_eq!(
        integer(&verified, "verified_through"),
        integer(&second, "through_seq")
    );
    let states = array(&verified, "states");
    assert_eq!(states.len(), 2);
    assert_eq!(text(&states[0], "oid"), text(&second, "oid"));
    assert_eq!(text(&states[1], "oid"), text(&first, "oid"));
    assert!(
        states
            .iter()
            .all(|state| state.get("finding") == Some(&Json::Null))
    );
    assert!(array(&verified, "unchained").is_empty());
    assert_eq!(
        ok(&book, &["verify", "accumulator", "--json"]),
        verified_bytes
    );
    let human = ok(&book, &["verify", "accumulator"]);
    assert!(
        human.contains("2 checkpoints") && human.contains("signed checkpoint reproduced"),
        "{human}"
    );
    let human_created = ok(&book, &["checkpoint", "create", "--grant", "witness"]);
    assert!(
        human_created.contains("Signed TransparencyCheckpoint") && human_created.contains("entry"),
        "{human_created}"
    );
    let after_human = parsed(&ok(&book, &["verify", "accumulator", "--json"]));
    assert_eq!(integer(&after_human, "states_checked"), 3);
}

#[test]
fn accumulator_commands_refuse_extra_arguments_and_period_filters_before_opening() {
    let missing_book = fixture().join("not-created");
    for args in [
        vec!["checkpoint", "create", "unexpected", "--json"],
        vec!["verify", "accumulator", "unexpected", "--json"],
        vec!["verify", "accumulator", "--period", "FY2026-P03", "--json"],
        vec!["verify", "accumulator", "--fiscal-year", "2026", "--json"],
    ] {
        let (code, out, err) = run(&missing_book, &args);
        assert_eq!(code, 2, "args={args:?}\n{out}\n{err}");
        let failure = parsed(&out);
        assert_eq!(text(&failure, "event"), "error");
        assert_eq!(text(&failure, "class"), "usage");
        assert!(!text(&failure, "fix").is_empty());
    }
    assert!(
        !missing_book.exists(),
        "refused arguments must not create a book"
    );
    for args in [
        vec!["checkpoint", "create", "--json"],
        vec!["checkpoint", "create", "--grant", "read", "--json"],
    ] {
        let (code, out, err) = run(&missing_book, &args);
        assert_eq!(code, 7, "args={args:?}\n{out}\n{err}");
        let refusal = parsed(&out);
        assert_eq!(text(&refusal, "event"), "error");
        assert_eq!(text(&refusal, "class"), "safety");
        assert_eq!(text(&refusal, "refusal_id"), "FA-REF-011");
        assert!(text(&refusal, "message").contains("witness"));
    }
    assert!(
        !missing_book.exists(),
        "authorization must precede opening a book"
    );
}

#[test]
fn a_tampered_persisted_state_fails_verification_and_blocks_a_new_checkpoint() {
    assert_corruption_refused(false);
}

#[test]
fn a_malformed_chain_head_is_reported_and_blocks_a_new_checkpoint() {
    assert_corruption_refused(true);
}

fn assert_corruption_refused(corrupt_head: bool) {
    use asupersync::Budget;
    use asupersync::runtime::RuntimeBuilder;
    use fa::book::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_journal::rows::book_root;
    use fa_model::Id128;
    use fa_model::symbols::{label, property, relation};
    use fgdb::{Database, DatabaseKeys, WriteBatch};
    use fgdb_types::CanonicalScalar;
    use fgdb_types::context::PurposeContexts;
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    let dir = fixture();
    let book = dir.join("book");
    let book_id = Id128([0x31; 16]);
    let units = fa_money::UnitRegistry::embedded().expect("units");
    let keys = BookKeys::for_development(43);
    let handle = Book::create_dir(
        &book,
        keys.clone(),
        BookSpec {
            book_id,
            name: "Tamper fixture".into(),
            base_unit: units.lookup("USD").expect("USD"),
            calendar: fa_time::FiscalCalendar::monthly("fiscal", 1, 1).expect("calendar"),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        },
        Entropy::deterministic(43),
    )
    .expect("create real persisted book");
    keys.save(&book.join("book.keys"))
        .expect("save fixture keys");
    drop(handle);
    ok(
        &book,
        &["checkpoint", "create", "--grant", "witness", "--json"],
    );
    ok(&book, &["verify", "accumulator", "--json"]);

    // Plant a content-addressed but false state through the real substrate.
    // The object hash is valid; only recomputation from the journal exposes it.
    let runtime = RuntimeBuilder::new().build().expect("runtime");
    let root = runtime.request_cx_with_budget(Budget::INFINITE);
    let ctx = PurposeContexts::narrow_runtime_root(&root);
    let db_keys = DatabaseKeys::new([43; 32], DatabaseSecurityNamespaceId([44; 32]), [45; 32]);
    let store = book.join("store");
    let mut db = runtime
        .block_on(async { Database::open(&ctx.commit(), &store, db_keys).await })
        .expect("reopen fixture through substrate");
    let prior = fa_notary::latest(&db, None)
        .expect("read state")
        .expect("checkpoint exists");
    let mut forged = prior.state;
    forged.prev_state_oid = Some(prior.oid);
    forged.through_seq = db.frontier().expect("frontier");
    forged.root[0] ^= 1;
    let bytes = forged.canonical_bytes().expect("state bytes");
    let oid = fa_notary::state_oid(&bytes);
    let scalar = |bytes| CanonicalScalar::bytes(bytes).expect("bounded fixture scalar");
    let mut props = vec![
        (property::FA_PAYLOAD, scalar(bytes)),
        (property::FA_DIGEST, scalar(oid.0.to_vec())),
        (property::BOOK_ID, scalar(book_id.0.to_vec())),
    ];
    props.sort_by_key(|(key, _)| key.0);
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    if !corrupt_head {
        batch.create_vertex(
            fa_notary::state_vid(&oid),
            vec![label::ACCUMULATOR_STATE],
            props,
        );
    }
    batch.set_vertex_property(
        book_root(),
        property::ACCUMULATOR_HEAD,
        Some(scalar(if corrupt_head {
            vec![0xff]
        } else {
            oid.0.to_vec()
        })),
    );
    runtime
        .block_on(async { db.write(&ctx.commit(), batch).await })
        .expect("plant false state");
    drop(db);
    drop(runtime);

    let (code, failed, diagnostics) = run(&book, &["verify", "accumulator", "--json"]);
    assert_eq!(code, 8, "{failed}\n{diagnostics}");
    let report = parsed(&failed);
    assert_eq!(text(&report, "event"), "error");
    assert_eq!(text(&report, "class"), "verification");
    let detail = get(&report, "detail").expect("failure detail");
    assert_eq!(text(detail, "status"), "failed");
    assert_eq!(detail.get("verified_through"), Some(&Json::Null));
    if corrupt_head {
        assert!(text(detail, "broken").contains("32-byte oid"), "{failed}");
        assert!(
            text(&report, "message").contains("broken chain"),
            "{failed}"
        );
        // The dangling head strands the one real state and the signed
        // checkpoint beside it (fa-l3c slice 3 reports both).
        assert_eq!(array(detail, "unchained").len(), 2, "{failed}");
    } else {
        assert_eq!(detail.get("broken"), Some(&Json::Null));
        assert!(
            array(detail, "states").iter().any(|state| {
                state
                    .get("finding")
                    .and_then(Json::as_str)
                    .is_some_and(|finding| finding.contains("recomputed"))
            }),
            "{failed}"
        );
    }
    let (code, blocked, diagnostics) = run(
        &book,
        &["checkpoint", "create", "--grant", "witness", "--json"],
    );
    assert_eq!(code, 8, "{blocked}\n{diagnostics}");
    assert_eq!(
        text(&parsed(&blocked), "refusal_id"),
        fa_notary::code::ACCUMULATOR_DRIFT
    );
    let (code, unchanged, diagnostics) = run(&book, &["verify", "accumulator", "--json"]);
    assert_eq!(code, 8, "{unchanged}\n{diagnostics}");
    assert_eq!(
        unchanged, failed,
        "a refused checkpoint must not hide the false state"
    );
}
