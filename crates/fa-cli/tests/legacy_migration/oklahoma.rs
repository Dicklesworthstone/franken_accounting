//! A complete official agency slice through the retained-source migration path.
//!
//! Oklahoma publishes monthly chartfield activity, not original journal entries.
//! The helper preserves the original rows and gives each balanced monthly funding
//! group an explicit reconstruction ID. This isolated book starts from zero:
//! its balances are accumulated Q4 activity, not the agency's opening/closing GL.

use super::*;
use std::collections::BTreeMap;

// Track runtime helper/data inputs in Cargo and the repository's verdict closure.
const _: &str = include_str!("../../../../tools/public-data/oklahoma_gl.py");
const _: &str = include_str!("../../../../tools/public-data/test_oklahoma_gl.py");
const _: &[u8] = include_bytes!("../../../fa-oracles/data/oklahoma/source.csv");
const _: &[u8] = include_bytes!("../../../fa-oracles/data/oklahoma/source_rows.csv");

const RAW: &str = "crates/fa-oracles/data/oklahoma/source.csv";
const HELPER: &str = "tools/public-data/oklahoma_gl.py";
const ACCOUNT_CODES: [&str; 4] = ["101000", "416101", "548110", "548130"];
const CUMULATIVE_NETS: [[&str; 4]; 3] = [
    ["-8237688.62", "-7347513.21", "15666701.83", "-81500.00"],
    ["-1347411.23", "-14695794.78", "16088206.01", "-45000.00"],
    ["5565766.76", "-21898252.44", "16352485.68", "-20000.00"],
];

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn retained_dir() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let dir = std::env::temp_dir().join(format!(
            "fa-oklahoma-activity-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create {}: {error}", dir.display()),
        }
    }
}

#[test]
fn public_ledger_helper_offline_regressions() {
    let output = Command::new("python3")
        .args([
            "-B",
            "-m",
            "unittest",
            "discover",
            "-v",
            "-s",
            "tools/public-data",
        ])
        .current_dir(repository())
        .output()
        .expect("Python 3.11+ is required for the public-source authoring helper");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn public_oklahoma_activity_imports_all_source_legs_and_replays_certified_folds() {
    let dir = retained_dir();
    let prepared_dir = dir.join("prepared");
    let output = Command::new("python3")
        .arg("-B")
        .arg(repository().join(HELPER))
        .arg("prepare")
        .arg("--source")
        .arg(repository().join(RAW))
        .arg("--output")
        .arg(&prepared_dir)
        .output()
        .expect("run the actual source adapter");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let manifest_text = std::fs::read_to_string(prepared_dir.join("manifest.json")).unwrap();
    let manifest = json::parse(&manifest_text).unwrap();
    assert_eq!(integer(&manifest, "selection_rows"), 312);
    assert_eq!(integer(&manifest, "zero_rows_retained"), 6);
    assert_eq!(integer(&manifest, "normalized_legs"), 306);
    assert_eq!(integer(&manifest, "reconstructed_entries"), 104);
    assert_eq!(
        text(&manifest, "source_sha256"),
        "141e2d5524f6aa9d25c7331bc56f623f43da9a1f00cdfee42b7c5f3ccf6fc0fe"
    );
    assert_eq!(
        text(&manifest, "selection_sha256"),
        "146940518122397bf9b66f92fa06b8b7a1cb15e58ae8c0cf0e42584933a1f64c"
    );
    let periods = rows(&manifest, "period_totals");
    assert_eq!(periods.len(), 3);
    for (row, (source_rows, legs, groups, magnitude)) in periods.iter().zip([
        (144, 138, 38, 2_301_421_504_i128),
        (86, 86, 33, 780_628_575),
        (82, 82, 33, 777_711_423),
    ]) {
        assert_eq!(integer(row, "rows"), source_rows);
        assert_eq!(integer(row, "nonzero_rows"), legs);
        assert_eq!(integer(row, "entries"), groups);
        assert_eq!(integer(row, "debit_cents"), magnitude);
        assert_eq!(integer(row, "credit_cents"), magnitude);
    }

    let book = dir.join("activity-book");
    ok(
        &book,
        &[
            "book",
            "create",
            "--name",
            "Oklahoma FY24 Q4 published activity — zero baseline reconstruction",
            "--base-unit",
            "USD",
            "--opening-date",
            "2024-07-01",
        ],
    );
    let mut fixture = Fixture {
        dir,
        book,
        unit: "USD".into(),
        source: String::new(),
        trial_balance: String::new(),
        run_vid: String::new(),
        format: "csv".into(),
        opening_entries: None,
        entry_periods: None,
        period_trial_balances: Vec::new(),
    };
    ok(
        &fixture.book,
        &[
            "chart",
            "import",
            &prepared_dir.join("chart.json").display().to_string(),
        ],
    );
    ok(
        &fixture.book,
        &["period", "create", "--fiscal-year", "2024"],
    );
    // Keep the original source and exact row-index manifest in the same book.
    // These retained documents do not manufacture a third-party attestation.
    let raw = std::fs::read_to_string(prepared_dir.join("source.csv")).unwrap();
    fixture.document("official-activity-source.csv", &raw, "Spreadsheet");
    fixture.document("official-activity-manifest.json", &manifest_text, "Other");
    let source = std::fs::read_to_string(prepared_dir.join("legacy.csv")).unwrap();
    fixture.source = fixture.document("normalized-activity.csv", &source, "Spreadsheet");
    fixture.trial_balance = fixture.document(
        "declared-zero-baseline.csv",
        &tb_document("analysis-only; no published opening balance", &[]),
        "Spreadsheet",
    );
    let mut period_specs = Vec::new();
    for (period, expected) in periods.iter().zip(CUMULATIVE_NETS) {
        let code = text(period, "period");
        let lines: Vec<_> = ACCOUNT_CODES.into_iter().zip(expected).collect();
        let document = fixture.document(
            &format!("independent-python-fold-{code}.csv"),
            &tb_document(code, &lines),
            "Spreadsheet",
        );
        period_specs.push(obj(vec![
            ("period", s(code)),
            ("trial_balance", s(&document)),
            ("lines", tb_lines(&lines)),
        ]));
        fixture.period_trial_balances.push(document);
    }
    // FullDetail is the native staging/activation protocol used here; the
    // retained source and book name explicitly declare aggregate source
    // granularity. No original journal ID/date or opening balance is asserted.
    let run_body = obj(vec![
        ("run_key", s("oklahoma-activity")),
        ("source_system", s("oklahoma-omes-period-activity-v1")),
        ("mode", s("FullDetail")),
        ("trial_balance", s(&fixture.trial_balance)),
        ("opening_date", s("2024-01-01")),
        ("lines", tb_lines(&[])),
        ("periods", Json::Arr(period_specs)),
        ("detail_base", tb_lines(&[])),
        ("sole_opening_source", Json::Bool(true)),
    ]);
    let run_path = fixture.file("activity-run.json", &run_body.render());
    let opened = ok(&fixture.book, &["migrate", "open", "--intent", &run_path]);
    fixture.run_vid = text(data(&opened), "run_vid").into();
    let columns = std::fs::read_to_string(prepared_dir.join("column_map.toml")).unwrap();
    let import_body = |source_oid: &str| {
        obj(vec![
            ("run", s(format!("MR:{}", fixture.run_vid))),
            ("source", s(format!("D:{source_oid}"))),
            ("format", s("csv")),
            ("column_map", s(&columns)),
            (
                "account_map",
                obj(ACCOUNT_CODES
                    .into_iter()
                    .map(|code| (code, s(code)))
                    .collect()),
            ),
        ])
    };
    // Duplicating the balanced source still balances, but must fail the
    // separately declared period controls without publishing an import.
    let header_end = source.find('\n').unwrap() + 1;
    let duplicated = format!("{source}{}", &source[header_end..]);
    let bad_source = fixture.document("duplicated-activity.csv", &duplicated, "Spreadsheet");
    let bad_path = fixture.file("duplicated-import.json", &import_body(&bad_source).render());
    let before_bad = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &bad_path,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert_eq!(
        head(&fixture.book),
        before_bad,
        "a failed tie-out publishes nothing"
    );
    let import_path = fixture.file(
        "activity-import.json",
        &import_body(&fixture.source).render(),
    );
    let prepared = ok(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "prepare",
            "--intent",
            &import_path,
        ],
    );
    let package = text(data(&prepared), "package_oid");
    let chunks = rows(data(&prepared), "chunks");
    assert_eq!(chunks.len(), 104);
    assert_eq!(
        chunks
            .iter()
            .map(|chunk| integer(chunk, "leg_count"))
            .sum::<i128>(),
        306,
        "each nonzero published row remains one leg"
    );
    // Approval, staging and each read reopen the actual persisted book.
    // Retry the first chunk without publishing a second monetary effect.
    for (index, chunk) in chunks.iter().enumerate() {
        let digest = text(chunk, "proposal_digest");
        let first = fixture.approve(digest, "activity-reviewer-one");
        let second = fixture.approve(digest, "activity-reviewer-two");
        let staged = fixture.stage(package, index, &[&first, &second]);
        assert_eq!(text(&staged, "event"), "migration_import_staged");
        assert_eq!(
            integer(data(&staged), "recorded_count"),
            (index + 1) as i128
        );
        if index == 0 {
            let before_retry = head(&fixture.book);
            let retry = fixture.stage(package, index, &[&first, &second]);
            assert_eq!(
                data(&retry).get("already_recorded"),
                Some(&Json::Bool(true))
            );
            assert_eq!(head(&fixture.book), before_retry);
        }
    }
    let before_finalize = head(&fixture.book);
    for period in periods {
        assert!(stock_lines(&fixture.book, text(period, "period")).is_empty());
    }
    assert_eq!(
        data(&fixture.show(package)).get("ties_out"),
        Some(&Json::Bool(true))
    );
    assert_eq!(
        text(data(&fixture.finalize("activity-finalize.plan")), "to"),
        "Finalized"
    );
    for (period, expected) in periods.iter().zip(CUMULATIVE_NETS) {
        let code = text(period, "period");
        let expected: Vec<_> = ACCOUNT_CODES
            .into_iter()
            .zip(expected)
            .map(|(account, value)| (account.to_string(), value.to_string()))
            .collect();
        assert_eq!(stock_lines(&fixture.book, code), expected);
        ok(&fixture.book, &["verify", "registers", "--period", code]);
        let certified = certified_events(&fixture.book, &["tb", "--period", code, "--certify"]);
        let metadata = data(report_event(&certified, "report_certificate"));
        let locator = format!("C:{}", text(metadata, "oid"));
        let before_replay = head(&fixture.book);
        let replayed = certified_events(&fixture.book, &["replay", &locator]);
        assert_eq!(
            data(report_event(&replayed, "trial_balance")),
            data(report_event(&certified, "trial_balance")),
            "reopened replay reproduces the exact retained report"
        );
        assert_eq!(head(&fixture.book), before_replay);

        let historical = ok(
            &fixture.book,
            &[
                "tb",
                "--period",
                code,
                "--as-known-at",
                &before_finalize.to_string(),
            ],
        );
        assert!(
            rows(data(&historical), "rows")
                .iter()
                .all(|row| text(row, "net") == "0.00 USD"),
            "finalization cannot change an earlier known-at coordinate"
        );
    }
    // Compare every monthly account movement to the separate Python source
    // fold, including credits to the expenditure account and negative cash.
    for period in periods {
        let result = ok(
            &fixture.book,
            &["tb", "--period", text(period, "period"), "--activity"],
        );
        let actual: BTreeMap<_, _> = rows(data(&result), "rows")
            .iter()
            .map(|row| {
                (
                    text(row, "code").to_owned(),
                    text(row, "net").strip_suffix(" USD").unwrap().to_owned(),
                )
            })
            .collect();
        for code in ACCOUNT_CODES {
            assert_eq!(
                actual.get(code).map(String::as_str),
                Some(text(period.get("account_nets").unwrap(), code))
            );
        }
    }
}

fn certified_events(book: &Path, args: &[&str]) -> Vec<Json> {
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
    assert!(
        output.status.success(),
        "{args:?}: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<_> = stdout
        .lines()
        .map(|line| {
            fa_cli::verbs::registry().unwrap().check_line(line).unwrap();
            json::parse(line).unwrap()
        })
        .collect();
    assert!(!events.is_empty());
    events
}

fn report_event<'a>(events: &'a [Json], name: &str) -> &'a Json {
    events
        .iter()
        .find(|event| text(event, "event") == name)
        .expect(name)
}
