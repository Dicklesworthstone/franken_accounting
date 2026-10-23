//! Certify, retain and replay equity across real binary processes and book reopen.

use super::*;

fn many(book: &Path, args: &[&str]) -> (i32, Vec<Json>) {
    let result = Command::new(env!("CARGO_BIN_EXE_fa"))
        .arg("--book")
        .arg(book)
        .args(args)
        .arg("--json")
        .env_remove("FA_BOOK")
        .stdin(Stdio::null())
        .output()
        .expect("run fa");
    let stdout = String::from_utf8(result.stdout).expect("UTF-8 stdout");
    let registry = fa_cli::verbs::registry().unwrap();
    assert!(
        !stdout.is_empty(),
        "args={args:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let events = stdout
        .lines()
        .map(|line| {
            registry
                .check_line(line)
                .unwrap_or_else(|e| panic!("{e}: {line}"));
            json::parse(line).unwrap()
        })
        .collect();
    (result.status.code().unwrap_or(-1), events)
}

#[test]
fn equity_certification_reopens_replays_and_tracks_backdated_changes() {
    let f = Fixture::with_chart(
        true,
        r#"{"accounts":[
        {"code":"1000","name":"Cash","type":"Asset","unit":"USD"},
        {"code":"3000","name":"Retained earnings","type":"Equity","unit":"USD"},
        {"code":"3100","name":"Common stock","type":"Equity","unit":"USD"},
        {"code":"3200","name":"Dividends","type":"Equity","unit":"USD"},
        {"code":"4000","name":"Revenue","type":"Revenue","unit":"USD"},
        {"code":"6000","name":"Expense","type":"Expense","unit":"USD"}
    ]}"#,
    );
    f.post("equity-issued", "1000", "3100", "500.00");
    f.post("equity-sale", "1000", "4000", "100.00");
    f.post("equity-dividend", "3200", "1000", "30.00");
    let at = head(&f.book);
    let path = f.dir.join("equity.cert");
    let args = [
        "statement",
        "equity-roll-forward",
        "--from",
        "2026-01-01",
        "--to",
        "2026-12-31",
        "--issuance",
        "3100",
        "--distribution",
        "3200",
        "--label",
        "Annual equity",
        "--certify",
        "--certificate-out",
        path.to_str().unwrap(),
    ];
    let (code, produced) = many(&f.book, &args);
    assert_eq!(code, 0, "{produced:?}");
    assert_eq!(produced.len(), 2);
    assert_eq!(text(&produced[0], "event"), "equity_roll_forward");
    assert_eq!(text(&produced[1], "event"), "report_certificate");
    let bytes = std::fs::read(&path).unwrap();
    let artifact = fa::ReportArtifact::decode(&bytes).unwrap();
    assert_eq!(
        artifact.family(),
        fa::ReportArtifactFamily::EquityRollForward
    );
    assert_eq!(
        text(&produced[1], "output_format"),
        fa::EQUITY_REPORT_FORMAT
    );
    assert!(text(&produced[1], "replay_command").contains("--expect"));
    let oid = format!("C:{}", text(&produced[1], "oid"));
    let expected = format!(
        r#"{{"kind":"equity-roll-forward","units":["USD"],"label":"Annual equity","from":"2026-01-01","through":"2026-12-31","known_at":{at},"issuance_accounts":["3100"],"distribution_accounts":["3200"]}}"#
    );
    let retained_at = head(&f.book);
    let current = ok(
        &f.book,
        &["certificate", "status", &oid, "--expect", &expected],
    );
    assert_eq!(text(&current, "status"), "Current");
    let output = f.dir.join("equity.replayed");
    let (code, replayed) = many(
        &f.book,
        &[
            "replay",
            &oid,
            "--expect",
            &expected,
            "--output",
            output.to_str().unwrap(),
        ],
    );
    assert_eq!(code, 0, "{replayed:?}");
    assert_eq!(get(&replayed[0], "data"), get(&produced[0], "data"));
    assert_eq!(std::fs::read(output).unwrap(), artifact.output());
    assert_eq!(
        head(&f.book),
        retained_at,
        "replay/status write no metadata"
    );
    let (code, refused) = many(&f.book, &["replay", &oid]);
    assert_eq!(code, 8, "{refused:?}");
    for wrong in [
        expected.replace(
            "\"issuance_accounts\":[\"3100\"]",
            "\"issuance_accounts\":[]",
        ),
        expected.replace("2026-12-31", "2026-12-30"),
        expected.replace("Annual equity", "Another statement"),
    ] {
        let (code, refused) = many(&f.book, &["replay", &oid, "--expect", &wrong]);
        assert_eq!(code, 8, "{refused:?}");
        let (code, refused) = many(
            &f.book,
            &["certificate", "status", &oid, "--expect", &wrong],
        );
        assert_eq!(code, 8, "{refused:?}");
    }
    let (code, refused) = many(&f.book, &args);
    assert_eq!(
        code, 2,
        "an existing certificate is not replaced: {refused:?}"
    );
    assert_eq!(head(&f.book), retained_at);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    f.post("equity-late-expense", "6000", "1000", "20.00");
    let status = ok(
        &f.book,
        &["certificate", "status", &oid, "--expect", &expected],
    );
    assert_eq!(text(&status, "status"), "SupersededBy");
    assert_eq!(get(&status, "later_entries").as_arr().unwrap().len(), 1);
    f.close_now("equity-certificate-close");
    let (code, replayed) = many(&f.book, &["replay", &oid, "--expect", &expected]);
    assert_eq!(code, 0, "{replayed:?}");
    assert_eq!(
        get(&replayed[0], "data"),
        get(&produced[0], "data"),
        "closing does not rewrite a retained statement"
    );
}
