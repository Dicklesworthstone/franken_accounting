//! The real CLI forwards a bounded migration selection over the daemon's
//! socket. Every member retains its prepared digest and native approvals.

use super::*;
use fa_cli::cli::{Files, Stdin};
use fa_cli::json::{self, Json, obj, s};

fn data(stdout: &str) -> Json {
    assert_eq!(stdout.lines().count(), 1, "{stdout}");
    json::parse(stdout.trim())
        .unwrap()
        .get("data")
        .unwrap()
        .clone()
}

fn reviewed_document(dir: &Path, book: &str, name: &str, contents: &str) -> String {
    let path = write(dir, name, contents);
    let added = ok(&[
        "document",
        "add",
        &path,
        "--kind",
        "Spreadsheet",
        "--mime",
        "text/csv",
        "--grade",
        "AgentUpload",
        "--as",
        "grouped-stage-fixture-uploader",
        "--book",
        book,
        "--json",
    ]);
    let oid = field(&added, "oid").unwrap().to_string();
    assert_eq!(field(&added, "grade"), Some("AgentUpload"));
    // These fixture roles exercise native review, not independent human
    // examination or a change to the original upload's custody grade.
    ok(&[
        "document",
        "attest",
        "review",
        "--document",
        &oid,
        "--as",
        "grouped-stage-fixture-reviewer-a",
        "--grant",
        "approve",
        "--book",
        book,
        "--json",
    ]);
    oid
}

#[test]
fn grouped_staging_forwards_stdin_to_the_held_daemon_and_retries_without_duplication() {
    let dir = tmp("grouped-stage");
    let book = dir.join("book");
    let b = book.display().to_string();
    ok(&[
        "book",
        "create",
        "--name",
        "Daemon migration batch",
        "--base-unit",
        "USD",
        "--opening-date",
        "2026-07-01",
        "--book",
        &b,
        "--json",
    ]);
    let chart = write(
        &dir,
        "chart.json",
        r#"{"accounts":[{"code":"1000","name":"Cash","type":"Asset","unit":"USD"},{"code":"3000","name":"Opening equity","type":"Equity","unit":"USD"}]}"#,
    );
    ok(&["chart", "import", &chart, "--book", &b, "--json"]);
    ok(&[
        "period",
        "create",
        "--fiscal-year",
        "2026",
        "--book",
        &b,
        "--json",
    ]);
    let source = reviewed_document(
        &dir,
        &b,
        "original.csv",
        concat!(
            "Transaction ID,Date,Account,Debit,Credit,Currency,Memo/Description,Created At,Created By\n",
            "first,2025-12-20,Legacy cash,3.00,,USD,First cash,2025-12-21T12:00:00Z,legacy-preparer\n",
            "first,2025-12-20,Legacy equity,,3.00,USD,First equity,2025-12-21T12:00:00Z,legacy-preparer\n",
            "second,2025-12-29,Legacy cash,4.00,,USD,Second cash,2025-12-30T12:00:00Z,legacy-preparer\n",
            "second,2025-12-29,Legacy equity,,4.00,USD,Second equity,2025-12-30T12:00:00Z,legacy-preparer\n",
        ),
    );
    let trial_balance = reviewed_document(
        &dir,
        &b,
        "independent-trial-balance.csv",
        "account,unit,debit,credit\n1000,USD,7.00,\n3000,USD,,7.00\n",
    );
    let opening = obj(vec![
        ("run_key", s("fad-grouped-stage")),
        ("source_system", s("quickbooks-csv")),
        ("mode", s("OpeningOnly")),
        ("trial_balance", s(trial_balance)),
        ("opening_date", s("2026-01-01")),
        (
            "lines",
            Json::Arr(vec![
                obj(vec![
                    ("account", s("1000")),
                    ("unit", s("USD")),
                    ("debit", s("7.00")),
                ]),
                obj(vec![
                    ("account", s("3000")),
                    ("unit", s("USD")),
                    ("credit", s("7.00")),
                ]),
            ]),
        ),
    ]);
    let opening_path = write(&dir, "opening.json", &opening.render());
    let opened = ok(&[
        "migrate",
        "open",
        "--intent",
        &opening_path,
        "--book",
        &b,
        "--json",
    ]);
    let run_vid = field(&opened, "run_vid").unwrap().to_string();
    let import = obj(vec![
        ("run", s(format!("MR:{run_vid}"))),
        ("source", s(format!("D:{source}"))),
        ("format", s("quickbooks-csv")),
        (
            "account_map",
            obj(vec![
                ("Legacy cash", s("1000")),
                ("Legacy equity", s("3000")),
            ]),
        ),
    ]);
    let import_path = write(&dir, "import.json", &import.render());
    let prepared = data(&ok(&[
        "migrate",
        "import",
        "--action",
        "prepare",
        "--intent",
        &import_path,
        "--book",
        &b,
        "--json",
    ]));
    let package = format!(
        "D:{}",
        prepared.get("package_oid").unwrap().as_str().unwrap()
    );
    let chunks = prepared.get("chunks").unwrap().as_arr().unwrap();
    assert_eq!(chunks.len(), 2);
    let mut members = Vec::new();
    // Reverse the indices: native events must prove the requested order and
    // bind each member to its own saved proposal, not the array position.
    for index in [1usize, 0] {
        let digest = chunks[index]
            .get("proposal_digest")
            .unwrap()
            .as_str()
            .unwrap();
        let approvals = [
            "grouped-stage-fixture-reviewer-a",
            "grouped-stage-fixture-reviewer-b",
        ]
        .iter()
        .enumerate()
        .map(|(ordinal, principal)| {
            let approved = ok(&[
                "approve",
                "--proposal",
                digest,
                "--as",
                principal,
                "--book",
                &b,
                "--json",
            ]);
            let vid = field(&approved, "approval_vid").unwrap();
            // Both declared typed references and bare VIDs use the same
            // bounded parser and native approval law.
            s(if ordinal == 0 {
                format!("A:{vid}")
            } else {
                vid.to_string()
            })
        })
        .collect();
        members.push(obj(vec![
            ("index", Json::Int(index as i128)),
            ("approvals", Json::Arr(approvals)),
        ]));
    }
    let batch = obj(vec![("chunks", Json::Arr(members))])
        .render()
        .into_bytes();
    let before_rows = data(&ok(&[
        "tb",
        "--period",
        "FY2026-OPEN",
        "--book",
        &b,
        "--json",
    ]))
    .get("rows")
    .unwrap()
    .clone();
    let mut daemon = start_without_files_root(&book);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let forward = || {
            let argv = [
                "migrate",
                "import",
                "--action",
                "stage",
                "--package",
                &package,
                "--intent",
                "-",
                "--via",
                "fad",
                "--book",
                &b,
                "--json",
            ]
            .map(String::from);
            let (exit, output) = fa_cli::entry::fa_with_env_token(
                &argv,
                None,
                Files {
                    cwd: Some(dir.clone()),
                    stdin: Stdin::Forwarded(batch.clone()),
                },
                true,
            );
            assert_eq!(exit, 0, "{}{}", output.stdout, output.stderr);
            assert_eq!(
                checked(&output.stdout),
                vec!["migration_import_group_staged"]
            );
            let group = data(&output.stdout);
            assert_eq!(group.get("package_oid"), prepared.get("package_oid"));
            assert_eq!(group.get("run_vid"), Some(&s(&run_vid)));
            assert_eq!(group.get("atomic"), Some(&Json::Bool(false)));
            for count in [
                "selected_count",
                "completed_count",
                "recorded_count",
                "chunk_count",
            ] {
                assert_eq!(group.get(count), Some(&Json::Int(2)), "{count}");
            }
            assert_eq!(group.get("run_state"), Some(&s("Open")));
            assert_eq!(group.get("ready_to_finalize"), Some(&Json::Bool(true)));
            let receipts = group.get("chunks").unwrap().as_arr().unwrap().to_vec();
            assert_eq!(receipts.len(), 2);
            receipts
        };
        let staged = forward();
        for (ordinal, index) in [1usize, 0].into_iter().enumerate() {
            let event = &staged[ordinal];
            assert_eq!(event.get("chunk_index"), Some(&Json::Int(index as i128)));
            assert_eq!(event.get("entry_vid"), chunks[index].get("entry_vid"));
            assert_eq!(
                event.get("proposal_digest"),
                chunks[index].get("proposal_digest")
            );
            assert_eq!(event.get("already_recorded"), Some(&Json::Bool(false)));
        }
        let (Some(Json::Int(first)), Some(Json::Int(second))) =
            (staged[0].get("recorded_at"), staged[1].get("recorded_at"))
        else {
            panic!("group receipts must retain each native publication sequence");
        };
        assert!(
            first < second,
            "each selected chunk must publish independently"
        );
        let head = ok(&["book", "info", "--book", &b, "--via", "fad", "--json"]);
        let repeated = forward();
        for (original, retry) in staged.iter().zip(&repeated) {
            for key in ["chunk_index", "entry_vid", "proposal_digest", "recorded_at"] {
                assert_eq!(retry.get(key), original.get(key), "retry {key}");
            }
            assert_eq!(retry.get("already_recorded"), Some(&Json::Bool(true)));
        }
        let after = ok(&["book", "info", "--book", &b, "--via", "fad", "--json"]);
        assert_eq!(field(&after, "known_at"), field(&head, "known_at"));
        let hidden = data(&ok(&[
            "tb",
            "--period",
            "FY2026-OPEN",
            "--book",
            &b,
            "--via",
            "fad",
            "--json",
        ]));
        assert_eq!(
            hidden.get("rows"),
            Some(&before_rows),
            "staging remains invisible"
        );
    }));
    // Cleanup remains outside assertions so protocol failures cannot leave
    // an owned daemon holding the book's writer lease.
    let (stop_code, stopped, stop_error) = fad(&["stop", "--book", &b, "--json"]);
    if stop_code != 0 && daemon.child.try_wait().ok().flatten().is_none() {
        let _ = daemon.child.kill();
    }
    let (exit, rest) = daemon.finish();
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
    assert_eq!(stop_code, 0, "{stopped}{stop_error}");
    assert_eq!(exit, 0, "{rest}");
    assert_eq!(checked(&rest), vec!["fad_stopped"]);
    let reopened = data(&ok(&[
        "migrate",
        "import",
        "--action",
        "show",
        "--package",
        &package,
        "--book",
        &b,
        "--json",
    ]));
    assert_eq!(reopened.get("recorded_count"), Some(&Json::Int(2)));
    assert_eq!(reopened.get("chunk_count"), Some(&Json::Int(2)));
    assert_eq!(reopened.get("ties_out"), Some(&Json::Bool(true)));
    assert_eq!(reopened.get("run_state"), Some(&s("Open")));
    assert_eq!(
        data(&ok(&[
            "tb",
            "--period",
            "FY2026-OPEN",
            "--book",
            &b,
            "--json"
        ]))
        .get("rows"),
        Some(&before_rows),
        "durable reopen keeps staged entries invisible until finalization",
    );
}
