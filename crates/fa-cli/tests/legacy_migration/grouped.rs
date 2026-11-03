//! One authenticated source replay for several independently approved chunks.
//! The group is resumable, not an atomic posting batch; a later refusal must
//! retain both the earlier durable receipts and the native refusal contract.

use super::*;

fn chunk(index: usize, approvals: &[String]) -> Json {
    obj(vec![
        ("index", Json::Int(index as i128)),
        ("approvals", Json::Arr(approvals.iter().map(s).collect())),
    ])
}

fn selection(fixture: &Fixture, name: &str, chunks: Vec<Json>) -> String {
    fixture.file(name, &obj(vec![("chunks", Json::Arr(chunks))]).render())
}

fn approve(fixture: &Fixture, prepared: &Json) -> Vec<[String; 2]> {
    rows(data(prepared), "chunks")
        .iter()
        .map(|chunk| {
            let digest = text(chunk, "proposal_digest");
            [
                fixture.approve(digest, "group-reviewer-one"),
                fixture.approve(digest, "group-reviewer-two"),
            ]
        })
        .collect()
}

fn stage(fixture: &Fixture, package: &str, intent: &str) -> Json {
    let result = ok(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--intent",
            intent,
        ],
    );
    assert_eq!(text(&result, "event"), "migration_import_group_staged");
    assert_eq!(data(&result).get("atomic"), Some(&Json::Bool(false)));
    result
}

#[test]
fn grouped_staging_preserves_approvals_visibility_and_retry_sequences() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let package = text(data(&prepared), "package_oid");
    let expected = rows(data(&prepared), "chunks");
    let approvals = approve(&fixture, &prepared);
    assert_eq!(expected.len(), 2);

    // Selection order is explicit and need not match source order. Every
    // group member keeps its own approval digest and native identity.
    let first = selection(
        &fixture,
        "first-selection.json",
        vec![chunk(1, &approvals[1])],
    );
    let partial = stage(&fixture, package, &first);
    assert_eq!(integer(data(&partial), "selected_count"), 1);
    assert_eq!(integer(data(&partial), "completed_count"), 1);
    assert_eq!(integer(data(&partial), "recorded_count"), 1);
    assert_eq!(
        data(&partial).get("ready_to_finalize"),
        Some(&Json::Bool(false))
    );
    assert_eq!(fixture.cash(None), "0.00 USD");
    let first_receipt = &rows(data(&partial), "chunks")[0];
    assert_eq!(integer(first_receipt, "chunk_index"), 1);
    assert_eq!(
        text(first_receipt, "entry_vid"),
        text(&expected[1], "entry_vid")
    );
    assert_eq!(
        text(first_receipt, "proposal_digest"),
        text(&expected[1], "proposal_digest")
    );

    let prefixed = approvals[0].clone().map(|approval| format!("A:{approval}"));
    let both = selection(
        &fixture,
        "both-selection.json",
        vec![chunk(0, &prefixed), chunk(1, &approvals[1])],
    );
    let complete = stage(&fixture, package, &both);
    assert_eq!(integer(data(&complete), "selected_count"), 2);
    assert_eq!(integer(data(&complete), "completed_count"), 2);
    assert_eq!(integer(data(&complete), "recorded_count"), 2);
    assert_eq!(
        data(&complete).get("ready_to_finalize"),
        Some(&Json::Bool(true))
    );
    let receipts = rows(data(&complete), "chunks");
    assert_eq!(
        receipts[0].get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(receipts[1].get("already_recorded"), Some(&Json::Bool(true)));
    assert_eq!(
        receipts[1].get("recorded_at"),
        first_receipt.get("recorded_at")
    );
    assert_eq!(fixture.cash(None), "0.00 USD");
    for (index, receipt) in receipts.iter().enumerate() {
        assert_eq!(integer(receipt, "chunk_index"), index as i128);
        assert_eq!(
            text(receipt, "entry_vid"),
            text(&expected[index], "entry_vid")
        );
        assert_eq!(
            text(receipt, "proposal_digest"),
            text(&expected[index], "proposal_digest")
        );
    }

    let before_finalize = head(&fixture.book);
    fixture.finalize("grouped-finalize.plan");
    assert_eq!(fixture.cash(None), "125.50 USD");
    assert_eq!(fixture.cash(Some(before_finalize)), "0.00 USD");
    let before_retry = head(&fixture.book);
    let repeated = stage(&fixture, package, &both);
    assert_eq!(text(data(&repeated), "run_state"), "Finalized");
    assert_eq!(
        data(&repeated).get("ready_to_finalize"),
        Some(&Json::Bool(false))
    );
    for (before, after) in receipts.iter().zip(rows(data(&repeated), "chunks")) {
        assert_eq!(after.get("already_recorded"), Some(&Json::Bool(true)));
        assert_eq!(after.get("recorded_at"), before.get("recorded_at"));
        assert_eq!(after.get("entry_vid"), before.get("entry_vid"));
    }
    assert_eq!(head(&fixture.book), before_retry);
}

#[test]
fn grouped_staging_reports_partial_progress_and_resumes_after_native_refusal() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let package = text(data(&prepared), "package_oid");
    let approvals = approve(&fixture, &prepared);
    // These approvals are valid for chunk 0, never for chunk 1. Retain the
    // native single-chunk refusal as the independent exit/code comparator.
    let (expected_exit, expected_refusal) = run(
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
            "--approval",
            &approvals[0][0],
            "--approval",
            &approvals[0][1],
        ],
    );
    assert_ne!(expected_exit, 0);
    let path = selection(
        &fixture,
        "later-refusal.json",
        vec![chunk(0, &approvals[0]), chunk(1, &approvals[0])],
    );
    let (status, events) = run_events(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--intent",
            &path,
        ],
    );
    assert_eq!(status, expected_exit);
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(text(&events[0], "event"), "migration_import_progress");
    let progress = data(&events[0]);
    assert_eq!(progress.get("atomic"), Some(&Json::Bool(false)));
    assert_eq!(integer(progress, "selected_count"), 2);
    assert_eq!(integer(progress, "completed_count"), 1);
    assert_eq!(integer(progress, "failed_chunk_index"), 1);
    assert_eq!(text(progress, "phase"), "posting");
    assert_eq!(
        progress.get("coordinate_refreshed"),
        Some(&Json::Bool(true))
    );
    assert!(text(progress, "resume_hint").contains("same selection"));
    assert_eq!(
        data(&events[1]).get("refusal_id"),
        data(&expected_refusal).get("refusal_id")
    );
    assert_eq!(integer(data(&fixture.show(package)), "recorded_count"), 1);
    assert_eq!(fixture.cash(None), "0.00 USD");
    let receipt = &rows(progress, "chunks")[0];
    assert_eq!(integer(receipt, "chunk_index"), 0);

    let resumed = selection(
        &fixture,
        "resumed-selection.json",
        vec![chunk(0, &approvals[0]), chunk(1, &approvals[1])],
    );
    let result = stage(&fixture, package, &resumed);
    let completed = rows(data(&result), "chunks");
    assert_eq!(
        completed[0].get("already_recorded"),
        Some(&Json::Bool(true))
    );
    assert_eq!(completed[0].get("recorded_at"), receipt.get("recorded_at"));
    assert_eq!(
        completed[1].get("already_recorded"),
        Some(&Json::Bool(false))
    );
    assert_eq!(
        data(&result).get("ready_to_finalize"),
        Some(&Json::Bool(true))
    );
    fixture.finalize("resumed-finalize.plan");
    assert_eq!(fixture.cash(None), "125.50 USD");
}

#[test]
fn grouped_staging_validates_the_whole_selection_before_any_publication() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let package = text(data(&prepared), "package_oid");
    let approvals = approve(&fixture, &prepared);
    let valid = chunk(0, &approvals[0]).render();
    let too_many = obj(vec![("chunks", Json::Arr(vec![chunk(0, &[]); 4097]))]).render();
    let excess_approvals = obj(vec![(
        "chunks",
        Json::Arr(vec![chunk(
            0,
            &vec!["ab".repeat(16); fa_model::limits::MAX_APPROVALS + 1],
        )]),
    )])
    .render();
    let malformed = vec![
        "[]".to_owned(),
        "{}".to_owned(),
        "{\"chunks\":[]}".to_owned(),
        "{\"chunks\":false}".to_owned(),
        format!("{{\"chunks\":[{valid}],\"chunks\":[]}}"),
        format!("{{\"chunks\":[{valid}],\"unregistered\":true}}"),
        format!("{{\"chunks\":[{valid},{valid}]}}"),
        format!("{{\"chunks\":[{valid},{{\"index\":2,\"approvals\":[]}}]}}"),
        format!("{{\"chunks\":[{valid},{{\"index\":1,\"approvals\":[\"bad\"]}}]}}"),
        "{\"chunks\":[{\"index\":0,\"index\":1,\"approvals\":[]}]}".to_owned(),
        "{\"chunks\":[{\"index\":0,\"approvals\":[],\"approvals\":[]}]}".to_owned(),
        "{\"chunks\":[{\"index\":0,\"approvals\":[],\"unregistered\":true}]}".to_owned(),
        "{\"chunks\":[{\"index\":0}]}".to_owned(),
        "{\"chunks\":[{\"index\":-1,\"approvals\":[]}]}".to_owned(),
        "{\"chunks\":[{\"index\":0.5,\"approvals\":[]}]}".to_owned(),
        "{\"chunks\":[{\"index\":\"0\",\"approvals\":[]}]}".to_owned(),
        "{\"chunks\":[{\"index\":0,\"approvals\":[false]}]}".to_owned(),
        too_many,
        excess_approvals,
    ];
    let before = head(&fixture.book);
    for (index, body) in malformed.iter().enumerate() {
        let path = fixture.file(&format!("malformed-selection-{index}.json"), body);
        let (status, events) = run_events(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "stage",
                "--package",
                package,
                "--intent",
                &path,
            ],
        );
        assert_eq!(status, 2, "case {index}: {events:?}");
        assert_eq!(events.len(), 1, "invalid shape is refused before execution");
        assert_eq!(
            head(&fixture.book),
            before,
            "case {index} published a partial selection"
        );
    }
    let path = selection(
        &fixture,
        "valid-selection.json",
        vec![chunk(0, &approvals[0])],
    );
    for conflict in [
        ["--chunk", "0"],
        ["--approval", &approvals[0][0]],
        ["--intent", &path],
    ] {
        let mut args = vec![
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--intent",
            &path,
        ];
        args.extend(conflict);
        let (status, _) = run(&fixture.book, &args);
        assert_eq!(status, 2);
        assert_eq!(head(&fixture.book), before);
    }
    let shown = fixture.show(package);
    assert_eq!(integer(data(&shown), "recorded_count"), 0);
    assert_eq!(fixture.cash(None), "0.00 USD");
}

#[test]
fn grouped_staging_authenticates_unselected_proposals_in_the_complete_source() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let original = text(data(&prepared), "package_oid");
    let approvals = approve(&fixture, &prepared);
    let path = selection(
        &fixture,
        "untampered-selection.json",
        vec![chunk(1, &approvals[1])],
    );
    for private_memo in [false, true] {
        // Only chunk 0 changes. A selection containing the unchanged chunk 1
        // must still reject the dishonest complete package before any post.
        let forged = forged_package(&fixture, original, private_memo);
        let before = head(&fixture.book);
        let (status, events) = run_events(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "stage",
                "--package",
                &forged,
                "--intent",
                &path,
            ],
        );
        assert_eq!(status, 8, "{events:?}");
        assert_eq!(events.len(), 1);
        assert!(events[0].render().contains("source"));
        assert_eq!(head(&fixture.book), before);
    }
    assert_eq!(integer(data(&fixture.show(original)), "recorded_count"), 0);
}

#[test]
fn grouped_staging_reauthorizes_source_and_unselected_period_trial_balances() {
    let fixtures = [
        Fixture::new("quickbooks-csv", QB, "USD", "BankStatement", "2026-07-01"),
        Fixture::period_balances(
            "quickbooks-csv",
            &format!("{QB}{PERIOD_ACTIVITY}"),
            "BankStatement",
        ),
    ];
    for fixture in fixtures {
        let prepare = fixture.file("governed-group-prepare.json", &fixture.intent().render());
        let prepared = ok(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "prepare",
                "--intent",
                &prepare,
                "--grant",
                "privileged",
            ],
        );
        let package = text(data(&prepared), "package_oid");
        let approvals = approve(&fixture, &prepared);
        let path = selection(
            &fixture,
            "governed-group-stage.json",
            vec![chunk(0, &approvals[0])],
        );
        let before = head(&fixture.book);
        let (status, events) = run_events(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "stage",
                "--package",
                package,
                "--intent",
                &path,
            ],
        );
        assert_eq!(status, 3, "{events:?}");
        assert_eq!(events.len(), 1);
        assert_eq!(text(data(&events[0]), "refusal_id"), "FA-REF-142");
        assert!(!events[0].render().contains(LEGACY_CASH));
        assert_eq!(head(&fixture.book), before);
        let admitted = ok(
            &fixture.book,
            &[
                "migrate",
                "import",
                "--action",
                "stage",
                "--package",
                package,
                "--intent",
                &path,
                "--grant",
                "privileged",
            ],
        );
        assert_eq!(text(&admitted, "event"), "migration_import_group_staged");
        assert_eq!(integer(data(&admitted), "recorded_count"), 1);
        assert_eq!(fixture.cash(None), "0.00 USD");
    }
}

#[test]
fn grouped_staging_uses_forwarded_stdin_without_granting_daemon_file_access() {
    let fixture = Fixture::quickbooks();
    let prepared = fixture.prepare();
    let package = text(data(&prepared), "package_oid");
    let approvals = approve(&fixture, &prepared);
    let body = obj(vec![(
        "chunks",
        Json::Arr(vec![chunk(1, &approvals[1]), chunk(0, &approvals[0])]),
    )])
    .render();
    let path = fixture.file("daemon-selection.json", &body);
    let before = head(&fixture.book);
    let mut book = fixture.open();
    let arguments = |path: &str| {
        [
            "migrate",
            "import",
            "--action",
            "stage",
            "--package",
            package,
            "--intent",
            path,
            "--json",
        ]
        .map(str::to_owned)
    };
    let (status, captured) = fa_cli::cli::run_for_daemon(
        &arguments(&path),
        &mut book,
        fixture.book.clone(),
        None,
        Some(fixture.dir.clone()),
        Stdin::Missing,
        true,
    );
    assert_eq!(status, 2, "{captured:?}");
    assert!(captured.stdout.contains("--files-root"));
    assert_eq!(i128::from(book.head().unwrap().0), before);
    let (status, captured) = fa_cli::cli::run_for_daemon(
        &arguments("-"),
        &mut book,
        fixture.book.clone(),
        None,
        Some(fixture.dir.clone()),
        Stdin::Forwarded(body.into_bytes()),
        true,
    );
    assert_eq!(status, 0, "{captured:?}");
    let events = captured.stdout.lines().collect::<Vec<_>>();
    assert_eq!(events.len(), 1, "{captured:?}");
    fa_cli::verbs::registry()
        .unwrap()
        .check_line(events[0])
        .unwrap();
    let staged = json::parse(events[0]).unwrap();
    assert_eq!(text(&staged, "event"), "migration_import_group_staged");
    assert_eq!(
        data(&staged).get("ready_to_finalize"),
        Some(&Json::Bool(true))
    );
    assert_eq!(integer(&rows(data(&staged), "chunks")[0], "chunk_index"), 1);
    assert_eq!(integer(&rows(data(&staged), "chunks")[1], "chunk_index"), 0);
    drop(book);
    assert_eq!(fixture.cash(None), "0.00 USD");
}

#[test]
fn full_detail_declared_dmy_dates_bind_native_periods_and_replay_certified_activity() {
    let (mut fixture, mut body) = Fixture::full_detail(true, "Spreadsheet");
    // Preserve the fixture's four independently balanced journals, moving its
    // revenue from December into May. Only effective-date CSV cells change:
    // the original ISO recorded-at timestamps remain provenance.
    let source = full_detail_source(true)
        .replace(",2025-01-01,", ",01/01/2025,")
        .replace(",2025-12-15,", ",04/05/2025,")
        .replace(",2025-12-31,", ",31/12/2025,");
    fixture.source = fixture.document("dmy-history-source.csv", &source, "Spreadsheet");
    fixture.format = "csv".into();
    set_field(&mut body, "source_system", s("legacy-csv"));
    let mut periods = rows(&body, "periods").to_vec();
    for period in &mut periods {
        let code = text(period, "period").to_owned();
        if ("FY2025-P05"..="FY2025-P11").contains(&code.as_str()) {
            let lines = [("1000", "120.00"), ("3000", "-100.00"), ("4000", "-20.00")];
            let document = fixture.document(
                &format!("dmy-{code}-independent-tb.csv"),
                &tb_document(&code, &lines),
                "Spreadsheet",
            );
            set_field(period, "trial_balance", s(document));
            set_field(period, "lines", tb_lines(&lines));
        }
    }
    set_field(&mut body, "periods", Json::Arr(periods));
    fixture.run_vid = full_detail_variant(&fixture, body, "native-dmy-history");
    let columns = concat!(
        "[columns]\n",
        "entry_id_column = \"Transaction ID\"\n",
        "effective_date_column = \"Date\"\n",
        "account_column = \"Account\"\n",
        "debit_column = \"Debit\"\n",
        "credit_column = \"Credit\"\n",
        "unit_column = \"Currency\"\n",
        "memo_column = \"Memo/Description\"\n",
        "recorded_at_column = \"Created At\"\n",
        "entered_by_column = \"Created By\"\n",
        "[parsing]\n",
        "date_order = \"DMY\"\n",
    );
    let mut intent = fixture.intent();
    set_field(&mut intent, "column_map", s(columns));
    let mut wrong = intent.clone();
    let mut wrong_routes = fixture.entry_periods.clone().unwrap();
    set_field(
        &mut wrong_routes,
        "private-history-revenue",
        s("FY2025-P04"),
    );
    set_field(&mut wrong, "entry_periods", wrong_routes);
    let wrong_path = fixture.file("wrong-dmy-period.json", &wrong.render());
    let before = head(&fixture.book);
    let (status, refused) = run(
        &fixture.book,
        &[
            "migrate",
            "import",
            "--action",
            "prepare",
            "--intent",
            &wrong_path,
        ],
    );
    assert_eq!(status, 2, "{}", refused.render());
    assert!(refused.render().contains("outside its source date"));
    assert_eq!(
        head(&fixture.book),
        before,
        "April must not admit a May 4 source row"
    );

    let path = fixture.file("correct-dmy-history.json", &intent.render());
    let prepared = ok(
        &fixture.book,
        &[
            "migrate", "import", "--action", "prepare", "--intent", &path,
        ],
    );
    assert_eq!(text(data(&prepared), "mode"), "FullDetail");
    let package = text(data(&prepared), "package_oid");
    let expected = rows(data(&prepared), "chunks");
    let may = expected
        .iter()
        .find(|chunk| text(chunk, "effective_period") == "FY2025-P05")
        .expect("the source date routes to May without a supplied normal-period override");
    assert_eq!(text(may, "effective_date"), "2025-05-04");
    assert_eq!(text(may, "document_date"), "2025-05-04");
    assert!(
        expected
            .iter()
            .all(|chunk| text(chunk, "effective_period") != "FY2025-P04")
    );
    let approvals = approve(&fixture, &prepared);
    let request = selection(
        &fixture,
        "dmy-history-selection.json",
        approvals
            .iter()
            .enumerate()
            .map(|(index, approvals)| chunk(index, approvals))
            .collect(),
    );
    let staged = stage(&fixture, package, &request);
    assert_eq!(
        data(&staged).get("ready_to_finalize"),
        Some(&Json::Bool(true))
    );
    assert_eq!(fixture.cash_at("FY2025-P05", None), "0.00 USD");
    {
        let book = fixture.open();
        let vid = VId(u128::from_str_radix(text(may, "entry_vid"), 16).unwrap());
        let (entry, _) = book.read_entry(vid).unwrap().unwrap();
        assert_eq!(entry.proposal.effective_date.render(), "2025-05-04");
        assert_eq!(
            entry.proposal.effective_period.as_ref().unwrap().code,
            "FY2025-P05"
        );
        let fa_model::EntryOrigin::Migration {
            source_recorded_at_ns,
            ..
        } = entry.proposal.origin
        else {
            panic!("native migration provenance");
        };
        assert_eq!(source_recorded_at_ns, Some(1_765_886_400_000_000_000));
    }
    let before_finalize = head(&fixture.book);
    fixture.finalize("dmy-history-finalize.plan");
    assert_eq!(fixture.cash_at("FY2025-P04", None), "100.00 USD");
    assert_eq!(fixture.cash_at("FY2025-P05", None), "120.00 USD");
    assert_eq!(fixture.cash_activity("FY2025-P04"), "0.00 USD");
    assert_eq!(fixture.cash_activity("FY2025-P05"), "20.00 USD");
    assert_eq!(
        fixture.cash_at("FY2025-P05", Some(before_finalize)),
        "0.00 USD"
    );

    let (status, certified) = run_events(
        &fixture.book,
        &["tb", "--period", "FY2025-P05", "--activity", "--certify"],
    );
    assert_eq!(status, 0, "{certified:?}");
    let report = certified
        .iter()
        .find(|event| text(event, "event") == "trial_balance")
        .unwrap();
    let cash = rows(data(report), "rows")
        .iter()
        .find(|row| text(row, "code") == "1000")
        .unwrap();
    assert_eq!(text(cash, "net"), "20.00 USD");
    let certificate = certified
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .unwrap();
    let locator = format!("C:{}", text(data(certificate), "oid"));
    let (status, replayed) = run_events(&fixture.book, &["replay", &locator]);
    assert_eq!(status, 0, "{replayed:?}");
    let replay = replayed
        .iter()
        .find(|event| text(event, "event") == "trial_balance")
        .unwrap();
    assert_eq!(
        data(replay),
        data(report),
        "certified May activity replays unchanged"
    );
}
