//! The real CLI reaches the authenticated detector, native v4 retention and
//! immutable findings through its existing generic procedure surfaces.

use super::*;

pub(super) fn matched_two_bank_cycle() -> Fixture {
    let f = Fixture::with_chart(
        r#"{"accounts":[{"code":"1000","name":"First bank","type":"Asset","unit":"USD"},{"code":"1010","name":"Second bank","type":"Asset","unit":"USD"}]}"#,
    );
    for account in ["1000", "1010"] {
        ok(&f.book, &["chart", "role", account, "cash"]);
    }
    for (source, destination) in [("1000", "1010"), ("1010", "1000")] {
        let path = f.file(
            &format!("transfer-{source}.json"),
            &format!(r#"{{"effective_date":"2026-03-05","idempotency_key":"transfer-{source}","legs":[{{"side":"credit","account":"{source}","amount":"100.00 USD"}},{{"side":"debit","account":"{destination}","amount":"100.00 USD"}}]}}"#),
        );
        ok(
            &f.book,
            &["post", "--intent", &path, "--evidence", &f.evidence],
        );
    }
    for account in ["1000", "1010"] {
        let statement = format!(
            "{CSV_HEADER}1,INSTRUMENT-{account},USD,2026-03-15,0.00,0.00,2026-03-05,2026-03-05,CRDT,100.00,Private bank customer,\n1,INSTRUMENT-{account},USD,2026-03-15,0.00,0.00,2026-03-05,2026-03-10,DBIT,100.00,Private bank customer,\n"
        );
        let path = f.file(&format!("statement-{account}.csv"), &statement);
        let imported = ok(
            &f.book,
            &[
                "bank",
                "import",
                &path,
                "--bank-format",
                "csv",
                "--account",
                account,
            ],
        );
        let manifest = text(data(&imported), "manifest_oid");
        let matched = ok_privileged(&f.book, &["bank", "match", "--import", manifest]);
        assert_eq!(rows(data(&matched), "proposals").len(), 2);
        for ordinal in 0..2 {
            confirm_selection(
                &f.book,
                &confirmation_args(&matched, ordinal, "bank-reviewer"),
            );
        }
    }

    f
}

#[test]
fn graph_kiting_runs_and_records_a_source_backed_two_bank_cycle() {
    let f = matched_two_bank_cycle();
    let before = head(&f.book);
    let report = ok_privileged(
        &f.book,
        &["procedure", "run", "graph.kiting@1", "--grant", "reconcile"],
    );
    assert_eq!(text(&report, "event"), "procedure_run");
    assert_eq!(rows(data(&report), "findings").len(), 1);
    assert!(!report.render().contains("Private bank customer"));
    assert_eq!(head(&f.book), before);

    let recorded = ok_privileged(
        &f.book,
        &["finding", "record", "graph.kiting", "--grant", "reconcile"],
    );
    assert_eq!(integer(data(&recorded), "finding_count"), 1);
    let certificate = text(data(&recorded), "certificate");
    let listed = ok_privileged(
        &f.book,
        &[
            "finding",
            "list",
            "--certificate",
            certificate,
            "--grant",
            "reconcile",
        ],
    );
    assert_eq!(rows(data(&listed), "findings").len(), 1);
    let recorded_head = head(&f.book);
    for grant in ["reconcile", "privileged"] {
        let (exit, refused) = run(&f.book, &["replay", certificate, "--grant", grant]);
        assert_eq!(exit, 7, "{refused:?}");
        let refusal = data(&refused).get("refusal").unwrap();
        assert_eq!(text(refusal, "code"), "FA-REF-011");
        assert!(!refused.render().contains("Private bank customer"));
    }
    let replayed = ok_privileged(&f.book, &["replay", certificate, "--grant", "reconcile"]);
    assert_eq!(
        data(&replayed).get("findings"),
        data(&report).get("findings")
    );
    let status = ok_privileged(
        &f.book,
        &["certificate", "status", certificate, "--grant", "reconcile"],
    );
    assert_eq!(text(data(&status), "status"), "Current");
    assert_eq!(head(&f.book), recorded_head);

    let path = f.dir.join("kiting.cert");
    let path = path.to_str().unwrap();
    let events = certified_events(
        &f.book,
        &[
            "procedure",
            "run",
            "graph.kiting@1",
            "--certificate-out",
            path,
            "--grant",
            "reconcile",
            "--grant",
            "privileged",
        ],
    );
    let saved = events
        .iter()
        .find(|event| text(event, "event") == "report_certificate")
        .unwrap();
    let bytes = std::fs::read(path).unwrap();
    let file = fa::ProcedureCertificate::decode(&bytes).unwrap();
    assert_eq!(
        text(data(saved), "oid"),
        fa_verify::blake3::hex(file.digest())
    );
    let file_replay = ok_privileged(&f.book, &["replay", path, "--grant", "reconcile"]);
    assert_eq!(
        data(&file_replay).get("findings"),
        data(&report).get("findings")
    );
}
