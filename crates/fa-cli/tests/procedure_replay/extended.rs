//! Extended native input certificates cross the actual operator process boundary.
use super::*;
use fa::ReportArtifactExpectation;
use fa_model::{Oid, PartyKind, PartySpec};
use fa_registers::EntityCellKey;

#[test]
fn extended_analytics_replay_from_retained_handles_files_and_stdin_after_new_evidence() {
    let dir = temp();
    let path = dir.join("book");
    ok(
        &path,
        &["book", "create", "--name", "Extended analytic replay"],
    );
    let chart = dir.join("chart.json");
    std::fs::write(&chart, r#"{"accounts":[{"code":"1000","name":"Cash A","type":"Asset","unit":"USD"},{"code":"1010","name":"Cash B","type":"Asset","unit":"USD"},{"code":"1020","name":"Cash C","type":"Asset","unit":"USD"},{"code":"3000","name":"Capital","type":"Equity","unit":"USD"},{"code":"6000","name":"Expense","type":"Expense","unit":"USD"}]}"#).unwrap();
    ok(&path, &["chart", "import", chart.to_str().unwrap()]);
    ok(&path, &["period", "create", "--fiscal-year", "2026"]);
    ok(&path, &["period", "open", "FY2026-P01"]);
    let doc = dir.join("statement.txt");
    std::fs::write(
        &doc,
        "Independent statement used for a real balance attestation",
    )
    .unwrap();
    let evidence = ok(
        &path,
        &[
            "document",
            "add",
            doc.to_str().unwrap(),
            "--kind",
            "Invoice",
            "--grade",
            "HumanUpload",
        ],
    );
    let evidence = text(data(&evidence[0]), "oid");
    let source = post(
        &path,
        &dir,
        evidence,
        "source",
        1,
        "3000",
        "1000",
        "100.00 USD",
    );
    let keys = BookKeys::load(&path.join("book.keys")).unwrap();
    let head = || {
        Book::open_dir(&path, keys.clone(), Entropy::production())
            .unwrap()
            .head()
            .unwrap()
    };
    let (certificates, original_at) = {
        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(UnixVfs::new);
        let mut book = runtime
            .block_on(AsyncBook::open_with_vfs(
                &cx,
                vfs,
                &path,
                keys.clone(),
                Entropy::production(),
            ))
            .unwrap();
        let principal = VId(73);
        let capability = Capability::embedded(principal, &["read", "produce"]).unwrap();
        for (code, identifier) in [("VENDOR-A", "AB-123"), ("VENDOR-B", "ab 123")] {
            let spec = PartySpec {
                code: code.into(),
                kind: PartyKind::Vendor,
                name: book.seal_text(&cx, code).unwrap(),
                identifiers: vec![(
                    "bank_account".into(),
                    book.seal_text(&cx, identifier).unwrap(),
                )],
                external_ids: Vec::new(),
            };
            runtime
                .block_on(book.create_party(
                    &cx,
                    &spec,
                    principal,
                    DateDay::from_ymd(2026, 1, 1).unwrap(),
                    code.as_bytes(),
                    &Capability::embedded(principal, &["schema_change"]).unwrap(),
                ))
                .unwrap()
                .unwrap();
        }
        let account = account_vid(book.context().book_id, "1000");
        let claim = book
            .evaluate_register_equals(
                &cx,
                &EntityCellKey {
                    account,
                    unit_id: book.context().units.lookup("USD").unwrap().0,
                    period: "FY2026-P01".into(),
                    entity: None,
                },
                None,
            )
            .unwrap();
        let mut oid = [0; 32];
        for (out, pair) in oid.iter_mut().zip(evidence.as_bytes().as_chunks::<2>().0) {
            *out = u8::from_str_radix(std::str::from_utf8(pair.as_slice()).unwrap(), 16).unwrap();
        }
        runtime
            .block_on(book.record_register_equals(
                &cx,
                &Capability::embedded(principal, &["reconcile"]).unwrap(),
                &claim,
                vec![Oid(oid)],
            ))
            .unwrap()
            .unwrap();
        let at = book.head(&cx).unwrap();
        let mut certificates = Vec::new();
        for id in [
            "graph.identity_resolution",
            "recon.book_to_book",
            "confirm.coverage",
            "trace.restitution_order",
            "trace.network_fifo",
        ] {
            let row = fa_lantern::bind(id).unwrap();
            let mut request = ProcedureRequest::new(
                id,
                Inputs {
                    account: row
                        .inputs
                        .iter()
                        .any(|i| i.name == "account")
                        .then_some(account),
                    source: row
                        .inputs
                        .iter()
                        .any(|i| i.name == "source")
                        .then_some(source),
                },
            )
            .unwrap();
            request.known_at = Some(at);
            request.effective_through = Some(DateDay::from_ymd(2026, 1, 31).unwrap());
            let certificate = book
                .certify_procedure(&cx, principal, &capability, &request)
                .unwrap()
                .unwrap()
                .certificate;
            let legacy = id == "trace.network_fifo";
            assert_eq!(certificate.supplemental_inputs().is_empty(), legacy);
            let bytes = certificate.canonical_bytes().unwrap();
            let retained = runtime
                .block_on(book.retain_report_artifact(
                    &cx,
                    principal,
                    &capability,
                    &bytes,
                    Some(certificate.digest()),
                ))
                .unwrap()
                .unwrap();
            let kept_at = book.head(&cx).unwrap();
            let retry = runtime
                .block_on(book.retain_report_artifact(
                    &cx,
                    principal,
                    &capability,
                    &bytes,
                    Some(certificate.digest()),
                ))
                .unwrap()
                .unwrap();
            assert_eq!(retry, retained);
            assert_eq!(book.head(&cx).unwrap(), kept_at);
            let actual = runtime
                .block_on(book.replay_retained_report_artifact(
                    &cx,
                    principal,
                    &capability,
                    certificate.digest(),
                    ReportArtifactExpectation::AsSupplied,
                ))
                .unwrap()
                .unwrap();
            assert_eq!(actual.output, certificate.output());
            certificates.push(certificate);
        }
        (certificates, at)
    };
    post(
        &path,
        &dir,
        evidence,
        "later",
        1,
        "3000",
        "1000",
        "70.00 USD",
    );
    let after = head();
    assert!(after > original_at);
    for (index, certificate) in certificates.iter().enumerate() {
        let bytes = certificate.canonical_bytes().unwrap();
        let handle = format!("C:{}", hex(certificate.digest()));
        let file = dir.join(format!("extended-{index}.cert"));
        let encoded = dir.join(format!("extended-{index}.hex"));
        std::fs::write(&file, &bytes).unwrap();
        std::fs::write(&encoded, hex(&bytes)).unwrap();
        let (exit, baseline, events) = call(&path, &["replay", &handle], None);
        assert_eq!(exit, 0, "{baseline}");
        assert_eq!(events.len(), 1);
        assert_eq!(text(&events[0], "event"), "procedure_run");
        assert_eq!(text(&events[0], "certificate"), hex(certificate.digest()));
        assert_eq!(
            text(data(&events[0]), "procedure"),
            certificate.report().procedure
        );
        assert_eq!(
            text(data(&events[0]), "findings_digest"),
            hex(&certificate.report().findings_digest)
        );
        assert_eq!(
            number(data(&events[0]), "known_at"),
            i128::from(original_at.0)
        );
        for (arg, input) in [
            (file.to_str().unwrap(), None),
            (encoded.to_str().unwrap(), None),
            ("-", Some(bytes.as_slice())),
            ("-", Some(handle.as_bytes())),
        ] {
            let (exit, actual, _) = call(&path, &["replay", arg], input);
            assert_eq!(exit, 0, "{actual}");
            assert_eq!(
                actual, baseline,
                "transport must not change the original report"
            );
        }
        let output = dir.join(format!("canonical-{index}.output"));
        let (exit, stdout, events) = call(
            &path,
            &["replay", &handle, "--output", output.to_str().unwrap()],
            None,
        );
        assert_eq!(exit, 0, "{stdout}");
        assert_eq!(events.len(), 2);
        assert_eq!(text(&events[1], "event"), "report_replayed");
        assert_eq!(std::fs::read(&output).unwrap(), certificate.output());
        let (exit, _, errors) = call(
            &path,
            &["replay", &handle, "--output", output.to_str().unwrap()],
            None,
        );
        assert_ne!(exit, 0);
        assert_eq!(
            errors.len(),
            1,
            "an existing output file prevents any success event"
        );
        assert_eq!(text(&errors[0], "event"), "error");
        assert_eq!(std::fs::read(&output).unwrap(), certificate.output());
        let mut damaged = bytes.clone();
        *damaged.last_mut().unwrap() ^= 1;
        for bad in [&damaged[..], &bytes[..bytes.len() / 2]] {
            let (exit, stdout, events) = call(&path, &["replay", "-"], Some(bad));
            assert_eq!(exit, 8, "{stdout}");
            assert_eq!(events.len(), 1);
            assert_eq!(text(&events[0], "event"), "error");
        }
        assert_eq!(
            head(),
            after,
            "replay, retries and refusals create no accounting or metadata writes"
        );
    }
    // recon.book_to_book folds every posting regardless of effective date,
    // so a new run refuses a date rather than ignoring it (fa-9pjp); the
    // retained certificate above, which carries one, still replays.
    let (code, stdout, _) = call(
        &path,
        &[
            "procedure",
            "run",
            "recon.book_to_book",
            "--effective-through",
            "2026-01-31",
        ],
        None,
    );
    assert_eq!(code, 2, "{stdout}");
    assert!(
        stdout.contains("does not take --effective-through"),
        "{stdout}"
    );
    let current = ok(&path, &["procedure", "run", "recon.book_to_book"]);
    let findings = data(&current[0])
        .get("findings")
        .and_then(Json::as_arr)
        .unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| number(finding.get("statistic").unwrap(), "value") == 7_000)
    );
    assert!(
        certificates
            .iter()
            .find(|c| c.report().procedure == "recon.book_to_book")
            .unwrap()
            .report()
            .findings
            .is_empty()
    );
}
