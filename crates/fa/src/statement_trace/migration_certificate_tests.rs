//! Genuine approved migration publications cross the independent verifier.
//! The signed prefix contains both finalized and abandoned runs; its later
//! records cannot change either a staged historical trace or a saved report.
use super::*;
use fa_journal::{
    Document, PostRequest, Posted, RunBody, RunControlRequest, RunControlled, RunMode,
    TrialBalanceLine,
};
use fa_model::{
    ApprovalRef, EntryClass, EntryOrigin, EntryPayload, EvidenceRef, LegPayload, PeriodRef, Writer,
};
use fa_money::{Amount, Side};
use fa_verify::report::{VerifiedReport, VerifiedStatementEntryEvent, verify_report_expected};

fn source(h: &mut Harness) -> (RunBody, EvidenceRef) {
    let cx = h.cx();
    let document = Document {
        book_id: h.book.context().book_id,
        kind: 18,
        mime: "text/csv".into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: b"account,USD debit balance\ncapital,-70\ncash,70\n".to_vec(),
    };
    h.runtime
        .block_on(h.book.add_document(&cx, &document))
        .unwrap()
        .unwrap();
    let body = RunBody {
        book_id: h.book.context().book_id,
        run_key: "trace-finalized".into(),
        source_system: "legacy-trace".into(),
        mode: RunMode::OpeningOnly,
        trial_balance: document.oid(),
        opening_date: day("2026-01-01"),
        lines: vec![
            TrialBalanceLine {
                account_code: "capital".into(),
                unit: h.usd,
                mantissa: -70,
            },
            TrialBalanceLine {
                account_code: "cash".into(),
                unit: h.usd,
                mantissa: 70,
            },
        ],
        periods: Vec::new(),
        detail_base: Vec::new(),
        sole_opening_source: false,
    };
    (body, document.evidence_ref(1))
}

fn approvals(h: &mut Harness, proposal: &EntryPayload) -> Vec<ApprovalRef> {
    let cx = h.cx();
    let digest = proposal.proposal_digest().unwrap();
    [VId(2), VId(3)]
        .into_iter()
        .map(|principal| {
            h.runtime
                .block_on(h.book.approve(
                    &cx,
                    Capability::embedded(principal, &["approve"]).unwrap(),
                    digest,
                ))
                .unwrap()
                .unwrap()
                .approval()
        })
        .collect()
}

fn open(h: &mut Harness, body: &RunBody, evidence: EvidenceRef) -> RunControlled {
    let cx = h.cx();
    let key = format!("{}-open", body.run_key);
    let proposal = h
        .book
        .open_migration_proposal(
            PRINCIPAL,
            body,
            vec![evidence],
            key.as_bytes(),
            h.book
                .seal_text(&cx, "Open retained legacy balances")
                .unwrap(),
        )
        .unwrap();
    h.runtime
        .block_on(h.book.open_migration_run(
            &cx,
            body,
            RunControlRequest {
                proposal,
                capability: cap(&["post", "migrate"]),
                approvals: Vec::new(),
            },
        ))
        .unwrap()
        .unwrap()
}

fn stage(h: &mut Harness, body: &RunBody, evidence: EvidenceRef) -> Posted {
    let cx = h.cx();
    let key = format!("{}-opening", body.run_key);
    let legs = vec![
        LegPayload::simple(Side::Debit, h.id("cash"), Amount::new(h.usd, 70)),
        LegPayload::simple(Side::Credit, h.id("capital"), Amount::new(h.usd, 70)),
    ];
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id: h.book.context().book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::MIGRATION,
        effective_date: body.opening_date,
        document_date: None,
        description: h.book.seal_text(&cx, "Legacy opening chunk").unwrap(),
        effective_period: Some(PeriodRef {
            calendar: h.book.context().calendar.id.clone(),
            code: "FY2026-OPEN".into(),
        }),
        unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
        legs,
        control: None,
        base_totals: None,
        idempotency_key: key.as_bytes().to_vec(),
        origin: EntryOrigin::Migration {
            run_ref: body.vid(),
            source_system: body.source_system.clone(),
            source_id: h.book.seal_text(&cx, &key).unwrap(),
            source_recorded_at_ns: None,
            source_entered_by: None,
            source_approved_by: None,
            batch_oid: body.trial_balance,
        },
        principal_ref: PRINCIPAL,
        session_ref: None,
        evidence: vec![evidence],
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let approvals = approvals(h, &proposal);
    h.runtime
        .block_on(h.book.post(
            &cx,
            PostRequest {
                proposal,
                capability: cap(&["post", "migrate"]),
                approvals,
                plan_certificate: None,
            },
        ))
        .unwrap()
        .unwrap()
}

fn transition(h: &mut Harness, body: &RunBody, kind: u8) -> RunControlled {
    let cx = h.cx();
    let key = format!("{}-terminal", body.run_key);
    let proposal = h
        .book
        .plan_migration_transition(
            &cx,
            body.vid(),
            kind,
            PRINCIPAL,
            key.as_bytes(),
            h.book
                .seal_text(&cx, "Resolve the retained migration population")
                .unwrap(),
        )
        .unwrap()
        .unwrap();
    let approvals = if kind == fa_journal::migration::kind::FINALIZE {
        approvals(h, &proposal)
    } else {
        Vec::new()
    };
    h.runtime
        .block_on(h.book.transition_migration_run(
            &cx,
            RunControlRequest {
                proposal,
                capability: cap(&["post", "migrate"]),
                approvals,
            },
        ))
        .unwrap()
        .unwrap()
}

fn produce(h: &mut Harness, certificate: &StatementTraceCertificate) -> crate::ProducedBundle {
    let cx = h.cx();
    h.runtime
        .block_on(h.book.checkpoint(&cx, PRINCIPAL, &cap(&["witness"])))
        .unwrap()
        .unwrap();
    h.runtime
        .block_on(h.book.produce_statement_trace_bundle(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            None,
            certificate,
        ))
        .unwrap()
        .unwrap()
        .expect("complete checkpoint covers every retained trace source")
}

fn verify(
    h: &Harness,
    produced: &crate::ProducedBundle,
    certificate: &StatementTraceCertificate,
) -> VerifiedReport {
    let key = h.book.checkpoint_public_key();
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        Some(certificate.digest()),
    )
    .unwrap();
    assert_eq!(verified.certificate_digest, *certificate.digest());
    assert_eq!(verified.output, certificate.output());
    verified
}

#[test]
fn migration_statement_traces_round_trip_all_four_producer_families_and_historical_frontiers() {
    let mut h = Harness::in_book_with_opening_date(Id128([0x74; 16]), Some(day("2026-01-02")));
    let selection = super::custom::activate(&mut h, 1);
    let (body, evidence) = source(&mut h);
    let before = h.head();
    let opened = open(&mut h, &body, evidence);
    let chunk = stage(&mut h, &body, evidence);
    let staged = chunk.recorded_at();
    let mut abandoned = body.clone();
    abandoned.run_key = "trace-abandoned".into();
    open(&mut h, &abandoned, evidence);
    let abandoned_chunk = stage(&mut h, &abandoned, evidence);
    let abandoned_at =
        transition(&mut h, &abandoned, fa_journal::migration::kind::ABANDON).recorded_at;
    let finalized = transition(&mut h, &body, fa_journal::migration::kind::FINALIZE);
    let after = finalized.recorded_at;
    h.post(
        "later-backdate",
        "2026-03-20",
        h.usd,
        ("cash", "sales"),
        500,
        false,
    );

    for family in 0..4 {
        let mut request = h.request(before, "balance-sheet");
        request.comparison.after = Some(after);
        let cx = h.cx();
        let certified = match family {
            0 => certify(&h, &request),
            1 => h
                .runtime
                .block_on(h.book.certify_functional_statement_trace(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read", "produce"]),
                    &request,
                ))
                .unwrap()
                .unwrap(),
            _ => {
                let mut selection = selection.clone();
                selection.functional = family == 3;
                super::custom::direct(
                    &mut h,
                    &crate::CustomStatementTraceRequest {
                        selection,
                        before,
                        after: Some(after),
                        max_publications: (after.0 - before.0) as usize,
                    },
                )
            }
        };
        let produced = produce(&mut h, &certified.certificate);
        let verified = verify(&h, &produced, &certified.certificate);
        assert_eq!(verified.known_at, after.0);
        let trace = verified.statement_trace.unwrap();
        assert_eq!(trace.publications.len() as u64, after.0 - before.0);
        let finalization = trace
            .publications
            .iter()
            .find(|step| step.recorded_at == after.0)
            .unwrap();
        let visible: Vec<_> = finalization
            .entries
            .iter()
            .filter(|entry| entry.event == VerifiedStatementEntryEvent::BecameVisible)
            .collect();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].entry, chunk.entry_ref().vid.0);
        assert_eq!(visible[0].digest, chunk.entry_ref().entry_digest);
        assert_eq!(visible[0].recorded_at, staged.0);
        assert_eq!(visible[0].migration_run, Some(body.vid().0));
        assert_eq!(visible[0].posting_date, Some(body.opening_date.0));
        assert!(
            trace
                .publications
                .iter()
                .flat_map(|step| &step.entries)
                .all(|entry| entry.entry != abandoned_chunk.entry_ref().vid.0
                    || entry.event == VerifiedStatementEntryEvent::Recorded)
        );
        for at in [opened.recorded_at, staged, abandoned_at] {
            let step = trace
                .publications
                .iter()
                .find(|step| step.recorded_at == at.0)
                .unwrap();
            assert!(step.changes.is_empty());
            assert!(
                step.entries
                    .iter()
                    .all(|entry| entry.event == VerifiedStatementEntryEvent::Recorded)
            );
        }
        if family < 2 {
            assert_eq!(
                finalization
                    .changes
                    .iter()
                    .find(|line| line.code == "assets" && line.unit == h.usd.0)
                    .unwrap()
                    .delta,
                [70, 0]
            );
        } else {
            assert!(
                trace
                    .publications
                    .iter()
                    .all(|step| step.changes.is_empty())
            );
        }
        assert_eq!(replay(&h, &certified.certificate), certified.report);
    }

    // A current checkpoint must not activate a migration in a source that
    // explicitly ends while its chunks were still staged.
    for end in [opened.recorded_at, staged, abandoned_at] {
        let mut request = h.request(before, "balance-sheet");
        request.comparison.after = Some(end);
        let certified = certify(&h, &request);
        let produced = produce(&mut h, &certified.certificate);
        let trace = verify(&h, &produced, &certified.certificate)
            .statement_trace
            .unwrap();
        assert!(
            trace
                .publications
                .iter()
                .all(|step| step.changes.is_empty())
        );
        assert!(
            trace
                .publications
                .iter()
                .flat_map(|step| &step.entries)
                .all(|entry| entry.event == VerifiedStatementEntryEvent::Recorded)
        );
    }
}

fn replace_outer(bundle: &[u8], certificate: &[u8]) -> Vec<u8> {
    let mut reader = Reader::new(bundle);
    let format = reader.bytes(64, "report format").unwrap();
    let major = reader.u16("major").unwrap();
    let minor = reader.u16("minor").unwrap();
    reader
        .bytes(MAX_STATEMENT_TRACE_CERTIFICATE_BYTES, "certificate")
        .unwrap();
    let tail = &bundle[bundle.len() - reader.remaining()..];
    let mut w = Writer::new();
    w.bytes(format)
        .u16(major)
        .u16(minor)
        .bytes(certificate)
        .fixed(tail);
    w.finish().unwrap()
}

#[test]
fn migration_statement_trace_real_bundle_refuses_resealed_attribution_and_unpinned_recipients() {
    let mut h = Harness::in_book_with_opening_date(Id128([0x74; 16]), Some(day("2026-01-02")));
    let (body, evidence) = source(&mut h);
    let before = h.head();
    open(&mut h, &body, evidence);
    let chunk = stage(&mut h, &body, evidence);
    let finalized = transition(&mut h, &body, fa_journal::migration::kind::FINALIZE);
    let mut request = h.request(before, "balance-sheet");
    request.comparison.after = Some(finalized.recorded_at);
    let certified = certify(&h, &request);
    let produced = produce(&mut h, &certified.certificate);
    verify(&h, &produced, &certified.certificate);
    let key = h.book.checkpoint_public_key();
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    for defect in 0..5 {
        let mut false_report = certified.report.clone();
        let entries = &mut false_report.publications.last_mut().unwrap().entries;
        let visible = entries
            .iter()
            .position(|entry| entry.event == StatementEntryEvent::BecameVisible)
            .unwrap();
        assert_eq!(entries[visible].entry_ref, chunk.entry_ref());
        match defect {
            0 => {
                entries.remove(visible);
            }
            1 => entries[visible].migration_run = Some(VId(body.vid().0 ^ 1)),
            2 => entries[visible].recorded_at = finalized.recorded_at,
            3 => entries[visible].event = StatementEntryEvent::Recorded,
            4 => entries.reverse(),
            _ => unreachable!(),
        }
        let forged = reseal(
            &certified.certificate,
            false_report.canonical_bytes().unwrap(),
        );
        let bundle = replace_outer(&produced.bundle.bytes, &forged.canonical_bytes().unwrap());
        assert!(
            verify_report_expected(
                &bundle,
                &[key],
                Some(&checkpoint.checkpoint),
                None,
                Some(forged.digest())
            )
            .is_err(),
            "defect {defect}"
        );
    }
    let mut wrong_pin = *certified.certificate.digest();
    wrong_pin[0] ^= 1;
    assert!(
        verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            Some(&checkpoint.checkpoint),
            None,
            Some(&wrong_pin)
        )
        .is_err()
    );
    assert!(verify_report_expected(&produced.bundle.bytes, &[key], None, None, None).is_err());
}
