//! Native exact statement closes, then authorized late monetary activity.
//! The procedure consumes the real native historical fold and retains the
//! original attestation as evidence in every later observation.

use super::*;
use fa_journal::bank::{
    BankReconciliationRecorded, BankReconciliationRequest, read_bank_reconciliation_states,
    reconcile_bank_statement, verify_bank_reconciliation_history,
};
use fa_journal::import::{BankFormat, BankImportManifest, BankImportWitness};
use fa_lantern::bank_reconciliation::BankStatementDrift;
use fa_model::{EntryRef, IntakeSource};
use fa_registry::evidence_policy::EvidencePolicy;

fn read_cap() -> Capability {
    Capability::embedded(PREPARER, &["read", "reconcile"]).unwrap()
}

fn empty_close(h: &mut Harness, closing: DateDay, key: &[u8]) -> BankReconciliationRecorded {
    let policy = EvidencePolicy::embedded().unwrap();
    let kind = |name| policy.kind_by_name(name).unwrap().tag;
    let source = Document {
        book_id: h.book.book_id,
        kind: kind("BankStatement"),
        mime: "text/csv".into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: format!(
            "statement_date,opening_balance,closing_balance\n{},0,0\n",
            closing.render()
        )
        .into_bytes(),
    };
    let manifest = BankImportManifest {
        book_id: h.book.book_id,
        account: h.account("1000"),
        format: BankFormat::Csv,
        statement_oid: source.oid(),
        statement_commit: source.doc_commit(),
        unit: h.usd,
        sequence_number: 1,
        statement_date: closing,
        opening_balance: 0,
        closing_balance: 0,
        line_oids: Vec::new(),
        predecessor: None,
    };
    let document = Document {
        book_id: h.book.book_id,
        kind: kind("Workpaper"),
        mime: fa_journal::import::bank::BANK_MANIFEST_MIME.into(),
        grade: 3,
        retrieved_by: PREPARER,
        bytes: manifest.canonical_bytes().unwrap(),
    };
    let capability =
        Capability::embedded(PREPARER, &["post", "read", "reconcile", "privileged"]).unwrap();
    let request = ImportRequest {
        principal: PREPARER,
        source: IntakeSource::Upload {
            principal: PREPARER,
        },
        idempotency_key: key.to_vec(),
        effective_date: closing,
        description: h.seal("empty bank statement for exact native close"),
        documents: vec![source, document.clone()],
    };
    let cx = h.ctx();
    let imported = h
        .runtime
        .block_on(import_run(&mut h.db, &cx, &h.book, &capability, request))
        .unwrap()
        .unwrap();
    let import = BankImportWitness::capture(&h.db, h.book.book_id, &document, &imported.receipt)
        .unwrap()
        .unwrap();
    let request = BankReconciliationRequest {
        import,
        predecessors: Vec::new(),
        evaluated_known_at: h.db.frontier().unwrap(),
    };
    h.runtime
        .block_on(reconcile_bank_statement(
            &mut h.db,
            &cx,
            &h.book,
            &capability,
            request,
        ))
        .unwrap()
        .unwrap()
}

fn late_post(h: &mut Harness, spec: &Spec) -> EntryRef {
    let request = PostRequest {
        proposal: h.proposal(spec),
        approvals: Vec::new(),
        plan_certificate: None,
        capability: Capability::embedded(PREPARER, &["post", "reconcile"]).unwrap(),
    };
    let cx = h.ctx();
    let posted = h
        .runtime
        .block_on(post(&mut h.db, &cx, &h.book, request))
        .unwrap()
        .unwrap();
    let Posted::Committed {
        entry_ref,
        recorded_at,
        ..
    } = posted
    else {
        panic!("fresh late entry must commit")
    };
    h.posted.push((entry_ref.vid, recorded_at));
    entry_ref
}

pub(super) fn snapshot(
    h: &Harness,
    known_at: Option<CommitSeq>,
    effective_through: Option<DateDay>,
) -> Snapshot {
    // The native boundary admits before reading the complete bank source.
    let states = read_bank_reconciliation_states(&h.db, &h.ctx(), &h.book, &read_cap(), known_at)
        .unwrap()
        .unwrap();
    let mut snapshot = Snapshot::read(&h.db, &h.book, known_at, effective_through).unwrap();
    snapshot.bank_reconciliations = Some(states);
    snapshot
}

#[test]
fn native_balance_and_net_zero_drift_preserve_the_original_close_and_all_entry_citations() {
    let mut h = harness();
    let close = empty_close(&mut h, day(2026, 3, 31), b"march-empty");
    let procedure = BankStatementDrift::new().unwrap();
    let original = snapshot(&h, Some(close.recorded_at), None);
    let original_run = run_over(&original, &h.book, &procedure).unwrap();
    assert!(original_run.findings.is_empty());

    let debit = late_post(&mut h, &Spec::simple(day(2026, 3, 20), "1000", "4000", 70));
    let after_debit = snapshot(&h, None, None);
    let run = run_over(&after_debit, &h.book, &procedure).unwrap();
    assert_eq!(run.findings.len(), 1);
    let finding = &run.findings[0];
    assert_eq!(finding.statistic.name, "bank_statement_balance_drift");
    assert_eq!((finding.statistic.value, finding.statistic.scale), (70, 2));
    assert_eq!(finding.statistic.population, 1);
    assert_eq!(finding.severity, Severity::High);
    assert!(
        finding
            .cites
            .contains(&Cite::Attestation(close.attestation_vid))
    );
    assert!(finding.cites.contains(&Cite::Entry(debit.vid)));
    assert!(
        finding
            .cites
            .contains(&Cite::Document(close.claim.manifest_oid))
    );
    h.assert_cites_resolve(&run);

    let credit = late_post(&mut h, &Spec::simple(day(2026, 3, 21), "6000", "1000", 70));
    let net_zero = snapshot(&h, None, None);
    let run = run_over(&net_zero, &h.book, &procedure).unwrap();
    assert_eq!(run.findings.len(), 1);
    let finding = &run.findings[0];
    assert_eq!(finding.statistic.name, "bank_statement_contribution_drift");
    assert_eq!((finding.statistic.value, finding.statistic.scale), (2, 0));
    assert_eq!(finding.severity, Severity::Medium);
    assert!(finding.cites.contains(&Cite::Entry(debit.vid)));
    assert!(finding.cites.contains(&Cite::Entry(credit.vid)));
    assert_eq!(
        finding.cites.len(),
        6,
        "duplicate changed/citing entries are combined"
    );
    h.assert_cites_resolve(&run);
    let states = net_zero.bank_reconciliations.as_ref().unwrap();
    assert_eq!(states[0].recorded, close);
    assert_eq!(states[0].cash_balance, 0);
    assert!(states[0].cash_drift);
    assert_eq!(states[0].changed_entries.len(), 2);
    assert_eq!(states[0].citing_entries.len(), 2);
    assert!(
        determinism(&net_zero, &h.book, &procedure)
            .unwrap()
            .deterministic()
    );
    let row = fa_lantern::bind(BankStatementDrift::ID).unwrap();
    assert!(run.work.within_registered_bound(&row.complexity, &net_zero));

    let restored = snapshot(&h, Some(close.recorded_at), None);
    let restored_run = run_over(&restored, &h.book, &procedure).unwrap();
    assert_eq!(restored_run.findings_digest, original_run.findings_digest);
    assert!(
        restored_run.findings.is_empty(),
        "later drift does not rewrite historical truth"
    );
    verify_bank_reconciliation_history(&h.db, &h.ctx(), &h.book, &read_cap(), None)
        .unwrap()
        .unwrap();
}

#[test]
fn complete_close_population_and_effective_selection_use_statement_dates() {
    let mut h = harness();
    let march = empty_close(&mut h, day(2026, 3, 31), b"march-close");
    let april = empty_close(&mut h, day(2026, 4, 30), b"april-close");
    let procedure = BankStatementDrift::new().unwrap();
    assert_eq!(
        snapshot(&h, Some(march.recorded_at), None)
            .bank_reconciliations
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        snapshot(&h, Some(april.recorded_at), None)
            .bank_reconciliations
            .unwrap()
            .len(),
        2
    );
    late_post(&mut h, &Spec::simple(day(2026, 3, 20), "1000", "4000", 100));
    let all = run_over(&snapshot(&h, None, None), &h.book, &procedure).unwrap();
    assert_eq!(all.findings.len(), 2);
    assert!(
        all.findings
            .iter()
            .all(|finding| finding.statistic.population == 2)
    );
    let march_only = run_over(
        &snapshot(&h, None, Some(day(2026, 3, 31))),
        &h.book,
        &procedure,
    )
    .unwrap();
    assert_eq!(march_only.findings.len(), 1);
    assert_eq!(march_only.findings[0].statistic.population, 1);
    assert!(
        march_only.findings[0]
            .cites
            .contains(&Cite::Attestation(march.attestation_vid))
    );
    let before_closes = run_over(
        &snapshot(&h, None, Some(day(2026, 3, 30))),
        &h.book,
        &procedure,
    )
    .unwrap();
    assert!(before_closes.findings.is_empty());
}

#[test]
fn missing_admission_or_native_close_population_is_an_explicit_refusal() {
    let mut h = harness();
    empty_close(&mut h, day(2026, 3, 31), b"close-for-refusal");
    let procedure = BankStatementDrift::new().unwrap();
    let read_only = Capability::embedded(PREPARER, &["read"]).unwrap();
    assert!(
        read_bank_reconciliation_states(&h.db, &h.ctx(), &h.book, &read_only, None)
            .unwrap()
            .is_err()
    );
    assert!(
        verify_bank_reconciliation_history(&h.db, &h.ctx(), &h.book, &read_only, None)
            .unwrap()
            .is_err()
    );

    let mut raw = Snapshot::read(&h.db, &h.book, None, None).unwrap();
    assert!(matches!(
        run_over(&raw, &h.book, &procedure),
        Err(LanternError::Parameter { .. })
    ));
    raw.bank_reconciliations = Some(Vec::new());
    let missing = run_over(&raw, &h.book, &procedure).unwrap_err();
    assert!(matches!(missing, LanternError::Parameter { message, .. }
        if message.contains("omit a Reconciled attestation")));
    let mut duplicate = snapshot(&h, None, None);
    let states = duplicate.bank_reconciliations.as_mut().unwrap();
    states.push(states[0].clone());
    assert!(run_over(&duplicate, &h.book, &procedure).is_err());
}

#[test]
fn complete_citations_and_exact_difference_refuse_overflow_without_partial_findings() {
    let mut h = harness();
    empty_close(&mut h, day(2026, 3, 31), b"close-for-bounds");
    let procedure = BankStatementDrift::new().unwrap();
    let mut bounded = snapshot(&h, None, None);
    // Adversarial adapter input tests the fixed output limit directly; real
    // orchestration can supply states only by the native verified fold above.
    let state = &mut bounded.bank_reconciliations.as_mut().unwrap()[0];
    state.cash_balance = 1;
    state.cash_fold_digest[0] ^= 1;
    state.balance_drift = true;
    state.cash_drift = true;
    state.changed_entries = (0..fa_lantern::MAX_CITES - 3)
        .map(|index| EntryRef {
            vid: VId(100_000 + index as u128),
            entry_digest: [7; 32],
        })
        .collect();
    let failure = run_over(&bounded, &h.book, &procedure).unwrap_err();
    assert!(matches!(failure, LanternError::Parameter { message, .. }
        if message.contains("exceeds 4096 citations")));

    let state = &mut bounded.bank_reconciliations.as_mut().unwrap()[0];
    state.changed_entries.truncate(1);
    state.cash_balance = i128::MIN;
    assert!(matches!(
        run_over(&bounded, &h.book, &procedure),
        Err(LanternError::Overflow("bank statement cash discrepancy"))
    ));
}
