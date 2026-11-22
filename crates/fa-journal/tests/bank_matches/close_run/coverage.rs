//! Portfolio close coverage is derived from the authentic REA inventory.

use super::*;
use fa_journal::close_run::{
    BankInstrumentCoverageCheckpoint, verify_bank_instrument_coverage_checkpoint,
};
use fa_model::{InstrumentKind, InstrumentSpec, PartyKind, PartySpec};

fn bank(h: &mut Harness, code: &str, account: &str) -> VId {
    let schema = Capability::embedded(OWNER, &["schema_change"]).unwrap();
    let cx = h.cx();
    let party = PartySpec {
        code: format!("PARTY-{code}"),
        kind: PartyKind::Bank,
        name: seal(&h.book, "Registered bank"),
        identifiers: Vec::new(),
        external_ids: Vec::new(),
    };
    let held_at = h
        .runtime
        .block_on(fa_journal::create_party(
            &mut h.db,
            &cx,
            &h.book,
            &party,
            OWNER,
            day(),
            party.code.as_bytes(),
            seal(&h.book, "register bank party"),
            &schema,
        ))
        .unwrap()
        .unwrap()
        .target_vid;
    let instrument = InstrumentSpec {
        code: code.into(),
        name: format!("Bank account {code}"),
        kind: InstrumentKind::BankAccount,
        unit: h.usd,
        held_at_party: held_at,
        mirrors_account: account_vid(h.book.book_id, account),
        external_ids: Vec::new(),
    };
    h.runtime
        .block_on(fa_journal::create_instrument(
            &mut h.db,
            &cx,
            &h.book,
            &instrument,
            OWNER,
            day(),
            code.as_bytes(),
            seal(&h.book, "register bank account"),
            &schema,
        ))
        .unwrap()
        .unwrap()
        .target_vid
}

fn second_cash_account(h: &mut Harness) {
    let cx = h.cx();
    h.runtime
        .block_on(install_chart(
            &mut h.db,
            &cx,
            &h.book,
            &[AccountSpec {
                code: "1001".into(),
                name: "Second bank cash".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: UnitPolicy::Single(h.usd),
                parent_code: None,
                limit: None,
            }],
            OWNER,
            day(),
            b"second-bank-chart",
            seal(&h.book, "second cash account"),
            &Capability::embedded(OWNER, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
}

fn empty_reconciliation(h: &mut Harness, account: &str, key: &[u8]) -> Oid {
    let policy = EvidencePolicy::embedded().unwrap();
    let end = DateDay::from_ymd(2026, 3, 31).unwrap();
    let source = Document {
        book_id: h.book.book_id,
        kind: policy.kind_by_name("BankStatement").unwrap().tag,
        mime: "text/csv".into(),
        grade: 3,
        retrieved_by: OWNER,
        bytes: format!("Zero-balance period-end statement {account} {key:?}").into_bytes(),
    };
    let manifest = BankImportManifest {
        book_id: h.book.book_id,
        account: account_vid(h.book.book_id, account),
        format: BankFormat::Csv,
        statement_oid: source.oid(),
        statement_commit: source.doc_commit(),
        unit: h.usd,
        sequence_number: 1,
        statement_date: end,
        opening_balance: 0,
        closing_balance: 0,
        line_oids: Vec::new(),
        csv_layout: None,
        predecessor: None,
    };
    let document = Document {
        book_id: h.book.book_id,
        kind: policy.kind_by_name("Workpaper").unwrap().tag,
        mime: fa_journal::import::bank::BANK_MANIFEST_MIME.into(),
        grade: 3,
        retrieved_by: OWNER,
        bytes: manifest.canonical_bytes().unwrap(),
    };
    let request = ImportRequest {
        principal: OWNER,
        source: IntakeSource::Upload { principal: OWNER },
        idempotency_key: key.to_vec(),
        effective_date: end,
        description: seal(&h.book, "period-end statement"),
        documents: vec![source, document.clone()],
    };
    let cx = h.cx();
    let imported = h
        .runtime
        .block_on(fa_journal::import::import_run_in_store(
            &mut h.db,
            &cx,
            &h.book,
            &cap(OWNER),
            &h.store,
            request,
        ))
        .unwrap()
        .unwrap();
    let import = BankImportWitness::capture(&h.db, h.book.book_id, &document, &imported.receipt)
        .unwrap()
        .unwrap();
    let oid = import.manifest_oid();
    let request = BankReconciliationRequest {
        import,
        predecessors: Vec::new(),
        evaluated_known_at: h.head(),
    };
    h.runtime
        .block_on(reconcile_bank_statement(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            None,
            request,
        ))
        .unwrap()
        .unwrap();
    oid
}

fn coverage(
    h: &Harness,
    manifests: &[Oid],
    at: Option<CommitSeq>,
) -> Result<BankInstrumentCoverageCheckpoint, Refusal> {
    verify_bank_instrument_coverage_checkpoint(
        &h.db,
        &h.cx(),
        &h.book,
        &metadata_cap(OWNER),
        manifests,
        &period(h),
        at,
    )
    .unwrap()
}

fn start_coverage(h: &mut Harness, manifests: Vec<Oid>) {
    let definition = CloseRunDefinition {
        name: "bank-close".into(),
        period: period(h),
        tasks: vec![
            CloseTaskDefinition {
                id: "bank".into(),
                depends_on: Vec::new(),
                action: CloseTaskAction::VerifyBankInstrumentCoverage {
                    manifest_oids: manifests,
                },
            },
            CloseTaskDefinition {
                id: "final".into(),
                depends_on: vec!["bank".into()],
                action: CloseTaskAction::PeriodTransition(PeriodTransition::Close),
            },
        ],
    };
    let cx = h.cx();
    h.runtime
        .block_on(create_close_run(
            &mut h.db,
            &cx,
            &h.book,
            &definition,
            &closer(),
            seal(&h.book, "complete registered-bank close coverage"),
        ))
        .unwrap()
        .unwrap();
}

#[test]
fn every_registered_bank_requires_one_distinct_exact_native_manifest() {
    let mut h = Harness::new();
    second_cash_account(&mut h);
    let first = bank(&mut h, "OPERATING", "1000");
    let second = bank(&mut h, "PAYROLL", "1001");
    let a = empty_reconciliation(&mut h, "1000", b"operating-statement");
    let b = empty_reconciliation(&mut h, "1001", b"payroll-statement");
    let second_a = empty_reconciliation(&mut h, "1000", b"other-operating-statement");
    let before = h.head();
    let checked = coverage(&h, &[b, a], None).unwrap();
    assert_eq!(checked.known_at(), before);
    assert_eq!(checked.instruments().len(), 2);
    for (instrument, manifest, account) in [(first, a, "1000"), (second, b, "1001")] {
        let item = checked
            .instruments()
            .iter()
            .find(|item| item.instrument == instrument)
            .unwrap();
        assert_eq!(item.manifest_oid, manifest);
        assert_eq!(item.account, account_vid(h.book.book_id, account));
        assert_eq!(item.unit, h.usd);
        let single = checkpoint(&h, manifest, None).unwrap();
        assert_eq!(item.attestation, single.attestation());
        assert_eq!(item.checkpoint_digest, *single.source_digest());
    }
    for selected in [
        vec![],
        vec![a],
        vec![a, a],
        vec![a, Oid([91; 32])],
        vec![a, b, second_a],
        vec![a, second_a],
    ] {
        assert_eq!(
            coverage(&h, &selected, None).unwrap_err().code,
            refusal::code::PLAN_INVALIDATED
        );
    }
    assert_eq!(
        h.head(),
        before,
        "complete and refused coverage checks are reads"
    );
    start_coverage(&mut h, vec![b, a]);
    let completed = step(&mut h, "bank", None, Vec::new()).unwrap();
    assert_eq!(completed.receipt.effect, fa_journal::rows::book_root());
    assert!(final_plan(&h).is_ok());
}

#[test]
fn empty_inventory_is_authenticated_and_a_new_bank_blocks_even_a_prepared_close() {
    let mut h = Harness::new();
    // A chart cash balance does not invent a BankAccount registration.
    h.entry(&[123], "PETTY CASH", b"unregistered-cash");
    let empty = coverage(&h, &[], None).unwrap();
    assert!(empty.instruments().is_empty());
    start_coverage(&mut h, Vec::new());
    let completed = step(&mut h, "bank", None, Vec::new()).unwrap();
    assert_eq!(completed.receipt.effect, fa_journal::rows::book_root());
    let original_at = h.head();
    let plan = final_plan(&h).unwrap();
    bank(&mut h, "NEW-BANK", "1000");
    let after_registration = h.head();
    assert_eq!(
        coverage(&h, &[], Some(original_at))
            .unwrap()
            .source_digest(),
        empty.source_digest()
    );
    assert_eq!(
        coverage(&h, &[], None).unwrap_err().code,
        refusal::code::PLAN_INVALIDATED
    );

    let view = close_run_status(
        &h.db,
        &h.cx(),
        &h.book,
        "bank-close",
        &Capability::embedded(OWNER, &["read"]).unwrap(),
    )
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(view.tasks[0].completion.as_ref(), Some(&completed.receipt));
    let request = CloseTaskRequest {
        capability: Capability::embedded(OWNER, &["read", "close"]).unwrap(),
        description: seal(&h.book, "observe original complete inventory"),
        transition_plan: None,
        approvals: Vec::new(),
        review: None,
    };
    let cx = h.cx();
    let retry = h
        .runtime
        .block_on(execute_close_task(
            &mut h.db,
            &cx,
            &h.book,
            "bank-close",
            "bank",
            request,
        ))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.receipt, completed.receipt);
    assert_eq!(
        final_plan(&h).unwrap_err().code,
        refusal::code::PLAN_INVALIDATED
    );
    assert_eq!(
        step(&mut h, "final", Some(plan), Vec::new())
            .unwrap_err()
            .code,
        refusal::code::PLAN_INVALIDATED
    );
    assert_eq!(
        h.head(),
        after_registration,
        "no stale completion is published"
    );
}

#[test]
fn shared_bank_mirror_scope_is_ambiguous_and_authority_precedes_inventory_reads() {
    let mut h = Harness::new();
    let (import, _, _) = fixture(&mut h, DateDay::from_ymd(2026, 3, 31).unwrap());
    bank(&mut h, "FIRST", "1000");
    bank(&mut h, "SECOND", "1000");
    let before = h.head();
    let refusal = coverage(&h, &[import.manifest_oid()], None).unwrap_err();
    assert_eq!(refusal.code, refusal::code::PLAN_INVALIDATED);
    assert!(refusal.message.contains("share one account/unit"));
    for denied in [
        Capability::embedded(OWNER, &["read"]).unwrap(),
        metadata_cap(OWNER).for_accounts(&["1000"]).unwrap(),
    ] {
        let checked = |manifests: &[Oid]| {
            verify_bank_instrument_coverage_checkpoint(
                &h.db,
                &h.cx(),
                &h.book,
                &denied,
                manifests,
                &period(&h),
                None,
            )
            .unwrap()
            .unwrap_err()
        };
        assert_eq!(checked(&[import.manifest_oid()]), checked(&[Oid([99; 32])]));
        assert_eq!(checked(&[]), checked(&[Oid([99; 32])]));
    }
    assert_eq!(h.head(), before);
}

#[test]
fn portfolio_cannot_accept_partial_coverage_by_forging_the_period_end() {
    let mut h = Harness::new();
    let (import, _, _) = fixture(&mut h, DateDay::from_ymd(2026, 3, 30).unwrap());
    bank(&mut h, "OPERATING", "1000");
    assert!(coverage(&h, &[import.manifest_oid()], None).is_err());
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        fa_model::period_vid(&h.book.calendar.id, &period(&h)),
        property::PERIOD_END,
        Some(CanonicalScalar::Int(i64::from(
            DateDay::from_ymd(2026, 3, 31).unwrap().0,
        ))),
    );
    h.write(damage);
    let error = verify_bank_instrument_coverage_checkpoint(
        &h.db,
        &h.cx(),
        &h.book,
        &metadata_cap(OWNER),
        &[import.manifest_oid()],
        &period(&h),
        None,
    )
    .unwrap_err();
    assert!(
        matches!(error, KernelError::Corrupt(ref message) if message.contains("canonical birth definition"))
    );
}
