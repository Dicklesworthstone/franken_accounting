//! Exact statement closing against the real native import, match and posting
//! paths. These cases distinguish cumulative cash from period movement and
//! historical truth from live drift.

use super::*;
use fa_journal::attestation::{
    Attestation, AttestationClaim, CapabilityBinding, Subject, read_attestation, reconciled_vid,
};
use fa_journal::bank::{
    BankReconciliationRecorded, BankReconciliationRequest, BankReconciliationStatus,
    bank_reconciliation_status, reconcile_bank_statement,
};

fn close_request(h: &Harness, import: BankImportWitness) -> BankReconciliationRequest {
    BankReconciliationRequest {
        import,
        predecessors: Vec::new(),
        evaluated_known_at: h.head(),
    }
}

fn close(
    h: &mut Harness,
    request: BankReconciliationRequest,
) -> Result<BankReconciliationRecorded, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(reconcile_bank_statement(
            &mut h.db,
            &cx,
            &h.book,
            &cap(CONFIRMER),
            request,
        ))
        .unwrap()
}

fn status(
    h: &mut Harness,
    manifest: Oid,
    at: Option<CommitSeq>,
) -> Result<BankReconciliationStatus, Refusal> {
    let cx = h.cx();
    h.runtime
        .block_on(bank_reconciliation_status(
            &mut h.db,
            &cx,
            &h.book,
            &metadata_cap(OWNER),
            manifest,
            at,
        ))
        .unwrap()
}

fn confirmed(h: &mut Harness) -> (BankImportWitness, BankMatchRecorded) {
    let entry = h.entry(&[10_000], "WIRE", b"cash");
    let (import, line) = h.imported("WIRE", 10_000, b"statement");
    let request = h.request(import.clone(), line, entry, 0);
    let matched = h.confirm(&cap(CONFIRMER), request).unwrap();
    (import, matched)
}

fn post_on(h: &mut Harness, amount: i128, reference: &str, key: &[u8], date: DateDay) -> EntryRef {
    let mut proposal = h.entry_payload(&[amount], reference, key);
    proposal.effective_date = date;
    let cx = h.cx();
    h.runtime
        .block_on(post(
            &mut h.db,
            &cx,
            &h.book,
            PostRequest {
                proposal,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(OWNER),
            },
        ))
        .unwrap()
        .unwrap()
        .entry_ref()
}

pub(super) fn statement(
    h: &mut Harness,
    reference: &str,
    amounts: &[i128],
    booking: DateDay,
    closing: DateDay,
    opening_balance: i128,
    key: &[u8],
) -> (BankImportWitness, Vec<Document>) {
    let policy = EvidencePolicy::embedded().unwrap();
    let kind = |name| policy.kind_by_name(name).unwrap().tag;
    let source = Document {
        book_id: h.book.book_id,
        kind: kind("BankStatement"),
        mime: "text/csv".into(),
        grade: 3,
        retrieved_by: OWNER,
        bytes: format!(
            "statement {:?} opens {opening_balance} closes on {} with {amounts:?}",
            key,
            closing.render()
        )
        .into_bytes(),
    };
    let mut lines = Vec::new();
    for (index, amount) in amounts.iter().enumerate() {
        let mut w = Writer::new();
        w.bytes(LINE_DOMAIN)
            .fixed(&source.oid().0)
            .u64(1)
            .u32((index + 1) as u32)
            .i32(booking.0)
            .i32(booking.0)
            .u8(1)
            .u32(h.usd.0)
            .i128(*amount)
            .str("Bank customer")
            .str(reference);
        lines.push(Document {
            book_id: h.book.book_id,
            kind: kind("Other"),
            mime: fa_journal::import::bank::BANK_LINE_MIME.into(),
            grade: 3,
            retrieved_by: OWNER,
            bytes: w.finish().unwrap(),
        });
    }
    let manifest = BankImportManifest {
        book_id: h.book.book_id,
        account: account_vid(h.book.book_id, "1000"),
        format: BankFormat::Csv,
        statement_oid: source.oid(),
        statement_commit: source.doc_commit(),
        unit: h.usd,
        sequence_number: 1,
        statement_date: closing,
        opening_balance,
        closing_balance: opening_balance + amounts.iter().sum::<i128>(),
        line_oids: lines.iter().map(Document::oid).collect(),
        csv_layout: None,
        predecessor: None,
    };
    let document = Document {
        book_id: h.book.book_id,
        kind: kind("Workpaper"),
        mime: fa_journal::import::bank::BANK_MANIFEST_MIME.into(),
        grade: 3,
        retrieved_by: OWNER,
        bytes: manifest.canonical_bytes().unwrap(),
    };
    let mut documents = lines.clone();
    documents.extend([source, document.clone()]);
    let request = ImportRequest {
        principal: OWNER,
        source: IntakeSource::Upload { principal: OWNER },
        idempotency_key: key.to_vec(),
        effective_date: closing,
        description: seal(&h.book, "closing statement"),
        documents,
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
    let witness = BankImportWitness::capture(&h.db, h.book.book_id, &document, &imported.receipt)
        .unwrap()
        .unwrap();
    (witness, lines)
}

#[test]
fn exact_close_is_cumulative_and_uses_the_statement_date_not_the_last_booking_day() {
    let mut h = Harness::new();
    let feb = DateDay::from_ymd(2026, 2, 15).unwrap();
    let period = h
        .book
        .calendar
        .periods_for_year(2026)
        .unwrap()
        .into_iter()
        .find(|period| period.kind == PeriodKind::Normal && period.contains(feb))
        .unwrap();
    let cx = h.cx();
    h.runtime
        .block_on(transition_period(
            &mut h.db,
            &cx,
            &h.book,
            &period.code,
            PeriodTransition::Open,
            OWNER,
            1,
            b"open-february",
            seal(&h.book, "open February"),
            &Capability::embedded(OWNER, &["close"]).unwrap(),
            &[],
        ))
        .unwrap()
        .unwrap();
    post_on(&mut h, 100_000, "OPENING", b"prior-period-cash", feb);
    let current = h.entry(&[10_000], "WIRE", b"current-cash");
    let closing = DateDay::from_ymd(2026, 3, 20).unwrap();
    let (import, mut lines) = statement(
        &mut h,
        "WIRE",
        &[10_000],
        day(),
        closing,
        100_000,
        b"cumulative-statement",
    );
    let request = h.request(import.clone(), lines.remove(0), current, 0);
    let matched = h.confirm(&cap(CONFIRMER), request).unwrap();
    let request = close_request(&h, import.clone());
    let evaluated = request.evaluated_known_at;
    let recorded = close(&mut h, request).unwrap();
    assert_eq!(
        recorded.claim.cash_balance, 110_000,
        "prior-period opening cash contributes"
    );
    assert_eq!(recorded.claim.manifest.statement_date, closing);
    assert_eq!(recorded.claim.evaluated_known_at, evaluated);
    assert_eq!(recorded.recorded_at.0, evaluated.0 + 1);
    assert_eq!(recorded.claim.matches, vec![decision_ref(&matched)]);
    let (stored, at) = read_attestation(&h.db, recorded.attestation_vid)
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.attestation.claim,
        AttestationClaim::Reconciled(Box::new(recorded.claim.clone()))
    );
    assert_eq!(
        stored.attestation.subject,
        Subject::Document(import.manifest_oid())
    );
    assert_eq!(at, recorded.recorded_at);
    assert_eq!(
        status(&mut h, import.manifest_oid(), None)
            .unwrap()
            .reconciled_through,
        Some(closing)
    );
}

#[test]
fn an_empty_statement_can_close_and_pending_holds_are_not_posted_cash() {
    let mut h = Harness::new();
    let mut pending = h.entry_payload(&[91_000], "HOLD", b"pending-hold");
    pending.class = EntryClass::PENDING;
    pending.pending = Some(fa_model::Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let cx = h.cx();
    h.runtime
        .block_on(post(
            &mut h.db,
            &cx,
            &h.book,
            PostRequest {
                proposal: pending,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: cap(OWNER),
            },
        ))
        .unwrap()
        .unwrap();
    let closing = DateDay::from_ymd(2026, 3, 23).unwrap();
    let (import, _) = statement(&mut h, "", &[], day(), closing, 0, b"empty-statement");
    let request = close_request(&h, import.clone());
    let recorded = close(&mut h, request).unwrap();
    assert_eq!(recorded.claim.cash_balance, 0);
    assert!(recorded.claim.matches.is_empty());
    let result = status(&mut h, import.manifest_oid(), None).unwrap();
    assert_eq!(result.reconciled_through, Some(closing));
    assert!(!result.reconciliations[0].cash_drift);
}

#[test]
fn missing_confirmations_and_unexplained_cash_differences_cannot_close() {
    let mut h = Harness::new();
    h.entry(&[10_000], "WIRE", b"cash");
    let (import, _) = h.imported("WIRE", 10_000, b"unconfirmed-statement");
    let request = close_request(&h, import);
    let before = h.head();
    let failure = close(&mut h, request).unwrap_err();
    assert!(failure.message.contains("every retained statement line"));
    assert_eq!(h.head(), before);

    let mut h = Harness::new();
    let (import, _) = confirmed(&mut h);
    h.entry(&[111], "OTHER", b"unexplained-cash");
    let request = close_request(&h, import);
    let before = h.head();
    let failure = close(&mut h, request).unwrap_err();
    assert!(failure.message.contains("differs from statement closing"));
    assert_eq!(h.head(), before);
}

#[test]
fn a_future_cash_leg_cannot_close_an_earlier_statement_even_when_it_was_matchable() {
    let mut h = Harness::new();
    let tomorrow = DateDay(day().0 + 1);
    let entry = post_on(&mut h, 10_000, "WIRE", b"tomorrow-cash", tomorrow);
    let (import, line) = h.imported("WIRE", 10_000, b"today-statement");
    let mut request = h.request(import.clone(), line, entry, 0);
    let mut candidates = request.decision_card.candidates.clone();
    candidates[0].analytic_score = 1_490_000_000;
    let mut features = request.decision_card.features.clone();
    features
        .iter_mut()
        .find(|f| f.name.ends_with("date_delta_days"))
        .unwrap()
        .value = 1;
    request.decision_card = fa_policy::decide_bank_match(
        None,
        [0; 32],
        Oid(domain_digest(LINE_DOMAIN, &[&request.line.bytes])).0,
        candidates,
        features,
        BenefitInterval {
            lower_bps: 0,
            upper_bps: 2_000,
        },
    );
    rebind(&mut request);
    h.confirm(&cap(CONFIRMER), request).unwrap();
    let request = close_request(&h, import);
    let before = h.head();
    let failure = close(&mut h, request).unwrap_err();
    assert!(
        failure
            .message
            .contains("effective after the statement close")
    );
    assert_eq!(h.head(), before);
}

#[test]
fn close_retries_remain_historical_after_late_cash_and_explicit_unmatch() {
    let mut h = Harness::new();
    let (import, matched) = confirmed(&mut h);
    let request = close_request(&h, import.clone());
    let recorded = close(&mut h, request.clone()).unwrap();
    let original = h.db.vertex(recorded.attestation_vid).unwrap().unwrap();
    let later = h.entry(&[555], "LATE", b"late-cash");
    h.unmatch(&metadata_cap(OWNER), decision_ref(&matched))
        .unwrap();
    let before = h.head();
    let retry = close(&mut h, request).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.attestation_vid, recorded.attestation_vid);
    assert_eq!(retry.recorded_at, recorded.recorded_at);
    assert_eq!(retry.principal, CONFIRMER);
    assert_eq!(h.head(), before);
    assert_eq!(
        h.db.vertex(recorded.attestation_vid).unwrap().unwrap(),
        original
    );

    let historical = status(&mut h, import.manifest_oid(), Some(recorded.recorded_at)).unwrap();
    assert!(!historical.reconciliations[0].cash_drift);
    assert!(!historical.reconciliations[0].match_drift);
    let current = status(&mut h, import.manifest_oid(), None).unwrap();
    let state = &current.reconciliations[0];
    assert!(state.balance_drift && state.cash_drift && state.match_drift);
    assert_eq!(state.cash_balance, 10_555);
    assert_eq!(state.changed_entries, vec![later]);
    assert_eq!(state.citing_entries, vec![later]);
    assert_eq!(
        current.reconciled_through,
        Some(day()),
        "drift never removes protection"
    );
}

#[test]
fn a_new_close_requires_the_current_prefix_but_exact_original_retry_does_not() {
    let mut h = Harness::new();
    let (import, _) = confirmed(&mut h);
    let request = close_request(&h, import.clone());
    let old = request.evaluated_known_at;
    let later = DateDay(day().0 + 1);
    post_on(&mut h, 3, "FUTURE", b"future-cash", later);
    let before = h.head();
    assert_eq!(
        close(&mut h, request).unwrap_err().code,
        refusal::code::CONFLICT
    );
    assert_eq!(h.head(), before);
    let current = close_request(&h, import);
    let recorded = close(&mut h, current).unwrap();
    assert!(recorded.claim.evaluated_known_at > old);
    assert_eq!(
        recorded.claim.cash_balance, 10_000,
        "cash after cutoff does not contribute"
    );
}

#[test]
fn native_attestation_births_cannot_be_deleted_relabelled_or_rewritten_then_restored() {
    for attack in 0..4 {
        let mut h = Harness::new();
        let (import, _) = confirmed(&mut h);
        let request = close_request(&h, import.clone());
        let recorded = close(&mut h, request.clone()).unwrap();
        let original = h.db.vertex(recorded.attestation_vid).unwrap().unwrap();
        let mut damage = WriteBatch::new(relation::ATTESTS);
        match attack {
            0 => damage.delete_vertex(recorded.attestation_vid),
            1 => damage.set_vertex_label(recorded.attestation_vid, label::ATTESTATION, false),
            _ => damage.set_vertex_property(
                recorded.attestation_vid,
                property::CODE,
                Some(CanonicalScalar::ucs_basic_text("Changed").unwrap()),
            ),
        };
        h.write(damage);
        if attack == 3 {
            let mut restore = WriteBatch::new(relation::ATTESTS);
            for (key, value) in original.props {
                restore.set_vertex_property(recorded.attestation_vid, key, Some(value));
            }
            h.write(restore);
        }
        let before = h.head();
        assert_eq!(
            status(&mut h, import.manifest_oid(), None)
                .unwrap_err()
                .code,
            refusal::code::ATTESTATION_DRIFT
        );
        assert_eq!(
            close(&mut h, request).unwrap_err().code,
            refusal::code::ATTESTATION_DRIFT
        );
        assert_eq!(h.head(), before);
        assert!(
            status(&mut h, import.manifest_oid(), Some(recorded.recorded_at)).is_ok(),
            "the intact earlier native prefix remains valid"
        );
    }
}

#[test]
fn native_guard_anchor_and_late_citation_deletion_are_not_silent() {
    for late_citation in [false, true] {
        let mut h = Harness::new();
        let (import, _) = confirmed(&mut h);
        let request = close_request(&h, import.clone());
        let recorded = close(&mut h, request).unwrap();
        let (kind, from, to) = if late_citation {
            let later = h.entry(&[1], "LATE", b"late-cash");
            (relation::CITES, later.vid, recorded.attestation_vid)
        } else {
            (
                relation::ATTESTS,
                recorded.attestation_vid,
                recorded.claim.manifest.account,
            )
        };
        let mut damage = WriteBatch::new(kind);
        damage.delete_edge(fa_journal::rows::edge_id(kind, from, to));
        h.write(damage);
        assert_eq!(
            status(&mut h, import.manifest_oid(), None)
                .unwrap_err()
                .code,
            refusal::code::ATTESTATION_DRIFT
        );
    }
}

#[test]
fn a_self_consistent_attestation_digest_cannot_invent_its_original_cash_fold() {
    let mut h = Harness::new();
    let (import, _) = confirmed(&mut h);
    let request = close_request(&h, import.clone());
    let recorded = close(&mut h, request).unwrap();
    let mut forged = recorded.claim;
    forged.evaluated_known_at = h.head();
    forged.cash_fold_digest = [0x7f; 32];
    let identity = reconciled_vid(
        h.book.book_id,
        import.manifest_oid(),
        forged.evaluated_known_at,
        OWNER,
    );
    let mut evidence = vec![import.manifest_oid(), import.manifest().statement_oid];
    evidence.sort();
    let attestation = Attestation {
        book_id: h.book.book_id,
        claim: AttestationClaim::Reconciled(Box::new(forged)),
        subject: Subject::Document(import.manifest_oid()),
        principal: OWNER,
        evidence_refs: evidence,
    };
    let binding = CapabilityBinding {
        profile: Profile::Human,
        capability_commitment: cap(OWNER).commitment().unwrap(),
    };
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(attestation.canonical_bytes(&binding).unwrap()).unwrap(),
        ),
        (
            property::FA_DIGEST,
            CanonicalScalar::bytes(attestation.signed_digest().unwrap().to_vec()).unwrap(),
        ),
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(h.book.book_id.0.to_vec()).unwrap(),
        ),
        (
            property::CODE,
            CanonicalScalar::ucs_basic_text("Reconciled").unwrap(),
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    let mut damage = WriteBatch::new(relation::ATTESTS);
    damage.create_vertex(identity, vec![label::ATTESTATION], props);
    h.write(damage);
    let failure = status(&mut h, import.manifest_oid(), None).unwrap_err();
    assert_eq!(failure.code, refusal::code::ATTESTATION_DRIFT);
    assert!(failure.message.contains("original cumulative cash"));
}

#[test]
fn reconciliation_authority_is_current_and_checked_before_any_close_write() {
    let mut h = Harness::new();
    let (import, _) = confirmed(&mut h);
    let request = close_request(&h, import);
    let before = h.head();
    let cx = h.cx();
    let missing_privileged = Capability::embedded(CONFIRMER, &["read", "reconcile"]).unwrap();
    assert!(
        h.runtime
            .block_on(reconcile_bank_statement(
                &mut h.db,
                &cx,
                &h.book,
                &missing_privileged,
                request.clone()
            ))
            .unwrap()
            .is_err()
    );
    let no_reconcile = Capability::embedded(CONFIRMER, &["read", "privileged"]).unwrap();
    assert!(
        h.runtime
            .block_on(reconcile_bank_statement(
                &mut h.db,
                &cx,
                &h.book,
                &no_reconcile,
                request
            ))
            .unwrap()
            .is_err()
    );
    assert_eq!(h.head(), before);
}
