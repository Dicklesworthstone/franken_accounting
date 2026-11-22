//! Adjustment bridges follow the same posted population as native registers.
use super::*;
use fa::{BookToBookBridgeRow, BookToBookReasonCode};
use fa_model::{ControlPayload, EntryRef, Supersession, SupersessionKind};

const RULE: Oid = Oid([0x42; 32]);

#[test]
fn uploaded_anchor_documents_are_inert_until_an_authorized_atomic_activation() {
    let mut f = Fixture::new(0xb6);
    let book_id = f.book.context().book_id;
    let parent = Id128([0xc1; 16]);
    let anchor = fa_journal::adjustment_layer::AdjustmentLayerAnchor {
        book_id,
        parent_book_id: parent,
        parent_known_at: CommitSeq(12),
    };
    let uploaded = Document {
        book_id,
        kind: fa::consolidation::ADJUSTMENT_LAYER_DOCUMENT_KIND,
        mime: fa::consolidation::ADJUSTMENT_LAYER_MIME.into(),
        grade: 3,
        retrieved_by: PRINCIPAL,
        bytes: anchor.encode().unwrap(),
    };
    let imported = f.book.add_document(&uploaded).unwrap().unwrap();
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    assert_eq!(
        f.book.book_kind_at(None, &read).unwrap().unwrap(),
        fa::BookKind::Primary
    );
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let activated = f
        .book
        .anchor_adjustment_layer(&schema, parent, CommitSeq(12))
        .unwrap()
        .unwrap();
    assert_eq!(activated.document_oid, imported.oid);
    assert!(activated.recorded_at > imported.recorded_at);
    assert!(!activated.already_recorded);
    assert_eq!(
        f.book
            .book_kind_at(Some(imported.recorded_at), &read)
            .unwrap()
            .unwrap(),
        fa::BookKind::Primary
    );
    assert_eq!(
        f.book.book_kind_at(None, &read).unwrap().unwrap(),
        fa::BookKind::AdjustmentLayer {
            parent_book_id: parent,
            parent_known_at: 12,
        }
    );
    let head = f.book.head().unwrap();
    let retry = f
        .book
        .anchor_adjustment_layer(&schema, parent, CommitSeq(12))
        .unwrap()
        .unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.recorded_at, activated.recorded_at);
    assert_eq!(f.book.head().unwrap(), head);

    // Neither a forged parent change nor invalid bytes bearing the reserved
    // MIME may change the authoritative anchor or poison its historical fold.
    let mut forged = uploaded;
    forged.bytes = fa_journal::adjustment_layer::AdjustmentLayerAnchor {
        book_id,
        parent_book_id: Id128([0xc2; 16]),
        parent_known_at: CommitSeq(99),
    }
    .encode()
    .unwrap();
    f.book.add_document(&forged).unwrap().unwrap();
    forged.bytes = b"not an anchor".to_vec();
    f.book.add_document(&forged).unwrap().unwrap();
    assert_eq!(
        f.book.book_kind_at(None, &read).unwrap().unwrap(),
        fa::BookKind::AdjustmentLayer {
            parent_book_id: parent,
            parent_known_at: 12,
        }
    );
    let advanced = f
        .book
        .anchor_adjustment_layer(&schema, parent, CommitSeq(13))
        .unwrap()
        .unwrap();
    assert!(advanced.recorded_at > head);
    assert_eq!(
        f.book
            .book_kind_at(Some(activated.recorded_at), &read)
            .unwrap()
            .unwrap(),
        fa::BookKind::AdjustmentLayer {
            parent_book_id: parent,
            parent_known_at: 12,
        }
    );
    assert_eq!(
        f.book.book_kind_at(None, &read).unwrap().unwrap(),
        fa::BookKind::AdjustmentLayer {
            parent_book_id: parent,
            parent_known_at: 13,
        }
    );
    let head = f.book.head().unwrap();
    assert!(
        f.book
            .anchor_adjustment_layer(&schema, parent, CommitSeq(12))
            .unwrap()
            .is_err()
    );
    assert!(
        f.book
            .anchor_adjustment_layer(&schema, Id128([0xc2; 16]), CommitSeq(14))
            .unwrap()
            .is_err()
    );
    assert_eq!(f.book.head().unwrap(), head);
    // An anchor is a recognized nonmonetary schema control in chart replay.
    assert!(f.book.balance_as_of(day(2026, 1, 31), None).is_ok());
}

#[test]
fn adjustment_anchor_requires_schema_control_class_and_direct_write_authority() {
    let mut f = Fixture::new(0xb7);
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let denied = [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        schema.clone().for_classes(&[EntryClass::ORIGINAL]).unwrap(),
        schema.clone().for_accounts(&["1000"]).unwrap(),
        schema.with_requires_dry_run(),
    ];
    let before = f.book.head().unwrap();
    for capability in denied {
        assert!(
            f.book
                .anchor_adjustment_layer(&capability, Id128([0xc3; 16]), CommitSeq(10))
                .unwrap()
                .is_err()
        );
        assert_eq!(f.book.head().unwrap(), before);
    }
}

#[test]
fn activated_layer_survives_evidence_custody_transfer_and_portable_report_replay() {
    let mut f = Fixture::new(0xb8);
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    let anchored = f
        .book
        .anchor_adjustment_layer(&schema, Id128([0xc4; 16]), CommitSeq(10))
        .unwrap()
        .unwrap();
    f.book
        .transfer_custody(
            &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            &anchored.document_oid,
            VId(2),
        )
        .unwrap()
        .unwrap();
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let expected = fa::BookKind::AdjustmentLayer {
        parent_book_id: Id128([0xc4; 16]),
        parent_known_at: 10,
    };
    assert_eq!(f.book.book_kind_at(None, &read).unwrap().unwrap(), expected);
    assert_eq!(
        f.book
            .book_kind_at(Some(anchored.recorded_at), &read)
            .unwrap()
            .unwrap(),
        expected
    );
    f.transfer(
        day(2026, 1, 15),
        b"anchored-report",
        f.usd,
        ("1000", "4000"),
        800,
    );
    let certificate = f
        .book
        .certify_trial_balance(fa::TrialBalanceSelection::AsOf(day(2026, 1, 31)), None)
        .unwrap()
        .unwrap()
        .certificate;
    let produced = super::report_bundle::produce(&mut f.book, &certificate);
    let key = f.book.checkpoint_public_key();
    let checkpoint = fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
    let verified = fa_verify::report::verify_report_expected(
        &produced.bundle.bytes,
        &[key],
        Some(&checkpoint.checkpoint),
        Some(&produced.receipt),
        Some(&certificate.digest),
    )
    .unwrap();
    assert_eq!(verified.output, certificate.output);
    assert_eq!(verified.known_at, certificate.known_at.0);
}

struct BridgeFixture {
    parent: Fixture,
    layer: Fixture,
    parent_at: CommitSeq,
}

impl BridgeFixture {
    fn new() -> Self {
        let mut parent = Fixture::new(0xb4);
        parent.transfer(
            day(2026, 1, 5),
            b"parent-expense",
            parent.usd,
            ("6000", "1000"),
            1_000,
        );
        let parent_at = parent.book.head().unwrap();
        let mut layer = Fixture::new(0xb5);
        layer
            .book
            .anchor_adjustment_layer(
                &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
                parent.book.context().book_id,
                parent_at,
            )
            .unwrap()
            .unwrap();
        Self {
            parent,
            layer,
            parent_at,
        }
    }

    fn reconcile(
        &self,
        through: DateDay,
        at: Option<CommitSeq>,
    ) -> Result<fa::consolidation::BookToBookReconciliation, fa_journal::Refusal> {
        let parent = self
            .parent
            .book
            .balance_as_of(through, Some(self.parent_at))
            .unwrap();
        self.layer
            .book
            .reconcile_book_to_book(
                &Capability::embedded(PRINCIPAL, &["read", "reconcile"]).unwrap(),
                self.parent.book.context().book_id,
                self.parent_at,
                &parent,
                None,
                Some(through),
                at,
            )
            .unwrap()
    }

    fn reserve(&mut self, key: &[u8], amount: i128) -> Posted {
        let mut proposal = self.layer.proposal(
            day(2026, 1, 15),
            key,
            EntryClass::PENDING,
            self.layer.legs(self.layer.usd, ("6000", "1000"), amount),
        );
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: None,
            disposition: None,
        });
        self.layer
            .book
            .attach_book_to_book_tag(
                &mut proposal,
                BookToBookReasonCode::M1TemporaryDepreciation,
                Oid([0x41; 32]),
            )
            .unwrap();
        self.layer.commit(proposal)
    }

    fn partial(&mut self, hold: EntryRef, tagged: bool) -> Posted {
        let mut proposal = self.layer.proposal(
            day(2026, 2, 5),
            b"partial-adjustment",
            EntryClass::RESOLUTION,
            self.layer.legs(self.layer.usd, ("6000", "1000"), 7_500),
        );
        proposal.pending = Some(Pending {
            timeout_ns: None,
            resolution_of: Some(hold),
            disposition: Some(Disposition::Posts {
                source_ordinals: vec![0, 1],
            }),
        });
        if tagged {
            self.layer
                .book
                .attach_book_to_book_tag(
                    &mut proposal,
                    BookToBookReasonCode::ManagementCostAllocation,
                    RULE,
                )
                .unwrap();
        }
        self.layer.commit(proposal)
    }
}

#[test]
fn native_parent_replay_rejects_a_valid_certificate_from_a_different_same_id_history() {
    let f = BridgeFixture::new();
    let through = day(2026, 1, 31);
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let reconcile = Capability::embedded(PRINCIPAL, &["read", "reconcile"]).unwrap();
    let genuine = f
        .parent
        .book
        .certify_trial_balance(fa::TrialBalanceSelection::AsOf(through), Some(f.parent_at))
        .unwrap()
        .unwrap();
    let source = f
        .parent
        .book
        .replay_parent_trial_balance(&read, &genuine.certificate)
        .unwrap()
        .unwrap();
    assert_eq!(source.book_id(), f.parent.book.context().book_id);
    assert_eq!(source.known_at(), f.parent_at);
    let native = f
        .layer
        .book
        .reconcile_book_to_book_from_parent(&reconcile, &source, None, Some(through), None)
        .unwrap()
        .unwrap();
    assert_eq!(native, f.reconcile(through, None).unwrap());
    assert_eq!(expense(&native).parent_net, 1_000);

    // A self-consistent certificate can claim the same book and prefix while
    // coming from a completely different source history. Its content digest
    // alone is not evidence that the actual parent carried these amounts.
    let mut alternate = Fixture::new(0xb4);
    alternate.transfer(
        day(2026, 1, 5),
        b"parent-expense",
        alternate.usd,
        ("6000", "1000"),
        9_000,
    );
    let substituted = alternate
        .book
        .certify_trial_balance(fa::TrialBalanceSelection::AsOf(through), None)
        .unwrap()
        .unwrap();
    assert_eq!(substituted.certificate.book_id, genuine.certificate.book_id);
    assert_eq!(
        substituted.certificate.known_at,
        genuine.certificate.known_at
    );
    let decoded =
        ReportCertificate::decode(&substituted.certificate.canonical_bytes().unwrap()).unwrap();
    assert!(
        f.parent
            .book
            .replay_parent_trial_balance(&read, &decoded)
            .unwrap()
            .is_err()
    );

    let head = f.parent.book.head().unwrap();
    for denied in [
        Capability::embedded(PRINCIPAL, &["reconcile"]).unwrap(),
        read.clone().for_accounts(&["1000"]).unwrap(),
        read.clone()
            .for_books(&[f.layer.book.context().book_id])
            .unwrap(),
    ] {
        let genuine_denial = f
            .parent
            .book
            .replay_parent_trial_balance(&denied, &genuine.certificate)
            .unwrap()
            .unwrap_err();
        let substitute_denial = f
            .parent
            .book
            .replay_parent_trial_balance(&denied, &decoded)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            genuine_denial, substitute_denial,
            "authority precedes source replay"
        );
    }
    assert_eq!(f.parent.book.head().unwrap(), head);
}

#[test]
fn native_parent_source_keeps_its_actual_civil_cutoff_and_refuses_activity() {
    let f = BridgeFixture::new();
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let reconcile = Capability::embedded(PRINCIPAL, &["read", "reconcile"]).unwrap();
    let later = f
        .parent
        .book
        .certify_trial_balance(
            fa::TrialBalanceSelection::AsOf(day(2026, 2, 28)),
            Some(f.parent_at),
        )
        .unwrap()
        .unwrap();
    let source = f
        .parent
        .book
        .replay_parent_trial_balance(&read, &later.certificate)
        .unwrap()
        .unwrap();
    let refused = f
        .layer
        .book
        .reconcile_book_to_book_from_parent(&reconcile, &source, Some(JANUARY), None, None)
        .unwrap()
        .unwrap_err();
    assert!(refused.message.contains("cutoff"), "{refused}");
    let matching = f
        .layer
        .book
        .reconcile_book_to_book_from_parent(&reconcile, &source, Some(FEBRUARY), None, None)
        .unwrap()
        .unwrap();
    assert_eq!(matching.effective_through, day(2026, 2, 28));
    let activity = f
        .parent
        .book
        .certify_trial_balance(
            fa::TrialBalanceSelection::Activity(vec![JANUARY.into()]),
            Some(f.parent_at),
        )
        .unwrap()
        .unwrap();
    let refused = f
        .parent
        .book
        .replay_parent_trial_balance(&read, &activity.certificate)
        .unwrap()
        .unwrap_err();
    assert!(refused.message.contains("period activity"), "{refused}");
}

fn expense(report: &fa::consolidation::BookToBookReconciliation) -> &BookToBookBridgeRow {
    report
        .bridge
        .rows
        .iter()
        .find(|row| row.account_code == "6000")
        .unwrap()
}

fn pending_total(fixture: &Fixture, at: Option<CommitSeq>) -> (i128, i128) {
    fixture
        .book
        .period_activity(&[JANUARY.into()], at)
        .unwrap()
        .pending_unit_totals
        .get(&fixture.usd.0)
        .copied()
        .unwrap_or_default()
}

#[test]
fn posted_hold_adjustments_reconcile_partial_release_reversal_and_both_time_axes() {
    let mut f = BridgeFixture::new();
    let january = day(2026, 1, 31);
    let february = day(2026, 2, 28);
    let march = day(2026, 3, 31);
    let held = f.reserve(b"partly-consumed-adjustment", 20_000);
    let voidable = f.reserve(b"unused-adjustment", 1_300);
    let held_at = f.layer.book.head().unwrap();
    let reserved = f.reconcile(march, Some(held_at)).unwrap();
    assert_eq!(expense(&reserved).parent_net, 1_000);
    assert_eq!(expense(&reserved).adjustments_net, 0);
    assert!(expense(&reserved).explanations.is_empty());
    assert_eq!(pending_total(&f.layer, Some(held_at)), (21_300, 21_300));

    // Posting 75.00 of a 200.00 hold releases its remaining 125.00. The
    // independently attributed Resolution, not the hold's different tag,
    // is the only posted adjustment.
    let posted = f.partial(held.entry_ref(), true);
    let posted_at = posted.recorded_at();
    let pinned = f.reconcile(february, Some(posted_at)).unwrap();
    let row = expense(&pinned);
    assert_eq!(
        (row.parent_net, row.adjustments_net, row.layered_net),
        (1_000, 7_500, 8_500)
    );
    assert_eq!(row.explanations.len(), 1);
    assert_eq!(row.explanations[0].entry_id, posted.entry_ref().vid.0);
    assert_eq!(row.explanations[0].net_delta, 7_500);
    assert_eq!(
        row.explanations[0].reason_code,
        BookToBookReasonCode::ManagementCostAllocation
    );
    assert_eq!(row.explanations[0].rule_version_oid, RULE);
    assert_eq!(pending_total(&f.layer, Some(posted_at)), (1_300, 1_300));
    assert_eq!(
        expense(&f.reconcile(january, Some(posted_at)).unwrap()).adjustments_net,
        0
    );
    assert_eq!(
        expense(&f.reconcile(march, Some(held_at)).unwrap()).adjustments_net,
        0
    );

    let mut release = f.layer.proposal(
        day(2026, 2, 10),
        b"void-unused-adjustment",
        EntryClass::RESOLUTION,
        Vec::new(),
    );
    release.control = Some(ControlPayload::ReservationRelease);
    release.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: Some(voidable.entry_ref()),
        disposition: Some(Disposition::Voids),
    });
    f.layer.commit(release);
    assert_eq!(pending_total(&f.layer, None), (0, 0));
    assert_eq!(
        expense(&f.reconcile(february, None).unwrap()).adjustments_net,
        7_500
    );

    let (original, _) = f
        .layer
        .book
        .read_entry(posted.entry_ref().vid)
        .unwrap()
        .unwrap();
    let mut reversal = original.proposal;
    reversal.class = EntryClass::REVERSAL;
    reversal.effective_date = day(2026, 3, 1);
    reversal.effective_period = None;
    reversal.idempotency_key = b"reverse-posted-adjustment".to_vec();
    reversal.pending = None;
    reversal.supersession = vec![Supersession {
        target: posted.entry_ref(),
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut reversal.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    reversal.unit_totals = EntryPayload::fold_unit_totals(&reversal.legs).unwrap();
    let reversed = f.layer.commit(reversal);
    let current = f.reconcile(march, None).unwrap();
    let row = expense(&current);
    assert_eq!((row.adjustments_net, row.layered_net), (0, 1_000));
    assert_eq!(row.explanations.len(), 2);
    let undo = row
        .explanations
        .iter()
        .find(|explanation| explanation.entry_id == reversed.entry_ref().vid.0)
        .unwrap();
    assert_eq!(undo.net_delta, -7_500);
    assert_eq!(undo.rule_version_oid, RULE);
    assert_eq!(pending_total(&f.layer, None), (0, 0));
    assert_eq!(
        expense(&f.reconcile(february, None).unwrap()).adjustments_net,
        7_500
    );
    assert_eq!(
        expense(&f.reconcile(january, None).unwrap()).adjustments_net,
        0
    );
    assert_eq!(f.reconcile(february, Some(posted_at)).unwrap(), pinned);
}

#[test]
fn an_untagged_posted_resolution_cannot_borrow_its_holds_explanation() {
    let mut f = BridgeFixture::new();
    let held = f.reserve(b"tagged-hold", 20_000);
    let held_at = held.recorded_at();
    f.partial(held.entry_ref(), false);
    let head = f.layer.book.head().unwrap();
    let refusal = f.reconcile(day(2026, 2, 28), None).unwrap_err();
    assert_eq!(refusal.code, "FA-REF-194");
    assert!(
        refusal
            .message
            .contains("unexplained book-to-book difference"),
        "{refusal:?}"
    );
    assert_eq!(f.layer.book.head().unwrap(), head);
    assert_eq!(
        expense(&f.reconcile(day(2026, 1, 31), None).unwrap()).adjustments_net,
        0
    );
    assert_eq!(
        expense(&f.reconcile(day(2026, 2, 28), Some(held_at)).unwrap()).adjustments_net,
        0
    );
}
