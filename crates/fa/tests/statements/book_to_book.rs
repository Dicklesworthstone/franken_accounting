//! Adjustment bridges follow the same posted population as native registers.
use super::*;
use fa::{BookToBookBridgeRow, BookToBookReasonCode};
use fa_model::{ControlPayload, EntryRef, Supersession, SupersessionKind};

const RULE: Oid = Oid([0x42; 32]);

#[test]
fn parent_anchor_activations_leave_historical_statement_certificates_current() {
    let mut f = Fixture::new(0xba);
    f.transfer(
        day(2026, 1, 15),
        b"pre-anchor-statement",
        f.usd,
        ("1000", "4000"),
        1_250,
    );
    let statements = ["balance-sheet", "income-statement"]
        .into_iter()
        .map(|name| {
            f.book
                .certify_statement(selection(name, JANUARY, DECEMBER), None)
                .unwrap()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let schema = Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap();
    for parent_known_at in [CommitSeq(12), CommitSeq(13)] {
        let activation = f
            .book
            .anchor_adjustment_layer(&schema, Id128([0xc5; 16]), parent_known_at)
            .unwrap()
            .unwrap();
        let head = f.book.head().unwrap();
        assert_eq!(activation.recorded_at, head);
        for certified in &statements {
            assert!(certified.certificate.known_at < head);
            assert_eq!(
                f.book
                    .certificate_status(&certified.certificate)
                    .unwrap()
                    .unwrap(),
                CertificateStatus::Current { checked_at: head }
            );
            assert_eq!(replay(&f.book, &certified.certificate), certified.statement);
        }
        assert_eq!(f.book.head().unwrap(), head, "status and replay are reads");
    }
}

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

fn open_bridge_account(
    fixture: &mut Fixture,
    code: &str,
    name: &str,
    account_type: AccountType,
    unit_policy: UnitPolicy,
) {
    let mut spec = account(code, name, account_type);
    spec.unit_policy = unit_policy;
    fixture
        .book
        .open_account(
            &spec,
            day(2025, 12, 1),
            None,
            PRINCIPAL,
            day(2025, 12, 1),
            code.as_bytes(),
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
}

fn replayed_parent(
    parent: &Fixture,
    known_at: Option<CommitSeq>,
) -> fa::consolidation::ReplayedParentTrialBalance {
    let certified = parent
        .book
        .certify_trial_balance(fa::TrialBalanceSelection::AsOf(day(2026, 1, 31)), known_at)
        .unwrap()
        .unwrap();
    parent
        .book
        .replay_parent_trial_balance(
            &Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
            &certified.certificate,
        )
        .unwrap()
        .unwrap()
}

fn anchor_replayed_parent(
    layer: &mut Fixture,
    parent: &fa::consolidation::ReplayedParentTrialBalance,
) -> CommitSeq {
    layer
        .book
        .anchor_adjustment_layer(
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
            parent.book_id(),
            parent.known_at(),
        )
        .unwrap()
        .unwrap()
        .recorded_at
}

fn reconcile_replayed_parent(
    layer: &Fixture,
    parent: &fa::consolidation::ReplayedParentTrialBalance,
    known_at: Option<CommitSeq>,
) -> Result<fa::consolidation::BookToBookReconciliation, fa_journal::Refusal> {
    layer
        .book
        .reconcile_book_to_book_from_parent(
            &Capability::embedded(PRINCIPAL, &["read", "reconcile"]).unwrap(),
            parent,
            None,
            Some(day(2026, 1, 31)),
            known_at,
        )
        .unwrap()
}

fn native_stock_certificate(fixture: &Fixture, at: Option<CommitSeq>) -> ReportCertificate {
    fixture
        .book
        .certify_trial_balance(fa::TrialBalanceSelection::AsOf(day(2026, 1, 31)), at)
        .unwrap()
        .unwrap()
        .certificate
}

fn composed_parent(
    layer: &Fixture,
    parent: &fa::consolidation::ReplayedParentTrialBalance,
    certificate: &ReportCertificate,
) -> Result<fa::consolidation::ReplayedParentTrialBalance, fa_journal::Refusal> {
    layer
        .book
        .replay_layered_parent_trial_balance(
            &Capability::embedded(PRINCIPAL, &["read", "reconcile"]).unwrap(),
            certificate,
            parent,
        )
        .unwrap()
}

fn tagged_adjustment(fixture: &mut Fixture, key: &[u8], accounts: (&str, &str), amount: i128) {
    let mut proposal = fixture.proposal(
        day(2026, 1, 15),
        key,
        EntryClass::ORIGINAL,
        fixture.legs(fixture.usd, accounts, amount),
    );
    fixture
        .book
        .attach_book_to_book_tag(
            &mut proposal,
            BookToBookReasonCode::M1TemporaryDepreciation,
            RULE,
        )
        .unwrap();
    fixture.commit(proposal);
}

fn composed_columns(
    source: &fa::consolidation::ReplayedParentTrialBalance,
    code: &str,
) -> [i128; 4] {
    let row = source
        .trial_balance()
        .rows
        .iter()
        .find(|row| row.code == code)
        .unwrap();
    [
        row.debits,
        row.credits,
        row.debits_pending,
        row.credits_pending,
    ]
}

#[test]
fn native_parent_chain_preserves_gross_posted_and_pending_stock() {
    let mut f = BridgeFixture::new();
    f.parent.transfer(
        day(2026, 1, 6),
        b"parent-offsetting-expense",
        f.parent.usd,
        ("1000", "6000"),
        400,
    );
    let mut hold = f.parent.proposal(
        day(2026, 1, 7),
        b"ancestor-reservation",
        EntryClass::PENDING,
        f.parent.legs(f.parent.usd, ("6100", "1000"), 900),
    );
    hold.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    f.parent.commit(hold);
    let primary = replayed_parent(&f.parent, None);
    anchor_replayed_parent(&mut f.layer, &primary);
    tagged_adjustment(&mut f.layer, b"layer-expense", ("6000", "1000"), 100);
    f.reserve(b"layer-reservation", 200);
    let layer_certificate = native_stock_certificate(&f.layer, None);
    let layered = composed_parent(&f.layer, &primary, &layer_certificate).unwrap();
    assert_eq!(composed_columns(&layered, "6000"), [1_100, 400, 200, 0]);
    assert_eq!(composed_columns(&layered, "6100"), [0, 0, 900, 0]);

    let mut child = Fixture::new(0xd4);
    anchor_replayed_parent(&mut child, &layered);
    tagged_adjustment(&mut child, b"child-expense-release", ("1000", "6000"), 25);
    let child_certificate = native_stock_certificate(&child, None);
    let heads = (
        f.parent.book.head().unwrap(),
        f.layer.book.head().unwrap(),
        child.book.head().unwrap(),
    );
    let complete = composed_parent(&child, &layered, &child_certificate).unwrap();
    assert_eq!(composed_columns(&complete, "6000"), [1_100, 425, 200, 0]);
    assert_eq!(composed_columns(&complete, "1000"), [425, 1_100, 0, 1_100]);
    assert_eq!(composed_columns(&complete, "6100"), [0, 0, 900, 0]);
    assert_eq!(
        complete.trial_balance().unit_totals[&child.usd.0],
        (1_525, 1_525)
    );
    assert_eq!(
        complete.trial_balance().pending_unit_totals[&child.usd.0],
        (1_100, 1_100)
    );
    assert_eq!(
        complete.ancestry(),
        &[
            (primary.book_id(), primary.known_at()),
            (layered.book_id(), layered.known_at()),
            (child.book.context().book_id, child_certificate.known_at),
        ]
    );
    let again = composed_parent(&child, &layered, &child_certificate).unwrap();
    assert_eq!(again.trial_balance(), complete.trial_balance());
    assert_eq!(again.source_digest(), complete.source_digest());
    let bridge = reconcile_replayed_parent(&child, &layered, None).unwrap();
    assert_eq!(
        (
            expense(&bridge).parent_net,
            expense(&bridge).adjustments_net,
            expense(&bridge).layered_net,
        ),
        (700, -25, 675),
        "pending holds remain separate from the posted bridge"
    );
    assert_eq!(
        (
            f.parent.book.head().unwrap(),
            f.layer.book.head().unwrap(),
            child.book.head().unwrap(),
        ),
        heads,
        "composition and reconciliation never publish"
    );
}

#[test]
fn native_parent_chain_binds_ancestor_history_even_when_stock_matches() {
    let f = BridgeFixture::new();
    let first_parent = replayed_parent(&f.parent, None);
    let mut alternate = Fixture::new(0xb4);
    alternate.transfer(
        day(2026, 1, 5),
        b"different-parent-source",
        alternate.usd,
        ("6000", "1000"),
        1_000,
    );
    let other_parent = replayed_parent(&alternate, None);
    assert_eq!(first_parent.book_id(), other_parent.book_id());
    assert_eq!(first_parent.known_at(), other_parent.known_at());
    assert_eq!(first_parent.trial_balance(), other_parent.trial_balance());
    assert_ne!(first_parent.source_digest(), other_parent.source_digest());
    let certificate = native_stock_certificate(&f.layer, None);
    let first = composed_parent(&f.layer, &first_parent, &certificate).unwrap();
    let other = composed_parent(&f.layer, &other_parent, &certificate).unwrap();
    assert_eq!(first.trial_balance(), other.trial_balance());
    assert_eq!(first.ancestry(), other.ancestry());
    assert_ne!(
        first.source_digest(),
        other.source_digest(),
        "equal boundary coordinates and rows cannot erase ancestor history identity"
    );
}

#[test]
fn native_parent_chain_replays_historical_anchors_and_refuses_stale_parents() {
    let mut f = BridgeFixture::new();
    tagged_adjustment(
        &mut f.layer,
        b"historical-layer-expense",
        ("6000", "1000"),
        100,
    );
    let parent_before = replayed_parent(&f.parent, None);
    let certificate_before = native_stock_certificate(&f.layer, None);
    let before = composed_parent(&f.layer, &parent_before, &certificate_before).unwrap();
    assert_eq!(composed_columns(&before, "6000"), [1_100, 0, 0, 0]);

    f.parent.transfer(
        day(2026, 1, 6),
        b"parent-restatement",
        f.parent.usd,
        ("6000", "1000"),
        250,
    );
    let parent_after = replayed_parent(&f.parent, None);
    assert!(composed_parent(&f.layer, &parent_after, &certificate_before).is_err());
    anchor_replayed_parent(&mut f.layer, &parent_after);
    let certificate_after = native_stock_certificate(&f.layer, None);
    assert!(composed_parent(&f.layer, &parent_before, &certificate_after).is_err());
    let after = composed_parent(&f.layer, &parent_after, &certificate_after).unwrap();
    assert_eq!(composed_columns(&after, "6000"), [1_350, 0, 0, 0]);
    let old_again = composed_parent(&f.layer, &parent_before, &certificate_before).unwrap();
    assert_eq!(old_again.source_digest(), before.source_digest());
    assert_eq!(old_again.trial_balance(), before.trial_balance());
    let unrelated = Fixture::new(0xd5);
    let unrelated = replayed_parent(&unrelated, None);
    assert!(composed_parent(&f.layer, &unrelated, &certificate_after).is_err());
    assert_eq!(f.layer.book.head().unwrap(), certificate_after.known_at);
}

#[test]
fn native_parent_chain_validates_pending_only_inherited_account_semantics() {
    let mut parent = Fixture::new(0xd6);
    open_bridge_account(
        &mut parent,
        "7000",
        "Reserved prepaid asset",
        AccountType::ASSET,
        UnitPolicy::AnyCurrency,
    );
    let mut reservation = parent.proposal(
        day(2026, 1, 5),
        b"pending-only-parent",
        EntryClass::PENDING,
        parent.legs(parent.usd, ("7000", "1000"), 900),
    );
    reservation.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    parent.commit(reservation);
    let source = replayed_parent(&parent, None);
    for (seed, account_type, policy, expected) in [
        (0xd7, None, UnitPolicy::AnyCurrency, "absent"),
        (
            0xd8,
            Some(AccountType::REVENUE),
            UnitPolicy::AnyCurrency,
            "type",
        ),
        (
            0xd9,
            Some(AccountType::ASSET),
            UnitPolicy::Single(parent.jpy),
            "unit policy",
        ),
        (0xda, Some(AccountType::ASSET), UnitPolicy::AnyCurrency, ""),
    ] {
        let mut layer = Fixture::new(seed);
        if let Some(account_type) = account_type {
            open_bridge_account(&mut layer, "7000", "Layer asset", account_type, policy);
        }
        anchor_replayed_parent(&mut layer, &source);
        let certificate = native_stock_certificate(&layer, None);
        let result = composed_parent(&layer, &source, &certificate);
        if expected.is_empty() {
            let complete = result.unwrap();
            assert_eq!(composed_columns(&complete, "7000"), [0, 0, 900, 0]);
        } else {
            let refused = result.unwrap_err();
            assert!(refused.message.contains(expected), "{refused}");
        }
        assert_eq!(layer.book.head().unwrap(), certificate.known_at);
    }
}

#[test]
fn native_parent_chain_checks_authority_before_replay_and_rejects_cycles() {
    let mut f = BridgeFixture::new();
    let parent = replayed_parent(&f.parent, None);
    let certificate = native_stock_certificate(&f.layer, None);
    let mut malformed = certificate.clone();
    malformed.digest[0] ^= 1;
    let admitted = Capability::embedded(PRINCIPAL, &["read", "reconcile"]).unwrap();
    for denied in [
        Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
        Capability::embedded(PRINCIPAL, &["reconcile"]).unwrap(),
        admitted.clone().for_accounts(&["6000"]).unwrap(),
        admitted.clone().for_books(&[parent.book_id()]).unwrap(),
    ] {
        let original = f
            .layer
            .book
            .replay_layered_parent_trial_balance(&denied, &certificate, &parent)
            .unwrap()
            .unwrap_err();
        let corrupt = f
            .layer
            .book
            .replay_layered_parent_trial_balance(&denied, &malformed, &parent)
            .unwrap()
            .unwrap_err();
        assert_eq!(original, corrupt, "admission precedes source observation");
    }
    assert!(composed_parent(&f.layer, &parent, &malformed).is_err());
    let layered = composed_parent(&f.layer, &parent, &certificate).unwrap();
    anchor_replayed_parent(&mut f.parent, &layered);
    let cyclic = native_stock_certificate(&f.parent, None);
    let refusal = composed_parent(&f.parent, &layered, &cyclic).unwrap_err();
    assert!(
        refusal.message.contains("cannot repeat a book"),
        "{refusal}"
    );
    let refusal = reconcile_replayed_parent(&f.parent, &layered, None).unwrap_err();
    assert!(
        refusal.message.contains("cannot repeat a book"),
        "{refusal}"
    );
    assert_eq!(f.parent.book.head().unwrap(), cyclic.known_at);
    assert_eq!(f.layer.book.head().unwrap(), certificate.known_at);
}

#[test]
fn native_parent_bridge_refuses_same_code_with_a_different_account_type() {
    let mut parent = Fixture::new(0xc6);
    open_bridge_account(
        &mut parent,
        "7000",
        "Parent prepaid asset",
        AccountType::ASSET,
        UnitPolicy::AnyCurrency,
    );
    parent.transfer(
        day(2026, 1, 5),
        b"parent-prepaid",
        parent.usd,
        ("7000", "1000"),
        5_000,
    );
    let parent = replayed_parent(&parent, None);
    let mut layer = Fixture::new(0xc7);
    open_bridge_account(
        &mut layer,
        "7000",
        "Unrelated revenue",
        AccountType::REVENUE,
        UnitPolicy::AnyCurrency,
    );
    anchor_replayed_parent(&mut layer, &parent);
    let head = layer.book.head().unwrap();
    let refusal = reconcile_replayed_parent(&layer, &parent, None).unwrap_err();
    assert!(refusal.message.contains("7000"), "{refusal}");
    assert!(refusal.message.contains("Asset"), "{refusal}");
    assert!(refusal.message.contains("Revenue"), "{refusal}");
    assert_eq!(
        layer.book.head().unwrap(),
        head,
        "a refusal publishes nothing"
    );
}

#[test]
fn native_parent_bridge_respects_account_units_without_requiring_identical_charts() {
    // JPY is foreign to these USD-functional books. BTC is a quantity unit
    // carried by balanced memo accounts, so AnyCurrency must not admit it.
    for (seed, code, kind, is_currency) in [
        (0xc8, "JPY", AccountType::ASSET, true),
        (0xcd, "BTC", AccountType::MEMO, false),
    ] {
        let mut parent = Fixture::new(seed);
        let unit = parent.book.context().units.lookup(code).unwrap();
        for account_code in ["7000", "7001"] {
            open_bridge_account(
                &mut parent,
                account_code,
                "Parent account name",
                kind,
                UnitPolicy::Single(unit),
            );
        }
        open_bridge_account(
            &mut parent,
            "7100",
            "Unused parent asset",
            AccountType::ASSET,
            UnitPolicy::AnyCurrency,
        );
        parent.transfer(
            day(2026, 1, 5),
            b"inherited-native-unit",
            unit,
            ("7000", "7001"),
            5_000,
        );
        let parent_at = parent.book.head().unwrap();
        parent.transfer(
            day(2026, 1, 6),
            b"later-parent-balance",
            unit,
            ("7000", "7001"),
            250,
        );
        let parent_head = parent.book.head().unwrap();
        let source = replayed_parent(&parent, Some(parent_at));
        assert!(source.known_at() < parent_head);
        for (i, (policy, accepted)) in [
            (UnitPolicy::Single(parent.usd), false),
            (UnitPolicy::Single(unit), true),
            (UnitPolicy::AnyCurrency, is_currency),
            (UnitPolicy::AnyUnit, true),
        ]
        .into_iter()
        .enumerate()
        {
            let mut layer = Fixture::new(seed + 1 + u8::try_from(i).unwrap());
            for account_code in ["7000", "7001"] {
                open_bridge_account(
                    &mut layer,
                    account_code,
                    "Different layer account name",
                    kind,
                    policy,
                );
            }
            // Compatibility is required for inherited balances, not unrelated
            // unused declarations or an exact byte-for-byte chart identity.
            let layer_usd = layer.usd;
            open_bridge_account(
                &mut layer,
                "7100",
                "Unused layer revenue",
                AccountType::REVENUE,
                UnitPolicy::Single(layer_usd),
            );
            let layer_at = anchor_replayed_parent(&mut layer, &source);
            let result = reconcile_replayed_parent(&layer, &source, None);
            if accepted {
                let result = result.unwrap();
                let row = result
                    .bridge
                    .rows
                    .iter()
                    .find(|row| row.account_code == "7000")
                    .unwrap();
                assert_eq!(row.unit_id, unit.0);
                assert_eq!(
                    (row.parent_net, row.adjustments_net, row.layered_net),
                    (5_000, 0, 5_000)
                );
                assert!(row.explanations.is_empty());
                assert_eq!(result.bridge.parent_known_at, parent_at.0);
            } else {
                let refusal = result.unwrap_err();
                assert!(refusal.message.contains("unit policy"), "{refusal}");
                assert!(refusal.message.contains(code), "{refusal}");
            }
            assert_eq!(layer.book.head().unwrap(), layer_at);
            assert_eq!(parent.book.head().unwrap(), parent_head);
        }
    }
}

#[test]
fn native_parent_bridge_reads_the_selected_historical_layer_chart() {
    let mut f = BridgeFixture::new();
    let source = replayed_parent(&f.parent, Some(f.parent_at));
    let layer_at = f.layer.book.head().unwrap();
    let original = reconcile_replayed_parent(&f.layer, &source, Some(layer_at)).unwrap();
    // This account has only inherited balances, so its own native chart may
    // be promoted. A current bridge still cannot put those balances on a
    // summary, and a historical bridge must retain the earlier posting leaf.
    f.layer
        .book
        .promote_to_summary(
            "6000",
            day(2026, 1, 31),
            PRINCIPAL,
            day(2026, 1, 31),
            b"promote-layer-expense",
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        )
        .unwrap()
        .unwrap();
    let head = f.layer.book.head().unwrap();
    let refused = reconcile_replayed_parent(&f.layer, &source, None).unwrap_err();
    assert!(refused.message.contains("summary account"), "{refused}");
    assert_eq!(
        reconcile_replayed_parent(&f.layer, &source, Some(layer_at)).unwrap(),
        original
    );
    assert_eq!(f.layer.book.head().unwrap(), head);
}

#[test]
fn native_parent_replay_refuses_nested_layers_instead_of_omitting_inherited_stock() {
    let mut f = BridgeFixture::new();
    let mut adjustment = f.layer.proposal(
        day(2026, 1, 15),
        b"nested-parent-adjustment",
        EntryClass::ORIGINAL,
        f.layer.legs(f.layer.usd, ("6000", "1000"), 100),
    );
    f.layer
        .book
        .attach_book_to_book_tag(
            &mut adjustment,
            BookToBookReasonCode::M1TemporaryDepreciation,
            RULE,
        )
        .unwrap();
    f.layer.commit(adjustment);
    let primary = replayed_parent(&f.parent, Some(f.parent_at));
    let bridge = reconcile_replayed_parent(&f.layer, &primary, None).unwrap();
    assert_eq!(
        (
            expense(&bridge).parent_net,
            expense(&bridge).adjustments_net,
            expense(&bridge).layered_net,
        ),
        (1_000, 100, 1_100)
    );
    let own_only = f
        .layer
        .book
        .certify_trial_balance(fa::TrialBalanceSelection::AsOf(day(2026, 1, 31)), None)
        .unwrap()
        .unwrap();
    let expense = own_only
        .report
        .rows
        .iter()
        .find(|row| row.code == "6000")
        .unwrap();
    assert_eq!((expense.debits, expense.credits), (100, 0));
    let heads = (f.parent.book.head().unwrap(), f.layer.book.head().unwrap());
    let refused = f
        .layer
        .book
        .replay_parent_trial_balance(
            &Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
            &own_only.certificate,
        )
        .unwrap()
        .unwrap_err();
    assert!(
        refused.message.contains("adjustment-layer parent"),
        "{refused}"
    );
    assert!(
        refused.message.contains("inherited parent balances"),
        "{refused}"
    );
    assert_eq!(
        (f.parent.book.head().unwrap(), f.layer.book.head().unwrap()),
        heads
    );
}

#[test]
fn native_parent_replay_checks_historical_book_kind_after_current_read_admission() {
    let ancestor = Fixture::new(0xd2);
    let ancestor = replayed_parent(&ancestor, None);
    let mut parent = Fixture::new(0xd3);
    parent.transfer(
        day(2026, 1, 5),
        b"before-layer-activation",
        parent.usd,
        ("6000", "1000"),
        500,
    );
    let before = parent
        .book
        .certify_trial_balance(fa::TrialBalanceSelection::AsOf(day(2026, 1, 31)), None)
        .unwrap()
        .unwrap();
    let activation = anchor_replayed_parent(&mut parent, &ancestor);
    let after = parent
        .book
        .certify_trial_balance(
            fa::TrialBalanceSelection::AsOf(day(2026, 1, 31)),
            Some(activation),
        )
        .unwrap()
        .unwrap();
    let read = Capability::embedded(PRINCIPAL, &["read"]).unwrap();
    let historical = parent
        .book
        .replay_parent_trial_balance(&read, &before.certificate)
        .unwrap()
        .unwrap();
    assert_eq!(historical.known_at(), before.certificate.known_at);
    assert!(historical.known_at() < activation);
    assert!(
        parent
            .book
            .replay_parent_trial_balance(&read, &after.certificate)
            .unwrap()
            .unwrap_err()
            .message
            .contains("adjustment-layer parent")
    );
    for denied in [
        Capability::embedded(PRINCIPAL, &["reconcile"]).unwrap(),
        read.clone().for_accounts(&["6000"]).unwrap(),
        read.for_books(&[ancestor.book_id()]).unwrap(),
    ] {
        let before_denial = parent
            .book
            .replay_parent_trial_balance(&denied, &before.certificate)
            .unwrap()
            .unwrap_err();
        let after_denial = parent
            .book
            .replay_parent_trial_balance(&denied, &after.certificate)
            .unwrap()
            .unwrap_err();
        assert_eq!(
            before_denial, after_denial,
            "authority precedes book-kind observation"
        );
    }
    assert_eq!(parent.book.head().unwrap(), activation);
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
