//! Adjustment bridges follow the same posted population as native registers.
use super::*;
use fa::{BookToBookBridgeRow, BookToBookReasonCode};
use fa_model::{ControlPayload, EntryRef, Supersession, SupersessionKind};

const RULE: Oid = Oid([0x42; 32]);

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
        refusal.message.contains("unexplained book-to-book difference"),
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
