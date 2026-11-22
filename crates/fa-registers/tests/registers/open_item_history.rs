//! Resident open-item folds against the independent canonical payload fold.

use super::*;
use fa_model::{EntryRef, Settlement, entry_vid};
use fa_registers::open_items::history::{OpenItemSnapshot, open_items_as_of};
use fa_registers::open_items::{
    OpenItemMemo, OpenItemReadWork, OpenItemsReport, open_items_as_of_carried, open_items_report,
    open_items_report_carried,
};

fn read(
    h: &Harness,
    memo: &mut OpenItemMemo,
    account: Option<VId>,
    at: Option<CommitSeq>,
) -> Result<OpenItemsReport, RegisterError> {
    open_items_report_carried(&h.db, &h.ctx().query(), &h.book, account, at, memo)
}

fn assert_literal(
    h: &Harness,
    memo: &mut OpenItemMemo,
    account: Option<VId>,
    at: Option<CommitSeq>,
) -> Option<OpenItemsReport> {
    let literal = open_items_report(&h.db, &h.book, account, at);
    let carried = read(h, memo, account, at);
    match (literal, carried) {
        (Ok(literal), Ok(carried)) => {
            assert_eq!(literal, carried);
            assert_eq!(literal.canonical_bytes(), carried.canonical_bytes());
            Some(carried)
        }
        (Err(literal), Err(carried)) => {
            assert_eq!(format!("{literal:?}"), format!("{carried:?}"));
            None
        }
        (literal, carried) => panic!("literal={literal:?}, carried={carried:?}"),
    }
}

fn receipt(h: &Harness, target: EntryRef, amount: i128, key: &[u8]) -> EntryPayload {
    let mut receipt = h.proposal(
        vec![
            LegPayload::simple(Side::Debit, h.cash, Amount::new(h.usd, amount)),
            LegPayload::simple(Side::Credit, h.rent, Amount::new(h.usd, amount)),
        ],
        key,
        EntryClass::ORIGINAL,
    );
    receipt.legs[0].settles.push(Settlement {
        target,
        ordinal: 1,
        amount: Amount::new(h.usd, amount),
    });
    receipt
}

fn assert_carried(work: OpenItemReadWork, entries: usize) {
    assert_eq!(work.snapshot_reads, 0, "{work:?}");
    assert_eq!(work.snapshot_rows, 0, "{work:?}");
    assert_eq!(work.literal_folds, 0, "{work:?}");
    assert_eq!(work.entries_decoded, entries, "{work:?}");
    assert_eq!(work.marker_reads, 1, "the native prefix is authenticated");
}

#[test]
fn resident_open_items_share_exact_folds_and_update_settlement_targets() {
    let mut h = harness();
    let invoice = h.post_rent(100, b"resident-invoice");
    let mut memo = OpenItemMemo::default();
    let original = assert_literal(&h, &mut memo, Some(h.cash), None).unwrap();
    assert_eq!(original.items[0].open, 100);
    assert_eq!(memo.read_work().snapshot_reads, 1);
    assert_eq!(memo.read_work().literal_folds, 1);
    let at_invoice = original.known_at;
    assert_literal(&h, &mut memo, None, None).unwrap();
    assert_carried(memo.read_work(), 0);

    let payment = h.commit(receipt(&h, invoice.entry_ref(), 20, b"resident-payment"));
    let paid = assert_literal(&h, &mut memo, Some(h.cash), None).unwrap();
    let target = paid
        .items
        .iter()
        .find(|item| item.entry == invoice.entry_ref().vid)
        .unwrap();
    assert_eq!(
        (target.original, target.applied, target.open),
        (100, 20, 80)
    );
    let applying = paid
        .items
        .iter()
        .find(|item| item.entry == payment.entry_ref().vid)
        .unwrap();
    assert_eq!((applying.applied_out, applying.open), (20, 0));
    assert_carried(memo.read_work(), 1);
    assert_eq!(memo.read_work().applications_appended, 1);
    assert_eq!(memo.read_work().item_updates, 3);

    h.commit(receipt(&h, invoice.entry_ref(), 30, b"resident-payment-2"));
    let paid_again = assert_literal(&h, &mut memo, Some(h.cash), None).unwrap();
    let target = paid_again
        .items
        .iter()
        .find(|item| item.entry == invoice.entry_ref().vid)
        .unwrap();
    assert_eq!(
        (target.applied, target.open, target.applications.len()),
        (50, 50, 2)
    );
    assert_carried(memo.read_work(), 1);
    let at_paid = paid_again.known_at;

    // Nonforward reads keep the later resident state, including applications.
    assert_eq!(
        assert_literal(&h, &mut memo, Some(h.cash), Some(at_invoice)).unwrap(),
        original
    );
    assert_eq!(memo.known_at(), Some(at_paid));
    assert_eq!(
        assert_literal(&h, &mut memo, Some(h.cash), None).unwrap(),
        paid_again
    );
    assert_carried(memo.read_work(), 0);

    let mut undo = h.proposal(h.expense_legs(20), b"resident-undo", EntryClass::REVERSAL);
    // Reversal legs preserve the original receipt's ordinals, side-swapped.
    undo.legs.swap(0, 1);
    undo.supersession.push(Supersession {
        target: payment.entry_ref(),
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    });
    let undone = h.commit(undo);
    let reopened = assert_literal(&h, &mut memo, Some(h.cash), None).unwrap();
    let target = reopened
        .items
        .iter()
        .find(|item| item.entry == invoice.entry_ref().vid)
        .unwrap();
    assert_eq!((target.applied, target.open), (30, 70));
    assert!(!target.applications[0].live);
    assert_eq!(memo.read_work().snapshot_reads, 1);

    let mut restore = receipt(&h, invoice.entry_ref(), 20, b"resident-restore");
    restore.class = EntryClass::REVERSAL;
    restore.legs[0].settles.clear();
    restore.supersession.push(Supersession {
        target: undone.entry_ref(),
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    });
    h.commit(restore);
    let restored = assert_literal(&h, &mut memo, Some(h.cash), None).unwrap();
    assert_eq!(
        restored
            .items
            .iter()
            .find(|item| item.entry == invoice.entry_ref().vid)
            .unwrap()
            .open,
        50
    );
    assert_eq!(memo.read_work().snapshot_reads, 1);
    assert_literal(&h, &mut memo, Some(h.cash), None).unwrap();
    assert_carried(memo.read_work(), 0);
}

#[test]
fn resident_open_item_native_work_is_bounded_by_the_new_suffix() {
    let mut expected = None;
    for unrelated in [0_u32, 8, 64] {
        let mut h = harness();
        h.post_rent(100, b"account-selection");
        let utilities = account_vid(h.book.book_id, "7000");
        for index in 0..unrelated {
            h.post_expense(utilities, 1, &index.to_le_bytes());
        }
        let mut memo = OpenItemMemo::default();
        let selected = assert_literal(&h, &mut memo, Some(h.rent), None).unwrap();
        assert_eq!(selected.items.len(), 1);
        assert!(memo.read_work().entries_decoded >= usize::try_from(unrelated).unwrap());
        h.post_rent(7, b"one-suffix-entry");
        let result = assert_literal(&h, &mut memo, Some(h.rent), None).unwrap();
        assert_eq!(result.items.len(), 2);
        let work = memo.read_work();
        assert_carried(work, 1);
        assert_eq!((work.item_updates, work.returned_items), (2, 2));
        assert!(work.delta_rows > 0 && work.vertex_reads > 0);
        if let Some(expected) = expected {
            assert_eq!(work, expected, "unrelated postings={unrelated}");
        } else {
            expected = Some(work);
        }
    }
}

#[test]
fn resident_open_items_handle_same_commit_targets_before_vid_order() {
    let mut h = harness();
    let mut memo = OpenItemMemo::default();
    assert_literal(&h, &mut memo, None, None).unwrap();
    let proposal = h.proposal(h.expense_legs(100), b"batch-invoice", EntryClass::ORIGINAL);
    let target = proposal
        .clone()
        .seal(Vec::new(), None)
        .unwrap()
        .entry_ref(entry_vid(
            h.book.book_id,
            &PRINCIPAL.0.to_le_bytes(),
            b"batch-invoice",
        ));
    let mut candidate = None;
    for index in 0..256_u32 {
        let key = format!("batch-receipt-{index}");
        if entry_vid(h.book.book_id, &PRINCIPAL.0.to_le_bytes(), key.as_bytes()) < target.vid {
            candidate = Some(receipt(&h, target, 37, key.as_bytes()));
            break;
        }
    }
    let payment = candidate.expect("a receipt whose vid sorts before its invoice");
    let batch = PostBatch::new(
        b"resident-dependent-batch".to_vec(),
        vec![
            PostIntent::new(proposal, Vec::new()).unwrap(),
            PostIntent::new(payment, Vec::new()).unwrap(),
        ],
    )
    .unwrap();
    let cx = h.ctx();
    h.runtime
        .block_on(post_batch(
            &mut h.db,
            &cx,
            &h.book,
            Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            batch,
        ))
        .unwrap()
        .unwrap();
    let report = assert_literal(&h, &mut memo, Some(h.cash), None).unwrap();
    assert_eq!(
        report
            .items
            .iter()
            .find(|item| item.entry == target.vid)
            .unwrap()
            .open,
        63
    );
    assert_carried(memo.read_work(), 2);
    assert_eq!(memo.read_work().applications_appended, 1);
}

#[test]
fn resident_open_items_authenticate_the_native_prefix_and_ignore_projection_damage() {
    let mut a = harness();
    let mut b = harness();
    a.post_rent(13, b"same-key");
    b.post_rent(29, b"same-key");
    assert_eq!(a.db.frontier().unwrap(), b.db.frontier().unwrap());
    let mut memo = OpenItemMemo::default();
    assert_literal(&a, &mut memo, Some(a.rent), None).unwrap();
    let other = assert_literal(&b, &mut memo, Some(b.rent), None).unwrap();
    assert_eq!(other.items[0].original, 29);
    assert_eq!(memo.read_work().snapshot_reads, 1);
    assert_literal(&a, &mut memo, None, None).unwrap();
    let posted = a.post_rent(7, b"unlinked-post");
    let mut damage = WriteBatch::new(relation::IN_PERIOD);
    let mut removed = 0;
    for edge in a.db.edges().unwrap() {
        if edge.entry.relation == relation::IN_PERIOD && edge.entry.src == posted.entry_ref().vid {
            damage.delete_edge(edge.entry.eid);
            removed += 1;
        }
    }
    assert!(removed > 0);
    a.write_derived(damage);
    let mut applied = WriteBatch::new(relation::IN_BOOK);
    applied.set_vertex_property(
        fa_journal::rows::leg_vid(posted.entry_ref().vid, 0),
        property::APPLIED,
        Some(scalar_bytes(999_i128.to_le_bytes().to_vec())),
    );
    a.write_derived(applied);
    let result = assert_literal(&a, &mut memo, Some(a.rent), None).unwrap();
    assert_eq!(result.items.iter().map(|item| item.open).sum::<i128>(), 20);
    assert_carried(memo.read_work(), 1);
}

#[test]
fn resident_open_item_source_mutations_preserve_literal_errors_and_coordinates() {
    for fault in ["payload", "entry-label", "restored-entry", "account"] {
        let mut h = harness();
        let posted = h.post_rent(13, b"source-to-change");
        let mut memo = OpenItemMemo::default();
        assert_literal(&h, &mut memo, Some(h.rent), None).unwrap();
        let original = h.db.vertex(posted.entry_ref().vid).unwrap().unwrap();
        let mut change = WriteBatch::new(relation::IN_BOOK);
        match fault {
            "entry-label" => change.set_vertex_label(posted.entry_ref().vid, label::ENTRY, false),
            "account" => {
                change.set_vertex_property(h.rent, property::NAME, Some(CanonicalScalar::Int(9)))
            }
            _ => change.set_vertex_property(
                posted.entry_ref().vid,
                property::FA_PAYLOAD,
                Some(scalar_bytes(vec![0xff])),
            ),
        }
        h.write_derived(change);
        if fault == "restored-entry" {
            let mut restore = WriteBatch::new(relation::IN_BOOK);
            restore.set_vertex_property(
                posted.entry_ref().vid,
                property::FA_PAYLOAD,
                fa_journal::rows::prop(&original, property::FA_PAYLOAD).cloned(),
            );
            h.write_derived(restore);
        }
        let previous = memo.known_at();
        let outcome = assert_literal(&h, &mut memo, Some(h.rent), None);
        if fault == "account" {
            assert!(outcome.is_none());
            assert_eq!(
                memo.known_at(),
                previous,
                "invalid selection never touches the memo"
            );
        } else {
            assert_eq!(memo.read_work().snapshot_reads, 1, "{fault}");
        }
    }
}

#[test]
fn resident_open_items_reconstruct_fragmented_entries_and_refuse_changed_fragments() {
    let mut h = harness();
    let mut memo = OpenItemMemo::default();
    assert_literal(&h, &mut memo, None, None).unwrap();
    let mut legs = Vec::new();
    for _ in 0..64 {
        legs.extend(h.expense_legs(1));
    }
    let posted = h.commit(h.proposal(legs, b"fragmented-item-source", EntryClass::ORIGINAL));
    assert_literal(&h, &mut memo, None, None).unwrap();
    assert_carried(memo.read_work(), 1);
    let fragment = h
        .db
        .vertices()
        .unwrap()
        .into_iter()
        .find(|row| {
            row.labels.contains(&label::ENTRY_FRAGMENT) && row.created_at == posted.recorded_at()
        })
        .expect("the entry uses immutable payload fragments");
    let mut change = WriteBatch::new(relation::IN_BOOK);
    change.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(scalar_bytes(vec![0xff])),
    );
    h.write_derived(change);
    assert!(assert_literal(&h, &mut memo, None, None).is_none());
    assert_eq!(memo.read_work().snapshot_reads, 1);
}

#[test]
fn resident_open_item_cancellation_precedes_memo_access() {
    let mut h = harness();
    h.post_rent(100, b"before-cancellation");
    let mut memo = OpenItemMemo::default();
    assert_literal(&h, &mut memo, None, None).unwrap();
    let before = (memo.known_at(), memo.read_work());
    h.root.cancel_fast(asupersync::types::CancelKind::User);
    let error = read(&h, &mut memo, None, None).unwrap_err();
    assert!(matches!(
        error,
        RegisterError::Kernel(KernelError::Txn(fgdb::WriteTxnError::Interrupted(_)))
    ));
    assert_eq!((memo.known_at(), memo.read_work()), before);
    let error = open_items_as_of_carried(
        &h.db,
        &h.ctx().query(),
        &h.book,
        None,
        DateDay::from_ymd(2026, 3, 31).unwrap(),
        None,
        &mut memo,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        RegisterError::Kernel(KernelError::Txn(fgdb::WriteTxnError::Interrupted(_)))
    ));
    assert_eq!((memo.known_at(), memo.read_work()), before);
}

fn assert_literal_as_of(
    h: &Harness,
    memo: &mut OpenItemMemo,
    account: Option<VId>,
    through: DateDay,
    at: Option<CommitSeq>,
) -> Option<OpenItemSnapshot> {
    let literal = open_items_as_of(&h.db, &h.book, account, through, at);
    let carried =
        open_items_as_of_carried(&h.db, &h.ctx().query(), &h.book, account, through, at, memo);
    match (literal, carried) {
        (Ok(literal), Ok(carried)) => {
            assert_eq!(literal, carried);
            Some(carried)
        }
        (Err(literal), Err(carried)) => {
            assert_eq!(format!("{literal:?}"), format!("{carried:?}"));
            None
        }
        (literal, carried) => panic!("literal={literal:?}, carried={carried:?}"),
    }
}

#[test]
fn resident_effective_open_items_preserve_cutoffs_and_historical_applications() {
    let mut h = harness();
    let invoice = h.post_rent(100, b"effective-invoice");
    let at_invoice = h.db.frontier().unwrap();
    h.open_april();
    let march = DateDay::from_ymd(2026, 3, 31).unwrap();
    let april = DateDay::from_ymd(2026, 4, 30).unwrap();
    let mut future = receipt(&h, invoice.entry_ref(), 20, b"future-receipt");
    future.effective_date = DateDay::from_ymd(2026, 4, 5).unwrap();
    h.commit(future);
    let mut memo = OpenItemMemo::default();
    let initial = assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).unwrap();
    assert_eq!(initial.items.len(), 1);
    assert_eq!(initial.items[0].open, 100);
    assert!(initial.items[0].applications.is_empty());
    assert_eq!(memo.effective_through(), Some(march));
    assert_eq!(memo.read_work().snapshot_reads, 1);
    assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).unwrap();
    assert_carried(memo.read_work(), 0);

    let payment = h.commit(receipt(&h, invoice.entry_ref(), 30, b"march-receipt"));
    let paid = assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).unwrap();
    let target = paid
        .items
        .iter()
        .find(|i| i.entry == invoice.entry_ref().vid)
        .unwrap();
    assert_eq!(
        (target.applied, target.open, target.applications.len()),
        (30, 70, 1)
    );
    assert_carried(memo.read_work(), 1);
    assert_eq!(memo.read_work().applications_appended, 1);

    let at_paid = paid.known_at;
    let historical =
        assert_literal_as_of(&h, &mut memo, Some(h.cash), march, Some(at_invoice)).unwrap();
    assert_eq!(historical.items, initial.items);
    assert_eq!(memo.known_at(), Some(at_paid));
    assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).unwrap();
    assert_carried(memo.read_work(), 0);

    // An April undo must not reopen March, even though native applied mirrors
    // have changed and the same source item remains in the resident snapshot.
    let mut undo = h.proposal(h.expense_legs(30), b"april-undo", EntryClass::REVERSAL);
    undo.legs.swap(0, 1);
    undo.effective_date = DateDay::from_ymd(2026, 4, 10).unwrap();
    undo.supersession.push(Supersession {
        target: payment.entry_ref(),
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    });
    h.commit(undo);
    let still_march = assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).unwrap();
    assert_eq!(still_march.items, paid.items);
    assert_carried(memo.read_work(), 1);
    assert_eq!(memo.read_work().item_updates, 0);

    // Changing the effective coordinate or dropping it cannot reuse March's
    // balances. Each selection independently reconstructs its exact lineage.
    let in_april = assert_literal_as_of(&h, &mut memo, Some(h.cash), april, None).unwrap();
    assert_eq!(
        in_april
            .items
            .iter()
            .find(|i| i.entry == invoice.entry_ref().vid)
            .unwrap()
            .open,
        80
    );
    assert_eq!(memo.read_work().snapshot_reads, 1);
    assert_eq!(memo.effective_through(), Some(april));
    assert_literal(&h, &mut memo, Some(h.cash), None).unwrap();
    assert_eq!(memo.read_work().snapshot_reads, 1);
    assert_eq!(memo.effective_through(), None);
    assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).unwrap();
    assert_eq!(memo.read_work().snapshot_reads, 1);
    assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).unwrap();
    assert_carried(memo.read_work(), 0);
}

#[test]
fn resident_effective_open_items_preserve_split_link_refusals_and_account_scope() {
    let mut h = harness();
    h.open_april();
    let march = DateDay::from_ymd(2026, 3, 31).unwrap();
    let mut proposal = h.proposal(h.expense_legs(100), b"april-invoice", EntryClass::ORIGINAL);
    proposal.effective_date = DateDay::from_ymd(2026, 4, 5).unwrap();
    let invoice = h.commit(proposal);
    let mut memo = OpenItemMemo::default();
    let empty = assert_literal_as_of(&h, &mut memo, None, march, None).unwrap();
    assert!(empty.items.is_empty());
    let before = memo.known_at();
    h.commit(receipt(&h, invoice.entry_ref(), 20, b"backdated-receipt"));
    assert!(assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).is_none());
    assert!(matches!(
        open_items_as_of(&h.db, &h.book, Some(h.cash), march, None),
        Err(RegisterError::InvalidSelection(message)) if message.contains("splits a settlement")
    ));
    assert_eq!(
        memo.known_at(),
        before,
        "a refused suffix never installs a prefix"
    );

    // The unrelated rent leg has no settlement. Its historical read succeeds
    // even while a whole-book cutoff would be invalid, and no partial fold
    // may be promoted into a whole-book optimization.
    let other = assert_literal_as_of(&h, &mut memo, Some(h.rent), march, None).unwrap();
    assert_eq!(other.items.len(), 1);
    assert_eq!(other.items[0].open, 20);
    assert_eq!(memo.known_at(), before);
    let unknown = assert_literal_as_of(&h, &mut memo, Some(VId(u128::MAX)), march, None).unwrap();
    assert!(unknown.items.is_empty());
    assert_eq!(memo.known_at(), before);
    let april = DateDay::from_ymd(2026, 4, 30).unwrap();
    assert_literal_as_of(&h, &mut memo, Some(h.cash), april, None).unwrap();
    assert_literal_as_of(&h, &mut memo, Some(h.cash), april, None).unwrap();
    assert_carried(memo.read_work(), 0);
}

#[test]
fn resident_effective_open_items_refuse_applications_stranded_by_reversals() {
    let mut h = harness();
    let invoice = h.post_rent(100, b"stranded-invoice");
    let payment = h.commit(receipt(&h, invoice.entry_ref(), 20, b"stranded-receipt"));
    h.open_april();
    let march = DateDay::from_ymd(2026, 3, 31).unwrap();
    let mut memo = OpenItemMemo::default();
    assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).unwrap();
    let mut undo_payment = h.proposal(h.expense_legs(20), b"receipt-undo", EntryClass::REVERSAL);
    undo_payment.legs.swap(0, 1);
    undo_payment.effective_date = DateDay::from_ymd(2026, 4, 5).unwrap();
    undo_payment.supersession.push(Supersession {
        target: payment.entry_ref(),
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    });
    h.commit(undo_payment);
    assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).unwrap();
    assert_carried(memo.read_work(), 1);
    let before = memo.known_at();

    let mut undo_invoice = h.proposal(h.expense_legs(100), b"invoice-undo", EntryClass::REVERSAL);
    for leg in &mut undo_invoice.legs {
        leg.side = match leg.side {
            Side::Debit => Side::Credit,
            Side::Credit => Side::Debit,
        };
    }
    undo_invoice.unit_totals = EntryPayload::fold_unit_totals(&undo_invoice.legs).unwrap();
    undo_invoice.effective_date = DateDay::from_ymd(2026, 3, 25).unwrap();
    undo_invoice.supersession.push(Supersession {
        target: invoice.entry_ref(),
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    });
    h.commit(undo_invoice);
    assert!(assert_literal_as_of(&h, &mut memo, Some(h.cash), march, None).is_none());
    assert!(matches!(
        open_items_as_of(&h.db, &h.book, Some(h.cash), march, None),
        Err(RegisterError::InvalidSelection(message)) if message.contains("strands a live settlement")
    ));
    assert_eq!(memo.known_at(), before);
}

#[test]
fn resident_effective_open_item_work_depends_on_suffix_not_unrelated_history() {
    let mut expected = None;
    let through = DateDay::from_ymd(2026, 3, 31).unwrap();
    for unrelated in [0_u32, 8, 64] {
        let mut h = harness();
        h.post_rent(100, b"effective-selected-account");
        let utilities = account_vid(h.book.book_id, "7000");
        for index in 0..unrelated {
            h.post_expense(utilities, 1, &index.to_le_bytes());
        }
        let mut memo = OpenItemMemo::default();
        assert_literal_as_of(&h, &mut memo, Some(h.rent), through, None).unwrap();
        h.post_rent(7, b"effective-new-suffix");
        let result = assert_literal_as_of(&h, &mut memo, Some(h.rent), through, None).unwrap();
        assert_eq!(result.items.len(), 2);
        let work = memo.read_work();
        assert_carried(work, 1);
        assert_eq!((work.item_updates, work.returned_items), (2, 2));
        if let Some(expected) = expected {
            assert_eq!(work, expected, "unrelated postings={unrelated}");
        } else {
            expected = Some(work);
        }
    }
}

#[test]
fn resident_effective_open_items_do_not_hide_corruption_after_the_cutoff() {
    let mut h = harness();
    h.open_april();
    let through = DateDay::from_ymd(2026, 3, 31).unwrap();
    let mut future = h.proposal(h.expense_legs(100), b"future-source", EntryClass::ORIGINAL);
    future.effective_date = DateDay::from_ymd(2026, 4, 5).unwrap();
    let posted = h.commit(future);
    let mut memo = OpenItemMemo::default();
    assert!(
        assert_literal_as_of(&h, &mut memo, None, through, None)
            .unwrap()
            .items
            .is_empty()
    );
    let before = memo.known_at();
    let mut damage = WriteBatch::new(relation::IN_BOOK);
    damage.set_vertex_property(
        posted.entry_ref().vid,
        property::FA_PAYLOAD,
        Some(scalar_bytes(vec![0xff])),
    );
    h.write_derived(damage);
    assert!(assert_literal_as_of(&h, &mut memo, None, through, None).is_none());
    assert_eq!(memo.known_at(), before);
    assert_eq!(memo.read_work().snapshot_reads, 1);
}
