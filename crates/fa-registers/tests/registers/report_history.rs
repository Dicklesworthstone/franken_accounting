//! Carried source metadata must preserve the literal report and its failures.

use super::*;
use fa_registers::{ReportHistoryMemo, ReportHistoryWork, Served, TrialBalance};

fn advance_march(h: &mut Harness) {
    let cx = h.ctx();
    h.runtime
        .block_on(fa_registers::advance(&mut h.db, &cx, &h.book, &h.march))
        .unwrap();
}

fn read(
    h: &Harness,
    memo: &mut ReportHistoryMemo,
    periods: &[String],
    at: Option<CommitSeq>,
    activity: bool,
) -> Result<(TrialBalance, Served), RegisterError> {
    let cx = h.ctx();
    if activity {
        fa_registers::period_activity_served_at_carried(
            &h.db,
            &cx.query(),
            &h.book,
            periods,
            at,
            memo,
        )
    } else {
        fa_registers::trial_balance_served_at_carried(
            &h.db,
            &cx.query(),
            &h.book,
            periods,
            at,
            memo,
        )
    }
}

fn assert_literal(
    h: &Harness,
    memo: &mut ReportHistoryMemo,
    periods: &[String],
    at: Option<CommitSeq>,
    activity: bool,
) -> Option<(TrialBalance, Served)> {
    let cx = h.ctx();
    let literal = if activity {
        fa_registers::period_activity_served_at_with_context(
            &h.db,
            &cx.query(),
            &h.book,
            periods,
            at,
        )
    } else {
        fa_registers::trial_balance_served_at_with_context(&h.db, &cx.query(), &h.book, periods, at)
    };
    let carried = read(h, memo, periods, at, activity);
    match (literal, carried) {
        (Ok(literal), Ok(carried)) => {
            assert_eq!(literal, carried);
            let independent = if activity {
                period_activity(&h.db, &h.book, periods, at)
            } else {
                trial_balance_at(&h.db, &h.book, periods, at)
            }
            .unwrap();
            assert_eq!(carried.0, independent);
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
fn resident_tb_and_activity_share_exact_source_reads() {
    let mut h = harness();
    h.post_rent(123, b"resident-source");
    advance_march(&mut h);
    let periods = vec![h.march.clone()];
    let head = h.db.frontier().unwrap();
    let rows = h.db.vertices().unwrap();
    let mut memo = ReportHistoryMemo::default();
    let first = assert_literal(&h, &mut memo, &periods, None, false).unwrap();
    assert!(matches!(first.1, Served::Maintained(_)), "{first:?}");
    assert_eq!(memo.read_work().metadata_scans, 1);
    assert_eq!(memo.read_work().population_scans, 1);
    assert!(memo.read_work().entries_decoded > 0);
    for activity in [true, false, true] {
        assert_literal(&h, &mut memo, &periods, None, activity).unwrap();
        assert_eq!(memo.read_work(), ReportHistoryWork::default());
    }
    assert_eq!(memo.known_at(), Some(head));
    assert_eq!(h.db.frontier().unwrap(), head);
    assert_eq!(h.db.vertices().unwrap(), rows);
}

#[test]
fn resident_report_source_work_is_bounded_by_the_suffix_not_unrelated_history() {
    let mut expected = None;
    for unrelated in [0_u32, 256, 4_096] {
        let mut h = harness();
        h.post_rent(100, b"initial-rent");
        advance_march(&mut h);
        if unrelated != 0 {
            let mut batch = WriteBatch::new(relation::IN_BOOK);
            for index in 0..unrelated {
                batch.create_vertex(VId(1_000_000 + u128::from(index)), Vec::new(), Vec::new());
            }
            h.write_derived(batch);
        }
        let periods = vec![h.march.clone()];
        let mut memo = ReportHistoryMemo::default();
        assert_literal(&h, &mut memo, &periods, None, false).unwrap();
        let cold = memo.read_work();
        assert_eq!(cold.metadata_scans, 1);
        assert_eq!(cold.population_scans, 1);
        assert!(cold.snapshot_rows >= usize::try_from(unrelated).unwrap());
        h.post_rent(7, b"one-suffix-post");
        assert_literal(&h, &mut memo, &periods, None, false).unwrap();
        let work = memo.read_work();
        assert_eq!(
            (
                work.metadata_scans,
                work.population_scans,
                work.snapshot_rows
            ),
            (0, 0, 0)
        );
        assert_eq!(work.entries_decoded, 1);
        assert!(work.delta_rows > 0 && work.vertex_reads > 0);
        if let Some(expected) = expected {
            assert_eq!(work, expected, "unrelated vertices={unrelated}");
        } else {
            expected = Some(work);
        }
        assert_literal(&h, &mut memo, &periods, None, false).unwrap();
        assert_eq!(memo.read_work(), ReportHistoryWork::default());
    }
}

#[test]
fn resident_population_sees_new_postings_without_trusting_period_membership() {
    let mut h = harness();
    let april = h.open_april();
    h.post_rent(50, b"march-before-april");
    advance_march(&mut h);
    let mut memo = ReportHistoryMemo::default();
    assert_literal(&h, &mut memo, &[h.march.clone()], None, false).unwrap();
    let mut proposal = h.proposal(
        h.expense_legs(77),
        b"april-new-source",
        EntryClass::ORIGINAL,
    );
    proposal.effective_date = DateDay::from_ymd(2026, 4, 15).unwrap();
    let posted = h.commit(proposal);
    let mut remove = WriteBatch::new(relation::IN_PERIOD);
    let mut removed = 0;
    for edge in h.db.edges().unwrap() {
        if edge.entry.relation == relation::IN_PERIOD && edge.entry.src == posted.entry_ref().vid {
            remove.delete_edge(edge.entry.eid);
            removed += 1;
        }
    }
    assert!(
        removed > 0,
        "the posting has a derived period edge to remove"
    );
    h.write_derived(remove);
    let (report, served) = assert_literal(&h, &mut memo, &[april], None, true).unwrap();
    assert!(matches!(served, Served::Literal(_)));
    assert_eq!(report.unit_totals.get(&h.usd.0), Some(&(77, 77)));
    assert_eq!(memo.read_work().metadata_scans, 0);
    assert_eq!(memo.read_work().population_scans, 0);
    assert_eq!(memo.read_work().entries_decoded, 1);
}

#[test]
fn resident_report_history_checks_prefix_identity_and_preserves_older_coordinates() {
    let mut a = harness();
    let mut b = harness();
    a.post_rent(13, b"same-identity");
    b.post_rent(29, b"same-identity");
    advance_march(&mut a);
    advance_march(&mut b);
    let mut memo = ReportHistoryMemo::default();
    let periods = vec![a.march.clone()];
    let older = a.db.frontier().unwrap();
    assert_literal(&a, &mut memo, &periods, None, false).unwrap();
    assert_eq!(older, b.db.frontier().unwrap());
    let (other, _) = assert_literal(&b, &mut memo, &periods, None, false).unwrap();
    assert_eq!(other.unit_totals.get(&b.usd.0), Some(&(29, 29)));
    assert_eq!(memo.read_work().metadata_scans, 1);
    assert_literal(&a, &mut memo, &periods, None, false).unwrap();
    assert_eq!(memo.read_work().metadata_scans, 1);
    a.post_rent(3, b"later-source");
    assert_literal(&a, &mut memo, &periods, None, false).unwrap();
    let newer = a.db.frontier().unwrap();
    assert_eq!(memo.known_at(), Some(newer));
    let (historical, _) = assert_literal(&a, &mut memo, &periods, Some(older), false).unwrap();
    assert_eq!(historical.unit_totals.get(&a.usd.0), Some(&(13, 13)));
    assert_eq!(memo.known_at(), Some(newer));
    assert_literal(&a, &mut memo, &periods, Some(newer), false).unwrap();
    assert_eq!(memo.read_work(), ReportHistoryWork::default());
}

#[test]
fn resident_source_edits_and_corruption_keep_the_literal_verdict() {
    for fault in [
        "account",
        "period",
        "entry",
        "entry-label",
        "restored-entry",
    ] {
        let mut h = harness();
        let posted = h.post_rent(13, b"source-to-change");
        advance_march(&mut h);
        let periods = vec![h.march.clone()];
        let mut memo = ReportHistoryMemo::default();
        assert_literal(&h, &mut memo, &periods, None, false).unwrap();
        let original = h.db.vertex(posted.entry_ref().vid).unwrap().unwrap();
        let mut change = WriteBatch::new(relation::IN_BOOK);
        match fault {
            "account" => {
                change.set_vertex_property(h.rent, property::NAME, Some(CanonicalScalar::Int(9)));
            }
            "period" => {
                change.set_vertex_property(
                    period_vid(&h.book.calendar.id, "FY2026-P01"),
                    property::CALENDAR_ID,
                    None,
                );
            }
            "entry-label" => {
                change.set_vertex_label(posted.entry_ref().vid, label::ENTRY, false);
            }
            _ => {
                change.set_vertex_property(
                    posted.entry_ref().vid,
                    property::FA_PAYLOAD,
                    Some(scalar_bytes(vec![0xff])),
                );
            }
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
        assert_literal(&h, &mut memo, &periods, None, false);
        assert_eq!(memo.read_work().metadata_scans, 1, "{fault}");
    }
}

#[test]
fn resident_population_does_not_hide_changed_entry_fragments() {
    let mut h = harness();
    let mut legs = Vec::new();
    for _ in 0..64 {
        legs.extend(h.expense_legs(1));
    }
    let posted = h.commit(h.proposal(legs, b"fragmented-source", EntryClass::ORIGINAL));
    let mut memo = ReportHistoryMemo::default();
    let periods = vec![h.march.clone()];
    assert_literal(&h, &mut memo, &periods, None, false).unwrap();
    let fragment = h
        .db
        .vertices()
        .unwrap()
        .into_iter()
        .find(|row| {
            row.labels.contains(&label::ENTRY_FRAGMENT) && row.created_at == posted.recorded_at()
        })
        .expect("the large canonical entry has immutable fragments");
    let mut change = WriteBatch::new(relation::IN_BOOK);
    change.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(scalar_bytes(vec![0xff])),
    );
    h.write_derived(change);
    assert!(assert_literal(&h, &mut memo, &periods, None, false).is_none());
    assert_eq!(memo.read_work().metadata_scans, 1);
}

#[test]
fn resident_metadata_includes_new_accounts_and_preserves_source_without_book_edges() {
    let mut h = harness();
    h.post_rent(10, b"before-new-account");
    advance_march(&mut h);
    let mut memo = ReportHistoryMemo::default();
    let periods = vec![h.march.clone()];
    assert_literal(&h, &mut memo, &periods, None, false).unwrap();
    let spec = AccountSpec {
        code: "8000".into(),
        name: "New expense".into(),
        account_type: AccountType::EXPENSE.0,
        normal_balance: 0,
        is_leaf: true,
        unit_policy: UnitPolicy::Single(h.usd),
        parent_code: None,
        limit: None,
    };
    let cx = h.ctx();
    let day = DateDay::from_ymd(2026, 3, 15).unwrap();
    h.runtime
        .block_on(open_account(
            &mut h.db,
            &cx,
            &h.book,
            &spec,
            day,
            None,
            PRINCIPAL,
            day,
            b"new-report-account",
            Erasable::seal(
                &"new account".into(),
                None,
                &h.book.seal_key,
                [91; 32],
                [92; 24],
            ),
            &Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap(),
        ))
        .unwrap()
        .unwrap();
    let account = account_vid(h.book.book_id, "8000");
    h.post_expense(account, 49, b"new-account-source");
    let mut remove = WriteBatch::new(relation::IN_BOOK);
    let period = period_vid(&h.book.calendar.id, &h.march);
    for edge in h.db.edges().unwrap() {
        if edge.entry.relation == relation::IN_BOOK && [account, period].contains(&edge.entry.src) {
            remove.delete_edge(edge.entry.eid);
        }
    }
    h.write_derived(remove);
    let (report, _) = assert_literal(&h, &mut memo, &periods, None, false).unwrap();
    assert_eq!(
        report
            .rows
            .iter()
            .find(|row| row.code == "8000")
            .unwrap()
            .debits,
        49
    );
    assert_eq!(memo.read_work().metadata_scans, 0);
    assert_eq!(memo.read_work().population_scans, 0);
}

#[test]
fn resident_report_cancellation_precedes_memo_access() {
    let h = harness();
    let periods = vec![h.march.clone()];
    let mut memo = ReportHistoryMemo::default();
    assert_literal(&h, &mut memo, &periods, None, false).unwrap();
    let at = memo.known_at();
    let work = memo.read_work();
    h.root.cancel_fast(asupersync::types::CancelKind::User);
    for activity in [false, true] {
        let error = read(&h, &mut memo, &periods, None, activity).unwrap_err();
        assert!(matches!(
            error,
            RegisterError::Kernel(KernelError::Txn(fgdb::WriteTxnError::Interrupted(_)))
        ));
        assert_eq!(memo.known_at(), at);
        assert_eq!(memo.read_work(), work);
    }
}
