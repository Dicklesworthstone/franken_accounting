use super::*;
use fa_journal::external_subledger::{
    EXTERNAL_SUBLEDGER_DOCUMENT_KIND, ExternalSubledgerBatch, ExternalSubledgerDetail,
    reconcile_at, verify_all_at,
};

fn detail(h: &Harness, batch_key: &str) -> ExternalSubledgerBatch {
    ExternalSubledgerBatch {
        book_id: h.book.book_id,
        feed: "external-ap".into(),
        batch_key: batch_key.into(),
        effective_date: h.day(),
        rows: vec![
            ExternalSubledgerDetail {
                source_digest: [1; 32],
                account: h.rent,
                side: Side::Debit,
                amount: Amount::new(h.usd, 4_000),
                dimensions: vec![],
            },
            ExternalSubledgerDetail {
                source_digest: [2; 32],
                account: h.rent,
                side: Side::Debit,
                amount: Amount::new(h.usd, 6_000),
                dimensions: vec![],
            },
            ExternalSubledgerDetail {
                source_digest: [3; 32],
                account: h.cash,
                side: Side::Credit,
                amount: Amount::new(h.usd, 10_000),
                dimensions: vec![],
            },
        ],
    }
}

fn retain(h: &mut Harness, detail: &ExternalSubledgerBatch, reviewed: bool) {
    let bytes = detail.canonical_bytes().unwrap();
    let doc = h.document(EXTERNAL_SUBLEDGER_DOCUMENT_KIND, HUMAN_UPLOAD, &bytes);
    let added = h.add_document(&doc).unwrap();
    assert_eq!(added.oid, detail.evidence().unwrap().document_oid);
    if reviewed {
        h.review(REVIEWER, added.oid, vec![]).unwrap();
    }
}

fn proposal(h: &Harness, detail: &ExternalSubledgerBatch, key: &[u8]) -> EntryPayload {
    let mut template = h.proposal(vec![], key, EntryClass::ORIGINAL);
    template.evidence = vec![detail.evidence().unwrap()];
    detail.proposal(template).unwrap()
}

#[test]
fn external_feed_posts_one_summary_and_replays_its_reviewed_source() {
    let mut h = harness();
    let detail = detail(&h, "001");
    retain(&mut h, &detail, true);
    let prepared = proposal(&h, &detail, b"external-001");
    let before = h.db.frontier().unwrap();
    let before_rows = h.db.vertices_at(before).unwrap();
    let posted = h.post(h.request(prepared.clone(), &["post"])).unwrap();
    assert_eq!(posted.recorded_at().0, before.0 + 1);
    let after_rows = h.db.vertices_at(posted.recorded_at()).unwrap();
    let new_entries = after_rows
        .iter()
        .filter(|row| {
            row.created_at == posted.recorded_at()
                && row.labels.contains(&fa_model::symbols::label::ENTRY)
        })
        .count();
    let new_details = after_rows
        .iter()
        .filter(|row| {
            row.created_at == posted.recorded_at()
                && row
                    .labels
                    .contains(&fa_model::symbols::label::EXTERNAL_SUBLEDGER_BATCH)
        })
        .count();
    assert_eq!((new_entries, new_details), (1, 1));
    assert!(after_rows.len() > before_rows.len());
    let report = reconcile_at(&h.db, &h.book, posted.entry_ref(), posted.recorded_at())
        .unwrap()
        .unwrap();
    assert!(report.reconciled);
    assert_eq!(report.detail_rows, 3);
    assert_eq!(report.summary_legs.len(), 2);
    assert_eq!(report.review.reviewer, REVIEWER);
    assert!(
        verify_all_at(&h.db, &h.book, posted.recorded_at())
            .unwrap()
            .is_empty()
    );
    let retry = h.post(h.request(prepared, &["post"])).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
    let duplicate = proposal(&h, &detail, b"another-idempotency-key");
    let refusal = h.post(h.request(duplicate, &["post"])).unwrap_err();
    assert!(refusal.message.contains("already has a committed summary"));
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
    let reverse = h.reversal_of_entry(posted.entry_ref(), b"reverse-external-001");
    h.post(h.request(reverse, &["post"])).unwrap();
    let replay = reconcile_at(&h.db, &h.book, posted.entry_ref(), h.db.frontier().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(replay, report);
}

#[test]
fn external_feed_requires_independent_review_before_any_accounting_publication() {
    let mut h = harness();
    let detail = detail(&h, "002");
    retain(&mut h, &detail, false);
    let source = detail.evidence().unwrap();
    let before = h.db.frontier().unwrap();
    let refusal = h
        .post(h.request(proposal(&h, &detail, b"external-002"), &["post"]))
        .unwrap_err();
    assert!(refusal.message.contains("independent Reviewed"));
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(h.db.vertex(detail.identity()).unwrap().is_none());
    assert!(h.review(PRINCIPAL, source.document_oid, vec![]).is_err());
    h.review(REVIEWER, source.document_oid, vec![]).unwrap();
    assert!(
        h.post(h.request(proposal(&h, &detail, b"external-002"), &["post"]))
            .is_ok()
    );
}

#[test]
fn external_feed_rejects_balanced_forgery_and_wrong_date_without_mutating_book() {
    let mut h = harness();
    let detail = detail(&h, "003");
    retain(&mut h, &detail, true);
    let original = proposal(&h, &detail, b"external-003");
    let before = h.db.frontier().unwrap();
    let mut forged = original.clone();
    for leg in &mut forged.legs {
        leg.amount.mantissa += 1;
    }
    forged.unit_totals = EntryPayload::fold_unit_totals(&forged.legs).unwrap();
    let refusal = h.post(h.request(forged, &["post"])).unwrap_err();
    assert!(refusal.message.contains("complete gross detail fold"));
    let mut wrong_day = original;
    wrong_day.effective_date.0 += 1;
    assert!(
        h.post(h.request(wrong_day, &["post"]))
            .unwrap_err()
            .message
            .contains("coordinate")
    );
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(h.db.vertex(detail.identity()).unwrap().is_none());
}

#[test]
fn two_members_cannot_claim_the_same_external_batch_in_one_atomic_publication() {
    let mut h = harness();
    let detail = detail(&h, "004");
    retain(&mut h, &detail, true);
    let first = proposal(&h, &detail, b"external-004-a");
    let second = proposal(&h, &detail, b"external-004-b");
    let batch = h.batch(b"duplicate-feed-batch", vec![first, second]);
    let before = h.db.frontier().unwrap();
    assert!(h.post_batch(batch).is_err());
    assert_eq!(h.db.frontier().unwrap(), before);
    assert!(h.db.vertex(detail.identity()).unwrap().is_none());
}

#[test]
fn separately_prepared_summaries_compete_for_one_source_batch_in_both_commit_orders() {
    for second_wins in [false, true] {
        let mut h = harness();
        let detail = detail(&h, "source-race");
        retain(&mut h, &detail, true);
        let cx = h.ctx();
        let first_request = h.request(proposal(&h, &detail, b"source-race-a"), &["post"]);
        let second_request = h.request(proposal(&h, &detail, b"source-race-b"), &["post"]);
        let ready = |prepared| match prepared {
            PostPreparation::Ready(ready) => ready,
            PostPreparation::AlreadyRecorded(_) => panic!("fresh source batch"),
        };
        let first = ready(
            prepare_post(&mut h.db, &cx, &h.book, first_request)
                .unwrap()
                .unwrap(),
        );
        let second = ready(
            prepare_post(&mut h.db, &cx, &h.book, second_request)
                .unwrap()
                .unwrap(),
        );
        let (winner, loser) = if second_wins {
            (second, first)
        } else {
            (first, second)
        };
        let posted = h
            .runtime
            .block_on(winner.commit(&mut h.db, &cx))
            .unwrap()
            .unwrap();
        let refused = h
            .runtime
            .block_on(loser.commit(&mut h.db, &cx))
            .expect("the stale source witness is an ordinary accounting conflict")
            .expect_err("a second summary must not commit");
        assert_eq!(refused.exit, exit::CONFLICT);
        assert_eq!(h.db.frontier().unwrap(), posted.recorded_at());
        let rows = h.db.vertices_at(posted.recorded_at()).unwrap();
        assert_eq!(
            rows.iter()
                .filter(|row| row
                    .labels
                    .contains(&fa_model::symbols::label::EXTERNAL_SUBLEDGER_BATCH))
                .count(),
            1
        );
        assert!(
            verify_all_at(&h.db, &h.book, posted.recorded_at())
                .unwrap()
                .is_empty()
        );
    }
}
