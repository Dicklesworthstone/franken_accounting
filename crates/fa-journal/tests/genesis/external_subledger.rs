use super::*;
use fa_journal::external_subledger::{
    EXTERNAL_SUBLEDGER_DOCUMENT_KIND, ExternalSubledgerBatch, ExternalSubledgerDetail,
    reconcile_at, reconcile_unchanged_at, verify_all_at, verify_all_at_with_work,
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

#[test]
fn external_feed_verification_uses_one_review_point_read_per_summary() {
    let mut h = harness();
    let mut unrelated = fgdb::WriteBatch::new(relation::REVIEWED_BY);
    let source = VId(u128::MAX - 1);
    let destination = VId(u128::MAX - 2);
    unrelated.create_vertex(source, vec![], vec![]);
    unrelated.create_vertex(destination, vec![], vec![]);
    for index in 0..4_096_u128 {
        unrelated.create_vertex(VId(1_000_000 + index), vec![], vec![]);
        unrelated.add_edge(fgdb_types::EId(index + 1), source, destination, vec![]);
    }
    h.write_raw(unrelated);

    // Unrelated rows and edges precede publication: every original review
    // check would materialize all of them at the summary's own prefix.
    let mut summaries = Vec::new();
    for index in 0..4 {
        let batch = detail(&h, &format!("lookup-{index}"));
        retain(&mut h, &batch, true);
        let entry = proposal(&h, &batch, format!("lookup-{index}").as_bytes());
        let posted = h.post(h.request(entry, &["post"])).unwrap();
        summaries.push(
            reconcile_at(&h.db, &h.book, posted.entry_ref(), posted.recorded_at())
                .unwrap()
                .unwrap(),
        );
    }
    let at = h.db.frontier().unwrap();
    let (drift, work) = verify_all_at_with_work(&h.db, &h.book, at).unwrap();
    assert!(drift.is_empty(), "{drift:?}");
    assert!(work.vertex_rows_selected > 4_096);
    assert_eq!(work.review_edge_point_reads, summaries.len());
    assert!(
        work.identity_row_comparisons
            <= summaries.len() * (work.vertex_rows_selected.ilog2() as usize + 2)
    );

    // Keep the former exhaustive edge predicate live in the same test. Its
    // result agrees, but its actual materialized population grows with all
    // unrelated edges, whereas the production path performs four point reads.
    let mut literal_edges_materialized = 0;
    for report in &summaries {
        let expected = edge_id(
            relation::REVIEWED_BY,
            report.entry.vid,
            report.review.attestation,
        );
        let edges = h.db.edges_at(report.recorded_at).unwrap();
        literal_edges_materialized += edges.len();
        assert!(edges.iter().any(|edge| {
            edge.entry.eid == expected
                && edge.entry.relation == relation::REVIEWED_BY
                && edge.entry.src == report.entry.vid
                && edge.entry.dst == report.review.attestation
                && edge.props.is_empty()
        }));
        assert_eq!(
            reconcile_unchanged_at(&h.db, &h.book, report.entry, at)
                .unwrap()
                .unwrap(),
            *report
        );
    }
    assert!(literal_edges_materialized >= summaries.len() * 4_096);
}

#[test]
fn external_feed_history_and_dependency_refusal_order_survive_lineage_tampering() {
    let mut h = harness();
    let batch = detail(&h, "historical-lineage");
    retain(&mut h, &batch, true);
    let before = h.db.frontier().unwrap();
    let entry = proposal(&h, &batch, b"historical-lineage");
    let posted = h.post(h.request(entry, &["post"])).unwrap();
    let target = posted.entry_ref();
    let original = posted.recorded_at();
    let report = reconcile_at(&h.db, &h.book, target, original)
        .unwrap()
        .unwrap();
    assert!(
        reconcile_at(&h.db, &h.book, target, before)
            .unwrap()
            .unwrap_err()
            .message
            .contains("entry is absent at this prefix")
    );
    let lineage = edge_id(relation::REVIEWED_BY, target.vid, report.review.attestation);
    let mut tamper = fgdb::WriteBatch::new(relation::REVIEWED_BY);
    tamper.set_edge_property(lineage, property::CODE, Some(CanonicalScalar::Int(1)));
    h.write_raw(tamper);
    let altered = h.db.frontier().unwrap();
    assert_eq!(
        reconcile_at(&h.db, &h.book, target, altered)
            .unwrap()
            .unwrap(),
        report
    );
    assert!(
        reconcile_unchanged_at(&h.db, &h.book, target, altered)
            .unwrap()
            .unwrap_err()
            .message
            .contains("selected prefix lost the summary's review lineage")
    );

    let mut retire = fgdb::WriteBatch::new(relation::REVIEWED_BY);
    retire.delete_edge(lineage);
    h.write_raw(retire);
    let retired = h.db.frontier().unwrap();
    assert!(h.db.edge_at(lineage, retired).unwrap().is_none());
    assert_eq!(
        reconcile_at(&h.db, &h.book, target, retired)
            .unwrap()
            .unwrap(),
        report
    );
    assert!(
        reconcile_unchanged_at(&h.db, &h.book, target, retired)
            .unwrap()
            .unwrap_err()
            .message
            .contains("selected prefix lost the summary's review lineage")
    );
    assert!(verify_all_at(&h.db, &h.book, retired).unwrap().is_empty());

    let mut tamper = fgdb::WriteBatch::new(relation::REVIEWED_BY);
    tamper.set_vertex_property(
        batch.identity(),
        property::FA_DIGEST,
        Some(CanonicalScalar::bytes(vec![0; 32]).unwrap()),
    );
    h.write_raw(tamper);
    let altered_identity = h.db.frontier().unwrap();
    let missing_identity =
        "missing or altered external feed identity for external-ap/historical-lineage";
    assert_eq!(
        verify_all_at(&h.db, &h.book, altered_identity).unwrap(),
        [missing_identity]
    );
    // The immutable dependency refusal must still precede the already
    // missing review edge; indexing must not move lineage checks earlier.
    assert!(
        reconcile_unchanged_at(&h.db, &h.book, target, altered_identity)
            .unwrap()
            .unwrap_err()
            .message
            .contains("unique-batch identity changed after publication")
    );
    let orphan = VId(u128::MAX - 3);
    let mut remove = fgdb::WriteBatch::new(relation::REVIEWED_BY);
    remove.delete_vertex(batch.identity());
    remove.create_vertex(
        orphan,
        vec![fa_model::symbols::label::EXTERNAL_SUBLEDGER_BATCH],
        vec![],
    );
    h.write_raw(remove);
    assert_eq!(
        verify_all_at(&h.db, &h.book, h.db.frontier().unwrap()).unwrap(),
        [
            missing_identity.to_string(),
            format!("orphan external feed identity {:032x}", orphan.0),
        ]
    );
    assert_eq!(
        reconcile_unchanged_at(&h.db, &h.book, target, original)
            .unwrap()
            .unwrap(),
        report
    );
    assert!(verify_all_at(&h.db, &h.book, original).unwrap().is_empty());
}
