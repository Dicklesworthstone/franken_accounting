use super::*;

mod batch;

#[test]
fn a_complete_run_includes_open_reviewed_and_dismissed_occurrences_in_source_order() {
    let mut f = Fixture::new(161);
    for date in [10, 11, 17] { f.post(date, "3000", "1000", 100); }
    let cert = f.certify("jet.weekend", None);
    let recorded = f.record(cert.digest()).unwrap();
    assert_eq!(recorded.finding_ids.len(), 3);
    let first = apply(&mut f, &request(recorded.finding_ids[0], None, FindingReviewAction::Acknowledge, vec![]));
    let evidence = vec![f.evidence[0].document_oid];
    let second = apply(&mut f, &request(recorded.finding_ids[1], None,
        FindingReviewAction::Dismiss(DismissalReason::Explained), evidence));
    let head = f.head();
    let cx = f.cx();
    let full = f.runtime.block_on(f.book.finding_run_review_history(
        &cx, PRINCIPAL, &cap(&["read"]), cert.digest(), None,
    )).unwrap().unwrap();
    assert_eq!(full.run, recorded);
    assert_eq!(full.known_at, head);
    assert_eq!(full.checked_through, head);
    assert_eq!(full.histories.iter().map(|h| h.finding.finding_vid).collect::<Vec<_>>(), recorded.finding_ids);
    assert_eq!(full.histories[0].status(), FindingReviewStatus::Reviewed);
    assert_eq!(full.histories[1].status(), FindingReviewStatus::Dismissed { reason: DismissalReason::Explained, principal: REVIEWER });
    assert_eq!(full.histories[2].status(), FindingReviewStatus::Open);
    assert_eq!(full.histories[0].reviews, [first.clone()]);
    assert_eq!(full.histories[1].reviews, [second]);
    assert!(full.histories[2].reviews.is_empty());
    for (i, &id) in recorded.finding_ids.iter().enumerate() {
        assert_eq!(full.histories[i], history(&mut f, id, None));
    }
    let earlier = f.runtime.block_on(f.book.finding_run_review_history(
        &cx, PRINCIPAL, &cap(&["read"]), cert.digest(), Some(first.recorded_at),
    )).unwrap().unwrap();
    assert_eq!(earlier.histories[0].reviews, [first]);
    assert!(earlier.histories[1..].iter().all(|h| h.status() == FindingReviewStatus::Open));
    assert_eq!(f.head(), head, "all review reads leave the book unchanged");
    f = f.reopen();
    f.post(1, "3000", "1000", 99);
    let later_head = f.head();
    let cx = f.cx();
    let historical = f.runtime.block_on(f.book.finding_run_review_history(
        &cx, PRINCIPAL, &cap(&["read"]), cert.digest(), Some(head),
    )).unwrap().unwrap();
    assert_eq!(historical.run, full.run);
    assert_eq!(historical.known_at, head);
    assert_eq!(historical.checked_through, later_head);
    for (a, b) in historical.histories.iter().zip(&full.histories) {
        assert_eq!(a.finding, b.finding);
        assert_eq!(a.reviews, b.reviews);
        assert_eq!(a.status(), b.status());
    }
    assert_eq!(f.head(), later_head);
}

#[test]
fn an_empty_recorded_run_is_explicit_but_missing_runs_and_invalid_cutoffs_refuse() {
    let mut f = Fixture::new(162);
    f.post(1, "3000", "1000", 1);
    let cert = f.certify("jet.weekend", None); // Thursday: no observations.
    let cx = f.cx();
    assert!(f.runtime.block_on(f.book.finding_run_review_history(
        &cx, PRINCIPAL, &cap(&["read"]), cert.digest(), None,
    )).unwrap().is_err());
    let recorded = f.record(cert.digest()).unwrap();
    assert!(recorded.finding_ids.is_empty());
    let head = f.head();
    let full = f.runtime.block_on(f.book.finding_run_review_history(
        &cx, PRINCIPAL, &cap(&["read"]), cert.digest(), Some(recorded.recorded_at),
    )).unwrap().unwrap();
    assert_eq!(full.run, recorded);
    assert!(full.histories.is_empty());
    for at in [CommitSeq(recorded.recorded_at.0 - 1), CommitSeq(head.0 + 1)] {
        assert!(f.runtime.block_on(f.book.finding_run_review_history(
            &cx, PRINCIPAL, &cap(&["read"]), cert.digest(), Some(at),
        )).unwrap().is_err());
    }
    assert_eq!(f.head(), head);
}

#[test]
fn run_review_authority_precedes_unknown_digest_and_future_selector_observation() {
    let (mut f, _) = setup(163);
    let at = f.head();
    let cx = f.cx();
    for denied in [cap(&["post"]), cap(&["approve"]), cap(&["produce"]),
        cap(&["read"]).for_accounts(&["1000"]).unwrap(), cap(&["read"]).expiring_at(at)] {
        let refusal = f.runtime.block_on(f.book.finding_run_review_history(
            &cx, PRINCIPAL, &denied, &[0xff; 32], Some(CommitSeq(u64::MAX)),
        )).unwrap().unwrap_err();
        assert_eq!(refusal.exit, exit::SAFETY);
    }
    assert_eq!(f.head(), at);
}

#[test]
fn a_retired_review_cannot_disappear_from_a_complete_run_or_an_earlier_cutoff() {
    let mut f = Fixture::new(164);
    for date in [10, 11] { f.post(date, "3000", "1000", 100); }
    let cert = f.certify("jet.weekend", None);
    let recorded = f.record(cert.digest()).unwrap();
    assert_eq!(recorded.finding_ids.len(), 2);
    apply(&mut f, &request(recorded.finding_ids[0], None, FindingReviewAction::Acknowledge, vec![]));
    let evidence = vec![f.evidence[0].document_oid];
    let final_review = apply(&mut f, &request(recorded.finding_ids[1], None,
        FindingReviewAction::Dismiss(DismissalReason::DataQuality), evidence));
    let cx = f.cx();
    let mut damage = WriteBatch::new(relation::RESOLVES);
    damage.delete_vertex(final_review.review_vid);
    f.runtime.block_on(f.book.db.write(&cx.commit(), damage)).unwrap();
    let head = f.head();
    for cutoff in [None, Some(recorded.recorded_at), Some(final_review.recorded_at)] {
        let result = f.runtime.block_on(f.book.finding_run_review_history(
            &cx, PRINCIPAL, &cap(&["read"]), cert.digest(), cutoff,
        ));
        assert!(!matches!(result, Ok(Ok(_))), "no partial histories or apparently open second finding");
    }
    assert_eq!(f.head(), head);
}
