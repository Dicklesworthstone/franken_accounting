use super::*;
use crate::findings::review::*;

mod run;
mod workpaper;

const REVIEWER: VId = VId(84);
const SECOND_REVIEWER: VId = VId(85);

fn reviewer() -> Capability {
    Capability::embedded(REVIEWER, &["read", "approve"]).unwrap()
}

fn setup(seed: u8) -> (Fixture, RecordedFindings) {
    let mut f = Fixture::new(seed);
    f.post(10, "3000", "1000", 100); // Saturday: real journal-entry finding.
    let cert = f.certify("jet.weekend", None);
    let findings = f.record(cert.digest()).unwrap();
    assert!(!findings.finding_ids.is_empty());
    (f, findings)
}

fn request(
    finding: VId,
    previous: Option<VId>,
    action: FindingReviewAction,
    evidence: Vec<Oid>,
) -> FindingReviewRequest {
    FindingReviewRequest { finding_vid: finding, expected_previous: previous, action,
        note: "Reviewed against the retained source; this is a human decision, not a change to the journal.".into(), evidence }
}

fn apply(f: &mut Fixture, request: &FindingReviewRequest) -> FindingReview {
    let cx = f.cx();
    f.runtime
        .block_on(f.book.review_finding(&cx, REVIEWER, &reviewer(), request))
        .unwrap()
        .unwrap()
}

fn history(f: &mut Fixture, finding: VId, at: Option<CommitSeq>) -> FindingReviewHistory {
    let cx = f.cx();
    f.runtime
        .block_on(
            f.book
                .finding_review_history(&cx, PRINCIPAL, &cap(&["read"]), finding, at),
        )
        .unwrap()
        .unwrap()
}

#[test]
fn acknowledgements_dismissals_and_reopening_keep_original_history_across_reopen() {
    let (mut f, recorded) = setup(141);
    let finding = recorded.finding_ids[0];
    let before = f.head();
    let original = f.read(&recorded.certificate_digest).unwrap();
    let cx = f.cx();
    let paper = f
        .runtime
        .block_on(f.book.finding_workpaper(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &recorded.certificate_digest,
        ))
        .unwrap()
        .unwrap();
    let entries_before = f
        .book
        .query(&cx, |db, book| {
            Ok(fa_registers::entries_at(db, book, before)?.len())
        })
        .unwrap();
    assert_eq!(
        history(&mut f, finding, None).status(),
        FindingReviewStatus::Open
    );

    let acknowledge = request(finding, None, FindingReviewAction::Acknowledge, vec![]);
    let first = apply(&mut f, &acknowledge);
    assert_eq!(first.recorded_at.0, before.0 + 1);
    assert_eq!(first.ordinal, 0);
    assert_eq!(
        history(&mut f, finding, None).status(),
        FindingReviewStatus::Reviewed
    );
    let evidence = vec![f.evidence[0].document_oid];
    let dismiss = request(
        finding,
        Some(first.review_vid),
        FindingReviewAction::Dismiss(DismissalReason::Explained),
        evidence,
    );
    let second = apply(&mut f, &dismiss);
    assert_eq!(second.recorded_at.0, first.recorded_at.0 + 1);
    assert_eq!(
        history(&mut f, finding, None).status(),
        FindingReviewStatus::Dismissed {
            reason: DismissalReason::Explained,
            principal: REVIEWER
        }
    );
    assert_eq!(
        history(&mut f, finding, Some(first.recorded_at)).status(),
        FindingReviewStatus::Reviewed
    );
    assert_eq!(
        history(&mut f, finding, Some(before)).status(),
        FindingReviewStatus::Open
    );

    f = f.reopen();
    f.post(1, "3000", "1000", 7); // unrelated backdated activity cannot erase a decision.
    let current = f.head();
    assert_eq!(
        apply(&mut f, &acknowledge),
        first,
        "retry an earlier decision after its successor"
    );
    assert_eq!(apply(&mut f, &dismiss), second);
    assert_eq!(f.head(), current);
    let reopen = request(
        finding,
        Some(second.review_vid),
        FindingReviewAction::Reopen,
        vec![],
    );
    let third = apply(&mut f, &reopen);
    let timeline = history(&mut f, finding, None);
    assert_eq!(timeline.reviews, [first, second, third]);
    assert_eq!(timeline.status(), FindingReviewStatus::Open);
    assert_eq!(f.read(&recorded.certificate_digest).unwrap(), original);
    let cx = f.cx();
    let after_paper = f
        .runtime
        .block_on(f.book.finding_workpaper(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &recorded.certificate_digest,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(
        paper, after_paper,
        "original observation workpaper does not silently incorporate a later review"
    );
    let after = f
        .book
        .query(&cx, |db, book| {
            Ok(fa_registers::entries_at(db, book, f.head())?.len())
        })
        .unwrap();
    assert_eq!(
        after,
        entries_before + 1,
        "only the explicit backdated posting adds an accounting Entry"
    );
}

#[test]
fn stale_decisions_conflict_without_changing_the_winners_explanation() {
    for reverse in [false, true] {
        let (mut f, recorded) = setup(if reverse { 142 } else { 143 });
        let finding = recorded.finding_ids[0];
        let mut a = request(finding, None, FindingReviewAction::Acknowledge, vec![]);
        let mut b = a.clone();
        a.note = "Reviewer A examined original evidence".into();
        b.note = "Reviewer B reached a different documented conclusion".into();
        let second_cap = Capability::embedded(SECOND_REVIEWER, &["read", "approve"]).unwrap();
        let candidates = if reverse {
            [(SECOND_REVIEWER, second_cap, b), (REVIEWER, reviewer(), a)]
        } else {
            [(REVIEWER, reviewer(), a), (SECOND_REVIEWER, second_cap, b)]
        };
        let cx = f.cx();
        let winner = f
            .runtime
            .block_on(f.book.review_finding(
                &cx,
                candidates[0].0,
                &candidates[0].1,
                &candidates[0].2,
            ))
            .unwrap()
            .unwrap();
        let at = f.head();
        let refused = f
            .runtime
            .block_on(f.book.review_finding(
                &cx,
                candidates[1].0,
                &candidates[1].1,
                &candidates[1].2,
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refused.exit, exit::CONFLICT);
        assert_eq!(f.head(), at);
        assert_eq!(history(&mut f, finding, None).reviews, [winner]);
    }
}

#[test]
fn current_whole_book_human_approval_and_independence_precede_any_decision() {
    let (mut f, recorded) = setup(144);
    let finding = recorded.finding_ids[0];
    let at = f.head();
    let cx = f.cx();
    let invalid = request(VId(0), None, FindingReviewAction::Acknowledge, vec![]);
    for denied in [
        Capability::embedded(REVIEWER, &["read"]).unwrap(),
        Capability::embedded(REVIEWER, &["approve"]).unwrap(),
        Capability::embedded(REVIEWER, &["produce"]).unwrap(),
        reviewer().expiring_at(at),
        reviewer().for_accounts(&["1000"]).unwrap(),
        cap(&["read", "approve"]), // holder differs from the alleged reviewer.
    ] {
        let refusal = f
            .runtime
            .block_on(f.book.review_finding(&cx, REVIEWER, &denied, &invalid))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::SAFETY);
        assert_eq!(f.head(), at);
    }
    let real = request(finding, None, FindingReviewAction::Acknowledge, vec![]);
    let self_review = f
        .runtime
        .block_on(
            f.book
                .review_finding(&cx, PRINCIPAL, &cap(&["read", "approve"]), &real),
        )
        .unwrap()
        .unwrap_err();
    assert_eq!(self_review.exit, exit::SAFETY);
    assert_eq!(f.head(), at);
    let good = apply(&mut f, &real);
    let now = f.head();
    let expired = reviewer().expiring_at(now);
    assert_eq!(
        f.runtime
            .block_on(f.book.review_finding(&cx, REVIEWER, &expired, &real))
            .unwrap()
            .unwrap_err()
            .exit,
        exit::SAFETY
    );
    assert_eq!(f.head(), good.recorded_at);
    let read = Capability::embedded(REVIEWER, &["read"]).unwrap();
    assert!(
        f.runtime
            .block_on(
                f.book
                    .finding_review_history(&cx, REVIEWER, &read, finding, None)
            )
            .unwrap()
            .is_ok()
    );
    assert_eq!(f.head(), now);
}

#[test]
fn dismissal_requires_retained_evidence_and_explicit_reopening() {
    let (mut f, recorded) = setup(145);
    let finding = recorded.finding_ids[0];
    let evidence = f.evidence[0].document_oid;
    let mut bad = vec![
        request(
            finding,
            None,
            FindingReviewAction::Dismiss(DismissalReason::Other),
            vec![],
        ),
        request(
            finding,
            None,
            FindingReviewAction::Dismiss(DismissalReason::Other),
            vec![Oid([0; 32])],
        ),
        request(
            finding,
            None,
            FindingReviewAction::Dismiss(DismissalReason::Other),
            vec![evidence, evidence],
        ),
        request(finding, None, FindingReviewAction::Reopen, vec![]),
    ];
    let mut empty = request(finding, None, FindingReviewAction::Acknowledge, vec![]);
    empty.note = " \n\t".into();
    bad.push(empty);
    let mut huge = request(finding, None, FindingReviewAction::Acknowledge, vec![]);
    huge.note = "x".repeat(MAX_REVIEW_NOTE_BYTES + 1);
    bad.push(huge);
    let before = f.head();
    let cx = f.cx();
    for request in bad {
        assert!(
            f.runtime
                .block_on(f.book.review_finding(&cx, REVIEWER, &reviewer(), &request))
                .unwrap()
                .is_err()
        );
        assert_eq!(f.head(), before);
    }
    let dismiss = request(
        finding,
        None,
        FindingReviewAction::Dismiss(DismissalReason::Other),
        vec![evidence],
    );
    let decision = apply(&mut f, &dismiss);
    let forbidden = request(
        finding,
        Some(decision.review_vid),
        FindingReviewAction::Acknowledge,
        vec![],
    );
    assert!(
        f.runtime
            .block_on(
                f.book
                    .review_finding(&cx, REVIEWER, &reviewer(), &forbidden)
            )
            .unwrap()
            .is_err()
    );
    assert_eq!(f.head(), decision.recorded_at);
    let reopened = request(
        finding,
        Some(decision.review_vid),
        FindingReviewAction::Reopen,
        vec![],
    );
    apply(&mut f, &reopened);
    assert_eq!(
        history(&mut f, finding, None).status(),
        FindingReviewStatus::Open
    );
}

#[test]
fn removing_the_latest_review_cannot_make_a_finding_open_again() {
    for relabel in [false, true] {
        let (mut f, recorded) = setup(if relabel { 146 } else { 147 });
        let finding = recorded.finding_ids[0];
        let r = request(
            finding,
            None,
            FindingReviewAction::Dismiss(DismissalReason::DataQuality),
            vec![f.evidence[0].document_oid],
        );
        let review = apply(&mut f, &r);
        let cx = f.cx();
        let mut damage = WriteBatch::new(relation::RESOLVES);
        if relabel {
            damage.set_vertex_label(review.review_vid, label::FINDING, false);
        } else {
            damage.delete_vertex(review.review_vid);
        }
        f.runtime
            .block_on(f.book.db.write(&cx.commit(), damage))
            .unwrap();
        let at = f.head();
        assert!(
            f.runtime
                .block_on(f.book.finding_review_history(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read"]),
                    finding,
                    None
                ))
                .is_err()
        );
        assert!(
            f.runtime
                .block_on(f.book.finding_review_history(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read"]),
                    finding,
                    Some(recorded.recorded_at)
                ))
                .is_err(),
            "historical selector cannot conceal later corruption"
        );
        assert!(
            f.runtime
                .block_on(f.book.review_finding(&cx, REVIEWER, &reviewer(), &r))
                .is_err()
        );
        assert_eq!(f.head(), at);
    }
}

#[test]
fn restored_review_payload_and_lineage_are_not_repaired_by_a_retry() {
    for edge_attack in [false, true] {
        let (mut f, recorded) = setup(if edge_attack { 148 } else { 149 });
        let finding = recorded.finding_ids[0];
        let r = request(finding, None, FindingReviewAction::Acknowledge, vec![]);
        let review = apply(&mut f, &r);
        let cx = f.cx();
        let original = f
            .book
            .query(&cx, |db, _| {
                Ok(db
                    .vertex_at(review.review_vid, review.recorded_at)
                    .map_err(KernelError::from)?
                    .unwrap())
            })
            .unwrap();
        let eid = edge_id(relation::RESOLVES, review.review_vid, finding);
        let mut damage = WriteBatch::new(relation::RESOLVES);
        if edge_attack {
            damage.set_edge_property(
                eid,
                property::FA_DIGEST,
                Some(CanonicalScalar::bytes(vec![1; 32]).unwrap()),
            );
        } else {
            damage.set_vertex_property(
                review.review_vid,
                property::FA_DIGEST,
                Some(CanonicalScalar::bytes(vec![1; 32]).unwrap()),
            );
        }
        f.runtime
            .block_on(f.book.db.write(&cx.commit(), damage))
            .unwrap();
        let mut restore = WriteBatch::new(relation::RESOLVES);
        if edge_attack {
            restore.set_edge_property(eid, property::FA_DIGEST, None);
        } else {
            restore.set_vertex_property(
                review.review_vid,
                property::FA_DIGEST,
                prop(&original, property::FA_DIGEST).cloned(),
            );
        }
        f.runtime
            .block_on(f.book.db.write(&cx.commit(), restore))
            .unwrap();
        let at = f.head();
        let read = f.runtime.block_on(f.book.finding_review_history(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            finding,
            None,
        ));
        assert!(read.is_err() || read.unwrap().is_err());
        let retry = f
            .runtime
            .block_on(f.book.review_finding(&cx, REVIEWER, &reviewer(), &r));
        assert!(retry.is_err() || retry.unwrap().is_err());
        assert_eq!(f.head(), at);
    }
}
