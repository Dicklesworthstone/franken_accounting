use super::*;

fn batch_setup(seed: u8, count: usize) -> (Fixture, RecordedFindings) {
    let mut f = Fixture::new(seed);
    for _ in 0..count { f.post(10, "3000", "1000", 100); }
    let certificate = f.certify("jet.weekend", None);
    let recorded = f.record(certificate.digest()).unwrap();
    assert_eq!(recorded.finding_ids.len(), count);
    (f, recorded)
}

fn acknowledgements(run: &RecordedFindings) -> Vec<FindingReviewRequest> {
    run.finding_ids.iter().map(|&id| request(id, None, FindingReviewAction::Acknowledge, vec![])).collect()
}

fn batch(f: &mut Fixture, run: &RecordedFindings, requests: &[FindingReviewRequest]) -> Result<Vec<FindingReview>, Refusal> {
    let cx = f.cx();
    f.runtime.block_on(f.book.review_finding_run(
        &cx, REVIEWER, &reviewer(), &run.certificate_digest, requests,
    )).unwrap()
}

#[test]
fn selected_run_decisions_publish_together_in_source_order_and_replay_as_a_workpaper() {
    let (mut f, run) = batch_setup(191, 3);
    let cx = f.cx();
    let original = f.runtime.block_on(f.book.finding_workpaper(
        &cx, PRINCIPAL, &cap(&["read", "produce"]), &run.certificate_digest,
    )).unwrap().unwrap().canonical_bytes().unwrap();
    let before = f.head();
    let entry_count = f.book.query(&cx, |db, book| Ok(fa_registers::entries_at(db, book, before)?.len())).unwrap();
    let mut requests = acknowledgements(&run);
    requests[1].action = FindingReviewAction::Dismiss(DismissalReason::Explained);
    requests[1].evidence = vec![f.evidence[0].document_oid];
    requests.reverse();
    let decisions = batch(&mut f, &run, &requests).unwrap();
    assert_eq!(f.head().0, before.0 + 1);
    assert_eq!(decisions.iter().map(|d| d.request.finding_vid).collect::<Vec<_>>(), run.finding_ids);
    assert!(decisions.iter().all(|d| d.recorded_at == f.head()));
    let at = f.head();
    assert_eq!(f.book.query(&cx, |db, book| Ok(fa_registers::entries_at(db, book, at)?.len())).unwrap(), entry_count);
    let view = f.runtime.block_on(f.book.finding_run_review_history(
        &cx, PRINCIPAL, &cap(&["read"]), &run.certificate_digest, None,
    )).unwrap().unwrap();
    for (history, decision) in view.histories.iter().zip(&decisions) {
        assert_eq!(history.reviews, std::slice::from_ref(decision));
    }
    let old = f.runtime.block_on(f.book.finding_run_review_history(
        &cx, PRINCIPAL, &cap(&["read"]), &run.certificate_digest, Some(before),
    )).unwrap().unwrap();
    assert!(old.histories.iter().all(|h| h.status() == FindingReviewStatus::Open));
    let revised = f.runtime.block_on(f.book.finding_review_workpaper(
        &cx, PRINCIPAL, &cap(&["read", "produce"]), &run.certificate_digest, Some(at),
    )).unwrap().unwrap();
    let bytes = revised.canonical_bytes().unwrap();
    f = f.reopen();
    let cx = f.cx();
    let replayed = f.runtime.block_on(f.book.replay_finding_review_workpaper(
        &cx, PRINCIPAL, &cap(&["read"]), &bytes,
    )).unwrap().unwrap();
    assert_eq!(replayed.histories, view.histories);
    assert_eq!(f.runtime.block_on(f.book.finding_workpaper(
        &cx, PRINCIPAL, &cap(&["read", "produce"]), &run.certificate_digest,
    )).unwrap().unwrap().canonical_bytes().unwrap(), original);
    assert_eq!(f.head(), at);
}

#[test]
fn exact_retries_and_subsets_reuse_one_birth_even_after_later_individual_decisions() {
    let (mut f, run) = batch_setup(192, 3);
    let mut requests = acknowledgements(&run);
    let first = batch(&mut f, &run, &requests).unwrap();
    requests.reverse();
    assert_eq!(batch(&mut f, &run, &requests).unwrap(), first);
    assert_eq!(f.head(), first[0].recorded_at);
    let dismissal = request(run.finding_ids[0], Some(first[0].review_vid),
        FindingReviewAction::Dismiss(DismissalReason::Other), vec![f.evidence[0].document_oid]);
    let later = apply(&mut f, &dismissal);
    f = f.reopen();
    assert_eq!(batch(&mut f, &run, &requests).unwrap(), first);
    assert_eq!(batch(&mut f, &run, &requests[..1]).unwrap(), vec![first[2].clone()]);
    assert_eq!(apply(&mut f, &first[1].request), first[1], "single and batch retries use the same records");
    assert_eq!(f.head(), later.recorded_at);
}

#[test]
fn one_invalid_member_refuses_every_new_decision_before_publication() {
    let (mut f, run) = batch_setup(193, 3);
    let before = f.head();
    let count = f.count();
    let base = acknowledgements(&run);
    for mode in 0..7 {
        let mut bad = base.clone();
        match mode {
            0 => bad[2].expected_previous = Some(VId(0)),
            1 => bad[2].finding_vid = VId(0),
            2 => bad[2].action = FindingReviewAction::Reopen,
            3 => bad[2].note.clear(),
            4 => {
                bad[2].action = FindingReviewAction::Dismiss(DismissalReason::Other);
                bad[2].evidence = vec![Oid([0; 32])];
            }
            5 => bad[2].finding_vid = bad[0].finding_vid,
            _ => {
                bad[2].action = FindingReviewAction::Dismiss(DismissalReason::Duplicate);
                bad[2].evidence.clear();
            }
        }
        assert!(batch(&mut f, &run, &bad).is_err(), "mode {mode}");
        assert_eq!(f.head(), before, "mode {mode}");
        assert_eq!(f.count(), count, "mode {mode}");
    }
    assert!(batch(&mut f, &run, &[]).is_err());
    assert_eq!(batch(&mut f, &run, &base).unwrap().len(), 3);
}

#[test]
fn old_and_new_decisions_or_separate_births_cannot_be_repackaged_as_one_atomic_result() {
    let (mut f, run) = batch_setup(194, 3);
    let requests = acknowledgements(&run);
    let first = apply(&mut f, &requests[0]);
    assert_eq!(batch(&mut f, &run, &requests).unwrap_err().exit, exit::CONFLICT);
    assert_eq!(f.head(), first.recorded_at);
    let second = apply(&mut f, &requests[1]);
    assert_eq!(batch(&mut f, &run, &requests[..2]).unwrap_err().exit, exit::CONFLICT);
    assert_eq!(f.head(), second.recorded_at);
    let successors = vec![
        request(run.finding_ids[0], Some(first.review_vid), FindingReviewAction::Acknowledge, vec![]),
        request(run.finding_ids[1], Some(second.review_vid), FindingReviewAction::Acknowledge, vec![]),
        requests[2].clone(),
    ];
    let decisions = batch(&mut f, &run, &successors).unwrap();
    assert!(decisions.iter().all(|d| d.recorded_at == f.head()));
    assert_eq!(decisions.iter().map(|d| d.ordinal).collect::<Vec<_>>(), [1, 1, 0]);
}

#[test]
fn competing_actor_and_changed_explanation_refuse_without_lost_updates() {
    let (mut f, run) = batch_setup(195, 3);
    let requests = acknowledgements(&run);
    let first = batch(&mut f, &run, &requests).unwrap();
    let cx = f.cx();
    let other = Capability::embedded(SECOND_REVIEWER, &["read", "approve"]).unwrap();
    assert_eq!(f.runtime.block_on(f.book.review_finding_run(
        &cx, SECOND_REVIEWER, &other, &run.certificate_digest, &requests,
    )).unwrap().unwrap_err().exit, exit::CONFLICT);
    let mut changed = requests;
    changed[2].note.push_str(" Changed.");
    assert_eq!(batch(&mut f, &run, &changed).unwrap_err().exit, exit::CONFLICT);
    assert_eq!(f.head(), first[0].recorded_at);
    assert_eq!(f.read(&run.certificate_digest).unwrap(), run);
}

#[test]
fn authority_is_checked_before_batch_shape_or_source_and_on_exact_retry() {
    let (mut f, run) = batch_setup(196, 2);
    let at = f.head();
    let cx = f.cx();
    for denied in [
        Capability::embedded(REVIEWER, &["read"]).unwrap(),
        Capability::embedded(REVIEWER, &["approve"]).unwrap(),
        Capability::embedded(REVIEWER, &["produce"]).unwrap(),
        reviewer().expiring_at(at),
        reviewer().for_accounts(&["1000"]).unwrap(),
        cap(&["read", "approve"]),
    ] {
        let refused = f.runtime.block_on(f.book.review_finding_run(
            &cx, REVIEWER, &denied, &[0; 32], &[],
        )).unwrap().unwrap_err();
        assert_eq!(refused.exit, exit::SAFETY);
        assert_eq!(f.head(), at);
    }
    let requests = acknowledgements(&run);
    assert_eq!(f.runtime.block_on(f.book.review_finding_run(
        &cx, PRINCIPAL, &cap(&["read", "approve"]), &run.certificate_digest, &requests,
    )).unwrap().unwrap_err().exit, exit::SAFETY);
    let decisions = batch(&mut f, &run, &requests).unwrap();
    let after = f.head();
    assert_eq!(f.runtime.block_on(f.book.review_finding_run(
        &cx, REVIEWER, &reviewer().expiring_at(after), &run.certificate_digest, &requests,
    )).unwrap().unwrap_err().exit, exit::SAFETY);
    assert_eq!(f.head(), decisions[0].recorded_at);
}

#[test]
fn a_preexisting_final_slot_does_not_publish_earlier_batch_members() {
    let (mut f, run) = batch_setup(197, 3);
    let requests = acknowledgements(&run);
    let conflicting = finding_review_vid(f.book.context().book_id, run.finding_ids[2], 0);
    let cx = f.cx();
    let mut orphan = WriteBatch::new(relation::RESOLVES);
    // Not a Finding label: this tests the final point-read identity check,
    // rather than an earlier whole-population Finding corruption refusal.
    orphan.create_vertex(conflicting, vec![label::PARTY], vec![]);
    f.runtime.block_on(f.book.db.write(&cx.commit(), orphan)).unwrap();
    let at = f.head();
    let count = f.count();
    assert_eq!(batch(&mut f, &run, &requests).unwrap_err().exit, exit::CONFLICT);
    assert_eq!(f.head(), at);
    assert_eq!(f.count(), count);
    for &finding in &run.finding_ids[..2] {
        let id = finding_review_vid(f.book.context().book_id, finding, 0);
        assert!(f.book.db.vertex_at(id, at).unwrap().is_none());
    }
}

#[test]
fn batch_admission_accepts_the_exact_limit_and_refuses_one_more_without_truncation() {
    let maximum = FindingRunReviewHistory::MAX_BATCH_DECISIONS;
    let (mut f, run) = batch_setup(198, maximum + 1);
    let requests = acknowledgements(&run);
    let at = f.head();
    assert!(batch(&mut f, &run, &requests).is_err());
    assert_eq!(f.head(), at);
    let accepted = batch(&mut f, &run, &requests[..maximum]).unwrap();
    assert_eq!(accepted.len(), maximum);
    assert!(accepted.iter().all(|d| d.recorded_at.0 == at.0 + 1));
    assert_eq!(history(&mut f, run.finding_ids[maximum], None).status(), FindingReviewStatus::Open);
    assert_eq!(f.head().0, at.0 + 1);
    let data = include_str!("../../../../../../../registries/finding_storage.toml");
    assert!(data.contains("[review_batch]\nmax_decisions = 64\n"));
}
