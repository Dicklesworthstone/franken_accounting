use super::*;

fn export(f: &mut Fixture, digest: &[u8; 32], at: Option<CommitSeq>) -> FindingReviewWorkpaper {
    let cx = f.cx();
    f.runtime
        .block_on(f.book.finding_review_workpaper(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            digest,
            at,
        ))
        .unwrap()
        .unwrap()
}

/// Deliberately build a forged but internally consistent public frame. The test
/// must get through decoding and fail native recomputation, not checksum syntax.
fn forged(paper: &FindingReviewWorkpaper, at: CommitSeq, json: &str, md: &str) -> Vec<u8> {
    let id = format!("{}-R-{}", paper.observation_workpaper().id(), at.0);
    let original = paper.observation_workpaper().canonical_bytes().unwrap();
    let mut w = Writer::new();
    w.bytes(FINDING_REVIEW_WORKPAPER_FORMAT)
        .str(&id)
        .u64(at.0)
        .bytes(&original)
        .str(json)
        .str(md);
    let mut bytes = encoded(w).unwrap();
    let hash = domain_digest(b"fa:finding-review-workpaper-digest:v1", &[&bytes]);
    bytes.extend_from_slice(&hash);
    assert!(FindingReviewWorkpaper::decode(&bytes).is_ok());
    bytes
}

#[test]
fn review_workpapers_keep_original_observations_and_every_selected_human_decision() {
    let mut f = Fixture::new(165);
    for date in [10, 11, 17] {
        f.post(date, "3000", "1000", 100);
    }
    let cert = f.certify("jet.weekend", None);
    let recorded = f.record(cert.digest()).unwrap();
    assert_eq!(recorded.finding_ids.len(), 3);
    let unreviewed = export(&mut f, cert.digest(), None);
    let mut acknowledge = request(
        recorded.finding_ids[0],
        None,
        FindingReviewAction::Acknowledge,
        vec![],
    );
    acknowledge.note = "Invoice <script>|[source](path)\n\"quoted\" \\ 零".into();
    let first = apply(&mut f, &acknowledge);
    let evidence = vec![f.evidence[0].document_oid];
    let second = apply(
        &mut f,
        &request(
            recorded.finding_ids[1],
            None,
            FindingReviewAction::Dismiss(DismissalReason::Explained),
            evidence.clone(),
        ),
    );
    let head = f.head();
    let paper = export(&mut f, cert.digest(), Some(head));
    assert_eq!(
        paper.observation_workpaper(),
        unreviewed.observation_workpaper()
    );
    assert_eq!(
        paper.observation_workpaper().certificate_bytes(),
        cert.canonical_bytes().unwrap()
    );
    assert_eq!(paper.review_known_at(), head);
    assert_eq!(
        paper.id(),
        format!("{}-R-{}", unreviewed.observation_workpaper().id(), head.0)
    );
    assert!(
        paper
            .review_jsonl()
            .contains("\"open\":1,\"reviewed\":1,\"dismissed\":1")
    );
    assert_eq!(
        paper
            .review_jsonl()
            .lines()
            .filter(|l| l.contains("\"event\":\"finding_review_state\""))
            .count(),
        3
    );
    assert_eq!(
        paper
            .review_jsonl()
            .lines()
            .filter(|l| l.contains("\"event\":\"finding_review_decision\""))
            .count(),
        2
    );
    assert!(paper.review_jsonl().contains("\\n\\\"quoted\\\" \\\\ 零"));
    assert!(
        paper
            .review_markdown()
            .contains("&lt;script&gt;&#124;\\[source\\](path)")
    );
    assert!(!paper.review_markdown().contains("<script>"));
    assert!(
        paper
            .review_markdown()
            .contains("Dismissal reason: **Explained**")
    );
    assert!(
        paper
            .review_jsonl()
            .contains(&format!("\"principal\":\"{:032x}\"", REVIEWER.0))
    );
    let oid: String = evidence[0].0.iter().map(|b| format!("{b:02x}")).collect();
    assert!(paper.review_jsonl().contains(&oid));
    assert!(paper.review_markdown().contains(&oid));
    let bytes = paper.canonical_bytes().unwrap();
    assert_eq!(FindingReviewWorkpaper::decode(&bytes).unwrap(), paper);
    assert_eq!(f.head(), head, "export must not publish or renumber");

    f = f.reopen();
    f.post(1, "3000", "1000", 777);
    let reopened = apply(
        &mut f,
        &request(
            recorded.finding_ids[1],
            Some(second.review_vid),
            FindingReviewAction::Reopen,
            vec![],
        ),
    );
    let now = f.head();
    assert_eq!(
        export(&mut f, cert.digest(), Some(head)),
        paper,
        "same review cutoff remains byte stable"
    );
    let changed = export(&mut f, cert.digest(), None);
    assert_ne!(changed.digest(), paper.digest());
    assert_eq!(
        changed.observation_workpaper(),
        paper.observation_workpaper()
    );
    assert!(
        changed
            .review_jsonl()
            .contains("\"open\":2,\"reviewed\":1,\"dismissed\":0")
    );
    let cx = f.cx();
    let replayed = f
        .runtime
        .block_on(
            f.book
                .replay_finding_review_workpaper(&cx, PRINCIPAL, &cap(&["read"]), &bytes),
        )
        .unwrap()
        .unwrap();
    assert_eq!(replayed.known_at, head);
    assert_eq!(replayed.checked_through, now);
    assert_eq!(replayed.run, recorded);
    assert_eq!(replayed.histories[0].reviews, [first]);
    assert_eq!(replayed.histories[1].reviews, [second]);
    assert!(
        !replayed
            .histories
            .iter()
            .flat_map(|h| &h.reviews)
            .any(|r| r.review_vid == reopened.review_vid)
    );
    assert_eq!(
        f.head(),
        now,
        "read-only replay neither restores authority nor writes"
    );
}

#[test]
fn altered_or_omitted_decisions_cannot_be_repaired_by_rehashing_review_appendices() {
    let (mut f, run) = setup(166);
    let before = export(&mut f, &run.certificate_digest, None);
    let evidence = vec![f.evidence[0].document_oid];
    apply(
        &mut f,
        &request(
            run.finding_ids[0],
            None,
            FindingReviewAction::Dismiss(DismissalReason::DataQuality),
            evidence,
        ),
    );
    let after = export(&mut f, &run.certificate_digest, None);
    let head = f.head();
    let missing_json: String = after
        .review_jsonl()
        .lines()
        .filter(|l| !l.contains("\"event\":\"finding_review_decision\""))
        .map(|l| format!("{l}\n"))
        .collect();
    let changed_note = after
        .review_jsonl()
        .replace("Reviewed against", "Ignored against");
    let forged_frames = [
        forged(&after, head, &missing_json, after.review_markdown()),
        forged(&after, head, &changed_note, after.review_markdown()),
        // Pretend that the previous Open view describes the newer cutoff.
        forged(
            &after,
            head,
            before.review_jsonl(),
            before.review_markdown(),
        ),
        forged(
            &after,
            head,
            after.review_jsonl(),
            "No review decisions were ever recorded.",
        ),
        forged(
            &after,
            CommitSeq(head.0 + 1),
            after.review_jsonl(),
            after.review_markdown(),
        ),
    ];
    let cx = f.cx();
    for bytes in forged_frames {
        let result = f.runtime.block_on(f.book.replay_finding_review_workpaper(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            &bytes,
        ));
        assert!(
            !matches!(result, Ok(Ok(_))),
            "internally consistent false workpaper must not replay"
        );
    }
    assert_eq!(f.head(), head);
}

#[test]
fn current_authority_precedes_workpaper_decoding_and_export_requires_produce() {
    let (mut f, run) = setup(167);
    let paper = export(&mut f, &run.certificate_digest, None);
    let bytes = paper.canonical_bytes().unwrap();
    let head = f.head();
    let cx = f.cx();
    for denied in [
        cap(&["post"]),
        cap(&["approve"]),
        cap(&["produce"]),
        cap(&["read"]).for_accounts(&["1000"]).unwrap(),
        cap(&["read"]).expiring_at(head),
    ] {
        for input in [b"hostile workpaper".as_slice(), bytes.as_slice()] {
            let error = f
                .runtime
                .block_on(
                    f.book
                        .replay_finding_review_workpaper(&cx, PRINCIPAL, &denied, input),
                )
                .unwrap()
                .unwrap_err();
            assert_eq!(error.exit, exit::SAFETY);
        }
    }
    let error = f
        .runtime
        .block_on(f.book.finding_review_workpaper(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            &[0xff; 32],
            Some(CommitSeq(u64::MAX)),
        ))
        .unwrap()
        .unwrap_err();
    assert_eq!(error.exit, exit::SAFETY);
    assert!(
        f.runtime
            .block_on(f.book.replay_finding_review_workpaper(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
            ))
            .unwrap()
            .is_ok()
    );
    for length in [0, 1, 31, bytes.len() - 1] {
        assert!(
            f.runtime
                .block_on(f.book.replay_finding_review_workpaper(
                    &cx,
                    PRINCIPAL,
                    &cap(&["read"]),
                    &bytes[..length],
                ))
                .unwrap()
                .is_err()
        );
    }
    assert_eq!(f.head(), head);
}

#[test]
fn subsequent_review_corruption_invalidates_even_an_older_open_workpaper() {
    for restore in [false, true] {
        let (mut f, run) = setup(if restore { 168 } else { 169 });
        let old = export(&mut f, &run.certificate_digest, None)
            .canonical_bytes()
            .unwrap();
        let decision = apply(
            &mut f,
            &request(
                run.finding_ids[0],
                None,
                FindingReviewAction::Acknowledge,
                vec![],
            ),
        );
        let new = export(&mut f, &run.certificate_digest, None)
            .canonical_bytes()
            .unwrap();
        let cx = f.cx();
        let original = f
            .book
            .db
            .vertex_at(decision.review_vid, decision.recorded_at)
            .unwrap()
            .unwrap();
        let mut damage = WriteBatch::new(relation::RESOLVES);
        if restore {
            damage.set_vertex_property(
                decision.review_vid,
                property::FA_DIGEST,
                Some(CanonicalScalar::bytes(vec![99; 32]).unwrap()),
            );
        } else {
            damage.delete_vertex(decision.review_vid);
        }
        f.runtime
            .block_on(f.book.db.write(&cx.commit(), damage))
            .unwrap();
        if restore {
            let mut restored = WriteBatch::new(relation::RESOLVES);
            restored.set_vertex_property(
                decision.review_vid,
                property::FA_DIGEST,
                prop(&original, property::FA_DIGEST).cloned(),
            );
            f.runtime
                .block_on(f.book.db.write(&cx.commit(), restored))
                .unwrap();
        }
        f = f.reopen();
        let head = f.head();
        let cx = f.cx();
        for bytes in [&old, &new] {
            let result = f.runtime.block_on(f.book.replay_finding_review_workpaper(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                bytes,
            ));
            assert!(!matches!(result, Ok(Ok(_))));
        }
        let result = f.runtime.block_on(f.book.finding_review_workpaper(
            &cx,
            PRINCIPAL,
            &cap(&["read", "produce"]),
            &run.certificate_digest,
            Some(run.recorded_at),
        ));
        assert!(!matches!(result, Ok(Ok(_))));
        assert_eq!(f.head(), head);
    }
}

#[test]
fn empty_review_workpapers_replay_and_wrong_book_or_prepublication_cutoffs_refuse() {
    let mut f = Fixture::new(170);
    f.post(1, "3000", "1000", 1);
    let cert = f.certify("jet.weekend", None);
    let recorded = f.record(cert.digest()).unwrap();
    let paper = export(&mut f, cert.digest(), None);
    assert!(
        paper
            .review_jsonl()
            .contains("\"finding_count\":0,\"open\":0,\"reviewed\":0,\"dismissed\":0")
    );
    let bytes = paper.canonical_bytes().unwrap();
    let head = f.head();
    let cx = f.cx();
    let run = f
        .runtime
        .block_on(
            f.book
                .replay_finding_review_workpaper(&cx, PRINCIPAL, &cap(&["read"]), &bytes),
        )
        .unwrap()
        .unwrap();
    assert_eq!(run.run, recorded);
    assert!(run.histories.is_empty());
    assert!(
        f.runtime
            .block_on(f.book.finding_review_workpaper(
                &cx,
                PRINCIPAL,
                &cap(&["read", "produce"]),
                cert.digest(),
                Some(CommitSeq(recorded.recorded_at.0 - 1)),
            ))
            .unwrap()
            .is_err()
    );
    assert_eq!(f.head(), head);
    let mut other = Fixture::new(171);
    let cx = other.cx();
    let other_head = other.head();
    let result = other
        .runtime
        .block_on(other.book.replay_finding_review_workpaper(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            &bytes,
        ));
    assert!(!matches!(result, Ok(Ok(_))));
    assert_eq!(other.head(), other_head);
}

#[test]
fn genuine_historical_packets_cannot_substitute_for_the_recipients_requested_scope() {
    use crate::findings::review::workpaper::FindingReviewExpectation;

    let (mut f, recorded) = setup(172);
    let open = export(&mut f, &recorded.certificate_digest, None);
    let evidence = vec![f.evidence[0].document_oid];
    let dismissed = apply(
        &mut f,
        &request(
            recorded.finding_ids[0],
            None,
            FindingReviewAction::Dismiss(DismissalReason::Explained),
            evidence,
        ),
    );
    let requested = FindingReviewExpectation {
        book_id: f.book.context().book_id,
        certificate_digest: recorded.certificate_digest,
        review_known_at: dismissed.recorded_at,
    };
    let current = export(
        &mut f,
        &recorded.certificate_digest,
        Some(requested.review_known_at),
    );
    let old_bytes = open.canonical_bytes().unwrap();
    let current_bytes = current.canonical_bytes().unwrap();
    let head = f.head();
    let cx = f.cx();
    // The old packet is genuine and still locally replayable, but does not
    // answer the request. No malformed frame or checksum is involved.
    assert!(
        f.runtime
            .block_on(f.book.replay_finding_review_workpaper(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &old_bytes,
            ))
            .unwrap()
            .is_ok()
    );
    assert!(
        f.runtime
            .block_on(f.book.replay_finding_review_workpaper_for(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &old_bytes,
                &requested,
            ))
            .unwrap()
            .is_err()
    );
    let accepted = f
        .runtime
        .block_on(f.book.replay_finding_review_workpaper_for(
            &cx,
            PRINCIPAL,
            &cap(&["read"]),
            &current_bytes,
            &requested,
        ))
        .unwrap()
        .unwrap();
    assert_eq!(accepted.known_at, requested.review_known_at);
    assert!(matches!(
        accepted.histories[0].status(),
        FindingReviewStatus::Dismissed { .. }
    ));
    assert_eq!(f.head(), head);

    // A different, fully replayable source at the SAME review cutoff must also
    // be refused; both source identity and review cutoff are load-bearing.
    f.post(11, "3000", "1000", 77);
    let second_cert = f.certify("jet.weekend", None);
    f.record(second_cert.digest()).unwrap();
    let head = f.head();
    let second = export(&mut f, second_cert.digest(), Some(head));
    let first_at_head = export(&mut f, &recorded.certificate_digest, Some(head));
    let requested_second = FindingReviewExpectation {
        certificate_digest: *second_cert.digest(),
        review_known_at: head,
        ..requested
    };
    let first_at_head_bytes = first_at_head.canonical_bytes().unwrap();
    assert!(
        f.runtime
            .block_on(f.book.replay_finding_review_workpaper(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &first_at_head_bytes,
            ))
            .unwrap()
            .is_ok()
    );
    assert!(
        f.runtime
            .block_on(f.book.replay_finding_review_workpaper_for(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &first_at_head_bytes,
                &requested_second,
            ))
            .unwrap()
            .is_err()
    );
    assert!(
        f.runtime
            .block_on(f.book.replay_finding_review_workpaper_for(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &second.canonical_bytes().unwrap(),
                &requested_second,
            ))
            .unwrap()
            .is_ok()
    );
    assert_eq!(f.head(), head);
}

#[test]
fn recipient_scope_cannot_supply_authority_or_replace_recomputation() {
    use crate::findings::review::workpaper::FindingReviewExpectation;

    let (mut f, recorded) = setup(173);
    let paper = export(&mut f, &recorded.certificate_digest, None);
    let expected = FindingReviewExpectation {
        book_id: f.book.context().book_id,
        certificate_digest: recorded.certificate_digest,
        review_known_at: paper.review_known_at(),
    };
    let false_text = forged(
        &paper,
        paper.review_known_at(),
        paper.review_jsonl(),
        "No original finding exists.",
    );
    let head = f.head();
    let cx = f.cx();
    assert!(
        f.runtime
            .block_on(f.book.replay_finding_review_workpaper_for(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &false_text,
                &expected,
            ))
            .unwrap()
            .is_err(),
        "correct external scope cannot excuse a false presentation"
    );
    let bytes = paper.canonical_bytes().unwrap();
    let wrong_book = FindingReviewExpectation {
        book_id: Id128([99; 16]),
        ..expected
    };
    assert!(
        f.runtime
            .block_on(f.book.replay_finding_review_workpaper_for(
                &cx,
                PRINCIPAL,
                &cap(&["read"]),
                &bytes,
                &wrong_book,
            ))
            .unwrap()
            .is_err()
    );
    for denied in [
        cap(&["produce"]),
        cap(&["approve"]),
        cap(&["read"]).expiring_at(head),
        cap(&["read"]).for_accounts(&["1000"]).unwrap(),
    ] {
        let refusal = f
            .runtime
            .block_on(f.book.replay_finding_review_workpaper_for(
                &cx,
                PRINCIPAL,
                &denied,
                b"not a workpaper",
                &expected,
            ))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::SAFETY);
    }
    assert_eq!(f.head(), head);
}
