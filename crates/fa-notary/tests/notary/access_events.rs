//! AccessEvent coverage of the signed accumulator (fa-0hs4.12).

use super::*;
use fa_model::{AccessEvent, AccessRecord};

// The facade integration test records through Book::record_access. This
// fixture writes the same canonical native object so it can plant deliberate
// raw-store corruption without adding a facade dependency to the Notary.
fn record_access(h: &mut Harness, command: &str) -> (AccessEvent, CommitSeq) {
    let event = AccessEvent {
        book_id: h.book.book_id,
        record: AccessRecord {
            principal: VId(71),
            principal_name: "examiner".into(),
            capability_commitment: [0x71; 32],
            ops: vec!["read".into()],
            command: command.into(),
            request_digest: fa_model::domain_digest(b"test:access-request", &[command.as_bytes()]),
        },
        observed_at: h.db.frontier().unwrap(),
    };
    let mut properties = vec![
        (
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(event.canonical_bytes().unwrap()).unwrap(),
        ),
        (
            property::FA_DIGEST,
            CanonicalScalar::bytes(event.digest().unwrap().to_vec()).unwrap(),
        ),
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(event.book_id.0.to_vec()).unwrap(),
        ),
    ];
    properties.sort_by_key(|(key, _)| key.0);
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.create_vertex(event.vid().unwrap(), vec![label::ACCESS_EVENT], properties);
    h.write_raw(batch);
    (event, h.db.frontier().unwrap())
}

fn selected(h: &Harness, state: &AccumulatorState) -> Journal {
    Journal::read_with_boundaries(
        &h.db,
        &h.book,
        Some(state.through_seq),
        state.evidence_after,
        state.access_after,
    )
    .unwrap()
    .unwrap()
}

// Construct a correctly framed, deliberately incomplete prefix. Keeping all
// envelopes isolates payload omission; removing both isolates leaf omission.
fn omit_access(journal: &Journal, omitted: usize, omit_envelope: bool) -> Vec<u8> {
    let leaves: Vec<_> = journal
        .leaves
        .iter()
        .enumerate()
        .filter(|(index, _)| !omit_envelope || *index != omitted)
        .collect();
    let mut writer = Writer::new();
    writer.bytes(fa_notary::prefix::PREFIX_FORMAT_V2);
    journal.statement().encode(&mut writer);
    writer.list(&leaves, |writer, (_, leaf)| {
        writer.bytes(&leaf.envelope_bytes);
    });
    writer.u32(u32::try_from(journal.leaves.len() - 1).unwrap());
    let mut emitted = 0;
    for (index, leaf) in journal.leaves.iter().enumerate() {
        if index == omitted {
            continue;
        }
        let claimed_index = if omit_envelope { emitted } else { index };
        writer
            .u64(u64::try_from(claimed_index).unwrap())
            .u32(u32::try_from(leaf.proposal_len).unwrap())
            .bytes(&leaf.payload);
        emitted += 1;
    }
    writer.finish().unwrap()
}

#[test]
fn access_payloads_and_omissions_are_checked_offline_without_changing_balances() {
    let mut h = harness();
    h.post(h.rent, 500, b"access-covered-expense");
    let (first, _) = record_access(&mut h, "statement");
    let (second, _) = record_access(&mut h, "access log");
    let published = h.checkpoint();
    let trusted = outsider_checkpoint(&published);
    let journal = selected(&h, &published.state);
    let first_index = journal.leaf_index(first.vid().unwrap()).unwrap();
    let second_index = journal.leaf_index(second.vid().unwrap()).unwrap();
    assert!(first_index < second_index);
    assert_eq!(
        published.state.access_after,
        Some(fa_notary::state::FIRST_COMMIT)
    );
    for index in [first_index, second_index] {
        let leaf = &journal.leaves[index];
        assert_eq!(leaf.envelope.kind, fa_notary::journal::KIND_ACCESS_EVENT);
        assert_eq!(leaf.proposal_len, leaf.payload.len());
        assert!(leaf.envelope.effective_day.is_none());
        assert!(leaf.envelope.account_vids.is_empty());
        assert!(leaf.envelope.unit_ids.is_empty());
    }
    let proof = fa_notary::prefix::prove_prefix_with_records(&h.db, &h.book, &published.state)
        .unwrap()
        .unwrap();
    fa_verify::proof::production::derivation::verify_prefix_with_records(&proof, &trusted)
        .expect("both access payloads independently rebuild their authenticated leaves");
    for omit_envelope in [false, true] {
        assert!(
            fa_verify::proof::production::derivation::verify_prefix_with_records(
                &omit_access(&journal, first_index, omit_envelope),
                &trusted,
            )
            .is_err(),
            "omitting an access record cannot claim a complete prefix"
        );
    }
    let balance = prove_balance(&h.db, &h.book, &published.state, h.rent, h.usd.0, None)
        .unwrap()
        .unwrap();
    let verified = fa_verify::verify_balance(&balance, &trusted).unwrap();
    assert_eq!((verified.claim.debits, verified.claim.credits), (500, 0));
    assert_eq!(verified.contributing.len(), 1);
    assert!(
        verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer)
            .unwrap()
            .is_green()
    );
}

#[test]
fn access_event_rewrite_after_checkpoint_is_detected() {
    for change in [
        "payload and recomputed digest",
        "delete",
        "relabel",
        "extra label",
        "digest",
        "book mirror",
    ] {
        let mut h = harness();
        let (event, _) = record_access(&mut h, "statement");
        let vid = event.vid().unwrap();
        let old = h.checkpoint();
        let trusted = outsider_checkpoint(&old);
        let saved = prove_inclusion(&h.db, &h.book, &old.state, vid, true)
            .unwrap()
            .unwrap();
        let before = selected(&h, &old.state);
        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        match change {
            "payload and recomputed digest" => {
                let mut forged = event.clone();
                forged.record.principal = VId(event.record.principal.0 + 1);
                let payload = forged.canonical_bytes().unwrap();
                assert_eq!(AccessEvent::decode(&payload).unwrap(), forged);
                batch.set_vertex_property(
                    vid,
                    property::FA_PAYLOAD,
                    Some(CanonicalScalar::bytes(payload).unwrap()),
                );
                batch.set_vertex_property(
                    vid,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(forged.digest().unwrap().to_vec()).unwrap()),
                );
            }
            "delete" => {
                batch.delete_vertex(vid);
            }
            "relabel" => {
                batch.set_vertex_label(vid, label::ACCESS_EVENT, false);
            }
            "extra label" => {
                batch.set_vertex_label(vid, label::ENTRY, true);
            }
            "digest" => {
                batch.set_vertex_property(
                    vid,
                    property::FA_DIGEST,
                    Some(CanonicalScalar::bytes(vec![0xee; 32]).unwrap()),
                );
            }
            "book mirror" => {
                batch.set_vertex_property(
                    vid,
                    property::BOOK_ID,
                    Some(CanonicalScalar::bytes(vec![0xee; 16]).unwrap()),
                );
            }
            _ => unreachable!(),
        };
        h.write_raw(batch);
        let attacked_head = h.db.frontier().unwrap();
        assert_eq!(
            selected(&h, &old.state),
            before,
            "historical snapshots still exist"
        );
        let found = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
        assert!(!found.is_green(), "{change}: {found:?}");
        assert!(
            found.states.iter().any(|state| state
                .finding
                .as_deref()
                .is_some_and(|finding| finding.contains(&format!("{:032x}", vid.0)))),
            "{change}: the finding identifies the corrupted access event: {found:?}"
        );
        for refused in [
            prove_inclusion(&h.db, &h.book, &old.state, vid, true),
            fa_notary::prefix::prove_prefix_with_records(&h.db, &h.book, &old.state),
        ] {
            let refusal = refused.unwrap().unwrap_err();
            assert_eq!(refusal.code, code::ACCUMULATOR_DRIFT, "{change}");
            assert_eq!(refusal.exit, exit::VERIFICATION, "{change}");
        }
        assert_eq!(
            h.checkpoint_refusal().code,
            code::ACCUMULATOR_DRIFT,
            "{change}"
        );
        assert_eq!(
            h.db.frontier().unwrap(),
            attacked_head,
            "refusals publish nothing"
        );
        fa_verify::verify_inclusion(&saved, &trusted)
            .expect("a previously saved proof remains valid historical evidence");
    }
}

#[test]
fn legacy_checkpoint_keeps_its_bytes_and_access_coverage_starts_at_its_prefix() {
    let mut h = harness();
    let (uncovered, _) = record_access(&mut h, "legacy read");
    let legacy = h.plant_first_checkpoint(h.db.frontier().unwrap(), None);
    let legacy_bytes = legacy.stored.bytes.clone();
    assert_eq!(legacy.stored.state.access_after, None);
    assert_eq!(&legacy_bytes[2..4], &1u16.to_le_bytes());
    assert!(
        selected(&h, &legacy.stored.state)
            .leaf_index(uncovered.vid().unwrap())
            .is_none()
    );

    let (covered, _) = record_access(&mut h, "covered read");
    let next = h.checkpoint();
    assert_eq!(
        next.state.access_after,
        Some(legacy.stored.state.through_seq)
    );
    assert_eq!(
        next.state.evidence_after,
        legacy.stored.state.evidence_after
    );
    let journal = selected(&h, &next.state);
    assert!(journal.leaf_index(uncovered.vid().unwrap()).is_none());
    assert!(journal.leaf_index(covered.vid().unwrap()).is_some());
    let old_anchor = outsider_checkpoint(&legacy.stored);
    let new_anchor = outsider_checkpoint(&next);
    let consistency = prove_consistency(
        &h.db,
        &h.book,
        &legacy.stored.state.statement(),
        &next.state,
    )
    .unwrap()
    .unwrap();
    fa_verify::verify_consistency(&consistency, &old_anchor, &new_anchor).unwrap();
    let retained = chain(&h.db, None).unwrap();
    assert_eq!(
        retained
            .iter()
            .find(|state| state.oid == legacy.stored.oid)
            .unwrap()
            .bytes,
        legacy_bytes
    );
    assert!(
        verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer)
            .unwrap()
            .is_green()
    );
}

fn coverage_refusal<T: core::fmt::Debug>(
    result: fa_journal::refusal::Outcome<T>,
    operation: &str,
    expected_finding: &str,
) {
    let refusal = result.unwrap().expect_err(operation);
    assert_eq!(refusal.code, code::ACCUMULATOR_DRIFT, "{operation}");
    assert_eq!(refusal.exit, exit::VERIFICATION, "{operation}");
    assert!(
        refusal.message.contains(expected_finding),
        "{operation}: {refusal:?}"
    );
}

fn assert_coverage_production_refused(
    h: &mut Harness,
    state: &AccumulatorState,
    previous: &fa_notary::Statement,
    expected_finding: &str,
) {
    let observed_at = h.db.frontier().unwrap();
    // An actual covered entry isolates coverage admission from target lookup.
    let target = selected(h, state).leaves[0].vid;
    for (operation, result) in [
        (
            "inclusion",
            prove_inclusion(&h.db, &h.book, state, target, true),
        ),
        ("prefix envelopes", prove_prefix(&h.db, &h.book, state)),
        (
            "complete prefix",
            fa_notary::prefix::prove_prefix_with_records(&h.db, &h.book, state),
        ),
        (
            "consistency",
            prove_consistency(&h.db, &h.book, previous, state),
        ),
        (
            "balance",
            prove_balance(&h.db, &h.book, state, h.rent, h.usd.0, None),
        ),
        (
            "complete balance",
            fa_notary::migration_balance::prove_balance_complete(
                &h.db, &h.book, state, h.rent, h.usd.0, None,
            ),
        ),
    ] {
        coverage_refusal(result, operation, expected_finding);
    }
    coverage_refusal(
        fa_notary::prefix::prove_suffix_with_records(
            &h.db,
            &h.book,
            previous,
            state,
            fa_notary::prefix::MAX_PREFIX_PROOF_BYTES,
        ),
        "complete suffix",
        expected_finding,
    );
    let refusal = h.checkpoint_refusal();
    assert_eq!(refusal.code, code::ACCUMULATOR_DRIFT);
    assert_eq!(refusal.exit, exit::VERIFICATION);
    assert!(refusal.message.contains(expected_finding), "{refusal:?}");
    assert_eq!(
        h.db.frontier().unwrap(),
        observed_at,
        "refusals publish nothing"
    );
}

#[test]
fn access_coverage_cannot_be_moved_forward_or_downgraded() {
    for downgrade in [false, true] {
        let mut h = harness();
        h.checkpoint();
        record_access(&mut h, "covered read");
        let covered = h.checkpoint();
        let boundary = if downgrade {
            None
        } else {
            Some(covered.state.through_seq)
        };
        let hidden = Journal::read_with_boundaries(
            &h.db,
            &h.book,
            None,
            covered.state.evidence_after,
            boundary,
        )
        .unwrap()
        .unwrap();
        let forged = AccumulatorState::of_journal(&hidden, Some(covered.oid));
        h.plant_state(&forged, Some(covered.oid));
        let found = verify_accumulator(&h.db, &h.ctx(), &h.book, &h.signer).unwrap();
        assert!(
            found.states[0]
                .finding
                .as_deref()
                .is_some_and(|finding| finding.contains("access boundary")),
            "downgrade={downgrade}: {found:?}"
        );
        assert!(
            found.states[1..]
                .iter()
                .all(|state| state.finding.is_none())
        );
        assert_coverage_production_refused(
            &mut h,
            &forged,
            &covered.state.statement(),
            "access boundary",
        );
        assert!(
            prove_prefix(&h.db, &h.book, &covered.state)
                .unwrap()
                .is_ok()
        );
    }
}

#[test]
fn an_apparently_valid_successor_cannot_hide_its_ancestors_access_downgrade() {
    for downgrade in [false, true] {
        let mut h = harness();
        h.checkpoint();
        record_access(&mut h, "covered read");
        let covered = h.checkpoint();
        let hidden = Journal::read_with_boundaries(
            &h.db,
            &h.book,
            None,
            covered.state.evidence_after,
            if downgrade {
                None
            } else {
                Some(covered.state.through_seq)
            },
        )
        .unwrap()
        .unwrap();
        let bad_ancestor = AccumulatorState::of_journal(&hidden, Some(covered.oid));
        let (bad_oid, _) = h.plant_state(&bad_ancestor, Some(covered.oid));

        // The child obeys the immediate predecessor's declared boundary. A
        // one-link admission check would miss the illegal ancestor transition.
        let next_boundary = fa_notary::state::chained_access_boundary(Some(&bad_ancestor));
        let child_journal = Journal::read_with_boundaries(
            &h.db,
            &h.book,
            None,
            bad_ancestor.evidence_after,
            Some(next_boundary),
        )
        .unwrap()
        .unwrap();
        let child = AccumulatorState::of_journal(&child_journal, Some(bad_oid));
        h.plant_state(&child, Some(bad_oid));
        assert_eq!(selected(&h, &child), child_journal);
        assert_coverage_production_refused(
            &mut h,
            &child,
            &covered.state.statement(),
            "access boundary",
        );
        assert!(
            prove_prefix(&h.db, &h.book, &covered.state)
                .unwrap()
                .is_ok()
        );
    }
}

#[test]
fn a_legacy_ancestor_cannot_claim_future_history_to_hide_later_access() {
    let mut h = harness();
    let head = h.db.frontier().unwrap();
    let legacy_journal = Journal::read(
        &h.db,
        &h.book,
        Some(head),
        Some(fa_notary::state::FIRST_COMMIT),
    )
    .unwrap()
    .unwrap();
    let mut legacy = AccumulatorState::of_journal(&legacy_journal, None);
    legacy.through_seq = CommitSeq(head.0 + 2);
    let (legacy_oid, recorded_at) = h.plant_state(&legacy, None);
    assert_eq!(recorded_at, CommitSeq(head.0 + 1));
    assert!(recorded_at < legacy.through_seq);

    // The access occurs after the legacy object was recorded, but within
    // its impossible claimed prefix. Its v1 leaf population still reproduces
    // because the old format never accumulated access events.
    let (hidden, access_recorded_at) = record_access(&mut h, "hidden future read");
    assert_eq!(access_recorded_at, legacy.through_seq);
    assert_eq!(
        AccumulatorState::of_journal(&selected(&h, &legacy), None),
        legacy
    );
    h.post(h.rent, 1, b"after-future-access-cut");

    let child_journal = Journal::read_with_boundaries(
        &h.db,
        &h.book,
        None,
        legacy.evidence_after,
        Some(legacy.through_seq),
    )
    .unwrap()
    .unwrap();
    assert!(child_journal.leaf_index(hidden.vid().unwrap()).is_none());
    let child = AccumulatorState::of_journal(&child_journal, Some(legacy_oid));
    assert!(legacy.through_seq < child.through_seq);
    assert!(recorded_at <= child.through_seq);
    assert!(legacy.leaf_count <= child.leaf_count);
    h.plant_state(&child, Some(legacy_oid));
    assert_eq!(selected(&h, &child), child_journal);

    // Both roots and both boundary choices reproduce. The ancestor's
    // actual recording time must nevertheless block every new production.
    assert_coverage_production_refused(
        &mut h,
        &child,
        &legacy.statement(),
        "coverage ancestor was recorded at",
    );
}
