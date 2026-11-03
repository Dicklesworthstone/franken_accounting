//! Large canonical Entries exercise the production posting and batch paths.
//! Fragment boundaries must never split an accounting entry or change its legs.

use super::*;
use fa_journal::entry_storage;
use fa_model::symbols::label;

fn large_legs(h: &Harness) -> Vec<LegPayload> {
    (1..=256).flat_map(|amount| h.rent_legs(amount)).collect()
}

#[test]
fn large_entry_keeps_one_publication_exact_bytes_and_original_retry() {
    let mut h = harness();
    let proposal = h.proposal(large_legs(&h), b"large-fragmented", EntryClass::ORIGINAL);
    let canonical = proposal.clone().seal(Vec::new(), None).unwrap();
    let encoded = canonical.encode().unwrap();
    assert!(encoded.len() > 16_384);
    let before = h.db.frontier().unwrap();
    let posted = h.post(h.request(proposal.clone(), &["post"])).unwrap();
    let at = posted.recorded_at();
    assert_eq!(at.0, before.0 + 1);
    assert!(
        h.db.vertex_at(posted.entry_ref().vid, before)
            .unwrap()
            .is_none()
    );
    let root = h.db.vertex(posted.entry_ref().vid).unwrap().unwrap();
    let stored = fa_journal::rows::bytes(&root, property::FA_PAYLOAD, "entry root").unwrap();
    assert!(entry_storage::is_stored_entry_payload(&stored));
    assert_eq!(
        entry_storage::payload_at(&h.db, &root, at).unwrap(),
        encoded
    );
    assert_eq!(read_entry(&h.db, root.vid).unwrap().unwrap().0, canonical);
    assert_eq!(posted.entry_ref(), canonical.entry_ref(root.vid));
    assert!(entry_storage::mirrors_match(&root, &canonical).unwrap());

    let born =
        h.db.vertices_at(at)
            .unwrap()
            .into_iter()
            .filter(|row| row.created_at == at)
            .collect::<Vec<_>>();
    assert_eq!(
        born.iter()
            .filter(|row| row.labels == [label::ENTRY])
            .count(),
        1
    );
    assert_eq!(
        born.iter().filter(|row| row.labels == [label::LEG]).count(),
        512
    );
    let fragments = born
        .iter()
        .filter(|row| row.labels == [label::ENTRY_FRAGMENT])
        .collect::<Vec<_>>();
    assert_eq!(fragments.len(), encoded.len().div_ceil(4096));
    for fragment in fragments {
        assert_eq!(fragment.created_at, at);
        assert!(h.db.vertex_at(fragment.vid, before).unwrap().is_none());
        assert_eq!(fragment.props.len(), 3);
        assert!(
            fa_journal::rows::bytes(fragment, property::FA_PAYLOAD, "fragment")
                .unwrap()
                .len()
                <= 4096
        );
    }
    assert!(
        fa_journal::verify_projections(&h.db, &h.book, Some(at))
            .unwrap()
            .drift
            .is_empty()
    );
    fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, Some(at)).unwrap();

    let retry = h.post(h.request(proposal, &["post"])).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), posted.entry_ref());
    assert_eq!(retry.recorded_at(), at);
    assert_eq!(h.db.frontier().unwrap(), at);
}

#[test]
fn atomic_large_pending_and_resolution_read_the_same_staged_fragments() {
    let mut h = harness();
    let legs = large_legs(&h);
    let mut pending = h.proposal(legs.clone(), b"large-hold", EntryClass::PENDING);
    pending.pending = Some(Pending {
        timeout_ns: None,
        resolution_of: None,
        disposition: None,
    });
    let reference = h.member_ref(&pending);
    let resolution = h.resolution_posts(reference, legs, (0..512).collect(), b"large-resolution");
    let batch = h.batch(b"large-atomic-lifecycle", vec![pending, resolution]);
    let before = h.db.frontier().unwrap();
    let posted = h.post_batch(batch.clone()).unwrap();
    assert_eq!(posted.recorded_at.0, before.0 + 1);
    assert_eq!(posted.entries.len(), 2);
    for reference in &posted.entries {
        let (entry, at) = read_entry(&h.db, reference.vid).unwrap().unwrap();
        assert_eq!(at, posted.recorded_at);
        assert_eq!(entry.entry_ref(reference.vid), *reference);
        assert_eq!(entry.proposal.legs.len(), 512);
        assert!(entry.encode().unwrap().len() > 16_384);
    }
    assert!(
        fa_journal::verify_projections(&h.db, &h.book, None)
            .unwrap()
            .drift
            .is_empty()
    );
    fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, None).unwrap();
    let retry = h.post_batch(batch).unwrap();
    assert!(retry.already_recorded);
    assert_eq!(retry.entries, posted.entries);
    assert_eq!(h.db.frontier().unwrap(), posted.recorded_at);
}

#[test]
fn changed_fragment_and_identical_restoration_refuse_but_original_prefix_survives() {
    let mut h = harness();
    let proposal = h.proposal(large_legs(&h), b"fragment-corruption", EntryClass::ORIGINAL);
    let posted = h.post(h.request(proposal.clone(), &["post"])).unwrap();
    let intact = posted.recorded_at();
    let fragment =
        h.db.vertices_at(intact)
            .unwrap()
            .into_iter()
            .find(|row| row.labels == [label::ENTRY_FRAGMENT])
            .unwrap();
    let original = fa_journal::rows::bytes(&fragment, property::FA_PAYLOAD, "fragment").unwrap();
    let mut damaged = original.clone();
    damaged[0] ^= 1;
    let mut edit = fgdb::WriteBatch::new(relation::HAS_LEG);
    edit.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(damaged).unwrap()),
    );
    h.write_raw(edit);
    assert!(read_entry(&h.db, posted.entry_ref().vid).is_err());
    assert!(
        fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, None).is_err()
    );
    assert!(
        fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, Some(intact))
            .is_ok()
    );

    // Admission from request metadata must still win over the poisoned body.
    let before = h.db.frontier().unwrap();
    h.post(h.request(proposal, &["read"])).unwrap_err();
    assert_eq!(h.db.frontier().unwrap(), before);

    let mut restore = fgdb::WriteBatch::new(relation::HAS_LEG);
    restore.set_vertex_property(
        fragment.vid,
        property::FA_PAYLOAD,
        Some(CanonicalScalar::bytes(original).unwrap()),
    );
    h.write_raw(restore);
    assert!(read_entry(&h.db, posted.entry_ref().vid).is_err());
    assert!(
        fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, None).is_err()
    );
    let original_root =
        h.db.vertex_at(posted.entry_ref().vid, intact)
            .unwrap()
            .unwrap();
    assert_eq!(
        entry_storage::decode_at(&h.db, &original_root, intact)
            .unwrap()
            .entry_digest,
        posted.entry_ref().entry_digest
    );
}

#[test]
fn previous_native_inline_entries_above_four_kib_remain_readable() {
    let mut h = harness_legacy();
    let legs = (1..=48).flat_map(|amount| h.rent_legs(amount)).collect();
    let proposal = h.proposal(legs, b"legacy-inline-large", EntryClass::ORIGINAL);
    let canonical = proposal.clone().seal(Vec::new(), None).unwrap();
    let bytes = canonical.encode().unwrap();
    assert!(bytes.len() > 4096 && bytes.len() < 12_000);
    let reference = super::outcome_recovery_tests::write_legacy(&mut h, proposal.clone());
    let row = h.db.vertex(reference.vid).unwrap().unwrap();
    let at = row.created_at;
    assert_eq!(entry_storage::payload_at(&h.db, &row, at).unwrap(), bytes);
    assert!(entry_storage::mirrors_match(&row, &canonical).unwrap());
    assert!(!entry_storage::is_stored_entry_payload(
        &fa_journal::rows::bytes(&row, property::FA_PAYLOAD, "legacy root").unwrap()
    ));
    fa_journal::entry_history::verify_entry_history(&h.db, &h.ctx(), &h.book, Some(at)).unwrap();
    let retry = h.post(h.request(proposal, &["post"])).unwrap();
    assert!(matches!(retry, Posted::AlreadyRecorded { .. }));
    assert_eq!(retry.entry_ref(), reference);
    assert_eq!(h.db.frontier().unwrap(), at);
}
