//! Real postings and attachments exported by Notary, checked independently.
//! Re-pinned negative fixtures test semantic joins after proof hashes pass.

use super::*;
use fa_journal::evidence::{EvidenceAttached, SupplementalEvidence, attach_evidence};
use fa_journal::post::read_entry;
use fa_model::{EntryRef, Supersession, SupersessionKind};
use fa_verify::evidence::inventory::production::documents::{
    DocumentContent, verify_document_prefix_for,
};
use fa_verify::evidence::inventory::production::prefix::verify_evidence_prefix_for;
use fa_verify::evidence::inventory::production::supplements::{
    verify_supplemented_document_prefix_for, verify_supplemented_evidence_prefix_for,
};
use fa_verify::proof::production::ProductionScope;
use fa_verify::proof::production::derivation::verify_prefix_with_records;

fn entry_ref(h: &Harness, vid: VId) -> EntryRef {
    read_entry(&h.db, vid)
        .unwrap()
        .expect("committed entry")
        .0
        .entry_ref(vid)
}

fn attach(h: &mut Harness, target: EntryRef, mut documents: Vec<EvidenceRef>) -> EvidenceAttached {
    documents.sort_unstable();
    let supplement = SupplementalEvidence {
        book_id: h.book.book_id,
        entry_ref: target,
        documents,
        attached_by: PRINCIPAL,
    };
    let ctx = h.ctx();
    h.runtime
        .block_on(attach_evidence(
            &mut h.db,
            &ctx,
            &h.book,
            &Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            &supplement,
        ))
        .expect("attachment storage")
        .expect("attachment admitted")
}

fn document(h: &Harness, citation: EvidenceRef) -> Document {
    read_document(&h.db, &citation.document_oid)
        .unwrap()
        .unwrap()
        .expect("retained full document")
}

fn contents(documents: &[Document]) -> Vec<DocumentContent<'_>> {
    documents
        .iter()
        .map(|document| DocumentContent {
            document_oid: document.oid().0,
            kind: document.kind,
            bytes: &document.bytes,
        })
        .collect()
}

struct History {
    journal: Journal,
    prefix: Vec<u8>,
    checkpoint: fa_verify::Checkpoint,
    scope: ProductionScope,
    first: EntryRef,
    second: EntryRef,
    first_recorded_at: u64,
    second_recorded_at: u64,
    attached: [EvidenceAttached; 3],
    original: EvidenceRef,
    shared: EvidenceRef,
    later: EvidenceRef,
    documents: Vec<Document>,
}

fn history() -> History {
    let mut h = harness();
    let original = h.evidence[0];
    let first_vid = h.post(h.rent, 500, b"supplement-production-first");
    let first = entry_ref(&h, first_vid);
    let first_recorded_at = h.db.frontier().unwrap().0;
    let shared = h.document(b"Receipt shared by two postings and two roles", 2);
    let mut contract = shared;
    contract.role = 4;
    let first_attachment = attach(&mut h, first, vec![shared, contract]);
    let second_vid = h.post(h.rent, 700, b"supplement-production-second");
    let second = entry_ref(&h, second_vid);
    let second_recorded_at = h.db.frontier().unwrap().0;
    let second_attachment = attach(&mut h, second, vec![shared]);
    let later = h.document(b"Confirmation obtained after both original postings", 2);
    let later_attachment = attach(&mut h, first, vec![later]);
    let stored = h.checkpoint();
    let checkpoint = outsider_checkpoint(&stored);
    let journal = Journal::read_with_boundaries(
        &h.db,
        &h.book,
        Some(stored.state.through_seq),
        stored.state.evidence_after,
        stored.state.access_after,
    )
    .unwrap()
    .unwrap();
    let prefix = fa_notary::prefix::prove_prefix_with_records(&h.db, &h.book, &stored.state)
        .unwrap()
        .unwrap();
    let mut documents = [original, shared, later]
        .map(|citation| document(&h, citation))
        .to_vec();
    documents.sort_by_key(Document::oid);
    History {
        journal,
        prefix,
        checkpoint,
        scope: ProductionScope {
            first_seq: first_recorded_at,
            known_at: checkpoint.through_seq,
            account: Some(h.rent.0),
            effective_days: Some((
                DateDay::from_ymd(2026, 3, 15).unwrap().0,
                DateDay::from_ymd(2026, 3, 15).unwrap().0,
            )),
        },
        first,
        second,
        first_recorded_at,
        second_recorded_at,
        attached: [first_attachment, second_attachment, later_attachment],
        original,
        shared,
        later,
        documents,
    }
}

#[test]
fn native_supplemented_production_preserves_originals_and_every_role_association() {
    let h = history();
    let original = verify_evidence_prefix_for(&h.prefix, &h.checkpoint, &h.scope).unwrap();
    let inventory =
        verify_supplemented_evidence_prefix_for(&h.prefix, &h.checkpoint, &h.scope).unwrap();
    assert_eq!(inventory.inventory, original);
    assert_eq!(original.entries.len(), 2);
    assert_eq!(original.citation_count, 2);
    assert_eq!(inventory.supplements.len(), 3);
    assert_eq!(inventory.citation_count, 6);
    for (supplement, recorded) in inventory.supplements.iter().zip(&h.attached) {
        assert_eq!(supplement.recorded_at, recorded.recorded_at.0);
        assert_eq!(supplement.record_digest, recorded.body_digest);
        assert_eq!(supplement.attached_by, PRINCIPAL.0);
        assert_eq!(
            supplement.leaf_index,
            u64::try_from(h.journal.leaf_index(recorded.vid).unwrap()).unwrap()
        );
    }
    assert_eq!(inventory.supplements[0].entry_vid, h.first.vid.0);
    assert_eq!(inventory.supplements[0].entry_digest, h.first.entry_digest);
    assert_eq!(inventory.supplements[1].entry_vid, h.second.vid.0);
    assert_eq!(inventory.supplements[2].entry_vid, h.first.vid.0);
    assert_eq!(
        inventory.supplements[0]
            .citations
            .iter()
            .map(|citation| (citation.document_oid, citation.role))
            .collect::<Vec<_>>(),
        vec![(h.shared.document_oid.0, 2), (h.shared.document_oid.0, 4)]
    );

    let produced = verify_supplemented_document_prefix_for(
        &h.prefix,
        &contents(&h.documents),
        &h.checkpoint,
        &h.scope,
    )
    .unwrap();
    assert_eq!(produced.inventory, inventory);
    assert_eq!(produced.document_scope, "recomputation");
    assert_eq!(produced.documents.len(), 3);
    for (citation, count) in [(h.original, 2), (h.shared, 3), (h.later, 1)] {
        let document = produced
            .documents
            .iter()
            .find(|document| document.document_oid == citation.document_oid.0)
            .unwrap();
        assert_eq!(document.doc_commit, citation.doc_commit);
        assert_eq!(document.citation_count, count);
    }
    assert_eq!(
        produced.document_byte_count,
        h.documents
            .iter()
            .map(|document| u64::try_from(document.bytes.len()).unwrap())
            .sum::<u64>()
    );
}

#[test]
fn historical_scope_selects_targets_then_only_supplements_known_at_the_requested_cut() {
    let h = history();
    for (known_at, supplements, citations, required_documents) in [
        (h.first_recorded_at, 0, 1, vec![h.original.document_oid]),
        (
            h.attached[0].recorded_at.0,
            1,
            3,
            vec![h.original.document_oid, h.shared.document_oid],
        ),
    ] {
        let scope = ProductionScope {
            known_at,
            ..h.scope
        };
        let documents: Vec<_> = h
            .documents
            .iter()
            .filter(|document| required_documents.contains(&document.oid()))
            .cloned()
            .collect();
        let verified = verify_supplemented_document_prefix_for(
            &h.prefix,
            &contents(&documents),
            &h.checkpoint,
            &scope,
        )
        .unwrap();
        assert_eq!(verified.inventory.inventory.entries.len(), 1);
        assert_eq!(verified.inventory.supplements.len(), supplements);
        assert_eq!(verified.inventory.citation_count, citations);
        assert_eq!(verified.documents.len(), required_documents.len());
    }
    // A late attachment to an earlier, excluded target does not become a
    // selected entry merely because the attachment is in the recorded range.
    let scope = ProductionScope {
        first_seq: h.second_recorded_at,
        ..h.scope
    };
    let verified =
        verify_supplemented_evidence_prefix_for(&h.prefix, &h.checkpoint, &scope).unwrap();
    assert_eq!(verified.inventory.entries.len(), 1);
    assert_eq!(verified.supplements.len(), 1);
    assert_eq!(verified.supplements[0].entry_vid, h.second.vid.0);
    assert_eq!(verified.citation_count, 2);
    for scope in [
        ProductionScope {
            account: Some(u128::MAX),
            ..h.scope
        },
        ProductionScope {
            effective_days: Some((0, 0)),
            ..h.scope
        },
    ] {
        let verified =
            verify_supplemented_evidence_prefix_for(&h.prefix, &h.checkpoint, &scope).unwrap();
        assert!(verified.inventory.entries.is_empty());
        assert!(verified.supplements.is_empty());
        assert_eq!(verified.citation_count, 0);
    }
}

#[test]
fn full_document_union_requires_added_files_and_rejects_wrong_bytes_and_extra_copies() {
    let h = history();
    let documents = contents(&h.documents);
    let original: Vec<_> = documents
        .iter()
        .copied()
        .filter(|document| document.document_oid == h.original.document_oid.0)
        .collect();
    verify_document_prefix_for(&h.prefix, &original, &h.checkpoint, &h.scope).unwrap();
    assert!(
        verify_supplemented_document_prefix_for(&h.prefix, &original, &h.checkpoint, &h.scope)
            .is_err(),
        "the complete original file set is insufficient after attachments"
    );
    let without_later: Vec<_> = documents
        .iter()
        .copied()
        .filter(|document| document.document_oid != h.later.document_oid.0)
        .collect();
    assert!(
        verify_supplemented_document_prefix_for(
            &h.prefix,
            &without_later,
            &h.checkpoint,
            &h.scope,
        )
        .is_err()
    );
    let mut wrong_bytes = documents.clone();
    let late = wrong_bytes
        .iter_mut()
        .find(|document| document.document_oid == h.later.document_oid.0)
        .unwrap();
    late.bytes = b"different retained document bytes";
    assert!(
        verify_supplemented_document_prefix_for(&h.prefix, &wrong_bytes, &h.checkpoint, &h.scope,)
            .is_err()
    );
    let mut duplicate = documents.clone();
    duplicate.insert(0, documents[0]);
    assert!(
        verify_supplemented_document_prefix_for(&h.prefix, &duplicate, &h.checkpoint, &h.scope,)
            .is_err()
    );
    let earlier = ProductionScope {
        known_at: h.first_recorded_at,
        ..h.scope
    };
    assert!(
        verify_supplemented_document_prefix_for(&h.prefix, &documents, &h.checkpoint, &earlier,)
            .is_err(),
        "files from later attachments are extra at an earlier known-at"
    );
}

// Re-encode the native transport with an independently supplied checkpoint.
// This lets negative cases isolate omission and semantic checks from signing.
fn prefix_bytes(
    journal: &Journal,
    checkpoint: &fa_verify::Checkpoint,
    replacement: Option<(usize, Vec<u8>, Vec<u8>)>,
    omitted: Option<(usize, bool)>,
) -> Vec<u8> {
    let mut writer = Writer::new();
    writer
        .bytes(fa_notary::prefix::PREFIX_FORMAT_V2)
        .fixed(&checkpoint.encode());
    let envelopes: Vec<_> = journal
        .leaves
        .iter()
        .enumerate()
        .filter(|(index, _)| omitted != Some((*index, true)))
        .collect();
    writer.list(&envelopes, |writer, (index, leaf)| {
        let envelope = replacement
            .as_ref()
            .filter(|(changed, _, _)| changed == index)
            .map_or(leaf.envelope_bytes.as_slice(), |(_, envelope, _)| envelope);
        writer.bytes(envelope);
    });
    writer.u32(u32::try_from(journal.leaves.len() - usize::from(omitted.is_some())).unwrap());
    let mut emitted = 0u64;
    for (index, leaf) in journal.leaves.iter().enumerate() {
        if omitted.is_some_and(|(omitted, _)| omitted == index) {
            continue;
        }
        let changed = replacement
            .as_ref()
            .filter(|(changed, _, _)| *changed == index);
        let payload = changed.map_or(leaf.payload.as_slice(), |(_, _, payload)| payload);
        let split = changed.map_or(leaf.proposal_len, |(_, _, payload)| payload.len() - 32);
        let index = if omitted.is_some_and(|(_, envelope)| envelope) {
            emitted
        } else {
            u64::try_from(index).unwrap()
        };
        writer
            .u64(index)
            .u32(u32::try_from(split).unwrap())
            .bytes(payload);
        emitted += 1;
    }
    writer.finish().unwrap()
}

#[test]
fn supplemental_prefix_omission_and_tampering_fail_even_for_an_earlier_selection() {
    let h = history();
    assert_eq!(
        prefix_bytes(&h.journal, &h.checkpoint, None, None),
        h.prefix,
        "the negative-case encoder preserves the genuine complete witness"
    );
    let index = h.journal.leaf_index(h.attached[2].vid).unwrap();
    let earlier = ProductionScope {
        known_at: h.first_recorded_at,
        ..h.scope
    };
    for omit_envelope in [false, true] {
        let incomplete = prefix_bytes(
            &h.journal,
            &h.checkpoint,
            None,
            Some((index, omit_envelope)),
        );
        assert!(
            verify_supplemented_evidence_prefix_for(&incomplete, &h.checkpoint, &earlier).is_err(),
            "the later attachment still belongs to the authenticated full prefix"
        );
    }
    let leaf = &h.journal.leaves[index];
    let mut payload = leaf.payload.clone();
    payload[18] ^= 1; // target VID, without rehashing its body
    let tampered = prefix_bytes(
        &h.journal,
        &h.checkpoint,
        Some((index, leaf.envelope_bytes.clone(), payload)),
        None,
    );
    assert!(verify_supplemented_evidence_prefix_for(&tampered, &h.checkpoint, &earlier).is_err());
    assert!(
        verify_supplemented_evidence_prefix_for(
            &h.journal.prefix_proof().unwrap(),
            &h.checkpoint,
            &h.scope,
        )
        .is_err(),
        "an envelope-only prefix cannot establish the complete supplement joins"
    );
}

fn repinned_supplement(
    h: &History,
    index: usize,
    supplement: &SupplementalEvidence,
) -> (Vec<u8>, fa_verify::Checkpoint) {
    let payload = supplement.canonical_bytes().unwrap();
    let mut envelope = h.journal.leaves[index].envelope_bytes.clone();
    // Native envelope wire: kind, book, branch, sequence, ordinal, digest.
    envelope[1..17].copy_from_slice(&supplement.book_id.0);
    envelope[45..77].copy_from_slice(&supplement.body_digest().unwrap());
    let leaves: Vec<_> = h
        .journal
        .leaves
        .iter()
        .enumerate()
        .map(|(position, leaf)| {
            fa_verify::tree::leaf_hash(if position == index {
                &envelope
            } else {
                &leaf.envelope_bytes
            })
        })
        .collect();
    let checkpoint = fa_verify::Checkpoint {
        root: fa_verify::tree::root_of(&leaves),
        ..h.checkpoint
    };
    let prefix = prefix_bytes(
        &h.journal,
        &checkpoint,
        Some((index, envelope, payload)),
        None,
    );
    (prefix, checkpoint)
}

#[test]
fn repinned_supplements_cannot_claim_another_target_digest_future_entry_or_document_oid() {
    let h = history();
    let index = h.journal.leaf_index(h.attached[0].vid).unwrap();
    let original = SupplementalEvidence::decode(&h.journal.leaves[index].payload).unwrap();
    assert!(h.attached[0].recorded_at.0 < h.second_recorded_at);
    for defect in [
        "target VID",
        "target digest",
        "future target",
        "document locator",
    ] {
        let mut changed = original.clone();
        match defect {
            "target VID" => changed.entry_ref.vid = VId(u128::MAX),
            "target digest" => changed.entry_ref.entry_digest[0] ^= 1,
            "future target" => changed.entry_ref = h.second,
            "document locator" => {
                changed.documents[0].document_oid.0[0] ^= 1;
                changed.documents.sort_unstable();
            }
            _ => unreachable!(),
        }
        let (prefix, checkpoint) = repinned_supplement(&h, index, &changed);
        verify_prefix_with_records(&prefix, &checkpoint)
            .expect("re-pinned record hashes and derived selectors are internally consistent");
        let earlier = ProductionScope {
            known_at: h.first_recorded_at,
            ..h.scope
        };
        let before_attachment =
            verify_supplemented_evidence_prefix_for(&prefix, &checkpoint, &earlier).unwrap();
        assert_eq!(before_attachment.inventory.entries.len(), 1);
        assert!(before_attachment.supplements.is_empty());
        for scope in [
            h.scope,
            ProductionScope {
                account: Some(u128::MAX),
                ..h.scope
            },
        ] {
            assert!(
                verify_supplemented_evidence_prefix_for(&prefix, &checkpoint, &scope).is_err(),
                "{defect}: an excluded target cannot hide an invalid known supplement"
            );
        }
    }
    let mut foreign = original;
    foreign.book_id = Id128([0x99; 16]);
    let (prefix, checkpoint) = repinned_supplement(&h, index, &foreign);
    assert!(
        verify_supplemented_evidence_prefix_for(&prefix, &checkpoint, &h.scope).is_err(),
        "re-pinning cannot put another book's attachment into this checkpoint"
    );
}

#[test]
fn an_attachment_requires_a_target_committed_before_its_own_publication() {
    let h = history();
    let target = h.journal.leaves[h.journal.leaf_index(h.first.vid).unwrap()]
        .record()
        .unwrap();
    let supplement = h.journal.leaves[h.journal.leaf_index(h.attached[0].vid).unwrap()]
        .record()
        .unwrap();
    // A synthetic checkpoint keeps real native payloads but claims that the
    // two were born together. The arbitrary higher supplement VID forces its
    // leaf after the target, so a position-only test would wrongly accept it.
    // AttachEvidence requires an already committed target in its own txn.
    let journal = Journal::from_records_with_evidence(
        h.journal.book_id,
        CommitSeq(2),
        Some(CommitSeq(1)),
        vec![
            (h.first.vid, target, CommitSeq(2)),
            (VId(u128::MAX), supplement, CommitSeq(2)),
        ],
    )
    .unwrap();
    let state = AccumulatorState::of_journal(&journal, None);
    let checkpoint = fa_verify::verify_state(&state.canonical_bytes().unwrap())
        .unwrap()
        .checkpoint;
    let prefix = journal.prefix_proof_with_records().unwrap().unwrap();
    verify_prefix_with_records(&prefix, &checkpoint).unwrap();
    assert_eq!(journal.leaves[0].envelope.within_commit_ordinal, 0);
    assert_eq!(journal.leaves[1].envelope.within_commit_ordinal, 1);
    let scope = ProductionScope {
        first_seq: 0,
        known_at: 2,
        ..h.scope
    };
    assert!(verify_supplemented_evidence_prefix_for(&prefix, &checkpoint, &scope).is_err());
}

#[test]
fn actual_reversal_target_uses_its_target_derived_vid_in_offline_attachment_joins() {
    let mut h = harness();
    let target_vid = h.post(h.rent, 500, b"supplement-reversal-source");
    let (entry, _) = read_entry(&h.db, target_vid).unwrap().unwrap();
    let target = entry.entry_ref(target_vid);
    let mut reversed = entry.proposal;
    reversed.class = EntryClass::REVERSAL;
    reversed.idempotency_key = b"supplement-reversal".to_vec();
    reversed.supersession = vec![Supersession {
        target,
        kind: SupersessionKind::Reverses,
        reason_code: 1,
    }];
    for leg in &mut reversed.legs {
        leg.side = leg.side.flipped();
    }
    reversed.unit_totals = EntryPayload::fold_unit_totals(&reversed.legs).unwrap();
    let ordinary_vid = fa_model::entry_vid(
        h.book.book_id,
        &PRINCIPAL.0.to_le_bytes(),
        &reversed.idempotency_key,
    );
    let ctx = h.ctx();
    let posted = h
        .runtime
        .block_on(post(
            &mut h.db,
            &ctx,
            &h.book,
            PostRequest {
                proposal: reversed,
                approvals: Vec::new(),
                plan_certificate: None,
                capability: Capability::embedded(PRINCIPAL, &["post"]).unwrap(),
            },
        ))
        .unwrap()
        .unwrap();
    let reversal = posted.entry_ref();
    assert_eq!(reversal.vid, fa_journal::rows::reversal_vid(target_vid));
    assert_ne!(reversal.vid, ordinary_vid);
    let supporting = h.document(b"Reviewer explanation of the exact undo", 2);
    let attached = attach(&mut h, reversal, vec![supporting]);
    let stored = h.checkpoint();
    let checkpoint = outsider_checkpoint(&stored);
    let prefix = fa_notary::prefix::prove_prefix_with_records(&h.db, &h.book, &stored.state)
        .unwrap()
        .unwrap();
    let scope = ProductionScope {
        first_seq: 0,
        known_at: checkpoint.through_seq,
        account: Some(h.rent.0),
        effective_days: None,
    };
    let verified = verify_supplemented_evidence_prefix_for(&prefix, &checkpoint, &scope).unwrap();
    assert_eq!(verified.inventory.entries.len(), 2);
    assert_eq!(verified.supplements.len(), 1);
    assert_eq!(verified.supplements[0].entry_vid, reversal.vid.0);
    assert_eq!(verified.supplements[0].entry_digest, reversal.entry_digest);
    assert_eq!(verified.supplements[0].recorded_at, attached.recorded_at.0);
}
