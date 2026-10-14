//! Complete-entry citation inventory API regressions.

#[path = "support/evidence_inventory.rs"]
mod fixture;

#[path = "evidence_inventory/cli.rs"]
mod cli;

use fa_verify::RecordCheck;
use fa_verify::evidence::inventory::{
    InventoryError, validate_citation_request, verify_evidence_inventory_exact,
    verify_evidence_inventory_for,
};
use fa_verify::evidence::{
    EvidenceCitation, EvidenceError, MAX_EVIDENCE_PER_ENTRY, MAX_PROOF_BYTES,
};

fn check(f: &fixture::Fixture) -> Result<Vec<EvidenceCitation>, InventoryError> {
    verify_evidence_inventory_for(&f.proof, &f.checkpoint, &f.entry_digest)
        .map(|inventory| inventory.citations)
}

#[test]
fn complete_inventories_preserve_multiple_roles_and_explicit_empty_lists() {
    for citations in [Vec::new(), fixture::citations()] {
        let f = fixture::proof(&fixture::proposal(&citations).bytes, true, 7);
        let result =
            verify_evidence_inventory_for(&f.proof, &f.checkpoint, &f.entry_digest).unwrap();
        assert_eq!(result.inclusion.scope, "inclusion");
        assert_eq!(result.inclusion.record, RecordCheck::Recomputed);
        assert_eq!(result.citations, citations);
        assert_eq!(
            verify_evidence_inventory_exact(&f.proof, &f.checkpoint, &f.entry_digest, &citations,)
                .unwrap(),
            result
        );
    }
}

#[test]
fn exact_expectations_reject_missing_extra_changed_commitment_and_changed_role() {
    let citations = fixture::citations();
    let f = fixture::proof(&fixture::proposal(&citations).bytes, true, 7);
    assert_eq!(check(&f).unwrap(), citations);
    let mut missing = citations.clone();
    missing.remove(1);
    let mut extra = citations.clone();
    extra.push(fixture::citation([8; 32], 3));
    extra.sort();
    let mut changed_commit = citations.clone();
    changed_commit[0].doc_commit[0] ^= 1;
    changed_commit.sort();
    let mut changed_role = citations.clone();
    changed_role[0].role = 1;
    changed_role.sort();
    for expected in [Vec::new(), missing, extra, changed_commit, changed_role] {
        validate_citation_request(&expected).unwrap();
        assert!(matches!(
            verify_evidence_inventory_exact(&f.proof, &f.checkpoint, &f.entry_digest, &expected,),
            Err(InventoryError::CitationSetMismatch { .. })
        ));
    }
    let empty = fixture::proof(&fixture::proposal(&[]).bytes, true, 7);
    assert!(matches!(
        verify_evidence_inventory_exact(
            &empty.proof,
            &empty.checkpoint,
            &empty.entry_digest,
            &citations,
        ),
        Err(InventoryError::CitationSetMismatch { ordinal: 0 })
    ));
}

#[test]
fn noncanonical_or_over_budget_recipient_sets_refuse_before_invalid_proofs() {
    let citations = fixture::citations();
    let f = fixture::proof(&fixture::proposal(&citations).bytes, true, 7);
    let mut reversed = citations.clone();
    reversed.reverse();
    let duplicate = vec![citations[0], citations[0]];
    let too_many = vec![citations[0]; MAX_EVIDENCE_PER_ENTRY + 1];
    for expected in [reversed, duplicate, too_many] {
        assert!(matches!(
            verify_evidence_inventory_exact(
                b"not a proof",
                &f.checkpoint,
                &f.entry_digest,
                &expected,
            ),
            Err(InventoryError::Request(_))
        ));
    }
}

#[test]
fn every_citation_identity_is_checked_not_only_the_first_selected_document() {
    let mut citations = fixture::citations();
    let f = fixture::proof(&fixture::proposal(&citations).bytes, true, 7);
    assert_eq!(check(&f).unwrap(), citations);
    // Recompute a genuine proof around a false locator after the first row.
    // Authentication alone must not turn inconsistent metadata into a success.
    citations.last_mut().unwrap().document_oid[0] ^= 1;
    citations.sort();
    let f = fixture::proof(&fixture::proposal(&citations).bytes, true, 7);
    assert!(matches!(
        check(&f),
        Err(InventoryError::Evidence(EvidenceError::DocumentIdentity))
    ));
}

#[test]
fn valid_root_and_entry_digest_do_not_excuse_malformed_citation_or_tail_framing() {
    let citations = fixture::citations();
    let good = fixture::proposal(&citations);
    assert_eq!(
        check(&fixture::proof(&good.bytes, true, 7)).unwrap(),
        citations
    );
    let mut reversed = citations.clone();
    reversed.reverse();
    let mut candidates = vec![
        fixture::proposal(&reversed).bytes,
        fixture::proposal(&[citations[0], citations[0]]).bytes,
    ];
    let mut count = good.bytes.clone();
    count[good.count_offset..good.count_offset + 4]
        .copy_from_slice(&((MAX_EVIDENCE_PER_ENTRY + 1) as u32).to_le_bytes());
    candidates.push(count);
    let mut pending_tag = good.bytes.clone();
    pending_tag[good.tail_offset + 4] = 2;
    candidates.push(pending_tag);
    let mut trailing = good.bytes.clone();
    trailing.push(0);
    candidates.push(trailing);
    let mut extensions = good.bytes.clone();
    *extensions.last_mut().unwrap() = 1;
    candidates.push(extensions);
    for bytes in candidates {
        let f = fixture::proof(&bytes, true, 7);
        assert!(check(&f).is_err(), "malformed but rehashed entry accepted");
    }
}

#[test]
fn maximum_canonical_inventory_is_accepted_without_weakening_the_bound() {
    let mut citations: Vec<_> = (0..MAX_EVIDENCE_PER_ENTRY)
        .map(|index| {
            let mut commitment = [0; 32];
            commitment[..8].copy_from_slice(&(index as u64).to_le_bytes());
            fixture::citation(commitment, 3)
        })
        .collect();
    citations.sort();
    let f = fixture::proof(&fixture::proposal(&citations).bytes, true, 7);
    assert_eq!(check(&f).unwrap(), citations);
    assert_eq!(
        verify_evidence_inventory_exact(&f.proof, &f.checkpoint, &f.entry_digest, &citations,)
            .unwrap()
            .citations,
        citations
    );
    citations.push(fixture::citation([99; 32], 3));
    citations.sort();
    assert!(
        check(&fixture::proof(
            &fixture::proposal(&citations).bytes,
            true,
            7
        ))
        .is_err()
    );
}

#[test]
fn recipient_entry_and_checkpoint_are_independent_and_a_record_is_mandatory() {
    let p = fixture::proposal(&fixture::citations());
    let f = fixture::proof(&p.bytes, true, 7);
    assert!(check(&f).is_ok());
    assert!(matches!(
        verify_evidence_inventory_for(&f.proof, &f.checkpoint, &[0xaa; 32],),
        Err(InventoryError::Evidence(EvidenceError::EntryMismatch))
    ));
    let no_record = fixture::proof(&p.bytes, false, 7);
    assert!(matches!(
        check(&no_record),
        Err(InventoryError::Evidence(EvidenceError::RecordRequired))
    ));
    let mut changed = f.checkpoint;
    changed.root[0] ^= 1;
    assert!(verify_evidence_inventory_for(&f.proof, &changed, &f.entry_digest).is_err());
    let unrelated = fixture::proof(&fixture::proposal(&[]).bytes, true, 7);
    assert!(matches!(
        verify_evidence_inventory_for(&unrelated.proof, &unrelated.checkpoint, &f.entry_digest,),
        Err(InventoryError::Evidence(EvidenceError::EntryMismatch))
    ));
}

#[test]
fn all_truncated_proofs_and_trailing_proof_bytes_refuse_without_partial_reports() {
    let f = fixture::proof(&fixture::proposal(&fixture::citations()).bytes, true, 7);
    assert!(check(&f).is_ok());
    for end in 0..f.proof.len() {
        assert!(
            verify_evidence_inventory_for(&f.proof[..end], &f.checkpoint, &f.entry_digest).is_err()
        );
    }
    let mut trailing = f.proof.clone();
    trailing.push(0);
    assert!(verify_evidence_inventory_for(&trailing, &f.checkpoint, &f.entry_digest).is_err());
}

#[test]
fn single_document_verification_remains_compatible_with_the_shared_parser() {
    let doc = b"a cited document";
    let cited = fixture::citation(fa_verify::document::doc_commit(1, doc), 3);
    let mut citations = fixture::citations();
    citations.push(cited);
    citations.sort();
    let f = fixture::proof(&fixture::proposal(&citations).bytes, true, 7);
    assert_eq!(check(&f).unwrap(), citations);
    let mut compact = fixture::Wire::default();
    compact
        .bytes(fa_verify::disclosure::FORMAT)
        .u8(1)
        .u64(doc.len() as u64)
        .u32(1)
        .u64(0)
        .bytes(doc)
        .u32(0);
    let expected = fa_verify::evidence::EvidenceExpectation {
        entry_digest: f.entry_digest,
        document_oid: cited.document_oid,
        role: cited.role,
    };
    let verified = fa_verify::evidence::verify_evidence_disclosure_for(
        &f.proof,
        &compact.0,
        &f.checkpoint,
        &expected,
        &[0],
    )
    .unwrap();
    assert_eq!(verified.citation, cited);
    assert_eq!(verified.disclosure.scope, "membership_only");
}

#[test]
fn library_rejects_oversized_proofs_before_attempting_to_decode_them() {
    let f = fixture::proof(&fixture::proposal(&[]).bytes, true, 7);
    let oversized = vec![0; MAX_PROOF_BYTES + 1];
    assert!(matches!(
        verify_evidence_inventory_for(&oversized, &f.checkpoint, &f.entry_digest,),
        Err(InventoryError::Evidence(EvidenceError::InputLimit))
    ));
}

#[test]
fn legacy_minor_zero_inventory_uses_its_original_tail_without_extensions() {
    let citations = fixture::citations();
    let mut p = fixture::proposal(&citations);
    p.bytes[2..4].copy_from_slice(&0u16.to_le_bytes());
    p.bytes.truncate(p.bytes.len() - 4); // v1.0 has no extension count
    let f = fixture::proof(&p.bytes, true, 7);
    assert_eq!(check(&f).unwrap(), citations);
    p.bytes.push(0);
    let malformed = fixture::proof(&p.bytes, true, 7);
    assert!(check(&malformed).is_err());
}
