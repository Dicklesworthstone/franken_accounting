//! Independent wire fixtures for entries and later supplemental evidence.
//! No journal, producer, keys or storage implementation is linked.

#![allow(dead_code)]

use fa_verify::LeafEnvelope;
use fa_verify::blake3::hash_parts;
use fa_verify::envelope::{
    ENTRY_DIGEST_DOMAIN, KIND_SUPPLEMENTAL_EVIDENCE, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry,
};
use fa_verify::evidence::EvidenceCitation;
use fa_verify::proof::Checkpoint;
use fa_verify::proof::production::ProductionScope;
use fa_verify::proof::production::derivation::PREFIX_FORMAT_V2;
use fa_verify::tree::{leaf_hash, root_of};

use super::fixture::{self, Wire};

#[derive(Clone)]
pub struct Record {
    pub envelope: LeafEnvelope,
    pub payload: Vec<u8>,
    pub split: usize,
}

#[derive(Clone, Copy)]
pub struct Target {
    pub vid: u128,
    pub digest: [u8; 32],
}

fn identity(principal: u128) -> u128 {
    let key = b"evidence-inventory";
    let digest = hash_parts(
        b"fa:vid:entry:v1",
        &[
            &16u32.to_le_bytes(),
            &fixture::BOOK,
            &16u32.to_le_bytes(),
            &principal.to_le_bytes(),
            &(key.len() as u32).to_le_bytes(),
            key,
        ],
    );
    u128::from_le_bytes(digest[..16].try_into().unwrap())
}

pub fn posting(
    principal: u128,
    sequence: u64,
    day: i32,
    citations: &[EvidenceCitation],
) -> (Record, Target) {
    let mut proposal = fixture::proposal(citations);
    proposal.bytes[38..42].copy_from_slice(&day.to_le_bytes());
    // The fixture's principal precedes the absent-session byte and citations.
    let principal_at = proposal.count_offset - 17;
    proposal.bytes[principal_at..principal_at + 16].copy_from_slice(&principal.to_le_bytes());
    let split = proposal.bytes.len();
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&proposal.bytes]);
    let digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[0; 5]]);
    let mut payload = proposal.bytes;
    payload.extend_from_slice(&[0; 5]);
    payload.extend_from_slice(&proposal_digest);
    payload.extend_from_slice(&digest);
    let envelope = envelope_of_entry(&payload, split, sequence, 0).unwrap();
    (
        Record {
            envelope,
            payload,
            split,
        },
        Target {
            vid: identity(principal),
            digest,
        },
    )
}

/// Rehash even deliberately invalid bodies. The verifier must establish the
/// payload's meaning as well as its Merkle membership.
pub fn supplement_body(body: Vec<u8>, sequence: u64, ordinal: u32) -> Record {
    let split = body.len();
    let record_digest = hash_parts(
        b"fa:supplemental-evidence:v1",
        &[&(split as u32).to_le_bytes(), &body],
    );
    let mut payload = body;
    payload.extend_from_slice(&record_digest);
    Record {
        envelope: LeafEnvelope {
            kind: KIND_SUPPLEMENTAL_EVIDENCE,
            book_id: fixture::BOOK,
            branch_id: [0; 16],
            commit_seq: sequence,
            within_commit_ordinal: ordinal,
            record_digest,
            class: 1,
            effective_day: None,
            account_vids: Vec::new(),
            unit_ids: Vec::new(),
        },
        payload,
        split,
    }
}

pub fn supplement(
    target: Target,
    citations: &[EvidenceCitation],
    sequence: u64,
    attached_by: u128,
) -> Record {
    let mut body = Wire::default();
    body.u16(1)
        .fixed(&fixture::BOOK)
        .u128(target.vid)
        .fixed(&target.digest)
        .u32(citations.len() as u32);
    for citation in citations {
        body.fixed(&citation.document_oid)
            .fixed(&citation.doc_commit)
            .u8(citation.role);
    }
    body.u128(attached_by);
    supplement_body(body.0, sequence, 0)
}

pub struct Journal {
    pub prefix: Vec<u8>,
    pub checkpoint: Checkpoint,
}

impl Journal {
    pub fn new(records: &[Record], through_seq: u64) -> Self {
        let leaves: Vec<_> = records
            .iter()
            .map(|record| leaf_hash(&record.envelope.encode()))
            .collect();
        let checkpoint = Checkpoint {
            book_id: fixture::BOOK,
            branch_id: [0; 16],
            through_seq,
            leaf_count: records.len() as u64,
            root: root_of(&leaves),
        };
        let mut prefix = Wire::default();
        prefix
            .bytes(PREFIX_FORMAT_V2)
            .fixed(&checkpoint.encode())
            .u32(records.len() as u32);
        for record in records {
            prefix.bytes(&record.envelope.encode());
        }
        prefix.u32(records.len() as u32);
        for (index, record) in records.iter().enumerate() {
            prefix
                .u64(index as u64)
                .u32(record.split as u32)
                .bytes(&record.payload);
        }
        Self {
            prefix: prefix.0,
            checkpoint,
        }
    }

    pub fn scope(&self) -> ProductionScope {
        ProductionScope {
            first_seq: 0,
            known_at: self.checkpoint.through_seq,
            account: None,
            effective_days: None,
        }
    }
}
