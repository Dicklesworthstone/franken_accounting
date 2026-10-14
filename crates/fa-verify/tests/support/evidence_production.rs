//! Multi-leaf fixtures in the existing raw formats; no producer dependency.

use fa_verify::blake3::hash_parts;
use fa_verify::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
use fa_verify::evidence::EvidenceCitation;
use fa_verify::proof::production::ProductionScope;
use fa_verify::proof::{Checkpoint, INCLUSION_FORMAT, PREFIX_FORMAT};
use fa_verify::tree::{Digest, leaf_hash, root_of};

use super::fixture::{self, Wire};

pub struct Entry {
    pub proposal: Vec<u8>,
    pub sequence: u64,
    pub ordinal: u32,
    pub include_record: bool,
    pub entry_envelope: Vec<u8>,
}

pub fn entry(citations: &[EvidenceCitation], sequence: u64, day: i32) -> Entry {
    let mut proposal = fixture::proposal(citations).bytes;
    // Fixed v1 prefix: schema 4, book 16, branch 16, class 2, civil day 4.
    proposal[38..42].copy_from_slice(&day.to_le_bytes());
    Entry {
        proposal,
        sequence,
        ordinal: 0,
        include_record: true,
        entry_envelope: vec![0; 5],
    }
}

pub struct Journal {
    pub prefix: Vec<u8>,
    pub records: Vec<Vec<u8>>,
    pub checkpoint: Checkpoint,
}

impl Journal {
    pub fn scope(&self) -> ProductionScope {
        ProductionScope {
            first_seq: 0,
            known_at: self.checkpoint.through_seq,
            account: None,
            effective_days: None,
        }
    }

    pub fn records(&self) -> Vec<&[u8]> {
        self.records.iter().map(Vec::as_slice).collect()
    }
}

// Construction follows the recursive tree definition, independently of the
// verifier's iterative inclusion-path checking algorithm.
fn path(leaves: &[Digest], index: usize) -> Vec<Digest> {
    if leaves.len() == 1 {
        return Vec::new();
    }
    let mut split = 1;
    while split * 2 < leaves.len() {
        split *= 2;
    }
    let (mut result, sibling) = if index < split {
        (path(&leaves[..split], index), root_of(&leaves[split..]))
    } else {
        (
            path(&leaves[split..], index - split),
            root_of(&leaves[..split]),
        )
    };
    result.push(sibling);
    result
}

pub fn journal(entries: &[Entry]) -> Journal {
    let mut payloads = Vec::new();
    let mut envelopes = Vec::new();
    for entry in entries {
        let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&entry.proposal]);
        let digest = hash_parts(
            ENTRY_DIGEST_DOMAIN,
            &[&proposal_digest, &entry.entry_envelope],
        );
        let mut payload = entry.proposal.clone();
        payload.extend_from_slice(&entry.entry_envelope);
        payload.extend_from_slice(&proposal_digest);
        payload.extend_from_slice(&digest);
        let envelope = envelope_of_entry(
            &payload,
            entry.proposal.len(),
            entry.sequence,
            entry.ordinal,
        )
        .unwrap()
        .encode();
        payloads.push(payload);
        envelopes.push(envelope);
    }
    let leaves: Vec<_> = envelopes.iter().map(|bytes| leaf_hash(bytes)).collect();
    let checkpoint = Checkpoint {
        book_id: fixture::BOOK,
        branch_id: [0; 16],
        through_seq: entries.last().map_or(0, |entry| entry.sequence),
        leaf_count: entries.len() as u64,
        root: root_of(&leaves),
    };
    let mut prefix = Wire::default();
    prefix
        .bytes(PREFIX_FORMAT)
        .fixed(&checkpoint.encode())
        .u32(entries.len() as u32);
    for envelope in &envelopes {
        prefix.bytes(envelope);
    }
    let mut records = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let mut proof = Wire::default();
        proof
            .bytes(INCLUSION_FORMAT)
            .fixed(&checkpoint.encode())
            .u64(index as u64)
            .bytes(&envelopes[index])
            .u8(u8::from(entry.include_record));
        if entry.include_record {
            proof
                .u32(entry.proposal.len() as u32)
                .bytes(&payloads[index]);
        }
        let path = path(&leaves, index);
        proof.u32(path.len() as u32);
        for sibling in path {
            proof.fixed(&sibling);
        }
        records.push(proof.0);
    }
    Journal {
        prefix: prefix.0,
        records,
        checkpoint,
    }
}
