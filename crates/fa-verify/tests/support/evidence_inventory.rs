//! Independent v1 wire fixtures; no producer crate or secret book keys.

use fa_verify::Checkpoint;
use fa_verify::blake3::hash_parts;
use fa_verify::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
use fa_verify::evidence::EvidenceCitation;
use fa_verify::proof::INCLUSION_FORMAT;
use fa_verify::tree::{leaf_hash, root_of};

pub const BOOK: [u8; 16] = [0x42; 16];
pub const SECRET: &[u8] = b"NEVER_PRINT_ENTRY_DESCRIPTION_BYTES";

#[derive(Default)]
pub struct Wire(pub Vec<u8>);

impl Wire {
    pub fn fixed(&mut self, bytes: &[u8]) -> &mut Self { self.0.extend_from_slice(bytes); self }
    pub fn u8(&mut self, value: u8) -> &mut Self { self.fixed(&[value]) }
    pub fn u16(&mut self, value: u16) -> &mut Self { self.fixed(&value.to_le_bytes()) }
    pub fn u32(&mut self, value: u32) -> &mut Self { self.fixed(&value.to_le_bytes()) }
    pub fn u64(&mut self, value: u64) -> &mut Self { self.fixed(&value.to_le_bytes()) }
    pub fn u128(&mut self, value: u128) -> &mut Self { self.fixed(&value.to_le_bytes()) }
    pub fn i128(&mut self, value: i128) -> &mut Self { self.fixed(&value.to_le_bytes()) }
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.u32(u32::try_from(value.len()).unwrap()).fixed(value)
    }
}

pub fn citation(commitment: [u8; 32], role: u8) -> EvidenceCitation {
    EvidenceCitation {
        document_oid: hash_parts(b"fa:oid:document:v1", &[
            &16u32.to_le_bytes(), &BOOK, &32u32.to_le_bytes(), &commitment,
        ]),
        doc_commit: commitment,
        role,
    }
}

pub fn citations() -> Vec<EvidenceCitation> {
    let mut result = vec![citation([7; 32], 3), citation([7; 32], 4), citation([9; 32], 255)];
    result.sort();
    result
}

pub struct Proposal {
    pub bytes: Vec<u8>,
    pub count_offset: usize,
    pub tail_offset: usize,
}

pub fn proposal(citations: &[EvidenceCitation]) -> Proposal {
    let mut p = Wire::default();
    p.u16(1).u16(1).fixed(&BOOK).fixed(&[0; 16]).u16(1)
        .fixed(&20_527i32.to_le_bytes()).u8(0)
        .fixed(&[0; 32]).u8(0).fixed(&[0; 24]).bytes(SECRET)
        .u8(0).u32(2);
    for (side, account) in [(0, 10), (1, 20)] {
        p.u8(side).u128(account).u32(1).i128(123)
            .u8(0).u32(0).u8(0).u32(0);
    }
    p.u8(0).u32(1).u32(1).i128(123).i128(123).u8(0)
        .bytes(b"evidence-inventory").u8(0).fixed(&[9; 32]).u16(1)
        .u128(7).u8(0);
    let count_offset = p.0.len();
    p.u32(u32::try_from(citations.len()).unwrap());
    for citation in citations {
        p.fixed(&citation.document_oid).fixed(&citation.doc_commit).u8(citation.role);
    }
    let tail_offset = p.0.len();
    p.u32(0).u8(0).u32(0).u32(0).u32(0);
    Proposal { bytes: p.0, count_offset, tail_offset }
}

pub struct Fixture {
    pub proof: Vec<u8>,
    pub checkpoint: Checkpoint,
    pub entry_digest: [u8; 32],
}

pub fn proof(proposal: &[u8], include_record: bool, sequence: u64) -> Fixture {
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[proposal]);
    let entry_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[0; 5]]);
    let mut payload = proposal.to_vec();
    payload.extend_from_slice(&[0; 5]);
    payload.extend_from_slice(&proposal_digest);
    payload.extend_from_slice(&entry_digest);
    let envelope = envelope_of_entry(&payload, proposal.len(), sequence, 0).unwrap().encode();
    let checkpoint = Checkpoint {
        book_id: BOOK, branch_id: [0; 16], through_seq: sequence,
        leaf_count: 1, root: root_of(&[leaf_hash(&envelope)]),
    };
    let mut out = Wire::default();
    out.bytes(INCLUSION_FORMAT).fixed(&checkpoint.encode()).u64(0)
        .bytes(&envelope).u8(u8::from(include_record));
    if include_record { out.u32(u32::try_from(proposal.len()).unwrap()).bytes(&payload); }
    out.u32(0);
    Fixture { proof: out.0, checkpoint, entry_digest }
}
