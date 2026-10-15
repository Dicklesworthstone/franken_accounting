//! Independent encoder of raw inclusion and payload-complete prefix formats.

use fa_verify::blake3::hash_parts;
use fa_verify::envelope::{ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, envelope_of_entry};
use fa_verify::proof::{Checkpoint, INCLUSION_FORMAT};
use fa_verify::proof::production::derivation::PREFIX_FORMAT_V2;
use fa_verify::tree::{Digest, leaf_hash, root_of};

pub const BOOK: [u8; 16] = [0x51; 16];
pub const SECRET: &[u8] = b"PRIVATE_PRODUCTION_PAYLOAD_NOT_OUTPUT";

#[derive(Default)]
pub struct Wire(pub Vec<u8>);

impl Wire {
    pub fn fixed(&mut self, bytes: &[u8]) -> &mut Self {
        self.0.extend_from_slice(bytes);
        self
    }
    pub fn u8(&mut self, n: u8) -> &mut Self {
        self.fixed(&[n])
    }
    pub fn u16(&mut self, n: u16) -> &mut Self {
        self.fixed(&n.to_le_bytes())
    }
    pub fn u32(&mut self, n: u32) -> &mut Self {
        self.fixed(&n.to_le_bytes())
    }
    pub fn u64(&mut self, n: u64) -> &mut Self {
        self.fixed(&n.to_le_bytes())
    }
    pub fn bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.u32(u32::try_from(bytes.len()).unwrap()).fixed(bytes)
    }
}

pub struct Record {
    pub envelope: fa_verify::LeafEnvelope,
    pub payload: Vec<u8>,
    pub split: usize,
}

pub fn record(seq: u64, ordinal: u32, class: u16, day: i32, account: Option<u128>) -> Record {
    let mut w = Wire::default();
    w.u16(1)
        .u16(1)
        .fixed(&BOOK)
        .fixed(&[0; 16])
        .u16(class)
        .fixed(&day.to_le_bytes())
        .u8(0)
        .fixed(&[0; 32])
        .u8(0)
        .fixed(&[0; 24])
        .bytes(SECRET)
        .u8(0);
    w.u32(if account.is_some() { 2 } else { 0 });
    if let Some(account) = account {
        for (side, account) in [(0, account), (1, account + 1)] {
            w.u8(side)
                .fixed(&account.to_le_bytes())
                .u32(1)
                .fixed(&123i128.to_le_bytes())
                .u8(0)
                .u32(0)
                .u8(0)
                .u32(0);
        }
    }
    w.u8(0).u32(if account.is_some() { 1 } else { 0 });
    if account.is_some() {
        w.u32(1)
            .fixed(&123i128.to_le_bytes())
            .fixed(&123i128.to_le_bytes());
    }
    w.u8(0)
        .bytes(&seq.to_le_bytes())
        .u8(0)
        .fixed(&[9; 32])
        .u16(1)
        .fixed(&7u128.to_le_bytes())
        .u8(0)
        .u32(0)
        .u32(0)
        .u8(0)
        .u32(0)
        .u32(0)
        .u32(0);
    let split = w.0.len();
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&w.0]);
    let entry_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[0; 5]]);
    w.fixed(&[0; 5])
        .fixed(&proposal_digest)
        .fixed(&entry_digest);
    let envelope = envelope_of_entry(&w.0, split, seq, ordinal).unwrap();
    Record {
        envelope,
        payload: w.0,
        split,
    }
}

fn path(leaves: &[Digest], index: usize) -> Vec<Digest> {
    if leaves.len() == 1 {
        return Vec::new();
    }
    let mut split = 1;
    while split * 2 < leaves.len() {
        split *= 2;
    }
    if index < split {
        let mut result = path(&leaves[..split], index);
        result.push(root_of(&leaves[split..]));
        result
    } else {
        let mut result = path(&leaves[split..], index - split);
        result.push(root_of(&leaves[..split]));
        result
    }
}

pub struct Fixture {
    pub records: Vec<Record>,
    pub checkpoint: Checkpoint,
}

impl Fixture {
    pub fn new(records: Vec<Record>, through_seq: u64) -> Self {
        let leaves: Vec<_> = records
            .iter()
            .map(|r| leaf_hash(&r.envelope.encode()))
            .collect();
        let checkpoint = Checkpoint {
            book_id: BOOK,
            branch_id: [0; 16],
            through_seq,
            leaf_count: records.len() as u64,
            root: root_of(&leaves),
        };
        Self {
            records,
            checkpoint,
        }
    }

    pub fn mixed() -> Self {
        Self::new(
            vec![
                record(1, 0, 1, 20, Some(10)),
                record(2, 0, 1, 20, Some(20)),
                record(2, 1, 2, 10, Some(10)), // Pending, not a posted balance
                record(3, 0, 12, 11, Some(10)), // Migration, no visibility claim
                record(5, 0, 1, 21, Some(10)),
                record(6, 0, 19, 0, None), // undated control
                record(8, 0, 1, 10, Some(30)),
            ],
            10,
        )
    }

    pub fn prefix(&self) -> Vec<u8> {
        let mut w = Wire::default();
        w.bytes(PREFIX_FORMAT_V2).fixed(&self.checkpoint.encode())
            .u32(u32::try_from(self.records.len()).unwrap());
        for record in &self.records { w.bytes(&record.envelope.encode()); }
        w.u32(u32::try_from(self.records.len()).unwrap());
        for (index, record) in self.records.iter().enumerate() {
            w.u64(index as u64).u32(u32::try_from(record.split).unwrap()).bytes(&record.payload);
        }
        w.0
    }

    pub fn inclusion(&self, index: usize, payload: bool) -> Vec<u8> {
        let record = &self.records[index];
        let leaves: Vec<_> = self
            .records
            .iter()
            .map(|r| leaf_hash(&r.envelope.encode()))
            .collect();
        let path = path(&leaves, index);
        let mut w = Wire::default();
        w.bytes(INCLUSION_FORMAT)
            .fixed(&self.checkpoint.encode())
            .u64(index as u64)
            .bytes(&record.envelope.encode())
            .u8(u8::from(payload));
        if payload {
            w.u32(u32::try_from(record.split).unwrap())
                .bytes(&record.payload);
        }
        w.u32(u32::try_from(path.len()).unwrap());
        for sibling in path {
            w.fixed(&sibling);
        }
        w.0
    }

    pub fn inclusions(&self, indexes: &[usize]) -> Vec<Vec<u8>> {
        indexes.iter().map(|i| self.inclusion(*i, true)).collect()
    }
}

pub fn borrowed(proofs: &[Vec<u8>]) -> Vec<&[u8]> {
    proofs.iter().map(Vec::as_slice).collect()
}
