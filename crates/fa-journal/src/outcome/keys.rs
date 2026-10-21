//! Authenticated legacy-key nonmembership using immutable native point rows.
//! A copied coverage root cannot make an omitted historical claim look free:
//! the signed root of this balanced search tree still reserves its key.
//! Nodes disclose only opaque common-key VIDs and child commitments, never
//! Entry refs, request digests, sealed fields or principal identities.

use core::cmp::Ordering;

use super::*;

const MAGIC: &[u8; 15] = b"FA-OUTCOME-KEY\0";
const MAX_DEPTH: usize = 128;

pub(super) fn empty_digest() -> [u8; 32] {
    domain_digest(b"fa:outcome-key-empty:v1", &[])
}

fn node_vid(book: Id128, digest: &[u8; 32]) -> VId {
    let hash = domain_digest(b"fa:vid:intent-outcome-key-node:v1", &[&book.0, digest]);
    let mut low = [0; 16];
    low.copy_from_slice(&hash[..16]);
    VId(u128::from_le_bytes(low))
}

#[derive(Debug)]
struct Node {
    key: VId,
    left: [u8; 32],
    right: [u8; 32],
}

impl Node {
    fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(VERSION)
            .u16(0)
            .u128(self.key.0)
            .fixed(&self.left)
            .fixed(&self.right);
        Ok(w.finish()?)
    }

    fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        if r.fixed::<15>("legacy outcome key magic").map_err(decode)? != *MAGIC
            || r.u16("legacy outcome key major").map_err(decode)? != VERSION
            || r.u16("legacy outcome key minor").map_err(decode)? != 0
        {
            return Err(KernelError::Corrupt(
                "unsupported legacy outcome key node".into(),
            ));
        }
        let value = Self {
            key: VId(r.u128("legacy outcome key").map_err(decode)?),
            left: r.fixed("legacy outcome left").map_err(decode)?,
            right: r.fixed("legacy outcome right").map_err(decode)?,
        };
        r.finish().map_err(decode)?;
        Ok(value)
    }
}

pub(super) fn stage(
    batch: &mut WriteBatch,
    book: Id128,
    sorted: &[VId],
) -> Result<[u8; 32], KernelError> {
    if sorted.is_empty() {
        return Ok(empty_digest());
    }
    let middle = sorted.len() / 2;
    let node = Node {
        key: sorted[middle],
        left: stage(batch, book, &sorted[..middle])?,
        right: stage(batch, book, &sorted[middle + 1..])?,
    };
    let bytes = node.canonical_bytes()?;
    let digest = domain_digest(b"fa:outcome-key-node:v1", &[&bytes]);
    batch.create_vertex(
        node_vid(book, &digest),
        vec![label::INTENT_OUTCOME],
        vec![(
            property::FA_PAYLOAD,
            scalar_bytes("legacy outcome key node", bytes)?,
        )],
    );
    Ok(digest)
}

pub(super) fn contains<V: Vfs + Clone>(
    txn: Option<&WriteTxn>,
    db: &Database<V>,
    coverage: &Coverage,
    born: CommitSeq,
    key: VId,
) -> Result<bool, KernelError> {
    let mut digest = coverage.keys_digest;
    let (mut lower, mut upper) = (None, None);
    for _ in 0..MAX_DEPTH {
        if digest == empty_digest() {
            return Ok(false);
        }
        let vid = node_vid(coverage.book, &digest);
        let row = match txn {
            Some(txn) => txn.vertex(db, vid)?,
            None => db.vertex(vid)?,
        }
        .ok_or_else(|| {
            KernelError::Corrupt("verified legacy key coverage is missing a node".into())
        })?;
        if row.labels.as_slice() != [label::INTENT_OUTCOME]
            || row.props.len() != 1
            || row.created_at != born
            || !original(db, &row)?
        {
            return Err(KernelError::Corrupt(
                "legacy key node is not its original recovery publication".into(),
            ));
        }
        let bytes = bytes(&row, property::FA_PAYLOAD, "legacy outcome key node")?;
        if domain_digest(b"fa:outcome-key-node:v1", &[&bytes]) != digest {
            return Err(KernelError::Corrupt(
                "legacy key node differs from authenticated coverage".into(),
            ));
        }
        let node = Node::decode(&bytes)?;
        if lower.is_some_and(|bound| node.key <= bound)
            || upper.is_some_and(|bound| node.key >= bound)
        {
            return Err(KernelError::Corrupt(
                "legacy key node violates its ordered range".into(),
            ));
        }
        match key.cmp(&node.key) {
            Ordering::Equal => return Ok(true),
            Ordering::Less => {
                upper = Some(node.key);
                digest = node.left;
            }
            Ordering::Greater => {
                lower = Some(node.key);
                digest = node.right;
            }
        }
    }
    Err(KernelError::Corrupt(
        "legacy key coverage exceeds its bounded search depth".into(),
    ))
}
