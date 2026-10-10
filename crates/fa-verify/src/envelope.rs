//! The leaf envelope and the record it commits (plan §13.2, Appendix A).
//!
//! ```text
//! LeafEnvelope { kind: u8, book_id: [16], branch_id: [16], commit_seq: u64,
//!                within_commit_ordinal: u32, record_digest: [32], class: u16,
//!                effective_day: Option<i32>, account_vids: sorted [u128],
//!                unit_ids: sorted [u32] }
//! ```
//!
//! The envelope, not the checkpoint, binds each record's commit sequence and
//! within-commit ordinal, so leaf order is `(commit_seq, ordinal)` and the
//! selection fields let a verifier apply a scope predicate without payloads.
//! When the payload is supplied, the verifier recomputes the record digest
//! from its bytes and rebuilds every selection field from them: an envelope
//! that disagrees with its own record is refused.
//!
//! The record of kind 1 is an `fa:entry:v1` payload (the `_fa_payload`
//! bytes): `proposal ‖ envelope ‖ proposal_digest ‖ entry_digest`, with
//! `proposal_digest = BLAKE3("fa:entry-proposal:v1" ‖ proposal)` and
//! `record_digest = entry_digest = BLAKE3("fa:entry:v1" ‖ proposal_digest ‖
//! envelope)`. The verifier is told where the proposal ends and checks both
//! trailing digests against its recomputation, so a wrong split cannot pass
//! (it would change the proposal digest).

use crate::blake3::hash_parts;
use crate::codec::{DecodeError, Reader, Reason, Writer};

/// Record kinds. Only journal entries are accumulated today; attestations
/// and document receipts take the next tags when they exist.
pub const KIND_ENTRY: u8 = 1;

pub const PROPOSAL_DIGEST_DOMAIN: &[u8] = b"fa:entry-proposal:v1";
pub const ENTRY_DIGEST_DOMAIN: &[u8] = b"fa:entry:v1";

/// The entry classes that are book-scoped and undated (`SchemaControl`,
/// `PolicyControl`, `TimeControl`, `SweepControl`, `ScheduleControl`;
/// `registries/entry_classes.toml`): their envelopes carry no effective day.
/// Every other class is period-scoped and carries one.
pub const UNDATED_CLASSES: [u16; 5] = [17, 18, 19, 20, 21];

/// Bounds for the selection lists (`max_legs_per_entry` bounds both).
pub const MAX_ENVELOPE_LIST: usize = 4096;
/// The largest entry payload (`max_entry_bytes`).
pub const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafEnvelope {
    pub kind: u8,
    pub book_id: [u8; 16],
    pub branch_id: [u8; 16],
    pub commit_seq: u64,
    pub within_commit_ordinal: u32,
    pub record_digest: [u8; 32],
    pub class: u16,
    pub effective_day: Option<i32>,
    /// Strictly ascending.
    pub account_vids: Vec<u128>,
    /// Strictly ascending.
    pub unit_ids: Vec<u32>,
}

fn strictly_ascending<T: Ord>(v: &[T]) -> bool {
    v.windows(2).all(|w| w[0] < w[1])
}

impl LeafEnvelope {
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        let kind = r.u8("envelope.kind")?;
        if kind != KIND_ENTRY {
            return Err(r.error("envelope.kind", Reason::BadTag(kind)));
        }
        let book_id = r.fixed("envelope.book_id")?;
        let branch_id = r.fixed("envelope.branch_id")?;
        let commit_seq = r.u64("envelope.commit_seq")?;
        let within_commit_ordinal = r.u32("envelope.within_commit_ordinal")?;
        let record_digest = r.fixed("envelope.record_digest")?;
        let class = r.u16("envelope.class")?;
        let effective_day = if r.present("envelope.effective_day")? {
            Some(r.i32("envelope.effective_day")?)
        } else {
            None
        };
        let n = r.count(MAX_ENVELOPE_LIST, 16, "envelope.account_vids")?;
        let mut account_vids = Vec::with_capacity(n);
        for _ in 0..n {
            account_vids.push(r.u128("envelope.account_vid")?);
        }
        if !strictly_ascending(&account_vids) {
            return Err(r.error("envelope.account_vids", Reason::Unsorted));
        }
        let n = r.count(MAX_ENVELOPE_LIST, 4, "envelope.unit_ids")?;
        let mut unit_ids = Vec::with_capacity(n);
        for _ in 0..n {
            unit_ids.push(r.u32("envelope.unit_id")?);
        }
        if !strictly_ascending(&unit_ids) {
            return Err(r.error("envelope.unit_ids", Reason::Unsorted));
        }
        r.finish("envelope")?;
        Ok(Self {
            kind,
            book_id,
            branch_id,
            commit_seq,
            within_commit_ordinal,
            record_digest,
            class,
            effective_day,
            account_vids,
            unit_ids,
        })
    }

    /// The canonical bytes (the inverse of [`LeafEnvelope::decode`]).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u8(self.kind)
            .fixed(&self.book_id)
            .fixed(&self.branch_id)
            .u64(self.commit_seq)
            .u32(self.within_commit_ordinal)
            .fixed(&self.record_digest)
            .u16(self.class);
        match self.effective_day {
            None => {
                w.u8(0);
            }
            Some(d) => {
                w.u8(1).i32(d);
            }
        }
        w.count(self.account_vids.len());
        for v in &self.account_vids {
            w.u128(*v);
        }
        w.count(self.unit_ids.len());
        for u in &self.unit_ids {
            w.u32(*u);
        }
        w.buf
    }

    /// `(commit_seq, within_commit_ordinal)`: the leaf order.
    #[must_use]
    pub fn position(&self) -> (u64, u32) {
        (self.commit_seq, self.within_commit_ordinal)
    }
}

/// Why a supplied record does not support its envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// The record bytes do not parse as an `fa:entry:v1` payload.
    Decode(DecodeError),
    /// The split hint does not leave room for the envelope and two digests.
    Split,
    /// A trailing digest does not match its recomputation from the bytes.
    Digest { which: &'static str },
    /// The envelope rebuilt from the record differs from the one presented.
    Envelope,
}

/// One leg of an `fa:entry:v1` proposal, as a fold reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leg {
    pub debit: bool,
    pub account: u128,
    pub unit: u32,
    /// Non-negative in a valid entry; the fold checks rather than assumes.
    pub mantissa: i128,
}

/// The selection fields an `fa:entry:v1` proposal determines, read from the
/// front of the proposal through its legs. Every byte after the legs is
/// covered by the digests and does not feed an envelope field.
struct ProposalPrefix {
    book_id: [u8; 16],
    branch_id: [u8; 16],
    class: u16,
    effective_date: i32,
    legs: Vec<Leg>,
}

impl ProposalPrefix {
    fn account_vids(&self) -> Vec<u128> {
        let mut v: Vec<u128> = self.legs.iter().map(|l| l.account).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn unit_ids(&self) -> Vec<u32> {
        let mut v: Vec<u32> = self.legs.iter().map(|l| l.unit).collect();
        v.sort_unstable();
        v.dedup();
        v
    }
}

/// The `fa:entry:v1` erasable field: digest, optional subject, nonce, sealed
/// bytes. Its content never feeds an envelope; it is skipped exactly.
fn skip_erasable(r: &mut Reader<'_>, what: &'static str) -> Result<(), DecodeError> {
    r.fixed::<32>(what)?;
    if r.present(what)? {
        r.u128(what)?;
    }
    r.fixed::<24>(what)?;
    r.bytes(MAX_RECORD_BYTES, what)?;
    Ok(())
}

fn amount(r: &mut Reader<'_>, what: &'static str) -> Result<(u32, i128), DecodeError> {
    Ok((r.u32(what)?, r.i128(what)?))
}

fn proposal_prefix(proposal: &[u8]) -> Result<ProposalPrefix, DecodeError> {
    let mut r = Reader::new(proposal);
    let major = r.u16("entry.schema_major")?;
    if major != 1 {
        return Err(r.error("entry.schema_major", Reason::BadTag(major.to_le_bytes()[0])));
    }
    r.u16("entry.schema_minor")?;
    let book_id = r.fixed("entry.book_id")?;
    let branch_id = r.fixed("entry.branch_id")?;
    let class = r.u16("entry.class")?;
    let effective_date = r.i32("entry.effective_date")?;
    if r.present("entry.document_date")? {
        r.i32("entry.document_date")?;
    }
    skip_erasable(&mut r, "entry.description")?;
    if r.present("entry.effective_period")? {
        r.bytes(MAX_RECORD_BYTES, "entry.effective_period.calendar")?;
        r.bytes(MAX_RECORD_BYTES, "entry.effective_period.code")?;
    }
    // side u8, account u128, amount (u32, i128), option tag, two counts, memo tag.
    let legs = r.count(MAX_ENVELOPE_LIST, 1 + 16 + 20 + 1 + 4 + 1 + 4, "entry.legs")?;
    let mut parsed = Vec::with_capacity(legs);
    for _ in 0..legs {
        let debit = match r.u8("leg.side")? {
            0 => true,
            1 => false,
            t => return Err(r.error("leg.side", Reason::BadTag(t))),
        };
        let account = r.u128("leg.account_ref")?;
        let (unit, mantissa) = amount(&mut r, "leg.amount")?;
        parsed.push(Leg {
            debit,
            account,
            unit,
            mantissa,
        });
        if r.present("leg.base_amount")? {
            amount(&mut r, "leg.base_amount")?;
        }
        let dims = r.count(MAX_ENVELOPE_LIST, 20, "leg.dimension_set")?;
        for _ in 0..dims {
            r.u32("dimension.id")?;
            r.u128("dimension.value")?;
        }
        if r.present("leg.memo")? {
            skip_erasable(&mut r, "leg.memo")?;
        }
        let settles = r.count(MAX_ENVELOPE_LIST, 16 + 32 + 2 + 20, "leg.settles")?;
        for _ in 0..settles {
            r.u128("settles.target.vid")?;
            r.fixed::<32>("settles.target.entry_digest")?;
            r.u16("settles.ordinal")?;
            amount(&mut r, "settles.amount")?;
        }
    }
    Ok(ProposalPrefix {
        book_id,
        branch_id,
        class,
        effective_date,
        legs: parsed,
    })
}

/// Recompute the record digest of an `fa:entry:v1` payload whose proposal
/// is its first `proposal_len` bytes, checking both stored digests.
pub fn entry_record_digest(payload: &[u8], proposal_len: usize) -> Result<[u8; 32], RecordError> {
    let n = payload.len();
    if proposal_len > n || n - proposal_len < 64 {
        return Err(RecordError::Split);
    }
    let proposal = &payload[..proposal_len];
    let envelope = &payload[proposal_len..n - 64];
    let stored_proposal_digest = &payload[n - 64..n - 32];
    let stored_entry_digest = &payload[n - 32..];
    let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[proposal]);
    if proposal_digest[..] != *stored_proposal_digest {
        return Err(RecordError::Digest {
            which: "proposal_digest",
        });
    }
    let entry_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, envelope]);
    if entry_digest[..] != *stored_entry_digest {
        return Err(RecordError::Digest {
            which: "entry_digest",
        });
    }
    Ok(entry_digest)
}

/// The envelope a journal entry's payload determines at journal position
/// `(commit_seq, ordinal)`.
pub fn envelope_of_entry(
    payload: &[u8],
    proposal_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<LeafEnvelope, RecordError> {
    record_of_entry(payload, proposal_len, commit_seq, within_commit_ordinal).map(|(e, _)| e)
}

/// The envelope and the legs of an `fa:entry:v1` payload at a journal
/// position.
fn record_of_entry(
    payload: &[u8],
    proposal_len: usize,
    commit_seq: u64,
    within_commit_ordinal: u32,
) -> Result<(LeafEnvelope, Vec<Leg>), RecordError> {
    let record_digest = entry_record_digest(payload, proposal_len)?;
    let p = proposal_prefix(&payload[..proposal_len]).map_err(RecordError::Decode)?;
    let envelope = LeafEnvelope {
        kind: KIND_ENTRY,
        book_id: p.book_id,
        branch_id: p.branch_id,
        commit_seq,
        within_commit_ordinal,
        record_digest,
        class: p.class,
        effective_day: (!UNDATED_CLASSES.contains(&p.class)).then_some(p.effective_date),
        account_vids: p.account_vids(),
        unit_ids: p.unit_ids(),
    };
    Ok((envelope, p.legs))
}

/// Check that `envelope` is exactly the envelope its record determines, and
/// return the record's legs.
pub fn check_record(
    envelope: &LeafEnvelope,
    payload: &[u8],
    proposal_len: usize,
) -> Result<Vec<Leg>, RecordError> {
    let (rebuilt, legs) = record_of_entry(
        payload,
        proposal_len,
        envelope.commit_seq,
        envelope.within_commit_ordinal,
    )?;
    if rebuilt != *envelope {
        return Err(RecordError::Envelope);
    }
    Ok(legs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope() -> LeafEnvelope {
        LeafEnvelope {
            kind: KIND_ENTRY,
            book_id: [8; 16],
            branch_id: [0; 16],
            commit_seq: 42,
            within_commit_ordinal: 0,
            record_digest: [3; 32],
            class: 1,
            effective_day: Some(20_527),
            account_vids: vec![5, 9],
            unit_ids: vec![1],
        }
    }

    #[test]
    fn envelope_round_trips_and_refuses_disorder_unknown_kinds_and_trailing_bytes() {
        let e = envelope();
        let bytes = e.encode();
        assert_eq!(LeafEnvelope::decode(&bytes).unwrap(), e);
        // kind 1 + ids 32 + seq 8 + ordinal 4 + digest 32 + class 2 + day 5 + lists 4+32 + 4+4.
        assert_eq!(bytes.len(), 1 + 32 + 8 + 4 + 32 + 2 + 5 + 36 + 8);

        let mut undated = e.clone();
        undated.effective_day = None;
        assert_eq!(LeafEnvelope::decode(&undated.encode()).unwrap(), undated);

        let mut unsorted = e.clone();
        unsorted.account_vids = vec![9, 5];
        assert_eq!(
            LeafEnvelope::decode(&unsorted.encode()).unwrap_err().reason,
            Reason::Unsorted
        );
        let mut duplicate = e.clone();
        duplicate.unit_ids = vec![1, 1];
        assert_eq!(
            LeafEnvelope::decode(&duplicate.encode())
                .unwrap_err()
                .reason,
            Reason::Unsorted
        );
        let mut foreign = bytes.clone();
        foreign[0] = 2;
        assert_eq!(
            LeafEnvelope::decode(&foreign).unwrap_err().reason,
            Reason::BadTag(2)
        );
        let mut long = bytes.clone();
        long.push(0);
        assert_eq!(
            LeafEnvelope::decode(&long).unwrap_err().reason,
            Reason::Trailing
        );
        assert_eq!(
            LeafEnvelope::decode(&bytes[..bytes.len() - 1])
                .unwrap_err()
                .reason,
            Reason::Truncated
        );
    }

    #[test]
    fn a_split_that_leaves_no_room_for_the_digests_is_refused() {
        assert_eq!(entry_record_digest(&[0; 63], 0), Err(RecordError::Split));
        assert_eq!(entry_record_digest(&[0; 64], 1), Err(RecordError::Split));
        assert_eq!(
            entry_record_digest(&[0; 64], 0),
            Err(RecordError::Digest {
                which: "proposal_digest"
            })
        );
    }
}
