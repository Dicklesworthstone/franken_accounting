//! The journal as the accumulator sees it: every committed `Entry` (posting
//! and control classes alike) as one leaf, in `(commit_seq, ordinal)` order,
//! read from the authoritative payloads at a fixed known-at sequence.
//!
//! Leaf envelope (plan §13.2, Appendix A), canonical bytes under the model's
//! codec laws:
//!
//! ```text
//! LeafEnvelope { kind: u8 (1 = Entry), book_id: [16], branch_id: [16],
//!                commit_seq: u64, within_commit_ordinal: u32,
//!                record_digest: [32] (= entry_digest), class: u16,
//!                effective_day: Option<i32>, account_vids: sorted [u128],
//!                unit_ids: sorted [u32] }
//! ```
//!
//! `commit_seq` is the entry vertex's creating commit — recorded time, never
//! user-supplied. `within_commit_ordinal` ranks the entries of one commit by
//! ascending vertex id: a pure function of the journal. (Every kernel path
//! today commits one entry per transaction, so the ordinal is 0; batches
//! inherit the same rule.) `effective_day` is absent exactly for the
//! book-scoped, undated control classes (`SchemaControl`, `PolicyControl`).
//! The selection fields are the sorted distinct leg accounts and leg units.

use std::collections::BTreeSet;

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_journal::rows::bytes;
use fa_model::symbols::{label, property};
use fa_model::{ControlPayload, EncodeError, Entry, EntryClass, EntryOrigin, Id128, Writer};
use fa_money::Side;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use crate::tree::{Digest, Tree, leaf_hash};
use crate::{Statement, code};

pub const KIND_ENTRY: u8 = 1;

pub const INCLUSION_FORMAT: &[u8] = b"fa:acc-inclusion-proof:v1";
pub const CONSISTENCY_FORMAT: &[u8] = b"fa:acc-consistency-proof:v1";
pub const PREFIX_FORMAT: &[u8] = b"fa:acc-prefix-proof:v1";
pub const BALANCE_FORMAT: &[u8] = b"fa:acc-balance-proof:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafEnvelope {
    pub kind: u8,
    pub book_id: Id128,
    pub branch_id: Id128,
    pub commit_seq: CommitSeq,
    pub within_commit_ordinal: u32,
    pub record_digest: [u8; 32],
    pub class: EntryClass,
    pub effective_day: Option<i32>,
    /// Strictly ascending.
    pub account_vids: Vec<VId>,
    /// Strictly ascending.
    pub unit_ids: Vec<u32>,
}

/// The book-scoped control classes carry no effective day (plan §7.1).
#[must_use]
pub fn is_undated(class: EntryClass) -> bool {
    matches!(
        class,
        EntryClass::SCHEMA_CONTROL
            | EntryClass::POLICY_CONTROL
            | EntryClass::TIME_CONTROL
            | EntryClass::SWEEP_CONTROL
            | EntryClass::SCHEDULE_CONTROL
    )
}

impl LeafEnvelope {
    /// The envelope of `entry` at journal position `(commit_seq, ordinal)`.
    #[must_use]
    pub fn of_entry(entry: &Entry, commit_seq: CommitSeq, within_commit_ordinal: u32) -> Self {
        let p = &entry.proposal;
        let account_vids: BTreeSet<u128> = p.legs.iter().map(|l| l.account_ref.0).collect();
        let unit_ids: BTreeSet<u32> = p.legs.iter().map(|l| l.amount.unit.0).collect();
        Self {
            kind: KIND_ENTRY,
            book_id: p.book_id,
            branch_id: p.branch_id,
            commit_seq,
            within_commit_ordinal,
            record_digest: entry.entry_digest,
            class: p.class,
            effective_day: (!is_undated(p.class)).then_some(p.effective_date.0),
            account_vids: account_vids.into_iter().map(VId).collect(),
            unit_ids: unit_ids.into_iter().collect(),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::with_capacity(128 + 16 * self.account_vids.len());
        w.u8(self.kind)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.commit_seq.0)
            .u32(self.within_commit_ordinal)
            .fixed(&self.record_digest)
            .u16(self.class.0)
            .opt(self.effective_day.as_ref(), |w, d| {
                w.i32(*d);
            })
            .list(&self.account_vids, |w, v| {
                w.u128(v.0);
            })
            .list(&self.unit_ids, |w, u| {
                w.u32(*u);
            });
        w.finish()
    }
}

/// One accumulated record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub vid: VId,
    pub envelope: LeafEnvelope,
    pub envelope_bytes: Vec<u8>,
    pub hash: Digest,
    /// The entry's `_fa_payload` bytes.
    pub payload: Vec<u8>,
    /// Where the proposal ends inside `payload`.
    pub proposal_len: usize,
}

/// The journal prefix through `through_seq`, with its accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub through_seq: CommitSeq,
    pub leaves: Vec<Leaf>,
    tree: Tree,
}

fn corrupt(what: impl Into<String>) -> KernelError {
    KernelError::Corrupt(what.into())
}

fn encode_failed(e: EncodeError) -> KernelError {
    KernelError::Model(fa_model::EntryError::Encode(e))
}

impl Journal {
    /// Accumulate `records` — `(vertex id, entry, creating commit)` — as the
    /// prefix through `through_seq`. Every record must belong to the book's
    /// trunk and lie inside the prefix; order is derived, never trusted.
    pub fn from_records(
        book_id: Id128,
        through_seq: CommitSeq,
        mut records: Vec<(VId, Entry, CommitSeq)>,
    ) -> Result<Self, KernelError> {
        records.sort_by_key(|(vid, _, seq)| (*seq, vid.0));
        let mut leaves: Vec<Leaf> = Vec::with_capacity(records.len());
        let mut tree = Tree::new();
        let mut ordinal = 0u32;
        for (vid, entry, seq) in records {
            if entry.proposal.book_id != book_id || entry.proposal.branch_id != Id128::TRUNK {
                return Err(corrupt(format!(
                    "entry {:032x} does not belong to this book's trunk",
                    vid.0
                )));
            }
            if seq > through_seq {
                return Err(corrupt(format!(
                    "entry {:032x} was recorded at {} after the prefix through {}",
                    vid.0, seq.0, through_seq.0
                )));
            }
            ordinal = match leaves.last() {
                Some(prev) if prev.envelope.commit_seq == seq => ordinal
                    .checked_add(1)
                    .ok_or_else(|| corrupt("more than u32::MAX entries in one commit"))?,
                _ => 0,
            };
            let envelope = LeafEnvelope::of_entry(&entry, seq, ordinal);
            let envelope_bytes = envelope.canonical_bytes().map_err(encode_failed)?;
            let payload = entry.encode()?;
            let proposal_len = entry.proposal.canonical_bytes()?.len();
            let hash = leaf_hash(&envelope_bytes);
            tree.push(hash);
            leaves.push(Leaf {
                vid,
                envelope,
                envelope_bytes,
                hash,
                payload,
                proposal_len,
            });
        }
        Ok(Self {
            book_id,
            branch_id: Id128::TRUNK,
            through_seq,
            leaves,
            tree,
        })
    }

    /// Read the journal of `book` as known at `known_at` (default: head)
    /// from the authoritative `Entry` payloads. Derived vertices (registers,
    /// mirrors, accumulator states) are never an input.
    pub fn read<V: asupersync::fs::Vfs + Clone>(
        db: &Database<V>,
        book: &BookContext,
        known_at: Option<CommitSeq>,
    ) -> Outcome<Self> {
        let head = db.frontier()?;
        let seq = known_at.unwrap_or(head);
        if seq > head {
            return Ok(Err(Refusal::new(
                code::BEYOND_HEAD,
                exit::USAGE,
                format!(
                    "known-at sequence {} is beyond the book head {}",
                    seq.0, head.0
                ),
                "plan §13.1 (a prefix cannot extend past the head)",
                format!("select a sequence at or before {}", head.0),
            )));
        }
        let mut records = Vec::new();
        for row in db.vertices_at(seq)? {
            if !row.labels.contains(&label::ENTRY) {
                continue;
            }
            let payload = bytes(&row, property::FA_PAYLOAD, "entry.payload")?;
            let entry = Entry::decode(&payload)?;
            records.push((row.vid, entry, row.created_at));
        }
        Ok(Ok(Self::from_records(book.book_id, seq, records)?))
    }

    #[must_use]
    pub fn len(&self) -> u64 {
        self.leaves.len() as u64
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    #[must_use]
    pub fn root(&self) -> Digest {
        self.tree.root()
    }

    /// The root over the first `leaf_count` leaves.
    #[must_use]
    pub fn root_at(&self, leaf_count: u64) -> Option<Digest> {
        self.tree.root_at(usize::try_from(leaf_count).ok()?)
    }

    #[must_use]
    pub fn peaks(&self) -> Vec<Digest> {
        self.tree.peaks_at(self.leaves.len()).unwrap_or_default()
    }

    #[must_use]
    pub fn peaks_at(&self, leaf_count: u64) -> Option<Vec<Digest>> {
        self.tree.peaks_at(usize::try_from(leaf_count).ok()?)
    }

    /// What a checkpoint of this prefix commits.
    #[must_use]
    pub fn statement(&self) -> Statement {
        Statement {
            book_id: self.book_id,
            branch_id: self.branch_id,
            through_seq: self.through_seq,
            leaf_count: self.len(),
            root: self.root(),
        }
    }

    /// The leaf index of the entry vertex `vid`, if it is in this prefix.
    #[must_use]
    pub fn leaf_index(&self, vid: VId) -> Option<usize> {
        self.leaves.iter().position(|l| l.vid == vid)
    }

    /// The inclusion proof of entry `vid` against this prefix's statement,
    /// with the entry's own payload when `with_record`. `None` when the
    /// entry is not in the prefix.
    pub fn inclusion_proof(
        &self,
        vid: VId,
        with_record: bool,
    ) -> Result<Option<Vec<u8>>, KernelError> {
        let Some(index) = self.leaf_index(vid) else {
            return Ok(None);
        };
        let path = self
            .tree
            .inclusion_path(index, self.leaves.len())
            .ok_or_else(|| corrupt("inclusion path outside the tree"))?;
        let leaf = &self.leaves[index];
        let mut w = Writer::with_capacity(512 + leaf.payload.len());
        w.bytes(INCLUSION_FORMAT);
        self.statement().encode(&mut w);
        w.u64(index as u64).bytes(&leaf.envelope_bytes);
        if with_record {
            let proposal_len = u32::try_from(leaf.proposal_len)
                .map_err(|_| corrupt("proposal longer than u32::MAX bytes"))?;
            w.u8(1).u32(proposal_len).bytes(&leaf.payload);
        } else {
            w.u8(0);
        }
        w.list(&path, |w, d| {
            w.fixed(d);
        });
        Ok(Some(w.finish().map_err(encode_failed)?))
    }

    /// The consistency proof that this prefix extends `old`. `None` when
    /// `old` is not a prefix of this journal — another book or branch, a
    /// later sequence, more leaves, or a root these leaves do not reproduce.
    pub fn consistency_proof(&self, old: &Statement) -> Result<Option<Vec<u8>>, KernelError> {
        if old.book_id != self.book_id
            || old.branch_id != self.branch_id
            || old.through_seq > self.through_seq
            || self.root_at(old.leaf_count) != Some(old.root)
        {
            return Ok(None);
        }
        let old_size =
            usize::try_from(old.leaf_count).map_err(|_| corrupt("leaf count beyond usize"))?;
        let path = self
            .tree
            .consistency_path(old_size, self.leaves.len())
            .ok_or_else(|| corrupt("consistency path outside the tree"))?;
        let mut w = Writer::with_capacity(256 + 32 * path.len());
        w.bytes(CONSISTENCY_FORMAT);
        old.encode(&mut w);
        self.statement().encode(&mut w);
        w.list(&path, |w, d| {
            w.fixed(d);
        });
        Ok(Some(w.finish().map_err(encode_failed)?))
    }

    /// Every leaf envelope of the prefix, for complete-prefix verification
    /// (`SeqRangeComplete`, plan §13.1).
    pub fn prefix_proof(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::with_capacity(128 + 160 * self.leaves.len());
        w.bytes(PREFIX_FORMAT);
        self.statement().encode(&mut w);
        w.list(&self.leaves, |w, l| {
            w.bytes(&l.envelope_bytes);
        });
        w.finish().map_err(encode_failed)
    }

    /// Whether leaf `l` contributes posted legs to (account, unit) by the
    /// cutoff: the envelope names both, the class is not `Pending`, and the
    /// effective day is at or before the cutoff when one is given.
    fn contributes(l: &Leaf, account: VId, unit: u32, through: Option<i32>) -> bool {
        let e = &l.envelope;
        e.class != EntryClass::PENDING
            && e.account_vids.binary_search(&account).is_ok()
            && e.unit_ids.binary_search(&unit).is_ok()
            && through.is_none_or(|cutoff| e.effective_day.is_some_and(|d| d <= cutoff))
    }

    /// The FA-INV-07 migration predicate over this prefix's own leaves: the
    /// first leaf that would contribute to (account, unit) and is a chunk of
    /// a migration run with no Finalize leaf in the prefix. The accumulator
    /// keeps such leaves (they are journaled); a register fold does not count
    /// them; and `fa-verify` decides its in-scope set from envelopes, which
    /// do not carry the run — so the proof refuses rather than disagree with
    /// the fold (ruling 3243; the format change is bead fa-e00).
    fn staged_chunk(
        &self,
        account: VId,
        unit: u32,
        through: Option<i32>,
    ) -> Result<Option<VId>, KernelError> {
        let mut finalized = BTreeSet::new();
        for leaf in self
            .leaves
            .iter()
            .filter(|l| l.envelope.class == EntryClass::MIGRATION_CONTROL)
        {
            if let Some(ControlPayload::MigrationControl { run_ref, kind, .. }) =
                Entry::decode(&leaf.payload)?.proposal.control
                && kind == fa_journal::migration::kind::FINALIZE
            {
                finalized.insert(run_ref);
            }
        }
        for leaf in self.leaves.iter().filter(|l| {
            l.envelope.class == EntryClass::MIGRATION
                && Self::contributes(l, account, unit, through)
        }) {
            if let EntryOrigin::Migration { run_ref, .. } =
                Entry::decode(&leaf.payload)?.proposal.origin
                && !finalized.contains(&run_ref)
            {
                return Ok(Some(leaf.vid));
            }
        }
        Ok(None)
    }

    /// The posted (debits, credits) of (account, unit) through the cutoff,
    /// folded from the entry payloads with checked arithmetic. Refused
    /// (FA-REF-133) while a contributing migration chunk's run is not
    /// finalized in this prefix.
    pub fn posted_balance(
        &self,
        account: VId,
        unit: u32,
        through: Option<i32>,
    ) -> Outcome<(i128, i128)> {
        if let Some(chunk) = self.staged_chunk(account, unit, through)? {
            return Ok(Err(Refusal::new(
                code::MIGRATION_STAGED,
                exit::REFUSAL,
                format!(
                    "the balance would count migration chunk {:032x}, whose run is not finalized in this prefix",
                    chunk.0
                ),
                "plan §8.6, FA-INV-07 (a staged or abandoned chunk is invisible to every fold)",
                "prove the balance at a checkpoint after the run is finalized; an abandoned run's accounts are provable once balance proofs carry the migration predicate (fa-e00)",
            )));
        }
        let (mut debits, mut credits) = (0i128, 0i128);
        for leaf in self
            .leaves
            .iter()
            .filter(|l| Self::contributes(l, account, unit, through))
        {
            let entry = Entry::decode(&leaf.payload)?;
            for leg in entry
                .proposal
                .legs
                .iter()
                .filter(|g| g.account_ref == account && g.amount.unit.0 == unit)
            {
                let slot = match leg.side {
                    Side::Debit => &mut debits,
                    Side::Credit => &mut credits,
                };
                *slot = slot
                    .checked_add(leg.amount.mantissa)
                    .ok_or_else(|| corrupt("a posted balance overflowed i128"))?;
            }
        }
        Ok(Ok((debits, credits)))
    }

    /// The balance-recomputation proof of (account, unit) through the cutoff
    /// against this prefix's statement: the claim, every leaf envelope, and
    /// the payload of exactly the contributing leaves.
    pub fn balance_proof(&self, account: VId, unit: u32, through: Option<i32>) -> Outcome<Vec<u8>> {
        let (debits, credits) = match self.posted_balance(account, unit, through)? {
            Ok(sums) => sums,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let contributing: Vec<(u64, &Leaf)> = self
            .leaves
            .iter()
            .enumerate()
            .filter(|(_, l)| Self::contributes(l, account, unit, through))
            .map(|(i, l)| (i as u64, l))
            .collect();
        let mut w = Writer::with_capacity(256 + 160 * self.leaves.len());
        w.bytes(BALANCE_FORMAT);
        self.statement().encode(&mut w);
        w.u128(account.0)
            .u32(unit)
            .opt(through.as_ref(), |w, d| {
                w.i32(*d);
            })
            .i128(debits)
            .i128(credits)
            .list(&self.leaves, |w, l| {
                w.bytes(&l.envelope_bytes);
            });
        let mut lens = Vec::with_capacity(contributing.len());
        for (_, leaf) in &contributing {
            lens.push(
                u32::try_from(leaf.proposal_len)
                    .map_err(|_| corrupt("proposal longer than u32::MAX bytes"))?,
            );
        }
        let records: Vec<(u64, u32, &[u8])> = contributing
            .iter()
            .zip(lens)
            .map(|((i, leaf), len)| (*i, len, leaf.payload.as_slice()))
            .collect();
        w.list(&records, |w, (i, len, payload)| {
            w.u64(*i).u32(*len).bytes(payload);
        });
        Ok(Ok(w.finish().map_err(encode_failed)?))
    }
}
