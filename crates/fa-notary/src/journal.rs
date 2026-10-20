//! The journal as the accumulator sees it: every committed `Entry` (posting
//! and control classes alike) and, after the prefix's evidence boundary,
//! every journaled evidence record (attestations, import receipts, custody
//! transfers, supplemental evidence) as one leaf, in `(commit_seq, ordinal)`
//! order, read from the authoritative payloads at a fixed known-at sequence.
//!
//! Leaf envelope (plan §13.2, Appendix A), canonical bytes under the model's
//! codec laws:
//!
//! ```text
//! LeafEnvelope { kind: u8, book_id: [16], branch_id: [16],
//!                commit_seq: u64, within_commit_ordinal: u32,
//!                record_digest: [32], class: u16,
//!                effective_day: Option<i32>, account_vids: sorted [u128],
//!                unit_ids: sorted [u32] }
//! ```
//!
//! `commit_seq` is the record vertex's creating commit — recorded time, never
//! user-supplied. `within_commit_ordinal` ranks the records of one commit by
//! ascending vertex id, whatever their kind: a pure function of the journal.
//! (Most kernel paths commit one entry per transaction, so the ordinal is 0;
//! batches and a document's intake beside its entry follow the same rule.)
//!
//! For an entry (kind 1) `record_digest` is its `entry_digest`, `class` its
//! entry class, `effective_day` absent exactly for the book-scoped, undated
//! control classes, and the selection fields the sorted distinct leg
//! accounts and leg units. An evidence record carries no effective day and
//! no selectors; its `record_digest` is the digest its payload ends with,
//! and `class` names its variant: the claim tag of an attestation (kind 2),
//! the intake-source tag of an import receipt (kind 3), 2 for a custody
//! transfer (kind 4) and 1 for supplemental evidence (kind 5) — exactly as
//! `fa-verify` rebuilds them from the payload.
//!
//! **The evidence boundary.** Accumulator states journaled before evidence
//! records were leaves (state schema minor 0) cover entries only. Their
//! prefixes stay valid forever, so evidence enters a book's accumulator
//! only after a recorded boundary: a journal read with `evidence_after =
//! Some(b)` adds the evidence records created after commit `b`, and `None`
//! reads entries alone. A fresh book's boundary is the substrate's first
//! commit (`state::FIRST_COMMIT`): nothing at or before a book's genesis is
//! evidence, so every evidence record is a leaf. A book whose last state
//! predates the boundary takes that state's sequence, so the next state
//! still extends it (consistency).

use std::collections::btree_map::Entry as MapEntry;
use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::attestation::StoredAttestation;
use fa_journal::custody::{CustodyBody, CustodyEvent};
use fa_journal::evidence::SupplementalEvidence;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_journal::rows::bytes;
use fa_model::symbols::{label, property};
use fa_model::{
    ControlPayload, EncodeError, Entry, EntryClass, EntryOrigin, Id128, IntakeSource, Writer,
};
use fa_money::Side;
use fgdb::{Database, VertexRow};
use fgdb_types::{CommitSeq, VId};

use crate::tree::{Digest, Tree, leaf_hash};
use crate::{Statement, code};

/// Record kinds (plan §13.2, bead fa-va02): journal entries (posting and
/// control classes), attestations (`Reviewed`, `ManualAssertion`,
/// `RegisterEquals`), import receipts, custody transfers, and supplemental
/// evidence. The tags are `fa-verify`'s.
pub const KIND_ENTRY: u8 = 1;
pub const KIND_ATTESTATION: u8 = 2;
pub const KIND_IMPORT_RECEIPT: u8 = 3;
pub const KIND_CUSTODY_TRANSFER: u8 = 4;
pub const KIND_SUPPLEMENTAL_EVIDENCE: u8 = 5;

/// An attestation's payload ends with its `signed_digest` and the
/// authentication trailer (scheme, profile, capability commitment).
const ATTESTATION_TRAILER: usize = 32 + 1 + 1 + 32;
/// Custody events and supplements end with the digest of their body.
const DIGEST_TRAILER: usize = 32;

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
    /// An entry's class; for an evidence record, its variant tag in the
    /// same `u16` (see the module docs). Compare it only together with
    /// `kind`.
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
            | EntryClass::IMPORT_CONTROL
            | EntryClass::HOLD_CONTROL
            | EntryClass::DRAFT_CONTROL
            | EntryClass::SCENARIO_CONTROL
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

    /// Whether the leaf is a journal entry (kind 1), the only kind that
    /// carries legs, an entry class and an effective day.
    #[must_use]
    pub fn is_entry(&self) -> bool {
        self.kind == KIND_ENTRY
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

/// A journaled record the accumulator folds, decoded and verified against
/// the digest its payload carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Entry(Box<Entry>),
    Attestation(StoredAttestation),
    /// An import receipt (custody event 0) or a custody transfer.
    Custody(CustodyEvent),
    Supplement(SupplementalEvidence),
}

impl From<Entry> for Record {
    fn from(entry: Entry) -> Self {
        Self::Entry(Box::new(entry))
    }
}

impl Record {
    /// The record a vertex row holds, or `None` for a vertex that is no
    /// record kind (a derived, metadata or chart vertex).
    pub fn of_row(row: &VertexRow) -> Result<Option<Self>, KernelError> {
        let decode = |what: &'static str| bytes(row, property::FA_PAYLOAD, what);
        let record = if row.labels.contains(&label::ENTRY) {
            Self::Entry(Box::new(Entry::decode(&decode("entry.payload")?)?))
        } else if row.labels.contains(&label::ATTESTATION) {
            Self::Attestation(StoredAttestation::decode(&decode("attestation.payload")?)?)
        } else if row.labels.contains(&label::IMPORT_RECEIPT)
            || row.labels.contains(&label::CUSTODY_TRANSFER)
        {
            Self::Custody(CustodyEvent::decode(&decode("custody.payload")?)?)
        } else if row.labels.contains(&label::SUPPLEMENTAL_EVIDENCE) {
            Self::Supplement(SupplementalEvidence::decode(&decode(
                "supplement.payload",
            )?)?)
        } else {
            return Ok(None);
        };
        if !has_record_label(row, record.kind()) {
            return Err(corrupt(format!(
                "vertex {:032x}: its label is not the record kind its payload holds",
                row.vid.0
            )));
        }
        Ok(Some(record))
    }

    /// Decode `payload` as a record of `kind`.
    pub fn decode(kind: u8, payload: &[u8]) -> Result<Self, KernelError> {
        let record = match kind {
            KIND_ENTRY => Self::Entry(Box::new(Entry::decode(payload)?)),
            KIND_ATTESTATION => Self::Attestation(StoredAttestation::decode(payload)?),
            KIND_IMPORT_RECEIPT | KIND_CUSTODY_TRANSFER => {
                Self::Custody(CustodyEvent::decode(payload)?)
            }
            KIND_SUPPLEMENTAL_EVIDENCE => Self::Supplement(SupplementalEvidence::decode(payload)?),
            other => return Err(corrupt(format!("record kind {other} is not accumulated"))),
        };
        if record.kind() != kind {
            return Err(corrupt(format!(
                "a kind {kind} leaf holds a kind {} record",
                record.kind()
            )));
        }
        Ok(record)
    }

    #[must_use]
    pub fn kind(&self) -> u8 {
        match self {
            Self::Entry(_) => KIND_ENTRY,
            Self::Attestation(_) => KIND_ATTESTATION,
            Self::Custody(e) if e.index == 0 => KIND_IMPORT_RECEIPT,
            Self::Custody(_) => KIND_CUSTODY_TRANSFER,
            Self::Supplement(_) => KIND_SUPPLEMENTAL_EVIDENCE,
        }
    }

    #[must_use]
    pub fn book_id(&self) -> Id128 {
        match self {
            Self::Entry(e) => e.proposal.book_id,
            Self::Attestation(a) => a.attestation.book_id,
            Self::Custody(e) => e.book_id,
            Self::Supplement(s) => s.book_id,
        }
    }

    /// Entries name their branch; evidence records belong to the trunk.
    #[must_use]
    pub fn branch_id(&self) -> Id128 {
        match self {
            Self::Entry(e) => e.proposal.branch_id,
            _ => Id128::TRUNK,
        }
    }

    /// The canonical `_fa_payload` bytes: the record body followed by its
    /// digest (and, for an attestation, its authentication trailer).
    pub fn payload(&self) -> Result<Vec<u8>, KernelError> {
        match self {
            Self::Entry(e) => Ok(e.encode()?),
            Self::Attestation(a) => a.attestation.canonical_bytes(&a.binding),
            Self::Custody(e) => e.canonical_bytes(),
            Self::Supplement(s) => s.canonical_bytes(),
        }
    }

    /// Where the digested body ends inside [`Record::payload`]: an entry's
    /// proposal, or the body before an evidence record's digest. This is
    /// the split `fa-verify` is told when a proof carries the record.
    pub fn body_len(&self, payload: &[u8]) -> Result<usize, KernelError> {
        let trailer = match self {
            Self::Entry(e) => return Ok(e.proposal.canonical_bytes()?.len()),
            Self::Attestation(_) => ATTESTATION_TRAILER,
            Self::Custody(_) | Self::Supplement(_) => DIGEST_TRAILER,
        };
        payload
            .len()
            .checked_sub(trailer)
            .ok_or_else(|| corrupt("a record payload shorter than its digest trailer"))
    }

    /// The digest the envelope binds: an entry's `entry_digest`, or the
    /// domain-separated digest of an evidence record's body.
    pub fn record_digest(&self) -> Result<[u8; 32], KernelError> {
        match self {
            Self::Entry(e) => Ok(e.entry_digest),
            Self::Attestation(a) => Ok(a.signed_digest),
            Self::Custody(e) => e.digest(),
            Self::Supplement(s) => s.body_digest(),
        }
    }

    /// The envelope of this record at journal position `(commit_seq,
    /// ordinal)`.
    pub fn envelope(
        &self,
        commit_seq: CommitSeq,
        within_commit_ordinal: u32,
    ) -> Result<LeafEnvelope, KernelError> {
        let class = match self {
            Self::Entry(entry) => {
                return Ok(LeafEnvelope::of_entry(
                    entry,
                    commit_seq,
                    within_commit_ordinal,
                ));
            }
            Self::Attestation(a) => u16::from(a.attestation.claim.tag()),
            Self::Custody(CustodyEvent {
                body: CustodyBody::Receipt { source, .. },
                ..
            }) => intake_tag(source),
            Self::Custody(_) => 2,
            Self::Supplement(_) => 1,
        };
        Ok(LeafEnvelope {
            kind: self.kind(),
            book_id: self.book_id(),
            branch_id: Id128::TRUNK,
            commit_seq,
            within_commit_ordinal,
            record_digest: self.record_digest()?,
            class: EntryClass(class),
            effective_day: None,
            account_vids: Vec::new(),
            unit_ids: Vec::new(),
        })
    }
}

/// The intake source's wire tag (`IntakeSource::encode`).
fn intake_tag(source: &IntakeSource) -> u16 {
    match source {
        IntakeSource::Upload { .. } => 1,
        IntakeSource::Connector { .. } => 2,
        IntakeSource::Email { .. } => 3,
        IntakeSource::Scan { .. } => 4,
    }
}

/// Whether `row` carries the label of record `kind`.
fn has_record_label(row: &VertexRow, kind: u8) -> bool {
    let want = match kind {
        KIND_ENTRY => label::ENTRY,
        KIND_ATTESTATION => label::ATTESTATION,
        KIND_IMPORT_RECEIPT => label::IMPORT_RECEIPT,
        KIND_CUSTODY_TRANSFER => label::CUSTODY_TRANSFER,
        KIND_SUPPLEMENTAL_EVIDENCE => label::SUPPLEMENTAL_EVIDENCE,
        _ => return false,
    };
    row.labels.contains(&want)
}

/// One accumulated record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub vid: VId,
    pub envelope: LeafEnvelope,
    pub envelope_bytes: Vec<u8>,
    pub hash: Digest,
    /// The record's `_fa_payload` bytes.
    pub payload: Vec<u8>,
    /// Where the digested body ends inside `payload`: an entry's proposal,
    /// or an evidence record's body ([`Record::body_len`]).
    pub proposal_len: usize,
}

impl Leaf {
    /// The record this leaf accumulates, decoded from its payload.
    pub fn record(&self) -> Result<Record, KernelError> {
        Record::decode(self.envelope.kind, &self.payload)
    }

    /// The record this leaf accumulates, when the leaf is exactly what that
    /// record determines at its journal position: envelope, envelope bytes,
    /// canonical payload and body split. `None` when the leaf disagrees with
    /// its own record.
    pub fn authenticated_record(&self) -> Result<Option<Record>, KernelError> {
        let record = self.record()?;
        let envelope = record.envelope(
            self.envelope.commit_seq,
            self.envelope.within_commit_ordinal,
        )?;
        let payload = record.payload()?;
        let same = envelope == self.envelope
            && envelope.canonical_bytes().map_err(encode_failed)? == self.envelope_bytes
            && record.body_len(&payload)? == self.proposal_len
            && payload == self.payload;
        Ok(same.then_some(record))
    }
}

/// The journal prefix through `through_seq`, with its accumulator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Journal {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub through_seq: CommitSeq,
    /// The evidence boundary: evidence records created after this commit
    /// are leaves; `None` accumulates entries alone (see the module docs).
    pub evidence_after: Option<CommitSeq>,
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
    /// Accumulate the entries `records` — `(vertex id, entry, creating
    /// commit)` — as the prefix through `through_seq`, with no evidence
    /// records ([`Journal::from_records_with_evidence`]).
    pub fn from_records(
        book_id: Id128,
        through_seq: CommitSeq,
        records: Vec<(VId, Entry, CommitSeq)>,
    ) -> Result<Self, KernelError> {
        let records = records
            .into_iter()
            .map(|(vid, entry, seq)| (vid, Record::from(entry), seq))
            .collect();
        Self::from_records_with_evidence(book_id, through_seq, None, records)
    }

    /// Accumulate `records` — `(vertex id, record, creating commit)` — as
    /// the prefix through `through_seq` with the evidence boundary
    /// `evidence_after`. Every record must belong to the book's trunk and
    /// lie inside the prefix, and every evidence record after the boundary;
    /// order is derived, never trusted.
    pub fn from_records_with_evidence(
        book_id: Id128,
        through_seq: CommitSeq,
        evidence_after: Option<CommitSeq>,
        mut records: Vec<(VId, Record, CommitSeq)>,
    ) -> Result<Self, KernelError> {
        records.sort_by_key(|(vid, _, seq)| (*seq, vid.0));
        let mut leaves: Vec<Leaf> = Vec::with_capacity(records.len());
        let mut tree = Tree::new();
        let mut ordinal = 0u32;
        for (vid, record, seq) in records {
            if record.book_id() != book_id || record.branch_id() != Id128::TRUNK {
                return Err(corrupt(format!(
                    "record {:032x} does not belong to this book's trunk",
                    vid.0
                )));
            }
            if seq > through_seq {
                return Err(corrupt(format!(
                    "record {:032x} was recorded at {} after the prefix through {}",
                    vid.0, seq.0, through_seq.0
                )));
            }
            if record.kind() != KIND_ENTRY && evidence_after.is_none_or(|b| seq <= b) {
                return Err(corrupt(format!(
                    "evidence record {:032x} was recorded at {}, inside the prefix's entries-only history",
                    vid.0, seq.0
                )));
            }
            ordinal = match leaves.last() {
                Some(prev) if prev.envelope.commit_seq == seq => ordinal
                    .checked_add(1)
                    .ok_or_else(|| corrupt("more than u32::MAX records in one commit"))?,
                _ => 0,
            };
            let envelope = record.envelope(seq, ordinal)?;
            let envelope_bytes = envelope.canonical_bytes().map_err(encode_failed)?;
            let payload = record.payload()?;
            let proposal_len = record.body_len(&payload)?;
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
            evidence_after,
            leaves,
            tree,
        })
    }

    /// Read the journal of `book` as known at `known_at` (default: head)
    /// from the authoritative record payloads: every `Entry`, and every
    /// evidence record created after `evidence_after` (none when `None`).
    /// Derived vertices (registers, mirrors, accumulator states) are never
    /// an input.
    pub fn read<V: asupersync::fs::Vfs + Clone>(
        db: &Database<V>,
        book: &BookContext,
        known_at: Option<CommitSeq>,
        evidence_after: Option<CommitSeq>,
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
            let entry = row.labels.contains(&label::ENTRY);
            if !entry && evidence_after.is_none_or(|b| row.created_at <= b) {
                continue;
            }
            if let Some(record) = Record::of_row(&row)? {
                records.push((row.vid, record, row.created_at));
            }
        }
        Ok(Ok(Self::from_records_with_evidence(
            book.book_id,
            seq,
            evidence_after,
            records,
        )?))
    }

    /// Require every record in this historical prefix to remain unchanged
    /// at one fixed observed frontier. Re-reading only the old snapshot
    /// cannot detect a later raw-store rewrite or retirement: the substrate
    /// correctly preserves the old version for historical reads.
    ///
    /// This costs one point read per leaf and compares authoritative bytes,
    /// their digest mirror, the record kind's label and the creating
    /// sequence. New records after the prefix are permitted; derived Leg
    /// mirrors are the separate projection invariant. This is local tamper
    /// detection, not protection against replacement of the entire book
    /// directory.
    pub fn verify_unchanged_at<V: asupersync::fs::Vfs + Clone>(
        &self,
        db: &Database<V>,
        observed_at: CommitSeq,
    ) -> Outcome<()> {
        let refusal = |message: String| {
            Refusal::new(
                code::ACCUMULATOR_DRIFT,
                exit::VERIFICATION,
                message,
                "FA-INV-02 / FA-INV-14 (checkpointed journal records remain immutable)",
                "run `fa verify accumulator` and preserve the store for investigation; do not publish proofs or checkpoint over changed history",
            )
        };
        let head = db.frontier()?;
        if observed_at < self.through_seq || observed_at > head {
            return Ok(Err(refusal(format!(
                "cannot check the journal prefix through {} at sequence {}; the observed sequence must be between the prefix and head {}",
                self.through_seq.0, observed_at.0, head.0
            ))));
        }
        for leaf in &self.leaves {
            let noun = if leaf.envelope.is_entry() {
                "entry"
            } else {
                "evidence record"
            };
            let changed = |why: &str| {
                refusal(format!(
                    "checkpointed journal {noun} {:032x} {why} at observed sequence {} after the prefix through {}",
                    leaf.vid.0, observed_at.0, self.through_seq.0
                ))
            };
            let Some(row) = db.vertex_at(leaf.vid, observed_at)? else {
                return Ok(Err(changed("was retired or is absent")));
            };
            if !has_record_label(&row, leaf.envelope.kind) {
                return Ok(Err(changed(if leaf.envelope.is_entry() {
                    "lost its Entry label"
                } else {
                    "lost its record label"
                })));
            }
            if row.created_at != leaf.envelope.commit_seq {
                return Ok(Err(changed("has a different creating sequence")));
            }
            if bytes(&row, property::FA_PAYLOAD, "checkpointed record payload")
                .ok()
                .as_deref()
                != Some(leaf.payload.as_slice())
            {
                return Ok(Err(changed("has a rewritten or missing payload")));
            }
            if bytes(&row, property::FA_DIGEST, "checkpointed record digest")
                .ok()
                .as_deref()
                != Some(leaf.envelope.record_digest.as_slice())
            {
                return Ok(Err(changed("has a rewritten or missing digest")));
            }
        }
        Ok(Ok(()))
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

    /// The accumulator inclusion path of leaf `index` in this prefix.
    #[must_use]
    pub fn leaf_path(&self, index: usize) -> Option<Vec<Digest>> {
        self.tree.inclusion_path(index, self.leaves.len())
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
    /// cutoff: an entry whose envelope names both, whose class is not
    /// `Pending`, and whose effective day is at or before the cutoff when
    /// one is given.
    fn contributes(l: &Leaf, account: VId, unit: u32, through: Option<i32>) -> bool {
        let e = &l.envelope;
        e.is_entry()
            && e.class != EntryClass::PENDING
            && e.account_vids.binary_search(&account).is_ok()
            && e.unit_ids.binary_search(&unit).is_ok()
            && through.is_none_or(|cutoff| e.effective_day.is_some_and(|d| d <= cutoff))
    }

    /// The first leaf that would contribute to (account, unit) and is a
    /// migration chunk a register fold may not count at this prefix, with
    /// the reason, decided from the journal's own leaves (never from a run's
    /// state projection or its unauthenticated body; WhiteCreek 3905): a
    /// chunk whose run has no Finalize leaf in the prefix (staged or
    /// abandoned), or one dated before its run's `Open` leaf, which
    /// `open_run` dates on the run's opening date (a non-sole `FullDetail`
    /// run's summarized history, ruling 3675 F3). A run with no single Open
    /// leaf, or a leaf whose class and origin disagree about migration, is
    /// refused too (WhiteCreek 3910, MaroonSquirrel 3917): records are
    /// arbitrary to `from_records`. The accumulator keeps such leaves (they
    /// are journaled), and `fa-verify` decides its in-scope set from
    /// envelopes, which carry neither the run nor its body — so the proof
    /// refuses rather than disagree with the fold (ruling 3243; the format
    /// change is bead fa-e00). Conservative by design: a sole-source
    /// `FullDetail` run's history, which does count, is refused too until
    /// the format carries authenticated run metadata.
    fn staged_chunk(
        &self,
        account: VId,
        unit: u32,
        through: Option<i32>,
    ) -> Result<Option<(VId, &'static str)>, KernelError> {
        let mut finalized = BTreeSet::new();
        let mut opened: BTreeMap<VId, Option<i32>> = BTreeMap::new();
        for leaf in self
            .leaves
            .iter()
            .filter(|l| l.envelope.is_entry() && l.envelope.class == EntryClass::MIGRATION_CONTROL)
        {
            if let Some(ControlPayload::MigrationControl { run_ref, kind, .. }) =
                Entry::decode(&leaf.payload)?.proposal.control
            {
                if kind == fa_journal::migration::kind::FINALIZE {
                    finalized.insert(run_ref);
                } else if kind == fa_journal::migration::kind::OPEN {
                    // Two Open records for one run are not an honest journal
                    // (records are arbitrary to `from_records`): neither
                    // dates the run, so its chunks refuse (WhiteCreek 3910).
                    match opened.entry(run_ref) {
                        MapEntry::Vacant(slot) => {
                            slot.insert(leaf.envelope.effective_day);
                        }
                        MapEntry::Occupied(mut slot) => {
                            slot.insert(None);
                        }
                    }
                }
            }
        }
        for leaf in self
            .leaves
            .iter()
            .filter(|l| Self::contributes(l, account, unit, through))
        {
            let chunk = leaf.envelope.class == EntryClass::MIGRATION;
            let run_ref = match (Entry::decode(&leaf.payload)?.proposal.origin, chunk) {
                (EntryOrigin::Migration { run_ref, .. }, true) => run_ref,
                (EntryOrigin::Migration { .. }, false) | (_, true) => {
                    return Ok(Some((
                        leaf.vid,
                        "its class and origin disagree about migration",
                    )));
                }
                _ => continue,
            };
            if !finalized.contains(&run_ref) {
                return Ok(Some((leaf.vid, "its run has no Finalize record here")));
            }
            match opened.get(&run_ref) {
                Some(Some(open)) if leaf.envelope.effective_day.is_some_and(|d| d >= *open) => {}
                Some(Some(_)) => {
                    return Ok(Some((
                        leaf.vid,
                        "it is dated before its run's opening date (FullDetail history, refused even for a sole-source run until proofs carry run metadata)",
                    )));
                }
                _ => return Ok(Some((leaf.vid, "its run has no single Open record here"))),
            }
        }
        Ok(None)
    }

    /// The posted (debits, credits) of (account, unit) through the cutoff,
    /// folded from the entry payloads with checked arithmetic. Refused
    /// (FA-REF-133) while a contributing migration chunk is one a fold may
    /// not count at this prefix (see `staged_chunk`).
    pub fn posted_balance(
        &self,
        account: VId,
        unit: u32,
        through: Option<i32>,
    ) -> Outcome<(i128, i128)> {
        if let Some((chunk, why)) = self.staged_chunk(account, unit, through)? {
            return Ok(Err(Refusal::new(
                code::MIGRATION_STAGED,
                exit::REFUSAL,
                format!(
                    "the balance would count migration chunk {:032x}, which a fold may not count at this prefix: {why}",
                    chunk.0
                ),
                "plan §8.6, FA-INV-07 (a staged or abandoned chunk, or summarized FullDetail history, is invisible to every fold)",
                "prove the balance at a checkpoint after the run is finalized; accounts carrying abandoned migration chunks or pre-opening FullDetail history are provable once balance proofs carry the migration predicate (fa-e00)",
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

#[cfg(test)]
mod tests {
    use fa_journal::attestation::{Attestation, AttestationClaim, CapabilityBinding, Subject};
    use fa_model::{EntryRef, EvidenceRef, Oid};

    use super::*;

    const BOOK: Id128 = Id128([0x5a; 16]);

    fn receipt(document: u8, received_by: u128) -> Record {
        Record::Custody(CustodyEvent {
            book_id: BOOK,
            document_oid: Oid([document; 32]),
            index: 0,
            prev_digest: [0; 32],
            body: CustodyBody::Receipt {
                source: IntakeSource::Email {
                    message_id: "m-1".into(),
                },
                received_by: VId(received_by),
                digest_at_receipt: [document ^ 0xff; 32],
                run_ref: None,
            },
        })
    }

    fn transfer() -> Record {
        Record::Custody(CustodyEvent {
            book_id: BOOK,
            document_oid: Oid([1; 32]),
            index: 1,
            prev_digest: [9; 32],
            body: CustodyBody::Transfer {
                from: VId(7),
                to: VId(8),
            },
        })
    }

    fn supplement() -> Record {
        Record::Supplement(SupplementalEvidence {
            book_id: BOOK,
            entry_ref: EntryRef {
                vid: VId(41),
                entry_digest: [4; 32],
            },
            documents: vec![EvidenceRef {
                document_oid: Oid([2; 32]),
                doc_commit: [3; 32],
                role: 1,
            }],
            attached_by: VId(7),
        })
    }

    fn review() -> Record {
        let attestation = Attestation {
            book_id: BOOK,
            claim: AttestationClaim::Reviewed {
                against: Vec::new(),
            },
            subject: Subject::Document(Oid([1; 32])),
            principal: VId(11),
            evidence_refs: Vec::new(),
        };
        Record::Attestation(StoredAttestation {
            signed_digest: attestation.signed_digest().expect("digest"),
            attestation,
            binding: CapabilityBinding {
                profile: fa_journal::Profile::Human,
                capability_commitment: [6; 32],
            },
        })
    }

    /// The producer's evidence envelopes are exactly what the independent
    /// verifier rebuilds from the payload bytes alone, kind by kind, and the
    /// split the producer reports is the verifier's.
    #[test]
    fn every_evidence_kind_matches_the_verifier_byte_for_byte() {
        for (record, kind, class) in [
            (review(), KIND_ATTESTATION, 2),
            (receipt(1, 7), KIND_IMPORT_RECEIPT, 3),
            (transfer(), KIND_CUSTODY_TRANSFER, 2),
            (supplement(), KIND_SUPPLEMENTAL_EVIDENCE, 1),
        ] {
            assert_eq!(record.kind(), kind);
            let envelope = record.envelope(CommitSeq(9), 2).expect("envelope");
            assert_eq!(envelope.class, EntryClass(class));
            let payload = record.payload().expect("payload");
            let split = record.body_len(&payload).expect("split");
            let rebuilt = fa_verify::envelope::envelope_of_record(kind, &payload, split, 9, 2)
                .expect("the verifier accepts the record");
            assert_eq!(
                rebuilt.encode(),
                envelope.canonical_bytes().expect("bytes"),
                "kind {kind}"
            );
            assert_eq!(Record::decode(kind, &payload).expect("decodes"), record);
        }
        // A receipt is never read back as a transfer, nor the reverse.
        let payload = receipt(1, 7).payload().unwrap();
        assert!(Record::decode(KIND_CUSTODY_TRANSFER, &payload).is_err());
    }

    /// Records of one commit are ranked by vertex id whatever their kind,
    /// and evidence inside the entries-only history is refused, never
    /// silently dropped.
    #[test]
    fn evidence_leaves_respect_the_boundary_and_commit_order() {
        let records = vec![
            (VId(30), receipt(3, 7), CommitSeq(5)),
            (VId(20), supplement(), CommitSeq(5)),
            (VId(10), review(), CommitSeq(6)),
        ];
        let journal =
            Journal::from_records_with_evidence(BOOK, CommitSeq(6), Some(CommitSeq(4)), records)
                .expect("journal");
        let order: Vec<_> = journal
            .leaves
            .iter()
            .map(|l| {
                (
                    l.vid.0,
                    l.envelope.commit_seq.0,
                    l.envelope.within_commit_ordinal,
                )
            })
            .collect();
        assert_eq!(order, vec![(20, 5, 0), (30, 5, 1), (10, 6, 0)]);
        assert_eq!(journal.evidence_after, Some(CommitSeq(4)));
        for leaf in &journal.leaves {
            assert!(leaf.authenticated_record().unwrap().is_some());
        }

        for boundary in [None, Some(CommitSeq(5))] {
            let refused = Journal::from_records_with_evidence(
                BOOK,
                CommitSeq(6),
                boundary,
                vec![(VId(30), receipt(3, 7), CommitSeq(5))],
            );
            assert!(
                matches!(&refused, Err(KernelError::Corrupt(why)) if why.contains("entries-only history")),
                "{boundary:?}: {refused:?}"
            );
        }
    }

    /// A leaf whose payload is another valid record of its kind is not
    /// authenticated: the envelope binds the record digest.
    #[test]
    fn a_leaf_whose_payload_was_rewritten_is_not_authenticated() {
        let journal = Journal::from_records_with_evidence(
            BOOK,
            CommitSeq(6),
            Some(CommitSeq(1)),
            vec![(VId(30), receipt(3, 7), CommitSeq(5))],
        )
        .unwrap();
        let mut leaf = journal.leaves[0].clone();
        leaf.payload = receipt(3, 8).payload().unwrap();
        assert_eq!(leaf.authenticated_record().unwrap(), None);
    }
}
