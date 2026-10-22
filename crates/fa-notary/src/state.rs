//! Journaled accumulator states (plan §13.2, Appendix A `AccumulatorState`).
//!
//! ```text
//! AccumulatorState { schema_major: u16 (1), schema_minor: u16 (0 | 1),
//!                    book_id: [16], branch_id: [16], through_seq: u64,
//!                    leaf_count: u64, root: [32], peaks: [[32]],
//!                    prev_state_oid: Option<[32]>,
//!                    evidence_after_seq: u64 (minor 1 only) }
//! oid = BLAKE3("fa:accumulator-state:v1" ‖ canonical bytes)
//! vid = low 128 bits of BLAKE3("fa:vid:accumulator-state:v1" ‖ oid)
//! ```
//!
//! Minor 0 states accumulate entries alone. A minor 1 state also
//! accumulates the evidence records created after `evidence_after_seq`
//! (bead fa-va02; [`crate::journal`]'s evidence boundary), which lies in
//! `1..=through_seq`. Every new state is minor 1, and the boundary is a
//! property of the chain, never a choice: a book's first state takes
//! [`FIRST_COMMIT`] (the substrate's first commit, which is or precedes the
//! book's genesis and records no evidence, so every evidence record is a
//! leaf), a state after a minor 0 predecessor takes that predecessor's
//! sequence, and a state after a minor 1 predecessor keeps its boundary.
//! [`verify_accumulator`] refuses any other boundary, so a key holder
//! cannot drop evidence by moving it.
//!
//! A state is a payload object: immutable, content-addressed, written by
//! the notary in its own transaction — never inside a posting transaction,
//! so there is no hot object on the write path — and it is not itself a
//! leaf. The book-root vertex's `accumulator_head` property names the latest
//! state; it moves only by compare-and-set from the `prev_state_oid` the new
//! state records, so two notaries racing from one head are a
//! first-committer-wins conflict and the chain can never fork. The pointer
//! is a projection of the chain, never more authoritative than the journal
//! the states are recomputed from ([`verify_accumulator`], FA-INV-14).
//!
//! A state is unsigned itself: the signed object is the
//! [`TransparencyCheckpoint`] journaled beside it in the same transaction,
//! one per state at a vertex derived from the state's oid, linked
//! `CHECKPOINTS` → the state. Both are recomputed by
//! [`verify_accumulator`].

use std::collections::BTreeSet;

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_journal::rows::{book_root, bytes, edge_id, prop};
use fa_model::symbols::{label, property, relation};
use fa_model::{DecodeError, EncodeError, Id128, Oid, Reader, Writer};
use fgdb::{Database, QueryError, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_crypto::Hasher;
use fgdb_gql::{GqlParameters, GqlQueryPolicy};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::checkpoint::{
    CheckpointBody, SignError, TransparencyCheckpoint, checkpoint_oid, checkpoint_vid,
};
use crate::journal::{Journal, LeafKinds};
use crate::scope::{ScopeIndex, ScopeRequest};
use crate::sign::CheckpointSigner;
use crate::tree::Digest;
use crate::{Statement, code};

pub const STATE_OID_DOMAIN: &[u8] = b"fa:accumulator-state:v1";
pub const STATE_VID_DOMAIN: &[u8] = b"fa:vid:accumulator-state:v1";
pub const STATE_SCHEMA_MAJOR: u16 = 1;
/// States that accumulate entries alone.
pub const STATE_SCHEMA_MINOR: u16 = 0;
/// States that also accumulate evidence records after a recorded boundary.
pub const STATE_SCHEMA_MINOR_BOUNDARY: u16 = 1;
/// The substrate's first commit (an empty database's frontier is 0): the
/// evidence boundary of a book's first state. No commit at or before a
/// book's genesis records evidence, so the state accumulates all of it.
pub const FIRST_COMMIT: CommitSeq = CommitSeq(1);
/// One peak per bit of a `u64` leaf count.
const MAX_PEAKS: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccumulatorState {
    pub book_id: Id128,
    pub branch_id: Id128,
    /// The prefix is every entry recorded at or before this sequence.
    pub through_seq: CommitSeq,
    pub leaf_count: u64,
    pub root: Digest,
    /// Largest (leftmost) first; they bag right to left to `root`.
    pub peaks: Vec<Digest>,
    pub prev_state_oid: Option<Oid>,
    /// The evidence boundary: `None` for a minor 0 state (entries alone),
    /// otherwise the commit after which evidence records are leaves.
    pub evidence_after: Option<CommitSeq>,
}

impl AccumulatorState {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let minor = match self.evidence_after {
            None => STATE_SCHEMA_MINOR,
            Some(_) => STATE_SCHEMA_MINOR_BOUNDARY,
        };
        let mut w = Writer::with_capacity(136 + 32 * self.peaks.len());
        w.u16(STATE_SCHEMA_MAJOR)
            .u16(minor)
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.through_seq.0)
            .u64(self.leaf_count)
            .fixed(&self.root)
            .list(&self.peaks, |w, p| {
                w.fixed(p);
            })
            .opt(self.prev_state_oid.as_ref(), |w, o| {
                w.fixed(&o.0);
            });
        if let Some(boundary) = self.evidence_after {
            w.u64(boundary.0);
        }
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u16("state.schema_major")? != STATE_SCHEMA_MAJOR {
            return Err(r.invalid("state.schema_major"));
        }
        let minor = r.u16("state.schema_minor")?;
        if minor != STATE_SCHEMA_MINOR && minor != STATE_SCHEMA_MINOR_BOUNDARY {
            return Err(r.invalid("state.schema_minor"));
        }
        let mut state = Self {
            book_id: Id128(r.fixed("state.book_id")?),
            branch_id: Id128(r.fixed("state.branch_id")?),
            through_seq: CommitSeq(r.u64("state.through_seq")?),
            leaf_count: r.u64("state.leaf_count")?,
            root: r.fixed("state.root")?,
            peaks: r.list(MAX_PEAKS, "state.peaks", |r| r.fixed("state.peak"))?,
            prev_state_oid: r.opt("state.prev_state_oid", |r| {
                r.fixed("state.prev_state_oid").map(Oid)
            })?,
            evidence_after: None,
        };
        if minor == STATE_SCHEMA_MINOR_BOUNDARY {
            let boundary = r.u64("state.evidence_after_seq")?;
            if boundary == 0 || boundary > state.through_seq.0 {
                return Err(r.invalid("state.evidence_after_seq"));
            }
            state.evidence_after = Some(CommitSeq(boundary));
        }
        r.finish()?;
        Ok(state)
    }

    pub fn oid(&self) -> Result<Oid, EncodeError> {
        Ok(state_oid(&self.canonical_bytes()?))
    }

    #[must_use]
    pub fn statement(&self) -> Statement {
        Statement {
            book_id: self.book_id,
            branch_id: self.branch_id,
            through_seq: self.through_seq,
            leaf_count: self.leaf_count,
            root: self.root,
        }
    }

    /// The state that commits `journal` after `prev`, with the journal's
    /// evidence boundary.
    #[must_use]
    pub fn of_journal(journal: &Journal, prev_state_oid: Option<Oid>) -> Self {
        Self {
            book_id: journal.book_id,
            branch_id: journal.branch_id,
            through_seq: journal.through_seq,
            leaf_count: journal.len(),
            root: journal.root(),
            peaks: journal.peaks(),
            prev_state_oid,
            evidence_after: journal.evidence_after,
        }
    }

    /// The evidence boundary of the state that follows this one on the
    /// chain: this state's own, or, after an entries-only state, its
    /// sequence (so the successor still extends it).
    #[must_use]
    pub fn successor_boundary(&self) -> CommitSeq {
        self.evidence_after.unwrap_or(self.through_seq)
    }
}

#[must_use]
pub fn state_oid(canonical_bytes: &[u8]) -> Oid {
    let mut h = Hasher::new();
    h.update(STATE_OID_DOMAIN);
    h.update(canonical_bytes);
    Oid(h.finalize().0)
}

#[must_use]
pub fn state_vid(oid: &Oid) -> VId {
    let mut h = Hasher::new();
    h.update(STATE_VID_DOMAIN);
    h.update(&oid.0);
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

/// A state as stored: its object, oid, vertex, and creating commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredState {
    pub oid: Oid,
    pub vid: VId,
    pub recorded_at: CommitSeq,
    pub state: AccumulatorState,
    /// The canonical bytes, for outsiders (`fa_verify::verify_state`).
    pub bytes: Vec<u8>,
}

fn oid_scalar(oid: &Oid) -> Result<CanonicalScalar, KernelError> {
    CanonicalScalar::bytes(oid.0.to_vec()).map_err(|_| KernelError::Scalar("accumulator oid"))
}

/// The head pointer a book-root row holds: `None` before the first state.
fn head_of(row: &VertexRow) -> Result<Option<Oid>, KernelError> {
    match prop(row, property::ACCUMULATOR_HEAD) {
        None => Ok(None),
        Some(CanonicalScalar::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map(|raw: [u8; 32]| Some(Oid(raw)))
            .map_err(|_| KernelError::Corrupt("accumulator_head is not a 32-byte oid".into())),
        Some(other) => Err(KernelError::Corrupt(format!(
            "accumulator_head is not bytes: {other:?}"
        ))),
    }
}

/// Decode a state vertex and check it is the object its oid names.
fn stored(row: &VertexRow, oid: &Oid) -> Result<StoredState, KernelError> {
    if !row.labels.contains(&label::ACCUMULATOR_STATE) {
        return Err(KernelError::Corrupt(format!(
            "vertex {:032x} named by an accumulator oid is not an AccumulatorState",
            row.vid.0
        )));
    }
    let payload = bytes(row, property::FA_PAYLOAD, "accumulator_state.payload")?;
    if state_oid(&payload) != *oid {
        return Err(KernelError::Corrupt(format!(
            "accumulator state {:032x} does not hash to its oid",
            row.vid.0
        )));
    }
    let state = AccumulatorState::decode(&payload)
        .map_err(|e| KernelError::Corrupt(format!("accumulator state: {e}")))?;
    Ok(StoredState {
        oid: *oid,
        vid: row.vid,
        recorded_at: row.created_at,
        state,
        bytes: payload,
    })
}

fn load<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    oid: &Oid,
    at: CommitSeq,
) -> Result<StoredState, KernelError> {
    let row = db.vertex_at(state_vid(oid), at)?.ok_or_else(|| {
        KernelError::Corrupt(format!(
            "accumulator state {} is named but absent",
            hex(&oid.0)
        ))
    })?;
    stored(&row, oid)
}

/// A checkpoint as stored: its object, oid, vertex, and canonical bytes
/// (for outsiders: `fa_verify::verify_checkpoint`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredCheckpoint {
    pub oid: Oid,
    pub vid: VId,
    pub checkpoint: TransparencyCheckpoint,
    pub bytes: Vec<u8>,
}

/// The substrate's chain commitment at `at`: the Chronicle marker-chain
/// hash a certified read at that sequence names (`snapshot_identity`). The
/// read itself is a fixed count; only its certificate is used.
fn chain_commitment<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Digest, KernelError> {
    const READ: &str = "MATCH (n:Entry) FOR SYSTEM_TIME AS OF SEQ $at RETURN COUNT(*) AS c";
    let refused = |what: String| {
        KernelError::Corrupt(format!("the chain-commitment read at {}: {what}", at.0))
    };
    let params = GqlParameters::new()
        .with_uint64("at", at.0)
        .map_err(|e| refused(format!("{e:?}")))?;
    let policy = GqlQueryPolicy::new(1 << 24, 1, 1 << 26, 1 << 20);
    match db.execute_certified(&ctx.query(), READ, &params, book.symbols.clone(), policy) {
        Ok((_, certificate)) => Ok(certificate.snapshot_identity.0),
        Err(QueryError::Read(e)) => Err(KernelError::Read(e)),
        Err(e) => Err(refused(format!("{e:?}"))),
    }
}

/// The checkpoint the journal prefix of `state` (journaled as `state_oid`)
/// and the book's signer reproduce.
fn expected_checkpoint<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    journal: &Journal,
    state_oid: &Oid,
    signer: &dyn CheckpointSigner,
) -> Result<TransparencyCheckpoint, KernelError> {
    let body = CheckpointBody {
        statement: journal.statement(),
        state_oid: *state_oid,
        scope_index_root: ScopeIndex::of(journal).root(),
        substrate_chain_commitment: chain_commitment(db, ctx, book, journal.through_seq)?,
        witness_policy_oid: None,
        time_evidence_oid: None,
    };
    TransparencyCheckpoint::sign(body, &[signer]).map_err(|e| match e {
        SignError::Encode(e) => KernelError::Model(fa_model::EntryError::Encode(e)),
        // Unreachable for a key derived from BookKeys (a clamped scalar
        // times the base point has order L); a foreign signer with an
        // untrustable key is a configuration fault, never a signature.
        SignError::UntrustableKey { .. } => KernelError::Corrupt(e.to_string()),
    })
}

/// The checkpoint vertex of `state_oid` as stored at `at`, or a finding:
/// absent, mislabeled, not hashing to the oid it records, or undecodable.
fn load_checkpoint<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    state_oid: &Oid,
    at: CommitSeq,
) -> Result<Result<StoredCheckpoint, String>, KernelError> {
    let vid = checkpoint_vid(state_oid);
    let Some(row) = db.vertex_at(vid, at)? else {
        return Ok(Err(format!(
            "the state {} has no checkpoint",
            hex(&state_oid.0)
        )));
    };
    if !row.labels.contains(&label::TRANSPARENCY_CHECKPOINT) {
        return Ok(Err(format!(
            "vertex {:032x} at the checkpoint id is not a TransparencyCheckpoint",
            vid.0
        )));
    }
    let payload = bytes(&row, property::FA_PAYLOAD, "checkpoint.payload")?;
    let oid = checkpoint_oid(&payload);
    match prop(&row, property::FA_DIGEST) {
        Some(CanonicalScalar::Bytes(d)) if d.as_slice() == oid.0 => {}
        _ => {
            return Ok(Err(format!(
                "checkpoint {:032x} does not hash to the digest it records",
                vid.0
            )));
        }
    }
    match TransparencyCheckpoint::decode(&payload) {
        Ok(checkpoint) => Ok(Ok(StoredCheckpoint {
            oid,
            vid,
            checkpoint,
            bytes: payload,
        })),
        Err(e) => Ok(Err(format!("checkpoint {:032x}: {e}", vid.0))),
    }
}

/// The refusal for a checkpoint the journal and the book's key do not
/// reproduce.
fn checkpoint_invalid(message: String) -> Refusal {
    Refusal::new(
        code::CHECKPOINT_INVALID,
        exit::VERIFICATION,
        message,
        "FA-INV-14 (a checkpoint is recomputed from the journal prefix and the book's key)",
        "run `fa verify accumulator` and preserve the store for investigation; no proof is issued against it",
    )
}

/// The stored checkpoint of the journaled `state`, after recomputing it —
/// statement, scope-index root, chain commitment, and the signature (Ed25519
/// is deterministic) — and comparing byte for byte. Refused (FA-REF-127,
/// exit 8) when the store holds anything else.
pub fn stored_checkpoint<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    state: &StoredState,
    signer: &dyn CheckpointSigner,
) -> Outcome<StoredCheckpoint> {
    let journal = match supported(db, book, &state.state)? {
        Ok(j) => j,
        Err(r) => return Ok(Err(r)),
    };
    let stored = match load_checkpoint(db, &state.oid, db.frontier()?)? {
        Ok(s) => s,
        Err(finding) => return Ok(Err(checkpoint_invalid(finding))),
    };
    let expected = expected_checkpoint(db, ctx, book, &journal, &state.oid, signer)?;
    if stored.checkpoint != expected {
        return Ok(Err(checkpoint_invalid(format!(
            "the checkpoint of the state through {} is not what the journal and the book's key reproduce",
            state.state.through_seq.0
        ))));
    }
    Ok(Ok(stored))
}

/// The latest journaled state as known at `known_at` (default: head).
pub fn latest<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    known_at: Option<CommitSeq>,
) -> Result<Option<StoredState>, KernelError> {
    let at = known_at.unwrap_or(db.frontier()?);
    let root = db
        .vertex_at(book_root(), at)?
        .ok_or_else(|| KernelError::Corrupt("the book root vertex is missing".into()))?;
    match head_of(&root)? {
        None => Ok(None),
        Some(oid) => load(db, &oid, at).map(Some),
    }
}

/// Every journaled state as known at `known_at` (default: head), newest
/// first, following `prev_state_oid` links. A link that cannot be followed
/// is an error here; [`verify_accumulator`] reports it as a finding instead.
pub fn chain<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    known_at: Option<CommitSeq>,
) -> Result<Vec<StoredState>, KernelError> {
    let frontier = db.frontier()?;
    match walk(db, known_at.map_or(frontier, |at| at.min(frontier)))? {
        (states, None) => Ok(states),
        (_, Some(broken)) => Err(KernelError::Corrupt(broken)),
    }
}

/// Follow the chain from the head at `at`, newest first. Content faults —
/// a malformed head pointer, a named state that is absent, mislabeled,
/// undecodable or not hashing to its oid, a cycle — end the walk with the
/// fault named; substrate read failures are errors.
fn walk<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    at: CommitSeq,
) -> Result<(Vec<StoredState>, Option<String>), KernelError> {
    fn content(e: KernelError) -> Result<String, KernelError> {
        match e {
            KernelError::Corrupt(why) => Ok(why),
            other => Err(other),
        }
    }
    let mut out: Vec<StoredState> = Vec::new();
    let root = db
        .vertex_at(book_root(), at)?
        .ok_or_else(|| KernelError::Corrupt("the book root vertex is missing".into()))?;
    let mut next = match head_of(&root) {
        Ok(head) => head,
        Err(e) => return Ok((out, Some(content(e)?))),
    };
    while let Some(oid) = next {
        if out.iter().any(|o| o.oid == oid) {
            return Ok((out, Some("the accumulator chain has a cycle".into())));
        }
        match load(db, &oid, at) {
            Ok(s) => {
                next = s.state.prev_state_oid;
                out.push(s);
            }
            Err(e) => return Ok((out, Some(content(e)?))),
        }
    }
    Ok((out, None))
}

/// The refusal for an accumulator chain the journal does not support.
fn drift(message: String) -> Refusal {
    Refusal::new(
        code::ACCUMULATOR_DRIFT,
        exit::VERIFICATION,
        message,
        "FA-INV-14 (each AccumulatorState extends the previous)",
        "run `fa verify accumulator` and preserve the store for investigation; do not checkpoint over it",
    )
}

/// A published state and the signed checkpoint beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpointed {
    pub stored: StoredState,
    pub checkpoint: StoredCheckpoint,
    /// The new state's leaves by record kind.
    pub leaf_kinds: LeafKinds,
}

/// The evidence boundary of a book's state given its predecessor on the
/// chain (module docs): [`FIRST_COMMIT`] for the first state, otherwise
/// [`AccumulatorState::successor_boundary`].
#[must_use]
pub fn chained_boundary(prev: Option<&AccumulatorState>) -> CommitSeq {
    prev.map_or(FIRST_COMMIT, AccumulatorState::successor_boundary)
}

/// Recompute the accumulator over the whole journal at the head and journal
/// it as the next `AccumulatorState` with its `TransparencyCheckpoint`
/// signed by `signer`, after checking that the journal still extends the
/// previous state and reproduces its checkpoint (a rewritten history or a
/// forged checkpoint is refused with exit 8, never papered over). The new
/// state accumulates evidence records after the boundary the chain implies
/// ([`chained_boundary`]).
pub async fn checkpoint<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    signer: &dyn CheckpointSigner,
) -> Outcome<Checkpointed> {
    let through = db.frontier()?;
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    let basis = txn.basis();
    if basis != through {
        txn.abort();
        return Ok(Err(Refusal::new(
            code::BASIS_MOVED,
            exit::CONFLICT,
            format!(
                "the book moved from {} to {} while the accumulator was computed",
                through.0, basis.0
            ),
            "plan §5.10 (an aggregate basis must equal the head at publication)",
            "checkpoint again",
        )));
    }
    let Some(root_row) = txn.vertex(db, book_root())? else {
        txn.abort();
        return Err(KernelError::Corrupt(
            "the book root vertex is missing".into(),
        ));
    };
    // The predecessor as the head names it. A head or predecessor that is
    // malformed, absent, or not the object its oid names is tampering:
    // refused with exit 8, like a predecessor the journal does not extend.
    let prev = match head_of(&root_row) {
        Ok(None) => Ok(None),
        Ok(Some(oid)) => match txn.vertex(db, state_vid(&oid))? {
            None => Err(KernelError::Corrupt(
                "accumulator_head names an absent state".into(),
            )),
            Some(row) => stored(&row, &oid).map(Some),
        },
        Err(e) => Err(e),
    };
    let prev = match prev {
        Ok(prev) => prev,
        Err(KernelError::Corrupt(why)) => {
            txn.abort();
            return Ok(Err(drift(why)));
        }
        Err(e) => {
            txn.abort();
            return Err(e);
        }
    };
    let boundary = chained_boundary(prev.as_ref().map(|p| &p.state));
    let journal = match Journal::read(db, book, Some(through), Some(boundary)) {
        Ok(Ok(journal)) => journal,
        Ok(Err(refusal)) => {
            txn.abort();
            return Ok(Err(refusal));
        }
        Err(KernelError::Corrupt(why)) => {
            txn.abort();
            return Ok(Err(drift(why)));
        }
        Err(KernelError::Model(error)) => {
            txn.abort();
            return Ok(Err(drift(format!(
                "the journal contains an invalid record payload: {error}"
            ))));
        }
        Err(error) => {
            txn.abort();
            return Err(error);
        }
    };
    match journal.verify_unchanged_at(db, through) {
        Ok(Ok(())) => {}
        Ok(Err(refusal)) => {
            txn.abort();
            return Ok(Err(refusal));
        }
        Err(error) => {
            txn.abort();
            return Err(error);
        }
    }
    if let Some(stored_prev) = prev.as_ref() {
        let prev = &stored_prev.state;
        // Publish only over a predecessor verification accepts: recorded
        // after the prefix it covers, and exactly what the journal through
        // its own sequence reproduces (so its leaf count is the count
        // through that sequence, not a prefix with an advanced sequence).
        if stored_prev.recorded_at <= prev.through_seq {
            txn.abort();
            return Ok(Err(drift(format!(
                "the last accumulator state was recorded at {} but claims a prefix through {}",
                stored_prev.recorded_at.0, prev.through_seq.0
            ))));
        }
        let prev_journal = match supported(db, book, prev)? {
            Ok(j) => j,
            Err(refusal) => {
                txn.abort();
                return Ok(Err(drift(format!(
                    "the last accumulator state is not what the journal reproduces: {}",
                    refusal.message
                ))));
            }
        };
        let finding = match load_checkpoint(db, &stored_prev.oid, through)? {
            Err(finding) => Some(finding),
            Ok(stored_cp) => {
                let expected =
                    expected_checkpoint(db, ctx, book, &prev_journal, &stored_prev.oid, signer)?;
                (stored_cp.checkpoint != expected).then(|| {
                    "the last checkpoint is not what the journal and the book's key reproduce"
                        .to_string()
                })
            }
        };
        if let Some(finding) = finding {
            txn.abort();
            return Ok(Err(checkpoint_invalid(finding)));
        }
        let extends = prev.book_id == journal.book_id
            && prev.branch_id == journal.branch_id
            && prev.through_seq < through
            && journal.root_at(prev.leaf_count) == Some(prev.root)
            && journal.peaks_at(prev.leaf_count).as_ref() == Some(&prev.peaks);
        if !extends {
            txn.abort();
            return Ok(Err(drift(format!(
                "the journal through {} does not extend the last accumulator state ({} leaves through {}): history was rewritten or the state is corrupt",
                through.0, prev.leaf_count, prev.through_seq.0
            ))));
        }
    }
    let prev_oid = prev.map(|p| p.oid);

    let state = AccumulatorState::of_journal(&journal, prev_oid);
    let payload = state
        .canonical_bytes()
        .map_err(fa_model::EntryError::Encode)?;
    let oid = state_oid(&payload);
    let svid = state_vid(&oid);
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(payload.clone())
                .map_err(|_| KernelError::Scalar("accumulator_state.payload"))?,
        ),
        (property::FA_DIGEST, oid_scalar(&oid)?),
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(book.book_id.0.to_vec())
                .map_err(|_| KernelError::Scalar("book_id"))?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    batch.create_vertex(svid, vec![label::ACCUMULATOR_STATE], props);
    batch.compare_and_set_vertex_property(
        book_root(),
        property::ACCUMULATOR_HEAD,
        prev_oid.as_ref().map(oid_scalar).transpose()?,
        oid_scalar(&oid)?,
        WriteMismatchPolicy::AbortWrite,
    );
    if let Some(prev) = &prev_oid {
        let pvid = state_vid(prev);
        batch.add_edge(
            edge_id(relation::DERIVED_FROM, svid, pvid),
            svid,
            pvid,
            vec![],
        );
    }

    // The signed checkpoint beside the state, in the same transaction.
    let cp = expected_checkpoint(db, ctx, book, &journal, &oid, signer)?;
    let cp_bytes = cp.canonical_bytes().map_err(fa_model::EntryError::Encode)?;
    let cp_oid = checkpoint_oid(&cp_bytes);
    let cvid = checkpoint_vid(&oid);
    let mut cprops = vec![
        (
            property::FA_PAYLOAD,
            CanonicalScalar::bytes(cp_bytes.clone())
                .map_err(|_| KernelError::Scalar("checkpoint.payload"))?,
        ),
        (property::FA_DIGEST, oid_scalar(&cp_oid)?),
        (
            property::BOOK_ID,
            CanonicalScalar::bytes(book.book_id.0.to_vec())
                .map_err(|_| KernelError::Scalar("book_id"))?,
        ),
    ];
    cprops.sort_by_key(|(k, _)| k.0);
    let mut checkpoints = WriteBatch::new(relation::CHECKPOINTS);
    checkpoints.create_vertex(cvid, vec![label::TRANSPARENCY_CHECKPOINT], cprops);
    checkpoints.add_edge(
        edge_id(relation::CHECKPOINTS, cvid, svid),
        cvid,
        svid,
        vec![],
    );
    txn.write_ordered(db, vec![batch, checkpoints])?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Checkpointed {
            stored: StoredState {
                oid,
                vid: svid,
                recorded_at: seq,
                state,
                bytes: payload,
            },
            checkpoint: StoredCheckpoint {
                oid: cp_oid,
                vid: cvid,
                checkpoint: cp,
                bytes: cp_bytes,
            },
            leaf_kinds: journal.leaf_kinds(),
        })),
        Err(WriteTxnError::Write(
            fgdb::WriteError::FirstCommitterWins { .. }
            | fgdb::WriteError::CompareAndSetMismatch(_)
            | fgdb::WriteError::AlreadyLive { .. },
        )) => Ok(Err(Refusal::new(
            code::HEAD_MOVED,
            exit::CONFLICT,
            "another accumulator state was published from the same head",
            "plan §13.2 (prev_state_oid moves under a compare-and-set)",
            "checkpoint again; the new state will extend the winner",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// One state's recomputation from the journal prefix it claims.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateCheck {
    pub oid: Oid,
    pub through_seq: CommitSeq,
    pub leaf_count: u64,
    pub recorded_at: CommitSeq,
    /// The state's evidence boundary (`None`: entries alone).
    pub evidence_after: Option<CommitSeq>,
    /// The recomputed prefix's leaves by kind; `None` when the prefix was
    /// not read (the state was refused before recomputation).
    pub leaf_kinds: Option<LeafKinds>,
    /// `None` when green; otherwise what failed.
    pub finding: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccumulatorVerification {
    /// Newest first, as far as the chain could be followed.
    pub states: Vec<StateCheck>,
    /// Why the chain could not be followed further: a malformed head
    /// pointer, or a named state that is absent, mislabeled, undecodable, or
    /// not the object its oid names, or a cycle. Tampering is a finding,
    /// never a read error.
    pub broken: Option<String>,
    /// State or checkpoint vertices the chain does not reach (a forged or
    /// orphaned object).
    pub unchained: Vec<VId>,
}

impl AccumulatorVerification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.broken.is_none()
            && self.unchained.is_empty()
            && self.states.iter().all(|s| s.finding.is_none())
    }
}

/// The evidence boundaries a state may carry after `prev` (`None` for the
/// oldest state on the chain): an entries-only state may follow only an
/// entries-only predecessor (or start the chain); otherwise exactly the
/// boundary [`chained_boundary`] derives.
fn boundary_admitted(state: &AccumulatorState, prev: Option<&AccumulatorState>) -> bool {
    match state.evidence_after {
        None => prev.is_none_or(|p| p.evidence_after.is_none()),
        Some(b) => b == chained_boundary(prev),
    }
}

/// FA-INV-14 by recomputation: every state on the chain is rebuilt from the
/// journal prefix it names and must match field for field; its checkpoint
/// is rebuilt from the same prefix and signed again by `signer` (Ed25519 is
/// deterministic) and must match byte for byte; each state extends its
/// predecessor; each was recorded after the prefix it covers; each carries
/// the evidence boundary its place on the chain implies; and every state
/// and checkpoint vertex in the store is on the chain. Every checkpointed
/// record must also retain its label, creating sequence, payload and digest
/// at the observed head: historical MVCC versions alone cannot show a later
/// rewrite or retirement. The additional work is one point read per leaf
/// of each checked state.
pub fn verify_accumulator<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    signer: &dyn CheckpointSigner,
) -> Result<AccumulatorVerification, KernelError> {
    let at = db.frontier()?;
    let (chain, broken) = walk(db, at)?;
    let mut states = Vec::with_capacity(chain.len());
    for (i, s) in chain.iter().enumerate() {
        let st = &s.state;
        let prev = chain.get(i + 1).map(|p| &p.state);
        let mut leaf_kinds = None;
        let mut finding = if st.book_id != book.book_id || st.branch_id != Id128::TRUNK {
            Some("the state names another book or branch".to_string())
        } else if s.recorded_at <= st.through_seq {
            Some(format!(
                "recorded at {} but claims a prefix through {}",
                s.recorded_at.0, st.through_seq.0
            ))
        } else if !boundary_admitted(st, prev) {
            Some(format!(
                "its evidence boundary {} is not the one its place on the chain implies ({})",
                st.evidence_after
                    .map_or_else(|| "none".to_string(), |b| b.0.to_string()),
                chained_boundary(prev).0
            ))
        } else {
            match Journal::read(db, book, Some(st.through_seq), st.evidence_after)? {
                Err(r) => Some(r.message),
                Ok(journal) => {
                    leaf_kinds = Some(journal.leaf_kinds());
                    let expected = AccumulatorState::of_journal(&journal, st.prev_state_oid);
                    if expected == *st {
                        if let Err(refusal) = journal.verify_unchanged_at(db, at)? {
                            Some(refusal.message)
                        } else {
                            match load_checkpoint(db, &s.oid, at)? {
                                Err(f) => Some(f),
                                Ok(stored_cp) => {
                                    let expected = expected_checkpoint(
                                        db, ctx, book, &journal, &s.oid, signer,
                                    )?;
                                    (stored_cp.checkpoint != expected).then(|| {
                                        "its checkpoint is not what the journal and the book's key reproduce (signature, scope-index root, chain commitment, or statement)".to_string()
                                    })
                                }
                            }
                        }
                    } else {
                        Some(format!(
                            "recomputed {} leaves with root {} from the journal through {}; the state claims {} leaves with root {}",
                            expected.leaf_count,
                            hex(&expected.root),
                            st.through_seq.0,
                            st.leaf_count,
                            hex(&st.root)
                        ))
                    }
                }
            }
        };
        if finding.is_none()
            && let Some(prev) = chain.get(i + 1)
            && (prev.state.through_seq >= st.through_seq
                || prev.state.leaf_count > st.leaf_count
                || prev.recorded_at > st.through_seq)
        {
            finding = Some(format!(
                "does not extend its predecessor (through {}, {} leaves)",
                prev.state.through_seq.0, prev.state.leaf_count
            ));
        }
        states.push(StateCheck {
            oid: s.oid,
            through_seq: st.through_seq,
            leaf_count: st.leaf_count,
            recorded_at: s.recorded_at,
            evidence_after: st.evidence_after,
            leaf_kinds,
            finding,
        });
    }
    let on_chain: BTreeSet<VId> = chain
        .iter()
        .flat_map(|s| [s.vid, checkpoint_vid(&s.oid)])
        .collect();
    let unchained = db
        .vertices_at(at)?
        .into_iter()
        .filter(|row| {
            (row.labels.contains(&label::ACCUMULATOR_STATE)
                || row.labels.contains(&label::TRANSPARENCY_CHECKPOINT))
                && !on_chain.contains(&row.vid)
        })
        .map(|row| row.vid)
        .collect();
    Ok(AccumulatorVerification {
        states,
        broken,
        unchained,
    })
}

fn hex(d: &[u8]) -> String {
    d.iter().map(|b| format!("{b:02x}")).collect()
}

/// Read the journal prefix a journaled state names and confirm it
/// reproduces the state and remains unchanged at the observed head;
/// refusing (exit 8) when either check fails, so retained historical
/// versions cannot conceal a later rewrite while a new proof is issued.
fn supported<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
) -> Outcome<Journal> {
    let observed_at = db.frontier()?;
    let journal = match Journal::read(db, book, Some(state.through_seq), state.evidence_after)? {
        Ok(j) => j,
        Err(r) => return Ok(Err(r)),
    };
    if AccumulatorState::of_journal(&journal, state.prev_state_oid) != *state {
        return Ok(Err(Refusal::new(
            code::ACCUMULATOR_DRIFT,
            exit::VERIFICATION,
            format!(
                "the journal through {} does not reproduce the accumulator state",
                state.through_seq.0
            ),
            "FA-INV-14 (states are recomputed from the journal prefix)",
            "run `fa verify accumulator`; no proof is issued against an unsupported state",
        )));
    }
    if let Err(refusal) = journal.verify_unchanged_at(db, observed_at)? {
        return Ok(Err(refusal));
    }
    Ok(Ok(journal))
}

/// The inclusion proof of entry `entry` against the journaled `state`.
pub fn prove_inclusion<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
    entry: VId,
    with_record: bool,
) -> Outcome<Vec<u8>> {
    let journal = match supported(db, book, state)? {
        Ok(j) => j,
        Err(r) => return Ok(Err(r)),
    };
    match journal.inclusion_proof(entry, with_record)? {
        Some(proof) => Ok(Ok(proof)),
        None => Ok(Err(Refusal::new(
            code::NOT_IN_PREFIX,
            exit::REFUSAL,
            format!(
                "entry {:032x} is not in the accumulator prefix through {}",
                entry.0, state.through_seq.0
            ),
            "plan §13.1 (inclusion is proved only within an authenticated prefix)",
            "checkpoint after the entry was recorded and prove against that state, with a consistency proof from the one you trust",
        ))),
    }
}

/// The consistency proof that the journaled state `new` extends `old`.
pub fn prove_consistency<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    old: &AccumulatorState,
    new: &AccumulatorState,
) -> Outcome<Vec<u8>> {
    let journal = match supported(db, book, new)? {
        Ok(j) => j,
        Err(r) => return Ok(Err(r)),
    };
    match journal.consistency_proof(&old.statement())? {
        Some(proof) => Ok(Ok(proof)),
        None => Ok(Err(Refusal::new(
            code::NOT_EXTENDED,
            exit::VERIFICATION,
            format!(
                "the state through {} does not extend the one through {}",
                new.through_seq.0, old.through_seq.0
            ),
            "FA-INV-14 (each AccumulatorState extends the previous)",
            "order the states by through_seq, and run `fa verify accumulator`",
        ))),
    }
}

/// Every leaf envelope of the journaled `state`'s prefix.
pub fn prove_prefix<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
) -> Outcome<Vec<u8>> {
    match supported(db, book, state)? {
        Ok(journal) => Ok(Ok(journal.prefix_proof()?)),
        Err(r) => Ok(Err(r)),
    }
}

/// The `ScopeIndexComplete` proof `request` asks for against the journaled
/// `state` (plan §13.1): one account's effective-day interval. Other scopes
/// are refused with FA-REF-126, naming the complete prefix as the honest
/// alternative. The proof is checked against the checkpoint beside `state`,
/// whose scope-index root it opens.
pub fn prove_scope<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
    request: &ScopeRequest,
) -> Outcome<Vec<u8>> {
    match supported(db, book, state)? {
        Ok(journal) => crate::scope::prove(&journal, request),
        Err(r) => Ok(Err(r)),
    }
}

/// The balance-recomputation proof of (account, unit) — posted debits and
/// credits through the inclusive civil-day cutoff, or every effective day —
/// against the journaled `state`. Versioned automatically: the exact v1
/// bytes when the cell has no migration candidates, otherwise the v2 format
/// that authenticates each run's visibility, since a v1 verifier cannot
/// (fa-e00); see [`crate::migration_balance::prove_balance`].
pub fn prove_balance<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
    account: VId,
    unit: u32,
    effective_through: Option<i32>,
) -> Outcome<Vec<u8>> {
    crate::migration_balance::prove_balance(db, book, state, account, unit, effective_through)
}

/// What an evidence bundle against the journaled `state` is assembled over
/// (plan §13.2): the journal prefix and the checkpoint beside the state.
/// The checkpoint is recomputed from the journal and the book's key first,
/// and refused (FA-REF-127) when the store holds anything else, so a bundle
/// never carries a checkpoint the journal does not reproduce. The caller
/// assembles it with [`crate::bundle::assemble`], reading each cited
/// document as the producing capability may see it
/// (`fa_journal::read_document_for`).
pub fn bundle_basis<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    state: &StoredState,
    signer: &dyn CheckpointSigner,
) -> Outcome<(Journal, StoredCheckpoint)> {
    let checkpoint = match stored_checkpoint(db, ctx, book, state, signer)? {
        Ok(c) => c,
        Err(r) => return Ok(Err(r)),
    };
    match supported(db, book, &state.state)? {
        Ok(journal) => Ok(Ok((journal, checkpoint))),
        Err(r) => Ok(Err(r)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(evidence_after: Option<u64>) -> AccumulatorState {
        // The empty prefix: no peaks, and the root the verifier expects.
        let journal = Journal::from_records(Id128([7; 16]), CommitSeq(9), Vec::new()).unwrap();
        AccumulatorState {
            evidence_after: evidence_after.map(CommitSeq),
            ..AccumulatorState::of_journal(&journal, Some(Oid([3; 32])))
        }
    }

    /// A minor 0 state keeps its exact bytes; a minor 1 state appends its
    /// boundary; the independent verifier accepts both, and both decoders
    /// refuse a boundary outside `1..=through_seq`.
    #[test]
    fn the_boundary_is_an_additive_minor_both_implementations_read() {
        let entries_only = state(None);
        let old = entries_only.canonical_bytes().unwrap();
        assert_eq!(old[2..4], STATE_SCHEMA_MINOR.to_le_bytes());
        assert_eq!(AccumulatorState::decode(&old).unwrap(), entries_only);
        fa_verify::verify_state(&old).expect("minor 0 verifies");

        let bounded = state(Some(4));
        let new = bounded.canonical_bytes().unwrap();
        assert_eq!(new[2..4], STATE_SCHEMA_MINOR_BOUNDARY.to_le_bytes());
        assert_eq!(new[4..new.len() - 8], old[4..]);
        assert_eq!(new[new.len() - 8..], 4u64.to_le_bytes());
        assert_eq!(AccumulatorState::decode(&new).unwrap(), bounded);
        let outsider = fa_verify::verify_state(&new).expect("minor 1 verifies");
        assert_eq!(outsider.oid, state_oid(&new).0);

        for boundary in [0, 10] {
            let bytes = state(Some(boundary)).canonical_bytes().unwrap();
            assert!(AccumulatorState::decode(&bytes).is_err(), "{boundary}");
            assert!(fa_verify::verify_state(&bytes).is_err(), "{boundary}");
        }
        let mut unknown = new;
        unknown[2] = 2;
        assert!(AccumulatorState::decode(&unknown).is_err());
    }

    /// The boundary is a property of the chain: the first commit for the
    /// first state, the predecessor's sequence after an entries-only state,
    /// and otherwise inherited. An entries-only state never follows a
    /// bounded one, and no other boundary is admitted.
    #[test]
    fn the_chain_admits_exactly_one_boundary_per_state() {
        let legacy = state(None);
        let bounded = state(Some(4));
        assert_eq!(chained_boundary(None), FIRST_COMMIT);
        assert_eq!(chained_boundary(Some(&legacy)), legacy.through_seq);
        assert_eq!(chained_boundary(Some(&bounded)), CommitSeq(4));

        assert!(boundary_admitted(&state(Some(1)), None));
        assert!(boundary_admitted(&state(None), None));
        assert!(!boundary_admitted(&state(Some(2)), None));
        assert!(boundary_admitted(&state(Some(9)), Some(&legacy)));
        assert!(boundary_admitted(&state(None), Some(&legacy)));
        assert!(!boundary_admitted(&state(Some(8)), Some(&legacy)));
        assert!(boundary_admitted(&state(Some(4)), Some(&bounded)));
        assert!(!boundary_admitted(&state(Some(5)), Some(&bounded)));
        assert!(!boundary_admitted(&state(None), Some(&bounded)));
    }
}
