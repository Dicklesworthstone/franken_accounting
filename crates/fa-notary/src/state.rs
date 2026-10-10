//! Journaled accumulator states (plan §13.2, Appendix A `AccumulatorState`).
//!
//! ```text
//! AccumulatorState { schema_major: u16 (1), schema_minor: u16 (0),
//!                    book_id: [16], branch_id: [16], through_seq: u64,
//!                    leaf_count: u64, root: [32], peaks: [[32]],
//!                    prev_state_oid: Option<[32]> }
//! oid = BLAKE3("fa:accumulator-state:v1" ‖ canonical bytes)
//! vid = low 128 bits of BLAKE3("fa:vid:accumulator-state:v1" ‖ oid)
//! ```
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
//! States are unsigned. Signed, witnessed `TransparencyCheckpoint`s (plan
//! §13.5) are not implemented; fa-verify's reports say `Unsigned`.

use std::collections::BTreeSet;

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_journal::rows::{book_root, bytes, edge_id, prop};
use fa_model::symbols::{label, property, relation};
use fa_model::{DecodeError, EncodeError, Id128, Oid, Reader, Writer};
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxnError};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::journal::Journal;
use crate::tree::Digest;
use crate::{Statement, code};

pub const STATE_OID_DOMAIN: &[u8] = b"fa:accumulator-state:v1";
pub const STATE_VID_DOMAIN: &[u8] = b"fa:vid:accumulator-state:v1";
pub const STATE_SCHEMA_MAJOR: u16 = 1;
pub const STATE_SCHEMA_MINOR: u16 = 0;
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
}

impl AccumulatorState {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::with_capacity(128 + 32 * self.peaks.len());
        w.u16(STATE_SCHEMA_MAJOR)
            .u16(STATE_SCHEMA_MINOR)
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
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u16("state.schema_major")? != STATE_SCHEMA_MAJOR {
            return Err(r.invalid("state.schema_major"));
        }
        if r.u16("state.schema_minor")? != STATE_SCHEMA_MINOR {
            return Err(r.invalid("state.schema_minor"));
        }
        let state = Self {
            book_id: Id128(r.fixed("state.book_id")?),
            branch_id: Id128(r.fixed("state.branch_id")?),
            through_seq: CommitSeq(r.u64("state.through_seq")?),
            leaf_count: r.u64("state.leaf_count")?,
            root: r.fixed("state.root")?,
            peaks: r.list(MAX_PEAKS, "state.peaks", |r| r.fixed("state.peak"))?,
            prev_state_oid: r.opt("state.prev_state_oid", |r| {
                r.fixed("state.prev_state_oid").map(Oid)
            })?,
        };
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

    /// The state that commits `journal` after `prev`.
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
        }
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

/// Every journaled state, newest first, following `prev_state_oid` links.
/// A link that cannot be followed is an error here; [`verify_accumulator`]
/// reports it as a finding instead.
pub fn chain<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
) -> Result<Vec<StoredState>, KernelError> {
    match walk(db, db.frontier()?)? {
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

/// A published state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpointed {
    pub stored: StoredState,
}

/// Recompute the accumulator over the whole journal at the head and journal
/// it as the next `AccumulatorState`, after checking that the journal still
/// extends the previous state (a rewritten history is refused with exit 8,
/// never papered over by a new root).
pub async fn checkpoint<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
) -> Outcome<Checkpointed> {
    let through = db.frontier()?;
    let journal = match Journal::read(db, book, Some(through))? {
        Ok(j) => j,
        Err(refusal) => return Ok(Err(refusal)),
    };
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
        if let Err(refusal) = supported(db, book, prev)? {
            txn.abort();
            return Ok(Err(drift(format!(
                "the last accumulator state is not what the journal reproduces: {}",
                refusal.message
            ))));
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
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(Checkpointed {
            stored: StoredState {
                oid,
                vid: svid,
                recorded_at: seq,
                state,
                bytes: payload,
            },
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
    /// State vertices the chain does not reach (a forged or orphaned state).
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

/// FA-INV-14 by recomputation: every state on the chain is rebuilt from the
/// journal prefix it names and must match field for field; each extends its
/// predecessor; each was recorded after the prefix it covers; and every
/// state vertex in the store is on the chain.
pub fn verify_accumulator<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
) -> Result<AccumulatorVerification, KernelError> {
    let at = db.frontier()?;
    let (chain, broken) = walk(db, at)?;
    let mut states = Vec::with_capacity(chain.len());
    for (i, s) in chain.iter().enumerate() {
        let st = &s.state;
        let mut finding = None;
        if st.book_id != book.book_id || st.branch_id != Id128::TRUNK {
            finding = Some("the state names another book or branch".to_string());
        } else if s.recorded_at <= st.through_seq {
            finding = Some(format!(
                "recorded at {} but claims a prefix through {}",
                s.recorded_at.0, st.through_seq.0
            ));
        } else {
            match Journal::read(db, book, Some(st.through_seq))? {
                Err(r) => finding = Some(r.message),
                Ok(journal) => {
                    let expected = AccumulatorState::of_journal(&journal, st.prev_state_oid);
                    if expected != *st {
                        finding = Some(format!(
                            "recomputed {} leaves with root {} from the journal through {}; the state claims {} leaves with root {}",
                            expected.leaf_count,
                            hex(&expected.root),
                            st.through_seq.0,
                            st.leaf_count,
                            hex(&st.root)
                        ));
                    }
                }
            }
        }
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
            finding,
        });
    }
    let on_chain: BTreeSet<VId> = chain.iter().map(|s| s.vid).collect();
    let unchained = db
        .vertices_at(at)?
        .into_iter()
        .filter(|row| {
            row.labels.contains(&label::ACCUMULATOR_STATE) && !on_chain.contains(&row.vid)
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
/// reproduces the state; refusing (exit 8) when it does not, so no proof is
/// ever issued against a checkpoint the journal does not support.
fn supported<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    state: &AccumulatorState,
) -> Outcome<Journal> {
    let journal = match Journal::read(db, book, Some(state.through_seq))? {
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
