//! One scoped key for each successful posting intent (plan §5.9, fa-nl7).
//!
//! Entry identity still enforces target uniqueness. These immutable claims
//! additionally reserve (book, principal, key), shared with atomic batches.
//! Migration retains its declared run-scoped keys. Period, time and normal-key
//! policy activation, account lifecycle, dimension creation and native
//! subledger registration controls also reserve the common key; their
//! pre-protocol entries remain valid retry anchors. Other dedicated
//! writers, including target-derived capability issuance and revocation, have
//! not migrated.
//! Existing normal-key controls are checked before a posting takes their key.

mod keys;
mod rebuild;
mod replay;
#[cfg(test)]
mod tests;
pub use rebuild::{
    OutcomeRebuild, OutcomeRebuildPreview, PreparedOutcomeRebuild, prepare_outcome_rebuild,
    publish_outcome_rebuild,
};
pub(crate) use replay::{
    VerifiedCoverageReplay, prepare_replay, recovered_coverage_bytes, replay_vid,
};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property};
use fa_model::{
    ApprovalRef, Entry, EntryClass, EntryPayload, EntryRef, Id128, Reader, Writer, domain_digest,
    intent_outcome_vid,
};
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId};

use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, bytes, prop, scalar_bytes};

const CLAIM_MAGIC: &[u8; 17] = b"FA-ENTRY-OUTCOME\0";
const COVERAGE_MAGIC: &[u8; 20] = b"FA-OUTCOME-COVERAGE\0";
const VERSION: u16 = 1;

fn decode(error: fa_model::DecodeError) -> KernelError {
    KernelError::Corrupt(format!("intent outcome: {error}"))
}

pub(crate) fn covered_class(class: EntryClass) -> bool {
    class != EntryClass::MIGRATION && !class.is_control()
}

#[must_use]
pub fn coverage_vid(book: Id128) -> VId {
    let digest = domain_digest(b"fa:vid:intent-outcome-coverage:v1", &[&book.0]);
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(low))
}

pub(crate) fn entry_outcome_vid(proposal: &EntryPayload) -> VId {
    intent_outcome_vid(
        proposal.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    )
}

/// Bind the complete sealed semantic request, including ordered approvals.
/// Plan delivery/confirmation and the derived native certificate are not inputs.
fn request_digest(
    proposal: &EntryPayload,
    approvals: &[ApprovalRef],
) -> Result<[u8; 32], KernelError> {
    let request = crate::limit::request_form(proposal)?.unwrap_or_else(|| proposal.clone());
    let bytes = request.seal(approvals.to_vec(), None)?.encode()?;
    Ok(domain_digest(b"fa:posting-request:v1", &[&bytes]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EntryClaim {
    book: Id128,
    principal: VId,
    request_digest: [u8; 32],
    entry: EntryRef,
    /// A recovered claim was published with the authenticated coverage root.
    /// An ordinary claim is born in precisely its Entry's commit.
    recovered_from: Option<CommitSeq>,
}

impl EntryClaim {
    fn new(
        entry: &Entry,
        vid: VId,
        recovered_from: Option<CommitSeq>,
    ) -> Result<Self, KernelError> {
        Ok(Self {
            book: entry.proposal.book_id,
            principal: entry.proposal.principal_ref,
            request_digest: request_digest(&entry.proposal, &entry.approvals)?,
            entry: entry.entry_ref(vid),
            recovered_from,
        })
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.fixed(CLAIM_MAGIC)
            .u16(VERSION)
            .u16(0)
            .fixed(&self.book.0)
            .u128(self.principal.0)
            .fixed(&self.request_digest);
        self.entry.encode(&mut w);
        w.opt(self.recovered_from.as_ref(), |w, seq| {
            w.u64(seq.0);
        });
        Ok(w.finish()?)
    }

    fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        if r.fixed::<17>("entry outcome magic").map_err(decode)? != *CLAIM_MAGIC
            || r.u16("entry outcome major").map_err(decode)? != VERSION
            || r.u16("entry outcome minor").map_err(decode)? != 0
        {
            return Err(KernelError::Corrupt("unsupported entry outcome".into()));
        }
        let value = Self {
            book: Id128(r.fixed("entry outcome book").map_err(decode)?),
            principal: VId(r.u128("entry outcome principal").map_err(decode)?),
            request_digest: r.fixed("entry outcome request").map_err(decode)?,
            entry: EntryRef::decode(&mut r).map_err(decode)?,
            recovered_from: r
                .opt("entry outcome recovery", |r| {
                    r.u64("recovery basis").map(CommitSeq)
                })
                .map_err(decode)?,
        };
        r.finish().map_err(decode)?;
        Ok(value)
    }
}

pub(crate) fn is_entry_claim(row: &VertexRow) -> bool {
    matches!(prop(row, property::FA_PAYLOAD), Some(CanonicalScalar::Bytes(v)) if v.as_slice().starts_with(CLAIM_MAGIC))
}

fn claim_of(row: &VertexRow) -> Result<EntryClaim, KernelError> {
    if row.labels.as_slice() != [label::INTENT_OUTCOME] || row.props.len() != 2 {
        return Err(KernelError::Corrupt(
            "entry outcome root has unexpected metadata".into(),
        ));
    }
    let claim = EntryClaim::decode(&bytes(row, property::FA_PAYLOAD, "entry outcome payload")?)?;
    if !matches!(prop(row, property::TARGET_REF), Some(CanonicalScalar::Bytes(value))
        if value.as_slice() == claim.entry.vid.0.to_le_bytes())
    {
        return Err(KernelError::Corrupt(
            "entry outcome target mirror differs from its payload".into(),
        ));
    }
    Ok(claim)
}

fn claim_properties(
    claim: &EntryClaim,
) -> Result<Vec<(fgdb_delta_types::PropertyKeyId, CanonicalScalar)>, KernelError> {
    Ok(vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("entry outcome", claim.canonical_bytes()?)?,
        ),
        (
            property::TARGET_REF,
            scalar_bytes(
                "entry outcome target",
                claim.entry.vid.0.to_le_bytes().to_vec(),
            )?,
        ),
    ])
}

pub(crate) fn key_conflict() -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        "this principal's idempotency key is already bound to a different intent",
        "plan §5.9 (one successful outcome per book, principal and key)",
        "retry the original intent, or use a new idempotency key for different content",
    )
}

fn needs_rebuild() -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        "this legacy book has no verified posting-key coverage; a new posting cannot safely reserve its key",
        "plan §5.9 (legacy outcomes require an authenticated complete rebuild)",
        "run `fa recover outcomes --dry-run`, then confirm the reviewed basis with `fa recover outcomes --yes --basis <seq>`",
    )
}

/// Check the common point identity before any target-derived retry can return.
/// The caller has already admitted the complete request and target footprint.
pub(crate) fn witness_key<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    proposal: &EntryPayload,
    expected_entry: VId,
) -> Outcome<bool> {
    if !covered_class(proposal.class) {
        return Ok(Ok(false));
    }
    witness_named_key(
        txn,
        db,
        proposal.book_id,
        proposal.principal_ref,
        &proposal.idempotency_key,
        expected_entry,
    )
}

/// A dedicated control admits its named scope before observing this opaque
/// key. Its normal Entry identity remains the legacy retry anchor; a batch or
/// target-derived posting at the common key conflicts without payload reads.
pub(crate) fn witness_named_key<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: Id128,
    principal: VId,
    key: &[u8],
    expected_entry: VId,
) -> Outcome<bool> {
    let ovid = intent_outcome_vid(book, &principal.0.to_le_bytes(), key);
    match txn.vertex_has_label(db, ovid, label::INTENT_OUTCOME)? {
        None => return Ok(Ok(false)),
        Some(false) => return Ok(Err(key_conflict())),
        Some(true) => {}
    }
    // The metadata mirror contains only an Entry VID, never a request or
    // envelope digest. A claim for another identity (or a batch) conflicts
    // before its payload is observed. The caller has already checked reach
    // of an existing expected Entry when its capability is scoped.
    let target = txn.vertex_property(db, ovid, property::TARGET_REF)?;
    if !matches!(target, Some(CanonicalScalar::Bytes(value))
        if value.as_slice() == expected_entry.0.to_le_bytes())
        || txn.vertex_has_label(db, expected_entry, label::ENTRY)? != Some(true)
    {
        return Ok(Err(key_conflict()));
    }
    let row = txn
        .vertex(db, ovid)?
        .ok_or_else(|| KernelError::Corrupt("an outcome vanished during its point read".into()))?;
    if !is_entry_claim(&row) {
        return Ok(Err(key_conflict()));
    }
    let claim = claim_of(&row)?;
    if claim.book != book || claim.principal != principal || claim.entry.vid != expected_entry {
        return Ok(Err(key_conflict()));
    }
    Ok(Ok(true))
}

/// A fresh target-derived writer also respects a pre-protocol normal-key
/// Entry (including a dedicated control entry). The lookup is metadata only.
pub(crate) fn require_fresh_key<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    proposal: &EntryPayload,
    expected_entry: VId,
) -> Outcome<()> {
    if !covered_class(proposal.class) {
        return Ok(Ok(()));
    }
    match witness_key(txn, db, proposal, expected_entry)? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(true) => return Ok(Err(key_conflict())),
        Ok(false) => {}
    }
    let key_vid = fa_model::entry_vid(
        book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    if key_vid != expected_entry && txn.vertex_has_label(db, key_vid, label::ENTRY)?.is_some() {
        return Ok(Err(key_conflict()));
    }
    require_unused_legacy_key(txn, db, book, entry_outcome_vid(proposal))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Coverage {
    book: Id128,
    basis: CommitSeq,
    source_marker: [u8; 32],
    operator: VId,
    epoch: u64,
    entries: u64,
    claims_digest: [u8; 32],
    keys_digest: [u8; 32],
    authentication: [u8; 32],
}

impl Coverage {
    fn genesis(book: Id128) -> Self {
        Self {
            book,
            basis: CommitSeq(0),
            source_marker: [0; 32],
            operator: VId(0),
            epoch: 0,
            entries: 0,
            claims_digest: domain_digest(b"fa:outcome-claims:v1", &[&[]]),
            keys_digest: keys::empty_digest(),
            authentication: [0; 32],
        }
    }

    fn authentication_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.fixed(COVERAGE_MAGIC)
            .u16(VERSION)
            .u16(0)
            .fixed(&self.book.0)
            .u64(self.basis.0)
            .fixed(&self.source_marker)
            .u128(self.operator.0)
            .u64(self.epoch)
            .u64(self.entries)
            .fixed(&self.claims_digest)
            .fixed(&self.keys_digest);
        Ok(w.finish()?)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut encoded = self.authentication_bytes()?;
        encoded.extend_from_slice(&self.authentication);
        Ok(encoded)
    }

    fn authenticate(&self, book: &BookContext) -> Result<[u8; 32], KernelError> {
        let key =
            fgdb_crypto::derive_key("fa:outcome-coverage-authentication:v1", &book.seal_key.0);
        Ok(fgdb_crypto::keyed_hash(&key, &self.authentication_bytes()?).0)
    }

    fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        if r.fixed::<20>("outcome coverage magic").map_err(decode)? != *COVERAGE_MAGIC
            || r.u16("coverage major").map_err(decode)? != VERSION
            || r.u16("coverage minor").map_err(decode)? != 0
        {
            return Err(KernelError::Corrupt("unsupported outcome coverage".into()));
        }
        let value = Self {
            book: Id128(r.fixed("coverage book").map_err(decode)?),
            basis: CommitSeq(r.u64("coverage basis").map_err(decode)?),
            source_marker: r.fixed("coverage source marker").map_err(decode)?,
            operator: VId(r.u128("coverage operator").map_err(decode)?),
            epoch: r.u64("coverage epoch").map_err(decode)?,
            entries: r.u64("coverage entries").map_err(decode)?,
            claims_digest: r.fixed("coverage claims").map_err(decode)?,
            keys_digest: r.fixed("coverage keys").map_err(decode)?,
            authentication: r.fixed("coverage authentication").map_err(decode)?,
        };
        r.finish().map_err(decode)?;
        Ok(value)
    }
}

fn original<V: Vfs + Clone>(db: &Database<V>, row: &VertexRow) -> Result<bool, KernelError> {
    let Some(before) = row.created_at.0.checked_sub(1).map(CommitSeq) else {
        return Ok(false);
    };
    Ok(db.vertex_at(row.vid, before)?.is_none()
        && db.vertex_at(row.vid, row.created_at)?.as_ref() == Some(row))
}

/// The substrate's authenticated marker chains the complete source prefix.
/// This is an indexed point lookup, never a semantic journal scan. The async
/// posting/recovery facades admit authority before hydrating native history.
fn marker_at<V: Vfs + Clone>(db: &Database<V>, at: CommitSeq) -> Result<[u8; 32], KernelError> {
    let before =
        at.0.checked_sub(1).map(CommitSeq).ok_or_else(|| {
            KernelError::Corrupt("outcome coverage has no source publication".into())
        })?;
    // Preserve the native retired-window error for synchronous callers that
    // have not materialized history, rather than misreporting corruption.
    let _ = db.delta_since(before)?;
    db.delta_index()?
        .get(at)
        .map(|batch| batch.commit_marker_identity().marker_oid.0)
        .ok_or_else(|| KernelError::Corrupt("the native outcome-coverage basis is missing".into()))
}

/// Empty coverage is valid only for the real Book creation frame, before
/// any journal entry can exist. This examines one indexed, native-bounded
/// genesis frame's metadata; its cost does not grow with journal history.
fn empty_genesis<V: Vfs + Clone>(db: &Database<V>, row: &VertexRow) -> Result<bool, KernelError> {
    use fa_model::symbols::relation;
    use fgdb_delta_types::DeltaRow;

    let before = row
        .created_at
        .0
        .checked_sub(1)
        .map(CommitSeq)
        .ok_or_else(|| KernelError::Corrupt("genesis coverage has sequence zero".into()))?;
    // Birth ordinals are database-wide and the book root must be the first
    // birth: its frame is the database's first commit, and no birth in that
    // frame precedes it (fgdb numbers births from one, not zero).
    if before != CommitSeq(0) {
        return Ok(false);
    }
    // A checkpoint-opened database (every reopened on-disk book) retains no
    // delta batch before its frontier, so the frame may be unloaded. Then
    // the snapshot at the genesis sequence is exactly what the first commit
    // created, and is checked instead.
    let Some(batch) = db.delta_index()?.get(row.created_at) else {
        return genesis_snapshot(db, row);
    };
    let mut found_book = false;
    let mut found_coverage = false;
    let mut book_ordinal = None;
    let mut first_ordinal = u64::MAX;
    for coordinate in batch.coordinate_entries() {
        if coordinate.relation != relation::IN_BOOK && coordinate.relation != relation::REPRESENTS {
            return Ok(false);
        }
        for delta in &coordinate.rows {
            match delta {
                DeltaRow::CreateVertex {
                    vid,
                    labels,
                    birth_ordinal,
                    valid_time,
                    ..
                } if valid_time.is_none() => {
                    first_ordinal = first_ordinal.min(*birth_ordinal);
                    if *vid == book_root() {
                        if labels.as_slice() != [label::BOOK] || found_book {
                            return Ok(false);
                        }
                        found_book = true;
                        book_ordinal = Some(*birth_ordinal);
                    } else if *vid == row.vid {
                        if labels.as_slice() != [label::INTENT_OUTCOME] || found_coverage {
                            return Ok(false);
                        }
                        found_coverage = true;
                    } else if ![
                        label::UNIT,
                        label::LEGAL_ENTITY,
                        label::DIMENSION,
                        label::DIMENSION_VALUE,
                    ]
                    .iter()
                    .any(|allowed| labels.as_slice() == [*allowed])
                    {
                        return Ok(false);
                    }
                }
                DeltaRow::CreateEdge {
                    canonical_key,
                    valid_time,
                    props,
                    birth_ordinal,
                    ..
                } if canonical_key.is_none() && valid_time.is_none() && props.is_empty() => {
                    first_ordinal = first_ordinal.min(*birth_ordinal);
                }
                _ => return Ok(false),
            }
        }
    }
    Ok(found_book && found_coverage && book_ordinal == Some(first_ordinal))
}

/// [`empty_genesis`] over the snapshot at the genesis sequence, for a frame
/// the delta window no longer holds: every vertex visible there was born in
/// the first commit, the book root first, and each is the book root, the
/// coverage root or a whitelisted genesis row; every edge is a plain
/// IN_BOOK or REPRESENTS edge. This scans the genesis snapshot once.
fn genesis_snapshot<V: Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
) -> Result<bool, KernelError> {
    use fa_model::symbols::relation;

    let at = row.created_at;
    let mut found_book = false;
    let mut found_coverage = false;
    let mut book_ordinal = None;
    let mut first_ordinal = u64::MAX;
    for vertex in db.vertices_at(at)? {
        if vertex.created_at != at {
            return Ok(false);
        }
        first_ordinal = first_ordinal.min(vertex.birth_ordinal);
        if vertex.vid == book_root() {
            if vertex.labels.as_slice() != [label::BOOK] || found_book {
                return Ok(false);
            }
            found_book = true;
            book_ordinal = Some(vertex.birth_ordinal);
        } else if vertex.vid == row.vid {
            if vertex.labels.as_slice() != [label::INTENT_OUTCOME] || found_coverage {
                return Ok(false);
            }
            found_coverage = true;
        } else if ![
            label::UNIT,
            label::LEGAL_ENTITY,
            label::DIMENSION,
            label::DIMENSION_VALUE,
        ]
        .iter()
        .any(|allowed| vertex.labels.as_slice() == [*allowed])
        {
            return Ok(false);
        }
    }
    for edge in db.edges_at(at)? {
        if edge.entry.created_at != at
            || (edge.entry.relation != relation::IN_BOOK
                && edge.entry.relation != relation::REPRESENTS)
            || !edge.props.is_empty()
        {
            return Ok(false);
        }
    }
    Ok(found_book && found_coverage && book_ordinal == Some(first_ordinal))
}

fn coverage_of<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &VertexRow,
) -> Result<Coverage, KernelError> {
    if row.vid != coverage_vid(book.book_id)
        || row.labels.as_slice() != [label::INTENT_OUTCOME]
        || row.props.len() != 1
        || !original(db, row)?
    {
        return Err(KernelError::Corrupt(
            "outcome coverage is not its immutable original root".into(),
        ));
    }
    let value = Coverage::decode(&bytes(row, property::FA_PAYLOAD, "outcome coverage")?)?;
    let valid = if value.basis == CommitSeq(0) {
        value == Coverage::genesis(book.book_id)
            && db.vertex_at(book_root(), row.created_at)?.is_some_and(|root|
                root.labels.contains(&label::BOOK)
                && root.created_at == row.created_at
                && matches!(prop(&root, property::BOOK_ID), Some(CanonicalScalar::Bytes(id)) if id.as_slice() == book.book_id.0))
            && db.vertex_at(book_root(), CommitSeq(row.created_at.0 - 1))?.is_none()
            && empty_genesis(db, row)?
    } else {
        value.book == book.book_id
            && value.basis.0.checked_add(1) == Some(row.created_at.0)
            && value.authenticate(book)? == value.authentication
            && (marker_at(db, value.basis)? == value.source_marker
                || replay::verify_replay(db, book, row, &value)?)
    };
    if !valid {
        return Err(KernelError::Corrupt(
            "outcome coverage does not authenticate this book's source prefix".into(),
        ));
    }
    Ok(value)
}

pub(crate) fn stage_genesis(batch: &mut WriteBatch, book: Id128) -> Result<(), KernelError> {
    stage_coverage(batch, &Coverage::genesis(book))
}

fn stage_coverage(batch: &mut WriteBatch, coverage: &Coverage) -> Result<(), KernelError> {
    batch.create_vertex(
        coverage_vid(coverage.book),
        vec![label::INTENT_OUTCOME],
        vec![(
            property::FA_PAYLOAD,
            scalar_bytes("outcome coverage", coverage.canonical_bytes()?)?,
        )],
    );
    Ok(())
}

pub(crate) fn require_unused_legacy_key<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    key: VId,
) -> Outcome<()> {
    let Some(row) = txn.vertex(db, coverage_vid(book.book_id))? else {
        return Ok(Err(needs_rebuild()));
    };
    let coverage = coverage_of(db, book, &row)?;
    if keys::contains(Some(txn), db, &coverage, row.created_at, key)? {
        return Ok(Err(key_conflict()));
    }
    Ok(Ok(()))
}

/// Stage the outcome claim a covered posting writes beside `entry` at `vid`,
/// in the same commit; `None` for a class outside the outcome protocol. A
/// substrate-level append of a historical entry (a fixture reproducing an
/// older CLI's canonical bytes) stages it so the covered book can verify it.
pub fn stage_entry(
    batch: &mut WriteBatch,
    entry: &Entry,
    vid: VId,
) -> Result<Option<[u8; 32]>, KernelError> {
    if !covered_class(entry.proposal.class) {
        return Ok(None);
    }
    stage_claim(batch, entry, vid).map(Some)
}

/// These controls retain their normal-key Entry identity, including
/// old immutable entries that predate these common-key claims. Do not broaden
/// `covered_class`: historical coverage authenticates monetary posting keys,
/// and an old control's absence of a claim must not invalidate its exact retry.
fn normal_key_control(entry: &Entry, vid: VId) -> bool {
    let proposal = &entry.proposal;
    let admitted = matches!(
        proposal.class,
        EntryClass::PERIOD_CONTROL | EntryClass::TIME_CONTROL
    ) || (proposal.class == EntryClass::POLICY_CONTROL
        && matches!(
            &proposal.control,
            Some(fa_model::ControlPayload::PolicyActivation { .. })
        ))
        || (proposal.class == EntryClass::SCHEMA_CONTROL
            && matches!(
                &proposal.control,
                Some(fa_model::ControlPayload::SchemaChange {
                    kind: 2..=4 | 15 | 17,
                    ..
                })
            ));
    admitted
        && vid
            == fa_model::entry_vid(
                proposal.book_id,
                &proposal.principal_ref.0.to_le_bytes(),
                &proposal.idempotency_key,
            )
}

/// Stage only an admitted normal-key control. In particular, a target-derived
/// capability event cannot use the legacy normal-identity retry exception.
pub(crate) fn stage_control(
    batch: &mut WriteBatch,
    entry: &Entry,
    vid: VId,
) -> Result<(), KernelError> {
    if !normal_key_control(entry, vid) {
        return Err(KernelError::Corrupt(
            "control outcome claim requires an admitted normal-key control entry".into(),
        ));
    }
    stage_claim(batch, entry, vid).map(|_| ())
}

fn stage_claim(batch: &mut WriteBatch, entry: &Entry, vid: VId) -> Result<[u8; 32], KernelError> {
    let claim = EntryClaim::new(entry, vid, None)?;
    let encoded = claim.canonical_bytes()?;
    let digest = domain_digest(b"fa:entry-outcome:v1", &[&encoded]);
    batch.create_vertex(
        entry_outcome_vid(&entry.proposal),
        vec![label::INTENT_OUTCOME],
        claim_properties(&claim)?,
    );
    Ok(digest)
}

/// A legacy normal-key control is its own immutable key reservation. When a
/// common claim exists, it must be the original claim published with that
/// exact entry; neither an unrelated batch nor a copied claim can supply it.
pub(crate) fn verify_control_recorded<V: Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
    entry: &Entry,
) -> Result<bool, KernelError> {
    if !normal_key_control(entry, row.vid) || !original(db, row)? {
        return Ok(false);
    }
    let outcome = entry_outcome_vid(&entry.proposal);
    let Some(claim_row) = db.vertex(outcome)? else {
        // A deleted modern claim is not a legacy control. The authentic
        // publication must itself predate the common-key claim protocol.
        return Ok(db.vertex_at(outcome, row.created_at)?.is_none());
    };
    if !is_entry_claim(&claim_row) {
        return Ok(false);
    }
    Ok(
        claim_of(&claim_row)? == EntryClaim::new(entry, row.vid, None)?
            && original(db, &claim_row)?
            && claim_row.created_at == row.created_at,
    )
}

/// A concurrent newly published winner must have its original atomic claim.
/// Legacy recovery cannot win this path: fresh posts require coverage before
/// preparation, and recovery creates that immutable marker exactly once.
pub(crate) fn verify_atomic_recorded<V: Vfs + Clone>(
    db: &Database<V>,
    row: &VertexRow,
    entry: &Entry,
) -> Result<bool, KernelError> {
    if !covered_class(entry.proposal.class) {
        return Ok(true);
    }
    let Some(claim_row) = db.vertex(entry_outcome_vid(&entry.proposal))? else {
        return Ok(false);
    };
    if !is_entry_claim(&claim_row) {
        return Ok(false);
    }
    Ok(
        claim_of(&claim_row)? == EntryClaim::new(entry, row.vid, None)?
            && original(db, &claim_row)?
            && claim_row.created_at == row.created_at,
    )
}

/// Called only after current authority, metadata scope and original Entry
/// validation. A legacy exact retry remains readable without publishing an
/// upgrade. A covered book cannot silently accept a missing/replaced claim.
pub(crate) fn verify_recorded<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    row: &VertexRow,
    entry: &Entry,
) -> Result<bool, KernelError> {
    cx.checkpoint().map_err(WriteTxnError::Interrupted)?;
    if !covered_class(entry.proposal.class) {
        return Ok(true);
    }
    let Some(claim_row) = db.vertex(entry_outcome_vid(&entry.proposal))? else {
        return Ok(db.vertex(coverage_vid(book.book_id))?.is_none() && original(db, row)?);
    };
    if !is_entry_claim(&claim_row) {
        return Ok(false);
    }
    let claim = claim_of(&claim_row)?;
    if claim != EntryClaim::new(entry, row.vid, claim.recovered_from)? || !original(db, &claim_row)?
    {
        return Ok(false);
    }
    match claim.recovered_from {
        None => Ok(claim_row.created_at == row.created_at),
        Some(basis) => {
            let Some(coverage_row) = db.vertex(coverage_vid(book.book_id))? else {
                return Ok(false);
            };
            let coverage = coverage_of(db, book, &coverage_row)?;
            Ok(coverage.basis == basis
                && row.created_at <= basis
                && claim_row.created_at == coverage_row.created_at
                && keys::contains(None, db, &coverage, coverage_row.created_at, claim_row.vid)?)
        }
    }
}
