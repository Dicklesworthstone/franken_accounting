//! Principal signing keys in the journal (plan §14.5 non-repudiation,
//! Appendix A `TrustAnchorSet`, bead fa-kae).
//!
//! Each generation of a principal's key chain is one PolicyControl record
//! (`SchemaChange` kind [`SCHEMA_CHANGE_PRINCIPAL_KEY`], body
//! `fa:principal-key:v1`) at the target-derived identity
//! [`principal_key_vid`], so the kernel reads a principal's current key by
//! point reads: generation 0, 1, … until the first absent one. Those reads
//! are the transaction's witnesses, so a concurrent rotation invalidates an
//! approval or a registration (first committer wins). Generation `g` is
//! valid from its recorded sequence until generation `g + 1`'s.
//!
//! The rules of a generation (possession proof, endorsement by the current
//! key, chain order) are fa-policy's [`PrincipalKey::check`]; this module
//! journals what passes them. Verification is the caller's
//! [`SignatureVerifier`]: the kernel cannot import the evidence layer that
//! owns the Ed25519 implementation.

use fa_model::symbols::{label, relation};
use fa_model::{
    ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128, entry_mirrors,
};
use fa_policy::principal_key::{KeyError, MAX_KEY_GENERATIONS, PrincipalKey, SignatureVerifier};
use fa_policy::{Capability, Intent, Op};
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch, WriteTxnError};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

/// `SchemaChange.kind` of a principal-key generation (kinds 1–23 are
/// taken).
pub const SCHEMA_CHANGE_PRINCIPAL_KEY: u16 = 24;

const CITE: &str = "plan §14.5 (non-repudiation) and Appendix A TrustAnchorSet (bead fa-kae)";

/// `vid(key generation) = H("fa:vid:principal-key:v1" ‖ book ‖ principal ‖
/// u32 generation)`: one record per generation, found by a point read.
#[must_use]
pub fn principal_key_vid(book: Id128, principal: VId, generation: u32) -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:vid:principal-key:v1");
    h.update(&book.0);
    h.update(&principal.0.to_le_bytes());
    h.update(&generation.to_le_bytes());
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

/// One journaled generation of a principal's key chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyGeneration {
    pub key: PrincipalKey,
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
}

/// The key a principal-key control carries, if `proposal` is one.
#[must_use]
pub fn key_of(proposal: &EntryPayload) -> Option<PrincipalKey> {
    match &proposal.control {
        Some(ControlPayload::SchemaChange {
            kind: SCHEMA_CHANGE_PRINCIPAL_KEY,
            canonical_bytes,
        }) if proposal.class == EntryClass::POLICY_CONTROL => {
            PrincipalKey::decode(canonical_bytes).ok()
        }
        _ => None,
    }
}

fn corrupt(what: String) -> KernelError {
    KernelError::Corrupt(what)
}

/// A principal's chain, generation 0 first, read through `read` (a point
/// read of the database or of a transaction, which records the witness).
pub(crate) fn chain(
    book: &BookContext,
    principal: VId,
    mut read: impl FnMut(VId) -> Result<Option<VertexRow>, KernelError>,
) -> Result<Vec<KeyGeneration>, KernelError> {
    let mut out = Vec::new();
    for generation in 0..MAX_KEY_GENERATIONS {
        let vid = principal_key_vid(book.book_id, principal, generation);
        let Some(row) = read(vid)? else {
            break;
        };
        let (entry, recorded_at) = crate::post::entry_of(&row)?;
        let key = key_of(&entry.proposal).ok_or_else(|| {
            corrupt(format!(
                "principal key record {:032x} carries no principal key",
                vid.0
            ))
        })?;
        if key.book_id != book.book_id
            || key.principal != principal
            || key.generation != generation
            || entry.proposal.principal_ref != principal
        {
            return Err(corrupt(format!(
                "principal key record {:032x} is not generation {generation} of its principal",
                vid.0
            )));
        }
        out.push(KeyGeneration {
            key,
            control_entry: vid,
            recorded_at,
        });
    }
    Ok(out)
}

/// `principal`'s key chain as the journal records it, generation 0 first.
pub fn read_principal_keys<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    principal: VId,
) -> Result<Vec<KeyGeneration>, KernelError> {
    chain(book, principal, |vid| Ok(db.vertex(vid)?))
}

/// The refusal for a key or signature `error` under `code`.
pub(crate) fn key_refusal(error: &KeyError, signature: bool) -> Refusal {
    if signature {
        Refusal::new(
            code::APPROVAL_SIGNATURE,
            exit::SAFETY,
            error.to_string(),
            CITE,
            "approve the proposal with fa approve --proposal <digest> --sign-key <the principal's current key file>, never routed through fad; a principal with no registered key approves without --sign-key. A keyed principal's review approvals (fa approve --review) cannot be signed yet (fa-kae)",
        )
    } else {
        Refusal::new(
            code::PRINCIPAL_KEY,
            exit::USAGE,
            error.to_string(),
            CITE,
            "register as the principal itself with --sign-key <new key file>, adding --endorse-key <current key file> to rotate an existing key",
        )
    }
}

/// Register one generation of a principal's key chain.
#[derive(Clone, Debug)]
pub struct PrincipalKeyRequest {
    /// The principal's own capability; it must hold `approve`.
    pub capability: Capability,
    pub key: PrincipalKey,
    pub effective_date: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
    /// What checks the generation's possession proof and endorsement.
    pub verifier: &'static dyn SignatureVerifier,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRegistered {
    pub control_entry: VId,
    pub generation: u32,
    pub key_id: [u8; 32],
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

/// Journal the next generation of the capability holder's key chain (plan
/// §14.5, fa-kae): a PolicyControl entry at [`principal_key_vid`], in one
/// commit. Only the principal itself registers, holding `approve` (the op
/// its key signs). The generation must be the chain's next, carry the new
/// key's possession proof and, after the first, the current key's
/// endorsement; the chain is read with point witnesses, so a concurrent
/// registration of the same generation loses.
pub async fn register_principal_key<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    req: PrincipalKeyRequest,
) -> Outcome<KeyRegistered> {
    let principal = req.key.principal;
    if let Err(d) = fa_policy::admit(
        &req.capability,
        &Intent {
            principal,
            trunk: true,
            op: Op::Approve,
            book: book.book_id,
            legs: &[],
        },
    ) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    if let Err(d) = fa_policy::current(&req.capability, db.frontier()?) {
        return Ok(Err(crate::policy::refusal(&d)));
    }
    if req.key.book_id != book.book_id {
        return Ok(Err(Refusal::new(
            code::PRINCIPAL_KEY,
            exit::USAGE,
            "the key's registration statement names another book",
            CITE,
            "register the key in the book it was made for",
        )));
    }
    let key_id = req.key.key_id();
    let proposal = EntryPayload {
        schema_minor: fa_model::entry::EXTENSIONS_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::POLICY_CONTROL,
        effective_date: req.effective_date,
        document_date: None,
        description: req.description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::SchemaChange {
            kind: SCHEMA_CHANGE_PRINCIPAL_KEY,
            canonical_bytes: req
                .key
                .canonical_bytes()
                .map_err(|e| KernelError::Model(e.into()))?,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: req.idempotency_key,
        origin: EntryOrigin::Control {
            control_kind: fa_model::ControlKind::PRINCIPAL_KEY,
            spec_body_digest: key_id,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    if proposal.validate().is_err() {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "the key registration is not a valid PolicyControl entry (a non-empty idempotency key is required)",
            CITE,
            "supply a non-empty --key",
        )));
    }
    let vid = principal_key_vid(book.book_id, principal, req.key.generation);
    let entry = proposal.seal(Vec::new(), None)?;
    if let Err(r) = crate::scratch::ensure_history(db, ctx).await? {
        return Ok(Err(r));
    }
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, &req.capability)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Err(r) = crate::policy::capability_key_witness(&txn, db, &entry.proposal, vid)? {
        txn.abort();
        return Ok(Err(r));
    }
    if let Some(row) = txn.vertex(db, vid)? {
        txn.abort();
        return Ok(
            recorded(db, book, &row, &entry)?.map(|recorded_at| KeyRegistered {
                control_entry: vid,
                generation: req.key.generation,
                key_id,
                recorded_at,
                already_recorded: true,
            }),
        );
    }
    let current = chain(book, principal, |v| Ok(txn.vertex(db, v)?))?;
    let generations = u32::try_from(current.len())
        .map_err(|_| corrupt("a principal key chain beyond u32".into()))?;
    if let Err(error) = req.key.check(
        generations,
        current.last().map(|g| &g.key.public_key),
        req.verifier,
    ) {
        txn.abort();
        return Ok(Err(key_refusal(&error, false)));
    }
    if let Err(r) = crate::outcome::require_unused_legacy_key(
        &txn,
        db,
        book,
        crate::outcome::entry_outcome_vid(&entry.proposal),
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(vid, vec![label::ENTRY], entry_mirrors(&entry)?);
    crate::outcome::stage_principal_key_control(&mut batch, &entry, vid)?;
    txn.write(db, batch)?;
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(KeyRegistered {
            control_entry: vid,
            generation: req.key.generation,
            key_id,
            recorded_at: seq,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                format!(
                    "a concurrent commit invalidated this key registration's witness: {detail}"
                ),
                "FG-LAW-FCW-01 (first committer wins)",
                "retry; if the generation is already registered the retry says so",
            )))
        }
        Err(WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => match db.vertex(vid)? {
            Some(row) => Ok(
                recorded(db, book, &row, &entry)?.map(|recorded_at| KeyRegistered {
                    control_entry: vid,
                    generation: req.key.generation,
                    key_id,
                    recorded_at,
                    already_recorded: true,
                }),
            ),
            None => Ok(Err(crate::outcome::key_conflict())),
        },
        Err(e) => Err(e.into()),
    }
}

/// A retry of the generation already at `row`: the same key, principal and
/// idempotency key, published with its original claim. A different key at
/// the same generation is a conflict, never an overwrite.
fn recorded<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    row: &VertexRow,
    requested: &Entry,
) -> Outcome<CommitSeq> {
    let (stored, recorded_at) = crate::post::entry_of(row)?;
    let same = key_of(&stored.proposal) == key_of(&requested.proposal)
        && stored.proposal.book_id == book.book_id
        && stored.proposal.principal_ref == requested.proposal.principal_ref
        && stored.proposal.idempotency_key == requested.proposal.idempotency_key
        && stored.proposal.origin == requested.proposal.origin
        && row.labels == vec![label::ENTRY]
        && row.props == entry_mirrors(&stored)?
        && crate::outcome::verify_principal_key_recorded(db, row, &stored)?;
    if same {
        Ok(Ok(recorded_at))
    } else {
        Ok(Err(Refusal::new(
            code::IDEMPOTENCY_CONFLICT,
            exit::CONFLICT,
            format!(
                "key generation {:032x} is already registered with different content",
                row.vid.0
            ),
            CITE,
            "register the chain's next generation, endorsed by the current key",
        )))
    }
}
