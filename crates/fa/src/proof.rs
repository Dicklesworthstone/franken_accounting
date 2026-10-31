//! Portable accounting proofs (plan §13.1–§13.3).
//!
//! Exports use the existing canonical Notary formats. An outsider checks a
//! proof with the independent `fa-verify` program against a checkpoint it
//! trusts: either the state's `TransparencyCheckpoint` signed by the book's
//! key ([`ProofKind::SignedCheckpoint`], checked with `--key`), or the raw
//! 80-byte statement ([`ProofKind::Checkpoint`]) whose trust the outsider
//! establishes separately. A proof never authenticates its own anchor, and
//! no artifact here carries document receipts. The exported checkpoint is a
//! candidate trust anchor, never its own proof of authenticity.
//! Balance exports automatically use migration-aware v2 when necessary, and
//! payload-complete v3 when every prefix entry is disclosed and every scope
//! selector can be independently derived. Scopes without migration candidates
//! retain their exact v1 wire bytes. Legacy notary v1/v2 APIs remain
//! available, but are not used to claim recomputation of a complete proof.
//! PrefixWithRecords exports the native v2 journal witness without requiring
//! any account, unit, or migration-balance policy. Prefix retains v1 bytes.
//! State exports the full canonical AccumulatorState, including its evidence
//! and access coverage boundaries, for binding to a signed checkpoint's oid.

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::symbols::label;
use fa_model::{Oid, Writer};
use fa_money::UnitId;
use fa_notary::StoredState;
use fa_policy::{Capability, Op};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::VId;

use crate::{BookError, Outcome};

/// Shared producer limit; the standalone verifier also bounds its input.
pub const MAX_PROOF_BYTES: usize = fa_notary::migration_balance::MAX_BALANCE_PROOF_BYTES;

pub mod code {
    /// The requested checkpoint is not on this book's recorded state chain.
    pub const PROOF_STATE_UNKNOWN: &str = "FA-REF-145";
    /// This export cannot fit the bounded portable proof transport.
    pub const PROOF_EXPORT_LIMIT: &str = "FA-REF-146";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    /// The full canonical AccumulatorState, including versioned coverage
    /// boundaries. Authenticate its oid through the signed checkpoint;
    /// the raw 80-byte statement alone does not bind those boundaries.
    State,
    /// The exact 80-byte checkpoint statement, for separate distribution.
    Checkpoint,
    /// The state's journaled `TransparencyCheckpoint`, signed by the book's
    /// key and recomputed from the journal before export: the anchor
    /// `fa-verify … --key <public key>` checks instead of trusting it.
    SignedCheckpoint,
    Inclusion {
        entry: VId,
        with_record: bool,
    },
    /// Extend the selected old checkpoint to this recorded new checkpoint.
    Consistency {
        next_state: Oid,
    },
    /// Every leaf envelope in the checkpoint's prefix, in journal order.
    Prefix,
    /// Every envelope AND entry payload, including controls and staged entries.
    /// Explicit whole-book disclosure for independent scope derivation.
    PrefixWithRecords,
    /// Exact posted amounts with every prefix entry payload for scope derivation.
    /// This is whole-book disclosure, not an account-filtered entry export.
    Balance {
        account: VId,
        unit: UnitId,
        effective_through: Option<DateDay>,
    },
}

impl ProofKind {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::State => "state",
            Self::Checkpoint => "checkpoint",
            Self::SignedCheckpoint => "signed-checkpoint",
            Self::Inclusion { .. } => "inclusion",
            Self::Consistency { .. } => "consistency",
            Self::Prefix | Self::PrefixWithRecords => "prefix",
            Self::Balance { .. } => "balance",
        }
    }

    #[must_use]
    pub fn scope(self) -> &'static str {
        match self {
            Self::State | Self::Checkpoint | Self::SignedCheckpoint => "entry_prefix",
            Self::Inclusion { .. } => "inclusion",
            Self::Consistency { .. } => "consistency",
            Self::Prefix | Self::PrefixWithRecords => "seq_range_complete",
            Self::Balance { .. } => "recomputation",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofRequest {
    /// `None` selects the latest existing checkpoint; export never creates one.
    pub state: Option<Oid>,
    pub kind: ProofKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofArtifact {
    pub request: ProofRequest,
    pub checkpoint: StoredState,
    /// A consistency proof's producer-claimed extension, not a trusted root.
    pub next_checkpoint: Option<StoredState>,
    /// Raw canonical bytes, consumed without a wrapper by `fa-verify`.
    pub bytes: Vec<u8>,
}

/// The exact statement bytes that an independent verifier accepts as a
/// separately supplied checkpoint. No schema or platform encoding is added.
pub fn checkpoint_bytes(state: &StoredState) -> Result<Vec<u8>, BookError> {
    let mut writer = Writer::with_capacity(80);
    state.state.statement().encode(&mut writer);
    writer
        .finish()
        .map_err(|e| KernelError::Model(e.into()).into())
}

fn select(states: &[StoredState], oid: Option<Oid>) -> Result<StoredState, Refusal> {
    states
        .iter()
        .find(|state| oid.is_none_or(|oid| state.oid == oid))
        .cloned()
        .ok_or_else(|| {
            Refusal::new(
                code::PROOF_STATE_UNKNOWN,
                exit::USAGE,
                match oid {
                    Some(oid) => format!(
                        "accumulator state {} is not on this book's recorded checkpoint chain",
                        oid.0.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    ),
                    None => "the book has no recorded accumulator checkpoint".into(),
                },
                "plan §13.2 (proofs select an existing journaled AccumulatorState)",
                "use fa verify accumulator --json to find a recorded state; the owner can publish one with fa checkpoint create --grant witness",
            )
        })
}

/// The recorded state chain, newest first, once the export is admitted and
/// every state is recomputed from the journal.
fn admitted_chain<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &fgdb_types::context::PurposeContexts,
    book: &BookContext,
    signer: &dyn fa_notary::CheckpointSigner,
    principal: VId,
    capability: &Capability,
) -> Outcome<Vec<StoredState>> {
    // Admission precedes even the current authority frontier. Prefix proofs
    // reveal every envelope; PrefixWithRecords, v3 balances and suffixes
    // disclose every entry payload. All require whole-book read plus the
    // production operation. Even a proof naming an earlier checkpoint
    // verifies the complete chain at HEAD before selecting that checkpoint;
    // its apparent output scope must not widen the caller's read authority.
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.book_id)
        .and_then(|()| fa_policy::require(capability, Op::Produce, "exporting accounting proofs"))
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
    {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    let head = db.frontier().map_err(KernelError::from)?;
    if let Err(denial) = fa_policy::current(capability, head) {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    if let Err(refusal) = fa_journal::policy::capability_admitted(db, book, capability)? {
        return Ok(Err(refusal));
    }
    // States and their signed checkpoints are both recomputed from the
    // journal and the book's key before any proof is cut from them.
    let verified = fa_notary::verify_accumulator(db, ctx, book, signer)?;
    if !verified.is_green() {
        return Ok(Err(Refusal::new(
            fa_notary::code::ACCUMULATOR_DRIFT,
            exit::VERIFICATION,
            "the recorded accumulator chain does not agree with the current journal",
            "FA-INV-14 (every published state is supported by immutable journal history)",
            "run fa verify accumulator --json and preserve its findings; no proof is exported over a damaged chain",
        )));
    }
    Ok(Ok(fa_notary::chain(db, None)?))
}

/// Which suffix to export: from the recipient's retained recorded state to
/// a later one (`None`: the latest).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuffixRequest {
    pub state: Oid,
    pub next_state: Option<Oid>,
}

/// A complete record-bearing suffix between two recorded states (plan
/// §13.2: extend previously verified state instead of sending the whole
/// history again). It is the consistency proof from `checkpoint` to
/// `next_checkpoint`, plus one record-bearing inclusion proof at
/// `next_checkpoint` per appended leaf, in leaf order, undated controls and
/// evidence records included. That is exactly what `fa-verify witness index
/// --consistency … --delta-record …` advances a retained baseline with, in
/// the existing v1 formats.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuffixArtifact {
    /// The recipient's retained state.
    pub checkpoint: StoredState,
    /// The state the suffix extends it to.
    pub next_checkpoint: StoredState,
    pub consistency: Vec<u8>,
    /// Leaves `[checkpoint.leaf_count, next_checkpoint.leaf_count)`.
    pub records: Vec<Vec<u8>>,
}

pub(crate) fn export_suffix<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &fgdb_types::context::PurposeContexts,
    book: &BookContext,
    signer: &dyn fa_notary::CheckpointSigner,
    principal: VId,
    capability: &Capability,
    request: SuffixRequest,
) -> Outcome<SuffixArtifact> {
    let states = match admitted_chain(db, ctx, book, signer, principal, capability)? {
        Ok(states) => states,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let checkpoint = match select(&states, Some(request.state)) {
        Ok(state) => state,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let next_checkpoint = match select(&states, request.next_state) {
        Ok(state) => state,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let suffix = match fa_notary::prefix::prove_suffix_with_records(
        db,
        book,
        &checkpoint.state.statement(),
        &next_checkpoint.state,
        fa_notary::prefix::MAX_PREFIX_PROOF_BYTES,
    )? {
        Ok(suffix) => suffix,
        Err(refusal) => return Ok(Err(refusal)),
    };
    Ok(Ok(SuffixArtifact {
        checkpoint,
        next_checkpoint,
        consistency: suffix.consistency_proof().to_vec(),
        records: suffix.records().to_vec(),
    }))
}

pub(crate) fn export<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &fgdb_types::context::PurposeContexts,
    book: &BookContext,
    signer: &dyn fa_notary::CheckpointSigner,
    principal: VId,
    capability: &Capability,
    request: ProofRequest,
) -> Outcome<ProofArtifact> {
    let states = match admitted_chain(db, ctx, book, signer, principal, capability)? {
        Ok(states) => states,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let checkpoint = match select(&states, request.state) {
        Ok(state) => state,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut next_checkpoint = None;
    let produced = match request.kind {
        ProofKind::State => Ok(checkpoint.bytes.clone()),
        ProofKind::Checkpoint => Ok(checkpoint_bytes(&checkpoint)?),
        ProofKind::SignedCheckpoint => {
            fa_notary::stored_checkpoint(db, ctx, book, &checkpoint, signer)?
                .map(|stored| stored.bytes)
        }
        ProofKind::Inclusion { entry, with_record } => {
            fa_notary::prove_inclusion(db, book, &checkpoint.state, entry, with_record)?
        }
        ProofKind::Consistency { next_state } => {
            let next = match select(&states, Some(next_state)) {
                Ok(state) => state,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let proof =
                fa_notary::prove_consistency(db, book, &checkpoint.state.statement(), &next.state)?;
            next_checkpoint = Some(next);
            proof
        }
        ProofKind::Prefix => fa_notary::prove_prefix(db, book, &checkpoint.state)?,
        ProofKind::PrefixWithRecords => {
            fa_notary::prefix::prove_prefix_with_records(db, book, &checkpoint.state)?
        }
        ProofKind::Balance {
            account,
            unit,
            effective_through,
        } => {
            let row = db
                .vertex_at(account, checkpoint.state.through_seq)
                .map_err(KernelError::from)?;
            if !row.is_some_and(|row| row.labels.contains(&label::ACCOUNT)) {
                return Ok(Err(Refusal::new(
                    fa_journal::refusal::code::UNKNOWN_ACCOUNT,
                    exit::REFUSAL,
                    format!(
                        "account {:032x} does not exist at the selected checkpoint",
                        account.0
                    ),
                    "plan §4.3 (the claimed account must exist at the proof coordinate)",
                    "select an account present at this checkpoint, or checkpoint after its chart installation",
                )));
            }
            if book.units.get(unit).is_none() {
                return Ok(Err(Refusal::new(
                    fa_journal::refusal::code::UNIT_POLICY,
                    exit::REFUSAL,
                    format!("unit {} is not registered in this book", unit.0),
                    "plan §4.2 (exact amounts require a canonical unit)",
                    "select a unit from this book's canonical registry",
                )));
            }
            // Whole-book disclosure admission and accumulator checks above
            // remain mandatory before the complete producer reads witnesses.
            fa_notary::migration_balance::prove_balance_complete(
                db,
                book,
                &checkpoint.state,
                account,
                unit.0,
                effective_through.map(|day| day.0),
            )?
        }
    };
    let bytes = match produced {
        Ok(bytes) => bytes,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if bytes.len() > MAX_PROOF_BYTES {
        return Ok(Err(Refusal::new(
            code::PROOF_EXPORT_LIMIT,
            exit::USAGE,
            "the proof exceeds the 64 MiB portable input limit",
            "plan §13.1–§13.3 (bounded, explicitly scoped outsider proofs)",
            "choose an earlier checkpoint or an inclusion proof; a truncated complete-prefix proof is never emitted",
        )));
    }
    Ok(Ok(ProofArtifact {
        request,
        checkpoint,
        next_checkpoint,
        bytes,
    }))
}

/// What a witness cosigns (plan §13.5, fa-qtfd).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WitnessRequest<'a> {
    /// The recorded state (default: the latest, or the one `onto` names).
    pub state: Option<Oid>,
    /// The cosigned checkpoint this witness key produced last.
    pub previous: Option<&'a [u8]>,
    /// A checkpoint of the same state already cosigned by other witnesses,
    /// to add this signature to (as a checkpoint circulates among its
    /// witnesses); its body must be exactly the one the book signed.
    pub onto: Option<&'a [u8]>,
}

/// A recorded state's signed checkpoint cosigned by a witness (plan §13.5,
/// bead fa-qtfd), and what the witness checked first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witnessed {
    pub checkpoint: StoredState,
    /// The book-signed checkpoint with the witness's signature added: the
    /// same body, a new object.
    pub cosigned: Vec<u8>,
    pub cosigned_oid: Oid,
    pub witness_key_id: [u8; 32],
    /// The statement this witness last cosigned, which the book's history
    /// was proved to extend before this one was signed; `None` for a
    /// witness's first checkpoint.
    pub extends: Option<fa_notary::Statement>,
}

/// Cosign the recorded state `state` (default: the latest) with `witness`
/// (plan §13.5: "this root was observed", never a statement about content).
/// The holder needs current read and witness authority, and the chain must
/// recompute from the journal. A witness never signs a history that does not
/// extend the one it signed last: given `previous` (its last cosigned
/// checkpoint, carrying its own valid signature), the book must prove, and
/// the independent verifier must accept, that this state extends that
/// statement; a rollback or a rewritten history is refused
/// (`NOT_EXTENDED`, exit 8) and nothing is signed. Nothing is written to
/// the book: the cosignature is the witness's to keep and distribute.
#[allow(clippy::too_many_arguments)]
pub(crate) fn witness<V: Vfs + Clone>(
    db: &Database<V>,
    ctx: &fgdb_types::context::PurposeContexts,
    book: &BookContext,
    signer: &dyn fa_notary::CheckpointSigner,
    principal: VId,
    capability: &Capability,
    witness: &dyn fa_notary::CheckpointSigner,
    request: WitnessRequest<'_>,
) -> Outcome<Witnessed> {
    // Witnessing recomputes the whole current journal just like proof export.
    // Judge that reach before observing the frontier, inspecting requested
    // checkpoints, or invoking the witness signer.
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.book_id)
        .and_then(|()| fa_policy::require(capability, Op::Witness, "witnessing a checkpoint"))
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
    {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    let head = db.frontier().map_err(KernelError::from)?;
    if let Err(denial) = fa_policy::current(capability, head) {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    if let Err(refusal) = fa_journal::policy::capability_admitted(db, book, capability)? {
        return Ok(Err(refusal));
    }
    let witness_key_id = fa_notary::checkpoint::signer_key_id(&witness.public_key());
    // What the witness signed last, judged before the book is read further.
    let structure = |why: &str| {
        Refusal::new(
            fa_journal::refusal::code::STRUCTURE,
            exit::USAGE,
            why,
            "plan §13.5 (witnesses cosign the exact body the book signed)",
            "pass a TransparencyCheckpoint file this book's state produced (fa proof signed-checkpoint, or another witness's fa checkpoint witness --out)",
        )
    };
    let onto = match request.onto {
        None => None,
        Some(bytes) => match fa_notary::TransparencyCheckpoint::decode(bytes) {
            Ok(onto) => Some(onto),
            Err(_) => {
                return Ok(Err(structure(
                    "--onto is not a canonical TransparencyCheckpoint",
                )));
            }
        },
    };
    let state = match (request.state, &onto) {
        (Some(named), Some(onto)) if named != onto.body.state_oid => {
            return Ok(Err(structure(
                "--onto cosigns another state than --state names",
            )));
        }
        (named, onto) => named.or(onto.as_ref().map(|o| o.body.state_oid)),
    };
    let remembered = match request.previous {
        None => None,
        Some(bytes) => {
            let not_ours = |why: String| {
                Refusal::new(
                    fa_journal::refusal::code::STRUCTURE,
                    exit::USAGE,
                    why,
                    "plan §13.5 (a witness extends only the history it signed itself)",
                    "pass as --previous the cosigned checkpoint this witness key produced last",
                )
            };
            let Ok(prior) = fa_notary::TransparencyCheckpoint::decode(bytes) else {
                return Ok(Err(not_ours(
                    "--previous is not a canonical TransparencyCheckpoint".into(),
                )));
            };
            // Ed25519 signing is deterministic (RFC 8032): this key's
            // signature over that body is exactly the bytes it would produce
            // now, and no other key produces them.
            let message = prior
                .body
                .signed_message()
                .map_err(|e| KernelError::Model(e.into()))?;
            let ours = prior
                .signatures
                .iter()
                .find(|s| (s.signer_key_id, s.scheme) == (witness_key_id, witness.scheme()));
            if ours.is_none_or(|s| s.bytes.as_slice() != witness.sign(&message).as_slice()) {
                return Ok(Err(not_ours(
                    "--previous carries no signature by this witness key".into(),
                )));
            }
            if prior.body.statement.book_id != book.book_id {
                return Ok(Err(not_ours(
                    "--previous is a checkpoint of another book".into(),
                )));
            }
            Some(prior.body.statement)
        }
    };
    let verified = fa_notary::verify_accumulator(db, ctx, book, signer)?;
    if !verified.is_green() {
        return Ok(Err(Refusal::new(
            fa_notary::code::ACCUMULATOR_DRIFT,
            exit::VERIFICATION,
            "the recorded accumulator chain does not agree with the current journal",
            "FA-INV-14 (every published state is supported by immutable journal history)",
            "run fa verify accumulator --json and preserve its findings; nothing is witnessed over a damaged chain",
        )));
    }
    let states = fa_notary::chain(db, None)?;
    let checkpoint = match select(&states, state) {
        Ok(state) => state,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Some(prior) = &remembered {
        let diverged = || {
            Refusal::new(
                fa_notary::code::NOT_EXTENDED,
                exit::VERIFICATION,
                format!(
                    "this book's history does not extend the checkpoint this witness signed last (through {}, {} leaves, root {}): a rollback or a rewritten history; nothing was signed",
                    prior.through_seq.0,
                    prior.leaf_count,
                    hex(&prior.root)
                ),
                "plan §13.5 (a witness never signs a history that does not extend the one it signed); FA-INV-14",
                "keep both checkpoints as evidence of the divergence and report it; do not cosign",
            )
        };
        // A consistency proof exists only when the recomputed journal's
        // prefix at the remembered size has the remembered root: that is the
        // extension the witness requires. (An outsider re-checks it with
        // fa-verify consistency; engine code never links the verifier.)
        match fa_notary::prove_consistency(db, book, prior, &checkpoint.state)? {
            Ok(_proof) => {}
            Err(refusal) if refusal.code == fa_notary::code::NOT_EXTENDED => {
                return Ok(Err(diverged()));
            }
            Err(refusal) => return Ok(Err(refusal)),
        }
    }
    let signed = match fa_notary::stored_checkpoint(db, ctx, book, &checkpoint, signer)? {
        Ok(stored) => stored.bytes,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let decoded = fa_notary::TransparencyCheckpoint::decode(&signed)
        .map_err(|e| KernelError::Corrupt(format!("stored checkpoint: {e:?}")))?;
    let base = match onto {
        None => decoded,
        // The book's own signatures come from the book, never from the
        // file: whatever `onto` claims under the book's key ids is replaced,
        // so a stripped or altered copy still carries the book's signature.
        Some(mut onto) if onto.body == decoded.body => {
            onto.signatures.retain(|o| {
                !decoded
                    .signatures
                    .iter()
                    .any(|d| (d.signer_key_id, d.scheme) == (o.signer_key_id, o.scheme))
            });
            onto.signatures.extend(decoded.signatures);
            onto.signatures.sort_by_key(|s| (s.signer_key_id, s.scheme));
            if onto.signatures.len() > fa_notary::checkpoint::MAX_SIGNATURES {
                return Ok(Err(structure(
                    "--onto with the book's signature holds more signatures than a verifier decodes",
                )));
            }
            onto
        }
        Some(_) => {
            return Ok(Err(structure(
                "--onto's body is not the one this book signed for that state",
            )));
        }
    };
    let cosigned = match base.cosign(witness) {
        Ok(cosigned) => cosigned,
        Err(fa_notary::checkpoint::SignError::UntrustableKey { .. }) => {
            return Ok(Err(Refusal::new(
                fa_journal::refusal::code::STRUCTURE,
                exit::USAGE,
                "the witness key is not a usable Ed25519 key",
                "plan §13.2 (ruling 3392: a small-order or non-curve key signs nothing)",
                "generate a witness key with fa checkpoint witness-key --out <new file>",
            )));
        }
        Err(fa_notary::checkpoint::SignError::Full) => {
            return Ok(Err(Refusal::new(
                fa_journal::refusal::code::STRUCTURE,
                exit::USAGE,
                "this checkpoint already holds the most signatures a verifier decodes",
                "plan §13.2 (bounded checkpoint signature lists)",
                "cosign a later checkpoint",
            )));
        }
        Err(fa_notary::checkpoint::SignError::Encode(e)) => {
            return Err(KernelError::Model(e.into()).into());
        }
    };
    let bytes = cosigned
        .canonical_bytes()
        .map_err(|e| KernelError::Model(e.into()))?;
    Ok(Ok(Witnessed {
        cosigned_oid: fa_notary::checkpoint::checkpoint_oid(&bytes),
        checkpoint,
        cosigned: bytes,
        witness_key_id,
        extends: remembered,
    }))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
