//! Portable, unsigned accounting proofs (plan §13.1–§13.3).
//!
//! Exports use the existing canonical Notary formats. An outsider supplies
//! their own trusted checkpoint to the independent `fa-verify` program.
//! The exported checkpoint is a candidate trust anchor, never its own proof
//! of authenticity. These artifacts carry no signatures or document receipts.
//! Balance exports automatically use migration-aware v2 when necessary;
//! scopes without migration candidates retain their exact v1 wire bytes.

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
pub const MAX_PROOF_BYTES: usize = 64 * 1024 * 1024;

pub mod code {
    /// The requested checkpoint is not on this book's recorded state chain.
    pub const PROOF_STATE_UNKNOWN: &str = "FA-REF-126";
    /// This export cannot fit the bounded portable proof transport.
    pub const PROOF_EXPORT_LIMIT: &str = "FA-REF-127";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofKind {
    /// The exact 80-byte checkpoint statement, for separate distribution.
    Checkpoint,
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
    /// Exact posted debits and credits, with a complete-prefix predicate.
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
            Self::Checkpoint => "checkpoint",
            Self::Inclusion { .. } => "inclusion",
            Self::Consistency { .. } => "consistency",
            Self::Prefix => "prefix",
            Self::Balance { .. } => "balance",
        }
    }

    #[must_use]
    pub fn scope(self) -> &'static str {
        match self {
            Self::Checkpoint => "entry_prefix",
            Self::Inclusion { .. } => "inclusion",
            Self::Consistency { .. } => "consistency",
            Self::Prefix => "seq_range_complete",
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

pub(crate) fn export<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    principal: VId,
    capability: &Capability,
    request: ProofRequest,
) -> Outcome<ProofArtifact> {
    // Admission precedes even the current authority frontier. Complete-prefix
    // and balance formats reveal every envelope; they require whole-book read
    // authority plus the explicit production operation. Current capabilities
    // support book caveats, not silently filtered account/period views.
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.book_id)
        .and_then(|()| fa_policy::require(capability, Op::Produce, "exporting accounting proofs"))
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
    let verified = fa_notary::verify_accumulator(db, book)?;
    if !verified.is_green() {
        return Ok(Err(Refusal::new(
            fa_notary::code::ACCUMULATOR_DRIFT,
            exit::VERIFICATION,
            "the recorded accumulator chain does not agree with the current journal",
            "FA-INV-14 (every published state is supported by immutable journal history)",
            "run fa verify accumulator --json and preserve its findings; no proof is exported over a damaged chain",
        )));
    }
    let states = fa_notary::chain(db)?;
    let checkpoint = match select(&states, request.state) {
        Ok(state) => state,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut next_checkpoint = None;
    let produced = match request.kind {
        ProofKind::Checkpoint => Ok(checkpoint_bytes(&checkpoint)?),
        ProofKind::Inclusion { entry, with_record } => {
            fa_notary::prove_inclusion(db, book, &checkpoint.state, entry, with_record)?
        }
        ProofKind::Consistency { next_state } => {
            let next = match select(&states, Some(next_state)) {
                Ok(state) => state,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let proof = fa_notary::prove_consistency(db, book, &checkpoint.state, &next.state)?;
            next_checkpoint = Some(next);
            proof
        }
        ProofKind::Prefix => fa_notary::prove_prefix(db, book, &checkpoint.state)?,
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
            // All admission, current-authority and accumulator checks above
            // remain mandatory before the versioned producer reads witnesses.
            fa_notary::migration_balance::prove_balance(
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
