//! Attributable, immutable confirmations of exact bank-line/cash-leg matches.
//!
//! A confirmation is a recorded fact, not an assertion that a statement or
//! account is fully reconciled. The source is an already retained bank import;
//! the facade replays its parser and proposal, and this boundary independently
//! checks the committed line against the exact immutable cash leg. A Human
//! principal with current `read`, `reconcile` and `privileged` authority confirms
//! it. No amount, Entry payload, balance register, or reconciliation-through date
//! is changed.
//!
//! Two derived identities claim the source statement line and the actual cash
//! leg in one transaction. They are immutable, including after a reversal;
//! supersession/unmatching requires a future explicit lineage contract.

use asupersync::fs::Vfs;
use fa_model::symbols::{label, relation};
use fa_model::{EntryRef, Id128, Oid, domain_digest};
use fa_policy::{Capability, DecisionCard, Op, Profile, Reach};
use fgdb::{Database, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::evidence::{Document, document_vid};
use crate::genesis::BookContext;
use crate::import::{BankImportManifest, BankImportWitness};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, edge_id, leg_vid, reversal_vid};

mod verify;
mod wire;

/// Frozen canonical storage and authority contract for native confirmations.
pub const SCHEMA_REGISTRY: &str =
    include_str!("../../../registries/object_schemas/bank_match.toml");

pub use wire::BankMatchConfirmation;
use wire::{BankLine, claim_props, match_props};

/// A previously replayed exact proposal. `line` must be the complete retained
/// line document, not caller-entered monetary fields. The opaque import witness
/// was captured from the actual native ImportRun and its complete closure.
#[derive(Clone, Debug)]
pub struct BankMatchRequest {
    pub import: BankImportWitness,
    /// Complete predecessor chain in descending statement order, excluding
    /// `import`, ending at an explicitly unlinked manifest.
    pub predecessors: Vec<BankImportWitness>,
    /// Complete committed line closure in the manifest's original order.
    /// This prevents omitted competing lines from manufacturing uniqueness.
    pub lines: Vec<Document>,
    pub line: Document,
    pub entry_ref: EntryRef,
    /// The ordinal in the immutable Entry, never the report's candidate index.
    pub leg_ordinal: u16,
    pub source_known_at: CommitSeq,
    pub date_window_days: u32,
    pub candidate_ordinal: u64,
    /// Principal bound in the selected proposal bytes. This is not a claim
    /// that a separately authenticated preparation event was retained.
    pub proposer: VId,
    pub proposal_digest: [u8; 32],
    pub decision_card: DecisionCard,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankMatchRecorded {
    pub match_vid: VId,
    pub match_digest: [u8; 32],
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
    pub confirmation: BankMatchConfirmation,
}

/// The line identity is independent of parser choice, account remapping,
/// uploader, confirmer, proposal digest, and idempotency keys.
#[must_use]
pub fn bank_match_vid(book: Id128, statement: Oid, line_ordinal: u32) -> VId {
    short_id(domain_digest(
        b"fa:vid:bank-match:v1",
        &[&book.0, &statement.0, &line_ordinal.to_le_bytes()],
    ))
}

/// A cash leg cannot be consumed by two lines or statements. Its Entry digest
/// is deliberately not an identity input: a damaged rewritten Entry cannot
/// obtain an unspent identity by changing the digest.
#[must_use]
pub fn bank_matched_leg_vid(book: Id128, entry: VId, ordinal: u16) -> VId {
    short_id(domain_digest(
        b"fa:vid:bank-matched-leg:v1",
        &[&book.0, &entry.0.to_le_bytes(), &ordinal.to_le_bytes()],
    ))
}

fn short_id(digest: [u8; 32]) -> VId {
    let mut short = [0; 16];
    short.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(short))
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::BANK_MATCH,
        exit::REFUSAL,
        message,
        "plan §5.7 / §9.5 (confirmed exact retained bank line and immutable cash leg)",
        "replay the retained statement at its explicit source sequence and confirm the exact proposal; residuals, unmatching and account reconciliation require separate supported operations",
    )
}

fn drift(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::BANK_MATCH_DRIFT,
        exit::VERIFICATION,
        message,
        "FA-INV-02; FA-INV-04; plan §5.7 (a confirmation and its source bindings are immutable native facts)",
        "preserve the store and investigate the original match, ImportRun, source documents and cash Entry; never reuse a damaged line or leg claim",
    )
}

fn conflict(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::IDEMPOTENCY_CONFLICT,
        exit::CONFLICT,
        message,
        "plan §5.7 (one immutable confirmed match per statement line and cash leg)",
        "use the originally recorded confirmation; selecting another parser, principal or proposal cannot replace it",
    )
}

fn checkpoint(cx: &PurposeContexts) -> Result<(), KernelError> {
    cx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    Ok(())
}

/// Current native admission precedes history, source metadata and journal
/// observation. This operation reaches the whole retained source closure.
pub fn admit_bank_match<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id)
        .and_then(|()| fa_policy::require(capability, Op::Reconcile, "confirming bank matches"))
        .and_then(|()| {
            fa_policy::require(
                capability,
                Op::Privileged,
                "replaying complete bank statement evidence",
            )
        })
        .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
    {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    Ok(crate::policy::current_at(db, book, capability)?.map(|_| ()))
}

fn admit_confirmation<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    if let Err(refusal) = admit_bank_match(db, book, capability)? {
        return Ok(Err(refusal));
    }
    if capability.profile() != Profile::Human {
        return Ok(Err(crate::policy::refusal(
            &fa_policy::Denial::ApproverProfile {
                rule: "bank_match_confirmer".into(),
                approver: capability.holder(),
                profile: capability.profile(),
                allowed: vec!["Human".into()],
            },
        )));
    }
    Ok(Ok(()))
}

/// Publish exactly one immutable line/leg confirmation and its strong source
/// references. An exact retry returns the original approver, sequence and
/// digest, even if a different authorized holder retries it later.
pub async fn confirm_bank_match<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: BankMatchRequest,
) -> Outcome<BankMatchRecorded> {
    if let Err(refusal) = admit_confirmation(db, book, capability)? {
        return Ok(Err(refusal));
    }
    checkpoint(cx)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    let preparation = match prepare_bank_match(db, cx, book, capability, request)? {
        Ok(preparation) => preparation,
        Err(refusal) => return Ok(Err(refusal)),
    };
    match preparation {
        BankMatchPreparation::AlreadyRecorded(recorded) => Ok(Ok(*recorded)),
        BankMatchPreparation::Ready(prepared) => prepared.commit(db, cx).await,
    }
}

/// A carried native transaction for first-committer-wins confirmation. This
/// synchronous entrypoint requires resident retained history; ordinary callers
/// use `confirm_bank_match`, which hydrates it after current admission.
pub enum BankMatchPreparation {
    AlreadyRecorded(Box<BankMatchRecorded>),
    Ready(Box<PreparedBankMatch>),
}

pub struct PreparedBankMatch {
    txn: WriteTxn,
    confirmation: BankMatchConfirmation,
}

impl PreparedBankMatch {
    pub async fn commit<V: Vfs + Clone>(
        self: Box<Self>,
        db: &mut Database<V>,
        cx: &PurposeContexts,
    ) -> Outcome<BankMatchRecorded> {
        let Self {
            mut txn,
            confirmation,
        } = *self;
        match txn.commit(db, &cx.commit()).await {
            Ok(recorded_at) => Ok(Ok(confirmation.recorded(recorded_at, false)?)),
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
                Ok(Err(Refusal::new(
                    code::CONFLICT,
                    exit::CONFLICT,
                    format!("a bank confirmation witness changed before publication: {detail}"),
                    "FG-LAW-FCW-01 (current authority, source and unique line/leg claims)",
                    "retry the complete original confirmation under current authority",
                )))
            }
            Err(error) => Err(error.into()),
        }
    }
}

pub fn prepare_bank_match<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: BankMatchRequest,
) -> Outcome<BankMatchPreparation> {
    if let Err(refusal) = admit_confirmation(db, book, capability)? {
        return Ok(Err(refusal));
    }
    checkpoint(cx)?;
    let line = match BankLine::decode(&request.line.bytes) {
        Ok(line) => line,
        Err(error) => return Ok(Err(invalid(format!("invalid retained bank line: {error}")))),
    };
    let manifest = request.import.manifest();
    let head = db.frontier()?;
    if request.source_known_at > head
        || request.source_known_at < request.import.receipt().recorded_at
        || request.date_window_days > i32::MAX as u32
        || manifest.book_id != book.book_id
        || line.statement_oid != manifest.statement_oid
        || line.statement_seq != manifest.sequence_number
        || line.amount.unit != manifest.unit
        || line
            .line_ordinal
            .checked_sub(1)
            .and_then(|ordinal| usize::try_from(ordinal).ok())
            .and_then(|ordinal| manifest.line_oids.get(ordinal))
            != Some(&request.line.oid())
    {
        return Ok(Err(invalid(
            "the selected line, source sequence or window differs from its retained bank manifest",
        )));
    }
    if let Err(refusal) = wire::validate_proposal(&request, &line)? {
        return Ok(Err(refusal));
    }
    let mut txn = db.begin(&cx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let epoch = crate::policy::epoch_witness(&txn, db)?;
    let vid = bank_match_vid(book.book_id, line.statement_oid, line.line_ordinal);
    if let Some(row) = txn.vertex(db, vid)? {
        let mut recorded =
            match verify::read_record(db, cx, book, &row, head, Some(request.import.manifest()))? {
                Ok(recorded) => recorded,
                Err(refusal) => return Ok(Err(refusal)),
            };
        txn.abort();
        if !recorded.confirmation.same_request(&request, &line) {
            return Ok(Err(conflict(
                "this statement line already has a different immutable confirmation",
            )));
        }
        recorded.already_recorded = true;
        return Ok(Ok(BankMatchPreparation::AlreadyRecorded(Box::new(
            recorded,
        ))));
    }
    let claim = bank_matched_leg_vid(book.book_id, request.entry_ref.vid, request.leg_ordinal);
    if txn.vertex(db, claim)?.is_some() {
        txn.abort();
        return Ok(Err(conflict(
            "this exact cash leg is already claimed by another bank statement line",
        )));
    }
    if let Err(refusal) = request.import.retain(&txn, db, book.book_id)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    if request.predecessors.len() > fa_model::limits::MAX_BANK_PREDECESSOR_DEPTH {
        return Ok(Err(invalid(
            "bank confirmation predecessor history exceeds its registered bound",
        )));
    }
    let mut previous = request.import.manifest();
    for witness in &request.predecessors {
        checkpoint(cx)?;
        if let Err(refusal) = previous.verify_predecessor(witness) {
            return Ok(Err(refusal));
        }
        if witness.receipt().recorded_at >= request.import.receipt().recorded_at {
            return Ok(Err(invalid(
                "a bank confirmation predecessor was not published before this import",
            )));
        }
        if let Err(refusal) = witness.retain(&txn, db, book.book_id)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = verify::import_birth(db, cx, book, witness)? {
            return Ok(Err(refusal));
        }
        previous = witness.manifest();
    }
    if previous.predecessor.is_some() {
        return Ok(Err(invalid(
            "the complete retained bank predecessor history is required for confirmation",
        )));
    }
    if let Err(refusal) = verify::line_document(db, &txn, book, &request.line)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    if let Err(refusal) = verify::import_birth(db, cx, book, &request.import)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let entry =
        match verify::source_entry(db, cx, book, request.entry_ref, request.source_known_at)? {
            Ok(entry) => entry,
            Err(refusal) => return Ok(Err(refusal)),
        };
    if let Err(refusal) = verify::current_entry(db, &txn, book, &entry, &request)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let reversal = reversal_vid(request.entry_ref.vid);
    if txn.vertex(db, reversal)?.is_some() {
        txn.abort();
        return Ok(Err(invalid(
            "a cash Entry with reversal lineage cannot receive a new confirmation in the one-to-one bank profile",
        )));
    }
    if verify::was_created(db, cx, reversal, head)? {
        txn.abort();
        return Ok(Err(drift(
            "a previously published cash reversal is absent; absence cannot revive bank-match eligibility",
        )));
    }
    if let Err(refusal) = verify::exact_cash_leg(book, &entry, &request, &line)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    if let Err(refusal) = verify::unique_selection(db, &txn, cx, book, &request, &line)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let confirmation = BankMatchConfirmation::from_request(book, capability, epoch, request, line)?;
    let mut batch = WriteBatch::new(relation::MATCHES);
    batch.create_vertex(vid, vec![label::BANK_MATCH], match_props(&confirmation)?);
    batch.create_vertex(
        claim,
        vec![label::BANK_MATCHED_LEG],
        claim_props(&confirmation)?,
    );
    let source = document_vid(&confirmation.line_document_oid);
    let cash_leg = leg_vid(confirmation.entry_ref.vid, confirmation.leg_ordinal);
    batch.add_edge(
        edge_id(relation::MATCHES, source, cash_leg),
        source,
        cash_leg,
        wire::match_edge_props(&confirmation)?,
    );
    let mut references = WriteBatch::new(relation::CITES);
    for target in confirmation.source_vertices() {
        references.add_edge(edge_id(relation::CITES, vid, target), vid, target, vec![]);
    }
    references.add_edge(edge_id(relation::CITES, claim, vid), claim, vid, vec![]);
    let mut membership = WriteBatch::new(relation::IN_BOOK);
    for source in [vid, claim] {
        membership.add_edge(
            edge_id(relation::IN_BOOK, source, book_root()),
            source,
            book_root(),
            vec![],
        );
    }
    // Stage every relation partition together so the unique line/leg claims
    // and their strong references share one publication and witness set.
    if let Err(error) = txn.write_ordered(db, vec![batch, references, membership]) {
        txn.abort();
        return match error {
            WriteTxnError::Write(fgdb::WriteError::IdentitySpent { .. }) => Ok(Err(drift(
                "a retired native line or cash-leg identity cannot be reused for confirmation",
            ))),
            other => Err(other.into()),
        };
    }
    Ok(Ok(BankMatchPreparation::Ready(Box::new(
        PreparedBankMatch { txn, confirmation },
    ))))
}

/// Read the original confirmation fact at an explicit prefix. Current
/// authority always wins over the historical selector. This neither promises
/// that a later correction is reconciled nor computes a complete inventory.
pub async fn read_bank_match<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    match_vid: VId,
    known_at: Option<CommitSeq>,
    manifest: Option<&BankImportManifest>,
) -> Outcome<Option<BankMatchRecorded>> {
    if let Err(refusal) = admit_bank_match(db, book, capability)? {
        return Ok(Err(refusal));
    }
    checkpoint(cx)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    let at = known_at.unwrap_or(db.frontier()?);
    let Some(row) = db.vertex_at(match_vid, at)? else {
        if verify::was_created(db, cx, match_vid, at)? {
            return Ok(Err(drift(
                "a previously created bank confirmation is absent",
            )));
        }
        return Ok(Ok(None));
    };
    Ok(verify::read_record(db, cx, book, &row, at, manifest)?.map(Some))
}

/// The complete immutable occupied-line/cash-leg set at a fixed prefix.
/// Native births, canonical pair bindings, strong edge projections and cash
/// Entry visibility are checked before any pair is returned. Missing or
/// relabelled claims fail closed, including when both claim vertices were
/// removed. This is an occupied-pair fact reader; to verify each original
/// complete source closure, pass its retained manifest to read_bank_match.
/// External manifests do not make an already claimed cash leg available.
pub async fn read_bank_match_claims<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    known_at: Option<CommitSeq>,
) -> Outcome<Vec<BankMatchRecorded>> {
    if let Err(refusal) = admit_bank_match(db, book, capability)? {
        return Ok(Err(refusal));
    }
    checkpoint(cx)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = admit_bank_match(db, book, capability)? {
        return Ok(Err(refusal));
    }
    let head = db.frontier()?;
    let at = known_at.unwrap_or(head);
    if at > head {
        return Ok(Err(invalid(
            "the occupied-pair coordinate is beyond the native book frontier",
        )));
    }
    verify::claims_at(db, cx, book, at)
}
