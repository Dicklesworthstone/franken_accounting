//! Atomic reciprocal intercompany posting (plan §12.3, fa-22v5).
//!
//! The bounded native profile declares both legs in one complete entry, in
//! the book's base unit. Ordinary posting still enforces every per-entity
//! balance, account, authority and period law. Cross-book, FX and asynchronous
//! matching are not admitted by this profile.
//!
//! A point-witnessed INTERCOMPANY_WITH edge claims each book-wide pair key in
//! the same transaction. Its endpoints and key are a projection of the
//! immutable approval-bound proposal, checked by verify_projections.

use fa_model::symbols::{property, relation};
use fa_model::{EntryClass, EntryPayload, Id128, domain_digest};
use fa_money::UnitId;
use fgdb::{Database, WriteTxn};
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::{CanonicalScalar, EId, VId};

use crate::refusal::{KernelError, Refusal, code, exit};
use crate::rows::{leg_vid, scalar_text};

fn invalid_declaration(error: impl std::fmt::Display) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        error.to_string(),
        "plan §12.3 (canonical intercompany pair declaration)",
        "supply strictly ordered, unique pair keys and two distinct in-range leg ordinals per pair; each leg may occur only once",
    )
}

fn nonreciprocal_pair(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::INTERCOMPANY_PAIR,
        exit::REFUSAL,
        message,
        "plan §12.3 (declared intercompany pairs are complete and reciprocal at commit)",
        "declare two distinct entities' equal positive base-unit legs with opposite sides in one complete Original/Adjusting entry; balance each entity separately and use a fresh book-wide pair_key",
    )
}

pub(crate) fn admit(
    proposal: &EntryPayload,
    base_unit: UnitId,
    entities: &[Option<String>],
) -> Result<(), Refusal> {
    let Some(pairs) = proposal
        .intercompany_pairs()
        .map_err(invalid_declaration)?
    else {
        return Ok(());
    };
    pairs
        .validate_shape(proposal.legs.len())
        .map_err(invalid_declaration)?;
    if proposal.base_totals.is_some()
        || proposal
            .legs
            .iter()
            .any(|leg| leg.amount.unit != base_unit || leg.base_amount.is_some())
    {
        return Err(Refusal::new(
            code::CLASS_NOT_IMPLEMENTED,
            exit::REFUSAL,
            "intercompany pairs v1 require the book's base unit without FX valuations",
            "plan §12.3 (FX differences require a declared executable matching law)",
            "post both reciprocal base-unit legs in this book; cross-currency and cross-book matching are not implemented",
        ));
    }
    for pair in &pairs.pairs {
        let left = usize::from(pair.left_leg);
        let right = usize::from(pair.right_leg);
        let lhs = &proposal.legs[left];
        let rhs = &proposal.legs[right];
        if lhs.amount.mantissa <= 0
            || lhs.amount != rhs.amount
            || lhs.side == rhs.side
            || lhs.account_ref == rhs.account_ref
        {
            return Err(nonreciprocal_pair(
                "an intercompany pair requires distinct accounts, equal positive amounts and opposite debit/credit sides",
            )
            .at("pair_key", &pair.pair_key)
            .at("left_leg", left)
            .at("right_leg", right));
        }
        let (Some(Some(left_entity)), Some(Some(right_entity))) =
            (entities.get(left), entities.get(right))
        else {
            return Err(nonreciprocal_pair("both intercompany legs must belong to declared legal entities")
                .at("pair_key", &pair.pair_key));
        };
        if left_entity == right_entity {
            return Err(nonreciprocal_pair("intercompany counterpart legs must belong to different legal entities")
                .at("pair_key", &pair.pair_key));
        }
    }
    Ok(())
}

/// Original claims remain spent after reversal. A reversal projects the
/// same declaration with its own derived identity and never frees the key.
pub(crate) fn pair_edge_id(book: Id128, key: &str, reversal: Option<VId>) -> EId {
    let digest = match reversal {
        None => domain_digest(b"fa:eid:intercompany-pair:v1", &[&book.0, key.as_bytes()]),
        Some(entry) => domain_digest(
            b"fa:eid:intercompany-pair-reversal:v1",
            &[&book.0, key.as_bytes(), &entry.0.to_le_bytes()],
        ),
    };
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    EId(u128::from_le_bytes(low))
}

pub(crate) fn witness_fresh<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    proposal: &EntryPayload,
    scoped: bool,
) -> Result<Result<(), Refusal>, KernelError> {
    if proposal.class == EntryClass::REVERSAL {
        return Ok(Ok(()));
    }
    let Some(pairs) = proposal.intercompany_pairs()? else {
        return Ok(Ok(()));
    };
    // Key identities span the whole book. Until the substrate provides a
    // metadata-only edge-existence witness, a confined writer must not read
    // the endpoints of a different pair's claim. Exact outcomes have already
    // been recognized; reversals never acquire a fresh original key.
    if scoped {
        return Ok(Err(Refusal::new(
            code::CAPABILITY,
            exit::SAFETY,
            "fresh intercompany pair declarations require an unscoped capability",
            "plan §4.5, §12.3 (authority precedes book-wide pair-key observation)",
            "have an authorized whole-book operator post this complete native pair; scoped retries and exact reversals still follow their ordinary target authorization",
        )));
    }
    for pair in pairs.pairs {
        // This read includes staged earlier members of the same atomic batch.
        // Absence is a first-committer-wins witness across concurrent writers.
        if txn
            .edge(db, pair_edge_id(proposal.book_id, &pair.pair_key, None))?
            .is_some()
        {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                "this book's intercompany pair_key already belongs to a recorded pair",
                "plan §12.3 (one economic intercompany pair per declared key)",
                "retry the original unchanged entry with its original idempotency key, or use a new pair_key for a different economic pair; a reversal does not release its key",
            )
            .at("pair_key", pair.pair_key)));
        }
    }
    Ok(Ok(()))
}

pub(crate) struct PairEdge {
    pub eid: EId,
    pub src: VId,
    pub dst: VId,
    pub props: Vec<(PropertyKeyId, CanonicalScalar)>,
    pub ordinal: u16,
}

pub(crate) fn projection_edges(
    entry_vid: VId,
    proposal: &EntryPayload,
) -> Result<Vec<PairEdge>, KernelError> {
    let Some(pairs) = proposal.intercompany_pairs()? else {
        return Ok(Vec::new());
    };
    let reversal = (proposal.class == EntryClass::REVERSAL).then_some(entry_vid);
    pairs
        .pairs
        .into_iter()
        .map(|pair| {
            Ok(PairEdge {
                eid: pair_edge_id(proposal.book_id, &pair.pair_key, reversal),
                src: leg_vid(entry_vid, pair.left_leg),
                dst: leg_vid(entry_vid, pair.right_leg),
                props: vec![(property::CODE, scalar_text("intercompany pair_key", &pair.pair_key)?)],
                ordinal: pair.left_leg,
            })
        })
        .collect()
}

/// Stage from exactly the same authoritative inputs used by verification.
pub(crate) fn projection_batch(
    entry_vid: VId,
    proposal: &EntryPayload,
) -> Result<fgdb::WriteBatch, KernelError> {
    let mut batch = fgdb::WriteBatch::new(relation::INTERCOMPANY_WITH);
    for edge in projection_edges(entry_vid, proposal)? {
        batch.add_edge(edge.eid, edge.src, edge.dst, edge.props);
    }
    Ok(batch)
}
