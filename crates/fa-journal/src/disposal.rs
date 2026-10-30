//! Source-bound inventory and securities lot disposal (plan §6.5).
//!
//! A disposal is an ordinary, evidence-bearing posting whose quantity and
//! cost applications are recomputed from immutable history under the account's
//! journaled lot policy. The native application mirrors still provide the
//! point-conflict witnesses. The complete observation prefix also remains
//! guarded: a newly acquired earlier FIFO layer cannot escape an old plan.
//!
//! This profile handles debit-normal asset lots with native quantities and
//! cost in the book's functional unit. Dimensions and foreign-valued layers
//! need their own partition/valuation contract and are refused. Reversals
//! restore the recorded applications, never a newly priced disposal.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::entry::LOT_DISPOSAL_EXTENSION;
use fa_model::lot_disposal::LotDisposalBasis;
use fa_model::symbols::label;
use fa_model::{
    AccountType, Entry, EntryClass, EntryPayload, EntryRef, Id128, LegPayload, Settlement,
    SupersessionKind, entry_vid,
};
use fa_money::{
    Amount, LotCandidate, LotLaw, LotReliefOutcome, Side, UnitId, UnitKind, relieve_lots,
};
use fa_policy::{Capability, Op, Reach};
use fa_time::DateDay;
use fgdb::{Database, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::chart::lots::{StoredLotPolicy, policy_at, witness_policy};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotDisposalRequest {
    pub account: VId,
    pub quantity: Amount,
    pub quantity_offset_account: VId,
    pub cost_offset_account: VId,
    /// Ordered, digest-bound acquisition quantity legs for SpecificId only.
    pub specific_ids: Vec<(EntryRef, u16)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedLotDisposal {
    basis: LotDisposalBasis,
    outcome: LotReliefOutcome,
    proposal: EntryPayload,
}

impl PreparedLotDisposal {
    pub fn basis(&self) -> &LotDisposalBasis {
        &self.basis
    }
    pub fn outcome(&self) -> &LotReliefOutcome {
        &self.outcome
    }
    pub fn proposal(&self) -> &EntryPayload {
        &self.proposal
    }
    pub fn into_proposal(self) -> EntryPayload {
        self.proposal
    }
}

fn invalid(detail: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::SETTLE_SHAPE,
        exit::REFUSAL,
        detail.to_string(),
        "plan §6.5 (journal-derived lot relief under the account's retained lot policy)",
        "inspect `fa gl lots --account <code>` and prepare `fa dispose` under the journaled policy; never supply a cost plug or edit the derived applications",
    )
}

pub(crate) fn unsupported_batch() -> Refusal {
    Refusal::new(
        code::CLASS_NOT_IMPLEMENTED,
        exit::REFUSAL,
        "this compound operation cannot combine source-bound lot disposals",
        "plan §5.8–5.10 / §6.5 (the complete lot population is an aggregate dependency)",
        "use native plans, or an atomic batch or native draft of disposals from distinct lot accounts whose offsets do not touch another member's source; mixed batches, cases and counterfactual scenarios remain unsupported",
    )
}

pub(crate) fn has_basis(proposal: &EntryPayload) -> bool {
    proposal
        .extensions
        .iter()
        .any(|(tag, _)| *tag == LOT_DISPOSAL_EXTENSION)
}

/// Current authority precedes the complete-history observation. A caller's
/// request fields alone do not grant access to another account's lots.
pub(crate) fn authorize<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id)
        .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
        .and_then(|()| {
            fa_policy::require(capability, Op::Post, "preparing source-bound lot disposal")
        })
    {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    Ok(crate::policy::current_at(db, book, capability)?.map(|_| ()))
}

/// Derive a reviewed posting from the retained policy and acquisition/application
/// history. No caller-provided cost or mutable register is an input.
pub fn prepare_lot_disposal<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: &LotDisposalRequest,
    mut template: EntryPayload,
) -> Outcome<PreparedLotDisposal> {
    cx.query().with_restriction(|| {
        if let Err(refusal) = authorize(db, book, capability)? {
            return Ok(Err(refusal));
        }
        if template.book_id != book.book_id
            || template.branch_id != Id128::TRUNK
            || template.principal_ref != capability.holder()
            || template.class != EntryClass::ORIGINAL
            || !template.legs.is_empty()
            || !template.unit_totals.is_empty()
            || template.base_totals.is_some()
            || template.control.is_some()
            || template.pending.is_some()
            || !template.supersession.is_empty()
            || !template.extensions.is_empty()
        {
            return Ok(Err(invalid(
                "lot disposal requires an empty Original template for the acting principal",
            )));
        }
        let head = db.frontier()?;
        let id = entry_vid(
            book.book_id,
            &template.principal_ref.0.to_le_bytes(),
            &template.idempotency_key,
        );
        // An exact retry must reproduce the original law calculation even
        // after subsequent acquisitions, applications, reversals or policy
        // changes. Ordinary semantic-key admission judges the complete bytes.
        let at = match crate::post::read_entry_at(db, id, head)? {
            Some((prior, _))
                if prior.proposal.class != EntryClass::REVERSAL && has_basis(&prior.proposal) =>
            {
                prior
                    .proposal
                    .lot_disposal_basis()
                    .map_err(|error| KernelError::Corrupt(error.to_string()))?
                    .ok_or_else(|| KernelError::Corrupt("disposal lost its basis".into()))?
                    .known_at
            }
            _ => head,
        };
        let Some(policy) = policy_at(db, book, request.account, at)? else {
            return Ok(Err(invalid(
                "the lot account has no journaled lot policy at this prefix",
            )));
        };
        let basis = LotDisposalBasis {
            account: request.account,
            quantity: request.quantity,
            quantity_offset_account: request.quantity_offset_account,
            cost_offset_account: request.cost_offset_account,
            specific_ids: request.specific_ids.clone(),
            known_at: at,
            policy: policy.entry,
            law: policy.policy.law,
            regime: policy.policy.regime,
            rounding_law: policy.policy.rounding_law,
        };
        let derived = match derive(db, cx, book, &basis, &policy, template.effective_date)? {
            Ok(value) => value,
            Err(refusal) => return Ok(Err(refusal)),
        };
        template.legs = derived.legs;
        template.unit_totals = EntryPayload::fold_unit_totals(&template.legs)
            .map_err(|error| KernelError::Corrupt(error.to_string()))?;
        if let Err(error) = template
            .set_lot_disposal_basis(&basis)
            .and_then(|()| template.validate())
        {
            return Ok(Err(invalid(error)));
        }
        Ok(Ok(PreparedLotDisposal {
            basis,
            outcome: derived.outcome,
            proposal: template,
        }))
    })
}

fn matching_policy(basis: &LotDisposalBasis, policy: &StoredLotPolicy) -> bool {
    basis.policy == policy.entry
        && basis.account == policy.policy.account
        && basis.law == policy.policy.law
        && basis.regime == policy.policy.regime
        && basis.rounding_law == policy.policy.rounding_law
}

/// Apply the source-bound law after outcome recognition, while retaining the
/// policy point witness in the transaction that publishes the entry.
pub(crate) fn validate_post<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    proposal: &EntryPayload,
    admission: crate::post::Admission,
) -> Outcome<()> {
    let basis = match proposal.lot_disposal_basis() {
        Ok(value) => value,
        Err(error) => return Ok(Err(invalid(error))),
    };
    // The target's exact side-swap and recorded UNSETTLES are checked by the
    // existing reversal pipeline, including extension equality below it.
    if proposal.class == EntryClass::REVERSAL {
        return Ok(Ok(()));
    }
    let accounts: BTreeSet<_> = proposal.legs.iter().map(|leg| leg.account_ref).collect();
    let base = crate::genesis::read_book_spec_at(db, txn.basis())?
        .ok_or_else(|| KernelError::Corrupt("lot admission has no book".into()))?
        .base_unit;
    let mut selected = None;
    for account in accounts {
        let Some(policy) = witness_policy(txn, db, book, account)? else {
            continue;
        };
        if basis.as_ref().is_some_and(|basis| basis.account == account) {
            selected = Some(policy);
        } else if let Err(refusal) = acquisition_shape(book, proposal, account, base) {
            return Ok(Err(refusal));
        }
    }
    let Some(basis) = basis else {
        return Ok(Ok(()));
    };
    if proposal.class != EntryClass::ORIGINAL
        || proposal.base_totals.is_some()
        || proposal.control.is_some()
        || proposal.pending.is_some()
        || !proposal.supersession.is_empty()
        || proposal.extensions.len() != 1
    {
        return Ok(Err(invalid(
            "lot disposal belongs only to an otherwise native Original posting",
        )));
    }
    let Some(policy) = selected else {
        return Ok(Err(invalid(
            "the bound lot account has no current journaled lot policy",
        )));
    };
    if !matching_policy(&basis, &policy) {
        return Ok(Err(invalid(
            "the lot law or policy handle differs from the account's retained policy",
        )));
    }
    let draft = matches!(
        admission,
        crate::post::Admission::PlanDraft(_)
            | crate::post::Admission::Promote(_)
            | crate::post::Admission::ScratchDraft(_)
    );
    // Native plans retain their exact-prefix law. An admitted draft must
    // survive its own Plan records, but never silently refresh its reviewed
    // proposal: the complete historical source is compared below with a new
    // derivation at this transaction's actual prefix.
    if (!draft || basis.known_at > txn.basis())
        && let Err(refusal) = crate::post::check_aggregate_basis(basis.known_at, txn.basis())
    {
        return Ok(Err(refusal));
    }
    // The point-read projection is a conflict witness, not independent
    // authority. Reconstruct the latest immutable control once before using
    // it to judge the complete historical lot population.
    let Some(retained_policy) = policy_at(db, book, basis.account, basis.known_at)? else {
        return Ok(Err(invalid(
            "the disposal policy was absent at its observation prefix",
        )));
    };
    let retained = match cx.query().with_restriction(|| {
        derive(
            db,
            cx,
            book,
            &basis,
            &retained_policy,
            proposal.effective_date,
        )
    })? {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if proposal.legs != retained.legs {
        return Ok(Err(invalid(
            "the disposal legs, cost relief or application targets differ from the journal-derived lot law",
        )));
    }
    if draft && basis.known_at != txn.basis() {
        let mut current_basis = basis.clone();
        current_basis.known_at = txn.basis();
        let current = match cx.query().with_restriction(|| {
            derive(
                db,
                cx,
                book,
                &current_basis,
                &policy,
                proposal.effective_date,
            )
        })? {
            Ok(value) => value,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if current.source != retained.source || current.legs != retained.legs {
            return Ok(Err(Refusal::new(
                code::PLAN_INVALIDATED,
                exit::CONFLICT,
                "the draft's complete lot source changed after the retained disposal review",
                "plan §5.10 / §6.5 (retained lot sources and reviewed effects)",
                "review the current lot population and prepare a new draft; a source posting followed by its reversal still changes the retained history",
            )));
        }
    }
    Ok(Ok(()))
}

/// Prevent an unbound credit or an application on a governed account from
/// bypassing the lot law. New native acquisitions must remain unambiguous
/// quantity/cost pairs, rather than stranding an unpaired cost adjustment.
fn acquisition_shape(
    book: &BookContext,
    proposal: &EntryPayload,
    account: VId,
    base: UnitId,
) -> Result<(), Refusal> {
    let legs: Vec<_> = proposal
        .legs
        .iter()
        .filter(|leg| leg.account_ref == account)
        .collect();
    if legs.is_empty() {
        return Ok(());
    }
    if proposal.base_totals.is_some()
        || legs.iter().any(|leg| {
            leg.side != Side::Debit
                || !leg.settles.is_empty()
                || !leg.dimension_set.is_empty()
                || leg.base_amount.is_some()
        })
    {
        return Err(invalid(
            "credits, applications, dimensions and foreign-valued adjustments on a governed lot account require its supported source-bound disposal law",
        ));
    }
    let quantities = legs.iter().filter(|leg| leg.amount.unit != base).count();
    let costs = legs.len() - quantities;
    if quantities == 0 || quantities != costs {
        return Err(invalid(
            "a governed lot acquisition needs one native quantity debit and one base-cost debit per layer",
        ));
    }
    for leg in legs {
        if leg.amount.unit != base
            && book.units.get(leg.amount.unit).is_none_or(|unit| {
                matches!(unit.kind, UnitKind::Currency { .. }) || unit.allows_single_sided()
            })
        {
            return Err(invalid(
                "lot quantities must be registered balanced noncurrency units",
            ));
        }
    }
    Ok(())
}

struct DerivedDisposal {
    outcome: LotReliefOutcome,
    legs: Vec<LegPayload>,
    source: LotSource,
}

#[derive(PartialEq, Eq)]
struct LotSource {
    book: crate::genesis::BookSpec,
    account: crate::rows::AccountRow,
    history: LotHistory,
}

fn derive<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    basis: &LotDisposalBasis,
    policy: &StoredLotPolicy,
    effective: DateDay,
) -> Outcome<DerivedDisposal> {
    cx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    let Some(spec) = crate::genesis::read_book_spec_at(db, basis.known_at)? else {
        return Err(KernelError::Corrupt(
            "lot disposal has no retained book".into(),
        ));
    };
    if spec.entities.len() > 1
        || basis.quantity.unit == spec.base_unit
        || basis.quantity.mantissa <= 0
        || book.units.get(basis.quantity.unit).is_none_or(|unit| {
            matches!(unit.kind, UnitKind::Currency { .. }) || unit.allows_single_sided()
        })
    {
        return Ok(Err(invalid(
            "this lot profile requires a positive balanced noncurrency quantity in a single-entity book",
        )));
    }
    if basis.account == basis.quantity_offset_account || basis.account == basis.cost_offset_account
    {
        return Ok(Err(invalid(
            "quantity and cost offset accounts must differ from the lot account",
        )));
    }
    let Some(source_row) = db
        .vertex_at(basis.account, basis.known_at)?
        .filter(|row| row.labels.contains(&label::ACCOUNT))
    else {
        return Ok(Err(invalid(
            "the governed lot account is absent at this prefix",
        )));
    };
    let source = crate::rows::AccountRow::decode(&source_row)?;
    if !source.is_leaf
        || source.account_type != AccountType::ASSET.0
        || source.normal_balance != 0
        || source.unit_policy != crate::genesis::UnitPolicy::AnyUnit
    {
        return Ok(Err(invalid(
            "the governed lot account is no longer a debit-normal AnyUnit Asset posting leaf",
        )));
    }
    if !matching_policy(basis, policy) {
        return Ok(Err(invalid(
            "the disposal does not bind its historical account policy",
        )));
    }
    let history = match read_lots(db, cx, book, basis, spec.base_unit, effective)? {
        Ok(history) => history,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let selectable: BTreeSet<_> = history
        .candidates
        .iter()
        .map(|lot| (lot.entry_id, lot.qty_ordinal))
        .collect();
    for (target, ordinal) in &basis.specific_ids {
        if history.digests.get(&target.vid) != Some(&target.entry_digest)
            || !selectable.contains(&(target.vid.0, *ordinal))
        {
            return Ok(Err(invalid(
                "SpecificId names an absent, exhausted or differently sealed acquisition quantity leg",
            )));
        }
    }
    if (basis.law == LotLaw::SpecificId) == basis.specific_ids.is_empty() {
        return Ok(Err(invalid(
            "SpecificId requires explicit acquisition targets; other lot laws derive their selection",
        )));
    }
    let ids: Vec<_> = basis
        .specific_ids
        .iter()
        .map(|(target, ordinal)| (target.vid.0, *ordinal))
        .collect();
    let outcome = match relieve_lots(
        &history.candidates,
        basis.quantity.mantissa,
        basis.law,
        basis.regime,
        basis.rounding_law,
        (!ids.is_empty()).then_some(ids.as_slice()),
    ) {
        Ok(outcome) => outcome,
        Err(error) => return Ok(Err(invalid(error))),
    };
    let mut quantity = LegPayload::simple(Side::Credit, basis.account, basis.quantity);
    let mut cost = LegPayload::simple(
        Side::Credit,
        basis.account,
        Amount::new(spec.base_unit, outcome.total_relieved_cost),
    );
    for slice in &outcome.slices {
        let vid = VId(slice.entry_id);
        let target = EntryRef {
            vid,
            entry_digest: *history
                .digests
                .get(&vid)
                .ok_or_else(|| KernelError::Corrupt("lot law named an unobserved layer".into()))?,
        };
        if slice.relieved_quantity > 0 {
            quantity.settles.push(Settlement {
                target,
                ordinal: slice.qty_ordinal,
                amount: Amount::new(basis.quantity.unit, slice.relieved_quantity),
            });
        }
        if slice.relieved_cost > 0 {
            cost.settles.push(Settlement {
                target,
                ordinal: slice.cost_ordinal,
                amount: Amount::new(spec.base_unit, slice.relieved_cost),
            });
        }
    }
    if quantity.settles.len() > fa_model::limits::MAX_SETTLES_PER_LEG
        || cost.settles.len() > fa_model::limits::MAX_SETTLES_PER_LEG
    {
        return Ok(Err(invalid(format!(
            "disposal exceeds max_settles_per_leg {}; prepare smaller sequential disposals",
            fa_model::limits::MAX_SETTLES_PER_LEG
        ))));
    }
    let mut legs = vec![
        quantity,
        LegPayload::simple(Side::Debit, basis.quantity_offset_account, basis.quantity),
    ];
    if outcome.total_relieved_cost > 0 {
        legs.push(cost);
        legs.push(LegPayload::simple(
            Side::Debit,
            basis.cost_offset_account,
            Amount::new(spec.base_unit, outcome.total_relieved_cost),
        ));
    }
    Ok(Ok(DerivedDisposal {
        outcome,
        legs,
        source: LotSource {
            book: spec,
            account: source,
            history,
        },
    }))
}

#[derive(PartialEq, Eq)]
struct LotHistory {
    candidates: Vec<LotCandidate>,
    digests: BTreeMap<VId, [u8; 32]>,
    /// Every visible source-account entry, including exhausted acquisitions,
    /// reversed applications and their undos. Equal balances alone must not
    /// make changed history equivalent to a retained disposal review.
    sources: Vec<(EntryRef, CommitSeq)>,
}

/// Each reversal suffix is evaluated once. A long reversal ancestry must
/// not turn one complete journal selection into quadratic lot-fold work.
fn liveness(
    entries: &BTreeMap<VId, (Entry, CommitSeq)>,
    reversals: &BTreeMap<VId, VId>,
) -> Result<BTreeMap<VId, bool>, KernelError> {
    let mut live = BTreeMap::new();
    for vid in entries.keys() {
        let mut path = Vec::new();
        let mut seen = BTreeSet::new();
        let mut current = *vid;
        let mut value = loop {
            if let Some(value) = live.get(&current) {
                break *value;
            }
            if !seen.insert(current) {
                return Err(KernelError::Corrupt("cyclic lot reversal lineage".into()));
            }
            match reversals.get(&current) {
                Some(next) => {
                    path.push(current);
                    current = *next;
                }
                None => {
                    live.insert(current, true);
                    break true;
                }
            }
        };
        for ancestor in path.into_iter().rev() {
            value = !value;
            live.insert(ancestor, value);
        }
    }
    Ok(live)
}

/// One authenticated selection, followed by a literal application fold. The
/// full-prefix guard protects arrivals and migration activation as well as
/// the point-witnessed layers chosen for relief.
fn read_lots<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    basis: &LotDisposalBasis,
    base: UnitId,
    effective: DateDay,
) -> Outcome<LotHistory> {
    let mut entries = BTreeMap::new();
    let mut reversals = BTreeMap::new();
    let mut runs = BTreeMap::new();
    for row in db.vertices_at(basis.known_at)? {
        cx.query()
            .checkpoint()
            .map_err(WriteTxnError::Interrupted)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let Some((entry, seq)) = crate::post::read_entry_at(db, row.vid, basis.known_at)? else {
            continue;
        };
        if entry.proposal.book_id != book.book_id
            || entry.proposal.branch_id != Id128::TRUNK
            || !crate::migration::visible_at(db, &entry, basis.known_at, &mut runs)?
        {
            continue;
        }
        if entry.proposal.class == EntryClass::REVERSAL {
            for link in &entry.proposal.supersession {
                if link.kind == SupersessionKind::Reverses
                    && reversals.insert(link.target.vid, row.vid).is_some()
                {
                    return Err(KernelError::Corrupt(
                        "a lot application has multiple reversal successors".into(),
                    ));
                }
            }
        }
        // Retain controls only when they contribute lineage. Monetary
        // entries on unrelated accounts can still apply to a corrupt target;
        // the application fold below checks the target's account and unit.
        if entry.proposal.class.carries_open_items() || entry.proposal.class == EntryClass::REVERSAL
        {
            entries.insert(row.vid, (entry, seq));
        }
    }
    let history = match fold_lots(&entries, &reversals, basis, base, effective)? {
        Ok(history) => history,
        Err(refusal) => return Ok(Err(refusal)),
    };
    // Native application mirrors serialize competing reliefs, but never
    // supply the cost calculation. Refuse a drifted mirror rather than
    // carrying its corruption into another otherwise balanced posting.
    for lot in &history.candidates {
        cx.query()
            .checkpoint()
            .map_err(WriteTxnError::Interrupted)?;
        let vid = VId(lot.entry_id);
        let (entry, _) = entries
            .get(&vid)
            .ok_or_else(|| KernelError::Corrupt("lot lost its source entry".into()))?;
        for (ordinal, open) in [
            (lot.qty_ordinal, lot.open_quantity),
            (lot.cost_ordinal, lot.open_cost),
        ] {
            let original = entry
                .proposal
                .legs
                .get(usize::from(ordinal))
                .ok_or_else(|| KernelError::Corrupt("lot lost its source leg".into()))?;
            let expected = original
                .amount
                .mantissa
                .checked_sub(open)
                .ok_or_else(|| KernelError::Corrupt("lot application underflow".into()))?;
            let row = db
                .vertex_at(crate::rows::leg_vid(vid, ordinal), basis.known_at)?
                .ok_or_else(|| KernelError::Corrupt("lot source mirror is absent".into()))?;
            if crate::rows::applied(&row)? != Some(expected) {
                return Err(KernelError::Corrupt(
                    "lot application mirror differs from immutable application history".into(),
                ));
            }
        }
    }
    Ok(Ok(history))
}

fn fold_lots(
    entries: &BTreeMap<VId, (Entry, CommitSeq)>,
    reversals: &BTreeMap<VId, VId>,
    basis: &LotDisposalBasis,
    base: UnitId,
    effective: DateDay,
) -> Outcome<LotHistory> {
    let live = liveness(entries, reversals)?;
    let mut applied: BTreeMap<(VId, u16), i128> = BTreeMap::new();
    for (vid, (entry, _)) in entries {
        if !entry.proposal.class.carries_open_items() || !live[vid] {
            continue;
        }
        for leg in &entry.proposal.legs {
            for application in &leg.settles {
                let Some((target, _)) = entries.get(&application.target.vid) else {
                    return Err(KernelError::Corrupt(
                        "a live application has no visible target".into(),
                    ));
                };
                let Some(target_leg) = target.proposal.legs.get(usize::from(application.ordinal))
                else {
                    return Err(KernelError::Corrupt(
                        "a live application has no target leg".into(),
                    ));
                };
                if target_leg.account_ref != basis.account {
                    continue;
                }
                if !live[&application.target.vid]
                    || target.entry_digest != application.target.entry_digest
                    || leg.account_ref != basis.account
                    || target_leg.amount.unit != application.amount.unit
                    || leg.amount.unit != application.amount.unit
                    || target_leg.side == leg.side
                    || application.amount.mantissa <= 0
                {
                    return Err(KernelError::Corrupt(
                        "invalid lot application identity, unit, account or side".into(),
                    ));
                }
                if entry.proposal.effective_date > effective {
                    return Ok(Err(invalid(
                        "disposal precedes a retained application on its lot account",
                    )));
                }
                let total = applied
                    .entry((application.target.vid, application.ordinal))
                    .or_default();
                *total = total
                    .checked_add(application.amount.mantissa)
                    .ok_or_else(|| KernelError::Corrupt("lot applications overflow".into()))?;
            }
        }
    }
    let mut candidates = Vec::new();
    let mut digests = BTreeMap::new();
    for (vid, (entry, recorded)) in entries {
        if !live[vid] {
            continue;
        }
        let account_legs: Vec<_> = entry
            .proposal
            .legs
            .iter()
            .enumerate()
            .filter(|(_, leg)| leg.account_ref == basis.account)
            .collect();
        // An undo after the requested effective date also changes the open
        // population. Never silently backdate through that recorded effect.
        if !account_legs.is_empty() && entry.proposal.effective_date > effective {
            return Ok(Err(invalid(
                "disposal precedes an acquisition, application or undo on its lot account",
            )));
        }
        if !entry.proposal.class.carries_open_items() {
            continue;
        }
        let mut quantities = Vec::new();
        let mut costs = Vec::new();
        for (ordinal, leg) in account_legs {
            if !leg.dimension_set.is_empty()
                || leg.base_amount.is_some()
                || entry.proposal.base_totals.is_some()
            {
                return Ok(Err(invalid(
                    "this lot profile cannot pool dimensioned or foreign-valued historical layers",
                )));
            }
            if !leg.settles.is_empty() {
                let outgoing = leg.settles.iter().try_fold(0_i128, |sum, application| {
                    sum.checked_add(application.amount.mantissa)
                });
                if leg.side != Side::Credit || outgoing != Some(leg.amount.mantissa) {
                    return Ok(Err(invalid(
                        "historical lot applications must fully relieve credit legs; mixed acquisition/application legs are unsupported",
                    )));
                }
                continue;
            }
            if leg.side != Side::Debit {
                return Ok(Err(invalid(
                    "an unallocated historical credit prevents deriving the account's complete open lots",
                )));
            }
            let ordinal = u16::try_from(ordinal)
                .map_err(|_| KernelError::Corrupt("lot ordinal overflow".into()))?;
            let open = leg
                .amount
                .mantissa
                .checked_sub(*applied.get(&(*vid, ordinal)).unwrap_or(&0))
                .filter(|value| *value >= 0)
                .ok_or_else(|| {
                    KernelError::Corrupt("lot applications exceed acquisition".into())
                })?;
            if leg.amount.unit == base {
                costs.push((ordinal, open));
            } else {
                quantities.push((ordinal, leg.amount.unit, open));
            }
        }
        if quantities.len() != costs.len() {
            return Ok(Err(invalid(
                "historical acquisition does not pair each quantity leg with one base-cost leg",
            )));
        }
        for ((qty_ordinal, unit, open_quantity), (cost_ordinal, open_cost)) in
            quantities.into_iter().zip(costs)
        {
            if unit != basis.quantity.unit || (open_quantity == 0 && open_cost == 0) {
                continue;
            }
            candidates.push(LotCandidate {
                entry_id: vid.0,
                qty_ordinal,
                cost_ordinal,
                effective_day: entry.proposal.effective_date.0,
                recorded_seq: recorded.0,
                open_quantity,
                open_cost,
            });
            digests.insert(*vid, entry.entry_digest);
        }
    }
    Ok(Ok(LotHistory {
        candidates,
        digests,
        sources: entries
            .iter()
            .filter(|(_, (entry, _))| {
                entry
                    .proposal
                    .legs
                    .iter()
                    .any(|leg| leg.account_ref == basis.account)
            })
            .map(|(vid, (entry, seq))| (entry.entry_ref(*vid), *seq))
            .collect(),
    }))
}
