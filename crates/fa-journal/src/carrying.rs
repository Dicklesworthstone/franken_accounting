//! Journal-derived functional carrying values for foreign open items (§5.7).
//!
//! The bounded application law is RemainingCarryingValue with HalfEven:
//! a partial application relieves `open_base * native / open_native`, and
//! the final application relieves the entire remaining base amount. Each
//! applying leg names exactly one target and applies its entire native
//! amount; its immutable `base_amount` is the recorded relief. Reversals
//! restore that recorded amount, including a zero rounded relief.
//!
//! Allocated revaluations retain every item's original-cost and valuation
//! components. Settlement relieves both under explicit laws; legacy aggregate
//! adjustments never acquire an inferred allocation.

mod allocated;
pub(crate) use allocated::covers_valuation_account;
pub(crate) use allocated::{basis as allocated_basis, check_release as check_allocated_release};
pub(crate) use allocated::{has_allocated_basis, verify_allocated_fx_structure};

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::entry::FX_REVALUATION_EXTENSION;
use fa_model::symbols::{label, property};
use fa_model::{
    EntryClass, EntryPayload, EntryRef, FxRevaluationBasis, Id128, Oid, Settlement,
    SupersessionKind, entry_vid,
};
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fa_money::{Amount, Rate, RoundingLaw, Side};
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::evidence::{DocumentRecord, Storage, document_vid};
use crate::fx::{FxLawId, FxRateDocument, FxRatePurpose, RATE_DOCUMENT_KIND};
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarryingOpenItem {
    pub target: EntryRef,
    pub ordinal: u16,
    pub account: VId,
    pub side: Side,
    pub dimensions: Vec<(u32, VId)>,
    pub effective_date: DateDay,
    pub known_at: CommitSeq,
    pub original_native: Amount,
    pub original_base: Amount,
    pub applied_native: Amount,
    pub applied_base: Amount,
    pub open_native: Amount,
    pub open_base: Amount,
    pub historical_open_base: Amount,
    pub valuation_open_base: Amount,
    pub carrying_source_digest: [u8; 32],
    pub valuation_route: Option<crate::chart::FxRevaluationRoute>,
    pub valuation_routes_entry: Option<VId>,
    pub valuation_routes_digest: Option<[u8; 32]>,
    /// Latest contributing application or undo date; a new application
    /// must not precede it and thereby change historical relief ordering.
    pub latest_effective_date: DateDay,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxSettlementRequest {
    pub target: EntryRef,
    pub target_ordinal: u16,
    pub amount: Amount,
    pub settlement_amount: Amount,
    pub settlement_account: VId,
    pub conversion_account: VId,
    pub realized_fx_account: VId,
    pub rate_document: Oid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFxSettlement {
    carrying: CarryingOpenItem,
    base_relief: Amount,
    proposal: EntryPayload,
}

/// One item's journal-derived explanation inside a complete group proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxSettlementItem {
    pub carrying: CarryingOpenItem,
    pub base_relief: Amount,
    pub leg_range: core::ops::Range<usize>,
}

/// Independent foreign applications recorded as one ordinary accounting entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFxSettlementGroup {
    items: Vec<FxSettlementItem>,
    proposal: EntryPayload,
}

impl PreparedFxSettlementGroup {
    pub fn items(&self) -> &[FxSettlementItem] {
        &self.items
    }
    pub fn proposal(&self) -> &EntryPayload {
        &self.proposal
    }
    pub fn into_proposal(self) -> EntryPayload {
        self.proposal
    }
}

/// Every admitted item requires at least four nonzero native legs.
pub const MAX_FX_SETTLEMENT_ITEMS: usize = fa_model::limits::MAX_LEGS_PER_ENTRY / 4;

impl PreparedFxSettlement {
    pub fn carrying(&self) -> &CarryingOpenItem {
        &self.carrying
    }
    pub fn base_relief(&self) -> Amount {
        self.base_relief
    }
    pub fn historical_base_relief(&self) -> Amount {
        self.proposal.legs[0].base_amount.expect("prepared relief")
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
        "plan §5.7 (RemainingCarryingValue, HalfEven; immutable recorded base relief)",
        "prepare one foreign open-item application from retained history and its Settlement rate document; use a separate fully applied leg for each target",
    )
}

pub(crate) fn unsupported_batch() -> Refusal {
    Refusal::new(
        code::CLASS_NOT_IMPLEMENTED,
        exit::REFUSAL,
        "this compound operation cannot combine source-bound foreign settlements",
        "plan §5.10 (complete aggregate carrying-value dependency)",
        "commit each settlement alone, or use an FX-only atomic batch or native draft of distinct existing target legs; paired replacement, mixed batches, and case promotion remain unsupported",
    )
}

pub(crate) fn is_source_bound(proposal: &EntryPayload) -> bool {
    proposal.class != EntryClass::REVERSAL
        && proposal.base_totals.as_ref().is_some_and(|totals| {
            matches!(
                FxLawId::from_oid(&totals.fx_law_oid),
                Some(
                    FxLawId::SettlementCarryingBasis
                        | FxLawId::SettlementAllocatedCarrying
                        | FxLawId::SettlementSpotCarrying
                )
            )
        })
}

/// Exact law arithmetic, in base minor units. The final remainder is never
/// re-rounded; a partial amount may legitimately relieve zero base units.
pub fn remaining_carrying_relief(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    open_native: Amount,
    open_base: Amount,
    application: Amount,
) -> Result<Amount, Refusal> {
    if application.unit != open_native.unit
        || open_native.mantissa <= 0
        || open_base.mantissa < 0
        || application.mantissa <= 0
        || application.mantissa > open_native.mantissa
    {
        return Err(invalid(
            "application must be positive and no greater than the remaining native amount",
        ));
    }
    if application == open_native {
        return Ok(open_base);
    }
    let numerator = u128::try_from(application.mantissa).map_err(invalid)?;
    let denominator = u128::try_from(open_native.mantissa).map_err(invalid)?;
    let rate = Rate::new(budget, numerator, denominator).map_err(invalid)?;
    open_base
        .mul_rate(budget, &rate, RoundingLaw::HalfEven)
        .map_err(invalid)
}

pub(crate) fn live(vid: VId, reversals: &BTreeMap<VId, VId>) -> Result<bool, KernelError> {
    let mut current = vid;
    let mut result = true;
    let mut seen = BTreeSet::new();
    while let Some(next) = reversals.get(&current) {
        if !seen.insert(current) {
            return Err(KernelError::Corrupt(
                "cyclic application reversal lineage".into(),
            ));
        }
        result = !result;
        current = *next;
    }
    Ok(result)
}

/// Read one historical foreign open item. Callers enforce read capability
/// and complete-history availability first. The kernel invokes this only
/// after current whole-book read/post admission and protects the fold with
/// the complete-prefix publication guard.
pub fn open_item_carrying_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    target: EntryRef,
    ordinal: u16,
    at: CommitSeq,
) -> Outcome<CarryingOpenItem> {
    cx.query().with_restriction(|| {
        let result = open_item_carrying_inner(db, cx, book, target, ordinal, at)?;
        if let Ok(item) = &result
            && item.valuation_route.is_some()
            && let Err(refusal) =
                crate::revaluation::verify_item_history(db, cx, book, item.account, at)?
        {
            return Ok(Err(refusal));
        }
        Ok(result)
    })
}

pub(crate) fn open_item_carrying_inner<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    target: EntryRef,
    ordinal: u16,
    at: CommitSeq,
) -> Outcome<CarryingOpenItem> {
    let query = cx.query();
    query
        .checkpoint()
        .map_err(fgdb::WriteTxnError::Interrupted)?;
    if at > db.frontier()? {
        return Ok(Err(invalid(
            "carrying-value prefix is beyond the retained frontier",
        )));
    }
    let Some((original, recorded)) = crate::post::read_entry_at(db, target.vid, at)? else {
        return Ok(Err(invalid(
            "the foreign open item does not exist at this prefix",
        )));
    };
    if original.entry_digest != target.entry_digest
        || original.proposal.book_id != book.book_id
        || original.proposal.branch_id != Id128::TRUNK
        || !original.proposal.class.carries_open_items()
    {
        return Ok(Err(invalid(
            "the target handle does not name this book's retained posted item",
        )));
    }
    let Some(leg) = original.proposal.legs.get(usize::from(ordinal)) else {
        return Ok(Err(invalid("target ordinal is outside the original entry")));
    };
    let spec = crate::fx::book_spec_at(db, book, at)?;
    let Some(original_base) = leg.base_amount else {
        return Ok(Err(invalid(
            "the original foreign item has no retained base valuation",
        )));
    };
    if leg.amount.unit == spec.base_unit
        || original_base.unit != spec.base_unit
        || leg.amount.mantissa <= 0
        || original_base.mantissa < 0
        || !leg.settles.is_empty()
        || original.proposal.base_totals.as_ref().is_none_or(|totals| {
            !matches!(
                FxLawId::from_oid(&totals.fx_law_oid),
                Some(FxLawId::SpotClose | FxLawId::PeriodAverage)
            )
        })
    {
        return Ok(Err(invalid(
            "carrying-value relief requires an original foreign item valued by SpotClose or PeriodAverage, with no outgoing applications",
        )));
    }
    let mut entries = Vec::new();
    let mut reversals = BTreeMap::new();
    for row in db.vertices_at(at)? {
        query
            .checkpoint()
            .map_err(fgdb::WriteTxnError::Interrupted)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let Some((entry, seq)) = crate::post::read_entry_at(db, row.vid, at)? else {
            continue;
        };
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            continue;
        }
        if entry.proposal.class == EntryClass::REVERSAL {
            for link in &entry.proposal.supersession {
                if link.kind == SupersessionKind::Reverses
                    && reversals.insert(link.target.vid, row.vid).is_some()
                {
                    return Err(KernelError::Corrupt(
                        "an application has duplicate reversal successors".into(),
                    ));
                }
            }
        }
        entries.push((seq, row.vid, entry));
    }
    if !live(target.vid, &reversals)? {
        return Ok(Err(invalid("the target open item is reversed")));
    }
    // A valuation contra account carries an aggregate adjustment, not a
    // per-item allocation. Refuse instead of assigning it to this invoice.
    let chart = crate::chart::read_at(db, book, at)?;
    let valuation_accounts: BTreeSet<_> = chart
        .fx_revaluation_routes()
        .iter()
        .filter_map(|routes| {
            routes
                .routes
                .get(&leg.account_ref)
                .map(|route| route.valuation_account)
        })
        .collect();
    for (seq, vid, entry) in &entries {
        if *seq < recorded
            || !live(*vid, &reversals)?
            || entry.proposal.class == EntryClass::REVERSAL
        {
            continue;
        }
        let adjustment = entry
            .proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
            .map(|(_, raw)| FxRevaluationBasis::decode(raw))
            .transpose()
            .map_err(|error| KernelError::Corrupt(error.to_string()))?;
        if has_allocated_basis(&entry.proposal) {
            if let Err(refusal) = allocated::retained_shape(&entry.proposal) {
                return Ok(Err(refusal));
            }
            for routes in chart.fx_revaluation_routes() {
                if let Some(route) = routes.routes.get(&leg.account_ref)
                    && let Err(refusal) =
                        allocated::covers_valuation_account(&entry.proposal, leg.account_ref, route)
                {
                    return Ok(Err(refusal));
                }
            }
            continue;
        }
        if adjustment.as_ref().is_some_and(|basis| {
            basis.source_account == leg.account_ref && basis.item_allocation.is_some()
        }) {
            continue;
        }
        let source_adjustment =
            adjustment.is_some_and(|basis| basis.source_account == leg.account_ref);
        if source_adjustment
            || entry
                .proposal
                .legs
                .iter()
                .any(|other| valuation_accounts.contains(&other.account_ref))
        {
            return Ok(Err(invalid(
                "the source account has valuation adjustments without a registered per-item relief allocation; its carrying basis cannot be inferred",
            )));
        }
    }
    entries.sort_by_key(|(seq, vid, _)| (*seq, *vid));
    let mut open_native = leg.amount;
    let mut open_base = original_base;
    let mut historical_open_base = original_base;
    let mut valuation_open_base = Amount::new(original_base.unit, 0);
    let mut valuation_route = None;
    let mut valuation_routes_entry = None;
    let mut valuation_routes_digest = None;
    let mut source_hash = fgdb_crypto::Hasher::new();
    source_hash.update(b"fa:allocated-carrying-source:v1");
    source_hash.update(&target.vid.0.to_le_bytes());
    source_hash.update(&target.entry_digest);
    source_hash.update(&ordinal.to_le_bytes());
    let mut latest_effective_date = original.proposal.effective_date;
    let mut effects: BTreeMap<VId, (i128, i128, i128)> = BTreeMap::new();
    let mut previous_effect_seq = None;
    let mut previous_effect_is_undo = false;
    let current = asupersync::Cx::current().ok_or_else(|| {
        KernelError::Corrupt("carrying-value arithmetic requires the caller context".into())
    })?;
    let stripped = current.restrict::<asupersync::cx::cap::None>();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    for (seq, vid, entry) in entries {
        query
            .checkpoint()
            .map_err(fgdb::WriteTxnError::Interrupted)?;
        let mut effect = (0i128, 0i128, 0i128);
        if seq < recorded {
            continue;
        }
        if let Some((_, raw)) = entry
            .proposal
            .extensions
            .iter()
            .find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
        {
            let basis = FxRevaluationBasis::decode(raw)
                .map_err(|error| KernelError::Corrupt(error.to_string()))?;
            if basis.source_account == leg.account_ref
                && crate::revaluation::item_entity(&spec, leg)
                    .map_err(|error| KernelError::Corrupt(error.message))?
                    == basis.entity
                && let Some(allocation) = &basis.item_allocation
            {
                let item = allocation
                    .items
                    .iter()
                    .find(|item| item.target.vid == target.vid && item.ordinal == ordinal);
                if let Some(item) = item {
                    if item.target != target
                        || item.open_native != open_native
                        || item.historical_base != historical_open_base
                        || item.prior_valuation != valuation_open_base
                        || basis.closing_date < latest_effective_date
                    {
                        return Ok(Err(invalid(
                            "retained item allocation does not reproduce the item's preceding carrying components",
                        )));
                    }
                    let Some(routes) = crate::chart::fx_revaluation_routes_at(
                        db,
                        book,
                        basis.closing_date,
                        basis.observed_at,
                    )?
                    else {
                        return Ok(Err(invalid("item allocation has no retained route map")));
                    };
                    let Some(route) = routes.routes.get(&leg.account_ref).copied() else {
                        return Ok(Err(invalid("item allocation has no source route")));
                    };
                    if routes.control_entry != basis.routes_entry
                        || routes.digest != basis.routes_digest
                    {
                        return Ok(Err(invalid(
                            "item allocation route commitment differs from history",
                        )));
                    }
                    valuation_open_base = item
                        .target_base
                        .checked_sub(historical_open_base)
                        .map_err(|error| KernelError::Corrupt(error.to_string()))?;
                    open_base = item.target_base;
                    valuation_route = Some(route);
                    valuation_routes_entry = Some(basis.routes_entry);
                    valuation_routes_digest = Some(basis.routes_digest);
                    latest_effective_date = basis.closing_date;
                    source_hash.update(&seq.0.to_le_bytes());
                    source_hash.update(&vid.0.to_le_bytes());
                    source_hash.update(&entry.entry_digest);
                } else if open_native.mantissa > 0
                    && original.proposal.effective_date <= basis.closing_date
                {
                    return Ok(Err(invalid(
                        "the complete item allocation omits an open source item",
                    )));
                }
            }
        }
        if entry.proposal.class == EntryClass::REVERSAL {
            for link in &entry.proposal.supersession {
                if link.kind == SupersessionKind::Reverses
                    && let Some((native, base, valuation)) = effects.get(&link.target.vid)
                {
                    effect = (
                        native
                            .checked_neg()
                            .ok_or_else(|| KernelError::Corrupt("native undo overflow".into()))?,
                        base.checked_neg()
                            .ok_or_else(|| KernelError::Corrupt("base undo overflow".into()))?,
                        valuation.checked_neg().ok_or_else(|| {
                            KernelError::Corrupt("valuation undo overflow".into())
                        })?,
                    );
                }
            }
        } else if entry.proposal.class.carries_open_items() {
            for (applying_ordinal, applying) in entry.proposal.legs.iter().enumerate() {
                for application in &applying.settles {
                    if application.target.vid != target.vid || application.ordinal != ordinal {
                        continue;
                    }
                    let spot = entry.proposal.base_totals.as_ref().is_some_and(|totals| {
                        totals.fx_law_oid == FxLawId::SettlementSpotCarrying.oid()
                    });
                    if application.target != target
                        || applying.settles.len() != 1
                        || if spot {
                            application.amount.mantissa > applying.amount.mantissa
                        } else {
                            application.amount != applying.amount
                                || settlement_ranges(&entry.proposal).is_err()
                        }
                        || applying.account_ref != leg.account_ref
                        || applying.side == leg.side
                        || applying.dimension_set != leg.dimension_set
                        || !is_source_bound(&entry.proposal)
                    {
                        return Ok(Err(invalid(
                            "retained application has no unambiguous single-target recorded carrying relief",
                        )));
                    }
                    let relief = if spot {
                        match spot_application_relief(
                            db,
                            book,
                            &entry.proposal,
                            application.amount,
                            seq,
                            &mut budget,
                        )? {
                            Ok(relief) => relief,
                            Err(refusal) => return Ok(Err(refusal)),
                        }
                    } else {
                        let Some(relief) = applying.base_amount else {
                            return Ok(Err(invalid(
                                "retained application lacks recorded base relief",
                            )));
                        };
                        relief
                    };
                    let expected = match remaining_carrying_relief(
                        &mut budget,
                        open_native,
                        historical_open_base,
                        application.amount,
                    ) {
                        Ok(value) => value,
                        Err(refusal) => return Ok(Err(refusal)),
                    };
                    if relief != expected {
                        return Ok(Err(invalid(
                            "retained application base relief does not reproduce RemainingCarryingValue",
                        )));
                    }
                    let allocated_relief = if has_allocated_basis(&entry.proposal) {
                        let total = match remaining_carrying_relief(
                            &mut budget,
                            open_native,
                            open_base,
                            application.amount,
                        ) {
                            Ok(value) => value,
                            Err(refusal) => return Ok(Err(refusal)),
                        };
                        let expected_release = match allocated::release_basis(
                            applying_ordinal,
                            source_hash.finalize().0,
                            expected,
                            total,
                            valuation_route,
                            valuation_routes_entry,
                            valuation_routes_digest,
                        ) {
                            Ok(value) => value,
                            Err(refusal) => return Ok(Err(refusal)),
                        };
                        if let Err(refusal) =
                            allocated::check_release(&entry.proposal, &expected_release)
                        {
                            return Ok(Err(refusal));
                        }
                        expected_release.valuation_relief.mantissa
                    } else {
                        if valuation_route.is_some() {
                            return Ok(Err(invalid(
                                "an allocated carrying item requires its explicit valuation-release law",
                            )));
                        }
                        0
                    };
                    effect.0 = effect
                        .0
                        .checked_add(application.amount.mantissa)
                        .ok_or_else(|| {
                            KernelError::Corrupt("native application sum overflow".into())
                        })?;
                    effect.1 = effect.1.checked_add(relief.mantissa).ok_or_else(|| {
                        KernelError::Corrupt("base application sum overflow".into())
                    })?;
                    effect.2 = effect
                        .2
                        .checked_add(allocated_relief)
                        .ok_or_else(|| KernelError::Corrupt("valuation relief overflow".into()))?;
                }
            }
        }
        if effect != (0, 0, 0) {
            // Exact undo effects commute: a batch may restore several
            // previously recorded applications at one publication. Fresh
            // proportional relief needs an unambiguous execution order.
            let is_recorded_undo =
                entry.proposal.class == EntryClass::REVERSAL && effect.0 < 0 && effect.1 <= 0;
            if previous_effect_seq == Some(seq) && !(previous_effect_is_undo && is_recorded_undo) {
                return Ok(Err(invalid(
                    "multiple carrying-value effects share a publication without a retained execution order",
                )));
            }
            previous_effect_seq = Some(seq);
            previous_effect_is_undo = is_recorded_undo;
            open_native.mantissa = open_native
                .mantissa
                .checked_sub(effect.0)
                .ok_or_else(|| KernelError::Corrupt("native carrying fold overflow".into()))?;
            historical_open_base.mantissa = historical_open_base
                .mantissa
                .checked_sub(effect.1)
                .ok_or_else(|| KernelError::Corrupt("base carrying fold overflow".into()))?;
            if open_native.mantissa < 0
                || open_native.mantissa > leg.amount.mantissa
                || historical_open_base.mantissa < 0
                || historical_open_base.mantissa > original_base.mantissa
            {
                return Ok(Err(invalid(
                    "retained applications or undos exceed the original native/base carrying amount",
                )));
            }
            valuation_open_base.mantissa = valuation_open_base
                .mantissa
                .checked_sub(effect.2)
                .ok_or_else(|| KernelError::Corrupt("valuation carrying fold overflow".into()))?;
            open_base = historical_open_base
                .checked_add(valuation_open_base)
                .map_err(|error| KernelError::Corrupt(error.to_string()))?;
            if open_base.mantissa < 0 || (open_native.mantissa == 0 && open_base.mantissa != 0) {
                return Ok(Err(invalid(
                    "recorded item effects leave a negative or stranded carrying balance",
                )));
            }
            latest_effective_date = latest_effective_date.max(entry.proposal.effective_date);
            effects.insert(vid, effect);
            source_hash.update(&seq.0.to_le_bytes());
            source_hash.update(&vid.0.to_le_bytes());
            source_hash.update(&entry.entry_digest);
        }
    }
    Ok(Ok(CarryingOpenItem {
        target,
        ordinal,
        account: leg.account_ref,
        side: leg.side,
        dimensions: leg.dimension_set.clone(),
        effective_date: original.proposal.effective_date,
        known_at: at,
        original_native: leg.amount,
        original_base,
        applied_native: leg
            .amount
            .checked_sub(open_native)
            .map_err(|e| KernelError::Corrupt(e.to_string()))?,
        applied_base: original_base
            .checked_sub(historical_open_base)
            .map_err(|e| KernelError::Corrupt(e.to_string()))?,
        open_native,
        open_base,
        historical_open_base,
        valuation_open_base,
        carrying_source_digest: source_hash.finalize().0,
        valuation_route,
        valuation_routes_entry,
        valuation_routes_digest,
        latest_effective_date,
    }))
}

/// Prepare from the journal and retained Rate evidence, never caller balances.
pub fn prepare_fx_settlement<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: &FxSettlementRequest,
    template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<PreparedFxSettlement> {
    cx.query().with_restriction(|| {
        prepare_fx_settlement_inner(db, cx, book, capability, request, template, budget)
    })
}

/// Compose complete single-item effects at one prefix. One retained rate and
/// disjoint targets make every relief independent; no within-entry order can
/// spend another item's remaining native or functional balance.
pub fn prepare_fx_settlement_group<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    requests: &[FxSettlementRequest],
    template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<PreparedFxSettlementGroup> {
    if let Err(refusal) = crate::revaluation::authorize(db, book, capability)? {
        return Ok(Err(refusal));
    }
    if requests.is_empty() || requests.len() > MAX_FX_SETTLEMENT_ITEMS {
        return Ok(Err(invalid(
            "FX group is empty or exceeds the entry leg work bound",
        )));
    }
    let mut targets = BTreeSet::new();
    for request in requests {
        if !targets.insert((request.target.vid, request.target_ordinal)) {
            return Ok(Err(invalid(
                "FX group targets must be pairwise distinct existing legs",
            )));
        }
        if request.rate_document != requests[0].rate_document {
            return Ok(Err(invalid(
                "FX group requires one explicitly shared Settlement Rate document",
            )));
        }
    }
    let head = db.frontier()?;
    let mut proposal: Option<EntryPayload> = None;
    let mut items = Vec::with_capacity(requests.len());
    for request in requests {
        let prepared = match prepare_fx_settlement(
            db,
            cx,
            book,
            capability,
            request,
            template.clone(),
            budget,
        )? {
            Ok(prepared) => prepared,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if items.first().is_some_and(|item: &FxSettlementItem| {
            item.carrying.known_at != prepared.carrying.known_at
        }) {
            return Ok(Err(invalid(
                "FX group preparation did not retain one carrying prefix",
            )));
        }
        let start = proposal.as_ref().map_or(0, |value| value.legs.len());
        let end = start
            .checked_add(prepared.proposal.legs.len())
            .ok_or_else(|| KernelError::Corrupt("FX group leg count overflow".into()))?;
        items.push(FxSettlementItem {
            carrying: prepared.carrying,
            base_relief: prepared.base_relief,
            leg_range: start..end,
        });
        match &mut proposal {
            None => proposal = Some(prepared.proposal),
            Some(combined) => {
                let Some(total) = &mut combined.base_totals else {
                    return Err(KernelError::Corrupt(
                        "FX component has no base totals".into(),
                    ));
                };
                let Some(next) = prepared.proposal.base_totals else {
                    return Err(KernelError::Corrupt(
                        "FX component has no base totals".into(),
                    ));
                };
                if total.fx_law_oid != next.fx_law_oid {
                    return Ok(Err(invalid(
                        "one FX group cannot mix allocated and legacy carrying laws; use separate source-bound entries",
                    )));
                }
                let Some(debits) = total.debits.checked_add(next.debits) else {
                    return Ok(Err(invalid("FX group functional debits overflow")));
                };
                let Some(credits) = total.credits.checked_add(next.credits) else {
                    return Ok(Err(invalid("FX group functional credits overflow")));
                };
                total.debits = debits;
                total.credits = credits;
                if has_allocated_basis(combined) {
                    let mut combined_basis = match allocated::basis(combined) {
                        Ok(value) => value,
                        Err(refusal) => return Ok(Err(refusal)),
                    };
                    let Some((_, raw)) = prepared.proposal.extensions.iter().find(|(tag, _)| {
                        *tag == fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION
                    }) else {
                        return Ok(Err(invalid(
                            "allocated FX group member lost its release basis",
                        )));
                    };
                    let mut next_basis = fa_model::FxSettlementValuationBasis::decode(raw)
                        .map_err(|error| KernelError::Corrupt(error.to_string()))?;
                    for release in &mut next_basis.items {
                        release.applying_ordinal = match usize::from(release.applying_ordinal)
                            .checked_add(start)
                            .and_then(|ordinal| u16::try_from(ordinal).ok())
                        {
                            Some(ordinal) => ordinal,
                            None => {
                                return Ok(Err(invalid(
                                    "allocated group ordinal exceeds the entry bound",
                                )));
                            }
                        };
                    }
                    combined_basis.items.extend(next_basis.items);
                    combined.extensions = vec![(
                        fa_model::entry::FX_SETTLEMENT_VALUATION_EXTENSION,
                        combined_basis.canonical_bytes()?,
                    )];
                }
                combined.legs.extend(prepared.proposal.legs);
            }
        }
    }
    if let Err(refusal) = crate::post::check_aggregate_basis(head, db.frontier()?) {
        return Ok(Err(refusal));
    }
    let Some(mut proposal) = proposal else {
        return Err(KernelError::Corrupt(
            "nonempty FX group has no proposal".into(),
        ));
    };
    proposal.unit_totals = match EntryPayload::fold_unit_totals(&proposal.legs) {
        Ok(totals) => totals,
        Err(error) => return Ok(Err(invalid(error))),
    };
    if let Err(error) = proposal.validate() {
        return Ok(Err(invalid(error)));
    }
    Ok(Ok(PreparedFxSettlementGroup { items, proposal }))
}

/// Ordered components consume every leg exactly once. Identity deliberately
/// excludes a caller's digest so two handles cannot spend the same source.
pub(crate) fn settlement_ranges(
    proposal: &EntryPayload,
) -> Result<Vec<core::ops::Range<usize>>, Refusal> {
    let mut starts = Vec::new();
    let mut targets = BTreeSet::new();
    for (ordinal, leg) in proposal.legs.iter().enumerate() {
        if leg.settles.is_empty() {
            continue;
        }
        let [application] = leg.settles.as_slice() else {
            return Err(invalid("each FX component requires exactly one target"));
        };
        if application.amount != leg.amount
            || !targets.insert((application.target.vid, application.ordinal))
        {
            return Err(invalid(
                "FX components require fully applied, pairwise distinct target legs",
            ));
        }
        starts.push(ordinal);
    }
    if starts.first() != Some(&0) {
        return Err(invalid(
            "an FX effect vector must start with its applied foreign leg",
        ));
    }
    starts.push(proposal.legs.len());
    Ok(starts.windows(2).map(|pair| pair[0]..pair[1]).collect())
}

fn prepare_fx_settlement_inner<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: &FxSettlementRequest,
    mut template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<PreparedFxSettlement> {
    if let Err(refusal) = crate::revaluation::authorize(db, book, capability)? {
        return Ok(Err(refusal));
    }
    if template.book_id != book.book_id
        || template.branch_id != Id128::TRUNK
        || template.principal_ref != capability.holder()
        || !matches!(template.class, EntryClass::ORIGINAL | EntryClass::ADJUSTING)
        || !template.legs.is_empty()
        || !template.unit_totals.is_empty()
        || template.base_totals.is_some()
        || template.control.is_some()
        || template.pending.is_some()
        || !template.supersession.is_empty()
        || !template.extensions.is_empty()
    {
        return Ok(Err(invalid(
            "foreign settlement requires an empty Original or Adjusting template for the authorized principal",
        )));
    }
    let head = db.frontier()?;
    // A retry is reconstructed at the prefix preceding its first publication.
    // The normal kernel semantic-key comparison still judges all request and
    // template bytes; an altered request is never accepted as a replay.
    let id = entry_vid(
        book.book_id,
        &template.principal_ref.0.to_le_bytes(),
        &template.idempotency_key,
    );
    let at = match crate::post::read_entry_at(db, id, head)? {
        Some((prior, seq)) if is_source_bound(&prior.proposal) => CommitSeq(
            seq.0
                .checked_sub(1)
                .ok_or_else(|| KernelError::Corrupt("settlement has sequence zero".into()))?,
        ),
        _ => head,
    };
    let query = cx.query();
    let carrying = match query.with_restriction(|| {
        open_item_carrying_at(db, cx, book, request.target, request.target_ordinal, at)
    })? {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if BTreeSet::from([
        carrying.account,
        request.settlement_account,
        request.conversion_account,
        request.realized_fx_account,
    ])
    .len()
        != 4
    {
        return Ok(Err(invalid(
            "target, cash, conversion, and realized-FX accounts must be distinct",
        )));
    }
    if template.effective_date < carrying.latest_effective_date {
        return Ok(Err(invalid(
            "settlement date precedes the target or an already recorded application/undo",
        )));
    }
    let relief = match remaining_carrying_relief(
        budget,
        carrying.open_native,
        carrying.open_base,
        request.amount,
    ) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let historical_relief = match remaining_carrying_relief(
        budget,
        carrying.open_native,
        carrying.historical_open_base,
        request.amount,
    ) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let Some(row) = db.vertex_at(document_vid(&request.rate_document), at)? else {
        return Ok(Err(invalid(
            "Settlement Rate document is absent at the preparation prefix",
        )));
    };
    if !row.labels.contains(&label::DOCUMENT) {
        return Ok(Err(invalid(
            "the rate reference is not a retained Document",
        )));
    }
    let record = DocumentRecord::decode(&crate::rows::bytes(
        &row,
        property::FA_PAYLOAD,
        "settlement Rate document",
    )?)?;
    let Storage::Inline(raw) = record.storage else {
        return Ok(Err(invalid(
            "settlement requires complete retained inline Rate bytes",
        )));
    };
    if record.kind != RATE_DOCUMENT_KIND {
        return Ok(Err(invalid("the retained evidence is not a Rate document")));
    }
    let rate = match FxRateDocument::decode(&raw) {
        Ok(rate) => rate,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let rate_evidence = match rate.evidence_ref(book.book_id) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if rate_evidence.document_oid != request.rate_document {
        return Ok(Err(invalid(
            "retained Rate bytes do not reproduce the requested document identity",
        )));
    }
    if rate.purpose != FxRatePurpose::Settlement
        || rate.base_unit != relief.unit
        || rate.quote_unit != request.amount.unit
        || rate.rounding != RoundingLaw::HalfEven
        || rate.as_of > template.effective_date
    {
        return Ok(Err(invalid(
            "rate unit, purpose, rounding law, or effective date does not match this settlement",
        )));
    }
    let converted = match rate.to_rate(budget).and_then(|rate| {
        request
            .amount
            .convert(
                budget,
                relief.unit,
                &rate,
                RoundingLaw::HalfEven,
                &book.units,
            )
            .map_err(invalid)
    }) {
        Ok(value) => value,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if converted != request.settlement_amount {
        return Ok(Err(invalid(
            "declared cash amount does not equal the retained Settlement rate conversion; an unexplained difference is not a plug",
        )));
    }
    template = match crate::fx::plan_realized_fx_settlement(
        budget,
        template,
        carrying.account,
        carrying.side.flipped(),
        request.amount,
        historical_relief,
        request.settlement_account,
        request.conversion_account,
        request.realized_fx_account,
        &rate,
        carrying.dimensions.clone(),
        &book.units,
    ) {
        Ok(proposal) => proposal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    template.legs[0].settles = vec![Settlement {
        target: request.target,
        ordinal: request.target_ordinal,
        amount: request.amount,
    }];
    if carrying.valuation_route.is_some() {
        let release = match allocated::release_basis(
            0,
            carrying.carrying_source_digest,
            historical_relief,
            relief,
            carrying.valuation_route,
            carrying.valuation_routes_entry,
            carrying.valuation_routes_digest,
        ) {
            Ok(release) => release,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = allocated::append_release(&mut template, release) {
            return Ok(Err(refusal));
        }
    }
    Ok(Ok(PreparedFxSettlement {
        carrying,
        base_relief: relief,
        proposal: template,
    }))
}

pub(crate) fn validate_post<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    proposal: &EntryPayload,
    at: CommitSeq,
) -> Outcome<()> {
    if !is_source_bound(proposal) {
        return Ok(Ok(()));
    }
    if proposal
        .base_totals
        .as_ref()
        .is_some_and(|totals| totals.fx_law_oid == FxLawId::SettlementSpotCarrying.oid())
    {
        return validate_spot_applications(db, cx, book, proposal, at);
    }
    if has_allocated_basis(proposal) {
        // Dedicated valuation leaves are never settlement consideration or
        // technical conversion accounts for another source. Validate the
        // complete proposed vector against every retained route before any
        // append, as well as checking those leaves during historical replay.
        let chart = crate::chart::read_at(db, book, at)?;
        for epoch in chart.fx_revaluation_routes() {
            for (source, route) in &epoch.routes {
                if let Err(refusal) = allocated::covers_valuation_account(proposal, *source, route)
                {
                    return Ok(Err(refusal));
                }
            }
        }
    }
    let ranges = match settlement_ranges(proposal) {
        Ok(ranges) => ranges,
        Err(refusal) => return Ok(Err(refusal)),
    };
    for range in ranges {
        if let Err(refusal) = validate_component(
            db,
            cx,
            book,
            proposal,
            at,
            range.start,
            &proposal.legs[range],
        )? {
            return Ok(Err(refusal));
        }
    }
    Ok(Ok(()))
}

/// A partial application's immutable quote and native amount uniquely record
/// its relief, independently of any unapplied remainder on the same leg.
fn spot_application_relief<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    proposal: &EntryPayload,
    amount: Amount,
    at: CommitSeq,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<Amount> {
    let Some(totals) = &proposal.base_totals else {
        return Ok(Err(invalid("spot settlement has no valuation claim")));
    };
    let mut selected = None;
    for oid in &totals.rate_doc_oids {
        let Some(row) = db.vertex_at(document_vid(oid), at)? else {
            return Ok(Err(invalid(
                "spot settlement Rate is absent at its recorded prefix",
            )));
        };
        let record = DocumentRecord::decode(&crate::rows::bytes(
            &row,
            property::FA_PAYLOAD,
            "spot settlement Rate",
        )?)?;
        let Storage::Inline(raw) = record.storage else {
            return Ok(Err(invalid(
                "spot settlement requires retained inline Rate bytes",
            )));
        };
        let rate = match FxRateDocument::decode(&raw) {
            Ok(rate) => rate,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if rate.quote_unit != amount.unit {
            continue;
        }
        if selected.is_some()
            || record.kind != RATE_DOCUMENT_KIND
            || !row.labels.contains(&label::DOCUMENT)
            || rate.purpose != FxRatePurpose::Settlement
            || rate.as_of != proposal.effective_date
            || rate.base_unit.0 != totals.unit_id
            || rate.rounding != RoundingLaw::HalfEven
            || rate
                .evidence_ref(book.book_id)
                .map_err(|refusal| KernelError::Corrupt(refusal.message))?
                .document_oid
                != *oid
        {
            return Ok(Err(invalid(
                "spot settlement requires one exact current Settlement quote for its unit",
            )));
        }
        let value = match rate.to_rate(budget).and_then(|rate| {
            amount
                .convert(
                    budget,
                    fa_money::UnitId(totals.unit_id),
                    &rate,
                    RoundingLaw::HalfEven,
                    &book.units,
                )
                .map_err(invalid)
        }) {
            Ok(value) => value,
            Err(refusal) => return Ok(Err(refusal)),
        };
        selected = Some(value);
    }
    Ok(selected
        .ok_or_else(|| invalid("spot settlement has no retained quote for its applying unit")))
}

fn validate_spot_applications<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    proposal: &EntryPayload,
    at: CommitSeq,
) -> Outcome<()> {
    let spec = crate::fx::book_spec_at(db, book, at)?;
    let current = asupersync::Cx::current()
        .ok_or_else(|| KernelError::Corrupt("spot settlement requires caller context".into()))?;
    let stripped = current.restrict::<asupersync::cx::cap::None>();
    let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
    let mut targets = BTreeSet::new();
    for leg in &proposal.legs {
        if leg.amount.unit == spec.base_unit || leg.settles.is_empty() {
            continue;
        }
        cx.query()
            .checkpoint()
            .map_err(fgdb::WriteTxnError::Interrupted)?;
        let [application] = leg.settles.as_slice() else {
            return Ok(Err(invalid(
                "each foreign spot-settlement leg names one explicit target",
            )));
        };
        if application.amount.unit != leg.amount.unit
            || application.amount.mantissa > leg.amount.mantissa
            || !targets.insert((application.target.vid, application.ordinal))
        {
            return Ok(Err(invalid(
                "foreign spot applications require positive disjoint target allocations bounded by their complete legs",
            )));
        }
        let item =
            match open_item_carrying_at(db, cx, book, application.target, application.ordinal, at)?
            {
                Ok(item) => item,
                Err(refusal) => return Ok(Err(refusal)),
            };
        if item.valuation_route.is_some()
            || item.account != leg.account_ref
            || item.side == leg.side
            || item.dimensions != leg.dimension_set
            || proposal.effective_date < item.latest_effective_date
        {
            return Ok(Err(invalid(
                "spot settlement requires an unadjusted matching carrying source and nonretroactive date; use the explicit conversion/release path",
            )));
        }
        let expected = match remaining_carrying_relief(
            &mut budget,
            item.open_native,
            item.open_base,
            application.amount,
        ) {
            Ok(value) => value,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let recorded =
            match spot_application_relief(db, book, proposal, application.amount, at, &mut budget)?
            {
                Ok(value) => value,
                Err(refusal) => return Ok(Err(refusal)),
            };
        if expected != recorded {
            return Ok(Err(invalid(
                "Settlement quote disagrees with RemainingCarryingValue relief; use an explicit realized-FX conversion route",
            )));
        }
    }
    if targets.is_empty() {
        return Ok(Err(invalid(
            "SettlementSpotCarrying requires at least one foreign application",
        )));
    }
    Ok(Ok(()))
}

/// Exact application undo restores its recorded split, without repricing the
/// old receipt after a later revaluation. Reversing an original source while
/// its contra component remains would orphan that component and is refused.
pub(crate) fn validate_reversal<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    target: EntryRef,
    original: &EntryPayload,
    reversal: &EntryPayload,
    at: CommitSeq,
) -> Outcome<()> {
    cx.query().with_restriction(|| {
        if has_allocated_basis(original) {
            let releases = match allocated::basis(original) { Ok(value) => value, Err(refusal) => return Ok(Err(refusal)) };
            for release in releases.items {
                let Some(leg) = original.legs.get(usize::from(release.applying_ordinal)) else { return Ok(Err(invalid("allocated undo has no original applying leg"))); };
                let [application] = leg.settles.as_slice() else { return Ok(Err(invalid("allocated undo has no unique recorded application"))); };
                let item = match open_item_carrying_at(db, cx, book, application.target, application.ordinal, at)? { Ok(item) => item, Err(refusal) => return Ok(Err(refusal)) };
                let native = item.open_native.checked_add(application.amount).map_err(|error| KernelError::Corrupt(error.to_string()))?;
                let historical = item.historical_open_base.checked_add(release.historical_relief).map_err(|error| KernelError::Corrupt(error.to_string()))?;
                let valuation = item.valuation_open_base.checked_add(release.valuation_relief).map_err(|error| KernelError::Corrupt(error.to_string()))?;
                let total = historical.checked_add(valuation).map_err(|error| KernelError::Corrupt(error.to_string()))?;
                if native.mantissa > item.original_native.mantissa || historical.mantissa > item.original_base.mantissa
                    || total.mantissa < 0 || reversal.effective_date < item.latest_effective_date
                {
                    return Ok(Err(invalid("exact allocated-settlement undo would exceed original capacity, produce negative carrying, or precede a later item effect")));
                }
            }
            return Ok(Ok(()));
        }
        if original.class == EntryClass::REVERSAL || original.base_totals.as_ref().is_none_or(|total| {
            !matches!(FxLawId::from_oid(&total.fx_law_oid), Some(FxLawId::SpotClose | FxLawId::PeriodAverage))
        }) { return Ok(Ok(())); }
        let mut allocated_ordinals = BTreeSet::new();
        for row in db.vertices_at(at)? {
            cx.query().checkpoint().map_err(fgdb::WriteTxnError::Interrupted)?;
            if !row.labels.contains(&label::ENTRY) { continue; }
            let Some((entry, _)) = crate::post::read_entry_at(db, row.vid, at)? else { continue; };
            let Some((_, raw)) = entry.proposal.extensions.iter().find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION) else { continue; };
            let basis = FxRevaluationBasis::decode(raw).map_err(|error| KernelError::Corrupt(error.to_string()))?;
            if let Some(allocation) = basis.item_allocation {
                for item in allocation.items { if item.target == target { allocated_ordinals.insert(item.ordinal); } }
            }
        }
        for ordinal in allocated_ordinals {
            let item = match open_item_carrying_at(db, cx, book, target, ordinal, at)? { Ok(item) => item, Err(refusal) => return Ok(Err(refusal)) };
            if item.valuation_open_base.mantissa != 0 || reversal.effective_date < item.latest_effective_date {
                return Ok(Err(invalid("the original item retains allocated valuation or a later item effect; correct its valuation through a new allocated revaluation before reversing the original")));
            }
        }
        Ok(Ok(()))
    })
}

fn validate_component<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    proposal: &EntryPayload,
    at: CommitSeq,
    applying_ordinal: usize,
    legs: &[fa_model::LegPayload],
) -> Outcome<()> {
    let applying: Vec<_> = legs.iter().filter(|leg| !leg.settles.is_empty()).collect();
    let [leg] = applying.as_slice() else {
        return Ok(Err(invalid(
            "source-bound FX settlement requires exactly one explicitly applied foreign leg",
        )));
    };
    let [application] = leg.settles.as_slice() else {
        return Ok(Err(invalid(
            "an FX applying leg must name exactly one target",
        )));
    };
    if application.amount != leg.amount {
        return Ok(Err(invalid(
            "the foreign applying leg must be fully allocated to its explicit target",
        )));
    }
    cx.query().with_restriction(|| {
        let carrying = match open_item_carrying_at(
            db, cx, book, application.target, application.ordinal, at,
        )? {
            Ok(value) => value,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if leg.account_ref != carrying.account
            || leg.side == carrying.side
            || leg.dimension_set != carrying.dimensions
            || proposal.effective_date < carrying.latest_effective_date
        {
            return Ok(Err(invalid(
                "application account, side, dimensions, or chronology does not match the retained open item",
            )));
        }
        let current = asupersync::Cx::current().ok_or_else(|| {
            KernelError::Corrupt("settlement validation requires caller context".into())
        })?;
        let stripped = current.restrict::<asupersync::cx::cap::None>();
        let mut budget = ArithmeticBudget::new(&stripped, BudgetLimits::uniform(1_000_000, 0), 4096);
        let expected = match remaining_carrying_relief(
            &mut budget, carrying.open_native, carrying.historical_open_base, application.amount,
        ) {
            Ok(value) => value,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if leg.base_amount != Some(expected) {
            return Ok(Err(invalid(format!(
                "supplied base relief {:?} disagrees with journal-derived {} under RemainingCarryingValue",
                leg.base_amount, expected.render(&book.units),
            ))));
        }
        let legs = if carrying.valuation_route.is_some() {
            let total = match remaining_carrying_relief(&mut budget, carrying.open_native, carrying.open_base, application.amount) {
                Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
            };
            let release = match allocated::release_basis(applying_ordinal, carrying.carrying_source_digest, expected, total,
                carrying.valuation_route, carrying.valuation_routes_entry, carrying.valuation_routes_digest) {
                Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) = allocated::check_release(proposal, &release) { return Ok(Err(refusal)); }
            let tail = usize::from(release.valuation_relief.mantissa != 0) * 2;
            let Some(end) = legs.len().checked_sub(tail) else { return Ok(Err(invalid("valuation release tail is missing"))); };
            &legs[..end]
        } else {
            if has_allocated_basis(proposal) { return Ok(Err(invalid("a legacy unallocated item cannot acquire a caller-authored valuation-release basis"))); }
            legs
        };
        // This law's complete effect vector is explicit and bounded. Merely
        // finding one plausible pair somewhere in arbitrary extra legs would
        // leave other foreign valuations unchecked.
        let core_len = if expected.mantissa == 0 { 3 } else { 4 };
        if !(core_len..=core_len + 1).contains(&legs.len())
            || legs[0].settles.len() != 1
        {
            return Ok(Err(invalid(
                "a source-bound settlement has its ordered core legs and, only when needed, one explicit realized-FX leg; a zero base conversion leg is omitted",
            )));
        }
        let settled = &legs[0];
        let conversion_foreign = &legs[1];
        let cash = &legs[core_len - 1];
        if conversion_foreign.account_ref == settled.account_ref
            || conversion_foreign.account_ref == cash.account_ref
            || settled.account_ref == cash.account_ref
            || conversion_foreign.side != settled.side.flipped()
            || conversion_foreign.amount != settled.amount
            || conversion_foreign.base_amount != Some(expected)
            || conversion_foreign.dimension_set != settled.dimension_set
            || cash.side != settled.side.flipped()
            || cash.amount.unit != expected.unit
            || cash.base_amount != Some(cash.amount)
        {
            return Ok(Err(invalid(
                "settlement core legs do not reproduce the target relief, paired conversion, and declared functional cash",
            )));
        }
        if expected.mantissa != 0 {
            let conversion_base = &legs[2];
            if conversion_base.account_ref != conversion_foreign.account_ref
                || conversion_base.side != settled.side
                || conversion_base.amount != expected
                || conversion_base.base_amount != Some(expected)
                || conversion_base.dimension_set != settled.dimension_set
            {
                return Ok(Err(invalid("base conversion leg differs from the exact recorded carrying relief")));
            }
        }
        let difference = cash.amount.mantissa.checked_sub(expected.mantissa)
            .ok_or_else(|| KernelError::Corrupt("settlement difference overflow".into()))?;
        if difference == 0 {
            if legs.len() != core_len {
                return Ok(Err(invalid("a zero realized-FX difference has no extra posting")));
            }
        } else {
            let Some(realized) = legs.get(core_len) else {
                return Ok(Err(invalid("the nonzero realized-FX difference requires its explicit paired leg")));
            };
            let magnitude = difference.checked_abs()
                .ok_or_else(|| KernelError::Corrupt("realized FX magnitude overflow".into()))?;
            let expected_side = if difference > 0 { settled.side } else { settled.side.flipped() };
            if BTreeSet::from([
                settled.account_ref, conversion_foreign.account_ref,
                cash.account_ref, realized.account_ref,
            ]).len() != 4
                || realized.side != expected_side
                || realized.amount != Amount::new(expected.unit, magnitude)
                || realized.base_amount != Some(realized.amount)
                || realized.dimension_set != settled.dimension_set
            {
                return Ok(Err(invalid(
                    "realized-FX leg differs from the exact cash-minus-recorded-relief difference",
                )));
            }
        }
        Ok(Ok(()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_money::UnitId;

    #[test]
    fn partial_final_and_zero_relief_are_exact_at_i128_boundaries() {
        let cx = asupersync::Cx::detached_cancel_context();
        let mut budget = ArithmeticBudget::new(&cx, BudgetLimits::uniform(1_000_000, 0), 4096);
        let native = |m| Amount::new(UnitId(2), m);
        let base = |m| Amount::new(UnitId(1), m);
        assert_eq!(
            remaining_carrying_relief(&mut budget, native(3), base(10), native(1)).unwrap(),
            base(3)
        );
        assert_eq!(
            remaining_carrying_relief(&mut budget, native(2), base(7), native(1)).unwrap(),
            base(4)
        );
        assert_eq!(
            remaining_carrying_relief(&mut budget, native(1), base(3), native(1)).unwrap(),
            base(3)
        );
        assert_eq!(
            remaining_carrying_relief(&mut budget, native(2), base(1), native(1)).unwrap(),
            base(0)
        );
        assert_eq!(
            remaining_carrying_relief(
                &mut budget,
                native(i128::MAX),
                base(i128::MAX),
                native(i128::MAX - 1)
            )
            .unwrap(),
            base(i128::MAX - 1)
        );
        assert!(remaining_carrying_relief(&mut budget, native(1), base(1), native(2)).is_err());
    }
}
