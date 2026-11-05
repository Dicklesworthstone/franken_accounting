//! Journal-derived functional carrying values for foreign open items (§5.7).
//!
//! The bounded application law is RemainingCarryingValue with HalfEven:
//! a partial application relieves `open_base * native / open_native`, and
//! the final application relieves the entire remaining base amount. Each
//! applying conversion leg names exactly one target and applies its entire
//! native amount; its immutable `base_amount` is the recorded relief.
//! SettlementSpotCarrying instead records a current Settlement quote that
//! must reproduce the exact relief of its applied portion, separately from
//! an unapplied remainder. Reversals restore the recorded relief, including zero.
//!
//! Allocated revaluations retain every item's original-cost and valuation
//! components. Settlement relieves both under explicit laws; legacy aggregate
//! adjustments never acquire an inferred allocation.

mod allocated;
mod history;
pub(crate) use allocated::ReleaseIndex as AllocatedReleaseIndex;
pub(crate) use allocated::basis as allocated_basis;
pub(crate) use allocated::covers_valuation_account;
pub(crate) use allocated::{has_allocated_basis, verify_allocated_fx_structure};
pub use history::CarryingPopulationWork;
pub(crate) use history::cached_liveness as reversal_liveness;
pub(crate) use history::{CarryingHistory, CarryingIndex};

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::entry::FX_REVALUATION_EXTENSION;
use fa_model::symbols::{label, property};
use fa_model::{
    EntryClass, EntryPayload, EntryRef, FxRevaluationBasis, Id128, LegPayload, Oid, Settlement,
    SupersessionKind, entry_vid,
};
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fa_money::{Amount, Rate, RoundingLaw, Side};
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

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
    audit_work: CarryingAuditWork,
    population_work: CarryingPopulationWork,
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
    /// Actual whole-source audit calls and successful same-prefix reuses.
    pub fn audit_work(&self) -> CarryingAuditWork {
        self.audit_work
    }
    /// Work selecting the compound operation's carrying population. One
    /// complete fixed-prefix index serves every item; historical source
    /// audits remain separately counted by [`Self::audit_work`].
    pub fn population_work(&self) -> CarryingPopulationWork {
        self.population_work
    }
}

/// Work performed by the source-history verifier within one compound operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CarryingAuditWork {
    pub source_history_audits: usize,
    pub successful_reuses: usize,
}

/// A successful audit covers all allocated items on one source, independently
/// of which item triggered it. Keep only successes, within one immutable read
/// operation and one exact book/prefix. This is deliberately not a cached item
/// result: each target must first pass its own original carrying checks.
/// The accompanying observation belongs only to this compound operation and
/// exact prefix; it never escapes to another database or a later invocation.
#[derive(Default)]
struct SuccessfulHistoryAudits {
    coordinate: Option<(Id128, CommitSeq)>,
    sources: BTreeSet<VId>,
    work: CarryingAuditWork,
    history: Option<CarryingHistory>,
    population_work: CarryingPopulationWork,
}

impl SuccessfulHistoryAudits {
    fn select(&mut self, book: Id128, at: CommitSeq) {
        if self.coordinate != Some((book, at)) {
            // A retry can return to the prefix preceding first publication.
            // Neither observations nor successful audits cross coordinates.
            if let Some(history) = self.history.take() {
                self.population_work.accumulate(history.work());
            }
            self.sources.clear();
            self.coordinate = Some((book, at));
        }
    }

    fn population_work(&self) -> CarryingPopulationWork {
        let mut work = self.population_work;
        if let Some(history) = &self.history {
            work.accumulate(history.work());
        }
        work
    }

    #[allow(clippy::too_many_arguments)]
    fn read_item<V: Vfs + Clone>(
        &mut self,
        db: &Database<V>,
        cx: &PurposeContexts,
        book: &BookContext,
        target: EntryRef,
        ordinal: u16,
        at: CommitSeq,
    ) -> Outcome<CarryingOpenItem> {
        self.select(book.book_id, at);
        if self.history.is_none() {
            // Preserve the literal reader's early target refusals before any
            // whole-prefix observation. Later targets reuse the same payloads,
            // but still repeat every digest, ordinal and valuation check.
            if let Err(refusal) = carrying_target_at(db, cx, book, target, ordinal, at, None)? {
                return Ok(Err(refusal));
            }
            self.population_work.entries_decoded += 1;
            self.history = match CarryingHistory::read_at(db, cx, book, at) {
                Ok(history) => Some(history),
                Err(error @ KernelError::Txn(fgdb::WriteTxnError::Interrupted(_))) => {
                    return Err(error);
                }
                // Index construction can discover several malformed rows in
                // a different order. The original native scan remains the
                // authority for the exact first error on a damaged prefix.
                Err(_) => return open_item_carrying_inner(db, cx, book, target, ordinal, at),
            };
        }
        open_item_carrying_observed(db, cx, book, target, ordinal, at, self.history.as_ref())
    }

    fn verify(
        &mut self,
        cx: &PurposeContexts,
        book: Id128,
        at: CommitSeq,
        source: VId,
        audit: impl FnOnce() -> Outcome<()>,
    ) -> Outcome<()> {
        self.select(book, at);
        if self.sources.contains(&source) {
            cx.query()
                .checkpoint()
                .map_err(fgdb::WriteTxnError::Interrupted)?;
            self.work.successful_reuses += 1;
            return Ok(Ok(()));
        }
        self.work.source_history_audits += 1;
        let result = audit()?;
        if result.is_ok() {
            self.sources.insert(source);
        }
        Ok(result)
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
        "use distinct existing FX targets with independent, nonapplying Original companions outside their source and valuation accounts; companion applications, reversals and adjustments, paired replacement, and case promotion require separate publication",
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
/// after current read/post admission or typed owned-draft source admission,
/// and protects the fold with the complete-prefix publication guard. Draft
/// source facades return only derived effects, never this source observation.
pub fn open_item_carrying_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    target: EntryRef,
    ordinal: u16,
    at: CommitSeq,
) -> Outcome<CarryingOpenItem> {
    open_item_carrying_with_audits(db, cx, book, target, ordinal, at, None)
}

fn open_item_carrying_with_audits<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    target: EntryRef,
    ordinal: u16,
    at: CommitSeq,
    mut audits: Option<&mut SuccessfulHistoryAudits>,
) -> Outcome<CarryingOpenItem> {
    cx.query().with_restriction(|| {
        let result = match audits.as_deref_mut() {
            Some(audits) => audits.read_item(db, cx, book, target, ordinal, at)?,
            None => open_item_carrying_inner(db, cx, book, target, ordinal, at)?,
        };
        if let Ok(item) = &result
            && item.valuation_route.is_some()
        {
            let audit = || crate::revaluation::verify_item_history(db, cx, book, item.account, at);
            let verified = match audits {
                Some(audits) => audits.verify(cx, book.book_id, at, item.account, audit)?,
                None => audit()?,
            };
            if let Err(refusal) = verified {
                return Ok(Err(refusal));
            }
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
    open_item_carrying_observed(db, cx, book, target, ordinal, at, None)
}

struct CarryingTarget<'a> {
    original: Cow<'a, fa_model::Entry>,
    recorded: CommitSeq,
    spec: Cow<'a, crate::genesis::BookSpec>,
    original_base: Amount,
}

/// Target identity and shape checks precede all complete-history work in both
/// readers. A target outside the index is still point-read: another book or
/// branch must retain the literal reader's handle refusal, not become absent.
fn carrying_target_at<'a, V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    target: EntryRef,
    ordinal: u16,
    at: CommitSeq,
    history: Option<&'a CarryingHistory>,
) -> Outcome<CarryingTarget<'a>> {
    let query = cx.query();
    query
        .checkpoint()
        .map_err(fgdb::WriteTxnError::Interrupted)?;
    if at > db.frontier()? {
        return Ok(Err(invalid(
            "carrying-value prefix is beyond the retained frontier",
        )));
    }
    if history.is_some_and(|history| history.at != at || history.spec.book_id != book.book_id) {
        return Err(KernelError::Corrupt(
            "carrying observation belongs to another book or prefix".into(),
        ));
    }
    let (original, recorded) = match history.and_then(|history| history.original(target.vid)) {
        Some((original, recorded)) => (Cow::Borrowed(original), recorded),
        None => {
            let Some((original, recorded)) = crate::post::read_entry_at(db, target.vid, at)? else {
                return Ok(Err(invalid(
                    "the foreign open item does not exist at this prefix",
                )));
            };
            (Cow::Owned(original), recorded)
        }
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
    let spec = match history {
        Some(history) => Cow::Borrowed(&history.spec),
        None => Cow::Owned(crate::fx::book_spec_at(db, book, at)?),
    };
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
    Ok(Ok(CarryingTarget {
        original,
        recorded,
        spec,
        original_base,
    }))
}

/// The same monetary fold with an optional shared, fixed-prefix observation.
/// The literal single-item reader remains the comparison path: only candidate
/// selection and already authenticated metadata differ in the population path.
pub(crate) fn open_item_carrying_observed<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    target: EntryRef,
    ordinal: u16,
    at: CommitSeq,
    history: Option<&CarryingHistory>,
) -> Outcome<CarryingOpenItem> {
    let CarryingTarget {
        original,
        recorded,
        spec,
        original_base,
    } = match carrying_target_at(db, cx, book, target, ordinal, at, history)? {
        Ok(target) => target,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let leg = &original.proposal.legs[usize::from(ordinal)];
    let query = cx.query();
    let mut entries = Vec::new();
    let mut reversals = BTreeMap::new();
    if history.is_none() {
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
    }
    let target_is_live = match history {
        Some(history) => history.is_live(cx, target.vid)?,
        None => live(target.vid, &reversals)?,
    };
    if !target_is_live {
        return Ok(Err(invalid("the target open item is reversed")));
    }
    // A valuation contra account carries an aggregate adjustment, not a
    // per-item allocation. Refuse instead of assigning it to this invoice.
    if let Some(history) = history {
        if let Err(refusal) = history.check_source(db, cx, book, leg.account_ref, recorded)? {
            return Ok(Err(refusal));
        }
    } else {
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
                        && let Err(refusal) = allocated::covers_valuation_account(
                            &entry.proposal,
                            leg.account_ref,
                            route,
                        )
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
    let indices: Box<dyn Iterator<Item = usize>> = match history {
        Some(history) => {
            let entity = crate::revaluation::item_entity(&spec, leg)
                .map_err(|error| KernelError::Corrupt(error.message))?;
            Box::new(
                history
                    .events((target.vid, ordinal), leg.account_ref, entity, recorded)
                    .into_iter(),
            )
        }
        None => Box::new(0..entries.len()),
    };
    for index in indices {
        let (seq, vid, entry) = match history {
            Some(history) => history.event(index),
            None => &entries[index],
        };
        let (seq, vid) = (*seq, *vid);
        query
            .checkpoint()
            .map_err(fgdb::WriteTxnError::Interrupted)?;
        let mut effect = (0i128, 0i128, 0i128);
        if seq < recorded {
            continue;
        }
        let adjustment = match history {
            Some(history) => history.adjustment(index).map(Cow::Borrowed),
            None => entry
                .proposal
                .extensions
                .iter()
                .find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
                .map(|(_, raw)| {
                    FxRevaluationBasis::decode(raw)
                        .map(Cow::Owned)
                        .map_err(|error| KernelError::Corrupt(error.to_string()))
                })
                .transpose()?,
        };
        if let Some(basis) = adjustment
            && basis.source_account == leg.account_ref
            && crate::revaluation::item_entity(&spec, leg)
                .map_err(|error| KernelError::Corrupt(error.message))?
                == basis.entity
            && let Some(allocation) = &basis.item_allocation
        {
            let item = match history {
                Some(history) => history.allocation_item(index, (target.vid, ordinal)),
                None => allocation
                    .items
                    .iter()
                    .find(|item| item.target.vid == target.vid && item.ordinal == ordinal),
            };
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
                let route = match history {
                    Some(history) => match history.route(db, book, index)? {
                        Ok(route) => route,
                        Err(refusal) => return Ok(Err(refusal)),
                    },
                    None => {
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
                        route
                    }
                };
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
            let applications: Cow<'_, [(usize, usize)]> = match history {
                Some(history) => Cow::Borrowed(history.applications((target.vid, ordinal), index)),
                None => Cow::Owned(
                    entry
                        .proposal
                        .legs
                        .iter()
                        .enumerate()
                        .flat_map(|(leg_ordinal, applying)| {
                            applying.settles.iter().enumerate().filter_map(
                                move |(application_ordinal, application)| {
                                    (application.target.vid == target.vid
                                        && application.ordinal == ordinal)
                                        .then_some((leg_ordinal, application_ordinal))
                                },
                            )
                        })
                        .collect(),
                ),
            };
            for &(applying_ordinal, application_ordinal) in applications.iter() {
                let applying = &entry.proposal.legs[applying_ordinal];
                let application = &applying.settles[application_ordinal];
                let spot = entry.proposal.base_totals.as_ref().is_some_and(|totals| {
                    totals.fx_law_oid == FxLawId::SettlementSpotCarrying.oid()
                });
                if application.target != target
                    || applying.settles.len() != 1
                    || if spot {
                        application.amount.mantissa > applying.amount.mantissa
                    } else {
                        application.amount != applying.amount
                            || match history {
                                Some(history) => !history.settlement_ranges_valid(index),
                                None => settlement_ranges(&entry.proposal).is_err(),
                            }
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
                    let checked = match history {
                        Some(history) => history.check_release(index, &expected_release),
                        None => allocated::check_release(&entry.proposal, &expected_release),
                    };
                    if let Err(refusal) = checked {
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
                effect.1 = effect
                    .1
                    .checked_add(relief.mantissa)
                    .ok_or_else(|| KernelError::Corrupt("base application sum overflow".into()))?;
                effect.2 = effect
                    .2
                    .checked_add(allocated_relief)
                    .ok_or_else(|| KernelError::Corrupt("valuation relief overflow".into()))?;
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

/// Resolve only a named open-item source for an owned draft. The current
/// branch-confined Post capability admits metadata before the entry payload
/// is decoded. Missing and out-of-scope entries have the same result, and
/// only the canonical handle is returned, never the source's monetary facts.
pub fn draft_source_entry_ref<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    vid: VId,
) -> Outcome<Option<EntryRef>> {
    draft_source_entry(db, cx, book, admission, vid)
        .map(|result| result.map(|entry| entry.map(|entry| entry.entry_ref(vid))))
}

/// Decode only one completely admitted source at a time. Keeping the entry
/// private lets the settlement preflight validate all selected ordinals with
/// one decode, while the public handle resolver reveals no monetary facts.
fn draft_source_entry<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    vid: VId,
) -> Outcome<Option<fa_model::Entry>> {
    cx.query()
        .checkpoint()
        .map_err(fgdb::WriteTxnError::Interrupted)?;
    if let Err(refusal) = admission.recheck(db, book)? {
        return Ok(Err(refusal));
    }
    let capability = admission.capability();
    let current = match crate::policy::current_at(db, book, capability)? {
        Ok(current) => current,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let scope = crate::policy::account_scope(db, book, &current)?;
    let txn = db.begin(&cx.txn())?;
    let result = (|| {
        if txn.vertex_has_label(db, vid, label::ENTRY)? != Some(true)
            || !matches!(
                txn.vertex_property(db, vid, property::BOOK_ID)?,
                Some(CanonicalScalar::Bytes(value)) if value.as_slice() == book.book_id.0
            )
            || !matches!(
                txn.vertex_property(db, vid, property::CLASS)?,
                Some(CanonicalScalar::Int(tag))
                    if u16::try_from(tag).ok().is_some_and(|tag| EntryClass(tag).carries_open_items())
            )
            || !crate::policy::entry_in_scope_by_metadata(
                &txn,
                db,
                book,
                capability,
                scope.as_ref(),
                vid,
            )?
        {
            return Ok(Ok(None));
        }
        let Some(row) = txn.vertex(db, vid)? else {
            return Ok(Ok(None));
        };
        let (entry, _) = crate::post::checked_entry(db, &row)?;
        if !crate::entry_storage::mirrors_match(&row, &entry)? {
            return Err(KernelError::Corrupt(
                "an admitted draft source disagrees with its immutable entry mirrors".into(),
            ));
        }
        if entry.proposal.book_id != book.book_id
            || entry.proposal.branch_id != Id128::TRUNK
            || !entry.proposal.class.carries_open_items()
            || crate::policy::payload_reach_in_branch(
                capability,
                book,
                &entry.proposal,
                scope.as_ref(),
                fa_model::draft_branch(book.book_id, admission.name()),
            )
            .is_err()
        {
            return Ok(Ok(None));
        }
        Ok(Ok(Some(entry)))
    })();
    // This is a read-only snapshot pin, not a publication or a reservation.
    // Release it on errors as well as on success.
    txn.abort();
    result
}

fn settlement_template(
    book: &BookContext,
    capability: &Capability,
    template: &EntryPayload,
) -> Result<(), Refusal> {
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
        return Err(invalid(
            "foreign settlement requires an empty Original or Adjusting template for the authorized principal",
        ));
    }
    Ok(())
}

fn settlement_requests(requests: &[FxSettlementRequest]) -> Result<(), Refusal> {
    if requests.is_empty() || requests.len() > MAX_FX_SETTLEMENT_ITEMS {
        return Err(invalid(
            "FX group is empty or exceeds the entry leg work bound",
        ));
    }
    let mut targets = BTreeSet::new();
    for request in requests {
        if !targets.insert((request.target.vid, request.target_ordinal)) {
            return Err(invalid(
                "FX group targets must be pairwise distinct existing legs",
            ));
        }
        if request.rate_document != requests[0].rate_document {
            return Err(invalid(
                "FX group requires one explicitly shared Settlement Rate document",
            ));
        }
    }
    Ok(())
}

/// Admit named settlement sources and declared effects before hydrating the
/// carrying history. Only the selected immutable target entries are point
/// read here; their balances are neither folded nor returned. The complete
/// generated proposal is admitted separately after exact relief derivation.
pub fn admit_draft_settlement_requests<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    requests: &[FxSettlementRequest],
    template: &EntryPayload,
) -> Outcome<()> {
    cx.query().with_restriction(|| {
        if let Err(refusal) = admission.admit_proposal(db, book, template)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = settlement_template(book, admission.capability(), template)
            .and_then(|()| settlement_requests(requests))
        {
            return Ok(Err(refusal));
        }
        let mut declared = template.clone();
        for request in requests {
            if request.amount.mantissa <= 0 || request.settlement_amount.mantissa <= 0 {
                return Ok(Err(invalid(
                    "FX settlement requires positive declared native and cash amounts",
                )));
            }
            // These are admission inputs, not a proposed posting vector.
            // Admit every declared route using only the caller's amounts;
            // the as-yet unknown realized amount is checked after derivation.
            declared.legs.extend([
                LegPayload::simple(
                    Side::Debit,
                    request.settlement_account,
                    request.settlement_amount,
                ),
                LegPayload::simple(
                    Side::Credit,
                    request.conversion_account,
                    request.settlement_amount,
                ),
                LegPayload::simple(Side::Debit, request.conversion_account, request.amount),
                LegPayload::simple(
                    Side::Credit,
                    request.realized_fx_account,
                    request.settlement_amount,
                ),
            ]);
        }
        if let Err(refusal) = admission.admit_proposal(db, book, &declared)? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = crate::redaction::admit_draft_source_record(
            db,
            book,
            admission.capability(),
            requests[0].rate_document,
            crate::redaction::DraftSourceKind::FxRate,
        )? {
            return Ok(Err(refusal));
        }
        let mut targets: BTreeMap<VId, Vec<&FxSettlementRequest>> = BTreeMap::new();
        for request in requests {
            targets.entry(request.target.vid).or_default().push(request);
        }
        for request in requests {
            cx.query()
                .checkpoint()
                .map_err(fgdb::WriteTxnError::Interrupted)?;
            let Some(selected) = targets.remove(&request.target.vid) else {
                continue;
            };
            // One bounded entry is decoded at a time, even when every request
            // names a different maximal-size source. Its selected ordinals share
            // its decode without retaining the complete source population.
            let original = match draft_source_entry(db, cx, book, admission, request.target.vid)? {
                Ok(Some(entry)) => entry,
                Ok(None) => {
                    return Ok(Err(invalid(
                        "the foreign open item is unavailable within this draft's source scope",
                    )));
                }
                Err(refusal) => return Ok(Err(refusal)),
            };
            for request in selected {
                if original.entry_ref(request.target.vid) != request.target {
                    return Ok(Err(invalid(
                        "the target handle does not name this book's retained posted item",
                    )));
                }
                let Some(source) = original
                    .proposal
                    .legs
                    .get(usize::from(request.target_ordinal))
                else {
                    return Ok(Err(invalid("target ordinal is outside the original entry")));
                };
                if source.amount.unit != request.amount.unit
                    || source
                        .base_amount
                        .is_none_or(|amount| amount.unit != request.settlement_amount.unit)
                    || !source.settles.is_empty()
                {
                    return Ok(Err(invalid(
                        "the selected target is not a matching foreign carrying source",
                    )));
                }
                let mut applying =
                    LegPayload::simple(source.side.flipped(), source.account_ref, request.amount);
                applying.dimension_set = source.dimension_set.clone();
                declared.legs.push(applying);
            }
        }
        admission.admit_proposal(db, book, &declared)
    })
}

/// Derive one source-bound settlement for an owned, explicitly confined draft.
/// Only admitted posting effects escape; the source's original, applied and
/// remaining balances in `PreparedFxSettlement` are not disclosed.
pub fn prepare_fx_settlement_in_draft<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    request: &FxSettlementRequest,
    template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<EntryPayload> {
    prepare_fx_settlement_group_in_draft(
        db,
        cx,
        book,
        admission,
        std::slice::from_ref(request),
        template,
        budget,
    )
}

/// Derive a complete disjoint group under the draft's original authority.
/// Source explanations remain internal; only the admitted proposal is returned.
/// Targets are existing trunk items. Draft append and promotion retain the
/// independent carrying-batch rule: one target leg cannot occur in two members.
pub fn prepare_fx_settlement_group_in_draft<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    admission: &crate::draft::DraftSourceAdmission,
    requests: &[FxSettlementRequest],
    template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<EntryPayload> {
    if let Err(refusal) =
        admit_draft_settlement_requests(db, cx, book, admission, requests, &template)?
    {
        return Ok(Err(refusal));
    }
    let prepared = match prepare_fx_settlement_group_with_admission(
        db,
        cx,
        book,
        admission.capability(),
        Some(admission),
        requests,
        template,
        budget,
    )? {
        Ok(prepared) => prepared,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let proposal = prepared.into_proposal();
    Ok(admission
        .admit_derived_proposal(db, book, &proposal)?
        .map(|()| proposal))
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
        prepare_fx_settlement_inner(
            db, cx, book, capability, None, request, template, budget, None,
        )
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
    prepare_fx_settlement_group_with_admission(
        db, cx, book, capability, None, requests, template, budget,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_fx_settlement_group_with_admission<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    draft: Option<&crate::draft::DraftSourceAdmission>,
    requests: &[FxSettlementRequest],
    template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<PreparedFxSettlementGroup> {
    let authorized = match draft {
        Some(admission) => admission.admit_proposal(db, book, &template)?,
        None => crate::revaluation::authorize(db, book, capability)?,
    };
    if let Err(refusal) = authorized {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = settlement_requests(requests) {
        return Ok(Err(refusal));
    }
    let head = db.frontier()?;
    let mut proposal: Option<EntryPayload> = None;
    let mut items = Vec::with_capacity(requests.len());
    let mut audits = SuccessfulHistoryAudits::default();
    for request in requests {
        let prepared = match cx.query().with_restriction(|| {
            prepare_fx_settlement_inner(
                db,
                cx,
                book,
                capability,
                draft,
                request,
                template.clone(),
                budget,
                Some(&mut audits),
            )
        })? {
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
    Ok(Ok(PreparedFxSettlementGroup {
        items,
        proposal,
        audit_work: audits.work,
        population_work: audits.population_work(),
    }))
}

/// Ordered components consume every leg exactly once. Identity deliberately
/// excludes a caller's digest so two handles cannot spend the same source.
pub(crate) fn settlement_ranges(
    proposal: &EntryPayload,
) -> Result<Vec<core::ops::Range<usize>>, Refusal> {
    settlement_ranges_counted(proposal, &mut 0)
}

fn settlement_ranges_counted(
    proposal: &EntryPayload,
    visited: &mut usize,
) -> Result<Vec<core::ops::Range<usize>>, Refusal> {
    let mut starts = Vec::new();
    let mut targets = BTreeSet::new();
    for (ordinal, leg) in proposal.legs.iter().enumerate() {
        *visited += 1;
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

#[allow(clippy::too_many_arguments)]
fn prepare_fx_settlement_inner<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    draft: Option<&crate::draft::DraftSourceAdmission>,
    request: &FxSettlementRequest,
    mut template: EntryPayload,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    audits: Option<&mut SuccessfulHistoryAudits>,
) -> Outcome<PreparedFxSettlement> {
    let authorized = match draft {
        Some(admission) => admission.admit_proposal(db, book, &template)?,
        None => crate::revaluation::authorize(db, book, capability)?,
    };
    if let Err(refusal) = authorized {
        return Ok(Err(refusal));
    }
    if let Err(refusal) = settlement_template(book, capability, &template) {
        return Ok(Err(refusal));
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
        open_item_carrying_with_audits(
            db,
            cx,
            book,
            request.target,
            request.target_ordinal,
            at,
            audits,
        )
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
    if draft.is_some() {
        let commit = crate::rows::bytes(&row, property::FA_DIGEST, "settlement Rate commitment")?
            .try_into()
            .map_err(|_| {
                KernelError::Corrupt("settlement Rate commitment has the wrong length".into())
            })?;
        if let Err(refusal) = crate::redaction::DraftSourceKind::FxRate.admit_record(
            &record,
            book.book_id,
            request.rate_document,
            commit,
        ) {
            return Ok(Err(refusal));
        }
    }
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
        return cx
            .query()
            .with_restriction(|| validate_spot_applications(db, cx, book, proposal, at));
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
    let mut audits = SuccessfulHistoryAudits::default();
    for range in ranges {
        if let Err(refusal) = validate_component(
            db,
            cx,
            book,
            proposal,
            at,
            range.start,
            &proposal.legs[range],
            &mut audits,
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
        if record.book_id != book.book_id || record.oid() != *oid {
            return Ok(Err(invalid(
                "spot settlement Rate belongs to another book or content identity",
            )));
        }
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
        let evidence = match rate.evidence_ref(book.book_id) {
            Ok(evidence) => evidence,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if selected.is_some()
            || record.kind != RATE_DOCUMENT_KIND
            || !row.labels.contains(&label::DOCUMENT)
            || rate.purpose != FxRatePurpose::Settlement
            || rate.as_of != proposal.effective_date
            || rate.base_unit.0 != totals.unit_id
            || rate.rounding != RoundingLaw::HalfEven
            || evidence.document_oid != *oid
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
    let mut audits = SuccessfulHistoryAudits::default();
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
            || application.amount.mantissa <= 0
            || application.amount.mantissa > leg.amount.mantissa
            || !book
                .units
                .get(leg.amount.unit)
                .is_some_and(|unit| matches!(unit.kind, fa_money::UnitKind::Currency { .. }))
            || !targets.insert((application.target.vid, application.ordinal))
        {
            return Ok(Err(invalid(
                "foreign spot applications require positive disjoint target allocations bounded by their complete legs",
            )));
        }
        let item = match open_item_carrying_with_audits(
            db,
            cx,
            book,
            application.target,
            application.ordinal,
            at,
            Some(&mut audits),
        )? {
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
        let mut audits = SuccessfulHistoryAudits::default();
        if has_allocated_basis(original) {
            let releases = match allocated::basis(original) { Ok(value) => value, Err(refusal) => return Ok(Err(refusal)) };
            for release in releases.items {
                let Some(leg) = original.legs.get(usize::from(release.applying_ordinal)) else { return Ok(Err(invalid("allocated undo has no original applying leg"))); };
                let [application] = leg.settles.as_slice() else { return Ok(Err(invalid("allocated undo has no unique recorded application"))); };
                let item = match open_item_carrying_with_audits(db, cx, book, application.target, application.ordinal, at, Some(&mut audits))? { Ok(item) => item, Err(refusal) => return Ok(Err(refusal)) };
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
            let item = match open_item_carrying_with_audits(db, cx, book, target, ordinal, at, Some(&mut audits))? { Ok(item) => item, Err(refusal) => return Ok(Err(refusal)) };
            if item.valuation_open_base.mantissa != 0 || reversal.effective_date < item.latest_effective_date {
                return Ok(Err(invalid("the original item retains allocated valuation or a later item effect; correct its valuation through a new allocated revaluation before reversing the original")));
            }
        }
        Ok(Ok(()))
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_component<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    proposal: &EntryPayload,
    at: CommitSeq,
    applying_ordinal: usize,
    legs: &[fa_model::LegPayload],
    audits: &mut SuccessfulHistoryAudits,
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
        let carrying = match open_item_carrying_with_audits(
            db, cx, book, application.target, application.ordinal, at, Some(audits),
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
#[path = "carrying/audit_tests.rs"]
mod audit_tests;

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
