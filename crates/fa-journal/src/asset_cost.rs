//! Finite source-bound straight-line depreciation and amortization.
//!
//! Immutable terms select one original acquisition debit, full monthly fiscal
//! periods and a separate accumulated-cost account. Charges are cumulative
//! targets less the exact recorded charges and reversals, never caller amounts.
//! The source projection is only a conflict witness: every read reconstructs
//! it and the financial state from immutable controls and monetary entries.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::asset_cost::SCHEMA_CHANGE_ASSET_SCHEDULE;
pub use fa_model::asset_cost::{AssetChargeBasis, AssetCostKind, AssetScheduleSpec};
use fa_model::entry::{ASSET_CHARGE_EXTENSION, ASSET_CHARGE_SCHEMA_MINOR};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ApprovalRef, ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin,
    EntryPayload, EntryRef, Erasable, Id128, LegPayload, PeriodRef, SupersessionKind, Writer,
    domain_digest, entry_mirrors, entry_vid, period_vid,
};
use fa_money::{Amount, Side, UnitKind};
use fa_policy::{Capability, Op, Reach};
use fa_time::{CalendarKind, DateDay, PeriodKind};
use fgdb::{Database, VertexRow, WriteBatch, WriteMismatchPolicy, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::genesis::{BookContext, UnitPolicy};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, PeriodRow, bytes, scalar_bytes};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredAssetSchedule {
    pub entry: EntryRef,
    pub spec: AssetScheduleSpec,
    pub recorded_at: CommitSeq,
}

/// One acquisition schedule as it stood at the register's recorded prefix.
/// All recorded charges and exact reversals contribute, regardless of their
/// effective dates. This is not an effective-as-of financial statement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRegisterRow {
    pub schedule: StoredAssetSchedule,
    pub original_cost: Amount,
    pub source_live: bool,
    pub recognized: Amount,
    pub carrying_amount: Amount,
    pub remaining_depreciable: Amount,
    /// Highest period ever charged, retained even if that charge was reversed.
    pub covered_through: Option<PeriodRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetRegister {
    pub known_at: CommitSeq,
    /// Stable schedule-name order, including fully recognized and reversed assets.
    pub rows: Vec<AssetRegisterRow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetScheduleRecorded {
    pub entry: EntryRef,
    pub spec: AssetScheduleSpec,
    pub recorded_at: CommitSeq,
    pub already_recorded: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetScheduleRequest {
    pub principal: VId,
    pub spec: AssetScheduleSpec,
    pub effective_date: DateDay,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
    pub approvals: Vec<ApprovalRef>,
}

impl AssetScheduleRequest {
    /// Preserve these sealed bytes when collecting approvals for registration.
    pub fn proposal(&self, book: &BookContext) -> Result<EntryPayload, KernelError> {
        asset_schedule_proposal(
            book,
            self.principal,
            &self.spec,
            self.effective_date,
            &self.idempotency_key,
            self.description.clone(),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetChargeRequest {
    pub schedule: EntryRef,
    pub through_period: PeriodRef,
    pub kind: AssetCostKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedAssetCharge {
    basis: AssetChargeBasis,
    schedule: StoredAssetSchedule,
    cost: Amount,
    target: Amount,
    recognized: Amount,
    delta: Amount,
    effective_date: DateDay,
    legs: Vec<LegPayload>,
    high_water: Option<i64>,
}

impl PreparedAssetCharge {
    pub fn basis(&self) -> &AssetChargeBasis {
        &self.basis
    }
    pub fn schedule(&self) -> &StoredAssetSchedule {
        &self.schedule
    }
    pub fn cost(&self) -> Amount {
        self.cost
    }
    pub fn target(&self) -> Amount {
        self.target
    }
    pub fn recognized(&self) -> Amount {
        self.recognized
    }
    pub fn delta(&self) -> Amount {
        self.delta
    }
    pub fn effective_date(&self) -> DateDay {
        self.effective_date
    }
    pub fn is_noop(&self) -> bool {
        self.delta.mantissa == 0
    }
    pub fn legs(&self) -> &[LegPayload] {
        &self.legs
    }

    /// Fill an empty Adjusting intent. Monetary effects and law provenance are
    /// supplied exclusively by the verified preparation, including for retries.
    pub fn proposal(&self, mut template: EntryPayload) -> Result<EntryPayload, Refusal> {
        empty_template(&template)?;
        if self.is_noop() {
            return Err(invalid(
                "the cumulative target is already recognized; no entry is needed",
            ));
        }
        if template.effective_date != self.effective_date
            || template.effective_period.as_ref() != Some(&self.basis.through_period)
        {
            return Err(invalid(
                "the charge must select its through-period and that period's last included day",
            ));
        }
        template.legs = self.legs.clone();
        template.unit_totals = EntryPayload::fold_unit_totals(&template.legs).map_err(invalid)?;
        template
            .set_asset_charge_basis(&self.basis)
            .map_err(invalid)?;
        template.validate().map_err(invalid)?;
        Ok(template)
    }
}

fn invalid(detail: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        format!("asset cost: {detail}"),
        "plan §10.2 / Appendix B (source-bound Depreciate and Amortize)",
        "use an immutable native-currency acquisition schedule, full normal monthly periods and its journal-derived Adjusting charge",
    )
}

fn corrupt(detail: impl core::fmt::Display) -> KernelError {
    KernelError::Corrupt(format!("asset cost: {detail}"))
}

fn changed(detail: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        format!("the asset's acquisition or recognized coverage changed after review: {detail}"),
        "plan §5.10 (source-bound aggregate dependencies)",
        "prepare and review the charge again at the current prefix",
    )
}

pub(crate) fn unsupported_batch() -> Refusal {
    invalid(
        "asset charges and their reversals require their own native plan/commit; compound, draft and case protocols are not implemented for these schedules",
    )
}

pub(crate) fn has_basis(proposal: &EntryPayload) -> bool {
    proposal
        .extensions
        .iter()
        .any(|(tag, _)| *tag == ASSET_CHARGE_EXTENSION)
}

fn empty_template(proposal: &EntryPayload) -> Result<(), Refusal> {
    if proposal.class != EntryClass::ADJUSTING
        || !matches!(proposal.origin, EntryOrigin::Intent { intent_kind: 1, .. })
        || proposal.branch_id != Id128::TRUNK
        || !proposal.legs.is_empty()
        || !proposal.unit_totals.is_empty()
        || proposal.base_totals.is_some()
        || proposal.control.is_some()
        || proposal.pending.is_some()
        || !proposal.supersession.is_empty()
        || !proposal.extensions.is_empty()
    {
        return Err(invalid(
            "prepare an empty Adjusting PostEntry template without lifecycle or other computation effects",
        ));
    }
    Ok(())
}

pub(crate) fn authorize<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id)
        .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
        .and_then(|()| fa_policy::require(capability, Op::Post, "preparing an asset charge"))
    {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    Ok(crate::policy::current_at(db, book, capability)?.map(|_| ()))
}

fn period<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    selected: &PeriodRef,
    at: CommitSeq,
) -> Outcome<PeriodRow> {
    if selected.calendar != book.calendar.id
        || !matches!(book.calendar.kind, CalendarKind::Monthly12 { .. })
    {
        return Ok(Err(invalid(
            "the schedule requires the book's Monthly12 calendar",
        )));
    }
    let Some(definition) = crate::policy::calendar_period(book, &selected.code) else {
        return Ok(Err(invalid("unknown fiscal period")));
    };
    let Some(row) = db.vertex_at(period_vid(&selected.calendar, &selected.code), at)? else {
        return Ok(Err(invalid(
            "the fiscal period was not installed at this prefix",
        )));
    };
    let period = PeriodRow::decode(&row)?;
    if !row.labels.contains(&label::PERIOD)
        || period.calendar_id != selected.calendar
        || period.code != definition.code
        || period.fiscal_year != definition.fiscal_year
        || period.ordinal != definition.ordinal
        || period.start != definition.start
        || period.end != definition.end
    {
        return Err(corrupt("period mirrors differ from the declared calendar"));
    }
    if period.kind != PeriodKind::Normal || definition.kind != PeriodKind::Normal {
        return Ok(Err(invalid(
            "asset charges require normal full monthly periods",
        )));
    }
    Ok(Ok(period))
}

fn period_index(period: &PeriodRow) -> i64 {
    i64::from(period.start.year()) * 12 + i64::from(period.start.month()) - 1
}

pub(crate) fn source_guard_vid(book: Id128, source: VId) -> VId {
    let digest = domain_digest(
        b"fa:vid:asset-source:v1",
        &[&book.0, &source.0.to_le_bytes()],
    );
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(id))
}

fn guard_bytes(book: Id128, source: EntryRef, last: EntryRef) -> Result<Vec<u8>, KernelError> {
    let mut writer = Writer::new();
    writer.bytes(b"fa:asset-source-guard:v1").fixed(&book.0);
    source.encode(&mut writer);
    last.encode(&mut writer);
    Ok(writer.finish().map_err(fa_model::EntryError::from)?)
}

#[derive(Default)]
struct ChargeState {
    recognized: i128,
    high_water: Option<i64>,
    covered_through: Option<PeriodRef>,
    versions: Vec<(CommitSeq, i128, Option<i64>)>,
}

struct History {
    entries: BTreeMap<VId, (Entry, CommitSeq)>,
    schedules: BTreeMap<VId, StoredAssetSchedule>,
    states: BTreeMap<VId, ChargeState>,
    heads: BTreeMap<VId, (EntryRef, EntryRef)>,
    corrected: BTreeMap<VId, Vec<(VId, SupersessionKind)>>,
    applied_sources: BTreeSet<(VId, u16)>,
}

fn declared(row: &VertexRow, book: Id128) -> Result<Option<StoredAssetSchedule>, KernelError> {
    if !row.labels.contains(&label::ENTRY) {
        return Ok(None);
    }
    let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "asset schedule")?)?;
    let Some(ControlPayload::SchemaChange {
        kind: SCHEMA_CHANGE_ASSET_SCHEDULE,
        canonical_bytes,
    }) = &entry.proposal.control
    else {
        return Ok(None);
    };
    if entry.proposal.class != EntryClass::SCHEMA_CONTROL
        || entry.proposal.book_id != book
        || entry.proposal.branch_id != Id128::TRUNK
        || !matches!(
            entry.proposal.origin,
            EntryOrigin::Control {
                control_kind: ControlKind::CHART_INSTALL,
                ..
            }
        )
        || entry_mirrors(&entry)? != row.props
    {
        return Err(corrupt("schedule control or mirrors differ"));
    }
    let spec = AssetScheduleSpec::decode(canonical_bytes).map_err(corrupt)?;
    Ok(Some(StoredAssetSchedule {
        entry: EntryRef {
            vid: row.vid,
            entry_digest: entry.entry_digest,
        },
        spec,
        recorded_at: row.created_at,
    }))
}

fn live_source(history: &History, source: VId) -> Result<bool, Refusal> {
    live_source_at(history, source, None)
}

fn live_source_at(history: &History, source: VId, at: Option<CommitSeq>) -> Result<bool, Refusal> {
    let mut current = source;
    let mut live = true;
    let mut seen = BTreeSet::new();
    while let Some(all) = history.corrected.get(&current) {
        let corrections = all
            .iter()
            .filter(|(vid, _)| {
                at.is_none_or(|at| {
                    history
                        .entries
                        .get(vid)
                        .is_some_and(|(_, recorded)| *recorded <= at)
                })
            })
            .collect::<Vec<_>>();
        if corrections.is_empty() {
            break;
        }
        if corrections.len() != 1
            || corrections[0].1 != SupersessionKind::Reverses
            || !seen.insert(current)
        {
            return Err(invalid(
                "the acquisition has an unsupported correction lineage",
            ));
        }
        current = corrections[0].0;
        live = !live;
    }
    Ok(live)
}

fn source_cost(history: &History, schedule: &StoredAssetSchedule) -> Result<Amount, Refusal> {
    let spec = &schedule.spec;
    let (entry, recorded) = history
        .entries
        .get(&spec.acquisition.vid)
        .ok_or_else(|| invalid("the acquisition is absent"))?;
    let source = &entry.proposal;
    let leg = source
        .legs
        .get(usize::from(spec.acquisition_ordinal))
        .ok_or_else(|| invalid("the acquisition leg ordinal is absent"))?;
    if entry.entry_digest != spec.acquisition.entry_digest
        || *recorded >= schedule.recorded_at
        || source.class != EntryClass::ORIGINAL
        || source.pending.is_some()
        || !source.supersession.is_empty()
        || !source.extensions.is_empty()
        || source.base_totals.is_some()
        || leg.side != Side::Debit
        || leg.amount.mantissa <= 0
        || leg.base_amount.is_some()
        || !leg.dimension_set.is_empty()
        || !leg.settles.is_empty()
        || spec.salvage.unit != leg.amount.unit
        || spec.salvage.mantissa < 0
        || spec.salvage.mantissa > leg.amount.mantissa
        || history
            .applied_sources
            .contains(&(spec.acquisition.vid, spec.acquisition_ordinal))
        || spec.expense_account == spec.accumulated_account
        || leg.account_ref == spec.accumulated_account
        || leg.account_ref == spec.expense_account
    {
        return Err(invalid(
            "the schedule needs one digest-bound positive Original asset debit, native cost, salvage at most cost and distinct destinations",
        ));
    }
    Ok(leg.amount)
}

fn charge_legs(spec: &AssetScheduleSpec, amount: Amount) -> Vec<LegPayload> {
    if amount.mantissa == 0 {
        return Vec::new();
    }
    vec![
        LegPayload::simple(Side::Debit, spec.expense_account, amount),
        LegPayload::simple(Side::Credit, spec.accumulated_account, amount),
    ]
}

fn recognized_ceiling<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    schedule: &StoredAssetSchedule,
    cost: Amount,
    high_water: Option<i64>,
    at: CommitSeq,
) -> Result<i128, KernelError> {
    let Some(high) = high_water else {
        return Ok(0);
    };
    let first =
        period(db, book, &schedule.spec.first_period, at)?.map_err(|r| corrupt(r.message))?;
    let elapsed = u32::try_from(high - period_index(&first) + 1).map_err(corrupt)?;
    Ok(fa_money::straight_line::cumulative(
        cost,
        schedule.spec.salvage,
        elapsed.min(schedule.spec.useful_life_periods),
        schedule.spec.useful_life_periods,
        schedule.spec.rounding_law,
    )
    .map_err(corrupt)?
    .mantissa)
}

/// A single ordered fold validates each original cumulative target, exact
/// reversal and conflict projection. There is no recursive prefix replay.
fn history<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Result<History, KernelError> {
    crate::entry_history::verify_entry_history(db, cx, book, Some(at))?;
    let rows = db.vertices_at(at)?;
    let mut ordered = Vec::new();
    for row in &rows {
        if row.labels.contains(&label::ENTRY) {
            let Some((entry, recorded)) = crate::post::read_entry_at(db, row.vid, at)? else {
                continue;
            };
            ordered.push((recorded, row.vid, entry, declared(row, book.book_id)?));
        }
    }
    ordered.sort_by_key(|(at, vid, _, _)| (*at, *vid));
    let mut result = History {
        entries: BTreeMap::new(),
        schedules: BTreeMap::new(),
        states: BTreeMap::new(),
        heads: BTreeMap::new(),
        corrected: BTreeMap::new(),
        applied_sources: BTreeSet::new(),
    };
    let mut names = BTreeSet::new();
    let mut acquisitions = BTreeSet::new();
    for (recorded, vid, entry, schedule) in ordered {
        cx.query()
            .checkpoint()
            .map_err(WriteTxnError::Interrupted)?;
        let reference = EntryRef {
            vid,
            entry_digest: entry.entry_digest,
        };
        if let Some(schedule) = schedule {
            if !names.insert(schedule.spec.name.clone())
                || !acquisitions.insert((
                    schedule.spec.acquisition.vid,
                    schedule.spec.acquisition_ordinal,
                ))
            {
                return Err(corrupt(
                    "duplicate immutable schedule name or acquisition leg",
                ));
            }
            source_cost(&result, &schedule).map_err(|r| corrupt(r.message))?;
            if !live_source(&result, schedule.spec.acquisition.vid)
                .map_err(|r| corrupt(r.message))?
            {
                return Err(corrupt(
                    "schedule was declared against a reversed acquisition",
                ));
            }
            result.heads.insert(
                schedule.spec.acquisition.vid,
                (schedule.spec.acquisition, reference),
            );
            result.states.insert(
                vid,
                ChargeState {
                    versions: vec![(recorded, 0, None)],
                    ..ChargeState::default()
                },
            );
            result.schedules.insert(vid, schedule);
        }
        if let Some(basis) = entry.proposal.asset_charge_basis().map_err(corrupt)? {
            let schedule = result
                .schedules
                .get(&basis.schedule.vid)
                .ok_or_else(|| corrupt("charge has no earlier schedule"))?;
            if schedule.entry != basis.schedule {
                return Err(corrupt("charge schedule digest differs"));
            }
            let cost = source_cost(&result, schedule).map_err(|r| corrupt(r.message))?;
            let delta = if entry.proposal.class == EntryClass::ADJUSTING {
                if basis.known_at < schedule.recorded_at || basis.known_at >= recorded {
                    return Err(corrupt(
                        "charge observation does not precede publication or its schedule",
                    ));
                }
                if !live_source(&result, schedule.spec.acquisition.vid)
                    .map_err(|r| corrupt(r.message))?
                    || !live_source_at(&result, schedule.spec.acquisition.vid, Some(basis.known_at))
                        .map_err(|r| corrupt(r.message))?
                {
                    return Err(corrupt("charge used a reversed acquisition"));
                }
                let first = period(db, book, &schedule.spec.first_period, basis.known_at)?
                    .map_err(|r| corrupt(r.message))?;
                let selected = period(db, book, &basis.through_period, basis.known_at)?
                    .map_err(|r| corrupt(r.message))?;
                let state = result
                    .states
                    .get_mut(&basis.schedule.vid)
                    .ok_or_else(|| corrupt("missing charge state"))?;
                let observed = state
                    .versions
                    .partition_point(|(at, _, _)| *at <= basis.known_at);
                let Some((_, recognized, high_water)) =
                    observed.checked_sub(1).map(|index| state.versions[index])
                else {
                    return Err(corrupt("charge has no state at its reviewed prefix"));
                };
                if recognized != state.recognized || high_water != state.high_water {
                    return Err(corrupt(
                        "the reviewed asset state changed before its charge was published",
                    ));
                }
                let elapsed = u32::try_from(period_index(&selected) - period_index(&first) + 1)
                    .map_err(corrupt)?;
                if state
                    .high_water
                    .is_some_and(|high| period_index(&selected) < high)
                {
                    return Err(corrupt("charge moved behind its historical coverage"));
                }
                let target = fa_money::straight_line::cumulative(
                    cost,
                    schedule.spec.salvage,
                    elapsed.min(schedule.spec.useful_life_periods),
                    schedule.spec.useful_life_periods,
                    schedule.spec.rounding_law,
                )
                .map_err(corrupt)?;
                let delta = target
                    .mantissa
                    .checked_sub(state.recognized)
                    .ok_or_else(|| corrupt("charge difference overflow"))?;
                if delta <= 0
                    || entry.proposal.legs
                        != charge_legs(&schedule.spec, Amount::new(cost.unit, delta))
                    || entry.proposal.effective_period.as_ref() != Some(&basis.through_period)
                    || entry.proposal.effective_date != selected.end.pred().map_err(corrupt)?
                    || entry.proposal.extensions.len() != 1
                    || entry.proposal.base_totals.is_some()
                    || entry.proposal.pending.is_some()
                    || !entry.proposal.supersession.is_empty()
                {
                    return Err(corrupt(
                        "recorded charge differs from its exact cumulative law",
                    ));
                }
                state.high_water = Some(period_index(&selected));
                state.covered_through = Some(basis.through_period.clone());
                delta
            } else if entry.proposal.class == EntryClass::REVERSAL {
                if entry.proposal.supersession.len() != 1
                    || entry.proposal.supersession[0].kind != SupersessionKind::Reverses
                {
                    return Err(corrupt("charge reversal has invalid lineage"));
                }
                let target = entry.proposal.supersession[0].target;
                let (original, _) = result
                    .entries
                    .get(&target.vid)
                    .ok_or_else(|| corrupt("charge reversal target is absent"))?;
                if original.entry_digest != target.entry_digest
                    || !crate::post::exact_side_swap(&original.proposal, &entry.proposal)
                {
                    return Err(corrupt(
                        "charge reversal is not its target's exact negation",
                    ));
                }
                let leg = entry
                    .proposal
                    .legs
                    .get(1)
                    .ok_or_else(|| corrupt("charge reversal lacks its contra leg"))?;
                if leg.side == Side::Credit {
                    leg.amount.mantissa
                } else {
                    leg.amount
                        .mantissa
                        .checked_neg()
                        .ok_or_else(|| corrupt("charge reversal negation overflow"))?
                }
            } else {
                return Err(corrupt("asset basis on an unsupported entry class"));
            };
            let state = result
                .states
                .get_mut(&basis.schedule.vid)
                .ok_or_else(|| corrupt("missing charge state"))?;
            state.recognized = state
                .recognized
                .checked_add(delta)
                .ok_or_else(|| corrupt("recognized amount overflow"))?;
            if state.recognized < 0
                || state.recognized
                    > cost
                        .checked_sub(schedule.spec.salvage)
                        .map_err(corrupt)?
                        .mantissa
            {
                return Err(corrupt(
                    "recognized amount escaped the cost less salvage bound",
                ));
            }
            if state.recognized
                > recognized_ceiling(db, book, schedule, cost, state.high_water, recorded)?
            {
                return Err(corrupt(
                    "recognized amount exceeds the cumulative target at recorded coverage",
                ));
            }
            state
                .versions
                .push((recorded, state.recognized, state.high_water));
            result.heads.insert(
                schedule.spec.acquisition.vid,
                (schedule.spec.acquisition, reference),
            );
        }
        for link in &entry.proposal.supersession {
            let mut ancestor = link.target.vid;
            let mut seen = BTreeSet::new();
            loop {
                if !seen.insert(ancestor) {
                    return Err(corrupt("cyclic acquisition correction lineage"));
                }
                if result.heads.contains_key(&ancestor) {
                    if entry.proposal.class != EntryClass::REVERSAL
                        || link.kind != SupersessionKind::Reverses
                        || result.schedules.values().any(|schedule| {
                            schedule.spec.acquisition.vid == ancestor
                                && result.states[&schedule.entry.vid].recognized != 0
                        })
                    {
                        return Err(corrupt(
                            "acquisition correction stranded recognized asset cost",
                        ));
                    }
                    break;
                }
                let Some((target, _)) = result.entries.get(&ancestor) else {
                    break;
                };
                if target.proposal.class != EntryClass::REVERSAL
                    || target.proposal.supersession.len() != 1
                    || target.proposal.supersession[0].kind != SupersessionKind::Reverses
                {
                    break;
                }
                ancestor = target.proposal.supersession[0].target.vid;
            }
            result
                .corrected
                .entry(link.target.vid)
                .or_default()
                .push((vid, link.kind));
        }
        for leg in &entry.proposal.legs {
            for application in &leg.settles {
                if acquisitions.contains(&(application.target.vid, application.ordinal))
                    || result
                        .entries
                        .get(&application.target.vid)
                        .is_some_and(|(target, _)| has_basis(&target.proposal))
                {
                    return Err(corrupt(
                        "an application bypassed the asset source/charge lifecycle",
                    ));
                }
                result
                    .applied_sources
                    .insert((application.target.vid, application.ordinal));
            }
        }
        result.entries.insert(vid, (entry, recorded));
    }
    let mut expected = BTreeSet::new();
    let rows_by_id = rows
        .iter()
        .map(|row| (row.vid, row))
        .collect::<BTreeMap<_, _>>();
    for (source, (reference, last)) in &result.heads {
        let vid = source_guard_vid(book.book_id, *source);
        expected.insert(vid);
        let row = rows_by_id
            .get(&vid)
            .ok_or_else(|| corrupt("source guard is absent"))?;
        if row.labels != [label::ASSET_SCHEDULE]
            || bytes(row, property::FA_PAYLOAD, "asset source guard")?
                != guard_bytes(book.book_id, *reference, *last)?
        {
            return Err(corrupt(
                "source guard differs from immutable schedule/effect history",
            ));
        }
    }
    if rows
        .iter()
        .any(|row| row.labels.contains(&label::ASSET_SCHEDULE) && !expected.contains(&row.vid))
    {
        return Err(corrupt("source guard has no immutable schedule"));
    }
    Ok(result)
}

fn accounts<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    schedule: &StoredAssetSchedule,
    history: &History,
    at: CommitSeq,
) -> Outcome<Amount> {
    let cost = match source_cost(history, schedule) {
        Ok(value) => value,
        Err(r) => return Ok(Err(r)),
    };
    let spec =
        crate::genesis::read_book_spec_at(db, at)?.ok_or_else(|| corrupt("book is absent"))?;
    if spec.entities.len() > 1
        || cost.unit != spec.base_unit
        || book
            .units
            .get(cost.unit)
            .is_none_or(|unit| !matches!(unit.kind, UnitKind::Currency { .. }))
    {
        return Ok(Err(invalid(
            "this profile requires native base currency in a single-entity book",
        )));
    }
    let source = &history.entries[&schedule.spec.acquisition.vid].0.proposal;
    let source_account = source.legs[usize::from(schedule.spec.acquisition_ordinal)].account_ref;
    for (vid, kind, normal) in [
        (source_account, AccountType::ASSET.0, 0),
        (schedule.spec.expense_account, AccountType::EXPENSE.0, 0),
        (schedule.spec.accumulated_account, AccountType::ASSET.0, 1),
    ] {
        let Some(row) = db.vertex_at(vid, at)? else {
            return Ok(Err(invalid("a schedule account is absent")));
        };
        let account = AccountRow::decode(&row)?;
        if !row.labels.contains(&label::ACCOUNT)
            || !account.is_leaf
            || account.account_type != kind
            || account.normal_balance != normal
            || !matches!(account.unit_policy, UnitPolicy::AnyUnit)
                && account.unit_policy != UnitPolicy::Single(cost.unit)
        {
            return Ok(Err(invalid(
                "schedule accounts must be native-currency posting leaves: debit Asset, debit Expense and credit Asset contra",
            )));
        }
        if crate::chart::lots::policy_at(db, book, vid, at)?.is_some() {
            return Ok(Err(invalid(
                "asset-cost schedules cannot use quantity-lot governed accounts",
            )));
        }
    }
    let first = match period(db, book, &schedule.spec.first_period, at)? {
        Ok(p) => p,
        Err(r) => return Ok(Err(r)),
    };
    if source.effective_date > first.end.pred().map_err(corrupt)? {
        return Ok(Err(invalid(
            "the first depreciation period cannot precede acquisition",
        )));
    }
    Ok(Ok(cost))
}

pub fn asset_schedule_proposal(
    book: &BookContext,
    principal: VId,
    spec: &AssetScheduleSpec,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Result<EntryPayload, KernelError> {
    let mut proposal = crate::chart::schema_control_proposal(
        book,
        SCHEMA_CHANGE_ASSET_SCHEDULE,
        spec.encode().map_err(fa_model::EntryError::from)?,
        principal,
        effective_date,
        idempotency_key,
        description,
    );
    proposal.schema_minor = ASSET_CHARGE_SCHEMA_MINOR;
    proposal.canonical_bytes()?;
    Ok(proposal)
}

fn stage_guard<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    batch: &mut WriteBatch,
    book: Id128,
    source: EntryRef,
    last: EntryRef,
) -> Result<(), KernelError> {
    let vid = source_guard_vid(book, source.vid);
    let old = txn.vertex_property(db, vid, property::FA_PAYLOAD)?;
    let next = scalar_bytes("asset source guard", guard_bytes(book, source, last)?)?;
    if old.is_some() {
        batch.compare_and_set_vertex_property(
            vid,
            property::FA_PAYLOAD,
            old,
            next,
            WriteMismatchPolicy::AbortWrite,
        );
    } else {
        batch.create_vertex(
            vid,
            vec![label::ASSET_SCHEDULE],
            vec![(property::FA_PAYLOAD, next)],
        );
    }
    Ok(())
}

pub async fn create_asset_schedule<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    cap: &Capability,
    request: AssetScheduleRequest,
) -> Outcome<AssetScheduleRecorded> {
    let proposal = asset_schedule_proposal(
        book,
        request.principal,
        &request.spec,
        request.effective_date,
        &request.idempotency_key,
        request.description,
    )?;
    create_asset_schedule_proposal(db, cx, book, cap, proposal, request.approvals).await
}

pub async fn create_asset_schedule_proposal<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    cap: &Capability,
    proposal: EntryPayload,
    approvals: Vec<ApprovalRef>,
) -> Outcome<AssetScheduleRecorded> {
    if let Err(denial) = fa_policy::admit_read(cap, proposal.principal_ref, book.book_id)
        .and_then(|()| fa_policy::reach(cap, &Reach::whole_book(true), None))
    {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    if let Err(r) = crate::policy::current_at(db, book, cap)? {
        return Ok(Err(r));
    }
    if let Some(r) = crate::chart::admit_schema_change(db, book, proposal.principal_ref, cap)? {
        return Ok(Err(r));
    }
    let Some(ControlPayload::SchemaChange {
        kind: SCHEMA_CHANGE_ASSET_SCHEDULE,
        canonical_bytes,
    }) = &proposal.control
    else {
        return Ok(Err(invalid(
            "the reviewed proposal is not an asset schedule",
        )));
    };
    let spec = match AssetScheduleSpec::decode(canonical_bytes) {
        Ok(s) => s,
        Err(e) => return Ok(Err(invalid(e))),
    };
    let expected = asset_schedule_proposal(
        book,
        proposal.principal_ref,
        &spec,
        proposal.effective_date,
        &proposal.idempotency_key,
        proposal.description.clone(),
    )?;
    if proposal != expected {
        return Ok(Err(invalid("the reviewed schedule has altered structure")));
    }
    if let Err(r) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(r));
    }
    let mut txn = db.begin(&cx.txn())?;
    if let Err(r) = crate::policy::capability_witness(&txn, db, book, cap)? {
        txn.abort();
        return Ok(Err(r));
    }
    let epoch = crate::policy::epoch_witness(&txn, db)?;
    let digest = proposal.proposal_digest()?;
    let vid = entry_vid(
        book.book_id,
        &proposal.principal_ref.0.to_le_bytes(),
        &proposal.idempotency_key,
    );
    if let Some(row) = txn.vertex(db, vid)? {
        txn.abort();
        let prior = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "asset schedule retry")?)?;
        let same = prior.proposal_digest == digest
            || matches!(
            (prior.proposal.semantic_digest(&book.seal_key), proposal.semantic_digest(&book.seal_key)),
            (Ok(a), Ok(b)) if a == b);
        let stored = declared(&row, book.book_id)?;
        if !same || prior.approvals != approvals || stored.is_none() {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                "asset schedule key already names different terms or approvals",
                "FA-INV-09",
                "retry the retained schedule proposal and approvals or choose a new key",
            )));
        }
        let stored = stored.ok_or_else(|| corrupt("recognized schedule disappeared"))?;
        return Ok(Ok(AssetScheduleRecorded {
            entry: stored.entry,
            spec: stored.spec,
            recorded_at: stored.recorded_at,
            already_recorded: true,
        }));
    }
    let history = history(db, cx, book, txn.basis())?;
    if history.schedules.values().any(|stored| {
        stored.spec.name == spec.name
            || (stored.spec.acquisition.vid == spec.acquisition.vid
                && stored.spec.acquisition_ordinal == spec.acquisition_ordinal)
    }) {
        txn.abort();
        return Ok(Err(invalid(
            "schedule names and acquisition legs have immutable unique terms",
        )));
    }
    let next = CommitSeq(
        txn.basis()
            .0
            .checked_add(1)
            .ok_or_else(|| corrupt("sequence overflow"))?,
    );
    let provisional = StoredAssetSchedule {
        entry: EntryRef {
            vid,
            entry_digest: [0; 32],
        },
        spec: spec.clone(),
        recorded_at: next,
    };
    if let Err(r) = accounts(db, book, &provisional, &history, txn.basis())? {
        txn.abort();
        return Ok(Err(r));
    }
    if !match live_source(&history, spec.acquisition.vid) {
        Ok(v) => v,
        Err(r) => {
            txn.abort();
            return Ok(Err(r));
        }
    } {
        txn.abort();
        return Ok(Err(invalid(
            "a reversed acquisition cannot start an asset schedule",
        )));
    }
    let key = fa_policy::sod::control_key("SchemaControl", None, "ChartInstall");
    if let Err(r) = crate::policy::authorize_approvals(
        &txn,
        db,
        book,
        &approvals,
        &digest,
        epoch,
        &key,
        0,
        fa_policy::Party::for_capability(proposal.principal_ref, cap),
    )? {
        txn.abort();
        return Ok(Err(r));
    }
    let entry = proposal.seal(approvals, None)?;
    let entry_ref = EntryRef {
        vid,
        entry_digest: entry.entry_digest,
    };
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(vid, vec![label::ENTRY], entry_mirrors(&entry)?);
    stage_guard(
        &txn,
        db,
        &mut batch,
        book.book_id,
        spec.acquisition,
        entry_ref,
    )?;
    txn.write(db, batch)?;
    if let Err(r) = crate::post::check_aggregate_basis(txn.basis(), db.frontier()?) {
        txn.abort();
        return Ok(Err(r));
    }
    if let Err(d) = fa_policy::current(cap, db.frontier()?) {
        txn.abort();
        return Ok(Err(crate::policy::refusal(&d)));
    }
    match txn.commit(db, &cx.commit()).await {
        Ok(recorded_at) => Ok(Ok(AssetScheduleRecorded {
            entry: entry_ref,
            spec,
            recorded_at,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(Refusal::new(
                code::CONFLICT,
                exit::CONFLICT,
                detail,
                "FG-LAW-FCW-01",
                "review the schedule against current acquisition history",
            )))
        }
        Err(e) => Err(e.into()),
    }
}

fn authorized_history<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    cap: &Capability,
    at: CommitSeq,
) -> Outcome<History> {
    if let Err(r) = crate::policy::admit_reads(db, book, cap.holder(), cap)? {
        return Ok(Err(r));
    }
    let mut reach = Reach::whole_book(true);
    reach.observes = fa_policy::Observes::At(at);
    if let Err(denial) = fa_policy::reach(cap, &reach, None) {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    if at > db.frontier()? {
        return Ok(Err(invalid("the selected prefix is in the future")));
    }
    Ok(Ok(history(db, cx, book, at)?))
}

pub fn asset_schedules<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    cap: &Capability,
    at: CommitSeq,
) -> Outcome<Vec<StoredAssetSchedule>> {
    let history = match authorized_history(db, cx, book, cap, at)? {
        Ok(history) => history,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut schedules = history.schedules.into_values().collect::<Vec<_>>();
    schedules.sort_by(|a, b| a.spec.name.cmp(&b.spec.name));
    Ok(Ok(schedules))
}

/// Reconstruct the asset register once at an explicit recorded prefix under
/// current whole-book Read authority. Posting authority is neither requested
/// nor inferred. Terms, cost and all recognition effects come from that same
/// immutable prefix; later reversals cannot change a historical row.
pub fn asset_register<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    cap: &Capability,
    at: CommitSeq,
) -> Outcome<AssetRegister> {
    let history = match authorized_history(db, cx, book, cap, at)? {
        Ok(history) => history,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut rows = Vec::with_capacity(history.schedules.len());
    for schedule in history.schedules.values() {
        cx.query()
            .checkpoint()
            .map_err(WriteTxnError::Interrupted)?;
        let original_cost =
            source_cost(&history, schedule).map_err(|refusal| corrupt(refusal.message))?;
        let source_live = live_source(&history, schedule.spec.acquisition.vid)
            .map_err(|refusal| corrupt(refusal.message))?;
        let state = history
            .states
            .get(&schedule.entry.vid)
            .ok_or_else(|| corrupt("asset register schedule has no recognition state"))?;
        let recognized = Amount::new(original_cost.unit, state.recognized);
        let (carrying_amount, remaining_depreciable) = if source_live {
            let carrying = original_cost.checked_sub(recognized).map_err(corrupt)?;
            let remaining = original_cost
                .checked_sub(schedule.spec.salvage)
                .and_then(|basis| basis.checked_sub(recognized))
                .map_err(corrupt)?;
            if carrying.mantissa < schedule.spec.salvage.mantissa || remaining.mantissa < 0 {
                return Err(corrupt(
                    "asset register recognition exceeds depreciable cost",
                ));
            }
            (carrying, remaining)
        } else {
            if recognized.mantissa != 0 {
                return Err(corrupt(
                    "a reversed acquisition retains recognized asset cost",
                ));
            }
            (
                Amount::new(original_cost.unit, 0),
                Amount::new(original_cost.unit, 0),
            )
        };
        rows.push(AssetRegisterRow {
            schedule: schedule.clone(),
            original_cost,
            source_live,
            recognized,
            carrying_amount,
            remaining_depreciable,
            covered_through: state.covered_through.clone(),
        });
    }
    rows.sort_by(|a, b| a.schedule.spec.name.cmp(&b.schedule.spec.name));
    Ok(Ok(AssetRegister { known_at: at, rows }))
}

fn derive<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    basis: AssetChargeBasis,
) -> Outcome<PreparedAssetCharge> {
    let history = history(db, cx, book, basis.known_at)?;
    let Some(schedule) = history.schedules.get(&basis.schedule.vid).cloned() else {
        return Ok(Err(invalid(
            "the schedule was absent at the selected prefix",
        )));
    };
    if schedule.entry != basis.schedule {
        return Ok(Err(invalid("schedule digest differs")));
    }
    let cost = match accounts(db, book, &schedule, &history, basis.known_at)? {
        Ok(value) => value,
        Err(r) => return Ok(Err(r)),
    };
    if !match live_source(&history, schedule.spec.acquisition.vid) {
        Ok(v) => v,
        Err(r) => return Ok(Err(r)),
    } {
        return Ok(Err(invalid(
            "the acquisition is reversed; its schedule cannot charge",
        )));
    }
    let first = match period(db, book, &schedule.spec.first_period, basis.known_at)? {
        Ok(p) => p,
        Err(r) => return Ok(Err(r)),
    };
    let selected = match period(db, book, &basis.through_period, basis.known_at)? {
        Ok(p) => p,
        Err(r) => return Ok(Err(r)),
    };
    let elapsed = match u32::try_from(period_index(&selected) - period_index(&first) + 1) {
        Ok(v) => v,
        Err(e) => return Ok(Err(invalid(e))),
    };
    if elapsed == 0 {
        return Ok(Err(invalid(
            "the through-period precedes the first scheduled period",
        )));
    }
    let state = &history.states[&schedule.entry.vid];
    if state
        .high_water
        .is_some_and(|high| period_index(&selected) < high)
    {
        return Ok(Err(invalid(
            "the through-period precedes previously recognized coverage, including reversed charges",
        )));
    }
    let target = match fa_money::straight_line::cumulative(
        cost,
        schedule.spec.salvage,
        elapsed.min(schedule.spec.useful_life_periods),
        schedule.spec.useful_life_periods,
        schedule.spec.rounding_law,
    ) {
        Ok(v) => v,
        Err(e) => return Ok(Err(invalid(e))),
    };
    let recognized = Amount::new(cost.unit, state.recognized);
    let delta = target
        .checked_sub(recognized)
        .map_err(|e| corrupt(e.to_string()))?;
    if delta.mantissa < 0 {
        return Ok(Err(invalid(
            "the cumulative target is below the already recognized cost",
        )));
    }
    let legs = charge_legs(&schedule.spec, delta);
    Ok(Ok(PreparedAssetCharge {
        basis,
        schedule,
        cost,
        target,
        recognized,
        delta,
        effective_date: selected.end.pred().map_err(corrupt)?,
        legs,
        high_water: state.high_water,
    }))
}

pub fn prepare_asset_charge<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    cap: &Capability,
    request: &AssetChargeRequest,
    template: &EntryPayload,
) -> Outcome<PreparedAssetCharge> {
    if let Err(r) = authorize(db, book, cap)? {
        return Ok(Err(r));
    }
    if let Err(r) = empty_template(template) {
        return Ok(Err(r));
    }
    if template.book_id != book.book_id || template.principal_ref != cap.holder() {
        return Ok(Err(invalid(
            "the template must belong to the acting principal and this book",
        )));
    }
    let head = db.frontier()?;
    let vid = entry_vid(
        book.book_id,
        &template.principal_ref.0.to_le_bytes(),
        &template.idempotency_key,
    );
    let at = match crate::post::read_entry_at(db, vid, head)? {
        Some((entry, _)) => {
            let prior = entry.proposal.asset_charge_basis().map_err(corrupt)?;
            let Some(prior) = prior.filter(|prior| {
                entry.proposal.class == EntryClass::ADJUSTING
                    && prior.schedule == request.schedule
                    && prior.through_period == request.through_period
            }) else {
                return Ok(Err(Refusal::new(
                    code::IDEMPOTENCY_CONFLICT,
                    exit::CONFLICT,
                    "asset charge key already names another intent or period",
                    "FA-INV-09",
                    "retry the original schedule and period or use a new key",
                )));
            };
            prior.known_at
        }
        None => head,
    };
    let prepared = match derive(
        db,
        cx,
        book,
        AssetChargeBasis {
            schedule: request.schedule,
            through_period: request.through_period.clone(),
            known_at: at,
        },
    )? {
        Ok(p) => p,
        Err(r) => return Ok(Err(r)),
    };
    if prepared.schedule.spec.kind != request.kind {
        return Ok(Err(invalid(
            "Depreciate/Amortize must match the schedule's declared kind",
        )));
    }
    if template.effective_date != prepared.effective_date
        || template.effective_period.as_ref() != Some(&request.through_period)
    {
        return Ok(Err(invalid(
            "the template must name the charge period and its last included day",
        )));
    }
    Ok(Ok(prepared))
}

/// Fresh native admission, after ordinary exact outcome recognition. Source
/// corrections point-witness even an absent schedule projection, closing the
/// race in which a schedule is registered after a reversal was prepared.
pub(crate) fn validate_post<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    proposal: &EntryPayload,
    capability: &Capability,
) -> Outcome<()> {
    for leg in &proposal.legs {
        for application in &leg.settles {
            if let Some(row) = txn.vertex(db, application.target.vid)?
                && row.labels.contains(&label::ENTRY)
            {
                let target = Entry::decode(&bytes(
                    &row,
                    property::FA_PAYLOAD,
                    "asset application target",
                )?)?;
                if has_basis(&target.proposal) {
                    return Ok(Err(invalid(
                        "scheduled asset charges cannot be application targets; use their exact reversal lifecycle",
                    )));
                }
            }
            if txn
                .vertex(db, source_guard_vid(book.book_id, application.target.vid))?
                .is_some()
            {
                if let Err(r) = authorize(db, book, capability)? {
                    return Ok(Err(r));
                }
                let history = history(db, cx, book, txn.basis())?;
                if history.schedules.values().any(|schedule| {
                    schedule.spec.acquisition.vid == application.target.vid
                        && schedule.spec.acquisition_ordinal == application.ordinal
                }) {
                    return Ok(Err(invalid(
                        "applications against a scheduled acquisition require an asset disposal lifecycle; this profile supports exact source reversal only",
                    )));
                }
            }
        }
    }
    if let Some(basis) = proposal.asset_charge_basis().map_err(corrupt)? {
        if proposal.class == EntryClass::REVERSAL {
            // Normal reversal admission independently enforces the exact
            // side-swap and identical asset marker, including nested reversals.
            let history = history(db, cx, book, txn.basis())?;
            let Some(schedule) = history.schedules.get(&basis.schedule.vid) else {
                return Ok(Err(invalid("charge reversal has no schedule")));
            };
            if schedule.entry != basis.schedule
                || proposal.supersession.len() != 1
                || proposal.supersession[0].kind != SupersessionKind::Reverses
            {
                return Ok(Err(invalid(
                    "charge reversal must retain its schedule and exact target",
                )));
            }
            let target = proposal.supersession[0].target;
            let Some((original, _)) = history.entries.get(&target.vid) else {
                return Ok(Err(invalid("charge reversal target is absent")));
            };
            if original.entry_digest != target.entry_digest
                || !crate::post::exact_side_swap(&original.proposal, proposal)
            {
                return Ok(Err(invalid(
                    "asset charge reversals must be exact recorded side swaps",
                )));
            }
            let cost = match source_cost(&history, schedule) {
                Ok(v) => v,
                Err(r) => return Ok(Err(r)),
            };
            let leg = proposal
                .legs
                .get(1)
                .ok_or_else(|| corrupt("charge reversal lacks contra leg"))?;
            let delta = if leg.side == Side::Credit {
                leg.amount.mantissa
            } else {
                leg.amount
                    .mantissa
                    .checked_neg()
                    .ok_or_else(|| corrupt("charge reversal negation overflow"))?
            };
            let recognized = history.states[&schedule.entry.vid]
                .recognized
                .checked_add(delta)
                .ok_or_else(|| corrupt("charge reversal amount overflow"))?;
            if recognized < 0
                || recognized
                    > cost
                        .checked_sub(schedule.spec.salvage)
                        .map_err(corrupt)?
                        .mantissa
            {
                return Ok(Err(invalid(
                    "reinstating a reversed charge would escape cost less salvage; reverse subsequent recognition first",
                )));
            }
            let ceiling = recognized_ceiling(
                db,
                book,
                schedule,
                cost,
                history.states[&schedule.entry.vid].high_water,
                txn.basis(),
            )?;
            if recognized > ceiling {
                return Ok(Err(invalid(
                    "reinstating this charge would duplicate cost already caught up through the covered period; reverse the later recognition first",
                )));
            }
            if delta > 0
                && !match live_source(&history, schedule.spec.acquisition.vid) {
                    Ok(value) => value,
                    Err(r) => return Ok(Err(r)),
                }
            {
                return Ok(Err(invalid(
                    "a charge cannot be reinstated against a reversed acquisition",
                )));
            }
        } else {
            if basis.known_at > txn.basis() {
                return Ok(Err(invalid("the charge observation is in the future")));
            }
            let expected = match derive(db, cx, book, basis.clone())? {
                Ok(p) => p,
                Err(r) => return Ok(Err(r)),
            };
            if basis.known_at != txn.basis() {
                let current = match derive(
                    db,
                    cx,
                    book,
                    AssetChargeBasis {
                        known_at: txn.basis(),
                        ..basis
                    },
                )? {
                    Ok(p) => p,
                    Err(r) => return Ok(Err(changed(r.message))),
                };
                if current.schedule != expected.schedule
                    || current.cost != expected.cost
                    || current.target != expected.target
                    || current.recognized != expected.recognized
                    || current.delta != expected.delta
                    || current.effective_date != expected.effective_date
                    || current.legs != expected.legs
                    || current.high_water != expected.high_water
                {
                    return Ok(Err(changed(
                        "the independently recomputed financial state differs",
                    )));
                }
            }
            if expected.is_noop()
                || proposal.class != EntryClass::ADJUSTING
                || proposal.legs != expected.legs
                || proposal.effective_date != expected.effective_date
                || proposal.effective_period.as_ref() != Some(&expected.basis.through_period)
                || proposal.base_totals.is_some()
                || proposal.pending.is_some()
                || proposal.control.is_some()
                || proposal.extensions.len() != 1
                || !proposal.supersession.is_empty()
                || !matches!(proposal.origin, EntryOrigin::Intent { intent_kind: 1, .. })
            {
                return Ok(Err(invalid(
                    "the proposed charge differs from its journal-derived cumulative schedule",
                )));
            }
        }
    }
    for link in &proposal.supersession {
        if let Some(row) = txn.vertex(db, link.target.vid)?
            && row.labels.contains(&label::ENTRY)
        {
            let target = Entry::decode(&bytes(
                &row,
                property::FA_PAYLOAD,
                "asset correction target",
            )?)?;
            if has_basis(&target.proposal) && proposal.class != EntryClass::REVERSAL {
                return Ok(Err(invalid(
                    "scheduled asset charges support exact reversal only; estimates and replacement corrections require a separate lifecycle protocol",
                )));
            }
        }
        let mut source = link.target.vid;
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert(source) {
                return Err(corrupt("cyclic acquisition correction ancestry"));
            }
            // Witness absence at every ancestor as well as a present guard:
            // registration on an ungoverned root must conflict with this plan.
            if txn
                .vertex(db, source_guard_vid(book.book_id, source))?
                .is_some()
            {
                break;
            }
            let Some(row) = txn.vertex(db, source)? else {
                break;
            };
            if !row.labels.contains(&label::ENTRY) {
                break;
            }
            let target = Entry::decode(&bytes(
                &row,
                property::FA_PAYLOAD,
                "asset correction ancestor",
            )?)?;
            if target.proposal.class != EntryClass::REVERSAL
                || target.proposal.supersession.len() != 1
                || target.proposal.supersession[0].kind != SupersessionKind::Reverses
            {
                break;
            }
            source = target.proposal.supersession[0].target.vid;
        }
        if txn
            .vertex(db, source_guard_vid(book.book_id, source))?
            .is_none()
        {
            continue;
        }
        if let Err(r) = authorize(db, book, capability)? {
            return Ok(Err(r));
        }
        let history = history(db, cx, book, txn.basis())?;
        let governed = history
            .schedules
            .values()
            .filter(|schedule| schedule.spec.acquisition.vid == source)
            .collect::<Vec<_>>();
        if governed.is_empty() {
            return Err(corrupt("source guard has no schedule"));
        }
        if proposal.class != EntryClass::REVERSAL || link.kind != SupersessionKind::Reverses {
            return Ok(Err(invalid(
                "a scheduled acquisition supports exact reversal only; replacement, reclassification and estimate revision need an asset lifecycle protocol",
            )));
        }
        if governed
            .iter()
            .any(|schedule| history.states[&schedule.entry.vid].recognized != 0)
        {
            return Ok(Err(invalid(
                "reverse the acquisition's recognized asset charges before reversing its source",
            )));
        }
    }
    Ok(Ok(()))
}

/// Add only a rebuildable conflict witness to the ordinary posting batch.
pub(crate) fn stage_post<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    entry: &Entry,
    vid: VId,
    batch: &mut WriteBatch,
    tracker: &mut crate::batch::TemplateByteTracker,
) -> Result<(), KernelError> {
    let Some(basis) = entry.proposal.asset_charge_basis().map_err(corrupt)? else {
        return Ok(());
    };
    let row = txn
        .vertex(db, basis.schedule.vid)?
        .ok_or_else(|| corrupt("charge schedule disappeared"))?;
    let schedule = declared(&row, book.book_id)?
        .ok_or_else(|| corrupt("charge does not name a schedule control"))?;
    let guard = source_guard_vid(book.book_id, schedule.spec.acquisition.vid);
    let old = txn.vertex_property(db, guard, property::FA_PAYLOAD)?;
    let next = scalar_bytes(
        "asset source guard",
        guard_bytes(
            book.book_id,
            schedule.spec.acquisition,
            EntryRef {
                vid,
                entry_digest: entry.entry_digest,
            },
        )?,
    )?;
    tracker.set_vertex_property(
        relation::HAS_LEG,
        guard,
        property::FA_PAYLOAD,
        old,
        Some(next),
    );
    stage_guard(
        txn,
        db,
        batch,
        book.book_id,
        schedule.spec.acquisition,
        EntryRef {
            vid,
            entry_digest: entry.entry_digest,
        },
    )
}

/// Rebuild all immutable schedules, cumulative charges and source witnesses.
pub fn verify_asset_schedules<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
) -> Result<crate::schedule::ScheduleVerification, KernelError> {
    // Legacy books with no asset-cost objects need no additional historical
    // window merely to retain their existing schedule verification contract.
    let mut present = false;
    for row in db.vertices()? {
        if row.labels.contains(&label::ASSET_SCHEDULE) {
            present = true;
            break;
        }
        if row.labels.contains(&label::ENTRY) {
            let entry = Entry::decode(&bytes(
                &row,
                property::FA_PAYLOAD,
                "asset verification entry",
            )?)?;
            if has_basis(&entry.proposal)
                || matches!(
                    entry.proposal.control,
                    Some(ControlPayload::SchemaChange {
                        kind: SCHEMA_CHANGE_ASSET_SCHEDULE,
                        ..
                    })
                )
            {
                present = true;
                break;
            }
        }
    }
    if !present {
        return Ok(crate::schedule::ScheduleVerification::default());
    }
    let history = history(db, cx, book, db.frontier()?)?;
    Ok(crate::schedule::ScheduleVerification {
        schedules_checked: history.schedules.len(),
        executed: history
            .entries
            .values()
            .filter(|(entry, _)| {
                entry.proposal.class == EntryClass::ADJUSTING && has_basis(&entry.proposal)
            })
            .count(),
        cancelled: 0,
        drift: Vec::new(),
    })
}
