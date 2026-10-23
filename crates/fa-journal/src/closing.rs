//! Mechanical fiscal-year close and incremental reclose (plan §7.5).
//!
//! The intrinsic YearEndClose computation closes Revenue/Expense leaves
//! to their journaled Equity destinations. Version 1 retains its native
//! base-currency format; version 2 transfers the exact native and functional
//! carrying amounts of committed source valuations. Only the existing
//! legal-entity balancing dimension is supported. This is not the larger
//! CloseRun task DAG and does not execute generic Canon rules.
//!
//! Every public Closing path must reproduce extension 12 from both its
//! saved observation and the current preparation snapshot. The original
//! prepared posting retains a complete-frontier guard until publication;
//! newly appended activity cannot escape an aggregate dependency check.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::closing::{YEAR_END_CLOSE_CARRYING_VERSION, YEAR_END_CLOSE_VERSION};
use fa_model::entry::{EXTENSIONS_MINOR, YEAR_END_CLOSE_EXTENSION};
use fa_model::symbols::{label, property};
use fa_model::{
    AccountType, BaseTotals, Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef, Id128,
    LEGAL_ENTITY_DIMENSION, LegPayload, Writer, YearEndCloseBasis, entity_value_vid, period_vid,
};
use fa_money::{Amount, Side, UnitId};
use fa_policy::{Capability, Op, Reach};
use fa_time::{DateDay, PeriodKind, PeriodState};
use fgdb::{Database, WriteTxn};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::chart::{ChartSnapshot, closing_routes_at};
use crate::genesis::{BookContext, BookSpec, UnitPolicy};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, PeriodRow, bytes};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YearEndCloseRequest {
    pub fiscal_year: i32,
    pub closing_period: String,
}

/// A remaining debit-minus-credit balance, before the proposed close.
/// Zero balances are retained so inspection does not hide reviewed accounts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosingResidual {
    pub account: VId,
    pub account_code: String,
    pub closes_to: VId,
    pub unit: UnitId,
    pub entity: Option<VId>,
    pub net: i128,
    /// Retained functional debit-minus-credit amount, in the book's base unit.
    pub base_net: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosingRecord {
    pub entry_ref: EntryRef,
    pub recorded_at: CommitSeq,
}

/// A read-only computation. A caller seals its own PostEntry description
/// before producing a proposal; the ordinary plan/approval path publishes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedYearEndClose {
    request: YearEndCloseRequest,
    basis: YearEndCloseBasis,
    unit: UnitId,
    residuals: Vec<ClosingResidual>,
    legs: Vec<LegPayload>,
    base_totals: Option<BaseTotals>,
    latest_close: Option<ClosingRecord>,
}

impl PreparedYearEndClose {
    pub fn request(&self) -> &YearEndCloseRequest {
        &self.request
    }

    pub fn basis(&self) -> &YearEndCloseBasis {
        &self.basis
    }

    pub fn closing_date(&self) -> DateDay {
        self.basis.closing_date
    }

    pub fn known_at(&self) -> CommitSeq {
        self.basis.observed_at
    }

    pub fn source_digest(&self) -> [u8; 32] {
        self.basis.source_digest
    }

    pub fn routes_digest(&self) -> [u8; 32] {
        self.basis.routes_digest
    }

    pub fn routes_entry(&self) -> VId {
        self.basis.routes_entry
    }

    pub fn unit(&self) -> UnitId {
        self.unit
    }

    pub fn residuals(&self) -> &[ClosingResidual] {
        &self.residuals
    }

    pub fn legs(&self) -> &[LegPayload] {
        &self.legs
    }

    pub fn latest_close(&self) -> Option<&ClosingRecord> {
        self.latest_close.as_ref()
    }

    pub fn is_noop(&self) -> bool {
        self.legs.is_empty()
    }

    /// Fill only the computed fields of an empty Closing PostEntry template.
    /// A zero-delta close is an explicit no-op, never an empty monetary entry.
    pub fn proposal(&self, mut template: EntryPayload) -> Result<EntryPayload, Refusal> {
        if template.class != EntryClass::CLOSING
            || !matches!(&template.origin, EntryOrigin::Intent { intent_kind: 1, .. })
            || !template.legs.is_empty()
            || !template.unit_totals.is_empty()
            || !template.extensions.is_empty()
            || template.control.is_some()
            || template.base_totals.is_some()
            || template.pending.is_some()
            || !template.supersession.is_empty()
        {
            return Err(unsupported(
                "use an empty Closing PostEntry template without other computation or lifecycle effects",
            ));
        }
        if self.is_noop() {
            return Err(unsupported(
                "the fiscal year has no nominal residual; no Closing entry is needed",
            ));
        }
        if template.effective_date != self.closing_date()
            || template.effective_period.as_ref().map(|p| p.code.as_str())
                != Some(self.request.closing_period.as_str())
        {
            return Err(unsupported(
                "the Closing template must name the selected fiscal-year-end date and Closing period",
            ));
        }
        template.schema_minor = EXTENSIONS_MINOR;
        template.legs = self.legs.clone();
        template.unit_totals =
            EntryPayload::fold_unit_totals(&template.legs).map_err(unsupported)?;
        template.base_totals = self.base_totals.clone();
        template.extensions = vec![(
            YEAR_END_CLOSE_EXTENSION,
            self.basis.canonical_bytes().map_err(unsupported)?,
        )];
        template.validate().map_err(unsupported)?;
        Ok(template)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YearEndCloseVerification {
    pub fiscal_year: i32,
    pub base_unit: UnitId,
    pub known_at: CommitSeq,
    pub latest_close: Option<ClosingRecord>,
    /// Evaluated at the latest Closing entry's own committed snapshot.
    pub nominal_zero_at_close: Option<bool>,
    /// Evaluated at the requested snapshot, including activity after that close.
    pub residuals: Vec<ClosingResidual>,
    pub needs_reclose: bool,
}

impl YearEndCloseVerification {
    pub fn is_green(&self) -> bool {
        self.nominal_zero_at_close == Some(true)
    }
}

fn unsupported(message: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::CLASS_NOT_IMPLEMENTED,
        exit::REFUSAL,
        format!("year-end close: {message}"),
        "plan §5.2 / §7.5; FA-INV-03.nominal-zero; intrinsic YearEndClose",
        "use reviewed Revenue/Expense-to-Equity routes accepting the source currencies, retained functional valuations and supported legal-entity dimensions; prepare and review fa close year-end --fiscal-year <year> --period FY<year>-CLOSE --key <new-key> --review-only (plan §7.5 / fa-4o0)",
    )
}

fn changed(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        message,
        "plan §5.10 / §7.5 / §10.4 (the complete fiscal-year aggregate and reviewed closing routes)",
        "prepare and review the complete fiscal-year close again; an old review never silently acquires new activity or routes",
    )
}

/// Close preparation observes the entire nominal population. Scope cannot
/// be widened implicitly by asking the kernel to calculate missing legs.
pub fn authorize<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    closing: bool,
) -> Outcome<()> {
    let mut admission = fa_policy::admit_read(capability, capability.holder(), book.book_id)
        .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(closing), None));
    if closing {
        admission = admission
            .and_then(|()| fa_policy::require(capability, Op::Post, "posting a year-end close"))
            .and_then(|()| fa_policy::require(capability, Op::Close, "closing a fiscal year"));
    }
    if let Err(denial) = admission {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    Ok(crate::policy::current_at(db, book, capability)?.map(|_| ()))
}

pub fn prepare_year_end_close<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: &YearEndCloseRequest,
) -> Outcome<PreparedYearEndClose> {
    let query = cx.query();
    query
        .checkpoint()
        .map_err(fgdb::WriteTxnError::Interrupted)?;
    query.with_restriction(|| {
        if let Err(refusal) = authorize(db, book, capability, true)? {
            return Ok(Err(refusal));
        }
        let at = db.frontier()?;
        if let Err(refusal) = validate_sources(db, cx, book, at)? {
            return Ok(Err(refusal));
        }
        observe(db, cx, book, request, at, true, None)
    })
}

fn selected_period<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    request: &YearEndCloseRequest,
    at: CommitSeq,
    posting: bool,
) -> Outcome<PeriodRow> {
    let (_, end) = book.calendar.year_bounds(request.fiscal_year)?;
    let periods = book.calendar.periods_for_year(request.fiscal_year)?;
    let Some(definition) = periods.iter().find(|p| p.code == request.closing_period) else {
        return Ok(Err(unsupported(
            "unknown Closing period in the selected fiscal year",
        )));
    };
    if definition.kind != PeriodKind::Closing || definition.start != end {
        return Ok(Err(unsupported(
            "year-end close requires the fiscal year's explicit Closing period",
        )));
    }
    let Some(row) = db.vertex_at(period_vid(&book.calendar.id, &definition.code), at)? else {
        return Ok(Err(unsupported(
            "install and open the fiscal year's Closing period first",
        )));
    };
    let period = PeriodRow::decode(&row)?;
    if !row.labels.contains(&label::PERIOD)
        || period.fiscal_year != request.fiscal_year
        || period.kind != PeriodKind::Closing
        || period.start != definition.start
        || period.end != definition.end
    {
        return Err(KernelError::Corrupt(
            "closing period differs from its calendar definition".into(),
        ));
    }
    if posting
        && !matches!(
            period.state,
            PeriodState::Open | PeriodState::SoftClosed | PeriodState::Closed
        )
    {
        return Ok(Err(unsupported(
            "Closing is supported only in Open, SoftClosed or Closed; Locked case-bound reclose is not implemented",
        )));
    }
    Ok(Ok(period))
}

fn closing_entity(spec: &BookSpec, leg: &LegPayload) -> Result<Option<VId>, Refusal> {
    // An analytic value (a cost center, department, project, product,
    // region, grant or segment) closes with its account: the close moves the
    // account's net per unit and entity and carries none (fa-ficc). A fund
    // or a party has no closing treatment yet.
    if leg.dimension_set.iter().any(|(dimension, _)| {
        *dimension != LEGAL_ENTITY_DIMENSION && !crate::dimension::closes_with_account(*dimension)
    }) {
        return Err(unsupported(
            "a nominal contribution uses a dimension without an implemented closing treatment",
        ));
    }
    match leg
        .dimension_set
        .iter()
        .find(|(dimension, _)| *dimension == LEGAL_ENTITY_DIMENSION)
        .map(|(_, value)| *value)
    {
        Some(value) if spec.entity_of(value).is_some() => Ok(Some(value)),
        Some(_) => Err(unsupported(
            "a nominal contribution names an undeclared legal entity",
        )),
        None if spec.entities.len() > 1 => Err(unsupported(
            "a nominal contribution omits its required legal entity",
        )),
        None => Ok(spec
            .entities
            .first()
            .map(|entity| entity_value_vid(spec.book_id, &entity.code))),
    }
}

fn route_account(
    chart: &ChartSnapshot,
    account: VId,
    nominal: bool,
    unit: Option<UnitId>,
    day: DateDay,
    require_posting: bool,
) -> Result<&AccountRow, Refusal> {
    let row = chart
        .accounts()
        .get(&account)
        .ok_or_else(|| unsupported("a closing route names an unknown account"))?;
    let kind = AccountType(row.account_type);
    if (require_posting && !row.is_leaf)
        || (nominal && !kind.is_flow())
        || (!nominal && kind != AccountType::EQUITY)
    {
        return Err(unsupported(
            "closing routes must map Revenue/Expense leaves to Equity leaves",
        ));
    }
    if row.limit.is_some() {
        return Err(unsupported(
            "closing a balance-limited account requires a separate implemented close law",
        ));
    }
    if unit
        .is_some_and(|unit| matches!(row.unit_policy, UnitPolicy::Single(fixed) if fixed != unit))
    {
        return Err(unsupported(
            "a closing route account does not accept the source currency",
        ));
    }
    if require_posting
        && !chart
            .account_effectivity(account)
            .unwrap_or_default()
            .is_effective_at(day)
    {
        return Err(unsupported(
            "a closing route account is not effective at the fiscal-year-end date",
        ));
    }
    Ok(row)
}

/// Keep dormant account declarations in the source commitment even when
/// they emit no Closing leg. The existing route binding bytes are unchanged.
fn bind_account(
    source: &mut fgdb_crypto::Hasher,
    chart: &ChartSnapshot,
    row: &AccountRow,
) -> Result<(), KernelError> {
    let mut encoded = Writer::new();
    encoded
        .u128(row.vid.0)
        .str(&row.code)
        .str(&row.name)
        .u8(row.account_type)
        .u8(row.normal_balance)
        .bool(row.is_leaf)
        .u64(row.created_at.0);
    match row.unit_policy {
        UnitPolicy::Single(unit) => {
            encoded.u8(0).u32(unit.0);
        }
        UnitPolicy::AnyCurrency => {
            encoded.u8(1);
        }
        UnitPolicy::AnyUnit => {
            encoded.u8(2);
        }
    }
    encoded.bytes(
        &chart
            .account_effectivity(row.vid)
            .unwrap_or_default()
            .encode_payload()?
            .unwrap_or_default(),
    );
    source.update(&encoded.finish()?);
    Ok(())
}

/// A signed native/functional vector. Carrying buckets use the reduced exact
/// quotient of the two *recorded* positive amounts, never a new quoted rate.
#[derive(Clone, Copy, Debug, Default)]
struct CarryingBalance {
    native: i128,
    base: i128,
}

impl CarryingBalance {
    fn add(&mut self, side: Side, native: i128, base: i128) -> Result<(), Refusal> {
        let signed = |total: i128, value: i128| match side {
            Side::Debit => total.checked_add(value),
            Side::Credit => total.checked_sub(value),
        };
        self.native = signed(self.native, native)
            .ok_or_else(|| unsupported("the nominal native fold exceeds exact i128 range"))?;
        self.base = signed(self.base, base)
            .ok_or_else(|| unsupported("the nominal functional fold exceeds exact i128 range"))?;
        Ok(())
    }

    fn is_zero(self) -> bool {
        self.native == 0 && self.base == 0
    }
}

#[derive(Default)]
struct CarryingCell {
    total: CarryingBalance,
    buckets: BTreeMap<(u128, u128), CarryingBalance>,
}

fn carrying_quotient(native: i128, base: i128) -> Result<(u128, u128), Refusal> {
    let native = u128::try_from(native)
        .ok()
        .filter(|amount| *amount > 0)
        .ok_or_else(|| unsupported("a source native amount must be strictly positive"))?;
    let base = u128::try_from(base)
        .map_err(|_| unsupported("a source functional carrying amount must be nonnegative"))?;
    let (mut a, mut b) = (native, base);
    while b != 0 {
        (a, b) = (b, a % b);
    }
    Ok((base / a, native / a))
}

/// The authenticated journal and its original valuation laws are checked at
/// public boundaries. The fold itself stays pure so FX history verification
/// can reproduce every retained Closing without recursively verifying itself.
fn validate_sources<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Outcome<()> {
    if at.0 == 0 || at > db.frontier()? {
        return Ok(Err(changed(
            "the closing observation is outside this book's recorded history",
        )));
    }
    crate::entry_history::verify_entry_history(db, cx, book, Some(at))?;
    // Native v1 closes have no FX claim, but their source-bound provenance is
    // just as authoritative. A bad older native close must not be laundered
    // into a later carrying close merely because its numerical entry balances.
    for row in db.vertices_at(at)? {
        cx.query()
            .checkpoint()
            .map_err(fgdb::WriteTxnError::Interrupted)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = crate::sweep::decode_entry(&row)?;
        if entry.proposal.class != EntryClass::CLOSING {
            continue;
        }
        let basis = match admit(&entry.proposal) {
            Ok(Some(basis)) => basis,
            _ => {
                return Ok(Err(unsupported(
                    "a retained Closing has no valid intrinsic source basis",
                )));
            }
        };
        if basis.version == YEAR_END_CLOSE_VERSION
            && !verify_record(
                db,
                cx,
                book,
                &YearEndCloseRequest {
                    fiscal_year: basis.fiscal_year,
                    closing_period: basis.closing_period,
                },
                &ClosingRecord {
                    entry_ref: entry.entry_ref(row.vid),
                    recorded_at: row.created_at,
                },
            )?
        {
            return Ok(Err(unsupported(
                "a retained native Closing does not reproduce its source basis",
            )));
        }
    }
    let verified = crate::fx::verify_fx_conversions(db, cx, book, at)?;
    if let Some(drift) = verified.drift.first() {
        return Ok(Err(unsupported(format!(
            "source valuation of entry {:032x} does not verify under {}: {}",
            drift.entry.0, drift.law, drift.problem,
        ))));
    }
    Ok(Ok(()))
}

#[allow(clippy::too_many_arguments)]
fn append_pair(
    legs: &mut Vec<LegPayload>,
    chart: &ChartSnapshot,
    end: DateDay,
    account: VId,
    closes_to: VId,
    unit: UnitId,
    base_unit: UnitId,
    entity: Option<VId>,
    balance: CarryingBalance,
    valued: bool,
) -> Result<(), Refusal> {
    if balance.is_zero() {
        return Ok(());
    }
    if balance.native == 0
        || (balance.base != 0 && balance.native.signum() != balance.base.signum())
    {
        return Err(unsupported(
            "a retained carrying bucket does not preserve its source signs",
        ));
    }
    let magnitude = balance
        .native
        .checked_abs()
        .ok_or_else(|| unsupported("a closing native leg magnitude exceeds exact i128 range"))?;
    let base = balance
        .base
        .checked_abs()
        .ok_or_else(|| unsupported("a closing functional magnitude exceeds exact i128 range"))?;
    let (nominal_side, equity_side) = if balance.native > 0 {
        (Side::Credit, Side::Debit)
    } else {
        (Side::Debit, Side::Credit)
    };
    for (target, side, nominal) in [
        (account, nominal_side, true),
        (closes_to, equity_side, false),
    ] {
        route_account(chart, target, nominal, Some(unit), end, true)?;
        let mut leg = LegPayload::simple(side, target, Amount::new(unit, magnitude));
        if valued {
            leg.base_amount = Some(Amount::new(base_unit, base));
        }
        if let Some(entity) = entity {
            leg.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, entity)];
        }
        legs.push(leg);
    }
    if legs.len() > fa_model::limits::MAX_LEGS_PER_ENTRY {
        return Err(unsupported(
            "the complete close exceeds the atomic entry leg bound; no partial close was prepared",
        ));
    }
    Ok(())
}

fn carrying_totals(legs: &[LegPayload], base_unit: UnitId) -> Result<BaseTotals, Refusal> {
    let (mut debits, mut credits) = (0_i128, 0_i128);
    for leg in legs {
        let base = leg
            .base_amount
            .filter(|amount| amount.unit == base_unit && amount.mantissa >= 0)
            .ok_or_else(|| {
                unsupported("every carrying-close leg requires its retained base amount")
            })?;
        let total = match leg.side {
            Side::Debit => &mut debits,
            Side::Credit => &mut credits,
        };
        *total = total
            .checked_add(base.mantissa)
            .ok_or_else(|| unsupported("closing functional totals exceed exact i128 range"))?;
    }
    if debits != credits {
        return Err(unsupported(
            "retained closing functional debits and credits differ",
        ));
    }
    Ok(BaseTotals {
        unit_id: base_unit.0,
        debits,
        credits,
        fx_law_oid: crate::fx::FxLawId::YearEndCloseCarrying.oid(),
        rate_doc_oids: Vec::new(),
        residual: None,
    })
}

fn observe<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    request: &YearEndCloseRequest,
    at: CommitSeq,
    posting: bool,
    version: Option<u16>,
) -> Outcome<PreparedYearEndClose> {
    if at.0 == 0 || at > db.frontier()? {
        return Ok(Err(changed(
            "the closing observation is outside this book's recorded history",
        )));
    }
    let period = match selected_period(db, book, request, at, posting)? {
        Ok(period) => period,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let (start, end) = book.calendar.year_bounds(request.fiscal_year)?;
    let spec = crate::fx::book_spec_at(db, book, at)?;
    if !book
        .units
        .get(spec.base_unit)
        .is_some_and(|unit| matches!(unit.kind, fa_money::UnitKind::Currency { .. }))
    {
        return Ok(Err(unsupported(
            "year-end close requires a registered base currency",
        )));
    }
    let chart = crate::chart::read_at(db, book, at)?;
    let Some(routes) = closing_routes_at(db, book, end, at)? else {
        return Ok(Err(unsupported(
            "no journaled closing route map applies at the fiscal-year-end date",
        )));
    };
    let mut entries = Vec::new();
    let mut runs = BTreeMap::new();
    for row in db.vertices_at(at)? {
        cx.query()
            .checkpoint()
            .map_err(fgdb::WriteTxnError::Interrupted)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "closing source entry")?)?;
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            return Err(KernelError::Corrupt(
                "closing source belongs to another book or branch".into(),
            ));
        }
        if entry.proposal.class == EntryClass::PENDING
            || entry.proposal.class.is_control()
            || entry.proposal.effective_date < start
            || entry.proposal.effective_date > end
            || !crate::migration::visible_at(db, &entry, at, &mut runs)?
        {
            continue;
        }
        entries.push((row.vid, entry, row.created_at));
    }
    entries.sort_by_key(|(vid, _, recorded_at)| (*recorded_at, *vid));
    let version = version.unwrap_or_else(|| {
        let foreign_route = routes.routes.iter().any(|(account, destination)| {
            [account, destination].into_iter().any(|vid| {
                chart.accounts().get(vid).is_some_and(|row| {
                    matches!(row.unit_policy, UnitPolicy::Single(unit) if unit != spec.base_unit)
                })
            })
        });
        if foreign_route
            || entries.iter().any(|(_, entry, _)| {
                entry.proposal.legs.iter().any(|leg| {
                    chart
                        .accounts()
                        .get(&leg.account_ref)
                        .is_some_and(|row| AccountType(row.account_type).is_flow())
                        && (leg.amount.unit != spec.base_unit || leg.base_amount.is_some())
                })
            })
        {
            YEAR_END_CLOSE_CARRYING_VERSION
        } else {
            YEAR_END_CLOSE_VERSION
        }
    });
    let valued = match version {
        YEAR_END_CLOSE_VERSION => false,
        YEAR_END_CLOSE_CARRYING_VERSION => true,
        _ => {
            return Ok(Err(unsupported(
                "unknown year-end closing computation version",
            )));
        }
    };
    let mut source = fgdb_crypto::Hasher::new();
    source.update(if valued {
        b"fa:year-end-close-source:v2"
    } else {
        b"fa:year-end-close-source:v1"
    });
    source.update(&book.book_id.0);
    source.update(&request.fiscal_year.to_le_bytes());
    source.update(&start.0.to_le_bytes());
    source.update(&end.0.to_le_bytes());
    source.update(&[period.state as u8]);
    source.update(&routes.control_entry.0.to_le_bytes());
    source.update(&routes.digest);
    if valued {
        source.update(&spec.canonical_bytes()?);
        let units = fa_model::unit::unit_table_digest(&book.units)
            .map_err(|error| KernelError::Corrupt(format!("closing unit definitions: {error}")))?;
        let root = db
            .vertex_at(crate::rows::book_root(), at)?
            .ok_or_else(|| KernelError::Corrupt("closing source has no Book root".into()))?;
        if bytes(&root, property::UNIT_TABLE_DIGEST, "closing unit table")? != units {
            return Err(KernelError::Corrupt(
                "closing unit definitions differ from the selected historical book".into(),
            ));
        }
        source.update(&units);
        source.update(&crate::fx::FxLawId::YearEndCloseCarrying.oid().0);
    }
    // Dormant routes remain bound. Version 2 checks currency acceptance for
    // each actual source unit instead of requiring every route to accept base.
    for (account, destination) in &routes.routes {
        for (vid, nominal) in [(*account, true), (*destination, false)] {
            let row = match route_account(
                &chart,
                vid,
                nominal,
                if valued { None } else { Some(spec.base_unit) },
                end,
                false,
            ) {
                Ok(row) => row,
                Err(refusal) => return Ok(Err(refusal)),
            };
            bind_account(&mut source, &chart, row)?;
        }
    }
    let mut balances: BTreeMap<(VId, UnitId, Option<VId>), CarryingCell> = BTreeMap::new();
    let mut latest_close = None;
    for (vid, entry, recorded_at) in entries {
        if entry.proposal.class == EntryClass::CLOSING {
            latest_close = Some(ClosingRecord {
                entry_ref: entry.entry_ref(vid),
                recorded_at,
            });
        }
        for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
            let Some(account) = chart.accounts().get(&leg.account_ref) else {
                return Err(KernelError::Corrupt(
                    "closing source leg names an unknown account".into(),
                ));
            };
            if !AccountType(account.account_type).is_flow() {
                continue;
            }
            if !valued && (leg.amount.unit != spec.base_unit || leg.base_amount.is_some()) {
                return Ok(Err(unsupported(
                    "version 1 closes only unvalued native base-currency sources",
                )));
            }
            if !book
                .units
                .get(leg.amount.unit)
                .is_some_and(|unit| matches!(unit.kind, fa_money::UnitKind::Currency { .. }))
            {
                return Ok(Err(unsupported(
                    "a nominal source uses an unsupported noncurrency unit",
                )));
            }
            let base = match leg.base_amount {
                Some(base)
                    if base.unit == spec.base_unit
                        && base.mantissa >= 0
                        && (leg.amount.unit != spec.base_unit || base == leg.amount) =>
                {
                    base.mantissa
                }
                None if leg.amount.unit == spec.base_unit => leg.amount.mantissa,
                None => {
                    return Ok(Err(unsupported(
                        "a foreign nominal source has no retained functional valuation",
                    )));
                }
                Some(_) => {
                    return Ok(Err(unsupported(
                        "a nominal source has an invalid functional carrying amount",
                    )));
                }
            };
            let entity = match closing_entity(&spec, leg) {
                Ok(entity) => entity,
                Err(refusal) => return Ok(Err(refusal)),
            };
            source.update(&vid.0.to_le_bytes());
            source.update(&recorded_at.0.to_le_bytes());
            source.update(&entry.entry_digest);
            source.update(&(ordinal as u64).to_le_bytes());
            let quotient = match carrying_quotient(leg.amount.mantissa, base) {
                Ok(quotient) => quotient,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let cell = balances
                .entry((leg.account_ref, leg.amount.unit, entity))
                .or_default();
            if let Err(refusal) = cell
                .total
                .add(leg.side, leg.amount.mantissa, base)
                .and_then(|()| {
                    cell.buckets.entry(quotient).or_default().add(
                        leg.side,
                        leg.amount.mantissa,
                        base,
                    )
                })
            {
                return Ok(Err(refusal));
            }
        }
    }
    let mut residuals = Vec::new();
    let mut legs = Vec::new();
    let mut bound_unrouted = BTreeSet::new();
    for ((account, unit, entity), cell) in balances {
        let row = &chart.accounts()[&account];
        let inactive = !row.is_leaf
            || !chart
                .account_effectivity(account)
                .unwrap_or_default()
                .is_effective_at(end);
        if inactive && !cell.total.is_zero() {
            return Ok(Err(unsupported(format!(
                "nominal account {} has a nonzero fiscal-year carrying balance but is not a posting leaf effective at fiscal-year end",
                row.code,
            ))));
        }
        let closes_to = match routes.routes.get(&account) {
            Some(destination) => *destination,
            None if inactive && cell.total.is_zero() => {
                let row = match route_account(&chart, account, true, Some(unit), end, false) {
                    Ok(row) => row,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                if bound_unrouted.insert(account) {
                    source.update(b"fa:year-end-close-unrouted-zero:v1");
                    bind_account(&mut source, &chart, row)?;
                }
                continue;
            }
            None => {
                return Ok(Err(unsupported(format!(
                    "nominal account {} has activity but no reviewed closing destination",
                    row.code,
                ))));
            }
        };
        residuals.push(ClosingResidual {
            account,
            account_code: row.code.clone(),
            closes_to,
            unit,
            entity,
            net: cell.total.native,
            base_net: cell.total.base,
        });
        // Opposing valuation cohorts can cancel both measures. Such an
        // account is already closed and must not create economic-zero turnover.
        if cell.total.is_zero() {
            continue;
        }
        if valued {
            for balance in cell.buckets.into_values() {
                if let Err(refusal) = append_pair(
                    &mut legs,
                    &chart,
                    end,
                    account,
                    closes_to,
                    unit,
                    spec.base_unit,
                    entity,
                    balance,
                    true,
                ) {
                    return Ok(Err(refusal));
                }
            }
        } else if let Err(refusal) = append_pair(
            &mut legs,
            &chart,
            end,
            account,
            closes_to,
            unit,
            spec.base_unit,
            entity,
            cell.total,
            false,
        ) {
            return Ok(Err(refusal));
        }
    }
    let base_totals = if valued {
        match carrying_totals(&legs, spec.base_unit) {
            Ok(totals) => Some(totals),
            Err(refusal) => return Ok(Err(refusal)),
        }
    } else {
        None
    };
    Ok(Ok(PreparedYearEndClose {
        request: request.clone(),
        basis: YearEndCloseBasis {
            version,
            fiscal_year: request.fiscal_year,
            closing_period: request.closing_period.clone(),
            closing_date: end,
            observed_at: at,
            routes_entry: routes.control_entry,
            routes_digest: routes.digest,
            source_digest: source.finalize().0,
        },
        unit: spec.base_unit,
        residuals,
        legs,
        base_totals,
        latest_close,
    }))
}

/// Mandatory structural gate, including on exact retries. No unrelated
/// entry class can smuggle a closing computation through an opaque extension.
pub(crate) fn admit(proposal: &EntryPayload) -> Result<Option<YearEndCloseBasis>, Refusal> {
    let record = proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == YEAR_END_CLOSE_EXTENSION);
    if proposal.class != EntryClass::CLOSING {
        return if record.is_some() {
            Err(unsupported(
                "closing provenance belongs only on Closing entries",
            ))
        } else {
            Ok(None)
        };
    }
    let Some((_, bytes)) = record else {
        return Err(unsupported(
            "arbitrary balanced Closing legs are not admitted; the intrinsic computation basis is required",
        ));
    };
    if proposal.schema_minor != EXTENSIONS_MINOR
        || proposal.extensions.len() != 1
        || !matches!(&proposal.origin, EntryOrigin::Intent { intent_kind: 1, .. })
        || proposal.control.is_some()
        || proposal.pending.is_some()
        || !proposal.supersession.is_empty()
        || proposal.legs.iter().any(|leg| !leg.settles.is_empty())
    {
        return Err(unsupported(
            "Closing requires only its registered computation and monetary effects",
        ));
    }
    let basis = YearEndCloseBasis::decode(bytes).map_err(unsupported)?;
    match basis.version {
        YEAR_END_CLOSE_VERSION => {
            if proposal.base_totals.is_some()
                || proposal.legs.iter().any(|leg| leg.base_amount.is_some())
            {
                return Err(unsupported(
                    "version 1 closes only unvalued native base amounts",
                ));
            }
        }
        YEAR_END_CLOSE_CARRYING_VERSION => {
            let totals = proposal.base_totals.as_ref().ok_or_else(|| {
                unsupported("version 2 requires its source-bound retained carrying law")
            })?;
            let expected = carrying_totals(&proposal.legs, UnitId(totals.unit_id))?;
            if *totals != expected {
                return Err(unsupported(
                    "version 2 preserves exact carrying totals without new Rate documents or a residual plug",
                ));
            }
        }
        _ => return Err(unsupported("unknown year-end closing computation version")),
    }
    if proposal.effective_date != basis.closing_date
        || proposal
            .effective_period
            .as_ref()
            .map(|period| period.code.as_str())
            != Some(basis.closing_period.as_str())
    {
        return Err(unsupported(
            "the entry date or period differs from its reviewed closing basis",
        ));
    }
    Ok(Some(basis))
}

pub(crate) fn validate_post<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    proposal: &EntryPayload,
    basis: &YearEndCloseBasis,
) -> Outcome<()> {
    if proposal
        .effective_period
        .as_ref()
        .is_none_or(|period| period.calendar != book.calendar.id)
        || basis.observed_at > txn.basis()
    {
        return Ok(Err(changed(
            "the closing basis does not belong to this period or snapshot",
        )));
    }
    let request = YearEndCloseRequest {
        fiscal_year: basis.fiscal_year,
        closing_period: basis.closing_period.clone(),
    };
    let mut snapshots = BTreeSet::new();
    snapshots.extend([basis.observed_at, txn.basis()]);
    for at in snapshots {
        if let Err(refusal) = validate_sources(db, cx, book, at)? {
            return Ok(Err(refusal));
        }
        let observed = match observe(db, cx, book, &request, at, true, Some(basis.version))? {
            Ok(observed) => observed,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if observed.basis.routes_entry != basis.routes_entry
            || observed.basis.routes_digest != basis.routes_digest
            || observed.basis.source_digest != basis.source_digest
            || observed.basis.closing_date != basis.closing_date
            || observed.legs != proposal.legs
            || observed.base_totals != proposal.base_totals
            || observed.is_noop()
        {
            return Ok(Err(changed(
                "the Closing entry does not reproduce its complete fiscal-year source and routing basis",
            )));
        }
    }
    Ok(Ok(()))
}

pub fn verify_year_end_close<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    fiscal_year: i32,
    known_at: Option<CommitSeq>,
) -> Outcome<YearEndCloseVerification> {
    let query = cx.query();
    query
        .checkpoint()
        .map_err(fgdb::WriteTxnError::Interrupted)?;
    query.with_restriction(|| {
        // Historical observation never restores expired or revoked authority.
        // Admit the current token before selecting the prefix it may observe.
        if let Err(refusal) = crate::policy::admit_reads(db, book, capability.holder(), capability)?
        {
            return Ok(Err(refusal));
        }
        if let Err(denial) = fa_policy::reach(
            capability,
            &Reach {
                branch: Some(Id128::TRUNK),
                observes: known_at.map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
                periods: None,
                through: None,
                accounts: None,
            },
            None,
        ) {
            return Ok(Err(crate::policy::refusal(&denial)));
        }
        let at = known_at.unwrap_or(db.frontier()?);
        if let Err(refusal) = validate_sources(db, cx, book, at)? {
            return Ok(Err(refusal));
        }
        let Some(period) = book
            .calendar
            .periods_for_year(fiscal_year)?
            .into_iter()
            .find(|period| period.kind == PeriodKind::Closing)
        else {
            return Ok(Err(unsupported("the fiscal year has no Closing period")));
        };
        let request = YearEndCloseRequest {
            fiscal_year,
            closing_period: period.code,
        };
        let current = match observe(db, cx, book, &request, at, false, None)? {
            Ok(current) => current,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let nominal_zero_at_close = if let Some(record) = &current.latest_close {
            Some(verify_record(db, cx, book, &request, record)?)
        } else {
            None
        };
        Ok(Ok(YearEndCloseVerification {
            fiscal_year,
            base_unit: current.unit,
            known_at: at,
            latest_close: current.latest_close.clone(),
            nominal_zero_at_close,
            needs_reclose: !current.is_noop(),
            residuals: current.residuals,
        }))
    })
}

/// A numerically zero balance is insufficient: historical verification
/// also reproduces the close's retained provenance and exact routing at
/// the original review and immediately before its native publication.
fn verify_record<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    request: &YearEndCloseRequest,
    record: &ClosingRecord,
) -> Result<bool, KernelError> {
    let Some((entry, recorded_at)) =
        crate::post::read_entry_at(db, record.entry_ref.vid, record.recorded_at)?
    else {
        return Err(KernelError::Corrupt(
            "the selected Closing entry is absent".into(),
        ));
    };
    if recorded_at != record.recorded_at
        || entry.entry_ref(record.entry_ref.vid) != record.entry_ref
    {
        return Err(KernelError::Corrupt(
            "the selected Closing entry reference differs".into(),
        ));
    }
    let Ok(Some(basis)) = admit(&entry.proposal) else {
        return Ok(false);
    };
    if basis.fiscal_year != request.fiscal_year
        || basis.closing_period != request.closing_period
        || basis.observed_at.0 == 0
        || basis.observed_at >= record.recorded_at
        || entry
            .proposal
            .effective_period
            .as_ref()
            .is_none_or(|period| period.calendar != book.calendar.id)
    {
        return Ok(false);
    }
    let mut snapshots = BTreeSet::new();
    snapshots.extend([basis.observed_at, CommitSeq(record.recorded_at.0 - 1)]);
    for at in snapshots {
        let observed = match observe(db, cx, book, request, at, true, Some(basis.version))? {
            Ok(observed) => observed,
            Err(_) => return Ok(false),
        };
        if observed.basis.routes_entry != basis.routes_entry
            || observed.basis.routes_digest != basis.routes_digest
            || observed.basis.source_digest != basis.source_digest
            || observed.basis.closing_date != basis.closing_date
            || observed.legs != entry.proposal.legs
            || observed.base_totals != entry.proposal.base_totals
            || observed.is_noop()
        {
            return Ok(false);
        }
    }
    Ok(
        match observe(
            db,
            cx,
            book,
            request,
            record.recorded_at,
            false,
            Some(basis.version),
        )? {
            Ok(closed) => closed.is_noop(),
            Err(_) => false,
        },
    )
}

/// Reproduce a retained carrying close for the global FX verifier. This is a
/// pure source/basis replay; the caller verifies every original valuation and
/// the complete immutable Entry history independently, avoiding recursion.
pub(crate) fn verify_recorded_carrying<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    entry_ref: EntryRef,
    recorded_at: CommitSeq,
) -> Result<bool, KernelError> {
    let Some((entry, actual_at)) = crate::post::read_entry_at(db, entry_ref.vid, recorded_at)?
    else {
        return Ok(false);
    };
    if entry.entry_ref(entry_ref.vid) != entry_ref || actual_at != recorded_at {
        return Ok(false);
    }
    let Ok(Some(basis)) = admit(&entry.proposal) else {
        return Ok(false);
    };
    if basis.version != YEAR_END_CLOSE_CARRYING_VERSION {
        return Ok(false);
    }
    verify_record(
        db,
        cx,
        book,
        &YearEndCloseRequest {
            fiscal_year: basis.fiscal_year,
            closing_period: basis.closing_period,
        },
        &ClosingRecord {
            entry_ref,
            recorded_at,
        },
    )
}
