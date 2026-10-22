//! Mechanical fiscal-year close and incremental reclose (plan §7.5).
//!
//! The intrinsic YearEndClose v1 computation closes Revenue/Expense leaves
//! to their journaled Equity destinations. It admits native base-currency
//! amounts and the existing legal-entity balancing dimension. Other
//! dimensions and valuation laws refuse explicitly. This is not the larger
//! CloseRun task DAG and does not execute generic Canon rules.
//!
//! Every public Closing path must reproduce extension 12 from both its
//! saved observation and the current preparation snapshot. The original
//! prepared posting retains a complete-frontier guard until publication;
//! newly appended activity cannot escape an aggregate dependency check.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::entry::{EXTENSIONS_MINOR, YEAR_END_CLOSE_EXTENSION};
use fa_model::symbols::{label, property};
use fa_model::{
    AccountType, Entry, EntryClass, EntryOrigin, EntryPayload, EntryRef, Id128,
    LEGAL_ENTITY_DIMENSION, LegPayload, Writer, YearEndCloseBasis, entity_value_vid, period_vid,
};
use fa_money::{Amount, Side, UnitId};
use fa_policy::{Capability, Op, Reach};
use fa_time::{DateDay, PeriodKind, PeriodState};
use fgdb::{Database, WriteTxn};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::chart::{ChartSnapshot, closing_routes_at};
use crate::genesis::{BookContext, BookSpec, UnitPolicy, read_book_spec};
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
        "plan §7.5; FA-INV-03.nominal-zero; intrinsic YearEndClose v1",
        "use reviewed Revenue/Expense-to-Equity routes, native base-currency amounts and supported legal-entity dimensions; prepare and review fa close year-end --fiscal-year <year> --period FY<year>-CLOSE --key <new-key> --review-only (plan §7.5 / fa-4o0)",
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
pub(crate) fn authorize<V: Vfs + Clone>(
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
        observe(db, cx, book, request, db.frontier()?, true)
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
    if leg
        .dimension_set
        .iter()
        .any(|(dimension, _)| *dimension != LEGAL_ENTITY_DIMENSION)
    {
        return Err(unsupported(
            "a nominal contribution uses a dimension without an implemented closing treatment",
        ));
    }
    match leg.dimension_set.first().map(|(_, value)| *value) {
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
    unit: UnitId,
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
    if matches!(row.unit_policy, UnitPolicy::Single(fixed) if fixed != unit) {
        return Err(unsupported(
            "a closing route account does not accept the book's native base currency",
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

fn observe<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    request: &YearEndCloseRequest,
    at: CommitSeq,
    posting: bool,
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
    let spec = read_book_spec(db)?.ok_or_else(|| KernelError::Corrupt("no book spec".into()))?;
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
    let mut source = fgdb_crypto::Hasher::new();
    source.update(b"fa:year-end-close-source:v1");
    source.update(&book.book_id.0);
    source.update(&request.fiscal_year.to_le_bytes());
    source.update(&start.0.to_le_bytes());
    source.update(&end.0.to_le_bytes());
    source.update(&[period.state as u8]);
    source.update(&routes.control_entry.0.to_le_bytes());
    source.update(&routes.digest);
    // Every declared route remains structurally checked and bound, including
    // zero balances. Posting activity is required only for emitted legs:
    // a legitimately retired zero account needs no year-end posting.
    for (account, destination) in &routes.routes {
        for (vid, nominal) in [(*account, true), (*destination, false)] {
            let row = match route_account(&chart, vid, nominal, spec.base_unit, end, false) {
                Ok(row) => row,
                Err(refusal) => return Ok(Err(refusal)),
            };
            bind_account(&mut source, &chart, row)?;
        }
    }
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
    let mut balances: BTreeMap<(VId, Option<VId>), i128> = BTreeMap::new();
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
            if leg.amount.unit != spec.base_unit || leg.base_amount.is_some() {
                return Ok(Err(unsupported(
                    "a nominal contribution uses foreign currency or a base-valuation law",
                )));
            }
            let entity = match closing_entity(&spec, leg) {
                Ok(entity) => entity,
                Err(refusal) => return Ok(Err(refusal)),
            };
            source.update(&vid.0.to_le_bytes());
            source.update(&recorded_at.0.to_le_bytes());
            source.update(&entry.entry_digest);
            source.update(&(ordinal as u64).to_le_bytes());
            let net = balances.entry((leg.account_ref, entity)).or_default();
            let updated = match leg.side {
                Side::Debit => net.checked_add(leg.amount.mantissa),
                Side::Credit => net.checked_sub(leg.amount.mantissa),
            };
            let Some(updated) = updated else {
                return Ok(Err(unsupported(
                    "the nominal-account fold exceeds exact i128 range",
                )));
            };
            *net = updated;
        }
    }
    let mut residuals = Vec::new();
    let mut legs = Vec::new();
    let mut bound_unrouted = BTreeSet::new();
    for ((account, entity), net) in balances {
        let row = &chart.accounts()[&account];
        let inactive = !row.is_leaf
            || !chart
                .account_effectivity(account)
                .unwrap_or_default()
                .is_effective_at(end);
        if inactive && net != 0 {
            return Ok(Err(unsupported(format!(
                "nominal account {} has a nonzero fiscal-year balance but is not a posting leaf effective at fiscal-year end",
                row.code
            ))));
        }
        let closes_to = match routes.routes.get(&account) {
            Some(destination) => *destination,
            None if inactive && net == 0 => {
                let row = match route_account(&chart, account, true, spec.base_unit, end, false) {
                    Ok(row) => row,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                if bound_unrouted.insert(account) {
                    // Newly admissible unrouted zero accounts keep their
                    // complete contribution and lifecycle dependencies.
                    source.update(b"fa:year-end-close-unrouted-zero:v1");
                    bind_account(&mut source, &chart, row)?;
                }
                continue;
            }
            None => {
                return Ok(Err(unsupported(format!(
                    "nominal account {} has activity but no reviewed closing destination",
                    row.code
                ))));
            }
        };
        residuals.push(ClosingResidual {
            account,
            account_code: chart.accounts()[&account].code.clone(),
            closes_to,
            unit: spec.base_unit,
            entity,
            net,
        });
        if net == 0 {
            continue;
        }
        let Some(magnitude) = net.checked_abs() else {
            return Ok(Err(unsupported(
                "a closing leg magnitude exceeds exact i128 range",
            )));
        };
        let (nominal_side, equity_side) = if net > 0 {
            (Side::Credit, Side::Debit)
        } else {
            (Side::Debit, Side::Credit)
        };
        for (target, side, nominal) in [
            (account, nominal_side, true),
            (closes_to, equity_side, false),
        ] {
            if let Err(refusal) = route_account(&chart, target, nominal, spec.base_unit, end, true)
            {
                return Ok(Err(refusal));
            }
            let mut leg = LegPayload::simple(side, target, Amount::new(spec.base_unit, magnitude));
            if let Some(entity) = entity {
                leg.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, entity)];
            }
            legs.push(leg);
        }
    }
    if legs.len() > fa_model::limits::MAX_LEGS_PER_ENTRY {
        return Ok(Err(unsupported(
            "the complete close exceeds the atomic entry leg bound; no partial close was prepared",
        )));
    }
    Ok(Ok(PreparedYearEndClose {
        request: request.clone(),
        basis: YearEndCloseBasis {
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
        || proposal.base_totals.is_some()
        || proposal.control.is_some()
        || proposal.pending.is_some()
        || !proposal.supersession.is_empty()
        || proposal
            .legs
            .iter()
            .any(|leg| leg.base_amount.is_some() || !leg.settles.is_empty())
    {
        return Err(unsupported(
            "Closing requires only its registered computation and native monetary effects",
        ));
    }
    let basis = YearEndCloseBasis::decode(bytes).map_err(unsupported)?;
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
        let observed = match observe(db, cx, book, &request, at, true)? {
            Ok(observed) => observed,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if observed.basis.routes_entry != basis.routes_entry
            || observed.basis.routes_digest != basis.routes_digest
            || observed.basis.source_digest != basis.source_digest
            || observed.basis.closing_date != basis.closing_date
            || observed.legs != proposal.legs
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
        let current = match observe(db, cx, book, &request, at, false)? {
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
        let observed = match observe(db, cx, book, request, at, true)? {
            Ok(observed) => observed,
            Err(_) => return Ok(false),
        };
        if observed.basis.routes_entry != basis.routes_entry
            || observed.basis.routes_digest != basis.routes_digest
            || observed.basis.source_digest != basis.source_digest
            || observed.basis.closing_date != basis.closing_date
            || observed.legs != entry.proposal.legs
            || observed.is_noop()
        {
            return Ok(false);
        }
    }
    Ok(
        match observe(db, cx, book, request, record.recorded_at, false)? {
            Ok(closed) => closed.is_noop(),
            Err(_) => false,
        },
    )
}
