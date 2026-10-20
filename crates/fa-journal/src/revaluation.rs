//! Cumulative, source-bound period-end FX revaluation (plan §5.2, §12.4).
//!
//! Native foreign units remain on the original account. A dedicated valuation
//! leaf records only the delta between the retained closing-rate target and
//! the original committed functional carrying amount plus prior adjustments.
//! Every fresh posting reproduces the original and current source populations;
//! its complete preparation frontier remains guarded until publication.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_model::entry::{EXTENSIONS_MINOR, FX_REVALUATION_EXTENSION};
use fa_model::symbols::{label, property};
use fa_model::{
    AccountType, BaseTotals, Entry, EntryClass, EntryOrigin, EntryPayload, EvidenceRef,
    FxRevaluationBasis, Id128, LEGAL_ENTITY_DIMENSION, LegPayload, Oid, Writer, entity_value_vid,
    period_vid,
};
use fa_money::rate::{ArithmeticBudget, BudgetLimits};
use fa_money::{Amount, Side, UnitId, UnitKind};
use fa_policy::{Capability, Op, Reach};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_registry::{EntryClasses, FxLaws};
use fa_time::{DateDay, PeriodKind, PeriodState};
use fgdb::{Database, WriteTxn};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::chart::{ChartSnapshot, FxRevaluationRoute, fx_revaluation_routes_at};
use crate::evidence::{Storage, document_vid};
use crate::fx::{FxLawId, FxRateDocument, FxRatePurpose, RATE_DOCUMENT_KIND, RATE_EVIDENCE_ROLE};
use crate::genesis::{BookContext, BookSpec, UnitPolicy};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, PeriodRow, book_root, bytes};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxRevaluationRequest {
    pub period: String,
    pub source_account: VId,
    pub rate_document: Oid,
    /// A legal-entity dimension value, required when the book has several.
    pub entity: Option<VId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedFxRevaluation {
    request: FxRevaluationRequest,
    basis: FxRevaluationBasis,
    route: FxRevaluationRoute,
    native_unit: UnitId,
    base_unit: UnitId,
    source_native_net: i128,
    source_base_net: i128,
    prior_adjustment_net: i128,
    current_carrying_net: i128,
    target_base_net: i128,
    delta: i128,
    legs: Vec<LegPayload>,
    evidence: EvidenceRef,
    base_totals: Option<BaseTotals>,
}

impl PreparedFxRevaluation {
    pub fn request(&self) -> &FxRevaluationRequest {
        &self.request
    }
    pub fn basis(&self) -> &FxRevaluationBasis {
        &self.basis
    }
    pub fn route(&self) -> &FxRevaluationRoute {
        &self.route
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
    pub fn native_unit(&self) -> UnitId {
        self.native_unit
    }
    pub fn base_unit(&self) -> UnitId {
        self.base_unit
    }
    pub fn source_native_net(&self) -> Amount {
        Amount::new(self.native_unit, self.source_native_net)
    }
    pub fn source_base_net(&self) -> Amount {
        Amount::new(self.base_unit, self.source_base_net)
    }
    pub fn prior_adjustment_net(&self) -> Amount {
        Amount::new(self.base_unit, self.prior_adjustment_net)
    }
    pub fn current_carrying_net(&self) -> Amount {
        Amount::new(self.base_unit, self.current_carrying_net)
    }
    pub fn target_base_net(&self) -> Amount {
        Amount::new(self.base_unit, self.target_base_net)
    }
    pub fn delta(&self) -> Amount {
        Amount::new(self.base_unit, self.delta)
    }
    pub fn legs(&self) -> &[LegPayload] {
        &self.legs
    }
    pub fn is_noop(&self) -> bool {
        self.delta == 0
    }

    /// Add the verified calculation to an otherwise empty Revaluation intent.
    /// Existing evidence may remain; no caller monetary or computation fields do.
    pub fn proposal(&self, mut template: EntryPayload) -> Result<EntryPayload, Refusal> {
        if template.class != EntryClass::REVALUATION
            || !matches!(&template.origin, EntryOrigin::Intent { intent_kind: 1, .. })
            || !template.legs.is_empty()
            || !template.unit_totals.is_empty()
            || !template.extensions.is_empty()
            || template.base_totals.is_some()
            || template.control.is_some()
            || template.pending.is_some()
            || !template.supersession.is_empty()
        {
            return Err(unsupported(
                "use an empty Revaluation PostEntry template without other computation or lifecycle effects",
            ));
        }
        if self.is_noop() {
            return Err(unsupported(
                "the functional carrying amount already equals the closing-rate target; no revaluation entry is needed",
            ));
        }
        if template.effective_date != self.closing_date()
            || template
                .effective_period
                .as_ref()
                .map(|period| period.code.as_str())
                != Some(self.request.period.as_str())
        {
            return Err(unsupported(
                "the template must name the selected period and its last included date",
            ));
        }
        template.schema_minor = EXTENSIONS_MINOR;
        template.legs = self.legs.clone();
        template.unit_totals =
            EntryPayload::fold_unit_totals(&template.legs).map_err(unsupported)?;
        template.base_totals = self.base_totals.clone();
        template.evidence.push(self.evidence);
        template.evidence.sort();
        template.evidence.dedup();
        template.extensions = vec![(
            FX_REVALUATION_EXTENSION,
            self.basis.canonical_bytes().map_err(unsupported)?,
        )];
        template.validate().map_err(unsupported)?;
        Ok(template)
    }
}

fn unsupported(detail: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::CLASS_NOT_IMPLEMENTED,
        exit::REFUSAL,
        format!("FX revaluation: {detail}"),
        "plan §5.2 / §12.4 (source-bound cumulative revaluation)",
        "use a registered route, a retained PeriodClose rate for the normal period's last included day, and fully valued foreign postings with supported legal-entity dimensions",
    )
}

fn invalid(detail: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        format!("FX revaluation: {detail}"),
        "FA-INV-01.base / plan §6.4 (retained rate and computation basis)",
        "prepare a new revaluation from the selected journal source and its canonical retained closing Rate document",
    )
}

fn changed(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        code::PLAN_INVALIDATED,
        exit::CONFLICT,
        detail,
        "plan §5.10 / §12.4 (complete source exposure, carrying basis and routes)",
        "prepare and review the revaluation again; a saved proposal never silently acquires new exposure, adjustments or routes",
    )
}

pub(crate) fn authorize<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, capability.holder(), book.book_id)
        .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
        .and_then(|()| {
            fa_policy::require(
                capability,
                Op::Post,
                "preparing source-bound FX revaluation",
            )
        })
    {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    Ok(crate::policy::current_at(db, book, capability)?.map(|_| ()))
}

/// Observe the current complete journal. The facade loads native history and
/// performs governed access to the Rate first; this function independently
/// verifies its retained inline bytes and never accepts caller balances.
pub fn prepare_fx_revaluation<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: &FxRevaluationRequest,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<PreparedFxRevaluation> {
    let query = cx.query();
    query
        .checkpoint()
        .map_err(fgdb::WriteTxnError::Interrupted)?;
    query.with_restriction(|| {
        if let Err(refusal) = authorize(db, book, capability)? {
            return Ok(Err(refusal));
        }
        observe_verified(db, cx, book, request, db.frontier()?, budget)
    })
}

fn selected_period<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    code: &str,
    at: CommitSeq,
) -> Outcome<PeriodRow> {
    let Some(definition) = crate::policy::calendar_period(book, code) else {
        return Ok(Err(invalid("unknown revaluation period")));
    };
    if definition.kind != PeriodKind::Normal {
        return Ok(Err(unsupported(
            "this workflow requires an explicit normal fiscal period",
        )));
    }
    let Some(row) = db.vertex_at(period_vid(&book.calendar.id, code), at)? else {
        return Ok(Err(invalid(
            "the selected period was not installed at the observation prefix",
        )));
    };
    let period = PeriodRow::decode(&row)?;
    if !row.labels.contains(&label::PERIOD)
        || period.calendar_id != book.calendar.id
        || period.code != definition.code
        || period.fiscal_year != definition.fiscal_year
        || period.ordinal != definition.ordinal
        || period.kind != definition.kind
        || period.start != definition.start
        || period.end != definition.end
    {
        return Err(KernelError::Corrupt(
            "revaluation period differs from the book calendar".into(),
        ));
    }
    if !matches!(
        period.state,
        PeriodState::Open | PeriodState::SoftClosed | PeriodState::Closed
    ) {
        return Ok(Err(unsupported(
            "revaluation requires an Open, SoftClosed or Closed period; ordinary closed-period authority and approval remain mandatory",
        )));
    }
    Ok(Ok(period))
}

fn selected_entity(spec: &BookSpec, entity: Option<VId>) -> Result<Option<VId>, Refusal> {
    match entity {
        Some(value) if spec.entity_of(value).is_some() => Ok(Some(value)),
        Some(_) => Err(invalid("the selected legal entity is undeclared")),
        None if spec.entities.len() > 1 => Err(invalid(
            "choose one explicit legal entity in a multi-entity book",
        )),
        None => Ok(spec
            .entities
            .first()
            .map(|entity| entity_value_vid(spec.book_id, &entity.code))),
    }
}

fn leg_entity(spec: &BookSpec, leg: &LegPayload) -> Result<Option<VId>, Refusal> {
    if leg
        .dimension_set
        .iter()
        .any(|(dimension, _)| *dimension != LEGAL_ENTITY_DIMENSION)
    {
        return Err(unsupported(
            "an exposure or valuation leg uses a dimension without an implemented revaluation treatment",
        ));
    }
    selected_entity(spec, leg.dimension_set.first().map(|(_, value)| *value))
}

fn route_accounts<'a>(
    chart: &'a ChartSnapshot,
    source: VId,
    route: &FxRevaluationRoute,
    base: UnitId,
    day: DateDay,
) -> Result<[&'a AccountRow; 3], Refusal> {
    let get = |vid| {
        chart
            .accounts()
            .get(&vid)
            .ok_or_else(|| invalid("a route account is absent"))
    };
    let rows = [
        get(source)?,
        get(route.valuation_account)?,
        get(route.unrealized_account)?,
    ];
    for row in rows {
        if !row.is_leaf
            || row.limit.is_some()
            || !chart
                .account_effectivity(row.vid)
                .unwrap_or_default()
                .is_effective_at(day)
        {
            return Err(unsupported(
                "each route account must be an effective posting leaf without balance limits at period end",
            ));
        }
    }
    if !matches!(
        AccountType(rows[0].account_type),
        AccountType::ASSET | AccountType::LIABILITY
    ) || !matches!(rows[0].unit_policy, UnitPolicy::Single(unit) if unit != base)
        || rows[1].account_type != rows[0].account_type
        || rows[1].unit_policy != UnitPolicy::Single(base)
        || !matches!(
            AccountType(rows[2].account_type),
            AccountType::REVENUE | AccountType::EXPENSE
        )
        || rows[2].unit_policy != UnitPolicy::Single(base)
        || source == route.valuation_account
        || source == route.unrealized_account
        || route.valuation_account == route.unrealized_account
    {
        return Err(invalid(
            "the selected route no longer has the declared foreign source, dedicated valuation and unrealized destinations",
        ));
    }
    Ok(rows)
}

fn bind_account(
    hash: &mut fgdb_crypto::Hasher,
    chart: &ChartSnapshot,
    row: &AccountRow,
) -> Result<(), KernelError> {
    let mut w = Writer::new();
    w.u128(row.vid.0)
        .str(&row.code)
        .str(&row.name)
        .u8(row.account_type)
        .u8(row.normal_balance)
        .bool(row.is_leaf)
        .u64(row.created_at.0);
    match row.unit_policy {
        UnitPolicy::Single(unit) => {
            w.u8(0).u32(unit.0);
        }
        UnitPolicy::AnyCurrency => {
            w.u8(1);
        }
        UnitPolicy::AnyUnit => {
            w.u8(2);
        }
    }
    w.bytes(
        &chart
            .account_effectivity(row.vid)
            .unwrap_or_default()
            .encode_payload()?
            .unwrap_or_default(),
    );
    hash.update(&w.finish()?);
    Ok(())
}

fn rate_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    oid: Oid,
    at: CommitSeq,
    native_unit: UnitId,
    base_unit: UnitId,
    date: DateDay,
) -> Outcome<(FxRateDocument, EvidenceRef)> {
    let Some(row) = db.vertex_at(document_vid(&oid), at)? else {
        return Ok(Err(Refusal::new(
            code::EVIDENCE_UNKNOWN,
            exit::REFUSAL,
            "the closing Rate document is not retained at the observation prefix",
            "FA-INV-05 (retained source evidence)",
            "upload the canonical Rate before preparing revaluation",
        )));
    };
    let policy =
        EvidencePolicy::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let record = crate::evidence::verify_row(&row, &policy).map_err(KernelError::Corrupt)?;
    if record.oid() != oid
        || record.book_id != book.book_id
        || record.kind != RATE_DOCUMENT_KIND
        || record.mime != "application/vnd.franken.fx-rate.v1"
    {
        return Ok(Err(invalid(
            "the retained closing source is not this book's canonical Rate document",
        )));
    }
    let Storage::Inline(raw) = &record.storage else {
        return Ok(Err(unsupported(
            "canonical closing Rate evidence must be stored inline",
        )));
    };
    let rate = match FxRateDocument::decode(raw) {
        Ok(rate) => rate,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let classes =
        EntryClasses::embedded().map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let registry =
        FxLaws::embedded(&classes).map_err(|error| KernelError::Corrupt(error.to_string()))?;
    let Some(law) = registry.laws.iter().find(|law| {
        law.id == FxLawId::PeriodEndRevaluation.id()
            && law.version == FxLawId::PeriodEndRevaluation.version()
            && law.status == "live"
    }) else {
        return Ok(Err(unsupported(
            "the registered PeriodEndRevaluation law is not live",
        )));
    };
    if !law
        .admitted_classes
        .iter()
        .any(|class| class == "Revaluation")
        || law.rounding_law != rate.rounding.name()
        || rate.base_unit != base_unit
        || rate.quote_unit != native_unit
        || rate.purpose != FxRatePurpose::PeriodClose
        || rate.as_of != date
    {
        return Ok(Err(invalid(
            "the closing Rate must use the live law's rounding, the source and functional currencies, PeriodClose purpose, and the selected period's last included date",
        )));
    }
    Ok(Ok((rate, record.evidence_ref(RATE_EVIDENCE_ROLE))))
}

fn add_signed(net: &mut i128, side: Side, magnitude: i128) -> Result<(), Refusal> {
    if magnitude <= 0 {
        return Err(invalid(
            "a retained monetary contribution has a nonpositive magnitude",
        ));
    }
    *net = match side {
        Side::Debit => net.checked_add(magnitude),
        Side::Credit => net.checked_sub(magnitude),
    }
    .ok_or_else(|| {
        invalid("the exact cumulative exposure or carrying amount exceeds i128 range")
    })?;
    Ok(())
}

fn recognized_adjustment(
    entry: &Entry,
    recorded_at: CommitSeq,
    source: VId,
    route: &FxRevaluationRoute,
    base_unit: UnitId,
) -> Result<FxRevaluationBasis, Refusal> {
    let Some(basis) = admit(&entry.proposal)? else {
        return Err(unsupported(
            "the dedicated valuation leaf contains an unrelated or legacy unbound posting",
        ));
    };
    let legs = &entry.proposal.legs;
    let Some(totals) = &entry.proposal.base_totals else {
        return Err(invalid(
            "a retained valuation adjustment has no functional totals",
        ));
    };
    if basis.source_account != source
        || basis.observed_at >= recorded_at
        || legs.len() != 2
        || legs[0].account_ref != route.valuation_account
        || legs[1].account_ref != route.unrealized_account
        || legs[0].side == legs[1].side
        || legs[0].amount != legs[1].amount
        || legs[0].amount.unit != base_unit
        || legs.iter().any(|leg| leg.base_amount != Some(leg.amount))
        || totals.unit_id != base_unit.0
        || totals.debits != legs[0].amount.mantissa
        || totals.credits != totals.debits
        || totals.fx_law_oid != FxLawId::PeriodEndRevaluation.oid()
        || totals.rate_doc_oids != [basis.rate_document]
        || totals.residual.is_some()
        || !entry.proposal.evidence.contains(&EvidenceRef {
            document_oid: basis.rate_document,
            doc_commit: basis.rate_commit,
            role: RATE_EVIDENCE_ROLE,
        })
    {
        return Err(unsupported(
            "the dedicated valuation leaf contains a posting that does not match its source-bound route",
        ));
    }
    Ok(basis)
}

fn observe<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    request: &FxRevaluationRequest,
    at: CommitSeq,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<PreparedFxRevaluation> {
    if at.0 == 0 || at > db.frontier()? {
        return Ok(Err(changed(
            "the revaluation observation is outside this book's recorded history",
        )));
    }
    crate::entry_history::verify_entry_history(db, cx, book, Some(at))?;
    crate::migration::verify_run_visibility_at(db, book, at)?;
    if !crate::period::verify_periods(db, book, Some(at))?.is_green() {
        return Err(KernelError::Corrupt(
            "revaluation requires period projections that reproduce their retained creation and transition history".into(),
        ));
    }
    let period = match selected_period(db, book, &request.period, at)? {
        Ok(period) => period,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let date = period.end.pred()?;
    let root = db
        .vertex_at(book_root(), at)?
        .ok_or_else(|| KernelError::Corrupt("revaluation has no book root".into()))?;
    let spec = BookSpec::decode(&bytes(&root, property::FA_PAYLOAD, "revaluation book")?)?;
    if spec.book_id != book.book_id || spec.calendar != book.calendar {
        return Err(KernelError::Corrupt(
            "revaluation book context disagrees with the selected root".into(),
        ));
    }
    let entity = match selected_entity(&spec, request.entity) {
        Ok(entity) => entity,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let chart = crate::chart::read_at(db, book, at)?;
    let Some(routes) = fx_revaluation_routes_at(db, book, date, at)? else {
        return Ok(Err(unsupported(
            "no journaled FX route map applies at period end",
        )));
    };
    let Some(route) = routes.routes.get(&request.source_account).copied() else {
        return Ok(Err(unsupported(
            "the foreign source has no registered revaluation route",
        )));
    };
    let accounts =
        match route_accounts(&chart, request.source_account, &route, spec.base_unit, date) {
            Ok(accounts) => accounts,
            Err(refusal) => return Ok(Err(refusal)),
        };
    let UnitPolicy::Single(native_unit) = accounts[0].unit_policy else {
        return Ok(Err(invalid("the source does not hold one currency")));
    };
    if [native_unit, spec.base_unit].iter().any(|unit| {
        !book
            .units
            .get(*unit)
            .is_some_and(|unit| matches!(unit.kind, UnitKind::Currency { .. }))
    }) {
        return Ok(Err(unsupported(
            "revaluation requires two registered currency units",
        )));
    }
    let (rate, evidence) = match rate_at(
        db,
        book,
        request.rate_document,
        at,
        native_unit,
        spec.base_unit,
        date,
    )? {
        Ok(rate) => rate,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut hash = fgdb_crypto::Hasher::new();
    hash.update(b"fa:fx-revaluation-source:v1");
    let mut selectors = Writer::new();
    selectors
        .fixed(&book.book_id.0)
        .str(&book.calendar.id)
        .str(&request.period)
        .i32(period.start.0)
        .i32(period.end.0)
        .u8(period.state as u8)
        .u128(request.source_account.0)
        .opt(entity.as_ref(), |w, value| {
            w.u128(value.0);
        })
        .u32(native_unit.0)
        .u32(spec.base_unit.0)
        .u128(routes.control_entry.0)
        .fixed(&routes.digest)
        .fixed(&request.rate_document.0)
        .fixed(&evidence.doc_commit);
    hash.update(&selectors.finish()?);
    for account in accounts {
        bind_account(&mut hash, &chart, account)?;
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
        let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "revaluation source")?)?;
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            return Err(KernelError::Corrupt(
                "revaluation source belongs to another book or branch".into(),
            ));
        }
        if entry.proposal.class == EntryClass::PENDING
            || entry.proposal.class.is_control()
            || !crate::migration::visible_at(db, &entry, at, &mut runs)?
        {
            continue;
        }
        if entry
            .proposal
            .legs
            .iter()
            .any(|leg| leg.account_ref == route.valuation_account)
        {
            let prior = match recognized_adjustment(
                &entry,
                row.created_at,
                request.source_account,
                &route,
                spec.base_unit,
            ) {
                Ok(prior) => prior,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let Some(old_routes) =
                fx_revaluation_routes_at(db, book, prior.closing_date, prior.observed_at)?
            else {
                return Ok(Err(invalid(
                    "a retained valuation adjustment has no original route map",
                )));
            };
            if old_routes.control_entry != prior.routes_entry
                || old_routes.digest != prior.routes_digest
                || old_routes.routes.get(&request.source_account) != Some(&route)
            {
                return Ok(Err(invalid(
                    "a retained valuation adjustment disagrees with its original routes",
                )));
            }
            for leg in &entry.proposal.legs {
                let prior_entity = match leg_entity(&spec, leg) {
                    Ok(entity) => entity,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                if prior_entity != prior.entity {
                    return Ok(Err(invalid(
                        "a retained valuation adjustment differs from its selected entity",
                    )));
                }
            }
        }
        if entry.proposal.effective_date <= date {
            entries.push((row.created_at, row.vid, entry));
        }
    }
    entries.sort_by_key(|(recorded_at, vid, _)| (*recorded_at, *vid));
    let mut source_native_net = 0_i128;
    let mut source_base_net = 0_i128;
    let mut prior_adjustment_net = 0_i128;
    for (recorded_at, vid, entry) in entries {
        for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
            if leg.account_ref != request.source_account
                && leg.account_ref != route.valuation_account
            {
                continue;
            }
            let leg_entity = match leg_entity(&spec, leg) {
                Ok(entity) => entity,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if leg_entity != entity {
                continue;
            }
            hash.update(&recorded_at.0.to_le_bytes());
            hash.update(&vid.0.to_le_bytes());
            hash.update(&entry.entry_digest);
            hash.update(&(ordinal as u64).to_le_bytes());
            if leg.account_ref == request.source_account {
                let Some(base) = leg.base_amount else {
                    return Ok(Err(unsupported(
                        "a foreign source contribution has no retained functional valuation",
                    )));
                };
                if leg.amount.unit != native_unit
                    || base.unit != spec.base_unit
                    || entry
                        .proposal
                        .base_totals
                        .as_ref()
                        .is_none_or(|total| total.unit_id != spec.base_unit.0)
                {
                    return Ok(Err(invalid(
                        "a source contribution does not have the route's native and functional units",
                    )));
                }
                if let Err(refusal) =
                    add_signed(&mut source_native_net, leg.side, leg.amount.mantissa)
                        .and_then(|()| add_signed(&mut source_base_net, leg.side, base.mantissa))
                {
                    return Ok(Err(refusal));
                }
            } else if let Err(refusal) =
                add_signed(&mut prior_adjustment_net, leg.side, leg.amount.mantissa)
            {
                return Ok(Err(refusal));
            }
        }
    }
    let Some(current_carrying_net) = source_base_net.checked_add(prior_adjustment_net) else {
        return Ok(Err(invalid("functional carrying amount overflow")));
    };
    let Some(native_magnitude) = source_native_net.checked_abs() else {
        return Ok(Err(invalid(
            "foreign exposure magnitude exceeds i128 range",
        )));
    };
    let conversion = match rate.to_rate(budget) {
        Ok(rate) => rate,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let converted = match Amount::new(native_unit, native_magnitude).convert(
        budget,
        spec.base_unit,
        &conversion,
        rate.rounding,
        &book.units,
    ) {
        Ok(amount) => amount,
        Err(error) => return Ok(Err(invalid(error))),
    };
    let target_base_net = if source_native_net < 0 {
        match converted.mantissa.checked_neg() {
            Some(value) => value,
            None => return Ok(Err(invalid("negative target exceeds i128 range"))),
        }
    } else {
        converted.mantissa
    };
    let Some(delta) = target_base_net.checked_sub(current_carrying_net) else {
        return Ok(Err(invalid("revaluation delta exceeds i128 range")));
    };
    let mut legs = Vec::new();
    let mut base_totals = None;
    if delta != 0 {
        let Some(magnitude) = delta.checked_abs() else {
            return Ok(Err(invalid("adjustment magnitude exceeds i128 range")));
        };
        let side = if delta > 0 { Side::Debit } else { Side::Credit };
        let opposite = if delta > 0 { Side::Credit } else { Side::Debit };
        let amount = Amount::new(spec.base_unit, magnitude);
        for (account, side) in [
            (route.valuation_account, side),
            (route.unrealized_account, opposite),
        ] {
            let mut leg = LegPayload::simple(side, account, amount);
            leg.base_amount = Some(amount);
            if let Some(entity) = entity {
                leg.dimension_set = vec![(LEGAL_ENTITY_DIMENSION, entity)];
            }
            legs.push(leg);
        }
        base_totals = Some(BaseTotals {
            unit_id: spec.base_unit.0,
            debits: magnitude,
            credits: magnitude,
            fx_law_oid: FxLawId::PeriodEndRevaluation.oid(),
            rate_doc_oids: vec![request.rate_document],
            residual: None,
        });
    }
    Ok(Ok(PreparedFxRevaluation {
        request: FxRevaluationRequest {
            entity,
            ..request.clone()
        },
        basis: FxRevaluationBasis {
            period: request.period.clone(),
            closing_date: date,
            observed_at: at,
            source_account: request.source_account,
            entity,
            routes_entry: routes.control_entry,
            routes_digest: routes.digest,
            rate_document: request.rate_document,
            rate_commit: evidence.doc_commit,
            source_digest: hash.finalize().0,
        },
        route,
        native_unit,
        base_unit: spec.base_unit,
        source_native_net,
        source_base_net,
        prior_adjustment_net,
        current_carrying_net,
        target_base_net,
        delta,
        legs,
        evidence,
        base_totals,
    }))
}

fn reproduces(
    observed: &PreparedFxRevaluation,
    basis: &FxRevaluationBasis,
    proposal: &EntryPayload,
) -> bool {
    let mut expected = observed.basis.clone();
    expected.observed_at = basis.observed_at;
    &expected == basis
        && observed.legs == proposal.legs
        && observed.base_totals == proposal.base_totals
        && !observed.is_noop()
        && proposal.evidence.contains(&observed.evidence)
}

/// Verify old source-bound adjustments in recorded order before exposing the
/// new result. Every old observation precedes that old publication. Earlier
/// adjustments in either fold have therefore already passed this loop; no
/// recursive call stack, opaque trusted marker, or caller amount is needed.
fn observe_verified<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    request: &FxRevaluationRequest,
    at: CommitSeq,
    budget: &mut ArithmeticBudget<'_, impl Sized>,
) -> Outcome<PreparedFxRevaluation> {
    let prepared = match observe(db, cx, book, request, at, budget)? {
        Ok(prepared) => prepared,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut adjustments = Vec::new();
    for row in db.vertices_at(at)? {
        cx.query()
            .checkpoint()
            .map_err(fgdb::WriteTxnError::Interrupted)?;
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(
            &row,
            property::FA_PAYLOAD,
            "prior revaluation basis",
        )?)?;
        if entry.proposal.class != EntryClass::REVALUATION
            || !entry
                .proposal
                .legs
                .iter()
                .any(|leg| leg.account_ref == prepared.route.valuation_account)
        {
            continue;
        }
        let basis = match recognized_adjustment(
            &entry,
            row.created_at,
            request.source_account,
            &prepared.route,
            prepared.base_unit,
        ) {
            Ok(basis) => basis,
            Err(refusal) => return Ok(Err(refusal)),
        };
        adjustments.push((row.created_at, row.vid, entry.proposal, basis));
    }
    adjustments.sort_by_key(|(created_at, vid, _, _)| (*created_at, *vid));
    if adjustments.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(KernelError::Corrupt(
            "multiple adjustments of one FX source were published in a single unguarded batch"
                .into(),
        ));
    }
    for (recorded_at, _, proposal, basis) in adjustments {
        let prior_request = FxRevaluationRequest {
            period: basis.period.clone(),
            source_account: basis.source_account,
            rate_document: basis.rate_document,
            entity: basis.entity,
        };
        let before_publication = CommitSeq(recorded_at.0.checked_sub(1).ok_or_else(|| {
            KernelError::Corrupt("a retained revaluation has sequence zero".into())
        })?);
        for prefix in [basis.observed_at, before_publication] {
            let reproduced = match observe(db, cx, book, &prior_request, prefix, budget)? {
                Ok(reproduced) => reproduced,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if !reproduces(&reproduced, &basis, &proposal) {
                return Err(KernelError::Corrupt(
                    "a retained FX adjustment does not reproduce its original observation and publication basis".into(),
                ));
            }
        }
    }
    Ok(Ok(prepared))
}

/// Decode present provenance before any aggregate observation. Missing basis
/// is judged only after exact recorded-outcome recognition, preserving legacy
/// immutable retries without permitting a new caller-supplied revaluation.
pub(crate) fn admit(proposal: &EntryPayload) -> Result<Option<FxRevaluationBasis>, Refusal> {
    let Some((_, raw)) = proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
    else {
        return Ok(None);
    };
    if proposal.class != EntryClass::REVALUATION
        || proposal.schema_minor != EXTENSIONS_MINOR
        || proposal.extensions.len() != 1
        || !matches!(&proposal.origin, EntryOrigin::Intent { intent_kind: 1, .. })
        || proposal.control.is_some()
        || proposal.pending.is_some()
        || !proposal.supersession.is_empty()
        || proposal.legs.iter().any(|leg| !leg.settles.is_empty())
    {
        return Err(invalid(
            "revaluation provenance is valid only on its intrinsic Revaluation PostEntry",
        ));
    }
    let basis = FxRevaluationBasis::decode(raw).map_err(invalid)?;
    if proposal.effective_date != basis.closing_date
        || proposal
            .effective_period
            .as_ref()
            .map(|period| period.code.as_str())
            != Some(basis.period.as_str())
    {
        return Err(invalid(
            "the entry's period or date differs from its retained revaluation basis",
        ));
    }
    Ok(Some(basis))
}

pub(crate) fn missing_basis() -> Refusal {
    unsupported(
        "a new Revaluation requires the native source-bound computation basis; arbitrary caller balances or balanced legs are not admitted",
    )
}

pub(crate) fn is_source_bound(proposal: &EntryPayload) -> bool {
    proposal
        .base_totals
        .as_ref()
        .is_some_and(|totals| totals.fx_law_oid == FxLawId::PeriodEndRevaluation.oid())
        || proposal
            .extensions
            .iter()
            .any(|(tag, _)| *tag == FX_REVALUATION_EXTENSION)
}

pub(crate) fn unsupported_batch() -> Refusal {
    unsupported(
        "aggregate revaluation cannot join an atomic batch or draft promotion; review and commit its own native PostPlan",
    )
}

pub(crate) fn frontier_changed(expected: CommitSeq, actual: CommitSeq) -> Refusal {
    changed(format!(
        "the revaluation publication frontier changed from {} to {} after preparation",
        expected.0, actual.0
    ))
}

pub(crate) fn validate_post<V: Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    proposal: &EntryPayload,
    basis: &FxRevaluationBasis,
) -> Outcome<()> {
    if basis.observed_at > txn.basis()
        || proposal
            .effective_period
            .as_ref()
            .is_none_or(|period| period.calendar != book.calendar.id)
    {
        return Ok(Err(changed(
            "the retained revaluation basis is outside this period or snapshot",
        )));
    }
    // QueryCx installs the caller's restricted runtime context. The arithmetic
    // meter inherits its cancellation, has no effects and is strictly bounded;
    // no detached context or fresh runtime is created by the kernel.
    cx.query().with_restriction(|| {
        let current = asupersync::Cx::current().ok_or_else(|| KernelError::Corrupt("revaluation arithmetic requires the installed caller context".into()))?;
        let arithmetic = current.restrict::<asupersync::cx::cap::None>();
        let mut budget = ArithmeticBudget::new(&arithmetic, BudgetLimits::uniform(1_000_000, 0), 4096);
        let request = FxRevaluationRequest { period: basis.period.clone(), source_account: basis.source_account, rate_document: basis.rate_document, entity: basis.entity };
        for at in [basis.observed_at, txn.basis()] {
            let observed = match observe_verified(db, cx, book, &request, at, &mut budget)? { Ok(observed) => observed, Err(refusal) => return Ok(Err(refusal)) };
            if !reproduces(&observed, basis, proposal) { return Ok(Err(changed("the Revaluation entry does not reproduce its original and current cumulative exposure, carrying basis, rate and routes"))); }
        }
        let _rate = txn.vertex(db, document_vid(&basis.rate_document))?;
        let _routes = txn.vertex(db, basis.routes_entry)?;
        let _root = txn.vertex_property(db, book_root(), property::FA_PAYLOAD)?;
        Ok(Ok(()))
    })
}
