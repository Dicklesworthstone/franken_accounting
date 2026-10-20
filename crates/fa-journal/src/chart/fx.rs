//! Journaled, effective-dated routes for source-bound period-end FX revaluation.
//!
//! A complete map grows by addition. An established source/valuation/unrealized
//! assignment cannot be reassigned or removed: its accumulated carrying
//! adjustment must continue to describe the same economic exposure.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, DecodeError, EncodeError, Entry, Erasable, Id128, Reader, Writer, domain_digest,
    entry_mirrors, entry_vid,
};
use fa_money::{UnitId, UnitKind, UnitRegistry};
use fa_policy::{Capability, Reach};
use fa_time::DateDay;
use fgdb::{Database, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{AccountEffectivity, admit_schema_change, schema_control_proposal};
use crate::genesis::{BookContext, BookSpec, UnitPolicy};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{AccountRow, book_root, bytes};

pub const SCHEMA_CHANGE_FX_REVALUATION_ROUTES: u16 = 14;
pub const MAX_FX_REVALUATION_ROUTES: usize = 4096;
const MAGIC: &[u8; 13] = b"FA-FX-ROUTES\0";
const VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FxRevaluationRoute {
    pub valuation_account: VId,
    pub unrealized_account: VId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxRevaluationRoutesRequest {
    pub principal: VId,
    pub effective_from: DateDay,
    pub routes: BTreeMap<VId, FxRevaluationRoute>,
    pub idempotency_key: Vec<u8>,
    pub description: Erasable<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxRevaluationRoutes {
    pub effective_from: DateDay,
    pub base_unit: UnitId,
    pub routes: BTreeMap<VId, FxRevaluationRoute>,
    pub digest: [u8; 32],
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxRevaluationRoutesRecorded {
    pub control_entry: VId,
    pub recorded_at: CommitSeq,
    pub digest: [u8; 32],
    pub already_recorded: bool,
}

#[derive(Clone, Debug)]
pub(super) struct FxRevaluationRoutesSpec {
    pub(super) effective_from: DateDay,
    base_unit: UnitId,
    routes: BTreeMap<VId, FxRevaluationRoute>,
}

impl FxRevaluationRoutesSpec {
    fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(VERSION)
            .i32(self.effective_from.0)
            .u32(self.base_unit.0)
            .u32(self.routes.len() as u32);
        for (source, route) in &self.routes {
            w.u128(source.0)
                .u128(route.valuation_account.0)
                .u128(route.unrealized_account.0);
        }
        w.finish()
    }

    pub(super) fn decode(raw: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(raw);
        if r.fixed::<13>("fx_routes.magic")? != *MAGIC || r.u16("fx_routes.version")? != VERSION {
            return Err(r.invalid("fx_routes.version"));
        }
        let effective_from = DateDay(r.i32("fx_routes.effective_from")?);
        let base_unit = UnitId(r.u32("fx_routes.base_unit")?);
        let pairs = r.list(MAX_FX_REVALUATION_ROUTES, "fx_routes.routes", |r| {
            Ok((
                VId(r.u128("fx_routes.source")?),
                FxRevaluationRoute {
                    valuation_account: VId(r.u128("fx_routes.valuation")?),
                    unrealized_account: VId(r.u128("fx_routes.unrealized")?),
                },
            ))
        })?;
        if pairs.is_empty() {
            return Err(r.invalid("fx_routes.routes"));
        }
        if pairs.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(r.unsorted("fx_routes.routes"));
        }
        r.finish()?;
        Ok(Self {
            effective_from,
            base_unit,
            routes: pairs.into_iter().collect(),
        })
    }

    fn digest(&self, book: Id128) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(
            b"fa:fx-revaluation-routes:v1",
            &[
                &book.0,
                &self.canonical_bytes().map_err(fa_model::EntryError::from)?,
            ],
        ))
    }

    pub(super) fn validate(
        &self,
        accounts: &BTreeMap<VId, AccountRow>,
        effectivity: &BTreeMap<VId, AccountEffectivity>,
        previous: &[FxRevaluationRoutes],
    ) -> Result<(), String> {
        if self.routes.is_empty() || self.routes.len() > MAX_FX_REVALUATION_ROUTES {
            return Err(format!(
                "an FX route map must contain 1..={MAX_FX_REVALUATION_ROUTES} routes"
            ));
        }
        let mut dedicated = BTreeSet::new();
        for (source, route) in &self.routes {
            let mut rows = Vec::with_capacity(3);
            for vid in [*source, route.valuation_account, route.unrealized_account] {
                let row = accounts
                    .get(&vid)
                    .ok_or_else(|| format!("FX route account {:032x} is undeclared", vid.0))?;
                if !row.is_leaf
                    || row.limit.is_some()
                    || !effectivity
                        .get(&vid)
                        .copied()
                        .unwrap_or_default()
                        .is_effective_at(self.effective_from)
                {
                    return Err(format!(
                        "FX route account {} must be an effective posting leaf without a balance limit",
                        row.code
                    ));
                }
                rows.push(row);
            }
            let [source_row, valuation, unrealized] = [rows[0], rows[1], rows[2]];
            if !matches!(
                AccountType(source_row.account_type),
                AccountType::ASSET | AccountType::LIABILITY
            ) || !matches!(source_row.unit_policy, UnitPolicy::Single(unit) if unit != self.base_unit)
            {
                return Err(format!(
                    "FX source {} must be a single foreign-currency Asset or Liability leaf",
                    source_row.code
                ));
            }
            if source == &route.valuation_account
                || source == &route.unrealized_account
                || route.valuation_account == route.unrealized_account
                || valuation.account_type != source_row.account_type
                || valuation.unit_policy != UnitPolicy::Single(self.base_unit)
                || !dedicated.insert(route.valuation_account)
            {
                return Err("each FX source requires a distinct, exclusively assigned base-unit valuation leaf of the same account type".into());
            }
            if !matches!(
                AccountType(unrealized.account_type),
                AccountType::REVENUE | AccountType::EXPENSE
            ) || unrealized.unit_policy != UnitPolicy::Single(self.base_unit)
            {
                return Err("the unrealized FX destination must be a distinct base-unit Revenue or Expense posting leaf".into());
            }
        }
        for old in previous {
            if old.base_unit != self.base_unit
                || old
                    .routes
                    .iter()
                    .any(|(source, route)| self.routes.get(source) != Some(route))
            {
                return Err("FX route updates may add sources but cannot remove or reassign an established source, valuation leaf or unrealized destination".into());
            }
        }
        Ok(())
    }

    fn validate_units(
        &self,
        accounts: &BTreeMap<VId, AccountRow>,
        units: &UnitRegistry,
    ) -> Result<(), String> {
        let currency = |unit| {
            units
                .get(unit)
                .is_some_and(|unit| matches!(unit.kind, UnitKind::Currency { .. }))
        };
        if !currency(self.base_unit) {
            return Err("FX routes require a registered functional currency".into());
        }
        for source in self.routes.keys() {
            if !accounts.get(source).is_some_and(
                |row| matches!(row.unit_policy, UnitPolicy::Single(unit) if currency(unit)),
            ) {
                return Err("every FX source must hold one registered foreign currency".into());
            }
        }
        Ok(())
    }

    pub(super) fn recorded(
        self,
        book: Id128,
        control_entry: VId,
        recorded_at: CommitSeq,
    ) -> Result<FxRevaluationRoutes, KernelError> {
        let digest = self.digest(book)?;
        Ok(FxRevaluationRoutes {
            effective_from: self.effective_from,
            base_unit: self.base_unit,
            routes: self.routes,
            digest,
            control_entry,
            recorded_at,
        })
    }
}

/// Low-level fixed-prefix selection. Callers admit current read authority
/// before inspecting this map; its base currency is checked against that prefix.
pub fn fx_revaluation_routes_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    effective_date: DateDay,
    known_at: CommitSeq,
) -> Result<Option<FxRevaluationRoutes>, KernelError> {
    let chart = super::read_at(db, book, known_at)?;
    let selected = chart
        .fx_revaluation_routes
        .iter()
        .filter(|map| map.effective_from <= effective_date)
        .max_by_key(|map| (map.effective_from, map.recorded_at, map.control_entry))
        .cloned();
    if let Some(map) = &selected {
        let root = db
            .vertex_at(book_root(), known_at)?
            .ok_or_else(|| KernelError::Corrupt("FX routes have no book root".into()))?;
        let spec = BookSpec::decode(&bytes(&root, property::FA_PAYLOAD, "FX routes book")?)?;
        if !root.labels.contains(&label::BOOK)
            || bytes(&root, property::BOOK_ID, "FX routes book identity")? != book.book_id.0
            || spec.book_id != book.book_id
            || map.base_unit != spec.base_unit
        {
            return Err(KernelError::Corrupt(
                "FX routes disagree with the selected book currency".into(),
            ));
        }
        FxRevaluationRoutesSpec {
            effective_from: map.effective_from,
            base_unit: map.base_unit,
            routes: map.routes.clone(),
        }
        .validate_units(chart.accounts(), &book.units)
        .map_err(KernelError::Corrupt)?;
    }
    Ok(selected)
}

fn invalid(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        detail,
        "plan §5.2 / §12.4 (journaled FX revaluation routes)",
        "declare a complete additive map from each foreign Asset/Liability leaf to its dedicated same-type base-unit valuation leaf and base-unit Revenue/Expense leaf",
    )
}

fn changed(detail: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CONFLICT,
        exit::CONFLICT,
        detail,
        "FG-LAW-FCW-01 (complete FX route and dedicated-account population)",
        "reload the chart and retry the complete FX route map",
    )
}

struct PreparedRoutes {
    txn: WriteTxn,
    capability: Capability,
    control_entry: VId,
    digest: [u8; 32],
}

enum Preparation {
    Recorded(FxRevaluationRoutesRecorded),
    Ready(Box<PreparedRoutes>),
}

fn authorize<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    capability: &Capability,
    principal: VId,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.book_id)
        .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
    {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    if let Err(refusal) = crate::policy::current_at(db, book, capability)? {
        return Ok(Err(refusal));
    }
    if let Some(refusal) = admit_schema_change(db, book, principal, capability)? {
        return Ok(Err(refusal));
    }
    Ok(Ok(()))
}

fn prepare<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: FxRevaluationRoutesRequest,
) -> Outcome<Preparation> {
    if let Err(refusal) = authorize(db, book, capability, request.principal)? {
        return Ok(Err(refusal));
    }
    let mut txn = db.begin(&cx.txn())?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let _epoch = crate::policy::epoch_witness(&txn, db)?;
    let root = txn
        .vertex(db, book_root())?
        .ok_or_else(|| KernelError::Corrupt("FX routes have no book root".into()))?;
    let book_spec = BookSpec::decode(&bytes(&root, property::FA_PAYLOAD, "FX routes book")?)?;
    if !root.labels.contains(&label::BOOK)
        || bytes(&root, property::BOOK_ID, "FX routes book identity")? != book.book_id.0
        || book_spec.book_id != book.book_id
    {
        txn.abort();
        return Err(KernelError::Corrupt(
            "FX route book identity differs".into(),
        ));
    }
    let spec = FxRevaluationRoutesSpec {
        effective_from: request.effective_from,
        base_unit: book_spec.base_unit,
        routes: request.routes,
    };
    if spec.routes.is_empty() || spec.routes.len() > MAX_FX_REVALUATION_ROUTES {
        txn.abort();
        return Ok(Err(invalid(
            "the FX route map is empty or exceeds the registered bound",
        )));
    }
    let digest = spec.digest(book.book_id)?;
    let proposal = schema_control_proposal(
        book,
        SCHEMA_CHANGE_FX_REVALUATION_ROUTES,
        spec.canonical_bytes().map_err(fa_model::EntryError::from)?,
        request.principal,
        request.effective_from,
        &request.idempotency_key,
        request.description,
    );
    let proposal_digest = proposal.proposal_digest()?;
    let control_entry = entry_vid(
        book.book_id,
        &request.principal.0.to_le_bytes(),
        &request.idempotency_key,
    );
    if let Some(row) = txn.vertex(db, control_entry)? {
        txn.abort();
        if !row.labels.contains(&label::ENTRY) {
            return Err(KernelError::Corrupt(
                "FX route identity is not an Entry".into(),
            ));
        }
        let stored = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "FX route retry")?)?;
        let same = stored.proposal_digest == proposal_digest
            || match (
                stored.proposal.semantic_digest(&book.seal_key),
                proposal.semantic_digest(&book.seal_key),
            ) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            };
        if !same {
            return Ok(Err(Refusal::new(
                code::IDEMPOTENCY_CONFLICT,
                exit::CONFLICT,
                "FX route key already names different content",
                "plan §4.9 (immutable keyed intent)",
                "retry the same map or choose a new key",
            )));
        }
        return Ok(Ok(Preparation::Recorded(FxRevaluationRoutesRecorded {
            control_entry,
            recorded_at: row.created_at,
            digest,
            already_recorded: true,
        })));
    }
    crate::entry_history::verify_entry_history(db, cx, book, Some(txn.basis()))?;
    let chart = super::read_at(db, book, txn.basis())?;
    if let Err(detail) = spec
        .validate(
            chart.accounts(),
            chart.effectivity(),
            &chart.fx_revaluation_routes,
        )
        .and_then(|()| spec.validate_units(chart.accounts(), &book.units))
    {
        txn.abort();
        return Ok(Err(invalid(detail)));
    }
    let existing: BTreeSet<_> = chart
        .fx_revaluation_routes
        .iter()
        .flat_map(|map| map.routes.values().map(|route| route.valuation_account))
        .collect();
    let new_valuation: BTreeSet<_> = spec
        .routes
        .values()
        .map(|route| route.valuation_account)
        .filter(|account| !existing.contains(account))
        .collect();
    for row in db.vertices_at(txn.basis())? {
        if row.labels.contains(&label::ENTRY) {
            let entry = Entry::decode(&bytes(
                &row,
                property::FA_PAYLOAD,
                "FX route account population",
            )?)?;
            if entry
                .proposal
                .legs
                .iter()
                .any(|leg| new_valuation.contains(&leg.account_ref))
            {
                txn.abort();
                return Ok(Err(invalid(
                    "a newly dedicated valuation leaf already has posting history; choose an unused leaf",
                )));
            }
        }
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::CHILD_OF);
    batch.create_vertex(control_entry, vec![label::ENTRY], entry_mirrors(&entry)?);
    if let Err(error) = txn.write(db, batch) {
        txn.abort();
        return Err(error.into());
    }
    Ok(Ok(Preparation::Ready(Box::new(PreparedRoutes {
        txn,
        capability: capability.clone(),
        control_entry,
        digest,
    }))))
}

/// Retain a complete map under current whole-book Read + SchemaChange authority.
/// The full-frontier guard protects both additive assignment and account vacancy.
pub async fn set_fx_revaluation_routes<V: Vfs + Clone>(
    db: &mut Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    capability: &Capability,
    request: FxRevaluationRoutesRequest,
) -> Outcome<FxRevaluationRoutesRecorded> {
    if let Err(refusal) = authorize(db, book, capability, request.principal)? {
        return Ok(Err(refusal));
    }
    cx.query()
        .checkpoint()
        .map_err(WriteTxnError::Interrupted)?;
    if let Err(refusal) = crate::scratch::ensure_history(db, cx).await? {
        return Ok(Err(refusal));
    }
    let mut prepared = match prepare(db, cx, book, capability, request)? {
        Err(refusal) => return Ok(Err(refusal)),
        Ok(Preparation::Recorded(recorded)) => return Ok(Ok(recorded)),
        Ok(Preparation::Ready(prepared)) => prepared,
    };
    if let Err(denial) = fa_policy::current(&prepared.capability, db.frontier()?) {
        prepared.txn.abort();
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    if db.frontier()? != prepared.txn.basis() {
        prepared.txn.abort();
        return Ok(Err(changed(
            "the journal changed after FX route validation",
        )));
    }
    match prepared.txn.commit(db, &cx.commit()).await {
        Ok(recorded_at) => Ok(Ok(FxRevaluationRoutesRecorded {
            control_entry: prepared.control_entry,
            recorded_at,
            digest: prepared.digest,
            already_recorded: false,
        })),
        Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
            Ok(Err(changed(detail)))
        }
        Err(error) => Err(error.into()),
    }
}
