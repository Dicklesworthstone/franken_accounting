//! Source-conserving network tracing (plan §11.5). The catalog exposes these
//! as separate procedures so the existing one-account laws retain their
//! versioned outputs. This is journal-account attribution, not bank-instrument
//! matching or a legal conclusion. Positive-normal Asset accounts are tracked;
//! exits to other account types and repayment of overdrafts are terminal.

mod engine;

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::genesis::BookContext;
use fa_model::AccountType;
use fa_money::{Amount, Side, UnitId, allocation::largest_remainder, wide::U256};
use fgdb_types::VId;

use crate::projection::{entity, entity_scope, scoped_entity};
use crate::{
    Cite, Finding, LanternError, Meter, Params, Procedure, Severity, Snapshot, SnapshotEntry,
    Statistic,
};

/// A selected source deposit followed through every asset-account transfer in
/// its native unit and legal entity, under one explicitly selected lot law.
pub struct NetworkTrace {
    law: engine::Law,
    params: Params,
    account: VId,
    source: VId,
}

/// Court-ordered restitution schedule (plan §11.5): parameterized tracing under
/// a court-designated law (`0 LIBR, 1 FIFO, 2 LIFO, 3 ProRata`), scope
/// (`0 SingleAccount, 1 Network`), intraday ordering, and replenishment mode.
pub struct RestitutionOrder {
    params: Params,
    account: VId,
    source: VId,
}

impl RestitutionOrder {
    pub fn with(params: Params, account: VId, source: VId) -> Self {
        Self {
            params,
            account,
            source,
        }
    }

    fn refuse(&self, name: &str, message: impl Into<String>) -> LanternError {
        LanternError::Parameter {
            procedure: "trace.restitution_order".into(),
            name: name.into(),
            message: message.into(),
        }
    }
}

impl Procedure for RestitutionOrder {
    fn id(&self) -> &'static str {
        "trace.restitution_order"
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn inputs(&self) -> Vec<(String, String)> {
        vec![
            ("account".into(), format!("{:032x}", self.account.0)),
            ("source".into(), format!("{:032x}", self.source.0)),
        ]
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let law_code = self.params.get("law")?;
        let (single_law, net_law) = match law_code {
            0 => (crate::trace::Law::Libr, engine::Law::Libr),
            1 => (crate::trace::Law::Fifo, engine::Law::Fifo),
            2 => (crate::trace::Law::Lifo, engine::Law::Lifo),
            3 => (crate::trace::Law::ProRata, engine::Law::ProRata),
            _ => {
                return Err(self.refuse("law", "0 LIBR, 1 FIFO, 2 LIFO, or 3 ProRata"));
            }
        };
        let replenishment = self.params.get("replenishment")?;
        if replenishment != 0 && replenishment != 1 {
            return Err(self.refuse("replenishment", "0 Never or 1 OnEvidence"));
        }
        if replenishment == 1 && law_code != 0 {
            return Err(self.refuse(
                "replenishment",
                "OnEvidence replenishment is only admissible when law = 0 (LIBR)",
            ));
        }
        let scope = self.params.get("scope")?;
        match scope {
            0 => {
                let single = crate::trace::Trace::with(
                    single_law,
                    self.params.clone(),
                    self.account,
                    self.source,
                );
                single.run_as(self.id(), self.version(), snapshot, book, work)
            }
            1 => {
                let trace = NetworkTrace {
                    law: net_law,
                    params: self.params.clone(),
                    account: self.account,
                    source: self.source,
                };
                trace.run_as(self.id(), true, law_code == 0, snapshot, book, work)
            }
            _ => Err(self.refuse("scope", "0 SingleAccount or 1 Network")),
        }
    }
}

impl NetworkTrace {
    pub fn with(id: &str, params: Params, account: VId, source: VId) -> Result<Self, LanternError> {
        let law = match id {
            "trace.network_libr" => engine::Law::Libr,
            "trace.network_fifo" => engine::Law::Fifo,
            "trace.network_lifo" => engine::Law::Lifo,
            "trace.network_pro_rata" => engine::Law::ProRata,
            _ => {
                return Err(LanternError::Unregistered {
                    procedure: id.into(),
                });
            }
        };
        Ok(Self {
            law,
            params,
            account,
            source,
        })
    }

    fn refuse_for(procedure_id: &str, name: &str, message: impl Into<String>) -> LanternError {
        LanternError::Parameter {
            procedure: procedure_id.into(),
            name: name.into(),
            message: message.into(),
        }
    }

    fn limit_for(
        &self,
        procedure_id: &str,
        name: &str,
        maximum: u32,
    ) -> Result<usize, LanternError> {
        let value = self.params.get_u32(name)?;
        if value == 0 || value > maximum {
            return Err(Self::refuse_for(
                procedure_id,
                name,
                format!("must be in 1..={maximum}"),
            ));
        }
        usize::try_from(value)
            .map_err(|_| Self::refuse_for(procedure_id, name, "not representable on this target"))
    }

    fn engine_error_for(procedure_id: &str, error: engine::Error) -> LanternError {
        match error {
            engine::Error::Limit(name) => Self::refuse_for(
                procedure_id,
                name,
                "network tracing exhausted this bound; no partial schedule was emitted; explicitly raise the bound within its registered maximum",
            ),
            engine::Error::Invalid(message) => Self::refuse_for(procedure_id, "source", message),
            engine::Error::Overflow(message) => LanternError::Overflow(message),
            engine::Error::Allocation => {
                LanternError::Overflow("network allocation did not conserve its capacities")
            }
            engine::Error::Interrupted => {
                LanternError::Overflow("network checkpoint stopped without a caller refusal")
            }
        }
    }
}

fn allocation(unit: UnitId, total: i128, capacities: &[i128]) -> Result<Vec<i128>, engine::Error> {
    let weights: Vec<u128> = capacities
        .iter()
        .map(|capacity| u128::try_from(*capacity).map_err(|_| engine::Error::Allocation))
        .collect::<Result<_, _>>()?;
    largest_remainder(Amount::new(unit, total), &weights)
        .map(|shares| shares.into_iter().map(|share| share.mantissa).collect())
        .map_err(|_| engine::Error::Allocation)
}

fn magnitude(value: U256) -> Result<i128, LanternError> {
    value
        .to_u128()
        .and_then(|v| i128::try_from(v).ok())
        .ok_or(LanternError::Overflow("net network movement"))
}

/// Remove intra-entry self movements before assigning counterparties. Native
/// debit/credit sums use U256, so a representable net is independent of leg
/// order even when a gross side exceeds i128. The remaining margins are
/// allocated under LargestRemainder in account-id order, decrementing debit
/// capacity after each credit. No synthetic posting or snapshot is created.
fn transfers(
    live: &[&SnapshotEntry],
    scope: &entity::Scope,
    unit: UnitId,
    legal_entity: Option<VId>,
    max_transfers: usize,
    max_steps: u64,
    work: &mut Meter<'_>,
) -> Result<(Vec<engine::Transfer>, u64), LanternError> {
    let mut out = Vec::new();
    let mut steps = 0u64;
    for entry in live {
        work.entry()?;
        let mut nets: BTreeMap<VId, (U256, U256)> = BTreeMap::new();
        for leg in &entry.entry.proposal.legs {
            work.leg()?;
            if leg.amount.unit != unit || scoped_entity(scope, leg)? != legal_entity {
                continue;
            }
            let amount = u128::try_from(leg.amount.mantissa)
                .map_err(|_| LanternError::Overflow("negative network leg"))?;
            let slot = nets
                .entry(leg.account_ref)
                .or_insert((U256::ZERO, U256::ZERO));
            let side = if leg.side == Side::Debit {
                &mut slot.0
            } else {
                &mut slot.1
            };
            *side = side
                .checked_add(U256::from_u128(amount))
                .ok_or(LanternError::Overflow("network leg sum"))?;
        }
        let mut credits = Vec::new();
        let mut debits = Vec::new();
        let mut debit_sum = U256::ZERO;
        let mut credit_sum = U256::ZERO;
        for (account, (debit, credit)) in nets {
            if debit > credit {
                let net = debit
                    .checked_sub(credit)
                    .ok_or(LanternError::Overflow("network debit net"))?;
                debit_sum = debit_sum
                    .checked_add(net)
                    .ok_or(LanternError::Overflow("network debit total"))?;
                debits.push((account, magnitude(net)?));
            } else if credit > debit {
                let net = credit
                    .checked_sub(debit)
                    .ok_or(LanternError::Overflow("network credit net"))?;
                credit_sum = credit_sum
                    .checked_add(net)
                    .ok_or(LanternError::Overflow("network credit total"))?;
                credits.push((account, magnitude(net)?));
            }
        }
        if debit_sum != credit_sum {
            return Err(LanternError::Overflow(
                "network partition is not natively balanced",
            ));
        }
        // Bound allocation work BEFORE building its potentially quadratic
        // transfer matrix; zero rounded cells still cost work.
        let cells = (credits.len() as u64)
            .checked_mul(debits.len() as u64)
            .ok_or(LanternError::Overflow("network allocation cells"))?;
        let price = cells
            .checked_mul(u64::from(debits.len().max(1).ilog2()) + 257)
            .ok_or(LanternError::Overflow("network allocation work"))?;
        steps = steps
            .checked_add(price)
            .ok_or(LanternError::Overflow("network projection work"))?;
        if steps >= max_steps {
            return Err(LanternError::Parameter { procedure: String::new(), name: "max_steps".into(), message: "network projection exhausted max_steps before tracing; no partial schedule was emitted".into() });
        }
        work.compare(price)?;
        let mut capacities: Vec<i128> = debits.iter().map(|(_, amount)| *amount).collect();
        for (from, total) in credits {
            let shares = allocation(unit, total, &capacities)
                .map_err(|_| LanternError::Overflow("network transport allocation"))?;
            if shares.len() != capacities.len() {
                return Err(LanternError::Overflow("network transport shape"));
            }
            let mut allocated = 0i128;
            for ((&(to, _), capacity), amount) in debits.iter().zip(&mut capacities).zip(shares) {
                if amount < 0 || amount > *capacity {
                    return Err(LanternError::Overflow(
                        "network transport exceeded capacity",
                    ));
                }
                *capacity = capacity
                    .checked_sub(amount)
                    .ok_or(LanternError::Overflow("network remaining capacity"))?;
                allocated = allocated
                    .checked_add(amount)
                    .ok_or(LanternError::Overflow("network allocated total"))?;
                if amount == 0 {
                    continue;
                }
                if out.len() == max_transfers {
                    return Err(LanternError::Parameter { procedure: String::new(), name: "max_transfers".into(), message: "network projection exceeded max_transfers; no partial schedule was emitted".into() });
                }
                out.push(engine::Transfer {
                    entry: entry.vid.0,
                    day: entry.entry.proposal.effective_date.0,
                    recorded: entry.recorded_at.0,
                    from: from.0,
                    to: to.0,
                    amount,
                });
            }
            if allocated != total {
                return Err(LanternError::Overflow("network credit margin"));
            }
        }
        if capacities.iter().any(|capacity| *capacity != 0) {
            return Err(LanternError::Overflow("network debit margin"));
        }
    }
    Ok((out, steps))
}

impl NetworkTrace {
    #[allow(clippy::too_many_arguments)]
    fn run_as(
        &self,
        procedure_id: &str,
        has_intraday_param: bool,
        has_replenishment_param: bool,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let claim = snapshot.coordinate.effective_through.ok_or_else(|| {
            Self::refuse_for(
                procedure_id,
                "effective_through",
                "network tracing requires an explicit inclusive effective cutoff",
            )
        })?;
        let intraday = if has_intraday_param {
            match self.params.get("intraday_order")? {
                0 => engine::IntradayOrder::StatementOrdinal,
                1 => {
                    return Err(Self::refuse_for(
                        procedure_id,
                        "intraday_order",
                        "ValueDate ordering needs retained value dates; a later slice",
                    ));
                }
                2 => engine::IntradayOrder::WithdrawalsFirst,
                3 => engine::IntradayOrder::DepositsFirst,
                _ => {
                    return Err(Self::refuse_for(
                        procedure_id,
                        "intraday_order",
                        "0 StatementOrdinal, 2 WithdrawalsFirst or 3 DepositsFirst",
                    ));
                }
            }
        } else {
            engine::IntradayOrder::StatementOrdinal
        };
        let replenish_on_evidence = if has_replenishment_param {
            match self.params.get("replenishment")? {
                0 => false,
                1 => true,
                _ => {
                    return Err(Self::refuse_for(
                        procedure_id,
                        "replenishment",
                        "0 Never or 1 OnEvidence",
                    ));
                }
            }
        } else {
            false
        };
        let max_input_legs = self.limit_for(procedure_id, "max_input_legs", 1_000_000)?;
        let max_transfers = self.limit_for(procedure_id, "max_transfers", 250_000)?;
        let max_fragments = self.limit_for(procedure_id, "max_fragments", 100_000)?;
        let max_hops = self.limit_for(procedure_id, "max_hops", 64)?;
        let max_steps = self.limit_for(procedure_id, "max_steps", 100_000_000)? as u64;
        // Admission before the netting/projection allocations. The existing
        // snapshot reader is separately responsible for bounding its read.
        let count = snapshot
            .entries
            .iter()
            .try_fold(0usize, |n, e| n.checked_add(e.entry.proposal.legs.len()))
            .ok_or_else(|| {
                Self::refuse_for(
                    procedure_id,
                    "max_input_legs",
                    "leg count exceeds this target's range",
                )
            })?;
        if count > max_input_legs {
            return Err(Self::refuse_for(
                procedure_id,
                "max_input_legs",
                "snapshot exceeds the network input bound",
            ));
        }
        let assets: BTreeSet<u128> = snapshot
            .accounts
            .iter()
            .filter(|(_, a)| a.account_type == AccountType::ASSET.0 && a.normal_balance == 0)
            .map(|(vid, _)| vid.0)
            .collect();
        if !assets.contains(&self.account.0) {
            return Err(Self::refuse_for(
                procedure_id,
                "account",
                "choose a debit-normal Asset account; credit-normal and non-asset destinations are terminal in this procedure",
            ));
        }
        let live = snapshot.live_postings_through(Some(claim))?;
        for e in &live {
            for leg in &e.entry.proposal.legs {
                if !snapshot.accounts.contains_key(&leg.account_ref) {
                    return Err(LanternError::Overflow(
                        "network leg has no historical account metadata",
                    ));
                }
            }
        }
        let scope = entity_scope(live.iter().flat_map(|e| &e.entry.proposal.legs))?;
        let mut selected = entity::Source::default();
        let mut source_docs = BTreeSet::new();
        for e in live.iter().filter(|e| e.vid == self.source) {
            for ev in &e.entry.proposal.evidence {
                source_docs.insert(ev.document_oid);
            }
            for leg in &e.entry.proposal.legs {
                if leg.account_ref == self.account
                    && leg.side == Side::Debit
                    && leg.amount.mantissa > 0
                {
                    selected
                        .observe(leg.amount.unit.0, scoped_entity(&scope, leg)?.map(|v| v.0))
                        .map_err(|_| Self::refuse_for(procedure_id, "source", "source deposit spans multiple units or legal entities; select an unambiguous source"))?;
                }
            }
        }
        let (unit, legal_entity) = selected.selected().ok_or_else(|| {
            Self::refuse_for(
                procedure_id,
                "source",
                "source is not a live deposit at the selected known-at/effective coordinate",
            )
        })?;
        let unit = UnitId(unit);
        let mut replenish_entries = BTreeSet::new();
        if replenish_on_evidence {
            for e in &live {
                if e.vid != self.source
                    && ((!source_docs.is_empty()
                        && e.entry
                            .proposal
                            .evidence
                            .iter()
                            .any(|ev| source_docs.contains(&ev.document_oid)))
                        || e.entry
                            .proposal
                            .supersession
                            .iter()
                            .any(|s| s.target.vid == self.source))
                {
                    replenish_entries.insert(e.vid.0);
                }
            }
        }
        let (edges, projection_steps) = transfers(
            &live,
            &scope,
            unit,
            legal_entity.map(VId),
            max_transfers,
            max_steps,
            work,
        )
        .map_err(|error| match error {
            LanternError::Parameter { name, message, .. } => {
                Self::refuse_for(procedure_id, &name, message)
            }
            other => other,
        })?;
        let comparisons_before_engine = work.work().comparisons;
        let mut interrupted = None;
        let result = engine::trace_with_options(
            &edges,
            &assets,
            (self.source.0, self.account.0),
            self.law,
            intraday,
            &replenish_entries,
            engine::Limits {
                max_transfers,
                max_fragments,
                max_hops,
                max_steps: max_steps - projection_steps,
            },
            &mut |steps| {
                work.compare(steps).map_err(|error| {
                    interrupted = Some(error);
                    engine::Error::Interrupted
                })
            },
            |amount, weights| allocation(unit, amount, weights),
        );
        // Keep the caller's original typed budget/cancellation refusal. The
        // engine's own limits remain independent, and no partial report can
        // escape even if an internal path ever swallows its callback error.
        if let Some(error) = interrupted {
            return Err(error);
        }
        let report = result.map_err(|e| Self::engine_error_for(procedure_id, e))?;
        if work
            .work()
            .comparisons
            .checked_sub(comparisons_before_engine)
            != Some(report.steps)
        {
            return Err(LanternError::Overflow(
                "network engine work does not reconcile to its caller's meter",
            ));
        }
        let scale = crate::unit_scale(book, unit.0)?;
        let entity_name =
            legal_entity.map_or_else(|| "implicit-book".into(), |v| format!("{v:032x}"));
        report.positions.into_iter().map(|position| {
            let name = match position.disposition {
                engine::Disposition::Held => "held_mantissa",
                engine::Disposition::Spent => "spent_mantissa",
                engine::Disposition::RepaidOverdraft => "overdraft_repaid_mantissa",
            };
            let mut cites = vec![Cite::Account(VId(position.account)), Cite::Entry(self.source)];
            for hop in &position.path {
                cites.extend([Cite::Entry(VId(hop.entry)), Cite::Account(VId(hop.from)), Cite::Account(VId(hop.to))]);
            }
            Ok(Finding {
                procedure: procedure_id.into(),
                version: self.version(),
                severity: Severity::Info,
                statistic: Statistic { name: name.into(), value: position.amount, scale, population: edges.len() as u64 },
                cites,
                narrative: format!("{}; unit {}; entity {}; disposition {:?}; account {:032x}; {} hops through {}; source total {}. Sum position statistics once: held + spent + overdraft_repaid = source. After destination/source citations, ordered (entry, from, to) triples encode the full path. Counterparties: net-account LargestRemainder with remaining capacities; same-day order: recorded sequence, then entry id. No claim of bank-instrument matching or legal ownership.", procedure_id, unit.0, entity_name, position.disposition, position.account, position.path.len(), claim.0, report.source_amount),
            })
        }).collect()
    }
}

impl Procedure for NetworkTrace {
    fn id(&self) -> &'static str {
        match self.law {
            engine::Law::Libr => "trace.network_libr",
            engine::Law::Fifo => "trace.network_fifo",
            engine::Law::Lifo => "trace.network_lifo",
            engine::Law::ProRata => "trace.network_pro_rata",
        }
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn inputs(&self) -> Vec<(String, String)> {
        vec![
            ("account".into(), format!("{:032x}", self.account.0)),
            ("source".into(), format!("{:032x}", self.source.0)),
        ]
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let has_intraday = matches!(self.law, engine::Law::Libr | engine::Law::ProRata);
        let has_replenish = matches!(self.law, engine::Law::Libr);
        self.run_as(self.id(), has_intraday, has_replenish, snapshot, book, work)
    }
}
