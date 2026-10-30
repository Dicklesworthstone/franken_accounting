//! Independent aggregate PeriodEndRevaluation v1 source replay.
//!
//! A balanced adjustment is insufficient. Both the reviewed observation and
//! the immediately preceding committed prefix must reproduce its complete
//! exposure, cumulative carrying adjustment, routing and source commitment.
//! Item-allocated revaluation has a different law and remains unsupported.

use super::{
    BookParameters, LeafEnvelope, Leg, ParsedEntry, Rate, Reader, ReportError, failed, framed_hash,
    law_oid, metadata, registry,
};
use crate::codec::Writer;
use crate::envelope::proposal_after_legs;
use std::collections::{BTreeMap, BTreeSet};

fn invalid(detail: &str) -> ReportError {
    failed("functional_revaluation", detail)
}

struct Basis {
    period: String,
    date: i32,
    observed_at: u64,
    source: u128,
    entity: Option<u128>,
    routes_entry: u128,
    routes_digest: [u8; 32],
    rate: [u8; 32],
    rate_commit: [u8; 32],
    source_digest: [u8; 32],
}

impl Basis {
    fn read(bytes: &[u8]) -> Result<Self, ReportError> {
        let mut r = Reader::new(bytes);
        if r.fixed::<14>("revaluation.magic")? != *b"FA-FX-REVALUE\0"
            || r.u16("revaluation.version")? != 1
        {
            return Err(failed(
                "supported_report",
                "portable functional reports support aggregate FX revaluation v1; item allocation requires its separate source replay",
            ));
        }
        let result = Self {
            period: super::text(&mut r, 64, "revaluation.period")?.into(),
            date: r.i32("revaluation.date")?,
            observed_at: r.u64("revaluation.observed_at")?,
            source: r.u128("revaluation.source")?,
            entity: r
                .present("revaluation.entity")?
                .then(|| r.u128("revaluation.entity"))
                .transpose()?,
            routes_entry: r.u128("revaluation.routes_entry")?,
            routes_digest: r.fixed("revaluation.routes_digest")?,
            rate: r.fixed("revaluation.rate")?,
            rate_commit: r.fixed("revaluation.rate_commit")?,
            source_digest: r.fixed("revaluation.source_digest")?,
        };
        r.finish("revaluation basis")?;
        if result.period.is_empty() || result.observed_at == 0 {
            return Err(invalid("empty revaluation period or observation"));
        }
        Ok(result)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Route {
    valuation: u128,
    unrealized: u128,
}

struct Routes {
    effective: i32,
    sequence: u64,
    identity: u128,
    digest: [u8; 32],
    rows: BTreeMap<u128, Route>,
}

fn routes(
    raw: &[u8],
    sequence: u64,
    identity: u128,
    spec: &BookParameters,
) -> Result<Routes, ReportError> {
    let mut r = Reader::new(raw);
    if r.fixed::<13>("routes.magic")? != *b"FA-FX-ROUTES\0" || r.u16("routes.version")? != 1 {
        return Err(invalid("unsupported revaluation route declaration"));
    }
    let effective = r.i32("routes.effective")?;
    if r.u32("routes.base")? != spec.base {
        return Err(invalid("revaluation route base differs from the book"));
    }
    let count = r.count(4096, 48, "routes.rows")?;
    if count == 0 {
        return Err(invalid("empty revaluation route map"));
    }
    let mut rows = BTreeMap::new();
    let mut dedicated = BTreeSet::new();
    let mut previous = None;
    for _ in 0..count {
        let source = r.u128("routes.source")?;
        let route = Route {
            valuation: r.u128("routes.valuation")?,
            unrealized: r.u128("routes.unrealized")?,
        };
        if previous.is_some_and(|last| last >= source)
            || source == route.valuation
            || source == route.unrealized
            || route.valuation == route.unrealized
            || !dedicated.insert(route.valuation)
        {
            return Err(invalid(
                "revaluation routes are ambiguous or share a valuation account",
            ));
        }
        previous = Some(source);
        rows.insert(source, route);
    }
    r.finish("revaluation routes")?;
    Ok(Routes {
        effective,
        sequence,
        identity,
        digest: framed_hash(b"fa:fx-revaluation-routes:v1", &[&spec.book, raw]),
        rows,
    })
}

fn route_accounts<'a>(
    schema: &'a metadata::Schema,
    source: u128,
    route: Route,
    day: i32,
    spec: &BookParameters,
    registry: &registry::FunctionalRegistry,
) -> Result<[&'a metadata::Account; 3], ReportError> {
    let get = |id| {
        let account = schema
            .accounts
            .get(&id)
            .ok_or_else(|| invalid("route account is absent"))?;
        let [opened, closed, promoted] = schema
            .account_effectivity
            .get(&id)
            .copied()
            .unwrap_or_default();
        if !account.is_leaf
            || account.limit.is_some()
            || opened.is_some_and(|start| start > day)
            || closed.is_some_and(|end| end <= day)
            || matches!((opened, closed), (Some(a), Some(b)) if a >= b)
            || matches!((opened, promoted), (Some(a), Some(b)) if a > b)
            || matches!((promoted, closed), (Some(a), Some(b)) if a > b)
        {
            return Err(invalid(
                "route accounts must be effective posting leaves without limits",
            ));
        }
        Ok(account)
    };
    let accounts = [get(source)?, get(route.valuation)?, get(route.unrealized)?];
    let [foreign, valuation, unrealized] = accounts;
    let currency = u32::try_from(foreign.unit_policy).ok().filter(|unit| {
        *unit != spec.base && registry.units.get(unit).is_some_and(|unit| unit.currency)
    });
    if !matches!(foreign.account_type, 1 | 2)
        || currency.is_none()
        || valuation.account_type != foreign.account_type
        || valuation.unit_policy != i64::from(spec.base)
        || !matches!(unrealized.account_type, 4 | 5)
        || unrealized.unit_policy != i64::from(spec.base)
    {
        return Err(invalid(
            "routes require a foreign Asset/Liability, same-type base valuation and base Revenue/Expense",
        ));
    }
    Ok(accounts)
}

pub(super) fn bind_account(
    w: &mut Writer,
    id: u128,
    account: &metadata::Account,
    schema: &metadata::Schema,
) {
    w.u128(id)
        .bytes(account.code.as_bytes())
        .bytes(account.name.as_bytes())
        .u8(account.account_type)
        .u8(account.normal_balance)
        .u8(u8::from(account.is_leaf))
        .u64(account.created_at);
    match account.unit_policy {
        -1 => {
            w.u8(1);
        }
        -2 => {
            w.u8(2);
        }
        unit => {
            w.u8(0).u32(unit as u32);
        }
    }
    let dates = schema
        .account_effectivity
        .get(&id)
        .copied()
        .unwrap_or_default();
    let mut effectivity = Writer::default();
    if dates.iter().any(Option::is_some) {
        effectivity.fixed(b"fa:account-effectivity:v1");
        for date in dates {
            effectivity.u8(u8::from(date.is_some()));
            if let Some(date) = date {
                effectivity.i32(date);
            }
        }
    }
    w.bytes(&effectivity.buf);
}

struct History<'a> {
    spec: &'a BookParameters,
    registry: &'a registry::FunctionalRegistry,
    rates: &'a BTreeMap<[u8; 32], Rate>,
    envelopes: &'a [LeafEnvelope],
    records: &'a [(usize, &'a [u8])],
    infos: &'a BTreeMap<usize, metadata::EntryInfo<'a>>,
    legs: &'a [Vec<Leg>],
    parsed: &'a BTreeMap<usize, ParsedEntry>,
    activations: &'a BTreeMap<u64, u64>,
    bases: BTreeMap<usize, Basis>,
    order: Vec<usize>,
}

impl History<'_> {
    fn snapshot(&self, at: u64) -> Result<(metadata::Schema, Vec<Routes>), ReportError> {
        let mut schema = metadata::Schema::default();
        let mut declarations: Vec<Routes> = Vec::new();
        let mut posted = BTreeSet::new();
        for &index in &self.order {
            let envelope = &self.envelopes[index];
            if envelope.commit_seq > at {
                break;
            }
            let info = &self.infos[&index];
            if let Some((kind, raw)) = info.schema {
                schema.apply(kind, raw, &self.spec.book, envelope.commit_seq)?;
                if kind == 14 {
                    let map = routes(raw, envelope.commit_seq, info.identity, self.spec)?;
                    for (&source, &route) in &map.rows {
                        route_accounts(
                            &schema,
                            source,
                            route,
                            map.effective,
                            self.spec,
                            self.registry,
                        )?;
                        if declarations
                            .iter()
                            .all(|old| !old.rows.contains_key(&source))
                            && posted.contains(&route.valuation)
                        {
                            return Err(invalid(
                                "a newly dedicated valuation account already has posting history",
                            ));
                        }
                    }
                    if declarations.iter().any(|old| {
                        old.rows
                            .iter()
                            .any(|(source, route)| map.rows.get(source) != Some(route))
                    }) {
                        return Err(invalid(
                            "an established revaluation route was removed or reassigned",
                        ));
                    }
                    declarations.push(map);
                }
            }
            if envelope.class == 16 {
                let proposal = &self.records[index].1[..self.records[index].0];
                let mut r = proposal_after_legs(proposal)?;
                if !r.present("period.control")? || r.u8("period.tag")? != 0 {
                    return Err(invalid("PeriodControl lacks a transition"));
                }
                let calendar = super::text(&mut r, 128, "period.calendar")?;
                let code = super::text(&mut r, 128, "period.code")?;
                let from = r.u8("period.from")?;
                let to = r.u8("period.to")?;
                let (start, end, _, _) = schema
                    .period_state(code)
                    .ok_or_else(|| invalid("period transition names an absent period"))?;
                let date = if from == 0 {
                    Some(start)
                } else {
                    end.checked_sub(1)
                };
                if info.period != Some((calendar, code)) || envelope.effective_day != date {
                    return Err(invalid(
                        "period transition header differs from its period-law coordinate",
                    ));
                }
                schema.transition_period(calendar, code, from, to)?;
            }
            posted.extend(self.legs[index].iter().map(|leg| leg.account));
        }
        Ok((schema, declarations))
    }

    fn entity(&self, index: usize, ordinal: usize) -> Result<Option<u128>, ReportError> {
        let dimensions = &self.parsed[&index].details[ordinal].dimensions;
        // Fund balance is a separate accounting law. Other registered
        // analytic dimensions close with the account, as in the native law.
        if dimensions
            .iter()
            .any(|(kind, _)| !matches!(kind, 1..=6 | 8 | 9))
        {
            return Err(failed(
                "supported_report",
                "this dimension has no aggregate revaluation treatment",
            ));
        }
        Ok(dimensions
            .iter()
            .find(|(kind, _)| *kind == 1)
            .map(|(_, id)| *id)
            .or_else(|| {
                (self.spec.entities.len() == 1)
                    .then(|| *self.spec.entities.keys().next().expect("one entity"))
            }))
    }

    fn shape(&self, index: usize, basis: &Basis, route: Route) -> Result<(), ReportError> {
        let entry = &self.parsed[&index];
        let Some(claim) = &entry.base else {
            return Err(invalid("revaluation has no functional totals"));
        };
        let [first, second] = self.legs[index].as_slice() else {
            return Err(invalid(
                "aggregate revaluation requires exactly two ordered adjustment legs",
            ));
        };
        if self.envelopes[index].class != 10
            || self.envelopes[index].effective_day != Some(basis.date)
            || self.infos[&index].period
                != Some((self.spec.calendar.as_str(), basis.period.as_str()))
            || basis.observed_at >= self.envelopes[index].commit_seq
            || first.account != route.valuation
            || second.account != route.unrealized
            || first.debit == second.debit
            || first.unit != self.spec.base
            || second.unit != self.spec.base
            || first.mantissa != second.mantissa
            || claim.law != law_oid(2)
            || claim.rates != [basis.rate]
            || claim.residual.is_some()
            || entry
                .details
                .iter()
                .any(|detail| !detail.settlements.is_empty())
        {
            return Err(invalid(
                "revaluation legs, law or coordinate differ from their source-bound route",
            ));
        }
        let dimensions: Vec<_> = basis.entity.into_iter().map(|entity| (1, entity)).collect();
        if entry
            .details
            .iter()
            .any(|detail| detail.dimensions != dimensions)
            || basis
                .entity
                .is_some_and(|id| !self.spec.entities.contains_key(&id))
            || basis.entity.is_none() && !self.spec.entities.is_empty()
        {
            return Err(invalid(
                "revaluation must select exactly its declared legal entity",
            ));
        }
        Ok(())
    }

    fn reproduce(&self, index: usize, basis: &Basis, at: u64) -> Result<(), ReportError> {
        let (schema, declarations) = self.snapshot(at)?;
        let (start, end, kind, state) = schema
            .period_state(&basis.period)
            .ok_or_else(|| invalid("revaluation period is absent at the observation"))?;
        if kind != 0 || !matches!(state, 1..=3) || end.checked_sub(1) != Some(basis.date) {
            return Err(invalid(
                "revaluation requires the final included date of an Open, SoftClosed or Closed normal period",
            ));
        }
        let map = declarations
            .iter()
            .filter(|map| map.effective <= basis.date)
            .max_by_key(|map| (map.effective, map.sequence, map.identity))
            .ok_or_else(|| invalid("no effective revaluation routes at the observation"))?;
        let route = *map
            .rows
            .get(&basis.source)
            .ok_or_else(|| invalid("foreign source has no revaluation route"))?;
        if map.identity != basis.routes_entry || map.digest != basis.routes_digest {
            return Err(invalid(
                "retained revaluation route identity or digest is stale",
            ));
        }
        self.shape(index, basis, route)?;
        let accounts = route_accounts(
            &schema,
            basis.source,
            route,
            basis.date,
            self.spec,
            self.registry,
        )?;
        let native = u32::try_from(accounts[0].unit_policy)
            .map_err(|_| invalid("source currency is absent"))?;
        let rate = self
            .rates
            .get(&basis.rate)
            .ok_or_else(|| invalid("closing Rate is absent"))?;
        if rate.commitment != basis.rate_commit
            || rate.purpose != 2
            || !rate.canonical_mime
            || rate.date != basis.date
            || rate.base != self.spec.base
            || rate.quote != native
        {
            return Err(invalid(
                "closing Rate purpose, date, currencies or commitment differ",
            ));
        }
        // Source observation requires the Rate's authenticated intake to
        // precede that observation, not merely the later adjustment.
        if !self
            .envelopes
            .iter()
            .zip(self.records)
            .any(|(envelope, &(len, raw))| {
                envelope.kind == crate::envelope::KIND_IMPORT_RECEIPT
                    && envelope.commit_seq <= at
                    && super::receipt(raw, len).is_ok_and(|(oid, _, _)| oid == basis.rate)
            })
        {
            return Err(invalid(
                "closing Rate was not retained at the reviewed observation",
            ));
        }
        let mut source = Writer::default();
        source
            .fixed(&self.spec.book)
            .bytes(self.spec.calendar.as_bytes())
            .bytes(basis.period.as_bytes())
            .i32(start)
            .i32(end)
            .u8(state)
            .u128(basis.source)
            .u8(u8::from(basis.entity.is_some()));
        if let Some(entity) = basis.entity {
            source.u128(entity);
        }
        source
            .u32(native)
            .u32(self.spec.base)
            .u128(map.identity)
            .fixed(&map.digest)
            .fixed(&basis.rate)
            .fixed(&basis.rate_commit);
        for (id, account) in [basis.source, route.valuation, route.unrealized]
            .into_iter()
            .zip(accounts)
        {
            bind_account(&mut source, id, account, &schema);
        }
        let (mut exposure, mut carrying, mut adjustment) = (0i128, 0i128, 0i128);
        for &previous in &self.order {
            let envelope = &self.envelopes[previous];
            if envelope.commit_seq > at {
                break;
            }
            if envelope.class == 2
                || envelope.class >= 16
                || envelope.class == 12
                    && self
                        .activations
                        .get(&(previous as u64))
                        .is_none_or(|seq| *seq > at)
            {
                continue;
            }
            if self.legs[previous]
                .iter()
                .any(|leg| leg.account == route.valuation)
            {
                let old = self.bases.get(&previous).ok_or_else(|| invalid("dedicated valuation history contains an unrelated or unsupported adjustment"))?;
                if old.source != basis.source {
                    return Err(invalid("valuation account belongs to another source"));
                }
                self.shape(previous, old, route)?;
            }
            if envelope.effective_day.is_none_or(|date| date > basis.date) {
                continue;
            }
            for (ordinal, leg) in self.legs[previous].iter().enumerate() {
                if ![basis.source, route.valuation].contains(&leg.account)
                    || self.entity(previous, ordinal)? != basis.entity
                {
                    continue;
                }
                source
                    .u64(envelope.commit_seq)
                    .u128(self.infos[&previous].identity)
                    .fixed(&envelope.record_digest)
                    .u64(ordinal as u64);
                let add = |sum: &mut i128, value: i128| -> Result<(), ReportError> {
                    *sum = if leg.debit {
                        sum.checked_add(value)
                    } else {
                        sum.checked_sub(value)
                    }
                    .ok_or_else(|| {
                        invalid("cumulative exposure or carrying amount exceeds i128")
                    })?;
                    Ok(())
                };
                if leg.account == basis.source {
                    if leg.unit != native
                        || self.parsed[&previous].details[ordinal]
                            .base_amount
                            .is_none()
                    {
                        return Err(invalid(
                            "foreign source lacks its retained functional valuation",
                        ));
                    }
                    add(&mut exposure, leg.mantissa)?;
                    add(&mut carrying, self.parsed[&previous].amounts[ordinal])?;
                } else {
                    add(&mut adjustment, leg.mantissa)?;
                }
            }
        }
        if crate::blake3::hash_parts(b"fa:fx-revaluation-source:v1", &[&source.buf])
            != basis.source_digest
        {
            return Err(invalid(
                "complete revaluation source commitment differs at observation or publication",
            ));
        }
        let magnitude = exposure
            .checked_abs()
            .ok_or_else(|| invalid("exposure magnitude exceeds i128"))?;
        let converted = super::super::arithmetic::convert(
            magnitude,
            self.registry.units[&native].scale,
            self.registry.units[&self.spec.base].scale,
            rate.numerator,
            rate.denominator,
        )?;
        let target = if exposure < 0 {
            converted.checked_neg()
        } else {
            Some(converted)
        }
        .ok_or_else(|| invalid("revaluation target exceeds i128"))?;
        let delta = carrying
            .checked_add(adjustment)
            .and_then(|current| target.checked_sub(current))
            .ok_or_else(|| invalid("revaluation delta exceeds i128"))?;
        let first = &self.legs[index][0];
        if delta == 0 || delta.checked_abs() != Some(first.mantissa) || first.debit != (delta > 0) {
            return Err(invalid(
                "recorded adjustment differs from the independently repriced cumulative delta",
            ));
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify<'a>(
    spec: &'a BookParameters,
    registry: &'a registry::FunctionalRegistry,
    rates: &'a BTreeMap<[u8; 32], Rate>,
    envelopes: &'a [LeafEnvelope],
    records: &'a [(usize, &'a [u8])],
    infos: &'a BTreeMap<usize, metadata::EntryInfo<'a>>,
    legs: &'a [Vec<Leg>],
    parsed: &'a BTreeMap<usize, ParsedEntry>,
    activations: &'a BTreeMap<u64, u64>,
) -> Result<(), ReportError> {
    let mut bases = BTreeMap::new();
    let mut publications = BTreeSet::new();
    for (&index, info) in infos {
        if let Some(raw) = info.fx_revaluation_basis {
            let basis = Basis::read(raw)?;
            if infos.keys().any(|other| {
                *other != index && envelopes[*other].commit_seq == envelopes[index].commit_seq
            }) {
                return Err(invalid(
                    "aggregate revaluation requires its own Entry publication; a sibling effect has no admitted execution order",
                ));
            }
            if !publications.insert((basis.source, envelopes[index].commit_seq)) {
                return Err(invalid(
                    "multiple revaluations of one source share an unguarded publication",
                ));
            }
            bases.insert(index, basis);
        } else if envelopes[index].class != 4
            && parsed[&index]
                .base
                .as_ref()
                .is_some_and(|base| base.law == law_oid(2))
        {
            return Err(invalid(
                "PeriodEndRevaluation requires its complete source-bound basis",
            ));
        }
    }
    let mut order: Vec<_> = infos.keys().copied().collect();
    order.sort_by_key(|index| (envelopes[*index].commit_seq, infos[index].identity));
    let history = History {
        spec,
        registry,
        rates,
        envelopes,
        records,
        infos,
        legs,
        parsed,
        activations,
        bases,
        order,
    };
    for &index in &history.order {
        if let Some(basis) = history.bases.get(&index) {
            let before = envelopes[index]
                .commit_seq
                .checked_sub(1)
                .ok_or_else(|| invalid("revaluation has sequence zero"))?;
            if basis.observed_at > before {
                return Err(invalid(
                    "revaluation observation does not precede publication",
                ));
            }
            history.reproduce(index, basis, basis.observed_at)?;
            if before != basis.observed_at {
                history.reproduce(index, basis, before)?;
            }
        }
    }
    Ok(())
}
