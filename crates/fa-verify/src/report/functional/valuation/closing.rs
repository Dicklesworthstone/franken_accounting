//! Independent native v1 and retained-carrying v2 YearEndClose replay.
//!
//! Every claimed close is rebuilt at its original observation and immediately
//! before publication. Older native closes are checked too: they cannot
//! launder an arbitrary nominal reduction into a later carrying close.
use super::{
    BaseTotals, BookParameters, LeafEnvelope, Leg, ParsedEntry, Reader, ReportError, failed,
    framed_hash, law_oid, metadata, registry,
};
use crate::blake3::hash_parts;
use crate::codec::Writer;
use crate::envelope::{proposal_after_legs, skip_erasable};
use std::collections::{BTreeMap, BTreeSet};

fn invalid(detail: &str) -> ReportError {
    failed("functional_closing", detail)
}

/// A governed singleton close shares its publication with its draft's
/// Promote record. That exact metadata shape has no monetary, schema or
/// period effect. Recognizing it does not assert the draft's authorization
/// or lifecycle proof, which remains outside this report certificate.
fn promotion_control(proposal: &[u8]) -> Result<bool, ReportError> {
    let mut header = Reader::new(proposal);
    if header.u16("draft.major")? != 1 || header.u16("draft.minor")? != 1 {
        return Ok(false);
    }
    header.fixed::<32>("draft.book_and_branch")?;
    if header.u16("draft.class")? != 25 {
        return Ok(false);
    }
    header.i32("draft.date")?;
    if header.present("draft.document_date")? {
        return Ok(false);
    }
    skip_erasable(&mut header, "draft.description")?;
    if header.present("draft.period")? || header.count(4096, 1, "draft.legs")? != 0 {
        return Ok(false);
    }
    let mut r = proposal_after_legs(proposal)?;
    if !r.present("draft.control")? || r.u8("draft.control_tag")? != 3 {
        return Ok(false);
    }
    let draft = r.u128("draft.object")?;
    if r.u8("draft.from")? != 1
        || r.u8("draft.to")? != 2
        || r.count(1, 17, "draft.proof_refs")? != 1
        || r.u8("draft.proof_ref_tag")? != 0
    {
        return Ok(false);
    }
    r.u128("draft.outcome")?;
    if r.u16("draft.reason")? != 0
        || r.count(4096, 36, "draft.unit_totals")? != 0
        || r.present("draft.base_totals")?
    {
        return Ok(false);
    }
    let expected_key = framed_hash(
        b"fa:draft-record-key:v1",
        &[&[2], &draft.to_le_bytes(), &[]],
    );
    if r.bytes(256, "draft.key")? != expected_key
        || r.u8("draft.origin")? != 3
        || r.u16("draft.control_kind")? != 11
    {
        return Ok(false);
    }
    r.fixed::<32>("draft.body_digest")?;
    r.u128("draft.principal")?;
    if r.present("draft.session")?
        || r.count(4096, 65, "draft.evidence")? != 0
        || r.count(4096, 51, "draft.supersession")? != 0
        || r.present("draft.pending")?
        || r.count(256, 65, "draft.external_ids")? != 0
        || r.count(32, 65, "draft.tags")? != 0
        || r.count(4096, 6, "draft.extensions")? != 0
    {
        return Ok(false);
    }
    r.finish("draft promotion metadata")?;
    Ok(true)
}

struct Basis {
    version: u16,
    year: i32,
    period: String,
    date: i32,
    observed_at: u64,
    routes_entry: u128,
    routes_digest: [u8; 32],
    source_digest: [u8; 32],
}

impl Basis {
    fn read(bytes: &[u8]) -> Result<Self, ReportError> {
        let mut r = Reader::new(bytes);
        if r.fixed::<14>("closing.magic")? != *b"FA-YEAR-CLOSE\0" {
            return Err(invalid("unknown intrinsic Closing basis"));
        }
        let version = r.u16("closing.version")?;
        if !matches!(version, 1 | 2) {
            return Err(failed(
                "supported_report",
                "unsupported YearEndClose computation version",
            ));
        }
        let basis = Self {
            version,
            year: r.i32("closing.fiscal_year")?,
            period: super::text(&mut r, 64, "closing.period")?.into(),
            date: r.i32("closing.date")?,
            observed_at: r.u64("closing.observed_at")?,
            routes_entry: r.u128("closing.routes_entry")?,
            routes_digest: r.fixed("closing.routes_digest")?,
            source_digest: r.fixed("closing.source_digest")?,
        };
        r.finish("Closing basis")?;
        if basis.period.is_empty() || basis.observed_at == 0 {
            return Err(invalid(
                "Closing requires a period and a nonzero original observation",
            ));
        }
        Ok(basis)
    }
}

struct Routes {
    date: i32,
    sequence: u64,
    identity: u128,
    digest: [u8; 32],
    rows: BTreeMap<u128, u128>,
}

fn route_map(
    bytes: &[u8],
    sequence: u64,
    identity: u128,
    book: &[u8; 16],
) -> Result<Routes, ReportError> {
    let mut r = Reader::new(bytes);
    if r.fixed::<17>("closing_routes.magic")? != *b"FA-CLOSING-ROUTES"
        || r.u16("closing_routes.version")? != 1
    {
        return Err(invalid("unknown closing-map format"));
    }
    let date = r.i32("closing_routes.date")?;
    let count = r.count(4096, 32, "closing_routes.rows")?;
    if count == 0 {
        return Err(invalid("closing map must not be empty"));
    }
    let mut rows = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let from = r.u128("closing_routes.source")?;
        let to = r.u128("closing_routes.destination")?;
        if from == to || previous.is_some_and(|prior| prior >= from) {
            return Err(invalid(
                "closing routes must be distinct and strictly ordered",
            ));
        }
        previous = Some(from);
        rows.insert(from, to);
    }
    r.finish("closing routes")?;
    Ok(Routes {
        date,
        sequence,
        identity,
        rows,
        digest: framed_hash(b"fa:closing-routes:v1", &[book, bytes]),
    })
}

fn effective(schema: &metadata::Schema, account: u128, day: i32) -> Result<bool, ReportError> {
    let [opened, closed, promoted] = schema
        .account_effectivity
        .get(&account)
        .copied()
        .unwrap_or_default();
    if matches!((opened, closed), (Some(a), Some(b)) if a >= b)
        || matches!((opened, promoted), (Some(a), Some(b)) if a > b)
        || matches!((promoted, closed), (Some(a), Some(b)) if a > b)
    {
        return Err(invalid("a closing route has invalid account effectivity"));
    }
    Ok(opened.is_none_or(|start| start <= day) && closed.is_none_or(|end| day < end))
}

fn account(
    schema: &metadata::Schema,
    id: u128,
    nominal: bool,
    unit: Option<u32>,
    day: i32,
    posting: bool,
) -> Result<&metadata::Account, ReportError> {
    let row = schema
        .accounts
        .get(&id)
        .ok_or_else(|| invalid("closing route account is absent"))?;
    if (nominal && !matches!(row.account_type, 4 | 5))
        || (!nominal && row.account_type != 3)
        || row.limit.is_some()
        || unit.is_some_and(|unit| row.unit_policy >= 0 && row.unit_policy != i64::from(unit))
        || posting && (!row.is_leaf || !effective(schema, id, day)?)
    {
        return Err(invalid(
            "closing requires effective nominal-to-equity routes accepting each source currency without balance limits",
        ));
    }
    Ok(row)
}

#[derive(Clone, Copy, Default)]
struct Balance {
    native: i128,
    base: i128,
}
impl Balance {
    fn add(&mut self, debit: bool, native: i128, base: i128) -> Result<(), ReportError> {
        let signed = |current: i128, amount| {
            if debit {
                current.checked_add(amount)
            } else {
                current.checked_sub(amount)
            }
        };
        self.native = signed(self.native, native)
            .ok_or_else(|| invalid("closing native balance exceeds i128"))?;
        self.base = signed(self.base, base)
            .ok_or_else(|| invalid("closing functional balance exceeds i128"))?;
        Ok(())
    }

    fn zero(self) -> bool {
        self.native == 0 && self.base == 0
    }
}
#[derive(Default)]
struct Cell {
    total: Balance,
    buckets: BTreeMap<(u128, u128), Balance>,
}
struct ClosingLeg {
    account: u128,
    unit: u32,
    debit: bool,
    native: i128,
    base: Option<i128>,
    entity: Option<u128>,
}

fn entity(spec: &BookParameters, dimensions: &[(u32, u128)]) -> Result<Option<u128>, ReportError> {
    if dimensions
        .iter()
        .any(|(id, _)| !matches!(id, 1..=6 | 8 | 9))
    {
        return Err(failed(
            "supported_report",
            "fund/party and unknown dimensions have no implemented closing treatment",
        ));
    }
    match dimensions
        .iter()
        .find(|(id, _)| *id == 1)
        .map(|(_, value)| *value)
    {
        Some(value) if spec.entities.contains_key(&value) => Ok(Some(value)),
        Some(_) => Err(invalid(
            "nominal contribution names an undeclared legal entity",
        )),
        None if spec.entities.len() > 1 => Err(invalid(
            "nominal contribution omits its required legal entity",
        )),
        None => Ok(spec.entities.keys().next().copied()),
    }
}

/// Native intrinsic closes author plain legs: no memo or application can be
/// smuggled into the independently reconstructed transfer.
fn plain_legs(proposal: &[u8]) -> Result<(), ReportError> {
    let mut r = Reader::new(proposal);
    r.fixed::<42>("closing.header")?;
    if r.present("closing.document_date")? {
        r.i32("closing.document_date")?;
    }
    skip_erasable(&mut r, "closing.description")?;
    if r.present("closing.period")? {
        r.bytes(128, "closing.calendar")?;
        r.bytes(128, "closing.period")?;
    }
    let count = r.count(4096, 47, "closing.legs")?;
    for _ in 0..count {
        r.fixed::<37>("closing.leg")?;
        if r.present("closing.base")? {
            r.fixed::<20>("closing.base")?;
        }
        let dimensions = r.count(64, 20, "closing.dimensions")?;
        for _ in 0..dimensions {
            r.fixed::<20>("closing.dimension")?;
        }
        if r.present("closing.memo")? {
            return Err(invalid("intrinsic Closing legs cannot carry a memo"));
        }
        r.count(0, 70, "closing.applications")?;
    }
    Ok(())
}

struct History<'a> {
    spec: &'a BookParameters,
    registry: &'a registry::FunctionalRegistry,
    envelopes: &'a [LeafEnvelope],
    records: &'a [(usize, &'a [u8])],
    infos: &'a BTreeMap<usize, metadata::EntryInfo<'a>>,
    legs: &'a [Vec<Leg>],
    parsed: &'a BTreeMap<usize, ParsedEntry>,
    activations: &'a BTreeMap<u64, u64>,
    order: Vec<usize>,
}

impl History<'_> {
    fn snapshot(&self, at: u64) -> Result<(metadata::Schema, Vec<Routes>), ReportError> {
        let mut schema = metadata::Schema::default();
        let mut routes = Vec::new();
        for &index in &self.order {
            let envelope = &self.envelopes[index];
            if envelope.commit_seq > at {
                break;
            }
            let info = &self.infos[&index];
            let proposal = &self.records[index].1[..self.records[index].0];
            if let Some((kind, bytes)) = info.schema {
                schema.apply(kind, bytes, &self.spec.book, envelope.commit_seq)?;
                if kind == 12 {
                    let map =
                        route_map(bytes, envelope.commit_seq, info.identity, &self.spec.book)?;
                    let mut header = Reader::new(proposal);
                    header.fixed::<38>("closing_routes.header")?;
                    if header.i32("closing_routes.effective_date")? != map.date {
                        return Err(invalid(
                            "closing-map date differs from its SchemaControl header",
                        ));
                    }
                    for (&source, &target) in &map.rows {
                        for (id, nominal) in [(source, true), (target, false)] {
                            let row = schema.accounts.get(&id).ok_or_else(|| {
                                invalid("closing-map declaration precedes its account")
                            })?;
                            if !row.is_leaf
                                || nominal && !matches!(row.account_type, 4 | 5)
                                || !nominal && row.account_type != 3
                                || !effective(&schema, id, map.date)?
                            {
                                return Err(invalid(
                                    "closing-map declaration requires effective nominal/equity posting leaves",
                                ));
                            }
                        }
                    }
                    routes.push(map);
                }
            }
            if envelope.class == 16 {
                let mut r = proposal_after_legs(proposal)?;
                if !r.present("period.control")? || r.u8("period.tag")? != 0 {
                    return Err(invalid("PeriodControl lacks its transition"));
                }
                let calendar = super::text(&mut r, 128, "period.calendar")?;
                let code = super::text(&mut r, 128, "period.code")?;
                let from = r.u8("period.from")?;
                let to = r.u8("period.to")?;
                let (start, end, _, _) = schema
                    .period_state(code)
                    .ok_or_else(|| invalid("period transition precedes declaration"))?;
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
        }
        Ok((schema, routes))
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &self,
        output: &mut Vec<ClosingLeg>,
        schema: &metadata::Schema,
        date: i32,
        source: u128,
        destination: u128,
        unit: u32,
        entity: Option<u128>,
        balance: Balance,
        valued: bool,
    ) -> Result<(), ReportError> {
        if balance.zero() {
            return Ok(());
        }
        if balance.native == 0
            || balance.base != 0 && balance.native.signum() != balance.base.signum()
        {
            return Err(invalid(
                "a retained carrying cohort has incompatible native/functional signs",
            ));
        }
        let native = balance
            .native
            .checked_abs()
            .ok_or_else(|| invalid("closing native magnitude exceeds i128"))?;
        let base = balance
            .base
            .checked_abs()
            .ok_or_else(|| invalid("closing functional magnitude exceeds i128"))?;
        for (id, debit, nominal) in [
            (source, balance.native < 0, true),
            (destination, balance.native > 0, false),
        ] {
            account(schema, id, nominal, Some(unit), date, true)?;
            output.push(ClosingLeg {
                account: id,
                unit,
                debit,
                native,
                base: valued.then_some(base),
                entity,
            });
        }
        if output.len() > 4096 {
            return Err(invalid(
                "complete Closing exceeds the atomic entry leg bound",
            ));
        }
        Ok(())
    }

    fn reproduce(&self, index: usize, basis: &Basis, at: u64) -> Result<(), ReportError> {
        let valued = basis.version == 2;
        let (start, end) = self.spec.fiscal_calendar.year_bounds(basis.year)?;
        let (schema, maps) = self.snapshot(at)?;
        let (period_start, period_end, kind, state) = schema
            .period_state(&basis.period)
            .ok_or_else(|| invalid("Closing period is absent at the source observation"))?;
        if basis.date != end
            || basis.period != format!("FY{}-CLOSE", basis.year)
            || !schema.calendar_matches(&self.spec.calendar)
            || schema.period_fiscal_year(&basis.period) != Some(basis.year)
            || kind != 3
            || period_start != end
            || end.checked_add(1) != Some(period_end)
            || !matches!(state, 1..=3)
        {
            return Err(invalid(
                "Closing requires its fiscal year's explicit Open/SoftClosed/Closed final-day period",
            ));
        }
        let map = maps
            .iter()
            .filter(|map| map.date <= end)
            .max_by_key(|map| (map.date, map.sequence, map.identity))
            .ok_or_else(|| invalid("no closing routes apply at fiscal year end"))?;
        if map.identity != basis.routes_entry || map.digest != basis.routes_digest {
            return Err(invalid(
                "retained closing route identity or digest is stale",
            ));
        }
        let mut source = Writer::default();
        source
            .fixed(&self.spec.book)
            .i32(basis.year)
            .i32(start)
            .i32(end)
            .u8(state)
            .u128(map.identity)
            .fixed(&map.digest);
        if valued {
            source
                .fixed(&self.spec.canonical)
                .fixed(&self.registry.unit_table_digest)
                .fixed(&law_oid(8));
        }
        for (&from, &to) in &map.rows {
            for (id, nominal) in [(from, true), (to, false)] {
                let row = account(
                    &schema,
                    id,
                    nominal,
                    (!valued).then_some(self.spec.base),
                    end,
                    false,
                )?;
                super::revaluation::bind_account(&mut source, id, row, &schema);
            }
        }
        let mut cells: BTreeMap<(u128, u32, Option<u128>), Cell> = BTreeMap::new();
        for &previous in &self.order {
            let envelope = &self.envelopes[previous];
            if envelope.commit_seq > at {
                break;
            }
            if envelope.class == 2
                || envelope.class >= 16
                || envelope
                    .effective_day
                    .is_none_or(|date| date < start || date > end)
                || envelope.class == 12
                    && self
                        .activations
                        .get(&(previous as u64))
                        .is_none_or(|activated| *activated > at)
            {
                continue;
            }
            for (ordinal, leg) in self.legs[previous].iter().enumerate() {
                let row = schema
                    .accounts
                    .get(&leg.account)
                    .ok_or_else(|| invalid("closing source names an unknown account"))?;
                if !matches!(row.account_type, 4 | 5) {
                    continue;
                }
                let details = &self.parsed[&previous].details[ordinal];
                if !self
                    .registry
                    .units
                    .get(&leg.unit)
                    .is_some_and(|unit| unit.currency)
                    || !valued && (leg.unit != self.spec.base || details.base_amount.is_some())
                {
                    return Err(invalid(
                        "nominal source is outside this native/carrying closing version",
                    ));
                }
                let base = self.parsed[&previous].amounts[ordinal];
                let entity = entity(self.spec, &details.dimensions)?;
                source
                    .u128(self.infos[&previous].identity)
                    .u64(envelope.commit_seq)
                    .fixed(&envelope.record_digest)
                    .u64(ordinal as u64);
                let native = u128::try_from(leg.mantissa)
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or_else(|| invalid("closing source native amount must be positive"))?;
                let functional = u128::try_from(base)
                    .map_err(|_| invalid("closing source functional amount cannot be negative"))?;
                let gcd = super::gcd(native, functional);
                let ratio = (functional / gcd, native / gcd);
                let cell = cells.entry((leg.account, leg.unit, entity)).or_default();
                cell.total.add(leg.debit, leg.mantissa, base)?;
                cell.buckets
                    .entry(ratio)
                    .or_default()
                    .add(leg.debit, leg.mantissa, base)?;
            }
        }
        let mut expected = Vec::new();
        let mut bound_unrouted = BTreeSet::new();
        for ((id, unit, entity), cell) in cells {
            let row = &schema.accounts[&id];
            let inactive = !row.is_leaf || !effective(&schema, id, end)?;
            if inactive && !cell.total.zero() {
                return Err(invalid(
                    "inactive nominal account retains a nonzero native/functional balance",
                ));
            }
            let destination = match map.rows.get(&id) {
                Some(destination) => *destination,
                None if inactive && cell.total.zero() => {
                    let row = account(&schema, id, true, Some(unit), end, false)?;
                    if bound_unrouted.insert(id) {
                        source.fixed(b"fa:year-end-close-unrouted-zero:v1");
                        super::revaluation::bind_account(&mut source, id, row, &schema);
                    }
                    continue;
                }
                None => {
                    return Err(invalid(
                        "nominal account activity has no reviewed closing destination",
                    ));
                }
            };
            // Different valuation cohorts may cancel both measures. An already
            // closed account must not manufacture offsetting economic-zero legs.
            if cell.total.zero() {
                continue;
            }
            if valued {
                for balance in cell.buckets.into_values() {
                    self.append(
                        &mut expected,
                        &schema,
                        end,
                        id,
                        destination,
                        unit,
                        entity,
                        balance,
                        true,
                    )?;
                }
            } else {
                self.append(
                    &mut expected,
                    &schema,
                    end,
                    id,
                    destination,
                    unit,
                    entity,
                    cell.total,
                    false,
                )?;
            }
        }
        let domain: &[u8] = if valued {
            b"fa:year-end-close-source:v2"
        } else {
            b"fa:year-end-close-source:v1"
        };
        if hash_parts(domain, &[&source.buf]) != basis.source_digest {
            return Err(invalid(
                "complete fiscal-year source differs from the retained closing commitment",
            ));
        }
        if expected.is_empty() || expected.len() != self.legs[index].len() {
            return Err(invalid(
                "Closing must contain exactly the nonzero complete incremental transfer",
            ));
        }
        for ((expected, leg), detail) in expected
            .iter()
            .zip(&self.legs[index])
            .zip(&self.parsed[&index].details)
        {
            let dimensions: Vec<_> = expected
                .entity
                .into_iter()
                .map(|entity| (1, entity))
                .collect();
            if expected.account != leg.account
                || expected.unit != leg.unit
                || expected.debit != leg.debit
                || expected.native != leg.mantissa
                || detail.base_amount != expected.base.map(|amount| (self.spec.base, amount))
                || detail.dimensions != dimensions
                || !detail.settlements.is_empty()
            {
                return Err(invalid(
                    "Closing legs differ from the independently reconstructed ordered carrying cohorts",
                ));
            }
        }
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify<'a>(
    spec: &'a BookParameters,
    registry: &'a registry::FunctionalRegistry,
    envelopes: &'a [LeafEnvelope],
    records: &'a [(usize, &'a [u8])],
    infos: &'a BTreeMap<usize, metadata::EntryInfo<'a>>,
    legs: &'a [Vec<Leg>],
    parsed: &'a BTreeMap<usize, ParsedEntry>,
    activations: &'a BTreeMap<u64, u64>,
) -> Result<(), ReportError> {
    // Existing native report folds may contain historical unbound Closing
    // amounts. They do not assert this intrinsic computation. Once a saved
    // basis or law 8 is claimed, every preceding close must reproduce too.
    if !infos
        .values()
        .any(|info| info.year_end_close_basis.is_some())
        && !parsed.values().any(|entry| {
            entry
                .base
                .as_ref()
                .is_some_and(|base| base.law == law_oid(8))
        })
    {
        return Ok(());
    }
    let mut bases = BTreeMap::new();
    for (&index, info) in infos {
        let claim = &parsed[&index].base;
        if envelopes[index].class != 8 {
            if info.year_end_close_basis.is_some()
                || envelopes[index].class != 4
                    && claim.as_ref().is_some_and(|base| base.law == law_oid(8))
            {
                return Err(invalid(
                    "YearEndCloseCarrying belongs only to an intrinsic Closing or exact inherited reversal",
                ));
            }
            continue;
        }
        let basis =
            Basis::read(info.year_end_close_basis.ok_or_else(|| {
                invalid("a retained Closing has no complete source-bound basis")
            })?)?;
        if info.period != Some((spec.calendar.as_str(), basis.period.as_str()))
            || envelopes[index].effective_day != Some(basis.date)
            || basis.observed_at >= envelopes[index].commit_seq
        {
            return Err(invalid(
                "Closing header or recorded observation differs from its saved basis",
            ));
        }
        let mut promotion_seen = false;
        for other in infos.keys().filter(|other| {
            **other != index && envelopes[**other].commit_seq == envelopes[index].commit_seq
        }) {
            if promotion_seen
                || envelopes[*other].class != 25
                || !promotion_control(&records[*other].1[..records[*other].0])?
            {
                return Err(invalid(
                    "intrinsic Closing cannot share publication with a monetary or source-changing Entry",
                ));
            }
            promotion_seen = true;
        }
        plain_legs(&records[index].1[..records[index].0])?;
        if basis.version == 1 {
            if claim.is_some()
                || parsed[&index]
                    .details
                    .iter()
                    .any(|detail| detail.base_amount.is_some())
            {
                return Err(invalid(
                    "native Closing v1 cannot carry functional valuations",
                ));
            }
        } else {
            let mut debits = 0i128;
            let mut credits = 0i128;
            for (leg, detail) in legs[index].iter().zip(&parsed[&index].details) {
                let Some((unit, amount)) = detail.base_amount else {
                    return Err(invalid(
                        "every carrying-close leg requires its retained functional amount",
                    ));
                };
                if unit != spec.base || amount < 0 {
                    return Err(invalid(
                        "carrying-close functional currency or sign differs",
                    ));
                }
                let total = if leg.debit { &mut debits } else { &mut credits };
                *total = total
                    .checked_add(amount)
                    .ok_or_else(|| invalid("closing functional totals exceed i128"))?;
            }
            let expected = BaseTotals {
                unit: spec.base,
                debits,
                credits,
                law: law_oid(8),
                rates: Vec::new(),
                residual: None,
            };
            if debits != credits || claim.as_ref() != Some(&expected) {
                return Err(invalid(
                    "carrying Closing requires exact totals without new rates or a residual",
                ));
            }
        }
        bases.insert(index, basis);
    }
    let mut order: Vec<_> = infos.keys().copied().collect();
    order.sort_by_key(|index| (envelopes[*index].commit_seq, infos[index].identity));
    let history = History {
        spec,
        registry,
        envelopes,
        records,
        infos,
        legs,
        parsed,
        activations,
        order,
    };
    for &index in &history.order {
        if let Some(basis) = bases.get(&index) {
            let before = envelopes[index]
                .commit_seq
                .checked_sub(1)
                .ok_or_else(|| invalid("Closing publication has sequence zero"))?;
            history.reproduce(index, basis, basis.observed_at)?;
            if before != basis.observed_at {
                history.reproduce(index, basis, before)?;
            }
        }
    }
    Ok(())
}
