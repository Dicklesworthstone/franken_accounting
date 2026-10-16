//! Graph procedures over the entry-level money flow (plan §11.4, bet A4):
//! two-account and bounded multi-account round trips (kiting motifs), and
//! sub-threshold clustering between a payer and a receiving account.
//! Amounts are exact allocated shares, legal entities never share a path,
//! and every citation resolves. A motif is a score, never a finding of fact.

mod cycles;

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_model::{AccountType, EntryClass};
use fa_money::{UnitId, UnitKind};
use fgdb_types::VId;

use crate::projection::{FlowLeg, scoped_flow_legs};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, Statistic, Work,
};

/// Use the implementation's version, not the legacy JET constructor's v1.
/// The run still independently checks code, registry and finding versions.
fn finding(
    identity: (&str, u16),
    severity: Severity,
    statistic: Statistic,
    cites: Vec<Cite>,
    narrative: String,
) -> Finding {
    Finding {
        procedure: identity.0.to_string(),
        version: identity.1,
        severity,
        statistic,
        cites,
        narrative,
    }
}

fn days(params: &Params, name: &'static str) -> Result<i32, LanternError> {
    i32::try_from(params.get_u32(name)?).map_err(|_| LanternError::Overflow(name))
}

/// Whether `account` is an asset account of the snapshot's chart.
fn is_asset(snapshot: &Snapshot, account: VId) -> bool {
    snapshot
        .accounts
        .get(&account)
        .is_some_and(|a| a.account_type == AccountType::ASSET.0)
}

/// Days from a leg's effective date to the last day of its period (`end`
/// is exclusive, so the last day is `end - 1`); `None` when the period is
/// not in the snapshot's calendar. Widen before subtracting DateDay values.
fn days_to_period_end(snapshot: &Snapshot, leg: &FlowLeg) -> Option<i64> {
    snapshot
        .periods
        .get(&leg.period)
        .map(|p| i64::from(p.end.0) - 1 - i64::from(leg.effective_date.0))
}

fn entity_text(entity: Option<VId>) -> String {
    entity.map_or_else(|| "implicit book entity".into(), |v| format!("entity {:032x}", v.0))
}

/// `graph.round_trips`: same-amount asset-account round trips. Two-hop mode
/// retains the linear chronological pairing algorithm; max_hops > 2 enables
/// bounded simple cycles through intermediate accounts.
pub struct RoundTrips {
    params: Params,
}

impl RoundTrips {
    pub const ID: &'static str = "graph.round_trips";
    pub const VERSION: u16 = 2;

    pub fn new() -> Result<Self, LanternError> {
        Ok(Self {
            params: Params::defaults(Self::ID)?,
        })
    }

    #[must_use]
    pub fn with(params: Params) -> Self {
        Self { params }
    }
}

impl Procedure for RoundTrips {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        Self::VERSION
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let window_days = days(&self.params, "window_days")?;
        let period_end_days = days(&self.params, "period_end_days")?;
        let max_hops = self.params.get_u32("max_hops")?;
        let max_steps = self.params.get_u32("max_search_steps")?;
        if !(2..=8).contains(&max_hops) || !(1..=10_000_000).contains(&max_steps) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "max_hops/max_search_steps".into(),
                message: "max_hops must be 2..=8 and max_search_steps 1..=10000000".into(),
            });
        }
        if max_hops > 2 {
            return multi_round_trips(
                snapshot,
                book,
                work,
                window_days,
                period_end_days,
                max_hops as usize,
                u64::from(max_steps),
            );
        }
        let legs = scoped_flow_legs(snapshot)?;
        // Pair only within an entity, unit and exact magnitude.
        type Bucket = (Option<VId>, VId, VId, u32, i128);
        let mut by_bucket: BTreeMap<Bucket, Vec<&FlowLeg>> = BTreeMap::new();
        let mut candidates = 0u64;
        for scoped in &legs {
            let l = &scoped.leg;
            work.leg();
            if l.class == EntryClass::REVERSAL
                || l.mantissa == 0
                || l.from == l.to
                || !is_asset(snapshot, l.from)
                || !is_asset(snapshot, l.to)
            {
                continue;
            }
            candidates += 1;
            let pair = if l.from <= l.to { (l.from, l.to) } else { (l.to, l.from) };
            by_bucket
                .entry((scoped.legal_entity, pair.0, pair.1, l.unit_id, l.mantissa))
                .or_default()
                .push(l);
        }
        let mut out = Vec::new();
        for ((entity, p0, p1, unit_id, _), mut bucket) in by_bucket {
            let n = bucket.len() as u64;
            work.compare(n.saturating_mul(n.max(1).ilog2().into()));
            bucket.sort_by_key(|l| (l.effective_date, l.recorded, l.entry, l.from, l.to));
            let dir = |l: &FlowLeg| usize::from(l.from != p0 || l.to != p1);
            let mut used = vec![false; bucket.len()];
            let mut cursor = [0usize; 2];
            for i in 0..bucket.len() {
                if used[i] { continue; }
                let o = bucket[i];
                let opp = 1 - dir(o);
                cursor[opp] = cursor[opp].max(i + 1);
                while cursor[opp] < bucket.len()
                    && (used[cursor[opp]] || dir(bucket[cursor[opp]]) != opp)
                {
                    work.compare(1);
                    cursor[opp] += 1;
                }
                let mut r_idx = cursor[opp];
                while r_idx < bucket.len()
                    && (used[r_idx] || dir(bucket[r_idx]) != opp || bucket[r_idx].entry == o.entry)
                {
                    work.compare(1);
                    r_idx += 1;
                }
                let Some(&r) = bucket.get(r_idx) else { continue; };
                work.compare(1);
                let gap = i64::from(r.effective_date.0) - i64::from(o.effective_date.0);
                if !(0..=i64::from(window_days)).contains(&gap) { continue; }
                used[i] = true;
                used[r_idx] = true;
                if r_idx == cursor[opp] { cursor[opp] += 1; }
                let (a, b) = (o.from, o.to);
                let out_days = days_to_period_end(snapshot, o);
                let back_days = days_to_period_end(snapshot, r);
                let near_end = [out_days, back_days].iter().flatten()
                    .any(|d| (0..=i64::from(period_end_days)).contains(d));
                let severity = if near_end { Severity::High } else { Severity::Medium };
                let day_text = |d: Option<i64>| d.map_or("?".to_string(), |d| d.to_string());
                out.push(finding(
                    (Self::ID, Self::VERSION),
                    severity,
                    Statistic {
                        name: "round_trip_mantissa".into(),
                        value: o.mantissa,
                        scale: crate::unit_scale(book, unit_id)?,
                        population: candidates,
                    },
                    vec![Cite::Entry(o.entry), Cite::Entry(r.entry), Cite::Account(a), Cite::Account(b)],
                    format!(
                        "unit {unit_id}, {}: {} (mantissa) out and back in {gap} day(s); outbound {} and return {} day(s) before their period ends{}",
                        entity_text(entity), o.mantissa, day_text(out_days), day_text(back_days),
                        if near_end { "; within the period-end window" } else { "" }
                    ),
                ));
            }
        }
        Ok(out)
    }
}

fn multi_round_trips(
    snapshot: &Snapshot,
    book: &BookContext,
    work: &mut Work,
    window_days: i32,
    period_end_days: i32,
    max_hops: usize,
    max_steps: u64,
) -> Result<Vec<Finding>, LanternError> {
    let scoped = scoped_flow_legs(snapshot)?;
    let mut sources = Vec::new();
    let mut edges = Vec::new();
    for flow in &scoped {
        work.leg();
        let leg = &flow.leg;
        if leg.class == EntryClass::REVERSAL || leg.from == leg.to
            || !is_asset(snapshot, leg.from) || !is_asset(snapshot, leg.to)
        { continue; }
        sources.push(flow);
        edges.push(cycles::Edge {
            day: leg.effective_date.0,
            recorded: leg.recorded.0,
            entry: leg.entry.0,
            from: leg.from.0,
            to: leg.to.0,
            unit: leg.unit_id,
            amount: leg.mantissa,
            entity: flow.legal_entity.map(|entity| entity.0),
        });
    }
    let n = edges.len() as u64;
    work.compare(n.saturating_mul(n.max(1).ilog2().into()));
    let found = cycles::find(&edges, max_hops, window_days, max_steps).map_err(|error| {
        match error {
            cycles::Error::NonPositiveAmount => LanternError::Overflow("nonpositive circular-flow edge"),
            cycles::Error::Parameters => LanternError::Parameter {
                procedure: RoundTrips::ID.into(),
                name: "max_hops/max_search_steps".into(),
                message: "invalid bounded circular-flow search parameters".into(),
            },
            cycles::Error::SearchLimit => LanternError::Parameter {
                procedure: RoundTrips::ID.into(),
                name: "max_search_steps".into(),
                message: "circular-flow search limit reached; no partial findings returned; narrow the population or increase max_search_steps (at most 10000000)".into(),
            },
        }
    })?;
    work.compare(found.steps);
    let mut out = Vec::new();
    for path in found.paths {
        let first_index = path.first().ok_or(LanternError::Overflow("empty circular-flow path"))?;
        let last_index = path.last().ok_or(LanternError::Overflow("empty circular-flow path"))?;
        let first = &sources[*first_index].leg;
        let last = &sources[*last_index].leg;
        let near_end = [days_to_period_end(snapshot, first), days_to_period_end(snapshot, last)]
            .iter().flatten().any(|d| (0..=i64::from(period_end_days)).contains(d));
        let mut cites = Vec::with_capacity(path.len() * 2);
        for index in &path {
            cites.push(Cite::Entry(sources[*index].leg.entry));
            cites.push(Cite::Account(sources[*index].leg.from));
        }
        let gap = i64::from(last.effective_date.0) - i64::from(first.effective_date.0);
        out.push(finding(
            (RoundTrips::ID, RoundTrips::VERSION),
            if near_end { Severity::High } else { Severity::Medium },
            Statistic {
                name: "round_trip_mantissa".into(),
                value: first.mantissa,
                scale: crate::unit_scale(book, first.unit_id)?,
                population: n,
            },
            cites,
            format!(
                "unit {}, {}: {} (mantissa) out and back through {} asset accounts in {gap} day(s); canonical edge-disjoint temporal cycle{}; a motif, not a tracing-law conclusion",
                first.unit_id, entity_text(sources[*first_index].legal_entity), first.mantissa, path.len(),
                if near_end { "; within the period-end window" } else { "" }
            ),
        ));
    }
    Ok(out)
}

/// `graph.structuring`: between one payer account and one receiving account
/// in one unit and entity, a chain of transfers each in `floor..threshold`,
/// consecutive ones at most `window_days` apart, at least `min_count` long
/// and summing to at least `threshold`.
pub struct Structuring {
    params: Params,
}

impl Structuring {
    pub const ID: &'static str = "graph.structuring";
    pub const VERSION: u16 = 2;

    pub fn new() -> Result<Self, LanternError> {
        Ok(Self { params: Params::defaults(Self::ID)? })
    }

    #[must_use]
    pub fn with(params: Params) -> Self { Self { params } }
}

struct Rule {
    threshold: i128,
    floor: i128,
    window_days: i32,
    min_count: usize,
    currency: u16,
}

type StructuringKey = (Option<VId>, VId, VId, u32);

impl Rule {
    fn from(params: &Params) -> Result<Self, LanternError> {
        let rule = Self {
            threshold: params.get("threshold")?,
            floor: params.get("floor")?,
            window_days: days(params, "window_days")?,
            min_count: usize::try_from(params.get_u32("min_count")?)
                .map_err(|_| LanternError::Overflow("min_count"))?,
            currency: u16::try_from(params.get_u32("currency_iso4217")?).map_err(|_| {
                LanternError::Parameter {
                    procedure: Structuring::ID.into(),
                    name: "currency_iso4217".into(),
                    message: "an ISO 4217 numeric currency code (1..=999)".into(),
                }
            })?,
        };
        if rule.currency == 0 || rule.currency > 999 {
            return Err(LanternError::Parameter {
                procedure: Structuring::ID.into(), name: "currency_iso4217".into(),
                message: "an ISO 4217 numeric currency code (1..=999)".into(),
            });
        }
        if rule.threshold <= 0 || rule.floor < 0 || rule.floor >= rule.threshold {
            return Err(LanternError::Parameter {
                procedure: Structuring::ID.into(), name: "floor".into(),
                message: "0 <= floor < threshold is required".into(),
            });
        }
        if rule.min_count == 0 {
            return Err(LanternError::Parameter {
                procedure: Structuring::ID.into(), name: "min_count".into(), message: "at least 1".into(),
            });
        }
        Ok(rule)
    }

    fn report(
        &self,
        out: &mut Vec<Finding>,
        chain: &[&FlowLeg],
        key: StructuringKey,
        population: u64,
        scale: u8,
    ) -> Result<(), LanternError> {
        let (entity, from, to, unit_id) = key;
        let (Some(first), Some(last)) = (chain.first(), chain.last()) else { return Ok(()); };
        if chain.len() < self.min_count { return Ok(()); }
        let sum = chain.iter().try_fold(0i128, |acc, l| acc.checked_add(l.mantissa))
            .ok_or(LanternError::Overflow("structuring chain"))?;
        if sum < self.threshold { return Ok(()); }
        let span = i64::from(last.effective_date.0) - i64::from(first.effective_date.0);
        let mut seen = std::collections::BTreeSet::new();
        let mut entries: Vec<VId> = chain.iter().map(|l| l.entry)
            .filter(|entry| seen.insert(*entry)).collect();
        entries.truncate(MAX_CITES - 2);
        let severity = if sum >= self.threshold.saturating_mul(2)
            || chain.len() >= self.min_count.saturating_mul(2)
        { Severity::High } else { Severity::Medium };
        let mut cites = vec![Cite::Account(to), Cite::Account(from)];
        cites.extend(entries.into_iter().map(Cite::Entry));
        out.push(finding(
            (Structuring::ID, Structuring::VERSION),
            severity,
            Statistic { name: "chain_mantissa".into(), value: sum, scale, population },
            cites,
            format!(
                "unit {unit_id} (ISO 4217 {}), {}: {} transfer(s) each in {}..{} (mantissas) within {span} day(s) summing to {sum}",
                self.currency, entity_text(entity), chain.len(), self.floor, self.threshold,
            ),
        ));
        Ok(())
    }
}

impl Procedure for Structuring {
    fn id(&self) -> &'static str { Self::ID }
    fn version(&self) -> u16 { Self::VERSION }
    fn params(&self) -> &Params { &self.params }
    fn run(
        &self,
        snapshot: &Snapshot,
        book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let rule = Rule::from(&self.params)?;
        let legs = scoped_flow_legs(snapshot)?;
        let mut groups: BTreeMap<StructuringKey, Vec<&FlowLeg>> = BTreeMap::new();
        let mut candidates = 0u64;
        for scoped in &legs {
            let l = &scoped.leg;
            work.leg();
            let in_currency = matches!(
                book.units.get(UnitId(l.unit_id)).map(|u| u.kind),
                Some(UnitKind::Currency { iso4217 }) if iso4217 == rule.currency
            );
            if !in_currency || l.class == EntryClass::REVERSAL || l.from == l.to
                || l.mantissa < rule.floor || l.mantissa >= rule.threshold
            { continue; }
            candidates += 1;
            groups.entry((scoped.legal_entity, l.from, l.to, l.unit_id)).or_default().push(l);
        }
        let mut out = Vec::new();
        for (key, mut group) in groups {
            let scale = crate::unit_scale(book, key.3)?;
            group.sort_by_key(|l| (l.effective_date, l.recorded, l.entry));
            work.compare(group.len() as u64);
            let mut chain: Vec<&FlowLeg> = Vec::new();
            for l in group {
                if let Some(last) = chain.last()
                    && i64::from(l.effective_date.0) - i64::from(last.effective_date.0) > i64::from(rule.window_days)
                {
                    rule.report(&mut out, &chain, key, candidates, scale)?;
                    chain.clear();
                }
                chain.push(l);
            }
            rule.report(&mut out, &chain, key, candidates, scale)?;
        }
        Ok(out)
    }
}
