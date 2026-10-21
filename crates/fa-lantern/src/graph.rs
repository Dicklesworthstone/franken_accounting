//! Graph procedures over the entry-level money flow (plan §11.4, bet A4):
//! two-account and bounded multi-account round trips (kiting motifs), and
//! sub-threshold clustering between a payer and a receiving account.
//! Amounts are exact allocated shares, legal entities never share a path,
//! and every citation resolves. A motif is a score, never a finding of fact.

mod cycles;

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::genesis::BookContext;
use fa_model::{AccountType, EntryClass};
use fa_money::wide::U256;
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

fn amount_sum(left: i128, right: i128, accumulator: &'static str) -> Result<i128, LanternError> {
    left.checked_add(right)
        .ok_or(LanternError::Overflow(accumulator))
}

/// Exact, truncated basis points. A valid large flow must not be refused merely
/// because multiplying its mantissa by 10,000 needs more than 128 bits.
fn amount_share_bps(
    numerator: i128,
    denominator: i128,
    statistic: &'static str,
) -> Result<i128, LanternError> {
    let numerator = u128::try_from(numerator).map_err(|_| LanternError::Overflow(statistic))?;
    let denominator = u128::try_from(denominator).map_err(|_| LanternError::Overflow(statistic))?;
    U256::from_u128(numerator)
        .checked_mul_u128(10_000)
        .and_then(|scaled| scaled.checked_div_rem(U256::from_u128(denominator)))
        .and_then(|(quotient, _)| quotient.to_u128())
        .and_then(|quotient| i128::try_from(quotient).ok())
        .ok_or(LanternError::Overflow(statistic))
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
    entity.map_or_else(
        || "implicit book entity".into(),
        |v| format!("entity {:032x}", v.0),
    )
}

/// No amount, path, or population baseline may cross this coordinate.
type MonetaryScope = (Option<VId>, u32);

fn monetary_scope_text(
    book: &BookContext,
    (entity, unit_id): MonetaryScope,
) -> Result<String, LanternError> {
    let unit = book.units.get(UnitId(unit_id)).ok_or_else(|| {
        fa_journal::KernelError::Corrupt("a leg names an unregistered unit".into())
    })?;
    Ok(format!(
        "{} (unit {unit_id}, version {}, scale {}), {}",
        unit.code,
        unit.version,
        unit.scale,
        entity_text(entity)
    ))
}

/// Count each live posting once in every unit/entity partition it touches.
fn monetary_populations(
    entries: &[&crate::SnapshotEntry],
    entities: &crate::projection::entity::Scope,
) -> Result<BTreeMap<MonetaryScope, u64>, LanternError> {
    let mut populations = BTreeMap::new();
    for entry in entries {
        let mut seen = BTreeSet::new();
        for leg in &entry.entry.proposal.legs {
            seen.insert((
                crate::projection::scoped_entity(entities, leg)?,
                leg.amount.unit.0,
            ));
        }
        for coordinate in seen {
            *populations.entry(coordinate).or_insert(0) += 1;
        }
    }
    Ok(populations)
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
            let pair = if l.from <= l.to {
                (l.from, l.to)
            } else {
                (l.to, l.from)
            };
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
                if used[i] {
                    continue;
                }
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
                let Some(&r) = bucket.get(r_idx) else {
                    continue;
                };
                work.compare(1);
                let gap = i64::from(r.effective_date.0) - i64::from(o.effective_date.0);
                if !(0..=i64::from(window_days)).contains(&gap) {
                    continue;
                }
                used[i] = true;
                used[r_idx] = true;
                if r_idx == cursor[opp] {
                    cursor[opp] += 1;
                }
                let (a, b) = (o.from, o.to);
                let out_days = days_to_period_end(snapshot, o);
                let back_days = days_to_period_end(snapshot, r);
                let near_end = [out_days, back_days]
                    .iter()
                    .flatten()
                    .any(|d| (0..=i64::from(period_end_days)).contains(d));
                let severity = if near_end {
                    Severity::High
                } else {
                    Severity::Medium
                };
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
        if leg.class == EntryClass::REVERSAL
            || leg.from == leg.to
            || !is_asset(snapshot, leg.from)
            || !is_asset(snapshot, leg.to)
        {
            continue;
        }
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
        let first_index = path
            .first()
            .ok_or(LanternError::Overflow("empty circular-flow path"))?;
        let last_index = path
            .last()
            .ok_or(LanternError::Overflow("empty circular-flow path"))?;
        let first = &sources[*first_index].leg;
        let last = &sources[*last_index].leg;
        let near_end = [
            days_to_period_end(snapshot, first),
            days_to_period_end(snapshot, last),
        ]
        .iter()
        .flatten()
        .any(|d| (0..=i64::from(period_end_days)).contains(d));
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
        Ok(Self {
            params: Params::defaults(Self::ID)?,
        })
    }

    #[must_use]
    pub fn with(params: Params) -> Self {
        Self { params }
    }
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
                procedure: Structuring::ID.into(),
                name: "currency_iso4217".into(),
                message: "an ISO 4217 numeric currency code (1..=999)".into(),
            });
        }
        if rule.threshold <= 0 || rule.floor < 0 || rule.floor >= rule.threshold {
            return Err(LanternError::Parameter {
                procedure: Structuring::ID.into(),
                name: "floor".into(),
                message: "0 <= floor < threshold is required".into(),
            });
        }
        if rule.min_count == 0 {
            return Err(LanternError::Parameter {
                procedure: Structuring::ID.into(),
                name: "min_count".into(),
                message: "at least 1".into(),
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
        let (Some(first), Some(last)) = (chain.first(), chain.last()) else {
            return Ok(());
        };
        if chain.len() < self.min_count {
            return Ok(());
        }
        let sum = chain
            .iter()
            .try_fold(0i128, |acc, l| acc.checked_add(l.mantissa))
            .ok_or(LanternError::Overflow("structuring chain"))?;
        if sum < self.threshold {
            return Ok(());
        }
        let span = i64::from(last.effective_date.0) - i64::from(first.effective_date.0);
        let mut seen = std::collections::BTreeSet::new();
        let mut entries: Vec<VId> = chain
            .iter()
            .map(|l| l.entry)
            .filter(|entry| seen.insert(*entry))
            .collect();
        entries.truncate(MAX_CITES - 2);
        let high_threshold = U256::from_u128(self.threshold.unsigned_abs())
            .checked_mul_u128(2)
            .ok_or(LanternError::Overflow(
                "graph.structuring severity threshold",
            ))?;
        let severity = if U256::from_u128(sum.unsigned_abs()) >= high_threshold
            || chain.len() >= self.min_count.saturating_mul(2)
        {
            Severity::High
        } else {
            Severity::Medium
        };
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
            if !in_currency
                || l.class == EntryClass::REVERSAL
                || l.from == l.to
                || l.mantissa < rule.floor
                || l.mantissa >= rule.threshold
            {
                continue;
            }
            candidates += 1;
            groups
                .entry((scoped.legal_entity, l.from, l.to, l.unit_id))
                .or_default()
                .push(l);
        }
        let mut out = Vec::new();
        for (key, mut group) in groups {
            let scale = crate::unit_scale(book, key.3)?;
            group.sort_by_key(|l| (l.effective_date, l.recorded, l.entry));
            work.compare(group.len() as u64);
            let mut chain: Vec<&FlowLeg> = Vec::new();
            for l in group {
                if let Some(last) = chain.last()
                    && i64::from(l.effective_date.0) - i64::from(last.effective_date.0)
                        > i64::from(rule.window_days)
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

fn vid_node(v: VId) -> String {
    format!("{:032x}", v.0)
}

fn parse_vid_node(s: &str) -> Option<VId> {
    u128::from_str_radix(s, 16).ok().map(VId)
}

fn cgse_digest_hex(decisions: &[(&str, &str)], n: usize, m: usize, term: &str) -> String {
    let (_, collected) = fnx_cgse::collect_witnesses(|| {
        let mut sink = fnx_cgse::WitnessSink::new(fnx_cgse::TieBreakPolicy::LexMin);
        for (chosen, rejected) in decisions {
            sink.record_decision(chosen, rejected);
        }
        sink.finalize(n, m, term, None)
    });
    let mut sink = fnx_cgse::WitnessSink::new(fnx_cgse::TieBreakPolicy::LexMin);
    for (chosen, rejected) in decisions {
        sink.record_decision(chosen, rejected);
    }
    let w = collected
        .into_iter()
        .next()
        .unwrap_or_else(|| sink.finalize(n, m, term, None));
    let mut hex = String::with_capacity(16);
    for b in &w.decision_path_blake3[..8] {
        use core::fmt::Write as _;
        let _ = write!(&mut hex, "{b:02x}");
    }
    hex
}

/// `graph.circular_flows`: directed k-cycles in the money-flow DiGraph where
/// bottleneck flow retains at least `min_retention_bps` of the initial leg,
/// decomposed by `fnx_algorithms::strongly_connected_components` with a CGSE witness.
pub struct CircularFlows {
    params: Params,
}
crate::jet::procedure_boilerplate!(CircularFlows, "graph.circular_flows");

impl Procedure for CircularFlows {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
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
        let max_hops = self.params.get_u32("max_hops")? as usize;
        let min_retention_bps = i128::from(self.params.get_u32("min_retention_bps")?);
        if !(2..=8).contains(&max_hops) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "max_hops".into(),
                message: "must be in 2..=8".into(),
            });
        }
        let scoped = scoped_flow_legs(snapshot)?;
        let mut by_partition: BTreeMap<(Option<VId>, u32), Vec<&FlowLeg>> = BTreeMap::new();
        for flow in &scoped {
            work.leg();
            let l = &flow.leg;
            if l.class == EntryClass::REVERSAL || l.mantissa <= 0 || l.from == l.to {
                continue;
            }
            by_partition
                .entry((flow.legal_entity, l.unit_id))
                .or_default()
                .push(l);
        }
        let population = scoped.len() as u64;
        let mut out = Vec::new();
        for ((_entity, unit_id), mut legs) in by_partition {
            legs.sort_by_key(|l| (l.effective_date, l.recorded, l.entry, l.from, l.to));
            work.compare(legs.len() as u64);
            let mut dg = fnx_classes::digraph::DiGraph::strict();
            let mut nodes = std::collections::BTreeSet::new();
            let mut edge_pairs = std::collections::BTreeSet::new();
            for l in &legs {
                nodes.insert(vid_node(l.from));
                nodes.insert(vid_node(l.to));
                edge_pairs.insert((vid_node(l.from), vid_node(l.to)));
            }
            for n in &nodes {
                dg.add_node(n.clone());
            }
            for (u, v) in &edge_pairs {
                let _ = dg.add_edge(u.clone(), v.clone());
            }
            let (sccs, _) =
                fnx_cgse::collect_witnesses(|| fnx_algorithms::strongly_connected_components(&dg));
            for mut scc in sccs {
                if scc.len() < 2 {
                    continue;
                }
                scc.sort();
                let scc_vids: std::collections::BTreeSet<VId> =
                    scc.iter().filter_map(|s| parse_vid_node(s)).collect();
                let scc_legs: Vec<&FlowLeg> = legs
                    .iter()
                    .copied()
                    .filter(|l| scc_vids.contains(&l.from) && scc_vids.contains(&l.to))
                    .collect();
                let mut used = vec![false; scc_legs.len()];
                for start_idx in 0..scc_legs.len() {
                    if used[start_idx] {
                        continue;
                    }
                    let first = scc_legs[start_idx];
                    let mut path_indices = vec![start_idx];
                    let mut visited_accts = std::collections::BTreeSet::new();
                    visited_accts.insert(first.from);
                    visited_accts.insert(first.to);
                    let mut cur_acct = first.to;
                    let mut cur_day = first.effective_date.0;
                    let mut min_flow = first.mantissa;
                    let mut closed = false;
                    while path_indices.len() < max_hops {
                        work.compare(1);
                        if let Some((close_idx, close_leg)) = scc_legs
                            .iter()
                            .enumerate()
                            .skip(start_idx + 1)
                            .find(|(idx, l)| {
                                !used[*idx]
                                    && !path_indices.contains(idx)
                                    && l.from == cur_acct
                                    && l.to == first.from
                                    && l.effective_date.0 >= cur_day
                                    && (l.effective_date.0 - first.effective_date.0) <= window_days
                                    && l.entry != scc_legs[*path_indices.last().unwrap()].entry
                            })
                        {
                            let candidate_min = min_flow.min(close_leg.mantissa);
                            let ret_bps = amount_share_bps(
                                candidate_min,
                                first.mantissa,
                                "graph.circular_flows retention",
                            )?;
                            if ret_bps >= min_retention_bps {
                                path_indices.push(close_idx);
                                min_flow = candidate_min;
                                closed = true;
                                break;
                            }
                        }
                        if path_indices.len() + 1 >= max_hops {
                            break;
                        }
                        let mut next_opt = None;
                        for (idx, l) in scc_legs.iter().enumerate().skip(start_idx + 1) {
                            if !used[idx]
                                && !path_indices.contains(&idx)
                                && l.from == cur_acct
                                && !visited_accts.contains(&l.to)
                                && l.effective_date.0 >= cur_day
                                && (l.effective_date.0 - first.effective_date.0) <= window_days
                                && amount_share_bps(
                                    l.mantissa.min(min_flow),
                                    first.mantissa,
                                    "graph.circular_flows retention",
                                )? >= min_retention_bps
                            {
                                next_opt = Some((idx, l));
                                break;
                            }
                        }
                        if let Some((next_idx, next_leg)) = next_opt {
                            path_indices.push(next_idx);
                            visited_accts.insert(next_leg.to);
                            cur_acct = next_leg.to;
                            cur_day = next_leg.effective_date.0;
                            min_flow = min_flow.min(next_leg.mantissa);
                        } else {
                            break;
                        }
                    }
                    if closed {
                        for &idx in &path_indices {
                            used[idx] = true;
                        }
                        let ret_bps = amount_share_bps(
                            min_flow,
                            first.mantissa,
                            "graph.circular_flows retention",
                        )?;
                        let mut cites = Vec::new();
                        let mut decisions = Vec::new();
                        for &idx in &path_indices {
                            let l = scc_legs[idx];
                            cites.push(Cite::Entry(l.entry));
                            if snapshot.accounts.contains_key(&l.from) {
                                cites.push(Cite::Account(l.from));
                            }
                            decisions.push((vid_node(l.from), vid_node(l.to)));
                        }
                        let dec_refs: Vec<(&str, &str)> = decisions
                            .iter()
                            .map(|(a, b)| (a.as_str(), b.as_str()))
                            .collect();
                        let cgse =
                            cgse_digest_hex(&dec_refs, nodes.len(), edge_pairs.len(), "scc_cycles");
                        cites.truncate(MAX_CITES);
                        out.push(finding(
                            (Self::ID, self.version()),
                            Severity::High,
                            Statistic {
                                name: "retained_flow_mantissa".into(),
                                value: min_flow,
                                scale: crate::unit_scale(book, unit_id)?,
                                population,
                            },
                            cites,
                            format!(
                                "{}-hop directed cycle in SCC retaining {min_flow} of {} ({ret_bps} bps, cgse_witness={cgse})",
                                path_indices.len(),
                                first.mantissa
                            ),
                        ));
                    }
                }
            }
        }
        Ok(out)
    }
}

/// `graph.layering`: multi-hop pass-through chains (`>= min_hops`) within
/// `window_days` where each intermediary forwards at least `min_passthrough_bps`
/// without closing a cycle, backed by `fnx` DiGraph traversal and CGSE witness.
pub struct Layering {
    params: Params,
}
crate::jet::procedure_boilerplate!(Layering, "graph.layering");

impl Procedure for Layering {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
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
        let min_hops = self.params.get_u32("min_hops")? as usize;
        let window_days = days(&self.params, "window_days")?;
        let min_pass_bps = i128::from(self.params.get_u32("min_passthrough_bps")?);
        if !(2..=8).contains(&min_hops) {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "min_hops".into(),
                message: "must be in 2..=8".into(),
            });
        }
        let scoped = scoped_flow_legs(snapshot)?;
        let mut by_partition: BTreeMap<(Option<VId>, u32), Vec<&FlowLeg>> = BTreeMap::new();
        for flow in &scoped {
            work.leg();
            let l = &flow.leg;
            if l.class == EntryClass::REVERSAL || l.mantissa <= 0 || l.from == l.to {
                continue;
            }
            by_partition
                .entry((flow.legal_entity, l.unit_id))
                .or_default()
                .push(l);
        }
        let population = scoped.len() as u64;
        let mut out = Vec::new();
        for ((_entity, unit_id), mut legs) in by_partition {
            legs.sort_by_key(|l| (l.effective_date, l.recorded, l.entry, l.from, l.to));
            work.compare(legs.len() as u64);
            let mut dg = fnx_classes::digraph::DiGraph::strict();
            for l in &legs {
                let u = vid_node(l.from);
                let v = vid_node(l.to);
                dg.add_node(u.clone());
                dg.add_node(v.clone());
                let _ = dg.add_edge(u, v);
            }
            let mut used = vec![false; legs.len()];
            for start_idx in 0..legs.len() {
                if used[start_idx] {
                    continue;
                }
                let first = legs[start_idx];
                let start_node = vid_node(first.from);
                let (layers, _) = fnx_cgse::collect_witnesses(|| {
                    fnx_algorithms::bfs_layers_directed(&dg, &start_node)
                });
                if layers.len() <= min_hops {
                    continue;
                }
                let mut chain = vec![start_idx];
                let mut visited = std::collections::BTreeSet::new();
                visited.insert(first.from);
                visited.insert(first.to);
                let mut cur_acct = first.to;
                let mut cur_day = first.effective_date.0;
                let mut prev_amt = first.mantissa;
                let mut min_amt = first.mantissa;
                while chain.len() < 8 {
                    work.compare(1);
                    let mut next_opt = None;
                    for (idx, l) in legs.iter().enumerate().skip(start_idx + 1) {
                        if !used[idx]
                            && !chain.contains(&idx)
                            && l.from == cur_acct
                            && !visited.contains(&l.to)
                            && l.effective_date.0 >= cur_day
                            && (l.effective_date.0 - first.effective_date.0) <= window_days
                            && l.mantissa <= prev_amt
                            && amount_share_bps(l.mantissa, prev_amt, "graph.layering passthrough")?
                                >= min_pass_bps
                        {
                            next_opt = Some((idx, l));
                            break;
                        }
                    }
                    if let Some((next_idx, next_leg)) = next_opt {
                        chain.push(next_idx);
                        visited.insert(next_leg.to);
                        cur_acct = next_leg.to;
                        cur_day = next_leg.effective_date.0;
                        prev_amt = next_leg.mantissa;
                        min_amt = min_amt.min(next_leg.mantissa);
                    } else {
                        break;
                    }
                }
                if chain.len() >= min_hops {
                    for &idx in &chain {
                        used[idx] = true;
                    }
                    let mut cites = Vec::new();
                    let mut decisions = Vec::new();
                    for &idx in &chain {
                        let l = legs[idx];
                        cites.push(Cite::Entry(l.entry));
                        if snapshot.accounts.contains_key(&l.from) {
                            cites.push(Cite::Account(l.from));
                        }
                        decisions.push((vid_node(l.from), vid_node(l.to)));
                    }
                    if let Some(&last_idx) = chain.last()
                        && snapshot.accounts.contains_key(&legs[last_idx].to)
                    {
                        cites.push(Cite::Account(legs[last_idx].to));
                    }
                    let dec_refs: Vec<(&str, &str)> = decisions
                        .iter()
                        .map(|(a, b)| (a.as_str(), b.as_str()))
                        .collect();
                    let cgse = cgse_digest_hex(
                        &dec_refs,
                        dg.node_count(),
                        dg.edge_count(),
                        "layering_bfs",
                    );
                    cites.truncate(MAX_CITES);
                    out.push(finding(
                        (Self::ID, self.version()),
                        Severity::High,
                        Statistic {
                            name: "layered_mantissa".into(),
                            value: min_amt,
                            scale: crate::unit_scale(book, unit_id)?,
                            population,
                        },
                        cites,
                        format!(
                            "{}-hop pass-through chain forwarding {min_amt} of {} within {window_days} day(s) (cgse_witness={cgse})",
                            chain.len(),
                            first.mantissa
                        ),
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// `graph.communities`: community detection over the money-flow projection via
/// `fnx_algorithms::louvain_communities` and `connected_components` with CGSE witness.
/// Topology and exact transfer volumes stay inside one native unit and entity.
pub struct Communities {
    params: Params,
}
crate::jet::procedure_boilerplate!(Communities, "graph.communities");

impl Procedure for Communities {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        2
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
        let min_size = self.params.get_u32("min_community_size")? as usize;
        let min_share_bps = i128::from(self.params.get_u32("min_internal_share_bps")?);
        // Preserve the entity label before building topology: money_flow()
        // deliberately collapses entities and cannot serve a path analysis.
        let mut partitions: BTreeMap<MonetaryScope, BTreeMap<(VId, VId), i128>> = BTreeMap::new();
        for scoped in scoped_flow_legs(snapshot)? {
            work.leg();
            let e = &scoped.leg;
            if e.from == e.to || e.mantissa <= 0 {
                continue;
            }
            let pair = if e.from <= e.to {
                (e.from, e.to)
            } else {
                (e.to, e.from)
            };
            let edge_weights = partitions
                .entry((scoped.legal_entity, e.unit_id))
                .or_default();
            let weight = edge_weights.entry(pair).or_insert(0);
            *weight = amount_sum(*weight, e.mantissa, "graph.communities edge volume")?;
        }
        let mut out = Vec::new();
        for (coordinate, edge_weights) in partitions {
            let scope_text = monetary_scope_text(book, coordinate)?;
            let mut g = fnx_classes::Graph::strict();
            let mut nodes = BTreeSet::new();
            for &(u, v) in edge_weights.keys() {
                nodes.insert(u);
                nodes.insert(v);
            }
            for &n in &nodes {
                g.add_node(vid_node(n));
            }
            for &(u, v) in edge_weights.keys() {
                let _ = g.add_edge(vid_node(u), vid_node(v));
            }
            let (mut comms, _) = fnx_cgse::collect_witnesses(|| {
                let mut out_comms =
                    fnx_algorithms::louvain_communities(&g, 1.0, "weight", 1e-7, None, Some(0));
                out_comms.extend(fnx_algorithms::connected_components(&g).components);
                out_comms
            });
            for c in &mut comms {
                c.sort();
            }
            comms.sort();
            comms.dedup();
            for comm in comms {
                work.compare(comm.len() as u64);
                let member_vids: BTreeSet<VId> = comm
                    .iter()
                    .filter_map(|s| parse_vid_node(s))
                    .filter(|v| snapshot.accounts.contains_key(v))
                    .collect();
                if member_vids.len() < min_size {
                    continue;
                }
                let mut internal_vol: i128 = 0;
                let mut total_incident_vol: i128 = 0;
                for (&(u, v), &w) in &edge_weights {
                    let u_in = member_vids.contains(&u);
                    let v_in = member_vids.contains(&v);
                    if u_in && v_in {
                        internal_vol =
                            amount_sum(internal_vol, w, "graph.communities internal volume")?;
                        total_incident_vol =
                            amount_sum(total_incident_vol, w, "graph.communities incident volume")?;
                    } else if u_in || v_in {
                        total_incident_vol =
                            amount_sum(total_incident_vol, w, "graph.communities incident volume")?;
                    }
                }
                if total_incident_vol <= 0 {
                    continue;
                }
                let share_bps = amount_share_bps(
                    internal_vol,
                    total_incident_vol,
                    "graph.communities internal share",
                )?;
                if share_bps >= min_share_bps {
                    let mut decisions = vec![(scope_text.clone(), "amount_scope".to_string())];
                    decisions.extend(
                        member_vids
                            .iter()
                            .map(|v| (vid_node(*v), "community".to_string())),
                    );
                    let dec_refs: Vec<(&str, &str)> = decisions
                        .iter()
                        .map(|(a, b)| (a.as_str(), b.as_str()))
                        .collect();
                    let cgse =
                        cgse_digest_hex(&dec_refs, g.node_count(), g.edge_count(), "louvain");
                    let cites: Vec<Cite> = member_vids
                        .iter()
                        .take(MAX_CITES)
                        .copied()
                        .map(Cite::Account)
                        .collect();
                    out.push(finding(
                        (Self::ID, self.version()),
                        Severity::Medium,
                        Statistic {
                            name: "internal_share_bps".into(),
                            value: share_bps,
                            scale: 0,
                            population: nodes.len() as u64,
                        },
                        cites,
                        format!(
                            "{}-account community in {scope_text} retains {share_bps} bps of incident volume internally (cgse_witness={cgse})",
                            member_vids.len()
                        ),
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// `graph.related_party_exposure`: valid-time traversal of `OWNS`, `CONTROLS`,
/// and `RELATED_TO` edges in `snapshot.rea` via `ReaSnapshot::related_as_of`
/// and `fnx_algorithms::bfs_layers_directed` with CGSE witness, intersected
/// with live postings carrying the reached party or legal-entity dimension.
/// Each finding retains the affected entry's native unit and legal entity.
pub struct RelatedPartyExposure {
    params: Params,
}
crate::jet::procedure_boilerplate!(RelatedPartyExposure, "graph.related_party_exposure");

impl Procedure for RelatedPartyExposure {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        2
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
        let max_depth = self.params.get_u32("max_depth")? as usize;
        if max_depth == 0 || snapshot.rea.relationships.is_empty() {
            return Ok(Vec::new());
        }
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let entities = crate::projection::entity_scope(
            live.iter().flat_map(|entry| &entry.entry.proposal.legs),
        )?;
        let populations = monetary_populations(&live, &entities)?;
        let mut dg = fnx_classes::digraph::DiGraph::strict();
        for r in &snapshot.rea.relationships {
            let u = vid_node(r.spec.from);
            let v = vid_node(r.spec.to);
            dg.add_node(u.clone());
            dg.add_node(v.clone());
            let _ = dg.add_edge(u.clone(), v.clone());
            let _ = dg.add_edge(v, u);
        }
        let mut dim_to_rea: BTreeMap<VId, VId> = BTreeMap::new();
        for (&vid, p) in &snapshot.rea.parties {
            dim_to_rea.insert(p.dimension_value_vid, vid);
            dim_to_rea.insert(vid, vid);
        }
        for (&vid, le) in &snapshot.rea.legal_entities {
            dim_to_rea.insert(le.dimension_value_vid, vid);
            dim_to_rea.insert(vid, vid);
        }
        let mut out = Vec::new();
        for e in &live {
            work.entry();
            let eff = e.entry.proposal.effective_date;
            let mut exposures: BTreeMap<MonetaryScope, i128> = BTreeMap::new();
            let mut hits_by_scope: BTreeMap<
                MonetaryScope,
                Vec<(VId, fa_journal::rea::RelatedPartyHit)>,
            > = BTreeMap::new();
            for leg in &e.entry.proposal.legs {
                work.leg();
                let coordinate = (
                    crate::projection::scoped_entity(&entities, leg)?,
                    leg.amount.unit.0,
                );
                if leg.side == fa_money::Side::Debit {
                    let exposure = exposures.entry(coordinate).or_insert(0);
                    *exposure = amount_sum(
                        *exposure,
                        leg.amount.mantissa,
                        "graph.related_party_exposure debit exposure",
                    )?;
                }
                for (dim, val) in &leg.dimension_set {
                    if *dim != fa_model::PARTY_DIMENSION && *dim != fa_model::LEGAL_ENTITY_DIMENSION
                    {
                        continue;
                    }
                    let Some(&rea_vid) = dim_to_rea.get(val) else {
                        continue;
                    };
                    let related_hits = hits_by_scope.entry(coordinate).or_default();
                    for &root_vid in snapshot.rea.legal_entities.keys() {
                        let hits = snapshot.rea.related_as_of(root_vid, eff, max_depth);
                        if let Some(hit) = hits.into_iter().find(|h| h.vid == rea_vid) {
                            related_hits.push((root_vid, hit));
                        }
                    }
                    for &root_vid in snapshot.rea.parties.keys() {
                        let hits = snapshot.rea.related_as_of(root_vid, eff, max_depth);
                        if let Some(hit) = hits.into_iter().find(|h| h.vid == rea_vid) {
                            related_hits.push((root_vid, hit));
                        }
                    }
                }
            }
            for (coordinate, mut related_hits) in hits_by_scope {
                if related_hits.is_empty() {
                    continue;
                }
                // A related counterparty may be named on either side. Its
                // exposure is the balanced posting's debit volume in this
                // entity/unit only, never the other partitions of the entry.
                let total_exposure = exposures.get(&coordinate).copied().unwrap_or(0);
                let scope_text = monetary_scope_text(book, coordinate)?;
                let scale = crate::unit_scale(book, coordinate.1)?;
                let population = populations.get(&coordinate).copied().unwrap_or(0);
                work.compare(related_hits.len() as u64);
                related_hits.sort_by_key(|(r, h)| (h.depth, h.vid, *r));
                let (root_vid, best) = &related_hits[0];
                let root_node = vid_node(*root_vid);
                let _ = fnx_cgse::collect_witnesses(|| {
                    fnx_algorithms::bfs_layers_directed(&dg, &root_node)
                });
                let cgse = cgse_digest_hex(
                    &[
                        (&scope_text, "amount_scope"),
                        (&root_node, &vid_node(best.vid)),
                    ],
                    dg.node_count(),
                    dg.edge_count(),
                    "related_party_bfs",
                );
                let mut cites = vec![Cite::Entry(e.vid)];
                if snapshot.rea.parties.contains_key(&best.vid) {
                    cites.push(Cite::Principal(best.vid));
                }
                out.push(finding(
                    (Self::ID, self.version()),
                    Severity::High,
                    Statistic {
                        name: "related_party_exposure_mantissa".into(),
                        value: total_exposure,
                        scale,
                        population,
                    },
                    cites,
                    format!(
                        "posting of {total_exposure} in {scope_text} involves related party `{}` at depth {} via `{}` (cgse_witness={cgse})",
                        best.code, best.depth, best.basis
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `graph.shell_signature`: undocumented asset-account pass-through conduits,
/// with flows and evidence isolated by native unit and legal entity.
pub struct ShellSignature {
    params: Params,
}
crate::jet::procedure_boilerplate!(ShellSignature, "graph.shell_signature");

#[derive(Default)]
struct ConduitFlows {
    inflow: i128,
    outflow: i128,
    documented: bool,
    entries: BTreeSet<VId>,
}

impl Procedure for ShellSignature {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        2
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
        let min_pass_bps = i128::from(self.params.get_u32("min_passthrough_bps")?);
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let entities = crate::projection::entity_scope(
            live.iter().flat_map(|entry| &entry.entry.proposal.legs),
        )?;
        let populations = monetary_populations(&live, &entities)?;
        let mut partitions: BTreeMap<MonetaryScope, BTreeMap<VId, ConduitFlows>> = BTreeMap::new();
        for e in &live {
            work.entry();
            for leg in &e.entry.proposal.legs {
                work.leg();
                if !is_asset(snapshot, leg.account_ref) {
                    continue;
                }
                let coordinate = (
                    crate::projection::scoped_entity(&entities, leg)?,
                    leg.amount.unit.0,
                );
                let flows = partitions
                    .entry(coordinate)
                    .or_default()
                    .entry(leg.account_ref)
                    .or_default();
                flows.documented |= !e.entry.proposal.evidence.is_empty();
                flows.entries.insert(e.vid);
                match leg.side {
                    fa_money::Side::Debit => {
                        flows.inflow = amount_sum(
                            flows.inflow,
                            leg.amount.mantissa,
                            "graph.shell_signature account inflow",
                        )?;
                    }
                    fa_money::Side::Credit => {
                        flows.outflow = amount_sum(
                            flows.outflow,
                            leg.amount.mantissa,
                            "graph.shell_signature account outflow",
                        )?;
                    }
                }
            }
        }
        let mut out = Vec::new();
        for (coordinate, accounts) in partitions {
            let scope_text = monetary_scope_text(book, coordinate)?;
            let population = populations.get(&coordinate).copied().unwrap_or(0);
            for (&acct_vid, flows) in &accounts {
                work.compare(1);
                if flows.inflow <= 0
                    || flows.outflow <= 0
                    || flows.documented
                    || flows.entries.len() < 2
                {
                    continue;
                }
                let hi = flows.inflow.max(flows.outflow);
                let lo = flows.inflow.min(flows.outflow);
                let pass_bps = amount_share_bps(lo, hi, "graph.shell_signature passthrough")?;
                if pass_bps >= min_pass_bps {
                    let cgse = cgse_digest_hex(
                        &[
                            (&scope_text, "amount_scope"),
                            (&vid_node(acct_vid), "shell_conduit"),
                        ],
                        accounts.len(),
                        flows.entries.len(),
                        "shell_conduit",
                    );
                    let mut cites = vec![Cite::Account(acct_vid)];
                    cites.extend(
                        flows
                            .entries
                            .iter()
                            .take(MAX_CITES - 1)
                            .copied()
                            .map(Cite::Entry),
                    );
                    out.push(finding(
                        (Self::ID, self.version()),
                        Severity::High,
                        Statistic {
                            name: "passthrough_bps".into(),
                            value: pass_bps,
                            scale: 0,
                            population,
                        },
                        cites,
                        format!(
                            "conduit account in {scope_text} passes through {lo} of {hi} ({pass_bps} bps) with 0 supporting documents (cgse_witness={cgse})"
                        ),
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// `graph.concentration`: counterparty and account concentration over the
/// money-flow DiGraph via `fnx_algorithms::betweenness_centrality_directed` and
/// `degree_centrality_directed` with CGSE witness and exact `i128` flow share.
pub struct Concentration {
    params: Params,
}
crate::jet::procedure_boilerplate!(Concentration, "graph.concentration");

impl Procedure for Concentration {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
    }
    fn params(&self) -> &Params {
        &self.params
    }
    fn run(
        &self,
        snapshot: &Snapshot,
        _book: &BookContext,
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let min_share_bps = i128::from(self.params.get_u32("min_share_bps")?);
        let flow = crate::projection::money_flow(snapshot)?;
        if flow.edges.is_empty() {
            return Ok(Vec::new());
        }
        let mut dg = fnx_classes::digraph::DiGraph::strict();
        let mut by_unit_total: BTreeMap<u32, i128> = BTreeMap::new();
        let mut by_acct_unit: BTreeMap<(VId, u32), i128> = BTreeMap::new();
        for e in &flow.edges {
            if e.mantissa <= 0 || e.from == e.to {
                continue;
            }
            let u = vid_node(e.from);
            let v = vid_node(e.to);
            dg.add_node(u.clone());
            dg.add_node(v.clone());
            let _ = dg.add_edge(u, v);
            let unit_total = by_unit_total.entry(e.unit_id).or_insert(0);
            *unit_total = amount_sum(*unit_total, e.mantissa, "graph.concentration unit volume")?;
            let from_total = by_acct_unit.entry((e.from, e.unit_id)).or_insert(0);
            *from_total = amount_sum(
                *from_total,
                e.mantissa,
                "graph.concentration account volume",
            )?;
            let to_total = by_acct_unit.entry((e.to, e.unit_id)).or_insert(0);
            *to_total = amount_sum(*to_total, e.mantissa, "graph.concentration account volume")?;
        }
        let ((bet, deg), _) = fnx_cgse::collect_witnesses(|| {
            (
                fnx_algorithms::betweenness_centrality_directed(&dg),
                fnx_algorithms::degree_centrality_directed(&dg),
            )
        });
        let population = dg.node_count() as u64;
        let mut out = Vec::new();
        for ((acct_vid, unit_id), acct_vol) in by_acct_unit {
            work.compare(1);
            if !snapshot.accounts.contains_key(&acct_vid) {
                continue;
            }
            let total_vol = by_unit_total.get(&unit_id).copied().unwrap_or(0);
            if total_vol <= 0 {
                continue;
            }
            let share_bps =
                amount_share_bps(acct_vol, total_vol, "graph.concentration flow share")?;
            if share_bps >= min_share_bps {
                let node_str = vid_node(acct_vid);
                let cgse = cgse_digest_hex(
                    &[
                        (&node_str, &bet.witness.algorithm),
                        (&node_str, &deg.witness.algorithm),
                    ],
                    dg.node_count(),
                    dg.edge_count(),
                    "centrality",
                );
                out.push(finding(
                    (Self::ID, self.version()),
                    Severity::Medium,
                    Statistic {
                        name: "flow_share_bps".into(),
                        value: share_bps,
                        scale: 0,
                        population,
                    },
                    vec![Cite::Account(acct_vid)],
                    format!(
                        "account participates in {share_bps} bps of unit {unit_id} directed volume (nodes_touched={}, cgse_witness={cgse})",
                        bet.witness.nodes_touched
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `graph.identity_resolution`: deterministic entity-resolution candidate
/// generator over `Party` identifiers using `fnx_algorithms::connected_components`
/// with a CGSE witness (`SAME_AS` candidate findings).
pub struct IdentityResolution {
    params: Params,
}
crate::jet::procedure_boilerplate!(IdentityResolution, "graph.identity_resolution");

impl Procedure for IdentityResolution {
    fn id(&self) -> &'static str {
        Self::ID
    }
    fn version(&self) -> u16 {
        1
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
        if snapshot.rea.parties.len() < 2 {
            return Ok(Vec::new());
        }
        let mut by_ident: BTreeMap<(String, String), Vec<VId>> = BTreeMap::new();
        for (&vid, party) in &snapshot.rea.parties {
            work.entry();
            for (k, sealed_v) in &party.identifiers {
                work.compare(1);
                if let Ok(plain) = sealed_v.open(&book.seal_key, 256) {
                    let norm_k = k.trim().to_ascii_lowercase();
                    let norm_v: String = plain
                        .chars()
                        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
                        .map(|c| c.to_ascii_lowercase())
                        .collect();
                    if !norm_v.is_empty() {
                        by_ident.entry((norm_k, norm_v)).or_default().push(vid);
                    }
                }
            }
        }
        let mut g = fnx_classes::Graph::strict();
        for &vid in snapshot.rea.parties.keys() {
            g.add_node(vid_node(vid));
        }
        let mut shared_keys: BTreeMap<(VId, VId), Vec<String>> = BTreeMap::new();
        for ((k, _), mut vids) in by_ident {
            vids.sort_unstable();
            vids.dedup();
            if vids.len() < 2 {
                continue;
            }
            for i in 0..vids.len() {
                for j in (i + 1)..vids.len() {
                    let u = vids[i];
                    let v = vids[j];
                    let _ = g.add_edge(vid_node(u), vid_node(v));
                    shared_keys.entry((u, v)).or_default().push(k.clone());
                }
            }
        }
        let (cc, _) = fnx_cgse::collect_witnesses(|| fnx_algorithms::connected_components(&g));
        let population = snapshot.rea.parties.len() as u64;
        let mut out = Vec::new();
        for mut comp in cc.components {
            if comp.len() < 2 {
                continue;
            }
            comp.sort();
            work.compare(comp.len() as u64);
            let vids: Vec<VId> = comp.iter().filter_map(|s| parse_vid_node(s)).collect();
            let mut keys = std::collections::BTreeSet::new();
            let mut decisions = Vec::new();
            for i in 0..vids.len() {
                for j in (i + 1)..vids.len() {
                    let pair = if vids[i] <= vids[j] {
                        (vids[i], vids[j])
                    } else {
                        (vids[j], vids[i])
                    };
                    if let Some(ks) = shared_keys.get(&pair) {
                        for k in ks {
                            keys.insert(k.clone());
                        }
                        decisions.push((vid_node(pair.0), vid_node(pair.1)));
                    }
                }
            }
            let dec_refs: Vec<(&str, &str)> = decisions
                .iter()
                .map(|(a, b)| (a.as_str(), b.as_str()))
                .collect();
            let cgse = cgse_digest_hex(
                &dec_refs,
                g.node_count(),
                g.edge_count(),
                "identity_connected_components",
            );
            let cites: Vec<Cite> = vids
                .iter()
                .take(MAX_CITES)
                .copied()
                .map(Cite::Principal)
                .collect();
            let key_list: Vec<String> = keys.into_iter().collect();
            out.push(finding(
                (Self::ID, self.version()),
                Severity::High,
                Statistic::count("same_as_cluster_size", vids.len() as u64, population),
                cites,
                format!(
                    "SAME_AS candidate cluster of {} parties sharing identifier key(s) {:?} (cgse_witness={cgse})",
                    vids.len(),
                    key_list
                ),
            ));
        }
        Ok(out)
    }
}
