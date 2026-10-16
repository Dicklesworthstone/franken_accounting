//! Graph procedures over the entry-level money flow (plan §11.9, bet A4):
//! round trips between asset accounts (the kiting motif) and sub-threshold
//! clustering between one payer and one receiving account (structuring).
//! Both walk `projection::flow_legs`, so every amount is an exact allocated
//! share and every citation resolves. A motif is a score, never a finding
//! of fact. Neither needs `fnx`: its graph types carry string node ids and
//! i64 weights read as f64, so exact arithmetic stays here and `fnx` is
//! reserved for topology (cycles, components, paths) in the tracing slice.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_model::{AccountType, EntryClass};
use fa_money::{UnitId, UnitKind};
use fgdb_types::VId;

use crate::jet::finding;
use crate::projection::{FlowLeg, flow_legs};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, Statistic, Work,
};

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
/// not in the snapshot's calendar.
fn days_to_period_end(snapshot: &Snapshot, leg: &FlowLeg) -> Option<i32> {
    snapshot
        .periods
        .get(&leg.period)
        .map(|p| p.end.0 - 1 - leg.effective_date.0)
}

/// `graph.round_trips`: value that leaves one asset account for another and
/// returns in the same exact amount within `window_days`.
pub struct RoundTrips {
    params: Params,
}

impl RoundTrips {
    pub const ID: &'static str = "graph.round_trips";

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
        let period_end_days = days(&self.params, "period_end_days")?;
        let legs = flow_legs(snapshot)?;
        // Candidate legs between two distinct asset accounts, grouped by
        // unordered account pair, unit, and exact mantissa so only equal-amount
        // opposite-direction legs ever meet.
        let mut by_bucket: BTreeMap<(VId, VId, u32, i128), Vec<&FlowLeg>> = BTreeMap::new();
        let mut candidates = 0u64;
        for l in &legs {
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
                .entry((pair.0, pair.1, l.unit_id, l.mantissa))
                .or_default()
                .push(l);
        }
        let mut out = Vec::new();
        for ((p0, p1, unit_id, _), mut bucket) in by_bucket {
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
                let gap = r.effective_date.0 - o.effective_date.0;
                if !(0..=window_days).contains(&gap) {
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
                    .any(|d| (0..=period_end_days).contains(d));
                let severity = if near_end {
                    Severity::High
                } else {
                    Severity::Medium
                };
                let day_text = |d: Option<i32>| d.map_or("?".to_string(), |d| d.to_string());
                out.push(finding(
                    Self::ID,
                    severity,
                    Statistic {
                        name: "round_trip_mantissa".into(),
                        value: o.mantissa,
                        scale: crate::unit_scale(book, unit_id)?,
                        population: candidates,
                    },
                    vec![
                        Cite::Entry(o.entry),
                        Cite::Entry(r.entry),
                        Cite::Account(a),
                        Cite::Account(b),
                    ],
                    format!(
                        "unit {unit_id}: {} (mantissa) out and back in {gap} day(s); outbound {} and return {} day(s) before their period ends{}",
                        o.mantissa,
                        day_text(out_days),
                        day_text(back_days),
                        if near_end {
                            "; within the period-end window"
                        } else {
                            ""
                        }
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `graph.structuring`: between one payer account and one receiving account
/// in one unit, a chain of transfers each in `floor..threshold`, consecutive
/// ones at most `window_days` apart, at least `min_count` long and summing
/// to at least `threshold`.
pub struct Structuring {
    params: Params,
}

impl Structuring {
    pub const ID: &'static str = "graph.structuring";

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

/// The registered bounds of one structuring run. A reporting threshold is
/// an amount in one currency, so a run examines that currency's transfers
/// only (`currency_iso4217`); the same mantissa in another unit is another
/// amount (10,000.00 USD, JPY 1,000,000 and 0.01 BTC are not one threshold).
struct Rule {
    threshold: i128,
    floor: i128,
    window_days: i32,
    min_count: usize,
    currency: u16,
}

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

    /// Emit a finding for `chain` when it meets the rule.
    fn report(
        &self,
        out: &mut Vec<Finding>,
        chain: &[&FlowLeg],
        key: (VId, VId, u32),
        population: u64,
        scale: u8,
    ) -> Result<(), LanternError> {
        let (from, to, unit_id) = key;
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
        let span = last.effective_date.0 - first.effective_date.0;
        // The chain's entries in its own (date, recorded) order, each once.
        let mut seen = std::collections::BTreeSet::new();
        let mut entries: Vec<VId> = chain
            .iter()
            .map(|l| l.entry)
            .filter(|entry| seen.insert(*entry))
            .collect();
        entries.truncate(MAX_CITES - 2);
        let severity = if sum >= self.threshold.saturating_mul(2)
            || chain.len() >= self.min_count.saturating_mul(2)
        {
            Severity::High
        } else {
            Severity::Medium
        };
        let mut cites = vec![Cite::Account(to), Cite::Account(from)];
        cites.extend(entries.into_iter().map(Cite::Entry));
        out.push(finding(
            Structuring::ID,
            severity,
            Statistic {
                name: "chain_mantissa".into(),
                value: sum,
                scale,
                population,
            },
            cites,
            format!(
                "unit {unit_id} (ISO 4217 {}): {} transfer(s) each in {}..{} (mantissas) within {span} day(s) summing to {sum}",
                self.currency,
                chain.len(),
                self.floor,
                self.threshold
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
        let rule = Rule::from(&self.params)?;
        let legs = flow_legs(snapshot)?;
        let mut groups: BTreeMap<(VId, VId, u32), Vec<&FlowLeg>> = BTreeMap::new();
        let mut candidates = 0u64;
        for l in &legs {
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
            groups.entry((l.from, l.to, l.unit_id)).or_default().push(l);
        }
        let mut out = Vec::new();
        for (key, mut group) in groups {
            let scale = crate::unit_scale(book, key.2)?;
            group.sort_by_key(|l| (l.effective_date, l.recorded, l.entry));
            work.compare(group.len() as u64);
            let mut chain: Vec<&FlowLeg> = Vec::new();
            for l in group {
                if let Some(last) = chain.last()
                    && l.effective_date.0 - last.effective_date.0 > rule.window_days
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
