//! Journal-entry testing (plan §11.2; AS 2401 ¶61, ISA 240 ¶A41): the
//! characteristics auditors test every population of entries for, each as a
//! registered procedure with pinned parameters. Every hit cites the entry
//! (and the legs or approval that made it a hit) and reports the population
//! it was drawn from.

use std::collections::BTreeMap;

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_model::EntryOrigin;
use fa_model::limits::{MAX_DESCRIPTION_BYTES, MAX_EXTERNAL_ID_BYTES};
use fa_time::{PeriodState, Weekday};
use fgdb_types::VId;

use crate::amount::{amount_share_bps, signed_leg};
use crate::{
    Cite, Finding, LanternError, MAX_CITES, Meter, Params, Procedure, Severity, Snapshot, Statistic,
};

pub(crate) fn finding(
    procedure: &str,
    severity: Severity,
    statistic: Statistic,
    cites: Vec<Cite>,
    narrative: String,
) -> Finding {
    Finding {
        procedure: procedure.to_string(),
        version: crate::bind(procedure).map_or(1, |row| row.version),
        severity,
        statistic,
        cites,
        narrative,
    }
}

pub(crate) fn ordinal(i: usize) -> Result<u16, LanternError> {
    u16::try_from(i).map_err(|_| LanternError::Overflow("leg ordinal"))
}

macro_rules! procedure_boilerplate {
    ($ty:ident, $id:literal) => {
        impl $ty {
            pub const ID: &'static str = $id;

            /// With the registry's pinned defaults.
            pub fn new() -> Result<Self, LanternError> {
                Ok(Self {
                    params: Params::defaults($id)?,
                })
            }

            /// With explicit (registered) parameters.
            #[must_use]
            pub fn with(params: Params) -> Self {
                Self { params }
            }
        }
    };
}
pub(crate) use procedure_boilerplate;

/// `jet.round_amounts`: legs whose magnitude is a whole multiple of
/// `10^round_power` units.
pub struct RoundAmounts {
    params: Params,
}
procedure_boilerplate!(RoundAmounts, "jet.round_amounts");

impl Procedure for RoundAmounts {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let power = self.params.get_u32("round_power")?;
        if power > 30 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "round_power".into(),
                message: "must be at most 30".into(),
            });
        }
        let factor = 10i128
            .checked_pow(power)
            .ok_or(LanternError::Overflow("round factor"))?;
        let mut population = 0u64;
        let mut hits = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry()?;
            let mut round = Vec::new();
            for (i, leg) in e.entry.proposal.legs.iter().enumerate() {
                work.leg()?;
                population += 1;
                let Some(unit) = book.units.get(leg.amount.unit) else {
                    return Err(
                        KernelError::Corrupt("a leg names an unregistered unit".into()).into(),
                    );
                };
                let base = unit
                    .one()
                    .checked_mul(factor)
                    .ok_or(LanternError::Overflow("round base"))?;
                let m = leg.amount.mantissa;
                if m != 0 && m.checked_rem(base) == Some(0) {
                    round.push(ordinal(i)?);
                }
            }
            if !round.is_empty() {
                hits.push((e.vid, round, e.entry.proposal.legs.len()));
            }
        }
        Ok(hits
            .into_iter()
            .map(|(vid, round, legs)| {
                let mut cites = vec![Cite::Entry(vid)];
                cites.extend(round.iter().map(|o| Cite::Leg {
                    entry: vid,
                    ordinal: *o,
                }));
                let severity = if round.len() == legs {
                    Severity::Medium
                } else {
                    Severity::Low
                };
                finding(
                    Self::ID,
                    severity,
                    Statistic::count("round_legs", round.len() as u64, population),
                    cites,
                    format!(
                        "{} of {legs} legs are whole multiples of 10^{power} units",
                        round.len()
                    ),
                )
            })
            .collect())
    }
}

/// `jet.period_end_timing`: entries effective in the last `window_days`
/// days of their period.
pub struct PeriodEndTiming {
    params: Params,
}
procedure_boilerplate!(PeriodEndTiming, "jet.period_end_timing");

impl Procedure for PeriodEndTiming {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let window = i32::try_from(self.params.get_u32("window_days")?)
            .map_err(|_| LanternError::Overflow("window_days"))?;
        let mut population = 0u64;
        let mut hits = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry()?;
            let Some(period) = snapshot.period_of(e) else {
                continue;
            };
            population += 1;
            // A period's `end` is exclusive (fa-time PeriodDef), so its last
            // day is `end - 1`: an entry on the last day is 0 days from it.
            let days_to_end = period.end.0 - 1 - e.entry.proposal.effective_date.0;
            if (0..window).contains(&days_to_end) {
                hits.push((e.vid, e.period.clone(), days_to_end));
            }
        }
        Ok(hits
            .into_iter()
            .map(|(vid, period, days)| {
                finding(
                    Self::ID,
                    Severity::Low,
                    Statistic::count("days_to_period_end", days as u64, population),
                    vec![Cite::Entry(vid), Cite::Period(period)],
                    format!(
                        "effective {days} day(s) before the period's last day (window {window})"
                    ),
                )
            })
            .collect())
    }
}

/// `jet.post_closing`: entries recorded after their period's first
/// SoftClose, Close or Lock transition.
pub struct PostClosing {
    params: Params,
}
procedure_boilerplate!(PostClosing, "jet.post_closing");

impl Procedure for PostClosing {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let mut first_close = BTreeMap::new();
        for (period, transitions) in &snapshot.transitions {
            for t in transitions {
                work.compare(1)?;
                if matches!(
                    t.to,
                    PeriodState::SoftClosed | PeriodState::Closed | PeriodState::Locked
                ) {
                    first_close.insert(period.as_str(), *t);
                    break;
                }
            }
        }
        let mut population = 0u64;
        let mut hits = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry()?;
            population += 1;
            if let Some(t) = first_close.get(e.period.as_str())
                && e.recorded_at > t.recorded_at
            {
                hits.push((
                    e.vid,
                    e.period.clone(),
                    e.recorded_at.0 - t.recorded_at.0,
                    t.to,
                ));
            }
        }
        Ok(hits
            .into_iter()
            .map(|(vid, period, after, state)| {
                finding(
                    Self::ID,
                    Severity::Medium,
                    Statistic::count("commits_after_close", after, population),
                    vec![Cite::Entry(vid), Cite::Period(period)],
                    format!(
                        "recorded {after} commit(s) after the period's first transition to {}",
                        state.name()
                    ),
                )
            })
            .collect())
    }
}

/// `jet.weekend`: entries dated on a Saturday or Sunday (document date when
/// present, else effective date).
pub struct Weekend {
    params: Params,
}
procedure_boilerplate!(Weekend, "jet.weekend");

impl Procedure for Weekend {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let mut population = 0u64;
        let mut hits = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry()?;
            population += 1;
            let date = e
                .entry
                .proposal
                .document_date
                .unwrap_or(e.entry.proposal.effective_date);
            let weekday = date.weekday();
            if matches!(weekday, Weekday::Saturday | Weekday::Sunday) {
                hits.push((e.vid, weekday.iso()));
            }
        }
        Ok(hits
            .into_iter()
            .map(|(vid, iso)| {
                finding(
                    Self::ID,
                    Severity::Low,
                    Statistic::count("iso_weekday", u64::from(iso), population),
                    vec![Cite::Entry(vid)],
                    format!("dated on ISO weekday {iso} (6 = Saturday, 7 = Sunday)"),
                )
            })
            .collect())
    }
}

/// `jet.self_approved`: entries one of whose recorded approvals was made by
/// the preparing principal, or migrated entries whose legacy
/// `source_approved_by` matches `source_entered_by`.
pub struct SelfApproved {
    params: Params,
}
procedure_boilerplate!(SelfApproved, "jet.self_approved");

impl Procedure for SelfApproved {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let mut population = 0u64;
        let mut hits: Vec<(VId, Vec<VId>, usize, usize)> = Vec::new();
        for e in snapshot.live_postings()? {
            let legacy_pair = match &e.entry.proposal.origin {
                EntryOrigin::Migration {
                    source_entered_by: Some(entered),
                    source_approved_by: Some(approved),
                    ..
                } => entered
                    .open(&book.seal_key, MAX_EXTERNAL_ID_BYTES)
                    .ok()
                    .zip(approved.open(&book.seal_key, MAX_EXTERNAL_ID_BYTES).ok())
                    .filter(|(ent, app)| !ent.trim().is_empty() && !app.trim().is_empty()),
                _ => None,
            };
            if e.approvals.is_empty() && legacy_pair.is_none() {
                continue;
            }
            work.entry()?;
            population += 1;
            work.compare(e.approvals.len() as u64 + u64::from(legacy_pair.is_some()))?;
            let own: Vec<VId> = e
                .approvals
                .iter()
                .filter(|(_, approver)| *approver == e.entry.proposal.principal_ref)
                .map(|(vid, _)| *vid)
                .collect();
            let legacy_self = usize::from(
                legacy_pair
                    .as_ref()
                    .is_some_and(|(ent, app)| ent.trim() == app.trim()),
            );
            let total_own = own.len() + legacy_self;
            if total_own > 0 {
                let total = e.approvals.len() + usize::from(legacy_pair.is_some());
                hits.push((e.vid, own, total_own, total));
            }
        }
        Ok(hits
            .into_iter()
            .map(|(vid, own, total_own, total)| {
                let mut cites = vec![Cite::Entry(vid)];
                cites.extend(own.iter().map(|a| Cite::Approval(*a)));
                finding(
                    Self::ID,
                    Severity::High,
                    Statistic::count("own_approvals", total_own as u64, population),
                    cites,
                    format!(
                        "{total_own} of {total} recorded approval(s) were made by the preparing principal"
                    ),
                )
            })
            .collect())
    }
}

/// `jet.thin_descriptions`: descriptions that open to fewer than `min_chars`
/// characters. An unopenable description is unreadable, never thin.
pub struct ThinDescriptions {
    params: Params,
}
procedure_boilerplate!(ThinDescriptions, "jet.thin_descriptions");

impl Procedure for ThinDescriptions {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let min = self.params.get_u32("min_chars")? as usize;
        let mut population = 0u64;
        let mut hits = Vec::new();
        let mut unreadable: Vec<VId> = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry()?;
            let Ok(text) = e
                .entry
                .proposal
                .description
                .open(&book.seal_key, MAX_DESCRIPTION_BYTES)
            else {
                unreadable.push(e.vid);
                continue;
            };
            population += 1;
            let chars = text.trim().chars().count();
            if chars < min {
                hits.push((e.vid, chars));
            }
        }
        let mut out: Vec<Finding> = hits
            .into_iter()
            .map(|(vid, chars)| {
                finding(
                    Self::ID,
                    Severity::Low,
                    Statistic::count("description_chars", chars as u64, population),
                    vec![Cite::Entry(vid)],
                    format!("description has {chars} character(s); fewer than {min}"),
                )
            })
            .collect();
        // Unreadable descriptions (erased, or sealed under another key) are
        // counted and reported as such: never thin, never silently skipped.
        if !unreadable.is_empty() {
            let n = unreadable.len() as u64;
            unreadable.sort_unstable();
            unreadable.truncate(MAX_CITES);
            out.push(finding(
                Self::ID,
                Severity::Info,
                Statistic::count("unreadable_descriptions", n, population + n),
                unreadable.into_iter().map(Cite::Entry).collect(),
                format!(
                    "{n} description(s) could not be opened under the book's seal key; counted as unreadable, not thin"
                ),
            ));
        }
        Ok(out)
    }
}

/// `jet.unusual_accounts`: live postings whose account-pair co-occurrence is
/// rare in the snapshot population.
pub struct UnusualAccounts {
    params: Params,
}
procedure_boilerplate!(UnusualAccounts, "jet.unusual_accounts");

impl Procedure for UnusualAccounts {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let max_pair_count = u64::from(self.params.get_u32("max_pair_count")?);
        let min_population = u64::from(self.params.get_u32("min_population")?);
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let population = live.len() as u64;
        let mut freq: BTreeMap<Vec<VId>, u64> = BTreeMap::new();
        let mut entry_keys: Vec<(VId, Vec<VId>)> = Vec::with_capacity(live.len());
        for e in &live {
            work.entry()?;
            let mut accts: Vec<VId> = Vec::with_capacity(e.entry.proposal.legs.len());
            for leg in &e.entry.proposal.legs {
                work.leg()?;
                if snapshot.accounts.contains_key(&leg.account_ref) {
                    accts.push(leg.account_ref);
                }
            }
            accts.sort_unstable();
            accts.dedup();
            if accts.len() >= 2 {
                *freq.entry(accts.clone()).or_insert(0) += 1;
            }
            entry_keys.push((e.vid, accts));
        }
        if population < min_population {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for (vid, accts) in entry_keys {
            work.compare(1)?;
            if accts.len() < 2 {
                continue;
            }
            let count = freq.get(&accts).copied().unwrap_or(0);
            if count <= max_pair_count {
                let mut cites = vec![Cite::Entry(vid)];
                cites.extend(accts.iter().take(MAX_CITES - 1).copied().map(Cite::Account));
                out.push(finding(
                    Self::ID,
                    Severity::Low,
                    Statistic::count("pair_occurrences", count, population),
                    cites,
                    format!(
                        "account combination ({} accounts) occurs {count} time(s) in {population} live postings (max_pair_count {max_pair_count})",
                        accts.len()
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `jet.unusual_preparers`: postings to an account by a principal who rarely
/// posts to that account.
pub struct UnusualPreparers {
    params: Params,
}
procedure_boilerplate!(UnusualPreparers, "jet.unusual_preparers");

impl Procedure for UnusualPreparers {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let max_prep_count = u64::from(self.params.get_u32("max_preparer_count")?);
        let min_acct_entries = u64::from(self.params.get_u32("min_account_entries")?);
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let mut acct_totals: BTreeMap<VId, u64> = BTreeMap::new();
        let mut acct_prep_counts: BTreeMap<(VId, VId), u64> = BTreeMap::new();
        let mut acct_preps: BTreeMap<VId, std::collections::BTreeSet<VId>> = BTreeMap::new();
        let mut entry_accts: Vec<(VId, VId, Vec<VId>)> = Vec::with_capacity(live.len());
        for e in &live {
            work.entry()?;
            let prep = e.entry.proposal.principal_ref;
            let mut accts: Vec<VId> = Vec::new();
            for leg in &e.entry.proposal.legs {
                work.leg()?;
                if snapshot.accounts.contains_key(&leg.account_ref) {
                    accts.push(leg.account_ref);
                }
            }
            accts.sort_unstable();
            accts.dedup();
            for &acct in &accts {
                *acct_totals.entry(acct).or_insert(0) += 1;
                *acct_prep_counts.entry((acct, prep)).or_insert(0) += 1;
                acct_preps.entry(acct).or_default().insert(prep);
            }
            entry_accts.push((e.vid, prep, accts));
        }
        let mut out = Vec::new();
        for (vid, prep, accts) in entry_accts {
            work.compare(1)?;
            for acct in accts {
                let total = acct_totals.get(&acct).copied().unwrap_or(0);
                let distinct_preps = acct_preps.get(&acct).map_or(0, |s| s.len());
                let count = acct_prep_counts.get(&(acct, prep)).copied().unwrap_or(0);
                if total >= min_acct_entries && distinct_preps >= 2 && count <= max_prep_count {
                    out.push(finding(
                        Self::ID,
                        Severity::Low,
                        Statistic::count("preparer_account_postings", count, total),
                        vec![Cite::Entry(vid), Cite::Account(acct)],
                        format!(
                            "preparer has {count} of {total} live posting(s) on this account across {distinct_preps} preparers"
                        ),
                    ));
                    break;
                }
            }
        }
        Ok(out)
    }
}

/// `jet.manual_vs_rule`: manual entries on accounts predominantly posted by
/// deterministic rules.
pub struct ManualVsRule {
    params: Params,
}
procedure_boilerplate!(ManualVsRule, "jet.manual_vs_rule");

impl Procedure for ManualVsRule {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let min_rule_bps = i128::from(self.params.get_u32("min_rule_share_bps")?);
        let min_acct_entries = u64::from(self.params.get_u32("min_account_entries")?);
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let mut acct_totals: BTreeMap<VId, u64> = BTreeMap::new();
        let mut acct_rules: BTreeMap<VId, u64> = BTreeMap::new();
        let mut manual_entries: Vec<(VId, Vec<VId>)> = Vec::new();
        for e in &live {
            work.entry()?;
            let is_rule = matches!(e.entry.proposal.origin, EntryOrigin::Rule { .. });
            let is_manual = matches!(e.entry.proposal.origin, EntryOrigin::Intent { .. });
            let mut accts: Vec<VId> = Vec::new();
            for leg in &e.entry.proposal.legs {
                work.leg()?;
                if snapshot.accounts.contains_key(&leg.account_ref) {
                    accts.push(leg.account_ref);
                }
            }
            accts.sort_unstable();
            accts.dedup();
            for &acct in &accts {
                *acct_totals.entry(acct).or_insert(0) += 1;
                if is_rule {
                    *acct_rules.entry(acct).or_insert(0) += 1;
                }
            }
            if is_manual {
                manual_entries.push((e.vid, accts));
            }
        }
        let mut out = Vec::new();
        for (vid, accts) in manual_entries {
            work.compare(1)?;
            for acct in accts {
                let total = acct_totals.get(&acct).copied().unwrap_or(0);
                if total < min_acct_entries {
                    continue;
                }
                let rules = acct_rules.get(&acct).copied().unwrap_or(0);
                let share_bps =
                    amount_share_bps(i128::from(rules), i128::from(total), "rule share")?;
                if share_bps >= min_rule_bps {
                    out.push(finding(
                        Self::ID,
                        Severity::Medium,
                        Statistic {
                            name: "rule_share_bps".into(),
                            value: share_bps,
                            scale: 0,
                            population: total,
                        },
                        vec![Cite::Entry(vid), Cite::Account(acct)],
                        format!(
                            "manual entry on an account where {rules} of {total} postings ({share_bps} bps) are rule-derived"
                        ),
                    ));
                    break;
                }
            }
        }
        Ok(out)
    }
}

/// `jet.large_round_reversals`: round-amount postings that are reversed in a
/// subsequent period within `window_days`.
pub struct LargeRoundReversals {
    params: Params,
}
procedure_boilerplate!(LargeRoundReversals, "jet.large_round_reversals");

impl Procedure for LargeRoundReversals {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let power = self.params.get_u32("round_power")?;
        if power > 30 {
            return Err(LanternError::Parameter {
                procedure: Self::ID.into(),
                name: "round_power".into(),
                message: "must be at most 30".into(),
            });
        }
        let factor = 10i128
            .checked_pow(power)
            .ok_or(LanternError::Overflow("round factor"))?;
        let window = i32::try_from(self.params.get_u32("window_days")?)
            .map_err(|_| LanternError::Overflow("window_days"))?;
        let mut by_vid: BTreeMap<VId, &crate::snapshot::SnapshotEntry> = BTreeMap::new();
        for e in &snapshot.entries {
            work.entry()?;
            by_vid.insert(e.vid, e);
        }
        let population = snapshot.entries.len() as u64;
        let mut out = Vec::new();
        for (&rev_vid, &rev) in &by_vid {
            if rev.entry.proposal.class != fa_model::EntryClass::REVERSAL {
                continue;
            }
            for sup in &rev.entry.proposal.supersession {
                if sup.kind != fa_model::SupersessionKind::Reverses {
                    continue;
                }
                let Some(&orig) = by_vid.get(&sup.target.vid) else {
                    continue;
                };
                work.compare(1)?;
                if orig.period.is_empty() || rev.period.is_empty() || orig.period == rev.period {
                    continue;
                }
                let days =
                    rev.entry.proposal.effective_date.0 - orig.entry.proposal.effective_date.0;
                if !(0..=window).contains(&days) {
                    continue;
                }
                let mut has_round = false;
                for leg in &orig.entry.proposal.legs {
                    work.leg()?;
                    let Some(unit) = book.units.get(leg.amount.unit) else {
                        return Err(KernelError::Corrupt(
                            "a leg names an unregistered unit".into(),
                        )
                        .into());
                    };
                    let base = unit
                        .one()
                        .checked_mul(factor)
                        .ok_or(LanternError::Overflow("round base"))?;
                    let m = leg.amount.mantissa;
                    if m != 0 && m.checked_rem(base) == Some(0) {
                        has_round = true;
                    }
                }
                if has_round {
                    let mut cites = vec![Cite::Entry(orig.vid), Cite::Entry(rev_vid)];
                    cites.sort_by_key(|c| match c {
                        Cite::Entry(v) => v.0,
                        _ => 0,
                    });
                    out.push(finding(
                        Self::ID,
                        Severity::High,
                        Statistic::count("days_to_reversal", days as u64, population),
                        cites,
                        format!(
                            "round-amount entry in {} reversed {} day(s) later in {}",
                            orig.period, days, rev.period
                        ),
                    ));
                }
            }
        }
        Ok(out)
    }
}

/// `jet.suspense_aging`: accounts holding the `suspense` role with uncleared
/// balances older than `max_age_days`. Version 2 selects by role; version 1
/// guessed from code and name tokens.
pub struct SuspenseAging {
    params: Params,
}
procedure_boilerplate!(SuspenseAging, "jet.suspense_aging");

impl Procedure for SuspenseAging {
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
        _book: &BookContext,
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let max_age = i32::try_from(self.params.get_u32("max_age_days")?)
            .map_err(|_| LanternError::Overflow("max_age_days"))?;
        let suspense_vids = snapshot.role_population(Self::ID)?;
        let mut live = snapshot.live_postings_through(snapshot.coordinate.effective_through)?;
        live.sort_by_key(|e| e.vid);
        let population = live.len() as u64;
        let as_of = snapshot
            .coordinate
            .effective_through
            .or_else(|| live.iter().map(|e| e.entry.proposal.effective_date).max());
        let Some(as_of) = as_of else {
            return Ok(Vec::new());
        };
        let mut balances: BTreeMap<(VId, fa_money::UnitId), (i128, fa_time::DateDay, Vec<VId>)> =
            BTreeMap::new();
        for e in &live {
            work.entry()?;
            let eff = e.entry.proposal.effective_date;
            for leg in &e.entry.proposal.legs {
                work.leg()?;
                if !suspense_vids.contains(&leg.account_ref) {
                    continue;
                }
                let signed = signed_leg(leg.side, leg.amount.mantissa)?;
                let entry = balances
                    .entry((leg.account_ref, leg.amount.unit))
                    .or_insert((0, eff, Vec::new()));
                entry.0 = entry
                    .0
                    .checked_add(signed)
                    .ok_or(LanternError::Overflow("suspense balance"))?;
                if eff < entry.1 {
                    entry.1 = eff;
                }
                if entry.2.last().copied() != Some(e.vid) {
                    entry.2.push(e.vid);
                }
            }
        }
        let mut out = Vec::new();
        for ((acct_vid, _unit), (net, oldest, mut entry_vids)) in balances {
            work.compare(1)?;
            if net == 0 {
                continue;
            }
            let age = as_of.0 - oldest.0;
            if age > max_age {
                entry_vids.sort_unstable();
                entry_vids.dedup();
                let mut cites = vec![Cite::Account(acct_vid)];
                cites.extend(entry_vids.into_iter().take(MAX_CITES - 1).map(Cite::Entry));
                let severity = if age > max_age.saturating_mul(2) {
                    Severity::High
                } else {
                    Severity::Medium
                };
                out.push(finding(
                    Self::ID,
                    severity,
                    Statistic::count("age_days", age as u64, population),
                    cites,
                    format!(
                        "suspense/clearing account retains non-zero net balance {net} aged {age} day(s) (max_age_days {max_age})"
                    ),
                ));
            }
        }
        Ok(out)
    }
}

/// `jet.intercompany_unmatched`: live postings on accounts holding the
/// `intercompany` role without a reciprocal matching balance in the same
/// period and unit. Version 2 selects by role; version 1 guessed from code
/// and name tokens.
pub struct IntercompanyUnmatched {
    params: Params,
}
procedure_boilerplate!(IntercompanyUnmatched, "jet.intercompany_unmatched");

impl Procedure for IntercompanyUnmatched {
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
        work: &mut Meter<'_>,
    ) -> Result<Vec<Finding>, LanternError> {
        let ic_vids = snapshot.role_population(Self::ID)?;
        let mut live = snapshot.live_postings()?;
        live.sort_by_key(|e| e.vid);
        let population = live.len() as u64;
        type Tally = (i128, Vec<VId>, Vec<VId>);
        let mut by_period_unit: BTreeMap<(String, fa_money::UnitId), Tally> = BTreeMap::new();
        for e in &live {
            work.entry()?;
            for leg in &e.entry.proposal.legs {
                work.leg()?;
                if !ic_vids.contains(&leg.account_ref) {
                    continue;
                }
                let signed = signed_leg(leg.side, leg.amount.mantissa)?;
                let bucket = by_period_unit
                    .entry((e.period.clone(), leg.amount.unit))
                    .or_insert((0, Vec::new(), Vec::new()));
                bucket.0 = bucket
                    .0
                    .checked_add(signed)
                    .ok_or(LanternError::Overflow("intercompany balance"))?;
                bucket.1.push(e.vid);
                bucket.2.push(leg.account_ref);
            }
        }
        let mut out = Vec::new();
        for ((period, unit_id), (net, mut entry_vids, mut acct_vids)) in by_period_unit {
            work.compare(1)?;
            if net == 0 {
                continue;
            }
            let scale = book.units.get(unit_id).map_or(2, |u| u.scale);
            entry_vids.sort_unstable();
            entry_vids.dedup();
            acct_vids.sort_unstable();
            acct_vids.dedup();
            let mut cites: Vec<Cite> = entry_vids.into_iter().map(Cite::Entry).collect();
            cites.extend(acct_vids.into_iter().map(Cite::Account));
            if !period.is_empty() && snapshot.periods.contains_key(&period) {
                cites.push(Cite::Period(period.clone()));
            }
            cites.truncate(MAX_CITES);
            out.push(finding(
                Self::ID,
                Severity::High,
                Statistic {
                    name: "unmatched_mantissa".into(),
                    value: net.abs(),
                    scale,
                    population,
                },
                cites,
                format!(
                    "intercompany postings in period `{period}` have unmatched net balance {net}"
                ),
            ));
        }
        Ok(out)
    }
}
