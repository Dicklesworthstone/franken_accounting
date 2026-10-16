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

use crate::{
    Cite, Finding, LanternError, MAX_CITES, Params, Procedure, Severity, Snapshot, Statistic, Work,
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
        version: 1,
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
        work: &mut Work,
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
            work.entry();
            let mut round = Vec::new();
            for (i, leg) in e.entry.proposal.legs.iter().enumerate() {
                work.leg();
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
                if m != 0 && m % base == 0 {
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
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let window = i32::try_from(self.params.get_u32("window_days")?)
            .map_err(|_| LanternError::Overflow("window_days"))?;
        let mut population = 0u64;
        let mut hits = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry();
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
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let mut first_close = BTreeMap::new();
        for (period, transitions) in &snapshot.transitions {
            for t in transitions {
                work.compare(1);
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
            work.entry();
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
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let mut population = 0u64;
        let mut hits = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry();
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
        work: &mut Work,
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
            work.entry();
            population += 1;
            work.compare(e.approvals.len() as u64 + u64::from(legacy_pair.is_some()));
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
        work: &mut Work,
    ) -> Result<Vec<Finding>, LanternError> {
        let min = self.params.get_u32("min_chars")? as usize;
        let mut population = 0u64;
        let mut hits = Vec::new();
        let mut unreadable: Vec<VId> = Vec::new();
        for e in snapshot.live_postings()? {
            work.entry();
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
