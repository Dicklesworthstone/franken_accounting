//! Dry-run warnings (plan §5.1's dry run; bead fa-d5un): what journal-entry
//! testing would later flag about a planned entry, said while its preparer
//! can still change it. A warning is data. It never refuses, and it never
//! changes the plan, its certificate or any amount.
//!
//! Only a preparer's own entries are judged (`Original` and `Adjusting`);
//! derived entries such as closings, revaluations and reversals are not.
//! Everything is read at the plan's snapshot, in work bounded by the plan's
//! legs and by the entries of the periods near its date, never by the book:
//! - `RoundAmount`: legs whose magnitude is a nonzero whole multiple of
//!   `10^round_power` units, with `jet.round_amounts`' registered default.
//! - `SoftClosedPeriod`: the entry posts into a SoftClosed period, which
//!   `jet.post_closing` flags once it is recorded.
//! - `PossibleDuplicate`: a live posting entry with the same legs (account,
//!   side, unit, amount and dimensions, so the same parties) effective at
//!   most `window_days` days away, `duplicates.same_same_different`'s
//!   registered default. Each such entry is cited. Reading other entries
//!   needs a capability that reads the whole book; without one, this check
//!   does not run and is reported as unchecked.
//! - `CutoffDrift`: the entry's document date lies outside the period its
//!   effective date posts to. The plan's `cutoff_tolerance_days` has no
//!   registered value, so a drift within one period is not judged.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_intents::PostPlan;
use fa_journal::{KernelError, PeriodRow};
use fa_model::symbols::relation;
use fa_model::{EntryClass, EntryPayload, LegPayload, SupersessionKind};
use fa_money::{Amount, Side};
use fa_policy::{Capability, Reach};
use fa_time::{DateDay, PeriodState};
use fgdb::Database;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{AsyncBook, BookError};

/// What a dry run noticed (plan §5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PlanWarningKind {
    RoundAmount,
    SoftClosedPeriod,
    PossibleDuplicate,
    CutoffDrift,
}

impl PlanWarningKind {
    /// The plan's name for it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RoundAmount => "RoundAmount",
            Self::SoftClosedPeriod => "SoftClosedPeriod",
            Self::PossibleDuplicate => "PossibleDuplicate",
            Self::CutoffDrift => "CutoffDrift",
        }
    }
}

/// One warning about a planned entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanWarning {
    pub kind: PlanWarningKind,
    /// The planned legs it concerns, ascending.
    pub legs: Vec<u16>,
    /// The recorded entries it cites, ascending by vid.
    pub entries: Vec<VId>,
    /// What was noticed and what to check, in one sentence.
    pub message: String,
}

/// Every warning about one plan, and the checks that did not run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlanWarnings {
    /// In kind order.
    pub warnings: Vec<PlanWarning>,
    /// Each check that did not run, with why.
    pub unchecked: Vec<(PlanWarningKind, String)>,
}

/// The preparer-authored classes the warnings judge.
fn judged(class: EntryClass) -> bool {
    class == EntryClass::ORIGINAL || class == EntryClass::ADJUSTING
}

/// A leg as duplicate matching compares it: everything but its memo,
/// valuation and applications.
type LegKey = (VId, bool, u32, i128, Vec<(u32, VId)>);

fn leg_keys(legs: &[LegPayload]) -> Vec<LegKey> {
    let mut keys: Vec<LegKey> = legs
        .iter()
        .map(|leg| {
            (
                leg.account_ref,
                leg.side == Side::Debit,
                leg.amount.unit.0,
                leg.amount.mantissa,
                leg.dimension_set.clone(),
            )
        })
        .collect();
    keys.sort();
    keys
}

fn corrupt(what: &str) -> BookError {
    BookError::Kernel(KernelError::Corrupt(what.into()))
}

fn ordinal(i: usize) -> Result<u16, BookError> {
    u16::try_from(i).map_err(|_| corrupt("a planned leg ordinal exceeds u16"))
}

fn round_amounts(
    proposal: &EntryPayload,
    book: &fa_journal::genesis::BookContext,
) -> Result<Option<PlanWarning>, BookError> {
    let power = fa_lantern::Params::defaults("jet.round_amounts")?.get_u32("round_power")?;
    let factor = 10i128
        .checked_pow(power)
        .ok_or_else(|| corrupt("the registered round_power overflows"))?;
    let mut legs = Vec::new();
    let mut base = None;
    for (i, leg) in proposal.legs.iter().enumerate() {
        let unit = book
            .units
            .get(leg.amount.unit)
            .ok_or_else(|| corrupt("a planned leg names an unregistered unit"))?;
        let step = unit
            .one()
            .checked_mul(factor)
            .ok_or_else(|| corrupt("the round base overflows its unit"))?;
        let m = leg.amount.mantissa;
        if m != 0 && m.checked_rem(step) == Some(0) {
            legs.push(ordinal(i)?);
            base.get_or_insert(Amount::new(leg.amount.unit, step));
        }
    }
    let Some(base) = base else {
        return Ok(None);
    };
    let named: Vec<String> = legs.iter().map(u16::to_string).collect();
    Ok(Some(PlanWarning {
        kind: PlanWarningKind::RoundAmount,
        message: format!(
            "leg {} is a whole multiple of {} (round_power {power}): journal-entry testing flags round amounts (jet.round_amounts); check that the amount is the documented one, not an estimate",
            named.join(", "),
            base.render(&book.units),
        ),
        legs,
        entries: Vec::new(),
    }))
}

/// The entry's period as the plan certified it, at the plan's snapshot.
fn plan_period<V: Vfs + Clone>(
    db: &Database<V>,
    periods: &[PeriodRow],
    code: &str,
    at: CommitSeq,
) -> Result<Option<PeriodRow>, BookError> {
    let Some(listed) = periods.iter().find(|p| p.code == code) else {
        return Ok(None);
    };
    db.vertex_at(listed.vid, at)
        .map_err(KernelError::from)?
        .map(|row| PeriodRow::decode(&row))
        .transpose()
        .map_err(BookError::from)
}

/// Whether `vid` is still in force at `at`: no recorded entry reverses or
/// replaces it.
fn in_force<V: Vfs + Clone>(db: &Database<V>, vid: VId, at: CommitSeq) -> Result<bool, BookError> {
    for superseder in db
        .in_neighbours_at(vid, relation::SUPERSEDES, at)
        .map_err(KernelError::from)?
    {
        let Some((entry, _)) = fa_journal::post::read_entry_at(db, superseder, at)? else {
            continue;
        };
        if entry.proposal.supersession.iter().any(|link| {
            link.target.vid == vid
                && matches!(
                    link.kind,
                    SupersessionKind::Reverses | SupersessionKind::Replaces
                )
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn possible_duplicates<V: Vfs + Clone>(
    db: &Database<V>,
    proposal: &EntryPayload,
    periods: &[PeriodRow],
    at: CommitSeq,
) -> Result<Option<PlanWarning>, BookError> {
    let window =
        fa_lantern::Params::defaults("duplicates.same_same_different")?.get_u32("window_days")?;
    let window =
        i32::try_from(window).map_err(|_| corrupt("the registered window_days overflows"))?;
    let date = proposal.effective_date;
    let (from, through) = (date.0.saturating_sub(window), date.0.saturating_add(window));
    let planned = leg_keys(&proposal.legs);
    let own: BTreeSet<VId> = proposal.supersession.iter().map(|s| s.target.vid).collect();
    let mut cited = BTreeSet::new();
    let mut nearest: Option<(i32, DateDay)> = None;
    for period in periods
        .iter()
        .filter(|p| p.start.0 <= through && p.end.0 > from)
    {
        for vid in db
            .in_neighbours_at(period.vid, relation::IN_PERIOD, at)
            .map_err(KernelError::from)?
        {
            if own.contains(&vid) || cited.contains(&vid) {
                continue;
            }
            let Some((entry, _)) = fa_journal::post::read_entry_at(db, vid, at)? else {
                continue;
            };
            let candidate = &entry.proposal;
            let distance = (candidate.effective_date.0 - date.0).abs();
            if candidate.legs.is_empty()
                || matches!(candidate.class, EntryClass::REVERSAL | EntryClass::PENDING)
                || (candidate.principal_ref == proposal.principal_ref
                    && candidate.idempotency_key == proposal.idempotency_key)
                || distance > window
                || leg_keys(&candidate.legs) != planned
                || !in_force(db, vid, at)?
            {
                continue;
            }
            cited.insert(vid);
            if nearest.is_none_or(|(d, _)| distance < d) {
                nearest = Some((distance, candidate.effective_date));
            }
        }
    }
    let Some((_, on)) = nearest else {
        return Ok(None);
    };
    let entries: Vec<VId> = cited.into_iter().collect();
    let named: Vec<String> = entries.iter().map(|v| format!("{:032x}", v.0)).collect();
    Ok(Some(PlanWarning {
        kind: PlanWarningKind::PossibleDuplicate,
        message: format!(
            "{} recorded entr{} with the same legs and parties, effective within {window} days (nearest {}): {}; if this records the same event, do not post it again (fa entry show <vid>)",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" },
            on.render(),
            named.join(", "),
        ),
        legs: Vec::new(),
        entries,
    }))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// The dry-run warnings about `plan`, read at its snapshot. `capability`
    /// is the one that planned it: the duplicate check reads other entries
    /// only when it reads the whole book, and is reported unchecked
    /// otherwise.
    pub fn plan_warnings(
        &self,
        cx: &PurposeContexts,
        plan: &PostPlan,
        capability: &Capability,
    ) -> Result<PlanWarnings, BookError> {
        let proposal = plan.proposal();
        let certificate = plan.certificate();
        let at = certificate.snapshot_seq;
        let mut out = PlanWarnings::default();
        if !judged(proposal.class) {
            return Ok(out);
        }
        let reads_book =
            fa_policy::admit_read(capability, proposal.principal_ref, proposal.book_id)
                .and_then(|()| fa_policy::reach(capability, &Reach::whole_book(true), None))
                .is_ok();
        self.query(cx, |db, book| {
            out.warnings.extend(round_amounts(proposal, book)?);
            let periods = fa_journal::genesis::list_periods(db)?;
            let period = plan_period(db, &periods, &certificate.period, at)?;
            if let Some(period) = &period
                && period.state == PeriodState::SoftClosed
            {
                out.warnings.push(PlanWarning {
                    kind: PlanWarningKind::SoftClosedPeriod,
                    legs: Vec::new(),
                    entries: Vec::new(),
                    message: format!(
                        "{} is SoftClosed: an entry posted after its soft close is in the post-closing population journal-entry testing reviews (jet.post_closing)",
                        period.code
                    ),
                });
            }
            if reads_book {
                out.warnings
                    .extend(possible_duplicates(db, proposal, &periods, at)?);
            } else {
                out.unchecked.push((
                    PlanWarningKind::PossibleDuplicate,
                    "the capability does not read the whole book, so other entries are not read"
                        .into(),
                ));
            }
            if let (Some(document), Some(period)) = (proposal.document_date, &period)
                && !(period.start..period.end).contains(&document)
            {
                out.warnings.push(PlanWarning {
                    kind: PlanWarningKind::CutoffDrift,
                    legs: Vec::new(),
                    entries: Vec::new(),
                    message: format!(
                        "the document date {} is outside {} ({} through {}), where the effective date {} posts: check the cutoff",
                        document.render(),
                        period.code,
                        period.start.render(),
                        period
                            .end
                            .add_days(-1)
                            .map_or_else(|_| period.end.render(), DateDay::render),
                        proposal.effective_date.render(),
                    ),
                });
            }
            Ok(())
        })?;
        out.warnings.sort_by_key(|w| w.kind);
        Ok(out)
    }
}
