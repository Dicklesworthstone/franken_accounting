//! Reconstruct post-closing observations from original period controls.
//!
//! The journal's recording order supplies chronology. Period declarations and
//! transitions are replayed even after a first close has been found; a later
//! reopen never replaces that first close, and malformed excluded controls
//! cannot be hidden by an otherwise valid finding population.

use std::collections::BTreeMap;

use super::{
    Entry, PeriodTransition, ReportError, VerifiedProcedureFinding, VerifiedProcedureStatistic,
};
use crate::envelope::{LeafEnvelope, proposal_after_legs};
use crate::report::{failed, metadata, text};

/// Only the caller's already authenticated historical entry inventory is
/// visited. Entries recorded after the certificate frontier are absent from
/// `infos`, even when the checkpoint authenticates a longer prefix.
pub(in crate::report) fn period_transitions(
    book: &[u8; 16],
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
) -> Result<BTreeMap<usize, PeriodTransition>, ReportError> {
    let mut schema = metadata::Schema::default();
    let mut transitions = BTreeMap::new();
    for (&index, info) in infos {
        let envelope = envelopes
            .get(index)
            .ok_or_else(|| invalid("period history has no original envelope"))?;
        let &(proposal_len, payload) = records
            .get(index)
            .ok_or_else(|| invalid("period history has no original payload"))?;
        let proposal = payload
            .get(..proposal_len)
            .ok_or_else(|| invalid("period history has an invalid proposal length"))?;
        if let Some((13, body)) = info.schema {
            schema.apply(13, body, book, envelope.commit_seq)?;
        }
        let mut r = proposal_after_legs(proposal)?;
        let is_transition = r.present("period.control")? && r.u8("period.tag")? == 0;
        if (envelope.class == 16) != is_transition {
            return Err(invalid(
                "PeriodControl class and transition payload disagree",
            ));
        }
        if !is_transition {
            continue;
        }
        if !envelope.account_vids.is_empty() || !envelope.unit_ids.is_empty() {
            return Err(invalid("period transition carries monetary legs"));
        }
        let calendar = text(&mut r, 128, "period.calendar")?;
        let code = text(&mut r, 128, "period.code")?;
        let from = r.u8("period.from")?;
        let to = r.u8("period.to")?;
        let (start, end, _, _) = schema
            .period_state(code)
            .ok_or_else(|| invalid("period transition precedes its declaration"))?;
        let effective = if from == 0 {
            Some(start)
        } else {
            end.checked_sub(1)
        };
        if info.period != Some((calendar, code)) || envelope.effective_day != effective {
            return Err(invalid(
                "period transition differs from its period-law coordinate",
            ));
        }
        schema.transition_period(calendar, code, from, to)?;
        transitions.insert(
            index,
            PeriodTransition {
                period: code.into(),
                to,
            },
        );
    }
    Ok(transitions)
}

#[derive(Debug)]
pub(super) struct FirstClose {
    recorded_at: u64,
    state: u8,
}

pub(super) fn first_closes(
    entries: &[Entry],
) -> Result<(BTreeMap<String, FirstClose>, u64), ReportError> {
    let mut transitions = Vec::new();
    for entry in entries {
        if (entry.class == 16) != entry.transition.is_some() {
            return Err(invalid("period-control facts are incomplete"));
        }
        if let Some(transition) = &entry.transition {
            if !entry.legs.is_empty() || !matches!(transition.to, 1..=4) {
                return Err(invalid("invalid period transition facts"));
            }
            transitions.push((entry.recorded_at, entry.identity, transition));
        }
    }
    // The native snapshot orders each period's transitions by recording
    // sequence. Entry identity makes equal-sequence order deterministic.
    transitions.sort_unstable_by_key(|&(recorded_at, identity, _)| (recorded_at, identity));
    let mut closes = BTreeMap::new();
    let mut comparisons = 0u64;
    for (recorded_at, _, transition) in transitions {
        if closes.contains_key(&transition.period) {
            continue;
        }
        comparisons = comparisons
            .checked_add(1)
            .ok_or_else(|| invalid("period transition comparison count overflows"))?;
        if matches!(transition.to, 2..=4) {
            closes.insert(
                transition.period.clone(),
                FirstClose {
                    recorded_at,
                    state: transition.to,
                },
            );
        }
    }
    Ok((closes, comparisons))
}

pub(super) fn finding(
    entry: &Entry,
    closes: &BTreeMap<String, FirstClose>,
) -> Result<Option<VerifiedProcedureFinding>, ReportError> {
    let period = entry
        .period
        .as_ref()
        .ok_or_else(|| invalid("a live posting has no authenticated period"))?;
    let Some(close) = closes.get(&period.code) else {
        return Ok(None);
    };
    if entry.recorded_at <= close.recorded_at {
        return Ok(None);
    }
    let commits = entry.recorded_at - close.recorded_at;
    let state = match close.state {
        2 => "SoftClosed",
        3 => "Closed",
        4 => "Locked",
        _ => return Err(invalid("first close has an invalid state")),
    };
    Ok(Some(VerifiedProcedureFinding {
        entry: Some(entry.identity),
        severity: 2,
        statistic: VerifiedProcedureStatistic::CommitsAfterClose {
            period: period.code.clone(),
            commits,
        },
        population: 0,
        narrative: format!(
            "recorded {commits} commit(s) after the period's first transition to {state}"
        ),
    }))
}

fn invalid(detail: &str) -> ReportError {
    failed("procedure_period", detail)
}

#[cfg(test)]
mod tests;
