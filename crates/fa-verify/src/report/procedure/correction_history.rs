//! Correction chains and subsequent events reconstructed from the complete
//! authenticated history. These procedures deliberately inspect reversed and
//! replaced entries too: net live balances cannot reveal how a correction was
//! made. Period boundaries and transition states come from journal controls,
//! never from the producer's finding narrative or mutable period projection.

use std::collections::BTreeMap;

use super::{
    Entry, MAX_FINDINGS, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, text,
};

type Replay = (Vec<VerifiedProcedureFinding>, u64, u64, u64);

pub(super) const SUBSEQUENT_DEFAULTS: [(&str, u32); 2] =
    [("min_amount", 100_000), ("window_days", 30)];

pub(super) fn decode(
    reader: &mut Reader<'_>,
    id: &str,
) -> Result<VerifiedProcedureParameters, ReportError> {
    let invalid = |message| failed("procedure_profile", message);
    if id == "reversal.patterns" {
        if reader.count(1, 20, "procedure.parameters")? != 0 {
            return Err(invalid("reversal patterns take no parameters"));
        }
        return Ok(VerifiedProcedureParameters::ReversalPatterns);
    }
    if id != "events.subsequent" {
        return Err(invalid("unknown correction-history profile"));
    }
    if reader.count(2, 20, "procedure.parameters")? != 2 {
        return Err(invalid(
            "subsequent events require both explicit parameters",
        ));
    }
    if text(reader, 64, "procedure.parameter")? != "min_amount" {
        return Err(invalid(
            "subsequent-event parameters must be lexically ordered",
        ));
    }
    let min_amount = reader.i128("procedure.parameter_value")?;
    if text(reader, 64, "procedure.parameter")? != "window_days" {
        return Err(invalid(
            "subsequent-event parameters must be lexically ordered",
        ));
    }
    let window_days = u32::try_from(reader.i128("procedure.parameter_value")?)
        .map_err(|_| invalid("subsequent-event lookahead must fit u32"))?;
    if min_amount < 0 || window_days == 0 {
        return Err(invalid(
            "subsequent events require a nonnegative amount and positive lookahead",
        ));
    }
    Ok(VerifiedProcedureParameters::SubsequentEvents {
        min_amount,
        window_days,
    })
}

fn invalid(message: &str) -> ReportError {
    failed("procedure_corrections", message)
}

fn charge(total: &mut u64, count: usize) -> Result<(), ReportError> {
    *total = total
        .checked_add(u64::try_from(count).map_err(|_| invalid("work count exceeds u64"))?)
        .ok_or_else(|| invalid("work count exceeds u64"))?;
    Ok(())
}

fn population(entries: &[Entry]) -> Result<BTreeMap<u128, &Entry>, ReportError> {
    let mut result = BTreeMap::new();
    for entry in entries {
        if result.insert(entry.identity, entry).is_some() {
            return Err(invalid("correction history repeats an entry identity"));
        }
        if !entry.legs.is_empty() && entry.period.is_none() {
            return Err(invalid("monetary entry lacks its authenticated period"));
        }
    }
    Ok(result)
}

fn period(entry: &Entry) -> &str {
    entry
        .period
        .as_ref()
        .map_or("", |period| period.code.as_str())
}

fn push(
    findings: &mut Vec<VerifiedProcedureFinding>,
    finding: VerifiedProcedureFinding,
) -> Result<(), ReportError> {
    if findings.len() == MAX_FINDINGS {
        return Err(failed(
            "bounded_input",
            "correction findings exceed the certificate bound",
        ));
    }
    findings.push(finding);
    Ok(())
}

fn reversal_patterns(entries: &[Entry]) -> Result<Replay, ReportError> {
    let by_identity = population(entries)?;
    let mut successors = BTreeMap::<u128, u128>::new();
    let mut comparisons = 0;
    for entry in entries {
        charge(&mut comparisons, entry.supersession.len())?;
        for &(target, _, _) in &entry.supersession {
            let successor = successors.entry(target).or_insert(entry.identity);
            *successor = (*successor).min(entry.identity);
        }
    }
    let count = u64::try_from(entries.len()).map_err(|_| invalid("population exceeds u64"))?;
    let mut findings = Vec::new();
    for entry in by_identity.values() {
        let Some(&(target, _, _)) = entry.supersession.first() else {
            continue;
        };
        charge(&mut comparisons, 1)?;
        let Some(original) = by_identity.get(&target) else {
            continue;
        };
        let cross_period = period(entry) != period(original);
        let next = successors.get(&entry.identity).copied();
        let chained = !original.supersession.is_empty() || next.is_some();
        if !cross_period && !chained {
            continue;
        }
        let mut cited = vec![entry.identity, original.identity];
        cited.extend(next);
        // The registered v2 algorithm retains traversal order and collapses
        // adjacent equal citations only. A set would change its wire contract.
        cited.dedup();
        let length = cited.len();
        push(
            &mut findings,
            VerifiedProcedureFinding {
                entry: Some(entry.identity),
                severity: if chained { 3 } else { 2 },
                statistic: VerifiedProcedureStatistic::ReversalChainEntries { entries: cited },
                population: count,
                narrative: format!(
                    "reversal/replacement pattern across {length} entries (cross_period={cross_period}, chained={chained}, {} -> {})",
                    period(original),
                    period(entry)
                ),
            },
        )?;
    }
    Ok((findings, count, 0, comparisons))
}

/// The latest transition governs subsequent-event boundary selection. In
/// particular, an Open transition is not a close, and reopening removes a
/// boundary. This differs intentionally from jet.post_closing's first close.
fn closed_boundaries(entries: &[Entry]) -> Result<BTreeMap<String, i32>, ReportError> {
    let mut latest = BTreeMap::<String, (u64, u128, i32, u8)>::new();
    for entry in entries {
        if (entry.class == 16) != entry.transition.is_some() {
            return Err(invalid("period-control facts are incomplete"));
        }
        let Some(transition) = &entry.transition else {
            continue;
        };
        let declaration = entry
            .period
            .as_ref()
            .ok_or_else(|| invalid("period transition lacks its authenticated boundary"))?;
        if declaration.code != transition.period
            || !entry.legs.is_empty()
            || !(1..=4).contains(&transition.to)
        {
            return Err(invalid("period transition and declaration disagree"));
        }
        let candidate = (
            entry.recorded_at,
            entry.identity,
            declaration.end,
            transition.to,
        );
        let current = latest.entry(transition.period.clone()).or_insert(candidate);
        if (candidate.0, candidate.1) > (current.0, current.1) {
            *current = candidate;
        }
    }
    Ok(latest
        .into_iter()
        .filter_map(|(period, (_, _, end, state))| (state >= 2).then_some((period, end)))
        .collect())
}

/// A half-open period's exclusive end is the first subsequent day. Widen
/// before subtracting so even the extreme civil-day values cannot wrap.
fn days_after(date: i32, end: i32, window: u32) -> Option<u32> {
    let days = u32::try_from(i64::from(date) - i64::from(end) + 1).ok()?;
    (days > 0 && days <= window).then_some(days)
}

fn subsequent_events(
    entries: &[Entry],
    registry: &Registry,
    min_amount: i128,
    window_days: u32,
) -> Result<Replay, ReportError> {
    if min_amount < 0 || window_days == 0 {
        return Err(invalid(
            "invalid subsequent-event amount or lookahead window",
        ));
    }
    let by_identity = population(entries)?;
    let boundaries = closed_boundaries(entries)?;
    let postings: Vec<_> = by_identity
        .values()
        .copied()
        .filter(|entry| !entry.legs.is_empty() && entry.class != 2)
        .collect();
    let count = u64::try_from(postings.len()).map_err(|_| invalid("population exceeds u64"))?;
    let mut legs = 0;
    let mut comparisons = 0;
    let mut findings = Vec::new();
    for entry in postings {
        charge(&mut legs, entry.legs.len())?;
        let effective = entry
            .effective
            .ok_or_else(|| invalid("subsequent posting lacks an effective date"))?;
        let mut maximum = None;
        for &(unit, amount) in &entry.legs {
            let amount = amount
                .checked_abs()
                .ok_or_else(|| invalid("leg magnitude exceeds i128"))?;
            // Equal maxima retain the first original leg, including its unit.
            if maximum.is_none_or(|(_, current)| amount > current) {
                maximum = Some((unit, amount));
            }
        }
        let Some((unit, mantissa)) = maximum.filter(|(_, amount)| *amount >= min_amount) else {
            continue;
        };
        // v3 chooses the first resolvable supersession target, then judges its
        // period. A later edge cannot replace a first same-period target.
        let original = entry
            .supersession
            .iter()
            .find_map(|(identity, _, _)| by_identity.get(identity).copied())
            .filter(|original| period(original) != period(entry));
        let mut prior = original.and_then(|original| {
            original.period.as_ref().and_then(|boundary| {
                days_after(effective, boundary.end, window_days)
                    .map(|days| (boundary.code.clone(), days))
            })
        });
        if prior.is_none() && matches!(entry.class, 4 | 5 | 7 | 14 | 15) {
            for (code, &end) in &boundaries {
                charge(&mut comparisons, 1)?;
                if code != period(entry)
                    && let Some(days) = days_after(effective, end, window_days)
                {
                    prior = Some((code.clone(), days));
                    break;
                }
            }
        }
        let Some((prior_period, days)) = prior else {
            continue;
        };
        let scale = *registry
            .unit_scales
            .get(&unit)
            .ok_or_else(|| invalid("subsequent posting names an unregistered unit"))?;
        push(
            &mut findings,
            VerifiedProcedureFinding {
                entry: Some(entry.identity),
                severity: 3,
                statistic: VerifiedProcedureStatistic::SubsequentEventAmount {
                    unit,
                    mantissa,
                    scale,
                    period: period(entry).into(),
                    prior_period: prior_period.clone(),
                    original: original.map(|original| original.identity),
                },
                population: count,
                narrative: format!(
                    "subsequent event in period {} ({days} day(s) after prior period {prior_period}) of magnitude {mantissa}",
                    period(entry)
                ),
            },
        )?;
    }
    Ok((findings, count, legs, comparisons))
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    entries: &[Entry],
    registry: &Registry,
) -> Result<Replay, ReportError> {
    match profile {
        VerifiedProcedureParameters::ReversalPatterns => reversal_patterns(entries),
        VerifiedProcedureParameters::SubsequentEvents {
            min_amount,
            window_days,
        } => subsequent_events(entries, registry, min_amount, window_days),
        _ => Err(invalid("unsupported correction-history procedure")),
    }
}

#[cfg(test)]
mod tests {
    use super::super::{EntryPeriod, PeriodTransition};
    use super::*;

    fn registry() -> Registry {
        Registry {
            unit_scales: BTreeMap::from([(1, 2), (2, 0)]),
            unit_currencies: BTreeMap::from([(1, 840), (2, 392)]),
            account_types: BTreeMap::new(),
            account_codes: BTreeMap::new(),
            account_roles: BTreeMap::new(),
            leg_parties: BTreeMap::new(),
            entry_facts: BTreeMap::new(),
            trace: None,
            open_items: None,
            policy_oid: [7; 32],
        }
    }

    fn entry(identity: u128, class: u16, code: &str, effective: i32, end: i32) -> Entry {
        Entry {
            identity,
            digest: [0; 32],
            recorded_at: identity as u64,
            effective: Some(effective),
            class,
            legs: vec![(1, 100_000), (1, 100_000)],
            leg_accounts: vec![(10, true), (20, false)],
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: Some(EntryPeriod {
                code: code.into(),
                effective,
                end,
                document: None,
            }),
            transition: None,
        }
    }

    fn control(identity: u128, recorded_at: u64, code: &str, end: i32, to: u8) -> Entry {
        let mut result = entry(identity, 16, code, end - 1, end);
        result.recorded_at = recorded_at;
        result.legs.clear();
        result.leg_accounts.clear();
        result.transition = Some(PeriodTransition {
            period: code.into(),
            to,
        });
        result
    }

    fn supersedes(mut entry: Entry, target: u128) -> Entry {
        entry.supersession.push((target, [0; 32], 1));
        entry
    }

    #[test]
    fn reversal_chains_choose_minimum_successor_and_preserve_traversal_order() {
        let mut entries = vec![
            entry(1, 1, "JAN", 1, 31),
            supersedes(entry(40, 4, "JAN", 2, 31), 1),
            supersedes(entry(30, 4, "JAN", 3, 31), 40),
            supersedes(entry(20, 5, "JAN", 3, 31), 40),
            entry(90, 17, "", 0, 0),
        ];
        entries.last_mut().unwrap().legs.clear();
        let first = reversal_patterns(&entries).unwrap();
        entries.reverse();
        let shuffled = reversal_patterns(&entries).unwrap();
        assert_eq!(first, shuffled);
        assert_eq!((first.1, first.2, first.3), (5, 0, 6));
        assert_eq!(first.0.len(), 3);
        assert_eq!(
            first
                .0
                .iter()
                .find(|finding| finding.entry == Some(40))
                .unwrap()
                .statistic,
            VerifiedProcedureStatistic::ReversalChainEntries {
                entries: vec![40, 1, 20],
            }
        );
        assert!(
            first
                .0
                .iter()
                .all(|finding| finding.severity == 3 && finding.population == 5)
        );
    }

    #[test]
    fn standalone_same_period_reversal_is_silent_but_cross_period_is_medium() {
        let entries = vec![
            entry(1, 1, "JAN", 1, 31),
            supersedes(entry(2, 4, "JAN", 2, 31), 1),
            entry(3, 1, "JAN", 3, 31),
            supersedes(entry(4, 4, "FEB", 31, 59), 3),
        ];
        let (findings, count, legs, comparisons) = reversal_patterns(&entries).unwrap();
        assert_eq!((count, legs, comparisons), (4, 0, 4));
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].entry, Some(4));
        assert_eq!(findings[0].severity, 2);
        assert_eq!(
            findings[0].narrative,
            "reversal/replacement pattern across 2 entries (cross_period=true, chained=false, JAN -> FEB)"
        );
    }

    #[test]
    fn latest_period_state_removes_reopened_boundaries_but_not_cross_period_lineage() {
        let mut entries = vec![
            control(100, 1, "JAN", 31, 1),
            control(101, 2, "JAN", 31, 2),
            control(102, 3, "FEB", 59, 1),
            entry(1, 1, "JAN", 10, 31),
            entry(2, 7, "FEB", 31, 59),
            supersedes(entry(3, 4, "FEB", 35, 59), 1),
            entry(4, 1, "FEB", 32, 59),
        ];
        let (closed, count, legs, comparisons) =
            subsequent_events(&entries, &registry(), 100_000, 5).unwrap();
        assert_eq!((count, legs, comparisons), (4, 8, 1));
        assert_eq!(
            closed
                .iter()
                .map(|finding| finding.entry)
                .collect::<Vec<_>>(),
            [Some(2), Some(3)]
        );
        entries.insert(0, control(99, 4, "JAN", 31, 1));
        let (reopened, count, legs, comparisons) =
            subsequent_events(&entries, &registry(), 100_000, 5).unwrap();
        assert_eq!((count, legs, comparisons), (4, 8, 0));
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened[0].entry, Some(3));
        assert!(matches!(
            reopened[0].statistic,
            VerifiedProcedureStatistic::SubsequentEventAmount {
                original: Some(1),
                ..
            }
        ));
    }

    #[test]
    fn subsequent_class_inventory_and_original_leg_unit_ties_are_exact() {
        let mut entries = vec![control(100, 1, "JAN", 31, 2)];
        for class in 1..=15 {
            let mut row = entry(u128::from(class), class, "FEB", 31, 59);
            row.legs = vec![(2, -100_000), (1, 100_000)];
            entries.push(row);
        }
        let (findings, count, legs, comparisons) =
            subsequent_events(&entries, &registry(), 100_000, 1).unwrap();
        assert_eq!((count, legs, comparisons), (14, 28, 5));
        assert_eq!(
            findings
                .iter()
                .map(|finding| finding.entry.unwrap())
                .collect::<Vec<_>>(),
            [4, 5, 7, 14, 15]
        );
        assert!(findings.iter().all(|finding| matches!(
            finding.statistic,
            VerifiedProcedureStatistic::SubsequentEventAmount {
                unit: 2,
                scale: 0,
                mantissa: 100_000,
                ..
            }
        )));
        assert!(
            subsequent_events(&entries, &registry(), 100_001, 1)
                .unwrap()
                .0
                .is_empty()
        );
    }

    #[test]
    fn first_resolvable_supersession_is_selected_before_testing_its_period() {
        let mut changed = supersedes(entry(3, 4, "FEB", 31, 59), 2);
        changed.supersession.push((1, [0; 32], 1));
        let mut entries = vec![
            entry(1, 1, "JAN", 5, 31),
            entry(2, 1, "FEB", 31, 59),
            changed,
        ];
        assert!(
            subsequent_events(&entries, &registry(), 0, 30)
                .unwrap()
                .0
                .is_empty()
        );
        entries[2].supersession[0].0 = 999;
        let (findings, _, _, _) = subsequent_events(&entries, &registry(), 0, 30).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(matches!(
            findings[0].statistic,
            VerifiedProcedureStatistic::SubsequentEventAmount {
                original: Some(1),
                ..
            }
        ));
    }

    #[test]
    fn closed_period_matching_uses_lexical_order_and_charges_every_examination() {
        let entries = vec![
            control(100, 1, "B", 31, 2),
            control(101, 2, "A", 0, 3),
            control(102, 3, "C", 59, 4),
            entry(1, 7, "C", 31, 59),
        ];
        let (findings, _, _, comparisons) = subsequent_events(&entries, &registry(), 0, 1).unwrap();
        assert_eq!(comparisons, 2);
        assert!(matches!(&findings[0].statistic,
            VerifiedProcedureStatistic::SubsequentEventAmount { prior_period, .. } if prior_period == "B"));
    }

    #[test]
    fn date_arithmetic_covers_half_open_boundaries_and_extreme_civil_days() {
        assert_eq!(days_after(30, 31, 30), None);
        assert_eq!(days_after(31, 31, 1), Some(1));
        assert_eq!(days_after(60, 31, 30), Some(30));
        assert_eq!(days_after(61, 31, 30), None);
        assert_eq!(days_after(i32::MIN, i32::MAX, u32::MAX), None);
        assert_eq!(days_after(i32::MAX, i32::MIN, u32::MAX), None);
        assert_eq!(days_after(i32::MAX - 1, i32::MIN, u32::MAX), Some(u32::MAX));
    }

    #[test]
    fn incomplete_authenticated_period_facts_fail_closed() {
        let mut posting = entry(1, 7, "FEB", 31, 59);
        posting.period = None;
        assert!(reversal_patterns(&[posting.clone()]).is_err());
        assert!(subsequent_events(&[posting], &registry(), 0, 30).is_err());
        let mut transition = control(2, 1, "JAN", 31, 2);
        transition.period.as_mut().unwrap().code = "FEB".into();
        assert!(subsequent_events(&[transition], &registry(), 0, 30).is_err());
        let mut missing = control(3, 1, "JAN", 31, 2);
        missing.transition = None;
        assert!(subsequent_events(&[missing], &registry(), 0, 30).is_err());
    }
}
