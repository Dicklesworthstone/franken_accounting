//! Different-date duplicate observations independently replayed from the prefix.
//!
//! Version 1 pairs each posting only with its nearest later unrelated occurrence
//! of the same exact leg multiset. A same-day occurrence is never a pair. The
//! authenticated correction graph excludes ancestors, not siblings. Range
//! summaries reconstruct the version's comparison witness without trusting a
//! producer-supplied search index or allocating from a claimed output count.

use std::collections::BTreeMap;

use super::{
    DuplicateLineage, Entry, MAX_FINDINGS, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureStatistic, failed,
};

type LegSignature = Vec<(u128, u8, u32, i128)>;
type DatedEntry = (i32, u64, u128);

#[derive(Clone, Copy, Default)]
struct Range {
    occupied: bool,
    component: Option<u128>,
    /// Minimum subtree end and maximum subtree start in a correction forest.
    extrema: Option<(usize, usize)>,
}

impl Range {
    fn join(left: Self, right: Self) -> Self {
        if !left.occupied {
            return right;
        }
        if !right.occupied {
            return left;
        }
        Self {
            occupied: true,
            component: left
                .component
                .filter(|component| Some(*component) == right.component),
            extrema: left.extrema.zip(right.extrema).map(
                |((left_end, left_start), (right_end, right_start))| {
                    (left_end.min(right_end), left_start.max(right_start))
                },
            ),
        }
    }

    fn may_contain_unrelated(&self, id: u128, lineage: &DuplicateLineage) -> bool {
        if !self.occupied {
            return false;
        }
        if self.component != lineage.components.get(&id).copied() {
            return true;
        }
        match (self.extrema, lineage.intervals.get(&id)) {
            (Some((min_end, max_start)), Some(&(start, end))) => {
                min_end <= start || max_start >= end
            }
            _ => true,
        }
    }
}

struct Candidates {
    ranges: Vec<Range>,
    leaves: usize,
}

impl Candidates {
    fn new(list: &[DatedEntry], lineage: &mut DuplicateLineage) -> Result<Self, ReportError> {
        let leaves = list
            .len()
            .checked_next_power_of_two()
            .ok_or_else(|| failed("bounded_input", "duplicate candidate range overflows"))?;
        let length = leaves
            .checked_mul(2)
            .ok_or_else(|| failed("bounded_input", "duplicate candidate range overflows"))?;
        let mut ranges = vec![Range::default(); length];
        for (index, &(_, _, id)) in list.iter().enumerate() {
            ranges[leaves + index] = Range {
                occupied: true,
                component: lineage.components.get(&id).copied(),
                extrema: lineage.intervals.get(&id).map(|&(start, end)| (end, start)),
            };
        }
        for index in (1..leaves).rev() {
            ranges[index] = Range::join(ranges[index * 2], ranges[index * 2 + 1]);
        }
        // One charge per populated leaf and per internal range, including
        // internal nodes containing the padding at the next power of two.
        lineage.charge(list.len() as u64)?;
        lineage.charge((leaves - 1) as u64)?;
        Ok(Self { ranges, leaves })
    }

    fn first(
        &self,
        list: &[DatedEntry],
        from: usize,
        id: u128,
        lineage: &mut DuplicateLineage,
    ) -> Result<Option<usize>, ReportError> {
        if !lineage.components.contains_key(&id) {
            return Ok((from < list.len()).then_some(from));
        }
        let mut pending = vec![(1usize, 0usize, self.leaves)];
        while let Some((index, start, end)) = pending.pop() {
            lineage.charge(1)?;
            if end <= from || !self.ranges[index].may_contain_unrelated(id, lineage) {
                continue;
            }
            if index >= self.leaves {
                let candidate = list.get(start).ok_or_else(|| {
                    failed(
                        "procedure_lineage",
                        "duplicate candidate range has no posting",
                    )
                })?;
                if !related(id, candidate.2, lineage)? {
                    return Ok(Some(start));
                }
            } else {
                let middle = start + (end - start) / 2;
                pending.push((index * 2 + 1, middle, end));
                pending.push((index * 2, start, middle));
            }
        }
        Ok(None)
    }
}

fn related(left: u128, right: u128, lineage: &mut DuplicateLineage) -> Result<bool, ReportError> {
    if left == right {
        return Ok(true);
    }
    let (Some(a), Some(b)) = (
        lineage.components.get(&left),
        lineage.components.get(&right),
    ) else {
        return Ok(false);
    };
    if a != b {
        return Ok(false);
    }
    if let (Some(&(a_start, a_end)), Some(&(b_start, b_end))) =
        (lineage.intervals.get(&left), lineage.intervals.get(&right))
    {
        return Ok(
            (a_start <= b_start && b_start < a_end) || (b_start <= a_start && a_start < b_end)
        );
    }
    Ok(lineage.reaches(left, right)? || lineage.reaches(right, left)?)
}

pub(super) fn replay(
    entries: &[Entry],
    live: &[&Entry],
    window_days: u32,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    let mut lineage = DuplicateLineage::new(entries)?;
    let mut groups: BTreeMap<LegSignature, Vec<DatedEntry>> = BTreeMap::new();
    let mut legs_visited = 0u64;
    for entry in live {
        if entry.legs.len() != entry.leg_accounts.len() {
            return Err(failed(
                "procedure_profile",
                "duplicate leg identities are incomplete",
            ));
        }
        let day = entry.effective.ok_or_else(|| {
            failed(
                "procedure_selection",
                "duplicate posting has no effective date",
            )
        })?;
        let mut signature: LegSignature = entry
            .legs
            .iter()
            .zip(&entry.leg_accounts)
            .map(|(&(unit, amount), &(account, debit))| (account, u8::from(!debit), unit, amount))
            .collect();
        legs_visited = legs_visited
            .checked_add(signature.len() as u64)
            .ok_or_else(|| failed("procedure_arithmetic", "duplicate leg count overflows"))?;
        signature.sort_unstable();
        groups
            .entry(signature)
            .or_default()
            .push((day, entry.recorded_at, entry.identity));
    }
    let mut findings = Vec::new();
    for list in groups.values_mut() {
        list.sort_unstable();
        // The v1 work contract builds each group's range index whenever the
        // complete prefix contains any correction, including another group.
        let candidates = if lineage.parents.is_empty() {
            None
        } else {
            Some(Candidates::new(list, &mut lineage)?)
        };
        let mut next_date = 0usize;
        for (index, &(day, _, earlier)) in list.iter().enumerate() {
            next_date = next_date.max(index + 1);
            while next_date < list.len() && list[next_date].0 == day {
                lineage.charge(1)?;
                next_date += 1;
            }
            let candidate = match &candidates {
                Some(candidates) => candidates.first(list, next_date, earlier, &mut lineage)?,
                None => (next_date < list.len()).then_some(next_date),
            };
            let Some(candidate) = candidate else {
                continue;
            };
            lineage.charge(1)?;
            let (later_day, _, later) = list[candidate];
            let days = u32::try_from(i64::from(later_day) - i64::from(day)).map_err(|_| {
                failed(
                    "procedure_arithmetic",
                    "duplicate date distance is out of range",
                )
            })?;
            if days > window_days {
                continue;
            }
            if findings.len() >= MAX_FINDINGS {
                return Err(failed(
                    "bounded_input",
                    "duplicate findings exceed the certificate bound",
                ));
            }
            findings.push(VerifiedProcedureFinding {
                entry: Some(earlier),
                severity: 1,
                statistic: VerifiedProcedureStatistic::DaysApart {
                    earlier,
                    later,
                    days,
                },
                population: live.len() as u64,
                narrative: format!(
                    "two entries share the same legs {days} day(s) apart (window {window_days})"
                ),
            });
        }
    }
    Ok((findings, legs_visited, lineage.comparisons))
}

#[cfg(test)]
mod tests {
    use super::super::{
        Certificate, Registry, VerifiedProcedure, VerifiedProcedureParameters, decode, framed_hash,
        recompute_version, replay as replay_certificate,
    };
    use super::*;
    use crate::blake3::hash_parts;
    use crate::codec::Writer;

    fn entry(id: u128, day: i32, recorded_at: u64, amount: i128) -> Entry {
        Entry {
            identity: id,
            digest: hash_parts(b"different-date-test", &[&id.to_le_bytes()]),
            recorded_at,
            effective: Some(day),
            class: 1,
            legs: vec![(1, amount), (1, amount)],
            leg_accounts: vec![(10, true), (20, false)],
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: None,
            transition: None,
        }
    }

    fn registry() -> Registry {
        Registry {
            unit_scales: BTreeMap::from([(1, 2)]),
            unit_currencies: BTreeMap::from([(1, 840)]),
            account_types: BTreeMap::new(),
            policy_oid: [7; 32],
        }
    }

    fn run(window_days: u32, entries: Vec<Entry>) -> (VerifiedProcedure, Vec<u8>) {
        recompute_version(
            [1; 16],
            100,
            1,
            None,
            VerifiedProcedureParameters::SameSameDifferent { window_days },
            entries,
            &registry(),
        )
        .unwrap()
    }

    fn pairs(report: &VerifiedProcedure) -> Vec<(u128, u128, u32)> {
        let mut pairs: Vec<_> = report
            .findings
            .iter()
            .map(|finding| {
                let VerifiedProcedureStatistic::DaysApart {
                    earlier,
                    later,
                    days,
                } = finding.statistic
                else {
                    panic!("different-date statistic");
                };
                assert_eq!(finding.entry, Some(earlier));
                assert_eq!(finding.severity, 1);
                (earlier, later, days)
            })
            .collect();
        pairs.sort_unstable();
        pairs
    }

    #[test]
    fn different_date_duplicates_use_nearest_later_day_recording_order_and_inclusive_window() {
        let entries = vec![
            entry(900, 0, 1, 100),
            entry(10, 2, 5, 100),
            entry(2, 2, 3, 100),
            entry(5, 4, 6, 100),
            entry(8, 35, 7, 100),
            entry(12, 0, 2, 100),
            entry(22, 2, 8, 101),
        ];
        let (report, output) = run(2, entries.clone());
        assert_eq!(
            pairs(&report),
            vec![(2, 5, 2), (10, 5, 2), (12, 2, 2), (900, 2, 2)]
        );
        assert_eq!(
            (
                report.population,
                report.live_entries,
                report.live_legs,
                report.comparisons
            ),
            (7, 7, 14, 14)
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.population == 7)
        );
        for window in [0, 1] {
            assert!(run(window, entries.clone()).0.findings.is_empty());
        }
        let mut reordered = entries;
        reordered.reverse();
        assert_eq!(run(2, reordered).1, output);
    }

    #[test]
    fn different_date_duplicates_skip_ancestors_but_keep_siblings_and_charge_every_group() {
        let root = entry(1, 0, 1, 100);
        let mut left = entry(2, 1, 2, 100);
        let mut right = entry(3, 1, 3, 100);
        let unrelated = entry(4, 2, 5, 100);
        let mut descendant = entry(5, 2, 4, 100);
        left.supersession.push((root.identity, root.digest, 3));
        right.supersession.push((root.identity, root.digest, 3));
        descendant
            .supersession
            .push((left.identity, left.digest, 3));
        let entries = vec![root, left, right, unrelated, descendant];
        let (report, _) = run(2, entries.clone());
        assert_eq!(pairs(&report), vec![(1, 4, 2), (2, 4, 1), (3, 5, 1)]);
        assert_eq!(report.comparisons, 66);
        // A separate, unrelated one-entry group still builds one range leaf
        // because the global history has a correction. Its input visit and
        // that leaf add two comparisons without adding any duplicate pair.
        let mut extra = entries;
        extra.push(entry(6, 0, 6, 101));
        let (extra, _) = run(2, extra);
        assert_eq!(pairs(&extra), pairs(&report));
        assert_eq!(extra.comparisons, 68);
        assert_eq!(extra.live_entries, 6);
    }

    #[test]
    fn different_date_duplicates_replay_multi_parent_directed_reachability() {
        let first = entry(1, 0, 1, 90);
        let second = entry(2, 0, 2, 91);
        let mut left = entry(3, 1, 3, 100);
        let mut right = entry(4, 2, 4, 100);
        left.supersession = vec![(1, first.digest, 3), (2, second.digest, 3)];
        right.supersession = left.supersession.clone();
        let (siblings, _) = run(
            2,
            vec![first.clone(), second.clone(), left.clone(), right.clone()],
        );
        assert_eq!(pairs(&siblings), vec![(3, 4, 1)]);
        assert_eq!(siblings.comparisons, 42);
        right.supersession.push((left.identity, left.digest, 3));
        let (related, _) = run(2, vec![first, second, left, right]);
        assert!(related.findings.is_empty());
        assert_eq!(related.comparisons, 44);
    }

    #[test]
    fn different_date_duplicates_exclude_pending_and_reversed_entries_and_reject_changed_inputs() {
        let first = entry(1, 0, 1, 100);
        let mut pending = entry(2, 1, 2, 100);
        pending.class = 2;
        let original = entry(3, 1, 3, 100);
        let mut reversal = entry(4, 1, 4, 100);
        reversal.class = 4;
        reversal.leg_accounts = vec![(10, false), (20, true)];
        reversal
            .supersession
            .push((original.identity, original.digest, 1));
        let entries = vec![first, pending, original, reversal, entry(5, 3, 5, 100)];
        let (report, output) = run(3, entries.clone());
        assert_eq!(pairs(&report), vec![(1, 5, 3)]);
        assert_eq!(
            (
                report.population,
                report.live_entries,
                report.live_legs,
                report.comparisons
            ),
            (5, 2, 4, 16)
        );
        let request = Certificate {
            source: &[],
            registry_digest: [0; 32],
            output: &output,
            digest: [0; 32],
            parameters: VerifiedProcedureParameters::SameSameDifferent { window_days: 3 },
            version: 1,
            book: [1; 16],
            known_at: 100,
            effective_through: None,
        };
        assert_eq!(
            replay_certificate(&request, [1; 16], 100, entries.clone(), &registry())
                .unwrap()
                .0,
            report
        );
        let mut missing = entries.clone();
        missing.retain(|entry| entry.identity != 5);
        let mut changed = entries.clone();
        changed.last_mut().unwrap().effective = Some(4);
        for inputs in [missing, changed] {
            assert_eq!(
                replay_certificate(&request, [1; 16], 100, inputs, &registry())
                    .unwrap_err()
                    .predicate,
                "procedure_recomputation"
            );
        }
        let mut wrong_output = output.clone();
        *wrong_output.last_mut().unwrap() ^= 1;
        let wrong_request = Certificate {
            output: &wrong_output,
            ..request
        };
        assert_eq!(
            replay_certificate(&wrong_request, [1; 16], 100, entries, &registry())
                .unwrap_err()
                .predicate,
            "procedure_recomputation"
        );
    }

    #[test]
    fn different_date_duplicates_widen_civil_day_distance_before_subtraction() {
        let entries = vec![entry(1, i32::MIN, 1, 100), entry(2, i32::MAX, 2, 100)];
        assert_eq!(
            pairs(&run(u32::MAX, entries.clone()).0),
            vec![(1, 2, u32::MAX)]
        );
        assert!(run(u32::MAX - 1, entries).0.findings.is_empty());
    }

    fn encoded(output: &[u8]) -> Vec<u8> {
        let mut certificate = Writer::default();
        certificate
            .bytes(super::super::FORMAT)
            .bytes(&[])
            .bytes(&[])
            .fixed(&[0; 32])
            .u128(1)
            .fixed(&[0; 32])
            .bytes(output);
        let digest = framed_hash(super::super::DIGEST_DOMAIN, &certificate.buf);
        certificate.fixed(&digest);
        certificate.buf
    }

    #[test]
    fn different_date_duplicate_profile_refuses_new_versions_cutoffs_and_invalid_windows() {
        let entries = vec![entry(1, 0, 1, 100), entry(2, 1, 2, 100)];
        let (_, output) = run(30, entries.clone());
        let certificate = encoded(&output);
        assert_eq!(
            decode(&certificate).unwrap().parameters,
            VerifiedProcedureParameters::SameSameDifferent { window_days: 30 }
        );
        for (version, cutoff) in [(2, None), (1, Some(2))] {
            let (_, output) = recompute_version(
                [1; 16],
                100,
                version,
                cutoff,
                VerifiedProcedureParameters::SameSameDifferent { window_days: 30 },
                entries.clone(),
                &registry(),
            )
            .unwrap();
            assert_eq!(
                decode(&encoded(&output))
                    .err()
                    .expect("unsupported profile")
                    .predicate,
                "procedure_profile"
            );
        }
        // Preserve the ordinary output and its rehashed outer certificate;
        // replace only the exact i128 parameter field after its canonical name.
        let marker = b"window_days";
        let parameter_at = output
            .windows(marker.len())
            .position(|part| part == marker)
            .unwrap()
            + marker.len();
        for amount in [-1, i128::from(u32::MAX) + 1] {
            let mut invalid = output.clone();
            invalid[parameter_at..parameter_at + 16].copy_from_slice(&amount.to_le_bytes());
            assert_eq!(
                decode(&encoded(&invalid))
                    .err()
                    .expect("invalid window")
                    .predicate,
                "procedure_profile"
            );
        }
    }
}
