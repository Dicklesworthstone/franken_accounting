//! Replay document/effective period cutoffs from authenticated date facts.
//!
//! The portable profile deliberately requires declared calendar coverage. A
//! native book can generate an absent fiscal year from its calendar, but that
//! generator is not part of this native report bundle's authenticated closure.

use super::{
    Entry, MAX_FINDINGS, ReportError, VerifiedProcedureFinding, VerifiedProcedureStatistic, failed,
};

pub(super) fn replay(live: &[&Entry]) -> Result<Vec<VerifiedProcedureFinding>, ReportError> {
    let mut findings = Vec::new();
    let mut population = 0u64;
    for entry in live {
        let period = entry.period.as_ref().ok_or_else(|| {
            failed(
                "procedure_period",
                "a live posting has no authenticated period",
            )
        })?;
        let Some(document) = &period.document else {
            continue;
        };
        population += 1;
        let document_period = document.code.as_ref().ok_or_else(|| {
            failed(
                "procedure_period_closure",
                "a live posting's document date has no authenticated normal period at the certificate's known-at; declare its fiscal year and create a fresh certificate, or replay the original certificate in its book",
            )
        })?;
        if document_period == &period.code {
            continue;
        }
        if findings.len() >= MAX_FINDINGS {
            return Err(failed(
                "bounded_input",
                "cutoff findings exceed the certificate bound",
            ));
        }
        // The difference of two signed i32 days fits exactly in u32. Widen
        // before subtraction so either direction crosses zero safely.
        let days =
            u32::try_from((i64::from(document.date) - i64::from(period.effective)).unsigned_abs())
                .map_err(|_| {
                    failed("procedure_arithmetic", "document-date distance exceeds u32")
                })?;
        findings.push(VerifiedProcedureFinding {
            entry: Some(entry.identity),
            severity: 2,
            statistic: VerifiedProcedureStatistic::DaysBetweenPeriods {
                effective_period: period.code.clone(),
                document_period: document_period.clone(),
                days,
            },
            population: 0,
            narrative: format!(
                "document dated in period {document_period}, effective in period {}, {days} day(s) apart",
                period.code
            ),
        });
    }
    for finding in &mut findings {
        finding.population = population;
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blake3::hash_parts;
    use crate::report::procedure::{
        Certificate, DocumentPeriod, EntryPeriod, Registry, VerifiedProcedureParameters,
        recompute_version,
    };
    use std::collections::BTreeMap;

    const BOOK: [u8; 16] = [37; 16];
    const PROFILE: VerifiedProcedureParameters = VerifiedProcedureParameters::PeriodBoundary;

    fn registry() -> Registry {
        Registry {
            unit_scales: BTreeMap::from([(1, 2)]),
            unit_currencies: BTreeMap::from([(1, 840)]),
            account_types: BTreeMap::new(),
            leg_parties: BTreeMap::new(),
            trace: None,
            open_items: None,
            policy_oid: [7; 32],
        }
    }

    fn posting(identity: u128, effective: i32, document: Option<(i32, Option<&str>)>) -> Entry {
        Entry {
            identity,
            digest: hash_parts(b"cutoff-test", &[&identity.to_le_bytes()]),
            recorded_at: identity as u64,
            effective: Some(effective),
            class: 1,
            legs: vec![(1, 100), (1, 100)],
            leg_accounts: vec![(1, true), (2, false)],
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: Some(EntryPeriod {
                code: "current".into(),
                effective,
                end: 31,
                document: document.map(|(date, code)| DocumentPeriod {
                    date,
                    code: code.map(str::to_owned),
                }),
            }),
            transition: None,
        }
    }

    fn population() -> Vec<Entry> {
        vec![
            posting(1, 0, Some((-1, Some("prior")))),
            posting(2, 3, Some((0, Some("current")))),
            posting(3, 5, None),
            posting(4, 7, Some((31, Some("next")))),
        ]
    }

    #[test]
    fn cutoff_counts_only_dated_live_postings_but_charges_every_live_entry() {
        let (report, output) =
            recompute_version(BOOK, 10, 1, None, PROFILE, population(), &registry()).unwrap();
        assert_eq!(report.procedure, "cutoff.period_boundary");
        assert_eq!(report.population, 4);
        assert_eq!(
            (report.live_entries, report.live_legs, report.comparisons),
            (4, 0, 0)
        );
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].entry, Some(4));
        assert_eq!(report.findings[0].statistic.value(), 24);
        assert_eq!(report.findings[1].entry, Some(1));
        assert_eq!(report.findings[1].statistic.value(), 1);
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.population == 3 && f.severity == 2)
        );
        assert_eq!(
            report.findings[0].narrative,
            "document dated in period next, effective in period current, 24 day(s) apart"
        );
        let mut unordered = population();
        unordered.reverse();
        assert_eq!(
            recompute_version(BOOK, 10, 1, None, PROFILE, unordered, &registry())
                .unwrap()
                .1,
            output
        );
    }

    #[test]
    fn cutoff_reversal_parity_selects_the_document_population_before_requiring_coverage() {
        let original = posting(100, 5, Some((-1, None)));
        let mut entries = vec![original];
        for length in 0..6 {
            let result =
                recompute_version(BOOK, 110, 1, None, PROFILE, entries.clone(), &registry());
            if length % 2 == 0 {
                assert_eq!(result.unwrap_err().predicate, "procedure_period_closure");
            } else {
                let report = result.unwrap().0;
                assert_eq!(report.live_entries, 0);
                assert!(report.findings.is_empty());
            }
            let previous = entries.last().unwrap();
            let mut reversal = posting(101 + length, 5, Some((-1, None)));
            reversal.class = 4;
            reversal
                .supersession
                .push((previous.identity, previous.digest, 1));
            entries.push(reversal);
        }
    }

    #[test]
    fn cutoff_distance_widens_before_subtraction_and_supports_either_direction() {
        for (effective, document) in [(i32::MIN, i32::MAX), (i32::MAX, i32::MIN)] {
            let entry = posting(1, effective, Some((document, Some("other"))));
            let report = replay(&[&entry]).unwrap();
            assert_eq!(report[0].statistic.value(), i128::from(u32::MAX));
            assert_eq!(report[0].population, 1);
        }
        let same_day_special = posting(2, 30, Some((30, Some("adjustment"))));
        let report = replay(&[&same_day_special]).unwrap();
        assert_eq!(report[0].statistic.value(), 0);
    }

    #[test]
    fn cutoff_replay_rejects_changed_dates_periods_population_work_and_omitted_findings() {
        let (_, output) =
            recompute_version(BOOK, 10, 1, None, PROFILE, population(), &registry()).unwrap();
        let request = Certificate {
            source: &[],
            registry_digest: [0; 32],
            output: &output,
            digest: [0; 32],
            parameters: PROFILE,
            version: 1,
            book: BOOK,
            known_at: 10,
            effective_through: None,
        };
        for what in [
            "document date",
            "effective date",
            "document period",
            "effective period",
            "population",
            "work",
            "omitted finding",
        ] {
            let mut entries = population();
            match what {
                "document date" => {
                    entries[0]
                        .period
                        .as_mut()
                        .unwrap()
                        .document
                        .as_mut()
                        .unwrap()
                        .date -= 1
                }
                "effective date" => entries[0].period.as_mut().unwrap().effective += 1,
                "document period" => {
                    entries[0]
                        .period
                        .as_mut()
                        .unwrap()
                        .document
                        .as_mut()
                        .unwrap()
                        .code = Some("forged".into())
                }
                "effective period" => entries[0].period.as_mut().unwrap().code = "forged".into(),
                "population" => entries[1].period.as_mut().unwrap().document = None,
                "work" => entries[2].class = 2,
                "omitted finding" => entries[0].period.as_mut().unwrap().document = None,
                _ => unreachable!(),
            }
            assert_eq!(
                crate::report::procedure::replay(&request, BOOK, 10, entries, &registry())
                    .unwrap_err()
                    .predicate,
                "procedure_recomputation",
                "{what}"
            );
        }
        let mut forged_output = output.clone();
        *forged_output.last_mut().unwrap() ^= 1;
        let forged = Certificate {
            output: &forged_output,
            ..request
        };
        assert_eq!(
            crate::report::procedure::replay(&forged, BOOK, 10, population(), &registry())
                .unwrap_err()
                .predicate,
            "procedure_recomputation"
        );
    }
}
