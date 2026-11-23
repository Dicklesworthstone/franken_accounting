//! Replay document/effective period cutoffs from authenticated date facts.
//!
//! The portable profile deliberately requires declared calendar coverage. A
//! native book can generate an absent fiscal year from its calendar, but that
//! generator is not part of this native report bundle's authenticated closure.

use super::{
    Entry, MAX_FINDINGS, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureStatistic, failed,
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

/// Registered v2 candidate screen: the lookahead begins at the document
/// period's exclusive end, independently of the document's age. This proves
/// the screen's observations, not that no prior accrual exists.
pub(super) fn unrecorded_liabilities(
    live: &[&Entry],
    window_days: u32,
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64), ReportError> {
    if window_days == 0 {
        return Err(failed(
            "procedure_profile",
            "unrecorded-liability window_days must be positive",
        ));
    }
    let mut findings = Vec::new();
    let mut legs = 0u64;
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
        if document.date >= period.effective {
            continue;
        }
        let (Some(document_period), Some(end)) = (&document.code, document.end) else {
            return Err(failed(
                "procedure_period_closure",
                "a live posting's prior document date has no authenticated period and exclusive end at the certificate's known-at; declare its fiscal year and create a fresh certificate, or replay the original certificate in its book",
            ));
        };
        if document_period == &period.code {
            continue;
        }
        let lag_days = i64::from(period.effective) - i64::from(end) + 1;
        if lag_days <= 0 || lag_days > i64::from(window_days) {
            continue;
        }
        if entry.legs.len() != entry.leg_accounts.len() {
            return Err(failed(
                "procedure_accounts",
                "original leg account inventory is incomplete",
            ));
        }
        let mut largest: Option<(u128, u32, i128)> = None;
        for (&(unit, amount), &(account, _)) in entry.legs.iter().zip(&entry.leg_accounts) {
            legs += 1;
            let kind = registry.account_types.get(&account).ok_or_else(|| {
                failed(
                    "procedure_accounts",
                    "posting account has no authenticated type",
                )
            })?;
            // Registered tags: Liability = 2, Expense = 5. Native v2 compares
            // raw mantissas across units and preserves the first leg on ties.
            if matches!(kind, 2 | 5) {
                let magnitude = amount.checked_abs().ok_or_else(|| {
                    failed(
                        "procedure_arithmetic",
                        "leg magnitude exceeds positive i128",
                    )
                })?;
                if largest.is_none_or(|(_, _, prior)| magnitude > prior) {
                    largest = Some((account, unit, magnitude));
                }
            }
        }
        let Some((account, unit, amount)) = largest else {
            continue;
        };
        let scale = *registry.unit_scales.get(&unit).ok_or_else(|| {
            failed(
                "procedure_units",
                "selected obligation leg uses an unregistered unit",
            )
        })?;
        if findings.len() >= MAX_FINDINGS {
            return Err(failed(
                "bounded_input",
                "unrecorded-liability findings exceed the certificate bound",
            ));
        }
        findings.push(VerifiedProcedureFinding {
            entry: Some(entry.identity),
            severity: 3,
            statistic: VerifiedProcedureStatistic::UnrecordedLiabilityAmount {
                account,
                unit,
                effective_period: period.code.clone(),
                document_period: document_period.clone(),
                amount,
                scale,
            },
            population: live.len() as u64,
            narrative: format!(
                "obligation dated in prior period {document_period} recorded in subsequent period {} ({lag_days} day(s) after prior period end, amount {amount})",
                period.code
            ),
        });
    }
    Ok((findings, legs))
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
            account_codes: BTreeMap::new(),
            account_roles: BTreeMap::new(),
            leg_parties: BTreeMap::new(),
            entry_facts: BTreeMap::new(),
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
                    end: code.map(|code| if code == "prior" { 0 } else { 31 }),
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

    fn obligation_registry() -> Registry {
        let mut value = registry();
        value.unit_scales.insert(2, 0);
        value.account_types = BTreeMap::from([(1, 5), (2, 1), (3, 2), (4, 3)]);
        value
    }

    #[test]
    fn unrecorded_v2_looks_after_period_end_not_document_age_and_meters_eligible_legs() {
        let mut cash_only = posting(16, 1, Some((-1, Some("prior"))));
        cash_only.leg_accounts = vec![(2, true), (4, false)];
        let entries = vec![
            posting(10, 0, Some((-30, Some("prior")))),
            posting(11, 1, Some((-1, Some("prior")))),
            posting(12, 2, Some((-1, Some("prior")))),
            posting(13, 5, Some((1, Some("current")))),
            posting(14, 5, Some((6, None))),
            posting(15, 5, None),
            cash_only,
        ];
        let profile = VerifiedProcedureParameters::UnrecordedLiabilities { window_days: 2 };
        let (report, output) = recompute_version(
            BOOK,
            20,
            2,
            None,
            profile,
            entries.clone(),
            &obligation_registry(),
        )
        .unwrap();
        assert_eq!(report.findings.len(), 2);
        assert_eq!(
            (
                report.population,
                report.live_entries,
                report.live_legs,
                report.comparisons
            ),
            (7, 7, 6, 0)
        );
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.population == 7 && finding.severity == 3)
        );
        assert_eq!(report.findings[0].entry, Some(10));
        assert_eq!(
            report.findings[0].narrative,
            "obligation dated in prior period prior recorded in subsequent period current (1 day(s) after prior period end, amount 100)"
        );
        assert_eq!(report.findings[1].entry, Some(11));
        assert!(report.findings[1].narrative.contains("2 day(s)"));
        let mut reordered = entries;
        reordered.reverse();
        assert_eq!(
            recompute_version(
                BOOK,
                20,
                2,
                None,
                profile,
                reordered,
                &obligation_registry()
            )
            .unwrap()
            .1,
            output
        );
    }

    #[test]
    fn unrecorded_v2_preserves_raw_unit_magnitude_and_original_leg_ties() {
        let mut entry = posting(1, 0, Some((-30, Some("prior"))));
        entry.legs = vec![(2, 100), (1, 100), (2, 100), (1, 100)];
        entry.leg_accounts = vec![(3, true), (1, true), (2, false), (4, false)];
        let (report, legs) = unrecorded_liabilities(&[&entry], 1, &obligation_registry()).unwrap();
        assert_eq!(legs, 4);
        assert_eq!(
            report[0].statistic,
            VerifiedProcedureStatistic::UnrecordedLiabilityAmount {
                account: 3,
                unit: 2,
                effective_period: "current".into(),
                document_period: "prior".into(),
                amount: 100,
                scale: 0,
            }
        );
        entry.legs[1].1 = i128::MAX;
        entry.legs[3].1 = i128::MAX;
        let (report, _) = unrecorded_liabilities(&[&entry], 1, &obligation_registry()).unwrap();
        assert_eq!(
            report[0].statistic,
            VerifiedProcedureStatistic::UnrecordedLiabilityAmount {
                account: 1,
                unit: 1,
                effective_period: "current".into(),
                document_period: "prior".into(),
                amount: i128::MAX,
                scale: 2,
            }
        );
    }

    #[test]
    fn unrecorded_v2_supports_full_day_windows_and_refuses_missing_semantic_inputs() {
        let mut entry = posting(1, i32::MAX - 1, Some((i32::MIN, Some("prior"))));
        entry
            .period
            .as_mut()
            .unwrap()
            .document
            .as_mut()
            .unwrap()
            .end = Some(i32::MIN + 1);
        let (findings, _) =
            unrecorded_liabilities(&[&entry], u32::MAX, &obligation_registry()).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].narrative.contains("4294967294 day(s)"));
        assert!(
            unrecorded_liabilities(&[&entry], u32::MAX - 2, &obligation_registry())
                .unwrap()
                .0
                .is_empty()
        );
        assert_eq!(
            unrecorded_liabilities(&[&entry], 0, &obligation_registry())
                .unwrap_err()
                .predicate,
            "procedure_profile"
        );
        for missing in [
            "document code",
            "document end",
            "account type",
            "unit scale",
            "leg account",
        ] {
            let mut input = posting(1, 0, Some((-1, Some("prior"))));
            let mut registry = obligation_registry();
            let predicate = match missing {
                "document code" => {
                    input
                        .period
                        .as_mut()
                        .unwrap()
                        .document
                        .as_mut()
                        .unwrap()
                        .code = None;
                    "procedure_period_closure"
                }
                "document end" => {
                    input
                        .period
                        .as_mut()
                        .unwrap()
                        .document
                        .as_mut()
                        .unwrap()
                        .end = None;
                    "procedure_period_closure"
                }
                "account type" => {
                    registry.account_types.remove(&1);
                    "procedure_accounts"
                }
                "unit scale" => {
                    registry.unit_scales.remove(&1);
                    "procedure_units"
                }
                "leg account" => {
                    input.leg_accounts.pop();
                    "procedure_accounts"
                }
                _ => unreachable!(),
            };
            assert_eq!(
                unrecorded_liabilities(&[&input], 1, &registry)
                    .unwrap_err()
                    .predicate,
                predicate,
                "{missing}"
            );
        }
    }

    #[test]
    fn unrecorded_v2_filters_reversal_parity_before_counting_obligations() {
        let mut entries = vec![posting(100, 0, Some((-30, Some("prior"))))];
        let profile = VerifiedProcedureParameters::UnrecordedLiabilities { window_days: 1 };
        for length in 0..6 {
            let (report, _) = recompute_version(
                BOOK,
                110,
                2,
                None,
                profile,
                entries.clone(),
                &obligation_registry(),
            )
            .unwrap();
            assert_eq!(report.live_entries, u64::from(length % 2 == 0));
            assert_eq!(report.findings.len(), usize::from(length % 2 == 0));
            assert_eq!(report.live_legs, 2 * u64::from(length % 2 == 0));
            let previous = entries.last().unwrap();
            let mut reversal = posting(101 + length, 0, Some((-30, Some("prior"))));
            reversal.class = 4;
            reversal
                .supersession
                .push((previous.identity, previous.digest, 1));
            entries.push(reversal);
        }
    }

    #[test]
    fn unrecorded_v2_rejects_changed_amount_account_scale_boundary_population_and_work() {
        let entries = vec![
            posting(1, 1, Some((-30, Some("prior")))),
            posting(2, 1, None),
        ];
        let profile = VerifiedProcedureParameters::UnrecordedLiabilities { window_days: 2 };
        let (_, output) = recompute_version(
            BOOK,
            10,
            2,
            None,
            profile,
            entries.clone(),
            &obligation_registry(),
        )
        .unwrap();
        let request = Certificate {
            source: &[],
            registry_digest: [0; 32],
            output: &output,
            digest: [0; 32],
            parameters: profile,
            version: 2,
            book: BOOK,
            known_at: 10,
            effective_through: None,
        };
        for mutation in [
            "amount",
            "account",
            "scale",
            "account type",
            "period end",
            "document period",
            "population",
            "work",
        ] {
            let mut changed = entries.clone();
            let mut registry = obligation_registry();
            match mutation {
                "amount" => changed[0].legs[0].1 += 1,
                "account" => changed[0].leg_accounts[0].0 = 3,
                "scale" => {
                    registry.unit_scales.insert(1, 3);
                }
                "account type" => {
                    registry.account_types.insert(1, 1);
                }
                "period end" => {
                    changed[0]
                        .period
                        .as_mut()
                        .unwrap()
                        .document
                        .as_mut()
                        .unwrap()
                        .end = Some(1)
                }
                "document period" => {
                    changed[0]
                        .period
                        .as_mut()
                        .unwrap()
                        .document
                        .as_mut()
                        .unwrap()
                        .code = Some("forged".into())
                }
                "population" => changed[1].class = 2,
                "work" => {
                    changed[0].legs.push((1, 1));
                    changed[0].leg_accounts.push((2, true));
                }
                _ => unreachable!(),
            }
            assert_eq!(
                crate::report::procedure::replay(&request, BOOK, 10, changed, &registry)
                    .unwrap_err()
                    .predicate,
                "procedure_recomputation",
                "{mutation}"
            );
        }
    }

    #[test]
    fn unrecorded_decoder_requires_extended_v2_and_positive_bounded_window() {
        use crate::codec::Writer;
        use crate::report::procedure::{
            DIGEST_DOMAIN, EXTENDED_FORMAT, FORMAT, OUTPUT_FORMAT, decode, framed_hash,
        };
        let frame = |extended: bool, version: u16, window: i128, through: Option<i32>| {
            let mut output = Writer::default();
            output
                .bytes(OUTPUT_FORMAT)
                .bytes(b"completeness.unrecorded_liabilities")
                .u16(version)
                .u8(0)
                .bytes(b"FA-EVID-L44")
                .fixed(&BOOK)
                .u64(1)
                .u8(u8::from(through.is_some()));
            if let Some(day) = through {
                output.i32(day);
            }
            output.count(1).bytes(b"window_days").i128(window).count(0);
            let mut certificate = Writer::default();
            certificate
                .bytes(if extended { EXTENDED_FORMAT } else { FORMAT })
                .bytes(&[])
                .bytes(&[]);
            if extended {
                certificate.count(6);
                for _ in 0..6 {
                    certificate.bytes(&[]);
                }
            }
            certificate
                .fixed(&[0; 32])
                .u128(1)
                .fixed(&[0; 32])
                .bytes(&output.buf);
            let digest = framed_hash(DIGEST_DOMAIN, &certificate.buf);
            certificate.fixed(&digest);
            certificate.buf
        };
        for window in [1, 45, i128::from(u32::MAX)] {
            let bytes = frame(true, 2, window, None);
            assert_eq!(
                decode(&bytes).unwrap().parameters,
                VerifiedProcedureParameters::UnrecordedLiabilities {
                    window_days: window as u32
                }
            );
        }
        for (extended, version, window, through) in [
            (false, 2, 45, None),
            (true, 1, 45, None),
            (true, 3, 45, None),
            (true, 2, 0, None),
            (true, 2, -1, None),
            (true, 2, i128::from(u32::MAX) + 1, None),
            (true, 2, 45, Some(0)),
        ] {
            assert!(decode(&frame(extended, version, window, through)).is_err());
        }
    }
}
