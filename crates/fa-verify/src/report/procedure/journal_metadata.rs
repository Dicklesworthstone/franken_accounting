//! Calendar observations reconstructed from authenticated journal metadata.
//!
//! Weekend screening needs civil dates only: an undeclared document year is
//! not missing evidence for its weekday. No clock, local timezone, mutable
//! period state, encrypted description, or producer finding supplies a date.

use super::{
    Entry, MAX_FINDINGS, ReportError, VerifiedProcedureFinding, VerifiedProcedureStatistic, failed,
};

pub(super) fn weekend(live: &[&Entry]) -> Result<Vec<VerifiedProcedureFinding>, ReportError> {
    let population = u64::try_from(live.len())
        .map_err(|_| failed("bounded_input", "weekend population exceeds u64"))?;
    let mut findings = Vec::new();
    for entry in live {
        let effective = entry.effective.ok_or_else(|| {
            failed(
                "procedure_dates",
                "a live posting has no authenticated effective date",
            )
        })?;
        let period = entry.period.as_ref().ok_or_else(|| {
            failed(
                "procedure_dates",
                "a live posting has no authenticated date metadata",
            )
        })?;
        if effective != period.effective {
            return Err(failed(
                "procedure_dates",
                "effective date and original date metadata disagree",
            ));
        }
        let day = period
            .document
            .as_ref()
            .map_or(effective, |document| document.date);
        // Day zero is Thursday, 1970-01-01. Widen before offsetting so the
        // complete signed civil-day range, including pre-epoch days, is exact.
        let iso = u8::try_from((i64::from(day) + 3).rem_euclid(7) + 1)
            .map_err(|_| failed("procedure_dates", "ISO weekday is outside u8"))?;
        if iso < 6 {
            continue;
        }
        if findings.len() >= MAX_FINDINGS {
            return Err(failed(
                "bounded_input",
                "weekend findings exceed the certificate bound",
            ));
        }
        findings.push(VerifiedProcedureFinding {
            entry: Some(entry.identity),
            severity: 1,
            statistic: VerifiedProcedureStatistic::IsoWeekday { iso },
            population,
            narrative: format!("dated on ISO weekday {iso} (6 = Saturday, 7 = Sunday)"),
        });
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::procedure::{DocumentPeriod, EntryPeriod};

    fn posting(id: u128, day: i32, document: Option<i32>) -> Entry {
        Entry {
            identity: id,
            digest: [id as u8; 32],
            recorded_at: id as u64,
            effective: Some(day),
            class: 1,
            legs: vec![(1, 100), (1, 100)],
            leg_accounts: vec![(10, true), (20, false)],
            supersession: Vec::new(),
            settlements: Vec::new(),
            period: Some(EntryPeriod {
                code: "period".into(),
                effective: day,
                end: day.saturating_add(1),
                document: document.map(|date| DocumentPeriod {
                    date,
                    code: None,
                    end: None,
                }),
            }),
            transition: None,
        }
    }

    fn observed(entries: &[Entry]) -> Vec<(u128, u8)> {
        weekend(&entries.iter().collect::<Vec<_>>())
            .unwrap()
            .iter()
            .map(|finding| {
                let VerifiedProcedureStatistic::IsoWeekday { iso } = finding.statistic else {
                    panic!("wrong weekend statistic");
                };
                assert_eq!(finding.severity, 1);
                assert_eq!(finding.population, entries.len() as u64);
                assert_eq!(finding.statistic.name(), "iso_weekday");
                assert_eq!(finding.statistic.scale(), 0);
                (finding.entry.unwrap(), iso)
            })
            .collect()
    }

    #[test]
    fn weekend_uses_document_date_before_effective_date_without_document_calendar_coverage() {
        let entries = [
            posting(1, 0, None),    // Thursday.
            posting(2, 2, None),    // Saturday.
            posting(3, 3, None),    // Sunday.
            posting(4, 4, None),    // Monday.
            posting(5, 2, Some(4)), // A Monday document overrides Saturday.
            posting(6, 4, Some(3)), // A Sunday document overrides Monday.
        ];
        assert_eq!(observed(&entries), vec![(2, 6), (3, 7), (6, 7)]);
    }

    #[test]
    fn weekend_preserves_pre_epoch_dates_and_the_entire_signed_day_domain() {
        let entries = [
            posting(1, -5, None), // Saturday, 1969-12-27.
            posting(2, -4, None), // Sunday, 1969-12-28.
            posting(3, -3, None), // Monday, 1969-12-29.
            posting(4, i32::MIN, None),
            posting(5, i32::MIN + 4, None),
            posting(6, i32::MAX - 6, None),
            posting(7, i32::MAX, None),
        ];
        assert_eq!(observed(&entries), vec![(1, 6), (2, 7), (5, 6), (6, 6)]);
    }

    #[test]
    fn weekend_refuses_missing_or_conflicting_authenticated_dates() {
        let original = posting(1, 2, None);
        let mut missing_effective = original.clone();
        missing_effective.effective = None;
        let mut missing_metadata = original.clone();
        missing_metadata.period = None;
        let mut conflict = original;
        conflict.period.as_mut().unwrap().effective = 3;
        for entry in [missing_effective, missing_metadata, conflict] {
            assert_eq!(weekend(&[&entry]).unwrap_err().predicate, "procedure_dates");
        }
        assert!(weekend(&[]).unwrap().is_empty());
    }
}
