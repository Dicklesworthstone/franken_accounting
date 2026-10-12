//! Cutoff (plan §11.7): entries whose document date resolves to a different
//! period than their effective date — candidates for the cutoff assertion on
//! either side of a boundary.

use fa_journal::genesis::BookContext;

use crate::jet::{finding, procedure_boilerplate};
use crate::{Cite, Finding, LanternError, Params, Procedure, Severity, Snapshot, Statistic, Work};

/// `cutoff.period_boundary`.
pub struct PeriodBoundary {
    params: Params,
}
procedure_boilerplate!(PeriodBoundary, "cutoff.period_boundary");

impl Procedure for PeriodBoundary {
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
        let mut hits = Vec::new();
        for e in snapshot.entries.iter().filter(|e| e.posts()) {
            work.entry();
            let Some(document_date) = e.entry.proposal.document_date else {
                continue;
            };
            population += 1;
            let document_period = snapshot.period_code_of(book, document_date)?;
            if document_period != e.period {
                let days = (document_date.0 - e.entry.proposal.effective_date.0).unsigned_abs();
                hits.push((e.vid, e.period.clone(), document_period, days));
            }
        }
        Ok(hits
            .into_iter()
            .map(|(vid, effective_period, document_period, days)| {
                let mut cites = vec![Cite::Entry(vid), Cite::Period(effective_period.clone())];
                // The document's period is cited only when the calendar has
                // generated it; otherwise it is named in the narrative only.
                if snapshot.periods.contains_key(&document_period) {
                    cites.push(Cite::Period(document_period.clone()));
                }
                finding(
                    Self::ID,
                    Severity::Medium,
                    Statistic::count("days_between_dates", u64::from(days), population),
                    cites,
                    format!(
                        "document dated in period {document_period}, effective in period {effective_period}, {days} day(s) apart"
                    ),
                )
            })
            .collect())
    }
}
