//! Optional equity evidence for the actual current-period effect of a posted
//! prior-period adjustment. The mandatory original-report statement questions
//! remain unchanged. These supplemental comparisons make no issuance claim.

use super::*;
use crate::{EquityRollForwardDiffRequest, EquityRollForwardRequest};

/// The caller's explicit equity question. Dates and recorded frontiers are
/// derived from the named actual posting period and the case's atomic Post.
/// Empty owner-account role lists are explicit choices, never inferred roles.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseEquityComparisonSelection {
    pub period: String,
    pub label: String,
    pub units: Vec<u32>,
    pub issuance_accounts: Vec<VId>,
    pub distribution_accounts: Vec<VId>,
}

/// A retained comparison and the separately selected complete question it must
/// answer. Reading an expectation back from the delivered certificate does not
/// supply an independently selected reporting policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseEquityDisclosureComparison {
    pub certificate: [u8; 32],
    pub expected: EquityRollForwardDiffRequest,
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Read one supplemental equity bridge under current Read authority, using
    /// the same selected question and math as its separately certified form.
    pub async fn case_equity_diff(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        ordinal: u32,
        selection: &CaseEquityComparisonSelection,
    ) -> Outcome<(EquityRollForwardDiffRequest, crate::EquityRollForwardDiff)> {
        let request = match self
            .case_equity_diff_request(cx, principal, capability, ordinal, selection)
            .await?
        {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let before = match self.equity_roll_forward(cx, principal, capability, &request.before)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let after_request = EquityRollForwardRequest {
            known_at: Some(request.after),
            ..request.before.clone()
        };
        let after = match self.equity_roll_forward(cx, principal, capability, &after_request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(crate::EquityRollForwardDiff::between(before, after).map(|report| (request, report)))
    }

    /// Select a complete equity bridge immediately before and at the case's
    /// atomic Post. Only an actual PPA posting period is admissible; its full
    /// monetary unit population must be included. The owner's issuance and
    /// distribution classifications stay explicit in the returned request.
    pub async fn case_equity_diff_request(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        ordinal: u32,
        selection: &CaseEquityComparisonSelection,
    ) -> Outcome<EquityRollForwardDiffRequest> {
        use fa_journal::case::comparison_refused;

        let selected = self.query(cx, |db, book| {
            let authority = match fa_journal::policy::admit_reads(db, book, principal, capability)? {
                Ok(authority) => authority,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) = authority.whole_book(db.frontier().map_err(KernelError::from)?) {
                return Ok(Err(refusal));
            }
            if selection.units.is_empty()
                || selection.units.len() > crate::equity_certificate::MAX_SCOPE
                || selection.issuance_accounts.len() > crate::equity_certificate::MAX_SCOPE
                || selection.distribution_accounts.len() > crate::equity_certificate::MAX_SCOPE
                || selection.label.trim().is_empty()
                || selection.label.len() > 256
                || selection.period.is_empty()
                || selection.period.len() > 128
            {
                return Ok(Err(comparison_refused("invalid or excessive explicit equity scope")));
            }
            let Some(view) = fa_journal::read_case(db, book, ordinal)? else {
                return Ok(Err(comparison_refused(format!(
                    "this book has no restatement case {ordinal}",
                ))));
            };
            if view.body.kind != CaseKind::PriorPeriodAdjustment {
                return Ok(Err(comparison_refused(
                    "supplemental equity disclosure compares only an actual prior-period-adjustment Post",
                )));
            }
            let Some(post) = view.transitions.iter().find(|record| record.to == CaseState::Posted) else {
                return Ok(Err(comparison_refused(
                    "an equity disclosure comparison requires the case's committed Post",
                )));
            };
            let at = post.recorded_at;
            let before = CommitSeq(at.0.checked_sub(1).ok_or_else(|| {
                KernelError::Corrupt("case Post has no preceding frontier".into())
            })?);
            Ok(Ok((view, before, at)))
        })?;
        let (view, before, after) = match selected {
            Ok(selected) => selected,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = self
            .prepare_report_history(cx, principal, capability, Some(before))
            .await?
        {
            return Ok(Err(refusal));
        }
        let request = self.query(cx, |db, book| {
            let authority = match fa_journal::policy::admit_reads(db, book, principal, capability)? {
                Ok(authority) => authority,
                Err(refusal) => return Ok(Err(refusal)),
            };
            for at in [before, after] {
                if let Err(refusal) = authority.whole_book(at) {
                    return Ok(Err(refusal));
                }
            }
            let periods = db
                .vertices_at(before)
                .map_err(KernelError::from)?
                .into_iter()
                .filter(|row| row.labels.contains(&fa_model::symbols::label::PERIOD))
                .map(|row| fa_journal::rows::PeriodRow::decode(&row))
                .collect::<Result<Vec<_>, _>>()?;
            let required = adjustment_posting_period_units(db, book, &view, &periods, after)?;
            let Some(required_units) = required.get(&selection.period) else {
                return Ok(Err(comparison_refused(format!(
                    "period `{}` is not an actual posting period of prior-period adjustment case {ordinal}",
                    selection.period,
                ))));
            };
            let period = periods
                .iter()
                .find(|period| period.code == selection.period && period.calendar_id == book.calendar.id)
                .ok_or_else(|| KernelError::Corrupt("case posting period vanished".into()))?;
            let through = fa_time::DateDay(period.end.0.checked_sub(1).ok_or_else(|| {
                KernelError::Corrupt("case posting period end underflow".into())
            })?);
            let request = EquityRollForwardRequest {
                units: selection.units.clone(),
                label: selection.label.clone(),
                effective_from: period.start,
                effective_through: through,
                known_at: Some(before),
                issuance_accounts: selection.issuance_accounts.clone(),
                distribution_accounts: selection.distribution_accounts.clone(),
            };
            let request = match crate::equity_certificate::normalize(&request, before) {
                Ok(request) => request,
                Err(refusal) => return Ok(Err(comparison_refused(refusal.message))),
            };
            if !required_units.iter().all(|unit| request.units.contains(unit)) {
                return Ok(Err(comparison_refused(
                    "the equity question omits a monetary unit of this period's posted prior-period adjustment",
                )));
            }
            if request.units.iter().any(|unit| book.units.get(fa_money::UnitId(*unit)).is_none()) {
                return Ok(Err(comparison_refused("an explicit equity unit is not registered")));
            }
            Ok(Ok(EquityRollForwardDiffRequest { before: request, after }))
        })?;
        let request = match request {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // Validate explicit roles against the real historical chart before a
        // caller certifies anything. The native report checks them again.
        if let Err(refusal) =
            self.equity_source_request(cx, principal, capability, &request.before)?
        {
            return Ok(Err(comparison_refused(refusal.message)));
        }
        Ok(Ok(request))
    }

    pub(super) async fn validate_case_equity_disclosures(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_policy::Capability,
        ordinal: u32,
        post: fa_journal::DisclosurePost,
        comparisons: &[CaseEquityDisclosureComparison],
    ) -> Outcome<Vec<fa_journal::ValidatedDisclosureComparison>> {
        use fa_journal::case::comparison_refused;

        let principal = capability.holder();
        let mut periods = BTreeSet::new();
        let mut validated = Vec::with_capacity(comparisons.len());
        for comparison in comparisons {
            let expected = &comparison.expected;
            if let Err(refusal) = expected.canonical_bytes() {
                return Ok(Err(comparison_refused(refusal.message)));
            }
            if expected.after != post.recorded_at
                || expected.before.known_at.and_then(|at| at.0.checked_add(1))
                    != Some(post.recorded_at.0)
            {
                return Ok(Err(comparison_refused(
                    "supplemental equity compares immediately before and at this case's atomic Post, never an issued frontier or a later HEAD",
                )));
            }
            // The expectation is independent of the delivered artifact. Find
            // its exact period first; the request builder then checks actual
            // membership, complete PPA units and the explicit owner roles.
            let period = self.query(cx, |db, book| {
                let before = expected.before.known_at.ok_or_else(|| {
                    KernelError::Corrupt("validated equity request lost its before frontier".into())
                })?;
                let authority =
                    match fa_journal::policy::admit_reads(db, book, principal, capability)? {
                        Ok(authority) => authority,
                        Err(refusal) => return Ok(Err(refusal)),
                    };
                if let Err(refusal) = authority.whole_book(before) {
                    return Ok(Err(refusal));
                }
                let rows = db.vertices_at(before).map_err(KernelError::from)?;
                let definitions = rows
                    .iter()
                    .filter(|row| row.labels.contains(&fa_model::symbols::label::PERIOD))
                    .map(fa_journal::rows::PeriodRow::decode)
                    .collect::<Result<Vec<_>, _>>()?;
                let view = fa_journal::read_case(db, book, ordinal)?
                    .ok_or_else(|| KernelError::Corrupt("validated case vanished".into()))?;
                let posting = adjustment_posting_period_units(
                    db,
                    book,
                    &view,
                    &definitions,
                    post.recorded_at,
                )?;
                let mut matches = Vec::new();
                for period in definitions {
                    if period.calendar_id == book.calendar.id
                        && posting.contains_key(&period.code)
                        && period.start == expected.before.effective_from
                        && period.end.0.checked_sub(1) == Some(expected.before.effective_through.0)
                    {
                        matches.push(period.code);
                    }
                }
                Ok(Ok(matches))
            })?;
            let period = match period {
                Ok(periods) if periods.len() == 1 => periods.into_iter().next().unwrap_or_default(),
                Ok(_) => {
                    return Ok(Err(comparison_refused(
                        "an equity disclosure question must name one unambiguous full posting period",
                    )));
                }
                Err(refusal) => return Ok(Err(refusal)),
            };
            if !periods.insert(period.clone()) {
                return Ok(Err(comparison_refused(
                    "a disclosure accepts at most one supplemental equity comparison per actual posting period",
                )));
            }
            let selection = CaseEquityComparisonSelection {
                period,
                label: expected.before.label.clone(),
                units: expected.before.units.clone(),
                issuance_accounts: expected.before.issuance_accounts.clone(),
                distribution_accounts: expected.before.distribution_accounts.clone(),
            };
            let selected = match self
                .case_equity_diff_request(cx, principal, capability, ordinal, &selection)
                .await?
            {
                Ok(selected) => selected,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if &selected != expected {
                return Ok(Err(comparison_refused(
                    "the equity disclosure expectation must preserve its canonical complete question and the case's exact Post frontiers",
                )));
            }
            let artifact = match self
                .read_report_artifact(cx, principal, capability, &comparison.certificate)
                .await?
            {
                Ok(artifact) => artifact,
                Err(refusal) => return Ok(Err(comparison_refused(refusal.message))),
            };
            let bytes = match artifact.canonical_bytes() {
                Ok(bytes) => bytes,
                Err(refusal) => return Ok(Err(comparison_refused(refusal.message))),
            };
            if let Err(refusal) = self
                .replay_report_artifact_for_with_history(
                    cx,
                    principal,
                    capability,
                    &bytes,
                    Some(&comparison.certificate),
                    crate::ReportArtifactExpectation::EquityRollForwardDiff(expected),
                )
                .await?
            {
                return Ok(Err(comparison_refused(format!(
                    "supplemental equity comparison does not replay: {}",
                    refusal.message,
                ))));
            }
            match fa_journal::validate_disclosure_comparison(
                self.context().book_id,
                post,
                comparison.certificate,
                &bytes,
            ) {
                Ok(comparison) => validated.push(comparison),
                Err(refusal) => return Ok(Err(refusal)),
            }
        }
        Ok(Ok(validated))
    }
}
