//! Statement questions for a posted correction case. Both frontiers are fixed
//! by journal evidence: later publications cannot change an old case's bridge.

use asupersync::fs::Vfs;
use fa_journal::{CaseKind, CaseState, IssuedTo, KernelError, Refusal};
use fa_model::Id128;
use fa_time::{PeriodKind, PeriodState};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{
    AsyncBook, Outcome, ReportSelection, StatementDefinition, StatementDiffRequest,
    StatementSelection,
};

/// Evidence selecting the earlier statement. `BeforePost` is deliberately
/// distinct from originally reported: a never-issued, never-locked period has
/// no originally reported closure, but its correction can still be inspected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CaseStatementBasis {
    FirstIssuance {
        ordinal: u32,
        recorded_at: CommitSeq,
        certificate: [u8; 32],
        issued_to: IssuedTo,
    },
    FirstLock {
        entry: VId,
        recorded_at: CommitSeq,
    },
    BeforePost,
}

impl CaseStatementBasis {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::FirstIssuance { .. } => "first-issuance",
            Self::FirstLock { .. } => "first-lock",
            Self::BeforePost => "before-post-unreported",
        }
    }
}

/// A fixed, independently replayable question and the reporting evidence that
/// selected it. This is a request, not an assertion that a case was disclosed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseStatementDiffRequest {
    pub case: u32,
    pub period: String,
    pub opening: bool,
    /// Preserve the originally issued statement's retained functional amounts.
    /// With no issuance, the comparison uses native units.
    pub functional: bool,
    pub basis: CaseStatementBasis,
    /// The period whose original reporting event supplies the earlier
    /// frontier. An otherwise unreported opening statement uses the earliest
    /// affected period's reporting closure.
    pub basis_period: String,
    pub request: StatementDiffRequest,
}

#[derive(Clone)]
struct PeriodSource {
    period: String,
    opening: bool,
    before: CommitSeq,
    posted_at: CommitSeq,
    basis: CaseStatementBasis,
    basis_period: String,
    issuances: Vec<fa_journal::IssuanceRecord>,
}

fn refused(code: &'static str, message: impl Into<String>, fix: &str) -> Refusal {
    Refusal::new(
        code,
        fa_journal::exit::REFUSAL,
        message,
        "plan §7.4 and §8.3 (originally reported closure versus the case's atomic Post)",
        fix,
    )
}

#[allow(clippy::too_many_arguments)]
fn period_source<V: Vfs + Clone>(
    db: &fgdb::Database<V>,
    book: &fa_journal::BookContext,
    view: &fa_journal::CaseView,
    period: &str,
    opening: bool,
    posted_at: CommitSeq,
    audience: Option<IssuedTo>,
    fallback: Option<&PeriodSource>,
) -> Outcome<PeriodSource> {
    let before_post = CommitSeq(posted_at.0.checked_sub(1).ok_or_else(|| {
        KernelError::Corrupt("case Post has no preceding journal frontier".into())
    })?);
    let mut issuances: Vec<_> = fa_journal::issuances(db, book, period)?
        .into_iter()
        .filter(|record| {
            record.recorded_at <= before_post
                && audience.is_none_or(|audience| record.issuance.issued_to == audience)
        })
        .collect();
    let (before, basis, basis_period) = if let Some(first) = issuances.first() {
        (
            first.issuance.certified_at,
            CaseStatementBasis::FirstIssuance {
                ordinal: first.issuance.ordinal,
                recorded_at: first.recorded_at,
                certificate: first.issuance.certificate,
                issued_to: first.issuance.issued_to,
            },
            period.to_string(),
        )
    } else if let Some(audience) = audience.filter(|_| !opening) {
        return Ok(Err(refused(
            fa_journal::refusal::code::NOT_ISSUED_TO,
            format!(
                "period `{period}` had no issuance to {} before case {} posted",
                audience.name(),
                view.body.ordinal
            ),
            "select an audience that received the period before the case Post, or omit the audience",
        )));
    } else if let Some(first) = fa_journal::period_transitions(db, book, period)?
        .into_iter()
        .find(|transition| {
            audience.is_none()
                && transition.to == PeriodState::Locked
                && transition.recorded_at <= before_post
        })
    {
        (
            first.recorded_at,
            CaseStatementBasis::FirstLock {
                entry: first.entry_vid,
                recorded_at: first.recorded_at,
            },
            period.to_string(),
        )
    } else if let Some(source) = fallback.filter(|_| opening) {
        issuances = source.issuances.clone();
        (
            source.before,
            source.basis.clone(),
            source.basis_period.clone(),
        )
    } else if view.body.kind == CaseKind::Revision {
        (
            before_post,
            CaseStatementBasis::BeforePost,
            period.to_string(),
        )
    } else {
        return Ok(Err(refused(
            fa_journal::refusal::code::NOT_ORIGINALLY_REPORTED,
            format!(
                "period `{period}` had no issuance or Lock before case {} posted; this case has no originally reported statement to compare",
                view.body.ordinal
            ),
            "compare a case over previously issued or locked statements; an unreported Revision may show only its own Post effect",
        )));
    };
    if before > before_post {
        return Err(
            KernelError::Corrupt("case reporting basis is later than its Post".into()).into(),
        );
    }
    Ok(Ok(PeriodSource {
        period: period.to_string(),
        opening,
        before,
        posted_at,
        basis,
        basis_period,
        issuances,
    }))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Select affected-period statements and the opening balance sheet under
    /// current whole-book Read authority. The original coordinate is the first
    /// issuance visible at Post, else the first Lock, never Close. An explicit
    /// audience requires an issuance to that audience. Without either original
    /// reporting event, only Revision cases may use the clearly labelled
    /// correction-only fallback. Restatements and retrospective policy changes
    /// require a real original-reporting closure. An unreported opening period
    /// uses the earliest affected period's original reporting frontier.
    /// The first issuance's definition, native or functional valuation basis,
    /// and complete period/comparative selection are preserved. Later issuances cannot introduce another layout
    /// into that original reporting closure, even if certified at the same
    /// frontier. The opening statement alone derives a new
    /// single-period stock question. Every `after` is Post, never HEAD.
    pub async fn case_statement_diff_requests(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        ordinal: u32,
        audience: Option<IssuedTo>,
    ) -> Outcome<Vec<CaseStatementDiffRequest>> {
        let posted = self.query(cx, |db, book| {
            let authority = match fa_journal::policy::admit_reads(db, book, principal, capability)?
            {
                Ok(authority) => authority,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let head = db.frontier().map_err(KernelError::from)?;
            if let Err(refusal) = authority.whole_book(head) {
                return Ok(Err(refusal));
            }
            let Some(view) = fa_journal::read_case(db, book, ordinal)? else {
                return Ok(Err(refused(
                    fa_journal::refusal::code::CASE_UNKNOWN,
                    format!("this book has no restatement case {ordinal}"),
                    "list the book's cases with `fa case list --json`",
                )));
            };
            let Some(posted_at) = view
                .transitions
                .iter()
                .find(|transition| transition.to == CaseState::Posted)
                .map(|transition| transition.recorded_at)
            else {
                return Ok(Err(refused(
                    fa_journal::refusal::code::CASE_STATE,
                    format!(
                        "restatement case {ordinal} is {} and has posted nothing",
                        view.state.name()
                    ),
                    "read its rehearsal with `fa case diff`, or post its approved manifest first",
                )));
            };
            let before_post = CommitSeq(posted_at.0.checked_sub(1).ok_or_else(|| {
                KernelError::Corrupt("case Post has no preceding journal frontier".into())
            })?);
            Ok(Ok((view, posted_at, before_post)))
        })?;
        let (view, posted_at, before_post) = match posted {
            Ok(posted) => posted,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = self
            .prepare_report_history(cx, principal, capability, Some(before_post))
            .await?
        {
            return Ok(Err(refusal));
        }
        let selected = self.query(cx, |db, book| {
            let authority = match fa_journal::policy::admit_reads(db, book, principal, capability)?
            {
                Ok(authority) => authority,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) = authority.whole_book(before_post) {
                return Ok(Err(refusal));
            }
            let periods = db
                .vertices_at(before_post)
                .map_err(KernelError::from)?
                .into_iter()
                .filter(|row| row.labels.contains(&fa_model::symbols::label::PERIOD))
                .map(|row| fa_journal::rows::PeriodRow::decode(&row))
                .collect::<Result<Vec<_>, _>>()?;
            if view
                .body
                .periods
                .iter()
                .any(|code| !periods.iter().any(|period| &period.code == code))
            {
                return Err(KernelError::Corrupt(
                    "an affected case period is absent at its Post".into(),
                )
                .into());
            }
            let mut selected = Vec::new();
            for period in &view.body.periods {
                cx.query().checkpoint().map_err(crate::BookError::Context)?;
                match period_source(db, book, &view, period, false, posted_at, audience, None)? {
                    Ok(source) => selected.push(source),
                    Err(refusal) => return Ok(Err(refusal)),
                }
            }
            Ok(Ok((periods, selected)))
        })?;
        let (periods, selected) = match selected {
            Ok(selected) => selected,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut requests = Vec::new();
        for source in &selected {
            match self
                .reported_case_statement_requests(
                    cx,
                    principal,
                    capability,
                    ordinal,
                    source.clone(),
                )
                .await?
            {
                Ok(mut next) => requests.append(&mut next),
                Err(refusal) => return Ok(Err(refusal)),
            }
        }

        // Resolve the opening only after the issued questions are known: an
        // issued comparative can precede every period named by the case.
        let earliest = requests
            .iter()
            .flat_map(|request| {
                request
                    .request
                    .selection
                    .periods
                    .iter()
                    .chain(&request.request.selection.comparative)
            })
            .filter_map(|code| periods.iter().find(|period| &period.code == code))
            .min_by_key(|period| (period.start, period.code.as_str()));
        let opening = earliest
            .and_then(|earliest| {
                periods.iter().find(|period| {
                    period.kind == PeriodKind::Normal && period.end == earliest.start
                })
            })
            .filter(|period| !view.body.periods.contains(&period.code));
        if let Some(opening) = opening {
            let fallback = selected.iter().min_by_key(|source| {
                periods
                    .iter()
                    .find(|period| period.code == source.period)
                    .map(|period| (period.start, period.code.as_str()))
            });
            let source = self.query(cx, |db, book| {
                let authority =
                    match fa_journal::policy::admit_reads(db, book, principal, capability)? {
                        Ok(authority) => authority,
                        Err(refusal) => return Ok(Err(refusal)),
                    };
                if let Err(refusal) = authority.whole_book(before_post) {
                    return Ok(Err(refusal));
                }
                period_source(
                    db,
                    book,
                    &view,
                    &opening.code,
                    true,
                    posted_at,
                    audience,
                    fallback,
                )
            })?;
            let source = match source {
                Ok(source) => source,
                Err(refusal) => return Ok(Err(refusal)),
            };
            match self
                .reported_case_statement_requests(cx, principal, capability, ordinal, source)
                .await?
            {
                Ok(mut opening) => requests.append(&mut opening),
                Err(refusal) => return Ok(Err(refusal)),
            }
        }
        Ok(Ok(requests))
    }

    async fn reported_case_statement_requests(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        ordinal: u32,
        source: PeriodSource,
    ) -> Outcome<Vec<CaseStatementDiffRequest>> {
        let PeriodSource {
            period,
            opening,
            before,
            posted_at,
            basis,
            basis_period,
            issuances,
        } = source;
        // AS ORIGINALLY REPORTED is the period's first issuance, not the
        // first issuance of each layout. A later publication must not lend
        // its selector to this earlier coordinate, even if its certificate
        // happens to name the same historical frontier.
        let original = match &basis {
            CaseStatementBasis::FirstIssuance {
                ordinal,
                recorded_at,
                certificate,
                ..
            } => Some(
                issuances
                    .iter()
                    .find(|record| {
                        record.issuance.ordinal == *ordinal
                            && record.recorded_at == *recorded_at
                            && record.issuance.certificate == *certificate
                            && record.issuance.certified_at == before
                    })
                    .ok_or_else(|| {
                        KernelError::Corrupt(
                            "case original issuance does not match its reporting frontier".into(),
                        )
                    })?,
            ),
            CaseStatementBasis::FirstLock { .. } | CaseStatementBasis::BeforePost => None,
        };
        let issued_selection = if let Some(issued) = original {
            let artifact = match self
                .read_report_artifact(cx, principal, capability, &issued.issuance.certificate)
                .await?
            {
                Ok(artifact) => artifact,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let source = artifact.source_certificate();
            let (selection, functional) = match &source.selection {
                ReportSelection::Statement(selection) => (selection, false),
                ReportSelection::FunctionalStatement(selection) => (selection, true),
                _ => {
                    return Err(KernelError::Corrupt(
                        "issued case source is not a supported native or functional statement"
                            .into(),
                    )
                    .into());
                }
            };
            if artifact.family() != crate::ReportArtifactFamily::Native
                || source.book_id != self.context().book_id
                || source.branch_id != Id128::TRUNK
                || source.known_at != issued.issuance.certified_at
                || selection.definition.name() != issued.issuance.definition_name
                || selection.definition.version() != issued.issuance.definition_version
                || selection.definition.digest().map_err(KernelError::from)?
                    != issued.issuance.definition_digest
                || !selection
                    .periods
                    .iter()
                    .chain(&selection.comparative)
                    .any(|code| code == &basis_period)
            {
                return Err(KernelError::Corrupt(
                    "issued case source does not match its issuance".into(),
                )
                .into());
            }
            Some(((**selection).clone(), functional))
        } else {
            None
        };
        let functional = issued_selection
            .as_ref()
            .is_some_and(|(_, functional)| *functional);
        let mut names = vec!["balance-sheet".to_string(), "income-statement".to_string()];
        if let Some(issued) = original
            && !names.contains(&issued.issuance.definition_name)
        {
            names.push(issued.issuance.definition_name.clone());
        }
        let mut requests = Vec::new();
        for name in names {
            let mut selection = if let Some((selection, _)) = issued_selection
                .as_ref()
                .filter(|(selection, _)| selection.definition.name() == name)
            {
                selection.clone()
            } else {
                StatementSelection {
                    definition: StatementDefinition::embedded(&name)
                        .map_err(|error| KernelError::Corrupt(error.to_string()))?,
                    periods: vec![period.clone()],
                    comparative: Vec::new(),
                }
            };
            if opening {
                if selection.definition.kind() != fa_statements::StatementKind::BalanceSheet {
                    continue;
                }
                selection.periods = vec![period.clone()];
                selection.comparative.clear();
            }
            requests.push(CaseStatementDiffRequest {
                case: ordinal,
                period: period.clone(),
                opening,
                functional,
                basis: basis.clone(),
                basis_period: basis_period.clone(),
                request: StatementDiffRequest {
                    selection,
                    before,
                    after: Some(posted_at),
                },
            });
        }
        Ok(Ok(requests))
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Validate the complete fixed set before a disclosure writes anything.
    /// The kernel separately witnesses the retained artifacts and immutable
    /// Post. This layer owns statement selection and independent replay of
    /// both historical sources; a digest alone is never that verdict.
    pub(crate) async fn validate_case_disclosure_comparisons(
        &mut self,
        cx: &PurposeContexts,
        capability: &fa_policy::Capability,
        ordinal: u32,
        comparisons: &[[u8; 32]],
    ) -> Outcome<(
        fa_journal::DisclosurePost,
        Vec<fa_journal::ValidatedDisclosureComparison>,
    )> {
        use fa_journal::case::{MAX_DISCLOSURE_COMPARISONS, comparison_refused};
        let principal = capability.holder();
        if let Err(denial) = fa_policy::require(
            capability,
            fa_policy::Op::Restate,
            "disclosing a restatement case",
        ) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let selected = match self
            .case_statement_diff_requests(cx, principal, capability, ordinal, None)
            .await?
        {
            Ok(selected) => selected,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if comparisons.is_empty() || comparisons.len() > MAX_DISCLOSURE_COMPARISONS {
            return Ok(Err(comparison_refused(format!(
                "a disclosure requires 1..={MAX_DISCLOSURE_COMPARISONS} retained statement comparison digests",
            ))));
        }
        let mut digests = comparisons.to_vec();
        digests.sort();
        if digests.iter().any(|digest| *digest == [0; 32])
            || digests.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Ok(Err(comparison_refused(
                "duplicate or zero disclosure comparison digest",
            )));
        }
        // An original issued selection can cover more than one affected
        // period. Bind that identical question once, regardless of producer.
        let mut expected = Vec::<CaseStatementDiffRequest>::new();
        for selection in selected {
            if !expected.iter().any(|prior| {
                prior.functional == selection.functional && prior.request == selection.request
            }) {
                expected.push(selection);
            }
        }
        if digests.len() != expected.len() {
            return Ok(Err(comparison_refused(format!(
                "case {ordinal} needs {} distinct fixed statement comparisons; {} were supplied",
                expected.len(),
                digests.len(),
            ))));
        }
        let post = self.query(cx, |db, book| {
            let authority = match fa_journal::policy::admit_reads(db, book, principal, capability)?
            {
                Ok(authority) => authority,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) = authority.whole_book(db.frontier().map_err(KernelError::from)?) {
                return Ok(Err(refusal));
            }
            let view = fa_journal::read_case(db, book, ordinal)?
                .ok_or_else(|| KernelError::Corrupt("validated case vanished".into()))?;
            let post = view
                .transitions
                .iter()
                .find(|transition| transition.to == CaseState::Posted)
                .ok_or_else(|| KernelError::Corrupt("validated case Post vanished".into()))?;
            Ok(Ok(fa_journal::DisclosurePost {
                entry: post.control_entry,
                recorded_at: post.recorded_at,
            }))
        })?;
        let post = match post {
            Ok(post) => post,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let mut matched = vec![false; expected.len()];
        let mut validated = Vec::with_capacity(digests.len());
        for digest in &digests {
            let artifact = match self
                .read_report_artifact(cx, principal, capability, digest)
                .await?
            {
                Ok(artifact) => artifact,
                Err(refusal) => {
                    return Ok(Err(comparison_refused(format!(
                        "comparison {} cannot be read: {}",
                        fa_journal::evidence::hex(digest),
                        refusal.message,
                    ))));
                }
            };
            let bytes = match artifact.canonical_bytes() {
                Ok(bytes) => bytes,
                Err(refusal) => return Ok(Err(comparison_refused(refusal.message))),
            };
            let certificate = match crate::StatementDiffCertificate::decode(&bytes) {
                Ok(certificate) => certificate,
                Err(refusal) => {
                    return Ok(Err(comparison_refused(format!(
                        "disclosure artifact is not a statement comparison: {}",
                        refusal.message,
                    ))));
                }
            };
            let request = match certificate.request() {
                Ok(request) => request,
                Err(refusal) => return Ok(Err(comparison_refused(refusal.message))),
            };
            let Some(index) = expected.iter().enumerate().find_map(|(index, expected)| {
                (!matched[index]
                    && expected.functional == certificate.uses_functional_valuations()
                    && expected.request == request)
                    .then_some(index)
            }) else {
                return Ok(Err(comparison_refused(format!(
                    "comparison {} is extra, repeats a question, or changes the case's original definition, periods, valuation basis or fixed frontiers",
                    fa_journal::evidence::hex(digest),
                ))));
            };
            if let Err(refusal) = self
                .replay_report_artifact_for_with_history(
                    cx,
                    principal,
                    capability,
                    &bytes,
                    Some(digest),
                    crate::ReportArtifactExpectation::AsSupplied,
                )
                .await?
            {
                return Ok(Err(comparison_refused(format!(
                    "comparison {} does not replay: {}",
                    fa_journal::evidence::hex(digest),
                    refusal.message,
                ))));
            }
            match fa_journal::validate_disclosure_comparison(
                self.context().book_id,
                post,
                *digest,
                &bytes,
            ) {
                Ok(comparison) => validated.push(comparison),
                Err(refusal) => return Ok(Err(refusal)),
            }
            matched[index] = true;
        }
        Ok(Ok((post, validated)))
    }
}
