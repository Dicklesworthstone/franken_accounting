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
    /// The first issuance's native definition and its complete period/comparative
    /// selection are preserved. Later issuances cannot introduce another layout
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
                .native_case_statement_requests(cx, principal, capability, ordinal, source.clone())
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
                .native_case_statement_requests(cx, principal, capability, ordinal, source)
                .await?
            {
                Ok(mut opening) => requests.append(&mut opening),
                Err(refusal) => return Ok(Err(refusal)),
            }
        }
        Ok(Ok(requests))
    }

    async fn native_case_statement_requests(
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
        let mut names = vec!["balance-sheet".to_string(), "income-statement".to_string()];
        if let Some(issued) = original
            && !names.contains(&issued.issuance.definition_name)
        {
            names.push(issued.issuance.definition_name.clone());
        }
        let mut requests = Vec::new();
        for name in names {
            let mut selection = if let Some(issued) =
                original.filter(|record| record.issuance.definition_name == name)
            {
                let artifact = match self
                    .read_report_artifact(cx, principal, capability, &issued.issuance.certificate)
                    .await?
                {
                    Ok(artifact) => artifact,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                let source = artifact.source_certificate();
                let ReportSelection::Statement(selection) = &source.selection else {
                    return Err(KernelError::Corrupt(
                        "issued case source is not a native statement".into(),
                    )
                    .into());
                };
                if artifact.family() != crate::ReportArtifactFamily::Native
                    || source.book_id != self.context().book_id
                    || source.branch_id != Id128::TRUNK
                    || source.known_at != issued.issuance.certified_at
                    || selection.definition.name() != name.as_str()
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
                (**selection).clone()
            } else {
                StatementSelection {
                    definition: StatementDefinition::embedded(&name).map_err(KernelError::from)?,
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
