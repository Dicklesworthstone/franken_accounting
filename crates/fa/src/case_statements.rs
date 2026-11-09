//! Statement questions for a posted correction case. Both frontiers are fixed
//! by journal evidence: later publications cannot change an old case's bridge.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::{CaseKind, CaseState, IssuedTo, KernelError, Refusal};
use fa_model::{EntryClass, Id128};
use fa_time::{PeriodDef, PeriodKind, PeriodState};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{
    AsyncBook, Outcome, ReportSelection, StatementDefinition, StatementDiffRequest,
    StatementSelection,
};

mod equity;
pub use equity::{CaseEquityComparisonSelection, CaseEquityDisclosureComparison};

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
    /// The case's effect in the current posting period of a prior-period
    /// adjustment. This is an additional bridge over the atomic Post, not a
    /// claim that the current period had already been issued or locked.
    BeforePostImpact,
}

impl CaseStatementBasis {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::FirstIssuance { .. } => "first-issuance",
            Self::FirstLock { .. } => "first-lock",
            Self::BeforePost => "before-post-unreported",
            Self::BeforePostImpact => "before-post-impact",
        }
    }
}

/// A statement-family-aware question with fixed case frontiers. Its selection
/// retains custom activation and presentation evidence without inventing a
/// built-in definition for a company layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseStatementComparisonRequest {
    pub selection: ReportSelection,
    pub before: CommitSeq,
    pub after: Option<CommitSeq>,
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
    /// affected period's reporting closure. For `BeforePostImpact`, this is
    /// the actual posting period whose case-only movement is compared.
    pub basis_period: String,
    pub request: CaseStatementComparisonRequest,
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

fn period_cutoff<V: Vfs + Clone>(
    db: &fgdb::Database<V>,
    book: &fa_journal::BookContext,
    period: &str,
    at: CommitSeq,
) -> Outcome<fa_time::DateDay> {
    let Some(row) = db
        .vertex_at(fa_model::period_vid(&book.calendar.id, period), at)
        .map_err(KernelError::from)?
        .filter(|row| row.labels.contains(&fa_model::symbols::label::PERIOD))
    else {
        return Ok(Err(crate::statements::invalid(format!(
            "case statement period `{period}` did not exist at its original reporting frontier {}",
            at.0,
        ))));
    };
    let row = fa_journal::rows::PeriodRow::decode(&row)?;
    if row.calendar_id != book.calendar.id || row.end <= row.start {
        return Err(KernelError::Corrupt(
            "case statement period has a different calendar or invalid bounds".into(),
        )
        .into());
    }
    Ok(Ok(fa_time::DateDay(row.end.0.checked_sub(1).ok_or_else(
        || KernelError::Corrupt("case statement period end underflow".into()),
    )?)))
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

/// Follow the immutable Post's bounded member list, rather than scanning later
/// entries or guessing that a prior-period adjustment posts in a declared
/// source period. Resolve each member against the historical period metadata,
/// including explicit adjustment-period discriminators.
fn adjustment_posting_periods<V: Vfs + Clone>(
    db: &fgdb::Database<V>,
    book: &fa_journal::BookContext,
    view: &fa_journal::CaseView,
    periods: &[fa_journal::rows::PeriodRow],
    posted_at: CommitSeq,
) -> Result<Vec<String>, KernelError> {
    Ok(
        adjustment_posting_period_units(db, book, view, periods, posted_at)?
            .into_keys()
            .collect(),
    )
}

fn adjustment_posting_period_units<V: Vfs + Clone>(
    db: &fgdb::Database<V>,
    book: &fa_journal::BookContext,
    view: &fa_journal::CaseView,
    periods: &[fa_journal::rows::PeriodRow],
    posted_at: CommitSeq,
) -> Result<BTreeMap<String, BTreeSet<u32>>, KernelError> {
    if view.body.kind != CaseKind::PriorPeriodAdjustment {
        return Ok(BTreeMap::new());
    }
    let mut by_year = BTreeMap::<i32, Vec<PeriodDef>>::new();
    for period in periods {
        if period.calendar_id == book.calendar.id {
            by_year
                .entry(period.fiscal_year)
                .or_default()
                .push(PeriodDef {
                    code: period.code.clone(),
                    fiscal_year: period.fiscal_year,
                    ordinal: period.ordinal,
                    kind: period.kind,
                    start: period.start,
                    end: period.end,
                });
        }
    }
    let chart = fa_journal::chart::read_at(db, book, posted_at)?;
    let mut selected = BTreeMap::<String, BTreeSet<u32>>::new();
    for member in &view.posted {
        let (entry, recorded_at) = fa_journal::post::read_entry_at(db, member.entry, posted_at)?
            .ok_or_else(|| {
                KernelError::Corrupt("case posting impact has a missing Post member".into())
            })?;
        if recorded_at != posted_at
            || entry.entry_digest != member.entry_digest
            || entry.proposal.book_id != book.book_id
            || entry.proposal.branch_id != Id128::TRUNK
            || entry.proposal.class != EntryClass::PRIOR_PERIOD_ADJUSTMENT
        {
            return Err(KernelError::Corrupt(
                "case posting impact differs from its committed Post member".into(),
            ));
        }
        let binding = entry
            .proposal
            .extensions
            .iter()
            .find_map(|(tag, bytes)| {
                (*tag == fa_model::entry::CASE_MEMBER_EXTENSION).then_some(bytes)
            })
            .ok_or_else(|| {
                KernelError::Corrupt("case posting impact lacks its membership".into())
            })?;
        let binding = fa_journal::CaseMember::decode(binding)?;
        if binding.ordinal != view.body.ordinal || binding.plan != member.plan {
            return Err(KernelError::Corrupt(
                "case posting impact names another case or approved plan".into(),
            ));
        }
        let explicit = entry.proposal.effective_period.as_ref();
        if explicit.is_some_and(|period| period.calendar != book.calendar.id) {
            return Err(KernelError::Corrupt(
                "case posting impact names another fiscal calendar".into(),
            ));
        }
        let year = book
            .calendar
            .fiscal_year_of(entry.proposal.effective_date)?;
        let calendar = by_year.get(&year).ok_or_else(|| {
            KernelError::Corrupt("case posting impact has no recorded fiscal year".into())
        })?;
        let period = fa_time::resolve_period(
            calendar,
            entry.proposal.effective_date,
            explicit.map(|period| period.code.as_str()),
        )
        .map_err(|error| KernelError::Corrupt(format!("case posting impact period: {error:?}")))?;
        let units = selected.entry(period.code.clone()).or_default();
        for leg in &entry.proposal.legs {
            let account = chart.accounts().get(&leg.account_ref).ok_or_else(|| {
                KernelError::Corrupt("case posting impact account is absent at Post".into())
            })?;
            if (1..=5).contains(&account.account_type) {
                units.insert(leg.amount.unit.0);
            }
        }
    }
    Ok(selected)
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
    /// Prior-period adjustments additionally compare their actual current
    /// posting periods immediately before and at Post, under every valuation
    /// measure used by the original-report comparisons. These explicitly
    /// labelled impact questions cannot replace the historical questions.
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
            let posting_periods = adjustment_posting_periods(db, book, &view, &periods, posted_at)?;
            Ok(Ok((periods, selected, posting_periods)))
        })?;
        let (periods, selected, posting_periods) = match selected {
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
            .filter_map(|request| request.request.selection.statement_columns())
            .flat_map(|(_, periods, comparative)| periods.iter().chain(comparative))
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
        // Keep original-report/opening questions intact. A PPA changes current
        // retained earnings while its historical source period can correctly
        // show zero movement; requiring these extra questions prevents that
        // zero historical bridge from concealing the actual correction.
        let measures: BTreeSet<_> = requests
            .iter()
            .filter(|request| !request.opening)
            .map(|request| request.functional)
            .collect();
        for period in posting_periods {
            for &functional in &measures {
                let selections = match self.case_layouts_at(
                    cx,
                    principal,
                    capability,
                    &period,
                    before_post,
                    functional,
                )? {
                    Ok(selections) => selections,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                for selection in selections {
                    requests.push(CaseStatementDiffRequest {
                        case: ordinal,
                        period: period.clone(),
                        opening: false,
                        functional,
                        basis: CaseStatementBasis::BeforePostImpact,
                        basis_period: period.clone(),
                        request: CaseStatementComparisonRequest {
                            selection,
                            before: before_post,
                            after: Some(posted_at),
                        },
                    });
                }
            }
        }
        Ok(Ok(requests))
    }

    #[allow(clippy::too_many_arguments)]
    fn case_layouts_at(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        period: &str,
        before: CommitSeq,
        functional: bool,
    ) -> Outcome<Vec<ReportSelection>> {
        self.query(cx, |db, book| {
            let authority = match fa_journal::policy::admit_reads(db, book, principal, capability)?
            {
                Ok(authority) => authority,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) = authority.whole_book(before) {
                return Ok(Err(refusal));
            }
            let through = match period_cutoff(db, book, period, before)? {
                Ok(through) => through,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let active = match crate::statement_definition::all_active_at(
                db,
                &cx.query(),
                book,
                through,
                before,
            )? {
                Ok(active) => active,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let mut selections = Vec::with_capacity(2 + active.len());
            for name in ["balance-sheet", "income-statement"] {
                let selection = Box::new(StatementSelection {
                    definition: StatementDefinition::embedded(name)
                        .map_err(|error| KernelError::Corrupt(error.to_string()))?,
                    periods: vec![period.to_string()],
                    comparative: Vec::new(),
                });
                selections.push(if functional {
                    ReportSelection::FunctionalStatement(selection)
                } else {
                    ReportSelection::Statement(selection)
                });
            }
            for active in active {
                selections.push(ReportSelection::CustomStatement(Box::new(
                    crate::CustomStatementSelection {
                        definition: active.definition,
                        activation: active.activation,
                        activated_at: active.recorded_at,
                        functional,
                        periods: vec![period.to_string()],
                        comparative: Vec::new(),
                        presentation: None,
                    },
                )));
            }
            Ok(Ok(selections))
        })
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
            CaseStatementBasis::FirstLock { .. }
            | CaseStatementBasis::BeforePost
            | CaseStatementBasis::BeforePostImpact => None,
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
            let selection = source
                .selection
                .statement_metadata()
                .map_err(KernelError::from)?
                .ok_or_else(|| {
                    KernelError::Corrupt(
                        "issued case source is not a supported native or functional statement"
                            .into(),
                    )
                })?;
            if artifact.family() != crate::ReportArtifactFamily::Native
                || source.book_id != self.context().book_id
                || source.branch_id != Id128::TRUNK
                || source.known_at != issued.issuance.certified_at
                || selection.definition_name != issued.issuance.definition_name
                || selection.definition_version != issued.issuance.definition_version
                || selection.definition_digest != issued.issuance.definition_digest
                || !selection
                    .periods
                    .iter()
                    .chain(selection.comparative)
                    .any(|code| code == &basis_period)
            {
                return Err(KernelError::Corrupt(
                    "issued case source does not match its issuance".into(),
                )
                .into());
            }
            Some(source.selection.clone())
        } else {
            None
        };
        let functional = issued_selection
            .as_ref()
            .is_some_and(ReportSelection::uses_functional_valuations);
        let mut selections =
            match self.case_layouts_at(cx, principal, capability, &period, before, functional)? {
                Ok(selections) => selections,
                Err(refusal) => return Ok(Err(refusal)),
            };
        // An issued question is immutable, even if a newer activation was
        // already present at its certified frontier. Opening stock uses the
        // layout applicable at the earlier opening cutoff; that activation
        // may precede the issued current period's layout. An unissued name
        // first effective after that cutoff has no opening question. An
        // explicitly issued stock layout must have an applicable counterpart;
        // missing it is a refusal below, never permission to omit it.
        if let Some(mut issued) = issued_selection {
            if opening {
                match &mut issued {
                    ReportSelection::Statement(selection)
                    | ReportSelection::FunctionalStatement(selection) => {
                        selection.periods = vec![period.clone()];
                        selection.comparative.clear();
                    }
                    ReportSelection::CustomStatement(selection)
                        if selection.definition.kind
                            == fa_statements::StatementKind::BalanceSheet =>
                    {
                        let applicable = self.query(cx, |db, book| {
                            let authority = match fa_journal::policy::admit_reads(
                                db, book, principal, capability,
                            )? {
                                Ok(authority) => authority,
                                Err(refusal) => return Ok(Err(refusal)),
                            };
                            if let Err(refusal) = authority.whole_book(before) {
                                return Ok(Err(refusal));
                            }
                            let mut current = None;
                            for code in &selection.periods {
                                let through = match period_cutoff(db, book, code, before)? {
                                    Ok(through) => through,
                                    Err(refusal) => return Ok(Err(refusal)),
                                };
                                current = Some(
                                    current
                                        .map_or(through, |day: fa_time::DateDay| day.max(through)),
                                );
                            }
                            let current = current.ok_or_else(|| {
                                KernelError::Corrupt(
                                    "issued statement has no current period".into(),
                                )
                            })?;
                            let activation = match crate::statement_definition::validate_active_at(
                                db,
                                &cx.query(),
                                book,
                                &selection.definition,
                                selection.activation,
                                current,
                                before,
                            )? {
                                Ok(activation) => activation,
                                Err(refusal) => return Ok(Err(refusal)),
                            };
                            let opening = match period_cutoff(db, book, &period, before)? {
                                Ok(opening) => opening,
                                Err(refusal) => return Ok(Err(refusal)),
                            };
                            Ok(Ok(activation.effective_from <= opening))
                        })?;
                        match applicable {
                            Ok(true) => {
                                selection.periods = vec![period.clone()];
                                selection.comparative.clear();
                            }
                            Ok(false) => {
                                let historical = selections.iter().find(|historical| matches!(historical,
                                    ReportSelection::CustomStatement(historical)
                                        if historical.definition.name == selection.definition.name
                                            && historical.definition.kind == fa_statements::StatementKind::BalanceSheet
                                ));
                                let Some(historical) = historical else {
                                    return Ok(Err(crate::statements::invalid(format!(
                                        "issued custom stock layout `{}` has no approved version at opening period `{period}` and original frontier {}; the required opening comparison cannot be omitted",
                                        selection.definition.name, before.0,
                                    ))));
                                };
                                issued = historical.clone();
                            }
                            Err(refusal) => return Ok(Err(refusal)),
                        }
                    }
                    _ => {}
                }
            }
            let issued_name = issued
                .statement_metadata()
                .map_err(KernelError::from)?
                .ok_or_else(|| KernelError::Corrupt("issued statement metadata vanished".into()))?
                .definition_name;
            let mut replace = None;
            for (index, selected) in selections.iter().enumerate() {
                if selected
                    .statement_metadata()
                    .map_err(KernelError::from)?
                    .is_some_and(|metadata| metadata.definition_name == issued_name)
                {
                    replace = Some(index);
                    break;
                }
            }
            if let Some(index) = replace {
                selections[index] = issued;
            } else {
                selections.push(issued);
            }
        }
        let mut requests = Vec::new();
        for selection in selections {
            let metadata = selection
                .statement_metadata()
                .map_err(KernelError::from)?
                .ok_or_else(|| KernelError::Corrupt("case statement metadata vanished".into()))?;
            if opening && metadata.kind != fa_statements::StatementKind::BalanceSheet {
                continue;
            }
            requests.push(CaseStatementDiffRequest {
                case: ordinal,
                period: period.clone(),
                opening,
                functional: metadata.functional,
                basis: basis.clone(),
                basis_period: basis_period.clone(),
                request: CaseStatementComparisonRequest {
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
    fn admit_case_statement_question(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        question: &CaseStatementDiffRequest,
        produce: bool,
    ) -> Outcome<()> {
        if produce
            && let Err(denial) = fa_policy::require(
                capability,
                fa_policy::Op::Produce,
                "certifying a case statement comparison",
            )
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        self.query(cx, |db, book| {
            let authority = match fa_journal::policy::admit_reads(db, book, principal, capability)?
            {
                Ok(authority) => authority,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let head = db.frontier().map_err(KernelError::from)?;
            if let Err(refusal) = authority.whole_book(head) {
                return Ok(Err(refusal));
            }
            let Some(metadata) = question
                .request
                .selection
                .statement_metadata()
                .map_err(KernelError::from)?
            else {
                return Ok(Err(crate::statements::invalid(
                    "case comparisons require a supported statement selection",
                )));
            };
            if metadata.functional != question.functional {
                return Ok(Err(crate::statements::invalid(
                    "case comparison valuation basis must match its exact report selection",
                )));
            }
            if !question
                .request
                .after
                .is_some_and(|after| question.request.before <= after && after <= head)
            {
                return Ok(Err(crate::statements::invalid(
                    "case comparisons require fixed frontiers with before <= after <= book head",
                )));
            }
            Ok(Ok(()))
        })
    }

    /// Evaluate a selected case question under Read authority. A custom
    /// presentation remains pinned, while the bridge compares exact amounts.
    pub async fn case_statement_diff(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        question: &CaseStatementDiffRequest,
    ) -> Outcome<crate::StatementDiff> {
        if let Err(refusal) =
            self.admit_case_statement_question(cx, principal, capability, question, false)?
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self
            .prepare_report_history(cx, principal, capability, Some(question.request.before))
            .await?
        {
            return Ok(Err(refusal));
        }
        let request = &question.request;
        match &request.selection {
            ReportSelection::Statement(selection)
            | ReportSelection::FunctionalStatement(selection) => {
                let request = StatementDiffRequest {
                    selection: (**selection).clone(),
                    before: request.before,
                    after: request.after,
                };
                if question.functional {
                    self.functional_statement_diff(cx, principal, capability, &request)
                        .await
                } else {
                    self.statement_diff(cx, principal, capability, &request)
                }
            }
            ReportSelection::CustomStatement(selection) => {
                let before = if question.functional {
                    self.functional_custom_statement(
                        cx,
                        capability,
                        (**selection).clone(),
                        Some(request.before),
                    )
                    .await?
                } else {
                    self.custom_statement(
                        cx,
                        capability,
                        (**selection).clone(),
                        Some(request.before),
                    )?
                };
                let before = match before {
                    Ok(before) => before,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                let after = if question.functional {
                    self.functional_custom_statement(
                        cx,
                        capability,
                        (**selection).clone(),
                        request.after,
                    )
                    .await?
                } else {
                    self.custom_statement(cx, capability, (**selection).clone(), request.after)?
                };
                let after = match after {
                    Ok(after) => after,
                    Err(refusal) => return Ok(Err(refusal)),
                };
                if question.functional {
                    Ok(crate::StatementDiff::between_functional(
                        before.statement,
                        after.statement,
                    ))
                } else {
                    Ok(crate::StatementDiff::between(
                        before.statement,
                        after.statement,
                    ))
                }
            }
            _ => Ok(Err(crate::statements::invalid(
                "unsupported case statement family",
            ))),
        }
    }

    async fn certify_case_statement_source(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        selection: &ReportSelection,
        at: CommitSeq,
    ) -> Outcome<crate::ReportCertificate> {
        match selection {
            ReportSelection::FunctionalStatement(selection) => self
                .certify_functional_statement(
                    cx,
                    principal,
                    capability,
                    (**selection).clone(),
                    Some(at),
                )
                .await
                .map(|result| result.map(|report| report.certificate)),
            ReportSelection::CustomStatement(selection) if selection.functional => self
                .certify_functional_custom_statement(
                    cx,
                    capability,
                    (**selection).clone(),
                    Some(at),
                )
                .await
                .map(|result| result.map(|report| report.certificate)),
            _ => self
                .certify_report(cx, selection.clone(), Some(at))
                .map(|result| result.map(|report| report.certificate)),
        }
    }

    async fn exact_issued_case_statement_source(
        &self,
        cx: &PurposeContexts,
        capability: &fa_policy::Capability,
        question: &CaseStatementDiffRequest,
    ) -> Outcome<Option<crate::ReportCertificate>> {
        let CaseStatementBasis::FirstIssuance { certificate, .. } = &question.basis else {
            return Ok(Ok(None));
        };
        let source = match self
            .reported_statement(cx, capability, certificate, &question.basis_period)
            .await?
        {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(Ok((source.time_selection.is_none()
            && source.known_at == question.request.before
            && source.selection == question.request.selection)
            .then_some(source)))
    }

    /// Certify a fixed case question, retaining the original issued source
    /// whenever it asks this exact sequence-selected question. An instant
    /// selection is recertified at its original resolved sequence, preserving
    /// the existing sequence-only comparison contract and issuance basis.
    pub async fn certify_case_statement_diff(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &fa_policy::Capability,
        question: &CaseStatementDiffRequest,
    ) -> Outcome<crate::CertifiedStatementDiff> {
        if let Err(refusal) =
            self.admit_case_statement_question(cx, principal, capability, question, true)?
        {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self
            .prepare_report_history(cx, principal, capability, Some(question.request.before))
            .await?
        {
            return Ok(Err(refusal));
        }
        let request = &question.request;
        let original = match self
            .exact_issued_case_statement_source(cx, capability, question)
            .await?
        {
            Ok(original) => original,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let before = if let Some(original) = original {
            original
        } else {
            match self
                .certify_case_statement_source(
                    cx,
                    principal,
                    capability,
                    &request.selection,
                    request.before,
                )
                .await?
            {
                Ok(source) => source,
                Err(refusal) => return Ok(Err(refusal)),
            }
        };
        let after = request.after.ok_or_else(|| {
            KernelError::Corrupt("validated case comparison lost its fixed Post".into())
        })?;
        let after = match self
            .certify_case_statement_source(cx, principal, capability, &request.selection, after)
            .await?
        {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.compare_statement_certificates(cx, principal, capability, &before, &after)
    }

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
        equity: &[CaseEquityDisclosureComparison],
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
        if comparisons.is_empty()
            || comparisons
                .len()
                .checked_add(equity.len())
                .is_none_or(|count| count > MAX_DISCLOSURE_COMPARISONS)
        {
            return Ok(Err(comparison_refused(format!(
                "a disclosure requires 1..={MAX_DISCLOSURE_COMPARISONS} retained statement comparison digests",
            ))));
        }
        let mut digests = comparisons.to_vec();
        digests.extend(equity.iter().map(|comparison| comparison.certificate));
        digests.sort();
        if digests.contains(&[0; 32]) || digests.windows(2).any(|pair| pair[0] == pair[1]) {
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
            let post = fa_journal::DisclosurePost {
                entry: post.control_entry,
                recorded_at: post.recorded_at,
            };
            // The immutable evidence set of an existing disclosure also fixes
            // its exact retry across additive comparison-profile extensions.
            // The kernel still requires the original document, request and
            // idempotency key; this path cannot publish another disclosure.
            let recorded = view
                .disclosure
                .filter(|disclosure| disclosure.post == Some(post))
                .map(|disclosure| disclosure.comparisons);
            Ok(Ok((post, recorded)))
        })?;
        let (post, recorded) = match post {
            Ok(post) => post,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let already_disclosed = recorded.is_some();
        if let Some(recorded) = recorded {
            if recorded != digests {
                return Ok(Err(comparison_refused(
                    "an already recorded disclosure fixes its comparison digests; an exact retry must supply the same set",
                )));
            }
        } else if comparisons.len() != expected.len() {
            return Ok(Err(comparison_refused(format!(
                "case {ordinal} needs {} distinct fixed statement comparisons; {} were supplied",
                expected.len(),
                comparisons.len(),
            ))));
        }
        let mut matched = vec![false; expected.len()];
        let mut validated = Vec::with_capacity(digests.len());
        for digest in comparisons {
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
            let selection = match certificate.report_selection() {
                Ok(selection) => selection,
                Err(refusal) => return Ok(Err(comparison_refused(refusal.message))),
            };
            let (before, after) = certificate.sources();
            let request = CaseStatementComparisonRequest {
                selection,
                before: before.known_at,
                after: Some(after.known_at),
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
            // A new disclosure must keep the actual issued closure for its
            // exact sequence-selected question. A replay-equivalent newly
            // certified source cannot replace what left the entity. Existing
            // immutable disclosures retain their exact retry contract above.
            if !already_disclosed {
                let issued = match self
                    .exact_issued_case_statement_source(cx, capability, &expected[index])
                    .await?
                {
                    Ok(issued) => issued,
                    Err(refusal) => return Ok(Err(comparison_refused(refusal.message))),
                };
                if let Some(issued) = issued
                    && before.digest != issued.digest
                {
                    return Ok(Err(comparison_refused(format!(
                        "comparison {} replaces the exact first-issued source certificate {}",
                        fa_journal::evidence::hex(digest),
                        fa_journal::evidence::hex(&issued.digest),
                    ))));
                }
            }
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
        match self
            .validate_case_equity_disclosures(cx, capability, ordinal, post, equity)
            .await?
        {
            Ok(mut supplemental) => validated.append(&mut supplemental),
            Err(refusal) => return Ok(Err(refusal)),
        }
        Ok(Ok((post, validated)))
    }
}
