//! The fixed wording tables (docs/FORENSIC_CASE_STUDIES_PLAN.md §0.3, §2.2,
//! §5.6; bead fa-yugf.9, A3c): every sentence carries its sources'
//! assertion status, and every D sentence its procedure's calibration
//! clause. K-ASSERT and K-ERRRATE check that the tables cover a case; the
//! renderer (A14) reads the same tables, so the wording has one source and
//! no free-text path.

use fa_registry::procedures::Calibration;

use super::Case;
use super::expect::{Expectation, ExpectationType};
use super::source::{AssertionStatus, Assurance, Source};
use super::trace::fact_closure;

/// The phrase of a source's assertion status (§2.2). An
/// `investigative_finding` reads "the committee found"; a source whose
/// publisher is an examiner reads [`source_phrase`]'s "the examiner
/// reported".
#[must_use]
pub const fn assertion_phrase(status: AssertionStatus) -> &'static str {
    match status {
        AssertionStatus::Allegation => "the SEC alleges",
        AssertionStatus::Charge => "the indictment charges",
        AssertionStatus::InvestigativeFinding => "the committee found",
        AssertionStatus::TrusteeComputation => "the trustee computed",
        AssertionStatus::FilerAudited => "reported (audited)",
        AssertionStatus::FilerReviewed => "reported (reviewed; a review is not an audit)",
        AssertionStatus::FilerUnaudited => "reported (unaudited)",
        AssertionStatus::FilerNotFromAuditedStatements => {
            "reported (selected data; not derived from audited statements)"
        }
        AssertionStatus::CourtRuling => "the court held",
    }
}

/// The phrase `table` gives `status` for `source`: §2.2 names two phrases
/// for an investigative finding, the special committee's and the
/// examiner's, told apart by the source's `publisher`.
#[must_use]
pub fn source_phrase(
    source: &Source,
    status: AssertionStatus,
    table: &dyn Fn(AssertionStatus) -> Option<&'static str>,
) -> Option<&'static str> {
    if status == AssertionStatus::InvestigativeFinding
        && source.publisher.to_lowercase().contains("examiner")
    {
        return table(status).map(|_| "the examiner reported");
    }
    table(status)
}

/// The committed phrase table, as `table` arguments take it.
#[must_use]
pub const fn phrase_table(status: AssertionStatus) -> Option<&'static str> {
    Some(assertion_phrase(status))
}

/// A procedure's calibration clause (§5.6, the FRE 702 error-rate note).
#[must_use]
pub const fn calibration_clause(calibration: Calibration) -> &'static str {
    match calibration {
        Calibration::Planted => {
            "exercised only on planted anomalies in tests; its false-positive rate on real books has not been estimated"
        }
        Calibration::Corpus => {
            "measured on fa-gen's labelled synthetic corpora, where precision is 100% by the generator's construction; its false-positive rate on real books has not been estimated"
        }
        Calibration::Uncalibrated => {
            "its thresholds are pinned, not measured; its false-positive rate on real books has not been estimated"
        }
    }
}

/// The committed clause table, as `table` arguments take it.
#[must_use]
pub const fn clause_table(calibration: Calibration) -> Option<&'static str> {
    Some(calibration_clause(calibration))
}

/// The status a fact-level `assurance` (§4.1) stands for (§2.2).
#[must_use]
pub const fn assurance_status(a: Assurance) -> Option<AssertionStatus> {
    match a {
        Assurance::Audited => Some(AssertionStatus::FilerAudited),
        Assurance::Reviewed => Some(AssertionStatus::FilerReviewed),
        Assurance::Unaudited => Some(AssertionStatus::FilerUnaudited),
        Assurance::NotFromAudited => Some(AssertionStatus::FilerNotFromAuditedStatements),
        Assurance::NotApplicable => None,
    }
}

/// A filer status's strength: audited > reviewed > unaudited =
/// not-from-audited; `None` for a status that is not a filer's own.
#[must_use]
pub const fn strength(status: AssertionStatus) -> Option<u8> {
    match status {
        AssertionStatus::FilerAudited => Some(3),
        AssertionStatus::FilerReviewed => Some(2),
        AssertionStatus::FilerUnaudited | AssertionStatus::FilerNotFromAuditedStatements => Some(1),
        _ => None,
    }
}

/// One source of an expectation's basis closure and the status its
/// sentence carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceStatus {
    pub source: String,
    /// The fact whose own `assurance` set the status, when one did.
    pub fact: Option<String>,
    pub status: AssertionStatus,
}

impl Expectation {
    /// The T's own `assurance` as a status, when it carries one that parses.
    #[must_use]
    pub fn assurance_status(&self) -> Option<AssertionStatus> {
        self.fields
            .str("assurance")
            .and_then(AssertionStatus::parse)
    }

    /// The T's published facts: its own `published`, and each target's (a
    /// T that reads once per target, such as X-T-01).
    #[must_use]
    pub fn published_facts<'a>(&'a self, case: &'a Case) -> Vec<&'a str> {
        let mut out: Vec<&str> = self.fields.str("published").into_iter().collect();
        if let Some(set) = &case.expectations {
            out.extend(
                set.targets_of(&self.id)
                    .filter_map(|t| t.fields.str("published")),
            );
        }
        out
    }

    /// The sources of the T's published facts that are sourced, in order.
    #[must_use]
    pub fn published_sources(&self, case: &Case) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for p in self.published_facts(case) {
            if let Some(s) = case
                .facts
                .iter()
                .find(|f| f.id == p)
                .and_then(|f| f.sourced())
                && !out.contains(&s.source)
            {
                out.push(s.source.clone());
            }
        }
        out
    }

    /// The sources of the expectation's basis closure (through
    /// `interpretation.from` and `derived.from`), each with the status its
    /// sentence carries, in fact order. Precedence (§2.2, §5.3): a T's own
    /// `assurance` for its published source, then a fact's own `assurance`
    /// for that fact, then the source row's `assertion_status`.
    #[must_use]
    pub fn source_statuses(&self, case: &Case) -> Vec<SourceStatus> {
        let mut facts = std::collections::BTreeSet::new();
        for b in self.fields.strs("basis").unwrap_or(&[]) {
            facts.extend(fact_closure(case, b));
        }
        let t_assurance = (self.kind == ExpectationType::T)
            .then(|| self.assurance_status())
            .flatten()
            .map(|status| (status, self.published_sources(case)));
        let mut out: Vec<SourceStatus> = Vec::new();
        for id in &facts {
            let Some(s) = case
                .facts
                .iter()
                .find(|f| f.id == *id)
                .and_then(|f| f.sourced())
            else {
                continue;
            };
            let Some(source) = case.sources.iter().find(|x| x.id == s.source) else {
                continue;
            };
            let entry = match (&t_assurance, s.assurance.and_then(assurance_status)) {
                (Some((status, published)), _) if published.contains(&source.id) => SourceStatus {
                    source: source.id.clone(),
                    fact: None,
                    status: *status,
                },
                (_, Some(status)) => SourceStatus {
                    source: source.id.clone(),
                    fact: Some(id.clone()),
                    status,
                },
                _ => SourceStatus {
                    source: source.id.clone(),
                    fact: None,
                    status: source.assertion_status,
                },
            };
            if !out.contains(&entry) {
                out.push(entry);
            }
        }
        out
    }

    /// The ordered phrase list of the expectation's basis closure, which
    /// the renderer (A14) renders: one (source id, phrase) per source and
    /// status.
    #[must_use]
    pub fn phrases(&self, case: &Case) -> Vec<(String, &'static str)> {
        let mut out: Vec<(String, &'static str)> = Vec::new();
        for s in self.source_statuses(case) {
            let Some(source) = case.sources.iter().find(|x| x.id == s.source) else {
                continue;
            };
            if let Some(p) = source_phrase(source, s.status, &phrase_table) {
                let pair = (s.source, p);
                if !out.contains(&pair) {
                    out.push(pair);
                }
            }
        }
        out
    }
}
