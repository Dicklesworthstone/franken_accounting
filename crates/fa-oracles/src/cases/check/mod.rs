//! The load-time checks K-PROV, K-BIND, K-SCOPE, K-ANCHOR and K-DERIVE
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.6; bead fa-yugf.7, A3a): the
//! harness's refusals of its own research record, run offline over a loaded
//! [`Case`] (tests never read the fetch cache, §4.3; a quote-less fact is
//! bound by its receipt, §4.4).
//!
//! Each check returns a [`CheckReport`]. It counts `inputs` (the rows of its
//! input kind), `examined` (those it checked) and `pending` (those whose data
//! waits on owner decision 2b, a rows file not yet committed: never
//! examined, never PASS). A report is FAIL when a row failed or when
//! `examined + pending < inputs` (a skipped row), UNRUN when it examined
//! nothing, and PASS otherwise. Its rendering is the gate vocabulary of
//! `scripts/lib/gate_verdict.sh`: one `CHECK <K-ID> PASS|FAIL|UNRUN
//! examined=<n>/<inputs>[ unrun=<k> (OD 2b)]` line, then one `FAIL <K-ID>
//! <file>:<line> <row>: <reason>` line per failure, all at column 0.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use super::derive::Rules;
use super::fact::Provenance;
use super::{Case, FACTS_FILE, Receipt};

pub mod anchor;
pub mod bind;
pub mod derive;
pub mod prov;
pub mod scope;
#[cfg(test)]
mod tests;

/// A check's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail,
    Unrun,
}

impl Verdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Unrun => "UNRUN",
        }
    }
}

/// One failing row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckFailure {
    pub file: String,
    pub line: Option<usize>,
    pub row: String,
    pub reason: String,
}

/// One check's result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckReport {
    pub check: String,
    pub verdict: Verdict,
    pub examined: usize,
    pub inputs: usize,
    pub pending: usize,
    pub failures: Vec<CheckFailure>,
    /// The examined rows, each with its note (`F12`, `LJM1 range=none`).
    pub rows: Vec<String>,
}

impl CheckReport {
    /// An open report over `inputs` rows; [`Self::finish`] sets the verdict.
    #[must_use]
    pub fn new(check: &str, inputs: usize) -> Self {
        Self {
            check: check.to_string(),
            verdict: Verdict::Unrun,
            examined: 0,
            inputs,
            pending: 0,
            failures: Vec::new(),
            rows: Vec::new(),
        }
    }

    /// Records one examined row.
    pub fn examined(&mut self, row: impl Into<String>) {
        self.examined += 1;
        self.rows.push(row.into());
    }

    /// Records one failure.
    pub fn fail(&mut self, file: &str, line: Option<usize>, row: &str, reason: impl Into<String>) {
        self.failures.push(CheckFailure {
            file: file.to_string(),
            line,
            row: row.to_string(),
            reason: reason.into(),
        });
    }

    /// Sets the verdict: FAIL on a failure or a skipped row, UNRUN when
    /// nothing was examined, PASS otherwise.
    #[must_use]
    pub fn finish(mut self) -> Self {
        if self.examined + self.pending < self.inputs {
            let reason = format!(
                "examined {} + pending {} < inputs {} (a skipped row)",
                self.examined, self.pending, self.inputs
            );
            self.fail("-", None, "-", reason);
        }
        self.verdict = if !self.failures.is_empty() {
            Verdict::Fail
        } else if self.examined == 0 {
            Verdict::Unrun
        } else {
            Verdict::Pass
        };
        self
    }

    /// The report's lines, with the case id after `CHECK` when given
    /// (A10a's per-case transcript).
    #[must_use]
    pub fn render(&self, case: Option<&str>) -> String {
        let mut out = String::from("CHECK ");
        if let Some(case) = case {
            out.push_str(case);
            out.push(' ');
        }
        out.push_str(&format!(
            "{} {} examined={}/{}",
            self.check,
            self.verdict.as_str(),
            self.examined,
            self.inputs
        ));
        if self.pending > 0 {
            out.push_str(&format!(" unrun={} (OD 2b)", self.pending));
        }
        out.push('\n');
        if !self.rows.is_empty() {
            out.push_str(&format!("  rows: {}\n", self.rows.join(", ")));
        }
        for f in &self.failures {
            let line = f.line.map_or_else(|| "-".to_string(), |l| l.to_string());
            out.push_str(&format!(
                "FAIL {} {}:{line} {}: {}\n",
                self.check, f.file, f.row, f.reason
            ));
        }
        out
    }
}

impl fmt::Display for CheckReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render(None))
    }
}

/// A check one case needs (X5's group-member basis check), registered by
/// case directory and run only on that case; its id is
/// `case:<case>:<name>`.
#[derive(Clone, Copy, Debug)]
pub struct CaseCheck {
    pub case: &'static str,
    pub name: &'static str,
    pub run: fn(&Case) -> CheckReport,
}

/// The registered case-scoped checks (none yet; X5 adds the first).
pub const CASE_CHECKS: &[CaseCheck] = &[];

/// A source's extraction text by source id, when one is at hand.
pub type Extraction<'a> = &'a dyn Fn(&str) -> Option<String>;

/// What the checks read besides the case.
pub struct Context<'a> {
    pub case: &'a Case,
    /// The pending facts ([`pending_facts`]).
    pub pending: BTreeSet<String>,
    /// The derivation table, or why it does not load.
    pub rules: Result<Rules, String>,
    /// Each registered unit's scale.
    pub scales: BTreeMap<String, u8>,
    /// A source's extraction text, when one is at hand (a test's fixture
    /// extraction; never the fetch cache).
    pub extraction: Option<Extraction<'a>>,
}

impl<'a> Context<'a> {
    #[must_use]
    pub fn new(case: &'a Case) -> Self {
        let rules = Rules::embedded().map_err(|errs| {
            errs.iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        });
        let scales = fa_registry::units_embedded()
            .map(|units| units.into_iter().map(|u| (u.code, u.scale)).collect())
            .unwrap_or_default();
        Self {
            case,
            pending: pending_facts(case),
            rules,
            scales,
            extraction: None,
        }
    }

    /// The receipt for `fact`, if any.
    #[must_use]
    pub fn receipt(&self, fact: &str) -> Option<&'a Receipt> {
        self.case.receipts.iter().find(|r| r.fact == fact)
    }
}

/// The facts whose data waits on owner decision 2b: every `rows_file` fact
/// whose file is not committed, and every fact whose `from` chain (derived
/// or interpretation, transitively) reaches one.
#[must_use]
pub fn pending_facts(case: &Case) -> BTreeSet<String> {
    let mut pending: BTreeSet<String> = case
        .facts
        .iter()
        .filter(|f| {
            f.sourced()
                .is_some_and(|s| s.rows_file.is_some() && !s.rows_committed)
        })
        .map(|f| f.id.clone())
        .collect();
    loop {
        let before = pending.len();
        for f in &case.facts {
            let from = match &f.provenance {
                Provenance::Derived(d) => d.from.as_slice(),
                Provenance::Interpretation(i) => i.from.as_slice(),
                Provenance::Sourced(_) | Provenance::Synthetic(_) => &[],
            };
            if from.iter().any(|x| pending.contains(x)) {
                pending.insert(f.id.clone());
            }
        }
        if pending.len() == before {
            return pending;
        }
    }
}

/// Every load-time check on `case`, then its registered case-scoped checks.
#[must_use]
pub fn run_load_checks(case: &Case) -> Vec<CheckReport> {
    run_load_checks_with(&Context::new(case), CASE_CHECKS)
}

/// [`run_load_checks`] with an explicit context and case-check table.
#[must_use]
pub fn run_load_checks_with(cx: &Context<'_>, case_checks: &[CaseCheck]) -> Vec<CheckReport> {
    let mut out = vec![
        prov::check(cx),
        bind::check(cx),
        scope::check(cx),
        anchor::check(cx),
        derive::check(cx),
    ];
    for c in case_checks.iter().filter(|c| c.case == cx.case.header.id) {
        let mut report = (c.run)(cx.case);
        report.check = format!("case:{}:{}", c.case, c.name);
        out.push(report);
    }
    out
}

/// The facts file, as failures name it.
pub(crate) const FACTS: &str = FACTS_FILE;
