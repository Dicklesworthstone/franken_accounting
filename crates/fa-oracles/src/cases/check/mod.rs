//! The load-time checks K-PROV, K-BIND, K-SCOPE, K-ANCHOR and K-DERIVE
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.6; bead fa-yugf.7, A3a), and
//! K-BASIS, K-TAUT, K-ORACLE and K-VINTAGE (bead fa-yugf.8, A3b), K-TIER
//! (bead fa-yugf.10, A4), and K-ASSERT, K-ERRRATE, K-NAMES, K-EVID and
//! K-REASON (bead fa-yugf.9, A3c): the
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
//! examined=<n>/<inputs>[ unrun=<k> (OD 2b)][ reason=<why>]` line, one
//! `RETYPE <id>[/<target>] <from>→<to> <K-ID> path=[…]` line per re-type
//! (A3b: a re-type is a result, never a failure), then one `FAIL <K-ID>
//! <file>:<line> <row>: <reason>` line per failure, all at column 0.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use super::derive::Rules;
use super::expect::ExpectationType;
use super::fact::Provenance;
use super::tiers::{self, Tiers};
use super::trace::Read;
use super::{Case, FACTS_FILE, Receipt};

pub mod anchor;
pub mod assert;
pub mod basis;
pub mod bind;
pub mod derive;
pub mod errrate;
pub mod evid;
pub mod names;
pub mod oracle;
pub mod prov;
pub mod reason;
pub mod scope;
#[cfg(test)]
mod t_tests;
pub mod taut;
#[cfg(test)]
mod tests;
pub mod tier;
pub mod vintage;

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

/// A re-type (A3b): the row's claim type after a check, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retype {
    pub expectation: String,
    /// The target fact, where the reads sit on targets.
    pub target: Option<String>,
    pub from: ExpectationType,
    pub to: ExpectationType,
    pub check: String,
    /// The chain of fact ids and rules (and the leg) that caused it.
    pub path: Vec<String>,
}

impl Retype {
    #[must_use]
    pub fn new(read: &Read<'_>, to: ExpectationType, check: &str, path: Vec<String>) -> Self {
        Self {
            expectation: read.expectation.id.clone(),
            target: read.target.map(|t| t.fact.clone()),
            from: read.expectation.kind,
            to,
            check: check.to_string(),
            path,
        }
    }
}

impl fmt::Display for Retype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RETYPE {}", self.expectation)?;
        if let Some(t) = &self.target {
            write!(f, "/{t}")?;
        }
        write!(
            f,
            " {}\u{2192}{} {} path=[{}]",
            self.from.as_str(),
            self.to.as_str(),
            self.check,
            self.path.join(", ")
        )
    }
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
    /// The re-types the check found (A3b).
    pub retypes: Vec<Retype>,
    /// Why the check examined nothing, when it is exempt (`exempt:
    /// harness_selftest`).
    pub reason: Option<String>,
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
            retypes: Vec::new(),
            reason: None,
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
        if let Some(reason) = &self.reason {
            out.push_str(&format!(" reason={reason}"));
        }
        out.push('\n');
        if !self.rows.is_empty() {
            out.push_str(&format!("  rows: {}\n", self.rows.join(", ")));
        }
        for r in &self.retypes {
            out.push_str(&format!("{r}\n"));
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
    /// The two-reader procedure tier table (A4), or why it does not load.
    pub tiers: Result<Tiers, String>,
    /// `registries/procedures.toml` as K-TIER digests it (tests pass an
    /// edited copy).
    pub procedures: &'a str,
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
            tiers: tier::embedded(),
            procedures: tiers::PROCEDURES,
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
        basis::check(cx),
        taut::check(cx),
        oracle::check(cx),
        vintage::check(cx),
        tier::check(cx),
        assert::check(cx),
        errrate::check(cx),
        names::check(cx),
        evid::check(cx),
        reason::check(cx),
    ];
    for c in case_checks.iter().filter(|c| c.case == cx.case.header.id) {
        let mut report = (c.run)(cx.case);
        report.check = format!("case:{}:{}", c.case, c.name);
        out.push(report);
    }
    out
}

impl Case {
    /// An expectation's claim type after every re-type of K-TAUT and K-ORACLE
    /// (A3b), for the whole row (`target = None`) or one target where the
    /// reads sit on targets: a re-type on the row applies to every target. R
    /// (read-back) wins over C. `None` when the case has no such expectation.
    #[must_use]
    pub fn effective_type(
        &self,
        expectation: &str,
        target: Option<&str>,
    ) -> Option<ExpectationType> {
        let declared = self.expectations.as_ref()?.get(expectation)?.kind;
        let cx = Context::new(self);
        let mut out = declared;
        for r in [taut::check(&cx), oracle::check(&cx)]
            .iter()
            .flat_map(|rep| rep.retypes.iter())
            .filter(|r| {
                r.expectation == expectation
                    && (r.target.is_none() || r.target.as_deref() == target)
            })
        {
            if out != ExpectationType::R {
                out = r.to;
            }
        }
        Some(out)
    }
}

/// The facts file, as failures name it.
pub(crate) const FACTS: &str = FACTS_FILE;
