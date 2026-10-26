//! K-BRANCH (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.6 and §2.6 rules 1, 2
//! and 8; bead fa-yugf.13, A5b).
//!
//! - Every input that a claimed component of a D target, or the kernel for
//!   a P target, reads is sourced, declared, interpreted, an observed
//!   covariate or a branch class ([`crate::cases::status`]); an unanchored
//!   one is refused.
//! - A D component's authored `*_status` is the status its inputs derive; a
//!   `Rel(<covariate>)` is admissible only on a component a covariate rule
//!   moves.
//! - A branched target's table enumerates (A5a refuses a capped table with a
//!   single component).
//! - A `[[branch_cell]]` marked `record_consistent = true` does not
//!   contradict a sourced constraint (`constraints`, R-QUAL): a per-leg cell
//!   with a non-multiple leg contradicts `round_dollar_lower_bound`. A cell
//!   marked `record_consistent = false` is admitted, evaluated and never
//!   summarized; CF rows are exempt.
//! - A CF row changes one attribute its parent's components read.

use std::collections::BTreeSet;

use super::{CheckReport, Context};
use crate::cases::EXPECTATIONS_FILE;
use crate::cases::book::BranchAttribute;
use crate::cases::branch::{self, BranchRules, ClassRule};
use crate::cases::expect::{Expectation, ExpectationType, Status, Target};
use crate::cases::status::{component_statuses, same_status, spell};

pub const ID: &str = "K-BRANCH";

/// The constraint rule that bounds entry amounts to whole multiples of 10^3
/// units (A2's derivation table).
pub const ROUND_DOLLAR: &str = "round_dollar_lower_bound";

/// A `harness_selftest` case is exempt by kind, as K-BASIS is: its synthetic
/// stand-ins anchor no claim about history. UNRUN with that reason.
pub(crate) fn selftest_exempt(cx: &Context<'_>, id: &str) -> Option<CheckReport> {
    (cx.case.header.kind == crate::cases::header::CaseKind::HarnessSelftest).then(|| {
        let mut r = CheckReport::new(id, 0);
        r.reason = Some("exempt: harness_selftest".into());
        r.finish()
    })
}

/// K-BRANCH under the committed branch rules.
#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    match branch::rules() {
        Ok(rules) => check_with(cx, &rules),
        Err(errs) => {
            let mut rep = CheckReport::new(ID, 1);
            for e in errs {
                rep.fail(branch::FILE, e.line, "-", e.detail);
            }
            rep.finish()
        }
    }
}

/// The D and P targets of a case's expectations, and its CF rows.
fn rows<'c>(cx: &Context<'c>) -> (Vec<(&'c Expectation, &'c Target)>, Vec<&'c Expectation>) {
    let Some(set) = cx.case.expectations.as_ref() else {
        return (Vec::new(), Vec::new());
    };
    let targets = set
        .expectations
        .iter()
        .filter(|e| matches!(e.kind, ExpectationType::D | ExpectationType::P))
        .flat_map(|e| set.targets_of(&e.id).map(move |t| (e, t)))
        .collect();
    let cfs = set
        .expectations
        .iter()
        .filter(|e| e.kind == ExpectationType::Cf)
        .collect();
    (targets, cfs)
}

/// K-BRANCH under `rules` (tests pass an edited table).
#[must_use]
pub fn check_with(cx: &Context<'_>, rules: &BranchRules) -> CheckReport {
    if let Some(r) = selftest_exempt(cx, ID) {
        return r;
    }
    let (targets, cfs) = rows(cx);
    let mut rep = CheckReport::new(ID, targets.len() + cfs.len());
    for (e, t) in &targets {
        target(cx, rules, e, t, &mut rep);
    }
    for cf in cfs {
        cf_row(cx, rules, cf, &mut rep);
    }
    rep.finish()
}

fn target(
    cx: &Context<'_>,
    rules: &BranchRules,
    e: &Expectation,
    t: &Target,
    rep: &mut CheckReport,
) {
    let row = format!("{}/{}", e.id, t.fact);
    let line = t.fields.line;
    let mut note = Vec::new();
    for d in component_statuses(cx.case, rules, e, t) {
        let authored = if e.kind == ExpectationType::D {
            t.fields
                .str(&format!("{}_status", d.component))
                .and_then(Status::parse)
        } else {
            None
        };
        // An X component is not asserted: what it reads is not claimed.
        if authored == Some(Status::X) {
            note.push(format!("{}=X", d.component));
            continue;
        }
        for why in d.unanchored() {
            rep.fail(
                EXPECTATIONS_FILE,
                line,
                &row,
                format!(
                    "{}: an unanchored attribute without a status: {why}",
                    d.component
                ),
            );
        }
        let Some(derived) = &d.status else {
            continue;
        };
        if let Some(authored) = &authored {
            let ok = match authored {
                Status::Rel(cov) => d.covariates.contains(cov),
                _ => same_status(authored, derived),
            };
            if !ok {
                let why = match authored {
                    Status::Rel(cov) => format!("no rule it reads selects by {cov}"),
                    _ => format!("its inputs derive {}", spell(derived)),
                };
                rep.fail(
                    EXPECTATIONS_FILE,
                    line,
                    &row,
                    format!(
                        "the authored status differs from the derived one: {}_status = \"{}\", but {why} (reads: {})",
                        d.component,
                        spell(authored),
                        d.note()
                    ),
                );
            }
            note.push(format!("{}={}", d.component, spell(authored)));
        } else {
            note.push(format!("{}={}", d.component, spell(derived)));
        }
    }
    if t.fields.strs("branch_attrs").is_some_and(|a| !a.is_empty())
        && let Err(err) = branch::enumerate_with(rules, cx.case, e, t)
    {
        rep.fail(EXPECTATIONS_FILE, err.line.or(line), &row, err.detail);
    }
    record_consistency(cx, rules, e, t, rep);
    rep.examined(format!("{row} {}", note.join(" ")));
}

/// The indexes of `branch_attrs` whose rule for the expectation's reader
/// branches per-leg residues.
fn residue_slots(rules: &BranchRules, e: &Expectation, t: &Target) -> Vec<usize> {
    let procedure = e.fields.str("procedure");
    let version = e.fields.int("version");
    t.fields
        .strs("branch_attrs")
        .unwrap_or(&[])
        .iter()
        .enumerate()
        .filter(|(_, a)| {
            rules.rules.iter().any(|r| {
                r.attribute.as_str() == a.as_str()
                    && matches!(r.class_rule, ClassRule::ResidueMod { .. })
                    && matches!(&r.reader, branch::Reader::Procedure { id, version: v }
                        if procedure == Some(id.as_str()) && version == Some(*v))
            })
        })
        .map(|(i, _)| i)
        .collect()
}

/// A record-consistent cell may not contradict a sourced constraint.
fn record_consistency(
    cx: &Context<'_>,
    rules: &BranchRules,
    e: &Expectation,
    t: &Target,
    rep: &mut CheckReport,
) {
    let Some(set) = cx.case.expectations.as_ref() else {
        return;
    };
    let round_dollar: Vec<&String> = t
        .fields
        .strs("constraints")
        .unwrap_or(&[])
        .iter()
        .filter(|c| c.split_once(':').map(|(r, _)| r) == Some(ROUND_DOLLAR))
        .collect();
    if round_dollar.is_empty() {
        return;
    }
    let slots = residue_slots(rules, e, t);
    for cell in set
        .branch_cells
        .iter()
        .filter(|c| c.expectation == e.id && c.target == t.fact)
        .filter(|c| c.fields.bool("record_consistent") == Some(true))
    {
        let non_multiple = slots
            .iter()
            .filter_map(|i| cell.cell.get(*i))
            .any(|letters| letters.contains('n'));
        if non_multiple {
            rep.fail(
                EXPECTATIONS_FILE,
                cell.fields.line,
                &format!("{}/{}", e.id, t.fact),
                format!(
                    "branch cell [{}] has a non-multiple leg, which contradicts the sourced constraint `{}`, but is marked record_consistent = true (mark it false: it is evaluated, never summarized)",
                    cell.cell.join(", "),
                    round_dollar[0]
                ),
            );
        }
    }
}

/// A CF row changes one attribute its parent's components read.
fn cf_row(cx: &Context<'_>, rules: &BranchRules, cf: &Expectation, rep: &mut CheckReport) {
    let Some(set) = cx.case.expectations.as_ref() else {
        return;
    };
    let row = cf.id.clone();
    let (Some(parent), Some(changed)) = (
        cf.fields.str("parent").and_then(|p| set.get(p)),
        cf.fields.str("changed_attribute"),
    ) else {
        // A1c refuses a CF without its parent or attribute at load.
        rep.examined(row);
        return;
    };
    let read: BTreeSet<&'static str> = set
        .targets_of(&parent.id)
        .flat_map(|t| component_statuses(cx.case, rules, parent, t))
        .flat_map(|d| d.reads.into_iter().map(|r| r.attribute.as_str()))
        .collect();
    if BranchAttribute::parse(changed).is_some() && !read.contains(changed) {
        rep.fail(
            EXPECTATIONS_FILE,
            cf.fields.line,
            &row,
            format!(
                "a CF changes an attribute its parent reads: `{changed}` is not read by {} (it reads [{}])",
                parent.id,
                read.into_iter().collect::<Vec<_>>().join(", ")
            ),
        );
    }
    rep.examined(format!("{row} changes {changed}"));
}
