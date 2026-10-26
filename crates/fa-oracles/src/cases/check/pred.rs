//! K-PRED (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.6 rules 2-4; bead
//! fa-yugf.13, A5b): a constraint or a default may not decide the claimed
//! predicate.
//!
//! - **R-QUAL (rule 3).** A target's `constraints` entry
//!   `<interpretive rule>:<fact>` is admitted only if the rule is an
//!   interpretive rule of A2's derivation table, the fact is sourced, its
//!   `about_scope` covers the target's reporting period, and the target
//!   lists no documented exception (`exceptions`).
//! - **Collapse (rule 4).** For a residue predicate (`jet.round_amounts`:
//!   residue 0 versus ≠ 0 modulo 10^round_power units) the branch domain
//!   must keep a feasible representative of every class the literal sourced
//!   values allow. A `round_dollar_lower_bound` constraint forces every
//!   branched leg to a multiple of 10^3 units; if that removes every
//!   non-multiple cell, the row restates the source's characterization: it
//!   passes only as `D.restates_characterization`, and `D.detection` is
//!   refused.
//! - **Defaults (rule 2).** A declared default makes a component single only
//!   if the component's value is the same in every feasible cell of the
//!   defaulted attribute's branch classes. Computed over A5a's enumeration
//!   with the attribute branched, under `jet.round_amounts`' own cell model
//!   (`crates/fa-lantern/src/jet.rs:126-138`: it cites the entry and every
//!   round leg, counts them, and is Medium only when every leg is round),
//!   the only residue reader in the rules table.

use std::collections::BTreeSet;

use super::{CheckReport, Context};
use crate::cases::EXPECTATIONS_FILE;
use crate::cases::book::{BookVariant, BranchAttribute};
use crate::cases::branch::{self, BranchRules, CellPart, ClassRule, Enumeration, Reader};
use crate::cases::expect::{Expectation, ExpectationType, Field, Status, Target};
use crate::cases::fact::Provenance;
use crate::cases::scope::{Scope, Span, parse_scope};
use crate::cases::status::{Anchor, component_statuses, intents_named};

pub const ID: &str = "K-PRED";

/// The template a characterization restated renders as (A1c).
pub const RESTATES: &str = "D.restates_characterization";

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

#[must_use]
pub fn check_with(cx: &Context<'_>, rules: &BranchRules) -> CheckReport {
    if let Some(r) = super::branch::selftest_exempt(cx, ID) {
        return r;
    }
    let Some(set) = cx.case.expectations.as_ref() else {
        return CheckReport::new(ID, 0).finish();
    };
    let ds: Vec<(&Expectation, &Target)> = set
        .expectations
        .iter()
        .filter(|e| e.kind == ExpectationType::D)
        .flat_map(|e| set.targets_of(&e.id).map(move |t| (e, t)))
        .collect();
    let mut rep = CheckReport::new(ID, ds.len());
    for (e, t) in ds {
        let row = format!("{}/{}", e.id, t.fact);
        r_qual(cx, t, &row, &mut rep);
        collapse(cx, rules, e, t, &row, &mut rep);
        defaults(cx, rules, e, t, &row, &mut rep);
        rep.examined(row);
    }
    rep.finish()
}

/// The days a scope covers, resolving `entry:<fact>` to that fact's scope.
fn span_of(cx: &Context<'_>, about: &str, depth: usize) -> Option<Span> {
    match parse_scope(about).ok()? {
        Scope::Period(_, span) => Some(span),
        Scope::Scheme(_, range) => range.map(|(_, span)| span),
        Scope::Entry(fact) if depth < 4 => {
            let f = cx.case.facts.iter().find(|f| f.id == fact)?;
            span_of(cx, f.sourced()?.about_scope.as_str(), depth + 1)
        }
        Scope::Entry(_) | Scope::Account(_) => None,
    }
}

/// R-QUAL's admission of each `constraints` entry.
fn r_qual(cx: &Context<'_>, t: &Target, row: &str, rep: &mut CheckReport) {
    let constraints = t.fields.strs("constraints").unwrap_or(&[]);
    if constraints.is_empty() {
        return;
    }
    let line = t.fields.line;
    let exceptions = t.fields.strs("exceptions").unwrap_or(&[]);
    let target_span = cx
        .case
        .facts
        .iter()
        .find(|f| f.id == t.fact)
        .and_then(|f| f.sourced())
        .and_then(|s| span_of(cx, &s.about_scope, 0));
    for c in constraints {
        let Some((rule, fact)) = c.split_once(':') else {
            rep.fail(
                EXPECTATIONS_FILE,
                line,
                row,
                format!("constraint `{c}` is <interpretive rule>:<fact>"),
            );
            continue;
        };
        match cx.rules.as_ref().map(|r| r.get(rule).map(|x| x.interpretive)) {
            Ok(Some(true)) => {}
            Ok(Some(false)) => rep.fail(EXPECTATIONS_FILE, line, row, format!("constraint `{c}`: `{rule}` is not an interpretive rule (R-QUAL constrains through a declared interpretive rule anchored on the source's usage)")),
            Ok(None) => rep.fail(EXPECTATIONS_FILE, line, row, format!("constraint `{c}`: `{rule}` is not a rule of the derivation table")),
            Err(why) => rep.fail(EXPECTATIONS_FILE, line, row, format!("constraint `{c}`: the derivation table does not load: {why}")),
        }
        let source = cx.case.facts.iter().find(|f| f.id == fact);
        let Some(sourced) = source.and_then(|f| f.sourced()) else {
            rep.fail(EXPECTATIONS_FILE, line, row, format!("constraint `{c}`: `{fact}` is not a sourced fact (a qualitative fact constrains only as sourced text)"));
            continue;
        };
        if !exceptions.is_empty() {
            rep.fail(
                EXPECTATIONS_FILE,
                line,
                row,
                format!(
                    "R-QUAL on a target with a documented exception ({}): `{c}` does not cover {} (§2.6 rule 3)",
                    exceptions.join(", "),
                    t.fact
                ),
            );
        }
        let covers = match (span_of(cx, &sourced.about_scope, 0), target_span) {
            (Some(c), Some(t)) => c.first <= t.first && t.last <= c.last,
            _ => false,
        };
        if !covers {
            rep.fail(
                EXPECTATIONS_FILE,
                line,
                row,
                format!(
                    "constraint `{c}`: {fact}'s scope `{}` does not cover {}'s reporting period",
                    sourced.about_scope, t.fact
                ),
            );
        }
        if let Some(exc) = exceptions.iter().find(|x| {
            !cx.case
                .facts
                .iter()
                .any(|f| f.id == **x && matches!(f.provenance, Provenance::Sourced(_)))
        }) {
            rep.fail(
                EXPECTATIONS_FILE,
                line,
                row,
                format!("exception `{exc}` is not a sourced fact"),
            );
        }
    }
}

/// The residue rule of the expectation's reader over `attribute`, if any.
fn residue_rule<'r>(
    rules: &'r BranchRules,
    e: &Expectation,
    attribute: &str,
) -> Option<&'r branch::BranchRule> {
    let procedure = e.fields.str("procedure")?;
    let version = e.fields.int("version")?;
    rules.rules.iter().find(|r| {
        r.attribute.as_str() == attribute
            && matches!(r.class_rule, ClassRule::ResidueMod { .. })
            && matches!(&r.reader, Reader::Procedure { id, version: v } if id == procedure && *v == version)
    })
}

/// One cell's per-leg letters (`mnm`) and the branched legs' ordinals.
type LegCell = (String, Vec<i128>);

/// The per-leg letters of each cell, with the branched ordinals.
fn leg_cells(en: &Enumeration) -> Vec<LegCell> {
    en.cells
        .iter()
        .filter_map(|c| {
            c.parts.iter().find_map(|p| match p {
                CellPart::Legs {
                    letters, ordinals, ..
                } => Some((letters.clone(), ordinals.clone())),
                _ => None,
            })
        })
        .collect()
}

/// A round_dollar constraint that leaves no non-multiple cell.
fn collapse(
    cx: &Context<'_>,
    rules: &BranchRules,
    e: &Expectation,
    t: &Target,
    row: &str,
    rep: &mut CheckReport,
) {
    let constrained = t
        .fields
        .strs("constraints")
        .unwrap_or(&[])
        .iter()
        .find(|c| c.split_once(':').map(|(r, _)| r) == Some(super::branch::ROUND_DOLLAR));
    let Some(constraint) = constrained else {
        return;
    };
    for attr in t.fields.strs("branch_attrs").unwrap_or(&[]) {
        let Some(rule) = residue_rule(rules, e, attr) else {
            continue;
        };
        let ClassRule::ResidueMod { power } = rule.class_rule else {
            continue;
        };
        // A multiple of 10^3 units is a multiple of 10^power units only when
        // power <= 3; above it the constraint forces nothing.
        if power > 3 {
            continue;
        }
        let Ok(en) = branch::enumerate_with(rules, cx.case, e, t) else {
            continue;
        };
        let cells = leg_cells(&en);
        let before = cells.iter().any(|(l, _)| l.contains('n'));
        let after: Vec<&str> = cells
            .iter()
            .filter(|(l, _)| !l.contains('n'))
            .map(|(l, _)| l.as_str())
            .collect();
        if before && e.fields.str("statement_template") != Some(RESTATES) {
            rep.fail(
                EXPECTATIONS_FILE,
                t.fields.line,
                row,
                format!(
                    "constraint `{constraint}` collapses residue≠0: of the feasible cells only [{}] remain, all multiples, so the row restates the source's characterization ({RESTATES}), never D.detection",
                    after.join(", ")
                ),
            );
        }
    }
}

/// Whether a single component's value differs across the cells, under
/// jet.round_amounts' model: `round` legs outside the branch (always round,
/// or not), the cited ordinals, and the legs' count.
fn varies(
    component: &str,
    cells: &[LegCell],
    unbranched_all_round: bool,
    cited: &BTreeSet<i128>,
) -> bool {
    let distinct = |f: &dyn Fn(&LegCell) -> String| -> bool {
        cells.iter().map(f).collect::<BTreeSet<_>>().len() > 1
    };
    match component {
        "statistic" => distinct(&|(l, _)| l.matches('m').count().to_string()),
        "severity" => unbranched_all_round && distinct(&|(l, _)| (!l.contains('n')).to_string()),
        "cite" => distinct(&|(l, ords)| {
            ords.iter()
                .zip(l.chars())
                .filter(|(o, _)| cited.contains(o))
                .map(|(o, c)| format!("{o}{c}"))
                .collect::<String>()
        }),
        _ => false,
    }
}

/// Whether every leg of the target outside the branch is a whole multiple
/// of 10^power units.
fn unbranched_round(book: &BookVariant, t: &Target, branched: &[i128], power: u32) -> bool {
    let scales: Vec<(String, u8)> = fa_registry::units_embedded()
        .map(|units| units.into_iter().map(|u| (u.code, u.scale)).collect())
        .unwrap_or_default();
    let ids: Vec<&str> = intents_named(book, &t.fact)
        .iter()
        .map(|i| i.id.as_str())
        .collect();
    book.legs
        .iter()
        .filter(|l| ids.contains(&l.intent.as_str()) && !branched.contains(&l.ordinal))
        .all(|l| {
            let Some(scale) = scales.iter().find(|(c, _)| *c == l.unit).map(|(_, s)| *s) else {
                return false;
            };
            let Ok(minor) = crate::cases::amount::parse_amount(&l.amount_literal, scale) else {
                return false;
            };
            let modulus = 10i128.checked_pow(power + u32::from(scale));
            modulus.is_some_and(|m| minor != 0 && minor % m == 0)
        })
}

/// A declared default may not decide a single component.
fn defaults(
    cx: &Context<'_>,
    rules: &BranchRules,
    e: &Expectation,
    t: &Target,
    row: &str,
    rep: &mut CheckReport,
) {
    let Some(book) = e
        .fields
        .str("book_variant")
        .and_then(|v| cx.case.books.get(v))
    else {
        return;
    };
    let branched = t.fields.strs("branch_attrs").unwrap_or(&[]);
    for d in component_statuses(cx.case, rules, e, t) {
        let authored = t
            .fields
            .str(&format!("{}_status", d.component))
            .and_then(Status::parse);
        if !matches!(authored, Some(Status::S | Status::Sd | Status::Si)) {
            continue;
        }
        // The defaulted per-leg attributes this component reads through a
        // branch leg the target does not branch.
        let mut defaulted: Vec<BranchAttribute> = Vec::new();
        for r in &d.reads {
            let Some(leg) = &r.leg else { continue };
            let Some((intent, ord)) = leg.rsplit_once('#') else {
                continue;
            };
            let class_attr = book
                .legs
                .iter()
                .find(|l| l.intent == intent && l.ordinal.to_string() == ord)
                .and_then(|l| l.amount_rule.strip_prefix("branch:"))
                .and_then(|class| book.branch_classes.iter().find(|b| b.id == class))
                .and_then(|b| BranchAttribute::parse(&b.attribute));
            if let Some(a) = class_attr
                && r.anchor == Anchor::Declared
                && !branched.iter().any(|x| x == a.as_str())
                && !defaulted.contains(&a)
            {
                defaulted.push(a);
            }
        }
        for a in defaulted {
            let Some(rule) = residue_rule(rules, e, a.as_str()) else {
                continue;
            };
            let ClassRule::ResidueMod { power } = rule.class_rule else {
                continue;
            };
            // The table with the defaulted attribute branched: every cell
            // its classes and the balance law allow.
            let mut as_branched = t.clone();
            let mut attrs: Vec<String> = branched.to_vec();
            attrs.push(a.as_str().to_string());
            as_branched
                .fields
                .map
                .insert("branch_attrs".into(), Field::Strs(attrs));
            for k in ["cite_status", "severity_status", "statistic_status"] {
                as_branched
                    .fields
                    .map
                    .insert(k.into(), Field::Str(format!("B({})", a.as_str())));
            }
            let Ok(en) = branch::enumerate_with(rules, cx.case, e, &as_branched) else {
                continue;
            };
            let cells = leg_cells(&en);
            let ords: Vec<i128> = cells.first().map(|(_, o)| o.clone()).unwrap_or_default();
            let cited: BTreeSet<i128> = t
                .fields
                .strs("cite")
                .unwrap_or(&[])
                .iter()
                .filter_map(|c| c.split_once('#').and_then(|(_, o)| o.parse().ok()))
                .collect();
            let all_round = unbranched_round(book, t, &ords, power);
            if varies(d.component, &cells, all_round, &cited) {
                rep.fail(
                    EXPECTATIONS_FILE,
                    t.fields.line,
                    row,
                    format!(
                        "the default decides the predicate: {} is declared single, but under the [[default]] for {} its value differs across the feasible cells [{}]; branch it (B({})) instead",
                        d.component,
                        a.as_str(),
                        cells.iter().map(|(l, _)| l.as_str()).collect::<Vec<_>>().join(", "),
                        a.as_str()
                    ),
                );
            }
        }
    }
}
