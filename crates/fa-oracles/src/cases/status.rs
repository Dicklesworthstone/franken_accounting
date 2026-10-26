//! Component statuses and the row-level D rules
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.6 rules 1-4 and 7-9, §5.2; bead
//! fa-yugf.13, A5b).
//!
//! `closed_cites` (A5b's row-level rule). A D compares per target, so a
//! finding that cites an entry none of its targets names is invisible to the
//! per-target evaluation. A D expectation with `closed_cites = true` states
//! that its targets are every documented or Δ entry its run's findings cite:
//! after the per-target evaluation, every cited intent whose fact is sourced
//! or an interpretation, or that is a case Δ (`restates`/`revises`), and that
//! no target names, fails the row on a line of its own. Filler and other
//! synthetic intents are never in scope (A11a's filler witness covers them).
//! The default is false: a D that claims findings on some entries claims
//! nothing about the others.
//!
//! **Derived statuses (§2.6 rule 1).** A component reads exactly the branch
//! rules (`data/case_branch_rules.toml`) whose reader is its procedure@version
//! (a kernel step, for a P's refusal and law row) and whose `components`
//! list it. Each input it reads is anchored for the target:
//! - a per-leg input (`leg_split`, `amount_precision`) by the legs the rule
//!   reads (`legs`; a cite reads only the legs it names): a leg's
//!   `amount_rule` is a sourced, interpreted or derived value, or a
//!   `branch:<class>` leg, branched when the target lists the class's
//!   attribute in `branch_attrs` and declared when the book declares a
//!   default for it. `leg_split` also needs the split itself declared (a
//!   `[[default]]`) or branched;
//! - an entry-level input by `branch_attrs` or a `[[default]]`.
//!
//! An input none of these anchors has no status (K-BRANCH). A component
//! with a branched input is `B(<those attributes>)`; otherwise `Si` if an
//! input is interpreted, `Sd` if one is declared, and `S`. A component a
//! covariate rule moves (`covariate`) may also be authored
//! `Rel(<covariate>)`. Whether a declared default decides the predicate is
//! K-PRED's question, not the derivation's.

use std::collections::BTreeSet;

use super::Case;
use super::book::{BookVariant, BranchAttribute, IntentDef, LegDef};
use super::branch::{BranchRule, BranchRules, ClassRule, D_COMPONENTS, P_COMPONENTS, Reader};
use super::expect::{Expectation, ExpectationType, Projection, Status, Target};
use super::fact::{Provenance, ProvenanceKind};

/// Whether `expectation` declares `closed_cites = true`.
#[must_use]
pub fn closed_cites(expectation: &Expectation) -> bool {
    expectation.fields.bool("closed_cites") == Some(true)
}

/// The intents of `cited` (the intent ids the expectation's run's findings
/// cite, as the runner maps them) that a `closed_cites` D did not expect:
/// documented (sourced or interpretation fact) or Δ intents of its book
/// variant that none of its targets names. Empty when the expectation does
/// not declare `closed_cites`.
#[must_use]
pub fn unexpected_cites(
    case: &Case,
    expectation: &Expectation,
    cited: &BTreeSet<String>,
) -> Vec<String> {
    if !closed_cites(expectation) {
        return Vec::new();
    }
    let Some(set) = case.expectations.as_ref() else {
        return Vec::new();
    };
    let Some(book) = expectation
        .fields
        .str("book_variant")
        .and_then(|v| case.books.get(v))
    else {
        return Vec::new();
    };
    let named: BTreeSet<&str> = set
        .targets_of(&expectation.id)
        .map(|t| t.fact.as_str())
        .collect();
    let documented = |fact: &str| {
        case.facts.iter().any(|f| {
            f.id == fact
                && matches!(
                    f.provenance.kind(),
                    ProvenanceKind::Sourced | ProvenanceKind::Interpretation
                )
        })
    };
    book.intents
        .iter()
        .filter(|i| cited.contains(&i.id))
        .filter(|i| documented(&i.fact) || i.is_delta())
        .filter(|i| !named.contains(i.id.as_str()) && !named.contains(i.fact.as_str()))
        .map(|i| i.id.clone())
        .collect()
}

/// How one input a component reads is anchored for a target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// Stated by a sourced fact.
    Sourced,
    /// A declared default (`[[default]]`) or a derived rule.
    Declared,
    /// A named interpretation.
    Interpreted,
    /// A branch class over this attribute the target lists in
    /// `branch_attrs`.
    Branched(BranchAttribute),
    /// None of these: why.
    Unanchored(String),
}

/// One component's status as its inputs derive it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    pub component: &'static str,
    /// `None` when an input is unanchored.
    pub status: Option<Status>,
    /// Each input read, with the rule that reads it and its anchor.
    pub reads: Vec<Read>,
    /// The covariates a rule it reads selects by: `Rel(<covariate>)` is
    /// admissible.
    pub covariates: Vec<String>,
}

/// One input a component reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Read {
    pub attribute: BranchAttribute,
    pub rule: String,
    /// The leg (`<intent>#<ordinal>`), for a per-leg input.
    pub leg: Option<String>,
    pub anchor: Anchor,
}

impl Derived {
    /// Why each unanchored input has no status.
    #[must_use]
    pub fn unanchored(&self) -> Vec<String> {
        self.reads
            .iter()
            .filter_map(|r| match &r.anchor {
                Anchor::Unanchored(why) => Some(why.clone()),
                _ => None,
            })
            .collect()
    }

    /// The reads, as a log note: `leg_split[F4#0]=sourced, ...`.
    #[must_use]
    pub fn note(&self) -> String {
        self.reads
            .iter()
            .map(|r| {
                let anchor = match &r.anchor {
                    Anchor::Sourced => "sourced".to_string(),
                    Anchor::Declared => "declared".to_string(),
                    Anchor::Interpreted => "interpreted".to_string(),
                    Anchor::Branched(a) => format!("branched({})", a.as_str()),
                    Anchor::Unanchored(_) => "unanchored".to_string(),
                };
                let leg = r
                    .leg
                    .as_ref()
                    .map_or_else(String::new, |l| format!("[{l}]"));
                format!("{}{leg}={anchor}", r.attribute.as_str())
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// Whether two statuses are the same, a B's attributes as a set.
#[must_use]
pub fn same_status(a: &Status, b: &Status) -> bool {
    match (a, b) {
        (Status::B(x), Status::B(y)) => {
            let x: BTreeSet<&str> = x.iter().map(|a| a.as_str()).collect();
            let y: BTreeSet<&str> = y.iter().map(|a| a.as_str()).collect();
            x == y
        }
        _ => a == b,
    }
}

/// A status as `*_status` spells it.
#[must_use]
pub fn spell(status: &Status) -> String {
    match status {
        Status::S => "S".into(),
        Status::Sd => "Sd".into(),
        Status::Si => "Si".into(),
        Status::X => "X".into(),
        Status::Rel(c) => format!("Rel({c})"),
        Status::B(attrs) => format!(
            "B({})",
            attrs
                .iter()
                .map(|a| a.as_str())
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// The book variant an expectation runs on.
fn book_of<'c>(case: &'c Case, expectation: &Expectation) -> Option<&'c BookVariant> {
    expectation
        .fields
        .str("book_variant")
        .and_then(|v| case.books.get(v))
}

/// The intents a target (or a cite subject) names: the intent with that
/// id, else every intent of that fact.
#[must_use]
pub fn intents_named<'b>(book: &'b BookVariant, subject: &str) -> Vec<&'b IntentDef> {
    let by_id: Vec<&IntentDef> = book.intents.iter().filter(|i| i.id == subject).collect();
    if by_id.is_empty() {
        book.intents.iter().filter(|i| i.fact == subject).collect()
    } else {
        by_id
    }
}

fn has_default(book: &BookVariant, attribute: BranchAttribute) -> bool {
    book.defaults
        .iter()
        .any(|d| d.attribute == attribute.as_str())
}

/// A leg's amount anchor (A1b's `amount_rule`).
fn leg_anchor(
    case: &Case,
    book: &BookVariant,
    branched: &[BranchAttribute],
    leg: &LegDef,
) -> Anchor {
    let rule = leg.amount_rule.as_str();
    let at = format!("{}#{}", leg.intent, leg.ordinal);
    if let Some(class) = rule.strip_prefix("branch:") {
        let Some(attr) = book
            .branch_classes
            .iter()
            .find(|b| b.id == class)
            .and_then(|b| BranchAttribute::parse(&b.attribute))
        else {
            return Anchor::Unanchored(format!(
                "leg {at}: branch class `{class}` resolves to no attribute"
            ));
        };
        return if branched.contains(&attr) {
            Anchor::Branched(attr)
        } else if has_default(book, attr) {
            Anchor::Declared
        } else {
            Anchor::Unanchored(format!(
                "leg {at} is branched by `{class}` ({}), which the target does not list in branch_attrs and the book does not default",
                attr.as_str()
            ))
        };
    }
    if rule.starts_with("derived:") {
        return Anchor::Declared;
    }
    if let Some(rest) = rule.strip_prefix("value:") {
        let fact = rest.split_once('#').map_or(rest, |(f, _)| f);
        return match case
            .facts
            .iter()
            .find(|f| f.id == fact)
            .map(|f| &f.provenance)
        {
            Some(Provenance::Sourced(_)) => Anchor::Sourced,
            Some(Provenance::Interpretation(_)) => Anchor::Interpreted,
            Some(Provenance::Derived(_)) => Anchor::Declared,
            Some(Provenance::Synthetic(_)) | None => Anchor::Unanchored(format!(
                "leg {at}: `{rule}` names no sourced, derived or interpreted fact"
            )),
        };
    }
    Anchor::Unanchored(format!("leg {at} has a synthetic amount"))
}

/// The legs a component reads under `rule`: for a cite that names legs,
/// those legs; otherwise the target's legs the rule's selector reads.
fn legs_read<'b>(
    book: &'b BookVariant,
    target: &Target,
    rule: &BranchRule,
    component: &str,
) -> Vec<&'b LegDef> {
    let role = |code: &str| {
        book.accounts
            .iter()
            .find(|a| a.code == code)
            .and_then(|a| a.role.as_deref())
            .filter(|r| !r.is_empty())
    };
    if component == "cite" {
        let cited: Vec<(String, i128)> = target
            .fields
            .strs("cite")
            .unwrap_or(&[])
            .iter()
            .filter_map(|c| {
                let (subject, ord) = c.split_once('#')?;
                Some((subject.to_string(), ord.parse().ok()?))
            })
            .collect();
        if !cited.is_empty() {
            return cited
                .iter()
                .flat_map(|(subject, ord)| {
                    let ids: Vec<&str> = intents_named(book, subject)
                        .iter()
                        .map(|i| i.id.as_str())
                        .collect();
                    book.legs
                        .iter()
                        .filter(move |l| ids.contains(&l.intent.as_str()) && l.ordinal == *ord)
                })
                .collect();
        }
    }
    let ids: Vec<&str> = intents_named(book, &target.fact)
        .iter()
        .map(|i| i.id.as_str())
        .collect();
    book.legs
        .iter()
        .filter(|l| ids.contains(&l.intent.as_str()))
        .filter(|l| rule.legs.reads(&l.side, role(&l.account)))
        .collect()
}

/// Combines a component's anchors into its status.
fn combine(reads: &[Read]) -> Option<Status> {
    if reads
        .iter()
        .any(|r| matches!(r.anchor, Anchor::Unanchored(_)))
    {
        return None;
    }
    let mut branched: Vec<BranchAttribute> = Vec::new();
    for r in reads {
        if let Anchor::Branched(a) = &r.anchor
            && !branched.contains(a)
        {
            branched.push(*a);
        }
    }
    if !branched.is_empty() {
        branched.sort_by_key(|a| a.as_str());
        return Some(Status::B(branched));
    }
    if reads.iter().any(|r| r.anchor == Anchor::Interpreted) {
        Some(Status::Si)
    } else if reads.iter().any(|r| r.anchor == Anchor::Declared) {
        Some(Status::Sd)
    } else {
        Some(Status::S)
    }
}

/// Whether `rule`'s reader is the expectation's: its procedure@version for
/// a D, any kernel step for a P.
fn reads_for(rule: &BranchRule, expectation: &Expectation) -> bool {
    match (&rule.reader, expectation.kind) {
        (Reader::Procedure { id, version }, ExpectationType::D) => {
            expectation.fields.str("procedure") == Some(id.as_str())
                && expectation.fields.int("version") == Some(*version)
        }
        (Reader::Kernel(_), ExpectationType::P) => true,
        _ => false,
    }
}

/// The derived status of each component of a D target (`cite`,
/// `severity`, `statistic`) or a P target (`refusal`, `law_row`), from the
/// inputs it reads (§2.6 rules 1-2). Other expectation types have none.
#[must_use]
pub fn component_statuses(
    case: &Case,
    rules: &BranchRules,
    expectation: &Expectation,
    target: &Target,
) -> Vec<Derived> {
    let components: &[&'static str] = match expectation.kind {
        ExpectationType::D => &D_COMPONENTS,
        ExpectationType::P => &P_COMPONENTS,
        _ => return Vec::new(),
    };
    let Some(book) = book_of(case, expectation) else {
        return Vec::new();
    };
    let branched: Vec<BranchAttribute> = target
        .fields
        .strs("branch_attrs")
        .unwrap_or(&[])
        .iter()
        .filter_map(|a| BranchAttribute::parse(a))
        .collect();
    let mut out = Vec::new();
    for &component in components {
        let mut reads = Vec::new();
        let mut covariates = Vec::new();
        for rule in rules
            .rules
            .iter()
            .filter(|r| reads_for(r, expectation) && r.components.iter().any(|c| c == component))
        {
            if let Some(c) = &rule.covariate
                && !covariates.contains(c)
            {
                covariates.push(c.clone());
            }
            let a = rule.attribute;
            let read = |leg: Option<String>, anchor: Anchor| Read {
                attribute: a,
                rule: rule.id.clone(),
                leg,
                anchor,
            };
            let per_leg = matches!(
                a,
                BranchAttribute::LegSplit | BranchAttribute::AmountPrecision
            );
            let residue = matches!(rule.class_rule, ClassRule::ResidueMod { .. });
            if branched.contains(&a) && !(per_leg && residue) {
                // An entry-level branch: the class is the attribute's value.
                reads.push(read(None, Anchor::Branched(a)));
                continue;
            }
            if !per_leg {
                let anchor = if has_default(book, a) {
                    Anchor::Declared
                } else {
                    Anchor::Unanchored(format!(
                        "{} is read by rule `{}` and is neither branched (branch_attrs) nor declared ([[default]]) for {}",
                        a.as_str(),
                        rule.id,
                        target.fact
                    ))
                };
                reads.push(read(None, anchor));
                continue;
            }
            for leg in legs_read(book, target, rule, component) {
                let at = format!("{}#{}", leg.intent, leg.ordinal);
                reads.push(read(Some(at), leg_anchor(case, book, &branched, leg)));
            }
            if a == BranchAttribute::LegSplit {
                // The split itself: how many legs per (account, side).
                let anchor = if has_default(book, a) {
                    Anchor::Declared
                } else if branched.contains(&a) {
                    Anchor::Branched(a)
                } else {
                    Anchor::Unanchored(format!(
                        "leg_split of {} (legs per account and side) is read by rule `{}` and is neither branched nor declared",
                        target.fact, rule.id
                    ))
                };
                reads.push(read(None, anchor));
            }
        }
        out.push(Derived {
            component,
            status: combine(&reads),
            reads,
            covariates,
        });
    }
    out
}

/// One `STATUS` log line per D and P target (A5b, §16 logging): each
/// component's status, the authored one for a D component that states one,
/// else the derived one (`none` when an input is unanchored, which K-BRANCH
/// refuses). A `harness_selftest` case has none: its synthetic stand-ins
/// anchor nothing (K-BRANCH is exempt there).
#[must_use]
pub fn status_lines(case: &Case, rules: &BranchRules) -> Vec<String> {
    if case.header.kind == super::header::CaseKind::HarnessSelftest {
        return Vec::new();
    }
    let Some(set) = case.expectations.as_ref() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in set
        .expectations
        .iter()
        .filter(|e| matches!(e.kind, ExpectationType::D | ExpectationType::P))
    {
        for t in set.targets_of(&e.id) {
            let parts: Vec<String> = component_statuses(case, rules, e, t)
                .iter()
                .map(|d| {
                    let authored = t
                        .fields
                        .str(&format!("{}_status", d.component))
                        .and_then(Status::parse);
                    let shown = authored
                        .as_ref()
                        .or(d.status.as_ref())
                        .map_or_else(|| "none".to_string(), spell);
                    format!("{}={shown}", d.component)
                })
                .collect();
            out.push(format!("STATUS {} {} {}", e.id, t.fact, parts.join(" ")));
        }
    }
    out
}

/// One run's finding for a D target, projected as §5.2 compares it (the
/// runner projects cites to `<intent>#<ordinal>` and account codes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservedD {
    pub cites: BTreeSet<String>,
    pub severity: String,
    pub statistic_name: String,
    pub statistic: String,
    pub scale: String,
}

/// A branch cell's authored values, projected like an observation; a value
/// the row does not state is `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CellWant {
    pub cites: Option<BTreeSet<String>>,
    pub severity: Option<String>,
    pub statistic: Option<String>,
}

/// One component's verdict on one cell of one run (§5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ComponentVerdict {
    /// Equal to its expectation (S, Sd, Si), its rule held (Rel), or equal
    /// to its cell's row (B).
    Pass(&'static str),
    /// The component, what it expected, what the run observed.
    Fail(&'static str, String, String),
    /// X: not asserted, never compared.
    NotAsserted(&'static str),
    /// A B component whose cell states no value for it: it waits.
    NoCellValue(&'static str),
    /// A Rel component the run could not judge (no account VIds).
    Unjudged(&'static str),
}

/// The row verdict of a cell's component verdicts: FAIL on any failure,
/// UNRUN when a component waits or is unjudged, PASS otherwise.
#[must_use]
pub fn row_verdict(verdicts: &[ComponentVerdict]) -> super::verdict::RowVerdict {
    use super::verdict::RowVerdict;
    if verdicts
        .iter()
        .any(|v| matches!(v, ComponentVerdict::Fail(..)))
    {
        RowVerdict::Fail
    } else if verdicts.iter().any(|v| {
        matches!(
            v,
            ComponentVerdict::NoCellValue(_) | ComponentVerdict::Unjudged(_)
        )
    }) {
        RowVerdict::Unrun
    } else {
        RowVerdict::Pass
    }
}

/// A cite set as a projection renders it (`-` when empty).
fn joined(set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        "-".into()
    } else {
        set.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

/// §5.2's D pass rule on one cell of one run: every S, Sd and Si component
/// equals its expectation and every Rel component's rule holds (`rel`,
/// judged by the runner from the run's account VIds; `None` when it cannot
/// judge), every B component equals its `[[branch_cell]]` row (`cell`), and
/// no X component is compared. `want_cites` is the target's cites projected
/// like the observation's.
#[must_use]
pub fn evaluate_d(
    projection: &Projection,
    want_cites: &BTreeSet<String>,
    observed: &ObservedD,
    cell: Option<&CellWant>,
    rel: &dyn Fn(&str) -> Option<bool>,
) -> Vec<ComponentVerdict> {
    let judge = |component: &'static str,
                 status: &Status,
                 want: Option<String>,
                 cell_want: Option<String>,
                 got: String| {
        match status {
            Status::X => ComponentVerdict::NotAsserted(component),
            Status::Rel(_) => match rel(component) {
                Some(true) => ComponentVerdict::Pass(component),
                Some(false) => ComponentVerdict::Fail(
                    component,
                    "its relational rule".into(),
                    format!("{got} (the rule does not hold on this run)"),
                ),
                None => ComponentVerdict::Unjudged(component),
            },
            Status::B(_) => match cell_want {
                None => ComponentVerdict::NoCellValue(component),
                Some(w) if w == got => ComponentVerdict::Pass(component),
                Some(w) => ComponentVerdict::Fail(component, w, got),
            },
            Status::S | Status::Sd | Status::Si => match want {
                Some(w) if w == got => ComponentVerdict::Pass(component),
                Some(w) => ComponentVerdict::Fail(component, w, got),
                None => ComponentVerdict::Fail(component, "-".into(), got),
            },
        }
    };
    let mut out = vec![judge(
        "cite",
        &projection.cite.status,
        Some(joined(want_cites)),
        cell.and_then(|c| c.cites.as_ref()).map(joined),
        joined(&observed.cites),
    )];
    out.push(judge(
        "severity",
        &projection.severity.status,
        projection.severity.value.clone(),
        cell.and_then(|c| c.severity.clone()),
        observed.severity.clone(),
    ));
    let mut statistic = judge(
        "statistic",
        &projection.statistic.status,
        projection.statistic.value.clone(),
        cell.and_then(|c| c.statistic.clone()),
        observed.statistic.clone(),
    );
    // A single statistic also names its statistic and scale, which fail as
    // `statistic_name` and `scale`.
    if matches!(
        projection.statistic.status,
        Status::S | Status::Sd | Status::Si
    ) && statistic == ComponentVerdict::Pass("statistic")
    {
        if let Some(name) = &projection.statistic_name
            && *name != observed.statistic_name
        {
            statistic = ComponentVerdict::Fail(
                "statistic_name",
                name.clone(),
                observed.statistic_name.clone(),
            );
        } else if let Some(scale) = projection.statistic_scale
            && scale.to_string() != observed.scale
        {
            statistic = ComponentVerdict::Fail("scale", scale.to_string(), observed.scale.clone());
        }
    }
    out.push(statistic);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::tests::pilot_planted;

    /// W-D-01 (targets F4 and F9) with `closed_cites` as given.
    fn w_d_01(closed: Option<bool>) -> Case {
        let anchor = "capabilities = [\"procedure:expense.capitalization@2\"]\nprocedure = \"expense.capitalization\"\nversion = 2\n";
        let with = closed.map_or_else(
            || anchor.to_string(),
            |c| format!("{anchor}closed_cites = {c}\n"),
        );
        pilot_planted(&[("expectations.toml", anchor, &with)])
    }

    fn component(status: &str, value: Option<&str>) -> crate::cases::expect::Component {
        crate::cases::expect::Component {
            status: Status::parse(status).expect("a status"),
            value: value.map(str::to_string),
        }
    }

    /// §5.2 per status on synthetic observations: single components equal
    /// their expectation, a Rel component passes when its rule holds whatever
    /// its value (two book ids, two values), a B component equals its cell
    /// row or waits without one, and an X component is never compared.
    #[test]
    fn evaluate_d_applies_the_section_5_2_pass_rule() {
        use crate::cases::verdict::RowVerdict;
        let p = Projection {
            procedure: "expense.capitalization".into(),
            version: 2,
            cite: component("Rel(account_vid_order)", None),
            severity: component("S", Some("High")),
            statistic_name: Some("capitalized_amount".into()),
            statistic: component("B(leg_split)", None),
            statistic_scale: Some(2),
        };
        let want = cited(&["F9#0"]);
        let obs = |cite: &str, stat: &str| ObservedD {
            cites: cited(&[cite]),
            severity: "High".into(),
            statistic_name: "capitalized_amount".into(),
            statistic: stat.into(),
            scale: "2".into(),
        };
        let cell = CellWant {
            cites: None,
            severity: None,
            statistic: Some("30000000000".into()),
        };
        let holds = |_: &str| Some(true);
        // Two runs (two book ids) cite different fixed-asset accounts and
        // capitalize different legs; the rule holds on both: PASS.
        for (cite, stat) in [("1500", "30000000000"), ("1510", "30000000000")] {
            let v = evaluate_d(&p, &want, &obs(cite, stat), Some(&cell), &holds);
            assert_eq!(row_verdict(&v), RowVerdict::Pass, "{v:?}");
        }
        // The rule fails on a run: FAIL naming the cite.
        let fails = |_: &str| Some(false);
        let v = evaluate_d(&p, &want, &obs("1500", "30000000000"), Some(&cell), &fails);
        assert!(matches!(v[0], ComponentVerdict::Fail("cite", ..)), "{v:?}");
        // No VIds to judge it: UNRUN.
        let none = |_: &str| None;
        let v = evaluate_d(&p, &want, &obs("1500", "30000000000"), Some(&cell), &none);
        assert_eq!(v[0], ComponentVerdict::Unjudged("cite"));
        assert_eq!(row_verdict(&v), RowVerdict::Unrun);
        // The B statistic differs from its cell row: FAIL; without a row
        // value it waits.
        let v = evaluate_d(&p, &want, &obs("1500", "1"), Some(&cell), &holds);
        assert_eq!(
            v[2],
            ComponentVerdict::Fail("statistic", "30000000000".into(), "1".into())
        );
        let v = evaluate_d(&p, &want, &obs("1500", "1"), None, &holds);
        assert_eq!(v[2], ComponentVerdict::NoCellValue("statistic"));
        // A single severity that differs fails; a single statistic checks
        // its name and scale; an X is never compared.
        let mut single = p.clone();
        single.cite = component("Sd", Some("F9#0"));
        single.statistic = component("Sd", Some("74272500000"));
        let mut o = obs("F9#0", "74272500000");
        assert_eq!(
            row_verdict(&evaluate_d(&single, &want, &o, None, &none)),
            RowVerdict::Pass
        );
        o.severity = "Low".into();
        assert_eq!(
            evaluate_d(&single, &want, &o, None, &none)[1],
            ComponentVerdict::Fail("severity", "High".into(), "Low".into())
        );
        o.severity = "High".into();
        o.scale = "0".into();
        assert_eq!(
            evaluate_d(&single, &want, &o, None, &none)[2],
            ComponentVerdict::Fail("scale", "2".into(), "0".into())
        );
        single.severity = component("X", None);
        o.scale = "2".into();
        o.severity = "anything".into();
        let v = evaluate_d(&single, &want, &o, None, &none);
        assert_eq!(v[1], ComponentVerdict::NotAsserted("severity"));
        assert_eq!(row_verdict(&v), RowVerdict::Pass);
    }

    /// The STATUS lines of the pilot (A5b's logging).
    #[test]
    fn status_lines_name_each_targets_component_statuses() {
        let case = pilot_planted(&[]);
        let rules = crate::cases::branch::rules().expect("rules");
        let lines = status_lines(&case, &rules);
        for want in [
            "STATUS W-D-01 F4 cite=Sd severity=S statistic=Sd",
            "STATUS W-D-01 F9 cite=Rel(account_vid_order) severity=S statistic=B(leg_split)",
            "STATUS W-D-03 F4 cite=Sd severity=B(leg_split) statistic=B(leg_split)",
            "STATUS W-P-02 F4 refusal=B(evidence_attached) law_row=B(evidence_attached)",
            "STATUS W-P-03 F4 refusal=B(entry_class,period_state_at_commit) law_row=B(entry_class,period_state_at_commit)",
        ] {
            assert!(
                lines.iter().any(|l| l == want),
                "{want}\n{}",
                lines.join("\n")
            );
        }
    }

    fn cited(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_string()).collect()
    }

    /// A5b's row-level rule on synthetic observations: a `closed_cites` D
    /// whose run also cites a documented entry (F12) and a Δ (delta-F4) no
    /// target names lists both; the same observations without the field list
    /// nothing; a cite of a non-documented intent is never in scope.
    #[test]
    fn unexpected_cite_fails_a_closed_cites_row() {
        let case = w_d_01(Some(true));
        let e = case.expectations.as_ref().unwrap().get("W-D-01").unwrap();
        assert!(closed_cites(e));
        let run = cited(&["F4", "F9", "F12", "delta-F4"]);
        assert_eq!(unexpected_cites(&case, e, &run), vec!["F12", "delta-F4"]);
        // Only the targets' own entries: nothing unexpected.
        assert!(unexpected_cites(&case, e, &cited(&["F4", "F9"])).is_empty());
        // An intent the book does not hold (a filler id) is never in scope.
        assert!(unexpected_cites(&case, e, &cited(&["F4", "filler-fv1-1-0"])).is_empty());
        for closed in [None, Some(false)] {
            let case = w_d_01(closed);
            let e = case.expectations.as_ref().unwrap().get("W-D-01").unwrap();
            assert!(!closed_cites(e));
            assert!(unexpected_cites(&case, e, &run).is_empty(), "{closed:?}");
        }
    }
}
