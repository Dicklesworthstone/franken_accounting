//! Mutation twins for N rows (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.7 item 3,
//! §5.2; bead fa-yugf.27, A11c).
//!
//! An N "passes" vacuously if nothing could ever fire, so every N carries a
//! harness-only twin: the target's book variant with exactly the one
//! attribute its mechanism names set to `twin_value`, run on its own book
//! (never adding a posting to the target's), which must then report
//! (`reports`), be refused (`refuses <FA-REF-NNN>`) or, for an `exact_gap`
//! N, show a zero gap on `twin_target` (`gap_zero`).
//!
//! `twin_value` grammar per `twin_attribute` (A11c defines it; A1c reads
//! the value as text):
//! - `entry_class`: a posting class (`Adjusting`);
//! - `effective_date`, `document_date`: `YYYY-MM-DD`;
//! - `amount_precision`: one amount literal, set on every leg of the target
//!   (a two-sided entry stays balanced; `1000.00`);
//! - `acting_principal`: a `[[principal]]` label;
//! - `evidence_attached`: a `[[document]]` id, or `none`;
//! - `chart_role_mapping`: `<account code>:<account type>[:<role>]`
//!   (`6100:Expense`).
//!
//! A harness-observability twin (`twin_kind = harness_observability`)
//! posts the same intent into a Closed period: the twin book soft-closes
//! and closes the target's period right before the target's step. A matcher
//! twin is A16's recorded probe input, not a book.

use super::Case;
use super::book::{BookVariant, StepDef, StepKind};
use super::error::{LoadError, LoadErrorKind};
use super::expect::{Expectation, ExpectationType};

closed_set! {
    /// `twin_kind`.
    TwinKind {
        Mutation => "mutation",
        HarnessObservability => "harness_observability",
        Matcher => "matcher",
    }
}

/// What the twin must show.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TwinExpect {
    /// The procedure reports the target.
    Reports,
    /// The kernel refuses the target with this refusal id.
    Refuses(String),
    /// An `exact_gap` N's `twin_target` shows a gap of zero.
    GapZero,
}

/// A built twin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TwinSpec {
    pub expectation: String,
    /// The N's `kind`: `no_refusal`, `no_finding` or `exact_gap`.
    pub n_kind: String,
    /// The target's book variant stem.
    pub variant: String,
    pub target: String,
    pub kind: TwinKind,
    pub attribute: Option<String>,
    pub value: Option<String>,
    pub expect: TwinExpect,
    /// The procedure the N reads, `no_finding` and `exact_gap` only.
    pub procedure: Option<(String, i128)>,
    /// The twin's target: `twin_target` for an `exact_gap` N, else the N's.
    pub twin_target: String,
    /// The twin's book (stem `<variant>~twin`); a matcher twin's is the
    /// target's unchanged.
    pub book: BookVariant,
}

fn refuse(e: &Expectation, kind: LoadErrorKind, detail: String) -> LoadError {
    LoadError {
        file: super::EXPECTATIONS_FILE.into(),
        line: e.fields.line,
        kind,
        row: Some(e.id.clone()),
        detail,
    }
}

/// The intent a target fact posted as: the intent with that id, or the one
/// intent whose `fact` it is.
fn target_intent<'b>(book: &'b BookVariant, target: &str) -> Option<&'b super::book::IntentDef> {
    book.intents.iter().find(|i| i.id == target).or_else(|| {
        let mut it = book.intents.iter().filter(|i| i.fact == target);
        match (it.next(), it.next()) {
            (Some(one), None) => Some(one),
            _ => None,
        }
    })
}

/// The twin of N row `n`.
///
/// # Errors
///
/// A row that is not an N; a `no_finding` or `exact_gap` N with no
/// `procedure`@`version`; a twin that flips more than one attribute, names
/// no attribute, or carries a value its attribute's grammar refuses; a
/// target that names no intent of its variant.
pub fn twin_of(case: &Case, n: &Expectation) -> Result<TwinSpec, LoadError> {
    let f = &n.fields;
    if n.kind != ExpectationType::N {
        return Err(refuse(
            n,
            LoadErrorKind::UnknownValue,
            "a twin belongs to an N row".into(),
        ));
    }
    let n_kind = f.str("kind").unwrap_or_default().to_string();
    let procedure = match (f.str("procedure"), f.int("version")) {
        (Some(p), Some(v)) => Some((p.to_string(), v)),
        _ => None,
    };
    if matches!(n_kind.as_str(), "no_finding" | "exact_gap") && procedure.is_none() {
        return Err(refuse(
            n,
            LoadErrorKind::MissingField,
            format!("a {n_kind} N names the `procedure`@`version` whose run it reads"),
        ));
    }
    let kind = f
        .str("twin_kind")
        .and_then(TwinKind::parse)
        .ok_or_else(|| {
            refuse(
                n,
                LoadErrorKind::UnknownValue,
                "`twin_kind` is mutation, harness_observability or matcher".into(),
            )
        })?;
    let expect = match f.str("twin_expect").unwrap_or_default() {
        "reports" => TwinExpect::Reports,
        "gap_zero" => TwinExpect::GapZero,
        other => match other.strip_prefix("refuses ") {
            Some(id) if id.starts_with("FA-REF-") => TwinExpect::Refuses(id.to_string()),
            _ => {
                return Err(refuse(
                    n,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "`twin_expect = \"{other}\"` is reports, gap_zero or `refuses <FA-REF-NNN>`"
                    ),
                ));
            }
        },
    };
    let variant = f.str("book_variant").unwrap_or_default().to_string();
    let Some(book) = case.books.get(&variant) else {
        return Err(refuse(
            n,
            LoadErrorKind::DanglingKey,
            format!("`book_variant = \"{variant}\"` has no book"),
        ));
    };
    let target = f.str("target").unwrap_or_default().to_string();
    let twin_target = f.str("twin_target").unwrap_or(&target).to_string();
    let attribute = f.str("twin_attribute").map(str::to_string);
    let value = f.str("twin_value").map(str::to_string);
    let mut twin = book.clone();
    twin.stem = format!("{variant}~twin");
    match kind {
        TwinKind::Matcher => {}
        TwinKind::HarnessObservability => {
            close_before_target(n, &mut twin, &target)?;
        }
        TwinKind::Mutation if n_kind == "exact_gap" => {}
        TwinKind::Mutation => {
            let Some(attr) = attribute.as_deref() else {
                return Err(refuse(
                    n,
                    LoadErrorKind::MissingField,
                    "a mutation twin names the one `twin_attribute` it flips".into(),
                ));
            };
            if attr.contains([',', ' ']) {
                return Err(refuse(
                    n,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "`twin_attribute = \"{attr}\"` flips more than one attribute; a twin flips exactly one"
                    ),
                ));
            }
            let Some(v) = value.as_deref() else {
                return Err(refuse(
                    n,
                    LoadErrorKind::MissingField,
                    "a mutation twin names its `twin_value`".into(),
                ));
            };
            mutate(n, &mut twin, &target, attr, v)?;
        }
    }
    Ok(TwinSpec {
        expectation: n.id.clone(),
        n_kind,
        variant,
        target,
        kind,
        attribute,
        value,
        expect,
        procedure,
        twin_target,
        book: twin,
    })
}

/// Sets `attr` of the target (or its account) to `v` in `twin`.
fn mutate(
    n: &Expectation,
    twin: &mut BookVariant,
    target: &str,
    attr: &str,
    v: &str,
) -> Result<(), LoadError> {
    let bad = |why: String| refuse(n, LoadErrorKind::UnknownValue, why);
    let id = target_intent(twin, target)
        .map(|i| i.id.clone())
        .ok_or_else(|| {
            refuse(
                n,
                LoadErrorKind::DanglingKey,
                format!("target `{target}` names no intent of the variant"),
            )
        })?;
    let is_date = |s: &str| super::date::Day::parse(s).is_some();
    let it = twin
        .intents
        .iter_mut()
        .find(|i| i.id == id)
        .expect("the target intent");
    match attr {
        "entry_class" => it.class = v.to_string(),
        "effective_date" if is_date(v) => it.effective_date = v.to_string(),
        "document_date" if is_date(v) => it.document_date = Some(v.to_string()),
        "acting_principal" => it.principal = v.to_string(),
        "evidence_attached" => it.evidence = (v != "none").then(|| v.to_string()),
        "amount_precision" => {
            if !v.chars().all(|c| c.is_ascii_digit() || c == '.') || v.is_empty() {
                return Err(bad(format!(
                    "`twin_value = \"{v}\"` for amount_precision is one amount literal"
                )));
            }
            for l in twin.legs.iter_mut().filter(|l| l.intent == id) {
                l.amount_literal = v.to_string();
                l.amount_rule = "synthetic".into();
            }
        }
        "chart_role_mapping" => {
            let mut parts = v.splitn(3, ':');
            let (Some(code), Some(account_type)) = (parts.next(), parts.next()) else {
                return Err(bad(format!(
                    "`twin_value = \"{v}\"` for chart_role_mapping is `<account code>:<account type>[:<role>]`"
                )));
            };
            let role = parts.next().map(str::to_string);
            let Some(a) = twin.accounts.iter_mut().find(|a| a.code == code) else {
                return Err(refuse(
                    n,
                    LoadErrorKind::DanglingKey,
                    format!(
                        "chart_role_mapping names account `{code}`, which the variant does not declare"
                    ),
                ));
            };
            a.account_type = account_type.to_string();
            if role.is_some() {
                a.role = role;
            }
        }
        "effective_date" | "document_date" => {
            return Err(bad(format!(
                "`twin_value = \"{v}\"` for {attr} is a YYYY-MM-DD date"
            )));
        }
        other => {
            return Err(bad(format!(
                "`twin_attribute = \"{other}\"` has no mutation (entry_class, effective_date, document_date, amount_precision, acting_principal, evidence_attached, chart_role_mapping)"
            )));
        }
    }
    Ok(())
}

/// A harness-observability twin: the target's period soft-closed and
/// closed right before the target's step, so the same intent posts into a
/// Closed period.
fn close_before_target(
    n: &Expectation,
    twin: &mut BookVariant,
    target: &str,
) -> Result<(), LoadError> {
    let it = target_intent(twin, target).ok_or_else(|| {
        refuse(
            n,
            LoadErrorKind::DanglingKey,
            format!("target `{target}` names no intent of the variant"),
        )
    })?;
    let id = it.id.clone();
    let Some(period) = twin
        .periods
        .iter()
        .find(|p| p.contains(&it.effective_date))
        .map(|p| p.code.clone())
    else {
        return Err(refuse(
            n,
            LoadErrorKind::UnknownPeriod,
            format!("no declared period contains {}'s effective date", id),
        ));
    };
    let Some(at) = twin
        .steps
        .iter()
        .position(|s| s.step_kind() == Some(StepKind::Intent) && s.reference == id)
    else {
        return Err(refuse(
            n,
            LoadErrorKind::DanglingKey,
            format!("no intent step posts {id}"),
        ));
    };
    let seq = twin.steps[at].seq;
    let principal = twin
        .steps
        .iter()
        .find(|s| matches!(s.step_kind(), Some(StepKind::PeriodOpen)) && s.reference == period)
        .and_then(|s| s.principal.clone());
    let transition = |kind: &str, n: i128| StepDef {
        seq: seq * 1000 - 2 + n,
        kind: kind.to_string(),
        reference: period.clone(),
        known_at: None,
        branch_class: None,
        principal: principal.clone(),
        approvers: None,
        params: None,
        evidence: None,
        asserts: None,
        document: None,
        line: None,
    };
    // Steps keep their order; the twin renumbers by ×1000 so the two
    // inserted transitions fit right before the target's step.
    for s in &mut twin.steps {
        s.seq *= 1000;
    }
    twin.steps.insert(at, transition("period_close", 1));
    twin.steps.insert(at, transition("period_soft_close", 0));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::expect::Field;
    use super::super::tests::pilot_planted;
    use super::*;

    fn n_row(case: &Case, id: &str) -> Expectation {
        case.expectations
            .as_ref()
            .and_then(|s| s.get(id))
            .expect("the N row")
            .clone()
    }

    fn set(e: &mut Expectation, key: &str, value: &str) {
        e.fields.map.insert(key.into(), Field::Str(value.into()));
    }

    #[test]
    fn pilot_w_n_01_twin_retypes_olta_as_expense() {
        let case = pilot_planted(&[]);
        let t = twin_of(&case, &n_row(&case, "W-N-01")).expect("a twin");
        assert_eq!(t.kind, TwinKind::Mutation);
        assert_eq!(t.expect, TwinExpect::Reports);
        assert_eq!(t.procedure, Some(("expense.capitalization".into(), 2)));
        assert_eq!(t.book.stem, "native~twin");
        let olta = |b: &BookVariant| {
            b.accounts
                .iter()
                .find(|a| a.code == "1400")
                .map(|a| a.account_type.clone())
        };
        assert_eq!(olta(&case.books["native"]).as_deref(), Some("Asset"));
        assert_eq!(olta(&t.book).as_deref(), Some("Expense"));
        // Only the one attribute moves.
        let mut back = t.book.clone();
        back.stem = "native".into();
        back.accounts
            .iter_mut()
            .find(|a| a.code == "1400")
            .expect("1400")
            .account_type = "Asset".into();
        assert_eq!(back, case.books["native"]);
    }

    #[test]
    fn twin_flipping_two_attributes_is_refused() {
        let case = pilot_planted(&[]);
        let mut n = n_row(&case, "W-N-01");
        set(&mut n, "twin_attribute", "chart_role_mapping,entry_class");
        let e = twin_of(&case, &n).expect_err("two attributes");
        assert_eq!(e.kind, LoadErrorKind::UnknownValue);
        assert!(e.detail.contains("flips more than one attribute"), "{e}");
    }

    #[test]
    fn no_finding_n_without_a_procedure_is_refused() {
        let case = pilot_planted(&[]);
        let mut n = n_row(&case, "W-N-01");
        n.fields.map.remove("procedure");
        let e = twin_of(&case, &n).expect_err("no procedure");
        assert_eq!(e.kind, LoadErrorKind::MissingField);
        assert!(
            e.detail
                .contains("no_finding N names the `procedure`@`version`"),
            "{e}"
        );
    }

    #[test]
    fn a_value_outside_its_attribute_grammar_is_refused() {
        let case = pilot_planted(&[]);
        let mut n = n_row(&case, "W-N-01");
        set(&mut n, "twin_value", "OLTA mapped to an Expense account");
        let e = twin_of(&case, &n).expect_err("prose value");
        assert!(
            e.detail.contains("<account code>:<account type>[:<role>]"),
            "{e}"
        );
    }

    #[test]
    fn harness_observability_twin_closes_the_target_period_before_its_step() {
        let case = pilot_planted(&[]);
        let mut n = n_row(&case, "W-N-01");
        set(&mut n, "kind", "no_refusal");
        set(&mut n, "twin_kind", "harness_observability");
        set(&mut n, "twin_expect", "refuses FA-REF-010");
        let t = twin_of(&case, &n).expect("a twin");
        assert_eq!(t.expect, TwinExpect::Refuses("FA-REF-010".into()));
        let at = t
            .book
            .steps
            .iter()
            .position(|s| s.step_kind() == Some(StepKind::Intent) && s.reference == "F2")
            .expect("F2's step");
        let before: Vec<&str> = t.book.steps[at - 2..at]
            .iter()
            .map(|s| s.kind.as_str())
            .collect();
        assert_eq!(before, ["period_soft_close", "period_close"]);
        assert!(t.book.steps.windows(2).all(|w| w[0].seq < w[1].seq));
        let f2 = t.book.intents.iter().find(|i| i.id == "F2").expect("F2");
        let period = t
            .book
            .periods
            .iter()
            .find(|p| p.contains(&f2.effective_date))
            .expect("F2's period");
        assert_eq!(t.book.steps[at - 1].reference, period.code);
    }
}
