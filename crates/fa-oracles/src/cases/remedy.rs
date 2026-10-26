//! The P rows' structured-remedy check (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §5.2; bead fa-yugf.15, A7a): what a refusal must say beyond its id.
//!
//! The admissible classes and ops per period state are derived here from
//! `registries/admissibility.toml`'s `[[cell]]` rows, read raw with
//! `fa_registry::toml::parse`: an independent derivation, never the
//! kernel's `Admissibility` type. Each check prints `ok`, `fail` or `n/a`,
//! and `n/a` only where the check's input cannot exist for that refusal:
//!
//! - `matrix=`: `refusal.why.matrix` equals the row's {state, class}. Only
//!   the posting pipeline's period-law and capability sites set a matrix, so
//!   it is required (absent or different is `fail`) on a row whose
//!   `law_row` is an `admissibility.toml` cell and whose refusal is
//!   `FA-REF-010` or `FA-REF-011`, and `n/a` elsewhere;
//! - `fix_argv=`: `refusal.fix.argv` parses against the named verb's
//!   registered flags (the runner passes `fa_cli::args::parse`); `n/a` when
//!   `fix.argv` is null;
//! - `alternatives=`: on the rows where `matrix=` is required, the refusal
//!   names every class `fa post` may carry in that state with its op (in its
//!   fix text or its `alternatives`); `n/a` elsewhere.
//!
//! A row's `law_row` names its law: `<registry file>#<row key>` is named by
//! the refusal's `why` or cite; `plan:§<section>` passes only on a refusal
//! whose cite begins `plan §<section>`.

use fa_registry::toml::Value as TomlValue;

use super::observe::{ObservedError, ObservedRefusal};

const ADMISSIBILITY: &str = include_str!("../../../../registries/admissibility.toml");

/// The refusal codes whose sites set `why.matrix` (posting law and
/// capability, `crates/fa-journal/src/post.rs`).
pub const MATRIX_CODES: [&str; 2] = ["FA-REF-010", "FA-REF-011"];

/// The classes `fa post` carries (`crates/fa-journal/src/post.rs`
/// `POSTED_CLASSES`) less those with a route of their own: Resolution (`fa
/// resolve`), Migration (a migration run), Allocation (`fa allocate`) and
/// Revaluation (`fa fx revalue`). A cell noted `case` (inside an approved
/// restatement case) is no lawful `fa post` remedy either.
pub const POST_REMEDY_CLASSES: [&str; 9] = [
    "Original",
    "Pending",
    "Reversal",
    "Reclassification",
    "Adjusting",
    "PriorPeriodAdjustment",
    "Revision",
    "Restatement",
    "Closing",
];

/// One admissible class in a state, with the op and approvals it needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remedy {
    pub class: String,
    pub op: Option<String>,
    pub approvals: u32,
}

impl Remedy {
    /// How the kernel's fix text names it: `Adjusting (with `post_closed``.
    #[must_use]
    pub fn named_as(&self) -> String {
        match &self.op {
            Some(op) => format!("{} (with `{op}`", self.class),
            None => self.class.clone(),
        }
    }
}

/// The admissibility cells, read raw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cells {
    /// (class, state, decision, note) in file order; disposition rows are
    /// left out (a release has its own route).
    rows: Vec<(String, String, String, Option<String>)>,
}

impl Cells {
    /// The committed matrix.
    ///
    /// # Errors
    ///
    /// When the registry does not parse.
    pub fn embedded() -> Result<Self, String> {
        Self::from_text(ADMISSIBILITY)
    }

    /// A matrix from text.
    ///
    /// # Errors
    ///
    /// When the text does not parse or a cell lacks its class, state or
    /// decision.
    pub fn from_text(text: &str) -> Result<Self, String> {
        let doc = fa_registry::toml::parse(text)
            .map_err(|e| format!("admissibility.toml:{}: {}", e.line, e.message))?;
        let mut rows = Vec::new();
        for t in doc.arrays.get("cell").map(Vec::as_slice).unwrap_or(&[]) {
            if t.contains_key("disposition") {
                continue;
            }
            let get = |k: &str| t.get(k).and_then(TomlValue::as_str).map(str::to_string);
            let (Some(class), Some(state), Some(decision)) =
                (get("class"), get("state"), get("decision"))
            else {
                return Err("an admissibility [[cell]] lacks class, state or decision".into());
            };
            rows.push((class, state, decision, get("note")));
        }
        Ok(Self { rows })
    }

    /// The decision of (class, state): `admit`, `with:<op>[,<n>]` or `refuse`.
    #[must_use]
    pub fn decision(&self, class: &str, state: &str) -> Option<&str> {
        self.rows
            .iter()
            .find(|(c, s, _, _)| c == class && s == state)
            .map(|(_, _, d, _)| d.as_str())
    }

    /// The classes `fa post` may lawfully carry in `state`, in file order.
    #[must_use]
    pub fn admissible(&self, state: &str) -> Vec<Remedy> {
        self.rows
            .iter()
            .filter(|(c, s, d, note)| {
                s == state
                    && d != "refuse"
                    && note.as_deref() != Some("case")
                    && POST_REMEDY_CLASSES.contains(&c.as_str())
            })
            .map(|(c, _, d, _)| {
                let (op, approvals) = match d.strip_prefix("with:") {
                    Some(rest) => match rest.split_once(',') {
                        Some((op, n)) => (Some(op.to_string()), n.parse().unwrap_or(0)),
                        None => (Some(rest.to_string()), 0),
                    },
                    None => (None, 0),
                };
                Remedy {
                    class: c.clone(),
                    op,
                    approvals,
                }
            })
            .collect()
    }
}

closed_set! {
    /// One remedy check's outcome.
    Check {
        Ok => "ok",
        Fail => "fail",
        NotApplicable => "n/a",
    }
}

/// A P row's three remedy checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RemedyChecks {
    pub matrix: Check,
    pub fix_argv: Check,
    pub alternatives: Check,
}

impl RemedyChecks {
    /// The projection tokens, in §16's order.
    #[must_use]
    pub fn tokens(&self) -> Vec<(String, String)> {
        vec![
            ("matrix".into(), self.matrix.as_str().into()),
            ("fix_argv".into(), self.fix_argv.as_str().into()),
            ("alternatives".into(), self.alternatives.as_str().into()),
        ]
    }
}

/// An `admissibility.toml#<Class>/<State>` law row's (class, state).
#[must_use]
pub fn admissibility_cell(law_row: &str) -> Option<(&str, &str)> {
    law_row.strip_prefix("admissibility.toml#")?.split_once('/')
}

/// The remedy checks of a P row whose observed refusal is `refusal`.
/// `argv_parses` says whether a `fix.argv` parses against the verb it
/// names (the runner passes `fa_cli::args::parse`).
#[must_use]
pub fn check(
    law_row: &str,
    refusal: &ObservedRefusal,
    cells: &Cells,
    argv_parses: &dyn Fn(&[String]) -> bool,
) -> RemedyChecks {
    let cell =
        admissibility_cell(law_row).filter(|_| MATRIX_CODES.contains(&refusal.code.as_str()));
    let matrix = match cell {
        None => Check::NotApplicable,
        Some((class, state)) => {
            if refusal.matrix() == Some((state, class)) {
                Check::Ok
            } else {
                Check::Fail
            }
        }
    };
    let fix_argv = match &refusal.fix_argv {
        None => Check::NotApplicable,
        Some(argv) if argv_parses(argv) => Check::Ok,
        Some(_) => Check::Fail,
    };
    let alternatives = match cell {
        None => Check::NotApplicable,
        Some((_, state)) => {
            let named: String = std::iter::once(refusal.fix_text.clone().unwrap_or_default())
                .chain(refusal.alternatives.iter().cloned())
                .collect::<Vec<_>>()
                .join("\n");
            if cells
                .admissible(state)
                .iter()
                .all(|r| named.contains(&r.named_as()))
            {
                Check::Ok
            } else {
                Check::Fail
            }
        }
    };
    RemedyChecks {
        matrix,
        fix_argv,
        alternatives,
    }
}

/// Whether the refusal names the row's `law_row`: a `plan:§<section>` row
/// by a cite that begins `plan §<section>` (and not a longer section); a
/// `<registry file>#<row key>` row by `why.matrix` (an admissibility cell),
/// or by a cite or `why` that names the file or the row key.
#[must_use]
pub fn law_named(law_row: &str, error: &ObservedError) -> bool {
    let cites: Vec<&str> = error
        .cite
        .as_deref()
        .into_iter()
        .chain(error.refusal.as_ref().and_then(ObservedRefusal::cite))
        .collect();
    if let Some(section) = law_row.strip_prefix("plan:§") {
        let want = format!("plan §{section}");
        return cites.iter().any(|c| {
            c.strip_prefix(want.as_str()).is_some_and(|rest| {
                let mut chars = rest.chars();
                match (chars.next(), chars.next()) {
                    (None, _) => true,
                    (Some(c), _) if c.is_ascii_digit() => false,
                    (Some('.'), Some(d)) if d.is_ascii_digit() => false,
                    _ => true,
                }
            })
        });
    }
    let Some((file, key)) = law_row.split_once('#') else {
        return false;
    };
    if let Some((class, state)) = admissibility_cell(law_row)
        && error
            .refusal
            .as_ref()
            .and_then(ObservedRefusal::matrix)
            .is_some_and(|m| m == (state, class))
    {
        return true;
    }
    let why = error
        .refusal
        .as_ref()
        .map(|r| r.why.to_string())
        .unwrap_or_default();
    cites
        .iter()
        .copied()
        .chain(std::iter::once(why.as_str()))
        .any(|c| c.contains(file) || c.contains(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::Json;

    fn refusal(
        code: &str,
        why: Json,
        fix_argv: Option<Vec<&str>>,
        fix_text: &str,
    ) -> ObservedRefusal {
        ObservedRefusal {
            id: format!("{code}:0123456789abcdef"),
            code: code.into(),
            exit: 7,
            why,
            fix_argv: fix_argv.map(|a| a.into_iter().map(str::to_string).collect()),
            fix_text: Some(fix_text.into()),
            alternatives: Vec::new(),
        }
    }

    fn matrix(state: &str, class: &str) -> Json {
        Json::Object(vec![(
            "matrix".into(),
            Json::Object(vec![
                ("state".into(), Json::Str(state.into())),
                ("class".into(), Json::Str(class.into())),
            ]),
        )])
    }

    fn cite(text: &str) -> Json {
        Json::Object(vec![("cite".into(), Json::Str(text.into()))])
    }

    #[test]
    fn remedy_checks_are_n_a_without_detail_and_fail_when_a_required_matrix_is_missing() {
        let cells = Cells::embedded().expect("admissibility.toml");
        let parses = |_: &[String]| true;
        // An evidence-minimum refusal with only a prose why and no parseable fix.
        let bare = refusal(
            "FA-REF-080",
            cite("evidence_policy.toml Original"),
            None,
            "attach a document",
        );
        let checks = check("evidence_policy.toml#Original", &bare, &cells, &parses);
        assert_eq!(
            checks.tokens(),
            [
                ("matrix".to_string(), "n/a".to_string()),
                ("fix_argv".to_string(), "n/a".to_string()),
                ("alternatives".to_string(), "n/a".to_string())
            ]
        );
        // FA-REF-010 on an admissibility cell with its matrix removed.
        let no_matrix = refusal("FA-REF-010", cite("admissibility.toml"), None, "");
        let checks = check(
            "admissibility.toml#Original/Closed",
            &no_matrix,
            &cells,
            &parses,
        );
        assert_eq!(checks.matrix, Check::Fail);
        assert_eq!(
            checks.alternatives,
            Check::Fail,
            "the remedies are not named"
        );
        // The same refusal with its matrix and the kernel's fix text passes.
        let full = refusal(
            "FA-REF-010",
            matrix("Closed", "Original"),
            Some(vec!["period", "list", "--json"]),
            "keep the entry's true effective date; never re-date it to escape the period law: a Closed period admits Reclassification (with `post_closed` and 1 approval), Adjusting (with `post_closed` and 1 approval), Reversal (with `post_closed`), Closing (with `close` and 1 approval)",
        );
        let checks = check("admissibility.toml#Original/Closed", &full, &cells, &parses);
        assert_eq!(
            (checks.matrix, checks.fix_argv, checks.alternatives),
            (Check::Ok, Check::Ok, Check::Ok)
        );
        // A matrix for another cell fails, and an unparseable argv fails.
        let other = refusal(
            "FA-REF-010",
            matrix("Locked", "Original"),
            Some(vec!["post"]),
            "",
        );
        let checks = check(
            "admissibility.toml#Original/Closed",
            &other,
            &cells,
            &|_: &[String]| false,
        );
        assert_eq!((checks.matrix, checks.fix_argv), (Check::Fail, Check::Fail));
    }

    #[test]
    fn plan_section_law_row_passes_on_the_refusal_cite_and_fails_on_another_section() {
        let err = |c: &str| ObservedError {
            class: "safety".into(),
            exit: 7,
            refusal_id: Some("FA-REF-012".into()),
            message: "approval count".into(),
            cite: Some(c.into()),
            fix: None,
            refusal: None,
        };
        let allocation = err("plan §14.3 (separation of preparer and approver)");
        assert!(law_named("plan:§14.3", &allocation));
        assert!(!law_named("plan:§14.3", &err("plan §14.4 (escrow)")));
        assert!(!law_named(
            "plan:§14.3",
            &err("plan §14.30 (a longer section)")
        ));
        assert!(law_named("plan:§14", &err("plan §14 (whole chapter)")));
        // A registry row is named by its matrix or its file.
        let mut matrixed = err("admissibility.toml");
        matrixed.refusal = Some(refusal(
            "FA-REF-010",
            matrix("Closed", "Original"),
            None,
            "",
        ));
        assert!(law_named("admissibility.toml#Original/Closed", &matrixed));
        assert!(law_named(
            "evidence_policy.toml#Original",
            &err("evidence_policy.toml row Original")
        ));
        assert!(!law_named(
            "sod_policy.toml#Adjusting",
            &err("evidence_policy.toml row Original")
        ));
    }

    #[test]
    fn remedy_alternatives_for_original_in_closed_are_derived_from_admissibility() {
        let cells = Cells::embedded().expect("admissibility.toml");
        assert_eq!(cells.decision("Original", "Closed"), Some("refuse"));
        let names: Vec<String> = cells
            .admissible("Closed")
            .iter()
            .map(|r| {
                format!(
                    "{}:{}:{}",
                    r.class,
                    r.op.as_deref().unwrap_or("-"),
                    r.approvals
                )
            })
            .collect();
        assert_eq!(
            names,
            [
                "Reversal:post_closed:0",
                "Reclassification:post_closed:1",
                "Adjusting:post_closed:1",
                "Closing:close:1"
            ]
        );
        // Open admits Original without an op; a case-bound cell is no remedy.
        assert!(
            cells
                .admissible("Open")
                .iter()
                .any(|r| r.class == "Original" && r.op.is_none())
        );
        assert!(
            cells
                .admissible("Closed")
                .iter()
                .all(|r| r.class != "Restatement" && r.class != "Revision")
        );
    }
}
