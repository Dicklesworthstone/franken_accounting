//! The filler- and identifier-invariance witness
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.7 item 1, §2.5; bead fa-yugf.25,
//! A11a).
//!
//! Tier rows (A4) are declarations; this witness executes them. A row's
//! single components (S, Sd, Si) must agree across every run of its
//! variant: the seeded filler variants, the empty variant, the extremal
//! variant of its tier, and at least two book ids (the empty variant run
//! twice). A disagreement names the procedure, the component and the two
//! runs. A Rel component agrees when its relational rule holds on every run,
//! its value free to differ. The wording is "shown on N variants", never
//! "proved".

/// One run's view of one row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantObservation {
    /// The filler variant (`<variant>@<seed label>`, A6), `empty` when the
    /// book posts none.
    pub variant: String,
    pub book_id: String,
    /// The row's projection tokens on this run.
    pub projection: Vec<(String, String)>,
}

impl VariantObservation {
    /// `<variant>/<book id>`, how a disagreement names a run.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{}/{}", self.variant, self.book_id)
    }

    fn token(&self, name: &str) -> Option<&str> {
        self.projection
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Which of a row's components the witness compares.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Statuses {
    /// A single component and the projection tokens it covers.
    pub single: Vec<(String, Vec<String>)>,
    /// A Rel component, judged by its rule on each run.
    pub relational: Vec<String>,
}

/// The witness's verdict on one row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvarianceVerdict {
    /// Every single component agreed and every Rel rule held, on this many
    /// filler variants and book ids.
    Agree { variants: usize, book_ids: usize },
    /// A component differs between two runs, or a Rel rule failed on one.
    Disagree {
        procedure: String,
        component: String,
        a: String,
        b: String,
    },
    /// Fewer than two book ids ran: identifier dependence is not shown, so
    /// the row can never read PASS.
    OneBookId,
}

impl InvarianceVerdict {
    /// The projection token: `agree(variants=<n>,book_ids=<m>)`, or
    /// `disagree(<procedure>,<component>,<a>,<b>)`, with no space inside.
    #[must_use]
    pub fn token(&self) -> String {
        match self {
            Self::Agree { variants, book_ids } => {
                format!("agree(variants={variants},book_ids={book_ids})")
            }
            Self::Disagree {
                procedure,
                component,
                a,
                b,
            } => format!("disagree({procedure},{component},{a},{b})"),
            Self::OneBookId => "one_book_id".into(),
        }
    }
}

/// Compares one row's observations: each single component's tokens must be
/// equal on every run, and `rel_holds(component, observation)` must hold on
/// every run for each Rel component. The first run is the reference a
/// disagreement is named against.
#[must_use]
pub fn compare(
    procedure: &str,
    observations: &[VariantObservation],
    statuses: &Statuses,
    rel_holds: &dyn Fn(&str, &VariantObservation) -> bool,
) -> InvarianceVerdict {
    let mut book_ids: Vec<&str> = observations.iter().map(|o| o.book_id.as_str()).collect();
    book_ids.sort_unstable();
    book_ids.dedup();
    if book_ids.len() < 2 {
        return InvarianceVerdict::OneBookId;
    }
    let disagree = |component: &str, a: &VariantObservation, b: &VariantObservation| {
        InvarianceVerdict::Disagree {
            procedure: procedure.to_string(),
            component: component.to_string(),
            a: a.label(),
            b: b.label(),
        }
    };
    let Some(first) = observations.first() else {
        return InvarianceVerdict::OneBookId;
    };
    for (component, tokens) in &statuses.single {
        let of = |o: &VariantObservation| -> Vec<Option<String>> {
            tokens
                .iter()
                .map(|t| o.token(t).map(str::to_string))
                .collect()
        };
        let want = of(first);
        if let Some(other) = observations.iter().find(|o| of(o) != want) {
            return disagree(component, first, other);
        }
    }
    for component in &statuses.relational {
        if let Some(bad) = observations.iter().find(|o| !rel_holds(component, o)) {
            return disagree(component, first, bad);
        }
    }
    let mut variants: Vec<&str> = observations.iter().map(|o| o.variant.as_str()).collect();
    variants.sort_unstable();
    variants.dedup();
    InvarianceVerdict::Agree {
        variants: variants.len(),
        book_ids: book_ids.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(variant: &str, book: &str, tokens: &[(&str, &str)]) -> VariantObservation {
        VariantObservation {
            variant: variant.into(),
            book_id: book.into(),
            projection: tokens
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    fn statistic_single() -> Statuses {
        Statuses {
            single: vec![
                ("cite".into(), vec!["cite".into()]),
                (
                    "statistic".into(),
                    vec!["statistic_name".into(), "statistic".into(), "scale".into()],
                ),
            ],
            relational: Vec::new(),
        }
    }

    fn always(_: &str, _: &VariantObservation) -> bool {
        true
    }

    #[test]
    fn compare_names_the_procedure_component_and_both_variants() {
        let base = [
            ("cite", "F4#0"),
            ("statistic_name", "density"),
            ("statistic", "4"),
            ("scale", "0"),
        ];
        let mut moved = base;
        moved[2] = ("statistic", "9");
        let observations = [
            obs("fv1@empty", "b1", &base),
            obs("fv1@empty", "b2", &base),
            obs("fv1@1", "b3", &base),
            obs("fv1@extremal-L", "b4", &moved),
        ];
        assert_eq!(
            compare(
                "numbers.round_amount_density@1",
                &observations,
                &statistic_single(),
                &always
            ),
            InvarianceVerdict::Disagree {
                procedure: "numbers.round_amount_density@1".into(),
                component: "statistic".into(),
                a: "fv1@empty/b1".into(),
                b: "fv1@extremal-L/b4".into(),
            }
        );
        // Agreement counts the distinct variants and book ids.
        let agree = compare("p@1", &observations[..3], &statistic_single(), &always);
        assert_eq!(
            agree,
            InvarianceVerdict::Agree {
                variants: 2,
                book_ids: 3
            }
        );
        assert_eq!(agree.token(), "agree(variants=2,book_ids=3)");
    }

    #[test]
    fn expectation_with_one_book_id_is_never_agreed() {
        let base = [("cite", "F4#0")];
        let observations = [obs("fv1@empty", "b1", &base), obs("fv1@1", "b1", &base)];
        assert_eq!(
            compare("p@1", &observations, &statistic_single(), &always),
            InvarianceVerdict::OneBookId
        );
    }

    #[test]
    fn rel_component_with_different_values_across_book_ids_agrees_when_its_rule_holds() {
        // expense.capitalization cites the lowest-VId cost account: its
        // value moves with the book id, the rule (lowest VId) holds on both.
        let statuses = Statuses {
            single: Vec::new(),
            relational: vec!["cite".into()],
        };
        let observations = [
            obs("fv1@empty", "b1", &[("cite", "6100"), ("lowest", "6100")]),
            obs("fv1@empty", "b2", &[("cite", "6110"), ("lowest", "6110")]),
        ];
        let rule = |_: &str, o: &VariantObservation| o.token("cite") == o.token("lowest");
        assert_eq!(
            compare("expense.capitalization@2", &observations, &statuses, &rule),
            InvarianceVerdict::Agree {
                variants: 1,
                book_ids: 2
            }
        );
    }

    #[test]
    fn rel_component_whose_rule_fails_on_one_run_disagrees() {
        let statuses = Statuses {
            single: Vec::new(),
            relational: vec!["cite".into()],
        };
        let observations = [
            obs("fv1@empty", "b1", &[("cite", "6100"), ("lowest", "6100")]),
            obs("fv1@empty", "b2", &[("cite", "6120"), ("lowest", "6110")]),
        ];
        let rule = |_: &str, o: &VariantObservation| o.token("cite") == o.token("lowest");
        assert_eq!(
            compare("expense.capitalization@2", &observations, &statuses, &rule),
            InvarianceVerdict::Disagree {
                procedure: "expense.capitalization@2".into(),
                component: "cite".into(),
                a: "fv1@empty/b1".into(),
                b: "fv1@empty/b2".into(),
            }
        );
    }
}
