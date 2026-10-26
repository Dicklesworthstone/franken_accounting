//! K-TIER (§2.5, §3.6; bead fa-yugf.10, A4): every procedure a case claims
//! has a two-reader tier row whose (id, version, row digest) matches the
//! tree, and tiers P and A carry no D unless the comparison population is
//! itself sourced and complete.
//!
//! A case claims every D's and N's `procedure`, every procedure a
//! `finding_record` step names, and, once it has a book variant, the
//! runner-generated `jet.self_sourced_evidence` row (A7a's SELF rows). A
//! version or row change invalidates the row until two readers classify the
//! procedure again. The §9.4 exception: a P- or A-tier D is admitted only
//! with `population = "sourced_complete"` and the facts that establish
//! completeness in `population_basis`.

use std::collections::BTreeMap;

use super::super::book::StepKind;
use super::super::expect::ExpectationType;
use super::super::tiers::{self, FILE, Tiers, registry_row};
use super::super::{Case, EXPECTATIONS_FILE};
use super::{CheckReport, Context};

/// The runner-generated self-disclosure row's procedure (A7a).
pub const SELF_ROW_PROCEDURE: &str = "jet.self_sourced_evidence";

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    let case = cx.case;
    let claimed = claimed(case);
    let mut r = CheckReport::new("K-TIER", claimed.len());
    let table = match &cx.tiers {
        Ok(t) => t,
        Err(e) => {
            r.fail(
                FILE,
                None,
                "-",
                format!("the tier table does not load: {e}"),
            );
            return r.finish();
        }
    };
    for (procedure, claims) in &claimed {
        r.examined(procedure.clone());
        for p in row_problems(table, cx.procedures, procedure, claims) {
            let (line, row) = table.get(procedure).map_or((None, procedure.clone()), |t| {
                (t.line, format!("{}@{}", t.procedure, t.version))
            });
            r.fail(FILE, line, &row, p);
        }
        // Tiers P and A carry no D without a sourced, complete population.
        if let Some(row) = table.get(procedure)
            && !row.tier.admissible_for_d()
        {
            for c in claims.iter().filter(|c| c.d) {
                if !c.sourced_complete {
                    r.fail(
                        EXPECTATIONS_FILE,
                        c.line,
                        &c.by,
                        format!(
                            "a D on {procedure} (tier {}) needs population = \"sourced_complete\" and its population_basis (§2.5, §9.4)",
                            row.tier.as_str()
                        ),
                    );
                }
            }
        }
    }
    r.finish()
}

/// One claim of a procedure: by which row, at which version, and whether it
/// is a D that marks its population sourced and complete.
#[derive(Clone, Debug)]
pub struct Claim {
    pub by: String,
    pub version: Option<i128>,
    pub d: bool,
    pub sourced_complete: bool,
    pub line: Option<usize>,
}

/// Every procedure the case claims, with its claims.
#[must_use]
pub fn claimed(case: &Case) -> BTreeMap<String, Vec<Claim>> {
    let mut out: BTreeMap<String, Vec<Claim>> = BTreeMap::new();
    if let Some(set) = &case.expectations {
        for e in set
            .expectations
            .iter()
            .filter(|e| matches!(e.kind, ExpectationType::D | ExpectationType::N))
        {
            if let Some(p) = e.fields.str("procedure") {
                let basis_given = e
                    .fields
                    .strs("population_basis")
                    .is_some_and(|b| !b.is_empty());
                out.entry(p.to_string()).or_default().push(Claim {
                    by: e.id.clone(),
                    version: e.fields.int("version"),
                    d: e.kind == ExpectationType::D,
                    sourced_complete: e.fields.str("population") == Some("sourced_complete")
                        && basis_given,
                    line: e.fields.line,
                });
            }
        }
    }
    for book in case.books.values() {
        for s in book
            .steps
            .iter()
            .filter(|s| s.step_kind() == Some(StepKind::FindingRecord))
        {
            // A finding_record step's ref is `<procedure id>@<version>`.
            let (procedure, version) = s
                .reference
                .split_once('@')
                .map_or((s.reference.as_str(), None), |(p, v)| (p, v.parse().ok()));
            out.entry(procedure.to_string()).or_default().push(Claim {
                by: format!("books/{}.toml step {}", book.stem, s.seq),
                version,
                d: false,
                sourced_complete: false,
                line: s.line,
            });
        }
    }
    if !case.books.is_empty() {
        out.entry(SELF_ROW_PROCEDURE.to_string())
            .or_default()
            .push(Claim {
                by: format!("{}-SELF", case.header.id),
                version: None,
                d: false,
                sourced_complete: false,
                line: None,
            });
    }
    out
}

fn row_problems(table: &Tiers, procedures: &str, procedure: &str, claims: &[Claim]) -> Vec<String> {
    let Some(row) = table.get(procedure) else {
        return vec![format!(
            "{procedure} is claimed by {} but has no two-reader tier row",
            claims
                .iter()
                .map(|c| c.by.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )];
    };
    let mut out = Vec::new();
    match registry_row(procedures, procedure) {
        Err(e) => out.push(e),
        Ok((version, digest)) => {
            if row.version != version || row.row_digest != digest {
                out.push(format!(
                    "registry is at version {version}, row digest {} != {digest}",
                    row.row_digest
                ));
            }
        }
    }
    for c in claims {
        if let Some(v) = c.version
            && v != row.version
        {
            out.push(format!(
                "{} claims {procedure}@{v}, the tier row reads version {}",
                c.by, row.version
            ));
        }
    }
    out
}

/// The committed table, or why it does not load, for [`Context`].
pub fn embedded() -> Result<Tiers, String> {
    tiers::tiers().map_err(|errs| {
        errs.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("; ")
    })
}

#[cfg(test)]
mod tests {
    use super::super::super::tests::{load_files, pilot};
    use super::super::super::tiers::{PROCEDURES, row_digest};
    use super::super::Verdict;
    use super::*;
    use crate::cases::CASE_EXTENSIONS;

    const TABLE: &str = include_str!("../../../data/case_procedure_tiers.toml");

    /// A D on `procedure@version` over the pilot's F4.
    fn d_row(id: &str, procedure: &str, version: i128, extra: &str) -> String {
        format!(
            "\n[[expectation]]\nid = \"{id}\"\ntype = \"D\"\nbook_variant = \"native\"\nstatement_template = \"D.detection\"\nbasis = [\"F4\"]\ngranularity = \"journal_entry\"\ncapabilities = [\"procedure:{procedure}@{version}\"]\nprocedure = \"{procedure}\"\nversion = {version}\n{extra}"
        )
    }

    /// The pilot with `extra` appended to its expectations.
    fn pilot_with(extra: &str) -> Case {
        let mut files = pilot();
        files.push((
            EXPECTATIONS_FILE,
            format!(
                "{}{extra}",
                include_str!("../../../tests/fixtures/pilot/expectations.toml")
            ),
        ));
        load_files("worldcom", &files, CASE_EXTENSIONS).expect("the planted pilot loads")
    }

    fn expectation_line(case: &Case, id: &str) -> String {
        case.expectations
            .as_ref()
            .and_then(|s| s.get(id))
            .and_then(|e| e.fields.line)
            .map_or_else(|| "-".into(), |l| l.to_string())
    }

    /// The committed row's (line, row digest).
    fn table_row(procedure: &str) -> (String, String) {
        let t = tiers::tiers().expect("the committed table");
        let row = t.get(procedure).expect("a row");
        (
            row.line.map_or_else(|| "-".into(), |l| l.to_string()),
            row.row_digest.clone(),
        )
    }

    #[test]
    fn k_tier_passes_over_the_pilot_d_rows() {
        let case = pilot_with("");
        let r = check(&Context::new(&case));
        let text = r.render(None);
        println!("{text}");
        assert_eq!(r.verdict, Verdict::Pass, "{text}");
        assert_eq!(
            text.lines().next(),
            Some("CHECK K-TIER PASS examined=3/3"),
            "{text}"
        );
        assert_eq!(
            claimed(&case)
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "expense.capitalization",
                "jet.round_amounts",
                "jet.self_sourced_evidence"
            ]
        );
    }

    #[test]
    fn version_bump_in_a_test_copy_invalidates_the_row() {
        let old = "id = \"jet.round_amounts\"\nversion = 1\n";
        assert_eq!(PROCEDURES.matches(old).count(), 1);
        let edited = PROCEDURES.replace(old, "id = \"jet.round_amounts\"\nversion = 2\n");
        let new = row_digest(&edited, "jet.round_amounts").expect("a digest");
        let (line, old_digest) = table_row("jet.round_amounts");
        assert_ne!(new, old_digest);
        let case = pilot_with("");
        let cx = Context {
            procedures: &edited,
            ..Context::new(&case)
        };
        let r = check(&cx);
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        let want = format!(
            "FAIL K-TIER case_procedure_tiers.toml:{line} jet.round_amounts@1: registry is at version 2, row digest {old_digest} != {new}"
        );
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
        assert_eq!(
            text.lines().filter(|l| l.starts_with("FAIL ")).count(),
            1,
            "only the edited row fails: {text}"
        );
    }

    #[test]
    fn p_tier_d_without_a_sourced_complete_population_is_refused() {
        let case = pilot_with(&d_row("W-D-90", "benford.first_digit", 2, ""));
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        let want = format!(
            "FAIL K-TIER expectations.toml:{} W-D-90: a D on benford.first_digit (tier P) needs population = \"sourced_complete\" and its population_basis (§2.5, §9.4)",
            expectation_line(&case, "W-D-90")
        );
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
    }

    #[test]
    fn p_tier_d_marked_sourced_complete_is_admitted() {
        let case = pilot_with(&d_row(
            "W-D-90",
            "benford.first_digit",
            2,
            "population = \"sourced_complete\"\npopulation_basis = [\"F4\"]\n",
        ));
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Pass, "{text}");
        assert!(
            text.starts_with("CHECK K-TIER PASS examined=4/4\n"),
            "{text}"
        );
    }

    #[test]
    fn claimed_procedure_without_a_tier_row_is_refused() {
        let case = pilot_with(&d_row("W-D-91", "jet.weekend", 1, ""));
        // The committed table without its jet.weekend row: chunk i of the
        // split holds row i's fields and row i+1's leading comments.
        let chunks: Vec<&str> = TABLE.split("\n[[tier]]\n").collect();
        let kept: Vec<&str> = chunks
            .iter()
            .copied()
            .filter(|c| !c.starts_with("procedure = \"jet.weekend\"\n"))
            .collect();
        assert_eq!(kept.len() + 1, chunks.len(), "exactly one row removed");
        let edited = kept.join("\n[[tier]]\n");
        let cx = Context {
            tiers: Tiers::from_text(&edited).map_err(|e| format!("{e:?}")),
            ..Context::new(&case)
        };
        let r = check(&cx);
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        assert!(
            text.lines().any(|l| l
                == "FAIL K-TIER case_procedure_tiers.toml:- jet.weekend: jet.weekend is claimed by W-D-91 but has no two-reader tier row"),
            "{text}"
        );
    }

    #[test]
    fn a_finding_record_step_claims_its_procedure_at_its_version() {
        let case = pilot_with("");
        let claims = &claimed(&case)["expense.capitalization"];
        assert!(
            claims
                .iter()
                .any(|c| c.by.starts_with("books/native.toml step") && c.version == Some(2)),
            "{claims:?}"
        );
    }
}
