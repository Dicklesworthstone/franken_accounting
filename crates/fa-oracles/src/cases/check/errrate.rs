//! K-ERRRATE (§3.6, §5.6; bead fa-yugf.9, A3c): every D names a
//! `procedure`@`version` row of `registries/procedures.toml` whose claim is
//! statistical or invariant and whose calibration has its fixed clause, so a
//! D sentence always carries its error-rate statement and never a free one.

use fa_registry::procedures::{Calibration, Procedures};

use super::super::EXPECTATIONS_FILE;
use super::super::expect::ExpectationType;
use super::super::phrases::clause_table;
use super::{CheckReport, Context};

#[must_use]
pub fn check(cx: &Context<'_>) -> CheckReport {
    check_with(cx, &clause_table)
}

const fn calibration_name(c: Calibration) -> &'static str {
    match c {
        Calibration::Planted => "planted",
        Calibration::Corpus => "corpus",
        Calibration::Uncalibrated => "uncalibrated",
    }
}

/// K-ERRRATE under a given clause table (tests pass a copy without a row).
#[must_use]
pub fn check_with(
    cx: &Context<'_>,
    table: &dyn Fn(Calibration) -> Option<&'static str>,
) -> CheckReport {
    let ds: Vec<_> = cx
        .case
        .expectations
        .iter()
        .flat_map(|s| s.expectations.iter())
        .filter(|e| e.kind == ExpectationType::D)
        .collect();
    let mut r = CheckReport::new("K-ERRRATE", ds.len());
    let procedures = match Procedures::embedded() {
        Ok(p) => p,
        Err(e) => {
            r.fail("registries/procedures.toml", None, "-", format!("{e:?}"));
            return r.finish();
        }
    };
    for e in ds {
        let (Some(id), Some(version)) = (e.fields.str("procedure"), e.fields.int("version")) else {
            r.fail(
                EXPECTATIONS_FILE,
                e.fields.line,
                &e.id,
                "a D names its procedure and version",
            );
            r.examined(e.id.clone());
            continue;
        };
        let Some(row) = procedures
            .get(id)
            .filter(|p| i128::from(p.version) == version)
        else {
            r.fail(
                EXPECTATIONS_FILE,
                e.fields.line,
                &e.id,
                format!("{id}@{version} is not a row of registries/procedures.toml"),
            );
            r.examined(e.id.clone());
            continue;
        };
        let name = calibration_name(row.calibration);
        match table(row.calibration) {
            Some(clause) => r.examined(format!("{} {id}@{version} {name}: {clause}", e.id)),
            None => {
                r.fail(
                    EXPECTATIONS_FILE,
                    e.fields.line,
                    &e.id,
                    format!("{id}@{version}'s calibration `{name}` has no clause (§5.6)"),
                );
                r.examined(e.id.clone());
            }
        }
    }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::super::super::phrases::calibration_clause;
    use super::super::super::tests::pilot_planted;
    use super::super::Verdict;
    use super::*;

    fn line_of(case: &crate::cases::Case, id: &str) -> String {
        case.expectations
            .as_ref()
            .and_then(|s| s.get(id))
            .and_then(|e| e.fields.line)
            .map_or_else(|| "-".into(), |l| l.to_string())
    }

    /// The registry's calibration of `id` (the bead's "planted" for
    /// expense.capitalization@2 was the registry at 8196f5e40; the row
    /// reads `uncalibrated` since).
    fn registry_calibration(id: &str) -> Calibration {
        Procedures::embedded()
            .expect("procedures.toml")
            .get(id)
            .expect("a registry row")
            .calibration
    }

    #[test]
    fn pilot_ds_carry_their_calibration_clauses() {
        let case = pilot_planted(&[]);
        let r = check(&Context::new(&case));
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Pass, "{text}");
        for (exp, id, version) in [
            ("W-D-01", "expense.capitalization", 2),
            ("W-D-03", "jet.round_amounts", 1),
        ] {
            let c = registry_calibration(id);
            let row = format!(
                "{exp} {id}@{version} {}: {}",
                calibration_name(c),
                calibration_clause(c)
            );
            assert!(r.rows.contains(&row), "{row}\n{text}");
        }
        assert_eq!(
            calibration_name(registry_calibration("jet.round_amounts")),
            "corpus"
        );
    }

    #[test]
    fn d_whose_calibration_has_no_clause_fails_k_errrate() {
        let case = pilot_planted(&[]);
        let missing = registry_calibration("expense.capitalization");
        let without = |c: Calibration| (c != missing).then(|| calibration_clause(c));
        let r = check_with(&Context::new(&case), &without);
        let text = r.render(None);
        assert_eq!(r.verdict, Verdict::Fail, "{text}");
        let want = format!(
            "FAIL K-ERRRATE expectations.toml:{} W-D-01: expense.capitalization@2's calibration `{}` has no clause (§5.6)",
            line_of(&case, "W-D-01"),
            calibration_name(missing)
        );
        assert!(text.lines().any(|l| l == want), "{want}\n{text}");
    }
}
