//! A runner row's verdict and its printed line (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §5, §16; bead fa-yugf.15, A7a).
//!
//! One line per evaluated (expectation, variant, target, cell) row:
//! `PASS|FAIL|UNRUN <id> <type> <variant> <target>/<cell> <projection>
//! [reason=<text>]`. `<target>` is the target fact id, or `-` for a row with
//! no target; `<cell>` is `default` or `attr=value[,attr=value]`; each
//! projected component is one `name=value` token; `reason=` comes last and
//! only on FAIL or UNRUN. A row is FAIL if any component it evaluates fails,
//! else UNRUN if a required witness or prerequisite is absent, else PASS; an
//! expectation's verdict is the worst of its rows.

use core::fmt;

closed_set! {
    /// A row's verdict, ordered by severity: the worst of a set is its max.
    RowVerdict {
        Pass => "PASS",
        Unrun => "UNRUN",
        Fail => "FAIL",
    }
}

impl RowVerdict {
    /// The worst of `rows` (FAIL over UNRUN over PASS); PASS for none.
    pub fn worst(rows: impl IntoIterator<Item = Self>) -> Self {
        rows.into_iter().max().unwrap_or(Self::Pass)
    }
}

/// One printed row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowLine {
    pub verdict: RowVerdict,
    pub id: String,
    /// The effective type (`D`, `P`, `T`, …) after load-time re-types.
    pub kind: String,
    pub variant: String,
    pub target: Option<String>,
    /// `default` or `attr=value[,attr=value]`.
    pub cell: String,
    /// `name=value` tokens in projection order.
    pub projection: Vec<(String, String)>,
    pub reason: Option<String>,
}

impl fmt::Display for RowLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} {} {} {}/{}",
            self.verdict.as_str(),
            self.id,
            self.kind,
            self.variant,
            self.target.as_deref().unwrap_or("-"),
            self.cell
        )?;
        for (name, value) in &self.projection {
            if value.is_empty() {
                write!(f, " {name}")?;
            } else {
                write!(f, " {name}={value}")?;
            }
        }
        if self.verdict != RowVerdict::Pass
            && let Some(reason) = &self.reason
        {
            write!(f, " reason={reason}")?;
        }
        Ok(())
    }
}

/// The `cell` field from a branch cell's attribute values.
#[must_use]
pub fn cell_label(cell: &[(String, String)]) -> String {
    if cell.is_empty() {
        "default".to_string()
    } else {
        cell.iter()
            .map(|(a, v)| format!("{a}={v}"))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(verdict: RowVerdict, reason: Option<&str>) -> RowLine {
        RowLine {
            verdict,
            id: "W-P-03".into(),
            kind: "P".into(),
            variant: "native".into(),
            target: None,
            cell: cell_label(&[("period_state_at_commit".into(), "Closed".into())]),
            projection: vec![
                ("refusal".into(), "FA-REF-010".into()),
                ("exit".into(), "7".into()),
                ("matrix".into(), "ok".into()),
            ],
            reason: reason.map(str::to_string),
        }
    }

    #[test]
    fn row_lines_follow_the_section_16_field_order() {
        assert_eq!(
            row(
                RowVerdict::Fail,
                Some("expected FA-REF-011 observed FA-REF-010")
            )
            .to_string(),
            "FAIL W-P-03 P native -/period_state_at_commit=Closed refusal=FA-REF-010 exit=7 matrix=ok reason=expected FA-REF-011 observed FA-REF-010"
        );
        // A PASS never prints a reason.
        assert_eq!(
            row(RowVerdict::Pass, Some("ignored")).to_string(),
            "PASS W-P-03 P native -/period_state_at_commit=Closed refusal=FA-REF-010 exit=7 matrix=ok"
        );
        assert_eq!(cell_label(&[]), "default");
    }

    #[test]
    fn row_verdict_worst_is_fail_over_unrun_over_pass() {
        use RowVerdict::{Fail, Pass, Unrun};
        assert_eq!(RowVerdict::worst([Pass, Pass]), Pass);
        assert_eq!(RowVerdict::worst([Pass, Unrun]), Unrun);
        assert_eq!(RowVerdict::worst([Unrun, Fail, Pass]), Fail);
        assert_eq!(RowVerdict::worst([]), Pass);
    }
}
