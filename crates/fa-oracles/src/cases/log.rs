//! The runner's JSONL log (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.5; bead
//! fa-yugf.15, A7a): one [`StepRecord`] per step it ran and one
//! [`VerdictRecord`] per printed row. A13 and A14 read the expectation
//! verdicts back from the log; A14b's transcript mode replays the steps,
//! rebinding the placeholders `argv_redacted` carries through `binds`.

use crate::json::{self, Json};

use super::verdict::RowVerdict;

/// One step of a run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepRecord {
    pub case: String,
    pub book_variant: String,
    pub branch_class: Option<String>,
    pub filler_variant: Option<String>,
    pub book_id: Option<String>,
    /// The `[[step]]` seq, or 0 for a setup step.
    pub step: i128,
    /// What the step runs (an intent id, a period label, a procedure id).
    pub reference: String,
    pub verb: String,
    /// The argv after `fa`, every run-variant token replaced by a
    /// placeholder (`$BOOK`, `$<fact id>`, `$C_<KIND>_<period>`,
    /// `$APPROVAL_<n>`, `$DOC_<document id>`).
    pub argv_redacted: Vec<String>,
    pub exit: i128,
    pub refusal_id: Option<String>,
    pub finding_procedure: Option<String>,
    pub certificate_kind: Option<String>,
    pub elapsed_ms: i128,
    /// Each placeholder and the `<event>.<field> of step <n>` that bound it.
    pub binds: Vec<(String, String)>,
}

/// One printed row's verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerdictRecord {
    pub case: String,
    pub expectation: String,
    /// The effective type.
    pub kind: String,
    pub book_variant: String,
    pub target: Option<String>,
    pub cell: String,
    pub verdict: RowVerdict,
    pub projection: Vec<(String, String)>,
    /// Each witness and its verdict (`contributing_entry` → `holds`).
    pub witnesses: Vec<(String, String)>,
    pub reason: Option<String>,
}

fn s(v: &str) -> Json {
    Json::Str(v.to_string())
}

fn pairs(v: &[(String, String)]) -> Json {
    Json::Object(v.iter().map(|(k, x)| (k.clone(), s(x))).collect())
}

fn strs(v: &[String]) -> Json {
    Json::Array(v.iter().map(|x| s(x)).collect())
}

/// The fields of a record line.
struct Fields(Json);

impl Fields {
    fn str(&self, k: &str) -> Result<String, String> {
        self.0
            .get(k)
            .and_then(Json::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("`{k}` is a string"))
    }

    fn opt(&self, k: &str) -> Result<Option<String>, String> {
        match self.0.get(k) {
            None | Some(Json::Null) => Ok(None),
            Some(Json::Str(v)) => Ok(Some(v.clone())),
            Some(_) => Err(format!("`{k}` is a string or null")),
        }
    }

    fn int(&self, k: &str) -> Result<i128, String> {
        self.0
            .get(k)
            .and_then(Json::as_int)
            .ok_or_else(|| format!("`{k}` is an integer"))
    }

    fn strs(&self, k: &str) -> Result<Vec<String>, String> {
        self.0
            .get(k)
            .and_then(Json::as_array)
            .ok_or_else(|| format!("`{k}` is an array"))?
            .iter()
            .map(|x| x.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| format!("`{k}` holds strings"))
    }

    fn pairs(&self, k: &str) -> Result<Vec<(String, String)>, String> {
        self.0
            .get(k)
            .and_then(Json::as_object)
            .ok_or_else(|| format!("`{k}` is an object"))?
            .iter()
            .map(|(a, x)| x.as_str().map(|x| (a.clone(), x.to_string())))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| format!("`{k}` maps to strings"))
    }
}

fn read(line: &str, record: &str) -> Result<Fields, String> {
    let v = json::parse(line).map_err(|e| e.to_string())?;
    let f = Fields(v);
    let got = f.str("record")?;
    if got != record {
        return Err(format!("`record` is `{got}`, not `{record}`"));
    }
    Ok(f)
}

impl StepRecord {
    /// The record as one JSON line (no trailing newline).
    #[must_use]
    pub fn to_line(&self) -> String {
        Json::Object(vec![
            ("record".into(), s("step")),
            ("case".into(), s(&self.case)),
            ("book_variant".into(), s(&self.book_variant)),
            (
                "branch_class".into(),
                Json::opt_str(self.branch_class.as_deref()),
            ),
            (
                "filler_variant".into(),
                Json::opt_str(self.filler_variant.as_deref()),
            ),
            ("book_id".into(), Json::opt_str(self.book_id.as_deref())),
            ("step".into(), Json::Int(self.step)),
            ("reference".into(), s(&self.reference)),
            ("verb".into(), s(&self.verb)),
            ("argv_redacted".into(), strs(&self.argv_redacted)),
            ("exit".into(), Json::Int(self.exit)),
            (
                "refusal_id".into(),
                Json::opt_str(self.refusal_id.as_deref()),
            ),
            (
                "finding_procedure".into(),
                Json::opt_str(self.finding_procedure.as_deref()),
            ),
            (
                "certificate_kind".into(),
                Json::opt_str(self.certificate_kind.as_deref()),
            ),
            ("elapsed_ms".into(), Json::Int(self.elapsed_ms)),
            ("binds".into(), pairs(&self.binds)),
        ])
        .to_string()
    }

    /// Reads a line [`Self::to_line`] wrote.
    ///
    /// # Errors
    ///
    /// The field that is missing or of another type.
    pub fn parse_line(line: &str) -> Result<Self, String> {
        let f = read(line, "step")?;
        Ok(Self {
            case: f.str("case")?,
            book_variant: f.str("book_variant")?,
            branch_class: f.opt("branch_class")?,
            filler_variant: f.opt("filler_variant")?,
            book_id: f.opt("book_id")?,
            step: f.int("step")?,
            reference: f.str("reference")?,
            verb: f.str("verb")?,
            argv_redacted: f.strs("argv_redacted")?,
            exit: f.int("exit")?,
            refusal_id: f.opt("refusal_id")?,
            finding_procedure: f.opt("finding_procedure")?,
            certificate_kind: f.opt("certificate_kind")?,
            elapsed_ms: f.int("elapsed_ms")?,
            binds: f.pairs("binds")?,
        })
    }
}

impl VerdictRecord {
    /// The record as one JSON line (no trailing newline).
    #[must_use]
    pub fn to_line(&self) -> String {
        Json::Object(vec![
            ("record".into(), s("verdict")),
            ("case".into(), s(&self.case)),
            ("expectation".into(), s(&self.expectation)),
            ("type".into(), s(&self.kind)),
            ("book_variant".into(), s(&self.book_variant)),
            ("target".into(), Json::opt_str(self.target.as_deref())),
            ("cell".into(), s(&self.cell)),
            ("verdict".into(), s(self.verdict.as_str())),
            ("projection".into(), pairs(&self.projection)),
            ("witnesses".into(), pairs(&self.witnesses)),
            ("reason".into(), Json::opt_str(self.reason.as_deref())),
        ])
        .to_string()
    }

    /// Reads a line [`Self::to_line`] wrote.
    ///
    /// # Errors
    ///
    /// The field that is missing or of another type.
    pub fn parse_line(line: &str) -> Result<Self, String> {
        let f = read(line, "verdict")?;
        let verdict = f.str("verdict")?;
        Ok(Self {
            case: f.str("case")?,
            expectation: f.str("expectation")?,
            kind: f.str("type")?,
            book_variant: f.str("book_variant")?,
            target: f.opt("target")?,
            cell: f.str("cell")?,
            verdict: RowVerdict::parse(&verdict)
                .ok_or_else(|| format!("`verdict = \"{verdict}\"` is PASS, FAIL or UNRUN"))?,
            projection: f.pairs("projection")?,
            witnesses: f.pairs("witnesses")?,
            reason: f.opt("reason")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_and_verdict_records_round_trip_through_parse_line() {
        let step = StepRecord {
            case: "worldcom".into(),
            book_variant: "native".into(),
            branch_class: Some("bc-entry-class".into()),
            filler_variant: None,
            book_id: Some("0f3a9c".into()),
            step: 12,
            reference: "F4".into(),
            verb: "post".into(),
            argv_redacted: vec![
                "--book".into(),
                "$BOOK".into(),
                "post".into(),
                "--intent".into(),
                "F4.json".into(),
                "--json".into(),
            ],
            exit: 0,
            refusal_id: None,
            finding_procedure: None,
            certificate_kind: None,
            elapsed_ms: 41,
            binds: vec![("$F4".into(), "posted.vid of step 12".into())],
        };
        let line = step.to_line();
        assert!(line.starts_with("{\"record\":\"step\""), "{line}");
        assert!(!line.contains('\n'));
        assert_eq!(StepRecord::parse_line(&line), Ok(step));

        let verdict = VerdictRecord {
            case: "worldcom".into(),
            expectation: "W-P-03".into(),
            kind: "P".into(),
            book_variant: "native".into(),
            target: None,
            cell: "period_state_at_commit=Closed".into(),
            verdict: RowVerdict::Unrun,
            projection: vec![
                ("refusal".into(), "FA-REF-010".into()),
                ("ref".into(), "not_modelled".into()),
            ],
            witnesses: vec![("reference".into(), "unrun".into())],
            reason: Some("reference".into()),
        };
        let line = verdict.to_line();
        assert_eq!(VerdictRecord::parse_line(&line), Ok(verdict));
        // A step line is not a verdict record, and a bad verdict is refused.
        assert!(VerdictRecord::parse_line(&step_line_of(&line)).is_err());
        assert!(VerdictRecord::parse_line(&line.replace("\"UNRUN\"", "\"MAYBE\"")).is_err());
    }

    fn step_line_of(verdict_line: &str) -> String {
        verdict_line.replace("\"record\":\"verdict\"", "\"record\":\"step\"")
    }
}
