//! Robot lines of the `fa` binary as observations (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.1, §3.3; bead fa-yugf.15, A7a).
//!
//! Robot mode prints one JSON object per stdout line, the envelope `{v,
//! event, book, coordinate, data, certificate, authority, warnings,
//! next_actions}` (`registries/verbs.toml` `[envelope]`). The runner turns
//! each line into an [`Observation`] with this crate's own JSON reader. A
//! non-zero exit emits exactly one `error` event, kept as [`ObservedError`]
//! with the Appendix D refusal object when the failure is a catalog refusal.

use core::fmt;

use crate::json::{self, Json};

/// The envelope's coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Coordinate {
    pub branch: Option<String>,
    pub known_at: Option<i128>,
    pub effective: Option<String>,
}

/// One robot line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub event: String,
    pub book: Option<String>,
    pub coordinate: Option<Coordinate>,
    /// The event's own fields (`data`).
    pub data: Json,
    pub certificate: Option<String>,
    pub error: Option<ObservedError>,
}

/// An `error` event's fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedError {
    pub class: String,
    pub exit: i128,
    pub refusal_id: Option<String>,
    pub message: String,
    pub cite: Option<String>,
    pub fix: Option<String>,
    pub refusal: Option<ObservedRefusal>,
}

/// The Appendix D refusal object (`refusal_object` in `verbs.toml`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedRefusal {
    pub id: String,
    pub code: String,
    pub exit: i128,
    /// `{law}`, `{policy}`, `{matrix: {state, class}}` or `{cite}`.
    pub why: Json,
    /// `fix.argv`: the first parseable `fa` command the fix names, after
    /// `fa`; `None` when the fix names none (`null`).
    pub fix_argv: Option<Vec<String>>,
    /// `fix.text`: the fix in prose.
    pub fix_text: Option<String>,
    pub alternatives: Vec<String>,
}

impl ObservedRefusal {
    /// `why.matrix` as (state, class), when the refusing site set it.
    #[must_use]
    pub fn matrix(&self) -> Option<(&str, &str)> {
        let m = self.why.get("matrix")?;
        Some((m.get("state")?.as_str()?, m.get("class")?.as_str()?))
    }

    /// `why.cite`, the prose citation, when that is the `why`.
    #[must_use]
    pub fn cite(&self) -> Option<&str> {
        self.why.get("cite")?.as_str()
    }
}

/// Why a line is not a robot observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObserveError {
    Json(json::JsonError),
    /// A required envelope or event field is missing or has another type.
    Shape(String),
}

impl fmt::Display for ObserveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "{e}"),
            Self::Shape(why) => write!(f, "not a robot envelope: {why}"),
        }
    }
}

impl core::error::Error for ObserveError {}

fn shape(why: impl Into<String>) -> ObserveError {
    ObserveError::Shape(why.into())
}

fn opt_str(v: Option<&Json>, field: &str) -> Result<Option<String>, ObserveError> {
    match v {
        None | Some(Json::Null) => Ok(None),
        Some(Json::Str(s)) => Ok(Some(s.clone())),
        Some(_) => Err(shape(format!("`{field}` is a string or null"))),
    }
}

impl Observation {
    /// Reads one robot line.
    ///
    /// # Errors
    ///
    /// [`ObserveError`]: not JSON, not an object with an `event` string, or
    /// an `error` event without its `class`, `exit` or `message`.
    pub fn from_robot_line(line: &str) -> Result<Self, ObserveError> {
        let v = json::parse(line).map_err(ObserveError::Json)?;
        if v.as_object().is_none() {
            return Err(shape("a robot line is one JSON object"));
        }
        let event = v
            .get("event")
            .and_then(Json::as_str)
            .ok_or_else(|| shape("no `event` string"))?
            .to_string();
        let coordinate = match v.get("coordinate") {
            None | Some(Json::Null) => None,
            Some(c) => Some(Coordinate {
                branch: opt_str(c.get("branch"), "coordinate.branch")?,
                known_at: c.get("known_at").and_then(Json::as_int),
                effective: opt_str(c.get("effective"), "coordinate.effective")?,
            }),
        };
        let data = v.get("data").cloned().unwrap_or(Json::Null);
        let error = if event == "error" {
            Some(Self::error_of(&data)?)
        } else {
            None
        };
        Ok(Self {
            event,
            book: opt_str(v.get("book"), "book")?,
            coordinate,
            certificate: opt_str(v.get("certificate"), "certificate")?,
            data,
            error,
        })
    }

    fn error_of(data: &Json) -> Result<ObservedError, ObserveError> {
        let refusal = match data.get("refusal") {
            None | Some(Json::Null) => None,
            Some(r) => Some(ObservedRefusal {
                id: r
                    .get("id")
                    .and_then(Json::as_str)
                    .ok_or_else(|| shape("refusal.id"))?
                    .to_string(),
                code: r
                    .get("code")
                    .and_then(Json::as_str)
                    .ok_or_else(|| shape("refusal.code"))?
                    .to_string(),
                exit: r
                    .get("exit")
                    .and_then(Json::as_int)
                    .ok_or_else(|| shape("refusal.exit"))?,
                why: r.get("why").cloned().unwrap_or(Json::Null),
                fix_argv: match r.at(&["fix", "argv"]) {
                    None | Some(Json::Null) => None,
                    Some(Json::Array(items)) => Some(
                        items
                            .iter()
                            .map(|a| a.as_str().map(str::to_string))
                            .collect::<Option<Vec<_>>>()
                            .ok_or_else(|| shape("refusal.fix.argv is strings"))?,
                    ),
                    Some(_) => return Err(shape("refusal.fix.argv is an array or null")),
                },
                fix_text: opt_str(r.at(&["fix", "text"]), "refusal.fix.text")?,
                alternatives: r
                    .get("alternatives")
                    .and_then(Json::as_array)
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|a| a.as_str().map(str::to_string))
                    .collect(),
            }),
        };
        Ok(ObservedError {
            class: data
                .get("class")
                .and_then(Json::as_str)
                .ok_or_else(|| shape("error.class"))?
                .to_string(),
            exit: data
                .get("exit")
                .and_then(Json::as_int)
                .ok_or_else(|| shape("error.exit"))?,
            refusal_id: opt_str(data.get("refusal_id"), "error.refusal_id")?,
            message: data
                .get("message")
                .and_then(Json::as_str)
                .ok_or_else(|| shape("error.message"))?
                .to_string(),
            cite: opt_str(data.get("cite"), "error.cite")?,
            fix: opt_str(data.get("fix"), "error.fix")?,
            refusal,
        })
    }

    /// Every robot line of a command's stdout, in order; blank lines are
    /// skipped.
    ///
    /// # Errors
    ///
    /// The first line that is not an observation, with its 1-based number.
    pub fn from_stdout(stdout: &str) -> Result<Vec<Self>, (usize, ObserveError)> {
        stdout
            .lines()
            .enumerate()
            .filter(|(_, l)| !l.trim().is_empty())
            .map(|(i, l)| Self::from_robot_line(l).map_err(|e| (i + 1, e)))
            .collect()
    }

    /// A field of the event's `data`.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&Json> {
        self.data.get(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lines shaped by `registries/verbs.toml`'s events and envelope
    /// (`posted`, `plan` with its legs, `error` with an Appendix D refusal,
    /// `procedure_run` with a finding); the values are synthetic.
    const POSTED: &str = r#"{"authority":{"ops":null,"posture":"embedded-owner","principal":null,"profile":"Human"},"book":"0f3a9c","certificate":null,"coordinate":{"branch":"trunk","effective":"head","known_at":14},"data":{"class":"Original","entry_digest":"aa01","moved":null,"period":"FY2001-P02","recorded_at":14,"requested":null,"vid":"7e2b"},"event":"posted","next_actions":[],"v":1,"warnings":[]}"#;
    const PLAN: &str = r#"{"authority":{"ops":null,"posture":"embedded-owner","principal":null,"profile":"Human"},"book":"0f3a9c","certificate":null,"coordinate":{"branch":"trunk","effective":"head","known_at":13},"data":{"class":"Original","effective_date":"2001-06-30","legs":[{"account":"1500","account_vid":"91","amount":"560000000.00 USD","ordinal":0,"side":"debit"},{"account":"6100","account_vid":"92","amount":"560000000.00 USD","ordinal":1,"side":"credit"}],"period":"FY2001-P02","plan_digest":"cc","snapshot_seq":13},"event":"plan","next_actions":[],"v":1,"warnings":[]}"#;
    const ERROR: &str = r#"{"authority":{"ops":null,"posture":"embedded-owner","principal":null,"profile":"Human"},"book":"0f3a9c","certificate":null,"coordinate":{"branch":"trunk","effective":"head","known_at":14},"data":{"cite":"admissibility.toml Original/Closed","class":"safety","detail":null,"exit":7,"fix":"fa post --intent adj.json --class Adjusting","message":"the period is Closed","refusal":{"alternatives":["fa period reopen FY2001-P02"],"code":"FA-REF-010","docs":"fa explain refusal FA-REF-010","exit":7,"fix":{"argv":["post","--intent","adj.json"],"command":"fa post --intent adj.json","or_field_change":null,"rerun_with":null,"text":"post an Adjusting entry"},"id":"FA-REF-010:0123456789abcdef","what_failed":"posting law","where":{"period":"FY2001-P02"},"why":{"matrix":{"class":"Original","state":"Closed"}}},"refusal_id":"FA-REF-010"},"event":"error","next_actions":[],"v":1,"warnings":[]}"#;
    const RUN: &str = r#"{"authority":{"ops":null,"posture":"embedded-owner","principal":null,"profile":"Human"},"book":"0f3a9c","certificate":null,"coordinate":{"branch":"trunk","effective":"head","known_at":20},"data":{"claim":"statistical","evidence":"FA-EVID-L48","finding_count":1,"findings":[{"cites":[{"entry":"7e2b"},{"leg":{"entry":"7e2b","ordinal":0}}],"narrative":"entry capitalizes","severity":"High","statistic":{"name":"capitalized_expense_amount","population":4,"scale":2,"value":"56000000000"}}],"known_at":20,"procedure":"expense.capitalization","version":2},"event":"procedure_run","next_actions":[],"v":1,"warnings":[]}"#;

    #[test]
    fn observation_parses_posted_plan_error_and_procedure_run_lines() {
        let posted = Observation::from_robot_line(POSTED).expect("posted");
        assert_eq!(posted.event, "posted");
        assert_eq!(posted.book.as_deref(), Some("0f3a9c"));
        assert_eq!(
            posted.coordinate.as_ref().and_then(|c| c.known_at),
            Some(14)
        );
        assert_eq!(posted.field("vid").and_then(Json::as_str), Some("7e2b"));
        assert!(posted.error.is_none());

        let plan = Observation::from_robot_line(PLAN).expect("plan");
        let legs = plan.field("legs").and_then(Json::as_array).expect("legs");
        let ordinals: Vec<i128> = legs
            .iter()
            .filter_map(|l| l.get("ordinal").and_then(Json::as_int))
            .collect();
        assert_eq!(ordinals, [0, 1]);

        let err = Observation::from_robot_line(ERROR).expect("error");
        let e = err.error.as_ref().expect("an error event");
        assert_eq!((e.class.as_str(), e.exit), ("safety", 7));
        assert_eq!(e.refusal_id.as_deref(), Some("FA-REF-010"));
        let r = e.refusal.as_ref().expect("a refusal object");
        assert_eq!(r.matrix(), Some(("Closed", "Original")));
        assert_eq!(
            r.fix_argv.as_deref(),
            Some(
                [
                    "post".to_string(),
                    "--intent".to_string(),
                    "adj.json".to_string()
                ]
                .as_slice()
            )
        );
        assert_eq!(r.alternatives, ["fa period reopen FY2001-P02"]);

        let run = Observation::from_robot_line(RUN).expect("procedure_run");
        assert_eq!(run.field("finding_count").and_then(Json::as_int), Some(1));
        let all = Observation::from_stdout(&format!("{PLAN}\n\n{POSTED}\n")).expect("two lines");
        assert_eq!(
            all.iter().map(|o| o.event.as_str()).collect::<Vec<_>>(),
            ["plan", "posted"]
        );
        // An error event without its class is refused.
        let broken = ERROR.replace("\"class\":\"safety\",", "");
        assert!(Observation::from_robot_line(&broken).is_err());
        assert!(Observation::from_stdout("{\"v\":1}\n").is_err_and(|(n, _)| n == 1));
    }
}
