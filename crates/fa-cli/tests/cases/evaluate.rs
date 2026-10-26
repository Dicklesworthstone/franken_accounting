//! Row evaluation (docs/FORENSIC_CASE_STUDIES_PLAN.md §5, §16; bead
//! fa-yugf.15, A7a): each declared row of a variant, and its SELF row,
//! against what the run observed.
//!
//! A row is FAIL if any component it evaluates disagrees (`reason=expected
//! <x> observed <y>`), else UNRUN if a witness or prerequisite it requires
//! is not implemented (`reason=<witness>` or `reason=needs:<item> (<what>)`),
//! else PASS. In this skeleton every D row still lacks the filler-invariance
//! witness and every P row the reference oracle's verdict, so no row here
//! can read PASS.

use std::collections::{BTreeMap, BTreeSet};

use fa_oracles::cases::expect::{Expectation, ExpectationType, Status, Target};
use fa_oracles::cases::log::VerdictRecord;
use fa_oracles::cases::observe::ObservedError;
use fa_oracles::cases::remedy::{self, Cells, Check};
use fa_oracles::cases::selfrow;
use fa_oracles::cases::verdict::{RowLine, RowVerdict, cell_label};
use fa_oracles::cases::{Case, Expectations};
use fa_oracles::json::Json;
use fa_registry::refusal_catalog::RefusalCatalog;

use super::run::{BookRun, reproduce};

/// One evaluated row, with the `REPRODUCE` line a FAIL prints above it.
pub struct Evaluated {
    pub row: RowLine,
    pub record: VerdictRecord,
    pub reproduce: Option<String>,
}

/// The witness a D row still lacks when every component agrees.
const FILLER: &str = "filler_invariance";
/// The witness a P row still lacks when every component agrees.
const REFERENCE: &str = "reference";

/// The (expectation, target)'s effective type (A3b's retypes applied).
fn kind_of(case: &Case, e: &Expectation, target: Option<&str>) -> String {
    case.effective_type(&e.id, target)
        .unwrap_or(e.kind)
        .as_str()
        .to_string()
}

fn blank(id: &str, kind: &str, variant: &str, target: Option<&str>) -> RowLine {
    RowLine {
        verdict: RowVerdict::Pass,
        id: id.to_string(),
        kind: kind.to_string(),
        variant: variant.to_string(),
        target: target.map(str::to_string),
        cell: cell_label(&[]),
        projection: Vec::new(),
        reason: None,
    }
}

fn expectations(case: &Case) -> Option<&Expectations> {
    case.expectations.as_ref()
}

fn variant_of(e: &Expectation) -> Option<&str> {
    e.fields.str("book_variant")
}

/// `expected <x> observed <y>`.
fn mismatch(
    what: &str,
    expected: impl std::fmt::Display,
    observed: impl std::fmt::Display,
) -> String {
    format!("expected {what}={expected} observed {what}={observed}")
}

/// Every row a case declares, unevaluated (verdict PASS as a placeholder):
/// what a load failure marks FAIL.
pub fn declared_rows(case: &Case) -> Vec<RowLine> {
    let mut rows = Vec::new();
    if let Some(set) = expectations(case) {
        for e in &set.expectations {
            let variant = variant_of(e).unwrap_or("-");
            let targets: Vec<&Target> = set.targets_of(&e.id).collect();
            if targets.is_empty() {
                rows.push(blank(&e.id, e.kind.as_str(), variant, None));
            }
            for t in targets {
                rows.push(blank(&e.id, e.kind.as_str(), variant, Some(&t.fact)));
            }
        }
    }
    if let Ok(selfs) = selfrow::self_rows(case) {
        for r in selfs {
            rows.push(blank(&r.id, "D", &r.variant, None));
        }
    }
    rows
}

/// Each expectation's verdict: the worst of its rows (§5; what `claims`
/// reads).
pub fn expectation_verdicts(records: &[VerdictRecord]) -> BTreeMap<String, RowVerdict> {
    let mut out: BTreeMap<String, Vec<RowVerdict>> = BTreeMap::new();
    for r in records {
        out.entry(r.expectation.clone())
            .or_default()
            .push(r.verdict);
    }
    out.into_iter()
        .map(|(id, rows)| (id, RowVerdict::worst(rows)))
        .collect()
}

type Eval = (RowLine, Vec<(String, String)>, Option<String>);

fn finish(case: &Case, (mut row, witnesses, reproduce): Eval) -> Evaluated {
    if row.verdict == RowVerdict::Pass {
        row.reason = None;
    }
    let record = VerdictRecord {
        case: case.header.id.clone(),
        expectation: row.id.clone(),
        kind: row.kind.clone(),
        book_variant: row.variant.clone(),
        target: row.target.clone(),
        cell: row.cell.clone(),
        verdict: row.verdict,
        projection: row.projection.clone(),
        witnesses,
        reason: row.reason.clone(),
    };
    Evaluated {
        row,
        record,
        reproduce,
    }
}

/// The item that implements a step kind the runner does not run yet
/// (plan §15).
fn owner_of(kind: &str) -> &'static str {
    match kind {
        "issue" => "A7b",
        k if k.starts_with("case_") || k.starts_with("scenario_") => "A7b",
        "filler_batch" => "A6",
        "migrate_open" | "migrate_stage" | "migrate_finalize" => "A7m",
        "checkpoint" | "checkpoint_witness" => "A8a",
        _ => "A7a",
    }
}

/// The variant-level gates, `Some` when one applies: a setup failure fails
/// every row, and a step kind the runner does not run leaves every row
/// UNRUN.
fn gate(run: &BookRun<'_>, row: &RowLine) -> Option<Eval> {
    let mut row = row.clone();
    if let Some(f) = &run.failure {
        row.verdict = RowVerdict::Fail;
        row.reason = Some(f.clone());
        return Some((row, Vec::new(), None));
    }
    let kind = run.unrun_steps.first()?;
    row.verdict = RowVerdict::Unrun;
    row.reason = Some(format!("needs:{} ({kind} step)", owner_of(kind)));
    Some((row, Vec::new(), None))
}

/// Every row of `run`'s variant, in declaration order, then its SELF row.
pub fn rows(run: &BookRun<'_>) -> Vec<Evaluated> {
    let case = run.case;
    let variant = run.book.stem.as_str();
    let mut out = Vec::new();
    if let Some(set) = expectations(case) {
        for e in set
            .expectations
            .iter()
            .filter(|e| variant_of(e) == Some(variant))
        {
            let targets: Vec<&Target> = set.targets_of(&e.id).collect();
            let mut slots: Vec<Option<&Target>> = targets.iter().copied().map(Some).collect();
            if slots.is_empty() {
                slots.push(None);
            }
            for t in slots {
                let fact = t.map(|t| t.fact.as_str());
                let row = blank(&e.id, &kind_of(case, e, fact), variant, fact);
                let eval = match gate(run, &row) {
                    Some(gated) => gated,
                    None => match (e.kind, t) {
                        (ExpectationType::D, Some(t)) => d_row(run, e, t, row),
                        (ExpectationType::P, None) => p_row(run, e, row),
                        (other, _) => {
                            let mut row = row;
                            row.verdict = RowVerdict::Unrun;
                            row.reason = Some(format!("needs:A7b ({} evaluation)", other.as_str()));
                            (row, Vec::new(), None)
                        }
                    },
                };
                out.push(finish(case, eval));
            }
        }
    }
    out.push(self_row(run));
    out
}

/// The fact or intent `subject` as the intent id it posted as, when that is
/// unambiguous.
pub fn intent_of(run: &BookRun<'_>, subject: &str) -> String {
    if run.book.intents.iter().any(|i| i.id == subject) {
        return subject.to_string();
    }
    let by_fact: Vec<&str> = run
        .book
        .intents
        .iter()
        .filter(|i| i.fact == subject)
        .map(|i| i.id.as_str())
        .collect();
    match by_fact.as_slice() {
        [one] => (*one).to_string(),
        _ => subject.to_string(),
    }
}

/// An expected cite in projection form: `<intent>#<ordinal>` or an account
/// code.
fn expected_cite(run: &BookRun<'_>, cite: &str) -> String {
    match cite.split_once('#') {
        Some((subject, ordinal)) => format!("{}#{ordinal}", intent_of(run, subject)),
        None => cite.to_string(),
    }
}

/// A finding's typed cites projected (§5.2 rule 1): the cited entry to its
/// intent, legs to `<intent>#<[[leg]] ordinal>`, accounts to codes. An
/// unmapped handle projects to `?<kind>`, never to a storage identifier.
pub struct Projected {
    pub entries: BTreeSet<String>,
    pub cites: BTreeSet<String>,
}

pub fn project(run: &BookRun<'_>, finding: &Json) -> Projected {
    let mut p = Projected {
        entries: BTreeSet::new(),
        cites: BTreeSet::new(),
    };
    let intent_of_vid = |vid: &str| {
        run.vids
            .iter()
            .find(|(_, v)| v.as_str() == vid)
            .map(|(i, _)| i.clone())
    };
    for c in finding.get("cites").and_then(Json::as_array).unwrap_or(&[]) {
        let kind = c.get("kind").and_then(Json::as_str).unwrap_or("?");
        let entry = c.get("entry").and_then(Json::as_str);
        match kind {
            "entry" => {
                p.entries.insert(
                    entry
                        .and_then(intent_of_vid)
                        .unwrap_or_else(|| "?entry".into()),
                );
            }
            "leg" => {
                let ordinal = c.get("ordinal").and_then(Json::as_int);
                let leg = entry
                    .zip(ordinal)
                    .and_then(|(e, o)| run.legs.get(&(e.to_string(), o)).cloned());
                p.cites.insert(leg.unwrap_or_else(|| "?leg".into()));
            }
            "account" => {
                let code = c
                    .get("account")
                    .and_then(Json::as_str)
                    .and_then(|v| run.accounts.get(v).cloned());
                p.cites.insert(code.unwrap_or_else(|| "?account".into()));
            }
            other => {
                p.cites.insert(format!("?{other}"));
            }
        }
    }
    p
}

fn joined(set: &BTreeSet<String>) -> String {
    if set.is_empty() {
        "-".into()
    } else {
        set.iter().cloned().collect::<Vec<_>>().join(",")
    }
}

const fn single(status: &Status) -> bool {
    matches!(status, Status::S | Status::Sd | Status::Si)
}

fn int_text(v: Option<i128>) -> String {
    v.map_or_else(|| "-".into(), |v| v.to_string())
}

/// A candidate finding's disagreements with its target, and its projection
/// tokens.
type Compared = (Vec<String>, Vec<(String, String)>);

/// One candidate finding's projection and its disagreements with the
/// target.
fn compare(
    p: &fa_oracles::cases::expect::Projection,
    want_cites: &BTreeSet<String>,
    pr: &Projected,
    f: &Json,
) -> Compared {
    let mut diff = Vec::new();
    let mut proj = Vec::new();
    let cites = joined(&pr.cites);
    if single(&p.cite.status) && pr.cites != *want_cites {
        diff.push(mismatch("cite", joined(want_cites), &cites));
    }
    proj.push(("cite".into(), cites));
    let severity = f
        .get("severity")
        .and_then(Json::as_str)
        .unwrap_or("-")
        .to_string();
    let want_severity = p.severity.value.as_deref().unwrap_or("-");
    if single(&p.severity.status) && severity != want_severity {
        diff.push(mismatch("severity", want_severity, &severity));
    }
    proj.push(("severity".into(), severity));
    let stat = f.get("statistic");
    let field = |k: &str| stat.and_then(|s| s.get(k));
    let name = field("name")
        .and_then(Json::as_str)
        .unwrap_or("-")
        .to_string();
    let value = int_text(field("value").and_then(Json::as_int));
    let scale = int_text(field("scale").and_then(Json::as_int));
    if single(&p.statistic.status) {
        if let Some(want) = &p.statistic_name
            && *want != name
        {
            diff.push(mismatch("statistic_name", want, &name));
        }
        let want_value = p.statistic.value.as_deref().unwrap_or("-");
        if value != want_value {
            diff.push(mismatch("statistic", want_value, &value));
        }
        if let Some(want) = p.statistic_scale
            && scale != want.to_string()
        {
            diff.push(mismatch("scale", want, &scale));
        }
    }
    proj.push(("statistic_name".into(), name));
    proj.push(("statistic".into(), value));
    proj.push(("scale".into(), scale));
    (diff, proj)
}

/// A D row (§5.4): the run of the row's procedure@version, the finding
/// citing the target's entry, and its cites, severity and statistic.
fn d_row(run: &BookRun<'_>, e: &Expectation, t: &Target, mut row: RowLine) -> Eval {
    let Some(p) = t.projection(e) else {
        row.verdict = RowVerdict::Fail;
        row.reason = Some("expected a D projection observed none".into());
        return (row, Vec::new(), None);
    };
    row.projection
        .push(("procedure".into(), format!("{}@{}", p.procedure, p.version)));
    for (status, what) in [
        (&p.cite.status, "cite"),
        (&p.severity.status, "severity"),
        (&p.statistic.status, "statistic"),
    ] {
        let needs = match status {
            Status::B(_) => Some(format!("needs:A7c ({what} branch cells)")),
            Status::Rel(cov) => Some(format!("needs:A7b ({what} relative to {cov})")),
            _ => None,
        };
        if let Some(needs) = needs {
            row.verdict = RowVerdict::Unrun;
            row.reason = Some(needs);
            return (row, Vec::new(), None);
        }
    }
    let Some(found) = run.runs.get(&p.procedure) else {
        row.verdict = RowVerdict::Fail;
        row.reason = Some(format!(
            "expected a recorded run of {} observed none",
            p.procedure
        ));
        return (row, Vec::new(), None);
    };
    let mut fails = Vec::new();
    if found.version != Some(p.version) {
        fails.push(mismatch("version", p.version, int_text(found.version)));
    }
    let subject = intent_of(run, &t.fact);
    row.projection.push(("entry".into(), subject.clone()));
    let want_cites: BTreeSet<String> = p
        .cite
        .value
        .as_deref()
        .unwrap_or_default()
        .split(',')
        .filter(|c| !c.is_empty())
        .map(|c| expected_cite(run, c))
        .collect();
    // The candidate citing the target's entry with the fewest
    // disagreements is the one compared.
    let mut candidates = 0usize;
    let mut best: Option<Compared> = None;
    for f in &found.findings {
        let pr = project(run, f);
        if !pr.entries.contains(&subject) {
            continue;
        }
        candidates += 1;
        let (diff, proj) = compare(&p, &want_cites, &pr, f);
        if best.as_ref().is_none_or(|(d, _)| diff.len() < d.len()) {
            best = Some((diff, proj));
        }
    }
    let witnesses = vec![
        ("findings".to_string(), found.findings.len().to_string()),
        ("candidates".to_string(), candidates.to_string()),
    ];
    match best {
        None => fails.push(format!(
            "expected a {} finding citing {subject} observed none",
            p.procedure
        )),
        Some((diff, proj)) => {
            row.projection.extend(proj);
            fails.extend(diff);
        }
    }
    if fails.is_empty() {
        row.verdict = RowVerdict::Unrun;
        row.reason = Some(FILLER.into());
    } else {
        row.verdict = RowVerdict::Fail;
        row.reason = Some(fails.join("; "));
    }
    (row, witnesses, None)
}

/// Whether a refusal's `fix.argv` (after `fa`) parses against the verb it
/// names, with the global and the verb's registered flags.
fn argv_parses(argv: &[String]) -> bool {
    let Ok(reg) = fa_cli::verbs::registry() else {
        return false;
    };
    let Some(verb) = argv
        .first()
        .and_then(|n| reg.verbs.iter().find(|v| v.name == *n))
    else {
        return false;
    };
    let flags: Vec<&str> = reg
        .global
        .flags
        .iter()
        .chain(&verb.flags)
        .map(String::as_str)
        .collect();
    let switches: Vec<&str> = reg
        .global
        .switches
        .iter()
        .chain(&verb.switches)
        .map(String::as_str)
        .collect();
    let Ok(args) = fa_cli::args::parse(argv, &flags, &switches) else {
        return false;
    };
    verb.subcommands.is_empty()
        || verb.default_subcommand.is_some()
        || args
            .positional
            .get(1)
            .is_some_and(|s| verb.subcommands.contains(s))
}

/// A P row (§5.2): the observed refusal id and exit against the catalog,
/// the law row named, and the structured remedy.
fn p_row(run: &BookRun<'_>, e: &Expectation, mut row: RowLine) -> Eval {
    let f = &e.fields;
    let (Some(intent), Some(refusal), Some(law_row)) =
        (f.str("intent"), f.str("refusal"), f.str("law_row"))
    else {
        row.verdict = RowVerdict::Fail;
        row.reason =
            Some("expected intent, refusal and law_row observed a P row lacking one".into());
        return (row, Vec::new(), None);
    };
    row.projection.push(("law".into(), law_row.to_string()));
    let Some(call) = run.posts.get(intent) else {
        row.verdict = RowVerdict::Fail;
        row.reason = Some(format!("expected a post of {intent} observed none"));
        return (row, Vec::new(), None);
    };
    let mut fails = Vec::new();
    let observed = call.refusal_id();
    let observed_text = observed.clone().unwrap_or_else(|| "admitted".into());
    row.projection
        .push(("refusal".into(), observed_text.clone()));
    row.projection.push(("exit".into(), call.exit.to_string()));
    if observed.as_deref() != Some(refusal) {
        fails.push(mismatch("refusal", refusal, &observed_text));
    }
    match RefusalCatalog::embedded() {
        Ok(cat) => match cat.by_code(refusal) {
            Some(r) if i32::from(r.exit) == call.exit => {}
            Some(r) => fails.push(mismatch("exit", r.exit, call.exit)),
            None => fails.push(format!(
                "expected {refusal} in refusal_catalog.toml observed no row"
            )),
        },
        Err(err) => fails.push(format!("expected refusal_catalog.toml observed {err:?}")),
    }
    let error: Option<&ObservedError> = call.event("error").and_then(|o| o.error.as_ref());
    if let Some(err) = error {
        let named = remedy::law_named(law_row, err);
        row.projection
            .push(("law_named".into(), if named { "ok" } else { "fail" }.into()));
        if !named {
            fails.push(format!(
                "expected the refusal to name {law_row} observed no such cite"
            ));
        }
        match (&err.refusal, Cells::embedded()) {
            (Some(r), Ok(cells)) => {
                for (name, value) in remedy::check(law_row, r, &cells, &argv_parses).tokens() {
                    if value == Check::Fail.as_str() {
                        fails.push(mismatch(&name, "ok", "fail"));
                    }
                    row.projection.push((name, value));
                }
            }
            (None, _) => fails.push("expected a refusal object observed none".into()),
            (_, Err(why)) => fails.push(format!("expected admissibility.toml observed {why}")),
        }
    } else if observed.is_some() {
        fails.push("expected an error event observed none".into());
    }
    let witnesses = vec![("exit".to_string(), call.exit.to_string())];
    if fails.is_empty() {
        row.verdict = RowVerdict::Unrun;
        row.reason = Some(REFERENCE.into());
        (row, witnesses, None)
    } else {
        row.verdict = RowVerdict::Fail;
        row.reason = Some(fails.join("; "));
        (row, witnesses, Some(reproduce(call)))
    }
}

/// The variant's SELF row (§2.7): `jet.self_sourced_evidence` cites every
/// posting that cites a reviewed citation stub, at severity Medium.
fn self_row(run: &BookRun<'_>) -> Evaluated {
    let case = run.case;
    let id = format!("{}-SELF-{}", selfrow::prefix(case), run.book.stem);
    let mut row = blank(&id, "D", &run.book.stem, None);
    if let Some(gated) = gate(run, &row) {
        return finish(case, gated);
    }
    let version = selfrow::version();
    row.projection.push((
        "procedure".into(),
        format!(
            "{}@{}",
            selfrow::PROCEDURE,
            version
                .as_ref()
                .map_or_else(|_| "-".into(), ToString::to_string)
        ),
    ));
    let reviewed: BTreeSet<&str> = run
        .book
        .documents
        .iter()
        .filter(|d| d.reviewed_by.as_deref().is_some_and(|r| !r.is_empty()))
        .map(|d| d.id.as_str())
        .collect();
    // Postings whose only document is a reviewed stub are cited at Medium.
    // An Allocation also cites the driver workpaper `fa allocate` uploads
    // under its poster's default grade (HumanUpload for a Human, not
    // self-sourced: `ensure_allocation_driver_imported`), so it is outside
    // the procedure's population and the row claims nothing of it.
    let cites_reviewed = |i: &&fa_oracles::cases::book::IntentDef| {
        run.vids.contains_key(&i.id) && i.evidence.as_deref().is_some_and(|d| reviewed.contains(d))
    };
    let expected: BTreeSet<String> = run
        .book
        .intents
        .iter()
        .filter(cites_reviewed)
        .filter(|i| i.class != "Allocation")
        .map(|i| i.id.clone())
        .collect();
    let allocations: BTreeSet<String> = run
        .book
        .intents
        .iter()
        .filter(cites_reviewed)
        .filter(|i| i.class == "Allocation")
        .map(|i| i.id.clone())
        .collect();
    row.projection.push(("entries".into(), joined(&expected)));
    row.projection.push(("severity".into(), "Medium".into()));
    if !allocations.is_empty() {
        row.projection
            .push(("outside".into(), joined(&allocations)));
    }
    let mut fails = Vec::new();
    match &run.self_run {
        None => fails.push("expected a procedure run observed none".into()),
        Some(Err(why)) => fails.push(why.clone()),
        Some(Ok(findings)) => {
            let medium: BTreeSet<String> = findings
                .iter()
                .filter(|f| f.get("severity").and_then(Json::as_str) == Some("Medium"))
                .flat_map(|f| project(run, f).entries)
                .collect();
            let missing: BTreeSet<String> = expected.difference(&medium).cloned().collect();
            if !missing.is_empty() {
                fails.push(format!(
                    "expected Medium findings citing {} observed none citing {}",
                    joined(&expected),
                    joined(&missing)
                ));
            }
        }
    }
    if let Err(why) = version {
        fails.push(format!("expected a registered version observed {why}"));
    }
    if fails.is_empty() {
        row.verdict = RowVerdict::Unrun;
        row.reason = Some(FILLER.into());
    } else {
        row.verdict = RowVerdict::Fail;
        row.reason = Some(fails.join("; "));
    }
    finish(case, (row, Vec::new(), None))
}
