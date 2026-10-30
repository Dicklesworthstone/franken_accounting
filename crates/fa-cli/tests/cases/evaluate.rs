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

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use fa_oracles::cases::amount::{format_amount, parse_amount};
use fa_oracles::cases::book::{CaseDef, StepKind, VariantKind};
use fa_oracles::cases::contrib::{ContribVerdict, cross_check, named_inputs, witness};
use fa_oracles::cases::expect::{Expectation, ExpectationType, Status, Target};
use fa_oracles::cases::log::VerdictRecord;
use fa_oracles::cases::observe::ObservedError;
use fa_oracles::cases::reference::{CellSetting, LiveEntry, RefVerdict, ReferenceAdapter};
use fa_oracles::cases::rel;
use fa_oracles::cases::remedy::{self, Cells, Check};
use fa_oracles::cases::selfrow;
use fa_oracles::cases::status::{ComponentVerdict, ObservedD, evaluate_d};
use fa_oracles::cases::verdict::{RowLine, RowVerdict, cell_label};
use fa_oracles::cases::{Case, Expectations};
use fa_oracles::json::Json;
use fa_registry::procedures::Procedures;
use fa_registry::refusal_catalog::RefusalCatalog;

use fa_oracles::cases::twin::{TwinExpect, TwinKind, TwinSpec};

use super::run::{BookRun, FindingRun, reproduce};

thread_local! {
    /// Test-only: drop one later entry from each `fa certificate status`
    /// observation (the negative; the binary reports every entry).
    pub static DROP_LATER_ENTRY: Cell<bool> = const { Cell::new(false) };
}

/// One evaluated row, with the `REPRODUCE` line a FAIL prints above it.
pub struct Evaluated {
    pub row: RowLine,
    pub record: VerdictRecord,
    pub reproduce: Option<String>,
}

/// The witness a D, P or N row still lacks when every component agrees
/// (A11a); a P row reaches it only once the reference oracle agrees (A4r).
pub(crate) const FILLER: &str = "filler_invariance";

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
            // An N is one row whatever its sourced-value targets (A11c).
            let targets: Vec<&Target> = if e.kind == ExpectationType::N {
                Vec::new()
            } else {
                set.targets_of(&e.id).collect()
            };
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

pub(crate) type Eval = (RowLine, Vec<(String, String)>, Option<String>);

pub(crate) fn finish(case: &Case, (mut row, witnesses, reproduce): Eval) -> Evaluated {
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
pub fn rows(
    run: &BookRun<'_>,
    specs: &[(String, Result<TwinSpec, String>)],
    twins: &BTreeMap<String, BookRun<'_>>,
) -> Vec<Evaluated> {
    let case = run.case;
    let variant = run.book.stem.as_str();
    let mut out = Vec::new();
    if let Some(set) = expectations(case) {
        for e in set
            .expectations
            .iter()
            .filter(|e| variant_of(e) == Some(variant))
        {
            // A CF of a P parent decided cell by cell is one of the parent
            // entry's swept cells (A5b, A7c).
            let swept_parent = e
                .fields
                .str("parent")
                .and_then(|p| set.get(p))
                .is_some_and(|p| {
                    p.kind == ExpectationType::P && set.targets_of(&p.id).any(has_branch_table)
                });
            if e.kind == ExpectationType::Cf && swept_parent {
                continue;
            }
            // An N is one row: its `[[target]]` rows state an exact_gap N's
            // sourced values, read by n_row (A11c).
            let targets: Vec<&Target> = if e.kind == ExpectationType::N {
                Vec::new()
            } else {
                set.targets_of(&e.id).collect()
            };
            let mut slots: Vec<Option<&Target>> = targets
                .iter()
                .copied()
                // A P or D target with a branch table is evaluated cell by
                // cell (A7c).
                .filter(|t| {
                    !matches!(e.kind, ExpectationType::P | ExpectationType::D)
                        || !has_branch_table(t)
                })
                .map(Some)
                .collect();
            if slots.is_empty() && !targets.is_empty() {
                continue;
            }
            if slots.is_empty() {
                slots.push(None);
            }
            for t in slots {
                // An N names its target in its own `target` field.
                let fact = t.map(|t| t.fact.as_str()).or_else(|| {
                    (e.kind == ExpectationType::N)
                        .then(|| e.fields.str("target"))
                        .flatten()
                });
                let row = blank(&e.id, &kind_of(case, e, fact), variant, fact);
                let eval = match gate(run, &row) {
                    Some(gated) => gated,
                    None => match (e.kind, t) {
                        (ExpectationType::D, Some(t)) => d_row(run, e, t, row),
                        (ExpectationType::P, None) => p_row(run, e, row),
                        (ExpectationType::T, t) => t_row(run, e, t, row),
                        (ExpectationType::R, t) => r_row(run, e, t, row),
                        (ExpectationType::N, None) => {
                            let spec = specs.iter().find(|(id, _)| *id == e.id).map(|(_, s)| s);
                            n_row(run, e, spec, twins.get(&e.id), row)
                        }
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
            if e.kind == ExpectationType::D && fa_oracles::cases::status::closed_cites(e) {
                out.extend(unexpected_cite_rows(run, e));
            }
        }
    }
    out.extend(case_rows(run));
    out.push(self_row(run));
    out
}

/// The runner's read-back row of each `[[case]]` (§3.3 step 5),
/// `<case>-CASE-<case id>`: `fa case show` after the history must report the
/// case Closed, of its row's kind, determined on its sourced or declared day
/// under its authority document, and disclosed under a reviewed document;
/// the disclosure's unreviewed twin was refused FA-REF-179, one approval
/// alone was refused FA-REF-012 and left the case Rehearsed, each delta
/// posted outside its case was refused FA-REF-178, and each restated
/// target's lineage names Restates. A history with no `case_close` step for
/// the case leaves the row UNRUN, never PASS.
fn case_rows(run: &BookRun<'_>) -> Vec<Evaluated> {
    let case = run.case;
    run.book
        .cases
        .iter()
        .map(|c| {
            let id = format!("{}-CASE-{}", selfrow::prefix(case), c.id);
            let mut row = blank(&id, "R", &run.book.stem, None);
            if let Some(gated) = gate(run, &row) {
                return finish(case, gated);
            }
            row.projection.push(("kind".into(), "case_show".into()));
            row.projection
                .push(("read".into(), format!("case show,{}", c.id)));
            let closes = run
                .book
                .steps
                .iter()
                .any(|x| x.step_kind() == Some(StepKind::CaseClose) && x.reference == c.id);
            if !closes {
                row.verdict = RowVerdict::Unrun;
                row.reason = Some("needs:case_close step".into());
                return finish(case, (row, Vec::new(), None));
            }
            let (projection, fails) = case_show(run, c);
            row.projection.extend(projection);
            if !fails.is_empty() {
                row.verdict = RowVerdict::Fail;
                row.reason = Some(fails.join("; "));
            }
            finish(case, (row, Vec::new(), None))
        })
        .collect()
}

/// A case row's tokens and its failures, from the case's runs.
fn case_show(run: &BookRun<'_>, c: &CaseDef) -> (Vec<(String, String)>, Vec<String>) {
    let mut tokens = Vec::new();
    let mut fails = Vec::new();
    let r = run.cases.get(&c.id);
    let shown = r
        .and_then(|r| r.show.as_ref())
        .and_then(|call| call.event("case"))
        .and_then(|o| o.field("case"))
        .cloned();
    let Some(shown) = shown else {
        fails.push(format!(
            "expected `fa case show` of case {} observed none",
            c.id
        ));
        return (tokens, fails);
    };
    let text = |path: &[&str]| {
        shown
            .at(path)
            .and_then(Json::as_str)
            .unwrap_or("none")
            .to_string()
    };
    let state = text(&["state"]);
    tokens.push(("state".to_string(), state.clone()));
    if state != "Closed" {
        fails.push(format!("expected Closed observed {state}"));
    }
    let kind = text(&["kind"]);
    tokens.push(("case_kind".to_string(), kind.clone()));
    if kind != c.kind {
        fails.push(format!("expected case_kind={} observed {kind}", c.kind));
    }
    let day = text(&["determination", "day"]);
    tokens.push(("determined_on".to_string(), day.clone()));
    match run.determination_day(c) {
        Ok(want) if want == day => {}
        Ok(want) => fails.push(format!("expected determined_on={want} observed {day}")),
        Err(why) => fails.push(why),
    }
    let authority = text(&["determination", "authority"]);
    let want = run
        .documents
        .get(&c.authority)
        .map(|o| o.trim_start_matches("D:").to_ascii_lowercase());
    tokens.push((
        "authority".to_string(),
        if want.as_deref() == Some(authority.as_str()) {
            c.authority.clone()
        } else {
            authority.clone()
        },
    ));
    if want.as_deref() != Some(authority.as_str()) {
        fails.push(format!(
            "expected authority={} observed {authority}",
            c.authority
        ));
    }
    let disclosed = text(&["disclosure", "document"]);
    let reviewed = shown
        .at(&["disclosure", "attestation"])
        .is_some_and(|a| a.as_str().is_some());
    let want = r
        .and_then(|r| r.disclosure.as_deref())
        .map(str::to_ascii_lowercase);
    let disclosure = if want.as_deref() == Some(disclosed.as_str()) && reviewed {
        "reviewed"
    } else {
        "none"
    };
    tokens.push(("disclosure".to_string(), disclosure.to_string()));
    if disclosure != "reviewed" {
        fails.push(format!(
            "expected a reviewed disclosure of {} observed {disclosed}",
            c.disclosure
        ));
    }
    match r.and_then(|r| r.twin.as_ref()) {
        Some(twin) => {
            let id = twin.refusal_id();
            tokens.push((
                "twin".to_string(),
                format!(
                    "refused:{}:exit={}",
                    id.as_deref().unwrap_or("none"),
                    twin.exit
                ),
            ));
            if id.as_deref() != Some("FA-REF-179") || twin.exit != 3 {
                fails.push(format!(
                    "expected the unreviewed disclosure twin refused FA-REF-179 exit=3 observed {} exit={}",
                    id.as_deref().unwrap_or("admitted"),
                    twin.exit
                ));
            }
        }
        None => fails.push("expected the unreviewed disclosure twin observed none".into()),
    }
    let has = |kind: StepKind| {
        run.book
            .steps
            .iter()
            .any(|x| x.step_kind() == Some(kind) && x.reference == c.id)
    };
    match r.and_then(|r| r.one_approval.as_ref()) {
        Some((twin, state)) => {
            let id = twin.refusal_id();
            tokens.push((
                "one_approval".to_string(),
                format!(
                    "refused:{}:exit={}:{state}",
                    id.as_deref().unwrap_or("none"),
                    twin.exit
                ),
            ));
            if id.as_deref() != Some("FA-REF-012") || twin.exit != 7 || state != "Rehearsed" {
                fails.push(format!(
                    "expected one approval refused FA-REF-012 exit=7 leaving the case Rehearsed observed {} exit={} state={state}",
                    id.as_deref().unwrap_or("admitted"),
                    twin.exit
                ));
            }
        }
        None if has(StepKind::CaseApprove) => {
            fails.push("expected the one-approval twin observed none".into());
        }
        None => {}
    }
    let outside = r.map(|r| r.outside.as_slice()).unwrap_or_default();
    let posts = has(StepKind::CasePost);
    if posts && outside.is_empty() {
        fails.push("expected each delta posted outside its case observed none".into());
    }
    let mut observed: Vec<String> = outside
        .iter()
        .map(|(_, twin)| {
            format!(
                "refused:{}:exit={}",
                twin.refusal_id().as_deref().unwrap_or("none"),
                twin.exit
            )
        })
        .collect();
    observed.dedup();
    if !observed.is_empty() {
        tokens.push(("outside_case".to_string(), observed.join(",")));
    }
    for (intent, twin) in outside {
        if twin.refusal_id().as_deref() != Some("FA-REF-178") || twin.exit != 3 {
            fails.push(format!(
                "expected {intent} posted outside its case refused FA-REF-178 exit=3 observed {} exit={}",
                twin.refusal_id().as_deref().unwrap_or("admitted"),
                twin.exit
            ));
        }
    }
    let lineages = r.map(|r| r.lineages.as_slice()).unwrap_or_default();
    if posts && lineages.is_empty() {
        fails.push("expected the lineage of a restated target observed none".into());
    }
    for (target, call) in lineages {
        if call.exit != 0 || !call.stdout.contains("Restates") {
            fails.push(format!(
                "expected the lineage of {target} to name Restates observed exit={}",
                call.exit
            ));
        }
    }
    // A12 (§12.7): each restated period's as-filed statement certificate is
    // SupersededBy exactly the entries the case posted, an independent
    // second half of the contributing-entry witness.
    let post_seq = run
        .book
        .steps
        .iter()
        .find(|x| x.step_kind() == Some(StepKind::CasePost) && x.reference == c.id)
        .map(|x| x.seq);
    let posted: BTreeSet<String> = run
        .posted_steps
        .iter()
        .filter(|(_, seq)| Some(**seq) == post_seq)
        .filter_map(|(intent, _)| run.vids.get(intent).cloned())
        .collect();
    for (period, call) in r.map(|r| r.statuses.as_slice()).unwrap_or_default() {
        let status = call
            .str_field("certificate_status", "status")
            .unwrap_or_else(|| "none".to_string());
        let mut later: BTreeSet<String> = call
            .array_field("certificate_status", "later_entries")
            .iter()
            .filter_map(|e| e.as_str().map(str::to_string))
            .collect();
        if DROP_LATER_ENTRY.with(Cell::get) {
            later.pop_first();
        }
        tokens.push((
            "superseded".to_string(),
            format!("{period}:{status}:later_entries={}", later.len()),
        ));
        if status != "SupersededBy" || later != posted {
            fails.push(format!(
                "expected the as-filed certificate of {period} SupersededBy the case's {} posted entries observed {status} with {} later entries ({} of them posted by the case)",
                posted.len(),
                later.len(),
                later.intersection(&posted).count()
            ));
        }
    }
    (tokens, fails)
}

/// A5b's row-level rule (§5.2): a `closed_cites` D states that its targets
/// are every documented or Δ entry its run's findings cite, so each other
/// such entry a finding cites is a FAIL line of its own, the entry in the
/// target slot.
fn unexpected_cite_rows(run: &BookRun<'_>, e: &Expectation) -> Vec<Evaluated> {
    let (Some(procedure), Some(version)) = (e.fields.str("procedure"), e.fields.int("version"))
    else {
        return Vec::new();
    };
    // Without a recorded run the targets' own rows already fail.
    let Some(found) = run.runs.get(procedure) else {
        return Vec::new();
    };
    let mut by_intent: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for f in &found.findings {
        let pr = project(run, f);
        for entry in &pr.entries {
            by_intent
                .entry(entry.clone())
                .or_default()
                .extend(pr.cites.iter().cloned());
        }
    }
    let cited: BTreeSet<String> = by_intent.keys().cloned().collect();
    fa_oracles::cases::status::unexpected_cites(run.case, e, &cited)
        .into_iter()
        .map(|intent| {
            let mut row = blank(&e.id, "D", run.book.stem.as_str(), Some(&intent));
            row.verdict = RowVerdict::Fail;
            row.projection
                .push(("procedure".into(), format!("{procedure}@{version}")));
            row.projection.push((
                "cite".into(),
                by_intent.get(&intent).map_or_else(|| "-".into(), joined),
            ));
            row.reason = Some(format!("unexpected finding cites {intent}"));
            finish(run.case, (row, Vec::new(), None))
        })
        .collect()
}

/// Whether a target branches attributes (A5a's table), which a P row's
/// sweep decides cell by cell (A7c).
pub fn has_branch_table(t: &Target) -> bool {
    t.fields.strs("branch_attrs").is_some_and(|a| !a.is_empty())
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
                // A finding that cites a leg is a finding on its entry
                // (an account-level procedure cites legs, never the entry).
                if let Some(i) = entry.and_then(intent_of_vid) {
                    p.entries.insert(i);
                }
            }
            "account" => {
                let code = c
                    .get("account")
                    .and_then(Json::as_str)
                    .and_then(|v| run.accounts.get(v).cloned());
                p.cites.insert(code.unwrap_or_else(|| "?account".into()));
            }
            // An attestation by the `assert_balance` step that recorded it,
            // a period by its label (recon.assertion_drift cites both).
            "attestation" => {
                let step = c
                    .get("attestation")
                    .and_then(Json::as_str)
                    .and_then(|v| run.attestations.get(v));
                p.cites.insert(
                    step.map_or_else(|| "?attestation".into(), |r| format!("attestation:{r}")),
                );
            }
            "period" => {
                let code = c.get("period").and_then(Json::as_str);
                let label = code.and_then(|code| {
                    run.periods
                        .iter()
                        .find(|(_, v)| v.as_str() == code)
                        .map(|(label, _)| label.clone())
                });
                p.cites
                    .insert(label.map_or_else(|| "?period".into(), |l| format!("period:{l}")));
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

fn int_text(v: Option<i128>) -> String {
    v.map_or_else(|| "-".into(), |v| v.to_string())
}

/// A candidate finding's disagreements with its target, and its projection
/// tokens.
type Compared = (Vec<String>, Vec<(String, String)>);

/// One candidate finding's projection and its disagreements with the
/// target: §5.2's pass rule per component (`evaluate_d`), a Rel component
/// judged by `rel` on this run.
fn compare(
    p: &fa_oracles::cases::expect::Projection,
    want_cites: &BTreeSet<String>,
    pr: &Projected,
    f: &Json,
    rel: &dyn Fn(&str, &ObservedD) -> Option<bool>,
) -> Compared {
    let stat = f.get("statistic");
    let field = |k: &str| stat.and_then(|s| s.get(k));
    let observed = ObservedD {
        cites: pr.cites.clone(),
        severity: f
            .get("severity")
            .and_then(Json::as_str)
            .unwrap_or("-")
            .to_string(),
        statistic_name: field("name")
            .and_then(Json::as_str)
            .unwrap_or("-")
            .to_string(),
        statistic: int_text(field("value").and_then(Json::as_int)),
        scale: int_text(field("scale").and_then(Json::as_int)),
    };
    let diff = evaluate_d(p, want_cites, &observed, None, &|c| rel(c, &observed))
        .into_iter()
        .filter_map(|v| match v {
            ComponentVerdict::Fail(what, want, got) => Some(mismatch(what, want, got)),
            ComponentVerdict::Unjudged(what) => Some(format!(
                "expected {what} judged by its relational rule observed no account VIds to judge it"
            )),
            _ => None,
        })
        .collect();
    let proj = vec![
        ("cite".into(), joined(&observed.cites)),
        ("severity".into(), observed.severity),
        ("statistic_name".into(), observed.statistic_name),
        ("statistic".into(), observed.statistic),
        ("scale".into(), observed.scale),
    ];
    (diff, proj)
}

/// A Rel target's rule under this run's account VIds (§2.6 rule 9), read
/// from the binary's own legs (`account` is the VId's 32-hex `u128`, the
/// order Lantern sorts by): the leg the rule selects. `None` when the
/// target names no `rel_rule`.
fn rel_expected(run: &BookRun<'_>, t: &Target) -> Option<Result<rel::Expected, String>> {
    let rule = match rel::rule_of(t)? {
        Ok(r) => r,
        Err(e) => return Some(Err(e)),
    };
    let legs = match rel::legs_of(run.book, &t.fact) {
        Ok(l) => l,
        Err(e) => return Some(Err(e)),
    };
    let vids: BTreeMap<String, u128> = run
        .accounts
        .iter()
        .filter_map(|(vid, code)| Some((code.clone(), u128::from_str_radix(vid, 16).ok()?)))
        .collect();
    Some(rel::expect_rel(&rule, &legs, &vids).ok_or_else(|| {
        format!(
            "no leg of {} qualifies for {rule}, or its account was not posted",
            t.fact
        )
    }))
}

/// The `rel=<account>/<magnitude>` token a Rel row carries, and the rule
/// judged against an observation: the cite names the selected account, the
/// statistic is its leg's magnitude. A11a re-judges every run from it.
pub(crate) fn rel_holds(
    token: Option<&str>,
    component: &str,
    cites: &str,
    statistic: &str,
) -> Option<bool> {
    let (account, magnitude) = token?.split_once('/')?;
    match component {
        "cite" => Some(cites.split(',').any(|c| c == account)),
        "statistic" => Some(statistic == magnitude),
        _ => None,
    }
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
    // A Rel component's rule, judged on this run's account VIds.
    let expected = rel_expected(run, t);
    let token = match &expected {
        Some(Ok(e)) => Some(format!("{}/{}", e.account, e.magnitude)),
        Some(Err(why)) => {
            fails.push(format!(
                "expected a relational rule to judge observed {why}"
            ));
            None
        }
        None => None,
    };
    let judge =
        |c: &str, o: &ObservedD| rel_holds(token.as_deref(), c, &joined(&o.cites), &o.statistic);
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
        let (diff, proj) = compare(&p, &want_cites, &pr, f, &judge);
        if best.as_ref().is_none_or(|(d, _)| diff.len() < d.len()) {
            best = Some((diff, proj));
        }
    }
    let mut witnesses = vec![
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
    if let Some(token) = &token {
        row.projection.push(("rel".into(), token.clone()));
    }
    // A4r: the reference's naive procedure over the run's admitted entries
    // flags the same case entries with the same statistic.
    let (reference, mut seen) = d_reference(run, &p.procedure, found);
    row.projection
        .push(("ref".into(), reference.token().to_string()));
    witnesses.append(&mut seen);
    if let RefVerdict::Disagree { reference, kernel } = &reference {
        fails.push(format!(
            "expected ref=agree observed ref=disagree (reference {reference}; kernel {kernel})"
        ));
    }
    // A12 (§12.1): the run's outsider replay, its canonical workpaper
    // exported and re-executed to the same certified run.
    if let Some(replayed) = run.run_replays.get(&p.procedure) {
        row.projection.push((
            "outsider".into(),
            if replayed.is_ok() {
                "replay:verified"
            } else {
                "replay:failed"
            }
            .into(),
        ));
        if let Err(why) = replayed {
            fails.push(format!("outsider replay: {why}"));
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

/// A D row's reference verdict (A4r) and its record witnesses: the
/// reference's naive procedure over the run's admitted entries (the case's
/// entries compared; a filler variant's entries only populate) against the
/// kernel's findings on the case's entries, under the run's procedure
/// parameters (the `finding_record` step's, else the registered defaults).
fn d_reference(
    run: &BookRun<'_>,
    procedure: &str,
    found: &FindingRun,
) -> (RefVerdict, Vec<(String, String)>) {
    let case_ids: BTreeSet<&str> = run.book.intents.iter().map(|i| i.id.as_str()).collect();
    // The run read the entries posted before its own step, not the history's
    // later ones.
    let mut live: Vec<LiveEntry<'_>> = run
        .book
        .intents
        .iter()
        .filter(|i| run.vids.contains_key(&i.id))
        .filter(|i| run.posted_steps.get(&i.id).is_some_and(|s| *s < found.step))
        .map(|i| LiveEntry {
            intent: i,
            legs: run.book.legs.iter().filter(|l| l.intent == i.id).collect(),
            compared: true,
        })
        .collect();
    let filler_before = |variant: &str| {
        run.book.steps.iter().any(|s| {
            s.step_kind() == Some(StepKind::FillerBatch)
                && s.reference == variant
                && s.seq < found.step
        })
    };
    if let Some(f) = run
        .filler
        .as_ref()
        .filter(|f| filler_before(&f.spec.variant))
    {
        live.extend(f.intents.iter().map(|i| LiveEntry {
            intent: i,
            legs: f.legs.iter().filter(|l| l.intent == i.id).collect(),
            compared: false,
        }));
    }
    let kernel: BTreeMap<String, String> = found
        .findings
        .iter()
        .filter_map(|f| {
            let pr = project(run, f);
            let entry = pr.entries.iter().find(|e| case_ids.contains(e.as_str()))?;
            let value = f
                .get("statistic")
                .and_then(|s| s.get("value"))
                .and_then(Json::as_int)?;
            Some((entry.clone(), value.to_string()))
        })
        .collect();
    let params: BTreeMap<String, i128> = run
        .book
        .steps
        .iter()
        .filter(|s| {
            s.step_kind() == Some(StepKind::FindingRecord)
                && s.reference.split_once('@').map(|(p, _)| p) == Some(procedure)
        })
        .flat_map(|s| s.params.iter().flatten())
        .filter_map(|p| {
            let (name, value) = p.split_once('=')?;
            Some((name.to_string(), value.parse().ok()?))
        })
        .collect();
    let verdict = match ReferenceAdapter::new(run.case, run.book) {
        Ok(a) => a.d_cites(procedure, &params, &live, &kernel),
        Err(why) => RefVerdict::Disagree {
            reference: format!("unmapped ({why})"),
            kernel: "-".into(),
        },
    };
    let mut witnesses = vec![("reference".to_string(), verdict.token().to_string())];
    match &verdict {
        RefVerdict::NotModelled { reason } => {
            witnesses.push(("reference_reason".into(), (*reason).into()));
        }
        RefVerdict::Disagree { reference, .. } => {
            witnesses.push(("reference_refusal".into(), reference.clone()));
        }
        RefVerdict::Agree => {}
    }
    (verdict, witnesses)
}

/// A T or R row's read, compared with the value its row names (`published`
/// for a T, `posted` for an R): the row's `read=` and `value=` tokens, and
/// why it fails, or why it waits (`needs:`), if it does.
fn read_against(
    run: &BookRun<'_>,
    e: &Expectation,
    t: Option<&Target>,
    row: &mut RowLine,
    value_key: &str,
) -> Result<(), (RowVerdict, String)> {
    let key = super::reads::key(e, t);
    let Some(read) = run.reads.get(&key) else {
        return Err((
            RowVerdict::Fail,
            format!("expected a read of {key} observed none"),
        ));
    };
    row.projection.push(("read".into(), read.token.clone()));
    let observed = match &read.value {
        Ok(v) => *v,
        Err(why) if why.starts_with("needs:") => return Err((RowVerdict::Unrun, why.clone())),
        Err(why) => return Err((RowVerdict::Fail, why.clone())),
    };
    let fact = super::reads::field(e, t, value_key).unwrap_or("-");
    let Some((want, unit)) = run.value_of(fact) else {
        return Err((
            RowVerdict::Fail,
            format!("expected a [[value]] of {value_key} fact {fact} observed none"),
        ));
    };
    let scale = super::reads::scale_of(&unit).unwrap_or(0);
    row.projection
        .push(("value".into(), format_amount(observed, scale)));
    // A11b: an as-originally-reported read of a line no delta moved does
    // not exercise its selector. The row says so and keeps its verdict.
    if read.exercised == Some(false) {
        row.projection
            .push(("selector".into(), "not_exercised".into()));
    }
    // A12 (§12.7): the second read path, an R-class cross-check of two FA
    // read paths. A query that does not net to the fold path's value fails
    // the row.
    if let Some(gql) = run.gql.get(&key) {
        row.projection
            .push(("gql".into(), if gql.is_ok() { "ok" } else { "fail" }.into()));
        if let Err(why) = gql {
            return Err((RowVerdict::Fail, format!("gql: {why}")));
        }
    }
    // Exact equality at the published value's declared precision (§5.3).
    // Equal to the minor unit is equal at any coarser precision; an unequal
    // value stated to a coarser precision needs its rounding rule to decide.
    if observed == want {
        return Ok(());
    }
    if run
        .case
        .values
        .iter()
        .find(|v| v.fact == fact && v.ordinal == 1)
        .and_then(|v| v.precision)
        .is_some_and(|p| p > 0)
    {
        return Err((
            RowVerdict::Unrun,
            format!("needs:A7b ({fact} is stated to a coarser precision)"),
        ));
    }
    Err((
        RowVerdict::Fail,
        mismatch(
            "value",
            format_amount(want, scale),
            format_amount(observed, scale),
        ),
    ))
}

/// The drift read-back of a kernel-attested T (§5.3): once the case has
/// moved the cell, `recon.assertion_drift` reports exactly the as-filed
/// assertion (any attestation but the T's own, whose B still equals the
/// fold), with the drift's magnitude |B - A| at the unit's scale as its
/// statistic. The token is `<drift>@attestation:<step>`, or what was seen.
fn drift_read_back(
    run: &BookRun<'_>,
    e: &Expectation,
    drift: &FindingRun,
) -> (String, Option<String>) {
    let published = e.fields.str("published").unwrap_or("-");
    let Some((b, unit)) = run.value_of(published) else {
        return (
            "unread".into(),
            Some(format!(
                "expected a [[value]] of published fact {published} observed none"
            )),
        );
    };
    let scale = super::reads::scale_of(&unit).unwrap_or(0);
    let own = format!("attestation:{}", e.id);
    let cited: Vec<(String, &Json)> = drift
        .findings
        .iter()
        .flat_map(|f| {
            project(run, f)
                .cites
                .into_iter()
                .filter(|c| c.starts_with("attestation:"))
                .map(move |c| (c, f))
        })
        .collect();
    if cited.iter().any(|(c, _)| *c == own) {
        return (
            format!("on:{own}"),
            Some(format!(
                "expected no drift finding on {own}, which equals the fold, observed one"
            )),
        );
    }
    let [(cite, f)] = cited.as_slice() else {
        return (
            format!("findings:{}", cited.len()),
            Some(format!(
                "expected one drift finding citing the as-filed attestation observed {}",
                cited.len()
            )),
        );
    };
    let step = cite.trim_start_matches("attestation:");
    let asserted = run
        .assertions
        .get(step)
        .and_then(|a| a.balance.split_once(' '))
        .and_then(|(amount, _)| parse_amount(amount, scale).ok());
    let Some(a) = asserted else {
        return (
            cite.clone(),
            Some(format!(
                "expected the asserted balance of {step} observed none"
            )),
        );
    };
    let stat = f.get("statistic");
    let field = |k: &str| stat.and_then(|s| s.get(k));
    let name = field("name").and_then(Json::as_str).unwrap_or("-");
    let value = field("value").and_then(Json::as_int);
    let stat_scale = field("scale").and_then(Json::as_int);
    let want = b.checked_sub(a).and_then(i128::checked_abs);
    let token = format!(
        "{}@{cite}",
        value.map_or_else(|| "-".into(), |v| format_amount(v, scale))
    );
    if name != "assertion_drift" || value != want || stat_scale != Some(i128::from(scale)) {
        let why = format!(
            "expected drift assertion_drift={} scale={scale} on {cite} observed {name}={} scale={}",
            want.map_or_else(|| "-".into(), |w| format_amount(w, scale)),
            value.map_or_else(|| "-".into(), |v| v.to_string()),
            int_text(stat_scale)
        );
        return (token, Some(why));
    }
    (token, None)
}

/// A T row (§5.3): its certified read equals its published value; a
/// `per_account` T is kernel-attested, so its `assert_balance` step must
/// have recorded B as a RegisterEquals attestation that holds, and its twins
/// (B plus and minus one minor unit) been refused `FA-REF-140`. A T that
/// holds passes only with its contributing-entry witness (A11b) and the
/// outsider check of its read kind (A12): never PASS before both.
fn t_row(run: &BookRun<'_>, e: &Expectation, t: Option<&Target>, mut row: RowLine) -> Eval {
    let kind = e.fields.str("kind").unwrap_or("-");
    row.projection.push(("kind".into(), kind.to_string()));
    let mut fails = Vec::new();
    let mut waits = None;
    match read_against(run, e, t, &mut row, "published") {
        Ok(()) => {}
        Err((RowVerdict::Unrun, why)) => waits = Some(why),
        Err((_, why)) => fails.push(why),
    }
    // Kernel-attested (§5.3): a per_account T, and a bridge whose A and
    // deltas sit on the one leaf account it reads, on a statement book.
    let one_leaf_bridge = kind == "bridge"
        && run.book.kind == VariantKind::Statement
        && super::reads::field(e, t, "read_verb") == Some("balance");
    if kind == "per_account" || one_leaf_bridge {
        let step = t.map_or_else(|| e.id.clone(), |t| format!("{}#{}", e.id, t.fact));
        match run
            .assertions
            .get(&step)
            .or_else(|| run.assertions.get(&e.id))
        {
            None => fails.push(format!(
                "expected an assert_balance step for {step} (a {kind} T is kernel-attested) observed none"
            )),
            Some(a) => {
                // Recorded: admitted, as a RegisterEquals attestation that
                // holds at the fold it was recorded against.
                let held =
                    a.claim.as_deref() == Some("RegisterEquals") && a.holds == Some(true);
                let token = match (a.asserted.exit, held) {
                    (0, true) => "recorded",
                    (0, false) => "unheld",
                    _ => "refused",
                };
                row.projection.push(("assert".into(), token.into()));
                if a.asserted.exit != 0 {
                    fails.push(format!(
                        "expected assert-balance {} recorded observed exit={} {}",
                        a.balance,
                        a.asserted.exit,
                        a.asserted.refusal_id().unwrap_or_default()
                    ));
                } else if !held {
                    fails.push(format!(
                        "expected assert-balance {} recorded as a RegisterEquals attestation that holds observed claim={} holds={}",
                        a.balance,
                        a.claim.as_deref().unwrap_or("none"),
                        a.holds.map_or("none", |h| if h { "true" } else { "false" })
                    ));
                }
                // One token when both twins agree, else one per offset.
                let tokens: Vec<String> = a
                    .twins
                    .iter()
                    .map(|(_, c)| {
                        format!(
                            "refused:{}:exit={}",
                            c.refusal_id().as_deref().unwrap_or("none"),
                            c.exit
                        )
                    })
                    .collect();
                let token = match tokens.as_slice() {
                    [plus, minus] if plus == minus => plus.clone(),
                    _ => a
                        .twins
                        .iter()
                        .zip(&tokens)
                        .map(|((offset, _), t)| format!("{offset:+}:{t}"))
                        .collect::<Vec<_>>()
                        .join(","),
                };
                row.projection.push(("twin".into(), token));
                if a.twins.len() != 2 {
                    fails.push(format!(
                        "expected the twins of {} at plus and minus one minor unit observed {}",
                        a.balance,
                        a.twins.len()
                    ));
                }
                for (offset, c) in &a.twins {
                    let id = c.refusal_id();
                    if id.as_deref() != Some("FA-REF-140") || c.exit != 3 {
                        fails.push(format!(
                            "expected the twin of {} at {offset:+} minor unit refused FA-REF-140 exit=3 observed {} exit={}",
                            a.balance,
                            id.as_deref().unwrap_or("admitted"),
                            c.exit
                        ));
                    }
                }
            }
        }
        // §5.3's drift read-back, when the book records the drift run.
        if let Some(drift) = run.runs.get("recon.assertion_drift") {
            let (token, why) = drift_read_back(run, e, drift);
            row.projection.push(("drift".into(), token));
            fails.extend(why);
        }
    }
    let mut witnesses = vec![("kind".to_string(), kind.to_string())];
    witnesses.extend(read_certificate(run, e, t));
    // A12: the outsider check of the read's kind (§12.1), printed last as
    // `outsider=<kind>:verified|failed`. A failed check fails the row
    // whatever else holds; a read with no check leaves a holding T UNRUN.
    let outsider = run.read_checks.get(&super::reads::key(e, t));
    if let Some((kind, Err(why))) = outsider {
        fails.push(format!("outsider {}: {why}", kind.name()));
    }
    let outsider_token = outsider.map(|(kind, verdict)| {
        (
            "outsider".to_string(),
            format!(
                "{}:{}",
                kind.name(),
                if verdict.is_ok() {
                    "verified"
                } else {
                    "failed"
                }
            ),
        )
    });
    // A12 (§12.7): on a book whose examiner witness cosigned the as-filed
    // checkpoint, a T holds only if the restated book extends it.
    let append_only = run.witness.as_ref().and_then(|_| {
        run.outsider
            .as_ref()?
            .checks
            .iter()
            .find(|(check, _)| check == "append_only")
            .map(|(_, verdict)| verdict.clone())
    });
    if let Some(Err(why)) = &append_only {
        fails.push(format!("append_only: {why}"));
    }
    let append_token = append_only.map(|verdict| {
        (
            "append_only".to_string(),
            if verdict.is_ok() { "ok" } else { "fail" }.to_string(),
        )
    });
    if !fails.is_empty() {
        row.projection.extend(outsider_token);
        row.projection.extend(append_token);
        row.verdict = RowVerdict::Fail;
        row.reason = Some(fails.join("; "));
        return (row, witnesses, None);
    }
    if let Some(why) = waits {
        row.verdict = RowVerdict::Unrun;
        row.reason = Some(why);
        return (row, witnesses, None);
    }
    // A11b: the contributing-entry witness decides whether the row is a T
    // at all. Holding, it passes once its outsider check verified (A12);
    // failing, the row is a read-back of its published value: an R, which
    // it equals. A statement line's trace that disagrees with its explained
    // balances re-types it too, the difference a witness and the trace
    // reproducible.
    let verified = outsider.is_some_and(|(_, verdict)| verdict.is_ok());
    let mut reproduce = None;
    match contrib_verdict(run, e, t) {
        Ok((verdict, named)) => {
            row.projection.push(("contrib".into(), verdict.token()));
            witnesses.push(("named_inputs".into(), named));
            if let ContribVerdict::Disagree { detail } = &verdict {
                witnesses.push(("disagreement".into(), detail.clone()));
                reproduce = run
                    .reads
                    .get(&super::reads::key(e, t))
                    .and_then(|r| r.trace.as_ref()?.as_ref().ok())
                    .map(|trace| trace.reproduce.clone());
            }
            if verdict != ContribVerdict::Holds {
                row.kind = "R".into();
                row.verdict = RowVerdict::Pass;
            } else if verified {
                row.verdict = RowVerdict::Pass;
            } else {
                row.verdict = RowVerdict::Unrun;
                row.reason = Some("outsider".into());
            }
        }
        Err(why) => {
            row.projection
                .push(("contrib".into(), format!("unrun({why})")));
            row.verdict = RowVerdict::Unrun;
            row.reason = Some(
                if verified {
                    "contributing_entry"
                } else {
                    "contributing_entry,outsider"
                }
                .into(),
            );
        }
    }
    row.projection.extend(outsider_token);
    row.projection.extend(append_token);
    (row, witnesses, reproduce)
}

/// A T read's contributing-entry witness (A11b) and its named inputs, or
/// why it cannot run yet. A statement line's trace is cross-checked first:
/// the witness runs on contributions both certified reads agree on.
fn contrib_verdict(
    run: &BookRun<'_>,
    e: &Expectation,
    t: Option<&Target>,
) -> Result<(ContribVerdict, String), String> {
    let set = run.case.expectations.as_ref().ok_or("no expectations")?;
    let reads = fa_oracles::cases::trace::t_reads(set);
    let read = reads
        .iter()
        .find(|r| {
            r.expectation.id == e.id
                && (r.target.is_none()
                    || r.target.map(|x| x.fact.as_str()) == t.map(|x| x.fact.as_str()))
        })
        .ok_or("no read")?;
    let observed = run.reads.get(&super::reads::key(e, t)).ok_or("no read")?;
    let contributions = observed.contributions.as_ref().ok_or_else(|| {
        format!(
            "needs:A11b {} lines",
            super::reads::field(e, t, "read_verb").unwrap_or("-")
        )
    })?;
    let certified = observed.value.clone()?;
    let b = super::reads::field(e, t, "published")
        .and_then(|f| run.value_of(f))
        .map(|(v, _)| v);
    let named = named_inputs(run.book, read);
    let verdict = match observed.trace.as_ref() {
        None => witness(run.case, run.book, read, contributions, certified, b),
        Some(Err(why)) => return Err(why.clone()),
        Some(Ok(trace)) => match cross_check(&trace.publications, contributions) {
            ContribVerdict::Holds => witness(run.case, run.book, read, contributions, certified, b),
            disagreement => disagreement,
        },
    };
    Ok((verdict, named.into_iter().collect::<Vec<_>>().join(",")))
}

/// An R row (§5.3): a read-back of a posted value through a selector or an
/// attestation path; it passes when the certified read equals the posted
/// value.
fn r_row(run: &BookRun<'_>, e: &Expectation, t: Option<&Target>, mut row: RowLine) -> Eval {
    row.projection.push(("kind".into(), "read_back".into()));
    match read_against(run, e, t, &mut row, "posted") {
        Ok(()) => row.verdict = RowVerdict::Pass,
        Err((verdict, why)) => {
            row.verdict = verdict;
            row.reason = Some(why);
        }
    }
    (row, read_certificate(run, e, t), None)
}

/// The certificate a row's read retained, as a record witness.
fn read_certificate(
    run: &BookRun<'_>,
    e: &Expectation,
    t: Option<&Target>,
) -> Vec<(String, String)> {
    run.reads
        .get(&super::reads::key(e, t))
        .and_then(|r| r.certificate.clone())
        .map(|c| ("certificate".to_string(), c))
        .into_iter()
        .collect()
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
    let mut witnesses = vec![("exit".to_string(), call.exit.to_string())];
    if fails.is_empty() {
        // A4r: the reference oracle decides the same intent, and its first
        // refusal must be the kernel's; then the row waits on the
        // filler-invariance witness (A11a).
        let (token, fail, mut seen) = reference(
            run,
            e,
            intent,
            &CellSetting::default(),
            observed.as_deref(),
            true,
        );
        row.projection.push(("ref".into(), token));
        witnesses.append(&mut seen);
        if let Some(why) = fail {
            row.verdict = RowVerdict::Fail;
            row.reason = Some(why);
            return (row, witnesses, Some(reproduce(call)));
        }
        row.verdict = RowVerdict::Unrun;
        row.reason = Some(FILLER.into());
        (row, witnesses, None)
    } else {
        row.verdict = RowVerdict::Fail;
        row.reason = Some(fails.join("; "));
        (row, witnesses, Some(reproduce(call)))
    }
}

/// The reference verdict (A4r) on a P row or cell: the `ref=` token, why it
/// fails the row if it does, and the verdict record's witnesses
/// (`reference`, and `reference_reason` or `reference_refusal`). The
/// oracle decides `intent` under `cell`; `kernel` is the kernel's first
/// refusal (`None` when it admitted). A disagreement fails; `not_modelled`
/// never counts as agreement and must be what the row declares; and on the
/// documented outcome (`documented`), the declared `reference_verdict` is
/// the refusal the reference agreed on.
pub(crate) fn reference(
    run: &BookRun<'_>,
    e: &Expectation,
    intent: &str,
    cell: &CellSetting,
    kernel: Option<&str>,
    documented: bool,
) -> (String, Option<String>, Vec<(String, String)>) {
    let Some(it) = run.book.intents.iter().find(|i| i.id == intent) else {
        return (
            "disagree".into(),
            Some(format!(
                "expected intent {intent} in the book observed none"
            )),
            Vec::new(),
        );
    };
    let verdict = match ReferenceAdapter::new(run.case, run.book) {
        Ok(a) => a.p_cell(it, cell, kernel),
        Err(why) => RefVerdict::Disagree {
            reference: format!("unmapped ({why})"),
            kernel: kernel.unwrap_or("admit").into(),
        },
    };
    let declared = e.fields.str("reference_verdict");
    let mut witnesses = vec![("reference".to_string(), verdict.token().to_string())];
    let observed = kernel.unwrap_or("admit");
    let fail = match &verdict {
        RefVerdict::Agree if declared == Some("not_modelled") => Some(format!(
            "expected reference_verdict=not_modelled observed ref=agree ({observed})"
        )),
        RefVerdict::Agree => declared
            .filter(|d| documented && *d != observed)
            .map(|d| format!("expected reference_verdict={d} observed {observed}")),
        RefVerdict::NotModelled { reason } => {
            witnesses.push(("reference_reason".into(), (*reason).into()));
            (declared != Some("not_modelled")).then(|| {
                format!(
                    "expected reference_verdict={} observed not_modelled ({reason})",
                    declared.unwrap_or("-")
                )
            })
        }
        RefVerdict::Disagree { reference, .. } => {
            witnesses.push(("reference_refusal".into(), reference.clone()));
            Some(format!(
                "expected ref=agree observed ref=disagree (reference {reference})"
            ))
        }
    };
    (verdict.token().to_string(), fail, witnesses)
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

/// Why an N cannot read a recorded run, and the failed call's `REPRODUCE`
/// line when there was one.
type RunMiss = (String, Option<String>);

/// `procedure`'s recorded run in `r`, at the N's `version`. A run that was
/// refused or errored names its exit (and refusal); `whose` is "a " for the
/// target run and "the twin's " for the twin.
fn recorded_run<'r>(
    r: &'r BookRun<'_>,
    procedure: &str,
    version: Option<i128>,
    whose: &str,
) -> Result<&'r FindingRun, RunMiss> {
    match r.runs.get(procedure) {
        Some(found) if version.is_some() && found.version != version => Err((
            format!(
                "expected {whose}run of {procedure}@{} observed @{}",
                int_text(version),
                int_text(found.version)
            ),
            None,
        )),
        Some(found) => Ok(found),
        None => Err(match r.failed_runs.get(procedure) {
            Some(c) => (
                format!(
                    "expected {whose}recorded run of {procedure} observed exit={}{}",
                    c.exit,
                    c.refusal_id()
                        .map_or_else(String::new, |id| format!(" refusal={id}"))
                ),
                Some(reproduce(c)),
            ),
            None => (
                format!("expected {whose}recorded run of {procedure} observed none"),
                None,
            ),
        }),
    }
}

/// How many of a run's findings cite `intent`'s entry.
fn findings_on(r: &BookRun<'_>, found: &FindingRun, intent: &str) -> usize {
    found
        .findings
        .iter()
        .filter(|f| project(r, f).entries.contains(intent))
        .count()
}

/// An exact_gap N's gap on `subject` (its target or twin target): the
/// sourced value of its `[[target]]` row less the procedure's value, read
/// from the one finding that cites the subject's entry under the sourced
/// statistic's name, at that statistic's scale.
fn gap_on(
    r: &BookRun<'_>,
    n: &Expectation,
    subject: &str,
    found: &FindingRun,
) -> Result<(i128, u8), String> {
    let sourced = r
        .case
        .expectations
        .as_ref()
        .and_then(|set| set.targets_of(&n.id).find(|t| t.fact == subject))
        .ok_or_else(|| format!("expected a sourced value of {subject} observed none"))?;
    let name = sourced.fields.str("statistic_name").unwrap_or_default();
    let want = sourced
        .fields
        .str("statistic_value")
        .and_then(|v| v.parse::<i128>().ok())
        .ok_or_else(|| format!("expected a sourced statistic_value of {subject} observed none"))?;
    let intent = intent_of(r, subject);
    let stat = |f: &Json, k: &str| f.get("statistic").and_then(|s| s.get(k)).cloned();
    let hits: Vec<&Json> = found
        .findings
        .iter()
        .filter(|f| {
            project(r, f).entries.contains(&intent)
                && stat(f, "name").as_ref().and_then(Json::as_str) == Some(name)
        })
        .collect();
    let [hit] = hits.as_slice() else {
        return Err(format!(
            "expected one {name} finding citing {intent} observed {}",
            hits.len()
        ));
    };
    let value = stat(hit, "value").as_ref().and_then(Json::as_int);
    let scale = stat(hit, "scale").as_ref().and_then(Json::as_int);
    let (Some(value), Some(scale)) = (value, scale.and_then(|s| u8::try_from(s).ok())) else {
        return Err(format!(
            "expected the {name} finding citing {intent} to state its value and scale observed none"
        ));
    };
    if let Some(s) = sourced.fields.int("statistic_scale")
        && s != i128::from(scale)
    {
        return Err(mismatch("scale", s, scale));
    }
    want.checked_sub(value)
        .map(|gap| (gap, scale))
        .ok_or_else(|| format!("expected a gap within i128 observed {want} - {value}"))
}

/// A registered unit's scale.
fn unit_scale(code: &str) -> Option<u8> {
    fa_registry::units_embedded()
        .ok()?
        .into_iter()
        .find(|u| u.code == code)
        .map(|u| u.scale)
}

/// Why a population-gated procedure's twin reported nothing: its run states
/// a population below the run's `min_population` (the step's param, else the
/// registered default), where the procedure claims nothing and cites nothing.
fn below_minimum(r: &BookRun<'_>, found: &FindingRun, procedure: &str) -> Option<String> {
    let population = found.findings.iter().find_map(|f| {
        let stat = f.get("statistic")?;
        (stat.get("name")?.as_str()? == "population")
            .then(|| stat.get("value")?.as_int())
            .flatten()
    })?;
    let set = r
        .book
        .steps
        .iter()
        .find(|s| {
            s.step_kind() == Some(StepKind::FindingRecord)
                && s.reference.split_once('@').map(|(p, _)| p) == Some(procedure)
        })
        .and_then(|s| s.params.as_ref())
        .and_then(|ps| {
            ps.iter()
                .find_map(|p| p.strip_prefix("min_population=")?.parse::<i128>().ok())
        });
    let min = match set {
        Some(m) => m,
        None => {
            Procedures::embedded()
                .ok()?
                .get(procedure)?
                .parameter("min_population")?
                .default
        }
    };
    (population < min).then(|| format!(" (population {population} < min_population {min})"))
}

/// An N row (§5.2, §3.7 item 3; A11c): the target run shows nothing (the
/// intent admitted, or no finding on it) or, for an exact_gap N, a gap of
/// exactly `gap_amount` from its sourced value; and the harness-only twin
/// shows what the mechanism predicts: it reports, is refused or, for an
/// exact_gap N's twin target in the same book, shows a gap of 0. A run that
/// is refused or errors is FAIL, never UNRUN. Like D and P, an N still lacks
/// the filler-invariance witness, so agreement reads UNRUN.
fn n_row(
    run: &BookRun<'_>,
    e: &Expectation,
    spec: Option<&Result<TwinSpec, String>>,
    twin: Option<&BookRun<'_>>,
    mut row: RowLine,
) -> Eval {
    let f = &e.fields;
    let kind = f.str("kind").unwrap_or_default();
    let target = f.str("target").unwrap_or_default();
    let intent = intent_of(run, target);
    row.projection.push(("kind".into(), kind.to_string()));
    let mut fails: Vec<String> = Vec::new();
    let mut needs: Option<String> = None;
    let mut repro: Vec<String> = Vec::new();
    let procedure = f.str("procedure").unwrap_or_default();
    let version = f.int("version");
    // The target run.
    match kind {
        "no_refusal" => match run.posts.get(&intent) {
            Some(c) if c.exit == 0 && run.vids.contains_key(&intent) => {}
            Some(c) => {
                fails.push(format!(
                    "expected {intent} admitted observed exit={}{}",
                    c.exit,
                    c.refusal_id()
                        .map_or_else(String::new, |r| format!(" refusal={r}"))
                ));
                repro.push(reproduce(c));
            }
            None => fails.push(format!("expected a post of {intent} observed none")),
        },
        "no_finding" => {
            if let Some(c) = run.posts.get(&intent)
                && (c.exit != 0 || !run.vids.contains_key(&intent))
            {
                fails.push(format!(
                    "expected {intent} posted observed exit={}{}",
                    c.exit,
                    c.refusal_id()
                        .map_or_else(String::new, |r| format!(" refusal={r}"))
                ));
                repro.push(reproduce(c));
            }
            match recorded_run(run, procedure, version, "a ") {
                Ok(found) => match findings_on(run, found, &intent) {
                    0 => {}
                    n => fails.push(format!(
                        "expected no {procedure} finding on {intent} observed {n}"
                    )),
                },
                Err((why, call)) => {
                    fails.push(why);
                    repro.extend(call);
                }
            }
        }
        "exact_gap" => match recorded_run(run, procedure, version, "a ")
            .and_then(|found| gap_on(run, e, target, found).map_err(|why| (why, None)))
        {
            Ok((gap, scale)) => {
                let observed = format_amount(gap, scale);
                let unit = f.str("gap_unit").unwrap_or_default();
                let want = f.str("gap_amount").unwrap_or_default();
                match unit_scale(unit) {
                    Some(s) if s != scale => fails.push(mismatch("scale", s, scale)),
                    Some(s) if parse_amount(want, s).ok() != Some(gap) => {
                        fails.push(mismatch("gap", want, &observed));
                    }
                    Some(_) => {}
                    None => {
                        fails.push(format!("expected gap_unit {unit} registered observed none"))
                    }
                }
                row.projection.push(("gap".into(), observed));
            }
            Err((why, call)) => {
                fails.push(why);
                repro.extend(call);
            }
        },
        _ => needs = Some(format!("needs:A11c ({kind} evaluation)")),
    }
    // The twin. An exact_gap N's twin target is in the target's own book.
    let twin = match spec {
        Some(Ok(s)) if s.n_kind == "exact_gap" => Some(run),
        _ => twin,
    };
    let token = match spec {
        None => {
            fails.push("expected a twin observed none".into());
            "none".to_string()
        }
        Some(Err(why)) => {
            fails.push(format!("expected a twin observed {why}"));
            "invalid".to_string()
        }
        Some(Ok(spec)) if spec.kind == TwinKind::Matcher => {
            needs.get_or_insert_with(|| "needs:A16 (matcher twin)".into());
            "matcher:unrun".to_string()
        }
        Some(Ok(spec)) => match twin {
            None => {
                needs.get_or_insert_with(|| format!("needs:A11c ({} twin)", spec.n_kind));
                format!("{}:unrun", spec.kind.as_str())
            }
            Some(t) => {
                let twin_intent = intent_of(t, &spec.twin_target);
                if let Some(why) = &t.failure {
                    fails.push(format!("expected the twin to run observed {why}"));
                    format!("{}:errored", spec.kind.as_str())
                } else {
                    match &spec.expect {
                        TwinExpect::Reports => {
                            match recorded_run(t, procedure, version, "the twin's ") {
                                Ok(found) if findings_on(t, found, &twin_intent) > 0 => {
                                    format!("{}:reported", spec.kind.as_str())
                                }
                                Ok(found) => {
                                    fails.push(format!(
                                        "expected the twin to report observed did_not_report{}",
                                        below_minimum(t, found, procedure).unwrap_or_default()
                                    ));
                                    format!("{}:did_not_report", spec.kind.as_str())
                                }
                                Err((why, call)) => {
                                    fails.push(why);
                                    repro.extend(call);
                                    format!("{}:errored", spec.kind.as_str())
                                }
                            }
                        }
                        TwinExpect::Refuses(want) => {
                            let call = t.posts.get(&twin_intent);
                            let got = call.and_then(super::run::Call::refusal_id);
                            if got.as_deref() != Some(want.as_str()) {
                                fails.push(format!(
                                    "expected the twin refused refusal={want} observed {}",
                                    got.clone().unwrap_or_else(|| "admitted".into())
                                ));
                                if let Some(c) = call {
                                    repro.push(reproduce(c));
                                }
                            }
                            format!(
                                "{}:refused:{}",
                                spec.kind.as_str(),
                                got.unwrap_or_else(|| "none".into())
                            )
                        }
                        TwinExpect::GapZero => {
                            match recorded_run(t, procedure, version, "the twin's ").and_then(
                                |found| {
                                    gap_on(t, e, &spec.twin_target, found)
                                        .map_err(|why| (why, None))
                                },
                            ) {
                                Ok((gap, scale)) => {
                                    let observed = format_amount(gap, scale);
                                    if gap != 0 {
                                        fails.push(format!(
                                        "expected the twin target {} gap=0 observed gap={observed}",
                                        spec.twin_target
                                    ));
                                    }
                                    format!("{}:gap:{observed}", spec.kind.as_str())
                                }
                                Err((why, call)) => {
                                    fails.push(why);
                                    repro.extend(call);
                                    format!("{}:errored", spec.kind.as_str())
                                }
                            }
                        }
                    }
                }
            }
        },
    };
    row.projection.push(("twin".into(), token));
    let witnesses = vec![("twin_target".to_string(), intent.clone())];
    // An exact_gap target and its twin target can name the same failed call.
    repro.dedup();
    let repro = (!repro.is_empty()).then(|| repro.join("\n"));
    if !fails.is_empty() {
        row.verdict = RowVerdict::Fail;
        row.reason = Some(fails.join("; "));
    } else if let Some(n) = needs {
        row.verdict = RowVerdict::Unrun;
        row.reason = Some(n);
    } else {
        row.verdict = RowVerdict::Unrun;
        row.reason = Some(FILLER.into());
    }
    (row, witnesses, repro)
}
