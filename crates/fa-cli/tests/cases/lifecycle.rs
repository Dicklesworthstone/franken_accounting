//! History steps of the restatement life cycle
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.3 steps 4 and 5; bead fa-yugf.16,
//! A7b): the `issue` step, and a restatement case's steps.
//!
//! An `issue` step certifies its period's balance sheet, plans that
//! certificate's StatementIssuance to the SEC citing the step's filing stub
//! in the step principal's hand, has each of the step's approvers approve
//! the plan's digest, and commits exactly that plan. A period's n-th
//! issuance binds its certificate to `$C_ISSUE_<period>` (n = 1) or
//! `$C_ISSUE_<period>_<n>`, and a `reported_in:<period>#<n>` read reads the
//! period as reported in it. An issuance the book refuses is a setup
//! failure: the reads after it would answer a different question.
//!
//! A `[[case]]` runs as `crates/fa-cli/tests/cli.rs` runs one: `case_open`
//! (the determination with it, unless a `case_determine` step follows),
//! `scenario_fork`/`scenario_run`/`scenario_diff` (the case's deltas
//! planned into a scenario and its diff certified to a file),
//! `case_rehearse` (that certificate), `case_approve` (the manifest digest
//! approved by the case's two approvers; a twin first cites one approval,
//! refused FA-REF-012, and the case stays Rehearsed), `case_post` (each
//! delta's twin first, posted outside its case and refused FA-REF-178; then
//! the post by its poster, `fa case diff --statements --certify` and each
//! restated target's lineage), `case_disclose` (an unreviewed twin first, refused
//! FA-REF-179, then a reviewed Disclosure copy of the case's disclosure
//! stub) and `case_close`. `fa case` takes the book's number for a case,
//! not its label: `case_open` logs the map (`CASES <variant>
//! <case>=<number>`). A refused case step leaves the case where it is, and
//! the case's generated read-back row reports its state.

use fa_oracles::cases::book::{CaseDef, DocumentDef, IntentDef, StepDef, StepKind};
use fa_oracles::cases::fact::LiteralRule;
use fa_oracles::cases::intent_json;
use fa_oracles::json::Json;

use super::run::{BookRun, Call, reproduce, s};

/// A certified scenario diff (a `scenario_diff` step): the scenario, the
/// file its certificate was written to, and the call, whose `scenario_diff`
/// event carries the diff's changed rows and whose `report_certificate`
/// event the retained certificate a `scenario-diff` read cites.
pub struct ScenarioDiffRun {
    pub name: String,
    pub certificate: String,
    pub call: Call,
}

impl BookRun<'_> {
    /// An `issue` step (§3.3 step 4).
    pub(crate) fn issue(&mut self, step: &StepDef) {
        let label = step.reference.as_str();
        let Some(code) = self.periods.get(label).cloned() else {
            self.fail(format!(
                "expected a created period for label {label} (step {}) observed none",
                step.seq
            ));
            return;
        };
        let n = self.issuances.get(label).map_or(0, Vec::len) + 1;
        let placeholder = if n == 1 {
            format!("$C_ISSUE_{label}")
        } else {
            format!("$C_ISSUE_{label}_{n}")
        };
        let principal = step.principal.clone();
        let with_principal = |mut args: Vec<String>| {
            if let Some(p) = principal.as_deref() {
                args.extend([s("--as"), p.to_string()]);
            }
            args.push(s("--json"));
            args
        };
        // Retaining the certificate needs produce, which the owner holds and
        // the planner need not.
        let certified = self.call(
            step.seq,
            label,
            "statement",
            vec![
                s("statement"),
                s("balance-sheet"),
                s("--for"),
                code.clone(),
                s("--certify"),
                s("--json"),
            ],
        );
        self.certificate_kind("BalanceSheet");
        let Some(oid) = certified.str_field("report_certificate", "oid") else {
            self.lines.push(reproduce(&certified));
            self.fail(format!(
                "expected a certified balance sheet of {label} to issue (step {}) observed exit={}",
                step.seq, certified.exit
            ));
            return;
        };
        self.bind(&oid, placeholder, "report_certificate.oid", step.seq, label);
        let mut args = vec![
            s("statement"),
            s("issue"),
            s("--certificate"),
            format!("C:{oid}"),
            s("--for"),
            code,
            s("--issued-to"),
            s("sec"),
        ];
        if let Some(doc) = step.document.as_deref().and_then(|d| self.documents.get(d)) {
            args.extend([s("--document"), doc.clone()]);
        }
        args.push(s("--dry-run"));
        let planned = self.call(step.seq, label, "statement", with_principal(args));
        let (Some(digest), Some(bytes)) = (
            planned.str_field("statement_issuance_plan", "proposal_digest"),
            planned.str_field("statement_issuance_plan", "bytes"),
        ) else {
            self.lines.push(reproduce(&planned));
            self.fail(format!(
                "expected an issuance plan for {label} (step {}) observed exit={} {}",
                step.seq,
                planned.exit,
                planned.refusal_id().unwrap_or_default()
            ));
            return;
        };
        let plan = self.work.join(format!("issue-{}.plan", step.seq));
        if let Err(err) = std::fs::write(&plan, bytes) {
            self.fail(format!("write {}: {err}", plan.display()));
            return;
        }
        let mut args = vec![
            s("statement"),
            s("issue"),
            s("--plan"),
            plan.display().to_string(),
        ];
        for approver in step.approvers.clone().unwrap_or_default() {
            match self.approve_as(step.seq, &approver, &digest) {
                Some(vid) => args.extend([s("--approval"), vid]),
                None => {
                    self.fail(format!(
                        "expected {approver} to approve the issuance of {label} (step {}) observed no approval",
                        step.seq
                    ));
                    return;
                }
            }
        }
        let issued = self.call(step.seq, label, "statement", with_principal(args));
        self.certificate_kind("StatementIssuance");
        if issued.event("statement_issued").is_none() {
            self.lines.push(reproduce(&issued));
            self.fail(format!(
                "expected {label}'s issuance #{n} recorded (step {}) observed exit={} {}",
                step.seq,
                issued.exit,
                issued.refusal_id().unwrap_or_default()
            ));
            return;
        }
        self.issuances
            .entry(label.to_string())
            .or_default()
            .push(oid);
    }

    /// Marks the last step record's call as retaining a certificate of
    /// `kind` (§3.5).
    pub(crate) fn certificate_kind(&mut self, kind: &str) {
        if let Some(last) = self.steps.last_mut() {
            last.certificate_kind = Some(kind.to_string());
        }
    }
}

/// What a `[[case]]`'s steps left for its generated read-back row
/// (§3.3 step 5).
#[derive(Default)]
pub struct CaseRun {
    /// The number `fa case open` reported.
    pub number: Option<i128>,
    /// The scenario its rehearsal certified.
    pub scenario: Option<String>,
    /// The Disclosure document `case_disclose` added and had reviewed.
    pub disclosure: Option<String>,
    /// `fa case disclose` citing the unreviewed twin of that document.
    pub twin: Option<Call>,
    /// `fa case approve` citing the first approver's approval alone, and
    /// the state `fa case show` read after it.
    pub one_approval: Option<(Call, String)>,
    /// Each rehearsed delta posted on its own (`fa post --intent`) once the
    /// case is approved.
    pub outside: Vec<(String, Call)>,
    /// `fa explain lineage` of each restated target after the post.
    pub lineages: Vec<(String, Call)>,
    /// `fa case show <number>` after the history.
    pub show: Option<Call>,
    /// `fa certificate status` of each restated period's first issuance
    /// (its as-filed statement certificate) after the history (A12).
    pub statuses: Vec<(String, Call)>,
}

/// `args`, run as the step's principal (when it names one), in robot mode.
pub(crate) fn as_principal(step: &StepDef, mut args: Vec<String>) -> Vec<String> {
    if let Some(p) = step.principal.as_deref() {
        args.extend([s("--as"), p.to_string()]);
    }
    args.push(s("--json"));
    args
}

impl<'c> BookRun<'c> {
    /// The `[[case]]` a case step names.
    fn case_of(&mut self, step: &StepDef) -> Option<&'c CaseDef> {
        let book = self.book;
        let found = book.cases.iter().find(|c| c.id == step.reference);
        if found.is_none() {
            self.fail(format!(
                "expected a [[case]] {} (step {}) observed none",
                step.reference, step.seq
            ));
        }
        found
    }

    /// The `[[case]]` a case step names and the number the book gave it.
    fn case_number(&mut self, step: &StepDef) -> Option<(&'c CaseDef, String)> {
        let case = self.case_of(step)?;
        if let Some(n) = self.cases.get(&case.id).and_then(|r| r.number) {
            return Some((case, n.to_string()));
        }
        self.fail(format!(
            "expected case {} opened before step {} observed no case number",
            case.id, step.seq
        ));
        None
    }

    /// A case's determination day (§2.6 `case_determination_date`): the date
    /// of its `determined_on` fact, or with `default`, the restating
    /// filing's date (the `filed_on` of the source its authority document
    /// stubs).
    pub(crate) fn determination_day(&self, case: &CaseDef) -> Result<String, String> {
        if case.determined_on == "default" {
            return self
                .book
                .documents
                .iter()
                .find(|d| d.id == case.authority)
                .and_then(|d| self.case.sources.iter().find(|x| x.id == d.stub_of))
                .and_then(|x| x.filed_on.clone())
                .ok_or_else(|| {
                    format!(
                        "expected the filed_on of the source {} stubs observed none",
                        case.authority
                    )
                });
        }
        self.case
            .values
            .iter()
            .find(|v| v.fact == case.determined_on && v.rule == LiteralRule::DateLiteral)
            .map(|v| v.value.clone())
            .ok_or_else(|| format!("expected a date of {} observed none", case.determined_on))
    }

    /// The determination day and the authority document's oid.
    fn determination(&self, case: &CaseDef) -> Result<(String, String), String> {
        let day = self.determination_day(case)?;
        let authority = self
            .documents
            .get(&case.authority)
            .cloned()
            .ok_or_else(|| {
                format!(
                    "expected the authority document {} added observed none",
                    case.authority
                )
            })?;
        Ok((day, authority))
    }

    /// A `case_open` step: `fa case open`, the determination recorded with
    /// it unless a `case_determine` step of the case follows. The book's
    /// number for the case is logged (`CASES <variant> <case>=<number>`) and
    /// used by every later `fa case` argv.
    pub(crate) fn case_open(&mut self, step: &StepDef) {
        let Some(case) = self.case_of(step) else {
            return;
        };
        let Some(codes) = case
            .periods
            .iter()
            .map(|p| self.periods.get(p).cloned())
            .collect::<Option<Vec<_>>>()
        else {
            self.fail(format!(
                "expected the periods {:?} of case {} created observed none",
                case.periods, case.id
            ));
            return;
        };
        let mut args = vec![
            s("case"),
            s("open"),
            s("--kind"),
            case.kind.clone(),
            s("--periods"),
            codes.join(","),
        ];
        let determined_later = self
            .book
            .steps
            .iter()
            .any(|x| x.step_kind() == Some(StepKind::CaseDetermine) && x.reference == case.id);
        if !determined_later {
            match self.determination(case) {
                Ok((day, authority)) => {
                    args.extend([s("--determined-on"), day, s("--authority"), authority]);
                }
                Err(why) => {
                    self.fail(why);
                    return;
                }
            }
        }
        let call = self.call(step.seq, &case.id, "case", as_principal(step, args));
        let number = call
            .event("case_opened")
            .and_then(|o| o.field("case"))
            .and_then(|c| c.get("case"))
            .and_then(Json::as_int);
        let Some(number) = number else {
            self.lines.push(reproduce(&call));
            self.fail(format!(
                "expected case {} opened (step {}) observed exit={} {}",
                case.id,
                step.seq,
                call.exit,
                call.refusal_id().unwrap_or_default()
            ));
            return;
        };
        self.lines
            .push(format!("CASES {} {}={number}", self.book.stem, case.id));
        self.cases.insert(
            case.id.clone(),
            CaseRun {
                number: Some(number),
                ..CaseRun::default()
            },
        );
    }

    /// A `case_determine` step: `fa case determine <case> --on <day>
    /// --authority <oid>`.
    pub(crate) fn case_determine(&mut self, step: &StepDef) {
        let Some((case, n)) = self.case_number(step) else {
            return;
        };
        let (day, authority) = match self.determination(case) {
            Ok(d) => d,
            Err(why) => {
                self.fail(why);
                return;
            }
        };
        let args = vec![
            s("case"),
            s("determine"),
            n,
            s("--on"),
            day,
            s("--authority"),
            authority,
        ];
        let call = self.call(step.seq, &case.id, "case", as_principal(step, args));
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
        }
    }

    /// The intents planned into scenario `name`, in file order.
    fn planned_into(&self, name: &str) -> Vec<&'c IntentDef> {
        let book = self.book;
        book.intents
            .iter()
            .filter(|i| i.scenario.as_deref() == Some(name))
            .collect()
    }

    /// A `scenario_fork` step: `fa scenario fork <name>` at the head.
    pub(crate) fn scenario_fork(&mut self, step: &StepDef) {
        let args = vec![s("scenario"), s("fork"), step.reference.clone()];
        let call = self.call(
            step.seq,
            &step.reference,
            "scenario",
            as_principal(step, args),
        );
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
            self.fail(format!(
                "expected scenario {} forked (step {}) observed exit={} {}",
                step.reference,
                step.seq,
                call.exit,
                call.refusal_id().unwrap_or_default()
            ));
        }
    }

    /// A `scenario_run` step: every intent planned into the scenario, in
    /// file order, run into it in its own principal's hand citing its
    /// evidence document, a Restatement with the restate grant (§3.3 step
    /// 5).
    pub(crate) fn scenario_run(&mut self, step: &StepDef) {
        let book = self.book;
        for it in self.planned_into(&step.reference) {
            let vids = self.vids.clone();
            let doc = match intent_json::render(book, it, &|t| vids.get(t).cloned()) {
                Ok(doc) => doc,
                Err(e) => {
                    self.fail(format!(
                        "expected intent {} to render (step {}) observed {e:?}",
                        it.id, step.seq
                    ));
                    return;
                }
            };
            let file = self.write(&format!("{}.json", it.id), doc.to_string().as_bytes());
            let mut args = vec![
                s("scenario"),
                s("run"),
                step.reference.clone(),
                s("--intent"),
                file,
                s("--as"),
                it.principal.clone(),
            ];
            if it.class == "Restatement" {
                args.extend([s("--grant"), s("restate")]);
            }
            // The entry cites the intent's evidence, as a posted one does.
            if let Some(e) = it.evidence.as_deref() {
                let Some(oid) = self.documents.get(e).cloned() else {
                    self.fail(format!(
                        "expected evidence {e} of {} to be added observed none",
                        it.id
                    ));
                    return;
                };
                args.extend([s("--evidence"), oid]);
            }
            args.push(s("--json"));
            let call = self.call(step.seq, &it.id, "scenario", args);
            if call.exit != 0 {
                self.lines.push(reproduce(&call));
                self.fail(format!(
                    "expected {} planned into scenario {} (step {}) observed exit={} {}",
                    it.id,
                    step.reference,
                    step.seq,
                    call.exit,
                    call.refusal_id().unwrap_or_default()
                ));
                return;
            }
            if let Some(entry) = call.str_field("scenario_run", "entry") {
                self.planned_entries.insert(it.id.clone(), entry);
            }
        }
    }

    /// A `scenario_diff` step: `fa scenario diff <name>` over every period
    /// the scenario's intents fall in, its certificate written to a file a
    /// later `case_rehearse` cites.
    pub(crate) fn scenario_diff(&mut self, step: &StepDef) {
        let name = step.reference.clone();
        let planned = self.planned_into(&name);
        let book = self.book;
        let codes: Vec<String> = book
            .periods
            .iter()
            .filter(|p| {
                planned.iter().any(|i| {
                    p.start.as_str() <= i.effective_date.as_str()
                        && i.effective_date.as_str() <= p.end.as_str()
                })
            })
            .filter_map(|p| self.periods.get(&p.code).cloned())
            .collect();
        let certificate = self
            .work
            .join(format!("scenario-{name}-{}.cert", step.seq))
            .display()
            .to_string();
        let mut args = vec![s("scenario"), s("diff"), name.clone()];
        for code in codes {
            args.extend([s("--period"), code]);
        }
        args.extend([s("--certificate-out"), certificate.clone()]);
        let call = self.call(step.seq, &name, "scenario", as_principal(step, args));
        self.certificate_kind("ScenarioDiff");
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
            self.fail(format!(
                "expected scenario {name}'s diff certified (step {}) observed exit={} {}",
                step.seq,
                call.exit,
                call.refusal_id().unwrap_or_default()
            ));
            return;
        }
        self.scenario_diffs.push(ScenarioDiffRun {
            name,
            certificate,
            call,
        });
    }

    /// A `case_rehearse` step: `fa case rehearse <case> --certificate` with
    /// the latest scenario diff the history certified.
    pub(crate) fn case_rehearse(&mut self, step: &StepDef) {
        let Some((case, n)) = self.case_number(step) else {
            return;
        };
        let Some((scenario, certificate)) = self
            .scenario_diffs
            .last()
            .map(|d| (d.name.clone(), d.certificate.clone()))
        else {
            self.fail(format!(
                "expected a scenario_diff before case_rehearse (step {}) observed none",
                step.seq
            ));
            return;
        };
        let args = vec![s("case"), s("rehearse"), n, s("--certificate"), certificate];
        let call = self.call(step.seq, &case.id, "case", as_principal(step, args));
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
        }
        if let Some(r) = self.cases.get_mut(&case.id) {
            r.scenario = Some(scenario);
        }
    }

    /// A `case_approve` step: the manifest's digest (`--dry-run`), approved
    /// by each of the case's two approvers. Its harness twin first: `fa case
    /// approve` with the first approval alone, which must be refused
    /// FA-REF-012 and leave the case Rehearsed. Then both approvals.
    pub(crate) fn case_approve(&mut self, step: &StepDef) {
        let Some((case, n)) = self.case_number(step) else {
            return;
        };
        let manifest = self.call(
            step.seq,
            &case.id,
            "case",
            vec![
                s("case"),
                s("approve"),
                n.clone(),
                s("--dry-run"),
                s("--json"),
            ],
        );
        let Some(digest) = manifest.str_field("case_manifest", "digest") else {
            self.lines.push(reproduce(&manifest));
            return;
        };
        let mut vids = Vec::new();
        for approver in &case.approvers {
            match self.approve_as(step.seq, approver, &digest) {
                Some(vid) => vids.push(vid),
                None => return,
            }
        }
        if let Some(first) = vids.first() {
            let args = vec![
                s("case"),
                s("approve"),
                n.clone(),
                s("--approval"),
                first.clone(),
                s("--json"),
            ];
            let twin = self.call(step.seq, &case.id, "case", args);
            let args = vec![s("case"), s("show"), n.clone(), s("--json")];
            let show = self.call(step.seq, &case.id, "case", args);
            let state = show
                .event("case")
                .and_then(|o| o.field("case"))
                .and_then(|c| c.get("state"))
                .and_then(Json::as_str)
                .unwrap_or("none")
                .to_string();
            if let Some(r) = self.cases.get_mut(&case.id) {
                r.one_approval = Some((twin, state));
            }
        }
        let mut args = vec![s("case"), s("approve"), n];
        for vid in vids {
            args.extend([s("--approval"), vid]);
        }
        args.push(s("--json"));
        let call = self.call(step.seq, &case.id, "case", args);
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
        }
    }

    /// A `case_post` step: `fa case post` as the case's poster, then what
    /// the post changed (`fa case diff --statements --certify`) and the
    /// lineage of each target the rehearsed scenario restates.
    pub(crate) fn case_post(&mut self, step: &StepDef) {
        let Some((case, n)) = self.case_number(step) else {
            return;
        };
        let rehearsed = self.cases.get(&case.id).and_then(|r| r.scenario.clone());
        let planned = rehearsed
            .map(|name| self.planned_into(&name))
            .unwrap_or_default();
        // The harness twin of each rehearsed delta: the same intent file
        // `scenario_run` ran, posted on its own while the case is Approved,
        // even confirmed and with restate, must be refused FA-REF-178.
        for it in &planned {
            let file = self.work.join(format!("{}.json", it.id));
            if !file.exists() {
                continue;
            }
            let args = vec![
                s("post"),
                s("--intent"),
                file.display().to_string(),
                s("--grant"),
                s("restate"),
                s("--yes"),
                s("--as"),
                it.principal.clone(),
                s("--json"),
            ];
            let twin = self.call(step.seq, &it.id, "post", args);
            if let Some(r) = self.cases.get_mut(&case.id) {
                r.outside.push((it.id.clone(), twin));
            }
        }
        let args = vec![
            s("case"),
            s("post"),
            n.clone(),
            s("--as"),
            case.poster.clone(),
            s("--json"),
        ];
        let call = self.call(step.seq, &case.id, "case", args);
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
            return;
        }
        // Each delta the post recorded is its intent's entry from now on:
        // the entry `fa scenario run` planned it as, else its place in the
        // rehearsed scenario's order.
        let posted: Vec<String> = call
            .event("case_posted")
            .and_then(|o| o.field("case"))
            .and_then(|c| c.get("posted"))
            .and_then(Json::as_array)
            .unwrap_or_default()
            .iter()
            .filter_map(|p| p.get("entry").and_then(Json::as_str).map(str::to_string))
            .collect();
        for (i, it) in planned.iter().enumerate() {
            let vid = self
                .planned_entries
                .get(&it.id)
                .filter(|v| posted.contains(v))
                .cloned()
                .or_else(|| posted.get(i).cloned());
            if let Some(vid) = vid {
                self.bind(
                    &vid,
                    format!("${}", it.id),
                    "case_posted.case.posted.entry",
                    step.seq,
                    &it.id,
                );
                self.vids.insert(it.id.clone(), vid.clone());
                self.posted_steps.insert(it.id.clone(), step.seq);
                self.map_legs(step.seq, &it.id, &vid);
            }
        }
        let args = vec![
            s("case"),
            s("diff"),
            n,
            s("--statements"),
            s("--certify"),
            s("--json"),
        ];
        let diff = self.call(step.seq, &case.id, "case", args);
        self.certificate_kind("StatementDiff");
        let kept = if diff.exit == 0 {
            Ok(diff)
        } else {
            self.lines.push(reproduce(&diff));
            Err(format!(
                "expected exit=0 from case diff --statements observed exit={} {}",
                diff.exit,
                diff.refusal_id().unwrap_or_default()
            )
            .trim_end()
            .to_string())
        };
        // A case-diff read (E-T-03) reads this diff.
        self.case_statement_diffs.insert(case.id.clone(), kept);
        let targets: Vec<String> = planned
            .into_iter()
            .filter(|i| i.is_delta())
            .filter_map(|i| i.target.clone())
            .collect();
        let mut lineages = Vec::new();
        for target in targets {
            let Some(vid) = self.vids.get(&target).cloned() else {
                continue;
            };
            let args = vec![s("explain"), s("lineage"), vid, s("--json")];
            lineages.push((
                target.clone(),
                self.call(step.seq, &target, "explain", args),
            ));
        }
        if let Some(r) = self.cases.get_mut(&case.id) {
            r.lineages = lineages;
        }
    }

    /// Adds a Disclosure-kind copy of `doc`'s stub (the setup added the stub
    /// itself as Other), marked `mark`, and returns its oid.
    fn disclosure_copy(&mut self, step: &StepDef, doc: &DocumentDef, mark: &str) -> Option<String> {
        let Some(mut bytes) = self.stub_bytes(&doc.stub_of) else {
            self.fail(format!(
                "expected a stub for {} observed stub_of={}",
                doc.id, doc.stub_of
            ));
            return None;
        };
        bytes.extend_from_slice(format!("\n{mark} of case {}\n", step.reference).as_bytes());
        let file = self.write(&format!("{}-{mark}.stub", doc.id), &bytes);
        let args = vec![
            s("document"),
            s("add"),
            file,
            s("--kind"),
            s("Disclosure"),
            s("--json"),
        ];
        let call = self.call(step.seq, &doc.id, "document", args);
        let oid = call.str_field("document", "oid");
        if oid.is_none() {
            self.lines.push(reproduce(&call));
            self.fail(format!(
                "expected the {mark} of {} added (step {}) observed exit={}",
                doc.id, step.seq, call.exit
            ));
        }
        oid
    }

    /// A `case_disclose` step. Its harness twin first: an unreviewed
    /// Disclosure copy of the case's disclosure stub, which `fa case
    /// disclose` must refuse FA-REF-179. Then the reviewed copy (reviewed
    /// by the stub's `reviewed_by`), which it records.
    pub(crate) fn case_disclose(&mut self, step: &StepDef) {
        let Some((case, n)) = self.case_number(step) else {
            return;
        };
        let book = self.book;
        let Some(doc) = book.documents.iter().find(|d| d.id == case.disclosure) else {
            self.fail(format!(
                "expected the disclosure document {} of case {} observed none",
                case.disclosure, case.id
            ));
            return;
        };
        let Some(unreviewed) = self.disclosure_copy(step, doc, "unreviewed-twin") else {
            return;
        };
        let args = vec![
            s("case"),
            s("disclose"),
            n.clone(),
            s("--document"),
            unreviewed,
        ];
        let twin = self.call(step.seq, &case.id, "case", as_principal(step, args));
        let Some(oid) = self.disclosure_copy(step, doc, "disclosure") else {
            return;
        };
        if let Some(reviewer) = doc.reviewed_by.as_deref().filter(|r| !r.is_empty()) {
            let args = vec![
                s("document"),
                s("attest"),
                s("review"),
                oid.clone(),
                s("--as"),
                reviewer.to_string(),
                s("--json"),
            ];
            let review = self.call(step.seq, &doc.id, "document", args);
            if review.exit != 0 {
                self.lines.push(reproduce(&review));
            }
        }
        let args = vec![s("case"), s("disclose"), n, s("--document"), oid.clone()];
        let call = self.call(step.seq, &case.id, "case", as_principal(step, args));
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
        }
        if let Some(r) = self.cases.get_mut(&case.id) {
            r.twin = Some(twin);
            r.disclosure = Some(oid);
        }
    }

    /// A `case_close` step: `fa case close <case>`. A refusal leaves the case
    /// in its state, which its read-back row reports.
    pub(crate) fn case_close(&mut self, step: &StepDef) {
        let Some((case, n)) = self.case_number(step) else {
            return;
        };
        let call = self.call(
            step.seq,
            &case.id,
            "case",
            as_principal(step, vec![s("case"), s("close"), n]),
        );
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
        }
    }

    /// Each opened case's `fa case show` after the history, which its
    /// generated read-back row evaluates.
    pub(crate) fn case_reads(&mut self) {
        let opened: Vec<(String, i128)> = self
            .cases
            .iter()
            .filter_map(|(label, r)| r.number.map(|n| (label.clone(), n)))
            .collect();
        for (label, n) in opened {
            let args = vec![s("case"), s("show"), n.to_string(), s("--json")];
            let call = self.call(self.head, &label, "case", args);
            if let Some(r) = self.cases.get_mut(&label) {
                r.show = Some(call);
            }
            // A12 (§12.7): each restated period's as-filed statement
            // certificate, read after the case posted.
            let book = self.book;
            let posted = book
                .steps
                .iter()
                .any(|x| x.step_kind() == Some(StepKind::CasePost) && x.reference == label);
            let Some(case) = book.cases.iter().find(|c| c.id == label) else {
                continue;
            };
            if !posted {
                continue;
            }
            for period in &case.periods {
                let Some(oid) = self.issuances.get(period).and_then(|v| v.first()).cloned() else {
                    continue;
                };
                let args = vec![
                    s("certificate"),
                    s("status"),
                    format!("C:{oid}"),
                    s("--json"),
                ];
                let call = self.call(self.head, &label, "certificate", args);
                if let Some(r) = self.cases.get_mut(&label) {
                    r.statuses.push((period.clone(), call));
                }
            }
        }
    }
}
