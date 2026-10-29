//! The migration steps (docs/FORENSIC_CASE_STUDIES_PLAN.md §6.6; bead
//! fa-yugf.18, A7m): `migrate_open`, `migrate_stage` and
//! `migrate_finalize`.
//!
//! `migrate_open` derives the variant's legacy trial balance
//! (`fa_oracles::cases::migration_doc`) and opens a sole-source FullDetail
//! run that declares it for every Historical period, its trial balance the
//! step's `[[document]]` (the derived document, added in setup).
//! `migrate_stage` stages each intent of its range as one chunk: planned
//! with `--plan-out` in the step principal's hand, approved by the step's
//! two approvers, and committed with those approvals. A twin first commits
//! the plan with the first approval only, which
//! `sod_policy.toml#migration-locked` refuses. A chunk carries its intent's
//! legacy `source_entered_by` and `source_approved_by`; its recorded time is
//! never authored. `migrate_finalize` first runs each of the variant's D
//! procedures, which see no staged chunk until the run is finalized (§6.6),
//! then plans, approves and commits the finalize. Each step logs one
//! `MIGRATION <variant> <step> <token>...` line; a refused call logs its
//! refusal there and its reproduce line, and the steps after it run on.

use fa_oracles::cases::book::{StepDef, StepKind};
use fa_oracles::cases::expect::ExpectationType;
use fa_oracles::cases::intent_json;
use fa_oracles::cases::migration_doc;
use fa_oracles::json::Json;

use super::run::{BookRun, Call, reproduce, s};

/// `refused:<refusal id>:exit=<n>`.
fn refused(call: &Call) -> String {
    format!(
        "refused:{}:exit={}",
        call.refusal_id().as_deref().unwrap_or("none"),
        call.exit
    )
}

impl BookRun<'_> {
    fn with_principal(step: &StepDef, mut args: Vec<String>) -> Vec<String> {
        if let Some(p) = step.principal.as_deref() {
            args.extend([s("--as"), p.to_string()]);
        }
        args.push(s("--json"));
        args
    }

    /// The run a stage or finalize step addresses: the run its `migrate_open`
    /// step opened (a finalize names that step's seq; a stage the latest).
    fn migration_run(&self, step: &StepDef) -> Option<String> {
        if step.step_kind() == Some(StepKind::MigrateFinalize) {
            let seq = step.reference.parse::<i128>().ok()?;
            return self.migration_runs.get(&seq).cloned();
        }
        self.migration_runs
            .range(..step.seq)
            .next_back()
            .map(|(_, v)| v.clone())
    }

    /// `migrate_open`.
    pub(crate) fn migrate_open(&mut self, step: &StepDef) {
        let stem = self.book.stem.clone();
        let tb = match migration_doc::legacy_tb(self.book) {
            Ok(tb) => tb,
            Err(e) => {
                self.fail(format!(
                    "expected the legacy trial balance of {stem} (step {}) observed {e}",
                    step.seq
                ));
                return;
            }
        };
        let Some(oid) = self.documents.get(&step.reference).cloned() else {
            self.fail(format!(
                "expected document {} to be added (step {}) observed none",
                step.reference, step.seq
            ));
            return;
        };
        let mut periods = Vec::new();
        for p in &tb {
            let Some(code) = self.periods.get(&p.period).cloned() else {
                self.fail(format!(
                    "expected a created period for label {} (step {}) observed none",
                    p.period, step.seq
                ));
                return;
            };
            let lines = p
                .lines
                .iter()
                .map(|l| {
                    let side = if l.minor > 0 { "debit" } else { "credit" };
                    Json::Object(vec![
                        ("account".into(), Json::Str(l.account.clone())),
                        ("unit".into(), Json::Str(l.unit.clone())),
                        (side.into(), Json::Str(l.magnitude())),
                    ])
                })
                .collect();
            periods.push(Json::Object(vec![
                ("period".into(), Json::Str(code)),
                ("trial_balance".into(), Json::Str(oid.clone())),
                ("lines".into(), Json::Array(lines)),
            ]));
        }
        let body = Json::Object(vec![
            (
                "run_key".into(),
                Json::Str(format!("{}-{stem}-{}", self.case.header.id, step.seq)),
            ),
            ("source_system".into(), Json::Str("legacy".into())),
            ("mode".into(), Json::Str("FullDetail".into())),
            ("trial_balance".into(), Json::Str(oid)),
            (
                "opening_date".into(),
                Json::Str(self.book.book.opening_date.clone()),
            ),
            ("sole_opening_source".into(), Json::Bool(true)),
            ("periods".into(), Json::Array(periods)),
        ]);
        let file = self.write(
            &format!("migration-run-{}.json", step.seq),
            body.to_string().as_bytes(),
        );
        let args = Self::with_principal(step, vec![s("migrate"), s("open"), s("--intent"), file]);
        let call = self.call(step.seq, &step.reference, "migrate", args);
        let labels: Vec<&str> = tb.iter().map(|p| p.period.as_str()).collect();
        let token = match call.str_field("migration_controlled", "run_vid") {
            Some(vid) => {
                let placeholder = format!("$RUN_{}", step.seq);
                self.bind(
                    &vid,
                    placeholder.clone(),
                    "migration_controlled.run_vid",
                    step.seq,
                    &step.reference,
                );
                self.migration_runs.insert(step.seq, vid);
                format!("run={placeholder} periods={}", labels.join(","))
            }
            None => {
                self.lines.push(reproduce(&call));
                refused(&call)
            }
        };
        self.lines.push(format!("MIGRATION {stem} open {token}"));
    }

    /// `migrate_stage`: each intent of the range, one chunk.
    pub(crate) fn migrate_stage(&mut self, step: &StepDef) {
        let book = self.book;
        let stem = book.stem.clone();
        let Some(run) = self.migration_run(step) else {
            self.fail(format!(
                "expected an opened migration run before step {} observed none",
                step.seq
            ));
            return;
        };
        let Some((a, b)) = step.reference.split_once("..") else {
            self.fail(format!(
                "expected an intent range A..B (step {}) observed {}",
                step.seq, step.reference
            ));
            return;
        };
        let pos = |id: &str| book.intents.iter().position(|i| i.id == id);
        let (Some(pa), Some(pb)) = (pos(a), pos(b)) else {
            self.fail(format!(
                "expected intents {a} and {b} (step {}) observed none",
                step.seq
            ));
            return;
        };
        let mut tokens = vec![step.reference.clone()];
        for it in &book.intents[pa..=pb] {
            let vids = self.vids.clone();
            let mut fields = match intent_json::render(book, it, &|t| vids.get(t).cloned()) {
                Ok(Json::Object(fields)) => fields,
                Ok(_) | Err(_) => {
                    self.fail(format!(
                        "expected intent {} to render (step {}) observed none",
                        it.id, step.seq
                    ));
                    return;
                }
            };
            for (k, v) in [
                ("source_entered_by", &it.source_entered_by),
                ("source_approved_by", &it.source_approved_by),
            ] {
                if let Some(v) = v.as_deref() {
                    fields.push((k.into(), Json::Str(v.to_string())));
                }
            }
            let file = self.write(
                &format!("{}.chunk.json", it.id),
                Json::Object(fields).to_string().as_bytes(),
            );
            let Some(code) = self.period_of(&it.effective_date) else {
                self.fail(format!(
                    "expected a period containing {} for {} observed none",
                    it.effective_date, it.id
                ));
                return;
            };
            let plan = self.work.join(format!("{}.stage.plan", it.id));
            let mut args = vec![
                s("migrate"),
                s("stage"),
                run.clone(),
                s("--intent"),
                file,
                s("--period"),
                code,
            ];
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
            args.extend([s("--plan-out"), plan.display().to_string()]);
            let planned = self.call(
                step.seq,
                &it.id,
                "migrate",
                Self::with_principal(step, args),
            );
            let Some(digest) = planned.str_field("migration_planned", "proposal_digest") else {
                self.lines.push(reproduce(&planned));
                tokens.push(format!("{}={}", it.id, refused(&planned)));
                continue;
            };
            let mut approvals = Vec::new();
            for a in step.approvers.clone().unwrap_or_default() {
                match self.approve_as(step.seq, &a, &digest) {
                    Some(v) => approvals.push(v),
                    None => return,
                }
            }
            let commit = |approvals: &[String]| {
                let mut args = vec![
                    s("migrate"),
                    s("stage"),
                    run.clone(),
                    s("--plan"),
                    plan.display().to_string(),
                ];
                for v in approvals {
                    args.extend([s("--approval"), v.clone()]);
                }
                Self::with_principal(step, args)
            };
            if let Some(first) = approvals.first().cloned() {
                let twin = self.call(step.seq, &it.id, "migrate", commit(&[first]));
                tokens.push(format!("one_approval={}", refused(&twin)));
            }
            let call = self.call(step.seq, &it.id, "migrate", commit(&approvals));
            match call.str_field("posted", "vid") {
                Some(vid) => {
                    self.bind(&vid, format!("${}", it.id), "posted.vid", step.seq, &it.id);
                    self.vids.insert(it.id.clone(), vid.clone());
                    self.posted_steps.insert(it.id.clone(), step.seq);
                    self.map_legs(step.seq, &it.id, &vid);
                    tokens.push(format!("{}=staged", it.id));
                }
                None => {
                    self.lines.push(reproduce(&call));
                    tokens.push(format!("{}={}", it.id, refused(&call)));
                }
            }
            self.posts.insert(it.id.clone(), call);
        }
        self.lines
            .push(format!("MIGRATION {stem} stage {}", tokens.join(" ")));
    }

    /// `migrate_finalize`: the variant's D procedures over the staged run,
    /// then the finalize, planned, approved and committed.
    pub(crate) fn migrate_finalize(&mut self, step: &StepDef) {
        let stem = self.book.stem.clone();
        let Some(run) = self.migration_run(step) else {
            self.fail(format!(
                "expected the run of migrate_open step {} (step {}) observed none",
                step.reference, step.seq
            ));
            return;
        };
        let mut tokens = Vec::new();
        for procedure in self.d_procedures() {
            let args =
                Self::with_principal(step, vec![s("procedure"), s("run"), procedure.clone()]);
            let call = self.call(step.seq, &procedure, "procedure", args);
            let count = call
                .event("procedure_run")
                .and_then(|o| o.field("finding_count"))
                .and_then(Json::as_int);
            match count {
                Some(n) => tokens.push(format!("before={procedure}:{n}")),
                None => {
                    self.lines.push(reproduce(&call));
                    tokens.push(format!("before={procedure}:{}", refused(&call)));
                }
            }
        }
        let plan = self.work.join(format!("finalize-{}.plan", step.seq));
        let args = Self::with_principal(
            step,
            vec![
                s("migrate"),
                s("finalize"),
                run.clone(),
                s("--plan-out"),
                plan.display().to_string(),
            ],
        );
        let planned = self.call(step.seq, &step.reference, "migrate", args);
        let Some(digest) = planned.str_field("migration_planned", "proposal_digest") else {
            self.lines.push(reproduce(&planned));
            tokens.push(format!("finalize={}", refused(&planned)));
            self.lines
                .push(format!("MIGRATION {stem} finalize {}", tokens.join(" ")));
            return;
        };
        let mut approvals = Vec::new();
        for a in step.approvers.clone().unwrap_or_default() {
            match self.approve_as(step.seq, &a, &digest) {
                Some(v) => approvals.push(v),
                None => return,
            }
        }
        let mut args = vec![
            s("migrate"),
            s("finalize"),
            run,
            s("--plan"),
            plan.display().to_string(),
        ];
        for v in approvals {
            args.extend([s("--approval"), v]);
        }
        let call = self.call(
            step.seq,
            &step.reference,
            "migrate",
            Self::with_principal(step, args),
        );
        match call.str_field("migration_controlled", "to") {
            Some(state) => tokens.push(format!("finalize={state}")),
            None => {
                self.lines.push(reproduce(&call));
                tokens.push(format!("finalize={}", refused(&call)));
            }
        }
        self.lines
            .push(format!("MIGRATION {stem} finalize {}", tokens.join(" ")));
    }

    /// The procedures of this variant's D expectations, in file order.
    fn d_procedures(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for e in self
            .case
            .expectations
            .iter()
            .flat_map(|set| set.expectations.iter())
            .filter(|e| {
                e.kind == ExpectationType::D
                    && e.fields.str("book_variant") == Some(self.book.stem.as_str())
            })
        {
            if let Some(p) = e.fields.str("procedure")
                && !out.iter().any(|o| o == p)
            {
                out.push(p.to_string());
            }
        }
        out
    }
}
