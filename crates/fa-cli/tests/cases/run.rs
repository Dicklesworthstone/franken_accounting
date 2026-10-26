//! The case runner's pipeline (docs/FORENSIC_CASE_STUDIES_PLAN.md §3.3;
//! bead fa-yugf.15, A7a): load and check a case, check the verb table, build
//! each book variant through the real `fa` binary, replay its documented
//! history, run its audit program, evaluate its rows and log every step.
//!
//! This is the walking skeleton. A row whose required witness or
//! prerequisite is not implemented prints UNRUN, never PASS; a step kind the
//! runner does not run yet makes every row of that variant UNRUN with
//! `reason=unrun_step:<kind>`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use fa_oracles::cases::book::{BookVariant, StepKind};
use fa_oracles::cases::check::{self, Verdict};
use fa_oracles::cases::date::Day;
use fa_oracles::cases::embedded::CASES;
use fa_oracles::cases::harness_verbs::{HARNESS_VERBS, missing};
use fa_oracles::cases::log::{StepRecord, VerdictRecord};
use fa_oracles::cases::observe::Observation;
use fa_oracles::cases::selfrow;
use fa_oracles::cases::verdict::{RowLine, RowVerdict};
use fa_oracles::cases::{Case, CaseFiles, intent_json, stub};
use fa_oracles::json::Json;

use super::evaluate;

/// A planted edit of a case file in a test copy: `old` must occur exactly
/// once in the file as it then stands.
#[derive(Clone, Copy, Debug)]
pub struct PlantedEdit {
    pub file: &'static str,
    pub old: &'static str,
    pub new: &'static str,
}

/// What one run of a case produced.
#[derive(Clone, Debug)]
pub struct RunOutcome {
    /// Every printed line: load checks, `PERIODS`, `REPRODUCE`, rows, then
    /// `LOG`.
    pub lines: Vec<String>,
    pub log_path: PathBuf,
    pub steps: Vec<StepRecord>,
    pub verdicts: Vec<VerdictRecord>,
    /// Each built variant's retained book directory.
    pub books: BTreeMap<String, PathBuf>,
    /// The case passed: no FAIL row, and no claimed row short of PASS.
    pub ok: bool,
}

impl RunOutcome {
    /// The printed lines as one text, for assertion messages.
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// The printed row line of `id`, if any.
    pub fn row(&self, id: &str) -> Option<&str> {
        self.lines
            .iter()
            .map(String::as_str)
            .find(|l| l.split(' ').nth(1) == Some(id))
    }
}

/// A fresh retained directory under the system temp dir; never deleted, so
/// a printed `REPRODUCE` argv stays runnable.
pub fn tmp(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    loop {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("fa-cases-{}-{name}-{n}", std::process::id()));
        match std::fs::create_dir(&d) {
            Ok(()) => return d,
            Err(e) => assert!(
                e.kind() == std::io::ErrorKind::AlreadyExists,
                "create {}: {e}",
                d.display()
            ),
        }
    }
}

/// One `fa` invocation's result.
#[derive(Clone, Debug)]
pub struct Call {
    pub argv: Vec<String>,
    pub exit: i32,
    pub stdout: String,
    pub observations: Vec<Observation>,
    /// stdout was not the robot envelope.
    pub parse_error: Option<String>,
    pub elapsed_ms: i128,
}

impl Call {
    /// The first observation of `event`.
    pub fn event(&self, event: &str) -> Option<&Observation> {
        self.observations.iter().find(|o| o.event == event)
    }

    /// The error event's refusal id, if the call failed with one.
    pub fn refusal_id(&self) -> Option<String> {
        self.event("error")
            .and_then(|o| o.error.as_ref())
            .and_then(|e| e.refusal_id.clone())
    }

    /// The highest `known_at` any observation reported.
    pub fn known_at(&self) -> Option<i128> {
        self.observations
            .iter()
            .filter_map(|o| o.coordinate.as_ref().and_then(|c| c.known_at))
            .max()
    }

    /// The string field `key` of the first `event`.
    pub fn str_field(&self, event: &str, key: &str) -> Option<String> {
        self.event(event)
            .and_then(|o| o.field(key))
            .and_then(Json::as_str)
            .map(str::to_string)
    }

    /// The array field `key` of the first `event`.
    pub fn array_field(&self, event: &str, key: &str) -> Vec<Json> {
        self.event(event)
            .and_then(|o| o.field(key))
            .and_then(Json::as_array)
            .map(<[Json]>::to_vec)
            .unwrap_or_default()
    }
}

/// Runs `fa --book <book> <args>`.
pub fn fa(book: &Path, args: &[String]) -> Call {
    let mut argv = vec!["--book".to_string(), book.display().to_string()];
    argv.extend(args.iter().cloned());
    let started = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_fa"))
        .args(&argv)
        .env_remove("FA_BOOK")
        .env("NO_COLOR", "1")
        .output()
        .expect("run fa");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let (observations, parse_error) = match Observation::from_stdout(&stdout) {
        Ok(o) => (o, None),
        Err((line, e)) => (Vec::new(), Some(format!("stdout line {line}: {e:?}"))),
    };
    Call {
        argv,
        exit: out.status.code().unwrap_or(-1),
        stdout,
        observations,
        parse_error,
        elapsed_ms: i128::try_from(started.elapsed().as_millis()).unwrap_or(i128::MAX),
    }
}

fn s<T: ToString>(v: T) -> String {
    v.to_string()
}

/// `REPRODUCE fa --book <retained dir> <exact argv>`.
pub fn reproduce(call: &Call) -> String {
    format!("REPRODUCE fa {}", call.argv.join(" "))
}

/// One recorded finding run.
#[derive(Clone, Debug)]
pub struct FindingRun {
    pub version: Option<i128>,
    /// Each recorded finding's `finding` object (severity, statistic,
    /// cites, narrative).
    pub findings: Vec<Json>,
}

/// The state one book variant's run carries.
pub struct BookRun<'c> {
    pub case: &'c Case,
    pub book: &'c BookVariant,
    /// The variant's working directory (periods, chart, stubs, intents).
    pub work: PathBuf,
    /// The book directory.
    pub dir: PathBuf,
    pub book_id: Option<String>,
    /// `[[period]] code` label → the book's period code.
    pub periods: BTreeMap<String, String>,
    /// `[[document]] id` → oid.
    pub documents: BTreeMap<String, String>,
    /// Intent id → entry vid, for the intents that posted.
    pub vids: BTreeMap<String, String>,
    /// (entry vid, entry leg ordinal) → `<intent>#<[[leg]] ordinal>`.
    pub legs: BTreeMap<(String, i128), String>,
    /// Account vid → `[[account]] code`, from the posted entries' legs.
    pub accounts: BTreeMap<String, String>,
    /// Intent id → the call that tried to post it.
    pub posts: BTreeMap<String, Call>,
    /// Procedure id → its recorded run.
    pub runs: BTreeMap<String, FindingRun>,
    /// The SELF row's procedure run: its findings, or why it did not run.
    pub self_run: Option<Result<Vec<Json>, String>>,
    /// The highest sequence observed so far.
    pub head: i128,
    /// The step kinds the runner met but does not run yet.
    pub unrun_steps: Vec<String>,
    /// Each run-variant value, its placeholder, and the `<event>.<field>
    /// of step <n> (<reference>)` that bound it (§3.5).
    pub placeholders: Vec<(String, String, String)>,
    pub steps: Vec<StepRecord>,
    pub lines: Vec<String>,
    /// A setup failure: every row of the variant reads FAIL with it.
    pub failure: Option<String>,
}

impl<'c> BookRun<'c> {
    fn new(case: &'c Case, book: &'c BookVariant, work: PathBuf) -> Self {
        let dir = work.join("book");
        Self {
            case,
            book,
            work,
            dir,
            book_id: None,
            periods: BTreeMap::new(),
            documents: BTreeMap::new(),
            vids: BTreeMap::new(),
            legs: BTreeMap::new(),
            accounts: BTreeMap::new(),
            posts: BTreeMap::new(),
            runs: BTreeMap::new(),
            self_run: None,
            head: 0,
            unrun_steps: Vec::new(),
            placeholders: Vec::new(),
            steps: Vec::new(),
            lines: Vec::new(),
            failure: None,
        }
    }

    fn fail(&mut self, why: String) {
        if self.failure.is_none() {
            self.failure = Some(why);
        }
    }

    /// Records `value` as the run-variant token `placeholder`, bound by
    /// `<event>.<field>` of this step.
    fn bind(
        &mut self,
        value: &str,
        placeholder: String,
        origin: &str,
        step: i128,
        reference: &str,
    ) {
        self.placeholders.push((
            value.to_string(),
            placeholder,
            format!("{origin} of step {step} ({reference})"),
        ));
    }

    /// `argv` with every run-variant token replaced by its placeholder, and
    /// the binds of the placeholders it carries.
    fn redact(&self, argv: &[String]) -> (Vec<String>, Vec<(String, String)>) {
        let book = self.dir.display().to_string();
        let work = self.work.display().to_string();
        let mut binds: Vec<(String, String)> = Vec::new();
        let redacted = argv
            .iter()
            .map(|a| {
                let mut a = a.replace(&book, "$BOOK").replace(&work, "$WORK");
                for (value, placeholder, origin) in &self.placeholders {
                    if a.contains(value.as_str()) {
                        a = a.replace(value.as_str(), placeholder);
                        if !binds.iter().any(|(p, _)| p == placeholder) {
                            binds.push((placeholder.clone(), origin.clone()));
                        }
                    }
                }
                a
            })
            .collect();
        (redacted, binds)
    }

    /// Runs `fa` on this variant's book and logs the step.
    fn call(&mut self, step: i128, reference: &str, verb: &str, args: Vec<String>) -> Call {
        let call = fa(&self.dir, &args);
        let (argv_redacted, binds) = self.redact(&call.argv);
        self.steps.push(StepRecord {
            case: self.case.header.id.clone(),
            book_variant: self.book.stem.clone(),
            branch_class: None,
            filler_variant: None,
            book_id: self.book_id.clone(),
            step,
            reference: reference.to_string(),
            verb: verb.to_string(),
            argv_redacted,
            exit: i128::from(call.exit),
            refusal_id: call.refusal_id(),
            finding_procedure: None,
            certificate_kind: None,
            elapsed_ms: call.elapsed_ms,
            binds,
        });
        if let Some(e) = &call.parse_error {
            self.fail(format!(
                "expected a robot envelope from {verb} ({reference}) observed {e}"
            ));
            self.lines.push(reproduce(&call));
        }
        if let Some(k) = call.known_at() {
            self.head = self.head.max(k);
        }
        call
    }

    /// Runs one setup call that must succeed; a failure stops the variant.
    fn setup(&mut self, reference: &str, verb: &str, args: Vec<String>) -> Option<Call> {
        if self.failure.is_some() {
            return None;
        }
        let call = self.call(0, reference, verb, args);
        if call.exit != 0 {
            let error = call.event("error").and_then(|o| o.error.as_ref());
            self.fail(format!(
                "expected exit=0 from {verb} ({reference}) observed exit={}{}{}",
                call.exit,
                call.refusal_id()
                    .map_or_else(String::new, |r| format!(" refusal={r}")),
                error.map_or_else(String::new, |e| format!(" ({})", e.message))
            ));
            self.lines.push(reproduce(&call));
            return None;
        }
        Some(call)
    }

    fn write(&self, name: &str, bytes: &[u8]) -> String {
        let p = self.work.join(name);
        std::fs::write(&p, bytes).expect("write a runner file");
        p.display().to_string()
    }

    /// Book, periods, chart and documents (plan §3.3 step 2).
    fn build(&mut self) {
        let mut years: BTreeMap<i128, Vec<Json>> = BTreeMap::new();
        for p in &self.book.periods {
            years
                .entry(p.fiscal_year)
                .or_default()
                .push(Json::Object(vec![
                    ("start".into(), Json::Str(p.start.clone())),
                    ("end".into(), Json::Str(p.end.clone())),
                ]));
        }
        let periods_json = Json::Object(vec![(
            "years".into(),
            Json::Array(
                years
                    .iter()
                    .map(|(fy, ps)| {
                        Json::Object(vec![
                            ("fiscal_year".into(), Json::Int(*fy)),
                            ("periods".into(), Json::Array(ps.clone())),
                        ])
                    })
                    .collect(),
            ),
        )]);
        let periods_file = self.write("periods.json", periods_json.to_string().as_bytes());
        let header = &self.book.book;
        let created = self.setup(
            "book",
            "book",
            vec![
                s("book"),
                s("create"),
                s("--name"),
                self.case.header.id.clone(),
                s("--base-unit"),
                header.base_unit.clone(),
                s("--calendar"),
                s("custom"),
                s("--periods"),
                periods_file,
                s("--opening-date"),
                header.opening_date.clone(),
                s("--json"),
            ],
        );
        self.book_id = created.and_then(|c| c.str_field("book_created", "book_id"));
        for fy in years.keys() {
            self.setup(
                &format!("FY{fy}"),
                "period",
                vec![
                    s("period"),
                    s("create"),
                    s("--fiscal-year"),
                    s(fy),
                    s("--json"),
                ],
            );
        }
        self.map_periods();
        self.chart();
        self.documents();
    }

    /// Maps each `[[period]]` label to the book's code by its dates (the
    /// listed `end` is exclusive) and prints the map once.
    fn map_periods(&mut self) {
        let Some(listed) = self.setup(
            "periods",
            "period",
            vec![s("period"), s("list"), s("--json")],
        ) else {
            return;
        };
        let rows = listed.array_field("periods", "periods");
        for p in &self.book.periods {
            let end_excl = Day::parse(&p.end).map(|d| d.add_days(1).to_string());
            let hits: Vec<String> = rows
                .iter()
                .filter(|r| {
                    r.get("start").and_then(Json::as_str) == Some(p.start.as_str())
                        && r.get("end").and_then(Json::as_str) == end_excl.as_deref()
                        && r.get("kind").and_then(Json::as_str) == Some("Normal")
                })
                .filter_map(|r| r.get("code").and_then(Json::as_str).map(str::to_string))
                .collect();
            if let [code] = hits.as_slice() {
                self.periods.insert(p.code.clone(), code.clone());
            } else {
                self.fail(format!(
                    "expected one Normal period {}..={} for label {} observed {}",
                    p.start,
                    p.end,
                    p.code,
                    hits.len()
                ));
                return;
            }
        }
        let map: Vec<String> = self
            .periods
            .iter()
            .map(|(label, code)| format!("{label}={code}"))
            .collect();
        self.lines
            .push(format!("PERIODS {} {}", self.book.stem, map.join(" ")));
    }

    fn chart(&mut self) {
        if self.failure.is_some() {
            return;
        }
        let unit = self.book.book.base_unit.clone();
        let accounts = Json::Object(vec![(
            "accounts".into(),
            Json::Array(
                self.book
                    .accounts
                    .iter()
                    .map(|a| {
                        Json::Object(vec![
                            ("code".into(), Json::Str(a.code.clone())),
                            ("name".into(), Json::Str(a.code.clone())),
                            ("type".into(), Json::Str(a.account_type.clone())),
                            ("leaf".into(), Json::Bool(true)),
                            ("unit".into(), Json::Str(unit.clone())),
                        ])
                    })
                    .collect(),
            ),
        )]);
        let file = self.write("chart.json", accounts.to_string().as_bytes());
        self.setup(
            "chart",
            "chart",
            vec![s("chart"), s("import"), file, s("--json")],
        );
        let roles: Vec<(String, String)> = self
            .book
            .accounts
            .iter()
            .filter_map(|a| {
                a.role
                    .as_deref()
                    .filter(|r| !r.is_empty())
                    .map(|r| (a.code.clone(), r.to_string()))
            })
            .collect();
        for (code, role) in roles {
            self.setup(
                &code,
                "chart",
                vec![s("chart"), s("role"), code.clone(), role, s("--json")],
            );
        }
    }

    /// The citation-stub bytes of a `[[document]] stub_of`.
    fn stub_bytes(&self, stub_of: &str) -> Option<Vec<u8>> {
        if let Some(fact) = stub_of.strip_prefix("placeholder:") {
            return Some(stub::placeholder(fact));
        }
        if let Some(src) = self.case.sources.iter().find(|x| x.id == stub_of) {
            return Some(stub::source_stub(src));
        }
        let fact = self.case.facts.iter().find(|f| f.id == stub_of)?;
        let src = self
            .case
            .sources
            .iter()
            .find(|x| fact.sourced().is_some_and(|sf| sf.source == x.id))?;
        stub::fact_stub(src, fact)
    }

    /// Each `[[document]]`'s stub added (default grade AgentUpload) and,
    /// where `reviewed_by` is set, reviewed by that principal.
    fn documents(&mut self) {
        for d in &self.book.documents {
            if self.failure.is_some() {
                return;
            }
            let Some(bytes) = self.stub_bytes(&d.stub_of) else {
                self.fail(format!(
                    "expected a source, sourced fact or placeholder for {} observed stub_of={}",
                    d.id, d.stub_of
                ));
                return;
            };
            let file = self.write(&format!("{}.stub", d.id), &bytes);
            let Some(added) = self.setup(
                &d.id,
                "document",
                vec![
                    s("document"),
                    s("add"),
                    file,
                    s("--kind"),
                    s("Other"),
                    s("--json"),
                ],
            ) else {
                return;
            };
            let Some(oid) = added.str_field("document", "oid") else {
                self.fail(format!("expected document.oid for {} observed none", d.id));
                return;
            };
            self.bind(&oid, format!("$DOC_{}", d.id), "document.oid", 0, &d.id);
            if let Some(reviewer) = d.reviewed_by.as_deref().filter(|r| !r.is_empty()) {
                self.setup(
                    &d.id,
                    "document",
                    vec![
                        s("document"),
                        s("attest"),
                        s("review"),
                        oid.clone(),
                        s("--as"),
                        reviewer.to_string(),
                        s("--json"),
                    ],
                );
            }
            self.documents.insert(d.id.clone(), oid);
        }
    }

    /// The documented history in `[[step]]` order (plan §3.3 steps 3 and 6).
    fn replay(&mut self) {
        for step in &self.book.steps {
            if self.failure.is_some() {
                return;
            }
            let kind = step.step_kind();
            match kind {
                Some(StepKind::PeriodOpen | StepKind::PeriodSoftClose | StepKind::PeriodClose) => {
                    let Some(code) = self.periods.get(&step.reference).cloned() else {
                        self.fail(format!(
                            "expected a created period for label {} (step {}) observed none",
                            step.reference, step.seq
                        ));
                        return;
                    };
                    let mut args = match kind {
                        Some(StepKind::PeriodOpen) => vec![s("period"), s("open"), code],
                        Some(StepKind::PeriodSoftClose) => {
                            vec![s("period"), s("soft-close"), code]
                        }
                        _ => vec![
                            s("period"),
                            s("close"),
                            code,
                            s("--reason"),
                            s("Scheduled"),
                            s("--yes"),
                        ],
                    };
                    if let Some(p) = step.principal.as_deref() {
                        args.extend([s("--as"), p.to_string()]);
                    }
                    args.push(s("--json"));
                    let call = self.call(step.seq, &step.reference, "period", args);
                    if call.exit != 0 {
                        self.lines.push(reproduce(&call));
                    }
                }
                Some(StepKind::Intent) => self.post(step.seq, &step.reference),
                Some(StepKind::FindingRecord) => {
                    let procedure = step
                        .reference
                        .split_once('@')
                        .map_or(step.reference.as_str(), |(p, _)| p);
                    self.finding_record(step.seq, procedure, step.principal.as_deref());
                }
                _ => {
                    if !self.unrun_steps.contains(&step.kind) {
                        self.unrun_steps.push(step.kind.clone());
                    }
                }
            }
        }
    }

    fn post(&mut self, seq: i128, intent_id: &str) {
        let book = self.book;
        let Some(it) = book.intents.iter().find(|i| i.id == intent_id) else {
            self.fail(format!(
                "expected an [[intent]] {intent_id} (step {seq}) observed none"
            ));
            return;
        };
        let vids = self.vids.clone();
        let doc = match intent_json::render(book, it, &|t| vids.get(t).cloned()) {
            Ok(doc) => doc,
            Err(e) => {
                self.fail(format!(
                    "expected intent {intent_id} to render (step {seq}) observed {e:?}"
                ));
                return;
            }
        };
        let file = self.write(&format!("{intent_id}.json"), doc.to_string().as_bytes());
        let mut args = vec![
            s("post"),
            s("--intent"),
            file,
            s("--as"),
            it.principal.clone(),
        ];
        if let Some(e) = it.evidence.as_deref() {
            let Some(oid) = self.documents.get(e).cloned() else {
                self.fail(format!(
                    "expected evidence {e} of {intent_id} to be added (step {seq}) observed none"
                ));
                return;
            };
            args.extend([s("--evidence"), oid]);
        }
        args.push(s("--json"));
        let call = self.call(seq, intent_id, "post", args);
        if let Some(vid) = call.str_field("posted", "vid") {
            self.bind(&vid, format!("${intent_id}"), "posted.vid", seq, intent_id);
            self.vids.insert(intent_id.to_string(), vid.clone());
            self.map_legs(seq, intent_id, &vid);
        }
        self.posts.insert(intent_id.to_string(), call);
    }

    /// Reads the posted entry back and maps its legs, in order, to the
    /// intent's `[[leg]]` rows (sorted by ordinal, as rendered), checking
    /// each side; this is what projects a leg or account cite to its fact.
    fn map_legs(&mut self, seq: i128, intent_id: &str, vid: &str) {
        let shown = self.call(
            seq,
            intent_id,
            "entry",
            vec![s("entry"), s("show"), vid.to_string(), s("--json")],
        );
        let got = shown.array_field("entry", "legs");
        let mut want: Vec<_> = self
            .book
            .legs
            .iter()
            .filter(|l| l.intent == intent_id)
            .collect();
        want.sort_by_key(|l| l.ordinal);
        if got.len() != want.len() {
            self.fail(format!(
                "expected legs={} of {intent_id} observed legs={}",
                want.len(),
                got.len()
            ));
            self.lines.push(reproduce(&shown));
            return;
        }
        for (i, (g, w)) in got.iter().zip(want).enumerate() {
            let side = match w.side.as_str() {
                "Dr" => "debit",
                _ => "credit",
            };
            let account = g.get("account").and_then(Json::as_str).unwrap_or_default();
            let observed = g.get("side").and_then(Json::as_str).unwrap_or("-");
            if observed != side || account.is_empty() {
                self.fail(format!(
                    "expected entry leg {i} of {intent_id} to be [[leg]] {} ({side}) observed {observed}",
                    w.ordinal
                ));
                self.lines.push(reproduce(&shown));
                return;
            }
            if let Some(code) = self.accounts.get(account)
                && *code != w.account
            {
                self.fail(format!(
                    "expected one account code per account vid observed {code} and {}",
                    w.account
                ));
                return;
            }
            self.accounts.insert(account.to_string(), w.account.clone());
            let i = i128::try_from(i).unwrap_or(i128::MAX);
            self.legs
                .insert((vid.to_string(), i), format!("{intent_id}#{}", w.ordinal));
        }
    }

    /// `fa finding record` at the head (a `pre_case` read on a variant with
    /// no `[[case]]` is the head at the step), then `fa finding list` of the
    /// run's certificate.
    fn finding_record(&mut self, seq: i128, procedure: &str, principal: Option<&str>) {
        let mut args = vec![
            s("finding"),
            s("record"),
            procedure.to_string(),
            s("--known-at"),
            s(self.head),
        ];
        if let Some(p) = principal {
            args.extend([s("--as"), p.to_string()]);
        }
        args.push(s("--json"));
        let call = self.call(seq, procedure, "finding", args);
        if let Some(last) = self.steps.last_mut() {
            last.finding_procedure = Some(procedure.to_string());
            last.certificate_kind = Some("FindingRun".into());
        }
        let Some(cert) = call.str_field("findings_recorded", "certificate") else {
            self.lines.push(reproduce(&call));
            return;
        };
        self.bind(
            &cert,
            format!("$C_FINDINGRUN_{procedure}"),
            "findings_recorded.certificate",
            seq,
            procedure,
        );
        let version = call
            .event("findings_recorded")
            .and_then(|o| o.field("version"))
            .and_then(Json::as_int);
        let listed = self.call(
            seq,
            procedure,
            "finding",
            vec![
                s("finding"),
                s("list"),
                s("--certificate"),
                format!("C:{cert}"),
                s("--json"),
            ],
        );
        if listed.exit != 0 {
            self.lines.push(reproduce(&listed));
            return;
        }
        let findings = listed
            .array_field("finding_list", "findings")
            .iter()
            .filter_map(|r| r.get("finding").cloned())
            .collect();
        self.runs
            .insert(procedure.to_string(), FindingRun { version, findings });
    }

    /// The SELF row's read: `fa procedure run jet.self_sourced_evidence`.
    fn self_procedure(&mut self) {
        if self.failure.is_some() || !self.unrun_steps.is_empty() {
            return;
        }
        let call = self.call(
            0,
            "SELF",
            "procedure",
            vec![
                s("procedure"),
                s("run"),
                s(selfrow::PROCEDURE),
                s("--known-at"),
                s(self.head),
                s("--json"),
            ],
        );
        self.self_run = Some(if call.exit == 0 {
            Ok(call.array_field("procedure_run", "findings"))
        } else {
            self.lines.push(reproduce(&call));
            Err(format!(
                "expected exit=0 from procedure run observed exit={}",
                call.exit
            ))
        });
    }

    /// The trial balance of each period (plan §3.3 step 7); a failure here
    /// fails the variant.
    fn trial_balances(&mut self) {
        let codes: Vec<String> = self.periods.values().cloned().collect();
        for code in codes {
            self.setup(
                &code,
                "tb",
                vec![s("tb"), s("--period"), code.clone(), s("--json")],
            );
        }
    }
}

/// Runs a case through every stage with the given verb table.
pub fn run_case(files: &CaseFiles<'_>, verbs: &[(&str, Option<&str>)]) -> RunOutcome {
    let root = tmp(files.id);
    let mut out = RunOutcome {
        lines: Vec::new(),
        log_path: root.join(format!("{}.jsonl", files.id)),
        steps: Vec::new(),
        verdicts: Vec::new(),
        books: BTreeMap::new(),
        ok: true,
    };
    // 1. Load and validate, purely.
    let case = match fa_oracles::cases::load(files) {
        Ok(case) => case,
        Err(errs) => {
            for e in errs {
                out.lines.push(format!("FAIL {} load {e:?}", files.id));
            }
            out.ok = false;
            return finish(out);
        }
    };
    let reports = check::run_load_checks(&case);
    for r in &reports {
        out.lines
            .extend(r.render(Some(files.id)).lines().map(str::to_string));
    }
    let failed: Vec<&str> = reports
        .iter()
        .filter(|r| r.verdict == Verdict::Fail)
        .map(|r| r.check.as_str())
        .collect();
    if !failed.is_empty() {
        let reason = failed
            .iter()
            .map(|k| format!("expected {k}=PASS observed {k}=FAIL"))
            .collect::<Vec<_>>()
            .join("; ");
        for row in evaluate::declared_rows(&case) {
            out.lines.push(
                RowLine {
                    verdict: RowVerdict::Fail,
                    reason: Some(reason.clone()),
                    ..row
                }
                .to_string(),
            );
        }
        out.ok = false;
        return finish(out);
    }
    // 2. The verb table, before any book exists.
    let registry: Vec<(String, Vec<String>)> = fa_cli::verbs::registry()
        .expect("verbs.toml")
        .verbs
        .iter()
        .map(|v| (v.name.clone(), v.subcommands.clone()))
        .collect();
    let unknown = missing(verbs, &registry);
    if !unknown.is_empty() {
        out.lines.push(format!(
            "FAIL {} verbs: the runner invokes {} that verbs.toml does not register",
            files.id,
            unknown.join(", ")
        ));
        out.ok = false;
        return finish(out);
    }
    // 3–10. Each book variant.
    for book in case.books.values() {
        let work = root.join(&book.stem);
        std::fs::create_dir_all(&work).expect("variant dir");
        let mut run = BookRun::new(&case, book, work);
        run.build();
        out.books.insert(book.stem.clone(), run.dir.clone());
        run.replay();
        run.self_procedure();
        if run.failure.is_none() && run.unrun_steps.is_empty() {
            run.trial_balances();
        }
        let rows = evaluate::rows(&run);
        out.lines.append(&mut run.lines);
        out.steps.append(&mut run.steps);
        for ev in rows {
            out.lines.extend(ev.reproduce);
            out.lines.push(ev.row.to_string());
            out.verdicts.push(ev.record);
        }
    }
    // The case passes when no row FAILs and every claimed expectation's
    // verdict, the worst of its rows, is PASS.
    let verdicts = evaluate::expectation_verdicts(&out.verdicts);
    out.ok = verdicts.values().all(|v| *v != RowVerdict::Fail)
        && case
            .header
            .claims
            .iter()
            .all(|c| verdicts.get(c) == Some(&RowVerdict::Pass));
    finish(out)
}

/// Writes the JSONL log, copies it to `FA_CASES_LOG_DIR` when set, and
/// appends the `LOG` line.
fn finish(mut out: RunOutcome) -> RunOutcome {
    let mut text = String::new();
    for s in &out.steps {
        text.push_str(&s.to_line());
        text.push('\n');
    }
    for v in &out.verdicts {
        text.push_str(&v.to_line());
        text.push('\n');
    }
    std::fs::write(&out.log_path, &text).expect("write the run log");
    if let Ok(dir) = std::env::var("FA_CASES_LOG_DIR")
        && let Some(name) = out.log_path.file_name()
    {
        std::fs::create_dir_all(&dir).expect("FA_CASES_LOG_DIR");
        std::fs::copy(&out.log_path, Path::new(&dir).join(name)).expect("copy the run log");
    }
    out.lines.push(format!("LOG {}", out.log_path.display()));
    out
}

/// A committed case's run, shared by every test of this binary.
pub fn outcome(case_id: &str) -> &'static RunOutcome {
    static RUNS: OnceLock<Mutex<BTreeMap<String, &'static RunOutcome>>> = OnceLock::new();
    let runs = RUNS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut guard = runs.lock().expect("the outcome map");
    if let Some(o) = guard.get(case_id) {
        return o;
    }
    let case = CASES
        .iter()
        .find(|c| c.id == case_id)
        .expect("a committed case");
    let o: &'static RunOutcome = Box::leak(Box::new(run_case(&case.case_files(), HARNESS_VERBS)));
    guard.insert(case_id.to_string(), o);
    o
}

/// The committed case's files copied, `edits` applied in order, and run with
/// `verbs`: `Err` when the copy's run is not ok.
///
/// # Panics
///
/// When an edit's `old` does not occur exactly once in its file as it then
/// stands: a stale plant never silently tests nothing.
pub fn run_planted(
    case_id: &str,
    edits: &[PlantedEdit],
    verbs: &[(&str, Option<&str>)],
) -> Result<RunOutcome, Box<RunOutcome>> {
    let case = CASES
        .iter()
        .find(|c| c.id == case_id)
        .expect("a committed case");
    let mut files: Vec<(&str, String)> = case
        .files
        .iter()
        .map(|(p, t)| (*p, (*t).to_string()))
        .collect();
    for e in edits {
        assert!(
            files.iter().any(|(p, _)| *p == e.file),
            "planted edit names no file `{}` of {case_id}",
            e.file
        );
        let entry = files
            .iter_mut()
            .find(|(p, _)| *p == e.file)
            .expect("the file checked above");
        assert_eq!(
            entry.1.matches(e.old).count(),
            1,
            "planted edit `{}` in {} must occur exactly once",
            e.old,
            e.file
        );
        entry.1 = entry.1.replacen(e.old, e.new, 1);
    }
    let refs: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
    let o = run_case(
        &CaseFiles {
            id: case_id,
            files: &refs,
        },
        verbs,
    );
    if o.ok { Ok(o) } else { Err(Box::new(o)) }
}
