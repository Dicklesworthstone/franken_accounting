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

use fa_oracles::cases::book::{BookVariant, StepDef, StepKind, VariantKind};
use fa_oracles::cases::check::{self, Verdict};
use fa_oracles::cases::date::Day;
use fa_oracles::cases::embedded::CASES;
use fa_oracles::cases::expect::ExpectationType;
use fa_oracles::cases::filler::{self, FillerVariant, Posting};
use fa_oracles::cases::harness_verbs::{HARNESS_VERBS, missing};
use fa_oracles::cases::log::{StepRecord, VerdictRecord};
use fa_oracles::cases::observe::Observation;
use fa_oracles::cases::selfrow;
use fa_oracles::cases::twin::{TwinKind, TwinSpec, twin_of};
use fa_oracles::cases::verdict::{RowLine, RowVerdict};
use fa_oracles::cases::{Case, CaseFiles, intent_json, stub};
use fa_oracles::json::Json;

use super::budget::Budget;
use super::cells;
use super::evaluate;
use super::invariance;

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
    /// The case passed: no FAIL row, no claimed row short of PASS, and it
    /// kept its wall-clock budget.
    pub ok: bool,
    /// The same, its budget aside. A harness test of another behavior
    /// asserts this: a contended worker can push a small case past 60 s
    /// (fa-yugf.17), which is the budget's verdict, not that behavior's. The
    /// budget's own tests assert `ok` and the BUDGET lines.
    pub rows_ok: bool,
}

impl RunOutcome {
    /// The printed lines as one text, for assertion messages.
    pub fn text(&self) -> String {
        self.lines.join("\n")
    }

    /// The printed row line of `id`, if any: a `PASS`, `FAIL` or `UNRUN`
    /// line, never a load check's `RETYPE` line of the same id.
    pub fn row(&self, id: &str) -> Option<&str> {
        self.lines.iter().map(String::as_str).find(|l| {
            let mut words = l.split(' ');
            matches!(words.next(), Some("PASS" | "FAIL" | "UNRUN")) && words.next() == Some(id)
        })
    }
}

/// The members one filler chunk posts by default: within the registered
/// `max_batch_entries` (8,190), as the chunk rule allows ("at most"), and
/// small because batch admission is superlinear in one batch's size. A
/// 2,000-member `fa batch` did not finish in 30 min on a worker, where 100-member
/// chunks posted the same entries at ~130 ms each (A11a's measurement).
pub const FILLER_CHUNK: usize = 100;

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

pub(crate) fn s<T: ToString>(v: T) -> String {
    v.to_string()
}

/// `REPRODUCE fa --book <retained dir> <exact argv>`.
pub fn reproduce(call: &Call) -> String {
    let argv: Vec<String> = call
        .argv
        .iter()
        .map(|a| {
            if a.contains(char::is_whitespace) || a.contains('\'') {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect();
    let mut line = format!("REPRODUCE fa {}", argv.join(" "));
    // What the call observed, as a shell comment so the argv stays runnable.
    if call.exit != 0 {
        line.push_str(&format!("  # exit={}", call.exit));
        if let Some(r) = call.refusal_id() {
            line.push_str(&format!(" refusal={r}"));
        }
        if let Some(e) = call.event("error").and_then(|o| o.error.as_ref()) {
            line.push_str(&format!(": {}", e.message.replace('\n', " ")));
        }
    }
    line
}

/// One recorded finding run.
#[derive(Clone, Debug)]
pub struct FindingRun {
    /// The `finding_record` step that recorded it.
    pub step: i128,
    pub version: Option<i128>,
    /// Each recorded finding's `finding` object (severity, statistic,
    /// cites, narrative).
    pub findings: Vec<Json>,
    /// Each finding's vid, in the same order.
    pub finding_vids: Vec<String>,
}

/// The provenance engagement every citation stub is filed in (plan §2.7).
pub const PROVENANCE: &str = "provenance";

/// `minor` minor units of `unit` at its registered scale (`0.01 USD`).
pub fn minor_amount(unit: &str, minor: u32) -> String {
    let scale = fa_registry::units_embedded()
        .ok()
        .and_then(|units| units.into_iter().find(|u| u.code == unit).map(|u| u.scale))
        .unwrap_or(2);
    if scale == 0 {
        format!("{minor} {unit}")
    } else {
        let width = usize::from(scale);
        let p = 10u32.pow(u32::from(scale));
        format!("{}.{:0width$} {unit}", minor / p, minor % p)
    }
}

/// The generated statement of a manual assertion over `fact` (A7a): fixed
/// text and the fact id, never free text.
pub fn assertion_statement(fact: &str) -> String {
    format!(
        "reconstruction placeholder: the record describes this document ({fact}); its bytes are not public"
    )
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
    /// Intent id → the step that posted it (a finding run reads the entries
    /// posted before its own step).
    pub posted_steps: BTreeMap<String, i128>,
    /// (entry vid, entry leg ordinal) → `<intent>#<[[leg]] ordinal>`.
    pub legs: BTreeMap<(String, i128), String>,
    /// Account vid → `[[account]] code`, from the posted entries' legs.
    pub accounts: BTreeMap<String, String>,
    /// Intent id → the call that tried to post it.
    pub posts: BTreeMap<String, Call>,
    /// Procedure id → its recorded run.
    pub runs: BTreeMap<String, FindingRun>,
    /// Procedure id → the call that was refused or errored instead of
    /// recording or listing its run (an N row's FAIL names it, A11c).
    pub failed_runs: BTreeMap<String, Call>,
    /// The case's files (a rule step's `rules/<name>.rule` source).
    pub texts: &'c [(&'c str, &'c str)],
    /// A `rule_propose` step's seq → the IR digest it reported.
    pub rule_digests: BTreeMap<i128, String>,
    /// The SELF row's procedure run: its findings, or why it did not run.
    pub self_run: Option<Result<Vec<Json>, String>>,
    /// The highest sequence observed so far.
    pub head: i128,
    /// The sequence the documented history starts from: the head after
    /// setup (a statement line's trace spans the history, A11b).
    pub history_from: i128,
    /// The step kinds the runner met but does not run yet.
    pub unrun_steps: Vec<String>,
    /// Each run-variant value, its placeholder, and the `<event>.<field>
    /// of step <n> (<reference>)` that bound it (§3.5).
    pub placeholders: Vec<(String, String, String)>,
    pub steps: Vec<StepRecord>,
    pub lines: Vec<String>,
    /// A setup failure: every row of the variant reads FAIL with it.
    pub failure: Option<String>,
    /// Whether a batch reads each member back to map its legs (a property
    /// micro-book maps native leg ordinals itself, A5a).
    pub map_batch_legs: bool,
    /// The filler variant this run posts at its `filler_batch` steps (A6);
    /// none, or the empty variant, posts nothing.
    pub filler: Option<FillerVariant>,
    /// The most members one filler chunk posts (`max_batch_entries`, A7c).
    pub chunk_max: usize,
    /// Each T and R row's certified read, by `<expectation>/<target>` (A7b).
    pub reads: BTreeMap<String, super::reads::Read>,
    /// Each `assert_balance` step's calls, by its `ref` (A7b).
    pub assertions: BTreeMap<String, super::reads::Assertion>,
    /// Each period label's issued report certificates, in step order (A7b).
    pub issuances: BTreeMap<String, Vec<String>>,
    /// Each opened `[[case]]`'s runs, by its id (A7b).
    pub cases: BTreeMap<String, super::lifecycle::CaseRun>,
    /// Each certified scenario diff: the scenario and its certificate file.
    pub scenario_diffs: Vec<(String, String)>,
    /// Intent id -> the entry vid `fa scenario run` planned it as (A11b).
    pub planned_entries: BTreeMap<String, String>,
    /// Attestation vid -> the `assert_balance` step ref that recorded it.
    pub attestations: BTreeMap<String, String>,
    /// The outsider stage's checks, for a book with a checkpoint (A8a).
    pub outsider: Option<super::outsider::Outsider>,
}

impl<'c> BookRun<'c> {
    pub(crate) fn new(
        case: &'c Case,
        book: &'c BookVariant,
        work: PathBuf,
        texts: &'c [(&'c str, &'c str)],
    ) -> Self {
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
            posted_steps: BTreeMap::new(),
            legs: BTreeMap::new(),
            accounts: BTreeMap::new(),
            posts: BTreeMap::new(),
            runs: BTreeMap::new(),
            failed_runs: BTreeMap::new(),
            texts,
            rule_digests: BTreeMap::new(),
            self_run: None,
            head: 0,
            history_from: 0,
            unrun_steps: Vec::new(),
            placeholders: Vec::new(),
            steps: Vec::new(),
            lines: Vec::new(),
            failure: None,
            map_batch_legs: true,
            filler: None,
            chunk_max: filler::max_batch_entries()
                .unwrap_or(8190)
                .min(FILLER_CHUNK),
            reads: BTreeMap::new(),
            assertions: BTreeMap::new(),
            issuances: BTreeMap::new(),
            cases: BTreeMap::new(),
            scenario_diffs: Vec::new(),
            planned_entries: BTreeMap::new(),
            attestations: BTreeMap::new(),
            outsider: None,
        }
    }

    pub(crate) fn fail(&mut self, why: String) {
        if self.failure.is_none() {
            self.failure = Some(why);
        }
    }

    /// Records `value` as the run-variant token `placeholder`, bound by
    /// `<event>.<field>` of this step.
    pub(crate) fn bind(
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
    pub(crate) fn call(
        &mut self,
        step: i128,
        reference: &str,
        verb: &str,
        args: Vec<String>,
    ) -> Call {
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

    pub(crate) fn write(&self, name: &str, bytes: &[u8]) -> String {
        let p = self.work.join(name);
        std::fs::write(&p, bytes).expect("write a runner file");
        p.display().to_string()
    }

    /// Book, periods, chart and documents (plan §3.3 step 2).
    pub(crate) fn build(&mut self) {
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
        let mut args = vec![
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
        ];
        // A1b's optional `[book] entities`, `<code>[:<name>]` each.
        for e in header.entities.iter().flatten() {
            args.extend([s("--entity"), e.clone()]);
        }
        args.push(s("--json"));
        let created = self.setup("book", "book", args);
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
        self.parties();
        self.documents();
        self.engagement();
    }

    /// `fa party add` per `[[party]]` (its `id` as the party code), then
    /// `fa party relate` per relation token, and per `[book]` entity
    /// relation.
    fn parties(&mut self) {
        let book = self.book;
        for p in &book.parties {
            let doc = Json::Object(vec![
                ("code".into(), Json::Str(p.id.clone())),
                ("kind".into(), Json::Str(p.kind.clone())),
                ("name".into(), Json::Str(p.label.clone())),
            ]);
            let file = self.write(&format!("party-{}.json", p.id), doc.to_string().as_bytes());
            self.setup(
                &p.id,
                "party",
                vec![s("party"), s("add"), file, s("--json")],
            );
        }
        let relations = book
            .parties
            .iter()
            .flat_map(|p| p.relations.iter().map(move |r| (p.id.as_str(), r)))
            .chain(
                book.book
                    .relations
                    .iter()
                    .map(|e| (e.from.as_str(), &e.relation)),
            );
        for (from, r) in relations {
            let mut args = vec![
                s("party"),
                s("relate"),
                from.to_string(),
                r.to.clone(),
                s("--kind"),
                s(r.kind.as_str()),
                s("--basis"),
                r.basis.clone(),
                s("--valid-from"),
                r.valid_from.clone(),
            ];
            if let Some(to) = &r.valid_to {
                args.extend([s("--valid-to"), to.clone()]);
            }
            if let Some((n, d)) = r.pct {
                args.extend([s("--pct"), format!("{n}/{d}")]);
            }
            args.push(s("--json"));
            self.setup(&format!("{from}->{}", r.to), "party", args);
        }
    }

    /// Whether `stub_of` names a citation stub (a source or fact id).
    fn is_citation_stub(&self, stub_of: &str) -> bool {
        self.case.sources.iter().any(|x| x.id == stub_of)
            || self.case.facts.iter().any(|f| f.id == stub_of)
    }

    /// The provenance engagement (§2.7), opened when the variant has a
    /// citation stub or an `engagement_file` step: no materiality judged,
    /// all three figures stated as zero in the base unit, then every
    /// citation stub filed in it.
    fn engagement(&mut self) {
        if self.failure.is_some() {
            return;
        }
        let stubs: Vec<String> = self
            .book
            .documents
            .iter()
            .filter(|d| self.is_citation_stub(&d.stub_of))
            .map(|d| d.id.clone())
            .collect();
        let filing_steps = self
            .book
            .steps
            .iter()
            .any(|s| s.step_kind() == Some(StepKind::EngagementFile));
        if stubs.is_empty() && !filing_steps {
            return;
        }
        // Plan §2.7 states all three figures as zero; `fa engagement open`
        // refuses that (FA-REF-100: performance and overall are positive).
        // The stated, never judged, rendering is the smallest positive
        // figure, one minor unit, so no misstatement is judged immaterial,
        // and a clearly-trivial threshold of zero.
        let unit = self.book.book.base_unit.clone();
        let (one, zero) = (minor_amount(&unit, 1), minor_amount(&unit, 0));
        let mut args = vec![
            s("engagement"),
            s("open"),
            s(PROVENANCE),
            s("--kind"),
            s("investigation"),
        ];
        for code in self.periods.values() {
            args.extend([s("--period"), code.clone()]);
        }
        for (flag, value) in [
            ("--overall", &one),
            ("--performance", &one),
            ("--clearly-trivial", &zero),
        ] {
            args.extend([s(flag), value.clone()]);
        }
        args.push(s("--json"));
        if self.setup(PROVENANCE, "engagement", args).is_none() {
            return;
        }
        for id in stubs {
            let Some(oid) = self.documents.get(&id).cloned() else {
                continue;
            };
            self.setup(
                &id,
                "engagement",
                vec![
                    s("engagement"),
                    s("file"),
                    s(PROVENANCE),
                    s("--document"),
                    oid,
                    s("--json"),
                ],
            );
        }
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
    pub(crate) fn stub_bytes(&self, stub_of: &str) -> Option<Vec<u8>> {
        if let Some(fact) = stub_of.strip_prefix("placeholder:") {
            return Some(stub::placeholder(fact));
        }
        if let Some(variant) = stub_of.strip_prefix("filler:") {
            return Some(stub::filler(&self.case.header.id, variant));
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
    pub(crate) fn replay(&mut self) {
        let book = self.book;
        self.history_from = self.head;
        for step in &book.steps {
            if self.failure.is_some() {
                return;
            }
            self.step(step);
        }
    }

    /// Runs one history step (a P-cell sweep replays steps one by one, A7c).
    pub(crate) fn step(&mut self, step: &StepDef) {
        {
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
                Some(StepKind::Allocate) => self.allocate(step.seq, &step.reference),
                Some(StepKind::Batch) if self.book.kind != VariantKind::Ledger => {
                    self.batch(step.seq, &step.reference);
                }
                Some(StepKind::PeriodLock) => self.period_lock(step),
                Some(StepKind::FindingRecord) => {
                    let procedure = step
                        .reference
                        .split_once('@')
                        .map_or(step.reference.as_str(), |(p, _)| p);
                    let params = step.params.clone().unwrap_or_default();
                    self.finding_record(step.seq, procedure, step.principal.as_deref(), &params);
                }
                Some(StepKind::EngagementFile) => self.engagement_file(step),
                Some(StepKind::RuleCheck | StepKind::RulePropose | StepKind::RuleBacktest) => {
                    self.rule_step(step);
                }
                Some(StepKind::EventRecord) => self.event_record(step),
                Some(StepKind::FillerBatch) => self.filler_batch(step),
                Some(StepKind::AssertBalance) => self.assert_balance(step),
                Some(StepKind::Issue) => self.issue(step),
                Some(StepKind::CaseOpen) => self.case_open(step),
                Some(StepKind::CaseDetermine) => self.case_determine(step),
                Some(StepKind::ScenarioFork) => self.scenario_fork(step),
                Some(StepKind::ScenarioRun) => self.scenario_run(step),
                Some(StepKind::ScenarioDiff) => self.scenario_diff(step),
                Some(StepKind::CaseRehearse) => self.case_rehearse(step),
                Some(StepKind::CaseApprove) => self.case_approve(step),
                Some(StepKind::CasePost) => self.case_post(step),
                Some(StepKind::CaseDisclose) => self.case_disclose(step),
                Some(StepKind::CaseClose) => self.case_close(step),
                Some(StepKind::Checkpoint) => self.checkpoint(step),
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
        if let Some(code) = it
            .evidence
            .as_deref()
            .and_then(|e| e.strip_prefix("manual_assertion:"))
        {
            self.post_manually_asserted(seq, it, file, code);
            return;
        }
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
            self.posted_steps.insert(intent_id.to_string(), seq);
            self.map_legs(seq, intent_id, &vid);
        }
        self.posts.insert(intent_id.to_string(), call);
    }

    /// An intent whose evidence is `manual_assertion:<code>`: one sealed
    /// proposal, asserted with `fa document attest manual --plan-out` and
    /// committed with `fa commit --plan`. A second `fa post --intent` would
    /// reseal it, and the assertion would no longer cover it.
    fn post_manually_asserted(
        &mut self,
        seq: i128,
        it: &fa_oracles::cases::book::IntentDef,
        file: String,
        code: &str,
    ) {
        let plan = self.work.join(format!("{}.plan", it.id));
        let attest = self.call(
            seq,
            &it.id,
            "document",
            vec![
                s("document"),
                s("attest"),
                s("manual"),
                s("--intent"),
                file,
                s("--reason"),
                code.to_string(),
                s("--statement"),
                assertion_statement(&it.fact),
                s("--plan-out"),
                plan.display().to_string(),
                s("--as"),
                it.principal.clone(),
                s("--json"),
            ],
        );
        if attest.exit != 0 {
            self.lines.push(reproduce(&attest));
            self.posts.insert(it.id.clone(), attest);
            return;
        }
        let call = self.call(
            seq,
            &it.id,
            "commit",
            vec![
                s("commit"),
                s("--plan"),
                plan.display().to_string(),
                s("--as"),
                it.principal.clone(),
                s("--json"),
            ],
        );
        if let Some(vid) = call.str_field("plan_committed", "vid") {
            self.bind(
                &vid,
                format!("${}", it.id),
                "plan_committed.vid",
                seq,
                &it.id,
            );
            self.vids.insert(it.id.clone(), vid.clone());
            self.posted_steps.insert(it.id.clone(), seq);
            self.map_legs(seq, &it.id, &vid);
        }
        self.posts.insert(it.id.clone(), call);
    }

    /// The book code of the `[[period]]` containing `day`.
    fn period_of(&self, day: &str) -> Option<String> {
        self.book
            .periods
            .iter()
            .find(|p| p.contains(day))
            .and_then(|p| self.periods.get(&p.code).cloned())
    }

    /// One approval of `digest` by `label`: the only place the runner
    /// produces an approval (A7a; fa-z46b will change what a second
    /// principal is). Returns the approval vid.
    pub(crate) fn approve_as(&mut self, seq: i128, label: &str, digest: &str) -> Option<String> {
        let call = self.call(
            seq,
            label,
            "approve",
            vec![
                s("approve"),
                s("--proposal"),
                digest.to_string(),
                s("--as"),
                label.to_string(),
                s("--json"),
            ],
        );
        let vid = call.str_field("approved", "approval_vid");
        match &vid {
            Some(v) => {
                let n = self
                    .placeholders
                    .iter()
                    .filter(|p| p.1.starts_with("$APPROVAL_"))
                    .count()
                    + 1;
                self.bind(
                    v,
                    format!("$APPROVAL_{n}"),
                    "approved.approval_vid",
                    seq,
                    label,
                );
            }
            None => self.lines.push(reproduce(&call)),
        }
        vid
    }

    /// `fa period lock` planned, approved by the step's `approvers` and
    /// committed with their approvals.
    fn period_lock(&mut self, step: &StepDef) {
        let Some(code) = self.periods.get(&step.reference).cloned() else {
            self.fail(format!(
                "expected a created period for label {} (step {}) observed none",
                step.reference, step.seq
            ));
            return;
        };
        let plan = self.work.join(format!("lock-{}.plan", step.seq));
        let mut args = vec![
            s("period"),
            s("lock"),
            code.clone(),
            s("--reason"),
            s("Scheduled"),
            s("--plan-out"),
            plan.display().to_string(),
        ];
        if let Some(p) = step.principal.as_deref() {
            args.extend([s("--as"), p.to_string()]);
        }
        args.push(s("--json"));
        let planned = self.call(step.seq, &step.reference, "period", args);
        let Some(digest) = planned.str_field("period_planned", "proposal_digest") else {
            self.lines.push(reproduce(&planned));
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
            s("period"),
            s("lock"),
            code,
            s("--plan"),
            plan.display().to_string(),
        ];
        for v in approvals {
            args.extend([s("--approval"), v]);
        }
        if let Some(p) = step.principal.as_deref() {
            args.extend([s("--as"), p.to_string()]);
        }
        args.push(s("--json"));
        let call = self.call(step.seq, &step.reference, "period", args);
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
        }
    }

    /// An `engagement_file` step: a document by its oid, or `finding:<D>`,
    /// every finding of that expectation's procedure run that cites one of
    /// its targets' entries.
    fn engagement_file(&mut self, step: &StepDef) {
        let principal = step.principal.clone();
        let file = |run: &mut Self, flag: &str, value: String| {
            let mut args = vec![s("engagement"), s("file"), s(PROVENANCE), s(flag), value];
            if let Some(p) = principal.as_deref() {
                args.extend([s("--as"), p.to_string()]);
            }
            args.push(s("--json"));
            let call = run.call(step.seq, &step.reference, "engagement", args);
            if call.exit != 0 {
                run.lines.push(reproduce(&call));
            }
        };
        let Some(exp_id) = step.reference.strip_prefix("finding:") else {
            let Some(oid) = self.documents.get(&step.reference).cloned() else {
                self.fail(format!(
                    "expected document {} to be added (step {}) observed none",
                    step.reference, step.seq
                ));
                return;
            };
            file(self, "--document", oid);
            return;
        };
        let case = self.case;
        let Some(set) = case.expectations.as_ref() else {
            return;
        };
        let Some(procedure) = set.get(exp_id).and_then(|e| e.fields.str("procedure")) else {
            self.fail(format!(
                "expected expectation {exp_id} with a procedure (step {}) observed none",
                step.seq
            ));
            return;
        };
        let subjects: Vec<String> = set
            .targets_of(exp_id)
            .map(|t| evaluate::intent_of(self, &t.fact))
            .collect();
        let vids: Vec<String> = self
            .runs
            .get(procedure)
            .map(|r| {
                r.findings
                    .iter()
                    .zip(&r.finding_vids)
                    .filter(|(f, _)| {
                        let p = evaluate::project(self, f);
                        subjects.iter().any(|s| p.entries.contains(s))
                    })
                    .map(|(_, v)| v.clone())
                    .collect()
            })
            .unwrap_or_default();
        for v in vids {
            file(self, "--finding", v);
        }
    }

    /// A `rule_check`, `rule_propose` or `rule_backtest` step over the case's
    /// `rules/<name>.rule`. A propose step's IR digest is bound as
    /// `$RULE_<seq>`; a backtest's `compare=<seq>` param passes that digest
    /// as `--compare`, and its `from`/`to` params as `--from`/`--to`.
    fn rule_step(&mut self, step: &StepDef) {
        let Some(text) = self
            .texts
            .iter()
            .find(|(p, _)| *p == step.reference)
            .map(|(_, t)| *t)
        else {
            self.fail(format!(
                "expected the case file {} (step {}) observed none",
                step.reference, step.seq
            ));
            return;
        };
        let file = self.write(&step.reference.replace('/', "_"), text.as_bytes());
        let kind = step.step_kind();
        let sub = match kind {
            Some(StepKind::RuleCheck) => "check",
            Some(StepKind::RulePropose) => "propose",
            _ => "backtest",
        };
        let mut args = vec![s("rule"), s(sub), file];
        for p in step.params.iter().flatten() {
            let Some((name, value)) = p.split_once('=') else {
                continue;
            };
            match name {
                "compare" => {
                    let digest = value
                        .parse::<i128>()
                        .ok()
                        .and_then(|seq| self.rule_digests.get(&seq).cloned());
                    let Some(digest) = digest else {
                        self.fail(format!(
                            "expected rule_propose step {value} to report an IR digest (step {}) observed none",
                            step.seq
                        ));
                        return;
                    };
                    args.extend([s("--compare"), digest]);
                }
                "from" | "to" => args.extend([format!("--{name}"), value.to_string()]),
                _ => {}
            }
        }
        if let Some(p) = step.principal.as_deref() {
            args.extend([s("--as"), p.to_string()]);
        }
        args.push(s("--json"));
        let call = self.call(step.seq, &step.reference, "rule", args);
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
            return;
        }
        if kind == Some(StepKind::RulePropose)
            && let Some(digest) = call.str_field("rule_proposed", "ir_digest")
        {
            self.bind(
                &digest,
                format!("$RULE_{}", step.seq),
                "rule_proposed.ir_digest",
                step.seq,
                &step.reference,
            );
            self.rule_digests.insert(step.seq, digest);
        }
    }

    /// `fa event record` from the step's `[[event]]` row.
    fn event_record(&mut self, step: &StepDef) {
        let book = self.book;
        let Some(ev) = book.events.iter().find(|e| e.id == step.reference) else {
            self.fail(format!(
                "expected an [[event]] {} (step {}) observed none",
                step.reference, step.seq
            ));
            return;
        };
        let mut args = vec![
            s("event"),
            s("record"),
            s("--code"),
            ev.id.clone(),
            s("--kind"),
            ev.kind.clone(),
            s("--occurred-on"),
            ev.occurred_on.clone(),
        ];
        for d in &ev.evidence {
            let Some(oid) = self.documents.get(d).cloned() else {
                self.fail(format!(
                    "expected evidence {d} of event {} to be added observed none",
                    ev.id
                ));
                return;
            };
            args.extend([s("--evidence"), oid]);
        }
        for p in ev.participants.iter().flatten() {
            args.extend([s("--participant"), p.clone()]);
        }
        if let (Some(label), Some(amount)) = (&ev.resource_label, &ev.resource_amount_literal) {
            let unit = ev
                .resource_unit
                .clone()
                .unwrap_or_else(|| book.book.base_unit.clone());
            args.extend([s("--resource"), format!("{label}:{amount} {unit}")]);
        }
        if let Some(p) = step.principal.as_deref() {
            args.extend([s("--as"), p.to_string()]);
        }
        args.push(s("--json"));
        let call = self.call(step.seq, &step.reference, "event", args);
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
        }
    }

    /// An `allocate` step: the allocation JSON from the intent's
    /// `allocation_*` fields, its law as `method` (never the CLI's default).
    fn allocate(&mut self, seq: i128, intent_id: &str) {
        let book = self.book;
        let Some(it) = book.intents.iter().find(|i| i.id == intent_id) else {
            self.fail(format!(
                "expected an [[intent]] {intent_id} (step {seq}) observed none"
            ));
            return;
        };
        let (Some(law), Some(source)) = (&it.allocation_law, &it.allocation_source) else {
            self.fail(format!(
                "expected allocation_law and allocation_source on {intent_id} observed a rendering that would leave the CLI's default law"
            ));
            return;
        };
        let mut doc = vec![
            ("source".to_string(), Json::Str(source.clone())),
            (
                "effective_date".into(),
                Json::Str(it.effective_date.clone()),
            ),
            (
                "idempotency_key".into(),
                Json::Str(
                    it.idempotency_key
                        .clone()
                        .unwrap_or_else(|| format!("case-{}", it.id)),
                ),
            ),
            ("method".into(), Json::Str(law.clone())),
            (
                "targets".into(),
                Json::Array(
                    it.allocation_targets
                        .iter()
                        .flatten()
                        .map(|t| Json::Object(vec![("account".into(), Json::Str(t.clone()))]))
                        .collect(),
                ),
            ),
        ];
        if let Some(memo) = it.memo.as_deref().filter(|m| !m.is_empty()) {
            doc.push(("description".into(), Json::Str(memo.to_string())));
        }
        let mut args = vec![s("allocate"), s("--intent")];
        if let Some(total) = &it.allocation_total {
            doc.push((
                "total".into(),
                Json::Str(format!("{total} {}", book.book.base_unit)),
            ));
            doc.push((
                "source_side".into(),
                Json::Str(it.allocation_source_side.clone().unwrap_or_default()),
            ));
        }
        let file = self.write(
            &format!("{intent_id}.alloc.json"),
            Json::Object(doc).to_string().as_bytes(),
        );
        args.push(file);
        if it.allocation_total.is_none() {
            let Some(code) = self.period_of(&it.effective_date) else {
                self.fail(format!(
                    "expected a period containing {} for {intent_id} observed none",
                    it.effective_date
                ));
                return;
            };
            args.extend([s("--period"), code]);
        }
        args.extend([s("--as"), it.principal.clone()]);
        if let Some(e) = it.evidence.as_deref() {
            match self.documents.get(e).cloned() {
                Some(oid) => args.extend([s("--evidence"), oid]),
                None => {
                    self.fail(format!(
                        "expected evidence {e} of {intent_id} to be added observed none"
                    ));
                    return;
                }
            }
        }
        args.push(s("--json"));
        let call = self.call(seq, intent_id, "allocate", args);
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
        }
        if let Some(vid) = call.str_field("posted", "vid") {
            self.bind(&vid, format!("${intent_id}"), "posted.vid", seq, intent_id);
            self.vids.insert(intent_id.to_string(), vid);
            self.posted_steps.insert(intent_id.to_string(), seq);
        }
        self.posts.insert(intent_id.to_string(), call);
    }

    /// A `batch` step over the intent range `A..B` (file order), posted as
    /// one `PostBatch` whose members carry their own evidence.
    fn batch(&mut self, seq: i128, range: &str) {
        let book = self.book;
        let Some((a, b)) = range.split_once("..") else {
            self.fail(format!(
                "expected an intent range A..B (step {seq}) observed {range}"
            ));
            return;
        };
        let pos = |id: &str| book.intents.iter().position(|i| i.id == id);
        let (Some(pa), Some(pb)) = (pos(a), pos(b)) else {
            self.fail(format!(
                "expected intents {a} and {b} (step {seq}) observed none"
            ));
            return;
        };
        let members = &book.intents[pa..=pb];
        let vids = self.vids.clone();
        let mut rendered = Vec::new();
        for it in members {
            let doc = match intent_json::render(book, it, &|t| vids.get(t).cloned()) {
                Ok(Json::Object(mut fields)) => {
                    if let Some(oid) = it.evidence.as_deref().and_then(|e| self.documents.get(e)) {
                        fields.push(("evidence".into(), Json::Array(vec![Json::Str(oid.clone())])));
                    }
                    Json::Object(fields)
                }
                Ok(other) => other,
                Err(e) => {
                    self.fail(format!(
                        "expected intent {} to render (step {seq}) observed {e:?}",
                        it.id
                    ));
                    return;
                }
            };
            rendered.push(doc);
        }
        let key = format!("case-batch-{}-{seq}", self.case.header.id);
        let doc = Json::Object(vec![
            ("idempotency_key".into(), Json::Str(key)),
            ("intents".into(), Json::Array(rendered)),
        ]);
        let file = self.write(&format!("batch-{seq}.json"), doc.to_string().as_bytes());
        let principal = members
            .first()
            .map(|i| i.principal.clone())
            .unwrap_or_default();
        let call = self.call(
            seq,
            range,
            "batch",
            vec![
                s("batch"),
                s("--intent"),
                file,
                s("--as"),
                principal,
                s("--json"),
            ],
        );
        let posted = call.array_field("batch_posted", "members");
        for m in &posted {
            let (Some(i), Some(vid)) = (
                m.get("index").and_then(Json::as_int),
                m.get("vid").and_then(Json::as_str),
            ) else {
                continue;
            };
            let Some(it) = usize::try_from(i).ok().and_then(|i| members.get(i)) else {
                continue;
            };
            self.bind(
                vid,
                format!("${}", it.id),
                "batch_posted.members.vid",
                seq,
                &it.id,
            );
            self.vids.insert(it.id.clone(), vid.to_string());
            self.posted_steps.insert(it.id.clone(), seq);
            if self.map_batch_legs {
                self.map_legs(seq, &it.id, vid);
            }
        }
        if call.exit != 0 {
            self.lines.push(reproduce(&call));
        }
        for it in members {
            self.posts.insert(it.id.clone(), call.clone());
        }
    }

    /// A `filler_batch` step: this run's filler variant for the step's id,
    /// posted as `PostBatch` chunks of at most `chunk_max` members, each
    /// chunk under A6's chunk key and logged as its own step with the
    /// variant's label (A7c). No variant, or the empty one, posts nothing.
    fn filler_batch(&mut self, step: &StepDef) {
        let Some(variant) = self
            .filler
            .clone()
            .filter(|v| v.spec.variant == step.reference && !v.intents.is_empty())
        else {
            return;
        };
        if variant.posting == Posting::Staged {
            if !self.unrun_steps.contains(&step.kind) {
                self.unrun_steps.push(step.kind.clone());
            }
            return;
        }
        let Some(doc) = self.documents.get(&variant.document).cloned() else {
            self.fail(format!(
                "expected filler document {} added (step {}) observed none",
                variant.document, step.seq
            ));
            return;
        };
        // The members render from the book with the variant's legs.
        let mut book = self.book.clone();
        book.intents.extend(variant.intents.iter().cloned());
        book.legs.extend(variant.legs.iter().cloned());
        for chunk in filler::chunks(&variant, self.chunk_max) {
            let mut rendered = Vec::new();
            for id in &chunk.intents {
                let Some(it) = book.intents.iter().find(|i| &i.id == id) else {
                    continue;
                };
                match intent_json::render(&book, it, &|_| None) {
                    Ok(Json::Object(mut fields)) => {
                        fields.push(("evidence".into(), Json::Array(vec![Json::Str(doc.clone())])));
                        rendered.push(Json::Object(fields));
                    }
                    Ok(other) => rendered.push(other),
                    Err(e) => {
                        self.fail(format!(
                            "expected filler intent {id} to render (step {}) observed {e:?}",
                            step.seq
                        ));
                        return;
                    }
                }
            }
            let body = Json::Object(vec![
                ("idempotency_key".into(), Json::Str(chunk.key.clone())),
                ("intents".into(), Json::Array(rendered)),
            ]);
            let file = self.write(
                &format!("filler-{}-{}.json", step.seq, chunk.index),
                body.to_string().as_bytes(),
            );
            let call = self.call(
                step.seq,
                &step.reference,
                "batch",
                vec![
                    s("batch"),
                    s("--intent"),
                    file,
                    s("--as"),
                    variant.principal.clone(),
                    s("--json"),
                ],
            );
            if let Some(last) = self.steps.last_mut() {
                last.filler_variant = Some(variant.spec.label());
            }
            if call.exit != 0 {
                self.lines.push(reproduce(&call));
                self.fail(format!(
                    "expected filler chunk {} of {} posted (step {}) observed exit={}",
                    chunk.index,
                    variant.spec.label(),
                    step.seq,
                    call.exit
                ));
                return;
            }
        }
    }

    /// Reads the posted entry back and maps its legs, in order, to the
    /// intent's `[[leg]]` rows (sorted by ordinal, as rendered), checking
    /// each side; this is what projects a leg or account cite to its fact.
    pub(crate) fn map_legs(&mut self, seq: i128, intent_id: &str, vid: &str) {
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
    fn finding_record(
        &mut self,
        seq: i128,
        procedure: &str,
        principal: Option<&str>,
        params: &[String],
    ) {
        let mut args = vec![
            s("finding"),
            s("record"),
            procedure.to_string(),
            s("--known-at"),
            s(self.head),
        ];
        // A1b's `params`, one `--param <name>=<integer>` each.
        for p in params {
            args.extend([s("--param"), p.clone()]);
        }
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
            self.failed_runs.insert(procedure.to_string(), call);
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
            self.failed_runs.insert(procedure.to_string(), listed);
            return;
        }
        let rows = listed.array_field("finding_list", "findings");
        let findings = rows
            .iter()
            .filter_map(|r| r.get("finding").cloned())
            .collect();
        let finding_vids = rows
            .iter()
            .filter_map(|r| {
                r.get("finding_vid")
                    .and_then(Json::as_str)
                    .map(str::to_string)
            })
            .collect();
        self.runs.insert(
            procedure.to_string(),
            FindingRun {
                step: seq,
                version,
                findings,
                finding_vids,
            },
        );
    }

    /// The SELF row's read: `fa procedure run jet.self_sourced_evidence`.
    pub(crate) fn self_procedure(&mut self) {
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
        // The history's end is also where every T and R row reads, and
        // each case is shown for its generated row (A7b).
        self.reads();
        self.case_reads();
        // A book with a checkpoint then proves its bundle, replay and
        // integrity to an outsider (A8a).
        self.outsider();
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
    run_case_with(files, verbs, None)
}

/// [`run_case`] under a budget of `budget_ms` (else `FA_CASES_BUDGET_MS`,
/// else 60 s; A7c).
pub fn run_case_with(
    files: &CaseFiles<'_>,
    verbs: &[(&str, Option<&str>)],
    budget_ms: Option<u64>,
) -> RunOutcome {
    let root = tmp(files.id);
    let mut out = RunOutcome {
        lines: Vec::new(),
        log_path: root.join(format!("{}.jsonl", files.id)),
        steps: Vec::new(),
        verdicts: Vec::new(),
        books: BTreeMap::new(),
        ok: true,
        rows_ok: true,
    };
    // 1. Load and validate, purely.
    let case = match fa_oracles::cases::load(files) {
        Ok(case) => case,
        Err(errs) => {
            for e in errs {
                out.lines.push(format!("FAIL {} load {e:?}", files.id));
            }
            out.ok = false;
            out.rows_ok = false;
            return finish(out);
        }
    };
    let reports = check::run_load_checks(&case);
    for r in &reports {
        out.lines
            .extend(r.render(Some(files.id)).lines().map(str::to_string));
    }
    // Each target's component statuses (A5b).
    if let Ok(rules) = fa_oracles::cases::branch::rules() {
        out.lines
            .extend(fa_oracles::cases::status::status_lines(&case, &rules));
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
        out.rows_ok = false;
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
        out.rows_ok = false;
        return finish(out);
    }
    // 3–10. Each book variant.
    let mut sweep_failed = false;
    let mut outsider_failed = false;
    let mut budget = Budget::new(budget_ms);
    for (index, book) in case.books.values().enumerate() {
        let book_started = Instant::now();
        let steps_before = out.steps.len();
        let work = root.join(&book.stem);
        std::fs::create_dir_all(&work).expect("variant dir");
        let mut run = BookRun::new(&case, book, work, files.files);
        run.build();
        if let Some(code) = run.periods.values().next() {
            budget.measure_warm(&run.dir, code);
        }
        out.books.insert(book.stem.clone(), run.dir.clone());
        run.replay();
        run.self_procedure();
        if run.failure.is_none() && run.unrun_steps.is_empty() {
            run.trial_balances();
        }
        // A failed outsider check fails the case whatever its rows say
        // (§12.1).
        outsider_failed |= run.outsider.as_ref().is_some_and(|o| !o.ok());
        // Each N row's harness-only twin runs on its own book (A11c), after
        // the target's history ran; a matcher twin (A16) or an exact_gap
        // twin target needs no book of its own.
        let specs: Vec<(String, Result<TwinSpec, String>)> = case
            .expectations
            .iter()
            .flat_map(|s| s.expectations.iter())
            .filter(|e| {
                e.kind == ExpectationType::N && e.fields.str("book_variant") == Some(&book.stem)
            })
            .map(|e| {
                (
                    e.id.clone(),
                    twin_of(&case, e).map_err(|err| err.to_string()),
                )
            })
            .collect();
        let mut twins: BTreeMap<String, BookRun<'_>> = BTreeMap::new();
        if run.failure.is_none() && run.unrun_steps.is_empty() {
            for (id, spec) in &specs {
                let Ok(spec) = spec else { continue };
                if spec.kind == TwinKind::Matcher || spec.n_kind == "exact_gap" {
                    continue;
                }
                let work = root.join(format!("{}-{id}", spec.book.stem));
                std::fs::create_dir_all(&work).expect("twin dir");
                let mut t = BookRun::new(&case, &spec.book, work, files.files);
                t.build();
                t.replay();
                twins.insert(id.clone(), t);
            }
        }
        let mut rows = evaluate::rows(&run, &specs, &twins);
        // A11a: the rows still waiting on filler invariance, compared
        // across every filler spec and two book ids.
        if let Ok(tiers) = fa_oracles::cases::tiers::tiers() {
            let applied = invariance::apply(
                &case,
                book,
                files.files,
                &run,
                &mut rows,
                &specs,
                &twins,
                &tiers,
            );
            out.steps.extend(applied.steps);
            out.lines.extend(applied.lines);
        }
        out.lines.append(&mut run.lines);
        out.steps.append(&mut run.steps);
        for t in twins.values_mut() {
            out.lines.extend(
                t.lines
                    .drain(..)
                    .filter(|l| !l.starts_with("PERIODS ") && !l.starts_with("CASES ")),
            );
            out.steps.append(&mut t.steps);
        }
        for ev in rows {
            out.lines.extend(ev.reproduce);
            out.lines.push(ev.row.to_string());
            out.verdicts.push(ev.record);
        }
        // Every P target with a branch table, swept cell by cell by dry run
        // on a book of its own per entry (A7c).
        match sweep_groups(&case, &book.stem) {
            Ok(groups) => {
                for g in &groups {
                    push_swept(&mut out, &case, cells::sweep(&case, g, files.files, None));
                }
            }
            Err(e) => {
                out.lines
                    .push(format!("FAIL {} sweep {} {e}", files.id, book.stem));
                sweep_failed = true;
            }
        }
        // Every D target with a branch table: its cells co-resident on one
        // book (tier L, C) or on a book each (A7c).
        if let Some(set) = &case.expectations {
            for e in set.expectations.iter().filter(|e| {
                e.kind == ExpectationType::D
                    && e.fields.str("book_variant") == Some(book.stem.as_str())
            }) {
                for t in set
                    .targets_of(&e.id)
                    .filter(|t| evaluate::has_branch_table(t))
                {
                    push_swept(&mut out, &case, cells::d_cells(&case, e, t, files.files));
                }
            }
        }
        let line = budget.book(
            files.id,
            &book.stem,
            index + 1,
            out.steps.len() - steps_before,
            book_started.elapsed().as_millis(),
        );
        out.lines.push(line);
    }
    let (budget_lines, within_budget) = budget.finish(files.id);
    out.lines.extend(budget_lines);
    // The case passes when no row FAILs, it kept its budget, and every
    // claimed expectation's verdict, the worst of its rows, is PASS.
    let verdicts = evaluate::expectation_verdicts(&out.verdicts);
    out.rows_ok = !sweep_failed
        && !outsider_failed
        && verdicts.values().all(|v| *v != RowVerdict::Fail)
        && case
            .header
            .claims
            .iter()
            .all(|c| verdicts.get(c) == Some(&RowVerdict::Pass));
    out.ok = out.rows_ok && within_budget;
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
    run_files(case_id, case.files, edits, verbs)
}

/// `files` (a committed case's or a runner fixture's) copied, `edits`
/// applied in order, and run as case `id` with `verbs`: `Err` when the
/// run is not ok.
///
/// # Panics
///
/// As [`run_planted`].
pub fn run_files(
    id: &str,
    files: &[(&str, &str)],
    edits: &[PlantedEdit],
    verbs: &[(&str, Option<&str>)],
) -> Result<RunOutcome, Box<RunOutcome>> {
    let mut files: Vec<(&str, String)> =
        files.iter().map(|(p, t)| (*p, (*t).to_string())).collect();
    for e in edits {
        assert!(
            files.iter().any(|(p, _)| *p == e.file),
            "planted edit names no file `{}` of {id}",
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
    let o = run_case(&CaseFiles { id, files: &refs }, verbs);
    if o.ok { Ok(o) } else { Err(Box::new(o)) }
}

/// One variant of a loaded case, built and replayed in a fresh retained
/// directory, with no rows evaluated: the property tests read its runs
/// directly (A5a). Every step record carries `branch_class`; batch members
/// are not read back (a cited leg's native ordinal is its fixture ordinal).
pub fn build_book<'c>(
    case: &'c Case,
    stem: &str,
    branch_class: &str,
    texts: &'c [(&'c str, &'c str)],
) -> BookRun<'c> {
    let book = case.books.get(stem).expect("the variant");
    let work = tmp(&format!("{}-{stem}", case.header.id));
    let mut run = BookRun::new(case, book, work, texts);
    run.map_batch_legs = false;
    run.build();
    run.replay();
    for s in &mut run.steps {
        s.branch_class = Some(branch_class.to_string());
    }
    run
}

/// The sweep groups of one variant: A5a's tables of its P targets with a
/// branch table, planned by A7c's sweep_plan.
pub(crate) fn sweep_groups(
    case: &Case,
    variant: &str,
) -> Result<Vec<fa_oracles::cases::sweep::SweepGroup>, fa_oracles::cases::LoadError> {
    let Some(set) = &case.expectations else {
        return Ok(Vec::new());
    };
    let mut tables = Vec::new();
    for e in set
        .expectations
        .iter()
        .filter(|e| e.kind == ExpectationType::P && e.fields.str("book_variant") == Some(variant))
    {
        for t in set
            .targets_of(&e.id)
            .filter(|t| evaluate::has_branch_table(t))
        {
            tables.push(fa_oracles::cases::branch::enumerate(case, e, t)?);
        }
    }
    if tables.is_empty() {
        return Ok(Vec::new());
    }
    Ok(fa_oracles::cases::sweep::sweep_plan(case, variant, &tables)?.groups)
}

/// A sweep's step records, log lines and cell rows, into the run's output.
fn push_swept(out: &mut RunOutcome, case: &Case, swept: cells::Swept) {
    out.lines.extend(
        swept
            .lines
            .into_iter()
            .filter(|l| !l.starts_with("PERIODS ") && !l.starts_with("CASES ")),
    );
    out.steps.extend(swept.steps);
    for c in swept.cells {
        let ev = evaluate::finish(case, (c.row, Vec::new(), c.reproduce));
        out.lines.extend(ev.reproduce);
        out.lines.push(ev.row.to_string());
        out.verdicts.push(ev.record);
    }
}
