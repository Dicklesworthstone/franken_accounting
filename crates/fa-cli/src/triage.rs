//! The mega-commands (plan §15.3 "Mega-commands", the agent Polish Bar;
//! bead fa-12x slice 2): one call answers "what is wrong, and what do I run
//! next". Ported from JadePeak's fa-12x slice 2 WIP (3a37d3c) onto the
//! RECON-2 integration tree.
//!
//! `fa doctor` checks what a book needs from its environment: the embedded
//! registries, the book directory, its key file, the writer lease and the
//! daemon, that the book opens, and that its derived state (registers,
//! limit availability, the entry accumulator) still equals the journal's
//! refold. Every check names its status and, when it is not ok, the exact
//! fix. The exit code is the verdict: 0 only when no check failed; otherwise
//! the report is followed by one `error` line whose class is the first
//! failing check's (foundation, environment, or verification).
//!
//! `fa triage` summarises a book's state and puts the commands an agent
//! should run next into the envelope's `next_actions`, computed from that
//! state. Without a running fad it reads the book directly and says
//! `daemon: absent`.

use std::path::Path;

use crate::args::Args;
use crate::cli::{Ctx, Fail};
use crate::json::{Json, obj, s};
use crate::lease::Lease;
use crate::verbs;
use fa::Book;
use fa_time::PeriodState;

/// One step an agent should run next: the command and why.
struct NextStep {
    command: String,
    why: String,
    /// The command writes the book: never offered to an Agent profile.
    writes: bool,
    /// For an Agent, the draft that takes this write instead (plan §15.2:
    /// an agent works on a draft a Human promotes): its name and the
    /// `fa draft plan` the agent runs into it.
    draft: Option<(&'static str, &'static str)>,
}

/// A check's outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
    /// Not checked: what it needs (an open book) is missing.
    Skipped,
}

impl Status {
    fn name(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skipped => "skipped",
        }
    }
}

/// The exit class a failed check maps to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Foundation,
    Environment,
    Verification,
}

struct Check {
    name: &'static str,
    status: Status,
    detail: String,
    fix: Option<String>,
    /// The one command to run next, when a single command is the remedy.
    command: Option<String>,
    /// `command` writes the book (a repair), rather than reading it.
    repairs: bool,
    class: Class,
}

impl Check {
    fn ok(name: &'static str, class: Class, detail: impl Into<String>) -> Self {
        Self {
            name,
            status: Status::Ok,
            detail: detail.into(),
            fix: None,
            command: None,
            repairs: false,
            class,
        }
    }

    fn not_ok(
        name: &'static str,
        class: Class,
        status: Status,
        detail: impl Into<String>,
        fix: impl Into<String>,
    ) -> Self {
        Self {
            name,
            status,
            detail: detail.into(),
            fix: Some(fix.into()),
            command: None,
            repairs: false,
            class,
        }
    }

    /// The command that reads further (a verification or a preview).
    fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// The command that repairs what the check found: it writes the book.
    fn with_repair(mut self, command: impl Into<String>) -> Self {
        self.repairs = true;
        self.with_command(command)
    }

    fn skipped(name: &'static str, class: Class, why: &str) -> Self {
        Self {
            name,
            status: Status::Skipped,
            detail: why.to_string(),
            fix: None,
            command: None,
            repairs: false,
            class,
        }
    }

    fn json(&self) -> Json {
        obj(vec![
            ("name", s(self.name)),
            ("status", s(self.status.name())),
            ("detail", s(&self.detail)),
            ("fix", self.fix.as_ref().map_or(Json::Null, s)),
        ])
    }
}

/// What a failure says, whatever its kind.
pub(crate) fn describe(fail: &Fail) -> String {
    match fail {
        Fail::Usage(e) => format!("{} (fix: {})", e.message, e.fix),
        Fail::Refusal(r) => format!("{}: {}", r.code, r.message),
        Fail::Book(e) => e.to_string(),
        Fail::Verification { message, .. } => message.clone(),
        Fail::Internal(m) | Fail::Io(m) | Fail::Environment(m) => m.clone(),
    }
}

/// Every registry this build embeds parses and agrees with the others.
fn registries() -> Check {
    let mut problems: Vec<String> = Vec::new();
    if let Err(e) = verbs::registry() {
        problems.push(format!("verbs.toml: {e}"));
    }
    match fa_registry::Registries::embedded() {
        Err(e) => problems.push(e.to_string()),
        Ok(r) => {
            if let Err(e) =
                fa_registry::sod_policy::SodPolicy::embedded(&r.entry_classes, &r.admissibility)
            {
                problems.push(e.to_string());
            }
        }
    }
    if let Err(e) = fa_registry::evidence_policy::EvidencePolicy::embedded() {
        problems.push(e.to_string());
    }
    if let Err(e) = fa_registry::reason_codes::ReasonCodes::embedded() {
        problems.push(e.to_string());
    }
    if let Err(e) = fa_registry::refusal_catalog::RefusalCatalog::embedded() {
        problems.push(e.to_string());
    }
    if problems.is_empty() {
        Check::ok(
            "registries",
            Class::Foundation,
            format!(
                "verbs, exit codes, entry classes, admissibility, units, rounding laws, symbols, SoD and evidence policy, reason codes and the refusal catalog all parse and agree (robot envelope v{})",
                verbs::ENVELOPE_VERSION
            ),
        )
    } else {
        Check::not_ok(
            "registries",
            Class::Foundation,
            Status::Fail,
            problems.join("; "),
            "this build's embedded registries are inconsistent: rebuild fa from a tree whose `scripts/check.sh` passes",
        )
    }
}

/// The key file exists and is private to its owner.
fn key_file(path: &Path) -> Check {
    if std::fs::symlink_metadata(path).is_err() {
        return Check::not_ok(
            "keys",
            Class::Environment,
            Status::Fail,
            format!("no key file at {}", path.display()),
            "pass --keys <file> naming the book's key file (fa book create writes <dir>/book.keys)",
        );
    }
    if let Err(error) = fa::book::BookKeys::check_permissions(path) {
        let fix = error
            .refusal()
            .map_or_else(|| format!("chmod 600 {}", path.display()), |r| r.fix);
        return Check::not_ok(
            "keys",
            Class::Environment,
            Status::Fail,
            error.to_string(),
            fix,
        );
    }
    Check::ok(
        "keys",
        Class::Environment,
        format!("{} is private to its owner", path.display()),
    )
}

/// Who holds the book's writer lease, and whether a fad serves it.
fn writer_lease(dir: &Path, held: bool) -> Check {
    if held {
        return Check::ok(
            "writer_lease",
            Class::Environment,
            "held by the fad answering this command",
        );
    }
    let Ok(reg) = verbs::registry() else {
        return Check::skipped("writer_lease", Class::Environment, "no registry");
    };
    match Lease::holder(dir, &reg.daemon.lease) {
        None => Check::ok(
            "writer_lease",
            Class::Environment,
            "free: no fad serves the book; commands open it directly",
        ),
        // A direct `fa` command holds the lease for its own duration.
        Some(holder) if holder == own_note() => Check::ok(
            "writer_lease",
            Class::Environment,
            "held by this command for its duration; no fad serves the book",
        ),
        Some(holder) => Check::not_ok(
            "writer_lease",
            Class::Environment,
            Status::Warn,
            format!("held by: {holder}"),
            format!(
                "`fa` routes through a serving fad by itself; see `fad status --book {}`",
                dir.display()
            ),
        ),
    }
}

/// The lease note a direct `fa` command writes for itself (`entry`).
fn own_note() -> String {
    format!("fa pid={}", std::process::id())
}

/// One materialized period's register cache against the journal: how far
/// its watermark trails the journal (plan §15.3 `register_watermark_lag`).
struct RegisterLag {
    period: String,
    cache_status: &'static str,
    verified_through: Option<u64>,
    lag_entries: usize,
}

impl RegisterLag {
    fn json(&self) -> Json {
        obj(vec![
            ("period", s(&self.period)),
            ("cache_status", s(self.cache_status)),
            (
                "verified_through",
                self.verified_through
                    .map_or(Json::Null, |seq| Json::Int(i128::from(seq))),
            ),
            ("lag_entries", Json::Int(self.lag_entries as i128)),
        ])
    }
}

/// The derived state still equals the journal's refold: the checks, and the
/// watermark lag of every materialized period's register cache (read in the
/// same pass).
fn derived_state(book: &Book) -> (Vec<Check>, Vec<RegisterLag>) {
    let mut checks = Vec::new();
    let mut lag = Vec::new();
    // Registers: every period with materialized cells.
    let registers = (|| -> Result<Check, fa::book::BookError> {
        let mut checked = 0usize;
        let mut drifted: Vec<String> = Vec::new();
        // A verified cache with journal entries after its basis is lag, not
        // drift: green, and advanced by `fa registers advance`.
        let mut lagging: Vec<(String, usize)> = Vec::new();
        for p in book.periods()? {
            let v = book.verify_registers(&p.code)?;
            let materialized = v.stored_digest.is_some()
                || v.drift
                    .iter()
                    .chain(&v.pending_drift)
                    .any(|d| d.stored.is_some());
            if materialized {
                lag.push(RegisterLag {
                    period: p.code.clone(),
                    cache_status: match v.cache_status {
                        fa_registers::CacheStatus::Uninitialized => "uninitialized",
                        fa_registers::CacheStatus::Verified => "verified",
                        fa_registers::CacheStatus::Corrupt => "corrupt",
                    },
                    verified_through: v.verified_through.map(|seq| seq.0),
                    lag_entries: v.lag_entries,
                });
                checked += 1;
                if !v.is_green() {
                    drifted.push(p.code.clone());
                } else if v.stale {
                    lagging.push((p.code.clone(), v.lag_entries));
                }
            }
        }
        Ok(match drifted.first() {
            None if !lagging.is_empty() => {
                let first = lagging[0].0.clone();
                Check::not_ok(
                    "registers",
                    Class::Verification,
                    Status::Warn,
                    format!(
                        "{} materialized period(s) equal the refold of their basis; behind the journal: {}",
                        checked,
                        lagging
                            .iter()
                            .map(|(code, n)| format!("{code} ({n} entries)"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    format!("fa registers advance --period {first} --json folds the unread entries in"),
                )
                .with_repair(format!("fa registers advance --period {first} --json"))
            }
            None => Check::ok(
                "registers",
                Class::Verification,
                format!("{checked} materialized period(s) equal the journal's refold"),
            ),
            Some(first) => Check::not_ok(
                "registers",
                Class::Verification,
                Status::Fail,
                format!(
                    "stored cells differ from the refold in {}",
                    drifted.join(", ")
                ),
                format!(
                    "fa verify registers --period {first} --json shows the cells; fa registers materialize --period {first} --yes rebuilds them"
                ),
            )
            .with_repair(format!("fa registers materialize --period {first} --yes --json")),
        })
    })();
    checks.push(registers.unwrap_or_else(|e| {
        Check::not_ok(
            "registers",
            Class::Verification,
            Status::Fail,
            e.to_string(),
            "fa verify registers --json",
        )
    }));
    // Leg mirrors and projection edges at HEAD (FA-INV-16). The repair is a
    // previewed, confirmed recovery from the journal, never this check's.
    checks.push(match book.verify_projections(None) {
        Ok(v) if v.is_green() => Check::ok(
            "projections",
            Class::Verification,
            format!(
                "{} legs and {} projection edges equal their entry payloads",
                v.legs_checked, v.edges_checked
            ),
        ),
        Ok(v) => Check::not_ok(
            "projections",
            Class::Verification,
            Status::Fail,
            format!(
                "{} leg projection finding(s) differ from the entry payloads",
                v.drift.len()
            ),
            "fa verify projections --json lists them; fa recover projections --dry-run --json previews the repair from the journal",
        )
        .with_command("fa recover projections --dry-run --json"),
        Err(e) => Check::not_ok(
            "projections",
            Class::Verification,
            Status::Fail,
            e.to_string(),
            "fa verify projections --json",
        ),
    });
    checks.push(match book.verify_availability() {
        Ok(v) if v.drift.is_empty() => Check::ok(
            "availability",
            Class::Verification,
            format!(
                "{} limited account(s), {} cell(s) equal the refold",
                v.accounts_checked, v.cells_checked
            ),
        ),
        Ok(v) => Check::not_ok(
            "availability",
            Class::Verification,
            Status::Fail,
            format!("{} limit cell(s) differ from the refold", v.drift.len()),
            "fa verify availability --json lists them",
        )
        .with_command("fa verify availability --json"),
        Err(e) => Check::not_ok(
            "availability",
            Class::Verification,
            Status::Fail,
            e.to_string(),
            "fa verify availability --json",
        ),
    });
    checks.push(match book.verify_accumulator() {
        Ok(v) if v.is_green() => Check::ok(
            "accumulator",
            Class::Verification,
            if v.states.is_empty() {
                "no checkpoints yet (fa checkpoint create --grant witness)".to_string()
            } else {
                format!(
                    "{} checkpoint(s) and their signatures recompute from the journal and the book's key",
                    v.states.len()
                )
            },
        ),
        Ok(v) => Check::not_ok(
            "accumulator",
            Class::Verification,
            Status::Fail,
            v.broken.unwrap_or_else(|| {
                format!(
                    "{} state finding(s), {} unchained state(s)",
                    v.states.iter().filter(|st| st.finding.is_some()).count(),
                    v.unchained.len()
                )
            }),
            "fa verify accumulator --json shows the findings",
        )
        .with_command("fa verify accumulator --json"),
        Err(e) => Check::not_ok(
            "accumulator",
            Class::Verification,
            Status::Fail,
            e.to_string(),
            "fa verify accumulator --json",
        ),
    });
    (checks, lag)
}

/// `fa doctor`: every check, then the verdict.
pub(crate) fn doctor_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if let Some(extra) = args.positional.get(1) {
        return Err(crate::cli::usage(
            format!("unexpected argument `{extra}`"),
            "fa doctor --book <dir> --json",
        ));
    }
    let mut checks = vec![registries()];
    let held = ctx.books.is_held();
    match ctx.books.locate(args) {
        Err(_) => {
            checks.push(Check::not_ok(
                "book_dir",
                Class::Environment,
                Status::Fail,
                "no book directory named",
                "--book <dir> (or export FA_BOOK=<dir>); a new book: fa book create --name <name> --book <dir>",
            ));
            for name in ["keys", "writer_lease", "book"] {
                checks.push(Check::skipped(
                    name,
                    Class::Environment,
                    "no book directory",
                ));
            }
        }
        Ok((dir, _)) if !dir.is_dir() => {
            checks.push(Check::not_ok(
                "book_dir",
                Class::Environment,
                Status::Fail,
                format!("no directory at {}", dir.display()),
                format!("fa book create --name <name> --book {}", dir.display()),
            ));
            for name in ["keys", "writer_lease", "book"] {
                checks.push(Check::skipped(
                    name,
                    Class::Environment,
                    "no book directory",
                ));
            }
        }
        Ok((dir, keys)) => {
            checks.push(Check::ok(
                "book_dir",
                Class::Environment,
                dir.display().to_string(),
            ));
            checks.push(key_file(&keys));
            checks.push(writer_lease(&dir, held));
            match ctx.books.open(args) {
                Err(fail) => {
                    checks.push(Check::not_ok(
                        "book",
                        Class::Environment,
                        Status::Fail,
                        describe(&fail),
                        "check --book and --keys; `fa book info --json` repeats the error",
                    ));
                    for name in ["registers", "projections", "availability", "accumulator"] {
                        checks.push(Check::skipped(
                            name,
                            Class::Verification,
                            "the book did not open",
                        ));
                    }
                }
                Ok(book) => {
                    let head = book.head().map(|h| h.0).unwrap_or_default();
                    let periods = book.periods().map(|p| p.len()).unwrap_or_default();
                    let accounts = book.accounts().map(|a| a.len()).unwrap_or_default();
                    checks.push(Check::ok(
                        "book",
                        Class::Environment,
                        format!(
                            "book {} opens at head {head}: {periods} period(s), {accounts} account(s)",
                            book.context().book_id.to_hex()
                        ),
                    ));
                    checks.extend(derived_state(&book).0);
                }
            }
        }
    }
    let healthy = checks.iter().all(|c| c.status != Status::Fail);
    let mut text = String::new();
    for c in &checks {
        text.push_str(&format!(
            "{:<8} {:<13} {}\n",
            c.status.name(),
            c.name,
            c.detail
        ));
        if let Some(fix) = &c.fix {
            text.push_str(&format!("{:<22} fix: {fix}\n", ""));
        }
    }
    text.push_str(if healthy {
        "healthy\n"
    } else {
        "NOT healthy: do the first fix above\n"
    });
    ctx.out.event(
        "doctor",
        vec![
            ("healthy", Json::Bool(healthy)),
            (
                "checks",
                Json::Arr(checks.iter().map(Check::json).collect()),
            ),
        ],
        text.trim_end(),
    );
    match checks.iter().find(|c| c.status == Status::Fail) {
        None => Ok(()),
        Some(first) => {
            if first.name == "keys"
                && let Ok((_, keys)) = ctx.books.locate(args)
                && let Err(error) = fa::book::BookKeys::check_permissions(&keys)
                && let Some(refusal) = error.refusal()
            {
                return Err(Fail::Refusal(refusal));
            }
            let message = format!("doctor: {} failed: {}", first.name, first.detail);
            let fix = first.command.clone().map_or_else(
                || {
                    first
                        .fix
                        .clone()
                        .unwrap_or_else(|| "see the checks above".to_string())
                },
                |c| format!("`{c}`"),
            );
            Err(match first.class {
                Class::Foundation => Fail::Internal(format!("{message}; fix: {fix}")),
                Class::Environment => Fail::Environment(format!("{message}; fix: {fix}")),
                Class::Verification => Fail::Verification {
                    message,
                    detail: first.json(),
                    cite: None,
                    fix: Some(fix),
                },
            })
        }
    }
}

/// What `fa triage` and `fa next` read from a book: its state, and the
/// commands to run next, most urgent first.
struct Survey {
    book_id: String,
    daemon: String,
    periods: usize,
    by_state: Vec<(String, i128)>,
    open: Vec<String>,
    accounts: usize,
    pending_cells: usize,
    due_holds: usize,
    due_reversals: usize,
    blocked_reversals: usize,
    derived: Vec<Check>,
    register_lag: Vec<RegisterLag>,
    open_drafts: usize,
    drafts_awaiting_promotion: usize,
    finding_runs: u32,
    /// Open findings across every recorded run, by severity name, most
    /// severe first; every severity is listed, zero included.
    open_findings: Vec<(&'static str, usize)>,
    steps: Vec<NextStep>,
}

/// Severity names, most severe first (fa_lantern::Severity).
const SEVERITIES: [fa_lantern::Severity; 5] = [
    fa_lantern::Severity::Critical,
    fa_lantern::Severity::High,
    fa_lantern::Severity::Medium,
    fa_lantern::Severity::Low,
    fa_lantern::Severity::Info,
];

impl Survey {
    fn healthy(&self) -> bool {
        self.derived.iter().all(|c| c.status != Status::Fail)
    }
}

/// A step that only reads the book.
fn step(command: impl Into<String>, why: impl Into<String>) -> NextStep {
    NextStep {
        command: command.into(),
        why: why.into(),
        writes: false,
        draft: None,
    }
}

/// A step that writes the book (a setup, a resolution or a repair).
fn write_step(command: impl Into<String>, why: impl Into<String>) -> NextStep {
    NextStep {
        writes: true,
        ..step(command, why)
    }
}

/// Read the book once: periods, accounts, pending cells, derived-state
/// health, the daemon, and the next steps that state calls for.
fn survey(ctx: &mut Ctx<'_>, args: &Args) -> Result<Survey, Fail> {
    let capability = ctx.capability(args, &["read"])?;
    let held = ctx.books.is_held();
    let (dir, _) = ctx.books.locate(args)?;
    let who = ctx.principal(args);
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::cli::admit_whole_book_read(book, &capability, &[], "surveying the book")
    })?;
    let daemon = if held {
        "serving".to_string()
    } else {
        let holder = verbs::registry()
            .ok()
            .and_then(|reg| Lease::holder(&dir, &reg.daemon.lease));
        match holder {
            None => "absent".to_string(),
            Some(h) if h == own_note() => "absent".to_string(),
            Some(h) => format!("held: {h}"),
        }
    };
    let periods = book.periods()?;
    let mut by_state: Vec<(String, i128)> = Vec::new();
    for p in &periods {
        match by_state.iter_mut().find(|(n, _)| *n == p.state.name()) {
            Some((_, n)) => *n += 1,
            None => by_state.push((p.state.name().to_string(), 1)),
        }
    }
    let open: Vec<String> = periods
        .iter()
        .filter(|p| p.state == PeriodState::Open)
        .map(|p| p.code.clone())
        .collect();
    let accounts = book.accounts()?.len();
    let mut pending_cells = 0usize;
    for code in &open {
        pending_cells += book.fold_period(code)?.pending.len();
    }
    // FA-CFG-02: a due-but-unswept hold is still pending; it is reported
    // as due until the sweep expires it.
    let due_holds = book.due_holds()?.len();
    let reversals = book.due_reversals()?;
    let due_reversals = reversals
        .iter()
        .filter(|r| r.status == fa_journal::ReversalStatus::Due)
        .count();
    let blocked_reversals = reversals
        .iter()
        .filter(|r| matches!(r.status, fa_journal::ReversalStatus::Blocked { .. }))
        .count();
    let (derived, register_lag) = derived_state(&book);
    // Drafts: a draft never holds an intent the kernel refused, so an open
    // draft with planned intents is work awaiting promotion by an approver
    // who is not its owner (plan §15.2). No other approval is persisted
    // before its commit: a plan is portable bytes until it is committed.
    let drafts = book.drafts()?;
    let open_drafts: Vec<_> = drafts
        .iter()
        .filter(|d| d.state == fa_journal::DraftState::Open)
        .collect();
    let awaiting: Vec<_> = open_drafts
        .iter()
        .filter(|d| !d.intents.is_empty())
        .collect();
    // Findings: every recorded run, and each finding's current review
    // status at the head (Open until acknowledged or dismissed).
    let mut open_findings: Vec<(&'static str, usize)> =
        SEVERITIES.iter().map(|sev| (sev.name(), 0)).collect();
    let mut most_severe: Option<(usize, [u8; 32])> = None;
    let mut request = fa::findings::lookup::FindingRunPageRequest {
        limit: fa::findings::lookup::MAX_FINDING_RUN_PAGE,
        ..Default::default()
    };
    let finding_runs = loop {
        let page = book.finding_runs(who, &capability, &request)??;
        for run in &page.runs {
            let history =
                book.finding_run_review_history(who, &capability, &run.certificate_digest, None)??;
            for finding in &history.histories {
                if finding.status() != fa::findings::review::FindingReviewStatus::Open {
                    continue;
                }
                let severity = finding.finding.finding.severity;
                let rank = SEVERITIES
                    .iter()
                    .position(|sev| *sev == severity)
                    .ok_or_else(|| Fail::Internal("unregistered finding severity".into()))?;
                open_findings[rank].1 += 1;
                if most_severe.is_none_or(|(worst, _)| rank < worst) {
                    most_severe = Some((rank, run.certificate_digest));
                }
            }
        }
        match page.next_cursor {
            Some(cursor) => request.after = Some(cursor),
            None => break page.total_recorded_runs,
        }
    };

    // The next steps, from the state (the first is the most urgent).
    let mut steps = Vec::new();
    if accounts == 0 {
        steps.push(write_step(
            "fa chart import <chart.json> --json",
            "the book has no accounts; install the chart",
        ));
    } else if periods.is_empty() {
        steps.push(write_step(
            "fa period create --fiscal-year <N> --json",
            "entries post into periods; create the fiscal year's",
        ));
    } else if open.is_empty() {
        let future = periods.iter().find(|p| p.state == PeriodState::Future);
        steps.push(write_step(
            format!(
                "fa period open {} --json",
                future.map_or("<code>", |p| p.code.as_str())
            ),
            "no period is open, so nothing can post",
        ));
    }
    // Failures first, then warnings that name their remedy.
    for check in derived
        .iter()
        .filter(|c| c.status == Status::Fail)
        .chain(derived.iter().filter(|c| c.status == Status::Warn))
    {
        if let Some(command) = &check.command {
            let why = format!("{}: {}", check.name, check.detail);
            steps.push(if check.repairs {
                write_step(command.clone(), why)
            } else {
                step(command.clone(), why)
            });
        }
    }
    if let Some((rank, certificate)) = most_severe {
        let open: usize = open_findings.iter().map(|(_, n)| n).sum();
        steps.push(step(
            format!(
                "fa finding list --certificate C:{} --json",
                crate::cli::hex(&certificate)
            ),
            format!(
                "{open} open finding(s) await review; this run holds a {} one (fa finding review F:<vid> --action acknowledge|dismiss)",
                open_findings[rank].0
            ),
        ));
    }
    if let Some(draft) = awaiting.first() {
        steps.push(step(
            format!("fa draft show {} --json", draft.body.name),
            format!(
                "{} draft(s) hold planned intents awaiting promotion by an approver who is not the owner; `{}` holds {}",
                awaiting.len(),
                draft.body.name,
                draft.intents.len()
            ),
        ));
    }
    if pending_cells > 0 {
        steps.push(NextStep {
            // Resolutions are batchable intents: an Agent plans them into a
            // draft instead.
            draft: Some((
                "resolve-holds",
                "fa draft plan resolve-holds --intent <resolution.json> --json",
            )),
            ..write_step(
                "fa resolve --intent <resolution.json> --json",
                format!(
                    "{pending_cells} register cell(s) carry reserved amounts: resolve the holds that are done"
                ),
            )
        });
    }
    if let Some(latest) = open.last() {
        steps.push(step(
            format!("fa tb --period {latest} --json"),
            "the trial balance of the latest open period",
        ));
    }
    Ok(Survey {
        book_id: book.context().book_id.to_hex(),
        daemon,
        periods: periods.len(),
        by_state,
        open,
        accounts,
        pending_cells,
        due_holds,
        due_reversals,
        blocked_reversals,
        derived,
        register_lag,
        open_drafts: open_drafts.len(),
        drafts_awaiting_promotion: awaiting.len(),
        finding_runs,
        open_findings,
        steps: rank_for(ctx, &capability, steps),
    })
}

/// Rank the next steps for the caller (plan §15.3: `fa next` ranks actions
/// for the caller's capability). The embedded owner grants itself each
/// command's ops, so its order is the state's. A launch capability (token,
/// fad session, MCP) runs the steps whose registered bound-route ops it
/// holds first; the rest follow, naming the ops they need. An Agent profile
/// never writes the trunk (plan §14.2), so no step that writes the book is
/// suggested to it.
fn rank_for(
    ctx: &Ctx<'_>,
    capability: &fa_policy::Capability,
    steps: Vec<NextStep>,
) -> Vec<NextStep> {
    if ctx.authority().is_none() {
        return steps;
    }
    let agent = capability.profile() == fa_policy::Profile::Agent;
    // An Agent never writes the book: a write a draft can take becomes that
    // draft's opening, naming the plan to run into it and who promotes it;
    // any other write is not offered.
    let steps = steps.into_iter().filter_map(|st| match (agent && st.writes, st.draft) {
        (false, _) => Some(st),
        (true, Some((name, plan))) => Some(NextStep {
            command: format!("fa draft new {name} --json"),
            why: format!(
                "{}; this Agent capability never writes trunk: open the draft, plan each intent into it with `{plan}`, and a Human approver who is not you promotes it (plan §15.2)",
                st.why
            ),
            writes: true,
            draft: None,
        }),
        (true, None) => None,
    });
    let Ok(reg) = verbs::registry() else {
        return steps.collect();
    };
    let mut runnable = Vec::new();
    let mut needing = Vec::new();
    for st in steps {
        let words: Vec<String> = st
            .command
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect();
        let Ok(parsed) = crate::args::parse(&words, &reg.value_flags(), &reg.switches()) else {
            needing.push(st);
            continue;
        };
        let Some(verb) = parsed.positional.first() else {
            needing.push(st);
            continue;
        };
        let missing: Vec<&str> = crate::cli::bound_command_rule(verb, &parsed)
            .map(|(ops, _)| {
                ops.iter()
                    .filter(|op| !capability.holds(**op))
                    .map(|op| op.name())
                    .collect()
            })
            .unwrap_or_default();
        if missing.is_empty() {
            runnable.push(st);
        } else {
            needing.push(NextStep {
                why: format!(
                    "{} (needs {}, which this capability does not hold)",
                    st.why,
                    missing.join(", ")
                ),
                ..st
            });
        }
    }
    runnable.extend(needing);
    runnable
}

fn no_arguments(args: &Args, example: &str) -> Result<(), Fail> {
    match args.positional.get(1) {
        Some(extra) => Err(crate::cli::usage(
            format!("unexpected argument `{extra}`"),
            example,
        )),
        None => Ok(()),
    }
}

/// `fa triage`: the book's state, and every next step in `next_actions`.
pub(crate) fn triage_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    no_arguments(args, "fa triage --book <dir> --json")?;
    let sv = survey(ctx, args)?;
    let actions: Vec<(String, String)> = sv
        .steps
        .iter()
        .map(|st| (st.command.clone(), st.why.clone()))
        .collect();
    let health = if sv.healthy() { "ok" } else { "failing" };
    let mut text = format!(
        "book {} · {} periods ({}) · open: {} · {} accounts · {} pending cell(s) · due: {} hold(s), {} reversal(s) ({} blocked) · derived state {} · daemon {}",
        sv.book_id,
        sv.periods,
        sv.by_state
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join(", "),
        if sv.open.is_empty() {
            "none".to_string()
        } else {
            sv.open.join(" ")
        },
        sv.accounts,
        sv.pending_cells,
        sv.due_holds,
        sv.due_reversals,
        sv.blocked_reversals,
        health,
        sv.daemon
    );
    let open_findings: usize = sv.open_findings.iter().map(|(_, n)| n).sum();
    text.push_str(&format!(
        "\ndrafts: {} open, {} awaiting promotion · findings: {} open across {} run(s) ({}) · register lag: {}",
        sv.open_drafts,
        sv.drafts_awaiting_promotion,
        open_findings,
        sv.finding_runs,
        sv.open_findings
            .iter()
            .map(|(name, n)| format!("{name} {n}"))
            .collect::<Vec<_>>()
            .join(", "),
        if sv.register_lag.is_empty() {
            "no materialized period".to_string()
        } else {
            sv.register_lag
                .iter()
                .map(|lag| format!("{} {} entr(ies)", lag.period, lag.lag_entries))
                .collect::<Vec<_>>()
                .join(", ")
        }
    ));
    for st in &sv.steps {
        text.push_str(&format!("\nnext: {}   ({})", st.command, st.why));
    }
    ctx.out.event_with_actions(
        "book_triage",
        vec![
            ("health", s(health)),
            ("daemon", s(&sv.daemon)),
            ("periods", Json::Int(sv.periods as i128)),
            (
                "periods_by_state",
                Json::Obj(
                    sv.by_state
                        .iter()
                        .map(|(k, v)| (k.clone(), Json::Int(*v)))
                        .collect(),
                ),
            ),
            ("open_periods", Json::Arr(sv.open.iter().map(s).collect())),
            ("accounts", Json::Int(sv.accounts as i128)),
            ("pending_cells", Json::Int(sv.pending_cells as i128)),
            ("due_holds", Json::Int(sv.due_holds as i128)),
            ("due_reversals", Json::Int(sv.due_reversals as i128)),
            ("blocked_reversals", Json::Int(sv.blocked_reversals as i128)),
            (
                "derived",
                Json::Arr(sv.derived.iter().map(Check::json).collect()),
            ),
            (
                "register_watermark_lag",
                Json::Arr(sv.register_lag.iter().map(RegisterLag::json).collect()),
            ),
            ("open_drafts", Json::Int(sv.open_drafts as i128)),
            (
                "drafts_awaiting_promotion",
                Json::Int(sv.drafts_awaiting_promotion as i128),
            ),
            ("finding_runs", Json::Int(i128::from(sv.finding_runs))),
            (
                "open_findings_by_severity",
                Json::Obj(
                    sv.open_findings
                        .iter()
                        .map(|(name, n)| ((*name).to_string(), Json::Int(*n as i128)))
                        .collect(),
                ),
            ),
        ],
        &text,
        &actions,
    );
    Ok(())
}

/// `fa next`: the single most urgent next step as data (the rest follow in
/// `next_actions`). A step that needs authority this build does not
/// self-issue names it in its command (`--grant approve`, `--grant witness`).
pub(crate) fn next_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    no_arguments(args, "fa next --book <dir> --json")?;
    let sv = survey(ctx, args)?;
    let mut steps = sv.steps.into_iter();
    let first = steps.next();
    let actions: Vec<(String, String)> = steps.map(|st| (st.command, st.why)).collect();
    let text = first.as_ref().map_or_else(
        || "nothing to do".to_string(),
        |st| format!("{}   ({})", st.command, st.why),
    );
    ctx.out.event_with_actions(
        "next_step",
        vec![
            (
                "command",
                first.as_ref().map_or(Json::Null, |st| s(&st.command)),
            ),
            ("why", first.as_ref().map_or(Json::Null, |st| s(&st.why))),
        ],
        &text,
        &actions,
    );
    Ok(())
}
