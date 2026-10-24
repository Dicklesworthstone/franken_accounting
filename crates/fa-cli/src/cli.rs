//! The `fa` command set (plan §15.3, Appendix D), shared by the `fa` binary
//! and the `fad` daemon.
//!
//! Contract: stdout is data, stderr is diagnostics; `--json` turns every
//! result into one JSON object per line with an `event` discriminator; the
//! exit code is the verdict (0 ok · 2 usage · 3 accounting-law refusal ·
//! 4 environment · 5 foundation · 6 conflict · 7 safety · 8 verification;
//! 1 is never emitted); empty results exit 0; bare `fa` prints triage and
//! exits; there is no TUI.
//!
//! Every verb, subcommand, alias, flag, usage line, and event schema comes
//! from the verb registry (`registries/verbs.toml`, [`crate::verbs`]);
//! `HANDLERS` is the only list of verbs in this crate, and the parity tests
//! fail when the two disagree.
//!
//! One dispatcher, two hosts. The `fa` binary runs a command against the book
//! directory it names, opening it for that command under the writer lease
//! ([`Books::Dir`]); `fad` runs the same command against the book it holds
//! ([`Books::Held`]). Output goes to a [`Sink`]: the process's stdio, or a
//! capture the daemon returns in its response frame. Refusals are therefore
//! byte-identical across the two hosts by construction.

use core::cell::RefCell;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use fa::aging::portfolio::{AgingAccountScope, AgingPortfolioRequest};
use fa::book::{Book, BookError, BookKeys, Entropy};
use fa::{
    AdjustmentCategory, AdjustmentSign, AgingBuckets, AgingReconciliationRequest, AllocationMethod,
    AllocationPosting, AllocationRequest, AllocationReview, AllocationTarget,
    BalanceAllocationRequest, BalanceAllocationReview, CashFlowActivity, CashFlowAssignment,
    CashFlowDefinition, CashFlowSection, IndirectCashFlowAdjustment, IndirectCashFlowDefinition,
    IndirectCashFlowRequest, MAX_ALLOCATION_REVIEW_BYTES, MAX_BALANCE_ALLOCATION_REVIEW_BYTES,
    MAX_PLAN_BYTES, MAX_SETTLEMENT_GROUP_REVIEW_BYTES, MAX_SETTLEMENT_REVIEW_BYTES, PostIntent,
    PostPlan, ReplacementPlan, ReportOutput, ReportSelection, RollForwardRequest,
    SettlementGroupRequest, SettlementGroupReview, SettlementLegSelection, SettlementPostRequest,
    SettlementReview, Statement, StatementDefinition, StatementDiffRequest, StatementEntryEvent,
    StatementSelection, StatementTraceRequest, SummaryRequest, SummaryScope, TrialBalanceSelection,
};
use fa_journal::BookContext;
use fa_journal::{
    AccountSpec, BalanceLimit, BookSpec, Capability, PostRequest, Posted, Refusal, UnitPolicy, exit,
};
use fa_model::{
    AccountType, EntryClass, EntryOrigin, EntryPayload, Id128, LegPayload, Oid, PeriodRef,
    account_vid, principal_vid,
};
use fa_model::{ControlPayload, Disposition, Pending};
use fa_money::{Amount, Side};
use fa_registry::reason_codes::{Reason, ReasonCodes};
use fa_time::{DateDay, FiscalCalendar, PeriodKind, PeriodState, PeriodTransition};
use fgdb_types::{CommitSeq, VId};

use crate::args::{self, Args, UsageError, nearest};
use crate::authority::{LaunchAuthority, owner_envelope};
use crate::document;
use crate::json::{self, Json, obj, s};
use crate::notary;
use crate::templates;
use crate::verbs::{self, Condition, Dangerous, Registry, Verb};

mod batch_plan;
mod outcome_recovery;

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Plan Appendix D FA-REF-007: an operation that cannot be undone in
/// practice was not confirmed (`--yes`, or a `--plan` file), exit 7.
pub(crate) const CONFIRMATION_REQUIRED: &str = "FA-REF-007";

type Handler = fn(&mut Ctx<'_>, &Args) -> Result<(), Fail>;

/// One handler per registered verb, keyed by the registry's verb name.
const HANDLERS: &[(&str, Handler)] = &[
    ("book", book_cmd),
    ("chart", chart_cmd),
    ("access", crate::access::access_cmd),
    ("law", crate::laws::law_cmd),
    ("unit", crate::laws::unit_cmd),
    ("period", period_cmd),
    ("calendar", calendar_cmd),
    ("close", crate::closing::close_cmd),
    ("approve", approve_cmd),
    ("capability", capability_cmd),
    ("draft", draft_cmd),
    ("scenario", crate::scenario::scenario_cmd),
    ("branch", crate::scenario::branch_cmd),
    ("case", crate::case::case_cmd),
    ("post", post_cmd),
    ("invoice", crate::typed::invoice_cmd),
    ("bill", crate::typed::bill_cmd),
    ("receipt", crate::typed::receipt_cmd),
    ("payment", crate::typed::payment_cmd),
    ("accrue", crate::typed::accrue_cmd),
    ("defer", crate::typed::defer_cmd),
    ("batch", crate::typed::batch_cmd),
    ("post-reserve", crate::typed::post_reserve_cmd),
    ("void-reserve", crate::typed::void_reserve_cmd),
    ("replace", crate::typed::replace_cmd),
    ("commit", commit_cmd),
    ("reclass", reclass_cmd),
    ("reverse", reverse_cmd),
    ("reserve", reserve_cmd),
    ("resolve", resolve_cmd),
    ("allocate", allocate_cmd),
    ("settle", settle_cmd),
    ("document", document::document_cmd),
    ("assert-balance", document::assert_balance_cmd),
    ("event", event_cmd),
    ("migrate", migrate_cmd),
    ("tb", tb_cmd),
    ("statement", statement_cmd),
    ("replay", notary::replay_cmd),
    ("certificate", notary::certificate_cmd),
    ("open-items", open_items_cmd),
    ("gl", gl_cmd),
    ("explain", explain_cmd),
    ("search", search_cmd),
    ("diff", crate::diff::diff_cmd),
    ("consolidate", crate::consolidate::consolidate_cmd),
    ("query", crate::query::query_cmd),
    ("rule", crate::rule::rule_cmd),
    ("procedure", procedure_cmd),
    ("jet", jet_cmd),
    ("benford", benford_cmd),
    ("trace", trace_cmd),
    ("sample", crate::sample::sample_cmd),
    ("engagement", crate::engagement::engagement_cmd),
    ("adjustment", crate::engagement::adjustment_cmd),
    ("checkpoint", notary::checkpoint_cmd),
    ("proof", crate::proof::proof_cmd),
    ("bundle", crate::proof::bundle_cmd),
    ("production", crate::production::production_cmd),
    ("produce", crate::production::produce_cmd),
    ("subledger", crate::subledger::subledger_cmd),
    ("party", crate::rea::party_cmd),
    ("instrument", crate::rea::instrument_cmd),
    ("entity", crate::rea::entity_cmd),
    ("dimension", crate::dimension::dimension_cmd),
    ("finding", crate::finding::finding_cmd),
    ("fx", crate::fx::fx_cmd),
    ("bank", crate::bank::bank_cmd),
    ("export", crate::export::export_cmd),
    ("verify", verify_cmd),
    ("registers", registers_cmd),
    ("recover", recover_cmd),
    ("entry", entry_cmd),
    ("doctor", crate::triage::doctor_cmd),
    ("triage", crate::triage::triage_cmd),
    ("next", crate::triage::next_cmd),
    ("capabilities", capabilities_cmd),
    ("robot-docs", robot_docs_cmd),
    ("help", help_cmd),
    ("demo", demo_cmd),
    ("schedule", crate::recurring::schedule_cmd),
];

/// The registered verbs this build can dispatch (the parity tests compare
/// it with `registries/verbs.toml`).
#[must_use]
pub fn handled_verbs() -> Vec<&'static str> {
    HANDLERS.iter().map(|(name, _)| *name).collect()
}

/// What a command can end with besides success.
pub(crate) enum Fail {
    Usage(UsageError),
    Refusal(Refusal),
    /// A catalog refusal whose error event carries a structured `detail`
    /// (a stale plan's fresh plan, fa-we7). Boxed: `Fail` stays small.
    RefusalDetail(Box<(Refusal, Json)>),
    Book(BookError),
    Verification {
        message: String,
        detail: Json,
        cite: Option<String>,
        fix: Option<String>,
    },
    /// The registry and this binary disagree (a parity defect), or the
    /// embedded registry is unreadable: a foundation failure, exit 5.
    Internal(String),
    /// A command's artifact input/output failed: a foundation I/O failure, exit 5.
    Io(String),
    /// The environment cannot serve the command (no daemon where one was
    /// asked for): exit 4.
    Environment(String),
}

impl From<UsageError> for Fail {
    fn from(e: UsageError) -> Self {
        Self::Usage(e)
    }
}
impl From<BookError> for Fail {
    fn from(e: BookError) -> Self {
        Self::Book(e)
    }
}
impl From<Refusal> for Fail {
    fn from(r: Refusal) -> Self {
        Self::Refusal(r)
    }
}

pub(crate) fn usage(message: impl Into<String>, fix: impl Into<String>) -> Fail {
    Fail::Usage(UsageError {
        message: message.into(),
        fix: fix.into(),
    })
}

/// Report amounts come from stored entries and cells. A unit absent from
/// the book's registry is corruption, not user input or printable money.
fn amount_corruption(error: fa_money::AmountError) -> Fail {
    Fail::Book(BookError::Kernel(fa_journal::KernelError::Corrupt(
        format!(
            "cannot render stored amount: {error}; preserve the book and use its creating registry; unit reconciliation is required (fa-nnm)"
        ),
    )))
}

pub(crate) fn render_amount(
    amount: Amount,
    units: &fa_money::UnitRegistry,
) -> Result<String, Fail> {
    amount.try_render(units).map_err(amount_corruption)
}

pub(crate) fn registered_unit_code(
    unit: fa_money::UnitId,
    units: &fa_money::UnitRegistry,
) -> Result<String, Fail> {
    units
        .get(unit)
        .map(|unit| unit.code.clone())
        .ok_or_else(|| amount_corruption(fa_money::AmountError::UnknownUnit(unit.to_string())))
}

/// Where a command's output goes.
#[derive(Debug)]
pub enum Sink {
    /// The process's own stdout and stderr (the `fa` binary).
    Stdio,
    /// Kept, in order, for a daemon response frame.
    Capture(RefCell<Captured>),
}

/// A command's captured stdout and stderr, byte for byte.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Captured {
    pub stdout: String,
    pub stderr: String,
}

/// Human-mode styling (plan §15.3, Appendix D determinism), resolved once
/// per command: off under `--no-color`, `NO_COLOR` (non-empty), `CI` (set,
/// and not `false`/`0`), `TERM=dumb`, a stdout that is not a terminal, a
/// daemon capture, or robot mode. Styling never changes a byte of data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    color: bool,
}

impl Style {
    /// No styling at all.
    pub const PLAIN: Self = Self { color: false };

    #[must_use]
    pub fn resolve(
        json: bool,
        no_color: bool,
        capture: bool,
        stdout_is_terminal: bool,
        env: impl Fn(&str) -> Option<String>,
    ) -> Self {
        let set = |name: &str| env(name).filter(|v| !v.is_empty());
        let off = json
            || no_color
            || capture
            || !stdout_is_terminal
            || set("NO_COLOR").is_some()
            || set("CI").is_some_and(|v| v != "false" && v != "0")
            || set("TERM").is_some_and(|v| v == "dumb");
        Self { color: !off }
    }

    /// A human table's header line.
    #[must_use]
    pub fn header(self, text: &str) -> String {
        if self.color {
            format!("\x1b[1m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }
}

/// What a command's envelope says beyond its event (plan Appendix D): the
/// book and coordinate it describes and the warnings it raised. Shared by
/// the command's [`Out`] and its book source, so opening a book sets it.
#[derive(Debug, Default)]
struct Said {
    at: Option<At>,
    warnings: Vec<String>,
    time_selection: Option<fa::InstantSelection>,
    authority: Option<Json>,
    /// Explicit issuer-token disclosure only; never a launch-bound session.
    issuer_authority: Option<Json>,
    /// The launch template is Agent: trunk plans are rehearsals (FA-REF-013).
    agent: bool,
    owner_principal: Option<String>,
    /// The branch a `--branch` read selected (`scenario:<name>`); trunk
    /// when absent.
    branch: Option<String>,
}

/// Where a robot line sits (plan §4.8): the book's id, and the branch
/// (`trunk`, or `scenario:<name>` for a read of a scenario's
/// materialization), recorded sequence and effective selector it
/// describes. A scenario read's `known_at` is its materialization's own
/// sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct At {
    pub book: String,
    pub branch: String,
    pub known_at: CommitSeq,
    pub effective: String,
}

/// One robot-mode line (plan Appendix D): `{v, event, book, coordinate,
/// data, certificate, authority, warnings, next_actions}` with the event's fields under
/// `data`; `book` and `coordinate` from `at` (null when no book backs the
/// line); and the registry's next actions for the event. This ordinary
/// constructor leaves `certificate` null; certified reports bind their
/// retained replay certificate per event. A daemon wire frame is its own
/// flat object, never a robot line.
#[must_use]
pub fn robot_line(event: &str, data: Json, at: Option<&At>, warnings: &[String]) -> Json {
    robot_line_with_actions(
        event,
        data,
        at,
        warnings,
        &[],
        RobotMetadata {
            certificate: None,
            time_selection: None,
            authority: owner_envelope(None),
        },
    )
}

struct RobotMetadata<'a> {
    certificate: Option<&'a str>,
    time_selection: Option<&'a fa::InstantSelection>,
    authority: Json,
}

fn robot_line_with_actions(
    event: &str,
    data: Json,
    at: Option<&At>,
    warnings: &[String],
    actions: &[(String, String)],
    metadata: RobotMetadata<'_>,
) -> Json {
    let mut next_actions: Vec<Json> = verbs::registry().map_or_else(
        |_| Vec::new(),
        |r| {
            r.next_actions_for(event)
                .map(|n| obj(vec![("command", s(&n.command)), ("why", s(&n.why))]))
                .collect()
        },
    );
    next_actions.extend(
        actions
            .iter()
            .map(|(command, why)| obj(vec![("command", s(command)), ("why", s(why))])),
    );
    obj(vec![
        ("v", Json::Int(verbs::ENVELOPE_VERSION)),
        ("event", s(event)),
        ("book", at.map_or(Json::Null, |a| s(&a.book))),
        (
            "coordinate",
            at.map_or(Json::Null, |a| {
                obj(vec![
                    ("branch", s(&a.branch)),
                    ("known_at", Json::Int(i128::from(a.known_at.0))),
                    ("effective", s(&a.effective)),
                    (
                        "time_evidence",
                        metadata
                            .time_selection
                            .map_or(Json::Null, time_selection_json),
                    ),
                ])
            }),
        ),
        (verbs::PAYLOAD, data),
        ("certificate", metadata.certificate.map_or(Json::Null, s)),
        ("authority", metadata.authority),
        ("warnings", Json::Arr(warnings.iter().map(s).collect())),
        ("next_actions", Json::Arr(next_actions)),
    ])
}

/// Point `said`'s coordinate at `book`'s head now, keeping a narrowed
/// effective selector (`all` otherwise).
fn stamp(said: &RefCell<Said>, book: &Book) -> Result<(), Fail> {
    let head = book.head()?;
    let mut said = said.borrow_mut();
    let effective = said
        .at
        .as_ref()
        .map_or_else(|| "all".to_string(), |a| a.effective.clone());
    said.time_selection = None;
    let branch = said.branch.clone().unwrap_or_else(|| "trunk".to_string());
    said.at = Some(At {
        book: book.context().book_id.to_hex(),
        branch,
        known_at: head,
        effective,
    });
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OutputFormat {
    Human,
    Json,
    Toon,
}

impl OutputFormat {
    pub(crate) const fn is_robot(self) -> bool {
        matches!(self, Self::Json | Self::Toon)
    }
}

pub(crate) struct Out {
    /// True in robot mode (`--json`, `--format json`, or `--format toon`).
    json: bool,
    format: OutputFormat,
    style: Style,
    sink: Sink,
    said: Rc<RefCell<Said>>,
}

impl Out {
    #[cfg(test)]
    fn new(json: bool, capture: bool) -> Self {
        Self::new_format(
            if json {
                OutputFormat::Json
            } else {
                OutputFormat::Human
            },
            capture,
        )
    }

    fn new_format(format: OutputFormat, capture: bool) -> Self {
        Self::styled_format(format, capture, Style::PLAIN)
    }

    fn with_authority(self, authority: Option<&LaunchAuthority>) -> Self {
        {
            let mut said = self.said.borrow_mut();
            said.authority = authority.map(LaunchAuthority::envelope_json);
            said.agent =
                authority.is_some_and(|a| a.profile() == crate::authority::LaunchProfile::Agent);
        }
        self
    }

    fn is_bound(&self) -> bool {
        self.said.borrow().authority.is_some()
    }

    /// The launch-bound Agent template, whose trunk plans commit for no one.
    fn is_bound_agent(&self) -> bool {
        self.said.borrow().agent
    }

    fn styled_format(format: OutputFormat, capture: bool, style: Style) -> Self {
        Self {
            json: format.is_robot(),
            format,
            style,
            sink: if capture {
                Sink::Capture(RefCell::new(Captured::default()))
            } else {
                Sink::Stdio
            },
            said: Rc::new(RefCell::new(Said::default())),
        }
    }

    /// The command's resolved human styling.
    pub(crate) fn style(&self) -> Style {
        self.style
    }

    /// Point the envelope coordinate at `book`'s head now, keeping a
    /// narrowed effective selector (`all` otherwise). Every book a command
    /// opens passes through here, and every write calls it again so the
    /// coordinate names the head the write produced.
    pub(crate) fn at_book(&self, book: &Book) -> Result<(), Fail> {
        stamp(&self.said, book)
    }

    /// Narrow the coordinate's effective selector (`period:<code>`, …).
    pub(crate) fn effective(&self, selector: String) {
        if let Some(a) = self.said.borrow_mut().at.as_mut() {
            a.effective = selector;
        }
    }

    /// Pin the coordinate's recorded sequence (an `--as-known-at` read).
    pub(crate) fn known_at(&self, seq: CommitSeq) {
        let mut said = self.said.borrow_mut();
        if let Some(a) = said.at.as_mut() {
            a.known_at = seq;
        }
        if said
            .time_selection
            .as_ref()
            .is_some_and(|time| time.resolution.resolved_seq != seq.0)
        {
            said.time_selection = None;
        }
    }

    /// Bind an instant-selected coordinate to the retained tick resolution.
    pub(crate) fn time_selection(&self, time: Option<&fa::InstantSelection>) {
        let mut said = self.said.borrow_mut();
        if let (Some(a), Some(time)) = (said.at.as_mut(), time) {
            a.known_at = CommitSeq(time.resolution.resolved_seq);
        }
        said.time_selection = time.cloned();
    }

    /// Something the command noticed but did not refuse: robot mode carries
    /// it in the envelope's `warnings`, human mode on stderr.
    pub(crate) fn warn(&self, text: impl Into<String>) {
        let text = text.into();
        if !self.json {
            self.diag(format!("warning: {text}"));
        }
        self.said.borrow_mut().warnings.push(text);
    }

    /// One line of data on stdout.
    pub(crate) fn line(&self, text: impl AsRef<str>) {
        match &self.sink {
            Sink::Stdio => println!("{}", text.as_ref()),
            Sink::Capture(c) => {
                let mut c = c.borrow_mut();
                c.stdout.push_str(text.as_ref());
                c.stdout.push('\n');
            }
        }
    }

    /// One line of diagnostics on stderr.
    pub(crate) fn diag(&self, text: impl AsRef<str>) {
        match &self.sink {
            Sink::Stdio => eprintln!("{}", text.as_ref()),
            Sink::Capture(c) => {
                let mut c = c.borrow_mut();
                c.stderr.push_str(text.as_ref());
                c.stderr.push('\n');
            }
        }
    }

    /// One event: in robot mode the Appendix D line with `fields` as its
    /// `data`, otherwise the human text (nothing when it is empty).
    pub(crate) fn event(&self, name: &str, fields: Vec<(&str, Json)>, human: &str) {
        self.event_with_actions(name, fields, human, &[]);
    }

    pub(crate) fn event_with_actions(
        &self,
        name: &str,
        fields: Vec<(&str, Json)>,
        human: &str,
        actions: &[(String, String)],
    ) {
        self.emit_event(name, fields, human, actions, None);
    }

    /// Bind a successful report line to its replay certificate. The binding
    /// is per event, so a later failure cannot inherit a success certificate.
    pub(crate) fn event_with_certificate(
        &self,
        name: &str,
        fields: Vec<(&str, Json)>,
        human: &str,
        certificate: Option<&str>,
    ) {
        self.emit_event(name, fields, human, &[], certificate);
    }

    fn emit_event(
        &self,
        name: &str,
        fields: Vec<(&str, Json)>,
        human: &str,
        actions: &[(String, String)],
        certificate: Option<&str>,
    ) {
        if self.json {
            let said = self.said.borrow();
            let line = robot_line_with_actions(
                name,
                obj(fields),
                said.at.as_ref(),
                &said.warnings,
                actions,
                RobotMetadata {
                    certificate,
                    time_selection: said.time_selection.as_ref(),
                    authority: said
                        .authority
                        .clone()
                        .or_else(|| said.issuer_authority.clone())
                        .unwrap_or_else(|| owner_envelope(said.owner_principal.as_deref())),
                },
            );
            match self.format {
                OutputFormat::Toon => self.line(line.render_toon()),
                OutputFormat::Json | OutputFormat::Human => self.line(line.render()),
            }
        } else if !human.is_empty() {
            self.line(human);
        }
    }

    fn into_captured(self) -> Captured {
        match self.sink {
            Sink::Stdio => Captured::default(),
            Sink::Capture(c) => c.into_inner(),
        }
    }
}

/// Where a command's book comes from.
pub enum Books<'a> {
    /// The directory `--book` (or `FA_BOOK`) names, opened for this one
    /// command while the command holds the book's writer lease.
    Dir,
    /// The same directory, with its writer lease taken only when a handler
    /// first opens the book: after the command's authority admission, so a
    /// refused launch-bound command never touches the book (fa-23r,
    /// authorization precedes observation). The lease is then held until the
    /// command ends.
    LeasedOnOpen {
        /// The registry's lease file name.
        lease: String,
        /// The holder note written into the lease.
        note: String,
        held: Option<crate::lease::Lease>,
    },
    /// The book a daemon holds open under its writer lease.
    Held { book: &'a mut Book, dir: PathBuf },
}

/// An open book: owned for one command, or lent by the daemon.
pub(crate) enum BookRef<'a> {
    Owned(Box<Book>),
    Held(&'a mut Book),
}

impl core::ops::Deref for BookRef<'_> {
    type Target = Book;
    fn deref(&self) -> &Book {
        match self {
            Self::Owned(b) => b,
            Self::Held(b) => b,
        }
    }
}

impl core::ops::DerefMut for BookRef<'_> {
    fn deref_mut(&mut self) -> &mut Book {
        match self {
            Self::Owned(b) => b,
            Self::Held(b) => b,
        }
    }
}

impl Books<'_> {
    /// Open the book `args` names, its path (and `--keys`) resolved against
    /// the caller's working directory `cwd` ([`Files::cwd`]): a daemon
    /// compares the client's book, not a path in its own directory, with
    /// the one it holds.
    pub(crate) fn open(&mut self, args: &Args, cwd: Option<&Path>) -> Result<BookRef<'_>, Fail> {
        let dir = self.dir_for(args, cwd)?;
        match self {
            Self::Dir => {
                let keys = BookKeys::load(&keys_path(args, &dir, cwd))?;
                Ok(BookRef::Owned(Box::new(Book::open_dir(
                    &dir,
                    keys,
                    Entropy::production(),
                )?)))
            }
            Self::LeasedOnOpen { lease, note, held } => {
                if held.is_none() {
                    // Lease admission comes first and writes nothing. A lease
                    // another writer holds (a fad, a direct command, a genesis
                    // in progress) is a conflict, exit 6, ahead of every check
                    // that reads the book: the precedence the front door
                    // gives a held book (its key pre-check runs only when
                    // nobody holds the lease).
                    if let Some(holder) = crate::lease::Lease::holder(&dir, lease) {
                        let error = crate::lease::LeaseError::Held {
                            path: dir.join(lease.as_str()),
                            holder,
                        };
                        return Err(Fail::Refusal(leased_on_open_held(&error, &dir)));
                    }
                    // Fail closed: a directory that is not a book (missing,
                    // empty, populated, or reached through a symlink) is never
                    // opened without its lease, and no lease file is written
                    // into it.
                    if !crate::lease::Lease::is_book_dir(&dir) {
                        return Err(Fail::Environment(format!(
                            "cannot take the book's writer lease: {} is not a FrankenAccounting book directory",
                            dir.display()
                        )));
                    }
                }
                // A key file that fails its 0600/owner check is refused
                // (FA-REF-155) before the lease note is rewritten.
                let keys = BookKeys::load(&keys_path(args, &dir, cwd))?;
                if held.is_none() {
                    match crate::lease::Lease::acquire(&dir, lease, note) {
                        Ok(acquired) => *held = Some(acquired),
                        Err(error @ crate::lease::LeaseError::Held { .. }) => {
                            return Err(Fail::Refusal(leased_on_open_held(&error, &dir)));
                        }
                        Err(error @ crate::lease::LeaseError::Io { .. }) => {
                            return Err(Fail::Environment(format!(
                                "cannot acquire the configured book's writer lease: {error}"
                            )));
                        }
                    }
                }
                Ok(BookRef::Owned(Box::new(Book::open_dir(
                    &dir,
                    keys,
                    Entropy::production(),
                )?)))
            }
            Self::Held { book, dir: held } => {
                if !same_dir(&dir, held) {
                    return Err(usage(
                        format!("this fad serves {}, not {}", held.display(), dir.display()),
                        format!(
                            "--book {} (or run the command directly against its own book)",
                            held.display()
                        ),
                    ));
                }
                Ok(BookRef::Held(book))
            }
        }
    }

    /// The book a command names: `--book` (or `FA_BOOK`). A daemon serves
    /// exactly the book it holds, so a held request without `--book` names
    /// that book, never one the daemon's own `FA_BOOK` would.
    fn dir_for(&self, args: &Args, cwd: Option<&Path>) -> Result<PathBuf, Fail> {
        match self {
            Self::Held { dir, .. } if args.flag("--book").is_none() => Ok(dir.clone()),
            _ => book_dir(args, cwd),
        }
    }

    fn is_held(&self) -> bool {
        matches!(self, Self::Held { .. })
    }

    /// Genesis: once `book create` has validated every argument, prepare
    /// `dir` and take its writer lease before any key or store byte is
    /// written, so a refused create leaves no directory, lease note or key.
    /// `Dir` already holds the lease (the front door took it for an existing
    /// directory) and a daemon's `Held` book never reaches genesis.
    fn lease_for_genesis(&mut self, dir: &Path) -> Result<(), Fail> {
        let Self::LeasedOnOpen { lease, note, held } = self else {
            return Ok(());
        };
        if held.is_some() {
            return Ok(());
        }
        if dir.exists()
            && !crate::lease::Lease::is_book_dir(dir)
            && !crate::lease::Lease::is_empty_or_lease_only(dir, lease)
        {
            return Err(Fail::Environment(format!(
                "cannot prepare book directory {} for its writer lease: directory is not a book and is not empty",
                dir.display()
            )));
        }
        std::fs::create_dir_all(dir).map_err(|error| {
            Fail::Environment(format!(
                "cannot prepare book directory {} for its writer lease: {error}",
                dir.display()
            ))
        })?;
        match crate::lease::Lease::acquire(dir, lease, note) {
            Ok(acquired) => {
                *held = Some(acquired);
                Ok(())
            }
            Err(error @ crate::lease::LeaseError::Held { .. }) => {
                Err(Fail::Refusal(error.refusal(dir)))
            }
            Err(error @ crate::lease::LeaseError::Io { .. }) => Err(Fail::Environment(format!(
                "cannot acquire the book's writer lease: {error}"
            ))),
        }
    }
}

/// FA-REF-018 for a lease held while [`Books::LeasedOnOpen`] admits a
/// command: a launch-config binding has no token to present to the fad
/// (a token-bound session is routed to it before this point, fa-r3q), so
/// the fix names the operator's remedies.
fn leased_on_open_held(error: &crate::lease::LeaseError, dir: &Path) -> Refusal {
    let mut refusal = error.refusal(dir);
    refusal
        .message
        .push_str("; a launch-config session has no issued token to present to the book's fad");
    refusal.fix = "ask the operator to release the book's writer lease, or to launch this session with an issued token (fa capability issue …, then --token <file>), which fad binds per request".into();
    refusal
}

/// A command's book source: its [`Books`], stamping the envelope coordinate
/// on every book it opens (plan Appendix D), so no handler can emit a book
/// event without one.
/// `--branch scenario:<name>` (plan §15.2, bead fa-k07b): the command reads
/// the scenario's materialization (a scratch replay of the trunk prefix at
/// its fork plus its intents) instead of trunk. `--branch draft:<name>`
/// (plan §15.2, bead fa-s7x) reads the draft's rehearsal: trunk at the head
/// with every planned intent posted together, exactly as promotion would,
/// under the reader's current whole-book read authority (`bound`, else the
/// embedded owner's read). Only read verbs register `--branch`, so no write
/// reaches a replay. A branch read is not yet certified, and trunk known-at
/// selectors do not apply to it.
fn select_branch<'b>(
    args: &Args,
    mut book: BookRef<'b>,
    said: &RefCell<Said>,
    bound: Option<&Capability>,
) -> Result<BookRef<'b>, Fail> {
    let selector = match args.flag("--branch") {
        None | Some("trunk") => return Ok(book),
        Some(selector) => selector,
    };
    let unknown = || {
        usage(
            format!("--branch `{selector}` is neither trunk, scenario:<name> nor draft:<name>"),
            "--branch scenario:<name> (fa scenario list --json) or draft:<name> (fa draft list --json), or omit --branch to read trunk",
        )
    };
    let scenario = selector
        .strip_prefix("scenario:")
        .filter(|name| !name.is_empty());
    let draft = selector
        .strip_prefix("draft:")
        .filter(|name| !name.is_empty());
    if scenario.is_none() && draft.is_none() {
        return Err(unknown());
    }
    let trunk_selector = ["--as-known-at", "--known-at", "--before", "--after"]
        .iter()
        .any(|flag| args.flag(flag).is_some());
    if trunk_selector
        || args.switch("--certify")
        || args.flag("--certificate-out").is_some()
        || crate::issuance::view_flag(args).is_some()
    {
        return Err(usage(
            "a branch read (a scenario or a draft) is not certified yet, and trunk known-at selectors do not apply to its replay",
            "drop --certify, --certificate-out, --as-originally-reported, --as-issued-to, --as-reported-in, --as-currently-stated and any known-at, --before or --after selector, or read trunk without --branch",
        ));
    }
    let replay = if let Some(name) = draft {
        let reader = match bound {
            Some(capability) => capability.clone(),
            None => {
                let mut ops = vec!["read"];
                ops.extend(args.flag_all("--grant"));
                Capability::embedded(principal(args), &ops).map_err(|e| {
                    usage(
                        e.to_string(),
                        "--grant takes a registered op name; `fa capabilities --json` lists them",
                    )
                })?
            }
        };
        let head = book.head()?;
        book.rehearse_draft_at(reader.holder(), &reader, name, head)??
            .0
    } else if let Some(name) = scenario {
        book.materialize_scenario(name)??.book
    } else {
        return Err(unknown());
    };
    said.borrow_mut().branch = Some(selector.to_string());
    Ok(BookRef::Owned(Box::new(replay)))
}

pub(crate) struct BookSource<'a> {
    books: Books<'a>,
    said: Rc<RefCell<Said>>,
    /// The command's [`Files::cwd`], which its book path is relative to.
    cwd: Option<PathBuf>,
    /// The launch-bound session's capability: every book it opens admits
    /// it as current authority before anything is read or stamped.
    bound: Option<Capability>,
    /// The AccessEvent a read-only bound session's command owes (plan §9.7,
    /// fa-7dw): committed on the first open, after admission and before the
    /// handler observes anything.
    access: Option<fa::access_log::AccessRecord>,
}

impl BookSource<'_> {
    /// The book directory and key file `args` name, resolved as `open`
    /// resolves them, without opening anything.
    pub(crate) fn locate(&self, args: &Args) -> Result<(PathBuf, PathBuf), Fail> {
        let dir = self.books.dir_for(args, self.cwd.as_deref())?;
        if let Books::Held { dir: held, .. } = &self.books {
            if !same_dir(&dir, held) {
                return Err(usage(
                    format!("this fad serves {}, not {}", held.display(), dir.display()),
                    format!(
                        "--book {} (or run the command directly against its own book)",
                        held.display()
                    ),
                ));
            }
            return Ok((held.clone(), held.join("book.keys")));
        }
        let keys = keys_path(args, &dir, self.cwd.as_deref());
        Ok((dir, keys))
    }

    pub(crate) fn open(&mut self, args: &Args) -> Result<BookRef<'_>, Fail> {
        let mut book = self.books.open(args, self.cwd.as_deref())?;
        // A bound session's token is current (not expired, not revoked, its
        // `books` caveat admits this book) before the book is read, its
        // coordinate stamped, or a scenario materialized (doctrine 8). The
        // command's own ops and scope are judged where it reads or writes.
        if let Some(capability) = &self.bound {
            book.admit_current(capability)??;
        }
        if let Some(record) = self.access.take() {
            book.record_access(&record)??;
        }
        let book = select_branch(args, book, &self.said, self.bound.as_ref())?;
        stamp(&self.said, &book)?;
        Ok(book)
    }

    /// Admit a bound token before resolving or reading permitted input paths.
    /// A daemon's existing handle is checked without resolving a book path;
    /// a cold open uses only the trusted launch book and emits no coordinate.
    /// The handler still admits its concrete operation and scope afterward.
    fn admit_current_before_input(
        &mut self,
        args: &Args,
        capability: &Capability,
    ) -> Result<(), Fail> {
        if let Books::Held { book, .. } = &self.books {
            book.admit_current(capability)??;
            return Ok(());
        }
        let book = self.books.open(args, self.cwd.as_deref())?;
        book.admit_current(capability)??;
        Ok(())
    }

    /// Open for native admission without first disclosing the book or its
    /// frontier in an error envelope. Only admitted reads receive a coordinate.
    pub(crate) fn open_admitted(
        &mut self,
        args: &Args,
        admit: impl FnOnce(&mut Book) -> Result<(), Fail>,
    ) -> Result<BookRef<'_>, Fail> {
        let mut book = self.books.open(args, self.cwd.as_deref())?;
        // Authority is admitted on trunk, never on a scenario's replay: a
        // fork never resurrects revoked authority.
        admit(&mut book)?;
        if let Some(record) = self.access.take() {
            book.record_access(&record)??;
        }
        let book = select_branch(args, book, &self.said, self.bound.as_ref())?;
        stamp(&self.said, &book)?;
        Ok(book)
    }

    pub(crate) fn prepare_create(&mut self, dir: &Path) -> Result<(), Fail> {
        match &mut self.books {
            Books::Dir => {
                std::fs::create_dir_all(dir).map_err(|e| BookError::Io(dir.to_path_buf(), e))?;
                Ok(())
            }
            Books::LeasedOnOpen { lease, note, held } => {
                if dir.exists()
                    && !crate::lease::Lease::is_book_dir(dir)
                    && !crate::lease::Lease::is_empty_or_lease_only(dir, lease)
                {
                    return Err(Fail::Environment(format!(
                        "cannot prepare book directory {} for its writer lease: directory is not a book and is not empty",
                        dir.display()
                    )));
                }
                if let Err(error) = std::fs::create_dir_all(dir) {
                    return Err(Fail::Environment(format!(
                        "cannot prepare book directory {} for its writer lease: {error}",
                        dir.display()
                    )));
                }
                if held.is_none() {
                    match crate::lease::Lease::acquire(dir, lease, note) {
                        Ok(acquired) => *held = Some(acquired),
                        Err(error @ crate::lease::LeaseError::Held { .. }) => {
                            return Err(Fail::Refusal(error.refusal(dir)));
                        }
                        Err(error @ crate::lease::LeaseError::Io { .. }) => {
                            return Err(Fail::Environment(format!(
                                "cannot acquire the book's writer lease: {error}"
                            )));
                        }
                    }
                }
                Ok(())
            }
            Books::Held { .. } => Err(usage(
                "`fa book create` makes a new book directory; a daemon serves an existing one",
                "run `fa book create --book <new dir> --name \"My Co\"` without a daemon for that directory",
            )),
        }
    }

    pub(crate) fn is_held(&self) -> bool {
        self.books.is_held()
    }

    pub(crate) fn lease_for_genesis(&mut self, dir: &Path) -> Result<(), Fail> {
        self.books.lease_for_genesis(dir)
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// How a command reads the files and stdin its arguments name, and finds
/// the book (`--book`, `FA_BOOK`) and keys file (`--keys`) it opens:
/// relative to the caller's working directory, which for a daemon request
/// is the client's, never the daemon's.
#[derive(Clone, Debug, Default)]
pub struct Files {
    /// `None`: the process's own working directory.
    pub cwd: Option<PathBuf>,
    pub stdin: Stdin,
}

/// Where an argument `-` reads from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Stdin {
    /// This process's stdin (the `fa` binary).
    #[default]
    Process,
    /// The client's stdin, forwarded in a daemon request.
    Forwarded(Vec<u8>),
    /// A daemon request that forwarded none: a daemon never reads its own
    /// stdin on a client's behalf.
    Missing,
}

/// `path` relative to the caller's working directory `cwd` (`None`: this
/// process's own); an absolute path stays itself. Lexical, reading nothing
/// on disk, so a directory `fa book create` has yet to make resolves like
/// any other. The one resolver for a command's files, book and keys.
fn resolve_in(cwd: Option<&Path>, path: &str) -> PathBuf {
    match cwd {
        Some(cwd) => cwd.join(path),
        None => PathBuf::from(path),
    }
}

impl Files {
    pub(crate) fn resolve(&self, path: &str) -> PathBuf {
        resolve_in(self.cwd.as_deref(), path)
    }

    /// The bytes of `path`, or of stdin when `path` is `-`.
    pub(crate) fn read_bytes(&self, path: &str) -> Result<Vec<u8>, Fail> {
        if path == "-" {
            return match &self.stdin {
                Stdin::Forwarded(bytes) => Ok(bytes.clone()),
                Stdin::Missing => Err(usage(
                    "`-` names stdin, but no stdin reached the daemon",
                    "pipe the document into `fa` (stdin was a terminal), or pass a file path",
                )),
                Stdin::Process => {
                    let mut buf = Vec::new();
                    std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
                        .map_err(|e| usage(format!("stdin: {e}"), "pipe the document to stdin"))?;
                    Ok(buf)
                }
            };
        }
        std::fs::read(self.resolve(path)).map_err(|e| {
            usage(
                format!("{path}: {e}"),
                "pass a readable file, or `-` for stdin",
            )
        })
    }

    pub(crate) fn read_text(&self, path: &str) -> Result<String, Fail> {
        String::from_utf8(self.read_bytes(path)?).map_err(|_| {
            usage(
                format!("{path}: not UTF-8 text"),
                "pass a UTF-8 JSON document",
            )
        })
    }
}

#[derive(Clone, Debug)]
struct DaemonFiles {
    book_dir: PathBuf,
    files_root: Option<PathBuf>,
}

/// Everything a command runs against.
pub(crate) struct Ctx<'a> {
    pub(crate) out: Out,
    pub(crate) books: BookSource<'a>,
    pub(crate) files: Files,
    authority: Option<LaunchAuthority>,
    daemon_files: Option<DaemonFiles>,
}

impl Ctx<'_> {
    pub(crate) fn principal(&self, args: &Args) -> VId {
        self.authority
            .as_ref()
            .map_or_else(|| principal(args), LaunchAuthority::principal_vid)
    }

    pub(crate) fn authority(&self) -> Option<&LaunchAuthority> {
        self.authority.as_ref()
    }

    /// A bound host reuses the launch capability verbatim. The handler's
    /// implied ops exist only on the explicit embedded-owner route.
    pub(crate) fn capability(&self, args: &Args, implied: &[&str]) -> Result<Capability, Fail> {
        if let Some(authority) = &self.authority {
            return Ok(authority.capability().clone());
        }
        let mut ops = implied.to_vec();
        ops.extend(args.flag_all("--grant"));
        Capability::embedded(self.principal(args), &ops).map_err(|e| {
            usage(
                e.to_string(),
                "--grant takes a registered op name; `fa capabilities --json` lists them",
            )
        })
    }
}

/// Run one `fa` command line. `capture` keeps the output for a response
/// frame instead of writing it to stdio. Returns the exit code and, when
/// captured, the output.
pub fn run(argv: &[String], books: Books<'_>, files: Files, capture: bool) -> (u8, Captured) {
    run_scoped(argv, books, files, None, None, capture)
}

/// Run one `fa` command line on a `fad` daemon holding `book` at `dir` (`fa-udti`).
///
/// The client's `client_cwd` is never used to resolve host file reads or writes
/// on the daemon; host file paths require an explicit `--files-root` (`files_root`)
/// and are confined to it.
pub fn run_for_daemon(
    argv: &[String],
    book: &mut Book,
    dir: PathBuf,
    files_root: Option<PathBuf>,
    client_cwd: Option<PathBuf>,
    stdin: Stdin,
    capture: bool,
) -> (u8, Captured) {
    let daemon_files = DaemonFiles {
        book_dir: dir.clone(),
        files_root: files_root.clone(),
    };
    let files = Files {
        cwd: client_cwd,
        stdin,
    };
    run_scoped(
        argv,
        Books::Held { book, dir },
        files,
        None,
        Some(daemon_files),
        capture,
    )
}

/// [`run_for_daemon`] for a request the daemon bound to a holder's issued
/// token (fa-r3q): the session's principal and journaled capability, never
/// the embedded-owner posture or any `--as`/`--grant` in `argv`.
#[allow(clippy::too_many_arguments)]
pub fn run_for_daemon_bound(
    argv: &[String],
    book: &mut Book,
    dir: PathBuf,
    files_root: Option<PathBuf>,
    client_cwd: Option<PathBuf>,
    stdin: Stdin,
    authority: &LaunchAuthority,
    capture: bool,
) -> (u8, Captured) {
    let daemon_files = DaemonFiles {
        book_dir: dir.clone(),
        files_root,
    };
    let files = Files {
        cwd: client_cwd,
        stdin,
    };
    run_scoped(
        argv,
        Books::Held { book, dir },
        files,
        Some(authority),
        Some(daemon_files),
        capture,
    )
}

/// Run under the immutable authority supplied by the host. Hosts opening
/// a directory should use [`crate::entry::fa_with_authority`] for the
/// writer lease as well. This route never self-issues an owner capability.
pub fn run_with_authority(
    argv: &[String],
    books: Books<'_>,
    files: Files,
    authority: &LaunchAuthority,
    capture: bool,
) -> (u8, Captured) {
    run_scoped(argv, books, files, Some(authority), None, capture)
}

fn output_format_from_raw_argv(argv: &[String]) -> OutputFormat {
    let mut format = OutputFormat::Human;
    let mut i = 0;
    while i < argv.len() {
        let arg = argv[i].as_str();
        if arg == "--" {
            break;
        }
        if arg == "--json" || arg == "--format=json" {
            return OutputFormat::Json;
        }
        if arg == "--format=toon" {
            format = OutputFormat::Toon;
        } else if arg == "--format" {
            match argv.get(i + 1).map(String::as_str) {
                Some("json") => return OutputFormat::Json,
                Some("toon") => format = OutputFormat::Toon,
                _ => {}
            }
            i += 1;
        }
        i += 1;
    }
    format
}

fn resolve_output_format(args: &Args) -> Result<OutputFormat, Fail> {
    let formats = args.flag_all("--format");
    if formats.len() > 1 {
        return Err(usage(
            "--format may be supplied at most once",
            "--format json|toon|text (or --json)",
        ));
    }
    let json_switch = args.switch("--json");
    match (json_switch, formats.first().copied()) {
        (false, None) | (false, Some("text" | "human")) => Ok(OutputFormat::Human),
        (true, None) | (false, Some("json")) | (true, Some("json")) => Ok(OutputFormat::Json),
        (false, Some("toon")) => Ok(OutputFormat::Toon),
        (true, Some("toon" | "text" | "human")) => Err(usage(
            "--json and --format disagree",
            "pass one of --json, --format json, --format toon, or --format text",
        )),
        (_, Some(other)) => Err(usage(
            format!("unknown output format `{other}`"),
            "--format json|toon|text (or --json)",
        )),
    }
}

/// The command line with each registered flag alias (`--robot`,
/// `--for-period`, …) spelled as its flag, before anything parses it.
fn apply_flag_aliases(argv: &[String], reg: &Registry) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len());
    let mut rest = argv.iter();
    for a in rest.by_ref() {
        if a == "--" {
            out.push(a.clone());
            break;
        }
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if a.starts_with("--") => (n, Some(v)),
            _ => (a.as_str(), None),
        };
        match reg.flag_alias(name) {
            Some(flag) => {
                out.push(inline.map_or_else(|| flag.to_string(), |v| format!("{flag}={v}")))
            }
            None => out.push(a.clone()),
        }
    }
    out.extend(rest.cloned());
    out
}

/// Plan §15.3 intent inference: a flag within the correction distance of a
/// registered one is corrected when the command only reads (its bound route
/// needs nothing but read or verify), and the run carries a warning naming
/// the correction. A writing command is never corrected: it fails as usage,
/// naming the fix.
fn correct_read_flags(argv: &[String], reg: &Registry) -> (Vec<String>, Vec<String>) {
    let known: Vec<&str> = reg
        .value_flags()
        .into_iter()
        .chain(reg.switches())
        .collect();
    let mut corrected = Vec::with_capacity(argv.len());
    let mut warnings = Vec::new();
    let mut rest = argv.iter();
    for a in rest.by_ref() {
        if a == "--" {
            corrected.push(a.clone());
            break;
        }
        let Some(body) = a.strip_prefix("--") else {
            corrected.push(a.clone());
            continue;
        };
        let (name, inline) = match body.split_once('=') {
            Some((n, v)) => (format!("--{n}"), Some(v)),
            None => (a.clone(), None),
        };
        match (known.contains(&name.as_str()), nearest(&name, &known)) {
            (false, Some(fix)) => {
                warnings.push(format!("`{name}` is not a flag; ran as `{fix}`"));
                corrected.push(inline.map_or_else(|| fix.to_string(), |v| format!("{fix}={v}")));
            }
            _ => corrected.push(a.clone()),
        }
    }
    corrected.extend(rest.cloned());
    if warnings.is_empty() {
        return (corrected, warnings);
    }
    // Read-class is what the command's bound route requires: nothing but
    // read or verify (a certifying `tb --certificate-out` needs produce).
    let reads = args::parse(&corrected, &reg.value_flags(), &reg.switches())
        .ok()
        .and_then(|mut parsed| {
            parsed.positional = reg.expand_alias(&parsed.positional);
            let verb = reg.verb(parsed.positional.first()?)?;
            if let Some(default) = &verb.default_subcommand
                && parsed.positional.len() == 1
            {
                parsed.positional.push(default.clone());
            }
            let (ops, _) = bound_command_rule(&verb.name, &parsed)?;
            Some(
                ops.iter()
                    .all(|op| matches!(op, fa_policy::Op::Read | fa_policy::Op::Verify)),
            )
        })
        .unwrap_or(false);
    if reads {
        (corrected, warnings)
    } else {
        (argv.to_vec(), Vec::new())
    }
}

fn run_scoped(
    argv: &[String],
    books: Books<'_>,
    mut files: Files,
    authority: Option<&LaunchAuthority>,
    daemon_files: Option<DaemonFiles>,
    capture: bool,
) -> (u8, Captured) {
    let reg = match registry() {
        Ok(r) => r,
        Err(fail) => {
            return finish_into(
                Out::new_format(output_format_from_raw_argv(argv), capture)
                    .with_authority(authority),
                Err(fail),
            );
        }
    };
    let aliased = apply_flag_aliases(argv, reg);
    let (argv, corrections) = correct_read_flags(&aliased, reg);
    let argv = argv.as_slice();
    let raw_format = output_format_from_raw_argv(argv);
    let mut args = match args::parse(argv, &reg.value_flags(), &reg.switches()) {
        Ok(a) => a,
        Err(e) => {
            return finish_into(
                Out::new_format(raw_format, capture).with_authority(authority),
                Err(Fail::Usage(e)),
            );
        }
    };
    if let Some(authority) = authority {
        for flag in [
            "--as",
            "--grant",
            "--yes",
            "--book",
            "--keys",
            "--via",
            "--token",
            "--issuer-token",
        ] {
            if args.flags.contains_key(flag) || args.switch(flag) {
                return usage_error_with_authority(
                    argv,
                    format!("{flag} cannot override launch-bound authority"),
                    "identity, authority, book, keys and transport are fixed when the server starts; ask the operator to start a server with the profile you need",
                    authority,
                    capture,
                );
            }
        }
        // Bind parsed fields, not appended argv: a caller's `--` terminator
        // or duplicate flag cannot turn the trusted paths into positionals.
        args.flags.insert(
            "--book".into(),
            vec![authority.book().to_string_lossy().into_owned()],
        );
        if let Some(keys) = authority.keys() {
            args.flags
                .insert("--keys".into(), vec![keys.to_string_lossy().into_owned()]);
        }
    }
    let format = match resolve_output_format(&args) {
        Ok(f) => f,
        Err(fail) => {
            return finish_into(
                Out::new_format(raw_format, capture).with_authority(authority),
                Err(fail),
            );
        }
    };
    let style = Style::resolve(
        format.is_robot(),
        args.switch("--no-color"),
        capture,
        std::io::stdout().is_terminal(),
        |name| std::env::var(name).ok(),
    );
    let out = Out::styled_format(format, capture, style).with_authority(authority);
    for correction in corrections {
        out.warn(correction);
    }
    if authority.is_none() {
        if daemon_files.is_some() {
            // The owner can still revoke through the serving daemon
            // (fa-b295): revocation only removes authority, and while fad
            // holds the writer lease no other route can perform it, since
            // a launch token never carries issue_capability.
            let grants = args.flag_all("--grant");
            let revocation = args.positional.first().map(String::as_str) == Some("capability")
                && args.positional.get(1).map(String::as_str) == Some("revoke")
                && !grants.is_empty()
                && grants.iter().all(|op| *op == "issue_capability");
            let override_flag = ["--as", "--grant"].into_iter().find(|flag| {
                (args.flags.contains_key(*flag) || args.switch(flag))
                    && !(*flag == "--grant" && revocation)
            });
            if let Some(flag) = override_flag {
                let message = match flag {
                    "--as" => {
                        "`--as` is not admitted on the daemon path: fad authenticates callers by capability token, never by unverified `--as` flag"
                    }
                    "--grant" => {
                        "`--grant` is not admitted on the daemon path: fad binds caller authority from a capability token, never from unverified per-request grants"
                    }
                    _ => unreachable!("the daemon override list is closed"),
                };
                return finish_into(
                    out,
                    Err(Fail::Refusal(Refusal::new(
                        fa_journal::refusal::code::CAPABILITY,
                        fa_journal::exit::SAFETY,
                        message,
                        "plan §14.2, §15.3 (daemon caller authentication; fa-r3q)",
                        "present a token: fa capability issue --holder <principal> --out <file> … then fa --token <file> …",
                    ))),
                );
            }
        }
        out.said.borrow_mut().owner_principal =
            Some(args.flag("--as").unwrap_or("operator").to_string());
    }
    let access = match authority.map(|authority| access_record(authority, &args)) {
        Some(Err(fail)) => return finish_into(out, Err(fail)),
        Some(Ok(record)) => record,
        None => None,
    };
    let books = BookSource {
        books,
        said: Rc::clone(&out.said),
        cwd: files.cwd.clone(),
        bound: authority.map(|authority| authority.capability().clone()),
        access,
    };
    if let Some(daemon) = &daemon_files {
        // The daemon never trusts a client working directory outside --files-root;
        // relative paths resolve only under --files-root (or a validated subdirectory
        // within it) (fa-udti).
        files.cwd = match (&daemon.files_root, &files.cwd) {
            (Some(root), Some(client_cwd)) => client_cwd
                .to_str()
                .and_then(|raw| {
                    crate::authority::resolve_in_daemon_files_root(
                        root,
                        &daemon.book_dir,
                        raw,
                        false,
                    )
                    .ok()
                })
                .filter(|path| path.is_dir())
                .or_else(|| Some(root.clone())),
            (Some(root), None) => Some(root.clone()),
            (None, _) => None,
        };
    }
    if let Some(root) = authority.and_then(LaunchAuthority::files) {
        files.cwd = Some(root.to_path_buf());
    }
    let mut ctx = Ctx {
        out,
        books,
        files,
        authority: authority.cloned(),
        daemon_files,
    };
    let result = dispatch(&mut ctx, reg, &args);
    finish_into(ctx.out, result)
}

fn finish_into(out: Out, result: Result<(), Fail>) -> (u8, Captured) {
    let code = finish(&out, result);
    (code, out.into_captured())
}

/// A refusal, rendered exactly as a command's would be: for hosts (the
/// front door, the daemon) that must refuse before any command runs.
#[must_use]
pub fn refuse(argv: &[String], refusal: Refusal, capture: bool) -> (u8, Captured) {
    host_failure(argv, Fail::Refusal(refusal), capture)
}

/// A host refusal that retains the launch binding before a book is opened.
#[must_use]
pub fn refuse_with_authority(
    argv: &[String],
    refusal: Refusal,
    authority: &LaunchAuthority,
    capture: bool,
) -> (u8, Captured) {
    host_failure_with_authority(argv, Fail::Refusal(refusal), authority, capture)
}

/// A bound host's usage error, including parsing and forbidden overrides.
#[must_use]
pub fn usage_error_with_authority(
    argv: &[String],
    message: impl Into<String>,
    fix: impl Into<String>,
    authority: &LaunchAuthority,
    capture: bool,
) -> (u8, Captured) {
    host_failure_with_authority(argv, usage(message, fix), authority, capture)
}

/// A bound host's environment error; it never falls back to owner execution.
#[must_use]
pub fn environment_error_with_authority(
    argv: &[String],
    message: String,
    authority: &LaunchAuthority,
    capture: bool,
) -> (u8, Captured) {
    host_failure_with_authority(argv, Fail::Environment(message), authority, capture)
}

fn host_failure_with_authority(
    argv: &[String],
    fail: Fail,
    authority: &LaunchAuthority,
    capture: bool,
) -> (u8, Captured) {
    let format = output_format_from_raw_argv(argv);
    finish_into(
        Out::new_format(format, capture).with_authority(Some(authority)),
        Err(fail),
    )
}

/// A usage error (exit 2) raised by a host before any command runs.
#[must_use]
pub fn usage_error(
    argv: &[String],
    message: impl Into<String>,
    fix: impl Into<String>,
    capture: bool,
) -> (u8, Captured) {
    host_failure(argv, usage(message, fix), capture)
}

/// An environment error (exit 4) raised by a host before any command runs.
#[must_use]
pub fn environment_error(argv: &[String], message: String, capture: bool) -> (u8, Captured) {
    host_failure(argv, Fail::Environment(message), capture)
}

/// A book that could not be opened (its exit class: 4 environment or 5
/// foundation), reported by a host before any command runs.
#[must_use]
pub fn book_error(argv: &[String], error: BookError, capture: bool) -> (u8, Captured) {
    host_failure(argv, Fail::Book(error), capture)
}

/// A foundation failure (exit 5) raised by a host before any command runs.
#[must_use]
pub fn foundation_error(argv: &[String], message: String, capture: bool) -> (u8, Captured) {
    host_failure(argv, Fail::Internal(message), capture)
}

fn host_failure(argv: &[String], fail: Fail, capture: bool) -> (u8, Captured) {
    let format = output_format_from_raw_argv(argv);
    finish_into(Out::new_format(format, capture), Err(fail))
}

fn registry() -> Result<&'static Registry, Fail> {
    verbs::registry().map_err(|e| Fail::Internal(format!("the embedded verb registry: {e}")))
}

/// An exit code's class: its name in exit_codes.toml (`usage`, `refusal`,
/// `environment`, `foundation`, `conflict`, `safety`, `verification`). An
/// exit the registry lacks is spelled `exit-<n>`, never a guessed class.
fn exit_class(exit: u8) -> String {
    fa_registry::ExitCodes::embedded()
        .ok()
        .and_then(|codes| {
            codes
                .rows
                .into_iter()
                .find(|row| row.code == exit)
                .map(|row| row.name)
        })
        .unwrap_or_else(|| format!("exit-{exit}"))
}

/// The AccessEvent a bound session's command owes, when its capability is a
/// read-only Human one: every op within read, produce and verify, as the
/// Auditor, Regulator, Investigator and Production templates are (plan §9.7,
/// §14.4; fa-7dw). Agent sessions are internal readers, left to the plan's
/// sampled policy. The request digest covers the command's positional words,
/// flags and switches, never the host's book or key paths. A session that
/// cannot state its record is refused, never served unrecorded.
fn access_record(
    authority: &LaunchAuthority,
    args: &Args,
) -> Result<Option<fa::access_log::AccessRecord>, Fail> {
    let capability = authority.capability();
    let read_only = capability.profile() == fa_policy::Profile::Human
        && capability.ops().iter().all(|op| {
            matches!(
                op,
                fa_policy::Op::Read | fa_policy::Op::Produce | fa_policy::Op::Verify
            )
        });
    let Some(verb) = args.positional.first() else {
        return Ok(None);
    };
    if !read_only {
        return Ok(None);
    }
    let commitment = capability
        .commitment()
        .map_err(|e| Fail::Internal(format!("the session capability has no commitment: {e}")))?;
    let mut ops: Vec<String> = capability
        .ops()
        .iter()
        .map(|op| op.name().to_string())
        .collect();
    ops.sort();
    ops.dedup();
    let command = match (registry()?.verb(verb), args.positional.get(1)) {
        (Some(v), Some(sub)) if v.subcommands.contains(sub) => format!("{verb} {sub}"),
        _ => verb.clone(),
    };
    let mut request: Vec<String> = args.positional.clone();
    for (flag, values) in &args.flags {
        if flag == "--book" || flag == "--keys" {
            continue;
        }
        for value in values {
            request.push(flag.clone());
            request.push(value.clone());
        }
    }
    let mut switches = args.switches.clone();
    switches.sort();
    request.extend(switches);
    Ok(Some(fa::access_log::AccessRecord {
        principal: authority.principal_vid(),
        principal_name: authority.principal().to_string(),
        capability_commitment: commitment,
        ops,
        command,
        request_digest: fa::access_log::request_digest(&request),
    }))
}

/// The verdict of a command: success, or exactly one `error` event (plan
/// Appendix D: `class`, `exit`, `refusal_id`) on stdout in robot mode and
/// one diagnostic on stderr.
fn finish(out: &Out, result: Result<(), Fail>) -> u8 {
    struct Failure {
        exit: u8,
        refusal_id: Option<&'static str>,
        message: String,
        cite: Option<String>,
        fix: Option<String>,
        detail: Json,
        diag: String,
        /// The Appendix D refusal object, for a catalog refusal.
        refusal: Json,
    }
    // A catalog refusal's Appendix D object, bound to the coordinate the
    // command reached (null before a book opened).
    let appendix_d = |r: &Refusal| -> Json {
        let Ok(reg) = registry() else {
            return Json::Null;
        };
        let said = out.said.borrow();
        let issued = crate::refusal_object::Issued {
            book: said.at.as_ref().map(|a| a.book.as_str()),
            known_at: said.at.as_ref().map(|a| a.known_at.0),
        };
        crate::refusal_object::render(reg, r, &issued)
    };
    let refused = |mut r: Refusal, detail: Json| {
        if out.is_bound() && r.fix.contains("--grant") {
            r.fix = "identity and authority are fixed when the server starts; ask the operator to start a server with the profile and operations you need".to_string();
        }
        // A launch-bound session cannot add --yes or --grant.
        if out.is_bound() && !r.rerun_args().is_empty() {
            r = r.rerun_with(Vec::new());
        }
        Failure {
            exit: r.exit,
            refusal_id: Some(r.code),
            diag: format!("refused {r}"),
            refusal: appendix_d(&r),
            message: r.message,
            cite: Some(r.cite),
            fix: Some(r.fix),
            detail,
        }
    };
    let failure = match result {
        Ok(()) => return exit::SUCCESS,
        Err(Fail::Usage(e)) => Failure {
            exit: exit::USAGE,
            refusal_id: None,
            diag: format!("usage: {}\n  fix: {}", e.message, e.fix),
            message: e.message,
            cite: None,
            fix: Some(e.fix),
            detail: Json::Null,
            refusal: Json::Null,
        },
        Err(Fail::Refusal(r)) => refused(r, Json::Null),
        Err(Fail::RefusalDetail(boxed)) => {
            let (r, detail) = *boxed;
            refused(r, detail)
        }
        Err(Fail::Book(e)) => {
            if let Some(r) = e.refusal() {
                Failure {
                    exit: r.exit,
                    refusal_id: Some(r.code),
                    diag: format!("refused {r}"),
                    refusal: appendix_d(&r),
                    message: r.message,
                    cite: Some(r.cite),
                    fix: Some(r.fix),
                    detail: Json::Null,
                }
            } else {
                let code = e.exit();
                let fix = match &e {
                    BookError::Lantern(le) => le.fix_hint(),
                    _ => None,
                };
                Failure {
                    exit: code,
                    refusal_id: None,
                    diag: format!("error (exit {code}): {e}"),
                    message: e.to_string(),
                    cite: None,
                    fix,
                    detail: Json::Null,
                    refusal: Json::Null,
                }
            }
        }
        Err(Fail::Verification {
            message,
            detail,
            cite,
            fix,
        }) => Failure {
            exit: exit::VERIFICATION,
            refusal_id: None,
            diag: format!(
                "verification failed (exit {}): {message}{}",
                exit::VERIFICATION,
                fix.as_ref()
                    .map_or_else(String::new, |hint| format!("\n  fix: {hint}"))
            ),
            message,
            cite,
            fix,
            detail,
            refusal: Json::Null,
        },
        Err(Fail::Internal(message) | Fail::Io(message)) => Failure {
            exit: exit::FOUNDATION,
            refusal_id: None,
            diag: format!("error (exit {}): {message}", exit::FOUNDATION),
            message,
            cite: None,
            fix: None,
            detail: Json::Null,
            refusal: Json::Null,
        },
        Err(Fail::Environment(message)) => Failure {
            exit: exit::ENVIRONMENT,
            refusal_id: None,
            diag: format!("error (exit {}): {message}", exit::ENVIRONMENT),
            message,
            cite: None,
            fix: None,
            detail: Json::Null,
            refusal: Json::Null,
        },
    };
    out.event(
        "error",
        vec![
            ("class", s(exit_class(failure.exit))),
            ("exit", Json::Int(i128::from(failure.exit))),
            ("refusal_id", failure.refusal_id.map_or(Json::Null, s)),
            ("message", s(&failure.message)),
            ("cite", failure.cite.map_or(Json::Null, s)),
            ("fix", failure.fix.map_or(Json::Null, s)),
            ("detail", failure.detail),
            ("refusal", failure.refusal),
        ],
        "",
    );
    out.diag(failure.diag);
    failure.exit
}

/// Format a human-readable version banner including `franken-stack.lock`
/// foundation revisions and the binary's embedded registry epochs (`fa-eqk`).
#[must_use]
pub fn version_text(binary: &str) -> String {
    match fa_registry::FoundationStack::embedded() {
        Ok(stack) => format!(
            "{binary} {VERSION} (foundations: {}; registries: schema_v={}, epochs={})",
            stack.foundations_summary(),
            stack.schema_version,
            stack.registry_epochs.len()
        ),
        Err(_) => format!("{binary} {VERSION}"),
    }
}

/// Structured JSON version metadata with `franken-stack.lock` foundation
/// revisions and canonical registry epoch digests (`fa-eqk`).
#[must_use]
pub fn version_metadata_json(binary: &str) -> Json {
    match fa_registry::FoundationStack::embedded() {
        Ok(stack) => {
            let foundations = Json::Arr(
                stack
                    .foundations
                    .iter()
                    .map(|f| {
                        obj(vec![
                            ("name", s(&f.name)),
                            ("source", s(&f.source)),
                            ("rev", f.rev.as_deref().map_or(Json::Null, s)),
                            ("version", s(&f.version)),
                            ("checksum", f.checksum.as_deref().map_or(Json::Null, s)),
                            ("role", s(&f.role)),
                        ])
                    })
                    .collect(),
            );
            let registry_epochs = Json::Arr(
                stack
                    .registry_epochs
                    .iter()
                    .map(|e| {
                        let digest = fa_model::domain_digest(
                            b"fa:registry-canonical-digest:v1",
                            &[&e.canonical_bytes],
                        );
                        obj(vec![
                            ("name", s(e.name)),
                            ("schema_version", Json::Int(e.schema_version)),
                            ("canonical_digest", s(hex(&digest))),
                        ])
                    })
                    .collect(),
            );
            obj(vec![
                ("binary", s(binary)),
                ("version", s(VERSION)),
                ("stack_schema_version", Json::Int(stack.schema_version)),
                ("stack_taken_on", s(&stack.taken_on)),
                ("foundations", foundations),
                ("registry_epochs", registry_epochs),
            ])
        }
        Err(_) => obj(vec![("binary", s(binary)), ("version", s(VERSION))]),
    }
}

fn dispatch(ctx: &mut Ctx<'_>, reg: &Registry, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    if args.switch("--version") {
        let text = version_text("fa");
        out.event("version", vec![("version", s(VERSION))], &text);
        return Ok(());
    }
    // An alias expands in the verb position (plan §15.3: the spellings agents
    // try first). It is a registered synonym, never a guessed correction.
    let mut expanded = args.clone();
    expanded.positional = reg.expand_alias(&args.positional);
    let args = &expanded;
    let Some(word) = args.positional.first() else {
        check_flags(reg, None, args)?;
        if args.switch("--help") {
            return emit_help(out, reg, None);
        }
        let here = here(args, ctx.files.cwd.as_deref(), reg);
        let text = format!("{}{}", here.text(), triage_text());
        out.event(
            "triage",
            vec![
                ("version", s(VERSION)),
                ("text", s(&text)),
                (
                    "book",
                    here.book
                        .as_ref()
                        .map_or(Json::Null, |dir| s(dir.display().to_string())),
                ),
                ("daemon", here.daemon.map_or(Json::Null, s)),
            ],
            text.trim_end(),
        );
        return Ok(());
    };
    let Some(verb) = reg.verb(word) else {
        let mut known: Vec<&str> = reg.verbs.iter().map(|v| v.name.as_str()).collect();
        known.extend(reg.aliases.iter().map(|a| a.name.as_str()));
        return Err(usage(
            format!("unknown command `{word}`"),
            match nearest(word, &known) {
                Some(n) => format!("did you mean `fa {n}`?"),
                None => "run `fa --help`".to_string(),
            },
        ));
    };
    // A bare verb with a registered default subcommand runs it (plan §15.3:
    // `fa gl` is `fa gl detail`).
    let defaulted;
    let args = match &verb.default_subcommand {
        Some(default) if args.positional.len() == 1 && !args.switch("--help") => {
            let mut a = args.clone();
            a.positional.push(default.clone());
            defaulted = a;
            &defaulted
        }
        _ => args,
    };
    check_flags(reg, Some(verb), args)?;
    if args.flag("--issuer-token").is_some()
        && (verb.name != "capability"
            || args.positional.get(1).map(String::as_str) != Some("issue"))
    {
        return Err(usage(
            "--issuer-token is only valid for capability issue",
            "fa capability issue --issuer-token <existing-token-file> --holder <principal> --profile agent|human --op <op>... --out <new-file>",
        ));
    }
    if args.switch("--help") {
        return emit_help(out, reg, Some(verb));
    }
    if !verb.subcommands.is_empty() {
        let joined = verb.subcommands.join("|");
        match args.positional.get(1) {
            Some(sub) if verb.subcommands.contains(sub) => {}
            Some(sub) => {
                return Err(usage(
                    format!("`fa {}` has no subcommand `{sub}`", verb.name),
                    match nearest(
                        sub,
                        &verb
                            .subcommands
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                    ) {
                        Some(n) => format!("did you mean `fa {} {n}`?", verb.name),
                        None => format!("fa {} {joined}", verb.name),
                    },
                ));
            }
            None => {
                return Err(usage(
                    format!("`fa {}` needs a subcommand: {joined}", verb.name),
                    format!("fa {} {joined} (see `fa {} --help`)", verb.name, verb.name),
                ));
            }
        }
    }
    // Authority before confirmation: a bound command the surface admits but
    // this capability cannot run (a missing operation, a scope caveat) is
    // refused for that, never asked to confirm what it could not do. A
    // command the surface does not admit keeps the confirmation refusal,
    // which names how to prepare it instead.
    let admitted = ctx.authority.is_none() || bound_command_rule(&verb.name, args).is_some();
    if admitted {
        admit_bound_command(ctx, verb, args)?;
    }
    gate_from_argv(out, reg, verb, args, ctx.authority.as_ref())?;
    if !admitted {
        admit_bound_command(ctx, verb, args)?;
    }
    if !host_path_arguments(&verb.name, args).is_empty()
        && let Some(authority) = &ctx.authority
        // Without a files root, the next check rejects the request from its
        // arguments alone. Opening a cold book solely for that refusal would
        // observe keys or take a lease for a path that can never be admitted.
        // An already-held book still checks revocation before this refusal.
        && (authority.files().is_some() || ctx.books.is_held())
    {
        ctx.books
            .admit_current_before_input(args, authority.capability())?;
    }
    admit_bound_files(ctx, verb, args)?;
    admit_daemon_files(ctx, verb, args)?;
    let handler = HANDLERS
        .iter()
        .find(|(name, _)| *name == verb.name)
        .map(|(_, h)| *h)
        .ok_or_else(|| {
            Fail::Internal(format!(
                "registered verb `{}` has no handler in this build",
                verb.name
            ))
        })?;
    handler(ctx, args)
}

/// The current period planner returns before every publication. Only this
/// concrete handler path may bypass dangerous-commit gating; an arbitrary
/// `--plan` or `--plan-out` argument is never an MCP confirmation.
fn period_plan_only(verb: &str, args: &Args) -> bool {
    verb == "period"
        && matches!(
            args.positional.get(1).map(String::as_str),
            Some("open" | "soft-close" | "close" | "lock" | "reopen")
        )
        && (args.flag("--plan-out").is_some() || args.switch("--dry-run"))
        && args.flag("--plan").is_none()
        && args.flag_all("--approval").is_empty()
}

/// These concrete handlers prepare and abort the real posting transaction.
/// No other verb may use a dry-run flag to bypass its confirmation gate.
fn post_plan_only(verb: &str, args: &Args) -> bool {
    (matches!(
        verb,
        "post"
            | "allocate"
            | "settle"
            | "reverse"
            | "reclass"
            | "reserve"
            | "resolve"
            | "invoice"
            | "bill"
            | "receipt"
            | "payment"
            | "accrue"
            | "defer"
            | "batch"
            | "post-reserve"
            | "void-reserve"
            | "replace"
    ) || (verb == "close" && args.positional.get(1).map(String::as_str) == Some("year-end"))
        || (verb == "fx" && args.positional.get(1).map(String::as_str) == Some("revalue")))
        && (args.switch("--dry-run")
            || args.switch("--review-only")
            || args.flag("--review-out").is_some())
}

/// `fa recover <target> --dry-run` derives and releases its prepared changes
/// without publishing; only publication needs confirmation.
fn recovery_preview_only(verb: &str, args: &Args) -> bool {
    verb == "recover" && args.switch("--dry-run")
}

/// The capability operations a launch-bound session (MCP, `fa --token`, fad
/// tokens) must hold to run this command: the first `[[bound]]` rule of
/// `registries/verbs.toml` that decides it (plan §15.1: one verb registry
/// drives every surface; fa-mg2j). `None`: no rule does, so the command is
/// not admitted on the bound route.
#[must_use]
pub fn bound_command_ops(verb: &str, args: &Args) -> Option<&'static [fa_policy::Op]> {
    bound_command_rule(verb, args).map(|(ops, _)| ops)
}

/// The deciding `[[bound]]` rule's ops, and whether the command judges the
/// session's scope caveats against what it reaches (`reach = "judged"`).
pub(crate) fn bound_command_rule(
    verb: &str,
    args: &Args,
) -> Option<(&'static [fa_policy::Op], bool)> {
    let reg = crate::verbs::registry().ok()?;
    let present = |flag: &str| args.switch(flag) || !args.flag_all(flag).is_empty();
    let value = |flag: &str| args.flag(flag).map(str::to_string);
    let (index, rule) = reg.bound_rule(
        verb,
        args.positional.get(1).map(String::as_str),
        args.positional.get(2).map(String::as_str),
        &present,
        &value,
    )?;
    Some((bound_rule_ops().get(index)?.as_deref()?, rule.judged))
}

/// A bound command that reads a book and does not judge its own reach
/// reaches the whole book at the head (doctrine 8, fa-0x0), so a token
/// carrying any scope caveat is refused before the book is opened, never
/// answered with a filtered result.
fn bound_scope_refusal(
    capability: &Capability,
    ops: &[fa_policy::Op],
    judged: bool,
    command: &str,
) -> Result<(), Refusal> {
    if judged || ops.is_empty() {
        return Ok(());
    }
    fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None).map_err(|denial| {
        let mut refusal = fa_journal::policy::refusal(&denial);
        let judging: std::collections::BTreeSet<&str> = crate::verbs::registry()
            .map(|reg| {
                reg.bound
                    .iter()
                    .filter(|rule| rule.judged)
                    .flat_map(|rule| rule.verbs.iter().map(String::as_str))
                    .collect()
            })
            .unwrap_or_default();
        refusal.message = format!(
            "`{command}` reaches the whole book at its head: {}",
            refusal.message
        );
        refusal.fix = format!(
            "a scoped capability runs only the commands that judge their own reach (fa {}); ask the book's steward for a capability without scope caveats to run `{command}`",
            judging.into_iter().collect::<Vec<_>>().join(", fa ")
        );
        refusal
    })
}

/// Each `[[bound]]` rule's ops as `fa_policy::Op`s, resolved once. A rule
/// naming an op this build lacks resolves to `None`: its command is refused,
/// never admitted on a partial set.
fn bound_rule_ops() -> &'static [Option<Vec<fa_policy::Op>>] {
    static OPS: std::sync::OnceLock<Vec<Option<Vec<fa_policy::Op>>>> = std::sync::OnceLock::new();
    OPS.get_or_init(|| {
        crate::verbs::registry().map_or_else(
            |_| Vec::new(),
            |reg| {
                reg.bound
                    .iter()
                    .map(|rule| {
                        rule.ops
                            .iter()
                            .map(|name| fa_policy::Op::from_name(name))
                            .collect()
                    })
                    .collect()
            },
        )
    })
}

/// Whether a concrete command is admissible under `authority` on the
/// launch-bound surface (including dangerous-operation confirmation gating and
/// Agent trunk-monetary restrictions).
pub fn bound_command_admissible(
    reg: &Registry,
    verb: &str,
    args: &Args,
    authority: &LaunchAuthority,
) -> Result<&'static [fa_policy::Op], String> {
    let sub = reg
        .verb(verb)
        .filter(|v| !v.subcommands.is_empty())
        .and_then(|_| args.positional.get(1).map(String::as_str));
    if !period_plan_only(verb, args) && !post_plan_only(verb, args) {
        for d in reg.dangerous_for(verb, sub) {
            let applies = match &d.condition {
                Condition::Always => true,
                Condition::Grant(op) => {
                    fa_policy::Op::from_name(op).is_some_and(|op| authority.capability().holds(op))
                }
                Condition::Voids | Condition::ExistingCells => false,
            };
            if applies {
                return Err(format!(
                    "`{}` requires independent confirmation unavailable over MCP (FA-REF-007)",
                    command_name(verb, sub)
                ));
            }
        }
    }
    let Some((required, judged)) = bound_command_rule(verb, args) else {
        return Err(format!(
            "`{}` is not admitted by the launch-bound MCP command surface",
            command_name(verb, sub)
        ));
    };
    for op in required {
        if !authority.capability().holds(*op) {
            return Err(format!(
                "`{}` requires `{op}`, which the launch capability does not hold",
                command_name(verb, sub)
            ));
        }
    }
    if let Err(refusal) = bound_scope_refusal(
        authority.capability(),
        required,
        judged,
        &command_name(verb, sub),
    ) {
        return Err(format!("{} ({})", refusal.message, refusal.code));
    }
    // The typed documents (fa invoice, bill, receipt, payment) post through
    // fa post's own path, so they are trunk posts like it. So does a
    // reclassification.
    let is_monetary_trunk_post = matches!(
        verb,
        "post"
            | "commit"
            | "reverse"
            | "reclass"
            | "reserve"
            | "resolve"
            | "invoice"
            | "bill"
            | "receipt"
            | "payment"
            | "accrue"
            | "defer"
            | "batch"
            | "post-reserve"
            | "void-reserve"
            | "replace"
    ) || (matches!(verb, "allocate" | "settle")
        && sub != Some("approve")
        && !args.switch("--approve"));
    // An Agent may rehearse a trunk post (plan §15.3): the kernel admits the
    // dry run and its plan binds the Agent's capability, so no one can commit
    // it. Allocation and settlement plans keep their own planners and
    // remain refused.
    // It may also plan the post into its draft (plan §15.2): a draft record
    // is not a trunk entry, and only a Human holding `approve` promotes it.
    // Or run it in a scenario, which never posts to trunk at all.
    let agent_rehearsal = matches!(
        verb,
        "post"
            | "reverse"
            | "reclass"
            | "reserve"
            | "resolve"
            | "invoice"
            | "bill"
            | "receipt"
            | "payment"
            | "accrue"
            | "defer"
            | "batch"
            | "post-reserve"
            | "void-reserve"
            | "replace"
    ) && (args.switch("--dry-run")
        || args.flag("--draft").is_some()
        || args.flag("--scenario").is_some());
    if authority.profile() == crate::authority::LaunchProfile::Agent
        && is_monetary_trunk_post
        && !agent_rehearsal
    {
        return Err(format!(
            "`{}` writes or plans monetary entries on trunk, which the Agent profile cannot perform (FA-REF-013)",
            command_name(verb, sub)
        ));
    }
    Ok(required)
}

/// Admit the concrete operation before handlers read input files or the
/// book. Legacy facade mutations without a caller capability remain owner
/// operations. Report certificates and derived register caches are metadata,
/// not accounting entries; their actual dangerous rewrites are gated too.
fn admit_bound_command(ctx: &Ctx<'_>, verb: &Verb, args: &Args) -> Result<(), Fail> {
    let Some(authority) = &ctx.authority else {
        return Ok(());
    };
    let sub = args.positional.get(1).map(String::as_str);
    let Some((required, judged)) = bound_command_rule(&verb.name, args) else {
        return Err(Refusal::new(
            fa_journal::refusal::code::CAPABILITY,
            exit::SAFETY,
            format!(
                "`{}` is not admitted by the launch-bound MCP command surface",
                command_name(&verb.name, sub)
            ),
            "plan §14.2–§14.4; fa-23r (authority before observation)",
            "ask the operator to perform this owner operation; document intake derives provenance grade from the launch capability (fa-vwf), and period lock/reopen can be prepared with --plan-out",
        )
        .into());
    };
    for op in required {
        fa_policy::require(authority.capability(), *op, &command_name(&verb.name, sub))
            .map_err(|denial| {
                let mut refusal = fa_journal::policy::refusal(&denial);
                refusal.fix = "identity and authority are fixed when the server starts; ask the operator to start a server with the profile and operations you need".into();
                Fail::Refusal(refusal)
            })?;
    }
    bound_scope_refusal(
        authority.capability(),
        required,
        judged,
        &command_name(&verb.name, sub),
    )?;
    Ok(())
}

/// What a command does with a host path one of its arguments names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostPath {
    /// A new file the command writes; its leaf may not exist yet.
    Output,
    /// Content a flag reads from the file (`--intent`, `--plan`, `--policy`,
    /// `--audited`, `--file`, `--replace-with`, `--issuer-token`,
    /// `--privilege`).
    Content,
    /// A review event read from the file.
    Review,
    /// An input file of `fa document import run`.
    ImportRun,
    /// An input file: a positional chart, account, party, instrument, entity,
    /// statement, document, certificate, rule or export (a file, or an ADS
    /// package directory), a saved-certificate source flag
    /// (`--before-certificate`, `--after-certificate`, `--from-diff`,
    /// `--from-source`, `--aging-certificate`, `--control-certificate`), or a
    /// rule's golden corpus (`--golden`, a file or directory).
    Input,
}

/// Every host path a command line names, in argument order within each kind.
/// Both containment checks (a launch-bound session's `--files` root and
/// fad's `--files-root`) walk this one list, so a file argument cannot be
/// confined on one route and read unconfined on the other. Stdin (`-`), a
/// review given as inline hex and a retained `C:<oid>` are not paths and are
/// left out; an output flag is listed whatever its value.
fn host_path_arguments<'a>(verb: &str, args: &'a Args) -> Vec<(&'static str, &'a str, HostPath)> {
    let mut paths = Vec::new();
    for flag in [
        "--plan-out",
        "--certificate-out",
        "--out",
        "--output",
        "--workpaper-out",
        "--review-out",
        "--receipt-out",
    ] {
        if let Some(value) = args.flag(flag) {
            paths.push((flag, value, HostPath::Output));
        }
    }
    for flag in [
        "--intent",
        "--from-json",
        "--plan",
        "--policy",
        "--audited",
        "--file",
        "--replace-with",
        "--issuer-token",
        "--privilege",
    ] {
        for value in args.flag_all(flag) {
            if value != "-" {
                paths.push((flag, value, HostPath::Content));
            }
        }
    }
    for flag in [
        "--before-certificate",
        "--after-certificate",
        "--from-diff",
        "--from-source",
        "--aging-certificate",
        "--control-certificate",
        "--golden",
    ] {
        for value in args.flag_all(flag) {
            let digits = value.strip_prefix("C:").unwrap_or(value);
            let retained = digits.len() == 64 && digits.bytes().all(|b| b.is_ascii_hexdigit());
            if value != "-" && !retained {
                paths.push((flag, value, HostPath::Input));
            }
        }
    }
    for value in args.flag_all("--review") {
        let is_hex = !value.is_empty()
            && value.len() % 2 == 0
            && value.bytes().all(|b| b.is_ascii_hexdigit());
        if value != "-" && !is_hex {
            paths.push(("--review", value, HostPath::Review));
        }
    }
    let sub = args.positional.get(1).map(String::as_str);
    // A custom calendar's period list (`fa case` uses --periods for period
    // codes, so only book create reads it as a file).
    if verb == "book"
        && sub == Some("create")
        && let Some(value) = args.flag("--periods")
        && value != "-"
    {
        paths.push(("--periods", value, HostPath::Content));
    }
    if verb == "document"
        && sub == Some("import")
        && args.positional.get(2).map(String::as_str) == Some("run")
    {
        for p in args.positional.iter().skip(3) {
            if p != "-" {
                paths.push(("file", p.as_str(), HostPath::ImportRun));
            }
        }
    }
    let input = match (verb, sub) {
        ("chart" | "bank", Some("import"))
        | ("document", Some("add"))
        | ("chart", Some("open"))
        | ("party" | "instrument" | "entity", Some("add"))
        | ("certificate", Some("status"))
        | ("finding", Some("replay"))
        // A Canon rule's source (fa-c34).
        | ("rule", Some("check" | "propose" | "eval" | "backtest" | "test")) => {
            args.positional.get(2)
        }
        ("replay", _) => args.positional.get(1),
        // The exported file, or the ADS package directory.
        ("verify", Some("export")) => args.positional.get(3),
        _ => None,
    };
    if let Some(input) = input {
        let digits = input.strip_prefix("C:").unwrap_or(input);
        let retained = matches!(verb, "replay" | "certificate")
            && digits.len() == 64
            && digits.bytes().all(|byte| byte.is_ascii_hexdigit());
        if input != "-" && !retained {
            paths.push(("file", input.as_str(), HostPath::Input));
        }
    }
    paths
}

/// Bound hosts receive content through forwarded stdin unless launched with an
/// explicit `--files <dir>` containment root. Caller paths outside `--files`
/// never become host reads or writes; the configured book and keys are
/// separate, trusted launch inputs.
fn admit_bound_files(ctx: &Ctx<'_>, verb: &Verb, args: &Args) -> Result<(), Fail> {
    let Some(authority) = &ctx.authority else {
        return Ok(());
    };
    let check_path = |argument: &str, value: &str, allow_missing_leaf: bool, fix: &str| {
        if authority.files().is_none() {
            return Err(usage(
                format!("{argument} cannot name a host filesystem path in a launch-bound request"),
                fix,
            ));
        }
        authority
            .resolve_in_files_root(value, allow_missing_leaf)
            .map(|_| ())
            .map_err(|reason| {
                usage(
                    format!("{argument} path `{value}` is outside the launch --files root: {reason}"),
                    "paths must stay within the launch --files root without `..`, symlinks, or absolute paths (fa-yha)",
                )
            })
    };
    for (argument, value, kind) in host_path_arguments(&verb.name, args) {
        let fix = match kind {
            HostPath::Output => {
                "use --dry-run for inline plan bytes, --review-only for inline review bytes, or --certify for a retained certificate; MCP accepts no output paths (fa-yha)"
            }
            HostPath::Content => {
                "forward the complete content on stdin with -; MCP takes the inline intent, plan, or policy property, never a file path (fa-yha)"
            }
            HostPath::Review => {
                "pass the review event's complete bytes hex string in review, or forward it on stdin with -; MCP accepts no host file paths (fa-yha)"
            }
            HostPath::ImportRun => {
                "forward the complete input on stdin with -; MCP accepts no host file paths (fa-yha)"
            }
            HostPath::Input => {
                "forward the complete input on stdin with -; report replay also accepts a retained C:<oid>. MCP uses inline chart, text, or certificate properties (fa-yha)"
            }
        };
        check_path(argument, value, kind == HostPath::Output, fix)?;
    }
    Ok(())
}

/// Commands routed through `fad` may only read or write host files inside the
/// daemon's configured `--files-root <dir>` containment directory (excluding
/// the book directory itself), or use forwarded stdin (`-`) / inline bytes (`fa-udti`).
fn admit_daemon_files(ctx: &Ctx<'_>, verb: &Verb, args: &Args) -> Result<(), Fail> {
    let Some(daemon_files) = &ctx.daemon_files else {
        return Ok(());
    };
    if args.flag("--keys").is_some() {
        return Err(usage(
            "--keys is set when fad starts; a command routed through fad cannot replace the daemon's key material",
            "restart fad with --keys <file>, or run with --via direct",
        ));
    }
    let check_path = |argument: &str, value: &str, allow_missing_leaf: bool, fix: &str| {
        let Some(root) = &daemon_files.files_root else {
            return Err(usage(
                format!(
                    "{argument} cannot name a host filesystem path (`{value}`) when fad serves without --files-root"
                ),
                format!(
                    "{fix}; or start the daemon with `fad serve --book <dir> --files-root <dir>` (fa-udti)"
                ),
            ));
        };
        let path_obj = Path::new(value);
        let has_parent_dir = path_obj
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
        let candidate = if path_obj.is_relative() && !has_parent_dir {
            ctx.files.cwd.as_ref().map_or_else(
                || value.to_string(),
                |base| base.join(path_obj).to_string_lossy().into_owned(),
            )
        } else {
            value.to_string()
        };
        crate::authority::resolve_in_daemon_files_root(
            root,
            &daemon_files.book_dir,
            &candidate,
            allow_missing_leaf,
        )
        .map(|_| ())
        .map_err(|reason| {
            usage(
                format!("{argument} path `{value}` is outside the daemon --files-root: {reason}"),
                "paths over fad must stay within the daemon --files-root without `..`, symlinks, or book-directory access (fa-udti)",
            )
        })
    };
    for (argument, value, kind) in host_path_arguments(&verb.name, args) {
        // An empty output value or `-` asks for the bytes inline on stdout.
        if kind == HostPath::Output && (value.is_empty() || value == "-") {
            continue;
        }
        let fix = match kind {
            HostPath::Output => {
                "omit the output path to receive inline bytes on stdout, or run with --via direct"
            }
            HostPath::Content => "forward the complete content on stdin with -",
            HostPath::Review => {
                "pass the review event's complete bytes hex string in --review, or forward it on stdin with -"
            }
            HostPath::ImportRun => "forward the complete input on stdin with -",
            HostPath::Input => {
                "forward the complete input on stdin with -; report replay also accepts a retained C:<oid>"
            }
        };
        check_path(argument, value, kind == HostPath::Output, fix)?;
    }
    Ok(())
}

/// Whether the command line confirms an operation that cannot be undone in
/// practice: `--yes`, or a `--plan` file (whose exact proposal the kernel
/// checks at commit).
pub(crate) fn confirmed(args: &Args) -> bool {
    args.switch("--yes") || args.flag("--plan").is_some()
}

fn command_name(verb: &str, subcommand: Option<&str>) -> String {
    match subcommand {
        Some(sub) => format!("fa {verb} {sub}"),
        None => format!("fa {verb}"),
    }
}

/// The FA-REF-007 refusal for an unconfirmed dangerous operation: what it
/// is, that nothing was written, and its safe alternative (verbs.toml).
/// A dangerous row's safe-alternative template with this command's target
/// in place of `<code>` / `<name>` (the period, draft or register named on
/// the command line), so the refusal names a command that can be run.
fn safe_for(template: &str, args: &Args) -> String {
    let target = args
        .flag("--period")
        .or_else(|| args.positional.get(2).map(String::as_str));
    match target {
        Some(t) => template.replace("<code>", t).replace("<name>", t),
        None => template.to_string(),
    }
}

fn unconfirmed(d: &Dangerous, args: &Args) -> Fail {
    let when = match &d.condition {
        Condition::Always => String::new(),
        Condition::Grant(op) => format!(" with --grant {op}"),
        Condition::Voids => " voiding a hold".to_string(),
        Condition::ExistingCells => " over cells already materialized".to_string(),
    };
    Fail::Refusal(Refusal::new(
        CONFIRMATION_REQUIRED,
        exit::SAFETY,
        format!(
            "`{}`{when} cannot be undone in practice and was not confirmed; nothing was written",
            command_name(&d.verb, d.subcommand.as_deref())
        ),
        "plan §15.3 (dangerous operations are gated and name a safe alternative) · Appendix D FA-REF-007",
        format!(
            "{}; or, when this is intended, rerun the same command with --yes",
            safe_for(&d.safe, args)
        ),
    )
    .rerun_with(vec!["--yes".to_string()]))
}

fn unconfirmed_bound(d: &Dangerous, args: &Args) -> Fail {
    let alternative = if d.verb == "period"
        && matches!(d.subcommand.as_deref(), Some("lock" | "reopen" | "close"))
    {
        safe_for(
            &format!(
                "prepare the operation with `fa period {} <code> --dry-run`; an independent operator must review and commit it",
                d.subcommand.as_deref().unwrap_or("lock")
            ),
            args,
        )
    } else {
        safe_for(&d.safe, args)
    };
    Refusal::new(
        CONFIRMATION_REQUIRED,
        exit::SAFETY,
        format!("`{}` requires independent confirmation; MCP cannot commit this dangerous operation until confirm_plan is implemented", command_name(&d.verb, d.subcommand.as_deref())),
        "plan §15.3; fa-23r; fa-we7 (typed confirmation plans)",
        alternative,
    ).into()
}

/// The dangerous operations the command line alone shows (verbs.toml
/// `[[dangerous]]`: `always`, `grant:<op>`) are refused unless confirmed,
/// before the handler opens the book. A confirmation on a command with no
/// dangerous row is a warning, never a silent no-op.
fn gate_from_argv(
    out: &Out,
    reg: &Registry,
    verb: &Verb,
    args: &Args,
    authority: Option<&LaunchAuthority>,
) -> Result<(), Fail> {
    let sub = if verb.subcommands.is_empty() {
        None
    } else {
        args.positional.get(1).map(String::as_str)
    };
    let mut rows = reg.dangerous_for(&verb.name, sub).peekable();
    // Planning commits nothing: the commit from the plan is what confirms.
    if period_plan_only(&verb.name, args)
        || post_plan_only(&verb.name, args)
        || recovery_preview_only(&verb.name, args)
    {
        return Ok(());
    }
    if authority.is_none() && confirmed(args) {
        // `--plan` is a file argument wherever it appears; only a bare
        // `--yes` can confirm nothing.
        if rows.peek().is_none() && args.switch("--yes") {
            out.warn(format!(
                "--yes confirms nothing here: `{}` is not an operation that needs confirmation",
                command_name(&verb.name, sub)
            ));
        }
        return Ok(());
    }
    for d in rows {
        let applies = match &d.condition {
            Condition::Always => true,
            Condition::Grant(op) => match authority {
                Some(authority) => {
                    fa_policy::Op::from_name(op).is_some_and(|op| authority.capability().holds(op))
                }
                None => args.flag_all("--grant").contains(&op.as_str()),
            },
            Condition::Voids | Condition::ExistingCells => false,
        };
        if applies {
            return Err(if authority.is_some() {
                unconfirmed_bound(d, args)
            } else {
                unconfirmed(d, args)
            });
        }
    }
    Ok(())
}

/// A handler-decided dangerous operation (`disposition:voids`,
/// `existing-cells`) that applies: refused unless confirmed, before any
/// write. A handler gating an operation verbs.toml does not list is a
/// parity defect.
pub(crate) fn gate(
    out: &Out,
    args: &Args,
    verb: &str,
    subcommand: Option<&str>,
    condition: &Condition,
) -> Result<(), Fail> {
    if (!out.is_bound() && confirmed(args)) || post_plan_only(verb, args) {
        return Ok(());
    }
    let reg = registry()?;
    match reg
        .dangerous_for(verb, subcommand)
        .find(|d| d.condition == *condition)
    {
        Some(d) => Err(if out.is_bound() {
            unconfirmed_bound(d, args)
        } else {
            unconfirmed(d, args)
        }),
        None => Err(Fail::Internal(format!(
            "`{}` gates `{}`, which verbs.toml [[dangerous]] does not list",
            command_name(verb, subcommand),
            condition.text()
        ))),
    }
}

/// Every supplied flag must be global or belong to the verb (verbs.toml).
fn check_flags(reg: &Registry, verb: Option<&Verb>, args: &Args) -> Result<(), Fail> {
    let supplied = args.flags.keys().chain(args.switches.iter());
    for flag in supplied {
        let global = reg.global.flags.contains(flag) || reg.global.switches.contains(flag);
        if global || verb.is_some_and(|v| v.accepts(flag)) {
            continue;
        }
        return Err(match verb {
            None => usage(
                format!("{flag} needs a command"),
                "fa --help lists the commands; e.g. fa tb --period FY2026-P03 --book <dir>",
            ),
            Some(v) => usage(
                format!("{flag} is not a flag of `fa {}`", v.name),
                if v.flags.is_empty() && v.switches.is_empty() {
                    format!(
                        "`fa {}` takes only the global flags; see `fa {} --help`",
                        v.name, v.name
                    )
                } else {
                    format!(
                        "flags of `fa {}`: {}; see `fa {} --help`",
                        v.name,
                        v.flags
                            .iter()
                            .chain(&v.switches)
                            .map(String::as_str)
                            .collect::<Vec<_>>()
                            .join(", "),
                        v.name
                    )
                },
            ),
        });
    }
    Ok(())
}

/// A subcommand the registry admitted but this handler does not implement:
/// a parity defect between verbs.toml and the binary, never a usage error.
pub(crate) fn unhandled(verb: &str, sub: Option<&str>) -> Fail {
    Fail::Internal(format!(
        "registered subcommand `{verb} {}` has no handler in this build",
        sub.unwrap_or("")
    ))
}

// ---------------------------------------------------------------------------
// Docs
// ---------------------------------------------------------------------------

/// Where bare `fa` stands (plan §15.3): the book this invocation would use
/// (`--book`, else FA_BOOK, else the working directory when it is a book)
/// and whether a fad serves it. Nothing is opened and no lease is taken: the
/// book is a directory probe, the daemon its lease file and one status call.
struct Here {
    /// The named directory, or the working directory when it is a book.
    book: Option<PathBuf>,
    /// serving | absent | not answering; null when `book` is not a book
    /// directory (genesis created no store there).
    daemon: Option<&'static str>,
}

fn here(args: &Args, cwd: Option<&Path>, reg: &Registry) -> Here {
    use crate::lease::Lease;
    // `cwd` is the client's directory over fad; `None` is this process's.
    let here_dir = cwd
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok());
    let book = named_book(args, cwd).or_else(|| here_dir.filter(|dir| Lease::is_book_dir(dir)));
    let daemon = book
        .as_deref()
        .filter(|dir| Lease::is_book_dir(dir))
        .map(|dir| {
            if Lease::holder(dir, &reg.daemon.lease).is_none() {
                return "absent";
            }
            let status = crate::wire::Request {
                op: crate::wire::Op::Status,
                argv: vec!["--json".to_string()],
                cwd: None,
                stdin: None,
                token: None,
            };
            match crate::client::call(&dir.join(&reg.daemon.socket), &status, &reg.daemon) {
                Ok(_) => "serving",
                Err(_) => "not answering",
            }
        });
    Here { book, daemon }
}

impl Here {
    fn text(&self) -> String {
        match (&self.book, self.daemon) {
            (Some(dir), Some(daemon)) => {
                let dir = dir.display();
                let fad = match daemon {
                    "serving" => "a fad serves it: commands route through it".to_string(),
                    "absent" => "no fad serves it: commands open it directly".to_string(),
                    _ => format!(
                        "its fad lease is held but no fad answers: fad status --book {dir} --json"
                    ),
                };
                format!(
                    "here\n  book {dir} ({fad})\n  \
                     fa triage --book {dir} --json   (state and what needs attention)\n  \
                     fa next --book {dir} --json   (the most urgent step)\n  \
                     fa doctor --book {dir} --json   (every health check and its fix)\n  \
                     fa period list --book {dir} --json\n  \
                     fa capabilities --json\n\n"
                )
            }
            (Some(dir), None) => format!(
                "here\n  {} is not a book: fa book create --book <dir> --name \"My Co\" makes one\n\n",
                dir.display()
            ),
            (None, _) => "here\n  no book: pass --book <dir> or set FA_BOOK (the working directory is not a book)\n\n"
                .to_string(),
        }
    }
}

fn triage_text() -> String {
    format!(
        "fa {VERSION} — FrankenAccounting\n\
         A double-entry, evidence-native ledger on FrankenGraphDB. Agents: add --json to any command.\n\n\
         start here\n  \
         fa book create --book <dir> --name \"My Co\" [--base-unit USD]\n  \
         fa chart import <chart.json> --book <dir>\n  \
         fa period create --fiscal-year 2026 --book <dir>; fa period open FY2026-P03 --book <dir>\n  \
         fa post --intent entry.json --book <dir> --json\n  \
         fa reserve --intent hold.json --book <dir> --json; fa resolve --intent res.json --book <dir> --json\n  \
         fa tb --period FY2026-P03 --book <dir> --json\n  \
         fa explain balance 1000 --period FY2026-P03 --book <dir> --json\n  \
         fa verify registers --period FY2026-P03 --book <dir>\n\n\
         discover\n  \
         fa capabilities --json · fa robot-docs guide|exit-codes|examples|schema · fa --help · fa <command> --help\n\n\
         exit codes: 0 ok · 2 usage · 3 accounting-law refusal · 4 environment · 5 foundation · 6 conflict · 7 safety · 8 verification (never 1)\n"
    )
}

/// The command list (`verb` = None) or one verb's usage, from verbs.toml.
fn help_text(reg: &Registry, verb: Option<&Verb>) -> String {
    let mut text = String::new();
    match verb {
        None => {
            text.push_str(&triage_text());
            text.push_str("\ncommands\n");
            for v in &reg.verbs {
                for line in &v.usage {
                    text.push_str(&format!("  {line}\n"));
                }
            }
            if !reg.aliases.is_empty() {
                text.push_str("\naliases\n");
                for a in &reg.aliases {
                    text.push_str(&format!("  {} = {}\n", a.name, a.expands.join(" ")));
                }
            }
        }
        Some(v) => {
            text.push_str(&format!("fa {} — {}\n\nusage\n", v.name, v.summary));
            for line in &v.usage {
                text.push_str(&format!("  fa {line}\n"));
            }
            if !v.flags.is_empty() || !v.switches.is_empty() {
                text.push_str(&format!(
                    "\nflags\n  {}\n",
                    v.flags
                        .iter()
                        .chain(&v.switches)
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                        .join(" · ")
                ));
            }
            let exits: Vec<String> = v.exits.iter().map(u8::to_string).collect();
            text.push_str(&format!(
                "\nevents (--json)\n  {}\nexits\n  {}\nexample\n  {}\n",
                v.events.join(" · "),
                exits.join(" · "),
                v.example
            ));
        }
    }
    text.push_str(&format!("\nglobal flags\n  {}\n", reg.global.usage));
    text
}

fn emit_help(out: &Out, reg: &Registry, verb: Option<&Verb>) -> Result<(), Fail> {
    let text = help_text(reg, verb);
    out.event(
        "help",
        vec![
            ("verb", verb.map_or(Json::Null, |v| s(&v.name))),
            ("text", s(&text)),
        ],
        text.trim_end(),
    );
    Ok(())
}

fn help_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let reg = registry()?;
    match args.positional.get(1) {
        None => emit_help(out, reg, None),
        Some(word) => {
            let words = reg.expand_alias(args.positional.get(1..).unwrap_or_default());
            let name = words.first().unwrap_or(word);
            match reg.verb(name) {
                Some(v) => emit_help(out, reg, Some(v)),
                None => Err(usage(
                    format!("no command `{word}`"),
                    match nearest(
                        word,
                        &reg.verbs
                            .iter()
                            .map(|v| v.name.as_str())
                            .collect::<Vec<_>>(),
                    ) {
                        Some(n) => format!("fa help {n}"),
                        None => "fa help".to_string(),
                    },
                )),
            }
        }
    }
}

fn capabilities_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let reg = registry()?;
    let bound_cap = ctx.capability(args, &[])?;
    let commitment = bound_cap
        .commitment()
        .map_err(|e| Fail::Internal(format!("capability commitment: {e}")))?;
    let exits = fa_registry::ExitCodes::embedded().map_err(BookError::Registry)?;
    let codes: Vec<Json> = exits
        .rows
        .iter()
        .map(|r| {
            obj(vec![
                ("code", Json::Int(i128::from(r.code))),
                ("name", s(&r.name)),
                ("meaning", s(&r.meaning)),
            ])
        })
        .collect();
    let classes = fa_registry::EntryClasses::embedded().map_err(BookError::Registry)?;
    let class_names: Vec<Json> = classes.rows.iter().map(|c| s(&c.name)).collect();
    let invariants =
        fa_registry::invariants::Invariants::embedded().map_err(BookError::Registry)?;
    let op_costs = fa_registry::g0::OperationCosts::embedded().map_err(BookError::Registry)?;
    let slo = fa_registry::g0::SloRegistry::embedded(&op_costs).map_err(BookError::Registry)?;
    let fields = vec![
        ("version", s(VERSION)),
        (
            "verbs",
            Json::Arr(reg.verbs.iter().map(|v| s(&v.name)).collect()),
        ),
        (
            "aliases",
            Json::Arr(
                reg.aliases
                    .iter()
                    .map(|a| {
                        obj(vec![
                            ("name", s(&a.name)),
                            ("expands", s(a.expands.join(" "))),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("exit_codes", Json::Arr(codes)),
        ("entry_classes", Json::Arr(class_names)),
        (
            "robot_mode",
            obj(vec![
                ("flag", s("--json")),
                ("envelope", s(&reg.envelope.description)),
                ("schema", s("fa robot-docs schema [<event>] --json")),
            ]),
        ),
        ("stdout", s("data")),
        ("stderr", s("diagnostics")),
        ("tui", Json::Bool(false)),
        (
            "capability",
            capability_model(ctx.authority.as_ref(), &commitment)?,
        ),
        (
            "dangerous",
            Json::Arr(
                reg.dangerous
                    .iter()
                    .map(|d| {
                        obj(vec![
                            ("verb", s(&d.verb)),
                            ("subcommand", d.subcommand.as_ref().map_or(Json::Null, s)),
                            ("condition", s(d.condition.text())),
                            ("safe", s(&d.safe)),
                        ])
                    })
                    .collect(),
            ),
        ),
        // The invariant clauses this build enforces (fa-37f, MaroonSquirrel
        // 3229): `live` have a running checker; `gate_g1` is Gate G1's set.
        (
            "invariants",
            obj(vec![
                (
                    "live",
                    Json::Arr(invariants.live_clause_ids().iter().map(s).collect()),
                ),
                (
                    "gate_g1",
                    Json::Arr(invariants.gate_g1.iter().map(s).collect()),
                ),
            ]),
        ),
        (
            "slo_manifests",
            Json::Arr(slo.activated_manifest_ids().iter().map(s).collect()),
        ),
        // Every registered Lantern procedure with the claim class of its
        // output (doctrine 12, fa-vpk); `fa procedure list` has the full rows.
        (
            "procedures",
            Json::Arr(
                fa_lantern::catalog::registered()
                    .map_err(|e| Fail::Internal(format!("procedure registry: {e}")))?
                    .iter()
                    .map(|row| {
                        obj(vec![
                            ("id", s(&row.id)),
                            ("version", Json::Int(i128::from(row.version))),
                            ("claim", s(row.claim.name())),
                            ("summary", s(&row.summary)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];

    if out.json {
        out.event("capabilities", fields, "");
    } else {
        out.line(obj(fields).render());
    }
    Ok(())
}

/// The capability model this build enforces (plan §14.2, §14.4; fa-policy):
/// the closed op vocabulary, the profiles and the ops each can never hold,
/// the caveats' semantics, and the embedded posture's binding.
fn capability_model(
    authority: Option<&LaunchAuthority>,
    commitment: &[u8; 32],
) -> Result<Json, Fail> {
    let steward = fa_journal::policy::steward().map_err(BookError::Kernel)?;
    let names = |ops: &[fa_policy::Op]| Json::Arr(ops.iter().map(|o| s(o.name())).collect());
    Ok(obj(vec![
        ("ops", names(&fa_policy::Op::ALL)),
        (
            "profiles",
            Json::Arr(
                fa_policy::Profile::ALL
                    .iter()
                    .map(|p| {
                        obj(vec![
                            ("name", s(p.name())),
                            ("forbidden_ops", names(p.forbidden_ops())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "ceilings",
            s(
                "amount <= A bounds every leg's mantissa in its unit; a ceiling-bearing capability admits only the units it bounds (FA-REF-015)",
            ),
        ),
        (
            "expiry",
            s(
                "a declared CommitSeq bound: admitted iff the book head at admission is below expires_at (FA-REF-014)",
            ),
        ),
        (
            "agent_trunk",
            s(
                "an Agent-profile capability never writes trunk (FA-REF-013); it may rehearse post, reverse, reserve and resolve with --dry-run (plan §15.3), and that plan commits for no one; drafts land with the branch slice",
            ),
        ),
        (
            "binding",
            obj(vec![
                ("commitment", s(hex(commitment))),
                (
                    "flags",
                    Json::Arr(if authority.is_some() {
                        Vec::new()
                    } else {
                        vec![s("--as <principal>"), s("--grant <op>")]
                    }),
                ),
                (
                    "posture",
                    s(if authority.is_some() {
                        "mcp-launch-config"
                    } else {
                        "embedded-owner"
                    }),
                ),
                (
                    "profile",
                    s(authority
                        .map_or(fa_policy::Profile::Human, |a| a.capability().profile())
                        .name()),
                ),
                ("ceilings", Json::Arr(Vec::new())),
                ("expires_at", Json::Null),
                (
                    "trust_boundary",
                    s(if authority.is_some() {
                        "MCP binds one capability from trusted operator launch configuration: fixed principal, profile, operations, book and key path. Requests cannot choose identity, grants, confirmation or daemon routing. Launch configuration does not authenticate the operator; issued tokens and authenticated daemon sessions remain fa-v62/fa-r3q. The envelope lists this session's actual launch template and ops."
                    } else {
                        "embedded-owner posture: the calling process supplies --as and self-issues Human-profile operations per command with --grant, without ceilings or expiry. The fad argv route has the same owner posture for a same-uid peer; a request carrying an issued token (fa --token) is bound to that token's principal and journaled capability instead. MCP uses a separate launch binding: a launch-config session refuses the daemon route, a --token session presents its token to fad. The kernel evaluates supplied authority; it does not authenticate the operator."
                    }),
                ),
            ]),
        ),
        ("policy_oid", s(hex(&steward.policy_oid))),
    ]))
}

fn robot_docs_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let topic = args.positional.get(1);
    let text = match topic.map(String::as_str) {
        Some("exit-codes") => {
            let exits = fa_registry::ExitCodes::embedded().map_err(BookError::Registry)?;
            exits
                .rows
                .iter()
                .map(|r| format!("{} {:<13} {}\n", r.code, r.name, r.meaning))
                .collect()
        }
        Some("guide") => GUIDE.to_string(),
        Some("examples") => EXAMPLES.to_string(),
        Some("schema") => return robot_schema(out, registry()?, args.positional.get(2)),
        _ => return Err(unhandled("robot-docs", topic.map(String::as_str))),
    };
    let text = match &ctx.authority {
        Some(authority) => format!(
            "This MCP server is bound at launch to principal `{}` under the `{}` template, with ops [{}]. Tool requests cannot override identity, grants, confirmation, book or keys. Dangerous commits require independent operator review until confirm_plan is available. The current daemon route cannot carry this authority and is refused. Launch configuration trusts the operator; it is not operator authentication. CLI --as/--grant/--yes examples below describe the operator's embedded-owner command line.\n\n{}",
            authority.principal(),
            authority.profile().name(),
            authority
                .capability()
                .ops()
                .iter()
                .map(|op| op.name())
                .collect::<Vec<_>>()
                .join(", "),
            text
        ),
        None => text,
    };
    out.event(
        "robot_docs",
        vec![
            ("topic", s(topic.map_or("", String::as_str))),
            ("text", s(&text)),
        ],
        text.trim_end(),
    );
    Ok(())
}

fn field_docs(fields: &[verbs::Field]) -> Json {
    Json::Arr(
        fields
            .iter()
            .map(|f| obj(vec![("name", s(&f.name)), ("type", s(&f.type_text))]))
            .collect(),
    )
}

/// `fa robot-docs schema [<name>]`: the envelope and every event (with the
/// shapes they reference), or one event or shape — printed from verbs.toml.
fn robot_schema(out: &Out, reg: &Registry, name: Option<&String>) -> Result<(), Fail> {
    let (events, shapes): (Vec<&verbs::Schema>, Vec<&verbs::Schema>) = match name {
        None => (reg.events.iter().collect(), reg.shapes.iter().collect()),
        Some(n) => match (reg.event(n), reg.shape(n)) {
            (Some(e), _) => (vec![e], reg.closure(&[e])),
            (None, Some(sh)) => {
                let mut shapes = vec![sh];
                shapes.extend(reg.closure(&[sh]));
                (Vec::new(), shapes)
            }
            (None, None) => {
                let mut known: Vec<&str> = reg.events.iter().map(|e| e.name.as_str()).collect();
                known.extend(reg.shapes.iter().map(|s| s.name.as_str()));
                return Err(usage(
                    format!("no event or shape `{n}` in the robot schema"),
                    match nearest(n, &known) {
                        Some(k) => format!("fa robot-docs schema {k}"),
                        None => "fa robot-docs schema (lists every event)".to_string(),
                    },
                ));
            }
        },
    };
    if out.json {
        out.event(
            "robot_schema",
            vec![
                (
                    "envelope",
                    obj(vec![
                        ("discriminator", s(&reg.envelope.discriminator)),
                        ("version", Json::Int(reg.envelope.version)),
                        ("fields", field_docs(&reg.envelope.fields)),
                        (
                            "frames",
                            Json::Arr(reg.envelope.frames.iter().map(s).collect()),
                        ),
                        ("description", s(&reg.envelope.description)),
                        (
                            "types",
                            Json::Arr(verbs::TYPES.iter().map(|t| s(*t)).collect()),
                        ),
                    ]),
                ),
                (
                    "events",
                    Json::Arr(
                        events
                            .iter()
                            .map(|e| {
                                obj(vec![
                                    ("name", s(&e.name)),
                                    ("doc", s(&e.doc)),
                                    ("book", Json::Bool(e.book)),
                                    (
                                        "verbs",
                                        Json::Arr(
                                            reg.emitters(&e.name).into_iter().map(s).collect(),
                                        ),
                                    ),
                                    ("fields", field_docs(&e.fields)),
                                ])
                            })
                            .collect(),
                    ),
                ),
                (
                    "shapes",
                    Json::Arr(
                        shapes
                            .iter()
                            .map(|sh| {
                                obj(vec![
                                    ("name", s(&sh.name)),
                                    ("doc", s(&sh.doc)),
                                    ("fields", field_docs(&sh.fields)),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ],
            "",
        );
        return Ok(());
    }
    if name.is_none() {
        out.line(format!(
            "envelope\n  {}\n  discriminator: `{}`\n  types: {}\n",
            reg.envelope.description,
            reg.envelope.discriminator,
            verbs::TYPES.join(" · ")
        ));
    }
    for e in &events {
        let emitters = reg.emitters(&e.name);
        out.line(format!(
            "event {} ({}) — {}",
            e.name,
            if emitters.is_empty() {
                "any command".to_string()
            } else {
                emitters.join(", ")
            },
            e.doc
        ));
        for f in &e.fields {
            out.line(format!("  {}: {}", f.name, f.type_text));
        }
    }
    for sh in &shapes {
        out.line(format!("shape {} — {}", sh.name, sh.doc));
        for f in &sh.fields {
            out.line(format!("  {}: {}", f.name, f.type_text));
        }
    }
    Ok(())
}

const GUIDE: &str = "fa robot-docs guide\n\
\n\
1. Every command accepts --json (or --format json|toon|text). Parse --json stdout line by line; each line is one JSON object {v, event, book, coordinate, data, certificate, authority, warnings, next_actions}: `event` names the schema of `data`; `book` and `coordinate` say which book and (branch, known_at, effective) the line describes; `authority` declares the actual execution binding; `next_actions` are the commands usually run next (add the same --book in the owner's CLI). Prefer `--format toon` on tabular read verbs (`tb`, `open-items`, `gl`, `chart list`, `period list`, `explain balance`, `statement`) when feeding large register, open-item, or trial-balance tables into an agent context window: TOON v3.0 encodes uniform object arrays as compact `rows[N]{f1,f2,...}:` tables while keeping every amount an exact string with its unit.\n\
2. Read the exit code before the output: 0 success (empty results are 0), 2 usage, 3 accounting-law refusal, 4 environment, 5 foundation/I-O, 6 conflict (retry with a fresh read), 7 safety block (period law, capability, an unconfirmed dangerous operation), 8 verification failure. 1 is never emitted.\n\
3. Every non-zero exit is exactly one `error` line: data {class, exit, refusal_id, message, cite, fix, detail, refusal}. `refusal_id` (FA-REF-nnn) is the refusal catalog code when one applies, and `refusal` is then its Appendix D object: `where` (leg, account, period …), `why` (law, policy or matrix cell), `fix.argv` (a command that parses against the registry, when the fix names one), `fix.or_field_change` (the field and the values it admits). Do the `fix`; do not invent a leg, a date, or an approval. FA-REF-007 means the operation cannot be undone in practice: its fix names the safe alternative; add --yes only when the operation is intended (`fa capabilities --json` lists them under `dangerous`).\n\
4. Amounts are strings with the unit: \"1500.00 USD\". Never floats. Dates are civil YYYY-MM-DD; recorded time is assigned by the journal, never supplied.\n\
5. Corrections are new entries that cite the original; nothing is edited in place. Reversal is live. A corrected Replacement posts only as a pair with its Reversal (`fa reverse <vid> --reason <name> --replace-with <file>`); a standalone Replacement is FA-REF-160. A Reclassification moves part of an entry to another account (`fa reclass <vid> --from <account> --to <account> --amount \"<amount>\" --reason <name>`; FA-REF-185 when it moves more than the target's legs have left). A PriorPeriodAdjustment, a Revision or a Restatement posts only as an approved restatement case's entry (`fa case post <case>`), FA-REF-178 otherwise; a Revision or Restatement case plans each entry in its scenario with `revises` or `restates` naming the posting it corrects and the delta legs. A Restatement's two approvers share no session lineage: neither's capability was issued, directly or further up the chain, by the other or by a preparer of the case.\n\
6. Idempotency: every intent carries idempotency_key; resubmitting returns the recorded outcome (event \"recorded\"), never a duplicate.\n\
7. Posting into a non-Open period is decided by the admissibility matrix; the refusal cites the (class, state) cell and names the admissible class or capability.\n\
8. Two-phase: `fa reserve` posts a Pending (amounts in the pending columns, never posted); `fa resolve` names it with `resolves` and either posts a sub-vector (`legs`, each drawn from one hold leg — same account and side, at most the reserved amount; add `source_ordinal` when the hold has several such legs) or voids it (`disposition: \"voids\"`). The rest of the hold is released either way. One resolution per hold: a second is exit 6 (FA-REF-062); resolving a non-hold is FA-REF-060.\n\
9. Explain before you trust: `fa explain balance <account> --period <code> --json` returns the account's register cells, the fold digest they belong to, every contributing leg with its entry and recorded_at, and the cells' known-at history; the legs re-add to the cells exactly. Add --as-known-at <seq> to see what was known then.\n\
10. Schemas: `fa robot-docs schema --json` lists every event and its fields (generated from registries/verbs.toml); `fa robot-docs schema <event>` prints one. `fa <command> --help` prints that command's usage, flags, events and exits.\n\
11. Application: a leg may carry `settles: [{entry, ordinal, amount}]` to apply itself to an open item — the opposite side on the same account and unit, at most the item's open amount (FA-REF-072 names what is open). `fa open-items --account <code>` lists items with their applications. Reversing a receipt reopens the invoice (its applications are undone, never re-entered); an invoice with live applications cannot be reversed until its receipts are (FA-REF-073).\n\
12. Corrections require a registered reason: `fa reverse <vid> --reason WrongAccount --json` derives the opposite legs and retains the target's date by default; --effective selects an explicit same-or-later admissible period. A Reversal passed to `fa post` likewise carries `reason`, for example \"WrongAmount\". `fa entry show <reversal vid> --json` reports the immutable supersession and its reason. Other requires a description; no reason code proves the explanation true.\n\
13. Retain a report for replay: `fa tb --period FY2026-P03 --certify --json`, `fa explain balance 1000 --period FY2026-P03 --certify --json`, and `fa open-items --account 1000 --certify --json` retain the report's certificate in the book. Each emits its original report event followed by report_certificate, binding the selector, known-at, historical account metadata and native history. `fa replay C:<oid> --json` reproduces the original report, and `fa certificate status C:<oid> --json` names later relevant entries without changing it. --certificate-out report.cert also writes a new external copy, never overwriting one. File and complete inline hex remain accepted; MCP accepts the returned oid or bytes as certificate. Certification writes metadata, never accounting entries; uncertified reads do not write. Scope is fa-fold-over-prefix with embedded-owner authority.\n\
14. Rehearse an entry before writing: add --dry-run to post, reverse, reserve or resolve. The actual posting laws run, their staged transaction is aborted, and one plan event returns the exact sealed proposal, native effects digest, snapshot and complete canonical bytes. --plan-out <new-file> saves a private binary copy without replacing a file. Review it, then `fa commit --plan <file|-> --json` with the same owner --as and --grant; stdin accepts the bytes hex string. MCP uses fa_post_commit_plan with plan set to that string and keeps its launch-bound capability unchanged: ordinary Preparer plans can commit, Agent trunk posting still refuses, and dangerous void commits remain unavailable until separate confirmation exists. A first commit atomically retains its graph Certificate and CITES edge; an exact retry returns plan_committed with already_recorded=true. Any intervening book publication invalidates this first same-snapshot plan and requires another dry run. Planning collects no new approvals and provides no draft or --balancing support. A dry-run void releases nothing; the owner explicitly confirms its exact artifact, while MCP must ask the operator to separately prepare and confirm a release. Public plan digests are data fields, never native object-store OIDs in the envelope.\n\
15. An Agent (or anyone) works on a draft (plan §15.2): `fa draft new <name>`, then the same post, reverse, reserve or resolve command with --draft <name> (or `fa draft plan <name> --intent <file|->`). Each intent is rehearsed under every posting law and journaled into the draft; nothing reaches trunk. `fa draft show <name> --json` lists the planned intents and the entries a promotion will create. A principal holding approve who is not the draft's owner runs `fa draft promote <name> --yes`: every intent is admitted again against current trunk (period law, ceilings, revocation, evidence) and all post in one batch, or none do; the planner stays each entry's principal. `fa draft discard <name>` closes a draft without posting. Over MCP the fa.draft cluster is on demand (`fa-mcp --cluster fa.draft`); promotion is host-only.\n\
16. Correct an entry in one step: `fa reverse <vid> --reason WrongAmount --replace-with corrected.json --json` posts the exact reversal and the corrected entry together, both or neither, citing the target under one reason (event corrected). corrected.json is an ordinary entry intent (legs, optional effective_date and description); its date and period default to the target's.\n\
17. Export for an auditor or another ledger: `fa export ads|saft|csv-gl|beancount|hledger|ndjson --period FY2026-P03 [--out <new path>] --json` writes what the trial balance folds (pending holds excluded) with its export coordinate certificate; ads writes four tables into a new directory. It needs read and produce. Over MCP the fa.io cluster is on demand.\n\
18. Maintain the chart and the REA graph: `fa chart open <account.json> --opened <day>`, `fa chart close <code> --on <day>`, `fa chart promote <code> --on <day>`; `fa party add <party.json>`, `fa party relate <from> <to> --kind owns --basis equity_voting --valid-from <day> --pct 51/100`, `fa instrument add <instrument.json>`, `fa entity add <entity.json>` (a legal entity's jurisdiction, functional unit and life span; a code declared at book creation is lifted), `fa party bind <code> --external-id qbo:55`, `fa party identifiers <code> --identifier bank_account=<value>... --key <change-id>` (replaces the party's identifier set under a named change; values sealed, never echoed; host-only over MCP). Each is a journaled schema change (schema_change authority) and no date defaults to today. Events then name parties with --participant and instruments with --resource <label>:<amount>:<instrument>.\n\
19. Read a period as it was first reported: `fa tb --period FY2026-P03 --as-originally-reported --json` pins known-at to the certificate its first StatementIssuance issued, else to its first Lock (never its first Close, never HEAD); a period neither issued nor locked is refused with FA-REF-161. `--as-issued-to <audience>` reads it as issued to that audience (FA-REF-173 when it never was) and `--as-reported-in C:<oid>` as reported in that retained statement certificate (FA-REF-174 when the certificate does not report the period). Record an issuance with `fa statement issue`.\n\
20. Typed documents: `fa invoice --party C-17 --number 10442 --date 2026-03-14 --receivable 1200 --revenue 4000 --line 'qty=10 unit_price=\"125.00 USD\" item=SKU-9' --evidence <oid> --dry-run --json` (and `fa bill ... --payable 2000 --expense 6000`) builds the entry from its lines and posts through fa post's path (--dry-run, --plan-out, --draft, --scenario); `fa receipt --party C-17 --number WIRE-IN-1 --date 2026-03-20 --cash 1000 --receivable 1200 --amount \"1290.00 USD\" --applies <invoice vid>` (and `fa payment`) settles it, its number becoming the cash leg's memo that fa bank match compares with a statement line's reference. You name every account; there is no tax or posting rule yet. An intent leg may name `entity` and `party` codes; in a multi-entity book every leg names its entity. `fa document list [--kind BankStatement]` lists held documents as metadata.\n\
21. Ask what-if or but-for (plan §15.2, §15.6.5): `fa scenario fork but-for-breach --from 2025-07-01 [--at HEAD|<seq>] --evidence <assumption oid>` forks a counterfactual over the trunk prefix at that sequence; `fa scenario run but-for-breach --intent receipt.json` (or fa post, invoice, bill, receipt or payment with --scenario but-for-breach) rehearses each intent on the scenario and journals it there, never on trunk; `fa scenario diff but-for-breach --period FY2025-P12 --json` is the exact change per account and unit against trunk as known at the fork (the damages schedule). Each run and diff replays the trunk prefix into a scratch book and posts every intent again under every posting law. `fa tb|statement|explain|open-items|gl|query ... --branch scenario:but-for-breach` runs the same read on the scenario's replay, and `--branch draft:<name>` on a draft's rehearsal (trunk with its planned intents posted, as promotion would), both uncertified with the branch in the coordinate. `fa scenario diff ... --certify` retains the diff as a certificate bound to trunk at the fork and the intents it covers: `fa replay C:<oid>` reproduces it byte for byte, and `fa certificate status C:<oid>` names the intents run since.\n\
22. Ask the graph anything (plan §15.5): `fa query \"MATCH (l:Leg)-[:IN_UNIT]->(u:Unit) RETURN u.code, l.side, SUM(l.amount) AS total FOR PERIOD 'FY2026-P03' AS KNOWN AT 120\" --json` runs native GQL over entries, legs, accounts, units, periods, parties and documents at one recorded sequence (query_rows: the native statement it ran, columns, rows, result_digest). Select with AS KNOWN AT <seq>|HEAD|'<instant>', FOR PERIOD '<code>' (the period an entry posted to), EFFECTIVE BETWEEN '<date>' AND '<date>' and AT BRANCH trunk | 'scenario:<name>' (a scenario's replay, as --branch reads it). Amounts aggregate only per unit and compare only within one pinned unit (FA-REF-189); other clauses are refused naming the admissible form (FA-REF-188). Rows are the graph as recorded, pending holds included: a balance is `fa query \"CALL fa.trial_balance FOR PERIOD 'FY2026-P03'\"`, which is `fa tb` itself. Add --certify to retain the result's certificate (read and produce): `fa replay C:<oid>` replays the native read and reproduces the rows byte for byte, and `fa certificate status C:<oid>` says whether the statement still answers the same at HEAD.\n";

const EXAMPLES: &str = "fa robot-docs examples\n\
\n\
# chart.json\n\
{\"accounts\":[{\"code\":\"1000\",\"name\":\"Cash\",\"type\":\"Asset\",\"leaf\":true,\"unit\":\"USD\"},\n\
              {\"code\":\"6000\",\"name\":\"Rent\",\"type\":\"Expense\",\"leaf\":true,\"unit\":\"USD\"}]}\n\
\n\
# entry.json\n\
{\"class\":\"Original\",\"effective_date\":\"2026-03-15\",\"description\":\"March rent\",\"idempotency_key\":\"inv-1001\",\n\
 \"legs\":[{\"side\":\"debit\",\"account\":\"6000\",\"amount\":\"1500.00 USD\"},\n\
          {\"side\":\"credit\",\"account\":\"1000\",\"amount\":\"1500.00 USD\"}]}\n\
\n\
fa book create --book ./books/myco --name \"My Co\" --json\n\
fa chart import chart.json --book ./books/myco --json\n\
fa period create --fiscal-year 2026 --book ./books/myco --json\n\
fa period open FY2026-P03 --book ./books/myco --json\n\
fa post --intent entry.json --book ./books/myco --json      # exit 0, event posted\n\
fa post --intent entry.json --book ./books/myco --json      # exit 0, event recorded (same idempotency_key)\n\
fa tb --period FY2026-P03 --book ./books/myco --json\n\
fa tb --as-of 2026-03-15 --as-known-at HEAD --book ./books/myco --json\n\
fa tb --period FY2026-P03 --activity --book ./books/myco --json\n\
fa registers materialize --period FY2026-P03 --book ./books/myco\n\
fa verify registers --period FY2026-P03 --book ./books/myco  # exit 8 on drift\n\
\n\
# hold.json (a Pending: 80.00 reserved, nothing posted)\n\
{\"effective_date\":\"2026-03-10\",\"description\":\"PO 77 hold\",\"idempotency_key\":\"hold-77\",\n\
 \"legs\":[{\"side\":\"debit\",\"account\":\"6000\",\"amount\":\"80.00 USD\"},{\"side\":\"credit\",\"account\":\"1000\",\"amount\":\"80.00 USD\"}]}\n\
# res.json (posts 60.00 of the hold; the other 20.00 is released)\n\
{\"resolves\":\"<vid from the reserve event>\",\"effective_date\":\"2026-03-20\",\"idempotency_key\":\"res-77\",\n\
 \"legs\":[{\"side\":\"debit\",\"account\":\"6000\",\"amount\":\"60.00 USD\"},{\"side\":\"credit\",\"account\":\"1000\",\"amount\":\"60.00 USD\"}]}\n\
# void.json (releases the whole hold)\n\
{\"resolves\":\"<vid>\",\"disposition\":\"voids\",\"effective_date\":\"2026-03-21\",\"idempotency_key\":\"void-77\"}\n\
fa reserve --intent hold.json --book ./books/myco --json      # exit 0, event posted, class Pending\n\
fa resolve --intent res.json --book ./books/myco --json       # exit 0, event posted, class Resolution\n\
fa resolve --intent void.json --book ./books/myco --json      # exit 6, FA-REF-062: the hold is already resolved\n\
\n\
# invoice.json / receipt.json (the receipt's credit leg settles the invoice's debit leg 0)\n\
{\"effective_date\":\"2026-03-05\",\"idempotency_key\":\"inv-9\",\"legs\":[{\"side\":\"debit\",\"account\":\"1200\",\"amount\":\"500.00 USD\"},{\"side\":\"credit\",\"account\":\"4000\",\"amount\":\"500.00 USD\"}]}\n\
{\"effective_date\":\"2026-03-20\",\"idempotency_key\":\"rcpt-9\",\"legs\":[{\"side\":\"debit\",\"account\":\"1000\",\"amount\":\"300.00 USD\"},\n\
  {\"side\":\"credit\",\"account\":\"1200\",\"amount\":\"300.00 USD\",\"settles\":[{\"entry\":\"<invoice vid>\",\"ordinal\":0,\"amount\":\"300.00 USD\"}]}]}\n\
fa open-items --account 1200 --book ./books/myco --json       # open 200.00 on the invoice's leg 0\n\
fa verify open-items --book ./books/myco                      # exit 8 if an applied mirror drifts from the fold\n\
\n\
fa explain balance 1000 --period FY2026-P03 --book ./books/myco --json   # cells, fold digest, every leg, history\n\
fa explain balance 1000 --period FY2026-P03 --as-known-at 12 --book ./books/myco --json\n\
fa robot-docs schema balance_explained --json\n";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// The book directory `--book` (else `FA_BOOK`) names, resolved against the
/// caller's working directory `cwd` (fa-40l). The front door leases and
/// routes by this path, and a command opens it, so every spelling of one
/// directory reaches the same book.
pub(crate) fn named_book(args: &Args, cwd: Option<&Path>) -> Option<PathBuf> {
    if let Some(d) = args.flag("--book") {
        return Some(resolve_in(cwd, d));
    }
    std::env::var("FA_BOOK")
        .ok()
        .filter(|d| !d.is_empty())
        .map(|d| resolve_in(cwd, &d))
}

fn book_dir(args: &Args, cwd: Option<&Path>) -> Result<PathBuf, Fail> {
    named_book(args, cwd).ok_or_else(|| {
        usage(
            "no book directory",
            "--book <dir> (or export FA_BOOK=<dir>)",
        )
    })
}

/// `--keys`, resolved against `cwd` like the book; else `<dir>/book.keys`.
pub(crate) fn keys_path(args: &Args, dir: &Path, cwd: Option<&Path>) -> PathBuf {
    args.flag("--keys")
        .map_or_else(|| dir.join("book.keys"), |k| resolve_in(cwd, k))
}

pub(crate) fn principal(args: &Args) -> VId {
    principal_vid(args.flag("--as").unwrap_or("operator"))
}

pub(crate) fn date_flag(args: &Args, default: DateDay) -> Result<DateDay, Fail> {
    match args.flag("--date") {
        None => Ok(default),
        Some(d) => DateDay::parse(d)
            .map_err(|e| usage(format!("--date `{d}`: {e:?}"), "--date YYYY-MM-DD")),
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub(crate) fn parse_json(path: &str, text: &str) -> Result<Json, Fail> {
    json::parse(text).map_err(|e| usage(format!("{path}: {e}"), "fa robot-docs examples"))
}

fn req_str<'a>(doc: &'a Json, key: &str, what: &str) -> Result<&'a str, Fail> {
    doc.get(key).and_then(Json::as_str).ok_or_else(|| {
        usage(
            format!("{what}: `{key}` must be a string"),
            "fa robot-docs examples",
        )
    })
}

// ---------------------------------------------------------------------------
// book
// ---------------------------------------------------------------------------

fn parse_cli_weekday(text: &str) -> Option<fa_time::Weekday> {
    use fa_time::Weekday as W;
    match text.to_ascii_lowercase().as_str() {
        "monday" | "mon" => Some(W::Monday),
        "tuesday" | "tue" => Some(W::Tuesday),
        "wednesday" | "wed" => Some(W::Wednesday),
        "thursday" | "thu" => Some(W::Thursday),
        "friday" | "fri" => Some(W::Friday),
        "saturday" | "sat" => Some(W::Saturday),
        "sunday" | "sun" => Some(W::Sunday),
        _ => None,
    }
}

fn parse_cli_calendar(
    kind_arg: &str,
    ysm_arg: Option<&str>,
    adj: u8,
) -> Result<FiscalCalendar, Fail> {
    use fa_time::{WeekPattern, Weekday, YearEndRule};
    const FIX: &str = "--calendar monthly|4-4-5|4-5-4|5-4-4|52-53[:last|nearest:<weekday>[:<month>]] --year-start-month 1..=12 --adjustment-periods 0..=4";
    let ysm: Option<u8> = match ysm_arg {
        None => None,
        Some(raw) => {
            let m: u8 = raw
                .parse()
                .map_err(|_| usage("--year-start-month must be 1..=12", "--year-start-month 1"))?;
            if !(1..=12).contains(&m) {
                return Err(usage(
                    "--year-start-month must be 1..=12",
                    "--year-start-month 1",
                ));
            }
            Some(m)
        }
    };
    let parts: Vec<&str> = kind_arg.split(':').collect();
    let head = parts[0];
    if head == "monthly" {
        if parts.len() > 1 {
            return Err(usage(
                "monthly calendar uses --year-start-month 1..=12, not a weekday year-end rule",
                "--calendar monthly --year-start-month 1",
            ));
        }
        return FiscalCalendar::monthly("fiscal", ysm.unwrap_or(1), adj)
            .map_err(|e| usage(format!("calendar: {e}"), FIX));
    }
    let default_end_month = match ysm.unwrap_or(1) {
        1 => 12,
        m => m - 1,
    };
    let end_rule = match parts.as_slice() {
        [_] => YearEndRule::WeekdayNearestEnd {
            weekday: Weekday::Saturday,
            month: default_end_month,
        },
        [_, rule_name, weekday_name] | [_, rule_name, weekday_name, _] => {
            let weekday = parse_cli_weekday(weekday_name).ok_or_else(|| {
                usage(
                    format!("unknown weekday `{weekday_name}` in --calendar `{kind_arg}`"),
                    FIX,
                )
            })?;
            let month = if let Some(month_str) = parts.get(3) {
                if ysm.is_some() {
                    return Err(usage(
                        "pass either --year-start-month or an explicit month in --calendar, not both",
                        FIX,
                    ));
                }
                let m: u8 = month_str
                    .parse()
                    .map_err(|_| usage("calendar end month must be 1..=12", FIX))?;
                if !(1..=12).contains(&m) {
                    return Err(usage("calendar end month must be 1..=12", FIX));
                }
                m
            } else {
                default_end_month
            };
            match *rule_name {
                "last" => YearEndRule::LastWeekdayOfMonth { weekday, month },
                "nearest" => YearEndRule::WeekdayNearestEnd { weekday, month },
                _ => {
                    return Err(usage(
                        format!(
                            "unknown year-end rule `{rule_name}` in --calendar `{kind_arg}`; expected `last` or `nearest`"
                        ),
                        FIX,
                    ));
                }
            }
        }
        _ => {
            return Err(usage(format!("malformed --calendar `{kind_arg}`"), FIX));
        }
    };
    let calendar = match head {
        "4-4-5" | "445" => FiscalCalendar::weeks("fiscal", WeekPattern::W445, end_rule, adj),
        "4-5-4" | "454" => FiscalCalendar::weeks("fiscal", WeekPattern::W454, end_rule, adj),
        "5-4-4" | "544" => FiscalCalendar::weeks("fiscal", WeekPattern::W544, end_rule, adj),
        "52-53" | "52/53" | "13x4" => FiscalCalendar::week_52_53("fiscal", end_rule, adj),
        _ => {
            return Err(usage(format!("unknown calendar `{kind_arg}`"), FIX));
        }
    };
    calendar.map_err(|e| usage(format!("calendar: {e}"), FIX))
}

const CUSTOM_CALENDAR_EXAMPLE: &str = "fa book create --name \"My Co\" --calendar custom --periods periods.json   (periods.json: {\"years\":[{\"fiscal_year\":2026,\"periods\":[{\"start\":\"2026-01-04\",\"end\":\"2026-01-31\"},...]}]})";

/// A custom calendar (plan §7.2 `Custom`, fa-94qd) from `--periods`: each
/// declared fiscal year's normal periods as inclusive `start`/`end` days,
/// each period starting the day after the one before it ends.
fn custom_calendar(path: &str, text: &str, adj: u8) -> Result<FiscalCalendar, Fail> {
    let bad = |why: String| usage(format!("--periods {path}: {why}"), CUSTOM_CALENDAR_EXAMPLE);
    let doc = parse_json(path, text)?;
    let years = doc
        .get("years")
        .and_then(Json::as_arr)
        .ok_or_else(|| bad("needs a `years` array".into()))?;
    let mut declared = Vec::with_capacity(years.len());
    for (i, year) in years.iter().enumerate() {
        let fiscal_year = match year.get("fiscal_year") {
            Some(Json::Int(n)) => i32::try_from(*n)
                .map_err(|_| bad(format!("years[{i}].fiscal_year {n} is not a year")))?,
            _ => return Err(bad(format!("years[{i}] needs an integer `fiscal_year`"))),
        };
        let periods = year
            .get("periods")
            .and_then(Json::as_arr)
            .ok_or_else(|| bad(format!("fiscal year {fiscal_year} needs a `periods` array")))?;
        let mut spans = Vec::with_capacity(periods.len());
        for (p, period) in periods.iter().enumerate() {
            let day = |field: &str| -> Result<DateDay, Fail> {
                let text = period.get(field).and_then(Json::as_str).ok_or_else(|| {
                    bad(format!(
                        "fiscal year {fiscal_year} period {} needs `{field}` as YYYY-MM-DD",
                        p + 1
                    ))
                })?;
                DateDay::parse(text).map_err(|e| {
                    bad(format!(
                        "fiscal year {fiscal_year} period {} {field} `{text}`: {e:?}",
                        p + 1
                    ))
                })
            };
            spans.push((day("start")?, day("end")?));
        }
        declared.push(
            fa_time::CustomYear::from_periods(fiscal_year, &spans)
                .map_err(|e| bad(e.to_string()))?,
        );
    }
    FiscalCalendar::custom("custom", declared, adj).map_err(|e| bad(e.to_string()))
}

fn book_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    if args.flag("--time-zone").is_some()
        && args.positional.get(1).map(String::as_str) != Some("create")
    {
        return Err(usage(
            "--time-zone declares the policy of a new book; it belongs to book create",
            "fa book create --name \"My Co\" --time-zone UTC",
        ));
    }
    if args.flag("--opening-date").is_some()
        && args.positional.get(1).map(String::as_str) != Some("create")
    {
        return Err(usage(
            "--opening-date declares the opening date of a new book; it belongs to book create",
            "fa book create --name \"My Co\" --opening-date YYYY-MM-DD",
        ));
    }
    if args.flag("--entity").is_some()
        && args.positional.get(1).map(String::as_str) != Some("create")
    {
        return Err(usage(
            "--entity declares legal entities of a new book; it belongs to book create",
            "fa book create --name \"My Co\" --entity HOLDCO",
        ));
    }
    match args.positional.get(1).map(String::as_str) {
        Some("create") => {
            if args.flag_all("--time-zone").len() > 1 {
                return Err(usage(
                    "--time-zone may be supplied only once",
                    "--time-zone UTC",
                ));
            }
            if args.flag_all("--opening-date").len() > 1 {
                return Err(usage(
                    "--opening-date may be supplied only once",
                    "--opening-date YYYY-MM-DD",
                ));
            }
            let time_zone_policy = match args.flag("--time-zone") {
                None => None,
                Some("UTC") => Some(fa_journal::TimeZonePolicy::Utc),
                Some(zone) => {
                    return Err(usage(
                        format!("time zone `{zone}` is not supported"),
                        "--time-zone UTC (the registered policy), or omit it to leave the policy undeclared",
                    ));
                }
            };
            let opening_date = match args.flag("--opening-date") {
                None => None,
                Some(d) => Some(DateDay::parse(d).map_err(|e| {
                    usage(
                        format!("--opening-date `{d}`: {e:?}"),
                        "--opening-date YYYY-MM-DD",
                    )
                })?),
            };
            if ctx.books.is_held() {
                return Err(usage(
                    "`fa book create` makes a new book directory; a daemon serves an existing one",
                    "run `fa book create --book <new dir> --name \"My Co\"` without a daemon for that directory",
                ));
            }
            let dir = book_dir(args, ctx.files.cwd.as_deref())?;
            let name = args.require("--name", "\"My Co\"")?;
            let units = fa_money::UnitRegistry::embedded().map_err(BookError::Registry)?;
            let base = args.flag("--base-unit").unwrap_or("USD");
            let base_unit = units.lookup(base).ok_or_else(|| {
                usage(
                    format!("unknown base unit `{base}`"),
                    "--base-unit USD|EUR|GBP|JPY|CHF|CAD|AUD|KWD",
                )
            })?;
            let mut entities = Vec::new();
            for raw in args.flag_all("--entity") {
                let parts: Vec<&str> = raw.splitn(3, ':').collect();
                let (code, ent_name, functional_unit) = match parts.as_slice() {
                    [code] => (*code, *code, base_unit),
                    [code, second] => {
                        if let Some(u) = units.lookup(second) {
                            (*code, *code, u)
                        } else {
                            (*code, *second, base_unit)
                        }
                    }
                    [code, ent_name, unit_code] => {
                        let u = units.lookup(unit_code).ok_or_else(|| {
                            usage(
                                format!("unknown entity functional unit `{unit_code}`"),
                                "--entity <code>[:<name>][:<functional_unit>]",
                            )
                        })?;
                        (*code, *ent_name, u)
                    }
                    _ => unreachable!(),
                };
                if code.trim().is_empty() || ent_name.trim().is_empty() {
                    return Err(usage(
                        format!("invalid --entity `{raw}`: code and name must be non-empty"),
                        "--entity <code>[:<name>][:<functional_unit>]",
                    ));
                }
                entities.push(fa_journal::LegalEntitySpec {
                    code: code.to_string(),
                    name: ent_name.to_string(),
                    functional_unit,
                });
            }
            let kind = args.flag("--calendar").unwrap_or("monthly");
            let adj: u8 = args
                .flag("--adjustment-periods")
                .unwrap_or("1")
                .parse()
                .map_err(|_| {
                    usage(
                        "--adjustment-periods must be 0..=4",
                        "--adjustment-periods 1",
                    )
                })?;
            let calendar = if kind == "custom" {
                if args.flag("--year-start-month").is_some() {
                    return Err(usage(
                        "a custom calendar's years and periods come from --periods; --year-start-month belongs to monthly calendars",
                        CUSTOM_CALENDAR_EXAMPLE,
                    ));
                }
                let path = args.require("--periods", "<periods.json> (or - for stdin)")?;
                custom_calendar(path, &ctx.files.read_text(path)?, adj)?
            } else {
                if args.flag("--periods").is_some() {
                    return Err(usage(
                        "--periods lists a custom calendar's periods; pass it with --calendar custom",
                        CUSTOM_CALENDAR_EXAMPLE,
                    ));
                }
                parse_cli_calendar(kind, args.flag("--year-start-month"), adj)?
            };
            let entropy = Entropy::production();
            let keys = BookKeys::generate(&entropy)?;
            let mut id = [0u8; 16];
            entropy.fill(&mut id).map_err(BookError::Entropy)?;
            let book_id = Id128(id);
            let spec = BookSpec {
                book_id,
                name: name.to_string(),
                base_unit,
                calendar,
                time_zone_policy,
                entities,
                opening_date,
            };
            spec.validate_functional_units(&units)
                .map_err(Fail::Refusal)?;
            spec.validate()
                .map_err(|m| usage(m, "fa book create --book <dir> --name \"My Co\""))?;
            let keys_file = keys_path(args, &dir, ctx.files.cwd.as_deref());
            // Every argument is valid: only now prepare the directory and
            // take its writer lease, before any key or store byte.
            ctx.books.lease_for_genesis(&dir)?;
            std::fs::create_dir_all(&dir).map_err(|e| BookError::Io(dir.clone(), e))?;
            keys.save(&keys_file)?;
            let book = Book::create_dir(&dir, keys, spec, entropy)?;
            out.at_book(&book)?;
            out.event(
                "book_created",
                vec![
                    ("book_id", s(book_id.to_hex())),
                    ("dir", s(dir.display().to_string())),
                    ("keys", s(keys_file.display().to_string())),
                    ("name", s(name)),
                    ("base_unit", s(base)),
                    ("calendar", s(&book.context().calendar.id)),
                ],
                &format!(
                    "created book {} in {} (keys: {}; keep them, they are never regenerated)",
                    book_id.to_hex(),
                    dir.display(),
                    keys_file.display()
                ),
            );
            Ok(())
        }
        Some("info") => {
            let book = ctx.books.open(args)?;
            let spec = book.spec()?;
            let base_unit = spec.base_unit;
            let entities: Vec<Json> = spec.entities.iter().map(|e| s(&e.code)).collect();
            let ctx = book.context();
            let periods = book.periods()?;
            let mut by_state: Vec<(String, i128)> = Vec::new();
            for p in &periods {
                match by_state.iter_mut().find(|(n, _)| *n == p.state.name()) {
                    Some((_, n)) => *n += 1,
                    None => by_state.push((p.state.name().to_string(), 1)),
                }
            }
            // The base unit journaled at genesis, not a guess.
            let unit = ctx
                .units
                .get(base_unit)
                .map(|u| u.code.clone())
                .unwrap_or_default();
            out.event(
                "book",
                vec![
                    ("book_id", s(ctx.book_id.to_hex())),
                    ("base_unit", s(&unit)),
                    ("calendar", s(&ctx.calendar.id)),
                    ("periods", Json::Int(periods.len() as i128)),
                    (
                        "periods_by_state",
                        Json::Obj(
                            by_state
                                .into_iter()
                                .map(|(k, v)| (k, Json::Int(v)))
                                .collect(),
                        ),
                    ),
                    ("accounts", Json::Int(book.accounts()?.len() as i128)),
                    (
                        "units_registered",
                        Json::Int(ctx.units.iter().count() as i128),
                    ),
                    ("entities", Json::Arr(entities)),
                ],
                &format!(
                    "book {} · calendar {} · {} periods · {} accounts · base unit {}",
                    ctx.book_id.to_hex(),
                    ctx.calendar.id,
                    periods.len(),
                    book.accounts()?.len(),
                    unit
                ),
            );
            Ok(())
        }
        Some("fork") => crate::scenario::fork_receivership(ctx, args),
        other => Err(unhandled("book", other)),
    }
}

fn demo_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    match args.positional.get(1).map(String::as_str) {
        Some("init") => {
            if args.flag_all("--scenario").len() > 1 {
                return Err(usage(
                    "--scenario may be supplied only once",
                    "--scenario retail|saas|manufacturing|nonprofit|holding|crypto|bank|ponzi|shell-network|worldcom|channel-stuffing",
                ));
            }
            if args.flag_all("--seed").len() > 1 {
                return Err(usage("--seed may be supplied only once", "--seed 7"));
            }
            let scenario_name = args.require(
                "--scenario",
                "retail|saas|manufacturing|nonprofit|holding|crypto|bank|ponzi|shell-network|worldcom|channel-stuffing",
            )?;
            let scenario = fa_demo::Scenario::parse(scenario_name).ok_or_else(|| {
                usage(
                    format!("unknown demo scenario `{scenario_name}`"),
                    "--scenario retail|saas|manufacturing|nonprofit|holding|crypto|bank|ponzi|shell-network|worldcom|channel-stuffing",
                )
            })?;
            let seed_raw = args.flag("--seed").unwrap_or("7");
            let seed: u64 = seed_raw.parse().map_err(|_| {
                usage(
                    format!("--seed `{seed_raw}` must be an unsigned integer"),
                    "--seed 7",
                )
            })?;
            if ctx.books.is_held() {
                return Err(usage(
                    "`fa demo init` initializes a new demo book directory; a daemon serves an existing one",
                    "run `fa demo init --scenario retail --seed 7 --book <new dir>` without a daemon for that directory",
                ));
            }
            let dir = book_dir(args, ctx.files.cwd.as_deref())?;
            let keys_file = keys_path(args, &dir, ctx.files.cwd.as_deref());
            ctx.books.prepare_create(&dir)?;
            let initialized =
                fa_demo::init_dir(&dir, &keys_file, scenario, seed).map_err(|e| match e {
                    fa_demo::DemoError::Book(b) => Fail::Book(b),
                    fa_demo::DemoError::Refusal(r) => Fail::Refusal(r),
                    fa_demo::DemoError::Verification(m) => Fail::Internal(m),
                })?;
            let book = ctx.books.open(args)?;
            out.at_book(&book)?;
            let planted_facts: Vec<Json> = initialized
                .planted_facts
                .iter()
                .map(|f| {
                    Json::Obj(vec![
                        ("id".into(), s(&f.id)),
                        ("kind".into(), s(&f.kind)),
                        ("period".into(), s(&f.period)),
                        (
                            "entry_vids".into(),
                            Json::Arr(
                                f.entry_vids
                                    .iter()
                                    .map(|v| s(format!("{:032x}", v.0)))
                                    .collect(),
                            ),
                        ),
                        ("summary".into(), s(&f.summary)),
                    ])
                })
                .collect();
            out.event(
                "demo_initialized",
                vec![
                    ("book_id", s(initialized.book_id.to_hex())),
                    ("dir", s(dir.display().to_string())),
                    ("keys", s(keys_file.display().to_string())),
                    ("readme", s(initialized.readme.display().to_string())),
                    ("name", s(&initialized.name)),
                    ("scenario", s(initialized.scenario.as_str())),
                    ("seed", Json::Int(i128::from(initialized.seed))),
                    ("base_unit", s(&initialized.base_unit)),
                    ("calendar", s(&initialized.calendar)),
                    ("chart_template", s(&initialized.chart_template)),
                    ("accounts", Json::Int(initialized.accounts as i128)),
                    ("periods", Json::Int(initialized.periods as i128)),
                    ("documents", Json::Int(initialized.documents as i128)),
                    ("entries", Json::Int(initialized.entries as i128)),
                    (
                        "migration_run_vid",
                        s(format!("{:032x}", initialized.migration_run_vid.0)),
                    ),
                    ("checkpoint_oid", s(hex(&initialized.checkpoint_oid.0))),
                    ("journal_digest", s(hex(&initialized.journal_digest))),
                    ("head_seq", Json::Int(i128::from(initialized.head_seq.0))),
                    ("planted_facts", Json::Arr(planted_facts)),
                ],
                &format!(
                    "initialized demo book {} ({}, seed {}) in {} · {} accounts · {} periods · {} entries · head #{}",
                    initialized.book_id.to_hex(),
                    initialized.scenario.as_str(),
                    initialized.seed,
                    dir.display(),
                    initialized.accounts,
                    initialized.periods,
                    initialized.entries,
                    initialized.head_seq.0
                ),
            );
            Ok(())
        }
        other => Err(unhandled("demo", other)),
    }
}

// ---------------------------------------------------------------------------
// chart
// ---------------------------------------------------------------------------

/// Parse a CLI invocation (`argv`) against the embedded verb registry,
/// expanding aliases, checking verb/subcommand/flag membership, and validating
/// pure flag syntax (`--calendar`, `--date`, `--opening-date`, `--fiscal-year`,
/// `--reason`, `--to`) without touching the filesystem or opening a book.
pub fn parse_cli_invocation(argv: &[String]) -> Result<Args, UsageError> {
    let reg = verbs::registry().map_err(|e| UsageError {
        message: format!("the embedded verb registry: {e}"),
        fix: "run `fa --help`".to_string(),
    })?;
    let aliased = apply_flag_aliases(argv, reg);
    let mut args = args::parse(&aliased, &reg.value_flags(), &reg.switches())?;
    if args.switch("--version") {
        return Ok(args);
    }
    args.positional = reg.expand_alias(&args.positional);
    let to_usage = |f: Fail| match f {
        Fail::Usage(u) => u,
        other => UsageError {
            message: match other {
                Fail::Internal(m) | Fail::Io(m) | Fail::Environment(m) => m,
                Fail::Refusal(r) => r.message,
                Fail::RefusalDetail(boxed) => boxed.0.message,
                Fail::Book(b) => b.to_string(),
                Fail::Verification { message, .. } => message,
                Fail::Usage(u) => u.message,
            },
            fix: "run `fa --help`".to_string(),
        },
    };
    let Some(word) = args.positional.first().cloned() else {
        check_flags(reg, None, &args).map_err(to_usage)?;
        return Ok(args);
    };
    let Some(verb) = reg.verb(&word) else {
        let mut known: Vec<&str> = reg.verbs.iter().map(|v| v.name.as_str()).collect();
        known.extend(reg.aliases.iter().map(|a| a.name.as_str()));
        return Err(UsageError {
            message: format!("unknown command `{word}`"),
            fix: match nearest(&word, &known) {
                Some(n) => format!("did you mean `fa {n}`?"),
                None => "run `fa --help`".to_string(),
            },
        });
    };
    if let Some(default) = &verb.default_subcommand
        && args.positional.len() == 1
        && !args.switch("--help")
    {
        args.positional.push(default.clone());
    }
    check_flags(reg, Some(verb), &args).map_err(to_usage)?;
    if args.switch("--help") {
        return Ok(args);
    }
    if !verb.subcommands.is_empty() {
        let joined = verb.subcommands.join("|");
        match args.positional.get(1) {
            Some(sub) if verb.subcommands.contains(sub) => {}
            Some(sub) => {
                return Err(UsageError {
                    message: format!("`fa {}` has no subcommand `{sub}`", verb.name),
                    fix: match nearest(
                        sub,
                        &verb
                            .subcommands
                            .iter()
                            .map(String::as_str)
                            .collect::<Vec<_>>(),
                    ) {
                        Some(n) => format!("did you mean `fa {} {n}`?", verb.name),
                        None => format!("fa {} {joined}", verb.name),
                    },
                });
            }
            None => {
                return Err(UsageError {
                    message: format!("`fa {}` needs a subcommand: {joined}", verb.name),
                    fix: format!("fa {} {joined} (see `fa {} --help`)", verb.name, verb.name),
                });
            }
        }
    }
    let _ = date_flag(&args, DateDay(0)).map_err(&to_usage)?;
    if let Some(d) = args.flag("--opening-date") {
        DateDay::parse(d).map_err(|e| UsageError {
            message: format!("--opening-date `{d}`: {e:?}"),
            fix: "--opening-date YYYY-MM-DD".to_string(),
        })?;
    }
    if args.flag("--calendar").is_some()
        || args.flag("--year-start-month").is_some()
        || args.flag("--adjustment-periods").is_some()
    {
        let kind = args.flag("--calendar").unwrap_or("monthly");
        let adj: u8 = args
            .flag("--adjustment-periods")
            .unwrap_or("1")
            .parse()
            .map_err(|_| UsageError {
                message: "--adjustment-periods must be 0..=4".to_string(),
                fix: "--adjustment-periods 1".to_string(),
            })?;
        // A custom calendar's syntax is its --periods file, read by book create.
        if kind != "custom" {
            parse_cli_calendar(kind, args.flag("--year-start-month"), adj).map_err(&to_usage)?;
        }
    }
    if let Some(fy) = args.flag("--fiscal-year") {
        fy.parse::<i32>().map_err(|_| UsageError {
            message: "--fiscal-year must be a year".to_string(),
            fix: "--fiscal-year 2026".to_string(),
        })?;
    }
    if let Some(sc) = args.flag("--scenario") {
        fa_demo::Scenario::parse(sc).ok_or_else(|| UsageError {
            message: format!("unknown demo scenario `{sc}`"),
            fix: "--scenario retail|saas|manufacturing|nonprofit|holding|crypto|bank|ponzi|shell-network|worldcom|channel-stuffing".to_string(),
        })?;
    }
    if let Some(sd) = args.flag("--seed") {
        sd.parse::<u64>().map_err(|_| UsageError {
            message: format!("--seed `{sd}` must be an unsigned integer"),
            fix: "--seed 7".to_string(),
        })?;
    }
    Ok(args)
}

/// Parse a chart JSON document into [`AccountSpec`] rows against `base_unit`
/// and `units` without opening a book or touching disk.
/// `fa chart open|close|promote` (plan §4.3, §5.6): an account's life cycle
/// after the chart is installed, each step one journaled `SchemaChange`
/// under `schema_change` authority. `open` takes one account object in the
/// chart format and its first effective day. `close` ends an account
/// (`[opened, closed)`: nothing posts on or after the day). `promote` makes a
/// leaf a summary account from that day. No date defaults to today: the CLI
/// never reads a clock.
fn chart_lifecycle(ctx: &mut Ctx<'_>, args: &Args, action: &str) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa chart open <account.json|-> --opened YYYY-MM-DD [--closed YYYY-MM-DD] | fa chart close <code> --on YYYY-MM-DD | fa chart promote <code> --on YYYY-MM-DD   [--key K]";
    if args.positional.len() != 3 {
        return Err(usage(
            match action {
                "open" => "chart open needs one account file (or - for stdin)",
                _ => "chart close and promote need one account code",
            },
            EXAMPLE,
        ));
    }
    for flag in ["--opened", "--closed", "--on", "--key", "--date"] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("chart {action} takes only one {flag}"),
                EXAMPLE,
            ));
        }
    }
    let applicable: &[&str] = match action {
        "open" => &["--opened", "--closed"],
        _ => &["--on"],
    };
    for flag in ["--opened", "--closed", "--on", "--template"] {
        if args.flag(flag).is_some() && !applicable.contains(&flag) {
            return Err(usage(
                format!("{flag} does not apply to chart {action}"),
                EXAMPLE,
            ));
        }
    }
    let day = |flag: &str| -> Result<Option<DateDay>, Fail> {
        args.flag(flag)
            .map(|text| {
                DateDay::parse(text)
                    .map_err(|e| usage(format!("{flag} `{text}`: {e:?}"), "YYYY-MM-DD"))
            })
            .transpose()
    };
    let required_day = |flag: &str| -> Result<DateDay, Fail> {
        day(flag)?.ok_or_else(|| {
            usage(
                format!("chart {action} needs {flag} YYYY-MM-DD (no date defaults to today)"),
                EXAMPLE,
            )
        })
    };
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["schema_change"])?;
    let out = &ctx.out;
    let target = args.positional[2].as_str();
    let date = date_flag(args, DateDay(0))?;
    let recorded = match action {
        "open" => {
            let opened = required_day("--opened")?;
            let closed = day("--closed")?;
            let text = ctx.files.read_text(target)?;
            let account = parse_json(target, &text)?;
            if !matches!(account, Json::Obj(_)) || account.get("accounts").is_some() {
                return Err(usage(
                    "chart open takes one account object, not a chart",
                    "{\"code\":\"6100\",\"name\":\"Office supplies\",\"type\":\"Expense\",\"unit\":\"USD\"}; fa chart import installs a whole chart",
                ));
            }
            let mut book = ctx.books.open(args)?;
            let base_unit = book.spec()?.base_unit;
            let wrapped = obj(vec![("accounts", Json::Arr(vec![account]))]).render();
            let specs = parse_chart_specs_fail(target, &wrapped, base_unit, &book.context().units)?;
            let [spec] = specs.as_slice() else {
                return Err(Fail::Internal(
                    "one account object parsed to several specs".into(),
                ));
            };
            let roles = crate::chart_role::chart_roles(target, &wrapped, &specs)?;
            let key = args
                .flag("--key")
                .map_or_else(|| format!("account-open:{}", spec.code), str::to_string);
            let recorded =
                book.open_account(spec, opened, closed, who, date, key.as_bytes(), &capability)??;
            // fa-kxc4: the opened account's roles, each its own control keyed
            // under the open's key, so a retried open completes them.
            let mut role_items = Vec::with_capacity(roles.len());
            for (code, role) in &roles {
                let role_spec = fa::account_role::AccountRoleSpec {
                    account: fa_model::account_vid(book.context().book_id, code),
                    role: role.clone(),
                    assigned: true,
                };
                let role_key = crate::chart_role::seeded_role_key(
                    format!("{key}:role:{role}").into_bytes(),
                    key.as_bytes(),
                    code,
                    role,
                );
                let held = book.record_account_role(&role_spec, who, &role_key, &capability)??;
                role_items.push(crate::chart_role::account_role_json(&held.control, code));
            }
            out.at_book(&book)?;
            (spec.code.clone(), recorded, role_items)
        }
        _ => {
            let on = required_day("--on")?;
            let mut book = ctx.books.open(args)?;
            if !book.accounts()?.iter().any(|a| a.code == target) {
                return Err(usage(
                    format!("no account `{target}` in this book"),
                    "fa chart list --json names the accounts",
                ));
            }
            let key = args.flag("--key").map_or_else(
                || format!("account-{action}:{target}:{}", on.render()),
                str::to_string,
            );
            let recorded = if action == "close" {
                book.close_account(target, on, who, date, key.as_bytes(), &capability)??
            } else {
                book.promote_to_summary(target, on, who, date, key.as_bytes(), &capability)??
            };
            out.at_book(&book)?;
            (target.to_string(), recorded, Vec::new())
        }
    };
    let (code, recorded, role_items) = recorded;
    out.event(
        "account_lifecycle",
        vec![
            ("action", s(action)),
            ("code", s(&code)),
            ("account", s(format!("{:032x}", recorded.account_vid.0))),
            (
                "control_entry",
                s(format!("{:032x}", recorded.control_entry.0)),
            ),
            ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
            ("roles", Json::Arr(role_items)),
        ],
        &format!(
            "{} account {code} (control entry {:032x}, recorded at {}){}",
            match action {
                "open" => "opened",
                "close" => "closed",
                _ => "promoted to summary",
            },
            recorded.control_entry.0,
            recorded.recorded_at.0,
            if recorded.already_recorded {
                "; already recorded, nothing new was written"
            } else {
                ""
            },
        ),
    );
    Ok(())
}

pub fn parse_chart_specs(
    path: &str,
    text: &str,
    base_unit: fa_money::UnitId,
    units: &fa_money::UnitRegistry,
) -> Result<Vec<AccountSpec>, UsageError> {
    parse_chart_specs_fail(path, text, base_unit, units).map_err(|f| match f {
        Fail::Usage(u) => u,
        _ => UsageError {
            message: "chart parse failure".to_string(),
            fix: "fa robot-docs examples".to_string(),
        },
    })
}

fn parse_chart_specs_fail(
    path: &str,
    text: &str,
    base_unit: fa_money::UnitId,
    units: &fa_money::UnitRegistry,
) -> Result<Vec<AccountSpec>, Fail> {
    let doc = parse_json(path, text)?;
    let rows = doc.get("accounts").and_then(Json::as_arr).ok_or_else(|| {
        usage(
            "chart: `accounts` must be an array",
            "fa robot-docs examples",
        )
    })?;
    let mut accounts = Vec::with_capacity(rows.len());
    for (i, row) in rows.iter().enumerate() {
        let what = format!("accounts[{i}]");
        let code = req_str(row, "code", &what)?;
        let name = row.get("name").and_then(Json::as_str).unwrap_or(code);
        let type_name = req_str(row, "type", &what)?;
        let account_type = AccountType::ALL
            .iter()
            .find(|(_, n, ..)| n.eq_ignore_ascii_case(type_name))
            .map(|(t, ..)| *t)
            .ok_or_else(|| {
                usage(
                    format!("{what}: unknown type `{type_name}`"),
                    "type: Asset|Liability|Equity|Revenue|Expense|Memo|Statistical|OffBalance",
                )
            })?;
        let normal_balance = AccountType(account_type).normal_balance().unwrap_or(0);
        let is_leaf = row.get("leaf").and_then(Json::as_bool).unwrap_or(true);
        let unit_policy = match row.get("unit").and_then(Json::as_str) {
            None | Some("any") => UnitPolicy::AnyUnit,
            Some("any-currency") => UnitPolicy::AnyCurrency,
            Some("base") => UnitPolicy::Single(base_unit),
            Some(u) => UnitPolicy::Single(units.lookup(u).ok_or_else(|| {
                usage(
                    format!("{what}: unknown unit `{u}`"),
                    "unit: USD|EUR|…|base|any|any-currency",
                )
            })?),
        };
        let parent_code = row.get("parent").and_then(Json::as_str).map(str::to_string);
        // Balance bounds (plan §5.4–5.5): exact decimals in the
        // account's single unit and its normal-balance sign.
        let bound = |key: &str| -> Result<Option<i128>, Fail> {
            let text = match row.get(key) {
                None | Some(Json::Null) => return Ok(None),
                Some(Json::Str(text)) => text,
                Some(_) => {
                    return Err(usage(
                        format!("{what}: `{key}` must be a decimal string"),
                        format!("{key}: \"0.00\" (exact, in the account's unit)"),
                    ));
                }
            };
            let UnitPolicy::Single(unit) = unit_policy else {
                return Err(usage(
                    format!("{what}: `{key}` needs the account's single unit"),
                    "unit: \"USD\" (a balance bound is stated in one registered unit)",
                ));
            };
            let code = units.get(unit).map(|u| u.code.clone()).unwrap_or_default();
            Amount::parse(&format!("{text} {code}"), units)
                .map(|a| Some(a.mantissa))
                .map_err(|e| {
                    usage(
                        format!("{what}: {key} `{text}`: {e:?}"),
                        format!("{key}: \"0.00\" (exact, at the unit's scale)"),
                    )
                })
        };
        let (lower, upper) = (bound("lower_bound")?, bound("upper_bound")?);
        // A lifetime limit bounds the account's whole history; a
        // period limit (a budget cap) bounds each fiscal period.
        let scope = match row.get("limit_scope") {
            None | Some(Json::Null) => fa_journal::LimitScope::Lifetime,
            Some(Json::Str(s)) if s == "lifetime" => fa_journal::LimitScope::Lifetime,
            Some(Json::Str(s)) if s == "period" => fa_journal::LimitScope::Period,
            Some(other) => {
                return Err(usage(
                    format!("{what}: limit_scope {} is not a scope", other.render()),
                    "limit_scope: \"lifetime\" (default) or \"period\" (a budget cap per fiscal period)",
                ));
            }
        };
        if row.get("limit_scope").is_some_and(|v| *v != Json::Null)
            && lower.is_none()
            && upper.is_none()
        {
            return Err(usage(
                format!("{what}: limit_scope names no bound to scope"),
                "add lower_bound and/or upper_bound, or drop limit_scope",
            ));
        }
        let limit = (lower.is_some() || upper.is_some()).then_some(BalanceLimit {
            lower,
            upper,
            scope,
        });
        accounts.push(AccountSpec {
            code: code.to_string(),
            name: name.to_string(),
            account_type,
            normal_balance,
            is_leaf,
            unit_policy,
            parent_code,
            limit,
        });
    }
    Ok(accounts)
}

fn chart_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let sub = args.positional.get(1).map(String::as_str);
    // The role flags belong to their own subcommands; anywhere else they
    // would be silently ignored.
    for (flag, used_by) in [("--remove", "role"), ("--as-known-at", "roles")] {
        let given = args.switch(flag) || args.flag(flag).is_some();
        if given && sub != Some(used_by) {
            return Err(usage(
                format!("{flag} is an input to chart {used_by} only"),
                "fa chart role <account> <role> [--remove] | fa chart roles [--as-known-at <seq>]",
            ));
        }
    }
    match sub {
        Some("role") => return crate::chart_role::role(ctx, args),
        Some("roles") => return crate::chart_role::roles(ctx, args),
        _ => {}
    }
    let who = ctx.principal(args);
    let out = &ctx.out;
    match sub {
        Some("import") => {
            // A chart comes from a file (or `-`), or from an embedded
            // template (plan §4.3, fa-48m): exactly one of the two.
            let capability = ctx.capability(args, &["schema_change"])?;
            let template = match args.flag("--template") {
                None => None,
                Some(name) => Some(templates::find(name).ok_or_else(|| {
                    let known: Vec<&str> = templates::TEMPLATES.iter().map(|t| t.name).collect();
                    usage(
                        format!("unknown chart template `{name}`"),
                        format!("fa chart templates --json lists them: {}", known.join(", ")),
                    )
                })?),
            };
            let (path, text) = match (template, args.positional.get(2)) {
                (Some(_), Some(file)) => {
                    return Err(usage(
                        format!("chart import takes a file or --template, not both (got `{file}`)"),
                        "fa chart import --template us-gaap-smb --book <dir>",
                    ));
                }
                (Some(t), None) => (format!("template:{}", t.name), t.text.to_string()),
                (None, Some(file)) => (file.clone(), ctx.files.read_text(file)?),
                (None, None) => {
                    return Err(usage(
                        "chart import needs a file or --template <name>",
                        "fa chart import chart.json --book <dir>  (or --template us-gaap-smb)",
                    ));
                }
            };
            let path = &path;
            let _ = parse_json(path, &text)?;
            let mut book = ctx.books.open(args)?;
            // `"unit": "base"` is the book's own base unit, journaled at
            // genesis, so one chart document serves a book in any currency.
            let base_unit = book.spec()?.base_unit;
            let units = &book.context().units;
            let accounts = parse_chart_specs_fail(path, &text, base_unit, units)?;
            let roles = crate::chart_role::chart_roles(path, &text, &accounts)?;
            let date = date_flag(args, DateDay(0))?;
            let key = match args.flag("--key") {
                Some(k) => k.as_bytes().to_vec(),
                None => templates::chart_key(&text).into_bytes(),
            };
            let installed = book.install_chart(&accounts, who, date, &key, &capability)??;
            // Each account role is its own control, keyed under the chart's
            // key, so a retried import completes them without duplicates.
            let mut role_items = Vec::with_capacity(roles.len());
            for (code, role) in &roles {
                let spec = fa::account_role::AccountRoleSpec {
                    account: fa_model::account_vid(book.context().book_id, code),
                    role: role.clone(),
                    assigned: true,
                };
                let role_key = crate::chart_role::seeded_role_key(
                    [key.as_slice(), format!(":role:{code}:{role}").as_bytes()].concat(),
                    &key,
                    code,
                    role,
                );
                let recorded = book.record_account_role(&spec, who, &role_key, &capability)??;
                role_items.push(crate::chart_role::account_role_json(
                    &recorded.control,
                    code,
                ));
            }
            out.at_book(&book)?;
            out.event(
                "chart_installed",
                vec![
                    ("accounts", Json::Int(installed.accounts as i128)),
                    (
                        "control_entry",
                        s(format!("{:032x}", installed.control_entry.0)),
                    ),
                    (
                        "recorded_at",
                        Json::Int(i128::from(installed.recorded_at.0)),
                    ),
                    ("template", template.map_or(Json::Null, |t| s(t.name))),
                    ("roles", Json::Arr(role_items)),
                ],
                &format!(
                    "installed {} accounts{} (control entry {:032x}, recorded at {}){}",
                    installed.accounts,
                    template.map_or_else(String::new, |t| format!(" from template {}", t.name)),
                    installed.control_entry.0,
                    installed.recorded_at.0,
                    if roles.is_empty() {
                        String::new()
                    } else {
                        format!("; {} account role(s) assigned", roles.len())
                    },
                ),
            );
            Ok(())
        }
        Some(action @ ("open" | "close" | "promote")) => chart_lifecycle(ctx, args, action),
        Some("templates") => {
            if let Some(extra) = args.positional.get(2) {
                return Err(usage(
                    format!("unexpected argument `{extra}`"),
                    "fa chart templates --json",
                ));
            }
            let mut items = Vec::with_capacity(templates::TEMPLATES.len());
            let mut human = Vec::with_capacity(templates::TEMPLATES.len());
            for template in templates::TEMPLATES {
                let listed = templates::listing(template).map_err(Fail::Internal)?;
                human.push(format!(
                    "{:<22} v{}  {:>3} accounts ({} leaves)  {}",
                    listed.name, listed.version, listed.accounts, listed.leaves, listed.description
                ));
                items.push(obj(vec![
                    ("name", s(listed.name)),
                    ("version", Json::Int(listed.version)),
                    ("description", s(&listed.description)),
                    ("accounts", Json::Int(listed.accounts as i128)),
                    ("leaves", Json::Int(listed.leaves as i128)),
                    ("key", s(&listed.key)),
                ]));
            }
            out.event(
                "chart_templates",
                vec![("templates", Json::Arr(items))],
                &human.join("\n"),
            );
            Ok(())
        }
        Some("list") => {
            let book = ctx.books.open(args)?;
            let rows = book.accounts()?;
            let units = &book.context().units;
            let items: Vec<Json> = rows
                .iter()
                .map(|a| Ok(obj(account_fields(a, units)?)))
                .collect::<Result<_, Fail>>()?;
            if out.json {
                out.event("accounts", vec![("accounts", Json::Arr(items))], "");
            } else {
                for a in &rows {
                    out.line(format!(
                        "{:<12} {:<32} {:<12} {}",
                        a.code,
                        a.name,
                        AccountType(a.account_type).name().unwrap_or("?"),
                        if a.is_leaf { "leaf" } else { "summary" }
                    ));
                }
            }
            Ok(())
        }
        Some("show") => {
            const EXAMPLE: &str = "fa chart show 1000 --book <dir> --json";
            let code = match args.positional.get(2) {
                Some(code) if args.positional.len() == 3 => code,
                _ => return Err(usage("chart show needs exactly one account code", EXAMPLE)),
            };
            let capability = ctx.capability(args, &["read"])?;
            let book = ctx.books.open(args)?;
            let chart = book.chart_at(book.head()?, &capability)??;
            let units = &book.context().units;
            let accounts = chart.accounts();
            let Some(account) = accounts.values().find(|a| &a.code == code) else {
                let codes: Vec<&str> = accounts.values().map(|a| a.code.as_str()).collect();
                return Err(usage(
                    format!("no account `{code}` in the chart"),
                    nearest(code, &codes).map_or_else(
                        || "fa chart list --json lists every code".to_string(),
                        |n| format!("did you mean `fa chart show {n}`? (fa chart list --json lists every code)"),
                    ),
                ));
            };
            let code_of = |vid: &VId| accounts.get(vid).map(|a| a.code.clone());
            let parent = chart.parents().get(&account.vid).and_then(code_of);
            let mut children: Vec<String> = chart
                .children()
                .get(&account.vid)
                .map(|c| c.iter().filter_map(code_of).collect())
                .unwrap_or_default();
            children.sort();
            let effectivity = chart.account_effectivity(account.vid).unwrap_or_default();
            let day = |d: Option<DateDay>| d.map_or(Json::Null, |d| s(d.render()));
            let side = if account.normal_balance == 0 {
                "debit"
            } else {
                "credit"
            };
            let mut fields = account_fields(account, units)?;
            fields.extend([
                ("normal_side", s(side)),
                ("parent", parent.as_ref().map_or(Json::Null, s)),
                ("children", Json::Arr(children.iter().map(s).collect())),
                ("opened", day(effectivity.opened)),
                ("closed", day(effectivity.closed)),
                ("promoted_on", day(effectivity.promoted_on)),
                ("created_at", Json::Int(i128::from(account.created_at.0))),
            ]);
            let human = format!(
                "{} {} ({}, {}, {}-normal){}{}{}",
                account.code,
                account.name,
                AccountType(account.account_type).name().unwrap_or("?"),
                if account.is_leaf { "leaf" } else { "summary" },
                side,
                parent.map_or_else(String::new, |p| format!("\n  parent: {p}")),
                if children.is_empty() {
                    String::new()
                } else {
                    format!("\n  children: {}", children.join(", "))
                },
                effectivity
                    .closed
                    .map_or_else(String::new, |d| format!("\n  closed on {}", d.render())),
            );
            out.event("chart_account", vec![("account", obj(fields))], &human);
            Ok(())
        }
        other => Err(unhandled("chart", other)),
    }
}

/// One chart row as `chart list` and `chart show` print it (shape `account`).
fn account_fields(
    a: &fa_journal::AccountRow,
    units: &fa_money::UnitRegistry,
) -> Result<Vec<(&'static str, Json)>, Fail> {
    let bound = |a: &fa_journal::AccountRow, m: Option<i128>| -> Result<Json, Fail> {
        match (a.unit_policy, m) {
            (UnitPolicy::Single(u), Some(m)) => Ok(s(render_amount(Amount::new(u, m), units)?)),
            _ => Ok(Json::Null),
        }
    };
    Ok(vec![
        ("lower_bound", bound(a, a.limit.and_then(|l| l.lower))?),
        ("upper_bound", bound(a, a.limit.and_then(|l| l.upper))?),
        (
            "limit_scope",
            a.limit.map_or(Json::Null, |l| {
                s(match l.scope {
                    fa_journal::LimitScope::Lifetime => "lifetime",
                    fa_journal::LimitScope::Period => "period",
                })
            }),
        ),
        ("code", s(&a.code)),
        ("name", s(&a.name)),
        ("type", s(AccountType(a.account_type).name().unwrap_or("?"))),
        ("leaf", Json::Bool(a.is_leaf)),
        (
            "unit",
            s(match a.unit_policy {
                UnitPolicy::Single(u) => registered_unit_code(u, units)?,
                UnitPolicy::AnyCurrency => "any-currency".into(),
                UnitPolicy::AnyUnit => "any".into(),
            }),
        ),
    ])
}

// ---------------------------------------------------------------------------
// period
// ---------------------------------------------------------------------------

/// What an `Open` of `code` mints inside its commit (plan §7.6, fa-7uhr):
/// every live schedule whose date the latest tick has reached and whose
/// reversal falls in this period, dated by that tick, but only when the
/// latest tick is corroborated (otherwise the open mints nothing and the
/// schedules wait for the reversal sweep). The commit rechecks the target's
/// applications and the availability law, which can still block one.
fn opening_mints(book: &Book, code: &str) -> Result<(Vec<Json>, Option<VId>), Fail> {
    let corroborated = book.corroborated_tick_at(book.head()?)?;
    let Some(tick) = book
        .latest_tick()?
        .filter(|latest| corroborated.is_some_and(|c| c.entry == latest.entry))
    else {
        return Ok((Vec::new(), None));
    };
    let rows = book
        .due_reversals()?
        .into_iter()
        .filter(|due| {
            matches!(&due.status, fa_journal::ReversalStatus::Waiting { period } if period == code)
        })
        .map(|due| {
            obj(vec![
                ("schedule", s(format!("{:032x}", due.schedule.vid.0))),
                ("target", s(format!("{:032x}", due.schedule.target.vid.0))),
                ("reverse_on", s(due.schedule.reverse_on.render())),
            ])
        })
        .collect();
    Ok((rows, Some(tick.entry)))
}

fn period_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let sub = args.positional.get(1).map(String::as_str);
    if args.switch("--dry-run") {
        if !matches!(
            sub,
            Some("open" | "soft-close" | "close" | "lock" | "reopen")
        ) {
            return Err(usage(
                "--dry-run prepares a period transition only",
                "fa period <transition> <code> --dry-run --json",
            ));
        }
        if args.flag("--plan-out").is_some()
            || args.flag("--plan").is_some()
            || !args.flag_all("--approval").is_empty()
        {
            return Err(usage(
                "--dry-run returns a proposal inline and cannot be combined with --plan-out, --plan, or --approval",
                "prepare with --dry-run first; an authorized owner commits the exact returned bytes separately",
            ));
        }
    }
    match sub {
        Some("create") => {
            let fy: i32 = args
                .require("--fiscal-year", "2026")?
                .parse()
                .map_err(|_| usage("--fiscal-year must be a year", "--fiscal-year 2026"))?;
            let principal = ctx.principal(args);
            let capability = ctx.capability(args, &["schema_change"])?;
            let mut book = ctx.books.open(args)?;
            let (seq, periods) = book.create_periods(fy, principal, &capability)??;
            out.at_book(&book)?;
            let codes: Vec<Json> = periods.iter().map(|p| s(&p.code)).collect();
            out.event("periods_created", vec![("fiscal_year", Json::Int(i128::from(fy))), ("periods", Json::Arr(codes)), ("recorded_at", Json::Int(i128::from(seq.0)))], &format!("recorded {} periods for FY{fy}; inspect birth states with `fa period list` and open current periods with `fa period open <code>`", periods.len()));
            Ok(())
        }
        Some("list") => {
            let book = ctx.books.open(args)?;
            let rows = book.periods()?;
            let items: Vec<Json> = rows
                .iter()
                .map(|p| {
                    obj(vec![
                        ("code", s(&p.code)),
                        ("state", s(p.state.name())),
                        ("kind", s(kind_name(p.kind))),
                        ("start", s(p.start.render())),
                        ("end", s(p.end.render())),
                        ("fiscal_year", Json::Int(i128::from(p.fiscal_year))),
                    ])
                })
                .collect();
            if out.json {
                out.event("periods", vec![("periods", Json::Arr(items))], "");
            } else {
                for p in &rows {
                    out.line(format!(
                        "{:<14} {:<10} {:<11} {} .. {}",
                        p.code,
                        p.state.name(),
                        kind_name(p.kind),
                        p.start.render(),
                        p.end.render()
                    ));
                }
            }
            Ok(())
        }
        Some(t @ ("open" | "soft-close" | "close" | "lock" | "reopen")) => {
            let code = args.positional.get(2).ok_or_else(|| {
                usage(
                    format!("period {t} needs a period code"),
                    format!("fa period {t} FY2026-P03 --book <dir>"),
                )
            })?;
            let transition = match t {
                "open" => PeriodTransition::Open,
                "soft-close" => PeriodTransition::SoftClose,
                "close" => PeriodTransition::Close,
                "lock" => PeriodTransition::Lock,
                _ => PeriodTransition::Reopen {
                    to: match args.flag("--to").unwrap_or("open") {
                        "open" => PeriodState::Open,
                        "soft-closed" => PeriodState::SoftClosed,
                        other => {
                            return Err(usage(format!("--to `{other}`"), "--to open|soft-closed"));
                        }
                    },
                },
            };
            // Every transition is journaled with its reason (plan §7.3,
            // fa-cvg): a registered name or code of the transition's scope.
            // A routine open or soft close defaults to Scheduled; close, lock
            // and reopen say why. The kernel refuses an unregistered code. A
            // plan carries the reason its approvals bind.
            let scope = fa_journal::period::reason_scope(transition);
            let reasons = ReasonCodes::embedded()
                .map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
            let reason: Option<u16> = match args.flag("--reason") {
                Some(_) if args.flag("--plan").is_some() => {
                    return Err(usage(
                        "--reason does not apply to --plan: the plan carries the reason its approvals bind",
                        format!("fa period {t} {code} --plan <file> [--approval <vid>]..."),
                    ));
                }
                None if args.flag("--plan").is_some() => None,
                Some(given) => Some(match given.parse::<u16>() {
                    Ok(number) => number,
                    Err(_) => reasons
                        .rows
                        .iter()
                        .find(|r| r.scope == scope && r.name == given)
                        .map(|r| r.code)
                        .ok_or_else(|| {
                            usage(
                                format!("--reason `{given}` is not a registered {scope} reason"),
                                format!("--reason <name>, one of: {}", reasons.listing(scope)),
                            )
                        })?,
                }),
                None if matches!(
                    transition,
                    PeriodTransition::Open | PeriodTransition::SoftClose
                ) =>
                {
                    Some(
                        reasons
                            .rows
                            .iter()
                            .find(|r| r.scope == scope && r.name == "Scheduled")
                            .map(|r| r.code)
                            .ok_or_else(|| {
                                Fail::Internal(format!(
                                    "reason_codes.toml has no {scope} Scheduled"
                                ))
                            })?,
                    )
                }
                None => {
                    return Err(usage(
                        format!("period {t} needs --reason: the journal records why"),
                        format!(
                            "fa period {t} {code} --reason <name>, one of: {}",
                            reasons.listing(scope)
                        ),
                    ));
                }
            };
            let who = ctx.principal(args);
            let op = fa_journal::policy::steward()
                .map_err(BookError::Kernel)?
                .transition_op("PeriodControl", fa_journal::transition_name(transition))
                .ok_or_else(|| {
                    Fail::Internal(format!("no PeriodControl {t} rule in sod_policy.toml"))
                })?;
            // Opening may publish due scheduled reversals atomically with the
            // period transition. The embedded owner authorizes both effects;
            // a launch-bound capability remains unchanged in `capability`.
            let implied_ops = if matches!(transition, PeriodTransition::Open) {
                vec![op.name(), "post"]
            } else {
                vec![op.name()]
            };
            let capability = ctx.capability(args, &implied_ops)?;
            let mut book = ctx.books.open(args)?;
            let current = book
                .periods()?
                .into_iter()
                .find(|p| &p.code == code)
                .map(|p| p.state.name())
                .unwrap_or("Unknown");
            let key = args
                .flag("--key")
                .map(|k| k.as_bytes().to_vec())
                .unwrap_or_else(|| format!("period:{code}:{current}:{t}").into_bytes());
            let approval_flags = args.flag_all("--approval");
            // Every branch but the plan commit has a reason of its own.
            let given_reason = || {
                reason.ok_or_else(|| Fail::Internal("only a period plan carries its reason".into()))
            };
            // A plan seals the description once (R4), so an approval
            // recorded by another principal, in another process, binds the
            // proposal the commit rebuilds from the plan's inputs. Plan files
            // resolve against the caller's working directory, as every file
            // argument does (a daemon writes and reads the client's).
            if args.switch("--dry-run") {
                let plan = book.plan_transition(code, transition, who, given_reason()?, &key)??;
                let digest = book.plan_digest(&plan)??;
                let bytes = plan
                    .encode()
                    .map_err(|e| Fail::Internal(format!("plan encoding: {e}")))?;
                let encoded = hex(&bytes);
                let (scheduled, reversal_tick) = if matches!(transition, PeriodTransition::Open) {
                    opening_mints(&book, code)?
                } else {
                    (Vec::new(), None)
                };
                let mints = if scheduled.is_empty() {
                    String::new()
                } else {
                    format!(
                        " The open has {} scheduled reversal candidate(s) dated by tick {}; publication requires current account, permission, availability, and budget checks.",
                        scheduled.len(),
                        reversal_tick.map_or(String::new(), |t| format!("{:032x}", t.0))
                    )
                };
                out.event(
                    "period_plan",
                    vec![
                        ("period", s(&plan.period_code)),
                        ("from", s(plan.from.name())),
                        ("to", s(plan.to.name())),
                        ("principal", s(format!("{:032x}", plan.principal_ref.0))),
                        ("proposal_digest", s(hex(&digest))),
                        ("bytes", s(&encoded)),
                        ("scope", s("period-transition-proposal")),
                        ("scheduled_reversals", Json::Arr(scheduled)),
                        (
                            "reversal_tick",
                            reversal_tick.map_or(Json::Null, |t| s(format!("{:032x}", t.0))),
                        ),
                    ],
                    &format!("{}: planned {} → {}; nothing was written.{mints} Approvals bind proposal {}. Commit authority and required approvals are checked separately.\nCanonical period plan bytes (hex):\n{encoded}", plan.period_code, plan.from.name(), plan.to.name(), hex(&digest)),
                );
                return Ok(());
            }
            if let Some(path) = args.flag("--plan-out") {
                if args.flag("--plan").is_some() || !approval_flags.is_empty() {
                    return Err(usage(
                        "--plan-out writes a plan and commits nothing",
                        format!(
                            "commit it with `fa period {t} {code} --plan <file> [--approval <vid>]...`"
                        ),
                    ));
                }
                if path.is_empty() || path == "-" {
                    return Err(usage(
                        "--plan-out names a new file; - is not an output file",
                        "use --dry-run to receive the complete plan bytes as hex on stdout",
                    ));
                }
                let plan = book.plan_transition(code, transition, who, given_reason()?, &key)??;
                let digest = book.plan_digest(&plan)??;
                let bytes = plan
                    .encode()
                    .map_err(|e| Fail::Internal(format!("plan encoding: {e}")))?;
                write_post_plan(&ctx.files, path, &bytes)?;
                out.event(
                    "period_planned",
                    vec![
                        ("period", s(&plan.period_code)),
                        ("from", s(plan.from.name())),
                        ("to", s(plan.to.name())),
                        ("proposal_digest", s(hex(&digest))),
                        ("plan", s(path)),
                    ],
                    &format!(
                        "{}: planned {} → {}; approvals bind proposal {}; commit with --plan {path}",
                        plan.period_code,
                        plan.from.name(),
                        plan.to.name(),
                        hex(&digest)
                    ),
                );
                return Ok(());
            }
            let tr = match args.flag("--plan") {
                Some(path) => {
                    let bytes =
                        read_plan_bytes(&ctx.files, path, b"fa:period-plan", "period transition")?;
                    let plan = fa_journal::TransitionPlan::decode(&bytes).map_err(|e| {
                        usage(
                            format!("{path} is not a period plan: {e}"),
                            format!("write one with `fa period {t} {code} --plan-out <file>`"),
                        )
                    })?;
                    if plan.period_code != *code || !plan.is_for(transition) {
                        return Err(usage(
                            format!(
                                "{path} plans `{}` {} → {}, not `{t} {code}`",
                                plan.period_code,
                                plan.from.name(),
                                plan.to.name()
                            ),
                            "commit a plan with the subcommand and period it was made for",
                        ));
                    }
                    let digest = book.plan_digest(&plan)??;
                    let approvals = approval_flags
                        .iter()
                        .map(|v| {
                            Ok(fa_model::ApprovalRef {
                                approval_vid: parse_vid(v, "--approval")?,
                                approved_digest: digest,
                            })
                        })
                        .collect::<Result<Vec<_>, Fail>>()?;
                    book.transition_planned(&plan, transition, &capability, &approvals)??
                }
                None if !approval_flags.is_empty() => {
                    return Err(usage(
                        "--approval binds a planned proposal",
                        format!(
                            "plan first with `fa period {t} {code} --plan-out <file>`, approve its proposal_digest with `fa approve --proposal`, then commit with `--plan <file> --approval <vid>`"
                        ),
                    ));
                }
                None => book.transition_period(
                    code,
                    transition,
                    who,
                    given_reason()?,
                    &key,
                    &capability,
                )??,
            };
            out.at_book(&book)?;
            out.effective(format!("period:{}", tr.period));
            if tr.already_recorded {
                // An identical retry (fa-l93 D13): the request's recorded
                // control entry, nothing new written.
                let Some((entry, recorded_at)) = book.read_entry(tr.control_entry)? else {
                    return Err(Fail::Book(BookError::Kernel(
                        fa_journal::KernelError::Corrupt(
                            "a recorded period control entry is absent".into(),
                        ),
                    )));
                };
                out.event(
                    "recorded",
                    vec![
                        ("vid", s(format!("{:032x}", tr.control_entry.0))),
                        ("entry_digest", s(hex(&entry.entry_digest))),
                        ("recorded_at", Json::Int(i128::from(recorded_at.0))),
                        ("requested", Json::Null),
                        ("moved", Json::Null),
                    ],
                    &format!(
                        "{}: {} → {} already recorded as {:032x} at {} (same idempotency key); nothing new was written",
                        tr.period,
                        tr.from.name(),
                        tr.to.name(),
                        tr.control_entry.0,
                        recorded_at.0
                    ),
                );
                return Ok(());
            }
            out.event(
                "period_transitioned",
                vec![
                    ("period", s(&tr.period)),
                    ("from", s(tr.from.name())),
                    ("to", s(tr.to.name())),
                    ("control_entry", s(format!("{:032x}", tr.control_entry.0))),
                    ("recorded_at", Json::Int(i128::from(tr.recorded_at.0))),
                ],
                &format!(
                    "{}: {} → {} (recorded at {})",
                    tr.period,
                    tr.from.name(),
                    tr.to.name(),
                    tr.recorded_at.0
                ),
            );
            Ok(())
        }
        other => Err(unhandled("period", other)),
    }
}

// ---------------------------------------------------------------------------
// approve
// ---------------------------------------------------------------------------

/// `fa approve --proposal <digest>` (R4) or `fa approve --review <file|-|hex> --digest <64-hex>`:
/// record an Approval binding a planned proposal's digest or a portable allocation/settlement
/// review under the caller's capability.
fn approve_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if let Some(review_arg) = args.flag("--review") {
        if args.flag("--proposal").is_some() {
            return Err(usage(
                "supply either --proposal <digest> or --review <file|-|hex> --digest <64-hex>, not both",
                "fa approve --review <file|-|hex> --digest <review_digest>",
            ));
        }
        let digest_text = args.require("--digest", "<64-hex review_digest>")?;
        let digest = parse_digest(digest_text, "--digest")?;
        let bytes = read_review_bytes(&ctx.files, review_arg, ctx.out.is_bound())?;
        return approve_any_review_bytes(ctx, args, &bytes, digest);
    }
    if args.flag("--digest").is_some() {
        return Err(usage(
            "--digest requires --review",
            "fa approve --review <file|-|hex> --digest <review_digest>, or fa approve --proposal <proposal_digest>",
        ));
    }
    let text = args.flag("--proposal").ok_or_else(|| {
        usage(
            "approve needs --proposal <digest> (or --review <file|-|hex> --digest <review_digest>)",
            "fa approve --proposal <proposal_digest> (64 hex, printed by `fa period <t> <code> --plan-out <file>`)",
        )
    })?;
    let digest = parse_digest(text, "--proposal")?;
    let capability = ctx.capability(args, &["approve"])?;
    let mut book = ctx.books.open(args)?;
    let approved = book.approve(capability, digest)??;
    emit_approved(&ctx.out, &book, approved)
}

fn emit_approved(out: &Out, book: &Book, approved: fa_journal::Approved) -> Result<(), Fail> {
    out.at_book(book)?;
    let approval = approved.approval();
    let recorded_at = approved.recorded_at();
    let (epoch, already) = match approved {
        fa_journal::Approved::Recorded {
            security_policy_epoch,
            ..
        } => (Json::Int(i128::from(security_policy_epoch)), false),
        fa_journal::Approved::AlreadyRecorded { .. } => (Json::Null, true),
    };
    out.event(
        "approved",
        vec![
            (
                "approval_vid",
                s(format!("{:032x}", approval.approval_vid.0)),
            ),
            ("approved_digest", s(hex(&approval.approved_digest))),
            ("security_policy_epoch", epoch),
            ("recorded_at", Json::Int(i128::from(recorded_at.0))),
            ("already_recorded", Json::Bool(already)),
        ],
        &format!(
            "approval {:032x} of proposal {} ({})",
            approval.approval_vid.0,
            hex(&approval.approved_digest),
            if already {
                "already recorded"
            } else {
                "recorded"
            }
        ),
    );
    Ok(())
}

/// Admit complete current authority before a command observes book metadata.
pub(crate) fn admit_whole_book_read(
    book: &Book,
    capability: &Capability,
    ops: &[fa_policy::Op],
    purpose: &str,
) -> Result<(), Fail> {
    fa_policy::admit_read(capability, capability.holder(), book.context().book_id)
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .and_then(|()| {
            for op in ops {
                fa_policy::require(capability, *op, purpose)?;
            }
            Ok(())
        })
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    book.read_scope(capability.holder(), capability)??;
    Ok(())
}

/// Issue, inspect or revoke a retained capability under current authority.
fn capability_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("revoke") => {
            let commitment_text = args.require("--commitment", "<64-hex>")?;
            let revoked_commitment = parse_digest(commitment_text, "--commitment")?;
            let capability = ctx.capability(args, &["read"])?;
            let mut book = ctx.books.open_admitted(args, |book| {
                admit_whole_book_read(
                    book,
                    &capability,
                    &[fa_policy::Op::IssueCapability],
                    "revoking a capability",
                )
            })?;
            let default_date = book
                .spec()?
                .opening_date
                .or_else(|| book.periods().ok()?.first().map(|p| p.start))
                .unwrap_or(DateDay(0));
            let date = date_flag(args, default_date)?;
            let key = args
                .flag("--key")
                .map(|k| k.as_bytes().to_vec())
                .unwrap_or_else(|| revoked_commitment.to_vec());
            let default_desc = format!("capability revoke {}", hex(&revoked_commitment));
            let description = args.flag("--description").unwrap_or(&default_desc);
            let revoked =
                book.revoke_capability(capability, revoked_commitment, date, &key, description)??;
            ctx.out.at_book(&book)?;
            ctx.out.event(
                "capability_revoked",
                vec![
                    (
                        "control_entry",
                        s(format!("{:032x}", revoked.control_entry.0)),
                    ),
                    ("recorded_at", Json::Int(i128::from(revoked.recorded_at.0))),
                    ("already_recorded", Json::Bool(revoked.already_recorded)),
                ],
                &format!(
                    "revoked capability {} at {} ({})",
                    hex(&revoked_commitment),
                    revoked.recorded_at.0,
                    if revoked.already_recorded {
                        "already recorded"
                    } else {
                        "recorded"
                    }
                ),
            );
            Ok(())
        }
        Some("issue") => capability_issue(ctx, args),
        Some("list") => {
            let capability = ctx.capability(args, &["read"])?;
            let book = ctx.books.open_admitted(args, |book| {
                admit_whole_book_read(book, &capability, &[], "listing issued capabilities")
            })?;
            let issued = book.issued_capabilities()?;
            ctx.out.at_book(&book)?;
            let rows: Vec<Json> = issued.iter().map(issued_json).collect();
            let human = if issued.is_empty() {
                "no capability has been issued in this book".to_string()
            } else {
                issued
                    .iter()
                    .map(|i| {
                        format!(
                            "{} holder {:032x} {} ops [{}] issued at {}{}",
                            hex(&i.commitment),
                            i.capability.holder().0,
                            i.capability.profile().name(),
                            i.capability
                                .ops()
                                .iter()
                                .map(|op| op.name())
                                .collect::<Vec<_>>()
                                .join(","),
                            i.issued_at.0,
                            i.revoked_at
                                .map(|at| format!(", revoked at {}", at.0))
                                .unwrap_or_default()
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            ctx.out.event(
                "capabilities_issued",
                vec![("capabilities", Json::Arr(rows))],
                &human,
            );
            Ok(())
        }
        Some("show") => {
            let commitment =
                parse_digest(args.require("--commitment", "<64-hex>")?, "--commitment")?;
            let capability = ctx.capability(args, &["read"])?;
            let book = ctx.books.open_admitted(args, |book| {
                admit_whole_book_read(book, &capability, &[], "showing an issued capability")
            })?;
            let Some(issued) = book.issued_capability(&commitment)? else {
                return Err(Refusal::new(
                    fa_journal::refusal::code::CAPABILITY_NOT_ISSUED,
                    exit::SAFETY,
                    format!(
                        "no capability with commitment {} was issued in this book",
                        hex(&commitment)
                    ),
                    "plan §14.2 (issuance is a journaled control entry; bead fa-v62)",
                    "list the book's issued capabilities with `fa capability list --json`",
                )
                .into());
            };
            ctx.out.at_book(&book)?;
            let row = issued_json(&issued);
            ctx.out.event(
                "capability_issued_detail",
                vec![("capability", row)],
                &format!(
                    "capability {} issued at {} to holder {:032x}",
                    hex(&issued.commitment),
                    issued.issued_at.0,
                    issued.capability.holder().0
                ),
            );
            Ok(())
        }
        other => Err(unhandled("capability", other)),
    }
}

/// One journaled issuance as robot data (plan §14.2, fa-v62).
fn issued_json(i: &fa_journal::IssuedCapability) -> Json {
    let cap = &i.capability;
    obj(vec![
        ("commitment", s(hex(&i.commitment))),
        ("control_entry", s(format!("{:032x}", i.control_entry.0))),
        ("holder", s(format!("{:032x}", cap.holder().0))),
        ("issuer", s(format!("{:032x}", cap.issuer().0))),
        ("profile", s(cap.profile().name())),
        (
            "ops",
            Json::Arr(cap.ops().iter().map(|op| s(op.name())).collect()),
        ),
        (
            "ceilings",
            Json::Arr(
                cap.ceilings()
                    .iter()
                    .map(|(unit, max)| {
                        obj(vec![
                            ("unit_id", Json::Int(i128::from(unit.0))),
                            ("max_mantissa", Json::Int(*max)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "daily_totals",
            Json::Arr(
                cap.daily_totals()
                    .iter()
                    .map(|(unit, max)| {
                        obj(vec![
                            ("unit_id", Json::Int(i128::from(unit.0))),
                            ("max_mantissa", Json::Int(*max)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "daily_root",
            cap.daily_root().map_or(Json::Null, |root| s(hex(&root))),
        ),
        (
            "expires_at",
            cap.expires_at()
                .map_or(Json::Null, |at| Json::Int(i128::from(at.0))),
        ),
        (
            "books",
            cap.books().map_or(Json::Null, |books| {
                Json::Arr(books.iter().map(|book| s(book.to_hex())).collect())
            }),
        ),
        (
            "accounts",
            cap.accounts()
                .map_or(Json::Null, |roots| Json::Arr(roots.iter().map(s).collect())),
        ),
        (
            "periods",
            cap.periods().map_or(Json::Null, |periods| {
                Json::Arr(periods.iter().map(s).collect())
            }),
        ),
        (
            "effective_through",
            cap.effective_bound()
                .map_or(Json::Null, |day| s(day.render())),
        ),
        (
            "known_at_most",
            cap.known_at_pin()
                .map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
        ),
        (
            "branch",
            cap.branch().map_or(Json::Null, |branch| s(branch.to_hex())),
        ),
        (
            "redaction",
            cap.redaction()
                .map_or(Json::Null, |contract| Json::Int(i128::from(contract))),
        ),
        ("issued_at", Json::Int(i128::from(i.issued_at.0))),
        (
            "revoked_at",
            i.revoked_at
                .map_or(Json::Null, |at| Json::Int(i128::from(at.0))),
        ),
    ])
}

/// An explicitly selected issuer token supplies exactly its retained
/// capability. It does not create a launch session or add embedded grants;
/// native current admission and issuance still judge every caveat.
fn capability_issuer(ctx: &Ctx<'_>, args: &Args) -> Result<Capability, Fail> {
    const FIX: &str = "fa capability issue --issuer-token <file> --holder <principal> --op <op>... --out <new-file> (drop --as and --grant; the issuer token supplies authority)";
    let paths = args.flag_all("--issuer-token");
    if paths.is_empty() {
        return ctx.capability(args, &["read"]);
    }
    if ctx.authority.is_some() {
        return Err(usage(
            "--issuer-token cannot replace a launch-bound capability",
            "invoke capability issue directly with the issuer token, outside a token-bound session",
        ));
    }
    for flag in ["--as", "--grant"] {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!(
                    "{flag} cannot be combined with --issuer-token: the token fixes the issuer and its operations"
                ),
                FIX,
            ));
        }
    }
    let path = match paths.as_slice() {
        [path] if !path.is_empty() && *path != "-" => *path,
        _ => {
            return Err(usage(
                "--issuer-token names exactly one nonempty token file; stdin is not accepted",
                FIX,
            ));
        }
    };
    let file = std::fs::File::open(ctx.files.resolve(path)).map_err(|e| {
        usage(
            format!("--issuer-token {path}: cannot read the token file: {e}"),
            FIX,
        )
    })?;
    // Files::read_bytes also accepts stdin and reads without a byte bound.
    // Credential input must stop at its canonical token limit before decode.
    let mut bytes = Vec::new();
    file.take((fa_policy::capability::MAX_TOKEN_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| {
            usage(
                format!("--issuer-token {path}: cannot read the token file: {e}"),
                FIX,
            )
        })?;
    if bytes.len() > fa_policy::capability::MAX_TOKEN_BYTES {
        return Err(usage("--issuer-token exceeds the 64 KiB token limit", FIX));
    }
    // Decode verifies the principal derives this holder, the secret proves
    // possession, and the complete capability bytes are canonical. Only the
    // capability leaves this helper; the issuer's secret is never retained.
    let token = fa_policy::CapabilityToken::decode(&bytes)
        .map_err(|e| usage(format!("--issuer-token {path}: {e}"), FIX))?;
    ctx.out.said.borrow_mut().owner_principal = Some(token.principal().to_string());
    ctx.out.said.borrow_mut().issuer_authority = Some(obj(vec![
        ("posture", s("issued-token")),
        ("principal", s(token.principal())),
        ("profile", s(token.capability().profile().name())),
        (
            "ops",
            Json::Arr(
                token
                    .capability()
                    .ops()
                    .iter()
                    .map(|op| s(op.name()))
                    .collect(),
            ),
        ),
    ]));
    Ok(token.capability().clone())
}

/// `fa capability issue` (plan §14.2, bead fa-v62): journal a holder-bound
/// capability for `--holder` under the caller's capability, then write the
/// holder's token (principal, capability, secret) to a new 0600 file. The
/// file is written only after the issuance commits, so a refused issuance
/// leaves no file; the secret is never journaled or printed.
fn capability_issue(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const FIX: &str = "fa capability issue --holder <principal> --profile agent|preparer|approver|controller|auditor|regulator|investigator|receiver|production|witness|human [--op <op>]... [--ceiling \"1000.00 USD\"]... [--daily-total \"1000.00 USD\"]... [--expires-at <seq>] [--period <code>]... [--effective-through YYYY-MM-DD] [--known-at-most <seq>] [--redaction <contract>] [--account <code>]... [--branch <32-hex>] [--class <EntryClass>]... [--operator-kind human|agent] [--requires-dry-run] [--book-scope] --out <new-file> (--issuer-token <file> or --as <issuer> --grant issue_capability --grant <each issued op>)";
    let holder = args.require("--holder", "<principal>")?.to_string();
    if holder.is_empty() || holder.len() > fa_policy::capability::MAX_TOKEN_PRINCIPAL_BYTES {
        return Err(usage("--holder is a 1..=256-byte principal name", FIX));
    }
    let raw_profile = args.flag("--profile").unwrap_or("agent");
    let (profile, selected_template) = if raw_profile.eq_ignore_ascii_case("human") {
        (fa_policy::Profile::Human, None)
    } else if let Some(template) = fa_policy::ProfileTemplate::from_name(raw_profile) {
        (template.base_profile(), Some(template))
    } else {
        return Err(usage(
            format!("--profile `{raw_profile}` is not an issuable profile or §14.4 template"),
            "--profile agent|preparer|approver|controller|auditor|regulator|investigator|receiver|production|witness|human",
        ));
    };
    let op_names = args.flag_all("--op");
    let ops = if op_names.is_empty() {
        match selected_template {
            Some(template) => template.default_ops().to_vec(),
            None => {
                return Err(usage("an issued capability names at least one --op", FIX));
            }
        }
    } else {
        let mut ops = Vec::with_capacity(op_names.len());
        for name in &op_names {
            ops.push(fa_policy::Op::from_name(name).ok_or_else(|| {
                usage(
                    format!("--op `{name}` is not a registered op"),
                    "`fa capabilities --json` lists the registered ops",
                )
            })?);
        }
        ops
    };
    let out_path = args.require("--out", "<new token file>")?.to_string();
    if out_path == "-" {
        return Err(usage(
            "--out names a new token file; the secret is never written to stdout",
            FIX,
        ));
    }
    let issuer = capability_issuer(ctx, args)?;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_whole_book_read(
            book,
            &issuer,
            &[fa_policy::Op::IssueCapability],
            "issuing a capability",
        )
    })?;
    // The token is written only after the issuance commits; refuse an
    // existing path first, so a grant is never journaled with its secret lost.
    if std::fs::symlink_metadata(ctx.files.resolve(&out_path)).is_ok() {
        return Err(usage(
            format!("--out {out_path} already exists; an existing file is never overwritten"),
            "choose a new --out path for the holder's token",
        ));
    }
    let holder_vid = fa_model::principal_vid(&holder);
    let mut issued = match selected_template {
        Some(template) => {
            Capability::from_template(holder_vid, template, Some(&ops), issuer.holder())
                .map_err(|e| usage(format!("the issued capability: {e}"), FIX))?
        }
        None => Capability::new(holder_vid, profile, &ops, issuer.holder())
            .map_err(|e| usage(format!("the issued capability: {e}"), FIX))?,
    };
    if args.switch("--book-scope")
        || selected_template.is_some_and(|t| t.required_caveats().contains(&"books"))
        || issuer.books().is_some()
    {
        issued = issued
            .for_books(&[book.context().book_id])
            .map_err(|e| usage(format!("--book-scope: {e}"), FIX))?;
    }
    if issuer.operator_kind() == fa_policy::OperatorKind::Agent {
        issued = issued
            .with_operator_kind(fa_policy::OperatorKind::Agent)
            .map_err(|e| usage(format!("inherited operator_kind: {e}"), FIX))?;
    }
    if let Some(raw_kind) = args.flag("--operator-kind") {
        let kind = fa_policy::OperatorKind::from_name(raw_kind).ok_or_else(|| {
            usage(
                format!("--operator-kind `{raw_kind}` must be `human` or `agent`"),
                "--operator-kind human|agent",
            )
        })?;
        issued = issued
            .with_operator_kind(kind)
            .map_err(|e| usage(format!("--operator-kind `{raw_kind}`: {e}"), FIX))?;
    }
    if issuer.has_requires_dry_run_caveat() || args.switch("--requires-dry-run") {
        issued = issued.with_requires_dry_run();
    }
    if let Some(text) = args.flag("--redaction") {
        let contract = text.parse::<u16>().map_err(|_| {
            usage(
                format!("--redaction `{text}` is not a u16 redaction contract id"),
                "--redaction <contract-id> (`redaction_contracts.toml`)",
            )
        })?;
        issued = issued
            .with_redaction(contract)
            .map_err(|e| usage(format!("--redaction `{text}`: {e}"), FIX))?;
    } else if let Some(contract) = issuer.redaction() {
        issued = issued
            .with_redaction(contract)
            .map_err(|e| usage(format!("inherited redaction: {e}"), FIX))?;
    }
    let accounts = args.flag_all("--account");
    if !accounts.is_empty() {
        issued = issued
            .for_accounts(&accounts)
            .map_err(|e| usage(format!("--account: {e}"), FIX))?;
    }
    if let Some(text) = args.flag("--branch") {
        let branch = if text.len() == 32 && text.is_ascii() {
            let mut raw = [0u8; 16];
            for (i, slot) in raw.iter_mut().enumerate() {
                *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| {
                    usage(
                        format!("--branch `{text}` is not a 32-hex branch id"),
                        "--branch <32-hex>",
                    )
                })?;
            }
            Id128(raw)
        } else {
            return Err(usage(
                format!("--branch `{text}` is not a 32-hex branch id"),
                "--branch <32-hex>",
            ));
        };
        issued = issued
            .on_branch(branch)
            .map_err(|e| usage(format!("--branch `{text}`: {e}"), FIX))?;
    }
    let class_names = args.flag_all("--class");
    if !class_names.is_empty() {
        let mut classes = Vec::with_capacity(class_names.len());
        for name in &class_names {
            classes.push(fa_model::EntryClass::from_name(name).ok_or_else(|| {
                usage(
                    format!("--class `{name}` is not a registered EntryClass"),
                    "`fa capabilities --json` lists the registered entry classes",
                )
            })?);
        }
        issued = issued
            .for_classes(&classes)
            .map_err(|e| usage(format!("--class: {e}"), FIX))?;
    }
    // A daily limit is a root's shared budget, never a fresh allowance for
    // each descendant. The kernel independently checks this lineage at issue.
    for (unit, maximum) in issuer.daily_totals() {
        issued = issued
            .with_daily_total(*unit, *maximum)
            .map_err(|e| usage(format!("inherited daily limit: {e}"), FIX))?;
    }
    if !issuer.daily_totals().is_empty() {
        let root = match issuer.daily_root() {
            Some(root) => root,
            None => issuer
                .commitment()
                .map_err(|e| Fail::Internal(format!("issuer commitment: {e}")))?,
        };
        issued = issued
            .with_daily_root(root)
            .map_err(|e| usage(format!("inherited daily root: {e}"), FIX))?;
    }
    for text in args.flag_all("--daily-total") {
        let amount = Amount::parse(text, &book.context().units).map_err(|e| {
            usage(format!("--daily-total `{text}`: {e:?}"), "--daily-total \"1000.00 USD\" (an exact positive gross-debit limit for each registered unit)")
        })?;
        issued = issued
            .with_daily_total(amount.unit, amount.mantissa)
            .map_err(|e| usage(format!("--daily-total `{text}`: {e}"), FIX))?;
    }
    for text in args.flag_all("--ceiling") {
        let amount = Amount::parse(text, &book.context().units).map_err(|e| {
            usage(
                format!("--ceiling `{text}`: {e:?}"),
                "--ceiling \"1000.00 USD\" (an exact amount at the unit's scale)",
            )
        })?;
        issued = issued
            .with_ceiling(amount.unit, amount.mantissa)
            .map_err(|e| usage(format!("--ceiling `{text}`: {e}"), FIX))?;
    }
    if let Some(text) = args.flag("--expires-at") {
        let seq = text.parse::<u64>().map_err(|_| {
            usage(
                format!("--expires-at `{text}` is not a commit sequence"),
                "--expires-at <seq> (the token is admitted while the head is below it)",
            )
        })?;
        issued = issued.expiring_at(CommitSeq(seq));
    }
    // Read scope caveats (plan §14.2): judged before any query a holder's
    // read or write constructs, never applied as a result filter.
    let periods = args.flag_all("--period");
    if !periods.is_empty() {
        let calendar = book.periods()?;
        if let Some(code) = periods
            .iter()
            .find(|code| !calendar.iter().any(|p| p.code == **code))
        {
            return Err(usage(
                format!("--period `{code}` is not a period of this book"),
                "`fa period list` lists the book's period codes",
            ));
        }
        issued = issued
            .for_periods(&periods)
            .map_err(|e| usage(format!("--period: {e}"), FIX))?;
    }
    if let Some(text) = args.flag("--effective-through") {
        let day = DateDay::parse(text).map_err(|e| {
            usage(
                format!("--effective-through `{text}`: {e}"),
                "--effective-through YYYY-MM-DD (the token reaches effective dates on or before it)",
            )
        })?;
        issued = issued.effective_through(day);
    }
    if let Some(text) = args.flag("--known-at-most") {
        let seq = text.parse::<u64>().map_err(|_| {
            usage(
                format!("--known-at-most `{text}` is not a commit sequence"),
                "--known-at-most <seq> (the token reads recorded frontiers at or before it, never the head beyond)",
            )
        })?;
        issued = issued.known_at_most(CommitSeq(seq));
    }
    if let Some(template) = selected_template {
        issued
            .validate_template(template)
            .map_err(|e| usage(format!("the issued `{template}` capability: {e}"), FIX))?;
    }
    let mut secret = [0u8; 32];
    Entropy::production()
        .fill(&mut secret)
        .map_err(BookError::Entropy)?;
    let issued = issued.holder_bound(fa_policy::possession_digest(&secret));
    let token = fa_policy::CapabilityToken::new(holder.clone(), issued.clone(), secret)
        .map_err(|e| Fail::Internal(format!("capability token: {e}")))?;
    let token_bytes = token
        .canonical_bytes()
        .map_err(|e| Fail::Internal(format!("capability token: {e}")))?;
    let commitment = issued
        .commitment()
        .map_err(|e| Fail::Internal(format!("capability commitment: {e}")))?;
    let default_date = book
        .spec()?
        .opening_date
        .or_else(|| book.periods().ok()?.first().map(|p| p.start))
        .unwrap_or(DateDay(0));
    let date = date_flag(args, default_date)?;
    let key = args
        .flag("--key")
        .map(|k| k.as_bytes().to_vec())
        .unwrap_or_else(|| commitment.to_vec());
    let default_desc = format!("capability issue to {holder}");
    let description = args.flag("--description").unwrap_or(&default_desc);
    let recorded = book.issue_capability(issuer, issued, date, &key, description)??;
    write_new_output_file(
        &ctx.files,
        &out_path,
        &token_bytes,
        "capability token",
        "--out",
    )?;
    ctx.out.at_book(&book)?;
    ctx.out.event(
        "capability_issued",
        vec![
            ("commitment", s(hex(&commitment))),
            (
                "control_entry",
                s(format!("{:032x}", recorded.control_entry.0)),
            ),
            ("holder", s(format!("{holder_vid:032x}", holder_vid = holder_vid.0))),
            ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
            ("token", s(&out_path)),
        ],
        &format!(
            "issued capability {} to {holder} at {}; token written to {out_path} (keep it 0600; launch fa-mcp with --token {out_path})",
            hex(&commitment),
            recorded.recorded_at.0
        ),
    );
    Ok(())
}

/// The undated control records' recorded date: `--date`, else the book's
/// opening date (as `fa capability` uses).
pub(crate) fn control_date(args: &Args, book: &Book) -> Result<DateDay, Fail> {
    let default_date = book
        .spec()?
        .opening_date
        .or_else(|| book.periods().ok()?.first().map(|p| p.start))
        .unwrap_or(DateDay(0));
    date_flag(args, default_date)
}

fn draft_name<'a>(args: &'a Args, sub: &str) -> Result<&'a str, Fail> {
    match args.positional.get(2) {
        Some(name) if args.positional.len() == 3 => Ok(name.as_str()),
        _ => Err(usage(
            format!("draft {sub} takes exactly one draft name"),
            format!("fa draft {sub} <name>"),
        )),
    }
}

/// One draft as robot data (plan §15.2, bead fa-s7x).
pub(crate) fn draft_json(view: &fa_journal::DraftView) -> Json {
    let closed = view.closed.as_ref();
    obj(vec![
        ("draft", s(format!("{:032x}", view.vid.0))),
        ("name", s(&view.body.name)),
        ("owner", s(format!("{:032x}", view.body.owner.0))),
        ("state", s(view.state.name())),
        ("opened_at", Json::Int(i128::from(view.opened_at.0))),
        ("intents", Json::Int(view.intents.len() as i128)),
        (
            "closed_at",
            closed.map_or(Json::Null, |c| Json::Int(i128::from(c.recorded_at.0))),
        ),
        (
            "closed_by",
            closed.map_or(Json::Null, |c| s(format!("{:032x}", c.by.0))),
        ),
        (
            "outcome",
            closed
                .and_then(|c| c.promoted.as_ref())
                .map_or(Json::Null, |(outcome, _)| s(format!("{:032x}", outcome.0))),
        ),
    ])
}

/// One planned intent as robot data: the entry its promotion will create.
pub(crate) fn draft_intent_json(book: &Book, planned: &fa_journal::PlannedIntent) -> Json {
    let p = planned.intent.proposal();
    let entry = fa_model::entry_vid(
        book.context().book_id,
        &p.principal_ref.0.to_le_bytes(),
        &p.idempotency_key,
    );
    obj(vec![
        ("record", s(format!("{:032x}", planned.record.0))),
        ("recorded_at", Json::Int(i128::from(planned.recorded_at.0))),
        ("entry", s(format!("{:032x}", entry.0))),
        ("class", s(p.class.name().unwrap_or("?"))),
        ("effective_date", s(p.effective_date.render())),
        ("idempotency_key", s(hex(&p.idempotency_key))),
        ("legs", Json::Int(p.legs.len() as i128)),
        ("principal", s(format!("{:032x}", p.principal_ref.0))),
    ])
}

/// `fa draft new|plan|list|show|promote|discard` (plan §15.2, bead fa-s7x):
/// an intent log that reaches trunk only when a principal holding `approve`
/// who is not its owner promotes it, replaying every intent in one batch.
fn draft_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let sub = args.positional.get(1).map(String::as_str);
    match sub {
        Some("new") => {
            let name = draft_name(args, "new")?.to_string();
            let capability = ctx.capability(args, &["post"])?;
            let mut book = ctx.books.open(args)?;
            let date = control_date(args, &book)?;
            let default_desc = format!("draft {name}");
            let description = args.flag("--description").unwrap_or(&default_desc);
            let opened = book.open_draft(capability, &name, date, description)??;
            ctx.out.at_book(&book)?;
            ctx.out.event(
                "draft_opened",
                draft_record_fields(&name, &opened),
                &format!(
                    "draft {name} {} at {}",
                    if opened.already_recorded {
                        "was already open"
                    } else {
                        "opened"
                    },
                    opened.recorded_at.0
                ),
            );
            Ok(())
        }
        Some("plan") => {
            let name = draft_name(args, "plan")?.to_string();
            let path = args.require("--intent", "entry.json (or - for stdin)")?;
            let text = ctx.files.read_text(path)?;
            let doc = parse_json(path, &text)?;
            plan_document_into_draft(ctx, args, &name, None, &doc)
        }
        Some("list") => {
            let book = ctx.books.open(args)?;
            let drafts = book.drafts()?;
            ctx.out.at_book(&book)?;
            let human = if drafts.is_empty() {
                "no drafts in this book".to_string()
            } else {
                drafts
                    .iter()
                    .map(|d| {
                        format!(
                            "{} {} {} intent(s), owner {:032x}",
                            d.body.name,
                            d.state.name(),
                            d.intents.len(),
                            d.body.owner.0
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            ctx.out.event(
                "drafts",
                vec![("drafts", Json::Arr(drafts.iter().map(draft_json).collect()))],
                &human,
            );
            Ok(())
        }
        Some("show") => {
            let name = draft_name(args, "show")?.to_string();
            let book = ctx.books.open(args)?;
            let Some(view) = book.draft(&name)? else {
                return Err(draft_unknown(&name));
            };
            ctx.out.at_book(&book)?;
            let intents: Vec<Json> = view
                .intents
                .iter()
                .map(|i| draft_intent_json(&book, i))
                .collect();
            let entries = view
                .closed
                .as_ref()
                .and_then(|c| c.promoted.as_ref())
                .map_or(Json::Null, |(_, entries)| {
                    Json::Arr(
                        entries
                            .iter()
                            .map(|e| s(format!("{:032x}", e.vid.0)))
                            .collect(),
                    )
                });
            ctx.out.event(
                "draft_detail",
                vec![
                    ("draft", draft_json(&view)),
                    ("intents", Json::Arr(intents)),
                    ("promoted_entries", entries),
                ],
                &format!(
                    "draft {name}: {}, {} planned intent(s)",
                    view.state.name(),
                    view.intents.len()
                ),
            );
            Ok(())
        }
        Some("promote") => {
            let name = draft_name(args, "promote")?.to_string();
            let capability = ctx.capability(args, &["approve"])?;
            let mut book = ctx.books.open(args)?;
            let date = control_date(args, &book)?;
            let default_desc = format!("promote draft {name}");
            let description = args.flag("--description").unwrap_or(&default_desc);
            let promoted = book.promote_draft(capability, &name, date, description)??;
            ctx.out.at_book(&book)?;
            ctx.out.event(
                "draft_promoted",
                vec![
                    ("draft", s(format!("{:032x}", promoted.draft.0))),
                    ("name", s(&name)),
                    (
                        "control_entry",
                        s(format!("{:032x}", promoted.control_entry.0)),
                    ),
                    ("outcome", s(format!("{:032x}", promoted.outcome.0))),
                    (
                        "entries",
                        Json::Arr(
                            promoted
                                .entries
                                .iter()
                                .map(|e| s(format!("{:032x}", e.vid.0)))
                                .collect(),
                        ),
                    ),
                    (
                        "periods",
                        Json::Arr(promoted.periods.iter().map(s).collect()),
                    ),
                    ("recorded_at", Json::Int(i128::from(promoted.recorded_at.0))),
                    ("already_recorded", Json::Bool(promoted.already_recorded)),
                ],
                &format!(
                    "draft {name} promoted: {} entr{} at {}{}",
                    promoted.entries.len(),
                    if promoted.entries.len() == 1 {
                        "y"
                    } else {
                        "ies"
                    },
                    promoted.recorded_at.0,
                    if promoted.already_recorded {
                        " (already recorded)"
                    } else {
                        ""
                    }
                ),
            );
            Ok(())
        }
        Some("discard") => {
            let name = draft_name(args, "discard")?.to_string();
            let capability = ctx.capability(args, &["post"])?;
            let mut book = ctx.books.open(args)?;
            let date = control_date(args, &book)?;
            let default_desc = format!("discard draft {name}");
            let description = args
                .flag("--reason")
                .or_else(|| args.flag("--description"))
                .unwrap_or(&default_desc);
            let discarded = book.discard_draft(capability, &name, date, description)??;
            ctx.out.at_book(&book)?;
            ctx.out.event(
                "draft_discarded",
                draft_record_fields(&name, &discarded),
                &format!("draft {name} discarded at {}", discarded.recorded_at.0),
            );
            Ok(())
        }
        other => Err(unhandled("draft", other)),
    }
}

fn draft_record_fields(
    name: &str,
    recorded: &fa_journal::DraftRecorded,
) -> Vec<(&'static str, Json)> {
    vec![
        ("draft", s(format!("{:032x}", recorded.draft.0))),
        ("name", s(name)),
        (
            "control_entry",
            s(format!("{:032x}", recorded.control_entry.0)),
        ),
        ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
        ("already_recorded", Json::Bool(recorded.already_recorded)),
    ]
}

fn draft_unknown(name: &str) -> Fail {
    Refusal::new(
        fa_journal::refusal::code::DRAFT_UNKNOWN,
        exit::REFUSAL,
        format!("this book has no draft named `{name}`"),
        "plan §15.2 (drafts; bead fa-s7x)",
        format!(
            "list the book's drafts with `fa draft list --json`, or open this one with `fa draft new {}`",
            fa_journal::refusal::command_word(name)
        ),
    )
    .at("draft", name)
    .into()
}

/// `fa post|reverse|reserve|resolve --draft <name>` and `fa draft plan`
/// (plan §15.2 `plan_in_draft`): build the intent exactly as the command
/// would post it, rehearse it under every posting law, and journal it into
/// the draft. Nothing reaches trunk until the draft is promoted.
fn plan_document_into_draft(
    ctx: &mut Ctx<'_>,
    args: &Args,
    name: &str,
    forced: Option<EntryClass>,
    doc: &Json,
) -> Result<(), Fail> {
    if args.switch("--dry-run") || args.flag("--plan-out").is_some() {
        return Err(usage(
            "--draft journals a rehearsed intent into the draft; it is not a dry run",
            "drop --dry-run/--plan-out to plan into the draft, or drop --draft to rehearse only",
        ));
    }
    if args.flag("--balancing").is_some() {
        return Err(usage(
            "a draft does not yet plan saturating --balancing requests",
            "plan an intent with explicit amounts",
        ));
    }
    if doc.get("intents").is_some() {
        return Err(usage(
            "a batch document cannot be planned into a draft; the draft is its own batch",
            "plan each intent into the draft; its promotion posts them as one batch",
        ));
    }
    let who = ctx.principal(args);
    let capability = ctx.capability(args, crate::fx::posting_ops(doc))?;
    let out = &ctx.out;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::fx::admit_intent_sources(book, &capability, doc)
    })?;
    let BuiltPost { request: req, .. } =
        build_post_request(out, &mut book, args, forced, doc, who, capability)?;
    let intent = PostIntent::new(req.proposal, req.approvals).map_err(|e| {
        usage(
            format!("cannot plan this entry: {e}"),
            "check the entry intent",
        )
    })?;
    let p = intent.proposal();
    let entry = fa_model::entry_vid(
        book.context().book_id,
        &p.principal_ref.0.to_le_bytes(),
        &p.idempotency_key,
    );
    let planned = book.plan_into_draft(req.capability, name, intent)??;
    out.at_book(&book)?;
    let (plan_digest, proposal_digest) = match &planned.plan {
        Some(plan) => (
            s(hex(&plan.digest().map_err(|e| {
                Fail::Internal(format!("encode the draft plan: {e}"))
            })?)),
            s(hex(&plan.certificate().proposal_digest)),
        ),
        None => (Json::Null, Json::Null),
    };
    let recorded = &planned.recorded;
    let mut fields = draft_record_fields(name, recorded);
    fields.push(("entry", s(format!("{:032x}", entry.0))));
    fields.push(("plan_digest", plan_digest));
    fields.push(("proposal_digest", proposal_digest));
    out.event(
        "draft_planned",
        fields,
        &format!(
            "planned into draft {name} (entry {:032x} on promotion){}",
            entry.0,
            if recorded.already_recorded {
                "; already planned"
            } else {
                ""
            }
        ),
    );
    Ok(())
}

/// `fa post|invoice|bill|receipt|payment --scenario <name>` and `fa scenario
/// run` (plan §15.2, bead fa-k07b): build the intent exactly as the command
/// would post it, rehearse it on the scenario's materialization (trunk at
/// the fork sequence plus every earlier intent of the scenario), and journal
/// it into the scenario. Trunk receives the record, never the entry.
pub(crate) fn plan_document_into_scenario(
    ctx: &mut Ctx<'_>,
    args: &Args,
    name: &str,
    forced: Option<EntryClass>,
    doc: &Json,
) -> Result<(), Fail> {
    if args.flag("--draft").is_some() {
        return Err(usage(
            "--draft and --scenario name different intent logs; nothing was planned",
            "plan into the draft with --draft <name>, or run in the scenario with --scenario <name>",
        ));
    }
    if args.switch("--dry-run") || args.flag("--plan-out").is_some() {
        return Err(usage(
            "--scenario rehearses the intent on the scenario and journals it there; it is not a dry run",
            "drop --dry-run/--plan-out to run the intent in the scenario, or drop --scenario to rehearse it on trunk",
        ));
    }
    if args.flag("--balancing").is_some() {
        return Err(usage(
            "a scenario does not yet run saturating --balancing requests",
            "run an intent with explicit amounts",
        ));
    }
    if doc.get("intents").is_some() {
        return Err(usage(
            "a batch document cannot run in a scenario yet; nothing was planned",
            "run each intent in the scenario in turn",
        ));
    }
    let who = ctx.principal(args);
    let capability = ctx.capability(args, crate::fx::posting_ops(doc))?;
    let out = &ctx.out;
    // Current authority to run intents in a scenario is admitted before the
    // book, its frontier or the scenario is disclosed.
    let mut book = ctx.books.open_admitted(args, |book| {
        book.admit_scenario_plan(&capability)??;
        crate::fx::admit_intent_sources(book, &capability, doc)?;
        Ok(())
    })?;
    let BuiltPost { request: req, .. } =
        build_post_request(out, &mut book, args, forced, doc, who, capability)?;
    let intent = PostIntent::new(req.proposal, req.approvals).map_err(|e| {
        usage(
            format!("cannot run this entry in a scenario: {e}"),
            "check the entry intent",
        )
    })?;
    let p = intent.proposal();
    let entry = fa_model::entry_vid(
        book.context().book_id,
        &p.principal_ref.0.to_le_bytes(),
        &p.idempotency_key,
    );
    let run = book.run_in_scenario(req.capability, name, intent)??;
    out.at_book(&book)?;
    let recorded = &run.recorded;
    out.event(
        "scenario_run",
        vec![
            ("scenario", s(format!("{:032x}", recorded.scenario.0))),
            ("name", s(name)),
            (
                "control_entry",
                s(format!("{:032x}", recorded.control_entry.0)),
            ),
            ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
            ("already_recorded", Json::Bool(recorded.already_recorded)),
            ("ordinal", Json::Int(run.ordinal as i128)),
            ("entry", s(format!("{:032x}", entry.0))),
            ("rehearsed", Json::Bool(run.rehearsed.is_some())),
        ],
        &format!(
            "ran in scenario {name} as intent #{} (entry {:032x} in the scenario; trunk unchanged){}",
            run.ordinal,
            entry.0,
            if recorded.already_recorded {
                "; already recorded"
            } else {
                ""
            }
        ),
    );
    Ok(())
}

/// A 64-hex digest from a flag.
pub(crate) fn parse_digest(text: &str, what: &str) -> Result<[u8; 32], Fail> {
    let bad = || {
        usage(
            format!("{what} `{text}` is not a 64-hex digest"),
            format!("{what} <proposal_digest printed by --plan-out>"),
        )
    };
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad());
    }
    let mut digest = [0u8; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
    }
    Ok(digest)
}

// ---------------------------------------------------------------------------
// calendar
// ---------------------------------------------------------------------------

/// `fa calendar show|periods` (plan §7.2, §15.3 Chart and registries;
/// fa-waow): the fiscal calendar the book journaled at genesis, and the
/// periods it generates for a fiscal year (whether or not `fa period create`
/// has recorded them yet). Reads only.
fn calendar_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa calendar show --json; fa calendar periods --fiscal-year 2026 --json";
    let sub = args.positional.get(1).map(String::as_str);
    if args.positional.len() != 2 || !matches!(sub, Some("show" | "periods")) {
        return Err(usage("calendar needs show or periods", EXAMPLE));
    }
    if sub == Some("show") && args.flag("--fiscal-year").is_some() {
        return Err(usage(
            "calendar show takes no --fiscal-year; calendar periods does",
            EXAMPLE,
        ));
    }
    let fiscal_year = if sub == Some("periods") {
        if args.flag_all("--fiscal-year").len() != 1 {
            return Err(usage(
                "calendar periods needs exactly one --fiscal-year",
                EXAMPLE,
            ));
        }
        let text = args.flag("--fiscal-year").unwrap_or_default();
        Some(
            text.parse::<i32>()
                .map_err(|_| usage(format!("--fiscal-year `{text}` is not a year"), EXAMPLE))?,
        )
    } else {
        None
    };
    let book = ctx.books.open(args)?;
    let calendar = book.context().calendar.clone();
    let Some(fy) = fiscal_year else {
        let (kind, year_start_month, pattern, end_rule) = match &calendar.kind {
            fa_time::CalendarKind::Monthly12 { year_start_month } => {
                ("monthly", Some(*year_start_month), None, None)
            }
            fa_time::CalendarKind::Weeks { pattern, end_rule } => (
                "weeks",
                None,
                Some(match pattern {
                    fa_time::WeekPattern::W445 => "4-4-5",
                    fa_time::WeekPattern::W454 => "4-5-4",
                    fa_time::WeekPattern::W544 => "5-4-4",
                }),
                Some(year_end_rule(end_rule)),
            ),
            fa_time::CalendarKind::Week5253 { end_rule } => {
                ("thirteen-period", None, None, Some(year_end_rule(end_rule)))
            }
            fa_time::CalendarKind::Custom { .. } => ("custom", None, None, None),
        };
        // A custom calendar defines only the years it declares.
        let declared: Option<Vec<i32>> = match &calendar.kind {
            fa_time::CalendarKind::Custom { years } => {
                Some(years.iter().map(|y| y.fiscal_year).collect())
            }
            _ => None,
        };
        ctx.out.event(
            "calendar",
            vec![
                ("id", s(&calendar.id)),
                ("kind", s(kind)),
                (
                    "year_start_month",
                    year_start_month.map_or(Json::Null, |m| Json::Int(i128::from(m))),
                ),
                ("week_pattern", pattern.map_or(Json::Null, s)),
                ("year_end_rule", end_rule.as_ref().map_or(Json::Null, s)),
                (
                    "adjustment_periods",
                    Json::Int(i128::from(calendar.adjustment_periods)),
                ),
                (
                    "fiscal_years",
                    declared.as_ref().map_or(Json::Null, |years| {
                        Json::Arr(years.iter().map(|y| Json::Int(i128::from(*y))).collect())
                    }),
                ),
            ],
            &format!(
                "calendar {} ({kind}{}{}{}), {} adjustment period(s)",
                calendar.id,
                year_start_month.map_or_else(String::new, |m| format!(
                    ", fiscal year starts in month {m}"
                )),
                end_rule.map_or_else(String::new, |r| format!(", year ends on the {r}")),
                declared.as_ref().map_or_else(String::new, |years| format!(
                    ", fiscal years {}..={}",
                    years.first().copied().unwrap_or_default(),
                    years.last().copied().unwrap_or_default()
                )),
                calendar.adjustment_periods
            ),
        );
        return Ok(());
    };
    let refused = |e: fa_time::DateError| {
        usage(
            format!("the book's calendar has no fiscal year {fy}: {e:?}"),
            EXAMPLE,
        )
    };
    let (start, end) = calendar.year_bounds(fy).map_err(refused)?;
    let periods = calendar.periods_for_year(fy).map_err(refused)?;
    let recorded: std::collections::BTreeSet<String> =
        book.periods()?.into_iter().map(|p| p.code).collect();
    let human = periods
        .iter()
        .map(|p| {
            format!(
                "{:<14} {:<11} {} .. {}{}",
                p.code,
                kind_name(p.kind),
                p.start.render(),
                p.end.render(),
                if recorded.contains(&p.code) {
                    ""
                } else {
                    "  (not created)"
                }
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    ctx.out.event(
        "calendar_periods",
        vec![
            ("fiscal_year", Json::Int(i128::from(fy))),
            ("start", s(start.render())),
            ("end", s(end.render())),
            (
                "periods",
                Json::Arr(
                    periods
                        .iter()
                        .map(|p| {
                            obj(vec![
                                ("code", s(&p.code)),
                                ("ordinal", Json::Int(i128::from(p.ordinal))),
                                ("kind", s(kind_name(p.kind))),
                                ("start", s(p.start.render())),
                                ("end", s(p.end.render())),
                                ("created", Json::Bool(recorded.contains(&p.code))),
                            ])
                        })
                        .collect(),
                ),
            ),
        ],
        &human,
    );
    Ok(())
}

/// A week-based year-end rule as one phrase.
fn year_end_rule(rule: &fa_time::YearEndRule) -> String {
    match rule {
        fa_time::YearEndRule::LastWeekdayOfMonth { weekday, month } => {
            format!("last {weekday:?} of month {month}")
        }
        fa_time::YearEndRule::WeekdayNearestEnd { weekday, month } => {
            format!("{weekday:?} nearest the end of month {month}")
        }
    }
}

fn kind_name(k: PeriodKind) -> &'static str {
    match k {
        PeriodKind::Normal => "Normal",
        PeriodKind::Adjustment => "Adjustment",
        PeriodKind::Opening => "Opening",
        PeriodKind::Closing => "Closing",
        PeriodKind::Historical => "Historical",
    }
}

// ---------------------------------------------------------------------------
// post
// ---------------------------------------------------------------------------

/// A 32-hex entry identity from an intent field.
pub(crate) fn parse_vid(text: &str, what: &str) -> Result<VId, Fail> {
    u128::from_str_radix(text, 16).map(VId).map_err(|_| {
        usage(
            format!("{what} `{text}` is not a 32-hex vid"),
            format!("{what}: the `vid` from the posted event"),
        )
    })
}

/// The `legs` array of an intent: each leg with its optional `source_ordinal`
/// (meaningful only for a Resolution(Posts)).
/// A leg's `settles` array: `{entry, ordinal, amount}` per application; the
/// entry's current digest is read from the book so the handle self-verifies.
fn parse_settles(
    leg_doc: &Json,
    what: &str,
    ctx: &BookContext,
    book: &Book,
    earlier: &batch_plan::PriorEntries,
) -> Result<Vec<fa_model::Settlement>, Fail> {
    let Some(list) = leg_doc.get("settles") else {
        return Ok(Vec::new());
    };
    let Some(list) = list.as_arr() else {
        return Err(usage(
            format!("{what}: `settles` must be an array"),
            "settles: [{\"entry\": \"<vid>\", \"ordinal\": 0, \"amount\": \"300.00 USD\"}]",
        ));
    };
    let mut out = Vec::with_capacity(list.len());
    for (j, item) in list.iter().enumerate() {
        let what = format!("{what}.settles[{j}]");
        let vid = parse_vid(req_str(item, "entry", &what)?, &format!("{what}.entry"))?;
        let Some(target) = batch_plan::target_entry(book, earlier, vid)? else {
            return Err(usage(
                format!("{what}: no entry {:032x} in this book", vid.0),
                "fa open-items --account <code> lists the open items to apply to",
            ));
        };
        let ordinal = match item.get("ordinal") {
            Some(Json::Int(n)) => u16::try_from(*n).map_err(|_| {
                usage(
                    format!("{what}: ordinal {n} is out of range"),
                    "ordinal: the 0-based index of the open item's leg",
                )
            })?,
            Some(other) => match other.as_str().and_then(|t| t.parse::<u16>().ok()) {
                Some(n) => n,
                None => {
                    return Err(usage(
                        format!("{what}: ordinal must be a small non-negative integer"),
                        "ordinal: the 0-based index of the open item's leg",
                    ));
                }
            },
            None => 0,
        };
        let amount_s = req_str(item, "amount", &what)?;
        let amount = Amount::parse(amount_s, &ctx.units).map_err(|e| {
            usage(
                format!("{what}: amount `{amount_s}`: {e:?}"),
                "amount: \"300.00 USD\" (exact, in the leg's unit)",
            )
        })?;
        out.push(fa_model::Settlement {
            target: target.entry_ref(vid),
            ordinal,
            amount,
        });
    }
    Ok(out)
}

fn parse_legs(
    doc: &Json,
    ctx: &BookContext,
    book: &Book,
    earlier: &batch_plan::PriorEntries,
) -> Result<Vec<(LegPayload, Option<u16>)>, Fail> {
    let legs_doc = doc.get("legs").and_then(Json::as_arr).ok_or_else(|| {
        usage(
            "intent: `legs` must be an array (or `reverses` a vid)",
            "fa robot-docs examples",
        )
    })?;
    let mut legs = Vec::with_capacity(legs_doc.len());
    for (i, l) in legs_doc.iter().enumerate() {
        let what = format!("legs[{i}]");
        if l.get("base_amount").is_some() || l.get("base_totals").is_some() {
            return Err(usage(
                format!("{what}: functional values must be derived from retained Rate evidence"),
                "remove base_amount/base_totals and supply intent.fx with a named law and Rate document OIDs",
            ));
        }
        let side = match req_str(l, "side", &what)? {
            "debit" | "dr" | "Debit" => Side::Debit,
            "credit" | "cr" | "Credit" => Side::Credit,
            other => {
                return Err(usage(
                    format!("{what}: side `{other}`"),
                    "side: debit|credit",
                ));
            }
        };
        let account = req_str(l, "account", &what)?;
        let amount_s = req_str(l, "amount", &what)?;
        let amount = Amount::parse(amount_s, &ctx.units).map_err(|e| {
            usage(
                format!("{what}: amount `{amount_s}`: {e:?}"),
                "amount: \"1500.00 USD\" (exact, at the unit's scale, non-negative)",
            )
        })?;
        let ordinal = match l.get("source_ordinal") {
            None => None,
            Some(Json::Int(n)) => Some(u16::try_from(*n).map_err(|_| {
                usage(
                    format!("{what}: source_ordinal {n} is out of range"),
                    "source_ordinal: the 0-based index of the hold leg this leg draws from",
                )
            })?),
            Some(other) => match other.as_str().and_then(|t| t.parse::<u16>().ok()) {
                Some(n) => Some(n),
                None => {
                    return Err(usage(
                        format!("{what}: source_ordinal must be a small non-negative integer"),
                        "source_ordinal: the 0-based index of the hold leg this leg draws from",
                    ));
                }
            },
        };
        let memo = match l.get("memo") {
            None | Some(Json::Null) => None,
            Some(Json::Str(m)) if m.is_empty() => None,
            Some(Json::Str(m)) => Some(book.seal_text(m)?),
            Some(_) => {
                return Err(usage(
                    format!("{what}: memo must be a string"),
                    "memo: \"optional leg memo\"",
                ));
            }
        };
        let mut leg = LegPayload::simple(side, account_vid(ctx.book_id, account), amount);
        leg.memo = memo;
        leg.settles = parse_settles(l, &what, ctx, book, earlier)?;
        // A leg names its legal entity (required in a multi-entity book)
        // and its counterparty by code; the kernel checks both exist
        // (plan §4.1, §4.5). Dimension ids ascend: entity 1, the registered
        // kinds 2..=9, party 12.
        let code_field = |field: &str| -> Result<Option<&str>, Fail> {
            match l.get(field) {
                None | Some(Json::Null) => Ok(None),
                Some(Json::Str(code)) if !code.is_empty() => Ok(Some(code.as_str())),
                Some(_) => Err(usage(
                    format!("{what}: {field} must be a non-empty code"),
                    "legs: [{\"side\": \"debit\", \"account\": \"1200\", \"amount\": \"10.00 USD\", \"entity\": \"ACME\", \"party\": \"C-17\"}]",
                )),
            }
        };
        if let Some(code) = code_field("entity")? {
            leg.dimension_set.push((
                fa_model::LEGAL_ENTITY_DIMENSION,
                fa_model::entity_value_vid(ctx.book_id, code),
            ));
        }
        if let Some(code) = code_field("party")? {
            leg.dimension_set.push((
                fa_model::PARTY_DIMENSION,
                fa_model::party_value_vid(ctx.book_id, code),
            ));
        }
        // The registered dimensions (cost center, project, ...; fa-ficc),
        // kept ascending by dimension id as the model requires.
        leg.dimension_set
            .extend(crate::dimension::leg_dimensions(l, &what, ctx.book_id)?);
        leg.dimension_set.sort_by_key(|(dimension, _)| *dimension);
        legs.push((leg, ordinal));
    }
    Ok(legs)
}

fn post_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    post_with(ctx, args, None)
}

/// Reverse an identified entry without making the operator re-enter its
/// legs. The original effective date is the default, never today's date or
/// the next open period; any explicit date still passes the kernel's law.
/// `fa reclass <vid> --from <account> --to <account> --amount "<amount>"
/// --reason <name>` (plan §8.2, Appendix B `Reclass`; bead fa-xvba): a
/// Reclassification citing the target with `Reclassifies`, moving `amount`
/// of its leg on `from` to `to` with the leg's side and dimensions. The
/// date, period and evidence default to the target's; the default key is
/// `reclass:<target>:<from>:<to>:<amount>`.
fn reclass_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa reclass <vid> --from 6100 --to 6200 --amount \"300.00 USD\" --reason WrongAccount [--effective YYYY-MM-DD] [--description <text>] [--key K] [--dry-run]";
    if args.positional.len() != 2 {
        return Err(usage("reclass needs exactly one entry vid", EXAMPLE));
    }
    for flag in [
        "--from",
        "--to",
        "--amount",
        "--reason",
        "--effective",
        "--period",
        "--key",
        "--description",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(format!("reclass takes only one {flag}"), EXAMPLE));
        }
    }
    let target = args.positional[1]
        .strip_prefix("E:")
        .unwrap_or(&args.positional[1]);
    let vid = parse_vid(target, "reclass target")?;
    let need = |flag: &str| {
        args.flag(flag)
            .ok_or_else(|| usage(format!("reclass needs {flag}"), EXAMPLE))
    };
    let (from, to, amount) = (need("--from")?, need("--to")?, need("--amount")?);
    let key = args.flag("--key").map_or_else(
        || format!("reclass:{:032x}:{from}:{to}:{amount}", vid.0),
        str::to_string,
    );
    let mut fields = vec![
        ("class", s("Reclassification")),
        ("reclassifies", s(format!("{:032x}", vid.0))),
        (
            "moves",
            Json::Arr(vec![obj(vec![
                ("from", s(from)),
                ("to", s(to)),
                ("amount", s(amount)),
            ])]),
        ),
        ("idempotency_key", s(key)),
    ];
    for (flag, field) in [
        ("--reason", "reason"),
        ("--effective", "effective_date"),
        ("--period", "effective_period"),
        ("--description", "description"),
    ] {
        if let Some(value) = args.flag(flag) {
            fields.push((field, s(value)));
        }
    }
    post_document(ctx, args, Some(EntryClass::RECLASSIFICATION), obj(fields))
}

pub(crate) fn reverse_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "reverse needs exactly one entry vid",
            "fa reverse <vid> --reason WrongAccount [--effective YYYY-MM-DD]",
        ));
    }
    for flag in [
        "--reason",
        "--effective",
        "--period",
        "--key",
        "--description",
        "--replace-with",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("reverse takes only one {flag}"),
                "fa reverse <vid> --reason WrongAccount [--effective YYYY-MM-DD]",
            ));
        }
    }
    let target = args.positional[1]
        .strip_prefix("E:")
        .unwrap_or(&args.positional[1]);
    let vid = parse_vid(target, "reverse target")?;
    let key = args
        .flag("--key")
        .map(str::to_string)
        .unwrap_or_else(|| format!("reverse:{:032x}", vid.0));
    let mut fields = vec![
        ("class", s("Reversal")),
        ("reverses", s(format!("{:032x}", vid.0))),
        ("idempotency_key", s(key)),
    ];
    for (flag, field) in [
        ("--reason", "reason"),
        ("--effective", "effective_date"),
        ("--period", "effective_period"),
        ("--description", "description"),
    ] {
        if let Some(value) = args.flag(flag) {
            fields.push((field, s(value)));
        }
    }
    if let Some(path) = args.flag("--replace-with") {
        return correction(ctx, args, vid, &obj(fields), path);
    }
    post_document(ctx, args, Some(EntryClass::REVERSAL), obj(fields))
}

/// `fa reverse <vid> --replace-with <intent>` (plan §8.2, bead fa-giar): the
/// target's exact Reversal and its corrected Replacement commit as one pair,
/// both or neither, under the reversal's reason. The replacement intent is an
/// ordinary entry intent without `class` or a supersession field; its date,
/// period and key default to the target's date, the target's period and
/// `replace:<target vid>`.
fn correction(
    ctx: &mut Ctx<'_>,
    args: &Args,
    vid: VId,
    reversal: &Json,
    path: &str,
) -> Result<(), Fail> {
    const FIX: &str = "fa reverse <vid> --reason <name> --replace-with <corrected entry intent>; the intent carries the corrected legs (and optionally effective_date, description, evidence)";
    check_post_planning_options(args)?;
    if !args.flag_all("--draft").is_empty() {
        return Err(usage(
            "a correction pair cannot be planned into a draft yet; nothing was posted",
            "plan the reversal into the draft with fa reverse <vid> --reason <name> --draft <name>, or post the pair to trunk",
        ));
    }
    let text = ctx.files.read_text(path)?;
    let doc = parse_json(path, &text)?;
    let Json::Obj(supplied) = &doc else {
        return Err(usage("the replacement intent must be an object", FIX));
    };
    for field in ["class", "reverses", "reason", "resolves", "intents"] {
        if doc.get(field).is_some() {
            return Err(usage(
                format!(
                    "the replacement intent takes no `{field}`: fa reverse supplies the class, the target and the reason"
                ),
                FIX,
            ));
        }
    }
    let who = ctx.principal(args);
    let capability = ctx.capability(args, crate::fx::posting_ops(&doc))?;
    let out = &ctx.out;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::fx::admit_intent_sources(book, &capability, &doc)
    })?;
    let Some((target, _)) = book.read_entry(vid)? else {
        return Err(usage(
            format!("reverse: no entry {:032x} in this book", vid.0),
            "fa entry show <vid> to check the identity",
        ));
    };
    let mut fields = supplied.clone();
    fields.push(("class".into(), s("Replacement")));
    if doc.get("effective_date").is_none() {
        fields.push((
            "effective_date".into(),
            s(target.proposal.effective_date.to_string()),
        ));
        if doc.get("effective_period").is_none()
            && let Some(period) = &target.proposal.effective_period
        {
            fields.push(("effective_period".into(), s(&period.code)));
        }
    }
    if doc.get("idempotency_key").is_none() {
        fields.push((
            "idempotency_key".into(),
            s(format!("replace:{:032x}", vid.0)),
        ));
    }
    let BuiltPost {
        request: reversal_req,
        reversal_detail,
        ..
    } = build_post_request(
        out,
        &mut book,
        args,
        Some(EntryClass::REVERSAL),
        reversal,
        who,
        capability.clone(),
    )?;
    let (target_hex, reason) = reversal_detail
        .ok_or_else(|| Fail::Internal("a typed reversal was built without its reason".into()))?;
    let BuiltPost {
        request: mut replacement_req,
        ..
    } = build_post_request(
        out,
        &mut book,
        args,
        None,
        &Json::Obj(fields),
        who,
        capability,
    )?;
    replacement_req
        .proposal
        .supersession
        .push(fa_model::Supersession {
            target: target.entry_ref(vid),
            kind: fa_model::SupersessionKind::Replaces,
            reason_code: reason.code,
        });
    if args.switch("--dry-run") || out.is_bound_agent() {
        let capability = reversal_req.capability.clone();
        let reversal = PostIntent::new(reversal_req.proposal, reversal_req.approvals)
            .map_err(|e| usage(format!("correction reversal: {e}"), FIX))?;
        let replacement = PostIntent::new(replacement_req.proposal, replacement_req.approvals)
            .map_err(|e| usage(format!("correction replacement: {e}"), FIX))?;
        let plan = book.plan_replacement(reversal, replacement, &capability)??;
        return emit_replacement_plan(out, &book, &ctx.files, args, &plan);
    }
    let (reversal_posted, replacement_posted) =
        book.post_replacement_pair(reversal_req, replacement_req)??;
    out.at_book(&book)?;
    let entry = |posted: &Posted| match posted {
        Posted::Committed {
            entry_ref, period, ..
        } => (*entry_ref, s(period.as_str())),
        Posted::AlreadyRecorded { entry_ref, .. } => (*entry_ref, Json::Null),
    };
    let (reversal_ref, reversal_period) = entry(&reversal_posted);
    let (replacement_ref, replacement_period) = entry(&replacement_posted);
    let already = matches!(replacement_posted, Posted::AlreadyRecorded { .. });
    let recorded_at = replacement_posted.recorded_at();
    out.event(
        "corrected",
        vec![
            ("target", s(&target_hex)),
            ("reason_code", Json::Int(i128::from(reason.code))),
            ("reason", s(&reason.name)),
            ("reversal", s(format!("{:032x}", reversal_ref.vid.0))),
            ("reversal_digest", s(hex(&reversal_ref.entry_digest))),
            ("replacement", s(format!("{:032x}", replacement_ref.vid.0))),
            ("replacement_digest", s(hex(&replacement_ref.entry_digest))),
            ("recorded_at", Json::Int(i128::from(recorded_at.0))),
            ("already_recorded", Json::Bool(already)),
            ("reversal_period", reversal_period),
            ("replacement_period", replacement_period),
        ],
        &if already {
            format!(
                "correction of {target_hex} already recorded at {} (reversal {:032x}, replacement {:032x}); nothing new was written",
                recorded_at.0, reversal_ref.vid.0, replacement_ref.vid.0
            )
        } else {
            format!(
                "corrected {target_hex}: reversal {:032x} and replacement {:032x}, recorded together at {} · reason {}",
                reversal_ref.vid.0, replacement_ref.vid.0, recorded_at.0, reason.name
            )
        },
    );
    Ok(())
}

/// Reason names and numeric codes have one registry-backed meaning. The
/// reason is part of the sealed proposal and therefore part of retry
/// identity; the caller's explanation belongs in its description.
fn reversal_reason(value: Option<&Json>) -> Result<Reason, Fail> {
    let reasons =
        ReasonCodes::embedded().map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
    let supplied = value.and_then(Json::as_str);
    let reason = supplied.and_then(|text| {
        reasons.rows.iter().find(|r| {
            r.scope == "supersession"
                && (r.name == text || text.parse::<u16>().ok() == Some(r.code))
        })
    });
    if let Some(reason) = reason {
        return Ok(reason.clone());
    }
    let names: Vec<&str> = reasons
        .rows
        .iter()
        .filter(|r| r.scope == "supersession")
        .map(|r| r.name.as_str())
        .collect();
    let nearest_name = supplied.and_then(|name| nearest(name, &names));
    let suggestion = nearest_name
        .map(|name| format!("did you mean `{name}`? "))
        .unwrap_or_default();
    // The registered names, the nearest spelling first.
    let mut one_of: Vec<String> = nearest_name.map(str::to_string).into_iter().collect();
    one_of.extend(
        names
            .iter()
            .filter(|n| Some(**n) != nearest_name)
            .map(|n| (*n).to_string()),
    );
    Err(Refusal::new(
        fa_journal::refusal::code::SUPERSESSION_REASON,
        exit::REFUSAL,
        match supplied {
            Some(name) => format!("reversal reason `{name}` is not registered"),
            None => "a reversal requires a registered reason string".to_string(),
        },
        "plan §8.2; registries/reason_codes.toml (scope supersession)",
        format!(
            "{suggestion}set `reason` in the reversal intent, or `fa reverse <vid> --reason <name>`; registered reasons: {}",
            reasons.listing("supersession")
        ),
    )
    .or_field_change("reason", one_of)
    .into())
}

pub(crate) fn lineage_json(link: &fa_model::Supersession, reasons: &ReasonCodes) -> Json {
    obj(vec![
        ("entry", s(format!("{:032x}", link.target.vid.0))),
        ("kind", s(format!("{:?}", link.kind))),
        ("reason_code", Json::Int(i128::from(link.reason_code))),
        (
            "reason",
            reasons
                .get("supersession", link.reason_code)
                .map_or(Json::Null, |reason| s(&reason.name)),
        ),
    ])
}

fn reserve_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    post_with(ctx, args, Some(EntryClass::PENDING))
}

fn resolve_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    post_with(ctx, args, Some(EntryClass::RESOLUTION))
}

fn post_with(ctx: &mut Ctx<'_>, args: &Args, forced: Option<EntryClass>) -> Result<(), Fail> {
    check_post_planning_options(args)?;
    let path = args.require("--intent", "entry.json (or - for stdin)")?;
    let text = ctx.files.read_text(path)?;
    let doc = parse_json(path, &text)?;
    post_document(ctx, args, forced, doc)
}

/// Construct a fixed recurring template using the ordinary intent parser.
/// The schedule kernel admits its supported template subset independently.
pub(crate) fn recurring_template(
    out: &Out,
    book: &mut Book,
    args: &Args,
    doc: &Json,
    principal: VId,
    capability: Capability,
) -> Result<EntryPayload, Fail> {
    if doc.get("fx").is_some() || doc.get("external_subledger").is_some() {
        return Err(usage(
            "recurring templates require fixed native-unit legs without source-derived FX or external feeds",
            "provide an Original entry intent with explicit legs and a start effective_date",
        ));
    }
    Ok(build_post_request(
        out,
        book,
        args,
        Some(EntryClass::ORIGINAL),
        doc,
        principal,
        capability,
    )?
    .request
    .proposal)
}

/// A batch member's failure names its member; nothing in the batch is posted.
fn batch_member_fail(index: usize, fail: Fail) -> Fail {
    match fail {
        Fail::Usage(e) => usage(format!("batch member {index}: {}", e.message), e.fix),
        Fail::Refusal(r) => Fail::Refusal(
            Refusal {
                message: format!("batch member {index}: {}", r.message),
                ..r
            }
            .at("member", index),
        ),
        other => other,
    }
}

/// `fa post --intent` with a PostBatch intent (plan §5.8, Appendix B):
/// `{"idempotency_key": K, "intents": [<entry intent>, ...]}` commits every
/// member atomically and in order, each member seeing the earlier members'
/// effects (an invoice and its application in one batch: the application
/// names the invoice's identity-derived vid). The batch key is the identity
/// of its IntentOutcome, so an identical retry returns the recorded outcome.
fn post_batch_document(ctx: &mut Ctx<'_>, args: &Args, doc: &Json) -> Result<(), Fail> {
    const FIX: &str = "a batch intent is {\"idempotency_key\": \"...\", \"intents\": [<entry intent>, ...]}; fa robot-docs examples shows an entry intent";
    for flag in [
        "--balancing",
        "--timeout-ns",
        "--reverse-on",
        "--prior-period-error",
        "--evidence",
    ] {
        if !args.flag_all(flag).is_empty() {
            return Err(usage(
                format!("a batch intent takes no {flag}; nothing was posted"),
                "put timeout_ns, reverse_on, prior_period_error and evidence in each member intent",
            ));
        }
    }
    let Json::Obj(fields) = doc else {
        return Err(usage("a batch intent must be an object", FIX));
    };
    if let Some((field, _)) = fields
        .iter()
        .find(|(field, _)| !matches!(field.as_str(), "idempotency_key" | "intents"))
    {
        return Err(usage(format!("batch intent: unknown field `{field}`"), FIX));
    }
    let Some(Json::Str(key)) = doc.get("idempotency_key") else {
        return Err(usage("a batch intent needs a string idempotency_key", FIX));
    };
    let Some(Json::Arr(members)) = doc.get("intents") else {
        return Err(usage(
            "batch intent: intents must be an array of entry intents",
            FIX,
        ));
    };
    let who = ctx.principal(args);
    let capability = ctx.capability(args, crate::fx::posting_ops(doc))?;
    let out = &ctx.out;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::fx::admit_intent_sources(book, &capability, doc)
    })?;
    let mut intents = Vec::with_capacity(members.len());
    let mut classes = Vec::with_capacity(members.len());
    let mut earlier = batch_plan::PriorEntries::new();
    for (i, member) in members.iter().enumerate() {
        let built = build_post_request_with_prior(
            out,
            &mut book,
            args,
            None,
            member,
            who,
            capability.clone(),
            &earlier,
        )
        .map_err(|f| batch_member_fail(i, f))?;
        classes.push(built.class_name);
        let intent = PostIntent::new(built.request.proposal, built.request.approvals)
            .map_err(|e| usage(format!("batch member {i}: {e}"), "check the member intent"))?;
        batch_plan::remember(&mut earlier, &intent).map_err(|f| batch_member_fail(i, f))?;
        intents.push(intent);
    }
    let batch = fa::PostBatch::new(key.as_bytes().to_vec(), intents)
        .map_err(|e| usage(format!("batch intent: {e}; nothing was posted"), FIX))?;
    if args.switch("--dry-run") || out.is_bound_agent() {
        let plan = book.plan_batch(batch, &capability)??;
        return batch_plan::emit(out, &book, &ctx.files, args, &plan);
    }
    let posted = book.post_batch(batch, &capability)??;
    out.at_book(&book)?;
    let members_json: Vec<Json> = posted
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            obj(vec![
                ("index", Json::Int(i as i128)),
                ("vid", s(format!("{:032x}", e.vid.0))),
                ("entry_digest", s(hex(&e.entry_digest))),
                (
                    "class",
                    classes.get(i).map_or(Json::Null, |c| s(c.as_str())),
                ),
                (
                    "period",
                    posted.periods.get(i).map_or(Json::Null, |p| s(p.as_str())),
                ),
            ])
        })
        .collect();
    let human = if posted.already_recorded {
        format!(
            "Batch `{key}` is already recorded as outcome {:032x} at sequence {}: {} entries; nothing new was written.",
            posted.outcome.0,
            posted.recorded_at.0,
            posted.entries.len()
        )
    } else {
        format!(
            "Posted batch `{key}` atomically at sequence {}: {} entries, outcome {:032x}.\n{}",
            posted.recorded_at.0,
            posted.entries.len(),
            posted.outcome.0,
            posted
                .entries
                .iter()
                .enumerate()
                .map(|(i, e)| format!("  {i}: {:032x}", e.vid.0))
                .collect::<Vec<_>>()
                .join("\n")
        )
    };
    out.event(
        "batch_posted",
        vec![
            ("outcome", s(format!("{:032x}", posted.outcome.0))),
            ("idempotency_key", s(key.as_str())),
            ("recorded_at", Json::Int(i128::from(posted.recorded_at.0))),
            ("already_recorded", Json::Bool(posted.already_recorded)),
            ("members", Json::Arr(members_json)),
        ],
        &human,
    );
    Ok(())
}

pub(crate) fn check_post_planning_options(args: &Args) -> Result<(), Fail> {
    if args.flag_all("--plan-out").len() > 1 {
        return Err(usage(
            "--plan-out may be supplied only once",
            "choose one new plan output file",
        ));
    }
    if let Some(path) = args.flag("--plan-out") {
        if !args.switch("--dry-run") {
            return Err(usage(
                "--plan-out requires --dry-run; nothing was posted",
                "add --dry-run to rehearse the entry and save its exact plan",
            ));
        }
        if path == "-" {
            return Err(usage(
                "--plan-out names a new file; - is not an output file",
                "omit --plan-out to receive the complete plan bytes as hex on stdout",
            ));
        }
    }
    if args.switch("--dry-run") && args.flag("--balancing").is_some() {
        return Err(usage(
            "--dry-run does not yet rehearse saturating --balancing requests",
            "plan an intent with explicit amounts and no --balancing; the normal posting laws still apply",
        ));
    }
    Ok(())
}

struct BuiltPost {
    request: PostRequest,
    class_name: String,
    typed_reversal: bool,
    reversal_detail: Option<(String, Reason)>,
}

/// The timing fields of an entry intent, and the earlier period an
/// Adjusting entry's out-of-period correction relates to (plan §8.2).
struct PostTiming {
    timeout_ns: Option<u64>,
    reverse_on: Option<DateDay>,
    prior_period_error: Option<String>,
}

/// Timing is request data. The posting kernel resolves its committed tick
/// anchor and schedule law, and judges the prior period; the CLI never reads
/// a clock or creates an effect.
fn post_timing(args: &Args, doc: &Json, class: EntryClass) -> Result<PostTiming, Fail> {
    let Json::Obj(fields) = doc else {
        return Err(usage("intent must be an object", "fa robot-docs examples"));
    };
    const FIELDS: &[&str] = &[
        "class",
        "effective_date",
        "document_date",
        "effective_period",
        "idempotency_key",
        "description",
        "legs",
        "evidence",
        "event",
        "reverses",
        "reclassifies",
        "revises",
        "restates",
        "moves",
        "reason",
        "resolves",
        "disposition",
        "amount",
        "timeout_ns",
        "reverse_on",
        "prior_period_error",
        "fx",
        "external_subledger",
    ];
    if let Some((field, _)) = fields
        .iter()
        .find(|(field, _)| !FIELDS.contains(&field.as_str()))
    {
        return Err(usage(
            format!("intent: unknown field `{field}`"),
            "use timeout_ns for a Pending duration in nanoseconds, or reverse_on for an Adjusting reversal date; fa robot-docs examples lists the supported intent fields",
        ));
    }
    for (field, flag, allowed, name) in [
        ("timeout_ns", "--timeout-ns", EntryClass::PENDING, "Pending"),
        (
            "reverse_on",
            "--reverse-on",
            EntryClass::ADJUSTING,
            "Adjusting",
        ),
        (
            "prior_period_error",
            "--prior-period-error",
            EntryClass::ADJUSTING,
            "Adjusting",
        ),
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("{flag} may be supplied only once"),
                format!("supply one {flag} value, or use the intent's {field} field"),
            ));
        }
        if doc.get(field).is_some() && args.flag(flag).is_some() {
            return Err(usage(
                format!("{field} was supplied in both the intent and {flag}"),
                format!("supply {field} in the intent or {flag}, once"),
            ));
        }
        if (doc.get(field).is_some() || args.flag(flag).is_some()) && class != allowed {
            return Err(usage(
                format!("{field} belongs to a {name} entry only"),
                format!("remove {field}/{flag}, or use class {name}"),
            ));
        }
    }
    let bad_timeout = || {
        usage(
            "timeout_ns must be an integer from 0 through 18446744073709551615 nanoseconds",
            "timeout_ns: 5000000000, or --timeout-ns 5000000000 (five seconds from the latest committed TimeEvidence tick)",
        )
    };
    let timeout_ns = match doc.get("timeout_ns") {
        Some(Json::Int(n)) => Some(u64::try_from(*n).map_err(|_| bad_timeout())?),
        Some(_) => return Err(bad_timeout()),
        None => args
            .flag("--timeout-ns")
            .map(|text| {
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(bad_timeout());
                }
                text.parse::<u64>().map_err(|_| bad_timeout())
            })
            .transpose()?,
    };
    let reverse_text = match doc.get("reverse_on") {
        Some(Json::Str(text)) => Some(text.as_str()),
        Some(_) => {
            return Err(usage(
                "reverse_on must be a civil-date string",
                "reverse_on: \"YYYY-MM-DD\", or --reverse-on YYYY-MM-DD",
            ));
        }
        None => args.flag("--reverse-on"),
    };
    let reverse_on = reverse_text
        .map(|text| {
            DateDay::parse(text).map_err(|e| {
                usage(
                    format!("reverse_on `{text}`: {e:?}"),
                    "reverse_on: \"YYYY-MM-DD\", or --reverse-on YYYY-MM-DD",
                )
            })
        })
        .transpose()?;
    let prior_period_error = match doc.get("prior_period_error") {
        Some(Json::Str(code)) => Some(code.clone()),
        Some(_) => {
            return Err(usage(
                "prior_period_error must be a period code string",
                "prior_period_error: \"FY2025-P12\", or --prior-period-error FY2025-P12 (the earlier period whose error this Adjusting entry corrects)",
            ));
        }
        None => args.flag("--prior-period-error").map(str::to_string),
    };
    Ok(PostTiming {
        timeout_ns,
        reverse_on,
        prior_period_error,
    })
}

/// Resolve and seal the request once. Planning and posting must use these
/// same bytes; rebuilding a description would change its randomized seal.
fn build_post_request(
    out: &Out,
    book: &mut Book,
    args: &Args,
    forced: Option<EntryClass>,
    doc: &Json,
    who: VId,
    capability: Capability,
) -> Result<BuiltPost, Fail> {
    build_post_request_with_prior(
        out,
        book,
        args,
        forced,
        doc,
        who,
        capability,
        &batch_plan::PriorEntries::new(),
    )
}

/// A batch may resolve only earlier members' sealed proposals. These are
/// request construction inputs; the carried native transaction independently
/// checks their identities, digests, admission and open amounts before commit.
#[allow(clippy::too_many_arguments)]
fn build_post_request_with_prior(
    out: &Out,
    book: &mut Book,
    args: &Args,
    forced: Option<EntryClass>,
    doc: &Json,
    who: VId,
    capability: Capability,
    earlier: &batch_plan::PriorEntries,
) -> Result<BuiltPost, Fail> {
    if doc.get("fx").is_some() || doc.get("external_subledger").is_some() {
        fa_policy::admit_read(&capability, who, book.context().book_id)
            .and_then(|()| {
                fa_policy::require(
                    &capability,
                    fa_policy::Op::Post,
                    "preparing an FX-valued posting",
                )
            })
            .and_then(|()| fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None))
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(who, &capability)??;
    }
    let ctx = book.context().clone();
    let class_name = match doc.get("class") {
        None => match forced {
            Some(EntryClass::PENDING) => "Pending",
            Some(EntryClass::RESOLUTION) => "Resolution",
            Some(EntryClass::REVERSAL) => "Reversal",
            Some(EntryClass::ADJUSTING) => "Adjusting",
            _ => "Original",
        },
        Some(Json::Str(name)) => name,
        Some(_) => {
            return Err(usage(
                "intent: class must be a string",
                "class: Pending|Adjusting|Original|…",
            ));
        }
    };
    let class = EntryClass::from_name(class_name).ok_or_else(|| {
        usage(
            format!("unknown class `{class_name}`"),
            "class: Original|Adjusting|Reversal|Pending|Resolution|…",
        )
    })?;
    if forced.is_some_and(|f| f != class) {
        return Err(usage(
            format!(
                "`fa {}` posts a {} but the intent says class `{class_name}`",
                args.positional
                    .first()
                    .map(String::as_str)
                    .unwrap_or("post"),
                forced.and_then(EntryClass::name).unwrap_or("?")
            ),
            "remove `class` from the intent, or use `fa post`",
        ));
    }
    let PostTiming {
        timeout_ns,
        reverse_on,
        prior_period_error,
    } = post_timing(args, doc, class)?;
    let typed_reversal = forced == Some(EntryClass::REVERSAL);
    if doc.get("reclassifies").is_some() && class != EntryClass::RECLASSIFICATION {
        return Err(usage(
            "`reclassifies` names the target of a Reclassification only",
            "set class: \"Reclassification\" (or use fa reclass), or remove `reclassifies`",
        ));
    }
    if doc.get("amount").is_some() && class != EntryClass::RESOLUTION {
        return Err(usage(
            "`amount` posts a two-leg hold: it belongs to a Resolution (fa post-reserve) only",
            "name the entry's legs in `legs`",
        ));
    }
    if doc.get("revises").is_some() && class != EntryClass::REVISION {
        return Err(usage(
            "`revises` names the target of a Revision only",
            "set class: \"Revision\" and plan it in its Revision case's scenario, or remove `revises`",
        ));
    }
    if doc.get("restates").is_some() && class != EntryClass::RESTATEMENT {
        return Err(usage(
            "`restates` names the target of a Restatement only",
            "set class: \"Restatement\" and plan it in its Restatement case's scenario, or remove `restates`",
        ));
    }
    let dated_by_target = typed_reversal
        || class == EntryClass::RECLASSIFICATION
        || class == EntryClass::REVISION
        || class == EntryClass::RESTATEMENT;
    let supplied_date = if dated_by_target && doc.get("effective_date").is_none() {
        None
    } else {
        let date_s = req_str(doc, "effective_date", "intent")?;
        Some(DateDay::parse(date_s).map_err(|e| {
            usage(
                format!("effective_date `{date_s}`: {e:?}"),
                "effective_date: \"YYYY-MM-DD\"",
            )
        })?)
    };
    let mut target_date = None;
    let mut target_period = None;
    let key = req_str(doc, "idempotency_key", "intent")?;
    let description = doc.get("description").and_then(Json::as_str).unwrap_or("");
    // The source document's own date (Appendix A `document_date`): recorded
    // on the entry, and judged against its period for cutoff (plan §5.1).
    let document_date = match doc.get("document_date") {
        None | Some(Json::Null) => None,
        Some(Json::Str(text)) => Some(DateDay::parse(text).map_err(|e| {
            usage(
                format!("document_date `{text}`: {e:?}"),
                "document_date: \"YYYY-MM-DD\", the source document's own date",
            )
        })?),
        Some(_) => {
            return Err(usage(
                "intent: `document_date` must be a string",
                "document_date: \"YYYY-MM-DD\"",
            ));
        }
    };
    // A Reversal names its target; its legs are the exact side-swap of the
    // target's, derived here so an agent never has to retype amounts. A
    // Resolution names the hold it resolves and either posts a sub-vector
    // drawn leg by leg from it or voids it (plan §5.4).
    let mut supersession = Vec::new();
    let mut pending = None;
    let mut control = None;
    let mut reversal_detail = None;
    let mut reversal_base_totals = None;
    let mut reversal_rate_evidence = Vec::new();
    let mut target_evidence = Vec::new();
    let legs: Vec<LegPayload> = if class == EntryClass::RECLASSIFICATION {
        // A Reclassification names its target and moves part of its legs to
        // other accounts (plan §8.2, Appendix B Reclass; bead fa-xvba). A move
        // takes the target's leg side and dimensions on `from`, so the caller
        // names accounts and an amount, never a side. The date, period and
        // evidence default to the target's.
        const FIX: &str = "fa reclass <vid> --from <account> --to <account> --amount \"<amount>\" --reason <name>";
        if doc.get("reverses").is_some() || doc.get("resolves").is_some() {
            return Err(usage(
                "a Reclassification names its target with `reclassifies` only",
                FIX,
            ));
        }
        let target_s = doc
            .get("reclassifies")
            .and_then(Json::as_str)
            .ok_or_else(|| {
                usage(
                    "a Reclassification names its target: `reclassifies` (vid)",
                    FIX,
                )
            })?;
        let reason = reversal_reason(doc.get("reason"))?;
        if reason.name == "Other" && description.trim().is_empty() {
            return Err(Refusal::new(
                fa_journal::refusal::code::SUPERSESSION_REASON,
                exit::REFUSAL,
                "the reclassification reason Other requires a description",
                "plan §8.2 (Other(text)); registries/reason_codes.toml",
                "state the reason in the intent's description or use `fa reclass <vid> ... --reason Other --description <explanation>`",
            )
            .into());
        }
        let vid = parse_vid(target_s, "reclassifies")?;
        let Some(target) = batch_plan::target_entry(book, earlier, vid)? else {
            return Err(usage(
                format!("reclassifies: no entry {target_s} in this book"),
                "fa entry show <vid> to check the identity",
            ));
        };
        supersession.push(fa_model::Supersession {
            target: target.entry_ref(vid),
            kind: fa_model::SupersessionKind::Reclassifies,
            reason_code: reason.code,
        });
        target_date = Some(target.proposal.effective_date);
        target_period = target.proposal.effective_period.clone();
        target_evidence.clone_from(&target.proposal.evidence);
        match (doc.get("moves"), doc.get("legs")) {
            (Some(Json::Arr(moves)), None) if !moves.is_empty() => {
                let mut legs = Vec::with_capacity(moves.len() * 2);
                for (i, m) in moves.iter().enumerate() {
                    let what = format!("moves[{i}]");
                    let from = req_str(m, "from", &what)?;
                    let to = req_str(m, "to", &what)?;
                    let amount_s = req_str(m, "amount", &what)?;
                    let amount = Amount::parse(amount_s, &ctx.units).map_err(|e| {
                        usage(
                            format!("{what}: amount `{amount_s}`: {e:?}"),
                            "amount: \"300.00 USD\" (exact, at the unit's scale, positive)",
                        )
                    })?;
                    let from_vid = account_vid(ctx.book_id, from);
                    let sources: Vec<&LegPayload> = target
                        .proposal
                        .legs
                        .iter()
                        .filter(|l| l.account_ref == from_vid && l.amount.unit == amount.unit)
                        .collect();
                    let Some(source) = sources.first() else {
                        return Err(usage(
                            format!("{what}: the target has no leg on account {from} in that unit"),
                            "fa entry show <vid> lists the target's legs; move out of one of them",
                        ));
                    };
                    if sources
                        .iter()
                        .any(|l| l.side != source.side || l.dimension_set != source.dimension_set)
                    {
                        return Err(usage(
                            format!(
                                "{what}: the target's legs on {from} differ in side or dimensions"
                            ),
                            "name each moved leg explicitly in the intent's `legs`",
                        ));
                    }
                    let opposite = if source.side == Side::Debit {
                        Side::Credit
                    } else {
                        Side::Debit
                    };
                    let mut out_of = LegPayload::simple(opposite, from_vid, amount);
                    out_of.dimension_set.clone_from(&source.dimension_set);
                    let mut into =
                        LegPayload::simple(source.side, account_vid(ctx.book_id, to), amount);
                    into.dimension_set.clone_from(&source.dimension_set);
                    legs.push(out_of);
                    legs.push(into);
                }
                legs
            }
            (None, Some(_)) => {
                let parsed = parse_legs(doc, &ctx, book, earlier)?;
                if let Some(i) = parsed.iter().position(|(_, o)| o.is_some()) {
                    return Err(usage(
                        format!("legs[{i}]: `source_ordinal` belongs to a Resolution(Posts) only"),
                        "remove it",
                    ));
                }
                parsed.into_iter().map(|(l, _)| l).collect()
            }
            _ => {
                return Err(usage(
                    "a Reclassification carries either `moves` ([{\"from\", \"to\", \"amount\"}], at least one) or explicit `legs`",
                    FIX,
                ));
            }
        }
    } else if let Some((field, kind)) = match class {
        EntryClass::REVISION => Some(("revises", fa_model::SupersessionKind::Revises)),
        EntryClass::RESTATEMENT => Some(("restates", fa_model::SupersessionKind::Restates)),
        _ => None,
    } {
        // A Revision names the posting it revises, and a Restatement the
        // posting it restates, with delta legs (plan §8.2 Revises/Restates,
        // §8.3; beads fa-75j4, fa-651f). Each is planned in its case's
        // scenario and reaches trunk only in the case's own Post. The
        // date, period and evidence default to the target's.
        let name = class.name().unwrap_or("?");
        let fix = format!(
            "an intent with class \"{name}\", \"{field}\": \"<vid>\", \"reason\": \"<name>\" and the delta \"legs\", run in the case's scenario: fa scenario run <name> --intent <file>"
        );
        if doc.get("reverses").is_some()
            || doc.get("resolves").is_some()
            || doc.get("moves").is_some()
        {
            return Err(usage(
                format!(
                    "a {name} names its target with `{field}` and carries explicit delta `legs`"
                ),
                fix,
            ));
        }
        let target_s = doc.get(field).and_then(Json::as_str).ok_or_else(|| {
            usage(
                format!("a {name} names the posting it corrects: `{field}` (vid)"),
                fix.clone(),
            )
        })?;
        let reason = reversal_reason(doc.get("reason"))?;
        if reason.name == "Other" && description.trim().is_empty() {
            return Err(Refusal::new(
                fa_journal::refusal::code::SUPERSESSION_REASON,
                exit::REFUSAL,
                format!(
                    "the {} reason Other requires a description",
                    name.to_lowercase()
                ),
                "plan §8.2 (Other(text)); registries/reason_codes.toml",
                "state the reason in the intent's description",
            )
            .into());
        }
        let vid = parse_vid(target_s, field)?;
        let Some(target) = batch_plan::target_entry(book, earlier, vid)? else {
            return Err(usage(
                format!("{field}: no entry {target_s} in this book"),
                "fa entry show <vid> to check the identity",
            ));
        };
        supersession.push(fa_model::Supersession {
            target: target.entry_ref(vid),
            kind,
            reason_code: reason.code,
        });
        target_date = Some(target.proposal.effective_date);
        target_period = target.proposal.effective_period.clone();
        target_evidence.clone_from(&target.proposal.evidence);
        let parsed = parse_legs(doc, &ctx, book, earlier)?;
        if let Some(i) = parsed.iter().position(|(_, o)| o.is_some()) {
            return Err(usage(
                format!("legs[{i}]: `source_ordinal` belongs to a Resolution(Posts) only"),
                "remove it",
            ));
        }
        parsed.into_iter().map(|(l, _)| l).collect()
    } else if let Some(target_s) = doc.get("reverses").and_then(Json::as_str) {
        if doc.get("fx").is_some() {
            return Err(usage(
                "a Reversal derives its exact valuation from the target; do not supply fx",
                "remove fx; use a paired Replacement to post corrected legs with new Rate evidence",
            ));
        }
        // Earlier raw-post clients recorded zero when no reason was supplied.
        // Let the kernel compare that complete historical request with the
        // recorded outcome. It refuses every fresh zero-reason correction
        // before publication; this path never invents a registered reason or
        // guesses that two requests are equivalent. Typed reverse remains strict.
        let legacy_reason = !typed_reversal
            && class == EntryClass::REVERSAL
            && match doc.get("reason") {
                None | Some(Json::Int(0)) => true,
                Some(Json::Str(reason)) => reason == "0",
                _ => false,
            };
        let reason = if legacy_reason {
            None
        } else {
            Some(reversal_reason(doc.get("reason"))?)
        };
        if reason.as_ref().is_some_and(|r| r.name == "Other") && description.trim().is_empty() {
            return Err(Refusal::new(
                fa_journal::refusal::code::SUPERSESSION_REASON,
                exit::REFUSAL,
                "the reversal reason Other requires a description",
                "plan §8.2 (Other(text)); registries/reason_codes.toml",
                "state the reason in the intent's description or use `fa reverse <vid> --reason Other --description <explanation>`",
            ).into());
        }
        let vid = parse_vid(target_s, "reverses")?;
        let Some(target) = batch_plan::target_entry(book, earlier, vid)? else {
            return Err(usage(
                format!("reverses: no entry {target_s} in this book"),
                "fa entry show <vid> to check the identity",
            ));
        };
        supersession.push(fa_model::Supersession {
            target: target.entry_ref(vid),
            kind: fa_model::SupersessionKind::Reverses,
            reason_code: reason.as_ref().map_or(0, |r| r.code),
        });
        target_date = Some(target.proposal.effective_date);
        target_period = target.proposal.effective_period.clone();
        reversal_base_totals = target.proposal.base_totals.clone();
        if let Some(totals) = &mut reversal_base_totals {
            std::mem::swap(&mut totals.debits, &mut totals.credits);
            reversal_rate_evidence = target
                .proposal
                .evidence
                .iter()
                .filter(|evidence| evidence.role == fa_journal::fx::RATE_EVIDENCE_ROLE)
                .copied()
                .collect();
        }
        reversal_detail = reason.map(|reason| (format!("{:032x}", vid.0), reason));
        if doc.get("legs").is_some() {
            return Err(usage(
                "a Reversal's legs are derived from the target; do not supply `legs`",
                "remove `legs`; a Reversal derives its exact opposite legs from the target. To post corrected legs, add them as the paired Replacement: --replace-with <file>",
            ));
        }
        target
            .proposal
            .legs
            .iter()
            .map(|l| {
                // Every field survives except the applications: the undo of
                // a reversed entry's applications is derived by the kernel,
                // never re-entered (plan §5.7).
                let mut swapped = l.clone();
                swapped.side = if l.side == Side::Debit {
                    Side::Credit
                } else {
                    Side::Debit
                };
                swapped.settles = Vec::new();
                swapped
            })
            .collect()
    } else if class == EntryClass::RESOLUTION {
        let target_s = doc.get("resolves").and_then(Json::as_str).ok_or_else(|| {
            usage(
                "a Resolution names the hold it resolves: `resolves` (vid)",
                "resolves: the `vid` from the reserve event; disposition: \"posts\" with legs, or \"voids\"",
            )
        })?;
        let vid = parse_vid(target_s, "resolves")?;
        let Some(hold) = batch_plan::target_entry(book, earlier, vid)? else {
            return Err(usage(
                format!("resolves: no entry {target_s} in this book"),
                "fa entry show <vid> to check the identity",
            ));
        };
        let resolution_of = Some(hold.entry_ref(vid));
        let disposition = doc.get("disposition").and_then(Json::as_str).unwrap_or(
            if doc.get("legs").is_some() || doc.get("amount").is_some() {
                "posts"
            } else {
                "voids"
            },
        );
        match disposition {
            "voids" | "void" | "release" => {
                if doc.get("legs").is_some() || doc.get("amount").is_some() {
                    return Err(usage(
                        "a Voids resolution carries no legs",
                        "remove `legs`, or set disposition to \"posts\"",
                    ));
                }
                // A void releases the hold for good (verbs.toml [[dangerous]]).
                gate(out, args, "resolve", None, &Condition::Voids)?;
                control = Some(ControlPayload::ReservationRelease);
                pending = Some(Pending {
                    timeout_ns: None,
                    resolution_of,
                    disposition: Some(Disposition::Voids),
                });
                Vec::new()
            }
            "posts" | "post" => {
                let mut pairs: Vec<(u16, LegPayload)> = Vec::new();
                if let Some(text) = doc.get("amount") {
                    // Appendix B PostReserve `amount`: sugar for a two-leg,
                    // single-unit hold, each leg posting `amount` on its
                    // own account, side and dimensions; the kernel bounds it
                    // by what each leg reserved.
                    if doc.get("legs").is_some() {
                        return Err(usage(
                            "a Posts resolution names `legs` or `amount`, not both",
                            "remove `amount`, or remove `legs` to post the same amount on both legs of a two-leg hold",
                        ));
                    }
                    let text = text
                        .as_str()
                        .ok_or_else(|| usage("amount must be a string", "amount: \"60.00 USD\""))?;
                    let [first, second] = hold.proposal.legs.as_slice() else {
                        return Err(usage(
                            format!(
                                "`amount` posts a two-leg hold; this hold has {} legs",
                                hold.proposal.legs.len()
                            ),
                            "name each posted leg in `legs` (with source_ordinal where an account repeats)",
                        ));
                    };
                    if first.amount.unit != second.amount.unit
                        || first.base_amount.is_some()
                        || second.base_amount.is_some()
                    {
                        return Err(usage(
                            "`amount` posts a single-unit hold without base valuations",
                            "name each posted leg in `legs`",
                        ));
                    }
                    let amount = Amount::parse(text, &ctx.units)
                        .map_err(|e| usage(format!("amount: {e}"), "amount: \"60.00 USD\""))?;
                    if amount.unit != first.amount.unit {
                        return Err(usage(
                            "amount is not in the hold's unit",
                            "write the amount in the unit the hold reserved",
                        ));
                    }
                    for (ordinal, held) in [(0u16, first), (1, second)] {
                        let mut leg = held.clone();
                        leg.amount = amount;
                        leg.settles = Vec::new();
                        pairs.push((ordinal, leg));
                    }
                }
                let listed = if pairs.is_empty() {
                    parse_legs(doc, &ctx, book, earlier)?
                } else {
                    Vec::new()
                };
                for (i, (leg, explicit)) in listed.into_iter().enumerate() {
                    let ordinal = match explicit {
                        Some(o) => o,
                        None => {
                            let candidates: Vec<usize> = hold
                                .proposal
                                .legs
                                .iter()
                                .enumerate()
                                .filter(|(_, t)| {
                                    t.account_ref == leg.account_ref && t.side == leg.side
                                })
                                .map(|(o, _)| o)
                                .collect();
                            match candidates.as_slice() {
                                [one] => u16::try_from(*one).map_err(|_| {
                                    usage("the hold has more than u16 legs", "fa entry show <vid>")
                                })?,
                                [] => {
                                    return Err(usage(
                                        format!(
                                            "legs[{i}]: the hold has no {} leg on that account",
                                            if leg.side == Side::Debit {
                                                "debit"
                                            } else {
                                                "credit"
                                            }
                                        ),
                                        "post only accounts and sides the hold reserved (fa entry show <hold vid>); anything else is a Voids plus a new Original",
                                    ));
                                }
                                many => {
                                    return Err(usage(
                                        format!(
                                            "legs[{i}]: the hold has several matching legs (ordinals {many:?})"
                                        ),
                                        "add \"source_ordinal\" to the leg",
                                    ));
                                }
                            }
                        }
                    };
                    if pairs.iter().any(|(o, _)| *o == ordinal) {
                        return Err(usage(
                            format!("legs[{i}]: source_ordinal {ordinal} is used twice"),
                            "one posted leg per hold leg",
                        ));
                    }
                    pairs.push((ordinal, leg));
                }
                pairs.sort_by_key(|(o, _)| *o);
                pending = Some(Pending {
                    timeout_ns: None,
                    resolution_of,
                    disposition: Some(Disposition::Posts {
                        source_ordinals: pairs.iter().map(|(o, _)| *o).collect(),
                    }),
                });
                pairs.into_iter().map(|(_, l)| l).collect()
            }
            other => {
                return Err(usage(
                    format!("disposition `{other}`"),
                    "disposition: posts|voids",
                ));
            }
        }
    } else if doc.get("external_subledger").is_some() {
        if doc.get("legs").is_some() {
            return Err(usage(
                "external_subledger derives all summary legs from its reviewed detail document",
                "omit legs and supply external_subledger: D:<reviewed detail document oid>",
            ));
        }
        Vec::new()
    } else {
        if class == EntryClass::PENDING {
            pending = Some(Pending {
                timeout_ns,
                resolution_of: None,
                disposition: None,
            });
        }
        let parsed = parse_legs(doc, &ctx, book, earlier)?;
        if let Some(i) = parsed.iter().position(|(_, o)| o.is_some()) {
            return Err(usage(
                format!("legs[{i}]: `source_ordinal` belongs to a Resolution(Posts) only"),
                "remove it, or set resolves/disposition to post a sub-vector of a hold",
            ));
        }
        parsed.into_iter().map(|(l, _)| l).collect()
    };
    let unit_totals = EntryPayload::fold_unit_totals(&legs)
        .map_err(fa_journal::KernelError::Model)
        .map_err(BookError::Kernel)?;
    let effective_date = supplied_date.or(target_date).ok_or_else(|| {
        usage(
            "a reversal, reclassification or revision needs its target's effective date",
            "fa entry show <vid> --json",
        )
    })?;
    let effective_period = doc
        .get("effective_period")
        .and_then(Json::as_str)
        .map(|c| PeriodRef {
            calendar: ctx.calendar.id.clone(),
            code: c.to_string(),
        })
        .or_else(|| {
            if supplied_date.is_none() {
                target_period
            } else {
                None
            }
        });
    if args.flag_all("--event").len() > 1 {
        return Err(usage(
            "--event may be supplied at most once",
            "--event <code|vid>",
        ));
    }
    let doc_event = match doc.get("event") {
        None | Some(Json::Null) => None,
        Some(Json::Str(s)) => Some(s.as_str()),
        Some(_) => {
            return Err(usage(
                "intent: `event` must be a string (event code or 32-hex vid)",
                "\"event\": \"EV-1001\"",
            ));
        }
    };
    let flag_event = args.flag("--event");
    if let (Some(a), Some(b)) = (doc_event, flag_event)
        && a != b
    {
        return Err(usage(
            "intent `event` and `--event` disagree",
            "supply the event once via `--event <code|vid>` or `\"event\": \"<code|vid>\"`",
        ));
    }
    let event_arg = flag_event.or(doc_event);
    let mut proposal = EntryPayload {
        schema_minor: 0,
        book_id: ctx.book_id,
        branch_id: Id128::TRUNK,
        class,
        effective_date,
        document_date,
        description: book.seal_text(description)?,
        effective_period,
        legs,
        control,
        unit_totals,
        base_totals: reversal_base_totals,
        idempotency_key: key.as_bytes().to_vec(),
        origin: EntryOrigin::Intent {
            intent_oid: Oid(fa_model::domain_digest(
                b"fa:intent:v1",
                &[&ctx.book_id.0, &who.0.to_le_bytes(), key.as_bytes()],
            )),
            intent_kind: 1,
        },
        principal_ref: who,
        session_ref: None,
        evidence: document::parse_evidence(doc, args, book)?,
        supersession,
        pending,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    for evidence in reversal_rate_evidence {
        if !proposal.evidence.contains(&evidence) {
            proposal.evidence.push(evidence);
        }
    }
    // A Reclassification rests on its target's documents unless the intent
    // names its own (fa-xvba).
    if proposal.evidence.is_empty() {
        proposal.evidence = target_evidence;
    }
    proposal.evidence.sort_unstable();
    if let Some(ev_arg) = event_arg {
        let rea = book.rea_snapshot(None)?;
        let stripped = ev_arg.strip_prefix("EV:").unwrap_or(ev_arg);
        let matched = if stripped.len() == 32
            && stripped.bytes().all(|b| b.is_ascii_hexdigit())
            && let Ok(raw) = u128::from_str_radix(stripped, 16)
        {
            rea.events
                .get(&VId(raw))
                .or_else(|| rea.events.values().find(|e| e.spec.code == ev_arg))
        } else {
            let derived = fa_model::event_vid(ctx.book_id, stripped);
            rea.events
                .get(&derived)
                .or_else(|| rea.events.values().find(|e| e.spec.code == stripped))
        };
        match matched {
            Some(ev_row) => {
                proposal.with_event_ref(ev_row.vid, ev_row.event_digest);
                for ev_ref in &ev_row.spec.evidence {
                    if !proposal.evidence.contains(ev_ref) {
                        proposal.evidence.push(*ev_ref);
                    }
                }
                proposal.evidence.sort_unstable();
            }
            None => {
                let missing_vid = if stripped.len() == 32
                    && stripped.bytes().all(|b| b.is_ascii_hexdigit())
                    && let Ok(raw) = u128::from_str_radix(stripped, 16)
                {
                    VId(raw)
                } else {
                    fa_model::event_vid(ctx.book_id, stripped)
                };
                proposal.with_event_ref(missing_vid, [0u8; 32]);
            }
        }
    }
    let proposal = crate::external_subledger::value_intent(book, &capability, doc, proposal)?;
    let proposal = crate::fx::value_intent(book, &capability, doc, proposal)?;
    let proposal = match reverse_on {
        Some(day) => fa_journal::with_auto_reverse(proposal, day),
        None => proposal,
    };
    let proposal = match prior_period_error {
        Some(code) => fa_journal::with_prior_period_error(
            proposal,
            &PeriodRef {
                calendar: ctx.calendar.id.clone(),
                code,
            },
        )
        .map_err(BookError::Kernel)?,
        None => proposal,
    };
    Ok(BuiltPost {
        request: PostRequest {
            proposal,
            approvals: Vec::new(),
            plan_certificate: None,
            capability,
        },
        class_name: class_name.to_string(),
        typed_reversal,
        reversal_detail,
    })
}

pub(crate) fn post_document(
    ctx: &mut Ctx<'_>,
    args: &Args,
    forced: Option<EntryClass>,
    doc: Json,
) -> Result<(), Fail> {
    if let Some(name) = args.flag("--scenario") {
        let name = name.to_string();
        return plan_document_into_scenario(ctx, args, &name, forced, &doc);
    }
    if let Some(name) = args.flag("--draft") {
        let name = name.to_string();
        return plan_document_into_draft(ctx, args, &name, forced, &doc);
    }
    if forced.is_none() && doc.get("intents").is_some() {
        return post_batch_document(ctx, args, &doc);
    }
    check_post_planning_options(args)?;
    let who = ctx.principal(args);
    let capability = ctx.capability(args, crate::fx::posting_ops(&doc))?;
    let out = &ctx.out;
    let mut book = ctx.books.open_admitted(args, |book| {
        crate::fx::admit_intent_sources(book, &capability, &doc)
    })?;
    let BuiltPost {
        request: req,
        class_name,
        typed_reversal,
        reversal_detail,
    } = build_post_request(out, &mut book, args, forced, &doc, who, capability)?;
    if args.switch("--dry-run") {
        let intent = PostIntent::new(req.proposal, req.approvals).map_err(|e| {
            usage(
                format!("cannot plan this entry: {e}"),
                "check the entry intent",
            )
        })?;
        let plan = book.plan(intent, &req.capability)??;
        return emit_post_plan(out, &book, &ctx.files, args, &plan, &req.capability);
    }
    // `--balancing <leg>` (post and reserve): the leg moves at most what its
    // account's limit admits, decided inside the posting transaction; the
    // event names what was asked and what moved.
    let balancing = match args.flag("--balancing") {
        None => None,
        Some(v) => Some(v.parse::<u16>().map_err(|_| {
            usage(
                format!("--balancing `{v}` is not a leg ordinal"),
                "--balancing 0 or --balancing 1 (the leg whose account's limit decides the amount)",
            )
        })?),
    };
    let (posted, amounts) = match balancing {
        None => (book.post(req)??, None),
        Some(leg) => {
            let unit = req
                .proposal
                .legs
                .get(usize::from(leg))
                .map(|l| l.amount.unit);
            let balanced = book.post_balancing(req, leg)??;
            let unit = unit.ok_or_else(|| {
                Fail::Internal(format!(
                    "balancing leg {leg} was admitted but does not exist"
                ))
            })?;
            let units = &book.context().units;
            (
                balanced.posted,
                Some((
                    render_amount(Amount::new(unit, balanced.requested), units)?,
                    render_amount(Amount::new(unit, balanced.moved), units)?,
                )),
            )
        }
    };
    out.at_book(&book)?;
    emit_posted(
        out,
        posted,
        &class_name,
        typed_reversal,
        reversal_detail,
        amounts,
    )
}

/// A plan is portable canonical bytes, never an authority token supplied by
/// the caller. Decode only within its format bound before the kernel checks
/// its book authentication, capability binding, and current snapshot.
enum CommitPlan {
    Post(Box<PostPlan>),
    Replacement(Box<ReplacementPlan>),
    Batch(Box<fa::BatchPlan>),
}

fn read_post_plan(files: &Files, path: &str) -> Result<CommitPlan, Fail> {
    let bytes = read_bounded_plan_bytes(
        files,
        path,
        b"FA-",
        "PostEntry, Replace or PostBatch",
        fa::MAX_BATCH_PLAN_BYTES.max(MAX_PLAN_BYTES),
    )?;
    let decoded = if bytes.starts_with(fa::BatchPlan::MAGIC) {
        fa::BatchPlan::decode(&bytes).map(|plan| CommitPlan::Batch(Box::new(plan)))
    } else if bytes.starts_with(ReplacementPlan::MAGIC) {
        ReplacementPlan::decode(&bytes).map(|plan| CommitPlan::Replacement(Box::new(plan)))
    } else {
        PostPlan::decode(&bytes).map(|plan| CommitPlan::Post(Box::new(plan)))
    };
    decoded.map_err(|e| {
        usage(
            format!("{path} is not a canonical posting plan: {e}"),
            "use the complete binary plan file or bytes hex string from a successful --dry-run",
        )
    })
}

pub(crate) fn build_proposal_from_intent(
    out: &Out,
    book: &mut Book,
    args: &Args,
    doc: &Json,
    who: VId,
    capability: Capability,
) -> Result<EntryPayload, Fail> {
    Ok(
        build_post_request(out, book, args, None, doc, who, capability)?
            .request
            .proposal,
    )
}

/// Both plan transports accept their existing canonical binary form and
/// its complete hex encoding. Bound allocation before either codec runs.
pub(crate) fn read_plan_bytes(
    files: &Files,
    path: &str,
    domain: &[u8],
    kind: &str,
) -> Result<Vec<u8>, Fail> {
    read_bounded_plan_bytes(files, path, domain, kind, MAX_PLAN_BYTES)
}

fn read_bounded_plan_bytes(
    files: &Files,
    path: &str,
    domain: &[u8],
    kind: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, Fail> {
    let limit = max_bytes * 2 + 2; // hex, optionally followed by CRLF
    let read = |reader: &mut dyn Read| -> Result<Vec<u8>, Fail> {
        let mut bytes = Vec::new();
        reader
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                usage(
                    format!("{path}: {e}"),
                    "pass a readable plan file or - for stdin",
                )
            })?;
        Ok(bytes)
    };
    let bytes = if path == "-" {
        match &files.stdin {
            Stdin::Forwarded(bytes) => {
                if bytes.len() > limit {
                    return Err(usage(
                        "plan input exceeds its bounded wire size",
                        "pass the complete plan bytes from a successful --dry-run",
                    ));
                }
                bytes.clone()
            }
            Stdin::Missing => {
                return Err(usage(
                    "- names plan stdin, but no bytes reached the command",
                    "forward the plan event's bytes string, or pass its saved plan file",
                ));
            }
            Stdin::Process => read(&mut std::io::stdin().lock())?,
        }
    } else {
        let mut file = std::fs::File::open(files.resolve(path)).map_err(|e| {
            usage(
                format!("{path}: {e}"),
                "pass the plan file saved with --dry-run --plan-out",
            )
        })?;
        read(&mut file)?
    };
    if bytes.len() > limit {
        return Err(usage(
            "plan input exceeds its bounded wire size",
            "pass the complete plan bytes from a successful --dry-run",
        ));
    }
    if bytes.starts_with(domain) {
        if bytes.len() > max_bytes {
            return Err(usage(
                "plan exceeds its bounded input size",
                "pass the complete plan bytes from a successful --dry-run",
            ));
        }
        return Ok(bytes);
    }
    let Some(text) = std::str::from_utf8(&bytes)
        .ok()
        .map(str::trim)
        .filter(|text| {
            !text.is_empty() && text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit())
        })
    else {
        return Err(usage(
            format!("expected a canonical binary {kind} plan or its complete hex encoding"),
            "pass --plan <file> or forward the plan event's bytes string on stdin with --plan -",
        ));
    };
    if text.len() / 2 > max_bytes {
        return Err(usage(
            "plan exceeds its canonical format limit",
            "pass the complete plan bytes from a successful --dry-run",
        ));
    }
    let decoded = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digits = std::str::from_utf8(pair)
                .map_err(|_| usage("invalid plan hex", "pass the complete plan bytes string"))?;
            u8::from_str_radix(digits, 16)
                .map_err(|_| usage("invalid plan hex", "pass the complete plan bytes string"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(decoded)
}

pub(crate) fn write_new_output_file(
    files: &Files,
    path: &str,
    bytes: &[u8],
    what: &str,
    flag: &str,
) -> Result<(), Fail> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(files.resolve(path)).map_err(|e| {
        usage(
            format!("cannot create {what} file {path}: {e}"),
            format!("choose a new {flag} path; an existing file is never overwritten"),
        )
    })?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|e| {
        Fail::Environment(format!(
            "could not finish {what} file {path}: {e}; preserve the partial file and retry with a new output path"
        ))
    })
}

pub(crate) fn write_post_plan(files: &Files, path: &str, bytes: &[u8]) -> Result<(), Fail> {
    if path.is_empty() || path == "-" {
        return Err(usage(
            "--plan-out names a new file; - is not an output file",
            "omit --plan-out or use --dry-run to receive the complete plan bytes as hex on stdout",
        ));
    }
    write_new_output_file(files, path, bytes, "plan", "--plan-out")
}

/// A Reclassification's net effect for its plan: the target plus this
/// entry's delta per (account, unit), the `Reclassifies` netting law
/// (supersession_kinds.toml; bead fa-xvba), sorted by account code. Earlier
/// reclassifications of the same target are not netted here: they may move
/// amounts into accounts this caller does not reach, and `fa explain
/// lineage` shows the whole component under read authority. `None` for
/// every other class.
fn reclass_net_effect(
    book: &Book,
    proposal: &EntryPayload,
    accounts: &std::collections::BTreeMap<VId, fa_journal::AccountRow>,
) -> Result<Option<(Json, Vec<String>)>, Fail> {
    let target = match proposal.supersession.first() {
        Some(link) if proposal.class == EntryClass::RECLASSIFICATION => link.target.vid,
        _ => return Ok(None),
    };
    let Some((entry, _)) = book.read_entry(target)? else {
        return Ok(None);
    };
    let overflow = || Fail::Internal("a reclassification's net effect overflows i128".into());
    let mut cells: std::collections::BTreeMap<(VId, fa_money::UnitId), (i128, i128)> =
        std::collections::BTreeMap::new();
    for leg in entry.proposal.legs.iter().chain(&proposal.legs) {
        let cell = cells
            .entry((leg.account_ref, leg.amount.unit))
            .or_insert((0, 0));
        let total = if leg.side == Side::Debit {
            &mut cell.0
        } else {
            &mut cell.1
        };
        *total = total
            .checked_add(leg.amount.mantissa)
            .ok_or_else(overflow)?;
    }
    let units = &book.context().units;
    let mut rows = Vec::with_capacity(cells.len());
    for ((account, unit), (debits, credits)) in cells {
        let (code, name) = accounts
            .get(&account)
            .map_or(("?", "?"), |row| (row.code.as_str(), row.name.as_str()));
        let net = render_amount(
            Amount::new(unit, debits.checked_sub(credits).ok_or_else(overflow)?),
            units,
        )?;
        rows.push((
            (code.to_string(), unit),
            obj(vec![
                ("account", s(code)),
                ("account_vid", s(format!("{:032x}", account.0))),
                ("account_name", s(name)),
                ("unit", s(registered_unit_code(unit, units)?)),
                (
                    "debits",
                    s(render_amount(Amount::new(unit, debits), units)?),
                ),
                (
                    "credits",
                    s(render_amount(Amount::new(unit, credits), units)?),
                ),
                ("net", s(&net)),
            ]),
            format!("  {code} ({name}) net {net}"),
        ));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let (json, human): (Vec<Json>, Vec<String>) = rows
        .into_iter()
        .map(|(_, json, human)| (json, human))
        .unzip();
    Ok(Some((Json::Arr(json), human)))
}

pub(crate) fn emit_post_plan(
    out: &Out,
    book: &Book,
    files: &Files,
    args: &Args,
    plan: &PostPlan,
    capability: &Capability,
) -> Result<(), Fail> {
    let certificate = plan.certificate();
    let proposal = plan.proposal();
    let encode_error = |e| Fail::Internal(format!("encode the admitted post plan: {e}"));
    let bytes = plan.canonical_bytes().map_err(encode_error)?;
    let plan_digest = hex(&plan.digest().map_err(encode_error)?);
    let certificate_digest = hex(&certificate.digest().map_err(encode_error)?);
    let accounts: std::collections::BTreeMap<_, _> =
        book.accounts()?.into_iter().map(|a| (a.vid, a)).collect();
    let mut human_legs = Vec::new();
    let legs = proposal
        .legs
        .iter()
        .enumerate()
        .map(|(ordinal, leg)| {
            let account = accounts.get(&leg.account_ref).ok_or_else(|| {
                Fail::Internal(format!(
                    "admitted plan leg {ordinal} names a missing account {:032x}",
                    leg.account_ref.0
                ))
            })?;
            let amount = render_amount(leg.amount, &book.context().units)?;
            let side = side_name(leg.side);
            let base = leg
                .base_amount
                .map(|amount| render_amount(amount, &book.context().units))
                .transpose()?
                .map_or_else(String::new, |amount| format!("; functional {amount}"));
            human_legs.push(format!(
                "  {ordinal}: {side} {} ({}) {amount}{base}",
                account.code, account.name
            ));
            Ok(obj(vec![
                ("ordinal", Json::Int(ordinal as i128)),
                ("account", s(&account.code)),
                ("account_vid", s(format!("{:032x}", leg.account_ref.0))),
                ("side", s(side)),
                ("amount", s(amount)),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let valuation = if let Some(totals) = &proposal.base_totals {
        let unit = fa_money::UnitId(totals.unit_id);
        let law = fa::FxLawId::from_oid(&totals.fx_law_oid)
            .ok_or_else(|| Fail::Internal("admitted plan has an unknown FX law".into()))?;
        let amounts = proposal
            .legs
            .iter()
            .enumerate()
            .map(|(ordinal, leg)| {
                let amount = leg.base_amount.ok_or_else(|| {
                    Fail::Internal("admitted valued plan has an unvalued leg".into())
                })?;
                Ok(obj(vec![
                    ("ordinal", Json::Int(ordinal as i128)),
                    (
                        "base_amount",
                        s(render_amount(amount, &book.context().units)?),
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, Fail>>()?;
        obj(vec![
            (
                "base_unit",
                s(registered_unit_code(unit, &book.context().units)?),
            ),
            ("law", s(law.name())),
            ("law_oid", s(hex(&totals.fx_law_oid.0))),
            (
                "debits",
                s(render_amount(
                    Amount::new(unit, totals.debits),
                    &book.context().units,
                )?),
            ),
            (
                "credits",
                s(render_amount(
                    Amount::new(unit, totals.credits),
                    &book.context().units,
                )?),
            ),
            ("legs", Json::Arr(amounts)),
        ])
    } else {
        Json::Null
    };
    let net_effect = reclass_net_effect(book, proposal, &accounts)?;
    // What journal-entry testing would flag, said before the commit (plan
    // §5.1, fa-d5un): data only, never a refusal or a change to the plan.
    // The duplicate scan reads other entries. A launch-bound session's own
    // token decides whether it may; the embedded posture's operator acts
    // with the owner's authority, so it reads as the planning principal.
    let embedded_reader;
    let reader = if out.is_bound() {
        capability
    } else {
        embedded_reader = Capability::embedded(capability.holder(), &["read"])
            .map_err(|e| Fail::Internal(format!("the embedded read capability: {e}")))?;
        &embedded_reader
    };
    let warned = book.plan_warnings(plan, reader)?;
    let warnings = Json::Arr(
        warned
            .warnings
            .iter()
            .map(|warning| {
                obj(vec![
                    ("kind", s(warning.kind.name())),
                    (
                        "legs",
                        Json::Arr(
                            warning
                                .legs
                                .iter()
                                .map(|leg| Json::Int(i128::from(*leg)))
                                .collect(),
                        ),
                    ),
                    (
                        "entries",
                        Json::Arr(
                            warning
                                .entries
                                .iter()
                                .map(|vid| s(format!("{:032x}", vid.0)))
                                .collect(),
                        ),
                    ),
                    ("message", s(&warning.message)),
                ])
            })
            .collect(),
    );
    let unchecked = Json::Arr(
        warned
            .unchecked
            .iter()
            .map(|(kind, reason)| obj(vec![("kind", s(kind.name())), ("reason", s(reason))]))
            .collect(),
    );
    let reasons =
        ReasonCodes::embedded().map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
    let resolves = proposal
        .pending
        .as_ref()
        .and_then(|pending| pending.resolution_of.as_ref());
    let disposition = proposal
        .pending
        .as_ref()
        .and_then(|pending| pending.disposition.as_ref())
        .map(|disposition| match disposition {
            Disposition::Posts { .. } => "posts",
            Disposition::Voids => "voids",
            Disposition::Expires { .. } => "expires",
        });
    let bound = out.is_bound();
    let authority_posture = if bound {
        "mcp-launch-config"
    } else {
        "embedded-owner"
    };
    let bound_void = bound && disposition == Some("voids");
    // An Agent's trunk plan is a rehearsal (plan §15.3): it binds the
    // Agent's capability, which commit_plan refuses (FA-REF-013), so no
    // commit is suggested; a Human principal posts the intent.
    let rehearsal = out.is_bound_agent();
    let command = if bound {
        "fa_post_commit_plan".to_string()
    } else {
        let quoted = |word: &str| format!("'{}'", word.replace('\'', "'\\''"));
        let mut command = format!(
            "fa commit --plan {}",
            quoted(args.flag("--plan-out").unwrap_or("-"))
        );
        for flag in ["--book", "--keys", "--as"] {
            if let Some(value) = args.flag(flag) {
                command.push_str(&format!(" {flag} {}", quoted(value)));
            }
        }
        for grant in args.flag_all("--grant") {
            command.push_str(&format!(" --grant {}", quoted(grant)));
        }
        if proposal.base_totals.is_some()
            && proposal.class != EntryClass::REVERSAL
            && !args.flag_all("--grant").contains(&"read")
        {
            command.push_str(" --grant 'read'");
        }
        if proposal.class == EntryClass::CLOSING {
            // The owner close command explicitly holds these operations.
            // A restored plan never grants them; the commit caller supplies
            // the same capability through these ordinary command arguments.
            for grant in ["read", "close"] {
                if !args.flag_all("--grant").contains(&grant) {
                    command.push_str(&format!(" --grant {}", quoted(grant)));
                }
            }
        }
        command.push_str(" --json");
        command
    };
    let commit_guidance = if rehearsal {
        "This Agent-profile plan is a rehearsal: it commits for no one (FA-REF-013). Plan the same intent into a draft with --draft <name> (open one with `fa draft new <name>`); a Human holding approve promotes the draft.".to_string()
    } else if bound_void {
        "MCP cannot commit this void plan. Ask the operator to separately prepare, review and confirm the release.".to_string()
    } else {
        command.clone()
    };
    let next_actions = if bound_void || rehearsal {
        Vec::new()
    } else {
        vec![(command, if bound {
            "review this exact plan, then call fa_post_commit_plan with plan set to data.bytes in the same launch-bound session"
        } else {
            "review this exact plan, then commit it with the same caller capability; when --plan is -, forward data.bytes on stdin"
        }.to_string())]
    };
    let mut human = format!(
        "Planned {} effective {} in {} at sequence {}; nothing was written to the book.\nPreparer {:032x}\nProposal {}\nNative effects {}\nCertificate {}\n{}\nScope: same-snapshot-post; any intervening publication requires another dry run. Authority: {authority_posture}.\n{commit_guidance}",
        proposal.class.name().unwrap_or("?"),
        proposal.effective_date.render(),
        certificate.period,
        certificate.snapshot_seq.0,
        certificate.principal.0,
        hex(&certificate.proposal_digest),
        hex(&certificate.effects_digest),
        certificate_digest,
        human_legs.join("\n"),
    );
    if let Some(disposition) = disposition {
        human.push_str(&format!("\nResolution disposition: {disposition}"));
    }
    if let Some((_, lines)) = &net_effect {
        human.push_str("\nNet effect (the target plus this entry):\n");
        human.push_str(&lines.join("\n"));
    }
    if let Some(target) = resolves {
        human.push_str(&format!("\nResolves hold {:032x}", target.vid.0));
    }
    for link in &proposal.supersession {
        let reason = reasons
            .get("supersession", link.reason_code)
            .map_or("unregistered historical reason", |reason| {
                reason.name.as_str()
            });
        human.push_str(&format!(
            "\n{:?} {:032x}; reason {} ({reason})",
            link.kind, link.target.vid.0, link.reason_code,
        ));
    }
    let encoded = hex(&bytes);
    if args.flag("--plan-out").is_none() {
        human.push_str(&format!(
            "\nComplete canonical plan bytes (hex):\n{encoded}"
        ));
    }
    // Complete rendering and encoding before creating a file, and create
    // the entire optional file before publishing any successful plan event.
    if let Some(path) = args.flag("--plan-out") {
        write_post_plan(files, path, &bytes)?;
    }
    for warning in &warned.warnings {
        out.warn(format!("{}: {}", warning.kind.name(), warning.message));
    }
    for (kind, reason) in &warned.unchecked {
        out.warn(format!("{} not checked: {reason}", kind.name()));
    }
    if bound_void || rehearsal {
        out.warn(&commit_guidance);
    }
    out.known_at(certificate.snapshot_seq);
    out.effective(format!("period:{}", certificate.period));
    out.event_with_actions(
        "plan",
        vec![
            ("intent_kind", s("PostEntry")),
            ("class", s(proposal.class.name().unwrap_or("?"))),
            ("effective_date", s(proposal.effective_date.render())),
            ("period", s(&certificate.period)),
            ("principal", s(format!("{:032x}", certificate.principal.0))),
            ("idempotency_key", s(hex(&proposal.idempotency_key))),
            ("intent_digest", s(hex(&certificate.intent_digest))),
            ("proposal_digest", s(hex(&certificate.proposal_digest))),
            ("effects_digest", s(hex(&certificate.effects_digest))),
            (
                "snapshot_seq",
                Json::Int(i128::from(certificate.snapshot_seq.0)),
            ),
            (
                "security_policy_epoch",
                Json::Int(i128::from(certificate.security_policy_epoch)),
            ),
            (
                "expires_at",
                certificate
                    .expires_at
                    .map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
            ),
            (
                "capability_commitment",
                s(hex(&certificate.capability_commitment)),
            ),
            ("certificate_digest", s(certificate_digest)),
            ("plan_digest", s(plan_digest)),
            ("legs", Json::Arr(legs)),
            ("valuation", valuation),
            (
                "resolves",
                resolves.map_or(Json::Null, |entry| s(format!("{:032x}", entry.vid.0))),
            ),
            ("disposition", disposition.map_or(Json::Null, s)),
            (
                "supersedes",
                Json::Arr(
                    proposal
                        .supersession
                        .iter()
                        .map(|link| lineage_json(link, &reasons))
                        .collect(),
                ),
            ),
            (
                "evidence",
                Json::Arr(
                    proposal
                        .evidence
                        .iter()
                        .map(|evidence| {
                            obj(vec![
                                ("document_oid", s(hex(&evidence.document_oid.0))),
                                ("doc_commit", s(hex(&evidence.doc_commit))),
                                ("role", Json::Int(i128::from(evidence.role))),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "net_effect",
                net_effect.map_or(Json::Null, |(json, _)| json),
            ),
            ("approvals", Json::Int(plan.approvals().len() as i128)),
            ("warnings", warnings),
            ("unchecked", unchecked),
            ("bytes", s(encoded)),
            ("file", args.flag("--plan-out").map_or(Json::Null, s)),
            ("scope", s("same-snapshot-post")),
            ("authority", s(authority_posture)),
        ],
        &human,
        &next_actions,
    );
    Ok(())
}

fn emit_replacement_plan(
    out: &Out,
    book: &Book,
    files: &Files,
    args: &Args,
    plan: &ReplacementPlan,
) -> Result<(), Fail> {
    let encode = |e| Fail::Internal(format!("encode admitted correction plan: {e}"));
    let bytes = plan.canonical_bytes().map_err(encode)?;
    let digest = hex(&plan.digest().map_err(encode)?);
    let certificate_digest = hex(&plan.certificate_digest().map_err(encode)?);
    let certificate = plan.replacement().certificate();
    let target = plan.reversal().proposal().supersession[0].target;
    let accounts: std::collections::BTreeMap<_, _> =
        book.accounts()?.into_iter().map(|a| (a.vid, a)).collect();
    let reasons = ReasonCodes::embedded().map_err(|e| Fail::Internal(e.to_string()))?;
    let mut human = format!(
        "Planned atomic correction of {:032x} at sequence {}; nothing was written.\nCertificate {certificate_digest}",
        target.vid.0, certificate.snapshot_seq.0
    );
    let mut members = Vec::new();
    for member in [plan.reversal(), plan.replacement()] {
        let proposal = member.proposal();
        let mut legs = Vec::new();
        human.push_str(&format!(
            "\n{} effective {} in {}:",
            proposal.class.name().unwrap_or("?"),
            proposal.effective_date,
            member.certificate().period
        ));
        for (ordinal, leg) in proposal.legs.iter().enumerate() {
            let account = accounts
                .get(&leg.account_ref)
                .ok_or_else(|| Fail::Internal("an admitted correction account is absent".into()))?;
            let amount = render_amount(leg.amount, &book.context().units)?;
            human.push_str(&format!(
                "\n  {} {} {amount}",
                side_name(leg.side),
                account.code
            ));
            legs.push(obj(vec![
                ("ordinal", Json::Int(ordinal as i128)),
                ("account", s(&account.code)),
                ("account_vid", s(format!("{:032x}", leg.account_ref.0))),
                ("side", s(side_name(leg.side))),
                ("amount", s(amount)),
            ]));
        }
        members.push(obj(vec![
            ("class", s(proposal.class.name().unwrap_or("?"))),
            ("effective_date", s(proposal.effective_date.render())),
            ("period", s(&member.certificate().period)),
            ("idempotency_key", s(hex(&proposal.idempotency_key))),
            ("intent_digest", s(hex(&member.certificate().intent_digest))),
            (
                "proposal_digest",
                s(hex(&member.certificate().proposal_digest)),
            ),
            (
                "entry_digest",
                s(hex(&member.prepared_entry().entry_digest)),
            ),
            ("legs", Json::Arr(legs)),
            (
                "supersedes",
                Json::Arr(
                    proposal
                        .supersession
                        .iter()
                        .map(|link| lineage_json(link, &reasons))
                        .collect(),
                ),
            ),
            (
                "evidence",
                Json::Arr(
                    proposal
                        .evidence
                        .iter()
                        .map(|e| {
                            obj(vec![
                                ("document_oid", s(hex(&e.document_oid.0))),
                                ("doc_commit", s(hex(&e.doc_commit))),
                                ("role", Json::Int(i128::from(e.role))),
                            ])
                        })
                        .collect(),
                ),
            ),
            ("approvals", Json::Int(member.approvals().len() as i128)),
        ]));
    }
    let encoded = hex(&bytes);
    let rehearsal = out.is_bound_agent();
    let command = if out.is_bound() {
        "fa_post_commit_plan".to_string()
    } else {
        let quoted = |word: &str| format!("'{}'", word.replace('\'', "'\\''"));
        let mut command = format!(
            "fa commit --plan {}",
            quoted(args.flag("--plan-out").unwrap_or("-"))
        );
        for flag in ["--book", "--keys", "--as"] {
            if let Some(value) = args.flag(flag) {
                command.push_str(&format!(" {flag} {}", quoted(value)));
            }
        }
        for grant in args.flag_all("--grant") {
            command.push_str(&format!(" --grant {}", quoted(grant)));
        }
        if plan.replacement().proposal().base_totals.is_some()
            && !args.flag_all("--grant").contains(&"read")
        {
            command.push_str(" --grant 'read'");
        }
        command.push_str(" --json");
        command
    };
    let actions = if rehearsal {
        let warning = "This Agent-profile correction plan is a rehearsal and cannot commit to trunk (FA-REF-013). A Human must independently prepare, review and commit the complete pair; correction drafts are not available yet.";
        out.warn(warning);
        human.push_str(&format!("\n{warning}"));
        Vec::new()
    } else {
        human.push_str(&format!("\nReview both entries, then {command}"));
        vec![(command, "commit the complete artifact with the same independently supplied capability; forward data.bytes when the input is stdin".into())]
    };
    if args.flag("--plan-out").is_none() {
        human.push_str(&format!(
            "\nComplete canonical plan bytes (hex):\n{encoded}"
        ));
    }
    if let Some(path) = args.flag("--plan-out") {
        write_post_plan(files, path, &bytes)?;
    }
    out.at_book(book)?;
    out.known_at(certificate.snapshot_seq);
    out.event_with_actions(
        "replacement_plan",
        vec![
            ("intent_kind", s("Replace")),
            ("target", s(format!("{:032x}", target.vid.0))),
            ("principal", s(format!("{:032x}", certificate.principal.0))),
            ("effects_digest", s(hex(&certificate.effects_digest))),
            (
                "snapshot_seq",
                Json::Int(i128::from(certificate.snapshot_seq.0)),
            ),
            (
                "security_policy_epoch",
                Json::Int(i128::from(certificate.security_policy_epoch)),
            ),
            (
                "expires_at",
                certificate
                    .expires_at
                    .map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
            ),
            (
                "capability_commitment",
                s(hex(&certificate.capability_commitment)),
            ),
            ("certificate_digest", s(certificate_digest)),
            ("plan_digest", s(digest)),
            ("members", Json::Arr(members)),
            ("bytes", s(encoded)),
            ("file", args.flag("--plan-out").map_or(Json::Null, s)),
            ("scope", s("same-snapshot-replacement")),
            (
                "authority",
                s(if out.is_bound() {
                    "mcp-launch-config"
                } else {
                    "embedded-owner"
                }),
            ),
        ],
        &human,
        &actions,
    );
    Ok(())
}

fn commit_replacement_cmd(
    ctx: &mut Ctx<'_>,
    args: &Args,
    plan: ReplacementPlan,
) -> Result<(), Fail> {
    let encode = |e| {
        usage(
            format!("correction plan: {e}"),
            "pass the unchanged artifact from a successful correction dry-run",
        )
    };
    let plan_digest = hex(&plan.digest().map_err(encode)?);
    let certificate_digest = hex(&plan.certificate_digest().map_err(encode)?);
    let capability = ctx.capability(args, &["post"])?;
    let mut book = ctx.books.open(args)?;
    let (reversal, replacement) = match book.commit_replacement_plan(plan.clone(), &capability)? {
        Ok(pair) => pair,
        Err(refusal) if refusal.code == fa_journal::refusal::code::PLAN_INVALIDATED => {
            let replanned = match book.replan_replacement(&plan, &capability)? {
                Ok(replanned) => Ok(fresh_replacement(replanned)?),
                Err(replan) => Err(replan),
            };
            return Err(stale_plan(refusal, replanned, ctx.out.is_bound()));
        }
        Err(refusal) => return Err(refusal.into()),
    };
    ctx.out.at_book(&book)?;
    let already = matches!(replacement, Posted::AlreadyRecorded { .. });
    ctx.out.event("replacement_plan_committed", vec![
        ("reversal", s(format!("{:032x}", reversal.entry_ref().vid.0))),
        ("reversal_digest", s(hex(&reversal.entry_ref().entry_digest))),
        ("replacement", s(format!("{:032x}", replacement.entry_ref().vid.0))),
        ("replacement_digest", s(hex(&replacement.entry_ref().entry_digest))),
        ("recorded_at", Json::Int(i128::from(replacement.recorded_at().0))),
        ("reversal_period", reversal.period().map_or(Json::Null, s)),
        ("replacement_period", replacement.period().map_or(Json::Null, s)),
        ("already_recorded", Json::Bool(already)),
        ("plan_digest", s(&plan_digest)), ("certificate_digest", s(&certificate_digest)),
    ], &format!("{} correction plan {plan_digest}: reversal {:032x} and replacement {:032x} at sequence {}", if already { "Already committed" } else { "Committed" }, reversal.entry_ref().vid.0, replacement.entry_ref().vid.0, replacement.recorded_at().0));
    Ok(())
}

fn commit_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 1 || args.flag_all("--plan").len() != 1 {
        return Err(usage(
            "commit requires exactly one --plan and no positional arguments",
            if ctx.out.is_bound() {
                "call fa_post_commit_plan with exactly one of plan or plan_file; this session's authority stays fixed"
            } else {
                "fa commit --plan <file|-> [--as <principal>] [--grant <op>]... --json"
            },
        ));
    }
    let path = args.require("--plan", "the exact reviewed plan file, or - for stdin")?;
    let plan = match read_post_plan(&ctx.files, path)? {
        CommitPlan::Post(plan) => *plan,
        CommitPlan::Replacement(plan) => return commit_replacement_cmd(ctx, args, *plan),
        CommitPlan::Batch(plan) => return batch_plan::commit(ctx, args, *plan),
    };
    let plan_digest = hex(&plan.digest().map_err(|e| {
        usage(
            format!("cannot identify plan: {e}"),
            "pass the unchanged plan from --dry-run",
        )
    })?);
    let certificate_digest = hex(&plan.certificate().digest().map_err(|e| {
        usage(
            format!("cannot identify plan certificate: {e}"),
            "pass the unchanged plan from --dry-run",
        )
    })?);
    // The artifact is never confirmation for a bound MCP host's dangerous
    // release, even when its capability exactly matches an owner's plan.
    // This check runs before the book is opened and before retry lookup.
    let voids = matches!(
        plan.proposal()
            .pending
            .as_ref()
            .and_then(|pending| pending.disposition.as_ref()),
        Some(Disposition::Voids)
    ) || matches!(
        plan.proposal().control.as_ref(),
        Some(ControlPayload::ReservationRelease)
    );
    if ctx.out.is_bound() && voids {
        gate(&ctx.out, args, "resolve", None, &Condition::Voids)?;
    }
    if plan.proposal().class == EntryClass::CLOSING {
        gate(
            &ctx.out,
            args,
            "close",
            Some("year-end"),
            &Condition::Always,
        )?;
    }
    let capability = ctx.capability(args, &["post"])?;
    let mut book = ctx.books.open(args)?;
    let posted = match book.commit_plan(plan.clone(), &capability)? {
        Ok(posted) => posted,
        Err(refusal) if refusal.code == fa_journal::refusal::code::PLAN_INVALIDATED => {
            let replanned = match book.replan(&plan, &capability)? {
                Ok(replanned) => Ok(fresh_post(replanned)?),
                Err(replan) => Err(replan),
            };
            return Err(stale_plan(refusal, replanned, ctx.out.is_bound()));
        }
        Err(refusal) => return Err(refusal.into()),
    };
    let (entry_ref, recorded_at, period, already_recorded) = match posted {
        Posted::Committed {
            entry_ref,
            recorded_at,
            period,
        } => (entry_ref, recorded_at, Some(period), false),
        Posted::AlreadyRecorded {
            entry_ref,
            recorded_at,
        } => (entry_ref, recorded_at, None, true),
    };
    ctx.out.at_book(&book)?;
    if let Some(period) = &period {
        ctx.out.effective(format!("period:{period}"));
    }
    ctx.out.event(
        "plan_committed",
        vec![
            ("vid", s(format!("{:032x}", entry_ref.vid.0))),
            ("entry_digest", s(hex(&entry_ref.entry_digest))),
            ("recorded_at", Json::Int(i128::from(recorded_at.0))),
            ("period", period.as_ref().map_or(Json::Null, s)),
            ("already_recorded", Json::Bool(already_recorded)),
            ("plan_digest", s(&plan_digest)),
            ("certificate_digest", s(&certificate_digest)),
        ],
        &format!(
            "{} plan {plan_digest} as entry {:032x}, recorded at {} (certificate {certificate_digest})",
            if already_recorded { "Already committed" } else { "Committed" }, entry_ref.vid.0, recorded_at.0,
        ),
    );
    Ok(())
}

/// A fresh plan in a stale plan's refusal detail (fa-we7).
struct FreshPlan {
    plan_digest: [u8; 32],
    certificate_digest: [u8; 32],
    snapshot_seq: CommitSeq,
    security_policy_epoch: u64,
    /// A PostEntry plan's period; null for a correction or a batch.
    period: Option<String>,
    /// For a correction, its replacement member's, as its dry run shows.
    effects_digest: [u8; 32],
    bytes: Vec<u8>,
}

fn fresh_error(error: fa::IntentError) -> Fail {
    Fail::Internal(format!("fresh plan: {error}"))
}

fn fresh_post(replanned: fa::Replanned) -> Result<(Vec<&'static str>, FreshPlan), Fail> {
    let plan = &replanned.plan;
    let certificate = plan.certificate();
    Ok((
        replanned.changed,
        FreshPlan {
            plan_digest: plan.digest().map_err(fresh_error)?,
            certificate_digest: certificate.digest().map_err(fresh_error)?,
            snapshot_seq: certificate.snapshot_seq,
            security_policy_epoch: certificate.security_policy_epoch,
            period: Some(certificate.period.clone()),
            effects_digest: certificate.effects_digest,
            bytes: plan.canonical_bytes().map_err(fresh_error)?,
        },
    ))
}

fn fresh_replacement(
    replanned: fa::Replanned<ReplacementPlan>,
) -> Result<(Vec<&'static str>, FreshPlan), Fail> {
    let plan = &replanned.plan;
    let certificate = plan.replacement().certificate();
    Ok((
        replanned.changed,
        FreshPlan {
            plan_digest: plan.digest().map_err(fresh_error)?,
            certificate_digest: plan.certificate_digest().map_err(fresh_error)?,
            snapshot_seq: certificate.snapshot_seq,
            security_policy_epoch: certificate.security_policy_epoch,
            period: None,
            effects_digest: certificate.effects_digest,
            bytes: plan.canonical_bytes().map_err(fresh_error)?,
        },
    ))
}

fn fresh_batch(
    replanned: fa::Replanned<fa::BatchPlan>,
) -> Result<(Vec<&'static str>, FreshPlan), Fail> {
    let plan = &replanned.plan;
    let certificate = plan.certificate();
    Ok((
        replanned.changed,
        FreshPlan {
            plan_digest: plan.digest().map_err(fresh_error)?,
            certificate_digest: plan.certificate_digest().map_err(fresh_error)?,
            snapshot_seq: certificate.snapshot_seq,
            security_policy_epoch: certificate.security_policy_epoch,
            period: None,
            effects_digest: certificate.effects_digest,
            bytes: plan.canonical_bytes().map_err(fresh_error)?,
        },
    ))
}

/// A stale plan's PlanInvalidated (plan §10.4, fa-we7): the refusal names
/// what changed and carries a fresh plan of the same intent at the current
/// head in its `detail`, never committed here. When the intent can no
/// longer be planned (the period closed, its key recorded meanwhile), the
/// detail carries that refusal instead.
fn stale_plan(
    mut refusal: Refusal,
    replanned: Result<(Vec<&'static str>, FreshPlan), Refusal>,
    bound: bool,
) -> Fail {
    let detail = match replanned {
        Ok((changed, fresh)) => {
            refusal.fix = if bound {
                "review detail.fresh_plan (detail.changed names what differs from the refused plan); to commit it unchanged, call fa_post_commit_plan with plan set to detail.fresh_plan.bytes"
            } else {
                "review detail.fresh_plan (detail.changed names what differs from the refused plan); to commit it unchanged, pass its bytes: fa commit --plan - (the hex on stdin)"
            }
            .to_string();
            obj(vec![
                ("changed", Json::Arr(changed.into_iter().map(s).collect())),
                (
                    "fresh_plan",
                    obj(vec![
                        ("plan_digest", s(hex(&fresh.plan_digest))),
                        ("certificate_digest", s(hex(&fresh.certificate_digest))),
                        ("snapshot_seq", Json::Int(i128::from(fresh.snapshot_seq.0))),
                        (
                            "security_policy_epoch",
                            Json::Int(i128::from(fresh.security_policy_epoch)),
                        ),
                        ("period", fresh.period.map_or(Json::Null, s)),
                        ("effects_digest", s(hex(&fresh.effects_digest))),
                        ("bytes", s(hex(&fresh.bytes))),
                    ]),
                ),
                ("replan_refusal", Json::Null),
            ])
        }
        Err(replan) => obj(vec![
            ("changed", Json::Null),
            ("fresh_plan", Json::Null),
            (
                "replan_refusal",
                obj(vec![
                    ("refusal_id", s(replan.code)),
                    ("exit", Json::Int(i128::from(replan.exit))),
                    ("message", s(&replan.message)),
                    ("fix", s(&replan.fix)),
                ]),
            ),
        ]),
    };
    Fail::RefusalDetail(Box::new((refusal, detail)))
}

pub(crate) fn emit_posted(
    out: &Out,
    posted: Posted,
    class_name: &str,
    typed_reversal: bool,
    reversal_detail: Option<(String, Reason)>,
    amounts: Option<(String, String)>,
) -> Result<(), Fail> {
    let (requested, moved) = match &amounts {
        Some((r, m)) => (s(r), s(m)),
        None => (Json::Null, Json::Null),
    };
    let balancing_text = amounts.as_ref().map_or(String::new(), |(r, m)| {
        format!(" · balancing: requested {r}, moved {m}")
    });
    match posted {
        Posted::Committed {
            entry_ref,
            recorded_at,
            period,
        } => {
            if typed_reversal {
                let (target, reason) = reversal_detail.ok_or_else(|| {
                    Fail::Internal("an admitted typed reversal has no supersession".into())
                })?;
                out.event(
                    "reversed",
                    vec![
                        ("vid", s(format!("{:032x}", entry_ref.vid.0))),
                        ("entry_digest", s(hex(&entry_ref.entry_digest))),
                        ("recorded_at", Json::Int(i128::from(recorded_at.0))),
                        ("period", s(&period)),
                        ("target", s(&target)),
                        ("reason_code", Json::Int(i128::from(reason.code))),
                        ("reason", s(&reason.name)),
                    ],
                    &format!(
                        "reversed {target} as {:032x} in {period}, recorded at {} · reason {}",
                        entry_ref.vid.0, recorded_at.0, reason.name
                    ),
                );
                return Ok(());
            }
            out.event(
                "posted",
                vec![
                    ("class", s(class_name)),
                    ("vid", s(format!("{:032x}", entry_ref.vid.0))),
                    ("entry_digest", s(hex(&entry_ref.entry_digest))),
                    ("recorded_at", Json::Int(i128::from(recorded_at.0))),
                    ("period", s(&period)),
                    ("requested", requested),
                    ("moved", moved),
                ],
                &format!(
                    "posted {:032x} in {period}, recorded at {} (entry_digest {}){balancing_text}",
                    entry_ref.vid.0,
                    recorded_at.0,
                    hex(&entry_ref.entry_digest)
                ),
            );
        }
        Posted::AlreadyRecorded {
            entry_ref,
            recorded_at,
        } => {
            out.event(
                "recorded",
                vec![
                    ("vid", s(format!("{:032x}", entry_ref.vid.0))),
                    ("entry_digest", s(hex(&entry_ref.entry_digest))),
                    ("recorded_at", Json::Int(i128::from(recorded_at.0))),
                    ("requested", requested),
                    ("moved", moved),
                ],
                &format!(
                    "already recorded as {:032x} at {} (same idempotency_key); nothing new was written{balancing_text}",
                    entry_ref.vid.0, recorded_at.0
                ),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// allocate / settle
// ---------------------------------------------------------------------------

const MAX_REVIEW_BYTES: usize = {
    let a = if MAX_ALLOCATION_REVIEW_BYTES > MAX_BALANCE_ALLOCATION_REVIEW_BYTES {
        MAX_ALLOCATION_REVIEW_BYTES
    } else {
        MAX_BALANCE_ALLOCATION_REVIEW_BYTES
    };
    let b = if MAX_SETTLEMENT_REVIEW_BYTES > MAX_SETTLEMENT_GROUP_REVIEW_BYTES {
        MAX_SETTLEMENT_REVIEW_BYTES
    } else {
        MAX_SETTLEMENT_GROUP_REVIEW_BYTES
    };
    if a > b { a } else { b }
};

fn decode_hex_bytes(text: &str, what: &str) -> Result<Vec<u8>, Fail> {
    let trimmed = text.trim();
    if trimmed.is_empty()
        || !trimmed.len().is_multiple_of(2)
        || !trimmed.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(usage(
            format!("expected a canonical binary {what} or its complete hex encoding"),
            format!("pass --review <file> or the {what} event's complete bytes hex string"),
        ));
    }
    if trimmed.len() / 2 > MAX_REVIEW_BYTES {
        return Err(usage(
            format!("{what} exceeds its canonical format limit"),
            format!("pass the complete {what} bytes from a successful review"),
        ));
    }
    trimmed
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let digits = std::str::from_utf8(pair).map_err(|_| {
                usage(
                    "invalid review hex",
                    "pass the complete review bytes string",
                )
            })?;
            u8::from_str_radix(digits, 16).map_err(|_| {
                usage(
                    "invalid review hex",
                    "pass the complete review bytes string",
                )
            })
        })
        .collect()
}

pub(crate) fn read_review_bytes(files: &Files, path: &str, bound: bool) -> Result<Vec<u8>, Fail> {
    let is_inline_hex = path != "-"
        && path.len() >= 28
        && path.len().is_multiple_of(2)
        && path.bytes().all(|b| b.is_ascii_hexdigit());
    if is_inline_hex {
        return decode_hex_bytes(path, "review");
    }
    if bound && path != "-" {
        return Err(usage(
            "--review cannot name a host filesystem path in a launch-bound request",
            "pass the review event's complete bytes hex string in review, or forward it on stdin with -",
        ));
    }
    let limit = MAX_REVIEW_BYTES * 2 + 2;
    let read = |reader: &mut dyn Read| -> Result<Vec<u8>, Fail> {
        let mut bytes = Vec::new();
        reader
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| {
                usage(
                    format!("{path}: {e}"),
                    "pass a readable review file, - for stdin, or complete review bytes in hex",
                )
            })?;
        Ok(bytes)
    };
    let bytes = if path == "-" {
        match &files.stdin {
            Stdin::Forwarded(bytes) => {
                if bytes.len() > limit {
                    return Err(usage(
                        "review input exceeds its bounded wire size",
                        "pass the complete review bytes from a successful review",
                    ));
                }
                bytes.clone()
            }
            Stdin::Missing => {
                return Err(usage(
                    "- names review stdin, but no bytes reached the command",
                    "forward the review event's bytes string, or pass its saved review file",
                ));
            }
            Stdin::Process => read(&mut std::io::stdin().lock())?,
        }
    } else {
        let mut file = std::fs::File::open(files.resolve(path)).map_err(|e| {
            usage(
                format!("{path}: {e}"),
                "pass the review file saved with --review-out, or its complete hex bytes",
            )
        })?;
        read(&mut file)?
    };
    if bytes.len() > limit {
        return Err(usage(
            "review input exceeds its bounded wire size",
            "pass the complete review bytes from a successful review",
        ));
    }
    if bytes.starts_with(b"FA-INTENT\0")
        || bytes.starts_with(fa::RecurringPlan::MAGIC)
        || bytes.starts_with(b"FA-ALLOC-REVIEW\0")
        || bytes.starts_with(b"FA-BAL-REVIEW\0")
        || bytes.starts_with(b"FA-SETTLEMENT-REVIEW\0")
        || bytes.starts_with(b"FA-SETTLEMENT-GROUP-REVIEW\0")
    {
        if bytes.len() > MAX_REVIEW_BYTES {
            return Err(usage(
                "review exceeds its bounded input size",
                "pass the complete review bytes from a successful review",
            ));
        }
        return Ok(bytes);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        usage(
            "expected a canonical binary review or its complete hex encoding",
            "pass --review <file> or the review event's complete bytes hex string",
        )
    })?;
    decode_hex_bytes(text, "review")
}

pub(crate) fn write_review_file(files: &Files, path: &str, bytes: &[u8]) -> Result<(), Fail> {
    if path.is_empty() || path == "-" {
        return Err(usage(
            "--review-out names a new file; - is not an output file",
            "use --review-only to receive the complete review bytes as hex on stdout without writing a file",
        ));
    }
    write_new_output_file(files, path, bytes, "review", "--review-out")
}

fn approve_any_review_bytes(
    ctx: &mut Ctx<'_>,
    args: &Args,
    bytes: &[u8],
    digest: [u8; 32],
) -> Result<(), Fail> {
    if bytes.starts_with(b"FA-BAL-REVIEW\0") || bytes.starts_with(b"FA-ALLOC-REVIEW\0") {
        approve_allocation_review_bytes(ctx, args, bytes, digest)
    } else if bytes.starts_with(b"FA-SETTLEMENT-GROUP-REVIEW\0")
        || bytes.starts_with(b"FA-SETTLEMENT-REVIEW\0")
    {
        approve_settlement_review_bytes(ctx, args, bytes, digest)
    } else {
        Err(usage(
            "unrecognized review artifact format",
            "supply a review exported by `fa allocate --review-out` or `fa settle --review-out`",
        ))
    }
}

fn approve_allocation_review_bytes(
    ctx: &mut Ctx<'_>,
    args: &Args,
    bytes: &[u8],
    digest: [u8; 32],
) -> Result<(), Fail> {
    let capability = ctx.capability(args, &["read", "approve"])?;
    let mut book = ctx.books.open(args)?;
    let approved = if bytes.starts_with(b"FA-BAL-REVIEW\0") {
        let review = BalanceAllocationReview::decode(bytes).map_err(|e| {
            usage(
                format!("invalid balance allocation review: {e}"),
                "supply the unchanged review exported by `fa allocate --review-out`",
            )
        })?;
        book.approve_balance_allocation(&review, digest, &capability)??
    } else {
        let review = AllocationReview::decode(bytes).map_err(|e| {
            usage(
                format!("invalid allocation review: {e}"),
                "supply the unchanged review exported by `fa allocate --review-out`",
            )
        })?;
        book.approve_allocation_review(&review, digest, &capability)??
    };
    emit_approved(&ctx.out, &book, approved)
}

fn approve_settlement_review_bytes(
    ctx: &mut Ctx<'_>,
    args: &Args,
    bytes: &[u8],
    digest: [u8; 32],
) -> Result<(), Fail> {
    let capability = ctx.capability(args, &["read", "approve"])?;
    let mut book = ctx.books.open(args)?;
    let approved = if bytes.starts_with(b"FA-SETTLEMENT-GROUP-REVIEW\0") {
        let review = SettlementGroupReview::decode(bytes).map_err(|e| {
            usage(
                format!("invalid settlement group review: {e}"),
                "supply the unchanged review exported by `fa settle --review-out`",
            )
        })?;
        book.approve_settlement_group_review(&review, digest, &capability)??
    } else {
        let review = SettlementReview::decode(bytes).map_err(|e| {
            usage(
                format!("invalid settlement review: {e}"),
                "supply the unchanged review exported by `fa settle --review-out`",
            )
        })?;
        book.approve_settlement_review(&review, digest, &capability)??
    };
    emit_approved(&ctx.out, &book, approved)
}

/// An allocation reads the book and posts to it: the presented capability
/// is the principal's and is current (not expired or revoked) before
/// anything is read or written.
fn admit_allocation(book: &Book, who: VId, capability: &Capability) -> Result<(), Fail> {
    let _ = book.read_scope(who, capability)??;
    Ok(())
}

/// The allocation basis is the entry's driver evidence. It is supplied under
/// the caller's capability, so `post` authority on this book is checked
/// before the document is observed or written, and its uploader and grade
/// derive from the capability (HumanUpload, or AgentUpload for an Agent).
fn ensure_allocation_driver_imported(
    book: &mut Book,
    posting: &AllocationPosting,
    capability: &Capability,
) -> Result<fa_model::EvidenceRef, Fail> {
    let driver_ev = posting.driver_evidence(book.context().book_id)?;
    if book.document_commitment(&driver_ev.document_oid)?.is_none() {
        book.upload_document(
            capability,
            fa_journal::UploadRequest {
                kind: fa_journal::allocation::ALLOCATION_DOCUMENT_KIND,
                mime: "application/x-fa-allocation-basis".into(),
                bytes: posting.basis_bytes()?,
                asserted_grade: None,
            },
        )??;
    }
    Ok(driver_ev)
}

fn parse_rounding_law(name: &str) -> Result<fa_money::RoundingLaw, Fail> {
    match name {
        "HalfEven" | "half_even" | "half-even" => Ok(fa_money::RoundingLaw::HalfEven),
        "HalfUp" | "half_up" | "half-up" => Ok(fa_money::RoundingLaw::HalfUp),
        "HalfDown" | "half_down" | "half-down" => Ok(fa_money::RoundingLaw::HalfDown),
        "HalfAwayFromZero" | "half_away_from_zero" => Ok(fa_money::RoundingLaw::HalfAwayFromZero),
        "HalfTowardZero" | "half_toward_zero" => Ok(fa_money::RoundingLaw::HalfTowardZero),
        "Down" | "down" | "TowardZero" | "toward_zero" => Ok(fa_money::RoundingLaw::TowardZero),
        "Up" | "up" | "AwayFromZero" | "away_from_zero" => Ok(fa_money::RoundingLaw::AwayFromZero),
        "Floor" | "floor" | "TowardNegativeInfinity" => Ok(fa_money::RoundingLaw::Floor),
        "Ceiling" | "ceiling" | "TowardPositiveInfinity" => Ok(fa_money::RoundingLaw::Ceiling),
        other => Err(usage(
            format!("unknown rounding law `{other}`"),
            "rounding: HalfEven|HalfUp|HalfDown|HalfAwayFromZero|HalfTowardZero|TowardZero|AwayFromZero|Floor|Ceiling",
        )),
    }
}

fn parse_allocation_method(doc: &Json, book_id: Id128) -> Result<AllocationMethod, Fail> {
    let method_name = doc
        .get("method")
        .or_else(|| doc.get("law"))
        .and_then(Json::as_str)
        .unwrap_or("largest_remainder");
    match method_name {
        "largest_remainder" | "LargestRemainder" | "hamilton" => {
            Ok(AllocationMethod::LargestRemainder)
        }
        "waterfall" | "Waterfall" => Ok(AllocationMethod::Waterfall),
        "equal_split_residual_first" | "EqualSplitResidualFirst" | "equal_split" => {
            Ok(AllocationMethod::EqualSplitResidualFirst)
        }
        "pro_rata_residual_to_named" | "ProRataResidualToNamed" | "pro_rata" => {
            let rounding = match doc.get("rounding").and_then(Json::as_str) {
                Some(r) => parse_rounding_law(r)?,
                None => fa_money::RoundingLaw::HalfEven,
            };
            let recipient_code = doc
                .get("recipient")
                .or_else(|| doc.get("residual_account"))
                .and_then(Json::as_str)
                .ok_or_else(|| {
                    usage(
                        "allocation method pro_rata: `recipient` (or `residual_account`) must be a string",
                        "recipient: \"6099\" (target account code that receives the rounding residual)",
                    )
                })?;
            let recipient = account_vid(book_id, recipient_code).0;
            Ok(AllocationMethod::ProRataResidualToNamed {
                rounding,
                recipient,
            })
        }
        other => Err(usage(
            format!("unknown allocation method `{other}`"),
            "method: largest_remainder|pro_rata_residual_to_named|waterfall|equal_split_residual_first",
        )),
    }
}

fn allocation_method_name(method: AllocationMethod) -> &'static str {
    match method {
        AllocationMethod::LargestRemainder => "largest_remainder",
        AllocationMethod::ProRataResidualToNamed { .. } => "pro_rata_residual_to_named",
        AllocationMethod::Waterfall => "waterfall",
        AllocationMethod::EqualSplitResidualFirst => "equal_split_residual_first",
    }
}

fn parse_allocation_targets(
    doc: &Json,
    book_id: Id128,
    method: AllocationMethod,
    units: &fa_money::UnitRegistry,
    unit: fa_money::UnitId,
) -> Result<Vec<AllocationTarget>, Fail> {
    let targets_arr = doc
        .get("targets")
        .and_then(Json::as_arr)
        .ok_or_else(|| {
            usage(
                "allocation intent requires a `targets` array",
                "targets: [{\"account\": \"5100\", \"basis\": 60}, {\"account\": \"5200\", \"basis\": 40}]",
            )
        })?;
    let mut out = Vec::with_capacity(targets_arr.len());
    for (i, item) in targets_arr.iter().enumerate() {
        let what = format!("targets[{i}]");
        let account_code = req_str(item, "account", &what)?;
        let id = account_vid(book_id, account_code).0;
        let basis_val = item
            .get("basis")
            .or_else(|| item.get("weight"))
            .or_else(|| item.get("cap"));
        let basis = match basis_val {
            Some(Json::Int(n)) => u128::try_from(*n).map_err(|_| {
                usage(
                    format!("{what}: basis must be a non-negative integer"),
                    "basis: non-negative integer weight or cap",
                )
            })?,
            Some(Json::Str(text)) => {
                if let Ok(n) = text.parse::<u128>() {
                    n
                } else {
                    let amt = Amount::parse(text, units).map_err(|e| {
                        usage(
                            format!("{what}: basis `{text}`: {e:?}"),
                            "basis: non-negative integer weight, or exact amount string for waterfall cap",
                        )
                    })?;
                    if amt.unit != unit || amt.mantissa < 0 {
                        return Err(usage(
                            format!(
                                "{what}: basis amount must be non-negative in the allocation unit"
                            ),
                            "use the same unit as the allocation source",
                        ));
                    }
                    amt.mantissa.unsigned_abs()
                }
            }
            Some(_) => {
                return Err(usage(
                    format!("{what}: basis must be a non-negative integer"),
                    "basis: 100",
                ));
            }
            None if matches!(method, AllocationMethod::EqualSplitResidualFirst) => 1,
            None => {
                return Err(usage(
                    format!("{what}: missing `basis` (or `weight`/`cap`)"),
                    "targets: [{\"account\": \"5100\", \"basis\": 1}]",
                ));
            }
        };
        out.push(AllocationTarget { id, basis });
    }
    Ok(out)
}

fn parse_allocation_dimensions(doc: &Json) -> Result<Vec<(u32, VId)>, Fail> {
    let Some(dims) = doc.get("dimensions") else {
        return Ok(Vec::new());
    };
    let Some(arr) = dims.as_arr() else {
        return Err(usage(
            "allocation `dimensions` must be an array",
            "dimensions: [{\"dimension\": 1, \"value\": \"<32-hex-vid>\"}]",
        ));
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let what = format!("dimensions[{i}]");
        let dim = match item.get("dimension") {
            Some(Json::Int(n)) => u32::try_from(*n).map_err(|_| {
                usage(
                    format!("{what}: dimension id out of u32 range"),
                    "dimension: 1",
                )
            })?,
            _ => {
                return Err(usage(
                    format!("{what}: missing integer `dimension`"),
                    "dimension: 1",
                ));
            }
        };
        let val_s = req_str(item, "value", &what)?;
        let vid = parse_vid(val_s, &format!("{what}.value"))?;
        out.push((dim, vid));
    }
    Ok(out)
}

fn render_proposal_legs(
    book: &Book,
    proposal: &EntryPayload,
) -> Result<(Vec<Json>, Vec<String>), Fail> {
    let accounts: std::collections::BTreeMap<_, _> =
        book.accounts()?.into_iter().map(|a| (a.vid, a)).collect();
    let mut human_legs = Vec::new();
    let legs = proposal
        .legs
        .iter()
        .enumerate()
        .map(|(ordinal, leg)| {
            let account = accounts.get(&leg.account_ref).ok_or_else(|| {
                usage(
                    format!(
                        "allocation/settlement leg {ordinal} names an unknown account {:032x}",
                        leg.account_ref.0
                    ),
                    "fa chart list shows the installed account codes",
                )
            })?;
            let amount = render_amount(leg.amount, &book.context().units)?;
            let side = side_name(leg.side);
            human_legs.push(format!(
                "  {ordinal}: {side} {} ({}) {amount}",
                account.code, account.name
            ));
            Ok(obj(vec![
                ("ordinal", Json::Int(ordinal as i128)),
                ("account", s(&account.code)),
                ("account_vid", s(format!("{:032x}", leg.account_ref.0))),
                ("side", s(side)),
                ("amount", s(amount)),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    Ok((legs, human_legs))
}

#[allow(clippy::too_many_arguments)]
fn emit_allocation_reviewed(
    out: &Out,
    book: &Book,
    files: &Files,
    args: &Args,
    kind: &str,
    source_code: &str,
    source_period: Option<&str>,
    source_digest: Option<[u8; 32]>,
    posting: &AllocationPosting,
    proposal: &EntryPayload,
    review_digest: [u8; 32],
    proposal_digest: [u8; 32],
    driver_oid: Oid,
    bytes: &[u8],
) -> Result<(), Fail> {
    if let Some(path) = args.flag("--review-out") {
        write_review_file(files, path, bytes)?;
    }
    out.at_book(book)?;
    let (legs, human_legs) = render_proposal_legs(book, proposal)?;
    let total_str = render_amount(posting.request.total, &book.context().units)?;
    let method_str = allocation_method_name(posting.request.method);
    let side_str = side_name(posting.source_side);
    let review_hex = hex(&review_digest);
    let proposal_hex = hex(&proposal_digest);
    let driver_hex = hex(&driver_oid.0);
    let encoded = hex(bytes);
    let human = format!(
        "Reviewed {kind} allocation from {source_code} ({side_str} {total_str}, {method_str})\nReview digest: {review_hex}\nProposal digest: {proposal_hex}\nDriver workpaper: {driver_hex}\n{}",
        human_legs.join("\n")
    );
    out.event(
        "allocation_reviewed",
        vec![
            ("kind", s(kind)),
            ("source", s(source_code)),
            ("source_period", source_period.map_or(Json::Null, s)),
            (
                "source_digest",
                source_digest.map_or(Json::Null, |d| s(hex(&d))),
            ),
            ("source_side", s(side_str)),
            ("total", s(total_str)),
            ("method", s(method_str)),
            ("review_digest", s(review_hex)),
            ("proposal_digest", s(proposal_hex)),
            ("driver_document_oid", s(driver_hex)),
            ("legs", Json::Arr(legs)),
            ("bytes", s(encoded)),
            ("file", args.flag("--review-out").map_or(Json::Null, s)),
        ],
        &human,
    );
    Ok(())
}

fn allocate_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    check_post_planning_options(args)?;
    let sub = args.positional.get(1).map(String::as_str);
    if let Some(other) = sub.filter(|s| *s != "approve") {
        return Err(usage(
            format!("`fa allocate` has no subcommand `{other}`"),
            "fa allocate --intent <file.json|->, fa allocate --review <file|-|hex> --digest <64-hex>, or fa allocate approve --review <file|-|hex> --digest <64-hex>",
        ));
    }
    if sub == Some("approve") || args.switch("--approve") {
        if args.flag("--intent").is_some()
            || args.flag("--review-out").is_some()
            || args.switch("--review-only")
            || args.switch("--dry-run")
        {
            return Err(usage(
                "allocate approve takes only --review <file|-|hex> and --digest <64-hex>",
                "fa allocate approve --review <file|-|hex> --digest <review_digest>",
            ));
        }
        let review_arg = args.require("--review", "<file|-|hex>")?;
        let digest_text = args.require("--digest", "<64-hex review_digest>")?;
        let digest = parse_digest(digest_text, "--digest")?;
        let bytes = read_review_bytes(&ctx.files, review_arg, ctx.out.is_bound())?;
        return approve_allocation_review_bytes(ctx, args, &bytes, digest);
    }

    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "post"])?;
    let out = &ctx.out;

    if let Some(review_arg) = args.flag("--review") {
        if args.flag("--intent").is_some()
            || args.flag("--review-out").is_some()
            || args.switch("--review-only")
        {
            return Err(usage(
                "--review cannot be combined with --intent, --review-out, or --review-only",
                "fa allocate --review <file|-|hex> --digest <64-hex> [--approval <vid>]... [--dry-run]",
            ));
        }
        let digest_text = args.require("--digest", "<64-hex review_digest>")?;
        let digest = parse_digest(digest_text, "--digest")?;
        let bytes = read_review_bytes(&ctx.files, review_arg, out.is_bound())?;
        // Current authority (holder, book, expiry, revocation) is admitted
        // before the book is observed or the basis document is written.
        let mut book = ctx
            .books
            .open_admitted(args, |book| admit_allocation(book, who, &capability))?;
        let plan = if bytes.starts_with(b"FA-BAL-REVIEW\0") {
            let review = BalanceAllocationReview::decode(&bytes).map_err(|e| {
                usage(
                    format!("invalid balance allocation review: {e}"),
                    "supply the unchanged review exported by `fa allocate --review-out`",
                )
            })?;
            ensure_allocation_driver_imported(&mut book, review.review().posting(), &capability)?;
            let prop_digest = review.review().proposal_digest().map_err(|e| {
                usage(
                    format!("invalid allocation review proposal: {e}"),
                    "supply an unchanged review",
                )
            })?;
            let approvals = args
                .flag_all("--approval")
                .iter()
                .map(|v| {
                    Ok(fa_model::ApprovalRef {
                        approval_vid: parse_vid(v, "--approval")?,
                        approved_digest: prop_digest,
                    })
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            book.plan_balance_allocation(&review, digest, approvals, &capability)??
        } else {
            let review = AllocationReview::decode(&bytes).map_err(|e| {
                usage(
                    format!("invalid allocation review: {e}"),
                    "supply the unchanged review exported by `fa allocate --review-out`",
                )
            })?;
            ensure_allocation_driver_imported(&mut book, review.posting(), &capability)?;
            let prop_digest = review.proposal_digest().map_err(|e| {
                usage(
                    format!("invalid allocation review proposal: {e}"),
                    "supply an unchanged review",
                )
            })?;
            let approvals = args
                .flag_all("--approval")
                .iter()
                .map(|v| {
                    Ok(fa_model::ApprovalRef {
                        approval_vid: parse_vid(v, "--approval")?,
                        approved_digest: prop_digest,
                    })
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            book.plan_allocation_review(&review, digest, approvals, &capability)??
        };
        if args.switch("--dry-run") {
            return emit_post_plan(out, &book, &ctx.files, args, &plan, &capability);
        }
        let posted = book.commit_plan(plan, &capability)??;
        out.at_book(&book)?;
        return emit_posted(out, posted, "Allocation", false, None, None);
    }

    let path = args.require("--intent", "allocation.json (or - for stdin)")?;
    let text = ctx.files.read_text(path)?;
    let doc = parse_json(path, &text)?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_allocation(book, who, &capability))?;
    let book_ctx = book.context().clone();
    let source_code = req_str(&doc, "source", "allocation intent")?;
    let source_vid = account_vid(book_ctx.book_id, source_code);
    let date_s = req_str(&doc, "effective_date", "allocation intent")?;
    let effective_date = DateDay::parse(date_s).map_err(|e| {
        usage(
            format!("effective_date `{date_s}`: {e:?}"),
            "effective_date: \"YYYY-MM-DD\"",
        )
    })?;
    let effective_period = doc
        .get("effective_period")
        .and_then(Json::as_str)
        .map(|c| PeriodRef {
            calendar: book_ctx.calendar.id.clone(),
            code: c.to_string(),
        });
    let key = req_str(&doc, "idempotency_key", "allocation intent")?;
    let description = doc.get("description").and_then(Json::as_str).unwrap_or("");
    let method = parse_allocation_method(&doc, book_ctx.book_id)?;
    let dimensions = parse_allocation_dimensions(&doc)?;
    let review_mode = args.flag("--review-out").is_some() || args.switch("--review-only");
    if review_mode && args.switch("--dry-run") {
        return Err(usage(
            "cannot combine --review-out/--review-only with --dry-run",
            "export the review first, or omit --review-out/--review-only to rehearse a PostPlan with --dry-run",
        ));
    }

    let source_period = doc
        .get("source_period")
        .and_then(Json::as_str)
        .or_else(|| args.flag("--period"))
        .map(str::to_string);

    if let Some(period) = source_period {
        if doc.get("total").is_some() {
            return Err(usage(
                "supply either `total` (explicit allocation) or `source_period`/`--period` (journal-derived balance allocation), not both",
                "remove `total` to derive the balance from the journal period, or remove `source_period`/`--period`",
            ));
        }
        let unit = match doc.get("unit").and_then(Json::as_str) {
            Some(code) => book_ctx.units.lookup(code).ok_or_else(|| {
                usage(
                    format!("unknown unit `{code}`"),
                    "use a registered unit code such as USD",
                )
            })?,
            None => book.spec()?.base_unit,
        };
        let targets =
            parse_allocation_targets(&doc, book_ctx.book_id, method, &book_ctx.units, unit)?;
        let bal_req = BalanceAllocationRequest {
            source: source_vid,
            period: period.clone(),
            unit,
            dimensions,
            method,
            targets,
        };
        let prepared = book.prepare_balance_allocation(&bal_req, &capability)??;
        let driver_ev = if review_mode {
            prepared.posting().driver_evidence(book_ctx.book_id)?
        } else {
            ensure_allocation_driver_imported(&mut book, prepared.posting(), &capability)?
        };
        let mut evidence = document::parse_evidence(&doc, args, &mut book)?;
        if !evidence.contains(&driver_ev) {
            evidence.push(driver_ev);
        }
        let template = EntryPayload {
            schema_minor: 0,
            book_id: book_ctx.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ALLOCATION,
            effective_date,
            document_date: None,
            description: book.seal_text(description)?,
            effective_period,
            legs: Vec::new(),
            control: None,
            unit_totals: Vec::new(),
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid(fa_model::domain_digest(
                    b"fa:intent:v1",
                    &[&book_ctx.book_id.0, &who.0.to_le_bytes(), key.as_bytes()],
                )),
                intent_kind: 1,
            },
            principal_ref: who,
            session_ref: None,
            evidence,
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let review = BalanceAllocationReview::new(&prepared, template).map_err(|e| {
            usage(
                format!("cannot build balance allocation review: {e}"),
                "check the allocation targets and template fields",
            )
        })?;
        let review_digest = review
            .digest()
            .map_err(|e| Fail::Internal(format!("balance allocation review digest: {e}")))?;
        let proposal_digest = review
            .review()
            .proposal_digest()
            .map_err(|e| Fail::Internal(format!("balance allocation proposal digest: {e}")))?;
        let bytes = review
            .canonical_bytes()
            .map_err(|e| Fail::Internal(format!("balance allocation review bytes: {e}")))?;
        if review_mode {
            return emit_allocation_reviewed(
                out,
                &book,
                &ctx.files,
                args,
                "balance",
                source_code,
                Some(&period),
                Some(review.source_digest()),
                review.review().posting(),
                review.review().proposal(),
                review_digest,
                proposal_digest,
                driver_ev.document_oid,
                &bytes,
            );
        }
        let approvals = args
            .flag_all("--approval")
            .iter()
            .map(|v| {
                Ok(fa_model::ApprovalRef {
                    approval_vid: parse_vid(v, "--approval")?,
                    approved_digest: proposal_digest,
                })
            })
            .collect::<Result<Vec<_>, Fail>>()?;
        let plan =
            book.plan_balance_allocation(&review, review_digest, approvals, &capability)??;
        if args.switch("--dry-run") {
            return emit_post_plan(out, &book, &ctx.files, args, &plan, &capability);
        }
        let posted = book.commit_plan(plan, &capability)??;
        out.at_book(&book)?;
        emit_posted(out, posted, "Allocation", false, None, None)
    } else {
        let total_s = req_str(
            &doc,
            "total",
            "explicit allocation intent (or supply source_period/--period)",
        )?;
        let total = Amount::parse(total_s, &book_ctx.units).map_err(|e| {
            usage(
                format!("total `{total_s}`: {e:?}"),
                "total: \"100.00 USD\" (positive amount in a registered unit)",
            )
        })?;
        let source_side = match req_str(&doc, "source_side", "explicit allocation intent")? {
            "debit" | "dr" | "Debit" => Side::Debit,
            "credit" | "cr" | "Credit" => Side::Credit,
            other => {
                return Err(usage(
                    format!("source_side `{other}`"),
                    "source_side: debit|credit (the side posted to the source account)",
                ));
            }
        };
        let targets =
            parse_allocation_targets(&doc, book_ctx.book_id, method, &book_ctx.units, total.unit)?;
        let posting = AllocationPosting {
            source: source_vid,
            source_side,
            dimensions,
            request: AllocationRequest {
                total,
                method,
                targets,
            },
        };
        let driver_ev = if review_mode {
            posting.driver_evidence(book_ctx.book_id)?
        } else {
            ensure_allocation_driver_imported(&mut book, &posting, &capability)?
        };
        let mut evidence = document::parse_evidence(&doc, args, &mut book)?;
        if !evidence.contains(&driver_ev) {
            evidence.push(driver_ev);
        }
        let template = EntryPayload {
            schema_minor: 0,
            book_id: book_ctx.book_id,
            branch_id: Id128::TRUNK,
            class: EntryClass::ALLOCATION,
            effective_date,
            document_date: None,
            description: book.seal_text(description)?,
            effective_period,
            legs: Vec::new(),
            control: None,
            unit_totals: Vec::new(),
            base_totals: None,
            idempotency_key: key.as_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid(fa_model::domain_digest(
                    b"fa:intent:v1",
                    &[&book_ctx.book_id.0, &who.0.to_le_bytes(), key.as_bytes()],
                )),
                intent_kind: 1,
            },
            principal_ref: who,
            session_ref: None,
            evidence,
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let review = AllocationReview::new(posting, template).map_err(|e| {
            usage(
                format!("cannot build allocation review: {e}"),
                "check the allocation total, source_side, and targets",
            )
        })?;
        let review_digest = review
            .digest()
            .map_err(|e| Fail::Internal(format!("allocation review digest: {e}")))?;
        let proposal_digest = review
            .proposal_digest()
            .map_err(|e| Fail::Internal(format!("allocation proposal digest: {e}")))?;
        let bytes = review
            .canonical_bytes()
            .map_err(|e| Fail::Internal(format!("allocation review bytes: {e}")))?;
        if review_mode {
            return emit_allocation_reviewed(
                out,
                &book,
                &ctx.files,
                args,
                "explicit",
                source_code,
                None,
                None,
                review.posting(),
                review.proposal(),
                review_digest,
                proposal_digest,
                driver_ev.document_oid,
                &bytes,
            );
        }
        let approvals = args
            .flag_all("--approval")
            .iter()
            .map(|v| {
                Ok(fa_model::ApprovalRef {
                    approval_vid: parse_vid(v, "--approval")?,
                    approved_digest: proposal_digest,
                })
            })
            .collect::<Result<Vec<_>, Fail>>()?;
        let plan =
            book.plan_allocation_review(&review, review_digest, approvals, &capability)??;
        if args.switch("--dry-run") {
            return emit_post_plan(out, &book, &ctx.files, args, &plan, &capability);
        }
        let posted = book.commit_plan(plan, &capability)??;
        out.at_book(&book)?;
        emit_posted(out, posted, "Allocation", false, None, None)
    }
}

fn parse_settlement_targets(item: &Json, what: &str) -> Result<Vec<(VId, u16)>, Fail> {
    let arr = item.get("targets").and_then(Json::as_arr).ok_or_else(|| {
        usage(
            format!("{what}: missing `targets` array"),
            "targets: [{\"entry\": \"<32-hex-vid>\", \"ordinal\": 0}]",
        )
    })?;
    let mut out = Vec::with_capacity(arr.len());
    for (i, t) in arr.iter().enumerate() {
        let twhat = format!("{what}.targets[{i}]");
        let vid_s = req_str(t, "entry", &twhat)?;
        let vid = parse_vid(vid_s, &format!("{twhat}.entry"))?;
        let ordinal = match t.get("ordinal") {
            Some(Json::Int(n)) => u16::try_from(*n).map_err(|_| {
                usage(
                    format!("{twhat}: ordinal {n} is out of u16 range"),
                    "ordinal: 0-based leg index on the target entry",
                )
            })?,
            None => 0,
            _ => {
                return Err(usage(
                    format!("{twhat}: ordinal must be a non-negative integer"),
                    "ordinal: 0",
                ));
            }
        };
        out.push((vid, ordinal));
    }
    Ok(out)
}

fn parse_payment_leg(item: &Json, what: &str) -> Result<u16, Fail> {
    match item.get("payment_leg") {
        Some(Json::Int(n)) => u16::try_from(*n).map_err(|_| {
            usage(
                format!("{what}: payment_leg {n} is out of u16 range"),
                "payment_leg: 0-based index of the applying leg in `legs`",
            )
        }),
        _ => Err(usage(
            format!("{what}: missing integer `payment_leg`"),
            "payment_leg: 0 (the 0-based index of the applying leg in `legs`)",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn emit_settlement_reviewed(
    out: &Out,
    book: &Book,
    files: &Files,
    args: &Args,
    kind: &str,
    known_at: CommitSeq,
    proposal: &EntryPayload,
    applications: Vec<Json>,
    review_digest: [u8; 32],
    proposal_digest: [u8; 32],
    bytes: &[u8],
) -> Result<(), Fail> {
    if let Some(path) = args.flag("--review-out") {
        write_review_file(files, path, bytes)?;
    }
    out.at_book(book)?;
    out.known_at(known_at);
    let (legs, human_legs) = render_proposal_legs(book, proposal)?;
    let review_hex = hex(&review_digest);
    let proposal_hex = hex(&proposal_digest);
    let encoded = hex(bytes);
    let human = format!(
        "Reviewed {kind} settlement at sequence {}\nReview digest: {review_hex}\nProposal digest: {proposal_hex}\n{}",
        known_at.0,
        human_legs.join("\n")
    );
    out.event(
        "settlement_reviewed",
        vec![
            ("kind", s(kind)),
            ("known_at", Json::Int(i128::from(known_at.0))),
            ("review_digest", s(review_hex)),
            ("proposal_digest", s(proposal_hex)),
            ("applications", Json::Arr(applications)),
            ("legs", Json::Arr(legs)),
            ("bytes", s(encoded)),
            ("file", args.flag("--review-out").map_or(Json::Null, s)),
        ],
        &human,
    );
    Ok(())
}

fn settle_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    check_post_planning_options(args)?;
    let sub = args.positional.get(1).map(String::as_str);
    if let Some(other) = sub.filter(|s| *s != "approve") {
        return Err(usage(
            format!("`fa settle` has no subcommand `{other}`"),
            "fa settle --intent <file.json|->, fa settle --review <file|-|hex> [--digest <64-hex>], or fa settle approve --review <file|-|hex> --digest <64-hex>",
        ));
    }
    if sub == Some("approve") || args.switch("--approve") {
        if args.flag("--intent").is_some()
            || args.flag("--review-out").is_some()
            || args.switch("--review-only")
            || args.switch("--dry-run")
        {
            return Err(usage(
                "settle approve takes only --review <file|-|hex> and --digest <64-hex>",
                "fa settle approve --review <file|-|hex> --digest <review_digest>",
            ));
        }
        let review_arg = args.require("--review", "<file|-|hex>")?;
        let digest_text = args.require("--digest", "<64-hex review_digest>")?;
        let digest = parse_digest(digest_text, "--digest")?;
        let bytes = read_review_bytes(&ctx.files, review_arg, ctx.out.is_bound())?;
        return approve_settlement_review_bytes(ctx, args, &bytes, digest);
    }

    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "post"])?;
    let out = &ctx.out;

    if let Some(review_arg) = args.flag("--review") {
        if args.flag("--intent").is_some()
            || args.flag("--review-out").is_some()
            || args.switch("--review-only")
        {
            return Err(usage(
                "--review cannot be combined with --intent, --review-out, or --review-only",
                "fa settle --review <file|-|hex> [--digest <64-hex>] [--approval <vid>]... [--dry-run]",
            ));
        }
        let expected_digest = args
            .flag("--digest")
            .map(|t| parse_digest(t, "--digest"))
            .transpose()?;
        let bytes = read_review_bytes(&ctx.files, review_arg, out.is_bound())?;
        let mut book = ctx.books.open(args)?;
        let (plan, class_name) = if bytes.starts_with(b"FA-SETTLEMENT-GROUP-REVIEW\0") {
            let review = SettlementGroupReview::decode(&bytes).map_err(|e| {
                usage(
                    format!("invalid settlement group review: {e}"),
                    "supply the unchanged review exported by `fa settle --review-out`",
                )
            })?;
            if let Some(expected) = expected_digest {
                let actual = review.digest().map_err(|e| {
                    usage(
                        format!("invalid settlement group review: {e}"),
                        "supply an unchanged review",
                    )
                })?;
                if actual != expected {
                    return Err(Refusal::new(
                        fa_journal::refusal::code::PLAN_INVALIDATED,
                        exit::CONFLICT,
                        "settlement group review digest does not match --digest",
                        "fa:settlement-group-review:v1; plan §5.7 / §10.4",
                        "supply the unchanged review and its matching --digest",
                    )
                    .into());
                }
            }
            let prop_digest = review.proposal().proposal_digest().map_err(|e| {
                usage(
                    format!("invalid settlement proposal: {e}"),
                    "supply an unchanged review",
                )
            })?;
            let approvals = args
                .flag_all("--approval")
                .iter()
                .map(|v| {
                    Ok(fa_model::ApprovalRef {
                        approval_vid: parse_vid(v, "--approval")?,
                        approved_digest: prop_digest,
                    })
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            let class_name = review
                .proposal()
                .class
                .name()
                .unwrap_or("Original")
                .to_string();
            let group_plan =
                book.plan_settlement_group_review(&review, approvals, &capability)??;
            (group_plan.into_post_plan(), class_name)
        } else {
            let review = SettlementReview::decode(&bytes).map_err(|e| {
                usage(
                    format!("invalid settlement review: {e}"),
                    "supply the unchanged review exported by `fa settle --review-out`",
                )
            })?;
            if let Some(expected) = expected_digest {
                let actual = review.digest().map_err(|e| {
                    usage(
                        format!("invalid settlement review: {e}"),
                        "supply an unchanged review",
                    )
                })?;
                if actual != expected {
                    return Err(Refusal::new(
                        fa_journal::refusal::code::PLAN_INVALIDATED,
                        exit::CONFLICT,
                        "settlement review digest does not match --digest",
                        "fa:settlement-review:v1; plan §5.7 / §10.4",
                        "supply the unchanged review and its matching --digest",
                    )
                    .into());
                }
            }
            let prop_digest = review.proposal().proposal_digest().map_err(|e| {
                usage(
                    format!("invalid settlement proposal: {e}"),
                    "supply an unchanged review",
                )
            })?;
            let approvals = args
                .flag_all("--approval")
                .iter()
                .map(|v| {
                    Ok(fa_model::ApprovalRef {
                        approval_vid: parse_vid(v, "--approval")?,
                        approved_digest: prop_digest,
                    })
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            let class_name = review
                .proposal()
                .class
                .name()
                .unwrap_or("Original")
                .to_string();
            let single_plan = book.plan_settlement_review(&review, approvals, &capability)??;
            (single_plan.into_post_plan(), class_name)
        };
        if args.switch("--dry-run") {
            return emit_post_plan(out, &book, &ctx.files, args, &plan, &capability);
        }
        let posted = book.commit_plan(plan, &capability)??;
        out.at_book(&book)?;
        return emit_posted(out, posted, &class_name, false, None, None);
    }

    let path = args.require("--intent", "settlement.json (or - for stdin)")?;
    let text = ctx.files.read_text(path)?;
    let doc = parse_json(path, &text)?;
    let Json::Obj(fields) = &doc else {
        return Err(usage(
            "settlement intent must be a JSON object",
            "fa settle --help",
        ));
    };
    let review_mode = args.flag("--review-out").is_some() || args.switch("--review-only");
    if review_mode && args.switch("--dry-run") {
        return Err(usage(
            "cannot combine --review-out/--review-only with --dry-run",
            "export the review first, or omit --review-out/--review-only to rehearse a PostPlan with --dry-run",
        ));
    }

    let base_fields: Vec<(String, Json)> = fields
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "payment_leg" | "targets" | "payments" | "applications"
            )
        })
        .cloned()
        .collect();
    let base_doc = Json::Obj(base_fields);

    let mut book = ctx.books.open(args)?;
    let proposal =
        build_proposal_from_intent(out, &mut book, args, &base_doc, who, capability.clone())?;
    let class_name = proposal.class.name().unwrap_or("Original").to_string();
    let accounts: std::collections::BTreeMap<_, _> =
        book.accounts()?.into_iter().map(|a| (a.vid, a)).collect();

    if let Some(payments_val) = doc.get("payments").or_else(|| doc.get("applications")) {
        if doc.get("payment_leg").is_some() || doc.get("targets").is_some() {
            return Err(usage(
                "supply either `payments` (multi-leg group) or `payment_leg` + `targets` (single-leg), not both",
                "put each leg selection inside `payments: [{\"payment_leg\": 0, \"targets\": [...]}]`",
            ));
        }
        let payments_arr = payments_val.as_arr().ok_or_else(|| {
            usage(
                "`payments` must be an array of leg selections",
                "payments: [{\"payment_leg\": 0, \"targets\": [{\"entry\": \"<vid>\", \"ordinal\": 0}]}]",
            )
        })?;
        let mut payments = Vec::with_capacity(payments_arr.len());
        for (i, p) in payments_arr.iter().enumerate() {
            let what = format!("payments[{i}]");
            let payment_leg = parse_payment_leg(p, &what)?;
            let targets = parse_settlement_targets(p, &what)?;
            payments.push(SettlementLegSelection {
                payment_leg,
                targets,
            });
        }
        let req = SettlementGroupRequest { proposal, payments };
        let prepared = book.prepare_settlement_group(req, &capability)??;
        if review_mode {
            let review = prepared.export_review().map_err(|e| {
                usage(
                    format!("cannot export settlement group review: {e}"),
                    "check the settlement group proposal and targets",
                )
            })?;
            let review_digest = review
                .digest()
                .map_err(|e| Fail::Internal(format!("settlement group review digest: {e}")))?;
            let proposal_digest = review
                .proposal()
                .proposal_digest()
                .map_err(|e| Fail::Internal(format!("settlement group proposal digest: {e}")))?;
            let bytes = review
                .canonical_bytes()
                .map_err(|e| Fail::Internal(format!("settlement group review bytes: {e}")))?;
            let apps = review
                .allocations()
                .iter()
                .map(|part| {
                    let code = accounts
                        .get(&part.allocation.request.account)
                        .map_or("?", |a| a.code.as_str());
                    let unapplied = render_amount(
                        Amount::new(
                            fa_money::UnitId(part.allocation.request.unit_id),
                            part.allocation.unapplied,
                        ),
                        &book.context().units,
                    )?;
                    Ok(obj(vec![
                        ("payment_leg", Json::Int(i128::from(part.payment_leg))),
                        ("account", s(code)),
                        (
                            "applied_count",
                            Json::Int(part.allocation.allocations.len() as i128),
                        ),
                        ("unapplied", s(unapplied)),
                    ]))
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            return emit_settlement_reviewed(
                out,
                &book,
                &ctx.files,
                args,
                "group",
                review.known_at(),
                review.proposal(),
                apps,
                review_digest,
                proposal_digest,
                &bytes,
            );
        }
        let prop_digest = prepared
            .proposal()
            .proposal_digest()
            .map_err(|e| Fail::Internal(format!("settlement group proposal digest: {e}")))?;
        let approvals = args
            .flag_all("--approval")
            .iter()
            .map(|v| {
                Ok(fa_model::ApprovalRef {
                    approval_vid: parse_vid(v, "--approval")?,
                    approved_digest: prop_digest,
                })
            })
            .collect::<Result<Vec<_>, Fail>>()?;
        let plan = book
            .plan_prepared_settlement_group(prepared, approvals, &capability)??
            .into_post_plan();
        if args.switch("--dry-run") {
            return emit_post_plan(out, &book, &ctx.files, args, &plan, &capability);
        }
        let posted = book.commit_plan(plan, &capability)??;
        out.at_book(&book)?;
        emit_posted(out, posted, &class_name, false, None, None)
    } else {
        let payment_leg = parse_payment_leg(&doc, "settlement intent")?;
        let targets = parse_settlement_targets(&doc, "settlement intent")?;
        let req = SettlementPostRequest {
            proposal,
            payment_leg,
            targets,
        };
        let prepared = book.prepare_settlement(req, &capability)??;
        if review_mode {
            let review = prepared.export_review().map_err(|e| {
                usage(
                    format!("cannot export settlement review: {e}"),
                    "check the settlement proposal and targets",
                )
            })?;
            let review_digest = review
                .digest()
                .map_err(|e| Fail::Internal(format!("settlement review digest: {e}")))?;
            let proposal_digest = review
                .proposal()
                .proposal_digest()
                .map_err(|e| Fail::Internal(format!("settlement proposal digest: {e}")))?;
            let bytes = review
                .canonical_bytes()
                .map_err(|e| Fail::Internal(format!("settlement review bytes: {e}")))?;
            let alloc = review.allocation();
            let code = accounts
                .get(&alloc.request.account)
                .map_or("?", |a| a.code.as_str());
            let unapplied = render_amount(
                Amount::new(fa_money::UnitId(alloc.request.unit_id), alloc.unapplied),
                &book.context().units,
            )?;
            let apps = vec![obj(vec![
                ("payment_leg", Json::Int(i128::from(review.payment_leg()))),
                ("account", s(code)),
                ("applied_count", Json::Int(alloc.allocations.len() as i128)),
                ("unapplied", s(unapplied)),
            ])];
            return emit_settlement_reviewed(
                out,
                &book,
                &ctx.files,
                args,
                "single",
                alloc.known_at,
                review.proposal(),
                apps,
                review_digest,
                proposal_digest,
                &bytes,
            );
        }
        let prop_digest = prepared
            .proposal()
            .proposal_digest()
            .map_err(|e| Fail::Internal(format!("settlement proposal digest: {e}")))?;
        let approvals = args
            .flag_all("--approval")
            .iter()
            .map(|v| {
                Ok(fa_model::ApprovalRef {
                    approval_vid: parse_vid(v, "--approval")?,
                    approved_digest: prop_digest,
                })
            })
            .collect::<Result<Vec<_>, Fail>>()?;
        let plan = book
            .plan_prepared_settlement(prepared, approvals, &capability)??
            .into_post_plan();
        if args.switch("--dry-run") {
            return emit_post_plan(out, &book, &ctx.files, args, &plan, &capability);
        }
        let posted = book.commit_plan(plan, &capability)??;
        out.at_book(&book)?;
        emit_posted(out, posted, &class_name, false, None, None)
    }
}

// ---------------------------------------------------------------------------
// tb / verify / registers / entry
// ---------------------------------------------------------------------------

/// The envelope's effective selector for a period selection (plan §4.8).
pub(crate) fn periods_selector(periods: &[String]) -> String {
    match periods {
        [] => "all".to_string(),
        [one] => format!("period:{one}"),
        many => format!("periods:{}", many.join(",")),
    }
}

fn time_selection_json(time: &fa::InstantSelection) -> Json {
    let resolution = &time.resolution;
    let tick = |tick: &fa_time::TimeObservation, entry: VId| {
        obj(vec![
            ("entry", s(format!("{:032x}", entry.0))),
            ("recorded_at", Json::Int(i128::from(tick.recorded_at))),
            (
                "observed_utc_ns",
                Json::Int(i128::from(tick.observed_utc_ns)),
            ),
            ("source", Json::Int(i128::from(tick.source))),
            ("monotonic_ok", Json::Bool(tick.monotonic_ok)),
        ])
    };
    obj(vec![
        (
            "requested_instant",
            s(fa_time::UtcInstant::from_unix_ns(resolution.requested_utc_ns).to_string()),
        ),
        (
            "requested_utc_ns",
            Json::Int(i128::from(resolution.requested_utc_ns)),
        ),
        ("frontier", Json::Int(i128::from(resolution.frontier))),
        (
            "resolved_seq",
            Json::Int(i128::from(resolution.resolved_seq)),
        ),
        ("precision", s(resolution.precision_grade())),
        ("source_grade", s(resolution.source_grade())),
        ("lower", tick(&resolution.lower, time.lower_entry)),
        (
            "upper",
            resolution
                .upper
                .as_ref()
                .zip(time.upper_entry)
                .map_or(Json::Null, |(observation, entry)| tick(observation, entry)),
        ),
    ])
}

/// Parse and resolve a known-at selector. An instant records its evidence
/// beside the resolved sequence; missing evidence is never a HEAD fallback.
pub(crate) fn known_at_flag(
    args: &Args,
    book: &Book,
    out: &Out,
) -> Result<(Option<CommitSeq>, Option<u64>), Fail> {
    let flag = if args.flag("--known-at").is_some() {
        "--known-at"
    } else {
        "--as-known-at"
    };
    if args.flag_all("--as-known-at").len() + args.flag_all("--known-at").len() > 1 {
        return Err(usage(
            format!("{flag} may be supplied only once; --known-at and --as-known-at are aliases"),
            format!("{flag} HEAD, <u64 commit sequence>, or <RFC3339 instant>"),
        ));
    }
    match args.flag(flag) {
        None | Some("HEAD") => Ok((None, None)),
        Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
            let sequence = value.parse::<u64>().map_err(|_| {
                usage(
                    format!("{flag} commit sequence exceeds u64"),
                    format!("{flag} HEAD or an existing unsigned commit sequence"),
                )
            })?;
            Ok((Some(CommitSeq(sequence)), None))
        }
        Some(value) => {
            let instant = fa_time::UtcInstant::parse(value).map_err(|error| {
                usage(
                    format!("invalid {flag} selector: {error}"),
                    format!("{flag} HEAD, <u64 commit sequence>, or 2026-03-15T00:00:00Z"),
                )
            })?;
            let time = book.resolve_known_at_instant(instant.unix_ns())??;
            out.time_selection(Some(&time));
            Ok((
                Some(CommitSeq(time.resolution.resolved_seq)),
                Some(instant.unix_ns()),
            ))
        }
    }
}

/// Resolve an authorized read's recorded coordinate. Resolving an instant
/// currently reads TimeEvidence at the head, so scoped tokens must use an
/// explicit sequence until that lookup itself has a bounded read API.
pub(crate) fn known_at_read_flag(
    args: &Args,
    book: &Book,
    out: &Out,
    capability: &Capability,
) -> Result<(Option<CommitSeq>, Option<u64>), Fail> {
    if let Some(value) = args
        .flag("--known-at")
        .or_else(|| args.flag("--as-known-at"))
        && value != "HEAD"
        && !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        admit_whole_book_read(book, capability, &[], "resolving a known-at instant")?;
    }
    known_at_flag(args, book, out)
}

const TB_VIEW_EXAMPLE: &str = "fa tb --period FY2026-P03 --as-originally-reported | --as-issued-to <audience> | --as-reported-in C:<oid>";

pub(crate) fn selected_periods(args: &Args, book: &Book) -> Result<Vec<String>, Fail> {
    if args.flag_all("--fiscal-year").len() > 1
        || (args.flag("--fiscal-year").is_some() && args.flag("--period").is_some())
    {
        return Err(usage(
            "select repeated --period values or one --fiscal-year, not both",
            "--period FY2026-P03 (repeatable) or --fiscal-year 2026",
        ));
    }
    let mut periods: Vec<String> = args
        .flag_all("--period")
        .iter()
        .map(|p| (*p).to_string())
        .collect();
    if let Some(fy) = args.flag("--fiscal-year") {
        let fy: i32 = fy
            .parse()
            .map_err(|_| usage("--fiscal-year must be a year", "--fiscal-year 2026"))?;
        periods.extend(
            book.periods()?
                .into_iter()
                .filter(|p| p.fiscal_year == fy)
                .map(|p| p.code),
        );
    }
    if periods.is_empty() {
        return Err(usage(
            "no periods selected",
            "--period FY2026-P03 (repeatable) or --fiscal-year 2026",
        ));
    }
    periods.sort();
    periods.dedup();
    Ok(periods)
}

/// An account's net movement, debits minus credits, in checked arithmetic.
/// Both are journal folds, so a result outside the exact amount range is a
/// foundation defect in the fold (exit 5), never a value to wrap or saturate.
fn tb_net(code: &str, debits: i128, credits: i128) -> Result<i128, Fail> {
    debits.checked_sub(credits).ok_or_else(|| {
        Fail::Internal(format!(
            "account {code}: debits {debits} minus credits {credits} is outside the exact amount range; nothing was written, and `fa doctor --json` checks the book and its derived state"
        ))
    })
}

/// Complete report families admit their native input closure before loading
/// history, including Produce when their existing retention contract needs it.
fn prepare_certificate_history(
    book: &mut Book,
    capability: &Capability,
    additional_ops: &[fa_policy::Op],
    known_at: Option<CommitSeq>,
) -> Result<(), Fail> {
    admit_whole_book_read(
        book,
        capability,
        additional_ops,
        "certifying and retaining a report",
    )?;
    book.prepare_report_history(capability.holder(), capability, known_at)??;
    Ok(())
}

/// Legacy native reports and certificates keep their Read-only admission contract.
/// Full history can be loaded only by a current whole-book reader. A scoped
/// caller keeps the existing evaluation path without loading additional data;
/// this adapter does not manufacture a scoped native-history capability.
pub(crate) fn prepare_native_certificate_history(
    book: &mut Book,
    capability: &Capability,
    known_at: Option<CommitSeq>,
) -> Result<(), Fail> {
    fa_policy::admit_read(capability, capability.holder(), book.context().book_id)
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    book.admit_current(capability)??;
    if fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None).is_ok() {
        book.prepare_report_history(capability.holder(), capability, known_at)??;
    }
    Ok(())
}

pub(crate) fn tb_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    // A dimension-filtered report is its own uncertified literal fold
    // (fa-ficc); it refuses the flags of every other mode.
    if args.flag("--dimension").is_some() {
        return crate::dimension::tb(ctx, args);
    }
    const RENDER_EXAMPLE: &str = "fa tb --period FY2026-P03 --render pdf --out trial-balance.pdf";
    let render = render_request(args, RENDER_EXAMPLE)?;
    if render.is_some()
        && (args.switch("--summary")
            || args.switch("--functional")
            || args.flag("--branch").is_some())
    {
        return Err(usage(
            "--render renders a trunk trial balance of native leaf accounts; it does not combine with --summary, --functional or --branch",
            RENDER_EXAMPLE,
        ));
    }
    if args.switch("--functional") {
        return crate::fx::functional_tb(ctx, args);
    }
    let who = ctx.principal(args);
    let summary_cap = if args.switch("--summary") {
        let ops: &[&str] = if args.switch("--certify") || args.flag("--certificate-out").is_some() {
            &["read", "produce"]
        } else {
            &["read"]
        };
        Some(ctx.capability(args, ops)?)
    } else {
        None
    };
    let certify_cap = if !args.switch("--summary")
        && (args.switch("--certify") || args.flag("--certificate-out").is_some())
    {
        Some(ctx.capability(args, &["read"])?)
    } else {
        None
    };
    // A native trial balance, plain or certified, is read under the
    // session's capability: admitted before the book is observed, and its
    // selection judged against the scope caveats before any query is
    // constructed (doctrine 8, fa-0x0); a caveat refuses, never filters. A
    // head read also loads its register window under it (fa-715).
    let read_cap = match &certify_cap {
        Some(capability) => capability.clone(),
        None => ctx.capability(args, &["read"])?,
    };
    let out = &ctx.out;
    let mut book = if let Some(capability) = summary_cap.as_ref() {
        ctx.books.open_admitted(args, |book| {
            // A summary retains the whole underlying leaf fold even when
            // --root selects fewer displayed groups. Admit that reach and
            // current authority before resolving time, periods or issuance.
            fa_policy::admit_read(capability, who, book.context().book_id)
                .and_then(|()| {
                    fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None)
                })
                .and_then(|()| {
                    if args.switch("--certify") || args.flag("--certificate-out").is_some() {
                        fa_policy::require(
                            capability,
                            fa_policy::Op::Produce,
                            "certifying and retaining a summary trial balance",
                        )
                    } else {
                        Ok(())
                    }
                })
                .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
            book.read_scope(who, capability)??;
            book.prepare_report_history(who, capability, None)??;
            Ok(())
        })?
    } else if let Some(capability) = certify_cap.as_ref() {
        ctx.books.open_admitted(args, |book| {
            prepare_native_certificate_history(book, capability, None)
        })?
    } else {
        ctx.books.open_admitted(args, |book| {
            book.read_scope(who, &read_cap)??;
            Ok(())
        })?
    };
    if args.positional.len() != 1 {
        return Err(usage("unexpected trial-balance argument", "fa tb --help"));
    }
    if args.flag_all("--as-of").len() > 1 {
        return Err(usage("--as-of may be supplied only once", "fa tb --help"));
    }
    if args.flag_all("--certificate-out").len() > 1 {
        return Err(usage(
            "--certificate-out may be supplied only once",
            "fa tb --help",
        ));
    }
    if !args.flag_all("--root").is_empty() && !args.switch("--summary") {
        return Err(usage(
            "--root requires --summary",
            "fa tb --period <code> --summary --root <code> --json",
        ));
    }
    let view = crate::issuance::reported_view(args, TB_VIEW_EXAMPLE)?;
    let (mut known_at, requested_utc_ns) = known_at_flag(args, &book, out)?;
    let selection = if let Some(date) = args.flag("--as-of") {
        if args.flag("--period").is_some()
            || args.flag("--fiscal-year").is_some()
            || args.switch("--activity")
        {
            return Err(usage(
                "--as-of cannot be combined with --period, --fiscal-year or --activity",
                "fa tb --as-of 2026-03-15 --book <dir>",
            ));
        }
        let day = DateDay::parse(date).map_err(|e| {
            usage(
                format!("{e}; --as-of requires a civil date; instant selectors are unsupported"),
                "--as-of YYYY-MM-DD",
            )
        })?;
        TrialBalanceSelection::AsOf(day)
    } else {
        let periods = selected_periods(args, &book)?;
        if args.switch("--activity") {
            TrialBalanceSelection::Activity(periods)
        } else {
            TrialBalanceSelection::Periods(periods)
        }
    };
    // Plan §7.4: a restatement view pins the period's known-at: as
    // originally reported (its first StatementIssuance, else its first Lock;
    // never HEAD, never a Close), as issued to an audience, or as reported in
    // a retained statement certificate.
    if let Some(view) = &view {
        let period = match &selection {
            TrialBalanceSelection::Periods(periods) | TrialBalanceSelection::Activity(periods)
                if periods.len() == 1 =>
            {
                periods[0].clone()
            }
            _ => {
                return Err(usage(
                    "a restatement view reads one period as it was reported; select exactly one --period",
                    TB_VIEW_EXAMPLE,
                ));
            }
        };
        // The period's scope is judged before its issuances, transitions or
        // certificate are read; the pinned coordinate is judged again before
        // the fold.
        book.read_scope(who, &read_cap)??
            .admit_report(&selection.clone().into(), known_at)??;
        known_at = Some(crate::issuance::reported_known_at(
            &book, &read_cap, view, &period,
        )?);
    }
    if let Some(capability) = summary_cap {
        book.prepare_report_history(who, &capability, known_at)??;
        let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
        if certify && requested_utc_ns.is_some() {
            return Err(usage(
                "summary certificates bind a recorded sequence; instant-resolution evidence is not part of this certificate format",
                format!(
                    "use --as-known-at {} to certify this resolved summary",
                    known_at.map_or(0, |seq| seq.0)
                ),
            ));
        }
        let roots: Vec<VId> = args
            .flag_all("--root")
            .into_iter()
            .flat_map(|r| r.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|code| account_vid(book.context().book_id, code))
            .collect();
        let scope = if roots.is_empty() {
            SummaryScope::AllRoots
        } else {
            SummaryScope::Selected(roots)
        };
        let request = SummaryRequest {
            selection: selection.clone(),
            scope,
            known_at,
        };
        if certify {
            let certified = book.certify_summary_trial_balance(who, &capability, &request)??;
            let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
            let (bytes, retained) = notary::retain_report_artifact(
                &mut book,
                &ctx.files,
                args,
                &artifact,
                &capability,
            )?;
            let digest = hex(artifact.digest());
            render_summary_trial_balance(out, &book, &certified.report, &selection, Some(&digest))?;
            notary::emit_report_artifact(
                out,
                args,
                &artifact,
                "fa:summary-trial-balance:v1",
                &bytes,
                &retained,
            );
            return Ok(());
        }
        let summary = book.summary_trial_balance(who, &capability, &request)??;
        return render_summary_trial_balance(out, &book, &summary, &selection, None);
    }
    book.read_scope(who, &read_cap)??
        .admit_report(&selection.clone().into(), known_at)??;
    let (tb, certificate, served) = if let Some(capability) = certify_cap.as_ref() {
        prepare_native_certificate_history(&mut book, capability, known_at)?;
        let certified = match requested_utc_ns {
            Some(instant) => {
                book.certify_trial_balance_at_instant(selection.clone(), instant)??
            }
            None => book.certify_trial_balance(selection.clone(), known_at)??,
        };
        out.time_selection(certified.certificate.time_selection.as_ref());
        (certified.report, Some(certified.certificate), None)
    } else {
        // A head read is answered from maintained registers plus the exact
        // tail when they can serve it, and says how it was served (fa-715,
        // plan §17). Loading the delta window is only preparation: a
        // capability that cannot load it reads the journal literally, and
        // the disclosure names its refusal.
        let window = if known_at.is_none() && !matches!(selection, TrialBalanceSelection::AsOf(_)) {
            Some(book.prepare_head_reads(who, &read_cap)?)
        } else {
            None
        };
        let refused = |refusal: Refusal| {
            Some(fa_registers::Served::Literal(format!(
                "this capability cannot load the register window ({}: {}); the read folds the journal",
                refusal.code, refusal.message
            )))
        };
        match (&selection, window) {
            (TrialBalanceSelection::Periods(periods), Some(Ok(()))) => {
                let (report, served) = book.trial_balance_served(periods)?;
                (report, None, Some(served))
            }
            (TrialBalanceSelection::Activity(periods), Some(Ok(()))) => {
                let (report, served) = book.period_activity_served(periods)?;
                (report, None, Some(served))
            }
            (TrialBalanceSelection::Periods(periods), Some(Err(refusal))) => (
                book.trial_balance_at(periods, None)?,
                None,
                refused(refusal),
            ),
            (TrialBalanceSelection::Activity(periods), Some(Err(refusal))) => {
                (book.period_activity(periods, None)?, None, refused(refusal))
            }
            (TrialBalanceSelection::AsOf(day), _) => {
                (book.balance_as_of(*day, known_at)?, None, None)
            }
            (TrialBalanceSelection::Periods(periods), None) => {
                (book.trial_balance_at(periods, known_at)?, None, None)
            }
            (TrialBalanceSelection::Activity(periods), None) => {
                (book.period_activity(periods, known_at)?, None, None)
            }
        }
    };
    validate_trial_balance_units(&tb, &book.context().units)?;
    // A requested document is rendered (a missing clock tick refused) and
    // written before a certificate is retained or the report emitted.
    let rendering = render
        .as_ref()
        .map(|request| {
            let rendering = render_trial_balance_document(&book, &tb, &selection, request)?;
            write_rendering(&ctx.files, request, &rendering)?;
            Ok::<_, Fail>(rendering)
        })
        .transpose()?;
    let retained = certificate
        .as_ref()
        .zip(certify_cap.as_ref())
        .map(|(certificate, cap)| {
            notary::retain_report_certificate(&mut book, &ctx.files, args, certificate, cap)
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    render_trial_balance(
        out,
        &book,
        &tb,
        &selection,
        digest.as_deref(),
        served.as_ref(),
    )?;
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        notary::emit_report_certificate(out, args, certificate, &bytes, &retained);
    }
    if let (Some(request), Some(rendering)) = (render.as_ref(), rendering) {
        emit_rendering(out, request, rendering);
    }
    Ok(())
}

/// A trunk trial balance (stock, activity or as-of) as a rendered document
/// (fa-cet): one table per native unit, each row an account's debits,
/// credits and net, exactly as `fa tb` reports them.
fn render_trial_balance_document(
    book: &Book,
    tb: &fa_registers::TrialBalance,
    selection: &TrialBalanceSelection,
    request: &RenderRequest<'_>,
) -> Result<Rendering, Fail> {
    let specs = unit_format_specs(
        &book.context().units,
        tb.rows
            .iter()
            .map(|row| row.unit_id)
            .chain(tb.unit_totals.keys().copied()),
    )?;
    if specs.is_empty() {
        return Err(usage(
            "the trial balance has no rows, so there is no document to render",
            "post entries first, or read it without --render",
        ));
    }
    let effective_label = match selection {
        TrialBalanceSelection::AsOf(day) => format!("as of {}", day.render()),
        TrialBalanceSelection::Activity(periods) => format!("activity {}", periods.join(", ")),
        TrialBalanceSelection::Periods(periods) => match tb.effective_through {
            Some(day) => format!("{} (through {})", periods.join(", "), day.render()),
            None => periods.join(", "),
        },
    };
    let input = fa::TrialBalanceIrInput {
        book_id: book.context().book_id,
        branch_id: Id128::TRUNK,
        known_at: tb.known_at.0,
        effective_label,
        activity_only: tb.activity,
        rows: tb
            .rows
            .iter()
            .map(|row| fa::TrialBalanceIrRow {
                account_code: row.code.clone(),
                account_name: row.name.clone(),
                unit_id: row.unit_id,
                debits: row.debits,
                credits: row.credits,
            })
            .collect(),
    };
    let ir = fa::render_trial_balance_ir(&input, &specs)
        .map_err(|e| Fail::Internal(format!("trial balance IR: {e}")))?;
    render_ir(book, request, &ir)
}

pub(crate) fn render_summary_trial_balance(
    out: &Out,
    book: &Book,
    summary: &fa::SummaryTrialBalance,
    selection: &TrialBalanceSelection,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let units = &book.context().units;
    validate_trial_balance_units(&summary.source, units)?;
    let periods: &[String] = match selection {
        TrialBalanceSelection::Periods(periods) | TrialBalanceSelection::Activity(periods) => {
            periods
        }
        TrialBalanceSelection::AsOf(_) => &[],
    };
    out.known_at(summary.source.known_at);
    out.effective(match selection {
        TrialBalanceSelection::AsOf(date) => format!("as-of:{date}"),
        _ => periods_selector(periods),
    });
    let render = |unit: u32, m: i128| render_amount(Amount::new(fa_money::UnitId(unit), m), units);
    let groups: Vec<Json> = summary
        .groups
        .iter()
        .map(|g| {
            let rows: Vec<Json> = g
                .rows
                .iter()
                .map(|r| {
                    Ok(obj(vec![
                        ("code", s(&r.code)),
                        ("name", s(&r.name)),
                        ("type", s(r.account_type.name().unwrap_or("?"))),
                        ("debits", s(render(r.unit_id, r.debits)?)),
                        ("credits", s(render(r.unit_id, r.credits)?)),
                        (
                            "net",
                            s(render(r.unit_id, tb_net(&r.code, r.debits, r.credits)?)?),
                        ),
                        ("debits_pending", s(render(r.unit_id, r.debits_pending)?)),
                        ("credits_pending", s(render(r.unit_id, r.credits_pending)?)),
                    ]))
                })
                .collect::<Result<_, Fail>>()?;
            Ok(obj(vec![
                ("code", s(&g.account.code)),
                ("name", s(&g.account.name)),
                (
                    "type",
                    s(AccountType(g.account.account_type).name().unwrap_or("?")),
                ),
                ("leaf", Json::Bool(g.account.is_leaf)),
                (
                    "leaves",
                    Json::Arr(g.leaves.iter().map(|l| s(&l.code)).collect()),
                ),
                ("rows", Json::Arr(rows)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    let pending_totals: Vec<Json> = summary
        .pending_unit_totals
        .iter()
        .map(|(u, (d, c))| {
            Ok(obj(vec![
                (
                    "unit",
                    s(registered_unit_code(fa_money::UnitId(*u), units)?),
                ),
                ("debits_pending", s(render(*u, *d)?)),
                ("credits_pending", s(render(*u, *c)?)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    let totals: Vec<Json> = summary
        .unit_totals
        .iter()
        .map(|(u, (d, c))| {
            Ok(obj(vec![
                (
                    "unit",
                    s(registered_unit_code(fa_money::UnitId(*u), units)?),
                ),
                ("debits", s(render(*u, *d)?)),
                ("credits", s(render(*u, *c)?)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    let uncovered: Vec<Json> = summary
        .uncovered_leaves
        .iter()
        .map(|l| s(&l.code))
        .collect();
    out.event_with_certificate(
        "summary_trial_balance",
        vec![
            ("periods", Json::Arr(periods.iter().map(s).collect())),
            ("known_at", Json::Int(i128::from(summary.source.known_at.0))),
            (
                "effective_through",
                summary
                    .source
                    .effective_through
                    .map_or(Json::Null, |d| s(d.render())),
            ),
            ("activity", Json::Bool(summary.source.activity)),
            (
                "mode",
                s(if summary.source.activity {
                    "activity"
                } else {
                    "stock"
                }),
            ),
            ("complete", Json::Bool(summary.is_complete())),
            ("balanced", Json::Bool(summary.is_complete_and_balanced())),
            ("groups", Json::Arr(groups)),
            ("uncovered_leaves", Json::Arr(uncovered)),
            ("unit_totals", Json::Arr(totals)),
            ("pending_unit_totals", Json::Arr(pending_totals)),
        ],
        &format!(
            "summary trial balance · {} group(s) · complete={} · balanced={}",
            summary.groups.len(),
            summary.is_complete(),
            summary.is_complete_and_balanced()
        ),
        certificate,
    );
    Ok(())
}

/// `fa statement lint --definition <name> [--as-known-at HEAD|<seq>]`: does
/// the definition partition the chart a statement folds at that frontier
/// (plan §12.1, FA-INV-04)? Findings are data (`clean`), never a refusal.
fn statement_lint(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa statement lint --definition us_gaap_small_company_balance_sheet [--as-known-at <seq>] --json";
    for flag in [
        "--for",
        "--compare",
        "--before",
        "--after",
        "--max-publications",
        "--certificate-out",
        "--branch",
        "--before-certificate",
        "--after-certificate",
        "--from-diff",
        "--certificate",
        "--issued-to",
        "--document",
        "--key",
        "--date",
        "--plan",
        "--approval",
        "--render",
        "--out",
    ] {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!("{flag} does not apply to `fa statement lint`, which reads the chart"),
                EXAMPLE,
            ));
        }
    }
    for switch in ["--certify", "--as-originally-reported", "--dry-run"] {
        if args.switch(switch) {
            return Err(usage(
                format!("{switch} does not apply to `fa statement lint`"),
                EXAMPLE,
            ));
        }
    }
    if args.flag_all("--definition").len() != 1 {
        return Err(usage(
            format!(
                "statement lint takes exactly one --definition: {}",
                fa::statements::LINTABLE_DEFINITIONS.join(", ")
            ),
            EXAMPLE,
        ));
    }
    let definition = args.require("--definition", "the definition to lint")?;
    let who = ctx.principal(args);
    let cap = ctx.capability(args, &["read"])?;
    let book = ctx
        .books
        .open_admitted(args, |book| crate::rea::admit_read(book, who, &cap))?;
    let (requested, _) = known_at_flag(args, &book, &ctx.out)?;
    let at = match requested {
        Some(seq) => seq,
        None => book.head()?,
    };
    let report = book.lint_statement(definition, at, &cap)??;
    ctx.out.at_book(&book)?;
    let strings = |items: &[String]| Json::Arr(items.iter().map(s).collect());
    let clean = report.is_clean();
    let human = if clean {
        format!(
            "{definition} partitions the chart at {}: {} covered leaves, each mapped once",
            at.0, report.covered_leaf_count
        )
    } else {
        format!(
            "{definition} does not partition the chart at {}: {} unmapped, {} multiply mapped, {} unknown, {} summary, {} outside coverage",
            at.0,
            report.unmapped_leaves.len(),
            report.multiply_mapped_leaves.len(),
            report.unknown_referenced_codes.len(),
            report.summary_referenced_codes.len(),
            report.outside_coverage_codes.len()
        )
    };
    ctx.out.event(
        "statement_lint",
        vec![
            ("definition", s(&report.definition_name)),
            ("version", Json::Int(i128::from(report.definition_version))),
            ("definition_digest", s(hex(&report.definition_digest.0))),
            ("known_at", Json::Int(i128::from(at.0))),
            ("clean", Json::Bool(clean)),
            (
                "covered_leaves",
                Json::Int(i128::from(report.covered_leaf_count)),
            ),
            (
                "mapped_leaves",
                Json::Int(i128::from(report.mapped_leaf_count)),
            ),
            ("unmapped_leaves", strings(&report.unmapped_leaves)),
            (
                "multiply_mapped_leaves",
                Json::Arr(
                    report
                        .multiply_mapped_leaves
                        .iter()
                        .map(|(account, lines)| {
                            obj(vec![("account", s(account)), ("lines", strings(lines))])
                        })
                        .collect(),
                ),
            ),
            ("unknown_codes", strings(&report.unknown_referenced_codes)),
            ("summary_codes", strings(&report.summary_referenced_codes)),
            (
                "outside_coverage_codes",
                strings(&report.outside_coverage_codes),
            ),
            ("empty_lines", strings(&report.empty_account_lines)),
            (
                "mappings",
                Json::Arr(
                    report
                        .mappings
                        .iter()
                        .map(|(account, line)| {
                            obj(vec![("account", s(account)), ("line", s(line))])
                        })
                        .collect(),
                ),
            ),
            (
                "report_digest",
                s(hex(&report
                    .digest()
                    .map_err(|e| Fail::Internal(format!("statement lint digest: {e}")))?
                    .0)),
            ),
        ],
        &human,
    );
    Ok(())
}

fn statement_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "statement needs a registered definition name, diff|trace, or issue|issuances",
            "fa statement balance-sheet|income-statement --for <period> [--compare <period>] --json",
        ));
    }
    let functional = args.switch("--functional");
    if functional
        && (matches!(
            args.positional[1].as_str(),
            "trace" | "issue" | "issuances" | "lint" | "equity-roll-forward"
        ) || args.flag("--branch").is_some()
            || args.flag("--from-diff").is_some()
            || crate::issuance::view_flag(args).is_some())
    {
        return Err(usage(
            "--functional selects a trunk balance sheet, income statement, or two-frontier statement diff; traces, issuance views and branch workflows do not support this basis",
            "fa statement diff --functional --definition income-statement --for <period> --before <seq> --after <seq> [--certify]",
        ));
    }
    // Statement issuance (plan §12.5, bead fa-wrrw).
    match args.positional[1].as_str() {
        "issue" => return crate::issuance::issue(ctx, args),
        "issuances" => return crate::issuance::issuances(ctx, args),
        "lint" => return statement_lint(ctx, args),
        "equity-roll-forward" => return statement_equity_roll_forward(ctx, args),
        _ => {}
    }
    if let Some(flag) = crate::issuance::ISSUE_ONLY
        .iter()
        .find(|flag| crate::issuance::present(args, flag))
    {
        return Err(usage(
            format!("{flag} applies only to `fa statement issue`, never to a statement report"),
            "fa statement issue --certificate C:<oid> --issued-to <audience> --dry-run --json",
        ));
    }
    for flag in [
        "--for",
        "--compare",
        "--definition",
        "--before",
        "--after",
        "--max-publications",
        "--certificate-out",
        "--before-certificate",
        "--after-certificate",
        "--from-diff",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("{flag} may be supplied only once"),
                "fa statement balance-sheet --for FY2026-P03 --compare FY2026-P02 --json",
            ));
        }
    }
    const RENDER_EXAMPLE: &str =
        "fa statement balance-sheet --for FY2026-P03 --render pdf --out balance-sheet.pdf";
    let render = render_request(args, RENDER_EXAMPLE)?;
    let presentation = presentation_request(args)?;
    let from_certificates = ["--before-certificate", "--after-certificate", "--from-diff"]
        .iter()
        .any(|flag| args.flag(flag).is_some());
    if render.is_some()
        && (from_certificates || matches!(args.positional[1].as_str(), "diff" | "trace"))
    {
        return Err(usage(
            "--render renders one statement; a diff or trace is not rendered",
            RENDER_EXAMPLE,
        ));
    }
    if presentation.is_some()
        && (from_certificates
            || render.is_some()
            || matches!(args.positional[1].as_str(), "diff" | "trace"))
    {
        return Err(usage(
            "--present-in presents one statement report; a diff, trace, certificate comparison or --render is not presented",
            PRESENT_EXAMPLE,
        ));
    }
    if from_certificates {
        return statement_from_certificates(ctx, args);
    }
    let period = args.require("--for", "<period>, for example FY2026-P03")?;
    if period.is_empty() || args.flag("--compare").is_some_and(str::is_empty) {
        return Err(usage(
            "statement period codes must not be empty",
            "--for FY2026-P03 [--compare FY2026-P02]",
        ));
    }
    let mode = args.positional[1].as_str();
    if matches!(mode, "diff" | "trace") {
        if args.flag("--known-at").is_some()
            || args.flag("--as-known-at").is_some()
            || crate::issuance::view_flag(args).is_some()
        {
            return Err(usage(
                "statement diff and trace select two frontiers with --before and --after; --known-at, --as-known-at and the restatement views (--as-originally-reported, --as-issued-to, --as-reported-in, --as-currently-stated) do not select this workflow",
                "fa statement diff --definition balance-sheet --for <period> --before <seq> --after <seq> --json",
            ));
        }
        if mode == "diff" && args.flag("--max-publications").is_some() {
            return Err(usage(
                "--max-publications bounds a statement trace, not a two-frontier diff",
                "use statement trace with --max-publications, or omit that flag for statement diff",
            ));
        }
        let def_name = args.require("--definition", "balance-sheet|income-statement")?;
        let definition = StatementDefinition::embedded(def_name).map_err(|error| {
            usage(
                format!("statement definition: {error}"),
                "fa statement diff --definition balance-sheet --for <period> --before <seq> --json",
            )
        })?;
        let before_raw = args.require("--before", "<seq>")?;
        let before = CommitSeq(before_raw.parse::<u64>().map_err(|_| {
            usage(
                "--before must be a recorded CommitSeq integer",
                "--before 1",
            )
        })?);
        let after = match args.flag("--after") {
            None | Some("HEAD") => None,
            Some(raw) => Some(CommitSeq(raw.parse::<u64>().map_err(|_| {
                usage(
                    "--after must be HEAD or a recorded CommitSeq integer",
                    "--after HEAD",
                )
            })?)),
        };
        let selection = StatementSelection {
            definition,
            periods: vec![period.to_string()],
            comparative: args
                .flag("--compare")
                .into_iter()
                .map(String::from)
                .collect(),
        };
        let who = ctx.principal(args);
        let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
        let capability = ctx.capability(
            args,
            if certify {
                &["read", "produce"]
            } else {
                &["read"]
            },
        )?;
        let mut book = ctx.books.open_admitted(args, |book| {
            prepare_certificate_history(
                book,
                &capability,
                if certify {
                    &[fa_policy::Op::Produce]
                } else {
                    &[]
                },
                Some(before),
            )
        })?;
        let comparison = StatementDiffRequest {
            selection,
            before,
            after,
        };
        if mode == "diff" {
            if certify {
                let certified = if functional {
                    book.certify_functional_statement_diff(who, &capability, &comparison)??
                } else {
                    book.certify_statement_diff(who, &capability, &comparison)??
                };
                return emit_certified_statement_diff(
                    &ctx.out,
                    &ctx.files,
                    args,
                    &mut book,
                    &capability,
                    &certified,
                );
            }
            let diff = if functional {
                book.functional_statement_diff(who, &capability, &comparison)??
            } else {
                book.statement_diff(who, &capability, &comparison)??
            };
            return render_statement_diff(&ctx.out, &book, &diff, None);
        }
        let request = StatementTraceRequest {
            comparison,
            max_publications: max_publications(args)?,
        };
        if certify {
            let certified = book.certify_statement_trace(who, &capability, &request)??;
            return emit_certified_statement_trace(
                &ctx.out,
                &ctx.files,
                args,
                &mut book,
                &capability,
                &certified,
            );
        }
        let trace = book.statement_trace(who, &capability, &request)??;
        return render_statement_trace(&ctx.out, &book, &trace, None);
    }
    let definition = StatementDefinition::embedded(mode).map_err(|error| {
        usage(
            format!("statement definition: {error}"),
            "fa statement balance-sheet|income-statement --for <period> --json",
        )
    })?;
    let selection = StatementSelection {
        definition,
        periods: vec![period.to_string()],
        comparative: args
            .flag("--compare")
            .into_iter()
            .map(String::from)
            .collect(),
    };
    let render_definition = render.as_ref().map(|_| selection.definition.clone());
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let view = crate::issuance::reported_view(
        args,
        "fa statement balance-sheet --for FY2026-P03 --as-originally-reported | --as-issued-to <audience> | --as-reported-in C:<oid>",
    )?;
    let who = ctx.principal(args);
    let capability = ctx.capability(
        args,
        if functional && certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    let mut book = ctx.books.open_admitted(args, |book| {
        if functional {
            let selected = args
                .flag("--known-at")
                .or_else(|| args.flag("--as-known-at"))
                .and_then(|raw| raw.parse::<u64>().ok())
                .map(CommitSeq);
            fa_policy::admit_read(&capability, who, book.context().book_id)
                .and_then(|()| {
                    fa_policy::reach(
                        &capability,
                        &fa_policy::Reach {
                            observes: selected
                                .map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
                            ..fa_policy::Reach::whole_book(true)
                        },
                        None,
                    )
                })
                .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        } else {
            prepare_native_certificate_history(book, &capability, None)?;
        }
        book.read_scope(who, &capability)??;
        Ok(())
    })?;
    let (mut known_at, requested_utc_ns) = known_at_flag(args, &book, &ctx.out)?;
    // Each column's reach is judged against the scope caveats before the
    // period's transitions or any column is read (doctrine 8, fa-0x0), and
    // the pinned coordinate is judged again before the fold.
    let reach = if functional {
        ReportSelection::FunctionalStatement(Box::new(selection.clone()))
    } else {
        ReportSelection::from(selection.clone())
    };
    // Plan §7.4: the statement as its --for period was reported (first, to
    // an audience, or in a retained certificate); a --compare column is read
    // at that same snapshot.
    if let Some(view) = &view {
        book.read_scope(who, &capability)??
            .admit_report(&reach, known_at)??;
        known_at = Some(crate::issuance::reported_known_at(
            &book,
            &capability,
            view,
            period,
        )?);
    }
    book.read_scope(who, &capability)??
        .admit_report(&reach, known_at)??;
    if !functional {
        prepare_native_certificate_history(&mut book, &capability, known_at)?;
    }
    let (statement, certificate) = if functional && certify {
        let certified = match requested_utc_ns {
            Some(instant) => {
                book.certify_functional_statement_at_instant(who, &capability, selection, instant)??
            }
            None => book.certify_functional_statement(who, &capability, selection, known_at)??,
        };
        ctx.out
            .time_selection(certified.certificate.time_selection.as_ref());
        (certified.statement, Some(certified.certificate))
    } else if functional {
        (
            book.functional_statement(who, &capability, selection, known_at)??,
            None,
        )
    } else if certify {
        let certified = match requested_utc_ns {
            Some(instant) => book.certify_statement_at_instant(selection, instant)??,
            None => book.certify_statement(selection, known_at)??,
        };
        ctx.out
            .time_selection(certified.certificate.time_selection.as_ref());
        (certified.statement, Some(certified.certificate))
    } else {
        (book.statement(selection, known_at)??, None)
    };
    // Render every amount, column and mapping before retaining a certificate
    // or emitting a success. Missing units never become printable fallbacks.
    let rendered = statement_presentation_basis(&statement, &book.context().units, functional)?;
    let presented = presentation
        .map(|request| present_statement(&statement, &book.context().units, request))
        .transpose()?;
    // A requested document is rendered (a missing clock tick refused) and
    // written before a certificate is retained or the report emitted.
    let rendering = match (render.as_ref(), render_definition.as_ref()) {
        (Some(request), Some(definition)) => {
            let specs = unit_format_specs(
                &book.context().units,
                statement.lines.iter().map(|line| line.unit_id),
            )?;
            let mut ir = fa::render_statement_ir(&statement, definition, &specs)
                .map_err(|e| Fail::Internal(format!("statement IR: {e}")))?;
            if functional {
                let unit = functional_statement_unit(&statement, &book.context().units)?;
                ir.definition_name
                    .push_str(&format!(" (functional {unit}; retained base amounts)"));
                ir.markdown.push_str(&format!("\nValuation basis: functional currency {unit}, from retained base amounts verified under their original laws.\n"));
            }
            let rendering = render_ir(&book, request, &ir)?;
            write_rendering(&ctx.files, request, &rendering)?;
            Some(rendering)
        }
        _ => None,
    };
    let retained = certificate
        .as_ref()
        .map(|certificate| {
            notary::retain_report_certificate(&mut book, &ctx.files, args, certificate, &capability)
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    emit_statement(&ctx.out, &statement, rendered, digest.as_deref());
    if let Some((fields, human)) = presented {
        ctx.out.event("statement_presented", fields, &human);
    }
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        notary::emit_report_certificate(&ctx.out, args, certificate, &bytes, &retained);
    }
    if let (Some(request), Some(rendering)) = (render.as_ref(), rendering) {
        emit_rendering(&ctx.out, request, rendering);
    }
    Ok(())
}

const STATEMENT_CERTIFICATES_EXAMPLE: &str = "fa statement diff --before-certificate C:<oid> --after-certificate C:<oid> [--certify] --json, or fa statement trace --from-diff C:<oid> [--max-publications 64] --certify --json";

/// `--max-publications` for a statement trace (default 64); the library
/// refuses a value outside 1..=256.
fn max_publications(args: &Args) -> Result<usize, Fail> {
    args.flag("--max-publications")
        .unwrap_or("64")
        .parse()
        .map_err(|_| {
            usage(
                "--max-publications must be an integer in 1..=256",
                "--max-publications 64",
            )
        })
}

/// Retain a certified statement comparison (after its replay), then render
/// the bridge and its certificate.
fn emit_certified_statement_diff(
    out: &Out,
    files: &Files,
    args: &Args,
    book: &mut Book,
    capability: &Capability,
    certified: &fa::CertifiedStatementDiff,
) -> Result<(), Fail> {
    let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
    let (bytes, retained) =
        notary::retain_report_artifact(book, files, args, &artifact, capability)?;
    render_statement_diff(out, book, &certified.report, Some(&hex(artifact.digest())))?;
    notary::emit_report_artifact(
        out,
        args,
        &artifact,
        certified.certificate.output_format(),
        &bytes,
        &retained,
    );
    Ok(())
}

/// Retain a certified statement trace (after its replay), then render the
/// publications and the trace certificate.
fn emit_certified_statement_trace(
    out: &Out,
    files: &Files,
    args: &Args,
    book: &mut Book,
    capability: &Capability,
    certified: &fa::CertifiedStatementTrace,
) -> Result<(), Fail> {
    let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
    let (bytes, retained) =
        notary::retain_report_artifact(book, files, args, &artifact, capability)?;
    render_statement_trace(out, book, &certified.report, Some(&hex(artifact.digest())))?;
    notary::emit_report_artifact(
        out,
        args,
        &artifact,
        "fa:statement-trace:v1",
        &bytes,
        &retained,
    );
    Ok(())
}

/// The statement a caller says it means (`--for`, `--compare`,
/// `--definition`) must be exactly the one the retained certificates answer.
/// It is checked, never used to re-select; omitting it accepts theirs.
fn statement_question_matches(args: &Args, selection: &fa::StatementSelection) -> Result<(), Fail> {
    let definition = selection.definition.name();
    let comparative: Vec<String> = args
        .flag("--compare")
        .into_iter()
        .map(String::from)
        .collect();
    let same_definition = args
        .flag("--definition")
        .is_none_or(|name| name == definition);
    let same_periods = args
        .flag("--for")
        .is_none_or(|period| selection.periods == [period] && selection.comparative == comparative);
    if same_definition && same_periods {
        return Ok(());
    }
    let compared = if selection.comparative.is_empty() {
        "no comparative".to_string()
    } else {
        format!("comparative {}", selection.comparative.join(", "))
    };
    Err(fa_journal::Refusal::new(
        fa::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        format!(
            "the certificates answer {definition} for {} with {compared}, not the statement --for/--compare/--definition name",
            selection.periods.join(", ")
        ),
        "plan §8.3 / §13.6 (a retained comparison answers only the question its sources were certified for)",
        "pass the certificates of the statement you mean, or omit --for, --compare and --definition to accept theirs",
    )
    .into())
}

/// `statement diff --before-certificate --after-certificate` bridges two
/// retained statement certificates; `statement trace --from-diff` attributes a
/// saved comparison to every intermediate publication. Both replay what was
/// retained and keep the original source certificates. Frontiers are never
/// re-selected; a stated --for/--compare/--definition is checked against them.
fn statement_from_certificates(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    for flag in [
        "--before",
        "--after",
        "--known-at",
        "--as-known-at",
        "--branch",
    ] {
        if args.flag(flag).is_some() {
            return Err(usage(
                format!(
                    "{flag} selects a frontier; certificate inputs already fix both frontiers on trunk"
                ),
                STATEMENT_CERTIFICATES_EXAMPLE,
            ));
        }
    }
    if let Some(flag) = crate::issuance::view_flag(args) {
        return Err(usage(
            format!(
                "{flag} selects a frontier; certificate inputs already fix both frontiers on trunk"
            ),
            STATEMENT_CERTIFICATES_EXAMPLE,
        ));
    }
    if args.flag("--compare").is_some() && args.flag("--for").is_none() {
        return Err(usage(
            "--compare names the comparative column of a --for period",
            "--for FY2026-P03 --compare FY2026-P02, or omit both to accept the certificates' own periods",
        ));
    }
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let who = ctx.principal(args);
    match args.positional[1].as_str() {
        "diff" => {
            if args.flag("--from-diff").is_some() || args.flag("--max-publications").is_some() {
                return Err(usage(
                    "--from-diff and --max-publications start a statement trace, not a statement diff",
                    "fa statement trace --from-diff C:<oid> --certify --json",
                ));
            }
            let (Some(before), Some(after)) = (
                args.flag("--before-certificate"),
                args.flag("--after-certificate"),
            ) else {
                return Err(usage(
                    "a certificate comparison needs both --before-certificate and --after-certificate",
                    STATEMENT_CERTIFICATES_EXAMPLE,
                ));
            };
            if before == "-" && after == "-" {
                return Err(usage(
                    "only one certificate can arrive on stdin",
                    "pass the other certificate as its C:<oid> or its saved file",
                ));
            }
            let capability = ctx.capability(
                args,
                if certify {
                    &["read", "produce"]
                } else {
                    &["read"]
                },
            )?;
            // Admission precedes fetching retained bytes or reading a file.
            let mut book = ctx.books.open_admitted(args, |book| {
                prepare_certificate_history(
                    book,
                    &capability,
                    if certify {
                        &[fa_policy::Op::Produce]
                    } else {
                        &[]
                    },
                    None,
                )
            })?;
            let decode = fa::ReportCertificate::decode;
            let before = notary::certificate_input(
                &book,
                &ctx.files,
                "--before-certificate",
                before,
                who,
                &capability,
                decode,
            )?;
            let after = notary::certificate_input(
                &book,
                &ctx.files,
                "--after-certificate",
                after,
                who,
                &capability,
                decode,
            )?;
            // Mismatched sources are the library's refusal; this checks only
            // the question the caller stated against the first source.
            if let fa::ReportSelection::Statement(selection)
            | fa::ReportSelection::FunctionalStatement(selection) = &before.selection
            {
                statement_question_matches(args, selection)?;
            }
            if args.switch("--functional")
                && !matches!(
                    before.selection,
                    fa::ReportSelection::FunctionalStatement(_)
                )
            {
                return Err(fa_journal::Refusal::new(
                    fa::certificate::code::CERTIFICATE_INVALID,
                    exit::VERIFICATION,
                    "--functional requires two functional statement source certificates",
                    "plan §8.3 / §12.5 (a comparison preserves its sources' accounting basis)",
                    "pass two retained functional statement certificates, or omit --functional to compare two native statement certificates",
                ).into());
            }
            // Functional sources also need immutable Entry creation history
            // when their prefix is HEAD after reopening a checkpointed book.
            for source in [&before, &after] {
                if source.selection.uses_functional_valuations() {
                    let bytes = source.canonical_bytes().map_err(|error| {
                        Fail::Internal(format!("functional comparison source: {error}"))
                    })?;
                    book.replay_report_artifact_for_with_history(
                        who,
                        &capability,
                        &bytes,
                        Some(&source.digest),
                        fa::ReportArtifactExpectation::AsSupplied,
                    )??;
                }
            }
            // Both sources replay: load the earlier retained prefix.
            book.prepare_report_history(
                who,
                &capability,
                Some(before.known_at.min(after.known_at)),
            )??;
            if certify {
                let certified =
                    book.compare_statement_certificates(who, &capability, &before, &after)??;
                return emit_certified_statement_diff(
                    &ctx.out,
                    &ctx.files,
                    args,
                    &mut book,
                    &capability,
                    &certified,
                );
            }
            let diff = book.diff_statement_certificates(who, &capability, &before, &after)??;
            render_statement_diff(&ctx.out, &book, &diff, None)
        }
        "trace" => {
            if args.flag("--before-certificate").is_some()
                || args.flag("--after-certificate").is_some()
            {
                return Err(usage(
                    "a statement trace starts from one saved comparison: --from-diff, not --before-certificate or --after-certificate",
                    "fa statement diff --before-certificate C:<oid> --after-certificate C:<oid> --certify --json, then fa statement trace --from-diff <its C:oid> --certify --json",
                ));
            }
            let Some(comparison) = args.flag("--from-diff") else {
                return Err(usage(
                    "a statement trace from certificates needs --from-diff",
                    STATEMENT_CERTIFICATES_EXAMPLE,
                ));
            };
            if !certify {
                return Err(usage(
                    "statement trace --from-diff certifies every intermediate publication of the saved comparison; add --certify",
                    "fa statement trace --from-diff C:<oid> --certify --json",
                ));
            }
            let capability = ctx.capability(args, &["read", "produce"])?;
            let mut book = ctx.books.open_admitted(args, |book| {
                prepare_certificate_history(book, &capability, &[fa_policy::Op::Produce], None)
            })?;
            let limit = max_publications(args)?;
            let comparison = notary::certificate_input(
                &book,
                &ctx.files,
                "--from-diff",
                comparison,
                who,
                &capability,
                fa::StatementDiffCertificate::decode,
            )?;
            if let Ok(request) = comparison.request() {
                statement_question_matches(args, &request.selection)?;
            }
            // The trace replays every publication from the earlier source on.
            let (before, after) = comparison.sources();
            book.prepare_report_history(
                who,
                &capability,
                Some(before.known_at.min(after.known_at)),
            )??;
            let certified =
                book.certify_statement_trace_from_diff(who, &capability, &comparison, limit)??;
            emit_certified_statement_trace(
                &ctx.out,
                &ctx.files,
                args,
                &mut book,
                &capability,
                &certified,
            )
        }
        other => Err(usage(
            format!(
                "certificate inputs select statement diff or statement trace, not statement {other}"
            ),
            STATEMENT_CERTIFICATES_EXAMPLE,
        )),
    }
}

fn statement_columns_json(statement: &Statement) -> Vec<Json> {
    statement
        .columns
        .iter()
        .map(|column| {
            let mode = if column.effective_from.is_some() {
                "activity"
            } else {
                "stock"
            };
            obj(vec![
                ("label", s(&column.label)),
                ("periods", Json::Arr(column.periods.iter().map(s).collect())),
                ("mode", s(mode)),
                (
                    "effective_from",
                    column
                        .effective_from
                        .map_or(Json::Null, |day| s(day.render())),
                ),
                ("effective_through", s(column.effective_through.render())),
            ])
        })
        .collect()
}

fn statement_line_changes_json(
    changes: &[fa::StatementLineChange],
    units: &fa_money::UnitRegistry,
) -> Result<Vec<Json>, Fail> {
    changes
        .iter()
        .map(|line| {
            let unit = fa_money::UnitId(line.unit_id);
            let code = registered_unit_code(unit, units)?;
            let fmt_vec = |vals: &[i128]| -> Result<Json, Fail> {
                Ok(Json::Arr(
                    vals.iter()
                        .map(|m| Ok(s(render_amount(Amount::new(unit, *m), units)?)))
                        .collect::<Result<Vec<_>, Fail>>()?,
                ))
            };
            Ok(obj(vec![
                ("code", s(&line.code)),
                ("label", s(&line.label)),
                ("unit", s(code)),
                ("before", fmt_vec(&line.before)?),
                ("after", fmt_vec(&line.after)?),
                ("delta", fmt_vec(&line.delta)?),
            ]))
        })
        .collect()
}

fn statement_mapping_json(mapping: &fa::AccountMapping) -> Result<Json, Fail> {
    let account_type = AccountType(mapping.account.account_type)
        .name()
        .ok_or_else(|| {
            Fail::Internal(format!(
                "statement mapping {} has an unregistered account type",
                mapping.account.code
            ))
        })?;
    Ok(obj(vec![
        ("account_vid", s(format!("{:032x}", mapping.account.id))),
        ("account", s(&mapping.account.code)),
        ("name", s(&mapping.account.name)),
        ("type", s(account_type)),
        ("line", s(&mapping.line_code)),
    ]))
}

fn statement_mapping_changes_json(
    changes: &[fa::StatementMappingChange],
) -> Result<Vec<Json>, Fail> {
    changes
        .iter()
        .map(|c| {
            Ok(obj(vec![
                ("account_vid", s(format!("{:032x}", c.account_id))),
                (
                    "before",
                    match &c.before {
                        Some(m) => statement_mapping_json(m)?,
                        None => Json::Null,
                    },
                ),
                (
                    "after",
                    match &c.after {
                        Some(m) => statement_mapping_json(m)?,
                        None => Json::Null,
                    },
                ),
            ]))
        })
        .collect()
}

pub(crate) fn render_statement_diff(
    out: &Out,
    book: &Book,
    diff: &fa::StatementDiff,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let units = &book.context().units;
    let before = diff.before();
    let after = diff.after();
    let periods: Vec<String> = after
        .columns
        .iter()
        .flat_map(|column| column.periods.iter().cloned())
        .collect();
    out.known_at(CommitSeq(after.known_at));
    out.effective(periods_selector(&periods));
    let columns = statement_columns_json(after);
    let lines = statement_line_changes_json(diff.lines(), units)?;
    let mapping_changes = statement_mapping_changes_json(diff.mapping_changes())?;
    let mut fields = vec![
        ("name", s(&after.definition_name)),
        (
            "definition_version",
            Json::Int(i128::from(after.definition_version)),
        ),
        ("definition_digest", s(hex(&after.definition_digest))),
        ("before_known_at", Json::Int(i128::from(before.known_at))),
        ("after_known_at", Json::Int(i128::from(after.known_at))),
        ("amounts_changed", Json::Bool(diff.amounts_changed())),
        ("unchanged", Json::Bool(diff.is_unchanged())),
        ("columns", Json::Arr(columns)),
        ("lines", Json::Arr(lines)),
        ("mapping_changes", Json::Arr(mapping_changes)),
    ];
    let mut human = format!(
        "{} diff · {} -> {} · unchanged={}",
        after.definition_name,
        before.known_at,
        after.known_at,
        diff.is_unchanged()
    );
    // The event declares all three fields (nullable), so a native diff
    // carries them too, as the statement event does.
    if let Some(base_unit) = diff.functional_unit() {
        let code = registered_unit_code(base_unit, units)?;
        fields.extend([
            ("functional", Json::Bool(true)),
            ("base_unit", s(&code)),
            ("valuation_basis", s("retained-base-amounts")),
        ]);
        human.push_str(&format!(" · functional {code} · retained base amounts"));
    } else {
        fields.extend([
            ("functional", Json::Bool(false)),
            ("base_unit", Json::Null),
            ("valuation_basis", s("native-amounts")),
        ]);
    }
    out.event_with_certificate("statement_diff", fields, &human, certificate);
    Ok(())
}

pub(crate) fn render_statement_trace(
    out: &Out,
    book: &Book,
    trace: &fa::StatementTrace,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let units = &book.context().units;
    let summary = trace.summary();
    let before = summary.before();
    let after = summary.after();
    let periods: Vec<String> = after
        .columns
        .iter()
        .flat_map(|column| column.periods.iter().cloned())
        .collect();
    out.known_at(CommitSeq(after.known_at));
    out.effective(periods_selector(&periods));
    let columns = statement_columns_json(after);
    let lines = statement_line_changes_json(summary.lines(), units)?;
    let mapping_changes = statement_mapping_changes_json(summary.mapping_changes())?;
    let publications = trace
        .publications()
        .iter()
        .map(|pub_step| {
            let entries: Vec<Json> = pub_step
                .entries
                .iter()
                .map(|link| {
                    let event_name = match link.event {
                        StatementEntryEvent::Recorded => "recorded",
                        StatementEntryEvent::BecameVisible => "became_visible",
                    };
                    obj(vec![
                        ("event", s(event_name)),
                        ("vid", s(format!("{:032x}", link.entry_ref.vid.0))),
                        ("entry_digest", s(hex(&link.entry_ref.entry_digest))),
                        ("class", s(link.class.name().unwrap_or("?"))),
                        ("recorded_at", Json::Int(i128::from(link.recorded_at.0))),
                        (
                            "posting_date",
                            link.posting_date.map_or(Json::Null, |d| s(d.render())),
                        ),
                        ("principal", s(format!("{:032x}", link.principal.0))),
                        (
                            "references",
                            Json::Arr(
                                link.references
                                    .iter()
                                    .map(|r| s(format!("{:032x}", r.vid.0)))
                                    .collect(),
                            ),
                        ),
                        (
                            "migration_run",
                            link.migration_run
                                .map_or(Json::Null, |v| s(format!("{:032x}", v.0))),
                        ),
                    ])
                })
                .collect();
            Ok(obj(vec![
                ("recorded_at", Json::Int(i128::from(pub_step.recorded_at.0))),
                ("unchanged", Json::Bool(pub_step.is_unchanged())),
                ("entries", Json::Arr(entries)),
                (
                    "changes",
                    Json::Arr(statement_line_changes_json(&pub_step.changes, units)?),
                ),
                (
                    "mapping_changes",
                    Json::Arr(statement_mapping_changes_json(&pub_step.mapping_changes)?),
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    out.event_with_certificate(
        "statement_trace",
        vec![
            ("name", s(&after.definition_name)),
            (
                "definition_version",
                Json::Int(i128::from(after.definition_version)),
            ),
            ("definition_digest", s(hex(&after.definition_digest))),
            ("before_known_at", Json::Int(i128::from(before.known_at))),
            ("after_known_at", Json::Int(i128::from(after.known_at))),
            ("had_changes", Json::Bool(trace.had_changes())),
            (
                "publication_count",
                Json::Int(trace.publications().len() as i128),
            ),
            ("columns", Json::Arr(columns)),
            ("lines", Json::Arr(lines)),
            ("mapping_changes", Json::Arr(mapping_changes)),
            ("publications", Json::Arr(publications)),
        ],
        &format!(
            "{} trace · {} -> {} · {} publication(s) · had_changes={}",
            after.definition_name,
            before.known_at,
            after.known_at,
            trace.publications().len(),
            trace.had_changes()
        ),
        certificate,
    );
    Ok(())
}

pub(crate) type StatementPresentation = (Vec<(&'static str, Json)>, String);

pub(crate) fn statement_presentation(
    statement: &Statement,
    units: &fa_money::UnitRegistry,
) -> Result<StatementPresentation, Fail> {
    statement_presentation_basis(statement, units, false)
}

fn functional_statement_unit(
    statement: &Statement,
    units: &fa_money::UnitRegistry,
) -> Result<String, Fail> {
    let unit = statement
        .lines
        .first()
        .map(|line| line.unit_id)
        .ok_or_else(|| Fail::Internal("a functional statement has no unit".into()))?;
    if statement.lines.iter().any(|line| line.unit_id != unit) {
        return Err(Fail::Internal(
            "a functional statement contains more than one unit".into(),
        ));
    }
    registered_unit_code(fa_money::UnitId(unit), units)
}

pub(crate) fn statement_presentation_basis(
    statement: &Statement,
    units: &fa_money::UnitRegistry,
    functional: bool,
) -> Result<StatementPresentation, Fail> {
    if statement.columns.is_empty() {
        return Err(Fail::Internal("a statement has no columns".into()));
    }
    let mut human = format!(
        "{} · definition version {} · known at {}\n",
        statement.definition_name, statement.definition_version, statement.known_at,
    );
    let columns = statement
        .columns
        .iter()
        .map(|column| {
            let mode = if column.effective_from.is_some() {
                "activity"
            } else {
                "stock"
            };
            human.push_str(&format!(
                "{}: {} · {mode}{} through {}\n",
                column.label,
                column.periods.join(", "),
                column
                    .effective_from
                    .map_or(String::new(), |day| format!(" from {}", day.render())),
                column.effective_through.render(),
            ));
            obj(vec![
                ("label", s(&column.label)),
                ("periods", Json::Arr(column.periods.iter().map(s).collect())),
                ("mode", s(mode)),
                (
                    "effective_from",
                    column
                        .effective_from
                        .map_or(Json::Null, |day| s(day.render())),
                ),
                ("effective_through", s(column.effective_through.render())),
            ])
        })
        .collect();
    human.push_str(&format!("{:<34}", "line"));
    for column in &statement.columns {
        human.push_str(&format!(" {:>24}", column.label));
    }
    human.push('\n');
    let mut lines = Vec::with_capacity(statement.lines.len());
    for line in &statement.lines {
        if line.amounts.len() != statement.columns.len() {
            return Err(Fail::Internal(format!(
                "statement line {} has {} amounts for {} columns",
                line.code,
                line.amounts.len(),
                statement.columns.len(),
            )));
        }
        let unit = fa_money::UnitId(line.unit_id);
        let code = registered_unit_code(unit, units)?;
        let amounts = line
            .amounts
            .iter()
            .map(|mantissa| render_amount(Amount::new(unit, *mantissa), units))
            .collect::<Result<Vec<_>, Fail>>()?;
        human.push_str(&format!("{:<34}", line.label));
        for amount in &amounts {
            human.push_str(&format!(" {amount:>24}"));
        }
        human.push('\n');
        lines.push(obj(vec![
            ("code", s(&line.code)),
            ("label", s(&line.label)),
            ("unit", s(code)),
            ("amounts", Json::Arr(amounts.iter().map(s).collect())),
        ]));
    }
    let mappings = statement
        .mappings
        .iter()
        .map(|mapping| {
            let account_type = AccountType(mapping.account.account_type)
                .name()
                .ok_or_else(|| {
                    Fail::Internal(format!(
                        "statement mapping {} has an unregistered account type",
                        mapping.account.code
                    ))
                })?;
            Ok(obj(vec![
                ("account_vid", s(format!("{:032x}", mapping.account.id))),
                ("account", s(&mapping.account.code)),
                ("name", s(&mapping.account.name)),
                ("type", s(account_type)),
                ("line", s(&mapping.line_code)),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let mut fields = vec![
        ("name", s(&statement.definition_name)),
        (
            "definition_version",
            Json::Int(i128::from(statement.definition_version)),
        ),
        ("definition_digest", s(hex(&statement.definition_digest))),
        ("known_at", Json::Int(i128::from(statement.known_at))),
        ("columns", Json::Arr(columns)),
        ("lines", Json::Arr(lines)),
        ("mappings", Json::Arr(mappings)),
        (
            "scope",
            s(if functional {
                "single-book-functional-currency"
            } else {
                "single-book-native-units"
            }),
        ),
    ];
    if functional {
        let unit = functional_statement_unit(statement, units)?;
        fields.extend([
            ("functional", Json::Bool(true)),
            ("base_unit", s(&unit)),
            ("valuation_basis", s("retained-base-amounts")),
        ]);
        human.push_str(&format!("Scope: one book, functional currency {unit}; retained base amounts verified under their original laws.\n"));
    } else {
        fields.extend([
            ("functional", Json::Bool(false)),
            ("base_unit", Json::Null),
            ("valuation_basis", s("native-amounts")),
        ]);
        human.push_str(
            "Scope: one book, exact native units; no FX conversion or presentation rounding.\n",
        );
    }
    Ok((fields, human))
}

const PRESENT_EXAMPLE: &str = "fa statement balance-sheet --for FY2026-P03 --present-in thousands [--rounding HalfEven] --json";

/// A statement presented in whole units, thousands or millions (plan §12.1
/// presentation rounding): how many decimal places of the unit to drop
/// beyond its scale, and the registered rounding law.
#[derive(Clone, Copy, Debug)]
struct PresentationRequest {
    name: &'static str,
    extra_digits: u8,
    law: fa_money::RoundingLaw,
}

/// `--present-in units|thousands|millions [--rounding <law>]`, checked
/// before the book is read. `--rounding` alone is refused.
fn presentation_request(args: &Args) -> Result<Option<PresentationRequest>, Fail> {
    let law = match args.flag("--rounding") {
        None => None,
        Some(name) => Some(fa_money::RoundingLaw::from_name(name).ok_or_else(|| {
            usage(
                format!("--rounding `{name}` is not a registered rounding law"),
                "--rounding HalfUp|HalfDown|HalfEven|HalfAwayFromZero|HalfTowardZero|Ceiling|Floor|TowardZero|AwayFromZero (registries/rounding_laws.toml)",
            )
        })?),
    };
    let Some(present_in) = args.flag("--present-in") else {
        return match law {
            Some(_) => Err(usage(
                "--rounding applies only with --present-in",
                PRESENT_EXAMPLE,
            )),
            None => Ok(None),
        };
    };
    let (name, extra_digits) = match present_in {
        "units" => ("units", 0),
        "thousands" => ("thousands", 3),
        "millions" => ("millions", 6),
        other => {
            return Err(usage(
                format!("--present-in `{other}` is not a presentation scale"),
                "--present-in units|thousands|millions",
            ));
        }
    };
    Ok(Some(PresentationRequest {
        name,
        extra_digits,
        law: law.unwrap_or(fa_money::RoundingLaw::HalfEven),
    }))
}

/// The statement presented per unit under the request: every line divided
/// by 10^(unit scale + extra digits) under the rounding law, with an explicit
/// residual line before any total whose rounded operands do not sum to its
/// rounded value (fa_statements::custom::apply_presentation_rounding), so the
/// presented statement foots. The exact statement is unchanged; its
/// certificate (when retained) binds the exact amounts.
fn present_statement(
    statement: &Statement,
    units: &fa_money::UnitRegistry,
    request: PresentationRequest,
) -> Result<StatementPresentation, Fail> {
    let definition = fa::CustomStatementDefinition::from_builtin(
        &StatementDefinition::embedded(&statement.definition_name)
            .map_err(|e| Fail::Internal(format!("statement definition: {e}")))?,
    );
    let mut unit_ids: Vec<u32> = statement.lines.iter().map(|l| l.unit_id).collect();
    unit_ids.sort_unstable();
    unit_ids.dedup();
    let mut blocks = Vec::new();
    let mut human = format!(
        "{} presented in {} ({:?})",
        statement.definition_name, request.name, request.law
    );
    for unit_id in unit_ids {
        let unit = units.get(fa_money::UnitId(unit_id)).ok_or_else(|| {
            amount_corruption(fa_money::AmountError::UnknownUnit(unit_id.to_string()))
        })?;
        let digits = unit
            .scale
            .checked_add(request.extra_digits)
            .ok_or_else(|| {
                usage(
                    format!("{} cannot be presented in {}", unit.code, request.name),
                    "--present-in units",
                )
            })?;
        let mut single = statement.clone();
        single.lines.retain(|l| l.unit_id == unit_id);
        let presented = fa::apply_presentation_rounding(
            &single,
            &definition,
            &fa::PresentationRoundingSpec {
                rounding_law: request.law,
                scale_reduction_digits: digits,
                residual_line_code: "presentation_rounding".into(),
                residual_line_label: "Presentation rounding".into(),
            },
        )
        .map_err(|e| usage(format!("presentation: {e}"), PRESENT_EXAMPLE))?;
        let digest = presented
            .digest()
            .map_err(|e| Fail::Internal(format!("presented statement digest: {e}")))?;
        let mut lines = Vec::with_capacity(presented.lines.len());
        for line in &presented.lines {
            let errors = line
                .rounding_errors
                .iter()
                .map(|e| render_amount(Amount::new(fa_money::UnitId(unit_id), *e), units).map(s))
                .collect::<Result<Vec<_>, _>>()?;
            human.push_str(&format!(
                "\n  {:<52} {}",
                line.label,
                line.presented_amounts
                    .iter()
                    .map(i128::to_string)
                    .collect::<Vec<_>>()
                    .join("  ")
            ));
            lines.push(obj(vec![
                ("code", s(&line.code)),
                ("label", s(&line.label)),
                (
                    "presented",
                    Json::Arr(
                        line.presented_amounts
                            .iter()
                            .map(|a| Json::Int(*a))
                            .collect(),
                    ),
                ),
                ("rounding_error", Json::Arr(errors)),
                ("residual", Json::Bool(line.is_residual_line)),
            ]));
        }
        blocks.push(obj(vec![
            ("unit", s(&unit.code)),
            ("divisor", Json::Int(presented.divisor)),
            ("digest", s(hex(&digest.0))),
            ("lines", Json::Arr(lines)),
        ]));
    }
    let fields = vec![
        ("definition", s(&statement.definition_name)),
        ("present_in", s(request.name)),
        ("rounding_law", s(format!("{:?}", request.law))),
        (
            "columns",
            Json::Arr(statement.columns.iter().map(|c| s(&c.label)).collect()),
        ),
        ("units", Json::Arr(blocks)),
    ];
    Ok((fields, human))
}

fn emit_statement(
    out: &Out,
    statement: &Statement,
    (fields, human): StatementPresentation,
    certificate: Option<&str>,
) {
    out.known_at(CommitSeq(statement.known_at));
    let periods: Vec<String> = statement
        .columns
        .iter()
        .flat_map(|column| column.periods.iter().cloned())
        .collect();
    out.effective(periods_selector(&periods));
    out.event_with_certificate("statement", fields, &human, certificate);
}

/// Original and verified replay share the exact same checked presentation.
pub(crate) fn render_statement(
    out: &Out,
    book: &Book,
    statement: &Statement,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let rendered = statement_presentation(statement, &book.context().units)?;
    emit_statement(out, statement, rendered, certificate);
    Ok(())
}

/// The functional replay retains its valuation basis through the typed
/// output rather than rendering committed base amounts as native currency.
pub(crate) fn render_functional_statement(
    out: &Out,
    book: &Book,
    statement: &Statement,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let rendered = statement_presentation_basis(statement, &book.context().units, true)?;
    emit_statement(out, statement, rendered, certificate);
    Ok(())
}

/// Check presentation inputs before retaining a certificate or emitting any
/// report. Even a zero total must name a registered unit.
fn validate_trial_balance_units(
    tb: &fa_registers::TrialBalance,
    units: &fa_money::UnitRegistry,
) -> Result<(), Fail> {
    for unit in tb
        .rows
        .iter()
        .map(|row| row.unit_id)
        .chain(tb.unit_totals.keys().copied())
        .chain(tb.pending_unit_totals.keys().copied())
    {
        registered_unit_code(fa_money::UnitId(unit), units)?;
    }
    Ok(())
}

/// A report's `--render md|html|svg|pdf|pdfa [--out <new-file>]` request
/// (fa-cet), checked before the book is read.
struct RenderRequest<'a> {
    format: fa::StatementRenderFormat,
    out: Option<&'a str>,
}

fn render_request<'a>(args: &'a Args, example: &str) -> Result<Option<RenderRequest<'a>>, Fail> {
    if args.flag_all("--render").len() > 1 || args.flag_all("--out").len() > 1 {
        return Err(usage(
            "--render and --out may each be supplied only once",
            example,
        ));
    }
    let Some(raw) = args.flag("--render") else {
        if args.flag("--out").is_some() {
            return Err(usage("--out names the file --render writes", example));
        }
        return Ok(None);
    };
    let format =
        fa::StatementRenderFormat::parse(raw).map_err(|e| usage(e.to_string(), example))?;
    let out = args.flag("--out");
    if out.is_some_and(|path| path.is_empty() || path == "-") {
        return Err(usage(
            "--out names a new file; - is not an output file",
            example,
        ));
    }
    if out.is_none() && format != fa::StatementRenderFormat::Markdown {
        return Err(usage(
            format!(
                "--render {} writes a document file: name a new one with --out",
                format.as_str()
            ),
            example,
        ));
    }
    Ok(Some(RenderRequest { format, out }))
}

/// The registered display metadata (code, scale) of each unit `ids` names.
fn unit_format_specs(
    units: &fa_money::UnitRegistry,
    ids: impl IntoIterator<Item = u32>,
) -> Result<Vec<fa::UnitFormatSpec>, Fail> {
    let mut specs: Vec<fa::UnitFormatSpec> = Vec::new();
    for id in ids {
        if specs.iter().any(|spec| spec.unit_id == id) {
            continue;
        }
        let code = registered_unit_code(fa_money::UnitId(id), units)?;
        let scale = units
            .get(fa_money::UnitId(id))
            .map(|unit| unit.scale)
            .ok_or_else(|| Fail::Internal(format!("unit {id} has no registered scale")))?;
        specs.push(fa::UnitFormatSpec {
            unit_id: id,
            code,
            scale,
        });
    }
    Ok(specs)
}

/// A report rendered as its `--render` request asks (fa-cet), before
/// anything is written: HTML, SVG and PDF are dated by the latest
/// corroborated TimeEvidence tick known at the report's own frontier, never
/// the wall clock, so one report renders to the same bytes whenever it is
/// rendered; with no such tick only Markdown, which carries no date,
/// renders. A PDF/A is checked by the PDF/A-2b validator.
struct Rendering {
    bytes: Vec<u8>,
    tick: Option<fa_journal::Tick>,
    pdfa_valid: bool,
    ir_digest: [u8; 32],
    markdown: String,
}

fn render_ir(
    book: &Book,
    request: &RenderRequest<'_>,
    ir: &fa::StatementMarkdownIr,
) -> Result<Rendering, Fail> {
    use fa::StatementRenderFormat as Format;
    type Renderer = fn(&fa::StatementMarkdownIr, u64) -> Result<Vec<u8>, fa::StatementError>;
    let dated = |render: Renderer| -> Result<(Vec<u8>, Option<fa_journal::Tick>), Fail> {
        let tick = book
            .corroborated_tick_at(CommitSeq(ir.known_at))?
            .ok_or_else(|| {
                Fail::Environment(format!(
                    "--render {} dates the document by the book's latest corroborated clock tick known at {}, and none is retained; render Markdown (--render md), which carries no date, or let fad's timed work journal TimeEvidence ticks first",
                    request.format.as_str(),
                    ir.known_at
                ))
            })?;
        let bytes = render(ir, tick.observed_utc_ns / 1_000_000_000)
            .map_err(|e| Fail::Internal(format!("rendering {}: {e}", request.format.as_str())))?;
        Ok((bytes, Some(tick)))
    };
    let (bytes, tick) = match request.format {
        Format::Markdown => (ir.markdown.as_bytes().to_vec(), None),
        Format::Html => dated(fa::render_html)?,
        Format::Svg => dated(fa::render_svg)?,
        Format::Pdf => dated(fa::render_pdf)?,
        Format::Pdfa2b => dated(fa::render_pdfa)?,
    };
    let pdfa_valid = request.format == Format::Pdfa2b;
    if pdfa_valid {
        fa::validate_pdfa2b(&bytes).map_err(|e| Fail::Verification {
            message: format!("the rendered PDF/A-2b fails its validator: {e}"),
            detail: Json::Null,
            cite: Some("ISO 19005-2 (PDF/A-2b), fa-cet".into()),
            fix: Some("render --render pdf instead, and report this as a defect".into()),
        })?;
    }
    let ir_digest = ir
        .digest()
        .map_err(|e| Fail::Internal(format!("rendering IR digest: {e}")))?
        .0;
    Ok(Rendering {
        bytes,
        tick,
        pdfa_valid,
        ir_digest,
        markdown: ir.markdown.clone(),
    })
}

/// Write a rendering to its new `--out` file, before the report is emitted
/// or its certificate retained, so a path that cannot be written refuses
/// the whole command.
fn write_rendering(
    files: &Files,
    request: &RenderRequest<'_>,
    rendering: &Rendering,
) -> Result<(), Fail> {
    match request.out {
        Some(path) => write_new_output_file(files, path, &rendering.bytes, "rendering", "--out"),
        None => Ok(()),
    }
}

/// Emit `rendered` after the report; without `--out` (Markdown only) the
/// document travels inline.
fn emit_rendering(out: &Out, request: &RenderRequest<'_>, rendering: Rendering) {
    let digest = fa_model::domain_digest(b"fa:rendering-file:v1", &[&rendering.bytes]);
    let inline = request.out.is_none().then_some(rendering.markdown);
    let human = match (&inline, request.out) {
        (Some(markdown), _) => markdown.trim_end().to_string(),
        (None, path) => format!(
            "rendered {} ({} bytes) to {}",
            request.format.as_str(),
            rendering.bytes.len(),
            path.unwrap_or_default()
        ),
    };
    let tick = rendering.tick.as_ref();
    out.event(
        "rendered",
        vec![
            ("format", s(request.format.as_str())),
            ("ir_digest", s(hex(&rendering.ir_digest))),
            ("digest", s(hex(&digest))),
            ("bytes", Json::Int(rendering.bytes.len() as i128)),
            ("out", request.out.map_or(Json::Null, s)),
            (
                "created",
                tick.map_or(Json::Null, |tick| {
                    s(fa::format_utc_epoch_iso8601(
                        tick.observed_utc_ns / 1_000_000_000,
                    ))
                }),
            ),
            (
                "tick",
                tick.map_or(Json::Null, |tick| s(format!("{:032x}", tick.entry.0))),
            ),
            (
                "pdfa_valid",
                if rendering.pdfa_valid {
                    Json::Bool(true)
                } else {
                    Json::Null
                },
            ),
            ("markdown", inline.map_or(Json::Null, s)),
        ],
        &human,
    );
}

/// The same renderer serves both an original report and its verified replay.
/// Its coordinate comes from the certified selector, never the present head.
pub(crate) fn render_trial_balance(
    out: &Out,
    book: &Book,
    tb: &fa_registers::TrialBalance,
    selection: &TrialBalanceSelection,
    certificate: Option<&str>,
    served: Option<&fa_registers::Served>,
) -> Result<(), Fail> {
    render_trial_balance_with_units(
        out,
        &book.context().units,
        tb,
        selection,
        certificate,
        served,
    )
}

/// How a head read was answered (`tb_served`, plan §17): maintained cells
/// at their cursors plus the exact tail, or the literal journal fold and why.
fn served_json(served: &fa_registers::Served) -> Json {
    match served {
        fa_registers::Served::Maintained(periods) => obj(vec![
            ("mode", s("maintained")),
            (
                "tail_length",
                Json::Int(periods.iter().map(|(_, _, tail)| *tail as i128).sum()),
            ),
            ("reason", Json::Null),
            (
                "periods",
                Json::Arr(
                    periods
                        .iter()
                        .map(|(period, served_at, tail)| {
                            obj(vec![
                                ("period", s(period)),
                                ("served_at", Json::Int(i128::from(served_at.0))),
                                ("tail_entries", Json::Int(*tail as i128)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]),
        fa_registers::Served::Literal(reason) => obj(vec![
            ("mode", s("literal")),
            ("tail_length", Json::Null),
            ("reason", s(reason)),
            ("periods", Json::Arr(Vec::new())),
        ]),
    }
}

fn render_trial_balance_with_units(
    out: &Out,
    units: &fa_money::UnitRegistry,
    tb: &fa_registers::TrialBalance,
    selection: &TrialBalanceSelection,
    certificate: Option<&str>,
    served: Option<&fa_registers::Served>,
) -> Result<(), Fail> {
    render_trial_balance_filtered(out, units, tb, selection, certificate, served, None)
}

/// The dimension filter a `trial_balance` names (`tb_dimension`, fa-ficc).
pub(crate) struct TbDimension<'a> {
    pub dimension: &'a str,
    pub value: &'a str,
    /// The value and its descendants, whose tagged legs the report folds.
    pub values: &'a [String],
}

/// A trial balance over only the legs tagged with `dimension`'s values
/// (`fa tb --dimension`), with its certificate's digest when certified.
pub(crate) fn render_tagged_trial_balance(
    out: &Out,
    book: &Book,
    tb: &fa_registers::TrialBalance,
    selection: &TrialBalanceSelection,
    dimension: &TbDimension<'_>,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    render_trial_balance_filtered(
        out,
        &book.context().units,
        tb,
        selection,
        certificate,
        None,
        Some(dimension),
    )
}

fn render_trial_balance_filtered(
    out: &Out,
    units: &fa_money::UnitRegistry,
    tb: &fa_registers::TrialBalance,
    selection: &TrialBalanceSelection,
    certificate: Option<&str>,
    served: Option<&fa_registers::Served>,
    dimension: Option<&TbDimension<'_>>,
) -> Result<(), Fail> {
    validate_trial_balance_units(tb, units)?;
    let periods: &[String] = match selection {
        TrialBalanceSelection::Periods(periods) | TrialBalanceSelection::Activity(periods) => {
            periods
        }
        TrialBalanceSelection::AsOf(_) => &[],
    };
    out.known_at(tb.known_at);
    out.effective(match selection {
        TrialBalanceSelection::AsOf(date) => format!("as-of:{date}"),
        _ => periods_selector(periods),
    });
    let render = |unit: u32, m: i128| render_amount(Amount::new(fa_money::UnitId(unit), m), units);
    let rows: Vec<Json> = tb
        .rows
        .iter()
        .map(|r| {
            Ok(obj(vec![
                ("code", s(&r.code)),
                ("name", s(&r.name)),
                ("type", s(r.account_type.name().unwrap_or("?"))),
                ("debits", s(render(r.unit_id, r.debits)?)),
                ("credits", s(render(r.unit_id, r.credits)?)),
                (
                    "net",
                    s(render(r.unit_id, tb_net(&r.code, r.debits, r.credits)?)?),
                ),
                ("debits_pending", s(render(r.unit_id, r.debits_pending)?)),
                ("credits_pending", s(render(r.unit_id, r.credits_pending)?)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    let pending_totals: Vec<Json> = tb
        .pending_unit_totals
        .iter()
        .map(|(u, (d, c))| {
            Ok(obj(vec![
                (
                    "unit",
                    s(registered_unit_code(fa_money::UnitId(*u), units)?),
                ),
                ("debits_pending", s(render(*u, *d)?)),
                ("credits_pending", s(render(*u, *c)?)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    let totals: Vec<Json> = tb
        .unit_totals
        .iter()
        .map(|(u, (d, c))| {
            Ok(obj(vec![
                (
                    "unit",
                    s(registered_unit_code(fa_money::UnitId(*u), units)?),
                ),
                ("debits", s(render(*u, *d)?)),
                ("credits", s(render(*u, *c)?)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    if out.json {
        out.event_with_certificate(
            "trial_balance",
            vec![
                ("periods", Json::Arr(periods.iter().map(s).collect())),
                ("known_at", Json::Int(i128::from(tb.known_at.0))),
                (
                    "effective_through",
                    tb.effective_through.map_or(Json::Null, |d| s(d.render())),
                ),
                ("activity", Json::Bool(tb.activity)),
                ("mode", s(if tb.activity { "activity" } else { "stock" })),
                ("rows", Json::Arr(rows)),
                ("unit_totals", Json::Arr(totals)),
                ("pending_unit_totals", Json::Arr(pending_totals)),
                ("balanced", Json::Bool(tb.is_balanced())),
                ("served", served.map_or(Json::Null, served_json)),
                (
                    "dimension",
                    dimension.map_or(Json::Null, |dimension| {
                        obj(vec![
                            ("dimension", s(dimension.dimension)),
                            ("value", s(dimension.value)),
                            (
                                "values",
                                Json::Arr(dimension.values.iter().map(s).collect()),
                            ),
                        ])
                    }),
                ),
            ],
            "",
            certificate,
        );
    } else {
        if let Some(day) = tb.effective_through {
            out.line(format!(
                "trial balance through {day} · known at {}",
                tb.known_at.0
            ));
        } else {
            out.line(format!(
                "period activity · {} · known at {}",
                periods.join(", "),
                tb.known_at.0
            ));
        }
        if let Some(dimension) = dimension {
            out.line(format!(
                "only legs tagged {} {} ({}); the other legs of their entries are left out, so the totals need not balance",
                dimension.dimension,
                dimension.value,
                dimension.values.join(", ")
            ));
        }
        out.line(out.style().header(&format!(
            "{:<10} {:<28} {:>22} {:>22} {:>22} {:>22}",
            "code",
            "account",
            "posted debits",
            "posted credits",
            "pending debits",
            "pending credits"
        )));
        for r in &tb.rows {
            out.line(format!(
                "{:<10} {:<28} {:>22} {:>22} {:>22} {:>22}",
                r.code,
                r.name,
                render(r.unit_id, r.debits)?,
                render(r.unit_id, r.credits)?,
                render(r.unit_id, r.debits_pending)?,
                render(r.unit_id, r.credits_pending)?
            ));
        }
        let total_units: std::collections::BTreeSet<_> = tb
            .unit_totals
            .keys()
            .chain(tb.pending_unit_totals.keys())
            .copied()
            .collect();
        for u in total_units {
            let (d, c) = tb.unit_totals.get(&u).copied().unwrap_or_default();
            let (pd, pc) = tb.pending_unit_totals.get(&u).copied().unwrap_or_default();
            out.line(format!(
                "{:<39} {:>22} {:>22} {:>22} {:>22}",
                "total",
                render(u, d)?,
                render(u, c)?,
                render(u, pd)?,
                render(u, pc)?
            ));
        }
        out.line(format!("balanced: {}", tb.is_balanced()));
    }
    Ok(())
}

fn drift_json(drifts: &[fa_registers::Drift]) -> Vec<Json> {
    drifts
        .iter()
        .map(|d| {
            obj(vec![
                ("account", s(format!("{:032x}", d.key.account.0))),
                ("unit_id", Json::Int(i128::from(d.key.unit_id))),
                (
                    "stored",
                    d.stored.map_or(Json::Null, |(dd, cc, n)| {
                        obj(vec![
                            ("debits", Json::Int(dd)),
                            ("credits", Json::Int(cc)),
                            ("entry_count", Json::Int(i128::from(n))),
                        ])
                    }),
                ),
                (
                    "refolded",
                    obj(vec![
                        ("debits", Json::Int(d.refolded.0)),
                        ("credits", Json::Int(d.refolded.1)),
                        ("entry_count", Json::Int(i128::from(d.refolded.2))),
                    ]),
                ),
            ])
        })
        .collect()
}

/// The `availability_verified` fields (also the detail of a failed
/// verification): each limited account in its unit, and each drift row with
/// the account its stored cell claims.
fn availability_fields(
    v: &fa_registers::AvailabilityVerification,
    amount: &dyn Fn(&str, i128) -> Result<Json, Fail>,
) -> Result<Vec<(&'static str, Json)>, Fail> {
    let cell = |c: &fa_journal::LimitCell| {
        obj(vec![
            ("debits_posted", Json::Int(c.debits_posted)),
            ("credits_posted", Json::Int(c.credits_posted)),
            ("debits_pending", Json::Int(c.debits_pending)),
            ("credits_pending", Json::Int(c.credits_pending)),
            ("generation", Json::Int(i128::from(c.generation))),
        ])
    };
    let mut accounts = Vec::with_capacity(v.accounts.len());
    for a in &v.accounts {
        accounts.push(obj(vec![
            ("account", s(&a.code)),
            ("period", a.period.as_ref().map_or(Json::Null, s)),
            ("normal", s(side_name(a.normal))),
            (
                "lower_bound",
                a.limit
                    .lower
                    .map_or(Ok(Json::Null), |m| amount(&a.code, m))?,
            ),
            (
                "upper_bound",
                a.limit
                    .upper
                    .map_or(Ok(Json::Null), |m| amount(&a.code, m))?,
            ),
            ("net", amount(&a.code, a.net)?),
            ("pending_out", amount(&a.code, a.pending_out)?),
            ("pending_in", amount(&a.code, a.pending_in)?),
            ("generation", Json::Int(i128::from(a.cell.generation))),
        ]));
    }
    let drift: Vec<Json> = v
        .drift
        .iter()
        .map(|d| {
            obj(vec![
                ("account", s(&d.code)),
                ("period", d.period.as_ref().map_or(Json::Null, s)),
                (
                    "stored_period",
                    d.stored_period.as_ref().map_or(Json::Null, s),
                ),
                ("stored", d.stored.as_ref().map_or(Json::Null, cell)),
                ("refolded", cell(&d.refolded)),
                (
                    "stored_account",
                    d.stored_account
                        .map_or(Json::Null, |a| s(format!("{:032x}", a.0))),
                ),
                (
                    "stored_account_code",
                    d.stored_account_code.as_ref().map_or(Json::Null, s),
                ),
            ])
        })
        .collect();
    Ok(vec![
        ("known_at", Json::Int(i128::from(v.known_at.0))),
        ("accounts_checked", Json::Int(v.accounts_checked as i128)),
        ("cells_checked", Json::Int(v.cells_checked as i128)),
        ("accounts", Json::Arr(accounts)),
        ("drift", Json::Arr(drift)),
    ])
}

fn usage_fields(v: &fa_journal::UsageVerification) -> Vec<(&'static str, Json)> {
    vec![
        ("known_at", Json::Int(i128::from(v.known_at.0))),
        ("charges_checked", Json::Int(v.charges_checked as i128)),
        ("cells_checked", Json::Int(v.cells_checked as i128)),
        ("drift", Json::Arr(v.drift.iter().map(s).collect())),
    ]
}

fn verify_usage_at(
    book: &mut Book,
    capability: &Capability,
    known_at: Option<CommitSeq>,
) -> Result<fa_journal::UsageVerification, Fail> {
    let verified = match book.verify_usage(capability, known_at) {
        Ok(result) => result?,
        Err(BookError::Kernel(fa_journal::KernelError::Corrupt(problem))) => {
            return Err(Fail::Verification {
                message: format!("daily usage verification failed: {problem}"),
                detail: obj(vec![("problem", s(&problem))]),
                cite: Some("FA-INV-10.ceiling / FA-INV-04 (daily usage refolds from immutable admission history)".into()),
                fix: Some("retain this finding with fa verify usage --json and the same --book and --as-known-at; preserve the original native history".into()),
            });
        }
        Err(error) => return Err(error.into()),
    };
    if !verified.is_green() {
        return Err(Fail::Verification {
            message: format!("daily usage differs from its immutable admission history: {}", verified.drift.join("; ")),
            detail: obj(usage_fields(&verified)),
            cite: Some("FA-INV-10.ceiling / FA-INV-04 (daily usage is a verified projection)".into()),
            fix: Some("retain this finding with fa verify usage --json; preserve the original book history and do not reset a cell or replace a quota to bypass its spent capacity".into()),
        });
    }
    Ok(verified)
}

/// The targets `fa verify book` runs, cheapest first (plan §15.3 Proofs;
/// fa-waow). `verify close` is not one: it asks whether a fiscal year needs a
/// close, which is not a question about the book's integrity.
const BOOK_VERIFY_TARGETS: [&str; 11] = [
    "projections",
    "periods",
    "schedules",
    "accumulator",
    "open-items",
    "availability",
    "usage",
    "fx-conversion",
    "entities",
    "registers",
    "replay",
];

/// `fa verify book`: every book-level verify target in one call, entities
/// and registers over every period. Each target emits its own event; then
/// `book_verification` names each target's verdict. Any target's
/// verification failure is exit 8; otherwise the first other failure (a
/// refusal, an I/O error) is returned as itself, after the remaining
/// targets ran.
fn verify_book(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2
        || args.flag("--period").is_some()
        || args.flag("--fiscal-year").is_some()
    {
        return Err(usage(
            "verify book runs every target over the whole book and takes no positional argument or period filter",
            "fa verify book --book <dir> --json",
        ));
    }
    let periods: Vec<String> = {
        let principal = ctx.principal(args);
        let capability = ctx.capability(args, &["read", "verify"])?;
        let book = ctx.books.open_admitted(args, |book| {
            admit_registers(book, principal, &capability, "verifying the book")
        })?;
        book.periods()?.into_iter().map(|p| p.code).collect()
    };
    let mut targets = Vec::new();
    let mut human = Vec::new();
    let mut failed = Vec::new();
    let mut first_error = None;
    for target in BOOK_VERIFY_TARGETS {
        let by_period = matches!(target, "entities" | "registers");
        let (verdict, detail) = if by_period && periods.is_empty() {
            ("skipped", "the book has no periods".to_string())
        } else {
            let mut sub = args.clone();
            sub.positional = vec!["verify".to_string(), target.to_string()];
            if by_period {
                sub.flags.insert("--period".to_string(), periods.clone());
            }
            match verify_cmd(ctx, &sub) {
                Ok(()) => ("pass", String::new()),
                Err(fail @ Fail::Verification { .. }) => {
                    failed.push(target);
                    ("fail", crate::triage::describe(&fail))
                }
                Err(fail) => {
                    let detail = crate::triage::describe(&fail);
                    first_error.get_or_insert(fail);
                    ("error", detail)
                }
            }
        };
        human.push(if detail.is_empty() {
            format!("{target:<13} {verdict}")
        } else {
            format!("{target:<13} {verdict}: {detail}")
        });
        targets.push(obj(vec![
            ("target", s(target)),
            ("verdict", s(verdict)),
            ("detail", s(&detail)),
        ]));
    }
    let green = failed.is_empty() && first_error.is_none();
    ctx.out.event(
        "book_verification",
        vec![
            ("green", Json::Bool(green)),
            ("targets", Json::Arr(targets.clone())),
        ],
        &human.join("\n"),
    );
    if !failed.is_empty() {
        return Err(Fail::Verification {
            message: format!("book verification failed: {}", failed.join(", ")),
            detail: Json::Arr(targets),
            cite: Some(
                "plan §16: the journal is the truth; every derived structure refolds to it".into(),
            ),
            fix: Some(format!(
                "run each failing target alone for its finding: {}",
                failed
                    .iter()
                    .map(|t| format!("fa verify {t} --json"))
                    .collect::<Vec<_>>()
                    .join("; ")
            )),
        });
    }
    first_error.map_or(Ok(()), Err)
}

/// `fa verify fx-conversion [--as-known-at HEAD|<seq>|<RFC3339>]` (plan §6.4,
/// §15.3; FA-INV-01 `base`, `base-residual`, `realized-fx`): every FX-valued
/// entry recorded at the selected prefix, recomputed from the Rate documents
/// it cites under the law it names. Current whole-book read and verify are
/// admitted before the book is read; exit 8 on any drift.
fn verify_fx_conversion(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str =
        "fa verify fx-conversion --book <dir> [--as-known-at HEAD|<seq>|<RFC3339>] [--json]";
    if args.positional.len() > 2 {
        return Err(usage(
            "verify fx-conversion takes no extra positional arguments",
            EXAMPLE,
        ));
    }
    if args.flag("--period").is_some() || args.flag("--fiscal-year").is_some() {
        return Err(usage(
            "verify fx-conversion checks every valued entry at the selected prefix; it takes no period filter",
            EXAMPLE,
        ));
    }
    let principal = ctx.principal(args);
    let capability = ctx.capability(args, &["read", "verify"])?;
    let book = ctx.books.open_admitted(args, |book| {
        fa_policy::admit_read(&capability, principal, book.context().book_id)
            .and_then(|()| {
                fa_policy::require(
                    &capability,
                    fa_policy::Op::Verify,
                    "verifying FX conversions",
                )
            })
            .and_then(|()| fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None))
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
        book.read_scope(principal, &capability)??;
        Ok(())
    })?;
    let out = &ctx.out;
    let (known_at, _) = known_at_flag(args, &book, out)?;
    let v = book.verify_fx_conversions(known_at)?;
    out.known_at(v.known_at);
    let valued: u64 = v.checked.values().sum();
    let fields = vec![
        ("known_at", Json::Int(i128::from(v.known_at.0))),
        ("valued_entries", Json::Int(i128::from(valued))),
        (
            "by_law",
            Json::Obj(
                v.checked
                    .iter()
                    .map(|(law, n)| (law.clone(), Json::Int(i128::from(*n))))
                    .collect(),
            ),
        ),
        (
            "drift",
            Json::Arr(
                v.drift
                    .iter()
                    .map(|d| {
                        obj(vec![
                            ("entry", s(format!("{:032x}", d.entry.0))),
                            ("recorded_at", Json::Int(i128::from(d.recorded_at.0))),
                            ("law", s(&d.law)),
                            ("problem", s(&d.problem)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ];
    if v.is_green() {
        out.event(
            "fx_conversion_verified",
            fields,
            &format!(
                "{valued} FX-valued entr{} recompute from their Rate documents at sequence {}",
                if valued == 1 { "y" } else { "ies" },
                v.known_at.0
            ),
        );
        Ok(())
    } else {
        Err(Fail::Verification {
            message: format!(
                "{} of {valued} FX-valued entries do not recompute: {}",
                v.drift.len(),
                v.drift
                    .iter()
                    .map(|d| format!("{:032x} ({}): {}", d.entry.0, d.law, d.problem))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            detail: obj(fields),
            cite: Some(
                "FA-INV-01 (`base`, `base-residual`, `realized-fx`: functional valuations recompute from the cited Rate documents under the named law)".into(),
            ),
            fix: Some(
                "retain this finding with fa verify fx-conversion --json and the same --book and --as-known-at; correct a mis-valued entry with a Reversal and a Replacement, never in place".into(),
            ),
        })
    }
}

fn verify_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let target = args.positional.get(1).map(String::as_str);
    if args.flag("--as-known-at").is_some()
        && !matches!(
            target,
            Some("periods" | "close" | "usage" | "fx-conversion")
        )
    {
        return Err(usage(
            "--as-known-at is supported only by verify periods, verify close, verify usage and verify fx-conversion",
            "select periods, close, usage or fx-conversion for historical verification, or omit --as-known-at",
        ));
    }
    match target {
        Some("book") => verify_book(ctx, args),
        Some("export") => crate::export::verify_export(ctx, args),
        Some("fx-conversion") => verify_fx_conversion(ctx, args),
        Some("accumulator") => notary::verify_accumulator(ctx, args),
        Some("close") => crate::closing::verify_close(ctx, args),
        Some("usage") => {
            if args.positional.len() != 2
                || args.flag("--period").is_some()
                || args.flag("--fiscal-year").is_some()
            {
                return Err(usage(
                    "verify usage checks every root, day and unit at one recorded prefix and takes no period filter",
                    "fa verify usage [--as-known-at HEAD|<seq>|<RFC3339>] --book <dir> --json",
                ));
            }
            let capability = ctx.capability(args, &["read", "verify"])?;
            let mut book = ctx.books.open_admitted(args, |book| {
                admit_whole_book_read(
                    book,
                    &capability,
                    &[fa_policy::Op::Verify],
                    "verifying daily usage",
                )
            })?;
            let (known_at, _) = known_at_flag(args, &book, out)?;
            let verified = verify_usage_at(&mut book, &capability, known_at)?;
            out.known_at(verified.known_at);
            out.event(
                "usage_verified",
                usage_fields(&verified),
                &format!(
                    "daily usage verified from immutable history: {} charges, {} cells agree at {}",
                    verified.charges_checked, verified.cells_checked, verified.known_at.0
                ),
            );
            Ok(())
        }
        Some("entities") => {
            if args.positional.len() != 2 {
                return Err(usage(
                    "verify entities takes no positional argument",
                    "fa verify entities (--period <code>)... | --fiscal-year N --book <dir> --json",
                ));
            }
            let principal = ctx.principal(args);
            let capability = ctx.capability(args, &["read", "verify"])?;
            let book = ctx.books.open_admitted(args, |book| {
                admit_registers(
                    book,
                    principal,
                    &capability,
                    "verifying per-entity registers",
                )
            })?;
            let periods = selected_periods(args, &book)?;
            out.effective(periods_selector(&periods));
            let mut details = Vec::new();
            let mut findings = Vec::new();
            for p in &periods {
                let v = book.verify_entities(p)?;
                findings.extend(v.findings.iter().map(|f| format!("{p}: {f}")));
                details.push(obj(vec![
                    ("period", s(p)),
                    ("green", Json::Bool(v.is_green())),
                    ("known_at", Json::Int(i128::from(v.known_at.0))),
                    ("cells_checked", Json::Int(v.cells_checked as i128)),
                    ("entries_checked", Json::Int(v.entries_checked as i128)),
                    ("fold_digest", s(hex(&v.fold_digest))),
                    ("findings", Json::Arr(v.findings.iter().map(s).collect())),
                ]));
            }
            if findings.is_empty() {
                out.event(
                    "entities_verified",
                    vec![("periods", Json::Arr(details))],
                    &format!(
                        "per-entity registers verified by refold: {} green",
                        periods.join(", ")
                    ),
                );
                Ok(())
            } else {
                Err(Fail::Verification {
                    message: format!(
                        "per-entity registers differ from the journal: {}",
                        findings.join("; ")
                    ),
                    detail: Json::Arr(details),
                    cite: Some(
                        "FA-INV-01.per-entity (entity cells sum to the plain fold; every entry balances per unit and entity)"
                            .into(),
                    ),
                    fix: Some(
                        "retain this finding: the journal is the truth and derived registers are rebuilt from it (fa registers materialize --period <code> --yes)"
                            .into(),
                    ),
                })
            }
        }
        Some("registers") => {
            let principal = ctx.principal(args);
            let capability = ctx.capability(args, &["read", "verify"])?;
            let mut book = ctx.books.open_admitted(args, |book| {
                admit_registers(book, principal, &capability, "verifying derived registers")
            })?;
            let periods = selected_periods(args, &book)?;
            verify_usage_at(&mut book, &capability, None)?;
            out.effective(periods_selector(&periods));
            let mut all_green = true;
            let mut details = Vec::new();
            let mut diagnostics = Vec::new();
            let mut actions = Vec::new();
            let mut repairs = Vec::new();
            for p in &periods {
                let v = match book.verify_registers(p) {
                    Ok(v) => v,
                    Err(BookError::Registers(fa_registers::RegisterError::ProjectionDrift(
                        why,
                    )))
                    | Err(BookError::Registers(fa_registers::RegisterError::Kernel(
                        fa_journal::KernelError::Corrupt(why),
                    ))) => {
                        return Err(Fail::Verification {
                            message: format!("register verification failed in {p}: {why}"),
                            detail: obj(vec![("period", s(p)), ("problem", s(&why))]),
                            cite: Some("FA-INV-04 (registers are derived from the journal)".into()),
                            fix: Some(format!(
                                "retain this finding (`fa verify registers --period {p} --json`); if repair is intended, run `fa registers materialize --period {p} --yes --json`"
                            )),
                        });
                    }
                    Err(error) => return Err(error.into()),
                };
                diagnostics.extend(v.projection_errors.iter().map(|e| format!("{p}: {e}")));
                if !v.drift.is_empty() {
                    diagnostics.push(format!("{p}: {} posted cells differ", v.drift.len()));
                }
                if !v.pending_drift.is_empty() {
                    diagnostics.push(format!(
                        "{p}: {} pending cells differ",
                        v.pending_drift.len()
                    ));
                }
                all_green &= v.is_green();
                if !v.is_green() {
                    repairs.push(format!("--period {p}"));
                }
                if v.is_green() && v.stale {
                    out.warn(format!(
                        "{p}: verified cache has {} unread journal entries; run fa registers advance --period {p} --json",
                        v.lag_entries
                    ));
                    actions.push((
                        format!("fa registers advance --period {p} --json"),
                        "consume unread journal entries after the verified cache prefix".into(),
                    ));
                }
                if v.cache_status == fa_registers::CacheStatus::Uninitialized {
                    out.warn(format!(
                        "{p}: register cache is uninitialized; no processed prefix is certified; initialize it with fa registers advance --period {p} --json"
                    ));
                }
                details.push(obj(vec![
                    ("period", s(p)),
                    ("green", Json::Bool(v.is_green())),
                    (
                        "cache_status",
                        s(match v.cache_status {
                            fa_registers::CacheStatus::Uninitialized => "uninitialized",
                            fa_registers::CacheStatus::Verified => "verified",
                            fa_registers::CacheStatus::Corrupt => "corrupt",
                        }),
                    ),
                    (
                        "verified_through",
                        v.verified_through
                            .map_or(Json::Null, |s| Json::Int(i128::from(s.0))),
                    ),
                    ("stale", Json::Bool(v.stale)),
                    ("lag_entries", Json::Int(v.lag_entries as i128)),
                    ("cells_checked", Json::Int(v.cells_checked as i128)),
                    ("refold_digest", s(hex(&v.refold_digest))),
                    (
                        "stored_digest",
                        v.stored_digest.map_or(Json::Null, |d| s(hex(&d))),
                    ),
                    ("drift", Json::Arr(drift_json(&v.drift))),
                    ("pending_drift", Json::Arr(drift_json(&v.pending_drift))),
                    (
                        "projection_errors",
                        Json::Arr(v.projection_errors.iter().map(s).collect()),
                    ),
                ]));
            }
            if all_green {
                out.event_with_actions(
                    "registers_verified",
                    vec![("periods", Json::Arr(details))],
                    &format!("registers verified by refold: {} green", periods.join(", ")),
                    &actions,
                );
                Ok(())
            } else {
                Err(Fail::Verification {
                    message: format!(
                        "stored registers differ from the refold in {}{}",
                        periods.join(", "),
                        if diagnostics.is_empty() {
                            String::new()
                        } else {
                            format!("; {}", diagnostics.join("; "))
                        }
                    ),
                    detail: Json::Arr(details),
                    cite: Some("FA-INV-04 (registers are derived from the journal)".into()),
                    fix: Some(format!(
                        "retain this verification finding; if repair is intended, run fa registers materialize {} --yes --json with the same --book",
                        repairs.join(" ")
                    )),
                })
            }
        }
        Some("projections") => {
            if args.positional.len() != 2 {
                return Err(usage(
                    "unexpected verify projections argument",
                    "fa verify projections --book <dir> [--json]",
                ));
            }
            if args.flag("--period").is_some() || args.flag("--fiscal-year").is_some() {
                return Err(usage(
                    "verify projections checks every entry at the current head and takes no period filter",
                    "fa verify projections --book <dir> [--json]",
                ));
            }
            let book = ctx.books.open(args)?;
            let v = book.verify_projections(None)?;
            out.known_at(v.known_at);
            let fields = vec![
                ("known_at", Json::Int(i128::from(v.known_at.0))),
                ("entries_checked", Json::Int(v.entries_checked as i128)),
                ("legs_checked", Json::Int(v.legs_checked as i128)),
                ("edges_checked", Json::Int(v.edges_checked as i128)),
                ("drift", Json::Arr(v.drift.iter().map(s).collect())),
            ];
            if v.is_green() {
                out.event(
                    "projections_verified",
                    fields,
                    &format!(
                        "leg projections verified against canonical payloads: {} entries, {} legs, {} edges at {}",
                        v.entries_checked, v.legs_checked, v.edges_checked, v.known_at.0
                    ),
                );
                Ok(())
            } else {
                Err(Fail::Verification {
                    message: format!(
                        "leg projections differ from canonical entry payloads: {}",
                        v.drift.join("; ")
                    ),
                    detail: obj(fields),
                    cite: Some("FA-INV-16 (leg projections equal entry payloads)".into()),
                    fix: Some(
                        "retain this finding with fa verify projections --json and the same --book; then preview the repair from the journal with fa recover projections --dry-run --json, and publish it with --yes if intended".into(),
                    ),
                })
            }
        }
        Some("availability") => {
            let book = ctx.books.open(args)?;
            let v = book.verify_availability()?;
            let units = &book.context().units;
            let unit_of: std::collections::BTreeMap<String, fa_money::UnitId> = book
                .accounts()?
                .into_iter()
                .filter_map(|a| match a.unit_policy {
                    UnitPolicy::Single(u) => Some((a.code, u)),
                    _ => None,
                })
                .collect();
            let amount = |code: &str, m: i128| -> Result<Json, Fail> {
                let unit = unit_of.get(code).ok_or_else(|| {
                    Fail::Internal(format!("limited account `{code}` has no single unit"))
                })?;
                Ok(s(render_amount(Amount::new(*unit, m), units)?))
            };
            let fields = availability_fields(&v, &amount)?;
            if v.is_green() {
                out.event(
                    "availability_verified",
                    fields,
                    &format!(
                        "availability verified by refold: {} limited accounts, {} cells, stored cells agree",
                        v.accounts_checked, v.cells_checked
                    ),
                );
                Ok(())
            } else {
                Err(Fail::Verification {
                    message: format!(
                        "{} limited accounts' stored cells differ from the refold",
                        v.drift.len()
                    ),
                    detail: obj(fields),
                    cite: None,
                    fix: None,
                })
            }
        }
        Some("open-items") => {
            let book = ctx.books.open(args)?;
            let v = book.verify_open_items()?;
            let drift: Vec<Json> = v
                .drift
                .iter()
                .map(|d| {
                    obj(vec![
                        ("entry", s(format!("{:032x}", d.entry.0))),
                        ("ordinal", Json::Int(i128::from(d.ordinal))),
                        ("stored", d.stored.map_or(Json::Null, Json::Int)),
                        ("refolded", Json::Int(d.refolded)),
                    ])
                })
                .collect();
            let fields = vec![
                ("known_at", Json::Int(i128::from(v.known_at.0))),
                ("legs_checked", Json::Int(v.legs_checked as i128)),
                ("drift", Json::Arr(drift)),
            ];
            if v.is_green() {
                out.event(
                    "open_items_verified",
                    fields,
                    &format!(
                        "open items verified by refold: {} legs, applied mirrors agree",
                        v.legs_checked
                    ),
                );
                Ok(())
            } else {
                Err(Fail::Verification {
                    message: format!(
                        "{} applied mirrors differ from the open-item fold",
                        v.drift.len()
                    ),
                    detail: obj(fields),
                    cite: Some(
                        "FA-INV-04.open-amount (an applied mirror is the fold of SETTLES and UNSETTLES over the lineage)".into(),
                    ),
                    fix: Some(
                        "retain this finding with fa verify open-items --json and the same --book; the leg-projection recovery rebuilds applied mirrors from the journal: preview it with fa recover projections --dry-run --json, and publish it with --yes if intended".into(),
                    ),
                })
            }
        }
        Some("schedules") => {
            if args.positional.len() > 2 {
                return Err(usage(
                    "verify schedules takes no extra positional arguments",
                    "fa verify schedules --book <dir> [--json]",
                ));
            }
            if args.flag("--period").is_some() || args.flag("--fiscal-year").is_some() {
                return Err(usage(
                    "verify schedules checks every Schedule vertex at the current head and takes no period filter",
                    "fa verify schedules --book <dir> [--json]",
                ));
            }
            let book = ctx.books.open(args)?;
            let v = book.verify_schedules()?;
            let fields = vec![
                ("schedules_checked", Json::Int(v.schedules_checked as i128)),
                ("executed", Json::Int(v.executed as i128)),
                ("cancelled", Json::Int(v.cancelled as i128)),
                ("drift", Json::Arr(v.drift.iter().map(s).collect())),
            ];
            if v.is_green() {
                out.event(
                    "schedules_verified",
                    fields,
                    &format!(
                        "schedules verified by refold: {} schedules ({} executed, {} cancelled), mirrors agree",
                        v.schedules_checked, v.executed, v.cancelled
                    ),
                );
                Ok(())
            } else {
                Err(Fail::Verification {
                    message: format!(
                        "{} schedule mirrors differ from the journal fold: {}",
                        v.drift.len(),
                        v.drift.join("; ")
                    ),
                    detail: obj(fields),
                    cite: Some("FA-INV-04 (schedules and SCHEDULED_BY mirrors are derived from the journal)".into()),
                    fix: Some(
                        "retain this finding with fa verify schedules --json and the same --book".into(),
                    ),
                })
            }
        }
        Some("periods") => {
            if args.positional.len() > 2 {
                return Err(usage(
                    "verify periods takes no extra positional arguments",
                    "fa verify periods --book <dir> [--as-known-at HEAD|<seq>|<RFC3339>] [--json]",
                ));
            }
            if args.flag("--period").is_some() || args.flag("--fiscal-year").is_some() {
                return Err(usage(
                    "verify periods checks complete journal history and every Period at the selected prefix; it takes no period filter",
                    "fa verify periods --book <dir> [--as-known-at HEAD|<seq>|<RFC3339>] [--json]",
                ));
            }
            let principal = ctx.principal(args);
            let capability = ctx.capability(args, &["read", "verify"])?;
            let mut book = ctx.books.open_admitted(args, |book| {
                // Admit current whole-book authority on trunk before branch
                // selection, timestamp resolution, or native history loading.
                fa_policy::admit_read(&capability, principal, book.context().book_id)
                    .and_then(|()| {
                        fa_policy::require(
                            &capability,
                            fa_policy::Op::Verify,
                            "verifying complete period history",
                        )
                    })
                    .and_then(|()| {
                        fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None)
                    })
                    .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
                book.read_scope(principal, &capability)??;
                Ok(())
            })?;
            let (known_at, _) = known_at_flag(args, &book, out)?;
            let verified = match book.verify_periods_with_history(principal, &capability, known_at)
            {
                Ok(result) => result?,
                Err(BookError::Kernel(fa_journal::KernelError::Corrupt(problem))) => {
                    return Err(Fail::Verification {
                        message: format!("period history verification failed: {problem}"),
                        detail: obj(vec![("problem", s(&problem))]),
                        cite: Some("FA-INV-02 (immutable journal history and rebuildable period state)".into()),
                        fix: Some(
                            "retain this finding with fa verify periods --json and the same --book and --as-known-at; preserve the original native history".into(),
                        ),
                    });
                }
                Err(error) => return Err(error.into()),
            };
            let history = verified.history;
            let v = verified.periods;
            out.known_at(v.known_at);
            let periods: Vec<Json> = v
                .periods
                .iter()
                .map(|p| {
                    obj(vec![
                        ("code", s(&p.code)),
                        ("fiscal_year", Json::Int(i128::from(p.fiscal_year))),
                        ("ordinal", Json::Int(i128::from(p.ordinal))),
                        ("kind", s(kind_name(p.kind))),
                        ("born_state", s(p.born_state.name())),
                        (
                            "stored_state",
                            p.stored_state.map_or(Json::Null, |st| s(st.name())),
                        ),
                        ("refolded_state", s(p.refolded_state.name())),
                        ("transitions", Json::Int(p.transitions as i128)),
                        ("green", Json::Bool(p.green)),
                    ])
                })
                .collect();
            let fields = vec![
                ("known_at", Json::Int(i128::from(v.known_at.0))),
                ("periods_checked", Json::Int(v.periods_checked as i128)),
                ("legacy_periods", Json::Int(v.legacy_periods as i128)),
                (
                    "history_commits_checked",
                    Json::Int(i128::from(history.commits_checked)),
                ),
                (
                    "history_entries_checked",
                    Json::Int(history.entries_checked as i128),
                ),
                (
                    "transitions_checked",
                    Json::Int(v.transitions_checked as i128),
                ),
                ("periods", Json::Arr(periods)),
                ("drift", Json::Arr(v.drift.iter().map(s).collect())),
            ];
            if v.is_green() {
                out.event(
                    "periods_verified",
                    fields,
                    &format!(
                        "periods verified through native history: {} commits, {} immutable entries, {} periods, {} transition(s); state mirrors agree at {}{}",
                        history.commits_checked, history.entries_checked,
                        v.periods_checked, v.transitions_checked, v.known_at.0,
                        if v.legacy_periods == 0 { String::new() } else {
                            format!("; {} legacy period(s) use the calendar baseline without journaled creation provenance", v.legacy_periods)
                        }
                    ),
                );
                Ok(())
            } else {
                Err(Fail::Verification {
                    message: format!(
                        "{} period state or mirror discrepancy(s) found: {}",
                        v.drift.len(),
                        v.drift.join("; ")
                    ),
                    detail: obj(fields),
                    cite: Some("FA-INV-02 (period state is a rebuildable projection of immutable birth declarations and PeriodControl transitions)".into()),
                    fix: Some(
                        "retain this finding with fa verify periods --json and the same --book and --as-known-at".into(),
                    ),
                })
            }
        }
        Some("replay") => {
            // Replay verification (plan §15.2, §16): every accounting
            // commit's recorded rows are replayed into a fresh scratch book
            // and checked against the source pair by pair, entry by entry and
            // fold by fold. It proves the retained history reproduces the
            // book's accounting state; it does not re-perform the posting
            // laws (rows are copied, not re-posted, and both sides fold with
            // the same code).
            if args.positional.len() != 2
                || args.flag("--period").is_some()
                || args.flag("--fiscal-year").is_some()
            {
                return Err(usage(
                    "verify replay replays the whole history and takes no argument",
                    "fa verify replay --book <dir> [--json]",
                ));
            }
            let mut book = ctx.books.open(args)?;
            let keys = BookKeys::generate(&Entropy::production())?;
            let (scratch, map) = book.replay_into_scratch(None, keys, Entropy::production())??;
            let v = book.verify_replay(&scratch, &map)??;
            out.known_at(map.source_prefix);
            out.event(
                "replay_verified",
                vec![
                    ("source_prefix", Json::Int(i128::from(map.source_prefix.0))),
                    ("commits", Json::Int(map.pairs.len() as i128)),
                    ("pairs_checked", Json::Int(v.pairs_checked as i128)),
                    ("entries_checked", Json::Int(v.entries_checked as i128)),
                    ("folds_checked", Json::Int(v.folds_checked as i128)),
                    ("seq_map_digest", s(hex(&v.seq_map_digest))),
                ],
                &format!(
                    "history through {} replayed into a fresh scratch book: {} commits, {} entries and {} period folds agree with the source",
                    map.source_prefix.0, v.pairs_checked, v.entries_checked, v.folds_checked
                ),
            );
            Ok(())
        }
        other => Err(unhandled("verify", other)),
    }
}

pub(crate) fn open_items_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let who = ctx.principal(args);
    let read_cap = ctx.capability(args, &["read"])?;
    let certify_cap = if args.flag("--as-of").is_none()
        && (args.switch("--certify") || args.flag("--certificate-out").is_some())
    {
        Some(read_cap.clone())
    } else {
        None
    };
    let out = &ctx.out;
    let mut book = if let Some(capability) = certify_cap.as_ref() {
        ctx.books.open_admitted(args, |book| {
            prepare_native_certificate_history(book, capability, None)
        })?
    } else {
        ctx.books.open_admitted(args, |book| {
            book.read_scope(who, &read_cap)??;
            Ok(())
        })?
    };
    if args.positional.len() != 1 {
        return Err(usage(
            "unexpected open-items argument",
            "fa open-items [--account <code>] [--as-of YYYY-MM-DD] [--as-known-at HEAD|<seq>|<RFC3339>] --book <dir>",
        ));
    }
    if args.flag_all("--as-of").len() > 1 {
        return Err(usage(
            "--as-of may be supplied only once",
            "fa open-items --help",
        ));
    }
    if args.flag_all("--certificate-out").len() > 1 {
        return Err(usage(
            "--certificate-out may be supplied only once",
            "fa open-items --help",
        ));
    }
    let account = args
        .flag("--account")
        .map(|code| account_vid(book.context().book_id, code));
    let (known_at, requested_utc_ns) = known_at_flag(args, &book, out)?;
    let (report, certificate) = if let Some(as_of) = args.flag("--as-of") {
        if args.switch("--certify") || args.flag("--certificate-out").is_some() {
            return Err(usage(
                "--as-of open-items snapshot cannot be combined with --certify; use `fa gl aging` for effective-date aging",
                "fa open-items [--account <code>] --as-of YYYY-MM-DD --book <dir>",
            ));
        }
        let day = DateDay::parse(as_of).map_err(|e| {
            usage(
                format!("{e}; --as-of requires a civil date; instant selectors are unsupported"),
                "--as-of YYYY-MM-DD",
            )
        })?;
        // Judged against the scope caveats before the query is constructed
        // (doctrine 8, fa-0x0): the snapshot reaches every period that
        // starts by its day.
        book.read_scope(who, &read_cap)??
            .admit_as_of(day, known_at)??;
        let snapshot = book.open_items_as_of(account, day, known_at)?;
        out.effective(format!("as-of:{day}"));
        let chart = book.accounts()?;
        let needed: std::collections::BTreeSet<VId> = snapshot
            .items
            .iter()
            .map(|i| i.account)
            .chain(account)
            .collect();
        let mut accounts = std::collections::BTreeMap::new();
        for row in chart {
            if row.created_at <= snapshot.known_at && needed.contains(&row.vid) {
                accounts.insert(row.vid, row);
            }
        }
        if let Some(acc) = account
            && !accounts.contains_key(&acc)
        {
            return Err(
                BookError::Registers(fa_registers::RegisterError::InvalidSelection(format!(
                    "unknown account {:032x} at sequence {}",
                    acc.0, snapshot.known_at.0
                )))
                .into(),
            );
        }
        (
            fa_registers::open_items::OpenItemsReport {
                known_at: snapshot.known_at,
                account_filter: account,
                accounts,
                items: snapshot.items,
            },
            None,
        )
    } else if let Some(capability) = certify_cap.as_ref() {
        prepare_native_certificate_history(&mut book, capability, known_at)?;
        let selection = ReportSelection::OpenItems { account };
        book.read_scope(who, &read_cap)??
            .admit_report(&selection, known_at)??;
        let certified = match requested_utc_ns {
            Some(instant) => book.certify_report_at_instant(selection, instant)??,
            None => book.certify_report(selection, known_at)??,
        };
        out.time_selection(certified.certificate.time_selection.as_ref());
        let ReportOutput::OpenItems(report) = certified.report else {
            return Err(Fail::Internal(
                "open-items certification returned another report kind".into(),
            ));
        };
        (report, Some(certified.certificate))
    } else {
        // Open items reach the whole book (doctrine 8, fa-0x0).
        book.read_scope(who, &read_cap)??
            .admit_report(&ReportSelection::OpenItems { account }, known_at)??;
        (book.open_items_report(account, known_at)?, None)
    };
    validate_open_items_report(&report, &book.context().units)?;
    let retained = certificate
        .as_ref()
        .zip(certify_cap.as_ref())
        .map(|(certificate, cap)| {
            notary::retain_report_certificate(&mut book, &ctx.files, args, certificate, cap)
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    render_open_items(out, &book, &report, digest.as_deref())?;
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        notary::emit_report_certificate(out, args, certificate, &bytes, &retained);
    }
    Ok(())
}

/// Refuse corrupt presentation inputs before retaining or emitting a report.
fn validate_open_items_report(
    report: &fa_registers::open_items::OpenItemsReport,
    units: &fa_money::UnitRegistry,
) -> Result<(), Fail> {
    for account in report
        .items
        .iter()
        .map(|item| item.account)
        .chain(report.account_filter)
    {
        if !report.accounts.contains_key(&account) {
            return Err(Fail::Internal(format!(
                "open-items report omits account {:032x} at sequence {}",
                account.0, report.known_at.0
            )));
        }
    }
    for item in &report.items {
        registered_unit_code(fa_money::UnitId(item.unit_id), units)?;
    }
    Ok(())
}

/// Account labels and item history belong to the same resolved snapshot.
/// Replay uses this renderer without observing the present chart.
pub(crate) fn render_open_items(
    out: &Out,
    book: &Book,
    report: &fa_registers::open_items::OpenItemsReport,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    validate_open_items_report(report, &book.context().units)?;
    out.known_at(report.known_at);
    let items = &report.items;
    let code_of = |vid: VId| {
        report
            .accounts
            .get(&vid)
            .map(|account| account.code.as_str())
            .ok_or_else(|| {
                Fail::Internal(format!(
                    "open-items report omits account {:032x} at sequence {}",
                    vid.0, report.known_at.0
                ))
            })
    };
    let filter = report.account_filter.map(code_of).transpose()?;
    let render = |unit: u32, m: i128| {
        render_amount(
            Amount::new(fa_money::UnitId(unit), m),
            &book.context().units,
        )
    };
    let rows: Vec<Json> = items
        .iter()
        .map(|i| {
            Ok(obj(vec![
                ("entry", s(format!("{:032x}", i.entry.0))),
                ("ordinal", Json::Int(i128::from(i.ordinal))),
                ("account", s(code_of(i.account)?)),
                (
                    "side",
                    s(if i.side == Side::Debit {
                        "debit"
                    } else {
                        "credit"
                    }),
                ),
                ("effective_date", s(i.effective_date.render())),
                ("recorded_at", Json::Int(i128::from(i.recorded_at.0))),
                ("original", s(render(i.unit_id, i.original)?)),
                ("applied", s(render(i.unit_id, i.applied)?)),
                ("applied_out", s(render(i.unit_id, i.applied_out)?)),
                ("open", s(render(i.unit_id, i.open)?)),
                (
                    "applications",
                    Json::Arr(
                        i.applications
                            .iter()
                            .map(|a| {
                                Ok(obj(vec![
                                    ("entry", s(format!("{:032x}", a.entry.0))),
                                    ("ordinal", Json::Int(i128::from(a.ordinal))),
                                    ("amount", s(render(i.unit_id, a.amount)?)),
                                    ("recorded_at", Json::Int(i128::from(a.recorded_at.0))),
                                    ("live", Json::Bool(a.live)),
                                ]))
                            })
                            .collect::<Result<_, Fail>>()?,
                    ),
                ),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    if out.json {
        out.event_with_certificate(
            "open_items",
            vec![
                ("account", filter.map_or(Json::Null, s)),
                ("count", Json::Int(items.len() as i128)),
                ("items", Json::Arr(rows)),
            ],
            "",
            certificate,
        );
    } else {
        out.line(out.style().header(&format!(
            "{:<10} {:<34} {:>3} {:<6} {:>18} {:>18} {:>18} {:>18}",
            "account", "entry", "leg", "side", "original", "applied", "applied_out", "open"
        )));
        for i in items {
            out.line(format!(
                "{:<10} {:<34} {:>3} {:<6} {:>18} {:>18} {:>18} {:>18}",
                code_of(i.account)?,
                format!("{:032x}", i.entry.0),
                i.ordinal,
                if i.side == Side::Debit {
                    "debit"
                } else {
                    "credit"
                },
                render(i.unit_id, i.original)?,
                render(i.unit_id, i.applied)?,
                render(i.unit_id, i.applied_out)?,
                render(i.unit_id, i.open)?
            ));
        }
        out.line(format!("{} open item(s)", items.len()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// gl (detail | roll-forward | aging | cash-flow)
// ---------------------------------------------------------------------------

/// Called after current read admission. Existing GL certificate formats bind
/// a sequence, so an instant request must not silently lose its TimeEvidence.
fn gl_known_at(args: &Args, book: &Book, out: &Out) -> Result<Option<CommitSeq>, Fail> {
    let (known_at, requested_utc_ns) = known_at_flag(args, book, out)?;
    if let (Some(sequence), Some(_)) = (known_at, requested_utc_ns)
        && (args.switch("--certify") || args.flag("--certificate-out").is_some())
    {
        return Err(usage(
            "GL certificates bind a recorded sequence; instant-resolution evidence is not part of this certificate format",
            format!(
                "use --as-known-at {} to certify this resolved GL report",
                sequence.0
            ),
        ));
    }
    Ok(known_at)
}

pub(crate) fn parse_gl_scope(
    args: &Args,
    book: &Book,
    capability: &Capability,
    out: &Out,
    default_label: &str,
    example: &str,
) -> Result<RollForwardRequest, Fail> {
    let known_at = gl_known_at(args, book, out)?;
    if let Some(seq) = known_at {
        out.known_at(seq);
    }
    let accounts: Vec<VId> = args
        .flag_all("--account")
        .into_iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|code| account_vid(book.context().book_id, code))
        .collect();
    if accounts.is_empty() {
        return Err(usage("--account is required", example));
    }
    let window = parse_gl_window(args, book, capability, out, known_at, default_label)?;
    Ok(RollForwardRequest {
        accounts,
        units: window.units,
        label: window.label,
        effective_from: window.from,
        effective_through: window.to,
        known_at,
    })
}

/// The selection every gl view shares after its accounts: native units
/// (the book's base unit when none is named), inclusive civil dates and the
/// label. `known_at` is the view's already-resolved frontier.
struct GlWindow {
    units: Vec<u32>,
    from: DateDay,
    to: DateDay,
    label: String,
}

fn parse_gl_window(
    args: &Args,
    book: &Book,
    capability: &Capability,
    out: &Out,
    known_at: Option<CommitSeq>,
    default_label: &str,
) -> Result<GlWindow, Fail> {
    let unit_codes: Vec<&str> = args
        .flag_all("--unit")
        .into_iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    let units: Vec<u32> = if unit_codes.is_empty() {
        vec![
            book.read_scope(capability.holder(), capability)??
                .spec_at(known_at)??
                .ok_or(BookError::NoBook)?
                .base_unit
                .0,
        ]
    } else {
        unit_codes
            .into_iter()
            .map(|code| {
                book.context()
                    .units
                    .lookup(code)
                    .map(|u| u.0)
                    .ok_or_else(|| {
                        usage(
                            format!("unknown unit `{code}`"),
                            "pass a registered currency/unit code such as USD",
                        )
                    })
            })
            .collect::<Result<_, Fail>>()?
    };
    let from = DateDay::parse(args.require("--from", "YYYY-MM-DD")?).map_err(|e| {
        usage(
            format!("{e}; --from requires a civil date"),
            "--from YYYY-MM-DD",
        )
    })?;
    let to = DateDay::parse(args.require("--to", "YYYY-MM-DD")?).map_err(|e| {
        usage(
            format!("{e}; --to requires a civil date"),
            "--to YYYY-MM-DD",
        )
    })?;
    let label = args.flag("--label").unwrap_or(default_label).to_string();
    out.effective(format!("between:{from}..{to}"));
    Ok(GlWindow {
        units,
        from,
        to,
        label,
    })
}

pub(crate) struct GeneralLedgerPresentation {
    fields: Vec<(&'static str, Json)>,
    human: String,
}

/// Resolve every label, amount and index before retention, an output file, or
/// a success event. Native reads and recipient-bound replay share this view.
pub(crate) fn general_ledger_presentation(
    book: &Book,
    gl: &fa::GeneralLedger,
) -> Result<GeneralLedgerPresentation, Fail> {
    let units = &book.context().units;
    let accounts_by_id: std::collections::BTreeMap<u128, _> =
        gl.accounts().iter().map(|a| (a.id, a)).collect();
    let cells: Vec<Json> = gl
        .cells()
        .iter()
        .map(|c| {
            let acc = accounts_by_id.get(&c.account_id).ok_or_else(|| {
                Fail::Internal(format!(
                    "gl cell references missing account {:032x}",
                    c.account_id
                ))
            })?;
            let unit_code = registered_unit_code(fa_money::UnitId(c.unit_id), units)?;
            let fmt = |m: i128| render_amount(Amount::new(fa_money::UnitId(c.unit_id), m), units);
            let line_count = c
                .line_end
                .checked_sub(c.line_start)
                .ok_or_else(|| Fail::Internal("gl cell has an inverted line range".into()))?;
            Ok(obj(vec![
                ("account", s(&acc.code)),
                ("account_vid", s(format!("{:032x}", c.account_id))),
                ("name", s(&acc.name)),
                (
                    "type",
                    s(AccountType(acc.account_type).name().unwrap_or("unknown")),
                ),
                ("unit", s(unit_code)),
                ("opening", s(fmt(c.opening)?)),
                ("debits", s(fmt(c.debits)?)),
                ("credits", s(fmt(c.credits)?)),
                ("net_change", s(fmt(c.net_change)?)),
                ("closing", s(fmt(c.closing)?)),
                ("line_count", Json::Int(i128::from(line_count))),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    let lines: Vec<Json> = gl
        .lines()
        .iter()
        .map(|line| {
            let cell = gl
                .cells()
                .get(line.cell_index as usize)
                .ok_or_else(|| Fail::Internal("gl line cell_index out of bounds".into()))?;
            let acc = accounts_by_id
                .get(&cell.account_id)
                .ok_or_else(|| Fail::Internal("gl cell account missing".into()))?;
            let bucket = gl
                .buckets()
                .get(line.bucket_index as usize)
                .ok_or_else(|| Fail::Internal("gl line bucket_index out of bounds".into()))?;
            let unit_code = registered_unit_code(fa_money::UnitId(cell.unit_id), units)?;
            let fmt =
                |m: i128| render_amount(Amount::new(fa_money::UnitId(cell.unit_id), m), units);
            Ok(obj(vec![
                ("account", s(&acc.code)),
                ("unit", s(unit_code)),
                ("entry_digest", s(hex(&line.entry_digest))),
                ("leg_index", Json::Int(i128::from(line.leg_index))),
                ("recorded_at", Json::Int(i128::from(line.recorded_seq))),
                ("effective_date", s(line.effective_day.render())),
                ("class", s(bucket.class.name().unwrap_or("unknown"))),
                ("reason_code", s(&bucket.reason_code)),
                ("debits", s(fmt(line.debits)?)),
                ("credits", s(fmt(line.credits)?)),
                ("running_balance", s(fmt(line.running_balance)?)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    Ok(GeneralLedgerPresentation {
        fields: vec![
            ("label", s(gl.label())),
            ("known_at", Json::Int(i128::from(gl.known_at().0))),
            ("effective_from", s(gl.effective_from().render())),
            ("effective_through", s(gl.effective_through().render())),
            ("cells", Json::Arr(cells)),
            ("lines", Json::Arr(lines)),
        ],
        human: format!(
            "gl detail `{}` ({}..={}): {} cell(s), {} line(s)",
            gl.label(),
            gl.effective_from(),
            gl.effective_through(),
            gl.cells().len(),
            gl.lines().len()
        ),
    })
}

pub(crate) fn render_general_ledger(
    out: &Out,
    gl: &fa::GeneralLedger,
    presentation: GeneralLedgerPresentation,
    certificate: Option<&str>,
) {
    out.known_at(gl.known_at());
    out.effective(format!(
        "between:{}..{}",
        gl.effective_from(),
        gl.effective_through()
    ));
    out.event_with_certificate(
        "general_ledger",
        presentation.fields,
        &presentation.human,
        certificate,
    );
}

pub(crate) fn render_roll_forward(
    out: &Out,
    book: &Book,
    report: &fa::RollForward,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    out.known_at(CommitSeq(report.known_at));
    out.effective(format!(
        "between:{}..{}",
        report.effective_from, report.effective_through
    ));
    let units = &book.context().units;
    let accounts: std::collections::BTreeMap<u128, _> = report
        .accounts
        .iter()
        .map(|account| (account.id, account))
        .collect();
    let buckets: Vec<Json> = report
        .buckets
        .iter()
        .map(|bucket| {
            obj(vec![
                ("class", s(bucket.class.name().unwrap_or("unknown"))),
                ("reason_code", s(&bucket.reason_code)),
                (
                    "rule_digest",
                    bucket
                        .rule_digest
                        .as_ref()
                        .map_or(Json::Null, |digest| s(hex(digest))),
                ),
            ])
        })
        .collect();
    let rows: Vec<Json> = report
        .rows
        .iter()
        .map(|row| {
            let account = accounts
                .get(&row.account_id)
                .ok_or_else(|| Fail::Internal("roll-forward row account missing".into()))?;
            let unit = fa_money::UnitId(row.unit_id);
            let render = |mantissa| render_amount(Amount::new(unit, mantissa), units);
            let activity = row
                .activity
                .iter()
                .map(|amount| Ok(s(render(*amount)?)))
                .collect::<Result<Vec<_>, Fail>>()?;
            Ok(obj(vec![
                ("account", s(&account.code)),
                ("account_vid", s(format!("{:032x}", row.account_id))),
                ("name", s(&account.name)),
                (
                    "type",
                    s(AccountType(account.account_type)
                        .name()
                        .unwrap_or("unknown")),
                ),
                ("unit", s(registered_unit_code(unit, units)?)),
                ("opening", s(render(row.opening)?)),
                ("activity", Json::Arr(activity)),
                ("net_change", s(render(row.net_change)?)),
                ("closing", s(render(row.closing)?)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    out.event_with_certificate(
        "roll_forward",
        vec![
            ("label", s(&report.label)),
            ("known_at", Json::Int(i128::from(report.known_at))),
            ("effective_from", s(report.effective_from.render())),
            ("effective_through", s(report.effective_through.render())),
            ("buckets", Json::Arr(buckets)),
            ("rows", Json::Arr(rows)),
            ("movement_count", Json::Int(report.movements.len() as i128)),
        ],
        &format!(
            "roll-forward `{}` ({}..={}): {} row(s), {} movement(s)",
            report.label,
            report.effective_from,
            report.effective_through,
            report.rows.len(),
            report.movements.len(),
        ),
        certificate,
    );
    Ok(())
}

pub(crate) fn render_aging(
    out: &Out,
    book: &Book,
    aging: &fa::EffectiveDateAging,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    out.known_at(aging.known_at);
    out.effective(format!("as-of:{}", aging.effective_through));
    let units = &book.context().units;
    let accounts: std::collections::BTreeMap<VId, String> = book
        .accounts()?
        .into_iter()
        .filter(|account| account.created_at <= aging.known_at)
        .map(|account| (account.vid, account.code))
        .collect();
    if let Some(account) = aging.account
        && !accounts.contains_key(&account)
    {
        return Err(
            BookError::Registers(fa_registers::RegisterError::InvalidSelection(format!(
                "unknown account {:032x} at sequence {}",
                account.0, aging.known_at.0
            )))
            .into(),
        );
    }
    let code_of = |vid: VId| -> Result<&str, Fail> {
        accounts
            .get(&vid)
            .map(String::as_str)
            .ok_or_else(|| Fail::Internal(format!("aging omits account {:032x}", vid.0)))
    };
    let bands = aging
        .bands
        .iter()
        .map(|band| {
            obj(vec![
                (
                    "lower_inclusive",
                    Json::Int(i128::from(band.lower_inclusive)),
                ),
                (
                    "upper_inclusive",
                    band.upper_inclusive
                        .map_or(Json::Null, |upper| Json::Int(i128::from(upper))),
                ),
            ])
        })
        .collect();
    let items = aging
        .items
        .iter()
        .map(|aged| {
            let item = &aged.item;
            let render =
                |amount| render_amount(Amount::new(fa_money::UnitId(item.unit_id), amount), units);
            Ok(obj(vec![
                ("entry", s(format!("{:032x}", item.entry.0))),
                ("ordinal", Json::Int(i128::from(item.ordinal))),
                ("account", s(code_of(item.account)?)),
                (
                    "side",
                    s(if item.side == Side::Debit {
                        "debit"
                    } else {
                        "credit"
                    }),
                ),
                ("effective_date", s(item.effective_date.render())),
                ("recorded_at", Json::Int(i128::from(item.recorded_at.0))),
                ("original", s(render(item.original)?)),
                ("applied", s(render(item.applied)?)),
                ("applied_out", s(render(item.applied_out)?)),
                ("open", s(render(item.open)?)),
                ("age_days", Json::Int(i128::from(aged.age_days))),
                ("bucket", Json::Int(aged.bucket as i128)),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let cells = aging
        .cells
        .iter()
        .map(|cell| {
            let unit = fa_money::UnitId(cell.unit_id);
            let render = |amount| render_amount(Amount::new(unit, amount), units);
            Ok(obj(vec![
                ("account", s(code_of(cell.account)?)),
                ("unit", s(registered_unit_code(unit, units)?)),
                ("bucket", Json::Int(cell.bucket as i128)),
                ("debits", s(render(cell.amounts.debits)?)),
                ("credits", s(render(cell.amounts.credits)?)),
                ("item_count", Json::Int(i128::from(cell.amounts.item_count))),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let totals = aging
        .totals
        .iter()
        .map(|total| {
            let unit = fa_money::UnitId(total.unit_id);
            let render = |amount| render_amount(Amount::new(unit, amount), units);
            Ok(obj(vec![
                ("account", s(code_of(total.account)?)),
                ("unit", s(registered_unit_code(unit, units)?)),
                ("debits", s(render(total.amounts.debits)?)),
                ("credits", s(render(total.amounts.credits)?)),
                (
                    "item_count",
                    Json::Int(i128::from(total.amounts.item_count)),
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let account = aging.account.map(code_of).transpose()?;
    out.event_with_certificate(
        "aging",
        vec![
            ("account", account.map_or(Json::Null, s)),
            ("known_at", Json::Int(i128::from(aging.known_at.0))),
            ("effective_through", s(aging.effective_through.render())),
            ("bands", Json::Arr(bands)),
            ("items", Json::Arr(items)),
            ("cells", Json::Arr(cells)),
            ("totals", Json::Arr(totals)),
        ],
        &format!(
            "effective-date aging through {}: {} open item(s) across {} cell(s)",
            aging.effective_through,
            aging.items.len(),
            aging.cells.len()
        ),
        certificate,
    );
    Ok(())
}

fn parse_digest32(text: &str, what: &str) -> Result<[u8; 32], Fail> {
    if text.len() != 64 {
        return Err(usage(
            format!("{what} must be a 64-character hex digest"),
            "pass the entry's 64-hex entry_digest",
        ));
    }
    let mut out = [0u8; 32];
    for (idx, chunk) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let s = core::str::from_utf8(chunk).unwrap_or("");
        out[idx] = u8::from_str_radix(s, 16).map_err(|_| {
            usage(
                format!("{what} must be valid hexadecimal"),
                "pass the entry's 64-hex entry_digest",
            )
        })?;
    }
    Ok(out)
}

/// Reject unrecognized policy inputs before deriving or retaining a report.
/// Existing optional defaults remain the responsibility of the typed parsers.
pub(crate) fn validate_cash_flow_policy_fields(doc: &Json, indirect: bool) -> Result<(), Fail> {
    let check = |value: &Json, allowed: &[&str], context: &str| -> Result<(), Fail> {
        let Json::Obj(fields) = value else {
            return Err(usage(
                format!("{context} must be a JSON object"),
                "use the documented direct or indirect cash-flow policy fields",
            ));
        };
        for (field, _) in fields {
            if !allowed.contains(&field.as_str()) {
                return Err(usage(
                    format!("unknown {context} field '{field}'"),
                    "use the documented direct or indirect cash-flow policy fields",
                ));
            }
        }
        Ok(())
    };
    let allowed: &[&str] = if indirect {
        &[
            "name",
            "cash_policy",
            "cash_accounts",
            "assignments",
            "adjustments",
        ]
    } else {
        &["name", "cash_accounts", "assignments"]
    };
    check(doc, allowed, "cash-flow policy")?;
    for (field, allowed) in [
        (
            "assignments",
            &["entry_digest", "leg_index", "activity"][..],
        ),
        (
            "adjustments",
            &["entry_digest", "leg_index", "category", "sign", "reason"][..],
        ),
    ] {
        let Some(value) = doc.get(field) else {
            continue;
        };
        let Json::Arr(items) = value else {
            return Err(usage(
                format!("cash-flow policy '{field}' must be an array"),
                "provide an array of explicit journal-leg classifications or adjustments",
            ));
        };
        for (index, item) in items.iter().enumerate() {
            check(item, allowed, &format!("{field}[{index}]"))?;
        }
    }
    Ok(())
}

pub(crate) fn parse_cash_flow_definition(
    doc: &Json,
    book_id: Id128,
    default_accounts: &[VId],
    default_name: &str,
) -> Result<CashFlowDefinition, Fail> {
    let Json::Obj(fields) = doc else {
        return Err(usage(
            "cash-flow policy must be a JSON object",
            r#"{"name":"cash-v1","assignments":[...]}"#,
        ));
    };
    let get = |k: &str| fields.iter().find(|(name, _)| name == k).map(|(_, v)| v);
    let name = match get("name") {
        Some(Json::Str(s)) => s.clone(),
        None => default_name.to_string(),
        _ => {
            return Err(usage(
                "policy `name` must be a string",
                r#"{"name":"cash-v1","assignments":[...]}"#,
            ));
        }
    };
    let cash_accounts: Vec<u128> = match get("cash_accounts") {
        None => default_accounts.iter().map(|v| v.0).collect(),
        Some(Json::Arr(items)) => items
            .iter()
            .map(|item| {
                let Json::Str(code) = item else {
                    return Err(usage(
                        "cash_accounts entries must be account code strings",
                        r#""cash_accounts":["1000"]"#,
                    ));
                };
                if code.len() == 32 && code.bytes().all(|b| b.is_ascii_hexdigit()) {
                    u128::from_str_radix(code, 16).map_err(|_| {
                        usage("invalid 32-hex account vid", r#""cash_accounts":["1000"]"#)
                    })
                } else {
                    Ok(account_vid(book_id, code).0)
                }
            })
            .collect::<Result<_, Fail>>()?,
        _ => {
            return Err(usage(
                "`cash_accounts` must be an array of account codes",
                r#""cash_accounts":["1000"]"#,
            ));
        }
    };
    let assignments = parse_cash_flow_assignments(get("assignments"), "assignment")?;
    Ok(CashFlowDefinition {
        name,
        cash_accounts,
        assignments,
    })
}

fn parse_cash_flow_activity(act: &str) -> Result<CashFlowActivity, Fail> {
    Ok(match act {
        "operating" | "Operating" => CashFlowActivity::Operating,
        "investing" | "Investing" => CashFlowActivity::Investing,
        "financing" | "Financing" => CashFlowActivity::Financing,
        "exchange_effect" | "exchange_effects" | "ExchangeEffect" => {
            CashFlowActivity::ExchangeEffect
        }
        "internal_transfer" | "InternalTransfer" => CashFlowActivity::InternalTransfer,
        other => {
            return Err(usage(
                format!("unknown cash-flow activity `{other}`"),
                "use operating, investing, financing, exchange_effect, or internal_transfer",
            ));
        }
    })
}

/// Whole original cash legs: a direct policy's `assignments` or a rule
/// policy's `overrides` (`what` names one item in messages).
fn parse_cash_flow_assignments(
    value: Option<&Json>,
    what: &str,
) -> Result<Vec<CashFlowAssignment>, Fail> {
    match value {
        None => Ok(Vec::new()),
        Some(Json::Arr(items)) => items
            .iter()
            .map(|item| {
                let Json::Obj(af) = item else {
                    return Err(usage(
                        format!("each {what} must be a JSON object"),
                        r#"{"entry_digest":"...","leg_index":0,"activity":"operating"}"#,
                    ));
                };
                let aget = |k: &str| af.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                let Some(Json::Str(digest_hex)) = aget("entry_digest") else {
                    return Err(usage(
                        format!("{what} requires string `entry_digest`"),
                        r#"{"entry_digest":"<64-hex>","leg_index":0,"activity":"operating"}"#,
                    ));
                };
                let entry_digest = parse_digest32(digest_hex, &format!("{what}.entry_digest"))?;
                let Some(Json::Int(leg_idx)) = aget("leg_index") else {
                    return Err(usage(
                        format!("{what} requires integer `leg_index`"),
                        r#"{"entry_digest":"<64-hex>","leg_index":0,"activity":"operating"}"#,
                    ));
                };
                let leg_index = u32::try_from(*leg_idx).map_err(|_| {
                    usage(
                        format!("{what} `leg_index` must fit in u32"),
                        r#""leg_index":0"#,
                    )
                })?;
                let Some(Json::Str(act)) = aget("activity") else {
                    return Err(usage(
                        format!("{what} requires string `activity`"),
                        r#""activity":"operating|investing|financing|exchange_effect|internal_transfer""#,
                    ));
                };
                Ok(CashFlowAssignment {
                    entry_digest,
                    leg_index,
                    activity: parse_cash_flow_activity(act)?,
                })
            })
            .collect(),
        _ => Err(usage(
            format!("`{what}s` must be an array"),
            format!(
                r#""{what}s":[{{"entry_digest":"...","leg_index":0,"activity":"operating"}}]"#
            ),
        )),
    }
}

pub(crate) fn cash_flow_activity_name(activity: CashFlowActivity) -> &'static str {
    match activity {
        CashFlowActivity::Operating => "operating",
        CashFlowActivity::Investing => "investing",
        CashFlowActivity::Financing => "financing",
        CashFlowActivity::ExchangeEffect => "exchange_effect",
        CashFlowActivity::InternalTransfer => "internal_transfer",
    }
}

const SPLIT_POLICY_EXAMPLE: &str = r#"{"name":"loan-payments-v1","cash_accounts":["1000"],"splits":[{"entry_digest":"<64-hex>","leg_index":0,"reason":"Principal and interest","portions":[{"activity":"financing","amount":"80.00 USD"},{"activity":"operating","amount":"20.00 USD"}]}]}"#;

/// Keep each supplied unit until the cited native cash leg has been checked.
/// The library's portion type is an i128 in its source leg's unit, so passing
/// only parsed mantissas would silently accept e.g. EUR portions of a USD leg.
type CashFlowSourceUnits = std::collections::BTreeMap<([u8; 32], u32), fa_money::UnitId>;

pub(crate) struct ParsedCashFlowSplits {
    definition: fa::cash_flow_split::CashFlowSplitDefinition,
    leg_units: CashFlowSourceUnits,
}

impl ParsedCashFlowSplits {
    pub(crate) fn bind_to_source(
        self,
        source: &fa::GeneralLedger,
    ) -> Result<fa::cash_flow_split::CashFlowSplitDefinition, Refusal> {
        let source_units = cash_flow_source_units(source)?;
        for (citation, unit) in self.leg_units {
            match source_units.get(&citation) {
                Some(source_unit) if *source_unit == unit => {}
                Some(source_unit) => {
                    return Err(cash_flow_split_source_refusal(format!(
                        "cash split {} leg {} declares unit {}, but its native cash leg has unit {}",
                        hex(&citation.0),
                        citation.1,
                        unit.0,
                        source_unit.0,
                    )));
                }
                None => {
                    return Err(cash_flow_split_source_refusal(format!(
                        "cash split {} leg {} is outside the selected native cash ledger",
                        hex(&citation.0),
                        citation.1,
                    )));
                }
            }
        }
        Ok(self.definition)
    }
}

fn cash_flow_split_source_refusal(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §12.1 (cash portions preserve each original leg's native unit)",
        "use gl detail at the same account, units, dates and known-at; quote every portion in its cited cash leg's unit and split that exact original amount",
    )
}

fn cash_flow_source_units(source: &fa::GeneralLedger) -> Result<CashFlowSourceUnits, Refusal> {
    source
        .lines()
        .iter()
        .map(|line| {
            let cell = source
                .cells()
                .get(line.cell_index as usize)
                .ok_or_else(|| {
                    cash_flow_split_source_refusal("cash split source leg has no native unit cell")
                })?;
            Ok((
                (line.entry_digest, line.leg_index),
                fa_money::UnitId(cell.unit_id),
            ))
        })
        .collect()
}

/// Split policies are a separate format selected by `splits`. Every nested
/// field is checked so a misspelled classification or amount cannot disappear.
pub(crate) fn validate_cash_flow_split_policy_fields(
    doc: &Json,
    indirect: bool,
) -> Result<(), Fail> {
    if indirect {
        return Err(usage(
            "splits policies partition direct cash flow and cannot combine with --indirect",
            "drop --indirect, or use an indirect policy with assignments and adjustments",
        ));
    }
    let check = |value: &Json, allowed: &[&str], context: &str| -> Result<(), Fail> {
        let Json::Obj(fields) = value else {
            return Err(usage(
                format!("{context} must be a JSON object"),
                SPLIT_POLICY_EXAMPLE,
            ));
        };
        for (field, _) in fields {
            if !allowed.contains(&field.as_str()) {
                return Err(usage(
                    format!("unknown {context} field '{field}'"),
                    SPLIT_POLICY_EXAMPLE,
                ));
            }
        }
        Ok(())
    };
    check(
        doc,
        &["name", "cash_accounts", "splits"],
        "cash split policy",
    )?;
    let Some(Json::Arr(splits)) = doc.get("splits") else {
        return Err(usage(
            "cash split policy requires an array `splits`",
            SPLIT_POLICY_EXAMPLE,
        ));
    };
    for split in splits {
        check(
            split,
            &["entry_digest", "leg_index", "reason", "portions"],
            "cash split",
        )?;
        let Some(Json::Arr(portions)) = split.get("portions") else {
            return Err(usage(
                "each cash split requires an array `portions`",
                SPLIT_POLICY_EXAMPLE,
            ));
        };
        for portion in portions {
            check(portion, &["activity", "amount"], "cash split portion")?;
        }
    }
    Ok(())
}

pub(crate) fn parse_cash_flow_splits(
    doc: &Json,
    book_id: Id128,
    default_accounts: &[VId],
    default_name: &str,
    units: &fa_money::UnitRegistry,
) -> Result<ParsedCashFlowSplits, Fail> {
    use fa::cash_flow_split::{CashFlowLegSplit, CashFlowPortion, CashFlowSplitDefinition};

    validate_cash_flow_split_policy_fields(doc, false)?;
    // Share direct-policy name/account defaults, after the split format has
    // excluded assignments and every other format's fields.
    let base = parse_cash_flow_definition(doc, book_id, default_accounts, default_name)?;
    let Some(Json::Arr(items)) = doc.get("splits") else {
        return Err(usage(
            "cash split policy requires `splits`",
            SPLIT_POLICY_EXAMPLE,
        ));
    };
    if items.len() > fa::MAX_GENERAL_LEDGER_LINES {
        return Err(usage(
            "cash split policy exceeds the native leg bound",
            SPLIT_POLICY_EXAMPLE,
        ));
    }
    let string = |value: &Json, field: &str| -> Result<String, Fail> {
        match value.get(field) {
            Some(Json::Str(text)) if !text.trim().is_empty() => Ok(text.clone()),
            _ => Err(usage(
                format!("cash split `{field}` requires a nonempty string"),
                SPLIT_POLICY_EXAMPLE,
            )),
        }
    };
    let mut splits = Vec::with_capacity(items.len());
    let mut leg_units = std::collections::BTreeMap::new();
    for item in items {
        let entry_digest = parse_digest32(&string(item, "entry_digest")?, "split.entry_digest")?;
        let leg_index = match item.get("leg_index") {
            Some(Json::Int(index)) => u32::try_from(*index)
                .map_err(|_| usage("cash split leg_index must fit in u32", SPLIT_POLICY_EXAMPLE))?,
            _ => {
                return Err(usage(
                    "cash split requires integer leg_index",
                    SPLIT_POLICY_EXAMPLE,
                ));
            }
        };
        let reason = string(item, "reason")?;
        let Some(Json::Arr(values)) = item.get("portions") else {
            return Err(usage(
                "cash split requires `portions`",
                SPLIT_POLICY_EXAMPLE,
            ));
        };
        if values.is_empty()
            || values.len() > fa::cash_flow_split::MAX_CASH_FLOW_SPLIT_PARTS_PER_LEG
        {
            return Err(usage(
                "each cash split needs one to five portions",
                SPLIT_POLICY_EXAMPLE,
            ));
        }
        let mut portions = Vec::with_capacity(values.len());
        let mut leg_unit = None;
        for value in values {
            let text = string(value, "amount")?;
            let amount = Amount::parse(&text, units).map_err(|error| {
                usage(
                    format!("cash split amount `{text}`: {error}"),
                    SPLIT_POLICY_EXAMPLE,
                )
            })?;
            if leg_unit.is_some_and(|unit| unit != amount.unit) {
                return Err(usage(
                    "all portions of one cash leg must declare the same native unit",
                    SPLIT_POLICY_EXAMPLE,
                ));
            }
            leg_unit = Some(amount.unit);
            portions.push(CashFlowPortion {
                activity: parse_cash_flow_activity(&string(value, "activity")?)?,
                amount: amount.mantissa,
            });
        }
        let unit =
            leg_unit.ok_or_else(|| usage("cash split has no amount", SPLIT_POLICY_EXAMPLE))?;
        if leg_units.insert((entry_digest, leg_index), unit).is_some() {
            return Err(usage(
                "cash split repeats an original leg",
                SPLIT_POLICY_EXAMPLE,
            ));
        }
        splits.push(CashFlowLegSplit {
            entry_digest,
            leg_index,
            reason,
            portions,
        });
    }
    let definition = CashFlowSplitDefinition {
        name: base.name,
        cash_accounts: base.cash_accounts,
        splits,
    };
    // The existing definition codec enforces bounded reasons, unique activities
    // and strictly positive amounts before any native read or certificate write.
    definition.canonical_bytes()?;
    Ok(ParsedCashFlowSplits {
        definition,
        leg_units,
    })
}

pub(crate) fn cash_flow_split_rows_json(
    report: &fa::cash_flow_split::SplitCashFlow,
    units: &fa_money::UnitRegistry,
) -> Result<Vec<Json>, Fail> {
    let source_units = cash_flow_source_units(report.source())?;
    report
        .definition()
        .splits
        .iter()
        .map(|split| {
            let unit = *source_units
                .get(&(split.entry_digest, split.leg_index))
                .ok_or_else(|| {
                    cash_flow_split_source_refusal("cash split output has no cited native leg")
                })?;
            let portions = split
                .portions
                .iter()
                .map(|portion| {
                    Ok(obj(vec![
                        ("activity", s(cash_flow_activity_name(portion.activity))),
                        (
                            "amount",
                            s(render_amount(Amount::new(unit, portion.amount), units)?),
                        ),
                    ]))
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            Ok(obj(vec![
                ("entry_digest", s(hex(&split.entry_digest))),
                ("leg_index", Json::Int(i128::from(split.leg_index))),
                ("reason", s(&split.reason)),
                ("portions", Json::Arr(portions)),
            ]))
        })
        .collect()
}

const RULES_POLICY_EXAMPLE: &str = r#"{"name":"cash-rules-v1","cash_accounts":["1000"],"account_rules":[{"account":"4000","activity":"operating"}],"overrides":[]}"#;

/// A rule policy (fa-i9yn) is its own format: `account_rules` classify non-cash
/// counterpart accounts and `overrides` fix whole cash legs. The direct and
/// indirect formats refuse `account_rules`; this one refuses their fields.
pub(crate) fn validate_cash_flow_rules_policy_fields(
    doc: &Json,
    indirect: bool,
) -> Result<(), Fail> {
    if indirect {
        return Err(usage(
            "account_rules policies classify direct cash flow; --indirect takes explicit assignments and adjustments",
            "drop --indirect, or pass an indirect policy with assignments and adjustments",
        ));
    }
    let check = |value: &Json, allowed: &[&str], context: &str| -> Result<(), Fail> {
        let Json::Obj(fields) = value else {
            return Err(usage(
                format!("{context} must be a JSON object"),
                RULES_POLICY_EXAMPLE,
            ));
        };
        for (field, _) in fields {
            if !allowed.contains(&field.as_str()) {
                return Err(usage(
                    format!("unknown {context} field '{field}'"),
                    RULES_POLICY_EXAMPLE,
                ));
            }
        }
        Ok(())
    };
    check(
        doc,
        &["name", "cash_accounts", "account_rules", "overrides"],
        "cash-flow rule policy",
    )?;
    for (field, allowed) in [
        ("account_rules", &["account", "activity"][..]),
        ("overrides", &["entry_digest", "leg_index", "activity"][..]),
    ] {
        let Some(value) = doc.get(field) else {
            continue;
        };
        let Json::Arr(items) = value else {
            return Err(usage(
                format!("cash-flow rule policy '{field}' must be an array"),
                RULES_POLICY_EXAMPLE,
            ));
        };
        for (index, item) in items.iter().enumerate() {
            check(item, allowed, &format!("{field}[{index}]"))?;
        }
    }
    Ok(())
}

pub(crate) fn parse_cash_flow_rules_policy(
    doc: &Json,
    book_id: Id128,
    default_accounts: &[VId],
    default_name: &str,
) -> Result<fa::cash_flow_policy::CashFlowPolicy, Fail> {
    // Name and cash accounts parse exactly as a direct policy's do; the
    // validator has already refused `assignments` in this format.
    let direct = parse_cash_flow_definition(doc, book_id, default_accounts, default_name)?;
    let Some(Json::Arr(items)) = doc.get("account_rules") else {
        return Err(usage(
            "a rule policy requires an `account_rules` array",
            RULES_POLICY_EXAMPLE,
        ));
    };
    let account_rules = items
        .iter()
        .map(|item| {
            let Some(Json::Str(code)) = item.get("account") else {
                return Err(usage(
                    "account rule requires string `account` (a non-cash posting account code)",
                    RULES_POLICY_EXAMPLE,
                ));
            };
            let account_id = if code.len() == 32 && code.bytes().all(|b| b.is_ascii_hexdigit()) {
                u128::from_str_radix(code, 16)
                    .map_err(|_| usage("invalid 32-hex account vid", RULES_POLICY_EXAMPLE))?
            } else {
                account_vid(book_id, code).0
            };
            let Some(Json::Str(activity)) = item.get("activity") else {
                return Err(usage(
                    "account rule requires string `activity`",
                    r#""activity":"operating|investing|financing|exchange_effect""#,
                ));
            };
            Ok(fa::cash_flow_policy::CashFlowAccountRule {
                account_id,
                activity: parse_cash_flow_activity(activity)?,
            })
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    Ok(fa::cash_flow_policy::CashFlowPolicy {
        name: direct.name,
        cash_accounts: direct.cash_accounts,
        account_rules,
        overrides: parse_cash_flow_assignments(doc.get("overrides"), "override")?,
    })
}

pub(crate) fn parse_indirect_cash_flow_definition(
    doc: &Json,
    default_name: &str,
) -> Result<(String, IndirectCashFlowDefinition), Fail> {
    let Json::Obj(fields) = doc else {
        return Err(usage(
            "indirect cash-flow policy must be a JSON object",
            r#"{"name":"indirect-v1","assignments":[...],"adjustments":[...]}"#,
        ));
    };
    let get = |k: &str| fields.iter().find(|(name, _)| name == k).map(|(_, v)| v);
    let name = match get("name") {
        Some(Json::Str(s)) => s.clone(),
        None => default_name.to_string(),
        _ => {
            return Err(usage(
                "policy `name` must be a string",
                r#"{"name":"indirect-v1"}"#,
            ));
        }
    };
    let cash_policy = match get("cash_policy") {
        Some(Json::Str(s)) => s.clone(),
        None => name.clone(),
        _ => {
            return Err(usage(
                "policy `cash_policy` must be a string",
                r#"{"cash_policy":"direct-v1"}"#,
            ));
        }
    };
    let adjustments = match get("adjustments") {
        None => Vec::new(),
        Some(Json::Arr(items)) => items
            .iter()
            .map(|item| {
                let Json::Obj(af) = item else {
                    return Err(usage(
                        "each adjustment must be a JSON object",
                        r#"{"entry_digest":"...","leg_index":0,"category":"non_cash","sign":"debit_minus_credit","reason":"..."}"#,
                    ));
                };
                let aget = |k: &str| af.iter().find(|(n, _)| n == k).map(|(_, v)| v);
                let Some(Json::Str(digest_hex)) = aget("entry_digest") else {
                    return Err(usage(
                        "adjustment requires string `entry_digest`",
                        r#"{"entry_digest":"<64-hex>","leg_index":0,"category":"non_cash","sign":"debit_minus_credit","reason":"..."}"#,
                    ));
                };
                let entry_digest = parse_digest32(digest_hex, "adjustment.entry_digest")?;
                let Some(Json::Int(leg_idx)) = aget("leg_index") else {
                    return Err(usage(
                        "adjustment requires integer `leg_index`",
                        r#""leg_index":0"#,
                    ));
                };
                let leg_index = u32::try_from(*leg_idx).map_err(|_| {
                    usage("adjustment `leg_index` must fit in u32", r#""leg_index":0"#)
                })?;
                let Some(Json::Str(cat)) = aget("category") else {
                    return Err(usage(
                        "adjustment requires string `category`",
                        r#""category":"non_cash|working_capital|non_operating""#,
                    ));
                };
                let category = match cat.as_str() {
                    "non_cash" | "NonCash" => AdjustmentCategory::NonCash,
                    "working_capital" | "WorkingCapital" => AdjustmentCategory::WorkingCapital,
                    "non_operating" | "NonOperating" => AdjustmentCategory::NonOperating,
                    other => {
                        return Err(usage(
                            format!("unknown adjustment category `{other}`"),
                            "use non_cash, working_capital, or non_operating",
                        ));
                    }
                };
                let Some(Json::Str(sgn)) = aget("sign") else {
                    return Err(usage(
                        "adjustment requires string `sign`",
                        r#""sign":"debit_minus_credit|credit_minus_debit""#,
                    ));
                };
                let sign = match sgn.as_str() {
                    "debit_minus_credit" | "DebitMinusCredit" => AdjustmentSign::DebitMinusCredit,
                    "credit_minus_debit" | "CreditMinusDebit" => AdjustmentSign::CreditMinusDebit,
                    other => {
                        return Err(usage(
                            format!("unknown adjustment sign `{other}`"),
                            "use debit_minus_credit or credit_minus_debit",
                        ));
                    }
                };
                let Some(Json::Str(reason)) = aget("reason") else {
                    return Err(usage(
                        "adjustment requires string `reason`",
                        r#""reason":"depreciation expense""#,
                    ));
                };
                Ok(IndirectCashFlowAdjustment {
                    entry_digest,
                    leg_index,
                    category,
                    sign,
                    reason: reason.clone(),
                })
            })
            .collect::<Result<_, Fail>>()?,
        _ => {
            return Err(usage(
                "`adjustments` must be an array",
                r#""adjustments":[...]"#,
            ));
        }
    };
    Ok((
        cash_policy,
        IndirectCashFlowDefinition { name, adjustments },
    ))
}

/// Admit certification before observing report inputs or an external output
/// path. Retention repeats the native authority checks at publication; this
/// preflight never reserves authority or creates an empty output artifact.
fn gl_certificate_preflight(
    book: &Book,
    files: &Files,
    args: &Args,
    capability: &Capability,
) -> Result<(), Fail> {
    fa_policy::admit_read(capability, capability.holder(), book.context().book_id)
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .and_then(|()| {
            fa_policy::require(
                capability,
                fa_policy::Op::Produce,
                "certifying and retaining a general-ledger report",
            )
        })
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    book.read_scope(capability.holder(), capability)??;
    if let Some(path) = args.flag("--certificate-out") {
        if path.is_empty() || path == "-" {
            return Err(usage(
                "--certificate-out names a new file; - is not an output file",
                "use --certify to receive the complete certificate as hex on stdout",
            ));
        }
        match std::fs::symlink_metadata(files.resolve(path)) {
            Ok(_) => {
                return Err(usage(
                    format!("certificate output {path} already exists"),
                    "choose a new --certificate-out path; an existing file is never overwritten",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(usage(
                    format!("cannot inspect certificate output {path}: {error}"),
                    "choose a new --certificate-out path in a writable directory",
                ));
            }
        }
    }
    Ok(())
}

fn aging_bands_json(bands: &[fa::AgingBand]) -> Vec<Json> {
    bands
        .iter()
        .map(|b| {
            obj(vec![
                ("lower_inclusive", Json::Int(i128::from(b.lower_inclusive))),
                (
                    "upper_inclusive",
                    b.upper_inclusive
                        .map_or(Json::Null, |u| Json::Int(i128::from(u))),
                ),
            ])
        })
        .collect()
}

/// One row per native unit, shared by the single-leaf and portfolio events.
fn aging_reconciliation_rows(
    rec: &fa::AgingReconciliation,
    units: &fa_money::UnitRegistry,
) -> Result<Vec<Json>, Fail> {
    rec.rows()
        .iter()
        .map(|r| {
            let unit_code = registered_unit_code(fa_money::UnitId(r.unit_id), units)?.to_string();
            let fmt = |m: i128| render_amount(Amount::new(fa_money::UnitId(r.unit_id), m), units);
            Ok(obj(vec![
                ("unit", s(&unit_code)),
                ("posted_debits", s(fmt(r.posted_debits)?)),
                ("posted_credits", s(fmt(r.posted_credits)?)),
                ("pending_debits", s(fmt(r.pending_debits)?)),
                ("pending_credits", s(fmt(r.pending_credits)?)),
                ("open_debits", s(fmt(r.open_debits)?)),
                ("open_credits", s(fmt(r.open_credits)?)),
                ("open_item_count", Json::Int(i128::from(r.open_item_count))),
                ("posted_net", s(fmt(r.posted_net)?)),
                ("open_net", s(fmt(r.open_net)?)),
                ("difference", s(fmt(r.difference)?)),
            ]))
        })
        .collect()
}

const AGING_SOURCES_EXAMPLE: &str = "fa gl aging --from-source C:<open-items-oid> --as-of YYYY-MM-DD --certify --json, or fa gl aging --reconcile --account <code> --as-of YYYY-MM-DD --as-known-at <seq> --aging-certificate C:<oid> --control-certificate C:<tb-as-of-oid> --certify --json";

/// `--from-source`, then the `--aging-certificate`/`--control-certificate` pair.
type AgingSources<'a> = (Option<&'a str>, Option<(&'a str, &'a str)>);

/// `gl aging` from saved certificates: `--from-source` ages one retained
/// open-items certificate; `--aging-certificate` with `--control-certificate`
/// reconciles (one leaf or a portfolio) from retained aging and as-of trial
/// balance certificates. The other flags state the recipient's question, and
/// each source is reused byte-for-byte, so each form certifies.
fn aging_source_flags(
    args: &Args,
    certify: bool,
    reconcile: bool,
) -> Result<AgingSources<'_>, Fail> {
    for flag in [
        "--from-source",
        "--aging-certificate",
        "--control-certificate",
    ] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("{flag} may be supplied only once"),
                AGING_SOURCES_EXAMPLE,
            ));
        }
    }
    let from_source = args.flag("--from-source");
    let saved_pair = match (
        args.flag("--aging-certificate"),
        args.flag("--control-certificate"),
    ) {
        (None, None) => None,
        (Some(aging), Some(control)) => Some((aging, control)),
        _ => {
            return Err(usage(
                "a reconciliation from saved sources needs both --aging-certificate and --control-certificate",
                AGING_SOURCES_EXAMPLE,
            ));
        }
    };
    if from_source.is_none() && saved_pair.is_none() {
        return Ok((None, None));
    }
    if !certify {
        return Err(usage(
            "aging from saved certificates retains a new certificate over them; add --certify or --certificate-out",
            AGING_SOURCES_EXAMPLE,
        ));
    }
    if from_source.is_some() && (reconcile || saved_pair.is_some()) {
        return Err(usage(
            "--from-source ages one saved open-items certificate; a reconciliation takes --aging-certificate and --control-certificate",
            AGING_SOURCES_EXAMPLE,
        ));
    }
    if saved_pair.is_some() && !reconcile {
        return Err(usage(
            "--aging-certificate and --control-certificate are the sources of --reconcile",
            AGING_SOURCES_EXAMPLE,
        ));
    }
    if from_source.is_some() && args.flag("--as-known-at").is_some() {
        return Err(usage(
            "--from-source fixes the recorded prefix; --as-known-at does not select it",
            AGING_SOURCES_EXAMPLE,
        ));
    }
    if saved_pair.is_some()
        && args
            .flag("--as-known-at")
            .and_then(|seq| seq.parse::<u64>().ok())
            .is_none()
    {
        return Err(usage(
            "a reconciliation from saved sources states the recipient's fixed --as-known-at <seq>, never HEAD or an instant",
            AGING_SOURCES_EXAMPLE,
        ));
    }
    if saved_pair == Some(("-", "-")) {
        return Err(usage(
            "only one certificate can arrive on stdin",
            "pass the other certificate as its C:<oid> or its saved file",
        ));
    }
    Ok((from_source, saved_pair))
}

/// `gl aging --reconcile` over every posting leaf or a selected list: one
/// chart, one whole-book aging fold and one control trial balance at a single
/// coordinate (plan §5.6–§5.7). Unselected leaves are listed as uncovered,
/// never printed as zero. This is an internal consistency report, not a close
/// permit or an external subledger attestation. With `saved`, the aging and
/// control sources are retained certificates reused byte-for-byte.
#[allow(clippy::too_many_arguments)]
fn gl_aging_portfolio(
    out: &Out,
    files: &Files,
    args: &Args,
    book: &mut Book,
    who: VId,
    capability: &Capability,
    certify: bool,
    request: AgingPortfolioRequest,
    saved: Option<&(fa::AgingCertificate, fa::ReportCertificate)>,
) -> Result<(), Fail> {
    let (portfolio, artifact) = if let Some((aging, control)) = saved {
        let certified =
            book.certify_aging_portfolio_from_sources(who, capability, aging, control, &request)??;
        let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
        (certified.report, Some(artifact))
    } else if certify {
        let certified = book.certify_aging_portfolio(who, capability, &request)??;
        let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
        (certified.report, Some(artifact))
    } else {
        (
            book.reconcile_aging_portfolio(who, capability, &request)??,
            None,
        )
    };
    // The library resolves HEAD once and orders a selection before reading;
    // the replay expectation carries that normalized request.
    let request = portfolio.request().clone();
    let known_at = request.known_at.ok_or_else(|| {
        Fail::Internal("an aging portfolio was returned without its fixed recorded sequence".into())
    })?;
    out.known_at(known_at);
    let units = &book.context().units;
    let accounts = portfolio
        .accounts()
        .iter()
        .map(|rec| {
            Ok(obj(vec![
                ("account", s(&rec.account().code)),
                ("account_vid", s(format!("{:032x}", rec.account().vid.0))),
                ("name", s(&rec.account().name)),
                ("reconciled", Json::Bool(rec.is_reconciled())),
                ("rows", Json::Arr(aging_reconciliation_rows(rec, units)?)),
                ("item_count", Json::Int(rec.aging().items.len() as i128)),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let uncovered: Vec<Json> = portfolio
        .uncovered_accounts()
        .iter()
        .map(|row| {
            obj(vec![
                ("account", s(&row.code)),
                ("account_vid", s(format!("{:032x}", row.vid.0))),
                ("name", s(&row.name)),
            ])
        })
        .collect();
    let mut human = format!(
        "aging portfolio as of {} at sequence {}: {} accounts, reconciled={}, complete={}, pending_reservations={}",
        request.effective_through.render(),
        known_at.0,
        portfolio.accounts().len(),
        portfolio.is_reconciled(),
        portfolio.is_complete(),
        portfolio.has_pending_reservations(),
    );
    for rec in portfolio.accounts() {
        human.push_str(&format!(
            "\n  {} {}: reconciled={}",
            rec.account().code,
            rec.account().name,
            rec.is_reconciled()
        ));
    }
    for row in portfolio.uncovered_accounts() {
        human.push_str(&format!("\n  {} {}: not selected", row.code, row.name));
    }
    let scope = match &request.scope {
        AgingAccountScope::AllPosting => "all-posting",
        AgingAccountScope::Selected(_) => "selected",
    };
    let retained = artifact
        .as_ref()
        .map(|artifact| {
            notary::retain_report_artifact_for(
                book,
                files,
                args,
                artifact,
                capability,
                fa::ReportArtifactExpectation::AgingPortfolio(&request),
            )
        })
        .transpose()?;
    let digest = artifact.as_ref().map(|artifact| hex(artifact.digest()));
    out.event_with_certificate(
        "aging_portfolio_reconciled",
        vec![
            ("scope", s(scope)),
            ("known_at", Json::Int(i128::from(known_at.0))),
            ("effective_through", s(request.effective_through.render())),
            ("reconciled", Json::Bool(portfolio.is_reconciled())),
            ("complete", Json::Bool(portfolio.is_complete())),
            (
                "pending_reservations",
                Json::Bool(portfolio.has_pending_reservations()),
            ),
            ("accounts", Json::Arr(accounts)),
            ("uncovered", Json::Arr(uncovered)),
            (
                "bands",
                Json::Arr(aging_bands_json(&request.buckets.bands())),
            ),
        ],
        &human,
        digest.as_deref(),
    );
    if let (Some(artifact), Some((bytes, retained))) = (artifact.as_ref(), retained) {
        notary::emit_report_artifact_for(
            out,
            args,
            artifact,
            "fa:aging-portfolio:v1",
            &bytes,
            &retained,
            &notary::portfolio_expectation_json(&request),
        );
    }
    Ok(())
}

/// One `cash_flow_unit` row per native unit, shared by direct, policy and split cash flow.
fn cash_flow_units_json(
    cash_units: &[fa::CashFlowUnit],
    units: &fa_money::UnitRegistry,
) -> Result<Vec<Json>, Fail> {
    let section_json = |sec: CashFlowSection, unit_id: u32| -> Result<Json, Fail> {
        let fmt = |m: i128| render_amount(Amount::new(fa_money::UnitId(unit_id), m), units);
        Ok(obj(vec![
            ("inflows", s(fmt(sec.inflows)?)),
            ("outflows", s(fmt(sec.outflows)?)),
            ("net", s(fmt(sec.net)?)),
        ]))
    };
    cash_units
        .iter()
        .map(|u| {
            let unit_code = registered_unit_code(fa_money::UnitId(u.unit_id), units)?.to_string();
            let fmt = |m: i128| render_amount(Amount::new(fa_money::UnitId(u.unit_id), m), units);
            Ok(obj(vec![
                ("unit", s(&unit_code)),
                ("opening", s(fmt(u.opening)?)),
                ("operating", section_json(u.operating, u.unit_id)?),
                ("investing", section_json(u.investing, u.unit_id)?),
                ("financing", section_json(u.financing, u.unit_id)?),
                (
                    "exchange_effects",
                    section_json(u.exchange_effects, u.unit_id)?,
                ),
                ("net_change", s(fmt(u.net_change)?)),
                ("closing", s(fmt(u.closing)?)),
            ]))
        })
        .collect()
}

/// `gl cash-flow` with a rule policy (fa-i9yn): each selected cash leg's
/// activity derives from its non-cash counterparts' account rules, or from an
/// explicit whole-leg override, and the original cash engine then classifies
/// it. No amount is split, netted or inferred; `decisions` records the basis
/// of every leg. The policy is a professional input, not approved or journaled.
#[allow(clippy::too_many_arguments)]
fn gl_policy_cash_flow(
    out: &Out,
    files: &Files,
    args: &Args,
    book: &mut Book,
    who: VId,
    capability: &Capability,
    certify: bool,
    mut request: RollForwardRequest,
    policy: fa::cash_flow_policy::CashFlowPolicy,
) -> Result<(), Fail> {
    let (report, artifact) = if certify {
        let certified =
            book.certify_cash_flow_with_policy(who, capability, &request, &policy)??;
        request.known_at = Some(certified.certificate().known_at());
        let artifact = fa::ReportArtifact::try_from(certified.certificate())?;
        (certified.report().clone(), Some(artifact))
    } else {
        (
            book.cash_flow_with_policy(who, capability, &request, &policy)??,
            None,
        )
    };
    // The certificate binds the policy the report carries.
    let policy = report.policy().clone();
    let cf = report.report();
    let source = cf.source();
    out.known_at(source.known_at());
    let units = &book.context().units;
    let cash_accounts: Vec<Json> = source.accounts().iter().map(|a| s(&a.code)).collect();
    let unit_rows = cash_flow_units_json(cf.units(), units)?;
    let decisions: Vec<Json> = report
        .decisions()
        .iter()
        .map(|decision| {
            obj(vec![
                ("entry_digest", s(hex(&decision.entry_digest))),
                ("leg_index", Json::Int(i128::from(decision.leg_index))),
                ("activity", s(cash_flow_activity_name(decision.activity))),
                (
                    "basis",
                    s(match decision.basis {
                        fa::cash_flow_policy::CashFlowDecisionBasis::AccountRules => {
                            "account_rules"
                        }
                        fa::cash_flow_policy::CashFlowDecisionBasis::ExplicitOverride => "override",
                        fa::cash_flow_policy::CashFlowDecisionBasis::InternalTransfer => {
                            "internal_transfer"
                        }
                    }),
                ),
            ])
        })
        .collect();
    let human = format!(
        "policy cash flow `{}` ({}..={}): {} unit(s), {} cash leg decision(s)",
        policy.name,
        source.effective_from().render(),
        source.effective_through().render(),
        cf.units().len(),
        report.decisions().len()
    );
    let retained = artifact
        .as_ref()
        .map(|artifact| {
            notary::retain_report_artifact_for(
                book,
                files,
                args,
                artifact,
                capability,
                fa::ReportArtifactExpectation::PolicyCashFlow {
                    request: &request,
                    policy: &policy,
                },
            )
        })
        .transpose()?;
    let digest = artifact.as_ref().map(|artifact| hex(artifact.digest()));
    out.event_with_certificate(
        "policy_cash_flow",
        vec![
            ("policy", s(&policy.name)),
            ("label", s(source.label())),
            ("known_at", Json::Int(i128::from(source.known_at().0))),
            ("effective_from", s(source.effective_from().render())),
            ("effective_through", s(source.effective_through().render())),
            ("cash_accounts", Json::Arr(cash_accounts)),
            ("units", Json::Arr(unit_rows)),
            ("decisions", Json::Arr(decisions)),
        ],
        &human,
        digest.as_deref(),
    );
    if let (Some(artifact), Some((bytes, retained))) = (artifact.as_ref(), retained) {
        notary::emit_report_artifact_for(
            out,
            args,
            artifact,
            "fa:policy-cash-flow:v1",
            &bytes,
            &retained,
            &notary::policy_cash_flow_expectation_json(&request, &policy),
        );
    }
    Ok(())
}

/// An explicit split policy classifies portions of original cash legs. Resolve
/// HEAD once, validate every supplied currency against that admitted native
/// source, then use the same fixed prefix for computation and certification.
#[allow(clippy::too_many_arguments)]
fn gl_split_cash_flow(
    out: &Out,
    files: &Files,
    args: &Args,
    book: &mut Book,
    who: VId,
    capability: &Capability,
    certify: bool,
    mut request: RollForwardRequest,
    parsed: ParsedCashFlowSplits,
) -> Result<(), Fail> {
    let source = book.general_ledger(who, capability, &request)??;
    request.known_at = Some(source.known_at());
    let definition = parsed.bind_to_source(&source)?;
    drop(source);
    let (report, artifact) = if certify {
        let certified = book.certify_cash_flow_split(who, capability, &request, &definition)??;
        let artifact = fa::ReportArtifact::try_from(certified.certificate())?;
        (certified.report().clone(), Some(artifact))
    } else {
        (
            book.read_split_cash_flow(who, capability, &request, &definition)??,
            None,
        )
    };
    let source = report.source();
    out.known_at(source.known_at());
    let units = &book.context().units;
    let unit_rows = cash_flow_units_json(report.units(), units)?;
    let split_rows = cash_flow_split_rows_json(&report, units)?;
    let cash_accounts = source
        .accounts()
        .iter()
        .map(|account| s(&account.code))
        .collect();
    // Formatting a replay expectation also checks its 1 MiB transport bound.
    // This must happen before retention or creation of a certificate file.
    let expected = artifact
        .as_ref()
        .map(|_| notary::split_cash_flow_expectation_json(&request, &report, units))
        .transpose()?;
    let human = format!(
        "split cash flow `{}` ({}..={}): {} unit(s), {} original cash leg split(s)",
        report.definition().name,
        source.effective_from().render(),
        source.effective_through().render(),
        report.units().len(),
        report.definition().splits.len(),
    );
    let retained = artifact
        .as_ref()
        .map(|artifact| {
            notary::retain_report_artifact_for(
                book,
                files,
                args,
                artifact,
                capability,
                fa::ReportArtifactExpectation::SplitCashFlow {
                    request: &request,
                    definition: report.definition(),
                },
            )
        })
        .transpose()?;
    let digest = artifact.as_ref().map(|artifact| hex(artifact.digest()));
    out.event_with_certificate(
        "split_cash_flow",
        vec![
            ("policy", s(&report.definition().name)),
            ("label", s(source.label())),
            ("known_at", Json::Int(i128::from(source.known_at().0))),
            ("effective_from", s(source.effective_from().render())),
            ("effective_through", s(source.effective_through().render())),
            ("cash_accounts", Json::Arr(cash_accounts)),
            ("units", Json::Arr(unit_rows)),
            ("splits", Json::Arr(split_rows)),
        ],
        &human,
        digest.as_deref(),
    );
    if let (Some(artifact), Some((bytes, retained)), Some(expected)) =
        (artifact.as_ref(), retained, expected.as_ref())
    {
        notary::emit_report_artifact_for(
            out,
            args,
            artifact,
            fa::cash_flow_split::CASH_FLOW_SPLIT_FORMAT,
            &bytes,
            &retained,
            expected,
        );
    }
    Ok(())
}

fn gl_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.flag_all("--certificate-out").len() > 1 {
        return Err(usage(
            "--certificate-out may be supplied only once",
            "use --certify or --certificate-out <new-file>",
        ));
    }
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    let sub = args.positional.get(1).map(String::as_str);
    // The saved-source flags are gl aging's; any other subcommand would fold
    // afresh and silently ignore the source, so they are refused there.
    if sub != Some("aging")
        && let Some(flag) = [
            "--from-source",
            "--aging-certificate",
            "--control-certificate",
        ]
        .into_iter()
        .find(|flag| args.flag(flag).is_some())
    {
        return Err(usage(
            format!("{flag} is a saved source of gl aging, not of this subcommand"),
            AGING_SOURCES_EXAMPLE,
        ));
    }
    if certify && !matches!(sub, Some("detail" | "roll-forward" | "aging" | "cash-flow")) {
        return Err(usage(
            "certification is available for gl detail, roll-forward, aging, and cash-flow",
            "use gl detail|roll-forward|aging|cash-flow --certify",
        ));
    }
    let who = ctx.principal(args);
    let capability = ctx.capability(
        args,
        if certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    let out = &ctx.out;
    let admit_report = |book: &mut Book| -> Result<(), Fail> {
        if certify {
            gl_certificate_preflight(book, &ctx.files, args, &capability)?;
        } else if matches!(sub, Some("detail" | "roll-forward")) {
            // These plain reports read one complete recorded prefix before
            // projecting their account/date selection. Admit that prefix,
            // never the selected output rows, and keep all non-temporal
            // scopes fail-closed. Instant resolution still needs head access.
            book.read_scope(who, &capability)??;
            let (known_at, _) = known_at_read_flag(args, book, out, &capability)?;
            book.prepare_report_history(who, &capability, known_at)??;
            return Ok(());
        } else {
            fa_policy::admit_read(&capability, who, book.context().book_id)
                .and_then(|()| {
                    fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None)
                })
                .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
            book.read_scope(who, &capability)??;
        }
        book.prepare_report_history(who, &capability, None)??;
        Ok(())
    };
    match sub {
        Some("detail") => {
            if args.positional.len() != 2 {
                return Err(usage(
                    "unexpected gl detail argument",
                    "fa gl detail --account <code> --from YYYY-MM-DD --to YYYY-MM-DD --book <dir>",
                ));
            }
            let mut book = ctx.books.open_admitted(args, admit_report)?;
            let req = parse_gl_scope(
                args,
                &book,
                &capability,
                out,
                "gl-detail",
                "fa gl detail --account 1000 --from 2026-03-01 --to 2026-03-31 --book <dir>",
            )?;
            book.prepare_report_history(who, &capability, req.known_at)??;
            let (gl, artifact) = if certify {
                let certified = book.certify_general_ledger(who, &capability, &req)??;
                let artifact = fa::ReportArtifact::try_from(certified.source_certificate())?;
                (certified.report().clone(), Some(artifact))
            } else {
                (book.general_ledger(who, &capability, &req)??, None)
            };
            let presentation = general_ledger_presentation(&book, &gl)?;
            let replay_options = artifact
                .as_ref()
                .map(|_| notary::general_ledger_replay_options(&book, &gl))
                .transpose()?;
            let retained = artifact
                .as_ref()
                .map(|artifact| {
                    notary::retain_report_artifact(
                        &mut book,
                        &ctx.files,
                        args,
                        artifact,
                        &capability,
                    )
                })
                .transpose()?;
            let digest = artifact.as_ref().map(|artifact| hex(artifact.digest()));
            render_general_ledger(out, &gl, presentation, digest.as_deref());
            if let (Some(artifact), Some((bytes, retained)), Some(options)) =
                (artifact.as_ref(), retained, replay_options.as_deref())
            {
                // Detail is the deterministic view of this complete source,
                // not a newly invented general-ledger certificate format.
                notary::emit_general_ledger_certificate(
                    out, args, artifact, &bytes, &retained, options,
                );
            }
            Ok(())
        }
        Some("roll-forward") => {
            if args.positional.len() != 2 {
                return Err(usage(
                    "unexpected gl roll-forward argument",
                    "fa gl roll-forward --account <code> --from YYYY-MM-DD --to YYYY-MM-DD --book <dir>",
                ));
            }
            let mut book = ctx.books.open_admitted(args, admit_report)?;
            let req = parse_gl_scope(
                args,
                &book,
                &capability,
                out,
                "roll-forward",
                "fa gl roll-forward --account 1000 --from 2026-03-01 --to 2026-03-31 --book <dir>",
            )?;
            book.prepare_report_history(who, &capability, req.known_at)??;
            let (rf, artifact, replay_options) = if certify {
                let certified = book.certify_roll_forward(who, &capability, &req)??;
                let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
                let options = notary::roll_forward_replay_options(
                    &book,
                    &certified.certificate,
                    &certified.report,
                )?;
                (certified.report, Some(artifact), Some(options))
            } else {
                (book.roll_forward(who, &capability, &req)??, None, None)
            };
            out.known_at(CommitSeq(rf.known_at));
            let units = &book.context().units;
            let accounts_by_id: std::collections::BTreeMap<u128, _> =
                rf.accounts.iter().map(|a| (a.id, a)).collect();
            let buckets: Vec<Json> = rf
                .buckets
                .iter()
                .map(|b| {
                    obj(vec![
                        ("class", s(b.class.name().unwrap_or("unknown"))),
                        ("reason_code", s(&b.reason_code)),
                        (
                            "rule_digest",
                            b.rule_digest.as_ref().map_or(Json::Null, |d| s(hex(d))),
                        ),
                    ])
                })
                .collect();
            let rows: Vec<Json> = rf
                .rows
                .iter()
                .map(|row| {
                    let acc = accounts_by_id
                        .get(&row.account_id)
                        .ok_or_else(|| Fail::Internal("roll-forward row account missing".into()))?;
                    let unit_code =
                        registered_unit_code(fa_money::UnitId(row.unit_id), units)?.to_string();
                    let fmt = |m: i128| {
                        render_amount(Amount::new(fa_money::UnitId(row.unit_id), m), units)
                    };
                    let activity: Vec<Json> = row
                        .activity
                        .iter()
                        .map(|m| Ok(s(fmt(*m)?)))
                        .collect::<Result<_, Fail>>()?;
                    Ok(obj(vec![
                        ("account", s(&acc.code)),
                        ("account_vid", s(format!("{:032x}", row.account_id))),
                        ("name", s(&acc.name)),
                        (
                            "type",
                            s(AccountType(acc.account_type).name().unwrap_or("unknown")),
                        ),
                        ("unit", s(&unit_code)),
                        ("opening", s(fmt(row.opening)?)),
                        ("activity", Json::Arr(activity)),
                        ("net_change", s(fmt(row.net_change)?)),
                        ("closing", s(fmt(row.closing)?)),
                    ]))
                })
                .collect::<Result<_, Fail>>()?;
            let human = format!(
                "roll-forward `{}` ({}..={}): {} row(s), {} movement(s)",
                rf.label,
                rf.effective_from.render(),
                rf.effective_through.render(),
                rf.rows.len(),
                rf.movements.len()
            );
            let retained = artifact
                .as_ref()
                .map(|artifact| {
                    notary::retain_report_artifact(
                        &mut book,
                        &ctx.files,
                        args,
                        artifact,
                        &capability,
                    )
                })
                .transpose()?;
            let digest = artifact.as_ref().map(|artifact| hex(artifact.digest()));
            out.event_with_certificate(
                "roll_forward",
                vec![
                    ("label", s(&rf.label)),
                    ("known_at", Json::Int(i128::from(rf.known_at))),
                    ("effective_from", s(rf.effective_from.render())),
                    ("effective_through", s(rf.effective_through.render())),
                    ("buckets", Json::Arr(buckets)),
                    ("rows", Json::Arr(rows)),
                    ("movement_count", Json::Int(rf.movements.len() as i128)),
                ],
                &human,
                digest.as_deref(),
            );
            if let (Some(artifact), Some((bytes, retained)), Some(options)) =
                (artifact.as_ref(), retained, replay_options.as_deref())
            {
                notary::emit_general_ledger_certificate(
                    out, args, artifact, &bytes, &retained, options,
                );
            }
            Ok(())
        }
        Some("aging") => {
            // `fa aging ar|ap` (plan §15.3; fa-kxc4 roles): the one account
            // holding the receivable or payable role.
            let role = match args.positional.get(2).map(String::as_str) {
                Some("ar") => Some("receivable"),
                Some("ap") => Some("payable"),
                _ => None,
            };
            if args.positional.len() != 2 + usize::from(role.is_some()) {
                return Err(usage(
                    "unexpected gl aging argument",
                    "fa gl aging [ar | ap | --account <code[,code...]> | --all-posting] --as-of YYYY-MM-DD [--bucket <days>]... [--reconcile] --book <dir>",
                ));
            }
            if role.is_some()
                && (args.flag("--account").is_some()
                    || args.switch("--all-posting")
                    || args.switch("--reconcile")
                    || args.flag("--from-source").is_some())
            {
                return Err(usage(
                    "gl aging ar|ap names its account by role; it takes no --account, --all-posting, --reconcile or --from-source",
                    "fa aging ar --as-of YYYY-MM-DD, or fa gl aging --account <code> --as-of YYYY-MM-DD",
                ));
            }
            let mut book = ctx.books.open_admitted(args, admit_report)?;
            let as_of = args.require("--as-of", "YYYY-MM-DD")?;
            let day = DateDay::parse(as_of).map_err(|e| {
                usage(
                    format!("{e}; --as-of requires a civil date"),
                    "--as-of YYYY-MM-DD",
                )
            })?;
            let raw_buckets: Vec<&str> = args
                .flag_all("--bucket")
                .into_iter()
                .flat_map(|s| s.split(','))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            let buckets = if raw_buckets.is_empty() {
                AgingBuckets::thirty_day()
            } else {
                let bounds: Vec<u32> = raw_buckets
                    .into_iter()
                    .map(|b| {
                        b.parse::<u32>().map_err(|_| {
                            usage(
                                format!(
                                    "invalid aging bucket `{b}`: expected nonnegative integer days"
                                ),
                                "--bucket 0 --bucket 30 --bucket 60 --bucket 90",
                            )
                        })
                    })
                    .collect::<Result<_, Fail>>()?;
                AgingBuckets::new(bounds)
                    .map_err(|e| usage(e.to_string(), "--bucket 0 --bucket 30 --bucket 60"))?
            };
            // Every --account occurrence counts, as in the other gl subcommands:
            // repeated flags and comma lists both name several leaves.
            let account_codes: Vec<&str> = args
                .flag_all("--account")
                .into_iter()
                .flat_map(|codes| codes.split(','))
                .map(str::trim)
                .collect();
            let reconcile = args.switch("--reconcile");
            let (from_source, saved_pair) = aging_source_flags(args, certify, reconcile)?;
            if !reconcile && account_codes.len() > 1 {
                return Err(usage(
                    "gl aging ages one --account, or every account when --account is omitted",
                    "fa gl aging --account 1200 --as-of YYYY-MM-DD --book <dir>; to tie several leaves to their control balances add --reconcile",
                ));
            }
            let account = account_codes
                .first()
                .map(|code| account_vid(book.context().book_id, code));
            let known_at = gl_known_at(args, &book, out)?;
            let account = match role {
                None => account,
                Some(role) => {
                    let (at, roles) = book.account_roles(known_at, &capability)??;
                    let holders: Vec<fgdb_types::VId> =
                        roles.accounts_with(role).into_iter().collect();
                    match holders.as_slice() {
                        [only] => Some(*only),
                        [] => {
                            return Err(usage(
                                format!("no account holds the {role} role at sequence {}", at.0),
                                format!(
                                    "fa chart role <account> {role} assigns it (fa chart roles lists the roles), or age an account with --account <code>"
                                ),
                            ));
                        }
                        many => {
                            let mut codes: Vec<String> = book
                                .accounts_at(at, &capability)??
                                .into_iter()
                                .filter(|a| many.contains(&a.vid))
                                .map(|a| a.code)
                                .collect();
                            codes.sort();
                            return Err(usage(
                                format!(
                                    "{} accounts hold the {role} role ({})",
                                    codes.len(),
                                    codes.join(", ")
                                ),
                                format!(
                                    "age one with fa gl aging --account <code>, or tie them all with fa gl aging --account {} --reconcile",
                                    codes.join(",")
                                ),
                            ));
                        }
                    }
                }
            };
            book.prepare_report_history(who, &capability, known_at)??;
            // Saved certificates are read after admission, and their own
            // prefix is prepared before the library replays them.
            let saved = match saved_pair {
                Some((aging_value, control_value)) => {
                    let aging = notary::certificate_input(
                        &book,
                        &ctx.files,
                        "--aging-certificate",
                        aging_value,
                        who,
                        &capability,
                        fa::AgingCertificate::decode,
                    )?;
                    let control = notary::certificate_input(
                        &book,
                        &ctx.files,
                        "--control-certificate",
                        control_value,
                        who,
                        &capability,
                        fa::ReportCertificate::decode,
                    )?;
                    let prefix = aging.source().known_at.min(control.known_at);
                    book.prepare_report_history(who, &capability, Some(prefix))??;
                    Some((aging, control))
                }
                None => None,
            };
            let source = match from_source {
                Some(value) => {
                    let source = notary::certificate_input(
                        &book,
                        &ctx.files,
                        "--from-source",
                        value,
                        who,
                        &capability,
                        fa::ReportCertificate::decode,
                    )?;
                    // The saved open-items selection is the account; a stated
                    // --account is the recipient's question, never a re-selection.
                    if let (Some(stated), fa::ReportSelection::OpenItems { account: saved }) =
                        (account, &source.selection)
                        && *saved != Some(stated)
                    {
                        return Err(fa_journal::Refusal::new(
                            fa::certificate::code::CERTIFICATE_INVALID,
                            exit::VERIFICATION,
                            "the saved open-items certificate selects a different account than --account",
                            "plan §13.6 (a retained source answers only the question it was certified for)",
                            "pass the open-items certificate of the account you mean, or omit --account to accept its selection",
                        )
                        .into());
                    }
                    book.prepare_report_history(who, &capability, Some(source.known_at))??;
                    Some(source)
                }
                None => None,
            };
            out.effective(format!("as-of:{day}"));
            let units = &book.context().units;
            let all_posting = args.switch("--all-posting");
            if all_posting && !reconcile {
                return Err(usage(
                    "--all-posting selects the accounts of an aging reconciliation",
                    "fa gl aging --all-posting --as-of YYYY-MM-DD --reconcile --book <dir>",
                ));
            }
            if reconcile {
                // One code keeps the single-leaf report. Several codes, or the
                // explicit --all-posting, reconcile several leaves at one
                // coordinate. A missing selection is never read as the whole book.
                let acc_vid = match (account_codes.as_slice(), all_posting) {
                    ([code], false) => account_vid(book.context().book_id, code),
                    ([], false) => {
                        return Err(usage(
                            "--reconcile requires --account <code[,code...]> or --all-posting",
                            "fa gl aging --account 1200 --as-of YYYY-MM-DD --reconcile --book <dir> (one leaf); --account 1200,2100 or --all-posting reconciles several leaves at one coordinate",
                        ));
                    }
                    ([_, ..], true) => {
                        return Err(usage(
                            "--all-posting and --account are separate account selections",
                            "pass either --account <code[,code...]> or --all-posting",
                        ));
                    }
                    (codes, _) => {
                        let scope = if codes.is_empty() {
                            AgingAccountScope::AllPosting
                        } else {
                            if codes.iter().any(|code| code.is_empty()) {
                                return Err(usage(
                                    "--account lists posting account codes separated by commas",
                                    "fa gl aging --account 1200,2100 --as-of YYYY-MM-DD --reconcile --book <dir>",
                                ));
                            }
                            AgingAccountScope::Selected(
                                codes
                                    .iter()
                                    .map(|code| account_vid(book.context().book_id, code))
                                    .collect(),
                            )
                        };
                        let request = AgingPortfolioRequest {
                            scope,
                            effective_through: day,
                            known_at,
                            buckets,
                        };
                        return gl_aging_portfolio(
                            out,
                            &ctx.files,
                            args,
                            &mut book,
                            who,
                            &capability,
                            certify,
                            request,
                            saved.as_ref(),
                        );
                    }
                };
                let mut request = AgingReconciliationRequest {
                    account: acc_vid,
                    effective_through: day,
                    known_at,
                    buckets,
                };
                let (rec, artifact) = if let Some((aging, control)) = &saved {
                    let certified = book
                        .certify_effective_date_aging_reconciliation_from_sources(
                            who,
                            &capability,
                            aging,
                            control,
                            &request,
                        )??;
                    let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
                    (certified.report, Some(artifact))
                } else if certify {
                    let certified = book.certify_effective_date_aging_reconciliation(
                        who,
                        &capability,
                        &request,
                    )??;
                    request.known_at = Some(certified.report.known_at());
                    let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
                    (certified.report, Some(artifact))
                } else {
                    (
                        book.reconcile_effective_date_aging(who, &capability, &request)??,
                        None,
                    )
                };
                out.known_at(rec.known_at());
                let bands = aging_bands_json(&rec.aging().bands);
                let rows = aging_reconciliation_rows(&rec, units)?;
                let human = format!(
                    "aging reconciliation for {} ({}) as of {}: reconciled={}",
                    rec.account().code,
                    rec.account().name,
                    rec.effective_through().render(),
                    rec.is_reconciled()
                );
                let retained = artifact
                    .as_ref()
                    .map(|artifact| {
                        notary::retain_report_artifact_for(
                            &mut book,
                            &ctx.files,
                            args,
                            artifact,
                            &capability,
                            fa::ReportArtifactExpectation::AgingReconciliation(&request),
                        )
                    })
                    .transpose()?;
                let digest = artifact.as_ref().map(|artifact| hex(artifact.digest()));
                out.event_with_certificate(
                    "aging_reconciled",
                    vec![
                        ("account", s(&rec.account().code)),
                        ("account_vid", s(format!("{:032x}", rec.account().vid.0))),
                        ("name", s(&rec.account().name)),
                        ("known_at", Json::Int(i128::from(rec.known_at().0))),
                        ("effective_through", s(rec.effective_through().render())),
                        ("reconciled", Json::Bool(rec.is_reconciled())),
                        ("rows", Json::Arr(rows)),
                        ("bands", Json::Arr(bands)),
                        ("item_count", Json::Int(rec.aging().items.len() as i128)),
                    ],
                    &human,
                    digest.as_deref(),
                );
                if let (Some(artifact), Some((bytes, retained))) = (artifact.as_ref(), retained) {
                    notary::emit_report_artifact_for(
                        out,
                        args,
                        artifact,
                        "fa:aging-control-reconciliation:v1",
                        &bytes,
                        &retained,
                        &notary::reconciliation_expectation_json(&request),
                    );
                }
                Ok(())
            } else {
                let (aging, artifact) = if let Some(source) = &source {
                    let certified = book.certify_effective_date_aging_from_source(
                        who,
                        &capability,
                        source,
                        day,
                        &buckets,
                    )??;
                    let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
                    let request = certified.certificate.request()?;
                    (certified.report, Some((artifact, request)))
                } else if certify {
                    let certified = book.certify_effective_date_aging(
                        who,
                        &capability,
                        &fa::AgingRequest {
                            account,
                            effective_through: day,
                            known_at,
                            buckets: buckets.clone(),
                        },
                    )??;
                    let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
                    // The receipt's replay_command carries the request the
                    // certificate binds, so a recipient can retain it apart.
                    let request = certified.certificate.request()?;
                    (certified.report, Some((artifact, request)))
                } else {
                    (
                        book.effective_date_aging(account, day, known_at, &buckets)?,
                        None,
                    )
                };
                let (artifact, aging_request) = artifact.unzip();
                out.known_at(aging.known_at);
                let chart = book.accounts()?;
                let accounts_by_vid: std::collections::BTreeMap<VId, String> = chart
                    .into_iter()
                    .filter(|r| r.created_at <= aging.known_at)
                    .map(|r| (r.vid, r.code))
                    .collect();
                if let Some(acc) = account
                    && !accounts_by_vid.contains_key(&acc)
                {
                    return Err(BookError::Registers(
                        fa_registers::RegisterError::InvalidSelection(format!(
                            "unknown account {:032x} at sequence {}",
                            acc.0, aging.known_at.0
                        )),
                    )
                    .into());
                }
                let code_of = |vid: VId| -> Result<&str, Fail> {
                    accounts_by_vid
                        .get(&vid)
                        .map(String::as_str)
                        .ok_or_else(|| {
                            Fail::Internal(format!("aging omits account {:032x}", vid.0))
                        })
                };
                let bands: Vec<Json> = aging
                    .bands
                    .iter()
                    .map(|b| {
                        obj(vec![
                            ("lower_inclusive", Json::Int(i128::from(b.lower_inclusive))),
                            (
                                "upper_inclusive",
                                b.upper_inclusive
                                    .map_or(Json::Null, |u| Json::Int(i128::from(u))),
                            ),
                        ])
                    })
                    .collect();
                let items: Vec<Json> = aging
                    .items
                    .iter()
                    .map(|aged| {
                        let i = &aged.item;
                        let fmt = |m: i128| {
                            render_amount(Amount::new(fa_money::UnitId(i.unit_id), m), units)
                        };
                        Ok(obj(vec![
                            ("entry", s(format!("{:032x}", i.entry.0))),
                            ("ordinal", Json::Int(i128::from(i.ordinal))),
                            ("account", s(code_of(i.account)?)),
                            (
                                "side",
                                s(if i.side == Side::Debit {
                                    "debit"
                                } else {
                                    "credit"
                                }),
                            ),
                            ("effective_date", s(i.effective_date.render())),
                            ("recorded_at", Json::Int(i128::from(i.recorded_at.0))),
                            ("original", s(fmt(i.original)?)),
                            ("applied", s(fmt(i.applied)?)),
                            ("applied_out", s(fmt(i.applied_out)?)),
                            ("open", s(fmt(i.open)?)),
                            ("age_days", Json::Int(i128::from(aged.age_days))),
                            ("bucket", Json::Int(aged.bucket as i128)),
                        ]))
                    })
                    .collect::<Result<_, Fail>>()?;
                let cells: Vec<Json> = aging
                    .cells
                    .iter()
                    .map(|c| {
                        let unit_code =
                            registered_unit_code(fa_money::UnitId(c.unit_id), units)?.to_string();
                        let fmt = |m: i128| {
                            render_amount(Amount::new(fa_money::UnitId(c.unit_id), m), units)
                        };
                        Ok(obj(vec![
                            ("account", s(code_of(c.account)?)),
                            ("unit", s(&unit_code)),
                            ("bucket", Json::Int(c.bucket as i128)),
                            ("debits", s(fmt(c.amounts.debits)?)),
                            ("credits", s(fmt(c.amounts.credits)?)),
                            ("item_count", Json::Int(i128::from(c.amounts.item_count))),
                        ]))
                    })
                    .collect::<Result<_, Fail>>()?;
                let totals: Vec<Json> = aging
                    .totals
                    .iter()
                    .map(|t| {
                        let unit_code =
                            registered_unit_code(fa_money::UnitId(t.unit_id), units)?.to_string();
                        let fmt = |m: i128| {
                            render_amount(Amount::new(fa_money::UnitId(t.unit_id), m), units)
                        };
                        Ok(obj(vec![
                            ("account", s(code_of(t.account)?)),
                            ("unit", s(&unit_code)),
                            ("debits", s(fmt(t.amounts.debits)?)),
                            ("credits", s(fmt(t.amounts.credits)?)),
                            ("item_count", Json::Int(i128::from(t.amounts.item_count))),
                        ]))
                    })
                    .collect::<Result<_, Fail>>()?;
                let human = format!(
                    "effective-date aging through {}: {} open item(s) across {} cell(s)",
                    aging.effective_through.render(),
                    aging.items.len(),
                    aging.cells.len()
                );
                let retained = artifact
                    .as_ref()
                    .map(|artifact| {
                        notary::retain_report_artifact(
                            &mut book,
                            &ctx.files,
                            args,
                            artifact,
                            &capability,
                        )
                    })
                    .transpose()?;
                let digest = artifact.as_ref().map(|artifact| hex(artifact.digest()));
                out.event_with_certificate(
                    "aging",
                    vec![
                        // The report's own selection: a saved open-items
                        // source fixes it even when no --account is stated.
                        (
                            "account",
                            aging
                                .account
                                .map(code_of)
                                .transpose()?
                                .map_or(Json::Null, s),
                        ),
                        ("known_at", Json::Int(i128::from(aging.known_at.0))),
                        ("effective_through", s(aging.effective_through.render())),
                        ("bands", Json::Arr(bands)),
                        ("items", Json::Arr(items)),
                        ("cells", Json::Arr(cells)),
                        ("totals", Json::Arr(totals)),
                    ],
                    &human,
                    digest.as_deref(),
                );
                if let (Some(artifact), Some((bytes, retained)), Some(request)) =
                    (artifact.as_ref(), retained, aging_request.as_ref())
                {
                    notary::emit_report_artifact_for(
                        out,
                        args,
                        artifact,
                        "fa:effective-date-aging:v1",
                        &bytes,
                        &retained,
                        &notary::aging_expectation_json(request),
                    );
                }
                Ok(())
            }
        }
        Some("cash-flow") => {
            if args.positional.len() != 2 {
                return Err(usage(
                    "unexpected gl cash-flow argument",
                    "fa gl cash-flow --account <code> --from YYYY-MM-DD --to YYYY-MM-DD --policy <file.json|-> --book <dir>",
                ));
            }
            let mut book = ctx.books.open_admitted(args, admit_report)?;
            let policy_path = args.require("--policy", "<policy.json|->")?;
            let policy_text = ctx.files.read_text(policy_path)?;
            let policy_doc = crate::json::parse(&policy_text).map_err(|e| {
                usage(
                    format!("invalid cash-flow policy JSON: {e}"),
                    "pass a valid JSON object for --policy",
                )
            })?;
            // Each richer policy format has an explicit selector. Its strict
            // parser rejects fields from the other formats rather than ignoring
            // a classification input supplied in the wrong shape.
            let splits = policy_doc.get("splits").is_some();
            let rules = policy_doc.get("account_rules").is_some();
            if splits {
                validate_cash_flow_split_policy_fields(&policy_doc, args.switch("--indirect"))?;
            } else if rules {
                validate_cash_flow_rules_policy_fields(&policy_doc, args.switch("--indirect"))?;
            } else {
                validate_cash_flow_policy_fields(&policy_doc, args.switch("--indirect"))?;
            }
            let mut req = parse_gl_scope(
                args,
                &book,
                &capability,
                out,
                "cash-flow",
                "fa gl cash-flow --account 1000 --from 2026-03-01 --to 2026-03-31 --policy policy.json --book <dir>",
            )?;
            book.prepare_report_history(who, &capability, req.known_at)??;
            let units = &book.context().units;
            if args.switch("--indirect") {
                let income_periods: Vec<String> = args
                    .flag_all("--income-period")
                    .into_iter()
                    .flat_map(|s| s.split(','))
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
                if income_periods.is_empty() {
                    return Err(usage(
                        "--indirect requires at least one --income-period <code>",
                        "fa gl cash-flow --indirect --income-period FY2026-P03 --account 1000 --from 2026-03-01 --to 2026-03-31 --policy policy.json --book <dir>",
                    ));
                }
                let (cash_policy_name, indirect_def) =
                    parse_indirect_cash_flow_definition(&policy_doc, "indirect-cash-flow")?;
                let mut cash_def = parse_cash_flow_definition(
                    &policy_doc,
                    book.context().book_id,
                    &req.accounts,
                    &cash_policy_name,
                )?;
                cash_def.name = cash_policy_name;
                let mut request = IndirectCashFlowRequest {
                    cash: req,
                    cash_definition: cash_def,
                    income_periods: income_periods.clone(),
                    definition: indirect_def,
                };
                let (report, artifact) = if certify {
                    let certified =
                        book.certify_indirect_cash_flow(who, &capability, &request)??;
                    request.cash.known_at = Some(certified.certificate().known_at());
                    let artifact = fa::ReportArtifact::try_from(certified.certificate())?;
                    (certified.report().clone(), Some(artifact))
                } else {
                    (book.indirect_cash_flow(who, &capability, &request)??, None)
                };
                let source = report.cash().source();
                out.known_at(source.known_at());
                let cash_accounts: Vec<Json> =
                    source.accounts().iter().map(|a| s(&a.code)).collect();
                let mut accounts_by_id: std::collections::BTreeMap<u128, String> = source
                    .accounts()
                    .iter()
                    .map(|a| (a.id, a.code.clone()))
                    .collect();
                if let Some(nc) = report.non_cash_source() {
                    for a in nc.accounts() {
                        accounts_by_id.entry(a.id).or_insert_with(|| a.code.clone());
                    }
                }
                let unit_rows: Vec<Json> = report
                    .units()
                    .iter()
                    .map(|u| {
                        let unit_code =
                            registered_unit_code(fa_money::UnitId(u.unit_id), units)?.to_string();
                        let fmt = |m: i128| {
                            render_amount(Amount::new(fa_money::UnitId(u.unit_id), m), units)
                        };
                        Ok(obj(vec![
                            ("unit", s(&unit_code)),
                            ("net_income", s(fmt(u.net_income)?)),
                            ("non_cash", s(fmt(u.non_cash)?)),
                            ("working_capital", s(fmt(u.working_capital)?)),
                            ("non_operating", s(fmt(u.non_operating)?)),
                            ("operating", s(fmt(u.operating)?)),
                            ("direct_operating", s(fmt(u.direct_operating)?)),
                            ("operating_residual", s(fmt(u.operating_residual)?)),
                            ("opening", s(fmt(u.opening)?)),
                            ("investing", s(fmt(u.investing)?)),
                            ("financing", s(fmt(u.financing)?)),
                            ("exchange_effects", s(fmt(u.exchange_effects)?)),
                            ("net_change", s(fmt(u.net_change)?)),
                            ("closing", s(fmt(u.closing)?)),
                        ]))
                    })
                    .collect::<Result<_, Fail>>()?;
                let contributions: Vec<Json> = report
                    .contributions()
                    .iter()
                    .map(|c| {
                        let unit_code =
                            registered_unit_code(fa_money::UnitId(c.unit_id), units)?.to_string();
                        let fmt = |m: i128| {
                            render_amount(Amount::new(fa_money::UnitId(c.unit_id), m), units)
                        };
                        let acc_code = accounts_by_id
                            .get(&c.account_id)
                            .cloned()
                            .unwrap_or_else(|| format!("{:032x}", c.account_id));
                        Ok(obj(vec![
                            ("entry_digest", s(hex(&c.entry_digest))),
                            ("leg_index", Json::Int(i128::from(c.leg_index))),
                            ("account", s(&acc_code)),
                            ("account_vid", s(format!("{:032x}", c.account_id))),
                            ("unit", s(&unit_code)),
                            ("amount", s(fmt(c.amount)?)),
                        ]))
                    })
                    .collect::<Result<_, Fail>>()?;
                let human = format!(
                    "indirect cash flow `{}` ({}..={}): {} unit(s), {} adjustment contribution(s)",
                    report.definition().name,
                    source.effective_from().render(),
                    source.effective_through().render(),
                    report.units().len(),
                    report.contributions().len()
                );
                let retained = artifact
                    .as_ref()
                    .map(|artifact| {
                        notary::retain_report_artifact_for(
                            &mut book,
                            &ctx.files,
                            args,
                            artifact,
                            &capability,
                            fa::ReportArtifactExpectation::IndirectCashFlow(&request),
                        )
                    })
                    .transpose()?;
                let digest = artifact.as_ref().map(|artifact| hex(artifact.digest()));
                out.event_with_certificate(
                    "indirect_cash_flow",
                    vec![
                        ("policy", s(&report.definition().name)),
                        ("cash_policy", s(&report.cash().definition().name)),
                        ("label", s(source.label())),
                        ("known_at", Json::Int(i128::from(source.known_at().0))),
                        ("effective_from", s(source.effective_from().render())),
                        ("effective_through", s(source.effective_through().render())),
                        (
                            "income_periods",
                            Json::Arr(income_periods.iter().map(s).collect()),
                        ),
                        ("cash_accounts", Json::Arr(cash_accounts)),
                        ("units", Json::Arr(unit_rows)),
                        ("contributions", Json::Arr(contributions)),
                    ],
                    &human,
                    digest.as_deref(),
                );
                if let (Some(artifact), Some((bytes, retained))) = (artifact.as_ref(), retained) {
                    notary::emit_report_artifact_for(
                        out,
                        args,
                        artifact,
                        fa::INDIRECT_CASH_FLOW_FORMAT,
                        &bytes,
                        &retained,
                        &notary::indirect_expectation_json(&request),
                    );
                }
                Ok(())
            } else if splits {
                let parsed = parse_cash_flow_splits(
                    &policy_doc,
                    book.context().book_id,
                    &req.accounts,
                    "cash-flow",
                    &book.context().units,
                )?;
                gl_split_cash_flow(
                    out,
                    &ctx.files,
                    args,
                    &mut book,
                    who,
                    &capability,
                    certify,
                    req,
                    parsed,
                )
            } else if rules {
                let policy = parse_cash_flow_rules_policy(
                    &policy_doc,
                    book.context().book_id,
                    &req.accounts,
                    "cash-flow",
                )?;
                gl_policy_cash_flow(
                    out,
                    &ctx.files,
                    args,
                    &mut book,
                    who,
                    &capability,
                    certify,
                    req,
                    policy,
                )
            } else {
                let cash_def = parse_cash_flow_definition(
                    &policy_doc,
                    book.context().book_id,
                    &req.accounts,
                    "cash-flow",
                )?;
                let (cf, artifact) = if certify {
                    let certified = book.certify_cash_flow(who, &capability, &req, &cash_def)??;
                    req.known_at = Some(certified.certificate().known_at());
                    let artifact = fa::ReportArtifact::try_from(certified.certificate())?;
                    (certified.report().clone(), Some(artifact))
                } else {
                    (book.cash_flow(who, &capability, &req, &cash_def)??, None)
                };
                let source = cf.source();
                out.known_at(source.known_at());
                let cash_accounts: Vec<Json> =
                    source.accounts().iter().map(|a| s(&a.code)).collect();
                let unit_rows = cash_flow_units_json(cf.units(), units)?;
                let human = format!(
                    "cash flow `{}` ({}..={}): {} unit(s)",
                    cf.definition().name,
                    source.effective_from().render(),
                    source.effective_through().render(),
                    cf.units().len()
                );
                let retained = artifact
                    .as_ref()
                    .map(|artifact| {
                        notary::retain_report_artifact_for(
                            &mut book,
                            &ctx.files,
                            args,
                            artifact,
                            &capability,
                            fa::ReportArtifactExpectation::CashFlow {
                                request: &req,
                                definition: &cash_def,
                            },
                        )
                    })
                    .transpose()?;
                let digest = artifact.as_ref().map(|artifact| hex(artifact.digest()));
                out.event_with_certificate(
                    "cash_flow",
                    vec![
                        ("policy", s(&cf.definition().name)),
                        ("label", s(source.label())),
                        ("known_at", Json::Int(i128::from(source.known_at().0))),
                        ("effective_from", s(source.effective_from().render())),
                        ("effective_through", s(source.effective_through().render())),
                        ("cash_accounts", Json::Arr(cash_accounts)),
                        ("units", Json::Arr(unit_rows)),
                    ],
                    &human,
                    digest.as_deref(),
                );
                if let (Some(artifact), Some((bytes, retained))) = (artifact.as_ref(), retained) {
                    notary::emit_report_artifact_for(
                        out,
                        args,
                        artifact,
                        fa::CASH_FLOW_FORMAT,
                        &bytes,
                        &retained,
                        &notary::cash_flow_expectation_json(&req, &cash_def),
                    );
                }
                Ok(())
            }
        }
        Some("lots") => {
            if args.positional.len() != 2 {
                return Err(usage(
                    "unexpected gl lots argument",
                    "fa gl lots --account <code> [--as-of YYYY-MM-DD] [--as-known-at HEAD|<seq>] [--relieve <amount> --law FIFO|LIFO|SpecificId|WeightedAverage] --book <dir>",
                ));
            }
            let account_code = args.require(
                "--account",
                "<code> (an AnyUnit lot-tracked account such as 1400)",
            )?;
            let mut book = ctx.books.open_admitted(args, admit_report)?;
            let account = account_vid(book.context().book_id, account_code);
            let effective_through = match args.flag("--as-of") {
                Some(as_of) => {
                    let day = DateDay::parse(as_of).map_err(|e| {
                        usage(
                            format!("{e}; --as-of requires a civil date"),
                            "--as-of YYYY-MM-DD",
                        )
                    })?;
                    out.effective(format!("as-of:{day}"));
                    Some(day)
                }
                None => None,
            };
            let (known_at, _) = known_at_flag(args, &book, out)?;
            book.prepare_report_history(who, &capability, known_at)??;
            let report = book.lots(account, effective_through, known_at)?;
            out.known_at(report.known_at);
            let units = &book.context().units;
            let base_unit_code = registered_unit_code(report.base_unit, units)?;

            let disposal_plan = if let Some(relieve_str) = args.flag("--relieve") {
                let quantity = Amount::parse(relieve_str, units).map_err(|e| {
                    usage(
                        format!("invalid --relieve amount `{relieve_str}`: {e}"),
                        "--relieve \"10.00000000 BTC\"",
                    )
                })?;
                let law_str = args.require("--law", "FIFO|LIFO|SpecificId|WeightedAverage")?;
                let law = fa_money::LotLaw::from_name(law_str).ok_or_else(|| {
                    usage(
                        format!("unknown lot law `{law_str}`"),
                        "--law FIFO|LIFO|SpecificId|WeightedAverage",
                    )
                })?;
                let regime = match args.flag("--regime") {
                    Some(r) => fa_money::AccountingRegime::parse(r).ok_or_else(|| {
                        usage(
                            format!("unknown accounting regime `{r}`"),
                            "--regime US-GAAP|US-TAX|IFRS",
                        )
                    })?,
                    None => fa_money::AccountingRegime::UsGaap,
                };
                let rounding_law = match args.flag("--rounding-law") {
                    Some(rl) => fa_money::RoundingLaw::from_name(rl).ok_or_else(|| {
                        usage(
                            format!("unknown rounding law `{rl}`"),
                            "--rounding-law HalfEven|HalfUp|Down|Up|Ceiling|Floor",
                        )
                    })?,
                    None => fa_money::RoundingLaw::HalfEven,
                };
                let mut targets = Vec::new();
                for raw in args.flag_all("--target") {
                    let (vid_str, ord) =
                        if let Some((v, o)) = raw.split_once(':').or_else(|| raw.split_once('/')) {
                            let ord = o.parse::<u16>().map_err(|_| {
                                usage(
                                    format!("invalid target ordinal in `{raw}`"),
                                    "--target <32-hex-vid>[:<ordinal>]",
                                )
                            })?;
                            (v, ord)
                        } else {
                            (raw, 0u16)
                        };
                    let vid = parse_vid(vid_str, "--target")?;
                    targets.push((vid, ord));
                }
                let plan = report
                    .plan_disposal(&fa::LotDisposalRequest {
                        quantity,
                        law,
                        regime,
                        rounding_law,
                        targets,
                    })
                    .map_err(|e| match e {
                        fa_money::LotError::OverRelief {
                            requested,
                            open_quantity,
                        } => {
                            let req_fmt =
                                render_amount(Amount::new(quantity.unit, requested), units)
                                    .unwrap_or_else(|_| requested.to_string());
                            let open_fmt =
                                render_amount(Amount::new(quantity.unit, open_quantity), units)
                                    .unwrap_or_else(|_| open_quantity.to_string());
                            Refusal::new(
                                fa_journal::refusal::code::OVER_APPLICATION,
                                exit::REFUSAL,
                                format!(
                                    "lot over-relief refused: requested {req_fmt}, but only {open_fmt} is open on `{account_code}`"
                                ),
                                "plan §6.5 (lot over-relief is refused naming open_quantity)",
                                format!("relieve at most {open_fmt}"),
                            )
                            .into()
                        }
                        fa_money::LotError::RegimeRefused {
                            law,
                            regime,
                            citation,
                        } => Refusal::new(
                            fa_journal::refusal::code::SETTLE_SHAPE,
                            exit::REFUSAL,
                            format!(
                                "lot law `{law}` is refused in `{regime}` books ({citation})"
                            ),
                            citation,
                            "choose FIFO, SpecificId, or WeightedAverage under IFRS",
                        )
                        .into(),
                        fa_money::LotError::UnknownTarget {
                            entry_id,
                            qty_ordinal,
                        } => Refusal::new(
                            fa_journal::refusal::code::SETTLE_TARGET,
                            exit::REFUSAL,
                            format!(
                                "unknown lot target {:032x}:{qty_ordinal} on `{account_code}`",
                                entry_id
                            ),
                            "plan §6.5 (SpecificId targets must name open lots on the account)",
                            format!("run `fa gl lots --account {account_code}` to list open lots"),
                        )
                        .into(),
                        other => usage(other.to_string(), "fa gl lots --help"),
                    })?;
                let slices: Vec<Json> = plan
                    .slices
                    .iter()
                    .map(|sl| {
                        Ok(obj(vec![
                            ("entry", s(format!("{:032x}", sl.entry.0))),
                            ("entry_digest", s(hex(&sl.entry_digest))),
                            ("qty_ordinal", Json::Int(i128::from(sl.qty_ordinal))),
                            ("cost_ordinal", Json::Int(i128::from(sl.cost_ordinal))),
                            ("effective_date", s(sl.effective_date.render())),
                            ("recorded_at", Json::Int(i128::from(sl.recorded_at.0))),
                            (
                                "quantity_relieved",
                                s(render_amount(sl.quantity_relieved, units)?),
                            ),
                            ("cost_relieved", s(render_amount(sl.cost_relieved, units)?)),
                            (
                                "open_quantity_before",
                                s(render_amount(sl.open_quantity_before, units)?),
                            ),
                            (
                                "open_quantity_after",
                                s(render_amount(sl.open_quantity_after, units)?),
                            ),
                            (
                                "open_cost_before",
                                s(render_amount(sl.open_cost_before, units)?),
                            ),
                            (
                                "open_cost_after",
                                s(render_amount(sl.open_cost_after, units)?),
                            ),
                        ]))
                    })
                    .collect::<Result<_, Fail>>()?;
                Some(obj(vec![
                    ("law", s(plan.law.name())),
                    ("regime", s(plan.regime.as_str())),
                    ("rounding_law", s(plan.rounding_law.name())),
                    (
                        "total_quantity",
                        s(render_amount(plan.total_quantity, units)?),
                    ),
                    ("total_cost", s(render_amount(plan.total_cost, units)?)),
                    (
                        "wac_residual_numerator",
                        Json::Int(plan.wac_residual_numerator),
                    ),
                    ("slices", Json::Arr(slices)),
                ]))
            } else {
                if args.flag("--law").is_some()
                    || args.flag("--regime").is_some()
                    || args.flag("--rounding-law").is_some()
                    || !args.flag_all("--target").is_empty()
                {
                    return Err(usage(
                        "--law, --regime, --rounding-law, and --target require --relieve <amount>",
                        "fa gl lots --account 1400 --relieve \"10.00000000 BTC\" --law FIFO --book <dir>",
                    ));
                }
                None
            };

            let lots: Vec<Json> = report
                .lots
                .iter()
                .map(|lot| {
                    let relieves: Vec<Json> = lot
                        .relieves
                        .iter()
                        .map(|r| {
                            Ok(obj(vec![
                                ("disposal_entry", s(format!("{:032x}", r.disposal_entry.0))),
                                ("qty_ordinal", Json::Int(i128::from(r.qty_ordinal))),
                                (
                                    "cost_ordinal",
                                    r.cost_ordinal
                                        .map_or(Json::Null, |c| Json::Int(i128::from(c))),
                                ),
                                ("quantity", s(render_amount(r.quantity, units)?)),
                                ("cost", s(render_amount(r.cost, units)?)),
                                ("recorded_at", Json::Int(i128::from(r.recorded_at.0))),
                                ("live", Json::Bool(r.live)),
                            ]))
                        })
                        .collect::<Result<_, Fail>>()?;
                    Ok(obj(vec![
                        ("entry", s(format!("{:032x}", lot.entry.0))),
                        ("entry_digest", s(hex(&lot.entry_digest))),
                        ("qty_ordinal", Json::Int(i128::from(lot.qty_ordinal))),
                        ("cost_ordinal", Json::Int(i128::from(lot.cost_ordinal))),
                        ("side", s(side_name(lot.side))),
                        ("effective_date", s(lot.effective_date.render())),
                        ("recorded_at", Json::Int(i128::from(lot.recorded_at.0))),
                        (
                            "original_quantity",
                            s(render_amount(lot.original_quantity, units)?),
                        ),
                        (
                            "relieved_quantity",
                            s(render_amount(lot.relieved_quantity, units)?),
                        ),
                        ("open_quantity", s(render_amount(lot.open_quantity, units)?)),
                        ("original_cost", s(render_amount(lot.original_cost, units)?)),
                        ("relieved_cost", s(render_amount(lot.relieved_cost, units)?)),
                        ("open_cost", s(render_amount(lot.open_cost, units)?)),
                        ("relieves", Json::Arr(relieves)),
                    ]))
                })
                .collect::<Result<_, Fail>>()?;

            let human = format!(
                "lots for {} ({}) at {}: {} lot(s)",
                report.account_code,
                report.account_name,
                report.known_at.0,
                report.lots.len()
            );
            out.event(
                "lots",
                vec![
                    ("account", s(&report.account_code)),
                    ("account_vid", s(format!("{:032x}", report.account.0))),
                    ("name", s(&report.account_name)),
                    ("base_unit", s(&base_unit_code)),
                    ("known_at", Json::Int(i128::from(report.known_at.0))),
                    (
                        "effective_through",
                        report
                            .effective_through
                            .map_or(Json::Null, |d| s(d.render())),
                    ),
                    ("count", Json::Int(report.lots.len() as i128)),
                    ("lots", Json::Arr(lots)),
                    ("disposal_plan", disposal_plan.unwrap_or(Json::Null)),
                ],
                &human,
            );
            Ok(())
        }
        other => Err(unhandled("gl", other)),
    }
}

const EQUITY_ROLL_FORWARD_EXAMPLE: &str = "fa statement equity-roll-forward --from 2026-01-01 --to 2026-12-31 --issuance 3100 --distribution 3200 [--certify | --certificate-out <new-file>] --book <dir>";

/// `fa statement equity-roll-forward` (plan §12.1, bead fa-nzix): the
/// statement of changes in equity over an inclusive effective window at one
/// recorded prefix. It reads like the lead schedule it is built from: the
/// whole recorded prefix is judged before the window projects it.
fn statement_equity_roll_forward(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.flag_all("--certificate-out").len() > 1 {
        return Err(usage(
            "--certificate-out may be supplied only once",
            EQUITY_ROLL_FORWARD_EXAMPLE,
        ));
    }
    let certify = args.switch("--certify") || args.flag("--certificate-out").is_some();
    if let Some(flag) = [
        "--for",
        "--compare",
        "--definition",
        "--before",
        "--after",
        "--max-publications",
        "--branch",
        "--before-certificate",
        "--after-certificate",
        "--from-diff",
        "--certificate",
        "--issued-to",
        "--document",
        "--key",
        "--date",
        "--plan",
        "--approval",
        "--as-issued-to",
        "--as-reported-in",
        "--render",
        "--out",
        "--present-in",
        "--rounding",
    ]
    .into_iter()
    .find(|flag| args.flag(flag).is_some())
    .or_else(|| {
        ["--as-originally-reported", "--dry-run"]
            .into_iter()
            .find(|switch| args.switch(switch))
    }) {
        return Err(usage(
            format!(
                "{flag} does not apply to statement equity-roll-forward: it selects inclusive --from/--to dates over every equity, revenue and expense leaf"
            ),
            EQUITY_ROLL_FORWARD_EXAMPLE,
        ));
    }
    let who = ctx.principal(args);
    let capability = ctx.capability(
        args,
        if certify {
            &["read", "produce"]
        } else {
            &["read"]
        },
    )?;
    let out = &ctx.out;
    let mut book = ctx
        .books
        .open_admitted(args, |book: &mut Book| -> Result<(), Fail> {
            if certify {
                gl_certificate_preflight(book, &ctx.files, args, &capability)?;
            }
            book.read_scope(who, &capability)??;
            let (known_at, _) = known_at_read_flag(args, book, out, &capability)?;
            book.prepare_report_history(who, &capability, known_at)??;
            Ok(())
        })?;
    let (known_at, _) = known_at_flag(args, &book, out)?;
    if let Some(seq) = known_at {
        out.known_at(seq);
    }
    let window = parse_gl_window(
        args,
        &book,
        &capability,
        out,
        known_at,
        "equity-roll-forward",
    )?;
    let named = |flag: &str| -> Vec<VId> {
        args.flag_all(flag)
            .into_iter()
            .flat_map(|s| s.split(','))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|code| account_vid(book.context().book_id, code))
            .collect()
    };
    let request = fa::EquityRollForwardRequest {
        units: window.units,
        label: window.label,
        effective_from: window.from,
        effective_through: window.to,
        known_at,
        issuance_accounts: named("--issuance"),
        distribution_accounts: named("--distribution"),
    };
    book.prepare_report_history(who, &capability, request.known_at)??;
    if certify {
        let certified = book.certify_equity_roll_forward(who, &capability, &request)??;
        let artifact = fa::ReportArtifact::try_from(&certified.certificate)?;
        let expected = certified.certificate.request();
        let expectation = notary::equity_expectation_json(expected);
        let (bytes, retained) = notary::retain_report_artifact_for(
            &mut book,
            &ctx.files,
            args,
            &artifact,
            &capability,
            fa::ReportArtifactExpectation::EquityRollForward(expected),
        )?;
        render_equity_roll_forward(out, &book, &certified.report, Some(&hex(artifact.digest())))?;
        notary::emit_report_artifact_for(
            out,
            args,
            &artifact,
            fa::EQUITY_REPORT_FORMAT,
            &bytes,
            &retained,
            &expectation,
        );
        Ok(())
    } else {
        let report = book.equity_roll_forward(who, &capability, &request)??;
        render_equity_roll_forward(out, &book, &report, None)
    }
}

/// The Statement of Changes in Equity as `equity_roll_forward`: every unit's
/// reconciliation and every classified equity leg it folded.
pub(crate) fn render_equity_roll_forward(
    out: &Out,
    book: &Book,
    report: &fa::EquityRollForwardReport,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    let statement = &report.statement;
    out.known_at(CommitSeq(statement.known_at));
    let units = &book.context().units;
    let codes: std::collections::BTreeMap<u128, &str> = report
        .accounts
        .iter()
        .map(|a| (a.id, a.code.as_str()))
        .collect();
    let code = |id: u128| {
        codes
            .get(&id)
            .copied()
            .ok_or_else(|| Fail::Internal("equity roll-forward account missing".into()))
    };
    let mut human = format!(
        "equity roll-forward `{}` ({}..={})",
        statement.label,
        statement.effective_from.render(),
        statement.effective_through.render()
    );
    let mut unit_rows = Vec::with_capacity(statement.units.len());
    for u in &statement.units {
        let fmt = |m: i128| render_amount(Amount::new(fa_money::UnitId(u.unit_id), m), units);
        human.push_str(&format!(
            "\n  {}: opening {} + net income {} + issuances {} + distributions {} + other {} = closing {}",
            registered_unit_code(fa_money::UnitId(u.unit_id), units)?,
            fmt(u.opening_total_equity)?,
            fmt(u.net_income)?,
            fmt(u.issuances)?,
            fmt(u.distributions)?,
            fmt(u.other_equity_movements)?,
            fmt(u.closing_total_equity)?,
        ));
        unit_rows.push(obj(vec![
            (
                "unit",
                s(registered_unit_code(fa_money::UnitId(u.unit_id), units)?),
            ),
            (
                "opening_contributed_equity",
                s(fmt(u.opening_contributed_equity)?),
            ),
            (
                "opening_unclosed_earnings",
                s(fmt(u.opening_unclosed_earnings)?),
            ),
            ("opening_total_equity", s(fmt(u.opening_total_equity)?)),
            ("net_income", s(fmt(u.net_income)?)),
            ("issuances", s(fmt(u.issuances)?)),
            ("distributions", s(fmt(u.distributions)?)),
            ("other_equity_movements", s(fmt(u.other_equity_movements)?)),
            ("closing_transfers_net", s(fmt(u.closing_transfers_net)?)),
            ("net_equity_change", s(fmt(u.net_equity_change)?)),
            (
                "closing_contributed_equity",
                s(fmt(u.closing_contributed_equity)?),
            ),
            (
                "closing_unclosed_earnings",
                s(fmt(u.closing_unclosed_earnings)?),
            ),
            ("closing_total_equity", s(fmt(u.closing_total_equity)?)),
            ("tie_out_residual", s(fmt(u.equity_tie_out_residual)?)),
        ]));
    }
    let movements = report
        .movements
        .iter()
        .map(|m| {
            let (side, mantissa) = if m.debits > 0 {
                ("debit", m.debits)
            } else {
                ("credit", m.credits)
            };
            Ok(obj(vec![
                ("entry_digest", s(hex(&m.entry_digest))),
                ("leg_index", Json::Int(i128::from(m.leg_index))),
                ("recorded_at", Json::Int(i128::from(m.recorded_seq))),
                ("effective_date", s(m.effective_day.render())),
                ("class", s(m.class.name().unwrap_or("unknown"))),
                (
                    "kind",
                    s(match m.kind {
                        fa::EquityActivityKind::Issuance => "issuance",
                        fa::EquityActivityKind::Distribution => "distribution",
                        fa::EquityActivityKind::ClosingTransfer => "closing_transfer",
                        fa::EquityActivityKind::OtherEquity => "other_equity",
                    }),
                ),
                ("account", s(code(m.account_id)?)),
                ("side", s(side)),
                (
                    "amount",
                    s(render_amount(
                        Amount::new(fa_money::UnitId(m.unit_id), mantissa),
                        units,
                    )?),
                ),
            ]))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    out.event_with_certificate(
        "equity_roll_forward",
        vec![
            ("label", s(&statement.label)),
            ("known_at", Json::Int(i128::from(statement.known_at))),
            ("effective_from", s(statement.effective_from.render())),
            ("effective_through", s(statement.effective_through.render())),
            ("units", Json::Arr(unit_rows)),
            ("movement_count", Json::Int(report.movements.len() as i128)),
            ("movements", Json::Arr(movements)),
        ],
        &human,
        certificate,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// explain
// ---------------------------------------------------------------------------

fn side_name(side: Side) -> &'static str {
    if side == Side::Debit {
        "debit"
    } else {
        "credit"
    }
}

/// `fa explain balance|entry|lineage|evidence|refusal|period|register ...`.
pub(crate) fn explain_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let sub = args.positional.get(1).map(String::as_str);
    // verbs.toml registers flags per verb, so the other subcommands would
    // otherwise accept these and silently answer without them.
    if sub.is_some_and(|sub| sub != "balance") {
        let balance_only = ["--certify"]
            .into_iter()
            .find(|switch| args.switch(switch))
            .or_else(|| crate::issuance::view_flag(args))
            .or_else(|| {
                args.flag("--certificate-out")
                    .is_some()
                    .then_some("--certificate-out")
            });
        if let Some(flag) = balance_only {
            return Err(usage(
                format!("{flag} applies only to `fa explain balance`"),
                "fa explain balance <account> --period <code> [--as-originally-reported | --as-issued-to <audience> | --as-reported-in C:<oid>] [--certify]",
            ));
        }
    }
    match sub {
        Some("balance") => explain_balance_cmd(ctx, args),
        Some("entry") => explain_entry_cmd(ctx, args),
        Some("lineage") => explain_lineage_cmd(ctx, args),
        Some("evidence") => explain_evidence_cmd(ctx, args),
        Some("refusal") => explain_refusal_cmd(ctx, args),
        Some("period") => explain_period_cmd(ctx, args),
        Some("register") => explain_register_cmd(ctx, args),
        other => Err(unhandled("explain", other)),
    }
}

fn parse_entry_target(raw: &str, example: &str) -> Result<VId, Fail> {
    let clean = raw.strip_prefix("E:").unwrap_or(raw);
    if clean.len() != 32 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(usage(
            format!("`{raw}` is not a 32-hex entry vid (or E:<32-hex>)"),
            example,
        ));
    }
    let id = u128::from_str_radix(clean, 16)
        .map_err(|_| usage(format!("`{raw}` is not a 32-hex entry vid"), example))?;
    Ok(VId(id))
}

fn explain_admissibility_cell_json(
    class_name: &str,
    state: PeriodState,
    decision: &fa_registry::Decision,
) -> Json {
    let (admitted, required_capability, min_approvers) = match decision {
        fa_registry::Decision::Admit => (true, Some("post"), 0i128),
        fa_registry::Decision::With { op, approvals } => {
            (true, Some(op.as_str()), i128::from(*approvals))
        }
        fa_registry::Decision::Refuse => (false, None, 0i128),
    };
    let requires_case_id = class_name == "PriorPeriodRestatement";
    let requires_reason_code = matches!(
        class_name,
        "Adjusting" | "Reversal" | "Reclass" | "PriorPeriodRestatement"
    ) || matches!(
        state,
        PeriodState::SoftClosed | PeriodState::Closed | PeriodState::Locked
    );
    obj(vec![
        ("entry_class", s(class_name)),
        ("period_state", s(state.name())),
        ("admitted", Json::Bool(admitted)),
        (
            "required_capability",
            required_capability.map_or(Json::Null, s),
        ),
        ("requires_case_id", Json::Bool(requires_case_id)),
        ("requires_reason_code", Json::Bool(requires_reason_code)),
        ("min_approvers", Json::Int(min_approvers)),
    ])
}

fn explain_entry_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let example = "fa explain entry <vid|E:vid> --book <dir>";
    let raw = args
        .positional
        .get(2)
        .ok_or_else(|| usage("explain entry needs an entry vid (32 hex)", example))?;
    if let Some(extra) = args.positional.get(3) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    let vid = parse_entry_target(raw, example)?;
    let who = ctx.principal(args);
    let read_cap = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        book.read_scope(who, &read_cap)??;
        Ok(())
    })?;
    // The entry's period is known only once it is read, so a scoped token
    // is refused before the read (doctrine 8, fa-0x0).
    book.read_scope(who, &read_cap)??.admit_whole_book(None)??;
    let (entry, recorded_at) = book.read_entry(vid)?.ok_or_else(|| {
        usage(
            format!("no entry {:032x} in this book", vid.0),
            "pass a committed entry vid from `fa post` or `fa explain balance`",
        )
    })?;
    out.known_at(recorded_at);
    let period = fa_registers::entry_period(book.context(), &entry).ok();
    if let Some(p) = &period {
        out.effective(format!("period:{p}"));
    }
    let accounts: std::collections::BTreeMap<VId, fa_journal::AccountRow> =
        book.accounts()?.into_iter().map(|a| (a.vid, a)).collect();
    let units = &book.context().units;
    let seal_key = &book.context().seal_key;
    let reasons =
        ReasonCodes::embedded().map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
    let vid_hex = format!("{:032x}", vid.0);
    let description = untrusted_text_json(
        entry
            .proposal
            .description
            .open(seal_key, fa_model::limits::MAX_DESCRIPTION_BYTES)
            .ok(),
        format!("E:{vid_hex}"),
    );
    let mut legs = Vec::with_capacity(entry.proposal.legs.len());
    for (idx, leg) in entry.proposal.legs.iter().enumerate() {
        let (acc_code, acc_name) = match accounts.get(&leg.account_ref) {
            Some(row) => (row.code.as_str(), row.name.as_str()),
            None => ("?", "?"),
        };
        let memo = untrusted_text_json(
            leg.memo
                .as_ref()
                .and_then(|m| m.open(seal_key, fa_model::limits::MAX_MEMO_BYTES).ok()),
            format!("E:{vid_hex}:L{idx}"),
        );
        legs.push(obj(vec![
            ("ordinal", Json::Int(idx as i128)),
            ("side", s(side_name(leg.side))),
            ("account", s(acc_code)),
            ("account_vid", s(format!("{:032x}", leg.account_ref.0))),
            ("account_name", s(acc_name)),
            ("amount", s(render_amount(leg.amount, units)?)),
            ("memo", memo),
        ]));
    }
    let resolves = entry
        .proposal
        .pending
        .as_ref()
        .and_then(|pending| pending.resolution_of.as_ref())
        .map(|target| format!("{:032x}", target.vid.0));
    let disposition = entry
        .proposal
        .pending
        .as_ref()
        .and_then(|pending| pending.disposition.as_ref())
        .map(|d| match d {
            Disposition::Posts { .. } => "posts",
            Disposition::Voids => "voids",
            Disposition::Expires { .. } => "expires",
        });
    let supersedes: Vec<Json> = entry
        .proposal
        .supersession
        .iter()
        .map(|l| lineage_json(l, &reasons))
        .collect();
    let superseded_by: Vec<Json> = book
        .superseded_by(vid)?
        .iter()
        .map(|l| lineage_json(l, &reasons))
        .collect();
    let evidence: Vec<Json> = entry
        .proposal
        .evidence
        .iter()
        .map(|e| {
            obj(vec![
                ("document_oid", s(hex(&e.document_oid.0))),
                ("doc_commit", s(hex(&e.doc_commit))),
                ("role", Json::Int(i128::from(e.role))),
            ])
        })
        .collect();
    let cited_event = match entry.proposal.cited_event() {
        Some((ev_vid, _)) => book
            .rea_snapshot(None)?
            .events
            .get(&ev_vid)
            .map(event_summary_json)
            .unwrap_or(Json::Null),
        None => Json::Null,
    };
    let class_name = entry.proposal.class.name().unwrap_or("?");
    let human = format!(
        "entry {:032x} · {class_name} effective {} ({}) · recorded at {} · {} leg(s) · {} approval(s)",
        vid.0,
        entry.proposal.effective_date.render(),
        period.as_deref().unwrap_or("book-scoped"),
        recorded_at.0,
        entry.proposal.legs.len(),
        entry.approvals.len()
    );
    out.event(
        "entry_explained",
        vec![
            ("vid", s(vid_hex)),
            ("entry_digest", s(hex(&entry.entry_digest))),
            ("proposal_digest", s(hex(&entry.proposal_digest))),
            ("class", s(class_name)),
            ("effective_date", s(entry.proposal.effective_date.render())),
            ("period", period.as_deref().map_or(Json::Null, s)),
            ("recorded_at", Json::Int(i128::from(recorded_at.0))),
            (
                "principal",
                s(format!("{:032x}", entry.proposal.principal_ref.0)),
            ),
            ("description", description),
            ("approvals", Json::Int(entry.approvals.len() as i128)),
            ("resolves", resolves.as_deref().map_or(Json::Null, s)),
            ("disposition", disposition.map_or(Json::Null, s)),
            ("legs", Json::Arr(legs)),
            ("supersedes", Json::Arr(supersedes)),
            ("superseded_by", Json::Arr(superseded_by)),
            ("evidence", Json::Arr(evidence)),
            ("cited_event", cited_event),
        ],
        &human,
    );
    Ok(())
}

fn explain_lineage_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let example = "fa explain lineage <vid|E:vid> [--as-known-at HEAD|<seq>] --book <dir>";
    let raw = args
        .positional
        .get(2)
        .ok_or_else(|| usage("explain lineage needs an entry vid (32 hex)", example))?;
    if let Some(extra) = args.positional.get(3) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    let vid = parse_entry_target(raw, example)?;
    let who = ctx.principal(args);
    let read_cap = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        book.read_scope(who, &read_cap)??;
        Ok(())
    })?;
    let (known_at, _) = known_at_flag(args, &book, out)?;
    // A lineage walks entries whose periods are known only once read
    // (doctrine 8, fa-0x0).
    book.read_scope(who, &read_cap)??
        .admit_whole_book(known_at)??;
    let report = book.explain_entry_lineage(vid, known_at)?.ok_or_else(|| {
        usage(
            format!("no entry {:032x} in this book", vid.0),
            "pass a committed entry vid from `fa post` or `fa explain balance`",
        )
    })?;
    let seq = report.known_at.unwrap_or_else(|| {
        report
            .entries
            .iter()
            .map(|st| st.recorded_at)
            .max()
            .unwrap_or(CommitSeq(0))
    });
    out.known_at(seq);
    let accounts: std::collections::BTreeMap<VId, fa_journal::AccountRow> =
        book.accounts()?.into_iter().map(|a| (a.vid, a)).collect();
    let units = &book.context().units;
    let reasons =
        ReasonCodes::embedded().map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
    let steps: Vec<Json> = report
        .entries
        .iter()
        .map(|st| {
            let supersedes: Vec<Json> = st
                .supersedes
                .iter()
                .map(|sup| {
                    let reason = reasons
                        .get("supersession", sup.reason_code)
                        .map(|r| r.name.as_str());
                    obj(vec![
                        ("target", s(format!("{:032x}", sup.target_vid.0))),
                        ("kind", s(format!("{:?}", sup.kind))),
                        ("netting_law", s(sup.netting_law.as_str())),
                        ("reason_code", Json::Int(i128::from(sup.reason_code))),
                        ("reason", reason.map_or(Json::Null, s)),
                    ])
                })
                .collect();
            obj(vec![
                ("entry", s(format!("{:032x}", st.vid.0))),
                ("entry_digest", s(hex(&st.entry_digest))),
                ("class", s(st.class.name().unwrap_or("?"))),
                ("effective_date", s(st.effective_date.render())),
                ("recorded_at", Json::Int(i128::from(st.recorded_at.0))),
                ("live", Json::Bool(st.live)),
                ("reverses_reversal", Json::Bool(st.reverses_reversal)),
                ("supersedes", Json::Arr(supersedes)),
            ])
        })
        .collect();
    let mut net_effect = Vec::with_capacity(report.net_positions.len());
    for pos in &report.net_positions {
        let (acc_code, acc_name) = match accounts.get(&pos.account_ref) {
            Some(row) => (row.code.as_str(), row.name.as_str()),
            None => ("?", "?"),
        };
        let unit_code = registered_unit_code(pos.unit, units)?;
        let debits_str = render_amount(Amount::new(pos.unit, pos.debits), units)?;
        let credits_str = render_amount(Amount::new(pos.unit, pos.credits), units)?;
        let net_str = render_amount(Amount::new(pos.unit, pos.net_debit), units)?;
        net_effect.push(obj(vec![
            ("account", s(acc_code)),
            ("account_vid", s(format!("{:032x}", pos.account_ref.0))),
            ("account_name", s(acc_name)),
            ("unit", s(unit_code)),
            ("debits", s(debits_str)),
            ("credits", s(credits_str)),
            ("net", s(net_str)),
        ]));
    }
    let human = format!(
        "lineage of entry {:032x} (root {:032x}) at {} · {} step(s) · fully_reversed={} · {} net cell(s)",
        vid.0,
        report.root_vid.0,
        seq.0,
        report.entries.len(),
        report.fully_reversed,
        net_effect.len()
    );
    out.event(
        "lineage_explained",
        vec![
            ("query_entry", s(format!("{:032x}", report.queried_vid.0))),
            ("root_entry", s(format!("{:032x}", report.root_vid.0))),
            ("known_at", Json::Int(i128::from(seq.0))),
            ("fully_reversed", Json::Bool(report.fully_reversed)),
            (
                "replaced_by",
                report
                    .replaced_by
                    .map_or(Json::Null, |v| s(format!("{:032x}", v.0))),
            ),
            ("steps", Json::Arr(steps)),
            ("net_effect", Json::Arr(net_effect)),
        ],
        &human,
    );
    Ok(())
}

pub(crate) fn untrusted_text_json(content: Option<String>, source: String) -> Json {
    match content.filter(|t| !t.is_empty()) {
        Some(text) => obj(vec![("untrusted_content", s(text)), ("source", s(source))]),
        None => Json::Null,
    }
}

/// The `extraction_info` shape: how a derived text document was extracted
/// (fa-646), without its text (`fa document read` shows that).
fn extraction_info_json(info: Option<&fa_journal::evidence::DerivedExtractionInfo>) -> Json {
    info.map_or(Json::Null, |x| {
        obj(vec![
            ("method", s(&x.method)),
            ("tool_name", s(&x.tool_name)),
            ("tool_version", s(&x.tool_version)),
            ("replayable", Json::Bool(x.replayable)),
            ("text_bytes", Json::Int(i128::from(x.extracted_text_bytes))),
        ])
    })
}

fn explain_evidence_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let example = "fa explain evidence <entry-vid> --book <dir>";
    let raw = args
        .positional
        .get(2)
        .ok_or_else(|| usage("explain evidence needs an entry vid (32 hex)", example))?;
    if let Some(extra) = args.positional.get(3) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    let vid = parse_entry_target(raw, example)?;
    let who = ctx.principal(args);
    let read_cap = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        book.read_scope(who, &read_cap)??;
        Ok(())
    })?;
    // An entry's evidence: its period is known only once it is read
    // (doctrine 8, fa-0x0).
    book.read_scope(who, &read_cap)??.admit_whole_book(None)??;
    let ex = book.explain_entry_evidence(vid)?.ok_or_else(|| {
        usage(
            format!("no entry {:032x} in this book", vid.0),
            "pass a committed entry vid from `fa post` or `fa explain balance`",
        )
    })?;
    out.known_at(ex.recorded_at);
    let policy = fa_registry::evidence_policy::EvidencePolicy::embedded()
        .map_err(|e| Fail::Internal(format!("evidence_policy.toml: {e}")))?;
    let reasons =
        ReasonCodes::embedded().map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
    let min_row = policy.minimum(&ex.class);
    let accepted_kinds: Vec<Json> = match min_row.map(|m| &m.kinds) {
        Some(fa_registry::evidence_policy::KindSet::Any) => {
            policy.kinds.iter().map(|k| s(&k.name)).collect()
        }
        Some(fa_registry::evidence_policy::KindSet::Only(tags)) => tags
            .iter()
            .filter_map(|tag| policy.kinds.iter().find(|k| k.tag == *tag))
            .map(|k| s(&k.name))
            .collect(),
        None => Vec::new(),
    };
    let mut docs_json = Vec::with_capacity(ex.documents.len());
    for doc in &ex.documents {
        let role_name = policy
            .roles
            .iter()
            .find(|r| r.tag == doc.role)
            .map(|r| r.name.as_str());
        let kind_name = policy
            .kinds
            .iter()
            .find(|k| k.tag == doc.kind)
            .map_or("?", |k| k.name.as_str());
        let grade_row = policy.grades.iter().find(|g| g.tag == doc.grade);
        let grade_name = grade_row.map_or("?", |g| g.name.as_str());
        let is_self_sourced = grade_row.is_some_and(|g| g.self_sourced);
        let counts = min_row.is_some_and(|m| m.kinds.admits(doc.kind))
            && (!is_self_sourced
                || doc
                    .review
                    .as_ref()
                    .is_some_and(|r| r.reviewer != doc.retrieved_by));
        let reviews: Vec<Json> = doc
            .review
            .iter()
            .map(|r| {
                obj(vec![
                    (
                        "attestation_vid",
                        s(format!("{:032x}", r.attestation_vid.0)),
                    ),
                    ("reviewer", s(format!("{:032x}", r.reviewer.0))),
                    (
                        "against",
                        Json::Arr(r.against.iter().map(|o| s(hex(&o.0))).collect()),
                    ),
                    ("recorded_at", Json::Int(i128::from(r.recorded_at.0))),
                ])
            })
            .collect();
        let mut supplements = Vec::new();
        for sup in &ex.supplements {
            for sref in &sup.documents {
                if sref.document_oid == doc.document_oid {
                    let srole = policy
                        .roles
                        .iter()
                        .find(|r| r.tag == sref.role)
                        .map(|r| r.name.as_str());
                    supplements.push(obj(vec![
                        ("supplement_vid", s(format!("{:032x}", sup.vid.0))),
                        ("document_oid", s(hex(&sref.document_oid.0))),
                        ("role", Json::Int(i128::from(sref.role))),
                        ("role_name", srole.map_or(Json::Null, s)),
                        ("recorded_at", Json::Int(i128::from(sup.recorded_at.0))),
                    ]));
                }
            }
        }
        // fa-646: a derived text document names how it was extracted and
        // the documents it derives from, ancestors included.
        let lineage: Vec<Json> = doc
            .derived_from
            .iter()
            .map(|src| {
                let kind = policy
                    .kinds
                    .iter()
                    .find(|k| k.tag == src.kind)
                    .map_or("?", |k| k.name.as_str());
                let grade = policy
                    .grades
                    .iter()
                    .find(|g| g.tag == src.grade)
                    .map_or("?", |g| g.name.as_str());
                obj(vec![
                    ("document_oid", s(hex(&src.document_oid.0))),
                    ("doc_commit", s(hex(&src.doc_commit))),
                    ("kind", s(kind)),
                    ("mime", s(&src.mime)),
                    ("grade", s(grade)),
                    ("size", Json::Int(i128::from(src.size))),
                    ("recorded_at", Json::Int(i128::from(src.recorded_at.0))),
                    ("extraction", extraction_info_json(src.extraction.as_ref())),
                    (
                        "derived_from",
                        Json::Arr(src.derived_from.iter().map(|o| s(hex(&o.0))).collect()),
                    ),
                ])
            })
            .collect();
        docs_json.push(obj(vec![
            ("document_oid", s(hex(&doc.document_oid.0))),
            ("doc_commit", s(hex(&doc.doc_commit))),
            ("role", Json::Int(i128::from(doc.role))),
            ("role_name", role_name.map_or(Json::Null, s)),
            ("kind", s(kind_name)),
            ("grade", s(grade_name)),
            ("self_sourced", Json::Bool(is_self_sourced)),
            ("size", Json::Int(i128::from(doc.size))),
            ("recorded_at", Json::Int(i128::from(doc.recorded_at.0))),
            ("reviews", Json::Arr(reviews)),
            ("supplements", Json::Arr(supplements)),
            ("extraction", extraction_info_json(doc.extraction.as_ref())),
            ("derived_from", Json::Arr(lineage)),
            ("counts_toward_minimum", Json::Bool(counts)),
        ]));
    }
    let manual_assertions: Vec<Json> = ex
        .manual_assertion
        .iter()
        .map(|ma| {
            let reason_name = reasons
                .get("manual_assertion", ma.reason_code)
                .map(|r| r.name.as_str());
            obj(vec![
                (
                    "attestation_vid",
                    s(format!("{:032x}", ma.attestation_vid.0)),
                ),
                ("asserter", s(format!("{:032x}", ma.principal.0))),
                ("reason_code", Json::Int(i128::from(ma.reason_code))),
                ("reason", reason_name.map_or(Json::Null, s)),
                ("recorded_at", Json::Int(i128::from(ma.recorded_at.0))),
            ])
        })
        .collect();
    // Every supplement with all its documents: an attachment usually
    // cites a document the entry itself does not (plan §9.2).
    let supplements: Vec<Json> = ex
        .supplements
        .iter()
        .map(|sup| {
            let documents = sup
                .documents
                .iter()
                .map(|d| {
                    obj(vec![
                        ("document_oid", s(hex(&d.document_oid.0))),
                        ("doc_commit", s(hex(&d.doc_commit))),
                        (
                            "role",
                            s(policy
                                .roles
                                .iter()
                                .find(|r| r.tag == d.role)
                                .map_or_else(|| d.role.to_string(), |r| r.name.clone())),
                        ),
                    ])
                })
                .collect();
            obj(vec![
                ("supplement_vid", s(format!("{:032x}", sup.vid.0))),
                ("attached_by", s(format!("{:032x}", sup.attached_by.0))),
                ("body_digest", s(hex(&sup.body_digest))),
                ("recorded_at", Json::Int(i128::from(sup.recorded_at.0))),
                ("documents", Json::Arr(documents)),
            ])
        })
        .collect();
    // Plan §9.2 (fa-ge0y): every member of the provenance closure, in
    // canonical order, with the original and current closure digests.
    let closure_members: Vec<Json> = ex
        .closure
        .members
        .iter()
        .map(|m| {
            obj(vec![
                ("kind", s(m.kind.name())),
                (
                    "vid",
                    m.vid.map_or(Json::Null, |vid| s(format!("{:032x}", vid.0))),
                ),
                (
                    "digest",
                    m.digest.as_ref().map_or(Json::Null, |d| s(hex(d))),
                ),
                (
                    "role",
                    m.role.map_or(Json::Null, |tag| {
                        s(policy
                            .roles
                            .iter()
                            .find(|r| r.tag == tag)
                            .map_or_else(|| tag.to_string(), |r| r.name.clone()))
                    }),
                ),
                (
                    "recorded_at",
                    m.recorded_at
                        .map_or(Json::Null, |seq| Json::Int(i128::from(seq.0))),
                ),
            ])
        })
        .collect();
    let human = format!(
        "evidence of entry {:032x} ({}) · minimum {} document(s) · satisfied={} · {} cited document(s) · {} supplement(s) · closure of {} member(s) {}",
        ex.entry_vid.0,
        ex.class,
        ex.min_documents,
        ex.minimum_satisfied,
        ex.documents.len(),
        ex.supplements.len(),
        ex.closure.members.len(),
        hex(&ex.closure.digest)
    );
    out.event(
        "evidence_explained",
        vec![
            ("entry", s(format!("{:032x}", ex.entry_vid.0))),
            ("entry_digest", s(hex(&ex.entry_digest))),
            ("proposal_digest", s(hex(&ex.proposal_digest))),
            ("class", s(&ex.class)),
            ("recorded_at", Json::Int(i128::from(ex.recorded_at.0))),
            ("min_documents", Json::Int(i128::from(ex.min_documents))),
            ("accepted_kinds", Json::Arr(accepted_kinds)),
            ("accepts_self_sourced", Json::Bool(true)),
            (
                "accepts_manual_assertion",
                Json::Bool(ex.manual_assertion_allowed),
            ),
            ("satisfied", Json::Bool(ex.minimum_satisfied)),
            ("documents", Json::Arr(docs_json)),
            ("supplements", Json::Arr(supplements)),
            ("manual_assertions", Json::Arr(manual_assertions)),
            (
                "closure",
                obj(vec![
                    ("digest", s(hex(&ex.closure.digest))),
                    ("original_digest", s(hex(&ex.closure.original_digest))),
                    ("members", Json::Arr(closure_members)),
                ]),
            ),
        ],
        &human,
    );
    Ok(())
}

fn explain_refusal_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let example = "fa explain refusal FA-REF-001 [--json]";
    let given = args
        .positional
        .get(2)
        .ok_or_else(|| usage("explain refusal needs a refusal code (FA-REF-nnn)", example))?;
    if let Some(extra) = args.positional.get(3) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    // An error's instance id (`FA-REF-nnn:<16 hex>`) expands its code.
    let target = crate::refusal_object::code_of(given);
    let instance = (target != given.as_str()).then(|| given.clone());
    if let Some(id) = &instance
        && !crate::refusal_object::is_instance_id(id)
    {
        return Err(usage(
            format!("`{id}` is neither a refusal code nor a refusal instance id"),
            "pass FA-REF-nnn, or an error's refusal.id (FA-REF-nnn:<16 hex digits>)",
        ));
    }
    let catalog = fa_registry::refusal_catalog::RefusalCatalog::embedded()
        .map_err(|e| Fail::Internal(format!("refusal_catalog.toml: {e}")))?;
    let row = catalog
        .by_code(target)
        .or_else(|| catalog.by_name(target))
        .ok_or_else(|| {
            usage(
                format!("unknown refusal code `{target}`"),
                "pass a registered FA-REF-nnn code from registries/refusal_catalog.toml",
            )
        })?;
    let classes = fa_registry::EntryClasses::embedded()
        .map_err(|e| Fail::Internal(format!("entry_classes.toml: {e}")))?;
    let matrix = fa_registry::Admissibility::embedded(&classes)
        .map_err(|e| Fail::Internal(format!("admissibility.toml: {e}")))?;
    let sod = fa_registry::sod_policy::SodPolicy::embedded(&classes, &matrix)
        .map_err(|e| Fail::Internal(format!("sod_policy.toml: {e}")))?;

    let mut admissibility_cells = Vec::new();
    if row.code == "FA-REF-003"
        || row.code == "FA-REF-013"
        || row.code == "FA-REF-051"
        || row.code == "FA-REF-062"
        || row.code == "FA-REF-070"
        || row.cite.contains("Appendix C")
        || row.cite.contains("admissibility.toml")
    {
        for c in classes.posting() {
            for state in fa_registry::ALL_STATES {
                if let Some(decision) = matrix.decide(&c.name, state) {
                    let include = match row.code.as_str() {
                        "FA-REF-003" => matches!(decision, fa_registry::Decision::Refuse),
                        "FA-REF-013" | "FA-REF-016" => {
                            matches!(decision, fa_registry::Decision::With { .. })
                        }
                        _ => true,
                    };
                    if include {
                        admissibility_cells
                            .push(explain_admissibility_cell_json(&c.name, state, decision));
                    }
                }
            }
        }
    }

    let mut sod_rules = Vec::new();
    if matches!(
        row.code.as_str(),
        "FA-REF-016" | "FA-REF-017" | "FA-REF-018" | "FA-REF-019" | "FA-REF-020"
    ) || row.cite.contains("sod_policy.toml")
        || row.cite.contains("§14.3")
    {
        for rule in &sod.rules {
            sod_rules.push(obj(vec![
                ("action", s(&rule.name)),
                ("conflict_with", s(rule.requirement.exclusions.join(","))),
                (
                    "min_distinct_principals",
                    Json::Int(i128::from(rule.requirement.approvers.saturating_add(1))),
                ),
                (
                    "agent_eligible",
                    Json::Bool(
                        rule.requirement
                            .approver_profiles
                            .iter()
                            .any(|p| p == "Agent"),
                    ),
                ),
                ("refusal_code", s(&row.code)),
            ]));
        }
    }

    let message = format!(
        "{} ({}): {} [owners: {}]",
        row.code,
        row.name,
        row.cite,
        row.owners.join(", ")
    );
    let human = format!(
        "{} ({}) · exit {} ({})\ncite: {}\nfix:  {}",
        row.code, row.name, row.exit, row.exit_name, row.cite, row.fix
    );
    out.event(
        "refusal_explained",
        vec![
            ("id", s(&row.code)),
            ("instance", instance.map_or(Json::Null, s)),
            ("exit", Json::Int(i128::from(row.exit))),
            ("class", s(&row.exit_name)),
            ("cite", s(&row.cite)),
            ("message", s(&message)),
            ("fix", s(&row.fix)),
            ("admissibility_cells", Json::Arr(admissibility_cells)),
            ("sod_rules", Json::Arr(sod_rules)),
        ],
        &human,
    );
    Ok(())
}

fn explain_period_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let example = "fa explain period FY2026-P01 --book <dir>";
    let code = args
        .positional
        .get(2)
        .ok_or_else(|| usage("explain period needs a period code", example))?;
    if let Some(extra) = args.positional.get(3) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    let who = ctx.principal(args);
    let read_cap = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        book.read_scope(who, &read_cap)??;
        Ok(())
    })?;
    // It reaches its one period, judged before the calendar or the period's
    // history is read (doctrine 8, fa-0x0).
    book.read_scope(who, &read_cap)??
        .admit_periods(&[code.as_str()], None)??;
    let periods = book.periods()?;
    let Some(period) = periods.iter().find(|p| p.code == *code) else {
        let codes: Vec<&str> = periods.iter().map(|p| p.code.as_str()).collect();
        return Err(usage(
            format!("no period `{code}` in this book"),
            match nearest(code, &codes) {
                Some(near) => format!("did you mean `{near}`? (fa period list)"),
                None => "fa period list --book <dir>".to_string(),
            },
        ));
    };
    out.effective(format!("period:{code}"));
    let reasons =
        ReasonCodes::embedded().map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
    let transitions_raw = book.period_transitions(code)?;
    let transitions: Vec<Json> = transitions_raw
        .iter()
        .map(|t| {
            let reason_name = reasons
                .get(
                    fa_journal::period::reason_scope_of(t.from, t.to),
                    t.reason_code,
                )
                .map(|r| r.name.as_str());
            obj(vec![
                ("control_entry", s(format!("{:032x}", t.entry_vid.0))),
                ("from", s(t.from.name())),
                ("to", s(t.to.name())),
                ("reason_code", Json::Int(i128::from(t.reason_code))),
                ("reason", reason_name.map_or(Json::Null, s)),
                ("principal", s(format!("{:032x}", t.principal_ref.0))),
                ("approvals", Json::Int(t.approvals.len() as i128)),
                ("effective_date", s(t.effective_date.render())),
                ("recorded_at", Json::Int(i128::from(t.recorded_at.0))),
            ])
        })
        .collect();

    let classes = fa_registry::EntryClasses::embedded()
        .map_err(|e| Fail::Internal(format!("entry_classes.toml: {e}")))?;
    let matrix = fa_registry::Admissibility::embedded(&classes)
        .map_err(|e| Fail::Internal(format!("admissibility.toml: {e}")))?;
    let opening_date = book.spec()?.opening_date;
    let pre_opening = matrix
        .pre_opening()
        .is_some_and(|r| r.governs(period.kind, period.end, opening_date));
    let mut admissible_classes = Vec::new();
    for c in classes.posting() {
        let decision = fa_journal::decide_admissibility_cell(
            &matrix,
            &c.name,
            period.state,
            fa_registry::DispositionFamily::Standard,
            period.kind,
            pre_opening,
        )
        .unwrap_or(fa_registry::Decision::Refuse);
        admissible_classes.push(explain_admissibility_cell_json(
            &c.name,
            period.state,
            &decision,
        ));
    }

    let human = format!(
        "period {} ({}, {}) · {}..={} · FY{} · {} transition(s)",
        period.code,
        kind_name(period.kind),
        period.state.name(),
        period.start.render(),
        period.end.render(),
        period.fiscal_year,
        transitions_raw.len()
    );
    out.event(
        "period_explained",
        vec![
            ("code", s(&period.code)),
            ("kind", s(kind_name(period.kind))),
            ("state", s(period.state.name())),
            ("start", s(period.start.render())),
            ("end", s(period.end.render())),
            ("fiscal_year", Json::Int(i128::from(period.fiscal_year))),
            ("transitions", Json::Arr(transitions)),
            ("admissible_classes", Json::Arr(admissible_classes)),
        ],
        &human,
    );
    Ok(())
}

fn explain_register_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let example = "fa explain register 1000 --period FY2026-P01 [--unit USD] [--as-known-at HEAD|<seq>] --book <dir>";
    let code = args
        .positional
        .get(2)
        .ok_or_else(|| usage("explain register needs an account code", example))?;
    if let Some(extra) = args.positional.get(3) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    if args.flag_all("--period").len() > 1 {
        return Err(usage(
            "explain register explains one period at a time",
            example,
        ));
    }
    let period = args.require("--period", "FY2026-P01")?;
    let who = ctx.principal(args);
    let read_cap = ctx.capability(args, &["read"])?;
    let book = ctx.books.open_admitted(args, |book| {
        book.read_scope(who, &read_cap)??;
        Ok(())
    })?;
    let (known_at, _) = known_at_flag(args, &book, out)?;
    // It reaches its one period at its frontier, and verifies the stored
    // cells as they are at the head, so a known-at pin refuses it
    // (doctrine 8, fa-0x0).
    {
        let scope = book.read_scope(who, &read_cap)??;
        scope.admit_periods(&[period], known_at)??;
        scope.admit_periods(&[period], None)??;
    }
    let unit_filter: Option<(u32, String)> = match args.flag("--unit") {
        None => None,
        Some(ucode) => {
            let uid = book.context().units.lookup(ucode).ok_or_else(|| {
                usage(
                    format!("unknown unit `{ucode}`"),
                    "pass a registered unit code such as USD",
                )
            })?;
            Some((uid.0, ucode.to_string()))
        }
    };
    let account = account_vid(book.context().book_id, code);
    let explain_error = |error| explanation_selection_error(&book, code, period, known_at, error);
    let ex = book
        .explain_balance(account, period, known_at)
        .map_err(explain_error)?;
    validate_balance_explanation_units(&ex, &book.context().units)?;
    let v = book.verify_registers(period)?;
    out.known_at(ex.known_at);
    out.effective(format!("period:{}", ex.period));

    let units = &book.context().units;
    let render = |unit: u32, m: i128| render_amount(Amount::new(fa_money::UnitId(unit), m), units);
    let unit_code = |unit: u32| registered_unit_code(fa_money::UnitId(unit), units);
    let account_row = &ex.account_row;
    let type_name = AccountType(account_row.account_type).name().unwrap_or("?");
    let reasons =
        ReasonCodes::embedded().map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;

    let mut by_unit: std::collections::BTreeMap<u32, [i128; 6]> = std::collections::BTreeMap::new();
    for c in &ex.cells {
        if unit_filter
            .as_ref()
            .is_none_or(|(u, _)| *u == c.key.unit_id)
        {
            let row = by_unit.entry(c.key.unit_id).or_insert([0; 6]);
            row[0] = c.debits;
            row[1] = c.credits;
            row[2] = i128::from(c.entry_count);
        }
    }
    for c in &ex.pending {
        if unit_filter
            .as_ref()
            .is_none_or(|(u, _)| *u == c.key.unit_id)
        {
            let row = by_unit.entry(c.key.unit_id).or_insert([0; 6]);
            row[3] = c.debits;
            row[4] = c.credits;
            row[5] = i128::from(c.entry_count);
        }
    }
    let cells: Vec<Json> = by_unit
        .iter()
        .map(|(u, [d, c, n, pd, pc, pn])| {
            Ok(obj(vec![
                ("unit", s(unit_code(*u)?)),
                ("debits", s(render(*u, *d)?)),
                ("credits", s(render(*u, *c)?)),
                ("net", s(render(*u, d - c)?)),
                ("entry_count", Json::Int(*n)),
                ("debits_pending", s(render(*u, *pd)?)),
                ("credits_pending", s(render(*u, *pc)?)),
                ("pending_count", Json::Int(*pn)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    let contributions: Vec<Json> = ex
        .contributions
        .iter()
        .filter(|c| unit_filter.as_ref().is_none_or(|(u, _)| *u == c.unit_id))
        .map(|c| {
            Ok(obj(vec![
                ("entry", s(format!("{:032x}", c.entry.0))),
                ("entry_digest", s(hex(&c.entry_digest))),
                ("class", s(c.class.name().unwrap_or("?"))),
                ("effective_date", s(c.effective_date.render())),
                ("recorded_at", Json::Int(i128::from(c.recorded_at.0))),
                ("ordinal", Json::Int(i128::from(c.ordinal))),
                ("side", s(side_name(c.side))),
                ("amount", s(render(c.unit_id, c.mantissa)?)),
                ("column", s(c.column.name())),
                (
                    "released_at",
                    c.released_at
                        .map_or(Json::Null, |r| Json::Int(i128::from(r.0))),
                ),
                (
                    "resolves",
                    c.resolves
                        .map_or(Json::Null, |v| s(format!("{:032x}", v.0))),
                ),
                (
                    "supersedes",
                    Json::Arr(
                        c.supersedes
                            .iter()
                            .map(|l| lineage_json(l, &reasons))
                            .collect(),
                    ),
                ),
                (
                    "evidence",
                    Json::Arr(
                        c.evidence
                            .iter()
                            .map(|e| {
                                obj(vec![
                                    ("document_oid", s(hex(&e.document_oid.0))),
                                    ("doc_commit", s(hex(&e.doc_commit))),
                                    ("role", Json::Int(i128::from(e.role))),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]))
        })
        .collect::<Result<_, Fail>>()?;

    let cache_status = match v.cache_status {
        fa_registers::CacheStatus::Uninitialized => "uninitialized",
        fa_registers::CacheStatus::Verified => "verified",
        fa_registers::CacheStatus::Corrupt => "corrupt",
    };
    let steward = fa_policy::Steward::embedded().map_err(|e| Fail::Internal(e.to_string()))?;
    let decision_card = fa_policy::decide_register_checkpoint_cadence(
        Some(steward.policy_oid),
        steward.policy_oid,
        &ex.period,
        v.verified_through.map_or(0, |s| s.0),
        ex.known_at.0,
        v.lag_entries as u64,
        ex.contributions.len() as u64,
    );
    let decision_card_bytes = decision_card
        .canonical_bytes()
        .map_err(|e| Fail::Internal(e.to_string()))?;
    let decision_card_digest = decision_card
        .digest()
        .map_err(|e| Fail::Internal(e.to_string()))?;
    let human = format!(
        "register {} {} ({type_name}) in {} · cache_status={cache_status} · green={} · stale={} · lag={} · decision_card={}",
        account_row.code,
        account_row.name,
        ex.period,
        v.is_green(),
        v.stale,
        v.lag_entries,
        hex(&decision_card_digest)
    );
    out.event(
        "register_explained",
        vec![
            ("account", s(&account_row.code)),
            ("account_vid", s(format!("{:032x}", account_row.vid.0))),
            ("name", s(&account_row.name)),
            ("type", s(type_name)),
            ("period", s(&ex.period)),
            (
                "unit",
                unit_filter.as_ref().map_or(Json::Null, |(_, code)| s(code)),
            ),
            ("known_at", Json::Int(i128::from(ex.known_at.0))),
            (
                "watermark",
                ex.watermark
                    .map_or(Json::Null, |w| Json::Int(i128::from(w.0))),
            ),
            ("fold_digest", s(hex(&ex.fold_digest))),
            ("green", Json::Bool(v.is_green())),
            ("cache_status", s(cache_status)),
            (
                "verified_through",
                v.verified_through
                    .map_or(Json::Null, |s| Json::Int(i128::from(s.0))),
            ),
            ("stale", Json::Bool(v.stale)),
            ("lag_entries", Json::Int(v.lag_entries as i128)),
            ("decision_card_digest", s(hex(&decision_card_digest))),
            ("decision_card_bytes", s(hex(&decision_card_bytes))),
            ("cells", Json::Arr(cells)),
            ("contributions", Json::Arr(contributions)),
        ],
        &human,
    );
    Ok(())
}

/// `fa explain balance <account> --period <code> [--as-known-at HEAD|<seq>]`.
fn explain_balance_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let example = "fa explain balance 1000 --period FY2026-P03 --book <dir>";
    let code = args
        .positional
        .get(2)
        .ok_or_else(|| usage("explain balance needs an account code", example))?;
    if let Some(extra) = args.positional.get(3) {
        return Err(usage(format!("unexpected argument `{extra}`"), example));
    }
    if args.flag_all("--period").len() > 1 {
        return Err(usage(
            "explain balance explains one period at a time",
            "fa explain balance <account> --period <code>; fa tb for several periods",
        ));
    }
    if args.flag_all("--certificate-out").len() > 1 {
        return Err(usage(
            "--certificate-out may be supplied only once",
            "fa explain balance --help",
        ));
    }
    let period = args.require("--period", "FY2026-P03")?;
    let view = crate::issuance::reported_view(
        args,
        "fa explain balance 1000 --period FY2026-P03 --as-originally-reported | --as-issued-to <audience> | --as-reported-in C:<oid>",
    )?;
    let who = ctx.principal(args);
    let read_cap = ctx.capability(args, &["read"])?;
    let certify_cap = if args.switch("--certify") || args.flag("--certificate-out").is_some() {
        Some(read_cap.clone())
    } else {
        None
    };
    let mut book = if let Some(capability) = certify_cap.as_ref() {
        ctx.books.open_admitted(args, |book| {
            prepare_native_certificate_history(book, capability, None)
        })?
    } else {
        ctx.books.open_admitted(args, |book| {
            book.read_scope(who, &read_cap)??;
            Ok(())
        })?
    };
    let (mut known_at, requested_utc_ns) = known_at_flag(args, &book, out)?;
    let account = account_vid(book.context().book_id, code);
    if let Some(view) = &view {
        // The period's scope is judged before its issuances, transitions or
        // certificate are read; the pinned coordinate is judged again below.
        book.read_scope(who, &read_cap)??.admit_report(
            &ReportSelection::ExplainBalance {
                account,
                period: period.to_string(),
            },
            known_at,
        )??;
        known_at = Some(crate::issuance::reported_known_at(
            &book, &read_cap, view, period,
        )?);
    }
    if let Some(capability) = certify_cap.as_ref() {
        prepare_native_certificate_history(&mut book, capability, known_at)?;
    }
    // Judged against the scope caveats before the query is constructed
    // (doctrine 8, fa-0x0): the explanation reaches its one period.
    book.read_scope(who, &read_cap)??.admit_report(
        &ReportSelection::ExplainBalance {
            account,
            period: period.to_string(),
        },
        known_at,
    )??;
    let explain_error = |error| explanation_selection_error(&book, code, period, known_at, error);
    let (ex, certificate) = if args.switch("--certify") || args.flag("--certificate-out").is_some()
    {
        let selection = ReportSelection::ExplainBalance {
            account,
            period: period.to_string(),
        };
        let certified = match requested_utc_ns {
            Some(instant) => book.certify_report_at_instant(selection, instant),
            None => book.certify_report(selection, known_at),
        }
        .map_err(explain_error)??;
        out.time_selection(certified.certificate.time_selection.as_ref());
        let ReportOutput::ExplainBalance(ex) = certified.report else {
            return Err(Fail::Internal(
                "explanation certification returned another report kind".into(),
            ));
        };
        (*ex, Some(certified.certificate))
    } else {
        (
            book.explain_balance(account, period, known_at)
                .map_err(explain_error)?,
            None,
        )
    };
    validate_balance_explanation_units(&ex, &book.context().units)?;
    let retained = certificate
        .as_ref()
        .zip(certify_cap.as_ref())
        .map(|(certificate, cap)| {
            notary::retain_report_certificate(&mut book, &ctx.files, args, certificate, cap)
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    render_balance_explanation(out, &book, &ex, digest.as_deref())?;
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        notary::emit_report_certificate(out, args, certificate, &bytes, &retained);
    }
    Ok(())
}

/// Suggestions may consult today's chart only after the historical read has
/// refused. Successful reports resolve identity and metadata at known-at.
fn explanation_selection_error(
    book: &Book,
    code: &str,
    period: &str,
    known_at: Option<CommitSeq>,
    error: BookError,
) -> Fail {
    if !matches!(
        &error,
        BookError::Registers(fa_registers::RegisterError::InvalidSelection(_))
    ) {
        return error.into();
    }
    if let Ok(periods) = book.periods()
        && !periods.iter().any(|row| row.code == period)
    {
        let codes: Vec<&str> = periods.iter().map(|row| row.code.as_str()).collect();
        return usage(
            format!("no period `{period}` in this book"),
            match nearest(period, &codes) {
                Some(near) => format!("did you mean --period {near}? (fa period list)"),
                None => "fa period list --book <dir>".to_string(),
            },
        );
    }
    if let Ok(accounts) = book.accounts() {
        let Some(account) = accounts.iter().find(|row| row.code == code) else {
            let codes: Vec<&str> = accounts.iter().map(|row| row.code.as_str()).collect();
            return usage(
                format!("no account `{code}` in this book's chart"),
                match nearest(code, &codes) {
                    Some(near) => format!("did you mean `{near}`? (fa chart list)"),
                    None => "fa chart list --book <dir>".to_string(),
                },
            );
        };
        if let Some(seq) = known_at
            && seq < account.created_at
        {
            return usage(
                format!(
                    "account `{code}` does not exist as known at {}: the chart created it at sequence {}",
                    seq.0, account.created_at.0
                ),
                format!("--as-known-at {} or later (or HEAD)", account.created_at.0),
            );
        }
        if !account.is_leaf {
            return usage(
                format!(
                    "account `{code}` is a summary account: an explanation lists one leaf account's postings, and a summary's balance is the roll-up of its leaves"
                ),
                format!(
                    "fa tb --period {period} --summary --root {code} --json (the roll-up with its leaf drilldown), then explain one of its leaves"
                ),
            );
        }
    }
    error.into()
}

/// Cells, released contributions, and historical changes can name different
/// units. Validate every one before retaining the explanation's certificate.
fn validate_balance_explanation_units(
    ex: &fa_registers::explain::BalanceExplanation,
    units: &fa_money::UnitRegistry,
) -> Result<(), Fail> {
    for unit in ex
        .cells
        .iter()
        .map(|cell| cell.key.unit_id)
        .chain(ex.pending.iter().map(|cell| cell.key.unit_id))
        .chain(
            ex.contributions
                .iter()
                .map(|contribution| contribution.unit_id),
        )
        .chain(ex.history.iter().map(|change| change.unit_id))
    {
        registered_unit_code(fa_money::UnitId(unit), units)?;
    }
    Ok(())
}

/// Original and replay share the exact contribution and history rendering.
pub(crate) fn render_balance_explanation(
    out: &Out,
    book: &Book,
    ex: &fa_registers::explain::BalanceExplanation,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    validate_balance_explanation_units(ex, &book.context().units)?;
    out.known_at(ex.known_at);
    out.effective(format!("period:{}", ex.period));
    let account = &ex.account_row;
    let units = &book.context().units;
    let render = |unit: u32, m: i128| render_amount(Amount::new(fa_money::UnitId(unit), m), units);
    let unit_code = |unit: u32| registered_unit_code(fa_money::UnitId(unit), units);
    let type_name = AccountType(account.account_type).name().unwrap_or("?");
    let reasons =
        ReasonCodes::embedded().map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
    // One row per unit with both columns, like a materialized register row.
    let mut by_unit: std::collections::BTreeMap<u32, [i128; 6]> = std::collections::BTreeMap::new();
    for c in &ex.cells {
        let row = by_unit.entry(c.key.unit_id).or_insert([0; 6]);
        row[0] = c.debits;
        row[1] = c.credits;
        row[2] = i128::from(c.entry_count);
    }
    for c in &ex.pending {
        let row = by_unit.entry(c.key.unit_id).or_insert([0; 6]);
        row[3] = c.debits;
        row[4] = c.credits;
        row[5] = i128::from(c.entry_count);
    }
    // Prepare every amount before emitting either format. In particular,
    // a corrupt later contribution must not follow a partial human report.
    let cells: Vec<Json> = by_unit
        .iter()
        .map(|(u, [d, c, n, pd, pc, pn])| {
            Ok(obj(vec![
                ("unit", s(unit_code(*u)?)),
                ("debits", s(render(*u, *d)?)),
                ("credits", s(render(*u, *c)?)),
                ("net", s(render(*u, d - c)?)),
                ("entry_count", Json::Int(*n)),
                ("debits_pending", s(render(*u, *pd)?)),
                ("credits_pending", s(render(*u, *pc)?)),
                ("pending_count", Json::Int(*pn)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    let contributions: Vec<Json> = ex
        .contributions
        .iter()
        .map(|c| {
            Ok(obj(vec![
                ("entry", s(format!("{:032x}", c.entry.0))),
                ("entry_digest", s(hex(&c.entry_digest))),
                ("class", s(c.class.name().unwrap_or("?"))),
                ("effective_date", s(c.effective_date.render())),
                ("recorded_at", Json::Int(i128::from(c.recorded_at.0))),
                ("ordinal", Json::Int(i128::from(c.ordinal))),
                ("side", s(side_name(c.side))),
                ("amount", s(render(c.unit_id, c.mantissa)?)),
                ("column", s(c.column.name())),
                (
                    "released_at",
                    c.released_at
                        .map_or(Json::Null, |r| Json::Int(i128::from(r.0))),
                ),
                (
                    "resolves",
                    c.resolves
                        .map_or(Json::Null, |v| s(format!("{:032x}", v.0))),
                ),
                (
                    "supersedes",
                    Json::Arr(
                        c.supersedes
                            .iter()
                            .map(|l| lineage_json(l, &reasons))
                            .collect(),
                    ),
                ),
                (
                    "evidence",
                    Json::Arr(
                        c.evidence
                            .iter()
                            .map(|e| {
                                obj(vec![
                                    ("document_oid", s(hex(&e.document_oid.0))),
                                    ("doc_commit", s(hex(&e.doc_commit))),
                                    ("role", Json::Int(i128::from(e.role))),
                                ])
                            })
                            .collect(),
                    ),
                ),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    let history: Vec<Json> = ex
        .history
        .iter()
        .map(|h| {
            Ok(obj(vec![
                ("recorded_at", Json::Int(i128::from(h.recorded_at.0))),
                ("unit", s(unit_code(h.unit_id)?)),
                ("debits", s(render(h.unit_id, h.debits)?)),
                ("credits", s(render(h.unit_id, h.credits)?)),
                ("debits_pending", s(render(h.unit_id, h.debits_pending)?)),
                ("credits_pending", s(render(h.unit_id, h.credits_pending)?)),
            ]))
        })
        .collect::<Result<_, Fail>>()?;
    if out.json {
        out.event_with_certificate(
            "balance_explained",
            vec![
                ("account", s(&account.code)),
                ("account_vid", s(format!("{:032x}", account.vid.0))),
                ("name", s(&account.name)),
                ("type", s(type_name)),
                ("period", s(&ex.period)),
                ("known_at", Json::Int(i128::from(ex.known_at.0))),
                (
                    "watermark",
                    ex.watermark
                        .map_or(Json::Null, |w| Json::Int(i128::from(w.0))),
                ),
                ("fold_digest", s(hex(&ex.fold_digest))),
                ("certificate", certificate.map_or(Json::Null, s)),
                ("cells", Json::Arr(cells)),
                ("contributions", Json::Arr(contributions)),
                ("history", Json::Arr(history)),
                (
                    "last_changed_at",
                    ex.last_changed_at()
                        .map_or(Json::Null, |w| Json::Int(i128::from(w.0))),
                ),
            ],
            "",
            certificate,
        );
        return Ok(());
    }
    out.line(format!(
        "balance of {} {} ({type_name}) in {} · known at {} · fold digest {} · watermark {}",
        account.code,
        account.name,
        ex.period,
        ex.known_at.0,
        hex(&ex.fold_digest[..8]),
        ex.watermark.map_or("none".to_string(), |w| w.0.to_string())
    ));
    // Only an account no leg ever touched in this period is empty: a
    // reservation released since still has its legs and its history.
    if ex.contributions.is_empty() {
        out.line(format!("no legs on this account in {}", ex.period));
        return Ok(());
    }
    if by_unit.is_empty() {
        out.line("nothing posted or pending: every leg below is a released reservation");
    } else {
        out.line(out.style().header(&format!(
            "{:<6} {:>20} {:>20} {:>20} {:>7} {:>20} {:>20}",
            "unit",
            "posted debits",
            "posted credits",
            "net",
            "entries",
            "pending debits",
            "pending credits"
        )));
        for (u, [d, c, n, pd, pc, _]) in &by_unit {
            out.line(format!(
                "{:<6} {:>20} {:>20} {:>20} {:>7} {:>20} {:>20}",
                unit_code(*u)?,
                render(*u, *d)?,
                render(*u, *c)?,
                render(*u, d - c)?,
                n,
                render(*u, *pd)?,
                render(*u, *pc)?
            ));
        }
    }
    out.line("contributions (by recorded sequence)");
    out.line(out.style().header(&format!(
        "{:>9} {:<32} {:>3} {:<12} {:<10} {:<6} {:>20} column",
        "recorded", "entry", "leg", "class", "effective", "side", "amount"
    )));
    for c in &ex.contributions {
        out.line(format!(
            "{:>9} {:<32} {:>3} {:<12} {:<10} {:<6} {:>20} {}{}",
            c.recorded_at.0,
            format!("{:032x}", c.entry.0),
            c.ordinal,
            c.class.name().unwrap_or("?"),
            c.effective_date.render(),
            side_name(c.side),
            render(c.unit_id, c.mantissa)?,
            c.column.name(),
            c.released_at
                .map_or(String::new(), |r| format!(" at {}", r.0))
        ));
    }
    if let Some(last) = ex.last_changed_at() {
        out.line(format!("last changed at recorded sequence {}", last.0));
    }
    Ok(())
}

/// A period's register cells fold every account of the book, and
/// maintaining them publishes: current whole-book `read` and `verify`
/// authority on trunk is admitted before the book is observed, exactly as
/// `fa verify periods` admits it, so a revoked, expired or scoped token
/// neither reads a fold nor advances the cache.
fn admit_registers(
    book: &Book,
    principal: VId,
    capability: &Capability,
    what: &str,
) -> Result<(), Fail> {
    fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| fa_policy::require(capability, fa_policy::Op::Verify, what))
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    let _ = book.read_scope(principal, capability)??;
    Ok(())
}

fn registers_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    match args.positional.get(1).map(String::as_str) {
        Some("advance") => {
            let principal = ctx.principal(args);
            let capability = ctx.capability(args, &["read", "verify"])?;
            let mut book = ctx.books.open_admitted(args, |book| {
                admit_registers(
                    book,
                    principal,
                    &capability,
                    "maintaining derived registers",
                )
            })?;
            let periods = selected_periods(args, &book)?;
            for p in &periods {
                out.effective(format!("period:{p}"));
                let advanced = match book.advance_registers(p) {
                    Ok(advanced) => advanced,
                    Err(BookError::Registers(fa_registers::RegisterError::ProjectionDrift(
                        why,
                    ))) => {
                        return Err(Fail::Verification {
                            message: format!("register cache drift in {p}: {why}"),
                            detail: obj(vec![("period", s(p)), ("problem", s(&why))]),
                            cite: Some("FA-INV-04 (registers are derived from the journal)".into()),
                            fix: Some(format!(
                                "run `fa verify registers --period {p} --json` with the same --book and retain the finding; if repair is intended, run `fa registers materialize --period {p} --yes --json`"
                            )),
                        });
                    }
                    Err(error) => return Err(error.into()),
                };
                let fold = &advanced.fold;
                out.at_book(&book)?;
                out.event(
                    "registers_advanced",
                    vec![
                        ("period", s(p)),
                        ("from", Json::Int(i128::from(advanced.from.0))),
                        ("through", Json::Int(i128::from(advanced.through.0))),
                        (
                            "recorded_at",
                            if advanced.wrote {
                                Json::Int(i128::from(advanced.published_at.0))
                            } else {
                                Json::Null
                            },
                        ),
                        ("entries_decoded", Json::Int(advanced.entries_decoded as i128)),
                        ("rebuilt", Json::Bool(advanced.rebuilt)),
                        ("wrote", Json::Bool(advanced.wrote)),
                        ("cells", Json::Int(fold.cells.len() as i128)),
                        ("pending_cells", Json::Int(fold.pending.len() as i128)),
                        ("entries", Json::Int(fold.entries as i128)),
                        (
                            "watermark",
                            fold.watermark
                                .map_or(Json::Null, |w| Json::Int(i128::from(w.0))),
                        ),
                        ("fold_digest", s(hex(&fold.fold_digest))),
                    ],
                    &format!(
                        "{p}: registers through {}, {} entries decoded, {} posted cells, {} pending cells ({})",
                        advanced.through.0,
                        advanced.entries_decoded,
                        fold.cells.len(),
                        fold.pending.len(),
                        if !advanced.wrote {
                            "already current"
                        } else if advanced.rebuilt {
                            "rebuilt from journal"
                        } else {
                            "advanced"
                        }
                    ),
                );
            }
            Ok(())
        }
        Some("materialize") => {
            let principal = ctx.principal(args);
            let capability = ctx.capability(args, &["read", "verify"])?;
            let mut book = ctx.books.open_admitted(args, |book| {
                admit_registers(
                    book,
                    principal,
                    &capability,
                    "materializing derived registers",
                )
            })?;
            let periods = selected_periods(args, &book)?;
            // Rematerializing over cells a period already has rewrites them
            // (verbs.toml [[dangerous]]): every period is checked, and the
            // whole command refused, before anything is written.
            for p in &periods {
                let v = match book.verify_registers(p) {
                    Ok(v) => v,
                    Err(BookError::Registers(fa_registers::RegisterError::ProjectionDrift(_)))
                    | Err(BookError::Registers(fa_registers::RegisterError::Kernel(
                        fa_journal::KernelError::Corrupt(_),
                    ))) => {
                        // Malformed derived values still require explicit
                        // replacement authorization. The rebuild below must
                        // independently fold valid journal payloads.
                        gate(
                            out,
                            args,
                            "registers",
                            Some("materialize"),
                            &Condition::ExistingCells,
                        )?;
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                let existing = v.stored_digest.is_some()
                    || v.drift
                        .iter()
                        .chain(&v.pending_drift)
                        .any(|d| d.stored.is_some());
                if existing {
                    gate(
                        out,
                        args,
                        "registers",
                        Some("materialize"),
                        &Condition::ExistingCells,
                    )?;
                }
            }
            for p in &periods {
                let (fold, seq) = book.materialize_registers(p)?;
                out.at_book(&book)?;
                out.effective(format!("period:{p}"));
                out.event(
                    "registers_materialized",
                    vec![
                        ("period", s(p)),
                        ("cells", Json::Int(fold.cells.len() as i128)),
                        ("pending_cells", Json::Int(fold.pending.len() as i128)),
                        ("entries", Json::Int(fold.entries as i128)),
                        (
                            "watermark",
                            fold.watermark
                                .map_or(Json::Null, |w| Json::Int(i128::from(w.0))),
                        ),
                        ("fold_digest", s(hex(&fold.fold_digest))),
                        ("recorded_at", Json::Int(i128::from(seq.0))),
                    ],
                    &format!(
                        "{p}: {} posted cells from {} posting entries, {} pending cells (fold digest {})",
                        fold.cells.len(),
                        fold.entries,
                        fold.pending.len(),
                        hex(&fold.fold_digest[..8])
                    ),
                );
            }
            Ok(())
        }
        other => Err(unhandled("registers", other)),
    }
}

/// Explicit recovery from verified native history. A dry run previews the
/// exact changes; publishing needs --yes (gated from argv by verbs.toml
/// [[dangerous]] before this handler runs) and rechecks the reviewed basis.
fn recover_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("outcomes") => outcome_recovery::recover(ctx, args),
        Some("projections") => {
            let out = &ctx.out;
            if args.positional.len() != 2 {
                return Err(usage(
                    "unexpected recover projections argument",
                    "fa recover projections --dry-run --book <dir> --json",
                ));
            }
            let dry_run = args.switch("--dry-run");
            if args.flag_all("--basis").len() > 1 {
                return Err(usage(
                    "--basis may be supplied only once",
                    "fa recover projections --yes --basis <the dry run's basis> --json",
                ));
            }
            let basis = args
                .flag("--basis")
                .map(|text| {
                    text.parse::<u64>().map(CommitSeq).map_err(|_| {
                        usage(
                            "--basis is the recorded sequence a dry run previewed",
                            "fa recover projections --yes --basis <the dry run's basis> --json",
                        )
                    })
                })
                .transpose()?;
            if dry_run && (args.switch("--yes") || basis.is_some()) {
                return Err(usage(
                    "--dry-run previews and writes nothing; --yes and --basis publish",
                    "fa recover projections --dry-run --json, then fa recover projections --yes --basis <its basis> --json",
                ));
            }
            let principal = ctx.principal(args);
            let capability = ctx.capability(args, &["read", "verify", "schema_change"])?;
            let mut book = ctx.books.open_admitted(args, |book| {
                admit_whole_book_read(
                    book,
                    &capability,
                    &[fa_policy::Op::Verify, fa_policy::Op::SchemaChange],
                    "rebuilding leg projections",
                )
            })?;
            let before = book.head()?;
            let outcome = if dry_run {
                book.prepare_projection_rebuild(principal, &capability)
                    .map(|prepared| prepared.map(|p| p.preview().clone()))
            } else if let Some(basis) = basis {
                // The publication is the previewed repair: prepared again
                // at the head, refused unless that head is the preview's.
                match book.prepare_projection_rebuild(principal, &capability) {
                    Ok(Ok(prepared)) if prepared.preview().basis != basis => {
                        return Err(Refusal::new(
                            fa_journal::refusal::code::PLAN_INVALIDATED,
                            exit::CONFLICT,
                            format!(
                                "the head moved from the previewed basis {} to {}; this is not the repair that was previewed",
                                basis.0,
                                prepared.preview().basis.0
                            ),
                            "plan §4.2, FA-INV-16 (a recovery publishes the repair it previewed)",
                            "preview again with fa recover projections --dry-run --json, retain it, and publish with --yes --basis <its basis>",
                        )
                        .into());
                    }
                    Ok(Ok(prepared)) => {
                        book.publish_projection_rebuild(principal, &capability, prepared)
                    }
                    Ok(Err(refusal)) => Ok(Err(refusal)),
                    Err(error) => Err(error),
                }
            } else {
                book.rebuild_projections(principal, &capability)
            };
            let report = match outcome {
                Ok(report) => report?,
                // The repair was published, but the independent checks still
                // find drift: report the commit, never "nothing was repaired".
                Err(BookError::Kernel(fa_journal::KernelError::Corrupt(problem)))
                    if book.head()? != before =>
                {
                    let published = book.head()?;
                    return Err(Fail::Verification {
                        message: format!(
                            "the repair was published at sequence {}, but projections or open items still do not verify: {problem}",
                            published.0
                        ),
                        detail: obj(vec![
                            ("problem", s(&problem)),
                            ("basis", Json::Int(i128::from(before.0))),
                            ("recorded_at", Json::Int(i128::from(published.0))),
                        ]),
                        cite: Some("FA-INV-16 (leg projections equal entry payloads)".into()),
                        fix: Some("do not post; retain fa verify projections --json and fa verify open-items --json at this head and preserve the book for inspection".into()),
                    });
                }
                // Orphans, occupied identities, incompatible endpoints: nothing
                // is repaired around them, and nothing was published.
                Err(BookError::Kernel(fa_journal::KernelError::Corrupt(problem))) => {
                    return Err(Fail::Verification {
                        message: format!("leg projections cannot be recovered from the journal: {problem}"),
                        detail: obj(vec![("problem", s(&problem))]),
                        cite: Some("FA-INV-16 (leg projections equal entry payloads)".into()),
                        fix: Some("retain this finding with fa verify projections --json and fa verify open-items --json; preserve the book, since the journal does not determine this repair".into()),
                    });
                }
                Err(error) => return Err(error.into()),
            };
            out.at_book(&book)?;
            let changes = report.legs_created
                + report.legs_repaired
                + report.edges_created
                + report.edges_repaired
                + report.edges_retired;
            out.event(
                "projections_rebuilt",
                vec![
                    ("dry_run", Json::Bool(dry_run)),
                    ("basis", Json::Int(i128::from(report.basis.0))),
                    (
                        "recorded_at",
                        if report.wrote {
                            Json::Int(i128::from(report.published_at.0))
                        } else {
                            Json::Null
                        },
                    ),
                    ("wrote", Json::Bool(report.wrote)),
                    ("entries_checked", Json::Int(report.entries_checked as i128)),
                    ("legs_checked", Json::Int(report.legs_checked as i128)),
                    ("legs_created", Json::Int(report.legs_created as i128)),
                    ("legs_repaired", Json::Int(report.legs_repaired as i128)),
                    ("edges_created", Json::Int(report.edges_created as i128)),
                    ("edges_repaired", Json::Int(report.edges_repaired as i128)),
                    ("edges_retired", Json::Int(report.edges_retired as i128)),
                ],
                &format!(
                    "{} {} projection changes over {} entries and {} legs at {}{}",
                    if dry_run {
                        "would publish"
                    } else {
                        "published"
                    },
                    changes,
                    report.entries_checked,
                    report.legs_checked,
                    report.basis.0,
                    if report.wrote {
                        format!(" (recorded at {})", report.published_at.0)
                    } else if dry_run && changes > 0 {
                        format!(
                            "; publish exactly this repair with fa recover projections --yes --basis {}",
                            report.basis.0
                        )
                    } else {
                        "; projections already equal the journal".to_string()
                    }
                ),
            );
            Ok(())
        }
        other => Err(unhandled("recover", other)),
    }
}

fn entry_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    match args.positional.get(1).map(String::as_str) {
        Some("show") => {
            let vid_s = args.positional.get(2).ok_or_else(|| {
                usage(
                    "entry show needs a vid (32 hex)",
                    "fa entry show <vid> --book <dir>",
                )
            })?;
            let vid = u128::from_str_radix(vid_s, 16).map_err(|_| {
                usage(
                    format!("`{vid_s}` is not a 32-hex vid"),
                    "use the `vid` from the posted event",
                )
            })?;
            let who = ctx.principal(args);
            let capability = ctx.capability(args, &["read"])?;
            let book = ctx.books.open_admitted(args, |book| {
                book.read_scope(who, &capability)??;
                Ok(())
            })?;
            let units = &book.context().units;
            let seal_key = &book.context().seal_key;
            // The entry's period is known only once it is read, so a
            // `periods` or `effective` caveat refuses the read before it,
            // and a known-at pin refuses the head (doctrine 8, fa-0x0).
            match book
                .read_scope(who, &capability)??
                .read_entry(VId(vid), None)??
            {
                None => {
                    // Every field is always present; absence is spelled null.
                    let mut fields = vec![("found", Json::Bool(false)), ("vid", s(vid_s))];
                    for absent in [
                        "class",
                        "effective_date",
                        "document_date",
                        "recorded_at",
                        "entry_digest",
                        "proposal_digest",
                        "description",
                        "approvals",
                        "legs",
                        "supersedes",
                    ] {
                        fields.push((absent, Json::Null));
                    }
                    out.event("entry", fields, &format!("no entry {vid_s}"));
                    Ok(())
                }
                Some((entry, seq)) => {
                    let reasons = ReasonCodes::embedded()
                        .map_err(|e| Fail::Internal(format!("reason_codes.toml: {e}")))?;
                    let description = untrusted_text_json(
                        entry
                            .proposal
                            .description
                            .open(seal_key, fa_model::limits::MAX_DESCRIPTION_BYTES)
                            .ok(),
                        format!("E:{vid_s}"),
                    );
                    let legs: Vec<Json> = entry
                        .proposal
                        .legs
                        .iter()
                        .enumerate()
                        .map(|(idx, l)| {
                            let memo = untrusted_text_json(
                                l.memo.as_ref().and_then(|m| {
                                    m.open(seal_key, fa_model::limits::MAX_MEMO_BYTES).ok()
                                }),
                                format!("E:{vid_s}:L{idx}"),
                            );
                            Ok(obj(vec![
                                (
                                    "side",
                                    s(if l.side == Side::Debit {
                                        "debit"
                                    } else {
                                        "credit"
                                    }),
                                ),
                                ("account", s(format!("{:032x}", l.account_ref.0))),
                                ("amount", s(render_amount(l.amount, units)?)),
                                ("memo", memo),
                                (
                                    "dimensions",
                                    Json::Arr(
                                        l.dimension_set
                                            .iter()
                                            .map(|(dimension, value)| {
                                                obj(vec![
                                                    (
                                                        "dimension",
                                                        s(crate::dimension::code_of(*dimension)),
                                                    ),
                                                    ("value", s(format!("{:032x}", value.0))),
                                                ])
                                            })
                                            .collect(),
                                    ),
                                ),
                            ]))
                        })
                        .collect::<Result<_, Fail>>()?;
                    let fields = vec![
                        ("found", Json::Bool(true)),
                        ("vid", s(vid_s)),
                        ("class", s(entry.proposal.class.name().unwrap_or("?"))),
                        ("effective_date", s(entry.proposal.effective_date.render())),
                        (
                            "document_date",
                            entry
                                .proposal
                                .document_date
                                .map_or(Json::Null, |day| s(day.render())),
                        ),
                        ("recorded_at", Json::Int(i128::from(seq.0))),
                        ("entry_digest", s(hex(&entry.entry_digest))),
                        ("proposal_digest", s(hex(&entry.proposal_digest))),
                        ("description", description),
                        ("approvals", Json::Int(entry.approvals.len() as i128)),
                        ("legs", Json::Arr(legs)),
                        (
                            "supersedes",
                            Json::Arr(
                                entry
                                    .proposal
                                    .supersession
                                    .iter()
                                    .map(|l| lineage_json(l, &reasons))
                                    .collect(),
                            ),
                        ),
                    ];
                    let mut human = format!(
                        "{} {} recorded at {} · {} legs · entry_digest {}",
                        entry.proposal.class.name().unwrap_or("?"),
                        entry.proposal.effective_date.render(),
                        seq.0,
                        entry.proposal.legs.len(),
                        hex(&entry.entry_digest)
                    );
                    if let Some(day) = entry.proposal.document_date {
                        human.push_str(&format!("\ndocument dated {}", day.render()));
                    }
                    for link in &entry.proposal.supersession {
                        let reason = reasons
                            .get("supersession", link.reason_code)
                            .map_or("unregistered historical reason", |r| r.name.as_str());
                        human.push_str(&format!(
                            "\n{:?} {:032x} · reason {} ({reason})",
                            link.kind, link.target.vid.0, link.reason_code
                        ));
                    }
                    out.event("entry", fields, &human);
                    Ok(())
                }
            }
        }
        other => Err(unhandled("entry", other)),
    }
}

// ---- procedure: Lantern over the CLI (plan §11, Appendix D) ----------------

/// A procedure's registry or parameter refusal as a usage error naming the
/// registry; a version mismatch is a parity defect of this build.
fn lantern_usage(error: fa_lantern::LanternError) -> Fail {
    use fa_lantern::LanternError as E;
    match error {
        E::Unregistered { procedure } => usage(
            format!("`{procedure}` is not a registered procedure"),
            "fa procedure list --json names every registered procedure id",
        ),
        E::Parameter {
            procedure,
            name,
            message,
        } => usage(
            format!("{procedure}: {name}: {message}"),
            "fa procedure list --json shows each procedure's registered parameters and inputs",
        ),
        E::Version {
            procedure,
            code,
            registry,
        } => Fail::Internal(format!(
            "{procedure}: this build implements version {code} but procedures.toml registers {registry}"
        )),
        other => Fail::Internal(format!("procedure: {other}")),
    }
}

fn tie_break_name(t: &fa_registry::procedures::TieBreak) -> &'static str {
    use fa_registry::procedures::TieBreak as T;
    match t {
        T::EntryVid => "entry_vid",
        T::AccountVid => "account_vid",
        T::None => "none",
    }
}

fn calibration_name(c: &fa_registry::procedures::Calibration) -> &'static str {
    use fa_registry::procedures::Calibration as C;
    match c {
        C::Planted => "planted",
        C::Corpus => "corpus",
        C::Uncalibrated => "uncalibrated",
    }
}

/// A date given to a procedure that folds every posting regardless of
/// effective date is refused, never silently ignored (fa-9pjp): the
/// registry row's `effective_through` says which procedures take one.
pub(crate) fn refuse_untaken_date(
    id: &str,
    effective_through: Option<DateDay>,
) -> Result<(), Fail> {
    if effective_through.is_none() {
        return Ok(());
    }
    let procedures = fa_registry::procedures::Procedures::embedded()
        .map_err(|e| usage(e.to_string(), "fa procedure list --json"))?;
    match procedures.get(id).map(|row| row.effective_through) {
        Some(fa_registry::procedures::EffectiveThrough::NotTaken) => Err(usage(
            format!(
                "{id} folds every posting regardless of effective date; it does not take --effective-through"
            ),
            "omit --effective-through, or narrow the snapshot with --known-at <seq>; `fa procedure list --json` shows each procedure's effective_through",
        )),
        _ => Ok(()),
    }
}

/// Basis points as a percentage with two decimals: 9210 -> "92.10%".
fn bps_percent(bps: u32) -> String {
    format!("{}.{:02}%", bps / 100, bps % 100)
}

/// A corpus-calibrated procedure's measurement (lantern_calibration.toml,
/// fa-4psc): the seeds and scale it rests on, its counts, and the 95% Wilson
/// intervals of precision, recall and the clean-corpus flag rate.
fn procedure_calibration_json(
    calibration: &fa_registry::lantern_calibration::LanternCalibration,
    m: &fa_registry::lantern_calibration::CalibrationRow,
) -> Json {
    let n = |v: u64| Json::Int(i128::from(v));
    let bps = |v: u32| Json::Int(i128::from(v));
    obj(vec![
        ("seeds", n(calibration.seeds)),
        ("scale", n(calibration.scale)),
        ("true_positives", n(m.true_positives)),
        ("false_positives", n(m.false_positives)),
        ("false_negatives", n(m.false_negatives)),
        ("precision_bps", bps(m.precision_bps)),
        ("precision_lower_bps", bps(m.precision_lower_bps)),
        ("precision_upper_bps", bps(m.precision_upper_bps)),
        ("recall_bps", bps(m.recall_bps)),
        ("recall_lower_bps", bps(m.recall_lower_bps)),
        ("recall_upper_bps", bps(m.recall_upper_bps)),
        ("clean_entries", n(m.clean_entries)),
        ("clean_flagged", n(m.clean_flagged)),
        ("clean_rate_bps", bps(m.clean_rate_bps)),
        ("clean_rate_upper_bps", bps(m.clean_rate_upper_bps)),
    ])
}

fn procedure_row_json(
    row: &fa_registry::procedures::Procedure,
    calibration: &fa_registry::lantern_calibration::LanternCalibration,
) -> Json {
    let measured = calibration
        .row(&row.id)
        .map_or(Json::Null, |m| procedure_calibration_json(calibration, m));
    obj(vec![
        ("id", s(&row.id)),
        ("version", Json::Int(i128::from(row.version))),
        ("claim", s(row.claim.name())),
        ("evidence", s(&row.evidence)),
        ("tie_break", s(tie_break_name(&row.tie_break))),
        ("complexity", s(&row.complexity)),
        ("calibration", s(calibration_name(&row.calibration))),
        ("measured", measured),
        ("summary", s(&row.summary)),
        ("effective_through", s(row.effective_through.name())),
        (
            "inputs",
            Json::Arr(
                row.inputs
                    .iter()
                    .map(|i| {
                        obj(vec![
                            ("name", s(&i.name)),
                            ("kind", s(&i.kind)),
                            ("meaning", s(&i.meaning)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "parameters",
            Json::Arr(
                row.parameters
                    .iter()
                    .map(|p| {
                        obj(vec![
                            ("name", s(&p.name)),
                            ("default", Json::Int(p.default)),
                            ("meaning", s(&p.meaning)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ])
}

/// A typed citation as one object: `kind` plus the handle fields, every
/// field present and null when it does not apply.
fn cite_json(c: &fa_lantern::Cite) -> Json {
    use fa_lantern::Cite as C;
    let vid = |v: &VId| s(format!("{:032x}", v.0));
    let mut fields: Vec<(&str, Json)> = vec![
        ("entry", Json::Null),
        ("ordinal", Json::Null),
        ("account", Json::Null),
        ("period", Json::Null),
        ("document", Json::Null),
        ("principal", Json::Null),
        ("approval", Json::Null),
        ("attestation", Json::Null),
    ];
    let (kind, set): (&str, Vec<(&str, Json)>) = match c {
        C::Entry(v) => ("entry", vec![("entry", vid(v))]),
        C::Leg { entry, ordinal } => (
            "leg",
            vec![
                ("entry", vid(entry)),
                ("ordinal", Json::Int(i128::from(*ordinal))),
            ],
        ),
        C::Account(v) => ("account", vec![("account", vid(v))]),
        C::Period(code) => ("period", vec![("period", s(code.as_str()))]),
        C::Document(oid) => ("document", vec![("document", s(hex(&oid.0)))]),
        C::Principal(v) => ("principal", vec![("principal", vid(v))]),
        C::Approval(v) => ("approval", vec![("approval", vid(v))]),
        C::Attestation(v) => ("attestation", vec![("attestation", vid(v))]),
    };
    for (key, value) in set {
        if let Some(slot) = fields.iter_mut().find(|(name, _)| *name == key) {
            slot.1 = value;
        }
    }
    fields.push(("kind", s(kind)));
    obj(fields)
}

pub(crate) fn finding_json(f: &fa_lantern::Finding) -> Json {
    obj(vec![
        ("severity", s(f.severity.name())),
        (
            "statistic",
            obj(vec![
                ("name", s(&f.statistic.name)),
                ("value", Json::Int(f.statistic.value)),
                ("scale", Json::Int(i128::from(f.statistic.scale))),
                ("population", Json::Int(i128::from(f.statistic.population))),
            ]),
        ),
        ("cites", Json::Arr(f.cites.iter().map(cite_json).collect())),
        ("narrative", s(&f.narrative)),
    ])
}

/// `fa procedure list` and `fa procedure run <id>`: Lantern's registered
/// procedures over the book's trunk, a pure read (plan §11; FA-INV-04: a
/// finding is derived, never authoritative).
/// `fa trace <law> ...` (plan §15.3 Forensics, §11.5 tracing laws): `fa
/// procedure run trace.<law> ...` under the plan's spelling. The law is a
/// registered tracing procedure's suffix (`libr`, `pro-rata`,
/// `network-fifo`, `restitution-order`, ...); every flag is procedure run's.
fn trace_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const FIX: &str =
        "fa trace libr --account 1000 --source <entry vid> --effective-through 2026-03-31 --json";
    let [_, law] = args.positional.as_slice() else {
        return Err(usage("fa trace takes one tracing law", FIX));
    };
    let id = format!("trace.{}", law.replace('-', "_"));
    let laws: Vec<String> = fa_lantern::catalog::registered()
        .map_err(lantern_usage)?
        .into_iter()
        .filter_map(|row| row.id.strip_prefix("trace.").map(|l| l.replace('_', "-")))
        .collect();
    if !laws
        .iter()
        .any(|l| l.replace('-', "_") == id["trace.".len()..])
    {
        return Err(usage(
            format!("`{law}` is not a registered tracing law"),
            format!(
                "fa trace <{}> ... (fa procedure list --json)",
                laws.join("|")
            ),
        ));
    }
    let mut run = args.clone();
    run.positional = vec!["procedure".into(), "run".into(), id];
    procedure_cmd(ctx, &run)
}

/// `fa jet [--known-at HEAD|<seq>] [--effective-through YYYY-MM-DD]
/// [--budget <units>]` (plan §15.3 Forensics, §11.2 journal-entry tests):
/// every registered `jet.*` procedure at its registered defaults, at one
/// coordinate.
fn jet_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    procedure_family(
        ctx,
        args,
        "jet",
        "fa jet [--known-at HEAD|<seq>] [--effective-through YYYY-MM-DD] --json",
    )
}

/// `fa benford [--scope <account type>] [--known-at HEAD|<seq>]
/// [--budget <units>]` (plan §15.3 Forensics, §11.3 digit tests, §15.6): the
/// registered first-digit, second-digit and first-two-digits tests at their
/// registered defaults, over every posting, or with `--scope` over the legs
/// of one registered account type (their `account_type` parameter).
fn benford_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const FIX: &str = "fa benford [--scope assets|liabilities|equity|revenue|expenses] [--known-at HEAD|<seq>] --json";
    let Some(scope) = args.flag("--scope") else {
        return procedure_family(ctx, args, "benford", FIX);
    };
    if args.flag_all("--scope").len() > 1 || args.flag("--param").is_some() {
        return Err(usage(
            "fa benford takes one --scope, and the scope is its only parameter",
            FIX,
        ));
    }
    // Plan §15.6 `fa benford --scope expenses`: every digit test over the
    // legs of one registered account type (the procedures' `account_type`).
    let tag = fa_model::AccountType::ALL
        .iter()
        .find(|(_, name, ..)| {
            let name = name.to_ascii_lowercase();
            let plural = match name.strip_suffix('y') {
                Some(stem) if name != "equity" => format!("{stem}ies"),
                _ => format!("{name}s"),
            };
            scope == name || scope == plural
        })
        .map(|(tag, ..)| *tag)
        .ok_or_else(|| {
            usage(
                format!("--scope {scope} names no registered account type"),
                FIX,
            )
        })?;
    let mut scoped = args.clone();
    scoped.flags.remove("--scope");
    scoped
        .flags
        .insert("--param".into(), vec![format!("account_type={tag}")]);
    procedure_family(ctx, &scoped, "benford", FIX)
}

/// Run every registered procedure of `family` in registry order, each
/// reported as `fa procedure run` reports it, then a `procedure_family`
/// summary. A procedure this book cannot run (an account role no account
/// holds, or a declared input) is listed as refused with its fix, and the
/// rest still run; any other failure stops the run. A date reaches only the
/// procedures that take one. A pure read: `fa finding record <id>` retains
/// one run.
fn procedure_family(ctx: &mut Ctx<'_>, args: &Args, family: &str, fix: &str) -> Result<(), Fail> {
    if args.positional.len() != 1 {
        return Err(usage(
            format!("fa {family} takes no positional argument"),
            fix,
        ));
    }
    let procedures = fa_registry::procedures::Procedures::embedded()
        .map_err(|e| usage(e.to_string(), "fa procedure list --json"))?;
    let prefix = format!("{family}.");
    let members: Vec<_> = procedures
        .rows
        .iter()
        .filter(|row| row.id.starts_with(&prefix))
        .collect();
    let mut ran = Vec::new();
    let mut refused = Vec::new();
    for row in members {
        let mut run = args.clone();
        run.positional = vec!["procedure".into(), "run".into(), row.id.clone()];
        if matches!(
            row.effective_through,
            fa_registry::procedures::EffectiveThrough::NotTaken
        ) {
            run.flags.remove("--effective-through");
        }
        match procedure_cmd(ctx, &run) {
            Ok(()) => ran.push(s(&row.id)),
            Err(Fail::Book(BookError::Lantern(
                error @ (fa_lantern::LanternError::RoleUnassigned { .. }
                | fa_lantern::LanternError::Parameter { .. }),
            ))) => refused.push(obj(vec![
                ("procedure", s(&row.id)),
                ("message", s(error.to_string())),
                ("fix", error.fix_hint().map_or(Json::Null, s)),
            ])),
            Err(other) => return Err(other),
        }
    }
    let human = format!(
        "fa {family}: {} procedure(s) ran, {} refused",
        ran.len(),
        refused.len()
    );
    ctx.out.event(
        "procedure_family",
        vec![
            ("family", s(family)),
            ("ran", Json::Arr(ran)),
            ("refused", Json::Arr(refused)),
        ],
        &human,
    );
    Ok(())
}

fn procedure_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let sub = args.positional.get(1).map(String::as_str);
    let example = "fa procedure run jet.round_amounts --book <dir> --json";
    match sub {
        Some("list") => {
            if let Some(extra) = args.positional.get(2) {
                return Err(usage(
                    format!("unexpected argument `{extra}`"),
                    "fa procedure list --json",
                ));
            }
            let rows = fa_lantern::catalog::registered().map_err(lantern_usage)?;
            let calibration = fa_lantern::catalog::calibration().map_err(lantern_usage)?;
            // Human mode lists one procedure per line; robot mode carries the
            // same rows in the event alone (stdout is one JSON object a line).
            for row in rows.iter().filter(|_| !out.json) {
                let measured = calibration.row(&row.id).map_or(String::new(), |m| {
                    format!(
                        " [on fa-gen synthetic corpora, {} seeds: recall {} ({}-{}), precision {} ({}-{}), 95% Wilson; not a field estimate]",
                        calibration.seeds,
                        bps_percent(m.recall_bps),
                        bps_percent(m.recall_lower_bps),
                        bps_percent(m.recall_upper_bps),
                        bps_percent(m.precision_bps),
                        bps_percent(m.precision_lower_bps),
                        bps_percent(m.precision_upper_bps),
                    )
                });
                out.line(format!(
                    "{} v{} {} {}{measured}",
                    row.id,
                    row.version,
                    row.claim.name(),
                    row.summary
                ));
            }
            out.event(
                "procedure_list",
                vec![
                    (
                        "procedures",
                        Json::Arr(
                            rows.iter()
                                .map(|row| procedure_row_json(row, &calibration))
                                .collect(),
                        ),
                    ),
                    ("count", Json::Int(rows.len() as i128)),
                ],
                &format!("{} registered procedure(s)", rows.len()),
            );
            Ok(())
        }
        Some("run") => {
            let id = args
                .positional
                .get(2)
                .ok_or_else(|| usage("procedure run needs a procedure id", example))?;
            if let Some(extra) = args.positional.get(3) {
                return Err(usage(format!("unexpected argument `{extra}`"), example));
            }
            for flag in ["--effective-through", "--account", "--source", "--budget"] {
                if args.flag_all(flag).len() > 1 {
                    return Err(usage(
                        format!("procedure run takes only one {flag}"),
                        example,
                    ));
                }
            }
            let mut params = fa_lantern::Params::defaults(id).map_err(lantern_usage)?;
            for assignment in args.flag_all("--param") {
                let Some((name, value)) = assignment.split_once('=') else {
                    return Err(usage(
                        format!("--param `{assignment}` is not name=value"),
                        "--param round_power=2",
                    ));
                };
                let value: i128 = value.trim().parse().map_err(|_| {
                    usage(
                        format!("--param {name}: `{value}` is not an integer"),
                        "--param name=<integer, in the parameter's registered unit>",
                    )
                })?;
                params = params.set(name.trim(), value).map_err(lantern_usage)?;
            }
            let effective_through = match args.flag("--effective-through") {
                None => None,
                Some(d) => Some(DateDay::parse(d).map_err(|e| {
                    usage(
                        format!("--effective-through `{d}`: {e:?}"),
                        "--effective-through YYYY-MM-DD",
                    )
                })?),
            };
            refuse_untaken_date(id, effective_through)?;
            // The run's work budget (fa-1tvm): the procedure stops at the
            // first charge past it, and the run is refused with exit 3 and
            // no finding.
            let budget = args
                .flag("--budget")
                .map(|text| {
                    text.parse::<u64>().ok().filter(|b| *b > 0).ok_or_else(|| {
                        usage(
                            format!("--budget `{text}` is not a positive count of work units"),
                            "--budget 1000000 (work units: entries, legs and comparisons)",
                        )
                    })
                })
                .transpose()?;
            let who = ctx.principal(args);
            let bank_cap = if id == "recon.bank_statement_drift" {
                let cap = ctx.capability(args, &["read"])?;
                for op in [fa_policy::Op::Read, fa_policy::Op::Reconcile] {
                    fa_policy::require(&cap, op, "observing bank statement drift")
                        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
                }
                fa_policy::reach(&cap, &fa_policy::Reach::whole_book(true), None)
                    .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
                Some(cap)
            } else {
                None
            };
            let mut book = if let Some(cap) = &bank_cap {
                ctx.books.open_admitted(args, |book| {
                    book.read_scope(who, cap)??;
                    Ok(())
                })?
            } else {
                ctx.books.open(args)?
            };
            let (known_at, requested_utc_ns) = known_at_flag(args, &book, out)?;
            if requested_utc_ns.is_some() {
                return Err(usage(
                    "procedures run at a recorded sequence, not at an instant",
                    "--known-at HEAD or --known-at <commit sequence>",
                ));
            }
            let inputs = fa_lantern::catalog::Inputs {
                account: args
                    .flag("--account")
                    .map(|code| account_vid(book.context().book_id, code)),
                source: args
                    .flag("--source")
                    .map(|text| parse_vid(text.strip_prefix("E:").unwrap_or(text), "--source"))
                    .transpose()?,
            };
            let run = if let Some(cap) = &bank_cap {
                let request = fa::ProcedureRequest {
                    procedure: id.clone(),
                    parameters: params,
                    inputs,
                    known_at,
                    effective_through,
                    budget,
                };
                book.run_procedure_with_history(who, cap, &request)??
            } else {
                let built =
                    fa_lantern::catalog::build(id, params, inputs).map_err(lantern_usage)?;
                book.run_procedure(built.as_ref(), known_at, effective_through, budget)?
            };
            out.known_at(run.coordinate.known_at);
            // Human mode prints one finding per line; robot mode carries
            // them in the event alone (stdout is one JSON object a line).
            for f in run.findings.iter().filter(|_| !out.json) {
                out.line(format!(
                    "{} {} {}={} {}",
                    f.severity.name(),
                    run.procedure,
                    f.statistic.name,
                    f.statistic.value,
                    f.narrative
                ));
            }
            let human = format!(
                "{}: {} finding(s) over {} entries",
                run.procedure,
                run.findings.len(),
                run.population
            );
            out.event(
                "procedure_run",
                vec![
                    ("procedure", s(&run.procedure)),
                    ("version", Json::Int(i128::from(run.version))),
                    ("claim", s(run.claim.name())),
                    ("evidence", s(&run.evidence)),
                    ("known_at", Json::Int(i128::from(run.coordinate.known_at.0))),
                    (
                        "effective_through",
                        run.coordinate
                            .effective_through
                            .map_or(Json::Null, |d| s(d.render())),
                    ),
                    (
                        "parameters",
                        Json::Arr(
                            run.parameters
                                .iter()
                                .map(|(k, v)| {
                                    obj(vec![("name", s(k.as_str())), ("value", Json::Int(*v))])
                                })
                                .collect(),
                        ),
                    ),
                    (
                        "inputs",
                        Json::Arr(
                            run.inputs
                                .iter()
                                .map(|(k, v)| {
                                    obj(vec![("name", s(k.as_str())), ("value", s(v.as_str()))])
                                })
                                .collect(),
                        ),
                    ),
                    ("parameters_digest", s(hex(&run.parameters_digest))),
                    ("inputs_digest", s(hex(&run.inputs_digest))),
                    ("population", Json::Int(i128::from(run.population))),
                    (
                        "work",
                        obj(vec![
                            ("entries", Json::Int(i128::from(run.work.entries))),
                            ("legs", Json::Int(i128::from(run.work.legs))),
                            ("comparisons", Json::Int(i128::from(run.work.comparisons))),
                        ]),
                    ),
                    (
                        "findings",
                        Json::Arr(run.findings.iter().map(finding_json).collect()),
                    ),
                    ("finding_count", Json::Int(run.findings.len() as i128)),
                    ("findings_digest", s(hex(&run.findings_digest))),
                ],
                &human,
            );
            Ok(())
        }
        _ => Err(unhandled("procedure", sub)),
    }
}

// ---------------------------------------------------------------------------
// migrate (plan §8.6, Appendix A MigrationRun, bead fa-wk4h)
// ---------------------------------------------------------------------------

const MIGRATE_PLAN_DOMAIN: &[u8; 16] = b"FA-MIGRATE-PLAN\0";
const MIGRATE_PLAN_VERSION: u16 = 1;

fn resolve_migration_run_vid(book_id: Id128, text: &str) -> VId {
    let trimmed = text.strip_prefix("MR:").unwrap_or(text);
    if trimmed.len() == 32
        && trimmed.bytes().all(|b| b.is_ascii_hexdigit())
        && let Ok(v) = u128::from_str_radix(trimmed, 16)
    {
        return VId(v);
    }
    fa_model::migration_run_vid(book_id, trimmed)
}

fn encode_migrate_plan(action_tag: u8, run: VId, proposal: &EntryPayload) -> Result<Vec<u8>, Fail> {
    let payload_bytes = proposal
        .clone()
        .seal(Vec::new(), None)
        .and_then(|entry| entry.encode())
        .map_err(|e| Fail::Internal(format!("encode migration proposal: {e}")))?;
    let mut w = fa_model::Writer::new();
    w.fixed(MIGRATE_PLAN_DOMAIN)
        .u16(MIGRATE_PLAN_VERSION)
        .u8(action_tag)
        .u128(run.0)
        .bytes(&payload_bytes);
    w.finish()
        .map_err(|e| Fail::Internal(format!("encode migration plan: {e}")))
}

fn decode_migrate_plan(
    bytes: &[u8],
    expected_tag: u8,
    action_name: &str,
) -> Result<(VId, EntryPayload), Fail> {
    let mut r = fa_model::Reader::new(bytes);
    let (tag, run, payload_bytes) = (|| -> Result<(u8, VId, Vec<u8>), fa_model::DecodeError> {
        let domain: [u8; 16] = r.fixed("migrate_plan.domain")?;
        if domain != *MIGRATE_PLAN_DOMAIN {
            return Err(r.invalid("migrate_plan.domain"));
        }
        if r.u16("migrate_plan.version")? != MIGRATE_PLAN_VERSION {
            return Err(r.invalid("migrate_plan.version"));
        }
        let tag = r.u8("migrate_plan.action")?;
        let run = VId(r.u128("migrate_plan.run")?);
        let payload = r.bytes(MAX_PLAN_BYTES, "migrate_plan.proposal")?.to_vec();
        r.finish()?;
        Ok((tag, run, payload))
    })()
    .map_err(|e| {
        usage(
            format!("invalid migration plan: {e}"),
            format!("plan first with `fa migrate {action_name} ... --dry-run`"),
        )
    })?;
    if tag != expected_tag {
        return Err(usage(
            format!("plan file was prepared for a different migration action (tag {tag})"),
            format!("pass a plan prepared with `fa migrate {action_name} --dry-run`"),
        ));
    }
    let proposal = fa_model::Entry::decode(&payload_bytes)
        .map(|entry| entry.proposal)
        .map_err(|e| {
            usage(
                format!("invalid migration proposal in plan: {e}"),
                format!("plan first with `fa migrate {action_name} ... --dry-run`"),
            )
        })?;
    Ok((run, proposal))
}

fn parse_tb_amount_str(
    raw: &str,
    unit_code: &str,
    units: &fa_money::UnitRegistry,
    what: &str,
) -> Result<Amount, Fail> {
    let trimmed = raw.trim();
    let candidate = if trimmed.contains(' ') {
        trimmed.to_string()
    } else {
        format!("{trimmed} {unit_code}")
    };
    Amount::parse(&candidate, units).map_err(|e| {
        usage(
            format!("{what}: invalid amount `{raw}`: {e}"),
            "\"10.00\" or \"10.00 USD\"",
        )
    })
}

fn parse_migration_tb_lines(
    book: &Book,
    value: Option<&Json>,
    what: &str,
) -> Result<Vec<fa_journal::TrialBalanceLine>, Fail> {
    let Some(Json::Arr(items)) = value else {
        return Err(usage(
            format!("{what} must be a JSON array of trial balance lines"),
            "lines: [{\"account\": \"1000\", \"unit\": \"USD\", \"debit\": \"10.00\"}]",
        ));
    };
    let default_unit = book.spec()?.base_unit;
    let ctx = book.context();
    let default_unit_code = ctx
        .units
        .get(default_unit)
        .map(|u| u.code.as_str())
        .unwrap_or("USD");
    let mut out = Vec::with_capacity(items.len());
    for (idx, item) in items.iter().enumerate() {
        let acct = item
            .get("account")
            .or_else(|| item.get("account_code"))
            .and_then(Json::as_str)
            .ok_or_else(|| {
                usage(
                    format!("{what}[{idx}]: `account` (or `account_code`) must be a string"),
                    "{\"account\": \"1000\", \"debit\": \"10.00\"}",
                )
            })?;
        let unit = match item.get("unit").and_then(Json::as_str) {
            None => default_unit,
            Some(code) => ctx.units.lookup(code).ok_or_else(|| {
                usage(
                    format!("{what}[{idx}]: unknown unit `{code}`"),
                    "use a registered unit code such as USD",
                )
            })?,
        };
        let unit_code = ctx
            .units
            .get(unit)
            .map(|u| u.code.as_str())
            .unwrap_or(default_unit_code);
        let (line_unit, mantissa) = if let Some(Json::Int(m)) = item.get("mantissa") {
            (unit, *m)
        } else if let Some(d_str) = item.get("debit").and_then(Json::as_str) {
            let amt = parse_tb_amount_str(
                d_str,
                unit_code,
                &ctx.units,
                &format!("{what}[{idx}].debit"),
            )?;
            (amt.unit, amt.mantissa)
        } else if let Some(c_str) = item.get("credit").and_then(Json::as_str) {
            let amt = parse_tb_amount_str(
                c_str,
                unit_code,
                &ctx.units,
                &format!("{what}[{idx}].credit"),
            )?;
            let neg = amt.mantissa.checked_neg().ok_or_else(|| {
                usage(
                    format!("{what}[{idx}]: credit amount overflows"),
                    "\"credit\": \"10.00\"",
                )
            })?;
            (amt.unit, neg)
        } else if let Some(n_str) = item.get("net").and_then(Json::as_str) {
            let amt =
                parse_tb_amount_str(n_str, unit_code, &ctx.units, &format!("{what}[{idx}].net"))?;
            (amt.unit, amt.mantissa)
        } else {
            return Err(usage(
                format!(
                    "{what}[{idx}]: supply `debit`, `credit`, `net`, or `mantissa` on each trial balance line"
                ),
                "{\"account\": \"1000\", \"debit\": \"10.00\"}",
            ));
        };
        out.push(fa_journal::TrialBalanceLine {
            account_code: acct.to_string(),
            unit: line_unit,
            mantissa,
        });
    }
    Ok(out)
}

fn parse_migration_run_body(
    book: &Book,
    args: &Args,
    doc: &Json,
) -> Result<fa_journal::RunBody, Fail> {
    let run_key = doc
        .get("run_key")
        .and_then(Json::as_str)
        .or_else(|| args.flag("--run"))
        .or_else(|| args.flag("--key"))
        .ok_or_else(|| {
            usage(
                "migration run requires `run_key` in the intent or `--run <key>`",
                "\"run_key\": \"go-live-2026\"",
            )
        })?
        .to_string();
    let source_system = doc
        .get("source_system")
        .and_then(Json::as_str)
        .unwrap_or("legacy")
        .to_string();
    let mode_str = doc
        .get("mode")
        .and_then(Json::as_str)
        .unwrap_or("OpeningOnly");
    let mode = match mode_str {
        "OpeningOnly" | "opening_only" | "opening-only" => fa_journal::RunMode::OpeningOnly,
        "PeriodBalances" | "period_balances" | "period-balances" => {
            fa_journal::RunMode::PeriodBalances
        }
        "FullDetail" | "full_detail" | "full-detail" => fa_journal::RunMode::FullDetail,
        other => {
            return Err(usage(
                format!("unknown migration mode `{other}`"),
                "mode: OpeningOnly | PeriodBalances | FullDetail",
            ));
        }
    };
    let tb_str = doc
        .get("trial_balance")
        .and_then(Json::as_str)
        .or_else(|| args.flag("--evidence"))
        .ok_or_else(|| {
            usage(
                "migration run requires `trial_balance` document oid in the intent or `--evidence <oid>`",
                "\"trial_balance\": \"<64-hex-oid>\"",
            )
        })?;
    let trial_balance = Oid(document::hex32(tb_str, "trial_balance")?);
    let opening_date_str = req_str(doc, "opening_date", "migration run")?;
    let opening_date = DateDay::parse(opening_date_str).map_err(|e| {
        usage(
            format!("opening_date `{opening_date_str}`: {e:?}"),
            "\"opening_date\": \"YYYY-MM-DD\"",
        )
    })?;
    let sole_opening_source = match doc.get("sole_opening_source") {
        None => false,
        Some(Json::Bool(b)) => *b,
        Some(_) => {
            return Err(usage(
                "sole_opening_source must be a boolean",
                "\"sole_opening_source\": true|false",
            ));
        }
    };
    let lines = if doc.get("lines").is_none() && sole_opening_source {
        Vec::new()
    } else {
        parse_migration_tb_lines(book, doc.get("lines"), "lines")?
    };
    let periods = match doc.get("periods") {
        None => Vec::new(),
        Some(Json::Arr(items)) => {
            let mut ps = Vec::with_capacity(items.len());
            for (i, p) in items.iter().enumerate() {
                let code = p
                    .get("period")
                    .or_else(|| p.get("period_code"))
                    .and_then(Json::as_str)
                    .ok_or_else(|| {
                        usage(
                            format!("periods[{i}]: `period` (or `period_code`) must be a string"),
                            "\"period\": \"FY2025-P12\"",
                        )
                    })?
                    .to_string();
                let p_tb = match p.get("trial_balance").and_then(Json::as_str) {
                    Some(s_oid) => Oid(document::hex32(s_oid, "period.trial_balance")?),
                    None => trial_balance,
                };
                let p_lines =
                    parse_migration_tb_lines(book, p.get("lines"), &format!("periods[{i}].lines"))?;
                ps.push(fa_journal::PeriodBalance {
                    period_code: code,
                    trial_balance: p_tb,
                    lines: p_lines,
                });
            }
            ps
        }
        Some(_) => {
            return Err(usage(
                "`periods` must be a JSON array",
                "periods: [{\"period\": \"FY2025-P12\", \"lines\": [...]}]",
            ));
        }
    };
    let detail_base = match doc.get("detail_base") {
        None => Vec::new(),
        Some(v) => parse_migration_tb_lines(book, Some(v), "detail_base")?,
    };
    Ok(fa_journal::RunBody {
        book_id: book.context().book_id,
        run_key,
        source_system,
        mode,
        trial_balance,
        opening_date,
        lines,
        periods,
        detail_base,
        sole_opening_source,
    })
}

fn run_mode_name(mode: fa_journal::RunMode) -> &'static str {
    match mode {
        fa_journal::RunMode::OpeningOnly => "OpeningOnly",
        fa_journal::RunMode::PeriodBalances => "PeriodBalances",
        fa_journal::RunMode::FullDetail => "FullDetail",
    }
}

fn emit_migration_controlled(
    out: &Out,
    action: &str,
    run_key: &str,
    tie_out_digest: &[u8; 32],
    controlled: &fa_journal::RunControlled,
) {
    let run_hex = format!("{:032x}", controlled.run.0);
    let ctrl_hex = format!("{:032x}", controlled.control_entry.0);
    let from_json = controlled.from.map_or(Json::Null, |st| s(st.name()));
    let to_name = controlled.to.name();
    let tie_hex = hex(tie_out_digest);
    out.event(
        "migration_controlled",
        vec![
            ("run_vid", s(&run_hex)),
            ("run_key", s(run_key)),
            ("action", s(action)),
            ("from", from_json),
            ("to", s(to_name)),
            ("control_entry", s(&ctrl_hex)),
            ("recorded_at", Json::Int(i128::from(controlled.recorded_at.0))),
            ("already_recorded", Json::Bool(controlled.already_recorded)),
            ("chunk_count", Json::Int(controlled.chunks.len() as i128)),
            ("tie_out_digest", s(&tie_hex)),
        ],
        &format!(
            "migration run `{run_key}` ({run_hex}): {action} -> {to_name} at {} (control entry {ctrl_hex})",
            controlled.recorded_at.0
        ),
    );
}

fn migration_capability(ctx: &Ctx<'_>, args: &Args, writing: bool) -> Result<Capability, Fail> {
    let ops: &[&str] = if writing {
        &["read", "post", "migrate"]
    } else {
        &["read"]
    };
    let capability = ctx.capability(args, ops)?;
    for name in ops {
        let op = fa_policy::Op::from_name(name)
            .ok_or_else(|| Fail::Internal("migration operation is not registered".into()))?;
        fa_policy::require(&capability, op, "migration run control")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    fa_policy::reach(&capability, &fa_policy::Reach::whole_book(true), None)
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    Ok(capability)
}

fn admit_migration(
    book: &Book,
    principal: VId,
    capability: &Capability,
    writing: bool,
) -> Result<(), Fail> {
    fa_policy::admit_read(capability, principal, book.context().book_id)
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    if writing {
        fa_policy::admit(
            capability,
            &fa_policy::Intent {
                principal,
                trunk: true,
                op: fa_policy::Op::Migrate,
                book: book.context().book_id,
                legs: &[],
            },
        )
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    // Current issuance and revocation precede input decoding, timestamp
    // resolution, run lookup and trusted facade planning.
    book.read_scope(principal, capability)??;
    Ok(())
}

fn migrate_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    match args.positional.get(1).map(String::as_str) {
        Some("import") => crate::migration_import::import_cmd(ctx, args),
        Some("open") => {
            let who = ctx.principal(args);
            let capability = migration_capability(ctx, args, true)?;
            let mut book = ctx
                .books
                .open_admitted(args, |book| admit_migration(book, who, &capability, true))?;
            let path = args.require("--intent", "run.json (or - for stdin)")?;
            let text = ctx.files.read_text(path)?;
            let doc = parse_json(path, &text)?;
            let body = parse_migration_run_body(&book, args, &doc)?;
            let key = args
                .flag("--key")
                .or_else(|| doc.get("idempotency_key").and_then(Json::as_str))
                .map(|k| k.as_bytes().to_vec())
                .unwrap_or_else(|| format!("migrate:open:{}", body.run_key).into_bytes());
            let description_text = args
                .flag("--description")
                .or_else(|| doc.get("description").and_then(Json::as_str))
                .unwrap_or("");
            let description = book.seal_text(description_text)?;
            let mut citations = Vec::new();
            for doc_oid in body.documents() {
                let commit = book.document_commitment(&doc_oid)?.unwrap_or([0u8; 32]);
                citations.push(fa_model::EvidenceRef {
                    document_oid: doc_oid,
                    doc_commit: commit,
                    role: 1,
                });
            }
            let proposal =
                book.open_migration_proposal(who, &body, citations, &key, description)?;
            let body_digest = body.digest().map_err(BookError::Kernel)?;
            let controlled = book.open_migration_run(
                &body,
                fa_journal::RunControlRequest {
                    proposal,
                    capability,
                    approvals: Vec::new(),
                },
            )??;
            ctx.out.at_book(&book)?;
            emit_migration_controlled(&ctx.out, "open", &body.run_key, &body_digest, &controlled);
            Ok(())
        }
        Some("stage") => {
            let who = ctx.principal(args);
            let capability = migration_capability(ctx, args, true)?;
            let approval_flags = args.flag_all("--approval");
            let mut book = ctx
                .books
                .open_admitted(args, |book| admit_migration(book, who, &capability, true))?;
            if let Some(plan_path) = args.flag("--plan") {
                if args.switch("--dry-run") || args.flag("--plan-out").is_some() {
                    return Err(usage(
                        "--plan commits a previously prepared stage plan; do not combine with --dry-run or --plan-out",
                        "fa migrate stage --plan <file> --approval <vid> --approval <vid>",
                    ));
                }
                let plan_bytes = read_plan_bytes(
                    &ctx.files,
                    plan_path,
                    MIGRATE_PLAN_DOMAIN,
                    "migration stage",
                )?;
                let (run_vid, proposal) = decode_migrate_plan(&plan_bytes, 0, "stage")?;
                if let Some(arg_run) = args
                    .positional
                    .get(2)
                    .map(String::as_str)
                    .or_else(|| args.flag("--run"))
                {
                    let expected = resolve_migration_run_vid(book.context().book_id, arg_run);
                    if expected != run_vid {
                        return Err(usage(
                            format!(
                                "{plan_path} stages into run {:032x}, not {:032x}",
                                run_vid.0, expected.0
                            ),
                            "pass the stage plan prepared for this migration run",
                        ));
                    }
                }
                let digest = proposal
                    .proposal_digest()
                    .map_err(|e| Fail::Internal(format!("proposal digest: {e}")))?;
                let approvals = approval_flags
                    .iter()
                    .map(|v| {
                        Ok(fa_model::ApprovalRef {
                            approval_vid: parse_vid(v, "--approval")?,
                            approved_digest: digest,
                        })
                    })
                    .collect::<Result<Vec<_>, Fail>>()?;
                let posted = book.post(PostRequest {
                    proposal,
                    approvals,
                    plan_certificate: None,
                    capability,
                })??;
                ctx.out.at_book(&book)?;
                return emit_posted(&ctx.out, posted, "Migration", false, None, None);
            }
            let path = args.require("--intent", "chunk.json (or - for stdin)")?;
            let text = ctx.files.read_text(path)?;
            let doc = parse_json(path, &text)?;
            let Json::Obj(raw_fields) = &doc else {
                return Err(usage(
                    "migration chunk intent must be a JSON object",
                    "fa robot-docs examples",
                ));
            };
            let run_str = args
                .positional
                .get(2)
                .map(String::as_str)
                .or_else(|| args.flag("--run"))
                .or_else(|| doc.get("run").and_then(Json::as_str))
                .or_else(|| doc.get("run_key").and_then(Json::as_str))
                .ok_or_else(|| {
                    usage(
                        "`fa migrate stage` needs a migration run key or vid (`--run <key|vid>` or positional)",
                        "fa migrate stage <run_key_or_vid> --intent chunk.json --book <dir> --json",
                    )
                })?;
            let book_id = book.context().book_id;
            let run_vid = resolve_migration_run_vid(book_id, run_str);
            let run_row = book.migration_run(run_vid, None)?;
            let mut filtered = Vec::new();
            let mut has_class = false;
            let mut has_period = false;
            for (k, v) in raw_fields {
                if matches!(
                    k.as_str(),
                    "run"
                        | "run_key"
                        | "source_system"
                        | "source_id"
                        | "source_recorded_at_ns"
                        | "source_entered_by"
                        | "source_approved_by"
                        | "batch_oid"
                ) {
                    continue;
                }
                if k == "class" {
                    has_class = true;
                }
                if k == "effective_period" {
                    has_period = true;
                }
                filtered.push((k.clone(), v.clone()));
            }
            if !has_class {
                filtered.push(("class".to_string(), s("Migration")));
            }
            if !has_period && let Some(p_flag) = args.flag("--period") {
                filtered.push(("effective_period".to_string(), s(p_flag)));
            }
            let post_doc = Json::Obj(filtered);
            let mut proposal = build_proposal_from_intent(
                &ctx.out,
                &mut book,
                args,
                &post_doc,
                who,
                capability.clone(),
            )?;
            proposal.class = EntryClass::MIGRATION;
            let source_system = doc
                .get("source_system")
                .and_then(Json::as_str)
                .map(str::to_string)
                .or_else(|| run_row.as_ref().map(|r| r.body.source_system.clone()))
                .unwrap_or_else(|| "legacy".to_string());
            let default_source_id = String::from_utf8_lossy(&proposal.idempotency_key).into_owned();
            let source_id_str = doc
                .get("source_id")
                .and_then(Json::as_str)
                .unwrap_or(&default_source_id);
            let source_id = book.seal_text(source_id_str)?;
            let source_recorded_at_ns = match doc.get("source_recorded_at_ns") {
                None | Some(Json::Null) => None,
                Some(Json::Int(n)) => Some(i64::try_from(*n).map_err(|_| {
                    usage(
                        "source_recorded_at_ns must fit in i64",
                        "\"source_recorded_at_ns\": 1700000000000000000",
                    )
                })?),
                Some(_) => {
                    return Err(usage(
                        "source_recorded_at_ns must be an integer",
                        "\"source_recorded_at_ns\": 1700000000000000000",
                    ));
                }
            };
            let source_entered_by = match doc.get("source_entered_by").and_then(Json::as_str) {
                Some(v) => Some(book.seal_text(v)?),
                None => None,
            };
            let source_approved_by = match doc.get("source_approved_by").and_then(Json::as_str) {
                Some(v) => Some(book.seal_text(v)?),
                None => None,
            };
            let batch_oid = match doc.get("batch_oid").and_then(Json::as_str) {
                Some(b_str) => Oid(document::hex32(b_str, "batch_oid")?),
                None => proposal
                    .evidence
                    .first()
                    .map(|e| e.document_oid)
                    .or_else(|| run_row.as_ref().map(|r| r.body.trial_balance))
                    .unwrap_or(Oid([0u8; 32])),
            };
            proposal.origin = EntryOrigin::Migration {
                run_ref: run_vid,
                source_system,
                source_id,
                source_recorded_at_ns,
                source_entered_by,
                source_approved_by,
                batch_oid,
            };
            let digest = proposal
                .proposal_digest()
                .map_err(|e| Fail::Internal(format!("proposal digest: {e}")))?;
            if args.switch("--dry-run") || args.flag("--plan-out").is_some() {
                let bytes = encode_migrate_plan(0, run_vid, &proposal)?;
                let plan_out = args.flag("--plan-out");
                if let Some(out_path) = plan_out {
                    write_post_plan(&ctx.files, out_path, &bytes)?;
                }
                ctx.out.at_book(&book)?;
                let run_hex = format!("{:032x}", run_vid.0);
                let digest_hex = hex(&digest);
                ctx.out.event(
                    "migration_planned",
                    vec![
                        ("run_vid", s(&run_hex)),
                        ("action", s("stage")),
                        ("proposal_digest", s(&digest_hex)),
                        ("tie_out_digest", Json::Null),
                        ("chunk_count", Json::Int(0)),
                        ("bytes", s(hex(&bytes))),
                        ("plan", plan_out.map_or(Json::Null, s)),
                    ],
                    &format!(
                        "planned migration chunk for run {run_hex}; approvals bind proposal {digest_hex}"
                    ),
                );
                return Ok(());
            }
            let approvals = approval_flags
                .iter()
                .map(|v| {
                    Ok(fa_model::ApprovalRef {
                        approval_vid: parse_vid(v, "--approval")?,
                        approved_digest: digest,
                    })
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            let posted = book.post(PostRequest {
                proposal,
                approvals,
                plan_certificate: None,
                capability,
            })??;
            ctx.out.at_book(&book)?;
            emit_posted(&ctx.out, posted, "Migration", false, None, None)
        }
        Some(sub @ ("finalize" | "abandon")) => {
            let is_finalize = sub == "finalize";
            let kind = if is_finalize {
                fa_journal::migration::kind::FINALIZE
            } else {
                fa_journal::migration::kind::ABANDON
            };
            let plan_tag: u8 = if is_finalize { 1 } else { 2 };
            let who = ctx.principal(args);
            let capability = migration_capability(ctx, args, true)?;
            let approval_flags = args.flag_all("--approval");
            let mut book = ctx
                .books
                .open_admitted(args, |book| admit_migration(book, who, &capability, true))?;
            let book_id = book.context().book_id;
            let (run_vid, proposal) = if let Some(plan_path) = args.flag("--plan") {
                if args.switch("--dry-run") || args.flag("--plan-out").is_some() {
                    return Err(usage(
                        format!(
                            "--plan commits a previously prepared {sub} plan; do not combine with --dry-run or --plan-out"
                        ),
                        format!("fa migrate {sub} --plan <file>"),
                    ));
                }
                let plan_bytes = read_plan_bytes(
                    &ctx.files,
                    plan_path,
                    MIGRATE_PLAN_DOMAIN,
                    &format!("migration {sub}"),
                )?;
                let (plan_run, decoded) = decode_migrate_plan(&plan_bytes, plan_tag, sub)?;
                if let Some(arg_run) = args
                    .positional
                    .get(2)
                    .map(String::as_str)
                    .or_else(|| args.flag("--run"))
                {
                    let expected = resolve_migration_run_vid(book_id, arg_run);
                    if expected != plan_run {
                        return Err(usage(
                            format!(
                                "{plan_path} plans {sub} of run {:032x}, not {:032x}",
                                plan_run.0, expected.0
                            ),
                            "pass the migration plan prepared for this run",
                        ));
                    }
                }
                (plan_run, decoded)
            } else {
                let run_str = args
                    .positional
                    .get(2)
                    .map(String::as_str)
                    .or_else(|| args.flag("--run"))
                    .ok_or_else(|| {
                        usage(
                            format!("`fa migrate {sub}` needs a migration run key or vid"),
                            format!("fa migrate {sub} <run_key_or_vid> --book <dir> --json"),
                        )
                    })?;
                let r_vid = resolve_migration_run_vid(book_id, run_str);
                let key = args
                    .flag("--key")
                    .map(|k| k.as_bytes().to_vec())
                    .unwrap_or_else(|| format!("migrate:{sub}:{:032x}", r_vid.0).into_bytes());
                let description = book.seal_text(args.flag("--description").unwrap_or(""))?;
                let planned =
                    book.plan_migration_transition(r_vid, kind, who, &key, description)??;
                (r_vid, planned)
            };
            let digest = proposal
                .proposal_digest()
                .map_err(|e| Fail::Internal(format!("proposal digest: {e}")))?;
            let tie_out_digest = match &proposal.control {
                Some(ControlPayload::MigrationControl { tie_out_digest, .. }) => *tie_out_digest,
                _ => [0u8; 32],
            };
            let run_row = book.migration_run(run_vid, None)?;
            let chunk_count = match &run_row {
                Some(r) => book.migration_tie_out(r, None)?.chunks.len(),
                None => 0,
            };
            if args.switch("--dry-run") || args.flag("--plan-out").is_some() {
                let bytes = encode_migrate_plan(plan_tag, run_vid, &proposal)?;
                let plan_out = args.flag("--plan-out");
                if let Some(out_path) = plan_out {
                    write_post_plan(&ctx.files, out_path, &bytes)?;
                }
                ctx.out.at_book(&book)?;
                let run_hex = format!("{:032x}", run_vid.0);
                let digest_hex = hex(&digest);
                let tie_hex = hex(&tie_out_digest);
                ctx.out.event(
                    "migration_planned",
                    vec![
                        ("run_vid", s(&run_hex)),
                        ("action", s(sub)),
                        ("proposal_digest", s(&digest_hex)),
                        ("tie_out_digest", s(&tie_hex)),
                        ("chunk_count", Json::Int(chunk_count as i128)),
                        ("bytes", s(hex(&bytes))),
                        ("plan", plan_out.map_or(Json::Null, s)),
                    ],
                    &format!(
                        "planned {sub} of migration run {run_hex} ({chunk_count} chunk(s), tie-out {tie_hex}); approvals bind proposal {digest_hex}"
                    ),
                );
                return Ok(());
            }
            let approvals = approval_flags
                .iter()
                .map(|v| {
                    Ok(fa_model::ApprovalRef {
                        approval_vid: parse_vid(v, "--approval")?,
                        approved_digest: digest,
                    })
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            let controlled = book.transition_migration_run(fa_journal::RunControlRequest {
                proposal,
                capability,
                approvals,
            })??;
            ctx.out.at_book(&book)?;
            let run_key = run_row
                .as_ref()
                .map(|r| r.body.run_key.as_str())
                .unwrap_or("");
            emit_migration_controlled(&ctx.out, sub, run_key, &tie_out_digest, &controlled);
            Ok(())
        }
        Some("show") => {
            let who = ctx.principal(args);
            let capability = migration_capability(ctx, args, false)?;
            let run_str = args
                .positional
                .get(2)
                .map(String::as_str)
                .or_else(|| args.flag("--run"))
                .ok_or_else(|| {
                    usage(
                        "`fa migrate show` needs a migration run key or vid",
                        "fa migrate show <run_key_or_vid> --book <dir> --json",
                    )
                })?;
            let book = ctx
                .books
                .open_admitted(args, |book| admit_migration(book, who, &capability, false))?;
            let (known_at, _requested_utc_ns) = known_at_flag(args, &book, &ctx.out)?;
            let run_vid = resolve_migration_run_vid(book.context().book_id, run_str);
            let Some(run) = book.migration_run(run_vid, known_at)? else {
                return Err(Refusal::new(
                    fa_journal::refusal::code::MIGRATION_OUTSIDE_RUN,
                    exit::REFUSAL,
                    format!("no migration run {:032x} in this book", run_vid.0),
                    "plan §8.6 (MigrationRun)",
                    "open the run first with `fa migrate open`",
                )
                .into());
            };
            let tie = book.migration_tie_out(&run, known_at)?;
            ctx.out.at_book(&book)?;
            let units = &book.context().units;
            let run_hex = format!("{:032x}", run.vid.0);
            let chunks_json: Vec<Json> = tie
                .chunks
                .iter()
                .map(|c| {
                    obj(vec![
                        ("vid", s(format!("{:032x}", c.vid.0))),
                        ("proposal_digest", s(hex(&c.proposal_digest))),
                        ("recorded_at", Json::Int(i128::from(c.recorded_at.0))),
                    ])
                })
                .collect();
            let mut mismatches_json = Vec::with_capacity(tie.mismatches.len());
            for m in &tie.mismatches {
                let unit_code = units
                    .get(m.unit)
                    .map(|u| u.code.clone())
                    .unwrap_or_else(|| format!("{}", m.unit.0));
                let declared_s = render_amount(Amount::new(m.unit, m.declared), units)?;
                let folded_s = render_amount(Amount::new(m.unit, m.folded), units)?;
                mismatches_json.push(obj(vec![
                    ("period", m.period.as_deref().map_or(Json::Null, s)),
                    ("account_code", s(&m.account_code)),
                    ("unit", s(&unit_code)),
                    ("declared", s(&declared_s)),
                    ("folded", s(&folded_s)),
                ]));
            }
            let ties_out = tie.mismatches.is_empty();
            let tie_hex = hex(&tie.digest);
            ctx.out.event(
                "migration_run",
                vec![
                    ("run_vid", s(&run_hex)),
                    ("run_key", s(&run.body.run_key)),
                    ("source_system", s(&run.body.source_system)),
                    ("mode", s(run_mode_name(run.body.mode))),
                    ("state", s(run.state.name())),
                    ("opened_at", Json::Int(i128::from(run.opened_at.0))),
                    ("opening_date", s(run.body.opening_date.render())),
                    ("trial_balance_oid", s(hex(&run.body.trial_balance.0))),
                    ("chunk_count", Json::Int(tie.chunks.len() as i128)),
                    ("chunks", Json::Arr(chunks_json)),
                    ("tie_out_digest", s(&tie_hex)),
                    ("ties_out", Json::Bool(ties_out)),
                    ("mismatches", Json::Arr(mismatches_json)),
                ],
                &format!(
                    "migration run `{}` ({run_hex}): {} · mode {} · {} chunk(s) · ties_out={ties_out}",
                    run.body.run_key,
                    run.state.name(),
                    run_mode_name(run.body.mode),
                    tie.chunks.len()
                ),
            );
            Ok(())
        }
        other => Err(unhandled("migrate", other)),
    }
}

fn event_summary_json(ev: &fa_journal::EventRow) -> Json {
    obj(vec![
        ("vid", s(format!("{:032x}", ev.vid.0))),
        ("code", s(&ev.spec.code)),
        ("kind", s(ev.spec.kind.name())),
        ("occurred_on", s(ev.spec.occurred_on.render())),
        ("event_digest", s(hex(&ev.event_digest))),
        ("recorded_at", Json::Int(i128::from(ev.created_at.0))),
    ])
}

/// The recorded event `target` names in `rea`: its 32-hex vid (optionally
/// `EV:`-prefixed) or its code.
pub(crate) fn find_event<'a>(
    rea: &'a fa_journal::ReaSnapshot,
    book_id: fa_model::Id128,
    target: &str,
) -> Option<&'a fa_journal::EventRow> {
    let stripped = target.strip_prefix("EV:").unwrap_or(target);
    if stripped.len() == 32
        && stripped.bytes().all(|b| b.is_ascii_hexdigit())
        && let Ok(raw) = u128::from_str_radix(stripped, 16)
    {
        rea.events
            .get(&VId(raw))
            .or_else(|| rea.events.values().find(|e| e.spec.code == target))
    } else {
        let derived = fa_model::event_vid(book_id, stripped);
        rea.events
            .get(&derived)
            .or_else(|| rea.events.values().find(|e| e.spec.code == stripped))
    }
}

fn event_detail_json(ev: &fa_journal::EventRow, book: &Book) -> Result<Json, Fail> {
    let seal_key = &book.context().seal_key;
    let units = &book.context().units;
    let description = ev
        .spec
        .description
        .open(seal_key, fa_model::limits::MAX_DESCRIPTION_BYTES)
        .unwrap_or_default();
    let participants: Vec<Json> = ev
        .spec
        .participants
        .iter()
        .map(|p| s(format!("{:032x}", p.0)))
        .collect();
    let mut resources = Vec::with_capacity(ev.spec.resources.len());
    for r in &ev.spec.resources {
        resources.push(obj(vec![
            ("label", s(&r.label)),
            (
                "instrument",
                r.instrument
                    .map_or(Json::Null, |inst| s(format!("{:032x}", inst.0))),
            ),
            ("amount", s(render_amount(r.amount, units)?)),
        ]));
    }
    let evidence: Vec<Json> = ev
        .spec
        .evidence
        .iter()
        .map(|e| {
            obj(vec![
                ("document_oid", s(hex(&e.document_oid.0))),
                ("doc_commit", s(hex(&e.doc_commit))),
                ("role", Json::Int(i128::from(e.role))),
            ])
        })
        .collect();
    let external_ids: Vec<Json> = ev
        .spec
        .external_ids
        .iter()
        .map(|ext| {
            let id_str = ext
                .id
                .open(seal_key, fa_model::limits::MAX_EXTERNAL_ID_BYTES)
                .unwrap_or_default();
            obj(vec![("system", s(&ext.system)), ("id", s(id_str))])
        })
        .collect();
    Ok(obj(vec![
        ("vid", s(format!("{:032x}", ev.vid.0))),
        ("code", s(&ev.spec.code)),
        ("kind", s(ev.spec.kind.name())),
        ("occurred_on", s(ev.spec.occurred_on.render())),
        ("description", s(description)),
        ("participants", Json::Arr(participants)),
        ("resources", Json::Arr(resources)),
        ("evidence", Json::Arr(evidence)),
        ("external_ids", Json::Arr(external_ids)),
        ("event_digest", s(hex(&ev.event_digest))),
        ("recorded_at", Json::Int(i128::from(ev.created_at.0))),
    ]))
}

/// `fa search <query> [--kind entry|document|finding|all]` (plan §9, fa-qip):
/// rank the entries whose description or memos match the query, the
/// documents whose text does, and the findings whose procedure or narrative
/// does, from one BM25 index rebuilt from the journal at the selected
/// frontier for this query alone and never stored. It reads every entry,
/// document and recorded finding run, so it is admitted as a whole-book read.
/// Text the book's key does not open (erased, or sealed under a subject's
/// key) is never indexed, and a document is indexed only when this
/// capability reads it whole: its own UTF-8 text, or a derived document's
/// extracted text.
fn search_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    const EXAMPLE: &str = "fa search \"office rent\" [--kind entry|document|finding|all] [--as-known-at HEAD|<seq>] [--limit 20] --book <dir> --json";
    let query = match args.positional.as_slice() {
        [_, query] => query.as_str(),
        _ => {
            return Err(usage(
                "fa search takes exactly one query (quote a phrase)",
                EXAMPLE,
            ));
        }
    };
    if query.trim().is_empty() || query.len() > 1024 {
        return Err(usage("a search query is 1..=1024 bytes of text", EXAMPLE));
    }
    if args.flag_all("--limit").len() > 1 {
        return Err(usage("--limit may be supplied only once", EXAMPLE));
    }
    let limit = match args.flag("--limit") {
        None => 20,
        Some(raw) => raw
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=200).contains(n))
            .ok_or_else(|| usage(format!("--limit `{raw}` is not 1..=200"), EXAMPLE))?,
    };
    let kind = match args.flag("--kind").unwrap_or("all") {
        "all" => None,
        "entry" => Some(fa::SearchRecordKind::Entry),
        "document" => Some(fa::SearchRecordKind::Document),
        "finding" => Some(fa::SearchRecordKind::Finding),
        other => {
            return Err(usage(
                format!("--kind `{other}` is not entry, document, finding or all"),
                EXAMPLE,
            ));
        }
    };
    let wants = |wanted: fa::SearchRecordKind| kind.is_none_or(|only| only == wanted);
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["read"])?;
    let mut book = ctx.books.open_admitted(args, |book| {
        admit_whole_book_read(book, &capability, &[], "searching the journal")
    })?;
    let (known_at, _) = known_at_flag(args, &book, &ctx.out)?;
    let mut records = Vec::new();
    // Documents are read through this capability. One it sees only
    // redacted, may not read, or that is erased contributes nothing; one
    // that fails its own proof is drift and fails the search (exit 8).
    if wants(fa::SearchRecordKind::Document) {
        for summary in book.documents(known_at)?? {
            let document = match book.read_document_for(&capability, &summary.oid)? {
                Ok(fa_journal::DocumentRead::Full(document)) => document,
                Err(refusal) if refusal.exit == fa_journal::exit::VERIFICATION => {
                    return Err(Fail::Refusal(refusal));
                }
                Ok(fa_journal::DocumentRead::Redacted(_)) | Err(_) => continue,
            };
            if let Some(text) = fa::document_search_text(&document) {
                records.push(fa::SearchIndexableRecord {
                    id: fa::SearchRecordId::Document(summary.oid),
                    recorded_at: summary.recorded_at.0,
                    subject_ref: None,
                    text,
                });
            }
        }
    }
    // Findings are the certified replays of every run recorded at the
    // frontier, never a graph cache: a run that does not replay fails the
    // search. Each finding is searched by its procedure and narrative.
    if wants(fa::SearchRecordKind::Finding) {
        let mut request = fa::findings::lookup::FindingRunPageRequest {
            known_at,
            after: None,
            limit: fa::findings::lookup::MAX_FINDING_RUN_PAGE,
        };
        loop {
            let page = book.finding_runs(who, &capability, &request)??;
            for run in &page.runs {
                let recorded =
                    book.read_findings_with_history(who, &capability, &run.certificate_digest)??;
                for (vid, finding) in recorded.finding_ids.iter().zip(&recorded.report.findings) {
                    records.push(fa::SearchIndexableRecord {
                        id: fa::SearchRecordId::Finding(*vid),
                        recorded_at: recorded.recorded_at.0,
                        subject_ref: None,
                        text: format!("{}\n{}", finding.procedure, finding.narrative),
                    });
                }
            }
            let Some(next) = page.next_cursor else {
                break;
            };
            request.after = Some(next);
        }
    }
    let results = book.search(query, known_at, &records, kind)?;
    ctx.out.known_at(results.known_at);
    let shown = &results.hits[..results.hits.len().min(limit)];
    let hits: Vec<Json> = shown
        .iter()
        .map(|hit| {
            obj(vec![
                ("kind", s(hit.kind.as_str())),
                ("id", s(hit.id.canonical_hex())),
                ("recorded_at", Json::Int(i128::from(hit.recorded_at))),
                ("score_micro", Json::Int(i128::from(hit.score_micro))),
                (
                    "matched_terms",
                    Json::Arr(hit.matched_terms.iter().map(s).collect()),
                ),
                ("snippet", s(&hit.snippet)),
            ])
        })
        .collect();
    let human = if shown.is_empty() {
        format!(
            "nothing matches `{query}` at {} ({} entries, documents and findings carry searchable text)",
            results.known_at.0, results.records
        )
    } else {
        shown
            .iter()
            .map(|hit| format!("{}  {}", hit.id.canonical_hex(), hit.snippet))
            .collect::<Vec<_>>()
            .join("\n")
    };
    ctx.out.event(
        "search_results",
        vec![
            ("query", s(query)),
            ("known_at", Json::Int(i128::from(results.known_at.0))),
            ("records", Json::Int(results.records as i128)),
            ("index_digest", s(hex(&results.index_digest))),
            ("total", Json::Int(results.hits.len() as i128)),
            ("hits", Json::Arr(hits)),
        ],
        &human,
    );
    Ok(())
}

fn event_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let who = ctx.principal(args);
    match args.positional.get(1).map(String::as_str) {
        Some("record") => {
            if let Some(extra) = args.positional.get(2) {
                return Err(usage(
                    format!("unexpected positional `{extra}` for `fa event record`"),
                    "fa event record --code EV-1001 --kind sale --occurred-on 2026-03-15 --evidence <oid>... --book <dir> --json",
                ));
            }
            for flag in [
                "--code",
                "--kind",
                "--occurred-on",
                "--description",
                "--effective",
                "--key",
            ] {
                if args.flag_all(flag).len() > 1 {
                    return Err(usage(
                        format!("{flag} may be supplied at most once"),
                        "fa event record --code EV-1001 --kind sale --occurred-on 2026-03-15 --evidence <oid>...",
                    ));
                }
            }
            let code = args
                .require("--code", "<CODE>, for example EV-1001")?
                .to_string();
            let kind_str = args.require(
                "--kind",
                "sale|purchase|receipt|payment|shipment|return|accrual|depreciation",
            )?;
            let kind = fa_model::EventKind::from_name(kind_str).ok_or_else(|| {
                usage(
                    format!("unknown event kind `{kind_str}`"),
                    "--kind sale|purchase|receipt|payment|shipment|return|accrual|depreciation",
                )
            })?;
            let occurred_raw = args.require("--occurred-on", "YYYY-MM-DD")?;
            let occurred_on = DateDay::parse(occurred_raw).map_err(|e| {
                usage(
                    format!("--occurred-on `{occurred_raw}`: {e:?}"),
                    "--occurred-on YYYY-MM-DD",
                )
            })?;
            let effective_date = match args.flag("--effective") {
                Some(raw) => DateDay::parse(raw).map_err(|e| {
                    usage(
                        format!("--effective `{raw}`: {e:?}"),
                        "--effective YYYY-MM-DD",
                    )
                })?,
                None => occurred_on,
            };
            let capability = ctx.capability(args, &["post"])?;
            let mut book = ctx.books.open(args)?;
            let book_id = book.context().book_id;
            let rea = book.rea_snapshot(None)?;
            let mut participants = Vec::new();
            for raw_p in args.flag_all("--participant") {
                let stripped = raw_p.strip_prefix("P:").unwrap_or(raw_p);
                let p_vid = if stripped.len() == 32
                    && stripped.bytes().all(|b| b.is_ascii_hexdigit())
                    && let Ok(val) = u128::from_str_radix(stripped, 16)
                {
                    VId(val)
                } else {
                    rea.parties
                        .values()
                        .find(|p| p.code == stripped)
                        .map_or_else(|| fa_model::party_vid(book_id, stripped), |p| p.vid)
                };
                if !participants.contains(&p_vid) {
                    participants.push(p_vid);
                }
            }
            participants.sort_unstable_by_key(|v| v.0);
            let mut resources = Vec::new();
            for raw_r in args.flag_all("--resource") {
                let parts: Vec<&str> = raw_r.split(':').collect();
                let (label_str, amount_str, inst_opt) = match parts.as_slice() {
                    [lbl, amt] => (*lbl, *amt, None),
                    [lbl, amt, inst] => (*lbl, *amt, Some(*inst)),
                    _ => {
                        return Err(usage(
                            format!(
                                "--resource `{raw_r}` must be `<label>:<amount>[:<instrument>]`"
                            ),
                            "--resource cash:100.00\\ USD or --resource inventory:10.00\\ USD:INST-1",
                        ));
                    }
                };
                if label_str.is_empty() || label_str.len() > 64 {
                    return Err(usage(
                        format!("--resource label `{label_str}` must be 1..=64 bytes"),
                        "--resource revenue:100.00\\ USD",
                    ));
                }
                let amount = Amount::parse(amount_str, &book.context().units).map_err(|e| {
                    usage(
                        format!("--resource `{raw_r}` amount `{amount_str}`: {e}"),
                        "--resource cash:100.00\\ USD",
                    )
                })?;
                let instrument = inst_opt.map(|inst_s| {
                    let stripped = inst_s.strip_prefix("I:").unwrap_or(inst_s);
                    if stripped.len() == 32
                        && stripped.bytes().all(|b| b.is_ascii_hexdigit())
                        && let Ok(val) = u128::from_str_radix(stripped, 16)
                    {
                        VId(val)
                    } else {
                        rea.instruments
                            .values()
                            .find(|i| i.code == stripped)
                            .map_or_else(|| fa_model::instrument_vid(book_id, stripped), |i| i.vid)
                    }
                });
                resources.push(fa_model::EventResource {
                    label: label_str.to_string(),
                    amount,
                    instrument,
                });
            }
            resources.sort_by(|a, b| {
                a.label.cmp(&b.label).then_with(|| {
                    a.instrument
                        .map_or(0, |v| v.0)
                        .cmp(&b.instrument.map_or(0, |v| v.0))
                })
            });
            let mut external_ids = Vec::new();
            for raw_ext in args.flag_all("--external-id") {
                let (sys, ext_id) = raw_ext.split_once(':').ok_or_else(|| {
                    usage(
                        format!("--external-id `{raw_ext}` must be `<system>:<id>`"),
                        "--external-id stripe:ch_12345",
                    )
                })?;
                if sys.is_empty() || ext_id.is_empty() {
                    return Err(usage(
                        format!("--external-id `{raw_ext}` system and id must be non-empty"),
                        "--external-id stripe:ch_12345",
                    ));
                }
                external_ids.push(fa_model::ExternalId {
                    system: sys.to_string(),
                    id: book.seal_text(ext_id)?,
                });
            }
            external_ids.sort_by(|a, b| {
                a.system
                    .cmp(&b.system)
                    .then_with(|| a.id.field_digest().cmp(&b.id.field_digest()))
            });
            let evidence = document::parse_evidence(&Json::Null, args, &mut book)?;
            let description_str = args.flag("--description").unwrap_or("");
            let description = book.seal_text(description_str)?;
            let key_str = args
                .flag("--key")
                .map(str::to_string)
                .unwrap_or_else(|| format!("event:{code}"));
            let spec = fa_model::EventSpec {
                code: code.clone(),
                kind,
                occurred_on,
                description,
                participants,
                resources,
                evidence,
                external_ids,
            };
            let event_digest = spec
                .event_digest()
                .map_err(|e| usage(format!("invalid event spec: {e}"), "fa event record --help"))?;
            let recorded =
                book.record_event(&spec, who, effective_date, key_str.as_bytes(), &capability)??;
            ctx.out.at_book(&book)?;
            let vid_hex = format!("{:032x}", recorded.target_vid.0);
            let ctrl_hex = format!("{:032x}", recorded.control_entry.0);
            let dig_hex = hex(&event_digest);
            ctx.out.event(
                "event_recorded",
                vec![
                    ("event_vid", s(&vid_hex)),
                    ("code", s(&code)),
                    ("kind", s(kind.name())),
                    ("occurred_on", s(occurred_on.render())),
                    ("event_digest", s(&dig_hex)),
                    ("control_entry", s(&ctrl_hex)),
                    ("recorded_at", Json::Int(i128::from(recorded.recorded_at.0))),
                    ("already_recorded", Json::Bool(recorded.already_recorded)),
                ],
                &format!(
                    "{} event `{code}` ({vid_hex}, kind {}) occurred on {}, recorded at {}",
                    if recorded.already_recorded {
                        "already recorded"
                    } else {
                        "recorded"
                    },
                    kind.name(),
                    occurred_on.render(),
                    recorded.recorded_at.0
                ),
            );
            Ok(())
        }
        Some("show") => {
            let target = args
                .positional
                .get(2)
                .map(String::as_str)
                .or_else(|| args.flag("--code"))
                .ok_or_else(|| {
                    usage(
                        "`fa event show` needs an event code or 32-hex vid",
                        "fa event show EV-1001 --book <dir> --json",
                    )
                })?;
            if let Some(extra) = args.positional.get(3) {
                return Err(usage(
                    format!("unexpected positional `{extra}`"),
                    "fa event show <code|vid> [--as-known-at HEAD|<seq>] --book <dir>",
                ));
            }
            let capability = ctx.capability(args, &["read"])?;
            let mut selected = None;
            let book = ctx.books.open_admitted(args, |book| {
                let scope = book.read_scope(who, &capability)??;
                let (known_at, _) = known_at_read_flag(args, book, &ctx.out, &capability)?;
                let seq = scope.admit_whole_book(known_at)??;
                selected = Some(book.rea_snapshot(Some(seq))?);
                Ok(())
            })?;
            let rea = selected.ok_or_else(|| Fail::Internal("event snapshot is missing".into()))?;
            ctx.out.known_at(rea.known_at);
            let ev_row = find_event(&rea, book.context().book_id, target).ok_or_else(|| {
                usage(
                    format!("no event `{target}` in this book at {}", rea.known_at.0),
                    "fa event list --book <dir> --json",
                )
            })?;
            let detail = event_detail_json(ev_row, &book)?;
            ctx.out.event(
                "event_shown",
                vec![("detail", detail)],
                &format!(
                    "event `{}` ({:032x}) · kind {} · occurred on {} · recorded at {}",
                    ev_row.spec.code,
                    ev_row.vid.0,
                    ev_row.spec.kind.name(),
                    ev_row.spec.occurred_on.render(),
                    ev_row.created_at.0
                ),
            );
            Ok(())
        }
        Some("list") => {
            if let Some(extra) = args.positional.get(2) {
                return Err(usage(
                    format!("unexpected positional `{extra}`"),
                    "fa event list [--as-known-at HEAD|<seq>] --book <dir>",
                ));
            }
            let capability = ctx.capability(args, &["read"])?;
            let mut selected = None;
            ctx.books.open_admitted(args, |book| {
                let scope = book.read_scope(who, &capability)??;
                let (known_at, _) = known_at_read_flag(args, book, &ctx.out, &capability)?;
                let seq = scope.admit_whole_book(known_at)??;
                selected = Some(book.rea_snapshot(Some(seq))?);
                Ok(())
            })?;
            let rea = selected.ok_or_else(|| Fail::Internal("event snapshot is missing".into()))?;
            ctx.out.known_at(rea.known_at);
            let mut rows: Vec<&fa_journal::EventRow> = rea.events.values().collect();
            rows.sort_by(|a, b| {
                a.spec
                    .occurred_on
                    .cmp(&b.spec.occurred_on)
                    .then_with(|| a.spec.code.cmp(&b.spec.code))
                    .then_with(|| a.vid.cmp(&b.vid))
            });
            let items: Vec<Json> = rows.iter().map(|r| event_summary_json(r)).collect();
            let human = if rows.is_empty() {
                format!("0 events at {}", rea.known_at.0)
            } else {
                rows.iter()
                    .map(|r| {
                        format!(
                            "{:<16} {:<14} {}  {:032x}  @{}",
                            r.spec.code,
                            r.spec.kind.name(),
                            r.spec.occurred_on.render(),
                            r.vid.0,
                            r.created_at.0
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            ctx.out.event(
                "events_listed",
                vec![
                    ("known_at", Json::Int(i128::from(rea.known_at.0))),
                    ("count", Json::Int(items.len() as i128)),
                    ("events", Json::Arr(items)),
                ],
                &human,
            );
            Ok(())
        }
        other => Err(unhandled("event", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The trial balance's net is checked arithmetic: an in-range difference
    /// is exact, including a full-range negative, and one outside `i128` is
    /// a foundation failure naming the account, never a wrapped value.
    #[test]
    fn the_trial_balance_net_is_checked_arithmetic() {
        assert_eq!(tb_net("1000", 500, 200).ok(), Some(300));
        assert_eq!(tb_net("1000", 0, i128::MAX).ok(), Some(-i128::MAX));
        let named = match tb_net("6000", i128::MIN, 1) {
            Err(Fail::Internal(message)) => message.contains("6000"),
            _ => false,
        };
        assert!(
            named,
            "an out-of-range net is a foundation failure naming the account"
        );
    }

    /// The other half of the parity gate (the binary tests prove every
    /// registered verb and subcommand reaches a handler): a handler whose
    /// verb is not in verbs.toml would be unreachable, so the two lists are
    /// the same verbs in the same order.
    #[test]
    fn handlers_and_the_verb_registry_name_the_same_verbs() {
        let reg = verbs::registry().expect("verbs.toml");
        let handled: Vec<&str> = HANDLERS.iter().map(|(name, _)| *name).collect();
        let registered: Vec<&str> = reg.verbs.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(handled, registered);
    }

    fn render_fixture(unit: fa_money::UnitId) -> fa_registers::TrialBalance {
        fa_registers::TrialBalance {
            periods: vec!["FY2026-P03".into()],
            known_at: CommitSeq(9),
            effective_through: Some(DateDay(0)),
            activity: false,
            rows: vec![fa_registers::TbRow {
                account: VId(1),
                code: "1000".into(),
                name: "Cash".into(),
                account_type: AccountType(1),
                unit_id: unit.0,
                debits: 1_234,
                credits: 1_234,
                debits_pending: 25,
                credits_pending: 25,
            }],
            unit_totals: [(unit.0, (1_234, 1_234))].into_iter().collect(),
            pending_unit_totals: [(unit.0, (25, 25))].into_iter().collect(),
        }
    }

    #[test]
    fn unknown_units_refuse_reports_before_any_success_output() {
        let units = fa_money::UnitRegistry::with_defaults();
        let usd = units.lookup("USD").unwrap();
        let unknown = fa_money::UnitId(u32::MAX);
        assert!(units.get(unknown).is_none());
        let certificate = "a".repeat(64);
        let reg = verbs::registry().expect("verbs.toml");
        for location in ["row", "posted total", "pending total"] {
            let mut tb = render_fixture(usd);
            match location {
                "row" => tb.rows.push(fa_registers::TbRow {
                    account: VId(2),
                    code: "2000".into(),
                    unit_id: unknown.0,
                    ..tb.rows[0].clone()
                }),
                "posted total" => {
                    tb.unit_totals.insert(unknown.0, (0, 0));
                }
                _ => {
                    tb.pending_unit_totals.insert(unknown.0, (0, 0));
                }
            }
            let selection = TrialBalanceSelection::Periods(tb.periods.clone());
            for json in [false, true] {
                let out = Out::new(json, true);
                let result = render_trial_balance_with_units(
                    &out,
                    &units,
                    &tb,
                    &selection,
                    Some(&certificate),
                    None,
                );
                assert!(matches!(
                    &result,
                    Err(Fail::Book(BookError::Kernel(
                        fa_journal::KernelError::Corrupt(_)
                    )))
                ));
                let (code, captured) = finish_into(out, result);
                assert_eq!(code, exit::FOUNDATION, "{location}: {}", captured.stderr);
                assert!(
                    captured.stderr.contains("unknown unit"),
                    "{}",
                    captured.stderr
                );
                assert!(
                    captured.stderr.contains("unit reconciliation"),
                    "{}",
                    captured.stderr
                );
                if json {
                    assert_eq!(captured.stdout.lines().count(), 1, "{}", captured.stdout);
                    assert_eq!(
                        reg.check_line(captured.stdout.trim_end()),
                        Ok("error"),
                        "{}",
                        captured.stdout
                    );
                    assert!(captured.stdout.contains(r#""exit":5"#));
                    assert!(captured.stdout.contains(r#""class":"foundation""#));
                    assert!(captured.stdout.contains(r#""certificate":null"#));
                    assert!(!captured.stdout.contains(r#""event":"trial_balance""#));
                } else {
                    assert!(
                        captured.stdout.is_empty(),
                        "{location}: {}",
                        captured.stdout
                    );
                }
            }
        }
    }

    #[test]
    fn registered_amounts_keep_report_text_and_certificate_binding() {
        let units = fa_money::UnitRegistry::with_defaults();
        let tb = render_fixture(units.lookup("USD").unwrap());
        let selection = TrialBalanceSelection::Periods(tb.periods.clone());
        let certificate = "b".repeat(64);
        let reg = verbs::registry().expect("verbs.toml");
        for json in [false, true] {
            let out = Out::new(json, true);
            out.said.borrow_mut().at = Some(At {
                book: "0a1b".into(),
                branch: "trunk".into(),
                known_at: CommitSeq(10),
                effective: "all".into(),
            });
            let result = render_trial_balance_with_units(
                &out,
                &units,
                &tb,
                &selection,
                Some(&certificate),
                None,
            );
            let (code, captured) = finish_into(out, result);
            assert_eq!(code, exit::SUCCESS, "{}", captured.stderr);
            assert!(captured.stderr.is_empty(), "{}", captured.stderr);
            assert!(captured.stdout.contains("12.34 USD"), "{}", captured.stdout);
            assert!(captured.stdout.contains("0.25 USD"), "{}", captured.stdout);
            if json {
                assert_eq!(
                    reg.check_line(captured.stdout.trim_end()),
                    Ok("trial_balance"),
                    "{}",
                    captured.stdout
                );
                assert!(captured.stdout.contains(r#""net":"0.00 USD""#));
                assert!(captured.stdout.contains(r#""known_at":9"#));
                assert!(
                    captured
                        .stdout
                        .contains(&format!(r#""certificate":"{certificate}""#)),
                    "{}",
                    captured.stdout
                );
            } else {
                assert!(captured.stdout.contains("balanced: true"));
            }
        }
    }

    /// A drift row only arises from a tampered store, which no binary test
    /// can produce: check the rendered rows (a cell rebound to another
    /// account, a missing cell) against the robot schema here.
    #[test]
    fn availability_drift_rows_render_to_the_schema() {
        let reg = verbs::registry().expect("verbs.toml");
        let cell = |posted: i128| fa_journal::LimitCell {
            debits_posted: posted,
            credits_posted: 0,
            debits_pending: 0,
            credits_pending: 0,
            generation: 1,
        };
        let v = fa_registers::AvailabilityVerification {
            known_at: CommitSeq(9),
            accounts_checked: 2,
            cells_checked: 2,
            accounts: vec![fa_registers::AccountAvailability {
                account: VId(1),
                code: "1000".into(),
                period: None,
                normal: Side::Debit,
                limit: BalanceLimit {
                    lower: Some(0),
                    upper: None,
                    scope: fa_journal::LimitScope::Lifetime,
                },
                cell: cell(4_000),
                net: 4_000,
                pending_out: 0,
                pending_in: 0,
            }],
            drift: vec![
                fa_registers::AvailabilityDrift {
                    account: VId(1),
                    code: "1000".into(),
                    stored: Some(cell(4_000)),
                    refolded: cell(4_000),
                    stored_account: Some(VId(2)),
                    stored_account_code: Some("1100".into()),
                    period: None,
                    stored_period: None,
                },
                fa_registers::AvailabilityDrift {
                    account: VId(3),
                    code: "1200".into(),
                    stored: None,
                    refolded: cell(0),
                    stored_account: None,
                    stored_account_code: None,
                    // A budget cap's cell that claims another period.
                    period: Some("FY2026-P03".into()),
                    stored_period: Some("FY2026-P04".into()),
                },
            ],
        };
        let amount = |_: &str, m: i128| -> Result<Json, Fail> {
            Ok(s(format!("{}.{:02} USD", m / 100, m % 100)))
        };
        let rendered = availability_fields(&v, &amount);
        assert!(rendered.is_ok(), "every amount renders");
        let at = At {
            book: "0a1b".into(),
            branch: "trunk".into(),
            known_at: CommitSeq(9),
            effective: "all".into(),
        };
        let data = obj(rendered.unwrap_or_default());
        let line = robot_line("availability_verified", data, Some(&at), &[]).render();
        assert_eq!(reg.check_line(&line), Ok("availability_verified"), "{line}");
        assert!(
            line.contains(&format!(r#""stored_account":"{:032x}""#, 2))
                && line.contains(r#""stored_account_code":"1100""#)
                && line.contains(r#""stored":null"#)
                && line.contains(r#""period":"FY2026-P03""#)
                && line.contains(r#""stored_period":"FY2026-P04""#)
                && line.contains(r#""cells_checked":2"#)
                && line.contains(r#""net":"40.00 USD""#),
            "{line}"
        );
        let missing_units = fa_money::UnitRegistry::empty();
        let corrupt_amount = |_: &str, m: i128| -> Result<Json, Fail> {
            Ok(s(render_amount(
                Amount::new(fa_money::UnitId(7), m),
                &missing_units,
            )?))
        };
        assert!(matches!(
            availability_fields(&v, &corrupt_amount),
            Err(Fail::Book(BookError::Kernel(
                fa_journal::KernelError::Corrupt(_)
            )))
        ));
    }

    /// Styling is resolved once (plan Appendix D determinism): only a
    /// terminal with nothing asking for plain output is styled; robot mode,
    /// a daemon capture, --no-color, NO_COLOR, CI and TERM=dumb never are,
    /// and an empty NO_COLOR or CI=false/0 asks for nothing.
    #[test]
    fn styling_is_off_unless_a_terminal_asks_for_nothing_plain() {
        let none = |_: &str| None::<String>;
        let styled = Style::resolve(false, false, false, true, none);
        assert_eq!(styled.header("code"), "\u{1b}[1mcode\u{1b}[0m");
        let only = |name: &'static str, value: &'static str| {
            move |k: &str| (k == name).then(|| value.to_string())
        };
        for (what, style) in [
            ("robot mode", Style::resolve(true, false, false, true, none)),
            ("--no-color", Style::resolve(false, true, false, true, none)),
            (
                "a daemon capture",
                Style::resolve(false, false, true, true, none),
            ),
            (
                "not a terminal",
                Style::resolve(false, false, false, false, none),
            ),
            (
                "NO_COLOR",
                Style::resolve(false, false, false, true, only("NO_COLOR", "1")),
            ),
            (
                "CI",
                Style::resolve(false, false, false, true, only("CI", "true")),
            ),
            (
                "TERM=dumb",
                Style::resolve(false, false, false, true, only("TERM", "dumb")),
            ),
        ] {
            assert_eq!(style, Style::PLAIN, "{what}");
            assert_eq!(style.header("code"), "code", "{what}");
        }
        for (name, value) in [
            ("NO_COLOR", ""),
            ("CI", "false"),
            ("CI", "0"),
            ("TERM", "xterm-256color"),
        ] {
            let style = Style::resolve(false, false, false, true, only(name, value));
            assert_eq!(style, styled, "{name}={value}");
        }
    }
}
