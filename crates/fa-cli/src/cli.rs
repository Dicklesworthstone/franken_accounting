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

use fa::book::{Book, BookError, BookKeys, Entropy};
use fa::{
    MAX_PLAN_BYTES, PostIntent, PostPlan, ReportOutput, ReportSelection, Statement,
    StatementDefinition, StatementSelection, TrialBalanceSelection,
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

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Plan Appendix D FA-REF-007: an operation that cannot be undone in
/// practice was not confirmed (`--yes`, or a `--plan` file), exit 7.
pub(crate) const CONFIRMATION_REQUIRED: &str = "FA-REF-007";

type Handler = fn(&mut Ctx<'_>, &Args) -> Result<(), Fail>;

/// One handler per registered verb, keyed by the registry's verb name.
const HANDLERS: &[(&str, Handler)] = &[
    ("book", book_cmd),
    ("chart", chart_cmd),
    ("period", period_cmd),
    ("approve", approve_cmd),
    ("post", post_cmd),
    ("commit", commit_cmd),
    ("reverse", reverse_cmd),
    ("reserve", reserve_cmd),
    ("resolve", resolve_cmd),
    ("document", document::document_cmd),
    ("tb", tb_cmd),
    ("statement", statement_cmd),
    ("replay", notary::replay_cmd),
    ("certificate", notary::certificate_cmd),
    ("open-items", open_items_cmd),
    ("explain", explain_cmd),
    ("procedure", procedure_cmd),
    ("checkpoint", notary::checkpoint_cmd),
    ("proof", crate::proof::proof_cmd),
    ("bundle", crate::proof::bundle_cmd),
    ("doctor", crate::triage::doctor_cmd),
    ("triage", crate::triage::triage_cmd),
    ("next", crate::triage::next_cmd),
    ("verify", verify_cmd),
    ("registers", registers_cmd),
    ("entry", entry_cmd),
    ("capabilities", capabilities_cmd),
    ("robot-docs", robot_docs_cmd),
    ("help", help_cmd),
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

fn render_amount(amount: Amount, units: &fa_money::UnitRegistry) -> Result<String, Fail> {
    amount.try_render(units).map_err(amount_corruption)
}

fn registered_unit_code(
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
    owner_principal: Option<String>,
}

/// Where a robot line sits (plan §4.8): the book's id, and the branch
/// (trunk; drafts and scenarios land later), recorded sequence and
/// effective selector it describes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct At {
    pub book: String,
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
                    ("branch", s("trunk")),
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
    said.at = Some(At {
        book: book.context().book_id.to_hex(),
        known_at: head,
        effective,
    });
    Ok(())
}

pub(crate) struct Out {
    json: bool,
    style: Style,
    sink: Sink,
    said: Rc<RefCell<Said>>,
}

impl Out {
    fn new(json: bool, capture: bool) -> Self {
        Self::styled(json, capture, Style::PLAIN)
    }

    fn with_authority(self, authority: Option<&LaunchAuthority>) -> Self {
        self.said.borrow_mut().authority = authority.map(LaunchAuthority::envelope_json);
        self
    }

    fn is_bound(&self) -> bool {
        self.said.borrow().authority.is_some()
    }

    fn styled(json: bool, capture: bool, style: Style) -> Self {
        Self {
            json,
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
                        .unwrap_or_else(|| owner_envelope(said.owner_principal.as_deref())),
                },
            );
            self.line(line.render());
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
        let dir = book_dir(args, cwd)?;
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
                    match crate::lease::Lease::acquire(&dir, lease, note) {
                        Ok(acquired) => *held = Some(acquired),
                        Err(error @ crate::lease::LeaseError::Held { .. }) => {
                            let mut refusal = error.refusal(&dir);
                            refusal.message.push_str(
                                "; launch-bound authority cannot be forwarded through the unauthenticated fad protocol",
                            );
                            refusal.fix = "ask the operator to release the book's writer lease, then retry this launch-bound session; authenticated daemon sessions are not yet available (fa-r3q)".into();
                            return Err(Fail::Refusal(refusal));
                        }
                        Err(error @ crate::lease::LeaseError::Io { .. }) => {
                            return Err(Fail::Environment(format!(
                                "cannot acquire the configured book's writer lease: {error}"
                            )));
                        }
                    }
                }
                let keys = BookKeys::load(&keys_path(args, &dir, cwd))?;
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

    fn is_held(&self) -> bool {
        matches!(self, Self::Held { .. })
    }
}

/// A command's book source: its [`Books`], stamping the envelope coordinate
/// on every book it opens (plan Appendix D), so no handler can emit a book
/// event without one.
pub(crate) struct BookSource<'a> {
    books: Books<'a>,
    said: Rc<RefCell<Said>>,
    /// The command's [`Files::cwd`], which its book path is relative to.
    cwd: Option<PathBuf>,
}

impl BookSource<'_> {
    /// The book directory and key file `args` name, resolved as `open`
    /// resolves them, without opening anything.
    pub(crate) fn locate(&self, args: &Args) -> Result<(PathBuf, PathBuf), Fail> {
        let dir = book_dir(args, self.cwd.as_deref())?;
        let keys = keys_path(args, &dir, self.cwd.as_deref());
        Ok((dir, keys))
    }

    pub(crate) fn open(&mut self, args: &Args) -> Result<BookRef<'_>, Fail> {
        let book = self.books.open(args, self.cwd.as_deref())?;
        stamp(&self.said, &book)?;
        Ok(book)
    }

    pub(crate) fn is_held(&self) -> bool {
        self.books.is_held()
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

/// Everything a command runs against.
pub(crate) struct Ctx<'a> {
    pub(crate) out: Out,
    pub(crate) books: BookSource<'a>,
    pub(crate) files: Files,
    authority: Option<LaunchAuthority>,
}

impl Ctx<'_> {
    pub(crate) fn principal(&self, args: &Args) -> VId {
        self.authority
            .as_ref()
            .map_or_else(|| principal(args), LaunchAuthority::principal_vid)
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
    run_scoped(argv, books, files, None, capture)
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
    run_scoped(argv, books, files, Some(authority), capture)
}

fn run_scoped(
    argv: &[String],
    books: Books<'_>,
    files: Files,
    authority: Option<&LaunchAuthority>,
    capture: bool,
) -> (u8, Captured) {
    let json = argv.iter().any(|a| a == "--json");
    let reg = match registry() {
        Ok(r) => r,
        Err(fail) => {
            return finish_into(Out::new(json, capture).with_authority(authority), Err(fail));
        }
    };
    let mut args = match args::parse(argv, &reg.value_flags(), &reg.switches()) {
        Ok(a) => a,
        Err(e) => {
            return finish_into(
                Out::new(json, capture).with_authority(authority),
                Err(Fail::Usage(e)),
            );
        }
    };
    if let Some(authority) = authority {
        for flag in ["--as", "--grant", "--yes", "--book", "--keys", "--via"] {
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
    let json = args.switch("--json");
    let style = Style::resolve(
        json,
        args.switch("--no-color"),
        capture,
        std::io::stdout().is_terminal(),
        |name| std::env::var(name).ok(),
    );
    let out = Out::styled(json, capture, style).with_authority(authority);
    if authority.is_none() {
        out.said.borrow_mut().owner_principal =
            Some(args.flag("--as").unwrap_or("operator").to_string());
    }
    let books = BookSource {
        books,
        said: Rc::clone(&out.said),
        cwd: files.cwd.clone(),
    };
    let mut ctx = Ctx {
        out,
        books,
        files,
        authority: authority.cloned(),
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
    let json = argv.iter().any(|a| a == "--json");
    finish_into(
        Out::new(json, capture).with_authority(Some(authority)),
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
    let json = argv.iter().any(|a| a == "--json");
    finish_into(Out::new(json, capture), Err(fail))
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
    }
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
        },
        Err(Fail::Refusal(r)) => Failure {
            exit: r.exit,
            refusal_id: Some(r.code),
            diag: format!("refused {r}"),
            message: r.message,
            cite: Some(r.cite),
            fix: Some(r.fix),
            detail: Json::Null,
        },
        Err(Fail::Book(e)) => {
            let code = e.exit();
            Failure {
                exit: code,
                refusal_id: None,
                diag: format!("error (exit {code}): {e}"),
                message: e.to_string(),
                cite: None,
                fix: None,
                detail: Json::Null,
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
        },
        Err(Fail::Internal(message) | Fail::Io(message)) => Failure {
            exit: exit::FOUNDATION,
            refusal_id: None,
            diag: format!("error (exit {}): {message}", exit::FOUNDATION),
            message,
            cite: None,
            fix: None,
            detail: Json::Null,
        },
        Err(Fail::Environment(message)) => Failure {
            exit: exit::ENVIRONMENT,
            refusal_id: None,
            diag: format!("error (exit {}): {message}", exit::ENVIRONMENT),
            message,
            cite: None,
            fix: None,
            detail: Json::Null,
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
        ],
        "",
    );
    out.diag(failure.diag);
    failure.exit
}

fn dispatch(ctx: &mut Ctx<'_>, reg: &Registry, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    if args.switch("--version") {
        out.event(
            "version",
            vec![("version", s(VERSION))],
            &format!("fa {VERSION}"),
        );
        return Ok(());
    }
    // An alias expands in the verb position (plan §15.3: the spellings agents
    // try first). It is a registered synonym, never a guessed correction.
    let expanded;
    let args = match args.positional.first().and_then(|w| reg.alias(w)) {
        Some(alias) => {
            let mut a = args.clone();
            a.positional = alias
                .expands
                .iter()
                .chain(args.positional.iter().skip(1))
                .cloned()
                .collect();
            expanded = a;
            &expanded
        }
        None => args,
    };
    let Some(word) = args.positional.first() else {
        check_flags(reg, None, args)?;
        if args.switch("--help") {
            return emit_help(out, reg, None);
        }
        out.event(
            "triage",
            vec![("version", s(VERSION)), ("text", s(triage_text()))],
            triage_text().trim_end(),
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
    check_flags(reg, Some(verb), args)?;
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
    gate_from_argv(out, reg, verb, args, ctx.authority.as_ref())?;
    admit_bound_command(ctx, verb, args)?;
    admit_bound_files(ctx, verb, args)?;
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
    matches!(verb, "post" | "reverse" | "reserve" | "resolve") && args.switch("--dry-run")
}

/// Admit the concrete operation before handlers read input files or the
/// book. Legacy facade mutations without a caller capability remain owner
/// operations. Report certificates and derived register caches are metadata,
/// not accounting entries; their actual dangerous rewrites are gated too.
fn admit_bound_command(ctx: &Ctx<'_>, verb: &Verb, args: &Args) -> Result<(), Fail> {
    let Some(authority) = &ctx.authority else {
        return Ok(());
    };
    use fa_policy::Op;
    let sub = args.positional.get(1).map(String::as_str);
    let required: &[Op] = if period_plan_only(&verb.name, args) {
        &[Op::Read]
    } else {
        match (verb.name.as_str(), sub) {
            // The chart templates are data embedded in this build; listing
            // them reads nothing from the book.
            ("capabilities" | "robot-docs" | "help", _) | ("chart", Some("templates")) => &[],
            ("book", Some("info"))
            | ("chart" | "period", Some("list"))
            | (
                "tb" | "statement" | "open-items" | "explain" | "replay" | "certificate" | "entry"
                | "procedure" | "triage" | "next",
                _,
            ) => &[Op::Read],
            ("verify" | "registers", _) => &[Op::Read, Op::Verify],
            ("post" | "commit" | "reverse" | "reserve" | "resolve", _) => &[Op::Post],
            ("approve", _) => &[Op::Approve],
            ("checkpoint", _) => &[Op::Witness],
            ("proof" | "bundle", _) => &[Op::Read, Op::Produce],
            _ => {
                return Err(Refusal::new(
                    fa_journal::refusal::code::CAPABILITY,
                    exit::SAFETY,
                    format!("`{}` is not admitted by the launch-bound MCP command surface", command_name(&verb.name, sub)),
                    "plan §14.2–§14.4; fa-23r (authority before observation)",
                    "ask the operator to perform this owner operation; document intake needs its provenance-authorized surface (fa-vwf), and period lock/reopen can be prepared with --plan-out",
                ).into());
            }
        }
    };
    for op in required {
        fa_policy::require(authority.capability(), *op, &command_name(&verb.name, sub))
            .map_err(|denial| {
                let mut refusal = fa_journal::policy::refusal(&denial);
                refusal.fix = "identity and authority are fixed when the server starts; ask the operator to start a server with the profile and operations you need".into();
                Fail::Refusal(refusal)
            })?;
    }
    Ok(())
}

/// Bound hosts receive content through forwarded stdin. Caller paths never
/// become host reads or writes; the configured book and keys are separate,
/// trusted launch inputs. No filesystem root is supported in this slice.
fn admit_bound_files(ctx: &Ctx<'_>, verb: &Verb, args: &Args) -> Result<(), Fail> {
    if ctx.authority.is_none() {
        return Ok(());
    }
    let blocked = |argument: &str, fix: &str| {
        usage(
            format!("{argument} cannot name a host filesystem path in a launch-bound request"),
            fix,
        )
    };
    for flag in ["--plan-out", "--certificate-out", "--out"] {
        if args.flag(flag).is_some() {
            return Err(blocked(
                flag,
                "use --dry-run for inline plan bytes or --certify for a retained certificate; MCP accepts no output paths (fa-yha)",
            ));
        }
    }
    for flag in ["--intent", "--plan"] {
        if args.flag_all(flag).iter().any(|value| *value != "-") {
            return Err(blocked(
                flag,
                "forward the complete content on stdin with -; MCP takes the inline intent or plan property, never a file path (fa-yha)",
            ));
        }
    }
    let sub = args.positional.get(1).map(String::as_str);
    let input = match (verb.name.as_str(), sub) {
        ("chart", Some("import")) | ("document", Some("add")) => args.positional.get(2),
        ("replay", _) => args.positional.get(1),
        ("certificate", Some("status")) => args.positional.get(2),
        _ => None,
    };
    if let Some(input) = input {
        let digits = input.strip_prefix("C:").unwrap_or(input);
        let retained = matches!(verb.name.as_str(), "replay" | "certificate")
            && digits.len() == 64
            && digits.bytes().all(|byte| byte.is_ascii_hexdigit());
        if input != "-" && !retained {
            return Err(blocked(
                "file",
                "forward the complete input on stdin with -; report replay also accepts a retained C:<oid>. MCP uses inline chart, text, or certificate properties (fa-yha)",
            ));
        }
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
fn unconfirmed(d: &Dangerous) -> Fail {
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
            d.safe
        ),
    ))
}

fn unconfirmed_bound(d: &Dangerous) -> Fail {
    let alternative = if d.verb == "period"
        && matches!(d.subcommand.as_deref(), Some("lock" | "reopen" | "close"))
    {
        format!(
            "prepare the operation with `fa period {} <code> --dry-run`; an independent operator must review and commit it",
            d.subcommand.as_deref().unwrap_or("lock")
        )
    } else {
        d.safe.clone()
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
    if period_plan_only(&verb.name, args) || post_plan_only(&verb.name, args) {
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
                unconfirmed_bound(d)
            } else {
                unconfirmed(d)
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
            unconfirmed_bound(d)
        } else {
            unconfirmed(d)
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
            let name = reg
                .alias(word)
                .and_then(|a| a.expands.first())
                .unwrap_or(word);
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

fn capabilities_cmd(ctx: &mut Ctx<'_>, _args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let reg = registry()?;
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
        ("capability", capability_model(ctx.authority.as_ref())?),
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
fn capability_model(authority: Option<&LaunchAuthority>) -> Result<Json, Fail> {
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
                "an Agent-profile capability never writes trunk (FA-REF-013); drafts land with the branch slice",
            ),
        ),
        (
            "binding",
            obj(vec![
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
                        "embedded-owner posture: the calling process supplies --as and self-issues Human-profile operations per command with --grant, without ceilings or expiry. The current fad argv route has the same owner posture and no authenticated session. MCP uses a separate launch-config binding and refuses this daemon route. The kernel evaluates supplied authority; it does not authenticate the operator."
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
1. Every command accepts --json. Parse stdout line by line; each line is one JSON object {v, event, book, coordinate, data, certificate, authority, warnings, next_actions}: `event` names the schema of `data`; `book` and `coordinate` say which book and (branch, known_at, effective) the line describes; `authority` declares the actual execution binding; `next_actions` are the commands usually run next (add the same --book in the owner's CLI).\n\
2. Read the exit code before the output: 0 success (empty results are 0), 2 usage, 3 accounting-law refusal, 4 environment, 5 foundation/I-O, 6 conflict (retry with a fresh read), 7 safety block (period law, capability, an unconfirmed dangerous operation), 8 verification failure. 1 is never emitted.\n\
3. Every non-zero exit is exactly one `error` line: data {class, exit, refusal_id, message, cite, fix, detail}. `refusal_id` (FA-REF-nnn) is the refusal catalog code when one applies. Do the `fix`; do not invent a leg, a date, or an approval. FA-REF-007 means the operation cannot be undone in practice: its fix names the safe alternative; add --yes only when the operation is intended (`fa capabilities --json` lists them under `dangerous`).\n\
4. Amounts are strings with the unit: \"1500.00 USD\". Never floats. Dates are civil YYYY-MM-DD; recorded time is assigned by the journal, never supplied.\n\
5. Corrections are new entries (Reversal, Replacement, Reclassification) that cite the original; nothing is edited in place.\n\
6. Idempotency: every intent carries idempotency_key; resubmitting returns the recorded outcome (event \"recorded\"), never a duplicate.\n\
7. Posting into a non-Open period is decided by the admissibility matrix; the refusal cites the (class, state) cell and names the admissible class or capability.\n\
8. Two-phase: `fa reserve` posts a Pending (amounts in the pending columns, never posted); `fa resolve` names it with `resolves` and either posts a sub-vector (`legs`, each drawn from one hold leg — same account and side, at most the reserved amount; add `source_ordinal` when the hold has several such legs) or voids it (`disposition: \"voids\"`). The rest of the hold is released either way. One resolution per hold: a second is exit 6 (FA-REF-062); resolving a non-hold is FA-REF-060.\n\
9. Explain before you trust: `fa explain balance <account> --period <code> --json` returns the account's register cells, the fold digest they belong to, every contributing leg with its entry and recorded_at, and the cells' known-at history; the legs re-add to the cells exactly. Add --as-known-at <seq> to see what was known then.\n\
10. Schemas: `fa robot-docs schema --json` lists every event and its fields (generated from registries/verbs.toml); `fa robot-docs schema <event>` prints one. `fa <command> --help` prints that command's usage, flags, events and exits.\n\
11. Application: a leg may carry `settles: [{entry, ordinal, amount}]` to apply itself to an open item — the opposite side on the same account and unit, at most the item's open amount (FA-REF-072 names what is open). `fa open-items --account <code>` lists items with their applications. Reversing a receipt reopens the invoice (its applications are undone, never re-entered); an invoice with live applications cannot be reversed until its receipts are (FA-REF-073).\n\
12. Corrections require a registered reason: `fa reverse <vid> --reason WrongAccount --json` derives the opposite legs and retains the target's date by default; --effective selects an explicit same-or-later admissible period. A Reversal passed to `fa post` likewise carries `reason`, for example \"WrongAmount\". `fa entry show <reversal vid> --json` reports the immutable supersession and its reason. Other requires a description; no reason code proves the explanation true.\n\
13. Retain a report for replay: `fa tb --period FY2026-P03 --certify --json`, `fa explain balance 1000 --period FY2026-P03 --certify --json`, and `fa open-items --account 1000 --certify --json` retain the report's certificate in the book. Each emits its original report event followed by report_certificate, binding the selector, known-at, historical account metadata and native history. `fa replay C:<oid> --json` reproduces the original report, and `fa certificate status C:<oid> --json` names later relevant entries without changing it. --certificate-out report.cert also writes a new external copy, never overwriting one. File and complete inline hex remain accepted; MCP accepts the returned oid or bytes as certificate. Certification writes metadata, never accounting entries; uncertified reads do not write. Scope is fa-fold-over-prefix with embedded-owner authority.\n\
14. Rehearse an entry before writing: add --dry-run to post, reverse, reserve or resolve. The actual posting laws run, their staged transaction is aborted, and one plan event returns the exact sealed proposal, native effects digest, snapshot and complete canonical bytes. --plan-out <new-file> saves a private binary copy without replacing a file. Review it, then `fa commit --plan <file|-> --json` with the same owner --as and --grant; stdin accepts the bytes hex string. MCP uses fa_post_commit_plan with plan set to that string and keeps its launch-bound capability unchanged: ordinary Preparer plans can commit, Agent trunk posting still refuses, and dangerous void commits remain unavailable until separate confirmation exists. A first commit atomically retains its graph Certificate and CITES edge; an exact retry returns plan_committed with already_recorded=true. Any intervening book publication invalidates this first same-snapshot plan and requires another dry run. Planning collects no new approvals and provides no draft or --balancing support. A dry-run void releases nothing; the owner explicitly confirms its exact artifact, while MCP must ask the operator to separately prepare and confirm a release. Public plan digests are data fields, never native object-store OIDs in the envelope.\n";

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
fn keys_path(args: &Args, dir: &Path, cwd: Option<&Path>) -> PathBuf {
    args.flag("--keys")
        .map_or_else(|| dir.join("book.keys"), |k| resolve_in(cwd, k))
}

pub(crate) fn principal(args: &Args) -> VId {
    principal_vid(args.flag("--as").unwrap_or("operator"))
}

fn date_flag(args: &Args, default: DateDay) -> Result<DateDay, Fail> {
    match args.flag("--date") {
        None => Ok(default),
        Some(d) => DateDay::parse(d)
            .map_err(|e| usage(format!("--date `{d}`: {e:?}"), "--date YYYY-MM-DD")),
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_json(path: &str, text: &str) -> Result<Json, Fail> {
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
    match args.positional.get(1).map(String::as_str) {
        Some("create") => {
            if args.flag_all("--time-zone").len() > 1 {
                return Err(usage(
                    "--time-zone may be supplied only once",
                    "--time-zone UTC",
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
            let kind = args.flag("--calendar").unwrap_or("monthly");
            if kind != "monthly" {
                return Err(usage(
                    format!("calendar `{kind}` is not available from the CLI yet"),
                    "--calendar monthly (4-4-5 and 52/53-week calendars land with the next slice)",
                ));
            }
            let ysm: u8 = args
                .flag("--year-start-month")
                .unwrap_or("1")
                .parse()
                .map_err(|_| usage("--year-start-month must be 1..=12", "--year-start-month 1"))?;
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
            let calendar = FiscalCalendar::monthly("fiscal", ysm, adj).map_err(|e| {
                usage(
                    format!("calendar: {e:?}"),
                    "--year-start-month 1..=12 --adjustment-periods 0..=4",
                )
            })?;
            let entropy = Entropy::production();
            let keys = BookKeys::generate(&entropy)?;
            let mut id = [0u8; 16];
            entropy.fill(&mut id).map_err(BookError::Entropy)?;
            let book_id = Id128(id);
            let keys_file = keys_path(args, &dir, ctx.files.cwd.as_deref());
            std::fs::create_dir_all(&dir).map_err(|e| BookError::Io(dir.clone(), e))?;
            keys.save(&keys_file)?;
            let book = Book::create_dir(
                &dir,
                keys,
                BookSpec {
                    book_id,
                    name: name.to_string(),
                    base_unit,
                    calendar,
                    time_zone_policy,
                    entities: Vec::new(),
                    opening_date: None,
                },
                entropy,
            )?;
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
            let base_unit = book.spec()?.base_unit;
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
        other => Err(unhandled("book", other)),
    }
}

// ---------------------------------------------------------------------------
// chart
// ---------------------------------------------------------------------------

fn chart_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let who = ctx.principal(args);
    let out = &ctx.out;
    match args.positional.get(1).map(String::as_str) {
        Some("import") => {
            // A chart comes from a file (or `-`), or from an embedded
            // template (plan §4.3, fa-48m): exactly one of the two.
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
            let doc = parse_json(path, &text)?;
            let mut book = ctx.books.open(args)?;
            // `"unit": "base"` is the book's own base unit, journaled at
            // genesis, so one chart document serves a book in any currency.
            let base_unit = book.spec()?.base_unit;
            let units = &book.context().units;
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
                            "type: Asset|Liability|Equity|Revenue|Expense|Memo|Statistical",
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
            let date = date_flag(args, DateDay(0))?;
            let key = match args.flag("--key") {
                Some(k) => k.as_bytes().to_vec(),
                None => templates::chart_key(&text).into_bytes(),
            };
            let installed = book.install_chart(&accounts, who, date, &key)??;
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
                ],
                &format!(
                    "installed {} accounts{} (control entry {:032x}, recorded at {})",
                    installed.accounts,
                    template.map_or_else(String::new, |t| format!(" from template {}", t.name)),
                    installed.control_entry.0,
                    installed.recorded_at.0
                ),
            );
            Ok(())
        }
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
            let bound = |a: &fa_journal::AccountRow, m: Option<i128>| -> Result<Json, Fail> {
                match (a.unit_policy, m) {
                    (UnitPolicy::Single(u), Some(m)) => {
                        Ok(s(render_amount(Amount::new(u, m), units)?))
                    }
                    _ => Ok(Json::Null),
                }
            };
            let items: Vec<Json> = rows
                .iter()
                .map(|a| {
                    Ok(obj(vec![
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
                    ]))
                })
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
        other => Err(unhandled("chart", other)),
    }
}

// ---------------------------------------------------------------------------
// period
// ---------------------------------------------------------------------------

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
            let mut book = ctx.books.open(args)?;
            let (seq, periods) = book.create_periods(fy)?;
            out.at_book(&book)?;
            let codes: Vec<Json> = periods.iter().map(|p| s(&p.code)).collect();
            out.event("periods_created", vec![("fiscal_year", Json::Int(i128::from(fy))), ("periods", Json::Arr(codes)), ("recorded_at", Json::Int(i128::from(seq.0)))], &format!("created {} periods for FY{fy} (all Future; open them with `fa period open <code>`)", periods.len()));
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
            let reason: u16 = args.flag("--reason").unwrap_or("0").parse().map_err(|_| {
                usage(
                    "--reason must be a registered reason code (u16)",
                    "--reason 0",
                )
            })?;
            let who = ctx.principal(args);
            let op = fa_journal::policy::steward()
                .map_err(BookError::Kernel)?
                .transition_op("PeriodControl", fa_journal::transition_name(transition))
                .ok_or_else(|| {
                    Fail::Internal(format!("no PeriodControl {t} rule in sod_policy.toml"))
                })?;
            let capability = ctx.capability(args, &[op.name()])?;
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
            let date = date_flag(
                args,
                book.periods()?
                    .into_iter()
                    .find(|p| &p.code == code)
                    .map(|p| p.start)
                    .unwrap_or(DateDay(0)),
            )?;
            let approval_flags = args.flag_all("--approval");
            // A plan seals the description once (R4), so an approval
            // recorded by another principal, in another process, binds the
            // proposal the commit rebuilds from the plan's inputs. Plan files
            // resolve against the caller's working directory, as every file
            // argument does (a daemon writes and reads the client's).
            if args.switch("--dry-run") {
                let plan = book.plan_transition(code, transition, who, reason, date, &key)??;
                let digest = book.plan_digest(&plan)?;
                let bytes = plan
                    .encode()
                    .map_err(|e| Fail::Internal(format!("plan encoding: {e}")))?;
                let encoded = hex(&bytes);
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
                    ],
                    &format!("{}: planned {} → {}; nothing was written. Approvals bind proposal {}. Commit authority and required approvals are checked separately.\nCanonical period plan bytes (hex):\n{encoded}", plan.period_code, plan.from.name(), plan.to.name(), hex(&digest)),
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
                let plan = book.plan_transition(code, transition, who, reason, date, &key)??;
                let digest = book.plan_digest(&plan)?;
                let bytes = plan
                    .encode()
                    .map_err(|e| Fail::Internal(format!("plan encoding: {e}")))?;
                let target = ctx.files.resolve(path);
                std::fs::write(&target, bytes).map_err(|e| BookError::Io(target.clone(), e))?;
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
                    let digest = book.plan_digest(&plan)?;
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
                None => {
                    book.transition_period(code, transition, who, reason, date, &key, &capability)??
                }
            };
            out.at_book(&book)?;
            out.effective(format!("period:{}", tr.period));
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

/// `fa approve --proposal <digest>` (R4): record an Approval binding a
/// planned proposal's digest under the caller's capability (embedded
/// posture: `--as` names the principal; `approve` is implied and `--grant`
/// adds ops, as for `post`). A second approver is a second invocation as a
/// second principal; the commit cites each approval's vid.
fn approve_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let text = args.flag("--proposal").ok_or_else(|| {
        usage(
            "approve needs --proposal <digest>",
            "fa approve --proposal <proposal_digest> (64 hex, printed by `fa period <t> <code> --plan-out <file>`)",
        )
    })?;
    let digest = parse_digest(text, "--proposal")?;
    let capability = ctx.capability(args, &["approve"])?;
    let mut book = ctx.books.open(args)?;
    let approved = book.approve(capability, digest)??;
    ctx.out.at_book(&book)?;
    let approval = approved.approval();
    let recorded_at = approved.recorded_at();
    let (epoch, already) = match approved {
        fa_journal::Approved::Recorded {
            security_policy_epoch,
            ..
        } => (Json::Int(i128::from(security_policy_epoch)), false),
        fa_journal::Approved::AlreadyRecorded { .. } => (Json::Null, true),
    };
    ctx.out.event(
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

/// A 64-hex digest from a flag.
fn parse_digest(text: &str, what: &str) -> Result<[u8; 32], Fail> {
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
fn parse_vid(text: &str, what: &str) -> Result<VId, Fail> {
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
        let Some((target, _)) = book.read_entry(vid)? else {
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
        let mut leg = LegPayload::simple(side, account_vid(ctx.book_id, account), amount);
        leg.settles = parse_settles(l, &what, ctx, book)?;
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
fn reverse_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
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
    post_document(ctx, args, Some(EntryClass::REVERSAL), obj(fields))
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
    let suggestion = supplied
        .and_then(|name| nearest(name, &names))
        .map(|name| format!("did you mean `{name}`? "))
        .unwrap_or_default();
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
    .into())
}

fn lineage_json(link: &fa_model::Supersession, reasons: &ReasonCodes) -> Json {
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

fn check_post_planning_options(args: &Args) -> Result<(), Fail> {
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

/// Timing is request data. The posting kernel resolves its committed tick
/// anchor and schedule law; the CLI never reads a clock or creates an effect.
fn post_timing(
    args: &Args,
    doc: &Json,
    class: EntryClass,
) -> Result<(Option<u64>, Option<DateDay>), Fail> {
    let Json::Obj(fields) = doc else {
        return Err(usage("intent must be an object", "fa robot-docs examples"));
    };
    const FIELDS: &[&str] = &[
        "class",
        "effective_date",
        "effective_period",
        "idempotency_key",
        "description",
        "legs",
        "evidence",
        "reverses",
        "reason",
        "resolves",
        "disposition",
        "timeout_ns",
        "reverse_on",
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
    Ok((timeout_ns, reverse_on))
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
    let ctx = book.context().clone();
    let class_name = match doc.get("class") {
        None => match forced {
            Some(EntryClass::PENDING) => "Pending",
            Some(EntryClass::RESOLUTION) => "Resolution",
            Some(EntryClass::REVERSAL) => "Reversal",
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
    let (timeout_ns, reverse_on) = post_timing(args, doc, class)?;
    let typed_reversal = forced == Some(EntryClass::REVERSAL);
    let supplied_date = if typed_reversal && doc.get("effective_date").is_none() {
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
    // A Reversal names its target; its legs are the exact side-swap of the
    // target's, derived here so an agent never has to retype amounts. A
    // Resolution names the hold it resolves and either posts a sub-vector
    // drawn leg by leg from it or voids it (plan §5.4).
    let mut supersession = Vec::new();
    let mut pending = None;
    let mut control = None;
    let mut reversal_detail = None;
    let legs: Vec<LegPayload> = if let Some(target_s) = doc.get("reverses").and_then(Json::as_str) {
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
        let Some((target, _)) = book.read_entry(vid)? else {
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
        reversal_detail = reason.map(|reason| (format!("{:032x}", vid.0), reason));
        if doc.get("legs").is_some() {
            return Err(usage(
                "a Reversal's legs are derived from the target; do not supply `legs`",
                "remove `legs`; a different correction is a Replacement",
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
        let Some((hold, _)) = book.read_entry(vid)? else {
            return Err(usage(
                format!("resolves: no entry {target_s} in this book"),
                "fa entry show <vid> to check the identity",
            ));
        };
        let resolution_of = Some(hold.entry_ref(vid));
        let disposition =
            doc.get("disposition")
                .and_then(Json::as_str)
                .unwrap_or(if doc.get("legs").is_some() {
                    "posts"
                } else {
                    "voids"
                });
        match disposition {
            "voids" | "void" | "release" => {
                if doc.get("legs").is_some() {
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
                for (i, (leg, explicit)) in parse_legs(doc, &ctx, book)?.into_iter().enumerate() {
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
    } else {
        if class == EntryClass::PENDING {
            pending = Some(Pending {
                timeout_ns,
                resolution_of: None,
                disposition: None,
            });
        }
        let parsed = parse_legs(doc, &ctx, book)?;
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
            "a reversal needs its target's effective date",
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
    let proposal = EntryPayload {
        schema_minor: 0,
        book_id: ctx.book_id,
        branch_id: Id128::TRUNK,
        class,
        effective_date,
        document_date: None,
        description: book.seal_text(description)?,
        effective_period,
        legs,
        control,
        unit_totals,
        base_totals: None,
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
    let proposal = match reverse_on {
        Some(day) => fa_journal::with_auto_reverse(proposal, day),
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

fn post_document(
    ctx: &mut Ctx<'_>,
    args: &Args,
    forced: Option<EntryClass>,
    doc: Json,
) -> Result<(), Fail> {
    check_post_planning_options(args)?;
    let who = ctx.principal(args);
    let capability = ctx.capability(args, &["post"])?;
    let out = &ctx.out;
    let mut book = ctx.books.open(args)?;
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
        return emit_post_plan(out, &book, &ctx.files, args, &plan);
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
fn read_post_plan(files: &Files, path: &str) -> Result<PostPlan, Fail> {
    let bytes = read_plan_bytes(files, path, b"FA-POST-PLAN\0", "PostEntry")?;
    PostPlan::decode(&bytes).map_err(|e| {
        usage(
            format!("{path} is not a canonical PostEntry plan: {e}"),
            "use the complete binary plan file or bytes hex string from a successful --dry-run",
        )
    })
}

/// Both plan transports accept their existing canonical binary form and
/// its complete hex encoding. Bound allocation before either codec runs.
fn read_plan_bytes(files: &Files, path: &str, domain: &[u8], kind: &str) -> Result<Vec<u8>, Fail> {
    let limit = MAX_PLAN_BYTES * 2 + 2; // hex, optionally followed by CRLF
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
        if bytes.len() > MAX_PLAN_BYTES {
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
    if text.len() / 2 > MAX_PLAN_BYTES {
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

fn write_post_plan(files: &Files, path: &str, bytes: &[u8]) -> Result<(), Fail> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(files.resolve(path)).map_err(|e| {
        usage(
            format!("cannot create plan file {path}: {e}"),
            "choose a new --plan-out path; an existing file is never overwritten",
        )
    })?;
    file.write_all(bytes).and_then(|()| file.sync_all()).map_err(|e| {
        Fail::Environment(format!(
            "could not finish plan file {path}: {e}; nothing was posted; preserve the partial file and retry with a new output path"
        ))
    })
}

fn emit_post_plan(
    out: &Out,
    book: &Book,
    files: &Files,
    args: &Args,
    plan: &PostPlan,
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
        command.push_str(" --json");
        command
    };
    let commit_guidance = if bound_void {
        "MCP cannot commit this void plan. Ask the operator to separately prepare, review and confirm the release.".to_string()
    } else {
        command.clone()
    };
    let next_actions = if bound_void {
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
    if bound_void {
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
            ("approvals", Json::Int(plan.approvals().len() as i128)),
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
    let plan = read_post_plan(&ctx.files, path)?;
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
    let capability = ctx.capability(args, &["post"])?;
    let mut book = ctx.books.open(args)?;
    let (entry_ref, recorded_at, period, already_recorded) =
        match book.commit_plan(plan, &capability)?? {
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

fn emit_posted(
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
fn known_at_flag(
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

fn selected_periods(args: &Args, book: &Book) -> Result<Vec<String>, Fail> {
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

fn tb_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let mut book = ctx.books.open(args)?;
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
    let (known_at, requested_utc_ns) = known_at_flag(args, &book, out)?;
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
    let (tb, certificate) = if args.switch("--certify") || args.flag("--certificate-out").is_some()
    {
        let certified = match requested_utc_ns {
            Some(instant) => {
                book.certify_trial_balance_at_instant(selection.clone(), instant)??
            }
            None => book.certify_trial_balance(selection.clone(), known_at)??,
        };
        out.time_selection(certified.certificate.time_selection.as_ref());
        (certified.report, Some(certified.certificate))
    } else {
        let report = match &selection {
            TrialBalanceSelection::AsOf(day) => book.balance_as_of(*day, known_at)?,
            TrialBalanceSelection::Periods(periods) => book.trial_balance_at(periods, known_at)?,
            TrialBalanceSelection::Activity(periods) => book.period_activity(periods, known_at)?,
        };
        (report, None)
    };
    validate_trial_balance_units(&tb, &book.context().units)?;
    let retained = certificate
        .as_ref()
        .map(|certificate| {
            notary::retain_report_certificate(&mut book, &ctx.files, args, certificate)
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    render_trial_balance(out, &book, &tb, &selection, digest.as_deref())?;
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        notary::emit_report_certificate(out, args, certificate, &bytes, &retained);
    }
    Ok(())
}

fn statement_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "statement needs exactly one registered definition name",
            "fa statement balance-sheet|income-statement --for <period> [--compare <period>] --json",
        ));
    }
    for flag in ["--for", "--compare", "--certificate-out"] {
        if args.flag_all(flag).len() > 1 {
            return Err(usage(
                format!("{flag} may be supplied only once"),
                "fa statement balance-sheet --for FY2026-P03 --compare FY2026-P02 --json",
            ));
        }
    }
    let period = args.require("--for", "<period>, for example FY2026-P03")?;
    if period.is_empty() || args.flag("--compare").is_some_and(str::is_empty) {
        return Err(usage(
            "statement period codes must not be empty",
            "--for FY2026-P03 [--compare FY2026-P02]",
        ));
    }
    let definition = StatementDefinition::embedded(&args.positional[1]).map_err(|error| {
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
    let mut book = ctx.books.open(args)?;
    let (known_at, requested_utc_ns) = known_at_flag(args, &book, &ctx.out)?;
    let (statement, certificate) =
        if args.switch("--certify") || args.flag("--certificate-out").is_some() {
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
    let rendered = statement_presentation(&statement, &book.context().units)?;
    let retained = certificate
        .as_ref()
        .map(|certificate| {
            notary::retain_report_certificate(&mut book, &ctx.files, args, certificate)
        })
        .transpose()?;
    let digest = certificate
        .as_ref()
        .map(|certificate| hex(&certificate.digest));
    emit_statement(&ctx.out, &statement, rendered, digest.as_deref());
    if let (Some(certificate), Some((bytes, retained))) = (certificate.as_ref(), retained) {
        notary::emit_report_certificate(&ctx.out, args, certificate, &bytes, &retained);
    }
    Ok(())
}

type StatementPresentation = (Vec<(&'static str, Json)>, String);

fn statement_presentation(
    statement: &Statement,
    units: &fa_money::UnitRegistry,
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
    human.push_str(
        "Scope: one book, exact native units; no FX conversion or presentation rounding.\n",
    );
    Ok((
        vec![
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
            ("scope", s("single-book-native-units")),
        ],
        human,
    ))
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

/// The same renderer serves both an original report and its verified replay.
/// Its coordinate comes from the certified selector, never the present head.
pub(crate) fn render_trial_balance(
    out: &Out,
    book: &Book,
    tb: &fa_registers::TrialBalance,
    selection: &TrialBalanceSelection,
    certificate: Option<&str>,
) -> Result<(), Fail> {
    render_trial_balance_with_units(out, &book.context().units, tb, selection, certificate)
}

fn render_trial_balance_with_units(
    out: &Out,
    units: &fa_money::UnitRegistry,
    tb: &fa_registers::TrialBalance,
    selection: &TrialBalanceSelection,
    certificate: Option<&str>,
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
                ("net", s(render(r.unit_id, r.debits - r.credits)?)),
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

fn verify_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    match args.positional.get(1).map(String::as_str) {
        Some("accumulator") => notary::verify_accumulator(ctx, args),
        Some("registers") => {
            let book = ctx.books.open(args)?;
            let periods = selected_periods(args, &book)?;
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
                        "retain this finding with fa verify projections --json and the same --book; projection recovery is not implemented".into(),
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
                    cite: None,
                    fix: None,
                })
            }
        }
        other => Err(unhandled("verify", other)),
    }
}

fn open_items_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let mut book = ctx.books.open(args)?;
    if args.positional.len() != 1 {
        return Err(usage(
            "unexpected open-items argument",
            "fa open-items [--account <code>] [--as-known-at HEAD|<seq>|<RFC3339>] --book <dir>",
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
    let (report, certificate) =
        if args.switch("--certify") || args.flag("--certificate-out").is_some() {
            let selection = ReportSelection::OpenItems { account };
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
            (book.open_items_report(account, known_at)?, None)
        };
    validate_open_items_report(&report, &book.context().units)?;
    let retained = certificate
        .as_ref()
        .map(|certificate| {
            notary::retain_report_certificate(&mut book, &ctx.files, args, certificate)
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
// explain
// ---------------------------------------------------------------------------

fn side_name(side: Side) -> &'static str {
    if side == Side::Debit {
        "debit"
    } else {
        "credit"
    }
}

/// `fa explain balance <account> --period <code> [--as-known-at HEAD|<seq>]`.
fn explain_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    let sub = args.positional.get(1).map(String::as_str);
    if sub != Some("balance") {
        return Err(unhandled("explain", sub));
    }
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
    let mut book = ctx.books.open(args)?;
    let (known_at, requested_utc_ns) = known_at_flag(args, &book, out)?;
    let account = account_vid(book.context().book_id, code);
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
        .map(|certificate| {
            notary::retain_report_certificate(&mut book, &ctx.files, args, certificate)
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
                    "account `{code}` is a summary account: registers hold leaf cells, and a summary roll-up is not available yet"
                ),
                "explain one of its leaf accounts (fa chart list --book <dir>)",
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

fn registers_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let out = &ctx.out;
    match args.positional.get(1).map(String::as_str) {
        Some("advance") => {
            let mut book = ctx.books.open(args)?;
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
            let mut book = ctx.books.open(args)?;
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
            let book = ctx.books.open(args)?;
            let units = &book.context().units;
            match book.read_entry(VId(vid))? {
                None => {
                    // Every field is always present; absence is spelled null.
                    let mut fields = vec![("found", Json::Bool(false)), ("vid", s(vid_s))];
                    for absent in [
                        "class",
                        "effective_date",
                        "recorded_at",
                        "entry_digest",
                        "proposal_digest",
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
                    let legs: Vec<Json> = entry
                        .proposal
                        .legs
                        .iter()
                        .map(|l| {
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
                            ]))
                        })
                        .collect::<Result<_, Fail>>()?;
                    let fields = vec![
                        ("found", Json::Bool(true)),
                        ("vid", s(vid_s)),
                        ("class", s(entry.proposal.class.name().unwrap_or("?"))),
                        ("effective_date", s(entry.proposal.effective_date.render())),
                        ("recorded_at", Json::Int(i128::from(seq.0))),
                        ("entry_digest", s(hex(&entry.entry_digest))),
                        ("proposal_digest", s(hex(&entry.proposal_digest))),
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

fn procedure_row_json(row: &fa_registry::procedures::Procedure) -> Json {
    obj(vec![
        ("id", s(&row.id)),
        ("version", Json::Int(i128::from(row.version))),
        ("claim", s(row.claim.name())),
        ("evidence", s(&row.evidence)),
        ("tie_break", s(tie_break_name(&row.tie_break))),
        ("complexity", s(&row.complexity)),
        ("calibration", s(calibration_name(&row.calibration))),
        ("summary", s(&row.summary)),
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
    };
    for (key, value) in set {
        if let Some(slot) = fields.iter_mut().find(|(name, _)| *name == key) {
            slot.1 = value;
        }
    }
    fields.push(("kind", s(kind)));
    obj(fields)
}

fn finding_json(f: &fa_lantern::Finding) -> Json {
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
            // Human mode lists one procedure per line; robot mode carries the
            // same rows in the event alone (stdout is one JSON object a line).
            for row in rows.iter().filter(|_| !out.json) {
                out.line(format!(
                    "{} v{} {} {}",
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
                        Json::Arr(rows.iter().map(procedure_row_json).collect()),
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
            for flag in ["--effective-through", "--account", "--source"] {
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
            let book = ctx.books.open(args)?;
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
            let built = fa_lantern::catalog::build(id, params, inputs).map_err(lantern_usage)?;
            let run = book.run_procedure(built.as_ref(), known_at, effective_through)?;
            out.known_at(run.coordinate.known_at);
            for f in &run.findings {
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

#[cfg(test)]
mod tests {
    use super::*;

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
                known_at: CommitSeq(10),
                effective: "all".into(),
            });
            let result =
                render_trial_balance_with_units(&out, &units, &tb, &selection, Some(&certificate));
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
