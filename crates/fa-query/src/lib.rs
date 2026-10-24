//! The FrankenAccounting GQL profile (plan §15.5, bead fa-5c1): a rewriter
//! onto the substrate's native reads, never an engine extension. Pure: no
//! storage, no clock, no authority. The caller admits the capability before
//! anything is read and resolves the selectors against the book.
//!
//! A profile statement is native GQL plus the namespaced selectors. This
//! slice compiles:
//! - `AS KNOWN AT <seq>|HEAD|'<RFC3339>'` and `AS CURRENTLY STATED` into
//!   the statement's one `FOR SYSTEM_TIME AS OF SEQ` clause, with the
//!   resolved sequence written as a literal;
//! - the restatement views (plan §7.4) `AS ORIGINALLY REPORTED`, `AS ISSUED
//!   TO '<audience>'` and `AS REPORTED IN 'C:<certificate>'`, which need
//!   `FOR PERIOD`: the caller resolves the sequence that period was reported
//!   at, as `fa tb --as-originally-reported` does, and reads there;
//! - `FOR PERIOD <code>` into the entry's `IN_PERIOD` edge: the period the
//!   posting resolved, so an entry of a special period is never claimed by
//!   the normal period that shares its day;
//! - `EFFECTIVE BETWEEN <date> AND <date>` into the leg's effective day;
//! - `AT BRANCH trunk`, or `AT BRANCH 'scenario:<name>'` / `'draft:<name>'`: the scenario's
//!   materialization (its trunk prefix replayed at the fork plus its
//!   intents), read at its own head and uncertified;
//! - `CALL fa.trial_balance`, `CALL fa.explain_balance('<account>')` and
//!   `CALL fa.open_items(['<account>'])`, which are the registered reads
//!   themselves (`fa tb`, `fa explain balance`, `fa open-items`) at the
//!   statement's period and known-at;
//! - `EXPLAIN (CERTIFICATE)` leading the statement: the caller certifies the
//!   result, as `fa query --certify` does.
//!
//! Every other selector, parameters and writes are refused with the
//! admissible form, never ignored. So is a statement that
//! breaks the amount law ([`law`]).

#![forbid(unsafe_code)]

mod aggregate;
mod law;
mod lex;

pub use aggregate::{Aggregation, Column, Function, Value};

use fa_time::DateDay;

use lex::{Kind, Lexed};

/// Which law a refusal applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Law {
    /// A clause outside the profile, a malformed selector or a construct this
    /// build does not compile.
    Profile,
    /// An amount aggregated, compared or ordered across units, or compared
    /// with a literal.
    Amount,
}

/// Why a statement was refused, where (a byte offset in the caller's text)
/// and what to write instead.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub law: Law,
    pub at: usize,
    pub message: String,
    pub fix: String,
}

impl Refusal {
    pub(crate) fn new(law: Law, at: usize, message: &str, fix: &str) -> Self {
        Self {
            law,
            at,
            message: message.to_string(),
            fix: fix.to_string(),
        }
    }
}

/// The recorded coordinate a statement selects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KnownAt {
    /// Omitted, `AS KNOWN AT HEAD` or `AS CURRENTLY STATED`: the frontier
    /// when the statement runs. The caller resolves it to a sequence before
    /// any read and reports that sequence.
    Head,
    Seq(u64),
    /// An RFC3339 instant, resolved through retained TimeEvidence (plan
    /// §7.1a), never a wall clock.
    Instant(String),
    /// A restatement view of the statement's `FOR PERIOD`: the caller
    /// resolves the sequence that period was reported at before any read.
    Reported(Reported),
}

/// A restatement view (plan §7.4): which report of a period fixes the
/// statement's known-at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reported {
    /// `AS ORIGINALLY REPORTED`: the period's first statement issuance,
    /// else its first Lock.
    Originally,
    /// `AS ISSUED TO '<audience>'`: the period's first issuance to that
    /// registered audience, as written.
    IssuedTo(String),
    /// `AS REPORTED IN 'C:<certificate>'`: the known-at of that retained
    /// statement certificate, as written.
    In(String),
}

/// A statement the profile compiled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profiled {
    pub known_at: KnownAt,
    /// `FOR PERIOD`: a period code the caller confirms exists at the
    /// selected sequence.
    pub period: Option<String>,
    pub selection: Selection,
    /// `EXPLAIN (CERTIFICATE)`: the caller certifies the result and retains
    /// its certificate, exactly as for `fa query --certify`.
    pub certify: bool,
    /// `AT BRANCH 'scenario:<name>'` or `'draft:<name>'`: the branch selector
    /// of trunk.
    pub branch: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selection {
    /// A native read over the book's graph.
    Native(Native),
    /// `CALL fa.trial_balance`: the registered trial balance at the
    /// statement's period and known-at.
    TrialBalance,
    /// `CALL fa.explain_balance('<account>')`: the account's balance in the
    /// statement's period, explained as `fa explain balance` does.
    ExplainBalance { account: String },
    /// `CALL fa.open_items(['<account>'])`: the open items at the
    /// statement's known-at, as `fa open-items` reads them.
    OpenItems { account: Option<String> },
}

/// A native read with its selectors compiled in, waiting only for the
/// resolved sequence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Native {
    head: String,
    tail: String,
    aggregation: Option<Aggregation>,
}

impl Native {
    /// The native statement at `known_at`.
    #[must_use]
    pub fn statement(&self, known_at: u64) -> String {
        format!(
            "{} FOR SYSTEM_TIME AS OF SEQ {known_at} {}",
            self.head.trim(),
            self.tail.trim()
        )
    }

    /// The statement aggregates an amount: its native read returns the group
    /// keys and raw arguments, and the caller computes the result exactly
    /// under this plan ([`aggregate`]).
    #[must_use]
    pub fn aggregation(&self) -> Option<&Aggregation> {
        self.aggregation.as_ref()
    }
}

/// The profile procedures this build runs.
pub const PROCEDURES: &[&str] = &["fa.trial_balance", "fa.explain_balance", "fa.open_items"];

const CALL_FIX: &str = "CALL fa.trial_balance FOR PERIOD '<code>' | CALL fa.explain_balance('<account>') FOR PERIOD '<code>' | CALL fa.open_items(['<account>']), each [AS KNOWN AT <seq>]; Lantern procedures: fa procedure run <id>";

/// The longest statement the profile reads (bytes).
pub const MAX_STATEMENT_BYTES: usize = 16 * 1024;

const BRANCH_FIX: &str = "AT BRANCH trunk, AT BRANCH 'scenario:<name>' for a scenario's replay (fa scenario list --json) or AT BRANCH 'draft:<name>' for a draft's rehearsal (fa draft list --json)";

const KNOWN_AT_FIX: &str =
    "select one coordinate: AS KNOWN AT <commit sequence> | HEAD | '<RFC3339 instant>'";

const REPORTED_FIX: &str = "FOR PERIOD 'FY2026-P03' AS ORIGINALLY REPORTED | AS ISSUED TO 'board' | AS REPORTED IN 'C:<64-hex>'";

/// Compile a profile statement.
///
/// # Errors
/// A [`Refusal`] naming the clause, its offset and the admissible form.
pub fn rewrite(text: &str) -> Result<Profiled, Refusal> {
    if text.trim().is_empty() || text.len() > MAX_STATEMENT_BYTES {
        return Err(Refusal::new(
            Law::Profile,
            0,
            &format!("a statement is 1..={MAX_STATEMENT_BYTES} bytes of text"),
            "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs",
        ));
    }
    let lexed = lex::lex(text)?;
    let selectors = selectors(&lexed)?;
    if matches!(selectors.known_at, Some(KnownAt::Reported(_))) && selectors.period.is_none() {
        return Err(Refusal::new(
            Law::Profile,
            0,
            "a restatement view reads one period as it was reported; the statement names no FOR PERIOD",
            REPORTED_FIX,
        ));
    }
    if selectors.branch.is_some() {
        // A scenario or a draft is read as its replay: with its own
        // sequences, at its head, and not certified.
        if !matches!(selectors.known_at, None | Some(KnownAt::Head)) {
            return Err(Refusal::new(
                Law::Profile,
                0,
                "a scenario or draft is read at its replay's head; AS KNOWN AT selects trunk's history",
                "drop AS KNOWN AT, or read trunk without AT BRANCH",
            ));
        }
        if selectors.certify {
            return Err(Refusal::new(
                Law::Profile,
                0,
                "a scenario or draft read is not certified",
                "drop EXPLAIN (CERTIFICATE); a scenario's change against trunk certifies with fa scenario diff --certify, a draft's with fa close dry-run --certify",
            ));
        }
    }
    let mut rest = text.to_string();
    for span in &selectors.spans {
        rest.replace_range(span.0..span.1, &" ".repeat(span.1 - span.0));
    }
    let lexed = lex::lex(&rest)?;
    if lexed.tokens.is_empty() {
        return Err(Refusal::new(
            Law::Profile,
            0,
            "the statement holds only selectors",
            "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs AS KNOWN AT HEAD",
        ));
    }
    reserved(&lexed)?;
    let selection = if lexed.word(0, "CALL") {
        call(&lexed, &selectors)?
    } else {
        Selection::Native(native(&lexed, &selectors)?)
    };
    Ok(Profiled {
        known_at: selectors.known_at.unwrap_or(KnownAt::Head),
        period: selectors.period,
        selection,
        certify: selectors.certify,
        branch: selectors.branch,
    })
}

#[derive(Default)]
struct Selectors {
    /// Byte spans of the selector clauses, removed before native analysis.
    spans: Vec<(usize, usize)>,
    known_at: Option<KnownAt>,
    period: Option<String>,
    effective: Option<(DateDay, DateDay)>,
    certify: bool,
    branched: bool,
    branch: Option<String>,
}

fn selectors(lexed: &Lexed<'_>) -> Result<Selectors, Refusal> {
    let mut found = Selectors::default();
    let at = |i: usize| lexed.tokens.get(i).map_or(lexed.text.len(), |t| t.start);
    let mut i = 0;
    while i < lexed.tokens.len() {
        if !lexed.root(i) {
            i += 1;
            continue;
        }
        let start = at(i);
        // A selector word in a property, label or alias position is a name.
        if i > 0 && (lexed.punct(i - 1, '.') || lexed.punct(i - 1, ':') || lexed.word(i - 1, "AS"))
        {
            i += 1;
            continue;
        }
        if lexed.word(i, "EXPLAIN") {
            if i == 0 && lexed.punct(1, '(') && lexed.word(2, "CERTIFICATE") && lexed.punct(3, ')')
            {
                found.spans.push((start, lexed.tokens[3].end));
                found.certify = true;
                i = 4;
                continue;
            }
            return Err(Refusal::new(
                Law::Profile,
                start,
                "EXPLAIN takes (CERTIFICATE) and leads the statement; it certifies the result",
                "EXPLAIN (CERTIFICATE) MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs AS KNOWN AT 12",
            ));
        }
        let (end, known_at) = if lexed.word(i, "AS")
            && lexed.word(i + 1, "KNOWN")
            && lexed.word(i + 2, "AT")
        {
            let j = i + 3;
            let selected = match lexed.kind(j) {
                Some(Kind::Digits) => KnownAt::Seq(lexed.str(j).parse().map_err(|_| {
                    Refusal::new(
                        Law::Profile,
                        at(j),
                        "the commit sequence exceeds u64",
                        KNOWN_AT_FIX,
                    )
                })?),
                Some(Kind::Word) if lexed.word(j, "HEAD") => KnownAt::Head,
                Some(Kind::Quoted) => KnownAt::Instant(lexed.unquoted(j)),
                _ => {
                    return Err(Refusal::new(
                        Law::Profile,
                        at(j),
                        "AS KNOWN AT takes a commit sequence, HEAD or a quoted RFC3339 instant",
                        KNOWN_AT_FIX,
                    ));
                }
            };
            (j + 1, Some(selected))
        } else if lexed.word(i, "AS")
            && lexed.word(i + 1, "CURRENTLY")
            && lexed.word(i + 2, "STATED")
        {
            (i + 3, Some(KnownAt::Head))
        } else if lexed.word(i, "AS")
            && lexed.word(i + 1, "ORIGINALLY")
            && lexed.word(i + 2, "REPORTED")
        {
            (i + 3, Some(KnownAt::Reported(Reported::Originally)))
        } else if lexed.word(i, "AS")
            && (lexed.word(i + 1, "ISSUED") && lexed.word(i + 2, "TO")
                || lexed.word(i + 1, "REPORTED") && lexed.word(i + 2, "IN"))
        {
            let j = i + 3;
            if lexed.kind(j) != Some(Kind::Quoted) {
                return Err(Refusal::new(
                    Law::Profile,
                    at(j),
                    "AS ISSUED TO takes a quoted audience and AS REPORTED IN a quoted statement certificate",
                    REPORTED_FIX,
                ));
            }
            let named = lexed.unquoted(j);
            let view = if lexed.word(i + 1, "ISSUED") {
                Reported::IssuedTo(named)
            } else {
                Reported::In(named)
            };
            (j + 1, Some(KnownAt::Reported(view)))
        } else {
            (i, None)
        };
        if let Some(selected) = known_at {
            if found.known_at.is_some() {
                return Err(Refusal::new(
                    Law::Profile,
                    start,
                    "a statement has one known-at selector",
                    KNOWN_AT_FIX,
                ));
            }
            found.known_at = Some(selected);
            found.spans.push((start, lexed.tokens[end - 1].end));
            i = end;
            continue;
        }
        if lexed.word(i, "FOR") && lexed.word(i + 1, "PERIOD") {
            let (code, end) = literal_run(lexed, i + 2).ok_or_else(|| {
                Refusal::new(
                    Law::Profile,
                    at(i + 2),
                    "FOR PERIOD takes one period code",
                    "FOR PERIOD 'FY2026-P03' (fa period list --json names every code)",
                )
            })?;
            if !code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            {
                return Err(Refusal::new(
                    Law::Profile,
                    at(i + 2),
                    &format!("`{code}` is not a period code"),
                    "FOR PERIOD 'FY2026-P03' (fa period list --json names every code)",
                ));
            }
            if lexed.punct(end, '.') && lexed.punct(end + 1, '.') {
                return Err(Refusal::new(
                    Law::Profile,
                    at(end),
                    "a period range is not compiled in this build",
                    "select one period: FOR PERIOD 'FY2026-P03'",
                ));
            }
            if found.period.replace(code).is_some() {
                return Err(Refusal::new(
                    Law::Profile,
                    start,
                    "a statement has one FOR PERIOD",
                    "FOR PERIOD 'FY2026-P03'",
                ));
            }
            found.spans.push((start, lexed.tokens[end - 1].end));
            i = end;
            continue;
        }
        if lexed.word(i, "EFFECTIVE") {
            const FIX: &str =
                "EFFECTIVE BETWEEN '2026-01-01' AND '2026-03-31' (both days included)";
            if !lexed.word(i + 1, "BETWEEN") {
                return Err(Refusal::new(
                    Law::Profile,
                    start,
                    "only EFFECTIVE BETWEEN is compiled in this build: a relationship's valid time (EFFECTIVE AT) is not",
                    FIX,
                ));
            }
            let day = |j: usize| {
                literal_run(lexed, j)
                    .and_then(|(text, end)| DateDay::parse(&text).ok().map(|day| (day, end)))
            };
            let bad = |j: usize| {
                Refusal::new(
                    Law::Profile,
                    at(j),
                    "EFFECTIVE BETWEEN takes two civil dates",
                    FIX,
                )
            };
            let (from, and) = day(i + 2).ok_or_else(|| bad(i + 2))?;
            if !lexed.word(and, "AND") {
                return Err(bad(and));
            }
            let (through, end) = day(and + 1).ok_or_else(|| bad(and + 1))?;
            if through < from {
                return Err(Refusal::new(
                    Law::Profile,
                    at(and + 1),
                    "EFFECTIVE BETWEEN ends before it starts",
                    FIX,
                ));
            }
            if found.effective.replace((from, through)).is_some() {
                return Err(Refusal::new(
                    Law::Profile,
                    start,
                    "a statement has one EFFECTIVE selector",
                    FIX,
                ));
            }
            found.spans.push((start, lexed.tokens[end - 1].end));
            i = end;
            continue;
        }
        if lexed.word(i, "AT") && lexed.word(i + 1, "BRANCH") {
            let name = match lexed.kind(i + 2) {
                Some(Kind::Quoted) => lexed.unquoted(i + 2),
                Some(Kind::Word) => lexed.str(i + 2).to_string(),
                _ => String::new(),
            };
            if found.branched {
                return Err(Refusal::new(
                    Law::Profile,
                    start,
                    "a statement has one AT BRANCH",
                    BRANCH_FIX,
                ));
            }
            let named = |prefix: &str| {
                name.strip_prefix(prefix)
                    .is_some_and(|rest| !rest.is_empty())
            };
            if name != "trunk" {
                if lexed.kind(i + 2) != Some(Kind::Quoted)
                    || !(named("scenario:") || named("draft:"))
                {
                    return Err(Refusal::new(
                        Law::Profile,
                        at(i + 2),
                        "a query reads trunk, one scenario or one draft",
                        BRANCH_FIX,
                    ));
                }
                found.branch = Some(name);
            }
            found.branched = true;
            found.spans.push((start, lexed.tokens[i + 2].end));
            i += 3;
            continue;
        }
        i += 1;
    }
    Ok(found)
}

/// `text[from..to]` with each blanked selector span, and the whitespace
/// around it, collapsed to one space: the statement as written, without its
/// selectors. Spans begin and end at token boundaries, outside any literal.
fn squeezed(text: &str, from: usize, to: usize, spans: &[(usize, usize)]) -> String {
    let mut inside: Vec<(usize, usize)> = spans
        .iter()
        .copied()
        .filter(|&(start, end)| end > from && start < to)
        .collect();
    inside.sort_unstable();
    let mut out = String::new();
    let mut at = from;
    for (start, end) in inside {
        let start = start.max(at);
        out.push_str(&text[at..start]);
        out.truncate(out.trim_end().len());
        out.push(' ');
        at = end.min(to);
        while let Some(ch) = text[at..to].chars().next().filter(|ch| ch.is_whitespace()) {
            at += ch.len_utf8();
        }
    }
    out.push_str(&text[at..to]);
    out
}

/// A quoted literal, or an unquoted run of adjacent words, digits, `-` and
/// `_` (`FY2026-P03`, `2026-03-31`), and the token after it.
fn literal_run(lexed: &Lexed<'_>, i: usize) -> Option<(String, usize)> {
    match lexed.kind(i)? {
        Kind::Quoted => Some((lexed.unquoted(i), i + 1)),
        Kind::Word | Kind::Digits => {
            let mut end = i + 1;
            while lexed.adjacent(end - 1, end)
                && (matches!(lexed.kind(end), Some(Kind::Word | Kind::Digits))
                    || lexed.punct(end, '-')
                    || lexed.punct(end, '_'))
            {
                end += 1;
            }
            let start = lexed.tokens[i].start;
            let stop = lexed.tokens[end - 1].end;
            Some((lexed.text[start..stop].to_string(), end))
        }
        _ => None,
    }
}

const WRITES: &[&str] = &[
    "CREATE", "INSERT", "SET", "DELETE", "DETACH", "MERGE", "REMOVE", "DROP",
];

/// Constructs the profile refuses wherever they appear.
fn reserved(lexed: &Lexed<'_>) -> Result<(), Refusal> {
    for (i, token) in lexed.tokens.iter().enumerate() {
        let text = lexed.str(i);
        let at = token.start;
        match token.kind {
            Kind::Param => {
                return Err(Refusal::new(
                    Law::Profile,
                    at,
                    &format!("`{text}`: fa query binds no parameters in this build"),
                    "write the value as a literal: a quoted text or an integer",
                ));
            }
            Kind::Float => {
                return Err(Refusal::new(
                    Law::Amount,
                    at,
                    &format!(
                        "`{text}` is a float literal; no amount path admits a float (doctrine 4)"
                    ),
                    "amounts compare only with amounts of the same unit; filter by account, unit, period or date, and aggregate per unit",
                ));
            }
            Kind::Word if text.starts_with("__fa_") => {
                return Err(Refusal::new(
                    Law::Profile,
                    at,
                    &format!("`{text}`: names beginning __fa_ are the profile's own"),
                    "rename the variable",
                ));
            }
            Kind::Word
                if token.depth == 0
                    && !(i > 0 && (lexed.punct(i - 1, '.') || lexed.punct(i - 1, ':')))
                    && WRITES.iter().any(|w| text.eq_ignore_ascii_case(w)) =>
            {
                return Err(Refusal::new(
                    Law::Profile,
                    at,
                    &format!(
                        "`{text}`: fa query is read-only; the journal changes only through its intents"
                    ),
                    "post with fa post --intent <file>; correct with fa reverse | fa reclass | a restatement case",
                ));
            }
            Kind::Word
                if token.depth == 0
                    && text.eq_ignore_ascii_case("FOR")
                    && lexed.word(i + 1, "SYSTEM_TIME") =>
            {
                return Err(Refusal::new(
                    Law::Profile,
                    at,
                    "the profile owns the statement's recorded coordinate",
                    "select it with AS KNOWN AT <commit sequence> | HEAD | '<RFC3339 instant>'",
                ));
            }
            Kind::Word
                if (text == "Register" || text == "RegisterState")
                    && i > 0
                    && (lexed.punct(i - 1, ':')
                        || lexed.punct(i - 1, '|')
                        || lexed.punct(i - 1, '&')) =>
            {
                return Err(Refusal::new(
                    Law::Profile,
                    at,
                    &format!(
                        "`{text}` is a register cache, never more authoritative than the journal (FA-INV-04)"
                    ),
                    "query the legs, or read the fold: CALL fa.trial_balance FOR PERIOD '<code>' | fa explain balance <account>",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn call(lexed: &Lexed<'_>, selectors: &Selectors) -> Result<Selection, Refusal> {
    let named = lexed.word(1, "fa") && lexed.punct(2, '.') && lexed.kind(3) == Some(Kind::Word);
    let procedure = if named {
        format!("fa.{}", lexed.str(3))
    } else {
        String::new()
    };
    let at = |i: usize| lexed.tokens.get(i).map_or(lexed.text.len(), |t| t.start);
    if !named || !PROCEDURES.contains(&procedure.as_str()) {
        return Err(Refusal::new(
            Law::Profile,
            at(1),
            &format!(
                "`CALL {}` is not a profile procedure in this build",
                if named {
                    procedure.as_str()
                } else {
                    lexed.str(1)
                }
            ),
            CALL_FIX,
        ));
    }
    // `()` or `('<account code>')`, then nothing.
    let mut end = 4;
    let mut account = None;
    if lexed.punct(end, '(') {
        if lexed.punct(end + 1, ')') {
            end += 2;
        } else if lexed.kind(end + 1) == Some(Kind::Quoted) && lexed.punct(end + 2, ')') {
            account = Some(lexed.unquoted(end + 1));
            end += 3;
        }
    }
    let refuse = |at: usize, message: &str| Err(Refusal::new(Law::Profile, at, message, CALL_FIX));
    if end != lexed.tokens.len() {
        return refuse(
            at(end),
            &format!(
                "CALL {procedure} stands alone in this build (at most one quoted account argument; no YIELD or further clauses)"
            ),
        );
    }
    if selectors.effective.is_some() {
        return Err(Refusal::new(
            Law::Profile,
            0,
            &format!("{procedure} is selected by period and known-at, not by EFFECTIVE BETWEEN"),
            "CALL fa.trial_balance FOR PERIOD '<code>'; a civil-date cutoff: fa tb --as-of YYYY-MM-DD or fa open-items --as-of YYYY-MM-DD",
        ));
    }
    match procedure.as_str() {
        "fa.trial_balance" => match account {
            Some(_) => refuse(at(4), "fa.trial_balance takes no argument"),
            None => Ok(Selection::TrialBalance),
        },
        "fa.explain_balance" => match (account, &selectors.period) {
            (None, _) => refuse(
                at(4),
                "fa.explain_balance takes the account code: CALL fa.explain_balance('6000') FOR PERIOD '<code>'",
            ),
            (Some(_), None) => refuse(
                0,
                "fa.explain_balance explains one period's balance; the statement names no FOR PERIOD",
            ),
            (Some(account), Some(_)) => Ok(Selection::ExplainBalance { account }),
        },
        _ => {
            if selectors.period.is_some()
                || matches!(selectors.known_at, Some(KnownAt::Reported(_)))
            {
                return Err(Refusal::new(
                    Law::Profile,
                    0,
                    "fa.open_items reads the open items at a known-at, not for a period or a restatement view",
                    "CALL fa.open_items('<account>') AS KNOWN AT <seq>; a civil-date cutoff: fa open-items --as-of YYYY-MM-DD",
                ));
            }
            Ok(Selection::OpenItems { account })
        }
    }
}

/// The root clause keywords: a native statement's clauses begin with one.
pub(crate) const CLAUSES: &[&str] = &[
    "MATCH", "OPTIONAL", "WHERE", "RETURN", "WITH", "ORDER", "SKIP", "LIMIT", "UNION", "UNWIND",
    "CALL", "YIELD",
];

pub(crate) fn clause_word(lexed: &Lexed<'_>, i: usize) -> bool {
    lexed.root(i) && CLAUSES.iter().any(|c| lexed.word(i, c))
}

fn native(lexed: &Lexed<'_>, selectors: &Selectors) -> Result<Native, Refusal> {
    if !lexed.word(0, "MATCH") {
        return Err(Refusal::new(
            Law::Profile,
            0,
            &format!(
                "`{}`: a query begins with MATCH in this build",
                lexed.str(0)
            ),
            "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs",
        ));
    }
    let tail = (1..lexed.tokens.len())
        .find(|&i| {
            lexed.root(i)
                && ["WHERE", "OPTIONAL", "WITH", "RETURN"]
                    .iter()
                    .any(|w| lexed.word(i, w))
        })
        .ok_or_else(|| {
            Refusal::new(
                Law::Profile,
                lexed.text.len(),
                "the statement returns nothing",
                "end it with RETURN <expressions>",
            )
        })?;
    if let Some(call) = (1..lexed.tokens.len()).find(|&i| lexed.root(i) && lexed.word(i, "CALL")) {
        return Err(Refusal::new(
            Law::Profile,
            lexed.tokens[call].start,
            "CALL stands alone in this build: CALL fa.trial_balance; no procedure runs inside a MATCH pipeline yet",
            "CALL fa.trial_balance FOR PERIOD '<code>'; Lantern procedures: fa procedure run <id>",
        ));
    }
    let spans = &selectors.spans;
    let (cut, returned, aggregation) = if law::check(lexed)? {
        let (cut, returned, plan) = aggregate::plan(lexed, spans)?;
        (cut, returned, Some(plan))
    } else {
        (lexed.text.len(), String::new(), None)
    };
    let tail_at = lexed.tokens[tail].start;
    let mut head = squeezed(lexed.text, 0, tail_at, spans);
    let mut rest = squeezed(lexed.text, tail_at, cut, spans);
    let mut filters = Vec::new();
    if selectors.period.is_some() || selectors.effective.is_some() {
        if (0..lexed.tokens.len()).any(|i| lexed.root(i) && lexed.word(i, "UNION")) {
            return Err(Refusal::new(
                Law::Profile,
                0,
                "FOR PERIOD and EFFECTIVE BETWEEN select one statement, not a UNION",
                "run each part of the union as its own query",
            ));
        }
        let nodes = law::nodes(lexed, 0, tail);
        let legs: Vec<&str> = nodes
            .iter()
            .filter(|n| n.labels.iter().any(|l| l == "Leg"))
            .filter_map(|n| n.var.as_deref())
            .collect();
        let entries: Vec<&str> = nodes
            .iter()
            .filter(|n| n.labels.iter().any(|l| l == "Entry"))
            .filter_map(|n| n.var.as_deref())
            .collect();
        if let Some(code) = &selectors.period {
            match (legs.as_slice(), entries.as_slice()) {
                ([leg], _) => {
                    head.truncate(head.trim_end().len());
                    head.push_str(&format!(
                        ", (__fa_entry:Entry)-[:HAS_LEG]->({leg}), (__fa_entry)-[:IN_PERIOD]->(__fa_period:Period)"
                    ));
                }
                ([], [entry]) => {
                    head.truncate(head.trim_end().len());
                    head.push_str(&format!(", ({entry})-[:IN_PERIOD]->(__fa_period:Period)"));
                }
                _ => {
                    return Err(Refusal::new(
                        Law::Profile,
                        0,
                        "FOR PERIOD selects the period an entry posted to: bind exactly one leg (l:Leg) or, with no leg, one entry (e:Entry) in the first MATCH",
                        "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs FOR PERIOD 'FY2026-P03'",
                    ));
                }
            }
            filters.push(format!("__fa_period.code = '{code}'"));
        }
        if let Some((from, through)) = selectors.effective {
            let [leg] = legs.as_slice() else {
                return Err(Refusal::new(
                    Law::Profile,
                    0,
                    "EFFECTIVE BETWEEN selects legs by effective date: bind exactly one leg (l:Leg) in the first MATCH",
                    "MATCH (l:Leg)-[:POSTS_TO]->(a:Account) RETURN a.code, COUNT(*) AS legs EFFECTIVE BETWEEN '2026-01-01' AND '2026-03-31'",
                ));
            };
            filters.push(format!(
                "{leg}._fa_effective_day >= {} AND {leg}._fa_effective_day <= {}",
                from.0, through.0
            ));
        }
    }
    if !filters.is_empty() {
        let filter = filters.join(" AND ");
        if lexed.word(tail, "WHERE") {
            // The first WHERE's expression runs to the next root clause.
            let end = (tail + 1..lexed.tokens.len())
                .find(|&i| clause_word(lexed, i))
                .map_or(lexed.text.len(), |i| lexed.tokens[i].start)
                .min(cut);
            let expression = squeezed(lexed.text, lexed.tokens[tail].end, end, spans);
            rest = format!(
                "WHERE {filter} AND ({}) {}",
                expression.trim(),
                squeezed(lexed.text, end, cut, spans)
            );
        } else {
            rest = format!("WHERE {filter} {rest}");
        }
    }
    if aggregation.is_some() {
        rest.truncate(rest.trim_end().len());
        rest.push(' ');
        rest.push_str(&returned);
    }
    Ok(Native {
        head,
        tail: rest,
        aggregation,
    })
}

#[cfg(test)]
mod tests;
