//! Report certificates (plan §13.6, FA-INV-11, bead fa-cqk): a certified
//! trial balance, its byte-identical replay, and its status.
//!
//! A [`ReportCertificate`] names its closure: the book, the resolved
//! known-at sequence, the report definition and its canonical parameters,
//! the registry epochs the output depends on (the symbol table and the unit
//! table), and, as `inputs`, one substrate `NativeResultCertificate` per
//! certified read the report rests on. Every input's `snapshot_identity` is
//! the chain commitment at the known-at sequence, which is the plan's
//! "book root". The output is bound by `output_digest` over the trial
//! balance's canonical bytes (fa-registers `canonical`) and by one digest
//! per row, so a replay that disagrees names the first row that moved.
//!
//! [`replay`] re-executes every input with `Database::replay` (the substrate
//! refuses a different history, plan, parameter or result), checks the
//! registry epochs, then recomputes the report with the same definition at
//! the same sequence and compares the digests. [`status`] reports the
//! entries recorded after the known-at that the report's selector would
//! fold, and whether the same report at the head differs.
//!
//! Scope (`replay_scope = "native-inputs+fold"`): the inputs are certified
//! native reads of the vertices the fold reads (entry digests, account
//! code/name/type, period code/bounds/state); the fold itself is
//! FrankenAccounting code named by the report definition and its version,
//! and it reads the same snapshot through `vertices_at` rather than
//! consuming the certified rows (a later slice). The read runs under the
//! embedded owner's authority (`capability = "embedded-owner"`; fa-0x0 adds
//! a capability commitment). A certificate is returned to its caller, not
//! journaled. No-claim boundary: replay proves that the same closure yields
//! the same bytes, not that the closure's entries are economically right.

use std::fmt::Write as _;

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::refusal::{Refusal, exit};
use fa_model::{DecodeError, Id128, Reader, Writer};
use fa_money::{UnitKind, UnitRegistry};
use fa_registers::{RegisterError, TrialBalance};
use fa_time::DateDay;
use fgdb::{Database, NativeResultCertificate, ReplayRefusal};
use fgdb_crypto::Hasher;
use fgdb_gql::{GqlParameters, GqlQueryPolicy};
use fgdb_types::{CommitSeq, QueryCx, VId};

use crate::book::BookError;

/// Refusal codes this module issues (registries/refusal_catalog.toml).
pub mod code {
    /// The certificate text is not a well-formed report certificate.
    pub const CERTIFICATE_MALFORMED: &str = "FA-REF-148";
    /// The certificate was issued by another book.
    pub const CERTIFICATE_OTHER_BOOK: &str = "FA-REF-149";
    /// Replay did not reproduce the certificate: an input, a registry epoch,
    /// the definition or the output differs.
    pub const CERTIFICATE_NOT_REPRODUCED: &str = "FA-REF-150";
}

const FORMAT: &str = "fa:report-certificate";
const FORMAT_VERSION: u16 = 1;
const ID_DOMAIN: &[u8] = b"fa:report-certificate-id:v1";
const UNITS_DOMAIN: &[u8] = b"fa:certificate-units:v1";

/// The version of the trial-balance definitions this build computes. A
/// change to what the fold selects or how it sums bumps it, so an old
/// certificate is refused by name rather than silently recomputed.
pub const DEFINITION_VERSION: u16 = 1;

/// The authority the certified read ran under (fa-0x0 replaces it with a
/// capability commitment).
pub const CAPABILITY: &str = "embedded-owner";

/// What replay covers (see the module docs).
pub const REPLAY_SCOPE: &str = "native-inputs+fold";

/// The certified reads every trial-balance certificate rests on, by name,
/// in order: exactly the vertex kinds and properties the fold reads.
pub const CERTIFIED_READS: [(&str, &str); 3] = [
    (
        "entries",
        "MATCH (e:Entry) FOR SYSTEM_TIME AS OF SEQ $at RETURN e._fa_digest AS digest",
    ),
    (
        "accounts",
        "MATCH (a:Account) FOR SYSTEM_TIME AS OF SEQ $at RETURN a.code AS code,a.name AS name,a.account_type AS kind ORDER BY code",
    ),
    (
        "periods",
        "MATCH (p:Period) FOR SYSTEM_TIME AS OF SEQ $at RETURN p.code AS code,p.period_start AS opens,p.period_end AS closes,p.state AS state ORDER BY code",
    ),
];

/// The certified reads' execution budget. It bounds one read; it is not
/// part of the closure, and replay runs under the same constants.
const BUDGET: GqlQueryPolicy =
    GqlQueryPolicy::new(50_000_000, 50_000_000, 1_000_000_000, 50_000_000);

const MAX_PERIODS: usize = 4_096;
const MAX_TEXT: usize = 1_024;
const MAX_INPUTS: usize = 16;
const MAX_INPUT_BYTES: usize = 1 << 20;
const MAX_ROWS: usize = 1 << 24;

/// Which trial balance a certificate covers (the `fa tb` modes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrialBalanceRequest {
    /// Stock through the latest selected period's inclusive end.
    Stock { periods: Vec<String> },
    /// Stock through an inclusive civil date.
    AsOf { day: DateDay },
    /// Movement in the selected periods.
    Activity { periods: Vec<String> },
}

impl TrialBalanceRequest {
    /// The report definition's id.
    #[must_use]
    pub fn definition(&self) -> &'static str {
        match self {
            Self::Stock { .. } => "fa.tb.stock",
            Self::AsOf { .. } => "fa.tb.as_of",
            Self::Activity { .. } => "fa.tb.activity",
        }
    }

    fn tag(&self) -> u8 {
        match self {
            Self::Stock { .. } => 1,
            Self::AsOf { .. } => 2,
            Self::Activity { .. } => 3,
        }
    }
}

/// One certified substrate read in a certificate's closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedInput {
    /// Which read: a name from [`CERTIFIED_READS`].
    pub name: String,
    pub certificate: NativeResultCertificate,
}

/// A certificate over one trial balance (see the module docs).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportCertificate {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub request: TrialBalanceRequest,
    pub definition_version: u16,
    /// `SymbolTable::digest` of the table the reads resolved names with.
    pub symbols_digest: [u8; 32],
    /// The unit table the output's unit ids mean (see [`units_digest`]).
    pub units_digest: [u8; 32],
    pub capability: String,
    pub replay_scope: String,
    pub inputs: Vec<CertifiedInput>,
    pub output_digest: [u8; 32],
    pub row_digests: Vec<[u8; 32]>,
}

/// The refusal for text that is not a well-formed report certificate
/// (FA-REF-148, usage).
pub fn malformed(why: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CERTIFICATE_MALFORMED,
        exit::USAGE,
        why,
        "plan §13.6 (a certificate is the canonical bytes `fa tb --json` returns, as lowercase hex)",
        "pass the `certificate.bytes` hex from `fa tb … --json`, unedited, as a file or on stdin (`-`)",
    )
}

fn other_book(certified: Id128, here: Id128) -> Refusal {
    Refusal::new(
        code::CERTIFICATE_OTHER_BOOK,
        exit::VERIFICATION,
        format!(
            "the certificate was issued by book {}, not this book ({})",
            certified.to_hex(),
            here.to_hex()
        ),
        "plan §13.6 (a certificate's closure names its book)",
        format!(
            "replay it against book {} (`--book <its directory>`)",
            certified.to_hex()
        ),
    )
}

fn not_reproduced(id: &str, why: impl AsRef<str>) -> Refusal {
    Refusal::new(
        code::CERTIFICATE_NOT_REPRODUCED,
        exit::VERIFICATION,
        format!("certificate {id} does not reproduce: {}", why.as_ref()),
        "FA-INV-11 determinism and replay (plan §13.6: the same closure reproduces byte-identical output)",
        "run `fa certificate status <certificate>` to see what was recorded since; re-certify with `fa tb … --json`; an altered certificate is never repaired",
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    digits
        .chunks(2)
        .map(|pair| Some((nibble(pair[0])? << 4) | nibble(pair[1])?))
        .collect()
}

/// `BLAKE3("fa:certificate-units:v1" ‖ units)`: every unit's id, code,
/// scale, version and kind, in id order. A certificate whose unit ids meant
/// other units is refused at replay, never re-rendered.
#[must_use]
pub fn units_digest(units: &UnitRegistry) -> [u8; 32] {
    let mut w = Writer::new();
    let rows: Vec<_> = units.iter().collect();
    w.list(&rows, |w, (id, unit)| {
        w.u32(id.0).str(&unit.code).u8(unit.scale).u16(unit.version);
        match unit.kind {
            UnitKind::Currency { iso4217 } => w.u8(1).u16(iso4217),
            UnitKind::Commodity => w.u8(2),
            UnitKind::Share => w.u8(3),
            UnitKind::Time => w.u8(4),
            UnitKind::Count => w.u8(5),
            UnitKind::Custom => w.u8(6),
        };
    });
    let mut h = Hasher::new();
    h.update(UNITS_DOMAIN);
    // A unit table too large for the codec's u32 prefixes is not a real
    // registry; its digest is the domain alone and never matches one.
    if let Ok(bytes) = w.finish() {
        h.update(&bytes);
    }
    h.finalize().0
}

impl ReportCertificate {
    /// The certificate's canonical bytes (Appendix A codec).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BookError> {
        let mut w = Writer::new();
        w.str(FORMAT)
            .u16(FORMAT_VERSION)
            .fixed(&self.book_id.0)
            .u64(self.known_at.0)
            .u8(self.request.tag());
        match &self.request {
            TrialBalanceRequest::Stock { periods } | TrialBalanceRequest::Activity { periods } => {
                w.list(periods, |w, p| {
                    w.str(p);
                });
            }
            TrialBalanceRequest::AsOf { day } => {
                w.i32(day.0);
            }
        }
        w.u16(self.definition_version)
            .fixed(&self.symbols_digest)
            .fixed(&self.units_digest)
            .str(&self.capability)
            .str(&self.replay_scope)
            .list(&self.inputs, |w, input| {
                w.str(&input.name)
                    .bytes(&input.certificate.canonical_bytes());
            })
            .fixed(&self.output_digest)
            .list(&self.row_digests, |w, d| {
                w.fixed(d);
            });
        w.finish()
            .map_err(|e| BookError::Certificate(format!("encode certificate: {e}")))
    }

    /// Decode canonical bytes; any structural departure is refused.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        let structural = |e: DecodeError| malformed(format!("not a report certificate: {e}"));
        let mut r = Reader::new(bytes);
        let format = r.str(64, "format").map_err(structural)?;
        if format != FORMAT {
            return Err(malformed(format!("format `{format}` is not `{FORMAT}`")));
        }
        let version = r.u16("format_version").map_err(structural)?;
        if version != FORMAT_VERSION {
            return Err(malformed(format!(
                "certificate format version {version}; this build reads {FORMAT_VERSION}"
            )));
        }
        let book_id = Id128(r.fixed::<16>("book_id").map_err(structural)?);
        let known_at = CommitSeq(r.u64("known_at").map_err(structural)?);
        let periods = |r: &mut Reader<'_>| {
            r.list(MAX_PERIODS, "periods", |r| {
                r.str(MAX_TEXT, "period").map(str::to_string)
            })
        };
        let request = match r.u8("request").map_err(structural)? {
            1 => TrialBalanceRequest::Stock {
                periods: periods(&mut r).map_err(structural)?,
            },
            2 => TrialBalanceRequest::AsOf {
                day: DateDay(r.i32("as_of").map_err(structural)?),
            },
            3 => TrialBalanceRequest::Activity {
                periods: periods(&mut r).map_err(structural)?,
            },
            tag => return Err(structural(r.bad_tag("request", tag))),
        };
        let definition_version = r.u16("definition_version").map_err(structural)?;
        let symbols_digest = r.fixed::<32>("symbols_digest").map_err(structural)?;
        let units_digest = r.fixed::<32>("units_digest").map_err(structural)?;
        let capability = r
            .str(MAX_TEXT, "capability")
            .map_err(structural)?
            .to_string();
        let replay_scope = r
            .str(MAX_TEXT, "replay_scope")
            .map_err(structural)?
            .to_string();
        let raw_inputs = r
            .list(MAX_INPUTS, "inputs", |r| {
                let name = r.str(MAX_TEXT, "input.name")?.to_string();
                let bytes = r.bytes(MAX_INPUT_BYTES, "input.certificate")?.to_vec();
                Ok((name, bytes))
            })
            .map_err(structural)?;
        let output_digest = r.fixed::<32>("output_digest").map_err(structural)?;
        let row_digests = r
            .list(MAX_ROWS, "row_digests", |r| r.fixed::<32>("row_digest"))
            .map_err(structural)?;
        r.finish().map_err(structural)?;
        let mut inputs = Vec::with_capacity(raw_inputs.len());
        for (name, bytes) in raw_inputs {
            let certificate = NativeResultCertificate::decode(&bytes).map_err(|e| {
                malformed(format!(
                    "input `{name}` is not a native result certificate: {e}"
                ))
            })?;
            inputs.push(CertifiedInput { name, certificate });
        }
        Ok(Self {
            book_id,
            known_at,
            request,
            definition_version,
            symbols_digest,
            units_digest,
            capability,
            replay_scope,
            inputs,
            output_digest,
            row_digests,
        })
    }

    /// `BLAKE3("fa:report-certificate-id:v1" ‖ canonical_bytes)`: the
    /// certificate's content address. It is never inside the bytes it names.
    pub fn id(&self) -> Result<[u8; 32], BookError> {
        let mut h = Hasher::new();
        h.update(ID_DOMAIN);
        h.update(&self.canonical_bytes()?);
        Ok(h.finalize().0)
    }

    /// The id as lowercase hex: the robot envelope's `certificate`.
    pub fn id_text(&self) -> Result<String, BookError> {
        Ok(hex(&self.id()?))
    }

    /// The canonical bytes as lowercase hex: what `fa replay` reads.
    pub fn to_hex(&self) -> Result<String, BookError> {
        Ok(hex(&self.canonical_bytes()?))
    }

    /// Parse the hex text `to_hex` produced (surrounding whitespace allowed).
    pub fn from_text(text: &str) -> Result<Self, Refusal> {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Err(malformed("the certificate text is empty"));
        }
        let bytes = unhex(trimmed)
            .ok_or_else(|| malformed("the certificate text is not lowercase hexadecimal"))?;
        Self::decode(&bytes)
    }
}

/// What a replay reproduced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replayed {
    /// The recomputed report: byte-identical to the certified one.
    pub report: TrialBalance,
    /// Every input the substrate replayed, by name.
    pub inputs: Vec<String>,
}

/// One entry recorded after a certificate's known-at that the certified
/// report's selector folds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaterEntry {
    pub vid: VId,
    pub recorded_at: CommitSeq,
    pub effective_date: DateDay,
    pub class: u16,
}

/// Whether a certificate still describes the book (plan §13.6
/// `Current | SupersededBy`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateStatus {
    /// The head the status was taken at.
    pub head: CommitSeq,
    /// Entries recorded after the known-at with an effective date inside
    /// the certified selector, oldest first.
    pub later: Vec<LaterEntry>,
    /// The same report recomputed at the head has other rows or totals
    /// (this also catches resolutions and migration activations, which
    /// change a fold without a new posting inside the selector).
    pub figures_changed: bool,
}

impl CertificateStatus {
    /// `Current`: nothing recorded since changes what the report selects.
    #[must_use]
    pub fn is_current(&self) -> bool {
        self.later.is_empty() && !self.figures_changed
    }
}

fn parameters(at: CommitSeq) -> Result<GqlParameters, BookError> {
    GqlParameters::new()
        .with_uint64("at", at.0)
        .map_err(|e| BookError::Certificate(format!("bind $at: {e:?}")))
}

fn encode_error(e: fa_model::EncodeError) -> BookError {
    BookError::Certificate(format!("encode trial balance: {e}"))
}

/// The trial balance `request` selects at `known_at` (`None` = head).
pub(crate) fn report<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    request: &TrialBalanceRequest,
    known_at: Option<CommitSeq>,
) -> Result<TrialBalance, BookError> {
    Ok(match request {
        TrialBalanceRequest::Stock { periods } => {
            fa_registers::trial_balance_at(db, book, periods, known_at)?
        }
        TrialBalanceRequest::AsOf { day } => fa_registers::balance_as_of(db, book, *day, known_at)?,
        TrialBalanceRequest::Activity { periods } => {
            fa_registers::period_activity(db, book, periods, known_at)?
        }
    })
}

/// Compute the report and certify it: run every [`CERTIFIED_READS`] read at
/// the report's resolved known-at through `Database::execute_certified`.
pub(crate) fn certify<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    cx: &QueryCx,
    request: &TrialBalanceRequest,
    known_at: Option<CommitSeq>,
) -> Result<(TrialBalance, ReportCertificate), BookError> {
    let report = report(db, book, request, known_at)?;
    let at = report.known_at;
    let params = parameters(at)?;
    let mut inputs = Vec::with_capacity(CERTIFIED_READS.len());
    for (name, statement) in CERTIFIED_READS {
        let (_, certificate) = db
            .execute_certified(cx, statement, &params, book.symbols.clone(), BUDGET)
            .map_err(|e| BookError::Certificate(format!("certified read `{name}`: {e}")))?;
        if certificate.plan.snapshot_seq != at {
            return Err(BookError::Certificate(format!(
                "certified read `{name}` ran at sequence {}, not the report's {}",
                certificate.plan.snapshot_seq.0, at.0
            )));
        }
        inputs.push(CertifiedInput {
            name: name.to_string(),
            certificate,
        });
    }
    let certificate = ReportCertificate {
        book_id: book.book_id,
        known_at: at,
        request: request.clone(),
        definition_version: DEFINITION_VERSION,
        symbols_digest: book.symbols.digest().0,
        units_digest: units_digest(&book.units),
        capability: CAPABILITY.to_string(),
        replay_scope: REPLAY_SCOPE.to_string(),
        inputs,
        output_digest: report.output_digest().map_err(encode_error)?,
        row_digests: report.row_digests().map_err(encode_error)?,
    };
    Ok((report, certificate))
}

fn replay_refusal(refusal: &ReplayRefusal, at: CommitSeq) -> String {
    match refusal {
        ReplayRefusal::SnapshotIdentityMismatch => format!(
            "this book's history at sequence {} is not the certified history (chain commitment differs)",
            at.0
        ),
        ReplayRefusal::Snapshot => format!(
            "sequence {} is beyond this book's frontier or no longer retained",
            at.0
        ),
        other => other.to_string(),
    }
}

/// Re-execute a certificate (see the module docs). Only a certificate
/// that fully reproduces is `Ok(Ok)`; every departure is a refusal naming
/// the first thing that differs.
pub(crate) fn replay<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    cx: &QueryCx,
    certificate: &ReportCertificate,
) -> Result<Result<Replayed, Refusal>, BookError> {
    let id = certificate.id_text()?;
    if certificate.book_id != book.book_id {
        return Ok(Err(other_book(certificate.book_id, book.book_id)));
    }
    if certificate.capability != CAPABILITY || certificate.replay_scope != REPLAY_SCOPE {
        return Ok(Err(not_reproduced(
            &id,
            format!(
                "capability `{}` / replay scope `{}` are not this build's `{CAPABILITY}` / `{REPLAY_SCOPE}`",
                certificate.capability, certificate.replay_scope
            ),
        )));
    }
    if certificate.definition_version != DEFINITION_VERSION {
        return Ok(Err(not_reproduced(
            &id,
            format!(
                "definition {} version {} is not this build's version {DEFINITION_VERSION}",
                certificate.request.definition(),
                certificate.definition_version
            ),
        )));
    }
    let names: Vec<&str> = certificate.inputs.iter().map(|i| i.name.as_str()).collect();
    let expected: Vec<&str> = CERTIFIED_READS.iter().map(|(name, _)| *name).collect();
    if names != expected {
        return Ok(Err(not_reproduced(
            &id,
            format!("its inputs {names:?} are not the definition's certified reads {expected:?}"),
        )));
    }
    let params = parameters(certificate.known_at)?;
    for (input, (_, statement)) in certificate.inputs.iter().zip(CERTIFIED_READS) {
        if input.certificate.statement != statement {
            return Ok(Err(not_reproduced(
                &id,
                format!("input `{}` names another statement", input.name),
            )));
        }
        if input.certificate.plan.snapshot_seq != certificate.known_at {
            return Ok(Err(not_reproduced(
                &id,
                format!(
                    "input `{}` is certified at sequence {}, not the certificate's known-at {}",
                    input.name, input.certificate.plan.snapshot_seq.0, certificate.known_at.0
                ),
            )));
        }
        if let Err(refusal) = db.replay(
            cx,
            &input.certificate,
            &params,
            book.symbols.clone(),
            BUDGET,
        ) {
            return Ok(Err(not_reproduced(
                &id,
                format!(
                    "input `{}`: {}",
                    input.name,
                    replay_refusal(&refusal, certificate.known_at)
                ),
            )));
        }
    }
    if certificate.symbols_digest != book.symbols.digest().0 {
        return Ok(Err(not_reproduced(
            &id,
            "the symbol table differs from the certified one",
        )));
    }
    if certificate.units_digest != units_digest(&book.units) {
        return Ok(Err(not_reproduced(
            &id,
            "the unit table differs from the certified one, so its unit ids would mean other units",
        )));
    }
    let replayed = match report(db, book, &certificate.request, Some(certificate.known_at)) {
        Ok(report) => report,
        Err(BookError::Registers(RegisterError::InvalidSelection(why))) => {
            return Ok(Err(not_reproduced(
                &id,
                format!("its selector does not resolve: {why}"),
            )));
        }
        Err(e) => return Err(e),
    };
    let rows = replayed.row_digests().map_err(encode_error)?;
    if let Some(index) = (0..rows.len().max(certificate.row_digests.len()))
        .find(|&i| rows.get(i) != certificate.row_digests.get(i))
    {
        let why = match replayed.rows.get(index) {
            Some(row) if index < certificate.row_digests.len() => format!(
                "row {index} (account {} unit {}) differs from the certified row",
                row.code, row.unit_id
            ),
            Some(row) => format!(
                "the replay has row {index} (account {} unit {}) the certificate lacks",
                row.code, row.unit_id
            ),
            None => format!(
                "the certificate has {} rows; the replay has {}",
                certificate.row_digests.len(),
                rows.len()
            ),
        };
        return Ok(Err(not_reproduced(&id, why)));
    }
    if replayed.output_digest().map_err(encode_error)? != certificate.output_digest {
        return Ok(Err(not_reproduced(
            &id,
            "every row matches, but the selector, known-at or totals differ from the certified output",
        )));
    }
    Ok(Ok(Replayed {
        report: replayed,
        inputs: expected.into_iter().map(str::to_string).collect(),
    }))
}

/// The certificate's status at the head (see [`CertificateStatus`]).
pub(crate) fn status<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    certificate: &ReportCertificate,
) -> Result<Result<CertificateStatus, Refusal>, BookError> {
    if certificate.book_id != book.book_id {
        return Ok(Err(other_book(certificate.book_id, book.book_id)));
    }
    let head = db.frontier().map_err(fa_journal::KernelError::from)?;
    if certificate.known_at > head {
        return Ok(Err(not_reproduced(
            &certificate.id_text()?,
            format!(
                "its known-at {} is beyond this book's head {}",
                certificate.known_at.0, head.0
            ),
        )));
    }
    let at_known = match report(db, book, &certificate.request, Some(certificate.known_at)) {
        Ok(report) => report,
        Err(BookError::Registers(RegisterError::InvalidSelection(why))) => {
            return Ok(Err(not_reproduced(
                &certificate.id_text()?,
                format!("its selector does not resolve: {why}"),
            )));
        }
        Err(e) => return Err(e),
    };
    let at_head = report(db, book, &certificate.request, Some(head))?;
    let figures_changed = at_head.rows != at_known.rows
        || at_head.unit_totals != at_known.unit_totals
        || at_head.pending_unit_totals != at_known.pending_unit_totals;
    let mut later = Vec::new();
    for (vid, entry, recorded_at) in fa_registers::canonical::entries_at_seq(db, book, head)? {
        if recorded_at <= certificate.known_at || entry.proposal.legs.is_empty() {
            continue;
        }
        let inside = match &certificate.request {
            TrialBalanceRequest::Stock { .. } => at_known
                .effective_through
                .is_some_and(|through| entry.proposal.effective_date <= through),
            TrialBalanceRequest::AsOf { day } => entry.proposal.effective_date <= *day,
            TrialBalanceRequest::Activity { periods } => {
                let period = fa_registers::canonical::entry_period_code(book, &entry)?;
                periods.contains(&period)
            }
        };
        if inside {
            later.push(LaterEntry {
                vid,
                recorded_at,
                effective_date: entry.proposal.effective_date,
                class: entry.proposal.class.0,
            });
        }
    }
    later.sort_by_key(|e| (e.recorded_at, e.vid));
    Ok(Ok(CertificateStatus {
        head,
        later,
        figures_changed,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fgdb::{NativePlanCertificate, NativeReadClass};

    fn native(statement: &str, seq: u64) -> NativeResultCertificate {
        let digest = fgdb_crypto::Digest([0x11; 32]);
        NativeResultCertificate {
            plan: NativePlanCertificate {
                digest,
                snapshot_seq: CommitSeq(seq),
            },
            values_digest: digest,
            result_digest: digest,
            statement: statement.to_string(),
            facade_class: NativeReadClass::TemporalPattern,
            snapshot_identity: digest,
            database_identity: digest,
            procedures: Vec::new(),
        }
    }

    fn sample() -> ReportCertificate {
        ReportCertificate {
            book_id: Id128([7; 16]),
            known_at: CommitSeq(12),
            request: TrialBalanceRequest::Stock {
                periods: vec!["FY2026-P03".into()],
            },
            definition_version: DEFINITION_VERSION,
            symbols_digest: [1; 32],
            units_digest: [2; 32],
            capability: CAPABILITY.into(),
            replay_scope: REPLAY_SCOPE.into(),
            inputs: CERTIFIED_READS
                .iter()
                .map(|(name, statement)| CertifiedInput {
                    name: (*name).to_string(),
                    certificate: native(statement, 12),
                })
                .collect(),
            output_digest: [3; 32],
            row_digests: vec![[4; 32], [5; 32]],
        }
    }

    #[test]
    fn a_certificate_round_trips_through_its_text_and_its_id_binds_every_field() {
        let cert = sample();
        let text = cert.to_hex().expect("encode");
        assert_eq!(
            ReportCertificate::from_text(&format!("  {text}\n")).expect("decode"),
            cert
        );
        let id = cert.id().expect("id");
        let variants = [
            ReportCertificate {
                known_at: CommitSeq(13),
                ..cert.clone()
            },
            ReportCertificate {
                request: TrialBalanceRequest::Activity {
                    periods: vec!["FY2026-P03".into()],
                },
                ..cert.clone()
            },
            ReportCertificate {
                request: TrialBalanceRequest::AsOf {
                    day: DateDay(20_000),
                },
                ..cert.clone()
            },
            ReportCertificate {
                output_digest: [9; 32],
                ..cert.clone()
            },
            ReportCertificate {
                row_digests: vec![[4; 32]],
                ..cert.clone()
            },
            ReportCertificate {
                units_digest: [8; 32],
                ..cert.clone()
            },
        ];
        for variant in variants {
            assert_ne!(variant.id().expect("id"), id, "{variant:?}");
            let back =
                ReportCertificate::from_text(&variant.to_hex().expect("encode")).expect("decode");
            assert_eq!(back, variant);
        }
    }

    #[test]
    fn malformed_certificate_text_is_refused_as_usage_never_decoded_partly() {
        let text = sample().to_hex().expect("encode");
        let cases = [
            String::new(),
            "zz".to_string(),
            text.to_uppercase(),
            text[..text.len() - 2].to_string(),
            format!("{text}00"),
            text.replacen("6661", "6662", 1),
        ];
        for case in cases {
            let refusal = ReportCertificate::from_text(&case).expect_err("refused");
            assert_eq!(refusal.code, code::CERTIFICATE_MALFORMED, "{case}");
            assert_eq!(refusal.exit, exit::USAGE);
        }
    }
}
