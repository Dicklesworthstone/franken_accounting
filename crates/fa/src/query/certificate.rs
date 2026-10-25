//! Query certificates (plan §15.5 and §13.6, bead fa-5c1). `fa query
//! --certify` retains a statement's exact result so that `fa replay`
//! reproduces it byte for byte (FA-INV-11).
//!
//! A certificate binds four things:
//! - the profile statement, as written;
//! - the substrate's `NativeResultCertificate` for the one native read the
//!   profile compiled;
//! - a source `ReportCertificate`: the whole-book stock trial balance at the
//!   same sequence, which binds the chart, calendar, periods, units and
//!   journal prefix the read saw;
//! - the canonical result ([`QueryRows::canonical_bytes`]).
//!
//! Replay replays the source and compiles the statement again; the profile
//! must still emit exactly the certified native statement. It then replays
//! the native read against the retained snapshot and recomputes the result,
//! which must equal the certified bytes. A digest alone is never a replay.
//!
//! Producing one needs current whole-book read and produce authority, and
//! replaying one needs whole-book read. Neither writes; retention is the
//! certificate store's. This v1 binds a recorded sequence: a statement
//! selected by an instant is certified at the sequence it resolves to.

use asupersync::fs::Vfs;
use fa_journal::genesis::BookContext;
use fa_journal::rows::PeriodRow;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::symbols::label;
use fa_model::{DecodeError, EncodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fa_query::{KnownAt, Native, Selection};
use fa_time::DateDay;
use fgdb::{Database, NativeResultCertificate};
use fgdb_gql::GqlParameters;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{
    QUERY_OUTPUT_FORMAT, QueryRows, budget, code, execute, period_bounds, profile_refusal,
    result_of,
};
use crate::{
    AsyncBook, BookError, Outcome, ReportCertificate, ReportSelection, TrialBalanceSelection,
};

pub const QUERY_CERTIFICATE_FORMAT: &[u8] = b"fa:query-certificate:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:query-certificate-digest:v1";
const MAX_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE_BYTES: usize = 1024 * 1024;

/// A sealed query certificate. Decoding checks its framing, digest and
/// that the statement still compiles to the certified native read, NOT its
/// historical validity: only replay establishes that.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCertificate {
    source: ReportCertificate,
    statement: String,
    native: NativeResultCertificate,
    output: Vec<u8>,
    digest: [u8; 32],
}

/// A query's result together with the certificate that replays it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedQuery {
    pub rows: QueryRows,
    pub certificate: QueryCertificate,
}

/// Whether the certified statement still answers the same at the head.
/// `Changed` carries the present result for inspection only; it is not a
/// new certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryCertificateStatus {
    Current {
        checked_at: CommitSeq,
    },
    Changed {
        checked_at: CommitSeq,
        current: Box<QueryRows>,
    },
}

fn invalid(why: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        why,
        "plan §15.5 / §13.6 (a query replays its native read and its exact result)",
        "recreate the certificate with fa query --certify on the original book; keep its source trial balance and native read certificate",
    )
}

fn encoding(error: EncodeError) -> BookError {
    KernelError::Model(error.into()).into()
}

/// The native read `statement` compiles to, and its `FOR PERIOD` code, as a
/// certificate at `known_at` binds them.
fn compiled(statement: &str, known_at: CommitSeq) -> Result<(Native, Option<String>), Refusal> {
    let profiled = fa_query::rewrite(statement).map_err(|r| {
        invalid(format!(
            "the certified statement no longer compiles: {}",
            r.message
        ))
    })?;
    match profiled.known_at {
        KnownAt::Head => {}
        KnownAt::Seq(seq) if seq == known_at.0 => {}
        KnownAt::Seq(seq) => {
            return Err(invalid(format!(
                "the statement selects AS KNOWN AT {seq}, but the certificate is at {}",
                known_at.0
            )));
        }
        KnownAt::Instant(_) => {
            return Err(invalid(
                "a v1 query certificate binds a recorded sequence, not an instant",
            ));
        }
        KnownAt::Reported(_) => {
            return Err(invalid(
                "a v1 query certificate binds a recorded sequence, not a restatement view",
            ));
        }
    }
    match profiled.selection {
        Selection::Native(native) => Ok((native, profiled.period)),
        Selection::TrialBalance
        | Selection::ExplainBalance { .. }
        | Selection::OpenItems { .. } => Err(invalid(
            "a CALL is certified as the report it runs (fa tb, fa explain balance or fa open-items --certify), not as a query",
        )),
        Selection::AccessLog { .. } => Err(invalid(
            "CALL fa.access_log reads the access events at the head; it has no certificate",
        )),
    }
}

/// The last day of the book's calendar at `seq`: the whole-book stock
/// trial balance is taken as of it.
fn last_day<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    seq: CommitSeq,
) -> Result<Option<DateDay>, BookError> {
    let mut last = None;
    for row in db.vertices_at(seq).map_err(KernelError::from)? {
        if !row.labels.contains(&label::PERIOD) {
            continue;
        }
        let period = PeriodRow::decode(&row)?;
        if period.calendar_id != book.calendar.id {
            continue;
        }
        // Periods are half-open: [start, end).
        let day = period
            .end
            .0
            .checked_sub(1)
            .map(DateDay)
            .ok_or_else(|| KernelError::Corrupt("period.period_end".into()))?;
        last = last.max(Some(day));
    }
    Ok(last)
}

fn output_tagged(output: &[u8]) -> bool {
    Reader::new(output)
        .bytes(64, "query output format")
        .is_ok_and(|tag| tag == QUERY_OUTPUT_FORMAT)
}

impl QueryCertificate {
    #[must_use]
    pub fn source_certificate(&self) -> &ReportCertificate {
        &self.source
    }

    /// The profile statement, as written.
    #[must_use]
    pub fn statement(&self) -> &str {
        &self.statement
    }

    #[must_use]
    pub fn native(&self) -> &NativeResultCertificate {
        &self.native
    }

    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.source.known_at
    }

    #[must_use]
    pub fn book_id(&self) -> Id128 {
        self.source.book_id
    }

    /// The statement's `FOR PERIOD` code.
    pub fn period(&self) -> Result<Option<String>, Refusal> {
        compiled(&self.statement, self.known_at()).map(|(_, period)| period)
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        if self.output.len() > MAX_CERTIFICATE_BYTES || !output_tagged(&self.output) {
            return Err(invalid("unsupported or oversized query output"));
        }
        if self.source.branch_id != Id128::TRUNK
            || self.source.time_selection.is_some()
            || !matches!(
                &self.source.selection,
                ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(_))
            )
        {
            return Err(invalid(
                "a v1 query needs a sequence-selected trunk stock trial-balance source",
            ));
        }
        let (native, _) = compiled(&self.statement, self.known_at())?;
        // A period range's native read binds its days, which a replay checks
        // against the book's periods at the certified sequence.
        let compiles = if native.period_range() {
            native
                .bound_period_range(&self.native.statement, self.known_at().0)
                .is_some()
        } else {
            self.native.statement == native.statement(self.known_at().0)
        };
        if self.native.plan.snapshot_seq != self.known_at() || !compiles {
            return Err(invalid(
                "the native read is not the one the statement compiles to at the certified sequence",
            ));
        }
        let source = self
            .source
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        // A ReportCertificate's public fields can be changed by an embedding
        // and its encoder is not validation: decode checks its closure.
        ReportCertificate::decode(&source)?;
        let native = self.native.canonical_bytes();
        if native.len() > MAX_NATIVE_BYTES {
            return Err(invalid("the native read certificate exceeds 1 MiB"));
        }
        let size = [
            4,
            QUERY_CERTIFICATE_FORMAT.len(),
            4,
            source.len(),
            4,
            self.statement.len(),
            4,
            native.len(),
            4,
            self.output.len(),
            32,
        ]
        .into_iter()
        .try_fold(0usize, |total, part| total.checked_add(part))
        .ok_or_else(|| invalid("query certificate length overflow"))?;
        if size > MAX_CERTIFICATE_BYTES {
            return Err(invalid("query certificate exceeds the 64 MiB format limit"));
        }
        let mut w = Writer::with_capacity(size);
        w.bytes(QUERY_CERTIFICATE_FORMAT)
            .bytes(&source)
            .str(&self.statement)
            .bytes(&native)
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(
        source: ReportCertificate,
        statement: String,
        native: NativeResultCertificate,
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut value = Self {
            source,
            statement,
            native,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// Canonical, bounded portable bytes. This checks framing and content
    /// integrity; only replay checks the retained history and the result.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&body]) != self.digest {
            return Err(invalid("query certificate content digest does not match"));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(invalid("query certificate exceeds the 64 MiB format limit"));
        }
        let read = || -> Result<Self, Refusal> {
            let malformed =
                |error: DecodeError| invalid(format!("malformed query certificate: {error}"));
            let mut r = Reader::new(bytes);
            if r.bytes(64, "query certificate format").map_err(malformed)?
                != QUERY_CERTIFICATE_FORMAT
            {
                return Err(invalid("unsupported query certificate format"));
            }
            let source = ReportCertificate::decode(
                r.bytes(MAX_CERTIFICATE_BYTES, "source certificate")
                    .map_err(malformed)?,
            )?;
            let statement = r
                .str(fa_query::MAX_STATEMENT_BYTES, "query statement")
                .map_err(malformed)?
                .to_string();
            let native = NativeResultCertificate::decode(
                r.bytes(MAX_NATIVE_BYTES, "native read certificate")
                    .map_err(malformed)?,
            )
            .map_err(|error| invalid(format!("malformed native read certificate: {error}")))?;
            let output = r
                .bytes(MAX_CERTIFICATE_BYTES, "query output")
                .map_err(malformed)?
                .to_vec();
            let digest = r.fixed("query certificate digest").map_err(malformed)?;
            r.finish().map_err(malformed)?;
            Ok(Self {
                source,
                statement,
                native,
                output,
                digest,
            })
        };
        let value = read()?;
        // Besides the digest, refuse any alternate encoding.
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical query certificate encoding"));
        }
        Ok(value)
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    produce: bool,
) -> Outcome<()> {
    let admitted = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
        .and_then(|()| {
            if produce {
                fa_policy::require(capability, Op::Produce, "certifying a query")
            } else {
                Ok(())
            }
        });
    if let Err(denial) = admitted {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    book.query(cx, |db, context| {
        let head = db.frontier().map_err(KernelError::from)?;
        if let Err(denial) = fa_policy::current(capability, head) {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        Ok(fa_journal::policy::capability_admitted(
            db, context, capability,
        )?)
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Run `statement` and certify exactly the result it returned. The
    /// statement's own selector picks the sequence (the head when it names
    /// none); an instant is refused, naming the sequence to certify at.
    pub fn certify_query(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        statement: &str,
    ) -> Outcome<CertifiedQuery> {
        if let Err(refusal) = authorize(self, cx, principal, capability, true)? {
            return Ok(Err(refusal));
        }
        let profiled = match fa_query::rewrite(statement) {
            Ok(profiled) => profiled,
            Err(refusal) => return Ok(Err(profile_refusal(&refusal))),
        };
        let Selection::Native(native) = profiled.selection else {
            return Ok(Err(Refusal::new(
                code::QUERY_PROFILE,
                exit::REFUSAL,
                "a CALL is certified as the report it runs",
                super::CITE,
                "fa query \"CALL fa.trial_balance FOR PERIOD '<code>'\" --certify, which is fa tb --certify (likewise fa explain balance and fa open-items)",
            )));
        };
        let requested = match profiled.known_at {
            KnownAt::Head => None,
            KnownAt::Seq(seq) => Some(CommitSeq(seq)),
            KnownAt::Instant(_) => {
                return Ok(Err(Refusal::new(
                    code::QUERY_PROFILE,
                    exit::REFUSAL,
                    "a query certificate binds a recorded sequence; this one is selected by an instant",
                    super::CITE,
                    "run the statement once to read the sequence its instant resolves to, then certify it AS KNOWN AT <that sequence>",
                )));
            }
            KnownAt::Reported(_) => {
                return Ok(Err(Refusal::new(
                    code::QUERY_PROFILE,
                    exit::REFUSAL,
                    "a query certificate binds a recorded sequence; this one is selected by a restatement view",
                    super::CITE,
                    "run the statement once to read the sequence its period was reported at, then certify it AS KNOWN AT <that sequence>",
                )));
            }
        };
        let (seq, day) = self.query(cx, |db, book| {
            let seq = fa_registers::resolve_known_at(db, requested)?;
            Ok((seq, last_day(db, book, seq)?))
        })?;
        let Some(day) = day else {
            return Ok(Err(invalid(format!(
                "the book holds no period at {}, so there is no trial balance to bind",
                seq.0
            ))));
        };
        let source =
            match self.certify_trial_balance(cx, TrialBalanceSelection::AsOf(day), Some(seq))? {
                Ok(source) => source.certificate,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let (rows, native_certificate) = match self.query(cx, |db, book| {
            execute(
                db,
                &cx.query(),
                book,
                &native,
                seq,
                profiled.period.as_deref(),
            )
        })? {
            Ok(executed) => executed,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if source.known_at != seq {
            return Ok(Err(invalid(
                "the source trial balance and the native read are at different sequences",
            )));
        }
        let output = rows.canonical_bytes().map_err(encoding)?;
        let certificate =
            match QueryCertificate::seal(source, statement.to_string(), native_certificate, output)
            {
                Ok(certificate) => certificate,
                Err(refusal) => return Ok(Err(refusal)),
            };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(CertifiedQuery { rows, certificate }))
    }

    /// Replay the source trial balance, then the native read against the
    /// retained snapshot, and recompute the result: it must equal the
    /// certified bytes. A later write never moves it; current authority
    /// cannot be taken from the certificate.
    pub fn replay_query(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &QueryCertificate,
    ) -> Outcome<QueryRows> {
        if let Err(refusal) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(refusal));
        }
        if certificate.book_id() != self.context().book_id {
            return Ok(Err(invalid(
                "the query certificate belongs to another book",
            )));
        }
        if let Err(refusal) = certificate.canonical_bytes() {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self.replay_trial_balance(cx, &certificate.source)? {
            return Ok(Err(refusal));
        }
        let (native, period) = match compiled(&certificate.statement, certificate.known_at()) {
            Ok(compiled) => compiled,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let seq = certificate.known_at();
        let replayed = self.query(cx, |db, book| {
            // A period range replays bound with the days it spans at the
            // certified sequence, which its native read must carry.
            let mut native = native.clone();
            if let Some(code) = period.as_deref() {
                match period_bounds(db, book, code, seq)? {
                    Err(refusal) => {
                        return Ok(Err(invalid(format!(
                            "the certified period does not replay: {}",
                            refusal.message
                        ))));
                    }
                    Ok((start, end)) if native.period_range() => {
                        if native.bound_period_range(&certificate.native.statement, seq.0)
                            != Some((start.0, end.0))
                        {
                            return Ok(Err(invalid(format!(
                                "the native read binds other days than the period range `{code}` spans at {}",
                                seq.0
                            ))));
                        }
                        native = native.bind_period_range(start.0, end.0);
                    }
                    Ok(_) => {}
                }
            }
            let result = match db.replay(
                &cx.query(),
                &certificate.native,
                &GqlParameters::new(),
                book.symbols.clone(),
                budget(&native),
            ) {
                Ok(result) => result,
                Err(error) => {
                    return Ok(Err(invalid(format!(
                        "the native read does not replay: {error}"
                    ))));
                }
            };
            Ok(
                result_of(&native, seq, result, &certificate.native).map_err(|refusal| {
                    invalid(format!(
                        "the replayed rows do not fold: {}",
                        refusal.message
                    ))
                }),
            )
        })?;
        let rows = match replayed {
            Ok(rows) => rows,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let output = rows.canonical_bytes().map_err(encoding)?;
        if output != certificate.output {
            let first = output
                .iter()
                .zip(&certificate.output)
                .position(|(a, b)| a != b)
                .unwrap_or(output.len().min(certificate.output.len()));
            return Ok(Err(invalid(format!(
                "the replayed result differs from the certified output at canonical byte {first}"
            ))));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(rows))
    }

    /// Replay first, then run the same statement at the head and compare
    /// its columns and rows. Only the sequence (and so the native text and
    /// the substrate's digest) may differ for `Current`.
    pub fn query_certificate_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &QueryCertificate,
    ) -> Outcome<QueryCertificateStatus> {
        let original = match self.replay_query(cx, principal, capability, certificate)? {
            Ok(rows) => rows,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let (native, period) = match compiled(&certificate.statement, certificate.known_at()) {
            Ok(compiled) => compiled,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let current = match self.query(cx, |db, book| {
            let head = db.frontier().map_err(KernelError::from)?;
            execute(db, &cx.query(), book, &native, head, period.as_deref())
        })? {
            Ok((rows, _)) => rows,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let checked_at = current.known_at;
        let unchanged = current.columns == original.columns && current.rows == original.rows;
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(if unchanged {
            QueryCertificateStatus::Current { checked_at }
        } else {
            QueryCertificateStatus::Changed {
                checked_at,
                current: Box::new(current),
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_foreign_containers_are_refused() {
        for bytes in [vec![], vec![0], vec![255; 32]] {
            assert!(QueryCertificate::decode(&bytes).is_err());
        }
        let mut w = Writer::new();
        w.bytes(b"fa:summary-certificate:v1");
        let foreign = w.finish().expect("encodes");
        let refusal = QueryCertificate::decode(&foreign).expect_err("a foreign format");
        assert!(refusal.message.contains("unsupported"), "{refusal:?}");
        let mut w = Writer::new();
        w.bytes(QUERY_CERTIFICATE_FORMAT).u32(u32::MAX);
        assert!(QueryCertificate::decode(&w.finish().expect("encodes")).is_err());
    }

    #[test]
    fn the_statement_must_compile_to_the_certified_coordinate() {
        let at = CommitSeq(7);
        let text = "MATCH (a:Account) RETURN a.code";
        assert!(compiled(text, at).is_ok());
        assert!(compiled(&format!("{text} AS KNOWN AT 7"), at).is_ok());
        let other = compiled(&format!("{text} AS KNOWN AT 6"), at).expect_err("another sequence");
        assert!(other.message.contains("AS KNOWN AT 6"), "{other:?}");
        assert!(compiled(&format!("{text} AS KNOWN AT '2026-03-01T00:00:00Z'"), at).is_err());
        assert!(compiled("CALL fa.trial_balance", at).is_err());
        assert!(compiled("MATCH (l:Leg) RETURN SUM(l.amount)", at).is_err());
        assert_eq!(
            compiled(
                "MATCH (l:Leg) RETURN COUNT(*) AS legs FOR PERIOD 'FY2026-P03'",
                at
            )
            .expect("compiles")
            .1
            .as_deref(),
            Some("FY2026-P03")
        );
    }
}
