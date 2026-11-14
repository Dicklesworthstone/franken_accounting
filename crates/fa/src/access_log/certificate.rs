//! Historical access-log selections and their retained-history replay evidence.
//!
//! A native read certificate binds the complete AccessEvent population at the
//! selected prefix; the report binds its interval and reader and every returned
//! event. The accompanying ordinary report certificate binds the original book
//! context and journal. Neither a saved capability commitment nor these local
//! replay certificates grant the recipient access. This is not an offline
//! checkpoint inclusion or completeness proof, or proof of successful delivery.

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::{AccessEvent, DecodeError, Id128, Reader, Writer, domain_digest, principal_vid};
use fa_policy::{Capability, Observes, Op};
use fa_time::DateDay;
use fgdb::NativeResultCertificate;
use fgdb_gql::{GqlParameters, GqlQueryPolicy};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::RecordedAccess;
use crate::{
    AsyncBook, BookError, Outcome, ReportCertificate, ReportSelection, TrialBalanceSelection,
};

pub const ACCESS_LOG_CERTIFICATE_FORMAT: &[u8] = b"fa:access-log-certificate:v1";
pub const ACCESS_LOG_OUTPUT_FORMAT: &str = "fa:access-log:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:access-log-certificate-digest:v1";
const MAX_BYTES: usize = crate::certificate::MAX_CERTIFICATE_BYTES;
const MAX_NATIVE_BYTES: usize = 1024 * 1024;

/// A recorded-time selection. `through = None` follows HEAD when first read;
/// a certificate resolves that frontier once and never re-dates its replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessLogRequest {
    pub since: CommitSeq,
    pub through: Option<CommitSeq>,
    pub reader: Option<String>,
}

impl AccessLogRequest {
    fn validate(&self) -> Result<(), Refusal> {
        if self.through.is_some_and(|at| at < self.since)
            || self.reader.as_ref().is_some_and(|reader| {
                reader.is_empty() || reader.len() > fa_model::access_event::MAX_ACCESS_NAME
            })
        {
            return Err(super::invalid(
                "the access-log interval or reader is invalid",
            ));
        }
        Ok(())
    }

    fn selects(&self, event: &RecordedAccess) -> bool {
        event.recorded_at > self.since
            && self.through.is_none_or(|at| event.recorded_at <= at)
            && self
                .reader
                .as_ref()
                .is_none_or(|reader| event.record.principal == principal_vid(reader))
    }
}

/// Complete selected rows at one pinned prefix. All names describe attempted
/// access, not successful disclosure or per-object READ receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessLogReport {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub request: AccessLogRequest,
    pub events: Vec<RecordedAccess>,
}

impl AccessLogReport {
    fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        self.request.validate().map_err(|e| invalid(e.message))?;
        if self.request.since > self.known_at
            || self.request.through.is_some_and(|at| at != self.known_at)
            || self.events.windows(2).any(|pair| {
                (pair[0].recorded_at, pair[0].vid) >= (pair[1].recorded_at, pair[1].vid)
            })
        {
            return Err(invalid(
                "access-log output has an inconsistent coordinate or row order",
            ));
        }
        let mut w = Writer::new();
        w.bytes(ACCESS_LOG_OUTPUT_FORMAT.as_bytes())
            .fixed(&self.book_id.0)
            .u64(self.known_at.0)
            .u64(self.request.since.0)
            .bool(self.request.through.is_some());
        if let Some(at) = self.request.through {
            w.u64(at.0);
        }
        w.bool(self.request.reader.is_some());
        if let Some(reader) = &self.request.reader {
            w.str(reader);
        }
        // Validate before writing; an event's ordinal and content identity come
        // from the retained row, never from caller-supplied summary columns.
        let mut rows = Vec::with_capacity(self.events.len());
        let mut total = 0usize;
        for row in &self.events {
            if !self.request.selects(row)
                || row.observed_at >= row.recorded_at
                || row.recorded_at > self.known_at
            {
                return Err(invalid(
                    "access-log event is outside the selected interval or reader",
                ));
            }
            row.record.validate().map_err(invalid)?;
            let event = AccessEvent {
                book_id: self.book_id,
                record: row.record.clone(),
                observed_at: row.observed_at,
            };
            let payload = event
                .canonical_bytes()
                .map_err(|e| invalid(e.to_string()))?;
            if event.digest().map_err(|e| invalid(e.to_string()))? != row.digest
                || event.vid().map_err(|e| invalid(e.to_string()))? != row.vid
            {
                return Err(invalid(
                    "access-log event identity differs from its payload",
                ));
            }
            total = total
                .checked_add(payload.len() + 60)
                .filter(|size| *size <= MAX_BYTES)
                .ok_or_else(|| invalid("access-log output exceeds the 64 MiB certificate limit"))?;
            rows.push((row, payload));
        }
        w.list(&rows, |w, (row, payload)| {
            w.u128(row.vid.0)
                .fixed(&row.digest)
                .u64(row.recorded_at.0)
                .bytes(payload);
        });
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        let malformed = |e: DecodeError| invalid(format!("malformed access-log output: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "access-log format").map_err(malformed)?
            != ACCESS_LOG_OUTPUT_FORMAT.as_bytes()
        {
            return Err(invalid("unsupported access-log output format"));
        }
        let book_id = Id128(r.fixed("access-log book").map_err(malformed)?);
        let known_at = CommitSeq(r.u64("access-log known-at").map_err(malformed)?);
        let since = CommitSeq(r.u64("access-log since").map_err(malformed)?);
        let through = if r.bool("access-log through present").map_err(malformed)? {
            Some(CommitSeq(r.u64("access-log through").map_err(malformed)?))
        } else {
            None
        };
        let reader = if r.bool("access-log reader present").map_err(malformed)? {
            Some(
                r.str(fa_model::access_event::MAX_ACCESS_NAME, "access-log reader")
                    .map_err(malformed)?
                    .to_owned(),
            )
        } else {
            None
        };
        // Each encoded row needs at least its 60-byte framing, before payload.
        let events = r
            .list(bytes.len() / 60, "access-log events", |r| {
                let vid = VId(r.u128("access-log event vid")?);
                let digest = r.fixed("access-log event digest")?;
                let recorded_at = CommitSeq(r.u64("access-log event sequence")?);
                let event = AccessEvent::decode(r.bytes(MAX_BYTES, "access-log event payload")?)?;
                if event.book_id != book_id {
                    return Err(r.invalid("access-log event book"));
                }
                Ok(RecordedAccess {
                    vid,
                    digest,
                    record: event.record,
                    observed_at: event.observed_at,
                    recorded_at,
                })
            })
            .map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let report = Self {
            book_id,
            known_at,
            request: AccessLogRequest {
                since,
                through,
                reader,
            },
            events,
        };
        if report.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical access-log output"));
        }
        Ok(report)
    }
}

/// Content-addressed retained-history proof, replayed only against its original
/// book. The capability commitment records the producer, never replay authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessLogCertificate {
    source: ReportCertificate,
    native: NativeResultCertificate,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedAccessLog {
    pub report: AccessLogReport,
    pub certificate: AccessLogCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccessLogCertificateStatus {
    Current { checked_at: CommitSeq },
    Changed { checked_at: CommitSeq },
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §9.7 / §13.6 / §14.5 (complete access-log selection at one retained prefix)",
        "recreate the access-log certificate from the original book and selector; preserve the original native history",
    )
}

fn statement(at: CommitSeq) -> String {
    format!(
        "MATCH (n:AccessEvent) FOR SYSTEM_TIME AS OF SEQ {} RETURN n,n._fa_payload,n._fa_digest,n.book_id ORDER BY n",
        at.0
    )
}

fn policy() -> GqlQueryPolicy {
    // The same bounded native closure budget as ordinary report certificates.
    GqlQueryPolicy::new(10_000_000, 1_000_000, 256 * 1024 * 1024, 256 * 1024 * 1024)
}

impl AccessLogCertificate {
    #[must_use]
    pub fn source_certificate(&self) -> &ReportCertificate {
        &self.source
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn capability_commitment(&self) -> &[u8; 32] {
        &self.capability_commitment
    }

    pub fn report(&self) -> Result<AccessLogReport, Refusal> {
        AccessLogReport::decode(&self.output)
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        if self.output.len() > MAX_BYTES {
            return Err(invalid("oversized access-log output"));
        }
        let report = self.report()?;
        if report.book_id != self.source.book_id
            || report.known_at != self.source.known_at
            || self.source.branch_id != Id128::TRUNK
            || self.source.time_selection.is_some()
            || self.source.selection
                != ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(DateDay(i32::MAX)))
            || self.native.statement != statement(report.known_at)
            || self.native.plan.snapshot_seq != report.known_at
            || self.source.inputs.iter().any(|input| {
                input.database_identity != self.native.database_identity
                    || input.snapshot_identity != self.native.snapshot_identity
            })
        {
            return Err(invalid(
                "access-log native read, report and book source bind different snapshots",
            ));
        }
        let source = self
            .source
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        ReportCertificate::decode(&source)?;
        let native = self.native.canonical_bytes();
        if native.len() > MAX_NATIVE_BYTES {
            return Err(invalid("access-log native certificate exceeds 1 MiB"));
        }
        let size = source
            .len()
            .checked_add(native.len())
            .and_then(|n| n.checked_add(self.output.len()))
            .and_then(|n| n.checked_add(128))
            .filter(|n| *n <= MAX_BYTES)
            .ok_or_else(|| invalid("access-log certificate exceeds the 64 MiB format limit"))?;
        let mut w = Writer::with_capacity(size);
        w.bytes(ACCESS_LOG_CERTIFICATE_FORMAT)
            .bytes(&source)
            .bytes(&native)
            .fixed(&self.capability_commitment)
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&body]) != self.digest {
            return Err(invalid(
                "access-log certificate content digest does not match",
            ));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_BYTES {
            return Err(invalid("access-log certificate exceeds 64 MiB"));
        }
        let malformed = |e: DecodeError| invalid(format!("malformed access-log certificate: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "access-log certificate format")
            .map_err(malformed)?
            != ACCESS_LOG_CERTIFICATE_FORMAT
        {
            return Err(invalid("unsupported access-log certificate format"));
        }
        let source =
            ReportCertificate::decode(r.bytes(MAX_BYTES, "access-log source").map_err(malformed)?)?;
        let native = NativeResultCertificate::decode(
            r.bytes(MAX_NATIVE_BYTES, "access-log native")
                .map_err(malformed)?,
        )
        .map_err(|e| invalid(format!("malformed access-log native certificate: {e}")))?;
        let capability_commitment = r.fixed("access-log capability").map_err(malformed)?;
        let output = r
            .bytes(MAX_BYTES, "access-log output")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed("access-log digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let certificate = Self {
            source,
            native,
            capability_commitment,
            output,
            digest,
        };
        if certificate.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical access-log certificate"));
        }
        Ok(certificate)
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    observes: Observes,
    produce: bool,
) -> Outcome<()> {
    let reach = fa_policy::Reach {
        observes,
        ..fa_policy::Reach::whole_book(true)
    };
    let admitted = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| fa_policy::reach(capability, &reach, None))
        .and_then(|()| {
            if produce {
                fa_policy::require(capability, Op::Produce, "certifying the access log")
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
    /// Read a complete historical interval under current whole-book authority.
    /// A reader selector narrows the report, never the capability's reach.
    pub fn read_access_log(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &AccessLogRequest,
    ) -> Outcome<AccessLogReport> {
        if let Err(refusal) = authorize(
            self,
            cx,
            principal,
            capability,
            request.through.map_or(Observes::Head, Observes::At),
            false,
        )? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = request.validate() {
            return Ok(Err(refusal));
        }
        self.query(cx, |db, book| {
            let head = db.frontier().map_err(KernelError::from)?;
            let at = request.through.unwrap_or(head);
            if at > head || request.since > at {
                return Ok(Err(super::invalid(
                    "access-log interval exceeds the selected book prefix",
                )));
            }
            crate::certificate::context_at(db, book, at)?;
            let mut events = super::log_at(db, book, request.since, at)?;
            events.retain(|event| request.selects(event));
            Ok(Ok(AccessLogReport {
                book_id: book.book_id,
                known_at: at,
                request: request.clone(),
                events,
            }))
        })
    }

    pub fn certify_access_log(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &AccessLogRequest,
    ) -> Outcome<CertifiedAccessLog> {
        if let Err(refusal) = authorize(
            self,
            cx,
            principal,
            capability,
            request.through.map_or(Observes::Head, Observes::At),
            true,
        )? {
            return Ok(Err(refusal));
        }
        let report = match self.read_access_log(cx, principal, capability, request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = match self.certify_trial_balance(
            cx,
            TrialBalanceSelection::AsOf(DateDay(i32::MAX)),
            Some(report.known_at),
        )? {
            Ok(source) => source.certificate,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let native = self.query(cx, |db, book| {
            db.execute_certified(
                &cx.query(),
                &statement(report.known_at),
                &GqlParameters::new(),
                book.symbols.clone(),
                policy(),
            )
            .map(|(_, certificate)| certificate)
            .map_err(BookError::CertifiedRead)
        })?;
        let capability_commitment = match capability.commitment() {
            Ok(commitment) => commitment,
            Err(error) => return Ok(Err(invalid(error.to_string()))),
        };
        let mut certificate = AccessLogCertificate {
            source,
            native,
            capability_commitment,
            output: match report.canonical_bytes() {
                Ok(bytes) => bytes,
                Err(refusal) => return Ok(Err(refusal)),
            },
            digest: [0; 32],
        };
        certificate.digest = match certificate.body_bytes() {
            Ok(body) => domain_digest(DIGEST_DOMAIN, &[&body]),
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(Ok(CertifiedAccessLog {
            report,
            certificate,
        }))
    }

    pub fn replay_access_log(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AccessLogCertificate,
    ) -> Outcome<AccessLogReport> {
        if let Err(refusal) = authorize(
            self,
            cx,
            principal,
            capability,
            Observes::At(certificate.source.known_at),
            false,
        )? {
            return Ok(Err(refusal));
        }
        if certificate.source.book_id != self.context().book_id {
            return Ok(Err(invalid(
                "access-log certificate belongs to another book",
            )));
        }
        if let Err(refusal) = certificate.canonical_bytes() {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = self.replay_trial_balance(cx, &certificate.source)? {
            return Ok(Err(refusal));
        }
        let original = match certificate.report() {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.query(cx, |db, book| {
            if let Err(error) = db.replay(
                &cx.query(),
                &certificate.native,
                &GqlParameters::new(),
                book.symbols.clone(),
                policy(),
            ) {
                return Ok(Err(invalid(format!(
                    "access-log population does not replay: {error}"
                ))));
            }
            let mut events = super::log_at(db, book, original.request.since, original.known_at)?;
            events.retain(|event| original.request.selects(event));
            if events != original.events {
                return Ok(Err(invalid(
                    "access-log rows differ from the certified historical selection",
                )));
            }
            Ok(Ok(original))
        })
    }

    /// Finite intervals stay Current after later access. An unbounded original
    /// request is Changed only when the same reader selection has later events.
    pub fn access_log_certificate_status(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &AccessLogCertificate,
    ) -> Outcome<AccessLogCertificateStatus> {
        if let Err(refusal) = authorize(self, cx, principal, capability, Observes::Head, false)? {
            return Ok(Err(refusal));
        }
        let original = match self.replay_access_log(cx, principal, capability, certificate)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let current = match self.read_access_log(cx, principal, capability, &original.request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let checked_at = self.head(cx)?;
        Ok(Ok(if original.events == current.events {
            AccessLogCertificateStatus::Current { checked_at }
        } else {
            AccessLogCertificateStatus::Changed { checked_at }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Book, BookKeys, Entropy};
    use fa_journal::BookSpec;
    use fa_money::UnitRegistry;
    use fa_time::FiscalCalendar;

    fn book() -> Book {
        Book::create_memory(
            BookKeys::for_development(0xac),
            BookSpec {
                book_id: Id128([0xac; 16]),
                name: "Access-log evidence".into(),
                base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
                calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            },
            Entropy::deterministic(172),
        )
        .unwrap()
    }

    fn capability() -> Capability {
        Capability::embedded(VId(7), &["read", "produce"]).unwrap()
    }

    fn record(book: &mut Book, reader: &str) -> RecordedAccess {
        book.record_access(&fa_model::AccessRecord {
            principal: principal_vid(reader),
            principal_name: reader.into(),
            capability_commitment: [4; 32],
            ops: vec!["read".into()],
            command: "tb".into(),
            request_digest: [5; 32],
        })
        .unwrap()
        .unwrap()
    }

    #[test]
    fn historical_access_log_replays_selected_rows_and_rejects_redigested_omissions() {
        let mut book = book();
        let first = record(&mut book, "auditor");
        record(&mut book, "other");
        let cap = capability();
        let request = AccessLogRequest {
            since: CommitSeq(0),
            through: Some(first.recorded_at),
            reader: None,
        };
        let certified = book
            .certify_access_log(VId(7), &cap, &request)
            .unwrap()
            .unwrap();
        assert_eq!(certified.report.events, vec![first]);
        assert_eq!(certified.report.known_at, request.through.unwrap());
        assert_eq!(
            *certified.certificate.capability_commitment(),
            cap.commitment().unwrap()
        );
        let bytes = certified.certificate.canonical_bytes().unwrap();
        let decoded = AccessLogCertificate::decode(&bytes).unwrap();
        let artifact = crate::ReportArtifact::decode(&bytes).unwrap();
        assert_eq!(artifact.family(), crate::ReportArtifactFamily::AccessLog);
        assert_eq!(
            book.replay_access_log(VId(7), &cap, &decoded)
                .unwrap()
                .unwrap(),
            certified.report
        );
        assert_eq!(
            book.replay_report_artifact(VId(7), &cap, &bytes, Some(decoded.digest()))
                .unwrap()
                .unwrap()
                .output,
            decoded.output()
        );

        // Repair the unkeyed envelope hash after dropping a real event. Local
        // framing alone accepts it; native historical reproduction must not.
        let mut forged = decoded.clone();
        let mut omitted = forged.report().unwrap();
        omitted.events.clear();
        forged.output = omitted.canonical_bytes().unwrap();
        forged.digest = domain_digest(DIGEST_DOMAIN, &[&forged.body_bytes().unwrap()]);
        let forged = AccessLogCertificate::decode(&forged.canonical_bytes().unwrap()).unwrap();
        let refusal = book
            .replay_access_log(VId(7), &cap, &forged)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::VERIFICATION);
        assert!(refusal.message.contains("rows differ"), "{refusal:?}");

        let mut corrupt = bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(AccessLogCertificate::decode(&corrupt).is_err());
        assert!(AccessLogCertificate::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn access_log_freshness_keeps_closed_intervals_fixed_and_compares_matching_readers() {
        let mut book = book();
        let first = record(&mut book, "auditor");
        let cap = capability();
        let request = AccessLogRequest {
            since: CommitSeq(0),
            through: None,
            reader: Some("auditor".into()),
        };
        let open = book
            .certify_access_log(VId(7), &cap, &request)
            .unwrap()
            .unwrap();
        let closed = book
            .certify_access_log(
                VId(7),
                &cap,
                &AccessLogRequest {
                    through: Some(first.recorded_at),
                    ..request.clone()
                },
            )
            .unwrap()
            .unwrap();
        record(&mut book, "other");
        assert!(matches!(
            book.access_log_certificate_status(VId(7), &cap, &open.certificate)
                .unwrap()
                .unwrap(),
            AccessLogCertificateStatus::Current { .. }
        ));
        record(&mut book, "auditor");
        assert!(matches!(
            book.access_log_certificate_status(VId(7), &cap, &open.certificate)
                .unwrap()
                .unwrap(),
            AccessLogCertificateStatus::Changed { .. }
        ));
        assert!(matches!(
            book.access_log_certificate_status(VId(7), &cap, &closed.certificate)
                .unwrap()
                .unwrap(),
            AccessLogCertificateStatus::Current { .. }
        ));
        assert_eq!(
            book.replay_access_log(VId(7), &cap, &open.certificate)
                .unwrap()
                .unwrap(),
            open.report
        );
    }

    #[test]
    fn access_log_authority_precedes_history_and_honors_an_explicit_recorded_pin() {
        let mut book = book();
        let first = record(&mut book, "auditor");
        record(&mut book, "later");
        let request = AccessLogRequest {
            since: CommitSeq(0),
            through: Some(first.recorded_at),
            reader: None,
        };
        let pinned = capability().known_at_most(first.recorded_at);
        let rows = book
            .read_access_log(VId(7), &pinned, &request)
            .unwrap()
            .unwrap();
        assert_eq!(rows.events, vec![first]);
        // Creating evidence without publishing metadata reaches only the
        // selected prefix; generic retained publication still reaches HEAD.
        assert_eq!(
            book.certify_access_log(VId(7), &pinned, &request)
                .unwrap()
                .unwrap()
                .report,
            rows
        );
        let refusal = book
            .read_access_log(
                VId(7),
                &pinned,
                &AccessLogRequest {
                    through: None,
                    ..request.clone()
                },
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::SAFETY);
        let no_read = Capability::embedded(VId(7), &["produce"]).unwrap();
        let refusal = book
            .read_access_log(
                VId(7),
                &no_read,
                &AccessLogRequest {
                    through: Some(CommitSeq(u64::MAX)),
                    ..request
                },
            )
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.exit, exit::SAFETY);
    }

    #[test]
    fn restoring_access_bytes_cannot_redate_a_receipt_but_original_history_still_replays() {
        use asupersync::Budget;
        use asupersync::runtime::RuntimeBuilder;
        use fa_journal::rows::{prop, scalar_bytes};
        use fa_model::symbols::{property, relation};
        use fgdb::{MemVfs, WriteBatch};

        let runtime = RuntimeBuilder::new().build().unwrap();
        let root = runtime.request_cx_with_budget(Budget::INFINITE);
        let cx = PurposeContexts::narrow_runtime_root(&root);
        let vfs = cx.commit().with_restriction(MemVfs::new).unwrap();
        let mut book = runtime
            .block_on(AsyncBook::create_with_vfs(
                &cx,
                vfs,
                std::path::Path::new("access-birth"),
                BookKeys::for_development(0xad),
                BookSpec {
                    book_id: Id128([0xad; 16]),
                    name: "Immutable access-log evidence".into(),
                    base_unit: UnitRegistry::embedded().unwrap().lookup("USD").unwrap(),
                    calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
                    time_zone_policy: None,
                    entities: Vec::new(),
                    opening_date: None,
                },
                Entropy::deterministic(173),
            ))
            .unwrap();
        let record = runtime
            .block_on(book.record_access(
                &cx,
                &fa_model::AccessRecord {
                    principal: principal_vid("auditor"),
                    principal_name: "auditor".into(),
                    capability_commitment: [4; 32],
                    ops: vec!["read".into()],
                    command: "tb".into(),
                    request_digest: [5; 32],
                },
            ))
            .unwrap()
            .unwrap();
        let cap = capability();
        let request = AccessLogRequest {
            since: CommitSeq(0),
            through: Some(record.recorded_at),
            reader: None,
        };
        let certified = book
            .certify_access_log(&cx, VId(7), &cap, &request)
            .unwrap()
            .unwrap();
        let row = book.db.vertex(record.vid).unwrap().unwrap();
        let original = prop(&row, property::FA_DIGEST).unwrap().clone();
        let mut damage = WriteBatch::new(relation::DERIVED_FROM);
        damage.set_vertex_property(
            record.vid,
            property::FA_DIGEST,
            Some(scalar_bytes("damaged access digest", vec![9; 32]).unwrap()),
        );
        runtime
            .block_on(book.db.write(&cx.commit(), damage))
            .unwrap();
        let mut restore = WriteBatch::new(relation::DERIVED_FROM);
        restore.set_vertex_property(record.vid, property::FA_DIGEST, Some(original));
        runtime
            .block_on(book.db.write(&cx.commit(), restore))
            .unwrap();

        let head_request = AccessLogRequest {
            through: None,
            ..request
        };
        assert!(
            book.read_access_log(&cx, VId(7), &cap, &head_request)
                .is_err()
        );
        assert!(
            book.certify_access_log(&cx, VId(7), &cap, &head_request)
                .is_err()
        );
        assert_eq!(
            book.replay_access_log(&cx, VId(7), &cap, &certified.certificate)
                .unwrap()
                .unwrap(),
            certified.report
        );
    }
}
