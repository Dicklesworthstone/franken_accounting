//! A retained comparison binds the complete journal/control closure and the
//! native source, review and unique-batch populations at one recorded prefix.
//! Decoding establishes container integrity only. Replay recomputes both gross
//! sides, original publication evidence and every emitted citation.

use asupersync::fs::Vfs;
use fa_journal::{BookContext, Refusal, exit};
use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::Capability;
use fa_time::DateDay;
use fgdb::{Database, NativeResultCertificate};
use fgdb_gql::{GqlParameters, GqlQueryPolicy};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::reconciliation::{OUTPUT, assemble, authorize, normalize};
use super::{ExternalFeedReconciliation, ExternalFeedRequest};
use crate::{
    AsyncBook, BookError, Outcome, ReportCertificate, ReportOutput, ReportSelection,
    TrialBalanceSelection,
};

mod status;
#[cfg(test)]
mod tests;

pub const EXTERNAL_FEED_CERTIFICATE_FORMAT: &[u8] = b"fa:external-feed-certificate:v1";
pub const MAX_EXTERNAL_FEED_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_NATIVE: usize = 1024 * 1024;
const INPUT_COUNT: usize = 4;
const DIGEST: &[u8] = b"fa:external-feed-certificate-digest:v1";
const REGISTRIES: &[(&str, &str)] = &[
    (
        "external_subledger",
        include_str!("../../../../registries/object_schemas/external_subledger.toml"),
    ),
    (
        "attestation",
        include_str!("../../../../registries/object_schemas/attestation.toml"),
    ),
    (
        "evidence_policy",
        include_str!("../../../../registries/evidence_policy.toml"),
    ),
    (
        "redaction_contracts",
        include_str!("../../../../registries/redaction_contracts.toml"),
    ),
];

#[derive(Clone, PartialEq, Eq)]
pub struct ExternalFeedCertificate {
    source: ReportCertificate,
    inputs: Vec<NativeResultCertificate>,
    request: ExternalFeedRequest,
    registry: [u8; 32],
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

impl core::fmt::Debug for ExternalFeedCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExternalFeedCertificate")
            .field("request", &self.request)
            .field("digest", &self.digest)
            .field("output_len", &self.output.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedExternalFeed {
    pub report: ExternalFeedReconciliation,
    pub certificate: ExternalFeedCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §5.6 / §13.6 (external detail, historical review and complete control effects must replay)",
        "retain the original book history and complete certificate; select the recipient's exact feed, control leaf, civil cutoff and recorded prefix",
    )
}

fn malformed(error: DecodeError) -> Refusal {
    invalid(format!("malformed external-feed certificate: {error}"))
}

fn bounded(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let size = parts
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or_else(|| invalid("external-feed encoding length overflow"))?;
    if size > MAX_EXTERNAL_FEED_CERTIFICATE_BYTES {
        return Err(invalid(
            "complete external-feed certificate exceeds 64 MiB; nothing was truncated",
        ));
    }
    Ok(size)
}

fn registry_digest() -> Result<[u8; 32], Refusal> {
    crate::certificate::canonical_closure(b"fa:external-feed-registry:v1", REGISTRIES)
}

fn policy() -> GqlQueryPolicy {
    GqlQueryPolicy::new(10_000_000, 1_000_000, 256 * 1024 * 1024, 256 * 1024 * 1024)
}

fn statements(at: CommitSeq) -> [String; INPUT_COUNT] {
    [
        // Workpapers only: unrelated protected document payloads are outside
        // this read closure, even when the caller can read accounting totals.
        format!(
            "MATCH (n:Document) FOR SYSTEM_TIME AS OF SEQ {} WHERE n.code = 'Workpaper' RETURN n,n._fa_payload,n._fa_digest,n.book_id,n.code ORDER BY n",
            at.0
        ),
        format!(
            "MATCH (n:Attestation) FOR SYSTEM_TIME AS OF SEQ {} RETURN n,n._fa_payload,n._fa_digest,n.book_id,n.code ORDER BY n",
            at.0
        ),
        format!(
            "MATCH (n:ExternalSubledgerBatch) FOR SYSTEM_TIME AS OF SEQ {} RETURN n,n._fa_payload,n._fa_digest,n.book_id,n.target_ref ORDER BY n",
            at.0
        ),
        format!(
            "MATCH (s)-[e:REVIEWED_BY]->(t) FOR SYSTEM_TIME AS OF SEQ {} RETURN s,e,t ORDER BY s,e,t",
            at.0
        ),
    ]
}

fn capture<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Result<Vec<NativeResultCertificate>, BookError> {
    let mut inputs = Vec::with_capacity(INPUT_COUNT);
    for statement in statements(at) {
        cx.query().checkpoint().map_err(BookError::Context)?;
        let (_, native) = db
            .execute_certified(
                &cx.query(),
                &statement,
                &GqlParameters::new(),
                book.symbols.clone(),
                policy(),
            )
            .map_err(BookError::CertifiedRead)?;
        inputs.push(native);
    }
    Ok(inputs)
}

impl ExternalFeedCertificate {
    #[must_use]
    pub fn source(&self) -> &ReportCertificate {
        &self.source
    }
    #[must_use]
    pub fn source_certificate(&self) -> &ReportCertificate {
        &self.source
    }
    #[must_use]
    pub fn supplemental_inputs(&self) -> &[NativeResultCertificate] {
        &self.inputs
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
    pub fn producer(&self) -> VId {
        self.producer
    }
    #[must_use]
    pub fn capability_commitment(&self) -> &[u8; 32] {
        &self.capability_commitment
    }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.source.known_at
    }
    #[must_use]
    pub fn book_id(&self) -> Id128 {
        self.source.book_id
    }

    pub fn request(&self) -> Result<ExternalFeedRequest, Refusal> {
        if self.request.known_at != Some(self.source.known_at)
            || self.source.branch_id != Id128::TRUNK
            || self.source.time_selection.is_some()
            || self.source.selection
                != ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(
                    self.request.effective_through,
                ))
        {
            return Err(invalid(
                "external-feed request and native control coordinates disagree",
            ));
        }
        normalize(&self.request, self.source.known_at).map_err(|r| invalid(r.message))
    }

    fn validate(&self) -> Result<(), Refusal> {
        self.request()?;
        let current = registry_digest()?;
        if self.registry != current {
            return Err(crate::certificate::registry_unavailable(
                "external-feed certificate",
                &self.registry,
                &current,
                REGISTRIES,
            ));
        }
        let basis = self
            .source
            .inputs
            .first()
            .ok_or_else(|| invalid("external-feed certificate has no native control source"))?;
        if self.inputs.len() != INPUT_COUNT {
            return Err(invalid(
                "external-feed certificate lacks its complete native source closure",
            ));
        }
        for (native, statement) in self.inputs.iter().zip(statements(self.known_at())) {
            if native.statement != statement
                || native.plan.snapshot_seq != self.known_at()
                || native.database_identity != basis.database_identity
                || native.snapshot_identity != basis.snapshot_identity
                || native.canonical_bytes().len() > MAX_NATIVE
            {
                return Err(invalid(
                    "external source input is not the required native population at the same snapshot",
                ));
            }
        }
        // The public output cannot advertise a question different from its
        // sources. Full row semantics are established only by native replay.
        let mut r = Reader::new(&self.output);
        if r.bytes(64, "external output format").map_err(malformed)? != OUTPUT
            || Id128(r.fixed("external output book").map_err(malformed)?) != self.source.book_id
            || CommitSeq(r.u64("external output prefix").map_err(malformed)?) != self.known_at()
            || r.str(64, "external output feed").map_err(malformed)? != self.request.feed
            || VId(r.u128("external output control").map_err(malformed)?)
                != self.request.control_account
            || DateDay(r.i32("external output cutoff").map_err(malformed)?)
                != self.request.effective_through
        {
            return Err(invalid(
                "external output header names another book, feed, account or coordinate",
            ));
        }
        Ok(())
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        bounded([self.output.len()])?;
        self.validate()?;
        let source = self
            .source
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        ReportCertificate::decode(&source)?;
        let natives: Vec<_> = self
            .inputs
            .iter()
            .map(NativeResultCertificate::canonical_bytes)
            .collect();
        let mut size = bounded([
            4,
            EXTERNAL_FEED_CERTIFICATE_FORMAT.len(),
            4,
            source.len(),
            4,
            4,
            self.request.feed.len(),
            16,
            4,
            8,
            32,
            16,
            32,
            4,
            self.output.len(),
            32,
        ])?;
        for native in &natives {
            size = bounded([size, 4, native.len()])?;
        }
        let mut w = Writer::with_capacity(size);
        w.bytes(EXTERNAL_FEED_CERTIFICATE_FORMAT)
            .bytes(&source)
            .list(&natives, |w, native| {
                w.bytes(native);
            })
            .str(&self.request.feed)
            .u128(self.request.control_account.0)
            .i32(self.request.effective_through.0)
            .u64(self.known_at().0)
            .fixed(&self.registry)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(
        source: ReportCertificate,
        inputs: Vec<NativeResultCertificate>,
        request: ExternalFeedRequest,
        principal: VId,
        capability: &Capability,
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut value = Self {
            source,
            inputs,
            request,
            registry: registry_digest()?,
            producer: principal,
            capability_commitment: capability
                .commitment()
                .map_err(|e| invalid(e.to_string()))?,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// This bounded unsigned container is not an independent accounting proof.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST, &[&body]) != self.digest {
            return Err(invalid("external-feed certificate digest mismatch"));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        bounded([bytes.len()])?;
        let mut r = Reader::new(bytes);
        if r.bytes(64, "external certificate format")
            .map_err(malformed)?
            != EXTERNAL_FEED_CERTIFICATE_FORMAT
        {
            return Err(invalid("unsupported external-feed certificate format"));
        }
        let source = ReportCertificate::decode(
            r.bytes(
                MAX_EXTERNAL_FEED_CERTIFICATE_BYTES,
                "external control source",
            )
            .map_err(malformed)?,
        )?;
        let count = r.u32("external source count").map_err(malformed)? as usize;
        if count != INPUT_COUNT {
            return Err(invalid("external-feed input closure count differs"));
        }
        let mut inputs = Vec::with_capacity(INPUT_COUNT);
        for _ in 0..INPUT_COUNT {
            inputs.push(
                NativeResultCertificate::decode(
                    r.bytes(MAX_NATIVE, "external native source")
                        .map_err(malformed)?,
                )
                .map_err(|e| invalid(format!("malformed external native source: {e}")))?,
            );
        }
        let request = ExternalFeedRequest {
            feed: r.str(64, "external feed").map_err(malformed)?.into(),
            control_account: VId(r.u128("external control").map_err(malformed)?),
            effective_through: DateDay(r.i32("external cutoff").map_err(malformed)?),
            known_at: Some(CommitSeq(r.u64("external prefix").map_err(malformed)?)),
        };
        let registry = r.fixed("external registries").map_err(malformed)?;
        let producer = VId(r.u128("external producer").map_err(malformed)?);
        let capability_commitment = r.fixed("external capability").map_err(malformed)?;
        let output = r
            .bytes(MAX_EXTERNAL_FEED_CERTIFICATE_BYTES, "external output")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed("external certificate digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            source,
            inputs,
            request,
            registry,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical external-feed certificate"));
        }
        Ok(value)
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Certify either agreement or a complete discrepancy. HEAD resolves once;
    /// no source or control effect is omitted to make the comparison reconcile.
    pub fn certify_external_feed(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &ExternalFeedRequest,
    ) -> Outcome<CertifiedExternalFeed> {
        let at = match authorize(self, cx, principal, capability, request.known_at, true)? {
            Ok(at) => at,
            Err(r) => return Ok(Err(r)),
        };
        let request = match normalize(request, at) {
            Ok(request) => request,
            Err(r) => return Ok(Err(r)),
        };
        self.query(cx, |db, book| {
            let source = match crate::certificate::certify_report(
                db,
                cx,
                book,
                TrialBalanceSelection::AsOf(request.effective_through).into(),
                Some(at),
            )? {
                Ok(source) => source,
                Err(r) => return Ok(Err(r)),
            };
            let ReportOutput::TrialBalance(control) = source.report else {
                return Ok(Err(invalid(
                    "external control source did not produce a trial balance",
                )));
            };
            let inputs = capture(db, cx, book, at)?;
            let report = match assemble(db, cx, book, &request, control)? {
                Ok(report) => report,
                Err(r) => return Ok(Err(r)),
            };
            let output = match report.canonical_bytes() {
                Ok(output) => output,
                Err(e) => return Ok(Err(invalid(e.to_string()))),
            };
            let certificate = match ExternalFeedCertificate::seal(
                source.certificate,
                inputs,
                request,
                principal,
                capability,
                output,
            ) {
                Ok(c) => c,
                Err(r) => return Ok(Err(r)),
            };
            Ok(Ok(CertifiedExternalFeed {
                report,
                certificate,
            }))
        })
    }

    /// Replay the original retained bytes for an independently fixed recipient
    /// question. A repaired checksum or newly generated equal total is not
    /// accepted as a replacement for the original native source certificates.
    pub fn replay_external_feed(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &ExternalFeedCertificate,
        expected: &ExternalFeedRequest,
    ) -> Outcome<ExternalFeedReconciliation> {
        if let Err(r) = authorize(self, cx, principal, capability, expected.known_at, false)? {
            return Ok(Err(r));
        }
        if expected.known_at.is_none() {
            return Ok(Err(invalid(
                "recipient external-feed expectations require a fixed known-at, not HEAD",
            )));
        }
        if let Err(r) = certificate.canonical_bytes() {
            return Ok(Err(r));
        }
        if expected != &certificate.request {
            return Ok(Err(invalid(
                "external-feed certificate answers a different recipient-selected question",
            )));
        }
        self.query(cx, |db, book| {
            let control =
                match crate::certificate::replay_report(db, cx, book, &certificate.source)? {
                    Ok(ReportOutput::TrialBalance(control)) => control,
                    Ok(_) => {
                        return Ok(Err(invalid(
                            "replayed external control is not a trial balance",
                        )));
                    }
                    Err(r) => return Ok(Err(r)),
                };
            for native in &certificate.inputs {
                cx.query().checkpoint().map_err(BookError::Context)?;
                if let Err(error) = db.replay(
                    &cx.query(),
                    native,
                    &GqlParameters::new(),
                    book.symbols.clone(),
                    policy(),
                ) {
                    return Ok(Err(invalid(format!(
                        "external native source does not replay: {error}"
                    ))));
                }
            }
            let report = match assemble(db, cx, book, expected, control)? {
                Ok(report) => report,
                Err(r) => return Ok(Err(invalid(r.message))),
            };
            let output = match report.canonical_bytes() {
                Ok(output) => output,
                Err(e) => return Ok(Err(invalid(e.to_string()))),
            };
            if output != certificate.output {
                return Ok(Err(invalid(
                    "replayed external detail/control comparison differs from the saved output",
                )));
            }
            Ok(Ok(report))
        })
    }
}
