//! Retained native AR/AP reconciliations bind the complete immutable journal,
//! independently selected control leaf and every posted/pending party column.
//! Container integrity is distinct from replay against the original book.

use asupersync::fs::Vfs;
use fa_journal::{Refusal, exit};
use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::{Capability, Op};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{NativeSubledgerReconciliation, NativeSubledgerSpec, admitted_at};
use crate::{AsyncBook, Outcome, ReportCertificate, ReportSelection, TrialBalanceSelection};

mod status;
#[cfg(test)]
mod tests;

pub const NATIVE_SUBLEDGER_CERTIFICATE_FORMAT: &[u8] = b"fa:native-subledger-certificate:v1";
pub const MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const DIGEST: &[u8] = b"fa:native-subledger-certificate-digest:v1";
const REGISTRIES: &[(&str, &str)] = &[
    (
        "control_payload",
        include_str!("../../../../registries/object_schemas/control_payload.toml"),
    ),
    (
        "entry_classes",
        include_str!("../../../../registries/entry_classes.toml"),
    ),
    (
        "symbols",
        include_str!("../../../../registries/symbols.toml"),
    ),
];

/// HEAD is accepted only by the producer. Replay requires a separately retained
/// recipient question with a fixed recorded prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeSubledgerRequest {
    pub code: String,
    pub control_account: VId,
    pub effective_through: DateDay,
    pub known_at: Option<CommitSeq>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct NativeSubledgerCertificate {
    source: ReportCertificate,
    request: NativeSubledgerRequest,
    registry: [u8; 32],
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

impl core::fmt::Debug for NativeSubledgerCertificate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeSubledgerCertificate")
            .field("request", &self.request)
            .field("digest", &self.digest)
            .field("output_len", &self.output.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedNativeSubledger {
    pub report: NativeSubledgerReconciliation,
    pub certificate: NativeSubledgerCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §5.6 / §13.6 (native party detail and independent control totals must replay)",
        "retain the original book and complete certificate; supply the recipient's exact subledger code, control leaf, civil cutoff and recorded prefix",
    )
}

fn malformed(error: DecodeError) -> Refusal {
    invalid(format!("malformed native-subledger certificate: {error}"))
}

fn bounded(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let size = parts
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .ok_or_else(|| invalid("native-subledger encoding length overflow"))?;
    if size > MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES {
        return Err(invalid(
            "complete native-subledger certificate exceeds 64 MiB; nothing was truncated",
        ));
    }
    Ok(size)
}

fn registry_digest() -> Result<[u8; 32], Refusal> {
    crate::certificate::canonical_closure(b"fa:native-subledger-registry:v1", REGISTRIES)
}

fn normalize(
    request: &NativeSubledgerRequest,
    at: CommitSeq,
) -> Result<NativeSubledgerRequest, Refusal> {
    if request.code.is_empty() || request.code.len() > 64 {
        return Err(invalid(
            "native subledger code must contain 1 through 64 bytes",
        ));
    }
    Ok(NativeSubledgerRequest {
        known_at: Some(at),
        ..request.clone()
    })
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    known_at: Option<CommitSeq>,
    produce: bool,
) -> Outcome<CommitSeq> {
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| {
            if produce {
                fa_policy::require(
                    capability,
                    Op::Produce,
                    "certifying a native subledger reconciliation",
                )
            } else {
                Ok(())
            }
        })
    {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    book.query(cx, |db, context| {
        admitted_at(db, context, capability, known_at)
    })
}

impl NativeSubledgerCertificate {
    #[must_use]
    pub fn source_certificate(&self) -> &ReportCertificate {
        &self.source
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

    pub fn request(&self) -> Result<NativeSubledgerRequest, Refusal> {
        if self.request.known_at != Some(self.known_at())
            || self.source.branch_id != Id128::TRUNK
            || self.source.time_selection.is_some()
            || self.source.selection
                != ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(
                    self.request.effective_through,
                ))
        {
            return Err(invalid(
                "native subledger and control source coordinates disagree",
            ));
        }
        normalize(&self.request, self.known_at())
    }

    fn validate(&self) -> Result<(), Refusal> {
        self.request()?;
        let current = registry_digest()?;
        if self.registry != current {
            return Err(crate::certificate::registry_unavailable(
                "native-subledger certificate",
                &self.registry,
                &current,
                REGISTRIES,
            ));
        }
        let Some(body) = self
            .output
            .strip_prefix(super::NATIVE_SUBLEDGER_REPORT_FORMAT.as_bytes())
        else {
            return Err(invalid("unsupported native subledger output format"));
        };
        let mut r = Reader::new(body);
        let vid = VId(r.u128("subledger identity").map_err(malformed)?);
        let spec =
            NativeSubledgerSpec::decode(r.bytes(1024, "subledger designation").map_err(malformed)?)
                .map_err(|error| invalid(error.to_string()))?;
        r.u128("subledger declaration").map_err(malformed)?;
        r.fixed::<32>("subledger declaration digest")
            .map_err(malformed)?;
        let declared_at = CommitSeq(r.u64("subledger declaration prefix").map_err(malformed)?);
        let known_at = CommitSeq(r.u64("subledger output prefix").map_err(malformed)?);
        let through = DateDay(r.i32("subledger output cutoff").map_err(malformed)?);
        if vid
            != fa_journal::subledger::native_subledger_vid(
                self.book_id(),
                self.request.control_account,
            )
            || spec.code != self.request.code
            || spec.control_account != self.request.control_account
            || declared_at > self.known_at()
            || known_at != self.known_at()
            || through != self.request.effective_through
        {
            return Err(invalid(
                "native subledger output answers a different accounting question",
            ));
        }
        // Complete rows and declaration/party controls are checked by replay.
        Ok(())
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        bounded([self.output.len()])?;
        self.validate()?;
        let source = self
            .source
            .canonical_bytes()
            .map_err(|error| invalid(error.to_string()))?;
        ReportCertificate::decode(&source)?;
        let size = bounded([
            4,
            NATIVE_SUBLEDGER_CERTIFICATE_FORMAT.len(),
            4,
            source.len(),
            4,
            self.request.code.len(),
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
        let mut w = Writer::with_capacity(size);
        w.bytes(NATIVE_SUBLEDGER_CERTIFICATE_FORMAT)
            .bytes(&source)
            .str(&self.request.code)
            .u128(self.request.control_account.0)
            .i32(self.request.effective_through.0)
            .u64(self.known_at().0)
            .fixed(&self.registry)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&self.output);
        w.finish().map_err(|error| invalid(error.to_string()))
    }

    fn seal(
        source: ReportCertificate,
        request: NativeSubledgerRequest,
        principal: VId,
        capability: &Capability,
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut value = Self {
            source,
            request,
            registry: registry_digest()?,
            producer: principal,
            capability_commitment: capability
                .commitment()
                .map_err(|error| invalid(error.to_string()))?,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// A bounded unsigned container; integrity alone is not an accounting proof.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST, &[&body]) != self.digest {
            return Err(invalid("native-subledger certificate digest mismatch"));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        bounded([bytes.len()])?;
        let mut r = Reader::new(bytes);
        if r.bytes(64, "native subledger certificate format")
            .map_err(malformed)?
            != NATIVE_SUBLEDGER_CERTIFICATE_FORMAT
        {
            return Err(invalid("unsupported native-subledger certificate format"));
        }
        let source = ReportCertificate::decode(
            r.bytes(
                MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES,
                "native control source",
            )
            .map_err(malformed)?,
        )?;
        let request = NativeSubledgerRequest {
            code: r.str(64, "subledger code").map_err(malformed)?.into(),
            control_account: VId(r.u128("subledger control").map_err(malformed)?),
            effective_through: DateDay(r.i32("subledger cutoff").map_err(malformed)?),
            known_at: Some(CommitSeq(r.u64("subledger prefix").map_err(malformed)?)),
        };
        let registry = r.fixed("subledger registries").map_err(malformed)?;
        let producer = VId(r.u128("subledger producer").map_err(malformed)?);
        let capability_commitment = r.fixed("subledger capability").map_err(malformed)?;
        let output = r
            .bytes(MAX_NATIVE_SUBLEDGER_CERTIFICATE_BYTES, "subledger output")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed("subledger certificate digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            source,
            request,
            registry,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical native-subledger certificate"));
        }
        Ok(value)
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Bind immutable designations, complete party detail and the independently
    /// folded control balance at one prefix. No second posting universe is added.
    pub fn certify_native_subledger(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &NativeSubledgerRequest,
    ) -> Outcome<CertifiedNativeSubledger> {
        let at = match authorize(self, cx, principal, capability, request.known_at, true)? {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let request = match normalize(request, at) {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let source = match self.query(cx, |db, book| {
            crate::certificate::certify_report(
                db,
                cx,
                book,
                TrialBalanceSelection::AsOf(request.effective_through).into(),
                Some(at),
            )
        })? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // The complete Entry source includes Subledger and REA/Party controls.
        // The detail fold reconstructs them and validates their graph mirrors
        // at the same immutable prefix.
        let report = match self.reconcile_native_subledger(
            cx,
            &request.code,
            request.effective_through,
            Some(at),
            capability,
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if report.subledger.spec.control_account != request.control_account {
            return Ok(Err(invalid(
                "the selected subledger does not designate the requested control leaf",
            )));
        }
        let output = match report.canonical_bytes() {
            Ok(output) => output,
            Err(error) => return Ok(Err(invalid(error.to_string()))),
        };
        let certificate = match NativeSubledgerCertificate::seal(
            source.certificate,
            request,
            principal,
            capability,
            output,
        ) {
            Ok(certificate) => certificate,
            Err(refusal) => return Ok(Err(refusal)),
        };
        Ok(Ok(CertifiedNativeSubledger {
            report,
            certificate,
        }))
    }

    /// Replay original native sources and every party column for an independently
    /// selected fixed question. Repaired checksums cannot waive current authority.
    pub fn replay_native_subledger(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &NativeSubledgerCertificate,
        expected: &NativeSubledgerRequest,
    ) -> Outcome<NativeSubledgerReconciliation> {
        if let Err(refusal) = authorize(self, cx, principal, capability, expected.known_at, false)?
        {
            return Ok(Err(refusal));
        }
        if expected.known_at.is_none() {
            return Ok(Err(invalid(
                "native subledger replay requires a fixed known-at, not HEAD",
            )));
        }
        if let Err(refusal) = certificate.canonical_bytes() {
            return Ok(Err(refusal));
        }
        if expected != &certificate.request {
            return Ok(Err(invalid(
                "native-subledger certificate answers a different recipient question",
            )));
        }
        if let Err(refusal) = self.query(cx, |db, book| {
            crate::certificate::replay_report(db, cx, book, &certificate.source)
        })? {
            return Ok(Err(refusal));
        }
        let report = match self.reconcile_native_subledger(
            cx,
            &expected.code,
            expected.effective_through,
            expected.known_at,
            capability,
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(invalid(refusal.message))),
        };
        let output = match report.canonical_bytes() {
            Ok(output) => output,
            Err(error) => return Ok(Err(invalid(error.to_string()))),
        };
        if output != certificate.output {
            return Ok(Err(invalid(
                "replayed native subledger detail/control output differs from retained bytes",
            )));
        }
        Ok(Ok(report))
    }
}
