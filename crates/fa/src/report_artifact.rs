//! One bounded decoder and current-authority replay entrypoint for retained-history
//! report artifacts. The original family encodings, digests and replay laws are
//! unchanged; this is dispatch, not another accounting fold or certificate format.
//!
//! Decoding establishes content integrity only. Replay checks the original book
//! through each family's existing implementation. Neither a saved producer nor a
//! capability commitment supplies authority to this caller. All currently supported
//! families contain whole-book native inputs and require whole-book read authority.
//! No signature, outsider completeness, freshness or economic-truth claim follows
//! from decoding or from the local retained-history replay receipt. Explicit
//! retention replays the complete family before publishing its immutable bytes.

mod retention;
mod status;
pub(crate) use retention::ValidatedArtifact;

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::{Id128, Reader};
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::aging::portfolio::{AgingPortfolioCertificate, AgingPortfolioRequest};
use crate::cash_flow_policy::{CashFlowPolicy, CashFlowPolicyCertificate};
use crate::cash_flow_split::{CashFlowSplitCertificate, CashFlowSplitDefinition};
use crate::{
    AgingCertificate, AgingReconciliationCertificate, AgingReconciliationRequest, AsyncBook,
    BookError, CashFlowCertificate, CashFlowDefinition, IndirectCashFlowCertificate,
    IndirectCashFlowRequest, Outcome, ReportCertificate, RollForwardCertificate,
    RollForwardRequest, StatementDiffCertificate, StatementTraceCertificate, SummaryCertificate,
};

/// Total encoded input bound, including the complete nested native closure.
pub const MAX_REPORT_ARTIFACT_BYTES: usize = crate::certificate::MAX_CERTIFICATE_BYTES;

/// A dispatch label, not a new durable discriminant or a verification grade.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportArtifactFamily {
    Native,
    Summary,
    EffectiveDateAging,
    RollForward,
    CashFlow,
    IndirectCashFlow,
    AgingReconciliation,
    Procedure,
    StatementDiff,
    StatementTrace,
    AgingPortfolio,
    SplitCashFlow,
    PolicyCashFlow,
    /// A scenario diff (fa-k07b). Its replay re-materializes the scenario,
    /// which only the sync facade can do: [`crate::Book::replay_scenario_diff`]
    /// and [`crate::Book::retain_scenario_diff`].
    ScenarioDiff,
    /// Existing-draft atomic rehearsal, replayed in full by the sync facade.
    DraftDiff,
}

impl ReportArtifactFamily {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Procedure => "procedure",
            Self::Native => "native",
            Self::Summary => "summary",
            Self::EffectiveDateAging => "effective-date-aging",
            Self::RollForward => "roll-forward",
            Self::CashFlow => "cash-flow",
            Self::IndirectCashFlow => "indirect-cash-flow",
            Self::AgingReconciliation => "aging-reconciliation",
            Self::StatementDiff => "statement-diff",
            Self::StatementTrace => "statement-trace",
            Self::AgingPortfolio => "aging-portfolio",
            Self::SplitCashFlow => "split-cash-flow",
            Self::PolicyCashFlow => "policy-cash-flow",
            Self::ScenarioDiff => "scenario-diff",
            Self::DraftDiff => "draft-diff",
        }
    }
}

/// Independently retained recipient expectations, never decoded from a delivery.
/// Cash-flow families require their fixed scope and accounting definitions;
/// neither an optional digest nor AsSupplied substitutes for those requirements.
#[derive(Clone, Copy, Debug)]
pub enum ReportArtifactExpectation<'a> {
    /// Local replay for native, summary, aging, roll-forward, procedure,
    /// statement-diff and statement-trace artifacts.
    /// This does not certify that the artifact answers a separate request.
    AsSupplied,
    CashFlow {
        request: &'a RollForwardRequest,
        definition: &'a CashFlowDefinition,
    },
    IndirectCashFlow(&'a IndirectCashFlowRequest),
    AgingReconciliation(&'a AgingReconciliationRequest),
    AgingPortfolio(&'a AgingPortfolioRequest),
    SplitCashFlow {
        request: &'a RollForwardRequest,
        definition: &'a CashFlowSplitDefinition,
    },
    PolicyCashFlow {
        request: &'a RollForwardRequest,
        policy: &'a CashFlowPolicy,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Artifact {
    Procedure(Box<crate::procedure_certificate::ProcedureCertificate>),
    Native(Box<ReportCertificate>),
    Summary(Box<SummaryCertificate>),
    Aging(Box<AgingCertificate>),
    RollForward(Box<RollForwardCertificate>),
    CashFlow(Box<CashFlowCertificate>),
    IndirectCashFlow(Box<IndirectCashFlowCertificate>),
    AgingReconciliation(Box<AgingReconciliationCertificate>),
    StatementDiff(Box<StatementDiffCertificate>),
    StatementTrace(Box<StatementTraceCertificate>),
    AgingPortfolio(Box<AgingPortfolioCertificate>),
    SplitCashFlow(Box<CashFlowSplitCertificate>),
    PolicyCashFlow(Box<PolicyArtifact>),
    ScenarioDiff(Box<crate::ScenarioDiffCertificate>),
    DraftDiff(Box<crate::DraftDiffCertificate>),
}

// Policy certificates retain their exact financial source and derivation inputs.
// Cache their complete canonical report on decode so output() also includes the
// policy and decision transcript, without changing the original durable format.
#[derive(Clone, Debug, PartialEq, Eq)]
struct PolicyArtifact {
    certificate: CashFlowPolicyCertificate,
    output: Vec<u8>,
}

/// An intact canonical artifact, NOT a successful replay. Private variants keep
/// hand-modified ReportCertificate fields from bypassing the family decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportArtifact {
    inner: Artifact,
}

/// Exact output returned only after the selected family's full historical replay.
/// The digest is the original family digest, not a digest of a replacement wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayedReportArtifact {
    pub family: ReportArtifactFamily,
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub certificate_digest: [u8; 32],
    pub output: Vec<u8>,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §13.6; fa-oimc (family-specific canonical bytes and retained-history replay)",
        "supply the complete supported report certificate from its original book; retain the independently expected digest when checking a delivered artifact",
    )
}

/// A recipient-dependent family replayed without its request names how to
/// supply one, instead of suggesting the certificate itself is damaged.
fn expectation_required(family: ReportArtifactFamily) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        format!(
            "{} report certificates replay only against an independently supplied request and policy; none was supplied",
            family.name()
        ),
        "plan §13.6; fa-oimc (family-specific canonical bytes and retained-history replay)",
        "pass the request retained apart from the delivered certificate when it was certified: fa replay C:<oid> --expect '<JSON>' (the report_certificate event's replay_command), or the family's ReportArtifactExpectation",
    )
}

impl ReportArtifact {
    /// Select EXACTLY one decoder from a bounded, borrowed format field. Unknown
    /// versions are refused; a failed decoder is never retried as another family.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_REPORT_ARTIFACT_BYTES {
            return Err(invalid("report artifact exceeds the 64 MiB total limit"));
        }
        if bytes.starts_with(b"fa:report-certificate:v") {
            return Ok(Self {
                inner: Artifact::Native(Box::new(ReportCertificate::decode(bytes)?)),
            });
        }
        let mut reader = Reader::new(bytes);
        let format = reader
            .bytes(64, "report artifact format")
            .map_err(|error| invalid(format!("malformed report artifact: {error}")))?;
        let inner = if format == crate::procedure_certificate::PROCEDURE_CERTIFICATE_FORMAT
            || format == crate::procedure_certificate::EXTENDED_PROCEDURE_CERTIFICATE_FORMAT
            || format == crate::procedure_certificate::BANK_PROCEDURE_CERTIFICATE_FORMAT
        {
            Artifact::Procedure(Box::new(
                crate::procedure_certificate::ProcedureCertificate::decode(bytes)?,
            ))
        } else if format == crate::summary_certificate::CERTIFICATE_FORMAT {
            Artifact::Summary(Box::new(SummaryCertificate::decode(bytes)?))
        } else if format == crate::AGING_CERTIFICATE_FORMAT {
            Artifact::Aging(Box::new(AgingCertificate::decode(bytes)?))
        } else if format == crate::ROLL_FORWARD_CERTIFICATE_FORMAT {
            Artifact::RollForward(Box::new(RollForwardCertificate::decode(bytes)?))
        } else if format == crate::CASH_FLOW_CERTIFICATE_FORMAT {
            Artifact::CashFlow(Box::new(CashFlowCertificate::decode(bytes)?))
        } else if format == crate::INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT {
            Artifact::IndirectCashFlow(Box::new(IndirectCashFlowCertificate::decode(bytes)?))
        } else if format == crate::aging::AGING_RECONCILIATION_CERTIFICATE_FORMAT {
            Artifact::AgingReconciliation(Box::new(AgingReconciliationCertificate::decode(bytes)?))
        } else if format == crate::statement_diff::CERTIFICATE_FORMAT {
            Artifact::StatementDiff(Box::new(StatementDiffCertificate::decode(bytes)?))
        } else if format == crate::statement_trace::CERTIFICATE_FORMAT {
            Artifact::StatementTrace(Box::new(StatementTraceCertificate::decode(bytes)?))
        } else if format == crate::aging::portfolio::CERTIFICATE_FORMAT {
            Artifact::AgingPortfolio(Box::new(AgingPortfolioCertificate::decode(bytes)?))
        } else if format == crate::cash_flow_split::CASH_FLOW_SPLIT_CERTIFICATE_FORMAT.as_bytes() {
            Artifact::SplitCashFlow(Box::new(CashFlowSplitCertificate::decode(bytes)?))
        } else if format == crate::SCENARIO_DIFF_CERTIFICATE_FORMAT
            || format == crate::LEGACY_SCENARIO_DIFF_CERTIFICATE_FORMAT
        {
            Artifact::ScenarioDiff(Box::new(crate::ScenarioDiffCertificate::decode(bytes)?))
        } else if format == crate::DRAFT_DIFF_CERTIFICATE_FORMAT {
            Artifact::DraftDiff(Box::new(crate::DraftDiffCertificate::decode(bytes)?))
        } else if format == crate::cash_flow_policy::CASH_FLOW_POLICY_CERTIFICATE_FORMAT {
            let certificate = CashFlowPolicyCertificate::decode(bytes)?;
            let output = certificate.output()?;
            Artifact::PolicyCashFlow(Box::new(PolicyArtifact {
                certificate,
                output,
            }))
        } else {
            return Err(invalid("unsupported report artifact family or version"));
        };
        Ok(Self { inner })
    }

    #[must_use]
    pub fn family(&self) -> ReportArtifactFamily {
        match &self.inner {
            Artifact::Procedure(_) => ReportArtifactFamily::Procedure,
            Artifact::Native(_) => ReportArtifactFamily::Native,
            Artifact::Summary(_) => ReportArtifactFamily::Summary,
            Artifact::Aging(_) => ReportArtifactFamily::EffectiveDateAging,
            Artifact::RollForward(_) => ReportArtifactFamily::RollForward,
            Artifact::CashFlow(_) => ReportArtifactFamily::CashFlow,
            Artifact::IndirectCashFlow(_) => ReportArtifactFamily::IndirectCashFlow,
            Artifact::AgingReconciliation(_) => ReportArtifactFamily::AgingReconciliation,
            Artifact::StatementDiff(_) => ReportArtifactFamily::StatementDiff,
            Artifact::StatementTrace(_) => ReportArtifactFamily::StatementTrace,
            Artifact::AgingPortfolio(_) => ReportArtifactFamily::AgingPortfolio,
            Artifact::SplitCashFlow(_) => ReportArtifactFamily::SplitCashFlow,
            Artifact::PolicyCashFlow(_) => ReportArtifactFamily::PolicyCashFlow,
            Artifact::ScenarioDiff(_) => ReportArtifactFamily::ScenarioDiff,
            Artifact::DraftDiff(_) => ReportArtifactFamily::DraftDiff,
        }
    }

    /// Inspect the source immutably. A nested source is not interchangeable with
    /// its outer certificate: it omits the outer selector and exact derived output.
    /// Comparisons and traces expose their final source here; replay still checks
    /// both endpoints or every publication, respectively. This accessor alone
    /// does not define a family's complete scope or freshness.
    #[must_use]
    pub fn source_certificate(&self) -> &ReportCertificate {
        match &self.inner {
            Artifact::Procedure(c) => c.source_certificate(),
            Artifact::Native(c) => c,
            Artifact::Summary(c) => c.source_certificate(),
            Artifact::Aging(c) => c.source(),
            Artifact::RollForward(c) => c.source_certificate(),
            Artifact::CashFlow(c) => c.source_certificate().source_certificate(),
            Artifact::IndirectCashFlow(c) => c
                .source_certificate()
                .source_certificate()
                .source_certificate(),
            Artifact::AgingReconciliation(c) => c.aging_source().source(),
            Artifact::StatementDiff(c) => c.sources().1,
            // The bounded family decoder requires a nonempty contiguous chain.
            Artifact::StatementTrace(c) => &c.sources()[c.sources().len() - 1],
            Artifact::AgingPortfolio(c) => c.control_source(),
            Artifact::SplitCashFlow(c) => c.source_certificate().source_certificate(),
            Artifact::PolicyCashFlow(c) => c
                .certificate
                .source_certificate()
                .source_certificate()
                .source_certificate(),
            // The trunk side; the scenario side has no native certificate.
            Artifact::ScenarioDiff(c) => c.trunk(),
            Artifact::DraftDiff(c) => c.trunk(),
        }
    }

    #[must_use]
    pub fn book_id(&self) -> Id128 {
        self.source_certificate().book_id
    }

    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.source_certificate().known_at
    }

    /// A bridge's displayed coordinate is its terminal source. Hydration must
    /// reach the earliest source it will replay, including when the terminal
    /// source equals HEAD and would otherwise need no historical preparation.
    fn earliest_source_known_at(&self) -> Result<CommitSeq, Refusal> {
        match &self.inner {
            Artifact::StatementDiff(certificate) => {
                let (before, after) = certificate.sources();
                Ok(before.known_at.min(after.known_at))
            }
            Artifact::StatementTrace(certificate) => certificate
                .sources()
                .iter()
                .map(|source| source.known_at)
                .min()
                .ok_or_else(|| invalid("a statement trace has no source prefix")),
            _ => Ok(self.known_at()),
        }
    }

    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        match &self.inner {
            Artifact::Procedure(c) => c.digest(),
            Artifact::Native(c) => &c.digest,
            Artifact::Summary(c) => c.digest(),
            Artifact::Aging(c) => c.digest(),
            Artifact::RollForward(c) => c.digest(),
            Artifact::CashFlow(c) => c.digest(),
            Artifact::IndirectCashFlow(c) => c.digest(),
            Artifact::AgingReconciliation(c) => c.digest(),
            Artifact::StatementDiff(c) => c.digest(),
            Artifact::StatementTrace(c) => c.digest(),
            Artifact::AgingPortfolio(c) => c.digest(),
            Artifact::SplitCashFlow(c) => c.digest(),
            Artifact::PolicyCashFlow(c) => c.certificate.digest(),
            Artifact::ScenarioDiff(c) => c.digest(),
            Artifact::DraftDiff(c) => c.digest(),
        }
    }

    /// Original family output, not accepted as a historical result until replay.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        match &self.inner {
            Artifact::Procedure(c) => c.output(),
            Artifact::Native(c) => &c.output,
            Artifact::Summary(c) => c.output(),
            Artifact::Aging(c) => c.output(),
            Artifact::RollForward(c) => c.output(),
            Artifact::CashFlow(c) => c.output(),
            Artifact::IndirectCashFlow(c) => c.output(),
            Artifact::AgingReconciliation(c) => c.output(),
            Artifact::StatementDiff(c) => c.output(),
            Artifact::StatementTrace(c) => c.output(),
            Artifact::AgingPortfolio(c) => c.output(),
            Artifact::SplitCashFlow(c) => c.output(),
            Artifact::PolicyCashFlow(c) => &c.output,
            Artifact::ScenarioDiff(c) => c.output(),
            Artifact::DraftDiff(c) => c.output(),
        }
    }

    /// Digest of the complete canonical output using the native report recipe.
    /// This is content identity only; replay must still establish the result.
    #[must_use]
    pub fn output_digest(&self) -> [u8; 32] {
        let mut hash = fgdb_crypto::Hasher::new();
        hash.update(b"fa:report-output:v1");
        hash.update(self.output());
        hash.finalize().0
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        match &self.inner {
            Artifact::Procedure(c) => c.canonical_bytes(),
            Artifact::Native(c) => c.canonical_bytes().map_err(|e| invalid(e.to_string())),
            Artifact::Summary(c) => c.canonical_bytes(),
            Artifact::Aging(c) => c.canonical_bytes(),
            Artifact::RollForward(c) => c.canonical_bytes(),
            Artifact::CashFlow(c) => c.canonical_bytes(),
            Artifact::IndirectCashFlow(c) => c.canonical_bytes(),
            Artifact::AgingReconciliation(c) => c.canonical_bytes(),
            Artifact::StatementDiff(c) => c.canonical_bytes(),
            Artifact::StatementTrace(c) => c.canonical_bytes(),
            Artifact::AgingPortfolio(c) => c.canonical_bytes(),
            Artifact::SplitCashFlow(c) => c.canonical_bytes(),
            Artifact::PolicyCashFlow(c) => c.certificate.canonical_bytes(),
            Artifact::ScenarioDiff(c) => c.canonical_bytes(),
            Artifact::DraftDiff(c) => c.canonical_bytes(),
        }
    }
}

// Typed entrypoints still validate the complete family encoding. In particular,
// ReportCertificate has public fields and its encoder alone is not validation.
macro_rules! from_certificate {
    ($($ty:ty),+ $(,)?) => {$(
        impl TryFrom<&$ty> for ReportArtifact {
            type Error = Refusal;
            fn try_from(certificate: &$ty) -> Result<Self, Self::Error> {
                let bytes = certificate.canonical_bytes().map_err(|e| invalid(e.to_string()))?;
                Self::decode(&bytes)
            }
        }
    )+};
}
from_certificate!(
    crate::procedure_certificate::ProcedureCertificate,
    ReportCertificate,
    SummaryCertificate,
    AgingCertificate,
    RollForwardCertificate,
    CashFlowCertificate,
    IndirectCashFlowCertificate,
    AgingReconciliationCertificate,
    StatementDiffCertificate,
    StatementTraceCertificate,
    AgingPortfolioCertificate,
    CashFlowSplitCertificate,
    CashFlowPolicyCertificate,
    crate::ScenarioDiffCertificate,
    crate::DraftDiffCertificate,
);

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
) -> Outcome<()> {
    if let Err(denial) = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| fa_policy::reach(capability, &fa_policy::Reach::whole_book(true), None))
    {
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
    /// Replay canonical bytes under CURRENT caller authority. Admission happens
    /// before decoding even malformed input. An expected digest, when supplied,
    /// must be selected independently of the delivered bytes; matching it does
    /// not bypass replay. None requests local replay of the artifact as supplied,
    /// not verification that it answers a separately specified business scope.
    /// Cash-flow families require replay_report_artifact_for with independently
    /// supplied expectations; this convenience method refuses those families.
    /// This method publishes nothing and never replaces known-at with HEAD.
    pub fn replay_report_artifact(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
        expected_digest: Option<&[u8; 32]>,
    ) -> Outcome<ReplayedReportArtifact> {
        self.replay_report_artifact_for(
            cx,
            principal,
            capability,
            bytes,
            expected_digest,
            ReportArtifactExpectation::AsSupplied,
        )
    }

    /// Prepare a retained procedure's native inputs without granting scope from
    /// its saved producer. Reading the artifact identity requires current Read;
    /// bank history is loaded only after current Reconcile admission as well.
    pub async fn prepare_retained_procedure_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        digest: &[u8; 32],
    ) -> Outcome<()> {
        let artifact = match self
            .read_report_artifact(cx, principal, capability, digest)
            .await?
        {
            Ok(artifact) => artifact,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Artifact::Procedure(certificate) = &artifact.inner {
            if let Err(refusal) = self
                .prepare_procedure_history(
                    cx,
                    principal,
                    capability,
                    &certificate.report().procedure,
                    false,
                )
                .await?
            {
                return Ok(Err(refusal));
            }
            return self
                .prepare_report_history(cx, principal, capability, Some(certificate.known_at()))
                .await;
        }
        Ok(Ok(()))
    }

    /// Replay a complete artifact from a cold book after current admission and
    /// authenticated history hydration. The synchronous entrypoint still
    /// requires resident history; it never substitutes a partial input set.
    #[allow(clippy::too_many_arguments)]
    pub async fn replay_report_artifact_for_with_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
        expected_digest: Option<&[u8; 32]>,
        expected: ReportArtifactExpectation<'_>,
    ) -> Outcome<ReplayedReportArtifact> {
        if let Err(refusal) = authorize(self, cx, principal, capability)? {
            return Ok(Err(refusal));
        }
        let artifact = match ReportArtifact::decode(bytes) {
            Ok(artifact) => artifact,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if artifact.book_id() != self.context().book_id {
            return Ok(Err(invalid("report artifact belongs to another book")));
        }
        if expected_digest.is_some_and(|expected| expected != artifact.digest()) {
            return Ok(Err(invalid(
                "report artifact differs from the independently expected digest",
            )));
        }
        if let Artifact::Procedure(certificate) = &artifact.inner
            && let Err(refusal) = self
                .prepare_procedure_history(
                    cx,
                    principal,
                    capability,
                    &certificate.report().procedure,
                    false,
                )
                .await?
        {
            return Ok(Err(refusal));
        }
        let earliest = match artifact.earliest_source_known_at() {
            Ok(at) => at,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = self
            .prepare_report_history(cx, principal, capability, Some(earliest))
            .await?
        {
            return Ok(Err(refusal));
        }
        self.replay_report_artifact_for(cx, principal, capability, bytes, expected_digest, expected)
    }

    /// The same bounded dispatch with independent expected scope/definitions.
    /// Expectations must name the delivered family and preserve its existing
    /// fixed-prefix requirements. A matching artifact digest cannot waive scope
    /// checks. No request, classification or adjustment is taken from the artifact.
    pub fn replay_report_artifact_for(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
        expected_digest: Option<&[u8; 32]>,
        expected: ReportArtifactExpectation<'_>,
    ) -> Outcome<ReplayedReportArtifact> {
        if let Err(refusal) = authorize(self, cx, principal, capability)? {
            return Ok(Err(refusal));
        }
        let artifact = match ReportArtifact::decode(bytes) {
            Ok(artifact) => artifact,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if artifact.book_id() != self.context().book_id {
            return Ok(Err(invalid("report artifact belongs to another book")));
        }
        if expected_digest.is_some_and(|expected| expected != artifact.digest()) {
            return Ok(Err(invalid(
                "report artifact differs from the independently expected digest",
            )));
        }
        let replayed = match (&artifact.inner, expected) {
            (Artifact::Procedure(c), ReportArtifactExpectation::AsSupplied) => self
                .replay_procedure(cx, principal, capability, c)?
                .map(|_| ()),
            (Artifact::Native(c), ReportArtifactExpectation::AsSupplied) => {
                self.replay_report(cx, c)?.map(|_| ())
            }
            (Artifact::Summary(c), ReportArtifactExpectation::AsSupplied) => self
                .replay_summary_trial_balance(cx, principal, capability, c)?
                .map(|_| ()),
            (Artifact::Aging(c), ReportArtifactExpectation::AsSupplied) => self
                .replay_effective_date_aging(cx, principal, capability, c)?
                .map(|_| ()),
            (Artifact::RollForward(c), ReportArtifactExpectation::AsSupplied) => self
                .replay_roll_forward(cx, principal, capability, c)?
                .map(|_| ()),
            (Artifact::StatementDiff(c), ReportArtifactExpectation::AsSupplied) => self
                .replay_statement_diff(cx, principal, capability, c)?
                .map(|_| ()),
            (Artifact::StatementTrace(c), ReportArtifactExpectation::AsSupplied) => self
                .replay_statement_trace(cx, principal, capability, c)?
                .map(|_| ()),
            (
                Artifact::CashFlow(c),
                ReportArtifactExpectation::CashFlow {
                    request,
                    definition,
                },
            ) => self
                .replay_cash_flow(cx, principal, capability, c, request, definition)?
                .map(|_| ()),
            (
                Artifact::IndirectCashFlow(c),
                ReportArtifactExpectation::IndirectCashFlow(request),
            ) => self
                .replay_indirect_cash_flow(cx, principal, capability, c, request)?
                .map(|_| ()),
            (
                Artifact::AgingReconciliation(c),
                ReportArtifactExpectation::AgingReconciliation(request),
            ) => self
                .replay_effective_date_aging_reconciliation(cx, principal, capability, c, request)?
                .map(|_| ()),
            (Artifact::AgingPortfolio(c), ReportArtifactExpectation::AgingPortfolio(request)) => {
                self.replay_aging_portfolio(cx, principal, capability, c, request)?
                    .map(|_| ())
            }
            (
                Artifact::SplitCashFlow(c),
                ReportArtifactExpectation::SplitCashFlow {
                    request,
                    definition,
                },
            ) => self
                .replay_split_cash_flow(cx, principal, capability, c, request, definition)?
                .map(|_| ()),
            (
                Artifact::PolicyCashFlow(c),
                ReportArtifactExpectation::PolicyCashFlow { request, policy },
            ) => self
                .replay_cash_flow_with_policy(
                    cx,
                    principal,
                    capability,
                    &c.certificate,
                    request,
                    policy,
                )?
                .map(|_| ()),
            (Artifact::ScenarioDiff(_), _) => {
                return Ok(Err(Refusal::new(
                    crate::certificate::code::CERTIFICATE_INVALID,
                    exit::VERIFICATION,
                    "a scenario diff certificate is replayed by re-materializing its scenario, which this replay cannot do",
                    "plan §15.2 (a scenario diff replays from its trunk certificate and its pinned intents)",
                    "replay it with fa replay (Book::replay_scenario_diff) and retain it with fa scenario diff --certify (Book::retain_scenario_diff)",
                )));
            }
            (Artifact::DraftDiff(_), _) => {
                return Ok(Err(Refusal::new(
                    crate::certificate::code::CERTIFICATE_INVALID,
                    exit::VERIFICATION,
                    "a draft diff certificate requires its complete source and one atomic scratch rehearsal, which this async replay cannot perform",
                    "plan §7.5 / §15.2 (a draft review replays its exact historical source and all members atomically)",
                    "replay with fa replay (Book::replay_draft_diff), or retain after full replay with Book::retain_draft_diff; a trunk source alone is not the draft result",
                )));
            }
            (_, ReportArtifactExpectation::AsSupplied) => {
                return Ok(Err(expectation_required(artifact.family())));
            }
            _ => {
                return Ok(Err(invalid(
                    "report artifact requires matching independently supplied replay expectations",
                )));
            }
        };
        if let Err(refusal) = replayed {
            return Ok(Err(refusal));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(ReplayedReportArtifact {
            family: artifact.family(),
            book_id: artifact.book_id(),
            known_at: artifact.known_at(),
            certificate_digest: *artifact.digest(),
            output: artifact.output().to_vec(),
        }))
    }
}

#[cfg(test)]
mod tests;
