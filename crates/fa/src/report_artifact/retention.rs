//! One authorized retention path for every supported report-artifact family.
//! The stored bytes and digest are the original family's, not its nested source.

use super::*;
use crate::RetainedCertificate;
use fa_policy::Op;

/// Storage admission is deliberately not a public constructor or a decoding
/// result. Only a successful family replay under current authority creates it.
/// Binding the head prevents a later caller from reusing an old admission.
pub(crate) struct ValidatedArtifact {
    artifact: ReportArtifact,
    verified_at: CommitSeq,
}

impl ValidatedArtifact {
    pub(crate) fn artifact(&self) -> &ReportArtifact {
        &self.artifact
    }

    pub(crate) fn verified_at(&self) -> CommitSeq {
        self.verified_at
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Retain a complete, replayed artifact under its ORIGINAL public digest.
    /// Cash-flow and reconciliation families require independently supplied
    /// expectations via retain_report_artifact_for instead. Read/produce authority
    /// is current and whole-book; saved certificate metadata grants no permission.
    ///
    /// One native transaction publishes the root and all fragments. It creates
    /// no journal Entry and cannot alter any accounting fold. An exact retry
    /// checks replay and storage integrity but publishes nothing and returns the
    /// original retention sequence. A damaged record is never repaired in place.
    pub async fn retain_report_artifact(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
        expected_digest: Option<&[u8; 32]>,
    ) -> Outcome<RetainedCertificate> {
        self.retain_report_artifact_for(
            cx,
            principal,
            capability,
            bytes,
            expected_digest,
            ReportArtifactExpectation::AsSupplied,
        )
        .await
    }

    /// Retention with recipient-selected scope and definitions. A matching hash
    /// never substitutes for the family-specific historical replay or expected
    /// cash classifications. Authority is checked before decoding or allocation.
    #[allow(clippy::too_many_arguments)]
    pub async fn retain_report_artifact_for(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        bytes: &[u8],
        expected_digest: Option<&[u8; 32]>,
        expected: ReportArtifactExpectation<'_>,
    ) -> Outcome<RetainedCertificate> {
        if let Err(refusal) = authorize(self, cx, principal, capability)? {
            return Ok(Err(refusal));
        }
        if let Err(denial) =
            fa_policy::require(capability, Op::Produce, "retaining a report artifact")
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let verified_at = self.head(cx)?;
        if let Err(refusal) = self
            .replay_report_artifact_for_with_history(
                cx,
                principal,
                capability,
                bytes,
                expected_digest,
                expected,
            )
            .await?
        {
            return Ok(Err(refusal));
        }
        let artifact = match ReportArtifact::decode(bytes) {
            Ok(artifact) => artifact,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = authorize(self, cx, principal, capability)? {
            return Ok(Err(refusal));
        }
        let validated = ValidatedArtifact {
            artifact,
            verified_at,
        };
        let context = self.context().clone();
        crate::certificate_store::retain_validated(
            &mut self.db,
            cx,
            &context,
            &self.blobs,
            &validated,
        )
        .await
    }

    /// Retain a scenario diff that the sync facade has just replayed in full
    /// ([`crate::Book::retain_scenario_diff`]): its replay re-materializes the
    /// scenario, which the async replay above cannot do. Authority is
    /// checked again here, and `verified_at` must still be the head (the
    /// store refuses the retention otherwise), so no later write can ride on
    /// an older replay.
    pub(crate) async fn retain_replayed_scenario_diff(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &crate::ScenarioDiffCertificate,
        verified_at: CommitSeq,
    ) -> Outcome<RetainedCertificate> {
        if let Err(refusal) = authorize(self, cx, principal, capability)? {
            return Ok(Err(refusal));
        }
        if let Err(denial) =
            fa_policy::require(capability, Op::Produce, "retaining a report artifact")
        {
            return Ok(Err(fa_journal::policy::refusal(&denial)));
        }
        let artifact = match ReportArtifact::try_from(certificate) {
            Ok(artifact) => artifact,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let validated = ValidatedArtifact {
            artifact,
            verified_at,
        };
        let context = self.context().clone();
        crate::certificate_store::retain_validated(
            &mut self.db,
            cx,
            &context,
            &self.blobs,
            &validated,
        )
        .await
    }

    /// Retrieve the original immutable artifact, including non-native families.
    /// The full public digest is mandatory; a nested source is never substituted.
    /// Current whole-book read authority is checked before fetching any bytes and
    /// again before returning them. This is storage integrity, not a replay verdict.
    pub async fn read_report_artifact(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        digest: &[u8; 32],
    ) -> Outcome<ReportArtifact> {
        if let Err(refusal) = authorize(self, cx, principal, capability)? {
            return Ok(Err(refusal));
        }
        let query = cx.query();
        let result = query
            .with_restriction_async(crate::certificate_store::read_artifact(
                &self.db,
                &query,
                self.context(),
                &self.blobs,
                digest,
            ))
            .await?;
        if let Err(refusal) = authorize(self, cx, principal, capability)? {
            return Ok(Err(refusal));
        }
        Ok(result)
    }

    /// Resolve a retained digest and replay its complete historical computation.
    /// A storage acknowledgment by itself is never promoted to this verdict.
    pub async fn replay_retained_report_artifact(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        digest: &[u8; 32],
        expected: ReportArtifactExpectation<'_>,
    ) -> Outcome<ReplayedReportArtifact> {
        let artifact = match self
            .read_report_artifact(cx, principal, capability, digest)
            .await?
        {
            Ok(artifact) => artifact,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let bytes = match artifact.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.replay_report_artifact_for(cx, principal, capability, &bytes, Some(digest), expected)
    }

    /// Resolve and replay a retained artifact after admitted history hydration.
    /// Keeps the immutable artifact bytes and original coordinate unchanged.
    pub async fn replay_retained_report_artifact_with_history(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        digest: &[u8; 32],
        expected: ReportArtifactExpectation<'_>,
    ) -> Outcome<ReplayedReportArtifact> {
        let artifact = match self
            .read_report_artifact(cx, principal, capability, digest)
            .await?
        {
            Ok(artifact) => artifact,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let bytes = match artifact.canonical_bytes() {
            Ok(bytes) => bytes,
            Err(refusal) => return Ok(Err(refusal)),
        };
        self.replay_report_artifact_for_with_history(
            cx,
            principal,
            capability,
            &bytes,
            Some(digest),
            expected,
        )
        .await
    }
}
