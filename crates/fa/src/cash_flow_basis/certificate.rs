//! Preserve the native classification family through certification and replay.
//!
//! An indirect report consumes these existing family certificates intact. In
//! particular, policy derivation decisions and exact portions are never replaced
//! by an equivalent whole-leg assignment or by equal section totals.

use asupersync::fs::Vfs;
use fa_journal::{Refusal, exit};
use fa_policy::Capability;
use fgdb_types::{CommitSeq, VId, context::PurposeContexts};

use super::{CashFlowBasis, CashFlowBasisDefinition, CashFlowBasisKind};
use crate::cash_flow_policy::CashFlowPolicyCertificate;
use crate::cash_flow_split::CashFlowSplitCertificate;
use crate::{AsyncBook, CashFlowCertificate, Outcome, ReportCertificate, RollForwardRequest};

/// The complete existing native certificate, including classification provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CashFlowBasisCertificate {
    Explicit(CashFlowCertificate),
    Policy(CashFlowPolicyCertificate),
    Split(CashFlowSplitCertificate),
}

impl CashFlowBasisCertificate {
    #[must_use]
    pub const fn kind(&self) -> CashFlowBasisKind {
        match self {
            Self::Explicit(_) => CashFlowBasisKind::Explicit,
            Self::Policy(_) => CashFlowBasisKind::Policy,
            Self::Split(_) => CashFlowBasisKind::Split,
        }
    }

    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        match self {
            Self::Explicit(certificate) => certificate.known_at(),
            Self::Policy(certificate) => certificate.known_at(),
            Self::Split(certificate) => certificate.known_at(),
        }
    }

    #[must_use]
    pub fn request(&self) -> &RollForwardRequest {
        match self {
            Self::Explicit(certificate) => certificate.request(),
            Self::Policy(certificate) => certificate.request(),
            Self::Split(certificate) => certificate.request(),
        }
    }

    /// Original normalized inputs, never inferred from delivered output totals.
    #[must_use]
    pub fn definition(&self) -> CashFlowBasisDefinition {
        match self {
            Self::Explicit(certificate) => {
                CashFlowBasisDefinition::Explicit(certificate.definition().clone())
            }
            Self::Policy(certificate) => {
                CashFlowBasisDefinition::Policy(certificate.policy().clone())
            }
            Self::Split(certificate) => {
                CashFlowBasisDefinition::Split(certificate.definition().clone())
            }
        }
    }

    /// The original confidential whole-book closure, regardless of basis kind.
    #[must_use]
    pub fn native_source_certificate(&self) -> &ReportCertificate {
        match self {
            Self::Explicit(certificate) => certificate.source_certificate().source_certificate(),
            Self::Policy(certificate) => certificate
                .source_certificate()
                .source_certificate()
                .source_certificate(),
            Self::Split(certificate) => certificate.source_certificate().source_certificate(),
        }
    }

    /// The exact existing family envelope, without another wrapper format.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        match self {
            Self::Explicit(certificate) => certificate.canonical_bytes(),
            Self::Policy(certificate) => certificate.canonical_bytes(),
            Self::Split(certificate) => certificate.canonical_bytes(),
        }
    }

    /// Complete family output, including policy rules and derivation decisions.
    /// These bytes remain untrusted until native replay succeeds.
    pub fn output_bytes(&self) -> Result<Vec<u8>, Refusal> {
        match self {
            Self::Explicit(certificate) => Ok(certificate.output().to_vec()),
            Self::Policy(certificate) => certificate.output(),
            Self::Split(certificate) => Ok(certificate.output().to_vec()),
        }
    }

    /// An outer version supplies the kind; each existing decoder checks its own
    /// exact family tag, framing, total bound and content integrity.
    pub(crate) fn decode(kind: CashFlowBasisKind, bytes: &[u8]) -> Result<Self, Refusal> {
        match kind {
            CashFlowBasisKind::Explicit => CashFlowCertificate::decode(bytes).map(Self::Explicit),
            CashFlowBasisKind::Policy => CashFlowPolicyCertificate::decode(bytes).map(Self::Policy),
            CashFlowBasisKind::Split => CashFlowSplitCertificate::decode(bytes).map(Self::Split),
        }
    }
}

/// Admit current authority and pin one prefix through the original producer.
/// Downstream reads receive the report and its same-family certificate together.
pub(crate) fn certify<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    request: &RollForwardRequest,
    definition: &CashFlowBasisDefinition,
) -> Outcome<(CashFlowBasis, CashFlowBasisCertificate)> {
    match definition {
        CashFlowBasisDefinition::Explicit(definition) => book
            .certify_cash_flow(cx, principal, capability, request, definition)
            .map(|result| {
                result.map(|certified| {
                    (
                        CashFlowBasis::Explicit(certified.report().clone()),
                        CashFlowBasisCertificate::Explicit(certified.into_certificate()),
                    )
                })
            }),
        CashFlowBasisDefinition::Policy(policy) => book
            .certify_cash_flow_with_policy(cx, principal, capability, request, policy)
            .map(|result| {
                result.map(|certified| {
                    (
                        CashFlowBasis::Policy(certified.report().clone()),
                        CashFlowBasisCertificate::Policy(certified.into_certificate()),
                    )
                })
            }),
        CashFlowBasisDefinition::Split(definition) => book
            .certify_split_cash_flow(cx, principal, capability, request, definition)
            .map(|result| {
                result.map(|certified| {
                    (
                        CashFlowBasis::Split(certified.report().clone()),
                        CashFlowBasisCertificate::Split(certified.into_certificate()),
                    )
                })
            }),
    }
}

/// Replay the exact original family against independent full expected inputs.
/// A kind mismatch is a structural refusal before any additional financial read;
/// matching kinds always enter the existing current-authority native replay.
pub(crate) fn replay<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    certificate: &CashFlowBasisCertificate,
    expected: &RollForwardRequest,
    definition: &CashFlowBasisDefinition,
) -> Outcome<CashFlowBasis> {
    match (certificate, definition) {
        (
            CashFlowBasisCertificate::Explicit(certificate),
            CashFlowBasisDefinition::Explicit(definition),
        ) => book
            .replay_cash_flow(cx, principal, capability, certificate, expected, definition)
            .map(|result| result.map(CashFlowBasis::Explicit)),
        (
            CashFlowBasisCertificate::Policy(certificate),
            CashFlowBasisDefinition::Policy(policy),
        ) => book
            .replay_cash_flow_with_policy(cx, principal, capability, certificate, expected, policy)
            .map(|result| result.map(CashFlowBasis::Policy)),
        (
            CashFlowBasisCertificate::Split(certificate),
            CashFlowBasisDefinition::Split(definition),
        ) => book
            .replay_split_cash_flow(cx, principal, capability, certificate, expected, definition)
            .map(|result| result.map(CashFlowBasis::Split)),
        _ => Ok(Err(Refusal::new(
            crate::certificate::code::CERTIFICATE_INVALID,
            exit::VERIFICATION,
            "delivered cash classification family differs from the independent expected basis",
            "plan §12.1 / §13.6 (original cash classification and provenance must replay)",
            "supply the independently retained explicit, policy or split definition and fixed scope; equal totals do not make different classification families interchangeable",
        ))),
    }
}
