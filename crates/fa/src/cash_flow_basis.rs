//! Native cash classifications shared by indirect reconciliation and replay.
//!
//! Each basis retains its original report and classification provenance. A
//! split basis keeps one citation per original cash leg and its exact portions;
//! a policy basis keeps its rules, overrides and derivation decisions. Neither
//! is flattened into whole-leg assignments when used by another report.

mod certificate;

pub use certificate::CashFlowBasisCertificate;
pub(crate) use certificate::{certify, replay};

use asupersync::fs::Vfs;
use fa_journal::Refusal;
use fa_policy::Capability;
use fgdb_types::{VId, context::PurposeContexts};

use crate::cash_flow_policy::{CashFlowPolicy, PolicyCashFlow};
use crate::cash_flow_split::{CashFlowSplitDefinition, SplitCashFlow};
use crate::{
    AsyncBook, CashFlow, CashFlowDefinition, CashFlowUnit, GeneralLedger, Outcome,
    RollForwardRequest,
};

/// The original classification family, including its distinct provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CashFlowBasisKind {
    Explicit = 0,
    Policy = 1,
    Split = 2,
}

/// Independent expected classification inputs for a native read or replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CashFlowBasisDefinition {
    Explicit(CashFlowDefinition),
    Policy(CashFlowPolicy),
    Split(CashFlowSplitDefinition),
}

impl CashFlowBasisDefinition {
    #[must_use]
    pub const fn kind(&self) -> CashFlowBasisKind {
        match self {
            Self::Explicit(_) => CashFlowBasisKind::Explicit,
            Self::Policy(_) => CashFlowBasisKind::Policy,
            Self::Split(_) => CashFlowBasisKind::Split,
        }
    }

    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Explicit(definition) => &definition.name,
            Self::Policy(policy) => &policy.name,
            Self::Split(definition) => &definition.name,
        }
    }

    #[must_use]
    pub fn cash_accounts(&self) -> &[u128] {
        match self {
            Self::Explicit(definition) => &definition.cash_accounts,
            Self::Policy(policy) => &policy.cash_accounts,
            Self::Split(definition) => &definition.cash_accounts,
        }
    }
}

/// An admitted native report, retaining the full selected classification basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CashFlowBasis {
    Explicit(CashFlow),
    Policy(PolicyCashFlow),
    Split(SplitCashFlow),
}

impl CashFlowBasis {
    #[must_use]
    pub fn source(&self) -> &GeneralLedger {
        match self {
            Self::Explicit(report) => report.source(),
            Self::Policy(report) => report.report().source(),
            Self::Split(report) => report.source(),
        }
    }

    #[must_use]
    pub fn units(&self) -> &[CashFlowUnit] {
        match self {
            Self::Explicit(report) => report.units(),
            Self::Policy(report) => report.report().units(),
            Self::Split(report) => report.units(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> CashFlowBasisKind {
        match self {
            Self::Explicit(_) => CashFlowBasisKind::Explicit,
            Self::Policy(_) => CashFlowBasisKind::Policy,
            Self::Split(_) => CashFlowBasisKind::Split,
        }
    }

    #[must_use]
    pub fn definition_name(&self) -> &str {
        match self {
            Self::Explicit(report) => &report.definition().name,
            Self::Policy(report) => &report.policy().name,
            Self::Split(report) => &report.definition().name,
        }
    }

    #[must_use]
    pub fn cash_accounts(&self) -> &[u128] {
        match self {
            Self::Explicit(report) => &report.definition().cash_accounts,
            Self::Policy(report) => &report.policy().cash_accounts,
            Self::Split(report) => &report.definition().cash_accounts,
        }
    }

    /// The normalized original inputs, including policy rules or split reasons
    /// that cannot be reconstructed from section totals or whole-leg assignments.
    #[must_use]
    pub fn definition(&self) -> CashFlowBasisDefinition {
        match self {
            Self::Explicit(report) => {
                CashFlowBasisDefinition::Explicit(report.definition().clone())
            }
            Self::Policy(report) => CashFlowBasisDefinition::Policy(report.policy().clone()),
            Self::Split(report) => CashFlowBasisDefinition::Split(report.definition().clone()),
        }
    }

    /// The complete native family output, without a replacement wrapper format.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        match self {
            Self::Explicit(report) => report.canonical_bytes(),
            Self::Policy(report) => report.canonical_bytes(),
            Self::Split(report) => report.canonical_bytes(),
        }
    }
}

/// Each family admits current whole-book authority before historical reads and
/// resolves HEAD once. Downstream reports consume that fixed native prefix.
pub(crate) fn read<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    request: &RollForwardRequest,
    definition: &CashFlowBasisDefinition,
) -> Outcome<CashFlowBasis> {
    match definition {
        CashFlowBasisDefinition::Explicit(definition) => book
            .cash_flow(cx, principal, capability, request, definition)
            .map(|result| result.map(CashFlowBasis::Explicit)),
        CashFlowBasisDefinition::Policy(policy) => book
            .cash_flow_with_policy(cx, principal, capability, request, policy)
            .map(|result| result.map(CashFlowBasis::Policy)),
        CashFlowBasisDefinition::Split(definition) => book
            .split_cash_flow(cx, principal, capability, request, definition)
            .map(|result| result.map(CashFlowBasis::Split)),
    }
}
