//! Portable indirect reports bound to the existing whole-book native closure.
//!
//! The nested cash certificate already certifies the Account, Entry, Period,
//! Book, FiscalCalendar, Unit and MigrationRun inputs used by the income and
//! non-cash readers. Reuse that closure; a second ledger or a claimed proof from
//! arithmetic alone is neither necessary nor sufficient. The outer transcript
//! retains exact period identities, adjustment decisions and report output.
//!
//! Decoding checks framing and unkeyed content integrity, not historical truth.
//! Replay checks current authority, independent expected inputs and native
//! history before rebuilding and comparing every output byte. These confidential
//! bytes are not an outsider proof, approval or GAAP/IFRS classification opinion.

mod codec;

use asupersync::fs::Vfs;
use fa_journal::{Refusal, exit};
use fa_model::domain_digest;
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use super::{IndirectCashFlow, IndirectCashFlowDefinition, IndirectCashFlowRequest,
    MAX_INDIRECT_CASH_FLOW_BYTES, native, normalize, periods};
use crate::{AsyncBook, BookError, CashFlowCertificate, Outcome};

pub const INDIRECT_CASH_FLOW_CERTIFICATE_FORMAT: &[u8] = b"fa:indirect-cash-flow-certificate:v1";
pub const MAX_INDIRECT_CASH_FLOW_CERTIFICATE_BYTES: usize = MAX_INDIRECT_CASH_FLOW_BYTES;
const DIGEST_DOMAIN: &[u8] = b"fa:indirect-cash-flow-certificate-digest:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndirectCashFlowCertificate {
    source: CashFlowCertificate,
    income_periods: Vec<String>,
    definition: IndirectCashFlowDefinition,
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedIndirectCashFlow {
    report: IndirectCashFlow,
    certificate: IndirectCashFlowCertificate,
}

impl CertifiedIndirectCashFlow {
    #[must_use]
    pub fn report(&self) -> &IndirectCashFlow { &self.report }
    #[must_use]
    pub fn certificate(&self) -> &IndirectCashFlowCertificate { &self.certificate }
    #[must_use]
    pub fn into_certificate(self) -> IndirectCashFlowCertificate { self.certificate }
}

impl IndirectCashFlowCertificate {
    /// Whole-book native evidence, despite the nested report's cash selection.
    #[must_use]
    pub fn source_certificate(&self) -> &CashFlowCertificate { &self.source }
    #[must_use]
    pub fn income_periods(&self) -> &[String] { &self.income_periods }
    #[must_use]
    pub fn definition(&self) -> &IndirectCashFlowDefinition { &self.definition }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq { self.source.known_at() }
    /// Opaque and untrusted until successful native replay.
    #[must_use]
    pub fn output(&self) -> &[u8] { &self.output }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] { &self.digest }

    fn seal(source: CashFlowCertificate, report: &IndirectCashFlow) -> Result<Self, Refusal> {
        let column = report.income().columns.first()
            .ok_or_else(|| invalid("indirect source income has no column"))?;
        let mut value = Self {
            source,
            income_periods: periods(&column.periods).map_err(as_invalid)?,
            definition: normalize(report.definition()).map_err(as_invalid)?,
            output: report.canonical_bytes().map_err(as_invalid)?,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID, exit::VERIFICATION, message,
        "plan §12.1 / §13.6 / fa-i9yn (native earnings and exact cash adjustments must replay)",
        "replay using the original retained book and independently fixed cash scope, income periods and adjustment definition; a matching total or recomputed hash is not a replay",
    )
}
fn as_invalid(refusal: Refusal) -> Refusal { invalid(refusal.message) }

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Require current Read+Produce authority through the native source, resolve
    /// HEAD once and bind income, non-cash citations and cash to that prefix.
    /// Returns portable confidential bytes; it does not append to the book.
    pub fn certify_indirect_cash_flow(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        request: &IndirectCashFlowRequest,
    ) -> Outcome<CertifiedIndirectCashFlow> {
        let source = match self.certify_cash_flow(
            cx, principal, capability, &request.cash, &request.cash_definition,
        )? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        let report = match native::from_cash(self, cx, principal, capability,
            source.report().clone(), &request.income_periods, &request.definition)? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        let certificate = match IndirectCashFlowCertificate::seal(source.into_certificate(), &report) {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(CertifiedIndirectCashFlow { report, certificate }))
    }

    /// Current Read authority and complete historical replay are mandatory.
    /// `expected.cash.known_at` must be explicit. Obtain expected inputs from the
    /// recipient's independently retained request, NOT from a delivered artifact.
    /// Permutations are equivalent; changed signs, categories, reasons, periods,
    /// cash classifications or zero-valued selected units are not.
    pub fn replay_indirect_cash_flow(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        certificate: &IndirectCashFlowCertificate, expected: &IndirectCashFlowRequest,
    ) -> Outcome<IndirectCashFlow> {
        // Admission and native replay precede additional financial reads. The
        // fixed expected request prevents silently accepting HEAD or an old cut.
        let cash = match self.replay_cash_flow(cx, principal, capability,
            &certificate.source, &expected.cash, &expected.cash_definition)? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        let selected = match periods(&expected.income_periods).map_err(as_invalid) {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        let definition = match normalize(&expected.definition).map_err(as_invalid) {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        if selected != certificate.income_periods || definition != certificate.definition {
            return Ok(Err(invalid("delivered indirect periods or adjustments differ from the independent expected request")));
        }
        if let Err(refusal) = certificate.canonical_bytes() { return Ok(Err(refusal)); }
        cx.query().checkpoint().map_err(BookError::Context)?;
        let report = match native::from_cash(self, cx, principal, capability, cash, &selected, &definition)? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        let output = match report.canonical_bytes().map_err(as_invalid) {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        if output != certificate.output {
            return Ok(Err(invalid("indirect income, adjustment citations, native detail or cash output did not replay")));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}
