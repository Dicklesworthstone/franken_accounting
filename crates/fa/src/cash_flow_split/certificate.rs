//! Bind original-leg portions to the existing retained native ledger closure.
//! This is local native-history replay, not a signed outsider proof or approval.
//! The source certificate contains whole-book evidence: keep it confidential.

use fa_model::{DecodeError, Id128, Reader, domain_digest};
use fgdb_types::CommitSeq;

use super::*;
use crate::general_ledger::{GENERAL_LEDGER_FORMAT, MAX_GENERAL_LEDGER_BYTES};
use crate::roll_forward::RollForwardCertificate;

pub const CASH_FLOW_SPLIT_CERTIFICATE_FORMAT: &str = "fa:cash-flow-split-certificate:v1";
pub const MAX_CASH_FLOW_SPLIT_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const DIGEST_DOMAIN: &[u8] = b"fa:cash-flow-split-certificate-digest:v1";

/// Private contents bind the native source, every split decision/reason, and
/// exact output. Successful decoding proves framing/content integrity ONLY.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowSplitCertificate {
    source: RollForwardCertificate,
    definition: CashFlowSplitDefinition,
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedSplitCashFlow {
    report: SplitCashFlow,
    certificate: CashFlowSplitCertificate,
}
impl CertifiedSplitCashFlow {
    #[must_use]
    pub fn report(&self) -> &SplitCashFlow { &self.report }
    #[must_use]
    pub fn certificate(&self) -> &CashFlowSplitCertificate { &self.certificate }
    #[must_use]
    pub fn into_certificate(self) -> CashFlowSplitCertificate { self.certificate }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(crate::certificate::code::CERTIFICATE_INVALID, exit::VERIFICATION, message,
        "plan §12.1 / §13.6 (original cash-leg splits must replay against native history)",
        "use the retained original book plus the recipient's independently fixed request and full split definition; a matching net cash amount or unkeyed digest is not verification")
}
fn as_invalid(refusal: Refusal) -> Refusal { invalid(refusal.message) }

fn transport_size(source: usize, definition: usize, output: usize) -> Result<usize, Refusal> {
    [4, CASH_FLOW_SPLIT_CERTIFICATE_FORMAT.len(), 4, source, 4, definition, 4, output, 32]
        .into_iter().try_fold(0usize, usize::checked_add)
        .filter(|n| *n <= MAX_CASH_FLOW_SPLIT_CERTIFICATE_BYTES)
        .ok_or_else(|| invalid("cash split certificate exceeds its total 64 MiB bound"))
}

/// Check only the existing output header and embedded split decisions here.
/// The remaining financial bytes stay opaque until native replay compares ALL
/// bytes. This deliberately does not create another general-ledger decoder.
fn check_header(
    output: &[u8], source: &RollForwardCertificate, definition: &CashFlowSplitDefinition,
) -> Result<(), Refusal> {
    let malformed = |e: DecodeError| invalid(format!("cash split output header: {e}"));
    let mut r = Reader::new(output);
    if r.str(64, "cash split output format").map_err(malformed)? != CASH_FLOW_SPLIT_FORMAT {
        return Err(invalid("unsupported split cash output format"));
    }
    let ledger = r.bytes(MAX_GENERAL_LEDGER_BYTES, "split cash ledger").map_err(malformed)?;
    let mut gl = Reader::new(ledger);
    let request = source.request();
    if gl.str(64, "split cash ledger format").map_err(malformed)? != GENERAL_LEDGER_FORMAT
        || gl.fixed::<16>("split cash book").map_err(malformed)? != source.source_certificate().book_id.0
        || gl.fixed::<16>("split cash branch").map_err(malformed)? != Id128::TRUNK.0
        || gl.u64("split cash known-at").map_err(malformed)? != source.known_at().0
        || gl.str(256, "split cash label").map_err(malformed)? != request.label
        || gl.i32("split cash from").map_err(malformed)? != request.effective_from.0
        || gl.i32("split cash through").map_err(malformed)? != request.effective_through.0
    { return Err(invalid("split cash output has a different native coordinate")); }
    let declared = CashFlowSplitDefinition::decode(
        r.bytes(MAX_CASH_FLOW_SPLIT_DEFINITION_BYTES, "split output decisions").map_err(malformed)?,
    ).map_err(as_invalid)?;
    if &declared != definition { return Err(invalid("split output decisions differ from its certificate")); }
    Ok(())
}

impl CashFlowSplitCertificate {
    #[must_use]
    pub fn source_certificate(&self) -> &RollForwardCertificate { &self.source }
    #[must_use]
    pub fn request(&self) -> &RollForwardRequest { self.source.request() }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq { self.source.known_at() }
    #[must_use]
    pub fn definition(&self) -> &CashFlowSplitDefinition { &self.definition }
    #[must_use]
    pub fn output(&self) -> &[u8] { &self.output }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] { &self.digest }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        if self.output.len() > MAX_CASH_FLOW_SPLIT_BYTES
            || codec::normalize(&self.definition).map_err(as_invalid)? != self.definition
            || self.definition.cash_accounts != self.request().accounts.iter().map(|a| a.0).collect::<Vec<_>>()
        { return Err(invalid("noncanonical split definition, cash scope or output size")); }
        check_header(&self.output, &self.source, &self.definition)?;
        let source = self.source.canonical_bytes()?;
        let definition = self.definition.canonical_bytes().map_err(as_invalid)?;
        transport_size(source.len(), definition.len(), self.output.len())?;
        let mut w = codec::Wire::new(MAX_CASH_FLOW_SPLIT_CERTIFICATE_BYTES - 32);
        w.text(CASH_FLOW_SPLIT_CERTIFICATE_FORMAT).map_err(as_invalid)?;
        w.bytes(&source).map_err(as_invalid)?;
        w.bytes(&definition).map_err(as_invalid)?;
        w.bytes(&self.output).map_err(as_invalid)?;
        Ok(w.finish())
    }
    fn seal(source: RollForwardCertificate, report: &SplitCashFlow) -> Result<Self, Refusal> {
        let mut value = Self { source, definition: report.definition().clone(),
            output: report.canonical_bytes().map_err(as_invalid)?, digest: [0; 32] };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&body]) != self.digest {
            return Err(invalid("cash split certificate content digest differs"));
        }
        body.try_reserve(32).map_err(|_| invalid("cannot reserve split certificate digest"))?;
        body.extend_from_slice(&self.digest);
        Ok(body)
    }
    /// Bound and authenticate unkeyed transport integrity before nested parsing.
    /// An attacker can recompute the digest. Replay, and independent expected
    /// inputs, are still mandatory before relying on any supplied amount.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_CASH_FLOW_SPLIT_CERTIFICATE_BYTES || bytes.len() < 32 {
            return Err(invalid("truncated or excessive cash split certificate"));
        }
        let body_len = bytes.len() - 32;
        let digest = domain_digest(DIGEST_DOMAIN, &[&bytes[..body_len]]);
        if bytes[body_len..] != digest { return Err(invalid("cash split transport digest differs")); }
        let malformed = |e: DecodeError| invalid(format!("malformed cash split certificate: {e}"));
        let mut r = Reader::new(&bytes[..body_len]);
        if r.str(64, "cash split certificate format").map_err(malformed)? != CASH_FLOW_SPLIT_CERTIFICATE_FORMAT {
            return Err(invalid("unsupported cash split certificate format"));
        }
        let source = RollForwardCertificate::decode(
            r.bytes(MAX_CASH_FLOW_SPLIT_CERTIFICATE_BYTES, "cash split native source").map_err(malformed)?,
        )?;
        let definition = CashFlowSplitDefinition::decode(
            r.bytes(MAX_CASH_FLOW_SPLIT_DEFINITION_BYTES, "cash split definition").map_err(malformed)?,
        ).map_err(as_invalid)?;
        let output = r.bytes(MAX_CASH_FLOW_SPLIT_BYTES, "cash split output").map_err(malformed)?.to_vec();
        r.finish().map_err(malformed)?;
        let value = Self { source, definition, output, digest };
        if value.canonical_bytes()?.as_slice() != bytes { return Err(invalid("noncanonical split certificate")); }
        Ok(value)
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Current native Read+Produce authority; HEAD is fixed exactly once by the
    /// existing source producer. No new checkpoint, journal record or write.
    pub fn certify_split_cash_flow(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        request: &RollForwardRequest, definition: &CashFlowSplitDefinition,
    ) -> Outcome<CertifiedSplitCashFlow> {
        let source = match self.certify_general_ledger(cx, principal, capability, request)? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        certify_source(source, &cx.query(), definition)
    }

    /// Verify CURRENT Read authority and native history before recomputing each
    /// original-leg partition. Require an independently fixed known-at, request
    /// and definition: do not derive expected inputs from a delivered artifact.
    pub fn replay_split_cash_flow(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        certificate: &CashFlowSplitCertificate, expected: &RollForwardRequest,
        expected_definition: &CashFlowSplitDefinition,
    ) -> Outcome<SplitCashFlow> {
        let source = match self.replay_general_ledger(cx, principal, capability, &certificate.source, expected)? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        replay_source(source, &cx.query(), certificate, expected_definition)
    }
}

// These are the only projection/sealing and exact-output replay paths. The
// sync and async adapters differ solely in how they obtain the native source.
fn certify_source(
    source: crate::general_ledger::CertifiedGeneralLedger,
    query: &QueryCx,
    definition: &CashFlowSplitDefinition,
) -> Outcome<CertifiedSplitCashFlow> {
    query.checkpoint().map_err(BookError::Context)?;
    let report = match source.report().clone().split_cash_flow(query, definition)? {
        Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
    };
    let certificate = match CashFlowSplitCertificate::seal(source.into_source_certificate(), &report) {
        Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
    };
    query.checkpoint().map_err(BookError::Context)?;
    Ok(Ok(CertifiedSplitCashFlow { report, certificate }))
}

fn replay_source(
    source: GeneralLedger,
    query: &QueryCx,
    certificate: &CashFlowSplitCertificate,
    expected_definition: &CashFlowSplitDefinition,
) -> Outcome<SplitCashFlow> {
    query.checkpoint().map_err(BookError::Context)?;
    let definition = match codec::normalize(expected_definition).map_err(as_invalid) {
        Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
    };
    if definition != certificate.definition {
        return Ok(Err(invalid("delivered cash portions or reasons differ from independent expected decisions")));
    }
    if let Err(refusal) = certificate.canonical_bytes() { return Ok(Err(refusal)); }
    let report = match source.split_cash_flow(query, &definition)? {
        Ok(value) => value, Err(refusal) => return Ok(Err(as_invalid(refusal))),
    };
    let output = match report.canonical_bytes().map_err(as_invalid) {
        Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
    };
    if output != certificate.output {
        return Ok(Err(invalid("cash split portions, original citations or exact amounts did not replay")));
    }
    query.checkpoint().map_err(BookError::Context)?;
    Ok(Ok(report))
}

impl crate::Book {
    /// Read split cash through this synchronous book's native ledger. The
    /// caller's query context meters the pure projection; native reads retain
    /// this Book's existing runtime/context. A cancelled caller is refused
    /// before source observation. No runtime is created by this adapter.
    pub fn split_cash_flow(
        &self,
        query: &QueryCx,
        principal: VId,
        capability: &Capability,
        request: &RollForwardRequest,
        definition: &CashFlowSplitDefinition,
    ) -> Outcome<SplitCashFlow> {
        query.checkpoint().map_err(BookError::Context)?;
        let source = match self.general_ledger(principal, capability, request)? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        source.split_cash_flow(query, definition)
    }

    /// Certify with current Read+Produce authority using exactly the same
    /// native source, split projection, encoding and seal as AsyncBook.
    /// This returns a portable confidential artifact without a book write.
    pub fn certify_split_cash_flow(
        &self,
        query: &QueryCx,
        principal: VId,
        capability: &Capability,
        request: &RollForwardRequest,
        definition: &CashFlowSplitDefinition,
    ) -> Outcome<CertifiedSplitCashFlow> {
        query.checkpoint().map_err(BookError::Context)?;
        let source = match self.certify_general_ledger(principal, capability, request)? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        certify_source(source, query, definition)
    }

    /// Replay only after current authority, the independently fixed request,
    /// and the complete native source pass the existing Book verifier. The
    /// common projection then checks every expected portion, reason and byte.
    #[allow(clippy::too_many_arguments)]
    pub fn replay_split_cash_flow(
        &self,
        query: &QueryCx,
        principal: VId,
        capability: &Capability,
        certificate: &CashFlowSplitCertificate,
        expected: &RollForwardRequest,
        expected_definition: &CashFlowSplitDefinition,
    ) -> Outcome<SplitCashFlow> {
        query.checkpoint().map_err(BookError::Context)?;
        let source = match self.replay_general_ledger(
            principal, capability, &certificate.source, expected,
        )? {
            Ok(value) => value, Err(refusal) => return Ok(Err(refusal)),
        };
        replay_source(source, query, certificate, expected_definition)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn total_bound_counts_every_length_field_and_the_final_digest() {
        let overhead = 4 + CASH_FLOW_SPLIT_CERTIFICATE_FORMAT.len() + 12 + 32;
        assert_eq!(transport_size(3, 5, 7).unwrap(), overhead + 15);
        assert_eq!(transport_size(MAX_CASH_FLOW_SPLIT_CERTIFICATE_BYTES - overhead, 0, 0).unwrap(), MAX_CASH_FLOW_SPLIT_CERTIFICATE_BYTES);
        assert!(transport_size(MAX_CASH_FLOW_SPLIT_CERTIFICATE_BYTES - overhead, 1, 0).is_err());
        assert!(transport_size(usize::MAX, 1, 1).is_err());
    }
    #[test]
    fn a_valid_unkeyed_digest_does_not_make_missing_native_evidence_decodable() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(CASH_FLOW_SPLIT_CERTIFICATE_FORMAT.len() as u32).to_le_bytes());
        bytes.extend_from_slice(CASH_FLOW_SPLIT_CERTIFICATE_FORMAT.as_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        let digest = domain_digest(DIGEST_DOMAIN, &[&bytes]); bytes.extend_from_slice(&digest);
        let refusal = CashFlowSplitCertificate::decode(&bytes).unwrap_err();
        assert_eq!(refusal.code, "FA-REF-150"); assert_eq!(refusal.exit, 8);
        assert!(CashFlowSplitCertificate::decode(&[]).is_err());
    }
    #[test]
    fn oversize_transport_is_rejected_before_nested_allocations() {
        let bytes = vec![0; MAX_CASH_FLOW_SPLIT_CERTIFICATE_BYTES + 1];
        assert!(CashFlowSplitCertificate::decode(&bytes).is_err());
    }
}
