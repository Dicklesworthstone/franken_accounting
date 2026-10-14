//! Replayable classified cash movements over retained native book history.
//!
//! The existing roll-forward certificate supplies the complete journal, chart,
//! registry and migration closure. This envelope additionally binds the cash
//! classification and exact output. It is not a second ledger or an outsider
//! proof. Decode verifies framing and an unkeyed digest, NOT accounting truth.
//! Replay requires current authority and an independently selected request and
//! definition; accepting either from an untrusted delivery defeats that binding.
//!
//! Portable bytes contain whole-book native evidence even though the report is
//! cash-scoped. Keep them confidential. Creating or replaying this artifact does
//! not write the book, approve a classification, or claim GAAP/IFRS conformity.

mod workpaper;

pub use workpaper::{CASH_FLOW_WORKPAPER_FORMAT, MAX_CASH_FLOW_WORKPAPER_BYTES};

use asupersync::fs::Vfs;
use fa_journal::{Refusal, exit};
use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_policy::Capability;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::general_ledger::{
    CASH_FLOW_FORMAT, CashFlow, CashFlowActivity, CashFlowAssignment, CashFlowDefinition,
    GENERAL_LEDGER_FORMAT, MAX_GENERAL_LEDGER_BYTES, MAX_GENERAL_LEDGER_LINES,
};
use crate::roll_forward::RollForwardCertificate;
use crate::{AsyncBook, BookError, Outcome, RollForwardRequest};

pub const CASH_FLOW_CERTIFICATE_FORMAT: &[u8] = b"fa:cash-flow-certificate:v1";
pub const MAX_CASH_FLOW_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const DIGEST_DOMAIN: &[u8] = b"fa:cash-flow-certificate-digest:v1";
const MAX_CASH_ACCOUNTS: usize = 4096;

/// Canonical content integrity is distinct from successful native replay.
/// Private fields prevent an embedding from mutating a verified report in place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowCertificate {
    source: RollForwardCertificate,
    definition: CashFlowDefinition,
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedCashFlow {
    report: CashFlow,
    certificate: CashFlowCertificate,
}

impl CertifiedCashFlow {
    #[must_use]
    pub fn report(&self) -> &CashFlow {
        &self.report
    }

    #[must_use]
    pub fn certificate(&self) -> &CashFlowCertificate {
        &self.certificate
    }

    #[must_use]
    pub fn into_certificate(self) -> CashFlowCertificate {
        self.certificate
    }
}

impl CashFlowCertificate {
    #[must_use]
    pub fn source_certificate(&self) -> &RollForwardCertificate {
        &self.source
    }

    #[must_use]
    pub fn definition(&self) -> &CashFlowDefinition {
        &self.definition
    }

    /// The native source carries the fixed prefix and original request once.
    #[must_use]
    pub fn request(&self) -> &RollForwardRequest {
        self.source.request()
    }

    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.source.known_at()
    }

    /// Untrusted until replay; never turn these bytes directly into a CashFlow.
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }

    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        if self.output.len() > MAX_GENERAL_LEDGER_BYTES
            || normalize(&self.definition)? != self.definition
            || self.definition.cash_accounts
                != self
                    .source
                    .request()
                    .accounts
                    .iter()
                    .map(|id| id.0)
                    .collect::<Vec<_>>()
        {
            return Err(invalid(
                "noncanonical cash-flow definition, source scope or output size",
            ));
        }
        check_output_header(&self.output, &self.source, &self.definition)
            .map_err(|error| invalid(error.to_string()))?;
        let source = self.source.canonical_bytes()?;
        let size = envelope_size(source.len(), &self.definition, self.output.len())?;
        let mut w = Writer::with_capacity(size);
        w.bytes(CASH_FLOW_CERTIFICATE_FORMAT).bytes(&source);
        write_definition(&mut w, &self.definition);
        w.bytes(&self.output);
        w.finish().map_err(|error| invalid(error.to_string()))
    }

    fn seal(source: RollForwardCertificate, report: &CashFlow) -> Result<Self, Refusal> {
        let mut value = Self {
            source,
            definition: normalize(report.definition())?,
            output: report.canonical_bytes()?,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// Buffered, bounded transport. The recipient must retain its identity and
    /// expected inputs independently of a later delivery from another party.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&body]) != self.digest {
            return Err(invalid(
                "cash-flow certificate digest differs from its contents",
            ));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    /// Strict framing, canonical definition and nested source validation only.
    /// An attacker can recompute this unkeyed digest. Only native replay proves
    /// the retained output, and only independent expected inputs fix its scope.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_CASH_FLOW_CERTIFICATE_BYTES {
            return Err(invalid(
                "cash-flow certificate exceeds its 64 MiB total bound",
            ));
        }
        let malformed =
            |error: DecodeError| invalid(format!("malformed cash-flow certificate: {error}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "cash-flow certificate format")
            .map_err(malformed)?
            != CASH_FLOW_CERTIFICATE_FORMAT
        {
            return Err(invalid("unsupported cash-flow certificate format"));
        }
        let source = RollForwardCertificate::decode(
            r.bytes(MAX_CASH_FLOW_CERTIFICATE_BYTES, "cash-flow native source")
                .map_err(malformed)?,
        )?;
        let definition = read_definition(&mut r).map_err(malformed)?;
        let output = r
            .bytes(MAX_GENERAL_LEDGER_BYTES, "cash-flow output")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed("cash-flow certificate digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            source,
            definition,
            output,
            digest,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical cash-flow certificate encoding"));
        }
        Ok(value)
    }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §12.1 / §13.6 (cash classifications and exact native activity must replay)",
        "use the original retained book and independently expected fixed request and cash definition; matching cash totals or a self-consistent hash are not a replay",
    )
}

fn normalize(definition: &CashFlowDefinition) -> Result<CashFlowDefinition, Refusal> {
    // Reject excessive caller-controlled vectors BEFORE copying or sorting them.
    if definition.name.trim().is_empty()
        || definition.name.len() > 256
        || definition.cash_accounts.is_empty()
        || definition.cash_accounts.len() > MAX_CASH_ACCOUNTS
        || definition.assignments.len() > MAX_GENERAL_LEDGER_LINES
    {
        return Err(invalid(
            "cash-flow definition exceeds its name, account or assignment bounds",
        ));
    }
    let mut value = definition.clone();
    value.cash_accounts.sort_unstable();
    value
        .assignments
        .sort_unstable_by_key(|a| (a.entry_digest, a.leg_index));
    if value
        .cash_accounts
        .windows(2)
        .any(|pair| pair[0] == pair[1])
        || value.assignments.windows(2).any(|pair| {
            (pair[0].entry_digest, pair[0].leg_index) == (pair[1].entry_digest, pair[1].leg_index)
        })
    {
        return Err(invalid(
            "cash-flow definition repeats an account or journal leg",
        ));
    }
    Ok(value)
}

fn envelope_size(
    source: usize,
    definition: &CashFlowDefinition,
    output: usize,
) -> Result<usize, Refusal> {
    let accounts = definition.cash_accounts.len().checked_mul(16);
    let assignments = definition.assignments.len().checked_mul(37);
    let size = accounts
        .zip(assignments)
        .and_then(|(accounts, assignments)| {
            [
                4,
                CASH_FLOW_CERTIFICATE_FORMAT.len(),
                4,
                source,
                4,
                definition.name.len(),
                4,
                accounts,
                4,
                assignments,
                4,
                output,
                32,
            ]
            .into_iter()
            .try_fold(0usize, usize::checked_add)
        });
    size.filter(|n| *n <= MAX_CASH_FLOW_CERTIFICATE_BYTES)
        .ok_or_else(|| invalid("cash-flow certificate exceeds its 64 MiB total bound"))
}

fn write_definition(w: &mut Writer, definition: &CashFlowDefinition) {
    w.str(&definition.name)
        .list(&definition.cash_accounts, |w, id| {
            w.u128(*id);
        })
        .list(&definition.assignments, |w, assignment| {
            w.fixed(&assignment.entry_digest)
                .u32(assignment.leg_index)
                .u8(assignment.activity as u8);
        });
}

fn read_definition(r: &mut Reader<'_>) -> Result<CashFlowDefinition, DecodeError> {
    let name = r.str(256, "cash-flow definition name")?.to_string();
    let count = r.count(MAX_CASH_ACCOUNTS, "cash accounts")?;
    if count == 0 || count > r.remaining() / 16 {
        return Err(r.invalid("empty or truncated cash account set"));
    }
    let mut cash_accounts = Vec::with_capacity(count);
    for _ in 0..count {
        cash_accounts.push(r.u128("cash account")?);
    }
    let count = r.count(MAX_GENERAL_LEDGER_LINES, "cash-flow assignments")?;
    if count > r.remaining() / 37 {
        return Err(r.invalid("truncated cash-flow assignments"));
    }
    let mut assignments = Vec::with_capacity(count);
    for _ in 0..count {
        let entry_digest = r.fixed("cash-flow entry digest")?;
        let leg_index = r.u32("cash-flow leg index")?;
        let activity = match r.u8("cash-flow activity")? {
            0 => CashFlowActivity::Operating,
            1 => CashFlowActivity::Investing,
            2 => CashFlowActivity::Financing,
            3 => CashFlowActivity::ExchangeEffect,
            4 => CashFlowActivity::InternalTransfer,
            _ => return Err(r.invalid("unknown cash-flow activity")),
        };
        assignments.push(CashFlowAssignment {
            entry_digest,
            leg_index,
            activity,
        });
    }
    let value = CashFlowDefinition {
        name,
        cash_accounts,
        assignments,
    };
    if normalize(&value).map_err(|_| r.invalid("invalid cash-flow definition"))? != value {
        return Err(r.invalid("cash-flow definition is not strictly ordered"));
    }
    Ok(value)
}

/// Check the existing output's envelope without making a second ledger decoder.
/// Its remaining financial bytes are opaque until exact native replay compares
/// them. Header validation alone is NOT a source or arithmetic verification.
fn check_output_header(
    bytes: &[u8],
    source: &RollForwardCertificate,
    definition: &CashFlowDefinition,
) -> Result<(), DecodeError> {
    let mut r = Reader::new(bytes);
    if r.str(64, "cash-flow output format")? != CASH_FLOW_FORMAT {
        return Err(r.invalid("unsupported cash-flow output format"));
    }
    let ledger = r.bytes(MAX_GENERAL_LEDGER_BYTES, "cash-flow ledger output")?;
    let mut gl = Reader::new(ledger);
    let request = source.request();
    if gl.str(64, "general-ledger output format")? != GENERAL_LEDGER_FORMAT
        || gl.fixed::<16>("cash-flow book")? != source.source_certificate().book_id.0
        || gl.fixed::<16>("cash-flow branch")? != Id128::TRUNK.0
        || gl.u64("cash-flow known-at")? != source.known_at().0
        || gl.str(256, "cash-flow label")? != request.label
        || gl.i32("cash-flow effective from")? != request.effective_from.0
        || gl.i32("cash-flow effective through")? != request.effective_through.0
        || read_definition(&mut r)? != *definition
    {
        return Err(r.invalid("cash-flow output header or classification differs from its source"));
    }
    Ok(())
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Native read+produce admission happens before classification or output.
    /// HEAD is resolved once by the native source and stored as a fixed prefix.
    /// All cash legs, including cancelling movements, remain in the closure.
    pub fn certify_cash_flow(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &RollForwardRequest,
        definition: &CashFlowDefinition,
    ) -> Outcome<CertifiedCashFlow> {
        let source = match self.certify_general_ledger(cx, principal, capability, request)? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        let report = match source
            .report()
            .clone()
            .classify_cash_flow(&cx.query(), definition)?
        {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let certificate = match CashFlowCertificate::seal(source.into_source_certificate(), &report)
        {
            Ok(certificate) => certificate,
            Err(refusal) => return Ok(Err(refusal)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(CertifiedCashFlow {
            report,
            certificate,
        }))
    }

    /// Verify native history under CURRENT read authority, check the independently
    /// expected fixed scope and definition, then reclassify and compare ALL bytes.
    /// `expected.known_at = None` is refused. Permuting equivalent scope/assignment
    /// lists is harmless; changing a class, label, zero leaf or unit is not.
    pub fn replay_cash_flow(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &CashFlowCertificate,
        expected: &RollForwardRequest,
        expected_definition: &CashFlowDefinition,
    ) -> Outcome<CashFlow> {
        // The native replay checks holder, scope, current expiry/revocation and
        // the fixed expected selector before observing any financial payload.
        let ledger = match self.replay_general_ledger(
            cx,
            principal,
            capability,
            &certificate.source,
            expected,
        )? {
            Ok(ledger) => ledger,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = certificate.canonical_bytes() {
            return Ok(Err(refusal));
        }
        let definition = match normalize(expected_definition) {
            Ok(definition) => definition,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if definition != certificate.definition {
            return Ok(Err(invalid(
                "delivered cash classification differs from the independent expected definition",
            )));
        }
        let report = match ledger.classify_cash_flow(&cx.query(), &definition)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let output = match report.canonical_bytes() {
            Ok(output) => output,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if output != certificate.output {
            return Ok(Err(invalid(
                "cash-flow amounts, classifications or journal-leg citations did not replay",
            )));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition() -> CashFlowDefinition {
        CashFlowDefinition {
            name: "Classification € v1".into(),
            cash_accounts: vec![1, u128::MAX],
            assignments: [
                CashFlowActivity::Operating,
                CashFlowActivity::Investing,
                CashFlowActivity::Financing,
                CashFlowActivity::ExchangeEffect,
                CashFlowActivity::InternalTransfer,
            ]
            .into_iter()
            .enumerate()
            .map(|(index, activity)| CashFlowAssignment {
                entry_digest: [index as u8; 32],
                leg_index: u32::MAX,
                activity,
            })
            .collect(),
        }
    }

    fn encoded(value: &CashFlowDefinition) -> Vec<u8> {
        let mut w = Writer::new();
        write_definition(&mut w, value);
        w.finish().unwrap()
    }

    #[test]
    fn definition_wire_layout_and_every_activity_are_explicit() {
        let value = definition();
        let bytes = encoded(&value);
        let mut expected = Vec::new();
        expected.extend_from_slice(&(value.name.len() as u32).to_le_bytes());
        expected.extend_from_slice(value.name.as_bytes());
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&1u128.to_le_bytes());
        expected.extend_from_slice(&u128::MAX.to_le_bytes());
        expected.extend_from_slice(&5u32.to_le_bytes());
        for index in 0u8..5 {
            expected.extend_from_slice(&[index; 32]);
            expected.extend_from_slice(&u32::MAX.to_le_bytes());
            expected.push(index);
        }
        assert_eq!(bytes, expected);
        let mut reader = Reader::new(&bytes);
        assert_eq!(read_definition(&mut reader).unwrap(), value);
        reader.finish().unwrap();
    }

    #[test]
    fn definitions_reject_truncation_unknown_activities_and_noncanonical_order() {
        let value = definition();
        let bytes = encoded(&value);
        for end in 0..bytes.len() {
            assert!(
                read_definition(&mut Reader::new(&bytes[..end])).is_err(),
                "prefix {end}"
            );
        }
        let mut invalid = bytes.clone();
        *invalid.last_mut().unwrap() = 5;
        assert!(read_definition(&mut Reader::new(&invalid)).is_err());
        let mut value = value;
        value.cash_accounts.reverse();
        assert!(read_definition(&mut Reader::new(&encoded(&value))).is_err());
        value.cash_accounts.reverse();
        value.assignments.reverse();
        assert!(read_definition(&mut Reader::new(&encoded(&value))).is_err());
        assert_eq!(normalize(&value).unwrap(), definition());
    }

    #[test]
    fn hostile_lengths_duplicates_and_total_envelope_bounds_fail_closed() {
        let mut w = Writer::new();
        w.str("bounded").u32(u32::MAX);
        assert!(read_definition(&mut Reader::new(&w.finish().unwrap())).is_err());
        let mut w = Writer::new();
        w.str("bounded").u32(1).u128(1).u32(u32::MAX);
        assert!(read_definition(&mut Reader::new(&w.finish().unwrap())).is_err());
        let mut value = definition();
        value.assignments.push(value.assignments[0].clone());
        assert!(normalize(&value).is_err());
        value = definition();
        value.cash_accounts.push(1);
        assert!(normalize(&value).is_err());
        value = definition();
        let overhead = envelope_size(0, &value, 0).unwrap();
        assert_eq!(
            envelope_size(MAX_CASH_FLOW_CERTIFICATE_BYTES - overhead, &value, 0).unwrap(),
            MAX_CASH_FLOW_CERTIFICATE_BYTES
        );
        assert!(envelope_size(MAX_CASH_FLOW_CERTIFICATE_BYTES - overhead, &value, 1).is_err());
        assert!(envelope_size(usize::MAX, &value, 1).is_err());
    }
}
