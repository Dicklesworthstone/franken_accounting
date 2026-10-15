//! Replay the policy decision, not merely an already classified cash total.
//!
//! The nested cash certificate authenticates the complete native input closure.
//! This envelope binds the policy, including unused rules, and every derivation
//! basis. Replay resolves the independently expected policy from original entry
//! payloads before checking the nested cash output. Hashes alone grant no trust.
//! Whole-book native evidence is confidential; this is neither a scoped outsider
//! proof nor a journaled policy activation, approval or accounting opinion.

use asupersync::fs::Vfs;
use fa_policy::Capability;
use fgdb_types::{CommitSeq, VId, context::PurposeContexts};

use super::*;
use crate::{AsyncBook, CashFlowCertificate, Outcome, RollForwardRequest};

pub const CASH_FLOW_POLICY_CERTIFICATE_FORMAT: &[u8] = b"fa:cash-flow-policy-certificate:v1";
pub const MAX_CASH_FLOW_POLICY_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const DIGEST_DOMAIN: &[u8] = b"fa:cash-flow-policy-certificate-digest:v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowPolicyCertificate {
    source: CashFlowCertificate,
    policy: CashFlowPolicy,
    decisions: Vec<CashFlowPolicyDecision>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedPolicyCashFlow {
    report: PolicyCashFlow,
    certificate: CashFlowPolicyCertificate,
}

impl CertifiedPolicyCashFlow {
    #[must_use]
    pub fn report(&self) -> &PolicyCashFlow { &self.report }
    #[must_use]
    pub fn certificate(&self) -> &CashFlowPolicyCertificate { &self.certificate }
    #[must_use]
    pub fn into_certificate(self) -> CashFlowPolicyCertificate { self.certificate }
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(crate::certificate::code::CERTIFICATE_INVALID, exit::VERIFICATION, message,
        "plan §12.1 / §13.6 (cash policy and its native derivation must replay)",
        "use independently retained policy and fixed scope with the original book; neither equal cash totals nor a recomputed content digest verifies a policy derivation")
}
fn as_invalid(r: Refusal) -> Refusal { invalid(r.message) }

fn size(source: usize, policy: usize, count: usize) -> Result<usize, Refusal> {
    if count > MAX_GENERAL_LEDGER_LINES { return Err(invalid("too many policy decisions")); }
    count.checked_mul(38).and_then(|n| {
        [4, CASH_FLOW_POLICY_CERTIFICATE_FORMAT.len(), 4, source, 4, policy, 4, n, 32]
            .into_iter().try_fold(0usize, usize::checked_add)
    }).filter(|n| *n <= MAX_CASH_FLOW_POLICY_CERTIFICATE_BYTES)
        .ok_or_else(|| invalid("cash policy certificate exceeds its 64 MiB total bound"))
}

/// Structural binding only. Actual counterpart classifications require replay.
fn bind(policy: &CashFlowPolicy, decisions: &[CashFlowPolicyDecision], definition: &CashFlowDefinition) -> Result<(), Refusal> {
    if normalize(policy).map_err(as_invalid)? != *policy || policy.name != definition.name
        || policy.cash_accounts != definition.cash_accounts
        || decisions.len() > MAX_GENERAL_LEDGER_LINES || decisions.len() != definition.assignments.len()
        || decisions.windows(2).any(|p| (p[0].entry_digest, p[0].leg_index) >= (p[1].entry_digest, p[1].leg_index))
    { return Err(invalid("cash policy certificate has a noncanonical policy, scope or decision set")); }
    let mut overrides: BTreeMap<_, _> = policy.overrides.iter().map(|a| ((a.entry_digest, a.leg_index), a.activity)).collect();
    for (d, a) in decisions.iter().zip(&definition.assignments) {
        if (d.entry_digest, d.leg_index, d.activity) != (a.entry_digest, a.leg_index, a.activity) {
            return Err(invalid("policy decision differs from its nested cash classification"));
        }
        match overrides.remove(&(d.entry_digest, d.leg_index)) {
            Some(activity) if d.basis == CashFlowDecisionBasis::ExplicitOverride && d.activity == activity => {},
            Some(_) => return Err(invalid("policy override and decision disagree")),
            None if d.basis == CashFlowDecisionBasis::ExplicitOverride => return Err(invalid("decision claims an absent explicit override")),
            None => {},
        }
        if (d.basis == CashFlowDecisionBasis::InternalTransfer && d.activity != CashFlowActivity::InternalTransfer)
            || (d.basis == CashFlowDecisionBasis::AccountRules && d.activity == CashFlowActivity::InternalTransfer)
        { return Err(invalid("internal-transfer decision has an invalid derivation basis")); }
    }
    if !overrides.is_empty() { return Err(invalid("policy certificate has an unused override")); }
    Ok(())
}

fn read_decisions(r: &mut Reader<'_>) -> Result<Vec<CashFlowPolicyDecision>, DecodeError> {
    let count = bounded_count(r, MAX_GENERAL_LEDGER_LINES, 38)?;
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let entry_digest = r.fixed("policy decision entry")?;
        let leg_index = r.u32("policy decision leg")?;
        let activity = activity(r)?;
        let basis = match r.u8("policy decision basis")? {
            0 => CashFlowDecisionBasis::AccountRules, 1 => CashFlowDecisionBasis::ExplicitOverride,
            2 => CashFlowDecisionBasis::InternalTransfer,
            _ => return Err(r.invalid("unknown cash policy decision basis")),
        };
        values.push(CashFlowPolicyDecision { entry_digest, leg_index, activity, basis });
    }
    Ok(values)
}

impl CashFlowPolicyCertificate {
    #[must_use]
    pub fn source_certificate(&self) -> &CashFlowCertificate { &self.source }
    #[must_use]
    pub fn policy(&self) -> &CashFlowPolicy { &self.policy }
    #[must_use]
    pub fn decisions(&self) -> &[CashFlowPolicyDecision] { &self.decisions }
    #[must_use]
    pub fn request(&self) -> &RollForwardRequest { self.source.request() }
    #[must_use]
    pub fn known_at(&self) -> CommitSeq { self.source.known_at() }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] { &self.digest }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        bind(&self.policy, &self.decisions, self.source.definition())?;
        let source = self.source.canonical_bytes()?;
        let policy = self.policy.canonical_bytes().map_err(as_invalid)?;
        let mut w = Writer::with_capacity(size(source.len(), policy.len(), self.decisions.len())?);
        w.bytes(CASH_FLOW_POLICY_CERTIFICATE_FORMAT).bytes(&source).bytes(&policy);
        write_decisions(&mut w, &self.decisions);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(source: CashFlowCertificate, report: &PolicyCashFlow) -> Result<Self, Refusal> {
        if source.output() != report.report.canonical_bytes().map_err(as_invalid)?.as_slice() {
            return Err(invalid("policy report differs from its certified cash source"));
        }
        let mut value = Self { source, policy: normalize(&report.policy).map_err(as_invalid)?,
            decisions: report.decisions.clone(), digest: [0; 32] };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&body]) != self.digest {
            return Err(invalid("cash policy certificate content digest differs"));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    /// Framing and unkeyed integrity only. Do not adopt a delivered policy or
    /// cutoff as the independent expected inputs to its own verification.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_CASH_FLOW_POLICY_CERTIFICATE_BYTES {
            return Err(invalid("cash policy certificate exceeds its total byte bound"));
        }
        let malformed = |e: DecodeError| invalid(format!("malformed cash policy certificate: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "policy certificate format").map_err(malformed)? != CASH_FLOW_POLICY_CERTIFICATE_FORMAT {
            return Err(invalid("unsupported cash policy certificate format"));
        }
        let source = CashFlowCertificate::decode(r.bytes(MAX_CASH_FLOW_POLICY_CERTIFICATE_BYTES,
            "policy certified native source").map_err(malformed)?)?;
        let policy = CashFlowPolicy::decode(r.bytes(MAX_CASH_FLOW_POLICY_BYTES,
            "certificate policy").map_err(malformed)?).map_err(as_invalid)?;
        let decisions = read_decisions(&mut r).map_err(malformed)?;
        let digest = r.fixed("policy certificate digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self { source, policy, decisions, digest };
        if value.canonical_bytes()?.as_slice() != bytes { return Err(invalid("noncanonical cash policy certificate")); }
        Ok(value)
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Current Read+Produce authority precedes policy/source observation. Fix
    /// HEAD once, derive classifications from that complete native snapshot,
    /// and certify through the original cash engine. The two native source
    /// certificates must be identical; a changed closure is never substituted.
    /// This composes existing certified readers, not a new posting/fold path.
    pub fn certify_cash_flow_with_policy(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        request: &RollForwardRequest, policy: &CashFlowPolicy,
    ) -> Outcome<CertifiedPolicyCashFlow> {
        let native = match self.certify_general_ledger(cx, principal, capability, request)? {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        let resolved = match native::resolve(self, cx, native.report(), policy)? {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        let source = match self.certify_cash_flow(cx, principal, capability,
            native.source_certificate().request(), &resolved.definition)? {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        if source.certificate().source_certificate() != native.source_certificate() {
            return Ok(Err(invalid("native source changed during policy certification")));
        }
        let report = PolicyCashFlow { policy: resolved.policy, report: source.report().clone(), decisions: resolved.decisions };
        let certificate = match CashFlowPolicyCertificate::seal(source.into_certificate(), &report) {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(CertifiedPolicyCashFlow { report, certificate }))
    }

    /// Current Read authority, independent fixed scope AND expected full policy
    /// are mandatory. Native history is authenticated before resolving original
    /// counterpart entries. Never treat delivered per-leg assignments as the
    /// recipient's expected classifications. The original cash replay verifies
    /// all financial bytes; the outer check also verifies every derivation basis.
    pub fn replay_cash_flow_with_policy(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        certificate: &CashFlowPolicyCertificate, expected: &RollForwardRequest,
        expected_policy: &CashFlowPolicy,
    ) -> Outcome<PolicyCashFlow> {
        let ledger = match self.replay_general_ledger(cx, principal, capability,
            certificate.source.source_certificate(), expected)? {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        let policy = match normalize(expected_policy).map_err(as_invalid) {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        if policy != certificate.policy { return Ok(Err(invalid("delivered cash policy differs from the independent expected policy"))); }
        if let Err(r) = certificate.canonical_bytes() { return Ok(Err(r)); }
        let resolved = match native::resolve(self, cx, &ledger, &policy)? {
            Ok(v) => v, Err(r) => return Ok(Err(as_invalid(r))),
        };
        if resolved.decisions != certificate.decisions || &resolved.definition != certificate.source.definition() {
            return Ok(Err(invalid("cash policy decisions did not reproduce from the original native counterparts")));
        }
        let report = match self.replay_cash_flow(cx, principal, capability, &certificate.source,
            expected, &resolved.definition)? {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(PolicyCashFlow { policy, report, decisions: resolved.decisions }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn total_size_bound_includes_policy_decisions_and_digest() {
        let overhead = 4 + CASH_FLOW_POLICY_CERTIFICATE_FORMAT.len() + 4 + 4 + 4 + 32;
        assert_eq!(size(10, 20, 2).unwrap(), overhead + 10 + 20 + 76);
        assert_eq!(size(MAX_CASH_FLOW_POLICY_CERTIFICATE_BYTES - overhead, 0, 0).unwrap(), MAX_CASH_FLOW_POLICY_CERTIFICATE_BYTES);
        assert!(size(MAX_CASH_FLOW_POLICY_CERTIFICATE_BYTES - overhead + 1, 0, 0).is_err());
        assert!(size(usize::MAX, 0, 0).is_err());
        assert!(size(0, 0, MAX_GENERAL_LEDGER_LINES + 1).is_err());
    }
    #[test]
    fn decision_wire_layout_unknown_basis_and_truncation_are_checked() {
        let d = CashFlowPolicyDecision { entry_digest: [9; 32], leg_index: 7,
            activity: CashFlowActivity::Operating, basis: CashFlowDecisionBasis::AccountRules };
        let mut w = Writer::new(); write_decisions(&mut w, std::slice::from_ref(&d)); let bytes = w.finish().unwrap();
        let mut expected = 1u32.to_le_bytes().to_vec(); expected.extend_from_slice(&[9; 32]);
        expected.extend_from_slice(&7u32.to_le_bytes()); expected.extend_from_slice(&[0, 0]);
        assert_eq!(bytes, expected);
        assert_eq!(read_decisions(&mut Reader::new(&bytes)).unwrap(), [d]);
        for n in 0..bytes.len() { assert!(read_decisions(&mut Reader::new(&bytes[..n])).is_err()); }
        *expected.last_mut().unwrap() = 3;
        assert!(read_decisions(&mut Reader::new(&expected)).is_err());
    }
    #[test]
    fn a_matching_activity_does_not_justify_an_unrecorded_override() {
        let a = CashFlowAssignment { entry_digest: [1; 32], leg_index: 0, activity: CashFlowActivity::Operating };
        let p = CashFlowPolicy { name: "P".into(), cash_accounts: vec![1], account_rules: Vec::new(), overrides: Vec::new() };
        let definition = CashFlowDefinition { name: "P".into(), cash_accounts: vec![1], assignments: vec![a.clone()] };
        let d = CashFlowPolicyDecision { entry_digest: a.entry_digest, leg_index: 0,
            activity: a.activity, basis: CashFlowDecisionBasis::ExplicitOverride };
        assert!(bind(&p, std::slice::from_ref(&d), &definition).is_err());
        let mut p = p; p.overrides.push(a); bind(&p, std::slice::from_ref(&d), &definition).unwrap();
        let mut wrong = d; wrong.basis = CashFlowDecisionBasis::AccountRules;
        assert!(bind(&p, &[wrong], &definition).is_err());
    }
}
