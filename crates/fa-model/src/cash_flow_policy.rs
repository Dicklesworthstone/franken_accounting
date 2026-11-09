//! Immutable, versioned non-cash account classification for cash-flow reports.
//!
//! The model validates canonical shape only. Activation separately validates
//! historical chart membership, current authority and two independent approvals.

use crate::{
    ControlKind, ControlPayload, DecodeError, EncodeError, EntryClass, EntryError, EntryOrigin,
    EntryPayload, Id128, Reader, TypedRef, Writer, domain_digest, entry_vid,
};

pub const CASH_FLOW_POLICY_DEFINITION_FORMAT: &[u8] = b"fa:cash-flow-policy-definition:v1";
pub const CASH_FLOW_POLICY_ACTIVATION_REASON: u16 = 0x4346;
const MAX_ACCOUNTS: usize = 4096;

/// A reusable classification map. Activity tags retain the cash report's
/// Operating=0, Investing=1, Financing=2 and ExchangeEffect=3 contract.
/// Internal transfers are determined from complete cash entry pairs, never
/// assigned to a non-cash account. Per-entry overrides remain explicit inputs
/// to individual reports rather than permanent rules on a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowPolicyDefinition {
    pub name: String,
    pub version: u32,
    pub cash_accounts: Vec<u128>,
    pub account_rules: Vec<(u128, u8)>,
}

impl CashFlowPolicyDefinition {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.name.is_empty()
            || self.name.len() > 64
            || !self
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || self.version == 0
        {
            return Err("cash policy needs a bounded ASCII name and positive version");
        }
        if self.cash_accounts.is_empty()
            || self.cash_accounts.len() > MAX_ACCOUNTS
            || self.account_rules.len() > MAX_ACCOUNTS
            || self.cash_accounts.windows(2).any(|p| p[0] >= p[1])
            || self.account_rules.windows(2).any(|p| p[0].0 >= p[1].0)
            || self
                .account_rules
                .iter()
                .any(|(id, activity)| *activity > 3 || self.cash_accounts.binary_search(id).is_ok())
        {
            return Err(
                "cash accounts and counterpart rules must be bounded, ordered, unique and disjoint, with activity tags 0..3",
            );
        }
        let size = CASH_FLOW_POLICY_DEFINITION_FORMAT.len()
            + 4
            + 4
            + self.name.len()
            + 4
            + 4
            + 4
            + self.cash_accounts.len() * 16
            + self.account_rules.len() * 17;
        if size > crate::limits::MAX_CASH_FLOW_POLICY_DEFINITION_BYTES {
            return Err(
                "cash policy exceeds max_cash_flow_policy_definition_bytes; reduce the classification map",
            );
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.bytes(CASH_FLOW_POLICY_DEFINITION_FORMAT)
            .str(&self.name)
            .u32(self.version)
            .list(&self.cash_accounts, |w, id| {
                w.u128(*id);
            })
            .list(&self.account_rules, |w, (id, activity)| {
                w.u128(*id).u8(*activity);
            });
        w.finish()
    }

    pub fn digest(&self) -> Result<[u8; 32], EncodeError> {
        Ok(domain_digest(
            b"fa:cash-flow-policy-definition-digest:v1",
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn decode(encoded: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(encoded);
        if encoded.len() > crate::limits::MAX_CASH_FLOW_POLICY_DEFINITION_BYTES
            || r.bytes(64, "cash_policy.format")? != CASH_FLOW_POLICY_DEFINITION_FORMAT
        {
            return Err(r.invalid("cash_policy.format"));
        }
        let value = Self {
            name: r.str(64, "cash_policy.name")?.to_string(),
            version: r.u32("cash_policy.version")?,
            cash_accounts: r.list(MAX_ACCOUNTS, "cash_policy.cash_accounts", |r| {
                r.u128("cash_policy.cash_account")
            })?,
            account_rules: r.list(MAX_ACCOUNTS, "cash_policy.account_rules", |r| {
                Ok((
                    r.u128("cash_policy.counterpart")?,
                    r.u8("cash_policy.activity")?,
                ))
            })?,
        };
        if value.validate().is_err() {
            return Err(r.invalid("cash_policy.definition"));
        }
        r.finish()?;
        Ok(value)
    }
}

/// Structural discriminator only. Historical chart membership and approval
/// authority are enforced by the dedicated native activation operation.
#[must_use]
pub fn is_activation_entry(proposal: &EntryPayload) -> bool {
    proposal
        .extensions
        .iter()
        .any(|(tag, _)| *tag == crate::entry::CASH_FLOW_POLICY)
        && validate_entry(proposal).is_ok()
}

/// Register the reason and extension together: neither can be used alone, on
/// a monetary entry, with a substituted target, or with unrelated effects.
pub(crate) fn validate_entry(proposal: &EntryPayload) -> Result<(), EntryError> {
    let error = || EntryError::Invalid {
        what: "extensions.cash_flow_policy",
        why: "requires a canonical policy body on its own self-targeted PolicyControl activation at minor 11, with a matching origin digest and one chart proof",
    };
    let extension = proposal
        .extensions
        .iter()
        .find(|(tag, _)| *tag == crate::entry::CASH_FLOW_POLICY);
    let reason = proposal.class == EntryClass::POLICY_CONTROL
        && matches!(
            &proposal.control,
            Some(ControlPayload::LifecycleTransition {
                reason_code: CASH_FLOW_POLICY_ACTIVATION_REASON,
                ..
            })
        );
    if extension.is_none() && !reason {
        return Ok(());
    }
    let (_, bytes) = extension.ok_or_else(error)?;
    let definition = CashFlowPolicyDefinition::decode(bytes).map_err(|_| error())?;
    let definition_digest = definition.digest().map_err(|_| error())?;
    if proposal.schema_minor < crate::entry::CASH_FLOW_POLICY_MINOR
        || proposal.class != EntryClass::POLICY_CONTROL
        || proposal.branch_id != Id128::TRUNK
        || proposal.document_date.is_some()
        || proposal.effective_period.is_some()
        || !proposal.legs.is_empty()
        || !proposal.unit_totals.is_empty()
        || proposal.base_totals.is_some()
        || proposal.idempotency_key.is_empty()
        || proposal.idempotency_key.len() > crate::limits::MAX_IDEMPOTENCY_KEY_BYTES
        || proposal.session_ref.is_some()
        || !proposal.evidence.is_empty()
        || !proposal.supersession.is_empty()
        || proposal.pending.is_some()
        || !proposal.external_ids.is_empty()
        || !proposal.tags.is_empty()
        || proposal.extensions.len() != 1
        || !matches!(&proposal.origin, EntryOrigin::Control {
            control_kind: ControlKind::POLICY_ACTIVATION, spec_body_digest,
        } if *spec_body_digest == definition_digest)
        || !matches!(&proposal.control, Some(ControlPayload::LifecycleTransition {
            object_ref, from: 0, to: 1, proof_refs, reason_code: CASH_FLOW_POLICY_ACTIVATION_REASON,
        }) if *object_ref == entry_vid(proposal.book_id, &proposal.principal_ref.0.to_le_bytes(), &proposal.idempotency_key)
            && matches!(proof_refs.as_slice(), [TypedRef::Object(_)]))
    {
        return Err(error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition() -> CashFlowPolicyDefinition {
        CashFlowPolicyDefinition {
            name: "company-cash".into(),
            version: 1,
            cash_accounts: vec![1, 2],
            account_rules: vec![(3, 0), (4, 1), (5, 2), (6, 3)],
        }
    }

    #[test]
    fn cash_policy_body_is_bounded_canonical_and_versioned() {
        let value = definition();
        let bytes = value.canonical_bytes().unwrap();
        assert_eq!(CashFlowPolicyDefinition::decode(&bytes).unwrap(), value);
        for end in 0..bytes.len() {
            assert!(
                CashFlowPolicyDefinition::decode(&bytes[..end]).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(CashFlowPolicyDefinition::decode(&trailing).is_err());
        let mut changed = value.clone();
        changed.version = 2;
        assert_ne!(changed.digest().unwrap(), value.digest().unwrap());
        for invalid in 0..6 {
            let mut value = definition();
            match invalid {
                0 => value.version = 0,
                1 => value.cash_accounts.push(2),
                2 => value.account_rules[0].0 = 1,
                3 => value.account_rules[0].1 = 4,
                4 => value.name = "not a policy name".into(),
                _ => value.account_rules = (10..4106).map(|id| (id, 0)).collect(),
            }
            assert!(value.validate().is_err());
            assert!(CashFlowPolicyDefinition::decode(&value.canonical_bytes().unwrap()).is_err());
        }
    }
}
