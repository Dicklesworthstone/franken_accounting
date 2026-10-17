//! Reusable, explicit cash classification policies (plan §12.1, fa-i9yn).
//!
//! Account rules classify NON-cash counterparts, never account names or text.
//! A cash leg inherits a class only when every nonzero non-cash counterpart in
//! the same journal entry and native unit has that one class. Mixed or unmapped
//! counterparts require an explicit whole-leg override. Amounts are never split
//! or allocated by inference. An all-cash transfer is recognized only within one
//! entry/unit across distinct declared cash accounts; the cash engine still
//! checks exact cancellation. Policy choices remain professional inputs.
//!
//! Native resolution pins one prefix and verifies each cash citation against
//! its complete entry payload. Rules for unused accounts remain in the policy
//! and must name existing historical non-cash monetary leaves. Overrides outside
//! the selected cash movement set are refused, not silently ignored. No policy
//! is activated, approved or journaled by these APIs.

mod certificate;
mod native;

pub use certificate::{
    CASH_FLOW_POLICY_CERTIFICATE_FORMAT, CashFlowPolicyCertificate, CertifiedPolicyCashFlow,
    MAX_CASH_FLOW_POLICY_CERTIFICATE_BYTES,
};

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::{Refusal, exit};
use fa_model::{DecodeError, Reader, Writer, domain_digest};

use crate::BookError;
use crate::general_ledger::{
    CashFlow, CashFlowActivity, CashFlowAssignment, CashFlowDefinition, MAX_GENERAL_LEDGER_LINES,
};

pub const CASH_FLOW_POLICY_FORMAT: &[u8] = b"fa:cash-flow-policy:v1";
pub const POLICY_CASH_FLOW_FORMAT: &[u8] = b"fa:policy-cash-flow:v1";
pub const MAX_CASH_FLOW_POLICY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_POLICY_CASH_FLOW_BYTES: usize = 64 * 1024 * 1024;
/// Cash and counterpart legs inspected for classification, not a ledger limit.
pub const MAX_CASH_FLOW_POLICY_SOURCE_LEGS: usize = 1_000_000;
const MAX_ACCOUNTS: usize = 4096;

/// Explicit treatment of a non-cash counterpart account. InternalTransfer is
/// not an account rule: it is an entry/unit-level cancellation relationship.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowAccountRule {
    pub account_id: u128,
    pub activity: CashFlowActivity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowPolicy {
    pub name: String,
    pub cash_accounts: Vec<u128>,
    pub account_rules: Vec<CashFlowAccountRule>,
    /// Whole original cash legs; explicit choices take precedence over rules.
    pub overrides: Vec<CashFlowAssignment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CashFlowDecisionBasis {
    AccountRules = 0,
    ExplicitOverride = 1,
    InternalTransfer = 2,
}

/// One derivation decision per selected original cash leg. Full counterpart
/// payloads stay in the native source closure, not in this compact transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowPolicyDecision {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub activity: CashFlowActivity,
    pub basis: CashFlowDecisionBasis,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyCashFlow {
    policy: CashFlowPolicy,
    report: CashFlow,
    decisions: Vec<CashFlowPolicyDecision>,
}

impl PolicyCashFlow {
    #[must_use]
    pub fn policy(&self) -> &CashFlowPolicy {
        &self.policy
    }
    #[must_use]
    pub fn report(&self) -> &CashFlow {
        &self.report
    }
    #[must_use]
    pub fn decisions(&self) -> &[CashFlowPolicyDecision] {
        &self.decisions
    }

    /// Exact cash output, canonical policy and derivation transcript. These
    /// bytes are a report, not a source-completeness proof or policy approval.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        canonical_report_bytes(&self.policy, &self.report.canonical_bytes()?, &self.decisions)
    }
}

/// One encoding for a live report and its intact certificate's output. The
/// certificate can reproduce these bytes without inventing another report
/// format; historical correctness still requires full native replay.
fn canonical_report_bytes(
    policy: &CashFlowPolicy,
    report: &[u8],
    decisions: &[CashFlowPolicyDecision],
) -> Result<Vec<u8>, Refusal> {
    let policy = policy.canonical_bytes()?;
    let size = decisions
        .len()
        .checked_mul(38)
        .and_then(|decisions| {
            [
                4,
                POLICY_CASH_FLOW_FORMAT.len(),
                4,
                policy.len(),
                4,
                report.len(),
                4,
                decisions,
            ]
            .into_iter()
            .try_fold(0usize, usize::checked_add)
        })
        .filter(|n| *n <= MAX_POLICY_CASH_FLOW_BYTES)
        .ok_or_else(|| invalid("policy cash-flow report exceeds its 64 MiB bound"))?;
    let mut w = Writer::with_capacity(size);
    w.bytes(POLICY_CASH_FLOW_FORMAT)
        .bytes(&policy)
        .bytes(report);
    write_decisions(&mut w, decisions);
    w.finish().map_err(|e| invalid(e.to_string()))
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §12.1 (explicit CashFlowClassification; no inferred amounts or judgment)",
        "select the exact cash scope and historical non-cash account rules; supply explicit whole-leg choices for ambiguous entries and remove out-of-scope overrides",
    )
}

#[derive(Debug)]
enum Error {
    Refusal(Refusal),
    Book(BookError),
}
impl From<Refusal> for Error {
    fn from(e: Refusal) -> Self {
        Self::Refusal(e)
    }
}
impl From<BookError> for Error {
    fn from(e: BookError) -> Self {
        Self::Book(e)
    }
}

fn outcome<T>(result: Result<T, Error>) -> crate::Outcome<T> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(Error::Refusal(e)) => Ok(Err(e)),
        Err(Error::Book(e)) => Err(e),
    }
}

fn normalize(policy: &CashFlowPolicy) -> Result<CashFlowPolicy, Refusal> {
    if policy.name.trim().is_empty()
        || policy.name.len() > 256
        || policy.cash_accounts.is_empty()
        || policy.cash_accounts.len() > MAX_ACCOUNTS
        || policy.account_rules.len() > MAX_ACCOUNTS
        || policy.overrides.len() > MAX_GENERAL_LEDGER_LINES
    {
        return Err(invalid(
            "cash-flow policy exceeds its name, account or override bounds",
        ));
    }
    let mut value = policy.clone();
    value.cash_accounts.sort_unstable();
    value
        .account_rules
        .sort_unstable_by_key(|rule| rule.account_id);
    value
        .overrides
        .sort_unstable_by_key(|a| (a.entry_digest, a.leg_index));
    if value.cash_accounts.windows(2).any(|p| p[0] == p[1])
        || value
            .account_rules
            .windows(2)
            .any(|p| p[0].account_id == p[1].account_id)
        || value
            .overrides
            .windows(2)
            .any(|p| (p[0].entry_digest, p[0].leg_index) == (p[1].entry_digest, p[1].leg_index))
        || value.account_rules.iter().any(|rule| {
            rule.activity == CashFlowActivity::InternalTransfer
                || value.cash_accounts.binary_search(&rule.account_id).is_ok()
        })
    {
        return Err(invalid(
            "policy repeats an identity, classifies a cash account as a counterpart, or uses an internal-transfer account rule",
        ));
    }
    Ok(value)
}

impl CashFlowPolicy {
    /// Input permutations normalize to one identity. Duplicates never do.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let value = normalize(self)?;
        let size = [
            Some(4),
            Some(CASH_FLOW_POLICY_FORMAT.len()),
            Some(4),
            Some(value.name.len()),
            Some(4),
            value.cash_accounts.len().checked_mul(16),
            Some(4),
            value.account_rules.len().checked_mul(17),
            Some(4),
            value.overrides.len().checked_mul(37),
        ]
        .into_iter()
        .try_fold(0usize, |sum, n| sum.checked_add(n?))
        .filter(|n| *n <= MAX_CASH_FLOW_POLICY_BYTES)
        .ok_or_else(|| invalid("cash-flow policy exceeds its 16 MiB byte bound"))?;
        let mut w = Writer::with_capacity(size);
        w.bytes(CASH_FLOW_POLICY_FORMAT)
            .str(&value.name)
            .list(&value.cash_accounts, |w, id| {
                w.u128(*id);
            })
            .list(&value.account_rules, |w, rule| {
                w.u128(rule.account_id).u8(rule.activity as u8);
            })
            .list(&value.overrides, |w, a| {
                w.fixed(&a.entry_digest)
                    .u32(a.leg_index)
                    .u8(a.activity as u8);
            });
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    pub fn digest(&self) -> Result<[u8; 32], Refusal> {
        Ok(domain_digest(
            b"fa:cash-flow-policy-digest:v1",
            &[&self.canonical_bytes()?],
        ))
    }

    /// Bounded transport validation, not historical account validation. Strict
    /// order, tags, lengths, UTF-8 and exhaustion are required before acceptance.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_CASH_FLOW_POLICY_BYTES {
            return Err(invalid("cash-flow policy exceeds its byte bound"));
        }
        let read = || -> Result<Self, DecodeError> {
            let mut r = Reader::new(bytes);
            if r.bytes(64, "cash policy format")? != CASH_FLOW_POLICY_FORMAT {
                return Err(r.invalid("unsupported cash policy format"));
            }
            let name = r.str(256, "cash policy name")?.to_string();
            let count = bounded_count(&mut r, MAX_ACCOUNTS, 16)?;
            let mut cash_accounts = Vec::with_capacity(count);
            for _ in 0..count {
                cash_accounts.push(r.u128("cash policy account")?);
            }
            let count = bounded_count(&mut r, MAX_ACCOUNTS, 17)?;
            let mut account_rules = Vec::with_capacity(count);
            for _ in 0..count {
                account_rules.push(CashFlowAccountRule {
                    account_id: r.u128("counterpart account")?,
                    activity: activity(&mut r)?,
                });
            }
            let count = bounded_count(&mut r, MAX_GENERAL_LEDGER_LINES, 37)?;
            let mut overrides = Vec::with_capacity(count);
            for _ in 0..count {
                overrides.push(CashFlowAssignment {
                    entry_digest: r.fixed("override entry")?,
                    leg_index: r.u32("override leg")?,
                    activity: activity(&mut r)?,
                });
            }
            r.finish()?;
            Ok(Self {
                name,
                cash_accounts,
                account_rules,
                overrides,
            })
        };
        let value = read().map_err(|e| invalid(format!("malformed cash policy: {e}")))?;
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("cash-flow policy encoding is not canonical"));
        }
        Ok(value)
    }
}

fn bounded_count(r: &mut Reader<'_>, max: usize, width: usize) -> Result<usize, DecodeError> {
    let count = r.count(max, "cash policy list")?;
    if count > r.remaining() / width {
        return Err(r.invalid("truncated cash policy list"));
    }
    Ok(count)
}

fn activity(r: &mut Reader<'_>) -> Result<CashFlowActivity, DecodeError> {
    Ok(match r.u8("cash policy activity")? {
        0 => CashFlowActivity::Operating,
        1 => CashFlowActivity::Investing,
        2 => CashFlowActivity::Financing,
        3 => CashFlowActivity::ExchangeEffect,
        4 => CashFlowActivity::InternalTransfer,
        _ => return Err(r.invalid("unknown cash policy activity")),
    })
}

fn write_decisions(w: &mut Writer, decisions: &[CashFlowPolicyDecision]) {
    w.list(decisions, |w, d| {
        w.fixed(&d.entry_digest)
            .u32(d.leg_index)
            .u8(d.activity as u8)
            .u8(d.basis as u8);
    });
}

/// No amount weights or netted counterpart balances enter this decision.
fn automatic(
    counterparts: &BTreeSet<u128>,
    cash_accounts: usize,
    rules: &BTreeMap<u128, CashFlowActivity>,
) -> Option<(CashFlowActivity, CashFlowDecisionBasis)> {
    if counterparts.is_empty() {
        return (cash_accounts >= 2).then_some((
            CashFlowActivity::InternalTransfer,
            CashFlowDecisionBasis::InternalTransfer,
        ));
    }
    let first = *rules.get(counterparts.first()?)?;
    counterparts
        .iter()
        .all(|id| rules.get(id) == Some(&first))
        .then_some((first, CashFlowDecisionBasis::AccountRules))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> CashFlowPolicy {
        CashFlowPolicy {
            name: "Cash policy € v1".into(),
            cash_accounts: vec![2, 1],
            account_rules: vec![
                CashFlowAccountRule {
                    account_id: 5,
                    activity: CashFlowActivity::Operating,
                },
                CashFlowAccountRule {
                    account_id: 4,
                    activity: CashFlowActivity::Financing,
                },
            ],
            overrides: vec![CashFlowAssignment {
                entry_digest: [9; 32],
                leg_index: 3,
                activity: CashFlowActivity::Investing,
            }],
        }
    }
    #[test]
    fn permutations_roundtrip_and_every_policy_choice_changes_identity() {
        let p = policy();
        let bytes = p.canonical_bytes().unwrap();
        let q = CashFlowPolicy::decode(&bytes).unwrap();
        assert_eq!(q, normalize(&p).unwrap());
        assert_eq!(q.digest().unwrap(), p.digest().unwrap());
        let mut changed = p.clone();
        changed.account_rules[0].activity = CashFlowActivity::Investing;
        assert_ne!(changed.digest().unwrap(), p.digest().unwrap());
        let mut changed = p;
        changed.name.push('2');
        assert_ne!(changed.canonical_bytes().unwrap(), bytes);
    }
    #[test]
    fn every_truncation_trailing_data_and_hostile_list_are_refused() {
        let bytes = policy().canonical_bytes().unwrap();
        for n in 0..bytes.len() {
            assert!(CashFlowPolicy::decode(&bytes[..n]).is_err(), "prefix {n}");
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(CashFlowPolicy::decode(&bad).is_err());
        let mut bad = bytes;
        let offset = 4 + CASH_FLOW_POLICY_FORMAT.len() + 4 + policy().name.len();
        bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(CashFlowPolicy::decode(&bad).is_err());
    }
    #[test]
    fn duplicate_and_cash_counterpart_rules_are_not_normalized_away() {
        let p = policy();
        let mut q = p.clone();
        q.cash_accounts.push(1);
        assert!(q.canonical_bytes().is_err());
        let mut q = p.clone();
        q.account_rules.push(q.account_rules[0].clone());
        assert!(q.canonical_bytes().is_err());
        let mut q = p.clone();
        q.overrides.push(q.overrides[0].clone());
        assert!(q.canonical_bytes().is_err());
        let mut q = p.clone();
        q.account_rules[0].account_id = 1;
        assert!(q.canonical_bytes().is_err());
        let mut q = p;
        q.account_rules[0].activity = CashFlowActivity::InternalTransfer;
        assert!(q.canonical_bytes().is_err());
    }
    #[test]
    fn mixed_unmapped_and_same_account_roundtrips_need_explicit_decisions() {
        let rules = BTreeMap::from([
            (4, CashFlowActivity::Operating),
            (5, CashFlowActivity::Investing),
            (6, CashFlowActivity::Operating),
        ]);
        assert_eq!(
            automatic(&BTreeSet::from([4, 6]), 1, &rules),
            Some((
                CashFlowActivity::Operating,
                CashFlowDecisionBasis::AccountRules
            ))
        );
        assert!(automatic(&BTreeSet::from([4, 5]), 2, &rules).is_none());
        assert!(automatic(&BTreeSet::from([4, 7]), 2, &rules).is_none());
        assert!(automatic(&BTreeSet::new(), 1, &rules).is_none());
        assert_eq!(
            automatic(&BTreeSet::new(), 2, &rules),
            Some((
                CashFlowActivity::InternalTransfer,
                CashFlowDecisionBasis::InternalTransfer
            ))
        );
    }
    #[test]
    fn wire_layout_tags_and_order_are_independently_checked() {
        let p = CashFlowPolicy {
            name: "P".into(),
            cash_accounts: vec![1],
            account_rules: vec![CashFlowAccountRule {
                account_id: 2,
                activity: CashFlowActivity::Operating,
            }],
            overrides: vec![CashFlowAssignment {
                entry_digest: [9; 32],
                leg_index: 3,
                activity: CashFlowActivity::Financing,
            }],
        };
        let mut expected = (CASH_FLOW_POLICY_FORMAT.len() as u32)
            .to_le_bytes()
            .to_vec();
        expected.extend_from_slice(CASH_FLOW_POLICY_FORMAT);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.push(b'P');
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&1u128.to_le_bytes());
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&2u128.to_le_bytes());
        expected.push(0);
        expected.extend_from_slice(&1u32.to_le_bytes());
        expected.extend_from_slice(&[9; 32]);
        expected.extend_from_slice(&3u32.to_le_bytes());
        expected.push(2);
        assert_eq!(p.canonical_bytes().unwrap(), expected);
        *expected.last_mut().unwrap() = 5;
        assert!(CashFlowPolicy::decode(&expected).is_err());
        let mut p = p;
        p.cash_accounts = vec![1, 3];
        let mut bytes = p.canonical_bytes().unwrap();
        let offset = 4 + CASH_FLOW_POLICY_FORMAT.len() + 4 + 1 + 4;
        bytes[offset..offset + 16].copy_from_slice(&3u128.to_le_bytes());
        bytes[offset + 16..offset + 32].copy_from_slice(&1u128.to_le_bytes());
        assert!(CashFlowPolicy::decode(&bytes).is_err());
    }
}
