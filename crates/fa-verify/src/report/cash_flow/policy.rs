//! Reproduce policy decisions from every nonzero original counterpart leg.
//! A matching cash total does not prove that the declared policy produced it.

use super::{
    CashFlowActivity, CashFlowAssignment, MAX_ACCOUNTS, MAX_LINES, VerifiedCashFlow, accounts,
    add_size, assignment_key, assignments, body, recognizes_format, writer,
};
use crate::codec::{Reader, Writer};
use crate::envelope::{KIND_ENTRY, LeafEnvelope, Leg};
use crate::report::metadata::Schema;
use crate::report::{MAX_REPORT_BUNDLE_BYTES, ReportError, failed, text};
use std::collections::{BTreeMap, BTreeSet};

const FORMAT: &[u8] = b"fa:cash-flow-policy-certificate:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:cash-flow-policy-certificate-digest:v1";
const POLICY_FORMAT: &[u8] = b"fa:cash-flow-policy:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:policy-cash-flow:v1";
const MAX_POLICY_BYTES: usize = 16 * 1024 * 1024;
const MAX_SOURCE_LEGS: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowAccountRule {
    pub account_id: u128,
    pub activity: CashFlowActivity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum CashFlowDecisionBasis {
    AccountRules = 0,
    ExplicitOverride = 1,
    InternalTransfer = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowPolicyDecision {
    pub entry_digest: [u8; 32],
    pub leg_index: u32,
    pub activity: CashFlowActivity,
    pub basis: CashFlowDecisionBasis,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CashFlowPolicy {
    pub name: String,
    pub cash_accounts: Vec<u128>,
    pub account_rules: Vec<CashFlowAccountRule>,
    pub overrides: Vec<CashFlowAssignment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCashFlowPolicy {
    /// The direct cash certificate whose assignments these decisions derive.
    pub source_certificate_digest: [u8; 32],
    pub policy: CashFlowPolicy,
    pub decisions: Vec<CashFlowPolicyDecision>,
}

pub(in crate::report) struct Certificate<'a> {
    pub source: &'a [u8],
    pub policy: CashFlowPolicy,
    policy_bytes: &'a [u8],
    pub decisions: Vec<CashFlowPolicyDecision>,
    pub digest: [u8; 32],
}

pub(in crate::report) fn recognizes(bytes: &[u8]) -> bool {
    recognizes_format(bytes, FORMAT)
}

fn invalid(message: &'static str) -> ReportError {
    failed("cash_flow_policy", message)
}

fn read_policy(bytes: &[u8]) -> Result<CashFlowPolicy, ReportError> {
    let mut r = Reader::new(bytes);
    if r.bytes(64, "cash.policy_format")? != POLICY_FORMAT {
        return Err(invalid("unsupported cash policy format"));
    }
    let name = text(&mut r, 256, "cash.policy_name")?.to_string();
    let cash_accounts = accounts(&mut r)?;
    let count = r.count(MAX_ACCOUNTS, 17, "cash.account_rules")?;
    let mut account_rules = Vec::with_capacity(count);
    for _ in 0..count {
        let account_id = r.u128("cash.rule_account")?;
        let activity = CashFlowActivity::read(&mut r)?;
        if activity == CashFlowActivity::InternalTransfer
            || cash_accounts.binary_search(&account_id).is_ok()
        {
            return Err(invalid(
                "cash policy cannot use a cash account or internal-transfer activity as a counterpart rule",
            ));
        }
        account_rules.push(CashFlowAccountRule {
            account_id,
            activity,
        });
    }
    let overrides = assignments(&mut r)?;
    r.finish("cash policy")?;
    if name.trim().is_empty()
        || !account_rules
            .windows(2)
            .all(|p| p[0].account_id < p[1].account_id)
    {
        return Err(invalid(
            "cash policy name or counterpart-rule order is invalid",
        ));
    }
    Ok(CashFlowPolicy {
        name,
        cash_accounts,
        account_rules,
        overrides,
    })
}

pub(in crate::report) fn decode(bytes: &[u8]) -> Result<Certificate<'_>, ReportError> {
    let (mut r, digest) = body(bytes, FORMAT, DIGEST_DOMAIN)?;
    let source = r.bytes(MAX_REPORT_BUNDLE_BYTES, "cash.policy_source")?;
    if !super::recognizes(source) {
        return Err(failed(
            "supported_report",
            "cash policy requires a direct cash-flow source",
        ));
    }
    let policy_bytes = r.bytes(MAX_POLICY_BYTES, "cash.policy")?;
    let policy = read_policy(policy_bytes)?;
    let count = r.count(MAX_LINES, 38, "cash.decisions")?;
    let mut decisions = Vec::with_capacity(count);
    for _ in 0..count {
        decisions.push(CashFlowPolicyDecision {
            entry_digest: r.fixed("cash.decision_entry")?,
            leg_index: r.u32("cash.decision_leg")?,
            activity: CashFlowActivity::read(&mut r)?,
            basis: match r.u8("cash.decision_basis")? {
                0 => CashFlowDecisionBasis::AccountRules,
                1 => CashFlowDecisionBasis::ExplicitOverride,
                2 => CashFlowDecisionBasis::InternalTransfer,
                _ => return Err(invalid("unknown cash decision basis")),
            },
        });
    }
    r.finish("cash policy certificate")?;
    if !decisions
        .windows(2)
        .all(|p| (p[0].entry_digest, p[0].leg_index) < (p[1].entry_digest, p[1].leg_index))
    {
        return Err(invalid(
            "cash policy decisions repeat a leg or are unordered",
        ));
    }
    Ok(Certificate {
        source,
        policy,
        policy_bytes,
        decisions,
        digest,
    })
}

#[derive(Default)]
struct Group {
    cash_accounts: BTreeSet<u128>,
    counterparts: BTreeSet<u128>,
    legs: Vec<u32>,
}

fn automatic(
    group: &Group,
    rules: &BTreeMap<u128, CashFlowActivity>,
) -> Option<(CashFlowActivity, CashFlowDecisionBasis)> {
    if group.counterparts.is_empty() {
        return (group.cash_accounts.len() >= 2).then_some((
            CashFlowActivity::InternalTransfer,
            CashFlowDecisionBasis::InternalTransfer,
        ));
    }
    let first = *rules.get(group.counterparts.first()?)?;
    group
        .counterparts
        .iter()
        .all(|id| rules.get(id) == Some(&first))
        .then_some((first, CashFlowDecisionBasis::AccountRules))
}

#[allow(clippy::too_many_arguments)]
pub(in crate::report) fn replay(
    certificate: &Certificate<'_>,
    report: &mut VerifiedCashFlow,
    source_digest: [u8; 32],
    cash_output: &[u8],
    schema: &Schema,
    envelopes: &[LeafEnvelope],
    legs: &[Vec<Leg>],
    by_digest: &BTreeMap<[u8; 32], usize>,
) -> Result<Vec<u8>, ReportError> {
    let policy = &certificate.policy;
    let ledger = &report.ledger;
    if policy.name != report.definition.name
        || policy.cash_accounts != report.definition.cash_accounts
        || certificate.decisions.len() != report.definition.assignments.len()
    {
        return Err(invalid(
            "policy, cash definition and decision scope disagree",
        ));
    }
    for rule in &policy.account_rules {
        if !schema
            .accounts
            .get(&rule.account_id)
            .is_some_and(|a| a.is_leaf && (1..=5).contains(&a.account_type))
        {
            return Err(invalid(
                "every counterpart rule must name an existing historical monetary leaf, including unused rules",
            ));
        }
    }
    let cash: BTreeSet<_> = policy.cash_accounts.iter().copied().collect();
    let rules: BTreeMap<_, _> = policy
        .account_rules
        .iter()
        .map(|r| (r.account_id, r.activity))
        .collect();
    let mut overrides: BTreeMap<_, _> = policy
        .overrides
        .iter()
        .map(|a| (assignment_key(a), a.activity))
        .collect();
    let mut expected = BTreeMap::new();
    let mut wanted = BTreeSet::new();
    let mut wanted_groups = BTreeSet::new();
    for line in &ledger.lines {
        let cell = &ledger.cells[line.cell_index as usize];
        if expected
            .insert((line.entry_digest, line.leg_index), (line, cell))
            .is_some()
        {
            return Err(invalid("cash ledger repeats a citation"));
        }
        wanted.insert(line.entry_digest);
        wanted_groups.insert((line.entry_digest, cell.unit_id));
    }
    let mut inspected = 0usize;
    let mut groups: BTreeMap<([u8; 32], u32), Group> = BTreeMap::new();
    for digest in wanted {
        let index = *by_digest.get(&digest).ok_or_else(|| {
            invalid("cash entry is absent from the complete authenticated prefix")
        })?;
        let entry = &envelopes[index];
        if entry.kind != KIND_ENTRY
            || entry.book_id != ledger.book_id
            || entry.branch_id != [0; 16]
            || entry.commit_seq > ledger.known_at
            || !(1..=15).contains(&entry.class)
            || entry.class == 2
        {
            return Err(invalid(
                "cash counterpart source has another identity, selection or posting class",
            ));
        }
        for (ordinal, leg) in legs[index].iter().enumerate() {
            if leg.mantissa == 0 || !wanted_groups.contains(&(digest, leg.unit)) {
                continue;
            }
            if leg.mantissa < 0 || inspected == MAX_SOURCE_LEGS {
                return Err(invalid(
                    "cash policy exceeds one million relevant nonzero source legs or contains a negative magnitude",
                ));
            }
            inspected += 1;
            let group = groups.entry((digest, leg.unit)).or_default();
            if !cash.contains(&leg.account) {
                group.counterparts.insert(leg.account);
                continue;
            }
            let ordinal = u32::try_from(ordinal)
                .map_err(|_| invalid("cash source leg ordinal exceeds its wire bound"))?;
            let (line, cell) = expected.remove(&(digest, ordinal)).ok_or_else(|| {
                invalid("an original cash leg is absent from the selected ledger")
            })?;
            let (debits, credits) = if leg.debit {
                (leg.mantissa, 0)
            } else {
                (0, leg.mantissa)
            };
            if cell.account_id != leg.account
                || cell.unit_id != leg.unit
                || line.debits != debits
                || line.credits != credits
                || Some(line.effective_day) != entry.effective_day
                || line.recorded_seq != entry.commit_seq
            {
                return Err(invalid(
                    "cash citation differs from its complete original entry payload",
                ));
            }
            group.cash_accounts.insert(leg.account);
            group.legs.push(ordinal);
        }
    }
    if !expected.is_empty() {
        return Err(invalid("cash policy lacks selected original entry legs"));
    }
    let mut decisions = Vec::with_capacity(ledger.lines.len());
    for ((digest, _), group) in groups {
        let inherited = automatic(&group, &rules);
        for ordinal in group.legs {
            let (activity, basis) = match overrides.remove(&(digest, ordinal)) {
                Some(activity) => (activity, CashFlowDecisionBasis::ExplicitOverride),
                None => inherited.ok_or_else(|| invalid("mixed, unmapped or non-transfer counterparts need an explicit cash decision"))?,
            };
            decisions.push(CashFlowPolicyDecision {
                entry_digest: digest,
                leg_index: ordinal,
                activity,
                basis,
            });
        }
    }
    if !overrides.is_empty() {
        return Err(invalid(
            "cash override names a leg outside the selected activity",
        ));
    }
    decisions.sort_unstable_by_key(|d| (d.entry_digest, d.leg_index));
    if decisions != certificate.decisions
        || decisions.len() != report.definition.assignments.len()
        || decisions
            .iter()
            .zip(&report.definition.assignments)
            .any(|(d, a)| {
                (d.entry_digest, d.leg_index, d.activity)
                    != (a.entry_digest, a.leg_index, a.activity)
            })
    {
        return Err(failed(
            "cash_flow_policy_derivation",
            "original counterparts do not reproduce every declared activity and derivation basis",
        ));
    }
    let mut size = 4 + OUTPUT_FORMAT.len();
    add_size(
        &mut size,
        4 + certificate.policy_bytes.len() + 4 + cash_output.len() + 4 + decisions.len() * 38,
    )?;
    let mut w = writer(size)?;
    w.bytes(OUTPUT_FORMAT)
        .bytes(certificate.policy_bytes)
        .bytes(cash_output);
    write_decisions(&mut w, &decisions);
    debug_assert_eq!(w.buf.len(), size);
    report.policy = Some(VerifiedCashFlowPolicy {
        source_certificate_digest: source_digest,
        policy: policy.clone(),
        decisions,
    });
    Ok(w.buf)
}

fn write_decisions(w: &mut Writer, values: &[CashFlowPolicyDecision]) {
    w.count(values.len());
    for d in values {
        w.fixed(&d.entry_digest)
            .u32(d.leg_index)
            .u8(d.activity as u8)
            .u8(d.basis as u8);
    }
}
