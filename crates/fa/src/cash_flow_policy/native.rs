//! Native classification reads: cash amounts still come from the existing fold.

use asupersync::fs::Vfs;
use fa_journal::{KernelError, rows::bytes};
use fa_model::{Entry, EntryClass, Id128, symbols::{label, property}};
use fa_money::Side;
use fa_policy::Capability;
use fgdb_types::{VId, context::PurposeContexts};

use super::*;
use crate::{AsyncBook, GeneralLedger, Outcome, RollForwardRequest};

struct Group {
    cash_accounts: BTreeSet<u128>,
    counterparts: BTreeSet<u128>,
    legs: Vec<u32>,
}

pub(super) struct Resolved {
    pub policy: CashFlowPolicy,
    pub definition: CashFlowDefinition,
    pub decisions: Vec<CashFlowPolicyDecision>,
}

/// Internal-only: ledger must be a current-authorized native read or replay.
/// Its fixed native closure authenticates the historical counterpart payloads.
pub(super) fn resolve<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>, cx: &PurposeContexts, ledger: &GeneralLedger,
    policy: &CashFlowPolicy,
) -> Outcome<Resolved> {
    let policy = match normalize(policy) { Ok(p) => p, Err(e) => return Ok(Err(e)) };
    let cash: BTreeSet<_> = policy.cash_accounts.iter().copied().collect();
    if ledger.accounts().iter().map(|a| a.id).collect::<BTreeSet<_>>() != cash {
        return Ok(Err(invalid("policy cash designations differ from the native cash selection")));
    }
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    let result = query.with_restriction(|| -> Result<Resolved, Error> {
        let chart = fa_journal::chart::read_at(&book.db, book.context(), ledger.known_at()).map_err(BookError::from)?;
        for rule in &policy.account_rules {
            query.checkpoint().map_err(BookError::Context)?;
            if !chart.accounts().get(&VId(rule.account_id)).is_some_and(|a| a.is_leaf && (1..=5).contains(&a.account_type)) {
                return Err(invalid(format!("policy counterpart {:032x} is not a historical monetary leaf", rule.account_id)).into());
            }
        }
        let rules: BTreeMap<_, _> = policy.account_rules.iter().map(|r| (r.account_id, r.activity)).collect();
        let mut overrides: BTreeMap<_, _> = policy.overrides.iter()
            .map(|a| ((a.entry_digest, a.leg_index), a.activity)).collect();
        let mut expected = BTreeMap::new();
        let mut wanted = BTreeSet::new();
        let mut wanted_groups = BTreeSet::new();
        for (i, line) in ledger.lines().iter().enumerate() {
            if i % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
            let cell = ledger.cells().get(line.cell_index as usize)
                .ok_or_else(|| invalid("native policy cash leg has no cell"))?;
            if expected.insert((line.entry_digest, line.leg_index), (line, cell)).is_some() {
                return Err(invalid("native cash selection repeats a leg").into());
            }
            wanted.insert(line.entry_digest);
            wanted_groups.insert((line.entry_digest, cell.unit_id));
        }
        let mut seen = BTreeSet::new();
        let mut inspected_legs = 0usize;
        let mut groups: BTreeMap<([u8; 32], u32), Group> = BTreeMap::new();
        if !wanted.is_empty() {
            for (i, row) in book.db.vertices_at(ledger.known_at()).map_err(KernelError::from).map_err(BookError::from)?
                .into_iter().enumerate() {
                if i % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
                if !row.labels.contains(&label::ENTRY) { continue; }
                let payload = bytes(&row, property::FA_PAYLOAD, "cash policy entry").map_err(BookError::from)?;
                let entry = Entry::decode(&payload).map_err(KernelError::from).map_err(BookError::from)?;
                if !wanted.contains(&entry.entry_digest) { continue; }
                let p = &entry.proposal;
                if !seen.insert(entry.entry_digest) || p.book_id != ledger.book_id()
                    || p.branch_id != Id128::TRUNK || !p.class.is_registered()
                    || p.class.is_control() || p.class == EntryClass::PENDING
                { return Err(invalid("cash policy source entry has a different identity or posting class").into()); }
                for (ordinal, leg) in p.legs.iter().enumerate() {
                    if ordinal % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
                    if !wanted_groups.contains(&(entry.entry_digest, leg.amount.unit.0)) || leg.amount.mantissa == 0 { continue; }
                    if inspected_legs == MAX_CASH_FLOW_POLICY_SOURCE_LEGS {
                        return Err(invalid("policy classification exceeds one million relevant source legs; narrow the selected interval").into());
                    }
                    inspected_legs += 1;
                    if leg.amount.mantissa < 0 { return Err(invalid("cash policy source contains a negative leg magnitude").into()); }
                    let group = groups.entry((entry.entry_digest, leg.amount.unit.0)).or_insert_with(|| Group {
                        cash_accounts: BTreeSet::new(), counterparts: BTreeSet::new(), legs: Vec::new(),
                    });
                    if !cash.contains(&leg.account_ref.0) {
                        group.counterparts.insert(leg.account_ref.0);
                        continue;
                    }
                    let ordinal = u32::try_from(ordinal).map_err(|_| invalid("cash leg ordinal exceeds its bound"))?;
                    let (line, cell) = expected.remove(&(entry.entry_digest, ordinal))
                        .ok_or_else(|| invalid("complete entry cash leg is absent from the native selection"))?;
                    let (debits, credits) = match leg.side {
                        Side::Debit => (leg.amount.mantissa, 0), Side::Credit => (0, leg.amount.mantissa),
                    };
                    if cell.account_id != leg.account_ref.0 || cell.unit_id != leg.amount.unit.0
                        || line.debits != debits || line.credits != credits
                        || line.effective_day != p.effective_date || line.recorded_seq != row.created_at.0
                    { return Err(invalid("cash policy citation differs from the complete native entry payload").into()); }
                    group.cash_accounts.insert(leg.account_ref.0);
                    group.legs.push(ordinal);
                }
            }
        }
        if !expected.is_empty() { return Err(invalid("cash policy native source is missing selected entries").into()); }
        let mut decisions = Vec::new();
        decisions.try_reserve(ledger.lines().len()).map_err(|_| invalid("cannot reserve cash policy decisions"))?;
        for ((digest, unit), group) in groups {
            query.checkpoint().map_err(BookError::Context)?;
            let inherited = automatic(&group.counterparts, group.cash_accounts.len(), &rules);
            for ordinal in group.legs {
                if decisions.len() % 256 == 0 { query.checkpoint().map_err(BookError::Context)?; }
                let (activity, basis) = match overrides.remove(&(digest, ordinal)) {
                    Some(activity) => (activity, CashFlowDecisionBasis::ExplicitOverride),
                    None => inherited.ok_or_else(|| invalid(format!(
                        "cash entry {} leg {ordinal} unit {unit} has mixed, unmapped or non-transfer counterparts; an explicit decision is required",
                        digest.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    )))?,
                };
                decisions.push(CashFlowPolicyDecision { entry_digest: digest, leg_index: ordinal, activity, basis });
            }
        }
        if !overrides.is_empty() { return Err(invalid("cash policy override names a leg outside the selected native cash activity").into()); }
        decisions.sort_unstable_by_key(|d| (d.entry_digest, d.leg_index));
        let definition = CashFlowDefinition { name: policy.name.clone(), cash_accounts: policy.cash_accounts.clone(),
            assignments: decisions.iter().map(|d| CashFlowAssignment { entry_digest: d.entry_digest,
                leg_index: d.leg_index, activity: d.activity }).collect() };
        query.checkpoint().map_err(BookError::Context)?;
        Ok(Resolved { policy, definition, decisions })
    });
    query.checkpoint().map_err(BookError::Context)?;
    outcome(result)
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Resolve an explicit reusable policy against complete original entries at
    /// the cash reader's ONE prefix, under CURRENT whole-book Read authority.
    /// Then invoke the existing cash engine; no second amount fold is introduced.
    pub fn cash_flow_with_policy(
        &self, cx: &PurposeContexts, principal: VId, capability: &Capability,
        request: &RollForwardRequest, policy: &CashFlowPolicy,
    ) -> Outcome<PolicyCashFlow> {
        let ledger = match self.general_ledger(cx, principal, capability, request)? {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        let resolved = match resolve(self, cx, &ledger, policy)? {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        let report = match ledger.classify_cash_flow(&cx.query(), &resolved.definition)? {
            Ok(v) => v, Err(r) => return Ok(Err(r)),
        };
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(PolicyCashFlow { policy: resolved.policy, report, decisions: resolved.decisions }))
    }
}
