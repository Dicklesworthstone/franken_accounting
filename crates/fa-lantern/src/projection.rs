//! Projections (plan §11.4, bet A4): deterministic folds of the snapshot into
//! the graphs the procedures walk — money flow between accounts, preparers
//! and approvers against accounts, documents against entries. Each carries a
//! digest, is rebuildable from the journal, and is never more authoritative
//! than it (FA-INV-04). Flow weights are exact: credit legs are allocated in
//! canonical account/magnitude order under the registered largest-remainder
//! law (plan §6.3), using the debit legs' remaining capacities as weights.
//! Both the credit and debit margins reconcile, including rounding ties.

mod transport;

use std::collections::BTreeMap;

use fa_model::{EntryClass, Writer};
use fa_money::Side;
use fa_time::DateDay;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::{LanternError, Snapshot};

pub const PROJECTION_DIGEST_DOMAIN: &[u8] = b"fa:lantern-projection:v1";

fn digest(name: &str, body: Vec<u8>) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(PROJECTION_DIGEST_DOMAIN);
    h.update(name.as_bytes());
    h.update(&body);
    h.finalize().0
}

/// Value flowing from a credited account to a debited account in one unit
/// and period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowEdge {
    pub from: VId,
    pub to: VId,
    pub unit_id: u32,
    pub period: String,
    pub mantissa: i128,
    /// Positive credit-leg × debit-leg contributions folded into this edge.
    pub contributions: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoneyFlow {
    /// Ascending by `(from, to, unit, period)`.
    pub edges: Vec<FlowEdge>,
    /// Posting entries folded.
    pub entries: u64,
    pub digest: [u8; 32],
}

/// One credit leg's allocated share of value to one debit account of the
/// same entry and unit: the entry-level grain the graph procedures walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowLeg {
    pub entry: VId,
    /// The entry's recorded commit sequence: its statement order, which
    /// orders same-day legs (never the hashed vid).
    pub recorded: CommitSeq,
    pub class: EntryClass,
    pub effective_date: DateDay,
    pub period: String,
    pub from: VId,
    pub to: VId,
    pub unit_id: u32,
    /// Exact and positive, in the unit's mantissa scale.
    pub mantissa: i128,
}

/// One entry's legs of one unit: `(credits as (account, amount), debits as
/// (account, amount))`.
type UnitLegs = (Vec<(VId, i128)>, Vec<(VId, i128)>);

/// Every live posting entry's credit→debit allocations under the registered
/// largest-remainder law, ascending by `(entry, unit, from, to, mantissa)`.
/// Allocation is capacity-conserving: each debit receives exactly its posted
/// amount, not merely an independently rounded share of every credit. Empty
/// or unbalanced sides with nonzero value are corruption, never an empty graph.
pub fn flow_legs(snapshot: &Snapshot) -> Result<Vec<FlowLeg>, LanternError> {
    let mut legs = Vec::new();
    for e in snapshot.live_postings()? {
        let mut by_unit: BTreeMap<u32, UnitLegs> = BTreeMap::new();
        for leg in &e.entry.proposal.legs {
            let slot = by_unit.entry(leg.amount.unit.0).or_default();
            let value = (leg.account_ref, leg.amount.mantissa);
            match leg.side {
                Side::Credit => slot.0.push(value),
                Side::Debit => slot.1.push(value),
            }
        }
        for (unit_id, (credits, debits)) in by_unit {
            for (from, to, mantissa) in
                transport::allocate(fa_money::UnitId(unit_id), credits, debits)?
            {
                legs.push(FlowLeg {
                    entry: e.vid,
                    recorded: e.recorded_at,
                    class: e.entry.proposal.class,
                    effective_date: e.entry.proposal.effective_date,
                    period: e.period.clone(),
                    from,
                    to,
                    unit_id,
                    mantissa,
                });
            }
        }
    }
    legs.sort_by(|a, b| {
        (a.entry, a.unit_id, a.from, a.to, a.mantissa)
            .cmp(&(b.entry, b.unit_id, b.from, b.to, b.mantissa))
    });
    Ok(legs)
}

/// The money-flow projection of every live posting entry in the snapshot: the
/// flow legs folded per `(from, to, unit, period)`.
pub fn money_flow(snapshot: &Snapshot) -> Result<MoneyFlow, LanternError> {
    let entries = snapshot.live_postings()?.len() as u64;
    let mut edges: BTreeMap<(u128, u128, u32, String), (i128, u64)> = BTreeMap::new();
    for l in flow_legs(snapshot)? {
        let slot = edges
            .entry((l.from.0, l.to.0, l.unit_id, l.period))
            .or_insert((0, 0));
        slot.0 = slot
            .0
            .checked_add(l.mantissa)
            .ok_or(LanternError::Overflow("flow edge"))?;
        slot.1 += 1;
    }
    let edges: Vec<FlowEdge> = edges
        .into_iter()
        .map(
            |((from, to, unit_id, period), (mantissa, contributions))| FlowEdge {
                from: VId(from),
                to: VId(to),
                unit_id,
                period,
                mantissa,
                contributions,
            },
        )
        .collect();
    let mut w = Writer::new();
    w.u64(entries);
    w.list(&edges, |w, e| {
        w.u128(e.from.0)
            .u128(e.to.0)
            .u32(e.unit_id)
            .str(&e.period)
            .i128(e.mantissa)
            .u64(e.contributions);
    });
    // Do not label the corrected two-margin allocation with the historical
    // independent-credit projection's digest domain.
    let digest = digest("money-flow:capacity-v2", w.finish()?);
    Ok(MoneyFlow {
        edges,
        entries,
        digest,
    })
}

/// What one principal posted to one account in one unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparerRow {
    pub principal: VId,
    pub account: VId,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
    pub entries: u64,
}

/// How many entries one approver approved for one preparer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRow {
    pub approver: VId,
    pub preparer: VId,
    pub entries: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preparers {
    /// Ascending by `(principal, account, unit)`.
    pub rows: Vec<PreparerRow>,
    /// Ascending by `(approver, preparer)`.
    pub approvals: Vec<ApprovalRow>,
    pub digest: [u8; 32],
}

/// The preparer/approver bipartite projection.
pub fn preparers(snapshot: &Snapshot) -> Result<Preparers, LanternError> {
    let mut rows: BTreeMap<(u128, u128, u32), (i128, i128, u64)> = BTreeMap::new();
    let mut approvals: BTreeMap<(u128, u128), u64> = BTreeMap::new();
    for e in snapshot.live_postings()? {
        let preparer = e.entry.proposal.principal_ref;
        let mut touched = std::collections::BTreeSet::new();
        for leg in &e.entry.proposal.legs {
            let key = (preparer.0, leg.account_ref.0, leg.amount.unit.0);
            let slot = rows.entry(key).or_insert((0, 0, 0));
            let column = match leg.side {
                Side::Debit => &mut slot.0,
                Side::Credit => &mut slot.1,
            };
            *column = column
                .checked_add(leg.amount.mantissa)
                .ok_or(LanternError::Overflow("preparer sum"))?;
            touched.insert(key);
        }
        for key in touched {
            if let Some(slot) = rows.get_mut(&key) {
                slot.2 += 1;
            }
        }
        for approver in e.approvers() {
            *approvals.entry((approver.0, preparer.0)).or_insert(0) += 1;
        }
    }
    let rows: Vec<PreparerRow> = rows
        .into_iter()
        .map(
            |((principal, account, unit_id), (debits, credits, entries))| PreparerRow {
                principal: VId(principal),
                account: VId(account),
                unit_id,
                debits,
                credits,
                entries,
            },
        )
        .collect();
    let approvals: Vec<ApprovalRow> = approvals
        .into_iter()
        .map(|((approver, preparer), entries)| ApprovalRow {
            approver: VId(approver),
            preparer: VId(preparer),
            entries,
        })
        .collect();
    let mut w = Writer::new();
    w.list(&rows, |w, r| {
        w.u128(r.principal.0)
            .u128(r.account.0)
            .u32(r.unit_id)
            .i128(r.debits)
            .i128(r.credits)
            .u64(r.entries);
    });
    w.list(&approvals, |w, a| {
        w.u128(a.approver.0).u128(a.preparer.0).u64(a.entries);
    });
    let digest = digest("preparers", w.finish()?);
    Ok(Preparers {
        rows,
        approvals,
        digest,
    })
}

/// How many entries cite one document in one role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentRow {
    pub document: [u8; 32],
    pub role: u8,
    pub entries: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Documents {
    /// Ascending by `(document, role)`.
    pub rows: Vec<DocumentRow>,
    /// Posting entries carrying no evidence reference at all.
    pub entries_without_evidence: u64,
    pub digest: [u8; 32],
}

/// The document-to-entry projection.
pub fn documents(snapshot: &Snapshot) -> Result<Documents, LanternError> {
    let mut rows: BTreeMap<([u8; 32], u8), u64> = BTreeMap::new();
    let mut entries_without_evidence = 0u64;
    for e in snapshot.live_postings()? {
        if e.entry.proposal.evidence.is_empty() {
            entries_without_evidence += 1;
        }
        let mut seen = std::collections::BTreeSet::new();
        for ev in &e.entry.proposal.evidence {
            if seen.insert((ev.document_oid.0, ev.role)) {
                *rows.entry((ev.document_oid.0, ev.role)).or_insert(0) += 1;
            }
        }
    }
    let rows: Vec<DocumentRow> = rows
        .into_iter()
        .map(|((document, role), entries)| DocumentRow {
            document,
            role,
            entries,
        })
        .collect();
    let mut w = Writer::new();
    w.u64(entries_without_evidence);
    w.list(&rows, |w, r| {
        w.fixed(&r.document).u8(r.role).u64(r.entries);
    });
    let digest = digest("documents", w.finish()?);
    Ok(Documents {
        rows,
        entries_without_evidence,
        digest,
    })
}
