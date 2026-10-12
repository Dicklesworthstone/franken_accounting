//! Projections (plan §11.4, bet A4): deterministic folds of the snapshot into
//! the graphs the procedures walk — money flow between accounts, preparers
//! and approvers against accounts, documents against entries. Each carries a
//! digest, is rebuildable from the journal, and is never more authoritative
//! than it (FA-INV-04). Flow weights are exact: a credit leg's magnitude is
//! allocated across the entry's debit accounts in proportion to their
//! magnitudes under the registered largest-remainder law (plan §6.3), so
//! every edge is an integer in the leg's unit and an entry's edges conserve
//! its credit total.

use std::collections::BTreeMap;

use fa_model::Writer;
use fa_money::allocation::largest_remainder;
use fa_money::{Amount, Side};
use fgdb_crypto::Hasher;
use fgdb_types::VId;

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
    /// Credit-leg × debit-leg contributions folded into this edge.
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

/// One entry's legs of one unit: `(credits as (account, amount), debits as
/// (account, magnitude))`.
type UnitLegs = (Vec<(VId, Amount)>, Vec<(VId, u128)>);

/// The money-flow projection of every posting entry in the snapshot.
pub fn money_flow(snapshot: &Snapshot) -> Result<MoneyFlow, LanternError> {
    let mut edges: BTreeMap<(u128, u128, u32, String), (i128, u64)> = BTreeMap::new();
    let mut entries = 0u64;
    for e in snapshot.entries.iter().filter(|e| e.posts()) {
        entries += 1;
        let mut by_unit: BTreeMap<u32, UnitLegs> = BTreeMap::new();
        for leg in &e.entry.proposal.legs {
            let slot = by_unit.entry(leg.amount.unit.0).or_default();
            match leg.side {
                Side::Credit => slot.0.push((leg.account_ref, leg.amount)),
                Side::Debit => slot
                    .1
                    .push((leg.account_ref, leg.amount.mantissa.unsigned_abs())),
            }
        }
        for (unit_id, (credits, debits)) in by_unit {
            if credits.is_empty() || debits.is_empty() || debits.iter().all(|(_, w)| *w == 0) {
                continue;
            }
            let weights: Vec<u128> = debits.iter().map(|(_, w)| *w).collect();
            for (from, amount) in credits {
                let magnitude = Amount::new(
                    amount.unit,
                    amount
                        .mantissa
                        .checked_abs()
                        .ok_or(LanternError::Overflow("flow magnitude"))?,
                );
                let shares = largest_remainder(magnitude, &weights)?;
                for ((to, _), share) in debits.iter().zip(shares) {
                    let slot = edges
                        .entry((from.0, to.0, unit_id, e.period.clone()))
                        .or_insert((0, 0));
                    slot.0 = slot
                        .0
                        .checked_add(share.mantissa)
                        .ok_or(LanternError::Overflow("flow edge"))?;
                    slot.1 += 1;
                }
            }
        }
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
    let digest = digest("money-flow", w.finish()?);
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
    for e in snapshot.entries.iter().filter(|e| e.posts()) {
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
    for e in snapshot.entries.iter().filter(|e| e.posts()) {
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
