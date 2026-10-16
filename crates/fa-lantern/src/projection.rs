//! Projections (plan §11.4, bet A4): deterministic folds of the snapshot into
//! the graphs the procedures walk — money flow between accounts, preparers
//! and approvers against accounts, documents against entries. Each carries a
//! digest, is rebuildable from the journal, and is never more authoritative
//! than it (FA-INV-04). Flow weights are exact: credit legs are allocated in
//! canonical account/magnitude order under the registered largest-remainder
//! law (plan §6.3), using the debit legs' remaining capacities as weights.
//! Both the credit and debit margins reconcile, including rounding ties.

pub(crate) mod entity;
mod transport;

use std::collections::BTreeMap;

use fa_model::{EntryClass, LEGAL_ENTITY_DIMENSION, LegPayload, Writer};
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

/// An entry-level transfer retaining its legal-entity partition. Procedures
/// must keep this scope when following edges through more than one entry;
/// the same chart account can carry different entities' balances.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopedFlowLeg {
    pub legal_entity: Option<VId>,
    pub leg: FlowLeg,
}

/// One entry's credits and debits in one `(unit, legal_entity)` partition.
type UnitLegs = (Vec<(VId, i128)>, Vec<(VId, i128)>);
type Partitions = BTreeMap<(u32, Option<VId>), UnitLegs>;

fn named_entity(leg: &LegPayload) -> Result<Option<VId>, LanternError> {
    let mut values = leg
        .dimension_set
        .iter()
        .filter(|(dimension, _)| *dimension == LEGAL_ENTITY_DIMENSION)
        .map(|(_, value)| *value);
    let entity = values.next();
    if values.next().is_some() {
        return Err(LanternError::Overflow("duplicate money-flow legal entity"));
    }
    Ok(entity)
}

/// Normalize entity mentions once for the selected, admitted population.
pub(crate) fn entity_scope<'a>(
    legs: impl IntoIterator<Item = &'a LegPayload>,
) -> Result<entity::Scope, LanternError> {
    let mut scope = entity::Scope::default();
    for leg in legs {
        scope.observe(named_entity(leg)?.map(|value| value.0));
    }
    Ok(scope)
}

pub(crate) fn scoped_entity(
    scope: &entity::Scope,
    leg: &LegPayload,
) -> Result<Option<VId>, LanternError> {
    scope
        .resolve(named_entity(leg)?.map(|value| value.0))
        .map(|value| value.map(VId))
        .map_err(|_| LanternError::Overflow("missing money-flow legal entity"))
}

fn partition(legs: &[LegPayload], scope: &entity::Scope) -> Result<Partitions, LanternError> {
    let mut partitions: Partitions = BTreeMap::new();
    for leg in legs {
        let entity = scoped_entity(scope, leg)?;
        let slot = partitions.entry((leg.amount.unit.0, entity)).or_default();
        let value = (leg.account_ref, leg.amount.mantissa);
        match leg.side {
            Side::Credit => slot.0.push(value),
            Side::Debit => slot.1.push(value),
        }
    }
    Ok(partitions)
}

/// Scope-preserving money flow. The kernel requires explicit legal entities
/// in multi-entity books; a single-entity book may omit that dimension. Over
/// an admitted snapshot a sole explicit value therefore also identifies its
/// omitted values. If no value is explicit, the implicit book scope is kept.
/// This normalization uses authenticated dimensions, never account names.
pub fn scoped_flow_legs(snapshot: &Snapshot) -> Result<Vec<ScopedFlowLeg>, LanternError> {
    let live = snapshot.live_postings()?;
    let scope = entity_scope(live.iter().flat_map(|entry| &entry.entry.proposal.legs))?;
    let mut legs = Vec::new();
    for e in live {
        let by_partition = partition(&e.entry.proposal.legs, &scope)?;
        for ((unit_id, legal_entity), (credits, debits)) in by_partition {
            for (from, to, mantissa) in
                transport::allocate(fa_money::UnitId(unit_id), credits, debits)?
            {
                legs.push(ScopedFlowLeg {
                    legal_entity,
                    leg: FlowLeg {
                        entry: e.vid,
                        recorded: e.recorded_at,
                        class: e.entry.proposal.class,
                        effective_date: e.entry.proposal.effective_date,
                        period: e.period.clone(),
                        from,
                        to,
                        unit_id,
                        mantissa,
                    },
                });
            }
        }
    }
    legs.sort_by_key(|scoped| {
        let leg = &scoped.leg;
        (
            leg.entry,
            leg.unit_id,
            leg.from,
            leg.to,
            leg.mantissa,
            scoped.legal_entity,
        )
    });
    Ok(legs)
}

/// Every live posting entry's credit→debit allocations, ascending by
/// `(entry, unit, from, to, mantissa)`. Each debit and credit margin reconciles
/// within its own legal entity. Use `scoped_flow_legs` for path analysis;
/// this compatibility view intentionally aggregates away the entity label.
pub fn flow_legs(snapshot: &Snapshot) -> Result<Vec<FlowLeg>, LanternError> {
    Ok(scoped_flow_legs(snapshot)?
        .into_iter()
        .map(|scoped| scoped.leg)
        .collect())
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
    let digest = digest("money-flow:capacity-entity-v3", w.finish()?);
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

#[cfg(test)]
mod scope_tests {
    use super::*;
    use fa_money::{Amount, UnitId};

    fn leg(side: Side, account: u128, entity: Option<u128>, unit: u32) -> LegPayload {
        let mut leg = LegPayload::simple(side, VId(account), Amount::new(UnitId(unit), 1));
        if let Some(entity) = entity {
            leg.dimension_set
                .push((LEGAL_ENTITY_DIMENSION, VId(entity)));
        }
        leg
    }

    #[test]
    fn allocations_cannot_invent_transfers_between_entities_or_units() {
        let legs = [
            leg(Side::Credit, 10, Some(1), 0),
            leg(Side::Debit, 20, Some(1), 0),
            leg(Side::Credit, 30, Some(2), 0),
            leg(Side::Debit, 40, Some(2), 0),
            leg(Side::Credit, 50, Some(1), 1),
            leg(Side::Debit, 60, Some(1), 1),
        ];
        let mut edges = Vec::new();
        for ((unit, entity), (credits, debits)) in
            partition(&legs, &entity_scope(&legs).unwrap()).unwrap()
        {
            for (from, to, value) in transport::allocate(UnitId(unit), credits, debits).unwrap() {
                edges.push((entity, unit, from, to, value));
            }
        }
        assert_eq!(
            edges,
            vec![
                (Some(VId(1)), 0, VId(10), VId(20), 1),
                (Some(VId(2)), 0, VId(30), VId(40), 1),
                (Some(VId(1)), 1, VId(50), VId(60), 1),
            ]
        );
    }

    #[test]
    fn a_single_implicit_entity_matches_its_explicit_dimension() {
        let legs = [
            leg(Side::Credit, 10, None, 0),
            leg(Side::Debit, 20, Some(1), 0),
        ];
        let parts = partition(&legs, &entity_scope(&legs).unwrap()).unwrap();
        assert_eq!(parts.len(), 1);
        let (credits, debits) = parts[&(0, Some(VId(1)))].clone();
        assert_eq!(
            transport::allocate(UnitId(0), credits, debits).unwrap(),
            vec![(VId(10), VId(20), 1)]
        );
        let mut multiple = entity_scope(&legs).unwrap();
        multiple.observe(Some(2));
        assert!(partition(&legs, &multiple).is_err());
    }

    #[test]
    fn globally_balanced_but_entity_unbalanced_input_is_refused() {
        let legs = [
            leg(Side::Credit, 10, Some(1), 0),
            leg(Side::Debit, 20, Some(2), 0),
        ];
        for ((unit, _), (credits, debits)) in
            partition(&legs, &entity_scope(&legs).unwrap()).unwrap()
        {
            assert!(transport::allocate(UnitId(unit), credits, debits).is_err());
        }
        let mut duplicate = leg(Side::Debit, 10, Some(1), 0);
        duplicate
            .dimension_set
            .push((LEGAL_ENTITY_DIMENSION, VId(2)));
        assert!(named_entity(&duplicate).is_err());
    }
}
