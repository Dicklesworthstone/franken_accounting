//! Naive reference oracle for REA relationship admission, valid-time
//! `[valid_from, valid_to)` related-party closure, and directed ownership
//! composition (plan §4.5, §16.2, bead `fa-l2h`).
//!
//! Uses only `std`, `fa-time`, `fa-registry`, and [`crate::Int`] limb
//! arithmetic — no `fa-money`, no `fa-model`, and no substrate types.

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::g0::RelationshipBases;
use fa_time::DateDay;

use crate::Int;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefRelationshipKind {
    Owns { num: i128, den: u128 },
    Controls,
    RelatedTo,
}

impl RefRelationshipKind {
    #[must_use]
    pub const fn edge_kind_name(&self) -> &'static str {
        match self {
            Self::Owns { .. } => "OWNS",
            Self::Controls => "CONTROLS",
            Self::RelatedTo => "RELATED_TO",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefRelationshipEdge {
    pub from: u128,
    pub to: u128,
    pub kind: RefRelationshipKind,
    pub basis: String,
    pub valid_from: DateDay,
    pub valid_to: Option<DateDay>,
}

impl RefRelationshipEdge {
    #[must_use]
    pub fn is_active_on(&self, day: DateDay) -> bool {
        day >= self.valid_from && self.valid_to.is_none_or(|to| day < to)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefRelatedHit {
    pub vid: u128,
    pub code: String,
    pub depth: usize,
    pub via: u128,
    pub kind: RefRelationshipKind,
    pub basis: String,
}

/// Independent admission check for a relationship edge against `known_endpoints`
/// (`vid -> code`) and `registries/relationship_bases.toml`.
/// Returns `Err((refusal_code, exit_class))` on refusal.
pub fn validate_relationship_edge(
    edge: &RefRelationshipEdge,
    known_endpoints: &BTreeMap<u128, String>,
    is_agent_on_trunk: bool,
) -> Result<(), (&'static str, u8)> {
    if is_agent_on_trunk {
        return Err(("FA-REF-013", 7));
    }
    if edge.from == edge.to {
        return Err(("FA-REF-100", 2));
    }
    if let RefRelationshipKind::Owns { num, den } = edge.kind
        && (den == 0 || num <= 0 || (num as u128) > den)
    {
        return Err(("FA-REF-100", 2));
    }
    if let Some(to_day) = edge.valid_to
        && edge.valid_from >= to_day
    {
        return Err(("FA-REF-100", 2));
    }
    let bases = RelationshipBases::embedded().map_err(|_| ("FA-REF-100", 2))?;
    let Some(basis_row) = bases.rows.iter().find(|r| r.code == edge.basis) else {
        return Err(("FA-REF-100", 2));
    };
    if basis_row.edge_kind != edge.kind.edge_kind_name() {
        return Err(("FA-REF-100", 2));
    }
    if !known_endpoints.contains_key(&edge.from) || !known_endpoints.contains_key(&edge.to) {
        return Err(("FA-REF-100", 2));
    }
    Ok(())
}

/// Naive iterative wave relaxation (Bellman-Ford style) for temporal related-party
/// closure as of `as_of` up to `max_depth` hops from `root`.
#[must_use]
pub fn naive_related_as_of(
    known_endpoints: &BTreeMap<u128, String>,
    edges: &[RefRelationshipEdge],
    root: u128,
    as_of: DateDay,
    max_depth: usize,
) -> Vec<RefRelatedHit> {
    if max_depth == 0 || !known_endpoints.contains_key(&root) {
        return Vec::new();
    }
    let active: Vec<&RefRelationshipEdge> =
        edges.iter().filter(|e| e.is_active_on(as_of)).collect();

    let mut reached: BTreeMap<u128, RefRelatedHit> = BTreeMap::new();
    let mut frontier: Vec<u128> = vec![root];

    for step in 1..=max_depth {
        let mut next_frontier = Vec::new();
        for &u in &frontier {
            let mut candidates: Vec<(u128, RefRelationshipKind, String)> = Vec::new();
            for e in &active {
                if e.from == u {
                    candidates.push((e.to, e.kind, e.basis.clone()));
                } else if e.to == u {
                    candidates.push((e.from, e.kind, e.basis.clone()));
                }
            }
            candidates.sort_by(|a, b| {
                a.0.cmp(&b.0)
                    .then_with(|| a.1.edge_kind_name().cmp(b.1.edge_kind_name()))
                    .then_with(|| a.2.cmp(&b.2))
            });
            for (v, kind, basis) in candidates {
                if v == root || reached.contains_key(&v) {
                    continue;
                }
                let code = known_endpoints.get(&v).cloned().unwrap_or_default();
                reached.insert(
                    v,
                    RefRelatedHit {
                        vid: v,
                        code,
                        depth: step,
                        via: u,
                        kind,
                        basis,
                    },
                );
                next_frontier.push(v);
            }
        }
        frontier = next_frontier;
        if frontier.is_empty() {
            break;
        }
    }

    let mut out: Vec<RefRelatedHit> = reached.into_values().collect();
    out.sort_by(|a, b| a.depth.cmp(&b.depth).then_with(|| a.vid.cmp(&b.vid)));
    out
}

fn gcd_u128(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let r = a % b;
        a = b;
        b = r;
    }
    a
}

/// Naive recursive directed `OWNS` path enumeration using [`Int`] limb arithmetic,
/// returning reduced `(numerator, denominator)` as of `as_of`.
#[must_use]
pub fn naive_effective_ownership_as_of(
    edges: &[RefRelationshipEdge],
    owner: u128,
    target: u128,
    as_of: DateDay,
    max_depth: usize,
) -> Option<(i128, u128)> {
    if max_depth == 0 || owner == target {
        return Some((0, 1));
    }
    let active_owns: Vec<(u128, u128, u128, u128)> = edges
        .iter()
        .filter(|e| e.is_active_on(as_of))
        .filter_map(|e| match e.kind {
            RefRelationshipKind::Owns { num, den } if num > 0 && den > 0 => {
                let g = gcd_u128(num as u128, den);
                Some((e.from, e.to, (num as u128) / g, den / g))
            }
            _ => None,
        })
        .collect();

    #[allow(clippy::too_many_arguments)]
    fn dfs(
        cur: u128,
        target: u128,
        rem_depth: usize,
        visited: &mut BTreeSet<u128>,
        edges: &[(u128, u128, u128, u128)],
        cur_num: &Int,
        cur_den: &Int,
        acc_num: &mut Int,
        acc_den: &mut Int,
    ) {
        if rem_depth == 0 {
            return;
        }
        for &(u, v, n, d) in edges {
            if u != cur || visited.contains(&v) {
                continue;
            }
            let next_num = cur_num.mul(&Int::from_u128(n));
            let next_den = cur_den.mul(&Int::from_u128(d));
            if v == target {
                // acc_num / acc_den + next_num / next_den
                let new_num = acc_num.mul(&next_den).add(&next_num.mul(acc_den));
                let new_den = acc_den.mul(&next_den);
                *acc_num = new_num;
                *acc_den = new_den;
            } else if rem_depth > 1 {
                visited.insert(v);
                dfs(
                    v,
                    target,
                    rem_depth - 1,
                    visited,
                    edges,
                    &next_num,
                    &next_den,
                    acc_num,
                    acc_den,
                );
                visited.remove(&v);
            }
        }
    }

    let mut visited = BTreeSet::new();
    visited.insert(owner);
    let mut acc_num = Int::zero();
    let mut acc_den = Int::from_u128(1);
    dfs(
        owner,
        target,
        max_depth,
        &mut visited,
        &active_owns,
        &Int::from_u128(1),
        &Int::from_u128(1),
        &mut acc_num,
        &mut acc_den,
    );
    let n = acc_num.to_u128()?;
    let d = acc_den.to_u128()?;
    if n == 0 {
        return Some((0, 1));
    }
    let g = gcd_u128(n, d);
    let rn = i128::try_from(n / g).ok()?;
    Some((rn, d / g))
}

/// Registered event kinds (`registries/object_schemas/event.toml`, bead `fa-f3bo`).
pub const EVENT_KINDS: &[(u8, &str)] = &[
    (1, "sale"),
    (2, "purchase"),
    (3, "receipt"),
    (4, "payment"),
    (5, "shipment"),
    (6, "return"),
    (7, "accrual"),
    (8, "depreciation"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefEventResource {
    pub label: String,
    pub unit_id: u32,
    pub mantissa: i128,
    pub instrument: Option<u128>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefEvent {
    pub vid: u128,
    pub code: String,
    pub kind_tag: u8,
    pub occurred_on: DateDay,
    pub participants: Vec<u128>,
    pub resources: Vec<RefEventResource>,
    /// `(document_oid, doc_commit, role)`
    pub evidence: Vec<([u8; 32], [u8; 32], u8)>,
    pub event_digest: [u8; 32],
}

/// Independent reference check for `RecordEvent` admission (`FA-INV-05.event-closure`,
/// bead `fa-f3bo`). Returns `Err((refusal_code, exit_class))` on refusal.
pub fn validate_event(
    event: &RefEvent,
    known_participants: &BTreeSet<u128>,
    known_instruments: &BTreeSet<u128>,
    known_units: &BTreeSet<u32>,
    known_documents: &BTreeMap<[u8; 32], [u8; 32]>,
    existing_events: &BTreeMap<u128, RefEvent>,
    is_agent_on_trunk: bool,
) -> Result<(), (&'static str, u8)> {
    if is_agent_on_trunk {
        return Err(("FA-REF-013", 7));
    }
    if event.code.is_empty() || event.code.len() > 64 {
        return Err(("FA-REF-100", 2));
    }
    if !EVENT_KINDS.iter().any(|(tag, _)| *tag == event.kind_tag) {
        return Err(("FA-REF-100", 2));
    }
    if event.participants.len() > 32
        || event
            .participants
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(("FA-REF-100", 2));
    }
    if event.resources.len() > 32 {
        return Err(("FA-REF-100", 2));
    }
    for res in &event.resources {
        if res.label.is_empty() || res.label.len() > 64 {
            return Err(("FA-REF-100", 2));
        }
        if !known_units.contains(&res.unit_id) {
            return Err(("FA-REF-006", 3));
        }
        if res.mantissa <= 0 {
            return Err(("FA-REF-100", 2));
        }
    }
    if event.evidence.is_empty() {
        return Err(("FA-REF-080", 3));
    }
    if event.evidence.len() > 32
        || event.evidence.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(("FA-REF-100", 2));
    }
    if existing_events.contains_key(&event.vid) {
        return Err(("FA-REF-100", 2));
    }
    for p in &event.participants {
        if !known_participants.contains(p) {
            return Err(("FA-REF-100", 2));
        }
    }
    for res in &event.resources {
        if let Some(inst) = res.instrument
            && !known_instruments.contains(&inst)
        {
            return Err(("FA-REF-100", 2));
        }
    }
    for (oid, commit, role) in &event.evidence {
        if *role == 0 || *role > 6 {
            return Err(("FA-REF-100", 2));
        }
        let Some(stored_commit) = known_documents.get(oid) else {
            return Err(("FA-REF-081", 3));
        };
        if stored_commit != commit {
            return Err(("FA-REF-082", 3));
        }
    }
    Ok(())
}

/// Independent reference check for an `Entry`'s `cited_event` (`FA-INV-05.event-closure`,
/// bead `fa-f3bo`).
pub fn validate_event_citation(
    cited_vid: u128,
    cited_digest: Option<[u8; 32]>,
    existing_events: &BTreeMap<u128, RefEvent>,
) -> Result<(), (&'static str, u8)> {
    let Some(ev) = existing_events.get(&cited_vid) else {
        return Err(("FA-REF-100", 2));
    };
    if ev.evidence.is_empty() {
        return Err(("FA-REF-080", 3));
    }
    if let Some(expected) = cited_digest
        && ev.event_digest != expected
    {
        return Err(("FA-REF-100", 2));
    }
    Ok(())
}

/// Independent reference check for rule-origin entry reproduction
/// (`FA-INV-05.rule-reproduction`, bead `fa-f3bo` / `fa-c34`).
pub fn validate_rule_reproduction(
    event_vid: u128,
    expected_proposal_digest: [u8; 32],
    recomputed_proposal_digest: [u8; 32],
    existing_events: &BTreeMap<u128, RefEvent>,
) -> Result<(), (&'static str, u8)> {
    validate_event_citation(event_vid, None, existing_events)?;
    if expected_proposal_digest != recomputed_proposal_digest {
        return Err(("FA-REF-100", 2));
    }
    Ok(())
}
