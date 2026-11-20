//! Bounded simple-cycle enumeration over already authenticated bank transfers.
//! A cycle exists only while every edge's positive float interval overlaps.

use std::collections::{BTreeMap, BTreeSet};

use fgdb_types::VId;

use super::{BankTransfer, MAX_KITING_FINDINGS, invalid};
use crate::{LanternError, Meter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Node<'a> {
    pub account: VId,
    pub instrument: &'a str,
}

/// An amount remains a magnitude in exactly one native-unit/entity scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Group {
    pub unit: u32,
    pub entity: Option<VId>,
    pub amount: i128,
}

#[derive(Clone, Copy)]
pub(super) struct Transfer<'a> {
    pub source: &'a BankTransfer,
    pub group: Group,
    pub start: i32,
    pub end: i32,
    pub earliest: i32,
    pub latest: i32,
}

impl Transfer<'_> {
    fn from(&self) -> Node<'_> {
        Node {
            account: self.source.source.account,
            instrument: &self.source.source.instrument,
        }
    }

    fn to(&self) -> Node<'_> {
        Node {
            account: self.source.destination.account,
            instrument: &self.source.destination.instrument,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Cycle {
    pub transfers: Vec<usize>,
    pub start: i32,
    pub end: i32,
}

pub(super) struct CycleSearch {
    pub cycles: Vec<Cycle>,
    pub witness: fnx_cgse::ComplexityWitness,
}

#[derive(Clone, Copy)]
struct Interval {
    start: i32,
    end: i32,
    earliest: i32,
    latest: i32,
}

impl Interval {
    fn include(self, edge: &Transfer<'_>) -> Self {
        Self {
            start: self.start.max(edge.start),
            end: self.end.min(edge.end),
            earliest: self.earliest.min(edge.earliest),
            latest: self.latest.max(edge.latest),
        }
    }

    fn admitted(self, window: u32) -> bool {
        self.start < self.end
            && i64::from(self.latest) - i64::from(self.earliest) <= i64::from(window)
    }
}

struct Search<'a, 'b, 'm, 'cx> {
    transfers: &'a [Transfer<'b>],
    nodes: Vec<Node<'a>>,
    endpoints: Vec<(usize, usize)>,
    outgoing: Vec<Vec<usize>>,
    max_hops: usize,
    window: u32,
    max_steps: u64,
    steps: u64,
    through: Option<i32>,
    work: &'m mut Meter<'cx>,
    found: Vec<Cycle>,
    witness: fnx_cgse::WitnessSink,
}

impl Search<'_, '_, '_, '_> {
    fn visit(
        &mut self,
        first: usize,
        current: usize,
        path: &mut Vec<usize>,
        visited: &mut Vec<usize>,
        interval: Option<Interval>,
    ) -> Result<(), LanternError> {
        for position in 0..self.outgoing[current].len() {
            // Charge before inspecting or retaining a candidate. Exceeding a
            // cap refuses the entire search, including any earlier findings.
            self.work.compare(1)?;
            self.steps += 1;
            if self.steps > self.max_steps {
                return Err(LanternError::BudgetExhausted {
                    procedure: super::Kiting::ID.into(),
                    used: self.steps,
                    budget: self.max_steps,
                    fix: "increase --param max_search_steps within its registered bound or select an earlier --known-at; no partial cycle list is returned".into(),
                });
            }
            let index = self.outgoing[current][position];
            let edge = self.transfers[index];
            // Every adjacency choice follows canonical source-entry order.
            // The next candidate is deferred, not omitted from the census.
            // Record the actual DFS decisions in a streaming CGSE sink; no
            // generic fnx cycle algorithm is claimed for these interval rules.
            let next_choice = self.outgoing[current]
                .get(position + 1)
                .map(|next| self.transfers[*next].source.entry.vid.0.to_le_bytes());
            self.witness.record_decision_bytes(
                &edge.source.entry.vid.0.to_le_bytes(),
                next_choice.as_ref().map_or(&[], |next| next.as_slice()),
            );
            let (_, next) = self.endpoints[index];
            if next < first
                || path
                    .first()
                    .is_some_and(|prior| self.transfers[*prior].group != edge.group)
            {
                continue;
            }
            let next_interval = interval.map_or(
                Interval {
                    start: edge.start,
                    end: edge.end,
                    earliest: edge.earliest,
                    latest: edge.latest,
                },
                |previous| previous.include(&edge),
            );
            if !next_interval.admitted(self.window)
                || self.through.is_some_and(|day| next_interval.start > day)
            {
                continue;
            }
            if next == first {
                if path.is_empty() {
                    continue;
                }
                if self.found.len() == MAX_KITING_FINDINGS {
                    return Err(invalid(format!(
                        "the complete cycle census exceeds {MAX_KITING_FINDINGS} findings; narrow the selected history, no partial result is returned"
                    )));
                }
                self.work.compare((path.len() + 1) as u64)?;
                let mut cycle = path.clone();
                cycle.push(index);
                self.found.push(Cycle {
                    transfers: cycle,
                    start: next_interval.start,
                    end: next_interval.end,
                });
                continue;
            }
            if path.len() + 1 >= self.max_hops {
                continue;
            }
            // Distinct tuples alone would allow two ledger accounts for the
            // same bank instrument (or the reverse) to manufacture a cycle.
            let mut repeated = false;
            for prior in visited.iter().copied() {
                self.work.compare(1)?;
                if self.nodes[prior].account == self.nodes[next].account
                    || self.nodes[prior].instrument == self.nodes[next].instrument
                {
                    repeated = true;
                    break;
                }
            }
            if repeated {
                continue;
            }
            path.push(index);
            visited.push(next);
            self.visit(first, next, path, visited, Some(next_interval))?;
            path.pop();
            visited.pop();
        }
        Ok(())
    }
}

/// `transfers` is in a stable source-identity order. Starting only at each
/// cycle's least node gives one rotation while preserving parallel transfers.
pub(super) fn cycles(
    transfers: &[Transfer<'_>],
    max_hops: usize,
    window: u32,
    max_steps: u64,
    through: Option<i32>,
    work: &mut Meter<'_>,
) -> Result<CycleSearch, LanternError> {
    let count = transfers.len() as u64;
    let sort_work = count
        .saturating_mul(u64::from(count.saturating_add(1).ilog2().max(1)))
        .saturating_mul(8);
    work.compare(sort_work)?;
    let nodes: Vec<_> = transfers
        .iter()
        .flat_map(|edge| [edge.from(), edge.to()])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let ordinals: BTreeMap<_, _> = nodes
        .iter()
        .copied()
        .enumerate()
        .map(|(index, node)| (node, index))
        .collect();
    let mut outgoing = vec![Vec::new(); nodes.len()];
    let mut endpoints = Vec::with_capacity(transfers.len());
    for (index, transfer) in transfers.iter().enumerate() {
        work.compare(1)?;
        let from = ordinals[&transfer.from()];
        let to = ordinals[&transfer.to()];
        endpoints.push((from, to));
        outgoing[from].push(index);
    }
    let mut search = Search {
        transfers,
        nodes,
        endpoints,
        outgoing,
        max_hops,
        window,
        max_steps,
        steps: 0,
        through,
        work,
        found: Vec::new(),
        witness: fnx_cgse::WitnessSink::new(fnx_cgse::TieBreakPolicy::DfsPreorder),
    };
    for first in 0..search.nodes.len() {
        search.work.compare(1)?;
        search.visit(
            first,
            first,
            &mut Vec::with_capacity(max_hops),
            &mut vec![first],
            None,
        )?;
    }
    Ok(CycleSearch {
        cycles: search.found,
        witness: search.witness.finalize(
            search.nodes.len(),
            transfers.len(),
            "bounded_temporal_dfs_complete",
            None,
        ),
    })
}
