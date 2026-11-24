//! Independent replay of account circular flows v2 and layering v3.
//!
//! Original posting legs determine the complete unit/entity-partitioned
//! transfer population. An iterative SCC traversal and bounded reachability
//! checks replace the producer's graph library. Chronological adjacency
//! indexes preserve its first-eligible-hop law, including unsuccessful
//! closing attempts; producer paths and graph witnesses are never inputs.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    Entry, MAX_FINDINGS, Reader, Registry, ReportError, VerifiedProcedureFinding,
    VerifiedProcedureParameters, VerifiedProcedureStatistic, failed, structuring, text,
};

pub(super) const CIRCULAR_DEFAULTS: [(&str, u32); 3] = [
    ("max_hops", 6),
    ("min_retention_bps", 7_000),
    ("window_days", 14),
];
pub(super) const LAYERING_DEFAULTS: [(&str, u32); 3] = [
    ("min_hops", 3),
    ("min_passthrough_bps", 8_500),
    ("window_days", 10),
];

// Native work counters describe the historical algorithm, not a recipient's
// resource policy. Bound our graph visits separately and refuse the entire
// report on exhaustion; never truncate a path or accept partial findings.
const MAX_GRAPH_VISITS: u64 = 10_000_000;

struct Budget(u64);

impl Budget {
    fn visit(&mut self) -> Result<(), ReportError> {
        self.0 = self.0.checked_sub(1).ok_or_else(|| {
            failed(
                "bounded_input",
                "temporal graph replay exceeds its independent traversal budget; no partial result is verified",
            )
        })?;
        Ok(())
    }
}

fn invalid(message: &str) -> ReportError {
    failed("procedure_profile", message)
}

pub(super) fn decode(
    reader: &mut Reader<'_>,
    circular: bool,
) -> Result<VerifiedProcedureParameters, ReportError> {
    let defaults = if circular {
        &CIRCULAR_DEFAULTS
    } else {
        &LAYERING_DEFAULTS
    };
    if reader.count(defaults.len(), 20, "procedure.parameters")? != defaults.len() {
        return Err(invalid(
            "temporal graph replay requires three explicit parameters",
        ));
    }
    let mut values = [0u32; 3];
    for (index, (name, _)) in defaults.iter().enumerate() {
        if text(reader, 64, "procedure.parameter")? != *name {
            return Err(invalid(
                "temporal graph parameters must be unique and lexically ordered",
            ));
        }
        values[index] = u32::try_from(reader.i128("procedure.parameter_value")?)
            .map_err(|_| invalid("temporal graph parameters require unsigned 32-bit integers"))?;
    }
    if !(2..=8).contains(&values[0]) {
        return Err(invalid("temporal graph hop bounds must be in 2..=8"));
    }
    Ok(if circular {
        VerifiedProcedureParameters::GraphCircularFlows {
            max_hops: values[0],
            min_retention_bps: values[1],
            window_days: values[2],
        }
    } else {
        VerifiedProcedureParameters::GraphLayering {
            min_hops: values[0],
            min_passthrough_bps: values[1],
            window_days: values[2],
        }
    })
}

/// Exact floor(numerator * 10000 / denominator) without a wide product.
/// Path bottlenecks and non-increasing pass-through amounts are in 0..=denom.
/// The remainder is reduced after each doubling and addition, so it fits u128
/// even when both monetary magnitudes approach i128::MAX.
fn basis_points(numerator: i128, denominator: i128) -> Result<i128, ReportError> {
    if numerator < 0 || denominator <= 0 || numerator > denominator {
        return Err(failed(
            "procedure_arithmetic",
            "invalid temporal flow ratio",
        ));
    }
    let numerator = numerator as u128;
    let denominator = denominator as u128;
    let whole = numerator / denominator;
    let fraction = numerator % denominator;
    let (mut quotient, mut remainder) = (0u128, 0u128);
    for bit in (0..14).rev() {
        quotient *= 2;
        remainder *= 2;
        if remainder >= denominator {
            quotient += 1;
            remainder -= denominator;
        }
        if 10_000u32 & (1 << bit) != 0 {
            remainder += fraction;
            if remainder >= denominator {
                quotient += 1;
                remainder -= denominator;
            }
        }
    }
    Ok((whole * 10_000 + quotient) as i128)
}

fn charge(comparisons: &mut u64, count: usize) -> Result<(), ReportError> {
    *comparisons = comparisons.checked_add(count as u64).ok_or_else(|| {
        failed(
            "procedure_arithmetic",
            "temporal graph work count exceeds u64",
        )
    })?;
    Ok(())
}

type Transfer = structuring::Transfer;

struct Graph {
    index: BTreeMap<u128, usize>,
    outgoing: Vec<Vec<usize>>,
    incoming: Vec<Vec<usize>>,
}

impl Graph {
    fn new(legs: &[&Transfer], budget: &mut Budget) -> Result<Self, ReportError> {
        let mut nodes = BTreeSet::new();
        let mut pairs = BTreeSet::new();
        for leg in legs {
            budget.visit()?;
            nodes.insert(leg.from);
            nodes.insert(leg.to);
            pairs.insert((leg.from, leg.to));
        }
        let index: BTreeMap<_, _> = nodes.into_iter().enumerate().map(|(i, n)| (n, i)).collect();
        let mut outgoing = vec![Vec::new(); index.len()];
        let mut incoming = vec![Vec::new(); index.len()];
        for (from, to) in pairs {
            budget.visit()?;
            let (from, to) = (index[&from], index[&to]);
            outgoing[from].push(to);
            incoming[to].push(from);
        }
        Ok(Self {
            index,
            outgoing,
            incoming,
        })
    }

    /// Iterative Kosaraju: no input-controlled recursion or producer SCC data.
    fn components(&self, budget: &mut Budget) -> Result<(Vec<usize>, Vec<usize>), ReportError> {
        let mut seen = vec![false; self.index.len()];
        let mut finished = Vec::with_capacity(seen.len());
        for start in 0..seen.len() {
            if seen[start] {
                continue;
            }
            seen[start] = true;
            let mut stack = vec![(start, 0usize)];
            while let Some((node, next)) = stack.last_mut() {
                budget.visit()?;
                if let Some(&child) = self.outgoing[*node].get(*next) {
                    *next += 1;
                    if !seen[child] {
                        seen[child] = true;
                        stack.push((child, 0));
                    }
                } else {
                    finished.push(*node);
                    stack.pop();
                }
            }
        }
        let mut component = vec![usize::MAX; seen.len()];
        let mut sizes = Vec::new();
        for start in finished.into_iter().rev() {
            if component[start] != usize::MAX {
                continue;
            }
            let id = sizes.len();
            let mut size = 0usize;
            component[start] = id;
            let mut stack = vec![start];
            while let Some(node) = stack.pop() {
                budget.visit()?;
                size += 1;
                for &child in &self.incoming[node] {
                    budget.visit()?;
                    if component[child] == usize::MAX {
                        component[child] = id;
                        stack.push(child);
                    }
                }
            }
            sizes.push(size);
        }
        Ok((component, sizes))
    }

    /// Only the predicate reachable > min_hops affects the registered law.
    /// Stop when proved; a direct shortcut must not hide a longer chain.
    fn has_reachable(
        &self,
        source: u128,
        min_hops: usize,
        budget: &mut Budget,
    ) -> Result<bool, ReportError> {
        let source = self.index[&source];
        let mut seen = BTreeSet::from([source]);
        let mut stack = vec![source];
        while let Some(node) = stack.pop() {
            budget.visit()?;
            for &child in &self.outgoing[node] {
                budget.visit()?;
                if seen.insert(child) {
                    if seen.len() > min_hops {
                        return Ok(true);
                    }
                    stack.push(child);
                }
            }
        }
        Ok(false)
    }
}

fn adjacency(legs: &[&Transfer]) -> BTreeMap<u128, Vec<usize>> {
    let mut outgoing: BTreeMap<u128, Vec<usize>> = BTreeMap::new();
    for (index, leg) in legs.iter().enumerate() {
        outgoing.entry(leg.from).or_default().push(index);
    }
    outgoing
}

fn after(outgoing: &BTreeMap<u128, Vec<usize>>, from: u128, last: usize) -> &[usize] {
    let Some(indices) = outgoing.get(&from) else {
        return &[];
    };
    &indices[indices.partition_point(|&index| index <= last)..]
}

/// The CGSE decision-path transcript is independently reconstructed from the
/// selected original transfers: each lower-case 32-hex node label has a u64
/// little-endian byte length. Its first eight BLAKE3 bytes appear in output.
fn witness(legs: &[&Transfer], path: &[usize]) -> String {
    let mut transcript = Vec::with_capacity(path.len() * 80);
    for &index in path {
        for node in [legs[index].from, legs[index].to] {
            transcript.extend_from_slice(&32u64.to_le_bytes());
            transcript.extend_from_slice(format!("{node:032x}").as_bytes());
        }
    }
    crate::blake3::hash(&transcript)[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn push(
    findings: &mut Vec<VerifiedProcedureFinding>,
    finding: VerifiedProcedureFinding,
) -> Result<(), ReportError> {
    if findings.len() >= MAX_FINDINGS {
        return Err(failed(
            "bounded_input",
            "temporal graph findings exceed the certificate bound",
        ));
    }
    findings.push(finding);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn circular(
    legs: &[&Transfer],
    max_hops: usize,
    minimum: i128,
    window: i64,
    scale: u8,
    population: u64,
    findings: &mut Vec<VerifiedProcedureFinding>,
    comparisons: &mut u64,
    budget: &mut Budget,
) -> Result<(), ReportError> {
    let outgoing = adjacency(legs);
    let mut used = vec![false; legs.len()];
    for start in 0..legs.len() {
        budget.visit()?;
        if used[start] {
            continue;
        }
        let first = legs[start];
        let mut path = vec![start];
        let mut visited = BTreeSet::from([first.from, first.to]);
        let (mut last, mut retained, mut closed) = (start, first.amount, false);
        while path.len() < max_hops {
            charge(comparisons, 1)?;
            let current = legs[last];
            // The first otherwise eligible closing transfer controls this
            // attempt even when its retained amount misses the threshold.
            let mut closing = None;
            for &index in after(&outgoing, current.to, last) {
                budget.visit()?;
                let leg = legs[index];
                if !used[index]
                    && leg.to == first.from
                    && leg.effective >= current.effective
                    && i64::from(leg.effective) - i64::from(first.effective) <= window
                    && leg.entry != current.entry
                {
                    closing = Some(index);
                    break;
                }
            }
            if let Some(index) = closing {
                let amount = retained.min(legs[index].amount);
                if basis_points(amount, first.amount)? >= minimum {
                    path.push(index);
                    retained = amount;
                    closed = true;
                    break;
                }
            }
            if path.len() + 1 >= max_hops {
                break;
            }
            let mut next = None;
            for &index in after(&outgoing, current.to, last) {
                budget.visit()?;
                let leg = legs[index];
                if !used[index]
                    && !visited.contains(&leg.to)
                    && leg.effective >= current.effective
                    && i64::from(leg.effective) - i64::from(first.effective) <= window
                    && basis_points(retained.min(leg.amount), first.amount)? >= minimum
                {
                    next = Some(index);
                    break;
                }
            }
            let Some(index) = next else { break };
            path.push(index);
            visited.insert(legs[index].to);
            last = index;
            retained = retained.min(legs[index].amount);
        }
        if closed {
            for &index in &path {
                used[index] = true;
            }
            let retention = basis_points(retained, first.amount)?;
            let proof = witness(legs, &path);
            push(
                findings,
                VerifiedProcedureFinding {
                    entry: None,
                    severity: 3,
                    statistic: VerifiedProcedureStatistic::CircularFlow {
                        hops: path
                            .iter()
                            .map(|&i| (legs[i].entry, legs[i].from))
                            .collect(),
                        unit: first.unit,
                        entity: first.entity,
                        mantissa: retained,
                        scale,
                    },
                    population,
                    narrative: format!(
                        "{}-hop directed cycle in SCC retaining {retained} of {} ({retention} bps, cgse_witness={proof})",
                        path.len(),
                        first.amount
                    ),
                },
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn layering(
    legs: &[&Transfer],
    graph: &Graph,
    min_hops: usize,
    minimum: i128,
    window: i64,
    scale: u8,
    population: u64,
    findings: &mut Vec<VerifiedProcedureFinding>,
    comparisons: &mut u64,
    budget: &mut Budget,
) -> Result<(), ReportError> {
    let outgoing = adjacency(legs);
    let mut reachable = BTreeMap::new();
    let mut used = vec![false; legs.len()];
    for start in 0..legs.len() {
        budget.visit()?;
        if used[start] {
            continue;
        }
        let first = legs[start];
        let enough = match reachable.get(&first.from) {
            Some(&enough) => enough,
            None => {
                let enough = graph.has_reachable(first.from, min_hops, budget)?;
                reachable.insert(first.from, enough);
                enough
            }
        };
        if !enough {
            continue;
        }
        let mut path = vec![start];
        let mut visited = BTreeSet::from([first.from, first.to]);
        let (mut last, mut minimum_amount) = (start, first.amount);
        while path.len() < 8 {
            charge(comparisons, 1)?;
            let current = legs[last];
            let mut next = None;
            for &index in after(&outgoing, current.to, last) {
                budget.visit()?;
                let leg = legs[index];
                if !used[index]
                    && !visited.contains(&leg.to)
                    && leg.effective >= current.effective
                    && i64::from(leg.effective) - i64::from(first.effective) <= window
                    && leg.amount <= current.amount
                    && basis_points(leg.amount, current.amount)? >= minimum
                {
                    next = Some(index);
                    break;
                }
            }
            let Some(index) = next else { break };
            path.push(index);
            visited.insert(legs[index].to);
            last = index;
            minimum_amount = minimum_amount.min(legs[index].amount);
        }
        if path.len() >= min_hops {
            for &index in &path {
                used[index] = true;
            }
            let proof = witness(legs, &path);
            push(
                findings,
                VerifiedProcedureFinding {
                    entry: None,
                    severity: 3,
                    statistic: VerifiedProcedureStatistic::LayeredFlow {
                        hops: path
                            .iter()
                            .map(|&i| (legs[i].entry, legs[i].from))
                            .collect(),
                        destination: legs[last].to,
                        unit: first.unit,
                        entity: first.entity,
                        mantissa: minimum_amount,
                        scale,
                    },
                    population,
                    narrative: format!(
                        "{}-hop pass-through chain forwarding {minimum_amount} of {} within {window} day(s) (cgse_witness={proof})",
                        path.len(),
                        first.amount
                    ),
                },
            )?;
        }
    }
    Ok(())
}

pub(super) fn replay(
    profile: VerifiedProcedureParameters,
    live: &[&Entry],
    registry: &Registry,
) -> Result<(Vec<VerifiedProcedureFinding>, u64, u64), ReportError> {
    let transfers = structuring::flow(live, registry)?;
    let population = transfers.len() as u64;
    let mut partitions: BTreeMap<_, Vec<&Transfer>> = BTreeMap::new();
    for transfer in &transfers {
        if !registry.account_types.contains_key(&transfer.from)
            || !registry.account_types.contains_key(&transfer.to)
        {
            return Err(invalid(
                "temporal graph accounts lack authenticated declarations",
            ));
        }
        if transfer.amount > 0 && transfer.from != transfer.to {
            partitions
                .entry((transfer.entity, transfer.unit))
                .or_default()
                .push(transfer);
        }
    }
    let mut findings = Vec::new();
    let mut comparisons = 0u64;
    let mut budget = Budget(MAX_GRAPH_VISITS);
    for ((_, unit), mut legs) in partitions {
        legs.sort_by_key(|leg| (leg.effective, leg.recorded, leg.entry, leg.from, leg.to));
        charge(&mut comparisons, legs.len())?;
        let scale = *registry
            .unit_scales
            .get(&unit)
            .ok_or_else(|| invalid("temporal graph unit has no authenticated scale"))?;
        let graph = Graph::new(&legs, &mut budget)?;
        match profile {
            VerifiedProcedureParameters::GraphCircularFlows {
                max_hops,
                min_retention_bps,
                window_days,
            } => {
                let (components, sizes) = graph.components(&mut budget)?;
                let mut by_component: BTreeMap<_, Vec<&Transfer>> = BTreeMap::new();
                for leg in legs {
                    budget.visit()?;
                    let component = components[graph.index[&leg.from]];
                    if component == components[graph.index[&leg.to]] && sizes[component] >= 2 {
                        by_component.entry(component).or_default().push(leg);
                    }
                }
                for legs in by_component.into_values() {
                    circular(
                        &legs,
                        max_hops as usize,
                        i128::from(min_retention_bps),
                        i64::from(window_days),
                        scale,
                        population,
                        &mut findings,
                        &mut comparisons,
                        &mut budget,
                    )?;
                }
            }
            VerifiedProcedureParameters::GraphLayering {
                min_hops,
                min_passthrough_bps,
                window_days,
            } => {
                layering(
                    &legs,
                    &graph,
                    min_hops as usize,
                    i128::from(min_passthrough_bps),
                    i64::from(window_days),
                    scale,
                    population,
                    &mut findings,
                    &mut comparisons,
                    &mut budget,
                )?;
            }
            _ => return Err(invalid("expected an account temporal graph procedure")),
        }
    }
    Ok((findings, population, comparisons))
}

#[cfg(test)]
mod tests;
