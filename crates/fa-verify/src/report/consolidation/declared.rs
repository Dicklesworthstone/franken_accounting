//! Independent transaction-granular intercompany inputs for v14/v15.
//!
//! The authenticated source legs, not the producer's matched-pair transcript,
//! determine every amount. Stock and period activity are separate signed folds:
//! a later-period reversal cancels stock but contributes negative activity in
//! its own period. Multiple economic keys may use the same account endpoints.

use std::collections::{BTreeMap, BTreeSet};

use crate::envelope::{LeafEnvelope, Leg, LegDetails, proposal_leg_details};

use super::{Entity, ReportError, add, functional, invalid, metadata, negate, statement};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsolidationPairKind {
    ReceivablePayable,
    RevenueExpense,
}

impl ConsolidationPairKind {
    pub(super) fn tag(self) -> u8 {
        match self {
            Self::ReceivablePayable => 1,
            Self::RevenueExpense => 2,
        }
    }
}

/// One economic pair's independently folded debit-normal endpoint amounts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsolidationPair {
    pub pair_key: String,
    pub kind: ConsolidationPairKind,
    pub unit_id: u32,
    pub entity_a: Entity,
    pub account_a: u128,
    pub entity_a_net: i128,
    pub entity_b: Entity,
    pub account_b: u128,
    pub entity_b_net: i128,
}

#[derive(Default)]
pub(super) struct Population {
    pub stock: Vec<ConsolidationPair>,
    pub income: Vec<ConsolidationPair>,
}

// The native declaration profile has the same bounded economic-pair population.
const MAX_DECLARED_PAIRS: usize = 4096;

fn dimensions(index: usize, records: &[(usize, &[u8])]) -> Result<Vec<LegDetails>, ReportError> {
    let (length, record) = records
        .get(index)
        .ok_or_else(|| invalid("intercompany source record is absent"))?;
    let proposal = record
        .get(..*length)
        .ok_or_else(|| invalid("intercompany source proposal is truncated"))?;
    Ok(proposal_leg_details(proposal)?)
}

fn merge(
    totals: &mut BTreeMap<String, ConsolidationPair>,
    contribution: ConsolidationPair,
) -> Result<(), ReportError> {
    if let Some(pair) = totals.get_mut(&contribution.pair_key) {
        if pair.kind != contribution.kind
            || pair.unit_id != contribution.unit_id
            || pair.entity_a != contribution.entity_a
            || pair.account_a != contribution.account_a
            || pair.entity_b != contribution.entity_b
            || pair.account_b != contribution.account_b
        {
            return Err(invalid(
                "an intercompany key changes its original endpoints",
            ));
        }
        pair.entity_a_net = add(pair.entity_a_net, contribution.entity_a_net)?;
        pair.entity_b_net = add(pair.entity_b_net, contribution.entity_b_net)?;
    } else {
        if totals.len() >= MAX_DECLARED_PAIRS {
            return Err(super::failed(
                "bounded_input",
                "declared intercompany population exceeds 4096 pairs",
            ));
        }
        totals.insert(contribution.pair_key.clone(), contribution);
    }
    Ok(())
}

fn entity(
    detail: &LegDetails,
    spec: &functional::BookParameters,
    members: &BTreeMap<String, Entity>,
) -> Result<Entity, ReportError> {
    let value = detail
        .dimensions
        .iter()
        .find(|(kind, _)| *kind == 1)
        .map(|(_, value)| value)
        .ok_or_else(|| invalid("declared intercompany leg has no legal entity"))?;
    let code = spec
        .entities
        .get(value)
        .ok_or_else(|| invalid("declared intercompany entity is not in this book"))?;
    members
        .get(code)
        .copied()
        .ok_or_else(|| invalid("declared intercompany entity is not a group member"))
}

/// Validate all declarations and reversal inheritance in the retained prefix,
/// then fold only the selected effective population. Historical admission and
/// current disclosure authority are not inferred from these arithmetic checks.
#[allow(clippy::too_many_arguments)]
pub(super) fn fold(
    spec: &functional::BookParameters,
    members: &BTreeMap<String, Entity>,
    schema: &metadata::Schema,
    period: &str,
    through: i32,
    envelopes: &[LeafEnvelope],
    records: &[(usize, &[u8])],
    legs: &[Vec<Leg>],
    infos: &BTreeMap<usize, metadata::EntryInfo<'_>>,
    identities: &BTreeMap<u128, usize>,
) -> Result<Population, ReportError> {
    let mut original_keys = BTreeSet::new();
    let mut declarations = BTreeMap::new();
    for (&index, info) in infos {
        let Some(bytes) = info.intercompany_pairs else {
            continue;
        };
        let source = legs
            .get(index)
            .ok_or_else(|| invalid("declared intercompany legs are absent"))?;
        let details = dimensions(index, records)?;
        let pairs = metadata::intercompany::validate_pairs(bytes, source, &details)?;
        if source.iter().any(|leg| leg.unit != spec.base) {
            return Err(invalid(
                "native declared intercompany pairs require the book's base unit",
            ));
        }
        for detail in &details {
            entity(detail, spec, members)?;
        }
        if envelopes[index].class != 4 {
            for pair in &pairs {
                if !original_keys.insert(pair.key.clone()) {
                    return Err(invalid("an original intercompany pair key is reused"));
                }
            }
        }
        declarations.insert(index, (pairs, details));
    }

    let mut lineage = statement::Lineage::default();
    let mut reversed_targets = BTreeSet::new();
    for (&index, info) in infos {
        if envelopes[index].class != 4 {
            continue;
        }
        let target = match info.supersession.as_slice() {
            [(identity, _, 1)] => identities.get(identity).copied(),
            _ => None,
        }
        .ok_or_else(|| invalid("reversal requires one retained Reverses target"))?;
        if !reversed_targets.insert(target) {
            return Err(invalid("an entry is reversed more than once"));
        }
        statement::origin(index, envelopes, infos, identities, &mut lineage)?;
        let target_declaration = infos.get(&target).and_then(|info| info.intercompany_pairs);
        if info.intercompany_pairs.is_none() && target_declaration.is_none() {
            continue;
        }
        if info.intercompany_pairs != target_declaration {
            return Err(invalid(
                "an intercompany reversal changes or drops the original declaration",
            ));
        }
        let source = legs
            .get(index)
            .ok_or_else(|| invalid("intercompany reversal legs are absent"))?;
        let original = legs
            .get(target)
            .ok_or_else(|| invalid("intercompany reversal target legs are absent"))?;
        let (_, source_details) = declarations
            .get(&index)
            .ok_or_else(|| invalid("intercompany reversal declaration is absent"))?;
        let (_, original_details) = declarations
            .get(&target)
            .ok_or_else(|| invalid("intercompany reversal target declaration is absent"))?;
        if source.len() != original.len() || source_details.len() != original_details.len() {
            return Err(invalid(
                "an intercompany reversal changes its target's leg count",
            ));
        }
        for ((after, before), (after_details, before_details)) in source
            .iter()
            .zip(original)
            .zip(source_details.iter().zip(original_details))
        {
            if after.account != before.account
                || after.unit != before.unit
                || after.mantissa != before.mantissa
                || after.debit == before.debit
                || after_details.base_amount != before_details.base_amount
                || after_details.dimensions != before_details.dimensions
            {
                return Err(invalid(
                    "an intercompany reversal is not the exact monetary side swap",
                ));
            }
        }
    }

    let mut stock = BTreeMap::new();
    let mut income = BTreeMap::new();
    // Match the journal's deterministic observation order, including members
    // published atomically at one sequence.
    let mut ordered: Vec<_> = declarations.into_iter().collect();
    ordered.sort_by_key(|(index, _)| (envelopes[*index].commit_seq, infos[index].identity));
    for (index, (pairs, details)) in ordered {
        let day = envelopes[index]
            .effective_day
            .ok_or_else(|| invalid("declared intercompany posting has no effective date"))?;
        if day > through {
            continue;
        }
        let in_period = schema.entry_period(&infos[&index], day)? == period;
        for pair in pairs {
            let left = &legs[index][pair.left];
            let right = &legs[index][pair.right];
            let left_type = schema
                .accounts
                .get(&left.account)
                .filter(|account| account.is_leaf)
                .map(|account| account.account_type);
            let right_type = schema
                .accounts
                .get(&right.account)
                .filter(|account| account.is_leaf)
                .map(|account| account.account_type);
            let kind = match (left_type, right_type) {
                (Some(1), Some(2)) | (Some(2), Some(1)) => ConsolidationPairKind::ReceivablePayable,
                (Some(4), Some(5)) | (Some(5), Some(4)) => ConsolidationPairKind::RevenueExpense,
                _ => {
                    return Err(invalid(
                        "declared consolidation pairs require asset/liability or revenue/expense endpoints",
                    ));
                }
            };
            let contribution = ConsolidationPair {
                pair_key: pair.key,
                kind,
                unit_id: left.unit,
                entity_a: entity(&details[pair.left], spec, members)?,
                account_a: left.account,
                entity_a_net: if left.debit {
                    left.mantissa
                } else {
                    negate(left.mantissa)?
                },
                entity_b: entity(&details[pair.right], spec, members)?,
                account_b: right.account,
                entity_b_net: if right.debit {
                    right.mantissa
                } else {
                    negate(right.mantissa)?
                },
            };
            if in_period && kind == ConsolidationPairKind::RevenueExpense {
                merge(&mut income, contribution.clone())?;
            }
            merge(&mut stock, contribution)?;
        }
    }
    Ok(Population {
        stock: stock
            .into_values()
            .filter(|pair| pair.entity_a_net != 0)
            .collect(),
        income: income
            .into_values()
            .filter(|pair| pair.entity_a_net != 0)
            .collect(),
    })
}
