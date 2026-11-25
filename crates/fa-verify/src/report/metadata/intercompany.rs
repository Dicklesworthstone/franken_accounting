//! Independent interpretation of native atomic intercompany declarations.
//!
//! These checks validate the authenticated literal monetary profile. They do
//! not assert posting authority, account policy or transactional key admission.

use std::collections::{BTreeMap, BTreeSet};

use crate::codec::Reader;
use crate::envelope::{Leg, LegDetails, proposal_legs_and_details};

use super::{ReportError, failed, text};

fn invalid(message: &'static str) -> ReportError {
    failed("intercompany_pairs", message)
}

pub(super) fn validate(proposal: &[u8], bytes: &[u8]) -> Result<(), ReportError> {
    let (legs, details) = proposal_legs_and_details(proposal)?;
    validate_pairs(bytes, &legs, &details)
}

fn validate_pairs(bytes: &[u8], legs: &[Leg], details: &[LegDetails]) -> Result<(), ReportError> {
    if bytes.len() > 65_536 || legs.len() != details.len() {
        return Err(invalid("intercompany declaration exceeds its bound or has incomplete legs"));
    }
    let mut r = Reader::new(bytes);
    if r.u16("intercompany.version")? != 1 {
        return Err(invalid("unsupported intercompany declaration version"));
    }
    let count = r.count(2_048, 9, "intercompany.pairs")?;
    if count == 0 {
        return Err(invalid("intercompany declarations must contain a complete pair"));
    }
    let unit = legs.first().map(|leg| leg.unit);
    let mut entities = Vec::with_capacity(details.len());
    let mut totals = BTreeMap::<u128, (i128, i128)>::new();
    for (leg, detail) in legs.iter().zip(details) {
        if Some(leg.unit) != unit || detail.base_amount.is_some() || leg.mantissa < 0 {
            return Err(invalid(
                "native intercompany entries require one unit, nonnegative amounts and no FX valuation",
            ));
        }
        let Some((_, entity)) = detail.dimensions.iter().find(|(dimension, _)| *dimension == 1)
        else {
            return Err(invalid("every intercompany entry leg must name its legal entity"));
        };
        entities.push(*entity);
        let totals = totals.entry(*entity).or_default();
        let total = if leg.debit { &mut totals.0 } else { &mut totals.1 };
        *total = total
            .checked_add(leg.mantissa)
            .ok_or_else(|| invalid("intercompany per-entity total overflow"))?;
    }
    if totals.values().any(|(debits, credits)| debits != credits) {
        return Err(invalid("a complete intercompany entry must balance each legal entity"));
    }
    let mut previous = None;
    let mut used = BTreeSet::new();
    for _ in 0..count {
        let key = text(&mut r, 64, "intercompany.pair_key")?;
        let left = usize::from(r.u16("intercompany.left_leg")?);
        let right = usize::from(r.u16("intercompany.right_leg")?);
        if key.trim().is_empty() || previous.is_some_and(|last| last >= key) {
            return Err(invalid("pair keys must be nonempty and strictly ascending"));
        }
        previous = Some(key);
        if left >= right || right >= legs.len() || !used.insert(left) || !used.insert(right) {
            return Err(invalid("pair leg ordinals must be ascending, in range and used once"));
        }
        let lhs = &legs[left];
        let rhs = &legs[right];
        if lhs.mantissa <= 0
            || lhs.mantissa != rhs.mantissa
            || lhs.unit != rhs.unit
            || lhs.debit == rhs.debit
            || lhs.account == rhs.account
            || entities[left] == entities[right]
        {
            return Err(invalid(
                "reciprocal pairs require distinct accounts and entities, equal positive native amounts and opposite sides",
            ));
        }
    }
    r.finish("intercompany pairs")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(pairs: &[(&str, u16, u16)]) -> Vec<u8> {
        let mut bytes = 1u16.to_le_bytes().to_vec();
        bytes.extend_from_slice(&(pairs.len() as u32).to_le_bytes());
        for (key, left, right) in pairs {
            bytes.extend_from_slice(&(key.len() as u32).to_le_bytes());
            bytes.extend_from_slice(key.as_bytes());
            bytes.extend_from_slice(&left.to_le_bytes());
            bytes.extend_from_slice(&right.to_le_bytes());
        }
        bytes
    }

    fn fixture() -> (Vec<Leg>, Vec<LegDetails>) {
        let legs = [(1, true), (2, false), (3, true), (4, false)]
            .into_iter()
            .map(|(account, debit)| Leg { account, debit, unit: 0, mantissa: 100 })
            .collect();
        let details = [10, 10, 20, 20]
            .into_iter()
            .map(|entity| LegDetails {
                base_amount: None,
                dimensions: vec![(1, entity)],
                settlements: Vec::new(),
            })
            .collect();
        (legs, details)
    }

    #[test]
    fn replay_checks_complete_native_pairs_and_per_entity_balance() {
        let bytes = encoded(&[("sale-1", 1, 2)]);
        let (legs, details) = fixture();
        assert!(validate_pairs(&bytes, &legs, &details).is_ok());
        for end in 0..bytes.len() {
            assert!(validate_pairs(&bytes[..end], &legs, &details).is_err());
        }
        let mut mismatched = legs.clone();
        mismatched[2].mantissa = 200;
        mismatched[3].mantissa = 200;
        assert!(validate_pairs(&bytes, &mismatched, &details).is_err());
        let mut unbalanced = details.clone();
        unbalanced[0].dimensions[0].1 = 20;
        unbalanced[3].dimensions[0].1 = 10;
        assert!(validate_pairs(&bytes, &legs, &unbalanced).is_err());
        let mut same_entity = details.clone();
        for detail in &mut same_entity {
            detail.dimensions[0].1 = 10;
        }
        assert!(validate_pairs(&bytes, &legs, &same_entity).is_err());
        for pairs in [
            vec![],
            vec![("sale-1", 0, 2)],
            vec![("sale-1", 1, 4)],
            vec![("sale-1", 2, 1)],
            vec![("sale-1", 1, 2), ("sale-2", 2, 3)],
            vec![("sale-1", 0, 3), ("sale-1", 1, 2)],
        ] {
            assert!(validate_pairs(&encoded(&pairs), &legs, &details).is_err());
        }
        let mut foreign = legs.clone();
        foreign[3].unit = 1;
        assert!(validate_pairs(&bytes, &foreign, &details).is_err());
        let mut valued = details;
        valued[0].base_amount = Some((0, 100));
        assert!(validate_pairs(&bytes, &legs, &valued).is_err());
    }
}
