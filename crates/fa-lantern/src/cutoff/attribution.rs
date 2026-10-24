//! Party attribution for the creditor and investor procedures (bead
//! fa-6l8g). Version 2 of `lookback.preferences`, `ponzi.net_investment` and
//! the two distributions gave every party an entry named the entry's whole
//! cash: one payment of 300 settling A's 100 and B's 200 paid each of them
//! 300. Now an entry's cash, within each `(unit, legal entity)` partition,
//! reaches a party only through that party's own legs:
//!
//! * a leg names its party through its `PARTY_DIMENSION` values (a
//!   registered party's value, or the value itself); the same party repeated
//!   is one party, two parties on one leg name none, and no other dimension
//!   kind is ever a party;
//! * the *group* is the legs the cash settles or funds (a payment's
//!   obligation debits, a subscription's capital credits). When no group leg
//!   names a party, the group inherits the one party the cash legs name
//!   (counter-leg evidence); a group that is partly named keeps its unnamed
//!   legs unattributed;
//! * when the cash covers the whole group, each party receives its own
//!   group margin and the unnamed margin is unresolved; when it covers less,
//!   a group of one party and no unnamed leg receives all of it, cash legs
//!   that each name a party receive their own (up to that party's margin),
//!   and the rest is unresolved.
//!
//! Nothing is split in proportion and nothing is guessed: cash that no
//! party's own legs account for is unresolved, reported with its entry, and
//! given to no party. A partition in which no cash or group leg names a
//! party is not a party movement at all (a sale, a payroll run).

use std::collections::BTreeMap;

use fa_model::{LegPayload, PARTY_DIMENSION};
use fgdb_types::VId;

use crate::LanternError;
use crate::amount::{amount_difference, amount_sum};

/// Who a leg names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Named {
    None,
    One(VId),
    /// Two different parties on one leg: ambiguous, so it names none.
    Several,
}

/// The party `leg` names; `parties` maps a party's dimension value (and its
/// vid) to the party.
pub(super) fn named(leg: &LegPayload, parties: &BTreeMap<VId, VId>) -> Named {
    let mut out = Named::None;
    for &(dimension, value) in &leg.dimension_set {
        if dimension != PARTY_DIMENSION {
            continue;
        }
        let party = parties.get(&value).copied().unwrap_or(value);
        out = match out {
            Named::None => Named::One(party),
            Named::One(previous) if previous == party => Named::One(party),
            _ => Named::Several,
        };
    }
    out
}

/// One leg of a partition: who it names and its magnitude.
#[derive(Clone, Copy, Debug)]
pub(super) struct Leg {
    pub(super) named: Named,
    pub(super) amount: i128,
}

/// One partition's cash, attributed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Attributed {
    /// Per party: the cash attributed to it and its group margin.
    pub(super) parties: BTreeMap<VId, Share>,
    /// Per group leg, in order: the party it belongs to.
    pub(super) owners: Vec<Option<VId>>,
    /// Cash no party's own legs account for.
    pub(super) unresolved: i128,
    /// Some cash or group leg names a party: this is a party movement.
    pub(super) party_movement: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Share {
    pub(super) cash: i128,
    pub(super) margin: i128,
}

/// The one party `legs` name, when they name exactly one (and no leg names
/// several).
fn sole(legs: &[Leg]) -> Option<VId> {
    let mut one = None;
    for leg in legs {
        match leg.named {
            Named::None => {}
            Named::One(party) if one.is_none_or(|previous| previous == party) => {
                one = Some(party);
            }
            Named::One(_) | Named::Several => return None,
        }
    }
    one
}

/// The owner of each `group` leg: its own party, or, when no group leg names
/// one, the one party `counter` names.
pub(super) fn owners(group: &[Leg], counter: &[Leg]) -> Vec<Option<VId>> {
    let inherited = if group.iter().all(|leg| leg.named == Named::None) {
        sole(counter)
    } else {
        None
    };
    group
        .iter()
        .map(|leg| match leg.named {
            Named::One(party) => Some(party),
            Named::None => inherited,
            Named::Several => None,
        })
        .collect()
}

/// Attribute one partition's `cash` legs to the parties of the `group` legs
/// it settles or funds (the module's law).
pub(super) fn attribute(cash: &[Leg], group: &[Leg]) -> Result<Attributed, LanternError> {
    const WHAT: &str = "party attribution";
    let mut out = Attributed {
        party_movement: cash.iter().chain(group).any(|leg| leg.named != Named::None),
        owners: owners(group, cash),
        ..Attributed::default()
    };
    let total_cash = cash
        .iter()
        .try_fold(0i128, |sum, leg| amount_sum(sum, leg.amount, WHAT))?;
    if !out.party_movement || total_cash == 0 {
        return Ok(out);
    }
    let mut unnamed = 0i128;
    let mut group_total = 0i128;
    for (leg, owner) in group.iter().zip(&out.owners) {
        group_total = amount_sum(group_total, leg.amount, WHAT)?;
        match owner {
            Some(party) => {
                let share = out.parties.entry(*party).or_default();
                share.margin = amount_sum(share.margin, leg.amount, WHAT)?;
            }
            None => unnamed = amount_sum(unnamed, leg.amount, WHAT)?,
        }
    }
    if total_cash >= group_total {
        // Cash beyond the group funds legs outside it: no party's.
        for share in out.parties.values_mut() {
            share.cash = share.margin;
        }
        out.unresolved = unnamed;
        return Ok(out);
    }
    if unnamed == 0 && out.parties.len() == 1 {
        if let Some(share) = out.parties.values_mut().next() {
            share.cash = total_cash;
        }
        return Ok(out);
    }
    // Part of a group of several parties: only a cash leg naming its party
    // says whose part it paid.
    let mut remaining = total_cash;
    for leg in cash {
        let Named::One(party) = leg.named else {
            continue;
        };
        let Some(share) = out.parties.get_mut(&party) else {
            continue;
        };
        let open = amount_difference(share.margin, share.cash, WHAT)?;
        let take = leg.amount.min(open);
        if take > 0 {
            share.cash = amount_sum(share.cash, take, WHAT)?;
            remaining = amount_difference(remaining, take, WHAT)?;
        }
    }
    out.unresolved = remaining;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: VId = VId(0xA);
    const B: VId = VId(0xB);

    fn leg(named: Named, amount: i128) -> Leg {
        Leg { named, amount }
    }

    fn cash_of(a: &Attributed) -> BTreeMap<VId, i128> {
        a.parties.iter().map(|(p, s)| (*p, s.cash)).collect()
    }

    #[test]
    fn a_batched_payment_pays_each_creditor_its_own_margin() {
        let a = attribute(
            &[leg(Named::None, 300)],
            &[leg(Named::One(A), 100), leg(Named::One(B), 200)],
        )
        .unwrap();
        assert_eq!(cash_of(&a), BTreeMap::from([(A, 100), (B, 200)]));
        assert_eq!(a.unresolved, 0);
        assert_eq!(a.owners, vec![Some(A), Some(B)]);
    }

    #[test]
    fn counter_leg_evidence_names_an_unnamed_group() {
        let a = attribute(&[leg(Named::One(A), 300)], &[leg(Named::None, 300)]).unwrap();
        assert_eq!(cash_of(&a), BTreeMap::from([(A, 300)]));
        assert_eq!(a.owners, vec![Some(A)]);
    }

    #[test]
    fn a_partly_named_group_keeps_its_unnamed_margin_unresolved() {
        let a = attribute(
            &[leg(Named::None, 300)],
            &[leg(Named::One(A), 100), leg(Named::None, 200)],
        )
        .unwrap();
        assert_eq!(cash_of(&a), BTreeMap::from([(A, 100)]));
        assert_eq!(a.unresolved, 200);
    }

    #[test]
    fn a_leg_naming_two_parties_names_none() {
        let mut leg_ab = LegPayload::simple(
            fa_money::Side::Debit,
            VId(1),
            fa_money::Amount {
                unit: fa_money::UnitId(1),
                mantissa: 5,
            },
        );
        leg_ab.dimension_set = vec![(PARTY_DIMENSION, A), (PARTY_DIMENSION, B)];
        assert_eq!(named(&leg_ab, &BTreeMap::new()), Named::Several);
        leg_ab.dimension_set = vec![(PARTY_DIMENSION, A), (PARTY_DIMENSION, A)];
        assert_eq!(named(&leg_ab, &BTreeMap::new()), Named::One(A));
        leg_ab.dimension_set = vec![(fa_model::LEGAL_ENTITY_DIMENSION, A)];
        assert_eq!(named(&leg_ab, &BTreeMap::new()), Named::None);

        let a = attribute(&[leg(Named::None, 300)], &[leg(Named::Several, 300)]).unwrap();
        assert!(a.party_movement);
        assert!(a.parties.is_empty());
        assert_eq!(a.unresolved, 300);
    }

    #[test]
    fn short_cash_over_several_parties_is_unresolved_unless_its_legs_say_whose() {
        // A discount covers 50 of the 300: whose 250 the cash paid is unknown.
        let group = [leg(Named::One(A), 100), leg(Named::One(B), 200)];
        let a = attribute(&[leg(Named::None, 250)], &group).unwrap();
        assert!(cash_of(&a).values().all(|&c| c == 0));
        assert_eq!(a.unresolved, 250);
        // Cash legs naming their parties say it, capped by each margin.
        let a = attribute(&[leg(Named::One(A), 100), leg(Named::One(B), 150)], &group).unwrap();
        assert_eq!(cash_of(&a), BTreeMap::from([(A, 100), (B, 150)]));
        assert_eq!(a.unresolved, 0);
        // One party's group takes the short cash whole.
        let a = attribute(&[leg(Named::None, 95)], &[leg(Named::One(A), 100)]).unwrap();
        assert_eq!(cash_of(&a), BTreeMap::from([(A, 95)]));
    }

    #[test]
    fn a_partition_naming_no_party_is_not_a_party_movement() {
        let a = attribute(&[leg(Named::None, 300)], &[leg(Named::None, 300)]).unwrap();
        assert!(!a.party_movement);
        assert!(a.parties.is_empty());
        assert_eq!(a.unresolved, 0);
    }
}
