//! Relational expectations over an observed covariate
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §2.6 rule 9; bead fa-yugf.13, A5b).
//!
//! An input the code reads but the harness cannot set is not a branch. The
//! only one today is account-VId order: `fa book create` draws the book id
//! from production entropy, and `account_vid = H("fa:vid:account:v1" ‖
//! book_id ‖ code)` (`crates/fa-model/src/ids.rs:296-298`). A component that
//! depends on it is `Rel(account_vid_order)`: the expectation names the
//! code's selection rule from the closed list below, and the runner checks
//! it on every run against the VIds of that run's book.
//!
//! The VIds come from the runner (`fa_model::account_vid(book, code).0`,
//! the `u128` inside `VId`, whose order is the numeric order Lantern sorts
//! by); this module only orders them.

use std::collections::{BTreeMap, BTreeSet};

/// The rules a `rel_rule` may name, as written before the `{role}`.
pub const RULES: [&str; 2] = ["min_vid_debit_leg", "max_vid_debit_leg"];

/// A relational rule: which leg of the entry a component follows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelRule {
    /// The debit leg on the minimum-VId account holding `role` among the
    /// entry's legs: `expense.capitalization`@2's selection
    /// (`crates/fa-lantern/src/cutoff.rs:1086-1110`: fixed-asset debits
    /// sorted by (account VId, unit, magnitude), the first taken).
    MinVidDebitLeg { role: String },
    /// The same with the maximum VId (the last in that order). No procedure
    /// selects this way; it is listed so that a misreading of the code can
    /// be written down and caught at run time.
    MaxVidDebitLeg { role: String },
}

impl RelRule {
    /// Parses `<rule>{<role>}`. `roles` is the registry's role list
    /// (`registries/account_roles.toml`).
    ///
    /// # Errors
    ///
    /// A rule outside [`RULES`], a missing or empty `{role}`, or a role the
    /// registry does not list.
    pub fn parse(s: &str, roles: &[&str]) -> Result<Self, String> {
        let Some((name, rest)) = s.split_once('{') else {
            return Err(format!(
                "`rel_rule = \"{s}\"` is `<rule>{{<role>}}` with <rule> one of {}",
                RULES.join(", ")
            ));
        };
        let Some(role) = rest.strip_suffix('}').filter(|r| !r.is_empty()) else {
            return Err(format!("`rel_rule = \"{s}\"` names no role"));
        };
        if !roles.contains(&role) {
            return Err(format!(
                "`rel_rule = \"{s}\"`: `{role}` is not a role of registries/account_roles.toml"
            ));
        }
        let role = role.to_string();
        match name {
            "min_vid_debit_leg" => Ok(Self::MinVidDebitLeg { role }),
            "max_vid_debit_leg" => Ok(Self::MaxVidDebitLeg { role }),
            other => Err(format!(
                "`rel_rule = \"{s}\"`: `{other}` is outside the closed list ({})",
                RULES.join(", ")
            )),
        }
    }

    /// The covariate the rule depends on, as a `Rel(…)` status names it.
    #[must_use]
    pub const fn covariate(&self) -> &'static str {
        "account_vid_order"
    }

    #[must_use]
    pub fn role(&self) -> &str {
        match self {
            Self::MinVidDebitLeg { role } | Self::MaxVidDebitLeg { role } => role,
        }
    }
}

impl std::fmt::Display for RelRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MinVidDebitLeg { role } => write!(f, "min_vid_debit_leg{{{role}}}"),
            Self::MaxVidDebitLeg { role } => write!(f, "max_vid_debit_leg{{{role}}}"),
        }
    }
}

/// One leg of the entry, as the rule reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelLeg {
    /// 0-based, in the entry's order.
    pub ordinal: i128,
    pub account: String,
    /// The account's role in the book's chart, if it holds one.
    pub role: Option<String>,
    pub debit: bool,
    pub unit: String,
    /// In minor units, unsigned.
    pub magnitude: i128,
}

/// The leg value a relational component expects on one run.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Expected {
    pub account: String,
    pub unit: String,
    pub magnitude: i128,
    /// Every leg of the entry carrying that (account, unit, magnitude).
    pub ordinals: Vec<i128>,
}

/// The debit legs on accounts holding the rule's role, keyed as the
/// procedure sorts them, with the account's VId supplied by `vid`.
fn candidates<'a>(
    rule: &RelRule,
    legs: &'a [RelLeg],
    vid: &dyn Fn(&str) -> Option<u128>,
) -> Option<Vec<((u128, &'a str, i128), &'a RelLeg)>> {
    let mut out = Vec::new();
    for leg in legs
        .iter()
        .filter(|l| l.debit && l.role.as_deref() == Some(rule.role()))
    {
        out.push(((vid(&leg.account)?, leg.unit.as_str(), leg.magnitude), leg));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Some(out)
}

fn expected(legs: &[RelLeg], pick: &RelLeg) -> Expected {
    Expected {
        account: pick.account.clone(),
        unit: pick.unit.clone(),
        magnitude: pick.magnitude,
        ordinals: legs
            .iter()
            .filter(|l| {
                l.debit
                    && l.account == pick.account
                    && l.unit == pick.unit
                    && l.magnitude == pick.magnitude
            })
            .map(|l| l.ordinal)
            .collect(),
    }
}

/// The value `rule` selects on a run whose account VIds are `vids`; `None`
/// when no leg qualifies or a qualifying leg's account has no VId.
#[must_use]
pub fn expect_rel(
    rule: &RelRule,
    legs: &[RelLeg],
    vids: &BTreeMap<String, u128>,
) -> Option<Expected> {
    let ordered = candidates(rule, legs, &|code| vids.get(code).copied())?;
    let pick = match rule {
        RelRule::MinVidDebitLeg { .. } => ordered.first(),
        RelRule::MaxVidDebitLeg { .. } => ordered.last(),
    }?;
    Some(expected(legs, pick.1))
}

/// Every value `rule` can select over all VId orders of the qualifying
/// accounts: how a `Rel` component renders ("the selection depends on a
/// random identifier").
#[must_use]
pub fn possible(rule: &RelRule, legs: &[RelLeg]) -> Vec<Expected> {
    let accounts: BTreeSet<&str> = legs
        .iter()
        .filter(|l| l.debit && l.role.as_deref() == Some(rule.role()))
        .map(|l| l.account.as_str())
        .collect();
    let mut out: BTreeSet<Expected> = BTreeSet::new();
    // An account is selected exactly when it sorts first (or last); within
    // one account the (unit, magnitude) order decides, whatever the VIds.
    for chosen in &accounts {
        let edge = match rule {
            RelRule::MinVidDebitLeg { .. } => 0,
            RelRule::MaxVidDebitLeg { .. } => u128::MAX,
        };
        let vid = |code: &str| {
            Some(if code == *chosen {
                edge
            } else if edge == 0 {
                1
            } else {
                0
            })
        };
        if let Some(e) = candidates(rule, legs, &vid).and_then(|ordered| {
            match rule {
                RelRule::MinVidDebitLeg { .. } => ordered.first(),
                RelRule::MaxVidDebitLeg { .. } => ordered.last(),
            }
            .map(|(_, leg)| expected(legs, leg))
        }) {
            out.insert(e);
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROLES: [&str; 3] = ["fixed_asset", "accrued_expense", "cash"];

    fn leg(ordinal: i128, account: &str, role: Option<&str>, debit: bool, minor: i128) -> RelLeg {
        RelLeg {
            ordinal,
            account: account.into(),
            role: role.map(Into::into),
            debit,
            unit: "USD".into(),
            magnitude: minor,
        }
    }

    /// F9's two-debit cell: two fixed-asset accounts debited with different
    /// amounts against one line-cost credit.
    fn f9_two_debits() -> Vec<RelLeg> {
        vec![
            leg(0, "1500", Some("fixed_asset"), true, 20_000_000_000),
            leg(1, "1510", Some("fixed_asset"), true, 10_000_000_000),
            leg(2, "6100", None, false, 30_000_000_000),
        ]
    }

    #[test]
    fn rel_rule_parse_names_the_closed_list_and_the_registry_roles() {
        let err = RelRule::parse("median_vid_debit_leg{fixed_asset}", &ROLES).unwrap_err();
        assert!(
            err.contains("`median_vid_debit_leg` is outside the closed list"),
            "{err}"
        );
        let err = RelRule::parse("min_vid_debit_leg{fixed_assets}", &ROLES).unwrap_err();
        assert!(err.contains("`fixed_assets` is not a role"), "{err}");
        assert!(RelRule::parse("min_vid_debit_leg", &ROLES).is_err());
        assert!(RelRule::parse("min_vid_debit_leg{}", &ROLES).is_err());
        let ok = RelRule::parse("min_vid_debit_leg{fixed_asset}", &ROLES).unwrap();
        assert_eq!(ok.to_string(), "min_vid_debit_leg{fixed_asset}");
        assert_eq!(ok.covariate(), "account_vid_order");
    }

    #[test]
    fn max_vid_debit_leg_selects_the_maximum_vid_debit_leg() {
        let legs = f9_two_debits();
        let min = RelRule::parse("min_vid_debit_leg{fixed_asset}", &ROLES).unwrap();
        let max = RelRule::parse("max_vid_debit_leg{fixed_asset}", &ROLES).unwrap();
        let vids: BTreeMap<String, u128> =
            [("1500".into(), 7), ("1510".into(), 9), ("6100".into(), 1)].into();
        let lo = expect_rel(&min, &legs, &vids).unwrap();
        let hi = expect_rel(&max, &legs, &vids).unwrap();
        assert_eq!(
            (lo.account.as_str(), lo.magnitude, lo.ordinals.clone()),
            ("1500", 20_000_000_000, vec![0])
        );
        assert_eq!(
            (hi.account.as_str(), hi.magnitude, hi.ordinals.clone()),
            ("1510", 10_000_000_000, vec![1])
        );
        // Swapping the VIds swaps the selections.
        let swapped: BTreeMap<String, u128> =
            [("1500".into(), 9), ("1510".into(), 7), ("6100".into(), 1)].into();
        assert_eq!(expect_rel(&min, &legs, &swapped), Some(hi));
        assert_eq!(expect_rel(&max, &legs, &swapped), Some(lo));
        // The rendering lists both documented amounts, by account.
        let all = possible(&min, &legs);
        let both: Vec<(&str, i128)> = all
            .iter()
            .map(|e| (e.account.as_str(), e.magnitude))
            .collect();
        assert_eq!(
            both,
            vec![("1500", 20_000_000_000), ("1510", 10_000_000_000)]
        );
    }

    #[test]
    fn rel_leg_without_a_vid_or_without_a_qualifying_leg_selects_nothing() {
        let legs = f9_two_debits();
        let min = RelRule::parse("min_vid_debit_leg{fixed_asset}", &ROLES).unwrap();
        let partial: BTreeMap<String, u128> = [("1500".into(), 7)].into();
        assert_eq!(expect_rel(&min, &legs, &partial), None);
        let cash = RelRule::parse("min_vid_debit_leg{cash}", &ROLES).unwrap();
        assert_eq!(expect_rel(&cash, &legs, &BTreeMap::new()), None);
        assert!(possible(&cash, &legs).is_empty());
        // Within one account the (unit, magnitude) order decides: two debits
        // on 1500 select the smaller, and both ordinals of an equal pair.
        let one_account = vec![
            leg(0, "1500", Some("fixed_asset"), true, 5),
            leg(1, "1500", Some("fixed_asset"), true, 3),
            leg(2, "1500", Some("fixed_asset"), true, 3),
        ];
        let vids: BTreeMap<String, u128> = [("1500".into(), 1)].into();
        let e = expect_rel(&min, &one_account, &vids).unwrap();
        assert_eq!((e.magnitude, e.ordinals), (3, vec![1, 2]));
    }
}
