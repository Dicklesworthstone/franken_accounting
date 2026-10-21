//! Legal entities as the book's balancing dimension (plan §4.1 `LegalEntity`
//! / `Dimension`, §5.2, FA-INV-01 clause `per-entity`).
//!
//! A book declares its entities at genesis (`BookSpec.entities`). A leg names
//! its entity in its `dimension_set`, as the value of the book's legal-entity
//! dimension (`LEGAL_ENTITY_DIMENSION`, value `entity_value_vid(book, code)`)
//! — no separate entity field ("derive its entity from the leg's
//! authenticated dimensions", §5.2). With more than one declared entity the
//! dimension is mandatory on every leg; with one, a leg may omit it (it is
//! that entity); with none, no leg may name one. The balance law then holds
//! per `(unit, legal_entity)`: an entry balanced per unit but not per entity
//! is refused naming every unbalanced pair, and no leg is ever invented
//! across entities — cross-entity entries balance each entity through its
//! intercompany due-to/due-from accounts.

use std::collections::BTreeMap;

use fa_model::{LEGAL_ENTITY_DIMENSION, LegPayload};
use fa_money::{Amount, Side, UnitId, UnitRegistry};

use crate::genesis::BookSpec;
use crate::refusal::{KernelError, Refusal, Why, code, exit};

/// Why a leg's entity is not admissible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LegEntityError {
    /// A dimension other than the legal entity: the dimension registry
    /// slice (plan §4.3) has not landed.
    OtherDimension,
    Refused(Refusal),
}

/// The legal entity leg `leg` names, judged against `spec`: `Ok(None)` when
/// it names none (admissible only when the book declares at most one).
pub fn leg_entity(spec: &BookSpec, leg: &LegPayload) -> Option<String> {
    leg.dimension_set
        .iter()
        .find(|(d, _)| *d == LEGAL_ENTITY_DIMENSION)
        .and_then(|(_, v)| spec.entity_of(*v).map(|e| e.code.clone()))
}

/// The entity every leg belongs to (plan §5.2): a declared entity's code,
/// the book's single entity when a leg names none and exactly one is
/// declared, or `None` in a book that declares none. Refused: a dimension
/// other than the legal entity (not implemented), an entity value the book
/// has not declared (FA-REF-104), a leg without an entity in a book that
/// declares more than one (FA-REF-005).
pub(crate) fn leg_entities(
    spec: &BookSpec,
    legs: &[LegPayload],
) -> Result<Vec<Option<String>>, LegEntityError> {
    let codes: Vec<&str> = spec.entities.iter().map(|e| e.code.as_str()).collect();
    let mut out = Vec::with_capacity(legs.len());
    for (i, leg) in legs.iter().enumerate() {
        if leg
            .dimension_set
            .iter()
            .any(|(d, _)| *d != LEGAL_ENTITY_DIMENSION && *d != fa_model::PARTY_DIMENSION)
        {
            return Err(LegEntityError::OtherDimension);
        }
        let named = leg
            .dimension_set
            .iter()
            .find(|(d, _)| *d == LEGAL_ENTITY_DIMENSION)
            .map(|(_, v)| *v);
        let entity = match named {
            Some(value) => match spec.entity_of(value) {
                Some(e) => Some(e.code.clone()),
                None => {
                    return Err(LegEntityError::Refused(Refusal::new(
                        code::ENTITY_UNDECLARED,
                        exit::REFUSAL,
                        if codes.is_empty() {
                            format!(
                                "leg {i} names legal-entity value {:032x}, but this book declares no legal entities",
                                value.0
                            )
                        } else {
                            format!(
                                "leg {i} names legal-entity value {:032x}, which is none of this book's entities ({})",
                                value.0,
                                codes.join(", ")
                            )
                        },
                        "plan §4.1 (Book.entities: a leg posts for a declared legal entity)",
                        "name one of the book's declared entities (fa book info --json lists them); a new entity is declared at genesis",
                    )));
                }
            },
            None if codes.len() > 1 => {
                return Err(LegEntityError::Refused(Refusal::new(
                    code::DIMENSION_MISSING,
                    exit::REFUSAL,
                    format!(
                        "leg {i} names no legal entity; this book declares {} ({}), so every leg carries one",
                        codes.len(),
                        codes.join(", ")
                    ),
                    "plan §4.1, §5.2 (legal_entity is a mandatory balancing dimension in a multi-entity book; FA-INV-01 per-entity)",
                    format!(
                        "add the legal-entity dimension to leg {i}: one of {}",
                        codes.join(", ")
                    ),
                )));
            }
            None => codes.first().map(|c| (*c).to_string()),
        };
        out.push(entity);
    }
    Ok(out)
}

/// The per-`(unit, entity)` balance law (FA-INV-01 `per-entity`): `Ok(None)`
/// when every pair balances, else the refusal naming every unbalanced pair
/// at unit scale. Called after the per-unit law, so a refusal here is an
/// entry balanced per unit but not per entity.
pub(crate) fn per_entity_refusal(
    legs: &[LegPayload],
    entities: &[Option<String>],
    units: &UnitRegistry,
) -> Result<Option<Refusal>, KernelError> {
    let mut totals: BTreeMap<(u32, Option<&str>), (i128, i128)> = BTreeMap::new();
    for (leg, entity) in legs.iter().zip(entities) {
        let slot = totals
            .entry((leg.amount.unit.0, entity.as_deref()))
            .or_insert((0, 0));
        let side = match leg.side {
            Side::Debit => &mut slot.0,
            Side::Credit => &mut slot.1,
        };
        *side = side
            .checked_add(leg.amount.mantissa)
            .ok_or_else(|| KernelError::Corrupt("per-entity totals overflow".into()))?;
    }
    let show = |unit: u32, m: i128| {
        if units.get(UnitId(unit)).is_some() {
            Amount::new(UnitId(unit), m).render(units)
        } else {
            format!("{m} (mantissa of unregistered unit {unit})")
        }
    };
    let mut lines = Vec::new();
    let mut named = Vec::new();
    for ((unit, entity), (d, c)) in &totals {
        if d == c {
            continue;
        }
        let gap = d
            .checked_sub(*c)
            .map(i128::unsigned_abs)
            .and_then(|g| i128::try_from(g).ok())
            .ok_or_else(|| KernelError::Corrupt("per-entity gap overflow".into()))?;
        let who = entity.unwrap_or("(the book)");
        named.push(who.to_string());
        lines.push(format!(
            "entity `{who}`: debits {} ≠ credits {} (difference {})",
            show(*unit, *d),
            show(*unit, *c),
            show(*unit, gap)
        ));
    }
    if lines.is_empty() {
        return Ok(None);
    }
    named.dedup();
    Ok(Some(Refusal::new(
        code::UNBALANCED,
        exit::REFUSAL,
        format!(
            "the entry balances per unit but not per legal entity: {}",
            lines.join("; ")
        ),
        "FA-INV-01 per-entity balance law (plan §5.2)",
        format!(
            "balance each entity on its own through its intercompany due-to/due-from accounts between {}; the kernel never invents a leg across entities",
            named.join(" and ")
        ),
    )
    .at("entities", named.join(", "))
    .because(Why::Law("FA-INV-01.per-entity".to_string()))))
}
