//! Scalar mirrors (plan §4.2 storage form, FA-INV-16).
//!
//! The substrate stores scalar properties only, so an `Entry` vertex carries
//! `_fa_payload` plus scalar mirrors for predicates and indexes, and each
//! derived `Leg` vertex mirrors its side, account, unit, effective day, and
//! amount. Mirrors are derived from the payload, never authoritative: the
//! kernel compares the decoded payload to every mirror after each commit and
//! recovery rebuilds them from payloads.

use core::fmt;

use fa_money::{Side, UnitRegistry};
use fa_time::DateDay;
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::{CanonicalDecimal, CanonicalScalar};

use crate::entry::{Entry, EntryOrigin, LegPayload};
use crate::symbols::property;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorError {
    Entry(crate::entry::EntryError),
    /// A leg names a unit the registry does not know.
    UnknownUnit(u32),
    /// A mirror value could not be built as a substrate scalar.
    Scalar(&'static str),
    /// A control record whose `control_kind` mints another class
    /// (registries/entry_classes.toml `[[control_kind]]`; fa-g23).
    ControlKind {
        class: u16,
        kind: u16,
    },
}

impl fmt::Display for MirrorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Entry(e) => write!(f, "{e}"),
            Self::UnknownUnit(u) => write!(f, "unit {u} is not registered"),
            Self::Scalar(what) => write!(f, "cannot build the `{what}` mirror as a scalar"),
            Self::ControlKind { class, kind } => write!(
                f,
                "control_kind {kind} mints {}, not class {class}: a control record carries its class's registered kind",
                crate::ControlKind::from_id(*kind)
                    .and_then(crate::ControlKind::class)
                    .and_then(crate::EntryClass::name)
                    .unwrap_or("no class")
            ),
        }
    }
}

impl core::error::Error for MirrorError {}

fn bytes(what: &'static str, b: Vec<u8>) -> Result<CanonicalScalar, MirrorError> {
    CanonicalScalar::bytes(b).map_err(|_| MirrorError::Scalar(what))
}

/// The scalar properties of an `Entry` vertex: `_fa_payload`, `_fa_digest`,
/// `proposal_digest`, `book_id`, `class`, `_fa_effective_day`,
/// `idempotency_key`. Sorted by key id, as the substrate requires.
pub fn entry_mirrors(entry: &Entry) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, MirrorError> {
    let payload = entry.encode().map_err(MirrorError::Entry)?;
    let p = &entry.proposal;
    // The staging cross-check (fa-g23): a control record carries the kind
    // registered for its class, and only a control class carries one.
    if let EntryOrigin::Control { control_kind, .. } = &p.origin
        && control_kind.class() != Some(p.class)
    {
        return Err(MirrorError::ControlKind {
            class: p.class.0,
            kind: control_kind.id(),
        });
    }
    let mut props = vec![
        (property::FA_PAYLOAD, bytes("_fa_payload", payload)?),
        (
            property::FA_DIGEST,
            bytes("_fa_digest", entry.entry_digest.to_vec())?,
        ),
        (property::BOOK_ID, bytes("book_id", p.book_id.0.to_vec())?),
        (property::CLASS, CanonicalScalar::Int(i64::from(p.class.0))),
        (
            property::IDEMPOTENCY_KEY,
            bytes("idempotency_key", p.idempotency_key.clone())?,
        ),
        (
            property::PROPOSAL_DIGEST,
            bytes("proposal_digest", entry.proposal_digest.to_vec())?,
        ),
    ];
    // PeriodCreation is a new Book-scoped control, with no posting date.
    // The v1 container's reserved zero scalar is not a temporal mirror.
    if !matches!(
        p.origin,
        EntryOrigin::Control {
            control_kind: crate::ControlKind::PERIOD_CREATION,
            ..
        }
    ) {
        props.push((
            property::FA_EFFECTIVE_DAY,
            CanonicalScalar::Int(i64::from(p.effective_date.0)),
        ));
    }
    props.sort_by_key(|(k, _)| k.0);
    Ok(props)
}

/// The scalar properties of a derived `Leg` vertex. `amount` is a `Decimal`
/// when `|mantissa| · 10^(18 − scale)` fits the substrate's 34-digit
/// coefficient, else `Null` with the exact mantissa in `amount_bytes`.
pub fn leg_mirrors(
    leg: &LegPayload,
    ordinal: u16,
    effective_date: DateDay,
    units: &UnitRegistry,
) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, MirrorError> {
    let unit = units
        .get(leg.amount.unit)
        .ok_or(MirrorError::UnknownUnit(leg.amount.unit.0))?;
    let (amount, amount_bytes) = if unit.scale <= 18 {
        match CanonicalDecimal::from_scaled_half_even(leg.amount.mantissa, u32::from(unit.scale)) {
            Ok(d) => (CanonicalScalar::Decimal(d), None),
            Err(_) => (
                CanonicalScalar::Null,
                Some(leg.amount.mantissa.to_le_bytes().to_vec()),
            ),
        }
    } else {
        (
            CanonicalScalar::Null,
            Some(leg.amount.mantissa.to_le_bytes().to_vec()),
        )
    };
    let mut props = vec![
        (
            property::FA_EFFECTIVE_DAY,
            CanonicalScalar::Int(i64::from(effective_date.0)),
        ),
        (
            property::SIDE,
            CanonicalScalar::Int(match leg.side {
                Side::Debit => 0,
                Side::Credit => 1,
            }),
        ),
        (
            property::ACCOUNT_REF,
            bytes("account_ref", leg.account_ref.0.to_le_bytes().to_vec())?,
        ),
        (
            property::UNIT_ID,
            CanonicalScalar::Int(i64::from(leg.amount.unit.0)),
        ),
        (property::AMOUNT, amount),
        (property::ORDINAL, CanonicalScalar::Int(i64::from(ordinal))),
    ];
    if let Some(b) = amount_bytes {
        props.push((property::AMOUNT_BYTES, bytes("amount_bytes", b)?));
    }
    props.sort_by_key(|(k, _)| k.0);
    Ok(props)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_money::{Amount, UnitId};
    use fgdb_types::VId;

    #[test]
    fn leg_amount_mirrors_as_decimal_when_representable_else_bytes() {
        let units = fa_money::UnitRegistry::embedded().unwrap();
        let usd = units.lookup("USD").unwrap();
        let eth = units.lookup("ETH").unwrap();
        // 1,234.56 USD → coefficient 1234.56 × 10^18.
        let leg = LegPayload::simple(Side::Debit, VId(1), Amount::new(usd, 123_456));
        let m = leg_mirrors(&leg, 0, DateDay(10), &units).unwrap();
        let amount = m
            .iter()
            .find(|(k, _)| *k == property::AMOUNT)
            .map(|(_, v)| v.clone())
            .unwrap();
        assert_eq!(
            amount,
            CanonicalScalar::Decimal(CanonicalDecimal::from_scaled_half_even(123_456, 2).unwrap())
        );
        assert!(m.iter().all(|(k, _)| *k != property::AMOUNT_BYTES));
        assert!(
            m.windows(2).all(|w| w[0].0.0 < w[1].0.0),
            "sorted by key id"
        );
        // 10^34 wei at scale 18 exceeds the 34-digit coefficient: bytes form.
        let big = LegPayload::simple(
            Side::Credit,
            VId(2),
            Amount::new(eth, 10_000_000_000_000_000_000_000_000_000_000_000),
        );
        let m = leg_mirrors(&big, 1, DateDay(10), &units).unwrap();
        assert_eq!(
            m.iter()
                .find(|(k, _)| *k == property::AMOUNT)
                .map(|(_, v)| v.clone()),
            Some(CanonicalScalar::Null)
        );
        assert!(m.iter().any(|(k, _)| *k == property::AMOUNT_BYTES));
        // An unregistered unit is refused.
        let bad = LegPayload::simple(Side::Debit, VId(3), Amount::new(UnitId(9_999), 1));
        assert_eq!(
            leg_mirrors(&bad, 0, DateDay(0), &units).unwrap_err(),
            MirrorError::UnknownUnit(9_999)
        );
    }
}
