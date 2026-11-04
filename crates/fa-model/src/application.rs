//! Typed base-unit payment and receipt differences (plan §5.7, Appendix B).
//!
//! Extension 41 binds the cash leg, applying leg and every reason-typed
//! difference leg. Account, amount, dimensions and memo remain in the indexed
//! leg, so there is no second mutable description of an accounting effect.
//! Native admission checks the direction, exact equation, complete application
//! amount and the book's base unit. A reversal retains these bytes and negates
//! its witnessed target; the direction continues to describe the original.
//!
//! Version 1 bytes: `u16 version | u8 direction | u16 cash_ordinal |
//! u16 applying_ordinal | list(u16 leg_ordinal | u8 difference_kind)`.
//! ShortPay is not a reduction here: a partial application leaves the residual
//! open. Reclassifying a disputed balance and source-bound RealizedFx require
//! their own laws, never an alias for a discount or write-off.

use crate::{DecodeError, EntryError, Reader, Writer};

pub const APPLICATION_TERMS_VERSION: u16 = 1;
pub const MAX_APPLICATION_DIFFERENCES: usize = 128;
pub const MAX_APPLICATION_TERMS_BYTES: usize = 11 + 3 * MAX_APPLICATION_DIFFERENCES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationDirection {
    Receipt,
    Payment,
}

impl ApplicationDirection {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Receipt => 1,
            Self::Payment => 2,
        }
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Receipt),
            2 => Some(Self::Payment),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Receipt => "Receipt",
            Self::Payment => "Payment",
        }
    }
}

/// Tags retain the application_difference_kind assignments in fx_laws.toml.
/// Tags 2 (ShortPay) and 5 (RealizedFx) are outside this posting profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplicationDifferenceKind {
    Discount,
    Writeoff,
    BankCharge,
}

impl ApplicationDifferenceKind {
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Discount => 1,
            Self::Writeoff => 3,
            Self::BankCharge => 4,
        }
    }

    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Discount),
            3 => Some(Self::Writeoff),
            4 => Some(Self::BankCharge),
            _ => None,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Discount => "Discount",
            Self::Writeoff => "Writeoff",
            Self::BankCharge => "BankCharge",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApplicationDifference {
    pub leg_ordinal: u16,
    pub kind: ApplicationDifferenceKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationTerms {
    pub direction: ApplicationDirection,
    pub cash_ordinal: u16,
    pub applying_ordinal: u16,
    /// Strictly ascending ordinals. Together with cash and applying, these
    /// identify every leg exactly once: no undeclared balancing leg remains.
    pub differences: Vec<ApplicationDifference>,
}

fn invalid(why: &'static str) -> EntryError {
    EntryError::Invalid {
        what: "extensions.application_terms",
        why,
    }
}

impl ApplicationTerms {
    /// Structural binding only; accounting admission supplies the base unit
    /// and checks the actual monetary effects and applications.
    pub fn validate_shape(&self, leg_count: usize) -> Result<(), EntryError> {
        if self.differences.is_empty() || self.differences.len() > MAX_APPLICATION_DIFFERENCES {
            return Err(invalid("requires 1..=128 explicit difference legs"));
        }
        if self.differences.len().checked_add(2) != Some(leg_count)
            || self.cash_ordinal == self.applying_ordinal
            || usize::from(self.cash_ordinal) >= leg_count
            || usize::from(self.applying_ordinal) >= leg_count
        {
            return Err(invalid(
                "cash, applying and difference ordinals must cover every leg exactly once",
            ));
        }
        let mut previous = None;
        for difference in &self.differences {
            let ordinal = difference.leg_ordinal;
            if usize::from(ordinal) >= leg_count
                || ordinal == self.cash_ordinal
                || ordinal == self.applying_ordinal
                || previous.is_some_and(|prior| prior >= ordinal)
            {
                return Err(invalid(
                    "difference ordinals must be strictly ascending, in range and distinct from cash and applying",
                ));
            }
            previous = Some(ordinal);
        }
        Ok(())
    }

    /// Refuse oversized or noncanonical bindings before allocating the body.
    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        let leg_count = self
            .differences
            .len()
            .checked_add(2)
            .ok_or_else(|| invalid("difference count overflow"))?;
        self.validate_shape(leg_count)?;
        let mut writer = Writer::new();
        writer
            .u16(APPLICATION_TERMS_VERSION)
            .u8(self.direction.tag())
            .u16(self.cash_ordinal)
            .u16(self.applying_ordinal)
            .list(&self.differences, |writer, difference| {
                writer.u16(difference.leg_ordinal).u8(difference.kind.tag());
            });
        Ok(writer.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() > MAX_APPLICATION_TERMS_BYTES {
            return Err(DecodeError {
                offset: 0,
                what: "application_terms.bytes",
                reason: crate::canon::Reason::TooLong {
                    max: MAX_APPLICATION_TERMS_BYTES,
                    actual: bytes.len(),
                },
            });
        }
        let mut reader = Reader::new(bytes);
        if reader.u16("application_terms.version")? != APPLICATION_TERMS_VERSION {
            return Err(reader.invalid("application_terms.version"));
        }
        let tag = reader.u8("application_terms.direction")?;
        let direction = ApplicationDirection::from_tag(tag)
            .ok_or_else(|| reader.bad_tag("application_terms.direction", tag))?;
        let cash_ordinal = reader.u16("application_terms.cash_ordinal")?;
        let applying_ordinal = reader.u16("application_terms.applying_ordinal")?;
        let differences = reader.list(
            MAX_APPLICATION_DIFFERENCES,
            "application_terms.differences",
            |reader| {
                let leg_ordinal = reader.u16("application_terms.difference.ordinal")?;
                let tag = reader.u8("application_terms.difference.kind")?;
                let kind = ApplicationDifferenceKind::from_tag(tag)
                    .ok_or_else(|| reader.bad_tag("application_terms.difference.kind", tag))?;
                Ok(ApplicationDifference { leg_ordinal, kind })
            },
        )?;
        let terms = Self {
            direction,
            cash_ordinal,
            applying_ordinal,
            differences,
        };
        // The bounded list fixes the intended arity even before a containing
        // entry is available. Its actual leg count is checked by the model.
        terms
            .validate_shape(terms.differences.len() + 2)
            .map_err(|_| reader.invalid("application_terms.ordinals"))?;
        reader.finish()?;
        Ok(terms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> ApplicationTerms {
        ApplicationTerms {
            direction: ApplicationDirection::Receipt,
            cash_ordinal: 0,
            applying_ordinal: 1,
            differences: vec![
                ApplicationDifference {
                    leg_ordinal: 2,
                    kind: ApplicationDifferenceKind::Discount,
                },
                ApplicationDifference {
                    leg_ordinal: 3,
                    kind: ApplicationDifferenceKind::BankCharge,
                },
            ],
        }
    }

    #[test]
    fn application_terms_have_exact_versioned_bytes_and_preserve_sparse_kind_tags() {
        let value = terms();
        let expected = vec![1, 0, 1, 0, 0, 1, 0, 2, 0, 0, 0, 2, 0, 1, 3, 0, 4];
        assert_eq!(value.encode().unwrap(), expected);
        assert_eq!(ApplicationTerms::decode(&expected).unwrap(), value);
        for direction in [ApplicationDirection::Receipt, ApplicationDirection::Payment] {
            for kind in [
                ApplicationDifferenceKind::Discount,
                ApplicationDifferenceKind::Writeoff,
                ApplicationDifferenceKind::BankCharge,
            ] {
                let mut value = terms();
                value.direction = direction;
                value.differences[0].kind = kind;
                assert_eq!(
                    ApplicationTerms::decode(&value.encode().unwrap()).unwrap(),
                    value
                );
            }
        }
    }

    #[test]
    fn application_terms_refuse_untyped_reductions_bad_frames_and_incomplete_leg_maps() {
        let bytes = terms().encode().unwrap();
        for end in 0..bytes.len() {
            assert!(ApplicationTerms::decode(&bytes[..end]).is_err());
        }
        for (offset, byte) in [(0, 2), (2, 0), (2, 3), (13, 0), (13, 2), (13, 5)] {
            let mut invalid = bytes.clone();
            invalid[offset] = byte;
            assert!(ApplicationTerms::decode(&invalid).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ApplicationTerms::decode(&trailing).is_err());
        let mut oversized = bytes;
        oversized[7..11].copy_from_slice(&129u32.to_le_bytes());
        assert!(ApplicationTerms::decode(&oversized).is_err());
        for ordinals in [
            [0, 1, 2, 2],
            [0, 1, 3, 2],
            [0, 1, 1, 3],
            [0, 0, 2, 3],
            [0, 1, 2, 4],
        ] {
            let mut value = terms();
            value.cash_ordinal = ordinals[0];
            value.applying_ordinal = ordinals[1];
            value.differences[0].leg_ordinal = ordinals[2];
            value.differences[1].leg_ordinal = ordinals[3];
            assert!(value.encode().is_err(), "{ordinals:?}");
        }
        assert!(terms().validate_shape(3).is_err());
        assert!(terms().validate_shape(5).is_err());
        let mut empty = terms();
        empty.differences.clear();
        assert!(empty.encode().is_err());
    }

    #[test]
    fn application_terms_accept_the_exact_bounded_maximum_and_no_more() {
        let mut value = terms();
        value.differences = (2..130)
            .map(|leg_ordinal| ApplicationDifference {
                leg_ordinal,
                kind: ApplicationDifferenceKind::Discount,
            })
            .collect();
        let bytes = value.encode().unwrap();
        assert_eq!(bytes.len(), MAX_APPLICATION_TERMS_BYTES);
        assert_eq!(ApplicationTerms::decode(&bytes).unwrap(), value);
        value.differences.push(ApplicationDifference {
            leg_ordinal: 130,
            kind: ApplicationDifferenceKind::Discount,
        });
        assert!(value.encode().is_err());
        let oversized = vec![0; MAX_APPLICATION_TERMS_BYTES + 1];
        assert!(ApplicationTerms::decode(&oversized).is_err());
    }
}
