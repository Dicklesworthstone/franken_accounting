//! Explicit net-cash differences for source-bound foreign settlements.
//!
//! Extension 42 opts a component into the complete version-2 paired effect
//! profile. Its ordinals bind the actual immutable legs; accounts, amounts
//! and dimensions are not duplicated in an unauthenticated description.

use crate::{
    ApplicationDifference, ApplicationDifferenceKind, DecodeError, EntryError, Reader, Writer,
};

pub const FX_SETTLEMENT_TERMS_VERSION: u16 = 2;
pub const MAX_FX_SETTLEMENT_COMPONENTS: usize = crate::limits::MAX_LEGS_PER_ENTRY / 4;
pub const MAX_FX_SETTLEMENT_TERMS_BYTES: usize =
    18 + 6 * MAX_FX_SETTLEMENT_COMPONENTS + 3 * crate::application::MAX_APPLICATION_DIFFERENCES;
const MAGIC: &[u8; 12] = b"FA-FX-TERMS\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxSettlementComponent {
    pub applying_ordinal: u16,
    /// Strictly ordered economic legs, each followed by its conversion pair.
    pub differences: Vec<ApplicationDifference>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxSettlementTerms {
    /// Only components with explicit differences appear. Unmarked components
    /// retain the original carrying-settlement profile and original bytes.
    pub components: Vec<FxSettlementComponent>,
}

fn invalid(why: &'static str) -> EntryError {
    EntryError::Invalid {
        what: "extensions.fx_settlement_terms",
        why,
    }
}

impl FxSettlementTerms {
    pub fn component(&self, applying_ordinal: usize) -> Option<&FxSettlementComponent> {
        self.components
            .binary_search_by_key(&applying_ordinal, |component| {
                usize::from(component.applying_ordinal)
            })
            .ok()
            .map(|index| &self.components[index])
    }

    /// Syntax and bounded ordinal coverage. Native accounting admission also
    /// binds every marker to a real fully applied source component and checks
    /// its complete ordered economic and conversion vector.
    pub fn validate_shape(&self, leg_count: usize) -> Result<(), EntryError> {
        if self.components.is_empty()
            || self.components.len() > MAX_FX_SETTLEMENT_COMPONENTS
            || leg_count > crate::limits::MAX_LEGS_PER_ENTRY
        {
            return Err(invalid(
                "requires a bounded nonempty list of affected components",
            ));
        }
        let mut previous = None;
        let mut total = 0usize;
        for (index, component) in self.components.iter().enumerate() {
            let start = usize::from(component.applying_ordinal);
            let end = self
                .components
                .get(index + 1)
                .map_or(leg_count, |next| usize::from(next.applying_ordinal));
            if previous.is_some_and(|prior| prior >= start)
                || start >= leg_count
                || component.differences.is_empty()
            {
                return Err(invalid(
                    "affected components must be nonempty and strictly ordered",
                ));
            }
            total = total
                .checked_add(component.differences.len())
                .ok_or_else(|| invalid("difference count overflow"))?;
            if total > crate::application::MAX_APPLICATION_DIFFERENCES {
                return Err(invalid("at most 128 explicit difference pairs per entry"));
            }
            let mut previous_difference = None;
            for difference in &component.differences {
                let ordinal = usize::from(difference.leg_ordinal);
                if ordinal < start + 4
                    || (ordinal - start) % 2 != 0
                    || ordinal + 1 >= end
                    || previous_difference.is_some_and(|prior| prior >= ordinal)
                {
                    return Err(invalid(
                        "difference pairs must be ordered, in range and after the four mandatory core legs",
                    ));
                }
                previous_difference = Some(ordinal);
            }
            previous = Some(start);
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, EntryError> {
        self.validate_shape(crate::limits::MAX_LEGS_PER_ENTRY)?;
        let mut writer = Writer::new();
        writer.fixed(MAGIC).u16(FX_SETTLEMENT_TERMS_VERSION).list(
            &self.components,
            |writer, component| {
                writer.u16(component.applying_ordinal).list(
                    &component.differences,
                    |writer, difference| {
                        writer.u16(difference.leg_ordinal).u8(difference.kind.tag());
                    },
                );
            },
        );
        Ok(writer.finish()?)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader::new(bytes);
        if bytes.len() > MAX_FX_SETTLEMENT_TERMS_BYTES {
            return Err(reader.invalid("fx_settlement_terms.bytes"));
        }
        if &reader.fixed::<12>("fx_settlement_terms.magic")? != MAGIC
            || reader.u16("fx_settlement_terms.version")? != FX_SETTLEMENT_TERMS_VERSION
        {
            return Err(reader.invalid("fx_settlement_terms.version"));
        }
        let mut remaining = crate::application::MAX_APPLICATION_DIFFERENCES;
        let components = reader.list(
            MAX_FX_SETTLEMENT_COMPONENTS,
            "fx_settlement_terms.components",
            |reader| {
                let applying_ordinal = reader.u16("fx_settlement_terms.applying_ordinal")?;
                let differences =
                    reader.list(remaining, "fx_settlement_terms.differences", |reader| {
                        let leg_ordinal = reader.u16("fx_settlement_terms.difference.ordinal")?;
                        let tag = reader.u8("fx_settlement_terms.difference.kind")?;
                        let kind = ApplicationDifferenceKind::from_tag(tag).ok_or_else(|| {
                            reader.bad_tag("fx_settlement_terms.difference.kind", tag)
                        })?;
                        Ok(ApplicationDifference { leg_ordinal, kind })
                    })?;
                remaining -= differences.len();
                Ok(FxSettlementComponent {
                    applying_ordinal,
                    differences,
                })
            },
        )?;
        let terms = Self { components };
        terms
            .validate_shape(crate::limits::MAX_LEGS_PER_ENTRY)
            .map_err(|_| reader.invalid("fx_settlement_terms.ordinals"))?;
        reader.finish()?;
        Ok(terms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> FxSettlementTerms {
        FxSettlementTerms {
            components: vec![FxSettlementComponent {
                applying_ordinal: 0,
                differences: vec![ApplicationDifference {
                    leg_ordinal: 6,
                    kind: ApplicationDifferenceKind::BankCharge,
                }],
            }],
        }
    }

    #[test]
    fn exact_versioned_fx_terms_and_bounded_malformed_frames() {
        let value = terms();
        let mut expected = b"FA-FX-TERMS\0".to_vec();
        expected.extend_from_slice(&[2, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 6, 0, 4]);
        assert_eq!(value.encode().unwrap(), expected);
        assert_eq!(FxSettlementTerms::decode(&expected).unwrap(), value);
        value.validate_shape(8).unwrap();
        assert!(value.validate_shape(7).is_err());
        for length in 0..expected.len() {
            assert!(FxSettlementTerms::decode(&expected[..length]).is_err());
        }
        let mut extra = expected.clone();
        extra.push(0);
        assert!(FxSettlementTerms::decode(&extra).is_err());
        for tag in [0, 2, 5, 255] {
            let mut wrong_kind = expected.clone();
            *wrong_kind.last_mut().unwrap() = tag;
            assert!(FxSettlementTerms::decode(&wrong_kind).is_err());
        }
        let mut huge = expected;
        huge[14..18].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(FxSettlementTerms::decode(&huge).is_err());
    }

    #[test]
    fn fx_terms_refuse_overlapping_unordered_or_unbounded_pairs() {
        let mut value = terms();
        value.components.push(value.components[0].clone());
        assert!(value.encode().is_err());
        value.components[1].applying_ordinal = 4;
        value.components[1].differences[0].leg_ordinal = 8;
        assert!(value.encode().is_err());
        value = terms();
        for ordinal in [0, 2, 5, 4095] {
            value.components[0].differences[0].leg_ordinal = ordinal;
            assert!(value.encode().is_err());
        }
        value = terms();
        value.components[0].differences.clear();
        assert!(value.encode().is_err());
        value.components.clear();
        assert!(value.encode().is_err());
    }
}
