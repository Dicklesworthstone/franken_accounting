//! Explicit dated valuation adjustments (plan §11.6, bead fa-8j3g): entry
//! extension 34, `fa:valuation-adjustment:v1`.
//!
//! An entry may carry typed valuation inputs: for an account, or for an
//! instrument and the account that carries it, a signed amount in a named
//! unit under a named basis law (a signed delta to the posted basis, or an
//! explicit signed basis), applicable under a named date law (exactly as of
//! one day, or within a window). `solvency.balance_sheet_test` applies the
//! inputs visible at its known-at under their own laws, and cites them; a
//! historical balance assertion is never read as a valuation. The terms are
//! part of the proposal, so its digest, the approvals over it and the
//! journal cover them.
//!
//! Bytes: `u16 version ‖ list(str id ‖ u8 subject (‖ u128 account | ‖ u128
//! instrument ‖ u128 carrying account) ‖ opt(u128 entity) ‖ u32 unit ‖ u8
//! basis law ‖ u8 applicability (‖ i32 day | ‖ i32 from ‖ i32 through) ‖
//! i128 signed amount ‖ opt(str supersedes))`, ids strictly ascending.

use fa_money::UnitId;
use fa_time::DateDay;
use fgdb_types::VId;

use crate::canon::{DecodeError, EncodeError, Reader, Writer};

/// The only version of the extension's bytes.
pub const VALUATION_TERMS_VERSION: u16 = 1;

/// The most valuation inputs one entry may carry, and the longest id.
pub const MAX_VALUATION_TERMS: usize = 256;
pub const MAX_VALUATION_ID_BYTES: usize = 128;

/// Target of an explicit valuation adjustment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValuationSubject {
    /// Valuation targets a leaf Asset or Liability account directly.
    Account(VId),
    /// Valuation targets a registered REA instrument (`snapshot.rea.instruments`)
    /// carried in `carrying_account`. Double-application to both an instrument
    /// and its carrying account in the same scope is refused.
    Instrument {
        instrument: VId,
        carrying_account: VId,
    },
}

impl ValuationSubject {
    /// The subject's byte in the extension.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Account(_) => 1,
            Self::Instrument { .. } => 2,
        }
    }

    #[must_use]
    pub const fn carrying_account(self) -> VId {
        match self {
            Self::Account(acct) => acct,
            Self::Instrument {
                carrying_account, ..
            } => carrying_account,
        }
    }
}

/// Law governing how `signed_amount` adjusts the subject's signed basis.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValuationBasisLaw {
    /// Signed delta added to the subject's posted signed basis (`debit - credit`
    /// for Assets, `credit - debit` for Liabilities).
    SignedDelta,
    /// Explicit signed basis replacement (`signed_amount` may be positive, zero,
    /// or negative under explicit valuation law, never silently clamped).
    AbsoluteSignedBasis,
}

impl ValuationBasisLaw {
    /// The basis law's byte in the extension.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::SignedDelta => 1,
            Self::AbsoluteSignedBasis => 2,
        }
    }

    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::SignedDelta => "signed_delta",
            Self::AbsoluteSignedBasis => "absolute_signed_basis",
        }
    }
}

/// Applicability law governing when a declared valuation input applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ValuationApplicabilityLaw {
    /// Applicable only when `as_of == effective_date`.
    ExactAsOf { effective_date: DateDay },
    /// Applicable when `effective_from <= as_of && as_of <= effective_through`.
    EffectiveWindow {
        effective_from: DateDay,
        effective_through: DateDay,
    },
}

impl ValuationApplicabilityLaw {
    /// The applicability law's byte in the extension.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::ExactAsOf { .. } => 1,
            Self::EffectiveWindow { .. } => 2,
        }
    }

    #[must_use]
    pub fn describe(self) -> String {
        match self {
            Self::ExactAsOf { effective_date } => format!("exact_as_of({effective_date})"),
            Self::EffectiveWindow {
                effective_from,
                effective_through,
            } => format!("window({effective_from}..={effective_through})"),
        }
    }
}

/// One valuation input an entry carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineValuationTerms {
    pub valuation_id: String,
    pub subject: ValuationSubject,
    pub entity: Option<VId>,
    pub unit: UnitId,
    pub basis_law: ValuationBasisLaw,
    pub applicability: ValuationApplicabilityLaw,
    pub signed_amount: i128,
    pub supersedes: Option<String>,
}

impl InlineValuationTerms {
    pub fn encode_list(terms: &[Self]) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u16(VALUATION_TERMS_VERSION).list(terms, |w, item| {
            w.str(&item.valuation_id).u8(item.subject.tag());
            match item.subject {
                ValuationSubject::Account(acct) => {
                    w.u128(acct.0);
                }
                ValuationSubject::Instrument {
                    instrument,
                    carrying_account,
                } => {
                    w.u128(instrument.0).u128(carrying_account.0);
                }
            }
            w.opt(item.entity.as_ref(), |w, e| {
                w.u128(e.0);
            })
            .u32(item.unit.0)
            .u8(item.basis_law.tag())
            .u8(item.applicability.tag());
            match item.applicability {
                ValuationApplicabilityLaw::ExactAsOf { effective_date } => {
                    w.i32(effective_date.0);
                }
                ValuationApplicabilityLaw::EffectiveWindow {
                    effective_from,
                    effective_through,
                } => {
                    w.i32(effective_from.0).i32(effective_through.0);
                }
            }
            w.i128(item.signed_amount)
                .opt(item.supersedes.as_ref(), |w, s| {
                    w.str(s);
                });
        });
        w.finish()
    }

    pub fn decode_list(bytes: &[u8]) -> Result<Vec<Self>, DecodeError> {
        let mut r = Reader::new(bytes);
        let version = r.u16("inline_valuation_terms.version")?;
        if version != VALUATION_TERMS_VERSION {
            return Err(r.invalid("inline_valuation_terms.version"));
        }
        let list = r.list(MAX_VALUATION_TERMS, "inline_valuation_terms.items", |r| {
            let valuation_id = r
                .str(MAX_VALUATION_ID_BYTES, "inline_valuation_terms.id")?
                .to_string();
            let subject = match r.u8("inline_valuation_terms.subject")? {
                1 => ValuationSubject::Account(VId(r.u128("subject.account")?)),
                2 => ValuationSubject::Instrument {
                    instrument: VId(r.u128("subject.instrument")?),
                    carrying_account: VId(r.u128("subject.carrying_account")?),
                },
                tag => return Err(r.bad_tag("inline_valuation_terms.subject", tag)),
            };
            let entity = r.opt("inline_valuation_terms.entity", |r| {
                Ok(VId(r.u128("entity")?))
            })?;
            let unit = UnitId(r.u32("inline_valuation_terms.unit")?);
            let basis_law = match r.u8("inline_valuation_terms.basis_law")? {
                1 => ValuationBasisLaw::SignedDelta,
                2 => ValuationBasisLaw::AbsoluteSignedBasis,
                tag => return Err(r.bad_tag("inline_valuation_terms.basis_law", tag)),
            };
            let applicability = match r.u8("inline_valuation_terms.applicability")? {
                1 => ValuationApplicabilityLaw::ExactAsOf {
                    effective_date: DateDay(r.i32("applicability.effective_date")?),
                },
                2 => ValuationApplicabilityLaw::EffectiveWindow {
                    effective_from: DateDay(r.i32("applicability.effective_from")?),
                    effective_through: DateDay(r.i32("applicability.effective_through")?),
                },
                tag => return Err(r.bad_tag("inline_valuation_terms.applicability", tag)),
            };
            let signed_amount = r.i128("inline_valuation_terms.signed_amount")?;
            let supersedes = r.opt("inline_valuation_terms.supersedes", |r| {
                Ok(r.str(MAX_VALUATION_ID_BYTES, "supersedes")?.to_string())
            })?;
            Ok(Self {
                valuation_id,
                subject,
                entity,
                unit,
                basis_law,
                applicability,
                signed_amount,
                supersedes,
            })
        })?;
        r.finish()?;
        Ok(list)
    }

    pub fn to_extension(terms: &[Self]) -> Result<(u16, Vec<u8>), EncodeError> {
        Ok((
            crate::entry::VALUATION_ADJUSTMENT_EXTENSION,
            Self::encode_list(terms)?,
        ))
    }
}

/// Check extension 34's bytes: they decode to at least one input and are
/// canonical; ids are nonempty and strictly ascending (so unique); an input
/// never supersedes itself; a window never ends before it starts.
pub fn validate_terms(bytes: &[u8]) -> Result<(), (&'static str, &'static str)> {
    const FIELD: &str = "extensions.valuation_adjustment";
    let terms = InlineValuationTerms::decode_list(bytes).map_err(|_| (FIELD, "does not decode"))?;
    if InlineValuationTerms::encode_list(&terms).ok().as_deref() != Some(bytes) {
        return Err((FIELD, "is not in canonical form"));
    }
    if terms.is_empty() {
        return Err((FIELD, "declares no inputs; omit the extension instead"));
    }
    if terms.iter().any(|term| term.valuation_id.is_empty()) {
        return Err((FIELD, "an input has an empty valuation_id"));
    }
    if terms
        .windows(2)
        .any(|w| w[0].valuation_id >= w[1].valuation_id)
    {
        return Err((FIELD, "valuation_ids must be unique and strictly ascending"));
    }
    if terms.iter().any(|term| {
        term.supersedes
            .as_ref()
            .is_some_and(|prior| prior.is_empty() || *prior == term.valuation_id)
    }) {
        return Err((
            FIELD,
            "an input supersedes itself or names an empty valuation_id",
        ));
    }
    if terms.iter().any(|term| {
        matches!(
            term.applicability,
            ValuationApplicabilityLaw::EffectiveWindow {
                effective_from,
                effective_through,
            } if effective_through < effective_from
        )
    }) {
        return Err((FIELD, "an applicability window ends before it starts"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(id: &str) -> InlineValuationTerms {
        InlineValuationTerms {
            valuation_id: id.into(),
            subject: ValuationSubject::Account(VId(7)),
            entity: None,
            unit: UnitId(1),
            basis_law: ValuationBasisLaw::SignedDelta,
            applicability: ValuationApplicabilityLaw::ExactAsOf {
                effective_date: DateDay::from_ymd(2026, 4, 30).unwrap(),
            },
            signed_amount: 2_200,
            supersedes: None,
        }
    }

    #[test]
    fn valuation_terms_round_trip_and_refuse_ambiguous_inputs() {
        let mut window = input("VAL-B");
        window.subject = ValuationSubject::Instrument {
            instrument: VId(9),
            carrying_account: VId(7),
        };
        window.entity = Some(VId(3));
        window.basis_law = ValuationBasisLaw::AbsoluteSignedBasis;
        window.applicability = ValuationApplicabilityLaw::EffectiveWindow {
            effective_from: DateDay::from_ymd(2026, 4, 1).unwrap(),
            effective_through: DateDay::from_ymd(2026, 6, 30).unwrap(),
        };
        window.signed_amount = -500;
        window.supersedes = Some("VAL-A".into());
        let terms = vec![input("VAL-A"), window];
        let (tag, bytes) = InlineValuationTerms::to_extension(&terms).unwrap();
        assert_eq!(tag, crate::entry::VALUATION_ADJUSTMENT_EXTENSION);
        assert_eq!(InlineValuationTerms::decode_list(&bytes).unwrap(), terms);
        assert_eq!(validate_terms(&bytes), Ok(()));

        let refused = |terms: &[InlineValuationTerms]| {
            validate_terms(&InlineValuationTerms::encode_list(terms).unwrap())
                .unwrap_err()
                .1
        };
        // Planted: no input, an empty id, a repeated or descending id, a
        // self-supersession and an inverted window are each refused.
        assert!(refused(&[]).contains("no inputs"));
        assert!(refused(&[input("")]).contains("empty valuation_id"));
        assert!(refused(&[input("VAL-A"), input("VAL-A")]).contains("strictly ascending"));
        assert!(refused(&[input("VAL-B"), input("VAL-A")]).contains("strictly ascending"));
        let mut circular = input("VAL-A");
        circular.supersedes = Some("VAL-A".into());
        assert!(refused(&[circular]).contains("supersedes itself"));
        let mut inverted = input("VAL-A");
        inverted.applicability = ValuationApplicabilityLaw::EffectiveWindow {
            effective_from: DateDay::from_ymd(2026, 6, 30).unwrap(),
            effective_through: DateDay::from_ymd(2026, 4, 1).unwrap(),
        };
        assert!(refused(&[inverted]).contains("ends before it starts"));
        // Bytes that do not decode, and trailing bytes, are refused too.
        assert_eq!(validate_terms(&[0xff]).unwrap_err().1, "does not decode");
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(validate_terms(&trailing).is_err());
    }
}
