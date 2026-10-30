//! Contractual maturity terms on posted open items (plan §11.6, beads
//! fa-5dpd / fa-0hs4.13): entry extension 33.
//!
//! Version 1 declares when credit-side obligations fall due. Version 2
//! also admits debit-side receivable terms; the referenced leg fixes the
//! side, amount and unit. Both carry a contractual installment schedule,
//! a dispute, or explicitly unknown maturity. Due-date aging reads either
//! side; `solvency.cash_flow_test` selects credit obligations and never
//! treats a receivable schedule as a debt or an expected cash receipt.
//! The terms are part of the proposal, so its digest, the approvals over
//! it and the journal cover them. Version 1 bytes retain their original
//! credit-only meaning.
//!
//! Bytes: `u16 version ‖ list(u16 leg ordinal ‖ u8 status [‖ u16 reason
//! code when Disputed] ‖ list(i32 due day ‖ i128 amount))`.

use fa_time::DateDay;

use crate::canon::{DecodeError, EncodeError, Reader, Writer};
use crate::entry::LegPayload;
use fa_money::Side;

/// The original, credit-only version. Existing payable encoders keep these
/// bytes so unchanged proposals retain their identities and approvals.
pub const OBLIGATION_TERMS_VERSION: u16 = 1;
/// The version admitting maturity on either debit or credit open items.
pub const RECEIVABLE_TERMS_VERSION: u16 = 2;

/// The most terms (one per leg) and installments (per term) one entry may
/// declare.
pub const MAX_OBLIGATION_TERMS: usize = 256;
pub const MAX_OBLIGATION_INSTALLMENTS: usize = 256;

/// One contractual installment: `amount > 0`, in the leg's unit and
/// scale, due on `due_date`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObligationInstallment {
    pub due_date: DateDay,
    pub amount: i128,
}

/// How an obligation's maturity is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObligationStatus {
    /// Its contractual maturity schedule is known and complete.
    Contractual,
    /// The claim or obligation is disputed, with a reason code.
    Disputed { reason_code: u16 },
    /// Its maturity is unknown, so no complete maturity-based cash-flow
    /// solvency conclusion can rest on it.
    MissingMaturity,
}

impl ObligationStatus {
    /// The status's byte in the extension.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Contractual => 1,
            Self::Disputed { .. } => 2,
            Self::MissingMaturity => 3,
        }
    }
}

/// The maturity terms of one leg of the entry that carries them. Version 1
/// admits credit legs only; version 2 admits either side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineObligationTerms {
    /// The leg's position in the entry's `legs`.
    pub ordinal: u16,
    pub status: ObligationStatus,
    pub installments: Vec<ObligationInstallment>,
}

impl InlineObligationTerms {
    /// The original credit-only extension's canonical bytes.
    ///
    /// # Errors
    /// The encoder's bounds.
    pub fn encode_list(terms: &[Self]) -> Result<Vec<u8>, EncodeError> {
        Self::encode_list_version(terms, OBLIGATION_TERMS_VERSION)
    }

    /// Canonical bytes for these terms and their posting legs. Credit-only
    /// schedules retain version 1 bytes; a named debit leg selects version 2.
    /// Encoding does not replace [`validate_terms`]: absent ordinals, malformed
    /// schedules and non-positive target amounts still need admission checks.
    ///
    /// # Errors
    /// The encoder's bounds.
    pub fn encode_list_for_legs(
        terms: &[Self],
        legs: &[LegPayload],
    ) -> Result<Vec<u8>, EncodeError> {
        let version = if terms.iter().any(|term| {
            legs.get(usize::from(term.ordinal))
                .is_some_and(|leg| leg.side == Side::Debit)
        }) {
            RECEIVABLE_TERMS_VERSION
        } else {
            OBLIGATION_TERMS_VERSION
        };
        Self::encode_list_version(terms, version)
    }

    fn encode_list_version(terms: &[Self], version: u16) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u16(version).list(terms, |w, item| {
            w.u16(item.ordinal).u8(item.status.tag());
            if let ObligationStatus::Disputed { reason_code } = item.status {
                w.u16(reason_code);
            }
            w.list(&item.installments, |w, inst| {
                w.i32(inst.due_date.0).i128(inst.amount);
            });
        });
        w.finish()
    }

    /// Decodes the extension's bytes. Every installment amount is positive.
    ///
    /// # Errors
    /// Malformed or non-canonical bytes, an unsupported version, an unknown status
    /// or a non-positive amount.
    pub fn decode_list(bytes: &[u8]) -> Result<Vec<Self>, DecodeError> {
        Self::decode_list_versioned(bytes).map(|(_, terms)| terms)
    }

    fn decode_list_versioned(bytes: &[u8]) -> Result<(u16, Vec<Self>), DecodeError> {
        let mut r = Reader::new(bytes);
        let version = r.u16("obligation_terms.version")?;
        if version != OBLIGATION_TERMS_VERSION && version != RECEIVABLE_TERMS_VERSION {
            return Err(r.invalid("obligation_terms.version"));
        }
        let list = r.list(MAX_OBLIGATION_TERMS, "obligation_terms.items", |r| {
            let ordinal = r.u16("obligation_terms.ordinal")?;
            let status = match r.u8("obligation_terms.status")? {
                1 => ObligationStatus::Contractual,
                2 => ObligationStatus::Disputed {
                    reason_code: r.u16("obligation_terms.reason_code")?,
                },
                3 => ObligationStatus::MissingMaturity,
                tag => return Err(r.bad_tag("obligation_terms.status", tag)),
            };
            let installments = r.list(
                MAX_OBLIGATION_INSTALLMENTS,
                "obligation_terms.installments",
                |r| {
                    let due_date = DateDay(r.i32("obligation_terms.due_date")?);
                    let amount = r.i128("obligation_terms.amount")?;
                    if amount <= 0 {
                        return Err(r.invalid("obligation_terms.amount"));
                    }
                    Ok(ObligationInstallment { due_date, amount })
                },
            )?;
            Ok(Self {
                ordinal,
                status,
                installments,
            })
        })?;
        r.finish()?;
        Ok((version, list))
    }

    /// The `(tag, bytes)` pair to put in `EntryPayload::extensions`.
    ///
    /// # Errors
    /// The encoder's bounds.
    pub fn to_extension(terms: &[Self]) -> Result<(u16, Vec<u8>), EncodeError> {
        Ok((
            crate::entry::OBLIGATION_MATURITY_EXTENSION,
            Self::encode_list(terms)?,
        ))
    }

    /// The versioned `(tag, bytes)` pair for maturity terms over these legs.
    /// Credit-only callers retain the original extension bytes.
    ///
    /// # Errors
    /// The encoder's bounds.
    pub fn to_extension_for_legs(
        terms: &[Self],
        legs: &[LegPayload],
    ) -> Result<(u16, Vec<u8>), EncodeError> {
        Ok((
            crate::entry::OBLIGATION_MATURITY_EXTENSION,
            Self::encode_list_for_legs(terms, legs)?,
        ))
    }
}

/// The structural law of an entry's obligation terms against its legs:
/// - the bytes decode and re-encode to themselves;
/// - terms are strictly ascending by leg ordinal and name existing legs;
/// - version 1 names credit legs only; version 2 admits either side and
///   requires a positive target amount, including for unscheduled terms;
/// - MissingMaturity declares no installment;
/// - any other status with installments declares them strictly ascending by
///   due date, totalling exactly the leg's amount, so the schedule covers
///   the whole obligation once.
///
/// Whether the leg's account is a liability, and how settlements relieve
/// the schedule later, are the reader's to judge (the kernel has the
/// chart; `solvency.cash_flow_test` has the open items).
///
/// # Errors
/// The first violation, as `(field, why)`.
pub fn validate_terms(
    bytes: &[u8],
    legs: &[LegPayload],
) -> Result<(), (&'static str, &'static str)> {
    let (version, terms) = InlineObligationTerms::decode_list_versioned(bytes)
        .map_err(|_| ("extensions.obligation_maturity", "does not decode"))?;
    if InlineObligationTerms::encode_list_version(&terms, version)
        .ok()
        .as_deref()
        != Some(bytes)
    {
        return Err(("extensions.obligation_maturity", "is not in canonical form"));
    }
    if terms.is_empty() {
        return Err((
            "extensions.obligation_maturity",
            "declares no terms; omit the extension instead",
        ));
    }
    if terms.windows(2).any(|w| w[0].ordinal >= w[1].ordinal) {
        return Err((
            "extensions.obligation_maturity",
            "terms must be strictly ascending by leg ordinal",
        ));
    }
    for term in &terms {
        let Some(leg) = legs.get(usize::from(term.ordinal)) else {
            return Err((
                "extensions.obligation_maturity",
                "names a leg ordinal the entry does not have",
            ));
        };
        if version == OBLIGATION_TERMS_VERSION && leg.side != Side::Credit {
            return Err((
                "extensions.obligation_maturity",
                "names a debit leg; an obligation is booked on a credit leg",
            ));
        }
        if version == RECEIVABLE_TERMS_VERSION && leg.amount.mantissa <= 0 {
            return Err((
                "extensions.obligation_maturity",
                "maturity terms require a positive target leg amount",
            ));
        }
        if term.status == ObligationStatus::MissingMaturity {
            if !term.installments.is_empty() {
                return Err((
                    "extensions.obligation_maturity",
                    "a MissingMaturity term declares no installment",
                ));
            }
            continue;
        }
        if term.status == ObligationStatus::Contractual && term.installments.is_empty() {
            return Err((
                "extensions.obligation_maturity",
                "a Contractual term declares at least one installment",
            ));
        }
        if term.installments.is_empty() {
            continue;
        }
        if term
            .installments
            .windows(2)
            .any(|w| w[0].due_date >= w[1].due_date)
        {
            return Err((
                "extensions.obligation_maturity",
                "installments must be strictly ascending by due date",
            ));
        }
        let mut total: i128 = 0;
        for installment in &term.installments {
            total = total.checked_add(installment.amount).ok_or((
                "extensions.obligation_maturity",
                "installments overflow their total",
            ))?;
        }
        if Some(total) != leg.amount.mantissa.checked_abs() {
            return Err((
                "extensions.obligation_maturity",
                "installments must total exactly the leg's amount",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fa_money::{Amount, UnitId};
    use fgdb_types::VId;

    use super::*;

    const USD: UnitId = UnitId(1);

    fn legs() -> Vec<LegPayload> {
        vec![
            LegPayload::simple(Side::Debit, VId(1), Amount::new(USD, 500)),
            LegPayload::simple(Side::Credit, VId(2), Amount::new(USD, 300)),
            LegPayload::simple(Side::Credit, VId(3), Amount::new(USD, 200)),
        ]
    }

    fn installment(day: i32, amount: i128) -> ObligationInstallment {
        ObligationInstallment {
            due_date: DateDay(day),
            amount,
        }
    }

    fn term(
        ordinal: u16,
        status: ObligationStatus,
        installments: Vec<ObligationInstallment>,
    ) -> InlineObligationTerms {
        InlineObligationTerms {
            ordinal,
            status,
            installments,
        }
    }

    fn judged(terms: &[InlineObligationTerms]) -> Result<(), &'static str> {
        let bytes = InlineObligationTerms::encode_list(terms).unwrap();
        validate_terms(&bytes, &legs()).map_err(|(_, why)| why)
    }

    #[test]
    fn payable_terms_keep_their_original_v1_bytes() {
        let terms = [term(
            1,
            ObligationStatus::Contractual,
            vec![installment(100, 300)],
        )];
        // Fixed v1 vector, independent of both encoder entry points: version,
        // term count, ordinal, status, installment count, date and i128 amount.
        let expected = [
            1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 0, 100, 0, 0, 0, 44, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0,
        ];
        assert_eq!(
            InlineObligationTerms::encode_list(&terms).unwrap(),
            expected
        );
        assert_eq!(
            InlineObligationTerms::encode_list_for_legs(&terms, &legs()).unwrap(),
            expected
        );
        assert_eq!(validate_terms(&expected, &legs()), Ok(()));
    }

    #[test]
    fn receivable_terms_use_v2_without_reinterpreting_v1() {
        let terms = vec![
            term(
                0,
                ObligationStatus::Contractual,
                vec![installment(100, 200), installment(130, 300)],
            ),
            term(
                1,
                ObligationStatus::Contractual,
                vec![installment(120, 300)],
            ),
        ];
        let bytes = InlineObligationTerms::encode_list_for_legs(&terms, &legs()).unwrap();
        assert_eq!(&bytes[..2], &RECEIVABLE_TERMS_VERSION.to_le_bytes());
        assert_eq!(InlineObligationTerms::decode_list(&bytes).unwrap(), terms);
        assert_eq!(validate_terms(&bytes, &legs()), Ok(()));
        assert_eq!(
            InlineObligationTerms::to_extension_for_legs(&terms, &legs())
                .unwrap()
                .1,
            bytes
        );

        let mut legacy = bytes.clone();
        legacy[..2].copy_from_slice(&OBLIGATION_TERMS_VERSION.to_le_bytes());
        assert!(validate_terms(&legacy, &legs()).is_err_and(|(_, why)| why.contains("debit leg")));

        let mut unknown = bytes;
        unknown[..2].copy_from_slice(&3u16.to_le_bytes());
        assert!(InlineObligationTerms::decode_list(&unknown).is_err());
        assert!(validate_terms(&unknown, &legs()).is_err());
    }

    #[test]
    fn receivable_terms_enforce_exact_totals_and_positive_targets() {
        let mut terms = vec![term(
            0,
            ObligationStatus::Contractual,
            vec![installment(100, 499)],
        )];
        let bytes = InlineObligationTerms::encode_list_for_legs(&terms, &legs()).unwrap();
        assert!(
            validate_terms(&bytes, &legs()).is_err_and(|(_, why)| why.contains("total exactly"))
        );

        terms[0].installments[0].amount = 500;
        let bytes = InlineObligationTerms::encode_list_for_legs(&terms, &legs()).unwrap();
        assert_eq!(validate_terms(&bytes, &legs()), Ok(()));
        for target_amount in [0, -500] {
            let mut targets = legs();
            targets[0].amount.mantissa = target_amount;
            assert!(
                validate_terms(&bytes, &targets)
                    .is_err_and(|(_, why)| why.contains("positive target"))
            );
        }

        // Unknown maturity cannot be used to attach a schedule to a zero leg.
        terms[0].status = ObligationStatus::MissingMaturity;
        terms[0].installments.clear();
        let bytes = InlineObligationTerms::encode_list_for_legs(&terms, &legs()).unwrap();
        assert_eq!(validate_terms(&bytes, &legs()), Ok(()));
        let mut zero = legs();
        zero[0].amount.mantissa = 0;
        assert!(
            validate_terms(&bytes, &zero).is_err_and(|(_, why)| why.contains("positive target"))
        );
    }

    /// Two credit legs, one with a two-installment schedule and one disputed,
    /// round-trip and pass; every structural violation is refused by name.
    #[test]
    fn terms_round_trip_and_each_violation_is_refused() {
        let good = vec![
            term(
                1,
                ObligationStatus::Contractual,
                vec![installment(100, 100), installment(130, 200)],
            ),
            term(2, ObligationStatus::Disputed { reason_code: 7 }, Vec::new()),
        ];
        let bytes = InlineObligationTerms::encode_list(&good).unwrap();
        assert_eq!(InlineObligationTerms::decode_list(&bytes).unwrap(), good);
        assert_eq!(judged(&good), Ok(()));
        assert_eq!(
            InlineObligationTerms::to_extension(&good).unwrap().0,
            crate::entry::OBLIGATION_MATURITY_EXTENSION
        );

        assert!(judged(&[]).is_err_and(|why| why.contains("no terms")));
        let mut descending = good.clone();
        descending.reverse();
        assert!(judged(&descending).is_err_and(|why| why.contains("ascending by leg ordinal")));
        assert!(
            judged(&[term(
                2,
                ObligationStatus::MissingMaturity,
                vec![installment(100, 200)]
            )])
            .is_err_and(|why| why.contains("MissingMaturity"))
        );
        assert!(
            judged(&[term(2, ObligationStatus::Contractual, Vec::new())])
                .is_err_and(|why| why.contains("at least one installment"))
        );
        assert!(
            judged(&[term(
                1,
                ObligationStatus::Contractual,
                vec![installment(130, 100), installment(100, 200)]
            )])
            .is_err_and(|why| why.contains("ascending by due date"))
        );
        assert_eq!(
            judged(&[term(2, ObligationStatus::MissingMaturity, Vec::new())]),
            Ok(())
        );

        // Another version is refused by the decoder, a non-positive amount too.
        let mut other_version = bytes.clone();
        other_version[0] ^= 0xff;
        assert!(InlineObligationTerms::decode_list(&other_version).is_err());
        let zero = InlineObligationTerms::encode_list(&[term(
            1,
            ObligationStatus::Contractual,
            vec![installment(100, 0)],
        )])
        .unwrap();
        assert!(InlineObligationTerms::decode_list(&zero).is_err());
        assert!(validate_terms(&zero, &legs()).is_err());
    }
}
