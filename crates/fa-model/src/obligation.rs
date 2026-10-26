//! Obligation maturity terms on a posted liability (plan §11.6, bead
//! fa-5dpd): entry extension 33, `fa:obligation-maturity:v1`.
//!
//! An entry that books an obligation may declare, per credit leg, when it
//! falls due: a contractual installment schedule, a dispute, or that its
//! maturity is unknown. `solvency.cash_flow_test` reads the terms of the
//! obligations open at its as-of date, so a debt is counted by when it is
//! due rather than when it was booked. The terms are part of the proposal,
//! so its digest, the approvals over it and the journal cover them.
//!
//! Bytes: `u16 version ‖ list(u16 leg ordinal ‖ u8 status [‖ u16 reason
//! code when Disputed] ‖ list(i32 due day ‖ i128 amount))`.

use fa_time::DateDay;

use crate::canon::{DecodeError, EncodeError, Reader, Writer};
use crate::entry::LegPayload;
use fa_money::Side;

/// The only version of the extension's bytes.
pub const OBLIGATION_TERMS_VERSION: u16 = 1;

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
    /// The liability is disputed, with a reason code.
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

/// The maturity terms of one credit leg of the entry that carries them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InlineObligationTerms {
    /// The leg's position in the entry's `legs`.
    pub ordinal: u16,
    pub status: ObligationStatus,
    pub installments: Vec<ObligationInstallment>,
}

impl InlineObligationTerms {
    /// The extension's canonical bytes.
    ///
    /// # Errors
    /// The encoder's bounds.
    pub fn encode_list(terms: &[Self]) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u16(OBLIGATION_TERMS_VERSION).list(terms, |w, item| {
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
    /// Malformed or non-canonical bytes, another version, an unknown status
    /// or a non-positive amount.
    pub fn decode_list(bytes: &[u8]) -> Result<Vec<Self>, DecodeError> {
        let mut r = Reader::new(bytes);
        let version = r.u16("obligation_terms.version")?;
        if version != OBLIGATION_TERMS_VERSION {
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
        Ok(list)
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
}

/// The structural law of an entry's obligation terms against its legs:
/// - the bytes decode and re-encode to themselves;
/// - terms are strictly ascending by leg ordinal, and each names a credit
///   leg of the entry (the side on which an obligation is booked);
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
    let terms = InlineObligationTerms::decode_list(bytes)
        .map_err(|_| ("extensions.obligation_maturity", "does not decode"))?;
    if InlineObligationTerms::encode_list(&terms).ok().as_deref() != Some(bytes) {
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
        if leg.side != Side::Credit {
            return Err((
                "extensions.obligation_maturity",
                "names a debit leg; an obligation is booked on a credit leg",
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
