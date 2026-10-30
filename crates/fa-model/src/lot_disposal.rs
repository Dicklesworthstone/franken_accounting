//! Canonical lot policy and source-bound disposal inputs (plan §6.5).
//!
//! The policy is selected by recorded prefix. A new backdated disposal does
//! not recover an obsolete policy. Extension 38 binds a disposal to that
//! policy's immutable control entry and the complete observed lot population;
//! the posting kernel, rather than this codec, derives and checks the legs.

use std::collections::BTreeSet;

use fa_money::{AccountingRegime, Amount, LotLaw, RoundingLaw, UnitId};
use fgdb_types::{CommitSeq, VId};

use crate::{DecodeError, EncodeError, EntryRef, Reader, Writer};

pub const LOT_POLICY_FORMAT: &[u8] = b"fa:lot-policy:v1";
pub const LOT_DISPOSAL_FORMAT: &[u8] = b"fa:lot-disposal:v1";
/// One disposal's targets fit its ordinary per-leg settlement bound.
pub const MAX_SPECIFIC_LOTS: usize = crate::limits::MAX_SETTLES_PER_LEG;

/// A single recorded-version policy for every non-base quantity on an account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotPolicy {
    pub account: VId,
    pub law: LotLaw,
    pub regime: AccountingRegime,
    pub rounding_law: RoundingLaw,
}

fn write_laws(w: &mut Writer, law: LotLaw, regime: AccountingRegime, rounding: RoundingLaw) {
    w.u16(law.id()).u16(1).u8(match regime {
        AccountingRegime::UsGaap => 0,
        AccountingRegime::UsTax => 1,
        AccountingRegime::Ifrs => 2,
    });
    w.u16(rounding.id()).u16(1);
}

fn read_laws(r: &mut Reader<'_>) -> Result<(LotLaw, AccountingRegime, RoundingLaw), DecodeError> {
    let law = LotLaw::from_id(r.u16("lot.law")?).ok_or_else(|| r.invalid("lot.law"))?;
    if r.u16("lot.law_version")? != 1 {
        return Err(r.invalid("lot.law_version"));
    }
    let regime = match r.u8("lot.regime")? {
        0 => AccountingRegime::UsGaap,
        1 => AccountingRegime::UsTax,
        2 => AccountingRegime::Ifrs,
        tag => return Err(r.bad_tag("lot.regime", tag)),
    };
    let rounding = RoundingLaw::from_id(r.u16("lot.rounding_law")?)
        .ok_or_else(|| r.invalid("lot.rounding_law"))?;
    if r.u16("lot.rounding_version")? != 1 {
        return Err(r.invalid("lot.rounding_version"));
    }
    Ok((law, regime, rounding))
}

impl LotPolicy {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.bytes(LOT_POLICY_FORMAT).u128(self.account.0);
        write_laws(&mut w, self.law, self.regime, self.rounding_law);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.bytes(64, "lot_policy.format")? != LOT_POLICY_FORMAT {
            return Err(r.invalid("lot_policy.format"));
        }
        let account = VId(r.u128("lot_policy.account")?);
        let (law, regime, rounding_law) = read_laws(&mut r)?;
        r.finish()?;
        Ok(Self {
            account,
            law,
            regime,
            rounding_law,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotDisposalBasis {
    pub account: VId,
    pub quantity: Amount,
    pub quantity_offset_account: VId,
    pub cost_offset_account: VId,
    /// Ordered SpecificId selections. Other laws require an empty list.
    pub specific_ids: Vec<(EntryRef, u16)>,
    pub known_at: CommitSeq,
    pub policy: EntryRef,
    pub law: LotLaw,
    pub regime: AccountingRegime,
    pub rounding_law: RoundingLaw,
}

impl LotDisposalBasis {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.bytes(LOT_DISPOSAL_FORMAT)
            .u128(self.account.0)
            .u32(self.quantity.unit.0)
            .i128(self.quantity.mantissa)
            .u128(self.quantity_offset_account.0)
            .u128(self.cost_offset_account.0)
            .list(&self.specific_ids, |w, (entry, ordinal)| {
                w.u128(entry.vid.0).fixed(&entry.entry_digest).u16(*ordinal);
            })
            .u64(self.known_at.0)
            .u128(self.policy.vid.0)
            .fixed(&self.policy.entry_digest);
        write_laws(&mut w, self.law, self.regime, self.rounding_law);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if bytes.len() > crate::limits::MAX_EXTENSION_BYTES
            || r.bytes(64, "lot_disposal.format")? != LOT_DISPOSAL_FORMAT
        {
            return Err(r.invalid("lot_disposal.format"));
        }
        let account = VId(r.u128("lot_disposal.account")?);
        let quantity = Amount::new(
            UnitId(r.u32("lot_disposal.unit")?),
            r.i128("lot_disposal.quantity")?,
        );
        let quantity_offset_account = VId(r.u128("lot_disposal.quantity_offset")?);
        let cost_offset_account = VId(r.u128("lot_disposal.cost_offset")?);
        let specific_ids = r.list(MAX_SPECIFIC_LOTS, "lot_disposal.specific_ids", |r| {
            Ok((
                EntryRef {
                    vid: VId(r.u128("lot_disposal.target")?),
                    entry_digest: r.fixed("lot_disposal.target_digest")?,
                },
                r.u16("lot_disposal.target_ordinal")?,
            ))
        })?;
        let known_at = CommitSeq(r.u64("lot_disposal.known_at")?);
        let policy = EntryRef {
            vid: VId(r.u128("lot_disposal.policy")?),
            entry_digest: r.fixed("lot_disposal.policy_digest")?,
        };
        let (law, regime, rounding_law) = read_laws(&mut r)?;
        let unique: BTreeSet<_> = specific_ids
            .iter()
            .map(|(entry, ordinal)| (entry.vid, *ordinal))
            .collect();
        if quantity.mantissa <= 0
            || account == quantity_offset_account
            || account == cost_offset_account
            || quantity_offset_account == cost_offset_account
            || known_at.0 == 0
            || unique.len() != specific_ids.len()
            || (law == LotLaw::SpecificId) == specific_ids.is_empty()
        {
            return Err(r.invalid("lot_disposal.inputs"));
        }
        r.finish()?;
        Ok(Self {
            account,
            quantity,
            quantity_offset_account,
            cost_offset_account,
            specific_ids,
            known_at,
            policy,
            law,
            regime,
            rounding_law,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basis() -> LotDisposalBasis {
        LotDisposalBasis {
            account: VId(10),
            quantity: Amount::new(UnitId(2), 37),
            quantity_offset_account: VId(11),
            cost_offset_account: VId(12),
            specific_ids: vec![(
                EntryRef {
                    vid: VId(50),
                    entry_digest: [4; 32],
                },
                0,
            )],
            known_at: CommitSeq(80),
            policy: EntryRef {
                vid: VId(20),
                entry_digest: [5; 32],
            },
            law: LotLaw::SpecificId,
            regime: AccountingRegime::UsGaap,
            rounding_law: RoundingLaw::HalfEven,
        }
    }

    #[test]
    fn lot_basis_binds_all_fields_and_rejects_invalid_frames() {
        let b = basis();
        let bytes = b.encode().unwrap();
        assert_eq!(LotDisposalBasis::decode(&bytes).unwrap(), b);
        for end in 0..bytes.len() {
            assert!(LotDisposalBasis::decode(&bytes[..end]).is_err());
        }
        let mut long = bytes.clone();
        long.push(0);
        assert!(LotDisposalBasis::decode(&long).is_err());
        let mut bad = b.clone();
        bad.specific_ids.push(bad.specific_ids[0]);
        assert!(LotDisposalBasis::decode(&bad.encode().unwrap()).is_err());
        bad = b.clone();
        bad.law = LotLaw::Fifo;
        assert!(LotDisposalBasis::decode(&bad.encode().unwrap()).is_err());
        bad = b.clone();
        bad.quantity.mantissa = 0;
        assert!(LotDisposalBasis::decode(&bad.encode().unwrap()).is_err());
        let mut wrong_version = bytes;
        *wrong_version.last_mut().unwrap() = 1;
        assert!(LotDisposalBasis::decode(&wrong_version).is_err());
    }

    #[test]
    fn lot_policy_round_trips_all_registered_tags() {
        for law in LotLaw::ALL {
            for regime in [
                AccountingRegime::UsGaap,
                AccountingRegime::UsTax,
                AccountingRegime::Ifrs,
            ] {
                for rounding_law in RoundingLaw::ALL {
                    let policy = LotPolicy {
                        account: VId(10),
                        law,
                        regime,
                        rounding_law,
                    };
                    assert_eq!(
                        LotPolicy::decode(&policy.encode().unwrap()).unwrap(),
                        policy
                    );
                }
            }
        }
    }
}
