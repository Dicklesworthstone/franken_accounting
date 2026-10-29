//! Retained basis of source-bound, cumulative period-end FX revaluation.

use fa_money::{Amount, UnitId};
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::canon::Reason;
use crate::limits::{MAX_EXTENSION_BYTES, MAX_LEGS_PER_ENTRY};
use crate::{DecodeError, EncodeError, EntryRef, Oid, Reader, Writer};

const MAGIC: &[u8; 14] = b"FA-FX-REVALUE\0";
pub const FX_REVALUATION_VERSION: u16 = 1;
pub const FX_ITEM_REVALUATION_VERSION: u16 = 2;
const RELIEF_MAGIC: &[u8; 13] = b"FA-FX-RELIEF\0";

/// One open item's immutable input and allocated closing value. Signed
/// valuation amounts use the original item's debit/credit orientation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxRevaluationItem {
    pub target: EntryRef,
    pub ordinal: u16,
    pub open_native: Amount,
    pub historical_base: Amount,
    pub prior_valuation: Amount,
    pub target_base: Amount,
}

/// LargestRemainder v1 distributes the complete rounded closing target over
/// native open amounts, with ties in `(target.vid, ordinal)` order. The kernel
/// proves that this is the complete eligible source population and reproduces
/// every amount. These fields are assertions, never authority to type balances.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxItemRevaluationBasis {
    pub allocation_law: u16,
    pub allocation_version: u16,
    pub items: Vec<FxRevaluationItem>,
}

/// Exact historical and total carrying relief for one settlement component.
/// The signed difference is released from the retained valuation route and
/// reclassified out of unrealized FX. Reversals restore these recorded effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxSettlementValuationRelease {
    pub applying_ordinal: u16,
    pub source_digest: [u8; 32],
    pub historical_relief: Amount,
    pub total_relief: Amount,
    pub valuation_relief: Amount,
    pub routes_entry: VId,
    pub routes_digest: [u8; 32],
    pub valuation_account: VId,
    pub unrealized_account: VId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxSettlementValuationBasis {
    pub items: Vec<FxSettlementValuationRelease>,
}

fn bounded_frame(raw: &[u8], what: &'static str) -> Result<(), DecodeError> {
    if raw.len() > MAX_EXTENSION_BYTES {
        return Err(DecodeError {
            offset: 0,
            what,
            reason: Reason::TooLong {
                max: MAX_EXTENSION_BYTES,
                actual: raw.len(),
            },
        });
    }
    Ok(())
}

fn write_amount(w: &mut Writer, amount: Amount) {
    w.u32(amount.unit.0).i128(amount.mantissa);
}

fn read_amount(r: &mut Reader<'_>) -> Result<Amount, DecodeError> {
    Ok(Amount::new(
        UnitId(r.u32("fx_item.amount.unit")?),
        r.i128("fx_item.amount.mantissa")?,
    ))
}

impl FxItemRevaluationBasis {
    fn encode(&self, w: &mut Writer) {
        w.u16(self.allocation_law)
            .u16(self.allocation_version)
            .list(&self.items, |w, item| {
                w.u128(item.target.vid.0)
                    .fixed(&item.target.entry_digest)
                    .u16(item.ordinal);
                write_amount(w, item.open_native);
                write_amount(w, item.historical_base);
                write_amount(w, item.prior_valuation);
                write_amount(w, item.target_base);
            });
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        let result = Self {
            allocation_law: r.u16("fx_item.allocation_law")?,
            allocation_version: r.u16("fx_item.allocation_version")?,
            items: r.list(MAX_LEGS_PER_ENTRY / 2, "fx_item.items", |r| {
                Ok(FxRevaluationItem {
                    target: EntryRef {
                        vid: VId(r.u128("fx_item.target.vid")?),
                        entry_digest: r.fixed("fx_item.target.entry_digest")?,
                    },
                    ordinal: r.u16("fx_item.ordinal")?,
                    open_native: read_amount(r)?,
                    historical_base: read_amount(r)?,
                    prior_valuation: read_amount(r)?,
                    target_base: read_amount(r)?,
                })
            })?,
        };
        if result.allocation_law != 1
            || result.allocation_version != 1
            || result.items.is_empty()
            || result.items.windows(2).any(|pair| {
                (pair[0].target.vid, pair[0].ordinal) >= (pair[1].target.vid, pair[1].ordinal)
            })
            || result.items.iter().any(|item| {
                usize::from(item.ordinal) >= MAX_LEGS_PER_ENTRY
                    || item.open_native.mantissa <= 0
                    || item.historical_base.mantissa < 0
                    || item.target_base.mantissa < 0
                    || item.open_native.unit == item.historical_base.unit
                    || item.historical_base.unit != item.prior_valuation.unit
                    || item.historical_base.unit != item.target_base.unit
                    || item
                        .historical_base
                        .mantissa
                        .checked_add(item.prior_valuation.mantissa)
                        .is_none_or(|carrying| carrying < 0)
            })
        {
            return Err(r.invalid("fx_item.allocation"));
        }
        Ok(result)
    }
}

impl FxSettlementValuationBasis {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(RELIEF_MAGIC).u16(1).list(&self.items, |w, item| {
            w.u16(item.applying_ordinal).fixed(&item.source_digest);
            write_amount(w, item.historical_relief);
            write_amount(w, item.total_relief);
            write_amount(w, item.valuation_relief);
            w.u128(item.routes_entry.0)
                .fixed(&item.routes_digest)
                .u128(item.valuation_account.0)
                .u128(item.unrealized_account.0);
        });
        w.finish()
    }

    pub fn decode(raw: &[u8]) -> Result<Self, DecodeError> {
        bounded_frame(raw, "fx_relief.bytes")?;
        let mut r = Reader::new(raw);
        if r.fixed::<13>("fx_relief.magic")? != *RELIEF_MAGIC || r.u16("fx_relief.version")? != 1 {
            return Err(r.invalid("fx_relief.version"));
        }
        let items = r.list(MAX_LEGS_PER_ENTRY / 4, "fx_relief.items", |r| {
            Ok(FxSettlementValuationRelease {
                applying_ordinal: r.u16("fx_relief.applying_ordinal")?,
                source_digest: r.fixed("fx_relief.source_digest")?,
                historical_relief: read_amount(r)?,
                total_relief: read_amount(r)?,
                valuation_relief: read_amount(r)?,
                routes_entry: VId(r.u128("fx_relief.routes_entry")?),
                routes_digest: r.fixed("fx_relief.routes_digest")?,
                valuation_account: VId(r.u128("fx_relief.valuation_account")?),
                unrealized_account: VId(r.u128("fx_relief.unrealized_account")?),
            })
        })?;
        if items.is_empty()
            || items
                .windows(2)
                .any(|pair| pair[0].applying_ordinal >= pair[1].applying_ordinal)
            || items.iter().any(|item| {
                usize::from(item.applying_ordinal) >= MAX_LEGS_PER_ENTRY
                    || item.historical_relief.mantissa < 0
                    || item.total_relief.mantissa < 0
                    || item.historical_relief.unit != item.total_relief.unit
                    || item.historical_relief.unit != item.valuation_relief.unit
                    || item
                        .historical_relief
                        .mantissa
                        .checked_add(item.valuation_relief.mantissa)
                        != Some(item.total_relief.mantissa)
                    || item.valuation_account == item.unrealized_account
            })
        {
            return Err(r.invalid("fx_relief.items"));
        }
        r.finish()?;
        Ok(Self { items })
    }
}

/// All selectors needed to independently reproduce a retained adjustment.
/// Monetary terms are derived from the journal; this basis accepts no caller
/// balance or amount assertion. Its complete bytes ride the proposal digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FxRevaluationBasis {
    pub period: String,
    pub closing_date: DateDay,
    pub observed_at: CommitSeq,
    pub source_account: VId,
    pub entity: Option<VId>,
    pub routes_entry: VId,
    pub routes_digest: [u8; 32],
    pub rate_document: Oid,
    pub rate_commit: [u8; 32],
    pub source_digest: [u8; 32],
    /// Absent in the unchanged aggregate-only v1 profile. Version 2 retains
    /// the complete per-item allocation needed for later carrying relief.
    pub item_allocation: Option<FxItemRevaluationBasis>,
}

impl FxRevaluationBasis {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(if self.item_allocation.is_some() {
                FX_ITEM_REVALUATION_VERSION
            } else {
                FX_REVALUATION_VERSION
            })
            .str(&self.period)
            .i32(self.closing_date.0)
            .u64(self.observed_at.0)
            .u128(self.source_account.0)
            .opt(self.entity.as_ref(), |w, value| {
                w.u128(value.0);
            })
            .u128(self.routes_entry.0)
            .fixed(&self.routes_digest)
            .fixed(&self.rate_document.0)
            .fixed(&self.rate_commit)
            .fixed(&self.source_digest);
        if let Some(allocation) = &self.item_allocation {
            allocation.encode(&mut w);
        }
        w.finish()
    }

    pub fn decode(raw: &[u8]) -> Result<Self, DecodeError> {
        bounded_frame(raw, "fx_revaluation.bytes")?;
        let mut r = Reader::new(raw);
        if r.fixed::<14>("fx_revaluation.magic")? != *MAGIC {
            return Err(r.invalid("fx_revaluation.version"));
        }
        let version = r.u16("fx_revaluation.version")?;
        if !matches!(
            version,
            FX_REVALUATION_VERSION | FX_ITEM_REVALUATION_VERSION
        ) {
            return Err(r.invalid("fx_revaluation.version"));
        }
        let result = Self {
            period: r.str(64, "fx_revaluation.period")?.to_string(),
            closing_date: DateDay(r.i32("fx_revaluation.closing_date")?),
            observed_at: CommitSeq(r.u64("fx_revaluation.observed_at")?),
            source_account: VId(r.u128("fx_revaluation.source_account")?),
            entity: r.opt("fx_revaluation.entity", |r| {
                Ok(VId(r.u128("fx_revaluation.entity")?))
            })?,
            routes_entry: VId(r.u128("fx_revaluation.routes_entry")?),
            routes_digest: r.fixed("fx_revaluation.routes_digest")?,
            rate_document: Oid(r.fixed("fx_revaluation.rate_document")?),
            rate_commit: r.fixed("fx_revaluation.rate_commit")?,
            source_digest: r.fixed("fx_revaluation.source_digest")?,
            item_allocation: if version == FX_ITEM_REVALUATION_VERSION {
                Some(FxItemRevaluationBasis::decode(&mut r)?)
            } else {
                None
            },
        };
        if result.period.is_empty() || result.observed_at.0 == 0 {
            return Err(r.invalid("fx_revaluation.coordinate"));
        }
        r.finish()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revaluation_basis_is_bounded_versioned_and_complete() {
        let basis = FxRevaluationBasis {
            period: "FY2026-P01".into(),
            closing_date: DateDay(20_484),
            observed_at: CommitSeq(9),
            source_account: VId(11),
            entity: Some(VId(12)),
            routes_entry: VId(13),
            routes_digest: [2; 32],
            rate_document: Oid([3; 32]),
            rate_commit: [4; 32],
            source_digest: [5; 32],
            item_allocation: None,
        };
        let bytes = basis.canonical_bytes().unwrap();
        assert_eq!(FxRevaluationBasis::decode(&bytes).unwrap(), basis);
        for end in 0..bytes.len() {
            assert!(FxRevaluationBasis::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(FxRevaluationBasis::decode(&trailing).is_err());
        let mut future = bytes;
        future[14] = 3;
        assert!(FxRevaluationBasis::decode(&future).is_err());
    }

    fn allocated_basis() -> FxRevaluationBasis {
        FxRevaluationBasis {
            period: "FY2026-P01".into(),
            closing_date: DateDay(20_484),
            observed_at: CommitSeq(9),
            source_account: VId(11),
            entity: None,
            routes_entry: VId(13),
            routes_digest: [2; 32],
            rate_document: Oid([3; 32]),
            rate_commit: [4; 32],
            source_digest: [5; 32],
            item_allocation: Some(FxItemRevaluationBasis {
                allocation_law: 1,
                allocation_version: 1,
                items: vec![FxRevaluationItem {
                    target: EntryRef {
                        vid: VId(17),
                        entry_digest: [8; 32],
                    },
                    ordinal: 0,
                    open_native: Amount::new(UnitId(2), 100),
                    historical_base: Amount::new(UnitId(1), 105),
                    prior_valuation: Amount::new(UnitId(1), -5),
                    target_base: Amount::new(UnitId(1), 110),
                }],
            }),
        }
    }

    #[test]
    fn item_revaluation_preserves_legacy_bytes_and_refuses_ambiguous_allocations() {
        let basis = allocated_basis();
        let bytes = basis.canonical_bytes().unwrap();
        assert_eq!(&bytes[14..16], &2u16.to_le_bytes());
        assert_eq!(FxRevaluationBasis::decode(&bytes).unwrap(), basis);
        let mut legacy = basis.clone();
        legacy.item_allocation = None;
        let legacy_bytes = legacy.canonical_bytes().unwrap();
        assert_eq!(&legacy_bytes[14..16], &1u16.to_le_bytes());
        assert_eq!(&bytes[..14], &legacy_bytes[..14]);
        assert_eq!(&bytes[16..legacy_bytes.len()], &legacy_bytes[16..]);
        assert_eq!(FxRevaluationBasis::decode(&legacy_bytes).unwrap(), legacy);
        for end in 0..bytes.len() {
            assert!(FxRevaluationBasis::decode(&bytes[..end]).is_err());
        }
        let refused = |edit: fn(&mut FxItemRevaluationBasis)| {
            let mut changed = basis.clone();
            edit(changed.item_allocation.as_mut().unwrap());
            assert!(FxRevaluationBasis::decode(&changed.canonical_bytes().unwrap()).is_err());
        };
        refused(|allocation| allocation.items.clear());
        refused(|allocation| allocation.allocation_law = 2);
        refused(|allocation| allocation.allocation_version = 2);
        refused(|allocation| allocation.items.push(allocation.items[0].clone()));
        refused(|allocation| allocation.items[0].open_native.mantissa = 0);
        refused(|allocation| allocation.items[0].historical_base.mantissa = -1);
        refused(|allocation| allocation.items[0].target_base.mantissa = -1);
        refused(|allocation| allocation.items[0].prior_valuation.mantissa = -106);
        refused(|allocation| allocation.items[0].prior_valuation.mantissa = i128::MAX);
        refused(|allocation| allocation.items[0].target_base.unit = UnitId(2));
        refused(|allocation| allocation.items[0].ordinal = MAX_LEGS_PER_ENTRY as u16);
        assert!(FxRevaluationBasis::decode(&vec![0; MAX_EXTENSION_BYTES + 1]).is_err());
        let mut future = bytes.clone();
        future[14] = 3;
        assert!(FxRevaluationBasis::decode(&future).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(FxRevaluationBasis::decode(&trailing).is_err());
    }

    #[test]
    fn settlement_valuation_requires_exact_signed_relief_and_unique_components() {
        let basis = FxSettlementValuationBasis {
            items: vec![FxSettlementValuationRelease {
                applying_ordinal: 0,
                source_digest: [1; 32],
                historical_relief: Amount::new(UnitId(1), 105),
                total_relief: Amount::new(UnitId(1), 100),
                valuation_relief: Amount::new(UnitId(1), -5),
                routes_entry: VId(2),
                routes_digest: [3; 32],
                valuation_account: VId(4),
                unrealized_account: VId(5),
            }],
        };
        let bytes = basis.canonical_bytes().unwrap();
        assert_eq!(FxSettlementValuationBasis::decode(&bytes).unwrap(), basis);
        for end in 0..bytes.len() {
            assert!(FxSettlementValuationBasis::decode(&bytes[..end]).is_err());
        }
        let refused = |edit: fn(&mut FxSettlementValuationBasis)| {
            let mut changed = basis.clone();
            edit(&mut changed);
            assert!(
                FxSettlementValuationBasis::decode(&changed.canonical_bytes().unwrap()).is_err()
            );
        };
        refused(|value| value.items.clear());
        refused(|value| value.items.push(value.items[0].clone()));
        refused(|value| value.items[0].total_relief.mantissa += 1);
        refused(|value| value.items[0].valuation_relief.mantissa = i128::MAX);
        refused(|value| value.items[0].historical_relief.mantissa = -1);
        refused(|value| value.items[0].valuation_relief.unit = UnitId(2));
        refused(|value| value.items[0].unrealized_account = value.items[0].valuation_account);
        refused(|value| value.items[0].applying_ordinal = MAX_LEGS_PER_ENTRY as u16);
        assert!(FxSettlementValuationBasis::decode(&vec![0; MAX_EXTENSION_BYTES + 1]).is_err());
        let mut future = bytes.clone();
        future[13] = 2;
        assert!(FxSettlementValuationBasis::decode(&future).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(FxSettlementValuationBasis::decode(&trailing).is_err());
    }
}
