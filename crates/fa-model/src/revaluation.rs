//! Retained basis of source-bound, cumulative period-end FX revaluation.

use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::{DecodeError, EncodeError, Oid, Reader, Writer};

const MAGIC: &[u8; 14] = b"FA-FX-REVALUE\0";
pub const FX_REVALUATION_VERSION: u16 = 1;

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
}

impl FxRevaluationBasis {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(FX_REVALUATION_VERSION)
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
        w.finish()
    }

    pub fn decode(raw: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(raw);
        if r.fixed::<14>("fx_revaluation.magic")? != *MAGIC
            || r.u16("fx_revaluation.version")? != FX_REVALUATION_VERSION
        {
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
        future[14] = 2;
        assert!(FxRevaluationBasis::decode(&future).is_err());
    }
}
