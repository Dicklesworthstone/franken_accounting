//! The retained basis of the intrinsic YearEndClose computation (§7.5).
//!
//! This is PostEntry provenance, not a claim that generic Canon executed.
//! The posting kernel must reproduce the complete nominal-account fold and
//! the selected journaled routing map before admitting a Closing entry.

use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::{DecodeError, EncodeError, Reader, Writer};

const MAGIC: &[u8; 14] = b"FA-YEAR-CLOSE\0";
pub const YEAR_END_CLOSE_VERSION: u16 = 1;
/// Retained native and functional carrying amounts, grouped by their exact
/// source valuation. Version 1 remains the native base-currency computation.
pub const YEAR_END_CLOSE_CARRYING_VERSION: u16 = 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct YearEndCloseBasis {
    pub version: u16,
    pub fiscal_year: i32,
    pub closing_period: String,
    pub closing_date: DateDay,
    /// Snapshot first used; later harmless metadata is allowed if digests reproduce.
    pub observed_at: CommitSeq,
    pub routes_entry: VId,
    pub routes_digest: [u8; 32],
    /// Complete selected nominal-entry population, including prior closes.
    pub source_digest: [u8; 32],
}

impl YearEndCloseBasis {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(self.version)
            .i32(self.fiscal_year)
            .str(&self.closing_period)
            .i32(self.closing_date.0)
            .u64(self.observed_at.0)
            .u128(self.routes_entry.0)
            .fixed(&self.routes_digest)
            .fixed(&self.source_digest);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.fixed::<14>("year_end_close.magic")? != *MAGIC {
            return Err(r.invalid("year_end_close.version"));
        }
        let version = r.u16("year_end_close.version")?;
        if !matches!(
            version,
            YEAR_END_CLOSE_VERSION | YEAR_END_CLOSE_CARRYING_VERSION
        ) {
            return Err(r.invalid("year_end_close.version"));
        }
        let result = Self {
            version,
            fiscal_year: r.i32("year_end_close.fiscal_year")?,
            closing_period: r.str(64, "year_end_close.closing_period")?.to_string(),
            closing_date: DateDay(r.i32("year_end_close.closing_date")?),
            observed_at: CommitSeq(r.u64("year_end_close.observed_at")?),
            routes_entry: VId(r.u128("year_end_close.routes_entry")?),
            routes_digest: r.fixed("year_end_close.routes_digest")?,
            source_digest: r.fixed("year_end_close.source_digest")?,
        };
        if result.closing_period.is_empty() {
            return Err(r.invalid("year_end_close.closing_period"));
        }
        r.finish()?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closing_basis_is_bounded_versioned_and_complete() {
        let basis = YearEndCloseBasis {
            version: YEAR_END_CLOSE_VERSION,
            fiscal_year: 2026,
            closing_period: "FY2026-CLOSE".into(),
            closing_date: DateDay(20_818),
            observed_at: CommitSeq(8),
            routes_entry: VId(17),
            routes_digest: [2; 32],
            source_digest: [3; 32],
        };
        let bytes = basis.canonical_bytes().unwrap();
        assert_eq!(YearEndCloseBasis::decode(&bytes).unwrap(), basis);
        for end in 0..bytes.len() {
            assert!(YearEndCloseBasis::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(YearEndCloseBasis::decode(&trailing).is_err());
        let mut carrying = basis.clone();
        carrying.version = YEAR_END_CLOSE_CARRYING_VERSION;
        let carrying_bytes = carrying.canonical_bytes().unwrap();
        assert_eq!(
            YearEndCloseBasis::decode(&carrying_bytes).unwrap(),
            carrying
        );
        assert_eq!(&bytes[16..], &carrying_bytes[16..]);
        let mut future = bytes;
        future[14] = 3;
        assert!(YearEndCloseBasis::decode(&future).is_err());
    }
}
