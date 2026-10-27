//! Canonical named proportional hold posting basis (plan §5.4).
//!
//! Extension 35 stores `u16 version | u16 law | u16 law_version |
//! bytes(canonical FAR1 rate)`. The pending EntryRef and source ordinal map
//! already belong to the containing Resolution. Journal admission decodes
//! the rate under an arithmetic budget and recomputes the sub-vector from
//! the authenticated pending entry, never from caller-supplied capacities.

use fa_money::proportional_post::{MAX_PROPORTIONAL_POST_RATE_BYTES, ProportionalPostLaw};

use crate::{DecodeError, EncodeError, Reader, Writer};

pub const PROPORTIONAL_POST_BASIS_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProportionalPostBasis {
    pub law: ProportionalPostLaw,
    /// Canonical `Rate::encode` bytes. Full rational canonicality and range
    /// are checked with `Rate::decode` in the budgeted admission step.
    pub rate_bytes: Vec<u8>,
}

impl ProportionalPostBasis {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.u16(PROPORTIONAL_POST_BASIS_VERSION)
            .u16(self.law.id())
            .u16(self.law.version())
            .bytes(&self.rate_bytes);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.u16("proportional.version")? != PROPORTIONAL_POST_BASIS_VERSION {
            return Err(r.invalid("proportional.version"));
        }
        let id = r.u16("proportional.law")?;
        let law = ProportionalPostLaw::from_id(id).ok_or_else(|| r.invalid("proportional.law"))?;
        if r.u16("proportional.law_version")? != law.version() {
            return Err(r.invalid("proportional.law_version"));
        }
        let rate = r.bytes(MAX_PROPORTIONAL_POST_RATE_BYTES, "proportional.rate")?;
        // Validate a bounded minimal unsigned FAR frame without allocating
        // big integers. Reduction is intentionally the metered decoder's job.
        let mut frame = Reader::new(rate);
        if frame.fixed::<4>("proportional.rate.magic")? != *b"FAR\x01" {
            return Err(frame.invalid("proportional.rate.magic"));
        }
        let n = usize::try_from(frame.u32("proportional.rate.numerator_len")?)
            .map_err(|_| frame.invalid("proportional.rate.numerator_len"))?;
        let d = usize::try_from(frame.u32("proportional.rate.denominator_len")?)
            .map_err(|_| frame.invalid("proportional.rate.denominator_len"))?;
        let total = n.checked_add(d).and_then(|length| length.checked_add(12));
        if d == 0 || total != Some(rate.len()) {
            return Err(frame.invalid("proportional.rate.length"));
        }
        let numerator = &rate[12..12 + n];
        let denominator = &rate[12 + n..];
        if numerator.last() == Some(&0)
            || denominator.last() == Some(&0)
            || (n == 0 && denominator != [1])
            || n > d
            || (n == d && numerator.iter().rev().cmp(denominator.iter().rev()).is_gt())
        {
            return Err(frame.invalid("proportional.rate.range_or_magnitude"));
        }
        r.finish()?;
        Ok(Self {
            law,
            rate_bytes: rate.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basis() -> ProportionalPostBasis {
        let mut rate = b"FAR\x01".to_vec();
        rate.extend_from_slice(&1_u32.to_le_bytes());
        rate.extend_from_slice(&1_u32.to_le_bytes());
        rate.extend_from_slice(&[37, 100]);
        ProportionalPostBasis {
            law: ProportionalPostLaw::BalancedLargestRemainder,
            rate_bytes: rate,
        }
    }

    #[test]
    fn proportional_basis_is_canonical_bounded_and_versioned() {
        let value = basis();
        let bytes = value.encode().unwrap();
        assert_eq!(ProportionalPostBasis::decode(&bytes).unwrap(), value);
        for at in [0, 2, 4, 10] {
            let mut bad = bytes.clone();
            bad[at] = 255;
            assert!(ProportionalPostBasis::decode(&bad).is_err(), "offset {at}");
        }
        for length in 0..bytes.len() {
            assert!(ProportionalPostBasis::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(ProportionalPostBasis::decode(&trailing).is_err());
        for (numerator, denominator) in [(101, 100), (1, 0), (0, 100)] {
            let mut bad = bytes.clone();
            let length = bad.len();
            bad[length - 2] = numerator;
            bad[length - 1] = denominator;
            assert!(ProportionalPostBasis::decode(&bad).is_err());
        }
    }
}
