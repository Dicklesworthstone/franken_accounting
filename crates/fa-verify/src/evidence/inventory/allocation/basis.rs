//! Exact versioned driver decoding and independent native-total redistribution.

use super::arithmetic::Wide;
use super::{AllocationError, MAX_BASIS_BYTES, MAX_TARGETS};
use crate::codec::{Reader, Writer};
use std::collections::BTreeSet;

pub(super) const BASIS_MAGIC: &[u8; 15] = b"FA-ALLOC-BASIS\0";
const REQUEST_MAGIC: &[u8; 17] = b"FA-ALLOC-REQUEST\0";

/// One caller-ordered target; zero shares retain their identities and basis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationTarget {
    /// Wire target identity: an account VId in v1, a cell digest in v2.
    /// Use AllocationBasis::target_cell to resolve the actual account.
    pub account: u128,
    pub basis: u128,
}

/// An exact destination account and canonical dimensions in a v2 driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationTargetCell {
    pub account: u128,
    pub dimensions: Vec<(u32, u128)>,
}

impl AllocationTargetCell {
    /// Independently reproduce the producer's bounded, domain-separated ID.
    pub fn identity(&self) -> Result<u128, AllocationError> {
        validate_dimensions(&self.dimensions)?;
        let mut w = Writer::default();
        w.u128(self.account).count(self.dimensions.len());
        for (dimension, value) in &self.dimensions {
            w.u32(*dimension).u128(*value);
        }
        let digest = crate::blake3::hash_parts(
            b"fa:allocation-target:v2",
            &[&(w.buf.len() as u32).to_le_bytes(), &w.buf],
        );
        let mut identity = [0; 16];
        identity.copy_from_slice(&digest[..16]);
        Ok(u128::from_le_bytes(identity))
    }
}

/// A strictly decoded driver, not proof of account legality or provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationBasis {
    pub source: u128,
    pub source_debit: bool,
    pub dimensions: Vec<(u32, u128)>,
    pub law: u16,
    pub unit: u32,
    pub total: i128,
    pub rounding: Option<u16>,
    pub recipient: Option<u128>,
    pub targets: Vec<AllocationTarget>,
    /// Empty means the v1 shared dimension set; v2 has one cell per target.
    pub target_cells: Vec<AllocationTargetCell>,
}

impl AllocationBasis {
    /// Consume the entire canonical driver. No sorting, inferred parameters,
    /// unsupported law/version, empty request or nonpositive posting is admitted.
    pub fn decode(bytes: &[u8]) -> Result<Self, AllocationError> {
        if bytes.len() > MAX_BASIS_BYTES {
            return Err(AllocationError::InputLimit);
        }
        let mut r = Reader::new(bytes);
        if r.fixed::<15>("allocation.basis.magic")? != *BASIS_MAGIC {
            return Err(invalid("unsupported driver format"));
        }
        let version = r.u16("allocation.basis.version")?;
        if !matches!(version, 1 | 2) {
            return Err(invalid("unsupported driver format"));
        }
        let source = r.u128("allocation.source")?;
        let source_debit = debit(r.u8("allocation.source_side")?)?;
        let dimensions = read_dimensions(&mut r)?;
        let request = r.bytes(MAX_BASIS_BYTES, "allocation.request")?;
        let mut target_cells = Vec::new();
        if version == 2 {
            let count = r.count(MAX_TARGETS, 20, "allocation.target_cells")?;
            if count == 0 {
                return Err(invalid("v2 requires explicit destination cells"));
            }
            target_cells
                .try_reserve_exact(count)
                .map_err(|_| AllocationError::InputLimit)?;
            for _ in 0..count {
                target_cells.push(AllocationTargetCell {
                    account: r.u128("allocation.cell.account")?,
                    dimensions: read_dimensions(&mut r)?,
                });
            }
        }
        r.finish("allocation basis")?;
        let mut r = Reader::new(request);
        if r.fixed::<17>("allocation.request.magic")? != *REQUEST_MAGIC
            || r.u16("allocation.request.major")? != 1
            || r.u16("allocation.request.minor")? != 0
        {
            return Err(invalid("unsupported allocation request format"));
        }
        let law = r.u16("allocation.law")?;
        if !matches!(law, 1 | 2 | 3 | 5) || r.u16("allocation.law_version")? != 1 {
            return Err(invalid("unsupported allocation law or version"));
        }
        let unit = r.u32("allocation.unit")?;
        let total = r.i128("allocation.total")?;
        if total <= 0 {
            return Err(invalid("posting total must be positive"));
        }
        let (rounding, recipient) = if law == 2 {
            let rounding = r.u16("allocation.rounding")?;
            if !(1..=9).contains(&rounding) {
                return Err(invalid("unknown rounding law"));
            }
            (Some(rounding), Some(r.u128("allocation.recipient")?))
        } else {
            (None, None)
        };
        let count = r.count(MAX_TARGETS, 32, "allocation.targets")?;
        if count == 0 {
            return Err(invalid("allocation needs targets"));
        }
        // This request format ends at its fixed-size target rows. Enforce
        // exact bytes before allocating, not merely the decoder's lower bound.
        let header = if law == 2 { 67usize } else { 49usize };
        if request.len() != header + 32 * count {
            return Err(invalid(
                "target count does not match the exact request length",
            ));
        }
        let mut targets = Vec::new();
        targets
            .try_reserve_exact(count)
            .map_err(|_| AllocationError::InputLimit)?;
        let mut ids = BTreeSet::new();
        for _ in 0..count {
            let account = r.u128("allocation.target")?;
            let basis = r.u128("allocation.weight_or_cap")?;
            if (version == 1 && account == source) || !ids.insert(account) {
                return Err(invalid(
                    "targets must be distinct and cannot include the source",
                ));
            }
            if law == 5 && basis != 1 {
                return Err(invalid("equal split requires basis one"));
            }
            targets.push(AllocationTarget { account, basis });
        }
        r.finish("allocation request")?;
        if recipient.is_some_and(|recipient| !ids.contains(&recipient)) {
            return Err(invalid("residual recipient is not a target"));
        }
        let basis = Self {
            source,
            source_debit,
            dimensions,
            law,
            unit,
            total,
            rounding,
            recipient,
            targets,
            target_cells,
        };
        basis.validate_target_cells()?;
        Ok(basis)
    }

    /// Retained wire version. A v2 driver always carries its nonempty cell map.
    pub fn version(&self) -> u16 {
        if self.target_cells.is_empty() { 1 } else { 2 }
    }

    /// Resolve an ordered arithmetic target to its actual posting destination.
    pub fn target_cell(&self, index: usize) -> Option<(u128, &[(u32, u128)])> {
        let target = self.targets.get(index)?;
        if self.target_cells.is_empty() {
            Some((target.account, &self.dimensions))
        } else {
            self.target_cells
                .get(index)
                .map(|cell| (cell.account, cell.dimensions.as_slice()))
        }
    }

    fn validate_target_cells(&self) -> Result<(), AllocationError> {
        validate_dimensions(&self.dimensions)?;
        if self.target_cells.is_empty() {
            if self
                .targets
                .iter()
                .any(|target| target.account == self.source)
            {
                return Err(invalid("a v1 target cannot be the source account"));
            }
            return Ok(());
        }
        if self.target_cells.len() != self.targets.len() || self.target_cells.len() > MAX_TARGETS {
            return Err(invalid("destination cells must match the ordered targets"));
        }
        let mut cells = BTreeSet::new();
        for (target, cell) in self.targets.iter().zip(&self.target_cells) {
            if target.account != cell.identity()? {
                return Err(invalid(
                    "target identity does not bind its destination cell",
                ));
            }
            if (cell.account == self.source && cell.dimensions == self.dimensions)
                || !cells.insert((cell.account, cell.dimensions.clone()))
            {
                return Err(invalid("duplicate or source destination cell"));
            }
        }
        Ok(())
    }

    /// Independent arithmetic. Public fields are checked again so a modified
    /// decoded value cannot invoke an unsupported law or a zero divisor.
    pub fn shares(&self) -> Result<Vec<i128>, AllocationError> {
        if self.total <= 0 || self.targets.is_empty() || self.targets.len() > MAX_TARGETS {
            return Err(invalid(
                "allocation total or target count is outside bounds",
            ));
        }
        let mut ids = BTreeSet::new();
        if self
            .targets
            .iter()
            .any(|target| !ids.insert(target.account))
        {
            return Err(invalid("duplicate or source target"));
        }
        self.validate_target_cells()?;
        if self.law == 2 {
            if !self.rounding.is_some_and(|law| (1..=9).contains(&law))
                || !self.recipient.is_some_and(|id| ids.contains(&id))
            {
                return Err(invalid("invalid pro-rata rounding or recipient"));
            }
        } else if self.rounding.is_some() || self.recipient.is_some() {
            return Err(invalid("only pro-rata names a rounding law and recipient"));
        }
        let total = u128::try_from(self.total).map_err(|_| AllocationError::Arithmetic)?;
        let mut shares = Vec::new();
        shares
            .try_reserve_exact(self.targets.len())
            .map_err(|_| AllocationError::InputLimit)?;
        match self.law {
            1 | 2 => {
                let denominator = self
                    .targets
                    .iter()
                    .try_fold(Wide::ZERO, |sum, target| sum.add(Wide::of(target.basis)))?;
                if denominator == Wide::ZERO {
                    return Err(invalid("weights sum to zero"));
                }
                let mut remainders = Vec::new();
                remainders
                    .try_reserve_exact(self.targets.len())
                    .map_err(|_| AllocationError::InputLimit)?;
                let mut sum = Wide::ZERO;
                for (index, target) in self.targets.iter().enumerate() {
                    let (q, r) = Wide::product(total, target.basis).div_rem(denominator)?;
                    let mut share = q.narrow()?;
                    if self.law == 2 {
                        let law = self.rounding.ok_or(invalid("missing rounding law"))?;
                        let half = r.cmp(&denominator.sub(r)?);
                        let increment = r != Wide::ZERO
                            && match law {
                                1 | 4 => half.is_ge(),
                                2 | 5 => half.is_gt(),
                                3 => half.is_gt() || (half.is_eq() && share % 2 == 1),
                                6 | 9 => true,
                                7 | 8 => false,
                                _ => return Err(invalid("unknown rounding law")),
                            };
                        share = share
                            .checked_add(u128::from(increment))
                            .ok_or(AllocationError::Arithmetic)?;
                    }
                    shares.push(i128::try_from(share).map_err(|_| AllocationError::Arithmetic)?);
                    sum = sum.add(Wide::of(share))?;
                    remainders.push((r, index));
                }
                if self.law == 1 {
                    let residual = Wide::of(total).sub(sum)?.narrow()?;
                    let count =
                        usize::try_from(residual).map_err(|_| AllocationError::Arithmetic)?;
                    if count >= shares.len() {
                        return Err(AllocationError::Arithmetic);
                    }
                    remainders.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
                    for (remainder, index) in remainders.into_iter().take(count) {
                        if remainder == Wide::ZERO {
                            return Err(AllocationError::Arithmetic);
                        }
                        shares[index] = shares[index]
                            .checked_add(1)
                            .ok_or(AllocationError::Arithmetic)?;
                    }
                } else {
                    let recipient = self
                        .targets
                        .iter()
                        .position(|target| Some(target.account) == self.recipient)
                        .ok_or(invalid("missing residual recipient"))?;
                    let negative = sum > Wide::of(total);
                    let residual = if negative {
                        sum.sub(Wide::of(total))?
                    } else {
                        Wide::of(total).sub(sum)?
                    };
                    let residual = i128::try_from(residual.narrow()?)
                        .map_err(|_| AllocationError::Arithmetic)?;
                    shares[recipient] = if negative {
                        shares[recipient].checked_sub(residual)
                    } else {
                        shares[recipient].checked_add(residual)
                    }
                    .ok_or(AllocationError::Arithmetic)?;
                }
            }
            3 => {
                let mut remaining = total;
                for target in &self.targets {
                    let share = remaining.min(target.basis);
                    remaining -= share;
                    shares.push(i128::try_from(share).map_err(|_| AllocationError::Arithmetic)?);
                }
                if remaining != 0 {
                    return Err(invalid("insufficient waterfall capacity"));
                }
            }
            5 => {
                if self.targets.iter().any(|target| target.basis != 1) {
                    return Err(invalid("equal split requires basis one"));
                }
                let count = self.targets.len() as u128;
                let ordinary = total / count;
                for i in 0..self.targets.len() {
                    let share = if i == 0 {
                        ordinary + total % count
                    } else {
                        ordinary
                    };
                    shares.push(i128::try_from(share).map_err(|_| AllocationError::Arithmetic)?);
                }
            }
            _ => return Err(invalid("unsupported allocation law")),
        }
        // Check signed conservation and the nonnegative gross posting total.
        // A representable signed total alone does not imply storable turnover.
        let mut positive = Wide::ZERO;
        let mut negative = Wide::ZERO;
        for share in &shares {
            let slot = if *share < 0 {
                &mut negative
            } else {
                &mut positive
            };
            *slot = slot.add(Wide::of(share.unsigned_abs()))?;
        }
        if positive.sub(negative)? != Wide::of(total) {
            return Err(AllocationError::Arithmetic);
        }
        i128::try_from(positive.narrow()?).map_err(|_| AllocationError::Arithmetic)?;
        Ok(shares)
    }
}

fn validate_dimensions(dimensions: &[(u32, u128)]) -> Result<(), AllocationError> {
    if dimensions.len() > 64 || dimensions.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(invalid("dimensions must be distinct and ascending"));
    }
    Ok(())
}

pub(super) fn read_dimensions(r: &mut Reader<'_>) -> Result<Vec<(u32, u128)>, AllocationError> {
    let count = r.count(64, 20, "allocation.dimensions")?;
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| AllocationError::InputLimit)?;
    let mut previous = None;
    for _ in 0..count {
        let dimension = r.u32("allocation.dimension")?;
        if previous.is_some_and(|last| last >= dimension) {
            return Err(invalid("dimensions must be distinct and ascending"));
        }
        values.push((dimension, r.u128("allocation.dimension_value")?));
        previous = Some(dimension);
    }
    Ok(values)
}

pub(super) fn debit(tag: u8) -> Result<bool, AllocationError> {
    match tag {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(invalid("unknown posting side")),
    }
}
fn invalid(why: &'static str) -> AllocationError {
    AllocationError::Invalid(why)
}
