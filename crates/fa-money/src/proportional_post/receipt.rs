//! Bounded canonical arithmetic requests and complete rounding receipts.
//! Replay accepts only the recipient's independently selected pending basis;
//! a receipt never authenticates its own source entry or grants authority.

use super::{
    HeldLeg, MAX_PROPORTIONAL_POST_LEGS, ProportionalPostCatalog, ProportionalPostError,
    ProportionalPostLaw, ProportionalPostOutcome, ProportionalPostRequest,
};
use crate::rate::{BudgetMeter, Dimension};
use crate::{Amount, AmountError, ArithmeticBudget, Rate, Side, UnitId};

const REQUEST_MAGIC: &[u8] = b"fa:proportional-post-request:v1\0";
const RECEIPT_MAGIC: &[u8] = b"fa:proportional-post-receipt:v1\0";
pub const MAX_PROPORTIONAL_POST_RATE_BYTES: usize = 8192;
pub const MAX_PROPORTIONAL_POST_REQUEST_BYTES: usize =
    128 + MAX_PROPORTIONAL_POST_RATE_BYTES + 40 * MAX_PROPORTIONAL_POST_LEGS;
pub const MAX_PROPORTIONAL_POST_RECEIPT_BYTES: usize =
    MAX_PROPORTIONAL_POST_REQUEST_BYTES + 128 + 136 * MAX_PROPORTIONAL_POST_LEGS;

impl ProportionalPostRequest {
    /// v1: magic, u16 law/id version, a length-prefixed canonical FAR rate,
    /// u32 leg count, then original ordinal u16, unit u32, side u8,
    /// entity-presence u8 [+u128], and positive reserved mantissa i128.
    pub fn canonical_bytes(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Result<Vec<u8>, ProportionalPostError> {
        self.validate_shape(budget, &ProportionalPostCatalog::embedded()?)?;
        let rate = self.rate.encode(budget)?;
        let mut size = REQUEST_MAGIC
            .len()
            .checked_add(12)
            .and_then(|n| n.checked_add(rate.len()))
            .ok_or(AmountError::Overflow)?;
        for leg in &self.legs {
            size = size
                .checked_add(if leg.legal_entity.is_some() { 40 } else { 24 })
                .ok_or(AmountError::Overflow)?;
        }
        let mut bytes = reserved(budget, size, MAX_PROPORTIONAL_POST_REQUEST_BYTES)?;
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&self.law.id().to_le_bytes());
        bytes.extend_from_slice(&self.law.version().to_le_bytes());
        count(&mut bytes, rate.len())?;
        bytes.extend_from_slice(&rate);
        count(&mut bytes, self.legs.len())?;
        for leg in &self.legs {
            bytes.extend_from_slice(&leg.source_ordinal.to_le_bytes());
            bytes.extend_from_slice(&leg.amount.unit.0.to_le_bytes());
            bytes.push(match leg.side {
                Side::Debit => 0,
                Side::Credit => 1,
            });
            entity(&mut bytes, leg.legal_entity);
            bytes.extend_from_slice(&leg.amount.mantissa.to_le_bytes());
        }
        if bytes.len() != size {
            return Err(ProportionalPostError::Invalid(
                "request size differs from its canonical encoding",
            ));
        }
        budget.checkpoint()?;
        Ok(bytes)
    }

    pub fn decode(
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        bytes: &[u8],
    ) -> Result<Self, ProportionalPostError> {
        bounded(bytes.len(), MAX_PROPORTIONAL_POST_REQUEST_BYTES)?;
        budget.charge(
            Dimension::ComputeSteps,
            u64::try_from(bytes.len()).map_err(|_| AmountError::Overflow)?,
        )?;
        let mut r = Reader { bytes, offset: 0 };
        if r.slice(REQUEST_MAGIC.len())? != REQUEST_MAGIC {
            return Err(ProportionalPostError::Invalid(
                "unsupported proportional post request format",
            ));
        }
        let law = ProportionalPostLaw::from_id(u16::from_le_bytes(r.take()?)).ok_or(
            ProportionalPostError::Invalid("unsupported proportional post law"),
        )?;
        if u16::from_le_bytes(r.take()?) != law.version() {
            return Err(ProportionalPostError::Invalid(
                "unsupported proportional post law version",
            ));
        }
        let rate_len =
            usize::try_from(u32::from_le_bytes(r.take()?)).map_err(|_| AmountError::Overflow)?;
        bounded(rate_len, MAX_PROPORTIONAL_POST_RATE_BYTES)?;
        let rate = Rate::decode(budget, r.slice(rate_len)?)?;
        let count =
            usize::try_from(u32::from_le_bytes(r.take()?)).map_err(|_| AmountError::Overflow)?;
        let catalog = ProportionalPostCatalog::embedded()?;
        if !(2..=catalog.max_legs()).contains(&count)
            || count.checked_mul(24).is_none_or(|n| n > r.remaining())
        {
            return Err(ProportionalPostError::Invalid(
                "invalid proportional post leg count or truncated body",
            ));
        }
        budget.reserve(
            u64::try_from(count)
                .map_err(|_| AmountError::Overflow)?
                .checked_mul(64)
                .ok_or(AmountError::Overflow)?,
            1,
        )?;
        let mut legs = Vec::new();
        legs.try_reserve_exact(count)
            .map_err(|_| AmountError::Overflow)?;
        for _ in 0..count {
            let source_ordinal = u16::from_le_bytes(r.take()?);
            let unit = UnitId(u32::from_le_bytes(r.take()?));
            let side = match r.take::<1>()?[0] {
                0 => Side::Debit,
                1 => Side::Credit,
                _ => {
                    return Err(ProportionalPostError::Invalid(
                        "invalid proportional post side tag",
                    ));
                }
            };
            let legal_entity = match r.take::<1>()?[0] {
                0 => None,
                1 => Some(u128::from_le_bytes(r.take()?)),
                _ => {
                    return Err(ProportionalPostError::Invalid(
                        "invalid proportional post entity tag",
                    ));
                }
            };
            legs.push(HeldLeg {
                source_ordinal,
                amount: Amount::new(unit, i128::from_le_bytes(r.take()?)),
                side,
                legal_entity,
            });
        }
        if r.remaining() != 0 {
            return Err(ProportionalPostError::Invalid(
                "trailing proportional post request bytes",
            ));
        }
        let request = Self { law, rate, legs };
        request.validate_shape(budget, &catalog)?;
        if request.canonical_bytes(budget)?.as_slice() != bytes {
            return Err(ProportionalPostError::Invalid(
                "noncanonical proportional post request",
            ));
        }
        Ok(request)
    }
}

impl ProportionalPostOutcome {
    /// Includes the full original basis and every zero/nonzero result. Each
    /// result names its original ordinal, floor, exact remainder numerator,
    /// one-unit rounding increment, posted amount and released remainder.
    /// Partition rows then bind the common held/posted/released totals.
    pub fn receipt_bytes(
        &self,
        budget: &mut ArithmeticBudget<'_, impl Sized>,
    ) -> Result<Vec<u8>, ProportionalPostError> {
        let request = self.request.canonical_bytes(budget)?;
        let mut size = RECEIPT_MAGIC
            .len()
            .checked_add(12)
            .and_then(|n| n.checked_add(request.len()))
            .and_then(|n| {
                self.legs
                    .len()
                    .checked_mul(67)
                    .and_then(|rows| n.checked_add(rows))
            })
            .ok_or(AmountError::Overflow)?;
        for partition in &self.partitions {
            size = size
                .checked_add(if partition.legal_entity.is_some() {
                    69
                } else {
                    53
                })
                .ok_or(AmountError::Overflow)?;
        }
        let mut bytes = reserved(budget, size, MAX_PROPORTIONAL_POST_RECEIPT_BYTES)?;
        bytes.extend_from_slice(RECEIPT_MAGIC);
        count(&mut bytes, request.len())?;
        bytes.extend_from_slice(&request);
        count(&mut bytes, self.legs.len())?;
        for leg in &self.legs {
            bytes.extend_from_slice(&leg.source_ordinal.to_le_bytes());
            bytes.extend_from_slice(&leg.floor.mantissa.to_le_bytes());
            bytes.extend_from_slice(&leg.remainder_numerator.to_le_bytes());
            bytes.push(leg.rounding_increment);
            bytes.extend_from_slice(&leg.posted.mantissa.to_le_bytes());
            bytes.extend_from_slice(&leg.released.mantissa.to_le_bytes());
        }
        count(&mut bytes, self.partitions.len())?;
        for partition in &self.partitions {
            bytes.extend_from_slice(&partition.unit.0.to_le_bytes());
            entity(&mut bytes, partition.legal_entity);
            bytes.extend_from_slice(&partition.held.to_le_bytes());
            bytes.extend_from_slice(&partition.posted.to_le_bytes());
            bytes.extend_from_slice(&partition.released.to_le_bytes());
        }
        if bytes.len() != size {
            return Err(ProportionalPostError::Invalid(
                "receipt size differs from its canonical encoding",
            ));
        }
        budget.checkpoint()?;
        Ok(bytes)
    }

    /// Untrusted transported counts never control allocation. Compute the
    /// recipient's own request and compare all bytes, including the rounding
    /// transcript, capacities, rate and source-ordinal mapping.
    pub fn replay_receipt_for(
        budget: &mut ArithmeticBudget<'_, impl Sized>,
        bytes: &[u8],
        expected: &ProportionalPostRequest,
    ) -> Result<Self, ProportionalPostError> {
        bounded(bytes.len(), MAX_PROPORTIONAL_POST_RECEIPT_BYTES)?;
        budget.checkpoint()?;
        if !bytes.starts_with(RECEIPT_MAGIC) {
            return Err(ProportionalPostError::Invalid(
                "unsupported proportional post receipt format",
            ));
        }
        let replayed = expected.execute(budget)?;
        if replayed.receipt_bytes(budget)?.as_slice() != bytes {
            return Err(ProportionalPostError::Mismatch);
        }
        Ok(replayed)
    }
}

fn entity(bytes: &mut Vec<u8>, value: Option<u128>) {
    match value {
        None => bytes.push(0),
        Some(value) => {
            bytes.push(1);
            bytes.extend_from_slice(&value.to_le_bytes());
        }
    }
}

fn count(bytes: &mut Vec<u8>, value: usize) -> Result<(), ProportionalPostError> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| AmountError::Overflow)?
            .to_le_bytes(),
    );
    Ok(())
}

fn bounded(size: usize, limit: usize) -> Result<(), ProportionalPostError> {
    if size > limit {
        Err(ProportionalPostError::Invalid(
            "proportional post artifact exceeds its byte bound",
        ))
    } else {
        Ok(())
    }
}

fn reserved(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    size: usize,
    limit: usize,
) -> Result<Vec<u8>, ProportionalPostError> {
    bounded(size, limit)?;
    budget.reserve(u64::try_from(size).map_err(|_| AmountError::Overflow)?, 1)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| AmountError::Overflow)?;
    Ok(bytes)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn slice(&mut self, count: usize) -> Result<&'a [u8], ProportionalPostError> {
        let end = self
            .offset
            .checked_add(count)
            .ok_or(AmountError::Overflow)?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProportionalPostError::Invalid(
                "truncated proportional post artifact",
            ))?;
        self.offset = end;
        Ok(bytes)
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProportionalPostError> {
        self.slice(N)?
            .try_into()
            .map_err(|_| ProportionalPostError::Invalid("truncated proportional post field"))
    }
    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
}
