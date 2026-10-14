//! Portable arithmetic receipts, not posting plans or signed evidence.
//!
//! The canonical request retains the law/version, signed native amount,
//! ordered stable target IDs, weights/caps and explicit rounding recipient.
//! A receipt adds every final share and the full pro-rata rounding transcript.
//! Replay compares *all* canonical bytes with a fresh computation of the
//! recipient's independent request. A changed allocation that preserves its
//! total is not accepted. No hash, stored total or publisher-supplied request
//! is treated as an authority. Unit-registry authenticity, document provenance,
//! account legality, approvals and journal publication are outside this scope.

use super::{
    AllocationCatalog, AllocationError, AllocationLaw, AllocationMethod, AllocationOutcome,
    AllocationRequest, AllocationTarget, MAX_ALLOCATION_TARGETS,
};
use crate::{Amount, AmountError, RoundingLaw, UnitId};

const REQUEST_MAGIC: &[u8; 17] = b"FA-ALLOC-REQUEST\0";
const RECEIPT_MAGIC: &[u8; 17] = b"FA-ALLOC-RECEIPT\0";
const VERSION: [u8; 4] = [1, 0, 0, 0]; // u16 major 1, u16 minor 0
pub const MAX_ALLOCATION_REQUEST_BYTES: usize = 128 + 32 * MAX_ALLOCATION_TARGETS;
pub const MAX_ALLOCATION_RECEIPT_BYTES: usize = MAX_ALLOCATION_REQUEST_BYTES
    + 32 * MAX_ALLOCATION_TARGETS + 128;

impl AllocationRequest {
    /// Structural encoding. A structurally valid request can still fail
    /// execution (for example, zero total weight or insufficient capacity).
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, AllocationError> {
        self.validate_shape(&AllocationCatalog::embedded()?)?;
        let mut bytes = reserved(128 + 32 * self.targets.len())?;
        bytes.extend_from_slice(REQUEST_MAGIC);
        bytes.extend_from_slice(&VERSION);
        bytes.extend_from_slice(&self.method.law().id().to_le_bytes());
        bytes.extend_from_slice(&self.method.law().version().to_le_bytes());
        bytes.extend_from_slice(&self.total.unit.0.to_le_bytes());
        bytes.extend_from_slice(&self.total.mantissa.to_le_bytes());
        if let AllocationMethod::ProRataResidualToNamed { rounding, recipient } = self.method {
            bytes.extend_from_slice(&rounding.id().to_le_bytes());
            bytes.extend_from_slice(&recipient.to_le_bytes());
        }
        write_count(&mut bytes, self.targets.len())?;
        for target in &self.targets {
            bytes.extend_from_slice(&target.id.to_le_bytes());
            bytes.extend_from_slice(&target.basis.to_le_bytes());
        }
        bounded(&bytes, MAX_ALLOCATION_REQUEST_BYTES)?;
        Ok(bytes)
    }

    /// Decode under both the byte limit and the current catalog target bound.
    /// Count and exact remaining byte length are checked before allocation.
    /// No future law/version, surplus parameter or trailing byte is skipped.
    pub fn decode(bytes: &[u8]) -> Result<Self, AllocationError> {
        bounded(bytes, MAX_ALLOCATION_REQUEST_BYTES)?;
        let catalog = AllocationCatalog::embedded()?;
        let mut r = Reader { bytes, offset: 0 };
        if r.take::<17>("request magic")? != *REQUEST_MAGIC
            || r.take::<4>("request version")? != VERSION
        {
            return Err(AllocationError::Invalid("unsupported allocation request format"));
        }
        let law = AllocationLaw::from_id(u16::from_le_bytes(r.take("law id")?))
            .ok_or(AllocationError::Invalid("unsupported allocation law"))?;
        if u16::from_le_bytes(r.take("law version")?) != law.version() {
            return Err(AllocationError::Invalid("unsupported allocation law version"));
        }
        let unit = UnitId(u32::from_le_bytes(r.take("unit id")?));
        let mantissa = i128::from_le_bytes(r.take("total mantissa")?);
        let method = match law {
            AllocationLaw::LargestRemainder => AllocationMethod::LargestRemainder,
            AllocationLaw::Waterfall => AllocationMethod::Waterfall,
            AllocationLaw::EqualSplitResidualFirst => AllocationMethod::EqualSplitResidualFirst,
            AllocationLaw::ProRataResidualToNamed => AllocationMethod::ProRataResidualToNamed {
                rounding: RoundingLaw::from_id(u16::from_le_bytes(r.take("rounding law")?))
                    .ok_or(AllocationError::Invalid("unsupported rounding law"))?,
                recipient: u128::from_le_bytes(r.take("residual recipient")?),
            },
        };
        let count = usize::try_from(u32::from_le_bytes(r.take("target count")?))
            .map_err(|_| AllocationError::Invalid("target count is unrepresentable"))?;
        if count == 0 || count > catalog.max_targets()
            || count.checked_mul(32) != Some(r.bytes.len() - r.offset)
        {
            return Err(AllocationError::Invalid("target count or request length is invalid"));
        }
        let mut targets = Vec::new();
        targets.try_reserve_exact(count).map_err(|_| AmountError::Overflow)?;
        for _ in 0..count {
            targets.push(AllocationTarget {
                id: u128::from_le_bytes(r.take("target id")?),
                basis: u128::from_le_bytes(r.take("target basis")?),
            });
        }
        let request = Self { total: Amount::new(unit, mantissa), method, targets };
        request.validate_shape(&catalog)?;
        Ok(request)
    }
}

impl AllocationOutcome {
    /// Receipt format v1: magic, version, length-prefixed canonical request,
    /// count + signed final mantissas, then a pro-rata presence byte. If present:
    /// count + signed independently rounded mantissas + signed residual.
    /// Unit and residual target are inherited from, and fixed by, the request.
    pub fn receipt_bytes(&self) -> Result<Vec<u8>, AllocationError> {
        self.verify_for(self.request())?;
        encode_receipt(self)
    }

    /// Verify a transported receipt against the recipient's independently
    /// selected request. Deliberately no "decode and trust its own request"
    /// convenience method: that would permit a valid but substituted basis.
    /// Computation depends only on `expected`, never on untrusted counts.
    pub fn replay_receipt_for(
        bytes: &[u8],
        expected: &AllocationRequest,
    ) -> Result<Self, AllocationError> {
        bounded(bytes, MAX_ALLOCATION_RECEIPT_BYTES)?;
        if !bytes.starts_with(RECEIPT_MAGIC) {
            return Err(AllocationError::Invalid("wrong allocation receipt magic"));
        }
        let replayed = expected.execute()?;
        if encode_receipt(&replayed)?.as_slice() != bytes {
            return Err(AllocationError::Mismatch);
        }
        Ok(replayed)
    }
}

fn encode_receipt(outcome: &AllocationOutcome) -> Result<Vec<u8>, AllocationError> {
    let request = outcome.request().canonical_bytes()?;
    // All vectors originate from an execution bounded to 4096 targets. The
    // checked length also bounds the output buffer before any write occurs.
    let capacity = request.len().checked_add(128)
        .and_then(|size| outcome.shares().len().checked_mul(32).and_then(|n| size.checked_add(n)))
        .filter(|size| *size <= MAX_ALLOCATION_RECEIPT_BYTES)
        .ok_or(AllocationError::Invalid("allocation receipt exceeds its byte bound"))?;
    let mut bytes = reserved(capacity)?;
    bytes.extend_from_slice(RECEIPT_MAGIC);
    bytes.extend_from_slice(&VERSION);
    write_count(&mut bytes, request.len())?;
    bytes.extend_from_slice(&request);
    write_count(&mut bytes, outcome.shares().len())?;
    for share in outcome.shares() {
        bytes.extend_from_slice(&share.mantissa.to_le_bytes());
    }
    match outcome.pro_rata() {
        None => bytes.push(0),
        Some(transcript) => {
            bytes.push(1);
            write_count(&mut bytes, transcript.rounded_shares.len())?;
            for share in &transcript.rounded_shares {
                bytes.extend_from_slice(&share.mantissa.to_le_bytes());
            }
            bytes.extend_from_slice(&transcript.residual.mantissa.to_le_bytes());
        }
    }
    bounded(&bytes, MAX_ALLOCATION_RECEIPT_BYTES)?;
    Ok(bytes)
}

fn reserved(capacity: usize) -> Result<Vec<u8>, AllocationError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity).map_err(|_| AmountError::Overflow)?;
    Ok(bytes)
}

fn write_count(bytes: &mut Vec<u8>, count: usize) -> Result<(), AllocationError> {
    let count = u32::try_from(count).map_err(|_| AllocationError::Invalid("count exceeds u32"))?;
    bytes.extend_from_slice(&count.to_le_bytes());
    Ok(())
}

fn bounded(bytes: &[u8], max: usize) -> Result<(), AllocationError> {
    if bytes.len() > max {
        return Err(AllocationError::Invalid("allocation artifact exceeds its byte bound"));
    }
    Ok(())
}

struct Reader<'a> { bytes: &'a [u8], offset: usize }
impl Reader<'_> {
    fn take<const N: usize>(&mut self, field: &'static str) -> Result<[u8; N], AllocationError> {
        let end = self.offset.checked_add(N)
            .ok_or(AllocationError::Decode { field, offset: self.offset })?;
        let value = self.bytes.get(self.offset..end)
            .and_then(|slice| <[u8; N]>::try_from(slice).ok())
            .ok_or(AllocationError::Decode { field, offset: self.offset })?;
        self.offset = end;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
