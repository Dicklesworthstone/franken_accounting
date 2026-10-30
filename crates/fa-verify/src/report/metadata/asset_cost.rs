//! Bounded transport of native asset schedules and charge provenance.
//!
//! These controls change neither account metadata nor period boundaries.
//! Ordinary reports fold their authenticated monetary effects; this module
//! does not claim independent reproduction of native asset-law admission.

use super::{Reader, ReportError, failed, text};

pub(super) fn schedule(bytes: &[u8]) -> Result<(), ReportError> {
    let mut r = Reader::new(bytes);
    if bytes.len() > 512 || r.bytes(64, "asset_schedule.format")? != b"fa:asset-schedule:v1" {
        return Err(failed(
            "schema_history",
            "unsupported asset schedule format",
        ));
    }
    let name = text(&mut r, 128, "asset_schedule.name")?;
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || !matches!(r.u8("asset_schedule.kind")?, 1 | 2)
    {
        return Err(failed(
            "schema_history",
            "invalid asset schedule name or kind",
        ));
    }
    r.u128("asset_schedule.acquisition")?;
    r.fixed::<32>("asset_schedule.acquisition_digest")?;
    if r.u16("asset_schedule.acquisition_ordinal")? >= 4096 {
        return Err(failed(
            "schema_history",
            "asset acquisition ordinal is out of bounds",
        ));
    }
    period(&mut r)?;
    if !(1..=1200).contains(&r.u32("asset_schedule.useful_life_periods")?) {
        return Err(failed("schema_history", "unsupported finite asset life"));
    }
    r.u32("asset_schedule.salvage_unit")?;
    if r.i128("asset_schedule.salvage")? < 0 {
        return Err(failed(
            "schema_history",
            "asset salvage must be nonnegative",
        ));
    }
    let expense = r.u128("asset_schedule.expense")?;
    let accumulated = r.u128("asset_schedule.accumulated")?;
    if expense == accumulated
        || !(1..=9).contains(&r.u16("asset_schedule.rounding_law")?)
        || r.u16("asset_schedule.rounding_version")? != 1
    {
        return Err(failed(
            "schema_history",
            "invalid asset routes or rounding law",
        ));
    }
    r.finish("asset schedule")?;
    Ok(())
}

pub(super) fn charge(bytes: &[u8], minor: u16, class: u16) -> Result<(), ReportError> {
    let mut r = Reader::new(bytes);
    if minor < 6
        || !matches!(class, 4 | 7)
        || bytes.len() > 256
        || r.bytes(64, "asset_charge.format")? != b"fa:asset-charge:v1"
    {
        return Err(failed(
            "entry_identity",
            "unsupported native asset charge basis",
        ));
    }
    r.u128("asset_charge.schedule")?;
    r.fixed::<32>("asset_charge.schedule_digest")?;
    period(&mut r)?;
    if r.u64("asset_charge.known_at")? == 0 {
        return Err(failed(
            "entry_identity",
            "asset charge has no observed prefix",
        ));
    }
    r.finish("asset charge")?;
    Ok(())
}

fn period(r: &mut Reader<'_>) -> Result<(), ReportError> {
    if text(r, 32, "asset.period.calendar")?.is_empty()
        || text(r, 32, "asset.period.code")?.is_empty()
    {
        return Err(failed(
            "schema_history",
            "asset period must name calendar and code",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::Writer;

    fn declared_schedule(kind: u8, life: u32, salvage: i128) -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(b"fa:asset-schedule:v1")
            .bytes(b"asset-1")
            .u8(kind)
            .u128(17)
            .fixed(&[5; 32])
            .u16(0)
            .bytes(b"monthly")
            .bytes(b"FY2026-P01")
            .u32(life)
            .u32(1)
            .i128(salvage)
            .u128(18)
            .u128(19)
            .u16(3)
            .u16(1);
        w.buf
    }

    fn charge_basis() -> Vec<u8> {
        let mut w = Writer::default();
        w.bytes(b"fa:asset-charge:v1")
            .u128(23)
            .fixed(&[6; 32])
            .bytes(b"monthly")
            .bytes(b"FY2026-P03")
            .u64(29);
        w.buf
    }

    #[test]
    fn asset_schedule_transport_accepts_known_bounds_without_claiming_source_admission() {
        for kind in [1, 2] {
            for life in [1, 1200] {
                schedule(&declared_schedule(kind, life, 0)).unwrap();
            }
        }
        for (kind, life, salvage) in [(0, 12, 0), (3, 12, 0), (1, 0, 0), (1, 1201, 0), (1, 12, -1)]
        {
            assert!(schedule(&declared_schedule(kind, life, salvage)).is_err());
        }
        let valid = declared_schedule(1, 12, 100);
        for end in 0..valid.len() {
            assert!(schedule(&valid[..end]).is_err());
        }
        let mut trailing = valid;
        trailing.push(0);
        assert!(schedule(&trailing).is_err());
        assert!(schedule(&vec![0; 513]).is_err());
    }

    #[test]
    fn asset_charge_transport_is_versioned_and_limited_to_adjusting_and_exact_reversal() {
        let valid = charge_basis();
        charge(&valid, 6, 7).unwrap();
        charge(&valid, 6, 4).unwrap();
        assert!(charge(&valid, 5, 7).is_err());
        assert!(charge(&valid, 6, 1).is_err());
        for end in 0..valid.len() {
            assert!(charge(&valid[..end], 6, 7).is_err());
        }
        let mut zero = valid.clone();
        let end = zero.len();
        zero[end - 8..].fill(0);
        assert!(charge(&zero, 6, 7).is_err());
        let mut trailing = valid;
        trailing.push(0);
        assert!(charge(&trailing, 6, 7).is_err());
    }
}
