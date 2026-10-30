//! Source-bound finite straight-line depreciation and amortization.
//!
//! A schedule's acquisition reference identifies its original cost. Neither
//! the schedule nor a charge basis accepts a caller-supplied cost, cumulative
//! amount or current carrying balance. Native admission derives those terms
//! from the immutable acquisition, schedule and prior charge history.

use fa_money::{Amount, RoundingLaw, UnitId};
use fgdb_types::{CommitSeq, VId};

use crate::{DecodeError, EncodeError, EntryRef, PeriodRef, Reader, Writer};

pub const ASSET_SCHEDULE: u16 = 22;
pub const SCHEMA_CHANGE_ASSET_SCHEDULE: u16 = ASSET_SCHEDULE;
pub const ASSET_SCHEDULE_FORMAT: &[u8] = b"fa:asset-schedule:v1";
pub const ASSET_CHARGE_FORMAT: &[u8] = b"fa:asset-charge:v1";
pub const MAX_ASSET_SCHEDULE_NAME: usize = 128;
pub const MAX_ASSET_LIFE_PERIODS: u32 = 1200;
pub const MAX_ASSET_SCHEDULE_BYTES: usize = 512;
pub const MAX_ASSET_CHARGE_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssetCostKind {
    Depreciation,
    Amortization,
}

impl AssetCostKind {
    pub const ALL: [Self; 2] = [Self::Depreciation, Self::Amortization];

    pub const fn id(self) -> u8 {
        match self {
            Self::Depreciation => 1,
            Self::Amortization => 2,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.id() == id)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Depreciation => "Depreciation",
            Self::Amortization => "Amortization",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|kind| kind.name().eq_ignore_ascii_case(name))
    }
}

/// An immutable registration, with one original acquisition debit as its
/// source. The kernel restricts version 1 to monthly fiscal periods, native
/// base-currency acquisitions and supported account/dimension shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetScheduleSpec {
    pub name: String,
    pub kind: AssetCostKind,
    pub acquisition: EntryRef,
    pub acquisition_ordinal: u16,
    pub first_period: PeriodRef,
    pub useful_life_periods: u32,
    pub salvage: Amount,
    pub expense_account: VId,
    pub accumulated_account: VId,
    pub rounding_law: RoundingLaw,
}

/// Selectors sufficient to reproduce one cumulative charge. The source
/// schedule, selected period, prior effects and exact posting legs are
/// checked again by native admission before the entry can publish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AssetChargeBasis {
    pub schedule: EntryRef,
    pub through_period: PeriodRef,
    pub known_at: CommitSeq,
}

fn read_entry(r: &mut Reader<'_>) -> Result<EntryRef, DecodeError> {
    Ok(EntryRef {
        vid: VId(r.u128("asset.entry.vid")?),
        entry_digest: r.fixed("asset.entry.digest")?,
    })
}

fn valid_period(period: &PeriodRef) -> bool {
    !period.calendar.is_empty() && !period.code.is_empty() && period.within_bounds()
}

impl AssetScheduleSpec {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.bytes(ASSET_SCHEDULE_FORMAT)
            .str(&self.name)
            .u8(self.kind.id())
            .u128(self.acquisition.vid.0)
            .fixed(&self.acquisition.entry_digest)
            .u16(self.acquisition_ordinal);
        self.first_period.encode(&mut w);
        w.u32(self.useful_life_periods)
            .u32(self.salvage.unit.0)
            .i128(self.salvage.mantissa)
            .u128(self.expense_account.0)
            .u128(self.accumulated_account.0)
            .u16(self.rounding_law.id())
            .u16(1);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if bytes.len() > MAX_ASSET_SCHEDULE_BYTES
            || r.bytes(64, "asset_schedule.format")? != ASSET_SCHEDULE_FORMAT
        {
            return Err(r.invalid("asset_schedule.format"));
        }
        let name = r
            .str(MAX_ASSET_SCHEDULE_NAME, "asset_schedule.name")?
            .to_string();
        let kind = AssetCostKind::from_id(r.u8("asset_schedule.kind")?)
            .ok_or_else(|| r.invalid("asset_schedule.kind"))?;
        let acquisition = read_entry(&mut r)?;
        let acquisition_ordinal = r.u16("asset_schedule.acquisition_ordinal")?;
        let first_period = PeriodRef::decode(&mut r)?;
        let useful_life_periods = r.u32("asset_schedule.useful_life_periods")?;
        let salvage = Amount::new(
            UnitId(r.u32("asset_schedule.salvage.unit")?),
            r.i128("asset_schedule.salvage.mantissa")?,
        );
        let expense_account = VId(r.u128("asset_schedule.expense_account")?);
        let accumulated_account = VId(r.u128("asset_schedule.accumulated_account")?);
        let rounding_law = RoundingLaw::from_id(r.u16("asset_schedule.rounding_law")?)
            .ok_or_else(|| r.invalid("asset_schedule.rounding_law"))?;
        if r.u16("asset_schedule.rounding_version")? != 1 {
            return Err(r.invalid("asset_schedule.rounding_version"));
        }
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || usize::from(acquisition_ordinal) >= crate::limits::MAX_LEGS_PER_ENTRY
            || !valid_period(&first_period)
            || !(1..=MAX_ASSET_LIFE_PERIODS).contains(&useful_life_periods)
            || salvage.mantissa < 0
            || expense_account == accumulated_account
        {
            return Err(r.invalid("asset_schedule.inputs"));
        }
        r.finish()?;
        Ok(Self {
            name,
            kind,
            acquisition,
            acquisition_ordinal,
            first_period,
            useful_life_periods,
            salvage,
            expense_account,
            accumulated_account,
            rounding_law,
        })
    }
}

impl AssetChargeBasis {
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.bytes(ASSET_CHARGE_FORMAT)
            .u128(self.schedule.vid.0)
            .fixed(&self.schedule.entry_digest);
        self.through_period.encode(&mut w);
        w.u64(self.known_at.0);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if bytes.len() > MAX_ASSET_CHARGE_BYTES
            || r.bytes(64, "asset_charge.format")? != ASSET_CHARGE_FORMAT
        {
            return Err(r.invalid("asset_charge.format"));
        }
        let schedule = read_entry(&mut r)?;
        let through_period = PeriodRef::decode(&mut r)?;
        let known_at = CommitSeq(r.u64("asset_charge.known_at")?);
        if !valid_period(&through_period) || known_at.0 == 0 {
            return Err(r.invalid("asset_charge.coordinate"));
        }
        r.finish()?;
        Ok(Self {
            schedule,
            through_period,
            known_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn schedule() -> AssetScheduleSpec {
        AssetScheduleSpec {
            name: "machine-2026.1".into(),
            kind: AssetCostKind::Depreciation,
            acquisition: EntryRef {
                vid: VId(17),
                entry_digest: [7; 32],
            },
            acquisition_ordinal: 0,
            first_period: PeriodRef {
                calendar: "monthly".into(),
                code: "FY2026-P01".into(),
            },
            useful_life_periods: 36,
            salvage: Amount::new(UnitId(1), 500),
            expense_account: VId(18),
            accumulated_account: VId(19),
            rounding_law: RoundingLaw::HalfEven,
        }
    }

    fn basis() -> AssetChargeBasis {
        AssetChargeBasis {
            schedule: EntryRef {
                vid: VId(21),
                entry_digest: [8; 32],
            },
            through_period: PeriodRef {
                calendar: "monthly".into(),
                code: "FY2026-P03".into(),
            },
            known_at: CommitSeq(29),
        }
    }

    #[test]
    fn schedules_round_trip_every_kind_and_rounding_law() {
        for kind in AssetCostKind::ALL {
            assert_eq!(AssetCostKind::from_name(kind.name()), Some(kind));
            assert_eq!(
                AssetCostKind::from_name(&kind.name().to_ascii_lowercase()),
                Some(kind)
            );
            for rounding_law in RoundingLaw::ALL {
                let value = AssetScheduleSpec {
                    kind,
                    rounding_law,
                    ..schedule()
                };
                assert_eq!(
                    AssetScheduleSpec::decode(&value.encode().unwrap()).unwrap(),
                    value
                );
            }
        }
        assert_eq!(AssetCostKind::from_name("Impairment"), None);
        assert_eq!(AssetCostKind::from_id(0), None);
        assert_eq!(AssetCostKind::from_id(3), None);
    }

    #[test]
    fn schedule_and_charge_reject_truncation_trailing_bytes_and_unknown_versions() {
        let schedule_bytes = schedule().encode().unwrap();
        let charge_bytes = basis().encode().unwrap();
        assert_eq!(AssetChargeBasis::decode(&charge_bytes).unwrap(), basis());
        for end in 0..schedule_bytes.len() {
            assert!(AssetScheduleSpec::decode(&schedule_bytes[..end]).is_err());
        }
        for end in 0..charge_bytes.len() {
            assert!(AssetChargeBasis::decode(&charge_bytes[..end]).is_err());
        }
        let mut trailing = schedule_bytes.clone();
        trailing.push(0);
        assert!(AssetScheduleSpec::decode(&trailing).is_err());
        trailing = charge_bytes.clone();
        trailing.push(0);
        assert!(AssetChargeBasis::decode(&trailing).is_err());
        let mut future = schedule_bytes;
        future[4 + ASSET_SCHEDULE_FORMAT.len() - 1] = b'2';
        assert!(AssetScheduleSpec::decode(&future).is_err());
        future = charge_bytes;
        future[4 + ASSET_CHARGE_FORMAT.len() - 1] = b'2';
        assert!(AssetChargeBasis::decode(&future).is_err());
        future = schedule().encode().unwrap();
        *future.last_mut().unwrap() = 1;
        assert!(AssetScheduleSpec::decode(&future).is_err());
    }

    #[test]
    fn schedule_refuses_invalid_source_coordinates_life_names_and_routes() {
        for name in [
            "".into(),
            "has space".into(),
            "has\nnewline".into(),
            "x".repeat(129),
        ] {
            let value = AssetScheduleSpec { name, ..schedule() };
            assert!(AssetScheduleSpec::decode(&value.encode().unwrap()).is_err());
        }
        for useful_life_periods in [0, MAX_ASSET_LIFE_PERIODS + 1, u32::MAX] {
            let value = AssetScheduleSpec {
                useful_life_periods,
                ..schedule()
            };
            assert!(AssetScheduleSpec::decode(&value.encode().unwrap()).is_err());
        }
        let mut value = schedule();
        value.salvage.mantissa = -1;
        assert!(AssetScheduleSpec::decode(&value.encode().unwrap()).is_err());
        value = schedule();
        value.acquisition_ordinal = u16::MAX;
        assert!(AssetScheduleSpec::decode(&value.encode().unwrap()).is_err());
        value = schedule();
        value.accumulated_account = value.expense_account;
        assert!(AssetScheduleSpec::decode(&value.encode().unwrap()).is_err());
        value = schedule();
        value.first_period.calendar.clear();
        assert!(AssetScheduleSpec::decode(&value.encode().unwrap()).is_err());
        value = schedule();
        value.first_period.code = "x".repeat(crate::limits::MAX_PERIOD_REF_BYTES + 1);
        assert!(AssetScheduleSpec::decode(&value.encode().unwrap()).is_err());
    }

    #[test]
    fn charge_binds_both_identities_and_the_historical_coordinate() {
        let original = basis();
        let bytes = original.encode().unwrap();
        let mut variants = vec![original.clone(); 5];
        variants[0].schedule.vid = VId(22);
        variants[1].schedule.entry_digest[0] = 9;
        variants[2].through_period.calendar = "another".into();
        variants[3].through_period.code = "FY2026-P04".into();
        variants[4].known_at = CommitSeq(30);
        for value in variants {
            assert_ne!(value.encode().unwrap(), bytes);
            assert_eq!(
                AssetChargeBasis::decode(&value.encode().unwrap()).unwrap(),
                value
            );
        }
        let mut bad = original;
        bad.known_at = CommitSeq(0);
        assert!(AssetChargeBasis::decode(&bad.encode().unwrap()).is_err());
        bad = basis();
        bad.through_period.code.clear();
        assert!(AssetChargeBasis::decode(&bad.encode().unwrap()).is_err());
    }
}
