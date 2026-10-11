//! Units: currencies, commodities, shares, time, counts — each with an
//! **immutable** scale (plan §4.4). A precision change is a new unit version;
//! historical mantissas are never reinterpreted.

use core::fmt;

use crate::rounding::RoundingLaw;

/// Index into a [`UnitRegistry`]. Stable for the life of the registry epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnitId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UnitKind {
    /// ISO 4217 currency with its numeric code.
    Currency {
        iso4217: u16,
    },
    Commodity,
    Share,
    Time,
    Count,
    Custom,
}

/// One unit version. `code` is the human spelling (`USD`), `version` the
/// precision epoch (`USD@2` is version 0 at scale 2; a later `USD@4` is a
/// different unit with a registered conversion law).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unit {
    pub code: String,
    pub scale: u8,
    pub version: u16,
    pub kind: UnitKind,
    /// Immutable default for this unit version. Arithmetic operations still
    /// require an explicit law; this is metadata, never implicit rounding.
    pub rounding_default: RoundingLaw,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnitError {
    InvalidScale(u8),
    InvalidCode,
    ConflictingVersion { code: String, version: u16 },
    TooManyUnits,
}

impl fmt::Display for UnitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScale(scale) => write!(f, "unit scale {scale} exceeds 38"),
            Self::InvalidCode => f.write_str("unit code must contain 1..=64 bytes"),
            Self::ConflictingVersion { code, version } => write!(
                f,
                "unit {code}@v{version} already has a different definition; register a new version"
            ),
            Self::TooManyUnits => f.write_str("unit registry exhausted its u32 identifiers"),
        }
    }
}

impl core::error::Error for UnitError {}

impl Unit {
    /// `10^scale` as the mantissa of one whole unit.
    pub fn one(&self) -> i128 {
        pow10(self.scale)
    }

    /// Display spelling: `USD` for version 0, `USD@vN` for later versions.
    pub fn spelling(&self) -> String {
        if self.version == 0 {
            self.code.clone()
        } else {
            format!("{}@v{}", self.code, self.version)
        }
    }
}

pub(crate) fn pow10(scale: u8) -> i128 {
    assert!(scale <= 38, "scale {scale} exceeds i128 capacity");
    let mut v: i128 = 1;
    for _ in 0..scale {
        v *= 10;
    }
    v
}

/// The unit table a book binds. Built-in defaults cover the common currencies
/// and a few non-monetary units; [`Self::embedded`] loads the production
/// `registries/units.toml` table and validates its executable rounding laws.
#[derive(Clone, Debug, Default)]
pub struct UnitRegistry {
    units: Vec<Unit>,
}

impl UnitRegistry {
    pub fn empty() -> Self {
        Self { units: Vec::new() }
    }

    pub fn embedded() -> Result<Self, fa_registry::RegistryError> {
        crate::rounding::validate_registry(&fa_registry::rounding_laws_embedded()?)?;
        let invalid = |message| fa_registry::RegistryError::Invalid {
            registry: "units.toml",
            message,
        };
        let mut registry = Self::empty();
        for row in fa_registry::units_embedded()? {
            let kind = match row.kind.as_str() {
                "currency" => UnitKind::Currency {
                    iso4217: row
                        .iso4217
                        .ok_or_else(|| invalid("currency lacks ISO code".into()))?,
                },
                "commodity" => UnitKind::Commodity,
                "share" => UnitKind::Share,
                "time" => UnitKind::Time,
                "count" => UnitKind::Count,
                "custom" => UnitKind::Custom,
                other => return Err(invalid(format!("unknown unit kind `{other}`"))),
            };
            let rounding_default = RoundingLaw::from_id(row.rounding_default)
                .ok_or_else(|| invalid("default rounding law is not executable".into()))?;
            let id = registry
                .register(Unit {
                    code: row.code,
                    scale: row.scale,
                    version: row.version,
                    kind,
                    rounding_default,
                })
                .map_err(|error| invalid(error.to_string()))?;
            if id.0 != row.id {
                return Err(invalid(format!(
                    "unit id {} differs from declared id {}",
                    id.0, row.id
                )));
            }
        }
        Ok(registry)
    }

    /// The default table used by examples and tests. Scales follow ISO 4217
    /// minor units; `BTC` 8; `ETH` 18; `SHARE` 6; `HOUR` 2; `EACH` 0.
    pub fn with_defaults() -> Self {
        let mut r = Self::empty();
        let cur = |code: &str, iso: u16, scale: u8| Unit {
            code: code.into(),
            scale,
            version: 0,
            kind: UnitKind::Currency { iso4217: iso },
            rounding_default: RoundingLaw::HalfEven,
        };
        for u in [
            cur("USD", 840, 2),
            cur("EUR", 978, 2),
            cur("GBP", 826, 2),
            cur("JPY", 392, 0),
            cur("CHF", 756, 2),
            cur("CAD", 124, 2),
            cur("AUD", 36, 2),
            cur("KWD", 414, 3),
        ] {
            r.register(u).expect("valid built-in unit");
        }
        r.register(Unit {
            code: "BTC".into(),
            scale: 8,
            version: 0,
            kind: UnitKind::Commodity,
            rounding_default: RoundingLaw::HalfEven,
        })
        .expect("valid built-in unit");
        r.register(Unit {
            code: "ETH".into(),
            scale: 18,
            version: 0,
            kind: UnitKind::Commodity,
            rounding_default: RoundingLaw::HalfEven,
        })
        .expect("valid built-in unit");
        r.register(Unit {
            code: "SHARE".into(),
            scale: 6,
            version: 0,
            kind: UnitKind::Share,
            rounding_default: RoundingLaw::HalfEven,
        })
        .expect("valid built-in unit");
        r.register(Unit {
            code: "HOUR".into(),
            scale: 2,
            version: 0,
            kind: UnitKind::Time,
            rounding_default: RoundingLaw::HalfEven,
        })
        .expect("valid built-in unit");
        r.register(Unit {
            code: "EACH".into(),
            scale: 0,
            version: 0,
            kind: UnitKind::Count,
            rounding_default: RoundingLaw::HalfEven,
        })
        .expect("valid built-in unit");
        r
    }

    /// Register an immutable unit version. An identical definition returns
    /// its existing id; a conflicting definition or unsupported scale is
    /// refused without changing the registry.
    pub fn register(&mut self, unit: Unit) -> Result<UnitId, UnitError> {
        if unit.code.is_empty() || unit.code.len() > 64 {
            return Err(UnitError::InvalidCode);
        }
        if unit.scale > 38 {
            return Err(UnitError::InvalidScale(unit.scale));
        }
        if let Some(i) = self
            .units
            .iter()
            .position(|u| u.code == unit.code && u.version == unit.version)
        {
            if self.units[i] != unit {
                return Err(UnitError::ConflictingVersion {
                    code: unit.code,
                    version: unit.version,
                });
            }
            return Ok(UnitId(
                u32::try_from(i).map_err(|_| UnitError::TooManyUnits)?,
            ));
        }
        let id = UnitId(u32::try_from(self.units.len()).map_err(|_| UnitError::TooManyUnits)?);
        self.units.push(unit);
        Ok(id)
    }

    /// Every registered unit with its id, in registration order.
    pub fn iter(&self) -> impl Iterator<Item = (UnitId, &Unit)> {
        self.units
            .iter()
            .enumerate()
            .map(|(i, u)| (UnitId(u32::try_from(i).unwrap_or(u32::MAX)), u))
    }

    pub fn get(&self, id: UnitId) -> Option<&Unit> {
        self.units.get(id.0 as usize)
    }

    /// Look up the current (highest) version of a code, or `CODE@vN`.
    pub fn lookup(&self, spelling: &str) -> Option<UnitId> {
        let (code, version) = match spelling.split_once("@v") {
            Some((c, v)) => (c, Some(v.parse::<u16>().ok()?)),
            None => (spelling, None),
        };
        let mut best: Option<(u16, usize)> = None;
        for (i, u) in self.units.iter().enumerate() {
            if u.code != code {
                continue;
            }
            match version {
                Some(v) if u.version == v => return Some(UnitId(i as u32)),
                Some(_) => {}
                None => {
                    if best.is_none_or(|(bv, _)| u.version > bv) {
                        best = Some((u.version, i));
                    }
                }
            }
        }
        best.map(|(_, i)| UnitId(i as u32))
    }

    pub fn len(&self) -> usize {
        self.units.len()
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }
}

impl fmt::Display for UnitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unit#{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_units_bind_registry_data_and_executable_laws() {
        let registry = UnitRegistry::embedded().unwrap();
        for row in fa_registry::units_embedded().unwrap() {
            let id = registry
                .lookup(&format!("{}@v{}", row.code, row.version))
                .unwrap();
            let unit = registry.get(id).unwrap();
            assert_eq!(id.0, row.id);
            assert_eq!(unit.scale, row.scale);
            assert_eq!(unit.rounding_default.id(), row.rounding_default);
            if let Some(iso4217) = row.iso4217 {
                assert_eq!(unit.kind, UnitKind::Currency { iso4217 });
            }
        }
    }

    #[test]
    fn registry_is_immutable_per_version() {
        let mut r = UnitRegistry::with_defaults();
        let usd = r.lookup("USD").unwrap();
        assert_eq!(r.get(usd).unwrap().scale, 2);
        let original = r.get(usd).unwrap().clone();
        let count = r.len();
        assert_eq!(r.register(original.clone()), Ok(usd));
        // Re-registering USD v0 with another scale is a typed refusal.
        let conflict = r.register(Unit {
            code: "USD".into(),
            scale: 4,
            version: 0,
            kind: UnitKind::Custom,
            rounding_default: RoundingLaw::HalfEven,
        });
        assert_eq!(
            conflict,
            Err(UnitError::ConflictingVersion {
                code: "USD".into(),
                version: 0
            })
        );
        let mut changed_kind = original.clone();
        changed_kind.kind = UnitKind::Custom;
        assert!(matches!(
            r.register(changed_kind),
            Err(UnitError::ConflictingVersion { .. })
        ));
        let mut changed_rounding = original.clone();
        changed_rounding.rounding_default = RoundingLaw::HalfUp;
        assert!(matches!(
            r.register(changed_rounding),
            Err(UnitError::ConflictingVersion { .. })
        ));
        assert_eq!(r.len(), count);
        assert_eq!(r.get(usd), Some(&original));
        // A precision change is a new version with its own id.
        let usd4 = r
            .register(Unit {
                code: "USD".into(),
                scale: 4,
                version: 1,
                kind: UnitKind::Currency { iso4217: 840 },
                rounding_default: RoundingLaw::HalfEven,
            })
            .unwrap();
        assert_ne!(usd4, usd);
        assert_eq!(
            r.lookup("USD"),
            Some(usd4),
            "bare code resolves to the newest version"
        );
        assert_eq!(r.lookup("USD@v0"), Some(usd));
    }

    #[test]
    fn unsupported_scales_are_refused_before_registration() {
        let mut registry = UnitRegistry::empty();
        for scale in [39, u8::MAX] {
            assert_eq!(
                registry.register(Unit {
                    code: "INVALID".into(),
                    scale,
                    version: 0,
                    kind: UnitKind::Custom,
                    rounding_default: RoundingLaw::HalfEven,
                }),
                Err(UnitError::InvalidScale(scale))
            );
            assert!(registry.is_empty());
        }
        let id = registry
            .register(Unit {
                code: "WIDE".into(),
                scale: 38,
                version: 0,
                kind: UnitKind::Custom,
                rounding_default: RoundingLaw::HalfEven,
            })
            .unwrap();
        assert_eq!(registry.get(id).unwrap().one(), pow10(38));
    }

    #[test]
    fn pow10_is_exact() {
        assert_eq!(pow10(0), 1);
        assert_eq!(pow10(2), 100);
        assert_eq!(pow10(18), 1_000_000_000_000_000_000);
    }
}
