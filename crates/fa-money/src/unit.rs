//! Units: currencies, commodities, shares, time, counts — each with an
//! **immutable** scale (plan §4.4). A precision change is a new unit version;
//! historical mantissas are never reinterpreted.

use core::fmt;

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
}

impl Unit {
    /// `10^scale` as the mantissa of one whole unit.
    pub fn one(&self) -> i128 {
        pow10(self.scale)
    }

    /// Display spelling: `USD` for version 0, `USD@4` otherwise... no — the
    /// spelling always carries the scale so a reader never has to look it up.
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
/// and a few non-monetary units; `registries/units.toml` supplies the rest
/// once `fa-registry` lands.
#[derive(Clone, Debug, Default)]
pub struct UnitRegistry {
    units: Vec<Unit>,
}

impl UnitRegistry {
    pub fn empty() -> Self {
        Self { units: Vec::new() }
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
            r.register(u);
        }
        r.register(Unit {
            code: "BTC".into(),
            scale: 8,
            version: 0,
            kind: UnitKind::Commodity,
        });
        r.register(Unit {
            code: "ETH".into(),
            scale: 18,
            version: 0,
            kind: UnitKind::Commodity,
        });
        r.register(Unit {
            code: "SHARE".into(),
            scale: 6,
            version: 0,
            kind: UnitKind::Share,
        });
        r.register(Unit {
            code: "HOUR".into(),
            scale: 2,
            version: 0,
            kind: UnitKind::Time,
        });
        r.register(Unit {
            code: "EACH".into(),
            scale: 0,
            version: 0,
            kind: UnitKind::Count,
        });
        r
    }

    /// Register a unit version; returns its id. Registering the same
    /// `(code, version)` twice returns the existing id and never mutates it.
    pub fn register(&mut self, unit: Unit) -> UnitId {
        if let Some(i) = self
            .units
            .iter()
            .position(|u| u.code == unit.code && u.version == unit.version)
        {
            return UnitId(i as u32);
        }
        self.units.push(unit);
        UnitId((self.units.len() - 1) as u32)
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
    fn registry_is_immutable_per_version() {
        let mut r = UnitRegistry::with_defaults();
        let usd = r.lookup("USD").unwrap();
        assert_eq!(r.get(usd).unwrap().scale, 2);
        // Re-registering USD v0 with another scale does not change the existing unit.
        let again = r.register(Unit {
            code: "USD".into(),
            scale: 4,
            version: 0,
            kind: UnitKind::Custom,
        });
        assert_eq!(again, usd);
        assert_eq!(r.get(usd).unwrap().scale, 2);
        // A precision change is a new version with its own id.
        let usd4 = r.register(Unit {
            code: "USD".into(),
            scale: 4,
            version: 1,
            kind: UnitKind::Currency { iso4217: 840 },
        });
        assert_ne!(usd4, usd);
        assert_eq!(
            r.lookup("USD"),
            Some(usd4),
            "bare code resolves to the newest version"
        );
        assert_eq!(r.lookup("USD@v0"), Some(usd));
    }

    #[test]
    fn pow10_is_exact() {
        assert_eq!(pow10(0), 1);
        assert_eq!(pow10(2), 100);
        assert_eq!(pow10(18), 1_000_000_000_000_000_000);
    }
}
