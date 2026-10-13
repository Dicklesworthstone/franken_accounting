//! The executable allocation-law catalog. Arithmetic dispatch consumes this
//! registry; unsupported plan laws are not advertised as implementations.

use fa_registry::RegistryError;
use fa_registry::toml::{Table, Value};

const REGISTRY: &str = "allocation_laws.toml";
const EMBEDDED: &str = include_str!("../../../../registries/allocation_laws.toml");
/// Hard implementation ceiling, independent of a configurable lower bound.
pub const MAX_ALLOCATION_TARGETS: usize = 4096;

/// Stable identity of an implemented allocation law. IDs 4 and 6 are reserved
/// for the distinct, currently unsupported Tiered and ByUnitsThenValue laws.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AllocationLaw {
    LargestRemainder,
    ProRataResidualToNamed,
    Waterfall,
    EqualSplitResidualFirst,
}

impl AllocationLaw {
    pub const ALL: [Self; 4] = [
        Self::LargestRemainder,
        Self::ProRataResidualToNamed,
        Self::Waterfall,
        Self::EqualSplitResidualFirst,
    ];

    pub const fn id(self) -> u16 {
        match self {
            Self::LargestRemainder => 1,
            Self::ProRataResidualToNamed => 2,
            Self::Waterfall => 3,
            Self::EqualSplitResidualFirst => 5,
        }
    }

    pub fn from_id(id: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|law| law.id() == id)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::LargestRemainder => "LargestRemainder",
            Self::ProRataResidualToNamed => "ProRataResidualToNamed",
            Self::Waterfall => "Waterfall",
            Self::EqualSplitResidualFirst => "EqualSplitResidualFirst",
        }
    }

    pub const fn version(self) -> u16 {
        1
    }

    fn semantics(self) -> [&'static str; 4] {
        match self {
            Self::LargestRemainder => [
                "weights",
                "input-order; remainder-descending; ties-lowest-index",
                "floor-magnitude; distribute-one-unit",
                "magnitude-then-restore-sign",
            ],
            Self::ProRataResidualToNamed => [
                "weights",
                "input-order; explicit-recipient-id",
                "explicit-registered-rounding-law",
                "signed-rounding; signed-residual-to-recipient",
            ],
            Self::Waterfall => [
                "native-mantissa-caps",
                "input-order; fill-earlier-cap-first",
                "none",
                "magnitude-then-restore-sign",
            ],
            Self::EqualSplitResidualFirst => [
                "one-per-target",
                "input-order; entire-residual-to-first",
                "truncate-magnitude",
                "magnitude-then-restore-sign",
            ],
        }
    }
}

/// Validated registry data. It cannot redefine compiled arithmetic through a
/// descriptive field: names, versions and all semantic selectors must match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationCatalog {
    max_targets: usize,
}

impl AllocationCatalog {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(EMBEDDED)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        if text.len() > 16 * 1024 {
            return Err(invalid("allocation catalog exceeds 16 KiB"));
        }
        let doc = fa_registry::toml::parse(text).map_err(|error| RegistryError::Toml {
            registry: REGISTRY,
            error,
        })?;
        if doc.root.len() != 2
            || doc.root.get("schema_version").and_then(Value::as_int) != Some(1)
            || !doc.tables.is_empty()
            || doc.arrays.len() != 1
        {
            return Err(invalid("unsupported allocation catalog schema"));
        }
        let max_targets = doc.root.get("max_targets").and_then(Value::as_int)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| (1..=MAX_ALLOCATION_TARGETS).contains(value))
            .ok_or_else(|| invalid("max_targets is outside the implementation bound"))?;
        let rows = doc.arrays.get("law")
            .ok_or_else(|| invalid("missing law rows"))?;
        if rows.len() != AllocationLaw::ALL.len() {
            return Err(invalid("every implemented law needs exactly one row"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for row in rows {
            let id = row.get("id").and_then(Value::as_int)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| invalid("invalid allocation law id"))?;
            let law = AllocationLaw::from_id(id)
                .ok_or_else(|| invalid("allocation law has no implementation"))?;
            if !seen.insert(id) || row.len() != 7
                || text_field(row, "name")? != law.name()
                || row.get("version").and_then(Value::as_int) != Some(i128::from(law.version()))
            {
                return Err(invalid("duplicate or incompatible allocation law row"));
            }
            for (field, expected) in ["basis", "ordering", "rounding", "signed"]
                .into_iter().zip(law.semantics())
            {
                if text_field(row, field)? != expected {
                    return Err(invalid("registry semantics differ from the executable law"));
                }
            }
        }
        Ok(Self { max_targets })
    }

    pub fn max_targets(&self) -> usize {
        self.max_targets
    }

    pub fn laws(&self) -> &[AllocationLaw] {
        &AllocationLaw::ALL
    }
}

fn text_field<'a>(row: &'a Table, name: &str) -> Result<&'a str, RegistryError> {
    row.get(name).and_then(Value::as_str)
        .ok_or_else(|| invalid("missing allocation law string field"))
}

fn invalid(message: &str) -> RegistryError {
    RegistryError::Invalid { registry: REGISTRY, message: message.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_catalog_has_exact_executable_correspondence() {
        let catalog = AllocationCatalog::embedded().unwrap();
        assert_eq!(catalog.max_targets(), MAX_ALLOCATION_TARGETS);
        assert_eq!(catalog.laws().iter().map(|law| law.id()).collect::<Vec<_>>(), [1, 2, 3, 5]);
        for law in AllocationLaw::ALL {
            assert_eq!(AllocationLaw::from_id(law.id()), Some(law));
        }
        for absent in [0, 4, 6, u16::MAX] {
            assert_eq!(AllocationLaw::from_id(absent), None);
        }
    }

    #[test]
    fn incompatible_or_incomplete_catalogs_fail_closed() {
        for text in [
            EMBEDDED.replacen("id = 5", "id = 1", 1),
            EMBEDDED.replacen("id = 5", "id = 4", 1),
            EMBEDDED.replacen("version = 1\nname", "version = 2\nname", 1),
            EMBEDDED.replacen("ties-lowest-index", "ties-highest-index", 1),
            EMBEDDED.replacen("max_targets = 4096", "max_targets = 4097", 1),
            EMBEDDED.replacen("max_targets = 4096", "max_targets = 0", 1),
            EMBEDDED.replacen("schema_version = 1", "schema_version = 2", 1),
            format!("{EMBEDDED}\nunknown = true\n"),
            EMBEDDED.split("[[law]]").take(4).collect::<Vec<_>>().join("[[law]]"),
        ] {
            assert!(AllocationCatalog::parse(&text).is_err(), "{text}");
        }
        let lower = EMBEDDED.replace("max_targets = 4096", "max_targets = 2");
        assert_eq!(AllocationCatalog::parse(&lower).unwrap().max_targets(), 2);
    }
}
