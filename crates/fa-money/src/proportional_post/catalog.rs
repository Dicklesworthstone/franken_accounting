//! Registered proportional hold laws. The catalog cannot redefine arithmetic.

use fa_registry::RegistryError;
use fa_registry::toml::Value;

use super::ProportionalPostLaw;

pub const MAX_PROPORTIONAL_POST_LEGS: usize = 4096;
const REGISTRY: &str = "proportional_post_laws.toml";
const EMBEDDED: &str = include_str!("../../../../registries/proportional_post_laws.toml");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProportionalPostCatalog {
    max_legs: usize,
}

impl ProportionalPostCatalog {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::parse(EMBEDDED)
    }

    pub fn parse(text: &str) -> Result<Self, RegistryError> {
        if text.len() > 16 * 1024 {
            return Err(invalid("proportional post catalog exceeds 16 KiB"));
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
            return Err(invalid("unsupported proportional post catalog schema"));
        }
        let max_legs = doc
            .root
            .get("max_legs")
            .and_then(Value::as_int)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| (2..=MAX_PROPORTIONAL_POST_LEGS).contains(value))
            .ok_or_else(|| invalid("max_legs is outside the implementation bound"))?;
        let rows = doc
            .arrays
            .get("law")
            .ok_or_else(|| invalid("missing law rows"))?;
        if rows.len() != ProportionalPostLaw::ALL.len() {
            return Err(invalid("every implemented law needs exactly one row"));
        }
        let mut seen = std::collections::BTreeSet::new();
        for row in rows {
            let id = row
                .get("id")
                .and_then(Value::as_int)
                .and_then(|value| u16::try_from(value).ok())
                .ok_or_else(|| invalid("invalid proportional post law id"))?;
            let law = ProportionalPostLaw::from_id(id)
                .ok_or_else(|| invalid("proportional post law has no implementation"))?;
            if !seen.insert(id)
                || row.len() != 9
                || row.get("name").and_then(Value::as_str) != Some(law.name())
                || row.get("version").and_then(Value::as_int) != Some(i128::from(law.version()))
            {
                return Err(invalid(
                    "duplicate or incompatible proportional post law row",
                ));
            }
            for (field, expected) in [
                (
                    "domain",
                    "positive-native-monetary-legs; exact-rate-in-[0,1]",
                ),
                ("partition", "unit-and-normalized-legal-entity"),
                (
                    "target",
                    "common-pending-debit-credit-total-times-rate; HalfEven",
                ),
                (
                    "allocation",
                    "same-target-per-side; largest-remainder; ties-lowest-source-ordinal",
                ),
                (
                    "zero",
                    "omit-zero-posted-legs; empty-result-refuses-with-VoidReserve",
                ),
                (
                    "remainder",
                    "released-per-original-leg; never-a-new-posting",
                ),
            ] {
                if row.get(field).and_then(Value::as_str) != Some(expected) {
                    return Err(invalid("registry semantics differ from the executable law"));
                }
            }
        }
        Ok(Self { max_legs })
    }

    pub fn max_legs(&self) -> usize {
        self.max_legs
    }

    pub fn laws(&self) -> &[ProportionalPostLaw] {
        &ProportionalPostLaw::ALL
    }
}

fn invalid(message: &str) -> RegistryError {
    RegistryError::Invalid {
        registry: REGISTRY,
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_and_executable_law_have_exact_correspondence() {
        let catalog = ProportionalPostCatalog::embedded().unwrap();
        assert_eq!(catalog.max_legs(), MAX_PROPORTIONAL_POST_LEGS);
        assert_eq!(catalog.laws(), &ProportionalPostLaw::ALL);
        assert_eq!(ProportionalPostLaw::from_id(0), None);
        assert_eq!(ProportionalPostLaw::from_id(2), None);
        assert_eq!(
            ProportionalPostLaw::from_id(1),
            Some(ProportionalPostLaw::BalancedLargestRemainder)
        );
        for text in [
            EMBEDDED.replacen("id = 1", "id = 2", 1),
            EMBEDDED.replacen("version = 1\nname", "version = 2\nname", 1),
            EMBEDDED.replace("HalfEven", "Floor"),
            EMBEDDED.replace("ties-lowest-source-ordinal", "ties-highest-source-ordinal"),
            EMBEDDED.replace("max_legs = 4096", "max_legs = 4097"),
            EMBEDDED.replace("max_legs = 4096", "max_legs = 1"),
            EMBEDDED.replace("schema_version = 1", "schema_version = 2"),
            format!("{EMBEDDED}\nunknown = true\n"),
            EMBEDDED.split("[[law]]").next().unwrap().to_string(),
        ] {
            assert!(ProportionalPostCatalog::parse(&text).is_err(), "{text}");
        }
        assert_eq!(
            ProportionalPostCatalog::parse(&EMBEDDED.replace("max_legs = 4096", "max_legs = 2"))
                .unwrap()
                .max_legs(),
            2
        );
    }
}
