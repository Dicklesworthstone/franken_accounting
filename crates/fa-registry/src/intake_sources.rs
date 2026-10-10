//! `registries/intake_sources.toml`: where a document may enter a book
//! (plan §9.3). The posting kernel admits a citation only when the
//! document's custody chain starts at a receipt whose source this registry
//! admits.

use std::collections::BTreeSet;

use crate::{RegistryError, invalid, load, req_int, req_str};

const INTAKE_SOURCES: &str = include_str!("../../../registries/intake_sources.toml");
const R: &str = "intake_sources.toml";

/// The source kinds an `IntakeSource` payload can encode.
pub const KINDS: [&str; 4] = ["Upload", "Connector", "Email", "Scan"];
/// The bound on every registered name and version (`max_intake_text_bytes`).
pub const MAX_TEXT_BYTES: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntakeSources {
    /// The admitted kinds.
    pub kinds: BTreeSet<String>,
    /// Registered connectors as `(name, version)`.
    pub connectors: BTreeSet<(String, String)>,
    /// Registered scanning devices.
    pub devices: BTreeSet<String>,
}

fn text(t: &crate::toml::Table, key: &str) -> Result<String, RegistryError> {
    let s = req_str(R, t, key)?;
    if s.is_empty() || s.len() > MAX_TEXT_BYTES {
        return Err(invalid(
            R,
            format!("`{key}` = `{s}` must be 1..={MAX_TEXT_BYTES} bytes"),
        ));
    }
    Ok(s.to_string())
}

impl IntakeSources {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(INTAKE_SOURCES)
    }

    pub fn from_text(text_in: &str) -> Result<Self, RegistryError> {
        let doc = load(R, text_in)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let empty = Vec::new();
        let mut kinds = BTreeSet::new();
        for t in doc.arrays.get("kind").unwrap_or(&empty) {
            let name = text(t, "name")?;
            text(t, "meaning")?;
            if !KINDS.contains(&name.as_str()) {
                return Err(invalid(
                    R,
                    format!("unknown source kind `{name}` (the payload encodes {KINDS:?})"),
                ));
            }
            if !kinds.insert(name.clone()) {
                return Err(invalid(R, format!("kind `{name}` is listed twice")));
            }
        }
        let mut connectors = BTreeSet::new();
        for t in doc.arrays.get("connector").unwrap_or(&empty) {
            let row = (text(t, "name")?, text(t, "version")?);
            text(t, "meaning")?;
            if !connectors.insert(row.clone()) {
                return Err(invalid(
                    R,
                    format!("connector `{}` version `{}` is listed twice", row.0, row.1),
                ));
            }
        }
        let mut devices = BTreeSet::new();
        for t in doc.arrays.get("device").unwrap_or(&empty) {
            let name = text(t, "name")?;
            text(t, "meaning")?;
            if !devices.insert(name.clone()) {
                return Err(invalid(R, format!("device `{name}` is listed twice")));
            }
        }
        if !connectors.is_empty() && !kinds.contains("Connector") {
            return Err(invalid(
                R,
                "connectors are registered but the Connector kind is not",
            ));
        }
        if !devices.is_empty() && !kinds.contains("Scan") {
            return Err(invalid(
                R,
                "devices are registered but the Scan kind is not",
            ));
        }
        Ok(Self {
            kinds,
            connectors,
            devices,
        })
    }

    #[must_use]
    pub fn admits_kind(&self, kind: &str) -> bool {
        self.kinds.contains(kind)
    }

    #[must_use]
    pub fn admits_connector(&self, name: &str, version: &str) -> bool {
        self.admits_kind("Connector")
            && self
                .connectors
                .contains(&(name.to_string(), version.to_string()))
    }

    #[must_use]
    pub fn admits_device(&self, device: &str) -> bool {
        self.admits_kind("Scan") && self.devices.contains(device)
    }

    /// `name version` of every registered connector, for refusal text.
    #[must_use]
    pub fn connector_listing(&self) -> String {
        self.connectors
            .iter()
            .map(|(n, v)| format!("{n} {v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_sources_load_and_answer() {
        let s = IntakeSources::embedded().expect("intake_sources.toml");
        for k in KINDS {
            assert!(s.admits_kind(k), "{k}");
        }
        assert!(s.admits_connector("fa-import", "1"));
        assert!(!s.admits_connector("fa-import", "2"));
        assert!(!s.admits_connector("bank-feed", "1"));
        assert!(
            !s.admits_device("office-scanner"),
            "no device is registered"
        );
        assert_eq!(s.connector_listing(), "fa-import 1");
    }

    #[test]
    fn malformed_source_tables_are_refused() {
        let good = INTAKE_SOURCES;
        for (what, from, to, expect) in [
            (
                "an unknown kind",
                "name = \"Email\"",
                "name = \"Pigeon\"",
                "unknown source kind",
            ),
            (
                "a duplicated kind",
                "name = \"Email\"",
                "name = \"Upload\"",
                "listed twice",
            ),
            (
                "an empty connector version",
                "version = \"1\"",
                "version = \"\"",
                "must be 1..=",
            ),
            (
                "a connector without the Connector kind",
                "[[kind]]\nname = \"Connector\"\nmeaning = \"a registered connector fetched the bytes in an import run\"\n\n",
                "",
                "the Connector kind is not",
            ),
            (
                "a device without the Scan kind",
                "[[kind]]\nname = \"Scan\"\nmeaning = \"a registered scanning device captured the bytes\"\n",
                "[[device]]\nname = \"scanner\"\nmeaning = \"m\"\n",
                "the Scan kind is not",
            ),
        ] {
            let text = good.replacen(from, to, 1);
            assert_ne!(text, good, "{what}: the planted edit did not apply");
            let err = IntakeSources::from_text(&text).expect_err(what);
            assert!(err.to_string().contains(expect), "{what}: {err}");
        }
    }
}
