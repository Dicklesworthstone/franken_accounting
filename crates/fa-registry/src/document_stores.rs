//! `registries/document_stores.toml`: the stores a document's bytes may live
//! in outside the journal (plan §9.1 `External`).

use std::collections::BTreeSet;

use crate::{RegistryError, invalid, load, req_int, req_str};

const DOCUMENT_STORES: &str = include_str!("../../../registries/document_stores.toml");
const R: &str = "document_stores.toml";

/// The store kinds a book knows how to address.
pub const KINDS: [&str; 1] = ["content_addressed"];
/// The decoder's ceiling on one document (64 MiB).
pub const MAX_STORE_DOCUMENT_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    pub id: u16,
    pub name: String,
    pub kind: String,
    pub max_document_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentStores {
    pub stores: Vec<Store>,
}

impl DocumentStores {
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(DOCUMENT_STORES)
    }

    pub fn from_text(text: &str) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let empty = Vec::new();
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut stores = Vec::new();
        for t in doc.arrays.get("store").unwrap_or(&empty) {
            let raw = req_int(R, t, "id")?;
            let id = u16::try_from(raw)
                .ok()
                .filter(|id| *id >= 1)
                .ok_or_else(|| invalid(R, format!("store id {raw} is not in 1..=65535")))?;
            let name = req_str(R, t, "name")?.to_string();
            let kind = req_str(R, t, "kind")?.to_string();
            if !KINDS.contains(&kind.as_str()) {
                return Err(invalid(R, format!("store {id}: unknown kind `{kind}`")));
            }
            let max_raw = req_int(R, t, "max_document_bytes")?;
            let max_document_bytes = u64::try_from(max_raw)
                .ok()
                .filter(|m| (1..=MAX_STORE_DOCUMENT_BYTES).contains(m))
                .ok_or_else(|| {
                    invalid(
                        R,
                        format!(
                            "store {id}: max_document_bytes {max_raw} is not in 1..={MAX_STORE_DOCUMENT_BYTES}"
                        ),
                    )
                })?;
            if req_str(R, t, "meaning")?.trim().is_empty() {
                return Err(invalid(R, format!("store {id}: meaning is required")));
            }
            if !ids.insert(id) {
                return Err(invalid(R, format!("store id {id} is listed twice")));
            }
            if name.is_empty() || !names.insert(name.clone()) {
                return Err(invalid(
                    R,
                    format!("store name `{name}` is empty or listed twice"),
                ));
            }
            stores.push(Store {
                id,
                name,
                kind,
                max_document_bytes,
            });
        }
        if stores.is_empty() {
            return Err(invalid(R, "at least one store is registered"));
        }
        Ok(Self { stores })
    }

    #[must_use]
    pub fn get(&self, id: u16) -> Option<&Store> {
        self.stores.iter().find(|s| s.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_stores_load() {
        let s = DocumentStores::embedded().expect("document_stores.toml");
        let blobs = s.get(1).expect("store 1");
        assert_eq!(
            (blobs.name.as_str(), blobs.kind.as_str()),
            ("book-blobs", "content_addressed")
        );
        assert_eq!(blobs.max_document_bytes, MAX_STORE_DOCUMENT_BYTES);
        assert!(s.get(2).is_none());
    }

    #[test]
    fn malformed_store_tables_are_refused() {
        let good = DOCUMENT_STORES;
        for (what, from, to, expect) in [
            ("a zero id", "id = 1\n", "id = 0\n", "not in 1..=65535"),
            (
                "an unknown kind",
                "kind = \"content_addressed\"",
                "kind = \"s3\"",
                "unknown kind",
            ),
            (
                "a bound past the decoder ceiling",
                "max_document_bytes = 67108864",
                "max_document_bytes = 67108865",
                "max_document_bytes",
            ),
            (
                "no stores",
                "[[store]]\nid = 1",
                "[[nostore]]\nid = 1",
                "at least one store",
            ),
        ] {
            let text = good.replacen(from, to, 1);
            assert_ne!(text, good, "{what}: the planted edit did not apply");
            let err = DocumentStores::from_text(&text).expect_err(what);
            assert!(err.to_string().contains(expect), "{what}: {err}");
        }
    }
}
