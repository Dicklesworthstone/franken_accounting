//! `registries/evidence_policy.toml`: the closed Document kinds, provenance
//! grades, EVIDENCED_BY roles, and the per-class evidence minimum (plan
//! §9.1–§9.3, FA-INV-05 clause `evidence-minimum`).
//!
//! The kernel branches on every table here: intake refuses an unregistered
//! kind or a grade not admitted at intake; the posting transaction resolves
//! each cited document and refuses an entry below its class's minimum; the
//! CLI parses `--kind`/`--grade`/roles by name. The minimum table is total
//! over `entry_classes.toml` — a class without a row is a load error, never an
//! implicit exemption.

use std::collections::BTreeSet;

use crate::toml::Value;
use crate::{EntryClasses, RegistryError, invalid, load, req_int, req_str};

const EVIDENCE_POLICY: &str = include_str!("../../../registries/evidence_policy.toml");
const R: &str = "evidence_policy.toml";

/// A registered Document kind (plan §9.1); `tag` is the durable `kind: u8`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentKind {
    pub tag: u8,
    pub name: String,
}

/// A provenance grade (plan §9.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grade {
    pub tag: u8,
    pub name: String,
    /// Evidence carrying only self-sourced grades makes an entry self-sourced.
    pub self_sourced: bool,
    /// Whether intake may record this grade today (the others are derived
    /// from a receipt chain this slice cannot verify).
    pub intake: bool,
}

/// An `EVIDENCED_BY` role; `tag` is `EvidenceRef.role`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    pub tag: u8,
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    /// At least `min_documents` cited documents of an admissible kind.
    Documents,
    /// The closure is the superseded or resolved target's.
    Target,
    /// Control classes rest on their control record alone.
    ControlRecord,
}

impl Requirement {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Documents => "documents",
            Self::Target => "target",
            Self::ControlRecord => "control_record",
        }
    }
}

/// The kinds a minimum admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KindSet {
    Any,
    /// Registered kind tags, ascending.
    Only(Vec<u8>),
}

impl KindSet {
    #[must_use]
    pub fn admits(&self, kind: u8) -> bool {
        match self {
            Self::Any => true,
            Self::Only(tags) => tags.binary_search(&kind).is_ok(),
        }
    }
}

/// One class's evidence minimum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Minimum {
    pub class: String,
    pub requirement: Requirement,
    pub min_documents: u16,
    pub kinds: KindSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidencePolicy {
    pub max_document_bytes: u64,
    pub max_mime_bytes: usize,
    pub kinds: Vec<DocumentKind>,
    pub grades: Vec<Grade>,
    pub roles: Vec<Role>,
    pub minimums: Vec<Minimum>,
}

fn tag_u8(t: &crate::toml::Table, what: &str) -> Result<u8, RegistryError> {
    let v = req_int(R, t, "tag")?;
    u8::try_from(v)
        .ok()
        .filter(|t| *t != 0)
        .ok_or_else(|| invalid(R, format!("{what} tag {v} is not in 1..=255")))
}

fn req_bool(t: &crate::toml::Table, key: &str, row: &str) -> Result<bool, RegistryError> {
    t.get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(R, format!("{row}: missing boolean `{key}`")))
}

/// Unique tags and names, or a load error naming the duplicate.
fn unique<'a>(
    what: &str,
    rows: impl Iterator<Item = (u8, &'a str)>,
) -> Result<usize, RegistryError> {
    let mut tags = BTreeSet::new();
    let mut names = BTreeSet::new();
    for (tag, name) in rows {
        if !tags.insert(tag) {
            return Err(invalid(R, format!("duplicate {what} tag {tag}")));
        }
        if name.is_empty() || !names.insert(name) {
            return Err(invalid(R, format!("duplicate or empty {what} `{name}`")));
        }
    }
    if tags.is_empty() {
        return Err(invalid(R, format!("no {what} rows")));
    }
    Ok(tags.len())
}

impl EvidencePolicy {
    /// The embedded registry, validated against the embedded entry classes.
    pub fn embedded() -> Result<Self, RegistryError> {
        Self::from_text(EVIDENCE_POLICY, &EntryClasses::embedded()?)
    }

    /// Parse and validate `text` against `classes`: every class has exactly
    /// one minimum row, and no row names a class that is not registered.
    pub fn from_text(text: &str, classes: &EntryClasses) -> Result<Self, RegistryError> {
        let doc = load(R, text)?;
        if req_int(R, &doc.root, "schema_version")? != 1 {
            return Err(invalid(R, "schema_version must be 1"));
        }
        let max_document_bytes = u64::try_from(req_int(R, &doc.root, "max_document_bytes")?)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| invalid(R, "max_document_bytes must be positive"))?;
        let max_mime_bytes = usize::try_from(req_int(R, &doc.root, "max_mime_bytes")?)
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| invalid(R, "max_mime_bytes must be positive"))?;

        let empty = Vec::new();
        let mut kinds = Vec::new();
        for t in doc.arrays.get("kind").unwrap_or(&empty) {
            kinds.push(DocumentKind {
                tag: tag_u8(t, "kind")?,
                name: req_str(R, t, "name")?.to_string(),
            });
        }
        unique("kind", kinds.iter().map(|k| (k.tag, k.name.as_str())))?;

        let mut grades = Vec::new();
        for t in doc.arrays.get("grade").unwrap_or(&empty) {
            let name = req_str(R, t, "name")?.to_string();
            grades.push(Grade {
                tag: tag_u8(t, "grade")?,
                self_sourced: req_bool(t, "self_sourced", &name)?,
                intake: req_bool(t, "intake", &name)?,
                name,
            });
        }
        unique("grade", grades.iter().map(|g| (g.tag, g.name.as_str())))?;

        let mut roles = Vec::new();
        for t in doc.arrays.get("role").unwrap_or(&empty) {
            roles.push(Role {
                tag: tag_u8(t, "role")?,
                name: req_str(R, t, "name")?.to_string(),
            });
        }
        unique("role", roles.iter().map(|r| (r.tag, r.name.as_str())))?;

        let mut minimums: Vec<Minimum> = Vec::new();
        for t in doc.arrays.get("minimum").unwrap_or(&empty) {
            let class = req_str(R, t, "class")?.to_string();
            if classes.by_name(&class).is_none() {
                return Err(invalid(
                    R,
                    format!("minimum names unregistered class `{class}`"),
                ));
            }
            if minimums.iter().any(|m| m.class == class) {
                return Err(invalid(R, format!("duplicate minimum for `{class}`")));
            }
            let requirement = match req_str(R, t, "requirement")? {
                "documents" => Requirement::Documents,
                "target" => Requirement::Target,
                "control_record" => Requirement::ControlRecord,
                other => {
                    return Err(invalid(
                        R,
                        format!("`{class}`: unknown requirement `{other}`"),
                    ));
                }
            };
            let min_documents = u16::try_from(req_int(R, t, "min_documents")?)
                .map_err(|_| invalid(R, format!("`{class}`: min_documents out of range")))?;
            if requirement == Requirement::Documents && min_documents == 0 {
                return Err(invalid(
                    R,
                    format!("`{class}`: a `documents` minimum requires at least one document"),
                ));
            }
            let kinds_set = match t.get("kinds") {
                Some(Value::Str(s)) if s == "any" => KindSet::Any,
                Some(Value::Array(items)) if !items.is_empty() => {
                    let mut tags = Vec::new();
                    for item in items {
                        let name = item.as_str().ok_or_else(|| {
                            invalid(R, format!("`{class}`: kinds lists kind names"))
                        })?;
                        let kind = kinds.iter().find(|k| k.name == name).ok_or_else(|| {
                            invalid(R, format!("`{class}`: unregistered kind `{name}`"))
                        })?;
                        tags.push(kind.tag);
                    }
                    tags.sort_unstable();
                    if tags.windows(2).any(|w| w[0] == w[1]) {
                        return Err(invalid(R, format!("`{class}`: a kind is listed twice")));
                    }
                    KindSet::Only(tags)
                }
                _ => {
                    return Err(invalid(
                        R,
                        format!("`{class}`: kinds is \"any\" or a non-empty list of kind names"),
                    ));
                }
            };
            minimums.push(Minimum {
                class,
                requirement,
                min_documents,
                kinds: kinds_set,
            });
        }
        for c in &classes.rows {
            if !minimums.iter().any(|m| m.class == c.name) {
                return Err(invalid(
                    R,
                    format!("class `{}` has no evidence minimum row", c.name),
                ));
            }
        }
        Ok(Self {
            max_document_bytes,
            max_mime_bytes,
            kinds,
            grades,
            roles,
            minimums,
        })
    }

    #[must_use]
    pub fn minimum(&self, class: &str) -> Option<&Minimum> {
        self.minimums.iter().find(|m| m.class == class)
    }

    #[must_use]
    pub fn kind_by_name(&self, name: &str) -> Option<&DocumentKind> {
        self.kinds.iter().find(|k| k.name == name)
    }

    #[must_use]
    pub fn kind_by_tag(&self, tag: u8) -> Option<&DocumentKind> {
        self.kinds.iter().find(|k| k.tag == tag)
    }

    #[must_use]
    pub fn grade_by_name(&self, name: &str) -> Option<&Grade> {
        self.grades.iter().find(|g| g.name == name)
    }

    #[must_use]
    pub fn grade_by_tag(&self, tag: u8) -> Option<&Grade> {
        self.grades.iter().find(|g| g.tag == tag)
    }

    #[must_use]
    pub fn role_by_name(&self, name: &str) -> Option<&Role> {
        self.roles.iter().find(|r| r.name == name)
    }

    #[must_use]
    pub fn role_by_tag(&self, tag: u8) -> Option<&Role> {
        self.roles.iter().find(|r| r.tag == tag)
    }

    /// The names a minimum admits, for refusal text.
    #[must_use]
    pub fn kind_names(&self, set: &KindSet) -> Vec<&str> {
        match set {
            KindSet::Any => vec!["any registered kind"],
            KindSet::Only(tags) => tags
                .iter()
                .filter_map(|t| self.kind_by_tag(*t).map(|k| k.name.as_str()))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ClassKind;

    #[test]
    fn embedded_policy_is_total_over_entry_classes() {
        let classes = EntryClasses::embedded().unwrap();
        let p = EvidencePolicy::embedded().expect("evidence_policy.toml");
        assert_eq!(p.minimums.len(), classes.rows.len());
        for c in &classes.rows {
            let m = p.minimum(&c.name).expect("a row per class");
            match c.kind {
                // Control records never pass through `post`.
                ClassKind::Control => assert_eq!(m.requirement, Requirement::ControlRecord),
                ClassKind::Posting => assert_ne!(m.requirement, Requirement::ControlRecord),
            }
        }
        // The three classes plan §9.2 names require a document.
        for class in ["Original", "Adjusting", "Reclassification"] {
            let m = p.minimum(class).unwrap();
            assert_eq!(m.requirement, Requirement::Documents, "{class}");
            assert!(m.min_documents >= 1, "{class}");
        }
        let rate = p.kind_by_name("Rate").unwrap().tag;
        let invoice = p.kind_by_name("Invoice").unwrap().tag;
        let reval = &p.minimum("Revaluation").unwrap().kinds;
        assert!(reval.admits(rate) && !reval.admits(invoice));
        assert!(p.grade_by_name("AgentUpload").unwrap().self_sourced);
        assert!(!p.grade_by_name("HumanUpload").unwrap().self_sourced);
        assert!(!p.grade_by_name("ThirdPartySigned").unwrap().intake);
        assert_eq!(p.kinds.len(), 22);
        assert_eq!(p.role_by_tag(1).map(|r| r.name.as_str()), Some("Source"));
    }

    /// Planted negatives: each edit of the real registry must fail to load.
    #[test]
    fn malformed_policies_are_refused() {
        let classes = EntryClasses::embedded().unwrap();
        let good = EVIDENCE_POLICY;
        let cases: [(&str, String); 8] = [
            (
                "a class without a row",
                good.replacen(
                    "[[minimum]]\nclass = \"Adjusting\"\nrequirement = \"documents\"\nmin_documents = 1\nkinds = \"any\"\n",
                    "",
                    1,
                ),
            ),
            (
                "a class with two rows",
                good.replacen("class = \"Adjusting\"", "class = \"Original\"", 1),
            ),
            (
                "an unregistered class",
                good.replacen("class = \"Adjusting\"", "class = \"Bogus\"", 1),
            ),
            (
                "a duplicate kind tag",
                good.replacen("tag = 2\nname = \"Bill\"", "tag = 1\nname = \"Bill\"", 1),
            ),
            (
                "an unregistered kind in a list",
                good.replacen("kinds = [\"Rate\"]", "kinds = [\"Ratee\"]", 1),
            ),
            (
                "a documents row with zero documents",
                good.replacen(
                    "class = \"Original\"\nrequirement = \"documents\"\nmin_documents = 1",
                    "class = \"Original\"\nrequirement = \"documents\"\nmin_documents = 0",
                    1,
                ),
            ),
            (
                "an unknown requirement",
                good.replacen("requirement = \"target\"", "requirement = \"vibes\"", 1),
            ),
            (
                "an empty kinds list",
                good.replacen("kinds = [\"Rate\"]", "kinds = []", 1),
            ),
        ];
        for (what, text) in cases {
            assert_ne!(text, good, "{what}: the planted edit did not apply");
            assert!(
                EvidencePolicy::from_text(&text, &classes).is_err(),
                "{what} must be refused"
            );
        }
    }
}
