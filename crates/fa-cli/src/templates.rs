//! Chart-of-accounts templates (plan §4.3, bead fa-48m): data under
//! `templates/charts/`, embedded in the binary and imported exactly like a
//! chart file (`fa chart import --template <name>`), as one journaled schema
//! effect. The import key is the template text's content digest, so the same
//! template, or the same bytes from a file, is the same chart: importing it
//! again is refused as an existing identity, never silently doubled.
//!
//! A template's leaves take `"unit": "base"`, the book's own base unit, so
//! one template serves a USD book and a EUR book alike. Templates are
//! starting points, not GAAP, IFRS or regulatory advice.

use crate::json::{self, Json};

/// One embedded template: its name and its JSON chart document.
pub(crate) struct Template {
    pub(crate) name: &'static str,
    pub(crate) text: &'static str,
}

/// Every template this build carries, by name.
pub(crate) const TEMPLATES: &[Template] = &[
    Template {
        name: "ifrs-sme",
        text: include_str!("../../../templates/charts/ifrs-sme.json"),
    },
    Template {
        name: "us-bank-call-report",
        text: include_str!("../../../templates/charts/us-bank-call-report.json"),
    },
    Template {
        name: "us-gaap-smb",
        text: include_str!("../../../templates/charts/us-gaap-smb.json"),
    },
];

/// The template called `name`.
pub(crate) fn find(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name == name)
}

/// The import key `fa chart import` journals for chart text `text`: the
/// same for a template and for the same bytes in a file.
pub(crate) fn chart_key(text: &str) -> String {
    format!(
        "chart:{}",
        crate::cli::hex(&fa_model::domain_digest(b"fa:chart:v1", &[text.as_bytes()])[..8])
    )
}

/// What `fa chart templates` lists for one template.
pub(crate) struct Listing {
    pub(crate) name: &'static str,
    pub(crate) version: i128,
    pub(crate) description: String,
    pub(crate) accounts: usize,
    pub(crate) leaves: usize,
    pub(crate) key: String,
}

/// Describe `template` from its own document.
pub(crate) fn listing(template: &Template) -> Result<Listing, String> {
    let doc = json::parse(template.text).map_err(|e| format!("{}: {e:?}", template.name))?;
    if doc.get("template").and_then(Json::as_str) != Some(template.name) {
        return Err(format!(
            "{}: the document's `template` names another template",
            template.name
        ));
    }
    let version = match doc.get("version") {
        Some(Json::Int(v)) if *v > 0 => *v,
        _ => {
            return Err(format!(
                "{}: `version` must be a positive integer",
                template.name
            ));
        }
    };
    let accounts = doc
        .get("accounts")
        .and_then(Json::as_arr)
        .ok_or_else(|| format!("{}: `accounts` must be an array", template.name))?;
    let leaves = accounts
        .iter()
        .filter(|a| a.get("leaf").and_then(Json::as_bool).unwrap_or(true))
        .count();
    Ok(Listing {
        name: template.name,
        version,
        description: doc
            .get("description")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string(),
        accounts: accounts.len(),
        leaves,
        key: chart_key(template.text),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_is_named_versioned_and_listable_with_a_distinct_key() {
        let mut keys = std::collections::BTreeSet::new();
        let mut names: Vec<&str> = TEMPLATES.iter().map(|t| t.name).collect();
        let sorted = {
            let mut s = names.clone();
            s.sort_unstable();
            s
        };
        assert_eq!(names, sorted, "TEMPLATES is sorted by name");
        names.dedup();
        assert_eq!(names.len(), TEMPLATES.len(), "template names are unique");
        for template in TEMPLATES {
            let listed = listing(template).expect("the template lists");
            assert!(listed.leaves > 0 && listed.leaves < listed.accounts);
            assert!(!listed.description.is_empty());
            assert!(
                keys.insert(listed.key),
                "{}: distinct import key",
                template.name
            );
            assert!(find(template.name).is_some());
        }
        assert!(find("us-gaap").is_none());
    }
}
