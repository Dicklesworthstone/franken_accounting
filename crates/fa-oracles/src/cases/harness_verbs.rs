//! Every (verb, subcommand) the case runner invokes (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.3; bead fa-yugf.15, A7a). The runner checks each against
//! `fa_cli::verbs::registry()` before it creates a book, so a renamed verb
//! fails the case before any book exists.

/// The runner's verbs, in pipeline order.
pub const HARNESS_VERBS: &[(&str, Option<&str>)] = &[
    ("book", Some("create")),
    ("period", Some("create")),
    ("period", Some("list")),
    ("period", Some("open")),
    ("period", Some("soft-close")),
    ("period", Some("close")),
    ("period", Some("lock")),
    ("chart", Some("import")),
    ("chart", Some("role")),
    ("party", Some("add")),
    ("party", Some("relate")),
    ("engagement", Some("open")),
    ("engagement", Some("file")),
    ("document", Some("add")),
    ("document", Some("attest")),
    ("post", None),
    ("entry", Some("show")),
    ("commit", None),
    ("allocate", None),
    ("batch", None),
    ("approve", None),
    ("event", Some("record")),
    ("rule", Some("check")),
    ("rule", Some("propose")),
    ("rule", Some("backtest")),
    ("migrate", Some("import")),
    ("procedure", Some("run")),
    ("finding", Some("record")),
    ("finding", Some("list")),
    ("tb", None),
];

/// The entries of `verbs` that a registry's (name, subcommands) rows do not
/// carry, each rendered `<verb>[ <subcommand>]`.
#[must_use]
pub fn missing<'v>(
    verbs: &'v [(&'v str, Option<&'v str>)],
    registry: &[(String, Vec<String>)],
) -> Vec<String> {
    verbs
        .iter()
        .filter(|(name, sub)| {
            !registry
                .iter()
                .any(|(n, subs)| n == name && sub.is_none_or(|s| subs.iter().any(|x| x == s)))
        })
        .map(|(name, sub)| match sub {
            Some(s) => format!("{name} {s}"),
            None => (*name).to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VERBS: &str = include_str!("../../../../registries/verbs.toml");

    fn registry() -> Vec<(String, Vec<String>)> {
        let doc = fa_registry::toml::parse(VERBS).expect("verbs.toml");
        doc.arrays
            .get("verb")
            .expect("[[verb]] rows")
            .iter()
            .map(|t| {
                let name = t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let subs = t
                    .get("subcommands")
                    .and_then(|v| v.as_array())
                    .unwrap_or(&[])
                    .iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect();
                (name, subs)
            })
            .collect()
    }

    #[test]
    fn every_harness_verb_is_in_verbs_toml() {
        assert_eq!(missing(HARNESS_VERBS, &registry()), Vec::<String>::new());
    }

    #[test]
    fn a_renamed_verb_is_named_missing() {
        let renamed = [
            ("periods", Some("open")),
            ("post", None),
            ("period", Some("reopenn")),
        ];
        assert_eq!(
            missing(&renamed, &registry()),
            ["periods open", "period reopenn"]
        );
    }
}
