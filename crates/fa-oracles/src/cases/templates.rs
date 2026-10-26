//! The closed `statement_template` ids (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §0.3, §5.1, §12.3; bead fa-yugf.5, A1c).
//!
//! Every sentence a case renders is generated from one of these ids, never
//! hand-written (§12.3: "There is no free-text path"). The plan names the
//! templates without ids, so A1c fixes them; A3c (K-ASSERT, K-ERRRATE) and
//! A14 (the template texts) key on them. Each expectation type accepts only
//! the ids of its own prefix.

/// Every template id.
pub const TEMPLATE_IDS: [&str; 17] = [
    "D.detection",
    "D.restates_characterization",
    "P.first_refusal",
    "T.bridge",
    "T.footing",
    "T.per_account",
    "T.allocation",
    "T.delta",
    "T.rule",
    "T.round_trip",
    "C.band",
    "R.read_back",
    "N.no_refusal",
    "N.no_finding",
    "N.exact_gap",
    "CF.counterfactual",
    "NOTE.observation",
];

/// Whether `id` is a template of the type `prefix` (`D`, `P`, `T`, `C`,
/// `R`, `N`, `CF` or `NOTE`).
#[must_use]
pub fn of_type(id: &str, prefix: &str) -> bool {
    TEMPLATE_IDS.contains(&id) && id.split_once('.').is_some_and(|(p, _)| p == prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_has_a_known_type_prefix_and_ids_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for id in TEMPLATE_IDS {
            assert!(seen.insert(id), "{id} is listed twice");
            let (prefix, name) = id.split_once('.').expect("<type>.<name>");
            assert!(
                ["D", "P", "T", "C", "R", "N", "CF", "NOTE"].contains(&prefix) && !name.is_empty(),
                "{id}"
            );
        }
        assert!(of_type("T.round_trip", "T"));
        assert!(!of_type("T.round_trip", "D"));
        assert!(!of_type("T.made_up", "T"));
    }
}
