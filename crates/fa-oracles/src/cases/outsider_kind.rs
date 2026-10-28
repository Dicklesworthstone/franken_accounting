//! The outsider route of each T read (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §5.3, §12.1; bead fa-yugf.28, A12).
//!
//! A T passes only with the outsider check of its read kind. Every read verb
//! the runner reads maps to exactly one route; a verb outside the table
//! leaves its T UNRUN `reason=outsider`, never PASS.
//!
//! - `report`: the read's certificates are bundled (`fa bundle produce
//!   --certificate`), verified offline (`fa-verify bundle` and `fa-verify
//!   report`, whose recomputation must equal B), and replayed byte for byte
//!   (`fa replay`). A `balance` read's certificates are its `fa explain
//!   balance` reports, one per period of its fold: a report bundle carries a
//!   balance explanation, and fa-verify recomputes its period cells.

/// The read verbs the runner reads (A7b).
pub const READ_VERBS: [&str; 4] = ["balance", "balance-sheet", "income-statement", "tb"];

/// An outsider route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutsiderKind {
    Report,
}

impl OutsiderKind {
    /// The route's name in the row's `outsider=<kind>:<verdict>` token.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Report => "report",
        }
    }
}

/// What fa-verify's report recomputes for a read verb, compared with B.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recomputed {
    /// The posted period cells of a balance explanation.
    Explanation,
    /// The trial-balance row of the read's account.
    TrialBalanceRow,
    /// The statement line, its current column.
    StatementLine,
}

/// The read verb's route and what its report recomputes.
#[must_use]
pub fn outsider_kind(verb: &str) -> Option<(OutsiderKind, Recomputed)> {
    match verb {
        "balance" => Some((OutsiderKind::Report, Recomputed::Explanation)),
        "tb" => Some((OutsiderKind::Report, Recomputed::TrialBalanceRow)),
        "balance-sheet" | "income-statement" => {
            Some((OutsiderKind::Report, Recomputed::StatementLine))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every read verb the runner reads has exactly one route; a verb it
    /// does not read has none, so its T stays UNRUN.
    #[test]
    fn every_t_read_verb_maps_to_one_outsider_kind() {
        for verb in READ_VERBS {
            assert!(outsider_kind(verb).is_some(), "{verb}");
        }
        assert_eq!(
            READ_VERBS.map(|v| outsider_kind(v).map(|(k, r)| (k.name(), r))),
            [
                Some(("report", Recomputed::Explanation)),
                Some(("report", Recomputed::StatementLine)),
                Some(("report", Recomputed::StatementLine)),
                Some(("report", Recomputed::TrialBalanceRow)),
            ]
        );
        assert_eq!(outsider_kind("gl-detail"), None);
    }
}
