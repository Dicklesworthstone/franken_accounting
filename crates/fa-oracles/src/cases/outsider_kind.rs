//! The outsider route of each T read (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §5.3, §12.1; bead fa-yugf.28, A12).
//!
//! A T passes only with the outsider check of its read kind. Every read verb
//! the runner reads maps to exactly one route; a verb outside the table
//! leaves its T UNRUN `reason=outsider`, never PASS.
//!
//! - `report`: the read's certificates are bundled (`fa bundle produce
//!   --certificate`), verified offline by `fa-verify report`, whose
//!   recomputation must equal B, and replayed byte for byte (`fa replay`).
//!   A report bundle (`fa:report-bundle:v1`) is not an evidence bundle:
//!   `fa-verify bundle` refuses it, so §12.1's `fa-verify bundle` step
//!   applies to account bundles, not to a certificate's. A `balance` read's
//!   certificates are its `fa explain balance` reports, one per period of
//!   its fold: a report bundle carries a balance explanation, and fa-verify
//!   recomputes its period cells.
//! - `replay`: certificates `fa bundle produce` does not take, replayed byte
//!   for byte with `fa replay C:<oid>`, whose output must hash to the digest
//!   the certificate recorded: the consolidation report (`fa consolidate
//!   --certify`). fa-verify has no consolidation recomputation, so this is a
//!   replay in the book, never an offline outsider verification.

/// The read verbs the runner reads (A7b).
pub const READ_VERBS: [&str; 5] = [
    "balance",
    "balance-sheet",
    "income-statement",
    "tb",
    "consolidate",
];

/// An outsider route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutsiderKind {
    Report,
    Replay,
}

impl OutsiderKind {
    /// The route's name in the row's `outsider=<kind>:<verdict>` token.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Replay => "replay",
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

/// The read verb's route and, on the report route, what its report
/// recomputes.
#[must_use]
pub fn outsider_kind(verb: &str) -> Option<(OutsiderKind, Option<Recomputed>)> {
    match verb {
        "balance" => Some((OutsiderKind::Report, Some(Recomputed::Explanation))),
        "tb" => Some((OutsiderKind::Report, Some(Recomputed::TrialBalanceRow))),
        "balance-sheet" | "income-statement" => {
            Some((OutsiderKind::Report, Some(Recomputed::StatementLine)))
        }
        "consolidate" => Some((OutsiderKind::Replay, None)),
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
                Some(("report", Some(Recomputed::Explanation))),
                Some(("report", Some(Recomputed::StatementLine))),
                Some(("report", Some(Recomputed::StatementLine))),
                Some(("report", Some(Recomputed::TrialBalanceRow))),
                Some(("replay", None)),
            ]
        );
        assert_eq!(outsider_kind("gl-detail"), None);
    }
}
