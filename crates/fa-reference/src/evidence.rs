//! The evidence-minimum oracle (plan §9.2–§9.3, FA-INV-05 clause
//! `evidence-minimum`).
//!
//! An independent, deliberately literal model of the posting kernel's
//! evidence law. It shares only the registry rows (`evidence_policy.toml`)
//! with `fa-journal`; the evaluation is written from the plan text, not from
//! the kernel's code. Documents are plain records keyed by an integer
//! surrogate, kinds and grades are plain registry names, and the refusal
//! codes are this module's own string constants, so a renumbering or a
//! re-ordering on either side is a differential failure.
//!
//! The law, in the order the kernel applies it:
//! 1. every citation's role is a registered role (else `STRUCTURE`);
//! 2. every cited document is held (else `EVIDENCE_UNKNOWN`), and the
//!    citation's commitment is the document's (else `EVIDENCE_COMMIT`),
//!    checked for every citation, in citation order;
//! 3. a class whose row requires documents needs at least `min_documents`
//!    distinct cited documents of an admissible kind whose grade is not
//!    self-sourced (`AgentUpload`, `Generated`: they count only once a
//!    reviewer attests them, which this build cannot record — fa-g21). When
//!    the self-sourced ones would have met it: `SELF_SOURCED`; otherwise
//!    `EVIDENCE_MINIMUM`. A class resting on its target, and a control class,
//!    needs none.

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::evidence_policy::{EvidencePolicy, KindSet, Requirement};

pub const STRUCTURE: &str = "FA-REF-100";
pub const EVIDENCE_MINIMUM: &str = "FA-REF-080";
pub const EVIDENCE_UNKNOWN: &str = "FA-REF-081";
pub const EVIDENCE_COMMIT: &str = "FA-REF-082";
pub const SELF_SOURCED: &str = "FA-REF-086";

/// The registry rows the oracle reads (`evidence_policy.toml`).
pub fn embedded_policy() -> Result<EvidencePolicy, fa_registry::RegistryError> {
    EvidencePolicy::embedded()
}

/// A document the oracle's book holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Doc {
    /// A registered kind name (`Invoice`, `Rate`, …).
    pub kind: String,
    /// A registered grade name (`HumanUpload`, `AgentUpload`, …).
    pub grade: String,
    /// Its public commitment, as the oracle recorded it at intake.
    pub commit: [u8; 32],
}

/// One citation, in the order the entry carries them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Citation {
    /// The surrogate of the document cited (a key into the held documents).
    pub doc: u64,
    pub commit: [u8; 32],
    pub role: u8,
}

fn admits(policy: &EvidencePolicy, set: &KindSet, kind_name: &str) -> bool {
    match set {
        KindSet::Any => policy.kind_by_name(kind_name).is_some(),
        KindSet::Only(tags) => tags
            .iter()
            .any(|t| policy.kind_by_tag(*t).is_some_and(|k| k.name == kind_name)),
    }
}

/// The oracle's verdict for an entry of `class` citing `citations` against
/// the held `docs`: `None` admits; otherwise the refusal code.
#[must_use]
pub fn verdict(
    policy: &EvidencePolicy,
    class: &str,
    docs: &BTreeMap<u64, Doc>,
    citations: &[Citation],
) -> Option<&'static str> {
    // 1. Roles.
    if citations
        .iter()
        .any(|c| policy.role_by_tag(c.role).is_none())
    {
        return Some(STRUCTURE);
    }
    // 2. Every citation names a held document under its commitment.
    for c in citations {
        let Some(doc) = docs.get(&c.doc) else {
            return Some(EVIDENCE_UNKNOWN);
        };
        if doc.commit != c.commit {
            return Some(EVIDENCE_COMMIT);
        }
    }
    // 3. The class's minimum over distinct documents.
    let Some(row) = policy.minimum(class) else {
        return Some(EVIDENCE_MINIMUM);
    };
    if row.requirement != Requirement::Documents {
        return None;
    }
    let distinct: BTreeSet<u64> = citations.iter().map(|c| c.doc).collect();
    let mut counted = 0usize;
    let mut admissible = 0usize;
    for id in &distinct {
        let doc = &docs[id];
        if !admits(policy, &row.kinds, &doc.kind) {
            continue;
        }
        admissible += 1;
        let self_sourced = policy
            .grade_by_name(&doc.grade)
            .is_none_or(|g| g.self_sourced);
        if !self_sourced {
            counted += 1;
        }
    }
    let needed = usize::from(row.min_documents);
    if counted >= needed {
        None
    } else if admissible >= needed {
        Some(SELF_SOURCED)
    } else {
        Some(EVIDENCE_MINIMUM)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(kind: &str, grade: &str, commit: u8) -> Doc {
        Doc {
            kind: kind.into(),
            grade: grade.into(),
            commit: [commit; 32],
        }
    }

    #[test]
    fn the_literal_law_on_hand_picked_cases() {
        let p = EvidencePolicy::embedded().unwrap();
        let docs: BTreeMap<u64, Doc> = [
            (1, doc("Invoice", "HumanUpload", 1)),
            (2, doc("Invoice", "AgentUpload", 2)),
            (3, doc("Rate", "HumanUpload", 3)),
        ]
        .into_iter()
        .collect();
        let cite = |d: u64, c: u8, role: u8| Citation {
            doc: d,
            commit: [c; 32],
            role,
        };
        assert_eq!(verdict(&p, "Original", &docs, &[cite(1, 1, 1)]), None);
        assert_eq!(verdict(&p, "Original", &docs, &[]), Some(EVIDENCE_MINIMUM));
        assert_eq!(
            verdict(&p, "Original", &docs, &[cite(2, 2, 1)]),
            Some(SELF_SOURCED)
        );
        assert_eq!(
            verdict(&p, "Original", &docs, &[cite(9, 9, 1)]),
            Some(EVIDENCE_UNKNOWN)
        );
        assert_eq!(
            verdict(&p, "Original", &docs, &[cite(1, 7, 1)]),
            Some(EVIDENCE_COMMIT)
        );
        // A right citation then a wrong one of the same document.
        assert_eq!(
            verdict(&p, "Original", &docs, &[cite(1, 1, 1), cite(1, 7, 2)]),
            Some(EVIDENCE_COMMIT)
        );
        assert_eq!(
            verdict(&p, "Original", &docs, &[cite(1, 1, 99)]),
            Some(STRUCTURE)
        );
        assert_eq!(
            verdict(&p, "Revaluation", &docs, &[cite(1, 1, 1)]),
            Some(EVIDENCE_MINIMUM)
        );
        assert_eq!(verdict(&p, "Revaluation", &docs, &[cite(3, 3, 3)]), None);
        assert_eq!(verdict(&p, "Reversal", &docs, &[]), None);
        assert_eq!(verdict(&p, "PeriodControl", &docs, &[]), None);
    }
}
