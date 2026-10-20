//! The evidence-minimum oracle (plan §9.2–§9.3, FA-INV-05 clause
//! `evidence-minimum`), with attestations.
//!
//! An independent, deliberately literal model of the posting kernel's
//! evidence law. It shares only the registry rows (`evidence_policy.toml`,
//! `reason_codes.toml`) with `fa-journal`; the evaluation is written from
//! the plan text, not from the kernel's code. Documents are plain records
//! keyed by an integer surrogate, principals are integers, kinds and grades
//! are plain registry names, attestations are plain maps, and the refusal
//! codes are this module's own string constants, so a renumbering or a
//! re-ordering on either side is a differential failure.
//!
//! The posting law, in the order the kernel applies it:
//! 1. every citation's role is a registered role (else `STRUCTURE`);
//! 2. every cited document is held (else `EVIDENCE_UNKNOWN`), the
//!    citation's commitment is the document's (else `EVIDENCE_COMMIT`), and
//!    the document's chain of custody is complete (else
//!    `CUSTODY_INCOMPLETE`): `len` events are present, the first a receipt
//!    from a registered source whose digest is the document's, each later
//!    one a transfer chained to its predecessor by its holder — checked for
//!    every citation, in citation order;
//! 3. a class whose row requires documents needs at least `min_documents`
//!    distinct cited documents of an admissible kind that count. A document
//!    counts when its grade is not self-sourced, or when it is (`AgentUpload`,
//!    `Generated`) and a principal reviewed it (`Reviewed`); a review by the
//!    principal that uploaded it is `SELF_REVIEW`.
//! 4. If they fall short and the row admits a ManualAssertion, the
//!    preparer's assertion over this proposal meets the minimum when its
//!    reason is registered (else `REASON_CODE`).
//! 5. Otherwise: `SELF_SOURCED` when the unreviewed self-sourced documents
//!    would have met it, else `EVIDENCE_MINIMUM`. A class resting on its
//!    target, and a control class, needs none.
//!
//! The recording laws: a review names a held document (else
//! `ATTESTATION_SUBJECT`) whose uploader is not the reviewer (else
//! `SELF_REVIEW`), compared against held documents (else
//! `ATTESTATION_SUBJECT`); an assertion carries a registered reason (else
//! `REASON_CODE`) for a class whose row admits one (else
//! `ATTESTATION_SUBJECT`).

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::RegistryError;
use fa_registry::evidence_policy::{EvidencePolicy, KindSet, Requirement};
use fa_registry::intake_sources::IntakeSources;
use fa_registry::reason_codes::ReasonCodes;

pub const STRUCTURE: &str = "FA-REF-100";
pub const EVIDENCE_MINIMUM: &str = "FA-REF-080";
pub const EVIDENCE_UNKNOWN: &str = "FA-REF-081";
pub const EVIDENCE_COMMIT: &str = "FA-REF-082";
pub const SELF_SOURCED: &str = "FA-REF-086";
pub const ATTESTATION_SUBJECT: &str = "FA-REF-110";
pub const SELF_REVIEW: &str = "FA-REF-111";
pub const REASON_CODE: &str = "FA-REF-112";
pub const DOCUMENT_INTAKE: &str = "FA-REF-083";
pub const GRADE_UNVERIFIED: &str = "FA-REF-084";
pub const CUSTODY_INCOMPLETE: &str = "FA-REF-114";
pub const RECEIPT_MISMATCH: &str = "FA-REF-115";
pub const NOT_CUSTODIAN: &str = "FA-REF-119";

/// The registry rows the oracle reads.
#[derive(Clone, Debug)]
pub struct Law {
    pub policy: EvidencePolicy,
    pub reasons: ReasonCodes,
    pub intake: IntakeSources,
}

impl Law {
    pub fn embedded() -> Result<Self, RegistryError> {
        Ok(Self {
            policy: EvidencePolicy::embedded()?,
            reasons: ReasonCodes::embedded()?,
            intake: IntakeSources::embedded()?,
        })
    }

    /// Whether a receipt from `source` opens a complete chain.
    #[must_use]
    pub fn source_registered(&self, source: &Source) -> bool {
        let text =
            |t: &str| !t.is_empty() && t.len() <= fa_registry::intake_sources::MAX_TEXT_BYTES;
        match source {
            Source::Upload => self.intake.kinds.contains("Upload"),
            Source::Email { message_id } => text(message_id) && self.intake.kinds.contains("Email"),
            Source::Connector { name, version } => {
                self.intake.kinds.contains("Connector")
                    && self
                        .intake
                        .connectors
                        .contains(&(name.clone(), version.clone()))
            }
            Source::Scan { device } => {
                self.intake.kinds.contains("Scan") && self.intake.devices.contains(device)
            }
        }
    }

    /// The chain is complete (module docs, step 2).
    #[must_use]
    pub fn custody_complete(&self, custody: &Custody) -> bool {
        if custody.len == 0 {
            return false;
        }
        (0..custody.len).all(|i| match (i, custody.events.get(&i)) {
            (
                0,
                Some(Event::Receipt {
                    source,
                    digest_matches,
                }),
            ) => *digest_matches && self.source_registered(source),
            (
                1..,
                Some(Event::Transfer {
                    chained,
                    from_holder,
                }),
            ) => *chained && *from_holder,
            _ => false,
        })
    }

    fn reason_registered(&self, reason: u16) -> bool {
        self.reasons
            .rows
            .iter()
            .any(|r| r.scope == "manual_assertion" && r.code == reason)
    }

    /// Whether `class`'s row requires documents and admits an assertion.
    fn admits_assertion(&self, class: &str) -> bool {
        self.policy
            .minimum(class)
            .is_some_and(|m| m.requirement == Requirement::Documents && m.manual_assertion)
    }
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
    /// The principal that uploaded it.
    pub uploader: u64,
    /// Its chain of custody.
    pub custody: Custody,
}

/// Where a document entered the book, as the oracle records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Upload,
    Connector { name: String, version: String },
    Email { message_id: String },
    Scan { device: String },
}

/// One custody event, as the oracle records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// Event 0: the receipt's source, and whether its digest is the
    /// document's commitment.
    Receipt {
        source: Source,
        digest_matches: bool,
    },
    /// A later event: whether it chains to its predecessor, and whether it
    /// was made by the principal that held the document.
    Transfer { chained: bool, from_holder: bool },
}

/// A document's chain of custody: the length its mirror states and the
/// events present, by index (an absent index is a missing link).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Custody {
    pub len: u32,
    pub events: BTreeMap<u32, Event>,
}

impl Custody {
    /// The chain `fa document add` writes: one receipt from an upload.
    #[must_use]
    pub fn uploaded() -> Self {
        Self {
            len: 1,
            events: [(
                0,
                Event::Receipt {
                    source: Source::Upload,
                    digest_matches: true,
                },
            )]
            .into_iter()
            .collect(),
        }
    }
}

/// One citation, in the order the entry carries them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Citation {
    /// The surrogate of the document cited (a key into the held documents).
    pub doc: u64,
    pub commit: [u8; 32],
    pub role: u8,
}

/// The attestations the posting law reads, as plain maps.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Attestations {
    /// Document surrogate → the principal whose Reviewed attestation names it.
    pub reviews: BTreeMap<u64, u64>,
    /// The reason code of the preparer's ManualAssertion over this proposal.
    pub manual: Option<u16>,
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
/// the held `docs` and the recorded `attestations`: `None` admits;
/// otherwise the refusal code.
#[must_use]
pub fn verdict(
    law: &Law,
    class: &str,
    docs: &BTreeMap<u64, Doc>,
    citations: &[Citation],
    attestations: &Attestations,
) -> Option<&'static str> {
    let policy = &law.policy;
    // 1. Roles.
    if citations
        .iter()
        .any(|c| policy.role_by_tag(c.role).is_none())
    {
        return Some(STRUCTURE);
    }
    // 2. Every citation names a held document under its commitment, with a
    //    complete chain of custody.
    for c in citations {
        let Some(doc) = docs.get(&c.doc) else {
            return Some(EVIDENCE_UNKNOWN);
        };
        if doc.commit != c.commit {
            return Some(EVIDENCE_COMMIT);
        }
        if !law.custody_complete(&doc.custody) {
            return Some(CUSTODY_INCOMPLETE);
        }
    }
    // 3. The class's minimum over distinct documents that count.
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
            continue;
        }
        match attestations.reviews.get(id) {
            Some(reviewer) if *reviewer == doc.uploader => return Some(SELF_REVIEW),
            Some(_) => counted += 1,
            None => {}
        }
    }
    let needed = usize::from(row.min_documents);
    if counted >= needed {
        return None;
    }
    // 4. The preparer's assertion, where the row admits one.
    if row.manual_assertion
        && let Some(reason) = attestations.manual
    {
        return if law.reason_registered(reason) {
            None
        } else {
            Some(REASON_CODE)
        };
    }
    // 5. Short.
    if admissible >= needed {
        Some(SELF_SOURCED)
    } else {
        Some(EVIDENCE_MINIMUM)
    }
}

/// The oracle's verdict on recording a review of `doc` by `reviewer`,
/// compared `against` other documents: `None` records it.
#[must_use]
pub fn review_verdict(
    docs: &BTreeMap<u64, Doc>,
    doc: u64,
    against: &[u64],
    reviewer: u64,
) -> Option<&'static str> {
    let Some(subject) = docs.get(&doc) else {
        return Some(ATTESTATION_SUBJECT);
    };
    if subject.uploader == reviewer {
        return Some(SELF_REVIEW);
    }
    if against.iter().any(|a| !docs.contains_key(a)) {
        return Some(ATTESTATION_SUBJECT);
    }
    None
}

/// The oracle's verdict on bringing a document in from `source`.
#[must_use]
pub fn intake_verdict(law: &Law, source: &Source) -> Option<&'static str> {
    (!law.source_registered(source)).then_some(DOCUMENT_INTAKE)
}

/// The oracle's verdict on `from` handing on a document `holder` holds.
#[must_use]
pub fn transfer_verdict(holder: u64, from: u64) -> Option<&'static str> {
    (holder != from).then_some(NOT_CUSTODIAN)
}

/// The oracle's verdict on presenting `presented` as the oids of a run that
/// recorded `recorded`: exactly the recorded set, in ascending order.
#[must_use]
pub fn receipt_verdict(
    recorded: &BTreeSet<[u8; 32]>,
    presented: &[[u8; 32]],
) -> Option<&'static str> {
    let canonical: Vec<[u8; 32]> = recorded.iter().copied().collect();
    (canonical.as_slice() != presented).then_some(RECEIPT_MISMATCH)
}

/// The oracle's verdict on the preparer recording an assertion with
/// `reason` over a proposal of `class`: `None` records it.
#[must_use]
pub fn manual_verdict(law: &Law, class: &str, reason: u16) -> Option<&'static str> {
    if !law.reason_registered(reason) {
        Some(REASON_CODE)
    } else if !law.admits_assertion(class) {
        Some(ATTESTATION_SUBJECT)
    } else {
        None
    }
}

/// The oracle's verdict on a capability-bound upload (plan §9.3, fa-vwf):
/// the provenance grade is derived from the session profile (`HumanUpload`
/// when `is_human`, else `AgentUpload`), and any caller assertion that
/// differs from the derived grade is refused with `GRADE_UNVERIFIED`.
pub fn upload_verdict(
    law: &Law,
    is_human: bool,
    asserted_grade: Option<&str>,
) -> Result<&'static str, &'static str> {
    let derived = if is_human {
        "HumanUpload"
    } else {
        "AgentUpload"
    };
    if !law.policy.grade_by_name(derived).is_some_and(|g| g.intake) {
        return Err(DOCUMENT_INTAKE);
    }
    if asserted_grade.is_some_and(|asserted| asserted != derived) {
        return Err(GRADE_UNVERIFIED);
    }
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(kind: &str, grade: &str, commit: u8, uploader: u64) -> Doc {
        Doc {
            kind: kind.into(),
            grade: grade.into(),
            commit: [commit; 32],
            uploader,
            custody: Custody::uploaded(),
        }
    }

    #[test]
    fn the_literal_law_on_hand_picked_cases() {
        let law = Law::embedded().unwrap();
        let none = Attestations::default();
        let docs: BTreeMap<u64, Doc> = [
            (1, doc("Invoice", "HumanUpload", 1, 7)),
            (2, doc("Invoice", "AgentUpload", 2, 7)),
            (3, doc("Rate", "HumanUpload", 3, 7)),
        ]
        .into_iter()
        .collect();
        let cite = |d: u64, c: u8, role: u8| Citation {
            doc: d,
            commit: [c; 32],
            role,
        };
        let v = |class: &str, citations: &[Citation]| verdict(&law, class, &docs, citations, &none);
        assert_eq!(v("Original", &[cite(1, 1, 1)]), None);
        assert_eq!(v("Original", &[]), Some(EVIDENCE_MINIMUM));
        assert_eq!(v("Original", &[cite(2, 2, 1)]), Some(SELF_SOURCED));
        assert_eq!(v("Original", &[cite(9, 9, 1)]), Some(EVIDENCE_UNKNOWN));
        assert_eq!(v("Original", &[cite(1, 7, 1)]), Some(EVIDENCE_COMMIT));
        // A right citation then a wrong one of the same document.
        assert_eq!(
            v("Original", &[cite(1, 1, 1), cite(1, 7, 2)]),
            Some(EVIDENCE_COMMIT)
        );
        assert_eq!(v("Original", &[cite(1, 1, 99)]), Some(STRUCTURE));
        assert_eq!(v("Revaluation", &[cite(1, 1, 1)]), Some(EVIDENCE_MINIMUM));
        assert_eq!(v("Revaluation", &[cite(3, 3, 3)]), None);
        assert_eq!(v("Reversal", &[]), None);
        assert_eq!(v("PeriodControl", &[]), None);
    }

    #[test]
    fn attestations_on_hand_picked_cases() {
        let law = Law::embedded().unwrap();
        let docs: BTreeMap<u64, Doc> = [
            (1, doc("Invoice", "HumanUpload", 1, 7)),
            (2, doc("Invoice", "AgentUpload", 2, 7)),
        ]
        .into_iter()
        .collect();
        let agent = [Citation {
            doc: 2,
            commit: [2; 32],
            role: 1,
        }];
        let with = |reviews: &[(u64, u64)], manual: Option<u16>| Attestations {
            reviews: reviews.iter().copied().collect(),
            manual,
        };
        let v = |class: &str, citations: &[Citation], a: &Attestations| {
            verdict(&law, class, &docs, citations, a)
        };
        assert_eq!(v("Original", &agent, &with(&[(2, 8)], None)), None);
        assert_eq!(
            v("Original", &agent, &with(&[(2, 7)], None)),
            Some(SELF_REVIEW)
        );
        assert_eq!(v("Original", &[], &with(&[], Some(1))), None);
        assert_eq!(v("Original", &[], &with(&[], Some(999))), Some(REASON_CODE));
        assert_eq!(
            v("Pending", &[], &with(&[], Some(1))),
            Some(EVIDENCE_MINIMUM)
        );
        assert_eq!(v("Original", &agent, &with(&[], Some(1))), None);
        assert_eq!(
            v("Pending", &agent, &with(&[], Some(1))),
            Some(SELF_SOURCED)
        );
        // Recording.
        assert_eq!(review_verdict(&docs, 2, &[1], 8), None);
        assert_eq!(review_verdict(&docs, 2, &[], 7), Some(SELF_REVIEW));
        assert_eq!(review_verdict(&docs, 9, &[], 8), Some(ATTESTATION_SUBJECT));
        assert_eq!(review_verdict(&docs, 2, &[9], 8), Some(ATTESTATION_SUBJECT));
        assert_eq!(manual_verdict(&law, "Original", 1), None);
        assert_eq!(manual_verdict(&law, "Original", 0), Some(REASON_CODE));
        assert_eq!(
            manual_verdict(&law, "Pending", 1),
            Some(ATTESTATION_SUBJECT)
        );
        assert_eq!(
            manual_verdict(&law, "Reversal", 1),
            Some(ATTESTATION_SUBJECT)
        );
    }
}
