//! Source-identity admission for portable literal balance explanations.
//!
//! The whole-period fold digest and contribution history contain physical
//! entry identities. The current prefix format authenticates only canonical
//! target-derived Replacement identities, so older key-derived identities must
//! be refused before a producer signs a bundle.

use std::collections::BTreeSet;

use fa_journal::KernelError;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_model::{EntryClass, SupersessionKind};
use fgdb_types::CommitSeq;

use crate::{Journal, Record, code};

fn unsupported(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::SCOPE_UNSUPPORTED,
        exit::REFUSAL,
        message,
        "plan §5.7 / §13.3 (portable explanations must reproduce original entry identities, whole-period folds and lineage)",
        "replay the retained explanation in its source book; preserve the certificate until an independent interpreter supports this historical identity representation",
    )
}

/// Check the certificate's actual known-at prefix after current whole-book
/// read/produce admission and native replay. A later checkpoint or retained
/// time frontier must not widen this test.
///
/// This first profile deliberately requires canonical Replacement identities
/// throughout the known-at prefix: the explanation hashes every monetary entry
/// in its selected period, and contribution lineage can name other periods.
/// The source book can still replay unsupported historical certificates.
pub fn check_scope(journal: &Journal, known_at: CommitSeq) -> Outcome<()> {
    if known_at > journal.through_seq {
        return Ok(Err(unsupported(
            "the explanation's known-at exceeds the captured journal prefix",
        )));
    }
    let mut identities = BTreeSet::new();
    for leaf in &journal.leaves {
        if !leaf.envelope.is_entry() || leaf.envelope.commit_seq > known_at {
            continue;
        }
        let Record::Entry(entry) = leaf.record()? else {
            return Err(KernelError::Corrupt(
                "an explanation entry envelope contains another record kind".into(),
            ));
        };
        if !identities.insert(leaf.vid) {
            return Err(KernelError::Corrupt(
                "the explanation prefix repeats an entry identity".into(),
            ));
        }
        if entry.proposal.class != EntryClass::REPLACEMENT {
            continue;
        }
        let [link] = entry.proposal.supersession.as_slice() else {
            return Err(KernelError::Corrupt(
                "an explanation Replacement lacks its unique target".into(),
            ));
        };
        if link.kind != SupersessionKind::Replaces {
            return Err(KernelError::Corrupt(
                "an explanation Replacement has another lineage kind".into(),
            ));
        }
        let canonical = fa_journal::rows::replacement_vid(link.target.vid);
        if leaf.vid != canonical {
            return Ok(Err(unsupported(format!(
                "replacement {:032x} uses a historical key-derived identity; portable explanations require its target-derived identity {:032x} and cannot substitute it",
                leaf.vid.0, canonical.0
            ))));
        }
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::{
        Entry, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey, Supersession,
        entry_vid,
    };
    use fa_money::{Amount, Side, UnitId};
    use fa_time::DateDay;
    use fgdb_types::VId;

    const BOOK: Id128 = Id128([0x94; 16]);
    const PRINCIPAL: VId = VId(7);

    fn original() -> (VId, Entry, CommitSeq) {
        let legs = vec![
            LegPayload::simple(Side::Debit, VId(10), Amount::new(UnitId(1), 100)),
            LegPayload::simple(Side::Credit, VId(20), Amount::new(UnitId(1), 100)),
        ];
        let proposal = EntryPayload {
            schema_minor: 1,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay(20_000),
            document_date: None,
            description: Erasable::seal(
                &"portable explanation scope".to_string(),
                None,
                &SealKey([0x34; 32]),
                [1; 32],
                [2; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: b"original".to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([4; 32]),
                intent_kind: 1,
            },
            principal_ref: PRINCIPAL,
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: None,
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        };
        let vid = entry_vid(BOOK, &PRINCIPAL.0.to_le_bytes(), &proposal.idempotency_key);
        (vid, proposal.seal(Vec::new(), None).unwrap(), CommitSeq(1))
    }

    #[test]
    fn canonical_replacement_sources_are_admitted_and_later_legacy_sources_do_not_widen_history() {
        let original = original();
        let mut proposal = original.1.proposal.clone();
        proposal.class = EntryClass::REPLACEMENT;
        proposal.idempotency_key = b"replacement".to_vec();
        proposal.supersession = vec![Supersession {
            target: original.1.entry_ref(original.0),
            kind: SupersessionKind::Replaces,
            reason_code: 1,
        }];
        let canonical = fa_journal::rows::replacement_vid(original.0);
        let legacy = entry_vid(BOOK, &PRINCIPAL.0.to_le_bytes(), &proposal.idempotency_key);
        let entry = proposal.seal(Vec::new(), None).unwrap();
        assert_ne!(canonical, legacy);
        for (id, supported) in [(canonical, true), (legacy, false)] {
            let journal = Journal::from_records(
                BOOK,
                CommitSeq(2),
                vec![original.clone(), (id, entry.clone(), CommitSeq(2))],
            )
            .unwrap();
            check_scope(&journal, CommitSeq(1)).unwrap().unwrap();
            let verdict = check_scope(&journal, CommitSeq(2)).unwrap();
            if supported {
                verdict.unwrap();
            } else {
                let refusal = verdict.unwrap_err();
                assert_eq!(refusal.code, code::SCOPE_UNSUPPORTED);
                assert!(refusal.message.contains("historical key-derived identity"));
            }
            assert_eq!(
                check_scope(&journal, CommitSeq(3))
                    .unwrap()
                    .unwrap_err()
                    .code,
                code::SCOPE_UNSUPPORTED,
            );
        }
    }

    #[test]
    fn v3_output_and_selector_must_agree_before_registry_profile_admission() {
        for (output, selector, explanation, open_items) in [
            ("fa:balance-explanation:v1", 0, true, false),
            ("fa:open-items:v1", 1, false, true),
            ("fa:balance-explanation:v1", 1, false, false),
            ("fa:open-items:v1", 0, false, false),
        ] {
            let mut writer = fa_model::Writer::new();
            writer
                .fixed(b"fa:report-certificate:v3")
                .str("fa-fold-over-prefix")
                .str("embedded-owner")
                .str(output)
                .fixed(&BOOK.0)
                .fixed(&Id128::TRUNK.0)
                .u64(2)
                .u8(selector);
            let header = writer.finish().unwrap();
            assert_eq!(crate::report::explanation_certificate(&header), explanation);
            assert_eq!(crate::report::open_items_certificate(&header), open_items);
        }
    }
}
