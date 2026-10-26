//! Admission for the independent open-item interpreter's supported inputs.
//!
//! This checks the captured source identities before a bundle or receipt is
//! issued. It neither changes journal records nor substitutes an identity or
//! dimension default. Accounting replay and complete-prefix authentication
//! remain separate requirements of report production.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::refusal::{Outcome, Refusal, exit};
use fa_model::{EntryClass, SupersessionKind};
use fgdb_types::{CommitSeq, VId};

use crate::{Journal, Record, code};

fn unsupported(message: impl Into<String>) -> Refusal {
    Refusal::new(
        code::SCOPE_UNSUPPORTED,
        exit::REFUSAL,
        message,
        "plan §5.7 / §13.3 (the independent open-item interpreter must reproduce original identities and application dimensions)",
        "replay the retained report in its source book; preserve its certificate until an offline interpreter supports this historical representation",
    )
}

/// Refuse source representations that the current portable OpenItems fold
/// cannot reproduce. The caller must already have admitted whole-prefix read
/// and produce authority and replayed the native certificate.
///
/// Only entry records through the certificate's actual `known_at` participate;
/// a later checkpoint or instant-resolution frontier does not widen the report.
/// Applications throughout that prefix require identical dimension vectors,
/// since the bundle does not authenticate a book's default legal entity.
/// Historical replacement identities outside a filtered report are harmless
/// unless an application/reversal references them or canonical identities
/// collide. This check therefore does not reject an entire historical book
/// merely because an unrelated account contains an older replacement.
pub fn check_scope(
    journal: &Journal,
    known_at: CommitSeq,
    account_filter: Option<VId>,
) -> Outcome<()> {
    if known_at > journal.through_seq {
        return Ok(Err(unsupported(
            "the open-item report's known-at exceeds the captured journal prefix",
        )));
    }
    let mut entries = BTreeMap::new();
    for leaf in &journal.leaves {
        if !leaf.envelope.is_entry() || leaf.envelope.commit_seq > known_at {
            continue;
        }
        let Record::Entry(entry) = leaf.record()? else {
            return Err(KernelError::Corrupt(
                "an entry envelope contains another record kind".into(),
            ));
        };
        if entries.insert(leaf.vid, entry).is_some() {
            return Err(KernelError::Corrupt(
                "the captured journal repeats an entry identity".into(),
            ));
        }
    }

    let mut referenced = BTreeSet::new();
    for entry in entries.values() {
        if entry.proposal.class == EntryClass::REVERSAL {
            let [supersession] = entry.proposal.supersession.as_slice() else {
                return Err(KernelError::Corrupt(
                    "an open-item reversal lacks its unique target".into(),
                ));
            };
            if supersession.kind != SupersessionKind::Reverses {
                return Err(KernelError::Corrupt(
                    "an open-item reversal has another supersession kind".into(),
                ));
            }
            referenced.insert(supersession.target.vid);
        }
        for leg in &entry.proposal.legs {
            referenced.extend(leg.settles.iter().map(|settlement| settlement.target.vid));
        }
    }

    let mut canonical_ids = BTreeMap::new();
    for (&source, entry) in &entries {
        let canonical = if entry.proposal.class == EntryClass::REPLACEMENT {
            let [supersession] = entry.proposal.supersession.as_slice() else {
                return Err(KernelError::Corrupt(
                    "an open-item replacement lacks its unique target".into(),
                ));
            };
            if supersession.kind != SupersessionKind::Replaces {
                return Err(KernelError::Corrupt(
                    "an open-item replacement has another supersession kind".into(),
                ));
            }
            fa_journal::rows::replacement_vid(supersession.target.vid)
        } else {
            source
        };
        if let Some(other) = canonical_ids.insert(canonical, source) {
            return Ok(Err(unsupported(format!(
                "entries {:032x} and {:032x} collide under the portable replacement identity law",
                other.0, source.0
            ))));
        }
        if source != canonical
            && (account_filter.is_none_or(|account| {
                entry
                    .proposal
                    .legs
                    .iter()
                    .any(|leg| leg.account_ref == account)
            }) || referenced.contains(&source))
        {
            return Ok(Err(unsupported(format!(
                "replacement {:032x} uses a historical key-derived identity; portable open items require its target-derived identity {:032x} and cannot substitute it",
                source.0, canonical.0
            ))));
        }
    }

    // The independent verifier checks all applications in the authenticated
    // prefix, including those outside the output's account filter and those
    // later undone. Applying the filter here would emit unverifiable bundles.
    for (&source, entry) in &entries {
        for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
            for settlement in &leg.settles {
                let target = entries.get(&settlement.target.vid).ok_or_else(|| {
                    KernelError::Corrupt("an open-item application target is absent".into())
                })?;
                let target_leg = target
                    .proposal
                    .legs
                    .get(usize::from(settlement.ordinal))
                    .filter(|_| target.entry_digest == settlement.target.entry_digest)
                    .ok_or_else(|| {
                        KernelError::Corrupt(
                            "an open-item application target digest or ordinal differs".into(),
                        )
                    })?;
                if leg.dimension_set != target_leg.dimension_set {
                    return Ok(Err(unsupported(format!(
                        "entry {:032x} leg {ordinal} applies to {:032x} leg {} with different dimension tags; portable open items cannot authenticate implicit legal-entity normalization from BookSpec defaults",
                        source.0, settlement.target.vid.0, settlement.ordinal
                    ))));
                }
            }
        }
    }
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::{
        Entry, EntryOrigin, EntryPayload, Erasable, Id128, LegPayload, Oid, SealKey, Settlement,
        Supersession, entry_vid,
    };
    use fa_money::{Amount, Side, UnitId};
    use fa_time::DateDay;

    const BOOK: Id128 = Id128([0x93; 16]);
    const PRINCIPAL: VId = VId(7);
    const CASH: VId = VId(10);
    const OFFSET: VId = VId(20);
    const OTHER: VId = VId(30);
    type Row = (VId, Entry, CommitSeq);

    // Detached canonical journals exercise transport admission only. They do
    // not claim to prove posting-law or principal admission for these fixtures.
    fn payload(seq: u64, account: VId, dimensions: &[(u32, VId)]) -> EntryPayload {
        let mut legs = vec![
            LegPayload::simple(Side::Debit, account, Amount::new(UnitId(1), 100)),
            LegPayload::simple(Side::Credit, OFFSET, Amount::new(UnitId(1), 100)),
        ];
        for leg in &mut legs {
            leg.dimension_set = dimensions.to_vec();
        }
        EntryPayload {
            schema_minor: 1,
            book_id: BOOK,
            branch_id: Id128::TRUNK,
            class: EntryClass::ORIGINAL,
            effective_date: DateDay(20_000),
            document_date: None,
            description: Erasable::seal(
                &"portable open-item scope".to_string(),
                None,
                &SealKey([0x33; 32]),
                [1; 32],
                [2; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: seq.to_le_bytes().to_vec(),
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
        }
    }

    fn seal(proposal: EntryPayload, seq: u64) -> Row {
        let identity = entry_vid(BOOK, &PRINCIPAL.0.to_le_bytes(), &proposal.idempotency_key);
        (
            identity,
            proposal.seal(Vec::new(), None).unwrap(),
            CommitSeq(seq),
        )
    }

    fn original(seq: u64, account: VId, dimensions: &[(u32, VId)]) -> Row {
        seal(payload(seq, account, dimensions), seq)
    }

    fn application(target: &Row, seq: u64, dimensions: &[(u32, VId)]) -> Row {
        let mut proposal = payload(seq, target.1.proposal.legs[0].account_ref, dimensions);
        for leg in &mut proposal.legs {
            leg.side = if leg.side == Side::Debit {
                Side::Credit
            } else {
                Side::Debit
            };
        }
        proposal.legs[0].settles.push(Settlement {
            target: target.1.entry_ref(target.0),
            ordinal: 0,
            amount: Amount::new(UnitId(1), 100),
        });
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        seal(proposal, seq)
    }

    fn replacement(target: &Row, seq: u64, legacy: bool) -> Row {
        let mut proposal = payload(seq, target.1.proposal.legs[0].account_ref, &[]);
        proposal.class = EntryClass::REPLACEMENT;
        proposal.supersession.push(Supersession {
            target: target.1.entry_ref(target.0),
            kind: SupersessionKind::Replaces,
            reason_code: 1,
        });
        let mut row = seal(proposal, seq);
        if !legacy {
            row.0 = fa_journal::rows::replacement_vid(target.0);
        }
        row
    }

    fn reversal(target: &Row, seq: u64) -> Row {
        let mut proposal = target.1.proposal.clone();
        proposal.class = EntryClass::REVERSAL;
        proposal.idempotency_key = seq.to_le_bytes().to_vec();
        proposal.supersession = vec![Supersession {
            target: target.1.entry_ref(target.0),
            kind: SupersessionKind::Reverses,
            reason_code: 1,
        }];
        for leg in &mut proposal.legs {
            leg.side = if leg.side == Side::Debit {
                Side::Credit
            } else {
                Side::Debit
            };
            leg.settles.clear();
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        let mut row = seal(proposal, seq);
        row.0 = fa_journal::rows::reversal_vid(target.0);
        row
    }

    fn journal(rows: Vec<Row>) -> Journal {
        let through = rows
            .iter()
            .map(|row| row.2)
            .max()
            .unwrap_or(CommitSeq::ORIGIN);
        Journal::from_records(BOOK, through, rows).unwrap()
    }

    #[test]
    fn open_items_scope_accepts_exact_dimensions_and_refuses_unbound_normalization() {
        let entity = [(fa_model::LEGAL_ENTITY_DIMENSION, VId(99))];
        for dimensions in [&[][..], &entity[..]] {
            let invoice = original(1, CASH, dimensions);
            let receipt = application(&invoice, 2, dimensions);
            check_scope(&journal(vec![invoice, receipt]), CommitSeq(2), Some(CASH))
                .unwrap()
                .unwrap();
        }
        for (invoice_dimensions, receipt_dimensions) in
            [(&[][..], &entity[..]), (&entity[..], &[][..])]
        {
            let invoice = original(1, CASH, invoice_dimensions);
            let receipt = application(&invoice, 2, receipt_dimensions);
            let source = journal(vec![invoice, receipt]);
            for filter in [None, Some(CASH), Some(OTHER)] {
                let refusal = check_scope(&source, CommitSeq(2), filter)
                    .unwrap()
                    .unwrap_err();
                assert_eq!(refusal.code, code::SCOPE_UNSUPPORTED);
                assert!(
                    refusal
                        .message
                        .contains("implicit legal-entity normalization")
                );
            }
            check_scope(&source, CommitSeq(1), None).unwrap().unwrap();
        }
    }

    #[test]
    fn open_items_scope_preserves_canonical_replacements_and_unrelated_legacy_history() {
        let invoice = original(1, CASH, &[]);
        let undo = reversal(&invoice, 2);
        let canonical = replacement(&invoice, 2, false);
        let source = journal(vec![invoice.clone(), undo.clone(), canonical]);
        check_scope(&source, CommitSeq(2), None).unwrap().unwrap();

        let legacy = replacement(&invoice, 2, true);
        let source = journal(vec![invoice, undo, legacy]);
        for filter in [None, Some(CASH)] {
            let refusal = check_scope(&source, CommitSeq(2), filter)
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, code::SCOPE_UNSUPPORTED);
            assert!(refusal.message.contains("historical key-derived identity"));
        }
        check_scope(&source, CommitSeq(2), Some(OTHER))
            .unwrap()
            .unwrap();
        check_scope(&source, CommitSeq(1), None).unwrap().unwrap();
    }

    #[test]
    fn open_items_scope_refuses_legacy_targets_even_outside_the_account_filter() {
        let invoice = original(1, CASH, &[]);
        let undo = reversal(&invoice, 2);
        let legacy = replacement(&invoice, 2, true);
        for later in [application(&legacy, 3, &[]), reversal(&legacy, 3)] {
            let source = journal(vec![invoice.clone(), undo.clone(), legacy.clone(), later]);
            check_scope(&source, CommitSeq(2), Some(OTHER))
                .unwrap()
                .unwrap();
            let refusal = check_scope(&source, CommitSeq(3), Some(OTHER))
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, code::SCOPE_UNSUPPORTED);
            assert!(refusal.message.contains("historical key-derived identity"));
        }
    }

    #[test]
    fn open_items_scope_rejects_canonical_alias_collisions_without_widening_history() {
        let invoice = original(1, CASH, &[]);
        let first = replacement(&invoice, 2, true);
        let second = replacement(&invoice, 3, true);
        assert_ne!(first.0, second.0);
        let source = journal(vec![invoice, first, second]);
        check_scope(&source, CommitSeq(2), Some(OTHER))
            .unwrap()
            .unwrap();
        let refusal = check_scope(&source, CommitSeq(3), Some(OTHER))
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, code::SCOPE_UNSUPPORTED);
        assert!(refusal.message.contains("collide"));
        assert_eq!(
            check_scope(&source, CommitSeq(4), None)
                .unwrap()
                .unwrap_err()
                .code,
            code::SCOPE_UNSUPPORTED
        );
    }
}
