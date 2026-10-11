//! Effective-date open-item snapshots, bounded by a recorded journal prefix.
//!
//! Filter immutable entries before evaluating reversal lineage or settlement
//! applications. A February receipt must not reduce a January balance, even
//! when both were already recorded at the selected known-at frontier.
//!
//! The existing kernel can admit links whose target has a later effective
//! date. When a cutoff splits such a link this reader refuses the selection:
//! silently subtracting an application whose target was excluded would lose
//! an unapplied balance. Classifying those cross-cutoff effects requires a
//! separate accounting law; this reader does not invent one.

use std::collections::BTreeMap;

use fa_journal::genesis::BookContext;
use fa_model::{Entry, EntryClass, Id128, SupersessionKind};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use super::{OpenItem, carries_open_items, fold_open_items};
use crate::{KernelError, RegisterError, entries_at, resolve_known_at};

/// A literal payload fold at both a civil-date cutoff and a recorded prefix.
/// It is not a certified report or a view of today's mutable applied mirrors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenItemSnapshot {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    pub effective_through: DateDay,
    pub account: Option<VId>,
    pub items: Vec<OpenItem>,
}

/// Include effective dates through `effective_through` (inclusive). `None`
/// resolves known-at to the current frontier once, and records that sequence.
/// Migration activation is still judged by the selected recorded prefix.
pub fn open_items_as_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    account: Option<VId>,
    effective_through: DateDay,
    known_at: Option<CommitSeq>,
) -> Result<OpenItemSnapshot, RegisterError> {
    let known_at = resolve_known_at(db, known_at)?;
    let mut entries = entries_at(db, book, known_at)?;
    restrict_effective(&mut entries, account, effective_through)?;
    Ok(OpenItemSnapshot {
        book_id: book.book_id,
        known_at,
        effective_through,
        account,
        items: fold_open_items(&entries, account)?,
    })
}

fn restrict_effective(
    entries: &mut Vec<(VId, Entry, CommitSeq)>,
    account: Option<VId>,
    through: DateDay,
) -> Result<(), RegisterError> {
    let dates: BTreeMap<_, _> = entries
        .iter()
        .map(|(vid, entry, _)| (*vid, entry.proposal.effective_date))
        .collect();
    let check_target = |source: VId, target: VId, kind: &str| {
        let target_date = dates.get(&target).ok_or_else(|| {
            KernelError::Corrupt(format!(
                "{kind} from {source:?} names missing entry {target:?}"
            ))
        })?;
        if *target_date > through {
            return Err(RegisterError::InvalidSelection(format!(
                "effective cutoff {through} splits a {kind} from {source:?} to \
                 {target:?} effective {target_date}; select a cutoff including both \
                 entries or inspect the known-at-only open items"
            )));
        }
        Ok(())
    };
    for (vid, entry, _) in entries.iter() {
        if entry.proposal.effective_date > through {
            continue;
        }
        if carries_open_items(entry) {
            for leg in &entry.proposal.legs {
                if account.is_some_and(|a| a != leg.account_ref) {
                    continue;
                }
                for settlement in &leg.settles {
                    check_target(*vid, settlement.target.vid, "settlement")?;
                }
            }
        }
        if entry.proposal.class == EntryClass::REVERSAL
            && entry
                .proposal
                .legs
                .iter()
                .any(|leg| account.is_none_or(|a| a == leg.account_ref))
        {
            for supersession in &entry.proposal.supersession {
                if supersession.kind == SupersessionKind::Reverses {
                    check_target(*vid, supersession.target.vid, "reversal")?;
                }
            }
        }
    }
    entries.retain(|(_, entry, _)| entry.proposal.effective_date <= through);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::{
        EntryOrigin, EntryPayload, EntryRef, Erasable, LegPayload, Oid, SealKey, Settlement,
        Supersession,
    };
    use fa_money::{Amount, Side, UnitId};

    type Record = (VId, Entry, CommitSeq);
    const RECEIVABLE: VId = VId(100);
    const CASH: VId = VId(200);
    const REVENUE: VId = VId(300);

    fn date(text: &str) -> DateDay {
        DateDay::parse(text).unwrap()
    }

    fn leg(side: Side, account: VId, amount: i128) -> LegPayload {
        LegPayload::simple(side, account, Amount::new(UnitId(1), amount))
    }

    // Structurally sealed payload fixtures exercise the projection. They do
    // not claim kernel admission, evidence, authority, or durable execution.
    fn record(
        id: u64,
        day: &str,
        class: EntryClass,
        legs: Vec<LegPayload>,
        supersession: Vec<Supersession>,
    ) -> Record {
        let mut nonce = [0; 24];
        nonce[..8].copy_from_slice(&id.to_le_bytes());
        let payload = EntryPayload {
            schema_minor: 1,
            book_id: Id128([1; 16]),
            branch_id: Id128::TRUNK,
            class,
            effective_date: date(day),
            document_date: None,
            description: Erasable::seal(
                &"open-item projection fixture".to_string(),
                None,
                &SealKey([1; 32]),
                Default::default(),
                nonce,
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: id.to_le_bytes().to_vec(),
            origin: EntryOrigin::Intent {
                intent_oid: Oid([0; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(1),
            session_ref: None,
            evidence: Vec::new(),
            supersession,
            pending: None,
            external_ids: Vec::new(),
            tags: Vec::new(),
            extensions: Vec::new(),
        };
        (
            VId(u128::from(id)),
            payload.seal(Vec::new(), None).unwrap(),
            CommitSeq(id),
        )
    }

    fn reference(record: &Record) -> EntryRef {
        EntryRef {
            vid: record.0,
            entry_digest: record.1.entry_digest,
        }
    }

    fn invoice(day: &str) -> Record {
        record(
            1,
            day,
            EntryClass::ORIGINAL,
            vec![leg(Side::Debit, RECEIVABLE, 100), leg(Side::Credit, REVENUE, 100)],
            Vec::new(),
        )
    }

    fn receipt(invoice: &Record, day: &str) -> Record {
        let mut application = leg(Side::Credit, RECEIVABLE, 40);
        application.settles.push(Settlement {
            target: reference(invoice),
            ordinal: 0,
            amount: Amount::new(UnitId(1), 40),
        });
        record(
            2,
            day,
            EntryClass::ORIGINAL,
            vec![leg(Side::Debit, CASH, 40), application],
            Vec::new(),
        )
    }

    fn reverse(target: &Record, id: u64, day: &str) -> Record {
        let legs = target
            .1
            .proposal
            .legs
            .iter()
            .map(|original| {
                let side = match original.side {
                    Side::Debit => Side::Credit,
                    Side::Credit => Side::Debit,
                };
                leg(side, original.account_ref, original.amount.mantissa)
            })
            .collect();
        record(
            id,
            day,
            EntryClass::REVERSAL,
            legs,
            vec![Supersession {
                target: reference(target),
                kind: SupersessionKind::Reverses,
                reason_code: 1,
            }],
        )
    }

    fn at(entries: &[Record], day: &str) -> Vec<OpenItem> {
        let mut entries = entries.to_vec();
        restrict_effective(&mut entries, Some(RECEIVABLE), date(day)).unwrap();
        fold_open_items(&entries, Some(RECEIVABLE)).unwrap()
    }

    fn invoice_item(items: &[OpenItem]) -> &OpenItem {
        items.iter().find(|i| i.entry == VId(1)).unwrap()
    }

    #[test]
    fn later_receipts_do_not_change_an_earlier_effective_snapshot() {
        let invoice = invoice("2026-01-10");
        let receipt = receipt(&invoice, "2026-02-05");
        let history = vec![invoice, receipt];
        let january = at(&history, "2026-01-31");
        assert_eq!(invoice_item(&january).open, 100);
        assert!(invoice_item(&january).applications.is_empty());
        assert_eq!(january.len(), 1);
        assert_eq!(invoice_item(&at(&history, "2026-02-04")).open, 100);
        let february = at(&history, "2026-02-05");
        assert_eq!(invoice_item(&february).open, 60);
        assert_eq!(invoice_item(&february).applied, 40);
        assert_eq!(invoice_item(&february).applications.len(), 1);
        assert_eq!(
            february.iter().find(|i| i.entry == VId(2)).unwrap().open,
            0
        );
    }

    #[test]
    fn reversal_parity_is_evaluated_inside_the_effective_cutoff() {
        let invoice = invoice("2026-01-10");
        let receipt = receipt(&invoice, "2026-02-05");
        let reversal = reverse(&receipt, 3, "2026-03-01");
        let restore = reverse(&reversal, 4, "2026-04-01");
        let history = vec![invoice, receipt, reversal, restore];
        for (cutoff, expected) in [
            ("2026-01-31", 100),
            ("2026-02-28", 60),
            ("2026-03-31", 100),
            ("2026-04-01", 60),
        ] {
            assert_eq!(invoice_item(&at(&history, cutoff)).open, expected);
        }
        assert_eq!(
            at(&history, "2026-12-31"),
            fold_open_items(&history, Some(RECEIVABLE)).unwrap()
        );
    }

    #[test]
    fn a_recorded_prefix_stays_independent_of_the_effective_cutoff() {
        let invoice = invoice("2026-01-10");
        let receipt = receipt(&invoice, "2026-01-20");
        let history = vec![invoice, receipt];
        assert_eq!(invoice_item(&at(&history[..1], "2026-01-31")).open, 100);
        assert_eq!(invoice_item(&at(&history, "2026-01-31")).open, 60);
    }

    #[test]
    fn splitting_a_backdated_application_is_refused_in_the_affected_scope() {
        let invoice = invoice("2026-01-31");
        let receipt = receipt(&invoice, "2026-01-01");
        let history = vec![invoice, receipt];
        for account in [None, Some(RECEIVABLE)] {
            assert!(matches!(
                restrict_effective(&mut history.clone(), account, date("2026-01-15")),
                Err(RegisterError::InvalidSelection(_))
            ));
        }
        let mut cash = history.clone();
        restrict_effective(&mut cash, Some(CASH), date("2026-01-15")).unwrap();
        assert_eq!(fold_open_items(&cash, Some(CASH)).unwrap()[0].open, 40);
        assert_eq!(invoice_item(&at(&history, "2026-01-31")).open, 60);
    }

    #[test]
    fn splitting_a_backdated_reversal_is_not_silently_dropped() {
        let invoice = invoice("2026-01-31");
        let reversal = reverse(&invoice, 2, "2026-01-01");
        let history = vec![invoice, reversal];
        assert!(matches!(
            restrict_effective(&mut history.clone(), Some(RECEIVABLE), date("2026-01-15")),
            Err(RegisterError::InvalidSelection(_))
        ));
        assert!(at(&history, "2026-01-31").is_empty());
    }

    #[test]
    fn missing_link_targets_are_corruption_not_an_empty_report() {
        let invoice = invoice("2026-01-10");
        let receipt = receipt(&invoice, "2026-01-20");
        assert!(matches!(
            restrict_effective(&mut vec![receipt], None, date("2026-01-31")),
            Err(RegisterError::Kernel(KernelError::Corrupt(_)))
        ));
    }
}
