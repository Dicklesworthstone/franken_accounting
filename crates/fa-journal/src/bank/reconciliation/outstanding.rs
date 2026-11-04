//! Explicit cash-leg selections for outstanding-adjusted statement closes.
//! No monetary assertion from the caller reaches the retained claim.

use std::collections::BTreeSet;

use asupersync::fs::Vfs;
use fa_model::EntryRef;
use fa_money::Side;
use fgdb::Database;
use fgdb_types::CommitSeq;
use fgdb_types::context::PurposeContexts;

use super::super::verify;
use super::{checkpoint, invalid};
use crate::genesis::BookContext;
use crate::import::BankImportManifest;
use crate::refusal::Outcome;

/// Bound on an explicit outstanding selection; native payload bounds also apply.
pub const MAX_BANK_OUTSTANDING_ITEMS: usize = fa_model::limits::MAX_BANK_OUTSTANDING_ITEMS;

/// The immutable source and actual leg ordinal, with no caller-entered amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BankOutstandingLeg {
    pub entry_ref: EntryRef,
    pub leg_ordinal: u16,
}

/// One original-prefix cash contribution removed by the reconciliation bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BankOutstandingItem {
    pub entry_ref: EntryRef,
    pub leg_ordinal: u16,
    /// Positive for a debit deposit, negative for a credit payment/check.
    pub signed_amount: i128,
}

impl BankOutstandingItem {
    #[must_use]
    pub fn reference(&self) -> BankOutstandingLeg {
        BankOutstandingLeg {
            entry_ref: self.entry_ref,
            leg_ordinal: self.leg_ordinal,
        }
    }
}

pub(super) fn canonicalize(
    mut references: Vec<BankOutstandingLeg>,
) -> Result<Vec<BankOutstandingLeg>, crate::refusal::Refusal> {
    if references.len() > MAX_BANK_OUTSTANDING_ITEMS {
        return Err(invalid(format!(
            "an outstanding selection exceeds {MAX_BANK_OUTSTANDING_ITEMS} cash legs; no item may be omitted from the reviewed bridge"
        )));
    }
    references.sort_by_key(|reference| (reference.entry_ref.vid, reference.leg_ordinal));
    if references.windows(2).any(|pair| {
        (pair[0].entry_ref.vid, pair[0].leg_ordinal) == (pair[1].entry_ref.vid, pair[1].leg_ordinal)
    }) {
        return Err(invalid(
            "the outstanding selection repeats a cash Entry and leg ordinal",
        ));
    }
    Ok(references)
}

pub(super) fn derive<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    manifest: &BankImportManifest,
    at: CommitSeq,
    references: &[BankOutstandingLeg],
) -> Outcome<Vec<BankOutstandingItem>> {
    if references.is_empty() {
        return Ok(Ok(Vec::new()));
    }
    let active = match verify::claims_at(db, cx, book, at)? {
        Ok(active) => active,
        Err(refusal) => return Ok(Err(refusal)),
    };
    // All retained interpretations count: a match under another statement must
    // not be hidden by filtering this close's manifest or candidate window.
    let occupied: BTreeSet<_> = active
        .iter()
        .map(|recorded| {
            (
                recorded.confirmation.entry_ref.vid,
                recorded.confirmation.leg_ordinal,
            )
        })
        .collect();
    let mut selected = Vec::with_capacity(references.len());
    for reference in references {
        checkpoint(cx)?;
        if occupied.contains(&(reference.entry_ref.vid, reference.leg_ordinal)) {
            return Ok(Err(invalid(
                "an outstanding cash leg already has an active native bank confirmation at the reviewed prefix",
            )));
        }
        let source = match verify::source_entry(db, cx, book, reference.entry_ref, at)? {
            Ok(source) => source,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let Some(leg) = source
            .entry
            .proposal
            .legs
            .get(usize::from(reference.leg_ordinal))
        else {
            return Ok(Err(invalid(
                "an outstanding reference has no such original cash-leg ordinal",
            )));
        };
        if source.entry.proposal.effective_date > manifest.statement_date
            || leg.account_ref != manifest.account
            || leg.amount.unit != manifest.unit
            || leg.amount.mantissa <= 0
        {
            return Ok(Err(invalid(
                "an outstanding item must be a positive posted leg of the statement's exact cash account and currency, effective through its closing date",
            )));
        }
        let signed_amount = match leg.side {
            Side::Debit => Some(leg.amount.mantissa),
            Side::Credit => leg.amount.mantissa.checked_neg(),
        };
        let Some(signed_amount) = signed_amount else {
            return Ok(Err(invalid(
                "an outstanding cash contribution is outside the exact signed amount range",
            )));
        };
        selected.push(BankOutstandingItem {
            entry_ref: reference.entry_ref,
            leg_ordinal: reference.leg_ordinal,
            signed_amount,
        });
    }
    Ok(Ok(selected))
}
