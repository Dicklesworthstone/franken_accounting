//! Teller bank, subledger, and three-way reconciliation engine: candidate
//! generation, replayable [`DecisionCard`] evaluation with pinned deterministic
//! fallback, immutable [`ReconciliationMatch`] objects with residual-entry
//! verification and supersession lineage, reconciliation register fold,
//! `reconciled_through` soft-lock check, and three-way (`PO <-> Receipt <-> Invoice`)
//! matching (plan §12.5, §15.9; bead `fa-2ek`).

use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
use fa_model::EntryRef;
use fa_model::{Oid, Writer, domain_digest};
#[cfg(test)]
use fa_money::Side;
use fa_money::{Amount, UnitId};
#[cfg(test)]
use fa_policy::DecisionReplayError;
use fa_policy::{
    BenefitInterval, Capability, DecisionCandidate, DecisionCard, DecisionFeature, DecisionKind,
    DecisionPolicyRow, Intent, Op, decide_bank_match,
};
use fa_time::DateDay;
use fgdb_types::{CommitSeq, VId};

use crate::entity::{EntityCellKey, RegisterEquals};

pub use fa_policy::bank_matching::{
    BANK_LINE_DOC_DOMAIN, BankStatementLine, BookCandidateEntry, MatcherConfig, RECON_MATCH_DOMAIN,
    ReconciliationError, ReconciliationMatch, ResidualExplanation, match_bank_lines,
    normalize_counterparty, normalize_reference, pinned_bank_candidate,
    verify_match_preserves_committed_amounts,
};

pub const RECON_FOLD_DOMAIN: &[u8] = b"fa:reconciliation-fold:v1";

/// Finding emitted when a bank line (such as a bank service fee) is unmatched
/// or has an unposted residual.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnpostedResidualFinding {
    pub bank_line_id: Oid,
    pub booking_date: DateDay,
    pub signed_cash_delta: i128,
    pub counterparty: String,
    pub reference: String,
}

/// Deterministic fold of a bank account's reconciliation register for one period
/// (plan §15.9, FA-INV-04; bead `fa-2ek`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationRegister {
    pub account: VId,
    pub period: String,
    pub unit: UnitId,
    pub book_opening: Amount,
    pub book_closing: Amount,
    pub statement_opening: Amount,
    pub statement_closing: Amount,
    pub active_matches: Vec<ReconciliationMatch>,
    pub unmatched_bank_lines: Vec<BankStatementLine>,
    pub outstanding_book_entries: Vec<BookCandidateEntry>,
    pub unposted_residuals: Vec<UnpostedResidualFinding>,
    /// `book_closing - Σ outstanding_book_entries + Σ unmatched_bank_lines`.
    pub adjusted_book_balance: Amount,
    /// True iff `adjusted_book_balance == statement_closing` AND `unmatched_bank_lines.is_empty()`.
    pub is_reconciled: bool,
    /// Highest statement booking date when `is_reconciled` is true.
    pub reconciled_through: Option<DateDay>,
    pub evaluated_known_at: CommitSeq,
    pub fold_digest: [u8; 32],
}

impl ReconciliationRegister {
    /// Convert this reconciliation register into a [`RegisterEquals`] claim
    /// binding `(cell_key, book_closing, as_of_effective, evaluated_known_at, fold_digest)`.
    #[must_use]
    pub fn to_register_equals(
        &self,
        entity: Option<String>,
        as_of_effective: DateDay,
    ) -> RegisterEquals {
        RegisterEquals {
            cell_key: EntityCellKey {
                account: self.account,
                unit_id: self.unit.0,
                period: self.period.clone(),
                entity,
            },
            amount: self.book_closing,
            as_of_effective,
            evaluated_known_at: self.evaluated_known_at,
            fold_digest: self.fold_digest,
        }
    }
}

/// Fold a [`ReconciliationRegister`] from the period's `bank_lines`, `book_entries`,
/// and journaled `matches` (honoring `supersedes_match_id` lineage).
#[allow(clippy::too_many_arguments)]
pub fn fold_reconciliation_register(
    account: VId,
    period: impl Into<String>,
    unit: UnitId,
    book_opening: Amount,
    book_closing: Amount,
    statement_opening: Amount,
    statement_closing: Amount,
    bank_lines: &[BankStatementLine],
    book_entries: &[BookCandidateEntry],
    matches: &[ReconciliationMatch],
    enforced_policy_epoch: [u8; 32],
    evaluated_known_at: CommitSeq,
) -> Result<ReconciliationRegister, ReconciliationError> {
    let period = period.into();
    for amt in [
        book_opening,
        book_closing,
        statement_opening,
        statement_closing,
    ] {
        if amt.unit != unit {
            return Err(ReconciliationError::UnitMismatch {
                expected: unit,
                actual: amt.unit,
            });
        }
    }

    let mut bank_by_id = BTreeMap::new();
    for line in bank_lines {
        if line.amount.unit != unit {
            return Err(ReconciliationError::UnitMismatch {
                expected: unit,
                actual: line.amount.unit,
            });
        }
        bank_by_id.insert(line.oid()?, line.clone());
    }

    let mut book_by_ref = BTreeMap::new();
    for entry in book_entries {
        if entry.amount.unit != unit {
            return Err(ReconciliationError::UnitMismatch {
                expected: unit,
                actual: entry.amount.unit,
            });
        }
        book_by_ref.insert(entry.entry_ref, entry.clone());
    }

    // Filter out matches superseded by a later match (`supersedes_match_id`).
    let mut superseded_ids = BTreeSet::new();
    for m in matches {
        if let Some(old_id) = m.supersedes_match_id {
            superseded_ids.insert(old_id);
        }
    }

    let mut active_matches = Vec::new();
    let mut matched_bank_ids = BTreeSet::new();
    let mut matched_book_refs = BTreeSet::new();

    for m in matches {
        let oid = m.validate(enforced_policy_epoch, &bank_by_id, &book_by_ref)?;
        if superseded_ids.contains(&oid) {
            continue;
        }
        if !m.book_entry_refs.is_empty() {
            for bid in &m.bank_line_ids {
                matched_bank_ids.insert(*bid);
            }
            for bref in &m.book_entry_refs {
                matched_book_refs.insert(*bref);
            }
            if let Some(res) = &m.residual {
                matched_book_refs.insert(res.residual_entry_ref);
            }
        }
        active_matches.push(m.clone());
    }

    let mut unmatched_bank_lines = Vec::new();
    let mut unposted_residuals = Vec::new();
    let mut unmatched_bank_sum: i128 = 0;

    for line in bank_lines {
        let oid = line.oid()?;
        if !matched_bank_ids.contains(&oid) {
            unmatched_bank_sum = unmatched_bank_sum
                .checked_add(line.signed_cash_delta())
                .ok_or(ReconciliationError::InvalidField(
                    "unmatched_bank_sum overflow",
                ))?;
            unposted_residuals.push(UnpostedResidualFinding {
                bank_line_id: oid,
                booking_date: line.booking_date,
                signed_cash_delta: line.signed_cash_delta(),
                counterparty: line.counterparty.clone(),
                reference: line.reference.clone(),
            });
            unmatched_bank_lines.push(line.clone());
        }
    }

    let mut outstanding_book_entries = Vec::new();
    let mut outstanding_book_sum: i128 = 0;

    for entry in book_entries {
        if !matched_book_refs.contains(&entry.entry_ref) {
            outstanding_book_sum = outstanding_book_sum
                .checked_add(entry.signed_cash_delta())
                .ok_or(ReconciliationError::InvalidField(
                    "outstanding_book_sum overflow",
                ))?;
            outstanding_book_entries.push(entry.clone());
        }
    }

    // Standard reconciliation bridge:
    // adjusted_book_balance = book_closing - outstanding_book + unmatched_bank
    let adjusted_mantissa = book_closing
        .mantissa
        .checked_sub(outstanding_book_sum)
        .and_then(|v| v.checked_add(unmatched_bank_sum))
        .ok_or(ReconciliationError::InvalidField(
            "adjusted_book_balance overflow",
        ))?;
    let adjusted_book_balance = Amount::new(unit, adjusted_mantissa);

    // A period is fully reconciled only when:
    // 1. All bank statement lines are matched to committed book entries (no unposted fee/residual lines).
    // 2. `book_closing - outstanding_book == statement_closing`.
    let is_reconciled = unmatched_bank_lines.is_empty()
        && adjusted_book_balance.mantissa == statement_closing.mantissa;

    let reconciled_through = if is_reconciled {
        bank_lines.iter().map(|l| l.booking_date).max()
    } else {
        None
    };

    let mut w = Writer::with_capacity(256);
    w.bytes(RECON_FOLD_DOMAIN)
        .u128(account.0)
        .str(&period)
        .u32(unit.0)
        .i128(book_opening.mantissa)
        .i128(book_closing.mantissa)
        .i128(statement_opening.mantissa)
        .i128(statement_closing.mantissa)
        .i128(adjusted_book_balance.mantissa)
        .bool(is_reconciled)
        .u64(evaluated_known_at.0)
        .u32(unmatched_bank_lines.len() as u32)
        .u32(outstanding_book_entries.len() as u32);
    let fold_bytes = w.finish()?;
    let fold_digest = domain_digest(RECON_FOLD_DOMAIN, &[&fold_bytes]);

    Ok(ReconciliationRegister {
        account,
        period,
        unit,
        book_opening,
        book_closing,
        statement_opening,
        statement_closing,
        active_matches,
        unmatched_bank_lines,
        outstanding_book_entries,
        unposted_residuals,
        adjusted_book_balance,
        is_reconciled,
        reconciled_through,
        evaluated_known_at,
        fold_digest,
    })
}

/// Refold and verify a [`ReconciliationRegister`] (`fa verify reconciliation`).
///
/// Fails with [`ReconciliationError::VerificationFailed`] when:
/// - the refolded register differs from `stored`;
/// - any active match's [`DecisionCard`] fails fallback validation or replay;
/// - any bank statement line (such as a fee residual) was not posted as a book
///   entry under a named law (`!refolded.unposted_residuals.is_empty()`); or
/// - `book_closing - outstanding_book != statement_closing`.
#[allow(clippy::too_many_arguments)]
pub fn verify_reconciliation_register(
    stored: &ReconciliationRegister,
    bank_lines: &[BankStatementLine],
    book_entries: &[BookCandidateEntry],
    matches: &[ReconciliationMatch],
    enforced_policy_epoch: [u8; 32],
) -> Result<(), ReconciliationError> {
    let refolded = fold_reconciliation_register(
        stored.account,
        &stored.period,
        stored.unit,
        stored.book_opening,
        stored.book_closing,
        stored.statement_opening,
        stored.statement_closing,
        bank_lines,
        book_entries,
        matches,
        enforced_policy_epoch,
        stored.evaluated_known_at,
    )?;

    if refolded.fold_digest != stored.fold_digest {
        return Err(ReconciliationError::VerificationFailed(
            "stored reconciliation fold digest drifted from journal refold".into(),
        ));
    }
    if !refolded.unposted_residuals.is_empty() {
        return Err(ReconciliationError::VerificationFailed(format!(
            "{} bank line(s) (including fee/FX residuals) are unmatched/unposted in book",
            refolded.unposted_residuals.len()
        )));
    }
    if !refolded.is_reconciled {
        return Err(ReconciliationError::VerificationFailed(format!(
            "reconciliation out of balance: adjusted book {} != statement closing {}",
            refolded.adjusted_book_balance.mantissa, refolded.statement_closing.mantissa
        )));
    }
    Ok(())
}

/// Enforce the `reconciled_through` soft-lock (plan §15.9): posting on or before
/// `reconciled_through` on a reconciled bank account requires `Op::Reconcile`
/// on `capability`.
pub fn check_reconciled_through_lock(
    reconciled_through: Option<DateDay>,
    effective_date: DateDay,
    book_id: fa_model::Id128,
    principal: VId,
    capability: &Capability,
) -> Result<(), ReconciliationError> {
    let Some(cutoff) = reconciled_through else {
        return Ok(());
    };
    if effective_date <= cutoff {
        let intent = Intent {
            principal,
            trunk: false,
            op: Op::Reconcile,
            book: book_id,
            legs: &[],
        };
        if fa_policy::admit(capability, &intent).is_err() {
            return Err(ReconciliationError::ReconciledPeriodLocked {
                effective_date,
                reconciled_through: cutoff,
            });
        }
    }
    Ok(())
}

/// Purchase order line for three-way matching (`PO <-> Receipt <-> Invoice`, plan §12.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurchaseOrderLine {
    pub po_oid: Oid,
    pub vendor: String,
    pub item_code: String,
    pub quantity: i128,
    pub unit_price: Amount,
}

/// Receiving report line for three-way matching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivingReportLine {
    pub receipt_oid: Oid,
    pub po_oid: Oid,
    pub item_code: String,
    pub quantity_received: i128,
}

/// Vendor invoice line for three-way matching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VendorInvoiceLine {
    pub invoice_oid: Oid,
    pub po_oid: Oid,
    pub vendor: String,
    pub item_code: String,
    pub quantity_billed: i128,
    pub unit_price_billed: Amount,
    pub total_billed: Amount,
}

/// Outcome of a three-way match (`PO <-> Receipt <-> VendorInvoice`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ThreeWayMatchVerdict {
    Matched,
    QuantityVariance {
        po_qty: i128,
        receipt_qty: i128,
        invoice_qty: i128,
    },
    PriceVariance {
        po_unit_price: Amount,
        invoice_unit_price: Amount,
    },
    ExtensionMismatch {
        expected_total: Amount,
        invoice_total: Amount,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreeWayMatchResult {
    pub po_oid: Oid,
    pub receipt_oid: Oid,
    pub invoice_oid: Oid,
    pub verdict: ThreeWayMatchVerdict,
    pub decision_card: DecisionCard,
}

/// Execute deterministic three-way matching (`PO <-> Receipt <-> VendorInvoice`)
/// with a replayable [`DecisionCard`].
pub fn match_three_way(
    po: &PurchaseOrderLine,
    receipt: &ReceivingReportLine,
    invoice: &VendorInvoiceLine,
    policy_epoch: Option<[u8; 32]>,
    enforced_policy_epoch: [u8; 32],
) -> Result<ThreeWayMatchResult, ReconciliationError> {
    if po.unit_price.unit != invoice.unit_price_billed.unit
        || po.unit_price.unit != invoice.total_billed.unit
    {
        return Err(ReconciliationError::UnitMismatch {
            expected: po.unit_price.unit,
            actual: invoice.total_billed.unit,
        });
    }
    let unit = po.unit_price.unit;
    let qty_diff = (po.quantity - receipt.quantity_received).abs()
        + (receipt.quantity_received - invoice.quantity_billed).abs();
    let price_diff = (po.unit_price.mantissa - invoice.unit_price_billed.mantissa).abs();
    let expected_total = invoice
        .quantity_billed
        .checked_mul(invoice.unit_price_billed.mantissa)
        .ok_or(ReconciliationError::InvalidField(
            "invoice extension overflow",
        ))?;

    let verdict = if po.quantity != receipt.quantity_received
        || receipt.quantity_received != invoice.quantity_billed
    {
        ThreeWayMatchVerdict::QuantityVariance {
            po_qty: po.quantity,
            receipt_qty: receipt.quantity_received,
            invoice_qty: invoice.quantity_billed,
        }
    } else if po.unit_price.mantissa != invoice.unit_price_billed.mantissa {
        ThreeWayMatchVerdict::PriceVariance {
            po_unit_price: po.unit_price,
            invoice_unit_price: invoice.unit_price_billed,
        }
    } else if expected_total != invoice.total_billed.mantissa {
        ThreeWayMatchVerdict::ExtensionMismatch {
            expected_total: Amount::new(unit, expected_total),
            invoice_total: invoice.total_billed,
        }
    } else {
        ThreeWayMatchVerdict::Matched
    };

    let features = vec![
        DecisionFeature {
            name: "qty_diff".to_string(),
            value: qty_diff,
            advisory: false,
        },
        DecisionFeature {
            name: "price_diff".to_string(),
            value: price_diff,
            advisory: false,
        },
    ];
    let candidates = vec![DecisionCandidate {
        action: DecisionPolicyRow::for_kind(DecisionKind::BankMatchHeuristic)
            .pinned_fallback_action
            .to_string(),
        parameter: 0,
        analytic_score: if verdict == ThreeWayMatchVerdict::Matched {
            1_000
        } else {
            0
        },
    }];
    let card = decide_bank_match(
        policy_epoch,
        enforced_policy_epoch,
        invoice.invoice_oid.0,
        candidates,
        features,
        BenefitInterval {
            lower_bps: 200,
            upper_bps: 600,
        },
    );
    card.validate_fallback()?;
    card.verify_replay(enforced_policy_epoch)?;

    Ok(ThreeWayMatchResult {
        po_oid: po.po_oid,
        receipt_oid: receipt.receipt_oid,
        invoice_oid: invoice.invoice_oid,
        verdict,
        decision_card: card,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_policy::Steward;
    use fa_reference::reconciliation::{
        RefBankLine, RefBookEntry, RefThreeWayVerdict, naive_fallback_match,
        naive_reconciliation_fold, naive_three_way_match,
    };

    fn fixture_epoch() -> [u8; 32] {
        Steward::embedded().unwrap().policy_oid
    }

    #[test]
    fn ambiguity_eligibility_agrees_with_pinned_matching_before_consumption() {
        let mut line = BankStatementLine {
            statement_oid: Oid([41; 32]),
            statement_seq: 1,
            line_ordinal: 1,
            booking_date: DateDay(100),
            value_date: DateDay(100),
            side: Side::Credit,
            amount: Amount::new(UnitId(1), 100),
            counterparty: "same payee".into(),
            reference: "INV-100".into(),
        };
        let mut entry = BookCandidateEntry {
            entry_ref: EntryRef {
                vid: VId(42),
                entry_digest: [43; 32],
            },
            entry_ordinal: 1,
            effective_date: DateDay(99),
            side: Side::Debit,
            amount: line.amount,
            counterparty: "same payee".into(),
            reference: "inv-100".into(),
        };
        let config = MatcherConfig {
            policy_epoch: None,
            enforced_policy_epoch: fixture_epoch(),
            max_date_window_days: 1,
            pinned_fallback_only: true,
            advisory_learned_scores_bps: BTreeMap::new(),
        };
        let check = |line: &BankStatementLine, entry: &BookCandidateEntry, expected: bool| {
            assert_eq!(pinned_bank_candidate(line, entry, 1).unwrap(), expected);
            let result = match_bank_lines(
                std::slice::from_ref(line),
                std::slice::from_ref(entry),
                &config,
                VId(7),
            )
            .unwrap();
            assert_eq!(result[0].matched_entry_ordinal.is_some(), expected);
            result[0]
                .decision_card
                .verify_replay(config.enforced_policy_epoch)
                .unwrap();
        };
        check(&line, &entry, true);
        entry.reference = "DIFFERENT".into();
        check(&line, &entry, false); // Counterparty similarity cannot override the pinned reference.
        line.reference.clear();
        check(&line, &entry, true);
        entry.side = Side::Credit;
        check(&line, &entry, false);
        entry.side = Side::Debit;
        entry.effective_date = DateDay(98);
        check(&line, &entry, false);
        entry.effective_date = DateDay(100);
        entry.amount.mantissa = 99;
        check(&line, &entry, false);
        entry.amount = Amount::new(UnitId(2), 100);
        assert!(matches!(
            pinned_bank_candidate(&line, &entry, 1),
            Err(ReconciliationError::UnitMismatch { .. })
        ));
    }

    #[test]
    fn date_window_comparison_handles_the_complete_civil_day_domain() {
        let epoch = fixture_epoch();
        let line = BankStatementLine {
            statement_oid: Oid([31; 32]),
            statement_seq: 1,
            line_ordinal: 1,
            booking_date: DateDay(i32::MAX),
            value_date: DateDay(i32::MAX),
            side: Side::Credit,
            amount: Amount::new(UnitId(1), 100),
            counterparty: String::new(),
            reference: "same".into(),
        };
        let entry = BookCandidateEntry {
            entry_ref: EntryRef {
                vid: VId(32),
                entry_digest: [33; 32],
            },
            entry_ordinal: 1,
            effective_date: DateDay(i32::MIN),
            side: Side::Debit,
            amount: line.amount,
            counterparty: String::new(),
            reference: "same".into(),
        };
        let config = MatcherConfig {
            policy_epoch: None,
            enforced_policy_epoch: epoch,
            max_date_window_days: i32::MAX,
            pinned_fallback_only: true,
            advisory_learned_scores_bps: BTreeMap::new(),
        };
        let proposed = match_bank_lines(&[line], &[entry], &config, VId(7)).unwrap();
        assert_eq!(proposed.len(), 1);
        assert!(proposed[0].book_entry_refs.is_empty());
        proposed[0].decision_card.verify_replay(epoch).unwrap();
    }

    #[test]
    fn pinned_fallback_matches_unambiguous_lines_replays_cards_and_agrees_with_fa_reference() {
        let epoch = fixture_epoch();
        let usd = UnitId(1);
        let stmt_oid = Oid([0x10; 32]);

        let b1 = BankStatementLine {
            statement_oid: stmt_oid,
            statement_seq: 1,
            line_ordinal: 1,
            booking_date: DateDay::from_ymd(2026, 3, 10).unwrap(),
            value_date: DateDay::from_ymd(2026, 3, 10).unwrap(),
            side: Side::Credit, // +$500.00 customer deposit
            amount: Amount::new(usd, 50_000),
            counterparty: "Acme Corp., Inc.".into(),
            reference: "INV-100".into(),
        };
        let b2 = BankStatementLine {
            statement_oid: stmt_oid,
            statement_seq: 1,
            line_ordinal: 2,
            booking_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            value_date: DateDay::from_ymd(2026, 3, 15).unwrap(),
            side: Side::Debit, // -$200.00 vendor payment
            amount: Amount::new(usd, 20_000),
            counterparty: "Cloud Hosting LLC".into(),
            reference: "BILL-200".into(),
        };
        let bank_lines = vec![b1.clone(), b2.clone()];

        let e1 = BookCandidateEntry {
            entry_ref: EntryRef {
                vid: VId(101),
                entry_digest: [0xA1; 32],
            },
            entry_ordinal: 1,
            effective_date: DateDay::from_ymd(2026, 3, 9).unwrap(),
            side: Side::Debit, // +$500.00 Debit to Cash
            amount: Amount::new(usd, 50_000),
            counterparty: "ACME CORP".into(),
            reference: "inv-100".into(),
        };
        let e2 = BookCandidateEntry {
            entry_ref: EntryRef {
                vid: VId(102),
                entry_digest: [0xA2; 32],
            },
            entry_ordinal: 2,
            effective_date: DateDay::from_ymd(2026, 3, 14).unwrap(),
            side: Side::Credit, // -$200.00 Credit to Cash
            amount: Amount::new(usd, 20_000),
            counterparty: "Cloud Hosting".into(),
            reference: "BILL-200".into(),
        };
        // Deposit in transit (+$100.00 in book, not yet on bank statement)
        let e3_outstanding = BookCandidateEntry {
            entry_ref: EntryRef {
                vid: VId(103),
                entry_digest: [0xA3; 32],
            },
            entry_ordinal: 3,
            effective_date: DateDay::from_ymd(2026, 3, 30).unwrap(),
            side: Side::Debit,
            amount: Amount::new(usd, 10_000),
            counterparty: "Late Customer".into(),
            reference: "INV-101".into(),
        };
        let book_entries = vec![e1, e2, e3_outstanding];

        // Run under pinned fallback alone (learned features disabled).
        let config = MatcherConfig {
            policy_epoch: Some(epoch),
            enforced_policy_epoch: epoch,
            max_date_window_days: 5,
            pinned_fallback_only: true,
            advisory_learned_scores_bps: BTreeMap::new(),
        };
        let matches = match_bank_lines(&bank_lines, &book_entries, &config, VId(7)).unwrap();
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].matched_entry_ordinal, Some(1));
        assert_eq!(matches[1].matched_entry_ordinal, Some(2));
        assert!(matches[0].decision_card.used_fallback());
        assert!(matches[1].decision_card.used_fallback());

        // Differential check against fa_reference::reconciliation::naive_fallback_match.
        let ref_bank: Vec<RefBankLine> = bank_lines
            .iter()
            .map(|l| RefBankLine {
                line_id: l.oid().unwrap().0,
                booking_date: l.booking_date,
                signed_mantissa: l.signed_cash_delta(),
                reference: l.reference.clone(),
            })
            .collect();
        let ref_book: Vec<RefBookEntry> = book_entries
            .iter()
            .map(|e| RefBookEntry {
                entry_ordinal: e.entry_ordinal,
                effective_date: e.effective_date,
                signed_mantissa: e.signed_cash_delta(),
                reference: e.reference.clone(),
            })
            .collect();
        let oracle_matches = naive_fallback_match(&ref_bank, &ref_book, 5);
        for (m, (oid, ord)) in matches.iter().zip(oracle_matches.iter()) {
            assert_eq!(m.bank_line_ids[0].0, *oid);
            assert_eq!(m.matched_entry_ordinal, *ord);
            m.decision_card.verify_replay(epoch).unwrap();
        }

        // Fold reconciliation register:
        // Opening = $1,000.00 (100_000).
        // Book closing = 100_000 + 50_000 - 20_000 + 10_000 = 140_000.
        // Statement closing = 100_000 + 50_000 - 20_000 = 130_000.
        // Outstanding book = +10_000 (e3_outstanding).
        // Adjusted book = 140_000 - 10_000 = 130_000 == Statement closing!
        let reg = fold_reconciliation_register(
            VId(1000),
            "2026-03",
            usd,
            Amount::new(usd, 100_000),
            Amount::new(usd, 140_000),
            Amount::new(usd, 100_000),
            Amount::new(usd, 130_000),
            &bank_lines,
            &book_entries,
            &matches,
            epoch,
            CommitSeq(25),
        )
        .unwrap();
        assert!(reg.is_reconciled);
        assert_eq!(reg.outstanding_book_entries.len(), 1);
        assert_eq!(reg.unmatched_bank_lines.len(), 0);
        assert_eq!(
            reg.reconciled_through,
            Some(DateDay::from_ymd(2026, 3, 15).unwrap())
        );

        let oracle_fold =
            naive_reconciliation_fold(140_000, 130_000, &ref_bank, &ref_book, &oracle_matches);
        assert_eq!(oracle_fold.ties_to_statement, reg.is_reconciled);
        assert_eq!(
            oracle_fold.adjusted_book_balance,
            reg.adjusted_book_balance.mantissa
        );

        // Verify reconciliation succeeds.
        verify_reconciliation_register(&reg, &bank_lines, &book_entries, &matches, epoch).unwrap();
    }

    #[test]
    fn planted_negatives_missing_fallback_modified_amount_and_unposted_fee_residual() {
        let epoch = fixture_epoch();
        let usd = UnitId(1);
        let stmt_oid = Oid([0x20; 32]);

        let b1 = BankStatementLine {
            statement_oid: stmt_oid,
            statement_seq: 1,
            line_ordinal: 1,
            booking_date: DateDay::from_ymd(2026, 3, 10).unwrap(),
            value_date: DateDay::from_ymd(2026, 3, 10).unwrap(),
            side: Side::Credit,
            amount: Amount::new(usd, 50_000),
            counterparty: "Acme".into(),
            reference: "INV-1".into(),
        };
        let fee_line = BankStatementLine {
            statement_oid: stmt_oid,
            statement_seq: 1,
            line_ordinal: 2,
            booking_date: DateDay::from_ymd(2026, 3, 11).unwrap(),
            value_date: DateDay::from_ymd(2026, 3, 11).unwrap(),
            side: Side::Debit, // -$25.00 bank wire fee not posted in book
            amount: Amount::new(usd, 2_500),
            counterparty: "Bank Fee".into(),
            reference: "FEE-1".into(),
        };
        let e1 = BookCandidateEntry {
            entry_ref: EntryRef {
                vid: VId(201),
                entry_digest: [0xB1; 32],
            },
            entry_ordinal: 1,
            effective_date: DateDay::from_ymd(2026, 3, 10).unwrap(),
            side: Side::Debit,
            amount: Amount::new(usd, 50_000),
            counterparty: "Acme".into(),
            reference: "INV-1".into(),
        };

        let config = MatcherConfig {
            policy_epoch: Some(epoch),
            enforced_policy_epoch: epoch,
            max_date_window_days: 3,
            pinned_fallback_only: true,
            advisory_learned_scores_bps: BTreeMap::new(),
        };
        let matches = match_bank_lines(
            &[b1.clone(), fee_line.clone()],
            std::slice::from_ref(&e1),
            &config,
            VId(7),
        )
        .unwrap();

        // 1. Planted negative: a card whose fallback is removed/altered is refused at registration.
        let mut tampered_card = matches[0].decision_card.clone();
        tampered_card.fallback.action = String::new();
        assert!(matches!(
            tampered_card.validate_fallback(),
            Err(DecisionReplayError::FallbackMissingOrInvalid { .. })
        ));

        // 2. Planted negative: a match that would change a committed amount is refused.
        assert!(matches!(
            verify_match_preserves_committed_amounts(
                &e1,
                Amount::new(usd, 47_500),
                &matches[0].decision_card
            ),
            Err(ReconciliationError::AmountModified { .. })
        ));

        // 3. Planted negative: a fee residual not posted under a law leaves the register
        // with unposted_residuals and `verify_reconciliation_register` catches it.
        let all_bank = [b1, fee_line];
        let all_book = [e1];
        let reg_unposted = fold_reconciliation_register(
            VId(1000),
            "2026-03",
            usd,
            Amount::new(usd, 100_000),
            Amount::new(usd, 150_000),
            Amount::new(usd, 100_000),
            Amount::new(usd, 147_500),
            &all_bank,
            &all_book,
            &matches,
            epoch,
            CommitSeq(30),
        )
        .unwrap();
        assert!(!reg_unposted.is_reconciled);
        assert_eq!(reg_unposted.unposted_residuals.len(), 1);
        let err =
            verify_reconciliation_register(&reg_unposted, &all_bank, &all_book, &matches, epoch)
                .unwrap_err();
        assert!(matches!(err, ReconciliationError::VerificationFailed(_)));
    }

    #[test]
    fn three_way_matching_verifies_po_receipt_invoice_and_agrees_with_oracle() {
        let epoch = fixture_epoch();
        let usd = UnitId(1);
        let po = PurchaseOrderLine {
            po_oid: Oid([1; 32]),
            vendor: "Acme Supplies".into(),
            item_code: "SKU-100".into(),
            quantity: 10,
            unit_price: Amount::new(usd, 1_500),
        };
        let receipt = ReceivingReportLine {
            receipt_oid: Oid([2; 32]),
            po_oid: po.po_oid,
            item_code: "SKU-100".into(),
            quantity_received: 10,
        };
        let invoice_ok = VendorInvoiceLine {
            invoice_oid: Oid([3; 32]),
            po_oid: po.po_oid,
            vendor: "Acme Supplies".into(),
            item_code: "SKU-100".into(),
            quantity_billed: 10,
            unit_price_billed: Amount::new(usd, 1_500),
            total_billed: Amount::new(usd, 15_000),
        };

        let res_ok = match_three_way(&po, &receipt, &invoice_ok, Some(epoch), epoch).unwrap();
        assert_eq!(res_ok.verdict, ThreeWayMatchVerdict::Matched);
        assert_eq!(
            naive_three_way_match(10, 1_500, 10, 10, 1_500, 15_000),
            RefThreeWayVerdict::Matched
        );

        let mut invoice_price_var = invoice_ok;
        invoice_price_var.unit_price_billed = Amount::new(usd, 1_600);
        invoice_price_var.total_billed = Amount::new(usd, 16_000);
        let res_var =
            match_three_way(&po, &receipt, &invoice_price_var, Some(epoch), epoch).unwrap();
        assert_eq!(
            res_var.verdict,
            ThreeWayMatchVerdict::PriceVariance {
                po_unit_price: Amount::new(usd, 1_500),
                invoice_unit_price: Amount::new(usd, 1_600),
            }
        );
        assert_eq!(
            naive_three_way_match(10, 1_500, 10, 10, 1_600, 16_000),
            RefThreeWayVerdict::PriceVariance {
                po_unit_price: 1_500,
                invoice_unit_price: 1_600,
            }
        );
    }
}
