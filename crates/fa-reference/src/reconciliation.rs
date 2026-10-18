//! Independent naive reference oracle for Teller bank/subledger reconciliation
//! and three-way matching (plan §15.9, §12.5, §16.2; bead `fa-2ek`).
//!
//! Uses only `std`, `fa_time::DateDay`, and `crate::Int` limb arithmetic.

use std::collections::BTreeSet;

use fa_time::DateDay;

use crate::Int;

/// Reference bank statement line (signed cash delta: inflow `> 0`, outflow `< 0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefBankLine {
    pub line_id: [u8; 32],
    pub booking_date: DateDay,
    pub signed_mantissa: i128,
    pub reference: String,
}

/// Reference book cash entry candidate (signed cash delta: debit to Cash `> 0`, credit to Cash `< 0`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefBookEntry {
    pub entry_ordinal: u64,
    pub effective_date: DateDay,
    pub signed_mantissa: i128,
    pub reference: String,
}

/// Naive pinned-fallback matcher: an exact signed amount,
/// `|booking_date - effective_date| <= max_date_window_days`, and exact
/// trimmed case-insensitive reference equality (when `bank.reference` is
/// non-empty), breaking ties deterministically by lowest `entry_ordinal`.
#[must_use]
pub fn naive_fallback_match(
    bank_lines: &[RefBankLine],
    book_entries: &[RefBookEntry],
    max_date_window_days: i32,
) -> Vec<([u8; 32], Option<u64>)> {
    let mut consumed_ordinals = BTreeSet::new();
    let mut results = Vec::with_capacity(bank_lines.len());

    for line in bank_lines {
        let bank_ref = line.reference.trim().to_ascii_lowercase();
        let mut best_ordinal: Option<u64> = None;

        for entry in book_entries {
            if consumed_ordinals.contains(&entry.entry_ordinal) {
                continue;
            }
            if entry.signed_mantissa != line.signed_mantissa {
                continue;
            }
            let day_delta = (line.booking_date.0 - entry.effective_date.0).abs();
            if day_delta > max_date_window_days {
                continue;
            }
            let entry_ref = entry.reference.trim().to_ascii_lowercase();
            if !bank_ref.is_empty() && bank_ref != entry_ref {
                continue;
            }
            match best_ordinal {
                None => best_ordinal = Some(entry.entry_ordinal),
                Some(prev) if entry.entry_ordinal < prev => {
                    best_ordinal = Some(entry.entry_ordinal);
                }
                _ => {}
            }
        }

        if let Some(ord) = best_ordinal {
            consumed_ordinals.insert(ord);
        }
        results.push((line.line_id, best_ordinal));
    }

    results
}

/// Independent reference fold of a bank reconciliation register using `Int` limb arithmetic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefReconciliationFold {
    pub matched_pairs: Vec<([u8; 32], u64)>,
    pub unmatched_bank_ids: Vec<[u8; 32]>,
    pub outstanding_book_ordinals: Vec<u64>,
    pub adjusted_book_balance: i128,
    pub ties_to_statement: bool,
}

#[must_use]
pub fn naive_reconciliation_fold(
    book_closing: i128,
    statement_closing: i128,
    bank_lines: &[RefBankLine],
    book_entries: &[RefBookEntry],
    matches: &[([u8; 32], Option<u64>)],
) -> RefReconciliationFold {
    let mut matched_bank = BTreeSet::new();
    let mut matched_book = BTreeSet::new();
    let mut matched_pairs = Vec::new();

    for (line_id, maybe_ord) in matches {
        if let Some(ord) = maybe_ord {
            matched_bank.insert(*line_id);
            matched_book.insert(*ord);
            matched_pairs.push((*line_id, *ord));
        }
    }

    let mut unmatched_bank_ids = Vec::new();
    let mut unmatched_bank_sum = Int::from_i128(0);
    for line in bank_lines {
        if !matched_bank.contains(&line.line_id) {
            unmatched_bank_ids.push(line.line_id);
            unmatched_bank_sum = unmatched_bank_sum.add(&Int::from_i128(line.signed_mantissa));
        }
    }

    let mut outstanding_book_ordinals = Vec::new();
    let mut outstanding_book_sum = Int::from_i128(0);
    for entry in book_entries {
        if !matched_book.contains(&entry.entry_ordinal) {
            outstanding_book_ordinals.push(entry.entry_ordinal);
            outstanding_book_sum = outstanding_book_sum.add(&Int::from_i128(entry.signed_mantissa));
        }
    }

    // Standard reconciliation bridge:
    // statement_closing = book_closing - outstanding_book + unmatched_bank
    let adjusted = Int::from_i128(book_closing)
        .sub(&outstanding_book_sum)
        .add(&unmatched_bank_sum);
    let adjusted_i128 = adjusted.to_i128().unwrap_or(0);
    let ties = adjusted == Int::from_i128(statement_closing);

    RefReconciliationFold {
        matched_pairs,
        unmatched_bank_ids,
        outstanding_book_ordinals,
        adjusted_book_balance: adjusted_i128,
        ties_to_statement: ties,
    }
}

/// Independent naive three-way match (`PO <-> Receipt <-> Invoice`) oracle using `Int` limb arithmetic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefThreeWayVerdict {
    Matched,
    QuantityVariance {
        po_qty: i128,
        receipt_qty: i128,
        invoice_qty: i128,
    },
    PriceVariance {
        po_unit_price: i128,
        invoice_unit_price: i128,
    },
    ExtensionMismatch {
        expected_total: i128,
        invoice_total: i128,
    },
}

#[must_use]
pub fn naive_three_way_match(
    po_qty: i128,
    po_unit_price: i128,
    receipt_qty: i128,
    invoice_qty: i128,
    invoice_unit_price: i128,
    invoice_total: i128,
) -> RefThreeWayVerdict {
    if po_qty != receipt_qty || receipt_qty != invoice_qty {
        return RefThreeWayVerdict::QuantityVariance {
            po_qty,
            receipt_qty,
            invoice_qty,
        };
    }
    if po_unit_price != invoice_unit_price {
        return RefThreeWayVerdict::PriceVariance {
            po_unit_price,
            invoice_unit_price,
        };
    }
    let expected = Int::from_i128(invoice_qty)
        .mul(&Int::from_i128(invoice_unit_price))
        .to_i128()
        .unwrap_or(0);
    if expected != invoice_total {
        return RefThreeWayVerdict::ExtensionMismatch {
            expected_total: expected,
            invoice_total,
        };
    }
    RefThreeWayVerdict::Matched
}
