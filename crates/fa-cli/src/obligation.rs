//! `obligation_maturity` on an entry intent (plan §11.6, beads fa-5dpd and
//! fa-0hs4.13): contractual maturity on payable credit legs and receivable
//! debit legs. Extension 33 retains v1 bytes for credit-only declarations;
//! declarations naming a debit leg use v2. The kernel validates the terms
//! against the legs; due-date aging preserves both sides, while the
//! cash-flow solvency procedure considers only liabilities.

use fa::Book;
use fa_model::EntryPayload;
use fa_model::entry::{EXTENSIONS_MINOR, OBLIGATION_MATURITY_EXTENSION};
use fa_model::obligation::{
    InlineObligationTerms, ObligationInstallment, ObligationStatus, validate_terms,
};
use fa_money::Amount;
use fa_time::DateDay;

use crate::cli::{Fail, usage};
use crate::json::Json;

pub(crate) const USAGE: &str = r#""obligation_maturity":[{"ordinal":2,"status":"contractual","installments":[{"due_date":"2026-12-31","amount":"1000.00 USD"}]}]: ordinal is the 0-based index of the payable credit leg or receivable debit leg; status is contractual (installments in the leg's unit, totalling its amount), disputed (with "reason_code") or missing_maturity (no installments)"#;

/// The intent's `obligation_maturity`, if any, as the proposal's extension 33.
pub(crate) fn declare_terms(
    book: &Book,
    doc: &Json,
    mut proposal: EntryPayload,
) -> Result<EntryPayload, Fail> {
    let Some(value) = doc.get("obligation_maturity") else {
        return Ok(proposal);
    };
    let items = value
        .as_arr()
        .ok_or_else(|| usage("obligation_maturity must be an array", USAGE))?;
    if items.is_empty() {
        return Err(usage(
            "obligation_maturity is empty; omit it instead",
            USAGE,
        ));
    }
    let units = &book.context().units;
    let mut terms = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        let what = format!("obligation_maturity[{i}]");
        let ordinal = match item.get("ordinal") {
            Some(Json::Int(n)) => u16::try_from(*n)
                .map_err(|_| usage(format!("{what}: ordinal {n} is out of range"), USAGE))?,
            _ => {
                return Err(usage(
                    format!(
                        "{what}: ordinal must be the 0-based index of the payable or receivable leg"
                    ),
                    USAGE,
                ));
            }
        };
        let Some(leg) = proposal.legs.get(usize::from(ordinal)) else {
            return Err(usage(
                format!("{what}: the intent has no leg {ordinal}"),
                USAGE,
            ));
        };
        let leg_unit = leg.amount.unit;
        let status = match item.get("status").and_then(Json::as_str) {
            Some("contractual") => ObligationStatus::Contractual,
            Some("disputed") => match item.get("reason_code") {
                Some(Json::Int(n)) => ObligationStatus::Disputed {
                    reason_code: u16::try_from(*n).map_err(|_| {
                        usage(format!("{what}: reason_code {n} is out of range"), USAGE)
                    })?,
                },
                _ => {
                    return Err(usage(
                        format!("{what}: a disputed obligation names its reason_code"),
                        USAGE,
                    ));
                }
            },
            Some("missing_maturity") => ObligationStatus::MissingMaturity,
            other => {
                return Err(usage(
                    format!(
                        "{what}: status `{}` is not contractual, disputed or missing_maturity",
                        other.unwrap_or("")
                    ),
                    USAGE,
                ));
            }
        };
        let mut installments = Vec::new();
        if let Some(list) = item.get("installments") {
            let list = list
                .as_arr()
                .ok_or_else(|| usage(format!("{what}: installments must be an array"), USAGE))?;
            for (j, installment) in list.iter().enumerate() {
                let at = format!("{what}.installments[{j}]");
                let due_text = installment
                    .get("due_date")
                    .and_then(Json::as_str)
                    .ok_or_else(|| usage(format!("{at}: due_date must be YYYY-MM-DD"), USAGE))?;
                let due_date = DateDay::parse(due_text)
                    .map_err(|e| usage(format!("{at}: due_date `{due_text}`: {e:?}"), USAGE))?;
                let amount_text = installment
                    .get("amount")
                    .and_then(Json::as_str)
                    .ok_or_else(|| {
                        usage(
                            format!("{at}: amount must be an exact string such as \"40.00 USD\""),
                            USAGE,
                        )
                    })?;
                let amount = Amount::parse(amount_text, units)
                    .map_err(|e| usage(format!("{at}: amount `{amount_text}`: {e}"), USAGE))?;
                if amount.unit != leg_unit {
                    return Err(usage(
                        format!("{at}: amount `{amount_text}` is not in leg {ordinal}'s unit"),
                        USAGE,
                    ));
                }
                installments.push(ObligationInstallment {
                    due_date,
                    amount: amount.mantissa,
                });
            }
        }
        installments.sort_unstable();
        terms.push(InlineObligationTerms {
            ordinal,
            status,
            installments,
        });
    }
    terms.sort_by_key(|term| term.ordinal);
    let bytes = InlineObligationTerms::encode_list_for_legs(&terms, &proposal.legs)
        .map_err(|e| usage(format!("obligation_maturity: {e:?}"), USAGE))?;
    validate_terms(&bytes, &proposal.legs)
        .map_err(|(field, why)| usage(format!("{field} {why}"), USAGE))?;
    proposal.schema_minor = proposal.schema_minor.max(EXTENSIONS_MINOR);
    proposal
        .extensions
        .retain(|(tag, _)| *tag != OBLIGATION_MATURITY_EXTENSION);
    proposal
        .extensions
        .push((OBLIGATION_MATURITY_EXTENSION, bytes));
    proposal.extensions.sort_by_key(|(tag, _)| *tag);
    Ok(proposal)
}
