//! Explicit immutable cash-leg selection for adjusted statement closing.

use fa::bank::{BankOutstandingLeg, BankReconciliationRecorded};
use fa_model::EntryRef;
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{Fail, usage};
use crate::json::{Json, obj, s};

use super::{RECONCILE_EXAMPLE, entry_ref_json, money};

pub(super) fn parse(args: &Args) -> Result<Vec<BankOutstandingLeg>, Fail> {
    let values = args.flag_all("--outstanding");
    if values.len() > fa_model::limits::MAX_BANK_OUTSTANDING_ITEMS {
        return Err(usage(
            format!(
                "--outstanding exceeds max_bank_outstanding_items ({})",
                fa_model::limits::MAX_BANK_OUTSTANDING_ITEMS,
            ),
            "retain the complete selection; an adjusted reconciliation must not omit items to fit a bound",
        ));
    }
    let mut selected = Vec::with_capacity(values.len());
    for value in values {
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 3 || parts[0].len() != 32 || parts[1].is_empty() {
            return Err(usage(
                "--outstanding requires <entry-vid>:<leg-ordinal>:<entry-digest>; amounts are derived from the retained leg",
                RECONCILE_EXAMPLE,
            ));
        }
        let vid = u128::from_str_radix(parts[0], 16).map(VId).map_err(|_| {
            usage(
                "--outstanding entry VID must be 32 hex digits",
                RECONCILE_EXAMPLE,
            )
        })?;
        let leg_ordinal = parts[1].parse::<u16>().map_err(|_| {
            usage(
                "--outstanding leg ordinal must be an unsigned 16-bit integer",
                RECONCILE_EXAMPLE,
            )
        })?;
        let entry_digest = crate::document::hex32(parts[2], "--outstanding entry digest")?;
        selected.push(BankOutstandingLeg {
            entry_ref: EntryRef { vid, entry_digest },
            leg_ordinal,
        });
    }
    // Native admission also normalizes and checks duplicates. Doing this here
    // gives a usage error before opening a book for a repeated selector.
    selected.sort_by_key(|item| (item.entry_ref.vid, item.leg_ordinal));
    if selected.windows(2).any(|pair| {
        pair[0].entry_ref.vid == pair[1].entry_ref.vid && pair[0].leg_ordinal == pair[1].leg_ordinal
    }) {
        return Err(usage(
            "--outstanding repeats a cash leg; changing its digest cannot create another item",
            RECONCILE_EXAMPLE,
        ));
    }
    Ok(selected)
}

pub(super) fn fields(
    recorded: &BankReconciliationRecorded,
    book: &fa::Book,
) -> Result<Vec<(&'static str, Json)>, Fail> {
    let claim = &recorded.claim;
    let unit = claim.manifest.unit;
    let mut total = 0_i128;
    let mut items = Vec::with_capacity(claim.outstanding.len());
    for item in &claim.outstanding {
        total = total
            .checked_add(item.signed_amount)
            .ok_or_else(|| Fail::Internal("verified outstanding cash total exceeds i128".into()))?;
        items.push(obj(vec![
            ("entry_ref", entry_ref_json(&item.entry_ref)),
            ("leg_ordinal", Json::Int(i128::from(item.leg_ordinal))),
            ("signed_amount", money(item.signed_amount, unit, book)?),
            (
                "kind",
                s(if item.signed_amount > 0 {
                    "DepositInTransit"
                } else {
                    "UnclearedPayment"
                }),
            ),
        ]));
    }
    let adjusted = claim
        .cash_balance
        .checked_sub(total)
        .ok_or_else(|| Fail::Internal("verified adjusted cash balance exceeds i128".into()))?;
    Ok(vec![
        (
            "statement_balance",
            money(claim.manifest.closing_balance, unit, book)?,
        ),
        ("outstanding", Json::Arr(items)),
        ("outstanding_total", money(total, unit, book)?),
        ("adjusted_cash_balance", money(adjusted, unit, book)?),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn selected(values: &[&str]) -> Result<Vec<BankOutstandingLeg>, Fail> {
        let mut argv = vec!["bank".to_string(), "reconcile".into()];
        for value in values {
            argv.extend(["--outstanding".into(), (*value).into()]);
        }
        let registry = crate::verbs::registry().unwrap();
        let args =
            crate::args::parse(&argv, &registry.value_flags(), &registry.switches()).unwrap();
        parse(&args)
    }

    #[test]
    fn outstanding_selectors_bind_digest_and_ordinal_without_accepting_amounts() {
        let one = format!("{:032x}:0:{}", 1, "ab".repeat(32));
        let two = format!("{:032x}:1:{}", 1, "cd".repeat(32));
        let rows = match selected(&[&two, &one]) {
            Ok(rows) => rows,
            // `Fail` is not `Debug`; this test proves a valid pair is accepted.
            Err(_) => panic!("selectors refused a valid digest:ordinal pair"),
        };
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].leg_ordinal, 0);
        assert_eq!(rows[0].entry_ref.entry_digest, [0xab; 32]);
        assert_eq!(rows[1].entry_ref.entry_digest, [0xcd; 32]);
        assert!(selected(&[&one, &one]).is_err());
        let changed = format!("{:032x}:0:{}", 1, "cd".repeat(32));
        assert!(selected(&[&one, &changed]).is_err());
        for bad in [
            "1:0:ab".to_string(),
            format!("{:032x}:65536:{}", 1, "ab".repeat(32)),
            format!("{:032x}:0", 1),
            format!("{:032x}:0:{}:10.00 USD", 1, "ab".repeat(32)),
            format!("{:032x}:-1:{}", 1, "ab".repeat(32)),
        ] {
            assert!(selected(&[&bad]).is_err(), "{bad}");
        }
    }
}
