//! Canonical primitives shared by literal report outputs.

use std::collections::BTreeSet;

use fa_journal::rows::AccountRow;
use fa_journal::{LimitScope, UnitPolicy};
use fa_model::Writer;
use fa_money::Side;

use crate::RegisterError;
use crate::open_items::{OpenItem, OpenItemsReport, SettlementPlan};

pub(crate) fn account(w: &mut Writer, row: &AccountRow) {
    w.u128(row.vid.0)
        .str(&row.code)
        .str(&row.name)
        .u8(row.account_type)
        .u8(row.normal_balance)
        .bool(row.is_leaf);
    match row.unit_policy {
        UnitPolicy::Single(unit) => {
            w.u8(0).u32(unit.0);
        }
        UnitPolicy::AnyCurrency => {
            w.u8(1);
        }
        UnitPolicy::AnyUnit => {
            w.u8(2);
        }
    }
    w.opt(row.limit.as_ref(), |w, limit| {
        w.opt(limit.lower.as_ref(), |w, amount| {
            w.i128(*amount);
        })
        .opt(limit.upper.as_ref(), |w, amount| {
            w.i128(*amount);
        })
        .u8(match limit.scope {
            LimitScope::Lifetime => 0,
            LimitScope::Period => 1,
        });
    })
    .u64(row.created_at.0);
}

pub(crate) const fn side(side: Side) -> u8 {
    match side {
        Side::Debit => 0,
        Side::Credit => 1,
    }
}

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Debit => "debit",
        Side::Credit => "credit",
    }
}

impl OpenItemsReport {
    /// Export exact open-item mantissas with their unit, leg identity and
    /// snapshot. Zero-open items remain visible. Rows use the authoritative
    /// fold's account/commit/entry/ordinal ordering, independent of input order.
    ///
    /// This is machine-readable CSV, not the report's canonical certificate.
    /// Names are preserved, not formula-sanitized. Spreadsheet consumers must
    /// import fields as text to avoid formulas and loss of integer precision.
    pub fn to_csv(&self) -> Result<String, RegisterError> {
        let items = csv_items(self)?;
        let mut out = String::from(concat!(
            "known_at,account_vid,account_code,account_name,unit_id,entry_vid,ordinal,",
            "side,effective_day,recorded_at,original_mantissa,applied_mantissa,",
            "applied_out_mantissa,open_mantissa\r\n"
        ));
        for (item, account) in items {
            csv_row(&mut out, &[
                self.known_at.0.to_string(),
                format!("{:032x}", item.account.0),
                account.code.clone(),
                account.name.clone(),
                item.unit_id.to_string(),
                format!("{:032x}", item.entry.0),
                item.ordinal.to_string(),
                side_name(item.side).into(),
                item.effective_date.0.to_string(),
                item.recorded_at.0.to_string(),
                item.original.to_string(),
                item.applied.to_string(),
                item.applied_out.to_string(),
                item.open.to_string(),
            ]);
        }
        Ok(out)
    }

    /// Export every application against the displayed live items, including
    /// undone applications (`live=false`). The target leg, applying entry/leg,
    /// commit coordinate and exact unit/amount are explicit on every row.
    /// Text-import requirements are the same as for [`Self::to_csv`].
    pub fn applications_to_csv(&self) -> Result<String, RegisterError> {
        let items = csv_items(self)?;
        let mut out = String::from(concat!(
            "known_at,account_vid,account_code,unit_id,target_entry_vid,target_ordinal,",
            "application_entry_vid,application_ordinal,application_recorded_at,",
            "amount_mantissa,live\r\n"
        ));
        for (item, account) in items {
            let mut history: Vec<_> = item.applications.iter().collect();
            history.sort_by_key(|application| {
                (
                    application.recorded_at,
                    application.entry,
                    application.ordinal,
                    application.amount,
                    application.live,
                )
            });
            for application in history {
                csv_row(&mut out, &[
                    self.known_at.0.to_string(),
                    format!("{:032x}", item.account.0),
                    account.code.clone(),
                    item.unit_id.to_string(),
                    format!("{:032x}", item.entry.0),
                    item.ordinal.to_string(),
                    format!("{:032x}", application.entry.0),
                    application.ordinal.to_string(),
                    application.recorded_at.0.to_string(),
                    application.amount.to_string(),
                    application.live.to_string(),
                ]);
            }
        }
        Ok(out)
    }
}

impl SettlementPlan {
    /// Export allocation advice, not a durable settlement receipt. A final
    /// `unapplied` row is always emitted, even when its amount is zero or no
    /// application was possible. No currency total is implicitly converted.
    /// Integer mantissas and hexadecimal identities must be imported as text
    /// by spreadsheet consumers to preserve all digits.
    #[must_use]
    pub fn to_csv(&self) -> String {
        let mut out = String::from(concat!(
            "record_type,known_at,account_vid,unit_id,payment_side,payment_effective_day,",
            "payment_mantissa,target_entry_vid,target_ordinal,amount_mantissa,",
            "open_before_mantissa,open_after_mantissa\r\n"
        ));
        let common = [
            self.known_at.0.to_string(),
            format!("{:032x}", self.request.account.0),
            self.request.unit_id.to_string(),
            side_name(self.request.side).into(),
            self.request.effective_date.0.to_string(),
            self.request.amount.to_string(),
        ];
        for allocation in &self.allocations {
            let mut fields = vec!["allocation".to_string()];
            fields.extend(common.iter().cloned());
            fields.extend([
                format!("{:032x}", allocation.entry.0),
                allocation.ordinal.to_string(),
                allocation.amount.to_string(),
                allocation.open_before.to_string(),
                allocation.open_after.to_string(),
            ]);
            csv_row(&mut out, &fields);
        }
        let mut fields = vec!["unapplied".to_string()];
        fields.extend(common);
        fields.extend([
            String::new(),
            String::new(),
            self.unapplied.to_string(),
            String::new(),
            String::new(),
        ]);
        csv_row(&mut out, &fields);
        out
    }
}

// Validate metadata before producing output; never manufacture a display name
// or silently collapse two rows with the same durable entry/leg identity.
fn csv_items(
    report: &OpenItemsReport,
) -> Result<Vec<(&OpenItem, &AccountRow)>, RegisterError> {
    if report.account_filter.is_some_and(|account| !report.accounts.contains_key(&account)) {
        return Err(RegisterError::InvalidSelection(
            "CSV report account filter has no snapshot metadata".into(),
        ));
    }
    let mut identities = BTreeSet::new();
    let mut items = Vec::new();
    for item in &report.items {
        if !identities.insert((item.entry, item.ordinal)) {
            return Err(RegisterError::InvalidSelection(
                "CSV report contains a duplicate entry/leg identity".into(),
            ));
        }
        let account = report.accounts.get(&item.account).ok_or_else(|| {
            RegisterError::InvalidSelection("CSV item has no account snapshot metadata".into())
        })?;
        if account.vid != item.account
            || account.created_at > report.known_at
            || item.recorded_at > report.known_at
            || report.account_filter.is_some_and(|selected| selected != item.account)
        {
            return Err(RegisterError::InvalidSelection(
                "CSV item or account metadata is outside the report selection".into(),
            ));
        }
        items.push((item, account));
    }
    items.sort_by_key(|(item, _)| (item.account, item.recorded_at, item.entry, item.ordinal));
    Ok(items)
}

fn csv_row(out: &mut String, fields: &[String]) {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            out.push(',');
        }
        if field.bytes().any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n')) {
            out.push('"');
            for character in field.chars() {
                if character == '"' {
                    out.push('"');
                }
                out.push(character);
            }
            out.push('"');
        } else {
            out.push_str(field);
        }
    }
    out.push_str("\r\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open_items::{Application, SettlementRequest};
    use fa_journal::BalanceLimit;
    use fa_time::DateDay;
    use fgdb_types::{CommitSeq, VId};
    use std::collections::BTreeMap;

    #[test]
    fn account_metadata_encoding_is_fixed_width_and_preserves_exact_limits() {
        let row = AccountRow {
            vid: VId(9),
            code: "A".into(),
            name: "Cash".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(fa_money::UnitId(1)),
            limit: Some(BalanceLimit {
                lower: Some(-9_007_199_254_740_993),
                upper: Some(i128::MAX),
                scope: LimitScope::Period,
            }),
            created_at: CommitSeq(7),
        };
        let mut w = Writer::new();
        account(&mut w, &row);
        let bytes = w.finish().unwrap();
        let mut expected = 9u128.to_le_bytes().to_vec();
        expected.extend_from_slice(b"\x01\x00\x00\x00A");
        expected.extend_from_slice(b"\x04\x00\x00\x00Cash");
        // Asset, debit-normal, leaf, single-unit tag/id, limit, lower bound.
        expected.extend_from_slice(&[1, 0, 1, 0, 1, 0, 0, 0, 1, 1]);
        expected.extend_from_slice(&(-9_007_199_254_740_993i128).to_le_bytes());
        expected.push(1);
        expected.extend_from_slice(&i128::MAX.to_le_bytes());
        expected.push(1); // Period-scoped limit.
        expected.extend_from_slice(&7u64.to_le_bytes());
        assert_eq!(bytes, expected);
    }

    fn fixture() -> OpenItemsReport {
        let account = AccountRow {
            vid: VId(9),
            code: "AR,domestic".into(),
            name: "Receivables \"east\"\r\n東京".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::AnyCurrency,
            limit: None,
            created_at: CommitSeq(1),
        };
        let first = OpenItem {
            entry: VId(11),
            ordinal: 0,
            account: account.vid,
            unit_id: 1,
            side: Side::Debit,
            effective_date: DateDay(20_000),
            recorded_at: CommitSeq(2),
            original: 9_007_199_254_740_993,
            applied: 3,
            applied_out: 0,
            open: 9_007_199_254_740_990,
            applications: vec![
                Application {
                    entry: VId(20),
                    ordinal: 1,
                    amount: 3,
                    recorded_at: CommitSeq(4),
                    live: true,
                },
                Application {
                    entry: VId(19),
                    ordinal: 1,
                    amount: 7,
                    recorded_at: CommitSeq(3),
                    live: false,
                },
            ],
        };
        let mut second = first.clone();
        second.entry = VId(12);
        second.unit_id = 2;
        second.applications.clear();
        second.original = 0;
        second.applied = 0;
        second.open = 0;
        OpenItemsReport {
            known_at: CommitSeq(10),
            account_filter: Some(account.vid),
            accounts: BTreeMap::from([(account.vid, account)]),
            items: vec![second, first],
        }
    }

    // Independent CSV decoder for checking escaped fields, column counts and
    // embedded line endings without adding a dependency to the closed universe.
    fn read_csv(text: &str) -> Vec<Vec<String>> {
        let mut chars = text.chars().peekable();
        let mut rows = Vec::new();
        let mut row = Vec::new();
        let mut field = String::new();
        let mut quoted = false;
        while let Some(character) = chars.next() {
            if quoted {
                if character == '"' {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        quoted = false;
                    }
                } else {
                    field.push(character);
                }
            } else {
                match character {
                    '"' => {
                        assert!(field.is_empty());
                        quoted = true;
                    }
                    ',' => row.push(std::mem::take(&mut field)),
                    '\r' => {
                        assert_eq!(chars.next(), Some('\n'));
                        row.push(std::mem::take(&mut field));
                        rows.push(std::mem::take(&mut row));
                    }
                    '\n' => panic!("bare record newline"),
                    other => field.push(other),
                }
            }
        }
        assert!(!quoted && field.is_empty() && row.is_empty());
        rows
    }

    #[test]
    fn open_items_csv_preserves_exact_amounts_units_and_escaped_metadata() {
        let report = fixture();
        let original = report.canonical_bytes().unwrap();
        let rows = read_csv(&report.to_csv().unwrap());
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.len() == 14));
        assert_eq!(rows[1][2], "AR,domestic");
        assert_eq!(rows[1][3], "Receivables \"east\"\r\n東京");
        assert_eq!(rows[1][4], "1");
        assert_eq!(rows[2][4], "2");
        assert_eq!(rows[1][5], format!("{:032x}", 11));
        assert_eq!(rows[1][10], "9007199254740993");
        assert_eq!(rows[1][13], "9007199254740990");
        assert_eq!(rows[2][13], "0");
        assert_eq!(report.canonical_bytes().unwrap(), original);
    }

    #[test]
    fn input_permutations_do_not_change_either_csv_export() {
        let mut report = fixture();
        let items = report.to_csv().unwrap();
        let applications = report.applications_to_csv().unwrap();
        report.items.reverse();
        for item in &mut report.items {
            item.applications.reverse();
        }
        assert_eq!(report.to_csv().unwrap(), items);
        assert_eq!(report.applications_to_csv().unwrap(), applications);
    }

    #[test]
    fn application_csv_keeps_undone_history_and_durable_target_identities() {
        let rows = read_csv(&fixture().applications_to_csv().unwrap());
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.len() == 11));
        assert_eq!(rows[1][4], format!("{:032x}", 11));
        assert_eq!(rows[1][6], format!("{:032x}", 19));
        assert_eq!(rows[1][8], "3");
        assert_eq!(rows[1][9], "7");
        assert_eq!(rows[1][10], "false");
        assert_eq!(rows[2][6], format!("{:032x}", 20));
        assert_eq!(rows[2][10], "true");
    }

    #[test]
    fn empty_exports_still_have_headers_and_invalid_selection_is_not_hidden() {
        let mut report = fixture();
        report.items.clear();
        assert_eq!(read_csv(&report.to_csv().unwrap()).len(), 1);
        assert_eq!(read_csv(&report.applications_to_csv().unwrap()).len(), 1);
        report.accounts.clear();
        assert!(report.to_csv().is_err());
        let mut report = fixture();
        report.items.push(report.items[0].clone());
        assert!(report.to_csv().is_err());
        assert!(report.applications_to_csv().is_err());
        let mut report = fixture();
        report.items[0].recorded_at = CommitSeq(11);
        assert!(report.to_csv().is_err());
    }

    #[test]
    fn settlement_csv_always_accounts_for_unapplied_cash() {
        let report = fixture();
        let mut request = SettlementRequest {
            account: fa_journal::rows::AccountRow::clone(
                report.accounts.get(&VId(9)).unwrap(),
            ).vid,
            unit_id: 1,
            side: Side::Credit,
            amount: 9_007_199_254_741_000,
            effective_date: DateDay(20_000),
            targets: vec![(VId(11), 0)],
        };
        let plan = report.plan_settlement(&request).unwrap();
        let rows = read_csv(&plan.to_csv());
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().all(|row| row.len() == 12));
        assert_eq!(rows[1][0], "allocation");
        assert_eq!(rows[1][9], "9007199254740990");
        assert_eq!(rows[2][0], "unapplied");
        assert_eq!(rows[2][9], "10");
        request.amount = 100;
        let plan = report.plan_settlement(&request).unwrap();
        assert_eq!(read_csv(&plan.to_csv())[2][9], "0");
        request.unit_id = 2;
        request.targets = vec![(VId(12), 0)];
        let plan = report.plan_settlement(&request).unwrap();
        let rows = read_csv(&plan.to_csv());
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1][0], "unapplied");
        assert_eq!(rows[1][9], "100");
    }
}
