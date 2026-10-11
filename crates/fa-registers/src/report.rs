//! Canonical primitives shared by literal report outputs.

use fa_journal::rows::AccountRow;
use fa_journal::{LimitScope, UnitPolicy};
use fa_model::Writer;
use fa_money::Side;

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

#[cfg(test)]
mod tests {
    use super::*;
    use fa_journal::BalanceLimit;
    use fgdb_types::{CommitSeq, VId};

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
}
