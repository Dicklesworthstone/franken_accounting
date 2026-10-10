//! Account types and the stock/flow rule (plan §4.3, §7.5; registry
//! `registries/account_types.toml`, cross-checked by the test below).

/// A registered account type tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountType(pub u8);

impl AccountType {
    pub const ASSET: Self = Self(1);
    pub const LIABILITY: Self = Self(2);
    pub const EQUITY: Self = Self(3);
    pub const REVENUE: Self = Self(4);
    pub const EXPENSE: Self = Self(5);
    pub const MEMO: Self = Self(6);
    pub const STATISTICAL: Self = Self(7);

    /// `(tag, name, kind, normal_balance)` for every registered type.
    pub const ALL: &[(u8, &str, &str, u8)] = &[
        (1, "Asset", "stock", 0),
        (2, "Liability", "stock", 1),
        (3, "Equity", "stock", 1),
        (4, "Revenue", "flow", 1),
        (5, "Expense", "flow", 0),
        (6, "Memo", "memo", 0),
        (7, "Statistical", "memo", 0),
    ];

    #[must_use]
    pub fn name(self) -> Option<&'static str> {
        Self::ALL
            .iter()
            .find(|(t, ..)| *t == self.0)
            .map(|(_, n, ..)| *n)
    }

    #[must_use]
    pub fn is_registered(self) -> bool {
        self.name().is_some()
    }

    /// Carries forward across fiscal years (balance-sheet account).
    #[must_use]
    pub fn is_stock(self) -> bool {
        Self::ALL
            .iter()
            .any(|(t, _, k, _)| *t == self.0 && *k == "stock")
    }

    /// Accumulates within a fiscal year and closes to equity.
    #[must_use]
    pub fn is_flow(self) -> bool {
        Self::ALL
            .iter()
            .any(|(t, _, k, _)| *t == self.0 && *k == "flow")
    }

    /// Outside the balance law.
    #[must_use]
    pub fn is_memo(self) -> bool {
        Self::ALL
            .iter()
            .any(|(t, _, k, _)| *t == self.0 && *k == "memo")
    }

    /// 0 = debit-normal, 1 = credit-normal.
    #[must_use]
    pub fn normal_balance(self) -> Option<u8> {
        Self::ALL
            .iter()
            .find(|(t, ..)| *t == self.0)
            .map(|(.., nb)| *nb)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_account_types_match_registry() {
        let reg = fa_registry::account_types_embedded().unwrap();
        assert_eq!(reg.len(), AccountType::ALL.len());
        for row in &reg {
            let t = AccountType(row.tag);
            assert_eq!(t.name(), Some(row.name.as_str()));
            assert_eq!(t.is_stock(), row.kind == "stock", "{}", row.name);
            assert_eq!(t.is_flow(), row.kind == "flow", "{}", row.name);
            assert_eq!(t.is_memo(), row.kind == "memo", "{}", row.name);
            assert_eq!(t.normal_balance(), Some(row.normal_balance));
        }
        assert!(
            AccountType::ASSET.is_stock()
                && AccountType::EXPENSE.is_flow()
                && !AccountType(99).is_registered()
        );
    }
}
