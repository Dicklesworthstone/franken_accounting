//! Historical chart forests from immutable chart-install records (plan §4.3,
//! §5.6, fa-up7). Parentage is read from the canonical SchemaChange payload,
//! not inferred from account codes or trusted from mutable CHILD_OF edges.
//!
//! This is the existing install-only chart format, including its two legacy
//! trailing limit lists. It does not implement account lifecycle mutations.
//! Unknown schema controls fail closed until their chart effect is understood.
//! The low-level reader follows the register-read contract: callers admit
//! authority and enter their query context before invoking it.

use std::collections::{BTreeMap, BTreeSet};

use fa_model::symbols::{label, property};
use fa_model::{
    AccountType, ControlKind, ControlPayload, DecodeError, Entry, EntryClass, EntryOrigin, Id128,
    Reader, account_vid,
};
use fgdb::Database;
use fgdb_types::{CommitSeq, VId};

use crate::KernelError;
use crate::genesis::{AccountSpec, BookContext, UnitPolicy};
use crate::limit::{BalanceLimit, LimitScope};
use crate::rows::{AccountRow, bytes};

/// A validated forest at one recorded frontier. Fields stay private so a
/// caller cannot introduce a cycle or an unjournaled parent after validation.
#[derive(Clone, Debug)]
pub struct ChartSnapshot {
    known_at: CommitSeq,
    accounts: BTreeMap<VId, AccountRow>,
    parents: BTreeMap<VId, VId>,
    children: BTreeMap<VId, Vec<VId>>,
}

impl ChartSnapshot {
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.known_at
    }

    #[must_use]
    pub fn accounts(&self) -> &BTreeMap<VId, AccountRow> {
        &self.accounts
    }

    #[must_use]
    pub fn parents(&self) -> &BTreeMap<VId, VId> {
        &self.parents
    }

    /// Exactly the posting leaves below `root`, including `root` itself if
    /// it is a leaf. An empty summary has an empty set, not a missing balance.
    /// The walk is iterative: valid deep charts never consume the call stack.
    pub fn leaves_under(&self, root: VId) -> Result<BTreeSet<VId>, KernelError> {
        if !self.accounts.contains_key(&root) {
            return Err(corrupt(format!("unknown chart account {:032x}", root.0)));
        }
        let mut leaves = BTreeSet::new();
        let mut pending = vec![root];
        while let Some(vid) = pending.pop() {
            let account = self
                .accounts
                .get(&vid)
                .ok_or_else(|| corrupt("validated chart lost an account"))?;
            if account.is_leaf {
                leaves.insert(vid);
            } else if let Some(children) = self.children.get(&vid) {
                pending.extend(children.iter().copied());
            }
        }
        Ok(leaves)
    }
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("journaled chart: {}", message.into()))
}

/// Rebuild the install-only chart at `known_at` and check every Account
/// mirror against its journaled declaration. Neither later chart installs
/// nor present-day metadata participate. Missing, extra, or rebound account
/// mirrors are corruption, not reasons to silently change subtree membership.
pub fn read_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: CommitSeq,
) -> Result<ChartSnapshot, KernelError> {
    if known_at > db.frontier()? {
        return Err(corrupt("requested frontier is beyond the book head"));
    }
    let rows = db.vertices_at(known_at)?;
    let mut definitions = Vec::new();
    for row in &rows {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "chart entry payload")?)?;
        if entry.proposal.class != EntryClass::SCHEMA_CONTROL {
            continue;
        }
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            return Err(corrupt(
                "a schema control belongs to another book or branch",
            ));
        }
        if !matches!(
            entry.proposal.origin,
            EntryOrigin::Control {
                control_kind: ControlKind::CHART_INSTALL,
                ..
            }
        ) {
            return Err(corrupt("unsupported schema-control origin"));
        }
        let Some(ControlPayload::SchemaChange {
            kind: 1,
            canonical_bytes,
        }) = &entry.proposal.control
        else {
            return Err(corrupt(
                "unsupported schema change; its chart effect must be implemented before reporting",
            ));
        };
        let accounts = decode_install(canonical_bytes)
            .map_err(|error| corrupt(format!("control {:032x}: {error}", row.vid.0)))?;
        for account in accounts {
            definitions.push((account, row.created_at));
        }
    }
    let chart = assemble(book.book_id, known_at, definitions)?;
    let mut observed = BTreeSet::new();
    for row in &rows {
        if !row.labels.contains(&label::ACCOUNT) {
            continue;
        }
        let expected = chart.accounts.get(&row.vid).ok_or_else(|| {
            corrupt(format!(
                "account {:032x} has no chart-install declaration",
                row.vid.0
            ))
        })?;
        if bytes(row, property::BOOK_ID, "account.book_id")? != book.book_id.0
            || AccountRow::decode(row)? != *expected
        {
            return Err(corrupt(format!(
                "account `{}` differs from its immutable declaration",
                expected.code
            )));
        }
        if let UnitPolicy::Single(unit) = expected.unit_policy
            && book.units.get(unit).is_none()
        {
            return Err(corrupt(format!(
                "account `{}` names unregistered unit {}",
                expected.code, unit.0
            )));
        }
        observed.insert(row.vid);
    }
    for (vid, account) in &chart.accounts {
        if !observed.contains(vid) {
            return Err(corrupt(format!(
                "declared account `{}` is absent at {}",
                account.code, known_at.0
            )));
        }
    }
    Ok(chart)
}

fn assemble(
    book: Id128,
    known_at: CommitSeq,
    definitions: Vec<(AccountSpec, CommitSeq)>,
) -> Result<ChartSnapshot, KernelError> {
    let mut accounts = BTreeMap::new();
    let mut parents = BTreeMap::new();
    for (spec, created_at) in definitions {
        if created_at > known_at {
            return Err(corrupt("a declaration lies after the selected frontier"));
        }
        if spec.code.is_empty()
            || spec.code.len() > 64
            || !AccountType(spec.account_type).is_registered()
            || spec.normal_balance > 1
        {
            return Err(corrupt(format!(
                "invalid account declaration `{}`",
                spec.code
            )));
        }
        if let Some(limit) = spec.limit
            && (!limit.is_well_formed()
                || !spec.is_leaf
                || !matches!(spec.unit_policy, UnitPolicy::Single(_)))
        {
            return Err(corrupt(format!("invalid balance limit on `{}`", spec.code)));
        }
        let vid = account_vid(book, &spec.code);
        if let Some(parent) = &spec.parent_code {
            parents.insert(vid, account_vid(book, parent));
        }
        let row = AccountRow {
            vid,
            code: spec.code,
            name: spec.name,
            account_type: spec.account_type,
            normal_balance: spec.normal_balance,
            is_leaf: spec.is_leaf,
            unit_policy: spec.unit_policy,
            limit: spec.limit,
            created_at,
        };
        if accounts.insert(vid, row).is_some() {
            return Err(corrupt(format!(
                "duplicate account identity {:032x}",
                vid.0
            )));
        }
    }
    let mut children: BTreeMap<VId, Vec<VId>> = BTreeMap::new();
    for (child, parent) in &parents {
        let row = accounts.get(parent).ok_or_else(|| {
            corrupt(format!(
                "account {:032x} has an absent parent {:032x}",
                child.0, parent.0
            ))
        })?;
        if row.is_leaf {
            return Err(corrupt(format!("posting leaf `{}` has a child", row.code)));
        }
        children.entry(*parent).or_default().push(*child);
    }
    // Mark completed paths so an arbitrarily deep forest takes linear walks
    // rather than restarting at the root for every descendant.
    let mut complete = BTreeSet::new();
    for vid in accounts.keys() {
        let mut path = BTreeSet::new();
        let mut current = Some(*vid);
        while let Some(node) = current {
            if complete.contains(&node) {
                break;
            }
            if !path.insert(node) {
                return Err(corrupt(format!("parent cycle at account {:032x}", node.0)));
            }
            current = parents.get(&node).copied();
        }
        complete.extend(path);
    }
    Ok(ChartSnapshot {
        known_at,
        accounts,
        parents,
        children,
    })
}

// install_chart's existing canonical format: list(AccountSpec base fields),
// optionally list(code, lower?, upper?), optionally list(period-limit code).
// No new stored bytes and no reinterpretation of legacy lifetime limits.
fn decode_install(payload: &[u8]) -> Result<Vec<AccountSpec>, DecodeError> {
    let mut reader = Reader::new(payload);
    // Even an empty-name/code base row takes 20 bytes. Admission is bounded
    // by actual input size, not by an unrelated small-business chart limit.
    let mut accounts = reader.list(payload.len() / 20, "chart.accounts", |reader| {
        Ok(AccountSpec {
            code: reader.str(64, "account.code")?.to_string(),
            name: reader.str(payload.len(), "account.name")?.to_string(),
            account_type: reader.u8("account.type")?,
            normal_balance: reader.u8("account.normal_balance")?,
            is_leaf: reader.bool("account.is_leaf")?,
            unit_policy: {
                let value = reader.i64("account.unit_policy")?;
                UnitPolicy::from_mirror(value)
                    .ok_or_else(|| reader.invalid("account.unit_policy"))?
            },
            parent_code: reader.opt("account.parent", |reader| {
                Ok(reader.str(64, "account.parent_code")?.to_string())
            })?,
            limit: None,
        })
    })?;
    let mut by_code = BTreeMap::new();
    for (index, account) in accounts.iter().enumerate() {
        if by_code.insert(account.code.clone(), index).is_some() {
            return Err(reader.invalid("chart.duplicate_account"));
        }
    }
    if reader.remaining() != 0 {
        let count = reader.count(accounts.len(), "chart.limits")?;
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let code = reader.str(64, "limit.account")?.to_string();
            let index = *by_code
                .get(&code)
                .ok_or_else(|| reader.invalid("limit.account"))?;
            if !seen.insert(index) {
                return Err(reader.invalid("chart.duplicate_limit"));
            }
            accounts[index].limit = Some(BalanceLimit {
                lower: reader.opt("limit.lower", |reader| reader.i128("limit.lower"))?,
                upper: reader.opt("limit.upper", |reader| reader.i128("limit.upper"))?,
                scope: LimitScope::Lifetime,
            });
        }
    }
    if reader.remaining() != 0 {
        let count = reader.count(accounts.len(), "chart.period_limits")?;
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let code = reader.str(64, "period_limit.account")?.to_string();
            let index = *by_code
                .get(&code)
                .ok_or_else(|| reader.invalid("period_limit.account"))?;
            if !seen.insert(index) {
                return Err(reader.invalid("chart.duplicate_period_limit"));
            }
            let limit = accounts[index]
                .limit
                .as_mut()
                .ok_or_else(|| reader.invalid("period_limit.missing_limit"))?;
            limit.scope = LimitScope::Period;
        }
    }
    reader.finish()?;
    Ok(accounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_model::Writer;
    use fa_money::UnitId;

    const BOOK: Id128 = Id128([0x42; 16]);

    fn account(code: &str, parent: Option<&str>, leaf: bool) -> AccountSpec {
        AccountSpec {
            code: code.into(),
            name: code.into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: leaf,
            unit_policy: UnitPolicy::Single(UnitId(1)),
            parent_code: parent.map(str::to_string),
            limit: None,
        }
    }

    fn forest(accounts: Vec<AccountSpec>) -> Result<ChartSnapshot, KernelError> {
        assemble(
            BOOK,
            CommitSeq(5),
            accounts.into_iter().map(|a| (a, CommitSeq(2))).collect(),
        )
    }

    // Independent encoding of the documented base layout, not the reader's
    // inverse. Persisted CLI tests additionally exercise install_chart itself.
    fn wire(accounts: &[AccountSpec]) -> Writer {
        let mut w = Writer::new();
        w.list(accounts, |w, a| {
            w.str(&a.code)
                .str(&a.name)
                .u8(a.account_type)
                .u8(a.normal_balance)
                .bool(a.is_leaf)
                .i64(a.unit_policy.mirror())
                .opt(a.parent_code.as_ref(), |w, parent| {
                    w.str(parent);
                });
        });
        w
    }

    #[test]
    fn subtree_membership_uses_parentage_not_codes_and_never_includes_summaries() {
        let chart = forest(vec![
            account("assets", None, false),
            account("nested", Some("assets"), false),
            account("cash", Some("nested"), true),
            account("receivable", Some("assets"), true),
            account("assets-looking-but-unrelated", None, true),
            account("empty", None, false),
        ])
        .unwrap();
        assert_eq!(chart.known_at(), CommitSeq(5));
        assert_eq!(
            chart.leaves_under(account_vid(BOOK, "assets")).unwrap(),
            BTreeSet::from([account_vid(BOOK, "cash"), account_vid(BOOK, "receivable")])
        );
        assert_eq!(
            chart.leaves_under(account_vid(BOOK, "cash")).unwrap(),
            BTreeSet::from([account_vid(BOOK, "cash")])
        );
        assert!(
            chart
                .leaves_under(account_vid(BOOK, "empty"))
                .unwrap()
                .is_empty()
        );
        assert!(chart.leaves_under(account_vid(BOOK, "absent")).is_err());
        assert_eq!(
            chart.parents()[&account_vid(BOOK, "cash")],
            account_vid(BOOK, "nested")
        );
    }

    #[test]
    fn duplicate_or_missing_accounts_leaf_parents_and_cycles_are_refused() {
        for definitions in [
            vec![account("a", None, true), account("a", None, true)],
            vec![account("a", Some("missing"), true)],
            vec![account("a", None, true), account("b", Some("a"), true)],
            vec![account("a", Some("a"), false)],
            vec![
                account("a", Some("b"), false),
                account("b", Some("a"), false),
            ],
        ] {
            assert!(forest(definitions).is_err());
        }
        assert!(
            assemble(
                BOOK,
                CommitSeq(1),
                vec![(account("late", None, true), CommitSeq(2))]
            )
            .is_err()
        );
    }

    #[test]
    fn deep_forests_are_iterative_and_input_order_independent() {
        let mut accounts = vec![account("0", None, false)];
        for n in 1..2048 {
            accounts.push(account(
                &n.to_string(),
                Some(&(n - 1).to_string()),
                n == 2047,
            ));
        }
        let first = forest(accounts.clone()).unwrap();
        accounts.reverse();
        let second = forest(accounts).unwrap();
        let root = account_vid(BOOK, "0");
        assert_eq!(
            first.leaves_under(root).unwrap(),
            BTreeSet::from([account_vid(BOOK, "2047")])
        );
        assert_eq!(
            first.leaves_under(root).unwrap(),
            second.leaves_under(root).unwrap()
        );
    }

    #[test]
    fn installed_chart_codec_retains_lifetime_and_period_limits() {
        let accounts = vec![
            account("summary", None, false),
            account("cash", Some("summary"), true),
        ];
        let raw = wire(&accounts).finish().unwrap();
        assert_eq!(decode_install(&raw).unwrap(), accounts);
        for scope in [LimitScope::Lifetime, LimitScope::Period] {
            let mut w = wire(&accounts);
            w.u32(1)
                .str("cash")
                .u8(1)
                .i128(i128::MIN)
                .u8(1)
                .i128(i128::MAX);
            if scope == LimitScope::Period {
                w.u32(1).str("cash");
            }
            let mut expected = accounts.clone();
            expected[1].limit = Some(BalanceLimit {
                lower: Some(i128::MIN),
                upper: Some(i128::MAX),
                scope,
            });
            assert_eq!(decode_install(&w.finish().unwrap()).unwrap(), expected);
        }
        for end in 0..raw.len() {
            assert!(
                decode_install(&raw[..end]).is_err(),
                "truncated base at {end}"
            );
        }
        let mut trailing = raw;
        trailing.push(0xff);
        assert!(decode_install(&trailing).is_err());
    }

    #[test]
    fn malformed_optional_limit_lists_do_not_reassign_policy() {
        let accounts = vec![account("cash", None, true)];
        let mut duplicate = wire(&accounts);
        duplicate
            .u32(2)
            .str("cash")
            .u8(1)
            .i128(0)
            .u8(0)
            .str("cash")
            .u8(1)
            .i128(1)
            .u8(0);
        assert!(decode_install(&duplicate.finish().unwrap()).is_err());
        let mut unknown = wire(&accounts);
        unknown.u32(1).str("other").u8(1).i128(0).u8(0);
        assert!(decode_install(&unknown.finish().unwrap()).is_err());
        let mut unbounded = wire(&accounts);
        unbounded.u32(0).u32(1).str("cash");
        assert!(decode_install(&unbounded.finish().unwrap()).is_err());
    }
}
