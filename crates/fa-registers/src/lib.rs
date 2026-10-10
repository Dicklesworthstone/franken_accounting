//! Registers as projections (plan §5.3, FA-INV-04).
//!
//! There are no balance rows in the journal. A register cell
//! `(account, unit, period)` is a deterministic fold over the committed
//! entry payloads of that period — the payloads, not the leg mirrors, because
//! the payload is what the digest covers. Every fold carries the watermark
//! (the highest commit sequence it saw) and a fold digest, so a materialized
//! register can be verified by refolding and comparing, and recovery can
//! discard and rebuild it. A register is never more authoritative than the
//! journal: `verify_period` is the proof, and drift is a finding, never a
//! correction applied to the journal.

#![forbid(unsafe_code)]

use core::fmt;
use std::collections::BTreeMap;

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::post::read_entry;
use fa_journal::rows::{AccountRow, bytes, edge_id, int, prop, scalar_bytes, scalar_text};
use fa_model::symbols::{label, property, relation};
use fa_model::{AccountType, Id128, Writer, period_vid};
use fa_money::Side;
use fgdb::{Database, WriteBatch};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

pub const FOLD_DIGEST_DOMAIN: &[u8] = b"fa:register-fold:v1";

#[derive(Debug)]
pub enum RegisterError {
    Kernel(KernelError),
    Read(fgdb::ReadError),
    Write(fgdb::WriteError),
    /// A leg sum overflowed `i128` (the register ceiling).
    Overflow,
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel(e) => write!(f, "{e}"),
            Self::Read(e) => write!(f, "substrate read: {e:?}"),
            Self::Write(e) => write!(f, "substrate write: {e:?}"),
            Self::Overflow => write!(f, "a register sum overflowed"),
        }
    }
}

impl core::error::Error for RegisterError {}

impl From<KernelError> for RegisterError {
    fn from(e: KernelError) -> Self {
        Self::Kernel(e)
    }
}
impl From<fgdb::ReadError> for RegisterError {
    fn from(e: fgdb::ReadError) -> Self {
        Self::Read(e)
    }
}
impl From<fgdb::WriteError> for RegisterError {
    fn from(e: fgdb::WriteError) -> Self {
        Self::Write(e)
    }
}

/// `(account, unit, period)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CellKey {
    pub account: VId,
    pub unit_id: u32,
    pub period: String,
}

/// One register cell: non-negative monotone sums (plan §4.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cell {
    pub key: CellKey,
    pub debits: i128,
    pub credits: i128,
    pub entry_count: u64,
}

impl Cell {
    /// Debits minus credits (positive = debit balance).
    #[must_use]
    pub fn net(&self) -> i128 {
        self.debits - self.credits
    }
}

/// The fold of one period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fold {
    pub period: String,
    /// Sorted by key.
    pub cells: Vec<Cell>,
    /// The highest commit sequence folded; `None` when the period has no entries.
    pub watermark: Option<CommitSeq>,
    pub entries: u64,
    pub fold_digest: [u8; 32],
}

/// `vid(Register) = H("fa:vid:register:v1" ‖ book ‖ account ‖ unit ‖ period)`.
#[must_use]
pub fn register_vid(book: Id128, key: &CellKey) -> VId {
    let mut h = Hasher::new();
    h.update(b"fa:vid:register:v1");
    h.update(&book.0);
    h.update(&key.account.0.to_le_bytes());
    h.update(&key.unit_id.to_le_bytes());
    h.update(&(key.period.len() as u32).to_le_bytes());
    h.update(key.period.as_bytes());
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

fn digest_of(cells: &[Cell], watermark: Option<CommitSeq>) -> [u8; 32] {
    let mut w = Writer::new();
    w.opt(watermark.as_ref(), |w, s| {
        w.u64(s.0);
    });
    w.list(cells, |w, c| {
        w.u128(c.key.account.0)
            .u32(c.key.unit_id)
            .str(&c.key.period)
            .i128(c.debits)
            .i128(c.credits)
            .u64(c.entry_count);
    });
    let mut h = Hasher::new();
    h.update(FOLD_DIGEST_DOMAIN);
    h.update(&w.finish().unwrap_or_default());
    h.finalize().0
}

/// Fold one period from its entries' payloads. Control records (no legs)
/// contribute nothing; a Pending entry's legs are not posted (plan §5.4) and
/// are excluded here — pending registers are a later increment.
pub fn fold_period<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
) -> Result<Fold, RegisterError> {
    let pvid = period_vid(&book.calendar.id, period_code);
    let mut entries = db.in_neighbours(pvid, relation::IN_PERIOD)?;
    entries.sort_unstable();
    let mut cells: BTreeMap<CellKey, Cell> = BTreeMap::new();
    let mut watermark: Option<CommitSeq> = None;
    let mut count = 0u64;
    for evid in entries {
        let Some(row) = db.vertex(evid)? else {
            continue;
        };
        if !row.labels.contains(&label::ENTRY) {
            // Materialized Register vertices also hang off the period; the
            // fold reads entries only (FA-INV-04: registers are never inputs).
            continue;
        }
        let Some((entry, created_at)) = read_entry(db, evid)? else {
            continue;
        };
        if entry.proposal.legs.is_empty() || entry.proposal.class == fa_model::EntryClass::PENDING {
            continue;
        }
        count += 1;
        watermark = Some(watermark.map_or(created_at, |w: CommitSeq| w.max(created_at)));
        let mut touched: Vec<CellKey> = Vec::new();
        for leg in &entry.proposal.legs {
            let key = CellKey {
                account: leg.account_ref,
                unit_id: leg.amount.unit.0,
                period: period_code.to_string(),
            };
            let cell = cells.entry(key.clone()).or_insert_with(|| Cell {
                key: key.clone(),
                debits: 0,
                credits: 0,
                entry_count: 0,
            });
            let slot = match leg.side {
                Side::Debit => &mut cell.debits,
                Side::Credit => &mut cell.credits,
            };
            *slot = slot
                .checked_add(leg.amount.mantissa)
                .ok_or(RegisterError::Overflow)?;
            if !touched.contains(&key) {
                touched.push(key);
            }
        }
        for key in touched {
            if let Some(c) = cells.get_mut(&key) {
                c.entry_count += 1;
            }
        }
    }
    let cells: Vec<Cell> = cells.into_values().collect();
    let fold_digest = digest_of(&cells, watermark);
    Ok(Fold {
        period: period_code.to_string(),
        cells,
        watermark,
        entries: count,
        fold_digest,
    })
}

/// Write the fold as `Register` vertices (derived state; rebuilt on demand).
pub async fn materialize<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    fold: &Fold,
) -> Result<CommitSeq, RegisterError> {
    let pvid = period_vid(&book.calendar.id, &fold.period);
    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    for cell in &fold.cells {
        let rvid = register_vid(book.book_id, &cell.key);
        batch.ensure_vertex(
            rvid,
            vec![label::REGISTER],
            vec![(
                property::BOOK_ID,
                scalar_bytes("book_id", book.book_id.0.to_vec())?,
            )],
        );
        let props = [
            (
                property::ACCOUNT_REF,
                scalar_bytes("account_ref", cell.key.account.0.to_le_bytes().to_vec())?,
            ),
            (
                property::UNIT_ID,
                CanonicalScalar::Int(i64::from(cell.key.unit_id)),
            ),
            (
                property::EFFECTIVE_PERIOD,
                scalar_text("effective_period", &cell.key.period)?,
            ),
            (
                property::DEBITS_POSTED,
                scalar_bytes("debits_posted", cell.debits.to_le_bytes().to_vec())?,
            ),
            (
                property::CREDITS_POSTED,
                scalar_bytes("credits_posted", cell.credits.to_le_bytes().to_vec())?,
            ),
            (
                property::ENTRY_COUNT,
                CanonicalScalar::Int(i64::try_from(cell.entry_count).unwrap_or(i64::MAX)),
            ),
            (
                property::WATERMARK,
                CanonicalScalar::Int(
                    i64::try_from(fold.watermark.map_or(0, |w| w.0)).unwrap_or(i64::MAX),
                ),
            ),
            (
                property::FA_FOLD_DIGEST,
                scalar_bytes("_fa_fold_digest", fold.fold_digest.to_vec())?,
            ),
        ];
        for (k, v) in props {
            batch.set_vertex_property(rvid, k, Some(v));
        }
        batch.ensure_edge_by_triple(edge_id(relation::IN_PERIOD, rvid, pvid), rvid, pvid, vec![]);
    }
    if batch.is_empty() {
        // Nothing to materialize: the period has no posting entries.
        return Ok(db.frontier()?);
    }
    Ok(db.write(&ctx.commit(), batch).await?)
}

/// One stored cell that disagrees with the refold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drift {
    pub key: CellKey,
    pub stored: Option<(i128, i128, u64)>,
    pub refolded: (i128, i128, u64),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    pub period: String,
    pub cells_checked: usize,
    pub drift: Vec<Drift>,
    pub refold_digest: [u8; 32],
    /// The fold digest the stored registers claim, when they agree with each
    /// other; `None` when no register is stored or they disagree.
    pub stored_digest: Option<[u8; 32]>,
}

impl Verification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty() && self.stored_digest == Some(self.refold_digest)
    }
}

/// Refold the period and compare every stored `Register` vertex to it.
pub fn verify_period<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
) -> Result<Verification, RegisterError> {
    let fold = fold_period(db, book, period_code)?;
    let mut drift = Vec::new();
    let mut stored_digest: Option<Option<[u8; 32]>> = None;
    for cell in &fold.cells {
        let rvid = register_vid(book.book_id, &cell.key);
        let stored = match db.vertex(rvid)? {
            None => None,
            Some(row) => {
                let d = bytes(&row, property::DEBITS_POSTED, "register.debits_posted")?;
                let c = bytes(&row, property::CREDITS_POSTED, "register.credits_posted")?;
                let n = int(&row, property::ENTRY_COUNT, "register.entry_count")?;
                let digest = match prop(&row, property::FA_FOLD_DIGEST) {
                    Some(CanonicalScalar::Bytes(b)) if b.len() == 32 => {
                        let mut d = [0u8; 32];
                        d.copy_from_slice(b.as_slice());
                        Some(d)
                    }
                    _ => None,
                };
                stored_digest = Some(match stored_digest {
                    None => digest,
                    Some(prev) if prev == digest => digest,
                    Some(_) => None,
                });
                let to_i128 = |b: Vec<u8>| -> Option<i128> {
                    let arr: [u8; 16] = b.try_into().ok()?;
                    Some(i128::from_le_bytes(arr))
                };
                match (to_i128(d), to_i128(c), u64::try_from(n).ok()) {
                    (Some(d), Some(c), Some(n)) => Some((d, c, n)),
                    _ => None,
                }
            }
        };
        let refolded = (cell.debits, cell.credits, cell.entry_count);
        if stored != Some(refolded) {
            drift.push(Drift {
                key: cell.key.clone(),
                stored,
                refolded,
            });
        }
    }
    Ok(Verification {
        period: period_code.to_string(),
        cells_checked: fold.cells.len(),
        drift,
        refold_digest: fold.fold_digest,
        stored_digest: stored_digest.flatten(),
    })
}

/// One trial-balance row: an account in one unit over the selected periods.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbRow {
    pub account: VId,
    pub code: String,
    pub name: String,
    pub account_type: AccountType,
    pub unit_id: u32,
    pub debits: i128,
    pub credits: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialBalance {
    pub periods: Vec<String>,
    pub rows: Vec<TbRow>,
    /// Per unit: (debits, credits).
    pub unit_totals: BTreeMap<u32, (i128, i128)>,
}

impl TrialBalance {
    /// FA-INV-01 at the register level: every unit's debits equal its credits.
    #[must_use]
    pub fn is_balanced(&self) -> bool {
        self.unit_totals.values().all(|(d, c)| d == c)
    }
}

/// Fold the named periods and sum them per `(account, unit)`.
pub fn trial_balance<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
) -> Result<TrialBalance, RegisterError> {
    let mut sums: BTreeMap<(VId, u32), (i128, i128)> = BTreeMap::new();
    for p in periods {
        for cell in fold_period(db, book, p)?.cells {
            let e = sums
                .entry((cell.key.account, cell.key.unit_id))
                .or_insert((0, 0));
            e.0 =
                e.0.checked_add(cell.debits)
                    .ok_or(RegisterError::Overflow)?;
            e.1 =
                e.1.checked_add(cell.credits)
                    .ok_or(RegisterError::Overflow)?;
        }
    }
    let mut rows = Vec::with_capacity(sums.len());
    let mut unit_totals: BTreeMap<u32, (i128, i128)> = BTreeMap::new();
    for ((account, unit_id), (debits, credits)) in sums {
        let (code, name, account_type) = match db.vertex(account)? {
            Some(row) => {
                let a = AccountRow::decode(&row)?;
                (a.code, a.name, AccountType(a.account_type))
            }
            None => (format!("{account:?}"), String::new(), AccountType(0)),
        };
        let t = unit_totals.entry(unit_id).or_insert((0, 0));
        t.0 = t.0.checked_add(debits).ok_or(RegisterError::Overflow)?;
        t.1 = t.1.checked_add(credits).ok_or(RegisterError::Overflow)?;
        rows.push(TbRow {
            account,
            code,
            name,
            account_type,
            unit_id,
            debits,
            credits,
        });
    }
    rows.sort_by(|a, b| a.code.cmp(&b.code).then(a.unit_id.cmp(&b.unit_id)));
    Ok(TrialBalance {
        periods: periods.to_vec(),
        rows,
        unit_totals,
    })
}

/// The periods that contribute to a balance "as of" `day` under the
/// stock/flow rule (plan §7.5, fa-xwv): stock accounts fold inception-to-date,
/// flow accounts fold the fiscal year to date. `all_periods` is the book's
/// known normal periods in order.
#[must_use]
pub fn periods_for_balance(
    account_type: AccountType,
    day: fa_time::DateDay,
    fiscal_year_of_day: i32,
    all_periods: &[fa_time::PeriodDef],
) -> Vec<String> {
    all_periods
        .iter()
        .filter(|p| p.kind == fa_time::PeriodKind::Normal && p.start <= day)
        .filter(|p| account_type.is_stock() || p.fiscal_year == fiscal_year_of_day)
        .map(|p| p.code.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_time::{DateDay, PeriodDef, PeriodKind};

    fn period(code: &str, fy: i32, start: i32, end: i32) -> PeriodDef {
        PeriodDef {
            code: code.into(),
            fiscal_year: fy,
            ordinal: 1,
            kind: PeriodKind::Normal,
            start: DateDay(start),
            end: DateDay(end),
        }
    }

    #[test]
    fn stock_folds_inception_to_date_and_flow_folds_year_to_date() {
        let periods = vec![
            period("FY2025-P12", 2025, 100, 131),
            period("FY2026-P01", 2026, 131, 162),
            period("FY2026-P02", 2026, 162, 190),
            period("FY2026-P03", 2026, 190, 221),
        ];
        let day = DateDay(170);
        assert_eq!(
            periods_for_balance(AccountType::ASSET, day, 2026, &periods),
            vec!["FY2025-P12", "FY2026-P01", "FY2026-P02"]
        );
        assert_eq!(
            periods_for_balance(AccountType::EXPENSE, day, 2026, &periods),
            vec!["FY2026-P01", "FY2026-P02"]
        );
    }

    #[test]
    fn fold_digest_is_a_function_of_cells_and_watermark() {
        let key = CellKey {
            account: VId(1),
            unit_id: 1,
            period: "P".into(),
        };
        let a = vec![Cell {
            key: key.clone(),
            debits: 10,
            credits: 10,
            entry_count: 1,
        }];
        let mut b = a.clone();
        b[0].debits = 11;
        assert_eq!(
            digest_of(&a, Some(CommitSeq(5))),
            digest_of(&a, Some(CommitSeq(5)))
        );
        assert_ne!(
            digest_of(&a, Some(CommitSeq(5))),
            digest_of(&b, Some(CommitSeq(5)))
        );
        assert_ne!(
            digest_of(&a, Some(CommitSeq(5))),
            digest_of(&a, Some(CommitSeq(6)))
        );
        assert_ne!(
            register_vid(Id128([1; 16]), &key),
            register_vid(Id128([2; 16]), &key)
        );
    }
}
