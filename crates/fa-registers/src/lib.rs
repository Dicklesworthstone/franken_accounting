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
// 128-bit (amount) arithmetic only: clippy.toml exempts the narrower integers.
#![deny(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::disallowed_methods
)]

pub mod assertion;
pub mod availability;
pub mod checkpoint;
pub mod entity;
pub mod explain;
pub mod fx;
pub mod lots;
pub mod maintainer;
pub mod open_items;
pub mod reconciliation;
pub mod replay;
mod report;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet, btree_map};

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::rows::{AccountRow, PeriodRow, bytes, int, prop, scalar_bytes, scalar_text, text};
use fa_model::symbols::{label, property, relation};
use fa_model::{
    AccountType, ControlPayload, Entry, EntryClass, EntryOrigin, Id128, Writer, period_vid,
};
use fa_money::Side;
use fa_time::{DateDay, PeriodKind};
use fgdb::{Database, VertexRow, WriteBatch};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, QueryCx, VId};

pub use availability::{
    AccountAvailability, AvailabilityDrift, AvailabilityVerification, verify_availability,
};
pub use entity::{
    EntityActivity, EntityBalance, EntityCell, EntityCellKey, EntityFold, EntityStock,
    EntityVerification, RegisterEquals, check_register_equals, fold_period_by_entity,
    period_activity_by_entity, register_equals, stock_by_entity, verify_entities,
};
pub use explain::{BalanceExplanation, explain_balance};
pub use fx::{
    CtaRollForwardSchedule, FUNCTIONAL_ACTIVITY_DIGEST_DOMAIN, FUNCTIONAL_FOLD_DIGEST_DOMAIN,
    FUNCTIONAL_STOCK_DIGEST_DOMAIN, FunctionalCell, FunctionalCellKey, FunctionalFold,
    FunctionalStockCell, FunctionalStockCellKey, FunctionalStockFold,
    REMEASUREMENT_CERTIFICATE_DOMAIN, RemeasurementBasis, RemeasurementInputLine,
    RemeasurementLineResult, RemeasurementRunResult, TRANSLATION_CERTIFICATE_DOMAIN,
    TranslatedStatement, TranslationInputLine, TranslationItemKind, TranslationLineResult,
    fold_functional_stock, fold_period_functional, fold_period_functional_excluding_classes,
    plan_cta_deconsolidation_recycling, plan_remeasurement_entry, remeasure_temporal,
    translate_current_rate, verify_functional_fold, verify_functional_fold_excluding_classes,
    verify_functional_stock, verify_remeasurement_certificate, verify_translation_certificate,
};
pub use lots::{
    LotDisposalPlan, LotDisposalRequest, LotDisposalSlice, LotItem, LotReliefEdge, LotsReport,
    fold_lots_from_open_items, lots,
};
pub use maintainer::{
    Advance, HeadFold, PreparedAdvance, advance, fold_at, fold_at_with_context, head_fold,
    prepare_advance, publish_advance, rebuild,
};
pub use open_items::{
    Application, AppliedDrift, OpenItem, OpenItemVerification, open_items, verify_open_items,
};
pub use reconciliation::{
    BANK_LINE_DOC_DOMAIN, BankStatementLine, BookCandidateEntry, MatcherConfig, PurchaseOrderLine,
    RECON_FOLD_DOMAIN, RECON_MATCH_DOMAIN, ReceivingReportLine, ReconciliationError,
    ReconciliationMatch, ReconciliationRegister, ResidualExplanation, ThreeWayMatchResult,
    ThreeWayMatchVerdict, UnpostedResidualFinding, VendorInvoiceLine,
    check_reconciled_through_lock, fold_reconciliation_register, match_bank_lines, match_three_way,
    normalize_counterparty, normalize_reference, verify_match_preserves_committed_amounts,
    verify_reconciliation_register,
};

pub const FOLD_DIGEST_DOMAIN: &[u8] = b"fa:register-fold:v2";

#[derive(Debug)]
pub enum RegisterError {
    Kernel(KernelError),
    Read(fgdb::ReadError),
    Write(fgdb::WriteError),
    /// A leg sum overflowed `i128` (the register ceiling).
    Overflow,
    InvalidSelection(String),
    Encoding(fa_model::EncodeError),
    /// A caller supplied an old or modified projection instead of the current fold.
    StaleFold,
    /// Derived cells or their maintenance metadata disagree. Rebuild from the journal.
    ProjectionDrift(String),
}

impl fmt::Display for RegisterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kernel(e) => write!(f, "{e}"),
            Self::Read(e) => write!(f, "substrate read: {e:?}"),
            Self::Write(e) => write!(f, "substrate write: {e:?}"),
            Self::Overflow => write!(f, "a register sum overflowed"),
            Self::InvalidSelection(e) => write!(f, "invalid report selection: {e}"),
            Self::Encoding(e) => write!(f, "register encoding: {e}"),
            Self::StaleFold => write!(
                f,
                "register fold changed; refold the journal before materializing"
            ),
            Self::ProjectionDrift(what) => write!(
                f,
                "register projection drift: {what}; rebuild from the journal"
            ),
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
    /// Checked debits minus credits (positive = debit balance).
    /// Returns `None` if the subtraction overflows `i128`.
    #[must_use]
    pub fn net(&self) -> Option<i128> {
        self.debits.checked_sub(self.credits)
    }
}

/// The fold of one period.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fold {
    pub period: String,
    /// Sorted by key.
    pub cells: Vec<Cell>,
    /// Outstanding reservations, keyed on the original Pending's period.
    pub pending: Vec<Cell>,
    /// The highest contributing commit, including cross-period releases
    /// and the finalization that activates staged migration chunks.
    pub watermark: Option<CommitSeq>,
    /// Posting entries contributing to `cells` (excludes reservations/releases).
    pub entries: u64,
    pub fold_digest: [u8; 32],
    /// Rolling BLAKE3 over posted leg contributions in `(commit_seq, entry_vid, ordinal)` order.
    pub(crate) posted_legs_digest: [u8; 32],
    /// Per-entry leg contribution digests of unresolved `Pending` holds, ordered by `(commit_seq, entry_vid)`.
    pub(crate) pending_holds: BTreeMap<(CommitSeq, VId), [u8; 32]>,
}

impl Fold {
    /// The unresolved `Pending` holds the fold digest commits to: each hold's
    /// leg contribution digest, keyed by `(commit_seq, entry_vid)`. Read-only;
    /// the fold alone maintains them.
    #[must_use]
    pub fn pending_holds(&self) -> &BTreeMap<(CommitSeq, VId), [u8; 32]> {
        &self.pending_holds
    }
}

/// `vid(Register) = H("fa:vid:register:v1" ‖ book ‖ account ‖ unit ‖ period)`.
#[must_use]
// The period code's length prefix: a period ref is at most
// MAX_PERIOD_REF_BYTES (32) bytes, far inside u32.
#[allow(clippy::cast_possible_truncation)]
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

pub(crate) fn fold_leg_contribution(
    prev: [u8; 32],
    (commit_seq, entry, ordinal): (CommitSeq, VId, u16),
    account: VId,
    unit_id: u32,
    side: Side,
    mantissa: i128,
) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(b"fa:register-leg-contribution:v1");
    h.update(&prev);
    h.update(&commit_seq.0.to_le_bytes());
    h.update(&entry.0.to_le_bytes());
    h.update(&ordinal.to_le_bytes());
    h.update(&account.0.to_le_bytes());
    h.update(&unit_id.to_le_bytes());
    h.update(&[match side {
        Side::Debit => 0,
        Side::Credit => 1,
    }]);
    h.update(&mantissa.to_le_bytes());
    h.finalize().0
}

pub(crate) fn fold_entry_contributions(
    mut acc: [u8; 32],
    commit_seq: CommitSeq,
    entry_vid: VId,
    entry: &Entry,
) -> Result<[u8; 32], RegisterError> {
    for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
        let ordinal = u16::try_from(ordinal)
            .map_err(|_| KernelError::Corrupt("leg ordinal exceeds u16".into()))?;
        acc = fold_leg_contribution(
            acc,
            (commit_seq, entry_vid, ordinal),
            leg.account_ref,
            leg.amount.unit.0,
            leg.side,
            leg.amount.mantissa,
        );
    }
    Ok(acc)
}

pub(crate) fn digest_of(
    period: &str,
    cells: &[Cell],
    pending: &[Cell],
    watermark: Option<CommitSeq>,
    posted_legs_digest: [u8; 32],
    pending_holds: &BTreeMap<(CommitSeq, VId), [u8; 32]>,
) -> Result<[u8; 32], RegisterError> {
    let mut w = Writer::new();
    w.str(period);
    w.opt(watermark.as_ref(), |w, s| {
        w.u64(s.0);
    });
    w.fixed(&posted_legs_digest);
    let holds: Vec<_> = pending_holds.iter().collect();
    w.list(&holds, |w, ((seq, vid), digest)| {
        w.u64(seq.0).u128(vid.0).fixed(*digest);
    });
    for column in [cells, pending] {
        w.list(column, |w, c| {
            w.u128(c.key.account.0)
                .u32(c.key.unit_id)
                .str(&c.key.period)
                .i128(c.debits)
                .i128(c.credits)
                .u64(c.entry_count);
        });
    }
    let mut h = Hasher::new();
    h.update(FOLD_DIGEST_DOMAIN);
    h.update(&w.finish().map_err(RegisterError::Encoding)?);
    Ok(h.finalize().0)
}

/// The commit sequence a known-at selection pins: the head when `None`.
/// Public for the analytics layer (fa-lantern), which reads the snapshot
/// the folds read.
pub fn resolve_known_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    known_at: Option<CommitSeq>,
) -> Result<CommitSeq, RegisterError> {
    let head = db.frontier()?;
    let seq = known_at.unwrap_or(head);
    if seq > head {
        return Err(RegisterError::InvalidSelection(format!(
            "known-at sequence {} is beyond book head {}",
            seq.0, head.0
        )));
    }
    Ok(seq)
}

pub(crate) fn period_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    code: &str,
    seq: CommitSeq,
) -> Result<PeriodRow, RegisterError> {
    let row = db
        .vertex_at(period_vid(&book.calendar.id, code), seq)?
        .filter(|r| r.labels.contains(&label::PERIOD))
        .ok_or_else(|| {
            RegisterError::InvalidSelection(format!(
                "unknown period `{code}` at sequence {}",
                seq.0
            ))
        })?;
    Ok(PeriodRow::decode(&row)?)
}

/// Read the authoritative payloads in a fixed historical snapshot. Derived
/// IN_PERIOD edges are not an input: a damaged projection cannot hide a posting.
/// The FA-INV-07 migration predicate applies here, once, for every fold:
/// a chunk of a migration run is selected only where its run is Finalized
/// at `seq` (`fa_journal::migration::visible_at`, plan §8.6).
/// Public for the analytics layer (fa-lantern): one entry-stream reader for
/// every fold and procedure, so the migration predicate is applied in one
/// place.
pub fn entries_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    seq: CommitSeq,
) -> Result<Vec<(VId, Entry, CommitSeq)>, RegisterError> {
    let mut entries = Vec::new();
    let mut runs = BTreeMap::new();
    for row in db.vertices_at(seq)? {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "entry.payload")?)
            .map_err(KernelError::from)?;
        if entry.proposal.book_id != book.book_id || entry.proposal.branch_id != Id128::TRUNK {
            return Err(KernelError::Corrupt(
                "entry coordinate does not belong to this trunk book".into(),
            )
            .into());
        }
        if !fa_journal::migration::visible_at(db, &entry, seq, &mut runs)? {
            continue;
        }
        entries.push((row.vid, entry, row.created_at));
    }
    entries.sort_by_key(|(vid, _, created_at)| (*created_at, vid.0));
    Ok(entries)
}

/// Visibility changes are contributions too. Resolve them from immutable
/// control payloads without changing any entry's real creation sequence.
pub(crate) fn migration_activations(
    entries: &[(VId, Entry, CommitSeq)],
) -> Result<BTreeMap<VId, CommitSeq>, RegisterError> {
    let mut activated = BTreeMap::new();
    for (_, entry, seq) in entries {
        if let Some(ControlPayload::MigrationControl {
            run_ref,
            kind: fa_journal::migration::kind::FINALIZE,
            ..
        }) = &entry.proposal.control
            && activated.insert(*run_ref, *seq).is_some()
        {
            return Err(KernelError::Corrupt("duplicate migration finalization".into()).into());
        }
    }
    Ok(activated)
}

pub(crate) fn contribution_seq(
    entry: &Entry,
    created_at: CommitSeq,
    activated: &BTreeMap<VId, CommitSeq>,
) -> Result<CommitSeq, RegisterError> {
    let EntryOrigin::Migration { run_ref, .. } = &entry.proposal.origin else {
        return Ok(created_at);
    };
    let finalized_at = activated
        .get(run_ref)
        .copied()
        .filter(|at| *at > created_at)
        .ok_or_else(|| {
            KernelError::Corrupt("visible migration chunk lacks a later finalization".into())
        })?;
    Ok(finalized_at)
}

/// The period an entry's effective date (and declared period, if any)
/// resolves to. Public for the analytics layer (fa-lantern).
pub fn entry_period(book: &BookContext, entry: &Entry) -> Result<String, RegisterError> {
    let date = entry.proposal.effective_date;
    let fy = book
        .calendar
        .fiscal_year_of(date)
        .map_err(KernelError::from)?;
    let periods = book
        .calendar
        .periods_for_year(fy)
        .map_err(KernelError::from)?;
    fa_time::resolve_period(
        &periods,
        date,
        entry
            .proposal
            .effective_period
            .as_ref()
            .map(|p| p.code.as_str()),
    )
    .map(|p| p.code.clone())
    .map_err(|e| KernelError::Corrupt(format!("entry period: {e:?}")).into())
}

/// [`entry_period`] over a stream of entries. An entry's period depends
/// only on its effective date, its declared period and the book's calendar,
/// so each distinct pair is resolved once instead of rebuilding the fiscal
/// year's periods for every entry (fa-rbs3). Errors are not kept: asking
/// again gives [`entry_period`]'s error again.
pub(crate) struct PeriodOf<'a> {
    book: &'a BookContext,
    resolved: BTreeMap<(DateDay, Option<String>), String>,
}

impl<'a> PeriodOf<'a> {
    pub(crate) fn new(book: &'a BookContext) -> Self {
        Self {
            book,
            resolved: BTreeMap::new(),
        }
    }

    pub(crate) fn period(&mut self, entry: &Entry) -> Result<&str, RegisterError> {
        let key = (
            entry.proposal.effective_date,
            entry
                .proposal
                .effective_period
                .as_ref()
                .map(|p| p.code.clone()),
        );
        Ok(match self.resolved.entry(key) {
            btree_map::Entry::Occupied(known) => known.into_mut().as_str(),
            btree_map::Entry::Vacant(new) => new.insert(entry_period(self.book, entry)?).as_str(),
        })
    }
}

/// Resolve holds using authoritative payloads at the same known-at frontier.
/// A missing or duplicated target is corruption, not an absent reservation.
pub(crate) fn resolutions(
    entries: &[(VId, Entry, CommitSeq)],
) -> Result<BTreeMap<VId, CommitSeq>, RegisterError> {
    let by_id: BTreeMap<_, _> = entries.iter().map(|(id, e, seq)| (*id, (e, seq))).collect();
    let mut resolved = BTreeMap::new();
    for (vid, entry, seq) in entries {
        if entry.proposal.class != EntryClass::RESOLUTION {
            continue;
        }
        let target = entry
            .proposal
            .pending
            .as_ref()
            .and_then(|p| p.resolution_of)
            .ok_or_else(|| KernelError::Corrupt("resolution has no pending target".into()))?;
        let Some((original, original_seq)) = by_id.get(&target.vid) else {
            return Err(KernelError::Corrupt("resolution target is missing".into()).into());
        };
        if original.proposal.class != EntryClass::PENDING
            || original.entry_digest != target.entry_digest
            // An earlier batch member and its resolution publish atomically.
            // Their VId order is not their staging order; both are visible at
            // this frontier, with the exact target digest and derived identity.
            || *original_seq > seq
            || *vid != fa_journal::rows::resolution_vid(target.vid)
            || resolved.insert(target.vid, *seq).is_some()
        {
            return Err(
                KernelError::Corrupt("invalid or duplicate pending resolution".into()).into(),
            );
        }
    }
    Ok(resolved)
}

fn add_entry(
    cells: &mut BTreeMap<CellKey, Cell>,
    entry: &Entry,
    period: &str,
) -> Result<(), RegisterError> {
    let mut touched = BTreeSet::new();
    for leg in &entry.proposal.legs {
        let key = CellKey {
            account: leg.account_ref,
            unit_id: leg.amount.unit.0,
            period: period.into(),
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
        touched.insert(key);
    }
    for key in touched {
        let cell = cells
            .get_mut(&key)
            .ok_or_else(|| KernelError::Corrupt("missing fold cell".into()))?;
        cell.entry_count = cell
            .entry_count
            .checked_add(1)
            .ok_or(RegisterError::Overflow)?;
    }
    Ok(())
}

/// Fold posted amounts and outstanding reservations from immutable payloads.
/// A resolution releases the original period's entire hold, even when its
/// posted sub-vector belongs to a later period (plan §5.4).
pub fn fold_period<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
) -> Result<Fold, RegisterError> {
    fold_period_at(db, book, period_code, None)
}

pub fn fold_period_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    known_at: Option<CommitSeq>,
) -> Result<Fold, RegisterError> {
    fold_period_counted(db, book, period_code, known_at).map(|(fold, _)| fold)
}

/// [`fold_period_at`] for each of `periods`, in their order, reading and
/// decoding the journal once for all of them rather than once per period
/// (fa-rbs3). The result, an error included, is the one folding each period
/// alone in order returns.
pub fn fold_periods_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[&str],
    known_at: Option<CommitSeq>,
) -> Result<Vec<Fold>, RegisterError> {
    // An empty request reads nothing, as no single-period fold would.
    if periods.is_empty() {
        return Ok(Vec::new());
    }
    let seq = resolve_known_at(db, known_at)?;
    let mut folds = folds_at(db, book, &periods.iter().copied().collect(), seq, None);
    let mut ordered = Vec::with_capacity(periods.len());
    for period in periods {
        if let Some(Ok((fold, _))) = folds.get(*period) {
            ordered.push(fold.clone());
            continue;
        }
        return Err(match folds.remove(*period) {
            Some(Err(error)) => error,
            _ => KernelError::Corrupt("a requested period has no fold".into()).into(),
        });
    }
    Ok(ordered)
}

/// Each of `periods` folded at `seq` exactly as [`fold_period_counted`] folds
/// it alone: from one read and decode of the prefix when every fold
/// succeeds; when any fails, every period is folded alone again, so each
/// result, an error included, is the single fold's (fa-rbs3). Errors come
/// only from damaged books, where the cost of exactness does not matter.
/// `read` is [`entries_at`] of `db` at `seq` when the caller already holds it.
pub(crate) fn folds_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &BTreeSet<&str>,
    seq: CommitSeq,
    read: Option<&[(VId, Entry, CommitSeq)]>,
) -> PeriodFolds {
    let together = || -> Result<_, RegisterError> {
        resolve_known_at(db, Some(seq))?;
        for period in periods {
            period_at(db, book, period, seq)?;
        }
        match read {
            Some(entries) => fold_entries(book, entries, periods),
            None => fold_entries(book, &entries_at(db, book, seq)?, periods),
        }
    };
    match together() {
        Ok(folds) => folds
            .into_iter()
            .map(|(period, fold)| (period, Ok(fold)))
            .collect(),
        Err(_) => periods
            .iter()
            .map(|period| {
                (
                    (*period).to_string(),
                    fold_period_counted(db, book, period, Some(seq)),
                )
            })
            .collect(),
    }
}

/// Each requested period's fold and leg count, or the error folding that
/// period alone gives ([`folds_at`]).
pub(crate) type PeriodFolds = BTreeMap<String, Result<(Fold, u64), RegisterError>>;

/// Take one period's fold out of [`folds_at`]'s answer.
pub(crate) fn take_fold(
    folds: &mut PeriodFolds,
    period: &str,
) -> Result<(Fold, u64), RegisterError> {
    folds.remove(period).unwrap_or_else(|| {
        Err(KernelError::Corrupt("a requested period has no fold".into()).into())
    })
}

/// [`fold_period_at`], with the number of legs it added to cells, posted
/// and held: the fold's own count of the work it did, which a rebuild
/// reports as its work witness (plan §17, fa-ykbp).
pub(crate) fn fold_period_counted<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    known_at: Option<CommitSeq>,
) -> Result<(Fold, u64), RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    period_at(db, book, period_code, seq)?;
    let entries = entries_at(db, book, seq)?;
    fold_entries(book, &entries, &BTreeSet::from([period_code]))?
        .into_values()
        .next()
        .ok_or_else(|| KernelError::Corrupt("a requested period has no fold".into()).into())
}

/// One period's fold while the entry stream passes ([`fold_entries`]).
#[derive(Default)]
struct PeriodFold {
    cells: BTreeMap<CellKey, Cell>,
    pending: BTreeMap<CellKey, Cell>,
    watermark: Option<CommitSeq>,
    count: u64,
    legs: u64,
    posted_legs_digest: [u8; 32],
    pending_holds: BTreeMap<(CommitSeq, VId), [u8; 32]>,
}

/// Fold each of `periods` from one entry stream, as [`entries_at`] returns
/// it for the fold's prefix, with each fold's leg count. The journal is read
/// and decoded once for every period rather than once per period (fa-rbs3);
/// a single period's fold is this with one code, so a period folds the same
/// whether alone or beside others. An error is the first one the stream meets.
pub(crate) fn fold_entries(
    book: &BookContext,
    entries: &[(VId, Entry, CommitSeq)],
    periods: &BTreeSet<&str>,
) -> Result<BTreeMap<String, (Fold, u64)>, RegisterError> {
    let resolved = resolutions(entries)?;
    let activated = migration_activations(entries)?;
    let mut folds: BTreeMap<&str, PeriodFold> = periods
        .iter()
        .map(|period| (*period, PeriodFold::default()))
        .collect();
    let mut period_of = PeriodOf::new(book);
    for (vid, entry, created_at) in entries {
        if entry.proposal.legs.is_empty() {
            continue;
        }
        let Some(period_code) = periods.get(period_of.period(entry)?).copied() else {
            continue;
        };
        let Some(fold) = folds.get_mut(period_code) else {
            continue;
        };
        let (vid, created_at) = (*vid, *created_at);
        let contribution = contribution_seq(entry, created_at, &activated)?;
        fold.watermark = Some(
            fold.watermark
                .map_or(contribution, |w: CommitSeq| w.max(contribution)),
        );
        if entry.proposal.class == EntryClass::PENDING {
            if let Some(release) = resolved.get(&vid) {
                fold.watermark = Some(fold.watermark.map_or(*release, |w| w.max(*release)));
            } else {
                add_entry(&mut fold.pending, entry, period_code)?;
                fold.legs = fold
                    .legs
                    .checked_add(entry.proposal.legs.len() as u64)
                    .ok_or(RegisterError::Overflow)?;
                let hold_digest = fold_entry_contributions([0u8; 32], created_at, vid, entry)?;
                fold.pending_holds.insert((created_at, vid), hold_digest);
            }
        } else {
            fold.count = fold.count.checked_add(1).ok_or(RegisterError::Overflow)?;
            add_entry(&mut fold.cells, entry, period_code)?;
            fold.legs = fold
                .legs
                .checked_add(entry.proposal.legs.len() as u64)
                .ok_or(RegisterError::Overflow)?;
            fold.posted_legs_digest =
                fold_entry_contributions(fold.posted_legs_digest, created_at, vid, entry)?;
        }
    }
    folds
        .into_iter()
        .map(|(period_code, fold)| {
            let cells: Vec<Cell> = fold.cells.into_values().collect();
            let pending: Vec<Cell> = fold.pending.into_values().collect();
            let fold_digest = digest_of(
                period_code,
                &cells,
                &pending,
                fold.watermark,
                fold.posted_legs_digest,
                &fold.pending_holds,
            )?;
            Ok((
                period_code.to_string(),
                (
                    Fold {
                        period: period_code.to_string(),
                        cells,
                        pending,
                        watermark: fold.watermark,
                        entries: fold.count,
                        fold_digest,
                        posted_legs_digest: fold.posted_legs_digest,
                        pending_holds: fold.pending_holds,
                    },
                    fold.legs,
                ),
            ))
        })
        .collect()
}

type CellValues = (i128, i128, u64);

/// A materialized row contains both columns, including a zero posted column
/// for an account which only has an outstanding reservation.
fn fold_columns(fold: &Fold) -> BTreeMap<&CellKey, (CellValues, CellValues)> {
    let mut columns = BTreeMap::new();
    for c in &fold.cells {
        columns.entry(&c.key).or_insert(((0, 0, 0), (0, 0, 0))).0 =
            (c.debits, c.credits, c.entry_count);
    }
    for c in &fold.pending {
        columns.entry(&c.key).or_insert(((0, 0, 0), (0, 0, 0))).1 =
            (c.debits, c.credits, c.entry_count);
    }
    columns
}

/// Write the fold as `Register` vertices (derived state; rebuilt on demand).
pub async fn materialize<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    fold: &Fold,
) -> Result<CommitSeq, RegisterError> {
    // The API accepts a Fold for inspection, not as a new source of truth.
    // Exclusive access to Database keeps this check and publication together.
    let (literal, legs) = fold_period_counted(db, book, &fold.period, None)?;
    if literal != *fold {
        return Err(RegisterError::StaleFold);
    }
    // Preserve the existing empty-materialization no-op. Explicit advance
    // initializes maintenance metadata even for an empty period; materialize
    // only needs that state when there are cells, repairs, or an existing cursor.
    if fold.cells.is_empty()
        && fold.pending.is_empty()
        && db
            .vertex(maintainer::state_vid(book.book_id, &fold.period))?
            .is_none()
        && db
            .vertex(checkpoint::head_vid(book.book_id, &fold.period))?
            .is_none()
        && materialize_batch(db, book, fold)?.is_empty()
    {
        return Ok(db.frontier()?);
    }
    let prepared = maintainer::prepare_fold(db, book, literal, legs)?;
    Ok(maintainer::publish_advance(db, ctx, book, prepared)
        .await?
        .published_at)
}

/// Every `IN_PERIOD` edge by its source, as `(eid, dst)` in scan order: one
/// pass over the book's edges instead of one per register cell (fa-rbs3).
fn period_memberships(edges: &[fgdb::EdgeRecord]) -> BTreeMap<VId, Vec<(fgdb_types::EId, VId)>> {
    let mut by_source: BTreeMap<VId, Vec<(fgdb_types::EId, VId)>> = BTreeMap::new();
    for edge in edges {
        if edge.entry.relation == relation::IN_PERIOD {
            by_source
                .entry(edge.entry.src)
                .or_default()
                .push((edge.entry.eid, edge.entry.dst));
        }
    }
    by_source
}

/// Build the projection write without publishing it, so maintenance can
/// publish its cursor in the same transaction. Callers validate the fold.
fn materialize_batch<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    fold: &Fold,
) -> Result<WriteBatch, RegisterError> {
    let pvid = period_vid(&book.calendar.id, &fold.period);
    let mut batch = WriteBatch::new(relation::IN_PERIOD);
    let expected: BTreeSet<_> = fold
        .cells
        .iter()
        .chain(fold.pending.iter())
        .map(|c| register_vid(book.book_id, &c.key))
        .collect();
    let candidates = stored_registers(db, book, fold)?;
    let memberships = period_memberships(&db.edges()?);
    for row in candidates.values() {
        if row.labels.iter().any(|l| *l != label::REGISTER) {
            return Err(KernelError::Corrupt(
                "register identity also belongs to an authoritative object".into(),
            )
            .into());
        }
        if !expected.contains(&row.vid) {
            // Derived cells may be retired, but their identity must remain
            // reusable if a later legitimate posting creates this cell.
            batch.set_vertex_label(row.vid, label::REGISTER, false);
            batch.set_vertex_property(row.vid, property::EFFECTIVE_PERIOD, None);
        }
        for (eid, dst) in memberships.get(&row.vid).into_iter().flatten() {
            if !expected.contains(&row.vid) || *dst != pvid {
                batch.delete_edge(*eid);
            }
        }
    }
    for (key, (posted, pending)) in fold_columns(fold) {
        let rvid = register_vid(book.book_id, key);
        batch.ensure_vertex(
            rvid,
            vec![label::REGISTER],
            vec![(
                property::BOOK_ID,
                scalar_bytes("book_id", book.book_id.0.to_vec())?,
            )],
        );
        batch.set_vertex_label(rvid, label::REGISTER, true);
        let props = [
            (
                property::BOOK_ID,
                scalar_bytes("book_id", book.book_id.0.to_vec())?,
            ),
            (
                property::ACCOUNT_REF,
                scalar_bytes("account_ref", key.account.0.to_le_bytes().to_vec())?,
            ),
            (
                property::UNIT_ID,
                CanonicalScalar::Int(i64::from(key.unit_id)),
            ),
            (
                property::EFFECTIVE_PERIOD,
                scalar_text("effective_period", &key.period)?,
            ),
            (
                property::DEBITS_POSTED,
                scalar_bytes("debits_posted", posted.0.to_le_bytes().to_vec())?,
            ),
            (
                property::CREDITS_POSTED,
                scalar_bytes("credits_posted", posted.1.to_le_bytes().to_vec())?,
            ),
            (
                property::ENTRY_COUNT,
                CanonicalScalar::Int(i64::try_from(posted.2).map_err(|_| RegisterError::Overflow)?),
            ),
            (
                property::DEBITS_PENDING,
                scalar_bytes("debits_pending", pending.0.to_le_bytes().to_vec())?,
            ),
            (
                property::CREDITS_PENDING,
                scalar_bytes("credits_pending", pending.1.to_le_bytes().to_vec())?,
            ),
            (
                property::PENDING_COUNT,
                CanonicalScalar::Int(
                    i64::try_from(pending.2).map_err(|_| RegisterError::Overflow)?,
                ),
            ),
            (
                property::WATERMARK,
                CanonicalScalar::Int(
                    i64::try_from(fold.watermark.map_or(0, |w| w.0))
                        .map_err(|_| RegisterError::Overflow)?,
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
        // A removed edge ID is spent in the substrate. A repair therefore
        // uses a fresh deterministic projection identity at this frontier.
        let mut h = Hasher::new();
        h.update(b"fa:register-membership:v1");
        h.update(&rvid.0.to_le_bytes());
        h.update(&pvid.0.to_le_bytes());
        h.update(&db.frontier()?.0.to_le_bytes());
        let mut lo = [0; 16];
        lo.copy_from_slice(&h.finalize().0[..16]);
        batch.ensure_edge_by_triple(fgdb_types::EId(u128::from_le_bytes(lo)), rvid, pvid, vec![]);
    }
    Ok(batch)
}

/// One stored cell that disagrees with the refold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Drift {
    pub key: CellKey,
    pub stored: Option<(i128, i128, u64)>,
    pub refolded: (i128, i128, u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheStatus {
    /// No maintenance header or stored cells exist. There is no cache to
    /// disagree with the journal, so the period is green and every entry is
    /// unread lag (`stale`), but no processed journal prefix is certified.
    Uninitialized,
    /// Stored cells and the maintenance header agree with their journal prefix.
    Verified,
    /// Stored cells, metadata, or the authoritative prefix disagree.
    Corrupt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    pub period: String,
    pub cache_status: CacheStatus,
    /// The journal prefix independently verified against the current stored
    /// cells. None on a mismatch or an uninitialized cache. This is the
    /// processed basis, not the last monetary contribution.
    pub verified_through: Option<CommitSeq>,
    /// Whether journal entries remain after the checked basis. Meaningful
    /// only when is_green(); corruption never becomes ordinary lag.
    pub stale: bool,
    /// Book-wide unread Entry creations, including controls and staged
    /// migrations. Projection-only commits do not contribute to this count.
    /// Counted by the pinned substrate's `(vid, created_at)` identity; a
    /// replaced prefix identity is corruption, not a second legitimate entry.
    pub lag_entries: usize,
    pub cells_checked: usize,
    pub drift: Vec<Drift>,
    pub pending_drift: Vec<Drift>,
    /// Membership, identity, or metadata mismatches, even if amounts agree.
    pub projection_errors: Vec<String>,
    pub refold_digest: [u8; 32],
    /// The fold digest the stored registers claim, when they agree with each
    /// other; `None` when no register is stored or they disagree.
    pub stored_digest: Option<[u8; 32]>,
}

impl Verification {
    #[must_use]
    pub fn is_green(&self) -> bool {
        self.drift.is_empty()
            && self.pending_drift.is_empty()
            && self.projection_errors.is_empty()
            && (self.cells_checked == 0 || self.stored_digest == Some(self.refold_digest))
    }
}

fn stored_registers<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    fold: &Fold,
) -> Result<BTreeMap<VId, VertexRow>, RegisterError> {
    stored_registers_in(db, book, fold, &db.vertices()?)
}

/// [`stored_registers`] among `rows`, the book's current vertices.
fn stored_registers_in<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    fold: &Fold,
    rows: &[VertexRow],
) -> Result<BTreeMap<VId, VertexRow>, RegisterError> {
    let expected: BTreeSet<_> = fold
        .cells
        .iter()
        .chain(fold.pending.iter())
        .map(|c| register_vid(book.book_id, &c.key))
        .collect();
    let linked: BTreeSet<_> = db
        .in_neighbours(
            period_vid(&book.calendar.id, &fold.period),
            relation::IN_PERIOD,
        )?
        .into_iter()
        .collect();
    Ok(rows.iter().filter(|row| {
        expected.contains(&row.vid) || (row.labels.contains(&label::REGISTER)
            && (linked.contains(&row.vid) || matches!(prop(row, property::EFFECTIVE_PERIOD), Some(CanonicalScalar::Text(p)) if p.as_str() == fold.period)))
    }).map(|row| (row.vid, row.clone())).collect())
}

fn stored_values(row: &VertexRow, pending: bool) -> Result<Option<CellValues>, RegisterError> {
    let (debits, credits, count) = if pending {
        (
            property::DEBITS_PENDING,
            property::CREDITS_PENDING,
            property::PENDING_COUNT,
        )
    } else {
        (
            property::DEBITS_POSTED,
            property::CREDITS_POSTED,
            property::ENTRY_COUNT,
        )
    };
    // Registers written before pending columns existed require a rebuild.
    // Missing columns are drift, never silently assumed to be zero.
    if [debits, credits, count]
        .iter()
        .any(|p| prop(row, *p).is_none())
    {
        return Ok(None);
    }
    let d = bytes(row, debits, "register.debits")?;
    let c = bytes(row, credits, "register.credits")?;
    let n = int(row, count, "register.count")?;
    Ok(
        match (
            <[u8; 16]>::try_from(d),
            <[u8; 16]>::try_from(c),
            u64::try_from(n),
        ) {
            (Ok(d), Ok(c), Ok(n)) => Some((i128::from_le_bytes(d), i128::from_le_bytes(c), n)),
            _ => None,
        },
    )
}

/// Compare current stored cells with the journal at their processed basis,
/// reporting freshness separately. Later postings are lag, not corruption.
/// A headerless cache retains the current-head comparison; no historical
/// prefix is inferred from a contribution watermark or publication sequence.
pub fn verify_period<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
) -> Result<Verification, RegisterError> {
    verify_period_in(&mut Reads::new(db, book, &[period_code]), period_code)
}

type Memberships = BTreeMap<VId, Vec<(fgdb_types::EId, VId)>>;

/// What verifying several periods reads of the book, each read once
/// (fa-rbs3). A `&Database` cannot change, so every answer is the one a
/// fresh read gives: a journal prefix is read and decoded once, and every
/// requested period folded from it ([`folds_at`]); the current vertices and
/// the edges' period memberships are scanned once, and a prefix's Entry rows
/// once while it is in use.
pub(crate) struct Reads<'a, V: asupersync::fs::Vfs + Clone> {
    pub(crate) db: &'a Database<V>,
    pub(crate) book: &'a BookContext,
    periods: BTreeSet<String>,
    folds: BTreeMap<CommitSeq, PeriodFolds>,
    vertices: Option<Vec<VertexRow>>,
    memberships: Option<Memberships>,
    entry_rows: BTreeMap<CommitSeq, BTreeMap<VId, VertexRow>>,
}

impl<'a, V: asupersync::fs::Vfs + Clone> Reads<'a, V> {
    pub(crate) fn new(db: &'a Database<V>, book: &'a BookContext, periods: &[&str]) -> Self {
        Self {
            db,
            book,
            periods: periods.iter().map(|period| (*period).to_string()).collect(),
            folds: BTreeMap::new(),
            vertices: None,
            memberships: None,
            entry_rows: BTreeMap::new(),
        }
    }

    /// `fold_period_at(db, book, period, Some(seq))`, exactly.
    pub(crate) fn fold_at(&mut self, period: &str, seq: CommitSeq) -> Result<Fold, RegisterError> {
        let (db, book) = (self.db, self.book);
        if !self.periods.contains(period) {
            return fold_period_at(db, book, period, Some(seq));
        }
        let periods = &self.periods;
        let folds = self.folds.entry(seq).or_insert_with(|| {
            folds_at(
                db,
                book,
                &periods.iter().map(String::as_str).collect(),
                seq,
                None,
            )
        });
        if let Some(Ok((fold, _))) = folds.get(period) {
            return Ok(fold.clone());
        }
        match folds.remove(period) {
            Some(Err(error)) => Err(error),
            _ => fold_period_at(db, book, period, Some(seq)),
        }
    }

    /// The current vertices and the edges' period memberships.
    fn scans(&mut self) -> Result<(&[VertexRow], &Memberships), RegisterError> {
        if self.vertices.is_none() {
            self.vertices = Some(self.db.vertices()?);
        }
        if self.memberships.is_none() {
            self.memberships = Some(period_memberships(&self.db.edges()?));
        }
        match (&self.vertices, &self.memberships) {
            (Some(rows), Some(memberships)) => Ok((rows, memberships)),
            _ => Err(KernelError::Corrupt("a book scan was not read".into()).into()),
        }
    }

    /// Read the Entry rows at `seq` unless they are held. Rows are the
    /// book's size, so at most the head's and one other prefix's are held:
    /// a book's periods usually share one basis.
    fn load_entry_rows(&mut self, seq: CommitSeq, head: CommitSeq) -> Result<(), RegisterError> {
        if self.entry_rows.contains_key(&seq) {
            return Ok(());
        }
        if seq != head {
            self.entry_rows.retain(|at, _| *at == head);
        }
        let rows = self
            .db
            .vertices_at(seq)?
            .into_iter()
            .filter(|row| row.labels.contains(&label::ENTRY))
            .map(|row| (row.vid, row))
            .collect();
        self.entry_rows.insert(seq, rows);
        Ok(())
    }

    fn entry_rows(&self, seq: CommitSeq) -> Result<&BTreeMap<VId, VertexRow>, RegisterError> {
        self.entry_rows.get(&seq).ok_or_else(|| {
            KernelError::Corrupt("a prefix's entry rows were not read".into()).into()
        })
    }
}

fn verify_period_in<V: asupersync::fs::Vfs + Clone>(
    reads: &mut Reads<'_, V>,
    period_code: &str,
) -> Result<Verification, RegisterError> {
    let (db, book) = (reads.db, reads.book);
    let head = db.frontier()?;
    let (through, state_error) = maintainer::verify_state_in(reads, period_code)?;
    let basis = through.unwrap_or(head);
    let fold = reads.fold_at(period_code, basis)?;
    let (rows, memberships) = reads.scans()?;
    let mut result = verify_projection_in(db, book, &fold, rows, memberships)?;
    let has_stored_cells = !stored_registers_in(db, book, &fold, rows)?.is_empty();
    let uninitialized = through.is_none() && state_error.is_none() && !has_stored_cells;
    if let Some(error) = state_error {
        result.projection_errors.push(error);
    }
    if through.is_none() && has_stored_cells {
        result
            .projection_errors
            .push("stored register cells have no valid maintenance header".into());
    }
    if uninitialized {
        // Nothing was ever materialized: no stored cell exists to disagree
        // with the refold, so the refold's cells are unread work, not drift
        // (the fa-q2z rule that lag is never corruption, at its extreme). A
        // header without cells, or cells without a header, stays corruption.
        result.drift.clear();
        result.pending_drift.clear();
        result.cells_checked = 0;
        reads.load_entry_rows(head, head)?;
        result.lag_entries = reads.entry_rows(head)?.len();
    }
    if basis < head {
        reads.load_entry_rows(basis, head)?;
        reads.load_entry_rows(head, head)?;
        let before = reads.entry_rows(basis)?;
        let current = reads.entry_rows(head)?;
        // Freshness is not head-minus-basis: register publications and other
        // non-entry commits do not create work. Never hide a rewrite or
        // retirement of the authoritative prefix behind a historical check.
        result.lag_entries = current
            .values()
            .filter(|row| row.created_at > basis)
            .count();
        for (vid, row) in before {
            if current.get(vid).is_none_or(|now| {
                now.created_at != row.created_at
                    || prop(now, property::FA_PAYLOAD) != prop(row, property::FA_PAYLOAD)
                    || prop(now, property::FA_DIGEST) != prop(row, property::FA_DIGEST)
            }) {
                result.projection_errors.push(format!(
                    "journal entry {:032x} changed or disappeared after the checked prefix",
                    vid.0
                ));
            }
        }
        for row in current.values() {
            if row.created_at <= basis && !before.contains_key(&row.vid) {
                result.projection_errors.push(format!(
                    "journal entry {:032x} appeared with a creation sequence inside the checked prefix",
                    row.vid.0
                ));
            }
        }
    }
    result.stale = result.lag_entries != 0;
    result.cache_status = if uninitialized {
        CacheStatus::Uninitialized
    } else if result.is_green() {
        result.verified_through = through;
        CacheStatus::Verified
    } else {
        CacheStatus::Corrupt
    };
    Ok(result)
}

/// Verify the maintained cells and every checkpoint reachable from their
/// current checkpoint pointer. Each snapshot is independently refolded from
/// immutable journal entries at its own processed prefix; intact checksums
/// alone do not establish that a cache contains the right amounts or history.
///
/// A broken checkpoint chain is reported as projection drift. Verification
/// never edits checkpoints or the journal; explicit rebuilding replaces the
/// damaged derived chain with a fresh independently computed snapshot.
pub fn verify_period_with_context<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    period_code: &str,
) -> Result<Verification, RegisterError> {
    verify_period_with_context_in(&mut Reads::new(db, book, &[period_code]), cx, period_code)
}

/// [`verify_period_with_context`] for each of `periods`, in order, from one
/// shared read of the book ([`Reads`], fa-rbs3): each result is the one
/// verifying that period alone returns, and the results stop after the
/// first error, as a loop over the periods stops.
pub fn verify_periods_with_context<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    periods: &[&str],
) -> Vec<Result<Verification, RegisterError>> {
    let mut reads = Reads::new(db, book, periods);
    let mut results = Vec::with_capacity(periods.len());
    for period in periods {
        let result = verify_period_with_context_in(&mut reads, cx, period);
        let failed = result.is_err();
        results.push(result);
        if failed {
            break;
        }
    }
    results
}

fn verify_period_with_context_in<V: asupersync::fs::Vfs + Clone>(
    reads: &mut Reads<'_, V>,
    cx: &QueryCx,
    period_code: &str,
) -> Result<Verification, RegisterError> {
    let (db, book) = (reads.db, reads.book);
    let mut result = verify_period_in(reads, period_code)?;
    let at = db.frontier()?;
    let mut next = match checkpoint::load_latest(db, cx, book, period_code, at) {
        Ok(value) => value,
        Err(RegisterError::ProjectionDrift(message))
        | Err(RegisterError::Kernel(KernelError::Corrupt(message))) => {
            result
                .projection_errors
                .push(format!("register checkpoint chain: {message}"));
            None
        }
        Err(error) => return Err(error),
    };
    let mut visited = BTreeSet::new();
    while let Some(snapshot) = next {
        if !visited.insert(snapshot.body_digest) {
            result
                .projection_errors
                .push("register checkpoint chain repeats a snapshot".into());
            break;
        }
        let truth = reads.fold_at(period_code, snapshot.through)?;
        if snapshot.fold != truth {
            result.projection_errors.push(format!(
                "register checkpoint at {} disagrees with its independently refolded journal prefix",
                snapshot.through.0,
            ));
        }
        next = match snapshot.previous {
            None => None,
            Some(previous) if previous.through >= snapshot.through => {
                result
                    .projection_errors
                    .push("register checkpoint predecessors are not strictly earlier".into());
                break;
            }
            Some(previous) => match checkpoint::load(db, cx, book, period_code, previous, at) {
                Ok(value) => Some(value),
                Err(RegisterError::ProjectionDrift(message))
                | Err(RegisterError::Kernel(KernelError::Corrupt(message))) => {
                    result
                        .projection_errors
                        .push(format!("register checkpoint chain: {message}"));
                    break;
                }
                Err(error) => return Err(error),
            },
        };
    }
    if !result.is_green() {
        result.cache_status = CacheStatus::Corrupt;
        result.verified_through = None;
    }
    Ok(result)
}

fn verify_projection<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    fold: &Fold,
) -> Result<Verification, RegisterError> {
    let rows = db.vertices()?;
    verify_projection_in(db, book, fold, &rows, &period_memberships(&db.edges()?))
}

/// [`verify_projection`] against `rows`, the book's current vertices, and
/// `memberships`, its period memberships ([`period_memberships`]).
fn verify_projection_in<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    fold: &Fold,
    rows: &[VertexRow],
    memberships: &Memberships,
) -> Result<Verification, RegisterError> {
    let period_code = &fold.period;
    let mut drift = Vec::new();
    let mut pending_drift = Vec::new();
    let mut projection_errors = Vec::new();
    let mut candidates = stored_registers_in(db, book, fold, rows)?;
    let pvid = period_vid(&book.calendar.id, period_code);
    let linked: BTreeSet<_> = db
        .in_neighbours(pvid, relation::IN_PERIOD)?
        .into_iter()
        .collect();
    let mut stored_digest: Option<Option<[u8; 32]>> = None;
    let columns = fold_columns(fold);
    for (key, (posted, pending)) in &columns {
        let rvid = register_vid(book.book_id, key);
        let (stored, stored_pending) = match candidates.remove(&rvid) {
            None => (None, None),
            Some(row) => {
                let metadata_ok = row.labels == vec![label::REGISTER]
                    && bytes(&row, property::BOOK_ID, "register.book_id")? == book.book_id.0
                    && bytes(&row, property::ACCOUNT_REF, "register.account_ref")?
                        == key.account.0.to_le_bytes()
                    && int(&row, property::UNIT_ID, "register.unit_id")? == i64::from(key.unit_id)
                    && text(&row, property::EFFECTIVE_PERIOD, "register.period")? == fold.period
                    && u64::try_from(int(&row, property::WATERMARK, "register.watermark")?).ok()
                        == Some(fold.watermark.map_or(0, |s| s.0))
                    && linked.contains(&rvid)
                    && !memberships
                        .get(&rvid)
                        .is_some_and(|m| m.iter().any(|(_, dst)| *dst != pvid));
                if !metadata_ok {
                    projection_errors.push(format!("register {:032x}: identity, metadata, watermark or period membership disagrees", rvid.0));
                }
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
                (stored_values(&row, false)?, stored_values(&row, true)?)
            }
        };
        if stored != Some(*posted) {
            drift.push(Drift {
                key: (*key).clone(),
                stored,
                refolded: *posted,
            });
        }
        if stored_pending != Some(*pending) {
            pending_drift.push(Drift {
                key: (*key).clone(),
                stored: stored_pending,
                refolded: *pending,
            });
        }
    }
    let cells_checked = columns.len() + candidates.len();
    for row in candidates.values() {
        let account: [u8; 16] = bytes(row, property::ACCOUNT_REF, "register.account_ref")?
            .try_into()
            .map_err(|_| KernelError::Corrupt("register.account_ref".into()))?;
        let unit_id = u32::try_from(int(row, property::UNIT_ID, "register.unit_id")?)
            .map_err(|_| KernelError::Corrupt("register.unit_id".into()))?;
        let key = CellKey {
            account: VId(u128::from_le_bytes(account)),
            unit_id,
            period: fold.period.clone(),
        };
        drift.push(Drift {
            key: key.clone(),
            stored: stored_values(row, false)?,
            refolded: (0, 0, 0),
        });
        pending_drift.push(Drift {
            key,
            stored: stored_values(row, true)?,
            refolded: (0, 0, 0),
        });
        projection_errors.push(format!("unexpected register {:032x}", row.vid.0));
    }
    Ok(Verification {
        period: period_code.to_string(),
        cache_status: CacheStatus::Uninitialized,
        verified_through: None,
        stale: false,
        lag_entries: 0,
        cells_checked,
        drift,
        pending_drift,
        projection_errors,
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
    pub debits_pending: i128,
    pub credits_pending: i128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialBalance {
    pub periods: Vec<String>,
    /// The actual fixed snapshot used, including when the caller requested HEAD.
    pub known_at: CommitSeq,
    /// Inclusive stock cutoff; absent for an explicit period-activity report.
    pub effective_through: Option<DateDay>,
    pub activity: bool,
    pub rows: Vec<TbRow>,
    /// Per unit: (debits, credits).
    pub unit_totals: BTreeMap<u32, (i128, i128)>,
    pub pending_unit_totals: BTreeMap<u32, (i128, i128)>,
}

impl TrialBalance {
    /// The versioned, exact report output bound by replay certificates. Amounts
    /// remain integer mantissas and unit IDs; presentation is not an input to
    /// the fold. The certificate separately binds the unit and symbol registries.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(b"fa:trial-balance:v1")
            .list(&self.periods, |w, p| {
                w.str(p);
            })
            .u64(self.known_at.0)
            .opt(self.effective_through.as_ref(), |w, d| {
                w.i32(d.0);
            })
            .bool(self.activity)
            .list(&self.rows, |w, r| {
                w.u128(r.account.0)
                    .str(&r.code)
                    .str(&r.name)
                    .u8(r.account_type.0)
                    .u32(r.unit_id)
                    .i128(r.debits)
                    .i128(r.credits)
                    .i128(r.debits_pending)
                    .i128(r.credits_pending);
            });
        for totals in [&self.unit_totals, &self.pending_unit_totals] {
            let ordered: Vec<_> = totals.iter().collect();
            w.list(&ordered, |w, (unit, (debits, credits))| {
                w.u32(**unit).i128(*debits).i128(*credits);
            });
        }
        w.finish()
    }

    /// FA-INV-01 at the register level: every monetary unit's debits equal its
    /// credits (`Memo` and `Statistical` accounts sit outside monetary footing).
    #[must_use]
    pub fn is_balanced(&self) -> bool {
        self.unit_totals
            .values()
            .chain(self.pending_unit_totals.values())
            .all(|(d, c)| d == c)
    }
}

/// Balances from inception through the latest selected period's inclusive end
/// (`fa-a57x`: stock and flow accounts fold inception-to-date so unclosed
/// prior-year nominal balances preserve `debits == credits` until `YearEndClose`
/// moves them to equity; `Memo` and `Statistical` accounts appear in `rows` and
/// are excluded from monetary `unit_totals` / `pending_unit_totals`).
/// Period activity is available explicitly through [`period_activity`].
pub fn trial_balance<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
) -> Result<TrialBalance, RegisterError> {
    trial_balance_at(db, book, periods, None)
}

pub fn trial_balance_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
) -> Result<TrialBalance, RegisterError> {
    trial_balance_filtered(db, book, periods, known_at, None)
}

fn trial_balance_filtered<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
    filter: Option<&DimensionFilter>,
) -> Result<TrialBalance, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let selected = select_periods(db, book, periods, seq)?;
    let mut through = None;
    for p in &selected {
        let end = period_at(db, book, p, seq)?
            .end
            .0
            .checked_sub(1)
            .ok_or_else(|| KernelError::Corrupt("period end underflow".into()))?;
        through = Some(through.map_or(DateDay(end), |d: DateDay| d.max(DateDay(end))));
    }
    report_at(db, book, selected, seq, through, &[], filter)
}

/// How a trial balance at its selected snapshot was served (plan §17: a balance
/// read states whether maintained cells answered it and how long its tail
/// was).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Served {
    /// Every contributing period from its maintained cells at its cursor,
    /// plus the exact tail after it: `(period, served_at, tail_entries)`.
    Maintained(Vec<(String, CommitSeq, usize)>),
    /// The literal journal fold, and why maintained cells could not answer.
    Literal(String),
}

impl Served {
    /// Entry payloads decoded for the tails; `None` for a literal fold.
    #[must_use]
    pub fn tail_length(&self) -> Option<usize> {
        match self {
            Self::Maintained(periods) => Some(periods.iter().map(|(_, _, tail)| tail).sum()),
            Self::Literal(_) => None,
        }
    }
}

/// [`trial_balance`] at the frontier, answered from maintained registers
/// when every period ending on or before the selection's last day can be
/// served exactly (plan §5.3, fa-715), and from the literal fold otherwise.
/// Both yield the same report; [`Served`] says which ran. The maintained
/// path reads the chart, each contributing period's cells and the tail
/// after its cursor, not the journal's history.
pub fn trial_balance_served<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
) -> Result<(TrialBalance, Served), RegisterError> {
    trial_balance_served_at(db, book, periods, None)
}

/// A trial balance at `known_at`, using that snapshot's retained register
/// state and exact tail when available. Metadata, cached cells and journal
/// contributions all use the same coordinate. This is a retained-snapshot
/// optimization, not a claim that certified RegisterCheckpoints exist.
pub fn trial_balance_served_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
) -> Result<(TrialBalance, Served), RegisterError> {
    trial_balance_served_at_inner(db, None, book, periods, known_at)
}

/// A trial balance at one recorded prefix, using durable register checkpoints
/// and their exact tails when available. Loading checkpoint objects uses the
/// caller's query context. A missing or damaged cache falls back to the same
/// authoritative journal fold as [`trial_balance_served_at`].
pub fn trial_balance_served_at_with_context<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
) -> Result<(TrialBalance, Served), RegisterError> {
    trial_balance_served_at_inner(db, Some(cx), book, periods, known_at)
}

fn trial_balance_served_at_inner<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: Option<&QueryCx>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
) -> Result<(TrialBalance, Served), RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let selected = select_periods(db, book, periods, seq)?;
    let mut through = None;
    for p in &selected {
        let end = period_at(db, book, p, seq)?
            .end
            .0
            .checked_sub(1)
            .ok_or_else(|| KernelError::Corrupt("period end underflow".into()))?;
        through = Some(through.map_or(DateDay(end), |d: DateDay| d.max(DateDay(end))));
    }
    let maintained = match through {
        Some(day) => maintained_sums(db, cx, book, day, seq)?,
        None => Err("no period was selected".to_string()),
    };
    match maintained {
        Ok((sums, served)) => Ok((
            trial_balance_from_sums(db, sums, selected, seq, through)?,
            Served::Maintained(served),
        )),
        Err(reason) => Ok((
            report_at(db, book, selected, seq, through, &[], None)?,
            Served::Literal(reason),
        )),
    }
}

/// Per-(account, unit) column sums: `[debits, credits, debits_pending,
/// credits_pending]`.
type ColumnSums = BTreeMap<(VId, u32), [i128; 4]>;

/// `(period, served_at, tail_entries)` of each period maintained cells answered.
type ServedPeriods = Vec<(String, CommitSeq, usize)>;

/// The trial balance's column sums through `day` from maintained cells, or
/// why they cannot answer exactly: a period straddles `day` (the literal
/// fold selects by date inside it), or a period with postings has no
/// servable cells.
fn maintained_sums<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: Option<&QueryCx>,
    book: &BookContext,
    day: DateDay,
    seq: CommitSeq,
) -> Result<Result<(ColumnSums, ServedPeriods), String>, RegisterError> {
    let (accounts, periods) = report_metadata_at(db, seq)?;
    let mut sums = ColumnSums::new();
    let mut served = Vec::new();
    for period in periods {
        let last = DateDay(
            period
                .end
                .0
                .checked_sub(1)
                .ok_or_else(|| KernelError::Corrupt("period end underflow".into()))?,
        );
        if period.start > day {
            continue;
        }
        if last > day {
            return Ok(Err(format!(
                "period `{}` straddles {}",
                period.code,
                day.render()
            )));
        }
        let Some(head) = maintained_fold_at(db, cx, book, &period.code, &accounts, seq)? else {
            if period_has_postings_at(db, period.vid, seq)? {
                return Ok(Err(unservable(&period.code)));
            }
            continue;
        };
        add_cells(&mut sums, &head.fold)?;
        served.push((period.code, head.served_at, head.tail_entries));
    }
    Ok(Ok((sums, served)))
}

fn maintained_fold_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: Option<&QueryCx>,
    book: &BookContext,
    period: &str,
    accounts: &[AccountRow],
    known_at: CommitSeq,
) -> Result<Option<HeadFold>, RegisterError> {
    match cx {
        Some(cx) => maintainer::fold_at_with_context(db, cx, book, period, accounts, known_at),
        None => maintainer::fold_at(db, book, period, accounts, known_at),
    }
}

/// Why maintained cells could not answer for a period with postings, and
/// how to make them answer.
fn unservable(period: &str) -> String {
    format!(
        "period `{period}` has postings but its maintained cells cannot answer at the selected snapshot (no or damaged state, drifted cells, or a tail outside this process's delta window); the journal is folded literally; `fa registers advance --period {period}` or a daemon's register cycle maintains future read snapshots"
    )
}

/// Add a fold's posted and pending cells into trial-balance column sums.
fn add_cells(sums: &mut ColumnSums, fold: &Fold) -> Result<(), RegisterError> {
    for (cells, column) in [(&fold.cells, 0), (&fold.pending, 2)] {
        for cell in cells {
            let sum = sums
                .entry((cell.key.account, cell.key.unit_id))
                .or_insert([0; 4]);
            sum[column] = sum[column]
                .checked_add(cell.debits)
                .ok_or(RegisterError::Overflow)?;
            sum[column + 1] = sum[column + 1]
                .checked_add(cell.credits)
                .ok_or(RegisterError::Overflow)?;
        }
    }
    Ok(())
}

/// [`period_activity`] at the frontier: the selected periods' maintained
/// cells plus their exact tails when every selected period with postings
/// can be served that way, and the literal fold otherwise (fa-715). Both
/// yield the same report; [`Served`] says which ran.
pub fn period_activity_served<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
) -> Result<(TrialBalance, Served), RegisterError> {
    period_activity_served_at(db, book, periods, None)
}

/// Period activity at a fixed known-at snapshot, served from retained
/// maintained cells plus an exact bounded tail, or from the literal fold.
pub fn period_activity_served_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
) -> Result<(TrialBalance, Served), RegisterError> {
    period_activity_served_at_inner(db, None, book, periods, known_at)
}

/// Period activity at one recorded prefix, using durable register checkpoints
/// and exact tails through the caller's query context. Unavailable derived
/// state never changes the report: the authoritative literal fold is the
/// fallback, with the serving choice returned separately.
pub fn period_activity_served_at_with_context<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
) -> Result<(TrialBalance, Served), RegisterError> {
    period_activity_served_at_inner(db, Some(cx), book, periods, known_at)
}

fn period_activity_served_at_inner<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    cx: Option<&QueryCx>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
) -> Result<(TrialBalance, Served), RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let selected = select_periods(db, book, periods, seq)?;
    let (accounts, _) = report_metadata_at(db, seq)?;
    let mut sums = ColumnSums::new();
    let mut served = Vec::new();
    for code in &selected {
        match maintained_fold_at(db, cx, book, code, &accounts, seq)? {
            Some(head) => {
                add_cells(&mut sums, &head.fold)?;
                served.push((code.clone(), head.served_at, head.tail_entries));
            }
            None if period_has_postings_at(db, period_at(db, book, code, seq)?.vid, seq)? => {
                let reason = unservable(code);
                return Ok((
                    report_at(db, book, selected.clone(), seq, None, &[], None)?,
                    Served::Literal(reason),
                ));
            }
            None => {}
        }
    }
    Ok((
        trial_balance_from_sums(db, sums, selected, seq, None)?,
        Served::Maintained(served),
    ))
}

/// Read only the selected snapshot's book membership and metadata. Loading
/// the current chart or periods here would let later schema changes alter a
/// historical report, even when all monetary contributions were pinned.
fn report_metadata_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    seq: CommitSeq,
) -> Result<(Vec<AccountRow>, Vec<PeriodRow>), RegisterError> {
    let mut accounts = Vec::new();
    let mut periods = Vec::new();
    for vid in db.in_neighbours_at(fa_journal::rows::book_root(), relation::IN_BOOK, seq)? {
        let Some(row) = db.vertex_at(vid, seq)? else {
            continue;
        };
        if row.labels.contains(&label::ACCOUNT) {
            accounts.push(AccountRow::decode(&row)?);
        }
        if row.labels.contains(&label::PERIOD) {
            periods.push(PeriodRow::decode(&row)?);
        }
    }
    accounts.sort_by(|a, b| a.code.cmp(&b.code));
    periods.sort_by(|a, b| {
        (a.fiscal_year, a.ordinal, &a.code).cmp(&(b.fiscal_year, b.ordinal, &b.code))
    });
    Ok((accounts, periods))
}

/// Whether anything that can carry a leg reaches `period`: an Entry with
/// legs, or a register cell (a stale cell without its state is not
/// trusted to be empty).
fn period_has_postings_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    period: VId,
    seq: CommitSeq,
) -> Result<bool, RegisterError> {
    for vid in db.in_neighbours_at(period, relation::IN_PERIOD, seq)? {
        let Some(row) = db.vertex_at(vid, seq)? else {
            continue;
        };
        if row.labels.contains(&label::REGISTER) {
            return Ok(true);
        }
        if row.labels.contains(&label::ENTRY) {
            let entry = Entry::decode(&bytes(&row, property::FA_PAYLOAD, "entry.payload")?)
                .map_err(KernelError::from)?;
            if !entry.proposal.legs.is_empty() {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// A stock position on a civil day, independent of when postings were recorded
/// (`fa-a57x`, plan §7.5, §12.1). Includes adjustment/closing periods and every
/// account type (`stock`, `flow`, `memo`) folded inception-to-date (`EFFECTIVE <= day`);
/// `Memo` and `Statistical` accounts (`AccountType::is_memo()`) are excluded from
/// monetary `unit_totals` and `pending_unit_totals`. Stock versus flow is a
/// report/statement selector choice, not an implicit branch on an account's type.
pub fn balance_as_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    day: DateDay,
    known_at: Option<CommitSeq>,
) -> Result<TrialBalance, RegisterError> {
    balance_as_of_filtered(db, book, day, known_at, None)
}

fn balance_as_of_filtered<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    day: DateDay,
    known_at: Option<CommitSeq>,
    filter: Option<&DimensionFilter>,
) -> Result<TrialBalance, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    let mut periods = BTreeSet::new();
    for row in db.vertices_at(seq)? {
        if row.labels.contains(&label::PERIOD) {
            let p = PeriodRow::decode(&row)?;
            if p.calendar_id == book.calendar.id && p.start <= day {
                periods.insert(p.code);
            }
        }
    }
    report_at(
        db,
        book,
        periods.into_iter().collect(),
        seq,
        Some(day),
        &[],
        filter,
    )
}

/// Movement within the explicitly selected periods. Overlapping civil dates
/// remain distinct by period identity, and repeated codes contribute only once.
pub fn period_activity<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
) -> Result<TrialBalance, RegisterError> {
    period_activity_excluding_classes(db, book, periods, known_at, &[])
}

/// Movement within the selected periods, excluding the named accounting
/// classes and exact reversals of those classes. This is the same authoritative
/// payload fold as [`period_activity`]; retained register cells never contribute.
/// In particular, income statements exclude Closing transfers without excluding
/// operating adjustments merely because they share a Closing-kind period.
///
/// Reversal lineage is checked against the retained target digest and followed
/// to its original class, including a reversal of a reversal. If Closing is
/// excluded, a Migration whose original entry lies in a Closing-kind period is
/// refused: its current payload does not retain the source's accounting class,
/// so treating it as either ordinary income or a closing transfer would guess.
pub fn period_activity_excluding_classes<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
    excluded_classes: &[EntryClass],
) -> Result<TrialBalance, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    report_at(
        db,
        book,
        select_periods(db, book, periods, seq)?,
        seq,
        None,
        excluded_classes,
        None,
    )
}

/// The legs a dimension-filtered report folds (plan §4.1, bead fa-ficc):
/// those tagging `dimension` with one of `values`, typically a value and
/// its descendants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DimensionFilter {
    pub dimension: u32,
    pub values: BTreeSet<VId>,
}

impl DimensionFilter {
    fn admits(&self, leg: &fa_model::LegPayload) -> bool {
        leg.dimension_set
            .iter()
            .any(|(dimension, value)| *dimension == self.dimension && self.values.contains(value))
    }
}

/// [`trial_balance_at`] over only the legs `filter` admits. Always the
/// literal journal fold: maintained cells carry no dimension. The other legs
/// of a tagged entry are left out, so the report need not balance.
pub fn trial_balance_tagged<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
    filter: &DimensionFilter,
) -> Result<TrialBalance, RegisterError> {
    trial_balance_filtered(db, book, periods, known_at, Some(filter))
}

/// [`period_activity`] over only the legs `filter` admits.
pub fn period_activity_tagged<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
    filter: &DimensionFilter,
) -> Result<TrialBalance, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    report_at(
        db,
        book,
        select_periods(db, book, periods, seq)?,
        seq,
        None,
        &[],
        Some(filter),
    )
}

/// [`balance_as_of`] over only the legs `filter` admits.
pub fn balance_as_of_tagged<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    day: DateDay,
    known_at: Option<CommitSeq>,
    filter: &DimensionFilter,
) -> Result<TrialBalance, RegisterError> {
    balance_as_of_filtered(db, book, day, known_at, Some(filter))
}

pub(crate) fn select_periods<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    seq: CommitSeq,
) -> Result<Vec<String>, RegisterError> {
    if periods.is_empty() {
        return Err(RegisterError::InvalidSelection(
            "select at least one period or an as-of date".into(),
        ));
    }
    let unique: BTreeSet<_> = periods.iter().cloned().collect();
    for code in &unique {
        period_at(db, book, code, seq)?;
    }
    Ok(unique.into_iter().collect())
}

#[allow(clippy::too_many_arguments)]
fn report_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: Vec<String>,
    seq: CommitSeq,
    through: Option<DateDay>,
    excluded_classes: &[EntryClass],
    filter: Option<&DimensionFilter>,
) -> Result<TrialBalance, RegisterError> {
    let mut sums: BTreeMap<(VId, u32), [i128; 4]> = BTreeMap::new();
    let entries = entries_at(db, book, seq)?;
    let resolved = resolutions(&entries)?;
    let by_id: BTreeMap<_, _> = if excluded_classes.is_empty() {
        BTreeMap::new()
    } else {
        entries
            .iter()
            .map(|(vid, entry, at)| (*vid, (entry, *at)))
            .collect()
    };
    for (vid, entry, _) in &entries {
        if entry.proposal.legs.is_empty() {
            continue;
        }
        let pending = entry.proposal.class == EntryClass::PENDING;
        // Releases are evaluated at the known-at frontier. They release the
        // original period, irrespective of their own posting effective date.
        if pending && resolved.contains_key(vid) {
            continue;
        }
        let selected = match through {
            Some(day) => entry.proposal.effective_date <= day,
            None => periods.binary_search(&entry_period(book, entry)?).is_ok(),
        };
        if !selected {
            continue;
        }
        if !accounting_class_included(db, book, seq, (*vid, entry), &by_id, excluded_classes)? {
            continue;
        }
        for leg in &entry.proposal.legs {
            if filter.is_some_and(|filter| !filter.admits(leg)) {
                continue;
            }
            let e = sums
                .entry((leg.account_ref, leg.amount.unit.0))
                .or_insert([0; 4]);
            let column = match (pending, leg.side) {
                (false, Side::Debit) => 0,
                (false, Side::Credit) => 1,
                (true, Side::Debit) => 2,
                (true, Side::Credit) => 3,
            };
            let amount = &mut e[column];
            *amount = amount
                .checked_add(leg.amount.mantissa)
                .ok_or(RegisterError::Overflow)?;
        }
    }
    trial_balance_from_sums(db, sums, periods, seq, through)
}

/// A trial balance over per-(account, unit) column sums `[debits, credits,
/// debits_pending, credits_pending]` known at `seq`. The literal fold and
/// the maintained read share it, so both reports follow one law.
fn trial_balance_from_sums<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    sums: ColumnSums,
    periods: Vec<String>,
    seq: CommitSeq,
    through: Option<DateDay>,
) -> Result<TrialBalance, RegisterError> {
    let mut rows = Vec::with_capacity(sums.len());
    let mut unit_totals: BTreeMap<u32, (i128, i128)> = BTreeMap::new();
    let mut pending_unit_totals: BTreeMap<u32, (i128, i128)> = BTreeMap::new();
    for ((account, unit_id), [debits, credits, debits_pending, credits_pending]) in sums {
        let row = db.vertex_at(account, seq)?.ok_or_else(|| {
            KernelError::Corrupt(format!("missing account {account:?} at sequence {}", seq.0))
        })?;
        let a = AccountRow::decode(&row)?;
        let (code, name, account_type) = (a.code, a.name, AccountType(a.account_type));
        if !account_type.is_memo() {
            let t = unit_totals.entry(unit_id).or_insert((0, 0));
            t.0 = t.0.checked_add(debits).ok_or(RegisterError::Overflow)?;
            t.1 = t.1.checked_add(credits).ok_or(RegisterError::Overflow)?;
            let p = pending_unit_totals.entry(unit_id).or_insert((0, 0));
            p.0 =
                p.0.checked_add(debits_pending)
                    .ok_or(RegisterError::Overflow)?;
            p.1 =
                p.1.checked_add(credits_pending)
                    .ok_or(RegisterError::Overflow)?;
        }
        rows.push(TbRow {
            account,
            code,
            name,
            account_type,
            unit_id,
            debits,
            credits,
            debits_pending,
            credits_pending,
        });
    }
    rows.sort_by(|a, b| a.code.cmp(&b.code).then(a.unit_id.cmp(&b.unit_id)));
    Ok(TrialBalance {
        periods,
        known_at: seq,
        effective_through: through,
        activity: through.is_none(),
        rows,
        unit_totals,
        pending_unit_totals,
    })
}

/// Native and functional activity apply the same accounting-class policy.
/// In particular, a Closing period can also contain operating adjustments;
/// only the retained entry class and its verified reversal lineage decide.
pub(crate) fn accounting_class_included<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
    source: (VId, &Entry),
    entries: &BTreeMap<VId, (&Entry, CommitSeq)>,
    excluded_classes: &[EntryClass],
) -> Result<bool, RegisterError> {
    if excluded_classes.is_empty() {
        return Ok(true);
    }
    let (vid, entry) = source;
    let (original_vid, original) = accounting_origin(vid, entry, entries)?;
    if excluded_classes.contains(&entry.proposal.class)
        || excluded_classes.contains(&original.proposal.class)
    {
        return Ok(false);
    }
    if excluded_classes.contains(&EntryClass::CLOSING)
        && original.proposal.class == EntryClass::MIGRATION
    {
        let code = entry_period(book, original)?;
        if period_at(db, book, &code, at)?.kind == PeriodKind::Closing {
            return Err(RegisterError::InvalidSelection(format!(
                "cannot classify migration entry {:032x} in Closing period `{code}` for activity excluding Closing: its original accounting class is not retained",
                original_vid.0
            )));
        }
    }
    Ok(true)
}

/// Exact reversals carry the economic class of the original entry for a
/// class-filtered report. The lookup is over one already-admitted journal
/// prefix, so lineage cannot consult a later head or a mutable projection.
fn accounting_origin<'a>(
    vid: VId,
    entry: &'a Entry,
    entries: &BTreeMap<VId, (&'a Entry, CommitSeq)>,
) -> Result<(VId, &'a Entry), RegisterError> {
    let mut current_vid = vid;
    let mut current = entry;
    let mut visited = BTreeSet::new();
    while current.proposal.class == EntryClass::REVERSAL {
        if !visited.insert(current_vid) {
            return Err(KernelError::Corrupt(format!(
                "reversal lineage of {:032x} cycles at {:032x}",
                vid.0, current_vid.0
            ))
            .into());
        }
        let target = match current.proposal.supersession.as_slice() {
            [supersession] if supersession.kind == fa_model::SupersessionKind::Reverses => {
                supersession.target
            }
            _ => {
                return Err(KernelError::Corrupt(format!(
                    "reversal entry {:032x} does not name exactly one Reverses target",
                    current_vid.0
                ))
                .into());
            }
        };
        let Some((original, original_at)) = entries.get(&target.vid) else {
            return Err(KernelError::Corrupt(format!(
                "reversal entry {:032x} names target {:032x} absent from its visible journal prefix",
                current_vid.0, target.vid.0
            )).into());
        };
        let current_at = entries
            .get(&current_vid)
            .map(|(_, at)| *at)
            .ok_or_else(|| KernelError::Corrupt("reversal absent from its journal index".into()))?;
        if original.entry_digest != target.entry_digest || *original_at > current_at {
            return Err(KernelError::Corrupt(format!(
                "reversal entry {:032x} has a mismatched or later target {:032x}",
                current_vid.0, target.vid.0
            ))
            .into());
        }
        current_vid = target.vid;
        current = original;
    }
    Ok((current_vid, current))
}

/// Candidate periods for a stock position. The actual fold must additionally
/// test each posting's effective date against `day`; period selection alone
/// cannot implement an intra-period cutoff. Special periods contribute too.
#[must_use]
pub fn periods_for_balance(
    day: fa_time::DateDay,
    all_periods: &[fa_time::PeriodDef],
) -> Vec<String> {
    all_periods
        .iter()
        .filter(|p| p.start <= day)
        .map(|p| p.code.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_time::{DateDay, PeriodDef, PeriodKind};

    #[test]
    fn cell_net_is_exact_at_the_i128_boundaries_and_none_on_overflow() {
        let cell = |debits, credits| Cell {
            key: CellKey {
                account: VId(1),
                unit_id: 1,
                period: "P".into(),
            },
            debits,
            credits,
            entry_count: 0,
        };
        for (debits, credits, expected) in [
            (0, 0, 0),
            (i128::MAX, 0, i128::MAX),
            (0, i128::MAX, -i128::MAX),
            (i128::MAX, i128::MAX, 0),
            (i128::MAX, i128::MAX - 1, 1),
            (i128::MAX - 1, i128::MAX, -1),
            (i128::MIN, 0, i128::MIN),
            (-1, i128::MAX, i128::MIN),
        ] {
            let value = cell(debits, credits);
            let original = value.clone();
            assert_eq!(value.net(), Some(expected));
            assert_eq!(value, original);
        }
        // These malformed public cells cannot come from a valid fold.
        // Their subtraction must still fail consistently in every profile.
        for (debits, credits) in [(i128::MAX, -1), (i128::MIN, 1), (0, i128::MIN)] {
            let value = cell(debits, credits);
            let original = value.clone();
            assert_eq!(value.net(), None);
            assert_eq!(value, original);
        }
    }

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
    fn stock_candidates_include_prior_years_and_special_periods() {
        let mut periods = vec![
            period("FY2025-P12", 2025, 100, 131),
            period("FY2026-P01", 2026, 131, 162),
            period("FY2026-P02", 2026, 162, 190),
            period("FY2026-P03", 2026, 190, 221),
        ];
        let mut adjustment = period("FY2025-ADJ", 2025, 130, 131);
        adjustment.kind = PeriodKind::Adjustment;
        periods.push(adjustment);
        let day = DateDay(170);
        assert_eq!(
            periods_for_balance(day, &periods),
            vec!["FY2025-P12", "FY2026-P01", "FY2026-P02", "FY2025-ADJ"]
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
            debits: 150,
            credits: 150,
            entry_count: 2,
        }];
        let mut b = a.clone();
        b[0].debits = 151;
        let holds = BTreeMap::new();
        // History 1: 100 at seq 5, then 50 at seq 7.
        let h1 = fold_leg_contribution(
            fold_leg_contribution(
                [0u8; 32],
                (CommitSeq(5), VId(10), 0),
                VId(1),
                1,
                Side::Debit,
                100,
            ),
            (CommitSeq(7), VId(11), 0),
            VId(1),
            1,
            Side::Debit,
            50,
        );
        // History 2: 50 at seq 5, then 100 at seq 7 (equal cell sum = 150, same watermark = 7).
        let h2 = fold_leg_contribution(
            fold_leg_contribution(
                [0u8; 32],
                (CommitSeq(5), VId(10), 0),
                VId(1),
                1,
                Side::Debit,
                50,
            ),
            (CommitSeq(7), VId(11), 0),
            VId(1),
            1,
            Side::Debit,
            100,
        );
        // History 3: different ordinal order within an entry.
        let h3 = fold_leg_contribution(
            fold_leg_contribution(
                [0u8; 32],
                (CommitSeq(5), VId(10), 1),
                VId(1),
                1,
                Side::Debit,
                100,
            ),
            (CommitSeq(7), VId(11), 0),
            VId(1),
            1,
            Side::Debit,
            50,
        );
        assert_ne!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(
            digest_of("P", &a, &[], Some(CommitSeq(7)), h1, &holds).unwrap(),
            digest_of("P", &a, &[], Some(CommitSeq(7)), h1, &holds).unwrap()
        );
        assert_ne!(
            digest_of("P", &a, &[], Some(CommitSeq(7)), h1, &holds).unwrap(),
            digest_of("P", &a, &[], Some(CommitSeq(7)), h2, &holds).unwrap(),
            "two histories with equal cell sums and identical watermark must have distinct fold digests"
        );
        assert_ne!(
            digest_of("P", &a, &[], Some(CommitSeq(7)), h1, &holds).unwrap(),
            digest_of("P", &a, &[], Some(CommitSeq(7)), h3, &holds).unwrap(),
            "leg ordinal within an entry is bound by fold_digest"
        );
        assert_ne!(
            digest_of("P", &a, &[], Some(CommitSeq(7)), h1, &holds).unwrap(),
            digest_of("P", &b, &[], Some(CommitSeq(7)), h1, &holds).unwrap()
        );
        assert_ne!(
            digest_of("P", &a, &[], Some(CommitSeq(7)), h1, &holds).unwrap(),
            digest_of("P", &a, &[], Some(CommitSeq(8)), h1, &holds).unwrap()
        );
        assert_ne!(
            register_vid(Id128([1; 16]), &key),
            register_vid(Id128([2; 16]), &key)
        );
    }

    #[test]
    fn cell_net_uses_checked_subtraction_and_detects_overflow() {
        let key = CellKey {
            account: VId(1),
            unit_id: 1,
            period: "P".into(),
        };
        let normal = Cell {
            key: key.clone(),
            debits: 250,
            credits: 100,
            entry_count: 2,
        };
        assert_eq!(normal.net(), Some(150));

        let credit_heavy = Cell {
            key: key.clone(),
            debits: 100,
            credits: 250,
            entry_count: 2,
        };
        assert_eq!(credit_heavy.net(), Some(-150));

        let overflow = Cell {
            key,
            debits: i128::MAX,
            credits: -1,
            entry_count: 2,
        };
        assert_eq!(overflow.net(), None);
    }
}
