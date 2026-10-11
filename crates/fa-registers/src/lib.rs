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

pub mod availability;
pub mod entity;
pub mod explain;
pub mod maintainer;
pub mod open_items;

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

use fa_journal::KernelError;
use fa_journal::genesis::BookContext;
use fa_journal::rows::{AccountRow, PeriodRow, bytes, int, prop, scalar_bytes, scalar_text, text};
use fa_model::symbols::{label, property, relation};
use fa_model::{AccountType, Entry, EntryClass, Id128, Writer, period_vid};
use fa_money::Side;
use fa_time::DateDay;
use fgdb::{Database, VertexRow, WriteBatch};
use fgdb_crypto::Hasher;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

pub use availability::{
    AccountAvailability, AvailabilityDrift, AvailabilityVerification, verify_availability,
};
pub use entity::{
    EntityCell, EntityCellKey, EntityFold, EntityVerification, RegisterEquals,
    check_register_equals, fold_period_by_entity, register_equals, verify_entities,
};
pub use explain::{BalanceExplanation, explain_balance};
pub use maintainer::{
    Advance, PreparedAdvance, advance, prepare_advance, publish_advance, rebuild,
};
pub use open_items::{
    Application, AppliedDrift, OpenItem, OpenItemVerification, open_items, verify_open_items,
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
    /// Outstanding reservations, keyed on the original Pending's period.
    pub pending: Vec<Cell>,
    /// The highest contributing commit, including cross-period releases.
    pub watermark: Option<CommitSeq>,
    /// Posting entries contributing to `cells` (excludes reservations/releases).
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

fn digest_of(
    cells: &[Cell],
    pending: &[Cell],
    watermark: Option<CommitSeq>,
) -> Result<[u8; 32], RegisterError> {
    let mut w = Writer::new();
    w.opt(watermark.as_ref(), |w, s| {
        w.u64(s.0);
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

pub(crate) fn resolve_known_at<V: asupersync::fs::Vfs + Clone>(
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
pub(crate) fn entries_at<V: asupersync::fs::Vfs + Clone>(
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
    Ok(entries)
}

pub(crate) fn entry_period(book: &BookContext, entry: &Entry) -> Result<String, RegisterError> {
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

/// Resolve holds using authoritative payloads at the same known-at frontier.
/// A missing or duplicated target is corruption, not an absent reservation.
pub(crate) fn resolutions(
    entries: &[(VId, Entry, CommitSeq)],
) -> Result<BTreeMap<VId, CommitSeq>, RegisterError> {
    let by_id: BTreeMap<_, _> = entries.iter().map(|(id, e, seq)| (*id, (e, seq))).collect();
    let mut resolved = BTreeMap::new();
    for (_, entry, seq) in entries {
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
            || *original_seq >= seq
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
    let seq = resolve_known_at(db, known_at)?;
    period_at(db, book, period_code, seq)?;
    let mut cells: BTreeMap<CellKey, Cell> = BTreeMap::new();
    let mut pending = BTreeMap::new();
    let mut watermark: Option<CommitSeq> = None;
    let mut count = 0u64;
    let entries = entries_at(db, book, seq)?;
    let resolved = resolutions(&entries)?;
    for (vid, entry, created_at) in entries {
        if entry.proposal.legs.is_empty() {
            continue;
        }
        if entry_period(book, &entry)? != period_code {
            continue;
        }
        watermark = Some(watermark.map_or(created_at, |w: CommitSeq| w.max(created_at)));
        if entry.proposal.class == EntryClass::PENDING {
            if let Some(release) = resolved.get(&vid) {
                watermark = Some(watermark.map_or(*release, |w| w.max(*release)));
            } else {
                add_entry(&mut pending, &entry, period_code)?;
            }
        } else {
            count = count.checked_add(1).ok_or(RegisterError::Overflow)?;
            add_entry(&mut cells, &entry, period_code)?;
        }
    }
    let cells: Vec<Cell> = cells.into_values().collect();
    let pending: Vec<Cell> = pending.into_values().collect();
    let fold_digest = digest_of(&cells, &pending, watermark)?;
    Ok(Fold {
        period: period_code.to_string(),
        cells,
        pending,
        watermark,
        entries: count,
        fold_digest,
    })
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
    if fold_period(db, book, &fold.period)? != *fold {
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
        && materialize_batch(db, book, fold)?.is_empty()
    {
        return Ok(db.frontier()?);
    }
    let prepared = maintainer::prepare_fold(db, book, fold.clone())?;
    Ok(maintainer::publish_advance(db, ctx, book, prepared)
        .await?
        .published_at)
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
    let edges = db.edges()?;
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
        for edge in &edges {
            if edge.entry.src == row.vid
                && edge.entry.relation == relation::IN_PERIOD
                && (!expected.contains(&row.vid) || edge.entry.dst != pvid)
            {
                batch.delete_edge(edge.entry.eid);
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verification {
    pub period: String,
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
    Ok(db.vertices()?.into_iter().filter(|row| {
        expected.contains(&row.vid) || (row.labels.contains(&label::REGISTER)
            && (linked.contains(&row.vid) || matches!(prop(row, property::EFFECTIVE_PERIOD), Some(CanonicalScalar::Text(p)) if p.as_str() == fold.period)))
    }).map(|row| (row.vid, row)).collect())
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

/// Refold the period and compare every stored `Register` vertex to it.
pub fn verify_period<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
) -> Result<Verification, RegisterError> {
    let fold = fold_period(db, book, period_code)?;
    let mut result = verify_projection(db, book, &fold)?;
    if let Some(error) = maintainer::verify_state(db, book, period_code)? {
        result.projection_errors.push(error);
    }
    Ok(result)
}

fn verify_projection<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    fold: &Fold,
) -> Result<Verification, RegisterError> {
    let period_code = &fold.period;
    let mut drift = Vec::new();
    let mut pending_drift = Vec::new();
    let mut projection_errors = Vec::new();
    let mut candidates = stored_registers(db, book, fold)?;
    let pvid = period_vid(&book.calendar.id, period_code);
    let linked: BTreeSet<_> = db
        .in_neighbours(pvid, relation::IN_PERIOD)?
        .into_iter()
        .collect();
    let edges = db.edges()?;
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
                    && !edges.iter().any(|e| {
                        e.entry.src == rvid
                            && e.entry.relation == relation::IN_PERIOD
                            && e.entry.dst != pvid
                    });
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
    /// FA-INV-01 at the register level: every unit's debits equal its credits.
    #[must_use]
    pub fn is_balanced(&self) -> bool {
        self.unit_totals
            .values()
            .chain(self.pending_unit_totals.values())
            .all(|(d, c)| d == c)
    }
}

/// Balances from inception through the latest selected period's inclusive end.
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
    report_at(db, book, selected, seq, through)
}

/// A stock position on a civil day, independent of when postings were recorded.
/// Includes adjustment/closing periods and every account type. Stock versus
/// flow is a report-line choice; it is not inferred from an account's type.
pub fn balance_as_of<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    day: DateDay,
    known_at: Option<CommitSeq>,
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
    report_at(db, book, periods.into_iter().collect(), seq, Some(day))
}

/// Movement within the explicitly selected periods. Overlapping civil dates
/// remain distinct by period identity, and repeated codes contribute only once.
pub fn period_activity<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: &[String],
    known_at: Option<CommitSeq>,
) -> Result<TrialBalance, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    report_at(db, book, select_periods(db, book, periods, seq)?, seq, None)
}

fn select_periods<V: asupersync::fs::Vfs + Clone>(
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

fn report_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    periods: Vec<String>,
    seq: CommitSeq,
    through: Option<DateDay>,
) -> Result<TrialBalance, RegisterError> {
    let mut sums: BTreeMap<(VId, u32), [i128; 4]> = BTreeMap::new();
    let entries = entries_at(db, book, seq)?;
    let resolved = resolutions(&entries)?;
    for (vid, entry, _) in entries {
        if entry.proposal.legs.is_empty() {
            continue;
        }
        let pending = entry.proposal.class == EntryClass::PENDING;
        // Releases are evaluated at the known-at frontier. They release the
        // original period, irrespective of their own posting effective date.
        if pending && resolved.contains_key(&vid) {
            continue;
        }
        let selected = match through {
            Some(day) => entry.proposal.effective_date <= day,
            None => periods.binary_search(&entry_period(book, &entry)?).is_ok(),
        };
        if !selected {
            continue;
        }
        for leg in &entry.proposal.legs {
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
    let mut rows = Vec::with_capacity(sums.len());
    let mut unit_totals: BTreeMap<u32, (i128, i128)> = BTreeMap::new();
    let mut pending_unit_totals: BTreeMap<u32, (i128, i128)> = BTreeMap::new();
    for ((account, unit_id), [debits, credits, debits_pending, credits_pending]) in sums {
        let row = db.vertex_at(account, seq)?.ok_or_else(|| {
            KernelError::Corrupt(format!("missing account {account:?} at sequence {}", seq.0))
        })?;
        let a = AccountRow::decode(&row)?;
        let (code, name, account_type) = (a.code, a.name, AccountType(a.account_type));
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
            debits: 10,
            credits: 10,
            entry_count: 1,
        }];
        let mut b = a.clone();
        b[0].debits = 11;
        assert_eq!(
            digest_of(&a, &[], Some(CommitSeq(5))).unwrap(),
            digest_of(&a, &[], Some(CommitSeq(5))).unwrap()
        );
        assert_ne!(
            digest_of(&a, &[], Some(CommitSeq(5))).unwrap(),
            digest_of(&b, &[], Some(CommitSeq(5))).unwrap()
        );
        assert_ne!(
            digest_of(&a, &[], Some(CommitSeq(5))).unwrap(),
            digest_of(&a, &[], Some(CommitSeq(6))).unwrap()
        );
        assert_ne!(
            register_vid(Id128([1; 16]), &key),
            register_vid(Id128([2; 16]), &key)
        );
    }
}
