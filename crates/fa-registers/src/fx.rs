//! Functional-currency register fold (plan §5.2, §5.3; bead `fa-s3c`;
//! `FA-INV-04.functional-fold`).
//!
//! A functional-value register cell `(account, base_unit, period, legal_entity)`
//! is a deterministic fold over the committed entry payloads of a period in
//! the book's `base_unit`. Every leg in `base_unit` contributes its native
//! amount at par (`1:1`), and every foreign-currency leg contributes its
//! verified `leg.base_amount` computed under the entry's registered FX law.
//! An unvalued foreign-currency leg in a functional fold is refused as
//! projection drift.

use std::collections::{BTreeMap, BTreeSet};

use fa_journal::entity::leg_entity;
use fa_journal::genesis::{BookContext, BookSpec, read_book_spec};
use fa_journal::refusal::{Refusal, code, exit};
use fa_journal::{FxLawId, FxRateDocument, FxRatePurpose, KernelError};
use fa_model::{AccountType, BaseTotals, Entry, EntryClass, EntryPayload, LegPayload, Writer};
use fa_money::rate::ArithmeticBudget;
use fa_money::{Amount, Side, UnitId, UnitRegistry};
use fa_time::DateDay;
use fgdb::Database;
use fgdb_crypto::Hasher;
use fgdb_types::{CommitSeq, VId};

use crate::{
    RegisterError, contribution_seq, entries_at, entry_period, migration_activations, period_at,
    resolutions, resolve_known_at,
};

/// Domain separator for functional-value register fold digests (`FA-INV-04.functional-fold`).
pub const FUNCTIONAL_FOLD_DIGEST_DOMAIN: &[u8] = b"fa:register-functional-fold:v1";
/// Domain separator for current-rate translation certificates (`plan §12.4`, `fa-rn6g`).
pub const TRANSLATION_CERTIFICATE_DOMAIN: &[u8] = b"fa:fx-translation-cert:v1";
/// Domain separator for temporal-method remeasurement certificates (`plan §12.4`, `fa-rn6g`).
pub const REMEASUREMENT_CERTIFICATE_DOMAIN: &[u8] = b"fa:fx-remeasurement-cert:v1";

/// Key of a functional-currency register cell: `(account, base_unit, period, entity)`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FunctionalCellKey {
    pub account: VId,
    pub unit_id: u32,
    pub period: String,
    pub entity: Option<String>,
}

/// One functional-currency register cell in the book's `base_unit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalCell {
    pub key: FunctionalCellKey,
    pub debits: i128,
    pub credits: i128,
    pub entry_count: u64,
}

impl FunctionalCell {
    /// Checked debits minus credits in `base_unit`.
    #[must_use]
    pub fn net(&self) -> Option<i128> {
        self.debits.checked_sub(self.credits)
    }
}

/// Deterministic functional-currency fold of one period at `known_at`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionalFold {
    pub period: String,
    pub base_unit: UnitId,
    pub known_at: CommitSeq,
    pub cells: Vec<FunctionalCell>,
    pub pending: Vec<FunctionalCell>,
    pub watermark: Option<CommitSeq>,
    pub entries: u64,
    pub fold_digest: [u8; 32],
}

impl FunctionalFold {
    /// Look up the posted functional cell at `key`.
    #[must_use]
    pub fn cell(&self, key: &FunctionalCellKey) -> Option<&FunctionalCell> {
        self.cells.iter().find(|c| c.key == *key)
    }

    /// Total functional debits across all posted cells in this period.
    pub fn total_debits(&self) -> Result<i128, RegisterError> {
        let mut sum = 0i128;
        for cell in &self.cells {
            sum = sum
                .checked_add(cell.debits)
                .ok_or(RegisterError::Overflow)?;
        }
        Ok(sum)
    }

    /// Total functional credits across all posted cells in this period.
    pub fn total_credits(&self) -> Result<i128, RegisterError> {
        let mut sum = 0i128;
        for cell in &self.cells {
            sum = sum
                .checked_add(cell.credits)
                .ok_or(RegisterError::Overflow)?;
        }
        Ok(sum)
    }
}

fn entity_of(spec: &BookSpec, leg: &LegPayload) -> Option<String> {
    leg_entity(spec, leg).or_else(|| match spec.entities.as_slice() {
        [only] => Some(only.code.clone()),
        _ => None,
    })
}

fn functional_mantissa(
    spec: &BookSpec,
    entry_vid: VId,
    ordinal: usize,
    leg: &LegPayload,
) -> Result<i128, RegisterError> {
    match leg.base_amount {
        Some(base) => {
            if base.unit != spec.base_unit || base.mantissa <= 0 {
                return Err(RegisterError::ProjectionDrift(format!(
                    "entry {:032x} leg {ordinal} has base_amount in unit {} (mantissa {}), expected positive base_unit {}",
                    entry_vid.0, base.unit.0, base.mantissa, spec.base_unit.0
                )));
            }
            if leg.amount.unit == spec.base_unit && base != leg.amount {
                return Err(RegisterError::ProjectionDrift(format!(
                    "entry {:032x} leg {ordinal} is in base_unit {} but base_amount {} != native amount {}",
                    entry_vid.0, spec.base_unit.0, base.mantissa, leg.amount.mantissa
                )));
            }
            Ok(base.mantissa)
        }
        None => {
            if leg.amount.unit == spec.base_unit {
                Ok(leg.amount.mantissa)
            } else {
                Err(RegisterError::ProjectionDrift(format!(
                    "entry {:032x} leg {ordinal} is in foreign unit {} without a functional base_amount",
                    entry_vid.0, leg.amount.unit.0
                )))
            }
        }
    }
}

fn add_functional_entry(
    cells: &mut BTreeMap<FunctionalCellKey, FunctionalCell>,
    spec: &BookSpec,
    entry_vid: VId,
    entry: &Entry,
    period: &str,
) -> Result<(), RegisterError> {
    let mut touched = BTreeSet::new();
    let mut by_entity: BTreeMap<Option<String>, (i128, i128)> = BTreeMap::new();
    for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
        let mantissa = functional_mantissa(spec, entry_vid, ordinal, leg)?;
        let entity = entity_of(spec, leg);
        let key = FunctionalCellKey {
            account: leg.account_ref,
            unit_id: spec.base_unit.0,
            period: period.into(),
            entity: entity.clone(),
        };
        let cell = cells.entry(key.clone()).or_insert_with(|| FunctionalCell {
            key: key.clone(),
            debits: 0,
            credits: 0,
            entry_count: 0,
        });
        let entity_slot = by_entity.entry(entity).or_insert((0, 0));
        match leg.side {
            Side::Debit => {
                cell.debits = cell
                    .debits
                    .checked_add(mantissa)
                    .ok_or(RegisterError::Overflow)?;
                entity_slot.0 = entity_slot
                    .0
                    .checked_add(mantissa)
                    .ok_or(RegisterError::Overflow)?;
            }
            Side::Credit => {
                cell.credits = cell
                    .credits
                    .checked_add(mantissa)
                    .ok_or(RegisterError::Overflow)?;
                entity_slot.1 = entity_slot
                    .1
                    .checked_add(mantissa)
                    .ok_or(RegisterError::Overflow)?;
            }
        }
        touched.insert(key);
    }
    for (entity, (debits, credits)) in by_entity {
        if debits != credits {
            let label = entity.as_deref().unwrap_or("<default>");
            return Err(RegisterError::ProjectionDrift(format!(
                "entry {:032x} functional base amounts do not balance in entity `{label}`: debits {debits} != credits {credits}",
                entry_vid.0
            )));
        }
    }
    for key in touched {
        let cell = cells
            .get_mut(&key)
            .ok_or_else(|| KernelError::Corrupt("missing functional fold cell".into()))?;
        cell.entry_count = cell
            .entry_count
            .checked_add(1)
            .ok_or(RegisterError::Overflow)?;
    }
    Ok(())
}

fn fold_functional_leg_contribution(
    prev: [u8; 32],
    (commit_seq, entry, ordinal): (CommitSeq, VId, u16),
    account: VId,
    base_unit_id: u32,
    entity: Option<&String>,
    side: Side,
    base_mantissa: i128,
) -> Result<[u8; 32], RegisterError> {
    let mut w = Writer::new();
    w.fixed(&prev)
        .u64(commit_seq.0)
        .u128(entry.0)
        .u16(ordinal)
        .u128(account.0)
        .u32(base_unit_id)
        .opt(entity, |w, e| {
            w.str(e);
        })
        .u8(match side {
            Side::Debit => 0,
            Side::Credit => 1,
        })
        .i128(base_mantissa);
    let mut h = Hasher::new();
    h.update(b"fa:register-functional-leg-contribution:v1");
    h.update(&w.finish().map_err(RegisterError::Encoding)?);
    Ok(h.finalize().0)
}

fn fold_functional_entry_contributions(
    mut acc: [u8; 32],
    spec: &BookSpec,
    commit_seq: CommitSeq,
    entry_vid: VId,
    entry: &Entry,
) -> Result<[u8; 32], RegisterError> {
    for (ordinal, leg) in entry.proposal.legs.iter().enumerate() {
        let ord_u16 = u16::try_from(ordinal)
            .map_err(|_| KernelError::Corrupt("leg ordinal exceeds u16".into()))?;
        let mantissa = functional_mantissa(spec, entry_vid, ordinal, leg)?;
        let entity = entity_of(spec, leg);
        acc = fold_functional_leg_contribution(
            acc,
            (commit_seq, entry_vid, ord_u16),
            leg.account_ref,
            spec.base_unit.0,
            entity.as_ref(),
            leg.side,
            mantissa,
        )?;
    }
    Ok(acc)
}

fn digest_of(
    period: &str,
    base_unit: UnitId,
    cells: &[FunctionalCell],
    pending: &[FunctionalCell],
    watermark: Option<CommitSeq>,
    posted_legs_digest: [u8; 32],
    pending_holds: &BTreeMap<(CommitSeq, VId), [u8; 32]>,
) -> Result<[u8; 32], RegisterError> {
    let mut w = Writer::new();
    w.str(period)
        .u32(base_unit.0)
        .opt(watermark.as_ref(), |w, s| {
            w.u64(s.0);
        })
        .fixed(&posted_legs_digest);
    let holds: Vec<_> = pending_holds.iter().collect();
    w.list(&holds, |w, ((seq, vid), digest)| {
        w.u64(seq.0).u128(vid.0).fixed(*digest);
    });
    for column in [cells, pending] {
        w.list(column, |w, c| {
            w.u128(c.key.account.0)
                .u32(c.key.unit_id)
                .str(&c.key.period)
                .opt(c.key.entity.as_ref(), |w, e| {
                    w.str(e);
                })
                .i128(c.debits)
                .i128(c.credits)
                .u64(c.entry_count);
        });
    }
    let mut h = Hasher::new();
    h.update(FUNCTIONAL_FOLD_DIGEST_DOMAIN);
    h.update(&w.finish().map_err(RegisterError::Encoding)?);
    Ok(h.finalize().0)
}

/// Fold functional-currency (`base_unit`) register cells for `period_code` at
/// `known_at` (head when `None`) (`FA-INV-04.functional-fold`).
pub fn fold_period_functional<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    known_at: Option<CommitSeq>,
) -> Result<FunctionalFold, RegisterError> {
    let seq = resolve_known_at(db, known_at)?;
    period_at(db, book, period_code, seq)?;
    let spec = read_book_spec(db)?
        .ok_or_else(|| KernelError::Corrupt("no book spec on the root".into()))?;
    let mut cells: BTreeMap<FunctionalCellKey, FunctionalCell> = BTreeMap::new();
    let mut pending: BTreeMap<FunctionalCellKey, FunctionalCell> = BTreeMap::new();
    let mut watermark: Option<CommitSeq> = None;
    let mut entries_count: u64 = 0;
    let mut posted_legs_digest = [0u8; 32];
    let mut pending_holds = BTreeMap::new();

    let entries = entries_at(db, book, seq)?;
    let resolved = resolutions(&entries)?;
    let activated = migration_activations(&entries)?;

    for (vid, entry, created_at) in &entries {
        if entry.proposal.legs.is_empty() || entry_period(book, entry)? != period_code {
            continue;
        }
        let contribution = contribution_seq(entry, *created_at, &activated)?;
        watermark = Some(watermark.map_or(contribution, |w| w.max(contribution)));
        if entry.proposal.class == EntryClass::PENDING {
            if let Some(release) = resolved.get(vid) {
                watermark = Some(watermark.map_or(*release, |w| w.max(*release)));
            } else {
                add_functional_entry(&mut pending, &spec, *vid, entry, period_code)?;
                let hold_digest = fold_functional_entry_contributions(
                    [0u8; 32],
                    &spec,
                    *created_at,
                    *vid,
                    entry,
                )?;
                pending_holds.insert((*created_at, *vid), hold_digest);
            }
        } else {
            add_functional_entry(&mut cells, &spec, *vid, entry, period_code)?;
            posted_legs_digest = fold_functional_entry_contributions(
                posted_legs_digest,
                &spec,
                *created_at,
                *vid,
                entry,
            )?;
            entries_count = entries_count
                .checked_add(1)
                .ok_or(RegisterError::Overflow)?;
        }
    }

    let cells: Vec<FunctionalCell> = cells.into_values().collect();
    let pending: Vec<FunctionalCell> = pending.into_values().collect();
    let fold_digest = digest_of(
        period_code,
        spec.base_unit,
        &cells,
        &pending,
        watermark,
        posted_legs_digest,
        &pending_holds,
    )?;

    Ok(FunctionalFold {
        period: period_code.into(),
        base_unit: spec.base_unit,
        known_at: seq,
        cells,
        pending,
        watermark,
        entries: entries_count,
        fold_digest,
    })
}

/// Verify a claimed [`FunctionalFold`] by refolding the journal at
/// `claimed.known_at` and checking exact cell, watermark, and `fold_digest`
/// equality (`FA-INV-04.functional-fold`).
pub fn verify_functional_fold<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    period_code: &str,
    claimed: &FunctionalFold,
) -> Result<(), RegisterError> {
    let refolded = fold_period_functional(db, book, period_code, Some(claimed.known_at))?;
    if refolded != *claimed {
        return Err(RegisterError::ProjectionDrift(format!(
            "functional fold drift on period `{period_code}` at seq {}: expected digest {:02x?}, got {:02x?}",
            claimed.known_at.0, refolded.fold_digest, claimed.fold_digest
        )));
    }
    Ok(())
}

// =============================================================================
// FX Translation (Current-Rate Method, ASC 830-30 / IAS 21.39; plan §12.4)
// =============================================================================

/// Classification of a line item for current-rate translation (`ASC 830-30 / IAS 21.39`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TranslationItemKind {
    /// Monetary or non-monetary asset translated at the period's `PeriodClose` rate.
    Asset,
    /// Monetary or non-monetary liability translated at the period's `PeriodClose` rate.
    Liability,
    /// Contributed equity layer translated at the historical `SpotClose` rate on `originating_date`.
    ContributedEquity { originating_date: DateDay },
    /// Period revenue flow translated at the period's `PeriodAverage` rate.
    Revenue,
    /// Period expense flow translated at the period's `PeriodAverage` rate.
    Expense,
    /// Dividend declared in the period, translated at the historical `SpotClose` rate on `declaration_date`.
    Dividend { declaration_date: DateDay },
}

impl TranslationItemKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Asset => 1,
            Self::Liability => 2,
            Self::ContributedEquity { .. } => 3,
            Self::Revenue => 4,
            Self::Expense => 5,
            Self::Dividend { .. } => 6,
        }
    }

    const fn historical_date(self) -> Option<DateDay> {
        match self {
            Self::ContributedEquity { originating_date } => Some(originating_date),
            Self::Dividend { declaration_date } => Some(declaration_date),
            _ => None,
        }
    }
}

/// Input line for current-rate translation (`ASC 830-30 / IAS 21.39`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationInputLine {
    pub account: VId,
    pub kind: TranslationItemKind,
    pub side: Side,
    pub functional_amount: Amount,
    /// For `ContributedEquity`, whether this layer was issued in the current period
    /// (used to decompose `ΔCTA` into opening-net-asset retranslation vs current-period issuance spread).
    pub is_current_period_activity: bool,
}

/// Translated line result under `TranslationCurrentRate`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationLineResult {
    pub account: VId,
    pub kind: TranslationItemKind,
    pub side: Side,
    pub functional_amount: Amount,
    pub reporting_amount: Amount,
    pub rate_doc_commit: [u8; 32],
    pub rate_purpose: FxRatePurpose,
}

/// Exact component-by-component roll-forward of Cumulative Translation Adjustment (`CTA`)
/// in AOCI (`ASC 830-30-45 / IAS 21.39`, plan §12.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CtaRollForwardSchedule {
    /// Prior period's ending cumulative CTA (credit-positive in `reporting_unit`).
    pub prior_cumulative_cta_credit: i128,
    /// Retranslation of opening net assets from prior closing rate to current closing rate.
    pub opening_net_assets_retranslation: i128,
    /// Spread between current-period net income at closing rate vs period average rate.
    pub period_net_income_spread: i128,
    /// Spread between current-period equity issuances / dividends at closing rate vs historical spot rate.
    pub equity_and_dividend_spread: i128,
    /// Delta-cumulative CTA recognized in AOCI for the current period (`ending - prior`).
    pub delta_cta_credit: i128,
    /// Ending cumulative CTA in AOCI (`prior + delta`).
    pub ending_cumulative_cta_credit: i128,
}

/// Certified output of a current-rate translation run (`ASC 830-30 / IAS 21.39`, plan §12.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslatedStatement {
    pub period: String,
    pub period_end: DateDay,
    pub functional_unit: UnitId,
    pub reporting_unit: UnitId,
    pub lines: Vec<TranslationLineResult>,
    pub total_assets_reporting: i128,
    pub total_liabilities_reporting: i128,
    pub total_contributed_equity_reporting: i128,
    pub total_revenue_reporting: i128,
    pub total_expense_reporting: i128,
    pub translated_net_income_reporting: i128,
    pub total_dividends_reporting: i128,
    pub prior_retained_earnings_reporting: i128,
    pub ending_retained_earnings_reporting: i128,
    pub cta_schedule: CtaRollForwardSchedule,
    pub certificate_digest: [u8; 32],
}

fn fx_refusal(why: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::STRUCTURE,
        exit::USAGE,
        format!("fx translation/remeasurement: {why}"),
        "plan §12.4, registries/fx_laws.toml",
        "supply valid FxRateDocument evidence and balanced inputs matching the registered FX law",
    )
}

fn fx_unbalanced(why: impl core::fmt::Display) -> Refusal {
    Refusal::new(
        code::UNBALANCED,
        exit::REFUSAL,
        format!("fx translation/remeasurement: {why}"),
        "plan §12.4, FA-INV-01",
        "ensure the source trial balance and prior retained earnings balance in the source currency",
    )
}

/// Execute current-rate translation (`FxLawId::TranslationCurrentRate`, `ASC 830-30 / IAS 21.39`)
/// from `functional_unit` into `reporting_unit` for `period` ending at `period_end`.
///
/// All rates come strictly from content-addressed [`FxRateDocument`]s:
/// - `closing_rate_doc` (`FxRatePurpose::PeriodClose`, `as_of == period_end`)
/// - `average_rate_doc` (`FxRatePurpose::PeriodAverage`, `as_of == period_end`)
/// - `historical_rate_docs` (`FxRatePurpose::SpotClose`, keyed by `as_of`)
///
/// Returns a [`TranslatedStatement`] with exact [`CtaRollForwardSchedule`] tie-out and
/// replayable `certificate_digest`.
#[allow(clippy::too_many_arguments)]
pub fn translate_current_rate(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    period: &str,
    period_end: DateDay,
    functional_unit: UnitId,
    reporting_unit: UnitId,
    lines: &[TranslationInputLine],
    closing_rate_doc: &FxRateDocument,
    average_rate_doc: &FxRateDocument,
    historical_rate_docs: &[FxRateDocument],
    prior_retained_earnings_functional: i128,
    prior_retained_earnings_reporting: i128,
    prior_cumulative_cta_credit: i128,
    units: &UnitRegistry,
) -> Result<TranslatedStatement, Refusal> {
    if period.trim().is_empty() {
        return Err(fx_refusal("period code must not be empty"));
    }
    if functional_unit == reporting_unit {
        return Err(fx_refusal(
            "functional_unit and reporting_unit must be distinct currencies",
        ));
    }
    if lines.is_empty() {
        return Err(fx_refusal("translation input lines must not be empty"));
    }
    if closing_rate_doc.base_unit != reporting_unit
        || closing_rate_doc.quote_unit != functional_unit
        || closing_rate_doc.purpose != FxRatePurpose::PeriodClose
        || closing_rate_doc.as_of != period_end
    {
        return Err(fx_refusal(
            "closing_rate_doc must have base_unit == reporting_unit, quote_unit == functional_unit, purpose == PeriodClose, and as_of == period_end",
        ));
    }
    if average_rate_doc.base_unit != reporting_unit
        || average_rate_doc.quote_unit != functional_unit
        || average_rate_doc.purpose != FxRatePurpose::PeriodAverage
        || average_rate_doc.as_of != period_end
    {
        return Err(fx_refusal(
            "average_rate_doc must have base_unit == reporting_unit, quote_unit == functional_unit, purpose == PeriodAverage, and as_of == period_end",
        ));
    }

    let mut hist_by_date: BTreeMap<DateDay, (&FxRateDocument, [u8; 32])> = BTreeMap::new();
    for doc in historical_rate_docs {
        if doc.base_unit != reporting_unit
            || doc.quote_unit != functional_unit
            || doc.purpose != FxRatePurpose::SpotClose
        {
            return Err(fx_refusal(
                "historical_rate_docs must have base_unit == reporting_unit, quote_unit == functional_unit, and purpose == SpotClose",
            ));
        }
        let commit = doc.doc_commit()?;
        if hist_by_date.insert(doc.as_of, (doc, commit)).is_some() {
            return Err(fx_refusal(format!(
                "duplicate historical SpotClose rate document for date {}",
                doc.as_of.render()
            )));
        }
    }

    let closing_commit = closing_rate_doc.doc_commit()?;
    let average_commit = average_rate_doc.doc_commit()?;
    let closing_rate = closing_rate_doc.to_rate(budget)?;
    let average_rate = average_rate_doc.to_rate(budget)?;

    let mut func_debits = 0i128;
    let mut func_credits = prior_retained_earnings_functional.max(0);
    if prior_retained_earnings_functional < 0 {
        func_debits = func_debits
            .checked_add(-prior_retained_earnings_functional)
            .ok_or_else(|| fx_refusal("functional debit overflow"))?;
    }

    let mut out_lines = Vec::with_capacity(lines.len());
    let mut total_assets_reporting = 0i128;
    let mut total_liabilities_reporting = 0i128;
    let mut total_contributed_equity_reporting = 0i128;
    let mut total_revenue_reporting = 0i128;
    let mut total_expense_reporting = 0i128;
    let mut total_dividends_reporting = 0i128;

    // Track closing-rate equivalents of period flows for exact CTA roll-forward decomposition.
    let mut revenue_at_closing = 0i128;
    let mut expense_at_closing = 0i128;
    let mut current_equity_spread = 0i128;
    let mut dividend_spread = 0i128;

    for (idx, line) in lines.iter().enumerate() {
        if line.functional_amount.unit != functional_unit || line.functional_amount.mantissa <= 0 {
            return Err(fx_refusal(format!(
                "line {idx} functional_amount must be a positive amount in functional_unit"
            )));
        }
        match line.side {
            Side::Debit => {
                func_debits = func_debits
                    .checked_add(line.functional_amount.mantissa)
                    .ok_or_else(|| fx_refusal("functional debit overflow"))?;
            }
            Side::Credit => {
                func_credits = func_credits
                    .checked_add(line.functional_amount.mantissa)
                    .ok_or_else(|| fx_refusal("functional credit overflow"))?;
            }
        }

        let (reporting_amount, rate_doc_commit, rate_purpose) = match line.kind {
            TranslationItemKind::Asset | TranslationItemKind::Liability => {
                let amt = line
                    .functional_amount
                    .convert(
                        budget,
                        reporting_unit,
                        &closing_rate,
                        closing_rate_doc.rounding,
                        units,
                    )
                    .map_err(fx_refusal)?;
                (amt, closing_commit, FxRatePurpose::PeriodClose)
            }
            TranslationItemKind::Revenue | TranslationItemKind::Expense => {
                let amt = line
                    .functional_amount
                    .convert(
                        budget,
                        reporting_unit,
                        &average_rate,
                        average_rate_doc.rounding,
                        units,
                    )
                    .map_err(fx_refusal)?;
                (amt, average_commit, FxRatePurpose::PeriodAverage)
            }
            TranslationItemKind::ContributedEquity { originating_date } => {
                let Some((doc, commit)) = hist_by_date.get(&originating_date) else {
                    return Err(Refusal::new(
                        code::EVIDENCE_UNKNOWN,
                        exit::REFUSAL,
                        format!(
                            "missing historical SpotClose FxRateDocument for equity originating_date {}",
                            originating_date.render()
                        ),
                        "plan §12.4, FA-INV-05 (equity items under current-rate translation require historical SpotClose rate documents)",
                        "commit the SpotClose FxRateDocument for the equity issuance date and pass it in historical_rate_docs",
                    ));
                };
                let rate = doc.to_rate(budget)?;
                let amt = line
                    .functional_amount
                    .convert(budget, reporting_unit, &rate, doc.rounding, units)
                    .map_err(fx_refusal)?;
                (amt, *commit, FxRatePurpose::SpotClose)
            }
            TranslationItemKind::Dividend { declaration_date } => {
                let Some((doc, commit)) = hist_by_date.get(&declaration_date) else {
                    return Err(Refusal::new(
                        code::EVIDENCE_UNKNOWN,
                        exit::REFUSAL,
                        format!(
                            "missing historical SpotClose FxRateDocument for dividend declaration_date {}",
                            declaration_date.render()
                        ),
                        "plan §12.4, FA-INV-05 (dividends under current-rate translation require SpotClose rate documents on declaration date)",
                        "commit the SpotClose FxRateDocument for the dividend declaration date and pass it in historical_rate_docs",
                    ));
                };
                let rate = doc.to_rate(budget)?;
                let amt = line
                    .functional_amount
                    .convert(budget, reporting_unit, &rate, doc.rounding, units)
                    .map_err(fx_refusal)?;
                (amt, *commit, FxRatePurpose::SpotClose)
            }
        };

        let at_closing = line
            .functional_amount
            .convert(
                budget,
                reporting_unit,
                &closing_rate,
                closing_rate_doc.rounding,
                units,
            )
            .map_err(fx_refusal)?
            .mantissa;
        let rep = reporting_amount.mantissa;

        match (line.kind, line.side) {
            (TranslationItemKind::Asset, Side::Debit) => total_assets_reporting += rep,
            (TranslationItemKind::Asset, Side::Credit) => total_assets_reporting -= rep,
            (TranslationItemKind::Liability, Side::Credit) => total_liabilities_reporting += rep,
            (TranslationItemKind::Liability, Side::Debit) => total_liabilities_reporting -= rep,
            (TranslationItemKind::ContributedEquity { .. }, Side::Credit) => {
                total_contributed_equity_reporting += rep;
                if line.is_current_period_activity {
                    current_equity_spread += at_closing - rep;
                }
            }
            (TranslationItemKind::ContributedEquity { .. }, Side::Debit) => {
                total_contributed_equity_reporting -= rep;
                if line.is_current_period_activity {
                    current_equity_spread -= at_closing - rep;
                }
            }
            (TranslationItemKind::Revenue, Side::Credit) => {
                total_revenue_reporting += rep;
                revenue_at_closing += at_closing;
            }
            (TranslationItemKind::Revenue, Side::Debit) => {
                total_revenue_reporting -= rep;
                revenue_at_closing -= at_closing;
            }
            (TranslationItemKind::Expense, Side::Debit) => {
                total_expense_reporting += rep;
                expense_at_closing += at_closing;
            }
            (TranslationItemKind::Expense, Side::Credit) => {
                total_expense_reporting -= rep;
                expense_at_closing -= at_closing;
            }
            (TranslationItemKind::Dividend { .. }, Side::Debit) => {
                total_dividends_reporting += rep;
                dividend_spread += rep - at_closing;
            }
            (TranslationItemKind::Dividend { .. }, Side::Credit) => {
                total_dividends_reporting -= rep;
                dividend_spread -= rep - at_closing;
            }
        }

        out_lines.push(TranslationLineResult {
            account: line.account,
            kind: line.kind,
            side: line.side,
            functional_amount: line.functional_amount,
            reporting_amount,
            rate_doc_commit,
            rate_purpose,
        });
    }

    if func_debits != func_credits {
        return Err(fx_unbalanced(format!(
            "functional trial balance does not balance: debits {func_debits} != credits {func_credits}"
        )));
    }

    let translated_net_income_reporting = total_revenue_reporting
        .checked_sub(total_expense_reporting)
        .ok_or_else(|| fx_refusal("translated net income overflow"))?;
    let ending_retained_earnings_reporting = prior_retained_earnings_reporting
        .checked_add(translated_net_income_reporting)
        .and_then(|v| v.checked_sub(total_dividends_reporting))
        .ok_or_else(|| fx_refusal("ending retained earnings overflow"))?;

    let net_assets_reporting = total_assets_reporting
        .checked_sub(total_liabilities_reporting)
        .ok_or_else(|| fx_refusal("net assets overflow"))?;
    let non_cta_equity_reporting = total_contributed_equity_reporting
        .checked_add(ending_retained_earnings_reporting)
        .ok_or_else(|| fx_refusal("non-CTA equity overflow"))?;
    let ending_cumulative_cta_credit =
        net_assets_reporting
            .checked_sub(non_cta_equity_reporting)
            .ok_or_else(|| fx_refusal("ending cumulative CTA overflow"))?;
    let delta_cta_credit = ending_cumulative_cta_credit
        .checked_sub(prior_cumulative_cta_credit)
        .ok_or_else(|| fx_refusal("delta CTA overflow"))?;

    let ni_at_closing = revenue_at_closing
        .checked_sub(expense_at_closing)
        .ok_or_else(|| fx_refusal("closing-rate net income overflow"))?;
    let period_net_income_spread = ni_at_closing
        .checked_sub(translated_net_income_reporting)
        .ok_or_else(|| fx_refusal("period net income spread overflow"))?;
    let equity_and_dividend_spread = current_equity_spread
        .checked_add(dividend_spread)
        .ok_or_else(|| fx_refusal("equity and dividend spread overflow"))?;
    let opening_net_assets_retranslation = delta_cta_credit
        .checked_sub(period_net_income_spread)
        .and_then(|v| v.checked_sub(equity_and_dividend_spread))
        .ok_or_else(|| fx_refusal("opening net assets retranslation overflow"))?;

    let cta_schedule = CtaRollForwardSchedule {
        prior_cumulative_cta_credit,
        opening_net_assets_retranslation,
        period_net_income_spread,
        equity_and_dividend_spread,
        delta_cta_credit,
        ending_cumulative_cta_credit,
    };

    let certificate_digest = compute_translation_digest(
        period,
        period_end,
        functional_unit,
        reporting_unit,
        &closing_commit,
        &average_commit,
        &out_lines,
        prior_retained_earnings_functional,
        prior_retained_earnings_reporting,
        ending_retained_earnings_reporting,
        &cta_schedule,
    )?;

    Ok(TranslatedStatement {
        period: period.to_string(),
        period_end,
        functional_unit,
        reporting_unit,
        lines: out_lines,
        total_assets_reporting,
        total_liabilities_reporting,
        total_contributed_equity_reporting,
        total_revenue_reporting,
        total_expense_reporting,
        translated_net_income_reporting,
        total_dividends_reporting,
        prior_retained_earnings_reporting,
        ending_retained_earnings_reporting,
        cta_schedule,
        certificate_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn compute_translation_digest(
    period: &str,
    period_end: DateDay,
    functional_unit: UnitId,
    reporting_unit: UnitId,
    closing_commit: &[u8; 32],
    average_commit: &[u8; 32],
    lines: &[TranslationLineResult],
    prior_re_func: i128,
    prior_re_rep: i128,
    ending_re_rep: i128,
    cta: &CtaRollForwardSchedule,
) -> Result<[u8; 32], Refusal> {
    let mut w = Writer::new();
    w.str(period)
        .i32(period_end.0)
        .u32(functional_unit.0)
        .u32(reporting_unit.0)
        .fixed(closing_commit)
        .fixed(average_commit)
        .i128(prior_re_func)
        .i128(prior_re_rep)
        .i128(ending_re_rep)
        .i128(cta.prior_cumulative_cta_credit)
        .i128(cta.opening_net_assets_retranslation)
        .i128(cta.period_net_income_spread)
        .i128(cta.equity_and_dividend_spread)
        .i128(cta.delta_cta_credit)
        .i128(cta.ending_cumulative_cta_credit)
        .list(lines, |w, l| {
            w.u128(l.account.0)
                .u8(l.kind.tag())
                .opt(l.kind.historical_date().as_ref(), |w, d| {
                    w.i32(d.0);
                })
                .u8(match l.side {
                    Side::Debit => 0,
                    Side::Credit => 1,
                })
                .u32(l.functional_amount.unit.0)
                .i128(l.functional_amount.mantissa)
                .u32(l.reporting_amount.unit.0)
                .i128(l.reporting_amount.mantissa)
                .fixed(&l.rate_doc_commit)
                .u8(l.rate_purpose.tag());
        });
    let mut h = Hasher::new();
    h.update(TRANSLATION_CERTIFICATE_DOMAIN);
    h.update(&w.finish().map_err(fx_refusal)?);
    Ok(h.finalize().0)
}

/// Replay and verify a [`TranslatedStatement`] certificate byte-for-byte from its
/// inputs and [`FxRateDocument`]s (`plan §12.4`, `fa-rn6g`).
#[allow(clippy::too_many_arguments)]
pub fn verify_translation_certificate(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    claimed: &TranslatedStatement,
    lines: &[TranslationInputLine],
    closing_rate_doc: &FxRateDocument,
    average_rate_doc: &FxRateDocument,
    historical_rate_docs: &[FxRateDocument],
    prior_retained_earnings_functional: i128,
    units: &UnitRegistry,
) -> Result<(), Refusal> {
    let replayed = translate_current_rate(
        budget,
        &claimed.period,
        claimed.period_end,
        claimed.functional_unit,
        claimed.reporting_unit,
        lines,
        closing_rate_doc,
        average_rate_doc,
        historical_rate_docs,
        prior_retained_earnings_functional,
        claimed.prior_retained_earnings_reporting,
        claimed.cta_schedule.prior_cumulative_cta_credit,
        units,
    )?;
    if replayed != *claimed {
        return Err(fx_unbalanced(format!(
            "translation certificate replay mismatch on period `{}`: expected digest {:02x?}, got {:02x?}",
            claimed.period, replayed.certificate_digest, claimed.certificate_digest
        )));
    }
    Ok(())
}

/// Plan the deconsolidation CTA recycling entry (`ASC 830-30-40-1 / IAS 21.48`, plan §12.4)
/// that reclassifies accumulated `ending_cumulative_cta_credit` out of AOCI (`cta_account`)
/// into P&L (`disposal_gain_loss_account`) upon disposal/deconsolidation of the foreign operation.
pub fn plan_cta_deconsolidation_recycling(
    mut template: EntryPayload,
    statement: &TranslatedStatement,
    cta_account: VId,
    disposal_gain_loss_account: VId,
    closing_rate_doc: &FxRateDocument,
    dimensions: Vec<(u32, VId)>,
) -> Result<EntryPayload, Refusal> {
    if !template.legs.is_empty() || template.base_totals.is_some() {
        return Err(fx_refusal(
            "plan_cta_deconsolidation_recycling requires a template with empty legs and no base_totals",
        ));
    }
    if cta_account == disposal_gain_loss_account {
        return Err(fx_refusal(
            "cta_account and disposal_gain_loss_account must be distinct accounts",
        ));
    }
    if closing_rate_doc.purpose != FxRatePurpose::PeriodClose
        || closing_rate_doc.as_of != template.effective_date
        || closing_rate_doc.base_unit != statement.reporting_unit
    {
        return Err(fx_refusal(
            "closing_rate_doc must have purpose == PeriodClose, as_of == template.effective_date, and base_unit == statement.reporting_unit",
        ));
    }
    let cta_credit = statement.cta_schedule.ending_cumulative_cta_credit;
    if cta_credit == 0 {
        return Err(fx_refusal(
            "accumulated CTA is zero; no deconsolidation recycling entry is required",
        ));
    }
    let mag = cta_credit.abs();
    let amt = Amount::new(statement.reporting_unit, mag);
    // If ending CTA is a credit (> 0), debit cta_account to zero AOCI and credit disposal_gain_loss_account.
    // If ending CTA is a debit (< 0), credit cta_account to zero AOCI and debit disposal_gain_loss_account.
    let (cta_side, pnl_side) = if cta_credit > 0 {
        (Side::Debit, Side::Credit)
    } else {
        (Side::Credit, Side::Debit)
    };

    let mut leg_cta = LegPayload::simple(cta_side, cta_account, amt);
    leg_cta.base_amount = Some(amt);
    leg_cta.dimension_set = dimensions.clone();

    let mut leg_pnl = LegPayload::simple(pnl_side, disposal_gain_loss_account, amt);
    leg_pnl.base_amount = Some(amt);
    leg_pnl.dimension_set = dimensions;

    let ev = closing_rate_doc.evidence_ref(template.book_id)?;
    if !template.evidence.contains(&ev) {
        template.evidence.push(ev);
    }
    template.evidence.sort();
    template.evidence.dedup();

    template.legs = vec![leg_cta, leg_pnl];
    template.unit_totals = EntryPayload::fold_unit_totals(&template.legs).map_err(fx_refusal)?;
    template.base_totals = Some(BaseTotals {
        unit_id: statement.reporting_unit.0,
        debits: mag,
        credits: mag,
        fx_law_oid: FxLawId::TranslationCurrentRate.oid(),
        rate_doc_oids: vec![ev.document_oid],
        residual: None,
    });
    template.validate().map_err(fx_refusal)?;
    Ok(template)
}

// =============================================================================
// FX Remeasurement (Temporal Method, ASC 830-10-45-17 / IAS 21.23; plan §12.4)
// =============================================================================

/// Temporal-method remeasurement basis (`ASC 830-10-45-17 / IAS 21.23(b)-(c)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RemeasurementBasis {
    /// Monetary assets and liabilities (cash, AR, AP, debt) remeasured at `PeriodClose`.
    MonetaryClosing,
    /// Non-monetary balance-sheet items (inventory, PP&E, intangibles, prepaid, contributed equity)
    /// remeasured at the historical `SpotClose` rate on `acquisition_date`.
    NonMonetaryHistorical { acquisition_date: DateDay },
    /// Non-monetary cost allocations in P&L (COGS, depreciation, amortization) remeasured at the
    /// historical `SpotClose` rate of the underlying asset layer on `acquisition_date`.
    HistoricalCostAllocation { acquisition_date: DateDay },
    /// Other income-statement flows (revenue, operating expenses) remeasured at `PeriodAverage`.
    FlowAverage,
}

impl RemeasurementBasis {
    const fn tag(self) -> u8 {
        match self {
            Self::MonetaryClosing => 1,
            Self::NonMonetaryHistorical { .. } => 2,
            Self::HistoricalCostAllocation { .. } => 3,
            Self::FlowAverage => 4,
        }
    }

    const fn historical_date(self) -> Option<DateDay> {
        match self {
            Self::NonMonetaryHistorical { acquisition_date }
            | Self::HistoricalCostAllocation { acquisition_date } => Some(acquisition_date),
            _ => None,
        }
    }
}

/// Input line for temporal-method remeasurement (`FxLawId::RemeasurementTemporal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemeasurementInputLine {
    pub account: VId,
    pub account_type: AccountType,
    pub basis: RemeasurementBasis,
    pub side: Side,
    pub record_amount: Amount,
}

/// Remeasured line result under `RemeasurementTemporal`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemeasurementLineResult {
    pub account: VId,
    pub account_type: AccountType,
    pub basis: RemeasurementBasis,
    pub side: Side,
    pub record_amount: Amount,
    pub functional_amount: Amount,
    pub rate_doc_commit: [u8; 32],
    pub rate_purpose: FxRatePurpose,
}

/// Certified output of a temporal-method remeasurement run (`ASC 830-10-45-17 / IAS 21.23`, plan §12.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemeasurementRunResult {
    pub period: String,
    pub period_end: DateDay,
    pub record_unit: UnitId,
    pub functional_unit: UnitId,
    pub lines: Vec<RemeasurementLineResult>,
    pub prior_cumulative_remeasurement_gain_credit: i128,
    pub cumulative_remeasurement_gain_credit: i128,
    /// Delta-cumulative remeasurement gain (> 0 credit) or loss (< 0 debit) recognized in P&L.
    pub delta_remeasurement_gain_credit: i128,
    pub pre_fx_net_income_functional: i128,
    pub remeasured_net_income_functional: i128,
    pub prior_retained_earnings_functional: i128,
    pub ending_retained_earnings_functional: i128,
    pub certificate_digest: [u8; 32],
}

/// Execute temporal-method remeasurement (`FxLawId::RemeasurementTemporal`, `ASC 830-10-45-17 / IAS 21.23`)
/// from `record_unit` (currency of record) into `functional_unit` for `period` ending at `period_end`.
///
/// Enforces temporal-method basis rules:
/// - `MonetaryClosing` is only admissible on `Asset` or `Liability` accounts.
/// - `NonMonetaryHistorical` is only admissible on `Asset`, `Liability`, or `Equity` accounts.
/// - `HistoricalCostAllocation` (COGS, depreciation, amortization) is only admissible on `Expense` accounts.
/// - `FlowAverage` is only admissible on `Revenue` or `Expense` accounts.
///
/// Recognizes the delta-cumulative remeasurement gain or loss in P&L (`delta_remeasurement_gain_credit`).
#[allow(clippy::too_many_arguments)]
pub fn remeasure_temporal(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    period: &str,
    period_end: DateDay,
    record_unit: UnitId,
    functional_unit: UnitId,
    lines: &[RemeasurementInputLine],
    closing_rate_doc: &FxRateDocument,
    average_rate_doc: &FxRateDocument,
    historical_rate_docs: &[FxRateDocument],
    prior_retained_earnings_record: i128,
    prior_retained_earnings_functional: i128,
    prior_cumulative_remeasurement_gain_credit: i128,
    units: &UnitRegistry,
) -> Result<RemeasurementRunResult, Refusal> {
    if period.trim().is_empty() {
        return Err(fx_refusal("period code must not be empty"));
    }
    if record_unit == functional_unit {
        return Err(fx_refusal(
            "record_unit and functional_unit must be distinct currencies",
        ));
    }
    if lines.is_empty() {
        return Err(fx_refusal("remeasurement input lines must not be empty"));
    }
    if closing_rate_doc.base_unit != functional_unit
        || closing_rate_doc.quote_unit != record_unit
        || closing_rate_doc.purpose != FxRatePurpose::PeriodClose
        || closing_rate_doc.as_of != period_end
    {
        return Err(fx_refusal(
            "closing_rate_doc must have base_unit == functional_unit, quote_unit == record_unit, purpose == PeriodClose, and as_of == period_end",
        ));
    }
    if average_rate_doc.base_unit != functional_unit
        || average_rate_doc.quote_unit != record_unit
        || average_rate_doc.purpose != FxRatePurpose::PeriodAverage
        || average_rate_doc.as_of != period_end
    {
        return Err(fx_refusal(
            "average_rate_doc must have base_unit == functional_unit, quote_unit == record_unit, purpose == PeriodAverage, and as_of == period_end",
        ));
    }

    let mut hist_by_date: BTreeMap<DateDay, (&FxRateDocument, [u8; 32])> = BTreeMap::new();
    for doc in historical_rate_docs {
        if doc.base_unit != functional_unit
            || doc.quote_unit != record_unit
            || doc.purpose != FxRatePurpose::SpotClose
        {
            return Err(fx_refusal(
                "historical_rate_docs must have base_unit == functional_unit, quote_unit == record_unit, and purpose == SpotClose",
            ));
        }
        let commit = doc.doc_commit()?;
        if hist_by_date.insert(doc.as_of, (doc, commit)).is_some() {
            return Err(fx_refusal(format!(
                "duplicate historical SpotClose rate document for date {}",
                doc.as_of.render()
            )));
        }
    }

    let closing_commit = closing_rate_doc.doc_commit()?;
    let average_commit = average_rate_doc.doc_commit()?;
    let closing_rate = closing_rate_doc.to_rate(budget)?;
    let average_rate = average_rate_doc.to_rate(budget)?;

    let mut rec_debits = 0i128;
    let mut rec_credits = prior_retained_earnings_record.max(0);
    if prior_retained_earnings_record < 0 {
        rec_debits = rec_debits
            .checked_add(-prior_retained_earnings_record)
            .ok_or_else(|| fx_refusal("record debit overflow"))?;
    }

    let mut out_lines = Vec::with_capacity(lines.len());
    let mut bs_dr_minus_cr = 0i128;
    let mut pre_fx_pnl_cr_minus_dr = 0i128;

    for (idx, line) in lines.iter().enumerate() {
        if line.record_amount.unit != record_unit || line.record_amount.mantissa <= 0 {
            return Err(fx_refusal(format!(
                "line {idx} record_amount must be a positive amount in record_unit"
            )));
        }

        // Validate basis admissibility against account_type per ASC 830-10-45-17 / IAS 21.23.
        let basis_ok = match (line.account_type, line.basis) {
            (
                AccountType::ASSET | AccountType::LIABILITY,
                RemeasurementBasis::MonetaryClosing
                | RemeasurementBasis::NonMonetaryHistorical { .. },
            ) => true,
            (AccountType::EQUITY, RemeasurementBasis::NonMonetaryHistorical { .. }) => true,
            (AccountType::REVENUE, RemeasurementBasis::FlowAverage) => true,
            (
                AccountType::EXPENSE,
                RemeasurementBasis::FlowAverage
                | RemeasurementBasis::HistoricalCostAllocation { .. },
            ) => true,
            _ => false,
        };
        if !basis_ok {
            return Err(fx_refusal(format!(
                "line {idx} account_type {:?} is not admissible with temporal remeasurement basis {:?}",
                line.account_type, line.basis
            )));
        }

        match line.side {
            Side::Debit => {
                rec_debits = rec_debits
                    .checked_add(line.record_amount.mantissa)
                    .ok_or_else(|| fx_refusal("record debit overflow"))?;
            }
            Side::Credit => {
                rec_credits = rec_credits
                    .checked_add(line.record_amount.mantissa)
                    .ok_or_else(|| fx_refusal("record credit overflow"))?;
            }
        }

        let (functional_amount, rate_doc_commit, rate_purpose) = match line.basis {
            RemeasurementBasis::MonetaryClosing => {
                let amt = line
                    .record_amount
                    .convert(
                        budget,
                        functional_unit,
                        &closing_rate,
                        closing_rate_doc.rounding,
                        units,
                    )
                    .map_err(fx_refusal)?;
                (amt, closing_commit, FxRatePurpose::PeriodClose)
            }
            RemeasurementBasis::FlowAverage => {
                let amt = line
                    .record_amount
                    .convert(
                        budget,
                        functional_unit,
                        &average_rate,
                        average_rate_doc.rounding,
                        units,
                    )
                    .map_err(fx_refusal)?;
                (amt, average_commit, FxRatePurpose::PeriodAverage)
            }
            RemeasurementBasis::NonMonetaryHistorical { acquisition_date }
            | RemeasurementBasis::HistoricalCostAllocation { acquisition_date } => {
                let Some((doc, commit)) = hist_by_date.get(&acquisition_date) else {
                    return Err(Refusal::new(
                        code::EVIDENCE_UNKNOWN,
                        exit::REFUSAL,
                        format!(
                            "missing historical SpotClose FxRateDocument for non-monetary acquisition_date {}",
                            acquisition_date.render()
                        ),
                        "plan §12.4, FA-INV-05 (non-monetary items and historical cost allocations under temporal remeasurement require historical SpotClose rate documents)",
                        "commit the SpotClose FxRateDocument for the acquisition date and pass it in historical_rate_docs",
                    ));
                };
                let rate = doc.to_rate(budget)?;
                let amt = line
                    .record_amount
                    .convert(budget, functional_unit, &rate, doc.rounding, units)
                    .map_err(fx_refusal)?;
                (amt, *commit, FxRatePurpose::SpotClose)
            }
        };

        let func = functional_amount.mantissa;
        match line.account_type {
            AccountType::REVENUE | AccountType::EXPENSE => match line.side {
                Side::Credit => pre_fx_pnl_cr_minus_dr += func,
                Side::Debit => pre_fx_pnl_cr_minus_dr -= func,
            },
            AccountType::ASSET | AccountType::LIABILITY | AccountType::EQUITY => match line.side {
                Side::Debit => bs_dr_minus_cr += func,
                Side::Credit => bs_dr_minus_cr -= func,
            },
            _ => {
                return Err(fx_refusal(
                    "statistical/memo accounts cannot participate in temporal remeasurement",
                ));
            }
        }

        out_lines.push(RemeasurementLineResult {
            account: line.account,
            account_type: line.account_type,
            basis: line.basis,
            side: line.side,
            record_amount: line.record_amount,
            functional_amount,
            rate_doc_commit,
            rate_purpose,
        });
    }

    if rec_debits != rec_credits {
        return Err(fx_unbalanced(format!(
            "record-currency trial balance does not balance: debits {rec_debits} != credits {rec_credits}"
        )));
    }

    let pre_fx_equity_carry = prior_retained_earnings_functional
        .checked_add(pre_fx_pnl_cr_minus_dr)
        .ok_or_else(|| fx_refusal("pre-FX equity carry overflow"))?;
    let delta_remeasurement_gain_credit = bs_dr_minus_cr
        .checked_sub(pre_fx_equity_carry)
        .ok_or_else(|| fx_refusal("delta remeasurement gain overflow"))?;
    let cumulative_remeasurement_gain_credit = prior_cumulative_remeasurement_gain_credit
        .checked_add(delta_remeasurement_gain_credit)
        .ok_or_else(|| fx_refusal("cumulative remeasurement gain overflow"))?;
    let remeasured_net_income_functional = pre_fx_pnl_cr_minus_dr
        .checked_add(delta_remeasurement_gain_credit)
        .ok_or_else(|| fx_refusal("remeasured net income overflow"))?;
    let ending_retained_earnings_functional = prior_retained_earnings_functional
        .checked_add(remeasured_net_income_functional)
        .ok_or_else(|| fx_refusal("ending retained earnings overflow"))?;

    let certificate_digest = compute_remeasurement_digest(
        period,
        period_end,
        record_unit,
        functional_unit,
        &closing_commit,
        &average_commit,
        &out_lines,
        prior_retained_earnings_record,
        prior_retained_earnings_functional,
        ending_retained_earnings_functional,
        prior_cumulative_remeasurement_gain_credit,
        cumulative_remeasurement_gain_credit,
        delta_remeasurement_gain_credit,
        pre_fx_pnl_cr_minus_dr,
        remeasured_net_income_functional,
    )?;

    Ok(RemeasurementRunResult {
        period: period.to_string(),
        period_end,
        record_unit,
        functional_unit,
        lines: out_lines,
        prior_cumulative_remeasurement_gain_credit,
        cumulative_remeasurement_gain_credit,
        delta_remeasurement_gain_credit,
        pre_fx_net_income_functional: pre_fx_pnl_cr_minus_dr,
        remeasured_net_income_functional,
        prior_retained_earnings_functional,
        ending_retained_earnings_functional,
        certificate_digest,
    })
}

#[allow(clippy::too_many_arguments)]
fn compute_remeasurement_digest(
    period: &str,
    period_end: DateDay,
    record_unit: UnitId,
    functional_unit: UnitId,
    closing_commit: &[u8; 32],
    average_commit: &[u8; 32],
    lines: &[RemeasurementLineResult],
    prior_re_rec: i128,
    prior_re_func: i128,
    ending_re_func: i128,
    prior_cum_gain: i128,
    cum_gain: i128,
    delta_gain: i128,
    pre_fx_ni: i128,
    remeasured_ni: i128,
) -> Result<[u8; 32], Refusal> {
    let mut w = Writer::new();
    w.str(period)
        .i32(period_end.0)
        .u32(record_unit.0)
        .u32(functional_unit.0)
        .fixed(closing_commit)
        .fixed(average_commit)
        .i128(prior_re_rec)
        .i128(prior_re_func)
        .i128(ending_re_func)
        .i128(prior_cum_gain)
        .i128(cum_gain)
        .i128(delta_gain)
        .i128(pre_fx_ni)
        .i128(remeasured_ni)
        .list(lines, |w, l| {
            w.u128(l.account.0)
                .u8(l.account_type.0)
                .u8(l.basis.tag())
                .opt(l.basis.historical_date().as_ref(), |w, d| {
                    w.i32(d.0);
                })
                .u8(match l.side {
                    Side::Debit => 0,
                    Side::Credit => 1,
                })
                .u32(l.record_amount.unit.0)
                .i128(l.record_amount.mantissa)
                .u32(l.functional_amount.unit.0)
                .i128(l.functional_amount.mantissa)
                .fixed(&l.rate_doc_commit)
                .u8(l.rate_purpose.tag());
        });
    let mut h = Hasher::new();
    h.update(REMEASUREMENT_CERTIFICATE_DOMAIN);
    h.update(&w.finish().map_err(fx_refusal)?);
    Ok(h.finalize().0)
}

/// Replay and verify a [`RemeasurementRunResult`] certificate byte-for-byte from its
/// inputs and [`FxRateDocument`]s (`plan §12.4`, `fa-rn6g`).
#[allow(clippy::too_many_arguments)]
pub fn verify_remeasurement_certificate(
    budget: &mut ArithmeticBudget<'_, impl Sized>,
    claimed: &RemeasurementRunResult,
    lines: &[RemeasurementInputLine],
    closing_rate_doc: &FxRateDocument,
    average_rate_doc: &FxRateDocument,
    historical_rate_docs: &[FxRateDocument],
    prior_retained_earnings_record: i128,
    units: &UnitRegistry,
) -> Result<(), Refusal> {
    let replayed = remeasure_temporal(
        budget,
        &claimed.period,
        claimed.period_end,
        claimed.record_unit,
        claimed.functional_unit,
        lines,
        closing_rate_doc,
        average_rate_doc,
        historical_rate_docs,
        prior_retained_earnings_record,
        claimed.prior_retained_earnings_functional,
        claimed.prior_cumulative_remeasurement_gain_credit,
        units,
    )?;
    if replayed != *claimed {
        return Err(fx_unbalanced(format!(
            "remeasurement certificate replay mismatch on period `{}`: expected digest {:02x?}, got {:02x?}",
            claimed.period, replayed.certificate_digest, claimed.certificate_digest
        )));
    }
    Ok(())
}

/// Plan the delta-cumulative temporal remeasurement entry (`FxLawId::RemeasurementTemporal`, plan §12.4)
/// that posts `delta_remeasurement_gain_credit` between `remeasurement_adjustment_account` (balance sheet)
/// and `remeasurement_gain_loss_account` (P&L), citing the period's `closing_rate_doc`, `average_rate_doc`,
/// and `historical_rate_docs`.
pub fn plan_remeasurement_entry(
    mut template: EntryPayload,
    run: &RemeasurementRunResult,
    remeasurement_adjustment_account: VId,
    remeasurement_gain_loss_account: VId,
    closing_rate_doc: &FxRateDocument,
    average_rate_doc: &FxRateDocument,
    historical_rate_docs: &[FxRateDocument],
    dimensions: Vec<(u32, VId)>,
) -> Result<EntryPayload, Refusal> {
    if !template.legs.is_empty() || template.base_totals.is_some() {
        return Err(fx_refusal(
            "plan_remeasurement_entry requires a template with empty legs and no base_totals",
        ));
    }
    if remeasurement_adjustment_account == remeasurement_gain_loss_account {
        return Err(fx_refusal(
            "remeasurement_adjustment_account and remeasurement_gain_loss_account must be distinct accounts",
        ));
    }
    let delta = run.delta_remeasurement_gain_credit;
    if delta == 0 {
        return Err(fx_refusal(
            "delta_remeasurement_gain_credit is zero; no remeasurement entry is required",
        ));
    }
    let mag = delta.abs();
    let amt = Amount::new(run.functional_unit, mag);
    let (adj_side, pnl_side) = if delta > 0 {
        (Side::Debit, Side::Credit)
    } else {
        (Side::Credit, Side::Debit)
    };

    let mut leg_adj = LegPayload::simple(adj_side, remeasurement_adjustment_account, amt);
    leg_adj.base_amount = Some(amt);
    leg_adj.dimension_set = dimensions.clone();

    let mut leg_pnl = LegPayload::simple(pnl_side, remeasurement_gain_loss_account, amt);
    leg_pnl.base_amount = Some(amt);
    leg_pnl.dimension_set = dimensions;

    let mut rate_doc_oids = Vec::new();
    for doc in std::iter::once(closing_rate_doc)
        .chain(std::iter::once(average_rate_doc))
        .chain(historical_rate_docs.iter())
    {
        let ev = doc.evidence_ref(template.book_id)?;
        rate_doc_oids.push(ev.document_oid);
        if !template.evidence.contains(&ev) {
            template.evidence.push(ev);
        }
    }
    template.evidence.sort();
    template.evidence.dedup();
    rate_doc_oids.sort();
    rate_doc_oids.dedup();

    template.legs = vec![leg_adj, leg_pnl];
    template.unit_totals = EntryPayload::fold_unit_totals(&template.legs).map_err(fx_refusal)?;
    template.base_totals = Some(BaseTotals {
        unit_id: run.functional_unit.0,
        debits: mag,
        credits: mag,
        fx_law_oid: FxLawId::RemeasurementTemporal.oid(),
        rate_doc_oids,
        residual: None,
    });
    template.validate().map_err(fx_refusal)?;
    Ok(template)
}
